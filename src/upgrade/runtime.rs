use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Notify};
use tokio::task::{AbortHandle, Id as TaskId, JoinHandle, JoinSet};
use tokio::time::Instant;

use crate::redaction::ProfileHandle;

const ENTRY_OPEN: u8 = 0;
const ENTRY_CLOSING: u8 = 1;
const ENTRY_CLOSED: u8 = 2;
const ENTRY_CLOSE_REQUESTED: u8 = 3;
const ENTRY_CLOSE_WAITING_SETUP: u8 = 4;
const SETUP_IDLE: u8 = 0;
const SETUP_POLLING: u8 = 1;
const SETUP_SUCCEEDED: u8 = 2;
const DEFAULT_ENTRY_CLEANUP_GRACE: Duration = Duration::from_secs(1);

type UpgradeSetupTask =
    Pin<Box<dyn Future<Output = Result<UpgradeRelayPair, UpgradeTerminalCause>> + Send + 'static>>;
type UpgradeSetupBuilder =
    Box<dyn FnOnce(UpgradedStreamSnapshot) -> UpgradeSetupTask + Send + 'static>;
type UpgradeRelayTask = Pin<Box<dyn Future<Output = UpgradeTerminalCause> + Send + 'static>>;
type UpgradeRawTeardownTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type UpgradeRawTeardownBuilder = Box<dyn FnOnce() -> UpgradeRawTeardownTask + Send + 'static>;
type UpgradeTerminalTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type UpgradeTerminalBuilder =
    Box<dyn FnOnce(UpgradeTerminalCause) -> UpgradeTerminalTask + Send + 'static>;

/// Static limits for the one process-owned upgrade runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UpgradeRuntimeLimits {
    max_active_upgrades: usize,
    max_upgrade_buffer_bytes: usize,
    relay_buffer_bytes: usize,
    max_upgrade_lifetime: Duration,
    cleanup_grace: Duration,
}

impl UpgradeRuntimeLimits {
    pub(crate) fn new(
        max_active_upgrades: usize,
        max_upgrade_buffer_bytes: usize,
        relay_buffer_bytes: usize,
        max_upgrade_lifetime: Duration,
    ) -> Self {
        Self {
            max_active_upgrades,
            max_upgrade_buffer_bytes,
            relay_buffer_bytes,
            max_upgrade_lifetime,
            cleanup_grace: DEFAULT_ENTRY_CLEANUP_GRACE,
        }
    }

    pub(crate) fn relay_buffer_bytes(self) -> usize {
        self.relay_buffer_bytes
    }

    #[cfg(test)]
    fn with_cleanup_grace(mut self, cleanup_grace: Duration) -> Self {
        self.cleanup_grace = cleanup_grace;
        self
    }
}

/// The compiler-produced mandatory wire working set for one matched rule.
/// Transport buffers are process-static and are added exactly at admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UpgradeAllocation {
    rule_index: usize,
    wire_bytes: usize,
}

impl UpgradeAllocation {
    pub(crate) fn from_compiled_rule(
        rule_index: usize,
        compiled_wire_bytes: Option<usize>,
    ) -> Result<Self, UpgradeAllocationError> {
        let wire_bytes =
            compiled_wire_bytes.ok_or(UpgradeAllocationError::RuleDisallowsUpgrades)?;
        Ok(Self {
            rule_index,
            wire_bytes,
        })
    }

    #[cfg(test)]
    pub(crate) fn rule_index(self) -> usize {
        self.rule_index
    }

    #[cfg(test)]
    pub(crate) fn wire_bytes(self) -> usize {
        self.wire_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum UpgradeAllocationError {
    #[error("the matched rule does not allow upgrades")]
    RuleDisallowsUpgrades,
}

/// Immutable state retained by an established stream. This type deliberately
/// contains no generation lease or generation-owned provider/callback handle.
pub(crate) struct UpgradedStreamSnapshot {
    relay_buffer_bytes: usize,
    wire_redaction: Option<ProfileHandle>,
}

impl UpgradedStreamSnapshot {
    fn new(relay_buffer_bytes: usize, wire_redaction: Option<ProfileHandle>) -> Self {
        Self {
            relay_buffer_bytes,
            wire_redaction,
        }
    }

    pub(crate) fn wire_redaction(&self) -> Option<&ProfileHandle> {
        self.wire_redaction.as_ref()
    }
}

impl fmt::Debug for UpgradedStreamSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpgradedStreamSnapshot")
            .field("relay_buffer_bytes", &self.relay_buffer_bytes)
            .field("wire_redaction", &self.wire_redaction.is_some())
            .finish()
    }
}

/// Cause-aware ownership adapter for downstream close, socket teardown, and
/// in-progress capture cancellation. Every established relay pair must provide
/// one, and only the entry coordinator invokes it.
pub(crate) struct UpgradeTerminalControl {
    raw_teardown: UpgradeRawTeardownBuilder,
    established_close: UpgradeTerminalBuilder,
}

struct ActiveUpgradeTerminalControl {
    raw_teardown: RawTeardownOwner,
    established_close: UpgradeTerminalBuilder,
}

struct RawTeardownOwner {
    cancel: Option<oneshot::Sender<()>>,
    joined: Option<oneshot::Receiver<Result<(), tokio::task::JoinError>>>,
}

impl RawTeardownOwner {
    async fn abort_and_join(mut self) {
        let _ = self
            .cancel
            .take()
            .expect("raw teardown task is cancelled once")
            .send(());
        let joined = self
            .joined
            .take()
            .expect("raw teardown task is joined once")
            .await;
        if let Ok(Err(error)) = joined {
            if !error.is_cancelled() {
                tracing::error!(%error, "upgrade raw teardown task failed");
            }
        }
    }
}

impl Drop for RawTeardownOwner {
    fn drop(&mut self) {
        self.cancel.take();
    }
}

impl UpgradeTerminalControl {
    pub(crate) fn new<BuildRaw, Raw, Build, Task>(
        build_raw_teardown: BuildRaw,
        established_close: Build,
    ) -> Self
    where
        BuildRaw: FnOnce() -> Raw + Send + 'static,
        Raw: Future<Output = ()> + Send + 'static,
        Build: FnOnce(UpgradeTerminalCause) -> Task + Send + 'static,
        Task: Future<Output = ()> + Send + 'static,
    {
        Self {
            raw_teardown: Box::new(move || Box::pin(build_raw_teardown())),
            established_close: Box::new(move |cause| Box::pin(established_close(cause))),
        }
    }

    async fn activate_with_hook<Hook>(
        self,
        inner: &Arc<RuntimeInner>,
        before_raw_start: Hook,
    ) -> Result<ActiveUpgradeTerminalControl, ()>
    where
        Hook: FnOnce() + Send + 'static,
    {
        Ok(ActiveUpgradeTerminalControl {
            raw_teardown: inner
                .spawn_raw_teardown((self.raw_teardown)(), before_raw_start)
                .await?,
            established_close: self.established_close,
        })
    }
}

impl ActiveUpgradeTerminalControl {
    fn into_parts(self) -> (RawTeardownOwner, UpgradeTerminalBuilder) {
        (self.raw_teardown, self.established_close)
    }
}

pub(crate) struct UpgradeEntryPlan {
    setup: UpgradeSetupBuilder,
    terminal_control: UpgradeTerminalControl,
}

impl UpgradeEntryPlan {
    pub(crate) fn new<Build, Setup>(terminal_control: UpgradeTerminalControl, build: Build) -> Self
    where
        Build: FnOnce(UpgradedStreamSnapshot) -> Setup + Send + 'static,
        Setup: Future<Output = Result<UpgradeRelayPair, UpgradeTerminalCause>> + Send + 'static,
    {
        Self {
            setup: Box::new(move |snapshot| Box::pin(build(snapshot))),
            terminal_control,
        }
    }
}

pub(crate) struct UpgradeRelayPair {
    relay: UpgradeRelayTask,
}

impl UpgradeRelayPair {
    #[cfg(test)]
    pub(crate) fn new<First, Second>(first: First, second: Second) -> Self
    where
        First: Future<Output = UpgradeTerminalCause> + Send + 'static,
        Second: Future<Output = UpgradeTerminalCause> + Send + 'static,
    {
        let mut first: UpgradeRelayTask = Box::pin(first);
        let mut second: UpgradeRelayTask = Box::pin(second);
        Self {
            relay: Box::pin(async move {
                tokio::select! {
                    cause = first.as_mut() => cause,
                    cause = second.as_mut() => cause,
                }
            }),
        }
    }

    pub(crate) fn new_with_graceful_drain_timeout<First, Second>(
        first: First,
        second: Second,
        graceful_drain_timeout: Option<Duration>,
    ) -> Self
    where
        First: Future<Output = UpgradeTerminalCause> + Send + 'static,
        Second: Future<Output = UpgradeTerminalCause> + Send + 'static,
    {
        let mut first: UpgradeRelayTask = Box::pin(first);
        let mut second: UpgradeRelayTask = Box::pin(second);
        Self {
            relay: Box::pin(async move {
                tokio::select! {
                    cause = first.as_mut() => {
                        if cause == UpgradeTerminalCause::PeerClosed {
                            await_graceful_peer(second, graceful_drain_timeout).await
                        } else {
                            cause
                        }
                    }
                    cause = second.as_mut() => {
                        if cause == UpgradeTerminalCause::PeerClosed {
                            await_graceful_peer(first, graceful_drain_timeout).await
                        } else {
                            cause
                        }
                    }
                }
            }),
        }
    }
}

async fn await_graceful_peer(
    peer: UpgradeRelayTask,
    drain_timeout: Option<Duration>,
) -> UpgradeTerminalCause {
    match drain_timeout {
        Some(timeout) => tokio::time::timeout(timeout, peer)
            .await
            .unwrap_or(UpgradeTerminalCause::PeerClosed),
        None => peer.await,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UpgradeTerminalCause {
    PeerClosed,
    RelayError,
    IdleTimeout,
    LifetimeExpired,
    Shutdown,
    #[cfg(test)]
    Cancelled,
    SetupFailed,
    DownstreamWriteFailed,
}

pub(crate) struct UpgradeRuntime {
    inner: Arc<RuntimeInner>,
    supervisor: AsyncMutex<Option<JoinHandle<()>>>,
}

struct RuntimeInner {
    limits: UpgradeRuntimeLimits,
    handle: Handle,
    state: Mutex<RuntimeState>,
    changed: Notify,
    supervisor_tasks: mpsc::UnboundedSender<SupervisorCommand>,
}

struct RuntimeState {
    accepting: bool,
    next_id: u64,
    reserved_slots: usize,
    reserved_bytes: usize,
    tracked_tasks: usize,
    uncommitted: HashMap<u64, UncommittedRecord>,
    entries: HashMap<u64, EntryRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Reservation {
    allocation: UpgradeAllocation,
    bytes: usize,
}

struct UncommittedRecord {
    reservation: Reservation,
    abort: AbortHandle,
}

struct EntryRecord {
    reservation: Reservation,
    shared: Arc<EntryShared>,
    origin_abort: AbortHandle,
    origin_done: bool,
    coordinator_done: bool,
}

struct EntryShared {
    timing: Mutex<EntryTiming>,
    cleanup_grace: Duration,
    winning_cause: Mutex<Option<UpgradeTerminalCause>>,
    // These two atomics form one handshake. SeqCst prevents the setup poll and
    // closer from each missing the other's publication via store buffering.
    setup_state: AtomicU8,
    changed: Notify,
    terminal_state: AtomicU8,
    closed: Notify,
}

#[derive(Clone, Copy, Debug)]
struct EntryTiming {
    application_stop: Instant,
    cleanup_cutoff: Instant,
    stop_cause: UpgradeTerminalCause,
}

enum SupervisorCommand {
    Track(OwnedTask),
    SpawnJoinable {
        task: UpgradeRawTeardownTask,
        joined: oneshot::Sender<Result<(), tokio::task::JoinError>>,
        started: oneshot::Sender<()>,
        before_start: Box<dyn FnOnce() + Send + 'static>,
    },
    Stop,
}

enum SupervisorTaskCompletion {
    Tracked(TaskId),
    Joinable,
}

struct OwnedTask {
    task: Option<JoinHandle<()>>,
}

struct TrackedTaskCompletion {
    inner: Arc<RuntimeInner>,
    counted: Arc<AtomicBool>,
}

struct HandshakeTaskCompletion {
    inner: Arc<RuntimeInner>,
    id: u64,
    _tracked: TrackedTaskCompletion,
}

impl OwnedTask {
    fn new(task: JoinHandle<()>) -> Self {
        Self { task: Some(task) }
    }

    fn id(&self) -> TaskId {
        self.task.as_ref().expect("owned task is pending").id()
    }

    fn abort_handle(&self) -> AbortHandle {
        self.task
            .as_ref()
            .expect("owned task is pending")
            .abort_handle()
    }
}

impl Future for OwnedTask {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let task = self.task.as_mut().expect("owned task is polled until join");
        match Pin::new(task).poll(context) {
            Poll::Ready(_) => {
                self.task.take();
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for OwnedTask {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl Drop for TrackedTaskCompletion {
    fn drop(&mut self) {
        if self.counted.swap(false, Ordering::AcqRel) {
            let mut state = lock(&self.inner.state);
            state.tracked_tasks = state
                .tracked_tasks
                .checked_sub(1)
                .expect("tracked task count cannot underflow");
            drop(state);
            self.inner.changed.notify_waiters();
        }
    }
}

impl Drop for HandshakeTaskCompletion {
    fn drop(&mut self) {
        self.inner.complete_handshake(self.id);
    }
}

enum EntryTaskResult {
    Setup(Result<UpgradeRelayPair, UpgradeTerminalCause>),
    Relay(UpgradeTerminalCause),
    TerminalControl,
}

struct LinearizedSetupTask {
    shared: Arc<EntryShared>,
    build: Option<UpgradeSetupBuilder>,
    snapshot: Option<UpgradedStreamSnapshot>,
    setup: Option<UpgradeSetupTask>,
}

struct SetupPollGuard {
    shared: Arc<EntryShared>,
    succeeded: bool,
}

impl Drop for SetupPollGuard {
    fn drop(&mut self) {
        self.shared.setup_state.store(
            if self.succeeded {
                SETUP_SUCCEEDED
            } else {
                SETUP_IDLE
            },
            Ordering::SeqCst,
        );
        self.shared.finish_close_request();
    }
}

impl Future for LinearizedSetupTask {
    type Output = Result<UpgradeRelayPair, UpgradeTerminalCause>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let shared = self.shared.clone();
        if shared.terminal_state.load(Ordering::SeqCst) != ENTRY_OPEN {
            return Poll::Ready(Err(lock(&shared.timing).stop_cause));
        }
        if shared
            .setup_state
            .compare_exchange(
                SETUP_IDLE,
                SETUP_POLLING,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_err()
        {
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        let mut guard = SetupPollGuard {
            shared: shared.clone(),
            succeeded: false,
        };
        let timing = *lock(&shared.timing);
        if shared.terminal_state.load(Ordering::SeqCst) != ENTRY_OPEN
            || Instant::now() >= timing.application_stop
        {
            return Poll::Ready(Err(timing.stop_cause));
        }
        if self.setup.is_none() {
            let build = self.build.take().expect("setup builder is invoked once");
            let snapshot = self
                .snapshot
                .take()
                .expect("setup snapshot is consumed once");
            self.setup = Some(build(snapshot));
        }
        let result = self
            .setup
            .as_mut()
            .expect("setup future is cached after builder invocation")
            .as_mut()
            .poll(context);
        if matches!(result, Poll::Ready(Ok(_))) {
            guard.succeeded = true;
        }
        result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryPhase {
    Establishing,
    Established,
}

impl UpgradeRuntime {
    pub(crate) fn try_new(limits: UpgradeRuntimeLimits) -> Result<Arc<Self>, UpgradeRuntimeError> {
        validate_limits(limits)?;
        let handle = Handle::try_current().map_err(|_| UpgradeRuntimeError::RuntimeUnavailable)?;
        let (supervisor_tasks, receiver) = mpsc::unbounded_channel();
        let inner = Arc::new(RuntimeInner {
            limits,
            handle: handle.clone(),
            state: Mutex::new(RuntimeState {
                accepting: true,
                next_id: 0,
                reserved_slots: 0,
                reserved_bytes: 0,
                tracked_tasks: 0,
                uncommitted: HashMap::new(),
                entries: HashMap::new(),
            }),
            changed: Notify::new(),
            supervisor_tasks,
        });
        let supervisor = handle.spawn(async move {
            run_task_supervisor(receiver).await;
        });
        Ok(Arc::new(Self {
            inner,
            supervisor: AsyncMutex::new(Some(supervisor)),
        }))
    }

    pub(crate) fn limits(&self) -> UpgradeRuntimeLimits {
        self.inner.limits
    }

    /// Atomically reserves admission and installs the runtime-owned handshake
    /// task. No unregistered guard is ever returned to the caller.
    pub(crate) fn try_spawn_handshake<Build, Task>(
        self: &Arc<Self>,
        allocation: UpgradeAllocation,
        build: Build,
    ) -> Result<(), UpgradeHandshakeSpawnError>
    where
        Build: FnOnce(UpgradeHandshake) -> Task + Send + 'static,
        Task: Future<Output = ()> + Send + 'static,
    {
        self.try_spawn_handshake_with_hook(allocation, build, || {})
    }

    fn try_spawn_handshake_with_hook<Build, Task, Hook>(
        self: &Arc<Self>,
        allocation: UpgradeAllocation,
        build: Build,
        after_spawn_before_registration: Hook,
    ) -> Result<(), UpgradeHandshakeSpawnError>
    where
        Build: FnOnce(UpgradeHandshake) -> Task + Send + 'static,
        Task: Future<Output = ()> + Send + 'static,
        Hook: FnOnce(),
    {
        let mut state = lock(&self.inner.state);
        let reservation = validate_admission(&self.inner.limits, &state, allocation)?;
        let (id, following_id) = validate_next_id(&state)?;
        let (start, started) = tokio::sync::oneshot::channel();
        let handshake = UpgradeHandshake {
            inner: self.inner.clone(),
            id,
            reservation,
        };
        let counted = Arc::new(AtomicBool::new(true));
        let tracked = TrackedTaskCompletion {
            inner: self.inner.clone(),
            counted: counted.clone(),
        };
        let completion = HandshakeTaskCompletion {
            inner: self.inner.clone(),
            id,
            _tracked: tracked,
        };
        let task = self.inner.handle.spawn(async move {
            async move {
                let _completion = completion;
                if started.await.is_err() {
                    return;
                }
                build(handshake).await;
            }
            .await;
        });
        let abort = task.abort_handle();
        after_spawn_before_registration();
        apply_reservation(&mut state, reservation);
        state.next_id = following_id;
        state
            .uncommitted
            .insert(id, UncommittedRecord { reservation, abort });
        state.tracked_tasks = state
            .tracked_tasks
            .checked_add(1)
            .expect("tracked task count cannot overflow bounded upgrade metadata");
        if let Err(error) = self
            .inner
            .supervisor_tasks
            .send(SupervisorCommand::Track(OwnedTask::new(task)))
        {
            let SupervisorCommand::Track(task) = error.0 else {
                unreachable!("only a tracked task was sent")
            };
            let record = state
                .uncommitted
                .remove(&id)
                .expect("new uncommitted admission is present");
            release_reservation(&mut state, record.reservation);
            if counted.swap(false, Ordering::AcqRel) {
                state.tracked_tasks -= 1;
            }
            state.next_id = id;
            drop(state);
            drop(task);
            drop(start);
            return Err(UpgradeHandshakeSpawnError::SupervisorStopped);
        }
        let _ = start.send(());
        drop(state);
        self.inner.changed.notify_waiters();
        Ok(())
    }

    /// Closes admission. A finite drain lowers both entry deadlines to the
    /// supplied instant; an unbounded drain leaves each finite lifetime intact.
    pub(crate) fn begin_shutdown(&self, drain_deadline: Option<Instant>) {
        let (handshakes, entries) = {
            let mut state = lock(&self.inner.state);
            state.accepting = false;
            let handshakes = state
                .uncommitted
                .values()
                .map(|record| record.abort.clone())
                .collect::<Vec<_>>();
            let entries = state
                .entries
                .values()
                .map(|record| record.shared.clone())
                .collect::<Vec<_>>();
            (handshakes, entries)
        };

        for abort in handshakes {
            abort.abort();
        }
        if let Some(deadline) = drain_deadline {
            for entry in entries {
                entry.lower_for_shutdown(deadline);
            }
        }
        self.inner.changed.notify_waiters();
    }

    pub(crate) async fn wait_until_drained(&self) {
        loop {
            let notified = self.inner.changed.notified();
            let drained = {
                let state = lock(&self.inner.state);
                !state.accepting
                    && state.uncommitted.is_empty()
                    && state.entries.is_empty()
                    && state.tracked_tasks == 0
            };
            if drained {
                return;
            }
            notified.await;
        }
    }

    async fn wait_until_registry_drained(&self) {
        loop {
            let notified = self.inner.changed.notified();
            let drained = {
                let state = lock(&self.inner.state);
                !state.accepting
                    && state.uncommitted.is_empty()
                    && state.entries.values().all(|entry| entry.coordinator_done)
            };
            if drained {
                return;
            }
            notified.await;
        }
    }

    pub(crate) async fn shutdown_and_wait(&self, drain_deadline: Option<Instant>) {
        self.shutdown_and_wait_with_hook(drain_deadline, std::future::ready(()))
            .await;
    }

    async fn shutdown_and_wait_with_hook<Hook>(
        &self,
        drain_deadline: Option<Instant>,
        after_supervisor_lock: Hook,
    ) where
        Hook: Future<Output = ()>,
    {
        self.begin_shutdown(drain_deadline);
        self.wait_until_registry_drained().await;
        let mut owned = self.supervisor.lock().await;
        if let Some(supervisor) = owned.as_mut() {
            let _ = self.inner.supervisor_tasks.send(SupervisorCommand::Stop);
            after_supervisor_lock.await;
            let _ = supervisor.await;
            owned.take();
        }
        drop(owned);
        self.wait_until_drained().await;
    }

    #[cfg(test)]
    pub(crate) fn counts(&self) -> UpgradeRuntimeCounts {
        let state = lock(&self.inner.state);
        UpgradeRuntimeCounts {
            maximum_slots: self.inner.limits.max_active_upgrades,
            maximum_bytes: self.inner.limits.max_upgrade_buffer_bytes,
            reserved_slots: state.reserved_slots,
            reserved_bytes: state.reserved_bytes,
            uncommitted: state.uncommitted.len(),
            committed: state.entries.len(),
            tracked_tasks: state.tracked_tasks,
            accepting: state.accepting,
        }
    }
}

impl Drop for UpgradeRuntime {
    fn drop(&mut self) {
        // Emergency abandonment only. Managed shutdown uses shutdown_and_wait
        // so every coordinator explicitly shuts down and joins its children.
        // Close the admission gate before Stop so every commit that won the
        // same state lock has already enqueued its coordinator for draining.
        self.begin_shutdown(Some(Instant::now()));
        let _ = self.inner.supervisor_tasks.send(SupervisorCommand::Stop);
    }
}

fn validate_limits(limits: UpgradeRuntimeLimits) -> Result<(), UpgradeRuntimeError> {
    if limits.max_active_upgrades == 0 {
        return Err(UpgradeRuntimeError::ZeroActiveUpgrades);
    }
    if limits.max_upgrade_buffer_bytes == 0 {
        return Err(UpgradeRuntimeError::ZeroBufferBytes);
    }
    if limits.relay_buffer_bytes == 0 {
        return Err(UpgradeRuntimeError::ZeroRelayBufferBytes);
    }
    if limits.max_upgrade_lifetime.is_zero() {
        return Err(UpgradeRuntimeError::ZeroLifetime);
    }
    let relay_bytes = limits
        .relay_buffer_bytes
        .checked_mul(2)
        .ok_or(UpgradeRuntimeError::RelayCapacityOverflow)?;
    let baseline = relay_bytes
        .checked_mul(limits.max_active_upgrades)
        .ok_or(UpgradeRuntimeError::BaselineCapacityOverflow)?;
    if baseline > limits.max_upgrade_buffer_bytes {
        return Err(UpgradeRuntimeError::InsufficientBaselineCapacity);
    }
    let now = Instant::now();
    now.checked_add(limits.max_upgrade_lifetime)
        .and_then(|deadline| deadline.checked_add(limits.cleanup_grace))
        .ok_or(UpgradeRuntimeError::LifetimeOverflow)?;
    Ok(())
}

fn validate_admission(
    limits: &UpgradeRuntimeLimits,
    state: &RuntimeState,
    allocation: UpgradeAllocation,
) -> Result<Reservation, UpgradeAdmissionError> {
    if !state.accepting {
        return Err(UpgradeAdmissionError::Closed);
    }
    if state.reserved_slots >= limits.max_active_upgrades {
        return Err(UpgradeAdmissionError::SlotCapacity);
    }
    let relay_bytes = limits
        .relay_buffer_bytes
        .checked_mul(2)
        .ok_or(UpgradeAdmissionError::BufferCapacity)?;
    let bytes = relay_bytes
        .checked_add(allocation.wire_bytes)
        .ok_or(UpgradeAdmissionError::BufferCapacity)?;
    let next_bytes = state
        .reserved_bytes
        .checked_add(bytes)
        .ok_or(UpgradeAdmissionError::BufferCapacity)?;
    if next_bytes > limits.max_upgrade_buffer_bytes {
        return Err(UpgradeAdmissionError::BufferCapacity);
    }
    Ok(Reservation { allocation, bytes })
}

fn validate_next_id(state: &RuntimeState) -> Result<(u64, u64), UpgradeAdmissionError> {
    let id = state.next_id;
    let following = state
        .next_id
        .checked_add(1)
        .ok_or(UpgradeAdmissionError::IdentifierExhausted)?;
    Ok((id, following))
}

fn apply_reservation(state: &mut RuntimeState, reservation: Reservation) {
    state.reserved_slots += 1;
    state.reserved_bytes = state
        .reserved_bytes
        .checked_add(reservation.bytes)
        .expect("validated upgrade reservation remains addressable");
}

impl RuntimeInner {
    fn track_owned_task(&self, task: OwnedTask) -> Result<(), OwnedTask> {
        self.supervisor_tasks
            .send(SupervisorCommand::Track(task))
            .map_err(|error| {
                let SupervisorCommand::Track(task) = error.0 else {
                    unreachable!("only a tracked task was sent")
                };
                task
            })
    }

    async fn spawn_raw_teardown<Hook>(
        self: &Arc<Self>,
        raw: UpgradeRawTeardownTask,
        before_start: Hook,
    ) -> Result<RawTeardownOwner, ()>
    where
        Hook: FnOnce() + Send + 'static,
    {
        let counted = Arc::new(AtomicBool::new(true));
        let completion = TrackedTaskCompletion {
            inner: self.clone(),
            counted,
        };
        let (cancel, cancelled) = oneshot::channel();
        let (joined, join_result) = oneshot::channel();
        let (started, registered) = oneshot::channel();
        let task = Box::pin(async move {
            let _completion = completion;
            tokio::select! {
                biased;
                _ = cancelled => {}
                _ = raw => {}
            }
        });
        {
            let mut state = lock(&self.state);
            state.tracked_tasks = state
                .tracked_tasks
                .checked_add(1)
                .expect("tracked task count cannot overflow bounded upgrade metadata");
        }
        if let Err(error) = self
            .supervisor_tasks
            .send(SupervisorCommand::SpawnJoinable {
                task,
                joined,
                started,
                before_start: Box::new(before_start),
            })
        {
            let SupervisorCommand::SpawnJoinable { task, joined, .. } = error.0 else {
                unreachable!("only a joinable task was sent")
            };
            drop(task);
            drop(joined);
        }
        self.changed.notify_waiters();
        let owner = RawTeardownOwner {
            cancel: Some(cancel),
            joined: Some(join_result),
        };
        registered.await.map_err(|_| ())?;
        Ok(owner)
    }

    fn complete_handshake(&self, id: u64) {
        let released = {
            let mut state = lock(&self.state);
            if let Some(record) = state.uncommitted.remove(&id) {
                release_reservation(&mut state, record.reservation);
                true
            } else {
                let release_entry = match state.entries.get_mut(&id) {
                    Some(entry) => {
                        entry.origin_done = true;
                        entry.coordinator_done
                    }
                    None => false,
                };
                if release_entry {
                    let record = state
                        .entries
                        .remove(&id)
                        .expect("completed entry remains registered");
                    release_reservation(&mut state, record.reservation);
                }
                release_entry
            }
        };
        if released {
            self.changed.notify_waiters();
        }
    }

    fn close_entry(&self, id: u64) {
        let (shared, abort_origin) = {
            let mut state = lock(&self.state);
            let Some(record) = state.entries.get_mut(&id) else {
                return;
            };
            record.coordinator_done = true;
            let shared = record.shared.clone();
            let abort_origin = (!record.origin_done).then(|| record.origin_abort.clone());
            if record.origin_done {
                let record = state
                    .entries
                    .remove(&id)
                    .expect("completed entry remains registered");
                release_reservation(&mut state, record.reservation);
            }
            (shared, abort_origin)
        };
        if let Some(abort) = abort_origin {
            abort.abort();
        }
        shared.terminal_state.store(ENTRY_CLOSED, Ordering::SeqCst);
        shared.closed.notify_waiters();
        self.changed.notify_waiters();
    }

    fn spawn_entry_coordinator<Register>(
        self: &Arc<Self>,
        state: &mut RuntimeState,
        id: u64,
        register: Register,
    ) -> Result<tokio::sync::oneshot::Sender<EntryCoordinatorStart>, OwnedTask>
    where
        Register: FnOnce(&RuntimeInner, OwnedTask) -> Result<(), OwnedTask>,
    {
        let completion = EntryCompletionGuard {
            inner: self.clone(),
            id,
        };
        let coordinator_inner = self.clone();
        let counted = Arc::new(AtomicBool::new(true));
        let task_completion = TrackedTaskCompletion {
            inner: self.clone(),
            counted: counted.clone(),
        };
        let (start, started) = tokio::sync::oneshot::channel::<EntryCoordinatorStart>();
        let task = self.handle.spawn(async move {
            async move {
                let _task_completion = task_completion;
                let _completion = completion;
                let Ok(start) = started.await else {
                    return;
                };
                run_entry_coordinator(coordinator_inner, start.shared, start.snapshot, start.plan)
                    .await;
            }
            .await;
        });
        state.tracked_tasks = state
            .tracked_tasks
            .checked_add(1)
            .expect("tracked task count cannot overflow bounded upgrade metadata");
        if let Err(task) = register(self, OwnedTask::new(task)) {
            if counted.swap(false, Ordering::AcqRel) {
                state.tracked_tasks -= 1;
            }
            return Err(task);
        }
        Ok(start)
    }
}

fn release_reservation(state: &mut RuntimeState, reservation: Reservation) {
    state.reserved_slots = state
        .reserved_slots
        .checked_sub(1)
        .expect("upgrade slot accounting cannot underflow");
    state.reserved_bytes = state
        .reserved_bytes
        .checked_sub(reservation.bytes)
        .expect("upgrade byte accounting cannot underflow");
}

pub(crate) struct UpgradeHandshake {
    inner: Arc<RuntimeInner>,
    id: u64,
    reservation: Reservation,
}

impl fmt::Debug for UpgradeHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpgradeHandshake")
            .field("id", &self.id)
            .field("reservation", &self.reservation)
            .finish()
    }
}

impl UpgradeHandshake {
    #[cfg(test)]
    pub(crate) fn allocation(&self) -> UpgradeAllocation {
        self.reservation.allocation
    }

    #[cfg(test)]
    pub(crate) fn reserved_bytes(&self) -> usize {
        self.reservation.bytes
    }

    /// Commits only while admission remains open. Snapshot construction and
    /// deadline derivation both happen inside the same winning gate.
    pub(crate) fn commit(
        mut self,
        wire_redaction: Option<ProfileHandle>,
        plan: UpgradeEntryPlan,
    ) -> Result<CommittedUpgrade, UpgradeCommitError> {
        self.commit_inner(wire_redaction, plan, || {}, RuntimeInner::track_owned_task)
    }

    #[cfg(test)]
    fn commit_with_start_hook<Hook>(
        &mut self,
        wire_redaction: Option<ProfileHandle>,
        plan: UpgradeEntryPlan,
        after_registration_before_start: Hook,
    ) -> Result<CommittedUpgrade, UpgradeCommitError>
    where
        Hook: FnOnce(),
    {
        self.commit_inner(
            wire_redaction,
            plan,
            after_registration_before_start,
            RuntimeInner::track_owned_task,
        )
    }

    fn commit_inner<Hook, Register>(
        &mut self,
        wire_redaction: Option<ProfileHandle>,
        plan: UpgradeEntryPlan,
        after_registration_before_start: Hook,
        register: Register,
    ) -> Result<CommittedUpgrade, UpgradeCommitError>
    where
        Hook: FnOnce(),
        Register: FnOnce(&RuntimeInner, OwnedTask) -> Result<(), OwnedTask>,
    {
        let mut state = lock(&self.inner.state);
        if !state.accepting {
            return Err(UpgradeCommitError::AdmissionClosed);
        }
        let record = state
            .uncommitted
            .get(&self.id)
            .ok_or(UpgradeCommitError::HandshakeReleased)?;
        debug_assert_eq!(record.reservation, self.reservation);

        let snapshot =
            UpgradedStreamSnapshot::new(self.inner.limits.relay_buffer_bytes, wire_redaction);
        let now = Instant::now();
        let application_stop = now
            .checked_add(self.inner.limits.max_upgrade_lifetime)
            .ok_or(UpgradeCommitError::LifetimeOverflow)?;
        let cleanup_cutoff = application_stop
            .checked_add(self.inner.limits.cleanup_grace)
            .ok_or(UpgradeCommitError::LifetimeOverflow)?;
        let shared = Arc::new(EntryShared {
            timing: Mutex::new(EntryTiming {
                application_stop,
                cleanup_cutoff,
                stop_cause: UpgradeTerminalCause::LifetimeExpired,
            }),
            cleanup_grace: self.inner.limits.cleanup_grace,
            winning_cause: Mutex::new(None),
            setup_state: AtomicU8::new(SETUP_IDLE),
            changed: Notify::new(),
            terminal_state: AtomicU8::new(ENTRY_OPEN),
            closed: Notify::new(),
        });

        let record = state
            .uncommitted
            .remove(&self.id)
            .expect("checked uncommitted handshake remains present");
        state.entries.insert(
            self.id,
            EntryRecord {
                reservation: record.reservation,
                shared: shared.clone(),
                origin_abort: record.abort,
                origin_done: false,
                coordinator_done: false,
            },
        );
        let start = match self
            .inner
            .spawn_entry_coordinator(&mut state, self.id, register)
        {
            Ok(start) => start,
            Err(task) => {
                let record = state
                    .entries
                    .remove(&self.id)
                    .expect("new committed entry remains present");
                release_reservation(&mut state, record.reservation);
                drop(state);
                drop(task);
                return Err(UpgradeCommitError::SupervisorStopped);
            }
        };
        drop(state);
        self.inner.changed.notify_waiters();
        after_registration_before_start();
        let _ = start.send(EntryCoordinatorStart {
            shared: shared.clone(),
            snapshot,
            plan,
        });
        Ok(CommittedUpgrade {
            _inner: self.inner.clone(),
            id: self.id,
            shared,
        })
    }
}

#[derive(Clone)]
pub(crate) struct CommittedUpgrade {
    _inner: Arc<RuntimeInner>,
    id: u64,
    shared: Arc<EntryShared>,
}

impl fmt::Debug for CommittedUpgrade {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedUpgrade")
            .field("id", &self.id)
            .field(
                "terminal_state",
                &self.shared.terminal_state.load(Ordering::SeqCst),
            )
            .field("terminal_cause", &self.terminal_cause())
            .finish()
    }
}

impl CommittedUpgrade {
    #[cfg(test)]
    pub(crate) fn submit_terminal(&self, cause: UpgradeTerminalCause) {
        self.shared
            .begin_closing(cause, Instant::now(), self.shared.cleanup_grace);
    }

    #[cfg(test)]
    pub(crate) async fn wait_closed(&self) {
        loop {
            let notified = self.shared.closed.notified();
            if self.shared.terminal_state.load(Ordering::SeqCst) == ENTRY_CLOSED {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn terminal_cause(&self) -> Option<UpgradeTerminalCause> {
        *lock(&self.shared.winning_cause)
    }

    #[cfg(test)]
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    #[cfg(test)]
    fn timing(&self) -> EntryTiming {
        *lock(&self.shared.timing)
    }
}

impl EntryShared {
    fn lower_for_shutdown(&self, deadline: Instant) {
        {
            let mut timing = lock(&self.timing);
            if deadline <= timing.application_stop {
                timing.application_stop = deadline;
                timing.stop_cause = UpgradeTerminalCause::Shutdown;
            }
            timing.cleanup_cutoff = timing.cleanup_cutoff.min(deadline);
        }
        self.changed.notify_waiters();
    }

    fn begin_closing(&self, cause: UpgradeTerminalCause, now: Instant, cleanup_grace: Duration) {
        if self
            .terminal_state
            .compare_exchange(
                ENTRY_OPEN,
                ENTRY_CLOSE_REQUESTED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_err()
        {
            return;
        }
        *lock(&self.winning_cause) = Some(cause);
        let cause_cutoff = now.checked_add(cleanup_grace).unwrap_or(now);
        let mut timing = lock(&self.timing);
        timing.application_stop = timing.application_stop.min(now);
        timing.cleanup_cutoff = timing.cleanup_cutoff.min(cause_cutoff);
        drop(timing);
        if self
            .terminal_state
            .compare_exchange(
                ENTRY_CLOSE_REQUESTED,
                ENTRY_CLOSE_WAITING_SETUP,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            self.finish_close_request();
        }
    }

    fn finish_close_request(&self) {
        if self.setup_state.load(Ordering::SeqCst) == SETUP_POLLING {
            return;
        }
        if self
            .terminal_state
            .compare_exchange(
                ENTRY_CLOSE_WAITING_SETUP,
                ENTRY_CLOSING,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            self.changed.notify_waiters();
        }
    }
}

struct EntryCompletionGuard {
    inner: Arc<RuntimeInner>,
    id: u64,
}

struct EntryCoordinatorStart {
    shared: Arc<EntryShared>,
    snapshot: UpgradedStreamSnapshot,
    plan: UpgradeEntryPlan,
}

impl Drop for EntryCompletionGuard {
    fn drop(&mut self) {
        self.inner.close_entry(self.id);
    }
}

async fn run_task_supervisor(mut receiver: mpsc::UnboundedReceiver<SupervisorCommand>) {
    let mut tasks = JoinSet::new();
    let mut aborts = HashMap::<TaskId, AbortHandle>::new();
    let mut join_waiters =
        HashMap::<TaskId, oneshot::Sender<Result<(), tokio::task::JoinError>>>::new();
    let mut stopping = false;
    loop {
        if stopping && tasks.is_empty() {
            return;
        }
        tokio::select! {
            biased;
            joined = tasks.join_next_with_id(), if !tasks.is_empty() => {
                let joined = joined.expect("non-empty supervisor task set yields a task");
                let (id, completion, result) = match joined {
                    Ok((id, completion)) => (id, Some(completion), Ok(())),
                    Err(error) => (error.id(), None, Err(error)),
                };
                let tracked_id = match completion {
                    Some(SupervisorTaskCompletion::Tracked(id)) => Some(id),
                    Some(SupervisorTaskCompletion::Joinable) | None => None,
                };
                aborts.remove(&tracked_id.unwrap_or(id));
                if let Some(waiter) = join_waiters.remove(&id) {
                    if let Err(Err(error)) = waiter.send(result) {
                        if !error.is_cancelled() {
                            tracing::error!(%error, "unobserved upgrade raw teardown task failure");
                        }
                    }
                } else if let Err(error) = result {
                    if !error.is_cancelled() {
                        tracing::error!(%error, "upgrade supervisor task failed");
                    }
                }
            }
            command = receiver.recv(), if !stopping => {
                match command {
                    Some(SupervisorCommand::Track(task)) => {
                        let id = task.id();
                        let replaced = aborts.insert(id, task.abort_handle());
                        debug_assert!(replaced.is_none(), "Tokio task identifiers are unique");
                        tasks.spawn(async move {
                            task.await;
                            SupervisorTaskCompletion::Tracked(id)
                        });
                    }
                    Some(SupervisorCommand::SpawnJoinable {
                        task,
                        joined,
                        started,
                        before_start,
                    }) => {
                        before_start();
                        let abort = tasks.spawn(async move {
                            task.await;
                            SupervisorTaskCompletion::Joinable
                        });
                        let id = abort.id();
                        let replaced = aborts.insert(id, abort);
                        debug_assert!(replaced.is_none(), "Tokio task identifiers are unique");
                        let replaced = join_waiters.insert(id, joined);
                        debug_assert!(replaced.is_none(), "joinable task identifiers are unique");
                        let _ = started.send(());
                    }
                    Some(SupervisorCommand::Stop) | None => {
                        for abort in aborts.values() {
                            abort.abort();
                        }
                        stopping = true;
                    }
                }
            }
        }
    }
}

fn handle_entry_task_completion(
    shared: &EntryShared,
    cleanup_grace: Duration,
    tasks: &mut JoinSet<EntryTaskResult>,
    phase: &mut EntryPhase,
    joined: Result<EntryTaskResult, tokio::task::JoinError>,
) {
    match (*phase, joined) {
        (EntryPhase::Establishing, Ok(EntryTaskResult::Setup(Ok(pair)))) => {
            *phase = EntryPhase::Established;
            let mut pair = Some(pair);
            let rejected = {
                let timing = lock(&shared.timing);
                let now = Instant::now();
                if shared.terminal_state.load(Ordering::SeqCst) == ENTRY_OPEN
                    && now < timing.application_stop
                {
                    let pair = pair.take().expect("relay pair is promoted once");
                    tasks.spawn(async move { EntryTaskResult::Relay(pair.relay.await) });
                    None
                } else if shared.terminal_state.load(Ordering::SeqCst) == ENTRY_OPEN
                    && now >= timing.application_stop
                {
                    Some((timing.stop_cause, timing.application_stop))
                } else {
                    None
                }
            };
            drop(pair);
            if let Some((cause, at)) = rejected {
                shared.begin_closing(cause, at, cleanup_grace);
            }
        }
        (EntryPhase::Establishing, Ok(EntryTaskResult::Setup(Err(cause)))) => {
            shared.begin_closing(cause, Instant::now(), cleanup_grace);
        }
        (EntryPhase::Establishing, Err(_)) => {
            shared.begin_closing(
                UpgradeTerminalCause::SetupFailed,
                Instant::now(),
                cleanup_grace,
            );
        }
        (EntryPhase::Established, Ok(EntryTaskResult::Relay(cause))) => {
            shared.begin_closing(cause, Instant::now(), cleanup_grace);
        }
        (EntryPhase::Established, Err(_)) => {
            shared.begin_closing(
                UpgradeTerminalCause::RelayError,
                Instant::now(),
                cleanup_grace,
            );
        }
        (_, Ok(EntryTaskResult::TerminalControl))
        | (_, Ok(EntryTaskResult::Setup(_)))
        | (_, Ok(EntryTaskResult::Relay(_))) => {}
    }
}

async fn finish_entry_cleanup_with_hook<Hook>(
    shared: &EntryShared,
    tasks: &mut JoinSet<EntryTaskResult>,
    established: bool,
    terminal_control: ActiveUpgradeTerminalControl,
    cause: UpgradeTerminalCause,
    before_close_authorization: Hook,
) where
    Hook: FnOnce(),
{
    let (raw_teardown, established_close) = terminal_control.into_parts();
    tasks.shutdown().await;
    'cleanup: {
        if !established {
            break 'cleanup;
        }
        if Instant::now() >= lock(&shared.timing).cleanup_cutoff {
            tasks.shutdown().await;
            break 'cleanup;
        }
        before_close_authorization();
        let mut established_close = Some(established_close);
        let admitted = {
            let timing = lock(&shared.timing);
            if Instant::now() >= timing.cleanup_cutoff {
                false
            } else {
                let established_close = established_close
                    .take()
                    .expect("established close is admitted once");
                tasks.spawn(async move {
                    established_close(cause).await;
                    EntryTaskResult::TerminalControl
                });
                true
            }
        };
        if !admitted {
            drop(established_close);
            tasks.shutdown().await;
            break 'cleanup;
        }
        while !tasks.is_empty() {
            let changed = shared.changed.notified();
            let cutoff = lock(&shared.timing).cleanup_cutoff;
            if Instant::now() >= cutoff {
                tasks.shutdown().await;
                break 'cleanup;
            }
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(cutoff) => {
                    tasks.shutdown().await;
                    break 'cleanup;
                }
                joined = tasks.join_next() => {
                    let _ = joined;
                }
                _ = changed => {}
            }
        }
    }
    raw_teardown.abort_and_join().await;
}

async fn run_entry_coordinator(
    inner: Arc<RuntimeInner>,
    shared: Arc<EntryShared>,
    snapshot: UpgradedStreamSnapshot,
    plan: UpgradeEntryPlan,
) {
    run_entry_coordinator_with_hooks(inner, shared, snapshot, plan, || {}, || {}, || {}).await;
}

async fn run_entry_coordinator_with_hooks<RawHook, SetupHook, CloseHook>(
    inner: Arc<RuntimeInner>,
    shared: Arc<EntryShared>,
    snapshot: UpgradedStreamSnapshot,
    plan: UpgradeEntryPlan,
    before_raw_start: RawHook,
    before_setup_authorization: SetupHook,
    before_close_authorization: CloseHook,
) where
    RawHook: FnOnce() + Send + 'static,
    SetupHook: FnOnce(),
    CloseHook: FnOnce(),
{
    let cleanup_grace = shared.cleanup_grace;
    let mut tasks = JoinSet::new();
    let mut phase = EntryPhase::Establishing;
    let mut terminal_control = match plan
        .terminal_control
        .activate_with_hook(&inner, before_raw_start)
        .await
    {
        Ok(control) => Some(control),
        Err(()) => {
            let cause = match lock(&shared.timing).stop_cause {
                UpgradeTerminalCause::Shutdown => UpgradeTerminalCause::Shutdown,
                _ => UpgradeTerminalCause::SetupFailed,
            };
            shared.begin_closing(cause, Instant::now(), cleanup_grace);
            return;
        }
    };
    let mut pending_setup = Some((plan.setup, snapshot));
    let mut before_setup_authorization = Some(before_setup_authorization);
    let mut before_close_authorization = Some(before_close_authorization);

    loop {
        while let Some(joined) = tasks.try_join_next() {
            handle_entry_task_completion(&shared, cleanup_grace, &mut tasks, &mut phase, joined);
        }
        let changed = shared.changed.notified();
        if shared.terminal_state.load(Ordering::SeqCst) == ENTRY_OPEN {
            let timing = *lock(&shared.timing);
            if Instant::now() >= timing.application_stop {
                shared.begin_closing(timing.stop_cause, timing.application_stop, cleanup_grace);
            }
        }

        if shared.terminal_state.load(Ordering::SeqCst) == ENTRY_CLOSING {
            let cause =
                lock(&shared.winning_cause).expect("closing entry has a winning terminal cause");
            let established = phase == EntryPhase::Established
                || shared.setup_state.load(Ordering::SeqCst) == SETUP_SUCCEEDED;
            let control = terminal_control
                .take()
                .expect("entry cleanup owns terminal control");
            finish_entry_cleanup_with_hook(
                &shared,
                &mut tasks,
                established,
                control,
                cause,
                before_close_authorization
                    .take()
                    .expect("entry cleanup is entered once"),
            )
            .await;
            return;
        }

        match shared.terminal_state.load(Ordering::SeqCst) {
            ENTRY_CLOSE_REQUESTED | ENTRY_CLOSE_WAITING_SETUP => {
                changed.await;
                continue;
            }
            ENTRY_CLOSED => return,
            _ => {}
        }

        if let Some((build, snapshot)) = pending_setup.take() {
            before_setup_authorization
                .take()
                .expect("setup authorization is attempted once")();
            let mut pending = Some((build, snapshot));
            let (admitted, stop) = {
                let timing = lock(&shared.timing);
                if shared.terminal_state.load(Ordering::SeqCst) == ENTRY_OPEN
                    && Instant::now() < timing.application_stop
                {
                    let (build, snapshot) = pending.take().expect("setup is admitted once");
                    let setup_shared = shared.clone();
                    tasks.spawn(async move {
                        let setup = LinearizedSetupTask {
                            shared: setup_shared,
                            build: Some(build),
                            snapshot: Some(snapshot),
                            setup: None,
                        };
                        EntryTaskResult::Setup(setup.await)
                    });
                    (true, None)
                } else {
                    (false, Some(*timing))
                }
            };
            drop(pending);
            if !admitted {
                if shared.terminal_state.load(Ordering::SeqCst) == ENTRY_OPEN {
                    let timing = stop.expect("rejected setup has terminal timing");
                    shared.begin_closing(timing.stop_cause, timing.application_stop, cleanup_grace);
                }
                continue;
            }
        }

        let timing = *lock(&shared.timing);
        tokio::select! {
            biased;
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(joined) = joined {
                    handle_entry_task_completion(
                        &shared,
                        cleanup_grace,
                        &mut tasks,
                        &mut phase,
                        joined,
                    );
                }
            }
            _ = tokio::time::sleep_until(timing.cleanup_cutoff) => {
                shared.begin_closing(
                    timing.stop_cause,
                    timing.application_stop,
                    cleanup_grace,
                );
            }
            _ = tokio::time::sleep_until(timing.application_stop) => {
                shared.begin_closing(
                    timing.stop_cause,
                    timing.application_stop,
                    cleanup_grace,
                );
            }
            _ = changed => {}
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UpgradeRuntimeCounts {
    pub(crate) maximum_slots: usize,
    pub(crate) maximum_bytes: usize,
    pub(crate) reserved_slots: usize,
    pub(crate) reserved_bytes: usize,
    pub(crate) uncommitted: usize,
    pub(crate) committed: usize,
    pub(crate) tracked_tasks: usize,
    pub(crate) accepting: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum UpgradeRuntimeError {
    #[error("upgrade runtime requires at least one active slot")]
    ZeroActiveUpgrades,
    #[error("upgrade runtime requires a positive aggregate buffer limit")]
    ZeroBufferBytes,
    #[error("upgrade runtime requires a positive relay buffer size")]
    ZeroRelayBufferBytes,
    #[error("upgrade runtime requires a positive maximum lifetime")]
    ZeroLifetime,
    #[error("two relay buffers overflow addressable capacity")]
    RelayCapacityOverflow,
    #[error("baseline relay capacity multiplication overflowed")]
    BaselineCapacityOverflow,
    #[error("aggregate buffer capacity cannot hold every admitted stream's relay buffers")]
    InsufficientBaselineCapacity,
    #[error("upgrade lifetime arithmetic overflowed")]
    LifetimeOverflow,
    #[error("upgrade runtime construction requires an active Tokio runtime")]
    RuntimeUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum UpgradeAdmissionError {
    #[error("upgrade admission is closed")]
    Closed,
    #[error("active upgrade capacity is exhausted")]
    SlotCapacity,
    #[error("upgrade buffer capacity is exhausted")]
    BufferCapacity,
    #[error("upgrade admission identifier space is exhausted")]
    IdentifierExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum UpgradeHandshakeSpawnError {
    #[error(transparent)]
    Admission(#[from] UpgradeAdmissionError),
    #[error("the upgrade task supervisor stopped")]
    SupervisorStopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum UpgradeCommitError {
    #[error("upgrade admission closed before commit")]
    AdmissionClosed,
    #[error("the runtime-owned upgrade handshake was already released")]
    HandshakeReleased,
    #[error("upgrade lifetime arithmetic overflowed")]
    LifetimeOverflow,
    #[error("the upgrade task supervisor stopped")]
    SupervisorStopped,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc as std_mpsc;
    use std::thread;

    use tokio::sync::oneshot;

    use super::*;
    use crate::config::compiler::{
        CompiledRedactionPayloads, RedactionPlan, RedactionProfilePlan, RedactionRulePlan,
    };
    use crate::redaction::{PayloadClass, RedactionSnapshot};

    fn limits(slots: usize, bytes: usize) -> UpgradeRuntimeLimits {
        UpgradeRuntimeLimits::new(slots, bytes, 2, Duration::from_secs(60))
    }

    fn short_limits(lifetime: Duration, cleanup: Duration) -> UpgradeRuntimeLimits {
        UpgradeRuntimeLimits::new(2, 64, 2, lifetime).with_cleanup_grace(cleanup)
    }

    fn allocation(rule: usize, wire_bytes: usize) -> UpgradeAllocation {
        UpgradeAllocation::from_compiled_rule(rule, Some(wire_bytes)).unwrap()
    }

    fn inert_raw_teardown() -> impl FnOnce() -> std::future::Pending<()> + Send + 'static {
        std::future::pending::<()>
    }

    fn inert_control() -> UpgradeTerminalControl {
        UpgradeTerminalControl::new(inert_raw_teardown(), |_| async {})
    }

    fn plan<Build, Setup>(build: Build) -> UpgradeEntryPlan
    where
        Build: FnOnce(UpgradedStreamSnapshot) -> Setup + Send + 'static,
        Setup: Future<Output = Result<UpgradeRelayPair, UpgradeTerminalCause>> + Send + 'static,
    {
        UpgradeEntryPlan::new(inert_control(), build)
    }

    fn parked_plan() -> UpgradeEntryPlan {
        plan(|_| async {
            std::future::pending::<Result<UpgradeRelayPair, UpgradeTerminalCause>>().await
        })
    }

    fn wire_profile(replacement: &[u8], literal: &[u8]) -> ProfileHandle {
        RedactionSnapshot::activate(
            RedactionPlan {
                profiles: BTreeMap::from([(
                    "wire".to_owned(),
                    RedactionProfilePlan {
                        replacement: replacement.to_vec(),
                        max_body_bytes: 1024,
                        max_decoded_body_bytes: 1024,
                        max_frame_bytes: 1024,
                        max_message_bytes: 1024,
                        allow_permessage_deflate: false,
                        max_environment_literal_sources: 0,
                        max_environment_literal_bytes: 1,
                        max_environment_literal_total_bytes: 1,
                        rules: vec![RedactionRulePlan {
                            literals: vec![literal.to_vec()],
                            literal_environment_variables: Vec::new(),
                            expressions: Vec::new(),
                            payloads: CompiledRedactionPayloads::Both,
                        }],
                    },
                )]),
            },
            || false,
        )
        .unwrap()
        .profile("wire")
        .unwrap()
    }

    async fn wait_for_counts(
        runtime: &UpgradeRuntime,
        predicate: impl Fn(UpgradeRuntimeCounts) -> bool,
    ) -> UpgradeRuntimeCounts {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let notified = runtime.inner.changed.notified();
                let counts = runtime.counts();
                if predicate(counts) {
                    return counts;
                }
                notified.await;
            }
        })
        .await
        .expect("upgrade runtime counts did not converge")
    }

    #[test]
    fn constructor_binds_baseline_relay_capacity() {
        assert_eq!(
            validate_limits(UpgradeRuntimeLimits::new(
                1,
                usize::MAX,
                usize::MAX,
                Duration::from_secs(1),
            )),
            Err(UpgradeRuntimeError::RelayCapacityOverflow)
        );
        assert_eq!(
            validate_limits(UpgradeRuntimeLimits::new(
                usize::MAX,
                usize::MAX,
                1,
                Duration::from_secs(1),
            )),
            Err(UpgradeRuntimeError::BaselineCapacityOverflow)
        );
        assert_eq!(
            validate_limits(UpgradeRuntimeLimits::new(2, 11, 3, Duration::from_secs(1),)),
            Err(UpgradeRuntimeError::InsufficientBaselineCapacity)
        );
    }

    #[tokio::test]
    async fn upgrade_admission_and_relay_bounds() {
        assert_eq!(
            UpgradeAllocation::from_compiled_rule(0, None),
            Err(UpgradeAllocationError::RuleDisallowsUpgrades)
        );
        assert_eq!(allocation(0, 0).wire_bytes(), 0);

        let slot_runtime = UpgradeRuntime::try_new(limits(1, 64)).unwrap();
        let (release_tx, release_rx) = oneshot::channel();
        slot_runtime
            .try_spawn_handshake(allocation(0, 0), move |handshake| async move {
                assert_eq!(handshake.reserved_bytes(), 4);
                let _ = release_rx.await;
            })
            .unwrap();
        assert_eq!(slot_runtime.counts().reserved_bytes, 4);
        assert_eq!(
            slot_runtime
                .try_spawn_handshake(allocation(1, 0), |_| async {})
                .unwrap_err(),
            UpgradeHandshakeSpawnError::Admission(UpgradeAdmissionError::SlotCapacity)
        );
        let _ = release_tx.send(());
        wait_for_counts(&slot_runtime, |counts| counts.reserved_slots == 0).await;
        slot_runtime.shutdown_and_wait(Some(Instant::now())).await;

        let byte_runtime = UpgradeRuntime::try_new(limits(2, 8)).unwrap();
        let (release_tx, release_rx) = oneshot::channel();
        byte_runtime
            .try_spawn_handshake(allocation(0, 1), move |_| async move {
                let _ = release_rx.await;
            })
            .unwrap();
        assert_eq!(byte_runtime.counts().reserved_bytes, 5);
        assert_eq!(
            byte_runtime
                .try_spawn_handshake(allocation(1, 0), |_| async {})
                .unwrap_err(),
            UpgradeHandshakeSpawnError::Admission(UpgradeAdmissionError::BufferCapacity)
        );
        let _ = release_tx.send(());
        wait_for_counts(&byte_runtime, |counts| counts.reserved_slots == 0).await;
        byte_runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handshake_cannot_poll_before_atomic_registration() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let polled = Arc::new(AtomicUsize::new(0));
        runtime
            .try_spawn_handshake_with_hook(
                allocation(0, 0),
                {
                    let polled = polled.clone();
                    move |_| async move {
                        polled.fetch_add(1, Ordering::SeqCst);
                    }
                },
                || {
                    thread::sleep(Duration::from_millis(20));
                    assert_eq!(polled.load(Ordering::SeqCst), 0);
                },
            )
            .unwrap();
        wait_for_counts(&runtime, |counts| {
            counts.reserved_slots == 0 && counts.tracked_tasks == 0
        })
        .await;
        assert_eq!(polled.load(Ordering::SeqCst), 1);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test]
    async fn identifier_exhaustion_is_mutation_free() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        lock(&runtime.inner.state).next_id = u64::MAX;
        let before = runtime.counts();
        assert_eq!(
            runtime
                .try_spawn_handshake(allocation(0, 0), |_| async {})
                .unwrap_err(),
            UpgradeHandshakeSpawnError::Admission(UpgradeAdmissionError::IdentifierExhausted)
        );
        assert_eq!(runtime.counts(), before);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    struct DropCount(Arc<AtomicUsize>);

    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct DropSignal(Option<oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(signal) = self.0.take() {
                let _ = signal.send(());
            }
        }
    }

    struct BlockingDrop {
        started: Option<std_mpsc::Sender<()>>,
        release: std_mpsc::Receiver<()>,
        completed: Arc<AtomicUsize>,
    }

    impl Drop for BlockingDrop {
        fn drop(&mut self) {
            if let Some(started) = self.started.take() {
                let _ = started.send(());
            }
            let _ = self.release.recv();
            self.completed.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn raw_teardown_with_guard(
        guard: impl Send + 'static,
    ) -> impl FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> + Send + 'static {
        move || {
            Box::pin(async move {
                let _guard = guard;
                std::future::pending::<()>().await;
            })
        }
    }

    fn counted_raw_teardown_with_guard(
        guard: impl Send + 'static,
        polls: Arc<AtomicUsize>,
    ) -> impl FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> + Send + 'static {
        move || {
            Box::pin(async move {
                let _guard = guard;
                polls.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<()>().await;
            })
        }
    }

    #[tokio::test]
    async fn handshake_task_releases_admission_on_pre101_failure() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        runtime
            .try_spawn_handshake(allocation(0, 0), |handshake| async move {
                assert_eq!(handshake.allocation().rule_index(), 0);
            })
            .unwrap();
        wait_for_counts(&runtime, |counts| {
            counts.reserved_slots == 0 && counts.tracked_tasks == 0
        })
        .await;
        tokio::time::timeout(
            Duration::from_secs(2),
            runtime.shutdown_and_wait(Some(Instant::now())),
        )
        .await
        .unwrap_or_else(|_| panic!("shutdown did not drain: {:?}", runtime.counts()));
    }

    #[tokio::test]
    async fn shutdown_aborts_and_joins_parked_uncommitted_handshake() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let drop_count = DropCount(dropped.clone());
        let (started_tx, started_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), move |_| async move {
                let _drop = drop_count;
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            })
            .unwrap();
        started_rx.await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            runtime.shutdown_and_wait(Some(Instant::now())),
        )
        .await
        .unwrap_or_else(|_| panic!("shutdown did not drain: {:?}", runtime.counts()));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.counts().reserved_bytes, 0);
        assert_eq!(runtime.counts().tracked_tasks, 0);
    }

    #[tokio::test]
    async fn shutdown_waiter_cancellation_retry_joins_same_supervisor() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let (locked_tx, locked_rx) = oneshot::channel();
        let first_runtime = runtime.clone();
        let first = tokio::spawn(async move {
            first_runtime
                .shutdown_and_wait_with_hook(Some(Instant::now()), async move {
                    let _ = locked_tx.send(());
                    std::future::pending::<()>().await;
                })
                .await;
        });

        locked_rx.await.unwrap();
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert!(runtime.supervisor.lock().await.is_some());

        tokio::time::timeout(
            Duration::from_secs(2),
            runtime.shutdown_and_wait(Some(Instant::now())),
        )
        .await
        .expect("shutdown retry did not rejoin the durable supervisor");
        assert!(runtime.supervisor.lock().await.is_none());
        assert_eq!(runtime.counts().tracked_tasks, 0);
    }

    #[tokio::test]
    async fn runtime_drop_aborts_every_owned_task() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let (started_tx, started_rx) = oneshot::channel();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), move |_| async move {
                let _drop = DropSignal(Some(dropped_tx));
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            })
            .unwrap();
        started_rx.await.unwrap();
        drop(runtime);
        tokio::time::timeout(Duration::from_secs(2), dropped_rx)
            .await
            .expect("runtime drop detached a tracked task")
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn runtime_drop_drains_supervised_raw_teardown() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let raw_drops = Arc::new(AtomicUsize::new(0));
        let (raw_dropped_tx, raw_dropped_rx) = oneshot::channel();
        let (setup_started_tx, setup_started_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let raw_drops = raw_drops.clone();
                move |handshake| async move {
                    handshake
                        .commit(
                            None,
                            UpgradeEntryPlan::new(
                                UpgradeTerminalControl::new(
                                    raw_teardown_with_guard((
                                        DropCount(raw_drops),
                                        DropSignal(Some(raw_dropped_tx)),
                                    )),
                                    |_| async {},
                                ),
                                move |_| async move {
                                    let _ = setup_started_tx.send(());
                                    std::future::pending::<
                                        Result<UpgradeRelayPair, UpgradeTerminalCause>,
                                    >()
                                    .await
                                },
                            ),
                        )
                        .unwrap();
                }
            })
            .unwrap();
        setup_started_rx.await.unwrap();

        drop(runtime);

        tokio::time::timeout(Duration::from_secs(2), raw_dropped_rx)
            .await
            .expect("runtime drop abandoned a supervised raw teardown")
            .unwrap();
        assert_eq!(raw_drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn runtime_drop_wins_against_inflight_commit_before_coordinator_registration() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let setup_polls = Arc::new(AtomicUsize::new(0));
        let raw_polls = Arc::new(AtomicUsize::new(0));
        let raw_drops = Arc::new(AtomicUsize::new(0));
        let (commit_entered_tx, commit_entered_rx) = std_mpsc::channel();
        let (commit_release_tx, commit_release_rx) = std_mpsc::channel();
        let (result_tx, result_rx) = std_mpsc::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let setup_polls = setup_polls.clone();
                let raw_polls = raw_polls.clone();
                let raw_drops = raw_drops.clone();
                move |handshake| async move {
                    commit_entered_tx.send(()).unwrap();
                    commit_release_rx.recv().unwrap();
                    let result = handshake.commit(
                        None,
                        UpgradeEntryPlan::new(
                            UpgradeTerminalControl::new(
                                counted_raw_teardown_with_guard(DropCount(raw_drops), raw_polls),
                                |_| async {},
                            ),
                            move |_| async move {
                                setup_polls.fetch_add(1, Ordering::SeqCst);
                                Err(UpgradeTerminalCause::SetupFailed)
                            },
                        ),
                    );
                    result_tx.send(result.map(|_| ())).unwrap();
                }
            })
            .unwrap();
        commit_entered_rx.recv().unwrap();

        drop(runtime);
        commit_release_tx.send(()).unwrap();

        assert_eq!(
            result_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Err(UpgradeCommitError::AdmissionClosed)
        );
        assert_eq!(setup_polls.load(Ordering::SeqCst), 0);
        assert_eq!(raw_polls.load(Ordering::SeqCst), 0);
        assert_eq!(raw_drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn inflight_commit_registration_precedes_runtime_drop_stop_and_drains() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let setup_polls = Arc::new(AtomicUsize::new(0));
        let raw_polls = Arc::new(AtomicUsize::new(0));
        let raw_drops = Arc::new(AtomicUsize::new(0));
        let (raw_dropped_tx, raw_dropped_rx) = oneshot::channel();
        let (registered_tx, registered_rx) = std_mpsc::channel();
        let (commit_release_tx, commit_release_rx) = std_mpsc::channel();
        let (result_tx, result_rx) = std_mpsc::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let setup_polls = setup_polls.clone();
                let raw_polls = raw_polls.clone();
                let raw_drops = raw_drops.clone();
                move |mut handshake| async move {
                    let result = handshake.commit_with_start_hook(
                        None,
                        UpgradeEntryPlan::new(
                            UpgradeTerminalControl::new(
                                counted_raw_teardown_with_guard(
                                    (DropCount(raw_drops), DropSignal(Some(raw_dropped_tx))),
                                    raw_polls,
                                ),
                                |_| async {},
                            ),
                            move |_| async move {
                                setup_polls.fetch_add(1, Ordering::SeqCst);
                                Err(UpgradeTerminalCause::SetupFailed)
                            },
                        ),
                        || {
                            registered_tx.send(()).unwrap();
                            commit_release_rx.recv().unwrap();
                        },
                    );
                    result_tx.send(result).unwrap();
                }
            })
            .unwrap();
        registered_rx.recv().unwrap();

        drop(runtime);
        commit_release_tx.send(()).unwrap();

        let entry = result_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .expect("commit that registered before Drop remains committed");
        tokio::time::timeout(Duration::from_secs(1), entry.wait_closed())
            .await
            .expect("runtime Drop detached the registered coordinator");
        tokio::time::timeout(Duration::from_secs(1), raw_dropped_rx)
            .await
            .expect("runtime Drop detached the registered terminal plan")
            .unwrap();
        assert_eq!(setup_polls.load(Ordering::SeqCst), 0);
        assert_eq!(raw_polls.load(Ordering::SeqCst), 0);
        assert_eq!(raw_drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn coordinator_panic_leaves_raw_teardown_joinable_by_supervisor() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let raw_drops = Arc::new(AtomicUsize::new(0));
        let now = Instant::now();
        let shared = Arc::new(EntryShared {
            timing: Mutex::new(EntryTiming {
                application_stop: now + Duration::from_secs(1),
                cleanup_cutoff: now + Duration::from_secs(2),
                stop_cause: UpgradeTerminalCause::LifetimeExpired,
            }),
            cleanup_grace: Duration::from_millis(100),
            winning_cause: Mutex::new(None),
            setup_state: AtomicU8::new(SETUP_IDLE),
            changed: Notify::new(),
            terminal_state: AtomicU8::new(ENTRY_OPEN),
            closed: Notify::new(),
        });
        let coordinator = tokio::spawn(run_entry_coordinator_with_hooks(
            runtime.inner.clone(),
            shared,
            UpgradedStreamSnapshot::new(2, None),
            UpgradeEntryPlan::new(
                UpgradeTerminalControl::new(
                    raw_teardown_with_guard(DropCount(raw_drops.clone())),
                    |_| async {},
                ),
                |_| async {
                    std::future::pending::<Result<UpgradeRelayPair, UpgradeTerminalCause>>().await
                },
            ),
            || {},
            || panic!("coordinator authorization panic"),
            || {},
        ));

        let error = coordinator.await.unwrap_err();
        assert!(error.is_panic());
        wait_for_counts(&runtime, |counts| counts.tracked_tasks == 0).await;
        assert_eq!(raw_drops.load(Ordering::SeqCst), 1);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn coordinator_abort_leaves_raw_teardown_joinable_by_supervisor() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let raw_drops = Arc::new(AtomicUsize::new(0));
        let (setup_started_tx, setup_started_rx) = oneshot::channel();
        let now = Instant::now();
        let shared = Arc::new(EntryShared {
            timing: Mutex::new(EntryTiming {
                application_stop: now + Duration::from_secs(1),
                cleanup_cutoff: now + Duration::from_secs(2),
                stop_cause: UpgradeTerminalCause::LifetimeExpired,
            }),
            cleanup_grace: Duration::from_millis(100),
            winning_cause: Mutex::new(None),
            setup_state: AtomicU8::new(SETUP_IDLE),
            changed: Notify::new(),
            terminal_state: AtomicU8::new(ENTRY_OPEN),
            closed: Notify::new(),
        });
        let coordinator = tokio::spawn(run_entry_coordinator(
            runtime.inner.clone(),
            shared,
            UpgradedStreamSnapshot::new(2, None),
            UpgradeEntryPlan::new(
                UpgradeTerminalControl::new(
                    raw_teardown_with_guard(DropCount(raw_drops.clone())),
                    |_| async {},
                ),
                move |_| async move {
                    let _ = setup_started_tx.send(());
                    std::future::pending::<Result<UpgradeRelayPair, UpgradeTerminalCause>>().await
                },
            ),
        ));
        setup_started_rx.await.unwrap();

        coordinator.abort();
        assert!(coordinator.await.unwrap_err().is_cancelled());
        wait_for_counts(&runtime, |counts| counts.tracked_tasks == 0).await;
        assert_eq!(raw_drops.load(Ordering::SeqCst), 1);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn setup_waits_for_supervisor_raw_registration_acknowledgment() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let setup_polls = Arc::new(AtomicUsize::new(0));
        let raw_polls = Arc::new(AtomicUsize::new(0));
        let raw_drops = Arc::new(AtomicUsize::new(0));
        let now = Instant::now();
        let shared = Arc::new(EntryShared {
            timing: Mutex::new(EntryTiming {
                application_stop: now + Duration::from_secs(1),
                cleanup_cutoff: now + Duration::from_secs(2),
                stop_cause: UpgradeTerminalCause::LifetimeExpired,
            }),
            cleanup_grace: Duration::from_millis(100),
            winning_cause: Mutex::new(None),
            setup_state: AtomicU8::new(SETUP_IDLE),
            changed: Notify::new(),
            terminal_state: AtomicU8::new(ENTRY_OPEN),
            closed: Notify::new(),
        });
        let (registration_tx, registration_rx) = std_mpsc::channel();
        let (registration_release_tx, registration_release_rx) = std_mpsc::channel();
        let coordinator = tokio::spawn(run_entry_coordinator_with_hooks(
            runtime.inner.clone(),
            shared,
            UpgradedStreamSnapshot::new(2, None),
            UpgradeEntryPlan::new(
                UpgradeTerminalControl::new(
                    counted_raw_teardown_with_guard(
                        DropCount(raw_drops.clone()),
                        raw_polls.clone(),
                    ),
                    |_| async {},
                ),
                {
                    let setup_polls = setup_polls.clone();
                    move |_| async move {
                        setup_polls.fetch_add(1, Ordering::SeqCst);
                        Err(UpgradeTerminalCause::SetupFailed)
                    }
                },
            ),
            move || {
                registration_tx.send(()).unwrap();
                registration_release_rx.recv().unwrap();
            },
            || {},
            || {},
        ));

        registration_rx.recv().unwrap();
        tokio::task::yield_now().await;
        assert_eq!(setup_polls.load(Ordering::SeqCst), 0);
        assert_eq!(raw_polls.load(Ordering::SeqCst), 0);
        registration_release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), coordinator)
            .await
            .expect("coordinator did not continue after raw registration")
            .unwrap();
        assert_eq!(setup_polls.load(Ordering::SeqCst), 1);
        assert_eq!(raw_drops.load(Ordering::SeqCst), 1);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test]
    async fn stopped_supervisor_preserves_shutdown_stamp_or_uses_setup_failure_fallback() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        runtime.shutdown_and_wait(Some(Instant::now())).await;
        for (shutdown_stamped, expected) in [
            (true, UpgradeTerminalCause::Shutdown),
            (false, UpgradeTerminalCause::SetupFailed),
        ] {
            let setup_polls = Arc::new(AtomicUsize::new(0));
            let raw_polls = Arc::new(AtomicUsize::new(0));
            let raw_drops = Arc::new(AtomicUsize::new(0));
            let now = Instant::now();
            let shared = Arc::new(EntryShared {
                timing: Mutex::new(EntryTiming {
                    application_stop: now + Duration::from_secs(1),
                    cleanup_cutoff: now + Duration::from_secs(2),
                    stop_cause: UpgradeTerminalCause::LifetimeExpired,
                }),
                cleanup_grace: Duration::from_millis(100),
                winning_cause: Mutex::new(None),
                setup_state: AtomicU8::new(SETUP_IDLE),
                changed: Notify::new(),
                terminal_state: AtomicU8::new(ENTRY_OPEN),
                closed: Notify::new(),
            });
            if shutdown_stamped {
                shared.lower_for_shutdown(now);
            }

            run_entry_coordinator(
                runtime.inner.clone(),
                shared.clone(),
                UpgradedStreamSnapshot::new(2, None),
                UpgradeEntryPlan::new(
                    UpgradeTerminalControl::new(
                        counted_raw_teardown_with_guard(
                            DropCount(raw_drops.clone()),
                            raw_polls.clone(),
                        ),
                        |_| async {},
                    ),
                    {
                        let setup_polls = setup_polls.clone();
                        move |_| async move {
                            setup_polls.fetch_add(1, Ordering::SeqCst);
                            Err(UpgradeTerminalCause::SetupFailed)
                        }
                    },
                ),
            )
            .await;

            assert_eq!(setup_polls.load(Ordering::SeqCst), 0);
            assert_eq!(raw_polls.load(Ordering::SeqCst), 0);
            assert_eq!(raw_drops.load(Ordering::SeqCst), 1);
            assert_eq!(*lock(&shared.winning_cause), Some(expected));
        }
        assert_eq!(runtime.counts().tracked_tasks, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn upgrade_commit_shutdown_race_linearizes_registration() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let setup_effects = Arc::new(AtomicUsize::new(0));
        let (registered_tx, registered_rx) = std_mpsc::channel();
        let (start_tx, start_rx) = std_mpsc::channel();
        let (result_tx, result_rx) = std_mpsc::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let setup_effects = setup_effects.clone();
                move |mut handshake| async move {
                    let entry_plan = plan({
                        let setup_effects = setup_effects.clone();
                        move |_| async move {
                            setup_effects.fetch_add(1, Ordering::SeqCst);
                            Err(UpgradeTerminalCause::DownstreamWriteFailed)
                        }
                    });
                    let result = handshake.commit_with_start_hook(None, entry_plan, || {
                        registered_tx.send(()).unwrap();
                        start_rx.recv().unwrap();
                    });
                    result_tx.send(result).unwrap();
                }
            })
            .unwrap();
        registered_rx.recv().unwrap();
        runtime.begin_shutdown(Some(Instant::now()));
        start_tx.send(()).unwrap();
        let entry = result_rx.recv().unwrap().expect("commit won the gate");
        entry.wait_closed().await;
        assert_eq!(setup_effects.load(Ordering::SeqCst), 0);
        runtime.wait_until_drained().await;

        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let setup_effects = Arc::new(AtomicUsize::new(0));
        let raw_drops = Arc::new(AtomicUsize::new(0));
        let raw_polls = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = std_mpsc::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let (result_tx, result_rx) = std_mpsc::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let setup_effects = setup_effects.clone();
                let raw_drops = raw_drops.clone();
                let raw_polls = raw_polls.clone();
                move |handshake| async move {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    let result = handshake.commit(
                        None,
                        UpgradeEntryPlan::new(
                            UpgradeTerminalControl::new(
                                counted_raw_teardown_with_guard(DropCount(raw_drops), raw_polls),
                                |_| async {},
                            ),
                            move |_| async move {
                                setup_effects.fetch_add(1, Ordering::SeqCst);
                                Err(UpgradeTerminalCause::DownstreamWriteFailed)
                            },
                        ),
                    );
                    result_tx.send(result.map(|_| ())).unwrap();
                }
            })
            .unwrap();
        entered_rx.recv().unwrap();
        runtime.begin_shutdown(Some(Instant::now()));
        release_tx.send(()).unwrap();
        assert_eq!(
            result_rx.recv().unwrap(),
            Err(UpgradeCommitError::AdmissionClosed)
        );
        assert_eq!(raw_drops.load(Ordering::SeqCst), 1);
        assert_eq!(raw_polls.load(Ordering::SeqCst), 0);
        runtime.wait_until_drained().await;
        assert_eq!(setup_effects.load(Ordering::SeqCst), 0);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn upgrade_admission_shutdown_race_linearizes_registry_snapshot() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let (admission_entered_tx, admission_entered_rx) = std_mpsc::channel();
        let (release_admission_tx, release_admission_rx) = std_mpsc::channel();
        let admission_runtime = runtime.clone();
        let admission = thread::spawn(move || {
            admission_runtime.try_spawn_handshake_with_hook(
                allocation(0, 0),
                |_| std::future::pending::<()>(),
                || {
                    admission_entered_tx.send(()).unwrap();
                    release_admission_rx.recv().unwrap();
                },
            )
        });

        admission_entered_rx.recv().unwrap();
        let (shutdown_done_tx, mut shutdown_done_rx) = oneshot::channel();
        let shutdown_runtime = runtime.clone();
        tokio::spawn(async move {
            shutdown_runtime.begin_shutdown(Some(Instant::now()));
            let _ = shutdown_done_tx.send(());
        });

        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut shutdown_done_rx)
                .await
                .is_err(),
            "shutdown must serialize behind the admission registry lock"
        );
        release_admission_tx.send(()).unwrap();
        assert_eq!(admission.join().unwrap(), Ok(()));
        shutdown_done_rx.await.unwrap();
        runtime.wait_until_drained().await;

        assert_eq!(
            runtime.counts(),
            UpgradeRuntimeCounts {
                maximum_slots: 1,
                maximum_bytes: 8,
                reserved_slots: 0,
                reserved_bytes: 0,
                uncommitted: 0,
                committed: 0,
                tracked_tasks: 0,
                accepting: false,
            }
        );
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test]
    async fn upgraded_stream_wire_rotation_is_lifetime_bounded() {
        let lifetime = Duration::from_millis(40);
        let cleanup = Duration::from_millis(30);
        let runtime = UpgradeRuntime::try_new(short_limits(lifetime, cleanup)).unwrap();
        let old_profile = wire_profile(b"[OLD]", b"secret");
        let new_profile = wire_profile(b"[NEW]", b"secret");
        let (observed_tx, observed_rx) = oneshot::channel();
        let (committed_tx, committed_rx) = oneshot::channel();

        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let retained_profile = old_profile.clone();
                move |handshake| async move {
                    let entry = handshake
                        .commit(
                            Some(retained_profile),
                            plan(move |snapshot| async move {
                                let profile = snapshot
                                    .wire_redaction()
                                    .cloned()
                                    .expect("wire profile remains in the stream snapshot");
                                let redacted = profile
                                    .redact_websocket_message(
                                        b"secret".to_vec(),
                                        PayloadClass::Text,
                                    )
                                    .unwrap();
                                observed_tx.send(redacted.bytes.clone()).unwrap();
                                Ok(UpgradeRelayPair::new(
                                    async move {
                                        let _profile = profile;
                                        std::future::pending::<UpgradeTerminalCause>().await
                                    },
                                    std::future::pending::<UpgradeTerminalCause>(),
                                ))
                            }),
                        )
                        .unwrap();
                    committed_tx.send(entry).unwrap();
                }
            })
            .unwrap();

        let entry = committed_rx.await.unwrap();
        assert_eq!(observed_rx.await.unwrap(), b"[OLD]");
        assert_eq!(
            new_profile
                .redact_websocket_message(b"secret".to_vec(), PayloadClass::Text)
                .unwrap()
                .bytes,
            b"[NEW]"
        );
        wait_for_counts(&runtime, |counts| counts.committed == 1).await;
        assert_eq!(old_profile.strong_count(), 2);

        tokio::time::timeout(
            lifetime + cleanup + Duration::from_millis(250),
            entry.wait_closed(),
        )
        .await
        .expect("wire-profile lifetime is bounded by stream cleanup");
        wait_for_counts(&runtime, |counts| {
            counts.committed == 0 && counts.tracked_tasks == 0
        })
        .await;
        assert_eq!(old_profile.strong_count(), 1);
        assert_eq!(
            entry.terminal_cause(),
            Some(UpgradeTerminalCause::LifetimeExpired)
        );
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test]
    async fn coordinator_registration_failure_does_not_poll_setup() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let setup_effects = Arc::new(AtomicUsize::new(0));
        let raw_aborts = Arc::new(AtomicUsize::new(0));
        let raw_polls = Arc::new(AtomicUsize::new(0));
        let (result_tx, result_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let setup_effects = setup_effects.clone();
                let raw_aborts = raw_aborts.clone();
                let raw_polls = raw_polls.clone();
                move |mut handshake| async move {
                    let result = handshake.commit_inner(
                        None,
                        UpgradeEntryPlan::new(
                            UpgradeTerminalControl::new(
                                counted_raw_teardown_with_guard(
                                    DropCount(raw_aborts.clone()),
                                    raw_polls,
                                ),
                                |_| async {},
                            ),
                            move |_| async move {
                                setup_effects.fetch_add(1, Ordering::SeqCst);
                                Err(UpgradeTerminalCause::SetupFailed)
                            },
                        ),
                        || {},
                        |_, task| Err(task),
                    );
                    let _ = result_tx.send(result.map(|_| ()));
                }
            })
            .unwrap();

        assert_eq!(
            result_rx.await.unwrap(),
            Err(UpgradeCommitError::SupervisorStopped)
        );
        assert_eq!(raw_aborts.load(Ordering::SeqCst), 1);
        assert_eq!(raw_polls.load(Ordering::SeqCst), 0);
        wait_for_counts(&runtime, |counts| {
            counts.reserved_slots == 0
                && counts.reserved_bytes == 0
                && counts.committed == 0
                && counts.tracked_tasks == 0
        })
        .await;
        assert_eq!(setup_effects.load(Ordering::SeqCst), 0);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test]
    async fn committed_origin_park_is_aborted_after_coordinator_close() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let (entry_tx, entry_rx) = oneshot::channel();
        let (setup_release_tx, setup_release_rx) = oneshot::channel();
        let (parked_tx, parked_rx) = oneshot::channel();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), move |handshake| async move {
                let entry = handshake
                    .commit(
                        None,
                        plan(|_| async move {
                            let _ = setup_release_rx.await;
                            Ok(UpgradeRelayPair::new(
                                async { UpgradeTerminalCause::PeerClosed },
                                async { UpgradeTerminalCause::PeerClosed },
                            ))
                        }),
                    )
                    .unwrap();
                entry_tx.send(entry).unwrap();
                let _drop = DropSignal(Some(dropped_tx));
                let _ = parked_tx.send(());
                std::future::pending::<()>().await;
            })
            .unwrap();
        let entry = entry_rx.await.unwrap();
        parked_rx.await.unwrap();
        assert_eq!(runtime.counts().reserved_slots, 1);
        assert_eq!(
            runtime
                .try_spawn_handshake(allocation(1, 0), |_| async {})
                .unwrap_err(),
            UpgradeHandshakeSpawnError::Admission(UpgradeAdmissionError::SlotCapacity)
        );
        let _ = setup_release_tx.send(());
        entry.wait_closed().await;
        dropped_rx.await.unwrap();
        wait_for_counts(&runtime, |counts| {
            counts.reserved_slots == 0
                && counts.reserved_bytes == 0
                && counts.committed == 0
                && counts.tracked_tasks == 0
        })
        .await;
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn repeated_quick_close_restores_one_slot_exactly() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        for _ in 0..64 {
            let (entry_tx, entry_rx) = oneshot::channel();
            runtime
                .try_spawn_handshake(allocation(0, 0), move |handshake| async move {
                    let entry = handshake
                        .commit(
                            None,
                            plan(|_| async {
                                Ok(UpgradeRelayPair::new(
                                    async { UpgradeTerminalCause::PeerClosed },
                                    async { UpgradeTerminalCause::PeerClosed },
                                ))
                            }),
                        )
                        .unwrap();
                    entry_tx.send(entry).unwrap();
                    std::future::pending::<()>().await;
                })
                .unwrap();
            let entry = entry_rx.await.unwrap();
            entry.wait_closed().await;
            let counts = wait_for_counts(&runtime, |counts| {
                counts.reserved_slots == 0
                    && counts.reserved_bytes == 0
                    && counts.committed == 0
                    && counts.tracked_tasks == 0
            })
            .await;
            assert!(counts.accepting);
        }
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test]
    async fn graceful_relay_half_close_waits_for_the_peer_direction() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let (entry_tx, entry_rx) = oneshot::channel();
        let (reverse_release_tx, reverse_release_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), move |handshake| async move {
                let entry = handshake
                    .commit(
                        None,
                        plan(|_| async move {
                            Ok(UpgradeRelayPair::new_with_graceful_drain_timeout(
                                async { UpgradeTerminalCause::PeerClosed },
                                async move {
                                    let _ = reverse_release_rx.await;
                                    UpgradeTerminalCause::PeerClosed
                                },
                                None,
                            ))
                        }),
                    )
                    .unwrap();
                entry_tx.send(entry).unwrap();
            })
            .unwrap();
        let entry = entry_rx.await.unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(20), entry.wait_closed())
                .await
                .is_err(),
            "one graceful relay EOF must not abort the reverse direction"
        );
        reverse_release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), entry.wait_closed())
            .await
            .unwrap();
        assert_eq!(
            entry.terminal_cause(),
            Some(UpgradeTerminalCause::PeerClosed)
        );
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test]
    async fn graceful_relay_drain_timeout_bounds_an_unresponsive_peer() {
        let pair = UpgradeRelayPair::new_with_graceful_drain_timeout(
            async { UpgradeTerminalCause::PeerClosed },
            async {
                std::future::pending::<()>().await;
                UpgradeTerminalCause::PeerClosed
            },
            Some(Duration::from_millis(20)),
        );

        let cause = tokio::time::timeout(Duration::from_secs(1), pair.relay)
            .await
            .expect("graceful relay drain timeout did not fire");
        assert_eq!(cause, UpgradeTerminalCause::PeerClosed);
    }

    #[tokio::test]
    async fn exact_relay_cause_reaches_terminal_control() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let (cause_tx, cause_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), move |handshake| async move {
                let entry = handshake
                    .commit(
                        None,
                        UpgradeEntryPlan::new(
                            UpgradeTerminalControl::new(
                                inert_raw_teardown(),
                                move |cause| async move {
                                    let _ = cause_tx.send(cause);
                                    let _ = release_tx.send(());
                                },
                            ),
                            |_| async move {
                                Ok(UpgradeRelayPair::new(
                                    async { UpgradeTerminalCause::RelayError },
                                    async move {
                                        let _ = release_rx.await;
                                        UpgradeTerminalCause::PeerClosed
                                    },
                                ))
                            },
                        ),
                    )
                    .unwrap();
                entry.wait_closed().await;
            })
            .unwrap();
        assert_eq!(cause_rx.await.unwrap(), UpgradeTerminalCause::RelayError);
        runtime.begin_shutdown(Some(Instant::now()));
        runtime.wait_until_drained().await;
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn lifetime_and_shutdown_closing_stop_relays_before_close_grace() {
        for cause in [
            UpgradeTerminalCause::LifetimeExpired,
            UpgradeTerminalCause::Shutdown,
        ] {
            let lifetime = if cause == UpgradeTerminalCause::LifetimeExpired {
                Duration::from_millis(30)
            } else {
                Duration::from_secs(60)
            };
            let runtime =
                UpgradeRuntime::try_new(short_limits(lifetime, Duration::from_millis(200)))
                    .unwrap();
            let frames = Arc::new(AtomicUsize::new(0));
            let pulse = Arc::new(Notify::new());
            let (relay_started_tx, relay_started_rx) = oneshot::channel();
            let (close_started_tx, close_started_rx) = oneshot::channel();
            let (close_release_tx, close_release_rx) = oneshot::channel();
            let (entry_tx, entry_rx) = oneshot::channel();
            runtime
                .try_spawn_handshake(allocation(0, 0), {
                    let frames = frames.clone();
                    let pulse = pulse.clone();
                    move |handshake| async move {
                        let entry = handshake
                            .commit(
                                None,
                                UpgradeEntryPlan::new(
                                    UpgradeTerminalControl::new(
                                        inert_raw_teardown(),
                                        move |_| async move {
                                            let _ = close_started_tx.send(());
                                            let _ = close_release_rx.await;
                                        },
                                    ),
                                    move |_| async move {
                                        Ok(UpgradeRelayPair::new(
                                            async move {
                                                let _ = relay_started_tx.send(());
                                                loop {
                                                    pulse.notified().await;
                                                    frames.fetch_add(1, Ordering::SeqCst);
                                                }
                                            },
                                            async {
                                                std::future::pending::<()>().await;
                                                UpgradeTerminalCause::PeerClosed
                                            },
                                        ))
                                    },
                                ),
                            )
                            .unwrap();
                        entry_tx.send(entry).unwrap();
                    }
                })
                .unwrap();
            let entry = entry_rx.await.unwrap();
            relay_started_rx.await.unwrap();
            pulse.notify_one();
            tokio::time::timeout(Duration::from_secs(1), async {
                while frames.load(Ordering::SeqCst) != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("relay did not process the pre-stop frame");

            if cause == UpgradeTerminalCause::Shutdown {
                entry.submit_terminal(UpgradeTerminalCause::Shutdown);
            }
            close_started_rx.await.unwrap();
            pulse.notify_one();
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert_eq!(
                frames.load(Ordering::SeqCst),
                1,
                "relay processed a frame after {cause:?} application stop"
            );

            close_release_tx.send(()).unwrap();
            entry.wait_closed().await;
            assert_eq!(entry.terminal_cause(), Some(cause));
            runtime.shutdown_and_wait(Some(Instant::now())).await;
        }
    }

    #[tokio::test]
    async fn terminal_cleanup_uses_grace_then_cutoff_aborts_and_joins() {
        let runtime =
            UpgradeRuntime::try_new(limits(1, 8).with_cleanup_grace(Duration::from_millis(100)))
                .unwrap();
        let (entry_tx, entry_rx) = oneshot::channel();
        let (cleanup_started_tx, cleanup_started_rx) = oneshot::channel();
        let (cleanup_release_tx, cleanup_release_rx) = oneshot::channel();
        let (relay_release_tx, relay_release_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), move |handshake| async move {
                let entry = handshake
                    .commit(
                        None,
                        UpgradeEntryPlan::new(
                            UpgradeTerminalControl::new(
                                inert_raw_teardown(),
                                move |_| async move {
                                    let _ = cleanup_started_tx.send(());
                                    let _ = cleanup_release_rx.await;
                                },
                            ),
                            |_| async move {
                                Ok(UpgradeRelayPair::new(
                                    async { UpgradeTerminalCause::PeerClosed },
                                    async move {
                                        let _ = relay_release_rx.await;
                                        UpgradeTerminalCause::PeerClosed
                                    },
                                ))
                            },
                        ),
                    )
                    .unwrap();
                entry_tx.send(entry).unwrap();
            })
            .unwrap();
        let entry = entry_rx.await.unwrap();
        cleanup_started_rx.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), entry.wait_closed())
                .await
                .is_err()
        );
        let _ = cleanup_release_tx.send(());
        let _ = relay_release_tx.send(());
        entry.wait_closed().await;
        assert_eq!(
            entry.terminal_cause(),
            Some(UpgradeTerminalCause::PeerClosed)
        );
        runtime.shutdown_and_wait(Some(Instant::now())).await;

        let runtime =
            UpgradeRuntime::try_new(limits(1, 8).with_cleanup_grace(Duration::from_millis(30)))
                .unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        let relay_drop = DropCount(drops.clone());
        let cleanup_drop = DropCount(drops.clone());
        let (entry_tx, entry_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), move |handshake| async move {
                let entry = handshake
                    .commit(
                        None,
                        UpgradeEntryPlan::new(
                            UpgradeTerminalControl::new(
                                raw_teardown_with_guard(cleanup_drop),
                                |_| async move {
                                    std::future::pending::<()>().await;
                                },
                            ),
                            |_| async move {
                                Ok(UpgradeRelayPair::new(
                                    async { UpgradeTerminalCause::PeerClosed },
                                    async move {
                                        let _drop = relay_drop;
                                        std::future::pending::<()>().await;
                                        UpgradeTerminalCause::PeerClosed
                                    },
                                ))
                            },
                        ),
                    )
                    .unwrap();
                entry_tx.send(entry).unwrap();
            })
            .unwrap();
        let entry = entry_rx.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), entry.wait_closed())
            .await
            .unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test]
    async fn lifetime_natural_close_and_shutdown_choose_one_cause() {
        async fn run_case(
            lifetime: Duration,
            shutdown: Option<Duration>,
            relay: UpgradeTerminalCause,
        ) -> UpgradeTerminalCause {
            let runtime =
                UpgradeRuntime::try_new(short_limits(lifetime, Duration::from_millis(30))).unwrap();
            let (entry_tx, entry_rx) = oneshot::channel();
            runtime
                .try_spawn_handshake(allocation(0, 0), move |handshake| async move {
                    let entry = handshake
                        .commit(
                            None,
                            plan(move |_| async move {
                                Ok(UpgradeRelayPair::new(
                                    async move {
                                        if relay == UpgradeTerminalCause::PeerClosed {
                                            return relay;
                                        }
                                        std::future::pending::<()>().await;
                                        relay
                                    },
                                    async {
                                        std::future::pending::<()>().await;
                                        UpgradeTerminalCause::PeerClosed
                                    },
                                ))
                            }),
                        )
                        .unwrap();
                    entry_tx.send(entry).unwrap();
                })
                .unwrap();
            let entry = entry_rx.await.unwrap();
            if let Some(delay) = shutdown {
                runtime.begin_shutdown(Some(Instant::now() + delay));
            }
            tokio::time::timeout(Duration::from_secs(1), entry.wait_closed())
                .await
                .unwrap();
            let cause = entry.terminal_cause().unwrap();
            runtime.begin_shutdown(Some(Instant::now()));
            runtime.wait_until_drained().await;
            runtime.shutdown_and_wait(Some(Instant::now())).await;
            cause
        }

        assert_eq!(
            run_case(
                Duration::from_secs(1),
                None,
                UpgradeTerminalCause::PeerClosed,
            )
            .await,
            UpgradeTerminalCause::PeerClosed
        );
        assert_eq!(
            run_case(
                Duration::from_millis(20),
                None,
                UpgradeTerminalCause::Cancelled,
            )
            .await,
            UpgradeTerminalCause::LifetimeExpired
        );
        assert_eq!(
            run_case(
                Duration::from_secs(1),
                Some(Duration::from_millis(20)),
                UpgradeTerminalCause::Cancelled,
            )
            .await,
            UpgradeTerminalCause::Shutdown
        );
    }

    #[tokio::test]
    async fn finite_equal_stop_and_cutoff_aborts_without_downstream_cleanup_grace() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let control_calls = Arc::new(AtomicUsize::new(0));
        let relay_drops = Arc::new(AtomicUsize::new(0));
        let (entry_tx, entry_rx) = oneshot::channel();
        let (relays_started_tx, relays_started_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let control_calls = control_calls.clone();
                let relay_drops = relay_drops.clone();
                move |handshake| async move {
                    let entry = handshake
                        .commit(
                            None,
                            UpgradeEntryPlan::new(
                                UpgradeTerminalControl::new(
                                    inert_raw_teardown(),
                                    move |_| async move {
                                        control_calls.fetch_add(1, Ordering::SeqCst);
                                    },
                                ),
                                move |_| async move {
                                    let first_drop = DropCount(relay_drops.clone());
                                    let second_drop = DropCount(relay_drops.clone());
                                    let _ = relays_started_tx.send(());
                                    Ok(UpgradeRelayPair::new(
                                        async move {
                                            let _drop = first_drop;
                                            std::future::pending::<()>().await;
                                            UpgradeTerminalCause::PeerClosed
                                        },
                                        async move {
                                            let _drop = second_drop;
                                            std::future::pending::<()>().await;
                                            UpgradeTerminalCause::PeerClosed
                                        },
                                    ))
                                },
                            ),
                        )
                        .unwrap();
                    entry_tx.send(entry).unwrap();
                }
            })
            .unwrap();
        let entry = entry_rx.await.unwrap();
        relays_started_rx.await.unwrap();
        runtime.begin_shutdown(Some(Instant::now()));
        entry.wait_closed().await;
        assert_eq!(entry.terminal_cause(), Some(UpgradeTerminalCause::Shutdown));
        assert_eq!(control_calls.load(Ordering::SeqCst), 0);
        assert_eq!(relay_drops.load(Ordering::SeqCst), 2);
        runtime.wait_until_drained().await;
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test]
    async fn setup_failure_and_panic_are_pre_relay_terminal_paths() {
        for panic_setup in [false, true] {
            let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
            let raw_aborts = Arc::new(AtomicUsize::new(0));
            let established_closes = Arc::new(AtomicUsize::new(0));
            let (entry_tx, entry_rx) = oneshot::channel();
            runtime
                .try_spawn_handshake(allocation(0, 0), {
                    let raw_aborts = raw_aborts.clone();
                    let established_closes = established_closes.clone();
                    move |handshake| async move {
                        let entry = handshake
                            .commit(
                                None,
                                UpgradeEntryPlan::new(
                                    UpgradeTerminalControl::new(
                                        raw_teardown_with_guard(DropCount(raw_aborts.clone())),
                                        move |_| async move {
                                            established_closes.fetch_add(1, Ordering::SeqCst);
                                        },
                                    ),
                                    move |_| async move {
                                        if panic_setup {
                                            panic!("setup panic");
                                        }
                                        Err(UpgradeTerminalCause::DownstreamWriteFailed)
                                    },
                                ),
                            )
                            .unwrap();
                        entry_tx.send(entry).unwrap();
                    }
                })
                .unwrap();
            let entry = entry_rx.await.unwrap();
            entry.wait_closed().await;
            assert_eq!(
                entry.terminal_cause(),
                Some(if panic_setup {
                    UpgradeTerminalCause::SetupFailed
                } else {
                    UpgradeTerminalCause::DownstreamWriteFailed
                })
            );
            assert_eq!(raw_aborts.load(Ordering::SeqCst), 1);
            assert_eq!(established_closes.load(Ordering::SeqCst), 0);
            assert_eq!(entry.shared.setup_state.load(Ordering::SeqCst), SETUP_IDLE);
            runtime.shutdown_and_wait(Some(Instant::now())).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn raw_teardown_is_joined_before_entry_closes() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let raw_teardowns = Arc::new(AtomicUsize::new(0));
        let established_closes = Arc::new(AtomicUsize::new(0));
        let setup_drops = Arc::new(AtomicUsize::new(0));
        let (raw_started_tx, raw_started_rx) = std_mpsc::channel();
        let (raw_release_tx, raw_release_rx) = std_mpsc::channel();
        let (entry_tx, entry_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let raw_teardowns = raw_teardowns.clone();
                let established_closes = established_closes.clone();
                let setup_drops = setup_drops.clone();
                move |handshake| async move {
                    let entry = handshake
                        .commit(
                            None,
                            UpgradeEntryPlan::new(
                                UpgradeTerminalControl::new(
                                    raw_teardown_with_guard(BlockingDrop {
                                        started: Some(raw_started_tx),
                                        release: raw_release_rx,
                                        completed: raw_teardowns,
                                    }),
                                    move |_| async move {
                                        established_closes.fetch_add(1, Ordering::SeqCst);
                                    },
                                ),
                                move |_| async move {
                                    let _drop = DropCount(setup_drops);
                                    Err(UpgradeTerminalCause::DownstreamWriteFailed)
                                },
                            ),
                        )
                        .unwrap();
                    entry_tx.send(entry).unwrap();
                }
            })
            .unwrap();
        let entry = entry_rx.await.unwrap();
        raw_started_rx.recv().unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), entry.wait_closed())
                .await
                .is_err(),
            "entry closed before its raw teardown task joined"
        );
        raw_release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), entry.wait_closed())
            .await
            .expect("entry did not close after raw teardown joined");
        assert_eq!(
            entry.terminal_cause(),
            Some(UpgradeTerminalCause::DownstreamWriteFailed)
        );
        assert_eq!(raw_teardowns.load(Ordering::SeqCst), 1);
        assert_eq!(established_closes.load(Ordering::SeqCst), 0);
        assert_eq!(setup_drops.load(Ordering::SeqCst), 1);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
        assert_eq!(runtime.counts().tracked_tasks, 0);
    }

    #[tokio::test]
    async fn lowered_cleanup_cutoff_interrupts_established_cleanup() {
        let runtime =
            UpgradeRuntime::try_new(limits(1, 8).with_cleanup_grace(Duration::from_secs(5)))
                .unwrap();
        let raw_aborts = Arc::new(AtomicUsize::new(0));
        let cleanup_drops = Arc::new(AtomicUsize::new(0));
        let relay_drops = Arc::new(AtomicUsize::new(0));
        let (entry_tx, entry_rx) = oneshot::channel();
        let (cleanup_started_tx, cleanup_started_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let raw_aborts = raw_aborts.clone();
                let cleanup_drops = cleanup_drops.clone();
                let relay_drops = relay_drops.clone();
                move |handshake| async move {
                    let entry = handshake
                        .commit(
                            None,
                            UpgradeEntryPlan::new(
                                UpgradeTerminalControl::new(
                                    raw_teardown_with_guard(DropCount(raw_aborts.clone())),
                                    move |_| async move {
                                        let _drop = DropCount(cleanup_drops);
                                        let _ = cleanup_started_tx.send(());
                                        std::future::pending::<()>().await;
                                    },
                                ),
                                move |_| async move {
                                    let relay_drop = DropCount(relay_drops);
                                    Ok(UpgradeRelayPair::new(
                                        async { UpgradeTerminalCause::PeerClosed },
                                        async move {
                                            let _drop = relay_drop;
                                            std::future::pending::<()>().await;
                                            UpgradeTerminalCause::PeerClosed
                                        },
                                    ))
                                },
                            ),
                        )
                        .unwrap();
                    entry_tx.send(entry).unwrap();
                }
            })
            .unwrap();
        let entry = entry_rx.await.unwrap();
        cleanup_started_rx.await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            runtime.shutdown_and_wait(Some(Instant::now())),
        )
        .await
        .expect("lowered cleanup cutoff was not observed by active cleanup");
        entry.wait_closed().await;
        assert_eq!(
            entry.terminal_cause(),
            Some(UpgradeTerminalCause::PeerClosed)
        );
        assert_eq!(raw_aborts.load(Ordering::SeqCst), 1);
        assert_eq!(cleanup_drops.load(Ordering::SeqCst), 1);
        assert_eq!(relay_drops.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.counts().tracked_tasks, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shutdown_between_setup_check_and_authorization_prevents_setup_poll() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let setup_effects = Arc::new(AtomicUsize::new(0));
        let raw_cancellations = Arc::new(AtomicUsize::new(0));
        let established_closes = Arc::new(AtomicUsize::new(0));
        let now = Instant::now();
        let shared = Arc::new(EntryShared {
            timing: Mutex::new(EntryTiming {
                application_stop: now + Duration::from_secs(1),
                cleanup_cutoff: now + Duration::from_secs(2),
                stop_cause: UpgradeTerminalCause::LifetimeExpired,
            }),
            cleanup_grace: Duration::from_millis(100),
            winning_cause: Mutex::new(None),
            setup_state: AtomicU8::new(SETUP_IDLE),
            changed: Notify::new(),
            terminal_state: AtomicU8::new(ENTRY_OPEN),
            closed: Notify::new(),
        });
        let (authorization_tx, authorization_rx) = std_mpsc::channel();
        let (resume_tx, resume_rx) = std_mpsc::channel();
        let coordinator = tokio::spawn(run_entry_coordinator_with_hooks(
            runtime.inner.clone(),
            shared.clone(),
            UpgradedStreamSnapshot::new(2, None),
            UpgradeEntryPlan::new(
                UpgradeTerminalControl::new(
                    raw_teardown_with_guard(DropCount(raw_cancellations.clone())),
                    {
                        let established_closes = established_closes.clone();
                        move |_| async move {
                            established_closes.fetch_add(1, Ordering::SeqCst);
                        }
                    },
                ),
                {
                    let setup_effects = setup_effects.clone();
                    move |_| async move {
                        setup_effects.fetch_add(1, Ordering::SeqCst);
                        Err(UpgradeTerminalCause::SetupFailed)
                    }
                },
            ),
            || {},
            move || {
                authorization_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
            },
            || {},
        ));

        authorization_rx.recv().unwrap();
        shared.lower_for_shutdown(Instant::now());
        resume_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), coordinator)
            .await
            .expect("coordinator did not reject setup after shutdown")
            .unwrap();
        assert_eq!(setup_effects.load(Ordering::SeqCst), 0);
        assert_eq!(established_closes.load(Ordering::SeqCst), 0);
        assert_eq!(
            *lock(&shared.winning_cause),
            Some(UpgradeTerminalCause::Shutdown)
        );
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn lowered_cutoff_before_close_authorization_prevents_close_poll() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let close_effects = Arc::new(AtomicUsize::new(0));
        let raw_cancellations = Arc::new(AtomicUsize::new(0));
        let relay_drops = Arc::new(AtomicUsize::new(0));
        let now = Instant::now();
        let shared = Arc::new(EntryShared {
            timing: Mutex::new(EntryTiming {
                application_stop: now + Duration::from_secs(1),
                cleanup_cutoff: now + Duration::from_secs(2),
                stop_cause: UpgradeTerminalCause::LifetimeExpired,
            }),
            cleanup_grace: Duration::from_millis(100),
            winning_cause: Mutex::new(None),
            setup_state: AtomicU8::new(SETUP_IDLE),
            changed: Notify::new(),
            terminal_state: AtomicU8::new(ENTRY_OPEN),
            closed: Notify::new(),
        });
        let (authorization_tx, authorization_rx) = std_mpsc::channel();
        let (resume_tx, resume_rx) = std_mpsc::channel();
        let coordinator = tokio::spawn(run_entry_coordinator_with_hooks(
            runtime.inner.clone(),
            shared.clone(),
            UpgradedStreamSnapshot::new(2, None),
            UpgradeEntryPlan::new(
                UpgradeTerminalControl::new(
                    raw_teardown_with_guard(DropCount(raw_cancellations.clone())),
                    {
                        let close_effects = close_effects.clone();
                        move |_| async move {
                            close_effects.fetch_add(1, Ordering::SeqCst);
                        }
                    },
                ),
                {
                    let relay_drops = relay_drops.clone();
                    move |_| async move {
                        let relay_drop = DropCount(relay_drops);
                        Ok(UpgradeRelayPair::new(
                            async { UpgradeTerminalCause::PeerClosed },
                            async move {
                                let _drop = relay_drop;
                                std::future::pending::<()>().await;
                                UpgradeTerminalCause::PeerClosed
                            },
                        ))
                    }
                },
            ),
            || {},
            || {},
            move || {
                authorization_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
            },
        ));

        authorization_rx.recv().unwrap();
        shared.lower_for_shutdown(Instant::now());
        resume_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), coordinator)
            .await
            .expect("coordinator did not reject close after cutoff lowering")
            .unwrap();
        assert_eq!(close_effects.load(Ordering::SeqCst), 0);
        assert_eq!(relay_drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            *lock(&shared.winning_cause),
            Some(UpgradeTerminalCause::PeerClosed)
        );
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn terminal_or_deadline_pending_setup_completion_drops_relays_unpolled() {
        for (winning_cause, deadline) in [
            (UpgradeTerminalCause::Cancelled, false),
            (UpgradeTerminalCause::LifetimeExpired, true),
        ] {
            for _ in 0..1 {
                let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
                let raw_aborts = Arc::new(AtomicUsize::new(0));
                let established_closes = Arc::new(AtomicUsize::new(0));
                let setup_completed = Arc::new(AtomicUsize::new(0));
                let relay_polls = Arc::new(AtomicUsize::new(0));
                let now = Instant::now();
                let shared = Arc::new(EntryShared {
                    timing: Mutex::new(EntryTiming {
                        application_stop: now + Duration::from_secs(1),
                        cleanup_cutoff: now + Duration::from_secs(2),
                        stop_cause: UpgradeTerminalCause::LifetimeExpired,
                    }),
                    cleanup_grace: Duration::from_millis(100),
                    winning_cause: Mutex::new(None),
                    setup_state: AtomicU8::new(SETUP_IDLE),
                    changed: Notify::new(),
                    terminal_state: AtomicU8::new(ENTRY_OPEN),
                    closed: Notify::new(),
                });
                let (setup_started_tx, setup_started_rx) = oneshot::channel();
                let (setup_release_tx, setup_release_rx) = oneshot::channel();
                let (final_poll_blocked_tx, final_poll_blocked_rx) = oneshot::channel();
                let (final_poll_release_tx, final_poll_release_rx) = std_mpsc::channel();
                let setup_shared = shared.clone();
                let setup_completed_for_task = setup_completed.clone();
                let setup_relay_polls = relay_polls.clone();
                let coordinator = tokio::spawn(run_entry_coordinator(
                    runtime.inner.clone(),
                    shared.clone(),
                    UpgradedStreamSnapshot::new(2, None),
                    UpgradeEntryPlan::new(
                        UpgradeTerminalControl::new(
                            raw_teardown_with_guard(DropCount(raw_aborts.clone())),
                            {
                                let established_closes = established_closes.clone();
                                move |_| async move {
                                    established_closes.fetch_add(1, Ordering::SeqCst);
                                }
                            },
                        ),
                        move |_| async move {
                            let _ = setup_started_tx.send(());
                            let _ = setup_release_rx.await;
                            if deadline {
                                let mut timing = lock(&setup_shared.timing);
                                timing.application_stop = Instant::now();
                                timing.stop_cause = winning_cause;
                                drop(timing);
                                setup_shared.changed.notify_waiters();
                            }
                            let _ = final_poll_blocked_tx.send(());
                            final_poll_release_rx.recv().unwrap();
                            let first_polls = setup_relay_polls.clone();
                            let second_polls = setup_relay_polls;
                            setup_completed_for_task.fetch_add(1, Ordering::SeqCst);
                            Ok(UpgradeRelayPair::new(
                                async move {
                                    first_polls.fetch_add(1, Ordering::SeqCst);
                                    std::future::pending::<()>().await;
                                    UpgradeTerminalCause::PeerClosed
                                },
                                async move {
                                    second_polls.fetch_add(1, Ordering::SeqCst);
                                    std::future::pending::<()>().await;
                                    UpgradeTerminalCause::PeerClosed
                                },
                            ))
                        },
                    ),
                ));

                setup_started_rx.await.unwrap();
                setup_release_tx.send(()).unwrap();
                final_poll_blocked_rx.await.unwrap();
                assert_eq!(shared.terminal_state.load(Ordering::SeqCst), ENTRY_OPEN);
                let terminal_shared = shared.clone();
                let (transition_started_tx, transition_started_rx) = std_mpsc::channel();
                let terminal = tokio::task::spawn_blocking(move || {
                    transition_started_tx.send(()).unwrap();
                    terminal_shared.begin_closing(
                        winning_cause,
                        Instant::now(),
                        terminal_shared.cleanup_grace,
                    );
                });
                transition_started_rx.recv().unwrap();
                tokio::time::timeout(Duration::from_secs(1), async {
                    while shared.terminal_state.load(Ordering::SeqCst) != ENTRY_CLOSE_WAITING_SETUP
                    {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("terminal transition did not contend with the final setup poll");
                final_poll_release_tx.send(()).unwrap();
                terminal.await.unwrap();
                tokio::time::timeout(Duration::from_secs(1), coordinator)
                    .await
                    .expect("coordinator did not resolve the setup/terminal race")
                    .unwrap();
                assert_eq!(setup_completed.load(Ordering::SeqCst), 1);
                assert_eq!(shared.setup_state.load(Ordering::SeqCst), SETUP_SUCCEEDED);
                assert_eq!(established_closes.load(Ordering::SeqCst), 1);
                assert_eq!(relay_polls.load(Ordering::SeqCst), 0);
                assert_eq!(raw_aborts.load(Ordering::SeqCst), 1);
                assert_eq!(*lock(&shared.winning_cause), Some(winning_cause));
                runtime.shutdown_and_wait(Some(Instant::now())).await;
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn terminal_transition_before_next_setup_poll_prevents_setup_success() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let raw_aborts = Arc::new(AtomicUsize::new(0));
        let established_closes = Arc::new(AtomicUsize::new(0));
        let setup_effects = Arc::new(AtomicUsize::new(0));
        let now = Instant::now();
        let shared = Arc::new(EntryShared {
            timing: Mutex::new(EntryTiming {
                application_stop: now + Duration::from_secs(1),
                cleanup_cutoff: now + Duration::from_secs(2),
                stop_cause: UpgradeTerminalCause::LifetimeExpired,
            }),
            cleanup_grace: Duration::from_millis(100),
            winning_cause: Mutex::new(None),
            setup_state: AtomicU8::new(SETUP_IDLE),
            changed: Notify::new(),
            terminal_state: AtomicU8::new(ENTRY_OPEN),
            closed: Notify::new(),
        });
        let (setup_started_tx, setup_started_rx) = oneshot::channel();
        let (setup_release_tx, setup_release_rx) = oneshot::channel();
        let coordinator = tokio::spawn(run_entry_coordinator(
            runtime.inner.clone(),
            shared.clone(),
            UpgradedStreamSnapshot::new(2, None),
            UpgradeEntryPlan::new(
                UpgradeTerminalControl::new(
                    raw_teardown_with_guard(DropCount(raw_aborts.clone())),
                    {
                        let established_closes = established_closes.clone();
                        move |_| async move {
                            established_closes.fetch_add(1, Ordering::SeqCst);
                        }
                    },
                ),
                {
                    let setup_effects = setup_effects.clone();
                    move |_| async move {
                        let _ = setup_started_tx.send(());
                        let _ = setup_release_rx.await;
                        setup_effects.fetch_add(1, Ordering::SeqCst);
                        Err(UpgradeTerminalCause::SetupFailed)
                    }
                },
            ),
        ));

        setup_started_rx.await.unwrap();
        let terminal_shared = shared.clone();
        tokio::task::spawn_blocking(move || {
            terminal_shared.begin_closing(
                UpgradeTerminalCause::Cancelled,
                Instant::now(),
                terminal_shared.cleanup_grace,
            );
        })
        .await
        .unwrap();
        assert_eq!(shared.terminal_state.load(Ordering::SeqCst), ENTRY_CLOSING);
        let _ = setup_release_tx.send(());
        tokio::time::timeout(Duration::from_secs(1), coordinator)
            .await
            .expect("coordinator did not cancel setup after terminal won transition")
            .unwrap();
        assert_eq!(setup_effects.load(Ordering::SeqCst), 0);
        assert_eq!(established_closes.load(Ordering::SeqCst), 0);
        assert_eq!(raw_aborts.load(Ordering::SeqCst), 1);
        assert_eq!(
            *lock(&shared.winning_cause),
            Some(UpgradeTerminalCause::Cancelled)
        );
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn setup_poll_can_reentrantly_submit_terminal_without_deadlock() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let established_closes = Arc::new(AtomicUsize::new(0));
        let relay_polls = Arc::new(AtomicUsize::new(0));
        let (entry_for_setup_tx, entry_for_setup_rx) = oneshot::channel();
        let (entry_tx, entry_rx) = oneshot::channel();
        let (terminal_returned_tx, terminal_returned_rx) = oneshot::channel();
        let (setup_release_tx, setup_release_rx) = std_mpsc::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let established_closes = established_closes.clone();
                let relay_polls = relay_polls.clone();
                move |handshake| async move {
                    let entry = handshake
                        .commit(
                            None,
                            UpgradeEntryPlan::new(
                                UpgradeTerminalControl::new(
                                    inert_raw_teardown(),
                                    move |_| async move {
                                        established_closes.fetch_add(1, Ordering::SeqCst);
                                    },
                                ),
                                move |_| async move {
                                    let entry: CommittedUpgrade = entry_for_setup_rx.await.unwrap();
                                    entry.submit_terminal(UpgradeTerminalCause::Cancelled);
                                    let _ = terminal_returned_tx.send(());
                                    setup_release_rx.recv().unwrap();
                                    let first_polls = relay_polls.clone();
                                    let second_polls = relay_polls;
                                    Ok(UpgradeRelayPair::new(
                                        async move {
                                            first_polls.fetch_add(1, Ordering::SeqCst);
                                            UpgradeTerminalCause::PeerClosed
                                        },
                                        async move {
                                            second_polls.fetch_add(1, Ordering::SeqCst);
                                            UpgradeTerminalCause::PeerClosed
                                        },
                                    ))
                                },
                            ),
                        )
                        .unwrap();
                    entry_for_setup_tx.send(entry.clone()).unwrap();
                    entry_tx.send(entry).unwrap();
                }
            })
            .unwrap();
        let entry = entry_rx.await.unwrap();
        terminal_returned_rx
            .await
            .expect("reentrant terminal submission did not return");
        assert_eq!(
            entry.shared.terminal_state.load(Ordering::SeqCst),
            ENTRY_CLOSE_WAITING_SETUP
        );
        assert_eq!(
            entry.shared.setup_state.load(Ordering::SeqCst),
            SETUP_POLLING
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            entry.shared.terminal_state.load(Ordering::SeqCst),
            ENTRY_CLOSE_WAITING_SETUP
        );
        setup_release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), entry.wait_closed())
            .await
            .expect("entry did not close after reentrant terminal setup poll returned");
        assert_eq!(
            entry.terminal_cause(),
            Some(UpgradeTerminalCause::Cancelled)
        );
        assert_eq!(
            entry.shared.setup_state.load(Ordering::SeqCst),
            SETUP_SUCCEEDED
        );
        assert_eq!(established_closes.load(Ordering::SeqCst), 1);
        assert_eq!(relay_polls.load(Ordering::SeqCst), 0);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn synchronous_setup_builder_is_guarded_by_terminal_transition() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let established_closes = Arc::new(AtomicUsize::new(0));
        let relay_polls = Arc::new(AtomicUsize::new(0));
        let (builder_entered_tx, builder_entered_rx) = std_mpsc::channel();
        let (builder_release_tx, builder_release_rx) = std_mpsc::channel();
        let (entry_tx, entry_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let established_closes = established_closes.clone();
                let relay_polls = relay_polls.clone();
                move |handshake| async move {
                    let entry = handshake
                        .commit(
                            None,
                            UpgradeEntryPlan::new(
                                UpgradeTerminalControl::new(
                                    inert_raw_teardown(),
                                    move |_| async move {
                                        established_closes.fetch_add(1, Ordering::SeqCst);
                                    },
                                ),
                                move |_| {
                                    builder_entered_tx.send(()).unwrap();
                                    builder_release_rx.recv().unwrap();
                                    let first_polls = relay_polls.clone();
                                    let second_polls = relay_polls;
                                    async move {
                                        Ok(UpgradeRelayPair::new(
                                            async move {
                                                first_polls.fetch_add(1, Ordering::SeqCst);
                                                UpgradeTerminalCause::PeerClosed
                                            },
                                            async move {
                                                second_polls.fetch_add(1, Ordering::SeqCst);
                                                UpgradeTerminalCause::PeerClosed
                                            },
                                        ))
                                    }
                                },
                            ),
                        )
                        .unwrap();
                    entry_tx.send(entry).unwrap();
                }
            })
            .unwrap();
        let entry = entry_rx.await.unwrap();
        builder_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("setup builder did not execute inside its guarded poll");
        assert_eq!(
            entry.shared.setup_state.load(Ordering::SeqCst),
            SETUP_POLLING
        );
        entry.submit_terminal(UpgradeTerminalCause::Cancelled);
        assert_eq!(
            entry.shared.terminal_state.load(Ordering::SeqCst),
            ENTRY_CLOSE_WAITING_SETUP
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            entry.shared.terminal_state.load(Ordering::SeqCst),
            ENTRY_CLOSE_WAITING_SETUP
        );
        builder_release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), entry.wait_closed())
            .await
            .expect("entry did not close after guarded setup builder returned");
        assert_eq!(
            entry.shared.setup_state.load(Ordering::SeqCst),
            SETUP_SUCCEEDED
        );
        assert_eq!(established_closes.load(Ordering::SeqCst), 1);
        assert_eq!(relay_polls.load(Ordering::SeqCst), 0);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test]
    async fn terminal_before_guarded_setup_poll_skips_builder() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let builds = Arc::new(AtomicUsize::new(0));
        let now = Instant::now();
        let shared = Arc::new(EntryShared {
            timing: Mutex::new(EntryTiming {
                application_stop: now + Duration::from_secs(1),
                cleanup_cutoff: now + Duration::from_secs(2),
                stop_cause: UpgradeTerminalCause::LifetimeExpired,
            }),
            cleanup_grace: Duration::from_millis(100),
            winning_cause: Mutex::new(None),
            setup_state: AtomicU8::new(SETUP_IDLE),
            changed: Notify::new(),
            terminal_state: AtomicU8::new(ENTRY_OPEN),
            closed: Notify::new(),
        });
        shared.begin_closing(
            UpgradeTerminalCause::Cancelled,
            Instant::now(),
            shared.cleanup_grace,
        );
        let setup = LinearizedSetupTask {
            shared: shared.clone(),
            build: Some(Box::new({
                let builds = builds.clone();
                move |_| {
                    builds.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async { Err(UpgradeTerminalCause::SetupFailed) })
                }
            })),
            snapshot: Some(UpgradedStreamSnapshot::new(2, None)),
            setup: None,
        };

        let result = setup.await;
        assert!(result.is_err());
        assert_eq!(builds.load(Ordering::SeqCst), 0);
        assert_eq!(shared.setup_state.load(Ordering::SeqCst), SETUP_IDLE);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn setup_poll_can_reentrantly_begin_shutdown_without_deadlock() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let relay_polls = Arc::new(AtomicUsize::new(0));
        let shutdown_returns = Arc::new(AtomicUsize::new(0));
        let (entry_tx, entry_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let setup_runtime = runtime.clone();
                let relay_polls = relay_polls.clone();
                let shutdown_returns = shutdown_returns.clone();
                move |handshake| async move {
                    let entry = handshake
                        .commit(
                            None,
                            UpgradeEntryPlan::new(inert_control(), move |_| async move {
                                setup_runtime.begin_shutdown(Some(Instant::now()));
                                shutdown_returns.fetch_add(1, Ordering::SeqCst);
                                let first_polls = relay_polls.clone();
                                let second_polls = relay_polls;
                                Ok(UpgradeRelayPair::new(
                                    async move {
                                        first_polls.fetch_add(1, Ordering::SeqCst);
                                        UpgradeTerminalCause::PeerClosed
                                    },
                                    async move {
                                        second_polls.fetch_add(1, Ordering::SeqCst);
                                        UpgradeTerminalCause::PeerClosed
                                    },
                                ))
                            }),
                        )
                        .unwrap();
                    entry_tx.send(entry).unwrap();
                }
            })
            .unwrap();
        let entry = entry_rx.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), entry.wait_closed())
            .await
            .expect("entry did not close after reentrant shutdown setup poll returned");
        assert_eq!(shutdown_returns.load(Ordering::SeqCst), 1);
        assert_eq!(entry.terminal_cause(), Some(UpgradeTerminalCause::Shutdown));
        assert_eq!(
            entry.shared.setup_state.load(Ordering::SeqCst),
            SETUP_SUCCEEDED
        );
        assert_eq!(relay_polls.load(Ordering::SeqCst), 0);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test]
    async fn setup_poll_panic_clears_polling_and_finishes_reentrant_terminal() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let now = Instant::now();
        let shared = Arc::new(EntryShared {
            timing: Mutex::new(EntryTiming {
                application_stop: now + Duration::from_secs(1),
                cleanup_cutoff: now + Duration::from_secs(2),
                stop_cause: UpgradeTerminalCause::LifetimeExpired,
            }),
            cleanup_grace: Duration::from_millis(100),
            winning_cause: Mutex::new(None),
            setup_state: AtomicU8::new(SETUP_IDLE),
            changed: Notify::new(),
            terminal_state: AtomicU8::new(ENTRY_OPEN),
            closed: Notify::new(),
        });
        let entry = CommittedUpgrade {
            _inner: runtime.inner.clone(),
            id: 0,
            shared: shared.clone(),
        };
        let setup = LinearizedSetupTask {
            shared: shared.clone(),
            build: Some(Box::new(move |_| {
                entry.submit_terminal(UpgradeTerminalCause::Cancelled);
                panic!("setup builder panic after reentrant terminal submission");
            })),
            snapshot: Some(UpgradedStreamSnapshot::new(2, None)),
            setup: None,
        };

        let error = match tokio::spawn(setup).await {
            Err(error) => error,
            Ok(_) => panic!("setup task did not panic"),
        };
        assert!(error.is_panic());
        assert_eq!(shared.setup_state.load(Ordering::SeqCst), SETUP_IDLE);
        assert_eq!(shared.terminal_state.load(Ordering::SeqCst), ENTRY_CLOSING);
        assert_eq!(
            *lock(&shared.winning_cause),
            Some(UpgradeTerminalCause::Cancelled)
        );
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn waiting_terminal_submission_cannot_reopen_closed_entry() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let (entry_tx, entry_rx) = oneshot::channel();
        let (setup_entered_tx, setup_entered_rx) = std_mpsc::channel();
        let (setup_release_tx, setup_release_rx) = std_mpsc::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), move |handshake| async move {
                let entry = handshake
                    .commit(
                        None,
                        UpgradeEntryPlan::new(inert_control(), move |_| async move {
                            setup_entered_tx.send(()).unwrap();
                            setup_release_rx.recv().unwrap();
                            Err(UpgradeTerminalCause::SetupFailed)
                        }),
                    )
                    .unwrap();
                entry_tx.send(entry).unwrap();
            })
            .unwrap();
        let entry = entry_rx.await.unwrap();
        setup_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("setup did not enter its gated poll");

        entry.submit_terminal(UpgradeTerminalCause::Cancelled);
        tokio::time::timeout(Duration::from_secs(1), async {
            while entry.shared.terminal_state.load(Ordering::SeqCst) != ENTRY_CLOSE_WAITING_SETUP {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("terminal submission did not wait for the active setup poll");

        runtime.inner.close_entry(entry.id());
        tokio::time::timeout(Duration::from_secs(1), entry.wait_closed())
            .await
            .expect("forced coordinator completion did not close the entry");
        assert_eq!(
            entry.shared.terminal_state.load(Ordering::SeqCst),
            ENTRY_CLOSED
        );

        setup_release_tx.send(()).unwrap();
        tokio::task::yield_now().await;
        assert_eq!(
            entry.shared.terminal_state.load(Ordering::SeqCst),
            ENTRY_CLOSED
        );
        runtime.shutdown_and_wait(Some(Instant::now())).await;
        assert_eq!(runtime.counts().tracked_tasks, 0);
    }

    #[tokio::test]
    async fn coordinator_preserves_cleanup_grace_when_deadlines_lowered_before_first_poll() {
        let runtime =
            UpgradeRuntime::try_new(limits(1, 8).with_cleanup_grace(Duration::from_millis(100)))
                .unwrap();
        let raw_aborts = Arc::new(AtomicUsize::new(0));
        let established_closes = Arc::new(AtomicUsize::new(0));
        let (entry_tx, entry_rx) = oneshot::channel();
        let origin_runtime = runtime.clone();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let raw_aborts = raw_aborts.clone();
                let established_closes = established_closes.clone();
                move |handshake| async move {
                    let entry = handshake
                        .commit(
                            None,
                            UpgradeEntryPlan::new(
                                UpgradeTerminalControl::new(
                                    raw_teardown_with_guard(DropCount(raw_aborts.clone())),
                                    move |_| async move {
                                        established_closes.fetch_add(1, Ordering::SeqCst);
                                    },
                                ),
                                |_| async {
                                    Ok(UpgradeRelayPair::new(
                                        async { UpgradeTerminalCause::PeerClosed },
                                        async {
                                            std::future::pending::<()>().await;
                                            UpgradeTerminalCause::PeerClosed
                                        },
                                    ))
                                },
                            ),
                        )
                        .unwrap();
                    origin_runtime
                        .begin_shutdown(Some(Instant::now() + Duration::from_millis(500)));
                    entry_tx.send(entry).unwrap();
                }
            })
            .unwrap();
        let entry = entry_rx.await.unwrap();
        entry.wait_closed().await;
        assert_eq!(
            entry.terminal_cause(),
            Some(UpgradeTerminalCause::PeerClosed)
        );
        assert_eq!(established_closes.load(Ordering::SeqCst), 1);
        assert_eq!(raw_aborts.load(Ordering::SeqCst), 1);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn upgrade_terminal_races_release_resources_once() {
        let runtime =
            UpgradeRuntime::try_new(limits(1, 8).with_cleanup_grace(Duration::from_millis(30)))
                .unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        let terminal_calls = Arc::new(AtomicUsize::new(0));
        let (entry_tx, entry_rx) = oneshot::channel();
        let (started_tx, started_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let drops = drops.clone();
                let terminal_calls = terminal_calls.clone();
                move |handshake| async move {
                    let terminal = DropCount(drops.clone());
                    let entry = handshake
                        .commit(
                            None,
                            UpgradeEntryPlan::new(
                                UpgradeTerminalControl::new(
                                    raw_teardown_with_guard(terminal),
                                    move |_| async move {
                                        terminal_calls.fetch_add(1, Ordering::SeqCst);
                                        std::future::pending::<()>().await;
                                    },
                                ),
                                move |_| async move {
                                    let first = DropCount(drops.clone());
                                    let second = DropCount(drops.clone());
                                    Ok(UpgradeRelayPair::new(
                                        async move {
                                            let _drop = first;
                                            let _ = started_tx.send(());
                                            std::future::pending::<()>().await;
                                            UpgradeTerminalCause::PeerClosed
                                        },
                                        async move {
                                            let _drop = second;
                                            std::future::pending::<()>().await;
                                            UpgradeTerminalCause::RelayError
                                        },
                                    ))
                                },
                            ),
                        )
                        .unwrap();
                    entry_tx.send(entry).unwrap();
                }
            })
            .unwrap();
        let entry = entry_rx.await.unwrap();
        started_rx.await.unwrap();
        let first = entry.clone();
        let second = entry.clone();
        let third = entry.clone();
        tokio::join!(
            async move { first.submit_terminal(UpgradeTerminalCause::PeerClosed) },
            async move { second.submit_terminal(UpgradeTerminalCause::RelayError) },
            async move { third.submit_terminal(UpgradeTerminalCause::Cancelled) },
        );
        entry.wait_closed().await;
        assert_eq!(terminal_calls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 3);
        assert_eq!(runtime.counts().reserved_slots, 0);
        assert_eq!(runtime.counts().reserved_bytes, 0);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test]
    async fn finite_shutdown_only_lowers_committed_deadlines() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let (entry_tx, entry_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), move |handshake| async move {
                let entry = handshake.commit(None, parked_plan()).unwrap();
                entry_tx.send(entry).unwrap();
            })
            .unwrap();
        let entry = entry_rx.await.unwrap();
        let before = entry.timing();
        let drain = Instant::now() + Duration::from_secs(10);
        runtime.begin_shutdown(Some(drain));
        let after = entry.timing();
        assert!(after.application_stop <= before.application_stop);
        assert_eq!(after.application_stop, drain);
        assert_eq!(after.cleanup_cutoff, drain);
        assert_eq!(after.stop_cause, UpgradeTerminalCause::Shutdown);

        runtime.begin_shutdown(Some(drain + Duration::from_secs(10)));
        assert_eq!(entry.timing().application_stop, drain);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }
}
