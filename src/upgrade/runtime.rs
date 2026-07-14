use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::sync::{mpsc, Notify};
use tokio::task::{AbortHandle, JoinHandle, JoinSet};
use tokio::time::Instant;

use crate::redaction::ProfileHandle;

const ENTRY_OPEN: u8 = 0;
const ENTRY_CLOSING: u8 = 1;
const ENTRY_CLOSED: u8 = 2;
const DEFAULT_ENTRY_CLEANUP_GRACE: Duration = Duration::from_secs(1);

type UpgradeSetupTask =
    Pin<Box<dyn Future<Output = Result<UpgradeRelayPair, UpgradeTerminalCause>> + Send + 'static>>;
type UpgradeSetupBuilder =
    Box<dyn FnOnce(UpgradedStreamSnapshot) -> UpgradeSetupTask + Send + 'static>;
type UpgradeRelayTask = Pin<Box<dyn Future<Output = UpgradeTerminalCause> + Send + 'static>>;
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

    pub(crate) fn rule_index(self) -> usize {
        self.rule_index
    }

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

    pub(crate) fn relay_buffer_bytes(&self) -> usize {
        self.relay_buffer_bytes
    }

    pub(crate) fn wire_redaction(&self) -> Option<&ProfileHandle> {
        self.wire_redaction.as_ref()
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct UpgradeSnapshotContext {
    relay_buffer_bytes: usize,
}

impl UpgradeSnapshotContext {
    pub(crate) fn build(self, wire_redaction: Option<ProfileHandle>) -> UpgradedStreamSnapshot {
        UpgradedStreamSnapshot::new(self.relay_buffer_bytes, wire_redaction)
    }

    pub(crate) fn relay_buffer_bytes(self) -> usize {
        self.relay_buffer_bytes
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
    build: Option<UpgradeTerminalBuilder>,
}

impl UpgradeTerminalControl {
    pub(crate) fn new<Build, Task>(build: Build) -> Self
    where
        Build: FnOnce(UpgradeTerminalCause) -> Task + Send + 'static,
        Task: Future<Output = ()> + Send + 'static,
    {
        Self {
            build: Some(Box::new(move |cause| Box::pin(build(cause)))),
        }
    }

    fn into_task(mut self, cause: UpgradeTerminalCause) -> UpgradeTerminalTask {
        self.build
            .take()
            .expect("terminal control is consumed exactly once")(cause)
    }
}

pub(crate) struct UpgradeRelayPair {
    first: UpgradeRelayTask,
    second: UpgradeRelayTask,
    terminal: UpgradeTerminalControl,
}

impl UpgradeRelayPair {
    pub(crate) fn new<First, Second>(
        first: First,
        second: Second,
        terminal: UpgradeTerminalControl,
    ) -> Self
    where
        First: Future<Output = UpgradeTerminalCause> + Send + 'static,
        Second: Future<Output = UpgradeTerminalCause> + Send + 'static,
    {
        Self {
            first: Box::pin(first),
            second: Box::pin(second),
            terminal,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UpgradeTerminalCause {
    PeerClosed,
    RelayError,
    LifetimeExpired,
    Shutdown,
    Cancelled,
    SetupFailed,
    DownstreamWriteFailed,
}

pub(crate) struct UpgradeRuntime {
    inner: Arc<RuntimeInner>,
    supervisor: Mutex<Option<JoinHandle<()>>>,
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
}

struct EntryShared {
    timing: Mutex<EntryTiming>,
    setup: Mutex<Option<UpgradeSetupBuilder>>,
    requested_cause: Mutex<Option<UpgradeTerminalCause>>,
    winning_cause: Mutex<Option<UpgradeTerminalCause>>,
    changed: Notify,
    terminal_state: AtomicU8,
    started: AtomicBool,
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
    Stop,
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
        self.inner.release_uncommitted(self.id);
    }
}

enum EntryTaskResult {
    Setup(Result<UpgradeRelayPair, UpgradeTerminalCause>),
    Relay(UpgradeTerminalCause),
    TerminalControl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryPhase {
    WaitingForSetup,
    SettingUp,
    Relaying,
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
            supervisor: Mutex::new(Some(supervisor)),
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
        let (uncommitted, entries) = {
            let mut state = lock(&self.inner.state);
            state.accepting = false;
            let uncommitted = state
                .uncommitted
                .values()
                .map(|record| record.abort.clone())
                .collect::<Vec<_>>();
            let entries = state
                .entries
                .values()
                .map(|record| record.shared.clone())
                .collect::<Vec<_>>();
            (uncommitted, entries)
        };

        for abort in uncommitted {
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
                !state.accepting && state.uncommitted.is_empty() && state.entries.is_empty()
            };
            if drained {
                return;
            }
            notified.await;
        }
    }

    pub(crate) async fn shutdown_and_wait(&self, drain_deadline: Option<Instant>) {
        self.begin_shutdown(drain_deadline);
        self.wait_until_registry_drained().await;
        let supervisor = {
            let mut owned = lock(&self.supervisor);
            let Some(supervisor) = owned.take() else {
                return;
            };
            let _ = self.inner.supervisor_tasks.send(SupervisorCommand::Stop);
            supervisor
        };
        let _ = supervisor.await;
        self.wait_until_drained().await;
    }

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
        let supervisor = lock(&self.supervisor).take();
        if let Some(supervisor) = supervisor {
            supervisor.abort();
        }
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
    fn release_uncommitted(&self, id: u64) {
        let removed = {
            let mut state = lock(&self.state);
            let Some(record) = state.uncommitted.remove(&id) else {
                return;
            };
            release_reservation(&mut state, record.reservation);
            true
        };
        if removed {
            self.changed.notify_waiters();
        }
    }

    fn close_entry(&self, id: u64) {
        let shared = {
            let mut state = lock(&self.state);
            let Some(record) = state.entries.remove(&id) else {
                return;
            };
            release_reservation(&mut state, record.reservation);
            record.shared
        };
        shared.terminal_state.store(ENTRY_CLOSED, Ordering::Release);
        drop(lock(&shared.setup).take());
        let _ = lock(&shared.requested_cause).take();
        shared.closed.notify_waiters();
        self.changed.notify_waiters();
    }

    fn spawn_entry_coordinator(
        self: &Arc<Self>,
        state: &mut RuntimeState,
        id: u64,
        shared: Arc<EntryShared>,
        snapshot: UpgradedStreamSnapshot,
    ) -> Result<(), OwnedTask> {
        let completion = EntryCompletionGuard {
            inner: self.clone(),
            id,
        };
        let counted = Arc::new(AtomicBool::new(true));
        let task_completion = TrackedTaskCompletion {
            inner: self.clone(),
            counted: counted.clone(),
        };
        let task = self.handle.spawn(async move {
            async move {
                let _task_completion = task_completion;
                let _completion = completion;
                run_entry_coordinator(shared, snapshot).await;
            }
            .await;
        });
        state.tracked_tasks = state
            .tracked_tasks
            .checked_add(1)
            .expect("tracked task count cannot overflow bounded upgrade metadata");
        if let Err(error) = self
            .supervisor_tasks
            .send(SupervisorCommand::Track(OwnedTask::new(task)))
        {
            let SupervisorCommand::Track(task) = error.0 else {
                unreachable!("only a tracked task was sent")
            };
            if counted.swap(false, Ordering::AcqRel) {
                state.tracked_tasks -= 1;
            }
            return Err(task);
        }
        Ok(())
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
    pub(crate) fn allocation(&self) -> UpgradeAllocation {
        self.reservation.allocation
    }

    pub(crate) fn reserved_bytes(&self) -> usize {
        self.reservation.bytes
    }

    /// Commits only while admission remains open. Snapshot construction and
    /// deadline derivation both happen inside the same winning gate.
    pub(crate) fn commit<Build>(
        mut self,
        snapshot_builder: Build,
    ) -> Result<CommittedUpgrade, UpgradeCommitError>
    where
        Build: FnOnce(UpgradeSnapshotContext) -> UpgradedStreamSnapshot,
    {
        self.commit_with_hook(snapshot_builder, || {})
    }

    fn commit_with_hook<Build, Hook>(
        &mut self,
        snapshot_builder: Build,
        hook: Hook,
    ) -> Result<CommittedUpgrade, UpgradeCommitError>
    where
        Build: FnOnce(UpgradeSnapshotContext) -> UpgradedStreamSnapshot,
        Hook: FnOnce(),
    {
        let mut state = lock(&self.inner.state);
        hook();
        if !state.accepting {
            return Err(UpgradeCommitError::AdmissionClosed);
        }
        let record = state
            .uncommitted
            .get(&self.id)
            .ok_or(UpgradeCommitError::HandshakeReleased)?;
        debug_assert_eq!(record.reservation, self.reservation);

        let snapshot = snapshot_builder(UpgradeSnapshotContext {
            relay_buffer_bytes: self.inner.limits.relay_buffer_bytes,
        });
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
            setup: Mutex::new(None),
            requested_cause: Mutex::new(None),
            winning_cause: Mutex::new(None),
            changed: Notify::new(),
            terminal_state: AtomicU8::new(ENTRY_OPEN),
            started: AtomicBool::new(false),
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
            },
        );
        if let Err(task) =
            self.inner
                .spawn_entry_coordinator(&mut state, self.id, shared.clone(), snapshot)
        {
            let record = state
                .entries
                .remove(&self.id)
                .expect("new committed entry remains present");
            release_reservation(&mut state, record.reservation);
            drop(state);
            drop(task);
            return Err(UpgradeCommitError::SupervisorStopped);
        }
        drop(state);
        self.inner.changed.notify_waiters();
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
                &self.shared.terminal_state.load(Ordering::Acquire),
            )
            .field("terminal_cause", &self.terminal_cause())
            .finish()
    }
}

impl CommittedUpgrade {
    /// Installs post-commit setup. Setup owns downstream 101 emission and
    /// returns both relay futures plus mandatory terminal control. The narrow
    /// snapshot is transferred into setup, never retained by clonable handles.
    pub(crate) fn start<Build, Setup>(&self, build: Build) -> Result<(), UpgradeEntryStartError>
    where
        Build: FnOnce(UpgradedStreamSnapshot) -> Setup + Send + 'static,
        Setup: Future<Output = Result<UpgradeRelayPair, UpgradeTerminalCause>> + Send + 'static,
    {
        if self.shared.terminal_state.load(Ordering::Acquire) != ENTRY_OPEN {
            return Err(UpgradeEntryStartError::Closed);
        }
        if self.shared.started.swap(true, Ordering::AcqRel) {
            return Err(UpgradeEntryStartError::AlreadyStarted);
        }
        let mut setup = lock(&self.shared.setup);
        if self.shared.terminal_state.load(Ordering::Acquire) != ENTRY_OPEN {
            return Err(UpgradeEntryStartError::Closed);
        }
        *setup = Some(Box::new(move |snapshot| Box::pin(build(snapshot))));
        drop(setup);
        self.shared.changed.notify_waiters();
        Ok(())
    }

    pub(crate) fn submit_terminal(&self, cause: UpgradeTerminalCause) {
        let mut requested = lock(&self.shared.requested_cause);
        if requested.is_none() {
            *requested = Some(cause);
            drop(requested);
            self.shared.changed.notify_waiters();
        }
    }

    pub(crate) async fn wait_closed(&self) {
        loop {
            let notified = self.shared.closed.notified();
            if self.shared.terminal_state.load(Ordering::Acquire) == ENTRY_CLOSED {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn terminal_cause(&self) -> Option<UpgradeTerminalCause> {
        *lock(&self.shared.winning_cause)
    }

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
                ENTRY_CLOSING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            *lock(&self.winning_cause) = Some(cause);
            let cause_cutoff = now.checked_add(cleanup_grace).unwrap_or(now);
            let mut timing = lock(&self.timing);
            timing.application_stop = timing.application_stop.min(now);
            timing.cleanup_cutoff = timing.cleanup_cutoff.min(cause_cutoff);
            drop(timing);
            self.changed.notify_waiters();
        }
    }
}

struct EntryCompletionGuard {
    inner: Arc<RuntimeInner>,
    id: u64,
}

impl Drop for EntryCompletionGuard {
    fn drop(&mut self) {
        self.inner.close_entry(self.id);
    }
}

async fn run_task_supervisor(mut receiver: mpsc::UnboundedReceiver<SupervisorCommand>) {
    let mut tasks = JoinSet::new();
    let mut stopping = false;
    loop {
        if stopping && tasks.is_empty() {
            return;
        }
        tokio::select! {
            biased;
            joined = tasks.join_next(), if !tasks.is_empty() => {
                let _ = joined;
            }
            command = receiver.recv(), if !stopping => {
                match command {
                    Some(SupervisorCommand::Track(task)) => {
                        tasks.spawn(async move { task.await });
                    }
                    Some(SupervisorCommand::Stop) | None => stopping = true,
                }
            }
        }
    }
}

async fn run_entry_coordinator(shared: Arc<EntryShared>, snapshot: UpgradedStreamSnapshot) {
    let cleanup_grace = {
        let timing = lock(&shared.timing);
        timing
            .cleanup_cutoff
            .saturating_duration_since(timing.application_stop)
    };
    let mut tasks = JoinSet::new();
    let mut snapshot = Some(snapshot);
    let mut phase = EntryPhase::WaitingForSetup;
    let mut terminal_control: Option<UpgradeTerminalControl> = None;

    loop {
        let changed = shared.changed.notified();
        if shared.terminal_state.load(Ordering::Acquire) == ENTRY_OPEN {
            let requested = { lock(&shared.requested_cause).take() };
            if let Some(cause) = requested {
                shared.begin_closing(cause, Instant::now(), cleanup_grace);
            } else {
                let timing = *lock(&shared.timing);
                if Instant::now() >= timing.application_stop {
                    shared.begin_closing(timing.stop_cause, timing.application_stop, cleanup_grace);
                }
            }
        }

        if shared.terminal_state.load(Ordering::Acquire) == ENTRY_CLOSING {
            match phase {
                EntryPhase::WaitingForSetup | EntryPhase::SettingUp => {
                    tasks.abort_all();
                    tasks.shutdown().await;
                    return;
                }
                EntryPhase::Relaying => {
                    let timing = *lock(&shared.timing);
                    if Instant::now() >= timing.cleanup_cutoff {
                        tasks.abort_all();
                        tasks.shutdown().await;
                        return;
                    }
                    if let Some(control) = terminal_control.take() {
                        let cause = lock(&shared.winning_cause)
                            .expect("closing entry has a winning terminal cause");
                        tasks.spawn(async move {
                            control.into_task(cause).await;
                            EntryTaskResult::TerminalControl
                        });
                    }
                    if tasks.is_empty() {
                        return;
                    }
                    tokio::select! {
                        biased;
                        _ = tokio::time::sleep_until(timing.cleanup_cutoff) => {
                            tasks.abort_all();
                            tasks.shutdown().await;
                            return;
                        }
                        _ = changed => {}
                        joined = tasks.join_next() => {
                            let _ = joined;
                        }
                    }
                    continue;
                }
            }
        }

        if phase == EntryPhase::WaitingForSetup {
            let build = { lock(&shared.setup).take() };
            if let Some(build) = build {
                let snapshot = snapshot
                    .take()
                    .expect("entry setup is installed at most once");
                tasks.spawn(async move {
                    let setup = build(snapshot);
                    EntryTaskResult::Setup(setup.await)
                });
                phase = EntryPhase::SettingUp;
                continue;
            }
        }

        let timing = *lock(&shared.timing);
        tokio::select! {
            biased;
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
            joined = tasks.join_next(), if !tasks.is_empty() => {
                match (phase, joined) {
                    (EntryPhase::SettingUp, Some(Ok(EntryTaskResult::Setup(Ok(pair))))) => {
                        terminal_control = Some(pair.terminal);
                        tasks.spawn(async move { EntryTaskResult::Relay(pair.first.await) });
                        tasks.spawn(async move { EntryTaskResult::Relay(pair.second.await) });
                        phase = EntryPhase::Relaying;
                    }
                    (EntryPhase::SettingUp, Some(Ok(EntryTaskResult::Setup(Err(cause))))) => {
                        shared.begin_closing(cause, Instant::now(), cleanup_grace);
                    }
                    (EntryPhase::SettingUp, Some(Err(_))) => {
                        shared.begin_closing(
                            UpgradeTerminalCause::SetupFailed,
                            Instant::now(),
                            cleanup_grace,
                        );
                    }
                    (EntryPhase::Relaying, Some(Ok(EntryTaskResult::Relay(cause)))) => {
                        shared.begin_closing(cause, Instant::now(), cleanup_grace);
                    }
                    (EntryPhase::Relaying, Some(Err(_))) => {
                        shared.begin_closing(
                            UpgradeTerminalCause::RelayError,
                            Instant::now(),
                            cleanup_grace,
                        );
                    }
                    (_, Some(Ok(EntryTaskResult::TerminalControl)))
                    | (_, Some(Ok(EntryTaskResult::Setup(_))))
                    | (_, Some(Ok(EntryTaskResult::Relay(_))))
                    | (_, None) => {}
                    (EntryPhase::WaitingForSetup, Some(Err(_))) => {
                        unreachable!("waiting phase owns no coordinator task")
                    }
                }
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum UpgradeEntryStartError {
    #[error("the committed upgrade is already closed")]
    Closed,
    #[error("the committed upgrade was already started")]
    AlreadyStarted,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc as std_mpsc, Barrier};
    use std::thread;

    use tokio::sync::oneshot;

    use super::*;

    fn limits(slots: usize, bytes: usize) -> UpgradeRuntimeLimits {
        UpgradeRuntimeLimits::new(slots, bytes, 2, Duration::from_secs(60))
    }

    fn short_limits(lifetime: Duration, cleanup: Duration) -> UpgradeRuntimeLimits {
        UpgradeRuntimeLimits::new(2, 64, 2, lifetime).with_cleanup_grace(cleanup)
    }

    fn allocation(rule: usize, wire_bytes: usize) -> UpgradeAllocation {
        UpgradeAllocation::from_compiled_rule(rule, Some(wire_bytes)).unwrap()
    }

    fn snapshot(context: UpgradeSnapshotContext) -> UpgradedStreamSnapshot {
        context.build(None)
    }

    fn inert_control() -> UpgradeTerminalControl {
        UpgradeTerminalControl::new(|_| async {})
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
    async fn upgrade_admission_shutdown_race_linearizes_registry_snapshot() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let snapshots = Arc::new(AtomicUsize::new(0));
        let setup_effects = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let (result_tx, result_rx) = std_mpsc::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let snapshots = snapshots.clone();
                let entered = entered.clone();
                let release = release.clone();
                move |mut handshake| async move {
                    let result = handshake.commit_with_hook(
                        |context| {
                            snapshots.fetch_add(1, Ordering::SeqCst);
                            snapshot(context)
                        },
                        || {
                            entered.wait();
                            release.wait();
                        },
                    );
                    result_tx.send(result).unwrap();
                }
            })
            .unwrap();
        entered.wait();
        let shutdown_runtime = runtime.clone();
        let shutdown = thread::spawn(move || {
            shutdown_runtime.begin_shutdown(Some(Instant::now()));
        });
        release.wait();
        shutdown.join().unwrap();
        let entry = result_rx.recv().unwrap().expect("commit won the gate");
        let _ = entry.start({
            let setup_effects = setup_effects.clone();
            move |_| async move {
                setup_effects.fetch_add(1, Ordering::SeqCst);
                Err(UpgradeTerminalCause::DownstreamWriteFailed)
            }
        });
        entry.wait_closed().await;
        assert_eq!(snapshots.load(Ordering::SeqCst), 1);
        assert_eq!(setup_effects.load(Ordering::SeqCst), 0);
        runtime.wait_until_drained().await;

        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let snapshots = Arc::new(AtomicUsize::new(0));
        let setup_effects = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = std_mpsc::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let (result_tx, result_rx) = std_mpsc::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let snapshots = snapshots.clone();
                let setup_effects = setup_effects.clone();
                move |handshake| async move {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    let result = handshake.commit(|context| {
                        snapshots.fetch_add(1, Ordering::SeqCst);
                        snapshot(context)
                    });
                    if let Ok(entry) = &result {
                        entry
                            .start(move |_| async move {
                                setup_effects.fetch_add(1, Ordering::SeqCst);
                                Err(UpgradeTerminalCause::DownstreamWriteFailed)
                            })
                            .unwrap();
                    }
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
        runtime.wait_until_drained().await;
        assert_eq!(snapshots.load(Ordering::SeqCst), 0);
        assert_eq!(setup_effects.load(Ordering::SeqCst), 0);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test]
    async fn committed_handshake_can_await_close_and_run_post_close_work() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let post_close = Arc::new(AtomicUsize::new(0));
        let (entry_tx, entry_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), {
                let post_close = post_close.clone();
                move |handshake| async move {
                    let entry = handshake.commit(snapshot).unwrap();
                    entry
                        .start(|_| async {
                            Ok(UpgradeRelayPair::new(
                                async { UpgradeTerminalCause::PeerClosed },
                                async { UpgradeTerminalCause::PeerClosed },
                                inert_control(),
                            ))
                        })
                        .unwrap();
                    entry_tx.send(entry.clone()).unwrap();
                    entry.wait_closed().await;
                    post_close.fetch_add(1, Ordering::SeqCst);
                }
            })
            .unwrap();
        let entry = entry_rx.await.unwrap();
        entry.wait_closed().await;
        wait_for_counts(&runtime, |counts| counts.tracked_tasks == 0).await;
        assert_eq!(post_close.load(Ordering::SeqCst), 1);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test]
    async fn exact_relay_cause_reaches_terminal_control() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let (cause_tx, cause_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(allocation(0, 0), move |handshake| async move {
                let entry = handshake.commit(snapshot).unwrap();
                entry
                    .start(|_| async move {
                        Ok(UpgradeRelayPair::new(
                            async { UpgradeTerminalCause::RelayError },
                            async move {
                                let _ = release_rx.await;
                                UpgradeTerminalCause::PeerClosed
                            },
                            UpgradeTerminalControl::new(move |cause| async move {
                                let _ = cause_tx.send(cause);
                                let _ = release_tx.send(());
                            }),
                        ))
                    })
                    .unwrap();
                entry.wait_closed().await;
            })
            .unwrap();
        assert_eq!(cause_rx.await.unwrap(), UpgradeTerminalCause::RelayError);
        runtime.begin_shutdown(Some(Instant::now()));
        runtime.wait_until_drained().await;
        runtime.shutdown_and_wait(Some(Instant::now())).await;
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
                let entry = handshake.commit(snapshot).unwrap();
                entry
                    .start(|_| async move {
                        Ok(UpgradeRelayPair::new(
                            async { UpgradeTerminalCause::PeerClosed },
                            async move {
                                let _ = relay_release_rx.await;
                                UpgradeTerminalCause::PeerClosed
                            },
                            UpgradeTerminalControl::new(move |_| async move {
                                let _ = cleanup_started_tx.send(());
                                let _ = cleanup_release_rx.await;
                            }),
                        ))
                    })
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
                let entry = handshake.commit(snapshot).unwrap();
                entry
                    .start(|_| async move {
                        Ok(UpgradeRelayPair::new(
                            async { UpgradeTerminalCause::PeerClosed },
                            async move {
                                let _drop = relay_drop;
                                std::future::pending::<()>().await;
                                UpgradeTerminalCause::PeerClosed
                            },
                            UpgradeTerminalControl::new(move |_| async move {
                                let _drop = cleanup_drop;
                                std::future::pending::<()>().await;
                            }),
                        ))
                    })
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
                    let entry = handshake.commit(snapshot).unwrap();
                    entry
                        .start(move |_| async move {
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
                                inert_control(),
                            ))
                        })
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
                    let entry = handshake.commit(snapshot).unwrap();
                    entry
                        .start(move |_| async move {
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
                                UpgradeTerminalControl::new(move |_| async move {
                                    control_calls.fetch_add(1, Ordering::SeqCst);
                                }),
                            ))
                        })
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
            let (entry_tx, entry_rx) = oneshot::channel();
            runtime
                .try_spawn_handshake(allocation(0, 0), move |handshake| async move {
                    let entry = handshake.commit(snapshot).unwrap();
                    entry
                        .start(move |_| async move {
                            if panic_setup {
                                panic!("setup panic");
                            }
                            Err(UpgradeTerminalCause::DownstreamWriteFailed)
                        })
                        .unwrap();
                    entry_tx.send(entry).unwrap();
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
            runtime.shutdown_and_wait(Some(Instant::now())).await;
        }
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
                    let entry = handshake.commit(snapshot).unwrap();
                    entry
                        .start(move |_| async move {
                            let first = DropCount(drops.clone());
                            let second = DropCount(drops.clone());
                            let terminal = DropCount(drops.clone());
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
                                UpgradeTerminalControl::new(move |_| async move {
                                    let _drop = terminal;
                                    terminal_calls.fetch_add(1, Ordering::SeqCst);
                                    std::future::pending::<()>().await;
                                }),
                            ))
                        })
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
                let entry = handshake.commit(snapshot).unwrap();
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
