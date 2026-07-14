use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, Notify};
use tokio::task::{AbortHandle, JoinHandle, JoinSet};
use tokio::time::Instant;

use crate::redaction::ProfileHandle;

const ENTRY_OPEN: u8 = 0;
const ENTRY_CLOSING: u8 = 1;
const ENTRY_CLOSED: u8 = 2;
const ENTRY_CLEANUP_GRACE: Duration = Duration::from_secs(1);

type UpgradeTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type UpgradeSetupTask =
    Pin<Box<dyn Future<Output = Result<UpgradeRelayPair, UpgradeTerminalCause>> + Send + 'static>>;
type UpgradeSetupBuilder =
    Box<dyn FnOnce(UpgradedStreamSnapshot) -> UpgradeSetupTask + Send + 'static>;
type UpgradeRelayTask = Pin<Box<dyn Future<Output = UpgradeTerminalCause> + Send + 'static>>;

/// Static limits for the one process-owned upgrade runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UpgradeRuntimeLimits {
    max_active_upgrades: usize,
    max_upgrade_buffer_bytes: usize,
    relay_buffer_bytes: usize,
    max_upgrade_lifetime: Duration,
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
        }
    }

    pub(crate) fn relay_buffer_bytes(self) -> usize {
        self.relay_buffer_bytes
    }
}

/// The compiler-produced exact reservation for one matched rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UpgradeAllocation {
    rule_index: usize,
    bytes: usize,
}

impl UpgradeAllocation {
    pub(crate) fn from_compiled_rule(
        rule_index: usize,
        compiled_bytes: Option<usize>,
    ) -> Result<Self, UpgradeAllocationError> {
        let bytes = compiled_bytes.ok_or(UpgradeAllocationError::RuleDisallowsUpgrades)?;
        if bytes == 0 {
            return Err(UpgradeAllocationError::ZeroBytes);
        }
        Ok(Self { rule_index, bytes })
    }

    pub(crate) fn rule_index(self) -> usize {
        self.rule_index
    }

    pub(crate) fn bytes(self) -> usize {
        self.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum UpgradeAllocationError {
    #[error("the matched rule does not allow upgrades")]
    RuleDisallowsUpgrades,
    #[error("the compiled upgrade allocation must be positive")]
    ZeroBytes,
}

/// Immutable state retained by an established stream. This type deliberately
/// contains no generation lease or generation-owned provider/callback handle.
pub(crate) struct UpgradedStreamSnapshot {
    relay_buffer_bytes: usize,
    wire_redaction: Option<ProfileHandle>,
}

impl UpgradedStreamSnapshot {
    pub(crate) fn new(relay_buffer_bytes: usize, wire_redaction: Option<ProfileHandle>) -> Self {
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

impl fmt::Debug for UpgradedStreamSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpgradedStreamSnapshot")
            .field("relay_buffer_bytes", &self.relay_buffer_bytes)
            .field("wire_redaction", &self.wire_redaction.is_some())
            .finish()
    }
}

pub(crate) struct UpgradeRelayPair {
    first: UpgradeRelayTask,
    second: UpgradeRelayTask,
}

impl UpgradeRelayPair {
    pub(crate) fn new<First, Second>(first: First, second: Second) -> Self
    where
        First: Future<Output = UpgradeTerminalCause> + Send + 'static,
        Second: Future<Output = UpgradeTerminalCause> + Send + 'static,
    {
        Self {
            first: Box::pin(first),
            second: Box::pin(second),
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
    state: Mutex<RuntimeState>,
    changed: Notify,
    tasks: mpsc::UnboundedSender<TaskCommand>,
}

struct RuntimeState {
    accepting: bool,
    next_id: u64,
    reserved_slots: usize,
    reserved_bytes: usize,
    supervisor_tasks: usize,
    uncommitted: HashMap<u64, UncommittedRecord>,
    entries: HashMap<u64, EntryRecord>,
}

struct UncommittedRecord {
    allocation: UpgradeAllocation,
    abort: Option<AbortHandle>,
}

struct EntryRecord {
    allocation: UpgradeAllocation,
    shared: Arc<EntryShared>,
    handshake_abort: Option<AbortHandle>,
    coordinator_abort: Option<AbortHandle>,
}

struct EntryShared {
    timing: Mutex<EntryTiming>,
    setup: Mutex<Option<UpgradeSetupBuilder>>,
    terminal_cause: Mutex<Option<UpgradeTerminalCause>>,
    changed: Notify,
    terminal_state: AtomicU8,
    started: AtomicBool,
    closed: Notify,
}

#[derive(Clone, Copy, Debug)]
struct EntryTiming {
    application_stop: Instant,
    cleanup_cutoff: Instant,
}

enum TaskCommand {
    StartHandshake { id: u64, task: UpgradeTask },
    StartEntry { id: u64, task: UpgradeTask },
    Stop,
}

#[derive(Clone, Copy)]
enum TaskKind {
    Handshake,
    Entry,
}

enum EntryTaskResult {
    Setup(Result<UpgradeRelayPair, UpgradeTerminalCause>),
    Relay(UpgradeTerminalCause),
}

impl UpgradeRuntime {
    pub(crate) fn try_new(limits: UpgradeRuntimeLimits) -> Result<Arc<Self>, UpgradeRuntimeError> {
        validate_limits(limits)?;
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| UpgradeRuntimeError::RuntimeUnavailable)?;
        let (tasks, receiver) = mpsc::unbounded_channel();
        let inner = Arc::new(RuntimeInner {
            limits,
            state: Mutex::new(RuntimeState {
                accepting: true,
                next_id: 0,
                reserved_slots: 0,
                reserved_bytes: 0,
                supervisor_tasks: 0,
                uncommitted: HashMap::new(),
                entries: HashMap::new(),
            }),
            changed: Notify::new(),
            tasks,
        });
        let supervisor_inner = inner.clone();
        let supervisor = handle.spawn(async move {
            run_task_supervisor(supervisor_inner, receiver).await;
        });
        Ok(Arc::new(Self {
            inner,
            supervisor: Mutex::new(Some(supervisor)),
        }))
    }

    pub(crate) fn limits(&self) -> UpgradeRuntimeLimits {
        self.inner.limits
    }

    pub(crate) fn try_admit(
        self: &Arc<Self>,
        allocation: UpgradeAllocation,
    ) -> Result<UpgradeAdmissionGuard, UpgradeAdmissionError> {
        let mut state = lock(&self.inner.state);
        if !state.accepting {
            return Err(UpgradeAdmissionError::Closed);
        }
        if state.reserved_slots >= self.inner.limits.max_active_upgrades {
            return Err(UpgradeAdmissionError::SlotCapacity);
        }
        let next_bytes = state
            .reserved_bytes
            .checked_add(allocation.bytes)
            .ok_or(UpgradeAdmissionError::BufferCapacity)?;
        if next_bytes > self.inner.limits.max_upgrade_buffer_bytes {
            return Err(UpgradeAdmissionError::BufferCapacity);
        }
        let id = state.next_id;
        state.next_id = state
            .next_id
            .checked_add(1)
            .ok_or(UpgradeAdmissionError::IdentifierExhausted)?;
        state.reserved_slots += 1;
        state.reserved_bytes = next_bytes;
        state.uncommitted.insert(
            id,
            UncommittedRecord {
                allocation,
                abort: None,
            },
        );
        drop(state);
        Ok(UpgradeAdmissionGuard {
            inner: self.inner.clone(),
            id,
            allocation,
            committed: false,
        })
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
                .filter_map(|record| record.abort.clone())
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
                    && state.supervisor_tasks == 0
            };
            if drained {
                break;
            }
            notified.await;
        }
    }

    pub(crate) async fn shutdown_and_wait(&self, drain_deadline: Option<Instant>) {
        self.begin_shutdown(drain_deadline);
        self.wait_until_drained().await;
        let supervisor = {
            let mut owned = lock(&self.supervisor);
            let Some(supervisor) = owned.take() else {
                return;
            };
            let _ = self.inner.tasks.send(TaskCommand::Stop);
            supervisor
        };
        let _ = supervisor.await;
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
            supervisor_tasks: state.supervisor_tasks,
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
    let now = Instant::now();
    now.checked_add(limits.max_upgrade_lifetime)
        .and_then(|deadline| deadline.checked_add(ENTRY_CLEANUP_GRACE))
        .ok_or(UpgradeRuntimeError::LifetimeOverflow)?;
    Ok(())
}

impl RuntimeInner {
    fn release_uncommitted(&self, id: u64) {
        let removed = {
            let mut state = lock(&self.state);
            let Some(record) = state.uncommitted.remove(&id) else {
                return;
            };
            release_reservation(&mut state, record.allocation);
            true
        };
        if removed {
            self.changed.notify_waiters();
        }
    }

    fn close_entry(&self, id: u64) {
        let (shared, handshake_abort) = {
            let mut state = lock(&self.state);
            let Some(record) = state.entries.remove(&id) else {
                return;
            };
            release_reservation(&mut state, record.allocation);
            (record.shared, record.handshake_abort)
        };
        shared.terminal_state.store(ENTRY_CLOSED, Ordering::Release);
        if let Some(abort) = handshake_abort {
            abort.abort();
        }
        drop(lock(&shared.setup).take());
        let _ = lock(&shared.terminal_cause).take();
        shared.closed.notify_waiters();
        self.changed.notify_waiters();
    }

    fn task_finished(&self) {
        let mut state = lock(&self.state);
        state.supervisor_tasks = state
            .supervisor_tasks
            .checked_sub(1)
            .expect("upgrade supervisor task count cannot underflow");
        drop(state);
        self.changed.notify_waiters();
    }
}

fn release_reservation(state: &mut RuntimeState, allocation: UpgradeAllocation) {
    state.reserved_slots = state
        .reserved_slots
        .checked_sub(1)
        .expect("upgrade slot accounting cannot underflow");
    state.reserved_bytes = state
        .reserved_bytes
        .checked_sub(allocation.bytes)
        .expect("upgrade byte accounting cannot underflow");
}

pub(crate) struct UpgradeAdmissionGuard {
    inner: Arc<RuntimeInner>,
    id: u64,
    allocation: UpgradeAllocation,
    committed: bool,
}

impl fmt::Debug for UpgradeAdmissionGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpgradeAdmissionGuard")
            .field("id", &self.id)
            .field("allocation", &self.allocation)
            .field("committed", &self.committed)
            .finish()
    }
}

impl UpgradeAdmissionGuard {
    pub(crate) fn allocation(&self) -> UpgradeAllocation {
        self.allocation
    }

    /// Transfers the guard into the runtime-owned uncommitted task set. The
    /// task must call `commit` only after body completion and 101 validation.
    pub(crate) fn spawn_handshake<Build, Task>(
        self,
        build: Build,
    ) -> Result<(), UpgradeHandshakeSpawnError>
    where
        Build: FnOnce(UpgradeAdmissionGuard) -> Task,
        Task: Future<Output = ()> + Send + 'static,
    {
        let id = self.id;
        let sender = self.inner.tasks.clone();
        let task = Box::pin(build(self));
        sender
            .send(TaskCommand::StartHandshake { id, task })
            .map_err(|_| UpgradeHandshakeSpawnError::SupervisorStopped)
    }

    pub(crate) fn commit(
        mut self,
        snapshot: UpgradedStreamSnapshot,
    ) -> Result<CommittedUpgrade, UpgradeCommitError> {
        self.commit_with_hook(snapshot, || {})
    }

    fn commit_with_hook(
        &mut self,
        snapshot: UpgradedStreamSnapshot,
        hook: impl FnOnce(),
    ) -> Result<CommittedUpgrade, UpgradeCommitError> {
        let now = Instant::now();
        let application_stop = now
            .checked_add(self.inner.limits.max_upgrade_lifetime)
            .ok_or(UpgradeCommitError::LifetimeOverflow)?;
        let cleanup_cutoff = application_stop
            .checked_add(ENTRY_CLEANUP_GRACE)
            .ok_or(UpgradeCommitError::LifetimeOverflow)?;
        let shared = Arc::new(EntryShared {
            timing: Mutex::new(EntryTiming {
                application_stop,
                cleanup_cutoff,
            }),
            setup: Mutex::new(None),
            terminal_cause: Mutex::new(None),
            changed: Notify::new(),
            terminal_state: AtomicU8::new(ENTRY_OPEN),
            started: AtomicBool::new(false),
            closed: Notify::new(),
        });

        {
            let mut state = lock(&self.inner.state);
            hook();
            if !state.accepting {
                return Err(UpgradeCommitError::AdmissionClosed);
            }
            let record = state
                .uncommitted
                .remove(&self.id)
                .ok_or(UpgradeCommitError::GuardReleased)?;
            debug_assert_eq!(record.allocation, self.allocation);
            state.entries.insert(
                self.id,
                EntryRecord {
                    allocation: record.allocation,
                    shared: shared.clone(),
                    handshake_abort: record.abort,
                    coordinator_abort: None,
                },
            );
            self.committed = true;
        }

        let completion = EntryCompletionGuard {
            inner: self.inner.clone(),
            id: self.id,
        };
        let coordinator_inner = self.inner.clone();
        let coordinator_shared = shared.clone();
        let id = self.id;
        let task = Box::pin(async move {
            let _completion = completion;
            run_entry_coordinator(coordinator_inner, id, coordinator_shared, snapshot).await;
        });
        if self
            .inner
            .tasks
            .send(TaskCommand::StartEntry { id, task })
            .is_err()
        {
            self.inner.close_entry(id);
            return Err(UpgradeCommitError::SupervisorStopped);
        }
        Ok(CommittedUpgrade {
            _inner: self.inner.clone(),
            id,
            shared,
        })
    }
}

impl Drop for UpgradeAdmissionGuard {
    fn drop(&mut self) {
        if !self.committed {
            self.inner.release_uncommitted(self.id);
        }
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
            .finish()
    }
}

impl CommittedUpgrade {
    /// Installs the post-commit setup. Setup owns downstream 101 emission and
    /// returns both relay futures, whose handles remain coordinator-owned. The
    /// narrow stream snapshot is transferred into setup and is never retained
    /// by clonable registry handles.
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
        let mut terminal = lock(&self.shared.terminal_cause);
        if terminal.is_none() {
            *terminal = Some(cause);
            drop(terminal);
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
            timing.application_stop = timing.application_stop.min(deadline);
            timing.cleanup_cutoff = timing.cleanup_cutoff.min(deadline);
        }
        self.changed.notify_waiters();
    }

    fn begin_closing(&self, _cause: UpgradeTerminalCause) {
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
            let now = Instant::now();
            let cause_cutoff = now.checked_add(ENTRY_CLEANUP_GRACE).unwrap_or(now);
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

async fn run_task_supervisor(
    inner: Arc<RuntimeInner>,
    mut receiver: mpsc::UnboundedReceiver<TaskCommand>,
) {
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
                inner.task_finished();
            }
            command = receiver.recv(), if !stopping => {
                match command {
                    Some(TaskCommand::StartHandshake { id, task }) => {
                        spawn_owned_task(&inner, &mut tasks, TaskKind::Handshake, id, task);
                    }
                    Some(TaskCommand::StartEntry { id, task }) => {
                        spawn_owned_task(&inner, &mut tasks, TaskKind::Entry, id, task);
                    }
                    Some(TaskCommand::Stop) | None => stopping = true,
                }
            }
        }
    }
}

fn spawn_owned_task(
    inner: &Arc<RuntimeInner>,
    tasks: &mut JoinSet<()>,
    kind: TaskKind,
    id: u64,
    task: UpgradeTask,
) {
    let mut state = lock(&inner.state);
    let record_exists = match kind {
        TaskKind::Handshake => state.accepting && state.uncommitted.contains_key(&id),
        TaskKind::Entry => state.entries.contains_key(&id),
    };
    if !record_exists {
        return;
    }
    let abort = tasks.spawn(task);
    state.supervisor_tasks += 1;
    match kind {
        TaskKind::Handshake => {
            state
                .uncommitted
                .get_mut(&id)
                .expect("checked uncommitted record exists")
                .abort = Some(abort);
        }
        TaskKind::Entry => {
            state
                .entries
                .get_mut(&id)
                .expect("checked committed entry exists")
                .coordinator_abort = Some(abort);
        }
    }
}

async fn run_entry_coordinator(
    _inner: Arc<RuntimeInner>,
    _id: u64,
    shared: Arc<EntryShared>,
    snapshot: UpgradedStreamSnapshot,
) {
    let mut tasks = JoinSet::new();
    let mut snapshot = Some(snapshot);
    loop {
        let changed = shared.changed.notified();
        if let Some(cause) = lock(&shared.terminal_cause).take() {
            shared.begin_closing(cause);
        }
        let state = shared.terminal_state.load(Ordering::Acquire);
        if state == ENTRY_CLOSING {
            tasks.abort_all();
            drain_entry_tasks(&shared, &mut tasks).await;
            return;
        }
        if state == ENTRY_CLOSED {
            return;
        }

        if let Some(build) = lock(&shared.setup).take() {
            let snapshot = snapshot
                .take()
                .expect("entry setup is installed at most once");
            let setup = build(snapshot);
            tasks.spawn(async move { EntryTaskResult::Setup(setup.await) });
            continue;
        }

        let timing = *lock(&shared.timing);
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(timing.cleanup_cutoff) => {
                shared.begin_closing(UpgradeTerminalCause::LifetimeExpired);
            }
            _ = tokio::time::sleep_until(timing.application_stop) => {
                shared.begin_closing(UpgradeTerminalCause::LifetimeExpired);
            }
            _ = changed => {}
            joined = tasks.join_next(), if !tasks.is_empty() => {
                match joined {
                    Some(Ok(EntryTaskResult::Setup(Ok(pair)))) => {
                        tasks.spawn(async move { EntryTaskResult::Relay(pair.first.await) });
                        tasks.spawn(async move { EntryTaskResult::Relay(pair.second.await) });
                    }
                    Some(Ok(EntryTaskResult::Setup(Err(cause))))
                    | Some(Ok(EntryTaskResult::Relay(cause))) => shared.begin_closing(cause),
                    Some(Err(_)) => shared.begin_closing(UpgradeTerminalCause::Cancelled),
                    None => {}
                }
            }
        }
    }
}

async fn drain_entry_tasks(shared: &EntryShared, tasks: &mut JoinSet<EntryTaskResult>) {
    tasks.abort_all();
    while !tasks.is_empty() {
        let changed = shared.changed.notified();
        let cutoff = lock(&shared.timing).cleanup_cutoff;
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(cutoff) => {
                tasks.shutdown().await;
                return;
            }
            _ = changed => {
                tasks.abort_all();
            }
            joined = tasks.join_next() => {
                let _ = joined;
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
    pub(crate) supervisor_tasks: usize,
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
    #[error("the upgrade task supervisor stopped")]
    SupervisorStopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum UpgradeCommitError {
    #[error("upgrade admission closed before commit")]
    AdmissionClosed,
    #[error("the upgrade admission guard was already released")]
    GuardReleased,
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

    use super::*;

    fn limits(slots: usize, bytes: usize) -> UpgradeRuntimeLimits {
        UpgradeRuntimeLimits::new(slots, bytes, 2, Duration::from_secs(60))
    }

    fn allocation(rule: usize, bytes: usize) -> UpgradeAllocation {
        UpgradeAllocation::from_compiled_rule(rule, Some(bytes)).unwrap()
    }

    fn snapshot(runtime: &UpgradeRuntime) -> UpgradedStreamSnapshot {
        UpgradedStreamSnapshot::new(runtime.limits().relay_buffer_bytes(), None)
    }

    async fn wait_for_counts(runtime: &UpgradeRuntime, expected: UpgradeRuntimeCounts) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if runtime.counts() == expected {
                    return;
                }
                runtime.inner.changed.notified().await;
            }
        })
        .await
        .expect("upgrade runtime counts did not converge");
    }

    #[tokio::test]
    async fn upgrade_admission_and_relay_bounds() {
        let runtime = UpgradeRuntime::try_new(limits(3, 10)).unwrap();
        assert_eq!(
            UpgradeAllocation::from_compiled_rule(0, None),
            Err(UpgradeAllocationError::RuleDisallowsUpgrades)
        );
        let first = runtime.try_admit(allocation(0, 6)).unwrap();
        let second = runtime.try_admit(allocation(1, 4)).unwrap();
        assert_eq!(
            runtime.try_admit(allocation(2, 1)).unwrap_err(),
            UpgradeAdmissionError::BufferCapacity
        );
        assert_eq!(first.allocation().bytes(), 6);
        assert_eq!(second.allocation().rule_index(), 1);
        assert_eq!(runtime.counts().reserved_bytes, 10);
        drop(first);
        let third = runtime.try_admit(allocation(2, 6)).unwrap();
        assert_eq!(runtime.counts().reserved_slots, 2);
        drop((second, third));
        runtime.shutdown_and_wait(Some(Instant::now())).await;
        assert_eq!(runtime.counts().reserved_bytes, 0);
    }

    #[tokio::test]
    async fn upgrade_admission_guard_releases_on_pre101_failure() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let guard = runtime.try_admit(allocation(0, 8)).unwrap();
        guard
            .spawn_handshake(|guard| async move {
                assert_eq!(guard.allocation().bytes(), 8);
                drop(guard);
            })
            .unwrap();
        let mut expected = runtime.counts();
        expected.reserved_slots = 0;
        expected.reserved_bytes = 0;
        expected.uncommitted = 0;
        expected.supervisor_tasks = 0;
        wait_for_counts(&runtime, expected).await;
        let replacement = runtime.try_admit(allocation(0, 8)).unwrap();
        drop(replacement);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn upgrade_admission_shutdown_race_linearizes_registry_snapshot() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let guard = runtime.try_admit(allocation(0, 8)).unwrap();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let (result_tx, result_rx) = std_mpsc::channel();
        let commit_thread = thread::spawn({
            let entered = entered.clone();
            let release = release.clone();
            move || {
                let mut guard = guard;
                let result = guard.commit_with_hook(UpgradedStreamSnapshot::new(2, None), || {
                    entered.wait();
                    release.wait();
                });
                result_tx.send(result).unwrap();
            }
        });
        entered.wait();
        let shutdown_runtime = runtime.clone();
        let shutdown = thread::spawn(move || {
            shutdown_runtime.begin_shutdown(Some(Instant::now()));
        });
        release.wait();
        commit_thread.join().unwrap();
        shutdown.join().unwrap();
        let entry = result_rx.recv().unwrap().expect("commit won the gate");
        entry.wait_closed().await;
        runtime.wait_until_drained().await;

        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let guard = runtime.try_admit(allocation(0, 8)).unwrap();
        runtime.begin_shutdown(Some(Instant::now()));
        assert_eq!(
            guard.commit(snapshot(&runtime)).unwrap_err(),
            UpgradeCommitError::AdmissionClosed
        );
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    struct DropCount(Arc<AtomicUsize>);

    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn upgrade_terminal_races_release_resources_once() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let entry = runtime
            .try_admit(allocation(0, 8))
            .unwrap()
            .commit(snapshot(&runtime))
            .unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let first_drop = DropCount(dropped.clone());
        let second_drop = DropCount(dropped.clone());
        let never_first = async move {
            let _drop = first_drop;
            std::future::pending::<()>().await;
            UpgradeTerminalCause::PeerClosed
        };
        let never_second = async move {
            let _drop = second_drop;
            std::future::pending::<()>().await;
            UpgradeTerminalCause::RelayError
        };
        entry
            .start(move |_snapshot| async move {
                Ok(UpgradeRelayPair::new(never_first, never_second))
            })
            .unwrap();

        let one = entry.clone();
        let two = entry.clone();
        let three = entry.clone();
        let terminal = tokio::spawn(async move {
            tokio::join!(
                async move { one.submit_terminal(UpgradeTerminalCause::PeerClosed) },
                async move { two.submit_terminal(UpgradeTerminalCause::RelayError) },
                async move { three.submit_terminal(UpgradeTerminalCause::Cancelled) },
            );
        });
        terminal.await.unwrap();
        entry.wait_closed().await;
        runtime.begin_shutdown(Some(Instant::now()));
        runtime.wait_until_drained().await;
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
        assert_eq!(runtime.counts().reserved_slots, 0);
        assert_eq!(runtime.counts().reserved_bytes, 0);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }

    #[tokio::test]
    async fn finite_shutdown_only_lowers_committed_deadlines() {
        let runtime = UpgradeRuntime::try_new(limits(1, 8)).unwrap();
        let entry = runtime
            .try_admit(allocation(0, 8))
            .unwrap()
            .commit(snapshot(&runtime))
            .unwrap();
        let before = entry.timing();
        let drain = Instant::now() + Duration::from_secs(10);
        runtime.begin_shutdown(Some(drain));
        let after = entry.timing();
        assert!(after.application_stop <= before.application_stop);
        assert_eq!(after.application_stop, drain);
        assert_eq!(after.cleanup_cutoff, drain);

        runtime.begin_shutdown(Some(drain + Duration::from_secs(10)));
        assert_eq!(entry.timing().application_stop, drain);
        runtime.shutdown_and_wait(Some(Instant::now())).await;
    }
}
