use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use credential_core::{CredentialError, ResolvedCredential};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Notify};
use tokio::task::JoinHandle;

const DEFAULT_MAX_OPERATIONS: usize = 256;
const WORKER_STACK_BYTES: usize = 1024 * 1024;
const PROJECTED_OPERATION_BYTES: u64 = 32 * 1024 + WORKER_STACK_BYTES as u64;

type CredentialIoJob = Box<
    dyn FnOnce(Arc<AtomicBool>) -> Result<ResolvedCredential, CredentialError> + Send + 'static,
>;

/// Process-owned admission and supervision for blocking credential operations.
pub(crate) struct CredentialIoRuntime {
    inner: Arc<RuntimeInner>,
    supervisor: AsyncMutex<Option<JoinHandle<()>>>,
}

struct RuntimeInner {
    state: Mutex<RuntimeState>,
    commands: mpsc::Sender<SupervisorCommand>,
    supervisor_control: mpsc::UnboundedSender<SupervisorControl>,
    state_changed: Notify,
}

struct RuntimeState {
    accepting: bool,
    slots: Vec<Option<Arc<OperationSignal>>>,
    active: usize,
}

struct SupervisorCommand {
    slot: OperationSlotGuard,
    signal: Arc<OperationSignal>,
    job: CredentialIoJob,
    result: oneshot::Sender<Result<ResolvedCredential, CredentialError>>,
}

struct OperationSlotGuard {
    inner: Arc<RuntimeInner>,
    slot: usize,
}

struct WorkerCompletionGuard {
    slot: Option<OperationSlotGuard>,
    completed: mpsc::UnboundedSender<usize>,
}

#[derive(Clone, Copy)]
enum SupervisorControl {
    StateChanged,
    Abandon,
}

struct OperationSignal {
    cancellation: Arc<AtomicBool>,
    publication: Mutex<()>,
    operation_waker: Mutex<Option<Waker>>,
}

/// A single admitted credential operation.
///
/// Dropping this future requests cancellation. It deliberately owns no runtime,
/// provider, descriptor, or task handle.
pub(crate) struct CredentialIoOperation {
    result: oneshot::Receiver<Result<ResolvedCredential, CredentialError>>,
    signal: Arc<OperationSignal>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CredentialIoRuntimeError {
    #[error("credential I/O operation ceiling must be nonzero")]
    ZeroOperationCeiling,
    #[error("Tokio runtime is unavailable for credential I/O")]
    RuntimeUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CredentialIoAdmissionError {
    #[error("credential I/O admission is closed")]
    Closed,
    #[error("credential I/O operation capacity is exhausted")]
    CapacityExhausted,
    #[error("credential I/O supervisor is unavailable")]
    SupervisorUnavailable,
}

/// Result of stopping credential I/O supervision.
///
/// A deadline cannot kill a blocking operating-system call. `DeadlineExceeded`
/// therefore reports workers detached from supervision; their slot ownership is
/// retained until each worker actually returns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialIoShutdownOutcome {
    Drained,
    DeadlineExceeded { detached_operations: usize },
}

/// Per-request allowance reserved before one admitted blocking credential job,
/// including its explicitly bounded operating-system worker stack.
pub(crate) const fn projected_credential_io_operation_bytes() -> u64 {
    PROJECTED_OPERATION_BYTES
}

impl CredentialIoRuntime {
    pub(crate) fn new() -> Result<Arc<Self>, CredentialIoRuntimeError> {
        Self::try_new(DEFAULT_MAX_OPERATIONS, SupervisorStart::Ready)
    }

    #[cfg(test)]
    fn for_test(max_operations: usize) -> Arc<Self> {
        Self::try_new(max_operations, SupervisorStart::Ready).unwrap()
    }

    #[cfg(test)]
    fn for_test_paused(max_operations: usize) -> (Arc<Self>, SupervisorStartGate) {
        let gate = SupervisorStartGate::new();
        let runtime = Self::try_new(max_operations, SupervisorStart::Paused(gate.clone())).unwrap();
        (runtime, gate)
    }

    fn try_new(
        max_operations: usize,
        supervisor_start: SupervisorStart,
    ) -> Result<Arc<Self>, CredentialIoRuntimeError> {
        if max_operations == 0 {
            return Err(CredentialIoRuntimeError::ZeroOperationCeiling);
        }
        let handle =
            Handle::try_current().map_err(|_| CredentialIoRuntimeError::RuntimeUnavailable)?;
        let (commands, receiver) = mpsc::channel(max_operations);
        let (supervisor_control, control_receiver) = mpsc::unbounded_channel();
        let inner = Arc::new(RuntimeInner {
            state: Mutex::new(RuntimeState {
                accepting: true,
                slots: (0..max_operations).map(|_| None).collect(),
                active: 0,
            }),
            commands,
            supervisor_control,
            state_changed: Notify::new(),
        });
        let supervisor_inner = Arc::clone(&inner);
        let supervisor = handle.spawn(async move {
            run_supervisor(
                supervisor_inner,
                receiver,
                control_receiver,
                supervisor_start,
            )
            .await;
        });
        Ok(Arc::new(Self {
            inner,
            supervisor: AsyncMutex::new(Some(supervisor)),
        }))
    }

    /// Synchronously admits one bounded blocking operation.
    pub(crate) fn submit(
        &self,
        job: CredentialIoJob,
    ) -> Result<CredentialIoOperation, CredentialIoAdmissionError> {
        self.submit_with_hook(job, || {})
    }

    fn submit_with_hook<Hook>(
        &self,
        job: CredentialIoJob,
        after_reservation: Hook,
    ) -> Result<CredentialIoOperation, CredentialIoAdmissionError>
    where
        Hook: FnOnce(),
    {
        let mut state = lock(&self.inner.state);
        if !state.accepting {
            return Err(CredentialIoAdmissionError::Closed);
        }
        let slot = state
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(CredentialIoAdmissionError::CapacityExhausted)?;
        let signal = Arc::new(OperationSignal {
            cancellation: Arc::new(AtomicBool::new(false)),
            publication: Mutex::new(()),
            operation_waker: Mutex::new(None),
        });
        state.slots[slot] = Some(Arc::clone(&signal));
        state.active = state
            .active
            .checked_add(1)
            .expect("credential I/O active count cannot exceed bounded slots");
        after_reservation();

        let (result, receiver) = oneshot::channel();
        let command = SupervisorCommand {
            slot: OperationSlotGuard {
                inner: Arc::clone(&self.inner),
                slot,
            },
            signal: Arc::clone(&signal),
            job,
            result,
        };
        if let Err(error) = self.inner.commands.try_send(command) {
            drop(state);
            return Err(match error {
                mpsc::error::TrySendError::Full(command) => {
                    drop(command);
                    CredentialIoAdmissionError::CapacityExhausted
                }
                mpsc::error::TrySendError::Closed(command) => {
                    drop(command);
                    CredentialIoAdmissionError::SupervisorUnavailable
                }
            });
        }
        drop(state);

        Ok(CredentialIoOperation {
            result: receiver,
            signal,
        })
    }

    /// Closes admission and requests cancellation for queued and running work.
    pub(crate) fn begin_shutdown(&self) {
        let mut state = lock(&self.inner.state);
        state.accepting = false;
        for signal in state.slots.iter().flatten() {
            signal.cancel();
        }
        drop(state);
        let _ = self
            .inner
            .supervisor_control
            .send(SupervisorControl::StateChanged);
    }

    /// Closes admission, cancels work, and waits for credential workers until
    /// `deadline`.
    ///
    /// Awaiting the stored join handle by mutable reference makes cancellation
    /// of this waiter retry-safe: a later caller can resume the same join.
    pub(crate) async fn shutdown_and_wait(
        &self,
        deadline: Option<tokio::time::Instant>,
    ) -> CredentialIoShutdownOutcome {
        self.shutdown_and_wait_with_hook(deadline, std::future::ready(()))
            .await
    }

    async fn shutdown_and_wait_with_hook<Hook>(
        &self,
        deadline: Option<tokio::time::Instant>,
        after_supervisor_lock: Hook,
    ) -> CredentialIoShutdownOutcome
    where
        Hook: Future<Output = ()>,
    {
        self.begin_shutdown();
        let mut supervisor = self.supervisor.lock().await;
        if let Some(task) = supervisor.as_mut() {
            after_supervisor_lock.await;
            let deadline_reached = match deadline {
                Some(deadline) => {
                    tokio::select! {
                        biased;
                        _ = tokio::time::sleep_until(deadline) => true,
                        _ = &mut *task => false,
                    }
                }
                None => {
                    let _ = (&mut *task).await;
                    false
                }
            };
            if deadline_reached {
                let _ = self
                    .inner
                    .supervisor_control
                    .send(SupervisorControl::Abandon);
                let _ = task.await;
            }
            supervisor.take();
            if deadline_reached {
                return self.deadline_outcome();
            }
        }
        self.wait_for_detached_operations(deadline).await
    }

    async fn wait_for_detached_operations(
        &self,
        deadline: Option<tokio::time::Instant>,
    ) -> CredentialIoShutdownOutcome {
        loop {
            let active = self.active_operations();
            if active == 0 {
                return CredentialIoShutdownOutcome::Drained;
            }
            let changed = self.inner.state_changed.notified();
            if self.active_operations() == 0 {
                continue;
            }
            match deadline {
                Some(deadline) => {
                    tokio::select! {
                        biased;
                        _ = tokio::time::sleep_until(deadline) => {
                            return self.deadline_outcome();
                        }
                        () = changed => {}
                    }
                }
                None => changed.await,
            }
        }
    }

    fn active_operations(&self) -> usize {
        lock(&self.inner.state).active
    }

    fn deadline_outcome(&self) -> CredentialIoShutdownOutcome {
        let detached_operations = self.active_operations();
        if detached_operations == 0 {
            CredentialIoShutdownOutcome::Drained
        } else {
            CredentialIoShutdownOutcome::DeadlineExceeded {
                detached_operations,
            }
        }
    }

    #[cfg(test)]
    fn counts(&self) -> CredentialIoRuntimeCounts {
        let state = lock(&self.inner.state);
        CredentialIoRuntimeCounts {
            accepting: state.accepting,
            active: state.active,
            maximum: state.slots.len(),
        }
    }
}

impl Drop for CredentialIoRuntime {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

impl Future for CredentialIoOperation {
    type Output = Result<ResolvedCredential, CredentialError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.result).poll(context) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(CredentialError::Cancelled)),
            Poll::Pending => {
                self.signal.register_operation_waker(context.waker());
                match Pin::new(&mut self.result).poll(context) {
                    Poll::Ready(Ok(result)) => Poll::Ready(result),
                    Poll::Ready(Err(_)) => Poll::Ready(Err(CredentialError::Cancelled)),
                    Poll::Pending if self.signal.is_cancelled() => {
                        Poll::Ready(Err(CredentialError::Cancelled))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}

impl Drop for CredentialIoOperation {
    fn drop(&mut self) {
        self.signal.cancel();
    }
}

async fn run_supervisor(
    inner: Arc<RuntimeInner>,
    mut commands: mpsc::Receiver<SupervisorCommand>,
    mut control: mpsc::UnboundedReceiver<SupervisorControl>,
    supervisor_start: SupervisorStart,
) {
    if supervisor_start.wait(&mut control).await {
        abandon_queued_commands(&mut commands);
        return;
    }
    let (completed, mut completions) = mpsc::unbounded_channel();
    let mut workers: Vec<Option<std::thread::JoinHandle<()>>> =
        (0..lock(&inner.state).slots.len()).map(|_| None).collect();
    loop {
        if supervisor_drained(&inner) && workers.iter().all(Option::is_none) {
            break;
        }

        tokio::select! {
            biased;
            control_message = control.recv() => {
                if matches!(control_message, Some(SupervisorControl::Abandon)) {
                    abandon_queued_commands(&mut commands);
                    for worker in &mut workers {
                        drop(worker.take());
                    }
                    return;
                }
            }
            completed_slot = completions.recv() => {
                if let Some(slot) = completed_slot {
                    join_completed_worker(&mut workers, slot);
                }
            }
            command = commands.recv() => {
                if let Some(command) = command {
                    start_or_cancel(&mut workers, completed.clone(), command);
                }
            }
        }
    }
}

fn start_or_cancel(
    workers: &mut [Option<std::thread::JoinHandle<()>>],
    completed: mpsc::UnboundedSender<usize>,
    command: SupervisorCommand,
) {
    if command.signal.is_cancelled() {
        if !command.result.is_closed() {
            let _ = command.result.send(Err(CredentialError::Cancelled));
        }
        return;
    }

    let slot = command.slot.slot;
    let pending = Arc::new(Mutex::new(Some(command)));
    let worker_pending = Arc::clone(&pending);
    match std::thread::Builder::new()
        .name(format!("credential-io-{slot}"))
        .stack_size(WORKER_STACK_BYTES)
        .spawn(move || {
            let command = lock(&worker_pending)
                .take()
                .expect("credential I/O worker command must be present");
            run_worker(command, completed);
        }) {
        Ok(worker) => {
            workers[slot] = Some(worker);
        }
        Err(error) => {
            tracing::error!(%error, "credential I/O worker thread could not be started");
            if let Some(command) = lock(&pending).take() {
                let _ = command
                    .result
                    .send(Err(CredentialError::ServiceUnavailable));
            }
        }
    }
}

fn run_worker(command: SupervisorCommand, completed: mpsc::UnboundedSender<usize>) {
    let SupervisorCommand {
        slot,
        signal,
        job,
        result,
    } = command;
    let _completion = WorkerCompletionGuard {
        completed,
        slot: Some(slot),
    };
    if signal.is_cancelled() || result.is_closed() {
        return;
    }
    let outcome = catch_unwind(AssertUnwindSafe(|| job(Arc::clone(&signal.cancellation))))
        .unwrap_or(Err(CredentialError::ServiceUnavailable));
    signal.publish_if_active(result, outcome);
}

fn join_completed_worker(workers: &mut [Option<std::thread::JoinHandle<()>>], slot: usize) {
    if let Some(worker) = workers.get_mut(slot).and_then(Option::take) {
        if worker.join().is_err() {
            tracing::error!("credential I/O worker failed outside the panic boundary");
        }
    }
}

fn abandon_queued_commands(commands: &mut mpsc::Receiver<SupervisorCommand>) {
    commands.close();
    while let Ok(command) = commands.try_recv() {
        if !command.result.is_closed() {
            let _ = command.result.send(Err(CredentialError::Cancelled));
        }
    }
}

fn supervisor_drained(inner: &RuntimeInner) -> bool {
    let state = lock(&inner.state);
    !state.accepting && state.active == 0
}

fn complete_slot(inner: &RuntimeInner, slot: usize) {
    let mut state = lock(&inner.state);
    if state.slots.get_mut(slot).and_then(Option::take).is_some() {
        state.active = state
            .active
            .checked_sub(1)
            .expect("credential I/O active count cannot underflow");
    }
    drop(state);
    inner.state_changed.notify_waiters();
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl OperationSignal {
    fn cancel(&self) {
        {
            let _publication = lock(&self.publication);
            self.cancellation.store(true, Ordering::Release);
        }
        let operation_waker = { lock(&self.operation_waker).take() };
        if let Some(waker) = operation_waker {
            waker.wake();
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation.load(Ordering::Acquire)
    }

    fn register_operation_waker(&self, waker: &Waker) {
        let mut registered = lock(&self.operation_waker);
        if registered
            .as_ref()
            .is_none_or(|registered| !registered.will_wake(waker))
        {
            *registered = Some(waker.clone());
        }
    }

    fn publish_if_active(
        &self,
        result: oneshot::Sender<Result<ResolvedCredential, CredentialError>>,
        outcome: Result<ResolvedCredential, CredentialError>,
    ) {
        let _publication = lock(&self.publication);
        if !self.is_cancelled() && !result.is_closed() {
            let _ = result.send(outcome);
        }
    }
}

enum SupervisorStart {
    Ready,
    #[cfg(test)]
    Paused(SupervisorStartGate),
}

impl SupervisorStart {
    async fn wait(self, _control: &mut mpsc::UnboundedReceiver<SupervisorControl>) -> bool {
        match self {
            Self::Ready => false,
            #[cfg(test)]
            Self::Paused(gate) => gate.wait(_control).await,
        }
    }
}

#[cfg(test)]
#[derive(Clone)]
struct SupervisorStartGate {
    open: Arc<AtomicBool>,
    changed: Arc<Notify>,
}

#[cfg(test)]
impl SupervisorStartGate {
    fn new() -> Self {
        Self {
            open: Arc::new(AtomicBool::new(false)),
            changed: Arc::new(Notify::new()),
        }
    }

    async fn wait(&self, control: &mut mpsc::UnboundedReceiver<SupervisorControl>) -> bool {
        while !self.open.load(Ordering::Acquire) {
            let gate_changed = self.changed.notified();
            if self.open.load(Ordering::Acquire) {
                break;
            }
            tokio::select! {
                () = gate_changed => {}
                message = control.recv() => {
                    if matches!(message, Some(SupervisorControl::Abandon)) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn open(&self) {
        self.open.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}

impl Drop for OperationSlotGuard {
    fn drop(&mut self) {
        complete_slot(&self.inner, self.slot);
    }
}

impl Drop for WorkerCompletionGuard {
    fn drop(&mut self) {
        let slot = self
            .slot
            .take()
            .expect("credential I/O worker slot must be present");
        let slot_index = slot.slot;
        let _ = self.completed.send(slot_index);
        drop(slot);
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CredentialIoRuntimeCounts {
    accepting: bool,
    active: usize,
    maximum: usize,
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc as std_mpsc;
    use std::sync::Condvar;

    use super::*;

    #[derive(Default)]
    struct BlockingGate {
        open: Mutex<bool>,
        changed: Condvar,
    }

    impl BlockingGate {
        fn wait(&self) {
            let mut open = lock(&self.open);
            while !*open {
                open = self
                    .changed
                    .wait(open)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }

        fn open(&self) {
            *lock(&self.open) = true;
            self.changed.notify_all();
        }
    }

    fn error_job(
        error: CredentialError,
    ) -> Box<
        dyn FnOnce(Arc<AtomicBool>) -> Result<ResolvedCredential, CredentialError> + Send + 'static,
    > {
        Box::new(move |_| Err(error))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn queued_work_is_cancelled_without_starting() {
        let (runtime, gate) = CredentialIoRuntime::for_test_paused(2);
        let started = Arc::new(AtomicBool::new(false));
        let started_for_job = Arc::clone(&started);
        let operation = runtime
            .submit(Box::new(move |_| {
                started_for_job.store(true, Ordering::SeqCst);
                Err(CredentialError::UnknownReference)
            }))
            .unwrap();

        runtime.begin_shutdown();
        gate.open();

        assert!(matches!(operation.await, Err(CredentialError::Cancelled)));
        runtime.shutdown_and_wait(None).await;
        assert!(!started.load(Ordering::SeqCst));
        assert_eq!(runtime.counts().active, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn running_work_observes_shutdown_cancellation() {
        let runtime = CredentialIoRuntime::for_test(1);
        let (started_tx, started_rx) = std_mpsc::channel();
        let operation = runtime
            .submit(Box::new(move |cancelled| {
                started_tx.send(()).unwrap();
                while !cancelled.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                Err(CredentialError::Cancelled)
            }))
            .unwrap();
        tokio::task::spawn_blocking(move || started_rx.recv().unwrap())
            .await
            .unwrap();

        runtime.begin_shutdown();
        assert!(matches!(operation.await, Err(CredentialError::Cancelled)));
        runtime.shutdown_and_wait(None).await;
        assert_eq!(runtime.counts().active, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn panic_is_sanitized_and_capacity_recovers() {
        let runtime = CredentialIoRuntime::for_test(1);
        let operation = runtime
            .submit(Box::new(
                |_| -> Result<ResolvedCredential, CredentialError> {
                    panic!("provider detail must not escape")
                },
            ))
            .unwrap();
        assert!(matches!(
            operation.await,
            Err(CredentialError::ServiceUnavailable)
        ));

        while runtime.counts().active != 0 {
            tokio::task::yield_now().await;
        }
        let recovered = runtime
            .submit(error_job(CredentialError::UnknownReference))
            .unwrap();
        assert!(matches!(
            recovered.await,
            Err(CredentialError::UnknownReference)
        ));
        runtime.shutdown_and_wait(None).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn submit_and_shutdown_are_linearized() {
        let runtime = CredentialIoRuntime::for_test(1);
        let (reserved_tx, reserved_rx) = std_mpsc::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let submit_runtime = Arc::clone(&runtime);
        let submitter = std::thread::spawn(move || {
            submit_runtime.submit_with_hook(
                Box::new(|cancelled| {
                    while !cancelled.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    Err(CredentialError::Cancelled)
                }),
                || {
                    reserved_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                },
            )
        });
        reserved_rx.recv().unwrap();
        let shutdown_runtime = Arc::clone(&runtime);
        let shutdown = std::thread::spawn(move || shutdown_runtime.begin_shutdown());
        release_tx.send(()).unwrap();
        let operation = submitter.join().unwrap().unwrap();
        shutdown.join().unwrap();

        assert!(matches!(operation.await, Err(CredentialError::Cancelled)));
        assert!(matches!(
            runtime.submit(error_job(CredentialError::UnknownReference)),
            Err(CredentialIoAdmissionError::Closed)
        ));
        runtime.shutdown_and_wait(None).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bounded_admission_drains_all_work() {
        let runtime = CredentialIoRuntime::for_test(2);
        let gate = Arc::new(BlockingGate::default());
        let (started_tx, started_rx) = std_mpsc::channel();
        let first_gate = Arc::clone(&gate);
        let first_started = started_tx.clone();
        let first = runtime
            .submit(Box::new(move |_| {
                first_started.send(()).unwrap();
                first_gate.wait();
                Err(CredentialError::UnknownReference)
            }))
            .unwrap();
        let second_gate = Arc::clone(&gate);
        let second = runtime
            .submit(Box::new(move |_| {
                started_tx.send(()).unwrap();
                second_gate.wait();
                Err(CredentialError::UseMismatch)
            }))
            .unwrap();
        tokio::task::spawn_blocking(move || {
            started_rx.recv().unwrap();
            started_rx.recv().unwrap();
        })
        .await
        .unwrap();
        assert_eq!(runtime.counts().maximum, 2);
        assert!(matches!(
            runtime.submit(error_job(CredentialError::InvalidContract)),
            Err(CredentialIoAdmissionError::CapacityExhausted)
        ));
        gate.open();
        assert!(matches!(
            first.await,
            Err(CredentialError::UnknownReference)
        ));
        assert!(matches!(second.await, Err(CredentialError::UseMismatch)));

        runtime.shutdown_and_wait(None).await;
        assert_eq!(
            runtime.counts(),
            CredentialIoRuntimeCounts {
                accepting: false,
                active: 0,
                maximum: 2,
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_shutdown_waiter_can_be_retried() {
        let runtime = CredentialIoRuntime::for_test(1);
        let (started_tx, started_rx) = std_mpsc::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let operation = runtime
            .submit(Box::new(move |_| {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Err(CredentialError::UnknownReference)
            }))
            .unwrap();
        tokio::task::spawn_blocking(move || started_rx.recv().unwrap())
            .await
            .unwrap();

        let first_runtime = Arc::clone(&runtime);
        let (locked_tx, locked_rx) = oneshot::channel();
        let first_waiter = tokio::spawn(async move {
            first_runtime
                .shutdown_and_wait_with_hook(None, async move {
                    let _ = locked_tx.send(());
                })
                .await;
        });
        locked_rx.await.unwrap();
        first_waiter.abort();
        assert!(first_waiter.await.unwrap_err().is_cancelled());

        release_tx.send(()).unwrap();
        assert!(matches!(operation.await, Err(CredentialError::Cancelled)));
        runtime.shutdown_and_wait(None).await;
        assert_eq!(runtime.counts().active, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_operation_cancels_running_work() {
        let runtime = CredentialIoRuntime::for_test(1);
        let (started_tx, started_rx) = std_mpsc::channel();
        let (cancelled_tx, cancelled_rx) = std_mpsc::channel();
        let operation = runtime
            .submit(Box::new(move |cancelled| {
                started_tx.send(()).unwrap();
                while !cancelled.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                cancelled_tx.send(()).unwrap();
                Err(CredentialError::UnknownReference)
            }))
            .unwrap();
        tokio::task::spawn_blocking(move || started_rx.recv().unwrap())
            .await
            .unwrap();

        drop(operation);
        tokio::task::spawn_blocking(move || cancelled_rx.recv().unwrap())
            .await
            .unwrap();
        while runtime.counts().active != 0 {
            tokio::task::yield_now().await;
        }
        runtime.shutdown_and_wait(None).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_deadline_drains_queued_work_without_starting_it() {
        let (runtime, _gate) = CredentialIoRuntime::for_test_paused(1);
        let started = Arc::new(AtomicBool::new(false));
        let started_for_job = Arc::clone(&started);
        let operation = runtime
            .submit(Box::new(move |_| {
                started_for_job.store(true, Ordering::Release);
                Err(CredentialError::UnknownReference)
            }))
            .unwrap();

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            runtime.shutdown_and_wait(Some(
                tokio::time::Instant::now() + std::time::Duration::from_millis(20),
            )),
        )
        .await
        .unwrap();

        assert_eq!(outcome, CredentialIoShutdownOutcome::Drained);
        assert!(matches!(operation.await, Err(CredentialError::Cancelled)));
        assert!(!started.load(Ordering::Acquire));
        assert_eq!(runtime.counts().active, 0);
        assert_eq!(
            runtime.shutdown_and_wait(None).await,
            CredentialIoShutdownOutcome::Drained
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_deadline_detaches_stuck_worker_until_it_really_returns() {
        let runtime = CredentialIoRuntime::for_test(1);
        let gate = Arc::new(BlockingGate::default());
        let gate_for_job = Arc::clone(&gate);
        let (started_tx, started_rx) = std_mpsc::channel();
        let operation = runtime
            .submit(Box::new(move |_| {
                started_tx.send(()).unwrap();
                gate_for_job.wait();
                Err(CredentialError::UnknownReference)
            }))
            .unwrap();
        tokio::task::spawn_blocking(move || started_rx.recv().unwrap())
            .await
            .unwrap();

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            runtime.shutdown_and_wait(Some(
                tokio::time::Instant::now() + std::time::Duration::from_millis(20),
            )),
        )
        .await
        .unwrap();

        assert_eq!(
            outcome,
            CredentialIoShutdownOutcome::DeadlineExceeded {
                detached_operations: 1,
            }
        );
        assert!(matches!(operation.await, Err(CredentialError::Cancelled)));
        assert_eq!(runtime.counts().active, 1);

        gate.open();
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                runtime.shutdown_and_wait(None),
            )
            .await
            .unwrap(),
            CredentialIoShutdownOutcome::Drained
        );
        assert_eq!(runtime.counts().active, 0);
    }

    #[test]
    fn tokio_runtime_drop_does_not_wait_for_detached_credential_thread() {
        let gate = Arc::new(BlockingGate::default());
        let gate_for_runtime = Arc::clone(&gate);
        let (runtime_stopping_tx, runtime_stopping_rx) = std_mpsc::channel();
        let (runtime_dropped_tx, runtime_dropped_rx) = std_mpsc::channel();
        let (worker_finished_tx, worker_finished_rx) = std_mpsc::channel();
        let manager = std::thread::spawn(move || {
            let tokio_runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            tokio_runtime.block_on(async move {
                let runtime = CredentialIoRuntime::for_test(1);
                let (started_tx, started_rx) = oneshot::channel();
                let operation = runtime
                    .submit(Box::new(move |_| {
                        let _ = started_tx.send(());
                        gate_for_runtime.wait();
                        worker_finished_tx.send(()).unwrap();
                        Err(CredentialError::UnknownReference)
                    }))
                    .unwrap();
                tokio::time::timeout(std::time::Duration::from_secs(1), started_rx)
                    .await
                    .unwrap()
                    .unwrap();

                assert_eq!(
                    runtime
                        .shutdown_and_wait(Some(
                            tokio::time::Instant::now() + std::time::Duration::from_millis(20),
                        ))
                        .await,
                    CredentialIoShutdownOutcome::DeadlineExceeded {
                        detached_operations: 1,
                    }
                );
                assert!(matches!(operation.await, Err(CredentialError::Cancelled)));
            });
            runtime_stopping_tx.send(()).unwrap();
            drop(tokio_runtime);
            runtime_dropped_tx.send(()).unwrap();
        });

        runtime_stopping_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("credential shutdown did not return before Tokio runtime drop");
        runtime_dropped_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("Tokio runtime drop waited for a detached credential thread");
        assert!(matches!(
            worker_finished_rx.try_recv(),
            Err(std_mpsc::TryRecvError::Empty)
        ));

        gate.open();
        worker_finished_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("detached credential thread did not finish after release");
        manager.join().unwrap();
    }

    #[tokio::test]
    async fn default_and_test_operation_ceilings_are_checked() {
        let runtime = CredentialIoRuntime::new().unwrap();
        assert_eq!(runtime.counts().maximum, DEFAULT_MAX_OPERATIONS);
        runtime.shutdown_and_wait(None).await;
        assert!(matches!(
            CredentialIoRuntime::try_new(0, SupervisorStart::Ready),
            Err(CredentialIoRuntimeError::ZeroOperationCeiling)
        ));
    }
}
