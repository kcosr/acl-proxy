use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use credential_core::{CredentialError, ResolvedCredential};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Notify};
use tokio::task::{JoinHandle, JoinSet};

const DEFAULT_MAX_OPERATIONS: usize = 256;
const PROJECTED_OPERATION_CONTROL_BYTES: u64 = 32 * 1024;

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
    shutdown: Notify,
}

struct RuntimeState {
    accepting: bool,
    slots: Vec<Option<Arc<OperationSignal>>>,
    active: usize,
}

struct SupervisorCommand {
    slot: usize,
    signal: Arc<OperationSignal>,
    job: CredentialIoJob,
    result: oneshot::Sender<Result<ResolvedCredential, CredentialError>>,
}

struct OperationSignal {
    cancellation: Arc<AtomicBool>,
    publication: Mutex<()>,
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

/// Per-request allowance reserved before one admitted blocking credential job.
/// The global operation ceiling separately bounds the number of live jobs.
pub(crate) const fn projected_credential_io_operation_control_bytes() -> u64 {
    PROJECTED_OPERATION_CONTROL_BYTES
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
        let inner = Arc::new(RuntimeInner {
            state: Mutex::new(RuntimeState {
                accepting: true,
                slots: (0..max_operations).map(|_| None).collect(),
                active: 0,
            }),
            commands,
            shutdown: Notify::new(),
        });
        let supervisor_inner = Arc::clone(&inner);
        let supervisor = handle.spawn(async move {
            supervisor_start.wait().await;
            run_supervisor(supervisor_inner, receiver).await;
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
        });
        state.slots[slot] = Some(Arc::clone(&signal));
        state.active = state
            .active
            .checked_add(1)
            .expect("credential I/O active count cannot exceed bounded slots");
        after_reservation();

        let (result, receiver) = oneshot::channel();
        let command = SupervisorCommand {
            slot,
            signal: Arc::clone(&signal),
            job,
            result,
        };
        if let Err(error) = self.inner.commands.try_send(command) {
            state.slots[slot] = None;
            state.active -= 1;
            drop(state);
            self.inner.shutdown.notify_waiters();
            return Err(match error {
                mpsc::error::TrySendError::Full(_) => CredentialIoAdmissionError::CapacityExhausted,
                mpsc::error::TrySendError::Closed(_) => {
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
        self.inner.shutdown.notify_waiters();
    }

    /// Closes admission, cancels work, and joins the supervisor and every worker.
    ///
    /// Awaiting the stored join handle by mutable reference makes cancellation
    /// of this waiter retry-safe: a later caller can resume the same join.
    pub(crate) async fn shutdown_and_wait(&self) {
        self.shutdown_and_wait_with_hook(std::future::ready(()))
            .await;
    }

    async fn shutdown_and_wait_with_hook<Hook>(&self, after_supervisor_lock: Hook)
    where
        Hook: Future<Output = ()>,
    {
        self.begin_shutdown();
        let mut supervisor = self.supervisor.lock().await;
        if let Some(task) = supervisor.as_mut() {
            after_supervisor_lock.await;
            let _ = task.await;
            supervisor.take();
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
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for CredentialIoOperation {
    fn drop(&mut self) {
        self.signal.cancel();
    }
}

async fn run_supervisor(inner: Arc<RuntimeInner>, mut commands: mpsc::Receiver<SupervisorCommand>) {
    let mut workers = JoinSet::new();
    loop {
        if supervisor_drained(&inner) {
            break;
        }

        tokio::select! {
            biased;
            joined = workers.join_next(), if !workers.is_empty() => {
                if let Some(joined) = joined {
                    match joined {
                        Ok(slot) => complete_slot(&inner, slot),
                        Err(error) => {
                            tracing::error!(%error, "credential I/O worker failed outside the panic boundary");
                        }
                    }
                }
            }
            command = commands.recv() => {
                if let Some(command) = command {
                    start_or_cancel(&inner, &mut workers, command);
                }
            }
            () = inner.shutdown.notified() => {}
        }
    }
}

fn start_or_cancel(
    inner: &Arc<RuntimeInner>,
    workers: &mut JoinSet<usize>,
    command: SupervisorCommand,
) {
    if command.signal.is_cancelled() {
        if !command.result.is_closed() {
            let _ = command.result.send(Err(CredentialError::Cancelled));
        }
        complete_slot(inner, command.slot);
        return;
    }

    let (start, started) = std::sync::mpsc::channel();
    workers.spawn_blocking(move || {
        let _ = started.recv();
        let SupervisorCommand {
            slot,
            signal,
            job,
            result,
        } = command;
        if signal.is_cancelled() || result.is_closed() {
            return slot;
        }
        let outcome = catch_unwind(AssertUnwindSafe(|| job(Arc::clone(&signal.cancellation))))
            .unwrap_or(Err(CredentialError::ServiceUnavailable));
        signal.publish_if_active(result, outcome);
        slot
    });
    let _ = start.send(());
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
    inner.shutdown.notify_waiters();
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl OperationSignal {
    fn cancel(&self) {
        let _publication = lock(&self.publication);
        self.cancellation.store(true, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation.load(Ordering::Acquire)
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
    async fn wait(self) {
        match self {
            Self::Ready => {}
            #[cfg(test)]
            Self::Paused(gate) => gate.wait().await,
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

    async fn wait(&self) {
        while !self.open.load(Ordering::Acquire) {
            let changed = self.changed.notified();
            if self.open.load(Ordering::Acquire) {
                break;
            }
            changed.await;
        }
    }

    fn open(&self) {
        self.open.store(true, Ordering::Release);
        self.changed.notify_waiters();
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
        runtime.shutdown_and_wait().await;
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
        runtime.shutdown_and_wait().await;
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
        runtime.shutdown_and_wait().await;
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
        runtime.shutdown_and_wait().await;
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

        runtime.shutdown_and_wait().await;
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
                .shutdown_and_wait_with_hook(async move {
                    let _ = locked_tx.send(());
                })
                .await;
        });
        locked_rx.await.unwrap();
        first_waiter.abort();
        assert!(first_waiter.await.unwrap_err().is_cancelled());

        release_tx.send(()).unwrap();
        assert!(matches!(operation.await, Err(CredentialError::Cancelled)));
        runtime.shutdown_and_wait().await;
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
        runtime.shutdown_and_wait().await;
    }

    #[tokio::test]
    async fn default_and_test_operation_ceilings_are_checked() {
        let runtime = CredentialIoRuntime::new().unwrap();
        assert_eq!(runtime.counts().maximum, DEFAULT_MAX_OPERATIONS);
        runtime.shutdown_and_wait().await;
        assert!(matches!(
            CredentialIoRuntime::try_new(0, SupervisorStart::Ready),
            Err(CredentialIoRuntimeError::ZeroOperationCeiling)
        ));
    }
}
