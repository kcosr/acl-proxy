use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use http_access_runtime::SystemTlsRootSet;
use http_access_types::PolicyGeneration;
use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Notify};
use tokio::task::JoinHandle;

use crate::runtime::ActivationCancellation;
use crate::tls::{load_bounded_custom_ca, load_bounded_system_roots, TlsActivationError};

const DEFAULT_MAX_OPERATIONS: usize = 32;
const WORKER_STACK_BYTES: usize = 1024 * 1024;

enum TlsIoJobOutput {
    CustomCa(Vec<Vec<u8>>),
    SystemRoots {
        certificates: Vec<Vec<u8>>,
        roots: SystemTlsRootSet,
    },
}

type TlsIoJob =
    Box<dyn FnOnce(Arc<AtomicBool>) -> Result<TlsIoJobOutput, TlsActivationError> + Send + 'static>;

/// Process-owned admission and supervision for blocking custom-CA file I/O.
pub(crate) struct TlsIoRuntime {
    inner: Arc<RuntimeInner>,
    supervisor: AsyncMutex<Option<JoinHandle<()>>>,
    #[cfg(test)]
    system_root_loads: std::sync::atomic::AtomicUsize,
}

struct RuntimeInner {
    state: Mutex<RuntimeState>,
    commands: mpsc::Sender<SupervisorCommand>,
    supervisor_control: mpsc::UnboundedSender<SupervisorControl>,
    state_changed: Notify,
    #[cfg(test)]
    completion_hook: Mutex<Option<Arc<CompletionHook>>>,
}

#[cfg(test)]
struct CompletionHook {
    reached: std::sync::mpsc::Sender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

struct RuntimeState {
    accepting: bool,
    slots: Vec<Option<Arc<OperationSignal>>>,
    active: usize,
}

struct SupervisorCommand {
    slot: OperationSlotGuard,
    signal: Arc<OperationSignal>,
    job: TlsIoJob,
    result: oneshot::Sender<Result<TlsIoJobOutput, TlsActivationError>>,
}

struct OperationSlotGuard {
    inner: Arc<RuntimeInner>,
    slot: usize,
}

struct WorkerCompletionGuard {
    slot: Option<OperationSlotGuard>,
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

/// A single admitted custom-CA operation.
///
/// Dropping this future requests cancellation while the worker retains its
/// capacity slot until the operating-system call actually returns.
struct TlsIoOperation {
    result: oneshot::Receiver<Result<TlsIoJobOutput, TlsActivationError>>,
    signal: Arc<OperationSignal>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum TlsIoRuntimeError {
    #[error("TLS I/O operation ceiling must be nonzero")]
    ZeroOperationCeiling,
    #[error("Tokio runtime is unavailable for TLS I/O supervision")]
    RuntimeUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
enum TlsIoAdmissionError {
    #[error("TLS I/O admission is closed")]
    Closed,
    #[error("TLS I/O operation capacity is exhausted")]
    CapacityExhausted,
    #[error("TLS I/O supervisor is unavailable")]
    SupervisorUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TlsIoShutdownOutcome {
    Drained,
    DeadlineExceeded { detached_operations: usize },
}

impl TlsIoRuntime {
    pub(crate) fn new() -> Result<Arc<Self>, TlsIoRuntimeError> {
        Self::try_new(DEFAULT_MAX_OPERATIONS)
    }

    #[cfg(test)]
    fn for_test(max_operations: usize) -> Arc<Self> {
        Self::try_new(max_operations).unwrap()
    }

    fn try_new(max_operations: usize) -> Result<Arc<Self>, TlsIoRuntimeError> {
        if max_operations == 0 {
            return Err(TlsIoRuntimeError::ZeroOperationCeiling);
        }
        let handle = Handle::try_current().map_err(|_| TlsIoRuntimeError::RuntimeUnavailable)?;
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
            #[cfg(test)]
            completion_hook: Mutex::new(None),
        });
        let supervisor_inner = Arc::clone(&inner);
        let supervisor = handle.spawn(async move {
            run_supervisor(supervisor_inner, receiver, control_receiver).await;
        });
        Ok(Arc::new(Self {
            inner,
            supervisor: AsyncMutex::new(Some(supervisor)),
            #[cfg(test)]
            system_root_loads: std::sync::atomic::AtomicUsize::new(0),
        }))
    }

    /// Loads and validates one custom-CA bundle without blocking a Tokio worker.
    pub(crate) async fn load_custom_ca(
        &self,
        path: PathBuf,
        generation: PolicyGeneration,
        cancellation: &ActivationCancellation,
    ) -> Result<Vec<Vec<u8>>, TlsActivationError> {
        self.load_custom_ca_inner(path, generation, cancellation, || {})
            .await
    }

    /// Loads and validates native system roots without blocking a Tokio worker.
    pub(crate) async fn load_system_roots(
        &self,
        generation: PolicyGeneration,
        cancellation: &ActivationCancellation,
    ) -> Result<(Vec<Vec<u8>>, SystemTlsRootSet), TlsActivationError> {
        if cancellation.is_cancelled() {
            return Err(TlsActivationError::ActivationCancelled);
        }
        #[cfg(test)]
        self.system_root_loads
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let operation = match self.submit(Box::new(move |worker_cancellation| {
            let (certificates, roots) = load_bounded_system_roots(generation, &mut || {
                worker_cancellation.load(Ordering::Acquire)
            })?;
            Ok(TlsIoJobOutput::SystemRoots {
                certificates,
                roots,
            })
        })) {
            Ok(operation) => operation,
            Err(_) if cancellation.is_cancelled() => {
                return Err(TlsActivationError::ActivationCancelled);
            }
            Err(_) => return Err(TlsActivationError::CaLoaderUnavailable),
        };
        tokio::pin!(operation);
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(TlsActivationError::ActivationCancelled),
            result = &mut operation => result,
        };
        if cancellation.is_cancelled() {
            Err(TlsActivationError::ActivationCancelled)
        } else {
            match result? {
                TlsIoJobOutput::SystemRoots {
                    certificates,
                    roots,
                } => Ok((certificates, roots)),
                TlsIoJobOutput::CustomCa(_) => Err(TlsActivationError::Configuration),
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn system_root_loads(&self) -> usize {
        self.system_root_loads
            .load(std::sync::atomic::Ordering::Acquire)
    }

    async fn load_custom_ca_inner(
        &self,
        path: PathBuf,
        generation: PolicyGeneration,
        cancellation: &ActivationCancellation,
        before_submit: impl FnOnce(),
    ) -> Result<Vec<Vec<u8>>, TlsActivationError> {
        if cancellation.is_cancelled() {
            return Err(TlsActivationError::ActivationCancelled);
        }
        before_submit();
        let operation = match self.submit(Box::new(move |worker_cancellation| {
            load_bounded_custom_ca(&path, generation, &mut || {
                worker_cancellation.load(Ordering::Acquire)
            })
            .map(TlsIoJobOutput::CustomCa)
        })) {
            Ok(operation) => operation,
            Err(_) if cancellation.is_cancelled() => {
                return Err(TlsActivationError::ActivationCancelled);
            }
            Err(_) => return Err(TlsActivationError::CaLoaderUnavailable),
        };
        tokio::pin!(operation);
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(TlsActivationError::ActivationCancelled),
            result = &mut operation => result,
        };
        if cancellation.is_cancelled() {
            Err(TlsActivationError::ActivationCancelled)
        } else {
            match result? {
                TlsIoJobOutput::CustomCa(certificates) => Ok(certificates),
                TlsIoJobOutput::SystemRoots { .. } => Err(TlsActivationError::Configuration),
            }
        }
    }

    #[cfg(test)]
    async fn load_custom_ca_with_admission_hook(
        &self,
        path: PathBuf,
        generation: PolicyGeneration,
        cancellation: &ActivationCancellation,
        before_submit: impl FnOnce(),
    ) -> Result<Vec<Vec<u8>>, TlsActivationError> {
        self.load_custom_ca_inner(path, generation, cancellation, before_submit)
            .await
    }

    #[cfg(test)]
    async fn load_custom_ca_with_open_hook(
        &self,
        path: PathBuf,
        generation: PolicyGeneration,
        cancellation: &ActivationCancellation,
        after_open: impl FnOnce() + Send + 'static,
    ) -> Result<Vec<Vec<u8>>, TlsActivationError> {
        if cancellation.is_cancelled() {
            return Err(TlsActivationError::ActivationCancelled);
        }
        let operation = match self.submit(Box::new(move |worker_cancellation| {
            crate::tls::load_bounded_custom_ca_with_open_hook(
                &path,
                generation,
                &mut || worker_cancellation.load(Ordering::Acquire),
                after_open,
            )
            .map(TlsIoJobOutput::CustomCa)
        })) {
            Ok(operation) => operation,
            Err(_) if cancellation.is_cancelled() => {
                return Err(TlsActivationError::ActivationCancelled);
            }
            Err(_) => return Err(TlsActivationError::CaLoaderUnavailable),
        };
        tokio::pin!(operation);
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(TlsActivationError::ActivationCancelled),
            result = &mut operation => result,
        };
        if cancellation.is_cancelled() {
            Err(TlsActivationError::ActivationCancelled)
        } else {
            match result? {
                TlsIoJobOutput::CustomCa(certificates) => Ok(certificates),
                TlsIoJobOutput::SystemRoots { .. } => Err(TlsActivationError::Configuration),
            }
        }
    }

    fn submit(&self, job: TlsIoJob) -> Result<TlsIoOperation, TlsIoAdmissionError> {
        let mut state = lock(&self.inner.state);
        if !state.accepting {
            return Err(TlsIoAdmissionError::Closed);
        }
        let slot = state
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(TlsIoAdmissionError::CapacityExhausted)?;
        let signal = Arc::new(OperationSignal {
            cancellation: Arc::new(AtomicBool::new(false)),
            publication: Mutex::new(()),
            operation_waker: Mutex::new(None),
        });
        state.slots[slot] = Some(Arc::clone(&signal));
        state.active = state
            .active
            .checked_add(1)
            .expect("TLS I/O active count cannot exceed bounded slots");

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
                    TlsIoAdmissionError::CapacityExhausted
                }
                mpsc::error::TrySendError::Closed(command) => {
                    drop(command);
                    TlsIoAdmissionError::SupervisorUnavailable
                }
            });
        }
        drop(state);
        Ok(TlsIoOperation {
            result: receiver,
            signal,
        })
    }

    #[cfg(test)]
    pub(crate) async fn run_for_test(
        &self,
        job: impl FnOnce(Arc<AtomicBool>) -> Result<Vec<Vec<u8>>, TlsActivationError> + Send + 'static,
    ) -> Result<Vec<Vec<u8>>, TlsActivationError> {
        let output = self
            .submit(Box::new(move |cancellation| {
                job(cancellation).map(TlsIoJobOutput::CustomCa)
            }))
            .map_err(|_| TlsActivationError::CaLoaderUnavailable)?
            .await?;
        match output {
            TlsIoJobOutput::CustomCa(certificates) => Ok(certificates),
            TlsIoJobOutput::SystemRoots { .. } => Err(TlsActivationError::Configuration),
        }
    }

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

    pub(crate) async fn shutdown_and_wait(
        &self,
        deadline: Option<tokio::time::Instant>,
    ) -> TlsIoShutdownOutcome {
        self.begin_shutdown();
        let mut supervisor = self.supervisor.lock().await;
        if let Some(task) = supervisor.as_mut() {
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
        drop(supervisor);
        self.wait_for_detached_operations(deadline).await
    }

    async fn wait_for_detached_operations(
        &self,
        deadline: Option<tokio::time::Instant>,
    ) -> TlsIoShutdownOutcome {
        loop {
            if self.active_operations() == 0 {
                return TlsIoShutdownOutcome::Drained;
            }
            let changed = self.inner.state_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.active_operations() == 0 {
                continue;
            }
            match deadline {
                Some(deadline) => {
                    tokio::select! {
                        biased;
                        _ = tokio::time::sleep_until(deadline) => return self.deadline_outcome(),
                        () = &mut changed => {}
                    }
                }
                None => changed.await,
            }
        }
    }

    fn active_operations(&self) -> usize {
        lock(&self.inner.state).active
    }

    fn deadline_outcome(&self) -> TlsIoShutdownOutcome {
        let detached_operations = self.active_operations();
        if detached_operations == 0 {
            TlsIoShutdownOutcome::Drained
        } else {
            TlsIoShutdownOutcome::DeadlineExceeded {
                detached_operations,
            }
        }
    }
}

impl Drop for TlsIoRuntime {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

impl Future for TlsIoOperation {
    type Output = Result<TlsIoJobOutput, TlsActivationError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.result).poll(context) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(TlsActivationError::ActivationCancelled)),
            Poll::Pending => {
                self.signal.register_operation_waker(context.waker());
                match Pin::new(&mut self.result).poll(context) {
                    Poll::Ready(Ok(result)) => Poll::Ready(result),
                    Poll::Ready(Err(_)) => {
                        Poll::Ready(Err(TlsActivationError::ActivationCancelled))
                    }
                    Poll::Pending if self.signal.is_cancelled() => {
                        Poll::Ready(Err(TlsActivationError::ActivationCancelled))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}

impl Drop for TlsIoOperation {
    fn drop(&mut self) {
        self.signal.cancel();
    }
}

async fn run_supervisor(
    inner: Arc<RuntimeInner>,
    mut commands: mpsc::Receiver<SupervisorCommand>,
    mut control: mpsc::UnboundedReceiver<SupervisorControl>,
) {
    loop {
        if supervisor_drained(&inner) {
            break;
        }
        tokio::select! {
            biased;
            control_message = control.recv() => {
                if matches!(control_message, Some(SupervisorControl::Abandon)) {
                    abandon_queued_commands(&mut commands);
                    return;
                }
            }
            command = commands.recv() => {
                if let Some(command) = command {
                    start_or_cancel(command);
                }
            }
        }
    }
}

fn start_or_cancel(command: SupervisorCommand) {
    if command.signal.is_cancelled() {
        if !command.result.is_closed() {
            let _ = command
                .result
                .send(Err(TlsActivationError::ActivationCancelled));
        }
        return;
    }
    let slot = command.slot.slot;
    let pending = Arc::new(Mutex::new(Some(command)));
    let worker_pending = Arc::clone(&pending);
    match std::thread::Builder::new()
        .name(format!("tls-io-{slot}"))
        .stack_size(WORKER_STACK_BYTES)
        .spawn(move || {
            let command = lock(&worker_pending)
                .take()
                .expect("TLS I/O worker command must be present");
            run_worker(command);
        }) {
        Ok(worker) => drop(worker),
        Err(error) => {
            tracing::error!(%error, "TLS I/O worker thread could not be started");
            if let Some(command) = lock(&pending).take() {
                let _ = command
                    .result
                    .send(Err(TlsActivationError::CaLoaderUnavailable));
            }
        }
    }
}

fn run_worker(command: SupervisorCommand) {
    let SupervisorCommand {
        slot,
        signal,
        job,
        result,
    } = command;
    let _completion = WorkerCompletionGuard { slot: Some(slot) };
    if signal.is_cancelled() || result.is_closed() {
        return;
    }
    let outcome = catch_unwind(AssertUnwindSafe(|| job(Arc::clone(&signal.cancellation))))
        .unwrap_or(Err(TlsActivationError::CaLoaderUnavailable));
    signal.publish_if_active(result, outcome);
}

fn abandon_queued_commands(commands: &mut mpsc::Receiver<SupervisorCommand>) {
    commands.close();
    while let Ok(command) = commands.try_recv() {
        if !command.result.is_closed() {
            let _ = command
                .result
                .send(Err(TlsActivationError::ActivationCancelled));
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
            .expect("TLS I/O active count cannot underflow");
    }
    drop(state);
    inner.state_changed.notify_waiters();
    let _ = inner
        .supervisor_control
        .send(SupervisorControl::StateChanged);
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
        if let Some(waker) = lock(&self.operation_waker).take() {
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
        result: oneshot::Sender<Result<TlsIoJobOutput, TlsActivationError>>,
        outcome: Result<TlsIoJobOutput, TlsActivationError>,
    ) {
        let _publication = lock(&self.publication);
        if !self.is_cancelled() && !result.is_closed() {
            let _ = result.send(outcome);
        }
    }
}

impl Drop for OperationSlotGuard {
    fn drop(&mut self) {
        complete_slot(&self.inner, self.slot);
    }
}

impl Drop for WorkerCompletionGuard {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            #[cfg(test)]
            if let Some(hook) = lock(&slot.inner.completion_hook).take() {
                let _ = hook.reached.send(());
                let _ = lock(&hook.release).recv();
            }
            drop(slot);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::ffi::CString;
    use std::fs::OpenOptions;
    use std::os::unix::ffi::OsStrExt as _;
    use std::sync::Condvar;
    use std::time::Duration;

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn completed_result_retains_its_slot_until_worker_exit() {
        let runtime = TlsIoRuntime::for_test(1);
        let (reached_tx, reached_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        *lock(&runtime.inner.completion_hook) = Some(Arc::new(CompletionHook {
            reached: reached_tx,
            release: Mutex::new(release_rx),
        }));

        assert!(runtime
            .submit(Box::new(|_| Ok(TlsIoJobOutput::CustomCa(Vec::new()))))
            .unwrap()
            .await
            .is_ok());
        reached_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker did not queue its completion");
        assert!(matches!(
            runtime.submit(Box::new(|_| Ok(TlsIoJobOutput::CustomCa(Vec::new())))),
            Err(TlsIoAdmissionError::CapacityExhausted)
        ));
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                runtime.shutdown_and_wait(Some(
                    tokio::time::Instant::now() + Duration::from_millis(20),
                )),
            )
            .await
            .expect("shutdown exceeded its deadline while a worker was exiting"),
            TlsIoShutdownOutcome::DeadlineExceeded {
                detached_operations: 1,
            }
        );
        release_tx.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), runtime.shutdown_and_wait(None))
                .await
                .unwrap(),
            TlsIoShutdownOutcome::Drained
        );
    }

    #[tokio::test]
    async fn cancellation_wins_a_concurrent_admission_close() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = TlsIoRuntime::for_test(1);
        let cancellation = ActivationCancellation::new_for_test();
        let hook_runtime = Arc::clone(&runtime);
        let hook_cancellation = cancellation.clone();

        assert_eq!(
            runtime
                .load_custom_ca_with_admission_hook(
                    directory.path().join("unobserved-sensitive-ca.pem"),
                    PolicyGeneration::new(7).unwrap(),
                    &cancellation,
                    move || {
                        hook_cancellation.cancel_for_test();
                        hook_runtime.begin_shutdown();
                    },
                )
                .await,
            Err(TlsActivationError::ActivationCancelled)
        );
        assert_eq!(
            runtime.shutdown_and_wait(None).await,
            TlsIoShutdownOutcome::Drained
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_detaches_a_worker_blocked_opening_a_fifo() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("blocked-open-ca.pem");
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let runtime = TlsIoRuntime::for_test(1);
        let load_runtime = Arc::clone(&runtime);
        let load_path = path.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let load = tokio::spawn(async move {
            load_runtime
                .run_for_test(move |_| {
                    started_tx.send(()).unwrap();
                    drop(OpenOptions::new().read(true).open(load_path).unwrap());
                    Ok(Vec::new())
                })
                .await
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker did not enter FIFO open");

        runtime.begin_shutdown();
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(200), load)
                .await
                .expect("cancellation waited for FIFO open")
                .unwrap(),
            Err(TlsActivationError::ActivationCancelled)
        );
        assert_eq!(
            runtime
                .shutdown_and_wait(Some(tokio::time::Instant::now()))
                .await,
            TlsIoShutdownOutcome::DeadlineExceeded {
                detached_operations: 1,
            }
        );

        let writer = std::thread::spawn(move || {
            drop(OpenOptions::new().write(true).open(path).unwrap());
        });
        writer.join().unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), runtime.shutdown_and_wait(None))
                .await
                .unwrap(),
            TlsIoShutdownOutcome::Drained
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fifo_cancellation_returns_promptly_and_shutdown_detaches_until_worker_returns() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("held-open-ca.pem");
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let held_open = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        let runtime = TlsIoRuntime::for_test(1);
        let cancellation = ActivationCancellation::new_for_test();
        let (opened_tx, opened_rx) = oneshot::channel();
        let load_runtime = Arc::clone(&runtime);
        let load_cancellation = cancellation.clone();
        let load_path = path.clone();
        let load = tokio::spawn(async move {
            load_runtime
                .load_custom_ca_with_open_hook(
                    load_path,
                    PolicyGeneration::new(7).unwrap(),
                    &load_cancellation,
                    move || {
                        let _ = opened_tx.send(());
                    },
                )
                .await
        });

        tokio::time::timeout(Duration::from_secs(1), opened_rx)
            .await
            .expect("FIFO open remained blocked")
            .expect("TLS worker stopped before the FIFO was opened");
        cancellation.cancel_for_test();
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(200), load)
                .await
                .expect("candidate cancellation waited for FIFO open")
                .unwrap(),
            Err(TlsActivationError::ActivationCancelled)
        );
        assert_eq!(runtime.active_operations(), 1);
        assert_eq!(
            runtime
                .shutdown_and_wait(Some(tokio::time::Instant::now()))
                .await,
            TlsIoShutdownOutcome::DeadlineExceeded {
                detached_operations: 1
            }
        );

        drop(held_open);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), runtime.shutdown_and_wait(None))
                .await
                .expect("detached FIFO worker did not release its charged slot"),
            TlsIoShutdownOutcome::Drained
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn candidate_cancellation_wins_a_concurrent_worker_error() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = TlsIoRuntime::for_test(1);
        let cancellation = ActivationCancellation::new_for_test();
        let worker_cancellation = cancellation.clone();

        let result = runtime
            .load_custom_ca_with_open_hook(
                directory.path().to_path_buf(),
                PolicyGeneration::new(7).unwrap(),
                &cancellation,
                move || worker_cancellation.cancel_for_test(),
            )
            .await;

        assert_eq!(result, Err(TlsActivationError::ActivationCancelled));
        assert_eq!(
            runtime.shutdown_and_wait(None).await,
            TlsIoShutdownOutcome::Drained
        );
    }

    #[tokio::test]
    async fn fixed_capacity_and_shutdown_close_admission() {
        let runtime = TlsIoRuntime::for_test(1);
        let operation = runtime
            .submit(Box::new(|cancellation| {
                while !cancellation.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                Err(TlsActivationError::ActivationCancelled)
            }))
            .unwrap();
        assert!(matches!(
            runtime.submit(Box::new(|_| Ok(TlsIoJobOutput::CustomCa(Vec::new())))),
            Err(TlsIoAdmissionError::CapacityExhausted)
        ));
        runtime.begin_shutdown();
        assert!(matches!(
            runtime.submit(Box::new(|_| Ok(TlsIoJobOutput::CustomCa(Vec::new())))),
            Err(TlsIoAdmissionError::Closed)
        ));
        assert!(matches!(
            operation.await,
            Err(TlsActivationError::ActivationCancelled)
        ));
        assert_eq!(
            runtime.shutdown_and_wait(None).await,
            TlsIoShutdownOutcome::Drained
        );
    }

    #[test]
    fn tokio_runtime_drop_does_not_wait_for_a_detached_tls_worker() {
        let gate = Arc::new(BlockingGate::default());
        let runtime_gate = Arc::clone(&gate);
        let (runtime_stopping_tx, runtime_stopping_rx) = std::sync::mpsc::channel();
        let (runtime_dropped_tx, runtime_dropped_rx) = std::sync::mpsc::channel();
        let (worker_finished_tx, worker_finished_rx) = std::sync::mpsc::channel();
        let manager = std::thread::spawn(move || {
            let tokio_runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            tokio_runtime.block_on(async move {
                let runtime = TlsIoRuntime::for_test(1);
                let (started_tx, started_rx) = oneshot::channel();
                let operation = runtime
                    .submit(Box::new(move |_| {
                        let _ = started_tx.send(());
                        runtime_gate.wait();
                        worker_finished_tx.send(()).unwrap();
                        Ok(TlsIoJobOutput::CustomCa(Vec::new()))
                    }))
                    .unwrap();
                tokio::time::timeout(Duration::from_secs(1), started_rx)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    runtime
                        .shutdown_and_wait(Some(
                            tokio::time::Instant::now() + Duration::from_millis(20),
                        ))
                        .await,
                    TlsIoShutdownOutcome::DeadlineExceeded {
                        detached_operations: 1,
                    }
                );
                assert!(matches!(
                    operation.await,
                    Err(TlsActivationError::ActivationCancelled)
                ));
            });
            runtime_stopping_tx.send(()).unwrap();
            drop(tokio_runtime);
            runtime_dropped_tx.send(()).unwrap();
        });

        runtime_stopping_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("TLS shutdown did not return before Tokio runtime drop");
        runtime_dropped_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("Tokio runtime drop waited for a detached TLS worker");
        assert!(matches!(
            worker_finished_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        gate.open();
        worker_finished_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("detached TLS worker did not finish after release");
        manager.join().unwrap();
    }
}
