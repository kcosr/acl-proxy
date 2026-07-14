use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};

use tokio::sync::mpsc;

const CLOSED_BIT: usize = 1usize << (usize::BITS - 1);
const ACTIVE_MASK: usize = CLOSED_BIT - 1;

pub(super) struct BoundedCaptureWorker<Job> {
    admission: std::sync::Arc<AdmissionState>,
    sender: mpsc::Sender<WorkerMessage<Job>>,
    join: Mutex<Option<std::thread::JoinHandle<()>>>,
    shutdown: OnceLock<std::sync::Arc<ShutdownCompletion>>,
}

enum WorkerMessage<Job> {
    Job(Job),
    Shutdown,
}

struct AdmissionState {
    state: AtomicUsize,
    wait_lock: Mutex<()>,
    quiescent: Condvar,
}

struct AdmissionGuard<'state> {
    state: &'state AdmissionState,
}

struct ShutdownCompletion {
    complete: AtomicBool,
    changed: tokio::sync::Notify,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureWorkerStartError {
    #[error("capture queue capacity must be at least one")]
    ZeroCapacity,
    #[error("failed to start capture worker: {0}")]
    Spawn(#[source] std::io::Error),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum CaptureSubmitError<Job> {
    Full(Job),
    Closed(Job),
}

impl<Job: Send + 'static> BoundedCaptureWorker<Job> {
    pub(super) fn start(
        capacity: usize,
        mut process: impl FnMut(Job) + Send + 'static,
    ) -> Result<Self, CaptureWorkerStartError> {
        if capacity == 0 {
            return Err(CaptureWorkerStartError::ZeroCapacity);
        }
        let (sender, mut receiver) = mpsc::channel(capacity);
        let join = std::thread::Builder::new()
            .name("acl-proxy-capture".to_owned())
            .spawn(move || {
                while let Some(message) = receiver.blocking_recv() {
                    match message {
                        WorkerMessage::Job(job) => {
                            if catch_unwind(AssertUnwindSafe(|| process(job))).is_err() {
                                tracing::error!(
                                    "capture worker isolated a record-processing panic"
                                );
                            }
                        }
                        WorkerMessage::Shutdown => break,
                    }
                }
            })
            .map_err(CaptureWorkerStartError::Spawn)?;
        Ok(Self {
            admission: std::sync::Arc::new(AdmissionState {
                state: AtomicUsize::new(0),
                wait_lock: Mutex::new(()),
                quiescent: Condvar::new(),
            }),
            sender,
            join: Mutex::new(Some(join)),
            shutdown: OnceLock::new(),
        })
    }

    pub(super) fn try_submit(&self, job: Job) -> Result<(), CaptureSubmitError<Job>> {
        let Some(_admission) = self.admission.try_enter() else {
            return Err(CaptureSubmitError::Closed(job));
        };
        match self.sender.try_send(WorkerMessage::Job(job)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(WorkerMessage::Job(job))) => {
                Err(CaptureSubmitError::Full(job))
            }
            Err(mpsc::error::TrySendError::Closed(WorkerMessage::Job(job))) => {
                Err(CaptureSubmitError::Closed(job))
            }
            Err(mpsc::error::TrySendError::Full(WorkerMessage::Shutdown))
            | Err(mpsc::error::TrySendError::Closed(WorkerMessage::Shutdown)) => {
                unreachable!("submit sends only capture jobs")
            }
        }
    }

    pub(super) fn begin_shutdown(&self) {
        self.admission.close();
    }

    pub(super) async fn shutdown(&self) {
        let completion = self
            .shutdown
            .get_or_init(|| {
                self.begin_shutdown();
                let join = self
                    .join
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take();
                let completion = std::sync::Arc::new(ShutdownCompletion {
                    complete: AtomicBool::new(false),
                    changed: tokio::sync::Notify::new(),
                });
                let worker_completion = completion.clone();
                let admission = self.admission.clone();
                let sender = self.sender.clone();
                tokio::task::spawn_blocking(move || {
                    if let Some(join) = join {
                        admission.wait_until_quiescent();
                        let _ = sender.blocking_send(WorkerMessage::Shutdown);
                        if join.join().is_err() {
                            tracing::error!("capture worker thread panicked during shutdown");
                        }
                    }
                    worker_completion.complete.store(true, Ordering::Release);
                    worker_completion.changed.notify_waiters();
                });
                completion
            })
            .clone();
        completion.wait().await;
    }
}

impl AdmissionState {
    fn try_enter(&self) -> Option<AdmissionGuard<'_>> {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state & CLOSED_BIT != 0 || state & ACTIVE_MASK == ACTIVE_MASK {
                return None;
            }
            match self.state.compare_exchange_weak(
                state,
                state + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(AdmissionGuard { state: self }),
                Err(observed) => state = observed,
            }
        }
    }

    fn close(&self) {
        let before = self.state.fetch_or(CLOSED_BIT, Ordering::AcqRel);
        if before & ACTIVE_MASK == 0 {
            self.quiescent.notify_all();
        }
    }

    fn wait_until_quiescent(&self) {
        let mut guard = self
            .wait_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while self.state.load(Ordering::Acquire) & ACTIVE_MASK != 0 {
            guard = self
                .quiescent
                .wait(guard)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

impl Drop for AdmissionGuard<'_> {
    fn drop(&mut self) {
        let before = self.state.state.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(before & ACTIVE_MASK != 0, "capture admission underflow");
        if before & CLOSED_BIT != 0 && before & ACTIVE_MASK == 1 {
            let _guard = self
                .state
                .wait_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.state.quiescent.notify_all();
        }
    }
}

impl ShutdownCompletion {
    async fn wait(&self) {
        loop {
            let changed = self.changed.notified();
            if self.complete.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
}

impl<Job> Drop for BoundedCaptureWorker<Job> {
    fn drop(&mut self) {
        self.admission.close();
        if self
            .join
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
        {
            tracing::error!("capture worker dropped before joined shutdown");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn full_queue_rejects_without_waiting_and_shutdown_drains_accepted_jobs() {
        let gate = Arc::new(Barrier::new(2));
        let processed = Arc::new(Mutex::new(Vec::new()));
        let worker = BoundedCaptureWorker::start(1, {
            let gate = gate.clone();
            let processed = processed.clone();
            move |job| {
                if job == 1 {
                    gate.wait();
                }
                processed.lock().unwrap().push(job);
            }
        })
        .unwrap();

        worker.try_submit(1).unwrap();
        while worker.sender.capacity() != 1 {
            std::thread::yield_now();
        }
        worker.try_submit(2).unwrap();
        assert_eq!(worker.try_submit(3), Err(CaptureSubmitError::Full(3)));

        worker.begin_shutdown();
        assert_eq!(worker.try_submit(4), Err(CaptureSubmitError::Closed(4)));
        gate.wait();
        worker.shutdown().await;
        assert_eq!(*processed.lock().unwrap(), [1, 2]);
    }

    #[tokio::test]
    async fn processing_panic_isolated_and_shutdown_is_idempotent() {
        let processed = Arc::new(AtomicUsize::new(0));
        let worker = BoundedCaptureWorker::start(2, {
            let processed = processed.clone();
            move |job| {
                if job == 1 {
                    panic!("injected capture panic");
                }
                processed.fetch_add(job, Ordering::Relaxed);
            }
        })
        .unwrap();
        worker.try_submit(1).unwrap();
        worker.try_submit(2).unwrap();
        worker.shutdown().await;
        worker.shutdown().await;
        assert_eq!(processed.load(Ordering::Relaxed), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_linearizes_with_an_inflight_submitter() {
        let admission_entered = Arc::new(AtomicBool::new(false));
        let release_admission = Arc::new(AtomicBool::new(false));
        let processed = Arc::new(AtomicUsize::new(0));
        let worker = Arc::new(
            BoundedCaptureWorker::start(4, {
                let processed = processed.clone();
                move |_| {
                    processed.fetch_add(1, Ordering::Relaxed);
                }
            })
            .unwrap(),
        );

        let submitter = {
            let worker = worker.clone();
            let admission_entered = admission_entered.clone();
            let release_admission = release_admission.clone();
            std::thread::spawn(move || {
                let guard = worker.admission.try_enter().unwrap();
                admission_entered.store(true, Ordering::Release);
                while !release_admission.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                worker.sender.try_send(WorkerMessage::Job(())).unwrap();
                drop(guard);
            })
        };
        while !admission_entered.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        worker.begin_shutdown();
        let shutdown = {
            let worker = worker.clone();
            tokio::spawn(async move { worker.shutdown().await })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!shutdown.is_finished());
        release_admission.store(true, Ordering::Release);
        submitter.join().unwrap();
        shutdown.await.unwrap();
        assert_eq!(processed.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_shutdown_waiter_cannot_detach_the_worker_join() {
        let gate = Arc::new(Barrier::new(2));
        let processed = Arc::new(AtomicUsize::new(0));
        let worker = Arc::new(
            BoundedCaptureWorker::start(1, {
                let gate = gate.clone();
                let processed = processed.clone();
                move |_| {
                    gate.wait();
                    processed.fetch_add(1, Ordering::Release);
                }
            })
            .unwrap(),
        );
        worker.try_submit(()).unwrap();

        let first_waiter = {
            let worker = worker.clone();
            tokio::spawn(async move { worker.shutdown().await })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        first_waiter.abort();
        assert!(first_waiter.await.is_err());
        gate.wait();

        tokio::time::timeout(Duration::from_secs(1), worker.shutdown())
            .await
            .expect("a replacement waiter observes the same worker join");
        assert_eq!(processed.load(Ordering::Acquire), 1);
    }
}
