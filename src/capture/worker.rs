use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const CLOSED_BIT: usize = 1usize << (usize::BITS - 1);
const ACTIVE_MASK: usize = CLOSED_BIT - 1;
const ADMISSION_QUIESCENCE_POLL: Duration = Duration::from_millis(5);

pub(super) struct BoundedCaptureWorker<Job> {
    admission: Arc<AdmissionState>,
    queue: Arc<WorkerQueue<Job>>,
    join: Mutex<Option<std::thread::JoinHandle<()>>>,
    completion: Arc<ShutdownCompletion>,
}

struct AdmissionState {
    state: AtomicUsize,
}

struct AdmissionGuard<'state> {
    state: &'state AdmissionState,
}

struct WorkerQueue<Job> {
    state: Mutex<WorkerQueueState<Job>>,
    changed: Condvar,
}

struct WorkerQueueState<Job> {
    jobs: VecDeque<Job>,
    capacity: usize,
    force_discard: bool,
    processing: bool,
    discarded: usize,
}

struct ShutdownCompletion {
    complete: AtomicBool,
    changed: tokio::sync::Notify,
}

struct ThreadCompletionGuard {
    completion: Arc<ShutdownCompletion>,
}

struct ShutdownWaitGuard<'worker, Job> {
    worker: &'worker BoundedCaptureWorker<Job>,
    armed: bool,
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
        process: impl FnMut(Job) + Send + 'static,
    ) -> Result<Self, CaptureWorkerStartError> {
        if capacity == 0 {
            return Err(CaptureWorkerStartError::ZeroCapacity);
        }
        let admission = Arc::new(AdmissionState {
            state: AtomicUsize::new(0),
        });
        let queue = Arc::new(WorkerQueue {
            state: Mutex::new(WorkerQueueState {
                jobs: VecDeque::with_capacity(capacity),
                capacity,
                force_discard: false,
                processing: false,
                discarded: 0,
            }),
            changed: Condvar::new(),
        });
        let completion = Arc::new(ShutdownCompletion {
            complete: AtomicBool::new(false),
            changed: tokio::sync::Notify::new(),
        });
        let worker_admission = Arc::clone(&admission);
        let worker_queue = Arc::clone(&queue);
        let worker_completion = Arc::clone(&completion);
        let join = std::thread::Builder::new()
            .name("acl-proxy-capture".to_owned())
            .spawn(move || {
                let _completion = ThreadCompletionGuard {
                    completion: worker_completion,
                };
                run_worker(worker_admission, worker_queue, process);
            })
            .map_err(CaptureWorkerStartError::Spawn)?;
        Ok(Self {
            admission,
            queue,
            join: Mutex::new(Some(join)),
            completion,
        })
    }
}

impl<Job> BoundedCaptureWorker<Job> {
    pub(super) fn try_submit(&self, job: Job) -> Result<(), CaptureSubmitError<Job>> {
        if self.completion.complete.load(Ordering::Acquire) {
            return Err(CaptureSubmitError::Closed(job));
        }
        let Some(_admission) = self.admission.try_enter() else {
            return Err(CaptureSubmitError::Closed(job));
        };
        let mut state = match self.queue.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(CaptureSubmitError::Full(job));
            }
        };
        if self.completion.complete.load(Ordering::Acquire) {
            return Err(CaptureSubmitError::Closed(job));
        }
        if state.jobs.len() == state.capacity {
            return Err(CaptureSubmitError::Full(job));
        }
        state.jobs.push_back(job);
        drop(state);
        self.queue.changed.notify_one();
        Ok(())
    }

    pub(super) fn begin_shutdown(&self) {
        self.admission.close();
        self.queue.changed.notify_all();
    }

    pub(super) async fn shutdown(&self) {
        self.begin_shutdown();
        let mut wait = ShutdownWaitGuard {
            worker: self,
            armed: true,
        };
        self.completion.wait().await;
        wait.armed = false;
        self.join_completed_worker();
    }

    fn join_completed_worker(&self) {
        let join = lock(&self.join).take();
        if let Some(join) = join {
            if join.join().is_err() {
                tracing::error!("capture worker thread panicked during shutdown");
            }
        }
    }

    fn force_discard(&self) -> DetachedCaptureWork {
        let mut state = lock(&self.queue.state);
        state.force_discard = true;
        let detached = DetachedCaptureWork {
            processing_records: usize::from(state.processing),
            queued_records: state.jobs.len(),
            admitted_submissions: self.admission.active(),
        };
        drop(state);
        self.queue.changed.notify_all();
        detached
    }

    #[cfg(test)]
    fn discarded_records(&self) -> usize {
        lock(&self.queue.state).discarded
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DetachedCaptureWork {
    processing_records: usize,
    queued_records: usize,
    admitted_submissions: usize,
}

fn run_worker<Job>(
    admission: Arc<AdmissionState>,
    queue: Arc<WorkerQueue<Job>>,
    mut process: impl FnMut(Job),
) {
    loop {
        let job = {
            let mut state = lock(&queue.state);
            loop {
                if state.force_discard {
                    if let Some(job) = state.jobs.pop_front() {
                        state.discarded = state
                            .discarded
                            .checked_add(1)
                            .expect("capture discard accounting overflow");
                        break WorkerAction::Discard(job);
                    }
                    if !state.processing && admission.is_closed_and_quiescent() {
                        break WorkerAction::Exit;
                    }
                } else if let Some(job) = state.jobs.pop_front() {
                    state.processing = true;
                    break WorkerAction::Process(job);
                } else if admission.is_closed_and_quiescent() {
                    break WorkerAction::Exit;
                }

                let (next, _) = queue
                    .changed
                    .wait_timeout(state, ADMISSION_QUIESCENCE_POLL)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state = next;
            }
        };

        match job {
            WorkerAction::Process(job) => {
                if catch_unwind(AssertUnwindSafe(|| process(job))).is_err() {
                    tracing::error!("capture worker isolated a record-processing panic");
                }
                let mut state = lock(&queue.state);
                state.processing = false;
                drop(state);
                queue.changed.notify_all();
            }
            WorkerAction::Discard(job) => drop(job),
            WorkerAction::Exit => return,
        }
    }
}

enum WorkerAction<Job> {
    Process(Job),
    Discard(Job),
    Exit,
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
        self.state.fetch_or(CLOSED_BIT, Ordering::AcqRel);
    }

    fn is_closed_and_quiescent(&self) -> bool {
        self.state.load(Ordering::Acquire) == CLOSED_BIT
    }

    fn active(&self) -> usize {
        self.state.load(Ordering::Acquire) & ACTIVE_MASK
    }
}

impl Drop for AdmissionGuard<'_> {
    fn drop(&mut self) {
        let before = self.state.state.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(before & ACTIVE_MASK != 0, "capture admission underflow");
    }
}

impl ShutdownCompletion {
    async fn wait(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.complete.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
}

impl Drop for ThreadCompletionGuard {
    fn drop(&mut self) {
        self.completion.complete.store(true, Ordering::Release);
        self.completion.changed.notify_waiters();
    }
}

impl<Job> Drop for ShutdownWaitGuard<'_, Job> {
    fn drop(&mut self) {
        if !self.armed || self.worker.completion.complete.load(Ordering::Acquire) {
            return;
        }
        let detached = self.worker.force_discard();
        tracing::warn!(
            detached_records = detached.processing_records,
            queued_records_marked_for_discard = detached.queued_records,
            admitted_submissions_still_in_flight = detached.admitted_submissions,
            "capture worker shutdown wait ended before the worker exited"
        );
    }
}

impl<Job> Drop for BoundedCaptureWorker<Job> {
    fn drop(&mut self) {
        self.begin_shutdown();
        if self.completion.complete.load(Ordering::Acquire) {
            self.join_completed_worker();
            return;
        }
        if !lock(&self.queue.state).force_discard {
            tracing::error!("capture worker dropped before bounded shutdown");
            let _ = self.force_discard();
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    use super::*;

    fn wait_until(test: impl Fn() -> bool) {
        let started = std::time::Instant::now();
        while !test() {
            assert!(started.elapsed() < Duration::from_secs(1));
            std::thread::yield_now();
        }
    }

    #[tokio::test]
    async fn full_queue_rejects_without_waiting_and_shutdown_drains_accepted_jobs() {
        let gate = Arc::new(Barrier::new(2));
        let processing = Arc::new(AtomicBool::new(false));
        let processed = Arc::new(Mutex::new(Vec::new()));
        let worker = BoundedCaptureWorker::start(1, {
            let gate = Arc::clone(&gate);
            let processing = Arc::clone(&processing);
            let processed = Arc::clone(&processed);
            move |job| {
                processing.store(true, Ordering::Release);
                if job == 1 {
                    gate.wait();
                }
                processed.lock().unwrap().push(job);
            }
        })
        .unwrap();

        worker.try_submit(1).unwrap();
        wait_until(|| processing.load(Ordering::Acquire));
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
            let processed = Arc::clone(&processed);
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
        let ((), ()) = tokio::join!(worker.shutdown(), worker.shutdown());
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
                let processed = Arc::clone(&processed);
                move |_| {
                    processed.fetch_add(1, Ordering::Relaxed);
                }
            })
            .unwrap(),
        );

        let submitter = {
            let worker = Arc::clone(&worker);
            let admission_entered = Arc::clone(&admission_entered);
            let release_admission = Arc::clone(&release_admission);
            std::thread::spawn(move || {
                let guard = worker.admission.try_enter().unwrap();
                admission_entered.store(true, Ordering::Release);
                while !release_admission.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                let mut state = lock(&worker.queue.state);
                state.jobs.push_back(());
                drop(state);
                worker.queue.changed.notify_one();
                drop(guard);
            })
        };
        wait_until(|| admission_entered.load(Ordering::Acquire));
        worker.begin_shutdown();
        let shutdown = {
            let worker = Arc::clone(&worker);
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
    async fn cancelled_shutdown_discards_queued_work_and_detaches_only_the_running_job() {
        let gate = Arc::new(Barrier::new(2));
        let processing = Arc::new(AtomicBool::new(false));
        let processed = Arc::new(Mutex::new(Vec::new()));
        let worker = Arc::new(
            BoundedCaptureWorker::start(2, {
                let gate = Arc::clone(&gate);
                let processing = Arc::clone(&processing);
                let processed = Arc::clone(&processed);
                move |job| {
                    processing.store(true, Ordering::Release);
                    if job == 1 {
                        gate.wait();
                    }
                    processed.lock().unwrap().push(job);
                }
            })
            .unwrap(),
        );
        worker.try_submit(1).unwrap();
        wait_until(|| processing.load(Ordering::Acquire));
        worker.try_submit(2).unwrap();
        worker.try_submit(3).unwrap();

        let waiter = {
            let worker = Arc::clone(&worker);
            tokio::spawn(async move { worker.shutdown().await })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        waiter.abort();
        assert!(waiter.await.is_err());
        assert_eq!(
            worker.force_discard(),
            DetachedCaptureWork {
                processing_records: 1,
                queued_records: 2,
                admitted_submissions: 0,
            }
        );

        gate.wait();
        tokio::time::timeout(Duration::from_secs(1), worker.shutdown())
            .await
            .expect("replacement waiter observes eventual raw-thread exit");
        assert_eq!(*processed.lock().unwrap(), [1]);
        assert_eq!(worker.discarded_records(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forced_shutdown_waits_for_a_preclosed_submitter_then_discards_its_job() {
        let processed = Arc::new(AtomicUsize::new(0));
        let worker = Arc::new(
            BoundedCaptureWorker::start(1, {
                let processed = Arc::clone(&processed);
                move |_| {
                    processed.fetch_add(1, Ordering::Release);
                }
            })
            .unwrap(),
        );
        let admission = worker
            .admission
            .try_enter()
            .expect("submitter crosses admission before shutdown");
        let waiter = {
            let worker = Arc::clone(&worker);
            tokio::spawn(async move { worker.shutdown().await })
        };
        wait_until(|| worker.admission.state.load(Ordering::Acquire) & CLOSED_BIT != 0);
        waiter.abort();
        assert!(waiter.await.is_err());
        assert!(!worker.completion.complete.load(Ordering::Acquire));
        assert_eq!(
            worker.force_discard(),
            DetachedCaptureWork {
                processing_records: 0,
                queued_records: 0,
                admitted_submissions: 1,
            }
        );

        lock(&worker.queue.state).jobs.push_back(());
        worker.queue.changed.notify_one();
        drop(admission);

        tokio::time::timeout(Duration::from_secs(1), worker.shutdown())
            .await
            .expect("worker exits after the admitted submitter becomes quiescent");
        assert_eq!(processed.load(Ordering::Acquire), 0);
        assert_eq!(worker.discarded_records(), 1);
    }

    #[test]
    fn detached_worker_exits_after_its_tokio_runtime_is_dropped() {
        let gate = Arc::new(Barrier::new(2));
        let processing = Arc::new(AtomicBool::new(false));
        let worker = Arc::new(
            BoundedCaptureWorker::start(1, {
                let gate = Arc::clone(&gate);
                let processing = Arc::clone(&processing);
                move |()| {
                    processing.store(true, Ordering::Release);
                    gate.wait();
                }
            })
            .unwrap(),
        );
        worker.try_submit(()).unwrap();
        wait_until(|| processing.load(Ordering::Acquire));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let result = tokio::time::timeout(Duration::from_millis(10), worker.shutdown()).await;
            assert!(result.is_err());
        });
        drop(runtime);

        gate.wait();
        wait_until(|| worker.completion.complete.load(Ordering::Acquire));
        let join = lock(&worker.join)
            .take()
            .expect("worker join remains owned");
        join.join().unwrap();
    }
}
