use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use access_async_contracts::{AccessCancellation, BoxAccessFuture};
use access_tls_trust::{
    PreparedTlsTrustCandidate, TlsClientTrustMode, TlsClientTrustPlan, TlsTrustFileSource,
    TlsTrustGeneration, TlsTrustLoadLimits, TlsTrustLoadWorkspace, TlsTrustRevalidationProgress,
};
use tokio::runtime::Handle;
use tokio::sync::{oneshot, watch, Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::runtime::ActivationCancellation;
use crate::tls::TlsActivationError;

pub(crate) const TLS_TRUST_OVERLAP_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TRUST_DESCRIPTORS: u64 = 520;
const MAX_LIVE_TRUST_GENERATIONS: usize = 8;
const OPERATION_DEADLINE: Duration = Duration::from_secs(30);
const CANDIDATE_BASE_DEADLINE: Duration = Duration::from_secs(60);
const CANDIDATE_MAX_DEADLINE: Duration = Duration::from_secs(180);
const CANDIDATE_PER_SOURCE_DEADLINE: Duration = Duration::from_millis(250);
const WORKER_STACK_BYTES: usize = 1024 * 1024;

/// Process-owned admission, retention accounting, and supervision for TLS trust.
pub(crate) struct TlsIoRuntime {
    accepting: AtomicBool,
    capacity: Arc<Semaphore>,
    active: AtomicUsize,
    changed: Notify,
    shutdown: watch::Sender<bool>,
    workers: Mutex<Vec<std::thread::JoinHandle<()>>>,
    retained: StdMutex<RetainedTrustState>,
    retention_changed: Notify,
    deadlines: TlsIoDeadlines,
    system_provider: Arc<dyn SystemTrustProvider>,
    custom_provider: Arc<dyn CustomTrustProvider>,
    custom_acquisitions: Arc<AtomicUsize>,
    #[cfg(test)]
    fail_next_spawn: AtomicBool,
}

trait SystemTrustProvider: Send + Sync {
    fn load(
        &self,
        workspace: &mut TlsTrustLoadWorkspace,
        cancellation: &dyn AccessCancellation,
    ) -> Result<(), TlsActivationError>;
}

struct NativeSystemTrustProvider;
struct NativeCustomTrustProvider;

#[cfg(test)]
struct FixedSystemTrustProvider(TlsActivationError);

#[cfg(test)]
impl SystemTrustProvider for FixedSystemTrustProvider {
    fn load(
        &self,
        _workspace: &mut TlsTrustLoadWorkspace,
        _cancellation: &dyn AccessCancellation,
    ) -> Result<(), TlsActivationError> {
        Err(self.0)
    }
}

impl SystemTrustProvider for NativeSystemTrustProvider {
    fn load(
        &self,
        workspace: &mut TlsTrustLoadWorkspace,
        cancellation: &dyn AccessCancellation,
    ) -> Result<(), TlsActivationError> {
        workspace
            .load_system(cancellation)
            .map_err(TlsActivationError::from)
    }
}

trait CustomTrustProvider: Send + Sync {
    fn load(
        &self,
        workspace: &mut TlsTrustLoadWorkspace,
        source: &TlsTrustFileSource,
        cancellation: &dyn AccessCancellation,
    ) -> Result<(), TlsActivationError>;
}

impl CustomTrustProvider for NativeCustomTrustProvider {
    fn load(
        &self,
        workspace: &mut TlsTrustLoadWorkspace,
        source: &TlsTrustFileSource,
        cancellation: &dyn AccessCancellation,
    ) -> Result<(), TlsActivationError> {
        workspace
            .load_custom(source, cancellation)
            .map_err(TlsActivationError::from)
    }
}

#[derive(Clone, Copy)]
struct TlsIoDeadlines {
    operation: Duration,
    candidate_base: Duration,
    candidate_max: Duration,
    candidate_per_source: Duration,
}

impl Default for TlsIoDeadlines {
    fn default() -> Self {
        Self {
            operation: OPERATION_DEADLINE,
            candidate_base: CANDIDATE_BASE_DEADLINE,
            candidate_max: CANDIDATE_MAX_DEADLINE,
            candidate_per_source: CANDIDATE_PER_SOURCE_DEADLINE,
        }
    }
}

#[derive(Default)]
struct RetainedTrustState {
    bytes: u64,
    generations: usize,
}

pub(crate) struct TlsTrustRetentionLease {
    runtime: Weak<TlsIoRuntime>,
    bytes: u64,
    released: bool,
}

impl fmt::Debug for TlsTrustRetentionLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsTrustRetentionLease")
            .field("bytes", &self.bytes)
            .field("released", &self.released)
            .finish_non_exhaustive()
    }
}

impl Drop for TlsTrustRetentionLease {
    fn drop(&mut self) {
        self.release();
    }
}

impl TlsTrustRetentionLease {
    fn release(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        let mut retained = runtime
            .retained
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        retained.bytes = retained
            .bytes
            .checked_sub(self.bytes)
            .expect("TLS trust retained-byte accounting underflow");
        retained.generations = retained
            .generations
            .checked_sub(1)
            .expect("TLS trust generation accounting underflow");
        drop(retained);
        runtime.retention_changed.notify_waiters();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum TlsIoRuntimeError {
    #[error("Tokio runtime is unavailable for TLS I/O supervision")]
    RuntimeUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TlsIoShutdownOutcome {
    Drained,
    DeadlineExceeded { detached_operations: usize },
}

pub(crate) struct TlsTrustPreflightFailure {
    source_index: Option<usize>,
    error: TlsActivationError,
}

impl TlsTrustPreflightFailure {
    pub(crate) fn source_index(&self) -> Option<usize> {
        self.source_index
    }

    pub(crate) fn error(&self) -> TlsActivationError {
        self.error
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(source_index: Option<usize>, error: TlsActivationError) -> Self {
        Self {
            source_index,
            error,
        }
    }
}

struct WorkerCancellation {
    cancelled: Arc<AtomicBool>,
}

impl AccessCancellation for WorkerCancellation {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn cancelled(&self) -> BoxAccessFuture<'_, ()> {
        if self.is_cancelled() {
            Box::pin(std::future::ready(()))
        } else {
            Box::pin(std::future::pending())
        }
    }
}

struct OperationCancellation {
    cancelled: Arc<AtomicBool>,
}

impl Drop for OperationCancellation {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

impl TlsIoRuntime {
    pub(crate) fn new() -> Result<Arc<Self>, TlsIoRuntimeError> {
        Self::new_with_parts(
            TlsIoDeadlines::default(),
            Arc::new(NativeSystemTrustProvider),
            Arc::new(NativeCustomTrustProvider),
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_system_failure_for_test(
        error: TlsActivationError,
    ) -> Result<Arc<Self>, TlsIoRuntimeError> {
        Self::new_with_parts(
            TlsIoDeadlines::default(),
            Arc::new(FixedSystemTrustProvider(error)),
            Arc::new(NativeCustomTrustProvider),
        )
    }

    fn new_with_parts(
        deadlines: TlsIoDeadlines,
        system_provider: Arc<dyn SystemTrustProvider>,
        custom_provider: Arc<dyn CustomTrustProvider>,
    ) -> Result<Arc<Self>, TlsIoRuntimeError> {
        Handle::try_current().map_err(|_| TlsIoRuntimeError::RuntimeUnavailable)?;
        let (shutdown, _) = watch::channel(false);
        Ok(Arc::new(Self {
            accepting: AtomicBool::new(true),
            capacity: Arc::new(Semaphore::new(1)),
            active: AtomicUsize::new(0),
            changed: Notify::new(),
            shutdown,
            workers: Mutex::new(Vec::new()),
            retained: StdMutex::new(RetainedTrustState::default()),
            retention_changed: Notify::new(),
            deadlines,
            system_provider,
            custom_provider,
            custom_acquisitions: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            fail_next_spawn: AtomicBool::new(false),
        }))
    }

    pub(crate) async fn prepare_candidate(
        self: &Arc<Self>,
        generation: TlsTrustGeneration,
        plans: Vec<TlsClientTrustPlan>,
        sources: Vec<TlsTrustFileSource>,
        cancellation: &ActivationCancellation,
    ) -> Result<(PreparedTlsTrustCandidate, TlsTrustRetentionLease), TlsActivationError> {
        if cancellation.is_cancelled() {
            return Err(TlsActivationError::ActivationCancelled);
        }
        if !self.accepting.load(Ordering::Acquire) {
            return Err(TlsActivationError::LoaderUnavailable);
        }
        let permit = Arc::clone(&self.capacity)
            .try_acquire_owned()
            .map_err(|_| TlsActivationError::ReloadBlocked)?;
        let candidate_deadline = Instant::now() + self.candidate_deadline(sources.len());
        let remaining_overlap = self.remaining_overlap_budget()?;
        let limits = Self::absolute_workspace_limits();
        let system_required = plans.iter().any(|plan| {
            matches!(
                plan.mode(),
                TlsClientTrustMode::System | TlsClientTrustMode::SystemPlusCustom
            )
        });
        let mut workspace = TlsTrustLoadWorkspace::new(generation, plans, limits)
            .map_err(TlsActivationError::from)?;
        Self::check_overlap_projection(workspace.working_bytes(), remaining_overlap)?;
        let mut permit = permit;

        if system_required {
            Self::check_overlap_projection(
                workspace
                    .next_system_working_bytes()
                    .map_err(TlsActivationError::from)?,
                remaining_overlap,
            )?;
            let system_provider = Arc::clone(&self.system_provider);
            (workspace, permit) = self
                .run_operation(
                    workspace,
                    permit,
                    candidate_deadline,
                    cancellation,
                    move |mut workspace, cancellation| {
                        system_provider.load(&mut workspace, cancellation)?;
                        Ok(workspace)
                    },
                )
                .await?;
        }
        for source in sources {
            Self::check_overlap_projection(
                workspace
                    .next_custom_working_bytes(&source)
                    .map_err(TlsActivationError::from)?,
                remaining_overlap,
            )?;
            let custom_acquisitions = Arc::clone(&self.custom_acquisitions);
            let custom_provider = Arc::clone(&self.custom_provider);
            (workspace, permit) = self
                .run_operation(
                    workspace,
                    permit,
                    candidate_deadline,
                    cancellation,
                    move |mut workspace, cancellation| {
                        custom_acquisitions.fetch_add(1, Ordering::AcqRel);
                        custom_provider.load(&mut workspace, &source, cancellation)?;
                        Ok(workspace)
                    },
                )
                .await?;
        }
        loop {
            let (next_workspace, next_permit, progress) = self
                .run_operation(
                    workspace,
                    permit,
                    candidate_deadline,
                    cancellation,
                    |mut workspace, cancellation| {
                        let progress = workspace
                            .revalidate_next(cancellation)
                            .map_err(TlsActivationError::from)?;
                        Ok((workspace, progress))
                    },
                )
                .await
                .map(|((workspace, progress), permit)| (workspace, permit, progress))?;
            workspace = next_workspace;
            permit = next_permit;
            if progress == TlsTrustRevalidationProgress::Complete {
                break;
            }
        }
        if cancellation.is_cancelled() || Instant::now() >= candidate_deadline {
            return Err(TlsActivationError::ActivationCancelled);
        }
        let candidate = workspace.finalize().map_err(TlsActivationError::from)?;
        let retention =
            self.reserve_generation(candidate.resource_projection().retained_bytes())?;
        drop(permit);
        self.reap_finished_workers().await;
        Ok((candidate, retention))
    }

    pub(crate) async fn preflight_custom_sources(
        self: &Arc<Self>,
        paths: Vec<std::path::PathBuf>,
        cancellation: &ActivationCancellation,
    ) -> Result<(), TlsTrustPreflightFailure> {
        if cancellation.is_cancelled() {
            return Err(TlsTrustPreflightFailure {
                source_index: None,
                error: TlsActivationError::ActivationCancelled,
            });
        }
        if !self.accepting.load(Ordering::Acquire) {
            return Err(TlsTrustPreflightFailure {
                source_index: None,
                error: TlsActivationError::LoaderUnavailable,
            });
        }
        let mut seen_paths = std::collections::BTreeSet::new();
        let paths = paths
            .into_iter()
            .enumerate()
            .filter_map(|(source_index, path)| {
                seen_paths
                    .insert(path.clone())
                    .then_some((source_index, path))
            })
            .collect::<Vec<_>>();
        if paths.is_empty() {
            return Ok(());
        }
        let paths_len = paths.len();
        let permit = Arc::clone(&self.capacity)
            .try_acquire_owned()
            .map_err(|_| TlsTrustPreflightFailure {
                source_index: None,
                error: TlsActivationError::ReloadBlocked,
            })?;
        let candidate_deadline = Instant::now() + self.candidate_deadline(paths.len());
        let remaining_overlap =
            self.remaining_overlap_budget()
                .map_err(|error| TlsTrustPreflightFailure {
                    source_index: None,
                    error,
                })?;
        let limits = Self::absolute_workspace_limits();
        let mut plans = Vec::with_capacity(paths.len());
        let mut sources = Vec::with_capacity(paths.len());
        for (source_index, path) in paths {
            let source =
                TlsTrustFileSource::new(path).map_err(|error| TlsTrustPreflightFailure {
                    source_index: Some(source_index),
                    error: error.into(),
                })?;
            plans.push(
                TlsClientTrustPlan::new(
                    TlsClientTrustMode::Custom,
                    Some(source.authored_source_id()),
                )
                .map_err(|error| TlsTrustPreflightFailure {
                    source_index: Some(source_index),
                    error: error.into(),
                })?,
            );
            sources.push((source_index, source));
        }
        let generation = TlsTrustGeneration::new(1).map_err(|error| TlsTrustPreflightFailure {
            source_index: None,
            error: error.into(),
        })?;
        let mut workspace =
            TlsTrustLoadWorkspace::new(generation, plans, limits).map_err(|error| {
                TlsTrustPreflightFailure {
                    source_index: None,
                    error: error.into(),
                }
            })?;
        Self::check_overlap_projection(workspace.working_bytes(), remaining_overlap).map_err(
            |error| TlsTrustPreflightFailure {
                source_index: None,
                error,
            },
        )?;
        let mut permit = permit;
        let source_indices = sources
            .iter()
            .map(|(source_index, _)| *source_index)
            .collect::<Vec<_>>();
        for (source_index, source) in sources {
            Self::check_overlap_projection(
                workspace
                    .next_custom_working_bytes(&source)
                    .map_err(TlsActivationError::from)
                    .map_err(|error| TlsTrustPreflightFailure {
                        source_index: Some(source_index),
                        error,
                    })?,
                remaining_overlap,
            )
            .map_err(|error| TlsTrustPreflightFailure {
                source_index: Some(source_index),
                error,
            })?;
            let custom_acquisitions = Arc::clone(&self.custom_acquisitions);
            let custom_provider = Arc::clone(&self.custom_provider);
            (workspace, permit) = self
                .run_operation(
                    workspace,
                    permit,
                    candidate_deadline,
                    cancellation,
                    move |mut workspace, cancellation| {
                        custom_acquisitions.fetch_add(1, Ordering::AcqRel);
                        custom_provider.load(&mut workspace, &source, cancellation)?;
                        Ok(workspace)
                    },
                )
                .await
                .map_err(|error| TlsTrustPreflightFailure {
                    source_index: Some(source_index),
                    error,
                })?;
        }
        for (position, source_index) in source_indices.into_iter().enumerate() {
            let (next_workspace, next_permit, progress) = self
                .run_operation(
                    workspace,
                    permit,
                    candidate_deadline,
                    cancellation,
                    |mut workspace, cancellation| {
                        let progress = workspace
                            .revalidate_next(cancellation)
                            .map_err(TlsActivationError::from)?;
                        Ok((workspace, progress))
                    },
                )
                .await
                .map(|((workspace, progress), permit)| (workspace, permit, progress))
                .map_err(|error| TlsTrustPreflightFailure {
                    source_index: Some(source_index),
                    error,
                })?;
            workspace = next_workspace;
            permit = next_permit;
            let expected = if position + 1 == paths_len {
                TlsTrustRevalidationProgress::Complete
            } else {
                TlsTrustRevalidationProgress::Pending {
                    remaining: paths_len - position - 1,
                }
            };
            if progress != expected {
                return Err(TlsTrustPreflightFailure {
                    source_index: Some(source_index),
                    error: TlsActivationError::Internal,
                });
            }
        }
        drop(workspace);
        drop(permit);
        self.reap_finished_workers().await;
        Ok(())
    }

    async fn run_operation<Input, Output>(
        self: &Arc<Self>,
        input: Input,
        permit: OwnedSemaphorePermit,
        candidate_deadline: Instant,
        cancellation: &ActivationCancellation,
        operation: impl FnOnce(Input, &dyn AccessCancellation) -> Result<Output, TlsActivationError>
            + Send
            + 'static,
    ) -> Result<(Output, OwnedSemaphorePermit), TlsActivationError>
    where
        Input: Send + 'static,
        Output: Send + 'static,
    {
        if cancellation.is_cancelled()
            || !self.accepting.load(Ordering::Acquire)
            || Instant::now() >= candidate_deadline
        {
            return Err(TlsActivationError::ActivationCancelled);
        }
        let operation_deadline =
            (Instant::now() + self.deadlines.operation).min(candidate_deadline);
        let (result_tx, result_rx) = oneshot::channel();
        let worker_cancelled = Arc::new(AtomicBool::new(false));
        let operation_cancellation = OperationCancellation {
            cancelled: Arc::clone(&worker_cancelled),
        };
        self.active.fetch_add(1, Ordering::AcqRel);
        #[cfg(test)]
        if self.fail_next_spawn.swap(false, Ordering::AcqRel) {
            self.active.fetch_sub(1, Ordering::AcqRel);
            self.changed.notify_waiters();
            return Err(TlsActivationError::Internal);
        }
        let runtime = Arc::clone(self);
        let worker = std::thread::Builder::new()
            .name("tls-trust-io".to_owned())
            .stack_size(WORKER_STACK_BYTES)
            .spawn(move || {
                let cancellation = WorkerCancellation {
                    cancelled: worker_cancelled,
                };
                let outcome = catch_unwind(AssertUnwindSafe(|| operation(input, &cancellation)))
                    .unwrap_or(Err(TlsActivationError::Internal))
                    .map(|output| (output, permit));
                let _ = result_tx.send(outcome);
                runtime.active.fetch_sub(1, Ordering::AcqRel);
                runtime.changed.notify_waiters();
            })
            .map_err(|_| {
                self.active.fetch_sub(1, Ordering::AcqRel);
                self.changed.notify_waiters();
                TlsActivationError::Internal
            })?;
        self.workers.lock().await.push(worker);

        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(TlsActivationError::ActivationCancelled),
            _ = self.shutdown_signal() => Err(TlsActivationError::ActivationCancelled),
            _ = tokio::time::sleep_until(operation_deadline) => {
                Err(TlsActivationError::ActivationCancelled)
            }
            result = result_rx => result.unwrap_or(Err(TlsActivationError::Internal)),
        };
        drop(operation_cancellation);
        self.reap_finished_workers().await;
        result
    }

    fn remaining_overlap_budget(&self) -> Result<u64, TlsActivationError> {
        let retained = self
            .retained
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if retained.generations >= MAX_LIVE_TRUST_GENERATIONS {
            return Err(TlsActivationError::TrustGenerationLimit);
        }
        TLS_TRUST_OVERLAP_BYTES
            .checked_sub(retained.bytes)
            .ok_or(TlsActivationError::TrustGenerationLimit)
    }

    fn absolute_workspace_limits() -> TlsTrustLoadLimits {
        TlsTrustLoadLimits::new(TLS_TRUST_OVERLAP_BYTES, MAX_TRUST_DESCRIPTORS)
            .expect("process TLS trust workspace ceiling is valid")
    }

    fn check_overlap_projection(
        projected: u64,
        remaining_overlap: u64,
    ) -> Result<(), TlsActivationError> {
        if projected > remaining_overlap {
            Err(TlsActivationError::TrustGenerationLimit)
        } else {
            Ok(())
        }
    }

    fn reserve_generation(
        self: &Arc<Self>,
        bytes: u64,
    ) -> Result<TlsTrustRetentionLease, TlsActivationError> {
        let mut retained = self
            .retained
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let next_generations = retained
            .generations
            .checked_add(1)
            .ok_or(TlsActivationError::TrustGenerationLimit)?;
        let next_bytes = retained
            .bytes
            .checked_add(bytes)
            .ok_or(TlsActivationError::TrustGenerationLimit)?;
        if next_generations > MAX_LIVE_TRUST_GENERATIONS || next_bytes > TLS_TRUST_OVERLAP_BYTES {
            return Err(TlsActivationError::TrustGenerationLimit);
        }
        retained.generations = next_generations;
        retained.bytes = next_bytes;
        Ok(TlsTrustRetentionLease {
            runtime: Arc::downgrade(self),
            bytes,
            released: false,
        })
    }

    fn candidate_deadline(&self, distinct_sources: usize) -> Duration {
        self.deadlines
            .candidate_base
            .checked_add(
                self.deadlines
                    .candidate_per_source
                    .checked_mul(u32::try_from(distinct_sources).unwrap_or(u32::MAX))
                    .unwrap_or(self.deadlines.candidate_max),
            )
            .unwrap_or(self.deadlines.candidate_max)
            .min(self.deadlines.candidate_max)
    }

    pub(crate) fn begin_shutdown(&self) {
        self.accepting.store(false, Ordering::Release);
        self.shutdown.send_replace(true);
    }

    pub(crate) async fn shutdown_and_wait(
        &self,
        deadline: Option<Instant>,
    ) -> TlsIoShutdownOutcome {
        self.begin_shutdown();
        loop {
            self.reap_finished_workers().await;
            let active = self.active.load(Ordering::Acquire);
            if active == 0 {
                return TlsIoShutdownOutcome::Drained;
            }
            let changed = self.changed.notified();
            match deadline {
                Some(deadline) => {
                    tokio::select! {
                        _ = tokio::time::sleep_until(deadline) => {
                            return TlsIoShutdownOutcome::DeadlineExceeded {
                                detached_operations: self.active.load(Ordering::Acquire),
                            };
                        }
                        () = changed => {}
                    }
                }
                None => changed.await,
            }
        }
    }

    async fn reap_finished_workers(&self) {
        let mut workers = self.workers.lock().await;
        let mut pending = Vec::with_capacity(workers.len());
        for worker in workers.drain(..) {
            if worker.is_finished() {
                let _ = worker.join();
            } else {
                pending.push(worker);
            }
        }
        *workers = pending;
    }

    async fn shutdown_signal(&self) {
        let mut shutdown = self.shutdown.subscribe();
        if *shutdown.borrow() {
            return;
        }
        let _ = shutdown.changed().await;
    }

    #[cfg(test)]
    pub(crate) async fn run_for_test(
        self: &Arc<Self>,
        job: impl FnOnce(&dyn AccessCancellation) -> Result<Vec<Vec<u8>>, TlsActivationError>
            + Send
            + 'static,
    ) -> Result<Vec<Vec<u8>>, TlsActivationError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(TlsActivationError::LoaderUnavailable);
        }
        let permit = Arc::clone(&self.capacity)
            .try_acquire_owned()
            .map_err(|_| TlsActivationError::ReloadBlocked)?;
        let candidate_deadline = Instant::now() + self.deadlines.candidate_max;
        self.run_operation(
            (),
            permit,
            candidate_deadline,
            &ActivationCancellation::new_for_test(),
            move |(), cancellation| job(cancellation),
        )
        .await
        .map(|(result, _)| result)
    }

    #[cfg(test)]
    pub(crate) fn retained_for_test(&self) -> (u64, usize) {
        let retained = self
            .retained
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (retained.bytes, retained.generations)
    }

    #[cfg(test)]
    pub(crate) fn custom_acquisitions_for_test(&self) -> usize {
        self.custom_acquisitions.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn fail_next_spawn_for_test(&self) {
        self.fail_next_spawn.store(true, Ordering::Release);
    }
}

impl Drop for TlsIoRuntime {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Condvar, Mutex as StdMutex};

    use tempfile::TempDir;

    use super::*;
    use crate::test_certificates::TestTlsIdentity;

    struct FailingSystemTrustProvider {
        calls: Arc<AtomicUsize>,
    }

    struct BlockingCustomState {
        entered: AtomicBool,
        observed_cancellation: AtomicBool,
        released: StdMutex<bool>,
        changed: Condvar,
    }

    struct BlockingCustomTrustProvider {
        state: Arc<BlockingCustomState>,
    }

    impl SystemTrustProvider for FailingSystemTrustProvider {
        fn load(
            &self,
            _workspace: &mut TlsTrustLoadWorkspace,
            _cancellation: &dyn AccessCancellation,
        ) -> Result<(), TlsActivationError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Err(TlsActivationError::SystemStoreUnavailable)
        }
    }

    impl CustomTrustProvider for BlockingCustomTrustProvider {
        fn load(
            &self,
            _workspace: &mut TlsTrustLoadWorkspace,
            _source: &TlsTrustFileSource,
            cancellation: &dyn AccessCancellation,
        ) -> Result<(), TlsActivationError> {
            self.state.entered.store(true, Ordering::Release);
            self.state.changed.notify_all();
            let mut released = self.state.released.lock().unwrap();
            while !*released {
                if cancellation.is_cancelled() {
                    self.state
                        .observed_cancellation
                        .store(true, Ordering::Release);
                }
                let (next, _) = self
                    .state
                    .changed
                    .wait_timeout(released, Duration::from_millis(1))
                    .unwrap();
                released = next;
            }
            Err(TlsActivationError::ActivationCancelled)
        }
    }

    fn secure_tempdir() -> TempDir {
        let base = PathBuf::from(std::env::var_os("HOME").expect("HOME is set"))
            .join(".cache/acl-proxy-test-fixtures");
        std::fs::create_dir_all(&base).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(
            &base,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        let directory = tempfile::Builder::new()
            .prefix("tls-io-runtime-")
            .tempdir_in(base)
            .unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(
            directory.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        directory
    }

    fn test_runtime(operation: Duration, candidate: Duration) -> Arc<TlsIoRuntime> {
        TlsIoRuntime::new_with_parts(
            TlsIoDeadlines {
                operation,
                candidate_base: candidate,
                candidate_max: candidate,
                candidate_per_source: Duration::ZERO,
            },
            Arc::new(NativeSystemTrustProvider),
            Arc::new(NativeCustomTrustProvider),
        )
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn worker_panic_and_spawn_failure_are_internal_while_shutdown_is_unavailable() {
        let panic_runtime = test_runtime(Duration::from_secs(1), Duration::from_secs(1));
        assert_eq!(
            panic_runtime
                .run_for_test(|_| panic!("injected TLS trust worker panic"))
                .await,
            Err(TlsActivationError::Internal)
        );
        assert_eq!(panic_runtime.active.load(Ordering::Acquire), 0);
        assert!(
            panic_runtime.run_for_test(|_| Ok(Vec::new())).await.is_ok(),
            "a contained worker panic must release admission"
        );

        let spawn_runtime = test_runtime(Duration::from_secs(1), Duration::from_secs(1));
        spawn_runtime.fail_next_spawn_for_test();
        assert_eq!(
            spawn_runtime.run_for_test(|_| Ok(Vec::new())).await,
            Err(TlsActivationError::Internal)
        );
        assert_eq!(spawn_runtime.active.load(Ordering::Acquire), 0);
        assert!(
            spawn_runtime.run_for_test(|_| Ok(Vec::new())).await.is_ok(),
            "a thread-spawn failure must release admission"
        );

        let shutdown_runtime = test_runtime(Duration::from_secs(1), Duration::from_secs(1));
        shutdown_runtime.begin_shutdown();
        assert_eq!(
            shutdown_runtime.run_for_test(|_| Ok(Vec::new())).await,
            Err(TlsActivationError::LoaderUnavailable)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn operation_timeout_blocks_reload_until_late_worker_exits_then_recovers() {
        let runtime = test_runtime(Duration::from_millis(20), Duration::from_secs(1));
        let gate = Arc::new((StdMutex::new(false), Condvar::new()));
        let worker_gate = Arc::clone(&gate);
        let operation_runtime = Arc::clone(&runtime);
        let operation = tokio::spawn(async move {
            operation_runtime
                .run_for_test(move |_| {
                    let (open, changed) = &*worker_gate;
                    let mut open = open.lock().unwrap();
                    while !*open {
                        open = changed.wait(open).unwrap();
                    }
                    Ok(Vec::new())
                })
                .await
        });
        assert_eq!(
            operation.await.unwrap(),
            Err(TlsActivationError::ActivationCancelled)
        );
        assert_eq!(
            runtime.run_for_test(|_| Ok(Vec::new())).await,
            Err(TlsActivationError::ReloadBlocked)
        );
        assert_eq!(
            TlsActivationError::ReloadBlocked.to_string(),
            "TLS trust reload is blocked by a late operation"
        );
        let (open, changed) = &*gate;
        *open.lock().unwrap() = true;
        changed.notify_all();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if runtime.run_for_test(|_| Ok(Vec::new())).await.is_ok() {
                    break;
                }
                runtime.changed.notified().await;
            }
        })
        .await
        .expect("late operation did not release reload admission");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn operation_timeout_reaches_blocking_loader_cancellation_checkpoints() {
        let runtime = test_runtime(Duration::from_millis(20), Duration::from_secs(1));
        let (observed_tx, observed_rx) = oneshot::channel();
        let operation_runtime = Arc::clone(&runtime);
        let operation = tokio::spawn(async move {
            operation_runtime
                .run_for_test(move |cancellation| {
                    while !cancellation.is_cancelled() {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    let _ = observed_tx.send(());
                    Err(TlsActivationError::ActivationCancelled)
                })
                .await
        });
        assert_eq!(
            operation.await.unwrap(),
            Err(TlsActivationError::ActivationCancelled)
        );
        tokio::time::timeout(Duration::from_secs(1), observed_rx)
            .await
            .expect("blocking loader did not observe operation cancellation")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while runtime.active.load(Ordering::Acquire) != 0 {
                runtime.changed.notified().await;
            }
        })
        .await
        .expect("cancelled operation did not terminate");
        assert!(runtime.run_for_test(|_| Ok(Vec::new())).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn candidate_deadline_bounds_a_sequence_of_individually_fast_operations() {
        let runtime = test_runtime(Duration::from_secs(1), Duration::from_millis(45));
        let permit = Arc::clone(&runtime.capacity).try_acquire_owned().unwrap();
        let candidate_deadline = Instant::now() + Duration::from_millis(45);
        let cancellation = ActivationCancellation::new_for_test();
        let ((), permit) = runtime
            .run_operation((), permit, candidate_deadline, &cancellation, |(), _| {
                std::thread::sleep(Duration::from_millis(30));
                Ok(())
            })
            .await
            .unwrap();
        let result = runtime
            .run_operation((), permit, candidate_deadline, &cancellation, |(), _| {
                std::thread::sleep(Duration::from_millis(30));
                Ok(())
            })
            .await;
        assert!(matches!(
            result,
            Err(TlsActivationError::ActivationCancelled)
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while runtime.active.load(Ordering::Acquire) != 0 {
                runtime.changed.notified().await;
            }
        })
        .await
        .expect("candidate-deadline operation did not terminate");
    }

    #[tokio::test]
    async fn retained_overlap_and_generation_boundaries_release_exactly() {
        let runtime = test_runtime(Duration::from_secs(1), Duration::from_secs(1));
        let exact = runtime
            .reserve_generation(TLS_TRUST_OVERLAP_BYTES)
            .expect("exact byte boundary is accepted");
        assert_eq!(
            runtime.reserve_generation(1).unwrap_err(),
            TlsActivationError::TrustGenerationLimit
        );
        assert_eq!(runtime.retained_for_test(), (TLS_TRUST_OVERLAP_BYTES, 1));
        drop(exact);
        assert_eq!(runtime.retained_for_test(), (0, 0));

        let mut leases = Vec::new();
        for _ in 0..MAX_LIVE_TRUST_GENERATIONS {
            leases.push(runtime.reserve_generation(0).unwrap());
        }
        assert_eq!(
            runtime.reserve_generation(0).unwrap_err(),
            TlsActivationError::TrustGenerationLimit
        );
        leases.pop();
        assert!(runtime.reserve_generation(0).is_ok());
    }

    #[tokio::test]
    async fn retained_bytes_reduce_candidate_workspace_and_recover_on_retirement() {
        let runtime = test_runtime(Duration::from_secs(1), Duration::from_secs(1));
        let plan = TlsClientTrustPlan::new(TlsClientTrustMode::Insecure, None).unwrap();
        let required = TlsTrustLoadWorkspace::new(
            TlsTrustGeneration::new(1).unwrap(),
            [plan],
            TlsIoRuntime::absolute_workspace_limits(),
        )
        .unwrap()
        .working_bytes();
        let exact = runtime
            .reserve_generation(TLS_TRUST_OVERLAP_BYTES - required)
            .unwrap();
        let (_, candidate) = runtime
            .prepare_candidate(
                TlsTrustGeneration::new(2).unwrap(),
                vec![plan],
                Vec::new(),
                &ActivationCancellation::new_for_test(),
            )
            .await
            .expect("exact remaining overlap boundary is accepted");
        drop(candidate);
        drop(exact);

        let retained = runtime
            .reserve_generation(TLS_TRUST_OVERLAP_BYTES - required + 1)
            .unwrap();
        assert_eq!(
            runtime
                .prepare_candidate(
                    TlsTrustGeneration::new(3).unwrap(),
                    vec![plan],
                    Vec::new(),
                    &ActivationCancellation::new_for_test(),
                )
                .await
                .unwrap_err(),
            TlsActivationError::TrustGenerationLimit
        );
        drop(retained);
        assert_eq!(
            runtime.remaining_overlap_budget().unwrap(),
            TLS_TRUST_OVERLAP_BYTES
        );
    }

    #[tokio::test]
    async fn oversized_custom_material_remains_a_source_resource_limit() {
        let runtime = test_runtime(Duration::from_secs(1), Duration::from_secs(1));
        let directory = secure_tempdir();
        let path = directory.path().join("oversized.pem");
        crate::filesystem::write_public_file(&path, vec![b'x'; 3 * 1024 * 1024]).unwrap();
        let source = TlsTrustFileSource::new(path).unwrap();
        let plan = TlsClientTrustPlan::new(
            TlsClientTrustMode::Custom,
            Some(source.authored_source_id()),
        )
        .unwrap();
        assert_eq!(
            runtime
                .prepare_candidate(
                    TlsTrustGeneration::new(1).unwrap(),
                    vec![plan],
                    vec![source],
                    &ActivationCancellation::new_for_test(),
                )
                .await
                .unwrap_err(),
            TlsActivationError::ResourceLimit
        );
    }

    #[tokio::test]
    async fn all_custom_and_all_insecure_candidates_skip_the_system_provider() {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(FailingSystemTrustProvider {
            calls: Arc::clone(&calls),
        });
        let runtime = TlsIoRuntime::new_with_parts(
            TlsIoDeadlines::default(),
            provider,
            Arc::new(NativeCustomTrustProvider),
        )
        .unwrap();
        let directory = secure_tempdir();
        let path = directory.path().join("ca.pem");
        crate::filesystem::write_public_file(
            &path,
            TestTlsIdentity::new("custom-only.test").root_certificate_pem(),
        )
        .unwrap();
        let source = TlsTrustFileSource::new(path).unwrap();
        let custom = TlsClientTrustPlan::new(
            TlsClientTrustMode::Custom,
            Some(source.authored_source_id()),
        )
        .unwrap();
        let cancellation = ActivationCancellation::new_for_test();
        let (_, custom_lease) = runtime
            .prepare_candidate(
                TlsTrustGeneration::new(1).unwrap(),
                vec![custom],
                vec![source],
                &cancellation,
            )
            .await
            .unwrap();
        drop(custom_lease);

        let insecure = TlsClientTrustPlan::new(TlsClientTrustMode::Insecure, None).unwrap();
        let (_, insecure_lease) = runtime
            .prepare_candidate(
                TlsTrustGeneration::new(2).unwrap(),
                vec![insecure],
                Vec::new(),
                &cancellation,
            )
            .await
            .unwrap();
        drop(insecure_lease);
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn system_candidate_uses_the_injected_system_provider() {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(FailingSystemTrustProvider {
            calls: Arc::clone(&calls),
        });
        let runtime = TlsIoRuntime::new_with_parts(
            TlsIoDeadlines::default(),
            provider,
            Arc::new(NativeCustomTrustProvider),
        )
        .unwrap();
        let system = TlsClientTrustPlan::new(TlsClientTrustMode::System, None).unwrap();
        assert_eq!(
            runtime
                .prepare_candidate(
                    TlsTrustGeneration::new(1).unwrap(),
                    vec![system],
                    Vec::new(),
                    &ActivationCancellation::new_for_test(),
                )
                .await
                .unwrap_err(),
            TlsActivationError::SystemStoreUnavailable
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_preflight_retains_admission_until_late_worker_exits() {
        let state = Arc::new(BlockingCustomState {
            entered: AtomicBool::new(false),
            observed_cancellation: AtomicBool::new(false),
            released: StdMutex::new(false),
            changed: Condvar::new(),
        });
        let runtime = TlsIoRuntime::new_with_parts(
            TlsIoDeadlines {
                operation: Duration::from_secs(1),
                candidate_base: Duration::from_secs(2),
                candidate_max: Duration::from_secs(2),
                candidate_per_source: Duration::ZERO,
            },
            Arc::new(NativeSystemTrustProvider),
            Arc::new(BlockingCustomTrustProvider {
                state: Arc::clone(&state),
            }),
        )
        .unwrap();
        let directory = secure_tempdir();
        let path = directory.path().join("ca.pem");
        crate::filesystem::write_public_file(
            &path,
            TestTlsIdentity::new("blocked-preflight.test").root_certificate_pem(),
        )
        .unwrap();
        let cancellation = ActivationCancellation::new_for_test();
        let task_runtime = Arc::clone(&runtime);
        let task_cancellation = cancellation.clone();
        let preflight = tokio::spawn(async move {
            task_runtime
                .preflight_custom_sources(vec![path], &task_cancellation)
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !state.entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("custom preflight provider did not start");

        cancellation.cancel_for_test();
        let Err(failure) = tokio::time::timeout(Duration::from_millis(200), preflight)
            .await
            .expect("cancelled preflight did not return promptly")
            .unwrap()
        else {
            panic!("cancelled preflight must fail");
        };
        assert_eq!(failure.source_index(), Some(0));
        assert_eq!(failure.error(), TlsActivationError::ActivationCancelled);
        assert_eq!(runtime.active.load(Ordering::Acquire), 1);
        assert_eq!(runtime.custom_acquisitions_for_test(), 1);
        let Err(blocked) = runtime
            .preflight_custom_sources(
                vec![directory.path().join("ca.pem")],
                &ActivationCancellation::new_for_test(),
            )
            .await
        else {
            panic!("late worker must retain preflight admission");
        };
        assert_eq!(blocked.error(), TlsActivationError::ReloadBlocked);

        assert_eq!(
            runtime
                .shutdown_and_wait(Some(Instant::now() + Duration::from_millis(20)))
                .await,
            TlsIoShutdownOutcome::DeadlineExceeded {
                detached_operations: 1
            }
        );
        assert!(state.observed_cancellation.load(Ordering::Acquire));
        *state.released.lock().unwrap() = true;
        state.changed.notify_all();
        assert_eq!(
            runtime.shutdown_and_wait(None).await,
            TlsIoShutdownOutcome::Drained
        );
    }
}
