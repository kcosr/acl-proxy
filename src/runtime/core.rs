use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::{panic::catch_unwind, panic::AssertUnwindSafe};

use arc_swap::ArcSwapOption;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;

use crate::config::{CompiledConfig, StaticFingerprint, StaticProductConfig};

use super::activation::{
    ActivationCancellation, BoxFuture, CandidateActivator, CandidateSource, RuntimeError,
};
use super::generation::{
    ActivatedGeneration, CleanupReason, Generation, GenerationId, GenerationLease,
};
use super::readiness::ServiceReadiness;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum LifecycleState {
    Starting = 0,
    Running = 1,
    Publishing = 2,
    ShuttingDown = 3,
    Stopped = 4,
}

#[derive(Clone)]
pub(crate) struct StaticResourceBrand(Arc<()>);

impl StaticResourceBrand {
    pub(crate) fn new() -> Self {
        Self(Arc::new(()))
    }

    pub(crate) fn same_instance(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl LifecycleState {
    fn from_raw(value: u8) -> Self {
        match value {
            0 => Self::Starting,
            1 => Self::Running,
            2 => Self::Publishing,
            3 => Self::ShuttingDown,
            4 => Self::Stopped,
            _ => unreachable!("invalid runtime lifecycle state"),
        }
    }
}

pub(crate) trait StaticResources: Send + Sync {
    fn brand(&self) -> &StaticResourceBrand;

    /// Returns the readiness state owned by these exact listener resources.
    fn readiness(&self) -> &Arc<ServiceReadiness>;

    /// Synchronously and idempotently closes new product ingress and admissions
    /// for new work or dispatches before generation retirement begins. Control
    /// callback ingress needed to drain pending operations remains available.
    fn begin_shutdown(&self);

    /// Supervises static ingress and handler drain concurrently with generation
    /// retirement. It must release every request-owned generation retention and
    /// complete all task joins, but must not wait for generation-owner cleanup.
    fn shutdown(&self) -> BoxFuture<'_, ()>;
}

/// Immutable process-lifetime ownership. Deliberately has no `Debug`
/// implementation because the compiled static configuration contains paths.
pub(crate) struct StaticOwnership {
    pub(crate) config: StaticProductConfig,
    pub(crate) claimed_fingerprint: StaticFingerprint,
    pub(crate) readiness: Arc<ServiceReadiness>,
    pub(crate) resources: Arc<dyn StaticResources>,
}

impl StaticOwnership {
    pub(crate) fn new(
        config: StaticProductConfig,
        claimed_fingerprint: StaticFingerprint,
        resources: Arc<dyn StaticResources>,
    ) -> Self {
        let readiness = resources.readiness().clone();
        Self {
            config,
            claimed_fingerprint,
            readiness,
            resources,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReloadTriggerResult {
    Coalesced,
    Completed {
        attempts: usize,
        generation: GenerationId,
    },
}

pub(crate) struct Runtime {
    static_ownership: StaticOwnership,
    static_fingerprint: StaticFingerprint,
    source: Arc<dyn CandidateSource>,
    activator: Arc<dyn CandidateActivator>,
    active: ArcSwapOption<Generation>,
    lifecycle: AtomicU8,
    lifecycle_changed: Notify,
    shutdown_transition: StdMutex<()>,
    next_generation: AtomicU64,
    activation: Mutex<()>,
    pending_reload: AtomicBool,
    reload_worker_active: AtomicBool,
    current_cancellation: StdMutex<Option<ActivationCancellation>>,
    retiring_count: AtomicUsize,
    retiring_changed: Notify,
    retirement_tasks: Mutex<Vec<JoinHandle<()>>>,
    #[cfg(test)]
    reload_exit_blocked: AtomicBool,
    #[cfg(test)]
    reload_exit_entered: Notify,
    #[cfg(test)]
    reload_exit_release: Notify,
    #[cfg(test)]
    lease_acquire_blocked: AtomicBool,
    #[cfg(test)]
    lease_acquire_entered: AtomicBool,
    #[cfg(test)]
    lease_acquire_changed: Notify,
    #[cfg(test)]
    lease_acquire_release: Notify,
    #[cfg(test)]
    lease_validation_blocked: AtomicBool,
    #[cfg(test)]
    lease_validation_entered: AtomicBool,
    #[cfg(test)]
    lease_validation_changed: Notify,
    #[cfg(test)]
    lease_validation_release: Notify,
    #[cfg(test)]
    publication_exit_blocked: AtomicBool,
    #[cfg(test)]
    publication_exit_entered: AtomicBool,
    #[cfg(test)]
    publication_exit_changed: Notify,
    #[cfg(test)]
    publication_exit_release: Notify,
}

struct ReloadWorkerOwnership {
    runtime: Arc<Runtime>,
    owns: bool,
}

struct MarkedRetirement {
    generation: Arc<Generation>,
    reason: CleanupReason,
}

fn reject_runtime_construction(
    static_ownership: StaticOwnership,
    error: RuntimeError,
) -> BoxFuture<'static, Result<Arc<Runtime>, RuntimeError>> {
    static_ownership.readiness.begin_shutdown();
    static_ownership.resources.begin_shutdown();
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            let cleanup = handle.spawn(async move { static_ownership.resources.shutdown().await });
            Box::pin(async move {
                let _ = cleanup.await;
                Err(error)
            })
        }
        Err(_) => Box::pin(async move {
            static_ownership.resources.shutdown().await;
            Err(error)
        }),
    }
}

impl Drop for ReloadWorkerOwnership {
    fn drop(&mut self) {
        if self.owns {
            self.runtime.pending_reload.store(true, Ordering::Release);
            self.runtime
                .reload_worker_active
                .store(false, Ordering::Release);
        }
    }
}

impl Runtime {
    pub(crate) fn new(
        static_ownership: StaticOwnership,
        source: Arc<dyn CandidateSource>,
        activator: Arc<dyn CandidateActivator>,
    ) -> BoxFuture<'static, Result<Arc<Self>, RuntimeError>> {
        let static_fingerprint = match StaticFingerprint::from_config(&static_ownership.config) {
            Ok(fingerprint) => fingerprint,
            Err(_) => {
                return reject_runtime_construction(
                    static_ownership,
                    RuntimeError::StaticFingerprintDerivationFailed,
                )
            }
        };
        if static_fingerprint != static_ownership.claimed_fingerprint {
            return reject_runtime_construction(
                static_ownership,
                RuntimeError::StaticOwnershipFingerprintMismatch,
            );
        }
        if activator.static_fingerprint() != &static_fingerprint {
            return reject_runtime_construction(
                static_ownership,
                RuntimeError::ActivatorStaticFingerprintMismatch,
            );
        }
        if !static_ownership
            .resources
            .brand()
            .same_instance(activator.static_resource_brand())
        {
            return reject_runtime_construction(
                static_ownership,
                RuntimeError::ActivatorStaticResourceMismatch,
            );
        }
        let runtime = Arc::new(Self {
            static_ownership,
            static_fingerprint,
            source,
            activator,
            active: ArcSwapOption::empty(),
            lifecycle: AtomicU8::new(LifecycleState::Starting as u8),
            lifecycle_changed: Notify::new(),
            shutdown_transition: StdMutex::new(()),
            next_generation: AtomicU64::new(1),
            activation: Mutex::new(()),
            pending_reload: AtomicBool::new(false),
            reload_worker_active: AtomicBool::new(false),
            current_cancellation: StdMutex::new(None),
            retiring_count: AtomicUsize::new(0),
            retiring_changed: Notify::new(),
            retirement_tasks: Mutex::new(Vec::new()),
            #[cfg(test)]
            reload_exit_blocked: AtomicBool::new(false),
            #[cfg(test)]
            reload_exit_entered: Notify::new(),
            #[cfg(test)]
            reload_exit_release: Notify::new(),
            #[cfg(test)]
            lease_acquire_blocked: AtomicBool::new(false),
            #[cfg(test)]
            lease_acquire_entered: AtomicBool::new(false),
            #[cfg(test)]
            lease_acquire_changed: Notify::new(),
            #[cfg(test)]
            lease_acquire_release: Notify::new(),
            #[cfg(test)]
            lease_validation_blocked: AtomicBool::new(false),
            #[cfg(test)]
            lease_validation_entered: AtomicBool::new(false),
            #[cfg(test)]
            lease_validation_changed: Notify::new(),
            #[cfg(test)]
            lease_validation_release: Notify::new(),
            #[cfg(test)]
            publication_exit_blocked: AtomicBool::new(false),
            #[cfg(test)]
            publication_exit_entered: AtomicBool::new(false),
            #[cfg(test)]
            publication_exit_changed: Notify::new(),
            #[cfg(test)]
            publication_exit_release: Notify::new(),
        });
        Box::pin(async move { Ok(runtime) })
    }

    pub(crate) fn static_config(&self) -> &StaticProductConfig {
        &self.static_ownership.config
    }

    pub(crate) fn lifecycle(&self) -> LifecycleState {
        LifecycleState::from_raw(self.lifecycle.load(Ordering::Acquire))
    }

    pub(crate) fn has_active_generation(&self) -> bool {
        self.active.load().is_some()
    }

    #[cfg(test)]
    pub(crate) fn is_ready(&self) -> bool {
        self.static_ownership.readiness.is_ready()
    }

    #[cfg(test)]
    pub(crate) fn active_generation_id(&self) -> Option<GenerationId> {
        self.active.load_full().map(|generation| generation.id())
    }

    #[cfg(test)]
    pub(crate) fn retiring_generations(&self) -> usize {
        self.retiring_count.load(Ordering::Acquire)
    }

    pub(crate) async fn lease(&self) -> Option<GenerationLease> {
        loop {
            let changed = self.lifecycle_changed.notified();
            match self.lifecycle() {
                LifecycleState::Starting | LifecycleState::Publishing => {
                    changed.await;
                }
                LifecycleState::ShuttingDown | LifecycleState::Stopped => return None,
                LifecycleState::Running => {
                    let Some(generation) = self.active.load_full() else {
                        if matches!(
                            self.lifecycle(),
                            LifecycleState::ShuttingDown | LifecycleState::Stopped
                        ) {
                            return None;
                        }
                        changed.await;
                        continue;
                    };
                    self.wait_before_lease_acquire_for_test().await;
                    let Some(lease) = generation.try_lease() else {
                        match self.lifecycle() {
                            LifecycleState::Running => continue,
                            LifecycleState::Starting | LifecycleState::Publishing => {
                                changed.await;
                            }
                            LifecycleState::ShuttingDown | LifecycleState::Stopped => return None,
                        }
                        continue;
                    };
                    self.wait_before_lease_validation_for_test().await;

                    match self.lifecycle() {
                        LifecycleState::Running => {
                            let still_active = self
                                .active
                                .load_full()
                                .is_some_and(|active| Arc::ptr_eq(&active, &generation));
                            if still_active {
                                return Some(lease);
                            }
                            drop(lease);
                        }
                        LifecycleState::Starting | LifecycleState::Publishing => {
                            drop(lease);
                            changed.await;
                        }
                        LifecycleState::ShuttingDown | LifecycleState::Stopped => {
                            drop(lease);
                            return None;
                        }
                    }
                }
            }
        }
    }

    pub(crate) async fn start(
        self: &Arc<Self>,
        initial: CompiledConfig,
    ) -> Result<GenerationId, RuntimeError> {
        let runtime = self.clone();
        tokio::spawn(async move { runtime.start_owned(initial).await })
            .await
            .map_err(|_| RuntimeError::CoordinatorTask)?
    }

    async fn start_owned(
        self: &Arc<Self>,
        initial: CompiledConfig,
    ) -> Result<GenerationId, RuntimeError> {
        let _activation = self.activation.lock().await;
        match self.lifecycle() {
            LifecycleState::Starting if self.active.load_full().is_none() => {}
            LifecycleState::ShuttingDown | LifecycleState::Stopped => {
                return Err(RuntimeError::ShuttingDown)
            }
            _ => return Err(RuntimeError::AlreadyStarted),
        }

        self.validate_compiled_static(&initial)?;

        let cancellation = self.register_cancellation();
        let id = self.allocate_generation_id();
        let activated = self
            .activator
            .activate(id, initial.reloadable_plan, cancellation.clone())
            .await;
        self.clear_cancellation(&cancellation);
        let activated = activated?;
        self.publish(id, activated, LifecycleState::Starting, &cancellation)
            .await
    }

    pub(crate) async fn trigger_reload(
        self: &Arc<Self>,
    ) -> Result<ReloadTriggerResult, RuntimeError> {
        match self.lifecycle() {
            LifecycleState::Running | LifecycleState::Publishing => {}
            LifecycleState::ShuttingDown | LifecycleState::Stopped => {
                return Err(RuntimeError::ShuttingDown)
            }
            LifecycleState::Starting => return Err(RuntimeError::NotRunning),
        }

        self.pending_reload.store(true, Ordering::Release);
        if self
            .reload_worker_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(ReloadTriggerResult::Coalesced);
        }

        let runtime = self.clone();
        tokio::spawn(async move { runtime.run_reload_worker().await })
            .await
            .map_err(|_| RuntimeError::CoordinatorTask)?
    }

    async fn run_reload_worker(self: &Arc<Self>) -> Result<ReloadTriggerResult, RuntimeError> {
        let mut ownership = ReloadWorkerOwnership {
            runtime: self.clone(),
            owns: true,
        };
        let mut attempts = 0;
        let mut last_result = None;
        loop {
            {
                let _activation = self.activation.lock().await;
                while self.pending_reload.swap(false, Ordering::AcqRel) {
                    if self.lifecycle() != LifecycleState::Running {
                        last_result = Some(Err(RuntimeError::ShuttingDown));
                        break;
                    }
                    attempts += 1;
                    last_result = Some(self.reload_once().await);
                }
            }

            self.wait_at_reload_exit_for_test().await;
            self.reload_worker_active.store(false, Ordering::Release);
            ownership.owns = false;
            if self.pending_reload.load(Ordering::Acquire)
                && self
                    .reload_worker_active
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                ownership.owns = true;
                continue;
            }
            break;
        }

        match last_result.unwrap_or(Err(RuntimeError::ShuttingDown)) {
            Ok(generation) => Ok(ReloadTriggerResult::Completed {
                attempts,
                generation,
            }),
            Err(error) => Err(error),
        }
    }

    async fn reload_once(self: &Arc<Self>) -> Result<GenerationId, RuntimeError> {
        self.check_retiring_ceiling()?;
        let cancellation = self.register_cancellation();
        let compiled = self.source.load_latest(cancellation.clone()).await;
        let result = match compiled {
            Ok(compiled) => self.activate_compiled(compiled, &cancellation).await,
            Err(error) => Err(error),
        };
        self.clear_cancellation(&cancellation);
        result
    }

    async fn activate_compiled(
        self: &Arc<Self>,
        compiled: CompiledConfig,
        cancellation: &ActivationCancellation,
    ) -> Result<GenerationId, RuntimeError> {
        cancellation.check()?;
        self.validate_compiled_static(&compiled)?;
        let id = self.allocate_generation_id();
        let activated = self
            .activator
            .activate(id, compiled.reloadable_plan, cancellation.clone())
            .await?;
        self.publish(id, activated, LifecycleState::Running, cancellation)
            .await
    }

    fn validate_compiled_static(&self, compiled: &CompiledConfig) -> Result<(), RuntimeError> {
        let canonical = StaticFingerprint::from_config(&compiled.static_config)
            .map_err(|_| RuntimeError::StaticFingerprintDerivationFailed)?;
        if canonical != compiled.static_fingerprint || canonical != self.static_fingerprint {
            return Err(RuntimeError::StaticFingerprintChanged);
        }
        Ok(())
    }

    async fn publish(
        self: &Arc<Self>,
        id: GenerationId,
        activated: ActivatedGeneration,
        expected: LifecycleState,
        cancellation: &ActivationCancellation,
    ) -> Result<GenerationId, RuntimeError> {
        let generation = Arc::new(Generation::from_activated(id, activated));
        let retirement = match self.publish_sync(&generation, expected, cancellation) {
            Ok(retirement) => retirement,
            Err(error) => {
                self.cleanup_candidate(generation.owner.clone()).await;
                return Err(error);
            }
        };

        self.wait_at_publication_exit_for_test().await;

        if let Some(retirement) = retirement {
            self.schedule_retirement(retirement).await;
        }
        Ok(id)
    }

    fn publish_sync(
        &self,
        generation: &Arc<Generation>,
        expected: LifecycleState,
        cancellation: &ActivationCancellation,
    ) -> Result<Option<MarkedRetirement>, RuntimeError> {
        let _shutdown_transition = self.shutdown_transition.lock().unwrap();
        let mut publication_guard = generation.owner.publication_guard()?;

        cancellation.check()?;

        if self
            .lifecycle
            .compare_exchange(
                expected as u8,
                LifecycleState::Publishing as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(RuntimeError::ShuttingDown);
        }

        let retirement = self
            .active
            .swap(Some(generation.clone()))
            .map(|previous| self.mark_retiring(previous, CleanupReason::Retired));
        publication_guard.commit();
        drop(publication_guard);
        self.lifecycle
            .store(LifecycleState::Running as u8, Ordering::Release);
        self.static_ownership.readiness.mark_runtime_published();
        self.lifecycle_changed.notify_waiters();
        Ok(retirement)
    }

    fn check_retiring_ceiling(&self) -> Result<(), RuntimeError> {
        let limit = self
            .static_ownership
            .config
            .service
            .max_retiring_generations;
        let additional = usize::from(self.active.load_full().is_some());
        if self
            .retiring_count
            .load(Ordering::Acquire)
            .saturating_add(additional)
            > limit
        {
            Err(RuntimeError::RetiringGenerationLimit { limit })
        } else {
            Ok(())
        }
    }

    fn mark_retiring(
        &self,
        generation: Arc<Generation>,
        reason: CleanupReason,
    ) -> MarkedRetirement {
        generation.begin_retirement();
        let owner = generation.owner.clone();
        if catch_unwind(AssertUnwindSafe(|| owner.retirement_started(reason))).is_err() {
            tracing::error!(
                generation = generation.id().get(),
                ?reason,
                "generation owner panicked while starting retirement"
            );
        }
        self.retiring_count.fetch_add(1, Ordering::AcqRel);
        MarkedRetirement { generation, reason }
    }

    async fn schedule_retirement(self: &Arc<Self>, retirement: MarkedRetirement) {
        let runtime = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            let MarkedRetirement { generation, reason } = retirement;
            generation.wait_for_leases().await;
            let owner = generation.owner.clone();
            let cleanup = tokio::spawn(async move { owner.cleanup(reason).await });
            let _ = cleanup.await;
            if let Some(runtime) = Weak::upgrade(&runtime) {
                runtime.retiring_count.fetch_sub(1, Ordering::AcqRel);
                runtime.retiring_changed.notify_waiters();
            }
        });
        let mut tasks = self.retirement_tasks.lock().await;
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }

    async fn cleanup_candidate(&self, owner: Arc<dyn super::generation::GenerationOwner>) {
        let cleanup =
            tokio::spawn(async move { owner.cleanup(CleanupReason::CandidateRejected).await });
        let _ = cleanup.await;
    }

    pub(crate) async fn shutdown(self: &Arc<Self>) {
        let runtime = self.clone();
        match tokio::spawn(async move { runtime.shutdown_owned().await }).await {
            Ok(()) => {}
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(error) => panic!("runtime shutdown task failed: {error}"),
        }
    }

    async fn shutdown_owned(self: &Arc<Self>) {
        loop {
            let changed = self.lifecycle_changed.notified();
            let shutdown_transition = self.shutdown_transition.lock().unwrap();
            let state = self.lifecycle();
            match state {
                LifecycleState::Starting | LifecycleState::Running => {
                    self.static_ownership.readiness.begin_shutdown();
                    self.static_ownership.resources.begin_shutdown();
                    if self
                        .lifecycle
                        .compare_exchange(
                            state as u8,
                            LifecycleState::ShuttingDown as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        self.lifecycle_changed.notify_waiters();
                        drop(shutdown_transition);
                        break;
                    }
                }
                LifecycleState::Publishing => {
                    drop(shutdown_transition);
                    changed.await;
                }
                LifecycleState::ShuttingDown => {
                    drop(shutdown_transition);
                    changed.await;
                }
                LifecycleState::Stopped => return,
            }
        }

        self.pending_reload.store(false, Ordering::Release);
        if let Some(cancellation) = self.current_cancellation.lock().unwrap().as_ref() {
            cancellation.cancel();
        }
        let static_resources = self.static_ownership.resources.clone();
        let static_shutdown = tokio::spawn(async move { static_resources.shutdown().await });

        let _activation = self.activation.lock().await;
        if let Some(active) = self.active.swap(None) {
            let retirement = self.mark_retiring(active, CleanupReason::Shutdown);
            self.schedule_retirement(retirement).await;
        }
        self.wait_for_retirements().await;
        match static_shutdown.await {
            Ok(()) => {}
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(error) => panic!("static-resource shutdown task failed: {error}"),
        }
        self.lifecycle
            .store(LifecycleState::Stopped as u8, Ordering::Release);
        self.lifecycle_changed.notify_waiters();
    }

    async fn wait_for_retirements(&self) {
        loop {
            let changed = self.retiring_changed.notified();
            if self.retiring_count.load(Ordering::Acquire) == 0 {
                break;
            }
            changed.await;
        }
        let tasks = std::mem::take(&mut *self.retirement_tasks.lock().await);
        for task in tasks {
            let _ = task.await;
        }
    }

    fn allocate_generation_id(&self) -> GenerationId {
        GenerationId::new(self.next_generation.fetch_add(1, Ordering::Relaxed))
    }

    fn register_cancellation(&self) -> ActivationCancellation {
        let cancellation = ActivationCancellation::new();
        *self.current_cancellation.lock().unwrap() = Some(cancellation.clone());
        cancellation
    }

    fn clear_cancellation(&self, cancellation: &ActivationCancellation) {
        let mut current = self.current_cancellation.lock().unwrap();
        if current
            .as_ref()
            .is_some_and(|active| active.same_instance(cancellation))
        {
            *current = None;
        }
    }

    #[cfg(test)]
    pub(super) fn block_reload_worker_exit(&self) {
        self.reload_exit_blocked.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(super) async fn wait_for_reload_worker_exit(&self) {
        loop {
            let entered = self.reload_exit_entered.notified();
            if self.reload_exit_blocked.load(Ordering::Acquire) {
                entered.await;
                return;
            }
            tokio::task::yield_now().await;
        }
    }

    #[cfg(test)]
    pub(super) fn release_reload_worker_exit(&self) {
        self.reload_exit_blocked.store(false, Ordering::Release);
        self.reload_exit_release.notify_waiters();
    }

    #[cfg(test)]
    pub(super) fn block_lease_before_acquire(&self) {
        self.lease_acquire_entered.store(false, Ordering::Release);
        self.lease_acquire_blocked.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(super) async fn wait_for_lease_before_acquire(&self) {
        loop {
            let changed = self.lease_acquire_changed.notified();
            if self.lease_acquire_entered.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }

    #[cfg(test)]
    pub(super) fn release_lease_before_acquire(&self) {
        self.lease_acquire_blocked.store(false, Ordering::Release);
        self.lease_acquire_release.notify_one();
    }

    #[cfg(test)]
    pub(super) fn block_lease_before_validation(&self) {
        self.lease_validation_entered
            .store(false, Ordering::Release);
        self.lease_validation_blocked.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(super) async fn wait_for_lease_before_validation(&self) {
        loop {
            let changed = self.lease_validation_changed.notified();
            if self.lease_validation_entered.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }

    #[cfg(test)]
    pub(super) fn release_lease_before_validation(&self) {
        self.lease_validation_blocked
            .store(false, Ordering::Release);
        self.lease_validation_release.notify_one();
    }

    #[cfg(test)]
    pub(super) fn block_publication_exit(&self) {
        self.publication_exit_entered
            .store(false, Ordering::Release);
        self.publication_exit_blocked.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(super) async fn wait_for_publication_exit(&self) {
        loop {
            let changed = self.publication_exit_changed.notified();
            if self.publication_exit_entered.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }

    #[cfg(test)]
    pub(super) fn release_publication_exit(&self) {
        self.publication_exit_blocked
            .store(false, Ordering::Release);
        self.publication_exit_release.notify_one();
    }

    #[cfg(test)]
    pub(super) async fn retirement_task_count(&self) -> usize {
        self.retirement_tasks.lock().await.len()
    }

    #[cfg(test)]
    pub(super) fn has_pending_reload(&self) -> bool {
        self.pending_reload.load(Ordering::Acquire)
    }

    #[cfg(test)]
    async fn wait_at_reload_exit_for_test(&self) {
        if self.reload_exit_blocked.load(Ordering::Acquire) {
            let released = self.reload_exit_release.notified();
            self.reload_exit_entered.notify_waiters();
            released.await;
        }
    }

    #[cfg(not(test))]
    async fn wait_at_reload_exit_for_test(&self) {}

    #[cfg(test)]
    async fn wait_before_lease_acquire_for_test(&self) {
        if self.lease_acquire_blocked.load(Ordering::Acquire) {
            let released = self.lease_acquire_release.notified();
            self.lease_acquire_entered.store(true, Ordering::Release);
            self.lease_acquire_changed.notify_one();
            released.await;
        }
    }

    #[cfg(not(test))]
    async fn wait_before_lease_acquire_for_test(&self) {}

    #[cfg(test)]
    async fn wait_before_lease_validation_for_test(&self) {
        if self.lease_validation_blocked.load(Ordering::Acquire) {
            let released = self.lease_validation_release.notified();
            self.lease_validation_entered.store(true, Ordering::Release);
            self.lease_validation_changed.notify_one();
            released.await;
        }
    }

    #[cfg(not(test))]
    async fn wait_before_lease_validation_for_test(&self) {}

    #[cfg(test)]
    async fn wait_at_publication_exit_for_test(&self) {
        if self.publication_exit_blocked.load(Ordering::Acquire) {
            let released = self.publication_exit_release.notified();
            self.publication_exit_entered.store(true, Ordering::Release);
            self.publication_exit_changed.notify_one();
            released.await;
        }
    }

    #[cfg(not(test))]
    async fn wait_at_publication_exit_for_test(&self) {}
}
