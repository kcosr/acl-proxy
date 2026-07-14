use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock, TryLockError};

use arc_swap::ArcSwap;

use super::CaptureEpoch;
use crate::runtime::{BoxFuture, CleanupReason, GenerationOwner, PublicationGuard, RuntimeError};

struct PublishedCaptureState {
    epoch: Arc<CaptureEpoch>,
    limit: usize,
    enabled: bool,
    closed: bool,
}

impl PublishedCaptureState {
    fn open(epoch: Arc<CaptureEpoch>, limit: usize) -> Self {
        let enabled = epoch.is_enabled() && limit != 0;
        Self {
            epoch,
            limit,
            enabled,
            closed: false,
        }
    }

    fn closed() -> Self {
        Self {
            epoch: Arc::new(CaptureEpoch::disabled()),
            limit: 0,
            enabled: false,
            closed: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CapturePublicationResult {
    Published,
    Closed,
}

/// One process-wide capture byte pool shared by every active and retiring
/// observation epoch. Admission uses atomic accounting and never waits or delays
/// the wire path.
pub(crate) struct CapturePool {
    publication_gate: RwLock<()>,
    published: ArcSwap<PublishedCaptureState>,
    used: AtomicUsize,
}

impl fmt::Debug for CapturePool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturePool")
            .field("committed_limit", &self.committed_limit())
            .field("used", &self.used())
            .field("closed", &self.is_closed())
            .finish()
    }
}

impl CapturePool {
    /// Creates the pool owned once by `ProductActivator` and shared with every
    /// observation generation it activates.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            publication_gate: RwLock::new(()),
            published: ArcSwap::from_pointee(PublishedCaptureState::open(
                Arc::new(CaptureEpoch::disabled()),
                0,
            )),
            used: AtomicUsize::new(0),
        })
    }

    /// Starts one bounded capture operation under the currently published
    /// enabled state and ceiling. Failure is immediate and observation-only;
    /// callers omit the payload rather than wait.
    pub(crate) fn try_admit(self: &Arc<Self>, bytes: usize) -> Option<CaptureOperation> {
        self.try_admit_with_hook(bytes, || {})
    }

    fn try_admit_with_hook(
        self: &Arc<Self>,
        bytes: usize,
        hook: impl FnOnce(),
    ) -> Option<CaptureOperation> {
        let _publication = match self.publication_gate.try_read() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return None,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        };
        hook();
        let published = self.published.load();
        if !published.enabled {
            return None;
        }
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let next = used.checked_add(bytes)?;
            if next > published.limit {
                return None;
            }
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(current) => used = current,
            }
        }
        Some(CaptureOperation {
            pool: self.clone(),
            ceiling: published.limit,
            charged: bytes,
        })
    }

    pub(crate) fn committed_limit(&self) -> usize {
        self.published.load().limit
    }

    pub(crate) fn current_epoch(&self) -> Arc<CaptureEpoch> {
        self.published.load().epoch.clone()
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.published.load().closed
    }

    #[cfg(test)]
    fn published_for_test(&self) -> (Arc<CaptureEpoch>, usize, bool, bool) {
        let published = self.published.load();
        (
            published.epoch.clone(),
            published.limit,
            published.enabled,
            published.closed,
        )
    }

    pub(crate) fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    fn publish(&self, epoch: Arc<CaptureEpoch>, limit: usize) -> CapturePublicationResult {
        let _publication = self
            .publication_gate
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.published.load().closed {
            return CapturePublicationResult::Closed;
        }
        self.published
            .store(Arc::new(PublishedCaptureState::open(epoch, limit)));
        CapturePublicationResult::Published
    }

    #[cfg(test)]
    fn publish_with_hook(
        &self,
        epoch: Arc<CaptureEpoch>,
        limit: usize,
        hook: impl FnOnce(),
    ) -> CapturePublicationResult {
        let _publication = self
            .publication_gate
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        hook();
        if self.published.load().closed {
            return CapturePublicationResult::Closed;
        }
        self.published
            .store(Arc::new(PublishedCaptureState::open(epoch, limit)));
        CapturePublicationResult::Published
    }

    pub(super) fn close(&self) {
        let _publication = self
            .publication_gate
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.published.load().closed {
            return;
        }
        self.published
            .store(Arc::new(PublishedCaptureState::closed()));
    }

    fn release(&self, bytes: usize) {
        assert!(
            self.used
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_sub(bytes)
                })
                .is_ok(),
            "capture operation accounting underflow"
        );
    }
}

/// Incremental byte budget for one observation-only capture attempt.
///
/// The ceiling is captured at admission. Reload cannot invalidate an admitted
/// operation. New operations through leased policies use the currently
/// published enabled state and ceiling.
pub(crate) struct CaptureOperation {
    pool: Arc<CapturePool>,
    ceiling: usize,
    charged: usize,
}

impl CaptureOperation {
    pub(crate) fn charged_bytes(&self) -> usize {
        self.charged
    }

    pub(crate) fn ceiling(&self) -> usize {
        self.ceiling
    }

    /// Charges additional capture-owned memory before allocation. Exhaustion
    /// or arithmetic overflow leaves both the operation and pool unchanged.
    pub(crate) fn try_grow(&mut self, additional: usize) -> bool {
        if additional == 0 {
            return true;
        }
        let Some(next_charge) = self.charged.checked_add(additional) else {
            return false;
        };
        if next_charge > self.ceiling {
            return false;
        }

        let mut used = self.pool.used.load(Ordering::Acquire);
        loop {
            let Some(next_used) = used.checked_add(additional) else {
                return false;
            };
            if next_used > self.ceiling {
                return false;
            }
            match self.pool.used.compare_exchange_weak(
                used,
                next_used,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.charged = next_charge;
                    return true;
                }
                Err(current) => used = current,
            }
        }
    }

    /// Releases bytes as capture-owned buffers are discarded.
    pub(crate) fn shrink(&mut self, bytes: usize) {
        assert!(bytes <= self.charged, "capture operation shrink underflow");
        self.pool.release(bytes);
        self.charged -= bytes;
    }
}

impl fmt::Debug for CaptureOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptureOperation")
            .field("ceiling", &self.ceiling)
            .field("charged", &self.charged)
            .finish()
    }
}

impl Drop for CaptureOperation {
    fn drop(&mut self) {
        self.pool.release(self.charged);
    }
}

/// Candidate-owned publication effect. Constructing or dropping an update has
/// no effect on the active capture epoch or ceiling; commit publishes both as
/// one immutable state.
pub(crate) struct CaptureEpochUpdate {
    pool: Arc<CapturePool>,
    proposed_epoch: Arc<CaptureEpoch>,
    proposed_limit: usize,
}

impl fmt::Debug for CaptureEpochUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptureEpochUpdate")
            .field("capture_enabled", &self.proposed_epoch.is_enabled())
            .field("proposed_limit", &self.proposed_limit)
            .finish()
    }
}

impl CaptureEpochUpdate {
    pub(crate) fn new(
        pool: Arc<CapturePool>,
        proposed_epoch: Arc<CaptureEpoch>,
        proposed_limit: usize,
    ) -> Self {
        Self {
            pool,
            proposed_epoch,
            proposed_limit,
        }
    }

    pub(crate) fn publication_guard(
        &self,
    ) -> Result<CaptureEpochPublicationGuard<'_>, RuntimeError> {
        // A guard acquired before shutdown is still safe: commit rechecks the
        // permanent pool state under the publication gate and becomes a no-op
        // if closure won. Acquisitions after closure fail deterministically.
        if self.pool.is_closed() {
            return Err(RuntimeError::ShuttingDown);
        }
        Ok(CaptureEpochPublicationGuard {
            update: self,
            committed: false,
        })
    }

    pub(crate) fn proposed_limit(&self) -> usize {
        self.proposed_limit
    }
}

impl GenerationOwner for CaptureEpochUpdate {
    fn publication_guard(&self) -> Result<Box<dyn PublicationGuard + '_>, RuntimeError> {
        Ok(Box::new(CaptureEpochUpdate::publication_guard(self)?))
    }

    fn retirement_started(&self, _reason: CleanupReason) {}

    fn cleanup(&self, _reason: CleanupReason) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

pub(crate) struct CaptureEpochPublicationGuard<'update> {
    update: &'update CaptureEpochUpdate,
    committed: bool,
}

impl PublicationGuard for CaptureEpochPublicationGuard<'_> {
    fn commit(&mut self) {
        if !self.committed {
            let result = self.update.pool.publish(
                self.update.proposed_epoch.clone(),
                self.update.proposed_limit,
            );
            if result == CapturePublicationResult::Closed {
                tracing::warn!(
                    "capture epoch publication skipped because the observation runtime is shutting down"
                );
            }
            self.committed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::Barrier;
    use std::thread;

    use super::*;
    use crate::config::compiler::{
        CapturePlan, CompiledCaptureEvent, CompiledLogLevel, CompiledRedactionPayloads,
        ObservationPlan, PolicyDecisionLoggingPlan, RedactionPlan, RedactionProfilePlan,
        RedactionRulePlan, ReloadableLoggingPlan,
    };
    use crate::observation::{CaptureEvent, ObservationActivation, ProductObservationSnapshot};
    use crate::redaction::RedactionSnapshot;

    fn accounting_capture_activation(
        pool: Arc<CapturePool>,
        limit: usize,
    ) -> ObservationActivation {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "accounting".to_owned(),
            RedactionProfilePlan {
                replacement: b"[REMOVED]".to_vec(),
                max_body_bytes: 8,
                max_decoded_body_bytes: 128,
                max_frame_bytes: 64,
                max_message_bytes: 128,
                allow_permessage_deflate: false,
                max_environment_literal_sources: 1,
                max_environment_literal_bytes: 64,
                max_environment_literal_total_bytes: 64,
                rules: vec![RedactionRulePlan {
                    literals: vec![b"secret".to_vec()],
                    literal_environment_variables: Vec::new(),
                    expressions: Vec::new(),
                    payloads: CompiledRedactionPayloads::Both,
                }],
            },
        );
        let redaction =
            RedactionSnapshot::activate(RedactionPlan { profiles }, || false).expect("redaction");
        ProductObservationSnapshot::activate(
            ObservationPlan {
                logging: ReloadableLoggingPlan {
                    level: CompiledLogLevel::Info,
                    policy_decisions: PolicyDecisionLoggingPlan {
                        allows: false,
                        denies: true,
                        allow_level: CompiledLogLevel::Info,
                        deny_level: CompiledLogLevel::Warn,
                    },
                },
                capture: Some(CapturePlan {
                    events: vec![CompiledCaptureEvent::RequestAllowed],
                    redaction_profile: "accounting".to_owned(),
                    directory: PathBuf::from("/accounting-captures"),
                    filename: "capture-{requestId}-{suffix}.json".to_owned(),
                    max_body_bytes: 1,
                    max_inflight_body_bytes: limit,
                    max_files: 10,
                    max_total_bytes: 100,
                }),
            },
            &redaction,
            pool,
        )
        .expect("capture activation")
    }

    fn enabled_pool(limit: usize) -> Arc<CapturePool> {
        let pool = CapturePool::new();
        let activation = accounting_capture_activation(pool.clone(), limit);
        let (_, owner) = activation.into_parts();
        owner
            .publication_guard()
            .expect("initial publication guard")
            .commit();
        assert!(pool.current_epoch().is_enabled());
        pool
    }

    fn try_admit_current(pool: &Arc<CapturePool>, bytes: usize) -> Option<CaptureOperation> {
        pool.try_admit(bytes)
    }

    #[test]
    fn rejected_update_does_not_change_the_committed_limit() {
        let pool = enabled_pool(16);
        let original = pool.current_epoch();
        let candidate = accounting_capture_activation(pool.clone(), 32);
        let (_snapshot, owner) = candidate.into_parts();
        {
            let _rejected_guard = owner.publication_guard().expect("publication guard");
        }
        assert_eq!(pool.committed_limit(), 16);
        assert!(Arc::ptr_eq(&pool.current_epoch(), &original));
    }

    #[test]
    fn publication_commit_changes_the_limit_once() {
        let pool = enabled_pool(16);
        let candidate = accounting_capture_activation(pool.clone(), 32);
        let (snapshot, owner) = candidate.into_parts();
        let proposed = snapshot.capture_epoch().clone();
        let mut guard = owner.publication_guard().expect("publication guard");
        guard.commit();
        guard.commit();
        assert_eq!(pool.committed_limit(), 32);
        assert!(Arc::ptr_eq(&pool.current_epoch(), &proposed));
    }

    #[test]
    fn admitted_operation_survives_disablement_and_new_admission_is_rejected() {
        let pool = enabled_pool(16);
        let mut old = try_admit_current(&pool, 12).expect("old operation");
        let old_epoch = pool.current_epoch();
        let update = CaptureEpochUpdate::new(pool.clone(), Arc::new(CaptureEpoch::disabled()), 4);
        update
            .publication_guard()
            .expect("publication guard")
            .commit();

        assert_eq!(pool.used(), 12);
        assert!(old.try_grow(4));
        assert_eq!(pool.used(), 16);
        assert!(old_epoch
            .capture()
            .expect("old policy")
            .try_admit(CaptureEvent::RequestAllowed, 0)
            .is_none());
        drop(old);
        assert_eq!(pool.used(), 0);
        assert!(try_admit_current(&pool, 0).is_none());
        assert!(try_admit_current(&pool, 4).is_none());
    }

    #[test]
    fn exact_operations_saturate_without_waiting() {
        let pool = enabled_pool(10);
        let first = try_admit_current(&pool, 6).expect("first");
        let second = try_admit_current(&pool, 4).expect("second");
        assert!(try_admit_current(&pool, 1).is_none());
        assert_eq!(pool.used(), 10);
        drop((first, second));
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn operation_grows_and_shrinks_with_exact_drop_restoration() {
        let pool = enabled_pool(20);
        let mut operation = try_admit_current(&pool, 3).expect("operation");

        assert_eq!(operation.ceiling(), 20);
        assert_eq!(operation.charged_bytes(), 3);
        assert!(operation.try_grow(9));
        assert_eq!(operation.charged_bytes(), 12);
        assert_eq!(pool.used(), 12);

        operation.shrink(5);
        assert_eq!(operation.charged_bytes(), 7);
        assert_eq!(pool.used(), 7);

        drop(operation);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn failed_growth_leaves_operation_and_pool_unchanged() {
        let pool = enabled_pool(10);
        let mut operation = try_admit_current(&pool, 6).expect("operation");
        let contention = try_admit_current(&pool, 4).expect("contention");

        assert!(!operation.try_grow(1));
        assert_eq!(operation.charged_bytes(), 6);
        assert_eq!(pool.used(), 10);

        drop(contention);
        assert!(!operation.try_grow(5));
        assert!(!operation.try_grow(usize::MAX));
        assert_eq!(operation.charged_bytes(), 6);
        assert_eq!(pool.used(), 6);

        drop(operation);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn arithmetic_overflow_is_an_observation_only_omission() {
        let pool = enabled_pool(usize::MAX);
        let operation = try_admit_current(&pool, usize::MAX).expect("maximum operation");
        assert!(try_admit_current(&pool, 1).is_none());
        drop(operation);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn concurrent_admissions_share_the_limit_gate() {
        let pool = enabled_pool(16);
        let first_entered = Arc::new(Barrier::new(2));
        let finish_first = Arc::new(Barrier::new(2));
        let first_pool = pool.clone();
        let first = thread::spawn({
            let first_entered = first_entered.clone();
            let finish_first = finish_first.clone();
            move || {
                first_pool.try_admit_with_hook(4, || {
                    first_entered.wait();
                    finish_first.wait();
                })
            }
        });

        first_entered.wait();
        let second = try_admit_current(&pool, 4)
            .expect("another admission may enter while the first holds a read gate");
        finish_first.wait();
        let first = first.join().expect("first admission thread").unwrap();

        assert_eq!(pool.used(), 8);
        drop((first, second));
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn enabled_lower_limit_preserves_admitted_ceiling_and_rebinds_old_epoch_admission() {
        let pool = enabled_pool(16);
        let old_epoch = pool.current_epoch();
        let mut existing = try_admit_current(&pool, 6).expect("existing operation");
        let candidate = accounting_capture_activation(pool.clone(), 8);
        let (snapshot, _owner) = candidate.into_parts();
        let new_epoch = snapshot.capture_epoch().clone();
        let publication_entered = Arc::new(Barrier::new(2));
        let finish_publication = Arc::new(Barrier::new(2));
        let publication_pool = pool.clone();
        let publisher = thread::spawn({
            let publication_entered = publication_entered.clone();
            let finish_publication = finish_publication.clone();
            move || {
                assert_eq!(
                    publication_pool.publish_with_hook(new_epoch, 8, || {
                        publication_entered.wait();
                        finish_publication.wait();
                    }),
                    CapturePublicationResult::Published
                );
            }
        });

        publication_entered.wait();
        assert!(try_admit_current(&pool, 1).is_none());
        finish_publication.wait();
        publisher.join().expect("publisher");

        assert!(pool.current_epoch().is_enabled());
        assert_eq!(pool.committed_limit(), 8);
        assert_eq!(pool.used(), 6);
        let reloaded_old = old_epoch
            .capture()
            .expect("old policy")
            .try_admit(CaptureEvent::RequestAllowed, 0)
            .expect("old leased policy uses newly published enabled ceiling");
        assert_eq!(reloaded_old.ceiling(), 8);
        let mut current = try_admit_current(&pool, 0).expect("new epoch operation");
        assert_eq!(current.ceiling(), 8);
        assert!(existing.try_grow(10));
        assert_eq!(existing.charged_bytes(), 16);
        assert_eq!(pool.used(), 16);
        assert!(!existing.try_grow(1));
        assert!(!current.try_grow(1));
        assert_eq!(current.charged_bytes(), 0);
        drop((current, reloaded_old));
        drop(existing);
        assert_eq!(pool.used(), 0);
        let current = try_admit_current(&pool, 8).expect("new ceiling");
        assert_eq!(current.charged_bytes(), 8);
        assert_eq!(current.ceiling(), 8);
    }

    #[test]
    fn capture_epoch_publication_is_atomic_with_limit() {
        let pool = enabled_pool(16);
        let old_epoch = pool.current_epoch();
        let candidate = accounting_capture_activation(pool.clone(), 32);
        let (snapshot, _owner) = candidate.into_parts();
        let new_epoch = snapshot.capture_epoch().clone();
        let publication_entered = Arc::new(Barrier::new(2));
        let finish_publication = Arc::new(Barrier::new(2));
        let publication_pool = pool.clone();
        let publisher = thread::spawn({
            let publication_entered = publication_entered.clone();
            let finish_publication = finish_publication.clone();
            let new_epoch = new_epoch.clone();
            move || {
                assert_eq!(
                    publication_pool.publish_with_hook(new_epoch, 32, || {
                        publication_entered.wait();
                        finish_publication.wait();
                    }),
                    CapturePublicationResult::Published
                );
            }
        });

        publication_entered.wait();
        let (
            epoch_during_publication,
            limit_during_publication,
            enabled_during_publication,
            closed_during_publication,
        ) = pool.published_for_test();
        assert!(Arc::ptr_eq(&epoch_during_publication, &old_epoch));
        assert_eq!(limit_during_publication, 16);
        assert!(enabled_during_publication);
        assert!(!closed_during_publication);
        finish_publication.wait();
        publisher.join().expect("publisher");

        let (published_epoch, published_limit, published_enabled, published_closed) =
            pool.published_for_test();
        assert!(Arc::ptr_eq(&published_epoch, &new_epoch));
        assert_eq!(published_limit, 32);
        assert!(published_enabled);
        assert!(!published_closed);
    }

    #[test]
    fn permanent_closure_rejects_all_admission_and_publication() {
        let pool = enabled_pool(16);
        let candidate = accounting_capture_activation(pool.clone(), 32);
        let (_snapshot, owner) = candidate.into_parts();
        let mut stale_guard = owner.publication_guard().expect("pre-shutdown guard");
        let pre_shutdown_zero = try_admit_current(&pool, 0).expect("open zero-byte admission");
        drop(pre_shutdown_zero);

        pool.close();
        let closed_epoch = pool.current_epoch();
        pool.close();
        stale_guard.commit();

        assert!(pool.is_closed());
        assert_eq!(pool.committed_limit(), 0);
        assert!(!closed_epoch.is_enabled());
        assert!(Arc::ptr_eq(&pool.current_epoch(), &closed_epoch));
        assert!(try_admit_current(&pool, 0).is_none());
        assert!(try_admit_current(&pool, 1).is_none());
        assert!(matches!(
            owner.publication_guard(),
            Err(RuntimeError::ShuttingDown)
        ));
    }

    #[test]
    fn publication_before_close_leaves_the_pool_permanently_closed() {
        let pool = enabled_pool(16);
        let candidate = accounting_capture_activation(pool.clone(), 32);
        let (snapshot, _owner) = candidate.into_parts();
        let proposed = snapshot.capture_epoch().clone();
        let publication_entered = Arc::new(Barrier::new(2));
        let finish_publication = Arc::new(Barrier::new(2));
        let close_started = Arc::new(Barrier::new(2));
        let publication_pool = pool.clone();
        let publisher = thread::spawn({
            let publication_entered = publication_entered.clone();
            let finish_publication = finish_publication.clone();
            move || {
                publication_pool.publish_with_hook(proposed, 32, || {
                    publication_entered.wait();
                    finish_publication.wait();
                })
            }
        });

        publication_entered.wait();
        let closing_pool = pool.clone();
        let closer = thread::spawn({
            let close_started = close_started.clone();
            move || {
                close_started.wait();
                closing_pool.close();
            }
        });
        close_started.wait();
        finish_publication.wait();

        assert_eq!(
            publisher.join().expect("publisher"),
            CapturePublicationResult::Published
        );
        closer.join().expect("closer");
        let (epoch, limit, enabled, closed) = pool.published_for_test();
        assert!(closed);
        assert_eq!(limit, 0);
        assert!(!enabled);
        assert!(!epoch.is_enabled());
        assert!(try_admit_current(&pool, 0).is_none());
    }

    #[test]
    fn close_before_publication_rejects_the_publication_and_preserves_closed_state() {
        let pool = enabled_pool(16);
        pool.close();
        let closed_epoch = pool.current_epoch();
        let candidate = accounting_capture_activation(pool.clone(), 32);
        let (snapshot, _owner) = candidate.into_parts();

        let result = pool.publish_with_hook(snapshot.capture_epoch().clone(), 32, || {});

        assert_eq!(result, CapturePublicationResult::Closed);
        let (epoch, limit, enabled, closed) = pool.published_for_test();
        assert!(closed);
        assert_eq!(limit, 0);
        assert!(!enabled);
        assert!(Arc::ptr_eq(&epoch, &closed_epoch));
        assert!(try_admit_current(&pool, 0).is_none());
    }
}
