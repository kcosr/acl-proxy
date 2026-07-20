use std::fmt;
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock, TryLockError};

use arc_swap::ArcSwap;

use super::CaptureEpoch;
use crate::runtime::{BoxFuture, CleanupReason, GenerationOwner, PublicationGuard, RuntimeError};
use crate::safety::allocation::{
    AllocationAuthority, ExactAllocationLease, ReservedStableBodyBuilder, StableBody,
    StableBodyBuilder, StableExactBytes, StableScratch, StableWorkspace, StableWorkspaceAllocation,
};

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
    #[cfg(test)]
    fail_next_allocation: AtomicBool,
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
            #[cfg(test)]
            fail_next_allocation: AtomicBool::new(false),
        })
    }

    /// Starts one bounded capture operation under the currently published
    /// enabled state and ceiling. Failure is immediate and observation-only;
    /// callers omit the payload rather than wait.
    pub(crate) fn try_admit(self: &Arc<Self>) -> Option<CaptureOperation> {
        self.try_admit_with_hook(|| {})
    }

    fn try_admit_with_hook(self: &Arc<Self>, hook: impl FnOnce()) -> Option<CaptureOperation> {
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
        let authority = CaptureAllocationAuthority(Arc::new(CaptureAccount {
            pool: self.clone(),
            ceiling: published.limit,
            live_bytes: AtomicUsize::new(0),
        }));
        Some(CaptureOperation { authority })
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
        if bytes == 0 {
            return;
        }
        assert!(
            self.used
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_sub(bytes)
                })
                .is_ok(),
            "capture operation accounting underflow"
        );
    }

    fn try_charge(&self, bytes: usize, ceiling: usize) -> Result<(), CaptureAllocationError> {
        if bytes == 0 {
            return Ok(());
        }
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let next = used
                .checked_add(bytes)
                .ok_or(CaptureAllocationError::CeilingExceeded)?;
            if next > ceiling {
                return Err(CaptureAllocationError::CeilingExceeded);
            }
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Ok(()),
                Err(current) => used = current,
            }
        }
    }

    #[cfg(test)]
    pub(super) fn fail_next_allocation(&self) {
        self.fail_next_allocation.store(true, Ordering::Release);
    }

    #[cfg(test)]
    fn take_allocation_failure(&self) -> bool {
        self.fail_next_allocation.swap(false, Ordering::AcqRel)
    }
}

/// Allocation account for one observation-only capture attempt. Every owned
/// allocation carries an exact RAII lease against this account.
pub(crate) struct CaptureOperation {
    authority: CaptureAllocationAuthority,
}

struct CaptureAccount {
    pool: Arc<CapturePool>,
    ceiling: usize,
    live_bytes: AtomicUsize,
}

#[derive(Clone)]
pub(crate) struct CaptureAllocationAuthority(Arc<CaptureAccount>);

pub(crate) type CaptureAllocationCharge = ExactAllocationLease<CaptureAllocationAuthority>;
pub(crate) type CaptureBodyBuilder = StableBodyBuilder<CaptureAllocationAuthority>;
pub(crate) type ReservedCaptureBodyBuilder = ReservedStableBodyBuilder<CaptureAllocationAuthority>;
pub(crate) type CaptureBody = StableBody<CaptureAllocationAuthority>;
pub(crate) type CaptureExactBytes = StableExactBytes<CaptureAllocationAuthority>;
pub(crate) type CaptureScratch = StableScratch<CaptureAllocationAuthority>;
pub(crate) type CaptureWorkspace = StableWorkspace<CaptureAllocationAuthority>;
pub(crate) type CaptureWorkspaceAllocation = StableWorkspaceAllocation<CaptureAllocationAuthority>;

impl CaptureOperation {
    pub(crate) fn charged_bytes(&self) -> usize {
        self.authority.0.live_bytes.load(Ordering::Acquire)
    }

    pub(crate) fn ceiling(&self) -> usize {
        self.authority.0.ceiling
    }

    pub(crate) fn charge_exact_allocation(
        &self,
        bytes: usize,
    ) -> Result<CaptureAllocationCharge, CaptureAllocationError> {
        CaptureAllocationCharge::try_new(self.authority.clone(), bytes)
    }

    pub(crate) fn body_buffer(&self) -> CaptureBodyBuilder {
        CaptureBodyBuilder::new(self.authority.clone())
    }

    pub(crate) fn reserve_exact_body(
        &self,
        exact_len: usize,
    ) -> Result<ReservedCaptureBodyBuilder, CaptureAllocationError> {
        CaptureBodyBuilder::reserve_exact(self.authority.clone(), exact_len)
    }

    pub(crate) fn scratch(&self) -> Result<CaptureScratch, CaptureAllocationError> {
        CaptureScratch::try_new(self.authority.clone())
    }

    pub(crate) fn exact_bytes(
        &self,
        len: usize,
    ) -> Result<CaptureExactBytes, CaptureAllocationError> {
        CaptureExactBytes::try_zeroed(self.authority.clone(), len)
    }

    pub(crate) fn workspace_allocation(
        &self,
        bytes: usize,
    ) -> Result<CaptureWorkspaceAllocation, CaptureAllocationError> {
        CaptureWorkspaceAllocation::try_new(self.authority.clone(), bytes)
    }

    pub(crate) fn validate_body(&self, body: &CaptureBody) -> Result<(), CaptureAllocationError> {
        if body.belongs_to(&self.authority) {
            Ok(())
        } else {
            Err(CaptureAllocationError::ForeignAuthority)
        }
    }

    #[cfg(test)]
    pub(crate) fn validate_exact_bytes(
        &self,
        bytes: &CaptureExactBytes,
    ) -> Result<(), CaptureAllocationError> {
        if bytes.belongs_to(&self.authority) {
            Ok(())
        } else {
            Err(CaptureAllocationError::ForeignAuthority)
        }
    }
}

impl AllocationAuthority for CaptureAllocationAuthority {
    type Error = CaptureAllocationError;

    fn try_charge(&self, bytes: usize) -> Result<(), Self::Error> {
        if bytes == 0 {
            return Ok(());
        }
        try_atomic_account_add(&self.0.live_bytes, bytes, self.0.ceiling)?;
        if let Err(error) = self.0.pool.try_charge(bytes, self.0.ceiling) {
            self.0.live_bytes.fetch_sub(bytes, Ordering::AcqRel);
            return Err(error);
        }
        Ok(())
    }

    fn release(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        self.0.pool.release(bytes);
        let live_before = self.0.live_bytes.fetch_sub(bytes, Ordering::AcqRel);
        assert!(live_before >= bytes, "capture account accounting underflow");
    }

    fn is_same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    fn limit_error() -> Self::Error {
        CaptureAllocationError::CeilingExceeded
    }

    fn allocation_error() -> Self::Error {
        CaptureAllocationError::AllocationFailed
    }

    fn reservation_error() -> Self::Error {
        CaptureAllocationError::ReservedLengthMismatch
    }

    #[cfg(test)]
    fn take_allocation_failure(&self) -> bool {
        self.0.pool.take_allocation_failure()
    }
}

fn try_atomic_account_add(
    counter: &AtomicUsize,
    bytes: usize,
    ceiling: usize,
) -> Result<(), CaptureAllocationError> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let next = current
            .checked_add(bytes)
            .ok_or(CaptureAllocationError::CeilingExceeded)?;
        if next > ceiling {
            return Err(CaptureAllocationError::CeilingExceeded);
        }
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum CaptureAllocationError {
    #[error("capture operation ceiling exceeded")]
    CeilingExceeded,
    #[error("capture allocation failed")]
    AllocationFailed,
    #[error("capture buffer belongs to another operation")]
    ForeignAuthority,
    #[error("capture exact reservation length was not satisfied")]
    ReservedLengthMismatch,
}

impl fmt::Debug for CaptureOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptureOperation")
            .field("ceiling", &self.ceiling())
            .field("charged", &self.charged_bytes())
            .finish()
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
    use std::path::PathBuf;
    use std::sync::Barrier;
    use std::thread;

    use super::*;
    use crate::config::compiler::{
        CapturePlan, CaptureWorkingSetPlan, CompiledCaptureEvent, ObservationPlan,
    };
    use crate::observation::{CaptureEvent, ObservationActivation, ProductObservationSnapshot};
    use crate::redaction::{test_snapshot, TestProfile};
    use crate::safety::allocation::{
        body_allocation_bytes, workspace_allocation_bytes, MAX_BUFFER_GROWTH_BYTES,
    };
    use base64::Engine as _;

    fn accounting_capture_activation(
        pool: Arc<CapturePool>,
        limit: usize,
    ) -> ObservationActivation {
        let (redaction, references) = test_snapshot(vec![TestProfile {
            name: "accounting".to_owned(),
            replacement: b"[REMOVED]".to_vec(),
            max_body_bytes: 8,
            max_decoded_body_bytes: 128,
            max_frame_bytes: 64,
            max_message_bytes: 128,
            allow_permessage_deflate: false,
            literals: vec![b"secret".to_vec()],
        }]);
        ProductObservationSnapshot::activate(
            ObservationPlan {
                capture: Some(CapturePlan {
                    events: vec![CompiledCaptureEvent::RequestAllowed],
                    redaction_profile: "accounting".to_owned(),
                    sink: crate::capture::CaptureSinkSpec::new(
                        PathBuf::from("/accounting-captures"),
                        "capture-{requestId}-{suffix}.json".to_owned(),
                        10,
                        100,
                    )
                    .unwrap(),
                    max_body_bytes: 1,
                    max_inflight_body_bytes: limit,
                    working_set: CaptureWorkingSetPlan::default(),
                }),
                ..ObservationPlan::default()
            },
            &redaction,
            references.get("accounting"),
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

    fn try_admit_current(pool: &Arc<CapturePool>) -> Option<CaptureOperation> {
        pool.try_admit()
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
        let old = try_admit_current(&pool).expect("old operation");
        let first = old.charge_exact_allocation(12).expect("first allocation");
        let old_epoch = pool.current_epoch();
        let update = CaptureEpochUpdate::new(pool.clone(), Arc::new(CaptureEpoch::disabled()), 4);
        update
            .publication_guard()
            .expect("publication guard")
            .commit();

        assert_eq!(pool.used(), 12);
        let second = old
            .charge_exact_allocation(4)
            .expect("old ceiling survives");
        assert_eq!(pool.used(), 16);
        assert!(old_epoch
            .capture()
            .expect("old policy")
            .try_admit(CaptureEvent::RequestAllowed)
            .is_none());
        drop((first, second));
        drop(old);
        assert_eq!(pool.used(), 0);
        assert!(try_admit_current(&pool).is_none());
    }

    #[test]
    fn exact_operations_saturate_without_waiting() {
        let pool = enabled_pool(10);
        let first = try_admit_current(&pool).expect("first");
        let second = try_admit_current(&pool).expect("second");
        let first_charge = first.charge_exact_allocation(6).unwrap();
        let second_charge = second.charge_exact_allocation(4).unwrap();
        let third = try_admit_current(&pool).expect("admission does not reserve bytes");
        assert!(matches!(
            third.charge_exact_allocation(1),
            Err(CaptureAllocationError::CeilingExceeded)
        ));
        assert_eq!(pool.used(), 10);
        drop((first_charge, second_charge, first, second, third));
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn exact_allocation_leases_restore_on_each_drop() {
        let pool = enabled_pool(20);
        let operation = try_admit_current(&pool).expect("operation");

        assert_eq!(operation.ceiling(), 20);
        assert_eq!(operation.charged_bytes(), 0);
        let first = operation.charge_exact_allocation(3).unwrap();
        let second = operation.charge_exact_allocation(9).unwrap();
        assert_eq!(operation.charged_bytes(), 12);
        assert_eq!(pool.used(), 12);

        drop(first);
        assert_eq!(operation.charged_bytes(), 9);
        assert_eq!(pool.used(), 9);

        drop(second);
        drop(operation);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn capture_body_allocation_failure_restores_every_charge() {
        let allocation = body_allocation_bytes(1).unwrap();
        let pool = enabled_pool(allocation);
        let operation = try_admit_current(&pool).expect("operation");
        let mut builder = operation.body_buffer();

        pool.fail_next_allocation();
        assert_eq!(
            builder.try_extend_from_slice(b"secret"),
            Err(CaptureAllocationError::AllocationFailed)
        );
        assert_eq!(builder.len(), 0);
        assert_eq!(builder.charged_bytes(), 0);
        assert!(!builder.has_allocated_segments_for_test());
        assert_eq!(operation.charged_bytes(), 0);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn capture_second_chunk_failure_is_terminal_and_releases_the_first_chunk() {
        let one = body_allocation_bytes(1).unwrap();
        let pool = enabled_pool(one * 2);
        let operation = try_admit_current(&pool).expect("operation");
        let mut builder = operation.body_buffer();
        builder
            .try_extend_from_slice(&vec![0xa5; MAX_BUFFER_GROWTH_BYTES])
            .unwrap();
        assert_eq!(pool.used(), one);

        pool.fail_next_allocation();
        assert_eq!(
            builder.try_extend_from_slice(b"tail"),
            Err(CaptureAllocationError::AllocationFailed)
        );
        assert_eq!(builder.len(), 0);
        assert_eq!(builder.charged_bytes(), 0);
        assert!(!builder.has_allocated_segments_for_test());
        assert_eq!(operation.charged_bytes(), 0);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn capture_body_cannot_cross_operation_authorities() {
        let allocation = body_allocation_bytes(1).unwrap();
        let pool = enabled_pool(allocation);
        let owner = try_admit_current(&pool).expect("owner");
        let foreign = try_admit_current(&pool).expect("foreign operation");
        let mut builder = owner.body_buffer();
        builder.try_extend_from_slice(b"secret").unwrap();
        let body = builder.finish();

        assert_eq!(owner.validate_body(&body), Ok(()));
        assert_eq!(
            foreign.validate_body(&body),
            Err(CaptureAllocationError::ForeignAuthority)
        );
        assert_eq!(pool.used(), allocation);
        drop(body);
        assert_eq!(owner.charged_bytes(), 0);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn capture_scratch_and_workspace_restore_exact_projected_charges() {
        let scratch_bytes = body_allocation_bytes(1).unwrap();
        let workspace_bytes = workspace_allocation_bytes(17).unwrap();
        let pool = enabled_pool(scratch_bytes.max(workspace_bytes));
        let operation = try_admit_current(&pool).expect("operation");

        let scratch = operation.scratch().unwrap();
        assert_eq!(operation.charged_bytes(), scratch_bytes);
        assert_eq!(pool.used(), scratch_bytes);
        drop(scratch);
        assert_eq!(operation.charged_bytes(), 0);

        let mut pending = operation.workspace_allocation(17).unwrap();
        assert_eq!(pending.len(), workspace_bytes);
        assert_eq!(operation.charged_bytes(), workspace_bytes);
        while !pending.is_initialized() {
            pending.initialize_next(7);
        }
        let workspace = pending.finish();
        assert_eq!(operation.charged_bytes(), workspace_bytes);
        drop(workspace);
        assert_eq!(operation.charged_bytes(), 0);
        assert_eq!(pool.used(), 0);

        pool.fail_next_allocation();
        assert!(matches!(
            operation.workspace_allocation(17),
            Err(CaptureAllocationError::AllocationFailed)
        ));
        assert_eq!(operation.charged_bytes(), 0);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn capture_exact_bytes_are_branded_and_restore_allocation_failures() {
        let pool = enabled_pool(32);
        let owner = try_admit_current(&pool).expect("owner");
        let foreign = try_admit_current(&pool).expect("foreign operation");
        let mut bytes = owner.exact_bytes(32).unwrap();
        bytes.as_mut_slice().copy_from_slice(&[0xa5; 32]);

        assert_eq!(bytes.len(), 32);
        assert!(!bytes.is_empty());
        assert_eq!(owner.validate_exact_bytes(&bytes), Ok(()));
        assert_eq!(
            foreign.validate_exact_bytes(&bytes),
            Err(CaptureAllocationError::ForeignAuthority)
        );
        assert_eq!(owner.charged_bytes(), 32);
        assert_eq!(pool.used(), 32);
        drop(bytes);
        assert_eq!(owner.charged_bytes(), 0);
        assert_eq!(pool.used(), 0);

        pool.fail_next_allocation();
        assert!(matches!(
            owner.exact_bytes(32),
            Err(CaptureAllocationError::AllocationFailed)
        ));
        assert_eq!(owner.charged_bytes(), 0);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn capture_artifact_base64_uses_exact_charge_after_in_place_truncation() {
        let payload_len = MAX_BUFFER_GROWTH_BYTES + 17;
        let stored_len = MAX_BUFFER_GROWTH_BYTES + 1;
        let encoded_len = base64::encoded_len(stored_len, true).unwrap();
        let peak = body_allocation_bytes(payload_len).unwrap() + encoded_len;
        let pool = enabled_pool(peak);
        let operation = try_admit_current(&pool).expect("operation");
        let payload = (0..payload_len)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut builder = operation.body_buffer();
        builder.try_extend_from_slice(&payload).unwrap();
        let body = builder.finish();

        let artifact = crate::capture::CaptureArtifactBody::encode(
            &operation,
            body,
            stored_len,
            Some("application/octet-stream".to_owned()),
            Some("identity".to_owned()),
        )
        .unwrap();

        assert_eq!(artifact.total_len(), payload_len);
        assert!(artifact.is_truncated());
        assert_eq!(operation.charged_bytes(), encoded_len);
        assert_eq!(pool.used(), encoded_len);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(artifact.data())
                .unwrap(),
            payload[..stored_len]
        );
        drop(artifact);
        assert_eq!(operation.charged_bytes(), 0);
        assert_eq!(pool.used(), 0);

        let mut builder = operation.body_buffer();
        builder.try_extend_from_slice(&payload).unwrap();
        let body = builder.finish();
        pool.fail_next_allocation();
        assert!(matches!(
            crate::capture::CaptureArtifactBody::encode(&operation, body, stored_len, None, None,),
            Err(crate::capture::CaptureArtifactBodyError::Allocation(
                CaptureAllocationError::AllocationFailed
            ))
        ));
        assert_eq!(operation.charged_bytes(), 0);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn owned_capture_body_survives_disablement_and_releases_normally() {
        let allocation = body_allocation_bytes(1).unwrap();
        let pool = enabled_pool(allocation);
        let operation = try_admit_current(&pool).expect("operation");
        let mut builder = operation.body_buffer();
        builder.try_extend_from_slice(b"secret").unwrap();
        let body = builder.finish();

        let update = CaptureEpochUpdate::new(pool.clone(), Arc::new(CaptureEpoch::disabled()), 0);
        update
            .publication_guard()
            .expect("publication guard")
            .commit();

        assert!(try_admit_current(&pool).is_none());
        assert_eq!(pool.used(), allocation);
        assert_eq!(operation.validate_body(&body), Ok(()));
        drop(body);
        assert_eq!(operation.charged_bytes(), 0);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn failed_charge_leaves_operation_and_pool_unchanged() {
        let pool = enabled_pool(10);
        let operation = try_admit_current(&pool).expect("operation");
        let operation_charge = operation.charge_exact_allocation(6).unwrap();
        let contention = try_admit_current(&pool).expect("contention");
        let contention_charge = contention.charge_exact_allocation(4).unwrap();

        assert!(matches!(
            operation.charge_exact_allocation(1),
            Err(CaptureAllocationError::CeilingExceeded)
        ));
        assert_eq!(operation.charged_bytes(), 6);
        assert_eq!(pool.used(), 10);

        drop((contention_charge, contention));
        assert!(matches!(
            operation.charge_exact_allocation(5),
            Err(CaptureAllocationError::CeilingExceeded)
        ));
        assert!(matches!(
            operation.charge_exact_allocation(usize::MAX),
            Err(CaptureAllocationError::CeilingExceeded)
        ));
        assert_eq!(operation.charged_bytes(), 6);
        assert_eq!(pool.used(), 6);

        drop(operation_charge);
        drop(operation);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn arithmetic_overflow_is_an_observation_only_omission() {
        let pool = enabled_pool(usize::MAX);
        let operation = try_admit_current(&pool).expect("maximum operation");
        let charge = operation.charge_exact_allocation(usize::MAX).unwrap();
        let second = try_admit_current(&pool).unwrap();
        assert!(matches!(
            second.charge_exact_allocation(1),
            Err(CaptureAllocationError::CeilingExceeded)
        ));
        drop(charge);
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
                first_pool.try_admit_with_hook(|| {
                    first_entered.wait();
                    finish_first.wait();
                })
            }
        });

        first_entered.wait();
        let second = try_admit_current(&pool)
            .expect("another admission may enter while the first holds a read gate");
        finish_first.wait();
        let first = first.join().expect("first admission thread").unwrap();

        assert_eq!(pool.used(), 0);
        drop((first, second));
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn enabled_lower_limit_preserves_admitted_ceiling_and_rebinds_old_epoch_admission() {
        let pool = enabled_pool(16);
        let old_epoch = pool.current_epoch();
        let existing = try_admit_current(&pool).expect("existing operation");
        let first = existing.charge_exact_allocation(6).unwrap();
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
        assert!(try_admit_current(&pool).is_none());
        finish_publication.wait();
        publisher.join().expect("publisher");

        assert!(pool.current_epoch().is_enabled());
        assert_eq!(pool.committed_limit(), 8);
        assert_eq!(pool.used(), 6);
        let reloaded_old = old_epoch
            .capture()
            .expect("old policy")
            .try_admit(CaptureEvent::RequestAllowed)
            .expect("old leased policy uses newly published enabled ceiling");
        assert_eq!(reloaded_old.ceiling(), 8);
        let current = try_admit_current(&pool).expect("new epoch operation");
        assert_eq!(current.ceiling(), 8);
        let second = existing.charge_exact_allocation(10).unwrap();
        assert_eq!(existing.charged_bytes(), 16);
        assert_eq!(pool.used(), 16);
        assert!(matches!(
            existing.charge_exact_allocation(1),
            Err(CaptureAllocationError::CeilingExceeded)
        ));
        assert!(matches!(
            current.charge_exact_allocation(1),
            Err(CaptureAllocationError::CeilingExceeded)
        ));
        assert_eq!(current.charged_bytes(), 0);
        drop((current, reloaded_old));
        drop((first, second));
        drop(existing);
        assert_eq!(pool.used(), 0);
        let current = try_admit_current(&pool).expect("new ceiling");
        let charge = current.charge_exact_allocation(8).unwrap();
        assert_eq!(current.charged_bytes(), 8);
        assert_eq!(current.ceiling(), 8);
        drop(charge);
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
        let pre_shutdown_zero = try_admit_current(&pool).expect("open admission");
        drop(pre_shutdown_zero);

        pool.close();
        let closed_epoch = pool.current_epoch();
        pool.close();
        stale_guard.commit();

        assert!(pool.is_closed());
        assert_eq!(pool.committed_limit(), 0);
        assert!(!closed_epoch.is_enabled());
        assert!(Arc::ptr_eq(&pool.current_epoch(), &closed_epoch));
        assert!(try_admit_current(&pool).is_none());
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
        assert!(try_admit_current(&pool).is_none());
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
        assert!(try_admit_current(&pool).is_none());
    }
}
