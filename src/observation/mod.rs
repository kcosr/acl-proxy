mod capture;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use crate::config::compiler::{
    CapturePlan, CompiledCaptureEvent, CompiledLogLevel, ObservationPlan,
    PolicyDecisionLoggingPlan, ReloadableLoggingPlan,
};
use crate::redaction::{ProfileHandle, RedactionActivation, RedactionSnapshot};
use crate::runtime::{GenerationOwner, ObservationSnapshot, RedactionProfileIndex};

use capture::CaptureEpochUpdate;
pub(crate) use capture::{CapturePermit, CapturePool};

/// Process-owned observation state shared by all candidate, active, and
/// retiring generations. Static sink construction will live behind this same
/// boundary; generations receive only their reloadable policy and narrow
/// shared admission handles.
pub(crate) struct ProductObservationRuntime {
    capture_pool: Arc<CapturePool>,
}

impl ProductObservationRuntime {
    pub(crate) fn new() -> Self {
        Self {
            capture_pool: CapturePool::new(),
        }
    }

    pub(crate) fn activate(
        &self,
        plan: ObservationPlan,
        redaction: &RedactionActivation,
    ) -> Result<ObservationActivation, ObservationActivationError> {
        ProductObservationSnapshot::activate(plan, redaction, self.capture_pool.clone())
    }

    /// Leases the capture-only state currently published for established
    /// streams. The returned handle has no generation backreference.
    pub(crate) fn current_capture_epoch(&self) -> Arc<CaptureEpoch> {
        self.capture_pool.current_epoch()
    }

    pub(crate) fn begin_shutdown(&self) {
        self.capture_pool.close();
    }

    #[cfg(test)]
    pub(crate) fn committed_capture_limit(&self) -> usize {
        self.capture_pool.committed_limit()
    }
}

/// Immutable capture-only state. Ordinary requests retain the epoch embedded
/// in their generation, while established streams lease the independently
/// published current epoch at a logical-message boundary.
pub(crate) struct CaptureEpoch {
    capture: Option<CapturePolicy>,
}

impl CaptureEpoch {
    pub(crate) fn disabled() -> Self {
        Self { capture: None }
    }

    fn enabled(capture: CapturePolicy) -> Self {
        Self {
            capture: Some(capture),
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.capture.is_some()
    }

    pub(crate) fn capture(&self) -> Option<&CapturePolicy> {
        self.capture.as_ref()
    }
}

impl fmt::Debug for CaptureEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptureEpoch")
            .field("capture_enabled", &self.is_enabled())
            .field(
                "capture_event_count",
                &self
                    .capture
                    .as_ref()
                    .map_or(0, |capture| capture.events.len()),
            )
            .finish()
    }
}

pub(crate) struct ProductObservationSnapshot {
    logging: ObservationLoggingPolicy,
    capture_epoch: Arc<CaptureEpoch>,
}

impl fmt::Debug for ProductObservationSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductObservationSnapshot")
            .field("logging_level", &log_level_name(self.logging.level))
            .field("capture_enabled", &self.capture_epoch.is_enabled())
            .field(
                "capture_event_count",
                &self
                    .capture_epoch
                    .capture()
                    .map_or(0, |capture| capture.events.len()),
            )
            .finish()
    }
}

impl ProductObservationSnapshot {
    pub(crate) fn activate(
        plan: ObservationPlan,
        redaction: &RedactionActivation,
        capture_pool: Arc<CapturePool>,
    ) -> Result<ObservationActivation, ObservationActivationError> {
        let ObservationPlan { logging, capture } = plan;
        let logging = ObservationLoggingPolicy::from_plan(logging);
        let (capture_epoch, proposed_limit) = match capture {
            None => (Arc::new(CaptureEpoch::disabled()), 0),
            Some(plan) => {
                let profile_name = &plan.redaction_profile;
                let profile_index = redaction
                    .profile_index(profile_name)
                    .ok_or(ObservationActivationError::MissingCaptureProfile)?;
                let profile = RedactionSnapshot::profile(redaction, profile_index)
                    .ok_or(ObservationActivationError::MissingCaptureProfile)?;
                let proposed_limit = plan.max_inflight_body_bytes;
                (
                    Arc::new(CaptureEpoch::enabled(CapturePolicy::activate(
                        plan,
                        profile_index,
                        profile,
                        Arc::downgrade(&capture_pool),
                    ))),
                    proposed_limit,
                )
            }
        };
        let owner = Arc::new(CaptureEpochUpdate::new(
            capture_pool,
            capture_epoch.clone(),
            proposed_limit,
        ));
        Ok(ObservationActivation {
            snapshot: Self {
                logging,
                capture_epoch,
            },
            owner,
        })
    }

    pub(crate) fn logging(&self) -> &ObservationLoggingPolicy {
        &self.logging
    }

    pub(crate) fn capture_epoch(&self) -> &Arc<CaptureEpoch> {
        &self.capture_epoch
    }

    pub(crate) fn capture(&self) -> Option<&CapturePolicy> {
        self.capture_epoch.capture()
    }
}

impl ObservationSnapshot for ProductObservationSnapshot {
    fn logging(&self) -> &ObservationLoggingPolicy {
        ProductObservationSnapshot::logging(self)
    }

    fn capture_epoch(&self) -> &Arc<CaptureEpoch> {
        ProductObservationSnapshot::capture_epoch(self)
    }
}

pub(crate) struct ObservationActivation {
    snapshot: ProductObservationSnapshot,
    owner: Arc<CaptureEpochUpdate>,
}

impl fmt::Debug for ObservationActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservationActivation")
            .field("snapshot", &self.snapshot)
            .field("capture_limit", &self.owner.proposed_limit())
            .finish()
    }
}

impl ObservationActivation {
    pub(crate) fn snapshot(&self) -> &ProductObservationSnapshot {
        &self.snapshot
    }

    pub(crate) fn into_parts(self) -> (ProductObservationSnapshot, Arc<dyn GenerationOwner>) {
        (self.snapshot, self.owner)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum ObservationActivationError {
    #[error("capture references a redaction profile that is not present in this activation")]
    MissingCaptureProfile,
}

#[derive(Clone, Copy)]
pub(crate) struct ObservationLoggingPolicy {
    level: CompiledLogLevel,
    decisions: DecisionLoggingPolicy,
}

impl ObservationLoggingPolicy {
    fn from_plan(plan: ReloadableLoggingPlan) -> Self {
        Self {
            level: plan.level,
            decisions: DecisionLoggingPolicy::from_plan(plan.policy_decisions),
        }
    }

    pub(crate) fn level(&self) -> CompiledLogLevel {
        self.level
    }

    pub(crate) fn decisions(&self) -> DecisionLoggingPolicy {
        self.decisions
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DecisionLoggingPolicy {
    allows: bool,
    denies: bool,
    allow_level: CompiledLogLevel,
    deny_level: CompiledLogLevel,
}

impl DecisionLoggingPolicy {
    fn from_plan(plan: PolicyDecisionLoggingPlan) -> Self {
        Self {
            allows: plan.allows,
            denies: plan.denies,
            allow_level: plan.allow_level,
            deny_level: plan.deny_level,
        }
    }

    pub(crate) fn enabled(&self, decision: CaptureDecision) -> bool {
        match decision {
            CaptureDecision::Allow => self.allows,
            CaptureDecision::Deny => self.denies,
        }
    }

    pub(crate) fn level(&self, decision: CaptureDecision) -> CompiledLogLevel {
        match decision {
            CaptureDecision::Allow => self.allow_level,
            CaptureDecision::Deny => self.deny_level,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CaptureDecision {
    Allow,
    Deny,
}

pub(crate) struct CapturePolicy {
    events: CaptureEventSet,
    profile_index: RedactionProfileIndex,
    profile: ProfileHandle,
    directory: PathBuf,
    filename: String,
    max_body_bytes: usize,
    max_files: usize,
    max_total_bytes: u64,
    pool: Weak<CapturePool>,
}

impl fmt::Debug for CapturePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturePolicy")
            .field("event_count", &self.events.len())
            .field("max_body_bytes", &self.max_body_bytes)
            .field("max_files", &self.max_files)
            .field("max_total_bytes", &self.max_total_bytes)
            .finish_non_exhaustive()
    }
}

impl CapturePolicy {
    fn activate(
        plan: CapturePlan,
        profile_index: RedactionProfileIndex,
        profile: ProfileHandle,
        pool: Weak<CapturePool>,
    ) -> Self {
        let CapturePlan {
            events,
            redaction_profile: _,
            directory,
            filename,
            max_body_bytes,
            max_inflight_body_bytes: _,
            max_files,
            max_total_bytes,
        } = plan;
        Self {
            events: CaptureEventSet::from_compiled(events),
            profile_index,
            profile,
            directory,
            filename,
            max_body_bytes,
            max_files,
            max_total_bytes,
            pool,
        }
    }

    pub(crate) fn captures(&self, event: CaptureEvent) -> bool {
        self.events.contains(event)
    }

    pub(crate) fn try_admit(&self, event: CaptureEvent, bytes: usize) -> Option<CapturePermit> {
        if !self.captures(event) {
            return None;
        }
        self.pool.upgrade()?.try_acquire(bytes)
    }

    pub(crate) fn profile_index(&self) -> RedactionProfileIndex {
        self.profile_index
    }

    pub(crate) fn profile(&self) -> &ProfileHandle {
        &self.profile
    }

    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn filename(&self) -> &str {
        &self.filename
    }

    pub(crate) fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    pub(crate) fn max_files(&self) -> usize {
        self.max_files
    }

    pub(crate) fn max_total_bytes(&self) -> u64 {
        self.max_total_bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CaptureEvent {
    RequestAllowed,
    ResponseAllowed,
    RequestDenied,
    ResponseDenied,
}

#[derive(Clone, Copy, Default)]
struct CaptureEventSet(u8);

impl CaptureEventSet {
    fn from_compiled(events: Vec<CompiledCaptureEvent>) -> Self {
        let mut set = Self::default();
        for event in events {
            set.0 |= match event {
                CompiledCaptureEvent::RequestAllowed => 1 << 0,
                CompiledCaptureEvent::ResponseAllowed => 1 << 1,
                CompiledCaptureEvent::RequestDenied => 1 << 2,
                CompiledCaptureEvent::ResponseDenied => 1 << 3,
            };
        }
        set
    }

    fn contains(self, event: CaptureEvent) -> bool {
        let bit = match event {
            CaptureEvent::RequestAllowed => 1 << 0,
            CaptureEvent::ResponseAllowed => 1 << 1,
            CaptureEvent::RequestDenied => 1 << 2,
            CaptureEvent::ResponseDenied => 1 << 3,
        };
        self.0 & bit != 0
    }

    fn len(self) -> usize {
        self.0.count_ones() as usize
    }
}

fn log_level_name(level: CompiledLogLevel) -> &'static str {
    match level {
        CompiledLogLevel::Trace => "trace",
        CompiledLogLevel::Debug => "debug",
        CompiledLogLevel::Info => "info",
        CompiledLogLevel::Warn => "warn",
        CompiledLogLevel::Error => "error",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::compiler::{
        CompiledRedactionPayloads, RedactionPlan, RedactionProfilePlan, RedactionRulePlan,
    };
    use crate::redaction::RedactionSnapshot;
    use crate::runtime::{CleanupReason, RuntimeError};

    fn logging() -> ReloadableLoggingPlan {
        ReloadableLoggingPlan {
            level: CompiledLogLevel::Info,
            policy_decisions: PolicyDecisionLoggingPlan {
                allows: false,
                denies: true,
                allow_level: CompiledLogLevel::Info,
                deny_level: CompiledLogLevel::Warn,
            },
        }
    }

    fn plan(
        profile_name: &str,
        events: Vec<CompiledCaptureEvent>,
        limit: usize,
    ) -> ObservationPlan {
        ObservationPlan {
            logging: logging(),
            capture: Some(CapturePlan {
                events,
                redaction_profile: profile_name.to_owned(),
                directory: PathBuf::from("/private/capture-name"),
                filename: "private-{requestId}-{suffix}.json".to_owned(),
                max_body_bytes: 8,
                max_inflight_body_bytes: limit,
                max_files: 10,
                max_total_bytes: 100,
            }),
        }
    }

    fn disabled_plan() -> ObservationPlan {
        ObservationPlan {
            logging: logging(),
            capture: None,
        }
    }

    fn profile_plan(max_body_bytes: usize) -> RedactionProfilePlan {
        RedactionProfilePlan {
            replacement: b"[REMOVED]".to_vec(),
            max_body_bytes,
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
        }
    }

    fn redaction<'a>(entries: impl IntoIterator<Item = (&'a str, usize)>) -> RedactionActivation {
        let mut profiles = BTreeMap::new();
        for (name, max_body_bytes) in entries {
            profiles.insert(name.to_owned(), profile_plan(max_body_bytes));
        }
        RedactionSnapshot::activate(RedactionPlan { profiles }, || false).expect("profiles")
    }

    fn activate(
        pool: Arc<CapturePool>,
        profile_name: &str,
        events: Vec<CompiledCaptureEvent>,
        limit: usize,
        profile_body_limit: usize,
    ) -> ObservationActivation {
        let redaction = redaction([(profile_name, profile_body_limit)]);
        ProductObservationSnapshot::activate(plan(profile_name, events, limit), &redaction, pool)
            .expect("observation activation")
    }

    fn commit(owner: &Arc<dyn GenerationOwner>) {
        owner
            .publication_guard()
            .expect("publication guard")
            .commit();
    }

    #[test]
    fn activation_resolves_the_named_typed_profile_from_one_activation() {
        let pool = CapturePool::new();
        let redaction = redaction([("first-profile", 17), ("private-profile-name", 73)]);
        let activation = ProductObservationSnapshot::activate(
            plan(
                "private-profile-name",
                vec![CompiledCaptureEvent::RequestDenied],
                16,
            ),
            &redaction,
            pool,
        )
        .expect("observation activation");
        let capture = activation.snapshot().capture().expect("capture");

        assert_eq!(
            capture.profile_index(),
            redaction
                .profile_index("private-profile-name")
                .expect("profile index")
        );
        assert_eq!(capture.profile().limits().max_body_bytes, 73);
        assert!(!format!("{activation:?}").contains("private-profile-name"));
    }

    #[test]
    fn event_set_and_decision_logging_are_immutable_typed_policy() {
        let pool = CapturePool::new();
        let activation = activate(
            pool,
            "profile",
            vec![
                CompiledCaptureEvent::RequestAllowed,
                CompiledCaptureEvent::ResponseDenied,
            ],
            16,
            8,
        );
        let snapshot = activation.snapshot();
        let capture = snapshot.capture().expect("capture");

        assert!(capture.captures(CaptureEvent::RequestAllowed));
        assert!(capture.captures(CaptureEvent::ResponseDenied));
        assert!(!capture.captures(CaptureEvent::ResponseAllowed));
        assert!(!snapshot
            .logging()
            .decisions()
            .enabled(CaptureDecision::Allow));
        assert!(snapshot
            .logging()
            .decisions()
            .enabled(CaptureDecision::Deny));
        assert!(matches!(
            snapshot.logging().decisions().level(CaptureDecision::Deny),
            CompiledLogLevel::Warn
        ));
    }

    #[test]
    fn rejected_candidate_does_not_change_capture_admission() {
        let pool = CapturePool::enabled_for_accounting_test(8);
        let original_epoch = pool.current_epoch();
        let activation = activate(
            pool.clone(),
            "profile",
            vec![CompiledCaptureEvent::RequestAllowed],
            32,
            8,
        );
        let (_snapshot, owner) = activation.into_parts();
        {
            let _rejected = owner.publication_guard().expect("publication guard");
        }
        drop(owner);

        assert_eq!(pool.committed_limit(), 8);
        assert!(Arc::ptr_eq(&pool.current_epoch(), &original_epoch));
        assert!(pool.try_acquire(9).is_none());
    }

    #[test]
    fn committed_candidate_updates_the_shared_limit() {
        let pool = CapturePool::enabled_for_accounting_test(8);
        let activation = activate(
            pool.clone(),
            "profile",
            vec![CompiledCaptureEvent::RequestAllowed],
            32,
            8,
        );
        let (snapshot, owner) = activation.into_parts();
        commit(&owner);

        assert_eq!(pool.committed_limit(), 32);
        assert!(Arc::ptr_eq(&pool.current_epoch(), snapshot.capture_epoch()));
        assert!(pool.try_acquire(32).is_some());
    }

    #[test]
    fn capture_disablement_publishes_a_new_epoch() {
        let pool = CapturePool::new();
        let enabled = activate(
            pool.clone(),
            "profile",
            vec![CompiledCaptureEvent::RequestAllowed],
            16,
            8,
        );
        let (enabled_snapshot, enabled_owner) = enabled.into_parts();
        commit(&enabled_owner);
        let enabled_epoch = pool.current_epoch();
        assert!(enabled_epoch.is_enabled());
        assert!(Arc::ptr_eq(
            &enabled_epoch,
            enabled_snapshot.capture_epoch()
        ));

        let disabled_redaction = redaction(std::iter::empty());
        let disabled = ProductObservationSnapshot::activate(
            disabled_plan(),
            &disabled_redaction,
            pool.clone(),
        )
        .expect("disabled observation activation");
        let (disabled_snapshot, disabled_owner) = disabled.into_parts();
        let disabled_epoch = disabled_snapshot.capture_epoch().clone();

        assert!(Arc::ptr_eq(&pool.current_epoch(), &enabled_epoch));
        assert_eq!(pool.committed_limit(), 16);
        commit(&disabled_owner);

        let published = pool.current_epoch();
        assert!(!published.is_enabled());
        assert!(Arc::ptr_eq(&published, &disabled_epoch));
        assert!(!Arc::ptr_eq(&published, &enabled_epoch));
        assert_eq!(pool.committed_limit(), 0);

        // The retired generation keeps its immutable policy, but admission is
        // governed by the atomically published disabled epoch and limit.
        assert!(enabled_snapshot.capture().is_some());
        assert!(enabled_snapshot
            .capture()
            .expect("enabled capture policy")
            .try_admit(CaptureEvent::RequestAllowed, 0)
            .is_none());
        assert!(disabled_snapshot.capture().is_none());
    }

    #[test]
    fn ordinary_snapshot_retains_epoch_without_current_publication_ownership() {
        let pool = CapturePool::new();
        let activation = activate(
            pool.clone(),
            "profile",
            vec![CompiledCaptureEvent::RequestAllowed],
            16,
            8,
        );
        let (snapshot, owner) = activation.into_parts();
        let epoch = snapshot.capture_epoch().clone();
        let weak = Arc::downgrade(&epoch);
        commit(&owner);
        drop(epoch);

        let disabled_redaction = redaction(std::iter::empty());
        let disabled =
            ProductObservationSnapshot::activate(disabled_plan(), &disabled_redaction, pool)
                .expect("disabled observation activation");
        let (disabled_snapshot, disabled_owner) = disabled.into_parts();
        commit(&disabled_owner);
        drop((owner, disabled_owner));

        assert!(
            weak.upgrade().is_some(),
            "the ordinary snapshot owns its epoch"
        );
        drop(snapshot);
        assert!(weak.upgrade().is_none());
        drop(disabled_snapshot);
    }

    #[test]
    fn shutdown_disables_new_epochs_without_invalidating_a_lease() {
        let runtime = ProductObservationRuntime::new();
        let redaction = redaction([("profile", 8)]);
        let activation = runtime
            .activate(
                plan("profile", vec![CompiledCaptureEvent::RequestAllowed], 16),
                &redaction,
            )
            .expect("observation activation");
        let (_snapshot, owner) = activation.into_parts();
        commit(&owner);
        let leased = runtime.current_capture_epoch();
        assert!(leased.is_enabled());

        runtime.begin_shutdown();

        assert!(!runtime.current_capture_epoch().is_enabled());
        assert_eq!(runtime.committed_capture_limit(), 0);
        assert!(leased.is_enabled());
    }

    #[test]
    fn shutdown_closure_rejects_stale_candidate_and_old_epoch_zero_byte_admission() {
        let runtime = ProductObservationRuntime::new();
        let redaction = redaction([("profile", 8)]);
        let activation = runtime
            .activate(
                plan("profile", vec![CompiledCaptureEvent::RequestAllowed], 16),
                &redaction,
            )
            .expect("observation activation");
        let (snapshot, owner) = activation.into_parts();
        let old_epoch = snapshot.capture_epoch().clone();
        let mut publication = owner
            .publication_guard()
            .expect("candidate is live before shutdown");

        runtime.begin_shutdown();
        publication.commit();

        assert!(!runtime.current_capture_epoch().is_enabled());
        assert_eq!(runtime.committed_capture_limit(), 0);
        assert!(old_epoch.is_enabled());
        assert!(old_epoch
            .capture()
            .expect("old capture policy")
            .try_admit(CaptureEvent::RequestAllowed, 0)
            .is_none());
        assert!(matches!(
            owner.publication_guard(),
            Err(RuntimeError::ShuttingDown)
        ));
    }

    #[test]
    fn epochs_share_one_pool_and_saturation_omits_without_waiting() {
        let pool = CapturePool::new();
        let first = activate(
            pool.clone(),
            "first-profile",
            vec![CompiledCaptureEvent::RequestAllowed],
            10,
            8,
        );
        let (first_snapshot, first_owner) = first.into_parts();
        commit(&first_owner);
        let second = activate(
            pool.clone(),
            "second-profile",
            vec![CompiledCaptureEvent::RequestAllowed],
            10,
            9,
        );
        let (second_snapshot, second_owner) = second.into_parts();
        commit(&second_owner);

        let first_permit = first_snapshot
            .capture()
            .expect("first capture")
            .try_admit(CaptureEvent::RequestAllowed, 6)
            .expect("first admission");
        let second_permit = second_snapshot
            .capture()
            .expect("second capture")
            .try_admit(CaptureEvent::RequestAllowed, 4)
            .expect("second admission");
        assert!(second_snapshot
            .capture()
            .expect("second capture")
            .try_admit(CaptureEvent::RequestAllowed, 1)
            .is_none());
        assert!(first_snapshot
            .capture()
            .expect("first capture")
            .try_admit(CaptureEvent::ResponseAllowed, 0)
            .is_none());
        drop((first_permit, second_permit));
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn debug_omits_profile_name_path_filename_and_matcher_material() {
        let pool = CapturePool::new();
        let activation = activate(
            pool,
            "secret-profile-name",
            vec![CompiledCaptureEvent::RequestDenied],
            16,
            8,
        );
        let debug = format!("{activation:?}");

        for forbidden in [
            "secret-profile-name",
            "private/capture-name",
            "private-{requestId}",
            "secret",
            "[REMOVED]",
        ] {
            assert!(!debug.contains(forbidden), "debug disclosed {forbidden:?}");
        }
    }

    #[test]
    fn missing_authored_profile_is_rejected() {
        let pool = CapturePool::new();
        let redaction = redaction([("different-profile", 8)]);
        assert_eq!(
            ProductObservationSnapshot::activate(
                plan(
                    "missing-profile",
                    vec![CompiledCaptureEvent::RequestDenied],
                    8,
                ),
                &redaction,
                pool,
            )
            .expect_err("missing binding"),
            ObservationActivationError::MissingCaptureProfile
        );
    }

    #[tokio::test]
    async fn generation_owner_contract_is_noop_after_publication() {
        let pool = CapturePool::enabled_for_accounting_test(8);
        let activation = activate(
            pool.clone(),
            "profile",
            vec![CompiledCaptureEvent::RequestAllowed],
            32,
            8,
        );
        let (_snapshot, owner) = activation.into_parts();
        let mut guard = owner.publication_guard().expect("publication guard");
        guard.commit();
        guard.commit();
        drop(guard);

        owner.retirement_started(CleanupReason::Retired);
        owner.cleanup(CleanupReason::Retired).await;
        owner.cleanup(CleanupReason::Shutdown).await;

        assert_eq!(pool.committed_limit(), 32);
    }
}
