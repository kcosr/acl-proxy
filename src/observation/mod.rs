mod capture;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::v3_compile::{
    CapturePlan, CompiledCaptureEvent, CompiledLogLevel, ObservationPlan,
    PolicyDecisionLoggingPlan, ReloadableLoggingPlan,
};
use crate::redaction::{ProfileHandle, RedactionActivation, RedactionSnapshot};
use crate::runtime::{GenerationOwner, ObservationSnapshot, RedactionProfileIndex};

use capture::CaptureLimitUpdate;
pub(crate) use capture::{CapturePermit, CapturePool};

pub(crate) struct ProductObservationSnapshot {
    logging: ObservationLoggingPolicy,
    capture: Option<CapturePolicy>,
}

impl fmt::Debug for ProductObservationSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductObservationSnapshot")
            .field("logging_level", &log_level_name(self.logging.level))
            .field("capture_enabled", &self.capture.is_some())
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

impl ProductObservationSnapshot {
    pub(crate) fn activate(
        plan: ObservationPlan,
        redaction: &RedactionActivation,
        capture_pool: Arc<CapturePool>,
    ) -> Result<ObservationActivation, ObservationActivationError> {
        let ObservationPlan { logging, capture } = plan;
        let logging = ObservationLoggingPolicy::from_plan(logging);
        let (capture, proposed_limit) = match capture {
            None => (None, 0),
            Some(plan) => {
                let profile_name = &plan.redaction_profile;
                let profile_index = redaction
                    .profile_index(profile_name)
                    .ok_or(ObservationActivationError::MissingCaptureProfile)?;
                let profile = RedactionSnapshot::profile(redaction, profile_index)
                    .ok_or(ObservationActivationError::MissingCaptureProfile)?;
                let proposed_limit = plan.max_inflight_body_bytes;
                (
                    Some(CapturePolicy::activate(
                        plan,
                        profile_index,
                        profile,
                        capture_pool.clone(),
                    )),
                    proposed_limit,
                )
            }
        };
        let owner = Arc::new(CaptureLimitUpdate::new(capture_pool, proposed_limit));
        Ok(ObservationActivation {
            snapshot: Self { logging, capture },
            owner,
        })
    }

    pub(crate) fn logging(&self) -> &ObservationLoggingPolicy {
        &self.logging
    }

    pub(crate) fn capture(&self) -> Option<&CapturePolicy> {
        self.capture.as_ref()
    }
}

impl ObservationSnapshot for ProductObservationSnapshot {}

pub(crate) struct ObservationActivation {
    snapshot: ProductObservationSnapshot,
    owner: Arc<CaptureLimitUpdate>,
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
    pool: Arc<CapturePool>,
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
        pool: Arc<CapturePool>,
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
        self.pool.try_acquire(bytes)
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
    use crate::config::v3_compile::{
        CompiledRedactionPayloads, RedactionPlan, RedactionProfilePlan, RedactionRulePlan,
    };
    use crate::redaction::RedactionSnapshot;
    use crate::runtime::CleanupReason;

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
        RedactionSnapshot::activate(RedactionPlan { profiles }).expect("profiles")
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
        let pool = CapturePool::new(0);
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
        let pool = CapturePool::new(0);
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
        let pool = CapturePool::new(8);
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
        assert!(pool.try_acquire(9).is_none());
    }

    #[test]
    fn committed_candidate_updates_the_shared_limit() {
        let pool = CapturePool::new(8);
        let activation = activate(
            pool.clone(),
            "profile",
            vec![CompiledCaptureEvent::RequestAllowed],
            32,
            8,
        );
        let (_snapshot, owner) = activation.into_parts();
        commit(&owner);

        assert_eq!(pool.committed_limit(), 32);
        assert!(pool.try_acquire(32).is_some());
    }

    #[test]
    fn epochs_share_one_pool_and_saturation_omits_without_waiting() {
        let pool = CapturePool::new(0);
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
        let pool = CapturePool::new(0);
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
        let pool = CapturePool::new(0);
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
        let pool = CapturePool::new(8);
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
