mod capture;

use std::fmt;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::{Arc, Weak};

use http_access_redaction::{RedactionProfile, RedactionSnapshot};
use http_access_runtime::BestEffortAdmission;
#[cfg(not(test))]
use http_access_runtime::ObservationQueue;
pub(crate) use http_access_types::CaptureEvent;
use http_access_types::{
    CaptureEventPolicy, DecisionAuditFacts, DecisionDisposition, RedactionRef,
};

use crate::capture::{
    CaptureArtifactJob, CaptureArtifactSubmitError, CaptureArtifactWorker, CaptureSinkSpec,
    CaptureWorkerStartError,
};
use crate::config::compiler::{
    CapturePlan, CompiledCaptureEvent, CompiledDecisionLogLevel, CompiledLogLevel, ObservationPlan,
    ReloadableLoggingPlan,
};
#[cfg(not(test))]
use crate::logging::PolicyDecisionLogSink;
use crate::runtime::{GenerationOwner, ObservationSnapshot};

use capture::CaptureEpochUpdate;
pub(crate) use capture::{
    CaptureAllocationAuthority, CaptureAllocationCharge, CaptureAllocationError, CaptureBody,
    CaptureBodyBuilder, CaptureExactBytes, CaptureOperation, CapturePool, CaptureScratch,
    CaptureWorkspace, CaptureWorkspaceAllocation, ReservedCaptureBodyBuilder,
};

#[cfg(not(test))]
const DECISION_QUEUE_CAPACITY: usize = 1_024;
#[cfg(not(test))]
const DECISION_MAX_FACT_BYTES: usize = 8 * 1_024;
#[cfg(not(test))]
const DECISION_POOL_BYTES: usize = (DECISION_QUEUE_CAPACITY + 1) * DECISION_MAX_FACT_BYTES;

/// Process-owned observation state shared by all candidate, active, and
/// retiring generations. Static sink construction will live behind this same
/// boundary; generations receive only their reloadable policy and narrow
/// shared admission handles.
pub(crate) struct ProductObservationRuntime {
    capture_pool: Arc<CapturePool>,
    capture_worker: CaptureArtifactWorker,
    #[cfg(test)]
    forwarding_terminal_completions: std::sync::atomic::AtomicUsize,
    #[cfg(not(test))]
    info_decisions: ObservationQueue,
    #[cfg(not(test))]
    warn_decisions: ObservationQueue,
}

impl ProductObservationRuntime {
    pub(crate) fn try_new(
        max_pending_records: usize,
    ) -> Result<Self, ProductObservationRuntimeStartError> {
        #[cfg(not(test))]
        let info_decisions = decision_queue(CompiledDecisionLogLevel::Info)?;
        #[cfg(not(test))]
        let warn_decisions = decision_queue(CompiledDecisionLogLevel::Warn)?;
        Ok(Self {
            capture_pool: CapturePool::new(),
            capture_worker: CaptureArtifactWorker::start(max_pending_records)?,
            #[cfg(test)]
            forwarding_terminal_completions: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(not(test))]
            info_decisions,
            #[cfg(not(test))]
            warn_decisions,
        })
    }

    pub(crate) fn activate(
        &self,
        plan: ObservationPlan,
        redaction: &RedactionSnapshot,
        capture_redaction: Option<&RedactionRef>,
    ) -> Result<ObservationActivation, ObservationActivationError> {
        ProductObservationSnapshot::activate(
            plan,
            redaction,
            capture_redaction,
            self.capture_pool.clone(),
        )
    }

    /// Leases the capture-only state currently published for established
    /// streams. The returned handle has no generation backreference.
    pub(crate) fn current_capture_epoch(&self) -> Arc<CaptureEpoch> {
        self.capture_pool.current_epoch()
    }

    pub(crate) fn try_submit_capture(
        &self,
        job: CaptureArtifactJob,
    ) -> Result<(), CaptureArtifactSubmitError> {
        self.capture_worker.try_submit(job)
    }

    pub(crate) fn try_submit_decision(
        &self,
        level: CompiledDecisionLogLevel,
        facts: DecisionAuditFacts,
    ) -> BestEffortAdmission {
        #[cfg(not(test))]
        {
            match level {
                CompiledDecisionLogLevel::Info => self.info_decisions.try_submit(facts),
                CompiledDecisionLogLevel::Warn => self.warn_decisions.try_submit(facts),
            }
        }
        #[cfg(test)]
        {
            let _ = (level, facts);
            BestEffortAdmission::DroppedClosed
        }
    }

    pub(crate) fn begin_shutdown(&self) {
        self.capture_pool.close();
        self.capture_worker.begin_shutdown();
        #[cfg(not(test))]
        {
            self.info_decisions.close_admission();
            self.warn_decisions.close_admission();
        }
    }

    pub(crate) async fn shutdown(&self) {
        self.begin_shutdown();
        self.capture_worker.shutdown().await;
    }

    #[cfg(test)]
    pub(crate) fn committed_capture_limit(&self) -> usize {
        self.capture_pool.committed_limit()
    }

    #[cfg(test)]
    pub(crate) fn record_forwarding_terminal_completion(&self) {
        self.forwarding_terminal_completions
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    #[cfg(test)]
    pub(crate) fn forwarding_terminal_completions(&self) -> usize {
        self.forwarding_terminal_completions
            .load(std::sync::atomic::Ordering::Acquire)
    }
}

/// One owned best-effort decision event. Moving this value through dispatch
/// keeps submission single-shot; dropping a cancelled dispatch still attempts
/// the same nonblocking submission.
pub(crate) struct PendingDecisionSubmission {
    target: DecisionSubmissionTarget,
    level: Option<CompiledDecisionLogLevel>,
    facts: Option<DecisionAuditFacts>,
}

impl PendingDecisionSubmission {
    pub(crate) fn new(
        target: DecisionSubmissionTarget,
        level: Option<CompiledDecisionLogLevel>,
        facts: DecisionAuditFacts,
    ) -> Self {
        Self {
            target,
            level,
            facts: Some(facts),
        }
    }

    pub(crate) fn omitted(
        target: DecisionSubmissionTarget,
        level: Option<CompiledDecisionLogLevel>,
    ) -> Self {
        Self {
            target,
            level,
            facts: None,
        }
    }

    pub(crate) fn submit_now(&mut self) {
        let Some(facts) = self.facts.take() else {
            return;
        };
        let Some(level) = self.level else {
            return;
        };
        match &self.target {
            DecisionSubmissionTarget::Runtime(runtime) => {
                let _ = runtime.try_submit_decision(level, facts);
            }
            #[cfg(test)]
            DecisionSubmissionTarget::Probe(submissions) => {
                submissions.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }

    pub(crate) fn discard(mut self) {
        self.facts.take();
    }
}

#[derive(Clone)]
pub(crate) enum DecisionSubmissionTarget {
    Runtime(Arc<ProductObservationRuntime>),
    #[cfg(test)]
    Probe(Arc<std::sync::atomic::AtomicUsize>),
}

impl From<Arc<ProductObservationRuntime>> for DecisionSubmissionTarget {
    fn from(runtime: Arc<ProductObservationRuntime>) -> Self {
        Self::Runtime(runtime)
    }
}

impl Drop for PendingDecisionSubmission {
    fn drop(&mut self) {
        self.submit_now();
    }
}

#[cfg(not(test))]
fn decision_queue(
    level: CompiledDecisionLogLevel,
) -> Result<ObservationQueue, http_access_runtime::RuntimeError> {
    ObservationQueue::new(
        DECISION_QUEUE_CAPACITY,
        DECISION_MAX_FACT_BYTES,
        DECISION_POOL_BYTES,
        Box::new(PolicyDecisionLogSink::new(level)),
    )
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductObservationRuntimeStartError {
    #[error("decision observation worker construction failed")]
    Decision(#[from] http_access_runtime::RuntimeError),
    #[error("capture worker construction failed")]
    Capture(#[from] CaptureWorkerStartError),
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
    decision_logging: DecisionLoggingPolicy,
    capture_epoch: Arc<CaptureEpoch>,
}

impl fmt::Debug for ProductObservationSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductObservationSnapshot")
            .field("decision_logging", &self.decision_logging)
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
        redaction: &RedactionSnapshot,
        capture_redaction: Option<&RedactionRef>,
        capture_pool: Arc<CapturePool>,
    ) -> Result<ObservationActivation, ObservationActivationError> {
        let ObservationPlan { logging, capture } = plan;
        let decision_logging = DecisionLoggingPolicy::from_plan(logging);
        let (capture_epoch, proposed_limit) = match capture {
            None => (Arc::new(CaptureEpoch::disabled()), 0),
            Some(plan) => {
                let reference =
                    capture_redaction.ok_or(ObservationActivationError::MissingCaptureProfile)?;
                let profile = redaction
                    .profile(reference)
                    .map_err(|_| ObservationActivationError::MissingCaptureProfile)?;
                let proposed_limit = plan.max_inflight_body_bytes;
                (
                    Arc::new(CaptureEpoch::enabled(CapturePolicy::activate(
                        plan,
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
                decision_logging,
                capture_epoch,
            },
            owner,
        })
    }

    pub(crate) fn capture_epoch(&self) -> &Arc<CaptureEpoch> {
        &self.capture_epoch
    }

    pub(crate) const fn decision_level(
        &self,
        disposition: DecisionDisposition,
    ) -> Option<CompiledDecisionLogLevel> {
        self.decision_logging.level(disposition)
    }

    #[cfg(test)]
    pub(crate) fn capture(&self) -> Option<&CapturePolicy> {
        self.capture_epoch.capture()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DecisionLoggingPolicy {
    allow: Option<CompiledDecisionLogLevel>,
    deny: Option<CompiledDecisionLogLevel>,
}

impl DecisionLoggingPolicy {
    fn from_plan(plan: ReloadableLoggingPlan) -> Self {
        let decisions = plan.policy_decisions;
        Self {
            allow: decisions
                .allows
                .then_some(decisions.allow_level)
                .filter(|level| log_level_admits(plan.level, *level)),
            deny: decisions
                .denies
                .then_some(decisions.deny_level)
                .filter(|level| log_level_admits(plan.level, *level)),
        }
    }

    const fn level(self, disposition: DecisionDisposition) -> Option<CompiledDecisionLogLevel> {
        match disposition {
            DecisionDisposition::Allow => self.allow,
            DecisionDisposition::Deny => self.deny,
        }
    }
}

const fn log_level_admits(threshold: CompiledLogLevel, event: CompiledDecisionLogLevel) -> bool {
    match (threshold, event) {
        (CompiledLogLevel::Trace | CompiledLogLevel::Debug | CompiledLogLevel::Info, _) => true,
        (CompiledLogLevel::Warn, CompiledDecisionLogLevel::Warn) => true,
        (CompiledLogLevel::Warn | CompiledLogLevel::Error, CompiledDecisionLogLevel::Info)
        | (CompiledLogLevel::Error, CompiledDecisionLogLevel::Warn) => false,
    }
}

impl ObservationSnapshot for ProductObservationSnapshot {
    fn capture_epoch(&self) -> &Arc<CaptureEpoch> {
        ProductObservationSnapshot::capture_epoch(self)
    }

    fn decision_level(&self, disposition: DecisionDisposition) -> Option<CompiledDecisionLogLevel> {
        ProductObservationSnapshot::decision_level(self, disposition)
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
    #[cfg(test)]
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

pub(crate) struct CapturePolicy {
    events: CaptureEventPolicy,
    profile: RedactionProfile,
    sink: CaptureSinkSpec,
    max_body_bytes: usize,
    pool: Weak<CapturePool>,
}

impl fmt::Debug for CapturePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturePolicy")
            .field("event_count", &self.events.len())
            .field("max_body_bytes", &self.max_body_bytes)
            .field("max_files", &self.sink.max_files())
            .field("max_total_bytes", &self.sink.max_total_bytes())
            .finish_non_exhaustive()
    }
}

impl CapturePolicy {
    fn activate(plan: CapturePlan, profile: RedactionProfile, pool: Weak<CapturePool>) -> Self {
        let CapturePlan {
            events,
            redaction_profile: _,
            sink,
            max_body_bytes,
            max_inflight_body_bytes: _,
            ..
        } = plan;
        Self {
            events: CaptureEventPolicy::new(events.into_iter().map(|event| match event {
                CompiledCaptureEvent::RequestAllowed => CaptureEvent::RequestAllowed,
                CompiledCaptureEvent::ResponseAllowed => CaptureEvent::ResponseAllowed,
                CompiledCaptureEvent::RequestDenied => CaptureEvent::RequestDenied,
                CompiledCaptureEvent::ResponseDenied => CaptureEvent::ResponseDenied,
            }))
            .expect("compiled capture events are nonempty and duplicate-free"),
            profile,
            sink,
            max_body_bytes,
            pool,
        }
    }

    pub(crate) fn captures(&self, event: CaptureEvent) -> bool {
        self.events.captures(event)
    }

    pub(crate) fn try_admit(&self, event: CaptureEvent) -> Option<CaptureOperation> {
        if !self.captures(event) {
            return None;
        }
        self.pool.upgrade()?.try_admit()
    }

    pub(crate) fn profile(&self) -> &RedactionProfile {
        &self.profile
    }

    pub(crate) fn sink(&self) -> &CaptureSinkSpec {
        &self.sink
    }

    pub(crate) fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::config::compiler::{CaptureWorkingSetPlan, PolicyDecisionLoggingPlan};
    use crate::redaction::{test_snapshot, TestProfile};
    use crate::runtime::{CleanupReason, RuntimeError};

    fn decision_facts() -> DecisionAuditFacts {
        let request_id = http_access_types::StableId::new("pending-decision").unwrap();
        let method = http_access_types::HttpMethod::new("GET").unwrap();
        let url = http_access_url::canonicalize_http_url("https://example.test/resource").unwrap();
        let source = http_access_types::DecisionAuditSource::Policy(
            http_access_types::DecisionProvenance::new(
                http_access_types::PolicyGeneration::new(1).unwrap(),
                http_access_types::EffectivePolicy::Default,
                http_access_types::DecisionReason::new(
                    http_access_types::DecisionReasonCategory::Policy,
                    1,
                ),
                None,
            ),
        );
        DecisionAuditFacts::new(http_access_types::DecisionAuditFactsInput {
            request_id: &request_id,
            disposition: DecisionDisposition::Allow,
            method: Some(&method),
            url: Some(&url),
            peer_ip: None,
            source: &source,
            sensitive_header_presence: &[],
        })
        .unwrap()
    }

    #[test]
    fn pending_decision_explicit_submission_is_exactly_once() {
        let submissions = Arc::new(AtomicUsize::new(0));
        let mut pending = PendingDecisionSubmission::new(
            DecisionSubmissionTarget::Probe(submissions.clone()),
            Some(CompiledDecisionLogLevel::Info),
            decision_facts(),
        );

        pending.submit_now();
        pending.submit_now();
        drop(pending);

        assert_eq!(submissions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn pending_decision_drop_is_the_single_fallback_submission() {
        let submissions = Arc::new(AtomicUsize::new(0));
        drop(PendingDecisionSubmission::new(
            DecisionSubmissionTarget::Probe(submissions.clone()),
            Some(CompiledDecisionLogLevel::Info),
            decision_facts(),
        ));

        assert_eq!(submissions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn discarded_or_disabled_pending_decisions_do_not_submit() {
        let submissions = Arc::new(AtomicUsize::new(0));
        PendingDecisionSubmission::new(
            DecisionSubmissionTarget::Probe(submissions.clone()),
            Some(CompiledDecisionLogLevel::Info),
            decision_facts(),
        )
        .discard();
        drop(PendingDecisionSubmission::new(
            DecisionSubmissionTarget::Probe(submissions.clone()),
            None,
            decision_facts(),
        ));

        assert_eq!(submissions.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn omitted_pending_decision_never_submits() {
        let submissions = Arc::new(AtomicUsize::new(0));
        let mut pending = PendingDecisionSubmission::omitted(
            DecisionSubmissionTarget::Probe(submissions.clone()),
            Some(CompiledDecisionLogLevel::Warn),
        );

        pending.submit_now();
        drop(pending);

        assert_eq!(submissions.load(Ordering::SeqCst), 0);
    }

    fn plan(
        profile_name: &str,
        events: Vec<CompiledCaptureEvent>,
        limit: usize,
    ) -> ObservationPlan {
        ObservationPlan {
            capture: Some(CapturePlan {
                events,
                redaction_profile: profile_name.to_owned(),
                sink: CaptureSinkSpec::new(
                    PathBuf::from("/private/capture-name"),
                    "private-{requestId}-{suffix}.json".to_owned(),
                    10,
                    100,
                )
                .unwrap(),
                max_body_bytes: 8,
                max_inflight_body_bytes: limit,
                working_set: CaptureWorkingSetPlan::default(),
            }),
            ..ObservationPlan::default()
        }
    }

    fn disabled_plan() -> ObservationPlan {
        ObservationPlan::default()
    }

    fn redaction<'a>(
        entries: impl IntoIterator<Item = (&'a str, usize)>,
    ) -> (
        RedactionSnapshot,
        BTreeMap<String, http_access_types::RedactionRef>,
    ) {
        test_snapshot(
            entries
                .into_iter()
                .map(|(name, max_body_bytes)| TestProfile {
                    name: name.to_owned(),
                    replacement: b"[REMOVED]".to_vec(),
                    max_body_bytes,
                    max_decoded_body_bytes: 128,
                    max_frame_bytes: 64,
                    max_message_bytes: 128,
                    allow_permessage_deflate: false,
                    literals: vec![b"secret".to_vec()],
                })
                .collect(),
        )
    }

    fn activate(
        pool: Arc<CapturePool>,
        profile_name: &str,
        events: Vec<CompiledCaptureEvent>,
        limit: usize,
        profile_body_limit: usize,
    ) -> ObservationActivation {
        let (redaction, references) = redaction([(profile_name, profile_body_limit)]);
        ProductObservationSnapshot::activate(
            plan(profile_name, events, limit),
            &redaction,
            references.get(profile_name),
            pool,
        )
        .expect("observation activation")
    }

    fn commit(owner: &Arc<dyn GenerationOwner>) {
        owner
            .publication_guard()
            .expect("publication guard")
            .commit();
    }

    fn enabled_pool(limit: usize) -> Arc<CapturePool> {
        let pool = CapturePool::new();
        let activation = activate(
            pool.clone(),
            "initial-profile",
            vec![CompiledCaptureEvent::RequestAllowed],
            limit,
            8,
        );
        let (_, owner) = activation.into_parts();
        commit(&owner);
        assert!(pool.current_epoch().is_enabled());
        pool
    }

    #[test]
    fn activation_resolves_the_named_typed_profile_from_one_activation() {
        let pool = CapturePool::new();
        let (redaction, references) =
            redaction([("first-profile", 17), ("private-profile-name", 73)]);
        let activation = ProductObservationSnapshot::activate(
            plan(
                "private-profile-name",
                vec![CompiledCaptureEvent::RequestDenied],
                16,
            ),
            &redaction,
            references.get("private-profile-name"),
            pool,
        )
        .expect("observation activation");
        let capture = activation.snapshot().capture().expect("capture");

        assert_eq!(capture.profile().limits().max_body_bytes(), 73);
        assert!(!format!("{activation:?}").contains("private-profile-name"));
    }

    #[test]
    fn event_set_is_immutable_typed_policy() {
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
    }

    #[test]
    fn generation_snapshot_filters_decisions_and_selects_static_severity_queue() {
        let (redaction, _) = redaction(std::iter::empty());
        let snapshot = ProductObservationSnapshot::activate(
            ObservationPlan {
                logging: ReloadableLoggingPlan {
                    level: CompiledLogLevel::Info,
                    policy_decisions: PolicyDecisionLoggingPlan {
                        allows: true,
                        denies: true,
                        allow_level: CompiledDecisionLogLevel::Info,
                        deny_level: CompiledDecisionLogLevel::Warn,
                    },
                },
                capture: None,
            },
            &redaction,
            None,
            CapturePool::new(),
        )
        .unwrap();
        assert_eq!(
            snapshot
                .snapshot()
                .decision_level(DecisionDisposition::Allow),
            Some(CompiledDecisionLogLevel::Info)
        );
        assert_eq!(
            snapshot
                .snapshot()
                .decision_level(DecisionDisposition::Deny),
            Some(CompiledDecisionLogLevel::Warn)
        );

        let warn_threshold = DecisionLoggingPolicy::from_plan(ReloadableLoggingPlan {
            level: CompiledLogLevel::Warn,
            policy_decisions: PolicyDecisionLoggingPlan {
                allows: true,
                denies: true,
                allow_level: CompiledDecisionLogLevel::Info,
                deny_level: CompiledDecisionLogLevel::Warn,
            },
        });
        assert_eq!(warn_threshold.level(DecisionDisposition::Allow), None);
        assert_eq!(
            warn_threshold.level(DecisionDisposition::Deny),
            Some(CompiledDecisionLogLevel::Warn)
        );

        let disabled = DecisionLoggingPolicy::from_plan(ReloadableLoggingPlan {
            level: CompiledLogLevel::Trace,
            policy_decisions: PolicyDecisionLoggingPlan {
                allows: false,
                denies: false,
                allow_level: CompiledDecisionLogLevel::Warn,
                deny_level: CompiledDecisionLogLevel::Warn,
            },
        });
        assert_eq!(disabled.level(DecisionDisposition::Allow), None);
        assert_eq!(disabled.level(DecisionDisposition::Deny), None);
    }

    #[test]
    fn rejected_candidate_does_not_change_capture_admission() {
        let pool = enabled_pool(8);
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
        let operation = pool.try_admit().expect("enabled admission");
        assert!(operation.charge_exact_allocation(9).is_err());
    }

    #[test]
    fn committed_candidate_updates_the_shared_limit() {
        let pool = enabled_pool(8);
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
        let operation = pool.try_admit().expect("enabled admission");
        assert!(operation.charge_exact_allocation(32).is_ok());
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

        let (disabled_redaction, _) = redaction(std::iter::empty());
        let disabled = ProductObservationSnapshot::activate(
            disabled_plan(),
            &disabled_redaction,
            None,
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
            .try_admit(CaptureEvent::RequestAllowed)
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

        let (disabled_redaction, _) = redaction(std::iter::empty());
        let disabled =
            ProductObservationSnapshot::activate(disabled_plan(), &disabled_redaction, None, pool)
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

    #[tokio::test]
    async fn shutdown_disables_new_epochs_without_invalidating_a_lease() {
        let runtime = ProductObservationRuntime::try_new(1).expect("capture worker");
        let (redaction, references) = redaction([("profile", 8)]);
        let activation = runtime
            .activate(
                plan("profile", vec![CompiledCaptureEvent::RequestAllowed], 16),
                &redaction,
                references.get("profile"),
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
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_closure_rejects_stale_candidate_and_old_epoch_zero_byte_admission() {
        let runtime = ProductObservationRuntime::try_new(1).expect("capture worker");
        let (redaction, references) = redaction([("profile", 8)]);
        let activation = runtime
            .activate(
                plan("profile", vec![CompiledCaptureEvent::RequestAllowed], 16),
                &redaction,
                references.get("profile"),
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
            .try_admit(CaptureEvent::RequestAllowed)
            .is_none());
        assert!(matches!(
            owner.publication_guard(),
            Err(RuntimeError::ShuttingDown)
        ));
        runtime.shutdown().await;
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

        let first_operation = first_snapshot
            .capture()
            .expect("first capture")
            .try_admit(CaptureEvent::RequestAllowed)
            .expect("first admission");
        let first_charge = first_operation.charge_exact_allocation(6).unwrap();
        let second_operation = second_snapshot
            .capture()
            .expect("second capture")
            .try_admit(CaptureEvent::RequestAllowed)
            .expect("second admission");
        let second_charge = second_operation.charge_exact_allocation(4).unwrap();
        let third_operation = second_snapshot
            .capture()
            .expect("second capture")
            .try_admit(CaptureEvent::RequestAllowed)
            .expect("admission does not reserve bytes");
        assert!(third_operation.charge_exact_allocation(1).is_err());
        assert!(first_snapshot
            .capture()
            .expect("first capture")
            .try_admit(CaptureEvent::ResponseAllowed)
            .is_none());
        drop((first_charge, second_charge));
        drop((first_operation, second_operation, third_operation));
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
        let (redaction, _) = redaction([("different-profile", 8)]);
        assert_eq!(
            ProductObservationSnapshot::activate(
                plan(
                    "missing-profile",
                    vec![CompiledCaptureEvent::RequestDenied],
                    8,
                ),
                &redaction,
                None,
                pool,
            )
            .expect_err("missing binding"),
            ObservationActivationError::MissingCaptureProfile
        );
    }

    #[tokio::test]
    async fn generation_owner_contract_is_noop_after_publication() {
        let pool = enabled_pool(8);
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
