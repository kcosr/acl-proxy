pub(crate) mod allocation;
pub(crate) mod wire_body;

use std::fmt;
use std::sync::Arc;

use http::header::{HeaderMap, HeaderValue};

use crate::config::compiler::{CompiledResourcePlan, HttpBodyResourcePlan, SafetyPlan};
use crate::policy::{HttpWireBodyPlanBrand, HttpWireBodyPlanIndex};
use crate::runtime::SafetySnapshot;

pub(crate) use wire_body::{
    ForwardResponseAdmission, GuardedBody, HttpBodyAdmission, HttpWireBodyGuard,
    ProviderResponseCharge, RequestStagingAuthority, RuntimeReplayLease, WireBodyPool,
    WireBodyQuotaKey,
};

pub(crate) struct ProductSafetySnapshot {
    loop_detection: LoopDetection,
    wire_body_pool: Arc<WireBodyPool>,
    http_body_resources: Box<[HttpBodyResourcePlan]>,
    forward_response_peak_bytes: usize,
    http_wire_body_plan_brand: HttpWireBodyPlanBrand,
}

struct LoopDetection {
    inject: bool,
    header: http::header::HeaderName,
}

impl fmt::Debug for ProductSafetySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductSafetySnapshot")
            .field("loop_injection_enabled", &self.loop_detection.inject)
            .finish_non_exhaustive()
    }
}

impl ProductSafetySnapshot {
    pub(crate) fn activate(
        plan: SafetyPlan,
        resources: &CompiledResourcePlan,
        http_wire_body_plan_brand: HttpWireBodyPlanBrand,
        wire_body_pool: Arc<WireBodyPool>,
    ) -> Result<Self, SafetyActivationError> {
        let expected_cursor_count = resources
            .upgrade_wire_working_set_bytes_by_rule
            .len()
            .checked_add(1)
            .ok_or(SafetyActivationError::InvalidHttpWireBodyPlans)?;
        if resources.http_body_resources_by_cursor.len() != expected_cursor_count
            || http_wire_body_plan_brand.cursor_count() != expected_cursor_count
            || resources
                .http_body_resources_by_cursor
                .iter()
                .any(|resource| {
                    resource
                        .product_incremental_peak_bytes
                        .checked_add(resource.runtime_replay_capacity_bytes)
                        != Some(resource.combined_peak_bytes)
                })
            || resources
                .http_body_resources_by_cursor
                .iter()
                .map(|resource| resource.combined_peak_bytes)
                .max()
                .unwrap_or(0)
                != resources.max_reachable_http_body_combined_peak_bytes
            || resources.forward_response_peak_bytes == 0
            || resources
                .http_body_resources_by_cursor
                .iter()
                .filter(|resource| resource.combined_peak_bytes != 0)
                .try_fold(0_usize, |maximum, resource| {
                    resource
                        .combined_peak_bytes
                        .checked_add(resources.forward_response_peak_bytes)
                        .map(|peak| maximum.max(peak))
                })
                != Some(resources.max_reachable_http_exchange_peak_bytes)
        {
            return Err(SafetyActivationError::InvalidHttpWireBodyPlans);
        }
        Ok(Self {
            loop_detection: LoopDetection {
                inject: plan.loop_detection.inject,
                header: plan.loop_detection.header,
            },
            wire_body_pool,
            http_body_resources: resources
                .http_body_resources_by_cursor
                .clone()
                .into_boxed_slice(),
            forward_response_peak_bytes: resources.forward_response_peak_bytes,
            http_wire_body_plan_brand,
        })
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum SafetyActivationError {
    #[error("compiled HTTP wire-body cursor plans are inconsistent")]
    InvalidHttpWireBodyPlans,
}

impl SafetySnapshot for ProductSafetySnapshot {
    fn contains_loop_marker(&self, headers: &HeaderMap) -> bool {
        headers.contains_key(&self.loop_detection.header)
    }

    fn inject_loop_marker(
        &self,
        headers: &mut HeaderMap,
        request_id: &str,
    ) -> Result<(), InvalidLoopMarker> {
        if !self.loop_detection.inject {
            return Ok(());
        }
        let value = HeaderValue::from_str(request_id).map_err(|_| InvalidLoopMarker)?;
        headers.insert(self.loop_detection.header.clone(), value);
        Ok(())
    }

    fn begin_http_body(
        &self,
        plan: HttpWireBodyPlanIndex,
        quota_key: WireBodyQuotaKey,
    ) -> Result<HttpBodyAdmission, HttpBodyAdmissionError> {
        let resource = plan
            .resolve(self.http_wire_body_plan_brand, &self.http_body_resources)
            .ok_or(HttpBodyAdmissionError::UnknownPlan)?;
        self.wire_body_pool
            .begin_admission(
                resource.product_incremental_peak_bytes,
                resource.runtime_replay_capacity_bytes,
                quota_key,
            )
            .map_err(HttpBodyAdmissionError::Resource)
    }

    fn begin_forward_response(
        &self,
        quota_key: WireBodyQuotaKey,
    ) -> Result<ForwardResponseAdmission, ForwardResponseAdmissionError> {
        self.wire_body_pool
            .begin_forward_response(self.forward_response_peak_bytes, quota_key)
            .map_err(ForwardResponseAdmissionError::Resource)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("request ID is not a valid HTTP loop marker")]
pub(crate) struct InvalidLoopMarker;

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum HttpBodyAdmissionError {
    #[error("HTTP wire-body plan does not belong to the active policy snapshot")]
    UnknownPlan,
    #[error(transparent)]
    Resource(#[from] wire_body::WireBodyBufferError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ForwardResponseAdmissionError {
    #[error("forward response resources are unavailable")]
    Resource(#[source] wire_body::WireBodyBufferError),
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;

    use http::header::{HeaderName, HeaderValue};

    use super::*;
    use crate::config::compiler::{Capacity, CompiledResourcePlan, LoopDetectionPlan, SafetyPlan};
    use crate::config::{compile_config_text, ConfigTextInput};
    use crate::policy::ProductAclSnapshot;
    use http_access_url::canonicalize_http_url;

    fn snapshot(inject: bool) -> ProductSafetySnapshot {
        let (brand, _) = HttpWireBodyPlanIndex::test_pair(2, 0);
        let peak = wire_body::guarded_body_allocation_bytes(128).unwrap();
        ProductSafetySnapshot::activate(
            SafetyPlan {
                loop_detection: LoopDetectionPlan {
                    inject,
                    header: HeaderName::from_static("x-loop-marker"),
                },
            },
            &CompiledResourcePlan {
                http_body_resources_by_cursor: vec![resource(peak, 0), resource(0, 0)],
                max_reachable_http_body_combined_peak_bytes: peak,
                forward_response_peak_bytes: peak,
                max_reachable_http_exchange_peak_bytes: 2 * peak,
                wire_body_full_peak_capacity: Capacity::Finite(4),
                wire_body_quota_key_full_peak_capacity: Capacity::Finite(2),
                webhook_request_allocation_bytes_by_rule: vec![None],
                webhook_callback_allocation_bytes_by_rule: vec![None],
                upgrade_wire_working_set_bytes_by_rule: vec![None],
                max_upgrade_allocation_per_stream: 0,
                max_upgrade_allocation_all_streams: 0,
            },
            brand,
            WireBodyPool::new(peak * 8, peak * 4),
        )
        .expect("test safety plan is consistent")
    }

    fn resource(product: usize, replay: usize) -> HttpBodyResourcePlan {
        HttpBodyResourcePlan {
            product_incremental_peak_bytes: product,
            runtime_replay_capacity_bytes: replay,
            combined_peak_bytes: product.checked_add(replay).unwrap(),
        }
    }

    fn key() -> WireBodyQuotaKey {
        WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), |_| false)
    }

    #[test]
    fn ingress_detection_is_unconditional_when_injection_is_disabled() {
        let snapshot = snapshot(false);
        let mut headers = HeaderMap::new();
        headers.insert("x-loop-marker", HeaderValue::from_static("upstream"));

        assert!(snapshot.contains_loop_marker(&headers));
        snapshot
            .inject_loop_marker(&mut headers, "replacement")
            .expect("disabled injection is a no-op");
        assert_eq!(headers["x-loop-marker"], "upstream");
    }

    #[test]
    fn enabled_injection_replaces_the_existing_origin_marker() {
        let snapshot = snapshot(true);
        let mut headers = HeaderMap::new();
        headers.insert("x-loop-marker", HeaderValue::from_static("old"));

        snapshot
            .inject_loop_marker(&mut headers, "request-123")
            .expect("valid request ID");
        assert_eq!(headers["x-loop-marker"], "request-123");
    }

    #[test]
    fn invalid_marker_is_atomic() {
        let snapshot = snapshot(true);
        let mut headers = HeaderMap::new();
        headers.insert("x-loop-marker", HeaderValue::from_static("old"));

        assert_eq!(
            snapshot.inject_loop_marker(&mut headers, "bad\nvalue"),
            Err(InvalidLoopMarker)
        );
        assert_eq!(headers["x-loop-marker"], "old");
    }

    #[test]
    fn snapshot_debug_omits_header_and_pool_details() {
        let debug = format!("{:?}", snapshot(true));
        assert!(debug.contains("loop_injection_enabled: true"));
        assert!(!debug.contains("x-loop-marker"));
        assert!(!debug.contains("1024"));
    }

    #[test]
    fn snapshot_starts_a_guard_against_the_shared_pool() {
        let snapshot = snapshot(true);
        let admission = snapshot
            .begin_http_body(
                HttpWireBodyPlanIndex::test_for_brand(snapshot.http_wire_body_plan_brand, 0),
                key(),
            )
            .expect("known plan");
        let (guard, replay, _staging) = admission.into_parts();
        let mut body = guard.buffer();
        body.try_extend_from_slice(&[1; 128]).expect("within peak");
        assert_eq!(guard.live_bytes(), body.charged_bytes());
        assert_eq!(replay.capacity_bytes(), 0);
    }

    #[test]
    fn forwarded_response_reservation_is_held_until_admission_drops() {
        let snapshot = snapshot(true);
        let expected = snapshot.forward_response_peak_bytes;
        let admission = snapshot
            .begin_forward_response(key())
            .expect("forward response capacity is available");

        assert_eq!(admission.capacity_bytes(), expected);
        assert_eq!(snapshot.wire_body_pool.global_charge(), expected);
        drop(admission);
        assert_eq!(snapshot.wire_body_pool.global_charge(), 0);
    }

    #[test]
    fn snapshot_rejects_unknown_plan_without_granting_a_guard() {
        let snapshot = snapshot(true);
        assert!(matches!(
            snapshot.begin_http_body(
                HttpWireBodyPlanIndex::test_for_brand(snapshot.http_wire_body_plan_brand, 2),
                key(),
            ),
            Err(HttpBodyAdmissionError::UnknownPlan)
        ));
        assert_eq!(snapshot.wire_body_pool.global_charge(), 0);
    }

    #[test]
    fn snapshot_rejects_foreign_plan_brand_without_granting_a_guard() {
        let snapshot = snapshot(true);
        let (_, foreign) = HttpWireBodyPlanIndex::test_pair(2, 0);
        assert!(matches!(
            snapshot.begin_http_body(foreign, key()),
            Err(HttpBodyAdmissionError::UnknownPlan)
        ));
        assert_eq!(snapshot.wire_body_pool.global_charge(), 0);
    }

    #[test]
    fn activation_rejects_missing_terminal_cursor_plan() {
        let (brand, _) = HttpWireBodyPlanIndex::test_pair(2, 0);
        let peak = wire_body::guarded_body_allocation_bytes(128).unwrap();
        let result = ProductSafetySnapshot::activate(
            SafetyPlan {
                loop_detection: LoopDetectionPlan {
                    inject: true,
                    header: HeaderName::from_static("x-loop-marker"),
                },
            },
            &CompiledResourcePlan {
                http_body_resources_by_cursor: vec![resource(peak, 0)],
                max_reachable_http_body_combined_peak_bytes: peak,
                forward_response_peak_bytes: peak,
                max_reachable_http_exchange_peak_bytes: 2 * peak,
                wire_body_full_peak_capacity: Capacity::Finite(4),
                wire_body_quota_key_full_peak_capacity: Capacity::Finite(2),
                webhook_request_allocation_bytes_by_rule: vec![None],
                webhook_callback_allocation_bytes_by_rule: vec![None],
                upgrade_wire_working_set_bytes_by_rule: vec![None],
                max_upgrade_allocation_per_stream: 0,
                max_upgrade_allocation_all_streams: 0,
            },
            brand,
            WireBodyPool::new(peak * 8, peak * 4),
        );

        assert!(matches!(
            result,
            Err(SafetyActivationError::InvalidHttpWireBodyPlans)
        ));
    }

    #[test]
    fn compiler_terminal_cursor_survives_final_delegate_resume() {
        let compiled = compile_config_text(ConfigTextInput {
            text: r#"
schema_version = 3

[listeners.explicit_http]
bind = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[authorization.providers.approval]
kind = "process"
command = "/bin/approval"

[policy]
default = "deny"

[[policy.rules]]
id = "final-delegate"
decision = "delegate"
urls = ["https://example.test/**"]
authorization_provider = "approval"
"#,
            source_path: Path::new("/tmp/terminal-cursor.toml"),
            config_root: Path::new("/tmp"),
        })
        .expect("test config compiles");
        let plan = compiled.reloadable_plan;
        assert_eq!(
            plan.resource_plan.combined_http_body_peaks_for_test().len(),
            2
        );
        assert!(plan.resource_plan.combined_http_body_peaks_for_test()[0] > 0);
        assert_eq!(plan.resource_plan.combined_http_body_peaks_for_test()[1], 0);

        let policy = ProductAclSnapshot::compile(
            &plan.policy,
            http_access_types::PolicyGeneration::new(1).unwrap(),
            http_access_types::SnapshotIdentity::new(),
            &[],
        )
        .expect("compiled policy activates");
        let safety = ProductSafetySnapshot::activate(
            plan.safety,
            &plan.resource_plan,
            policy.resources().wire_body_plan_brand(),
            WireBodyPool::new(1, 1),
        )
        .expect("compiler and policy cursor domains agree");
        let url = canonicalize_http_url("https://example.test/path").unwrap();
        let facts = http_access_types::InterceptedRequestFacts::new(
            http_access_types::IngressMode::ExplicitHttps,
            http_access_types::HttpVersion::Http11,
            http_access_types::HttpMethod::new("GET").unwrap(),
            url,
            Vec::new(),
            http_access_types::BodyMetadata::new(http_access_types::BodyFraming::None),
            None,
        )
        .unwrap();
        let header_facts =
            http_access_types::PolicyHeaderFacts::new(Vec::new(), Vec::new()).unwrap();
        let input = http_access_policy_acl::EvaluationInput::new(
            &facts,
            Ipv4Addr::new(192, 0, 2, 1).into(),
            &header_facts,
            1,
            http_access_types::BodyRepresentation::PreservedContentCoded,
            http_access_types::BodyObservation::unobserved(),
        )
        .unwrap();
        let first = policy.snapshot().evaluate(&input).unwrap();
        let http_access_policy_acl::PolicyEvaluation::Delegate(delegated) = first else {
            panic!("final rule should delegate")
        };
        let http_access_types::EffectivePolicy::Rule { id, .. } =
            delegated.provenance().effective_policy()
        else {
            panic!("delegate should retain rule provenance")
        };
        assert_eq!(id.as_str(), "final-delegate");
        let terminal = policy
            .snapshot()
            .resolve_delegate(
                delegated,
                http_access_policy_acl::ProviderDisposition::Pass,
                &input,
            )
            .unwrap();
        let http_access_policy_acl::PolicyEvaluation::Deny { provenance } = terminal else {
            panic!("passing the final delegate should reach the deny default")
        };
        let terminal_cursor = policy.resource_cursor(&provenance).unwrap();
        let terminal_wire_body_plan = policy.resources().wire_body_plan(terminal_cursor).unwrap();
        assert!(matches!(
            provenance.effective_policy(),
            http_access_types::EffectivePolicy::Default
        ));
        let admission = safety
            .begin_http_body(terminal_wire_body_plan, key())
            .expect("terminal cursor has a compiler-produced safety plan");
        let (guard, replay, _staging) = admission.into_parts();
        assert_eq!(guard.cursor_peak_bytes(), 0);
        assert_eq!(replay.capacity_bytes(), 0);
    }
}
