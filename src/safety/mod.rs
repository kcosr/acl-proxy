pub(crate) mod wire_body;

use std::fmt;
use std::sync::Arc;

use http::header::{HeaderMap, HeaderValue};

use crate::config::v3_compile::{CompiledResourcePlan, SafetyPlan};
use crate::policy::{HttpWireBodyPlanBrand, HttpWireBodyPlanIndex};
use crate::runtime::SafetySnapshot;

pub(crate) use wire_body::{GuardedBody, HttpWireBodyGuard, WireBodyPool, WireBodyQuotaKey};

pub(crate) struct ProductSafetySnapshot {
    loop_detection: LoopDetection,
    wire_body_pool: Arc<WireBodyPool>,
    http_wire_body_peaks: Box<[usize]>,
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
            .upgrade_allocation_bytes_by_rule
            .len()
            .checked_add(1)
            .ok_or(SafetyActivationError::InvalidHttpWireBodyPlans)?;
        if resources.http_wire_body_peak_bytes_by_cursor.len() != expected_cursor_count
            || http_wire_body_plan_brand.cursor_count() != expected_cursor_count
        {
            return Err(SafetyActivationError::InvalidHttpWireBodyPlans);
        }
        Ok(Self {
            loop_detection: LoopDetection {
                inject: plan.loop_detection.inject,
                header: plan.loop_detection.header,
            },
            wire_body_pool,
            http_wire_body_peaks: resources
                .http_wire_body_peak_bytes_by_cursor
                .clone()
                .into_boxed_slice(),
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
    ) -> Result<HttpWireBodyGuard, UnknownHttpWireBodyPlan> {
        let peak = plan
            .resolve(self.http_wire_body_plan_brand, &self.http_wire_body_peaks)
            .ok_or(UnknownHttpWireBodyPlan)?;
        Ok(self.wire_body_pool.begin(peak, quota_key))
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("request ID is not a valid HTTP loop marker")]
pub(crate) struct InvalidLoopMarker;

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("HTTP wire-body plan does not belong to the active policy snapshot")]
pub(crate) struct UnknownHttpWireBodyPlan;

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;

    use http::header::{HeaderName, HeaderValue};
    use http::Method;

    use super::*;
    use crate::config::v3_compile::{
        Capacity, CompiledResourcePlan, LoopDetectionPlan, SafetyPlan,
    };
    use crate::config::{compile_config_text, ConfigTextInput};
    use crate::policy::CompiledPolicySnapshot;
    use crate::runtime::{CredentialSourceRegistry, ProviderRegistry, RedactionProfileRegistry};
    use crate::url::canonicalize_http_url;

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
                http_wire_body_peak_bytes_by_cursor: vec![peak, 0],
                max_reachable_http_wire_body_peak_bytes: peak,
                wire_body_full_peak_capacity: Capacity::Finite(8),
                wire_body_quota_key_full_peak_capacity: Capacity::Finite(4),
                upgrade_allocation_bytes_by_rule: vec![None],
                max_upgrade_allocation_per_stream: 0,
                max_upgrade_allocation_all_streams: 0,
            },
            brand,
            WireBodyPool::new(peak * 8, peak * 4),
        )
        .expect("test safety plan is consistent")
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
        let guard = snapshot
            .begin_http_body(
                HttpWireBodyPlanIndex::test_for_brand(snapshot.http_wire_body_plan_brand, 0),
                key(),
            )
            .expect("known plan");
        let mut body = guard.buffer();
        body.try_extend_from_slice(&[1; 128]).expect("within peak");
        assert_eq!(guard.live_bytes(), body.charged_bytes());
    }

    #[test]
    fn snapshot_rejects_unknown_plan_without_granting_a_guard() {
        let snapshot = snapshot(true);
        assert!(matches!(
            snapshot.begin_http_body(
                HttpWireBodyPlanIndex::test_for_brand(snapshot.http_wire_body_plan_brand, 2),
                key(),
            ),
            Err(UnknownHttpWireBodyPlan)
        ));
        assert_eq!(snapshot.wire_body_pool.global_charge(), 0);
    }

    #[test]
    fn snapshot_rejects_foreign_plan_brand_without_granting_a_guard() {
        let snapshot = snapshot(true);
        let (_, foreign) = HttpWireBodyPlanIndex::test_pair(2, 0);
        assert!(matches!(
            snapshot.begin_http_body(foreign, key()),
            Err(UnknownHttpWireBodyPlan)
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
                http_wire_body_peak_bytes_by_cursor: vec![peak],
                max_reachable_http_wire_body_peak_bytes: peak,
                wire_body_full_peak_capacity: Capacity::Finite(8),
                wire_body_quota_key_full_peak_capacity: Capacity::Finite(4),
                upgrade_allocation_bytes_by_rule: vec![None],
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
            plan.resource_plan.http_wire_body_peak_bytes_by_cursor.len(),
            2
        );
        assert!(plan.resource_plan.http_wire_body_peak_bytes_by_cursor[0] > 0);
        assert_eq!(plan.resource_plan.http_wire_body_peak_bytes_by_cursor[1], 0);

        let providers = ProviderRegistry::from_names(plan.authorization.providers.into_keys());
        let policy_activation = CompiledPolicySnapshot::activate(
            plan.policy,
            &providers,
            &RedactionProfileRegistry::from_names([]),
            &CredentialSourceRegistry::from_names([]),
        )
        .expect("compiled policy activates");
        let safety = ProductSafetySnapshot::activate(
            plan.safety,
            &plan.resource_plan,
            policy_activation.wire_body_plan_brand(),
            WireBodyPool::new(1, 1),
        )
        .expect("compiler and policy cursor domains agree");
        let (policy, _) = policy_activation.into_parts();
        let url = canonicalize_http_url("https://example.test/path").unwrap();
        let first = policy.evaluate(
            &url,
            Ipv4Addr::new(192, 0, 2, 1).into(),
            &Method::GET,
            &HeaderMap::new(),
            |_| false,
        );
        assert_eq!(first.matched.as_ref().unwrap().id(), "final-delegate");
        let terminal = first.matched.unwrap().resume_cursor().resume(
            &url,
            Ipv4Addr::new(192, 0, 2, 1).into(),
            &Method::GET,
            &HeaderMap::new(),
            |_| false,
        );
        assert!(terminal.matched.is_none());
        let guard = safety
            .begin_http_body(terminal.wire_body_plan(), key())
            .expect("terminal cursor has a compiler-produced safety plan");
        assert_eq!(guard.cursor_peak_bytes(), 0);
    }
}
