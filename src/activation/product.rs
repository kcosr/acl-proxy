use std::sync::Arc;

use crate::authorization::{AuthorizationActivationError, ProductAuthorizationSnapshot};
use crate::config::v3_compile::ReloadableProductPlan;
use crate::config::{StaticFingerprint, StaticFingerprintError, StaticProductConfig};
use crate::credentials::CredentialResolverSnapshot;
use crate::egress::{EgressActivationError, EgressSnapshot};
use crate::observation::ProductObservationRuntime;
use crate::policy::CompiledPolicySnapshot;
use crate::redaction::{RedactionSnapshot, SnapshotError};
use crate::runtime::{
    ActivatedGeneration, ActivationCancellation, BoxFuture, CandidateActivator, CleanupReason,
    GenerationId, GenerationOwner, ProviderRegistry, RuntimeError,
};
use crate::safety::{ProductSafetySnapshot, WireBodyPool};

use super::owner::ProductGenerationOwner;

/// Process-lifetime factory for complete generation candidates.
///
/// Static admission pools are shared by every active, candidate, and retiring
/// generation. Every other handle returned by activation is generation-owned.
pub(crate) struct ProductActivator {
    static_fingerprint: StaticFingerprint,
    wire_body_pool: Arc<WireBodyPool>,
    observation_runtime: Arc<ProductObservationRuntime>,
}

impl ProductActivator {
    pub(crate) fn new(static_config: &StaticProductConfig) -> Result<Self, StaticFingerprintError> {
        let static_fingerprint = StaticFingerprint::from_config(static_config)?;
        Ok(Self {
            static_fingerprint,
            wire_body_pool: WireBodyPool::new(
                static_config.service.max_inflight_wire_body_bytes,
                static_config
                    .service
                    .max_inflight_wire_body_bytes_per_quota_key,
            ),
            observation_runtime: Arc::new(ProductObservationRuntime::new()),
        })
    }

    pub(crate) fn observation_runtime_handle(&self) -> Arc<ProductObservationRuntime> {
        self.observation_runtime.clone()
    }

    async fn activate_generation(
        &self,
        plan: ReloadableProductPlan,
        cancellation: ActivationCancellation,
    ) -> Result<ActivatedGeneration, RuntimeError> {
        cancellation.check()?;
        let ReloadableProductPlan {
            request_timeout,
            max_content_decoding_expansion_ratio,
            egress,
            policy,
            authorization,
            credentials,
            redaction,
            observation,
            safety,
            resource_plan,
        } = plan;

        // Bind every logical provider reference before any provider process is
        // started. Authorization consumes this exact registry during its final
        // activation step, so dense provider storage and adapter indices agree.
        let provider_registry =
            ProviderRegistry::from_names(authorization.providers.keys().cloned());

        let redaction = RedactionSnapshot::activate(redaction, || cancellation.is_cancelled())
            .map_err(|error| map_redaction_error(error, &cancellation))?;
        cancellation.check()?;

        let credentials = CredentialResolverSnapshot::activate(credentials, &provider_registry)
            .map_err(|error| {
                candidate_error(&cancellation, "credential resolver", error.to_string())
            })?;
        cancellation.check()?;

        let policy = CompiledPolicySnapshot::activate(
            policy,
            &provider_registry,
            redaction.profile_registry(),
            credentials.source_registry(),
        )
        .map_err(|error| candidate_error(&cancellation, "policy", error.to_string()))?;
        cancellation.check()?;

        let safety = ProductSafetySnapshot::activate(
            safety,
            &resource_plan,
            policy.wire_body_plan_brand(),
            self.wire_body_pool.clone(),
        )
        .map_err(|error| candidate_error(&cancellation, "safety", error.to_string()))?;
        cancellation.check()?;

        let observation = self
            .observation_runtime
            .activate(observation, &redaction)
            .map_err(|error| candidate_error(&cancellation, "observation", error.to_string()))?;
        cancellation.check()?;

        let egress = EgressSnapshot::activate(egress, credentials.source_registry(), || {
            cancellation.is_cancelled()
        })
        .map_err(|error| map_egress_error(error, &cancellation))?;
        cancellation.check()?;

        // Process providers are deliberately last. Failures in secret
        // resolution, binding, TLS construction, or resource validation cannot
        // create a child that then needs product-level rollback.
        let authorization = ProductAuthorizationSnapshot::activate(
            authorization,
            provider_registry,
            cancellation.clone(),
        )
        .await
        .map_err(|error| map_authorization_error(error, &cancellation))?;

        let (authorization, _provider_registry, provider_owners) = authorization.into_parts();
        let (observation, observation_owner) = observation.into_parts();
        let (policy, bindings) = policy.into_parts();
        let (credentials, _credential_registry) = credentials.into_parts();
        let (redaction, _redaction_registry) = redaction.into_parts();

        let owners = provider_owners
            .into_vec()
            .into_iter()
            .chain(std::iter::once(observation_owner));
        let owner: Arc<dyn GenerationOwner> = Arc::new(ProductGenerationOwner::new(owners));

        if cancellation.is_cancelled() {
            owner.cleanup(CleanupReason::CandidateRejected).await;
            return Err(RuntimeError::ActivationCancelled);
        }

        Ok(ActivatedGeneration {
            request_timeout,
            max_content_decoding_expansion_ratio,
            resource_plan,
            bindings,
            policy: Arc::new(policy),
            egress: Arc::new(egress),
            authorization: Arc::new(authorization),
            credentials: Arc::new(credentials),
            redaction: Arc::new(redaction),
            observation: Arc::new(observation),
            safety: Arc::new(safety),
            owner,
        })
    }
}

impl CandidateActivator for ProductActivator {
    fn static_fingerprint(&self) -> &StaticFingerprint {
        &self.static_fingerprint
    }

    fn activate(
        &self,
        _id: GenerationId,
        plan: ReloadableProductPlan,
        cancellation: ActivationCancellation,
    ) -> BoxFuture<'_, Result<ActivatedGeneration, RuntimeError>> {
        Box::pin(self.activate_generation(plan, cancellation))
    }
}

fn candidate_error(
    cancellation: &ActivationCancellation,
    component: &str,
    message: String,
) -> RuntimeError {
    if cancellation.is_cancelled() {
        RuntimeError::ActivationCancelled
    } else {
        RuntimeError::CandidateActivation(format!("{component} activation failed: {message}"))
    }
}

fn map_redaction_error(
    error: SnapshotError,
    cancellation: &ActivationCancellation,
) -> RuntimeError {
    if error == SnapshotError::ActivationCancelled {
        RuntimeError::ActivationCancelled
    } else {
        candidate_error(cancellation, "redaction", error.to_string())
    }
}

fn map_egress_error(
    error: EgressActivationError,
    cancellation: &ActivationCancellation,
) -> RuntimeError {
    if error == EgressActivationError::ActivationCancelled {
        RuntimeError::ActivationCancelled
    } else {
        candidate_error(cancellation, "egress", error.to_string())
    }
}

fn map_authorization_error(
    error: AuthorizationActivationError,
    cancellation: &ActivationCancellation,
) -> RuntimeError {
    if error == AuthorizationActivationError::Cancelled {
        RuntimeError::ActivationCancelled
    } else {
        candidate_error(cancellation, "authorization", error.to_string())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::fs;
    use std::path::Path;

    use super::*;
    use crate::config::{compile_config_text, ConfigTextInput};
    #[cfg(unix)]
    use tempfile::TempDir;

    const MINIMAL: &str = r#"schema_version = 3

[service]
request_timeout = "30s"
shutdown_drain_timeout = "30s"
max_retiring_generations = 2
max_active_upgrades = 256
upgrade_relay_buffer_bytes = 65536
max_upgrade_buffer_bytes = 2147483648
max_upgrade_lifetime = "8h"
max_inflight_wire_body_bytes = 8589934592
max_inflight_wire_body_bytes_per_quota_key = 1073741824
min_wire_body_concurrency = 64
max_content_decoding_expansion_ratio = 128

[listeners.explicit_http]
bind = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[observation.logging]
level = "info"
console = true

[safety.loop_detection]
inject = true
header = "x-acl-proxy-request-id"
"#;

    fn compile(text: &str) -> crate::config::CompiledConfig {
        compile_config_text(ConfigTextInput {
            text,
            source_path: Path::new("/tmp/product-activator/acl-proxy.toml"),
            config_root: Path::new("/tmp/product-activator"),
        })
        .expect("test configuration compiles")
    }

    #[tokio::test]
    async fn complete_candidate_uses_static_pools_and_commits_capture_limit_at_publication() {
        let text = format!(
            "{MINIMAL}\n[redaction.profiles.audit]\nrules = [{{ literals = [\"marker\"] }}]\n\n[observation.capture]\nevents = [\"request.denied\"]\nredaction_profile = \"audit\"\ndirectory = \"captures\"\nmax_body_bytes = 1024\nmax_inflight_body_bytes = 8192\n"
        );
        let compiled = compile(&text);
        let activator = ProductActivator::new(&compiled.static_config).unwrap();
        let observation_runtime = activator.observation_runtime_handle();

        let activated = activator
            .activate_generation(
                compiled.reloadable_plan,
                ActivationCancellation::new_for_test(),
            )
            .await
            .expect("candidate activation succeeds");

        assert_eq!(activated.bindings.provider_count, 0);
        assert_eq!(activated.bindings.redaction_profile_count, 1);
        assert_eq!(observation_runtime.committed_capture_limit(), 0);
        let mut publication = activated.owner.publication_guard().unwrap();
        publication.commit();
        assert_eq!(observation_runtime.committed_capture_limit(), 8192);
        drop(publication);

        let successor = compile(&text.replace(
            "max_inflight_body_bytes = 8192",
            "max_inflight_body_bytes = 4096",
        ));
        let successor = activator
            .activate_generation(
                successor.reloadable_plan,
                ActivationCancellation::new_for_test(),
            )
            .await
            .expect("successor candidate activation succeeds");
        assert_eq!(observation_runtime.committed_capture_limit(), 8192);
        let mut successor_publication = successor.owner.publication_guard().unwrap();
        successor_publication.commit();
        assert_eq!(observation_runtime.committed_capture_limit(), 4096);
        drop(successor_publication);

        activated.owner.cleanup(CleanupReason::Shutdown).await;
        successor.owner.cleanup(CleanupReason::Shutdown).await;
    }

    #[tokio::test]
    async fn pre_cancelled_candidate_has_no_publication_effect() {
        let compiled = compile(MINIMAL);
        let activator = ProductActivator::new(&compiled.static_config).unwrap();
        let observation_runtime = activator.observation_runtime_handle();
        let cancellation = ActivationCancellation::new_for_test();
        cancellation.cancel_for_test();

        let result = activator
            .activate_generation(compiled.reloadable_plan, cancellation)
            .await;

        assert!(matches!(result, Err(RuntimeError::ActivationCancelled)));
        assert_eq!(observation_runtime.committed_capture_limit(), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn process_provider_registry_and_owner_are_part_of_the_complete_candidate() {
        let directory = TempDir::new().unwrap();
        let script = directory.path().join("idle.py");
        fs::write(&script, "import sys\nfor _ in sys.stdin:\n    pass\n").unwrap();
        let text = MINIMAL.replace(
            "[policy]\ndefault = \"deny\"",
            &format!(
                r#"[authorization.providers.local]
kind = "process"
command = "/usr/bin/python3"
args = ["{}"]
retire_timeout = "1s"

[policy]
default = "deny""#,
                script.display()
            ),
        );
        let source_path = directory.path().join("acl-proxy.toml");
        let compiled = compile_config_text(ConfigTextInput {
            text: &text,
            source_path: &source_path,
            config_root: directory.path(),
        })
        .unwrap();
        let activator = ProductActivator::new(&compiled.static_config).unwrap();

        let activated = activator
            .activate_generation(
                compiled.reloadable_plan,
                ActivationCancellation::new_for_test(),
            )
            .await
            .expect("process provider candidate activates");

        assert_eq!(activated.bindings.provider_count, 1);
        let mut publication = activated.owner.publication_guard().unwrap();
        publication.commit();
        drop(publication);
        activated.owner.cleanup(CleanupReason::Shutdown).await;
    }

    #[tokio::test]
    async fn redaction_resolution_fails_before_process_activation() {
        let variable = format!("ACL_PROXY_PRODUCT_MISSING_{}", std::process::id());
        std::env::remove_var(&variable);
        let text = MINIMAL.replace(
            "[policy]\ndefault = \"deny\"",
            &format!(
                r#"[authorization.providers.must_not_start]
kind = "process"
command = "/missing/provider/command"

[redaction.profiles.secrets]
rules = [{{ literal_environment_variables = ["{variable}"] }}]

[policy]
default = "deny""#
            ),
        );
        let compiled = compile(&text);
        let activator = ProductActivator::new(&compiled.static_config).unwrap();

        let result = activator
            .activate_generation(
                compiled.reloadable_plan,
                ActivationCancellation::new_for_test(),
            )
            .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("redaction resolution must reject the candidate"),
        };

        let rendered = error.to_string();
        assert!(rendered.contains("redaction activation failed"));
        assert!(!rendered.contains(&variable));
        assert!(!rendered.contains("/missing/provider/command"));
    }

    #[tokio::test]
    async fn same_config_activators_own_isolated_capture_pools() {
        let text = format!(
            "{MINIMAL}\n[redaction.profiles.audit]\nrules = [{{ literals = [\"marker\"] }}]\n\n[observation.capture]\nevents = [\"request.denied\"]\nredaction_profile = \"audit\"\ndirectory = \"captures\"\nmax_body_bytes = 1024\nmax_inflight_body_bytes = 8192\n"
        );
        let first_config = compile(&text);
        let second_config = compile(&text);
        let first = ProductActivator::new(&first_config.static_config).unwrap();
        let second = ProductActivator::new(&second_config.static_config).unwrap();
        let first_observation = first.observation_runtime_handle();
        let second_observation = second.observation_runtime_handle();

        assert_eq!(first.static_fingerprint(), &first_config.static_fingerprint);
        assert_eq!(first.static_fingerprint(), second.static_fingerprint());
        assert!(!Arc::ptr_eq(&first_observation, &second_observation));

        let activated = first
            .activate_generation(
                first_config.reloadable_plan,
                ActivationCancellation::new_for_test(),
            )
            .await
            .unwrap();
        let mut publication = activated.owner.publication_guard().unwrap();
        publication.commit();

        assert_eq!(first_observation.committed_capture_limit(), 8192);
        assert_eq!(second_observation.committed_capture_limit(), 0);

        let second_plan = compile(&text.replace(
            "max_inflight_body_bytes = 8192",
            "max_inflight_body_bytes = 4096",
        ));
        assert_eq!(second.static_fingerprint(), &second_plan.static_fingerprint);
        let second_activated = second
            .activate_generation(
                second_plan.reloadable_plan,
                ActivationCancellation::new_for_test(),
            )
            .await
            .unwrap();
        let mut second_publication = second_activated.owner.publication_guard().unwrap();
        second_publication.commit();

        assert_eq!(first_observation.committed_capture_limit(), 8192);
        assert_eq!(second_observation.committed_capture_limit(), 4096);

        drop(publication);
        drop(second_publication);
        activated.owner.cleanup(CleanupReason::Shutdown).await;
        second_activated
            .owner
            .cleanup(CleanupReason::Shutdown)
            .await;
    }
}
