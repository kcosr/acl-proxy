use std::sync::Arc;

use crate::authorization::{
    AuthorizationActivation, AuthorizationActivationError, ProductAuthorizationSnapshot,
};
use crate::config::compiler::ReloadableProductPlan;
use crate::config::StaticFingerprint;
use crate::credentials::CredentialResolverSnapshot;
use crate::egress::{EgressActivationError, EgressSnapshot};
use crate::policy::CompiledPolicySnapshot;
use crate::redaction::{RedactionSnapshot, SnapshotError};
use crate::runtime::{
    ActivatedGeneration, ActivationCancellation, BoxFuture, CandidateActivator, CleanupReason,
    GenerationId, GenerationOwner, ProviderRegistry, RuntimeError,
};
use crate::safety::ProductSafetySnapshot;

use super::owner::ProductGenerationOwner;
use super::static_resources::ProductStaticResources;

/// Process-lifetime factory for complete generation candidates.
///
/// Static admission pools are shared by every active, candidate, and retiring
/// generation. Every other handle returned by activation is generation-owned.
pub(crate) struct ProductActivator {
    static_resources: Arc<ProductStaticResources>,
}

impl ProductActivator {
    pub(super) fn new(static_resources: Arc<ProductStaticResources>) -> Self {
        Self { static_resources }
    }

    pub(crate) fn observation_runtime_handle(
        &self,
    ) -> Arc<crate::observation::ProductObservationRuntime> {
        self.static_resources.observation_runtime()
    }

    pub(crate) fn authorization_runtime_handle(
        &self,
    ) -> Arc<crate::authorization::webhook::runtime::WebhookAuthorizationRuntime> {
        self.static_resources.authorization_runtime()
    }

    async fn activate_generation(
        &self,
        plan: ReloadableProductPlan,
        cancellation: ActivationCancellation,
    ) -> Result<ActivatedGeneration, RuntimeError> {
        self.activate_generation_inner(plan, cancellation, |_| {})
            .await
    }

    #[cfg(test)]
    async fn activate_generation_with_authorization_hook(
        &self,
        plan: ReloadableProductPlan,
        cancellation: ActivationCancellation,
        after_authorization_activation: impl FnMut(&AuthorizationActivation),
    ) -> Result<ActivatedGeneration, RuntimeError> {
        self.activate_generation_inner(plan, cancellation, after_authorization_activation)
            .await
    }

    async fn activate_generation_inner(
        &self,
        plan: ReloadableProductPlan,
        cancellation: ActivationCancellation,
        mut after_authorization_activation: impl FnMut(&AuthorizationActivation),
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
            self.static_resources.wire_body_pool(),
        )
        .map_err(|error| candidate_error(&cancellation, "safety", error.to_string()))?;
        cancellation.check()?;

        let observation = self
            .static_resources
            .observation_runtime()
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
            self.static_resources.authorization_runtime(),
            cancellation.clone(),
        )
        .await
        .map_err(|error| map_authorization_error(error, &cancellation))?;
        after_authorization_activation(&authorization);

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
    fn static_resource_brand(&self) -> &crate::runtime::StaticResourceBrand {
        self.static_resources.static_resource_brand()
    }

    fn static_fingerprint(&self) -> &StaticFingerprint {
        self.static_resources.static_fingerprint()
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
    use std::collections::VecDeque;
    #[cfg(unix)]
    use std::fs;
    use std::path::Path;
    use std::sync::Mutex;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    fn product_activator(
        static_config: &crate::config::StaticProductConfig,
    ) -> Arc<ProductActivator> {
        let resources = ProductStaticResources::try_new(static_config).unwrap();
        resources.activator()
    }

    #[derive(Default)]
    struct ProductCandidateSource(Mutex<VecDeque<crate::config::CompiledConfig>>);

    impl ProductCandidateSource {
        fn push(&self, candidate: crate::config::CompiledConfig) {
            self.0.lock().unwrap().push_back(candidate);
        }
    }

    impl crate::runtime::CandidateSource for ProductCandidateSource {
        fn load_latest(
            &self,
            cancellation: ActivationCancellation,
        ) -> BoxFuture<'_, Result<crate::config::CompiledConfig, RuntimeError>> {
            Box::pin(async move {
                cancellation.check()?;
                self.0.lock().unwrap().pop_front().ok_or_else(|| {
                    RuntimeError::CandidateSource("no product candidate queued".to_string())
                })
            })
        }
    }

    fn environment_redaction_config(variable: &str) -> String {
        format!(
            r#"{MINIMAL}
[redaction.profiles.environment]
rules = [{{ literal_environment_variables = ["{variable}"] }}]

[[policy.rules]]
id = "environment-redaction"
decision = "allow"
urls = ["https://example.test/**"]
redaction_profile = "environment"
"#
        )
    }

    async fn product_runtime(
        initial: &crate::config::CompiledConfig,
    ) -> (Arc<crate::runtime::Runtime>, Arc<ProductCandidateSource>) {
        let resources = ProductStaticResources::try_new(&initial.static_config).unwrap();
        let activator = resources.activator();
        let source = Arc::new(ProductCandidateSource::default());
        let ownership = crate::runtime::StaticOwnership::new(
            initial.static_config.clone(),
            initial.static_fingerprint.clone(),
            resources,
        );
        let runtime = crate::runtime::Runtime::new(ownership, source.clone(), activator)
            .await
            .unwrap();
        (runtime, source)
    }

    fn redact_environment_secret(lease: &crate::runtime::GenerationLease, input: &[u8]) -> Vec<u8> {
        let profile = lease.bindings().rules[0]
            .redaction_profile
            .expect("policy rule binds the environment redaction profile");
        let redacted = lease
            .redaction()
            .profile(profile)
            .unwrap()
            .redact_decoded_http_body(input.to_vec())
            .unwrap();
        redacted.bytes.clone()
    }

    #[tokio::test]
    async fn redaction_environment_rotation_publishes_one_generation() {
        const VARIABLE: &str = "ACL_PROXY_PRODUCT_REDACTION_ROTATION_6A51";
        std::env::set_var(VARIABLE, "old-generation-secret");
        let text = environment_redaction_config(VARIABLE);
        let initial = compile(&text);
        let successor = compile(&text);
        let (runtime, source) = product_runtime(&initial).await;
        let first = runtime.start(initial).await.unwrap();
        let old_lease = runtime.lease().await.unwrap();

        std::env::set_var(VARIABLE, "new-generation-secret");
        source.push(successor);
        let crate::runtime::ReloadTriggerResult::Completed {
            attempts,
            generation: second,
        } = runtime.trigger_reload().await.unwrap()
        else {
            panic!("the sole reload attempt must publish its candidate");
        };
        let new_lease = runtime.lease().await.unwrap();
        std::env::remove_var(VARIABLE);

        assert_eq!(attempts, 1);
        assert_ne!(first, second);
        assert_eq!(runtime.active_generation_id(), Some(second));
        assert_eq!(old_lease.id(), first);
        assert_eq!(new_lease.id(), second);
        assert_eq!(
            redact_environment_secret(&old_lease, b"old-generation-secret new-generation-secret"),
            b"[REDACTED] new-generation-secret"
        );
        assert_eq!(
            redact_environment_secret(&new_lease, b"old-generation-secret new-generation-secret"),
            b"old-generation-secret [REDACTED]"
        );

        drop(old_lease);
        drop(new_lease);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn redaction_source_failure_preserves_previous_generation() {
        const VARIABLE: &str = "ACL_PROXY_PRODUCT_REDACTION_FAILURE_8C37";
        std::env::set_var(VARIABLE, "published-generation-secret");
        let text = environment_redaction_config(VARIABLE);
        let initial = compile(&text);
        let failed_successor = compile(&text);
        let (runtime, source) = product_runtime(&initial).await;
        let first = runtime.start(initial).await.unwrap();

        std::env::remove_var(VARIABLE);
        source.push(failed_successor);
        let error = runtime.trigger_reload().await.unwrap_err();
        assert!(matches!(error, RuntimeError::CandidateActivation(_)));
        assert_eq!(runtime.active_generation_id(), Some(first));
        let retained = runtime.lease().await.unwrap();
        assert_eq!(retained.id(), first);
        assert_eq!(
            redact_environment_secret(&retained, b"published-generation-secret"),
            b"[REDACTED]"
        );
        assert!(!error.to_string().contains(VARIABLE));
        assert!(!error.to_string().contains("published-generation-secret"));

        drop(retained);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn product_static_owner_and_activator_share_one_authorization_runtime() {
        let compiled = compile(MINIMAL);
        let resources = ProductStaticResources::try_new(&compiled.static_config).unwrap();
        let activator = resources.activator();
        assert!(Arc::ptr_eq(
            &resources.authorization_runtime(),
            &activator.authorization_runtime_handle()
        ));
        assert!(Arc::ptr_eq(
            resources.ingress_assets().destination_guard(),
            resources.authorization_runtime().destination_guard()
        ));

        crate::runtime::StaticResources::begin_shutdown(resources.as_ref());
        assert!(
            !resources
                .authorization_runtime()
                .transport_counts()
                .accepting
        );
        assert!(
            !resources
                .authorization_runtime()
                .pending_store()
                .counts()
                .accepting
        );
        crate::runtime::StaticResources::shutdown(resources.as_ref()).await;
    }

    #[tokio::test]
    async fn product_static_owner_keeps_control_open_until_joined_shutdown() {
        let minimal = MINIMAL.replace(
            "shutdown_drain_timeout = \"30s\"",
            "shutdown_drain_timeout = \"1s\"",
        );
        let text = format!(
            "{minimal}\n[control]\nbind = \"127.0.0.1:8898\"\nbase_path = \"/_acl-proxy\"\nrequest_header_timeout = \"100ms\"\nrequest_body_timeout = \"1s\"\nmax_connections = 2\nmax_request_body_bytes = 65536\n"
        );
        let compiled = compile(&text);
        let resources = ProductStaticResources::try_new(&compiled.static_config).unwrap();
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = resources
            .start_control_with_listener(listener)
            .unwrap()
            .unwrap();

        async fn readiness(address: std::net::SocketAddr) -> Vec<u8> {
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            stream
                .write_all(b"GET /_acl-proxy/ready HTTP/1.1\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
            response
        }

        assert!(readiness(address).await.starts_with(b"HTTP/1.1 503"));
        crate::runtime::StaticResources::begin_shutdown(resources.as_ref());
        assert!(readiness(address).await.starts_with(b"HTTP/1.1 503"));

        let control = resources.control_server().unwrap();
        let mut admitted = tokio::net::TcpStream::connect(address).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while control.arena_counts().live != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the shutdown observer must be admitted");

        tokio::time::timeout(
            Duration::from_secs(2),
            crate::runtime::StaticResources::shutdown(resources.as_ref()),
        )
        .await
        .expect("joined shutdown must stay within its compiled deadline");
        let mut trailing = Vec::new();
        admitted.read_to_end(&mut trailing).await.unwrap();
        assert!(trailing.is_empty());
        assert_eq!(control.arena_counts().live, 0);
        assert_eq!(control.arena_counts().available, 2);
    }

    #[tokio::test]
    async fn unbounded_product_shutdown_closes_an_idle_control_keep_alive() {
        let minimal = MINIMAL.replace(
            "shutdown_drain_timeout = \"30s\"",
            "shutdown_drain_timeout = \"unbounded\"",
        );
        let text = format!(
            "{minimal}\n[control]\nbind = \"127.0.0.1:8898\"\nbase_path = \"/_acl-proxy\"\nrequest_header_timeout = \"30s\"\nrequest_body_timeout = \"1s\"\nmax_connections = 1\nmax_request_body_bytes = 65536\n"
        );
        let compiled = compile(&text);
        let resources = ProductStaticResources::try_new(&compiled.static_config).unwrap();
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = resources
            .start_control_with_listener(listener)
            .unwrap()
            .unwrap();
        let control = resources.control_server().unwrap();
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET /_acl-proxy/ready HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();

        let mut response = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            client.read_exact(&mut byte).await.unwrap();
            response.push(byte[0]);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head = std::str::from_utf8(&response).unwrap();
        let body_len = head
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let head_len = response.len();
        response.resize(head_len + body_len, 0);
        client.read_exact(&mut response[head_len..]).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));

        tokio::time::timeout(
            Duration::from_secs(1),
            crate::runtime::StaticResources::shutdown(resources.as_ref()),
        )
        .await
        .expect("unbounded product shutdown must not permit keep-alive renewal");
        let mut trailing = Vec::new();
        client.read_to_end(&mut trailing).await.unwrap();
        assert!(trailing.is_empty());
        assert_eq!(control.arena_counts().live, 0);
        assert_eq!(control.arena_counts().available, 1);
    }

    #[tokio::test]
    async fn control_graceful_join_escalates_at_the_static_shutdown_deadline() {
        let minimal = MINIMAL.replace(
            "shutdown_drain_timeout = \"30s\"",
            "shutdown_drain_timeout = \"50ms\"",
        );
        let text = format!(
            "{minimal}\n[control]\nbind = \"127.0.0.1:8898\"\nbase_path = \"/_acl-proxy\"\nrequest_header_timeout = \"5s\"\nrequest_body_timeout = \"1s\"\nmax_connections = 1\nmax_request_body_bytes = 65536\n"
        );
        let compiled = compile(&text);
        let resources = ProductStaticResources::try_new(&compiled.static_config).unwrap();
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = resources
            .start_control_with_listener(listener)
            .unwrap()
            .unwrap();
        let control = resources.control_server().unwrap();
        let mut stalled = tokio::net::TcpStream::connect(address).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while control.arena_counts().live != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the stalled connection must be admitted");

        tokio::time::timeout(
            Duration::from_millis(500),
            crate::runtime::StaticResources::shutdown(resources.as_ref()),
        )
        .await
        .expect("the original static deadline must bound graceful connection drain");
        let mut trailing = Vec::new();
        stalled.read_to_end(&mut trailing).await.unwrap();
        assert!(trailing.is_empty());
        assert_eq!(control.arena_counts().live, 0);
        assert_eq!(control.arena_counts().available, 1);
    }

    #[tokio::test]
    async fn fatal_control_failure_is_observed_and_shutdown_does_not_panic() {
        let text = format!(
            "{MINIMAL}\n[control]\nbind = \"127.0.0.1:8898\"\nbase_path = \"/_acl-proxy\"\nrequest_header_timeout = \"1s\"\nrequest_body_timeout = \"1s\"\nmax_connections = 1\nmax_request_body_bytes = 65536\n"
        );
        let compiled = compile(&text);
        let resources = ProductStaticResources::try_new(&compiled.static_config).unwrap();
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        resources
            .start_control_with_accept_errors(
                listener,
                [std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "injected fatal accept failure",
                )],
            )
            .unwrap();

        let failure =
            tokio::time::timeout(Duration::from_secs(1), resources.wait_for_control_failure())
                .await
                .expect("fatal supervisor failure must be observable")
                .expect("the failure channel must retain the fatal error");
        assert!(matches!(
            failure.as_ref(),
            crate::control::server::ControlServerRunError::Accept(error)
                if error.kind() == std::io::ErrorKind::InvalidInput
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !resources.shutdown_started_for_test() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the static owner must begin shutdown after control failure");
        assert!(
            !resources
                .authorization_runtime()
                .transport_counts()
                .accepting
        );
        assert!(
            !resources
                .authorization_runtime()
                .pending_store()
                .counts()
                .accepting
        );
        assert!(matches!(
            resources.start_control(),
            Err(crate::activation::static_resources::ProductStaticResourcesError::ShuttingDown)
        ));

        crate::runtime::StaticResources::shutdown(resources.as_ref()).await;
        assert!(matches!(
            resources.control_shutdown_error().as_deref(),
            Some(crate::control::server::ControlServerShutdownError::Supervisor(error))
                if matches!(error.as_ref(), crate::control::server::ControlServerRunError::Accept(_))
        ));
    }

    #[tokio::test]
    async fn complete_candidate_uses_static_pools_and_commits_capture_limit_at_publication() {
        let text = format!(
            "{MINIMAL}\n[redaction.profiles.audit]\nrules = [{{ literals = [\"marker\"] }}]\n\n[observation.capture]\nevents = [\"request.denied\"]\nredaction_profile = \"audit\"\ndirectory = \"captures\"\nmax_body_bytes = 1024\nmax_inflight_body_bytes = 8192\n"
        );
        let compiled = compile(&text);
        let activator = product_activator(&compiled.static_config);
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
        let url = crate::url::canonicalize_http_url("https://example.test/resource").unwrap();
        let policy = activated.policy.evaluate(
            &url,
            "192.0.2.10".parse().unwrap(),
            &http::Method::GET,
            &http::HeaderMap::new(),
            &|_| false,
        );
        assert_eq!(policy.outcome, crate::policy::PolicyOutcome::Deny);
        assert!(policy.matched.is_none());

        assert!(matches!(
            activated.egress.route(),
            crate::egress::EgressRoute::Direct
        ));
        assert_eq!(activated.egress.origin_tls().http_versions().len(), 2);
        assert!(activated.egress.credential_actions().is_empty());
        let mut request_headers = http::HeaderMap::new();
        activated
            .egress
            .apply_request_headers(&mut request_headers)
            .unwrap();
        let _origin_trust = activated.egress.origin_tls().trust();

        assert_eq!(activated.credentials.source_count(), 0);
        activated
            .credentials
            .inject(&[], &mut request_headers)
            .unwrap();
        let inbound = activated
            .credentials
            .extract_inbound(&mut request_headers)
            .unwrap();
        assert!(!inbound.is_present(&http::header::AUTHORIZATION));

        assert!(activated
            .authorization
            .internal_context_headers()
            .is_empty());

        assert_eq!(activated.redaction.len(), 1);
        assert!(!activated.redaction.is_empty());
        assert!(activated.redaction.compiled_matcher_resident_bytes() > 0);
        let capture = activated
            .observation
            .capture()
            .expect("capture policy is generation-owned");
        assert!(activated
            .redaction
            .profile(capture.profile_index())
            .is_some());
        assert!(matches!(
            activated.observation.logging().level(),
            crate::config::compiler::CompiledLogLevel::Info
        ));
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
        let activator = product_activator(&compiled.static_config);
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
        let activator = product_activator(&compiled.static_config);

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

    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_after_authorization_activation_rejects_and_reaps_provider_once() {
        let directory = TempDir::new().unwrap();
        let script = directory.path().join("idle-until-rejected.py");
        fs::write(&script, "import time\nwhile True:\n    time.sleep(1)\n").unwrap();
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
        let activator = product_activator(&compiled.static_config);
        let cancellation = ActivationCancellation::new_for_test();
        let hook_cancellation = cancellation.clone();
        let observed = Arc::new(Mutex::new(None));
        let hook_observed = observed.clone();

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            activator.activate_generation_with_authorization_hook(
                compiled.reloadable_plan,
                cancellation,
                move |authorization| {
                    let provider = authorization
                        .process_provider_for_test(0)
                        .expect("authorization activation owns the process provider");
                    let pid = provider.child_id().expect("activated provider has a child");
                    *hook_observed.lock().unwrap() = Some((provider, pid));
                    hook_cancellation.cancel_for_test();
                },
            ),
        )
        .await
        .expect("product cancellation cleanup completes");

        assert!(matches!(result, Err(RuntimeError::ActivationCancelled)));
        let (provider, pid) = observed
            .lock()
            .unwrap()
            .take()
            .expect("post-authorization hook ran");
        assert_eq!(provider.cleanup_starts(), 1);
        assert_eq!(
            provider.cleanup_reasons(),
            [CleanupReason::CandidateRejected]
        );
        // SAFETY: signal zero only checks whether the child PID still exists.
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
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
        let activator = product_activator(&compiled.static_config);

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
        let first = product_activator(&first_config.static_config);
        let second = product_activator(&second_config.static_config);
        let first_observation = first.observation_runtime_handle();
        let second_observation = second.observation_runtime_handle();
        let first_authorization = first.authorization_runtime_handle();
        let first_authorization_again = first.authorization_runtime_handle();
        let second_authorization = second.authorization_runtime_handle();

        assert_eq!(first.static_fingerprint(), &first_config.static_fingerprint);
        assert_eq!(first.static_fingerprint(), second.static_fingerprint());
        assert!(!Arc::ptr_eq(&first_observation, &second_observation));
        assert!(Arc::ptr_eq(
            &first_authorization,
            &first_authorization_again
        ));
        assert!(!Arc::ptr_eq(&first_authorization, &second_authorization));
        assert_eq!(
            first_authorization.transport_counts().maximum_deliveries,
            first_config
                .static_config
                .service
                .max_active_webhook_deliveries
        );

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
