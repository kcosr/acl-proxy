use std::sync::Arc;

use crate::authorization::{
    AuthorizationActivation, AuthorizationActivationError, ProductAuthorizationSnapshot,
};
use crate::config::compiler::ReloadableProductPlan;
use crate::config::StaticFingerprint;
use crate::credentials::CredentialActivation;
use crate::egress::{EgressActivationError, EgressSnapshot};
use crate::redaction::ProductRedactionActivationError;
use crate::runtime::{
    ActivatedGeneration, ActivationCancellation, BoxFuture, CandidateActivator, CleanupReason,
    GenerationId, GenerationOwner, ProviderRegistry, RuntimeError,
};
use crate::safety::ProductSafetySnapshot;
use crate::standalone::UnboundStandaloneGenerationPlan;

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

    #[cfg(test)]
    pub(crate) fn observation_runtime_handle(
        &self,
    ) -> Arc<crate::observation::ProductObservationRuntime> {
        self.static_resources.observation_runtime()
    }

    #[cfg(test)]
    pub(crate) fn logging_level_handle(&self) -> crate::logging::LoggingLevelControl {
        self.static_resources.logging_level()
    }

    #[cfg(test)]
    pub(crate) fn authorization_runtime_handle(
        &self,
    ) -> Arc<crate::authorization::webhook::runtime::WebhookAuthorizationRuntime> {
        self.static_resources.authorization_runtime()
    }

    #[cfg(test)]
    async fn activate_generation(
        &self,
        plan: ReloadableProductPlan,
        cancellation: ActivationCancellation,
    ) -> Result<ActivatedGeneration, RuntimeError> {
        self.activate_generation_inner(
            GenerationId::for_test(1),
            plan,
            cancellation,
            |_| {},
            |_| {},
        )
        .await
    }

    #[cfg(test)]
    async fn activate_generation_with_authorization_hook(
        &self,
        id: GenerationId,
        plan: ReloadableProductPlan,
        cancellation: ActivationCancellation,
        after_authorization_activation: impl FnMut(&AuthorizationActivation),
    ) -> Result<ActivatedGeneration, RuntimeError> {
        self.activate_generation_inner(
            id,
            plan,
            cancellation,
            after_authorization_activation,
            |_| {},
        )
        .await
    }

    #[cfg(test)]
    async fn activate_generation_with_failed_standalone_bind(
        &self,
        id: GenerationId,
        plan: ReloadableProductPlan,
        cancellation: ActivationCancellation,
        after_authorization_activation: impl FnMut(&AuthorizationActivation),
    ) -> Result<ActivatedGeneration, RuntimeError> {
        self.activate_generation_inner(
            id,
            plan,
            cancellation,
            after_authorization_activation,
            |standalone| standalone.invalidate_first_provider_output_for_test(),
        )
        .await
    }

    async fn activate_generation_inner(
        &self,
        id: GenerationId,
        plan: ReloadableProductPlan,
        cancellation: ActivationCancellation,
        mut after_authorization_activation: impl FnMut(&AuthorizationActivation),
        mut before_standalone_bind: impl FnMut(&mut UnboundStandaloneGenerationPlan),
    ) -> Result<ActivatedGeneration, RuntimeError> {
        cancellation.check()?;
        let mut standalone =
            UnboundStandaloneGenerationPlan::compile(&plan, id).map_err(|error| {
                candidate_error(
                    &cancellation,
                    "standalone generation plan",
                    error.to_string(),
                )
            })?;
        let capture_redaction = standalone.capture_redaction().cloned();
        cancellation.check()?;
        let ReloadableProductPlan {
            request_timeout,
            max_content_decoding_expansion_ratio,
            forwarding: _,
            egress,
            policy: _,
            authorization,
            credentials,
            redaction,
            observation,
            safety,
            resource_plan,
        } = plan;
        let logging_level_owner = self
            .static_resources
            .logging_level()
            .stage(observation.logging.level);

        // Bind every logical provider reference before any provider process is
        // started. Authorization consumes this exact registry during its final
        // activation step, so dense provider storage and adapter indices agree.
        let provider_registry =
            ProviderRegistry::from_names(authorization.providers.keys().cloned());

        let redaction = redaction
            .activate(standalone.identity().clone(), standalone.version(), || {
                cancellation.is_cancelled()
            })
            .map_err(|error| map_redaction_error(error, &cancellation))?;
        cancellation.check()?;

        let credentials = CredentialActivation::activate(credentials, &provider_registry)
            .map_err(|error| candidate_error(&cancellation, "credentials", error.to_string()))?;
        cancellation.check()?;

        let safety = ProductSafetySnapshot::activate(
            safety,
            &resource_plan,
            standalone.product_acl().resources().wire_body_plan_brand(),
            self.static_resources.wire_body_pool(),
        )
        .map_err(|error| candidate_error(&cancellation, "safety", error.to_string()))?;
        cancellation.check()?;

        let observation = self
            .static_resources
            .observation_runtime()
            .activate(observation, &redaction, capture_redaction.as_ref())
            .map_err(|error| candidate_error(&cancellation, "observation", error.to_string()))?;
        cancellation.check()?;

        let egress = EgressSnapshot::activate(egress, || cancellation.is_cancelled())
            .map_err(|error| map_egress_error(error, &cancellation))?;
        cancellation.check()?;

        // Process providers start only after the other generation-owned
        // resources have activated. Final binding follows because it consumes
        // the activated provider-output handles.
        let authorization = ProductAuthorizationSnapshot::activate(
            authorization,
            provider_registry,
            self.static_resources.authorization_runtime(),
            cancellation.clone(),
        )
        .await
        .map_err(|error| map_authorization_error(error, &cancellation))?;
        after_authorization_activation(&authorization);

        before_standalone_bind(&mut standalone);

        let (authorization, provider_registry, provider_owners) = authorization.into_parts();
        let (observation, observation_owner) = observation.into_parts();
        let (credentials, credential_sources) = credentials.into_parts();

        let owners = provider_owners
            .into_vec()
            .into_iter()
            .chain([observation_owner, logging_level_owner]);
        let owner: Arc<dyn GenerationOwner> = Arc::new(ProductGenerationOwner::new(owners));

        let standalone = match standalone.bind(
            &credential_sources,
            &redaction,
            &authorization,
            &provider_registry,
            &egress,
            &observation,
        ) {
            Ok(standalone) => standalone,
            Err(error) => {
                owner.cleanup(CleanupReason::CandidateRejected).await;
                return Err(candidate_error(
                    &cancellation,
                    "standalone generation binding",
                    error.to_string(),
                ));
            }
        };

        if cancellation.is_cancelled() {
            owner.cleanup(CleanupReason::CandidateRejected).await;
            return Err(RuntimeError::ActivationCancelled);
        }

        Ok(ActivatedGeneration {
            standalone,
            request_timeout,
            max_content_decoding_expansion_ratio,
            resource_plan,
            egress: Arc::new(egress),
            authorization: Arc::new(authorization),
            credentials: Arc::new(credentials),
            credential_io_runtime: self.static_resources.credential_io_runtime(),
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
        id: GenerationId,
        plan: ReloadableProductPlan,
        cancellation: ActivationCancellation,
    ) -> BoxFuture<'_, Result<ActivatedGeneration, RuntimeError>> {
        Box::pin(self.activate_generation_inner(id, plan, cancellation, |_| {}, |_| {}))
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
    error: ProductRedactionActivationError,
    cancellation: &ActivationCancellation,
) -> RuntimeError {
    if error == ProductRedactionActivationError::Cancelled {
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

    const INITIAL_CAPTURE_LIMIT: usize = 128 * 1024 * 1024;
    const LOWER_CAPTURE_LIMIT: usize = 112 * 1024 * 1024;

    const MINIMAL: &str = r#"schema_version = 3

[service]
request_timeout = "30s"
shutdown_drain_timeout = "30s"
max_retiring_generations = 2
max_active_upgrades = 256
upgrade_relay_buffer_bytes = 65536
max_upgrade_buffer_bytes = 2147483648
max_upgrade_lifetime = "8h"
max_inflight_wire_body_bytes = 17179869184
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
        let binding = lease
            .standalone()
            .activated()
            .rule_redaction(0)
            .expect("standalone generation binds the rule redaction profile");
        let redacted = binding
            .handle()
            .redact_websocket_message(
                &crate::redaction::UpgradeRedactionContext::for_profile(binding.handle()),
                crate::redaction::UpgradeRedactionBody::new(input.to_vec()).unwrap(),
                http_access_redaction::PayloadClass::Text,
            )
            .unwrap();
        redacted.into_body().into_vec().unwrap()
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
            "{MINIMAL}\n[redaction.profiles.audit]\nrules = [{{ literals = [\"marker\"] }}]\n\n[observation.capture]\nevents = [\"request.denied\"]\nredaction_profile = \"audit\"\ndirectory = \"captures\"\nmax_body_bytes = 1024\nmax_inflight_body_bytes = {INITIAL_CAPTURE_LIMIT}\n"
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

        assert_eq!(activated.standalone.snapshot_lease().generation().get(), 1);
        assert!(activated
            .standalone
            .snapshot_lease()
            .owns(activated.standalone.identity()));
        let standalone_bindings = activated.standalone.activated();
        assert!(standalone_bindings.provider_outputs().is_empty());
        assert!(activated.standalone.capture().is_some());
        let url = http_access_url::canonicalize_http_url("https://example.test/resource").unwrap();
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
        let header_facts = http_access_types::PolicyHeaderFacts::new(
            Vec::new(),
            activated.standalone.sensitive_headers().to_vec(),
        )
        .unwrap();
        let input = http_access_policy_acl::EvaluationInput::new(
            &facts,
            "192.0.2.10".parse().unwrap(),
            &header_facts,
            1,
            http_access_types::BodyRepresentation::PreservedContentCoded,
            http_access_types::BodyObservation::unobserved(),
        )
        .unwrap();
        let policy = activated
            .standalone
            .product_acl()
            .snapshot()
            .evaluate(&input)
            .unwrap();
        let http_access_policy_acl::PolicyEvaluation::Deny { provenance } = policy else {
            panic!("the minimal policy should deny by default")
        };
        assert!(matches!(
            provenance.effective_policy(),
            http_access_types::EffectivePolicy::Default
        ));

        assert!(matches!(
            activated.egress.route(),
            crate::egress::EgressRoute::Direct
        ));
        assert_eq!(activated.egress.origin_tls().http_versions().len(), 2);
        assert!(standalone_bindings.global_credentials().is_empty());
        let mut request_headers = http::HeaderMap::new();
        let _origin_trust = activated.egress.origin_tls().trust();

        let _inbound = activated.credentials.extract(&mut request_headers).unwrap();
        assert!(!request_headers.contains_key(http::header::AUTHORIZATION));

        assert!(activated
            .authorization
            .internal_context_headers()
            .is_empty());

        let capture = activated
            .observation
            .capture_epoch()
            .capture()
            .expect("capture policy is generation-owned");
        assert_eq!(capture.max_body_bytes(), 1024);
        assert!(
            capture
                .profile()
                .metrics()
                .compiled_matcher_resident_bytes()
                > 0
        );
        assert_eq!(observation_runtime.committed_capture_limit(), 0);
        let mut publication = activated.owner.publication_guard().unwrap();
        publication.commit();
        assert_eq!(
            observation_runtime.committed_capture_limit(),
            INITIAL_CAPTURE_LIMIT
        );
        drop(publication);

        let successor = compile(&text.replace(
            &format!("max_inflight_body_bytes = {INITIAL_CAPTURE_LIMIT}"),
            &format!("max_inflight_body_bytes = {LOWER_CAPTURE_LIMIT}"),
        ));
        let successor = activator
            .activate_generation(
                successor.reloadable_plan,
                ActivationCancellation::new_for_test(),
            )
            .await
            .expect("successor candidate activation succeeds");
        assert_eq!(
            observation_runtime.committed_capture_limit(),
            INITIAL_CAPTURE_LIMIT
        );
        let mut successor_publication = successor.owner.publication_guard().unwrap();
        successor_publication.commit();
        assert_eq!(
            observation_runtime.committed_capture_limit(),
            LOWER_CAPTURE_LIMIT
        );
        drop(successor_publication);

        activated.owner.cleanup(CleanupReason::Shutdown).await;
        successor.owner.cleanup(CleanupReason::Shutdown).await;
    }

    #[tokio::test]
    async fn logging_level_changes_only_with_generation_publication() {
        let initial = compile(&MINIMAL.replace("level = \"info\"", "level = \"warn\""));
        let activator = product_activator(&initial.static_config);
        let logging = activator.logging_level_handle();
        assert_eq!(
            logging.current(),
            crate::config::compiler::CompiledLogLevel::Info
        );

        let initial = activator
            .activate_generation(
                initial.reloadable_plan,
                ActivationCancellation::new_for_test(),
            )
            .await
            .unwrap();
        assert_eq!(
            logging.current(),
            crate::config::compiler::CompiledLogLevel::Info
        );
        initial.owner.publication_guard().unwrap().commit();
        assert_eq!(
            logging.current(),
            crate::config::compiler::CompiledLogLevel::Warn
        );

        let rejected = compile(&MINIMAL.replace("level = \"info\"", "level = \"trace\""));
        let rejected = activator
            .activate_generation(
                rejected.reloadable_plan,
                ActivationCancellation::new_for_test(),
            )
            .await
            .unwrap();
        rejected
            .owner
            .cleanup(CleanupReason::CandidateRejected)
            .await;
        assert_eq!(
            logging.current(),
            crate::config::compiler::CompiledLogLevel::Warn
        );

        let successor = compile(&MINIMAL.replace("level = \"info\"", "level = \"debug\""));
        let successor = activator
            .activate_generation(
                successor.reloadable_plan,
                ActivationCancellation::new_for_test(),
            )
            .await
            .unwrap();
        successor.owner.publication_guard().unwrap().commit();
        assert_eq!(
            logging.current(),
            crate::config::compiler::CompiledLogLevel::Debug
        );

        initial.owner.cleanup(CleanupReason::Shutdown).await;
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

    #[tokio::test]
    async fn product_candidate_publication_reports_runtime_shutdown() {
        let text = format!(
            "{MINIMAL}\n[redaction.profiles.audit]\nrules = [{{ literals = [\"marker\"] }}]\n\n[observation.capture]\nevents = [\"request.denied\"]\nredaction_profile = \"audit\"\ndirectory = \"captures\"\nmax_body_bytes = 1024\n"
        );
        let compiled = compile(&text);
        let activator = product_activator(&compiled.static_config);
        let activated = activator
            .activate_generation(
                compiled.reloadable_plan,
                ActivationCancellation::new_for_test(),
            )
            .await
            .expect("candidate activation succeeds");

        activator.observation_runtime_handle().begin_shutdown();

        assert!(matches!(
            activated.owner.publication_guard(),
            Err(RuntimeError::ShuttingDown)
        ));
        activated
            .owner
            .cleanup(CleanupReason::CandidateRejected)
            .await;
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

[authorization.providers.local.outputs.token]
kind = "bearer"
required = true

[credentials.sources.global]
source = "environment"
variable = "ACL_PROXY_TEST_GLOBAL_TOKEN"

[[egress.credential_actions]]
kind = "bearer"
credential = "global"

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

        let standalone_bindings = activated.standalone.activated();
        assert_eq!(standalone_bindings.global_credentials().len(), 1);
        assert!(standalone_bindings.global_credentials()[0]
            .reference()
            .belongs_to(activated.standalone.identity()));
        assert_eq!(standalone_bindings.provider_outputs().len(), 1);
        assert_eq!(
            standalone_bindings.provider_outputs()[0].provider().get(),
            0
        );
        assert_eq!(standalone_bindings.provider_outputs()[0].output().get(), 0);
        assert!(standalone_bindings.provider_outputs()[0]
            .reference()
            .belongs_to(activated.standalone.identity()));
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
                GenerationId::for_test(1),
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

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_standalone_bind_rejects_and_reaps_activated_provider_once() {
        let directory = TempDir::new().unwrap();
        let script = directory.path().join("idle-until-bind-rejected.py");
        fs::write(&script, "import time\nwhile True:\n    time.sleep(1)\n").unwrap();
        let text = MINIMAL.replace(
            "[policy]\ndefault = \"deny\"",
            &format!(
                r#"[authorization.providers.local]
kind = "process"
command = "/usr/bin/python3"
args = ["{}"]
retire_timeout = "1s"

[authorization.providers.local.outputs.token]
kind = "bearer"
required = true

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
        let observed = Arc::new(Mutex::new(None));
        let hook_observed = observed.clone();

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            activator.activate_generation_with_failed_standalone_bind(
                GenerationId::for_test(1),
                compiled.reloadable_plan,
                ActivationCancellation::new_for_test(),
                move |authorization| {
                    let provider = authorization
                        .process_provider_for_test(0)
                        .expect("authorization activation owns the process provider");
                    let pid = provider.child_id().expect("activated provider has a child");
                    *hook_observed.lock().unwrap() = Some((provider, pid));
                },
            ),
        )
        .await
        .expect("standalone bind cleanup completes");

        assert!(matches!(
            result,
            Err(RuntimeError::CandidateActivation(message))
                if message.contains("standalone generation binding")
        ));
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
            "{MINIMAL}\n[redaction.profiles.audit]\nrules = [{{ literals = [\"marker\"] }}]\n\n[observation.capture]\nevents = [\"request.denied\"]\nredaction_profile = \"audit\"\ndirectory = \"captures\"\nmax_body_bytes = 1024\nmax_inflight_body_bytes = {INITIAL_CAPTURE_LIMIT}\n"
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

        assert_eq!(
            first_observation.committed_capture_limit(),
            INITIAL_CAPTURE_LIMIT
        );
        assert_eq!(second_observation.committed_capture_limit(), 0);

        let second_plan = compile(&text.replace(
            &format!("max_inflight_body_bytes = {INITIAL_CAPTURE_LIMIT}"),
            &format!("max_inflight_body_bytes = {LOWER_CAPTURE_LIMIT}"),
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

        assert_eq!(
            first_observation.committed_capture_limit(),
            INITIAL_CAPTURE_LIMIT
        );
        assert_eq!(
            second_observation.committed_capture_limit(),
            LOWER_CAPTURE_LIMIT
        );

        drop(publication);
        drop(second_publication);
        activated.owner.cleanup(CleanupReason::Shutdown).await;
        second_activated
            .owner
            .cleanup(CleanupReason::Shutdown)
            .await;
    }
}
