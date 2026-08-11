use std::sync::{Arc, Mutex};

use http_access_runtime::{
    ListenerFailureObserver, ListenerMode, ListenerRuntime, ListenerServices, ListenerTlsAcceptors,
    OriginalDestinationProvider, StandaloneRequestFactory,
};

use super::access_flow_security::AccessFlowSecurityMaterialError;
use crate::config::LoadedCompiledConfig;
use crate::observation::ProductObservationRuntime;
use crate::runtime::{
    GenerationId, ReloadTriggerResult, Runtime, RuntimeError, StaticOwnership, StaticResources,
};

use super::listeners::{
    AccessFlowListenerRuntime, PreparedProxyListeners, ProductListenerRuntime,
    ProxyListenerFailure, SystemOriginalDestinationProvider,
};
use super::source::FileCandidateSource;
use super::static_resources::{ProductStaticResources, ProductStaticResourcesError};
use crate::standalone_policy_provider::ProductStandaloneRequestFactory;

/// Staged ownership for one product runtime.
///
/// Preparation reserves every configured ingress socket, but deliberately does
/// not assert that the shared listener runtime is serving them. Initial publication and
/// ingress confirmation remain separate gates so neither ordering can expose a
/// prematurely ready process.
pub(crate) struct ProductRuntime {
    runtime: Arc<Runtime>,
    static_resources: Arc<ProductStaticResources>,
    observation_runtime: Arc<ProductObservationRuntime>,
    initial: Mutex<Option<crate::config::RuntimeCandidate>>,
}

pub(crate) struct InitialActivationResult {
    pub(crate) generation: GenerationId,
    pub(crate) policy_source_summary: crate::config::PolicySourceSummary,
}

pub(crate) struct ProductReloadResult {
    pub(crate) configuration: Result<ReloadTriggerResult, RuntimeError>,
    pub(crate) access_flow_security: Result<(), AccessFlowSecurityMaterialError>,
}

struct ProductListenerFailureObserver {
    static_resources: std::sync::Weak<ProductStaticResources>,
}

impl ListenerFailureObserver for ProductListenerFailureObserver {
    fn listener_failed(&self, mode: ListenerMode, error: http_access_runtime::RuntimeError) {
        let Some(static_resources) = self.static_resources.upgrade() else {
            return;
        };
        let error = Arc::new(ProxyListenerFailure {
            listener: super::listeners::ProxyListenerKind::from_shared(mode),
            message: error.to_string(),
        });
        tracing::error!(error = %error, "proxy listener failed");
        static_resources.record_listener_failure(error);
        StaticResources::begin_shutdown(static_resources.as_ref());
    }

    fn connection_rejected(
        &self,
        mode: ListenerMode,
        transport: http_access_runtime::ListenerTransport,
        error: http_access_runtime::RuntimeError,
    ) {
        tracing::warn!(
            target: "acl_proxy::traffic",
            listener = %super::listeners::ProxyListenerKind::from_shared(mode),
            listener_transport = listener_transport_name(transport),
            category = "connection_rejected",
            error = %error,
            "proxy listener rejected a connection before HTTP/TLS processing"
        );
    }
}

fn listener_transport_name(transport: http_access_runtime::ListenerTransport) -> &'static str {
    match transport {
        http_access_runtime::ListenerTransport::Tcp => "tcp",
        http_access_runtime::ListenerTransport::AccessFlow => "access_flow",
    }
}

impl ProductRuntime {
    pub(crate) async fn prepare(
        loaded: LoadedCompiledConfig,
        identity_sources: Arc<crate::identity::IdentitySourceRegistry>,
    ) -> Result<Arc<Self>, ProductRuntimeError> {
        Self::prepare_inner(loaded, None, None, Some(identity_sources)).await
    }

    #[cfg(test)]
    pub(crate) async fn prepare_from_prebound(
        loaded: LoadedCompiledConfig,
        listeners: Vec<std::net::TcpListener>,
    ) -> Result<Arc<Self>, ProductRuntimeError> {
        Self::prepare_inner(loaded, Some(listeners), None, None).await
    }

    #[cfg(test)]
    pub(crate) async fn prepare_from_prebound_with_forwarding_network(
        loaded: LoadedCompiledConfig,
        listeners: Vec<std::net::TcpListener>,
        forwarding_network: Arc<http_access_runtime::ForwardingNetworkGuard>,
    ) -> Result<Arc<Self>, ProductRuntimeError> {
        Self::prepare_inner(loaded, Some(listeners), Some(forwarding_network), None).await
    }

    #[cfg(test)]
    pub(crate) async fn prepare_from_prebound_with_forwarding_network_and_identity_sources(
        loaded: LoadedCompiledConfig,
        listeners: Vec<std::net::TcpListener>,
        forwarding_network: Arc<http_access_runtime::ForwardingNetworkGuard>,
        identity_sources: Arc<crate::identity::IdentitySourceRegistry>,
    ) -> Result<Arc<Self>, ProductRuntimeError> {
        Self::prepare_inner(
            loaded,
            Some(listeners),
            Some(forwarding_network),
            Some(identity_sources),
        )
        .await
    }

    async fn prepare_inner(
        loaded: LoadedCompiledConfig,
        prebound: Option<Vec<std::net::TcpListener>>,
        forwarding_network: Option<Arc<http_access_runtime::ForwardingNetworkGuard>>,
        identity_sources: Option<Arc<crate::identity::IdentitySourceRegistry>>,
    ) -> Result<Arc<Self>, ProductRuntimeError> {
        let LoadedCompiledConfig { metadata, compiled } = loaded;
        #[cfg(not(test))]
        let _ = (prebound, forwarding_network);
        #[cfg(test)]
        let static_resources = match (forwarding_network, identity_sources) {
            (None, Some(identity_sources)) => {
                ProductStaticResources::try_new_with_identity_sources(
                    &compiled.static_config,
                    identity_sources,
                )
                .await?
            }
            (Some(forwarding_network), None) => {
                ProductStaticResources::try_new_with_forwarding_network(
                    &compiled.static_config,
                    forwarding_network,
                )
                .await?
            }
            (Some(forwarding_network), Some(identity_sources)) => {
                ProductStaticResources::try_new_with_forwarding_network_and_identity_sources(
                    &compiled.static_config,
                    forwarding_network,
                    identity_sources,
                )
                .await?
            }
            (None, None) => ProductStaticResources::try_new(&compiled.static_config).await?,
        };
        #[cfg(not(test))]
        let static_resources = ProductStaticResources::try_new_with_identity_sources(
            &compiled.static_config,
            identity_sources
                .expect("production preparation supplies preactivated identity sources"),
        )
        .await?;
        let observation_runtime = static_resources.observation_runtime();
        let tls_io_runtime = static_resources.tls_io_runtime();
        if let Err(error) = crate::config::validate_tls_trust_sources(
            &compiled,
            Arc::clone(&tls_io_runtime),
            &crate::runtime::ActivationCancellation::new(),
        )
        .await
        {
            StaticResources::shutdown(static_resources.as_ref()).await;
            return Err(error.into());
        }

        #[cfg(test)]
        let prepared = match prebound {
            Some(listeners) => static_resources.prepare_ingress_from_prebound(listeners),
            None => static_resources.prepare_ingress(),
        };
        #[cfg(not(test))]
        let prepared = static_resources.prepare_ingress();
        if let Err(error) = prepared {
            StaticResources::shutdown(static_resources.as_ref()).await;
            return Err(error.into());
        }

        let source = Arc::new(FileCandidateSource::new(&metadata));
        let activator = static_resources.activator();
        let static_ownership = StaticOwnership::new(
            compiled.static_config.clone(),
            compiled.static_fingerprint.clone(),
            static_resources.clone(),
        );
        let runtime = Runtime::new(static_ownership, source, activator).await?;

        let initial = compiled.into_runtime_candidate();
        Ok(Arc::new(Self {
            runtime,
            static_resources,
            observation_runtime,
            initial: Mutex::new(Some(initial)),
        }))
    }

    pub(crate) fn runtime(&self) -> &Arc<Runtime> {
        &self.runtime
    }

    #[cfg(test)]
    pub(crate) fn wire_body_pool(&self) -> Arc<crate::safety::WireBodyPool> {
        self.static_resources.wire_body_pool()
    }

    #[cfg(test)]
    pub(crate) fn capture_pool_used_for_test(&self) -> usize {
        self.observation_runtime.capture_pool_used()
    }

    #[cfg(test)]
    pub(crate) fn identity_publisher_for_test(&self) -> Arc<crate::identity::IdentityPublisher> {
        self.static_resources.identity_publisher()
    }

    #[cfg(test)]
    pub(crate) fn forwarding_terminal_completions_for_test(&self) -> usize {
        self.observation_runtime.forwarding_terminal_completions()
    }

    #[cfg(test)]
    pub(crate) fn forwarding_terminal_outcomes_for_test(
        &self,
    ) -> crate::observation::ForwardingTerminalCounts {
        self.observation_runtime.forwarding_terminal_outcomes()
    }

    /// Transfers the complete prepared socket bundle into shared activation.
    pub(super) fn take_prepared_proxy_listeners_for_start(
        &self,
    ) -> Result<PreparedProxyListeners, ProductRuntimeError> {
        self.static_resources
            .take_prepared_listener_bundle()
            .map_err(Into::into)
    }

    pub(crate) async fn start_listeners(self: &Arc<Self>) -> Result<(), ProductRuntimeError> {
        self.start_listeners_inner(
            cfg!(target_os = "linux"),
            Arc::new(SystemOriginalDestinationProvider),
            |services| services,
            || {},
        )
        .await
    }

    #[cfg(test)]
    async fn start_listeners_with_transparent_support(
        self: &Arc<Self>,
        transparent_supported: bool,
    ) -> Result<(), ProductRuntimeError> {
        self.start_listeners_inner(
            transparent_supported,
            Arc::new(SystemOriginalDestinationProvider),
            |services| services,
            || {},
        )
        .await
    }

    #[cfg(test)]
    async fn start_listeners_with_original_destination(
        self: &Arc<Self>,
        original_destination: Arc<dyn OriginalDestinationProvider>,
    ) -> Result<(), ProductRuntimeError> {
        self.start_listeners_inner(true, original_destination, |services| services, || {})
            .await
    }

    #[cfg(test)]
    async fn start_listeners_with_next_connection_panic(
        self: &Arc<Self>,
    ) -> Result<(), ProductRuntimeError> {
        self.start_listeners_inner(
            cfg!(target_os = "linux"),
            Arc::new(SystemOriginalDestinationProvider),
            ListenerServices::with_next_connection_panic,
            || {},
        )
        .await
    }

    async fn start_listeners_inner(
        self: &Arc<Self>,
        transparent_supported: bool,
        original_destination: Arc<dyn OriginalDestinationProvider>,
        configure_services: impl FnOnce(ListenerServices) -> ListenerServices,
        before_adoption: impl FnOnce(),
    ) -> Result<(), ProductRuntimeError> {
        if !self.runtime.has_active_generation() {
            return Err(ProductRuntimeError::InitialGenerationNotPublished);
        }
        let prepared = self.take_prepared_proxy_listeners_for_start()?;
        let inputs = match prepared.into_runtime_inputs_with_transparent_support(
            transparent_supported,
            self.static_resources.access_flow_security_subscription(),
        ) {
            Ok(bundle) => bundle,
            Err(error) => {
                self.shutdown().await;
                return Err(error.into());
            }
        };
        let assets = self.static_resources.ingress_assets();
        let tcp_tls = ListenerTlsAcceptors::new(
            assets.static_https(),
            assets.plaintext_connect(),
            assets.tls_connect(),
            assets.transparent_https(),
        );
        let request_factory: Arc<dyn StandaloneRequestFactory> =
            ProductStandaloneRequestFactory::new(
                Arc::clone(&self.runtime),
                Arc::clone(&self.observation_runtime),
                Arc::clone(assets),
                self.static_resources.wire_body_pool(),
            );
        let identity_publisher = self.static_resources.identity_publisher();
        let http_bearer_admission: Arc<dyn http_access_runtime::HttpBearerAdmission> =
            identity_publisher.clone();
        let access_flow_service = http_access_runtime::HttpAccessFlowService::new(
            ListenerTlsAcceptors::new(
                assets.static_https(),
                assets.plaintext_connect(),
                assets.tls_connect(),
                assets.transparent_https(),
            ),
            Arc::clone(&http_bearer_admission),
            Arc::clone(&request_factory),
            self.static_resources.upgrade_runtime(),
        );
        let shared_runtime = match inputs.tcp {
            Some(bundle) => {
                let services = configure_services(ListenerServices::new(
                    original_destination,
                    self.static_resources.local_address_provider(),
                    Arc::new(ProductListenerFailureObserver {
                        static_resources: Arc::downgrade(&self.static_resources),
                    }),
                    tcp_tls,
                    http_bearer_admission,
                    request_factory,
                    self.static_resources.upgrade_runtime(),
                ));
                match ListenerRuntime::start(bundle, services) {
                    Ok(runtime) => Some(runtime),
                    Err(error) => {
                        self.shutdown().await;
                        return Err(error.into());
                    }
                }
            }
            None => None,
        };
        let failure_resources = Arc::downgrade(&self.static_resources);
        let access_flow_runtime = AccessFlowListenerRuntime::start(
            inputs.access_flow,
            access_flow_service,
            identity_publisher,
            Arc::new(move |error| {
                let Some(resources) = failure_resources.upgrade() else {
                    return;
                };
                tracing::error!(error = %error, "Access Flow listener failed");
                resources.record_listener_failure(error);
                StaticResources::begin_shutdown(resources.as_ref());
            }),
        );
        let listener_runtime =
            match ProductListenerRuntime::new(shared_runtime, access_flow_runtime) {
                Ok(runtime) => runtime,
                Err(error) => {
                    self.shutdown().await;
                    return Err(error.into());
                }
            };
        before_adoption();
        if let Err(error) = self
            .static_resources
            .adopt_listener_runtime(listener_runtime, inputs.unix_socket_lifetimes)
        {
            self.shutdown().await;
            return Err(error.into());
        }
        StaticResources::readiness(self.static_resources.as_ref()).mark_ingress_started();
        Ok(())
    }

    pub(crate) async fn wait_for_listener_failure(&self) -> Option<Arc<ProxyListenerFailure>> {
        self.static_resources.wait_for_listener_failure().await
    }

    pub(crate) async fn wait_for_control_failure(
        &self,
    ) -> Option<Arc<crate::control::server::ControlServerRunError>> {
        self.static_resources.wait_for_control_failure().await
    }

    pub(crate) async fn activate_initial(
        &self,
    ) -> Result<InitialActivationResult, ProductRuntimeError> {
        let initial = self
            .initial
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .ok_or(ProductRuntimeError::InitialActivationAlreadyAttempted)?;
        let policy_source_summary = initial.policy_source_summary.clone();
        let runtime = self.runtime.clone();
        let activation_runtime = runtime.clone();

        let activation = tokio::spawn(async move {
            match activation_runtime.start(initial).await {
                Ok(generation) => Ok(InitialActivationResult {
                    generation,
                    policy_source_summary,
                }),
                Err(error) => {
                    activation_runtime.shutdown().await;
                    Err(error)
                }
            }
        });

        match activation.await {
            Ok(result) => result.map_err(Into::into),
            Err(_) => {
                runtime.shutdown().await;
                Err(ProductRuntimeError::InitialActivationCoordinator)
            }
        }
    }

    pub(crate) async fn trigger_reload(&self) -> ProductReloadResult {
        let (configuration, access_flow_security) = tokio::join!(
            self.runtime.trigger_reload(),
            self.static_resources.reload_access_flow_security(),
        );
        ProductReloadResult {
            configuration,
            access_flow_security,
        }
    }

    pub(crate) async fn shutdown(&self) {
        self.runtime.shutdown().await;
    }

    pub(crate) fn shutdown_diagnostic(&self) -> Option<String> {
        let control = self.static_resources.control_shutdown_error();
        control.map(|error| format!("control server shutdown failed: {error}"))
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductRuntimeError {
    #[error(transparent)]
    TlsTrustSourcePreflight(#[from] crate::config::TlsTrustSourcePreflightError),
    #[error(transparent)]
    StaticResources(#[from] ProductStaticResourcesError),
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    #[error(transparent)]
    SharedListener(#[from] http_access_runtime::RuntimeError),
    #[error("initial activation has already been attempted")]
    InitialActivationAlreadyAttempted,
    #[error("initial activation coordinator did not complete")]
    InitialActivationCoordinator,
    #[error("proxy listeners cannot start before the initial generation is published")]
    InitialGenerationNotPublished,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::net::{SocketAddr, TcpListener};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    #[cfg(unix)]
    use std::path::PathBuf;
    use std::time::Duration;

    use access_flow::{AccessFlowDestination, AccessFlowPreface};
    use access_identity::{
        AuthorityId, IdentityPresentation, PrincipalId, PrincipalKind, PrincipalRef,
        SensitiveBearer,
    };
    use bytes::Bytes;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use http::{Method, Request, StatusCode, Version};
    use http_access_mitm::{GeneratedCertificateAuthority, PrivateStorageRoot};
    use rustls::pki_types::ServerName;
    use tempfile::tempdir;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;
    use crate::config::load_and_compile_exact_config;
    use crate::test_certificates::{client_config_for_roots, TestTlsIdentity};

    async fn write_access_flow_preface<W>(
        writer: &mut W,
        destination: AccessFlowDestination,
        presentation: &IdentityPresentation,
    ) -> Result<(), access_flow::AccessFlowWriteError>
    where
        W: tokio::io::AsyncWrite + Unpin + Send,
    {
        access_flow::write_access_flow_preface(writer, destination, presentation, None).await
    }

    fn config(explicit_http: SocketAddr, control: SocketAddr, extra: &str) -> String {
        format!(
            r#"schema_version = 4

[service]
shutdown_drain_timeout = "1s"

[control]
bind = "{control}"
base_path = "/_acl-proxy"
request_header_timeout = "1s"
request_body_timeout = "1s"
max_connections = 2
max_request_body_bytes = 65536

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "{explicit_http}"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

{extra}
"#
        )
    }

    fn loaded(text: &str) -> (tempfile::TempDir, LoadedCompiledConfig) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("acl-proxy.toml");
        fs::write(&path, text).unwrap();
        let loaded = load_and_compile_exact_config(&path).unwrap();
        (directory, loaded)
    }

    #[tokio::test]
    async fn initial_activation_returns_the_published_source_summary() {
        let test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&test);
        let addresses = reservations.addresses();
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], ""));
        let expected = loaded.compiled.policy_source_summary.clone();
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();

        let activated = product.activate_initial().await.unwrap();

        assert_eq!(activated.generation.get(), 1);
        assert_eq!(activated.policy_source_summary, expected);
        assert_eq!(
            product.runtime().active_policy_source_summary(),
            Some(expected)
        );
        product.shutdown().await;
    }

    #[tokio::test]
    async fn startup_preflights_custom_tls_trust_before_ingress_preparation() {
        let (_directory, loaded) = loaded(&config(
            "127.0.0.1:8881".parse().unwrap(),
            "127.0.0.1:8891".parse().unwrap(),
            "[egress.origin_tls]\ntrust = \"custom\"\nca_certificate = \"missing-ca.pem\"",
        ));

        let error = ProductRuntime::prepare_from_prebound(loaded, Vec::new())
            .await
            .err()
            .expect("missing TLS trust source must fail startup");
        assert!(matches!(
            error,
            ProductRuntimeError::TlsTrustSourcePreflight(_)
        ));
        let message = error.to_string();
        assert!(message.contains("egress.origin_tls.ca_certificate"));
        assert!(message.contains("missing-ca.pem"));
        assert!(message.contains("tls_trust_source_custody"));
    }

    async fn read_http_message(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
        let mut message = Vec::new();
        let header_end = loop {
            if let Some(offset) = message.windows(4).position(|window| window == b"\r\n\r\n") {
                break offset + 4;
            }
            let mut buffer = [0_u8; 4096];
            let count = stream.read(&mut buffer).await.unwrap();
            assert_ne!(count, 0, "HTTP peer closed before the complete head");
            message.extend_from_slice(&buffer[..count]);
        };
        let head = std::str::from_utf8(&message[..header_end]).unwrap();
        let content_length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        while message.len() < header_end + content_length {
            let mut buffer = [0_u8; 4096];
            let count = stream.read(&mut buffer).await.unwrap();
            assert_ne!(count, 0, "HTTP peer closed before the complete body");
            message.extend_from_slice(&buffer[..count]);
        }
        message
    }

    async fn read_http_head(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut byte))
                .await
                .expect("HTTP head read timed out")
                .expect("HTTP head ended early");
            head.push(byte[0]);
            assert!(head.len() <= 32 * 1024, "HTTP head exceeded test bound");
        }
        head
    }

    #[cfg(unix)]
    fn remote_tls_test_identity(
        prefix: &str,
    ) -> (tempfile::TempDir, TestTlsIdentity, PathBuf, PathBuf) {
        let directory = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(std::env::var_os("HOME").expect("HOME is configured"))
            .unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let identity = TestTlsIdentity::new("localhost");
        let certificate_path = directory.path().join("server-chain.pem");
        let private_key_path = directory.path().join("server-key.pem");
        crate::filesystem::write_public_file(&certificate_path, identity.certificate_chain_pem())
            .unwrap();
        crate::filesystem::write_private_file(&private_key_path, identity.private_key_pem())
            .unwrap();
        (directory, identity, certificate_path, private_key_path)
    }

    #[cfg(unix)]
    async fn wait_for_tls_adapter_snapshot(
        adapter: &access_flow_tls::TlsAccessFlowServerAdapter,
        predicate: impl Fn(access_flow_tls::TlsAccessFlowAdapterSnapshot) -> bool,
    ) -> access_flow_tls::TlsAccessFlowAdapterSnapshot {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let snapshot = adapter.snapshot();
                if predicate(snapshot) {
                    return snapshot;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("TLS Access Flow adapter did not reach the expected state")
    }

    #[cfg(unix)]
    async fn assert_stream_closes_promptly(stream: &mut (impl AsyncRead + Unpin)) {
        let mut byte = [0_u8; 1];
        let closed = tokio::time::timeout(Duration::from_millis(250), stream.read(&mut byte))
            .await
            .expect("rejected TLS Access Flow remained open");
        assert!(
            matches!(closed, Ok(0))
                || closed.is_err_and(|error| {
                    matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe
                    )
                }),
            "rejected TLS Access Flow produced application bytes"
        );
    }

    async fn h2_identity_request(
        sender: &mut h2::client::SendRequest<Bytes>,
        uri: &str,
        bearer: &str,
    ) -> h2::client::ResponseFuture {
        sender.clone().ready().await.unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_2)
            .uri(uri)
            .header("x-aw-identity-token", bearer)
            .body(())
            .unwrap();
        sender.send_request(request, true).unwrap().0
    }

    async fn collect_h2_response(response: h2::client::ResponseFuture) -> (StatusCode, Vec<u8>) {
        let response = response.await.unwrap();
        let status = response.status();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        (status, bytes)
    }

    fn capture_records(directory: &Path) -> Vec<crate::capture::CaptureRecord> {
        let mut records = Vec::new();
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if !path.is_file() {
                continue;
            }
            let contents = fs::read_to_string(path).unwrap();
            records.extend(
                contents
                    .lines()
                    .filter(|line| !line.is_empty())
                    .map(|line| serde_json::from_str(line).unwrap()),
            );
        }
        records
    }

    #[tokio::test]
    async fn capture_only_decoding_preserves_upstream_content_coding() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let extra = format!(
            r#"[redaction.profiles.capture]
replacement = "[MASKED]"
rules = [{{ literals = ["capture-redaction-sentinel"], payloads = "both" }}]

[observation.capture]
events = ["request.allowed", "response.allowed"]
redaction_profile = "capture"
directory = "captures"
max_body_bytes = 1048576
max_inflight_body_bytes = 134217728
max_pending_records = 8
max_files = 8
max_total_bytes = 1048576

[[policy.rules]]
id = "capture-only"
decision = "allow"
urls = ["http://{origin_address}/compressed"]
methods = ["POST"]
"#
        );
        let (directory, loaded) = loaded(&config(addresses[0], addresses[1], &extra));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let (captured_tx, captured_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let message = read_http_message(&mut stream).await;
            captured_tx.send(message).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\naccepted",
                )
                .await
                .unwrap();
        });

        let plain = b"opaque capture-redaction-sentinel payload";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plain).unwrap();
        let encoded = encoder.finish().unwrap();
        let mut client = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let head = format!(
            "POST http://{origin_address}/compressed HTTP/1.1\r\nHost: {origin_address}\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            encoded.len()
        );
        client.write_all(head.as_bytes()).await.unwrap();
        client.write_all(&encoded).await.unwrap();
        let response = read_http_message(&mut client).await;
        assert!(response.starts_with(b"HTTP/1.1 200"));

        let origin_message = captured_rx.await.unwrap();
        let origin_header_end = origin_message
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let origin_head = std::str::from_utf8(&origin_message[..origin_header_end]).unwrap();
        assert!(origin_head
            .lines()
            .any(|line| line.eq_ignore_ascii_case("content-encoding: gzip")));
        assert_eq!(&origin_message[origin_header_end..], encoded);

        product.shutdown().await;
        origin_task.await.unwrap();
        let request = capture_records(&directory.path().join("captures"))
            .into_iter()
            .find(|record| record.kind == crate::capture::CaptureKind::Request)
            .expect("missing request capture");
        assert_eq!(
            request.decode_body_bytes().unwrap(),
            b"opaque [MASKED] payload"
        );
        assert_eq!(
            request.body.unwrap().content_encoding.as_deref(),
            Some("identity")
        );
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn opted_in_opaque_upgrade_relays_both_directions_and_releases_runtime() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let origin = Arc::new(
            tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap(),
        );
        let origin_address = origin.local_addr().unwrap();
        let extra = format!(
            r#"[[policy.rules]]
id = "opaque-upgrade"
decision = "allow"
methods = ["GET"]
urls = ["http://{origin_address}/socket"]
allow_upgrades = true
"#
        );
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], &extra));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(request.contains("\r\nconnection: upgrade\r\n"));
            assert!(request.contains("\r\nupgrade: test-echo\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n",
                )
                .await
                .unwrap();
            let mut ping = [0_u8; 4];
            stream.read_exact(&mut ping).await.unwrap();
            assert_eq!(&ping, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let mut client = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://{origin_address}/socket HTTP/1.1\r\nHost: {origin_address}\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_message(&mut client).await;
        assert!(response.starts_with(b"HTTP/1.1 101"));
        client.write_all(b"ping").await.unwrap();
        let mut pong = [0_u8; 4];
        client.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
        drop(client);
        origin_task.await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), product.shutdown())
            .await
            .expect("completed upgrade retained shared runtime resources during shutdown");
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn upgrade_admission_saturation_rejects_before_second_origin_connect() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let extra = format!(
            r#"[[policy.rules]]
id = "one-upgrade"
decision = "allow"
urls = ["http://{origin_address}/**"]
allow_upgrades = true
"#
        );
        let text = config(addresses[0], addresses[1], &extra).replacen(
            "[control]",
            "max_active_upgrades = 1\n\n[control]",
            1,
        );
        let (_directory, loaded) = loaded(&text);
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let (release_tx, release_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let _request = read_http_message(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n",
                )
                .await
                .unwrap();
            release_rx.await.ok();
            assert!(
                tokio::time::timeout(Duration::from_millis(150), origin.accept())
                    .await
                    .is_err(),
                "saturated upgrade opened a second origin connection"
            );
        });

        let mut first = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        first
            .write_all(
                format!(
                    "GET http://{origin_address}/first HTTP/1.1\r\nHost: {origin_address}\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let first_response = read_http_message(&mut first).await;
        assert!(first_response.starts_with(b"HTTP/1.1 101"));

        let mut second = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        second
            .write_all(
                format!(
                    "GET http://{origin_address}/second HTTP/1.1\r\nHost: {origin_address}\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let second_response = read_http_message(&mut second).await;
        assert!(
            second_response.starts_with(b"HTTP/1.1 503"),
            "unexpected saturation response: {}",
            String::from_utf8_lossy(&second_response)
        );
        release_tx.send(()).unwrap();
        drop(first);
        origin_task.await.unwrap();
        product.shutdown().await;
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn upgrade_requires_explicit_rule_opt_in_before_origin_connect() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let extra = format!(
            r#"[[policy.rules]]
id = "ordinary-only"
decision = "allow"
methods = ["GET"]
urls = ["http://{origin_address}/socket"]
"#
        );
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], &extra));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let mut client = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://{origin_address}/socket HTTP/1.1\r\nHost: {origin_address}\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_message(&mut client).await;
        assert!(
            response.starts_with(b"HTTP/1.1 403"),
            "upgrade without opt-in did not fail closed: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(150), origin.accept())
                .await
                .is_err(),
            "upgrade without opt-in connected to the origin"
        );
        product.shutdown().await;
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn upstream_non_switching_response_remains_an_ordinary_http_response() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let extra = format!(
            r#"[[policy.rules]]
id = "upgrade-rejected"
decision = "allow"
methods = ["GET"]
urls = ["http://{origin_address}/socket"]
allow_upgrades = true
"#
        );
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], &extra));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(request.contains("\r\nconnection: upgrade\r\n"));
            assert!(request.contains("\r\nupgrade: test-echo\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 7\r\nConnection: close\r\n\r\nupgrade",
                )
                .await
                .unwrap();
        });

        let mut client = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://{origin_address}/socket HTTP/1.1\r\nHost: {origin_address}\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_message(&mut client).await;
        assert!(response.starts_with(b"HTTP/1.1 426 "));
        assert!(response.ends_with(b"\r\n\r\nupgrade"));
        assert_eq!(product.forwarding_terminal_completions_for_test(), 1);

        origin_task.await.unwrap();
        product.shutdown().await;
        assert_eq!(product.forwarding_terminal_completions_for_test(), 1);
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn capture_redaction_failure_is_observation_only() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let extra = format!(
            r#"[redaction.profiles.capture_failure]
replacement = "replacement-exceeds-limit"
max_body_bytes = 8
max_decoded_body_bytes = 8
rules = [{{ literals = ["secret"], payloads = "text" }}]

[observation.capture]
events = ["request.allowed", "response.allowed"]
redaction_profile = "capture_failure"
directory = "captures"
max_body_bytes = 8
max_inflight_body_bytes = 134217728
max_pending_records = 8
max_files = 8
max_total_bytes = 1048576

[[policy.rules]]
id = "capture-failure"
decision = "allow"
methods = ["POST"]
urls = ["http://{origin_address}/capture-failure"]
"#
        );
        let (directory, loaded) = loaded(&config(addresses[0], addresses[1], &extra));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            assert!(request.ends_with(b"\r\n\r\nsecret"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\naccepted",
                )
                .await
                .unwrap();
        });

        let mut client = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        client
            .write_all(
                format!(
                    "POST http://{origin_address}/capture-failure HTTP/1.1\r\nHost: {origin_address}\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_message(&mut client).await;
        assert!(
            response.starts_with(b"HTTP/1.1 200 "),
            "{}",
            String::from_utf8_lossy(&response)
        );
        assert!(response.ends_with(b"\r\n\r\naccepted"));

        origin_task.await.unwrap();
        product.shutdown().await;
        let records = capture_records(&directory.path().join("captures"));
        let request = records
            .iter()
            .find(|record| record.kind == crate::capture::CaptureKind::Request)
            .expect("missing request capture");
        assert_eq!(request.decision, crate::capture::CaptureDecision::Allow);
        assert!(request.body.is_none());
        assert!(request.body_truncated.is_none());
        let response = records
            .iter()
            .find(|record| record.kind == crate::capture::CaptureKind::Response)
            .expect("missing response capture");
        assert_eq!(response.decode_body_bytes().unwrap(), b"accepted");
        assert_eq!(product.forwarding_terminal_completions_for_test(), 1);
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[derive(Clone, Copy)]
    enum NormalizedListenerMode {
        Explicit,
        Transparent,
    }

    struct FixedOriginalDestinationForTest(SocketAddr);

    impl OriginalDestinationProvider for FixedOriginalDestinationForTest {
        fn original_destination(
            &self,
            _stream: &std::net::TcpStream,
        ) -> Result<SocketAddr, http_access_runtime::RuntimeError> {
            Ok(self.0)
        }
    }

    struct NormalizedRoundTrip {
        origin_head: String,
        origin_body: Vec<u8>,
        response_head: String,
        request_capture: crate::capture::CaptureRecord,
    }

    async fn normalized_round_trip(mode: NormalizedListenerMode) -> NormalizedRoundTrip {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<1>(&_test);
        let addresses = reservations.addresses();
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let (listener_table, listener_connect) = match mode {
            NormalizedListenerMode::Explicit => (
                "explicit_http",
                "[listeners.explicit_http.connect]\nhttp1 = \"deny\"\n",
            ),
            NormalizedListenerMode::Transparent => ("transparent_http", ""),
        };
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.{listener_table}]
endpoint.kind = "tcp"
endpoint.address = "{}"
http_versions = ["http1"]

{listener_connect}
[egress]
route = "direct"

[[egress.request_headers]]
operation = "append"
when = "always"
name = "x-mutation-order"
value = "global"

[safety.loop_detection]
inject = true
header = "x-test-loop"

[redaction.profiles.wire]
replacement = "[MASKED]"
max_body_bytes = 1048576
max_decoded_body_bytes = 1048576
rules = [{{ literals = ["absent-test-marker"], payloads = "text" }}]

[observation.capture]
events = ["request.allowed", "response.allowed"]
redaction_profile = "wire"
directory = "captures"
max_body_bytes = 1048576
max_inflight_body_bytes = 134217728
max_pending_records = 8
max_files = 8
max_total_bytes = 1048576

[policy]
default = "deny"

[[policy.rules]]
id = "normalized"
decision = "allow"
urls = ["http://{origin_address}/**"]
methods = ["POST"]
redaction_profile = "wire"

[[policy.rules.request_headers]]
operation = "set"
when = "always"
name = "x-mutation-order"
value = "rule"

[[policy.rules.response_headers]]
operation = "set"
when = "always"
name = "x-shaped-response"
value = "policy"
"#,
            addresses[0]
        );
        let (directory, loaded) = loaded(&text);
        let facts =
            http_access_runtime::ForwardingNetworkFacts::new(vec![addresses[0]], None, None, None)
                .unwrap();
        let origin_url =
            http_access_url::canonicalize_http_url(&format!("http://{origin_address}/")).unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(facts)
                .map_prebound(&origin_url, origin_address)
                .unwrap()
                .into_standalone_guard(),
        );
        let product = ProductRuntime::prepare_from_prebound_with_forwarding_network(
            loaded,
            reservations.into_listeners(),
            network,
        )
        .await
        .unwrap();
        product.activate_initial().await.unwrap();
        match mode {
            NormalizedListenerMode::Explicit => product.start_listeners().await.unwrap(),
            NormalizedListenerMode::Transparent => product
                .start_listeners_with_original_destination(Arc::new(
                    FixedOriginalDestinationForTest(origin_address),
                ))
                .await
                .unwrap(),
        }

        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nX-Shaped-Response: origin\r\nConnection: close\r\n\r\naccepted",
                )
                .await
                .unwrap();
            request
        });

        let plain = b"canonical decoded request bytes";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plain).unwrap();
        let encoded = encoder.finish().unwrap();
        assert_ne!(encoded, plain);
        let target = match mode {
            NormalizedListenerMode::Explicit => {
                format!("http://{origin_address}/ingest")
            }
            NormalizedListenerMode::Transparent => "/ingest".to_owned(),
        };
        let mut client = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        client
            .write_all(
                format!(
                    "POST {target} HTTP/1.1\r\nHost: {origin_address}\r\nContent-Type: application/octet-stream\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    encoded.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        client.write_all(&encoded).await.unwrap();
        let response = read_http_message(&mut client).await;
        assert!(response.starts_with(b"HTTP/1.1 200 "));
        assert!(response.ends_with(b"\r\n\r\naccepted"));

        let origin_request = origin_task.await.unwrap();
        let origin_header_end = origin_request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let origin_head = String::from_utf8(origin_request[..origin_header_end].to_vec()).unwrap();
        let origin_body = origin_request[origin_header_end..].to_vec();
        let response_header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let response_head = String::from_utf8(response[..response_header_end].to_vec()).unwrap();

        product.shutdown().await;
        assert_eq!(product.wire_body_pool().global_charge(), 0);
        let request_capture = capture_records(&directory.path().join("captures"))
            .into_iter()
            .find(|record| record.kind == crate::capture::CaptureKind::Request)
            .expect("missing normalized request capture");
        super::super::assert_listener_addresses_released(&_test, addresses);
        NormalizedRoundTrip {
            origin_head,
            origin_body,
            response_head,
            request_capture,
        }
    }

    #[tokio::test]
    async fn normalized_http_body_forwards_identity_without_recompression() {
        let captured = normalized_round_trip(NormalizedListenerMode::Explicit).await;
        assert_eq!(captured.origin_body, b"canonical decoded request bytes");
        let head = captured.origin_head.to_ascii_lowercase();
        let mutation_order = head
            .lines()
            .filter(|line| line.starts_with("x-mutation-order:"))
            .collect::<Vec<_>>();
        assert_eq!(
            mutation_order,
            ["x-mutation-order: rule", "x-mutation-order: global"]
        );
        assert!(head.contains("\r\nx-test-loop:"));
        assert!(captured
            .response_head
            .to_ascii_lowercase()
            .contains("\r\nx-shaped-response: policy\r\n"));
        assert_eq!(
            captured.request_capture.decode_body_bytes().unwrap(),
            b"canonical decoded request bytes"
        );
        assert_eq!(
            captured
                .request_capture
                .body
                .as_ref()
                .unwrap()
                .content_encoding
                .as_deref(),
            Some("identity")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn authenticated_bearer_has_explicit_http_and_access_flow_product_parity() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<1>(&_test);
        let addresses = reservations.addresses();
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket_path = directory.path().join("identity-access-flow.sock");
        let config_path = directory.path().join("acl-proxy.toml");
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        const VARIABLE: &str = "AW_PRODUCT_PARITY_IDENTITY_TOKEN";
        const BEARER: &str = "product-parity-identity-bearer-000000000000";
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "{}"
http_versions = ["http1"]

[listeners.explicit_http.identity]
mode = "required"

[listeners.explicit_http.connect]
http1 = "deny"

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]

[listeners.transparent_http.identity]
mode = "required"

[listeners.transparent_http.endpoint.transport]
kind = "unix"
path = {:?}
mode = "0600"

[identity]
max_pending_authentications = 8
max_pending_authentications_per_connection = 2

[identity.resolver]
kind = "static"
authority = "product-parity"

[[identity.resolver.principals]]
id = "test-workload"
kind = "service_account"

[[identity.resolver.tokens]]
id = "test-workload-primary"
principal = "test-workload"
source = "environment"
variable = "{VARIABLE}"

[egress]
route = "direct"

[[egress.request_headers]]
operation = "remove"
when = "always"
name = "x-aw-policy-context"

[authorization]
internal_context_headers = ["x-aw-policy-context"]
legacy_execution_context_header = "x-aw-policy-context"

[policy]
default = "deny"

[[policy.rules]]
id = "legacy-context"
decision = "allow"
urls = ["http://origin.example.test/explicit"]
methods = ["GET"]
execution_contexts = ["internal"]

[[policy.rules]]
id = "access-flow-context"
decision = "allow"
urls = ["http://origin.example.test/access-flow"]
methods = ["GET"]
execution_contexts = ["external"]
"#,
            addresses[0], socket_path
        );
        fs::write(&config_path, &text).unwrap();
        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        unsafe {
            std::env::set_var(VARIABLE, BEARER);
        }
        let identity_sources = crate::identity::IdentitySourceRegistry::activate().unwrap();
        identity_sources
            .preload(&loaded.compiled.reloadable_plan)
            .unwrap();
        assert!(std::env::var_os(VARIABLE).is_none());

        let origin_url =
            http_access_url::canonicalize_http_url("http://origin.example.test/").unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(
                    vec![addresses[0]],
                    None,
                    None,
                    None,
                )
                .unwrap(),
            )
            .map_prebound(&origin_url, origin_address)
            .unwrap()
            .into_standalone_guard(),
        );
        let product =
            ProductRuntime::prepare_from_prebound_with_forwarding_network_and_identity_sources(
                loaded,
                reservations.into_listeners(),
                network,
                identity_sources,
            )
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let origin_task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = origin.accept().await.unwrap();
                requests.push(read_http_message(&mut stream).await);
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\naccepted",
                    )
                    .await
                    .unwrap();
            }
            requests
        });

        let mut missing = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        missing
            .write_all(
                b"GET http://origin.example.test/missing HTTP/1.1\r\nHost: origin.example.test\r\nx-aw-policy-context: internal\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let missing_response = read_http_message(&mut missing).await;
        assert!(missing_response.starts_with(b"HTTP/1.1 403 "));
        assert!(missing_response.ends_with(b"\r\n\r\nidentity required\n"));

        let mut unknown = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        unknown
            .write_all(
                b"GET http://origin.example.test/unknown HTTP/1.1\r\nHost: origin.example.test\r\nx-aw-identity-token: unknown-product-identity-bearer-000000000000\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let unknown_response = read_http_message(&mut unknown).await;
        assert!(unknown_response.starts_with(b"HTTP/1.1 403 "));
        assert!(unknown_response.ends_with(b"\r\n\r\nidentity invalid\n"));

        let mut missing_context = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        missing_context
            .write_all(
                format!(
                    "GET http://origin.example.test/explicit HTTP/1.1\r\nHost: origin.example.test\r\nx-aw-identity-token: {BEARER}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let missing_context_response = read_http_message(&mut missing_context).await;
        assert!(missing_context_response.starts_with(b"HTTP/1.1 403 "));

        let mut explicit = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        explicit
            .write_all(
                format!(
                    "GET http://origin.example.test/explicit HTTP/1.1\r\nHost: origin.example.test\r\nx-aw-identity-token: {BEARER}\r\nx-aw-policy-context: internal\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let explicit_response = read_http_message(&mut explicit).await;
        assert!(explicit_response.starts_with(b"HTTP/1.1 200 "));

        let mut access_flow = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
        let presentation =
            IdentityPresentation::Bearer(SensitiveBearer::new(BEARER.as_bytes()).unwrap());
        let execution_context =
            access_execution_context::ExecutionContext::new("external").unwrap();
        access_flow::write_access_flow_preface(
            &mut access_flow,
            AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
            &presentation,
            Some(&execution_context),
        )
        .await
        .unwrap();
        access_flow
            .write_all(
                b"GET /access-flow HTTP/1.1\r\nHost: origin.example.test\r\nx-aw-policy-context: internal\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let access_flow_response = read_http_message(&mut access_flow).await;
        assert!(access_flow_response.starts_with(b"HTTP/1.1 200 "));

        for request in origin_task.await.unwrap() {
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(!request.contains("x-aw-identity-token"));
            assert!(!request.contains("x-aw-policy-context"));
        }

        product.shutdown().await;
        assert!(!socket_path.exists());
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_access_flow_security_change_closes_pending_admission_but_drains_active_flow() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<1>(&_test);
        let addresses = reservations.addresses();
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket_path = directory.path().join("unix-security-reload.sock");
        let config_path = directory.path().join("acl-proxy.toml");
        let origin = Arc::new(
            tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap(),
        );
        let origin_address = origin.local_addr().unwrap();
        let (_identity_directory, _identity, certificate_path, private_key_path) =
            remote_tls_test_identity(".acl-proxy-unix-security-reload-");
        const VARIABLE: &str = "AW_UNIX_SECURITY_RELOAD_IDENTITY_TOKEN";
        const BEARER: &str = "unix-security-reload-identity-bearer-00000000000";
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "5s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]
max_connections = 4

[listeners.transparent_http.identity]
mode = "required"

[listeners.transparent_http.endpoint.transport]
kind = "unix"
path = {:?}
mode = "0600"

[listeners.transparent_https]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [443]
http_versions = ["http1"]
handshake_timeout = "1s"
max_connections = 2

[listeners.transparent_https.identity]
mode = "required"

[listeners.transparent_https.endpoint.transport]
kind = "tls_tcp"
bind = "{}"
handshake_timeout = "2s"

[listeners.transparent_https.endpoint.transport.server_identity]
certificate_chain = {:?}
private_key = {:?}

[listeners.transparent_https.endpoint.transport.abuse_control]
max_handshakes = 2

[listeners.transparent_https.endpoint.transport.abuse_control.per_source]
max_connections = 2
handshakes_per_second = 100
handshake_burst = 100
source_table_capacity = 4

[identity]
max_pending_authentications = 4
max_pending_authentications_per_connection = 1

[identity.resolver]
kind = "static"
authority = "unix-security-reload"

[[identity.resolver.principals]]
id = "unix-workload"
kind = "service_account"

[[identity.resolver.tokens]]
id = "unix-workload-primary"
principal = "unix-workload"
source = "environment"
variable = "{VARIABLE}"

[mitm]
mode = "generated"
directory = "mitm"

[egress]
route = "direct"

[policy]
default = "deny"

[[policy.rules]]
id = "unix-security-drain"
decision = "allow"
urls = ["http://origin.example.test/drain"]
methods = ["GET"]
"#,
            socket_path, addresses[0], certificate_path, private_key_path
        );
        fs::write(&config_path, text).unwrap();
        unsafe {
            std::env::set_var(VARIABLE, BEARER);
        }
        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        let identity_sources = crate::identity::IdentitySourceRegistry::activate().unwrap();
        identity_sources
            .preload(&loaded.compiled.reloadable_plan)
            .unwrap();
        let origin_url =
            http_access_url::canonicalize_http_url("http://origin.example.test/").unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(
                    vec![addresses[0]],
                    None,
                    None,
                    None,
                )
                .unwrap(),
            )
            .map_prebound(&origin_url, origin_address)
            .unwrap()
            .into_standalone_guard(),
        );
        let product =
            ProductRuntime::prepare_from_prebound_with_forwarding_network_and_identity_sources(
                loaded,
                reservations.into_listeners(),
                network,
                identity_sources,
            )
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let (origin_active_send, origin_active_receive) = oneshot::channel();
        let (origin_release_send, origin_release_receive) = oneshot::channel();
        let active_origin = Arc::clone(&origin);
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = active_origin.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            assert!(request.starts_with(b"GET /drain HTTP/1.1\r\n"));
            origin_active_send.send(()).unwrap();
            origin_release_receive.await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ndrained",
                )
                .await
                .unwrap();
        });

        let presentation =
            IdentityPresentation::Bearer(SensitiveBearer::new(BEARER.as_bytes()).unwrap());
        let mut active = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
        write_access_flow_preface(
            &mut active,
            AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
            &presentation,
        )
        .await
        .unwrap();
        active
            .write_all(
                b"GET /drain HTTP/1.1\r\nHost: origin.example.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), origin_active_receive)
            .await
            .expect("Unix Access Flow was not fully admitted before reload")
            .unwrap();

        let pending_preface = AccessFlowPreface::new(
            AccessFlowDestination::new("203.0.113.9".parse().unwrap(), 80).unwrap(),
            IdentityPresentation::Bearer(SensitiveBearer::new(BEARER.as_bytes()).unwrap()),
            None,
        );
        let partial_preface = pending_preface.expose_encoded(|encoded| {
            assert!(encoded.len() > access_flow::ACCESS_FLOW_V2_HEADER_LEN);
            encoded[..encoded.len() - 1].to_vec()
        });
        let mut pending = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
        pending.write_all(&partial_preface).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        fs::write(&private_key_path, b"invalid private key").unwrap();
        let failed_reload = product.trigger_reload().await;
        assert!(failed_reload.configuration.is_ok());
        assert!(failed_reload.access_flow_security.is_err());
        assert!(!product.runtime().is_ready());
        assert_stream_closes_promptly(&mut pending).await;

        let mut rejected = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
        assert_stream_closes_promptly(&mut rejected).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), active.read_u8())
                .await
                .is_err(),
            "fully admitted Unix Access Flow closed during security reload"
        );

        origin_release_send.send(()).unwrap();
        let response = read_http_message(&mut active).await;
        assert!(response.ends_with(b"\r\n\r\ndrained"));
        origin_task.await.unwrap();

        product.shutdown().await;
        assert!(!socket_path.exists());
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn remote_tls_access_flow_requires_bearer_and_uses_the_http_pipeline() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<1>(&_test);
        let addresses = reservations.addresses();
        let config_directory = tempdir().unwrap();
        let identity_directory = tempfile::Builder::new()
            .prefix(".acl-proxy-remote-tls-")
            .tempdir_in(std::env::var_os("HOME").expect("HOME is configured"))
            .unwrap();
        fs::set_permissions(identity_directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let identity = TestTlsIdentity::new("localhost");
        let certificate_path = identity_directory.path().join("server-chain.pem");
        let private_key_path = identity_directory.path().join("server-key.pem");
        crate::filesystem::write_public_file(&certificate_path, identity.certificate_chain_pem())
            .unwrap();
        crate::filesystem::write_private_file(&private_key_path, identity.private_key_pem())
            .unwrap();
        let config_path = config_directory.path().join("acl-proxy.toml");
        let origin = Arc::new(
            tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap(),
        );
        let origin_address = origin.local_addr().unwrap();
        const VARIABLE: &str = "AW_REMOTE_TLS_PRODUCT_IDENTITY_TOKEN";
        const BEARER: &str = "remote-tls-product-identity-bearer-000000000000";
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]
max_connections = 8

[listeners.transparent_http.identity]
mode = "required"

[listeners.transparent_http.endpoint.transport]
kind = "tls_tcp"
bind = "{}"
handshake_timeout = "2s"

[listeners.transparent_http.endpoint.transport.server_identity]
certificate_chain = {:?}
private_key = {:?}

[listeners.transparent_http.endpoint.transport.abuse_control]
max_handshakes = 4

[listeners.transparent_http.endpoint.transport.abuse_control.per_source]
max_connections = 8
handshakes_per_second = 100
handshake_burst = 100
source_table_capacity = 16

[identity]
max_pending_authentications = 8
max_pending_authentications_per_connection = 2

[identity.resolver]
kind = "static"
authority = "remote-tls-product"

[[identity.resolver.principals]]
id = "test-workload"
kind = "service_account"

[[identity.resolver.tokens]]
id = "test-workload-primary"
principal = "test-workload"
source = "environment"
variable = "{VARIABLE}"

[egress]
route = "direct"

[policy]
default = "deny"

[[policy.rules]]
id = "remote-tls"
decision = "allow"
urls = ["http://origin.example.test/**"]
methods = ["GET"]
"#,
            addresses[0], certificate_path, private_key_path
        );
        fs::write(&config_path, &text).unwrap();
        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        unsafe {
            std::env::set_var(VARIABLE, BEARER);
        }
        let identity_sources = crate::identity::IdentitySourceRegistry::activate().unwrap();
        identity_sources
            .preload(&loaded.compiled.reloadable_plan)
            .unwrap();

        let origin_url =
            http_access_url::canonicalize_http_url("http://origin.example.test/").unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(
                    vec![addresses[0]],
                    None,
                    None,
                    None,
                )
                .unwrap(),
            )
            .map_prebound(&origin_url, origin_address)
            .unwrap()
            .into_standalone_guard(),
        );
        let product =
            ProductRuntime::prepare_from_prebound_with_forwarding_network_and_identity_sources(
                loaded,
                reservations.into_listeners(),
                network,
                identity_sources,
            )
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let wrong_alpn = TlsConnector::from(Arc::new(client_config_for_roots(
            [identity.root_certificate_der()],
            &[b"wrong-access-flow/1"],
        )));
        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        assert!(
            wrong_alpn
                .connect(ServerName::try_from("localhost").unwrap(), tcp)
                .await
                .is_err(),
            "a TLS client without the exact Access Flow ALPN completed"
        );

        let connector = TlsConnector::from(Arc::new(client_config_for_roots(
            [identity.root_certificate_der()],
            &[access_flow_tls::ACCESS_FLOW_TLS_ALPN_V2],
        )));
        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let mut anonymous = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        write_access_flow_preface(
            &mut anonymous,
            AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
            &IdentityPresentation::Anonymous,
        )
        .await
        .unwrap();
        anonymous
            .write_all(
                b"GET /anonymous HTTP/1.1\r\nHost: origin.example.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut rejected = [0_u8; 1];
        let rejected = tokio::time::timeout(Duration::from_secs(1), anonymous.read(&mut rejected))
            .await
            .expect("anonymous remote Access Flow was not rejected");
        assert!(
            matches!(rejected, Ok(0))
                || rejected.is_err_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof),
            "anonymous remote Access Flow produced application bytes"
        );

        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let mut unknown_bearer = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        write_access_flow_preface(
            &mut unknown_bearer,
            AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
            &IdentityPresentation::Bearer(
                SensitiveBearer::new(b"unknown-remote-tls-bearer-000000000000000000").unwrap(),
            ),
        )
        .await
        .unwrap();
        unknown_bearer
            .write_all(
                b"GET /unknown HTTP/1.1\r\nHost: origin.example.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        assert_stream_closes_promptly(&mut unknown_bearer).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), origin.accept())
                .await
                .is_err(),
            "an unknown bearer reached HTTP forwarding or the mapped upstream"
        );

        let request_origin = Arc::clone(&origin);
        let (release_body, body_release) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = request_origin.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n")
                .await
                .unwrap();
            stream.flush().await.unwrap();
            body_release.await.unwrap();
            stream.write_all(b"accepted").await.unwrap();
            stream.shutdown().await.unwrap();
            request
        });

        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let mut channel = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        assert_eq!(
            channel.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(
            channel.get_ref().1.alpn_protocol(),
            Some(access_flow_tls::ACCESS_FLOW_TLS_ALPN_V2)
        );
        write_access_flow_preface(
            &mut channel,
            AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
            &IdentityPresentation::Bearer(SensitiveBearer::new(BEARER.as_bytes()).unwrap()),
        )
        .await
        .unwrap();
        channel
            .write_all(b"GET /remote HTTP/1.1\r\nHost: origin.example.test\r\n\r\n")
            .await
            .unwrap();
        channel.shutdown().await.unwrap();
        let head = read_http_head(&mut channel).await;
        assert!(head.starts_with(b"HTTP/1.1 200 "));
        release_body.send(()).unwrap();
        let mut body = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), channel.read_to_end(&mut body))
            .await
            .expect("remote TLS Access Flow did not close after the delayed response")
            .unwrap();
        assert_eq!(body, b"accepted");
        let request = String::from_utf8(origin_task.await.unwrap())
            .unwrap()
            .to_ascii_lowercase();
        assert!(request.starts_with("get /remote http/1.1\r\n"));
        assert!(!request.contains("x-aw-identity-token"));

        let old_security = product
            .static_resources
            .access_flow_security_subscription()
            .current_tls_route(
                super::super::access_flow_security::AccessFlowTlsRouteId::TransparentHttp,
            )
            .unwrap();
        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let mut active_before_rotation = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        write_access_flow_preface(
            &mut active_before_rotation,
            AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
            &IdentityPresentation::Bearer(SensitiveBearer::new(BEARER.as_bytes()).unwrap()),
        )
        .await
        .unwrap();
        wait_for_tls_adapter_snapshot(&old_security.adapter, |snapshot| {
            snapshot.active_channels() == 1 && snapshot.held_source_permits() == 1
        })
        .await;
        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let mut stale_candidate = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        wait_for_tls_adapter_snapshot(&old_security.adapter, |snapshot| {
            snapshot.held_preface_permits() == 1 && snapshot.held_global_permits() == 1
        })
        .await;

        let rotated_identity = TestTlsIdentity::new("localhost");
        fs::write(&certificate_path, rotated_identity.certificate_chain_pem()).unwrap();
        fs::write(&private_key_path, rotated_identity.private_key_pem()).unwrap();
        let successful_rotation = product.trigger_reload().await;
        assert!(successful_rotation.configuration.is_ok());
        assert!(successful_rotation.access_flow_security.is_ok());
        assert!(product.runtime().is_ready());
        assert_stream_closes_promptly(&mut stale_candidate).await;
        wait_for_tls_adapter_snapshot(&old_security.adapter, |snapshot| {
            snapshot.connecting_channels() == 0
                && snapshot.active_channels() == 1
                && snapshot.held_global_permits() == 0
                && snapshot.held_handshake_permits() == 0
                && snapshot.held_preface_permits() == 0
                && snapshot.held_source_permits() == 1
        })
        .await;
        let rotated_origin = Arc::clone(&origin);
        let rotated_origin_task = tokio::spawn(async move {
            let (mut stream, _) = rotated_origin.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nrotated",
                )
                .await
                .unwrap();
            request
        });
        active_before_rotation
            .write_all(
                b"GET /after-successful-rotation HTTP/1.1\r\nHost: origin.example.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_http_message(&mut active_before_rotation).await;
        assert!(response.ends_with(b"\r\n\r\nrotated"));
        assert!(rotated_origin_task
            .await
            .unwrap()
            .starts_with(b"GET /after-successful-rotation HTTP/1.1\r\n"));
        drop(active_before_rotation);
        wait_for_tls_adapter_snapshot(&old_security.adapter, |snapshot| {
            snapshot.active_channels() == 0 && snapshot.held_source_permits() == 0
        })
        .await;

        let new_security = product
            .static_resources
            .access_flow_security_subscription()
            .current_tls_route(
                super::super::access_flow_security::AccessFlowTlsRouteId::TransparentHttp,
            )
            .unwrap();
        assert_ne!(new_security.generation, old_security.generation);
        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        assert!(
            connector
                .connect(ServerName::try_from("localhost").unwrap(), tcp)
                .await
                .is_err(),
            "the old trust root authenticated the rotated server identity"
        );
        let rotated_connector = TlsConnector::from(Arc::new(client_config_for_roots(
            [rotated_identity.root_certificate_der()],
            &[access_flow_tls::ACCESS_FLOW_TLS_ALPN_V2],
        )));
        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let mut rotated_candidate = rotated_connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        write_access_flow_preface(
            &mut rotated_candidate,
            AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
            &IdentityPresentation::Bearer(SensitiveBearer::new(BEARER.as_bytes()).unwrap()),
        )
        .await
        .unwrap();
        wait_for_tls_adapter_snapshot(&new_security.adapter, |snapshot| {
            snapshot.active_channels() == 1
                && snapshot.held_global_permits() == 0
                && snapshot.held_preface_permits() == 0
        })
        .await;

        fs::write(&private_key_path, b"invalid private key").unwrap();
        let failed_material_reload = product.trigger_reload().await;
        assert!(failed_material_reload.configuration.is_ok());
        assert!(failed_material_reload.access_flow_security.is_err());
        assert!(!product.runtime().is_ready());
        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let rejected_after_failed_reload = tokio::time::timeout(
            Duration::from_millis(500),
            rotated_connector.connect(ServerName::try_from("localhost").unwrap(), tcp),
        )
        .await
        .expect("new TLS admission stalled after a failed security-material reload");
        assert!(
            rejected_after_failed_reload.is_err(),
            "new TLS admission completed after a failed security-material reload"
        );
        let failed_reload_origin = Arc::clone(&origin);
        let failed_reload_origin_task = tokio::spawn(async move {
            let (mut stream, _) = failed_reload_origin.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nretained",
                )
                .await
                .unwrap();
            request
        });
        rotated_candidate
            .write_all(
                b"GET /after-failed-rotation HTTP/1.1\r\nHost: origin.example.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_http_message(&mut rotated_candidate).await;
        assert!(response.ends_with(b"\r\n\r\nretained"));
        assert!(failed_reload_origin_task
            .await
            .unwrap()
            .starts_with(b"GET /after-failed-rotation HTTP/1.1\r\n"));
        drop(rotated_candidate);
        wait_for_tls_adapter_snapshot(&new_security.adapter, |snapshot| {
            snapshot.active_channels() == 0 && snapshot.held_source_permits() == 0
        })
        .await;

        let recovered_identity =
            TestTlsIdentity::new_expiring_after("localhost", Duration::from_secs(2));
        fs::write(
            &certificate_path,
            recovered_identity.certificate_chain_pem(),
        )
        .unwrap();
        fs::write(&private_key_path, recovered_identity.private_key_pem()).unwrap();
        fs::write(&config_path, b"not valid TOML").unwrap();
        let failed_config_reload = product.trigger_reload().await;
        assert!(failed_config_reload.configuration.is_err());
        assert!(failed_config_reload.access_flow_security.is_ok());
        assert!(product.runtime().is_ready());

        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        assert!(
            rotated_connector
                .connect(ServerName::try_from("localhost").unwrap(), tcp)
                .await
                .is_err(),
            "rotation continued serving the previous TLS identity"
        );
        let recovered_connector = TlsConnector::from(Arc::new(client_config_for_roots(
            [recovered_identity.root_certificate_der()],
            &[access_flow_tls::ACCESS_FLOW_TLS_ALPN_V2],
        )));
        let recovered_security = product
            .static_resources
            .access_flow_security_subscription()
            .current_tls_route(
                super::super::access_flow_security::AccessFlowTlsRouteId::TransparentHttp,
            )
            .unwrap();
        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let mut active_at_expiry = recovered_connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .expect("rotated TLS identity was not published");
        write_access_flow_preface(
            &mut active_at_expiry,
            AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
            &IdentityPresentation::Bearer(SensitiveBearer::new(BEARER.as_bytes()).unwrap()),
        )
        .await
        .unwrap();
        wait_for_tls_adapter_snapshot(&recovered_security.adapter, |snapshot| {
            snapshot.active_channels() == 1 && snapshot.held_source_permits() == 1
        })
        .await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while product.runtime().is_ready() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("published TLS identity expiry did not close product readiness");
        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let rejected_after_expiry = tokio::time::timeout(
            Duration::from_millis(500),
            recovered_connector.connect(ServerName::try_from("localhost").unwrap(), tcp),
        )
        .await
        .expect("new TLS admission stalled after server-identity expiry");
        assert!(
            rejected_after_expiry.is_err(),
            "new TLS admission completed after server-identity expiry"
        );

        let expiry_origin = Arc::clone(&origin);
        let expiry_origin_task = tokio::spawn(async move {
            let (mut stream, _) = expiry_origin.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ndrained",
                )
                .await
                .unwrap();
            request
        });
        active_at_expiry
            .write_all(
                b"GET /after-expiry HTTP/1.1\r\nHost: origin.example.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_http_message(&mut active_at_expiry).await;
        assert!(response.ends_with(b"\r\n\r\ndrained"));
        assert!(expiry_origin_task
            .await
            .unwrap()
            .starts_with(b"GET /after-expiry HTTP/1.1\r\n"));
        drop(active_at_expiry);
        wait_for_tls_adapter_snapshot(&recovered_security.adapter, |snapshot| {
            snapshot.active_channels() == 0 && snapshot.held_source_permits() == 0
        })
        .await;

        product.shutdown().await;
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn remote_tls_access_flow_projects_provider_client_and_principal_wire_quota() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<1>(&_test);
        let addresses = reservations.addresses();
        let config_directory = tempdir().unwrap();
        let (_identity_directory, identity, certificate_path, private_key_path) =
            remote_tls_test_identity(".acl-proxy-remote-gate-a-");
        let provider_script = config_directory.path().join("provider.py");
        let provider_log = config_directory.path().join("provider.jsonl");
        let provider_release = config_directory.path().join("provider.release");
        fs::write(
            &provider_script,
            r#"import json, os, sys, time
pending = []
for line in sys.stdin:
    request = json.loads(line)
    pending.append(request)
    with open(sys.argv[1], "a", encoding="utf-8") as output:
        output.write(json.dumps(request, separators=(",", ":")) + "\n")
    if len(pending) == 3:
        while not os.path.exists(sys.argv[2]):
            time.sleep(0.01)
        for item in pending:
            print(json.dumps({"id": item["id"], "type": "response", "decision": "allow"}, separators=(",", ":")), flush=True)
        pending.clear()
"#,
        )
        .unwrap();
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let config_path = config_directory.path().join("acl-proxy.toml");
        const TOKEN_A: &str = "AW_REMOTE_TLS_GATE_A_IDENTITY_TOKEN";
        const TOKEN_B: &str = "AW_REMOTE_TLS_GATE_B_IDENTITY_TOKEN";
        const BEARER_A: &str = "remote-tls-gate-a-bearer-a-000000000000000";
        const BEARER_B: &str = "remote-tls-gate-a-bearer-b-000000000000000";
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "10s"
shutdown_drain_timeout = "1s"

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]
max_connections = 8

[listeners.transparent_http.identity]
mode = "required"

[listeners.transparent_http.endpoint.transport]
kind = "tls_tcp"
bind = "{}"
handshake_timeout = "2s"

[listeners.transparent_http.endpoint.transport.server_identity]
certificate_chain = {:?}
private_key = {:?}

[listeners.transparent_http.endpoint.transport.abuse_control]
max_handshakes = 4

[listeners.transparent_http.endpoint.transport.abuse_control.per_source]
max_connections = 8
handshakes_per_second = 100
handshake_burst = 100
source_table_capacity = 16

[identity]
max_pending_authentications = 8
max_pending_authentications_per_connection = 2

[identity.resolver]
kind = "static"
authority = "remote-tls-gate-a"

[[identity.resolver.principals]]
id = "principal-a"
kind = "service_account"

[[identity.resolver.principals]]
id = "principal-b"
kind = "service_account"

[[identity.resolver.tokens]]
id = "principal-a-token"
principal = "principal-a"
source = "environment"
variable = "{TOKEN_A}"

[[identity.resolver.tokens]]
id = "principal-b-token"
principal = "principal-b"
source = "environment"
variable = "{TOKEN_B}"

[authorization.providers.audit]
kind = "process"
command = "/usr/bin/python3"
args = [{:?}, {:?}, {:?}]
timeout = "10s"
include_identity = true
include_request_body = true
max_request_body_bytes = 1024
max_decoded_request_body_bytes = 1024
max_pending_requests = 8

[egress]
route = "direct"

[policy]
default = "deny"

[[policy.rules]]
id = "remote-gate-a"
decision = "delegate"
authorization_provider = "audit"
urls = ["http://origin.example.test/**"]
methods = ["POST"]
"#,
            addresses[0],
            certificate_path,
            private_key_path,
            provider_script,
            provider_log,
            provider_release,
        );
        fs::write(&config_path, text).unwrap();
        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        unsafe {
            std::env::set_var(TOKEN_A, BEARER_A);
            std::env::set_var(TOKEN_B, BEARER_B);
        }
        let identity_sources = crate::identity::IdentitySourceRegistry::activate().unwrap();
        identity_sources
            .preload(&loaded.compiled.reloadable_plan)
            .unwrap();

        let origin_url =
            http_access_url::canonicalize_http_url("http://origin.example.test/").unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(
                    vec![addresses[0]],
                    None,
                    None,
                    None,
                )
                .unwrap(),
            )
            .map_prebound(&origin_url, origin_address)
            .unwrap()
            .into_standalone_guard(),
        );
        let product =
            ProductRuntime::prepare_from_prebound_with_forwarding_network_and_identity_sources(
                loaded,
                reservations.into_listeners(),
                network,
                identity_sources,
            )
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let origin_task = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut stream, _) = origin.accept().await.unwrap();
                let request = read_http_message(&mut stream).await;
                assert!(request.ends_with(b"\r\n\r\ndata"));
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            }
        });
        let connector = TlsConnector::from(Arc::new(client_config_for_roots(
            [identity.root_certificate_der()],
            &[access_flow_tls::ACCESS_FLOW_TLS_ALPN_V2],
        )));
        let send = |bearer: &'static str| {
            let connector = connector.clone();
            async move {
                let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
                let mut channel = connector
                    .connect(ServerName::try_from("localhost").unwrap(), tcp)
                    .await
                    .unwrap();
                write_access_flow_preface(
                    &mut channel,
                    AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
                    &IdentityPresentation::Bearer(SensitiveBearer::new(bearer.as_bytes()).unwrap()),
                )
                .await
                .unwrap();
                channel
                    .write_all(
                        b"POST /quota HTTP/1.1\r\nHost: origin.example.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata",
                    )
                    .await
                    .unwrap();
                read_http_message(&mut channel).await
            }
        };
        let request_a1 = tokio::spawn(send(BEARER_A));
        let request_a2 = tokio::spawn(send(BEARER_A));
        let request_b = tokio::spawn(send(BEARER_B));

        let provider_records = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let records = fs::read_to_string(&provider_log).unwrap_or_default();
                let records = records
                    .lines()
                    .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                    .collect::<Vec<_>>();
                if records.len() == 3 {
                    break records;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("three provider requests were not dispatched");
        assert!(provider_records
            .iter()
            .all(|record| record["clientIp"] == "0.0.0.0"));

        let principal = |authority: &str, id: &str| {
            PrincipalRef::new(
                AuthorityId::new(authority).unwrap(),
                PrincipalId::new(id).unwrap(),
                PrincipalKind::ServiceAccount,
            )
        };
        let principal_a = crate::safety::WireBodyQuotaKey::Principal(principal(
            "remote-tls-gate-a",
            "principal-a",
        ));
        let principal_b = crate::safety::WireBodyQuotaKey::Principal(principal(
            "remote-tls-gate-a",
            "principal-b",
        ));
        let other_authority =
            crate::safety::WireBodyQuotaKey::Principal(principal("other-authority", "principal-a"));
        let pool = product.wire_body_pool();
        let charge_a = pool.quota_charge(&principal_a);
        let charge_b = pool.quota_charge(&principal_b);
        assert!(charge_a > charge_b, "{charge_a} must include two requests");
        assert!(charge_b > 0, "principal B must have an independent charge");
        assert_eq!(pool.quota_charge(&other_authority), 0);

        fs::write(&provider_release, b"release").unwrap();
        for request in [request_a1, request_a2, request_b] {
            let response = request.await.unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200 "));
        }
        origin_task.await.unwrap();
        assert_eq!(pool.quota_charge(&principal_a), 0);
        assert_eq!(pool.quota_charge(&principal_b), 0);

        product.shutdown().await;
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn remote_tls_access_flow_enforces_response_admission_quotas_by_principal() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<1>(&_test);
        let addresses = reservations.addresses();
        let config_directory = tempdir().unwrap();
        let (_identity_directory, identity, certificate_path, private_key_path) =
            remote_tls_test_identity(".acl-proxy-remote-response-quota-");
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let config_path = config_directory.path().join("acl-proxy.toml");
        const TOKEN_A: &str = "AW_REMOTE_TLS_RESPONSE_QUOTA_A_IDENTITY_TOKEN";
        const TOKEN_B: &str = "AW_REMOTE_TLS_RESPONSE_QUOTA_B_IDENTITY_TOKEN";
        const BEARER_A: &str = "remote-tls-response-quota-a-0000000000000000";
        const BEARER_B: &str = "remote-tls-response-quota-b-0000000000000000";
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "10s"
shutdown_drain_timeout = "1s"

[service.forwarding]
max_request_wire_bytes = 1024
max_request_decoded_bytes = 1024
max_response_wire_bytes = 1024
max_response_decoded_bytes = 1024
chunk_bytes = 1024
preserve_request_trailers = false
max_trailer_count = 4
max_trailer_bytes = 256

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]
max_connections = 16

[listeners.transparent_http.identity]
mode = "required"

[listeners.transparent_http.endpoint.transport]
kind = "tls_tcp"
bind = "{}"
handshake_timeout = "2s"

[listeners.transparent_http.endpoint.transport.server_identity]
certificate_chain = {:?}
private_key = {:?}

[listeners.transparent_http.endpoint.transport.abuse_control]
max_handshakes = 8

[listeners.transparent_http.endpoint.transport.abuse_control.per_source]
max_connections = 16
handshakes_per_second = 100
handshake_burst = 100
source_table_capacity = 16

[identity]
max_pending_authentications = 8
max_pending_authentications_per_connection = 1

[identity.resolver]
kind = "static"
authority = "remote-tls-response-quota"

[[identity.resolver.principals]]
id = "principal-a"
kind = "service_account"

[[identity.resolver.principals]]
id = "principal-b"
kind = "service_account"

[[identity.resolver.tokens]]
id = "principal-a-token"
principal = "principal-a"
source = "environment"
variable = "{TOKEN_A}"

[[identity.resolver.tokens]]
id = "principal-b-token"
principal = "principal-b"
source = "environment"
variable = "{TOKEN_B}"

[egress]
route = "direct"

[policy]
default = "deny"

[[policy.rules]]
id = "bounded-response"
decision = "allow"
methods = ["GET"]
urls = ["http://origin.example.test/**"]
"#,
            addresses[0], certificate_path, private_key_path
        );
        fs::write(&config_path, &text).unwrap();
        let sizing = load_and_compile_exact_config(&config_path).unwrap();
        let resources = &sizing.compiled.reloadable_plan.resource_plan;
        let response_peak = resources.forward_response_peak_bytes;
        let exchange_peak = resources.max_reachable_http_exchange_peak_bytes;
        assert!(response_peak > 0);
        assert!(exchange_peak >= response_peak);
        let global_peak = exchange_peak.checked_mul(4).unwrap();
        let text = text.replacen(
            "shutdown_drain_timeout = \"1s\"",
            &format!(
                "shutdown_drain_timeout = \"1s\"\nmax_inflight_wire_body_bytes = {global_peak}\nmax_inflight_wire_body_bytes_per_quota_key = {exchange_peak}\nmin_wire_body_concurrency = 4"
            ),
            1,
        );
        fs::write(&config_path, text).unwrap();
        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        unsafe {
            std::env::set_var(TOKEN_A, BEARER_A);
            std::env::set_var(TOKEN_B, BEARER_B);
        }
        let identity_sources = crate::identity::IdentitySourceRegistry::activate().unwrap();
        identity_sources
            .preload(&loaded.compiled.reloadable_plan)
            .unwrap();
        let origin_url =
            http_access_url::canonicalize_http_url("http://origin.example.test/").unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(
                    vec![addresses[0]],
                    None,
                    None,
                    None,
                )
                .unwrap(),
            )
            .map_prebound(&origin_url, origin_address)
            .unwrap()
            .into_standalone_guard(),
        );
        let product =
            ProductRuntime::prepare_from_prebound_with_forwarding_network_and_identity_sources(
                loaded,
                reservations.into_listeners(),
                network,
                identity_sources,
            )
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let (check_tx, check_rx) = tokio::sync::oneshot::channel();
        let (checked_tx, checked_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let mut held = Vec::new();
            for expected in ["/held-a", "/held-b"] {
                let (mut stream, _) = tokio::time::timeout(Duration::from_secs(2), origin.accept())
                    .await
                    .expect("admitted remote TLS request did not reach the origin")
                    .unwrap();
                let request = read_http_message(&mut stream).await;
                assert!(
                    request.starts_with(format!("GET {expected} HTTP/1.1\r\n").as_bytes()),
                    "unexpected origin request: {}",
                    String::from_utf8_lossy(&request)
                );
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                held.push(stream);
            }
            check_rx.await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(250), origin.accept())
                    .await
                    .is_err(),
                "a quota-rejected remote TLS request reached the origin"
            );
            checked_tx.send(()).unwrap();
            release_rx.await.unwrap();
            for mut stream in held {
                stream.write_all(b"x").await.unwrap();
            }
            let (mut recovered, _) = tokio::time::timeout(Duration::from_secs(2), origin.accept())
                .await
                .expect("released quota did not permit a recovery request")
                .unwrap();
            let request = read_http_message(&mut recovered).await;
            assert!(request.starts_with(b"GET /recovered-a HTTP/1.1\r\n"));
            recovered
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nr")
                .await
                .unwrap();
        });

        let connector = TlsConnector::from(Arc::new(client_config_for_roots(
            [identity.root_certificate_der()],
            &[access_flow_tls::ACCESS_FLOW_TLS_ALPN_V2],
        )));
        let open = |bearer: &'static str, path: &'static str| {
            let connector = connector.clone();
            async move {
                let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
                let mut channel = connector
                    .connect(ServerName::try_from("localhost").unwrap(), tcp)
                    .await
                    .unwrap();
                write_access_flow_preface(
                    &mut channel,
                    AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
                    &IdentityPresentation::Bearer(SensitiveBearer::new(bearer.as_bytes()).unwrap()),
                )
                .await
                .unwrap();
                channel
                    .write_all(
                        format!(
                            "GET {path} HTTP/1.1\r\nHost: origin.example.test\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                channel
            }
        };
        let quota_key = |id: &str| {
            crate::safety::WireBodyQuotaKey::Principal(PrincipalRef::new(
                AuthorityId::new("remote-tls-response-quota").unwrap(),
                PrincipalId::new(id).unwrap(),
                PrincipalKind::ServiceAccount,
            ))
        };
        let principal_a = quota_key("principal-a");
        let principal_b = quota_key("principal-b");
        let pool = product.wire_body_pool();

        let mut held = Vec::new();
        let mut first = open(BEARER_A, "/held-a").await;
        assert!(read_http_head(&mut first)
            .await
            .starts_with(b"HTTP/1.1 200 "));
        assert!(pool.quota_charge(&principal_a) >= response_peak);
        held.push(first);

        let mut same_principal = open(BEARER_A, "/same-principal").await;
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            read_http_message(&mut same_principal),
        )
        .await
        .expect("same-principal rejection timed out");
        assert!(
            response.starts_with(b"HTTP/1.1 503 "),
            "same-principal saturation was not rejected: {}",
            String::from_utf8_lossy(&response)
        );

        let mut independent = open(BEARER_B, "/held-b").await;
        assert!(read_http_head(&mut independent)
            .await
            .starts_with(b"HTTP/1.1 200 "));
        assert!(
            pool.quota_charge(&principal_b) >= response_peak,
            "principal B did not retain its independent reservation"
        );
        held.push(independent);
        check_tx.send(()).unwrap();
        checked_rx.await.unwrap();

        release_tx.send(()).unwrap();
        for mut channel in held {
            let mut body = [0_u8; 1];
            channel.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"x");
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while pool.global_charge() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed remote TLS responses retained wire-body quota");
        for key in [&principal_a, &principal_b] {
            assert_eq!(pool.quota_charge(key), 0);
        }

        let mut recovered = open(BEARER_A, "/recovered-a").await;
        let response = read_http_message(&mut recovered).await;
        assert!(response.starts_with(b"HTTP/1.1 200 "));
        assert!(response.ends_with(b"\r\n\r\nr"));
        origin_task.await.unwrap();
        assert_eq!(pool.global_charge(), 0);

        product.shutdown().await;
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn remote_tls_access_flow_v1_uses_context_free_nested_mitm_pipeline() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<1>(&_test);
        let addresses = reservations.addresses();
        let config_directory = tempdir().unwrap();
        let (_identity_directory, outer_identity, certificate_path, private_key_path) =
            remote_tls_test_identity(".acl-proxy-remote-https-");
        let config_path = config_directory.path().join("acl-proxy.toml");
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_identity = TestTlsIdentity::new("origin.example.test");
        let origin_acceptor =
            TlsAcceptor::from(Arc::new(origin_identity.server_config(&[b"http/1.1"])));
        const VARIABLE: &str = "AW_REMOTE_TLS_HTTPS_IDENTITY_TOKEN";
        let vectors = access_flow_conformance::load_awaf_vector_suite().unwrap();
        let v1_bearer_vector = vectors
            .vectors()
            .iter()
            .find(|vector| vector.name() == "bearer")
            .unwrap();
        let v1_bearer = v1_bearer_vector.wire().to_vec();
        let bearer = std::str::from_utf8(
            &v1_bearer[v1_bearer.len() - v1_bearer_vector.presentation_length()..],
        )
        .unwrap()
        .to_owned();
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.transparent_https]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [443]
http_versions = ["http1"]
handshake_timeout = "1s"
max_connections = 4

[listeners.transparent_https.identity]
mode = "required"

[listeners.transparent_https.endpoint.transport]
kind = "tls_tcp"
bind = "{}"
handshake_timeout = "2s"

[listeners.transparent_https.endpoint.transport.server_identity]
certificate_chain = {:?}
private_key = {:?}

[listeners.transparent_https.endpoint.transport.abuse_control]
max_handshakes = 2

[listeners.transparent_https.endpoint.transport.abuse_control.per_source]
max_connections = 4
handshakes_per_second = 100
handshake_burst = 100
source_table_capacity = 8

[identity]
max_pending_authentications = 4
max_pending_authentications_per_connection = 1

[identity.resolver]
kind = "static"
authority = "remote-tls-https"

[[identity.resolver.principals]]
id = "https-workload"
kind = "service_account"

[[identity.resolver.tokens]]
id = "https-workload-primary"
principal = "https-workload"
source = "environment"
variable = "{VARIABLE}"

[mitm]
mode = "generated"
directory = "mitm"

[egress]
route = "direct"

[egress.access_flow_execution_context]
urls = ["https://origin.example.test/**"]

[egress.origin_tls]
trust = "insecure"
http_versions = ["http1"]

[policy]
default = "deny"

[[policy.rules]]
id = "remote-tls-transparent-https-context"
decision = "allow"
methods = ["GET"]
urls = ["https://origin.example.test/context-only"]
execution_contexts = ["external"]

[[policy.rules]]
id = "remote-tls-transparent-https"
decision = "allow"
methods = ["GET"]
urls = ["https://origin.example.test/outer-tls-mitm"]
"#,
            addresses[0], certificate_path, private_key_path
        );
        fs::write(&config_path, text).unwrap();
        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        unsafe {
            std::env::set_var(VARIABLE, &bearer);
        }
        let identity_sources = crate::identity::IdentitySourceRegistry::activate().unwrap();
        identity_sources
            .preload(&loaded.compiled.reloadable_plan)
            .unwrap();

        let ca_root =
            PrivateStorageRoot::open_or_create(&config_directory.path().join("mitm")).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let generated =
            GeneratedCertificateAuthority::open_or_generate(ca_root, i64::try_from(now).unwrap())
                .unwrap();
        let mitm_ca_chain = generated.public_ca_chain_der();
        drop(generated);

        let origin_url =
            http_access_url::canonicalize_http_url("https://origin.example.test/").unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(
                    vec![addresses[0]],
                    None,
                    None,
                    None,
                )
                .unwrap(),
            )
            .map_prebound(&origin_url, origin_address)
            .unwrap()
            .into_standalone_guard(),
        );
        let product =
            ProductRuntime::prepare_from_prebound_with_forwarding_network_and_identity_sources(
                loaded,
                reservations.into_listeners(),
                network,
                identity_sources,
            )
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let outer_connector = TlsConnector::from(Arc::new(client_config_for_roots(
            [outer_identity.root_certificate_der()],
            &[access_flow_tls::ACCESS_FLOW_TLS_ALPN_V1],
        )));
        let inner_connector = TlsConnector::from(Arc::new(client_config_for_roots(
            mitm_ca_chain,
            &[b"http/1.1"],
        )));

        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let mut denied_outer = outer_connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        assert_eq!(
            denied_outer.get_ref().1.alpn_protocol(),
            Some(access_flow_tls::ACCESS_FLOW_TLS_ALPN_V1)
        );
        denied_outer.write_all(&v1_bearer).await.unwrap();
        let mut denied = inner_connector
            .connect(
                ServerName::try_from("origin.example.test").unwrap(),
                denied_outer,
            )
            .await
            .unwrap();
        denied
            .write_all(
                b"GET /context-only HTTP/1.1\r\nHost: origin.example.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_http_message(&mut denied).await;
        assert!(response.starts_with(b"HTTP/1.1 403 "));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), origin.accept())
                .await
                .is_err()
        );

        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            let mut stream = origin_acceptor.accept(stream).await.unwrap();
            let request = read_http_message(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nnested mitm accepted",
                )
                .await
                .unwrap();
            request
        });

        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let mut outer = outer_connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        assert_eq!(
            outer.get_ref().1.alpn_protocol(),
            Some(access_flow_tls::ACCESS_FLOW_TLS_ALPN_V1)
        );
        outer.write_all(&v1_bearer).await.unwrap();

        let mut client = inner_connector
            .connect(ServerName::try_from("origin.example.test").unwrap(), outer)
            .await
            .unwrap();
        client
            .write_all(
                b"GET /outer-tls-mitm HTTP/1.1\r\nHost: origin.example.test\r\nX-Agent-Access-Context: spoofed\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_http_message(&mut client).await;
        assert!(response.starts_with(b"HTTP/1.1 200 "));
        assert!(response.ends_with(b"\r\n\r\nnested mitm accepted"));

        let request = String::from_utf8(origin_task.await.unwrap())
            .unwrap()
            .to_ascii_lowercase();
        assert!(request.starts_with("get /outer-tls-mitm http/1.1\r\n"));
        assert!(!request.contains("x-aw-identity-token"));
        assert!(!request.contains("x-agent-access-context"));

        product.shutdown().await;
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn remote_tls_access_flow_accept_coordinator_closes_at_handshake_capacity() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<1>(&_test);
        let addresses = reservations.addresses();
        let config_directory = tempdir().unwrap();
        let (_identity_directory, _identity, certificate_path, private_key_path) =
            remote_tls_test_identity(".acl-proxy-remote-overflow-");
        let config_path = config_directory.path().join("acl-proxy.toml");
        const VARIABLE: &str = "AW_REMOTE_TLS_OVERFLOW_IDENTITY_TOKEN";
        const BEARER: &str = "remote-tls-overflow-identity-bearer-00000000000";
        let text = format!(
            r#"schema_version = 4

[service]
shutdown_drain_timeout = "1s"

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]
max_connections = 2

[listeners.transparent_http.identity]
mode = "required"

[listeners.transparent_http.endpoint.transport]
kind = "tls_tcp"
bind = "{}"
handshake_timeout = "2s"

[listeners.transparent_http.endpoint.transport.server_identity]
certificate_chain = {:?}
private_key = {:?}

[listeners.transparent_http.endpoint.transport.abuse_control]
max_handshakes = 2

[listeners.transparent_http.endpoint.transport.abuse_control.per_source]
max_connections = 3
handshakes_per_second = 100
handshake_burst = 100
source_table_capacity = 4

[identity]
max_pending_authentications = 2
max_pending_authentications_per_connection = 1

[identity.resolver]
kind = "static"
authority = "remote-overflow"

[[identity.resolver.principals]]
id = "overflow-workload"
kind = "service_account"

[[identity.resolver.tokens]]
id = "overflow-workload-primary"
principal = "overflow-workload"
source = "environment"
variable = "{VARIABLE}"

[egress]
route = "direct"

[policy]
default = "deny"
"#,
            addresses[0], certificate_path, private_key_path
        );
        fs::write(&config_path, text).unwrap();
        unsafe {
            std::env::set_var(VARIABLE, BEARER);
        }
        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        let identity_sources = crate::identity::IdentitySourceRegistry::activate().unwrap();
        identity_sources
            .preload(&loaded.compiled.reloadable_plan)
            .unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(
                    vec![addresses[0]],
                    None,
                    None,
                    None,
                )
                .unwrap(),
            )
            .into_standalone_guard(),
        );
        let product =
            ProductRuntime::prepare_from_prebound_with_forwarding_network_and_identity_sources(
                loaded,
                reservations.into_listeners(),
                network,
                identity_sources,
            )
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let security = product.static_resources.access_flow_security_subscription();
        let adapter = security
            .current_tls_route(
                super::super::access_flow_security::AccessFlowTlsRouteId::TransparentHttp,
            )
            .unwrap()
            .adapter;

        let first = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        wait_for_tls_adapter_snapshot(&adapter, |snapshot| snapshot.held_handshake_permits() == 1)
            .await;
        let second = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let saturated = wait_for_tls_adapter_snapshot(&adapter, |snapshot| {
            snapshot.held_handshake_permits() == 2
        })
        .await;
        assert_eq!(saturated.held_global_permits(), 2);
        assert_eq!(saturated.connecting_channels(), 2);

        let mut overflow = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        assert_stream_closes_promptly(&mut overflow).await;
        let still_saturated = adapter.snapshot();
        assert_eq!(still_saturated.held_handshake_permits(), 2);
        assert_eq!(still_saturated.connecting_channels(), 2);

        drop(first);
        drop(second);
        wait_for_tls_adapter_snapshot(&adapter, |snapshot| {
            snapshot.held_handshake_permits() == 0
                && snapshot.held_global_permits() == 0
                && snapshot.connecting_channels() == 0
        })
        .await;

        product.shutdown().await;
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    // The fixture needs distinct 127.0.0.1 and 127.0.0.2 source addresses;
    // Linux routes all of 127/8 through loopback by default.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn remote_tls_access_flow_enforces_source_rate_table_and_admission_timeout() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<1>(&_test);
        let addresses = reservations.addresses();
        let config_directory = tempdir().unwrap();
        let (_identity_directory, identity, certificate_path, private_key_path) =
            remote_tls_test_identity(".acl-proxy-remote-source-limits-");
        let config_path = config_directory.path().join("acl-proxy.toml");
        const VARIABLE: &str = "AW_REMOTE_TLS_LIMITS_IDENTITY_TOKEN";
        const BEARER: &str = "remote-tls-limits-identity-bearer-0000000000000";
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "100ms"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]
max_connections = 4

[listeners.transparent_http.identity]
mode = "required"

[listeners.transparent_http.endpoint.transport]
kind = "tls_tcp"
bind = "{}"
handshake_timeout = "2s"

[listeners.transparent_http.endpoint.transport.server_identity]
certificate_chain = {:?}
private_key = {:?}

[listeners.transparent_http.endpoint.transport.abuse_control]
max_handshakes = 4

[listeners.transparent_http.endpoint.transport.abuse_control.per_source]
max_connections = 2
handshakes_per_second = 1
handshake_burst = 1
source_table_capacity = 1

[identity]
max_pending_authentications = 4
max_pending_authentications_per_connection = 1

[identity.resolver]
kind = "static"
authority = "remote-limits"

[[identity.resolver.principals]]
id = "limits-workload"
kind = "service_account"

[[identity.resolver.tokens]]
id = "limits-workload-primary"
principal = "limits-workload"
source = "environment"
variable = "{VARIABLE}"

[egress]
route = "direct"

[policy]
default = "deny"
"#,
            addresses[0], certificate_path, private_key_path
        );
        fs::write(&config_path, text).unwrap();
        unsafe {
            std::env::set_var(VARIABLE, BEARER);
        }
        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        let identity_sources = crate::identity::IdentitySourceRegistry::activate().unwrap();
        identity_sources
            .preload(&loaded.compiled.reloadable_plan)
            .unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(
                    vec![addresses[0]],
                    None,
                    None,
                    None,
                )
                .unwrap(),
            )
            .into_standalone_guard(),
        );
        let product =
            ProductRuntime::prepare_from_prebound_with_forwarding_network_and_identity_sources(
                loaded,
                reservations.into_listeners(),
                network,
                identity_sources,
            )
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let security = product.static_resources.access_flow_security_subscription();
        let adapter = security
            .current_tls_route(
                super::super::access_flow_security::AccessFlowTlsRouteId::TransparentHttp,
            )
            .unwrap()
            .adapter;
        let connector = TlsConnector::from(Arc::new(client_config_for_roots(
            [identity.root_certificate_der()],
            &[access_flow_tls::ACCESS_FLOW_TLS_ALPN_V2],
        )));

        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let mut active = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        write_access_flow_preface(
            &mut active,
            AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
            &IdentityPresentation::Bearer(SensitiveBearer::new(BEARER.as_bytes()).unwrap()),
        )
        .await
        .unwrap();
        wait_for_tls_adapter_snapshot(&adapter, |snapshot| {
            snapshot.active_channels() == 1 && snapshot.held_source_permits() == 1
        })
        .await;

        let mut rate_limited = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        assert_stream_closes_promptly(&mut rate_limited).await;
        let snapshot = adapter.snapshot();
        assert_eq!(snapshot.active_channels(), 1);
        assert_eq!(snapshot.held_source_permits(), 1);

        let alternate = tokio::net::TcpSocket::new_v4().unwrap();
        alternate
            .bind((std::net::Ipv4Addr::new(127, 0, 0, 2), 0).into())
            .unwrap();
        let mut source_table_limited = alternate.connect(addresses[0]).await.unwrap();
        assert_stream_closes_promptly(&mut source_table_limited).await;
        let snapshot = adapter.snapshot();
        assert_eq!(snapshot.active_channels(), 1);
        assert_eq!(snapshot.held_source_permits(), 1);

        drop(active);
        wait_for_tls_adapter_snapshot(&adapter, |snapshot| {
            snapshot.active_channels() == 0 && snapshot.held_source_permits() == 0
        })
        .await;

        let alternate = tokio::net::TcpSocket::new_v4().unwrap();
        alternate
            .bind((std::net::Ipv4Addr::new(127, 0, 0, 2), 0).into())
            .unwrap();
        let tcp = alternate.connect(addresses[0]).await.unwrap();
        let mut preface_timeout = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        wait_for_tls_adapter_snapshot(&adapter, |snapshot| {
            snapshot.held_preface_permits() == 1 && snapshot.held_source_permits() == 1
        })
        .await;
        assert_stream_closes_promptly(&mut preface_timeout).await;
        wait_for_tls_adapter_snapshot(&adapter, |snapshot| {
            snapshot.connecting_channels() == 0
                && snapshot.active_channels() == 0
                && snapshot.held_global_permits() == 0
                && snapshot.held_handshake_permits() == 0
                && snapshot.held_preface_permits() == 0
                && snapshot.held_source_permits() == 0
        })
        .await;

        product.shutdown().await;
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn remote_tls_access_flow_active_capacity_is_no_wait_and_shutdown_is_deadline_bound() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<1>(&_test);
        let addresses = reservations.addresses();
        let config_directory = tempdir().unwrap();
        let (_identity_directory, identity, certificate_path, private_key_path) =
            remote_tls_test_identity(".acl-proxy-remote-active-");
        let config_path = config_directory.path().join("acl-proxy.toml");
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        const VARIABLE: &str = "AW_REMOTE_TLS_ACTIVE_IDENTITY_TOKEN";
        const BEARER: &str = "remote-tls-active-identity-bearer-000000000000";
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]
max_connections = 1

[listeners.transparent_http.identity]
mode = "required"

[listeners.transparent_http.endpoint.transport]
kind = "tls_tcp"
bind = "{}"
handshake_timeout = "2s"

[listeners.transparent_http.endpoint.transport.server_identity]
certificate_chain = {:?}
private_key = {:?}

[listeners.transparent_http.endpoint.transport.abuse_control]
max_handshakes = 2

[listeners.transparent_http.endpoint.transport.abuse_control.per_source]
max_connections = 3
handshakes_per_second = 100
handshake_burst = 100
source_table_capacity = 4

[identity]
max_pending_authentications = 2
max_pending_authentications_per_connection = 1

[identity.resolver]
kind = "static"
authority = "remote-active"

[[identity.resolver.principals]]
id = "active-workload"
kind = "service_account"

[[identity.resolver.tokens]]
id = "active-workload-primary"
principal = "active-workload"
source = "environment"
variable = "{VARIABLE}"

[egress]
route = "direct"

[policy]
default = "deny"

[[policy.rules]]
id = "remote-active"
decision = "allow"
urls = ["http://origin.example.test/stalled"]
methods = ["GET"]
"#,
            addresses[0], certificate_path, private_key_path
        );
        fs::write(&config_path, text).unwrap();
        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        unsafe {
            std::env::set_var(VARIABLE, BEARER);
        }
        let identity_sources = crate::identity::IdentitySourceRegistry::activate().unwrap();
        identity_sources
            .preload(&loaded.compiled.reloadable_plan)
            .unwrap();
        let origin_url =
            http_access_url::canonicalize_http_url("http://origin.example.test/").unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(
                    vec![addresses[0]],
                    None,
                    None,
                    None,
                )
                .unwrap(),
            )
            .map_prebound(&origin_url, origin_address)
            .unwrap()
            .into_standalone_guard(),
        );
        let product =
            ProductRuntime::prepare_from_prebound_with_forwarding_network_and_identity_sources(
                loaded,
                reservations.into_listeners(),
                network,
                identity_sources,
            )
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let security = product.static_resources.access_flow_security_subscription();
        let adapter = security
            .current_tls_route(
                super::super::access_flow_security::AccessFlowTlsRouteId::TransparentHttp,
            )
            .unwrap()
            .adapter;
        let connector = TlsConnector::from(Arc::new(client_config_for_roots(
            [identity.root_certificate_der()],
            &[access_flow_tls::ACCESS_FLOW_TLS_ALPN_V2],
        )));

        let (origin_active_send, origin_active_receive) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            assert!(request.starts_with(b"GET /stalled HTTP/1.1\r\n"));
            origin_active_send.send(()).unwrap();
            let mut byte = [0_u8; 1];
            stream.read(&mut byte).await.unwrap_or(0)
        });

        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let mut active = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        write_access_flow_preface(
            &mut active,
            AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
            &IdentityPresentation::Bearer(SensitiveBearer::new(BEARER.as_bytes()).unwrap()),
        )
        .await
        .unwrap();
        active
            .write_all(
                b"GET /stalled HTTP/1.1\r\nHost: origin.example.test\r\nConnection: keep-alive\r\n\r\n",
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), origin_active_receive)
            .await
            .expect("remote TLS Access Flow request did not reach the stalled origin")
            .unwrap();
        let admitted = wait_for_tls_adapter_snapshot(&adapter, |snapshot| {
            snapshot.active_channels() == 1
                && snapshot.held_global_permits() == 0
                && snapshot.held_preface_permits() == 0
        })
        .await;
        assert_eq!(admitted.held_source_permits(), 1);

        let tcp = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let mut overflow = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        write_access_flow_preface(
            &mut overflow,
            AccessFlowDestination::new("203.0.113.9".parse().unwrap(), 80).unwrap(),
            &IdentityPresentation::Bearer(SensitiveBearer::new(BEARER.as_bytes()).unwrap()),
        )
        .await
        .unwrap();
        assert_stream_closes_promptly(&mut overflow).await;
        let after_overflow = wait_for_tls_adapter_snapshot(&adapter, |snapshot| {
            snapshot.active_channels() == 1
                && snapshot.held_global_permits() == 0
                && snapshot.held_preface_permits() == 0
        })
        .await;
        assert_eq!(after_overflow.held_source_permits(), 1);
        assert!(
            !origin_task.is_finished(),
            "active flow ended when an overflow flow was rejected"
        );

        let runtime = product.static_resources.listener_runtime_for_test();
        tokio::time::timeout(
            Duration::from_millis(250),
            runtime.stop_admission_and_wait_closed(),
        )
        .await
        .expect("remote TLS Access Flow admission closure waited for the active flow");
        assert!(
            tokio::net::TcpStream::connect(addresses[0]).await.is_err(),
            "remote TLS Access Flow listener still admitted TCP after closure"
        );
        assert!(
            !origin_task.is_finished(),
            "active flow ended while only listener admission was closed"
        );

        let deadline = std::time::Instant::now() + Duration::from_millis(150);
        let shutdown = tokio::spawn(async move {
            runtime.shutdown_and_wait(Some(deadline)).await;
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !shutdown.is_finished(),
            "active remote TLS Access Flow drained before the caller deadline"
        );
        tokio::time::timeout(Duration::from_secs(1), shutdown)
            .await
            .expect("remote TLS Access Flow join exceeded its caller deadline")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), origin_task)
            .await
            .expect("forced remote TLS Access Flow cancellation did not close the origin")
            .unwrap();
        assert_stream_closes_promptly(&mut active).await;

        product.shutdown().await;
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn process_identity_saturation_precedes_provider_parent_and_capture_work() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<1>(&_test);
        let addresses = reservations.addresses();
        let parent = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let parent_address = parent.local_addr().unwrap();
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("acl-proxy.toml");
        let provider_script = directory.path().join("provider.py");
        let provider_log = directory.path().join("provider.jsonl");
        fs::write(
            &provider_script,
            r#"import json, sys
for line in sys.stdin:
    request = json.loads(line)
    with open(sys.argv[1], "a", encoding="utf-8") as output:
        output.write(json.dumps(request, separators=(",", ":")) + "\n")
    print(json.dumps({"id": request["id"], "type": "response", "decision": "allow"}, separators=(",", ":")), flush=True)
"#,
        )
        .unwrap();
        const VARIABLE: &str = "AW_PROCESS_SATURATION_IDENTITY_TOKEN";
        const BEARER: &str = "process-saturation-identity-bearer-000000000";
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "{}"
http_versions = ["http1"]

[listeners.explicit_http.identity]
mode = "required"

[listeners.explicit_http.connect]
http1 = "deny"

[identity]
max_pending_authentications = 1
max_pending_authentications_per_connection = 1

[identity.resolver]
kind = "static"
authority = "process-saturation"

[[identity.resolver.principals]]
id = "saturation-workload"
kind = "service_account"

[[identity.resolver.tokens]]
id = "saturation-workload-primary"
principal = "saturation-workload"
source = "environment"
variable = "{VARIABLE}"

[authorization.providers.audit]
kind = "process"
command = "/usr/bin/python3"
args = [{:?}, {:?}]
include_headers = ["x-visible"]

[egress]
route = "parent_proxy"

[egress.parent_proxy]
kind = "generic"
url = "http://parent.test:8080"

[redaction.profiles.audit]
rules = [{{ literals = ["capture-marker"] }}]

[observation.capture]
events = ["request.allowed", "request.denied"]
redaction_profile = "audit"
directory = "captures"
max_body_bytes = 1024
max_inflight_body_bytes = 134217728
max_pending_records = 8
max_files = 8
max_total_bytes = 1048576

[policy]
default = "deny"

[[policy.rules]]
id = "saturation-delegate"
decision = "delegate"
authorization_provider = "audit"
urls = ["http://origin.example.test/**"]
methods = ["GET"]
"#,
            addresses[0], provider_script, provider_log
        );
        fs::write(&config_path, text).unwrap();
        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        unsafe {
            std::env::set_var(VARIABLE, BEARER);
        }
        let identity_sources = crate::identity::IdentitySourceRegistry::activate().unwrap();
        identity_sources
            .preload(&loaded.compiled.reloadable_plan)
            .unwrap();
        assert!(std::env::var_os(VARIABLE).is_none());

        let parent_url =
            http_access_url::canonicalize_http_url("http://parent.test:8080/").unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(
                    vec![addresses[0]],
                    None,
                    None,
                    None,
                )
                .unwrap(),
            )
            .map_local_parent(&parent_url, parent_address)
            .unwrap()
            .into_standalone_guard(),
        );
        let product =
            ProductRuntime::prepare_from_prebound_with_forwarding_network_and_identity_sources(
                loaded,
                reservations.into_listeners(),
                network,
                identity_sources,
            )
            .await
            .unwrap();
        let gate = crate::identity::IdentityAdmissionGate::new();
        product
            .identity_publisher_for_test()
            .set_admission_gate_for_test(Arc::clone(&gate));
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let (parent_request_tx, mut parent_request_rx) = oneshot::channel();
        let parent_task = tokio::spawn(async move {
            let (mut stream, _) = parent.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            parent_request_tx.send(request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\naccepted",
                )
                .await
                .unwrap();
        });

        let first_address = addresses[0];
        let first = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(first_address).await.unwrap();
            stream
                .write_all(
                    format!(
                        "GET http://origin.example.test/first HTTP/1.1\r\nHost: origin.example.test\r\nx-aw-identity-token: {BEARER}\r\nx-visible: retained\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            read_http_message(&mut stream).await
        });
        tokio::time::timeout(Duration::from_secs(2), gate.wait_for_entries(1))
            .await
            .expect("first authentication reached the deterministic gate");

        let mut overloaded = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        overloaded
            .write_all(
                format!(
                    "GET http://origin.example.test/overloaded HTTP/1.1\r\nHost: origin.example.test\r\nx-aw-identity-token: {BEARER}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let overloaded = read_http_message(&mut overloaded).await;
        assert!(overloaded.starts_with(b"HTTP/1.1 503 "));
        assert!(overloaded.ends_with(b"\r\n\r\nservice unavailable\n"));
        assert!(
            !provider_log.exists(),
            "saturated authentication reached the policy provider"
        );
        assert!(
            matches!(
                parent_request_rx.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "saturated authentication reached the generic parent"
        );

        gate.release(1);
        let first_response = first.await.unwrap();
        assert!(first_response.starts_with(b"HTTP/1.1 200 "));
        let parent_request = parent_request_rx.await.unwrap();
        let parent_request_lower = String::from_utf8(parent_request)
            .unwrap()
            .to_ascii_lowercase();
        assert!(!parent_request_lower.contains("x-aw-identity-token"));
        assert!(!parent_request_lower.contains(BEARER));

        parent_task.await.unwrap();
        product.shutdown().await;

        let provider_request = fs::read_to_string(&provider_log).unwrap();
        assert_eq!(provider_request.lines().count(), 1);
        assert!(!provider_request.contains("x-aw-identity-token"));
        assert!(!provider_request.contains(BEARER));
        let captures = capture_records(&directory.path().join("captures"));
        assert!(!captures.is_empty());
        let captures = serde_json::to_string(&captures)
            .unwrap()
            .to_ascii_lowercase();
        assert!(captures.contains("/first"));
        assert!(
            !captures.contains("/overloaded"),
            "saturated authentication produced capture work"
        );
        assert!(!captures.contains("x-aw-identity-token"));
        assert!(!captures.contains(BEARER));
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn connection_identity_saturation_is_isolated_before_origin_work() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<1>(&_test);
        let addresses = reservations.addresses();
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("acl-proxy.toml");
        const VARIABLE: &str = "AW_CONNECTION_SATURATION_IDENTITY_TOKEN";
        const BEARER: &str = "connection-saturation-identity-bearer-000000";
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "{}"
http_versions = ["http2"]
max_concurrent_streams = 8

[listeners.explicit_http.identity]
mode = "required"

[listeners.explicit_http.connect]
http2 = "deny"

[identity]
max_pending_authentications = 2
max_pending_authentications_per_connection = 1

[identity.resolver]
kind = "static"
authority = "connection-saturation"

[[identity.resolver.principals]]
id = "saturation-workload"
kind = "service_account"

[[identity.resolver.tokens]]
id = "saturation-workload-primary"
principal = "saturation-workload"
source = "environment"
variable = "{VARIABLE}"

[egress]
route = "direct"

[egress.origin_tls]
trust = "system"
http_versions = ["http1"]

[policy]
default = "allow"
"#,
            addresses[0]
        );
        fs::write(&config_path, text).unwrap();
        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        unsafe {
            std::env::set_var(VARIABLE, BEARER);
        }
        let identity_sources = crate::identity::IdentitySourceRegistry::activate().unwrap();
        identity_sources
            .preload(&loaded.compiled.reloadable_plan)
            .unwrap();
        assert!(std::env::var_os(VARIABLE).is_none());

        let origin_url =
            http_access_url::canonicalize_http_url(&format!("http://{origin_address}/")).unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(
                    vec![addresses[0]],
                    None,
                    None,
                    None,
                )
                .unwrap(),
            )
            .map_prebound(&origin_url, origin_address)
            .unwrap()
            .into_standalone_guard(),
        );
        let product =
            ProductRuntime::prepare_from_prebound_with_forwarding_network_and_identity_sources(
                loaded,
                reservations.into_listeners(),
                network,
                identity_sources,
            )
            .await
            .unwrap();
        let gate = crate::identity::IdentityAdmissionGate::new();
        product
            .identity_publisher_for_test()
            .set_admission_gate_for_test(Arc::clone(&gate));
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let origin_task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = origin.accept().await.unwrap();
                requests.push(read_http_message(&mut stream).await);
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\naccepted",
                    )
                    .await
                    .unwrap();
            }
            requests
        });

        let stream = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let (mut first_sender, first_connection) = h2::client::handshake(stream).await.unwrap();
        let first_driver = tokio::spawn(first_connection);
        let first = h2_identity_request(
            &mut first_sender,
            &format!("http://{origin_address}/first"),
            BEARER,
        )
        .await;
        tokio::time::timeout(Duration::from_secs(2), gate.wait_for_entries(1))
            .await
            .expect("first connection reached the deterministic gate");

        let overloaded = h2_identity_request(
            &mut first_sender,
            &format!("http://{origin_address}/overloaded"),
            BEARER,
        )
        .await;
        let (status, body) = collect_h2_response(overloaded).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, b"service unavailable\n");

        let stream = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let (mut isolated_sender, isolated_connection) =
            h2::client::handshake(stream).await.unwrap();
        let isolated_driver = tokio::spawn(isolated_connection);
        let isolated = h2_identity_request(
            &mut isolated_sender,
            &format!("http://{origin_address}/isolated"),
            BEARER,
        )
        .await;
        tokio::time::timeout(Duration::from_secs(2), gate.wait_for_entries(2))
            .await
            .expect("a separate connection retained independent authentication capacity");

        gate.release(2);
        let (first_status, first_body) = collect_h2_response(first).await;
        let (isolated_status, isolated_body) = collect_h2_response(isolated).await;
        assert_eq!(
            (first_status, first_body.as_slice()),
            (StatusCode::OK, b"accepted".as_slice())
        );
        assert_eq!(
            (isolated_status, isolated_body.as_slice()),
            (StatusCode::OK, b"accepted".as_slice())
        );
        let origin_requests = origin_task.await.unwrap();
        assert_eq!(origin_requests.len(), 2);
        for request in origin_requests {
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(!request.contains("x-aw-identity-token"));
            assert!(!request.contains(BEARER));
        }

        drop(first_sender);
        drop(isolated_sender);
        product.shutdown().await;
        first_driver.await.unwrap().unwrap();
        isolated_driver.await.unwrap().unwrap();
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn typed_acl_parent_presentation_is_injected_only_at_the_parent_boundary() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<1>(&_test);
        let addresses = reservations.addresses();
        let parent = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let parent_address = parent.local_addr().unwrap();
        let parent_identity = TestTlsIdentity::new("parent.test");
        let parent_identity_directory = tempfile::Builder::new()
            .prefix("acl-proxy-parent-ca-")
            .tempdir_in(std::env::var_os("HOME").expect("HOME is configured"))
            .unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            parent_identity_directory.path(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let parent_ca_path = parent_identity_directory.path().join("parent-ca.pem");
        crate::filesystem::write_public_file(
            &parent_ca_path,
            parent_identity.certificate_chain_pem(),
        )
        .unwrap();
        const INBOUND_VARIABLE: &str = "AW_INBOUND_PRODUCT_IDENTITY_TOKEN";
        const INBOUND_BEARER: &str = "inbound-product-identity-bearer-000000000000";
        const PARENT_VARIABLE: &str = "AW_PARENT_PRODUCT_IDENTITY_TOKEN";
        const PARENT_BEARER: &str = "parent-product-identity-bearer-0000000000000";
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "{}"
http_versions = ["http1"]

[listeners.explicit_http.identity]
mode = "required"

[listeners.explicit_http.connect]
http1 = "mitm"

[mitm]
mode = "generated"
directory = "mitm"

[identity]
max_pending_authentications = 8
max_pending_authentications_per_connection = 2

[identity.resolver]
kind = "static"
authority = "parent-boundary"

[[identity.resolver.principals]]
id = "inbound-workload"
kind = "service_account"

[[identity.resolver.tokens]]
id = "inbound-workload-primary"
principal = "inbound-workload"
source = "environment"
variable = "{INBOUND_VARIABLE}"

[egress]
route = "parent_proxy"

[egress.parent_proxy]
kind = "acl_proxy"
url = "https://parent.test:8443"

[egress.parent_proxy.presentation]
kind = "bearer_environment"
variable = "{PARENT_VARIABLE}"

[egress.parent_proxy.tls]
trust = "custom"
ca_certificate = {parent_ca_path:?}

[[egress.request_headers]]
operation = "remove"
when = "always"
name = "x-aw-policy-context"

[authorization]
internal_context_headers = ["x-aw-policy-context"]
legacy_execution_context_header = "x-aw-policy-context"

[policy]
default = "deny"

[[policy.rules]]
id = "direct-http"
decision = "allow"
urls = ["http://origin.example.test/resource"]
methods = ["GET"]

[[policy.rules]]
id = "connect-bootstrap"
decision = "allow"
urls = ["**"]
methods = ["CONNECT"]

[[policy.rules]]
id = "legacy-context-inside-connect"
decision = "allow"
urls = ["https://origin.example.test/inside-connect"]
methods = ["GET"]
execution_contexts = ["internal"]
"#,
            addresses[0]
        );
        let (directory, loaded) = loaded(&text);
        let generated_root =
            http_access_mitm::PrivateStorageRoot::open_or_create(&directory.path().join("mitm"))
                .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let generated_ca = http_access_mitm::GeneratedCertificateAuthority::open_or_generate(
            generated_root,
            i64::try_from(now).unwrap(),
        )
        .unwrap()
        .public_ca_chain_der();
        unsafe {
            std::env::set_var(INBOUND_VARIABLE, INBOUND_BEARER);
            std::env::set_var(PARENT_VARIABLE, PARENT_BEARER);
        }
        let identity_sources = crate::identity::IdentitySourceRegistry::activate().unwrap();
        identity_sources
            .preload(&loaded.compiled.reloadable_plan)
            .unwrap();
        assert!(std::env::var_os(INBOUND_VARIABLE).is_none());
        assert!(std::env::var_os(PARENT_VARIABLE).is_none());

        let parent_url =
            http_access_url::canonicalize_http_url("https://parent.test:8443/").unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(
                    vec![addresses[0]],
                    None,
                    None,
                    None,
                )
                .unwrap(),
            )
            .map_local_parent(&parent_url, parent_address)
            .unwrap()
            .into_standalone_guard(),
        );
        let product =
            ProductRuntime::prepare_from_prebound_with_forwarding_network_and_identity_sources(
                loaded,
                reservations.into_listeners(),
                network,
                identity_sources,
            )
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let parent_task = tokio::spawn(async move {
            let acceptor =
                TlsAcceptor::from(Arc::new(parent_identity.server_config(&[b"http/1.1"])));
            let mut requests = Vec::new();
            for index in 0..2 {
                let (stream, _) = parent.accept().await.unwrap();
                let mut stream = acceptor.accept(stream).await.unwrap();
                requests.push(read_http_message(&mut stream).await);
                let response = if index == 0 {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\naccepted"
                        .as_slice()
                } else {
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .as_slice()
                };
                stream.write_all(response).await.unwrap();
            }
            requests
        });

        let mut client = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://origin.example.test/resource HTTP/1.1\r\nHost: origin.example.test\r\nx-aw-identity-token: {INBOUND_BEARER}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_message(&mut client).await;
        assert!(
            response.starts_with(b"HTTP/1.1 200 "),
            "{}",
            String::from_utf8_lossy(&response)
        );

        let mut connect = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        connect
            .write_all(
                format!(
                    "CONNECT origin.example.test:443 HTTP/1.1\r\nHost: origin.example.test:443\r\nx-aw-identity-token: {INBOUND_BEARER}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let connect_response = read_http_message(&mut connect).await;
        assert!(
            connect_response.starts_with(b"HTTP/1.1 "),
            "{}",
            String::from_utf8_lossy(&connect_response)
        );
        let connector = TlsConnector::from(Arc::new(client_config_for_roots(
            generated_ca,
            &[b"http/1.1"],
        )));
        let mut tunnel = connector
            .connect(
                ServerName::try_from("origin.example.test").unwrap(),
                connect,
            )
            .await
            .unwrap();
        tunnel
            .write_all(
                b"GET /inside-connect HTTP/1.1\r\nHost: origin.example.test\r\nx-aw-policy-context: internal\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();

        let requests = tokio::time::timeout(Duration::from_secs(2), parent_task)
            .await
            .expect("typed parent did not receive the CONNECT request")
            .unwrap()
            .into_iter()
            .map(|request| String::from_utf8(request).unwrap())
            .collect::<Vec<_>>();
        let parent_request = &requests[0];
        assert!(
            parent_request.starts_with("GET http://origin.example.test/resource HTTP/1.1\r\n"),
            "{parent_request}"
        );
        assert!(
            requests[1].starts_with("CONNECT origin.example.test:443 HTTP/1.1\r\n"),
            "{}",
            requests[1]
        );
        for parent_request in requests {
            let lower = parent_request.to_ascii_lowercase();
            assert!(
                lower.contains(&format!("\r\nx-aw-identity-token: {PARENT_BEARER}\r\n")),
                "{parent_request}"
            );
            assert!(!parent_request.contains(INBOUND_BEARER), "{parent_request}");
        }

        product.shutdown().await;
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn access_flow_transparent_http_uses_the_existing_product_pipeline() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket_path = directory.path().join("transparent-http.sock");
        let config_path = directory.path().join("acl-proxy.toml");
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]

[listeners.transparent_http.endpoint.transport]
kind = "unix"
path = {:?}
mode = "0600"

[egress]
route = "direct"

[policy]
default = "deny"

[[policy.rules]]
id = "unix-transparent"
decision = "allow"
urls = ["http://origin.example.test/**"]
methods = ["GET"]

[safety.loop_detection]
inject = true
header = "x-test-loop"
"#,
            socket_path
        );
        fs::write(&config_path, text).unwrap();
        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        let origin_url =
            http_access_url::canonicalize_http_url("http://origin.example.test/").unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(Vec::new(), None, None, None)
                    .unwrap(),
            )
            .map_prebound(&origin_url, origin_address)
            .unwrap()
            .into_standalone_guard(),
        );
        let product = ProductRuntime::prepare_from_prebound_with_forwarding_network(
            loaded,
            Vec::new(),
            network,
        )
        .await
        .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\naccepted",
                )
                .await
                .unwrap();
            request
        });

        let mut client = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
        write_access_flow_preface(
            &mut client,
            AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
            &IdentityPresentation::Disabled,
        )
        .await
        .unwrap();
        client
            .write_all(
                b"GET /uds HTTP/1.1\r\nHost: origin.example.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_http_message(&mut client).await;
        assert!(response.starts_with(b"HTTP/1.1 200 "));
        assert!(response.ends_with(b"\r\n\r\naccepted"));
        let request = origin_task.await.unwrap();
        assert!(request.starts_with(b"GET /uds HTTP/1.1\r\n"));
        assert!(String::from_utf8_lossy(&request)
            .to_ascii_lowercase()
            .contains("\r\nx-test-loop:"));

        product.shutdown().await;
        assert!(!socket_path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn access_flow_stalled_preface_does_not_block_a_second_admission() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket_path = directory.path().join("concurrent-admission.sock");
        let config_path = directory.path().join("acl-proxy.toml");
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]
max_connections = 2

[listeners.transparent_http.endpoint.transport]
kind = "unix"
path = {:?}
mode = "0600"

[egress]
route = "direct"

[policy]
default = "deny"

[[policy.rules]]
id = "unix-concurrent-admission"
decision = "allow"
urls = ["http://origin.example.test/second"]
methods = ["GET"]
"#,
            socket_path
        );
        fs::write(&config_path, text).unwrap();
        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        let origin_url =
            http_access_url::canonicalize_http_url("http://origin.example.test/").unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(Vec::new(), None, None, None)
                    .unwrap(),
            )
            .map_prebound(&origin_url, origin_address)
            .unwrap()
            .into_standalone_guard(),
        );
        let product = ProductRuntime::prepare_from_prebound_with_forwarding_network(
            loaded,
            Vec::new(),
            network,
        )
        .await
        .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let mut stalled = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
        stalled.write_all(b"AWAF").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\naccepted",
                )
                .await
                .unwrap();
            request
        });
        let mut second = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
        write_access_flow_preface(
            &mut second,
            AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
            &IdentityPresentation::Disabled,
        )
        .await
        .unwrap();
        second
            .write_all(
                b"GET /second HTTP/1.1\r\nHost: origin.example.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(1), read_http_message(&mut second))
            .await
            .expect("stalled first preface serialized a later Access Flow admission");
        assert!(response.starts_with(b"HTTP/1.1 200 "));
        let request = origin_task.await.unwrap();
        assert!(request.starts_with(b"GET /second HTTP/1.1\r\n"));

        drop(stalled);
        drop(second);
        product.shutdown().await;
        assert!(!socket_path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn access_flow_shutdown_closes_admission_before_deadline_bound_connection_join() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket_path = directory.path().join("shutdown.sock");
        let config_path = directory.path().join("acl-proxy.toml");
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]

[listeners.transparent_http.endpoint.transport]
kind = "unix"
path = {:?}
mode = "0600"

[egress]
route = "direct"

[policy]
default = "deny"

[[policy.rules]]
id = "unix-shutdown"
decision = "allow"
urls = ["http://origin.example.test/stalled"]
methods = ["GET"]
"#,
            socket_path
        );
        fs::write(&config_path, text).unwrap();
        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        let origin_url =
            http_access_url::canonicalize_http_url("http://origin.example.test/").unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(Vec::new(), None, None, None)
                    .unwrap(),
            )
            .map_prebound(&origin_url, origin_address)
            .unwrap()
            .into_standalone_guard(),
        );
        let product = ProductRuntime::prepare_from_prebound_with_forwarding_network(
            loaded,
            Vec::new(),
            network,
        )
        .await
        .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let (origin_active_send, origin_active_receive) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            assert!(request.starts_with(b"GET /stalled HTTP/1.1\r\n"));
            origin_active_send.send(()).unwrap();
            let mut byte = [0_u8; 1];
            stream.read(&mut byte).await.unwrap_or(0)
        });

        let mut client = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
        write_access_flow_preface(
            &mut client,
            AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
            &IdentityPresentation::Disabled,
        )
        .await
        .unwrap();
        client
            .write_all(
                b"GET /stalled HTTP/1.1\r\nHost: origin.example.test\r\nConnection: keep-alive\r\n\r\n",
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), origin_active_receive)
            .await
            .expect("Access Flow request did not reach the stalled origin")
            .unwrap();

        let runtime = product.static_resources.listener_runtime_for_test();
        tokio::time::timeout(
            Duration::from_millis(250),
            runtime.stop_admission_and_wait_closed(),
        )
        .await
        .expect("Access Flow admission closure waited for the active connection");
        assert!(
            tokio::net::UnixStream::connect(&socket_path).await.is_err(),
            "Access Flow Unix listener still admitted connections after closure"
        );
        assert!(
            !origin_task.is_finished(),
            "active connection ended while only listener admission was closed"
        );

        let deadline = std::time::Instant::now() + Duration::from_millis(150);
        let shutdown = tokio::spawn(async move {
            runtime.shutdown_and_wait(Some(deadline)).await;
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !shutdown.is_finished(),
            "active Access Flow connection drained before the caller deadline"
        );
        tokio::time::timeout(Duration::from_secs(1), shutdown)
            .await
            .expect("Access Flow connection join exceeded its caller deadline")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), origin_task)
            .await
            .expect("forced Access Flow cancellation did not close the origin connection")
            .unwrap();

        let mut byte = [0_u8; 1];
        let _ = tokio::time::timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .expect("forced Access Flow cancellation did not close the client connection");
        product.shutdown().await;
        assert!(!socket_path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn access_flow_websocket_upgrade_uses_the_existing_product_pipeline() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket_path = directory.path().join("websocket.sock");
        let config_path = directory.path().join("acl-proxy.toml");
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]

[listeners.transparent_http.endpoint.transport]
kind = "unix"
path = {:?}
mode = "0600"

[egress]
route = "direct"

[policy]
default = "deny"

[[policy.rules]]
id = "unix-websocket"
decision = "allow"
urls = ["http://origin.example.test/socket"]
methods = ["GET"]
allow_upgrades = true
"#,
            socket_path
        );
        fs::write(&config_path, text).unwrap();
        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        let origin_url =
            http_access_url::canonicalize_http_url("http://origin.example.test/").unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(Vec::new(), None, None, None)
                    .unwrap(),
            )
            .map_prebound(&origin_url, origin_address)
            .unwrap()
            .into_standalone_guard(),
        );
        let product = ProductRuntime::prepare_from_prebound_with_forwarding_network(
            loaded,
            Vec::new(),
            network,
        )
        .await
        .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(request.starts_with("get /socket http/1.1\r\n"));
            assert!(request.contains("\r\nconnection: upgrade\r\n"));
            assert!(request.contains("\r\nupgrade: websocket\r\n"));
            assert!(request.contains("\r\nsec-websocket-key: dghlihnhbxbszsbub25jzq==\r\n"));
            assert!(request.contains("\r\nsec-websocket-version: 13\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                )
                .await
                .unwrap();

            let mut masked_text_frame = [0_u8; 11];
            stream.read_exact(&mut masked_text_frame).await.unwrap();
            assert_eq!(&masked_text_frame[..6], &[0x81, 0x85, 1, 2, 3, 4]);
            let decoded = masked_text_frame[6..]
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ [1, 2, 3, 4][index % 4])
                .collect::<Vec<_>>();
            assert_eq!(decoded, b"hello");
            stream.write_all(&[0x81, 0x05]).await.unwrap();
            stream.write_all(b"world").await.unwrap();
        });

        let mut client = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
        write_access_flow_preface(
            &mut client,
            AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
            &IdentityPresentation::Disabled,
        )
        .await
        .unwrap();
        client
            .write_all(
                b"GET /socket HTTP/1.1\r\nHost: origin.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_http_message(&mut client).await;
        assert!(response.starts_with(b"HTTP/1.1 101 "));
        assert!(String::from_utf8_lossy(&response)
            .to_ascii_lowercase()
            .contains("\r\nupgrade: websocket\r\n"));

        let mask = [1_u8, 2, 3, 4];
        let mut masked_payload = *b"hello";
        for (index, byte) in masked_payload.iter_mut().enumerate() {
            *byte ^= mask[index % mask.len()];
        }
        client
            .write_all(&[
                0x81,
                0x80 | u8::try_from(masked_payload.len()).unwrap(),
                mask[0],
                mask[1],
                mask[2],
                mask[3],
            ])
            .await
            .unwrap();
        client.write_all(&masked_payload).await.unwrap();
        let mut response_frame = [0_u8; 7];
        client.read_exact(&mut response_frame).await.unwrap();
        assert_eq!(&response_frame[..2], &[0x81, 0x05]);
        assert_eq!(&response_frame[2..], b"world");
        drop(client);
        origin_task.await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), product.shutdown())
            .await
            .expect("completed Access Flow WebSocket retained runtime resources");
        assert!(!socket_path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn access_flow_transparent_https_performs_mitm_in_the_existing_product_pipeline() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket_path = directory.path().join("transparent-https.sock");
        let config_path = directory.path().join("acl-proxy.toml");
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_identity = TestTlsIdentity::new("origin.example.test");
        let origin_acceptor =
            TlsAcceptor::from(Arc::new(origin_identity.server_config(&[b"http/1.1"])));
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.transparent_https]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [443]
http_versions = ["http1"]
handshake_timeout = "1s"

[listeners.transparent_https.endpoint.transport]
kind = "unix"
path = {:?}
mode = "0600"

[mitm]
mode = "generated"
directory = "mitm"

[egress]
route = "direct"

[egress.origin_tls]
trust = "insecure"
http_versions = ["http1"]

[policy]
default = "deny"

[[policy.rules]]
id = "unix-transparent-tls"
decision = "allow"
methods = ["GET"]
urls = ["https://origin.example.test/uds-tls"]
execution_contexts = ["external"]

[[policy.rules]]
id = "unix-transparent-tls-v1"
decision = "allow"
methods = ["GET"]
urls = ["https://origin.example.test/legacy"]

[egress.access_flow_execution_context]
urls = ["https://origin.example.test/**"]
"#,
            socket_path
        );
        fs::write(&config_path, text).unwrap();
        let loaded = load_and_compile_exact_config(&config_path).unwrap();
        let ca_root = PrivateStorageRoot::open_or_create(&directory.path().join("mitm")).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let generated =
            GeneratedCertificateAuthority::open_or_generate(ca_root, i64::try_from(now).unwrap())
                .unwrap();
        let ca_chain = generated.public_ca_chain_der();
        drop(generated);
        let origin_url =
            http_access_url::canonicalize_http_url("https://origin.example.test/").unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(Vec::new(), None, None, None)
                    .unwrap(),
            )
            .map_prebound(&origin_url, origin_address)
            .unwrap()
            .into_standalone_guard(),
        );
        let product = ProductRuntime::prepare_from_prebound_with_forwarding_network(
            loaded,
            Vec::new(),
            network,
        )
        .await
        .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let v1_absent = access_flow_conformance::load_awaf_vector_suite()
            .unwrap()
            .vectors()
            .iter()
            .find(|vector| vector.name() == "absent")
            .unwrap()
            .wire()
            .to_vec();
        let connector = TlsConnector::from(Arc::new(client_config_for_roots(
            ca_chain.clone(),
            &[b"http/1.1"],
        )));

        let mut legacy = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
        legacy.write_all(&v1_absent).await.unwrap();
        let mut denied = connector
            .connect(ServerName::try_from("origin.example.test").unwrap(), legacy)
            .await
            .unwrap();
        denied
            .write_all(
                b"GET /uds-tls HTTP/1.1\r\nHost: origin.example.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_http_message(&mut denied).await;
        assert!(response.starts_with(b"HTTP/1.1 403 "));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), origin.accept())
                .await
                .is_err()
        );

        let legacy_origin = tokio::spawn({
            let origin = origin;
            async move {
                let (stream, _) = origin.accept().await.unwrap();
                let mut stream = origin_acceptor.accept(stream).await.unwrap();
                let request = read_http_message(&mut stream).await;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nlegacy",
                    )
                    .await
                    .unwrap();
                (origin, origin_acceptor, request)
            }
        });
        let mut legacy = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
        legacy.write_all(&v1_absent).await.unwrap();
        let mut legacy = connector
            .connect(ServerName::try_from("origin.example.test").unwrap(), legacy)
            .await
            .unwrap();
        legacy
            .write_all(
                b"GET /legacy HTTP/1.1\r\nHost: origin.example.test\r\nX-Agent-Access-Context: spoofed\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_http_message(&mut legacy).await;
        assert!(response.starts_with(b"HTTP/1.1 200 "));
        let (origin, origin_acceptor, legacy_request) = legacy_origin.await.unwrap();
        assert!(!String::from_utf8(legacy_request)
            .unwrap()
            .to_ascii_lowercase()
            .contains("x-agent-access-context"));

        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            let mut stream = origin_acceptor.accept(stream).await.unwrap();
            let request = read_http_message(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nmitm accepted",
                )
                .await
                .unwrap();
            request
        });

        let mut unix = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
        let execution_context =
            access_execution_context::ExecutionContext::new("external").unwrap();
        access_flow::write_access_flow_preface(
            &mut unix,
            AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 443).unwrap(),
            &IdentityPresentation::Disabled,
            Some(&execution_context),
        )
        .await
        .unwrap();

        let mut client = connector
            .connect(ServerName::try_from("origin.example.test").unwrap(), unix)
            .await
            .unwrap();
        client
            .write_all(
                b"GET /uds-tls HTTP/1.1\r\nHost: origin.example.test\r\nX-Agent-Access-Context: internal\r\nX-Agent-Access-Context: workstation\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_http_message(&mut client).await;
        assert!(response.starts_with(b"HTTP/1.1 200 "));
        assert!(response.ends_with(b"\r\n\r\nmitm accepted"));
        let request = origin_task.await.unwrap();
        assert!(request.starts_with(b"GET /uds-tls HTTP/1.1\r\n"));
        let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
        assert_eq!(request.matches("\r\nx-agent-access-context:").count(), 1);
        assert!(request.contains("\r\nx-agent-access-context: external\r\n"));

        product.shutdown().await;
        assert!(!socket_path.exists());
    }

    #[tokio::test]
    async fn normalized_http_body_removes_stale_coding_and_length() {
        let captured = normalized_round_trip(NormalizedListenerMode::Transparent).await;
        assert_eq!(captured.origin_body, b"canonical decoded request bytes");
        let head = captured.origin_head.to_ascii_lowercase();
        assert!(!head.contains("\r\ncontent-encoding:"));
        assert!(head.contains("\r\ncontent-length: 31\r\n"));
        assert!(head.contains("\r\ncontent-type: application/octet-stream\r\n"));
    }

    #[tokio::test]
    async fn downstream_cancellation_after_accepted_101_releases_committed_upgrade_once() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let extra = format!(
            r#"[[policy.rules]]
id = "cancel-upgrade"
decision = "allow"
methods = ["GET"]
urls = ["http://{origin_address}/socket"]
allow_upgrades = true
"#
        );
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], &extra));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();
        assert_eq!(product.forwarding_terminal_completions_for_test(), 0);

        let (closed_tx, closed_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let _request = read_http_message(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n",
                )
                .await
                .unwrap();
            let mut byte = [0_u8; 1];
            let closed = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
                .await
                .map(|result| result.unwrap() == 0)
                .unwrap_or(false);
            closed_tx.send(closed).ok();
        });

        let mut client = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://{origin_address}/socket HTTP/1.1\r\nHost: {origin_address}\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_message(&mut client).await;
        assert!(response.starts_with(b"HTTP/1.1 101"));
        drop(client);
        assert!(
            closed_rx.await.unwrap(),
            "origin upgrade was not closed once"
        );
        origin_task.await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), product.shutdown())
            .await
            .expect("cancelled committed upgrade retained runtime work");
        assert_eq!(product.forwarding_terminal_completions_for_test(), 1);
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    async fn run_connect_mitm_upgrade_case(shutdown_while_active: bool) {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();

        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_identity = TestTlsIdentity::new("localhost");
        let origin_acceptor =
            TlsAcceptor::from(Arc::new(origin_identity.server_config(&[b"http/1.1"])));

        let extra = format!(
            r#"[mitm]
mode = "generated"
directory = "mitm"

[egress]
route = "direct"

[egress.origin_tls]
trust = "insecure"
http_versions = ["http1"]

[[policy.rules]]
id = "connect"
decision = "allow"
methods = ["CONNECT"]
urls = ["https://localhost:{}/**"]

[[policy.rules]]
id = "inner-upgrade"
decision = "allow"
methods = ["GET"]
urls = ["https://localhost:{}/socket"]
allow_upgrades = true
"#,
            origin_address.port(),
            origin_address.port()
        );
        let text = config(addresses[0], addresses[1], &extra).replace(
            "[listeners.explicit_http.connect]\nhttp1 = \"deny\"",
            "[listeners.explicit_http.connect]\nhttp1 = \"mitm\"",
        );
        let (directory, loaded) = loaded(&text);
        let ca_root = PrivateStorageRoot::open_or_create(&directory.path().join("mitm")).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let generated =
            GeneratedCertificateAuthority::open_or_generate(ca_root, i64::try_from(now).unwrap())
                .unwrap();
        let ca_chain = generated.public_ca_chain_der();
        drop(generated);

        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();
        assert_eq!(product.forwarding_terminal_completions_for_test(), 0);

        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            let mut stream = origin_acceptor.accept(stream).await.unwrap();
            let request = read_http_message(&mut stream).await;
            let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(request.contains("\r\nconnection: upgrade\r\n"));
            assert!(request.contains("\r\nupgrade: test-echo\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n",
                )
                .await
                .unwrap();
            let mut ping = [0_u8; 4];
            stream.read_exact(&mut ping).await.unwrap();
            assert_eq!(&ping, b"ping");
            stream.write_all(b"pong").await.unwrap();
            if shutdown_while_active {
                let mut byte = [0_u8; 1];
                let closed = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
                    .await
                    .is_ok_and(|result| result.is_err() || result.is_ok_and(|count| count == 0));
                assert!(
                    closed,
                    "CONNECT/MITM origin tunnel remained open after shutdown"
                );
            }
        });

        let mut client = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        client
            .write_all(
                format!(
                    "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
                    origin_address.port(),
                    origin_address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let outer = read_http_message(&mut client).await;
        assert!(
            outer.starts_with(b"HTTP/1.1 200"),
            "unexpected CONNECT response: {}",
            String::from_utf8_lossy(&outer)
        );

        let client_tls = client_config_for_roots(ca_chain, &[b"http/1.1"]);
        let connector = TlsConnector::from(Arc::new(client_tls));
        let mut tunnel = connector
            .connect(ServerName::try_from("localhost").unwrap(), client)
            .await
            .unwrap();
        tunnel
            .write_all(
                format!(
                    "GET /socket HTTP/1.1\r\nHost: localhost:{}\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n",
                    origin_address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let inner = read_http_message(&mut tunnel).await;
        assert!(inner.starts_with(b"HTTP/1.1 101"));
        tunnel.write_all(b"ping").await.unwrap();
        let mut pong = [0_u8; 4];
        tunnel.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
        if shutdown_while_active {
            tokio::time::timeout(Duration::from_secs(2), product.shutdown())
                .await
                .expect("active CONNECT/MITM upgrade did not join during shutdown");
            let mut byte = [0_u8; 1];
            let closed = tunnel.read(&mut byte).await;
            assert!(closed.is_err() || closed.is_ok_and(|count| count == 0));
            origin_task.await.unwrap();
        } else {
            drop(tunnel);
            origin_task.await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), product.shutdown())
                .await
                .expect("completed CONNECT/MITM upgrade did not join during shutdown");
        }
        assert_eq!(product.forwarding_terminal_completions_for_test(), 1);
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn connect_mitm_opaque_upgrade_round_trip_uses_generated_ca() {
        run_connect_mitm_upgrade_case(false).await;
    }

    #[tokio::test]
    async fn connect_mitm_shutdown_joins_pending_tunnel_and_releases_listener() {
        run_connect_mitm_upgrade_case(true).await;
    }

    #[tokio::test]
    async fn publication_before_ingress_confirmation_stays_not_ready() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], ""));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();

        assert!(!product.runtime().is_ready());
        for address in addresses {
            assert!(TcpListener::bind(address).is_err());
        }
        product.activate_initial().await.unwrap();
        assert!(!product.runtime().is_ready());

        product.start_listeners().await.unwrap();
        assert!(product.runtime().is_ready());

        product.shutdown().await;
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn listener_start_rejects_before_initial_publication() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], ""));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();

        assert!(matches!(
            product.start_listeners().await,
            Err(ProductRuntimeError::InitialGenerationNotPublished)
        ));
        assert!(!product.runtime().is_ready());
        for address in addresses {
            assert!(TcpListener::bind(address).is_err());
        }

        product.activate_initial().await.unwrap();
        assert!(!product.runtime().is_ready());
        product.start_listeners().await.unwrap();
        assert!(product.runtime().is_ready());

        product.shutdown().await;
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn failed_initial_activation_joins_shutdown_and_releases_every_socket() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let missing_variable = "ACL_PROXY_RUNNER_TEST_MISSING_REDACTION_LITERAL";
        std::env::remove_var(missing_variable);
        let extra = format!(
            r#"[redaction.profiles.secrets]
rules = [{{ literal_environment_variables = ["{missing_variable}"] }}]
"#
        );
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], &extra));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();

        let result = product.activate_initial().await;

        assert!(matches!(
            result,
            Err(ProductRuntimeError::Runtime(
                RuntimeError::CandidateActivation(_)
            ))
        ));
        assert_eq!(
            product.runtime().lifecycle(),
            crate::runtime::LifecycleState::Stopped
        );
        assert!(!product.runtime().is_ready());
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn later_prebind_failure_releases_earlier_proxy_and_control_sockets() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let mut listeners = reservations.into_listeners();
        let blocker = listeners.remove(1);
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], ""));

        let result = ProductRuntime::prepare_from_prebound(loaded, listeners).await;

        assert!(matches!(
            result,
            Err(ProductRuntimeError::StaticResources(
                ProductStaticResourcesError::Control(_)
            ))
        ));
        super::super::assert_listener_addresses_released(&_test, [addresses[0]]);
        drop(blocker);
        super::super::assert_listener_addresses_released(&_test, [addresses[1]]);
    }

    #[tokio::test]
    async fn bundle_conversion_failure_after_transfer_coordinates_full_shutdown() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<3>(&_test);
        let addresses = reservations.addresses();
        let extra = format!(
            r#"[listeners.transparent_http]
endpoint.kind = "tcp"
endpoint.address = "{}"
http_versions = ["http1"]
"#,
            addresses[1]
        );
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[2], &extra));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();
        product.activate_initial().await.unwrap();

        assert!(matches!(
            product
                .start_listeners_with_transparent_support(false)
                .await,
            Err(ProductRuntimeError::SharedListener(
                http_access_runtime::RuntimeError::InvalidInput
            ))
        ));
        assert_eq!(
            product.runtime().lifecycle(),
            crate::runtime::LifecycleState::Stopped
        );
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn static_asset_failure_occurs_before_prebinding_and_leaves_every_socket_free() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<3>(&_test);
        let addresses = reservations.addresses();
        let extra = format!(
            r#"[listeners.explicit_https]
endpoint.kind = "tcp"
endpoint.address = "{}"
http_versions = ["http1"]

[listeners.explicit_https.connect]
http1 = "deny"

[listeners.explicit_https.tls]
certificate_chain = "missing-server.pem"
private_key = "missing-server-key.pem"
"#,
            addresses[2]
        );
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], &extra));

        let result =
            ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners()).await;

        assert!(matches!(
            result,
            Err(ProductRuntimeError::StaticResources(
                ProductStaticResourcesError::IngressAssets(_)
            ))
        ));
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn terminal_listener_failure_is_observed_and_coordinated_shutdown_joins_once() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], ""));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product
            .start_listeners_with_next_connection_panic()
            .await
            .unwrap();
        assert!(product.runtime().is_ready());

        let _client = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        let failure =
            tokio::time::timeout(Duration::from_secs(1), product.wait_for_listener_failure())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            failure.listener,
            super::super::listeners::ProxyListenerKind::ExplicitHttp
        );
        assert!(!product.runtime().is_ready());
        assert_eq!(
            product.runtime().lifecycle(),
            crate::runtime::LifecycleState::Running
        );
        assert_eq!(
            product
                .static_resources
                .listener_failure_notifications_for_test(),
            1
        );

        tokio::time::timeout(Duration::from_secs(2), product.shutdown())
            .await
            .expect("coordinated listener panic shutdown did not join");
        product.shutdown().await;
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn cancelled_static_shutdown_does_not_lose_listener_runtime() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], ""));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();
        let mut partial_request = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        partial_request
            .write_all(b"GET / HTTP/1.1\r\nHost: local.test\r\n")
            .await
            .unwrap();

        let (shutdown_reached, shutdown_release) =
            product.static_resources.pause_listener_shutdown_for_test();
        let shutdown_product = Arc::clone(&product);
        let first_shutdown = tokio::spawn(async move {
            shutdown_product.shutdown().await;
        });
        tokio::time::timeout(Duration::from_secs(1), shutdown_reached)
            .await
            .expect("static shutdown did not begin joining the listener runtime")
            .expect("listener shutdown pause was dropped before it was reached");
        assert!(product
            .static_resources
            .listener_shutdown_started_for_test());
        first_shutdown.abort();
        assert!(first_shutdown.await.unwrap_err().is_cancelled());
        drop(shutdown_release);
        assert!(product.static_resources.owns_listener_runtime_for_test());

        drop(partial_request);
        tokio::time::timeout(Duration::from_secs(2), product.shutdown())
            .await
            .expect("retried static shutdown did not recover the listener runtime");
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn listener_adoption_after_shutdown_retains_and_joins_the_started_runtime() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], ""));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        let shutdown_resources = Arc::clone(&product.static_resources);

        let result = product
            .start_listeners_inner(
                true,
                Arc::new(SystemOriginalDestinationProvider),
                |services| services,
                move || {
                    StaticResources::begin_shutdown(shutdown_resources.as_ref());
                },
            )
            .await;

        assert!(matches!(
            result,
            Err(ProductRuntimeError::StaticResources(
                ProductStaticResourcesError::ShuttingDown
            ))
        ));
        assert!(product.static_resources.owns_listener_runtime_for_test());
        assert_eq!(
            product.runtime().lifecycle(),
            crate::runtime::LifecycleState::Stopped
        );
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    mod parent_proxy_tests {
        include!("runner_parent_proxy_tests.rs");
    }

    #[cfg(unix)]
    mod connect_mitm_tests {
        include!("runner_connect_mitm_tests.rs");
    }

    mod protocol_parity_tests {
        include!("runner_protocol_parity_tests.rs");
    }

    mod response_parity_tests {
        include!("runner_response_parity_tests.rs");
    }

    mod resource_stress_tests {
        include!("runner_resource_stress_tests.rs");
    }

    mod listener_lifecycle_tests {
        include!("runner_listener_lifecycle_tests.rs");
    }

    #[cfg(unix)]
    mod identity_product_tests {
        include!("runner_identity_product_tests.rs");
    }

    #[test]
    fn runner_module_and_api_names_are_versionless() {
        assert_eq!(Path::new(file!()).file_name().unwrap(), "runner.rs");
        assert!(!std::any::type_name::<ProductRuntime>().contains("V3"));
    }
}
