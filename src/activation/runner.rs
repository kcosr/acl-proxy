use std::sync::{Arc, Mutex};

use http_access_runtime::{
    ListenerFailureObserver, ListenerMode, ListenerRuntime, ListenerServices, ListenerTlsAcceptors,
    OriginalDestinationProvider, StandaloneRequestFactory,
};

use crate::config::{CompiledConfig, LoadedCompiledConfig};
use crate::observation::ProductObservationRuntime;
use crate::runtime::{GenerationId, Runtime, RuntimeError, StaticOwnership, StaticResources};

use super::listeners::{
    PreparedProxyListeners, ProxyListenerFailure, SystemOriginalDestinationProvider,
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
    initial: Mutex<Option<CompiledConfig>>,
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
}

impl ProductRuntime {
    pub(crate) async fn prepare(
        loaded: LoadedCompiledConfig,
    ) -> Result<Arc<Self>, ProductRuntimeError> {
        Self::prepare_inner(loaded, None, None).await
    }

    #[cfg(test)]
    pub(crate) async fn prepare_from_prebound(
        loaded: LoadedCompiledConfig,
        listeners: Vec<std::net::TcpListener>,
    ) -> Result<Arc<Self>, ProductRuntimeError> {
        Self::prepare_inner(loaded, Some(listeners), None).await
    }

    #[cfg(test)]
    pub(crate) async fn prepare_from_prebound_with_forwarding_network(
        loaded: LoadedCompiledConfig,
        listeners: Vec<std::net::TcpListener>,
        forwarding_network: Arc<http_access_runtime::ForwardingNetworkGuard>,
    ) -> Result<Arc<Self>, ProductRuntimeError> {
        Self::prepare_inner(loaded, Some(listeners), Some(forwarding_network)).await
    }

    async fn prepare_inner(
        loaded: LoadedCompiledConfig,
        prebound: Option<Vec<std::net::TcpListener>>,
        forwarding_network: Option<Arc<http_access_runtime::ForwardingNetworkGuard>>,
    ) -> Result<Arc<Self>, ProductRuntimeError> {
        let LoadedCompiledConfig { metadata, compiled } = loaded;
        #[cfg(not(test))]
        let _ = (prebound, forwarding_network);
        #[cfg(test)]
        let static_resources = match forwarding_network {
            Some(forwarding_network) => {
                ProductStaticResources::try_new_with_forwarding_network(
                    &compiled.static_config,
                    forwarding_network,
                )
                .await?
            }
            None => ProductStaticResources::try_new(&compiled.static_config).await?,
        };
        #[cfg(not(test))]
        let static_resources = ProductStaticResources::try_new(&compiled.static_config).await?;
        let observation_runtime = static_resources.observation_runtime();

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

        Ok(Arc::new(Self {
            runtime,
            static_resources,
            observation_runtime,
            initial: Mutex::new(Some(compiled)),
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
        let bundle =
            match prepared.into_shared_bundle_with_transparent_support(transparent_supported) {
                Ok(bundle) => bundle,
                Err(error) => {
                    self.shutdown().await;
                    return Err(error.into());
                }
            };
        let assets = self.static_resources.ingress_assets();
        let tls = ListenerTlsAcceptors::new(
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
        let services = configure_services(ListenerServices::new(
            original_destination,
            self.static_resources.local_address_provider(),
            Arc::new(ProductListenerFailureObserver {
                static_resources: Arc::downgrade(&self.static_resources),
            }),
            tls,
            request_factory,
            self.static_resources.upgrade_runtime(),
        ));
        let listener_runtime = match ListenerRuntime::start(bundle, services) {
            Ok(runtime) => runtime,
            Err(error) => {
                self.shutdown().await;
                return Err(error.into());
            }
        };
        before_adoption();
        if let Err(error) = self
            .static_resources
            .adopt_listener_runtime(listener_runtime)
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

    pub(crate) async fn activate_initial(&self) -> Result<GenerationId, ProductRuntimeError> {
        let initial = self
            .initial
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .ok_or(ProductRuntimeError::InitialActivationAlreadyAttempted)?;
        let runtime = self.runtime.clone();
        let activation_runtime = runtime.clone();

        let activation = tokio::spawn(async move {
            match activation_runtime.start(initial).await {
                Ok(generation) => Ok(generation),
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
    use std::path::Path;
    use std::time::Duration;

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use http_access_mitm::{GeneratedCertificateAuthority, PrivateStorageRoot};
    use rustls::pki_types::ServerName;
    use tempfile::tempdir;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;
    use crate::config::load_and_compile_exact_config;
    use crate::test_certificates::{client_config_for_roots, TestTlsIdentity};

    fn config(explicit_http: SocketAddr, control: SocketAddr, extra: &str) -> String {
        format!(
            r#"schema_version = 3

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
bind = "{explicit_http}"
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
        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
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
        assert!(response.starts_with(b"HTTP/1.1 200 "));
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
            r#"schema_version = 3

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.{listener_table}]
bind = "{}"
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
bind = "{}"
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
bind = "{}"
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

    #[test]
    fn runner_module_and_api_names_are_versionless() {
        assert_eq!(Path::new(file!()).file_name().unwrap(), "runner.rs");
        assert!(!std::any::type_name::<ProductRuntime>().contains("V3"));
    }
}
