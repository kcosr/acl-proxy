use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use http_access_mitm::{GeneratedCertificateAuthority, PrivateStorageRoot};
use http_access_runtime::{
    ForwardingDevHarness, ForwardingNetworkFacts, OriginalDestinationProvider,
};
use http_access_url::canonicalize_http_url;
use rustls::pki_types::ServerName;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::*;
use crate::config::load_and_compile_exact_config;
use crate::test_certificates::{client_config_for_pem_roots, TestTlsIdentity};

struct TestIdentity {
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    tls: TestTlsIdentity,
}

trait LifecycleIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> LifecycleIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

struct FixedOriginalDestination(SocketAddr);

impl OriginalDestinationProvider for FixedOriginalDestination {
    fn original_destination(
        &self,
        _stream: &std::net::TcpStream,
    ) -> Result<SocketAddr, http_access_runtime::RuntimeError> {
        Ok(self.0)
    }
}

fn identity(directory: &Path, dns_name: &str) -> TestIdentity {
    let tls = TestTlsIdentity::new(dns_name);
    let certificate_path = directory.join("listener-cert.pem");
    let private_key_path = directory.join("listener-key.pem");
    crate::filesystem::write_public_file(&certificate_path, tls.certificate_chain_pem()).unwrap();
    crate::filesystem::write_private_file(&private_key_path, tls.private_key_pem()).unwrap();
    TestIdentity {
        certificate_path,
        private_key_path,
        tls,
    }
}

fn tls_acceptor(identity: &TestIdentity) -> TlsAcceptor {
    TlsAcceptor::from(Arc::new(identity.tls.server_config(&[b"http/1.1"])))
}

fn tls_connector(certificate_path: &Path, alpn: &[&[u8]]) -> TlsConnector {
    let pem = fs::read(certificate_path).unwrap();
    TlsConnector::from(Arc::new(client_config_for_pem_roots(&pem, alpn)))
}

fn initialize_generated_ca(directory: &Path, public_chain_path: &Path) {
    let root = PrivateStorageRoot::open_or_create(directory).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let authority =
        GeneratedCertificateAuthority::open_or_generate(root, i64::try_from(now).unwrap()).unwrap();
    let mut pem = String::new();
    for certificate in authority.public_ca_chain_der() {
        pem.push_str("-----BEGIN CERTIFICATE-----\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(certificate);
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
    }
    crate::filesystem::write_public_file(public_chain_path, pem).unwrap();
}

fn explicit_http_config(bind: SocketAddr, extra: &str) -> String {
    format!(
        r#"schema_version = 4

[service]
request_timeout = "200ms"
shutdown_drain_timeout = "1s"

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "{bind}"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

{extra}
"#
    )
}

fn explicit_https_config(bind: SocketAddr, identity: &TestIdentity, extra: &str) -> String {
    format!(
        r#"schema_version = 4

[service]
request_timeout = "200ms"
shutdown_drain_timeout = "1s"

[listeners.explicit_https]
endpoint.kind = "tcp"
endpoint.address = "{bind}"
http_versions = ["http1"]
handshake_timeout = "1s"

[listeners.explicit_https.connect]
http1 = "deny"

[listeners.explicit_https.tls]
certificate_chain = "{}"
private_key = "{}"

[policy]
default = "deny"

{extra}
"#,
        identity.certificate_path.display(),
        identity.private_key_path.display(),
    )
}

fn transparent_https_config(bind: SocketAddr, directory: &Path, extra: &str) -> String {
    format!(
        r#"schema_version = 4

[service]
request_timeout = "200ms"
shutdown_drain_timeout = "1s"

[listeners.transparent_https]
endpoint.kind = "tcp"
endpoint.address = "{bind}"
http_versions = ["http1"]
handshake_timeout = "1s"

[mitm]
mode = "generated"
directory = "{}"

[policy]
default = "deny"

{extra}
"#,
        directory.join("mitm").display(),
    )
}

async fn prepare_product(
    directory: &Path,
    config: &str,
    listeners: Vec<StdTcpListener>,
) -> Arc<ProductRuntime> {
    let path = directory.join("acl-proxy.toml");
    fs::write(&path, config).unwrap();
    let loaded = load_and_compile_exact_config(&path).unwrap();
    ProductRuntime::prepare_from_prebound(loaded, listeners)
        .await
        .unwrap()
}

async fn start_product(
    directory: &Path,
    config: &str,
    listeners: Vec<StdTcpListener>,
) -> Arc<ProductRuntime> {
    let product = prepare_product(directory, config, listeners).await;
    product.activate_initial().await.unwrap();
    product.start_listeners().await.unwrap();
    product
}

async fn start_product_with_network(
    directory: &Path,
    config: &str,
    listener: StdTcpListener,
    origin_url: &str,
    origin: SocketAddr,
) -> Arc<ProductRuntime> {
    let bind = listener.local_addr().unwrap();
    let path = directory.join("acl-proxy.toml");
    fs::write(&path, config).unwrap();
    let loaded = load_and_compile_exact_config(&path).unwrap();
    let facts = ForwardingNetworkFacts::new(vec![bind], None, None, None).unwrap();
    let url = canonicalize_http_url(origin_url).unwrap();
    let network = Arc::new(
        ForwardingDevHarness::new(facts)
            .map_prebound(&url, origin)
            .unwrap()
            .into_standalone_guard(),
    );
    let product = ProductRuntime::prepare_from_prebound_with_forwarding_network(
        loaded,
        vec![listener],
        network,
    )
    .await
    .unwrap();
    product.activate_initial().await.unwrap();
    product.start_listeners().await.unwrap();
    product
}

async fn raw_status(bind: SocketAddr, target: &str) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(bind).await.unwrap();
    let host = target
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or_else(|| panic!("test target must be an absolute HTTP URI: {target}"));
    stream
        .write_all(
            format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    response
}

async fn read_http_head(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
        assert!(head.len() <= 32 * 1024);
    }
    head
}

async fn read_response(mut stream: Box<dyn LifecycleIo>) -> (u16, Vec<u8>) {
    let response = super::read_http_message(&mut stream).await;
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let head = std::str::from_utf8(&response[..head_end]).unwrap();
    let status = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let body = if head
        .to_ascii_lowercase()
        .contains("\r\ntransfer-encoding: chunked\r\n")
    {
        decode_chunked(&response[head_end..])
    } else {
        response[head_end..].to_vec()
    };
    (status, body)
}

fn decode_chunked(mut wire: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    loop {
        let line_end = wire
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk-size line terminator");
        let size = usize::from_str_radix(std::str::from_utf8(&wire[..line_end]).unwrap(), 16)
            .expect("hexadecimal chunk size");
        wire = &wire[line_end + 2..];
        if size == 0 {
            assert!(wire.starts_with(b"\r\n"));
            return body;
        }
        assert!(wire.len() >= size + 2 && &wire[size..size + 2] == b"\r\n");
        body.extend_from_slice(&wire[..size]);
        wire = &wire[size + 2..];
    }
}

async fn request_over_tls(
    proxy: SocketAddr,
    certificate: &Path,
    server_name: &'static str,
    uri: &str,
    host: Option<&str>,
) -> (
    tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    Vec<u8>,
) {
    let connector = tls_connector(certificate, &[b"http/1.1"]);
    let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let stream = connector
        .connect(
            ServerName::try_from(server_name.to_owned()).unwrap(),
            stream,
        )
        .await
        .unwrap();
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    let host = host.unwrap_or("example.test");
    let mut stream = stream;
    stream
        .write_all(
            format!("GET {uri} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let response = super::read_http_message(&mut stream).await;
    (stream, response)
}

#[tokio::test]
async fn proxy_listener_cannot_reach_itself() {
    let test = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let reservations = crate::activation::reserve_listeners::<1>(&test);
    let [proxy] = reservations.addresses();
    let directory = tempdir().unwrap();
    let product = start_product(
        directory.path(),
        &explicit_http_config(proxy, ""),
        reservations.into_listeners(),
    )
    .await;

    let response = raw_status(proxy, &format!("http://{proxy}/self")).await;
    assert!(
        response.starts_with(b"HTTP/1.1 403 "),
        "{}",
        String::from_utf8_lossy(&response)
    );

    product.shutdown().await;
    crate::activation::assert_listener_addresses_released(&test, [proxy]);
}

#[tokio::test]
async fn proxy_listener_cannot_reach_control_callback() {
    let test = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let reservations = crate::activation::reserve_listeners::<2>(&test);
    let [proxy, control] = reservations.addresses();
    let config = format!(
        r#"schema_version = 4

[service]
request_timeout = "1s"
shutdown_drain_timeout = "1s"
max_active_webhook_deliveries = 8
webhook_transport_buffer_bytes = 65536
max_webhook_transport_bytes = 1048576

[control]
bind = "{control}"
base_path = "/_acl-proxy"
request_header_timeout = "1s"
request_body_timeout = "1s"
max_connections = 8
max_request_body_bytes = 65536

[authorization.callback]
public_url = "http://{control}/_acl-proxy/external-auth/callback"
max_pending_operations = 8

[authorization.providers.unused]
kind = "webhook"
url = "https://approval.example.test/authorize"
max_request_bytes = 4097
max_response_bytes = 97

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "{proxy}"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "allow"
"#
    );
    let directory = tempdir().unwrap();
    let product = start_product(directory.path(), &config, reservations.into_listeners()).await;
    let target = format!("http://{control}/_acl-proxy/external-auth/callback");
    let response = raw_status(proxy, &target).await;
    assert!(
        response.starts_with(b"HTTP/1.1 403 "),
        "{}",
        String::from_utf8_lossy(&response)
    );

    product.shutdown().await;
    crate::activation::assert_listener_addresses_released(&test, [proxy, control]);
}

#[tokio::test]
async fn cleartext_supervisor_joins_and_releases_its_prebound_socket() {
    let test = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let reservations = crate::activation::reserve_listeners::<1>(&test);
    let [proxy] = reservations.addresses();
    let directory = tempdir().unwrap();
    let product = start_product(
        directory.path(),
        &explicit_http_config(proxy, ""),
        reservations.into_listeners(),
    )
    .await;
    assert!(StdTcpListener::bind(proxy).is_err());

    product.shutdown().await;
    product.shutdown().await;
    crate::activation::assert_listener_addresses_released(&test, [proxy]);
}

#[tokio::test]
async fn static_owner_closes_and_joins_runtime_owned_upgrade_tasks() {
    let test = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let reservations = crate::activation::reserve_listeners::<1>(&test);
    let [proxy] = reservations.addresses();
    let directory = tempdir().unwrap();
    let product = start_product(
        directory.path(),
        &explicit_http_config(proxy, ""),
        reservations.into_listeners(),
    )
    .await;
    let mut idle = tokio::net::TcpStream::connect(proxy).await.unwrap();

    tokio::time::timeout(Duration::from_secs(2), product.shutdown())
        .await
        .expect("static owner must close and join runtime listener tasks");
    let mut byte = [0_u8; 1];
    assert_eq!(idle.read(&mut byte).await.unwrap(), 0);
    assert_eq!(
        product.runtime().lifecycle(),
        crate::runtime::LifecycleState::Stopped
    );
    crate::activation::assert_listener_addresses_released(&test, [proxy]);
}

#[tokio::test]
async fn explicit_https_shutdown_closes_idle_keep_alive_connection() {
    let test = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let reservations = crate::activation::reserve_listeners::<1>(&test);
    let [proxy] = reservations.addresses();
    let directory = tempdir().unwrap();
    let identity = identity(directory.path(), "localhost");
    let product = start_product(
        directory.path(),
        &explicit_https_config(proxy, &identity, ""),
        reservations.into_listeners(),
    )
    .await;
    let (mut stream, response) = request_over_tls(
        proxy,
        &identity.certificate_path,
        "localhost",
        "https://example.test/denied",
        None,
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 403 "));

    tokio::time::timeout(Duration::from_secs(2), product.shutdown())
        .await
        .expect("shutdown must join an idle explicit HTTPS connection");
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
        .await
        .expect("request deadline must close the downstream response")
        .unwrap();
    assert_eq!(read, 0);
    crate::activation::assert_listener_addresses_released(&test, [proxy]);
}

#[tokio::test]
async fn explicit_https_shutdown_interrupts_stalled_client_hello() {
    let test = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let reservations = crate::activation::reserve_listeners::<1>(&test);
    let [proxy] = reservations.addresses();
    let directory = tempdir().unwrap();
    let identity = identity(directory.path(), "localhost");
    let config = explicit_https_config(proxy, &identity, "")
        .replace("handshake_timeout = \"1s\"", "handshake_timeout = \"1h\"");
    let product = start_product(directory.path(), &config, reservations.into_listeners()).await;
    let mut stalled = tokio::net::TcpStream::connect(proxy).await.unwrap();
    tokio::task::yield_now().await;

    tokio::time::timeout(Duration::from_secs(2), product.shutdown())
        .await
        .expect("shutdown must interrupt a stalled ClientHello");
    let mut byte = [0_u8; 1];
    assert_eq!(stalled.read(&mut byte).await.unwrap(), 0);
    crate::activation::assert_listener_addresses_released(&test, [proxy]);
}

#[tokio::test]
async fn explicit_https_uses_prebound_socket_static_identity_and_exact_alpn() {
    let test = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let reservations = crate::activation::reserve_listeners::<1>(&test);
    let [proxy] = reservations.addresses();
    let directory = tempdir().unwrap();
    let identity = identity(directory.path(), "localhost");
    let product = start_product(
        directory.path(),
        &explicit_https_config(proxy, &identity, ""),
        reservations.into_listeners(),
    )
    .await;
    assert!(StdTcpListener::bind(proxy).is_err());
    let (stream, response) = request_over_tls(
        proxy,
        &identity.certificate_path,
        "localhost",
        "https://example.test/denied",
        None,
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 403 "));

    drop(stream);
    product.shutdown().await;
    crate::activation::assert_listener_addresses_released(&test, [proxy]);
}

async fn transparent_product(
    test: &crate::activation::ListenerTestGuard<'_>,
    original_destination: SocketAddr,
    handshake_timeout: &str,
) -> (TempDir, PathBuf, SocketAddr, Arc<ProductRuntime>) {
    let reservations = crate::activation::reserve_listeners::<1>(test);
    let [proxy] = reservations.addresses();
    let directory = tempdir().unwrap();
    let ca = directory.path().join("mitm-ca.pem");
    initialize_generated_ca(&directory.path().join("mitm"), &ca);
    let config = transparent_https_config(proxy, directory.path(), "").replace(
        "handshake_timeout = \"1s\"",
        &format!("handshake_timeout = \"{handshake_timeout}\""),
    );
    let product = prepare_product(directory.path(), &config, reservations.into_listeners()).await;
    product.activate_initial().await.unwrap();
    product
        .start_listeners_with_original_destination(Arc::new(FixedOriginalDestination(
            original_destination,
        )))
        .await
        .unwrap();
    (directory, ca, proxy, product)
}

#[tokio::test]
async fn transparent_https_closes_a_stalled_client_hello_at_the_handshake_deadline() {
    let test = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (_directory, _ca, proxy, product) =
        transparent_product(&test, SocketAddr::from(([198, 51, 100, 17], 443)), "50ms").await;
    let mut stalled = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), stalled.read(&mut byte))
        .await
        .expect("stalled ClientHello must close at its deadline")
        .unwrap();
    assert_eq!(read, 0);
    product.shutdown().await;
    crate::activation::assert_listener_addresses_released(&test, [proxy]);
}

#[tokio::test]
async fn transparent_https_uses_sni_and_original_destination_port() {
    let test = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (_directory, ca, proxy, product) =
        transparent_product(&test, SocketAddr::from(([198, 51, 100, 17], 8443)), "1s").await;
    let (stream, response) = request_over_tls(
        proxy,
        &ca,
        "transparent.test",
        "/denied",
        Some("transparent.test:8443"),
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 403 "));
    drop(stream);
    product.shutdown().await;
    crate::activation::assert_listener_addresses_released(&test, [proxy]);
}

#[tokio::test]
async fn transparent_https_rejects_sni_and_host_authority_mismatch_through_listener() {
    let test = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (_directory, ca, proxy, product) =
        transparent_product(&test, SocketAddr::from(([198, 51, 100, 17], 8443)), "1s").await;
    let (stream, response) = request_over_tls(
        proxy,
        &ca,
        "transparent.test",
        "/denied",
        Some("other.test:8443"),
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 400 "));
    drop(stream);
    product.shutdown().await;
    crate::activation::assert_listener_addresses_released(&test, [proxy]);
}

#[tokio::test]
async fn transparent_https_forwards_through_https_acl_proxy_parent() {
    let _test = crate::activation::LISTENER_TEST_LOCK.lock().await;
    super::parent_proxy_tests::exercise_parent_websocket(false).await;
}

#[tokio::test]
async fn unbounded_shutdown_finishes_at_the_finite_request_deadline() {
    let test = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let reservations = crate::activation::reserve_listeners::<1>(&test);
    let [proxy] = reservations.addresses();
    let [listener] = reservations.into_listeners().try_into().ok().unwrap();
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin_listener.accept().await.unwrap();
        let request = super::read_http_message(&mut stream).await;
        assert!(request.starts_with(b"GET /pending HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        release_rx.await.ok();
    });
    let directory = tempdir().unwrap();
    let origin_url = format!("http://{origin}/");
    let config = explicit_http_config(
        proxy,
        &format!(
            r#"[[policy.rules]]
id = "allow-pending"
decision = "allow"
urls = ["http://{origin}/**"]
"#
        ),
    )
    .replace("request_timeout = \"200ms\"", "request_timeout = \"100ms\"")
    .replace(
        "shutdown_drain_timeout = \"1s\"",
        "shutdown_drain_timeout = \"unbounded\"",
    );
    let product =
        start_product_with_network(directory.path(), &config, listener, &origin_url, origin).await;
    let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(
            format!(
                "GET http://{origin}/pending HTTP/1.1\r\nHost: {origin}\r\nConnection: keep-alive\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response = read_http_head(&mut stream).await;
    assert!(response.starts_with(b"HTTP/1.1 200 "));

    tokio::time::timeout(Duration::from_secs(1), product.shutdown())
        .await
        .expect("unbounded drain must finish at the request deadline");
    let mut byte = [0_u8; 1];
    assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    release_tx.send(()).ok();
    origin_task.await.unwrap();
    crate::activation::assert_listener_addresses_released(&test, [proxy]);
}

#[tokio::test]
async fn terminal_supervisor_panic_is_observed_promptly() {
    let test = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let reservations = crate::activation::reserve_listeners::<1>(&test);
    let [proxy] = reservations.addresses();
    let directory = tempdir().unwrap();
    let product = prepare_product(
        directory.path(),
        &explicit_http_config(proxy, ""),
        reservations.into_listeners(),
    )
    .await;
    product.activate_initial().await.unwrap();
    product
        .start_listeners_with_next_connection_panic()
        .await
        .unwrap();

    let _client = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let failure = tokio::time::timeout(Duration::from_secs(2), product.wait_for_listener_failure())
        .await
        .expect("listener panic must reach the product failure observer")
        .expect("listener panic must be recorded");
    assert_eq!(
        failure.listener,
        crate::activation::listeners::ProxyListenerKind::ExplicitHttp
    );
    assert!(!product.runtime().is_ready());
    assert_eq!(
        product
            .static_resources
            .listener_failure_notifications_for_test(),
        1
    );
    product.shutdown().await;
    crate::activation::assert_listener_addresses_released(&test, [proxy]);
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
enum ProviderCase {
    ExplicitHttp,
    ExplicitHttps,
    TransparentHttp,
    ConnectMitmInner,
    TransparentHttps,
}

#[cfg(unix)]
struct ProviderFixture {
    case: ProviderCase,
    proxy: SocketAddr,
    origin: SocketAddr,
    client_certificate: PathBuf,
    _directory: TempDir,
    _marker_directory: TempDir,
    product: Arc<ProductRuntime>,
    origin_task: tokio::task::JoinHandle<()>,
}

#[cfg(unix)]
impl ProviderFixture {
    async fn open_stream(&self) -> Box<dyn LifecycleIo> {
        match self.case {
            ProviderCase::ExplicitHttp | ProviderCase::TransparentHttp => {
                Box::new(tokio::net::TcpStream::connect(self.proxy).await.unwrap())
            }
            ProviderCase::ExplicitHttps | ProviderCase::TransparentHttps => {
                let connector = tls_connector(&self.client_certificate, &[b"http/1.1"]);
                let stream = tokio::net::TcpStream::connect(self.proxy).await.unwrap();
                Box::new(
                    connector
                        .connect(ServerName::try_from("localhost").unwrap(), stream)
                        .await
                        .unwrap(),
                )
            }
            ProviderCase::ConnectMitmInner => {
                let mut outer = tokio::net::TcpStream::connect(self.proxy).await.unwrap();
                let authority = format!("localhost:{}", self.origin.port());
                outer
                    .write_all(
                        format!(
                            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                let response = read_http_head(&mut outer).await;
                assert!(response.starts_with(b"HTTP/1.1 200 "));
                let connector = tls_connector(&self.client_certificate, &[b"http/1.1"]);
                Box::new(
                    connector
                        .connect(ServerName::try_from("localhost").unwrap(), outer)
                        .await
                        .unwrap(),
                )
            }
        }
    }

    fn target(&self, path: &str) -> String {
        match self.case {
            ProviderCase::ExplicitHttp => {
                format!("http://localhost:{}{path}", self.origin.port())
            }
            ProviderCase::ExplicitHttps => {
                format!("https://localhost:{}{path}", self.origin.port())
            }
            ProviderCase::TransparentHttp
            | ProviderCase::ConnectMitmInner
            | ProviderCase::TransparentHttps => path.to_owned(),
        }
    }

    fn host(&self) -> String {
        format!("localhost:{}", self.origin.port())
    }

    async fn request(&self, path: &str, body: &str) -> (u16, Vec<u8>) {
        let mut stream = self.open_stream().await;
        stream
            .write_all(
                format!(
                    "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    self.target(path),
                    self.host(),
                    body.len(),
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        read_response(stream).await
    }

    async fn request_upgrade(&self) -> Vec<u8> {
        let mut stream = self.open_stream().await;
        stream
            .write_all(
                format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: upgrade\r\nUpgrade: obs-text\r\n\r\n",
                    self.target("/upgrade"),
                    self.host(),
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        read_http_head(&mut stream).await
    }

    async fn begin_cancelled_request(&self) -> Box<dyn LifecycleIo> {
        let mut stream = self.open_stream().await;
        stream
            .write_all(
                format!(
                    "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nbody",
                    self.target("/cancel"),
                    self.host(),
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stream
    }
}

#[cfg(unix)]
fn provider_policy(origin: SocketAddr, marker: &Path) -> String {
    format!(
        r#"[authorization.providers.corpus]
kind = "process"
command = "/usr/bin/python3"
args = ["-u", "-c", '''
import json, sys, threading, time
marker = {marker:?}
lock = threading.Lock()
def send(response):
    with lock:
        print(json.dumps(response, separators=(",", ":")), flush=True)
def complete(request):
    url = request["url"]
    if request["method"] == "CONNECT":
        send({{"id": request["id"], "type": "response", "decision": "allow"}})
    elif url.endswith("/timeout") or url.endswith("/cancel"):
        time.sleep(30)
        send({{"id": request["id"], "type": "response", "decision": "allow", "values": {{"token": "late"}}}})
    elif url.endswith("/pass"):
        send({{"id": request["id"], "type": "response", "decision": "pass"}})
    elif url.endswith("/deny"):
        send({{"id": request["id"], "type": "response", "decision": "deny"}})
    elif url.endswith("/error"):
        send({{"id": request["id"], "type": "response", "decision": "invalid"}})
    elif url.endswith("/invalid-encoding"):
        send({{"id": request["id"], "type": "response", "decision": "allow", "values": {{"token": "typed-secret"}}, "requestBody": {{"encoding": "base64", "contentType": "text/plain", "contentEncoding": "gzip", "data": "cmVwbGFjZW1lbnQtYm9keQ=="}}}})
    elif url.endswith("/upgrade"):
        send({{"id": request["id"], "type": "response", "decision": "allow", "values": {{"token": "typed-secret"}}}})
    else:
        send({{"id": request["id"], "type": "response", "decision": "allow", "values": {{"token": "typed-secret"}}, "requestBody": {{"encoding": "base64", "contentType": "text/plain", "data": "cmVwbGFjZW1lbnQtYm9keQ=="}}}})
for line in sys.stdin:
    request = json.loads(line)
    with open(marker, "a", encoding="utf-8") as output:
        output.write(request["url"] + "\n")
        output.flush()
    threading.Thread(target=complete, args=(request,), daemon=True).start()
''']
timeout = "5s"
retire_timeout = "6s"
on_failure = "error"
inherit_environment = false
environment = {{ PATH = "/usr/bin:/bin" }}
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 1024
max_decoded_request_body_bytes = 1024
max_stdout_line_bytes = 4096

[authorization.providers.corpus.outputs.token]
kind = "bearer"
transport_security = "cleartext_allowed"
required = true

[policy]
default = "deny"

[[policy.rules]]
id = "provider-timeout"
decision = "delegate"
urls = ["http://localhost:{port}/timeout", "https://localhost:{port}/timeout"]
methods = ["POST"]
authorization_provider = "corpus"
request_timeout = "100ms"

[[policy.rules]]
id = "provider-corpus"
decision = "delegate"
urls = ["http://localhost:{port}/**", "https://localhost:{port}/**"]
methods = ["POST"]
authorization_provider = "corpus"

[[policy.rules]]
id = "provider-upgrade"
decision = "delegate"
urls = ["http://localhost:{port}/upgrade", "https://localhost:{port}/upgrade"]
methods = ["GET"]
authorization_provider = "corpus"
allow_upgrades = true

[[policy.rules]]
id = "after-provider-pass"
decision = "allow"
urls = ["http://localhost:{port}/pass", "https://localhost:{port}/pass"]
methods = ["POST"]
"#,
        marker = marker.display().to_string(),
        port = origin.port(),
    )
}

#[cfg(unix)]
async fn provider_origin(
    tls: bool,
) -> (
    SocketAddr,
    tokio::sync::mpsc::UnboundedReceiver<(String, String, Vec<u8>)>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let identity_directory = tempdir().unwrap();
    let identity = identity(identity_directory.path(), "localhost");
    let acceptor = tls.then(|| tls_acceptor(&identity));
    let (seen_tx, seen_rx) = tokio::sync::mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let _identity_directory = identity_directory;
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let seen_tx = seen_tx.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut stream: Box<dyn LifecycleIo> = if let Some(acceptor) = acceptor {
                    Box::new(acceptor.accept(stream).await.unwrap())
                } else {
                    Box::new(stream)
                };
                let request = super::read_http_message(&mut stream).await;
                let head_end = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let head = String::from_utf8(request[..head_end].to_vec()).unwrap();
                let path = head
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_owned();
                seen_tx
                    .send((path.clone(), head.clone(), request[head_end..].to_vec()))
                    .unwrap();
                if path == "/upgrade" {
                    stream
                        .write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: obs-text\r\n\r\n",
                        )
                        .await
                        .unwrap();
                } else {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\norigin accepted",
                        )
                        .await
                        .unwrap();
                }
            });
        }
    });
    (address, seen_rx, task)
}

#[cfg(unix)]
async fn provider_fixture(
    test: &crate::activation::ListenerTestGuard<'_>,
    case: ProviderCase,
) -> (
    ProviderFixture,
    tokio::sync::mpsc::UnboundedReceiver<(String, String, Vec<u8>)>,
    PathBuf,
) {
    let tls_origin = matches!(
        case,
        ProviderCase::ExplicitHttps
            | ProviderCase::ConnectMitmInner
            | ProviderCase::TransparentHttps
    );
    let (origin, seen, origin_task) = provider_origin(tls_origin).await;
    let reservations = crate::activation::reserve_listeners::<1>(test);
    let [proxy] = reservations.addresses();
    let mut listeners = reservations.into_listeners();
    let listener = listeners.remove(0);
    let directory = tempdir().unwrap();
    let marker_directory = tempdir().unwrap();
    let marker = marker_directory.path().join("provider-calls");
    let policy = provider_policy(origin, &marker);
    let incoming_directory = directory.path().join("incoming");
    fs::create_dir_all(&incoming_directory).unwrap();
    let incoming = identity(&incoming_directory, "localhost");
    let (listener_table, listener_extra) = match case {
        ProviderCase::ExplicitHttp => (
            "explicit_http",
            format!("[listeners.explicit_http.connect]\nhttp1 = \"deny\"\n\n{policy}"),
        ),
        ProviderCase::ExplicitHttps => (
            "explicit_https",
            format!(
                "[listeners.explicit_https.connect]\nhttp1 = \"deny\"\n\n[listeners.explicit_https.tls]\ncertificate_chain = {:?}\nprivate_key = {:?}\n\n{policy}",
                incoming.certificate_path, incoming.private_key_path
            ),
        ),
        ProviderCase::TransparentHttp => ("transparent_http", policy),
        ProviderCase::ConnectMitmInner => (
            "explicit_http",
            format!(
                "[listeners.explicit_http.connect]\nhttp1 = \"mitm\"\n\n[mitm]\nmode = \"generated\"\ndirectory = {:?}\n\n[[policy.rules]]\nid = \"connect-target\"\ndecision = \"delegate\"\nurls = [\"https://localhost:{}/**\"]\nmethods = [\"CONNECT\"]\nauthorization_provider = \"corpus\"\n\n{policy}",
                directory.path().join("mitm"),
                origin.port(),
            ),
        ),
        ProviderCase::TransparentHttps => (
            "transparent_https",
            format!(
                "[mitm]\nmode = \"generated\"\ndirectory = {:?}\n\n{policy}",
                directory.path().join("mitm")
            ),
        ),
    };
    let generated_ca = matches!(
        case,
        ProviderCase::ConnectMitmInner | ProviderCase::TransparentHttps
    )
    .then(|| {
        let ca = directory.path().join("mitm-ca.pem");
        initialize_generated_ca(&directory.path().join("mitm"), &ca);
        ca
    });
    let config = format!(
        r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.{listener_table}]
endpoint.kind = "tcp"
endpoint.address = "{proxy}"
http_versions = ["http1"]

[egress]
route = "direct"

[egress.origin_tls]
trust = "insecure"
http_versions = ["http1"]

{listener_extra}
"#
    );
    let config_path = directory.path().join("acl-proxy.toml");
    fs::write(&config_path, config).unwrap();
    let loaded = load_and_compile_exact_config(&config_path).unwrap();
    let facts = ForwardingNetworkFacts::new(vec![proxy], None, None, None).unwrap();
    let scheme = if tls_origin { "https" } else { "http" };
    let origin_url =
        canonicalize_http_url(&format!("{scheme}://localhost:{}/", origin.port())).unwrap();
    let network = Arc::new(
        ForwardingDevHarness::new(facts)
            .map_prebound(&origin_url, origin)
            .unwrap()
            .into_standalone_guard(),
    );
    let product = ProductRuntime::prepare_from_prebound_with_forwarding_network(
        loaded,
        vec![listener],
        network,
    )
    .await
    .unwrap();
    product.activate_initial().await.unwrap();
    if matches!(
        case,
        ProviderCase::TransparentHttp | ProviderCase::TransparentHttps
    ) {
        product
            .start_listeners_with_original_destination(Arc::new(FixedOriginalDestination(origin)))
            .await
            .unwrap();
    } else {
        product.start_listeners().await.unwrap();
    }
    let client_certificate = match case {
        ProviderCase::ExplicitHttps => incoming.certificate_path.clone(),
        ProviderCase::ConnectMitmInner | ProviderCase::TransparentHttps => generated_ca.unwrap(),
        ProviderCase::ExplicitHttp | ProviderCase::TransparentHttp => PathBuf::new(),
    };
    (
        ProviderFixture {
            case,
            proxy,
            origin,
            client_certificate,
            _directory: directory,
            _marker_directory: marker_directory,
            product,
            origin_task,
        },
        seen,
        marker,
    )
}

#[cfg(unix)]
async fn wait_for_provider_call(marker: &Path, suffix: &str) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let calls = fs::read_to_string(marker).unwrap_or_default();
            if calls.lines().any(|line| line.ends_with(suffix)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("provider did not receive {suffix}"));
}

#[cfg(unix)]
#[tokio::test]
async fn provider_effects_and_release_corpus_covers_all_five_ingress_modes() {
    let test = crate::activation::LISTENER_TEST_LOCK.lock().await;
    for case in [
        ProviderCase::ExplicitHttp,
        ProviderCase::ExplicitHttps,
        ProviderCase::TransparentHttp,
        ProviderCase::ConnectMitmInner,
        ProviderCase::TransparentHttps,
    ] {
        let (fixture, mut seen, marker) = provider_fixture(&test, case).await;
        let pool = fixture.product.wire_body_pool();

        let (status, body) = fixture.request("/pass", "pass-body").await;
        assert_eq!(
            (status, body.as_slice()),
            (200, b"origin accepted".as_slice()),
            "{case:?}"
        );
        let (path, headers, body) = seen.recv().await.unwrap();
        assert_eq!(
            (path.as_str(), body.as_slice()),
            ("/pass", b"pass-body".as_slice())
        );
        assert!(!headers.to_ascii_lowercase().contains("\r\nauthorization:"));
        assert_eq!(pool.global_charge(), 0);

        let (status, body) = fixture.request("/replace", "original-body").await;
        assert_eq!(
            (status, body.as_slice()),
            (200, b"origin accepted".as_slice()),
            "{case:?}"
        );
        let (path, headers, body) = seen.recv().await.unwrap();
        let headers = headers.to_ascii_lowercase();
        assert_eq!(
            (path.as_str(), body.as_slice()),
            ("/replace", b"replacement-body".as_slice())
        );
        assert!(headers.contains("\r\nauthorization: bearer typed-secret\r\n"));
        assert!(headers.contains("\r\ncontent-type: text/plain\r\n"));
        assert!(headers.contains("\r\ncontent-length: 16\r\n"));
        assert!(!headers.contains("\r\ncontent-encoding:"));
        assert_eq!(pool.global_charge(), 0);

        for (path, expected_status, expected_body) in [
            ("/deny", 403, b"request denied\n".as_slice()),
            ("/error", 500, b"request failed\n".as_slice()),
            ("/invalid-encoding", 500, b"request failed\n".as_slice()),
        ] {
            let (status, body) = fixture.request(path, "terminal-body").await;
            assert_eq!(
                (status, body.as_slice()),
                (expected_status, expected_body),
                "{case:?} {path}"
            );
            assert!(seen.try_recv().is_err());
            assert_eq!(pool.global_charge(), 0);
        }

        let response = fixture.request_upgrade().await;
        assert!(
            response.starts_with(b"HTTP/1.1 101 "),
            "{case:?}: {}",
            String::from_utf8_lossy(&response)
        );
        let (path, headers, body) = seen.recv().await.unwrap();
        assert_eq!(
            (path.as_str(), body.as_slice()),
            ("/upgrade", b"".as_slice())
        );
        assert!(headers
            .to_ascii_lowercase()
            .contains("\r\nauthorization: bearer typed-secret\r\n"));

        let (status, body) = fixture.request("/timeout", "timeout-body").await;
        assert_eq!(
            (status, body.as_slice()),
            (504, b"request timed out\n".as_slice()),
            "{case:?}"
        );
        assert!(seen.try_recv().is_err());
        assert_eq!(pool.global_charge(), 0);

        let calls = fs::read_to_string(&marker).unwrap();
        let connect_mitm = matches!(case, ProviderCase::ConnectMitmInner);
        assert_eq!(
            calls.lines().count(),
            if connect_mitm { 14 } else { 7 },
            "{case:?}"
        );
        for suffix in [
            "/pass",
            "/replace",
            "/deny",
            "/error",
            "/invalid-encoding",
            "/upgrade",
            "/timeout",
        ] {
            assert_eq!(
                calls.lines().filter(|line| line.ends_with(suffix)).count(),
                1,
                "{case:?} {suffix}"
            );
        }

        tokio::time::timeout(Duration::from_secs(2), fixture.product.shutdown())
            .await
            .unwrap_or_else(|_| panic!("{case:?} shutdown did not complete"));
        fixture.origin_task.abort();
        let _ = fixture.origin_task.await;
        crate::activation::assert_listener_addresses_released(&test, [fixture.proxy]);

        let (cancel_fixture, _cancel_seen, cancel_marker) = provider_fixture(&test, case).await;
        let cancel_pool = cancel_fixture.product.wire_body_pool();
        let cancelled = cancel_fixture.begin_cancelled_request().await;
        wait_for_provider_call(&cancel_marker, "/cancel").await;
        let calls = fs::read_to_string(&cancel_marker).unwrap();
        assert_eq!(
            calls.lines().count(),
            if connect_mitm { 2 } else { 1 },
            "{case:?}"
        );
        drop(cancelled);
        tokio::time::timeout(Duration::from_secs(2), cancel_fixture.product.shutdown())
            .await
            .unwrap_or_else(|_| panic!("{case:?} cancellation shutdown did not complete"));
        assert_eq!(cancel_pool.global_charge(), 0);
        cancel_fixture.origin_task.abort();
        let _ = cancel_fixture.origin_task.await;
        crate::activation::assert_listener_addresses_released(&test, [cancel_fixture.proxy]);
    }
}
