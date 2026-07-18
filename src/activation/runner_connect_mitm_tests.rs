use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rcgen::{CertificateParams, KeyPair};
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig, ServerName};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::*;

struct TestIdentity {
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
}

fn prebound_listener() -> (SocketAddr, StdTcpListener) {
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    (listener.local_addr().unwrap(), listener)
}

fn write_identity(directory: &Path, dns_name: &str) -> TestIdentity {
    let key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(vec![dns_name.to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let certificate_path = directory.join("server-cert.pem");
    let private_key_path = directory.join("server-key.pem");
    fs::write(&certificate_path, certificate.pem()).unwrap();
    crate::filesystem::write_private_file(&private_key_path, key.serialize_pem()).unwrap();
    TestIdentity {
        certificate_path,
        private_key_path,
        certificate_der: certificate.der().to_vec(),
        private_key_der: key.serialize_der(),
    }
}

fn tls_acceptor(identity: &TestIdentity, alpn: &[&[u8]]) -> TlsAcceptor {
    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![Certificate(identity.certificate_der.clone())],
            PrivateKey(identity.private_key_der.clone()),
        )
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    TlsAcceptor::from(Arc::new(config))
}

fn tls_connector(certificates: impl IntoIterator<Item = Vec<u8>>, alpn: &[&[u8]]) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots.add(&Certificate(certificate)).unwrap();
    }
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    TlsConnector::from(Arc::new(config))
}

fn initialize_generated_ca(directory: &Path) -> Vec<Vec<u8>> {
    let root = PrivateStorageRoot::open_or_create(directory).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    GeneratedCertificateAuthority::open_or_generate(root, i64::try_from(now).unwrap())
        .unwrap()
        .public_ca_chain_der()
}

fn connect_policy(target: &str, extra_rule: &str) -> String {
    format!(
        r#"[policy]
default = "deny"

[[policy.rules]]
id = "connect-target"
decision = "allow"
urls = ["https://{target}/**"]
{extra_rule}
"#
    )
}

fn connect_config(
    proxy: SocketAddr,
    target: &str,
    listener_kind: &str,
    listener_extra: &str,
    rule_extra: &str,
    extra: &str,
) -> String {
    format!(
        r#"schema_version = 3

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.{listener_kind}]
bind = "{proxy}"
http_versions = ["http1"]
{listener_extra}

[listeners.{listener_kind}.connect]
http1 = "mitm"

[mitm]
mode = "generated"
directory = "mitm"

[egress]
route = "direct"

[egress.origin_tls]
trust = "insecure"
http_versions = ["http1"]

{}

{extra}
"#,
        connect_policy(target, rule_extra),
    )
}

fn mapped_network(
    proxy: SocketAddr,
    canonical: &str,
    endpoint: SocketAddr,
) -> Arc<http_access_runtime::ForwardingNetworkGuard> {
    let facts =
        http_access_runtime::ForwardingNetworkFacts::new(vec![proxy], None, None, None).unwrap();
    let canonical = http_access_url::canonicalize_http_url(canonical).unwrap();
    Arc::new(
        http_access_runtime::ForwardingDevHarness::new(facts)
            .map_prebound(&canonical, endpoint)
            .unwrap()
            .into_standalone_guard(),
    )
}

async fn start_product(
    directory: &TempDir,
    text: &str,
    listener: StdTcpListener,
    network: Option<Arc<http_access_runtime::ForwardingNetworkGuard>>,
) -> Arc<ProductRuntime> {
    let path = directory.path().join("acl-proxy.toml");
    fs::write(&path, text).unwrap();
    let loaded = load_and_compile_exact_config(&path).unwrap();
    let product = match network {
        Some(network) => {
            ProductRuntime::prepare_from_prebound_with_forwarding_network(
                loaded,
                vec![listener],
                network,
            )
            .await
        }
        None => ProductRuntime::prepare_from_prebound(loaded, vec![listener]).await,
    }
    .unwrap();
    product.activate_initial().await.unwrap();
    product.start_listeners().await.unwrap();
    product
}

async fn open_connect(proxy: SocketAddr, target: &str) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = read_http_message(&mut stream).await;
    assert!(
        head.starts_with(b"HTTP/1.1 200 "),
        "unexpected CONNECT response: {}",
        String::from_utf8_lossy(&head)
    );
    stream
}

async fn write_websocket_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    opcode: u8,
    payload: &[u8],
    masked: bool,
) -> io::Result<()> {
    assert!(payload.len() < 126);
    let mut frame = vec![0x80 | opcode, u8::try_from(payload.len()).unwrap()];
    if masked {
        frame[1] |= 0x80;
        let mask = [0x11, 0x22, 0x33, 0x44];
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % mask.len()]),
        );
    } else {
        frame.extend_from_slice(payload);
    }
    writer.write_all(&frame).await
}

async fn read_websocket_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header).await?;
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let length = usize::from(header[1] & 0x7f);
    assert!(length < 126);
    let mut mask = [0_u8; 4];
    if masked {
        reader.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % mask.len()];
        }
    }
    Ok((opcode, payload))
}

#[tokio::test]
async fn connect_deny_policy_returns_forbidden_without_mitm_activation() {
    let _test = super::super::super::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = prebound_listener();
    let directory = tempfile::tempdir().unwrap();
    let text = format!(
        r#"schema_version = 3

[service]
shutdown_drain_timeout = "1s"

[listeners.explicit_http]
bind = "{proxy}"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "allow"
"#
    );
    let product = start_product(&directory, &text, listener, None).await;
    let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"CONNECT 192.0.2.10:443 HTTP/1.1\r\nHost: 192.0.2.10:443\r\n\r\n")
        .await
        .unwrap();
    let mut response = read_http_message(&mut client).await;
    client.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 403 "));
    let body_offset = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert_eq!(
        &response[body_offset..],
        b"F\r\nCONNECT denied\n\r\n0\r\n\r\n"
    );
    assert!(!directory.path().join("mitm").exists());
    product.shutdown().await;
    assert!(StdTcpListener::bind(proxy).is_ok());
}

#[tokio::test]
async fn connect_mitm_forwards_inner_request_and_rejects_nested_connect() {
    let _test = super::super::super::LISTENER_TEST_LOCK.lock().await;
    let directory = tempfile::tempdir().unwrap();
    let origin_identity = write_identity(directory.path(), "localhost");
    let origin = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin_address = origin.local_addr().unwrap();
    let acceptor = tls_acceptor(&origin_identity, &[b"http/1.1"]);
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let origin_task = tokio::spawn(async move {
        let (stream, _) = origin.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let request = read_http_message(&mut stream).await;
        assert!(request.starts_with(b"GET /allowed HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\nconnect origin")
            .await
            .unwrap();
        let _ = release_rx.await;
    });
    let (proxy, listener) = prebound_listener();
    let target = format!("localhost:{}", origin_address.port());
    let ca = initialize_generated_ca(&directory.path().join("mitm"));
    let text = connect_config(proxy, &target, "explicit_http", "", "", "");
    let network = mapped_network(proxy, &format!("https://{target}/"), origin_address);
    let product = start_product(&directory, &text, listener, Some(network)).await;
    let stream = open_connect(proxy, &target).await;
    let connector = tls_connector(ca, &[b"http/1.1"]);
    let mut tunnel = connector
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    tunnel
        .write_all(
            format!("GET /allowed HTTP/1.1\r\nHost: {target}\r\nContent-Length: 0\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let response = read_http_message(&mut tunnel).await;
    assert!(response.starts_with(b"HTTP/1.1 200 "));
    assert!(response.ends_with(b"connect origin"));
    tunnel
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let nested = read_http_message(&mut tunnel).await;
    assert!(nested.starts_with(b"HTTP/1.1 400 "));
    release_tx.send(()).ok();
    drop(tunnel);
    origin_task.await.unwrap();
    product.shutdown().await;
    assert!(StdTcpListener::bind(proxy).is_ok());
}

#[tokio::test]
async fn connect_mitm_outer_tunnel_omits_global_origin_credentials() {
    const VARIABLE: &str = "ACL_PROXY_OUTER_CONNECT_IDENTITY";
    let _test = super::super::super::LISTENER_TEST_LOCK.lock().await;
    std::env::remove_var(VARIABLE);
    let directory = tempfile::tempdir().unwrap();
    let origin_identity = write_identity(directory.path(), "localhost");
    let origin = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin_address = origin.local_addr().unwrap();
    let acceptor = tls_acceptor(&origin_identity, &[b"http/1.1"]);
    let origin_task = tokio::spawn(async move {
        let (stream, _) = origin.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let request = read_http_message(&mut stream).await;
        let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
        assert!(request.contains("\r\nx-aw-identity-token: inner-identity\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\ncredentialized",
            )
            .await
            .unwrap();
    });
    let (proxy, listener) = prebound_listener();
    let target = format!("localhost:{}", origin_address.port());
    let ca = initialize_generated_ca(&directory.path().join("mitm"));
    let credential_config = format!(
        r#"[[egress.credential_actions]]
kind = "custom_header"
header = "x-aw-identity-token"
credential = "outer_identity"

[credentials]
allowed_custom_headers = ["x-aw-identity-token"]

[credentials.sources.outer_identity]
source = "environment"
variable = "{VARIABLE}"
"#
    );
    let text = connect_config(proxy, &target, "explicit_http", "", "", &credential_config);
    let network = mapped_network(proxy, &format!("https://{target}/"), origin_address);
    let product = start_product(&directory, &text, listener, Some(network)).await;
    let stream = open_connect(proxy, &target).await;
    std::env::set_var(VARIABLE, "inner-identity");
    let connector = tls_connector(ca, &[b"http/1.1"]);
    let mut tunnel = connector
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    tunnel
        .write_all(
            format!("GET /credentialized HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let response = read_http_message(&mut tunnel).await;
    assert!(response.starts_with(b"HTTP/1.1 200 "));
    assert!(response.ends_with(b"credentialized"));
    origin_task.await.unwrap();
    product.shutdown().await;
    std::env::remove_var(VARIABLE);
}

#[tokio::test]
async fn connect_mitm_inner_h2_alpn_forwards_canonical_origin_request() {
    let _test = super::super::super::LISTENER_TEST_LOCK.lock().await;
    let directory = tempfile::tempdir().unwrap();
    let origin_identity = write_identity(directory.path(), "localhost");
    let origin = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin_address = origin.local_addr().unwrap();
    let acceptor = tls_acceptor(&origin_identity, &[b"http/1.1"]);
    let origin_task = tokio::spawn(async move {
        let (stream, _) = origin.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let request = read_http_message(&mut stream).await;
        let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
        assert!(request.starts_with("get /inner-h2?mode=one http/1.1\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 25\r\nConnection: close\r\n\r\nconnect inner h2 accepted",
            )
            .await
            .unwrap();
    });
    let (proxy, listener) = prebound_listener();
    let target = format!("localhost:{}", origin_address.port());
    let ca = initialize_generated_ca(&directory.path().join("mitm"));
    let text = connect_config(
        proxy,
        &target,
        "explicit_http",
        "http_versions = [\"http1\", \"http2\"]",
        "",
        "",
    )
    .replace(
        "http_versions = [\"http1\"]\nhttp_versions",
        "http_versions",
    );
    let text = text.replace("http1 = \"mitm\"", "http1 = \"mitm\"\nhttp2 = \"deny\"");
    let network = mapped_network(proxy, &format!("https://{target}/"), origin_address);
    let product = start_product(&directory, &text, listener, Some(network)).await;
    let stream = open_connect(proxy, &target).await;
    let connector = tls_connector(ca, &[b"h2"]);
    let tunnel = tokio::time::timeout(
        Duration::from_secs(2),
        connector.connect(ServerName::try_from("localhost").unwrap(), stream),
    )
    .await
    .expect("inner h2 TLS handshake timed out")
    .unwrap();
    assert_eq!(tunnel.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) =
        tokio::time::timeout(Duration::from_secs(2), h2::client::handshake(tunnel))
            .await
            .expect("inner h2 preface timed out")
            .unwrap();
    let driver = tokio::spawn(connection);
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://{target}/inner-h2?mode=one"))
        .body(())
        .unwrap();
    let (response, _) = sender.send_request(request, true).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), response)
        .await
        .expect("inner h2 response timed out")
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = tokio::time::timeout(Duration::from_secs(2), body.data())
        .await
        .expect("inner h2 body timed out")
    {
        bytes.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(bytes, b"connect inner h2 accepted");
    drop(sender);
    origin_task.await.unwrap();
    product.shutdown().await;
    tokio::time::timeout(Duration::from_secs(2), driver)
        .await
        .expect("product shutdown did not close the inner h2 connection")
        .unwrap()
        .unwrap();
    assert!(StdTcpListener::bind(proxy).is_ok());
}

#[tokio::test]
async fn connect_mitm_websocket_applies_wire_redaction() {
    let _test = super::super::super::LISTENER_TEST_LOCK.lock().await;
    let directory = tempfile::tempdir().unwrap();
    let origin_identity = write_identity(directory.path(), "localhost");
    let origin = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin_address = origin.local_addr().unwrap();
    let acceptor = tls_acceptor(&origin_identity, &[b"http/1.1"]);
    let origin_task = tokio::spawn(async move {
        let (stream, _) = origin.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let request = read_http_message(&mut stream).await;
        assert!(String::from_utf8_lossy(&request)
            .to_ascii_lowercase()
            .contains("\r\nupgrade: websocket\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            )
            .await
            .unwrap();
        let frame = read_websocket_frame(&mut stream).await.unwrap();
        write_websocket_frame(&mut stream, 0x1, b"server response", false)
            .await
            .unwrap();
        frame
    });
    let (proxy, listener) = prebound_listener();
    let target = format!("localhost:{}", origin_address.port());
    let ca = initialize_generated_ca(&directory.path().join("mitm"));
    let redaction = r#"[redaction.profiles.wire]
replacement = "[REDACTED]"
max_frame_bytes = 1024
max_message_bytes = 1024
rules = [{ literals = ["password"], payloads = "text" }]
"#;
    let text = connect_config(
        proxy,
        &target,
        "explicit_http",
        "",
        "allow_upgrades = true\nredaction_profile = \"wire\"",
        redaction,
    );
    let network = mapped_network(proxy, &format!("https://{target}/"), origin_address);
    let product = start_product(&directory, &text, listener, Some(network)).await;
    let stream = open_connect(proxy, &target).await;
    let connector = tls_connector(ca, &[b"http/1.1"]);
    let mut tunnel = connector
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    tunnel
        .write_all(
            format!(
                "GET /socket HTTP/1.1\r\nHost: {target}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response = read_http_message(&mut tunnel).await;
    assert!(response.starts_with(b"HTTP/1.1 101 "));
    write_websocket_frame(&mut tunnel, 0x1, b"client password", true)
        .await
        .unwrap();
    let reply = read_websocket_frame(&mut tunnel).await.unwrap();
    let seen = origin_task.await.unwrap();
    assert_eq!(seen, (0x1, b"client [REDACTED]".to_vec()));
    assert_eq!(reply, (0x1, b"server response".to_vec()));
    drop(tunnel);
    product.shutdown().await;
    assert_eq!(product.forwarding_terminal_completions_for_test(), 1);
}

#[tokio::test]
async fn connect_mitm_rejects_listener_loop_before_200() {
    let _test = super::super::super::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = prebound_listener();
    let directory = tempfile::tempdir().unwrap();
    initialize_generated_ca(&directory.path().join("mitm"));
    let target = proxy.to_string();
    let text = connect_config(proxy, &target, "explicit_http", "", "", "");
    let product = start_product(&directory, &text, listener, None).await;
    let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let response = read_http_message(&mut client).await;
    assert!(response.starts_with(b"HTTP/1.1 403 "));
    product.shutdown().await;
}

#[tokio::test]
async fn explicit_https_listener_supports_http1_connect_mitm() {
    let _test = super::super::super::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = prebound_listener();
    let directory = tempfile::tempdir().unwrap();
    let identity = write_identity(directory.path(), "localhost");
    let ca = initialize_generated_ca(&directory.path().join("mitm"));
    let target = "192.0.2.10:443";
    let listener_extra = format!(
        "handshake_timeout = \"1s\"\n\n[listeners.explicit_https.tls]\ncertificate_chain = \"{}\"\nprivate_key = \"{}\"",
        identity.certificate_path.display(),
        identity.private_key_path.display()
    );
    let text = connect_config(proxy, target, "explicit_https", &listener_extra, "", "");
    let product = start_product(&directory, &text, listener, None).await;
    let outer_connector = tls_connector([identity.certificate_der], &[b"http/1.1"]);
    let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let mut outer = outer_connector
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    outer
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let response = read_http_message(&mut outer).await;
    assert!(response.starts_with(b"HTTP/1.1 200 "));
    let inner_connector = tls_connector(ca, &[b"http/1.1"]);
    let mut inner = inner_connector
        .connect(ServerName::try_from("192.0.2.10").unwrap(), outer)
        .await
        .unwrap();
    inner
        .write_all(b"GET https://other.example/denied HTTP/1.1\r\nHost: 192.0.2.10:443\r\n\r\n")
        .await
        .unwrap();
    let response = read_http_message(&mut inner).await;
    assert!(response.starts_with(b"HTTP/1.1 400 "));
    drop(inner);
    product.shutdown().await;
}

#[tokio::test]
async fn connect_mitm_closes_stalled_client_hello_at_listener_deadline() {
    let _test = super::super::super::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = prebound_listener();
    let directory = tempfile::tempdir().unwrap();
    initialize_generated_ca(&directory.path().join("mitm"));
    let target = "192.0.2.10:443";
    let text = connect_config(
        proxy,
        target,
        "explicit_http",
        "request_header_timeout = \"50ms\"",
        "",
        "",
    );
    let product = start_product(&directory, &text, listener, None).await;
    let mut stream = open_connect(proxy, target).await;
    let mut byte = [0_u8; 1];
    let count = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
        .await
        .expect("stalled CONNECT ClientHello was not closed")
        .unwrap();
    assert_eq!(count, 0);
    product.shutdown().await;
}

#[tokio::test]
async fn connect_tunnel_retains_connection_admission_until_terminal_join() {
    let _test = super::super::super::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = prebound_listener();
    let directory = tempfile::tempdir().unwrap();
    initialize_generated_ca(&directory.path().join("mitm"));
    let target = "192.0.2.10:443";
    let text = connect_config(
        proxy,
        target,
        "explicit_http",
        "max_connections = 1",
        "",
        "",
    );
    let product = start_product(&directory, &text, listener, None).await;
    let first = open_connect(proxy, target).await;
    let mut second = tokio::net::TcpStream::connect(proxy).await.unwrap();
    second
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut byte = [0_u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(50), second.read(&mut byte))
            .await
            .is_err(),
        "a second connection bypassed the CONNECT admission permit"
    );
    drop(first);
    let response = tokio::time::timeout(Duration::from_secs(2), read_http_message(&mut second))
        .await
        .expect("waiting CONNECT was not admitted after terminal join");
    assert!(response.starts_with(b"HTTP/1.1 200 "));
    drop(second);
    product.shutdown().await;
}
