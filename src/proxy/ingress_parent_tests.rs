use std::fs;
use std::io::{self, BufReader};
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hyper::body::to_bytes;
use hyper::client::conn;
use hyper::{Body, Method, Request, StatusCode};
use rcgen::{CertificateParams, KeyPair};
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig, ServerName};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::ProductProxySupervisorStarter;
use crate::activation::runner::ProductRuntime;
use crate::config::load_and_compile_exact_config;
use crate::destination::{
    DestinationFacts, DestinationGuard, DestinationResolver, LocalAddressSnapshot,
    LocalAddressSource, ResolveFuture,
};
use crate::proxy::original_destination::{OriginalDestinationError, OriginalDestinationResolver};

const PARENT_HOST: &str = "parent.test";
const ORIGIN_HOST: &str = "localhost";

struct TestIdentity {
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
}

struct FixedResolver(SocketAddr);

impl DestinationResolver for FixedResolver {
    fn resolve(&self, host: &str, port: u16, _max_addresses: usize) -> ResolveFuture<'_> {
        assert_eq!(host, PARENT_HOST);
        assert_eq!(port, self.0.port());
        let endpoint = self.0;
        Box::pin(async move { Ok(vec![endpoint]) })
    }
}

#[derive(Default)]
struct EmptyLocalAddresses;

impl LocalAddressSource for EmptyLocalAddresses {
    fn snapshot(&self) -> io::Result<LocalAddressSnapshot> {
        Ok(LocalAddressSnapshot::default())
    }
}

struct FixedOriginalDestination(SocketAddr);

impl OriginalDestinationResolver for FixedOriginalDestination {
    fn resolve(
        &self,
        _socket: &tokio::net::TcpStream,
    ) -> Result<SocketAddr, OriginalDestinationError> {
        Ok(self.0)
    }
}

struct HttpOriginRequest {
    head: String,
    body: Vec<u8>,
}

struct WebSocketFrame {
    opcode: u8,
    payload: Vec<u8>,
}

fn prebound_listener() -> (SocketAddr, StdTcpListener) {
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    (listener.local_addr().unwrap(), listener)
}

fn write_identity(directory: &Path, name: &str, dns_name: &str) -> TestIdentity {
    let key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(vec![dns_name.to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let certificate_path = directory.join(format!("{name}-cert.pem"));
    let private_key_path = directory.join(format!("{name}-key.pem"));
    fs::write(&certificate_path, certificate.pem()).unwrap();
    fs::write(&private_key_path, key.serialize_pem()).unwrap();
    TestIdentity {
        certificate_path,
        private_key_path,
        certificate_der: certificate.der().to_vec(),
        private_key_der: key.serialize_der(),
    }
}

fn tls_acceptor(identity: &TestIdentity) -> TlsAcceptor {
    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![Certificate(identity.certificate_der.clone())],
            PrivateKey(identity.private_key_der.clone()),
        )
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

fn tls_connector(certificate_path: &Path) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    let mut reader = BufReader::new(fs::File::open(certificate_path).unwrap());
    for certificate in rustls_pemfile::certs(&mut reader).unwrap() {
        roots.add(&Certificate(certificate)).unwrap();
    }
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(config))
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

fn content_length(head: &[u8]) -> usize {
    String::from_utf8_lossy(head)
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
        })
        .unwrap_or(0)
}

async fn spawn_http_origin(identity: &TestIdentity) -> (SocketAddr, JoinHandle<HttpOriginRequest>) {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = tls_acceptor(identity);
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let head = read_http_head(&mut stream).await;
        let mut body = vec![0_u8; content_length(&head)];
        stream.read_exact(&mut body).await.unwrap();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nparent-hop-ok\n",
            )
            .await
            .unwrap();
        HttpOriginRequest {
            head: String::from_utf8(head).unwrap(),
            body,
        }
    });
    (address, task)
}

async fn spawn_websocket_origin(
    identity: &TestIdentity,
) -> (SocketAddr, JoinHandle<WebSocketFrame>) {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = tls_acceptor(identity);
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let head = read_http_head(&mut stream).await;
        let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
        assert!(head.starts_with("get /socket http/1.1\r\n"), "{head}");
        assert!(head.contains("\r\nupgrade: websocket\r\n"), "{head}");
        assert!(
            head.contains("\r\nx-parent-proxy: strict-https\r\n"),
            "{head}"
        );
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();
        let frame = read_websocket_frame(&mut stream).await.unwrap();
        write_websocket_frame(&mut stream, 0x1, b"server password", false)
            .await
            .unwrap();
        frame
    });
    (address, task)
}

async fn write_websocket_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    opcode: u8,
    payload: &[u8],
    masked: bool,
) -> io::Result<()> {
    assert!(payload.len() < 126);
    let mut frame = vec![0x80 | opcode, payload.len() as u8];
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

async fn read_websocket_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<WebSocketFrame> {
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header).await?;
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let payload_len = usize::from(header[1] & 0x7f);
    if payload_len >= 126 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "extended WebSocket payload is unsupported in this test",
        ));
    }
    let mut mask = [0_u8; 4];
    if masked {
        reader.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0_u8; payload_len];
    reader.read_exact(&mut payload).await?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % mask.len()];
        }
    }
    Ok(WebSocketFrame { opcode, payload })
}

fn parent_config(
    bind: SocketAddr,
    identity: &TestIdentity,
    origin: SocketAddr,
    origin_certificate: &Path,
) -> String {
    format!(
        r#"schema_version = 3

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.explicit_https]
bind = "{bind}"
http_versions = ["http1"]
handshake_timeout = "1s"

[listeners.explicit_https.connect]
http1 = "mitm"

[listeners.explicit_https.tls]
certificate_chain = "{}"
private_key = "{}"

[mitm]
mode = "generated"
directory = "mitm"

[egress]
route = "direct"

[egress.origin_tls]
trust = "custom"
ca_certificate = "{}"
http_versions = ["http1"]

[[egress.request_headers]]
operation = "set"
when = "always"
name = "x-parent-proxy"
value = "strict-https"

[policy]
default = "deny"

[[policy.rules]]
id = "allow-origin"
decision = "allow"
urls = ["https://{ORIGIN_HOST}:{}/**"]
allow_upgrades = true

[safety.loop_detection]
inject = true
header = "x-test-loop"
"#,
        identity.certificate_path.display(),
        identity.private_key_path.display(),
        origin_certificate.display(),
        origin.port(),
    )
}

fn child_config(
    bind: SocketAddr,
    parent: SocketAddr,
    parent_identity: &TestIdentity,
    parent_mitm_ca: &Path,
    origin: SocketAddr,
    protect_websocket: bool,
) -> String {
    let redaction = protect_websocket.then_some(
        r#"
[redaction.profiles.wire]
replacement = "[REDACTED]"
max_frame_bytes = 1024
max_message_bytes = 1024
rules = [{ literals = ["password"], payloads = "both" }]
"#,
    );
    let rule = if protect_websocket {
        "allow_upgrades = true\nredaction_profile = \"wire\""
    } else {
        "allow_upgrades = false"
    };
    format!(
        r#"schema_version = 3

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.transparent_https]
bind = "{bind}"
http_versions = ["http1"]
handshake_timeout = "1s"

[mitm]
mode = "generated"
directory = "mitm"

[egress]
route = "parent_proxy"

[egress.origin_tls]
trust = "custom"
ca_certificate = "{}"
http_versions = ["http1"]

[egress.parent_proxy]
kind = "acl_proxy"
url = "https://{PARENT_HOST}:{}"

[egress.parent_proxy.tls]
trust = "custom"
ca_certificate = "{}"
server_name = "{PARENT_HOST}"
{}

[policy]
default = "deny"

[[policy.rules]]
id = "allow-origin"
decision = "allow"
urls = ["https://{ORIGIN_HOST}:{}/**"]
{rule}

[safety.loop_detection]
inject = false
header = "x-test-loop"
"#,
        parent_mitm_ca.display(),
        parent.port(),
        parent_identity.certificate_path.display(),
        redaction.unwrap_or_default(),
        origin.port(),
    )
}

async fn start_product(
    directory: &Path,
    config: String,
    listener: StdTcpListener,
) -> Arc<ProductRuntime> {
    let path = directory.join("acl-proxy.toml");
    fs::write(&path, config).unwrap();
    let loaded = load_and_compile_exact_config(&path).unwrap();
    let product = ProductRuntime::prepare_from_prebound(loaded, vec![listener])
        .await
        .unwrap();
    product.activate_initial().await.unwrap();
    let mut starter = ProductProxySupervisorStarter::new(
        product.runtime().clone(),
        product.observation_runtime().clone(),
        product.upgrade_runtime(),
    );
    product.start_proxy_supervisors(&mut starter).await.unwrap();
    product
}

async fn start_child_product(
    directory: &Path,
    config: String,
    listener: StdTcpListener,
    parent: SocketAddr,
    origin: SocketAddr,
) -> Arc<ProductRuntime> {
    let path = directory.join("acl-proxy.toml");
    fs::write(&path, config).unwrap();
    let loaded = load_and_compile_exact_config(&path).unwrap();
    let facts = DestinationFacts::from_static(&loaded.compiled.static_config).unwrap();
    let guard = Arc::new(
        DestinationGuard::with_sources_allowing_local_parent_for_test(
            facts,
            Arc::new(FixedResolver(parent)),
            Arc::new(EmptyLocalAddresses),
        ),
    );
    let product =
        ProductRuntime::prepare_from_prebound_with_destination_guard(loaded, vec![listener], guard)
            .await
            .unwrap();
    product.activate_initial().await.unwrap();
    let mut starter = ProductProxySupervisorStarter::with_original_destination_resolver(
        product.runtime().clone(),
        product.observation_runtime().clone(),
        product.upgrade_runtime(),
        Arc::new(FixedOriginalDestination(origin)),
    );
    product.start_proxy_supervisors(&mut starter).await.unwrap();
    product
}

async fn topology(
    websocket: bool,
) -> (
    TempDir,
    SocketAddr,
    SocketAddr,
    Arc<ProductRuntime>,
    Arc<ProductRuntime>,
    Option<JoinHandle<HttpOriginRequest>>,
    Option<JoinHandle<WebSocketFrame>>,
) {
    let root = tempdir().unwrap();
    let origin_directory = root.path().join("origin");
    let parent_directory = root.path().join("parent");
    let child_directory = root.path().join("child");
    fs::create_dir_all(&origin_directory).unwrap();
    fs::create_dir_all(&parent_directory).unwrap();
    fs::create_dir_all(&child_directory).unwrap();

    let origin_identity = write_identity(&origin_directory, "origin", ORIGIN_HOST);
    let parent_identity = write_identity(&parent_directory, "parent", PARENT_HOST);
    let (origin, http_origin, websocket_origin) = if websocket {
        let (origin, task) = spawn_websocket_origin(&origin_identity).await;
        (origin, None, Some(task))
    } else {
        let (origin, task) = spawn_http_origin(&origin_identity).await;
        (origin, Some(task), None)
    };
    let (parent, parent_listener) = prebound_listener();
    let parent_product = start_product(
        &parent_directory,
        parent_config(
            parent,
            &parent_identity,
            origin,
            &origin_identity.certificate_path,
        ),
        parent_listener,
    )
    .await;
    let parent_mitm_ca = parent_directory.join("mitm/ca-cert.pem");
    assert!(parent_mitm_ca.is_file());

    let (child, child_listener) = prebound_listener();
    let child_product = start_child_product(
        &child_directory,
        child_config(
            child,
            parent,
            &parent_identity,
            &parent_mitm_ca,
            origin,
            websocket,
        ),
        child_listener,
        parent,
        origin,
    )
    .await;
    (
        root,
        child,
        origin,
        child_product,
        parent_product,
        http_origin,
        websocket_origin,
    )
}

#[tokio::test]
async fn transparent_https_forwards_through_https_acl_proxy_parent() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (root, child, origin, child_product, parent_product, origin_task, _) =
        topology(false).await;
    let child_ca = root.path().join("child/mitm/ca-cert.pem");
    let connector = tls_connector(&child_ca);
    let stream = tokio::net::TcpStream::connect(child).await.unwrap();
    let stream = connector
        .connect(ServerName::try_from(ORIGIN_HOST).unwrap(), stream)
        .await
        .unwrap();
    let (mut sender, connection) = conn::handshake(stream).await.unwrap();
    let driver = tokio::spawn(connection);
    let response = sender
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/via-parent")
                .header("host", format!("{ORIGIN_HOST}:{}", origin.port()))
                .body(Body::from("parent-hop-body"))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let response_body = to_bytes(response.into_body()).await.unwrap();
    drop(sender);
    driver.await.unwrap().unwrap();
    let seen = origin_task.unwrap().await.unwrap();

    child_product.shutdown().await;
    parent_product.shutdown().await;
    let child_shutdown = child_product.shutdown_diagnostic();
    let parent_shutdown = parent_product.shutdown_diagnostic();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(response_body, "parent-hop-ok\n");
    assert_eq!(seen.body, b"parent-hop-body");
    let head = seen.head.to_ascii_lowercase();
    assert!(head.starts_with("post /via-parent http/1.1\r\n"), "{head}");
    assert!(
        head.contains("\r\nx-parent-proxy: strict-https\r\n"),
        "{head}"
    );
    assert!(child_shutdown.is_none(), "{child_shutdown:?}");
    assert!(parent_shutdown.is_none(), "{parent_shutdown:?}");
}

#[tokio::test]
async fn protected_websocket_redacts_client_message_through_https_acl_proxy_parent() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (root, child, origin, child_product, parent_product, http_origin, websocket_origin) =
        topology(true).await;
    assert!(http_origin.is_none());
    let connector = tls_connector(&root.path().join("child/mitm/ca-cert.pem"));
    let stream = tokio::net::TcpStream::connect(child).await.unwrap();
    let mut stream = connector
        .connect(ServerName::try_from(ORIGIN_HOST).unwrap(), stream)
        .await
        .unwrap();
    stream
        .write_all(
            format!(
                "GET /socket HTTP/1.1\r\nHost: {ORIGIN_HOST}:{}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGVzdC13ZWJzb2NrZXQta2V5\r\n\r\n",
                origin.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response = read_http_head(&mut stream).await;
    assert!(
        response.starts_with(b"HTTP/1.1 101 "),
        "{}",
        String::from_utf8_lossy(&response)
    );
    write_websocket_frame(&mut stream, 0x1, b"client password", true)
        .await
        .unwrap();
    let reply = read_websocket_frame(&mut stream).await.unwrap();
    let seen = websocket_origin.unwrap().await.unwrap();
    drop(stream);

    child_product.shutdown().await;
    parent_product.shutdown().await;
    let child_shutdown = child_product.shutdown_diagnostic();
    let parent_shutdown = parent_product.shutdown_diagnostic();

    assert_eq!(seen.opcode, 0x1);
    assert_eq!(seen.payload, b"client [REDACTED]");
    assert_eq!(reply.opcode, 0x1);
    assert_eq!(reply.payload, b"server password");
    assert!(child_shutdown.is_none(), "{child_shutdown:?}");
    assert!(parent_shutdown.is_none(), "{parent_shutdown:?}");
}
