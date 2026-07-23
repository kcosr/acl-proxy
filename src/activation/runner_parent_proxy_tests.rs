use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use flate2::write::GzEncoder;
use flate2::Compression;
use http_access_runtime::{
    ForwardingDevHarness, ForwardingNetworkFacts, OriginalDestinationProvider,
};
use http_access_url::canonicalize_http_url;
use rustls::pki_types::ServerName;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::*;
use crate::test_certificates::{client_config_for_pem_roots, TestTlsIdentity};

const PARENT_HOST: &str = "parent.test";
const ORIGIN_HOST: &str = "localhost";

struct TestIdentity {
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    tls: TestTlsIdentity,
}

struct FixedOriginalDestination(SocketAddr);

impl OriginalDestinationProvider for FixedOriginalDestination {
    fn original_destination(
        &self,
        _stream: &std::net::TcpStream,
    ) -> Result<SocketAddr, http_access_runtime::RuntimeError> {
        Ok(self.0)
    }
}

struct WebSocketFrame {
    opcode: u8,
    payload: Vec<u8>,
}

struct ParentTopology {
    _root: TempDir,
    child_address: SocketAddr,
    parent_address: SocketAddr,
    origin_address: SocketAddr,
    child_ca: PathBuf,
    child: Arc<ProductRuntime>,
    parent: Arc<ProductRuntime>,
    origin: JoinHandle<WebSocketFrame>,
}

fn prebound_listener() -> (SocketAddr, StdTcpListener) {
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    (listener.local_addr().unwrap(), listener)
}

fn write_identity(directory: &Path, name: &str, dns_name: &str) -> TestIdentity {
    let tls = TestTlsIdentity::new(dns_name);
    let certificate_path = directory.join(format!("{name}-cert.pem"));
    let private_key_path = directory.join(format!("{name}-key.pem"));
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

fn tls_connector(certificate_path: &Path) -> TlsConnector {
    let pem = fs::read(certificate_path).unwrap();
    TlsConnector::from(Arc::new(client_config_for_pem_roots(&pem, &[b"http/1.1"])))
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
    fs::write(public_chain_path, pem).unwrap();
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
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
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
endpoint.kind = "tcp"
endpoint.address = "{bind}"
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
    protected: bool,
) -> String {
    let redaction = protected.then_some(
        r#"
[redaction.profiles.wire]
replacement = "[REDACTED]"
max_frame_bytes = 1024
max_message_bytes = 1024
rules = [{ literals = ["password"], payloads = "both" }]
"#,
    );
    let redaction_profile = if protected {
        "redaction_profile = \"wire\""
    } else {
        ""
    };
    format!(
        r#"schema_version = 3

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.transparent_https]
endpoint.kind = "tcp"
endpoint.address = "{bind}"
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
allow_upgrades = true
{redaction_profile}

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

async fn start_parent(
    directory: &Path,
    config: String,
    listener: StdTcpListener,
    origin: SocketAddr,
) -> Arc<ProductRuntime> {
    let bind = listener.local_addr().unwrap();
    let path = directory.join("acl-proxy.toml");
    fs::write(&path, config).unwrap();
    let loaded = load_and_compile_exact_config(&path).unwrap();
    let facts = ForwardingNetworkFacts::new(vec![bind], None, None, None).unwrap();
    let origin_url =
        canonicalize_http_url(&format!("https://{ORIGIN_HOST}:{}/", origin.port())).unwrap();
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
    product.start_listeners().await.unwrap();
    product
}

async fn start_child(
    directory: &Path,
    config: String,
    listener: StdTcpListener,
    parent: SocketAddr,
    origin: SocketAddr,
) -> Arc<ProductRuntime> {
    let bind = listener.local_addr().unwrap();
    let path = directory.join("acl-proxy.toml");
    fs::write(&path, config).unwrap();
    let loaded = load_and_compile_exact_config(&path).unwrap();
    let facts = ForwardingNetworkFacts::new(vec![bind], None, None, None).unwrap();
    let parent_url =
        canonicalize_http_url(&format!("https://{PARENT_HOST}:{}/", parent.port())).unwrap();
    let network = Arc::new(
        ForwardingDevHarness::new(facts)
            .map_local_parent(&parent_url, parent)
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
    product
        .start_listeners_with_original_destination(Arc::new(FixedOriginalDestination(origin)))
        .await
        .unwrap();
    product
}

async fn topology(protected: bool) -> ParentTopology {
    let root = tempdir().unwrap();
    let origin_directory = root.path().join("origin");
    let parent_directory = root.path().join("parent");
    let child_directory = root.path().join("child");
    fs::create_dir_all(&origin_directory).unwrap();
    fs::create_dir_all(&parent_directory).unwrap();
    fs::create_dir_all(&child_directory).unwrap();

    let origin_identity = write_identity(&origin_directory, "origin", ORIGIN_HOST);
    let parent_identity = write_identity(&parent_directory, "parent", PARENT_HOST);
    let (origin_address, origin) = spawn_websocket_origin(&origin_identity).await;
    let parent_mitm_ca = parent_directory.join("parent-mitm-ca.pem");
    initialize_generated_ca(&parent_directory.join("mitm"), &parent_mitm_ca);
    let (parent_address, parent_listener) = prebound_listener();
    let parent = start_parent(
        &parent_directory,
        parent_config(
            parent_address,
            &parent_identity,
            origin_address,
            &origin_identity.certificate_path,
        ),
        parent_listener,
        origin_address,
    )
    .await;

    let child_ca = child_directory.join("child-mitm-ca.pem");
    initialize_generated_ca(&child_directory.join("mitm"), &child_ca);
    let (child_address, child_listener) = prebound_listener();
    let child = start_child(
        &child_directory,
        child_config(
            child_address,
            parent_address,
            &parent_identity,
            &parent_mitm_ca,
            origin_address,
            protected,
        ),
        child_listener,
        parent_address,
        origin_address,
    )
    .await;

    ParentTopology {
        _root: root,
        child_address,
        parent_address,
        origin_address,
        child_ca,
        child,
        parent,
        origin,
    }
}

pub(super) async fn exercise_parent_websocket(protected: bool) {
    let topology = topology(protected).await;
    assert_eq!(topology.child.forwarding_terminal_completions_for_test(), 0);
    assert_eq!(
        topology.parent.forwarding_terminal_completions_for_test(),
        0
    );
    let connector = tls_connector(&topology.child_ca);
    let stream = tokio::net::TcpStream::connect(topology.child_address)
        .await
        .unwrap();
    let mut stream = connector
        .connect(ServerName::try_from(ORIGIN_HOST).unwrap(), stream)
        .await
        .unwrap();
    stream
        .write_all(
            format!(
                "GET /socket HTTP/1.1\r\nHost: {ORIGIN_HOST}:{}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                topology.origin_address.port()
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
    let seen = topology.origin.await.unwrap();
    drop(stream);

    topology.child.shutdown().await;
    topology.parent.shutdown().await;

    assert_eq!(seen.opcode, 0x1);
    assert_eq!(
        seen.payload,
        if protected {
            b"client [REDACTED]".as_slice()
        } else {
            b"client password".as_slice()
        }
    );
    assert_eq!(reply.opcode, 0x1);
    assert_eq!(reply.payload, b"server password");
    assert_eq!(topology.child.forwarding_terminal_completions_for_test(), 1);
    assert_eq!(
        topology.parent.forwarding_terminal_completions_for_test(),
        1
    );
    assert!(topology.child.shutdown_diagnostic().is_none());
    assert!(topology.parent.shutdown_diagnostic().is_none());
    let child_rebound = StdTcpListener::bind(topology.child_address).unwrap();
    let parent_rebound = StdTcpListener::bind(topology.parent_address).unwrap();
    drop((child_rebound, parent_rebound));
}

#[tokio::test]
async fn unprotected_websocket_relays_through_https_acl_proxy_parent() {
    let _test = super::super::super::LISTENER_TEST_LOCK.lock().await;
    exercise_parent_websocket(false).await;
}

#[tokio::test]
async fn protected_websocket_redacts_client_message_through_https_acl_proxy_parent() {
    let _test = super::super::super::LISTENER_TEST_LOCK.lock().await;
    exercise_parent_websocket(true).await;
}

fn deterministic_telemetry_body(entropy_bytes: usize, repeated_bytes: usize) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut state = 0x0123_4567_89ab_cdef_u64;
    let entropy = (0..entropy_bytes).map(|_| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        ALPHABET[usize::try_from(state & 63).unwrap()]
    });
    b"{\"entropy\":\""
        .iter()
        .copied()
        .chain(entropy)
        .chain(b"\",\"telemetry\":\"".iter().copied())
        .chain(std::iter::repeat_n(b'a', repeated_bytes))
        .chain(b"\",\"secret\":\"synthetic-safe-literal\"}".iter().copied())
        .collect()
}

fn gzip_body(body: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    std::io::Write::write_all(&mut encoder, body).unwrap();
    encoder.finish().unwrap()
}

#[tokio::test]
async fn production_compressed_telemetry_body_compatibility() {
    let _test = super::super::super::LISTENER_TEST_LOCK.lock().await;
    let production_fixture: toml::Value = toml::from_str(include_str!(
        "../../tests/fixtures/production/host-proxy-tcp.toml"
    ))
    .unwrap();
    let telemetry_rule = production_fixture["policy"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["id"].as_str() == Some("prod-host-r13-telemetry"))
        .unwrap();
    assert_eq!(
        telemetry_rule["redaction_profile"].as_str(),
        Some("sensitive_strings")
    );
    assert_eq!(
        telemetry_rule["urls"].as_array().unwrap(),
        &[
            toml::Value::String("https://statsig.anthropic.com/**".to_owned()),
            toml::Value::String("https://**.sentry.io/**".to_owned()),
            toml::Value::String("https://**.datadoghq.com/**".to_owned()),
        ]
    );
    let production_profile = &production_fixture["redaction"]["profiles"]["sensitive_strings"];
    assert_eq!(
        production_profile["max_body_bytes"].as_integer(),
        Some(10_485_760)
    );
    assert_eq!(
        production_profile["max_decoded_body_bytes"].as_integer(),
        Some(52_428_800)
    );

    let root = tempdir().unwrap();
    let origin_directory = root.path().join("origin");
    let product_directory = root.path().join("product");
    fs::create_dir_all(&origin_directory).unwrap();
    fs::create_dir_all(&product_directory).unwrap();
    let origin_identity = write_identity(&origin_directory, "origin", "ingest.sentry.io");
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin_address = origin_listener.local_addr().unwrap();
    let origin_acceptor = tls_acceptor(&origin_identity);
    let origin_task = tokio::spawn(async move {
        let (stream, _) = origin_listener.accept().await.unwrap();
        let mut stream = origin_acceptor.accept(stream).await.unwrap();
        let request = read_http_message(&mut stream).await;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\nConnection: close\r\n\r\naccepted telemetry",
            )
            .await
            .unwrap();
        request
    });

    let product_ca = product_directory.join("product-mitm-ca.pem");
    initialize_generated_ca(&product_directory.join("mitm"), &product_ca);
    let (proxy, listener) = prebound_listener();
    let config_path = product_directory.join("acl-proxy.toml");
    let config = format!(
        r#"schema_version = 3

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"
max_content_decoding_expansion_ratio = 128

[listeners.transparent_https]
endpoint.kind = "tcp"
endpoint.address = "{proxy}"
http_versions = ["http1"]
handshake_timeout = "1s"

[mitm]
mode = "generated"
directory = "mitm"

[egress]
route = "direct"

[egress.origin_tls]
trust = "custom"
ca_certificate = "{}"
http_versions = ["http1"]

[authorization.providers.telemetry]
kind = "process"
command = "/usr/bin/python3"
args = ["-u", "-c", '''
import json, sys
for line in sys.stdin:
    request = json.loads(line)
    body = request.get("body")
    allowed = body is not None and body.get("encoding") == "base64" and len(body.get("data", "")) > 1000000
    print(json.dumps({{"id": request["id"], "type": "response", "decision": "allow" if allowed else "deny"}}, separators=(",", ":")), flush=True)
''']
timeout = "2s"
on_failure = "deny"
inherit_environment = false
environment = {{ PATH = "/usr/bin:/bin" }}
include_request_body = true
allow_request_body_replacement = false
max_request_body_bytes = 10485760
max_decoded_request_body_bytes = 52428800
max_stdout_line_bytes = 4096
max_pending_requests = 8
restart_backoff = "100ms"
retire_timeout = "6s"

[redaction.profiles.sensitive_strings]
replacement = "[REDACTED]"
max_body_bytes = 10485760
max_decoded_body_bytes = 52428800
max_frame_bytes = 262144
max_message_bytes = 1048576
allow_permessage_deflate = false
max_environment_literal_sources = 64
max_environment_literal_bytes = 65536
max_environment_literal_total_bytes = 1048576
rules = [{{ literals = ["synthetic-safe-literal"], payloads = "text" }}]

[policy]
default = "deny"

[[policy.rules]]
id = "prod-host-r13-telemetry"
decision = "delegate"
urls = ["https://statsig.anthropic.com/**", "https://**.sentry.io/**", "https://**.datadoghq.com/**"]
methods = ["POST"]
authorization_provider = "telemetry"
redaction_profile = "sensitive_strings"
"#,
        origin_identity.certificate_path.display(),
    );
    fs::write(&config_path, config).unwrap();
    let loaded = load_and_compile_exact_config(&config_path).unwrap();
    let facts = ForwardingNetworkFacts::new(vec![proxy], None, None, None).unwrap();
    let origin_url = canonicalize_http_url("https://ingest.sentry.io/").unwrap();
    let network = Arc::new(
        ForwardingDevHarness::new(facts)
            .map_prebound(&origin_url, origin_address)
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
    product
        .start_listeners_with_original_destination(Arc::new(FixedOriginalDestination(
            SocketAddr::from(([127, 0, 0, 1], 443)),
        )))
        .await
        .unwrap();

    let telemetry = deterministic_telemetry_body(16_000, 1_200_000);
    let encoded = gzip_body(&telemetry);
    assert!(telemetry.len() > 1024 * 1024);
    assert!(telemetry.len() > 64 * encoded.len());
    assert!(telemetry.len() <= 128 * encoded.len());
    let connector = tls_connector(&product_ca);
    let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let mut stream = connector
        .connect(ServerName::try_from("ingest.sentry.io").unwrap(), stream)
        .await
        .unwrap();
    stream
        .write_all(
            format!(
                "POST /api/telemetry HTTP/1.1\r\nHost: ingest.sentry.io\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                encoded.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    stream.write_all(&encoded).await.unwrap();
    let response = read_http_message(&mut stream).await;
    assert!(response.starts_with(b"HTTP/1.1 200 "));
    assert!(response.ends_with(b"\r\n\r\naccepted telemetry"));

    let request = origin_task.await.unwrap();
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let head = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
    let expected = String::from_utf8(telemetry)
        .unwrap()
        .replace("synthetic-safe-literal", "[REDACTED]");
    assert_eq!(&request[header_end..], expected.as_bytes());
    assert!(!head.contains("\r\ncontent-encoding:"));
    assert!(head.contains(&format!("\r\ncontent-length: {}\r\n", expected.len())));
    assert!(head.contains("\r\ncontent-type: application/json\r\n"));

    product.shutdown().await;
    assert_eq!(product.wire_body_pool().global_charge(), 0);
    assert_eq!(product.forwarding_terminal_completions_for_test(), 1);
    let rebound = StdTcpListener::bind(proxy).unwrap();
    drop(rebound);
}
