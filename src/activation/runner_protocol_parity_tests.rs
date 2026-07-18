use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode, Version};
use http_access_mitm::{GeneratedCertificateAuthority, PrivateStorageRoot};
use http_access_runtime::{
    ForwardingDevHarness, ForwardingNetworkFacts, OriginalDestinationProvider,
};
use rcgen::{CertificateParams, KeyPair};
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig, ServerName};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::*;

trait ParityIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> ParityIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

struct TestIdentity {
    _directory: TempDir,
    certificate_path: std::path::PathBuf,
    private_key_path: std::path::PathBuf,
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
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

fn prebound_listener() -> (SocketAddr, StdTcpListener) {
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    (listener.local_addr().unwrap(), listener)
}

fn test_identity(dns_name: &str) -> TestIdentity {
    let directory = tempdir().unwrap();
    let key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(vec![dns_name.to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let certificate_path = directory.path().join("server.pem");
    let private_key_path = directory.path().join("server-key.pem");
    fs::write(&certificate_path, certificate.pem()).unwrap();
    crate::filesystem::write_private_file(&private_key_path, key.serialize_pem()).unwrap();
    TestIdentity {
        _directory: directory,
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

fn tls_connector(certificates: impl IntoIterator<Item = Vec<u8>>, alpn: &[u8]) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots.add(&Certificate(certificate)).unwrap();
    }
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
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

fn base_config(bind: SocketAddr, table: &str, versions: &str, extra: &str) -> String {
    format!(
        r#"schema_version = 3

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.{table}]
bind = "{bind}"
http_versions = [{versions}]

[egress]
route = "direct"

[egress.origin_tls]
trust = "insecure"
http_versions = ["http1"]

[safety.loop_detection]
inject = true
header = "x-test-loop"

{extra}
"#
    )
}

async fn start_product(
    text: &str,
    listener: StdTcpListener,
    mapping: Option<(&str, SocketAddr)>,
    original_destination: Option<SocketAddr>,
) -> (TempDir, Arc<ProductRuntime>) {
    let bind = listener.local_addr().unwrap();
    let (directory, loaded) = loaded(text);
    let product = if let Some((url, address)) = mapping {
        let facts = ForwardingNetworkFacts::new(vec![bind], None, None, None).unwrap();
        let url = http_access_url::canonicalize_http_url(url).unwrap();
        let network = Arc::new(
            ForwardingDevHarness::new(facts)
                .map_prebound(&url, address)
                .unwrap()
                .into_standalone_guard(),
        );
        ProductRuntime::prepare_from_prebound_with_forwarding_network(
            loaded,
            vec![listener],
            network,
        )
        .await
        .unwrap()
    } else {
        ProductRuntime::prepare_from_prebound(loaded, vec![listener])
            .await
            .unwrap()
    };
    product.activate_initial().await.unwrap();
    if let Some(destination) = original_destination {
        product
            .start_listeners_with_original_destination(Arc::new(FixedOriginalDestination(
                destination,
            )))
            .await
            .unwrap();
    } else {
        product.start_listeners().await.unwrap();
    }
    (directory, product)
}

async fn read_to_close(mut stream: impl AsyncRead + Unpin) -> Vec<u8> {
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
        .await
        .expect("HTTP peer did not close")
        .unwrap();
    bytes
}

async fn open_connect(proxy: SocketAddr, target: &str) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = read_http_message(&mut stream).await;
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "unexpected CONNECT response: {}",
        String::from_utf8_lossy(&head)
    );
    stream
}

async fn h2_client(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
) -> (
    h2::client::SendRequest<Bytes>,
    JoinHandle<Result<(), h2::Error>>,
) {
    let (sender, connection) = h2::client::handshake(stream).await.unwrap();
    (sender, tokio::spawn(connection))
}

async fn h2_request(
    sender: &mut h2::client::SendRequest<Bytes>,
    method: Method,
    uri: String,
    body: &[u8],
) -> Result<(StatusCode, Version, Vec<u8>), h2::Error> {
    sender.clone().ready().await?;
    let request = Request::builder()
        .method(method)
        .version(Version::HTTP_2)
        .uri(uri)
        .body(())
        .unwrap();
    let (response, mut stream) = sender.send_request(request, body.is_empty())?;
    if !body.is_empty() {
        stream.send_data(Bytes::copy_from_slice(body), true)?;
    }
    let response = response.await?;
    let status = response.status();
    let version = response.version();
    let mut output = Vec::new();
    let mut body = response.into_body();
    while let Some(chunk) = body.data().await {
        output.extend_from_slice(&chunk?);
    }
    Ok((status, version, output))
}

async fn collect_h2_response(
    response: h2::client::ResponseFuture,
) -> Result<(StatusCode, Version, Vec<u8>), h2::Error> {
    let response = response.await?;
    let status = response.status();
    let version = response.version();
    let mut output = Vec::new();
    let mut body = response.into_body();
    while let Some(chunk) = body.data().await {
        output.extend_from_slice(&chunk?);
    }
    Ok((status, version, output))
}

fn assert_http10_denial(response: &[u8], mode: &str) {
    assert!(
        response.starts_with(b"HTTP/1.0 403 ") || response.starts_with(b"HTTP/1.1 403 "),
        "unexpected {mode} response: {}",
        String::from_utf8_lossy(response)
    );
    assert!(response.ends_with(b"request denied\n"), "{mode}");
}

fn assert_origin_host(request: &[u8], origin: SocketAddr) {
    let request = String::from_utf8_lossy(request).to_ascii_lowercase();
    assert!(
        request.contains(&format!("\r\nhost: {origin}\r\n")),
        "forwarded request omitted the canonical origin authority: {request}"
    );
}

#[tokio::test]
async fn http10_requests_reach_policy_in_all_five_ingress_modes() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;

    let (proxy, listener) = prebound_listener();
    let text = base_config(
        proxy,
        "explicit_http",
        "\"http1\"",
        "[listeners.explicit_http.connect]\nhttp1 = \"deny\"\n\n[policy]\ndefault = \"deny\"",
    );
    let (_directory, product) = start_product(&text, listener, None, None).await;
    let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
    client.write_all(b"GET http://explicit.test/denied HTTP/1.0\r\nHost: explicit.test\r\nConnection: close\r\n\r\n").await.unwrap();
    assert_http10_denial(&read_to_close(client).await, "explicit HTTP");
    product.shutdown().await;

    let (proxy, listener) = prebound_listener();
    let destination = SocketAddr::from(([198, 51, 100, 17], 8080));
    let text = base_config(
        proxy,
        "transparent_http",
        "\"http1\"",
        "[policy]\ndefault = \"deny\"",
    );
    let (_directory, product) = start_product(&text, listener, None, Some(destination)).await;
    let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"GET /denied HTTP/1.0\r\nHost: transparent.test:8080\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    assert_http10_denial(&read_to_close(client).await, "transparent HTTP");
    product.shutdown().await;

    let identity = test_identity("localhost");
    let (proxy, listener) = prebound_listener();
    let extra = format!(
        "[listeners.explicit_https.connect]\nhttp1 = \"deny\"\n\n[listeners.explicit_https.tls]\ncertificate_chain = {:?}\nprivate_key = {:?}\n\n[policy]\ndefault = \"deny\"",
        identity.certificate_path, identity.private_key_path
    );
    let text = base_config(proxy, "explicit_https", "\"http1\"", &extra);
    let (_directory, product) = start_product(&text, listener, None, None).await;
    let connector = tls_connector([identity.certificate_der.clone()], b"http/1.1");
    let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let mut stream = connector
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    stream.write_all(b"GET https://explicit.test/denied HTTP/1.0\r\nHost: explicit.test\r\nConnection: close\r\n\r\n").await.unwrap();
    assert_http10_denial(&read_to_close(stream).await, "explicit HTTPS");
    product.shutdown().await;

    let (proxy, listener) = prebound_listener();
    let destination = SocketAddr::from(([198, 51, 100, 17], 8443));
    let text = base_config(
        proxy,
        "transparent_https",
        "\"http1\"",
        "[mitm]\nmode = \"generated\"\ndirectory = \"mitm\"\n\n[policy]\ndefault = \"deny\"",
    );
    let (directory, loaded_config) = loaded(&text);
    let ca = initialize_generated_ca(&directory.path().join("mitm"));
    let product = ProductRuntime::prepare_from_prebound(loaded_config, vec![listener])
        .await
        .unwrap();
    product.activate_initial().await.unwrap();
    product
        .start_listeners_with_original_destination(Arc::new(FixedOriginalDestination(destination)))
        .await
        .unwrap();
    let connector = tls_connector(ca, b"http/1.1");
    let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let mut stream = connector
        .connect(ServerName::try_from("transparent.test").unwrap(), stream)
        .await
        .unwrap();
    stream
        .write_all(
            b"GET /denied HTTP/1.0\r\nHost: transparent.test:8443\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    assert_http10_denial(&read_to_close(stream).await, "transparent HTTPS");
    product.shutdown().await;

    let (proxy, listener) = prebound_listener();
    let target = "192.0.2.10:443";
    let extra = format!(
        "[listeners.explicit_http.connect]\nhttp1 = \"mitm\"\n\n[mitm]\nmode = \"generated\"\ndirectory = \"mitm\"\n\n[policy]\ndefault = \"deny\"\n\n[[policy.rules]]\nid = \"connect\"\ndecision = \"allow\"\nmethods = [\"CONNECT\"]\nurls = [\"https://{target}/**\"]"
    );
    let text = base_config(proxy, "explicit_http", "\"http1\"", &extra);
    let (directory, loaded_config) = loaded(&text);
    let ca = initialize_generated_ca(&directory.path().join("mitm"));
    let product = ProductRuntime::prepare_from_prebound(loaded_config, vec![listener])
        .await
        .unwrap();
    product.activate_initial().await.unwrap();
    product.start_listeners().await.unwrap();
    let outer = open_connect(proxy, target).await;
    let connector = tls_connector(ca, b"http/1.1");
    let mut inner = connector
        .connect(ServerName::try_from("192.0.2.10").unwrap(), outer)
        .await
        .unwrap();
    inner
        .write_all(b"GET /denied HTTP/1.0\r\nHost: 192.0.2.10\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    assert_http10_denial(&read_to_close(inner).await, "CONNECT MITM inner");
    product.shutdown().await;
}

#[tokio::test]
async fn cleartext_h2_idle_connection_releases_admission_for_waiting_client() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = prebound_listener();
    let extra =
        "[listeners.explicit_http.connect]\nhttp2 = \"deny\"\n\n[policy]\ndefault = \"deny\"";
    let text = base_config(proxy, "explicit_http", "\"http2\"", extra).replacen(
        "[listeners.explicit_http]",
        "[listeners.explicit_http]\nrequest_header_timeout = \"250ms\"\nmax_connections = 1\nmax_concurrent_streams = 1",
        1,
    );
    let (_directory, product) = start_product(&text, listener, None, None).await;

    let mut idle = tokio::net::TcpStream::connect(proxy).await.unwrap();
    idle.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        .await
        .unwrap();
    let mut settings = [0_u8; 9];
    tokio::time::timeout(Duration::from_secs(1), idle.read_exact(&mut settings))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(settings[3], 0x04);
    let length =
        usize::from(settings[0]) << 16 | usize::from(settings[1]) << 8 | usize::from(settings[2]);
    let mut payload = vec![0; length];
    idle.read_exact(&mut payload).await.unwrap();
    idle.write_all(b"\x00\x00\x00\x04\x01\x00\x00\x00\x00")
        .await
        .unwrap();

    let waiting = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let (mut sender, driver) = h2_client(waiting).await;
    let (status, _, _) = {
        let response = h2_request(
            &mut sender,
            Method::GET,
            format!("http://{proxy}/self"),
            b"",
        );
        tokio::pin!(response);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), response.as_mut())
                .await
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(3), response.as_mut())
            .await
            .unwrap()
            .unwrap()
    };
    assert_eq!(status, StatusCode::FORBIDDEN);
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), idle.read_to_end(&mut tail))
        .await
        .unwrap()
        .unwrap();
    drop(sender);
    product.shutdown().await;
    driver.await.unwrap().unwrap();
}

#[tokio::test]
async fn cleartext_connection_admission_and_h1_head_deadline_are_bounded() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = prebound_listener();
    let extra =
        "[listeners.explicit_http.connect]\nhttp1 = \"deny\"\n\n[policy]\ndefault = \"deny\"";
    let text = base_config(proxy, "explicit_http", "\"http1\"", extra).replacen(
        "[listeners.explicit_http]",
        "[listeners.explicit_http]\nrequest_header_timeout = \"100ms\"\nmax_connections = 1\nmax_concurrent_streams = 1",
        1,
    );
    let (_directory, product) = start_product(&text, listener, None, None).await;
    let mut first = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let mut second = tokio::net::TcpStream::connect(proxy).await.unwrap();
    second
        .write_all(
            format!(
                "GET http://{proxy}/self HTTP/1.1\r\nHost: {proxy}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), second.read(&mut byte))
            .await
            .is_err()
    );
    let mut first_tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), first.read_to_end(&mut first_tail))
        .await
        .unwrap()
        .unwrap();
    let response = read_to_close(second).await;
    assert!(response.starts_with(b"HTTP/1.1 403"));
    product.shutdown().await;
}

#[tokio::test]
async fn cleartext_h2_prior_knowledge_translation_and_stream_local_body_failure() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin_listener.accept().await.unwrap();
        let request = read_http_message(&mut stream).await;
        assert!(request.starts_with(b"GET /sibling HTTP/1.1\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nh2 accepted",
            )
            .await
            .unwrap();
        request
    });
    let (proxy, listener) = prebound_listener();
    let extra = format!(
        r#"[listeners.explicit_http.connect]
http2 = "deny"

[redaction.profiles.wire]
max_body_bytes = 8
max_decoded_body_bytes = 8
rules = [{{ literals = ["marker"], payloads = "text" }}]

[policy]
default = "allow"

[[policy.rules]]
id = "bounded-h2-body"
decision = "allow"
urls = ["http://{origin}/**"]
methods = ["POST"]
redaction_profile = "wire"
"#
    );
    let text = base_config(proxy, "explicit_http", "\"http2\"", &extra);
    let mapping = format!("http://{origin}/");
    let (_directory, product) =
        start_product(&text, listener, Some((&mapping, origin)), None).await;
    let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let (mut sender, driver) = h2_client(stream).await;

    let rejected = h2_request(
        &mut sender,
        Method::POST,
        format!("http://{origin}/too-large"),
        b"0123456789abcdef",
    )
    .await;
    match rejected {
        Ok((status, _, body)) => {
            assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
            assert_eq!(body, b"request body denied\n");
        }
        Err(error) => assert!(error.is_reset(), "unexpected H2 body failure: {error}"),
    }

    let (status, version, body) = h2_request(
        &mut sender,
        Method::GET,
        format!("http://{origin}/sibling"),
        b"",
    )
    .await
    .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(version, Version::HTTP_2);
    assert_eq!(body, b"h2 accepted");
    let origin_request = origin_task.await.unwrap();
    assert_origin_host(&origin_request, origin);

    drop(sender);
    product.shutdown().await;
    driver.await.unwrap().unwrap();
}

#[tokio::test]
async fn transparent_http_h2_prior_knowledge_forwards_canonical_origin_request() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin_listener.accept().await.unwrap();
        let request = read_http_message(&mut stream).await;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 23\r\nConnection: close\r\n\r\ntransparent h2 accepted",
            )
            .await
            .unwrap();
        request
    });
    let (proxy, listener) = prebound_listener();
    let extra = format!(
        r#"[policy]
default = "deny"

[[policy.rules]]
id = "transparent-h2"
decision = "allow"
urls = ["http://{origin}/transparent-h2?mode=one"]
methods = ["GET"]
"#
    );
    let text = base_config(proxy, "transparent_http", "\"http2\"", &extra);
    let mapping = format!("http://{origin}/");
    let (_directory, product) =
        start_product(&text, listener, Some((&mapping, origin)), Some(origin)).await;
    let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let (mut sender, driver) = h2_client(stream).await;
    let (status, version, body) = h2_request(
        &mut sender,
        Method::GET,
        format!("http://{origin}/transparent-h2?mode=one"),
        b"",
    )
    .await
    .unwrap();
    assert_eq!((status, version), (StatusCode::OK, Version::HTTP_2));
    assert_eq!(body, b"transparent h2 accepted");
    let origin_request = String::from_utf8(origin_task.await.unwrap()).unwrap();
    assert!(origin_request.starts_with("GET /transparent-h2?mode=one HTTP/1.1\r\n"));
    assert_origin_host(origin_request.as_bytes(), origin);
    drop(sender);
    product.shutdown().await;
    driver.await.unwrap().unwrap();
}

#[tokio::test]
async fn explicit_https_negotiates_http2_and_serves_an_http2_request() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let identity = test_identity("localhost");
    let (proxy, listener) = prebound_listener();
    let extra = format!(
        "[listeners.explicit_https.connect]\nhttp2 = \"deny\"\n\n[listeners.explicit_https.tls]\ncertificate_chain = {:?}\nprivate_key = {:?}\n\n[policy]\ndefault = \"deny\"",
        identity.certificate_path, identity.private_key_path
    );
    let text = base_config(proxy, "explicit_https", "\"http2\"", &extra);
    let (_directory, product) = start_product(&text, listener, None, None).await;
    let connector = tls_connector([identity.certificate_der.clone()], b"h2");
    let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let stream = connector
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, driver) = h2_client(stream).await;
    let (status, version, body) = h2_request(
        &mut sender,
        Method::GET,
        "https://example.test/denied".to_owned(),
        b"",
    )
    .await
    .unwrap();
    assert_eq!((status, version), (StatusCode::FORBIDDEN, Version::HTTP_2));
    assert_eq!(body, b"request denied\n");
    drop(sender);
    product.shutdown().await;
    driver.await.unwrap().unwrap();
}

#[tokio::test]
async fn transparent_https_negotiates_http2_and_serves_an_http2_request() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = prebound_listener();
    let destination = SocketAddr::from(([198, 51, 100, 17], 443));
    let text = base_config(
        proxy,
        "transparent_https",
        "\"http2\"",
        "[mitm]\nmode = \"generated\"\ndirectory = \"mitm\"\n\n[policy]\ndefault = \"deny\"",
    );
    let (directory, loaded) = loaded(&text);
    let ca = initialize_generated_ca(&directory.path().join("mitm"));
    let product = ProductRuntime::prepare_from_prebound(loaded, vec![listener])
        .await
        .unwrap();
    product.activate_initial().await.unwrap();
    product
        .start_listeners_with_original_destination(Arc::new(FixedOriginalDestination(destination)))
        .await
        .unwrap();
    let connector = tls_connector(ca, b"h2");
    let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let stream = connector
        .connect(ServerName::try_from("transparent.test").unwrap(), stream)
        .await
        .unwrap();
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, driver) = h2_client(stream).await;
    let (status, version, body) = h2_request(
        &mut sender,
        Method::GET,
        "https://transparent.test/denied".to_owned(),
        b"",
    )
    .await
    .unwrap();
    assert_eq!((status, version), (StatusCode::FORBIDDEN, Version::HTTP_2));
    assert_eq!(body, b"request denied\n");
    drop(sender);
    product.shutdown().await;
    driver.await.unwrap().unwrap();
}

#[tokio::test]
async fn concurrent_http2_streams_keep_mixed_allow_and_deny_decisions_isolated() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let origin_identity = test_identity("localhost");
    let origin_acceptor = tls_acceptor(&origin_identity);
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (stream, _) = origin_listener.accept().await.unwrap();
        let mut stream = origin_acceptor.accept(stream).await.unwrap();
        let request = read_http_message(&mut stream).await;
        assert!(request.starts_with(b"GET /ok HTTP/1.1\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nallowed stream",
            )
            .await
            .unwrap();
    });
    let (proxy, listener) = prebound_listener();
    let extra = format!(
        r#"[mitm]
mode = "generated"
directory = "mitm"

[policy]
default = "deny"

[[policy.rules]]
id = "allowed-stream"
decision = "allow"
urls = ["https://localhost:{}/ok"]
methods = ["GET"]
"#,
        origin.port()
    );
    let text = base_config(proxy, "transparent_https", "\"http2\"", &extra).replacen(
        "[listeners.transparent_https]",
        "[listeners.transparent_https]\nmax_concurrent_streams = 8",
        1,
    );
    let (directory, loaded) = loaded(&text);
    let ca = initialize_generated_ca(&directory.path().join("mitm"));
    let facts = ForwardingNetworkFacts::new(vec![proxy], None, None, None).unwrap();
    let origin_url =
        http_access_url::canonicalize_http_url(&format!("https://localhost:{}/", origin.port()))
            .unwrap();
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
    product
        .start_listeners_with_original_destination(Arc::new(FixedOriginalDestination(origin)))
        .await
        .unwrap();
    let connector = tls_connector(ca, b"h2");
    let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let stream = connector
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    let (mut sender, driver) = h2_client(stream).await;

    sender.clone().ready().await.unwrap();
    let allowed = sender
        .send_request(
            Request::builder()
                .method(Method::GET)
                .version(Version::HTTP_2)
                .uri(format!("https://localhost:{}/ok", origin.port()))
                .body(())
                .unwrap(),
            true,
        )
        .unwrap()
        .0;
    sender.clone().ready().await.unwrap();
    let denied = sender
        .send_request(
            Request::builder()
                .method(Method::GET)
                .version(Version::HTTP_2)
                .uri(format!("https://localhost:{}/denied", origin.port()))
                .body(())
                .unwrap(),
            true,
        )
        .unwrap()
        .0;
    let (allowed, denied) = tokio::join!(collect_h2_response(allowed), collect_h2_response(denied));
    let (allowed_status, _, allowed_body) = allowed.unwrap();
    let (denied_status, _, denied_body) = denied.unwrap();
    assert_eq!(allowed_status, StatusCode::OK);
    assert_eq!(allowed_body, b"allowed stream");
    assert_eq!(denied_status, StatusCode::FORBIDDEN);
    assert_eq!(denied_body, b"request denied\n");

    origin_task.await.unwrap();
    drop(sender);
    product.shutdown().await;
    driver.await.unwrap().ok();
}

#[tokio::test]
async fn explicit_https_ordinary_forwarding_succeeds_over_http1_and_http2() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    for (listener_version, alpn) in [
        ("http1", b"http/1.1".as_slice()),
        ("http2", b"h2".as_slice()),
    ] {
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 23\r\nConnection: close\r\n\r\nexplicit https accepted",
                )
                .await
                .unwrap();
            request
        });
        let identity = test_identity("localhost");
        let (proxy, listener) = prebound_listener();
        let extra = format!(
            r#"[listeners.explicit_https.connect]
{listener_version} = "deny"

[listeners.explicit_https.tls]
certificate_chain = {:?}
private_key = {:?}

[policy]
default = "deny"

[[policy.rules]]
id = "explicit-https-ordinary-{listener_version}"
decision = "allow"
urls = ["http://{origin}/**"]
methods = ["GET"]
"#,
            identity.certificate_path, identity.private_key_path
        );
        let text = base_config(
            proxy,
            "explicit_https",
            &format!("\"{listener_version}\""),
            &extra,
        );
        let mapping = format!("http://{origin}/");
        let (_directory, product) =
            start_product(&text, listener, Some((&mapping, origin)), None).await;
        let connector = tls_connector([identity.certificate_der.clone()], alpn);
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let mut stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(alpn));
        let target = format!("http://{origin}/ordinary?ingress={listener_version}");
        if listener_version == "http1" {
            stream
                .write_all(
                    format!("GET {target} HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            let response = read_to_close(stream).await;
            assert!(response.starts_with(b"HTTP/1.1 200"));
            assert!(response.ends_with(b"explicit https accepted"));
        } else {
            let (mut sender, driver) = h2_client(stream).await;
            let (status, version, body) = h2_request(&mut sender, Method::GET, target, b"")
                .await
                .unwrap();
            assert_eq!((status, version), (StatusCode::OK, Version::HTTP_2));
            assert_eq!(body, b"explicit https accepted");
            drop(sender);
            driver.await.unwrap().unwrap();
        }
        let request = String::from_utf8(origin_task.await.unwrap()).unwrap();
        assert!(request.starts_with(&format!(
            "GET /ordinary?ingress={listener_version} HTTP/1.1\r\n"
        )));
        assert_origin_host(request.as_bytes(), origin);
        product.shutdown().await;
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
enum ProviderIngressCase {
    ExplicitHttp,
    ExplicitHttps,
    TransparentHttp,
    ConnectMitmInner,
    TransparentHttps,
}

#[cfg(unix)]
fn provider_policy(target: &str, marker: &Path) -> String {
    format!(
        r#"[authorization.providers.parity]
kind = "process"
command = "/usr/bin/python3"
args = ["-u", "-c", '''
import json, sys
marker = {marker:?}
for line in sys.stdin:
    request = json.loads(line)
    with open(marker, "a", encoding="utf-8") as output:
        output.write(request["url"] + "\n")
        output.flush()
    print(json.dumps({{"id": request["id"], "type": "response", "decision": "allow", "values": {{"token": "typed-secret"}}}}, separators=(",", ":")), flush=True)
''']
timeout = "2s"
retire_timeout = "6s"
on_failure = "error"
inherit_environment = false
environment = {{ PATH = "/usr/bin:/bin" }}
include_request_body = false
max_request_body_bytes = 1024
max_decoded_request_body_bytes = 1024
max_stdout_line_bytes = 4096

[authorization.providers.parity.outputs.token]
kind = "bearer"
required = true

[policy]
default = "deny"

[[policy.rules]]
id = "provider-parity"
decision = "delegate"
urls = ["{target}"]
methods = ["GET"]
authorization_provider = "parity"
"#,
        marker = marker.display().to_string(),
    )
}

#[cfg(unix)]
#[tokio::test]
async fn http2_process_provider_equivalence_covers_all_five_ingress_modes() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    for case in [
        ProviderIngressCase::ExplicitHttp,
        ProviderIngressCase::ExplicitHttps,
        ProviderIngressCase::TransparentHttp,
        ProviderIngressCase::ConnectMitmInner,
        ProviderIngressCase::TransparentHttps,
    ] {
        let tls_origin = matches!(
            case,
            ProviderIngressCase::ConnectMitmInner | ProviderIngressCase::TransparentHttps
        );
        let origin_identity = test_identity("localhost");
        let origin_acceptor = tls_origin.then(|| tls_acceptor(&origin_identity));
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            let request = if let Some(acceptor) = origin_acceptor {
                let mut stream = acceptor.accept(stream).await.unwrap();
                let request = read_http_message(&mut stream).await;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\nprovider accepted",
                    )
                    .await
                    .unwrap();
                request
            } else {
                let mut stream = stream;
                let request = read_http_message(&mut stream).await;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\nprovider accepted",
                    )
                    .await
                    .unwrap();
                request
            };
            captured_tx.send(request).ok();
        });

        let marker_directory = tempdir().unwrap();
        let marker = marker_directory.path().join("provider-calls");
        let scheme = if tls_origin { "https" } else { "http" };
        let target = format!("{scheme}://localhost:{}/provider", origin.port());
        let policy = provider_policy(&target, &marker);
        let incoming_identity = test_identity("localhost");
        let (proxy, listener) = prebound_listener();
        let (table, versions, mut extra) = match case {
            ProviderIngressCase::ExplicitHttp => (
                "explicit_http",
                "\"http2\"",
                format!(
                    "[listeners.explicit_http.connect]\nhttp2 = \"deny\"\n\n{policy}"
                ),
            ),
            ProviderIngressCase::ExplicitHttps => (
                "explicit_https",
                "\"http2\"",
                format!(
                    "[listeners.explicit_https.connect]\nhttp2 = \"deny\"\n\n[listeners.explicit_https.tls]\ncertificate_chain = {:?}\nprivate_key = {:?}\n\n{policy}",
                    incoming_identity.certificate_path, incoming_identity.private_key_path
                ),
            ),
            ProviderIngressCase::TransparentHttp => {
                ("transparent_http", "\"http2\"", policy)
            }
            ProviderIngressCase::ConnectMitmInner => (
                "explicit_http",
                "\"http1\", \"http2\"",
                format!(
                    "[listeners.explicit_http.connect]\nhttp1 = \"mitm\"\nhttp2 = \"deny\"\n\n[mitm]\nmode = \"generated\"\ndirectory = \"mitm\"\n\n[[policy.rules]]\nid = \"connect-provider-origin\"\ndecision = \"allow\"\nmethods = [\"CONNECT\"]\nurls = [\"https://localhost:{}/**\"]\n\n{policy}",
                    origin.port()
                ),
            ),
            ProviderIngressCase::TransparentHttps => (
                "transparent_https",
                "\"http2\"",
                format!("[mitm]\nmode = \"generated\"\ndirectory = \"mitm\"\n\n{policy}"),
            ),
        };
        if matches!(case, ProviderIngressCase::ExplicitHttps) {
            extra.push('\n');
        }
        let text = base_config(proxy, table, versions, &extra);
        let (directory, loaded) = loaded(&text);
        let generated_ca = matches!(
            case,
            ProviderIngressCase::ConnectMitmInner | ProviderIngressCase::TransparentHttps
        )
        .then(|| initialize_generated_ca(&directory.path().join("mitm")));
        let facts = ForwardingNetworkFacts::new(vec![proxy], None, None, None).unwrap();
        let origin_url = http_access_url::canonicalize_http_url(&format!(
            "{scheme}://localhost:{}/",
            origin.port()
        ))
        .unwrap();
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
            ProviderIngressCase::TransparentHttp | ProviderIngressCase::TransparentHttps
        ) {
            product
                .start_listeners_with_original_destination(Arc::new(FixedOriginalDestination(
                    origin,
                )))
                .await
                .unwrap();
        } else {
            product.start_listeners().await.unwrap();
        }

        let stream: Box<dyn ParityIo> = match case {
            ProviderIngressCase::ExplicitHttp | ProviderIngressCase::TransparentHttp => {
                Box::new(tokio::net::TcpStream::connect(proxy).await.unwrap())
            }
            ProviderIngressCase::ExplicitHttps => {
                let connector = tls_connector([incoming_identity.certificate_der.clone()], b"h2");
                let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
                Box::new(
                    connector
                        .connect(ServerName::try_from("localhost").unwrap(), stream)
                        .await
                        .unwrap(),
                )
            }
            ProviderIngressCase::TransparentHttps => {
                let connector = tls_connector(generated_ca.unwrap(), b"h2");
                let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
                Box::new(
                    connector
                        .connect(ServerName::try_from("localhost").unwrap(), stream)
                        .await
                        .unwrap(),
                )
            }
            ProviderIngressCase::ConnectMitmInner => {
                let outer = open_connect(proxy, &format!("localhost:{}", origin.port())).await;
                let connector = tls_connector(generated_ca.unwrap(), b"h2");
                Box::new(
                    connector
                        .connect(ServerName::try_from("localhost").unwrap(), outer)
                        .await
                        .unwrap(),
                )
            }
        };
        let (mut sender, driver) = h2_client(stream).await;
        let (status, version, body) = h2_request(&mut sender, Method::GET, target.clone(), b"")
            .await
            .unwrap();
        assert_eq!(
            (status, version),
            (StatusCode::OK, Version::HTTP_2),
            "{case:?}"
        );
        assert_eq!(body, b"provider accepted", "{case:?}");
        let origin_request = String::from_utf8(captured_rx.await.unwrap()).unwrap();
        assert!(
            origin_request
                .to_ascii_lowercase()
                .contains("\r\nauthorization: bearer typed-secret\r\n"),
            "{case:?}: {origin_request}"
        );
        let calls = fs::read_to_string(&marker).unwrap();
        assert_eq!(
            calls.lines().collect::<Vec<_>>(),
            [target.as_str()],
            "{case:?}"
        );

        drop(sender);
        product.shutdown().await;
        driver.await.unwrap().ok();
        origin_task.await.unwrap();
    }
}
