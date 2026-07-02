use std::io::Cursor;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use acl_proxy::app::AppState;
use acl_proxy::config::Config;
use acl_proxy::proxy::explicit_https::{
    build_static_tls_acceptor, run_explicit_https_proxy_on_listener,
};
use acl_proxy::proxy::http::run_http_proxy_on_listener;
use http::StatusCode;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::client::ServerName;
use rustls::{Certificate as RustlsCertificate, ClientConfig, RootCertStore};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

#[derive(Clone, Debug)]
struct SeenRequest {
    uri: String,
    headers: hyper::HeaderMap,
}

async fn start_http_echo_server(body: &'static str) -> (SocketAddr, Arc<Mutex<Vec<SeenRequest>>>) {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind upstream");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking upstream");
    let addr = listener.local_addr().expect("upstream addr");

    let seen_requests: Arc<Mutex<Vec<SeenRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_requests_clone = seen_requests.clone();

    let make_svc = make_service_fn(move |_conn| {
        let seen_requests = seen_requests_clone.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                let seen_requests = seen_requests.clone();
                async move {
                    seen_requests.lock().unwrap().push(SeenRequest {
                        uri: req.uri().to_string(),
                        headers: req.headers().clone(),
                    });
                    Ok::<_, hyper::Error>(Response::new(Body::from(body)))
                }
            }))
        }
    });

    tokio::spawn(
        Server::from_tcp(listener)
            .expect("server from tcp")
            .serve(make_svc),
    );

    (addr, seen_requests)
}

fn write_proxy_identity(temp_dir: &TempDir) -> (PathBuf, PathBuf) {
    let mut params = CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "127.0.0.1");
    params.distinguished_name = dn;

    let key = KeyPair::generate().expect("generate proxy key");
    let cert = params.self_signed(&key).expect("self-signed proxy cert");

    let cert_path = temp_dir.path().join("proxy-cert.pem");
    let key_path = temp_dir.path().join("proxy-key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write proxy cert");
    std::fs::write(&key_path, key.serialize_pem()).expect("write proxy key");

    (cert_path, key_path)
}

fn explicit_https_config(cert_path: &Path, key_path: &Path, allow_pattern: &str) -> Config {
    let toml = format!(
        r#"
schema_version = "1"

[proxy]
listeners.explicit_https.bind = "127.0.0.1:1"
listeners.explicit_https.cert_chain_path = {cert_path:?}
listeners.explicit_https.key_path = {key_path:?}

[logging]
level = "info"

[capture]
allowed_request = false
allowed_response = false
denied_request = false
denied_response = false
directory = "logs-capture"

[tls]
verify_upstream = false

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = {allow_pattern:?}
"#,
        cert_path = cert_path.display().to_string(),
        key_path = key_path.display().to_string(),
    );

    toml::from_str(&toml).expect("parse explicit https config")
}

fn explicit_http_config_with_https_parent(
    parent_addr: SocketAddr,
    ca_cert_path: &Path,
    allow_pattern: &str,
) -> Config {
    let toml = format!(
        r#"
schema_version = "1"

[proxy]
listeners.explicit_http.bind = "127.0.0.1:1"

[proxy.egress.default]
type = "explicit_proxy"
transport = "https"
host = "127.0.0.1"
port = {parent_port}

[proxy.egress.default.tls]
trust = "custom_ca"
server_name = "127.0.0.1"
ca_cert_path = {ca_cert_path:?}

[logging]
level = "info"

[capture]
allowed_request = false
allowed_response = false
denied_request = false
denied_response = false
directory = "logs-capture"

[tls]
verify_upstream = false

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = {allow_pattern:?}
"#,
        parent_port = parent_addr.port(),
        ca_cert_path = ca_cert_path.display().to_string(),
    );

    toml::from_str(&toml).expect("parse explicit http config")
}

async fn start_explicit_https_proxy(
    mut config: Config,
    listener: StdTcpListener,
) -> (SocketAddr, TempDir) {
    let addr = listener.local_addr().expect("proxy addr");
    let temp_dir = TempDir::new().expect("temp dir");
    config.logging.directory = None;
    config.capture.directory = temp_dir
        .path()
        .join("captures")
        .to_string_lossy()
        .to_string();
    config.certificates.certs_dir = temp_dir.path().join("certs").to_string_lossy().to_string();

    let listener_cfg = config
        .proxy
        .listeners
        .explicit_https
        .as_ref()
        .expect("explicit https listener")
        .clone();
    let tls_acceptor = build_static_tls_acceptor(&listener_cfg).expect("static TLS acceptor");
    let state = AppState::shared_from_config(config).expect("app state");

    tokio::spawn(async move {
        let _ = run_explicit_https_proxy_on_listener(
            state,
            listener,
            tls_acceptor,
            listener_cfg,
            std::future::pending(),
        )
        .await
        .map_err(|e| eprintln!("explicit HTTPS proxy server on {addr} exited: {e}"));
    });

    (addr, temp_dir)
}

async fn start_explicit_http_proxy(mut config: Config) -> (SocketAddr, TempDir) {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let addr = listener.local_addr().expect("proxy addr");

    let temp_dir = TempDir::new().expect("temp dir");
    config.logging.directory = None;
    config.capture.directory = temp_dir
        .path()
        .join("captures")
        .to_string_lossy()
        .to_string();
    config.certificates.certs_dir = temp_dir.path().join("certs").to_string_lossy().to_string();
    let state = AppState::shared_from_config(config).expect("app state");

    tokio::spawn(async move {
        let _ = run_http_proxy_on_listener(state, listener, std::future::pending())
            .await
            .map_err(|e| eprintln!("explicit HTTP proxy server on {addr} exited: {e}"));
    });

    (addr, temp_dir)
}

async fn send_explicit_https_request(
    proxy_addr: SocketAddr,
    ca_cert_path: &Path,
    absolute_url: &str,
) -> (StatusCode, String) {
    let stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");

    let ca_pem = std::fs::read(ca_cert_path).expect("read proxy cert");
    let mut reader = Cursor::new(ca_pem);
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut reader).expect("parse proxy cert") {
        roots
            .add(&RustlsCertificate(cert.to_vec()))
            .expect("add proxy cert root");
    }

    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from("127.0.0.1").expect("server name");
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .expect("tls connect");

    let request = format!(
        "GET {absolute_url} HTTP/1.1\r\nHost: ignored-by-explicit-proxy.test\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(request.as_bytes())
        .await
        .expect("write request");

    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.expect("read response");
    let response = String::from_utf8_lossy(&buf).to_string();
    let status_line = response.lines().next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .expect("response status");
    (status, response)
}

async fn send_raw_http_request(proxy_addr: SocketAddr, absolute_url: &str) -> (StatusCode, String) {
    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");
    let request = format!(
        "GET {absolute_url} HTTP/1.1\r\nHost: ignored-by-explicit-proxy.test\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read response");
    let response = String::from_utf8_lossy(&buf).to_string();
    let status_line = response.lines().next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .expect("response status");
    (status, response)
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_https_listener_accepts_absolute_form_requests() {
    let (upstream_addr, seen_requests) = start_http_echo_server("explicit https ok").await;
    let identity_dir = TempDir::new().expect("identity dir");
    let (cert_path, key_path) = write_proxy_identity(&identity_dir);
    let allow_pattern = format!("http://{}:{}/**", upstream_addr.ip(), upstream_addr.port());
    let config = explicit_https_config(&cert_path, &key_path, &allow_pattern);

    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind explicit https proxy");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _proxy_temp_dir) = start_explicit_https_proxy(config, listener).await;

    let absolute_url = format!("http://{}:{}/ok", upstream_addr.ip(), upstream_addr.port());
    let (status, response) =
        send_explicit_https_request(proxy_addr, &cert_path, &absolute_url).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        response.contains("\r\n\r\nexplicit https ok"),
        "unexpected response: {response}"
    );

    let seen = seen_requests.lock().unwrap();
    let request = seen.first().expect("upstream request");
    assert_eq!(request.uri, "/ok");
    assert_eq!(
        request
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok()),
        Some(format!("{}:{}", upstream_addr.ip(), upstream_addr.port()).as_str())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_http_can_forward_to_parent_explicit_proxy_over_https() {
    let (upstream_addr, seen_requests) = start_http_echo_server("https parent ok").await;
    let identity_dir = TempDir::new().expect("identity dir");
    let (cert_path, key_path) = write_proxy_identity(&identity_dir);
    let allow_pattern = format!("http://{}:{}/**", upstream_addr.ip(), upstream_addr.port());

    let parent_config = explicit_https_config(&cert_path, &key_path, &allow_pattern);
    let parent_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind parent proxy");
    parent_listener
        .set_nonblocking(true)
        .expect("set nonblocking parent proxy");
    let (parent_addr, _parent_temp_dir) =
        start_explicit_https_proxy(parent_config, parent_listener).await;

    let mut inner_config =
        explicit_http_config_with_https_parent(parent_addr, &cert_path, &allow_pattern);
    inner_config.loop_protection.add_header = false;
    let (inner_addr, _inner_temp_dir) = start_explicit_http_proxy(inner_config).await;

    let absolute_url = format!(
        "http://{}:{}/via-parent",
        upstream_addr.ip(),
        upstream_addr.port()
    );
    let (status, response) = send_raw_http_request(inner_addr, &absolute_url).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        response.contains("\r\n\r\nhttps parent ok"),
        "unexpected response: {response}"
    );

    let seen = seen_requests.lock().unwrap();
    let request = seen.first().expect("upstream request");
    assert_eq!(request.uri, "/via-parent");
    assert_eq!(
        request
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok()),
        Some(format!("{}:{}", upstream_addr.ip(), upstream_addr.port()).as_str())
    );
}
