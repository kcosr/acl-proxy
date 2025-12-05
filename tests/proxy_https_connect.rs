use std::io::Read;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;

use acl_proxy::app::AppState;
use acl_proxy::capture::{CaptureMode, CaptureRecord};
use acl_proxy::config::Config;
use acl_proxy::proxy::http::run_http_proxy_on_listener;
use http::StatusCode;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::client::ServerName;
use rustls::{
    Certificate as RustlsCertificate, ClientConfig, PrivateKey,
    RootCertStore, ServerConfig,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request as HyperRequest, Response as HyperResponse};

async fn start_upstream_https_echo_server() -> SocketAddr {
    let listener =
        StdTcpListener::bind("127.0.0.1:0").expect("bind upstream");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking upstream");
    let addr = listener.local_addr().expect("upstream addr");

    // Generate a simple self-signed certificate for the upstream server.
    let mut params =
        CertificateParams::new(vec![addr.ip().to_string()]).expect("params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, addr.ip().to_string());
    params.distinguished_name = dn;
    let key =
        KeyPair::generate().expect("generate upstream key");
    let cert = params
        .self_signed(&key)
        .expect("self-signed upstream cert");

    let cert_der: Vec<u8> = cert.der().to_vec();
    let key_der = key.serialize_der();

    let mut tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![RustlsCertificate(cert_der)],
            PrivateKey(key_der),
        )
        .expect("server config");
    tls_config.alpn_protocols =
        vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    tokio::spawn(async move {
        let listener =
            TcpListener::from_std(listener).expect("tokio listener");
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(socket).await {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let service = service_fn(|_req: HyperRequest<Body>| async move {
                    Ok::<_, hyper::Error>(HyperResponse::new(Body::from("ok")))
                });

                let _ = Http::new()
                    .http1_keep_alive(false)
                    .serve_connection(tls_stream, service)
                    .await;
            });
        }
    });

    addr
}

fn minimal_connect_config() -> Config {
    let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 0

[logging]
directory = "logs"
level = "info"

[capture]
allowed_request = true
allowed_response = true
denied_request = true
denied_response = true
directory = "logs-capture"

[certificates]
certs_dir = "certs"

[tls]
verify_upstream = false

[policy]
default = "deny"
    "#;

    toml::from_str(toml).expect("parse config")
}

async fn start_proxy_with_config(
    mut config: Config,
    listener: StdTcpListener,
) -> (SocketAddr, TempDir) {
    let addr = listener.local_addr().expect("proxy addr");

    let temp_dir = TempDir::new().expect("temp dir for capture");
    let capture_dir = temp_dir.path().join("captures");
    let certs_dir = temp_dir.path().join("certs");
    config.capture.directory =
        capture_dir.to_string_lossy().to_string();
    config.certificates.certs_dir =
        certs_dir.to_string_lossy().to_string();

    let state =
        AppState::shared_from_config(config).expect("app state");

    let listener_addr = addr;
    tokio::spawn(async move {
        let _ = run_http_proxy_on_listener(
            state,
            listener,
            std::future::pending(),
        )
        .await
        .map_err(|e| {
            eprintln!(
                "proxy server on {listener_addr} exited: {e}"
            );
        });
    });

    (addr, temp_dir)
}

async fn send_https_via_connect(
    proxy_addr: SocketAddr,
    _ca_cert_path: &std::path::Path,
    target_host: &str,
    path: &str,
) -> (u16, String) {
    use rustls_pemfile;

    // Establish a TCP connection to the proxy and send CONNECT.
    let mut stream =
        tokio::net::TcpStream::connect(proxy_addr).await.expect("connect proxy");

    let connect_req = format!(
        "CONNECT {target_host} HTTP/1.1\r\nHost: {target_host}\r\nConnection: keep-alive\r\n\r\n"
    );
    stream
        .write_all(connect_req.as_bytes())
        .await
        .expect("write CONNECT");

    // Read CONNECT response headers.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await.expect("read CONNECT resp");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let response = String::from_utf8_lossy(&buf).to_string();
    let status_line = response.lines().next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status != 200 {
        return (status, String::new());
    }

    // Wrap the stream in TLS using the proxy's CA cert.
    let ca_pem =
        std::fs::read(_ca_cert_path).expect("read ca cert");
    let mut reader = std::io::Cursor::new(ca_pem);
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut reader).expect("parse ca cert") {
        let cert = RustlsCertificate(cert.to_vec());
        roots
            .add(&cert)
            .expect("add root cert to store");
    }

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let host_only = target_host
        .split(':')
        .next()
        .unwrap_or("localhost");
    let server_name =
        ServerName::try_from(host_only).expect("server name");

    let mut tls_stream = connector
        .connect(server_name, stream)
        .await
        .expect("tls connect");

    // Send inner HTTPS request.
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n"
    );
    tls_stream
        .write_all(request.as_bytes())
        .await
        .expect("write HTTPS request");

    let mut resp_buf = Vec::new();
    tls_stream
        .read_to_end(&mut resp_buf)
        .await
        .expect("read HTTPS response");

    let resp_str = String::from_utf8_lossy(&resp_buf).to_string();
    let status_line = resp_str.lines().next().unwrap_or_default();
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let body = resp_str
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .to_string();

    (status_code, body)
}

async fn send_raw_connect_request(
    proxy_addr: SocketAddr,
    raw_request: &str,
) -> (String, StatusCode) {
    let mut stream =
        tokio::net::TcpStream::connect(proxy_addr).await.expect("connect proxy");

    stream
        .write_all(raw_request.as_bytes())
        .await
        .expect("write request");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read response");

    let response = String::from_utf8_lossy(&buf).to_string();
    let status_line = response.lines().next().unwrap_or_default();
    let status = if let Some(code_str) =
        status_line.split_whitespace().nth(1)
    {
        match code_str.parse::<u16>() {
            Ok(code) => StatusCode::from_u16(code)
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };

    (response, status)
}

#[tokio::test(flavor = "multi_thread")]
async fn allowed_https_via_connect_is_proxied_and_captured() {
    let upstream_addr = start_upstream_https_echo_server().await;

    let mut config = minimal_connect_config();

    // Allow all HTTPS traffic to the upstream host.
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyDefaultAction::Allow,
            pattern: Some(format!(
                "https://{}:{}/**",
                upstream_addr.ip(),
                upstream_addr.port()
            )),
            description: None,
            methods: None,
            subnets: Vec::new(),
            with: None,
            add_url_enc_variants: None,
            header_actions: Vec::new(),
        },
    )];

    let proxy_listener =
        StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, temp_dir) =
        start_proxy_with_config(config, proxy_listener).await;

    let certs_dir = temp_dir.path().join("certs");
    let ca_cert_path = certs_dir.join("ca-cert.pem");

    let target_host =
        format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let (status, body) = send_https_via_connect(
        proxy_addr,
        &ca_cert_path,
        &target_host,
        "/ok",
    )
    .await;

    assert_eq!(status, StatusCode::OK.as_u16());
    assert_eq!(body, "ok");

    // Ensure capture files exist and are tagged as https_connect.
    use tokio::time::{sleep, Duration};

    let capture_dir = temp_dir.path().join("captures");
    // Wait briefly for async capture tasks to flush to disk.
    for _ in 0..10 {
        if capture_dir.is_dir() {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    let mut entries =
        std::fs::read_dir(&capture_dir).expect("read capture dir");
    let mut files = Vec::new();
    while let Some(entry) = entries.next() {
        let entry = entry.expect("dir entry");
        if entry.file_type().expect("file type").is_file() {
            files.push(entry.path());
        }
    }
    assert!(
        !files.is_empty(),
        "expected capture files for CONNECT traffic"
    );

    let mut contents = String::new();
    std::fs::File::open(&files[0])
        .expect("open capture")
        .read_to_string(&mut contents)
        .expect("read capture");
    let record: CaptureRecord =
        serde_json::from_str(&contents).expect("decode capture");
    assert_eq!(record.mode, CaptureMode::HttpsConnect);
    assert!(
        record.url.starts_with("https://"),
        "url should be https, got {}",
        record.url
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_https_via_connect_returns_403() {
    let upstream_addr = start_upstream_https_echo_server().await;

    let mut config = minimal_connect_config();
    // Allow only /ok, so /denied should be blocked.
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyDefaultAction::Allow,
            pattern: Some(format!(
                "https://{}:{}/ok",
                upstream_addr.ip(),
                upstream_addr.port()
            )),
            description: None,
            methods: None,
            subnets: Vec::new(),
            with: None,
            add_url_enc_variants: None,
            header_actions: Vec::new(),
        },
    )];

    let proxy_listener =
        StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, temp_dir) =
        start_proxy_with_config(config, proxy_listener).await;

    let certs_dir = temp_dir.path().join("certs");
    let ca_cert_path = certs_dir.join("ca-cert.pem");

    let target_host =
        format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let (status, body) = send_https_via_connect(
        proxy_addr,
        &ca_cert_path,
        &target_host,
        "/denied",
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN.as_u16());
    assert!(
        body.contains("Blocked by URL policy"),
        "unexpected body: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn loop_detected_on_connect_returns_508() {
    let upstream_addr = start_upstream_https_echo_server().await;
    let mut config = minimal_connect_config();

    // Allow traffic so that loop protection is the deciding factor.
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyDefaultAction::Allow,
            pattern: Some(format!(
                "https://{}:{}/**",
                upstream_addr.ip(),
                upstream_addr.port()
            )),
            description: None,
            methods: None,
            subnets: Vec::new(),
            with: None,
            add_url_enc_variants: None,
            header_actions: Vec::new(),
        },
    )];

    let proxy_listener =
        StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) =
        start_proxy_with_config(config, proxy_listener).await;

    let host = format!(
        "{}:{}",
        upstream_addr.ip(),
        upstream_addr.port()
    );
    let raw_request = format!(
        "CONNECT {host} HTTP/1.1\r\nHost: {host}\r\nx-acl-proxy-request-id: existing\r\nConnection: close\r\n\r\n"
    );

    let (_response, status) =
        send_raw_connect_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::LOOP_DETECTED);
}
