#![allow(clippy::while_let_on_iterator)]

use std::io::Read;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex};

use acl_proxy::app::AppState;
use acl_proxy::capture::{CaptureMode, CaptureRecord};
use acl_proxy::config::Config;
use acl_proxy::proxy::http::run_http_proxy_on_listener;
use http::header::{HeaderValue, CONNECTION, UPGRADE};
use http::StatusCode;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request as HyperRequest, Response as HyperResponse};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::client::ServerName;
use rustls::{
    Certificate as RustlsCertificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Clone, Debug)]
struct SeenForwardedRequest {
    uri: String,
    headers: hyper::HeaderMap,
}

#[derive(Debug)]
struct TestWebSocketFrame {
    opcode: u8,
    payload: Vec<u8>,
}

async fn start_upstream_https_echo_server() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind upstream");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking upstream");
    let addr = listener.local_addr().expect("upstream addr");

    // Generate a simple self-signed certificate for the upstream server.
    let mut params = CertificateParams::new(vec![addr.ip().to_string()]).expect("params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, addr.ip().to_string());
    params.distinguished_name = dn;
    let key = KeyPair::generate().expect("generate upstream key");
    let cert = params.self_signed(&key).expect("self-signed upstream cert");

    let cert_der: Vec<u8> = cert.der().to_vec();
    let key_der = key.serialize_der();

    let mut tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![RustlsCertificate(cert_der)], PrivateKey(key_der))
        .expect("server config");
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    tokio::spawn(async move {
        let listener = TcpListener::from_std(listener).expect("tokio listener");
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

async fn start_upstream_https_redaction_server() -> (SocketAddr, Arc<Mutex<Vec<TestWebSocketFrame>>>)
{
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind websocket upstream");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking websocket upstream");
    let addr = listener.local_addr().expect("websocket upstream addr");
    let seen_payloads = Arc::new(Mutex::new(Vec::new()));
    let seen_payloads_clone = seen_payloads.clone();

    let mut params = CertificateParams::new(vec![addr.ip().to_string()]).expect("params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, addr.ip().to_string());
    params.distinguished_name = dn;
    let key = KeyPair::generate().expect("generate upstream key");
    let cert = params.self_signed(&key).expect("self-signed upstream cert");

    let cert_der: Vec<u8> = cert.der().to_vec();
    let key_der = key.serialize_der();

    let mut tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![RustlsCertificate(cert_der)], PrivateKey(key_der))
        .expect("server config");
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    tokio::spawn(async move {
        let listener = TcpListener::from_std(listener).expect("tokio listener");
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let acceptor = tls_acceptor.clone();
            let seen_payloads = seen_payloads_clone.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(socket).await {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let service = service_fn(move |mut req: HyperRequest<Body>| {
                    let seen_payloads = seen_payloads.clone();
                    async move {
                        let on_upgrade = hyper::upgrade::on(&mut req);
                        tokio::spawn(async move {
                            let mut upgraded = match on_upgrade.await {
                                Ok(stream) => stream,
                                Err(_) => return,
                            };
                            let frame = read_websocket_frame(&mut upgraded)
                                .await
                                .expect("read upstream websocket frame");
                            seen_payloads.lock().unwrap().push(frame);
                            write_websocket_frame(&mut upgraded, 0x1, b"upstream password", false)
                                .await
                                .expect("write upstream websocket frame");
                        });

                        let mut resp = HyperResponse::new(Body::empty());
                        *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                        resp.headers_mut()
                            .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
                        resp.headers_mut()
                            .insert(UPGRADE, HeaderValue::from_static("websocket"));
                        Ok::<_, hyper::Error>(resp)
                    }
                });

                let _ = Http::new()
                    .http1_keep_alive(false)
                    .serve_connection(tls_stream, service)
                    .with_upgrades()
                    .await;
            });
        }
    });

    (addr, seen_payloads)
}

async fn start_forwarding_echo_server(
) -> (SocketAddr, Arc<std::sync::Mutex<Vec<SeenForwardedRequest>>>) {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind forwarding upstream");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking forwarding upstream");
    let addr = listener.local_addr().expect("forwarding upstream addr");

    let seen_requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_requests_clone = seen_requests.clone();

    tokio::spawn(
        hyper::Server::from_tcp(listener)
            .expect("server from tcp")
            .serve(hyper::service::make_service_fn(move |_conn| {
                let seen_requests = seen_requests_clone.clone();
                async move {
                    Ok::<_, hyper::Error>(service_fn(move |req: HyperRequest<Body>| {
                        let seen_requests = seen_requests.clone();
                        async move {
                            seen_requests.lock().unwrap().push(SeenForwardedRequest {
                                uri: req.uri().to_string(),
                                headers: req.headers().clone(),
                            });
                            Ok::<_, hyper::Error>(HyperResponse::new(Body::from("forwarded")))
                        }
                    }))
                }
            })),
    );

    (addr, seen_requests)
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
    config.capture.directory = capture_dir.to_string_lossy().to_string();
    config.certificates.certs_dir = certs_dir.to_string_lossy().to_string();

    let state = AppState::shared_from_config(config).expect("app state");

    let listener_addr = addr;
    tokio::spawn(async move {
        let _ = run_http_proxy_on_listener(state, listener, std::future::pending())
            .await
            .map_err(|e| {
                eprintln!("proxy server on {listener_addr} exited: {e}");
            });
    });

    (addr, temp_dir)
}

async fn send_https_via_connect(
    proxy_addr: SocketAddr,
    ca_cert_path: &std::path::Path,
    target_host: &str,
    path: &str,
) -> (u16, String) {
    send_https_via_connect_with_headers(proxy_addr, ca_cert_path, target_host, path, &[]).await
}

async fn send_https_via_connect_with_headers(
    proxy_addr: SocketAddr,
    ca_cert_path: &std::path::Path,
    target_host: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> (u16, String) {
    use rustls_pemfile;

    // Establish a TCP connection to the proxy and send CONNECT.
    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");

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
    let ca_pem = std::fs::read(ca_cert_path).expect("read ca cert");
    let mut reader = std::io::Cursor::new(ca_pem);
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut reader).expect("parse ca cert") {
        let cert = RustlsCertificate(cert.to_vec());
        roots.add(&cert).expect("add root cert to store");
    }

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let host_only = target_host.split(':').next().unwrap_or("localhost");
    let server_name = ServerName::try_from(host_only).expect("server name");

    let mut tls_stream = connector
        .connect(server_name, stream)
        .await
        .expect("tls connect");

    // Send inner HTTPS request.
    let extra_header_lines = if extra_headers.is_empty() {
        String::new()
    } else {
        extra_headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .collect::<String>()
    };

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {target_host}\r\n{extra_header_lines}Connection: close\r\n\r\n"
    );
    tls_stream
        .write_all(request.as_bytes())
        .await
        .expect("write HTTPS request");

    let mut resp_buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match tls_stream.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => resp_buf.extend_from_slice(&tmp[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof && !resp_buf.is_empty() => {
                break;
            }
            Err(err) => panic!("read HTTPS response: {err:?}"),
        }
    }

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
    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");

    stream
        .write_all(raw_request.as_bytes())
        .await
        .expect("write request");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read response");

    let response = String::from_utf8_lossy(&buf).to_string();
    let status_line = response.lines().next().unwrap_or_default();
    let status = if let Some(code_str) = status_line.split_whitespace().nth(1) {
        match code_str.parse::<u16>() {
            Ok(code) => StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };

    (response, status)
}

fn build_websocket_frame(opcode: u8, payload: &[u8], masked: bool) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.push(0x80 | (opcode & 0x0f));
    let mask_bit = if masked { 0x80 } else { 0x00 };
    if payload.len() < 126 {
        frame.push(mask_bit | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        frame.push(mask_bit | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(mask_bit | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }

    if masked {
        let mask = [0x55, 0x66, 0x77, 0x88];
        frame.extend_from_slice(&mask);
        for (idx, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[idx % mask.len()]);
        }
    } else {
        frame.extend_from_slice(payload);
    }
    frame
}

async fn write_websocket_frame<W>(
    writer: &mut W,
    opcode: u8,
    payload: &[u8],
    masked: bool,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    writer
        .write_all(&build_websocket_frame(opcode, payload, masked))
        .await
}

async fn read_websocket_frame<R>(reader: &mut R) -> std::io::Result<TestWebSocketFrame>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header).await?;
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let mut len = u64::from(header[1] & 0x7f);
    if len == 126 {
        let mut extended = [0_u8; 2];
        reader.read_exact(&mut extended).await?;
        len = u64::from(u16::from_be_bytes(extended));
    } else if len == 127 {
        let mut extended = [0_u8; 8];
        reader.read_exact(&mut extended).await?;
        len = u64::from_be_bytes(extended);
    }

    let mut mask = [0_u8; 4];
    if masked {
        reader.read_exact(&mut mask).await?;
    }

    let mut payload = vec![0_u8; len as usize];
    reader.read_exact(&mut payload).await?;
    if masked {
        for (idx, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[idx % mask.len()];
        }
    }

    Ok(TestWebSocketFrame { opcode, payload })
}

async fn read_http_response_head<R>(reader: &mut R) -> std::io::Result<(String, u16)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        reader.read_exact(&mut byte).await?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let response = String::from_utf8_lossy(&buf).to_string();
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);

    Ok((response, status))
}

#[tokio::test(flavor = "multi_thread")]
async fn allowed_https_via_connect_is_proxied_and_captured() {
    let upstream_addr = start_upstream_https_echo_server().await;

    let mut config = minimal_connect_config();

    // Allow all HTTPS traffic to the upstream host.
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some(format!(
                "https://{}:{}/**",
                upstream_addr.ip(),
                upstream_addr.port()
            )),
            patterns: None,
            description: None,
            methods: None,
            subnets: Vec::new(),
            headers_absent: None,
            headers_match: None,
            headers_not_match: None,
            request_timeout_ms: None,
            allow_upgrades: true,
            redaction_profile: None,
            with: None,
            add_url_enc_variants: None,
            header_actions: Vec::new(),
            external_auth_profile: None,
            rule_id: None,
        },
    )];

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let certs_dir = temp_dir.path().join("certs");
    let ca_cert_path = certs_dir.join("ca-cert.pem");

    let target_host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let (status, body) =
        send_https_via_connect(proxy_addr, &ca_cert_path, &target_host, "/ok").await;

    assert_eq!(status, StatusCode::OK.as_u16());
    assert_eq!(body, "ok");

    // Ensure capture files exist and are tagged as https_connect.
    use tokio::time::{sleep, Duration};

    let capture_dir = temp_dir.path().join("captures");
    // Wait for async capture tasks to flush to disk and ensure at least one file.
    for _ in 0..10 {
        if capture_dir.is_dir() {
            let entries: Vec<_> = std::fs::read_dir(&capture_dir)
                .expect("read capture dir")
                .collect();
            if !entries.is_empty() {
                break;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }
    let mut entries = std::fs::read_dir(&capture_dir).expect("read capture dir");
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
    let record: CaptureRecord = serde_json::from_str(&contents).expect("decode capture");
    assert_eq!(record.mode, CaptureMode::HttpsConnect);
    assert!(
        record.url.starts_with("https://"),
        "url should be https, got {}",
        record.url
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn allow_upgrades_false_blocks_connect_inner_upgrade() {
    let upstream_addr = start_upstream_https_echo_server().await;

    let mut config = minimal_connect_config();
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some(format!(
                "https://{}:{}/ws",
                upstream_addr.ip(),
                upstream_addr.port()
            )),
            patterns: None,
            description: None,
            methods: None,
            subnets: Vec::new(),
            headers_absent: None,
            headers_match: None,
            headers_not_match: None,
            request_timeout_ms: None,
            allow_upgrades: false,
            redaction_profile: None,
            with: None,
            add_url_enc_variants: None,
            header_actions: Vec::new(),
            external_auth_profile: None,
            rule_id: None,
        },
    )];

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, temp_dir) = start_proxy_with_config(config, proxy_listener).await;
    let ca_cert_path = temp_dir.path().join("certs").join("ca-cert.pem");
    let target_host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let (status, _body) = send_https_via_connect_with_headers(
        proxy_addr,
        &ca_cert_path,
        &target_host,
        "/ws",
        &[
            ("Connection", "Upgrade"),
            ("Upgrade", "websocket"),
            ("Sec-WebSocket-Version", "13"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN.as_u16());
}

#[tokio::test(flavor = "multi_thread")]
async fn redaction_profile_redacts_connect_inner_messages() {
    use rustls_pemfile;

    let (upstream_addr, seen_payloads) = start_upstream_https_redaction_server().await;

    let mut config = minimal_connect_config();
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.redaction.profiles.insert(
        "secrets".to_string(),
        acl_proxy::config::RedactionProfileConfig {
            replacement: "[REDACTED]".to_string(),
            rules: vec![acl_proxy::config::RedactionRuleConfig {
                literals: vec!["password".to_string()],
                expressions: Vec::new(),
                match_mode: acl_proxy::config::RedactionMatch::Both,
            }],
            ..Default::default()
        },
    );
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some(format!(
                "https://{}:{}/ws",
                upstream_addr.ip(),
                upstream_addr.port()
            )),
            patterns: None,
            description: None,
            methods: None,
            subnets: Vec::new(),
            headers_absent: None,
            headers_match: None,
            headers_not_match: None,
            request_timeout_ms: None,
            allow_upgrades: true,
            redaction_profile: Some("secrets".to_string()),
            with: None,
            add_url_enc_variants: None,
            header_actions: Vec::new(),
            external_auth_profile: None,
            rule_id: None,
        },
    )];

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, temp_dir) = start_proxy_with_config(config, proxy_listener).await;
    let ca_cert_path = temp_dir.path().join("certs").join("ca-cert.pem");
    let target_host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");
    let connect_req = format!(
        "CONNECT {target_host} HTTP/1.1\r\nHost: {target_host}\r\nConnection: keep-alive\r\n\r\n"
    );
    stream
        .write_all(connect_req.as_bytes())
        .await
        .expect("write CONNECT");
    let (_connect_head, connect_status) = read_http_response_head(&mut stream)
        .await
        .expect("read CONNECT response");
    assert_eq!(connect_status, StatusCode::OK.as_u16());

    let ca_pem = std::fs::read(&ca_cert_path).expect("read ca cert");
    let mut reader = std::io::Cursor::new(ca_pem);
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut reader).expect("parse ca cert") {
        let cert = RustlsCertificate(cert.to_vec());
        roots.add(&cert).expect("add root cert to store");
    }
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let upstream_ip = upstream_addr.ip().to_string();
    let server_name = ServerName::try_from(upstream_ip.as_str()).expect("server name");
    let mut tls_stream = connector
        .connect(server_name, stream)
        .await
        .expect("tls connect");

    let request = format!(
        concat!(
            "GET /ws HTTP/1.1\r\n",
            "Host: {target_host}\r\n",
            "Connection: Upgrade\r\n",
            "Upgrade: websocket\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "\r\n"
        ),
        target_host = target_host
    );
    tls_stream
        .write_all(request.as_bytes())
        .await
        .expect("write websocket upgrade request");

    let (_head, status) = read_http_response_head(&mut tls_stream)
        .await
        .expect("read websocket response");
    assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS.as_u16());

    write_websocket_frame(&mut tls_stream, 0x1, b"client password", true)
        .await
        .expect("write websocket frame");
    let frame = read_websocket_frame(&mut tls_stream)
        .await
        .expect("read websocket frame");
    assert_eq!(frame.opcode, 0x1);
    assert_eq!(frame.payload, b"upstream password");

    let seen = seen_payloads.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].payload, b"client [REDACTED]");
}

#[tokio::test(flavor = "multi_thread")]
async fn configured_egress_forwarding_applies_to_https_connect_inner_requests() {
    let (forward_addr, seen_requests) = start_forwarding_echo_server().await;

    let mut config = minimal_connect_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some("https://connect-target.test:9443/**".to_string()),
            patterns: None,
            description: None,
            methods: None,
            subnets: Vec::new(),
            headers_absent: None,
            headers_match: None,
            headers_not_match: None,
            request_timeout_ms: None,
            allow_upgrades: true,
            redaction_profile: None,
            with: None,
            add_url_enc_variants: None,
            header_actions: Vec::new(),
            external_auth_profile: None,
            rule_id: None,
        },
    )];
    config.proxy.egress.default = Some(acl_proxy::config::EgressTargetConfig {
        host: "127.0.0.1".to_string(),
        port: forward_addr.port(),
    });

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, temp_dir) = start_proxy_with_config(config, proxy_listener).await;
    let ca_cert_path = temp_dir.path().join("certs").join("ca-cert.pem");

    let (status, body) =
        send_https_via_connect(proxy_addr, &ca_cert_path, "connect-target.test:9443", "/ok").await;

    assert_eq!(status, StatusCode::OK.as_u16());
    assert_eq!(body, "forwarded");

    let requests = seen_requests.lock().unwrap();
    let forwarded = requests
        .first()
        .expect("forwarding destination should see request");
    assert_eq!(forwarded.uri, "https://connect-target.test:9443/ok");
    assert_eq!(
        forwarded
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok()),
        Some("connect-target.test:9443")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn global_egress_request_actions_apply_to_https_connect_inner_requests() {
    let (forward_addr, seen_requests) = start_forwarding_echo_server().await;

    let mut config = minimal_connect_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some("https://connect-target.test:9443/**".to_string()),
            patterns: None,
            description: None,
            methods: None,
            subnets: Vec::new(),
            headers_absent: None,
            headers_match: None,
            headers_not_match: None,
            request_timeout_ms: None,
            allow_upgrades: true,
            redaction_profile: None,
            with: None,
            add_url_enc_variants: None,
            header_actions: Vec::new(),
            external_auth_profile: None,
            rule_id: None,
        },
    )];
    config.proxy.egress.default = Some(acl_proxy::config::EgressTargetConfig {
        host: "127.0.0.1".to_string(),
        port: forward_addr.port(),
    });
    config.proxy.egress.request_header_actions =
        vec![acl_proxy::config::EgressRequestHeaderActionConfig {
            action: acl_proxy::config::HeaderActionKind::Set,
            name: "x-egress-tag".to_string(),
            when: acl_proxy::config::HeaderWhen::Always,
            value: Some("connect".to_string()),
            values: None,
            search: None,
            replace: None,
        }];

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, temp_dir) = start_proxy_with_config(config, proxy_listener).await;
    let ca_cert_path = temp_dir.path().join("certs").join("ca-cert.pem");

    let (status, body) =
        send_https_via_connect(proxy_addr, &ca_cert_path, "connect-target.test:9443", "/ok").await;

    assert_eq!(status, StatusCode::OK.as_u16());
    assert_eq!(body, "forwarded");

    let requests = seen_requests.lock().unwrap();
    let forwarded = requests
        .first()
        .expect("forwarding destination should see request");
    assert_eq!(
        forwarded
            .headers
            .get("x-egress-tag")
            .and_then(|value| value.to_str().ok()),
        Some("connect")
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
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some(format!(
                "https://{}:{}/ok",
                upstream_addr.ip(),
                upstream_addr.port()
            )),
            patterns: None,
            description: None,
            methods: None,
            subnets: Vec::new(),
            headers_absent: None,
            headers_match: None,
            headers_not_match: None,
            request_timeout_ms: None,
            allow_upgrades: true,
            redaction_profile: None,
            with: None,
            add_url_enc_variants: None,
            header_actions: Vec::new(),
            external_auth_profile: None,
            rule_id: None,
        },
    )];

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let certs_dir = temp_dir.path().join("certs");
    let ca_cert_path = certs_dir.join("ca-cert.pem");

    let target_host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let (status, body) =
        send_https_via_connect(proxy_addr, &ca_cert_path, &target_host, "/denied").await;

    assert_eq!(status, StatusCode::FORBIDDEN.as_u16());
    assert!(
        body.contains("Blocked by URL policy"),
        "unexpected body: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn delegate_plugin_pass_falls_through_for_connect_inner_request() {
    let upstream_addr = start_upstream_https_echo_server().await;

    let plugin_temp_dir = TempDir::new().expect("temp dir");
    let script_path = plugin_temp_dir.path().join("auth-plugin-pass.sh");
    let script = r#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf "%s" "$line" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  if [ -n "$id" ]; then
    printf '{"id":"%s","type":"response","decision":"pass"}\n' "$id"
  fi
done
"#;
    std::fs::write(&script_path, script).expect("write plugin script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path)
            .expect("stat plugin script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).expect("chmod plugin script");
    }

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let toml = format!(
        r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 0

[logging]
directory = "logs"
level = "info"

[capture]
allowed_request = false
allowed_response = false
denied_request = false
denied_response = false
directory = "logs-capture"

[certificates]
certs_dir = "certs"

[tls]
verify_upstream = false

[policy]
default = "deny"

[policy.external_auth_profiles]
[policy.external_auth_profiles.pass_plugin]
type = "plugin"
command = "{script_path}"
timeout_ms = 1000

[[policy.rules]]
action = "delegate"
pattern = "https://{host}/**"
external_auth_profile = "pass_plugin"

[[policy.rules]]
action = "allow"
pattern = "https://{host}/**"
"#,
        script_path = script_path.to_string_lossy(),
        host = host
    );
    let config: Config = toml::from_str(&toml).expect("parse config");

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, proxy_temp_dir) = start_proxy_with_config(config, proxy_listener).await;
    let ca_cert_path = proxy_temp_dir.path().join("certs").join("ca-cert.pem");

    let (status, body) = send_https_via_connect(proxy_addr, &ca_cert_path, &host, "/ok").await;

    assert_eq!(status, StatusCode::OK.as_u16());
    assert_eq!(body, "ok");
}

#[tokio::test(flavor = "multi_thread")]
async fn headers_match_is_evaluated_on_decrypted_inner_connect_requests() {
    let (forward_addr, seen_requests) = start_forwarding_echo_server().await;

    let mut config = minimal_connect_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some("https://connect-target.test:9443/**".to_string()),
            patterns: None,
            description: Some("Allow trusted workload identities".to_string()),
            methods: None,
            subnets: Vec::new(),
            headers_absent: None,
            headers_match: Some(std::collections::BTreeMap::from([(
                "x-workload-id".to_string(),
                acl_proxy::config::HeaderMatchValueConfig::Single("worker-123".to_string()),
            )])),
            headers_not_match: None,
            request_timeout_ms: None,
            allow_upgrades: true,
            redaction_profile: None,
            with: None,
            add_url_enc_variants: None,
            header_actions: Vec::new(),
            external_auth_profile: None,
            rule_id: None,
        },
    )];
    config.proxy.egress.default = Some(acl_proxy::config::EgressTargetConfig {
        host: "127.0.0.1".to_string(),
        port: forward_addr.port(),
    });

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, temp_dir) = start_proxy_with_config(config, proxy_listener).await;
    let ca_cert_path = temp_dir.path().join("certs").join("ca-cert.pem");

    let (denied_status, denied_body) = send_https_via_connect_with_headers(
        proxy_addr,
        &ca_cert_path,
        "connect-target.test:9443",
        "/ok",
        &[("x-workload-id", "worker-999")],
    )
    .await;

    assert_eq!(denied_status, StatusCode::FORBIDDEN.as_u16());
    assert!(
        denied_body.contains("Blocked by URL policy"),
        "unexpected denied body: {denied_body}"
    );
    assert!(
        seen_requests.lock().unwrap().is_empty(),
        "non-matching CONNECT inner request must not be forwarded"
    );

    let (allowed_status, allowed_body) = send_https_via_connect_with_headers(
        proxy_addr,
        &ca_cert_path,
        "connect-target.test:9443",
        "/ok",
        &[("X-Workload-Id", "worker-123")],
    )
    .await;

    assert_eq!(allowed_status, StatusCode::OK.as_u16());
    assert_eq!(allowed_body, "forwarded");

    let requests = seen_requests.lock().unwrap();
    let forwarded = requests
        .first()
        .expect("forwarding destination should see allowed inner request");
    assert_eq!(
        forwarded
            .headers
            .get("x-workload-id")
            .and_then(|value| value.to_str().ok()),
        Some("worker-123")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn headers_not_match_is_evaluated_on_decrypted_inner_connect_requests() {
    let (forward_addr, seen_requests) = start_forwarding_echo_server().await;

    let mut config = minimal_connect_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![
        acl_proxy::config::PolicyRuleConfig::Direct(acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Deny,
            pattern: Some("https://connect-target.test:9443/**".to_string()),
            patterns: None,
            description: Some("Deny non-internal contexts".to_string()),
            methods: None,
            subnets: Vec::new(),
            headers_absent: None,
            headers_match: None,
            headers_not_match: Some(std::collections::BTreeMap::from([(
                "x-aw-policy-context".to_string(),
                acl_proxy::config::HeaderMatchValueConfig::Single("internal".to_string()),
            )])),
            request_timeout_ms: None,
            allow_upgrades: true,
            redaction_profile: None,
            with: None,
            add_url_enc_variants: None,
            header_actions: Vec::new(),
            external_auth_profile: None,
            rule_id: None,
        }),
        acl_proxy::config::PolicyRuleConfig::Direct(acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some("https://connect-target.test:9443/**".to_string()),
            patterns: None,
            description: Some("Allow upstream traffic".to_string()),
            methods: None,
            subnets: Vec::new(),
            headers_absent: None,
            headers_match: None,
            headers_not_match: None,
            request_timeout_ms: None,
            allow_upgrades: true,
            redaction_profile: None,
            with: None,
            add_url_enc_variants: None,
            header_actions: Vec::new(),
            external_auth_profile: None,
            rule_id: None,
        }),
    ];
    config.proxy.egress.default = Some(acl_proxy::config::EgressTargetConfig {
        host: "127.0.0.1".to_string(),
        port: forward_addr.port(),
    });

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, temp_dir) = start_proxy_with_config(config, proxy_listener).await;
    let ca_cert_path = temp_dir.path().join("certs").join("ca-cert.pem");

    let (denied_status, denied_body) = send_https_via_connect_with_headers(
        proxy_addr,
        &ca_cert_path,
        "connect-target.test:9443",
        "/ok",
        &[("x-aw-policy-context", "default")],
    )
    .await;

    assert_eq!(denied_status, StatusCode::FORBIDDEN.as_u16());
    assert!(
        denied_body.contains("Blocked by URL policy"),
        "unexpected denied body: {denied_body}"
    );
    assert!(
        seen_requests.lock().unwrap().is_empty(),
        "non-internal CONNECT inner request must not be forwarded"
    );

    let (allowed_status, allowed_body) = send_https_via_connect_with_headers(
        proxy_addr,
        &ca_cert_path,
        "connect-target.test:9443",
        "/ok",
        &[("X-AW-Policy-Context", "internal")],
    )
    .await;

    assert_eq!(allowed_status, StatusCode::OK.as_u16());
    assert_eq!(allowed_body, "forwarded");

    let requests = seen_requests.lock().unwrap();
    let forwarded = requests
        .first()
        .expect("forwarding destination should see allowed inner request");
    assert_eq!(
        forwarded
            .headers
            .get("x-aw-policy-context")
            .and_then(|value| value.to_str().ok()),
        Some("internal")
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
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some(format!(
                "https://{}:{}/**",
                upstream_addr.ip(),
                upstream_addr.port()
            )),
            patterns: None,
            description: None,
            methods: None,
            subnets: Vec::new(),
            headers_absent: None,
            headers_match: None,
            headers_not_match: None,
            request_timeout_ms: None,
            allow_upgrades: true,
            redaction_profile: None,
            with: None,
            add_url_enc_variants: None,
            header_actions: Vec::new(),
            external_auth_profile: None,
            rule_id: None,
        },
    )];

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let raw_request = format!(
        "CONNECT {host} HTTP/1.1\r\nHost: {host}\r\nx-acl-proxy-request-id: existing\r\nConnection: close\r\n\r\n"
    );

    let (_response, status) = send_raw_connect_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::LOOP_DETECTED);
}
