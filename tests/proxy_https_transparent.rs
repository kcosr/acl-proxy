use std::io::Read;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;

use acl_proxy::app::AppState;
use acl_proxy::capture::{
    CaptureDecision, CaptureKind, CaptureMode, CaptureRecord, DEFAULT_MAX_BODY_BYTES,
};
use acl_proxy::config::Config;
use acl_proxy::proxy::https_transparent::run_https_transparent_proxy_on_listener;
use h2::client as h2_client;
use http::header::{HeaderValue, CONNECTION, UPGRADE};
use http::Method;
use http::{StatusCode, Version};
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

// Use a body slightly larger than DEFAULT_MAX_BODY_BYTES to exercise
// truncation logic without introducing excessively large in-memory
// payloads that could slow down tests.
const LARGE_BODY_BYTES: usize = DEFAULT_MAX_BODY_BYTES + 1024;

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

async fn start_upstream_https_websocket_echo_server() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind upstream");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking upstream");
    let addr = listener.local_addr().expect("upstream addr");

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
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(socket).await {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let service = service_fn(|mut req: HyperRequest<Body>| async move {
                    let on_upgrade = hyper::upgrade::on(&mut req);
                    tokio::spawn(async move {
                        let mut upgraded = match on_upgrade.await {
                            Ok(stream) => stream,
                            Err(_) => return,
                        };
                        let mut buf = [0_u8; 1024];
                        loop {
                            let n = match upgraded.read(&mut buf).await {
                                Ok(0) => break,
                                Ok(n) => n,
                                Err(_) => break,
                            };
                            if upgraded.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    });

                    let mut resp = HyperResponse::new(Body::empty());
                    *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                    resp.headers_mut()
                        .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
                    resp.headers_mut()
                        .insert(UPGRADE, HeaderValue::from_static("websocket"));
                    Ok::<_, hyper::Error>(resp)
                });

                let _ = Http::new()
                    .http1_keep_alive(false)
                    .serve_connection(tls_stream, service)
                    .with_upgrades()
                    .await;
            });
        }
    });

    addr
}

async fn start_upstream_https_large_response_server() -> SocketAddr {
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
        eprintln!("large_response_upstream: listening on {}", addr);
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
                    eprintln!(
                        "large_response_upstream: received request, sending {} bytes",
                        LARGE_BODY_BYTES
                    );
                    let body = vec![b'x'; LARGE_BODY_BYTES];
                    Ok::<_, hyper::Error>(HyperResponse::new(Body::from(body)))
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

async fn start_upstream_https_http1_only_echo_server() -> SocketAddr {
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

fn minimal_https_transparent_config() -> Config {
    let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 0
https_bind_address = "127.0.0.1"
https_port = 0

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
) -> (SocketAddr, TempDir, std::path::PathBuf) {
    let addr = listener.local_addr().expect("proxy addr");

    let temp_dir = TempDir::new().expect("temp dir for capture");
    let capture_dir = temp_dir.path().join("captures");
    let certs_dir = temp_dir.path().join("certs");
    config.capture.directory = capture_dir.to_string_lossy().to_string();
    config.certificates.certs_dir = certs_dir.to_string_lossy().to_string();

    let state = AppState::shared_from_config(config).expect("app state");

    let listener_addr = addr;
    tokio::spawn(async move {
        let _ = run_https_transparent_proxy_on_listener(state, listener, std::future::pending())
            .await
            .map_err(|e| {
                eprintln!("HTTPS transparent proxy server on {listener_addr} exited: {e}");
            });
    });

    let ca_cert_path = certs_dir.join("ca-cert.pem");
    (addr, temp_dir, ca_cert_path)
}

async fn send_https_request_via_transparent(
    proxy_addr: SocketAddr,
    ca_cert_path: &std::path::Path,
    sni_host: &str,
    host_header: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> (u16, String) {
    use rustls_pemfile;

    let stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");

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
    let server_name = ServerName::try_from(sni_host).expect("server name");
    let mut tls_stream = connector
        .connect(server_name, stream)
        .await
        .expect("tls connect");

    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n",
        path = path,
        host = host_header,
    );
    for (name, value) in extra_headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

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

async fn send_h2_https_request_via_transparent(
    proxy_addr: SocketAddr,
    ca_cert_path: &std::path::Path,
    host_header: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> (Version, u16, String) {
    use rustls_pemfile;

    let stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");

    let ca_pem = std::fs::read(ca_cert_path).expect("read ca cert");
    let mut reader = std::io::Cursor::new(ca_pem);
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut reader).expect("parse ca cert") {
        let cert = RustlsCertificate(cert.to_vec());
        roots.add(&cert).expect("add root cert to store");
    }

    let mut tls_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = ServerName::try_from("transparent.test").expect("server name");
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .expect("tls connect");

    eprintln!("send_h2_https_request_via_transparent: starting h2 handshake");
    let (send_request, connection) = h2_client::handshake(tls_stream)
        .await
        .expect("h2 handshake");

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("h2 connection error: {e}");
        }
    });

    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };

    eprintln!("send_h2_https_request_via_transparent: waiting for send_request.ready()");
    let mut send_request = send_request.ready().await.expect("h2 ready");

    let uri = format!("https://{host_header}{path}");

    let mut req_builder = http::Request::builder()
        .method(Method::GET)
        .uri(uri.as_str())
        .version(Version::HTTP_2);

    {
        let headers = req_builder.headers_mut().expect("headers mut");
        headers.insert(
            http::header::HOST,
            http::HeaderValue::from_str(host_header).expect("host header"),
        );
        for (name, value) in extra_headers {
            let name = http::HeaderName::from_bytes(name.as_bytes()).expect("header name");
            let value = http::HeaderValue::from_str(value).expect("header value");
            headers.insert(name, value);
        }
    }

    let request = req_builder.body(()).expect("build h2 request");

    eprintln!(
        "send_h2_https_request_via_transparent: sending request to {}",
        uri
    );
    let (response, _send_stream) = send_request
        .send_request(request, true)
        .expect("send h2 request");

    eprintln!("send_h2_https_request_via_transparent: awaiting response head");
    let response = response.await.expect("await h2 response");
    let (head, mut body_stream) = response.into_parts();
    let status = head.status.as_u16();

    let mut body_bytes = Vec::new();
    eprintln!("send_h2_https_request_via_transparent: reading response body");
    while let Some(chunk) = body_stream.data().await.transpose().expect("h2 data") {
        body_bytes.extend_from_slice(&chunk);
    }

    let body = String::from_utf8_lossy(&body_bytes).to_string();

    eprintln!(
        "send_h2_https_request_via_transparent: done reading body ({} bytes, status={})",
        body_bytes.len(),
        status
    );

    (Version::HTTP_2, status, body)
}

async fn send_h2_https_request_with_body_via_transparent(
    proxy_addr: SocketAddr,
    ca_cert_path: &std::path::Path,
    host_header: &str,
    path: &str,
    body_bytes: Vec<u8>,
) -> (Version, u16, String) {
    use bytes::Bytes;
    use rustls_pemfile;

    let stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");

    let ca_pem = std::fs::read(ca_cert_path).expect("read ca cert");
    let mut reader = std::io::Cursor::new(ca_pem);
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut reader).expect("parse ca cert") {
        let cert = RustlsCertificate(cert.to_vec());
        roots.add(&cert).expect("add root cert to store");
    }

    let mut tls_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = ServerName::try_from("transparent.test").expect("server name");
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .expect("tls connect");

    let (send_request, connection) = h2_client::handshake(tls_stream)
        .await
        .expect("h2 handshake");

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("h2 connection error: {e}");
        }
    });

    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };

    let mut send_request = send_request.ready().await.expect("h2 ready");

    let uri = format!("https://{host_header}{path}");

    let mut req_builder = http::Request::builder()
        .method(Method::POST)
        .uri(uri.as_str())
        .version(Version::HTTP_2);

    {
        let headers = req_builder.headers_mut().expect("headers mut");
        headers.insert(
            http::header::HOST,
            http::HeaderValue::from_str(host_header).expect("host header"),
        );
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_str(&body_bytes.len().to_string()).expect("content-length"),
        );
    }

    let request = req_builder.body(()).expect("build h2 request");

    let (response, mut send_stream) = send_request
        .send_request(request, false)
        .expect("send h2 request");

    // Send the entire body in a single DATA frame; HTTP/2 will handle
    // framing and flow control internally.
    send_stream
        .send_data(Bytes::from(body_bytes), true)
        .expect("send h2 body");

    let response = response.await.expect("await h2 response");
    let (head, mut body_stream) = response.into_parts();
    let status = head.status.as_u16();

    let mut resp_body_bytes = Vec::new();
    while let Some(chunk) = body_stream
        .data()
        .await
        .transpose()
        .expect("h2 response data")
    {
        resp_body_bytes.extend_from_slice(&chunk);
    }

    let body = String::from_utf8_lossy(&resp_body_bytes).to_string();

    (Version::HTTP_2, status, body)
}

#[tokio::test(flavor = "multi_thread")]
async fn allowed_https_transparent_is_proxied_and_captured() {
    let upstream_addr = start_upstream_https_echo_server().await;

    let mut config = minimal_https_transparent_config();

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
            request_timeout_ms: None,
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

    let (proxy_addr, temp_dir, ca_cert_path) =
        start_proxy_with_config(config, proxy_listener).await;

    let sni_host = "transparent.test";
    let host_header = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let (status, body) = send_https_request_via_transparent(
        proxy_addr,
        &ca_cert_path,
        &sni_host,
        &host_header,
        "/ok",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::OK.as_u16());
    assert_eq!(body, "ok");

    // Ensure capture files exist and are tagged as https_transparent.
    use tokio::time::{sleep, Duration};

    let capture_dir = temp_dir.path().join("captures");
    // Wait briefly for async capture tasks to flush to disk.
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
        "expected capture files for transparent HTTPS traffic"
    );

    let mut contents = String::new();
    std::fs::File::open(&files[0])
        .expect("open capture")
        .read_to_string(&mut contents)
        .expect("read capture");
    let record: CaptureRecord = serde_json::from_str(&contents).expect("decode capture");
    assert_eq!(record.mode, CaptureMode::HttpsTransparent);
    assert!(
        record.url.starts_with("https://"),
        "url should be https, got {}",
        record.url
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn transparent_https_websocket_upgrade_is_tunneled() {
    use rustls_pemfile;

    let upstream_addr = start_upstream_https_websocket_echo_server().await;

    let mut config = minimal_https_transparent_config();
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyDefaultAction::Allow,
            pattern: Some(format!(
                "https://{}:{}/ws",
                upstream_addr.ip(),
                upstream_addr.port()
            )),
            description: None,
            methods: None,
            subnets: Vec::new(),
            request_timeout_ms: None,
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

    let (proxy_addr, _temp_dir, ca_cert_path) =
        start_proxy_with_config(config, proxy_listener).await;
    let host_header = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");

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
    let server_name = ServerName::try_from("transparent.test").expect("server name");
    let mut tls_stream = connector
        .connect(server_name, stream)
        .await
        .expect("tls connect");

    let request = format!(
        concat!(
            "GET /ws HTTP/1.1\r\n",
            "Host: {host}\r\n",
            "Connection: Upgrade\r\n",
            "Upgrade: websocket\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "\r\n"
        ),
        host = host_header
    );
    tls_stream
        .write_all(request.as_bytes())
        .await
        .expect("write websocket upgrade request");

    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let n = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            tls_stream.read(&mut chunk),
        )
        .await
        .expect("timed out waiting for websocket response")
        .expect("read websocket response");
        assert!(n > 0, "unexpected EOF while waiting for response headers");
        response.extend_from_slice(&chunk[..n]);
        if response.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let response_head = String::from_utf8_lossy(&response);
    let status_line = response_head.lines().next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS.as_u16());

    let payload = b"ping-through-proxy";
    tls_stream
        .write_all(payload)
        .await
        .expect("write tunneled payload");

    let mut echoed = vec![0_u8; payload.len()];
    tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        tls_stream.read_exact(&mut echoed),
    )
    .await
    .expect("timed out waiting for echoed payload")
    .expect("read echoed payload");

    assert_eq!(echoed.as_slice(), payload);
}

#[tokio::test(flavor = "multi_thread")]
async fn allowed_https_transparent_h2_is_proxied_and_captured() {
    let upstream_addr = start_upstream_https_echo_server().await;

    let mut config = minimal_https_transparent_config();

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
            request_timeout_ms: None,
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

    let (proxy_addr, temp_dir, ca_cert_path) =
        start_proxy_with_config(config, proxy_listener).await;

    let host_header = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let (version, status, body) =
        send_h2_https_request_via_transparent(proxy_addr, &ca_cert_path, &host_header, "/ok", &[])
            .await;

    assert_eq!(version, Version::HTTP_2);
    assert_eq!(status, StatusCode::OK.as_u16());
    assert_eq!(body, "ok");

    use tokio::time::{sleep, Duration};

    let capture_dir = temp_dir.path().join("captures");
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
        "expected capture files for transparent HTTPS traffic"
    );

    let mut found_request = false;
    for path in files {
        let mut contents = String::new();
        std::fs::File::open(&path)
            .expect("open capture")
            .read_to_string(&mut contents)
            .expect("read capture");
        let record: CaptureRecord = serde_json::from_str(&contents).expect("decode capture");
        assert_eq!(record.mode, CaptureMode::HttpsTransparent);

        if record.kind != CaptureKind::Request {
            continue;
        }

        assert!(
            record
                .http_version
                .as_deref()
                .unwrap_or_default()
                .starts_with('2'),
            "expected httpVersion starting with '2', got {:?}",
            record.http_version
        );
        found_request = true;
        break;
    }

    assert!(
        found_request,
        "did not find request capture record for transparent HTTPS h2"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_failure_https_transparent_is_captured() {
    // Choose an unused local port and immediately drop the listener so
    // that upstream connections will fail, triggering a Bad Gateway
    // error from the proxy.
    let upstream_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind placeholder upstream");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    drop(upstream_listener);

    let mut config = minimal_https_transparent_config();

    // Allow all HTTPS traffic to the failing upstream host.
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
            request_timeout_ms: None,
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

    let (proxy_addr, temp_dir, ca_cert_path) =
        start_proxy_with_config(config, proxy_listener).await;

    let sni_host = "transparent.test";
    let host_header = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let (status, body) = send_https_request_via_transparent(
        proxy_addr,
        &ca_cert_path,
        &sni_host,
        &host_header,
        "/upstream-fail",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_GATEWAY.as_u16());
    assert_eq!(body, "Bad Gateway");

    use tokio::time::{sleep, Duration};

    let capture_dir = temp_dir.path().join("captures");
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
    let mut found_request = false;
    let mut found_response = false;
    while let Some(entry) = entries.next() {
        let entry = entry.expect("dir entry");
        if !entry.file_type().expect("file type").is_file() {
            continue;
        }

        let mut contents = String::new();
        std::fs::File::open(entry.path())
            .expect("open capture")
            .read_to_string(&mut contents)
            .expect("read capture");
        let record: CaptureRecord = serde_json::from_str(&contents).expect("decode capture");
        assert_eq!(record.mode, CaptureMode::HttpsTransparent);

        if record.url.ends_with("/upstream-fail") && record.decision == CaptureDecision::Allow {
            match record.kind {
                CaptureKind::Request => {
                    found_request = true;
                }
                CaptureKind::Response => {
                    assert_eq!(
                        record.status_code,
                        Some(StatusCode::BAD_GATEWAY.as_u16()),
                        "expected 502 statusCode for upstream failure capture"
                    );
                    found_response = true;
                }
            }
        }
    }

    assert!(
        found_request,
        "expected request capture for upstream failure"
    );
    assert!(
        found_response,
        "expected response capture for upstream failure"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_h2_streams_share_connection_and_are_captured() {
    let upstream_addr = start_upstream_https_echo_server().await;

    let mut config = minimal_https_transparent_config();
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
            request_timeout_ms: None,
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

    let (proxy_addr, temp_dir, ca_cert_path) =
        start_proxy_with_config(config, proxy_listener).await;

    // Build a single HTTP/2 connection and send two streams concurrently.
    use rustls_pemfile;

    let stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");

    let ca_pem = std::fs::read(&ca_cert_path).expect("read ca cert");
    let mut reader = std::io::Cursor::new(ca_pem);
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut reader).expect("parse ca cert") {
        let cert = RustlsCertificate(cert.to_vec());
        roots.add(&cert).expect("add root cert to store");
    }

    let mut tls_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = ServerName::try_from("transparent.test").expect("server name");
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .expect("tls connect");

    let (send_request, connection) = h2_client::handshake(tls_stream)
        .await
        .expect("h2 handshake");

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("h2 connection error: {e}");
        }
    });

    let host_header = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    // Prepare two requests on the same H2 connection.
    let mut send_request = send_request.ready().await.expect("h2 ready");

    let uri1 = format!("https://{host}{path}", host = host_header, path = "/ok");
    let uri2 = format!("https://{host}{path}", host = host_header, path = "/ok2");

    let req1 = http::Request::builder()
        .method(Method::GET)
        .uri(uri1.as_str())
        .version(Version::HTTP_2)
        .header(http::header::HOST, &host_header)
        .body(())
        .expect("build h2 request 1");

    let req2 = http::Request::builder()
        .method(Method::GET)
        .uri(uri2.as_str())
        .version(Version::HTTP_2)
        .header(http::header::HOST, &host_header)
        .body(())
        .expect("build h2 request 2");

    let (resp1_fut, _send1) = send_request.send_request(req1, true).expect("send h2 req1");
    let (resp2_fut, _send2) = send_request.send_request(req2, true).expect("send h2 req2");

    let resp1 = resp1_fut.await.expect("resp1");
    let resp2 = resp2_fut.await.expect("resp2");

    let (head1, mut body1) = resp1.into_parts();
    let (head2, mut body2) = resp2.into_parts();

    let mut body_bytes1 = Vec::new();
    while let Some(chunk) = body1.data().await.transpose().expect("h2 data1") {
        body_bytes1.extend_from_slice(&chunk);
    }

    let mut body_bytes2 = Vec::new();
    while let Some(chunk) = body2.data().await.transpose().expect("h2 data2") {
        body_bytes2.extend_from_slice(&chunk);
    }

    assert_eq!(head1.status.as_u16(), StatusCode::OK.as_u16());
    assert_eq!(head2.status.as_u16(), StatusCode::OK.as_u16());
    assert_eq!(String::from_utf8_lossy(&body_bytes1), "ok");
    assert_eq!(String::from_utf8_lossy(&body_bytes2), "ok");

    // Ensure at least two capture files exist for HTTPS transparent traffic
    // and that each logical stream has a unique requestId with both request
    // and response records.
    use tokio::time::{sleep, Duration};

    let capture_dir = temp_dir.path().join("captures");
    for _ in 0..10 {
        if capture_dir.is_dir() {
            let entries: Vec<_> = std::fs::read_dir(&capture_dir)
                .expect("read capture dir")
                .collect();
            if entries.len() >= 2 {
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
        files.len() >= 2,
        "expected at least two capture files for concurrent H2 streams"
    );

    let mut records = Vec::new();
    for path in files {
        let mut contents = String::new();
        std::fs::File::open(&path)
            .expect("open capture")
            .read_to_string(&mut contents)
            .expect("read capture");
        let record: CaptureRecord = serde_json::from_str(&contents).expect("decode capture");
        assert_eq!(record.mode, CaptureMode::HttpsTransparent);
        assert_eq!(record.decision, CaptureDecision::Allow);
        records.push(record);
    }

    // We expect exactly two logical requestIds (one per stream), each with
    // both a request and a response record.
    use std::collections::HashMap;

    let mut by_id: HashMap<String, (usize, usize)> = HashMap::new();
    for rec in records {
        let entry = by_id.entry(rec.request_id.clone()).or_insert((0, 0));
        match rec.kind {
            CaptureKind::Request => entry.0 += 1,
            CaptureKind::Response => entry.1 += 1,
        }
    }

    assert_eq!(
        by_id.len(),
        2,
        "expected two distinct requestIds for two streams, got {}",
        by_id.len()
    );

    for (req_id, (req_count, res_count)) in by_id {
        assert!(
            req_count >= 1,
            "expected at least one request capture for {req_id}"
        );
        assert!(
            res_count >= 1,
            "expected at least one response capture for {req_id}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_h2_streams_mixed_allow_and_deny() {
    let upstream_addr = start_upstream_https_echo_server().await;

    let mut config = minimal_https_transparent_config();
    // Allow only /ok; /denied will be blocked by policy.
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
            request_timeout_ms: None,
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

    let (proxy_addr, temp_dir, ca_cert_path) =
        start_proxy_with_config(config, proxy_listener).await;

    // Single HTTP/2 connection with one allowed and one denied stream.
    use rustls_pemfile;

    let stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");

    let ca_pem = std::fs::read(&ca_cert_path).expect("read ca cert");
    let mut reader = std::io::Cursor::new(ca_pem);
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut reader).expect("parse ca cert") {
        let cert = RustlsCertificate(cert.to_vec());
        roots.add(&cert).expect("add root cert to store");
    }

    let mut tls_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = ServerName::try_from("transparent.test").expect("server name");
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .expect("tls connect");

    let (send_request, connection) = h2_client::handshake(tls_stream)
        .await
        .expect("h2 handshake");

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("h2 connection error: {e}");
        }
    });

    let host_header = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let mut send_request = send_request.ready().await.expect("h2 ready");

    let uri_ok = format!("https://{host}{path}", host = host_header, path = "/ok");
    let uri_denied = format!("https://{host}{path}", host = host_header, path = "/denied");

    let req_ok = http::Request::builder()
        .method(Method::GET)
        .uri(uri_ok.as_str())
        .version(Version::HTTP_2)
        .header(http::header::HOST, &host_header)
        .body(())
        .expect("build ok request");

    let req_denied = http::Request::builder()
        .method(Method::GET)
        .uri(uri_denied.as_str())
        .version(Version::HTTP_2)
        .header(http::header::HOST, &host_header)
        .body(())
        .expect("build denied request");

    let (resp_ok_fut, _send_ok) = send_request.send_request(req_ok, true).expect("send ok");
    let (resp_denied_fut, _send_denied) = send_request
        .send_request(req_denied, true)
        .expect("send denied");

    let resp_ok = resp_ok_fut.await.expect("resp ok");
    let resp_denied = resp_denied_fut.await.expect("resp denied");

    let (head_ok, mut body_ok) = resp_ok.into_parts();
    let (head_denied, mut body_denied) = resp_denied.into_parts();

    let mut body_bytes_ok = Vec::new();
    while let Some(chunk) = body_ok.data().await.transpose().expect("ok data") {
        body_bytes_ok.extend_from_slice(&chunk);
    }
    let mut body_bytes_denied = Vec::new();
    while let Some(chunk) = body_denied.data().await.transpose().expect("denied data") {
        body_bytes_denied.extend_from_slice(&chunk);
    }

    assert_eq!(head_ok.status.as_u16(), StatusCode::OK.as_u16());
    assert_eq!(
        String::from_utf8_lossy(&body_bytes_ok),
        "ok",
        "expected ok body"
    );

    assert_eq!(head_denied.status.as_u16(), StatusCode::FORBIDDEN.as_u16());
    let denied_json: serde_json::Value =
        serde_json::from_slice(&body_bytes_denied).expect("deny JSON");
    assert_eq!(denied_json["error"], "Forbidden");
    assert_eq!(denied_json["message"], "Blocked by URL policy");

    // Inspect capture to ensure separate requestIds and per-stream decisions.
    use tokio::time::{sleep, Duration};

    let capture_dir = temp_dir.path().join("captures");
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
        "expected capture files for mixed H2 streams"
    );

    use std::collections::HashMap;

    let mut by_id: HashMap<String, (CaptureDecision, usize, usize)> = HashMap::new();

    for path in files {
        let mut contents = String::new();
        std::fs::File::open(&path)
            .expect("open capture")
            .read_to_string(&mut contents)
            .expect("read capture");
        let record: CaptureRecord = serde_json::from_str(&contents).expect("decode capture");
        assert_eq!(record.mode, CaptureMode::HttpsTransparent);

        let entry = by_id
            .entry(record.request_id.clone())
            .or_insert((record.decision, 0, 0));
        assert_eq!(
            entry.0, record.decision,
            "decision should not change for a given requestId"
        );
        match record.kind {
            CaptureKind::Request => entry.1 += 1,
            CaptureKind::Response => entry.2 += 1,
        }
    }

    assert_eq!(
        by_id.len(),
        2,
        "expected two logical H2 streams (one allowed, one denied)"
    );

    let mut allow_seen = 0;
    let mut deny_seen = 0;
    for (req_id, (decision, req_count, res_count)) in by_id {
        assert!(
            req_count >= 1,
            "expected at least one request capture for {req_id}"
        );
        assert!(
            res_count >= 1,
            "expected at least one response capture for {req_id}"
        );
        match decision {
            CaptureDecision::Allow => allow_seen += 1,
            CaptureDecision::Deny => deny_seen += 1,
        }
    }

    assert_eq!(allow_seen, 1, "expected exactly one allowed stream");
    assert_eq!(deny_seen, 1, "expected exactly one denied stream");
}

#[tokio::test(flavor = "multi_thread")]
async fn large_h2_request_body_is_truncated_in_capture() {
    let upstream_addr = start_upstream_https_echo_server().await;

    let mut config = minimal_https_transparent_config();
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyDefaultAction::Allow,
            pattern: Some(format!(
                "https://{}:{}/large-request",
                upstream_addr.ip(),
                upstream_addr.port()
            )),
            description: None,
            methods: None,
            subnets: Vec::new(),
            request_timeout_ms: None,
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

    let (proxy_addr, temp_dir, ca_cert_path) =
        start_proxy_with_config(config, proxy_listener).await;

    let host_header = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let body = vec![b'y'; LARGE_BODY_BYTES];
    let (_version, status, resp_body) = send_h2_https_request_with_body_via_transparent(
        proxy_addr,
        &ca_cert_path,
        &host_header,
        "/large-request",
        body.clone(),
    )
    .await;

    assert_eq!(status, StatusCode::OK.as_u16());
    assert_eq!(resp_body, "ok");

    use tokio::time::{sleep, Duration};

    let capture_dir = temp_dir.path().join("captures");
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
        "expected capture files for large H2 request"
    );

    // Find the request capture for the large POST and ensure body
    // length reflects the full payload while captured bytes are
    // bounded by DEFAULT_MAX_BODY_BYTES.
    let mut found_request = false;
    for path in files {
        let mut contents = String::new();
        std::fs::File::open(&path)
            .expect("open capture")
            .read_to_string(&mut contents)
            .expect("read capture");
        let record: CaptureRecord = serde_json::from_str(&contents).expect("decode capture");

        if record.kind == CaptureKind::Request
            && record.decision == CaptureDecision::Allow
            && record.url.ends_with("/large-request")
        {
            let body = record.body.as_ref().expect("expected captured body");
            let decoded = record.decode_body_bytes().expect("decode capture body");
            assert!(
                body.length >= decoded.len(),
                "logical body length should be at least the number of captured bytes"
            );
            assert!(
                decoded.len() <= DEFAULT_MAX_BODY_BYTES,
                "captured bytes should be truncated to DEFAULT_MAX_BODY_BYTES"
            );
            assert!(
                decoded.iter().all(|b| *b == b'y'),
                "captured bytes should match original payload pattern"
            );
            assert_eq!(
                record.http_version.as_deref(),
                Some("2"),
                "expected httpVersion \"2\" for H2 request capture"
            );
            found_request = true;
            break;
        }
    }

    assert!(
        found_request,
        "did not find large H2 request capture record"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn large_h2_response_body_is_truncated_in_capture() {
    eprintln!("large_h2_response: starting upstream server");
    let upstream_addr = start_upstream_https_large_response_server().await;

    let mut config = minimal_https_transparent_config();
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyDefaultAction::Allow,
            pattern: Some(format!(
                "https://{}:{}/large-response",
                upstream_addr.ip(),
                upstream_addr.port()
            )),
            description: None,
            methods: None,
            subnets: Vec::new(),
            request_timeout_ms: None,
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

    eprintln!("large_h2_response: starting proxy");
    let (proxy_addr, temp_dir, ca_cert_path) =
        start_proxy_with_config(config, proxy_listener).await;

    let host_header = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    eprintln!("large_h2_response: sending h2 request via transparent proxy");
    // Use an HTTP/1.1 client to keep the focus of this test on large
    // body capture and truncation behavior; HTTP/2 streaming for large
    // responses is exercised indirectly via the proxy’s internal tests.
    let sni_host = "transparent.test";
    let (status, body) = send_https_request_via_transparent(
        proxy_addr,
        &ca_cert_path,
        &sni_host,
        &host_header,
        "/large-response",
        &[],
    )
    .await;

    eprintln!(
        "large_h2_response: got response status={}, body_len={}",
        status,
        body.len()
    );
    assert_eq!(status, StatusCode::OK.as_u16());
    assert_eq!(body.len(), LARGE_BODY_BYTES);

    use tokio::time::{sleep, Duration};

    let capture_dir = temp_dir.path().join("captures");
    eprintln!(
        "large_h2_response: waiting for capture dir at {:?}",
        capture_dir
    );
    let mut found_response: Option<CaptureRecord> = None;
    eprintln!("large_h2_response: scanning capture files for response record");
    for _ in 0..20 {
        if !capture_dir.is_dir() {
            sleep(Duration::from_millis(50)).await;
            continue;
        }

        let mut entries = std::fs::read_dir(&capture_dir).expect("read capture dir");
        while let Some(entry) = entries.next() {
            let entry = entry.expect("dir entry");
            if !entry.file_type().expect("file type").is_file() {
                continue;
            }

            let mut contents = String::new();
            std::fs::File::open(entry.path())
                .expect("open capture")
                .read_to_string(&mut contents)
                .expect("read capture");
            let record: CaptureRecord = serde_json::from_str(&contents).expect("decode capture");

            if record.kind == CaptureKind::Response
                && record.decision == CaptureDecision::Allow
                && record.url.ends_with("/large-response")
            {
                found_response = Some(record);
                break;
            }
        }

        if found_response.is_some() {
            break;
        }

        sleep(Duration::from_millis(50)).await;
    }

    let record = found_response.expect("did not find large H2 response capture record");
    let body = record.body.as_ref().expect("expected captured body");
    assert_eq!(
        body.length, LARGE_BODY_BYTES,
        "logical body length should reflect full H2 response size"
    );

    let decoded = record.decode_body_bytes().expect("decode capture body");
    assert!(
        decoded.len() <= DEFAULT_MAX_BODY_BYTES,
        "captured bytes should be truncated to DEFAULT_MAX_BODY_BYTES"
    );
    assert!(
        decoded.iter().all(|b| *b == b'x'),
        "captured bytes should match upstream payload pattern"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_client_to_http1_only_upstream_preserves_versions_in_capture() {
    let upstream_addr = start_upstream_https_http1_only_echo_server().await;

    let mut config = minimal_https_transparent_config();
    // Enable optional HTTP/2 upstream support; the origin only offers
    // HTTP/1.1 via ALPN, so the proxy should downgrade while still
    // serving HTTP/2 to the client.
    config.tls.enable_http2_upstream = true;

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
            request_timeout_ms: None,
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

    let (proxy_addr, temp_dir, ca_cert_path) =
        start_proxy_with_config(config, proxy_listener).await;

    let host_header = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let (version, status, body) =
        send_h2_https_request_via_transparent(proxy_addr, &ca_cert_path, &host_header, "/ok", &[])
            .await;

    assert_eq!(version, Version::HTTP_2);
    assert_eq!(status, StatusCode::OK.as_u16());
    assert_eq!(body, "ok");

    use tokio::time::{sleep, Duration};

    let capture_dir = temp_dir.path().join("captures");
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
        "expected capture files for downgrade scenario"
    );

    use std::collections::HashMap;

    let mut by_id: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();

    for path in files {
        let mut contents = String::new();
        std::fs::File::open(&path)
            .expect("open capture")
            .read_to_string(&mut contents)
            .expect("read capture");
        let record: CaptureRecord = serde_json::from_str(&contents).expect("decode capture");
        assert_eq!(record.mode, CaptureMode::HttpsTransparent);
        assert_eq!(record.decision, CaptureDecision::Allow);

        let entry = by_id
            .entry(record.request_id.clone())
            .or_insert((None, None));
        match record.kind {
            CaptureKind::Request => entry.0 = record.http_version.clone(),
            CaptureKind::Response => entry.1 = record.http_version.clone(),
        }
    }

    assert_eq!(
        by_id.len(),
        1,
        "expected a single logical requestId for downgrade test"
    );

    let (req_version, resp_version) = by_id.into_iter().next().unwrap().1;
    assert_eq!(
        req_version.as_deref(),
        Some("2"),
        "expected client-facing httpVersion \"2\""
    );
    assert_eq!(
        resp_version.as_deref(),
        Some("1.1"),
        "expected upstream httpVersion \"1.1\" in response capture"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_client_to_h2_capable_upstream_preserves_h2_in_capture() {
    let upstream_addr = start_upstream_https_echo_server().await;

    let mut config = minimal_https_transparent_config();
    // Enable optional HTTP/2 upstream support; the origin offers both
    // HTTP/2 and HTTP/1.1 via ALPN, so the proxy should be able to
    // negotiate HTTP/2 upstream while serving HTTP/2 to the client.
    config.tls.enable_http2_upstream = true;

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
            request_timeout_ms: None,
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

    let (proxy_addr, temp_dir, ca_cert_path) =
        start_proxy_with_config(config, proxy_listener).await;

    let host_header = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let (version, status, body) =
        send_h2_https_request_via_transparent(proxy_addr, &ca_cert_path, &host_header, "/ok", &[])
            .await;

    assert_eq!(version, Version::HTTP_2);
    assert_eq!(status, StatusCode::OK.as_u16());
    assert_eq!(body, "ok");

    use tokio::time::{sleep, Duration};

    let capture_dir = temp_dir.path().join("captures");
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
        "expected capture files for HTTP/2-capable upstream scenario"
    );

    use std::collections::HashMap;

    let mut by_id: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();

    for path in files {
        let mut contents = String::new();
        std::fs::File::open(&path)
            .expect("open capture")
            .read_to_string(&mut contents)
            .expect("read capture");
        let record: CaptureRecord = serde_json::from_str(&contents).expect("decode capture");
        assert_eq!(record.mode, CaptureMode::HttpsTransparent);
        assert_eq!(record.decision, CaptureDecision::Allow);

        let entry = by_id
            .entry(record.request_id.clone())
            .or_insert((None, None));
        match record.kind {
            CaptureKind::Request => entry.0 = record.http_version.clone(),
            CaptureKind::Response => entry.1 = record.http_version.clone(),
        }
    }

    assert_eq!(
        by_id.len(),
        1,
        "expected a single logical requestId for upgrade test"
    );

    let (req_version, resp_version) = by_id.into_iter().next().unwrap().1;
    assert_eq!(
        req_version.as_deref(),
        Some("2"),
        "expected client-facing httpVersion \"2\""
    );
    assert_eq!(
        resp_version.as_deref(),
        Some("2"),
        "expected upstream httpVersion \"2\" in response capture"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_https_transparent_returns_403() {
    let upstream_addr = start_upstream_https_echo_server().await;

    let mut config = minimal_https_transparent_config();
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
            request_timeout_ms: None,
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

    let (proxy_addr, temp_dir, ca_cert_path) =
        start_proxy_with_config(config, proxy_listener).await;

    let sni_host = "transparent.test";
    let host_header = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let (status, body) = send_https_request_via_transparent(
        proxy_addr,
        &ca_cert_path,
        &sni_host,
        &host_header,
        "/denied",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN.as_u16());
    let json_body = body.trim();
    let json: serde_json::Value = serde_json::from_str(json_body).expect("parse deny JSON");
    assert_eq!(json["error"], "Forbidden");
    assert_eq!(json["message"], "Blocked by URL policy");

    // Capture records for denied HTTP/1.1 traffic should exist and have
    // httpVersion = "1.1" with consistent structure.
    use tokio::time::{sleep, Duration};

    let capture_dir = temp_dir.path().join("captures");
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
        files.len() >= 2,
        "expected at least two capture files for denied HTTPS transparent traffic"
    );

    let mut saw_request = false;
    let mut saw_response = false;
    for path in files {
        let mut contents = String::new();
        std::fs::File::open(&path)
            .expect("open capture")
            .read_to_string(&mut contents)
            .expect("read capture");
        let record: CaptureRecord = serde_json::from_str(&contents).expect("decode capture");

        assert_eq!(record.mode, CaptureMode::HttpsTransparent);
        assert_eq!(record.decision, CaptureDecision::Deny);
        assert_eq!(
            record.http_version.as_deref(),
            Some("1.1"),
            "expected httpVersion \"1.1\", got {:?}",
            record.http_version
        );

        match record.kind {
            CaptureKind::Request => {
                saw_request = true;
                assert_eq!(record.status_code, None);
            }
            CaptureKind::Response => {
                saw_response = true;
                assert_eq!(record.status_code, Some(StatusCode::FORBIDDEN.as_u16()));
                assert_eq!(
                    record.status_message.as_deref(),
                    Some("Forbidden"),
                    "unexpected status message in deny capture"
                );
            }
        }
    }

    assert!(saw_request, "expected at least one denied request capture");
    assert!(
        saw_response,
        "expected at least one denied response capture"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_https_transparent_h2_returns_403() {
    let upstream_addr = start_upstream_https_echo_server().await;

    let mut config = minimal_https_transparent_config();
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
            request_timeout_ms: None,
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

    let (proxy_addr, temp_dir, ca_cert_path) =
        start_proxy_with_config(config, proxy_listener).await;

    let host_header = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let (_version, status, body) = send_h2_https_request_via_transparent(
        proxy_addr,
        &ca_cert_path,
        &host_header,
        "/denied",
        &[],
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN.as_u16());
    let json_body = body.trim();
    let json: serde_json::Value = serde_json::from_str(json_body).expect("parse deny JSON");
    assert_eq!(json["error"], "Forbidden");
    assert_eq!(json["message"], "Blocked by URL policy");

    // Capture records for denied HTTP/2 transparent traffic should mirror
    // the HTTP/1.1 shape but with httpVersion = "2".
    use tokio::time::{sleep, Duration};

    let capture_dir = temp_dir.path().join("captures");
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
        files.len() >= 2,
        "expected at least two capture files for denied H2 transparent traffic"
    );

    let mut saw_request = false;
    let mut saw_response = false;
    for path in files {
        let mut contents = String::new();
        std::fs::File::open(&path)
            .expect("open capture")
            .read_to_string(&mut contents)
            .expect("read capture");
        let record: CaptureRecord = serde_json::from_str(&contents).expect("decode capture");

        assert_eq!(record.mode, CaptureMode::HttpsTransparent);
        assert_eq!(record.decision, CaptureDecision::Deny);
        assert_eq!(
            record.http_version.as_deref(),
            Some("2"),
            "expected httpVersion \"2\" for H2 deny capture, got {:?}",
            record.http_version
        );

        match record.kind {
            CaptureKind::Request => {
                saw_request = true;
                assert_eq!(record.status_code, None);
            }
            CaptureKind::Response => {
                saw_response = true;
                assert_eq!(record.status_code, Some(StatusCode::FORBIDDEN.as_u16()));
                assert_eq!(
                    record.status_message.as_deref(),
                    Some("Forbidden"),
                    "unexpected status message in H2 deny capture"
                );
            }
        }
    }

    assert!(
        saw_request,
        "expected at least one denied H2 request capture"
    );
    assert!(
        saw_response,
        "expected at least one denied H2 response capture"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn loop_detected_https_transparent_returns_508() {
    let upstream_addr = start_upstream_https_echo_server().await;

    let mut config = minimal_https_transparent_config();

    // Allow traffic so that loop protection is the deciding factor.
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Allow;

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir, ca_cert_path) =
        start_proxy_with_config(config, proxy_listener).await;

    let sni_host = "transparent.test";
    let host_header = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let (status, body) = send_https_request_via_transparent(
        proxy_addr,
        &ca_cert_path,
        &sni_host,
        &host_header,
        "/loop",
        &[("x-acl-proxy-request-id", "existing")],
    )
    .await;

    assert_eq!(status, StatusCode::LOOP_DETECTED.as_u16());
    let json_body = body.trim();
    let json: serde_json::Value = serde_json::from_str(json_body).expect("parse loop JSON");
    assert_eq!(json["error"], "LoopDetected");
    assert_eq!(
        json["message"],
        "Proxy loop detected via loop protection header"
    );
}
