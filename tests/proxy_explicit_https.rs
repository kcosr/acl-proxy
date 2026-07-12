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
use h2::client as h2_client;
use http::header::{HeaderValue, CONNECTION, UPGRADE};
use http::StatusCode;
use hyper::server::conn::Http;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::client::ServerName;
use rustls::{
    Certificate as RustlsCertificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};

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

async fn start_https_echo_server(body: &'static str) -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind HTTPS upstream");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking HTTPS upstream");
    let addr = listener.local_addr().expect("HTTPS upstream addr");

    let mut params = CertificateParams::new(vec![addr.ip().to_string()]).expect("params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, addr.ip().to_string());
    params.distinguished_name = dn;
    let key = KeyPair::generate().expect("generate upstream key");
    let cert = params.self_signed(&key).expect("self-signed upstream cert");

    let mut tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![RustlsCertificate(cert.der().to_vec())],
            PrivateKey(key.serialize_der()),
        )
        .expect("upstream server config");
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).expect("tokio HTTPS listener");
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let tls_acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                let tls = match tls_acceptor.accept(socket).await {
                    Ok(tls) => tls,
                    Err(_) => return,
                };
                let service = service_fn(move |_req: Request<Body>| async move {
                    Ok::<_, hyper::Error>(Response::new(Body::from(body)))
                });
                let _ = Http::new()
                    .http1_keep_alive(false)
                    .serve_connection(tls, service)
                    .await;
            });
        }
    });

    addr
}

async fn start_upstream_websocket_echo_server() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind websocket upstream");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking websocket upstream");
    let addr = listener.local_addr().expect("websocket upstream addr");

    tokio::spawn(async move {
        let listener =
            tokio::net::TcpListener::from_std(listener).expect("tokio websocket listener");
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };

            tokio::spawn(async move {
                let service = service_fn(|mut req: Request<Body>| async move {
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

                    let mut resp = Response::new(Body::empty());
                    *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                    resp.headers_mut()
                        .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
                    resp.headers_mut()
                        .insert(UPGRADE, HeaderValue::from_static("websocket"));
                    Ok::<_, hyper::Error>(resp)
                });

                let _ = Http::new()
                    .http1_keep_alive(false)
                    .serve_connection(socket, service)
                    .with_upgrades()
                    .await;
            });
        }
    });

    addr
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
schema_version = "2"

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
    let tls_block = format!(
        r#"[proxy.egress.default.tls]
trust = "custom_ca"
server_name = "127.0.0.1"
ca_cert_path = {ca_cert_path:?}
"#,
        ca_cert_path = ca_cert_path.display().to_string(),
    );
    explicit_http_config_with_https_parent_tls_block(parent_addr, Some(&tls_block), allow_pattern)
}

fn explicit_http_config_with_https_parent_tls_block(
    parent_addr: SocketAddr,
    tls_block: Option<&str>,
    allow_pattern: &str,
) -> Config {
    let toml = format!(
        r#"
schema_version = "2"

[proxy]
listeners.explicit_http.bind = "127.0.0.1:1"

[proxy.egress.default]
type = "explicit_proxy"
transport = "https"
host = "127.0.0.1"
port = {parent_port}

{tls_block}

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
        tls_block = tls_block.unwrap_or(""),
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
    let request = format!(
        "GET {absolute_url} HTTP/1.1\r\nHost: ignored-by-explicit-proxy.test\r\nConnection: close\r\n\r\n"
    );
    send_explicit_https_raw_request(proxy_addr, ca_cert_path, &request).await
}

async fn send_explicit_https_raw_request(
    proxy_addr: SocketAddr,
    ca_cert_path: &Path,
    request: &str,
) -> (StatusCode, String) {
    let mut tls = open_explicit_https_proxy_tls(proxy_addr, ca_cert_path).await;
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

async fn open_explicit_https_proxy_tls(
    proxy_addr: SocketAddr,
    ca_cert_path: &Path,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    open_explicit_https_proxy_tls_with_alpn(proxy_addr, ca_cert_path, vec![b"http/1.1".to_vec()])
        .await
}

async fn open_explicit_https_proxy_tls_with_alpn(
    proxy_addr: SocketAddr,
    ca_cert_path: &Path,
    alpn_protocols: Vec<Vec<u8>>,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
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
    config.alpn_protocols = alpn_protocols;

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from("127.0.0.1").expect("server name");
    connector
        .connect(server_name, stream)
        .await
        .expect("tls connect")
}

async fn send_https_via_explicit_https_connect(
    proxy_addr: SocketAddr,
    proxy_cert_path: &Path,
    mitm_ca_cert_path: &Path,
    target_host: &str,
    path: &str,
) -> (StatusCode, String) {
    let mut outer_tls = open_explicit_https_proxy_tls(proxy_addr, proxy_cert_path).await;
    let connect_req = format!(
        "CONNECT {target_host} HTTP/1.1\r\nHost: {target_host}\r\nConnection: keep-alive\r\n\r\n"
    );
    outer_tls
        .write_all(connect_req.as_bytes())
        .await
        .expect("write CONNECT");

    let (_head, connect_status) = read_http_response_head(&mut outer_tls)
        .await
        .expect("read CONNECT response");
    if connect_status != StatusCode::OK {
        return (connect_status, String::new());
    }

    let ca_pem = std::fs::read(mitm_ca_cert_path).expect("read MITM CA cert");
    let mut reader = Cursor::new(ca_pem);
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut reader).expect("parse MITM CA cert") {
        roots
            .add(&RustlsCertificate(cert.to_vec()))
            .expect("add MITM CA cert root");
    }

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let host_only = target_host.split(':').next().expect("target host name");
    let server_name = ServerName::try_from(host_only).expect("target server name");
    let mut inner_tls = connector
        .connect(server_name, outer_tls)
        .await
        .expect("inner TLS connect");

    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n");
    inner_tls
        .write_all(request.as_bytes())
        .await
        .expect("write inner HTTPS request");
    let mut buf = Vec::new();
    inner_tls
        .read_to_end(&mut buf)
        .await
        .expect("read inner HTTPS response");
    parse_http_response(&buf)
}

async fn send_https_via_explicit_http_connect(
    proxy_addr: SocketAddr,
    mitm_ca_cert_path: &Path,
    target_host: &str,
    path: &str,
) -> (StatusCode, String) {
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

    let (_head, connect_status) = read_http_response_head(&mut stream)
        .await
        .expect("read CONNECT response");
    if connect_status != StatusCode::OK {
        return (connect_status, String::new());
    }

    let ca_pem = std::fs::read(mitm_ca_cert_path).expect("read MITM CA cert");
    let mut reader = Cursor::new(ca_pem);
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut reader).expect("parse MITM CA cert") {
        roots
            .add(&RustlsCertificate(cert.to_vec()))
            .expect("add MITM CA cert root");
    }

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let host_only = target_host.split(':').next().expect("target host name");
    let server_name = ServerName::try_from(host_only).expect("target server name");
    let mut inner_tls = connector
        .connect(server_name, stream)
        .await
        .expect("inner TLS connect");

    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n");
    inner_tls
        .write_all(request.as_bytes())
        .await
        .expect("write inner HTTPS request");
    let mut buf = Vec::new();
    inner_tls
        .read_to_end(&mut buf)
        .await
        .expect("read inner HTTPS response");
    parse_http_response(&buf)
}

async fn send_h2c_http_request(addr: SocketAddr, uri: &str) -> (String, StatusCode) {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect h2c proxy");
    let (send_request, connection) = h2_client::handshake(stream).await.expect("h2 handshake");
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            eprintln!("h2 connection error: {err}");
        }
    });

    let mut send_request = send_request.ready().await.expect("h2 ready");
    let request = http::Request::builder()
        .method("GET")
        .uri(uri)
        .body(())
        .expect("build h2 request");
    let (response_fut, _send_stream) = send_request
        .send_request(request, true)
        .expect("send h2 request");
    let response = response_fut.await.expect("await h2 response");
    let status = response.status();
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("h2 response chunk");
        bytes.extend_from_slice(&chunk);
    }
    (String::from_utf8_lossy(&bytes).to_string(), status)
}

async fn send_h2_request_via_explicit_https(
    proxy_addr: SocketAddr,
    proxy_cert_path: &Path,
    method: &str,
    uri: &str,
) -> StatusCode {
    let tls = open_explicit_https_proxy_tls_with_alpn(
        proxy_addr,
        proxy_cert_path,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    )
    .await;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));

    let (send_request, connection) = h2_client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            eprintln!("h2 explicit HTTPS connection error: {err}");
        }
    });

    let mut send_request = send_request.ready().await.expect("h2 ready");
    let request = http::Request::builder()
        .method(method)
        .uri(uri)
        .body(())
        .expect("build h2 request");
    let (response_fut, _send_stream) = send_request
        .send_request(request, true)
        .expect("send h2 request");
    response_fut.await.expect("await h2 response").status()
}

async fn read_http_response_head<R>(reader: &mut R) -> std::io::Result<(String, StatusCode)>
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

    let head = String::from_utf8_lossy(&buf).to_string();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Ok((head, status))
}

async fn read_until_contains<R>(reader: &mut R, needle: &[u8]) -> Vec<u8>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 1024];
    loop {
        let n = tokio::time::timeout(tokio::time::Duration::from_secs(2), reader.read(&mut tmp))
            .await
            .expect("timed out waiting for response")
            .expect("read response");
        assert!(n > 0, "unexpected EOF before response contained needle");
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(needle.len()).any(|window| window == needle) {
            return buf;
        }
    }
}

fn parse_http_response(buf: &[u8]) -> (StatusCode, String) {
    let response = String::from_utf8_lossy(buf).to_string();
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .expect("response status");
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .to_string();
    (status, body)
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

#[test]
fn explicit_https_static_identity_rejects_malformed_and_mismatched_material() {
    let identity_dir = TempDir::new().expect("identity dir");
    let (cert_path, key_path) = write_proxy_identity(&identity_dir);
    let config = explicit_https_config(&cert_path, &key_path, "http://example.test/**");
    let listener = config
        .proxy
        .listeners
        .explicit_https
        .as_ref()
        .expect("explicit HTTPS listener");

    std::fs::write(&cert_path, "not a PEM certificate\n").expect("write malformed cert");
    let err = build_static_tls_acceptor(listener)
        .err()
        .expect("malformed cert should fail");
    assert!(err.to_string().contains("at least one PEM certificate"));

    let chain_identity = TempDir::new().expect("chain identity dir");
    let (cert_path, key_path) = write_proxy_identity(&chain_identity);
    let mut cert_bundle = std::fs::read_to_string(&cert_path).expect("read cert bundle");
    cert_bundle.push_str("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n");
    std::fs::write(&cert_path, cert_bundle).expect("write malformed intermediate");
    let config = explicit_https_config(&cert_path, &key_path, "http://example.test/**");
    let listener = config
        .proxy
        .listeners
        .explicit_https
        .as_ref()
        .expect("explicit HTTPS listener");
    let err = build_static_tls_acceptor(listener)
        .err()
        .expect("malformed intermediate should fail");
    assert!(err.to_string().contains("failed to parse certificate 2"));

    let first_identity = TempDir::new().expect("first identity dir");
    let second_identity = TempDir::new().expect("second identity dir");
    let (cert_path, _) = write_proxy_identity(&first_identity);
    let (_, key_path) = write_proxy_identity(&second_identity);
    let config = explicit_https_config(&cert_path, &key_path, "http://example.test/**");
    let listener = config
        .proxy
        .listeners
        .explicit_https
        .as_ref()
        .expect("explicit HTTPS listener");
    let err = build_static_tls_acceptor(listener)
        .err()
        .expect("mismatched key should fail");
    assert!(err.to_string().contains("does not match private key"));
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_https_serves_internal_endpoints_before_origin_form_rejection() {
    let identity_dir = TempDir::new().expect("identity dir");
    let (cert_path, key_path) = write_proxy_identity(&identity_dir);
    let config = explicit_https_config(&cert_path, &key_path, "http://example.test/**");
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind explicit HTTPS proxy");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _proxy_temp_dir) = start_explicit_https_proxy(config, listener).await;

    let ready_request =
        "GET /_acl-proxy/ready HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n";
    let (status, _) = send_explicit_https_raw_request(proxy_addr, &cert_path, ready_request).await;
    assert_eq!(status, StatusCode::OK);

    let origin_request =
        "GET /not-internal HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n";
    let (status, _) = send_explicit_https_raw_request(proxy_addr, &cert_path, origin_request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
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
async fn explicit_https_listener_defaults_to_http1_alpn() {
    let (upstream_addr, _seen_requests) = start_http_echo_server("unused").await;
    let identity_dir = TempDir::new().expect("identity dir");
    let (cert_path, key_path) = write_proxy_identity(&identity_dir);
    let allow_pattern = format!("http://{}:{}/**", upstream_addr.ip(), upstream_addr.port());
    let config = explicit_https_config(&cert_path, &key_path, &allow_pattern);

    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind explicit https proxy");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _proxy_temp_dir) = start_explicit_https_proxy(config, listener).await;

    let tls = open_explicit_https_proxy_tls_with_alpn(
        proxy_addr,
        &cert_path,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    )
    .await;

    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_https_h2_connect_returns_501() {
    let (upstream_addr, _seen_requests) = start_http_echo_server("unused").await;
    let identity_dir = TempDir::new().expect("identity dir");
    let (cert_path, key_path) = write_proxy_identity(&identity_dir);
    let allow_pattern = format!("http://{}:{}/**", upstream_addr.ip(), upstream_addr.port());
    let mut config = explicit_https_config(&cert_path, &key_path, &allow_pattern);
    config
        .proxy
        .listeners
        .explicit_https
        .as_mut()
        .expect("explicit HTTPS listener")
        .enable_http2 = true;

    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind explicit https proxy");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _proxy_temp_dir) = start_explicit_https_proxy(config, listener).await;

    let status = send_h2_request_via_explicit_https(
        proxy_addr,
        &cert_path,
        "CONNECT",
        "connect-target.test:443",
    )
    .await;

    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_https_listener_supports_connect_mitm_over_http1() {
    let upstream_addr = start_https_echo_server("explicit https connect ok").await;
    let identity_dir = TempDir::new().expect("identity dir");
    let (cert_path, key_path) = write_proxy_identity(&identity_dir);
    let allow_pattern = format!("https://{}:{}/**", upstream_addr.ip(), upstream_addr.port());
    let config = explicit_https_config(&cert_path, &key_path, &allow_pattern);

    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind explicit https proxy");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, proxy_temp_dir) = start_explicit_https_proxy(config, listener).await;

    let target_host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let mitm_ca_cert_path = proxy_temp_dir.path().join("certs").join("ca-cert.pem");
    let (status, body) = send_https_via_explicit_https_connect(
        proxy_addr,
        &cert_path,
        &mitm_ca_cert_path,
        &target_host,
        "/ok",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("explicit https connect ok"),
        "unexpected response body: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_https_listener_tunnels_websocket_upgrades() {
    let upstream_addr = start_upstream_websocket_echo_server().await;
    let identity_dir = TempDir::new().expect("identity dir");
    let (cert_path, key_path) = write_proxy_identity(&identity_dir);
    let allow_pattern = format!("http://{}:{}/**", upstream_addr.ip(), upstream_addr.port());
    let config = explicit_https_config(&cert_path, &key_path, &allow_pattern);

    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind explicit https proxy");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _proxy_temp_dir) = start_explicit_https_proxy(config, listener).await;

    let mut tls = open_explicit_https_proxy_tls(proxy_addr, &cert_path).await;
    let upstream_url = format!("http://{}:{}/ws", upstream_addr.ip(), upstream_addr.port());
    let upstream_host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let request = format!(
        concat!(
            "GET {url} HTTP/1.1\r\n",
            "Host: {host}\r\n",
            "Connection: Upgrade\r\n",
            "Upgrade: websocket\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "\r\n"
        ),
        url = upstream_url,
        host = upstream_host
    );
    tls.write_all(request.as_bytes())
        .await
        .expect("write websocket upgrade request");

    let (_head, status) = read_http_response_head(&mut tls)
        .await
        .expect("read websocket response");
    assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS);

    let payload = b"explicit-https-websocket";
    tls.write_all(payload)
        .await
        .expect("write tunneled payload");
    let mut echoed = vec![0_u8; payload.len()];
    tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        tls.read_exact(&mut echoed),
    )
    .await
    .expect("timed out waiting for echoed payload")
    .expect("read echoed payload");

    assert_eq!(echoed.as_slice(), payload);
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_https_listener_shutdown_closes_idle_keep_alive_connection() {
    let (upstream_addr, _seen_requests) = start_http_echo_server("shutdown ok").await;
    let identity_dir = TempDir::new().expect("identity dir");
    let (cert_path, key_path) = write_proxy_identity(&identity_dir);
    let allow_pattern = format!("http://{}:{}/**", upstream_addr.ip(), upstream_addr.port());
    let mut config = explicit_https_config(&cert_path, &key_path, &allow_pattern);

    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind explicit https proxy");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let proxy_addr = listener.local_addr().expect("proxy addr");

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

    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_for_task = shutdown.clone();
    let server_task = tokio::spawn(async move {
        run_explicit_https_proxy_on_listener(
            state,
            listener,
            tls_acceptor,
            listener_cfg,
            async move {
                shutdown_for_task.notified().await;
            },
        )
        .await
    });

    let absolute_url = format!(
        "http://{}:{}/keepalive",
        upstream_addr.ip(),
        upstream_addr.port()
    );
    let mut tls = open_explicit_https_proxy_tls(proxy_addr, &cert_path).await;
    let request = format!(
        "GET {absolute_url} HTTP/1.1\r\nHost: ignored.test\r\nConnection: keep-alive\r\n\r\n"
    );
    tls.write_all(request.as_bytes())
        .await
        .expect("write keep-alive request");
    let response = read_until_contains(&mut tls, b"shutdown ok").await;
    assert!(
        String::from_utf8_lossy(&response).contains("200 OK"),
        "unexpected response: {}",
        String::from_utf8_lossy(&response)
    );

    shutdown.notify_waiters();
    tokio::time::timeout(tokio::time::Duration::from_secs(2), server_task)
        .await
        .expect("explicit HTTPS listener did not stop after shutdown")
        .expect("listener task join")
        .expect("listener shutdown result");
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_https_shutdown_interrupts_unbounded_tls_handshake() {
    let identity_dir = TempDir::new().expect("identity dir");
    let (cert_path, key_path) = write_proxy_identity(&identity_dir);
    let mut config = explicit_https_config(&cert_path, &key_path, "http://example.test/**");
    config
        .proxy
        .listeners
        .explicit_https
        .as_mut()
        .expect("explicit HTTPS listener")
        .handshake_timeout_ms = 0;

    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind explicit HTTPS proxy");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let proxy_addr = listener.local_addr().expect("proxy addr");
    let listener_cfg = config
        .proxy
        .listeners
        .explicit_https
        .as_ref()
        .expect("explicit HTTPS listener")
        .clone();
    let tls_acceptor = build_static_tls_acceptor(&listener_cfg).expect("static TLS acceptor");
    let state = AppState::shared_from_config(config).expect("app state");
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_for_task = shutdown.clone();
    let server_task = tokio::spawn(async move {
        run_explicit_https_proxy_on_listener(
            state,
            listener,
            tls_acceptor,
            listener_cfg,
            async move { shutdown_for_task.notified().await },
        )
        .await
    });

    let _silent_client = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect silent TLS client");
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    shutdown.notify_waiters();
    tokio::time::timeout(tokio::time::Duration::from_secs(2), server_task)
        .await
        .expect("listener did not interrupt silent TLS handshake")
        .expect("listener task join")
        .expect("listener shutdown result");
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

#[tokio::test(flavor = "multi_thread")]
async fn h2_request_to_https_parent_requires_h2_alpn_without_downgrade() {
    let (upstream_addr, seen_requests) = start_http_echo_server("should not downgrade").await;
    let identity_dir = TempDir::new().expect("identity dir");
    let (cert_path, key_path) = write_proxy_identity(&identity_dir);
    let allow_pattern = format!("http://{}:{}/**", upstream_addr.ip(), upstream_addr.port());

    let mut parent_config = explicit_https_config(&cert_path, &key_path, &allow_pattern);
    parent_config
        .proxy
        .listeners
        .explicit_https
        .as_mut()
        .expect("parent explicit HTTPS listener")
        .enable_http2 = false;
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
        "http://{}:{}/h2-parent",
        upstream_addr.ip(),
        upstream_addr.port()
    );
    let (_body, status) = send_h2c_http_request(inner_addr, &absolute_url).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(
        seen_requests.lock().unwrap().is_empty(),
        "HTTP/2 requests must not downgrade to HTTP/1.1 on an HTTPS parent hop"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_upgrade_can_tunnel_over_https_parent() {
    let upstream_addr = start_upstream_websocket_echo_server().await;
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

    let mut stream = tokio::net::TcpStream::connect(inner_addr)
        .await
        .expect("connect inner proxy");
    let upstream_url = format!("http://{}:{}/ws", upstream_addr.ip(), upstream_addr.port());
    let upstream_host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let request = format!(
        concat!(
            "GET {url} HTTP/1.1\r\n",
            "Host: {host}\r\n",
            "Connection: Upgrade\r\n",
            "Upgrade: websocket\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "\r\n"
        ),
        url = upstream_url,
        host = upstream_host
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write websocket upgrade request");

    let (_head, status) = read_http_response_head(&mut stream)
        .await
        .expect("read websocket response");
    assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS);

    let payload = b"https-parent-websocket";
    stream
        .write_all(payload)
        .await
        .expect("write tunneled payload");
    let mut echoed = vec![0_u8; payload.len()];
    tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        stream.read_exact(&mut echoed),
    )
    .await
    .expect("timed out waiting for echoed payload")
    .expect("read echoed payload");

    assert_eq!(echoed.as_slice(), payload);
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_request_can_forward_to_h2_enabled_https_parent() {
    let (upstream_addr, seen_requests) = start_http_echo_server("h2 https parent ok").await;
    let identity_dir = TempDir::new().expect("identity dir");
    let (cert_path, key_path) = write_proxy_identity(&identity_dir);
    let allow_pattern = format!("http://{}:{}/**", upstream_addr.ip(), upstream_addr.port());

    let mut parent_config = explicit_https_config(&cert_path, &key_path, &allow_pattern);
    parent_config
        .proxy
        .listeners
        .explicit_https
        .as_mut()
        .expect("parent explicit HTTPS listener")
        .enable_http2 = true;
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
        "http://{}:{}/h2-parent-ok",
        upstream_addr.ip(),
        upstream_addr.port()
    );
    let (body, status) = send_h2c_http_request(inner_addr, &absolute_url).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "h2 https parent ok");

    let seen = seen_requests.lock().unwrap();
    let request = seen.first().expect("upstream request");
    assert_eq!(request.uri, "/h2-parent-ok");
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_inner_requests_can_forward_to_https_parent() {
    let (forward_addr, seen_requests) = start_http_echo_server("connect via https parent").await;
    let identity_dir = TempDir::new().expect("identity dir");
    let (cert_path, key_path) = write_proxy_identity(&identity_dir);
    let allow_pattern = "https://connect-target.test:9443/**";

    let mut parent_config = explicit_https_config(&cert_path, &key_path, allow_pattern);
    parent_config.proxy.egress.default =
        Some(acl_proxy::config::EgressTargetConfig::explicit_http_proxy(
            "127.0.0.1".to_string(),
            forward_addr.port(),
        ));
    let parent_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind parent proxy");
    parent_listener
        .set_nonblocking(true)
        .expect("set nonblocking parent proxy");
    let (parent_addr, _parent_temp_dir) =
        start_explicit_https_proxy(parent_config, parent_listener).await;

    let mut inner_config =
        explicit_http_config_with_https_parent(parent_addr, &cert_path, allow_pattern);
    inner_config.loop_protection.add_header = false;
    let (inner_addr, inner_temp_dir) = start_explicit_http_proxy(inner_config).await;
    let inner_ca_cert_path = inner_temp_dir.path().join("certs").join("ca-cert.pem");

    let (status, body) = send_https_via_explicit_http_connect(
        inner_addr,
        &inner_ca_cert_path,
        "connect-target.test:9443",
        "/ok",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("connect via https parent"),
        "unexpected response body: {body}"
    );

    let seen = seen_requests.lock().unwrap();
    let forwarded = seen.first().expect("forwarding destination request");
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
async fn https_parent_egress_fails_closed_when_parent_cert_is_untrusted() {
    let (upstream_addr, seen_requests) = start_http_echo_server("should not arrive").await;
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
        explicit_http_config_with_https_parent_tls_block(parent_addr, None, &allow_pattern);
    inner_config.loop_protection.add_header = false;
    let (inner_addr, _inner_temp_dir) = start_explicit_http_proxy(inner_config).await;

    let absolute_url = format!(
        "http://{}:{}/via-untrusted-parent",
        upstream_addr.ip(),
        upstream_addr.port()
    );
    let (status, _response) = send_raw_http_request(inner_addr, &absolute_url).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(
        seen_requests.lock().unwrap().is_empty(),
        "untrusted parent certificate should fail before reaching upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn https_parent_egress_trust_disabled_accepts_untrusted_parent_cert() {
    let (upstream_addr, seen_requests) = start_http_echo_server("trust disabled ok").await;
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

    let tls_block = r#"[proxy.egress.default.tls]
trust = "disabled"
server_name = "127.0.0.1"
"#;
    let mut inner_config = explicit_http_config_with_https_parent_tls_block(
        parent_addr,
        Some(tls_block),
        &allow_pattern,
    );
    inner_config.loop_protection.add_header = false;
    let (inner_addr, _inner_temp_dir) = start_explicit_http_proxy(inner_config).await;

    let absolute_url = format!(
        "http://{}:{}/via-disabled-trust-parent",
        upstream_addr.ip(),
        upstream_addr.port()
    );
    let (status, response) = send_raw_http_request(inner_addr, &absolute_url).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        response.contains("\r\n\r\ntrust disabled ok"),
        "unexpected response: {response}"
    );
    assert_eq!(seen_requests.lock().unwrap().len(), 1);
}
