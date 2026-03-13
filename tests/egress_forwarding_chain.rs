use std::io::Read;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex};

use acl_proxy::app::AppState;
use acl_proxy::capture::{CaptureKind, CaptureMode, CaptureRecord};
use acl_proxy::config::{
    Config, EgressTargetConfig, HeaderActionConfig, HeaderActionKind, HeaderDirection, HeaderWhen,
    PolicyDefaultAction, PolicyRuleConfig, PolicyRuleDirectConfig,
};
use acl_proxy::proxy::http::run_http_proxy_on_listener;
use h2::client as h2_client;
use http::header::{CONNECTION, UPGRADE};
use http::{HeaderValue, StatusCode};
use hyper::server::conn::Http;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

async fn start_http1_only_probe_server() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind http1 probe upstream");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking http1 probe upstream");
    let addr = listener.local_addr().expect("http1 probe upstream addr");

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).expect("tokio probe listener");
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };

            tokio::spawn(async move {
                let mut prefix = [0_u8; 3];
                if socket.read_exact(&mut prefix).await.is_err() {
                    return;
                }

                // If the peer starts the HTTP/2 prior-knowledge preface ("PRI"),
                // close the connection to simulate an HTTP/1.1-only egress target.
                if &prefix == b"PRI" {
                    return;
                }

                let response =
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = socket.write_all(response).await;
            });
        }
    });

    addr
}

fn minimal_config() -> Config {
    let toml = r#"
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

[policy]
default = "deny"
    "#;

    toml::from_str(toml).expect("parse config")
}

fn allow_rule(pattern: String, header_actions: Vec<HeaderActionConfig>) -> PolicyRuleConfig {
    PolicyRuleConfig::Direct(PolicyRuleDirectConfig {
        action: PolicyDefaultAction::Allow,
        pattern: Some(pattern),
        description: None,
        methods: None,
        subnets: Vec::new(),
        headers_absent: None,
        headers_match: None,
        request_timeout_ms: None,
        with: None,
        add_url_enc_variants: None,
        header_actions,
        external_auth_profile: None,
        rule_id: None,
    })
}

async fn start_proxy_with_config(mut config: Config) -> (SocketAddr, TempDir) {
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
    let listener_addr = addr;
    tokio::spawn(async move {
        let _ = run_http_proxy_on_listener(state, listener, std::future::pending())
            .await
            .map_err(|err| {
                eprintln!("proxy server on {listener_addr} exited: {err}");
            });
    });

    (addr, temp_dir)
}

async fn send_raw_http_request(addr: SocketAddr, raw_request: &str) -> (String, StatusCode) {
    let mut stream = tokio::net::TcpStream::connect(addr)
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

async fn send_h2c_http_request(addr: SocketAddr, uri: &str) -> (String, StatusCode) {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect proxy");
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
        .version(http::Version::HTTP_2)
        .body(())
        .expect("build h2 request");

    let (response_fut, _send_stream) = send_request
        .send_request(request, true)
        .expect("send h2 request");
    let response = response_fut.await.expect("await h2 response");
    let status = response.status();

    let mut body = response.into_body();
    let mut body_bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("h2 response chunk");
        body_bytes.extend_from_slice(&chunk);
    }

    (String::from_utf8_lossy(&body_bytes).to_string(), status)
}

#[tokio::test(flavor = "multi_thread")]
async fn two_proxy_chain_forwards_allowed_requests_end_to_end() {
    let (upstream_addr, seen_upstream) = start_http_echo_server("outer-upstream-ok").await;
    let upstream_url = format!("http://{}:{}/ok", upstream_addr.ip(), upstream_addr.port());
    let upstream_pattern = format!("http://{}:{}/**", upstream_addr.ip(), upstream_addr.port());
    let upstream_host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let mut outer_config = minimal_config();
    outer_config.policy.default = PolicyDefaultAction::Deny;
    outer_config.policy.rules = vec![allow_rule(upstream_pattern.clone(), Vec::new())];
    let (outer_addr, _outer_temp_dir) = start_proxy_with_config(outer_config).await;

    let mut inner_config = minimal_config();
    inner_config.policy.default = PolicyDefaultAction::Deny;
    inner_config.policy.rules = vec![allow_rule(upstream_pattern, Vec::new())];
    inner_config.loop_protection.enabled = true;
    inner_config.loop_protection.add_header = false;
    inner_config.proxy.egress.default = Some(EgressTargetConfig {
        host: "127.0.0.1".to_string(),
        port: outer_addr.port(),
    });
    let (inner_addr, _inner_temp_dir) = start_proxy_with_config(inner_config).await;

    let raw_request = format!(
        "GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        url = upstream_url,
        host = upstream_host
    );
    let (response, status) = send_raw_http_request(inner_addr, &raw_request).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        response.contains("\r\n\r\nouter-upstream-ok"),
        "unexpected response body: {response}"
    );

    let requests = seen_upstream.lock().unwrap();
    let request = requests
        .first()
        .expect("upstream should receive chained request");
    assert_eq!(request.uri, "/ok");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_proxy_chain_preserves_http2_on_inner_to_outer_hop() {
    let (upstream_addr, seen_upstream) = start_http_echo_server("outer-upstream-h2").await;
    let upstream_url = format!("http://{}:{}/h2", upstream_addr.ip(), upstream_addr.port());
    let upstream_pattern = format!("http://{}:{}/**", upstream_addr.ip(), upstream_addr.port());

    let mut outer_config = minimal_config();
    outer_config.policy.default = PolicyDefaultAction::Deny;
    outer_config.policy.rules = vec![allow_rule(upstream_pattern.clone(), Vec::new())];
    outer_config.capture.allowed_request = true;
    outer_config.capture.allowed_response = false;
    let (outer_addr, outer_temp_dir) = start_proxy_with_config(outer_config).await;

    let mut inner_config = minimal_config();
    inner_config.policy.default = PolicyDefaultAction::Deny;
    inner_config.policy.rules = vec![allow_rule(upstream_pattern, Vec::new())];
    inner_config.loop_protection.enabled = true;
    inner_config.loop_protection.add_header = false;
    inner_config.proxy.egress.default = Some(EgressTargetConfig {
        host: "127.0.0.1".to_string(),
        port: outer_addr.port(),
    });
    let (inner_addr, _inner_temp_dir) = start_proxy_with_config(inner_config).await;

    let (body, status) = send_h2c_http_request(inner_addr, &upstream_url).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "outer-upstream-h2");

    let requests = seen_upstream.lock().unwrap();
    let request = requests
        .first()
        .expect("upstream should receive chained request");
    assert_eq!(request.uri, "/h2");

    let capture_dir = outer_temp_dir.path().join("captures");
    for _ in 0..20 {
        if capture_dir.is_dir() {
            let entries: Vec<_> = std::fs::read_dir(&capture_dir)
                .expect("read capture dir")
                .collect();
            if !entries.is_empty() {
                break;
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    let mut found_request_record = false;
    for entry in std::fs::read_dir(&capture_dir).expect("read capture dir") {
        let entry = entry.expect("capture entry");
        if !entry.file_type().expect("capture file type").is_file() {
            continue;
        }

        let mut contents = String::new();
        std::fs::File::open(entry.path())
            .expect("open capture file")
            .read_to_string(&mut contents)
            .expect("read capture file");
        let record: CaptureRecord = serde_json::from_str(&contents).expect("decode capture");

        if record.kind != CaptureKind::Request || record.mode != CaptureMode::HttpProxy {
            continue;
        }
        if record.url != upstream_url {
            continue;
        }

        assert!(
            record
                .http_version
                .as_deref()
                .unwrap_or_default()
                .starts_with('2'),
            "expected outer proxy to observe HTTP/2 chain hop, got {:?}",
            record.http_version
        );
        found_request_record = true;
        break;
    }

    assert!(
        found_request_record,
        "did not find outer proxy capture record for chained HTTP/2 request"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_proxy_chain_preserves_http1_upgrade_tunneling() {
    let upstream_addr = start_upstream_websocket_echo_server().await;
    let upstream_url = format!("http://{}:{}/ws", upstream_addr.ip(), upstream_addr.port());
    let upstream_pattern = format!("http://{}:{}/**", upstream_addr.ip(), upstream_addr.port());
    let upstream_host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let mut outer_config = minimal_config();
    outer_config.policy.default = PolicyDefaultAction::Deny;
    outer_config.policy.rules = vec![allow_rule(upstream_pattern.clone(), Vec::new())];
    let (outer_addr, _outer_temp_dir) = start_proxy_with_config(outer_config).await;

    let mut inner_config = minimal_config();
    inner_config.policy.default = PolicyDefaultAction::Deny;
    inner_config.policy.rules = vec![allow_rule(upstream_pattern, Vec::new())];
    inner_config.loop_protection.enabled = true;
    inner_config.loop_protection.add_header = false;
    inner_config.proxy.egress.default = Some(EgressTargetConfig {
        host: "127.0.0.1".to_string(),
        port: outer_addr.port(),
    });
    let (inner_addr, _inner_temp_dir) = start_proxy_with_config(inner_config).await;

    let mut stream = tokio::net::TcpStream::connect(inner_addr)
        .await
        .expect("connect inner proxy");
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

    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let n = tokio::time::timeout(tokio::time::Duration::from_secs(2), stream.read(&mut chunk))
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

    let payload = b"ping-through-chain-upgrade";
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
async fn h2_chain_hop_to_http1_only_egress_returns_bad_gateway_without_downgrade() {
    let probe_addr = start_http1_only_probe_server().await;

    let mut inner_config = minimal_config();
    inner_config.policy.default = PolicyDefaultAction::Deny;
    inner_config.policy.rules = vec![allow_rule(
        "http://example.invalid/**".to_string(),
        Vec::new(),
    )];
    inner_config.loop_protection.enabled = true;
    inner_config.loop_protection.add_header = false;
    inner_config.proxy.egress.default = Some(EgressTargetConfig {
        host: "127.0.0.1".to_string(),
        port: probe_addr.port(),
    });
    let (inner_addr, _inner_temp_dir) = start_proxy_with_config(inner_config).await;

    let (_body, status) =
        send_h2c_http_request(inner_addr, "http://example.invalid/no-downgrade").await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

#[tokio::test(flavor = "multi_thread")]
async fn header_action_trust_chain_removes_then_sets_identity_header() {
    let (upstream_addr, seen_upstream) = start_http_echo_server("trusted-header-ok").await;
    let upstream_url = format!(
        "http://{}:{}/repo",
        upstream_addr.ip(),
        upstream_addr.port()
    );
    let upstream_pattern = format!("http://{}:{}/**", upstream_addr.ip(), upstream_addr.port());
    let upstream_host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let mut outer_config = minimal_config();
    outer_config.policy.default = PolicyDefaultAction::Deny;
    outer_config.policy.rules = vec![allow_rule(upstream_pattern.clone(), Vec::new())];
    let (outer_addr, _outer_temp_dir) = start_proxy_with_config(outer_config).await;

    let mut inner_config = minimal_config();
    inner_config.policy.default = PolicyDefaultAction::Deny;
    inner_config.policy.rules = vec![allow_rule(
        upstream_pattern,
        vec![
            HeaderActionConfig {
                direction: HeaderDirection::Request,
                action: HeaderActionKind::Remove,
                name: "x-forwarded-user".to_string(),
                when: HeaderWhen::Always,
                value: None,
                values: None,
                search: None,
                replace: None,
            },
            HeaderActionConfig {
                direction: HeaderDirection::Request,
                action: HeaderActionKind::Set,
                name: "x-forwarded-user".to_string(),
                when: HeaderWhen::Always,
                value: Some("trusted-user".to_string()),
                values: None,
                search: None,
                replace: None,
            },
        ],
    )];
    inner_config.loop_protection.add_header = false;
    inner_config.proxy.egress.default = Some(EgressTargetConfig {
        host: "127.0.0.1".to_string(),
        port: outer_addr.port(),
    });
    let (inner_addr, _inner_temp_dir) = start_proxy_with_config(inner_config).await;

    let raw_request = format!(
        concat!(
            "GET {url} HTTP/1.1\r\n",
            "Host: {host}\r\n",
            "X-Forwarded-User: attacker\r\n",
            "Connection: close\r\n",
            "\r\n"
        ),
        url = upstream_url,
        host = upstream_host
    );
    let (_response, status) = send_raw_http_request(inner_addr, &raw_request).await;

    assert_eq!(status, StatusCode::OK);

    let requests = seen_upstream.lock().unwrap();
    let request = requests
        .first()
        .expect("upstream should receive chained request");
    assert_eq!(
        request
            .headers
            .get("x-forwarded-user")
            .and_then(|value| value.to_str().ok()),
        Some("trusted-user")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unavailable_egress_destination_returns_bad_gateway() {
    let mut config = minimal_config();
    config.policy.default = PolicyDefaultAction::Deny;
    config.policy.rules = vec![allow_rule(
        "http://example.invalid/**".to_string(),
        Vec::new(),
    )];
    config.proxy.egress.default = Some(EgressTargetConfig {
        host: "127.0.0.1".to_string(),
        port: 1,
    });
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config).await;

    let raw_request =
        "GET http://example.invalid/unreachable HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n";
    let (_response, status) = send_raw_http_request(proxy_addr, raw_request).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

#[tokio::test(flavor = "multi_thread")]
async fn inner_proxy_can_disable_loop_header_injection_for_chained_deployments() {
    let (upstream_addr, seen_upstream) = start_http_echo_server("loop-strategy-ok").await;
    let upstream_url = format!(
        "http://{}:{}/loop",
        upstream_addr.ip(),
        upstream_addr.port()
    );
    let upstream_pattern = format!("http://{}:{}/**", upstream_addr.ip(), upstream_addr.port());
    let upstream_host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let mut outer_config = minimal_config();
    outer_config.policy.default = PolicyDefaultAction::Deny;
    outer_config.policy.rules = vec![allow_rule(upstream_pattern.clone(), Vec::new())];
    outer_config.loop_protection.enabled = true;
    outer_config.loop_protection.add_header = true;
    let (outer_addr, _outer_temp_dir) = start_proxy_with_config(outer_config).await;

    let mut inner_config = minimal_config();
    inner_config.policy.default = PolicyDefaultAction::Deny;
    inner_config.policy.rules = vec![allow_rule(upstream_pattern, Vec::new())];
    inner_config.loop_protection.enabled = true;
    inner_config.loop_protection.add_header = false;
    inner_config.proxy.egress.default = Some(EgressTargetConfig {
        host: "127.0.0.1".to_string(),
        port: outer_addr.port(),
    });
    let (inner_addr, _inner_temp_dir) = start_proxy_with_config(inner_config).await;

    let raw_request = format!(
        "GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        url = upstream_url,
        host = upstream_host
    );
    let (_response, status) = send_raw_http_request(inner_addr, &raw_request).await;

    assert_eq!(status, StatusCode::OK);

    let requests = seen_upstream.lock().unwrap();
    let request = requests
        .first()
        .expect("upstream should receive chained request");
    assert!(
        request.headers.get("x-acl-proxy-request-id").is_some(),
        "outer proxy should still inject its loop-protection header"
    );
}
