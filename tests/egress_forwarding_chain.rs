use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex};

use acl_proxy::app::AppState;
use acl_proxy::config::{
    Config, EgressTargetConfig, HeaderActionConfig, HeaderActionKind, HeaderDirection, HeaderWhen,
    PolicyDefaultAction, PolicyRuleConfig, PolicyRuleDirectConfig,
};
use acl_proxy::proxy::http::run_http_proxy_on_listener;
use http::StatusCode;
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
