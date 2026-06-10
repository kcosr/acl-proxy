#![allow(clippy::await_holding_lock)]

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex};

use acl_proxy::app::AppState;
use acl_proxy::config::{
    Config, EgressTargetConfig, ExternalAuthProfileConfig, ExternalAuthProfileType,
};
use acl_proxy::external_auth::ExternalDecision;
use acl_proxy::proxy::http::run_http_proxy_on_listener;
use http::StatusCode;
use hyper::service::{make_service_fn, service_fn};
use hyper::{body, Body, Request, Response, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
struct ObservedRequest {
    uri: String,
    headers: hyper::HeaderMap,
}

async fn start_upstream_echo_server() -> (SocketAddr, Arc<Mutex<Option<hyper::HeaderMap>>>) {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind upstream");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking upstream");
    let addr = listener.local_addr().expect("upstream addr");

    let seen_headers: Arc<Mutex<Option<hyper::HeaderMap>>> = Arc::new(Mutex::new(None));
    let seen_headers_clone = seen_headers.clone();

    let make_svc = make_service_fn(move |_conn| {
        let seen_headers = seen_headers_clone.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                let seen_headers = seen_headers.clone();
                async move {
                    *seen_headers.lock().unwrap() = Some(req.headers().clone());
                    Ok::<_, hyper::Error>(Response::new(Body::from("ok")))
                }
            }))
        }
    });

    let server = Server::from_tcp(listener)
        .expect("server from tcp")
        .serve(make_svc);
    tokio::spawn(server);

    (addr, seen_headers)
}

async fn start_observed_echo_server(
    body: &'static str,
) -> (SocketAddr, Arc<Mutex<Vec<ObservedRequest>>>) {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind upstream");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking upstream");
    let addr = listener.local_addr().expect("upstream addr");

    let observed: Arc<Mutex<Vec<ObservedRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let observed_clone = observed.clone();

    let make_svc = make_service_fn(move |_conn| {
        let observed = observed_clone.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                let observed = observed.clone();
                async move {
                    observed.lock().unwrap().push(ObservedRequest {
                        uri: req.uri().to_string(),
                        headers: req.headers().clone(),
                    });
                    Ok::<_, hyper::Error>(Response::new(Body::from(body)))
                }
            }))
        }
    });

    let server = Server::from_tcp(listener)
        .expect("server from tcp")
        .serve(make_svc);
    tokio::spawn(server);

    (addr, observed)
}

async fn start_status_webhook_server() -> (SocketAddr, mpsc::Receiver<serde_json::Value>) {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind webhook");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking webhook");
    let addr = listener.local_addr().expect("webhook addr");
    let (tx, rx) = mpsc::channel::<serde_json::Value>(8);

    let make_svc = make_service_fn(move |_conn| {
        let tx = tx.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                let tx = tx.clone();
                async move {
                    let bytes = body::to_bytes(req.into_body()).await?;
                    let payload: serde_json::Value =
                        serde_json::from_slice(&bytes).expect("status webhook json");
                    let _ = tx.send(payload).await;
                    Ok::<_, hyper::Error>(Response::new(Body::from("ok")))
                }
            }))
        }
    });

    tokio::spawn(
        Server::from_tcp(listener)
            .expect("server from tcp")
            .serve(make_svc),
    );

    (addr, rx)
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

fn prepare_app_config_for_reload_tests(config: &mut Config, certs_dir: &std::path::Path) {
    config.logging.directory = None;
    config.certificates.certs_dir = certs_dir.display().to_string();
}

fn http_external_auth_profile() -> ExternalAuthProfileConfig {
    ExternalAuthProfileConfig {
        profile_type: ExternalAuthProfileType::Http,
        webhook_url: Some("http://127.0.0.1:9/webhook".to_string()),
        timeout_ms: 60_000,
        webhook_timeout_ms: Some(1_000),
        on_webhook_failure: None,
        command: None,
        args: Vec::new(),
        include_headers: Vec::new(),
        include_request_body: false,
        max_request_body_bytes: 10 * 1024 * 1024,
        max_decompressed_request_body_bytes: 50 * 1024 * 1024,
        env: std::collections::BTreeMap::new(),
        restart_delay_ms: None,
    }
}

async fn start_proxy_with_shared_state(
    state: acl_proxy::app::SharedAppState,
    listener: StdTcpListener,
    shutdown: Arc<tokio::sync::Notify>,
) -> SocketAddr {
    let addr = listener.local_addr().expect("proxy addr");
    let listener_addr = addr;

    tokio::spawn(async move {
        let _ = run_http_proxy_on_listener(state, listener, async move {
            shutdown.notified().await;
        })
        .await
        .map_err(|e| {
            eprintln!("proxy server on {listener_addr} exited: {e}");
        });
    });

    addr
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
async fn loop_header_injection_updates_after_reload() {
    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;

    let mut config = minimal_config();

    // Allow all traffic to the upstream host.
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some(format!(
                "http://{}:{}/**",
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

    // Start with loop protection enabled but header injection disabled.
    config.loop_protection.enabled = true;
    config.loop_protection.add_header = false;

    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let shared_state = AppState::shared_from_config(config.clone()).expect("app state");

    let shutdown = Arc::new(tokio::sync::Notify::new());
    let proxy_addr =
        start_proxy_with_shared_state(shared_state.clone(), listener, shutdown.clone()).await;

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let raw_request =
        format!("GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    let (_response, status) = send_raw_http_request(proxy_addr, &raw_request).await;
    assert_eq!(status, StatusCode::OK);

    // Upstream should NOT see the loop header with the initial config.
    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard.as_ref().expect("upstream should see request");
    assert!(
        upstream_headers.get("x-acl-proxy-request-id").is_none(),
        "loop header should not be injected before reload"
    );
    drop(headers_guard);

    // Reload configuration enabling header injection.
    let mut updated = config.clone();
    updated.loop_protection.enabled = true;
    updated.loop_protection.add_header = true;
    AppState::reload_shared_from_config(&shared_state, updated).expect("reload config");

    // Send another request; this one should carry the loop header.
    let (response, status) = send_raw_http_request(proxy_addr, &raw_request).await;
    assert_eq!(status, StatusCode::OK);
    println!("reload loop header test response:\n{response}");

    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard
        .as_ref()
        .expect("upstream should see request after reload");

    assert!(
        upstream_headers.get("x-acl-proxy-request-id").is_some(),
        "loop header should be injected after reload"
    );

    shutdown.notify_waiters();
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_reload_keeps_previous_state() {
    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;

    let mut config = minimal_config();

    // Allow all traffic to the upstream host.
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some(format!(
                "http://{}:{}/**",
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

    // Start with header injection enabled.
    config.loop_protection.enabled = true;
    config.loop_protection.add_header = true;

    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let shared_state = AppState::shared_from_config(config.clone()).expect("app state");

    let shutdown = Arc::new(tokio::sync::Notify::new());
    let proxy_addr =
        start_proxy_with_shared_state(shared_state.clone(), listener, shutdown.clone()).await;

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let raw_request =
        format!("GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    let (_response, status) = send_raw_http_request(proxy_addr, &raw_request).await;
    assert_eq!(status, StatusCode::OK);

    // Upstream should see the loop header with the initial config.
    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard.as_ref().expect("upstream should see request");
    assert!(
        upstream_headers.get("x-acl-proxy-request-id").is_some(),
        "loop header should be injected before failed reload"
    );
    drop(headers_guard);

    // Attempt to reload with an invalid loop protection header name.
    let mut invalid = config.clone();
    invalid.loop_protection.enabled = true;
    invalid.loop_protection.header_name = "invalid header name".to_string();
    let err = AppState::reload_shared_from_config(&shared_state, invalid)
        .expect_err("reload should fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("loop_protection.header_name must be a valid HTTP header name"),
        "unexpected reload error: {msg}"
    );

    // A new request should still see the header injected, proving the
    // previous working state was preserved.
    let (_response, status) = send_raw_http_request(proxy_addr, &raw_request).await;
    assert_eq!(status, StatusCode::OK);

    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard
        .as_ref()
        .expect("upstream should see request after failed reload");
    assert!(
        upstream_headers.get("x-acl-proxy-request-id").is_some(),
        "loop header should still be injected after failed reload"
    );

    shutdown.notify_waiters();
}

#[test]
fn egress_forwarding_config_updates_after_reload() {
    let temp = tempfile::tempdir().expect("temp certs dir");

    let mut config = minimal_config();
    prepare_app_config_for_reload_tests(&mut config, temp.path());

    let shared_state = AppState::shared_from_config(config.clone()).expect("app state");
    assert!(
        shared_state.load().config.proxy.egress.default.is_none(),
        "egress target should be absent before reload"
    );

    let mut updated = config.clone();
    updated.proxy.egress.default = Some(EgressTargetConfig {
        host: "proxy.internal".to_string(),
        port: 9443,
    });

    AppState::reload_shared_from_config(&shared_state, updated).expect("reload config");

    let current = shared_state.load();
    let target = current
        .config
        .proxy
        .egress
        .default
        .as_ref()
        .expect("egress target should exist after reload");
    assert_eq!(target.host, "proxy.internal");
    assert_eq!(target.port, 9443);
}

#[test]
fn invalid_egress_forwarding_config_is_rejected_on_reload() {
    let temp = tempfile::tempdir().expect("temp certs dir");

    let mut config = minimal_config();
    prepare_app_config_for_reload_tests(&mut config, temp.path());

    let shared_state = AppState::shared_from_config(config.clone()).expect("app state");

    let mut invalid = config.clone();
    invalid.proxy.egress.default = Some(EgressTargetConfig {
        host: "proxy.internal:9443".to_string(),
        port: 9443,
    });

    let err = AppState::reload_shared_from_config(&shared_state, invalid)
        .expect_err("reload should fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("proxy.egress.default.host must not include a port suffix"),
        "unexpected reload error: {msg}"
    );
    assert!(
        shared_state.load().config.proxy.egress.default.is_none(),
        "failed reload should preserve the previous state"
    );
}

#[tokio::test]
async fn reload_preserves_pending_external_auth_approvals() {
    let temp = tempfile::tempdir().expect("temp certs dir");

    let mut config = minimal_config();
    prepare_app_config_for_reload_tests(&mut config, temp.path());
    config
        .policy
        .external_auth_profiles
        .insert("approval".to_string(), http_external_auth_profile());

    let shared_state = AppState::shared_from_config(config.clone()).expect("initial state");
    let initial = shared_state.load_full();

    let (_guard, decision_rx) = initial.external_auth.start_pending(
        "req-reload".to_string(),
        0,
        None,
        "approval".to_string(),
        "http://example.com/".to_string(),
        Some("GET".to_string()),
        Some("127.0.0.1".to_string()),
        Vec::new(),
    );
    assert_eq!(initial.external_auth.pending_count(), 1);

    let mut updated = config;
    updated.loop_protection.enabled = true;
    AppState::reload_shared_from_config(&shared_state, updated).expect("reload config");

    let reloaded = shared_state.load_full();
    assert_eq!(reloaded.external_auth.pending_count(), 1);
    let mut macro_values = BTreeMap::new();
    macro_values.insert("token".to_string(), "from-reloaded-callback".to_string());
    reloaded
        .external_auth
        .store_macro_values("req-reload", macro_values);
    assert_eq!(initial.external_auth.stored_macro_count(), 1);
    assert!(
        reloaded
            .external_auth
            .resolve("req-reload", ExternalDecision::Allow),
        "post-reload manager should resolve pre-reload pending request"
    );
    assert_eq!(decision_rx.await, Ok(ExternalDecision::Allow));
    let taken_macros = initial.external_auth.take_macro_values("req-reload");
    assert_eq!(
        taken_macros.get("token").map(String::as_str),
        Some("from-reloaded-callback")
    );
    assert_eq!(reloaded.external_auth.pending_count(), 0);
    assert_eq!(reloaded.external_auth.stored_macro_count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn external_auth_status_webhook_config_updates_after_reload() {
    let temp = tempfile::tempdir().expect("temp certs dir");
    let (first_addr, mut first_rx) = start_status_webhook_server().await;
    let (second_addr, mut second_rx) = start_status_webhook_server().await;

    let mut config = minimal_config();
    prepare_app_config_for_reload_tests(&mut config, temp.path());
    let mut profile = http_external_auth_profile();
    profile.webhook_url = Some(format!("http://{first_addr}/status"));
    config
        .policy
        .external_auth_profiles
        .insert("approval".to_string(), profile);

    let shared_state = AppState::shared_from_config(config.clone()).expect("initial state");
    let initial = shared_state.load_full();
    let (_guard, _decision_rx) = initial.external_auth.start_pending(
        "req-before-reload".to_string(),
        0,
        None,
        "approval".to_string(),
        "http://example.com/".to_string(),
        Some("GET".to_string()),
        Some("127.0.0.1".to_string()),
        Vec::new(),
    );
    initial
        .external_auth
        .finalize_timed_out("req-before-reload");

    let first_event = tokio::time::timeout(std::time::Duration::from_secs(2), first_rx.recv())
        .await
        .expect("first status webhook timed out")
        .expect("first status webhook channel closed");
    assert_eq!(first_event["requestId"], "req-before-reload");

    let mut updated = config;
    updated
        .policy
        .external_auth_profiles
        .get_mut("approval")
        .expect("profile")
        .webhook_url = Some(format!("http://{second_addr}/status"));
    AppState::reload_shared_from_config(&shared_state, updated).expect("reload config");

    let reloaded = shared_state.load_full();
    let (_guard, _decision_rx) = reloaded.external_auth.start_pending(
        "req-after-reload".to_string(),
        0,
        None,
        "approval".to_string(),
        "http://example.com/".to_string(),
        Some("GET".to_string()),
        Some("127.0.0.1".to_string()),
        Vec::new(),
    );
    reloaded
        .external_auth
        .finalize_timed_out("req-after-reload");

    let second_event = tokio::time::timeout(std::time::Duration::from_secs(2), second_rx.recv())
        .await
        .expect("second status webhook timed out")
        .expect("second status webhook channel closed");
    assert_eq!(second_event["requestId"], "req-after-reload");
}

#[tokio::test]
async fn late_external_auth_macro_values_are_not_orphaned() {
    let temp = tempfile::tempdir().expect("temp certs dir");

    let mut config = minimal_config();
    prepare_app_config_for_reload_tests(&mut config, temp.path());
    config
        .policy
        .external_auth_profiles
        .insert("approval".to_string(), http_external_auth_profile());

    let state = AppState::from_config(config).expect("state");

    let (_guard, _decision_rx) = state.external_auth.start_pending(
        "req-late-macro".to_string(),
        0,
        None,
        "approval".to_string(),
        "http://example.com/".to_string(),
        Some("GET".to_string()),
        Some("127.0.0.1".to_string()),
        Vec::new(),
    );
    assert_eq!(state.external_auth.pending_count(), 1);

    state.external_auth.finalize_timed_out("req-late-macro");
    assert_eq!(state.external_auth.pending_count(), 0);

    let mut macro_values = BTreeMap::new();
    macro_values.insert("token".to_string(), "late-secret".to_string());
    assert!(
        !state.external_auth.resolve_with_macro_values(
            "req-late-macro",
            ExternalDecision::Allow,
            Some(macro_values),
        ),
        "late callback should not resolve a finalized request"
    );

    assert_eq!(state.external_auth.stored_macro_count(), 0);
    assert!(state
        .external_auth
        .take_macro_values("req-late-macro")
        .is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn egress_forwarding_enable_disable_updates_after_reload() {
    let (direct_addr, direct_requests) = start_observed_echo_server("direct").await;
    let (forward_addr, forward_requests) = start_observed_echo_server("forwarded").await;

    let mut config = minimal_config();
    let temp = tempfile::tempdir().expect("temp certs dir");
    prepare_app_config_for_reload_tests(&mut config, temp.path());
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some(format!(
                "http://{}:{}/**",
                direct_addr.ip(),
                direct_addr.port()
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

    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let shared_state = AppState::shared_from_config(config.clone()).expect("app state");
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let proxy_addr =
        start_proxy_with_shared_state(shared_state.clone(), listener, shutdown.clone()).await;

    let direct_host = format!("{}:{}", direct_addr.ip(), direct_addr.port());
    let raw_request =
        format!("GET http://{direct_host}/reload HTTP/1.1\r\nHost: {direct_host}\r\nConnection: close\r\n\r\n");

    let (response, status) = send_raw_http_request(proxy_addr, &raw_request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        response.contains("\r\n\r\ndirect"),
        "expected direct upstream response before reload: {response}"
    );
    assert_eq!(direct_requests.lock().unwrap().len(), 1);
    assert_eq!(forward_requests.lock().unwrap().len(), 0);

    let mut enabled = config.clone();
    enabled.proxy.egress.default = Some(EgressTargetConfig {
        host: "127.0.0.1".to_string(),
        port: forward_addr.port(),
    });
    AppState::reload_shared_from_config(&shared_state, enabled).expect("reload config");

    let (response, status) = send_raw_http_request(proxy_addr, &raw_request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        response.contains("\r\n\r\nforwarded"),
        "expected forwarding response after enable reload: {response}"
    );
    assert_eq!(direct_requests.lock().unwrap().len(), 1);
    let forwarded = forward_requests.lock().unwrap();
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0].uri, format!("http://{direct_host}/reload"));
    assert_eq!(
        forwarded[0]
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok()),
        Some(direct_host.as_str())
    );
    drop(forwarded);

    AppState::reload_shared_from_config(&shared_state, config).expect("reload config");

    let (response, status) = send_raw_http_request(proxy_addr, &raw_request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        response.contains("\r\n\r\ndirect"),
        "expected direct upstream response after disable reload: {response}"
    );
    assert_eq!(direct_requests.lock().unwrap().len(), 2);
    assert_eq!(forward_requests.lock().unwrap().len(), 1);

    shutdown.notify_waiters();
}
