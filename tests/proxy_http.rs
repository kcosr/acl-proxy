use std::io::Read;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use acl_proxy::app::AppState;
use acl_proxy::config::Config;
use acl_proxy::proxy::http::run_http_proxy_on_listener;
use http::header::HeaderValue;
use http::StatusCode;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use serde_json::Value as JsonValue;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
                    let mut resp = Response::new(Body::from("ok"));
                    resp.headers_mut()
                        .insert("x-upstream-tag", HeaderValue::from_static("old-tag"));
                    Ok::<_, hyper::Error>(resp)
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

async fn start_upstream_delayed_server(delay: Duration) -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind upstream");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking upstream");
    let addr = listener.local_addr().expect("upstream addr");

    let make_svc = make_service_fn(move |_conn| {
        let delay = delay;
        async move {
            Ok::<_, hyper::Error>(service_fn(move |_req: Request<Body>| {
                let delay = delay;
                async move {
                    tokio::time::sleep(delay).await;
                    Ok::<_, hyper::Error>(Response::new(Body::from("ok")))
                }
            }))
        }
    });

    let server = Server::from_tcp(listener)
        .expect("server from tcp")
        .serve(make_svc);
    tokio::spawn(server);

    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn external_auth_webhook_failure_emits_status_event() {
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Body, Request, Response, Server};
    use std::time::Duration;

    #[derive(Clone, Debug)]
    struct ReceivedEvent {
        event_header: String,
        body: serde_json::Value,
    }

    let events: Arc<Mutex<Vec<ReceivedEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let events_clone = events.clone();

    let make_svc = make_service_fn(move |_conn| {
        let events = events_clone.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                let events = events.clone();
                async move {
                    let event_header = req
                        .headers()
                        .get("x-acl-proxy-event")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_ascii_lowercase();

                    let bytes = hyper::body::to_bytes(req.into_body())
                        .await
                        .unwrap_or_default();
                    let body: serde_json::Value =
                        serde_json::from_slice(&bytes).unwrap_or_else(|_| serde_json::json!({}));

                    events.lock().unwrap().push(ReceivedEvent {
                        event_header: event_header.clone(),
                        body: body.clone(),
                    });

                    let status = if event_header == "pending" {
                        http::StatusCode::INTERNAL_SERVER_ERROR
                    } else {
                        http::StatusCode::OK
                    };

                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(status)
                            .body(Body::from("ok"))
                            .unwrap(),
                    )
                }
            }))
        }
    });

    let webhook_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind webhook");
    webhook_listener
        .set_nonblocking(true)
        .expect("set nonblocking webhook");
    let webhook_addr = webhook_listener.local_addr().expect("webhook addr");

    tokio::spawn(
        Server::from_tcp(webhook_listener)
            .expect("server from tcp")
            .serve(make_svc),
    );

    let callback_url = "https://proxy.example.com/_acl-proxy/external-auth/callback";

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

[external_auth]
callback_url = "{callback}"

[policy]
default = "deny"

[policy.external_auth_profiles]
[policy.external_auth_profiles.test_profile]
webhook_url = "http://{addr}/webhook"
timeout_ms = 1000
webhook_timeout_ms = 200
on_webhook_failure = "error"

[[policy.rules]]
action = "allow"
pattern = "http://example.com/**"
description = "External auth test rule"
external_auth_profile = "test_profile"
rule_id = "external-auth-test-rule"
    "#,
        addr = webhook_addr,
        callback = callback_url
    );

    let config: Config = toml::from_str(&toml).expect("parse config");

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let raw_request =
        "GET http://example.com/ok HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";

    let (_response, status) = send_raw_http_request(proxy_addr, raw_request).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    tokio::time::sleep(Duration::from_millis(200)).await;

    let events_guard = events.lock().unwrap();
    let pending_event = events_guard
        .iter()
        .find(|e| e.event_header == "pending")
        .unwrap_or_else(|| panic!("expected pending webhook event"));
    let status_event = events_guard
        .iter()
        .find(|e| e.event_header == "status")
        .unwrap_or_else(|| panic!("expected status webhook event"));

    assert_eq!(
        status_event.body["status"],
        serde_json::Value::String("webhook_failed".to_string())
    );
    assert_eq!(status_event.body["terminal"], serde_json::Value::Bool(true));
    assert_eq!(
        status_event.body["failureKind"],
        serde_json::Value::String("non_2xx".to_string())
    );
    assert_eq!(
        status_event.body["ruleId"],
        serde_json::Value::String("external-auth-test-rule".to_string())
    );
    assert_eq!(
        pending_event.body["callbackUrl"],
        serde_json::Value::String(callback_url.to_string())
    );
    assert_eq!(
        status_event.body["callbackUrl"],
        serde_json::Value::String(callback_url.to_string())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn approval_macros_are_exposed_and_applied() {
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Body, Request, Response, Server};

    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;

    #[derive(Clone, Debug)]
    struct PendingEvent {
        body: serde_json::Value,
    }

    let pending_event: Arc<Mutex<Option<PendingEvent>>> = Arc::new(Mutex::new(None));
    let pending_event_clone = pending_event.clone();

    let proxy_addr_shared: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let proxy_addr_for_svc = proxy_addr_shared.clone();

    let make_svc = make_service_fn(move |_conn| {
        let pending_event = pending_event_clone.clone();
        let proxy_addr_for_svc = proxy_addr_for_svc.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                let pending_event = pending_event.clone();
                let proxy_addr_for_svc = proxy_addr_for_svc.clone();
                async move {
                    let event_header = req
                        .headers()
                        .get("x-acl-proxy-event")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_ascii_lowercase();

                    let bytes = hyper::body::to_bytes(req.into_body())
                        .await
                        .unwrap_or_default();
                    let body: serde_json::Value =
                        serde_json::from_slice(&bytes).unwrap_or_else(|_| serde_json::json!({}));

                    if event_header == "pending" {
                        {
                            let mut guard = pending_event.lock().unwrap();
                            *guard = Some(PendingEvent { body: body.clone() });
                        }

                        if let Some(request_id) = body
                            .get("requestId")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                        {
                            if let Some(proxy_addr) = *proxy_addr_for_svc.lock().unwrap() {
                                let callback_body = serde_json::json!({
                                    "requestId": request_id,
                                    "decision": "allow",
                                    "macros": {
                                        "github_token": "ghp_test_token",
                                        "reason": "Approving for test"
                                    }
                                });

                                let client = hyper::Client::new();
                                let uri = format!(
                                    "http://{}/_acl-proxy/external-auth/callback",
                                    proxy_addr
                                );

                                tokio::spawn(async move {
                                    let req = Request::builder()
                                        .method("POST")
                                        .uri(uri)
                                        .header(
                                            http::header::CONTENT_TYPE,
                                            HeaderValue::from_static("application/json"),
                                        )
                                        .body(Body::from(
                                            serde_json::to_vec(&callback_body)
                                                .unwrap_or_else(|_| b"{}".to_vec()),
                                        ))
                                        .unwrap();
                                    let _ = client.request(req).await;
                                });
                            }
                        }

                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(http::StatusCode::OK)
                                .body(Body::from("ok"))
                                .unwrap(),
                        )
                    } else {
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(http::StatusCode::OK)
                                .body(Body::from("ok"))
                                .unwrap(),
                        )
                    }
                }
            }))
        }
    });

    let webhook_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind webhook");
    webhook_listener
        .set_nonblocking(true)
        .expect("set nonblocking webhook");
    let webhook_addr = webhook_listener.local_addr().expect("webhook addr");

    tokio::spawn(
        Server::from_tcp(webhook_listener)
            .expect("server from tcp")
            .serve(make_svc),
    );

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

[policy]
default = "deny"

[policy.approval_macros]
github_token = {{ label = "GitHub token", required = true, secret = true }}
reason = {{ label = "Approval reason", required = false, secret = false }}

[policy.external_auth_profiles]
[policy.external_auth_profiles.test_profile]
webhook_url = "http://{addr}/webhook"
timeout_ms = 5000
webhook_timeout_ms = 1000
on_webhook_failure = "error"

[[policy.rules]]
action = "allow"
pattern = "http://{host}/**"
description = "External auth with macros"
external_auth_profile = "test_profile"

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "authorization"
value = "token {{{{github_token}}}}"

[[policy.rules.header_actions]]
direction = "request"
action = "add"
name = "x-approval-reason"
value = "{{{{reason}}}}"
"#,
        addr = webhook_addr,
        host = host
    );

    let config: Config = toml::from_str(&toml).expect("parse config");

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;
    {
        let mut guard = proxy_addr_shared.lock().unwrap();
        *guard = Some(proxy_addr);
    }

    let raw_request =
        format!("GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    let (_response, status) = send_raw_http_request(proxy_addr, &raw_request).await;
    assert_eq!(status, StatusCode::OK);

    // Verify that upstream saw interpolated headers.
    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard.as_ref().expect("upstream should see request");

    assert_eq!(
        upstream_headers
            .get("authorization")
            .and_then(|v| v.to_str().ok()),
        Some("token ghp_test_token")
    );
    assert_eq!(
        upstream_headers
            .get("x-approval-reason")
            .and_then(|v| v.to_str().ok()),
        Some("Approving for test")
    );

    // Verify that the pending webhook exposed macro descriptors.
    let pending_guard = pending_event.lock().unwrap();
    let pending = pending_guard
        .as_ref()
        .expect("expected pending external auth event");
    let macros = pending
        .body
        .get("macros")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    assert_eq!(macros.len(), 2, "expected two macro descriptors");

    let mut names: Vec<String> = macros
        .iter()
        .filter_map(|m| {
            m.get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["github_token".to_string(), "reason".to_string()]
    );

    assert!(
        pending.body.get("callbackUrl").is_none(),
        "callbackUrl should be omitted when no external_auth.callback_url is configured"
    );

    for m in macros {
        let name = m.get("name").and_then(|v| v.as_str()).unwrap_or("");
        match name {
            "github_token" => {
                assert_eq!(
                    m.get("label").and_then(|v| v.as_str()),
                    Some("GitHub token")
                );
                assert_eq!(m.get("required").and_then(|v| v.as_bool()), Some(true));
                assert_eq!(m.get("secret").and_then(|v| v.as_bool()), Some(true));
            }
            "reason" => {
                assert_eq!(
                    m.get("label").and_then(|v| v.as_str()),
                    Some("Approval reason")
                );
                assert_eq!(m.get("required").and_then(|v| v.as_bool()), Some(false));
                assert_eq!(m.get("secret").and_then(|v| v.as_bool()), Some(false));
            }
            other => panic!("unexpected macro name {other}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_plugin_allows_and_applies_headers() {
    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;

    let temp_dir = TempDir::new().expect("temp dir");
    let script_path = temp_dir.path().join("auth-plugin.sh");
    let script = r#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf "%s" "$line" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p')
  if [ -z "$id" ]; then
    continue
  fi
  auth=$(printf "%s" "$line" | sed -n 's/.*"authorization"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p')
  if echo "$auth" | grep -q "allow"; then
    printf '{"id":"%s","type":"response","decision":"allow","requestHeaders":[{"action":"remove","name":"authorization","when":"if_present"}],"responseHeaders":[{"action":"set","name":"x-auth-plugin","value":"demo"}]}\n' "$id"
  else
    printf '{"id":"%s","type":"response","decision":"deny"}\n' "$id"
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

[policy]
default = "deny"

[policy.external_auth_profiles]
[policy.external_auth_profiles.gitlab_acl]
type = "plugin"
command = "{script_path}"
timeout_ms = 1000
include_headers = ["authorization"]

[[policy.rules]]
action = "allow"
pattern = "http://{host}/**"
external_auth_profile = "gitlab_acl"

[[policy.rules.header_actions]]
direction = "response"
action = "set"
name = "x-auth-plugin"
value = "static"
"#,
        script_path = script_path.to_string_lossy(),
        host = host
    );

    let config: Config = toml::from_str(&toml).expect("parse config");
    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let raw_request = format!(
        "GET http://{host}/repo1 HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer allow\r\nConnection: close\r\n\r\n"
    );
    let (response, status) = send_raw_http_request(proxy_addr, &raw_request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(response
        .to_ascii_lowercase()
        .contains("x-auth-plugin: demo"));
    assert!(!response
        .to_ascii_lowercase()
        .contains("x-auth-plugin: static"));

    tokio::time::sleep(Duration::from_millis(50)).await;
    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard.as_ref().expect("upstream should see request");
    assert!(upstream_headers.get("authorization").is_none());

    let deny_request = format!(
        "GET http://{host}/repo1 HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer deny\r\nConnection: close\r\n\r\n"
    );
    let (_deny_response, deny_status) = send_raw_http_request(proxy_addr, &deny_request).await;
    assert_eq!(deny_status, StatusCode::FORBIDDEN);
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

async fn start_proxy_with_config(
    mut config: Config,
    listener: StdTcpListener,
) -> (SocketAddr, TempDir) {
    let addr = listener.local_addr().expect("proxy addr");

    let temp_dir = TempDir::new().expect("temp dir for capture");
    let capture_dir = temp_dir.path().join("captures");
    config.capture.directory = capture_dir.to_string_lossy().to_string();

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
async fn allowed_request_is_proxied_and_loop_header_added() {
    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;

    let mut config = minimal_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;

    // Allow all traffic to the upstream host.
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyDefaultAction::Allow,
            pattern: Some(format!(
                "http://{}:{}/**",
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

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let raw_request =
        format!("GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    let (response, status) = send_raw_http_request(proxy_addr, &raw_request).await;

    println!("allowed_request raw response:\n{response}");

    assert_eq!(status, StatusCode::OK);
    assert!(
        response.contains("\r\n\r\nok"),
        "response body should contain 'ok', got: {response}"
    );

    // Ensure the upstream saw the loop protection header and host header.
    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard.as_ref().expect("upstream should see request");

    assert!(
        upstream_headers.get("x-acl-proxy-request-id").is_some(),
        "upstream should receive loop protection header"
    );
    assert_eq!(
        upstream_headers.get("host").and_then(|v| v.to_str().ok()),
        Some(host.as_str())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn loop_header_not_added_when_disabled() {
    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;

    let mut config = minimal_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;

    // Allow all traffic to the upstream host.
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyDefaultAction::Allow,
            pattern: Some(format!(
                "http://{}:{}/**",
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

    // Disable outbound loop header injection.
    config.loop_protection.enabled = true;
    config.loop_protection.add_header = false;

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let raw_request =
        format!("GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    let (_response, status) = send_raw_http_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::OK);

    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard.as_ref().expect("upstream should see request");

    assert!(
        upstream_headers.get("x-acl-proxy-request-id").is_none(),
        "loop header should not be injected when add_header=false"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_request_returns_403_and_captures() {
    let mut config = minimal_config();
    config.capture.denied_request = true;
    config.capture.denied_response = true;

    // Default deny policy with no allow rules.
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules.clear();

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let host = "example.com:80";
    let raw_request =
        format!("GET http://{host}/denied HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    let (response, status) = send_raw_http_request(proxy_addr, &raw_request).await;

    println!("denied_request raw response:\n{response}");

    assert_eq!(status, StatusCode::FORBIDDEN);
    let body = response.split("\r\n\r\n").nth(1).unwrap_or_default().trim();
    let json: JsonValue = serde_json::from_str(body).expect("parse deny JSON");
    assert_eq!(json["error"], "Forbidden");
    assert_eq!(json["message"], "Blocked by URL policy");

    // Capture files for denied request/response should exist.
    let capture_dir = temp_dir.path().join("captures");
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
        "expected at least two capture files, found {}",
        files.len()
    );

    // Basic shape check on one capture file.
    let mut contents = String::new();
    std::fs::File::open(&files[0])
        .expect("open capture")
        .read_to_string(&mut contents)
        .expect("read capture");
    let record: acl_proxy::capture::CaptureRecord =
        serde_json::from_str(&contents).expect("decode capture");
    assert_eq!(record.mode, acl_proxy::capture::CaptureMode::HttpProxy);
    assert!(
        !record.request_id.is_empty(),
        "request_id should be non-empty"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn loop_detected_returns_508() {
    let mut config = minimal_config();
    config.capture.denied_request = true;
    config.capture.denied_response = true;

    // Loop protection enabled with default header.
    config.loop_protection.enabled = true;
    config.loop_protection.add_header = true;

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let host = "example.com:80";
    let raw_request = format!(
        "GET http://{host}/loop HTTP/1.1\r\nHost: {host}\r\nx-acl-proxy-request-id: existing\r\nConnection: close\r\n\r\n"
    );

    let (response, status) = send_raw_http_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::LOOP_DETECTED);
    let body = response.split("\r\n\r\n").nth(1).unwrap_or_default().trim();
    let json: JsonValue = serde_json::from_str(body).expect("parse loop JSON");
    assert_eq!(json["error"], "LoopDetected");
    assert_eq!(
        json["message"],
        "Proxy loop detected via loop protection header"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn non_absolute_form_request_returns_400() {
    let mut config = minimal_config();
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Allow;

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    // Origin-form request (no absolute URL) should be rejected with 400.
    let raw_request =
        "GET /relative/path HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";

    let (_response, status) = send_raw_http_request(proxy_addr, raw_request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_connection_failure_returns_502() {
    let mut config = minimal_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;

    // Allow traffic to 127.0.0.1:1 (assumed closed port).
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyDefaultAction::Allow,
            pattern: Some("http://127.0.0.1:1/**".to_string()),
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

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let host = "127.0.0.1:1";
    let raw_request = format!(
        "GET http://{host}/unreachable HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );

    let (_response, status) = send_raw_http_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_request_timeout_returns_504() {
    let upstream_addr = start_upstream_delayed_server(Duration::from_millis(500)).await;

    let mut config = minimal_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;
    config.proxy.request_timeout_ms = 1_000;

    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyDefaultAction::Allow,
            pattern: Some(format!(
                "http://{}:{}/**",
                upstream_addr.ip(),
                upstream_addr.port()
            )),
            description: None,
            methods: None,
            subnets: Vec::new(),
            request_timeout_ms: Some(150),
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
    let raw_request =
        format!("GET http://{host}/slow HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    let (_response, status) = send_raw_http_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
}

#[tokio::test(flavor = "multi_thread")]
async fn header_actions_apply_to_request_for_matching_rule() {
    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;

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

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "http://{host}/**"

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "x-test"
value = "one"

[[policy.rules.header_actions]]
direction = "request"
action = "add"
name = "x-test"
value = "two"

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "x-if-present"
value = "set-value"
when = "if_present"

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "x-if-absent"
value = "default"
when = "if_absent"
"#,
        host = host
    );

    let config: Config = toml::from_str(&toml).expect("parse config");

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let raw_request = format!(
        "GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nx-if-present: original\r\n\r\n"
    );

    let (_response, status) = send_raw_http_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::OK);

    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard.as_ref().expect("upstream should see request");

    // x-test should have two values: one and two.
    let x_test_values: Vec<String> = upstream_headers
        .get_all("x-test")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .collect();
    assert_eq!(x_test_values, vec!["one".to_string(), "two".to_string()]);

    // x-if-present existed on the original request and should be set.
    assert_eq!(
        upstream_headers
            .get("x-if-present")
            .and_then(|v| v.to_str().ok()),
        Some("set-value")
    );

    // x-if-absent did not exist originally and should be added.
    assert_eq!(
        upstream_headers
            .get("x-if-absent")
            .and_then(|v| v.to_str().ok()),
        Some("default")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn header_actions_apply_to_response_for_matching_rule() {
    let (upstream_addr, _seen_headers) = start_upstream_echo_server().await;

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

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "http://{host}/**"

[[policy.rules.header_actions]]
direction = "response"
action = "replace_substring"
name = "x-upstream-tag"
search = "old"
replace = "new"
"#,
        host = host
    );

    let config: Config = toml::from_str(&toml).expect("parse config");

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let raw_request =
        format!("GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    let (response, status) = send_raw_http_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::OK);

    let mut saw_header = false;
    for line in response.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("x-upstream-tag:") {
            assert!(
                lower.contains("new-tag"),
                "expected x-upstream-tag to contain 'new-tag', got: {line}"
            );
            saw_header = true;
            break;
        }
    }

    assert!(saw_header, "response should include x-upstream-tag header");
}
