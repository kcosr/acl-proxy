#![allow(clippy::await_holding_lock, clippy::while_let_on_iterator)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use acl_proxy::app::AppState;
use acl_proxy::config::Config;
use acl_proxy::proxy::http::run_http_proxy_on_listener;
use base64::engine::general_purpose;
use base64::Engine;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
use flate2::{Compress, Compression, FlushCompress};
use h2::client as h2_client;
use http::header::{HeaderValue, CONNECTION, UPGRADE};
use http::StatusCode;
use hyper::server::conn::Http;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use serde_json::Value as JsonValue;
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Debug)]
struct SeenForwardedRequest {
    uri: String,
    headers: hyper::HeaderMap,
}

#[derive(Clone, Debug)]
struct SeenBodyRequest {
    headers: hyper::HeaderMap,
    body: Vec<u8>,
}

#[derive(Debug)]
struct TestWebSocketFrame {
    fin: bool,
    rsv1: bool,
    opcode: u8,
    payload: Vec<u8>,
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

async fn start_forwarding_echo_server() -> (SocketAddr, Arc<Mutex<Vec<SeenForwardedRequest>>>) {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind forwarding upstream");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking forwarding upstream");
    let addr = listener.local_addr().expect("forwarding upstream addr");

    let seen_requests: Arc<Mutex<Vec<SeenForwardedRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_requests_clone = seen_requests.clone();

    let make_svc = make_service_fn(move |_conn| {
        let seen_requests = seen_requests_clone.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                let seen_requests = seen_requests.clone();
                async move {
                    seen_requests.lock().unwrap().push(SeenForwardedRequest {
                        uri: req.uri().to_string(),
                        headers: req.headers().clone(),
                    });
                    Ok::<_, hyper::Error>(Response::new(Body::from("forwarded")))
                }
            }))
        }
    });

    let server = Server::from_tcp(listener)
        .expect("server from tcp")
        .serve(make_svc);
    tokio::spawn(server);

    (addr, seen_requests)
}

async fn start_upstream_body_echo_server() -> (SocketAddr, Arc<Mutex<Vec<SeenBodyRequest>>>) {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind body upstream");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking body upstream");
    let addr = listener.local_addr().expect("body upstream addr");

    let seen_requests: Arc<Mutex<Vec<SeenBodyRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_requests_clone = seen_requests.clone();

    let make_svc = make_service_fn(move |_conn| {
        let seen_requests = seen_requests_clone.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                let seen_requests = seen_requests.clone();
                async move {
                    let headers = req.headers().clone();
                    let body = hyper::body::to_bytes(req.into_body()).await?.to_vec();
                    seen_requests
                        .lock()
                        .unwrap()
                        .push(SeenBodyRequest { headers, body });
                    Ok::<_, hyper::Error>(Response::new(Body::from("body-forwarded")))
                }
            }))
        }
    });

    let server = Server::from_tcp(listener)
        .expect("server from tcp")
        .serve(make_svc);
    tokio::spawn(server);

    (addr, seen_requests)
}

async fn start_upstream_redaction_server(
    use_permessage_deflate: bool,
) -> (SocketAddr, Arc<Mutex<Vec<TestWebSocketFrame>>>) {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind websocket upstream");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking websocket upstream");
    let addr = listener.local_addr().expect("websocket upstream addr");
    let seen_payloads = Arc::new(Mutex::new(Vec::new()));
    let seen_payloads_clone = seen_payloads.clone();

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(socket) => socket,
                Err(_) => break,
            };
            let seen_payloads = seen_payloads_clone.clone();

            tokio::spawn(async move {
                let service = service_fn(move |mut req: Request<Body>| {
                    let seen_payloads = seen_payloads.clone();
                    async move {
                        let on_upgrade = hyper::upgrade::on(&mut req);
                        tokio::spawn(async move {
                            let mut upgraded = match on_upgrade.await {
                                Ok(upgraded) => upgraded,
                                Err(_) => return,
                            };

                            let frame = read_websocket_frame(&mut upgraded)
                                .await
                                .expect("read upstream websocket frame");
                            seen_payloads.lock().unwrap().push(frame);

                            if use_permessage_deflate {
                                let compressed = websocket_deflate_compress(b"upstream password");
                                write_websocket_frame_with_bits(
                                    &mut upgraded,
                                    true,
                                    true,
                                    0x1,
                                    &compressed,
                                    false,
                                )
                                .await
                                .expect("write compressed upstream websocket frame");
                            } else {
                                write_websocket_frame(
                                    &mut upgraded,
                                    0x1,
                                    b"upstream password",
                                    false,
                                )
                                .await
                                .expect("write upstream websocket frame");
                            }
                        });

                        let mut builder = Response::builder()
                            .status(StatusCode::SWITCHING_PROTOCOLS)
                            .header(CONNECTION, "Upgrade")
                            .header(UPGRADE, "websocket");
                        if use_permessage_deflate {
                            builder = builder.header(
                                "sec-websocket-extensions",
                                "permessage-deflate; client_no_context_takeover; server_no_context_takeover",
                            );
                        }
                        Ok::<_, hyper::Error>(builder.body(Body::empty()).unwrap())
                    }
                });

                let _ = Http::new()
                    .http1_keep_alive(false)
                    .serve_connection(socket, service)
                    .with_upgrades()
                    .await;
            });
        }
    });

    (addr, seen_payloads)
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
action = "delegate"
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
action = "delegate"
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
  id=$(printf "%s" "$line" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  if [ -z "$id" ]; then
    continue
  fi
  auth=$(printf "%s" "$line" | sed -n 's/.*"authorization"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
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
action = "delegate"
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

#[tokio::test(flavor = "multi_thread")]
async fn auth_plugin_deny_message_customizes_json_response_message() {
    let (upstream_addr, _seen_headers) = start_upstream_echo_server().await;

    let temp_dir = TempDir::new().expect("temp dir");
    let script_path = temp_dir.path().join("auth-plugin-deny-message.sh");
    let script = r#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf "%s" "$line" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  if [ -z "$id" ]; then
    continue
  fi
  auth=$(printf "%s" "$line" | sed -n 's/.*"authorization"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  if echo "$auth" | grep -q "custom"; then
    printf '{"id":"%s","type":"response","decision":"deny","denyMessage":"Request blocked by body policy"}\n' "$id"
  elif echo "$auth" | grep -q "invalid"; then
    printf '{"id":"%s","type":"response","decision":"deny","denyMessage":"bad\\u0007message"}\n' "$id"
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
[policy.external_auth_profiles.body_guard]
type = "plugin"
command = "{script_path}"
timeout_ms = 1000
include_headers = ["authorization"]

[[policy.rules]]
action = "delegate"
pattern = "http://{host}/**"
external_auth_profile = "body_guard"
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

    for (authorization, expected_message) in [
        ("Bearer custom", "Request blocked by body policy"),
        ("Bearer default", "Blocked by auth plugin"),
        ("Bearer invalid", "Blocked by auth plugin"),
    ] {
        let raw_request = format!(
            "GET http://{host}/repo1 HTTP/1.1\r\nHost: {host}\r\nAuthorization: {authorization}\r\nConnection: close\r\n\r\n"
        );
        let (response, status) = send_raw_http_request(proxy_addr, &raw_request).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let body = response.split("\r\n\r\n").nth(1).expect("response body");
        let payload: JsonValue = serde_json::from_str(body).expect("json response");
        assert_eq!(
            payload.get("error").and_then(|v| v.as_str()),
            Some("Forbidden")
        );
        assert_eq!(
            payload.get("message").and_then(|v| v.as_str()),
            Some(expected_message)
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn allow_upgrades_false_blocks_upgrade_before_delegate_plugin() {
    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;

    let temp_dir = TempDir::new().expect("temp dir");
    let script_path = temp_dir.path().join("auth-plugin-upgrade-guard.sh");
    let marker_path = temp_dir.path().join("plugin-invoked");
    let script = format!(
        r#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf "%s" "$line" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  if [ -n "$id" ]; then
    printf '%s\n' "$id" >> "{marker_path}"
    printf '{{"id":"%s","type":"response","decision":"allow"}}\n' "$id"
  fi
done
"#,
        marker_path = marker_path.to_string_lossy()
    );
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
[policy.external_auth_profiles.upgrade_guard]
type = "plugin"
command = "{script_path}"
timeout_ms = 1000

[[policy.rules]]
action = "delegate"
pattern = "http://{host}/**"
external_auth_profile = "upgrade_guard"
allow_upgrades = false
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

    let upgrade_request = format!(
        "GET http://{host}/chat HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nConnection: close\r\n\r\n"
    );
    let (_response, status) = send_raw_http_request(proxy_addr, &upgrade_request).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        !marker_path.exists(),
        "upgrade deny should happen before plugin invocation"
    );

    let normal_request =
        format!("GET http://{host}/chat HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let (_response, status) = send_raw_http_request(proxy_addr, &normal_request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        marker_path.exists(),
        "normal request should still invoke plugin"
    );
    let headers_guard = seen_headers.lock().unwrap();
    assert!(
        headers_guard.is_some(),
        "normal request should reach upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn redaction_profile_redacts_client_messages_only() {
    let (upstream_addr, seen_payloads) = start_upstream_redaction_server(false).await;
    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let mut config = minimal_config();
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
            pattern: Some(format!("http://{host}/**")),
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
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");
    let request = format!(
        concat!(
            "GET http://{host}/chat HTTP/1.1\r\n",
            "Host: {host}\r\n",
            "Connection: Upgrade\r\n",
            "Upgrade: websocket\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "\r\n"
        ),
        host = host
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write websocket upgrade request");

    let (_head, status) = read_http_response_head(&mut stream)
        .await
        .expect("read websocket response head");
    assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS);

    write_websocket_frame(&mut stream, 0x1, b"client password", true)
        .await
        .expect("write client websocket frame");
    let frame = read_websocket_frame(&mut stream)
        .await
        .expect("read upstream websocket frame");
    assert_eq!(frame.opcode, 0x1);
    assert_eq!(frame.payload, b"upstream password");

    let seen = seen_payloads.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].opcode, 0x1);
    assert_eq!(seen[0].payload, b"client [REDACTED]");
}

#[tokio::test(flavor = "multi_thread")]
async fn redaction_buffers_fragmented_messages_before_forwarding() {
    let (upstream_addr, seen_payloads) = start_upstream_redaction_server(false).await;
    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let mut config = minimal_config();
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
            pattern: Some(format!("http://{host}/**")),
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
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");
    let request = format!(
        concat!(
            "GET http://{host}/chat HTTP/1.1\r\n",
            "Host: {host}\r\n",
            "Connection: Upgrade\r\n",
            "Upgrade: websocket\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "\r\n"
        ),
        host = host
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write websocket upgrade request");

    let (_head, status) = read_http_response_head(&mut stream)
        .await
        .expect("read websocket response head");
    assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS);

    write_websocket_frame_with_bits(&mut stream, false, false, 0x1, b"client pass", true)
        .await
        .expect("write first fragment");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        seen_payloads.lock().unwrap().is_empty(),
        "partial fragmented message must not be forwarded"
    );

    write_websocket_frame_with_bits(&mut stream, true, false, 0x0, b"word", true)
        .await
        .expect("write continuation");
    let frame = read_websocket_frame(&mut stream)
        .await
        .expect("read upstream websocket frame");
    assert_eq!(frame.payload, b"upstream password");

    let seen = seen_payloads.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].fin);
    assert_eq!(seen[0].opcode, 0x1);
    assert_eq!(seen[0].payload, b"client [REDACTED]");
}

#[tokio::test(flavor = "multi_thread")]
async fn redaction_recompresses_permessage_deflate_messages() {
    let (upstream_addr, seen_payloads) = start_upstream_redaction_server(true).await;
    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let mut config = minimal_config();
    config.redaction.profiles.insert(
        "secrets".to_string(),
        acl_proxy::config::RedactionProfileConfig {
            replacement: "[REDACTED]".to_string(),
            allow_permessage_deflate: true,
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
            pattern: Some(format!("http://{host}/**")),
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
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");
    let request = format!(
        concat!(
            "GET http://{host}/chat HTTP/1.1\r\n",
            "Host: {host}\r\n",
            "Connection: Upgrade\r\n",
            "Upgrade: websocket\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Extensions: permessage-deflate\r\n",
            "\r\n"
        ),
        host = host
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write websocket upgrade request");

    let (head, status) = read_http_response_head(&mut stream)
        .await
        .expect("read websocket response head");
    assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS);
    assert!(
        head.to_ascii_lowercase()
            .contains("sec-websocket-extensions: permessage-deflate"),
        "response should negotiate permessage-deflate: {head}"
    );

    let compressed = websocket_deflate_compress(b"client password");
    write_websocket_frame_with_bits(&mut stream, true, true, 0x1, &compressed, true)
        .await
        .expect("write compressed client websocket frame");
    let frame = read_websocket_frame(&mut stream)
        .await
        .expect("read compressed upstream websocket frame");
    assert!(frame.rsv1, "upstream response should remain compressed");
    assert_eq!(
        websocket_deflate_decompress(&frame.payload),
        b"upstream password"
    );

    let seen = seen_payloads.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].rsv1, "upstream should receive compressed frame");
    assert_eq!(
        websocket_deflate_decompress(&seen[0].payload),
        b"client [REDACTED]"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn redaction_profile_rejects_non_websocket_upgrades() {
    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;
    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let mut config = minimal_config();
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
            pattern: Some(format!("http://{host}/**")),
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
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let request = format!(
        concat!(
            "GET http://{host}/chat HTTP/1.1\r\n",
            "Host: {host}\r\n",
            "Connection: Upgrade, close\r\n",
            "Upgrade: h2c\r\n",
            "\r\n"
        ),
        host = host
    );
    let (_response, status) = send_raw_http_request(proxy_addr, &request).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        seen_headers.lock().unwrap().is_none(),
        "protected non-WebSocket upgrade should not reach upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn external_auth_callback_pass_falls_through_to_later_allow() {
    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;

    let proxy_addr_shared: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let proxy_addr_for_svc = proxy_addr_shared.clone();

    let make_svc = make_service_fn(move |_conn| {
        let proxy_addr_for_svc = proxy_addr_for_svc.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
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
                        if let Some(request_id) = body
                            .get("requestId")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                        {
                            if let Some(proxy_addr) = *proxy_addr_for_svc.lock().unwrap() {
                                let callback_body = serde_json::json!({
                                    "requestId": request_id,
                                    "decision": "pass"
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
                    }

                    Ok::<_, hyper::Error>(Response::new(Body::from("ok")))
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

[policy.external_auth_profiles]
[policy.external_auth_profiles.pass_profile]
webhook_url = "http://{webhook_addr}/webhook"
timeout_ms = 5000
webhook_timeout_ms = 1000
on_webhook_failure = "error"

[[policy.rules]]
action = "delegate"
pattern = "http://{host}/**"
external_auth_profile = "pass_profile"

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "x-delegate-pass"
value = "should-not-apply"

[[policy.rules]]
action = "allow"
pattern = "http://{host}/**"
"#,
        webhook_addr = webhook_addr,
        host = host
    );

    let config: Config = toml::from_str(&toml).expect("parse config");
    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;
    *proxy_addr_shared.lock().unwrap() = Some(proxy_addr);

    let raw_request =
        format!("GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let (_response, status) = send_raw_http_request(proxy_addr, &raw_request).await;
    assert_eq!(status, StatusCode::OK);

    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard.as_ref().expect("upstream should see request");
    assert!(upstream_headers.get("x-delegate-pass").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_plugin_pass_falls_through_to_later_allow() {
    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;

    let temp_dir = TempDir::new().expect("temp dir");
    let script_path = temp_dir.path().join("auth-plugin-pass.sh");
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

[policy]
default = "deny"

[policy.external_auth_profiles]
[policy.external_auth_profiles.pass_plugin]
type = "plugin"
command = "{script_path}"
timeout_ms = 1000

[[policy.rules]]
action = "delegate"
pattern = "http://{host}/**"
external_auth_profile = "pass_plugin"

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "x-delegate-pass"
value = "should-not-apply"

[[policy.rules]]
action = "allow"
pattern = "http://{host}/**"
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

    let raw_request =
        format!("GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let (_response, status) = send_raw_http_request(proxy_addr, &raw_request).await;
    assert_eq!(status, StatusCode::OK);

    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard.as_ref().expect("upstream should see request");
    assert!(upstream_headers.get("x-delegate-pass").is_none());
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

#[tokio::test(flavor = "multi_thread")]
async fn ready_probe_returns_ready_json_without_policy_match() {
    let config = minimal_config();

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let (response, status) = send_raw_http_request(
        proxy_addr,
        "GET /_acl-proxy/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        response
            .to_ascii_lowercase()
            .contains("content-type: application/json"),
        "response should include JSON content type, got: {response}"
    );
    assert!(
        response.ends_with("\r\n\r\n{\"status\":\"ready\"}"),
        "response should include ready JSON body, got: {response}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ready_probe_uses_configured_internal_base_path_and_requires_get() {
    let mut config = minimal_config();
    config.proxy.internal_base_path = "/internal".to_string();

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let (ready_response, ready_status) = send_raw_http_request(
        proxy_addr,
        "GET /internal/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(ready_status, StatusCode::OK);
    assert!(
        ready_response.ends_with("\r\n\r\n{\"status\":\"ready\"}"),
        "response should include ready JSON body, got: {ready_response}"
    );

    let (method_response, method_status) = send_raw_http_request(
        proxy_addr,
        "POST /internal/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    assert_eq!(method_status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(
        method_response.ends_with(
            "\r\n\r\n{\"error\":\"MethodNotAllowed\",\"message\":\"Ready probe must use GET\"}"
        ),
        "response should include method error JSON body, got: {method_response}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn allowed_request_uses_configured_egress_forwarding_destination() {
    let (forward_addr, seen_requests) = start_forwarding_echo_server().await;

    let mut config = minimal_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some("http://example.invalid/**".to_string()),
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

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let raw_request = "GET http://example.invalid/ok HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n";
    let (response, status) = send_raw_http_request(proxy_addr, raw_request).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        response.contains("\r\n\r\nforwarded"),
        "unexpected response body: {response}"
    );

    let requests = seen_requests.lock().unwrap();
    let forwarded = requests
        .first()
        .expect("forwarding destination should see request");
    assert_eq!(forwarded.uri, "http://example.invalid/ok");
    assert_eq!(
        forwarded
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok()),
        Some("example.invalid")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn global_egress_request_actions_are_applied_after_rule_actions_without_affecting_matching() {
    let (forward_addr, seen_requests) = start_forwarding_echo_server().await;

    let mut config = minimal_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![
        acl_proxy::config::PolicyRuleConfig::Direct(acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Deny,
            pattern: Some("http://example.invalid/**".to_string()),
            patterns: None,
            description: None,
            methods: None,
            subnets: Vec::new(),
            headers_absent: Some(vec!["x-gate".to_string()]),
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
        acl_proxy::config::PolicyRuleConfig::Direct(acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some("http://example.invalid/**".to_string()),
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
            header_actions: vec![
                acl_proxy::config::HeaderActionConfig {
                    direction: acl_proxy::config::HeaderDirection::Request,
                    action: acl_proxy::config::HeaderActionKind::Set,
                    name: "x-layer".to_string(),
                    when: acl_proxy::config::HeaderWhen::Always,
                    value: Some("rule-layer".to_string()),
                    values: None,
                    search: None,
                    replace: None,
                },
                acl_proxy::config::HeaderActionConfig {
                    direction: acl_proxy::config::HeaderDirection::Request,
                    action: acl_proxy::config::HeaderActionKind::Set,
                    name: "x-conditional".to_string(),
                    when: acl_proxy::config::HeaderWhen::Always,
                    value: Some("rule-set".to_string()),
                    values: None,
                    search: None,
                    replace: None,
                },
            ],
            external_auth_profile: None,
            rule_id: None,
        }),
    ];
    config.proxy.egress.default = Some(acl_proxy::config::EgressTargetConfig {
        host: "127.0.0.1".to_string(),
        port: forward_addr.port(),
    });
    config.proxy.egress.request_header_actions = vec![
        acl_proxy::config::EgressRequestHeaderActionConfig {
            action: acl_proxy::config::HeaderActionKind::ReplaceSubstring,
            name: "x-layer".to_string(),
            when: acl_proxy::config::HeaderWhen::IfPresent,
            value: None,
            values: None,
            search: Some("rule".to_string()),
            replace: Some("global".to_string()),
        },
        acl_proxy::config::EgressRequestHeaderActionConfig {
            action: acl_proxy::config::HeaderActionKind::Remove,
            name: "x-conditional".to_string(),
            when: acl_proxy::config::HeaderWhen::IfPresent,
            value: None,
            values: None,
            search: None,
            replace: None,
        },
        acl_proxy::config::EgressRequestHeaderActionConfig {
            action: acl_proxy::config::HeaderActionKind::Set,
            name: "x-conditional".to_string(),
            when: acl_proxy::config::HeaderWhen::IfAbsent,
            value: Some("should-not-appear".to_string()),
            values: None,
            search: None,
            replace: None,
        },
        acl_proxy::config::EgressRequestHeaderActionConfig {
            action: acl_proxy::config::HeaderActionKind::Set,
            name: "host".to_string(),
            when: acl_proxy::config::HeaderWhen::Always,
            value: Some("rewritten.invalid".to_string()),
            values: None,
            search: None,
            replace: None,
        },
        acl_proxy::config::EgressRequestHeaderActionConfig {
            action: acl_proxy::config::HeaderActionKind::Remove,
            name: "x-gate".to_string(),
            when: acl_proxy::config::HeaderWhen::IfPresent,
            value: None,
            values: None,
            search: None,
            replace: None,
        },
    ];

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let raw_request = "GET http://example.invalid/ok HTTP/1.1\r\nHost: example.invalid\r\nX-Gate: present\r\nConnection: close\r\n\r\n";
    let (response, status) = send_raw_http_request(proxy_addr, raw_request).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        response.contains("\r\n\r\nforwarded"),
        "unexpected response body: {response}"
    );

    let requests = seen_requests.lock().unwrap();
    let forwarded = requests
        .first()
        .expect("forwarding destination should see request");

    assert_eq!(
        forwarded.uri, "http://example.invalid/ok",
        "host header mutation must not rewrite request target"
    );
    assert_eq!(
        forwarded
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok()),
        Some("rewritten.invalid")
    );
    assert_eq!(
        forwarded
            .headers
            .get("x-layer")
            .and_then(|value| value.to_str().ok()),
        Some("global-layer")
    );
    assert!(
        forwarded.headers.get("x-conditional").is_none(),
        "if_absent should be evaluated against pre-global-action presence snapshot"
    );
    assert!(
        forwarded.headers.get("x-gate").is_none(),
        "global egress remove should mutate outbound request headers"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn global_egress_request_actions_respect_intra_layer_order() {
    let (forward_addr, seen_requests) = start_forwarding_echo_server().await;

    let mut config = minimal_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some("http://example.invalid/**".to_string()),
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
    config.proxy.egress.request_header_actions = vec![
        acl_proxy::config::EgressRequestHeaderActionConfig {
            action: acl_proxy::config::HeaderActionKind::Set,
            name: "x-order".to_string(),
            when: acl_proxy::config::HeaderWhen::Always,
            value: Some("rule".to_string()),
            values: None,
            search: None,
            replace: None,
        },
        acl_proxy::config::EgressRequestHeaderActionConfig {
            action: acl_proxy::config::HeaderActionKind::ReplaceSubstring,
            name: "x-order".to_string(),
            when: acl_proxy::config::HeaderWhen::IfPresent,
            value: None,
            values: None,
            search: Some("rule".to_string()),
            replace: Some("global".to_string()),
        },
        acl_proxy::config::EgressRequestHeaderActionConfig {
            action: acl_proxy::config::HeaderActionKind::Remove,
            name: "x-order".to_string(),
            when: acl_proxy::config::HeaderWhen::IfPresent,
            value: None,
            values: None,
            search: None,
            replace: None,
        },
        acl_proxy::config::EgressRequestHeaderActionConfig {
            action: acl_proxy::config::HeaderActionKind::Set,
            name: "x-order".to_string(),
            when: acl_proxy::config::HeaderWhen::IfAbsent,
            value: Some("should-not-reappear".to_string()),
            values: None,
            search: None,
            replace: None,
        },
    ];

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let raw_request = "GET http://example.invalid/ok HTTP/1.1\r\nHost: example.invalid\r\nX-Order: inbound\r\nConnection: close\r\n\r\n";
    let (_response, status) = send_raw_http_request(proxy_addr, raw_request).await;
    assert_eq!(status, StatusCode::OK);

    let requests = seen_requests.lock().unwrap();
    let forwarded = requests
        .first()
        .expect("forwarding destination should see request");
    assert!(
        forwarded.headers.get("x-order").is_none(),
        "global action order must be deterministic and if_absent should use pre-global snapshot"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_global_egress_actions_preserve_existing_rule_header_behavior() {
    let (forward_addr, seen_requests) = start_forwarding_echo_server().await;

    let mut config = minimal_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some("http://example.invalid/**".to_string()),
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
            header_actions: vec![acl_proxy::config::HeaderActionConfig {
                direction: acl_proxy::config::HeaderDirection::Request,
                action: acl_proxy::config::HeaderActionKind::Set,
                name: "x-rule-only".to_string(),
                when: acl_proxy::config::HeaderWhen::Always,
                value: Some("rule-applied".to_string()),
                values: None,
                search: None,
                replace: None,
            }],
            external_auth_profile: None,
            rule_id: None,
        },
    )];
    config.proxy.egress.default = Some(acl_proxy::config::EgressTargetConfig {
        host: "127.0.0.1".to_string(),
        port: forward_addr.port(),
    });
    config.proxy.egress.request_header_actions = Vec::new();

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let raw_request =
        "GET http://example.invalid/ok HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n";
    let (_response, status) = send_raw_http_request(proxy_addr, raw_request).await;
    assert_eq!(status, StatusCode::OK);

    let requests = seen_requests.lock().unwrap();
    let forwarded = requests
        .first()
        .expect("forwarding destination should see request");
    assert_eq!(
        forwarded
            .headers
            .get("x-rule-only")
            .and_then(|value| value.to_str().ok()),
        Some("rule-applied")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn external_auth_webhook_transport_is_not_redirected_by_egress_forwarding() {
    let (forward_addr, seen_forwarded_requests) = start_forwarding_echo_server().await;

    #[derive(Clone, Debug)]
    struct ReceivedEvent {
        event_header: String,
        path: String,
    }

    let received_events: Arc<Mutex<Vec<ReceivedEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let received_events_clone = received_events.clone();
    let proxy_addr_shared: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let proxy_addr_for_svc = proxy_addr_shared.clone();

    let make_svc = make_service_fn(move |_conn| {
        let received_events = received_events_clone.clone();
        let proxy_addr_for_svc = proxy_addr_for_svc.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                let received_events = received_events.clone();
                let proxy_addr_for_svc = proxy_addr_for_svc.clone();
                async move {
                    let event_header = req
                        .headers()
                        .get("x-acl-proxy-event")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    let path = req.uri().path().to_string();
                    let body_bytes = hyper::body::to_bytes(req.into_body())
                        .await
                        .unwrap_or_default();
                    let body: serde_json::Value = serde_json::from_slice(&body_bytes)
                        .unwrap_or_else(|_| serde_json::json!({}));

                    received_events.lock().unwrap().push(ReceivedEvent {
                        event_header: event_header.clone(),
                        path,
                    });

                    if event_header == "pending" {
                        let request_id = body["requestId"]
                            .as_str()
                            .expect("pending event request id")
                            .to_string();
                        let proxy_addr = proxy_addr_for_svc
                            .lock()
                            .unwrap()
                            .expect("proxy address should be set");

                        tokio::spawn(async move {
                            let callback = serde_json::json!({
                                "requestId": request_id,
                                "decision": "allow"
                            });
                            let req = Request::builder()
                                .method("POST")
                                .uri(format!(
                                    "http://{}/_acl-proxy/external-auth/callback",
                                    proxy_addr
                                ))
                                .header(
                                    http::header::CONTENT_TYPE,
                                    HeaderValue::from_static("application/json"),
                                )
                                .body(Body::from(
                                    serde_json::to_vec(&callback)
                                        .unwrap_or_else(|_| b"{}".to_vec()),
                                ))
                                .expect("build callback request");

                            let _ = hyper::Client::new().request(req).await;
                        });
                    }

                    Ok::<_, hyper::Error>(Response::new(Body::from("ok")))
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

    let toml = format!(
        r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 0

[proxy.egress.default]
host = "127.0.0.1"
port = {forward_port}

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
[policy.external_auth_profiles.test_profile]
webhook_url = "http://127.0.0.1:{webhook_port}/webhook"
timeout_ms = 1000
webhook_timeout_ms = 1000
on_webhook_failure = "error"

[[policy.rules]]
action = "delegate"
pattern = "http://example.invalid/**"
external_auth_profile = "test_profile"
        "#,
        forward_port = forward_addr.port(),
        webhook_port = webhook_addr.port()
    );

    let config: Config = toml::from_str(&toml).expect("parse config");

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;
    *proxy_addr_shared.lock().unwrap() = Some(proxy_addr);

    let raw_request = "GET http://example.invalid/ok HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n";
    let (response, status) = send_raw_http_request(proxy_addr, raw_request).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        response.contains("\r\n\r\nforwarded"),
        "unexpected response body: {response}"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;

    let events = received_events.lock().unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.event_header == "pending" && event.path == "/webhook"),
        "webhook server should receive the pending external-auth request directly"
    );

    let forwarded_requests = seen_forwarded_requests.lock().unwrap();
    let forwarded = forwarded_requests
        .first()
        .expect("forwarding destination should see proxied request");
    assert_eq!(forwarded.uri, "http://example.invalid/ok");
    assert_eq!(
        forwarded
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok()),
        Some("example.invalid")
    );
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

fn build_websocket_frame(opcode: u8, payload: &[u8], masked: bool) -> Vec<u8> {
    build_websocket_frame_with_bits(true, false, opcode, payload, masked)
}

fn build_websocket_frame_with_bits(
    fin: bool,
    rsv1: bool,
    opcode: u8,
    payload: &[u8],
    masked: bool,
) -> Vec<u8> {
    let mut frame = Vec::new();
    let mut first = opcode & 0x0f;
    if fin {
        first |= 0x80;
    }
    if rsv1 {
        first |= 0x40;
    }
    frame.push(first);
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
        let mask = [0x11, 0x22, 0x33, 0x44];
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
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&build_websocket_frame(opcode, payload, masked))
        .await
}

async fn write_websocket_frame_with_bits<W>(
    writer: &mut W,
    fin: bool,
    rsv1: bool,
    opcode: u8,
    payload: &[u8],
    masked: bool,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&build_websocket_frame_with_bits(
            fin, rsv1, opcode, payload, masked,
        ))
        .await
}

async fn read_websocket_frame<R>(reader: &mut R) -> std::io::Result<TestWebSocketFrame>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header).await?;
    let fin = header[0] & 0x80 != 0;
    let rsv1 = header[0] & 0x40 != 0;
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

    Ok(TestWebSocketFrame {
        fin,
        rsv1,
        opcode,
        payload,
    })
}

fn websocket_deflate_compress(payload: &[u8]) -> Vec<u8> {
    let tail = [0x00, 0x00, 0xff, 0xff];
    let mut encoder = Compress::new(Compression::default(), false);
    let mut output = Vec::with_capacity(payload.len() + (payload.len() / 16) + 64);

    for _ in 0..8 {
        if output.capacity() == output.len() {
            output.reserve(payload.len().max(64));
        }
        let consumed = encoder.total_in() as usize;
        encoder
            .compress_vec(&payload[consumed..], &mut output, FlushCompress::Sync)
            .expect("compress websocket message");
        if encoder.total_in() == payload.len() as u64 && output.ends_with(&tail) {
            output.truncate(output.len() - tail.len());
            return output;
        }
    }

    panic!("websocket deflate encoder did not produce sync flush tail");
}

fn websocket_deflate_decompress(payload: &[u8]) -> Vec<u8> {
    let mut encoded = payload.to_vec();
    encoded.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
    let mut decoder = DeflateDecoder::new(encoded.as_slice());
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .expect("decompress websocket message");
    decoded
}

async fn read_http_response_head(
    stream: &mut tokio::net::TcpStream,
) -> std::io::Result<(String, StatusCode)> {
    let mut buf = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
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
        .and_then(|code| StatusCode::from_u16(code).ok())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    Ok((response, status))
}

fn write_body_rewrite_plugin(dir: &TempDir, body: &[u8]) -> std::path::PathBuf {
    let script_path = dir.path().join("body-rewrite-plugin.sh");
    let encoded = general_purpose::STANDARD.encode(body);
    let script = format!(
        r#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf "%s" "$line" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  if [ -n "$id" ]; then
    printf '{{"id":"%s","type":"response","decision":"allow","requestBody":{{"encoding":"base64","contentType":"application/json","data":"{encoded}"}}}}\n' "$id"
  fi
done
"#
    );
    std::fs::write(&script_path, script).expect("write body rewrite plugin");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path)
            .expect("stat plugin script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).expect("chmod plugin script");
    }
    script_path
}

fn write_allow_plugin(dir: &TempDir) -> std::path::PathBuf {
    let script_path = dir.path().join("allow-plugin.sh");
    let script = r#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf "%s" "$line" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  if [ -n "$id" ]; then
    printf '{"id":"%s","type":"response","decision":"allow"}\n' "$id"
  fi
done
"#;
    std::fs::write(&script_path, script).expect("write allow plugin");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path)
            .expect("stat plugin script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).expect("chmod plugin script");
    }
    script_path
}

fn gzip_bytes(body: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).expect("write gzip body");
    encoder.finish().expect("finish gzip body")
}

fn gunzip_bytes(body: &[u8]) -> Vec<u8> {
    let mut decoder = GzDecoder::new(body);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).expect("decode gzip body");
    decoded
}

fn deflate_bytes(body: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).expect("write deflate body");
    encoder.finish().expect("finish deflate body")
}

fn raw_deflate_bytes(body: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).expect("write raw deflate body");
    encoder.finish().expect("finish raw deflate body")
}

fn inflate_bytes(body: &[u8]) -> Vec<u8> {
    let mut decoder = ZlibDecoder::new(body);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .expect("decode deflate body");
    decoded
}

fn brotli_bytes(body: &[u8]) -> Vec<u8> {
    let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
    encoder.write_all(body).expect("write brotli body");
    encoder.into_inner()
}

fn unbrotli_bytes(body: &[u8]) -> Vec<u8> {
    let mut decoder = brotli::Decompressor::new(body, 4096);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .expect("decode brotli body");
    decoded
}

fn zstd_bytes(body: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(body, 0).expect("encode zstd body")
}

fn zstd_bytes_with_window_log(body: &[u8], window_log: u32) -> Vec<u8> {
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), 0).expect("create zstd encoder");
    encoder.window_log(window_log).expect("set zstd window log");
    encoder.write_all(body).expect("write zstd body");
    encoder.finish().expect("finish zstd body")
}

fn unzstd_bytes(body: &[u8]) -> Vec<u8> {
    zstd::stream::decode_all(body).expect("decode zstd body")
}

fn body_plugin_config(
    host: &str,
    script_path: &std::path::Path,
    include_request_body: bool,
    max_request_body_bytes: usize,
    max_decompressed_request_body_bytes: usize,
) -> Config {
    let toml = format!(
        r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 0

[logging]
directory = "logs"
level = "debug"

[capture]
allowed_request = false
allowed_response = false
denied_request = false
denied_response = false
directory = "logs-capture"

[policy]
default = "deny"

[policy.external_auth_profiles.body_guard]
type = "plugin"
command = "{script_path}"
timeout_ms = 1000
include_request_body = {include_request_body}
max_request_body_bytes = {max_request_body_bytes}
max_decompressed_request_body_bytes = {max_decompressed_request_body_bytes}

[[policy.rules]]
action = "delegate"
pattern = "http://{host}/**"
external_auth_profile = "body_guard"
"#,
        script_path = script_path.to_string_lossy()
    );

    toml::from_str(&toml).expect("parse body plugin config")
}

async fn assert_body_aware_recompresses_request_body_encoding(
    encoding: &str,
    encode: fn(&[u8]) -> Vec<u8>,
    decode: fn(&[u8]) -> Vec<u8>,
    replacement: &[u8],
) {
    let (upstream_addr, seen_requests) = start_upstream_body_echo_server().await;
    let plugin_temp_dir = TempDir::new().expect("plugin temp dir");
    let script_path = write_body_rewrite_plugin(&plugin_temp_dir, replacement);

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let config = body_plugin_config(&host, &script_path, true, 4096, 8 * 1024 * 1024);

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let original_encoded = encode(br#"{"prompt":"secret encoded"}"#);
    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");
    let request_head = format!(
        "POST http://{host}/chat HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Encoding: {encoding}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        original_encoded.len()
    );
    stream
        .write_all(request_head.as_bytes())
        .await
        .expect("write request head");
    stream
        .write_all(&original_encoded)
        .await
        .expect("write request body");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read response");
    let response = String::from_utf8_lossy(&buf).to_string();
    let status_line = response.lines().next().unwrap_or_default();
    assert!(
        status_line.contains(" 200 "),
        "unexpected response: {response}"
    );

    let seen = seen_requests.lock().unwrap();
    let request = seen.first().expect("upstream should see request");
    assert_eq!(
        request
            .headers
            .get("content-encoding")
            .and_then(|value| value.to_str().ok()),
        Some(encoding)
    );
    assert_eq!(decode(&request.body), replacement);
    let content_length = request
        .headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    assert_eq!(content_length, Some(request.body.len().to_string()));
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
async fn http_explicit_listener_accepts_h2c_prior_knowledge_requests() {
    let (upstream_addr, _seen_headers) = start_upstream_echo_server().await;

    let mut config = minimal_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;
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

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let uri = format!("http://{}:{}/h2c", upstream_addr.ip(), upstream_addr.port());
    let (body, status) = send_h2c_http_request(proxy_addr, &uri).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test(flavor = "multi_thread")]
async fn body_aware_auth_plugin_rewrites_http_request_body() {
    let (upstream_addr, seen_requests) = start_upstream_body_echo_server().await;
    let plugin_temp_dir = TempDir::new().expect("plugin temp dir");
    let replacement = br#"{"prompt":"redacted"}"#;
    let script_path = write_body_rewrite_plugin(&plugin_temp_dir, replacement);

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let toml = format!(
        r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 0

[logging]
directory = "logs"
level = "debug"

[capture]
allowed_request = false
allowed_response = false
denied_request = false
denied_response = false
directory = "logs-capture"

[policy]
default = "deny"

[policy.external_auth_profiles.body_guard]
type = "plugin"
command = "{script_path}"
timeout_ms = 1000
include_request_body = true
max_request_body_bytes = 4096
max_decompressed_request_body_bytes = 4096
include_headers = ["content-type"]

[[policy.rules]]
action = "delegate"
pattern = "http://{host}/**"
external_auth_profile = "body_guard"
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

    let original = br#"{"prompt":"secret"}"#;
    let raw_request = format!(
        "POST http://{host}/chat HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        original.len(),
        String::from_utf8_lossy(original)
    );
    let (response, status) = send_raw_http_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        response.contains("\r\n\r\nbody-forwarded"),
        "unexpected response body: {response}"
    );
    let seen = seen_requests.lock().unwrap();
    let request = seen.first().expect("upstream should see request");
    assert_eq!(request.body, replacement);
    let content_length = request
        .headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    assert_eq!(content_length, Some(replacement.len().to_string()));
    assert_eq!(
        request
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert!(request.headers.get("content-encoding").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn native_redaction_rewrites_http_request_body() {
    let (upstream_addr, seen_requests) = start_upstream_body_echo_server().await;
    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let toml = format!(
        r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 0

[logging]
directory = "logs"
level = "debug"

[capture]
allowed_request = false
allowed_response = false
denied_request = false
denied_response = false
directory = "logs-capture"

[redaction.profiles.secrets]
replacement = "[REDACTED]"
max_body_bytes = 4096
max_decoded_body_bytes = 4096

[[redaction.profiles.secrets.rules]]
literals = ["password"]
expressions = ["token-[0-9]+"]
match = "text"

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "http://{host}/**"
redaction_profile = "secrets"
"#,
        host = host
    );
    let config: Config = toml::from_str(&toml).expect("parse config");

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let original = br#"{"prompt":"password token-123"}"#;
    let expected = br#"{"prompt":"[REDACTED] [REDACTED]"}"#;
    let raw_request = format!(
        "POST http://{host}/chat HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        original.len(),
        String::from_utf8_lossy(original)
    );
    let (_response, status) = send_raw_http_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::OK);
    let seen = seen_requests.lock().unwrap();
    let request = seen.first().expect("upstream should see request");
    assert_eq!(request.body, expected);
    let content_length = request
        .headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    assert_eq!(content_length, Some(expected.len().to_string()));
}

#[tokio::test(flavor = "multi_thread")]
async fn native_redaction_leaves_bodyless_http_request_headers_unchanged() {
    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;
    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());

    let mut config = minimal_config();
    config.redaction.profiles.insert(
        "secrets".to_string(),
        acl_proxy::config::RedactionProfileConfig {
            replacement: "[REDACTED]".to_string(),
            rules: vec![acl_proxy::config::RedactionRuleConfig {
                literals: vec!["password".to_string()],
                expressions: Vec::new(),
                match_mode: acl_proxy::config::RedactionMatch::Text,
            }],
            ..Default::default()
        },
    );
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some(format!("http://{host}/**")),
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
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let raw_request =
        format!("GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let (_response, status) = send_raw_http_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::OK);
    let headers = seen_headers
        .lock()
        .unwrap()
        .clone()
        .expect("upstream headers");
    assert!(headers.get("content-length").is_none());
    assert!(headers.get("transfer-encoding").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn native_redaction_recompresses_gzip_request_body() {
    let (upstream_addr, seen_requests) = start_upstream_body_echo_server().await;
    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let toml = format!(
        r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 0

[logging]
directory = "logs"
level = "debug"

[capture]
allowed_request = false
allowed_response = false
denied_request = false
denied_response = false
directory = "logs-capture"

[redaction.profiles.secrets]
replacement = "[REDACTED]"
max_body_bytes = 4096
max_decoded_body_bytes = 4096

[[redaction.profiles.secrets.rules]]
literals = ["password"]
match = "text"

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "http://{host}/**"
redaction_profile = "secrets"
"#,
        host = host
    );
    let config: Config = toml::from_str(&toml).expect("parse config");

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let original_encoded = gzip_bytes(br#"{"prompt":"password"}"#);
    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");
    let request_head = format!(
        "POST http://{host}/chat HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        original_encoded.len()
    );
    stream
        .write_all(request_head.as_bytes())
        .await
        .expect("write request head");
    stream
        .write_all(&original_encoded)
        .await
        .expect("write request body");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read response");
    let response = String::from_utf8_lossy(&buf);
    assert!(
        response
            .lines()
            .next()
            .unwrap_or_default()
            .contains(" 200 "),
        "unexpected response: {response}"
    );

    let seen = seen_requests.lock().unwrap();
    let request = seen.first().expect("upstream should see request");
    assert_eq!(
        request
            .headers
            .get("content-encoding")
            .and_then(|value| value.to_str().ok()),
        Some("gzip")
    );
    assert_eq!(gunzip_bytes(&request.body), br#"{"prompt":"[REDACTED]"}"#);
    let content_length = request
        .headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    assert_eq!(content_length, Some(request.body.len().to_string()));
}

#[tokio::test(flavor = "multi_thread")]
async fn body_aware_auth_plugin_recompresses_gzip_request_body() {
    assert_body_aware_recompresses_request_body_encoding(
        "gzip",
        gzip_bytes,
        gunzip_bytes,
        br#"{"prompt":"redacted gzip"}"#,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn body_aware_auth_plugin_recompresses_common_encoded_request_bodies() {
    assert_body_aware_recompresses_request_body_encoding(
        "deflate",
        deflate_bytes,
        inflate_bytes,
        br#"{"prompt":"redacted deflate"}"#,
    )
    .await;
    assert_body_aware_recompresses_request_body_encoding(
        "br",
        brotli_bytes,
        unbrotli_bytes,
        br#"{"prompt":"redacted br"}"#,
    )
    .await;
    assert_body_aware_recompresses_request_body_encoding(
        "zstd",
        zstd_bytes,
        unzstd_bytes,
        br#"{"prompt":"redacted zstd"}"#,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn body_aware_auth_plugin_accepts_raw_deflate_request_body() {
    let (upstream_addr, seen_requests) = start_upstream_body_echo_server().await;
    let plugin_temp_dir = TempDir::new().expect("plugin temp dir");
    let replacement = br#"{"prompt":"redacted raw deflate"}"#;
    let script_path = write_body_rewrite_plugin(&plugin_temp_dir, replacement);
    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let config = body_plugin_config(&host, &script_path, true, 4096, 4096);

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let original_encoded = raw_deflate_bytes(br#"{"prompt":"raw deflate"}"#);
    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");
    let request_head = format!(
        "POST http://{host}/chat HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Encoding: deflate\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        original_encoded.len()
    );
    stream
        .write_all(request_head.as_bytes())
        .await
        .expect("write request head");
    stream
        .write_all(&original_encoded)
        .await
        .expect("write request body");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read response");
    let response = String::from_utf8_lossy(&buf).to_string();
    let status_line = response.lines().next().unwrap_or_default();
    assert!(
        status_line.contains(" 200 "),
        "unexpected response: {response}"
    );

    let seen = seen_requests.lock().unwrap();
    let request = seen.first().expect("upstream should see request");
    assert_eq!(
        request
            .headers
            .get("content-encoding")
            .and_then(|value| value.to_str().ok()),
        Some("deflate")
    );
    assert_eq!(inflate_bytes(&request.body), replacement);
}

#[tokio::test(flavor = "multi_thread")]
async fn body_aware_auth_plugin_rejects_encoded_body_over_limit() {
    let (upstream_addr, seen_requests) = start_upstream_body_echo_server().await;
    let plugin_temp_dir = TempDir::new().expect("plugin temp dir");
    let script_path = write_allow_plugin(&plugin_temp_dir);
    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let config = body_plugin_config(&host, &script_path, true, 8, 4096);

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let body = "0123456789";
    let raw_request = format!(
        "POST http://{host}/chat HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    let (_response, status) = send_raw_http_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        seen_requests.lock().unwrap().is_empty(),
        "oversized request body must not reach upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn body_aware_auth_plugin_rejects_decompressed_body_over_limit() {
    let (upstream_addr, seen_requests) = start_upstream_body_echo_server().await;
    let plugin_temp_dir = TempDir::new().expect("plugin temp dir");
    let script_path = write_allow_plugin(&plugin_temp_dir);
    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let config = body_plugin_config(&host, &script_path, true, 4096, 8);

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let encoded = gzip_bytes(b"decoded body is too long");
    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");
    let request_head = format!(
        "POST http://{host}/chat HTTP/1.1\r\nHost: {host}\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        encoded.len()
    );
    stream
        .write_all(request_head.as_bytes())
        .await
        .expect("write request head");
    stream
        .write_all(&encoded)
        .await
        .expect("write request body");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read response");
    let response = String::from_utf8_lossy(&buf).to_string();
    let status_line = response.lines().next().unwrap_or_default();
    assert!(
        status_line.contains(" 503 "),
        "unexpected response: {response}"
    );
    assert!(
        seen_requests.lock().unwrap().is_empty(),
        "oversized decompressed body must not reach upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn body_aware_auth_plugin_rejects_zstd_window_over_limit() {
    let (upstream_addr, seen_requests) = start_upstream_body_echo_server().await;
    let plugin_temp_dir = TempDir::new().expect("plugin temp dir");
    let script_path = write_allow_plugin(&plugin_temp_dir);
    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let config = body_plugin_config(&host, &script_path, true, 4096, 4096);

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let encoded = zstd_bytes_with_window_log(b"small decoded body", 20);
    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect proxy");
    let request_head = format!(
        "POST http://{host}/chat HTTP/1.1\r\nHost: {host}\r\nContent-Encoding: zstd\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        encoded.len()
    );
    stream
        .write_all(request_head.as_bytes())
        .await
        .expect("write request head");
    stream
        .write_all(&encoded)
        .await
        .expect("write request body");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read response");
    let response = String::from_utf8_lossy(&buf).to_string();
    let status_line = response.lines().next().unwrap_or_default();
    assert!(
        status_line.contains(" 503 "),
        "unexpected response: {response}"
    );
    assert!(
        seen_requests.lock().unwrap().is_empty(),
        "zstd body with over-limit window must not reach upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn body_aware_auth_plugin_rejects_unsupported_content_encoding() {
    let (upstream_addr, seen_requests) = start_upstream_body_echo_server().await;
    let plugin_temp_dir = TempDir::new().expect("plugin temp dir");
    let script_path = write_allow_plugin(&plugin_temp_dir);
    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let config = body_plugin_config(&host, &script_path, true, 4096, 4096);

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let body = "plain";
    let raw_request = format!(
        "POST http://{host}/chat HTTP/1.1\r\nHost: {host}\r\nContent-Encoding: snappy\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    let (_response, status) = send_raw_http_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        seen_requests.lock().unwrap().is_empty(),
        "unsupported content encoding must not reach upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_plugin_request_body_mutation_requires_body_aware_profile() {
    let (upstream_addr, seen_requests) = start_upstream_body_echo_server().await;
    let plugin_temp_dir = TempDir::new().expect("plugin temp dir");
    let script_path = write_body_rewrite_plugin(&plugin_temp_dir, b"replacement");
    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let config = body_plugin_config(&host, &script_path, false, 4096, 4096);

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");
    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let body = "original";
    let raw_request = format!(
        "POST http://{host}/chat HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    let (_response, status) = send_raw_http_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        seen_requests.lock().unwrap().is_empty(),
        "requestBody mutation without include_request_body must not reach upstream"
    );
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
async fn headers_absent_top_deny_guard_falls_through_to_allow_rule() {
    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;

    let mut config = minimal_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![
        acl_proxy::config::PolicyRuleConfig::Direct(acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Deny,
            pattern: Some(format!("http://{host}/**")),
            patterns: None,
            description: Some("Deny requests missing identity".to_string()),
            methods: None,
            subnets: Vec::new(),
            headers_absent: Some(vec!["x-workload-id".to_string()]),
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
        acl_proxy::config::PolicyRuleConfig::Direct(acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some(format!("http://{host}/**")),
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

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let missing_header_request =
        format!("GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let (_response, deny_status) = send_raw_http_request(proxy_addr, &missing_header_request).await;
    assert_eq!(deny_status, StatusCode::FORBIDDEN);
    assert!(
        seen_headers.lock().unwrap().is_none(),
        "denied guard request must not reach upstream"
    );

    let empty_header_request = format!(
        "GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nX-Workload-Id:\r\nConnection: close\r\n\r\n"
    );
    let (response, allow_status) = send_raw_http_request(proxy_addr, &empty_header_request).await;
    assert_eq!(allow_status, StatusCode::OK);
    assert!(
        response.contains("\r\n\r\nok"),
        "response body should contain 'ok', got: {response}"
    );

    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard
        .as_ref()
        .expect("upstream should see allowed request");
    assert_eq!(
        upstream_headers
            .get("x-workload-id")
            .and_then(|value| value.to_str().ok()),
        Some("")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn method_scoped_headers_absent_guard_only_blocks_matching_methods() {
    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;

    let mut config = minimal_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![
        acl_proxy::config::PolicyRuleConfig::Direct(acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Deny,
            pattern: Some(format!("http://{host}/**")),
            patterns: None,
            description: Some("Deny POSTs missing identity".to_string()),
            methods: Some({
                #[derive(serde::Deserialize)]
                struct MethodListWrapper {
                    methods: acl_proxy::config::MethodList,
                }

                toml::from_str::<MethodListWrapper>("methods = [\"POST\"]")
                    .expect("parse methods")
                    .methods
            }),
            subnets: Vec::new(),
            headers_absent: Some(vec!["x-workload-id".to_string()]),
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
        acl_proxy::config::PolicyRuleConfig::Direct(acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some(format!("http://{host}/**")),
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

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let post_missing_header =
        format!("POST http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    let (_response, post_deny_status) =
        send_raw_http_request(proxy_addr, &post_missing_header).await;
    assert_eq!(post_deny_status, StatusCode::FORBIDDEN);

    let get_missing_header =
        format!("GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let (_response, get_allow_status) =
        send_raw_http_request(proxy_addr, &get_missing_header).await;
    assert_eq!(get_allow_status, StatusCode::OK);

    let post_with_header = format!(
        "POST http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nX-Workload-Id: worker-123\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    let (_response, post_allow_status) = send_raw_http_request(proxy_addr, &post_with_header).await;
    assert_eq!(post_allow_status, StatusCode::OK);

    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard
        .as_ref()
        .expect("upstream should see allowed request");
    assert_eq!(
        upstream_headers
            .get("x-workload-id")
            .and_then(|value| value.to_str().ok()),
        Some("worker-123")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn headers_match_top_guard_denies_non_matching_value_and_allows_matching_value() {
    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;

    let mut config = minimal_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![
        acl_proxy::config::PolicyRuleConfig::Direct(acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some(format!("http://{host}/**")),
            patterns: None,
            description: Some("Allow trusted identity header".to_string()),
            methods: None,
            subnets: Vec::new(),
            headers_absent: None,
            headers_match: Some(BTreeMap::from([(
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
        }),
        acl_proxy::config::PolicyRuleConfig::Direct(acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Deny,
            pattern: Some(format!("http://{host}/**")),
            patterns: None,
            description: Some("Deny all other traffic".to_string()),
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

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let blocked_request = format!(
        "GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nX-Workload-Id: worker-999\r\nConnection: close\r\n\r\n"
    );
    let (_response, deny_status) = send_raw_http_request(proxy_addr, &blocked_request).await;
    assert_eq!(deny_status, StatusCode::FORBIDDEN);
    assert!(
        seen_headers.lock().unwrap().is_none(),
        "non-matching request must not reach upstream"
    );

    let allowed_request = format!(
        "GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nX-Workload-Id: worker-123\r\nConnection: close\r\n\r\n"
    );
    let (_response, allow_status) = send_raw_http_request(proxy_addr, &allowed_request).await;
    assert_eq!(allow_status, StatusCode::OK);

    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard
        .as_ref()
        .expect("matching request should reach upstream");
    assert_eq!(
        upstream_headers
            .get("x-workload-id")
            .and_then(|value| value.to_str().ok()),
        Some("worker-123")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn headers_match_http_regressions_cover_repeated_values_comma_literals_and_case_insensitive_names(
) {
    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;

    let mut config = minimal_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some(format!("http://{host}/**")),
            patterns: None,
            description: Some("Allow only exact trusted header values".to_string()),
            methods: None,
            subnets: Vec::new(),
            headers_absent: None,
            headers_match: Some(BTreeMap::from([
                (
                    "x-workload-id".to_string(),
                    acl_proxy::config::HeaderMatchValueConfig::Many(vec![
                        "worker-123".to_string(),
                        "worker-456".to_string(),
                    ]),
                ),
                (
                    "x-comma".to_string(),
                    acl_proxy::config::HeaderMatchValueConfig::Single("a,b".to_string()),
                ),
            ])),
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

    let repeated_value_request = format!(
        "GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nX-Workload-Id: worker-999\r\nX-Workload-Id: worker-456\r\nX-Comma: a,b\r\nConnection: close\r\n\r\n"
    );
    let (_response, repeated_status) =
        send_raw_http_request(proxy_addr, &repeated_value_request).await;
    assert_eq!(repeated_status, StatusCode::OK);

    let comma_spacing_request = format!(
        "GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nX-Workload-Id: worker-123\r\nX-Comma: a, b\r\nConnection: close\r\n\r\n"
    );
    let (_response, comma_spacing_status) =
        send_raw_http_request(proxy_addr, &comma_spacing_request).await;
    assert_eq!(
        comma_spacing_status,
        StatusCode::FORBIDDEN,
        "comma-containing values must be compared exactly without tokenization"
    );

    let case_insensitive_name_request = format!(
        "GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nx-workload-id: worker-123\r\nx-comma: a,b\r\nConnection: close\r\n\r\n"
    );
    let (_response, case_insensitive_status) =
        send_raw_http_request(proxy_addr, &case_insensitive_name_request).await;
    assert_eq!(case_insensitive_status, StatusCode::OK);

    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard
        .as_ref()
        .expect("upstream should see matching request");
    assert_eq!(
        upstream_headers
            .get("x-comma")
            .and_then(|value| value.to_str().ok()),
        Some("a,b")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn headers_not_match_top_deny_guard_blocks_non_internal_and_allows_internal() {
    let (upstream_addr, seen_headers) = start_upstream_echo_server().await;

    let mut config = minimal_config();
    config.capture.allowed_request = false;
    config.capture.allowed_response = false;

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    config.policy.rules = vec![
        acl_proxy::config::PolicyRuleConfig::Direct(acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Deny,
            pattern: Some(format!("http://{host}/**")),
            patterns: None,
            description: Some("Deny non-internal contexts".to_string()),
            methods: None,
            subnets: Vec::new(),
            headers_absent: None,
            headers_match: None,
            headers_not_match: Some(BTreeMap::from([(
                "x-aw-policy-context".to_string(),
                acl_proxy::config::HeaderMatchValueConfig::Many(vec!["internal".to_string()]),
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
            pattern: Some(format!("http://{host}/**")),
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

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let missing_header_request =
        format!("GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let (_response, missing_status) =
        send_raw_http_request(proxy_addr, &missing_header_request).await;
    assert_eq!(missing_status, StatusCode::FORBIDDEN);

    let default_context_request = format!(
        "GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nX-AW-Policy-Context: default\r\nConnection: close\r\n\r\n"
    );
    let (_response, default_status) =
        send_raw_http_request(proxy_addr, &default_context_request).await;
    assert_eq!(default_status, StatusCode::FORBIDDEN);
    assert!(
        seen_headers.lock().unwrap().is_none(),
        "denied requests must not reach upstream"
    );

    let internal_context_request = format!(
        "GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nX-AW-Policy-Context: default\r\nX-AW-Policy-Context: internal\r\nConnection: close\r\n\r\n"
    );
    let (response, internal_status) =
        send_raw_http_request(proxy_addr, &internal_context_request).await;
    assert_eq!(internal_status, StatusCode::OK);
    assert!(
        response.contains("\r\n\r\nok"),
        "response body should contain 'ok', got: {response}"
    );

    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard
        .as_ref()
        .expect("internal request should reach upstream");
    let values = upstream_headers
        .get_all("x-aw-policy-context")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>();
    assert!(values.contains(&"internal"));
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
async fn origin_form_request_with_host_is_forwarded() {
    let (upstream_addr, _seen_headers) = start_upstream_echo_server().await;

    let mut config = minimal_config();
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Deny;
    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    config.policy.rules = vec![acl_proxy::config::PolicyRuleConfig::Direct(
        acl_proxy::config::PolicyRuleDirectConfig {
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some(format!("http://{host}/**")),
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

    let raw_request =
        format!("GET /relative/path HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

    let (response, status) = send_raw_http_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        response.contains("\r\n\r\nok"),
        "unexpected response body: {response}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn origin_form_request_with_empty_host_returns_400() {
    let mut config = minimal_config();
    config.policy.default = acl_proxy::config::PolicyDefaultAction::Allow;

    let proxy_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) = start_proxy_with_config(config, proxy_listener).await;

    let raw_request = "GET /relative/path HTTP/1.1\r\nHost:\r\nConnection: close\r\n\r\n";
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
            action: acl_proxy::config::PolicyRuleAction::Allow,
            pattern: Some("http://127.0.0.1:1/**".to_string()),
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
            request_timeout_ms: Some(150),
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
