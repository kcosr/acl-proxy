use std::collections::BTreeMap;
use std::io::Write;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex};

use acl_proxy::app::AppState;
use acl_proxy::config::Config;
use acl_proxy::proxy::http::run_http_proxy_on_listener;
use http::header::{HeaderValue, CONTENT_TYPE};
use http::StatusCode;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use serde::Deserialize;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

#[derive(Debug, Deserialize)]
struct WireGolden {
    name: String,
    status: u16,
    content_type: Option<String>,
    body: String,
}

#[derive(Debug)]
struct WireResponse {
    status: StatusCode,
    headers: BTreeMap<String, String>,
    body: String,
}

async fn start_upstream(body: &'static str) -> (SocketAddr, Arc<Mutex<Vec<http::HeaderMap>>>) {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind upstream");
    listener
        .set_nonblocking(true)
        .expect("set upstream nonblocking");
    let addr = listener.local_addr().expect("upstream address");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let service_seen = seen.clone();

    let service = make_service_fn(move |_connection| {
        let seen = service_seen.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |request: Request<Body>| {
                seen.lock().unwrap().push(request.headers().clone());
                async move { Ok::<_, hyper::Error>(Response::new(Body::from(body))) }
            }))
        }
    });
    tokio::spawn(
        Server::from_tcp(listener)
            .expect("create upstream server")
            .serve(service),
    );
    (addr, seen)
}

async fn start_resetting_upstream() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind failing upstream");
    listener
        .set_nonblocking(true)
        .expect("set failing upstream nonblocking");
    let addr = listener.local_addr().expect("failing upstream address");
    let listener = tokio::net::TcpListener::from_std(listener).expect("adopt failing upstream");
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept failing upstream");
        drop(stream);
    });
    addr
}

async fn start_proxy(mut config: Config) -> (SocketAddr, TempDir) {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    listener
        .set_nonblocking(true)
        .expect("set proxy nonblocking");
    let addr = listener.local_addr().expect("proxy address");
    let temp_dir = TempDir::new().expect("proxy temporary directory");
    config.capture.directory = temp_dir.path().join("captures").display().to_string();
    config.logging.directory = Some(temp_dir.path().join("logs"));
    config.certificates.certs_dir = temp_dir.path().join("certs").display().to_string();
    let state = AppState::shared_from_config(config).expect("create proxy state");

    tokio::spawn(async move {
        run_http_proxy_on_listener(state, listener, std::future::pending())
            .await
            .expect("run proxy");
    });
    (addr, temp_dir)
}

async fn send_request(proxy: SocketAddr, target: &str) -> WireResponse {
    let mut stream = timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(proxy),
    )
    .await
    .expect("proxy connect timed out")
    .expect("connect to proxy");
    let authority = target
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .expect("HTTP target authority");
    let request =
        format!("GET {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    timeout(Duration::from_secs(5), stream.write_all(request.as_bytes()))
        .await
        .expect("proxy request write timed out")
        .expect("write proxy request");

    let mut bytes = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .expect("proxy response read timed out")
        .expect("read proxy response");
    let response = String::from_utf8(bytes).expect("UTF-8 proxy response");
    let (head, body) = response.split_once("\r\n\r\n").expect("HTTP response head");
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .and_then(|value| StatusCode::from_u16(value).ok())
        .expect("HTTP response status");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    WireResponse {
        status,
        headers,
        body: body.to_string(),
    }
}

fn base_config(policy: &str) -> Config {
    toml::from_str(&format!(
        r#"
schema_version = "2"

[proxy]
listeners.explicit_http.bind = "127.0.0.1:1"

[logging]
directory = "logs"
level = "info"

[capture]
allowed_request = false
allowed_response = false
denied_request = false
denied_response = false
directory = "captures"

[certificates]
certs_dir = "certs"

[policy]
default = "deny"
{policy}
"#
    ))
    .expect("parse schema-v2 test config")
}

#[tokio::test(flavor = "multi_thread")]
async fn representative_wire_responses_match_golden_corpus() {
    let goldens: Vec<WireGolden> =
        serde_json::from_str(include_str!("fixtures/golden/wire-responses.json"))
            .expect("parse wire-response goldens");
    let by_name: BTreeMap<_, _> = goldens
        .into_iter()
        .map(|golden| (golden.name.clone(), golden))
        .collect();

    let (upstream, _) = start_upstream("allowed").await;
    let allowed_target = format!("http://{upstream}/ok");
    let allowed_policy = format!(
        r#"
[[policy.rules]]
action = "allow"
pattern = "http://{upstream}/**"
"#
    );
    let (proxy, _temp_dir) = start_proxy(base_config(&allowed_policy)).await;
    let allowed = send_request(proxy, &allowed_target).await;

    let (proxy, _temp_dir) = start_proxy(base_config("")).await;
    let denied = send_request(proxy, "http://example.com/denied").await;

    let failing_addr = start_resetting_upstream().await;
    let error_policy = format!(
        r#"
[[policy.rules]]
action = "allow"
pattern = "http://{failing_addr}/**"
"#
    );
    let (proxy, _temp_dir) = start_proxy(base_config(&error_policy)).await;
    let errored = send_request(proxy, &format!("http://{failing_addr}/unreachable")).await;

    for (name, actual) in [
        ("allowed upstream response", allowed),
        ("policy denial", denied),
        ("upstream connection failure", errored),
    ] {
        let expected = &by_name[name];
        assert_eq!(actual.status.as_u16(), expected.status, "{name}: status");
        assert_eq!(
            actual.headers.get("content-type"),
            expected.content_type.as_ref(),
            "{name}: content type"
        );
        assert_eq!(actual.body, expected.body, "{name}: body");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn webhook_pass_resumes_at_the_following_rule() {
    let (upstream, seen_headers) = start_upstream("webhook-pass").await;
    let proxy_address: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let service_proxy_address = proxy_address.clone();

    let webhook_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind webhook");
    webhook_listener
        .set_nonblocking(true)
        .expect("set webhook nonblocking");
    let webhook_addr = webhook_listener.local_addr().expect("webhook address");
    let webhook_service = make_service_fn(move |_connection| {
        let proxy_address = service_proxy_address.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |request: Request<Body>| {
                let proxy_address = proxy_address.clone();
                async move {
                    let is_pending = request
                        .headers()
                        .get("x-acl-proxy-event")
                        .and_then(|value| value.to_str().ok())
                        == Some("pending");
                    let body = hyper::body::to_bytes(request.into_body()).await?;
                    if is_pending {
                        let event: serde_json::Value =
                            serde_json::from_slice(&body).expect("pending webhook JSON");
                        let request_id = event["requestId"]
                            .as_str()
                            .expect("pending request ID")
                            .to_string();
                        let proxy = proxy_address.lock().unwrap().expect("proxy address set");
                        tokio::spawn(async move {
                            let callback = serde_json::json!({
                                "requestId": request_id,
                                "decision": "pass"
                            });
                            let request = Request::builder()
                                .method("POST")
                                .uri(format!("http://{proxy}/_acl-proxy/external-auth/callback"))
                                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                                .body(Body::from(serde_json::to_vec(&callback).unwrap()))
                                .unwrap();
                            hyper::Client::new()
                                .request(request)
                                .await
                                .expect("send pass callback");
                        });
                    }
                    Ok::<_, hyper::Error>(Response::new(Body::from("ok")))
                }
            }))
        }
    });
    tokio::spawn(
        Server::from_tcp(webhook_listener)
            .expect("create webhook server")
            .serve(webhook_service),
    );

    let policy = format!(
        r#"
[policy.external_auth_profiles.approval]
type = "http"
webhook_url = "http://{webhook_addr}/approval"
timeout_ms = 5000
webhook_timeout_ms = 1000
on_webhook_failure = "error"

[[policy.rules]]
action = "delegate"
pattern = "http://{upstream}/**"
external_auth_profile = "approval"

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "x-delegate-action"
value = "must-not-apply"

[[policy.rules]]
action = "allow"
pattern = "http://{upstream}/**"
"#
    );
    let (proxy, _temp_dir) = start_proxy(base_config(&policy)).await;
    *proxy_address.lock().unwrap() = Some(proxy);
    let response = send_request(proxy, &format!("http://{upstream}/ok")).await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "webhook-pass");
    let seen = seen_headers.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].get("x-delegate-action").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn stdio_provider_pass_resumes_at_the_following_rule() {
    let (upstream, seen_headers) = start_upstream("stdio-pass").await;
    let plugin_dir = TempDir::new().expect("plugin directory");
    let plugin_path = plugin_dir.path().join("pass-provider.sh");
    let mut plugin = std::fs::File::create(&plugin_path).expect("create provider script");
    plugin
        .write_all(
            br#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf "%s" "$line" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  if [ -n "$id" ]; then
    printf '{"id":"%s","type":"response","decision":"pass"}\n' "$id"
  fi
done
"#,
        )
        .expect("write provider script");
    drop(plugin);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&plugin_path)
            .expect("provider metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&plugin_path, permissions).expect("make provider executable");
    }

    let policy = format!(
        r#"
[policy.external_auth_profiles.pass_provider]
type = "plugin"
command = "{}"
timeout_ms = 5000

[[policy.rules]]
action = "delegate"
pattern = "http://{upstream}/**"
external_auth_profile = "pass_provider"

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "x-delegate-action"
value = "must-not-apply"

[[policy.rules]]
action = "allow"
pattern = "http://{upstream}/**"
"#,
        plugin_path.display()
    );
    let (proxy, _temp_dir) = start_proxy(base_config(&policy)).await;
    let response = send_request(proxy, &format!("http://{upstream}/ok")).await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "stdio-pass");
    let seen = seen_headers.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].get("x-delegate-action").is_none());
}
