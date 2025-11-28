use std::io::Read;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex};

use acl_proxy::app::AppState;
use acl_proxy::config::Config;
use acl_proxy::proxy::http::run_http_proxy_on_listener;
use http::StatusCode;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use serde_json::Value as JsonValue;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn start_upstream_echo_server(
) -> (SocketAddr, Arc<Mutex<Option<hyper::HeaderMap>>>) {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind upstream");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking upstream");
    let addr = listener.local_addr().expect("upstream addr");

    let seen_headers: Arc<Mutex<Option<hyper::HeaderMap>>> =
        Arc::new(Mutex::new(None));
    let seen_headers_clone = seen_headers.clone();

    let make_svc = make_service_fn(move |_conn| {
        let seen_headers = seen_headers_clone.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                let seen_headers = seen_headers.clone();
                async move {
                    *seen_headers.lock().unwrap() =
                        Some(req.headers().clone());
                    Ok::<_, hyper::Error>(Response::new(Body::from("ok")))
                }
            }))
        }
    });

    let server =
        Server::from_tcp(listener).expect("server from tcp").serve(make_svc);
    tokio::spawn(server);

    (addr, seen_headers)
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
    config.capture.directory =
        capture_dir.to_string_lossy().to_string();

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

async fn send_raw_http_request(
    addr: SocketAddr,
    raw_request: &str,
) -> (String, StatusCode) {
    let mut stream =
        tokio::net::TcpStream::connect(addr).await.expect("connect proxy");

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
async fn allowed_request_is_proxied_and_loop_header_added() {
    let (upstream_addr, seen_headers) =
        start_upstream_echo_server().await;

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
            with: None,
            add_url_enc_variants: None,
        },
    )];

    let proxy_listener =
        StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) =
        start_proxy_with_config(config, proxy_listener).await;

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let raw_request = format!(
        "GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );

    let (response, status) =
        send_raw_http_request(proxy_addr, &raw_request).await;

    println!("allowed_request raw response:\n{response}");

    assert_eq!(status, StatusCode::OK);
    assert!(
        response.contains("\r\n\r\nok"),
        "response body should contain 'ok', got: {response}"
    );

    // Ensure the upstream saw the loop protection header and host header.
    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard
        .as_ref()
        .expect("upstream should see request");

    assert!(
        upstream_headers
            .get("x-acl-proxy-request-id")
            .is_some(),
        "upstream should receive loop protection header"
    );
    assert_eq!(
        upstream_headers
            .get("host")
            .and_then(|v| v.to_str().ok()),
        Some(host.as_str())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn loop_header_not_added_when_disabled() {
    let (upstream_addr, seen_headers) =
        start_upstream_echo_server().await;

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
            with: None,
            add_url_enc_variants: None,
        },
    )];

    // Disable outbound loop header injection.
    config.loop_protection.enabled = true;
    config.loop_protection.add_header = false;

    let proxy_listener =
        StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) =
        start_proxy_with_config(config, proxy_listener).await;

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let raw_request = format!(
        "GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );

    let (_response, status) =
        send_raw_http_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::OK);

    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard
        .as_ref()
        .expect("upstream should see request");

    assert!(
        upstream_headers
            .get("x-acl-proxy-request-id")
            .is_none(),
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

    let proxy_listener =
        StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, temp_dir) =
        start_proxy_with_config(config, proxy_listener).await;

    let host = "example.com:80";
    let raw_request = format!(
        "GET http://{host}/denied HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );

    let (response, status) =
        send_raw_http_request(proxy_addr, &raw_request).await;

    println!("denied_request raw response:\n{response}");

    assert_eq!(status, StatusCode::FORBIDDEN);
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .trim();
    let json: JsonValue =
        serde_json::from_str(body).expect("parse deny JSON");
    assert_eq!(json["error"], "Forbidden");
    assert_eq!(json["message"], "Blocked by URL policy");

    // Capture files for denied request/response should exist.
    let capture_dir = temp_dir.path().join("captures");
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

    let proxy_listener =
        StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) =
        start_proxy_with_config(config, proxy_listener).await;

    let host = "example.com:80";
    let raw_request = format!(
        "GET http://{host}/loop HTTP/1.1\r\nHost: {host}\r\nx-acl-proxy-request-id: existing\r\nConnection: close\r\n\r\n"
    );

    let (response, status) =
        send_raw_http_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::LOOP_DETECTED);
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .trim();
    let json: JsonValue =
        serde_json::from_str(body).expect("parse loop JSON");
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

    let proxy_listener =
        StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) =
        start_proxy_with_config(config, proxy_listener).await;

    // Origin-form request (no absolute URL) should be rejected with 400.
    let raw_request = "GET /relative/path HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";

    let (_response, status) =
        send_raw_http_request(proxy_addr, raw_request).await;

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
            with: None,
            add_url_enc_variants: None,
        },
    )];

    let proxy_listener =
        StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    proxy_listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let (proxy_addr, _temp_dir) =
        start_proxy_with_config(config, proxy_listener).await;

    let host = "127.0.0.1:1";
    let raw_request = format!(
        "GET http://{host}/unreachable HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );

    let (_response, status) =
        send_raw_http_request(proxy_addr, &raw_request).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
}
