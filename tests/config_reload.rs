use std::io::Read;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex};

use acl_proxy::app::AppState;
use acl_proxy::config::Config;
use acl_proxy::proxy::http::run_http_proxy_on_listener;
use http::StatusCode;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn start_upstream_echo_server(
) -> (SocketAddr, Arc<Mutex<Option<hyper::HeaderMap>>>) {
    let listener =
        StdTcpListener::bind("127.0.0.1:0").expect("bind upstream");
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
            Ok::<_, hyper::Error>(service_fn(
                move |req: Request<Body>| {
                    let seen_headers = seen_headers.clone();
                    async move {
                        *seen_headers.lock().unwrap() =
                            Some(req.headers().clone());
                        Ok::<_, hyper::Error>(Response::new(
                            Body::from("ok"),
                        ))
                    }
                },
            ))
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

async fn start_proxy_with_shared_state(
    state: acl_proxy::app::SharedAppState,
    listener: StdTcpListener,
    shutdown: Arc<tokio::sync::Notify>,
) -> SocketAddr {
    let addr = listener.local_addr().expect("proxy addr");
    let listener_addr = addr;

    tokio::spawn(async move {
        let _ = run_http_proxy_on_listener(
            state,
            listener,
            async move {
                shutdown.notified().await;
            },
        )
        .await
        .map_err(|e| {
            eprintln!(
                "proxy server on {listener_addr} exited: {e}"
            );
        });
    });

    addr
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
async fn loop_header_injection_updates_after_reload() {
    let (upstream_addr, seen_headers) =
        start_upstream_echo_server().await;

    let mut config = minimal_config();

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
            header_actions: Vec::new(),
        },
    )];

    // Start with loop protection enabled but header injection disabled.
    config.loop_protection.enabled = true;
    config.loop_protection.add_header = false;

    let listener =
        StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let shared_state =
        AppState::shared_from_config(config.clone()).expect("app state");

    let shutdown = Arc::new(tokio::sync::Notify::new());
    let proxy_addr = start_proxy_with_shared_state(
        shared_state.clone(),
        listener,
        shutdown.clone(),
    )
    .await;

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let raw_request = format!(
        "GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );

    let (_response, status) =
        send_raw_http_request(proxy_addr, &raw_request).await;
    assert_eq!(status, StatusCode::OK);

    // Upstream should NOT see the loop header with the initial config.
    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard
        .as_ref()
        .expect("upstream should see request");
    assert!(
        upstream_headers
            .get("x-acl-proxy-request-id")
            .is_none(),
        "loop header should not be injected before reload"
    );
    drop(headers_guard);

    // Reload configuration enabling header injection.
    let mut updated = config.clone();
    updated.loop_protection.enabled = true;
    updated.loop_protection.add_header = true;
    AppState::reload_shared_from_config(&shared_state, updated)
        .expect("reload config");

    // Send another request; this one should carry the loop header.
    let (response, status) =
        send_raw_http_request(proxy_addr, &raw_request).await;
    assert_eq!(status, StatusCode::OK);
    println!("reload loop header test response:\n{response}");

    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard
        .as_ref()
        .expect("upstream should see request after reload");

    assert!(
        upstream_headers
            .get("x-acl-proxy-request-id")
            .is_some(),
        "loop header should be injected after reload"
    );

    shutdown.notify_waiters();
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_reload_keeps_previous_state() {
    let (upstream_addr, seen_headers) =
        start_upstream_echo_server().await;

    let mut config = minimal_config();

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
            header_actions: Vec::new(),
        },
    )];

    // Start with header injection enabled.
    config.loop_protection.enabled = true;
    config.loop_protection.add_header = true;

    let listener =
        StdTcpListener::bind("127.0.0.1:0").expect("bind proxy");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking proxy");

    let shared_state =
        AppState::shared_from_config(config.clone()).expect("app state");

    let shutdown = Arc::new(tokio::sync::Notify::new());
    let proxy_addr = start_proxy_with_shared_state(
        shared_state.clone(),
        listener,
        shutdown.clone(),
    )
    .await;

    let host = format!("{}:{}", upstream_addr.ip(), upstream_addr.port());
    let raw_request = format!(
        "GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );

    let (_response, status) =
        send_raw_http_request(proxy_addr, &raw_request).await;
    assert_eq!(status, StatusCode::OK);

    // Upstream should see the loop header with the initial config.
    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard
        .as_ref()
        .expect("upstream should see request");
    assert!(
        upstream_headers
            .get("x-acl-proxy-request-id")
            .is_some(),
        "loop header should be injected before failed reload"
    );
    drop(headers_guard);

    // Attempt to reload with an invalid loop protection header name.
    let mut invalid = config.clone();
    invalid.loop_protection.enabled = true;
    invalid.loop_protection.header_name =
        "invalid header name".to_string();
    let err =
        AppState::reload_shared_from_config(&shared_state, invalid)
            .expect_err("reload should fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("invalid loop protection header name"),
        "unexpected reload error: {msg}"
    );

    // A new request should still see the header injected, proving the
    // previous working state was preserved.
    let (_response, status) =
        send_raw_http_request(proxy_addr, &raw_request).await;
    assert_eq!(status, StatusCode::OK);

    let headers_guard = seen_headers.lock().unwrap();
    let upstream_headers = headers_guard
        .as_ref()
        .expect("upstream should see request after failed reload");
    assert!(
        upstream_headers
            .get("x-acl-proxy-request-id")
            .is_some(),
        "loop header should still be injected after failed reload"
    );

    shutdown.notify_waiters();
}
