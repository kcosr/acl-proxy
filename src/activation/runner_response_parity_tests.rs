use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use http_access_runtime::{ForwardingDevHarness, ForwardingNetworkFacts};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::config::{compile_config_text, ConfigTextInput};

fn response_prebound_listener() -> (SocketAddr, StdTcpListener) {
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    (listener.local_addr().unwrap(), listener)
}

fn response_base_config(bind: SocketAddr, extra: &str) -> String {
    format!(
        r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "{bind}"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[egress]
route = "direct"

[egress.origin_tls]
trust = "insecure"
http_versions = ["http1"]

[safety.loop_detection]
inject = true
header = "x-test-loop"

{extra}
"#
    )
}

async fn start_response_product(
    text: &str,
    listener: StdTcpListener,
    mappings: impl IntoIterator<Item = (String, SocketAddr)>,
) -> (TempDir, Arc<ProductRuntime>) {
    let bind = listener.local_addr().unwrap();
    let (directory, loaded) = loaded(text);
    let facts = ForwardingNetworkFacts::new(vec![bind], None, None, None).unwrap();
    let mut harness = ForwardingDevHarness::new(facts);
    for (url, address) in mappings {
        let url = http_access_url::canonicalize_http_url(&url).unwrap();
        harness = harness.map_prebound(&url, address).unwrap();
    }
    let product = ProductRuntime::prepare_from_prebound_with_forwarding_network(
        loaded,
        vec![listener],
        Arc::new(harness.into_standalone_guard()),
    )
    .await
    .unwrap();
    product.activate_initial().await.unwrap();
    product.start_listeners().await.unwrap();
    (directory, product)
}

async fn response_read_to_close(mut stream: impl AsyncRead + Unpin) -> Vec<u8> {
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut bytes))
        .await
        .expect("HTTP peer did not close")
        .unwrap();
    bytes
}

async fn response_send_raw(proxy: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    stream.write_all(request).await.unwrap();
    response_read_to_close(stream).await
}

fn local_failure_capture_config() -> &'static str {
    r#"[redaction.profiles.failure_capture]
replacement = "[MASKED]"
rules = [{ literals = ["request failed", "upstream failed", "service unavailable", "request timed out"], payloads = "both" }]

[observation.capture]
events = ["request.allowed", "response.allowed", "request.denied", "response.denied"]
redaction_profile = "failure_capture"
directory = "captures"
max_body_bytes = 1048576
max_inflight_body_bytes = 134217728
max_pending_records = 32
max_files = 32
max_total_bytes = 1048576
"#
}

fn response_capture_records(directory: &TempDir) -> Vec<crate::capture::CaptureRecord> {
    let mut records = Vec::new();
    for entry in fs::read_dir(directory.path().join("captures")).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let contents = fs::read_to_string(path).unwrap();
        records.extend(
            contents
                .lines()
                .filter(|line| !line.is_empty())
                .map(|line| serde_json::from_str(line).unwrap()),
        );
    }
    records
}

fn assert_sanitized_local_failure_capture(
    records: &[crate::capture::CaptureRecord],
    url: &str,
    status: u16,
    status_message: &str,
    original_body_len: usize,
    decision: crate::capture::CaptureDecision,
) {
    let captured = records
        .iter()
        .find(|record| {
            record.kind == crate::capture::CaptureKind::Response
                && record.url == url
                && record.status_code == Some(status)
        })
        .unwrap_or_else(|| panic!("missing local {status} capture for {url}: {records:?}"));
    assert_eq!(captured.decision, decision);
    assert_eq!(captured.status_message.as_deref(), Some(status_message));
    assert_eq!(captured.decode_body_bytes().unwrap(), b"[MASKED]\n");
    assert!(captured.body_omission.is_none());
    let headers = captured.headers.as_ref().unwrap();
    assert_eq!(
        headers.get("content-type"),
        Some(&serde_json::Value::String(
            "text/plain; charset=utf-8".to_owned()
        ))
    );
    assert_eq!(
        headers.get("content-length"),
        Some(&serde_json::Value::String(original_body_len.to_string()))
    );
}

async fn response_read_head(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut byte))
            .await
            .expect("HTTP head read timed out")
            .expect("HTTP head ended early");
        head.push(byte[0]);
        assert!(head.len() <= 32 * 1024, "HTTP head exceeded test bound");
    }
    head
}

fn response_decoded_body(response: &[u8]) -> Vec<u8> {
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response omitted the header terminator")
        + 4;
    let head = String::from_utf8_lossy(&response[..head_end]).to_ascii_lowercase();
    let body = &response[head_end..];
    if !head.contains("\r\ntransfer-encoding: chunked\r\n") {
        return body.to_vec();
    }
    let mut decoded = Vec::new();
    let mut cursor = 0;
    loop {
        let size_end = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk size omitted its terminator")
            + cursor;
        let size = std::str::from_utf8(&body[cursor..size_end])
            .unwrap()
            .split(';')
            .next()
            .and_then(|value| usize::from_str_radix(value, 16).ok())
            .expect("invalid chunk size");
        cursor = size_end + 2;
        if size == 0 {
            break;
        }
        let end = cursor.checked_add(size).expect("chunk size overflowed");
        decoded.extend_from_slice(body.get(cursor..end).expect("chunk ended early"));
        assert_eq!(body.get(end..end + 2), Some(b"\r\n".as_slice()));
        cursor = end + 2;
    }
    decoded
}

#[tokio::test]
async fn ordinary_forwarding_preserves_response_trailers_end_to_end() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin_listener.accept().await.unwrap();
        response_read_head(&mut stream).await;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: x-sequence, x-other\r\nConnection: x-remove, close\r\nX-Remove: private\r\n\r\nd\r\nresponse-body\r\n0\r\nX-Sequence: first\r\nX-Other: middle\r\nX-Sequence: second\r\n\r\n",
            )
            .await
            .unwrap();
    });
    let authority = format!("trailers.test:{}", origin.port());
    let (proxy, listener) = response_prebound_listener();
    let config = response_base_config(
        proxy,
        r#"[policy]
default = "allow"
"#,
    );
    let (_directory, product) = start_response_product(
        &config,
        listener,
        [(format!("http://{authority}/"), origin)],
    )
    .await;
    let request = format!(
        "GET http://{authority}/response HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    );
    let response = response_send_raw(proxy, request.as_bytes()).await;
    origin_task.await.unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "unexpected downstream response: {:?}",
        String::from_utf8_lossy(&response)
    );
    let wire = String::from_utf8(response).unwrap().to_ascii_lowercase();
    assert!(wire.contains("\r\ntransfer-encoding: chunked\r\n"));
    assert!(wire.contains("\r\nd\r\nresponse-body\r\n"));
    let first = wire
        .find("x-sequence: first")
        .unwrap_or_else(|| panic!("first response trailer was absent: {wire:?}"));
    let middle = wire
        .find("x-other: middle")
        .unwrap_or_else(|| panic!("middle response trailer was absent: {wire:?}"));
    let second = wire
        .find("x-sequence: second")
        .unwrap_or_else(|| panic!("second response trailer was absent: {wire:?}"));
    assert!(first < middle && middle < second);
    assert!(!wire.contains("connection: x-remove"));
    assert!(!wire.contains("x-remove: private"));
    product.shutdown().await;
}

#[tokio::test]
async fn forwarding_capture_marks_only_nonempty_request_and_response_trailers_omitted() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = response_prebound_listener();
    let config = response_base_config(
        proxy,
        &format!(
            r#"[policy]
default = "allow"

{}"#,
            local_failure_capture_config()
        ),
    );
    let (directory, product) = start_response_product(&config, listener, []).await;

    for with_trailers in [true, false] {
        let path = if with_trailers {
            "/with-trailers"
        } else {
            "/without-trailers"
        };
        let target =
            http_access_url::canonicalize_http_url(&format!("http://capture-trailers.test{path}"))
                .unwrap();
        crate::proxy::forwarding_adapter::exercise_trailer_observation_for_test(
            Arc::clone(&product.observation_runtime),
            product.observation_runtime.current_capture_epoch(),
            if with_trailers {
                "capture-with-trailers"
            } else {
                "capture-without-trailers"
            },
            &target,
            with_trailers,
        );
    }

    product.shutdown().await;
    let records = response_capture_records(&directory);
    for with_trailers in [true, false] {
        let path = if with_trailers {
            "/with-trailers"
        } else {
            "/without-trailers"
        };
        let url = format!("http://capture-trailers.test{path}");
        for kind in [
            crate::capture::CaptureKind::Request,
            crate::capture::CaptureKind::Response,
        ] {
            let captured = records
                .iter()
                .find(|record| record.kind == kind && record.url == url)
                .unwrap_or_else(|| panic!("missing {kind:?} capture for {url}: {records:?}"));
            assert_eq!(captured.trailers_omitted, with_trailers.then_some(true));
        }
    }
}

#[tokio::test]
async fn websocket_capture_records_fragment_allocation_failure_without_body() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = response_prebound_listener();
    let config = response_base_config(
        proxy,
        &format!(
            r#"[policy]
default = "allow"

{}"#,
            local_failure_capture_config()
        ),
    );
    let (directory, product) = start_response_product(&config, listener, []).await;
    let target =
        http_access_url::canonicalize_http_url("http://capture-websocket.test/allocation")
            .unwrap();
    crate::proxy::observation_adapter::exercise_upgrade_allocation_failure_for_test(
        Arc::clone(&product.observation_runtime),
        product.observation_runtime.current_capture_epoch(),
        "capture-allocation-failure",
        &target,
    );

    product.shutdown().await;
    let records = response_capture_records(&directory);
    let captured = records
        .iter()
        .find(|record| record.request_id == "capture-allocation-failure-ws-request-0")
        .unwrap_or_else(|| panic!("missing WebSocket allocation-failure capture: {records:?}"));
    assert!(captured.body.is_none());
    assert!(captured.body_truncated.is_none());
    assert_eq!(
        captured.body_omission,
        Some(crate::capture::CaptureBodyOmission::ResourceExhausted {})
    );
}

#[tokio::test]
async fn h2_origin_repeated_response_trailers_survive_product_forwarding() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (stream, _) = origin_listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.uri().path(), "/response");
        let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
        let mut body = respond.send_response(response, false).unwrap();
        body.send_data(Bytes::from_static(b"h2-response-body"), false)
            .unwrap();
        let mut trailers = HeaderMap::new();
        trailers.append("x-repeat", HeaderValue::from_static("one"));
        trailers.append("x-repeat", HeaderValue::from_static("two"));
        body.send_trailers(trailers).unwrap();
        connection.graceful_shutdown();
        while let Some(request) = connection.accept().await {
            request.unwrap();
        }
    });
    let authority = format!("h2-trailers.test:{}", origin.port());
    let (proxy, listener) = response_prebound_listener();
    let config = response_base_config(
        proxy,
        r#"[policy]
default = "allow"
"#,
    )
    .replace(
        "[egress.origin_tls]\ntrust = \"insecure\"\nhttp_versions = [\"http1\"]",
        "[egress.origin_tls]\ntrust = \"insecure\"\nhttp_versions = [\"http2\"]",
    );
    let (_directory, product) = start_response_product(
        &config,
        listener,
        [(format!("http://{authority}/"), origin)],
    )
    .await;
    let request = format!(
        "GET http://{authority}/response HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    );
    let response = response_send_raw(proxy, request.as_bytes()).await;
    origin_task.await.unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "unexpected H2-origin downstream response: {:?}",
        String::from_utf8_lossy(&response)
    );
    assert_eq!(response_decoded_body(&response), b"h2-response-body");
    let wire = String::from_utf8(response).unwrap().to_ascii_lowercase();
    let first = wire
        .find("x-repeat: one")
        .unwrap_or_else(|| panic!("first repeated H2 trailer was absent: {wire:?}"));
    let second = wire
        .find("x-repeat: two")
        .unwrap_or_else(|| panic!("second repeated H2 trailer was absent: {wire:?}"));
    assert!(first < second);
    product.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn provider_denials_close_before_a_pipelined_request_can_execute() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = response_prebound_listener();
    let unused_origin = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    unused_origin.set_nonblocking(true).unwrap();
    let origin = unused_origin.local_addr().unwrap();
    let authority = format!("provider-pipeline.test:{}", origin.port());
    let marker_directory = tempdir().unwrap();
    let marker = marker_directory.path().join("provider-calls");
    let policy = format!(
        r#"[authorization.providers.pipeline]
kind = "process"
command = "/usr/bin/python3"
args = ["-u", "-c", '''
import json, sys
marker = {marker:?}
for line in sys.stdin:
    request = json.loads(line)
    with open(marker, "a", encoding="utf-8") as output:
        output.write(request["url"] + "\n")
        output.flush()
    if request["url"].endswith("/deny"):
        decision = "deny"
    elif request["url"].endswith("/pass"):
        decision = "pass"
    else:
        decision = "invalid"
    print(json.dumps({{"id": request["id"], "type": "response", "decision": decision}}, separators=(",", ":")), flush=True)
''']
timeout = "2s"
retire_timeout = "6s"
on_failure = "deny"
inherit_environment = false
environment = {{ PATH = "/usr/bin:/bin" }}
include_request_body = false
max_request_body_bytes = 1024
max_decoded_request_body_bytes = 1024
max_stdout_line_bytes = 4096

[policy]
default = "deny"

[[policy.rules]]
id = "provider-first"
decision = "delegate"
urls = ["http://{authority}/deny", "http://{authority}/failure", "http://{authority}/pass"]
methods = ["POST"]
authorization_provider = "pipeline"

[[policy.rules]]
id = "deny-after-pass"
decision = "deny"
urls = ["http://{authority}/pass"]
methods = ["POST"]

[[policy.rules]]
id = "queued-second"
decision = "allow"
urls = ["http://{authority}/two"]
methods = ["GET"]
"#
    );
    let config = response_base_config(proxy, &policy);
    let (_directory, product) = start_response_product(
        &config,
        listener,
        [(format!("http://{authority}/"), origin)],
    )
    .await;

    for path in ["deny", "failure", "pass"] {
        let pipelined = format!(
            "POST http://{authority}/{path} HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 4\r\n\r\nbodyGET http://{authority}/two HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        );
        let response = response_send_raw(proxy, pipelined.as_bytes()).await;
        assert!(
            response.starts_with(b"HTTP/1.1 403"),
            "unexpected {path} response: {}",
            String::from_utf8_lossy(&response)
        );
        assert_eq!(
            response
                .windows(b"HTTP/1.1 ".len())
                .filter(|window| *window == b"HTTP/1.1 ")
                .count(),
            1,
            "queued request produced a second response after {path}"
        );
    }
    let calls = fs::read_to_string(&marker).unwrap();
    assert_eq!(calls.lines().count(), 3);
    assert!(
        unused_origin.accept().is_err(),
        "a queued request reached the origin"
    );
    product.shutdown().await;
}

#[tokio::test]
async fn fixed_policy_denial_and_upstream_failure_wire_response_corpus() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = response_prebound_listener();
    let closed = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let unavailable_origin = closed.local_addr().unwrap();
    drop(closed);
    let policy = format!(
        r#"[policy]
default = "deny"

[[policy.rules]]
id = "allow-unavailable-origin"
decision = "allow"
urls = ["http://{unavailable_origin}/failure"]
"#
    );
    let config = response_base_config(proxy, &policy);
    let (_directory, product) = start_response_product(
        &config,
        listener,
        [(format!("http://{unavailable_origin}/"), unavailable_origin)],
    )
    .await;
    for (uri, expected_status, expected_body) in [
        (
            "http://deny.example/resource".to_owned(),
            StatusCode::FORBIDDEN,
            b"request denied\n".as_slice(),
        ),
        (
            format!("http://{unavailable_origin}/failure"),
            StatusCode::BAD_GATEWAY,
            b"upstream failed\n".as_slice(),
        ),
    ] {
        let authority = uri
            .strip_prefix("http://")
            .unwrap()
            .split('/')
            .next()
            .unwrap();
        let request =
            format!("GET {uri} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
        let response = response_send_raw(proxy, request.as_bytes()).await;
        assert!(response.starts_with(format!("HTTP/1.1 {}", expected_status.as_u16()).as_bytes()));
        let head = String::from_utf8_lossy(&response).to_ascii_lowercase();
        assert!(
            head.contains("\r\ncontent-type: text/plain; charset=utf-8\r\n"),
            "{uri} omitted the fixed response content type: {head:?}"
        );
        assert_eq!(response_decoded_body(&response), expected_body);
    }
    product.shutdown().await;
}

#[tokio::test]
async fn closed_origin_captures_exact_local_502_and_abandons_incomplete_request() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = response_prebound_listener();
    let closed = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let unavailable_origin = closed.local_addr().unwrap();
    drop(closed);
    let policy = format!(
        r#"{}
[policy]
default = "deny"

[[policy.rules]]
id = "allow-unavailable-origin"
decision = "allow"
urls = ["http://{unavailable_origin}/failure"]
methods = ["POST"]
"#,
        local_failure_capture_config(),
    );
    let config = response_base_config(proxy, &policy);
    let (directory, product) = start_response_product(
        &config,
        listener,
        [(format!("http://{unavailable_origin}/"), unavailable_origin)],
    )
    .await;
    let request = format!(
        "POST http://{unavailable_origin}/failure HTTP/1.1\r\nHost: {unavailable_origin}\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n7\r\npartial\r\n"
    );

    let response = response_send_raw(proxy, request.as_bytes()).await;
    assert!(response.starts_with(b"HTTP/1.1 502"));
    assert_eq!(response_decoded_body(&response), b"upstream failed\n");

    product.shutdown().await;
    let records = response_capture_records(&directory);
    let request = records
        .iter()
        .find(|record| record.kind == crate::capture::CaptureKind::Request)
        .expect("missing abandoned request metadata");
    assert!(request.body.is_none());
    assert!(request.body_truncated.is_none());
    assert_eq!(
        request.body_omission,
        Some(crate::capture::CaptureBodyOmission::Incomplete {})
    );
    assert_sanitized_local_failure_capture(
        &records,
        &format!("http://{unavailable_origin}/failure"),
        502,
        "Bad Gateway",
        b"upstream failed\n".len(),
        crate::capture::CaptureDecision::Allow,
    );
}

#[cfg(unix)]
#[tokio::test]
async fn disappeared_file_credential_captures_sanitized_local_500() {
    use std::os::unix::fs::PermissionsExt;

    const SOURCE_SECRET: &str = "caller-source-secret-500";
    const INJECTED_SECRET: &str = "injected-file-secret-500";

    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = response_prebound_listener();
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin_listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
            .await
            .expect("credential failure did not close the origin connection")
            .unwrap();
        assert!(bytes.is_empty(), "credential failure emitted request bytes");
    });
    let policy = format!(
        r#"{}
[credentials.sources.rotating]
source = "file"
path = "rotating-token"

[policy]
default = "deny"

[[policy.rules]]
id = "missing-credential"
decision = "allow"
urls = ["http://{origin}/failure"]
methods = ["GET"]

[[policy.rules.credential_actions]]
kind = "bearer"
transport_security = "cleartext_allowed"
credential = "rotating"
"#,
        local_failure_capture_config(),
    );
    let (directory, product) = start_response_product(
        &response_base_config(proxy, &policy),
        listener,
        [(format!("http://{origin}/"), origin)],
    )
    .await;
    let credential = directory.path().join("rotating-token");
    fs::write(&credential, INJECTED_SECRET).unwrap();
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&credential).unwrap();

    let url = format!("http://{origin}/failure");
    let request = format!(
        "GET {url} HTTP/1.1\r\nHost: {origin}\r\nAuthorization: Bearer {SOURCE_SECRET}\r\nConnection: close\r\n\r\n"
    );
    let response = response_send_raw(proxy, request.as_bytes()).await;
    assert!(response.starts_with(b"HTTP/1.1 500"));
    assert_eq!(response_decoded_body(&response), b"request failed\n");
    origin_task.await.unwrap();

    product.shutdown().await;
    let records = response_capture_records(&directory);
    let request_capture = records
        .iter()
        .find(|record| record.kind == crate::capture::CaptureKind::Request && record.url == url)
        .expect("missing failed request capture");
    let request_json = serde_json::to_string(request_capture).unwrap();
    assert!(!request_json.contains(SOURCE_SECRET));
    assert!(!request_json.contains(INJECTED_SECRET));
    assert_sanitized_local_failure_capture(
        &records,
        &url,
        500,
        "Internal Server Error",
        b"request failed\n".len(),
        crate::capture::CaptureDecision::Allow,
    );
}

#[tokio::test]
async fn request_head_mutation_failure_captures_typed_metadata_only_omission() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = response_prebound_listener();
    let unused_origin = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    unused_origin.set_nonblocking(true).unwrap();
    let origin = unused_origin.local_addr().unwrap();
    let replacement = "r".repeat(64 * 1024);
    let policy = format!(
        r#"{}
[policy]
default = "deny"

[[policy.rules]]
id = "head-mutation-limit"
decision = "allow"
urls = ["http://{origin}/head-failure"]
methods = ["GET"]

[[policy.rules.request_headers]]
operation = "replace"
when = "always"
name = "x-trigger"
search = "x"
replace = {replacement:?}
"#,
        local_failure_capture_config(),
    );
    let (directory, product) = start_response_product(
        &response_base_config(proxy, &policy),
        listener,
        [(format!("http://{origin}/"), origin)],
    )
    .await;
    let url = format!("http://{origin}/head-failure");
    let request = format!(
        "GET {url} HTTP/1.1\r\nHost: {origin}\r\nX-Trigger: xx\r\nConnection: close\r\n\r\n"
    );
    let response = response_send_raw(proxy, request.as_bytes()).await;
    assert!(response.starts_with(b"HTTP/1.1 500"));
    assert_eq!(response_decoded_body(&response), b"request failed\n");
    assert!(
        unused_origin.accept().is_err(),
        "head preparation failure connected to the origin"
    );

    product.shutdown().await;
    let records = response_capture_records(&directory);
    let request_capture = records
        .iter()
        .find(|record| record.kind == crate::capture::CaptureKind::Request && record.url == url)
        .expect("missing request-head failure capture");
    assert!(request_capture.headers.is_none());
    assert!(request_capture.body.is_none());
    assert!(request_capture.body_truncated.is_none());
    assert_eq!(
        request_capture.body_omission,
        Some(crate::capture::CaptureBodyOmission::HeadPreparationFailed {})
    );
    assert_sanitized_local_failure_capture(
        &records,
        &url,
        500,
        "Internal Server Error",
        b"request failed\n".len(),
        crate::capture::CaptureDecision::Allow,
    );
}

#[tokio::test]
async fn stalled_origin_response_head_captures_sanitized_local_504() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = response_prebound_listener();
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin_listener.accept().await.unwrap();
        response_read_head(&mut stream).await;
        let mut byte = [0_u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .expect("response-head timeout did not close the origin");
        assert_origin_closed(closed, "timed-out origin connection remained open");
    });
    let policy = format!(
        r#"{}
[service.forwarding]
connect_timeout = "1s"
response_head_timeout = "200ms"
body_idle_timeout = "1s"
upgrade_idle_timeout = "1s"
max_request_wire_bytes = 65536
max_request_decoded_bytes = 65536
max_response_wire_bytes = 65536
max_response_decoded_bytes = 65536
chunk_bytes = 16384
preserve_request_trailers = false
max_trailer_count = 4
max_trailer_bytes = 256

[policy]
default = "deny"

[[policy.rules]]
id = "stalled-origin"
decision = "allow"
urls = ["http://{origin}/timeout"]
methods = ["GET"]
"#,
        local_failure_capture_config(),
    );
    let (directory, product) = start_response_product(
        &response_base_config(proxy, &policy),
        listener,
        [(format!("http://{origin}/"), origin)],
    )
    .await;
    let url = format!("http://{origin}/timeout");
    let request = format!("GET {url} HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n");
    let response = response_send_raw(proxy, request.as_bytes()).await;
    assert!(response.starts_with(b"HTTP/1.1 504"));
    assert_eq!(response_decoded_body(&response), b"request timed out\n");
    origin_task.await.unwrap();

    product.shutdown().await;
    let records = response_capture_records(&directory);
    assert_sanitized_local_failure_capture(
        &records,
        &url,
        504,
        "Gateway Timeout",
        b"request timed out\n".len(),
        crate::capture::CaptureDecision::Allow,
    );
}

async fn assert_empty_chunked_request_body(stream: &mut (impl AsyncRead + Unpin)) {
    let mut body = [0_u8; 5];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut body))
        .await
        .expect("empty chunked request body timed out")
        .expect("empty chunked request body ended early");
    assert_eq!(&body, b"0\r\n\r\n");
}

async fn assert_body_pool_released(product: &ProductRuntime, message: &str) {
    let pool = product.wire_body_pool();
    tokio::time::timeout(Duration::from_secs(2), async {
        while pool.global_charge() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{message}: {} bytes remain", pool.global_charge()));
}

fn assert_exact_request_path(request: &[u8], path: &str) {
    let request_line = String::from_utf8_lossy(request);
    let actual = request_line
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1));
    assert_eq!(actual, Some(path), "origin did not receive exact path");
}

fn assert_origin_closed(result: std::io::Result<usize>, message: &str) {
    assert!(matches!(result, Ok(0) | Err(_)), "{message}");
}

async fn accept_origin(
    listener: &tokio::net::TcpListener,
    message: &str,
) -> (tokio::net::TcpStream, SocketAddr) {
    tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap_or_else(|_| panic!("{message}"))
        .unwrap()
}

async fn assert_downstream_terminated(stream: &mut tokio::net::TcpStream) {
    let mut tail = Vec::new();
    match tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut tail)).await {
        Ok(Ok(_)) | Ok(Err(_)) => {}
        Err(_) => panic!("the response watchdog did not terminate the HTTP/1 downstream"),
    }
}

fn assert_cancel_reset(reset: &h2::Error) {
    assert!(reset.is_reset());
    assert_eq!(reset.reason(), Some(h2::Reason::CANCEL));
}

fn assert_no_partial_h1_response(response: &[u8]) {
    assert!(
        response.is_empty(),
        "over-limit response committed partial HTTP/1 bytes: {response:?}"
    );
}

fn assert_h2_limit_sibling(status: StatusCode, body: &[u8]) {
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"ok");
}

fn assert_304_pipeline(response: &[u8]) {
    let first_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("first response head is complete")
        + 4;
    let first_head = String::from_utf8_lossy(&response[..first_end]).to_ascii_lowercase();
    assert!(first_head.starts_with("http/1.1 304"));
    assert_eq!(first_head.matches("\r\ncontent-length:").count(), 1);
    assert_eq!(first_head.matches("\r\ncontent-length: 8\r\n").count(), 1);
    assert!(response[first_end..].starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(b"\r\n\r\nok"));
}

fn response_watchdog_config(
    proxy: SocketAddr,
    origin: SocketAddr,
    downstream_http2: bool,
) -> String {
    let policy = format!(
        r#"[service.forwarding]
connect_timeout = "1s"
response_head_timeout = "1s"
body_idle_timeout = "200ms"
upgrade_idle_timeout = "1s"
max_request_wire_bytes = 65536
max_request_decoded_bytes = 65536
max_response_wire_bytes = 67108864
max_response_decoded_bytes = 67108864
chunk_bytes = 65536
preserve_request_trailers = false
max_trailer_count = 4
max_trailer_bytes = 256

[policy]
default = "deny"

[[policy.rules]]
id = "watchdog-response"
decision = "allow"
methods = ["GET"]
urls = ["http://{origin}/**"]
"#
    );
    let config = response_base_config(proxy, &policy).replacen(
        "request_timeout = \"5s\"",
        "request_timeout = \"750ms\"",
        1,
    );
    if downstream_http2 {
        config
            .replacen(
                "http_versions = [\"http1\"]",
                "http_versions = [\"http2\"]\nmax_concurrent_streams = 1",
                1,
            )
            .replacen(
                "[listeners.explicit_http.connect]\nhttp1 = \"deny\"",
                "[listeners.explicit_http.connect]\nhttp2 = \"deny\"",
                1,
            )
    } else {
        config
    }
}

async fn response_h2_client(
    proxy: SocketAddr,
    initial_window_size: u32,
) -> (
    h2::client::SendRequest<Bytes>,
    tokio::task::JoinHandle<Result<(), h2::Error>>,
) {
    let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let mut builder = h2::client::Builder::new();
    builder.initial_window_size(initial_window_size);
    let (sender, connection) = builder.handshake::<_, Bytes>(stream).await.unwrap();
    (sender, tokio::spawn(connection))
}

async fn response_h2_send(
    sender: &mut h2::client::SendRequest<Bytes>,
    origin: SocketAddr,
    path: &str,
) -> h2::client::ResponseFuture {
    let (response, _request_body) = sender
        .send_request(
            Request::builder()
                .uri(format!("http://{origin}{path}"))
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    response
}

async fn assert_complete_h2_response_watchdog(
    path: &'static str,
    initial_window_size: u32,
    response_body: &'static [u8],
    expected_data: &'static [u8],
    expect_sibling: bool,
) {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = response_prebound_listener();
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let (origin_closed_tx, origin_closed_rx) = tokio::sync::oneshot::channel();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) =
            accept_origin(&origin_listener, "the watchdog origin was not contacted").await;
        let request = response_read_head(&mut stream).await;
        let request_text = String::from_utf8_lossy(&request).to_ascii_lowercase();
        assert_exact_request_path(&request, path);
        assert!(request_text.contains("transfer-encoding: chunked\r\n"));
        assert_empty_chunked_request_body(&mut stream).await;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    response_body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stream.write_all(response_body).await.unwrap();

        let mut byte = [0_u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .expect("the complete-response watchdog did not close the origin");
        assert_origin_closed(
            closed,
            "the origin connection remained reusable after downstream delivery stalled",
        );
        origin_closed_tx.send(()).unwrap();

        if expect_sibling {
            let (mut sibling, _) =
                accept_origin(&origin_listener, "the sibling origin was not contacted").await;
            let request = response_read_head(&mut sibling).await;
            assert!(String::from_utf8_lossy(&request).contains("/sibling"));
            sibling
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        }
    });
    let config = response_watchdog_config(proxy, origin, true);
    let (_directory, product) =
        start_response_product(&config, listener, [(format!("http://{origin}/"), origin)]).await;
    let pool = product.wire_body_pool();
    let (mut sender, driver) = response_h2_client(proxy, initial_window_size).await;

    let response = tokio::time::timeout(
        Duration::from_secs(2),
        response_h2_send(&mut sender, origin, path).await,
    )
    .await
    .expect("the proxy did not send the complete HTTP/2 response head")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        pool.global_charge() > 0,
        "the undelivered complete response did not retain response admission"
    );

    let mut body = response.into_body();
    if !expected_data.is_empty() {
        let data = tokio::time::timeout(Duration::from_secs(2), body.data())
            .await
            .expect("the proxy did not deliver the window-sized response data")
            .expect("the response ended before its expected data")
            .expect("the response reset before its expected data");
        assert_eq!(data.as_ref(), expected_data);
    }
    let reset = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match body
                .data()
                .await
                .expect("the complete response ended without RST_STREAM")
            {
                Ok(data) => assert!(
                    data.is_empty() && !body.is_end_stream(),
                    "the stalled response produced more data or ended cleanly"
                ),
                Err(reset) => break reset,
            }
        }
    })
    .await
    .expect("the complete-response watchdog did not terminate the HTTP/2 stream");
    assert_cancel_reset(&reset);
    drop(body);

    tokio::time::timeout(Duration::from_secs(2), origin_closed_rx)
        .await
        .expect("the complete-response watchdog did not close the origin")
        .unwrap();

    if expect_sibling {
        tokio::time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|context| sender.poll_ready(context)),
        )
        .await
        .expect("the watchdog did not release the sole HTTP/2 stream slot")
        .unwrap();
        let sibling = tokio::time::timeout(
            Duration::from_secs(2),
            response_h2_send(&mut sender, origin, "/sibling").await,
        )
        .await
        .expect("the sibling response timed out")
        .expect("the watchdog failed the whole HTTP/2 connection");
        assert_eq!(sibling.status(), StatusCode::NO_CONTENT);
    }

    assert_body_pool_released(
        &product,
        "the complete HTTP/2 response retained admission past its deadline",
    )
    .await;
    origin_task.await.unwrap();
    drop(sender);
    product.shutdown().await;
    driver.await.unwrap().unwrap();
}

#[tokio::test]
async fn h2_zero_window_complete_cl1_watchdog_resets_and_preserves_sibling_stream() {
    assert_complete_h2_response_watchdog("/complete-cl1", 0, b"x", b"", true).await;
}

#[tokio::test]
async fn h2_one_byte_window_complete_cl2_watchdog_resets_without_window_update() {
    assert_complete_h2_response_watchdog("/complete-cl2-partial", 1, b"xy", b"x", false).await;
}

#[tokio::test]
async fn h2_zero_window_complete_cl0_watchdog_resets_and_releases_admission() {
    assert_complete_h2_response_watchdog("/complete-cl0", 0, b"", b"", false).await;
}

#[tokio::test]
async fn h2_exact_final_chunk_window_watchdog_resets_before_eof_poll() {
    assert_complete_h2_response_watchdog("/complete-final-chunk", 2, b"xy", b"xy", false).await;
}

#[tokio::test]
async fn h1_unread_response_body_watchdog_releases_admission_and_closes_origin() {
    const RESPONSE_BYTES: usize = 64 * 1024 * 1024;
    const CHUNK_BYTES: usize = 64 * 1024;

    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = response_prebound_listener();
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let (origin_closed_tx, origin_closed_rx) = tokio::sync::oneshot::channel();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) =
            accept_origin(&origin_listener, "the unread origin was not contacted").await;
        let request = response_read_head(&mut stream).await;
        assert_exact_request_path(&request, "/unread");
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {RESPONSE_BYTES}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let chunk = vec![b'x'; CHUNK_BYTES];
        let mut sent = 0;
        while sent < RESPONSE_BYTES {
            match stream
                .write(&chunk[..CHUNK_BYTES.min(RESPONSE_BYTES - sent)])
                .await
            {
                Ok(0) | Err(_) => break,
                Ok(written) => sent += written,
            }
        }
        origin_closed_tx.send(sent).unwrap();
    });
    let config = response_watchdog_config(proxy, origin, false);
    let (_directory, product) =
        start_response_product(&config, listener, [(format!("http://{origin}/"), origin)]).await;
    let pool = product.wire_body_pool();

    let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://{origin}/unread HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response = response_read_head(&mut client).await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(
        pool.global_charge() > 0,
        "unread HTTP/1 response did not retain response admission"
    );

    let sent = tokio::time::timeout(Duration::from_secs(2), origin_closed_rx)
        .await
        .expect("the response watchdog did not close the HTTP/1 origin")
        .unwrap();
    assert!(
        sent < RESPONSE_BYTES,
        "the origin sent the complete body despite downstream backpressure"
    );
    assert_downstream_terminated(&mut client).await;
    origin_task.await.unwrap();
    assert_body_pool_released(
        &product,
        "the unread HTTP/1 response retained admission past its deadline",
    )
    .await;
    product.shutdown().await;
}

#[tokio::test]
async fn h2_zero_window_watchdog_releases_admission_and_preserves_sibling_stream() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = response_prebound_listener();
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let (origin_closed_tx, origin_closed_rx) = tokio::sync::oneshot::channel();
    let origin_task = tokio::spawn(async move {
        let (mut stalled, _) =
            accept_origin(&origin_listener, "the stalled origin was not contacted").await;
        let first = tokio::spawn(async move {
            let request = response_read_head(&mut stalled).await;
            let request_text = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert_exact_request_path(&request, "/stalled");
            assert!(request_text.contains("transfer-encoding: chunked\r\n"));
            assert_empty_chunked_request_body(&mut stalled).await;
            stalled
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\nx")
                .await
                .unwrap();
            let mut byte = [0_u8; 1];
            let closed = tokio::time::timeout(Duration::from_secs(2), stalled.read(&mut byte))
                .await
                .expect("the response watchdog did not close the HTTP/2 origin");
            assert_origin_closed(closed, "the stalled origin received later request bytes");
            origin_closed_tx.send(()).unwrap();
        });

        let (mut sibling, _) =
            accept_origin(&origin_listener, "the sibling origin was not contacted").await;
        let request = response_read_head(&mut sibling).await;
        assert!(String::from_utf8_lossy(&request).contains("/sibling"));
        sibling
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        first.await.unwrap();
    });
    let config = response_watchdog_config(proxy, origin, true);
    let (_directory, product) =
        start_response_product(&config, listener, [(format!("http://{origin}/"), origin)]).await;
    let pool = product.wire_body_pool();
    let (mut sender, driver) = response_h2_client(proxy, 0).await;

    let stalled = tokio::time::timeout(
        Duration::from_secs(2),
        response_h2_send(&mut sender, origin, "/stalled").await,
    )
    .await
    .expect("the stalled response head timed out")
    .unwrap();
    assert_eq!(stalled.status(), StatusCode::OK);
    assert!(
        pool.global_charge() > 0,
        "zero-window HTTP/2 response did not retain response admission"
    );

    tokio::time::timeout(
        Duration::from_secs(2),
        std::future::poll_fn(|context| sender.poll_ready(context)),
    )
    .await
    .expect("the watchdog did not release the sole HTTP/2 stream slot")
    .unwrap();
    let sibling = tokio::time::timeout(
        Duration::from_secs(2),
        response_h2_send(&mut sender, origin, "/sibling").await,
    )
    .await
    .expect("the sibling response timed out")
    .expect("the stalled response failed the whole HTTP/2 connection");
    assert_eq!(sibling.status(), StatusCode::NO_CONTENT);

    drop(stalled);
    drop(sibling);
    tokio::time::timeout(Duration::from_secs(2), origin_closed_rx)
        .await
        .expect("the zero-window response watchdog did not close the origin")
        .unwrap();
    origin_task.await.unwrap();
    assert_body_pool_released(
        &product,
        "the zero-window HTTP/2 response retained admission past its deadline",
    )
    .await;

    drop(sender);
    product.shutdown().await;
    driver.await.unwrap().unwrap();
}

#[tokio::test]
async fn h2_zero_window_watchdog_sends_stream_cancel() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = response_prebound_listener();
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) =
            accept_origin(&origin_listener, "the reset origin was not contacted").await;
        let request = response_read_head(&mut stream).await;
        let request_text = String::from_utf8_lossy(&request).to_ascii_lowercase();
        assert_exact_request_path(&request, "/reset");
        assert!(request_text.contains("transfer-encoding: chunked\r\n"));
        assert_empty_chunked_request_body(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\nx")
            .await
            .unwrap();
        let mut byte = [0_u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .expect("the response watchdog did not close the reset origin");
        assert_origin_closed(closed, "the reset origin remained open");
    });
    let config = response_watchdog_config(proxy, origin, true);
    let (_directory, product) =
        start_response_product(&config, listener, [(format!("http://{origin}/"), origin)]).await;
    let (mut sender, driver) = response_h2_client(proxy, 0).await;

    let response = tokio::time::timeout(
        Duration::from_secs(2),
        response_h2_send(&mut sender, origin, "/reset").await,
    )
    .await
    .expect("the proxy did not send the HTTP/2 response head")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let mut body = response.into_body();
    let reset = tokio::time::timeout(Duration::from_secs(2), body.data())
        .await
        .expect("the response watchdog did not terminate the HTTP/2 stream")
        .expect("the reset response body ended without RST_STREAM")
        .expect_err("the zero-window response unexpectedly produced data");
    assert_cancel_reset(&reset);

    origin_task.await.unwrap();
    drop(sender);
    product.shutdown().await;
    driver.await.unwrap().unwrap();
}

fn bounded_response_wire_config(
    proxy: SocketAddr,
    origin: SocketAddr,
    downstream_http2: bool,
) -> String {
    let policy = format!(
        r#"[service.forwarding]
connect_timeout = "1s"
response_head_timeout = "1s"
body_idle_timeout = "1s"
upgrade_idle_timeout = "1s"
max_request_wire_bytes = 64
max_request_decoded_bytes = 64
max_response_wire_bytes = 5
max_response_decoded_bytes = 8
chunk_bytes = 2
preserve_request_trailers = true
max_trailer_count = 4
max_trailer_bytes = 32

[policy]
default = "deny"

[[policy.rules]]
id = "bounded-response"
decision = "allow"
methods = ["GET"]
urls = ["http://{origin}/**"]
"#
    );
    let config = response_base_config(proxy, &policy);
    if downstream_http2 {
        config
            .replacen(
                "http_versions = [\"http1\"]",
                "http_versions = [\"http2\"]",
                1,
            )
            .replacen(
                "[listeners.explicit_http.connect]\nhttp1 = \"deny\"",
                "[listeners.explicit_http.connect]\nhttp2 = \"deny\"",
                1,
            )
    } else {
        config
    }
}

async fn serve_bounded_response_origin(listener: tokio::net::TcpListener, requests: usize) {
    for _ in 0..requests {
        let (mut stream, _) =
            accept_origin(&listener, "the bounded-response origin was not contacted").await;
        let request = response_read_head(&mut stream).await;
        let response = if request
            .windows(b"/oversized".len())
            .any(|window| window == b"/oversized")
        {
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nabcdef".as_slice()
        } else {
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".as_slice()
        };
        stream.write_all(response).await.unwrap();
        stream.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn h1_response_wire_limit_closes_before_committing_a_partial_response() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = response_prebound_listener();
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let origin_task = tokio::spawn(serve_bounded_response_origin(origin_listener, 1));
    let config = bounded_response_wire_config(proxy, origin, false);
    let (_directory, product) =
        start_response_product(&config, listener, [(format!("http://{origin}/"), origin)]).await;

    let response = response_send_raw(
        proxy,
        format!(
            "GET http://{origin}/oversized HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert_no_partial_h1_response(&response);

    origin_task.await.unwrap();
    product.shutdown().await;
}

#[tokio::test]
async fn h2_response_wire_limit_resets_only_the_failed_stream() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = response_prebound_listener();
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let origin_task = tokio::spawn(serve_bounded_response_origin(origin_listener, 2));
    let config = bounded_response_wire_config(proxy, origin, true);
    let (_directory, product) =
        start_response_product(&config, listener, [(format!("http://{origin}/"), origin)]).await;
    let (mut sender, driver) = response_h2_client(proxy, 65_535).await;

    let oversized = tokio::time::timeout(
        Duration::from_secs(2),
        response_h2_send(&mut sender, origin, "/oversized").await,
    )
    .await
    .expect("the over-limit HTTP/2 response did not complete");
    assert!(
        oversized.is_err(),
        "over-limit HTTP/2 response committed a response head"
    );

    tokio::time::timeout(
        Duration::from_secs(2),
        std::future::poll_fn(|context| sender.poll_ready(context)),
    )
    .await
    .expect("the failed stream did not release HTTP/2 sender readiness")
    .unwrap();
    let sibling = tokio::time::timeout(
        Duration::from_secs(2),
        response_h2_send(&mut sender, origin, "/sibling").await,
    )
    .await
    .expect("the sibling HTTP/2 response timed out")
    .expect("the over-limit stream failed the whole HTTP/2 connection");
    let sibling_status = sibling.status();
    let mut body = sibling.into_body();
    let mut bytes = Vec::new();
    while let Some(data) = tokio::time::timeout(Duration::from_secs(2), body.data())
        .await
        .expect("the sibling body stalled")
    {
        bytes.extend_from_slice(&data.unwrap());
    }
    assert_h2_limit_sibling(sibling_status, &bytes);

    drop(sender);
    product.shutdown().await;
    driver.await.unwrap().unwrap();
    origin_task.await.unwrap();
}

#[tokio::test]
async fn h1_304_preserves_representation_content_length_and_pipeline() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let (proxy, listener) = response_prebound_listener();
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) =
                accept_origin(&origin_listener, "the 304 origin was not contacted").await;
            let request = response_read_head(&mut stream).await;
            if request
                .windows(b"/first".len())
                .any(|window| window == b"/first")
            {
                stream
                    .write_all(
                        b"HTTP/1.1 304 Not Modified\r\nContent-Length: 8\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
            } else {
                assert!(request
                    .windows(b"/second".len())
                    .any(|window| window == b"/second"));
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            }
        }
    });
    let config = response_base_config(
        proxy,
        r#"[policy]
default = "allow"
"#,
    );
    let (_directory, product) =
        start_response_product(&config, listener, [(format!("http://{origin}/"), origin)]).await;

    let response = response_send_raw(
        proxy,
        format!(
            "GET http://{origin}/first HTTP/1.1\r\nHost: {origin}\r\n\r\nGET http://{origin}/second HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    product.shutdown().await;
    origin_task.await.unwrap();

    assert_304_pipeline(&response);
}

#[tokio::test]
async fn ordinary_response_admission_saturates_before_origin_connect_and_releases() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let (first_head_tx, first_head_rx) = tokio::sync::oneshot::channel();
    let (check_tx, check_rx) = tokio::sync::oneshot::channel();
    let (checked_tx, checked_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let origin_task = tokio::spawn(async move {
        let (mut first, _) = origin_listener.accept().await.unwrap();
        let request = response_read_head(&mut first).await;
        assert!(String::from_utf8_lossy(&request).contains("/first"));
        first
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
            .await
            .unwrap();
        first_head_tx.send(()).unwrap();
        check_rx.await.unwrap();
        let escaped =
            tokio::time::timeout(Duration::from_millis(250), origin_listener.accept()).await;
        assert!(
            escaped.is_err(),
            "saturation opened a second origin connection"
        );
        checked_tx.send(()).unwrap();
        release_rx.await.unwrap();
        first.write_all(b"a").await.unwrap();
        drop(first);
        let (mut third, _) = tokio::time::timeout(Duration::from_secs(2), origin_listener.accept())
            .await
            .expect("released admission did not permit another origin connection")
            .unwrap();
        let request = response_read_head(&mut third).await;
        assert!(String::from_utf8_lossy(&request).contains("/third"));
        third
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nb")
            .await
            .unwrap();
    });
    let (proxy, listener) = response_prebound_listener();
    let policy = format!(
        r#"{}
[service.forwarding]
max_request_wire_bytes = 1024
max_request_decoded_bytes = 1024
max_response_wire_bytes = 1024
max_response_decoded_bytes = 1024
chunk_bytes = 1024
preserve_request_trailers = false
max_trailer_count = 4
max_trailer_bytes = 256

[policy]
default = "deny"

[[policy.rules]]
id = "bounded-response"
decision = "allow"
methods = ["GET"]
urls = ["http://{origin}/**"]
"#,
        local_failure_capture_config(),
    );
    let sizing_config = response_base_config(proxy, &policy);
    let sizing_root = tempdir().unwrap();
    let compiled = compile_config_text(ConfigTextInput {
        text: &sizing_config,
        source_path: &sizing_root.path().join("sizing.toml"),
        config_root: sizing_root.path(),
    })
    .unwrap_or_else(|error| panic!("response-admission sizing failed: {error}"));
    let resources = &compiled.reloadable_plan.resource_plan;
    let response_peak = resources.forward_response_peak_bytes;
    let exchange_peak = resources.max_reachable_http_exchange_peak_bytes;
    assert!(response_peak > 0);
    assert!(exchange_peak >= response_peak);
    let global_peak = exchange_peak.checked_mul(4).unwrap();
    let config = sizing_config.replacen(
        "shutdown_drain_timeout = \"1s\"",
        &format!(
            "shutdown_drain_timeout = \"1s\"\nmax_inflight_wire_body_bytes = {global_peak}\nmax_inflight_wire_body_bytes_per_quota_key = {exchange_peak}\nmin_wire_body_concurrency = 1"
        ),
        1,
    );
    let (directory, product) =
        start_response_product(&config, listener, [(format!("http://{origin}/"), origin)]).await;
    let pool = product.wire_body_pool();

    let mut first = tokio::net::TcpStream::connect(proxy).await.unwrap();
    first
        .write_all(
            format!(
                "GET http://{origin}/first HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let first_response = response_read_head(&mut first).await;
    assert!(first_response.starts_with(b"HTTP/1.1 200"));
    first_head_rx.await.unwrap();
    assert!(pool.global_charge() >= response_peak);

    check_tx.send(()).unwrap();
    let second_response = response_send_raw(
        proxy,
        format!(
            "GET http://{origin}/second HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(
        second_response.starts_with(b"HTTP/1.1 503"),
        "unexpected saturated response: {}",
        String::from_utf8_lossy(&second_response)
    );
    assert_eq!(
        response_decoded_body(&second_response),
        b"service unavailable\n"
    );
    checked_rx.await.unwrap();

    release_tx.send(()).unwrap();
    let mut first_body = [0_u8; 1];
    first.read_exact(&mut first_body).await.unwrap();
    assert_eq!(&first_body, b"a");
    drop(first);
    tokio::time::timeout(Duration::from_secs(2), async {
        while pool.global_charge() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("completed response retained wire-body admission");

    let third_response = response_send_raw(
        proxy,
        format!(
            "GET http://{origin}/third HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(third_response.starts_with(b"HTTP/1.1 200"));
    assert!(third_response.ends_with(b"b"));
    origin_task.await.unwrap();
    assert_eq!(pool.global_charge(), 0);
    product.shutdown().await;
    let second_url = format!("http://{origin}/second");
    let records = response_capture_records(&directory);
    assert_sanitized_local_failure_capture(
        &records,
        &second_url,
        503,
        "Service Unavailable",
        b"service unavailable\n".len(),
        crate::capture::CaptureDecision::Deny,
    );
}
