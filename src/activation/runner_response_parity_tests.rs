use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Response, StatusCode};
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
        r#"schema_version = 3

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.explicit_http]
bind = "{bind}"
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
        r#"[service.forwarding]
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
"#
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
    let (_directory, product) =
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
}
