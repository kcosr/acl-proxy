use std::fs;

use tempfile::TempDir;

use acl_proxy::capture::{
    build_capture_record, should_capture, BodyCaptureBuffer, CaptureDecision, CaptureEndpoint,
    CaptureKind, CaptureMode, CaptureRecordOptions, HeaderMap, DEFAULT_MAX_BODY_BYTES,
};
use acl_proxy::config::Config;

#[test]
fn capture_write_creates_expected_file_and_json() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let capture_dir = temp_dir.path().join("captures");

    let mut config = Config::default();
    config.capture.allowed_request = true;
    config.capture.directory = capture_dir.to_string_lossy().to_string();

    let mut headers = HeaderMap::new();
    headers.insert(
        "Content-Type".to_string(),
        serde_json::Value::String("text/plain".to_string()),
    );

    let mut buf = BodyCaptureBuffer::new(DEFAULT_MAX_BODY_BYTES);
    buf.push(b"hello world");
    let body_result = buf.finish();

    let opts = CaptureRecordOptions {
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        request_id: "req-1".to_string(),
        kind: CaptureKind::Request,
        decision: CaptureDecision::Allow,
        mode: CaptureMode::HttpProxy,
        url: "http://example.com/echo".to_string(),
        method: Some("POST".to_string()),
        client: CaptureEndpoint {
            address: Some("127.0.0.1".to_string()),
            port: Some(12345),
        },
        target: None,
        http_version: Some("1.1".to_string()),
        headers: Some(headers),
        status_code: Some(200),
        status_message: Some("OK".to_string()),
        body: Some(body_result),
    };

    let record = build_capture_record(opts);
    let path = acl_proxy::capture::write_capture_record(&config, &record).unwrap();

    assert!(path.exists(), "capture file should exist");
    let contents = fs::read_to_string(&path).expect("read capture file");
    let decoded: acl_proxy::capture::CaptureRecord =
        serde_json::from_str(&contents).expect("decode capture");
    assert_eq!(decoded.request_id, "req-1");
    assert_eq!(decoded.method, "POST");
    assert!(decoded.body.is_some());
}

#[test]
fn should_capture_respects_flags_in_integration() {
    let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[capture]
allowed_request = true
allowed_response = false
denied_request = false
denied_response = true
directory = "logs-capture"

[policy]
default = "deny"
    "#;

    let config: Config = toml::from_str(toml).expect("parse");

    assert!(should_capture(
        &config,
        CaptureDecision::Allow,
        CaptureKind::Request
    ));
    assert!(!should_capture(
        &config,
        CaptureDecision::Allow,
        CaptureKind::Response
    ));
    assert!(!should_capture(
        &config,
        CaptureDecision::Deny,
        CaptureKind::Request
    ));
    assert!(should_capture(
        &config,
        CaptureDecision::Deny,
        CaptureKind::Response
    ));
}
