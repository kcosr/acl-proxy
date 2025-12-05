use std::fs::File;
use std::io::Write;
use std::process::Command;

use acl_proxy::capture::{CaptureBody, CaptureKind, CaptureRecord};
use assert_cmd::prelude::*;
use predicates::str::contains;
use tempfile::{NamedTempFile, TempDir};

fn sample_record(body: Option<CaptureBody>) -> CaptureRecord {
    CaptureRecord {
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        request_id: "req-1".to_string(),
        kind: CaptureKind::Request,
        decision: acl_proxy::capture::CaptureDecision::Allow,
        mode: acl_proxy::capture::CaptureMode::HttpProxy,
        url: "http://example.com/echo".to_string(),
        method: "POST".to_string(),
        status_code: Some(200),
        status_message: Some("OK".to_string()),
        client: acl_proxy::capture::CaptureEndpoint::default(),
        target: None,
        http_version: Some("1.1".to_string()),
        headers: None,
        body,
    }
}

#[test]
fn cli_outputs_decoded_body_for_valid_capture() {
    let body_bytes = b"hello world";
    use base64::engine::general_purpose;
    use base64::Engine as _;

    let encoded = general_purpose::STANDARD.encode(body_bytes);

    let body = CaptureBody {
        encoding: "base64".to_string(),
        length: body_bytes.len(),
        data: encoded,
        content_type: Some("text/plain".to_string()),
    };

    let record = sample_record(Some(body));
    let json = serde_json::to_string(&record).expect("serialize record");

    let mut file = NamedTempFile::new().expect("create temp capture file");
    write!(file, "{json}").expect("write capture json");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy-extract-capture-body"));
    cmd.arg(file.path());

    cmd.assert().success().stdout(contains("hello world"));
}

#[test]
fn cli_fails_for_invalid_json() {
    let file = NamedTempFile::new().expect("create temp capture file");
    {
        let mut f = File::create(file.path()).expect("open file");
        writeln!(f, "{{not-json").expect("write invalid json");
    }

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy-extract-capture-body"));
    cmd.arg(file.path());

    cmd.assert().failure().stderr(contains("invalid JSON"));
}

#[test]
fn cli_fails_when_body_missing() {
    let record = sample_record(None);
    let json = serde_json::to_string(&record).expect("serialize record");

    let mut file = NamedTempFile::new().expect("create temp capture file");
    write!(file, "{json}").expect("write capture json");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy-extract-capture-body"));
    cmd.arg(file.path());

    cmd.assert().failure().stderr(contains("no body field"));
}

#[test]
fn cli_fails_for_unsupported_encoding() {
    let body = CaptureBody {
        encoding: "utf8".to_string(),
        length: 0,
        data: "".to_string(),
        content_type: None,
    };

    let record = sample_record(Some(body));
    let json = serde_json::to_string(&record).expect("serialize record");

    let mut file = NamedTempFile::new().expect("create temp capture file");
    write!(file, "{json}").expect("write capture json");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy-extract-capture-body"));
    cmd.arg(file.path());

    cmd.assert().failure().stderr(contains("utf8"));
}

#[test]
fn cli_fails_for_empty_file() {
    let file = NamedTempFile::new().expect("create temp capture file");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy-extract-capture-body"));
    cmd.arg(file.path());

    cmd.assert().failure().stderr(contains("invalid JSON"));
}

#[test]
fn cli_fails_for_missing_file() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let missing = temp_dir.path().join("missing-capture.json");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy-extract-capture-body"));
    cmd.arg(&missing);

    cmd.assert()
        .failure()
        .stderr(contains("failed to read capture file"));
}
