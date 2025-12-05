use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::config::{CaptureConfig, Config, LoggingConfig};

/// Maximum number of body bytes to buffer per request/response for capture.
///
/// The legacy Node.js implementation captured full bodies. The Rust
/// implementation intentionally limits in-memory buffering to this value
/// while still recording the full logical length separately.
pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CaptureDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CaptureKind {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    HttpProxy,
    HttpsConnect,
    HttpsTransparent,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureEndpoint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

pub type HeaderMap = BTreeMap<String, JsonValue>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureBody {
    pub encoding: String,
    pub length: usize,
    pub data: String,

    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureRecord {
    pub timestamp: String,

    #[serde(rename = "requestId")]
    pub request_id: String,

    pub kind: CaptureKind,
    pub decision: CaptureDecision,
    pub mode: CaptureMode,
    pub url: String,
    pub method: String,

    #[serde(rename = "statusCode", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,

    #[serde(rename = "statusMessage", skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,

    pub client: CaptureEndpoint,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<CaptureEndpoint>,

    #[serde(rename = "httpVersion", skip_serializing_if = "Option::is_none")]
    pub http_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HeaderMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<CaptureBody>,
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureBodyDecodeError {
    #[error("capture has no body")]
    MissingBody,

    #[error("unsupported capture body encoding {encoding}, expected \"base64\"")]
    UnsupportedEncoding { encoding: String },

    #[error("failed to decode base64 body")]
    InvalidBase64(#[source] base64::DecodeError),
}

#[derive(Debug, Clone)]
pub struct CaptureRecordOptions {
    pub timestamp: String,
    pub request_id: String,
    pub kind: CaptureKind,
    pub decision: CaptureDecision,
    pub mode: CaptureMode,
    pub url: String,
    pub method: Option<String>,
    pub client: CaptureEndpoint,
    pub target: Option<CaptureEndpoint>,
    pub http_version: Option<String>,
    pub headers: Option<HeaderMap>,
    pub status_code: Option<u16>,
    pub status_message: Option<String>,
    pub body: Option<BodyCaptureResult>,
}

#[derive(Debug, Clone)]
pub struct BodyCaptureResult {
    pub captured: Vec<u8>,
    pub total_len: usize,
}

#[derive(Debug, Clone)]
pub struct BodyCaptureBuffer {
    max_bytes: usize,
    captured: Vec<u8>,
    total_len: usize,
}

impl BodyCaptureBuffer {
    /// Create a new bounded body capture buffer.
    ///
    /// The buffer will record at most `max_bytes` of body data while
    /// still tracking the full logical length of the stream.
    pub fn new(max_bytes: usize) -> Self {
        BodyCaptureBuffer {
            max_bytes,
            captured: Vec::new(),
            total_len: 0,
        }
    }

    /// Append a chunk of body bytes to the buffer.
    ///
    /// All bytes contribute to `total_len`, but only the first
    /// `max_bytes` bytes across all calls are retained in `captured`.
    pub fn push(&mut self, chunk: &[u8]) {
        self.total_len += chunk.len();
        if self.captured.len() >= self.max_bytes {
            return;
        }

        let remaining = self.max_bytes - self.captured.len();
        let to_take = remaining.min(chunk.len());
        if to_take > 0 {
            self.captured.extend_from_slice(&chunk[..to_take]);
        }
    }

    pub fn finish(self) -> BodyCaptureResult {
        BodyCaptureResult {
            captured: self.captured,
            total_len: self.total_len,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("failed to create capture directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write capture file {path}: {source}")]
    WriteFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to serialize capture record as JSON: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Determine whether a given request/response should be captured based on
/// the `[capture]` configuration flags.
pub fn should_capture(cfg: &Config, decision: CaptureDecision, kind: CaptureKind) -> bool {
    let capture_cfg: &CaptureConfig = &cfg.capture;
    match (decision, kind) {
        (CaptureDecision::Allow, CaptureKind::Request) => capture_cfg.allowed_request,
        (CaptureDecision::Allow, CaptureKind::Response) => capture_cfg.allowed_response,
        (CaptureDecision::Deny, CaptureKind::Request) => capture_cfg.denied_request,
        (CaptureDecision::Deny, CaptureKind::Response) => capture_cfg.denied_response,
    }
}

pub fn build_capture_record(opts: CaptureRecordOptions) -> CaptureRecord {
    let CaptureRecordOptions {
        timestamp,
        request_id,
        kind,
        decision,
        mode,
        url,
        method,
        client,
        target,
        http_version,
        headers,
        status_code,
        status_message,
        body,
    } = opts;

    let body_info = body.and_then(|b| build_body(headers.as_ref(), &b));

    CaptureRecord {
        timestamp,
        request_id,
        kind,
        decision,
        mode,
        url,
        method: method.unwrap_or_default(),
        status_code,
        status_message,
        client,
        target,
        http_version,
        headers,
        body: body_info,
    }
}

impl CaptureRecord {
    /// Decode the captured body bytes from this record.
    ///
    /// The capture format stores body bytes as base64-encoded data along with
    /// the original logical length. This helper decodes the stored bytes from
    /// the `body.data` field when present, returning an error if the body is
    /// missing, the encoding is unsupported, or the data is not valid base64.
    pub fn decode_body_bytes(&self) -> Result<Vec<u8>, CaptureBodyDecodeError> {
        let body = self
            .body
            .as_ref()
            .ok_or(CaptureBodyDecodeError::MissingBody)?;

        if body.encoding != "base64" {
            return Err(CaptureBodyDecodeError::UnsupportedEncoding {
                encoding: body.encoding.clone(),
            });
        }

        general_purpose::STANDARD
            .decode(&body.data)
            .map_err(CaptureBodyDecodeError::InvalidBase64)
    }
}

fn build_body(headers: Option<&HeaderMap>, body: &BodyCaptureResult) -> Option<CaptureBody> {
    if body.total_len == 0 {
        return None;
    }

    let content_type = headers.and_then(|map| {
        map.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .and_then(|(_, v)| match v {
                JsonValue::String(s) => Some(s.clone()),
                JsonValue::Array(arr) => arr.iter().find_map(|v| {
                    if let JsonValue::String(s) = v {
                        Some(s.clone())
                    } else {
                        None
                    }
                }),
                _ => None,
            })
    });

    let data = general_purpose::STANDARD.encode(&body.captured);

    Some(CaptureBody {
        encoding: "base64".to_string(),
        length: body.total_len,
        data,
        content_type,
    })
}

fn sanitize_path_component(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Resolve the on-disk path for a capture record.
///
/// Filenames are produced from `capture.filename` using `{requestId}`,
/// `{kind}`, and `{suffix}` placeholders. The `requestId` placeholder
/// is sanitized to avoid introducing path separators. The directory is
/// derived via `effective_capture_directory`.
pub fn resolve_capture_path(config: &Config, record: &CaptureRecord) -> PathBuf {
    let directory = effective_capture_directory(&config.capture, &config.logging);
    let kind_suffix = match record.kind {
        CaptureKind::Request => "req",
        CaptureKind::Response => "res",
    };

    let safe_request_id = sanitize_path_component(&record.request_id);
    let default_name = format!("{}-{}.json", safe_request_id, kind_suffix);

    let raw_template = {
        let tmpl = config.capture.filename.trim();
        if tmpl.is_empty() {
            default_name.as_str()
        } else {
            tmpl
        }
    };

    let filename = raw_template
        .replace("{requestId}", &safe_request_id)
        .replace(
            "{kind}",
            match record.kind {
                CaptureKind::Request => "request",
                CaptureKind::Response => "response",
            },
        )
        .replace("{suffix}", kind_suffix);

    Path::new(&directory).join(filename)
}

fn effective_capture_directory(capture: &CaptureConfig, logging: &LoggingConfig) -> String {
    let capture_dir = capture.directory.trim();
    if !capture_dir.is_empty() {
        return capture_dir.to_string();
    }

    let logging_dir = logging.directory.trim();
    if !logging_dir.is_empty() {
        return logging_dir.to_string();
    }

    "logs".to_string()
}

pub fn write_capture_record(
    config: &Config,
    record: &CaptureRecord,
) -> Result<PathBuf, CaptureError> {
    let path = resolve_capture_path(config, record);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| CaptureError::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let json = serde_json::to_string_pretty(record)?;
    fs::write(&path, format!("{json}\n")).map_err(|source| CaptureError::WriteFile {
        path: path.clone(),
        source,
    })?;

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config as AppConfig;

    fn minimal_config_with_capture() -> AppConfig {
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
denied_response = false
directory = "logs-capture"
filename = "{requestId}-{suffix}.json"

[policy]
default = "deny"
        "#;

        toml::from_str(toml).expect("parse config")
    }

    fn sample_body_result(data: &[u8]) -> BodyCaptureResult {
        let mut buf = BodyCaptureBuffer::new(DEFAULT_MAX_BODY_BYTES);
        buf.push(data);
        buf.finish()
    }

    fn sample_record_with_body(body: Option<CaptureBody>) -> CaptureRecord {
        CaptureRecord {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            request_id: "req-1".to_string(),
            kind: CaptureKind::Request,
            decision: CaptureDecision::Allow,
            mode: CaptureMode::HttpProxy,
            url: "http://example.com/echo".to_string(),
            method: "POST".to_string(),
            status_code: Some(200),
            status_message: Some("OK".to_string()),
            client: CaptureEndpoint::default(),
            target: None,
            http_version: Some("1.1".to_string()),
            headers: None,
            body,
        }
    }

    #[test]
    fn should_capture_respects_flags() {
        let cfg = minimal_config_with_capture();

        assert!(should_capture(
            &cfg,
            CaptureDecision::Allow,
            CaptureKind::Request
        ));
        assert!(!should_capture(
            &cfg,
            CaptureDecision::Allow,
            CaptureKind::Response
        ));
        assert!(!should_capture(
            &cfg,
            CaptureDecision::Deny,
            CaptureKind::Request
        ));
        assert!(!should_capture(
            &cfg,
            CaptureDecision::Deny,
            CaptureKind::Response
        ));
    }

    #[test]
    fn body_capture_truncates_at_max_size() {
        let max = 16usize;
        let mut buf = BodyCaptureBuffer::new(max);
        let chunk1 = vec![1u8; 10];
        let chunk2 = vec![2u8; 10];

        buf.push(&chunk1);
        buf.push(&chunk2);

        let result = buf.finish();
        assert_eq!(result.total_len, 20);
        assert_eq!(result.captured.len(), max);
    }

    #[test]
    fn decode_body_bytes_succeeds_for_base64_body() {
        let body_bytes = b"hello world";
        let encoded = general_purpose::STANDARD.encode(body_bytes);

        let body = CaptureBody {
            encoding: "base64".to_string(),
            length: body_bytes.len(),
            data: encoded,
            content_type: Some("text/plain".to_string()),
        };

        let record = sample_record_with_body(Some(body));
        let decoded = record.decode_body_bytes().expect("decode body");
        assert_eq!(decoded, body_bytes);
    }

    #[test]
    fn decode_body_bytes_errors_when_body_missing() {
        let record = sample_record_with_body(None);
        let err = record.decode_body_bytes().expect_err("expected error");
        match err {
            CaptureBodyDecodeError::MissingBody => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn decode_body_bytes_errors_for_unsupported_encoding() {
        let body = CaptureBody {
            encoding: "utf8".to_string(),
            length: 0,
            data: "".to_string(),
            content_type: None,
        };

        let record = sample_record_with_body(Some(body));
        let err = record.decode_body_bytes().expect_err("expected error");
        match err {
            CaptureBodyDecodeError::UnsupportedEncoding { encoding } => {
                assert_eq!(encoding, "utf8");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn decode_body_bytes_errors_for_invalid_base64() {
        let body = CaptureBody {
            encoding: "base64".to_string(),
            length: 10,
            data: "!!!not-base64!!!".to_string(),
            content_type: None,
        };

        let record = sample_record_with_body(Some(body));
        let err = record.decode_body_bytes().expect_err("expected error");
        match err {
            CaptureBodyDecodeError::InvalidBase64(_) => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn resolve_capture_path_uses_template_and_suffix() {
        let cfg = minimal_config_with_capture();

        let record = CaptureRecord {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            request_id: "req-123".to_string(),
            kind: CaptureKind::Request,
            decision: CaptureDecision::Allow,
            mode: CaptureMode::HttpProxy,
            url: "http://example.com/".to_string(),
            method: "GET".to_string(),
            status_code: None,
            status_message: None,
            client: CaptureEndpoint::default(),
            target: None,
            http_version: None,
            headers: None,
            body: None,
        };

        let path = resolve_capture_path(&cfg, &record);
        assert_eq!(path, Path::new("logs-capture").join("req-123-req.json"));
    }

    #[test]
    fn capture_record_json_shape_matches_expectations() {
        let mut cfg = minimal_config_with_capture();
        cfg.capture.directory = "logs-capture-json".to_string();

        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Type".to_string(),
            JsonValue::String("text/plain".to_string()),
        );

        let body_bytes = b"hello world";
        let body_result = sample_body_result(body_bytes);

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
            target: Some(CaptureEndpoint {
                address: Some("127.0.0.1".to_string()),
                port: Some(8080),
            }),
            http_version: Some("1.1".to_string()),
            headers: Some(headers),
            status_code: Some(200),
            status_message: Some("OK".to_string()),
            body: Some(body_result),
        };

        let record = build_capture_record(opts);
        let json = serde_json::to_string_pretty(&record).expect("serialize");

        let decoded: CaptureRecord = serde_json::from_str(&json).expect("round trip");
        assert_eq!(decoded.request_id, "req-1");
        assert_eq!(decoded.method, "POST");
        assert_eq!(decoded.status_code, Some(200));
        assert!(decoded.body.is_some());

        let body = decoded.body.unwrap();
        assert_eq!(body.encoding, "base64");
        assert_eq!(body.length, body_bytes.len());
        assert_eq!(body.content_type.as_deref(), Some("text/plain"));

        let data = general_purpose::STANDARD
            .decode(body.data)
            .expect("decode base64");
        assert_eq!(data, body_bytes);
    }

    #[test]
    fn resolve_capture_path_sanitizes_request_id() {
        let cfg = minimal_config_with_capture();

        let raw_request_id = "../etc/passwd";
        let record = CaptureRecord {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            request_id: raw_request_id.to_string(),
            kind: CaptureKind::Request,
            decision: CaptureDecision::Allow,
            mode: CaptureMode::HttpProxy,
            url: "http://example.com/".to_string(),
            method: "GET".to_string(),
            status_code: None,
            status_message: None,
            client: CaptureEndpoint::default(),
            target: None,
            http_version: None,
            headers: None,
            body: None,
        };

        let sanitized = sanitize_path_component(raw_request_id);
        assert!(!sanitized.contains('/'));
        assert!(!sanitized.contains('.'));

        let path = resolve_capture_path(&cfg, &record);
        let file_name = path
            .file_name()
            .expect("has file name")
            .to_string_lossy()
            .into_owned();
        assert!(
            file_name.starts_with(&sanitized),
            "file name {file_name} should start with sanitized id {sanitized}"
        );
    }
}
