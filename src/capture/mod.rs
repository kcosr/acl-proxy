use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind as IoErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::SystemTime;

use base64::{engine::general_purpose, Engine as _};
use fs2::FileExt;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::config::{CaptureConfig, Config};
use crate::filesystem::create_private_dir_all;
use crate::sensitive::redact_url_for_sink;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

static CAPTURE_DIRECTORY_LOCKS: Lazy<Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static CAPTURE_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Maximum number of body bytes to buffer per request/response for capture.
///
/// The legacy Node.js implementation captured full bodies. The Rust
/// implementation intentionally limits in-memory buffering to this value
/// while still recording the full logical length separately.
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

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

    #[serde(rename = "contentEncoding", skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
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
        self.total_len = self.total_len.saturating_add(chunk.len());
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

    #[error("failed to lock capture directory {path}: {source}")]
    LockDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read capture directory {path}: {source}")]
    ReadDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read capture directory entry in {path}: {source}")]
    ReadDirEntry {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to stat capture file {path}: {source}")]
    Metadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to remove old capture file {path}: {source}")]
    RemoveFile {
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
        url: redact_url_for_sink(&url),
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

    let content_type = headers.and_then(|map| first_header_string(map, "content-type"));
    let content_encoding = headers.and_then(|map| first_header_string(map, "content-encoding"));

    let data = general_purpose::STANDARD.encode(&body.captured);

    Some(CaptureBody {
        encoding: "base64".to_string(),
        length: body.total_len,
        data,
        content_type,
        content_encoding,
    })
}

fn first_header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
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
    let directory = effective_capture_directory(&config.capture);
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

fn effective_capture_directory(capture: &CaptureConfig) -> String {
    let capture_dir = capture.directory.trim();
    if !capture_dir.is_empty() {
        return capture_dir.to_string();
    }
    "logs-capture".to_string()
}

struct CaptureFileEntry {
    path: PathBuf,
    len: u64,
    modified: SystemTime,
    is_written_file: bool,
}

pub fn write_capture_record(
    config: &Config,
    record: &CaptureRecord,
) -> Result<PathBuf, CaptureError> {
    let json = serde_json::to_string_pretty(record)?;
    let requested_path = resolve_capture_path(config, record);
    let directory = requested_path.parent().unwrap_or_else(|| Path::new("."));
    create_private_dir_all(directory).map_err(|source| CaptureError::CreateDir {
        path: directory.to_path_buf(),
        source,
    })?;
    let canonical_directory =
        fs::canonicalize(directory).map_err(|source| CaptureError::CreateDir {
            path: directory.to_path_buf(),
            source,
        })?;
    let requested_path = canonical_directory.join(
        requested_path
            .file_name()
            .expect("validated capture path has a file name"),
    );
    let directory_lock = capture_directory_lock(&canonical_directory);
    let _guard = directory_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let lock_directory = canonical_directory.join(".capture-state");
    create_private_dir_all(&lock_directory).map_err(|source| CaptureError::LockDirectory {
        path: canonical_directory.clone(),
        source,
    })?;
    let lock_path = lock_directory.join("lock");
    let lock_file =
        open_capture_lock(&lock_path).map_err(|source| CaptureError::LockDirectory {
            path: canonical_directory.clone(),
            source,
        })?;
    lock_file
        .lock_exclusive()
        .map_err(|source| CaptureError::LockDirectory {
            path: canonical_directory.clone(),
            source,
        })?;

    let (temp_path, mut temp_file) =
        create_private_capture_temp(&requested_path).map_err(|source| CaptureError::WriteFile {
            path: requested_path.clone(),
            source,
        })?;
    if let Err(source) = temp_file
        .write_all(format!("{json}\n").as_bytes())
        .and_then(|()| sync_capture_file(&temp_file))
    {
        drop(temp_file);
        let _ = fs::remove_file(&temp_path);
        return Err(CaptureError::WriteFile {
            path: requested_path.clone(),
            source,
        });
    }
    drop(temp_file);
    let path = publish_capture_no_replace(&temp_path, &requested_path).map_err(|source| {
        let _ = fs::remove_file(&temp_path);
        CaptureError::WriteFile {
            path: requested_path.clone(),
            source,
        }
    })?;
    if let Err(error) = sync_capture_directory(&canonical_directory) {
        tracing::warn!(capture_path = %path.display(), %error, "capture published but directory sync failed");
    }
    if let Err(error) = prune_capture_directory(&config.capture, &canonical_directory, &path) {
        tracing::warn!(capture_path = %path.display(), %error, "capture published but retention maintenance failed");
    }
    if let Err(error) = sync_capture_directory(&canonical_directory) {
        tracing::warn!(capture_path = %path.display(), %error, "capture retention completed but directory sync failed");
    }

    Ok(path)
}

fn open_capture_lock(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)
}

fn capture_directory_lock(directory: &Path) -> Arc<Mutex<()>> {
    let key = if directory.is_absolute() {
        directory.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|current| current.join(directory))
            .unwrap_or_else(|_| directory.to_path_buf())
    };
    let mut locks = CAPTURE_DIRECTORY_LOCKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = locks.get(&key).and_then(Weak::upgrade) {
        return existing;
    }

    locks.retain(|_, lock| lock.strong_count() > 0);
    let lock = Arc::new(Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

fn collision_capture_path(requested_path: &Path, collision: u64) -> PathBuf {
    if collision == 0 {
        return requested_path.to_path_buf();
    }
    let stem = requested_path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy();
    let extension = requested_path
        .extension()
        .map(|value| value.to_string_lossy());
    let filename = match &extension {
        Some(extension) => format!("{stem}.{collision}.{extension}"),
        None => format!("{stem}.{collision}"),
    };
    requested_path.with_file_name(filename)
}

fn publish_capture_no_replace(temp_path: &Path, requested_path: &Path) -> std::io::Result<PathBuf> {
    for collision in 0u64.. {
        let candidate = collision_capture_path(requested_path, collision);
        match fs::hard_link(temp_path, &candidate) {
            Ok(()) => {
                if let Err(error) = fs::remove_file(temp_path) {
                    tracing::warn!(capture_path = %candidate.display(), temp_path = %temp_path.display(), %error, "capture published but temp cleanup failed");
                }
                return Ok(candidate);
            }
            Err(source) if source.kind() == IoErrorKind::AlreadyExists => continue,
            Err(source) => return Err(source),
        }
    }

    unreachable!("u64 capture filename suffixes exhausted")
}

fn create_private_capture_temp(final_path: &Path) -> std::io::Result<(PathBuf, File)> {
    if let Some(parent) = final_path.parent() {
        create_private_dir_all(parent)?;
    }

    loop {
        let sequence = CAPTURE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp_path =
            final_path.with_file_name(format!(".capture.{}.{}.tmp", std::process::id(), sequence));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&temp_path) {
            Ok(file) => return Ok((temp_path, file)),
            Err(source) if source.kind() == IoErrorKind::AlreadyExists => continue,
            Err(source) => return Err(source),
        }
    }
}

fn prune_capture_directory(
    capture: &CaptureConfig,
    directory: &Path,
    written_path: &Path,
) -> Result<(), CaptureError> {
    let directory = directory.to_path_buf();
    let read_dir = fs::read_dir(&directory).map_err(|source| CaptureError::ReadDir {
        path: directory.clone(),
        source,
    })?;

    let mut entries = Vec::new();
    for entry in read_dir {
        let entry = entry.map_err(|source| CaptureError::ReadDirEntry {
            path: directory.clone(),
            source,
        })?;
        let path = entry.path();
        if is_capture_internal_file(&path) {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(source) if source.kind() == IoErrorKind::NotFound => {}
                Err(source) => return Err(CaptureError::RemoveFile { path, source }),
            }
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == IoErrorKind::NotFound => continue,
            Err(source) => return Err(CaptureError::Metadata { path, source }),
        };
        if !metadata.is_file() {
            continue;
        }

        entries.push(CaptureFileEntry {
            is_written_file: path == written_path,
            path,
            len: metadata.len(),
            modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        });
    }

    entries.sort_by(|a, b| {
        b.is_written_file
            .cmp(&a.is_written_file)
            .then_with(|| b.modified.cmp(&a.modified))
            .then_with(|| b.path.cmp(&a.path))
    });

    let mut kept_files = 0usize;
    let mut kept_bytes = 0u64;

    for entry in entries {
        let is_first = kept_files == 0;
        let within_count = kept_files < capture.max_files;
        let next_bytes = kept_bytes.saturating_add(entry.len);
        let within_bytes = next_bytes <= capture.max_total_bytes;
        if is_first || (within_count && within_bytes) {
            kept_files += 1;
            kept_bytes = next_bytes;
            continue;
        }

        match fs::remove_file(&entry.path) {
            Ok(()) => {}
            Err(source) if source.kind() == IoErrorKind::NotFound => {}
            Err(source) => {
                return Err(CaptureError::RemoveFile {
                    path: entry.path,
                    source,
                });
            }
        }
    }

    Ok(())
}

fn is_capture_internal_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(".capture.") && name.ends_with(".tmp"))
}

#[cfg(unix)]
fn sync_capture_directory(directory: &Path) -> std::io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_capture_directory(_directory: &Path) -> std::io::Result<()> {
    Ok(())
}

fn sync_capture_file(file: &File) -> std::io::Result<()> {
    file.sync_all()?;

    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;

        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config as AppConfig;

    fn minimal_config_with_capture() -> AppConfig {
        let toml = r#"
schema_version = "2"

[proxy]
listeners.explicit_http.bind = "127.0.0.1:8080"

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
    fn body_capture_length_saturates_on_overflow() {
        let mut buf = BodyCaptureBuffer {
            max_bytes: 0,
            captured: Vec::new(),
            total_len: usize::MAX - 1,
        };

        buf.push(&[1, 2, 3, 4]);

        let result = buf.finish();
        assert_eq!(result.total_len, usize::MAX);
        assert!(result.captured.is_empty());
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
            content_encoding: None,
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
            content_encoding: None,
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
            content_encoding: None,
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
        headers.insert(
            "Content-Encoding".to_string(),
            JsonValue::String("gzip".to_string()),
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
        assert_eq!(body.content_encoding.as_deref(), Some("gzip"));

        let data = general_purpose::STANDARD
            .decode(body.data)
            .expect("decode base64");
        assert_eq!(data, body_bytes);
    }

    #[test]
    fn build_capture_record_redacts_sensitive_url_parts() {
        let record = build_capture_record(CaptureRecordOptions {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            request_id: "req-1".to_string(),
            kind: CaptureKind::Request,
            decision: CaptureDecision::Allow,
            mode: CaptureMode::HttpProxy,
            url: "http://user:pass@example.com/echo?token=secret".to_string(),
            method: Some("GET".to_string()),
            client: CaptureEndpoint::default(),
            target: None,
            http_version: Some("1.1".to_string()),
            headers: None,
            status_code: None,
            status_message: None,
            body: None,
        });

        assert_eq!(record.url, "http://example.com/echo?REDACTED");
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
