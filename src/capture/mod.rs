use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind as IoErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::SystemTime;

use base64::{encoded_len as base64_encoded_len, engine::general_purpose, Engine as _};
use fs2::FileExt;
use once_cell::sync::Lazy;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value as JsonValue;

use crate::config::{CaptureConfig, Config};
use crate::filesystem::create_private_dir_all;
use crate::http_body::{
    decode_capture_http_body, decode_capture_websocket_permessage_deflate, CaptureContentEncoding,
    CaptureHttpDecodeError,
};
use crate::observation::{
    CaptureAllocationError, CaptureBody as OwnedCaptureBody, CaptureEpoch, CaptureEvent,
    CaptureExactBytes, CaptureOperation,
};
use crate::redaction::{PayloadClass, SnapshotError as RedactionSnapshotError};
use crate::sensitive::{is_sensitive_header_name, redact_url_for_sink, REDACTED};

mod worker;

pub(crate) use worker::CaptureWorkerStartError;
use worker::{BoundedCaptureWorker, CaptureSubmitError as WorkerSubmitError};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureSinkSpec {
    directory: PathBuf,
    filename_template: String,
    max_files: usize,
    max_total_bytes: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CaptureSinkSpecError {
    #[error("capture directory must not be empty")]
    EmptyDirectory,
    #[error("capture filename template must be a nonempty basename")]
    InvalidFilenameTemplate,
    #[error("capture max_files must be at least 1")]
    ZeroMaxFiles,
    #[error("capture max_total_bytes must be at least 1")]
    ZeroMaxTotalBytes,
}

impl CaptureSinkSpec {
    pub fn new(
        directory: PathBuf,
        filename_template: String,
        max_files: usize,
        max_total_bytes: u64,
    ) -> Result<Self, CaptureSinkSpecError> {
        if directory.as_os_str().is_empty() {
            return Err(CaptureSinkSpecError::EmptyDirectory);
        }
        if !is_valid_capture_filename_template(&filename_template) {
            return Err(CaptureSinkSpecError::InvalidFilenameTemplate);
        }
        if max_files == 0 {
            return Err(CaptureSinkSpecError::ZeroMaxFiles);
        }
        if max_total_bytes == 0 {
            return Err(CaptureSinkSpecError::ZeroMaxTotalBytes);
        }
        Ok(Self {
            directory,
            filename_template,
            max_files,
            max_total_bytes,
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn filename_template(&self) -> &str {
        &self.filename_template
    }

    pub fn max_files(&self) -> usize {
        self.max_files
    }

    pub fn max_total_bytes(&self) -> u64 {
        self.max_total_bytes
    }
}

fn is_valid_capture_filename_template(template: &str) -> bool {
    if template.is_empty()
        || template.contains('/')
        || template.contains('\\')
        || template.contains("..")
        || template.chars().any(char::is_control)
    {
        return false;
    }
    let mut components = Path::new(template).components();
    matches!(
        (components.next(), components.next()),
        (Some(std::path::Component::Normal(_)), None)
    )
}

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

#[derive(Debug, Clone)]
pub struct CaptureRecord {
    pub timestamp: String,
    pub request_id: String,

    pub kind: CaptureKind,
    pub decision: CaptureDecision,
    pub mode: CaptureMode,
    pub url: String,
    pub method: String,

    pub status_code: Option<u16>,
    pub status_message: Option<String>,

    pub client: CaptureEndpoint,

    pub target: Option<CaptureEndpoint>,
    pub http_version: Option<String>,
    pub headers: Option<HeaderMap>,
    pub body: Option<CaptureBody>,

    pub body_truncated: Option<bool>,
    pub provider_replacement_omitted: Option<bool>,
    pub provider_replacement_size: Option<usize>,
}

pub(crate) struct CaptureArtifactBody {
    total_len: usize,
    stored_len: usize,
    data: CaptureExactBytes,
    content_type: Option<String>,
    content_encoding: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureArtifactBodyError {
    #[error("capture base64 length overflow")]
    LengthOverflow,
    #[error("capture base64 allocation failed")]
    Allocation(#[from] CaptureAllocationError),
    #[error("capture base64 encoding failed")]
    Encode(#[source] std::io::Error),
}

pub(crate) struct CaptureArtifactJob {
    operation: CaptureOperation,
    epoch: Arc<CaptureEpoch>,
    metadata: SanitizedCaptureMetadata,
    payload: CaptureArtifactPayload,
    max_expansion_ratio: usize,
}

struct SanitizedCaptureMetadata {
    record: CaptureRecord,
}

impl SanitizedCaptureMetadata {
    fn from_record(mut record: CaptureRecord) -> Self {
        record.url = redact_url_for_sink(&record.url);
        if let Some(headers) = record.headers.as_mut() {
            for (name, value) in headers {
                if is_sensitive_header_name(name) {
                    *value = JsonValue::String(REDACTED.to_owned());
                }
            }
        }
        Self { record }
    }
}

enum CaptureArtifactPayload {
    Unavailable,
    Http {
        encoded: OwnedCaptureBody,
        encoding: CaptureContentEncoding,
        content_type: Option<String>,
        content_encoding_present: bool,
    },
    WebSocket {
        encoded: OwnedCaptureBody,
        compressed: bool,
        class: PayloadClass,
    },
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureArtifactJobError {
    #[error("capture metadata already contains a body outcome")]
    MetadataAlreadyHasBodyOutcome,
    #[error("capture payload belongs to another operation")]
    ForeignBody(#[from] CaptureAllocationError),
}

#[derive(Debug, thiserror::Error)]
enum CaptureArtifactProcessError {
    #[error("capture HTTP decode omitted the payload")]
    HttpDecode(#[from] CaptureHttpDecodeError),
    #[error("capture redaction omitted the payload")]
    Redaction(#[from] RedactionSnapshotError),
    #[error("capture artifact encoding omitted the payload")]
    Artifact(#[from] CaptureArtifactBodyError),
    #[error("capture WebSocket compression is not enabled by the selected profile")]
    UnsupportedWebSocketCompression,
}

pub(crate) struct CaptureArtifactWorker {
    worker: BoundedCaptureWorker<CaptureArtifactJob>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CaptureArtifactSubmitError {
    Full,
    Closed,
}

impl CaptureArtifactJob {
    pub(crate) fn try_begin(
        epoch: Arc<CaptureEpoch>,
        event: CaptureEvent,
        metadata: CaptureRecord,
        max_expansion_ratio: usize,
    ) -> Result<Option<Self>, CaptureArtifactJobError> {
        if metadata.body.is_some() || metadata.body_truncated.is_some() {
            return Err(CaptureArtifactJobError::MetadataAlreadyHasBodyOutcome);
        }
        let Some(operation) = epoch.capture().and_then(|policy| policy.try_admit(event)) else {
            return Ok(None);
        };
        Ok(Some(Self {
            operation,
            epoch,
            metadata: SanitizedCaptureMetadata::from_record(metadata),
            payload: CaptureArtifactPayload::Unavailable,
            max_expansion_ratio,
        }))
    }

    pub(crate) fn operation(&self) -> &CaptureOperation {
        &self.operation
    }

    pub(crate) fn complete_http_body(
        &mut self,
        encoded: OwnedCaptureBody,
        encoding: CaptureContentEncoding,
        content_type: Option<String>,
        content_encoding_present: bool,
    ) -> Result<(), CaptureArtifactJobError> {
        self.operation.validate_body(&encoded)?;
        if self.metadata.record.provider_replacement_omitted.is_some()
            || self.metadata.record.provider_replacement_size.is_some()
        {
            return Err(CaptureArtifactJobError::MetadataAlreadyHasBodyOutcome);
        }
        if encoded.is_empty() {
            self.payload = CaptureArtifactPayload::Unavailable;
            return Ok(());
        }
        self.payload = CaptureArtifactPayload::Http {
            encoded,
            encoding,
            content_type,
            content_encoding_present,
        };
        Ok(())
    }

    pub(crate) fn omit_body(&mut self) {
        self.payload = CaptureArtifactPayload::Unavailable;
    }

    pub(crate) fn complete_websocket_message(
        &mut self,
        encoded: OwnedCaptureBody,
        compressed: bool,
        class: PayloadClass,
    ) -> Result<(), CaptureArtifactJobError> {
        self.operation.validate_body(&encoded)?;
        if self.metadata.record.provider_replacement_omitted.is_some()
            || self.metadata.record.provider_replacement_size.is_some()
        {
            return Err(CaptureArtifactJobError::MetadataAlreadyHasBodyOutcome);
        }
        if encoded.is_empty() {
            self.payload = CaptureArtifactPayload::Unavailable;
            return Ok(());
        }
        self.payload = CaptureArtifactPayload::WebSocket {
            encoded,
            compressed,
            class,
        };
        Ok(())
    }

    fn process(mut self) {
        let body = self.process_body().map_err(|error| {
            tracing::debug!(error = %error, "capture payload omitted during artifact processing");
            error
        });
        let Some(policy) = self.epoch.capture() else {
            return;
        };
        let result = match body {
            Ok(Some(body)) => {
                write_borrowed_capture_record(policy.sink(), &self.metadata.record, &body)
            }
            Ok(None) | Err(_) => write_capture_record(policy.sink(), &self.metadata.record),
        };
        if let Err(error) = result {
            tracing::warn!(error = %error, "capture artifact write failed");
        }
    }

    fn process_body(&mut self) -> Result<Option<CaptureArtifactBody>, CaptureArtifactProcessError> {
        let payload = std::mem::replace(&mut self.payload, CaptureArtifactPayload::Unavailable);
        let Some(policy) = self.epoch.capture() else {
            return Ok(None);
        };
        match payload {
            CaptureArtifactPayload::Unavailable => Ok(None),
            CaptureArtifactPayload::Http {
                encoded,
                encoding,
                content_type,
                content_encoding_present,
            } => {
                let decoded = decode_capture_http_body(
                    encoding,
                    encoded,
                    &self.operation,
                    policy.profile(),
                    self.max_expansion_ratio,
                )?;
                let redacted = policy
                    .profile()
                    .redact_capture_decoded_http_body(&self.operation, decoded)?;
                let body = CaptureArtifactBody::encode(
                    &self.operation,
                    redacted.body,
                    policy.max_body_bytes(),
                    content_type,
                    content_encoding_present.then(|| "identity".to_owned()),
                )?;
                Ok(Some(body))
            }
            CaptureArtifactPayload::WebSocket {
                encoded,
                compressed,
                class,
            } => {
                let limits = policy.profile().limits();
                let decoded = if compressed {
                    if !limits.allow_permessage_deflate {
                        return Err(CaptureArtifactProcessError::UnsupportedWebSocketCompression);
                    }
                    decode_capture_websocket_permessage_deflate(
                        encoded,
                        &self.operation,
                        limits.max_message_bytes,
                    )?
                } else {
                    encoded
                };
                let redacted = policy.profile().redact_capture_websocket_message(
                    &self.operation,
                    decoded,
                    class,
                )?;
                let body = CaptureArtifactBody::encode(
                    &self.operation,
                    redacted.body,
                    policy.max_body_bytes(),
                    None,
                    None,
                )?;
                Ok(Some(body))
            }
        }
    }
}

impl CaptureArtifactWorker {
    pub(crate) fn start(capacity: usize) -> Result<Self, CaptureWorkerStartError> {
        Ok(Self {
            worker: BoundedCaptureWorker::start(capacity, CaptureArtifactJob::process)?,
        })
    }

    pub(crate) fn try_submit(
        &self,
        job: CaptureArtifactJob,
    ) -> Result<(), CaptureArtifactSubmitError> {
        self.worker.try_submit(job).map_err(|error| match error {
            WorkerSubmitError::Full(_) => CaptureArtifactSubmitError::Full,
            WorkerSubmitError::Closed(_) => CaptureArtifactSubmitError::Closed,
        })
    }

    pub(crate) fn begin_shutdown(&self) {
        self.worker.begin_shutdown();
    }

    pub(crate) async fn shutdown(&self) {
        self.worker.shutdown().await;
    }
}

impl CaptureArtifactBody {
    pub(crate) fn encode(
        operation: &CaptureOperation,
        mut body: OwnedCaptureBody,
        max_body_bytes: usize,
        content_type: Option<String>,
        content_encoding: Option<String>,
    ) -> Result<Self, CaptureArtifactBodyError> {
        operation.validate_body(&body)?;
        let total_len = body.len();
        body.truncate(max_body_bytes.min(total_len));
        let stored_len = body.len();
        let encoded_len =
            base64_encoded_len(stored_len, true).ok_or(CaptureArtifactBodyError::LengthOverflow)?;
        let mut data = operation.exact_bytes(encoded_len)?;
        {
            let output = data.as_mut_slice();
            let mut encoder = base64::write::EncoderWriter::new(output, &general_purpose::STANDARD);
            for segment in body.segments() {
                encoder
                    .write_all(segment)
                    .map_err(CaptureArtifactBodyError::Encode)?;
            }
            let remaining = encoder.finish().map_err(CaptureArtifactBodyError::Encode)?;
            debug_assert!(remaining.is_empty(), "checked base64 length is exact");
        }
        drop(body);
        Ok(Self {
            total_len,
            stored_len,
            data,
            content_type,
            content_encoding,
        })
    }

    pub(crate) fn total_len(&self) -> usize {
        self.total_len
    }

    pub(crate) fn data(&self) -> &str {
        std::str::from_utf8(self.data.as_slice()).expect("base64 output is ASCII")
    }

    pub(crate) fn is_truncated(&self) -> bool {
        self.stored_len < self.total_len
    }
}

#[derive(Serialize)]
struct BorrowedCaptureArtifactBody<'a> {
    encoding: &'static str,
    length: usize,
    data: &'a str,
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    content_type: Option<&'a str>,
    #[serde(rename = "contentEncoding", skip_serializing_if = "Option::is_none")]
    content_encoding: Option<&'a str>,
}

struct BorrowedCaptureArtifactRecord<'a> {
    metadata: &'a CaptureRecord,
    body: &'a CaptureArtifactBody,
}

impl Serialize for BorrowedCaptureArtifactRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.metadata.body.is_some()
            || self.metadata.body_truncated.is_some()
            || self.metadata.provider_replacement_omitted.is_some()
            || self.metadata.provider_replacement_size.is_some()
        {
            return Err(serde::ser::Error::custom(
                "capture artifact metadata already contains a body outcome",
            ));
        }
        let body = BorrowedCaptureArtifactBody {
            encoding: "base64",
            length: self.body.total_len,
            data: self.body.data(),
            content_type: self.body.content_type.as_deref(),
            content_encoding: self.body.content_encoding.as_deref(),
        };
        let mut state = serializer.serialize_struct("CaptureRecord", 15)?;
        serialize_capture_metadata(&mut state, self.metadata)?;
        state.serialize_field("body", &body)?;
        if self.body.is_truncated() {
            state.serialize_field("bodyTruncated", &true)?;
        }
        state.end()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CaptureRecordInvariantError {
    #[error("bodyTruncated must be present only as true for a shorter base64 body prefix")]
    InvalidBodyTruncated,
    #[error("providerReplacementOmitted must be true and paired with providerReplacementSize")]
    InvalidProviderReplacementMarker,
    #[error("provider replacement records must omit body and bodyTruncated")]
    ProviderReplacementContainsBody,
}

#[derive(Deserialize)]
struct CaptureRecordWire {
    timestamp: String,
    #[serde(rename = "requestId")]
    request_id: String,
    kind: CaptureKind,
    decision: CaptureDecision,
    mode: CaptureMode,
    url: String,
    method: String,
    #[serde(rename = "statusCode")]
    status_code: Option<u16>,
    #[serde(rename = "statusMessage")]
    status_message: Option<String>,
    client: CaptureEndpoint,
    target: Option<CaptureEndpoint>,
    #[serde(rename = "httpVersion")]
    http_version: Option<String>,
    headers: Option<HeaderMap>,
    body: Option<CaptureBody>,
    #[serde(rename = "bodyTruncated")]
    body_truncated: Option<bool>,
    #[serde(rename = "providerReplacementOmitted")]
    provider_replacement_omitted: Option<bool>,
    #[serde(rename = "providerReplacementSize")]
    provider_replacement_size: Option<usize>,
}

impl CaptureRecord {
    fn validate_invariants(&self) -> Result<(), CaptureRecordInvariantError> {
        match (
            self.provider_replacement_omitted,
            self.provider_replacement_size,
        ) {
            (None, None) => {}
            (Some(true), Some(_)) => {
                if self.body.is_some() || self.body_truncated.is_some() {
                    return Err(CaptureRecordInvariantError::ProviderReplacementContainsBody);
                }
                return Ok(());
            }
            _ => return Err(CaptureRecordInvariantError::InvalidProviderReplacementMarker),
        }

        if self.body_truncated == Some(false)
            || self.body_truncated.is_some() && self.body.is_none()
        {
            return Err(CaptureRecordInvariantError::InvalidBodyTruncated);
        }
        if let Some(body) = &self.body {
            if body.encoding == "base64" {
                let Some(stored_len) = canonical_base64_decoded_len(&body.data) else {
                    return self
                        .body_truncated
                        .is_none()
                        .then_some(())
                        .ok_or(CaptureRecordInvariantError::InvalidBodyTruncated);
                };
                let truncated = stored_len < body.length;
                if stored_len > body.length || self.body_truncated != truncated.then_some(true) {
                    return Err(CaptureRecordInvariantError::InvalidBodyTruncated);
                }
            } else if self.body_truncated.is_some() {
                return Err(CaptureRecordInvariantError::InvalidBodyTruncated);
            }
        }
        Ok(())
    }

    pub fn mark_provider_replacement_omitted(&mut self, size: usize) {
        self.body = None;
        self.body_truncated = None;
        self.provider_replacement_omitted = Some(true);
        self.provider_replacement_size = Some(size);
    }
}

fn canonical_base64_decoded_len(encoded: &str) -> Option<usize> {
    let bytes = encoded.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    if bytes.is_empty() {
        return Some(0);
    }

    let padding = if bytes.ends_with(b"==") {
        2
    } else if bytes.ends_with(b"=") {
        1
    } else {
        0
    };
    let payload_len = bytes.len().checked_sub(padding)?;
    let mut last_sextet = 0;
    for (index, &byte) in bytes[..payload_len].iter().enumerate() {
        let sextet = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        if index + 1 == payload_len {
            last_sextet = sextet;
        }
    }
    if bytes[payload_len..].iter().any(|&byte| byte != b'=') {
        return None;
    }
    match padding {
        1 if payload_len % 4 != 3 || last_sextet & 0b11 != 0 => return None,
        2 if payload_len % 4 != 2 || last_sextet & 0b1111 != 0 => return None,
        0 if payload_len % 4 != 0 => return None,
        _ => {}
    }

    bytes
        .len()
        .checked_div(4)?
        .checked_mul(3)?
        .checked_sub(padding)
}

impl Serialize for CaptureRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate_invariants()
            .map_err(serde::ser::Error::custom)?;
        let mut state = serializer.serialize_struct("CaptureRecord", 18)?;
        serialize_capture_metadata(&mut state, self)?;
        if let Some(value) = &self.body {
            state.serialize_field("body", value)?;
        }
        if let Some(value) = &self.body_truncated {
            state.serialize_field("bodyTruncated", value)?;
        }
        if let Some(value) = &self.provider_replacement_omitted {
            state.serialize_field("providerReplacementOmitted", value)?;
        }
        if let Some(value) = &self.provider_replacement_size {
            state.serialize_field("providerReplacementSize", value)?;
        }
        state.end()
    }
}

fn serialize_capture_metadata<S>(state: &mut S, record: &CaptureRecord) -> Result<(), S::Error>
where
    S: SerializeStruct,
{
    state.serialize_field("timestamp", &record.timestamp)?;
    state.serialize_field("requestId", &record.request_id)?;
    state.serialize_field("kind", &record.kind)?;
    state.serialize_field("decision", &record.decision)?;
    state.serialize_field("mode", &record.mode)?;
    state.serialize_field("url", &record.url)?;
    state.serialize_field("method", &record.method)?;
    if let Some(value) = &record.status_code {
        state.serialize_field("statusCode", value)?;
    }
    if let Some(value) = &record.status_message {
        state.serialize_field("statusMessage", value)?;
    }
    state.serialize_field("client", &record.client)?;
    if let Some(value) = &record.target {
        state.serialize_field("target", value)?;
    }
    if let Some(value) = &record.http_version {
        state.serialize_field("httpVersion", value)?;
    }
    if let Some(value) = &record.headers {
        state.serialize_field("headers", value)?;
    }
    Ok(())
}

impl<'de> Deserialize<'de> for CaptureRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CaptureRecordWire::deserialize(deserializer)?;
        let record = Self {
            timestamp: wire.timestamp,
            request_id: wire.request_id,
            kind: wire.kind,
            decision: wire.decision,
            mode: wire.mode,
            url: wire.url,
            method: wire.method,
            status_code: wire.status_code,
            status_message: wire.status_message,
            client: wire.client,
            target: wire.target,
            http_version: wire.http_version,
            headers: wire.headers,
            body: wire.body,
            body_truncated: wire.body_truncated,
            provider_replacement_omitted: wire.provider_replacement_omitted,
            provider_replacement_size: wire.provider_replacement_size,
        };
        record
            .validate_invariants()
            .map_err(serde::de::Error::custom)?;
        Ok(record)
    }
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
    let body_truncated = body_info
        .as_ref()
        .and_then(|(_, truncated)| truncated.then_some(true));
    let body = body_info.map(|(body, _)| body);

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
        body,
        body_truncated,
        provider_replacement_omitted: None,
        provider_replacement_size: None,
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

fn build_body(
    headers: Option<&HeaderMap>,
    body: &BodyCaptureResult,
) -> Option<(CaptureBody, bool)> {
    if body.total_len == 0 {
        return None;
    }

    let content_type = headers.and_then(|map| first_header_string(map, "content-type"));
    let content_encoding = headers.and_then(|map| first_header_string(map, "content-encoding"));

    let data = general_purpose::STANDARD.encode(&body.captured);

    Some((
        CaptureBody {
            encoding: "base64".to_string(),
            length: body.total_len,
            data,
            content_type,
            content_encoding,
        },
        body.captured.len() < body.total_len,
    ))
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
pub fn resolve_capture_path(sink: &CaptureSinkSpec, record: &CaptureRecord) -> PathBuf {
    let kind_suffix = match record.kind {
        CaptureKind::Request => "req",
        CaptureKind::Response => "res",
    };

    let safe_request_id = sanitize_path_component(&record.request_id);
    let raw_template = sink.filename_template();

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

    sink.directory().join(filename)
}

struct CaptureFileEntry {
    path: PathBuf,
    len: u64,
    modified: SystemTime,
    is_written_file: bool,
}

pub fn write_capture_record(
    sink: &CaptureSinkSpec,
    record: &CaptureRecord,
) -> Result<PathBuf, CaptureError> {
    write_capture_value(sink, record, record)
}

fn write_borrowed_capture_record(
    sink: &CaptureSinkSpec,
    metadata: &CaptureRecord,
    body: &CaptureArtifactBody,
) -> Result<PathBuf, CaptureError> {
    write_capture_value(
        sink,
        metadata,
        &BorrowedCaptureArtifactRecord { metadata, body },
    )
}

fn write_capture_value<T: Serialize>(
    sink: &CaptureSinkSpec,
    naming_record: &CaptureRecord,
    value: &T,
) -> Result<PathBuf, CaptureError> {
    let requested_path = resolve_capture_path(sink, naming_record);
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
    if let Err(error) = write_capture_artifact(&mut temp_file, value) {
        drop(temp_file);
        let _ = fs::remove_file(&temp_path);
        return Err(match error {
            CaptureArtifactWriteError::Serialize(source) => CaptureError::Serialize(source),
            CaptureArtifactWriteError::Io(source) => CaptureError::WriteFile {
                path: requested_path.clone(),
                source,
            },
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
    if let Err(error) = prune_capture_directory(sink, &canonical_directory, &path) {
        tracing::warn!(capture_path = %path.display(), %error, "capture published but retention maintenance failed");
    }
    if let Err(error) = sync_capture_directory(&canonical_directory) {
        tracing::warn!(capture_path = %path.display(), %error, "capture retention completed but directory sync failed");
    }

    Ok(path)
}

enum CaptureArtifactWriteError {
    Serialize(serde_json::Error),
    Io(std::io::Error),
}

fn write_capture_artifact<T: Serialize>(
    file: &mut File,
    value: &T,
) -> Result<(), CaptureArtifactWriteError> {
    serde_json::to_writer(&mut *file, value).map_err(CaptureArtifactWriteError::Serialize)?;
    file.write_all(b"\n")
        .map_err(CaptureArtifactWriteError::Io)?;
    sync_capture_file(file).map_err(CaptureArtifactWriteError::Io)
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
    sink: &CaptureSinkSpec,
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
        let within_count = kept_files < sink.max_files();
        let next_bytes = kept_bytes.saturating_add(entry.len);
        let within_bytes = next_bytes <= sink.max_total_bytes();
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
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::compiler::{
        CapturePlan, CaptureWorkingSetPlan, CompiledCaptureEvent, CompiledLogLevel,
        CompiledRedactionPayloads, ObservationPlan, PolicyDecisionLoggingPlan, RedactionPlan,
        RedactionProfilePlan, RedactionRulePlan, ReloadableLoggingPlan,
    };
    use crate::config::Config as AppConfig;
    use crate::observation::{CapturePool, ProductObservationSnapshot};
    use crate::redaction::RedactionSnapshot;
    use crate::runtime::GenerationOwner;

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

    fn sink_from_config(config: &AppConfig) -> CaptureSinkSpec {
        CaptureSinkSpec::new(
            PathBuf::from(&config.capture.directory),
            if config.capture.filename.trim().is_empty() {
                "{requestId}-{suffix}.json".to_string()
            } else {
                config.capture.filename.clone()
            },
            config.capture.max_files,
            config.capture.max_total_bytes,
        )
        .unwrap()
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
            body_truncated: None,
            provider_replacement_omitted: None,
            provider_replacement_size: None,
        }
    }

    fn capture_engine_epoch(
        directory: &Path,
        max_body_bytes: usize,
        allow_permessage_deflate: bool,
    ) -> (
        Arc<crate::observation::CaptureEpoch>,
        Arc<dyn GenerationOwner>,
    ) {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "capture".to_owned(),
            RedactionProfilePlan {
                replacement: b"REDACTED".to_vec(),
                max_body_bytes: 1024,
                max_decoded_body_bytes: 1024,
                max_frame_bytes: 1024,
                max_message_bytes: 1024,
                allow_permessage_deflate,
                max_environment_literal_sources: 0,
                max_environment_literal_bytes: 0,
                max_environment_literal_total_bytes: 0,
                rules: vec![RedactionRulePlan {
                    literals: vec![b"secret".to_vec()],
                    literal_environment_variables: Vec::new(),
                    expressions: Vec::new(),
                    payloads: CompiledRedactionPayloads::Both,
                }],
            },
        );
        let redaction = RedactionSnapshot::activate(RedactionPlan { profiles }, || false)
            .expect("redaction activation");
        let pool = CapturePool::new();
        let activation = ProductObservationSnapshot::activate(
            ObservationPlan {
                logging: ReloadableLoggingPlan {
                    level: CompiledLogLevel::Info,
                    policy_decisions: PolicyDecisionLoggingPlan {
                        allows: false,
                        denies: false,
                        allow_level: CompiledLogLevel::Info,
                        deny_level: CompiledLogLevel::Warn,
                    },
                },
                capture: Some(CapturePlan {
                    events: vec![
                        CompiledCaptureEvent::RequestAllowed,
                        CompiledCaptureEvent::ResponseAllowed,
                    ],
                    redaction_profile: "capture".to_owned(),
                    sink: CaptureSinkSpec::new(
                        directory.to_path_buf(),
                        "{requestId}-{suffix}.json".to_owned(),
                        16,
                        1024 * 1024,
                    )
                    .expect("capture sink"),
                    max_body_bytes,
                    max_inflight_body_bytes: 1024 * 1024,
                    working_set: CaptureWorkingSetPlan::default(),
                }),
            },
            &redaction,
            pool.clone(),
        )
        .expect("observation activation");
        let (_snapshot, owner) = activation.into_parts();
        owner
            .publication_guard()
            .expect("capture publication")
            .commit();
        (pool.current_epoch(), owner)
    }

    fn operation_body(job: &CaptureArtifactJob, bytes: &[u8]) -> OwnedCaptureBody {
        let mut body = job.operation().body_buffer();
        body.try_extend_from_slice(bytes).expect("capture body");
        body.finish()
    }

    fn read_only_capture_record(directory: &Path) -> CaptureRecord {
        let mut records = fs::read_dir(directory)
            .expect("capture directory")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 1, "one capture artifact must be published");
        let bytes = fs::read(records.pop().unwrap()).expect("capture artifact");
        serde_json::from_slice(&bytes).expect("valid capture artifact")
    }

    #[tokio::test]
    async fn artifact_worker_redacts_before_truncation_and_base64_serialization() {
        let directory = tempfile::tempdir().unwrap();
        let (epoch, _owner) = capture_engine_epoch(directory.path(), 5, false);
        let mut job = CaptureArtifactJob::try_begin(
            epoch,
            crate::observation::CaptureEvent::RequestAllowed,
            sample_record_with_body(None),
            16,
        )
        .unwrap()
        .expect("capture admission");
        let encoded = operation_body(&job, b"AAsecretBB");
        job.complete_http_body(encoded, CaptureContentEncoding::Identity, None, false)
            .unwrap();

        let worker = CaptureArtifactWorker::start(1).unwrap();
        worker.try_submit(job).unwrap();
        worker.shutdown().await;

        let record = read_only_capture_record(directory.path());
        assert_eq!(record.decode_body_bytes().unwrap(), b"AARED");
        assert_eq!(record.body.as_ref().unwrap().length, 12);
        assert_eq!(record.body_truncated, Some(true));
        assert!(!fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| fs::read(entry.path()).ok())
            .any(|bytes| bytes
                .windows(b"secret".len())
                .any(|window| window == b"secret")));
    }

    #[tokio::test]
    async fn artifact_worker_emits_metadata_only_when_http_decode_fails() {
        let directory = tempfile::tempdir().unwrap();
        let (epoch, _owner) = capture_engine_epoch(directory.path(), 1024, false);
        let mut job = CaptureArtifactJob::try_begin(
            epoch,
            crate::observation::CaptureEvent::RequestAllowed,
            sample_record_with_body(None),
            16,
        )
        .unwrap()
        .expect("capture admission");
        let encoded = operation_body(&job, b"not-a-gzip-stream");
        job.complete_http_body(encoded, CaptureContentEncoding::Gzip, None, true)
            .unwrap();

        let worker = CaptureArtifactWorker::start(1).unwrap();
        worker.try_submit(job).unwrap();
        worker.shutdown().await;

        let record = read_only_capture_record(directory.path());
        assert!(record.body.is_none());
        assert!(record.body_truncated.is_none());
    }

    #[tokio::test]
    async fn artifact_worker_emits_metadata_only_for_complete_empty_http_body() {
        let directory = tempfile::tempdir().unwrap();
        let (epoch, _owner) = capture_engine_epoch(directory.path(), 1024, false);
        let mut job = CaptureArtifactJob::try_begin(
            epoch,
            crate::observation::CaptureEvent::RequestAllowed,
            sample_record_with_body(None),
            16,
        )
        .unwrap()
        .expect("capture admission");
        let encoded = operation_body(&job, b"");
        job.complete_http_body(encoded, CaptureContentEncoding::Gzip, None, true)
            .unwrap();

        let worker = CaptureArtifactWorker::start(1).unwrap();
        worker.try_submit(job).unwrap();
        worker.shutdown().await;

        let record = read_only_capture_record(directory.path());
        assert!(record.body.is_none());
        assert!(record.body_truncated.is_none());
    }

    #[tokio::test]
    async fn artifact_worker_redacts_complete_websocket_text_messages() {
        let directory = tempfile::tempdir().unwrap();
        let (epoch, _owner) = capture_engine_epoch(directory.path(), 1024, false);
        let mut metadata = sample_record_with_body(None);
        metadata.request_id = "websocket".to_owned();
        let mut job = CaptureArtifactJob::try_begin(
            epoch,
            crate::observation::CaptureEvent::ResponseAllowed,
            metadata,
            16,
        )
        .unwrap()
        .expect("capture admission");
        let encoded = operation_body(&job, b"before secret after");
        job.complete_websocket_message(encoded, false, PayloadClass::Text)
            .unwrap();

        let worker = CaptureArtifactWorker::start(1).unwrap();
        worker.try_submit(job).unwrap();
        worker.shutdown().await;

        let record = read_only_capture_record(directory.path());
        assert_eq!(
            record.decode_body_bytes().unwrap(),
            b"before REDACTED after"
        );
        assert_eq!(record.body_truncated, None);
    }

    #[tokio::test]
    async fn artifact_worker_emits_metadata_only_for_complete_empty_websocket_message() {
        let directory = tempfile::tempdir().unwrap();
        let (epoch, _owner) = capture_engine_epoch(directory.path(), 1024, false);
        let mut metadata = sample_record_with_body(None);
        metadata.request_id = "empty-websocket".to_owned();
        let mut job = CaptureArtifactJob::try_begin(
            epoch,
            crate::observation::CaptureEvent::ResponseAllowed,
            metadata,
            16,
        )
        .unwrap()
        .expect("capture admission");
        let encoded = operation_body(&job, b"");
        job.complete_websocket_message(encoded, true, PayloadClass::Binary)
            .unwrap();

        let worker = CaptureArtifactWorker::start(1).unwrap();
        worker.try_submit(job).unwrap();
        worker.shutdown().await;

        let record = read_only_capture_record(directory.path());
        assert!(record.body.is_none());
        assert!(record.body_truncated.is_none());
    }

    #[tokio::test]
    async fn artifact_worker_sanitizes_metadata_at_the_queue_boundary() {
        let directory = tempfile::tempdir().unwrap();
        let (epoch, _owner) = capture_engine_epoch(directory.path(), 1024, false);
        let mut metadata = sample_record_with_body(None);
        metadata.request_id = "credential-metadata".to_owned();
        metadata.url =
            "https://alice:url-password@example.com/path?token=query-secret#fragment".to_owned();
        metadata.headers = Some(HeaderMap::from([
            (
                "Authorization".to_owned(),
                JsonValue::String("Bearer authorization-secret".to_owned()),
            ),
            (
                "COOKIE".to_owned(),
                JsonValue::Array(vec![JsonValue::String("session=cookie-secret".to_owned())]),
            ),
            (
                "content-type".to_owned(),
                JsonValue::String("text/plain".to_owned()),
            ),
        ]));
        let job = CaptureArtifactJob::try_begin(
            epoch,
            crate::observation::CaptureEvent::RequestAllowed,
            metadata,
            16,
        )
        .unwrap()
        .expect("capture admission");

        let worker = CaptureArtifactWorker::start(1).unwrap();
        worker.try_submit(job).unwrap();
        worker.shutdown().await;

        let record = read_only_capture_record(directory.path());
        assert_eq!(record.url, "https://example.com/path?REDACTED");
        let headers = record.headers.as_ref().unwrap();
        assert_eq!(
            headers.get("Authorization"),
            Some(&JsonValue::String(REDACTED.to_owned()))
        );
        assert_eq!(
            headers.get("COOKIE"),
            Some(&JsonValue::String(REDACTED.to_owned()))
        );
        assert_eq!(
            headers.get("content-type"),
            Some(&JsonValue::String("text/plain".to_owned()))
        );
        let artifact = fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .and_then(|path| fs::read(path).ok())
            .expect("persisted capture artifact");
        for secret in [
            b"url-password".as_slice(),
            b"query-secret".as_slice(),
            b"authorization-secret".as_slice(),
            b"cookie-secret".as_slice(),
        ] {
            assert!(!artifact
                .windows(secret.len())
                .any(|window| window == secret));
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
    fn capture_sink_spec_validates_path_and_retention_inputs() {
        let valid = CaptureSinkSpec::new(
            PathBuf::from("captures"),
            "{requestId}-{suffix}.json".to_string(),
            10,
            1024,
        )
        .unwrap();
        assert_eq!(valid.directory(), Path::new("captures"));
        assert_eq!(valid.filename_template(), "{requestId}-{suffix}.json");
        assert_eq!(valid.max_files(), 10);
        assert_eq!(valid.max_total_bytes(), 1024);

        assert_eq!(
            CaptureSinkSpec::new(PathBuf::new(), "capture.json".to_string(), 1, 1),
            Err(CaptureSinkSpecError::EmptyDirectory)
        );
        for filename in ["", ".", "..", "nested/capture.json", "nested\\capture.json"] {
            assert_eq!(
                CaptureSinkSpec::new(PathBuf::from("captures"), filename.to_string(), 1, 1),
                Err(CaptureSinkSpecError::InvalidFilenameTemplate)
            );
        }
        assert_eq!(
            CaptureSinkSpec::new(PathBuf::from("captures"), "capture.json".to_string(), 0, 1,),
            Err(CaptureSinkSpecError::ZeroMaxFiles)
        );
        assert_eq!(
            CaptureSinkSpec::new(PathBuf::from("captures"), "capture.json".to_string(), 1, 0,),
            Err(CaptureSinkSpecError::ZeroMaxTotalBytes)
        );
    }

    #[test]
    fn canonical_base64_length_is_computed_without_decoding() {
        for (encoded, decoded_len) in [
            ("", 0),
            ("Zg==", 1),
            ("Zm8=", 2),
            ("Zm9v", 3),
            ("/w==", 1),
            ("//8=", 2),
            ("////", 3),
        ] {
            assert_eq!(
                canonical_base64_decoded_len(encoded),
                Some(decoded_len),
                "canonical input {encoded:?}"
            );
        }
    }

    #[test]
    fn canonical_base64_length_rejects_invalid_alphabet_padding_and_pad_bits() {
        for encoded in [
            "Zg", "Zg=", "Zg===", "=Zg=", "Z=g=", "Zg==\\n", "Zg-_", "====", "Zh==", "Zm9=",
        ] {
            assert_eq!(
                canonical_base64_decoded_len(encoded),
                None,
                "invalid input {encoded:?}"
            );
        }
    }

    #[test]
    fn truncated_body_marker_is_exact_and_round_trips() {
        let record = build_capture_record(CaptureRecordOptions {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            request_id: "truncated".to_string(),
            kind: CaptureKind::Response,
            decision: CaptureDecision::Allow,
            mode: CaptureMode::HttpProxy,
            url: "http://example.com/".to_string(),
            method: Some("GET".to_string()),
            client: CaptureEndpoint::default(),
            target: None,
            http_version: None,
            headers: None,
            status_code: Some(200),
            status_message: None,
            body: Some(BodyCaptureResult {
                captured: b"prefix".to_vec(),
                total_len: 12,
            }),
        });

        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(value["bodyTruncated"], true);
        assert_eq!(value["body"]["length"], 12);
        assert!(value.get("providerReplacementOmitted").is_none());
        assert!(value.get("providerReplacementSize").is_none());
        let decoded: CaptureRecord = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.body_truncated, Some(true));

        let complete = sample_record_with_body(Some(CaptureBody {
            encoding: "base64".to_string(),
            length: 6,
            data: general_purpose::STANDARD.encode(b"prefix"),
            content_type: None,
            content_encoding: None,
        }));
        let value = serde_json::to_value(complete).unwrap();
        assert!(value.get("bodyTruncated").is_none());
    }

    #[test]
    fn invalid_body_truncated_shapes_are_rejected() {
        let mut value = serde_json::to_value(sample_record_with_body(None)).unwrap();
        value["bodyTruncated"] = JsonValue::Bool(false);
        assert!(serde_json::from_value::<CaptureRecord>(value).is_err());

        let mut value = serde_json::to_value(sample_record_with_body(None)).unwrap();
        value["body"] = serde_json::json!({
            "encoding": "base64",
            "length": 8,
            "data": general_purpose::STANDARD.encode(b"short")
        });
        assert!(serde_json::from_value::<CaptureRecord>(value).is_err());

        let mut record = sample_record_with_body(Some(CaptureBody {
            encoding: "base64".to_string(),
            length: 2,
            data: "Zh==".to_string(),
            content_type: None,
            content_encoding: None,
        }));
        record.body_truncated = Some(true);
        assert!(serde_json::to_value(record).is_err());
    }

    #[test]
    fn provider_replacement_marker_pair_is_exact_and_excludes_body() {
        let mut record = sample_record_with_body(Some(CaptureBody {
            encoding: "base64".to_string(),
            length: 4,
            data: general_purpose::STANDARD.encode(b"body"),
            content_type: None,
            content_encoding: None,
        }));
        record.mark_provider_replacement_omitted(4096);

        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(value["providerReplacementOmitted"], true);
        assert_eq!(value["providerReplacementSize"], 4096);
        assert!(value.get("body").is_none());
        assert!(value.get("bodyTruncated").is_none());
        let decoded: CaptureRecord = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.provider_replacement_omitted, Some(true));
        assert_eq!(decoded.provider_replacement_size, Some(4096));
    }

    #[test]
    fn invalid_provider_replacement_shapes_are_rejected() {
        let base = serde_json::to_value(sample_record_with_body(None)).unwrap();
        for fields in [
            serde_json::json!({"providerReplacementOmitted": true}),
            serde_json::json!({"providerReplacementSize": 1}),
            serde_json::json!({
                "providerReplacementOmitted": false,
                "providerReplacementSize": 1
            }),
        ] {
            let mut value = base.clone();
            value.as_object_mut().unwrap().extend(
                fields
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
            assert!(serde_json::from_value::<CaptureRecord>(value).is_err());
        }
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
            body_truncated: None,
            provider_replacement_omitted: None,
            provider_replacement_size: None,
        };

        let path = resolve_capture_path(&sink_from_config(&cfg), &record);
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
            body_truncated: None,
            provider_replacement_omitted: None,
            provider_replacement_size: None,
        };

        let sanitized = sanitize_path_component(raw_request_id);
        assert!(!sanitized.contains('/'));
        assert!(!sanitized.contains('.'));

        let path = resolve_capture_path(&sink_from_config(&cfg), &record);
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
