use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind as IoErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::SystemTime;

use base64::{encoded_len as base64_encoded_len, engine::general_purpose, Engine as _};
use fs2::FileExt;
use http_access_types::{
    CaptureEvent, CaptureFacts, HttpVersion, IngressMode, SanitizedHeaderValue,
};
use once_cell::sync::Lazy;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value as JsonValue;

use crate::filesystem::create_private_dir_all;
use crate::http_body::{
    decode_capture_http_body, decode_capture_websocket_permessage_deflate, CaptureContentEncoding,
    CaptureHttpDecodeError,
};
use crate::observation::{
    CaptureAllocationError, CaptureBody as OwnedCaptureBody, CaptureEpoch, CaptureExactBytes,
    CaptureOperation,
};

#[cfg(test)]
mod integration_tests;
use http_access_redaction::{PayloadClass, RedactionError};

mod tap;
mod worker;

pub(crate) use tap::HttpCaptureTap;
pub(crate) use worker::CaptureWorkerStartError;
use worker::{BoundedCaptureWorker, CaptureSubmitError as WorkerSubmitError};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

static CAPTURE_DIRECTORY_LOCKS: Lazy<Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static CAPTURE_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) const REDACTED: &str = "[REDACTED]";

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
}

impl CaptureMode {
    pub(crate) const fn for_ingress(mode: IngressMode) -> Self {
        match mode {
            IngressMode::ExplicitHttp
            | IngressMode::ExplicitHttps
            | IngressMode::TransparentHttp
            | IngressMode::ConnectMitmInner
            | IngressMode::TransparentHttps => Self::HttpProxy,
        }
    }
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
pub(crate) struct CaptureSinkSpec {
    directory: PathBuf,
    filename_template: String,
    max_files: usize,
    max_total_bytes: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum CaptureSinkSpecError {
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
    pub(crate) fn new(
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

    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn filename_template(&self) -> &str {
        &self.filename_template
    }

    pub(crate) fn max_files(&self) -> usize {
        self.max_files
    }

    pub(crate) fn max_total_bytes(&self) -> u64 {
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

#[derive(Clone)]
pub(crate) struct SanitizedCaptureMetadata {
    record: CaptureRecord,
}

impl SanitizedCaptureMetadata {
    pub(crate) fn from_facts(
        facts: CaptureFacts,
        timestamp: String,
        client_port: Option<u16>,
        include_headers: bool,
        status_message: Option<String>,
    ) -> Self {
        let (kind, decision) = match facts.event() {
            CaptureEvent::RequestAllowed => (CaptureKind::Request, CaptureDecision::Allow),
            CaptureEvent::ResponseAllowed => (CaptureKind::Response, CaptureDecision::Allow),
            CaptureEvent::RequestDenied => (CaptureKind::Request, CaptureDecision::Deny),
            CaptureEvent::ResponseDenied => (CaptureKind::Response, CaptureDecision::Deny),
        };
        let headers = include_headers.then(|| capture_headers(facts.headers()));
        Self {
            record: CaptureRecord {
                timestamp,
                request_id: facts.request_id().as_str().to_owned(),
                kind,
                decision,
                mode: CaptureMode::for_ingress(facts.ingress_mode()),
                url: facts
                    .url()
                    .map_or_else(String::new, |url| url.as_str().to_owned()),
                method: facts
                    .method()
                    .map_or_else(String::new, |method| method.as_str().to_owned()),
                status_code: facts.status(),
                status_message,
                client: CaptureEndpoint {
                    address: facts.client_ip().map(|ip| ip.to_string()),
                    port: client_port,
                },
                target: facts.target().map(|target| CaptureEndpoint {
                    address: Some(target.host().authority_form()),
                    port: Some(target.effective_port()),
                }),
                http_version: facts.version().map(capture_http_version).map(str::to_owned),
                headers,
                body: None,
                body_truncated: None,
                provider_replacement_omitted: None,
                provider_replacement_size: None,
            },
        }
    }

    pub(crate) fn mark_provider_replacement_omitted(&mut self, size: usize) {
        self.record.mark_provider_replacement_omitted(size);
    }

    pub(crate) fn without_headers(mut self) -> Self {
        self.record.headers = None;
        self
    }

    pub(crate) fn for_websocket_message(
        &self,
        timestamp: String,
        label: &str,
        sequence: u64,
        kind: CaptureKind,
    ) -> Self {
        let mut metadata = self.clone();
        metadata.record.timestamp = timestamp;
        metadata.record.request_id = format!("{}-ws-{label}-{sequence}", self.record.request_id);
        metadata.record.kind = kind;
        metadata.record.status_code = None;
        metadata.record.status_message = None;
        metadata
    }

    #[cfg(test)]
    pub(crate) fn from_test_record(record: CaptureRecord) -> Self {
        Self { record }
    }
}

fn capture_headers(fields: &[http_access_types::SanitizedHeaderField]) -> HeaderMap {
    let mut captured = HeaderMap::new();
    for field in fields {
        let name = field.name().as_str().to_owned();
        let value = match field.value() {
            SanitizedHeaderValue::Redacted => JsonValue::String(REDACTED.to_owned()),
            SanitizedHeaderValue::Visible(value) => {
                let Ok(value) = std::str::from_utf8(value.as_bytes()) else {
                    continue;
                };
                JsonValue::String(value.to_owned())
            }
        };
        match captured.entry(name) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(value);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => match entry.get_mut() {
                JsonValue::String(existing) => {
                    *entry.get_mut() =
                        JsonValue::Array(vec![JsonValue::String(existing.clone()), value]);
                }
                JsonValue::Array(values) => values.push(value),
                _ => unreachable!("capture headers contain only strings and string arrays"),
            },
        }
    }
    captured
}

const fn capture_http_version(version: HttpVersion) -> &'static str {
    match version {
        HttpVersion::Http10 => "1.0",
        HttpVersion::Http11 => "1.1",
        HttpVersion::Http2 => "2",
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
    Redaction(#[from] RedactionError),
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
    #[cfg(test)]
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
            metadata: SanitizedCaptureMetadata::from_test_record(metadata),
            payload: CaptureArtifactPayload::Unavailable,
            max_expansion_ratio,
        }))
    }

    pub(crate) fn begin_admitted(
        epoch: Arc<CaptureEpoch>,
        operation: CaptureOperation,
        metadata: SanitizedCaptureMetadata,
        max_expansion_ratio: usize,
    ) -> Result<Self, CaptureArtifactJobError> {
        if metadata.record.body.is_some() || metadata.record.body_truncated.is_some() {
            return Err(CaptureArtifactJobError::MetadataAlreadyHasBodyOutcome);
        }
        Ok(Self {
            operation,
            epoch,
            metadata,
            payload: CaptureArtifactPayload::Unavailable,
            max_expansion_ratio,
        })
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
                    .redact_http_body(&self.operation, decoded)?
                    .into_body();
                if redacted.is_empty() {
                    return Ok(None);
                }
                let body = CaptureArtifactBody::encode(
                    &self.operation,
                    redacted,
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
                    if !limits.allow_permessage_deflate() {
                        return Err(CaptureArtifactProcessError::UnsupportedWebSocketCompression);
                    }
                    decode_capture_websocket_permessage_deflate(
                        encoded,
                        &self.operation,
                        limits.max_message_bytes(),
                    )?
                } else {
                    encoded
                };
                let redacted =
                    policy
                        .profile()
                        .redact_websocket_message(&self.operation, decoded, class)?;
                let redacted = redacted.into_body();
                if redacted.is_empty() {
                    return Ok(None);
                }
                let body = CaptureArtifactBody::encode(
                    &self.operation,
                    redacted,
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

    #[cfg(test)]
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
enum CaptureRecordInvariantError {
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

    pub(crate) fn mark_provider_replacement_omitted(&mut self, size: usize) {
        self.body = None;
        self.body_truncated = None;
        self.provider_replacement_omitted = Some(true);
        self.provider_replacement_size = Some(size);
    }
}

fn canonical_base64_decoded_len(encoded: &str) -> Option<usize> {
    let bytes = encoded.as_bytes();
    if bytes.len() & 3 != 0 {
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

#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureError {
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
pub(crate) fn resolve_capture_path(sink: &CaptureSinkSpec, record: &CaptureRecord) -> PathBuf {
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

pub(crate) fn write_capture_record(
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
    use std::io::Write as _;

    use super::*;
    use crate::config::compiler::{
        CapturePlan, CaptureWorkingSetPlan, CompiledCaptureEvent, ObservationPlan,
    };
    use crate::observation::{CapturePool, ProductObservationSnapshot};
    use crate::redaction::{test_snapshot, TestProfile};
    use crate::runtime::GenerationOwner;
    use flate2::write::GzEncoder;
    use flate2::{Compress, Compression, FlushCompress, Status};

    #[test]
    fn every_http_ingress_mode_preserves_the_http_proxy_capture_wire_value() {
        for ingress_mode in [
            IngressMode::ExplicitHttp,
            IngressMode::ExplicitHttps,
            IngressMode::TransparentHttp,
            IngressMode::ConnectMitmInner,
            IngressMode::TransparentHttps,
        ] {
            let capture_mode = CaptureMode::for_ingress(ingress_mode);
            assert_eq!(capture_mode, CaptureMode::HttpProxy);
            assert_eq!(
                serde_json::to_string(&capture_mode).unwrap(),
                r#""http_proxy""#
            );
        }
    }

    fn capture_sink(directory: PathBuf) -> CaptureSinkSpec {
        CaptureSinkSpec::new(
            directory,
            "{requestId}-{suffix}.json".to_string(),
            16,
            1024 * 1024,
        )
        .unwrap()
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
        let (redaction, references) = test_snapshot(vec![TestProfile {
            name: "capture".to_owned(),
            replacement: b"REDACTED".to_vec(),
            max_body_bytes: 1024,
            max_decoded_body_bytes: 1024,
            max_frame_bytes: 1024,
            max_message_bytes: 1024,
            allow_permessage_deflate,
            literals: vec![b"secret".to_vec()],
        }]);
        let pool = CapturePool::new();
        let activation = ProductObservationSnapshot::activate(
            ObservationPlan {
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
                ..ObservationPlan::default()
            },
            &redaction,
            references.get("capture"),
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

    fn gzip_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn permessage_deflate_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = Compress::new(Compression::default(), false);
        let mut encoded = Vec::with_capacity(bytes.len() + 64);
        assert_eq!(
            encoder
                .compress_vec(bytes, &mut encoded, FlushCompress::Sync)
                .unwrap(),
            Status::Ok
        );
        assert!(encoded.ends_with(&[0x00, 0x00, 0xff, 0xff]));
        encoded.truncate(encoded.len() - 4);
        encoded
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
        let encoded = operation_body(&job, &gzip_bytes(b""));
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
        let (epoch, _owner) = capture_engine_epoch(directory.path(), 1024, true);
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
        let encoded_bytes = permessage_deflate_bytes(b"");
        assert!(!encoded_bytes.is_empty());
        let encoded = operation_body(&job, &encoded_bytes);
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
    async fn artifact_worker_accepts_only_pre_sanitized_typed_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let (epoch, _owner) = capture_engine_epoch(directory.path(), 1024, false);
        let event = CaptureEvent::RequestAllowed;
        let operation = epoch
            .capture()
            .and_then(|policy| policy.try_admit(event))
            .expect("capture admission");
        let policy = http_access_types::SensitiveHeaderPolicy::new([], [], []).unwrap();
        let headers = [
            http_access_types::SanitizedHeaderField::redacted(
                http_access_types::HeaderName::new("authorization").unwrap(),
            ),
            http_access_types::SanitizedHeaderField::redacted(
                http_access_types::HeaderName::new("cookie").unwrap(),
            ),
            http_access_types::SanitizedHeaderField::visible(
                &policy,
                http_access_types::HeaderName::new("content-type").unwrap(),
                http_access_types::HeaderValue::new(b"text/plain".to_vec()).unwrap(),
            )
            .unwrap(),
        ];
        let request_id = http_access_types::StableId::new("credential-metadata").unwrap();
        let method = http_access_types::HttpMethod::new("GET").unwrap();
        let url =
            http_access_url::canonicalize_http_url("https://example.com/path?token=query-secret")
                .unwrap();
        let facts = CaptureFacts::new(
            &policy,
            http_access_types::CaptureFactsInput {
                request_id: &request_id,
                event,
                ingress_mode: IngressMode::ExplicitHttp,
                method: Some(&method),
                url: Some(&url),
                client_ip: None,
                target: Some(url.authority()),
                version: Some(HttpVersion::Http11),
                status: None,
                headers: &headers,
            },
        )
        .unwrap();
        let metadata = SanitizedCaptureMetadata::from_facts(
            facts,
            "2026-01-01T00:00:00Z".to_owned(),
            None,
            true,
            None,
        );
        let job = CaptureArtifactJob::begin_admitted(epoch, operation, metadata, 16).unwrap();

        let worker = CaptureArtifactWorker::start(1).unwrap();
        worker.try_submit(job).unwrap();
        worker.shutdown().await;

        let record = read_only_capture_record(directory.path());
        assert_eq!(record.url, "https://example.com/path?REDACTED");
        let headers = record.headers.as_ref().unwrap();
        assert_eq!(
            headers.get("authorization"),
            Some(&JsonValue::String(REDACTED.to_owned()))
        );
        assert_eq!(
            headers.get("cookie"),
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
        let secret = b"query-secret".as_slice();
        assert!(!artifact
            .windows(secret.len())
            .any(|window| window == secret));
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
        let mut record = sample_record_with_body(Some(CaptureBody {
            encoding: "base64".to_string(),
            length: 12,
            data: general_purpose::STANDARD.encode(b"prefix"),
            content_type: None,
            content_encoding: None,
        }));
        record.request_id = "truncated".to_string();
        record.kind = CaptureKind::Response;
        record.url = "http://example.com/".to_string();
        record.method = "GET".to_string();
        record.http_version = None;
        record.body_truncated = Some(true);

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

        let path = resolve_capture_path(&capture_sink(PathBuf::from("logs-capture")), &record);
        assert_eq!(path, Path::new("logs-capture").join("req-123-req.json"));
    }

    #[test]
    fn capture_record_json_shape_matches_expectations() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type".to_string(),
            JsonValue::String("text/plain".to_string()),
        );

        let body_bytes = b"hello";
        let record = CaptureRecord {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            request_id: "golden-request".to_string(),
            kind: CaptureKind::Request,
            decision: CaptureDecision::Allow,
            mode: CaptureMode::HttpProxy,
            url: "https://example.com/resource".to_string(),
            method: "POST".to_string(),
            status_code: Some(200),
            status_message: Some("OK".to_string()),
            client: CaptureEndpoint {
                address: Some("127.0.0.1".to_string()),
                port: Some(43210),
            },
            target: Some(CaptureEndpoint {
                address: Some("203.0.113.10".to_string()),
                port: Some(443),
            }),
            http_version: Some("1.1".to_string()),
            headers: Some(headers),
            body: Some(CaptureBody {
                encoding: "base64".to_string(),
                length: body_bytes.len(),
                data: general_purpose::STANDARD.encode(body_bytes),
                content_type: Some("text/plain".to_string()),
                content_encoding: None,
            }),
            body_truncated: None,
            provider_replacement_omitted: None,
            provider_replacement_size: None,
        };

        let actual = serde_json::to_value(&record).expect("serialize capture record");
        let expected: JsonValue = serde_json::from_str(include_str!(
            "../../tests/fixtures/golden/capture-record.json"
        ))
        .expect("parse capture record golden");

        assert_eq!(actual, expected);
    }

    #[test]
    fn resolve_capture_path_sanitizes_request_id() {
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

        let path = resolve_capture_path(&capture_sink(PathBuf::from("logs-capture")), &record);
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
