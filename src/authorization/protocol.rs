use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
#[cfg(test)]
use std::io::Write;
use std::io::{self, Read};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use allocator_api2::boxed::Box as FallibleBox;
use std::task::{Context, Poll};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::read::DecoderReader;
use base64::Engine as _;
use http::{HeaderName, HeaderValue};
#[cfg(test)]
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
#[cfg(test)]
use serde::{Deserialize, Deserializer};
use serde::{Serialize, Serializer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::ChildStdout;
#[cfg(test)]
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::config::compiler::{ProviderOutputPlan, MAX_PROVIDER_CREDENTIAL_BYTES};
use crate::safety::wire_body::{GuardedAllocationCharge, GuardedScratch};
use crate::safety::{GuardedBody, HttpWireBodyGuard};

#[cfg(test)]
const PROVIDER_STREAM_SCRATCH_BYTES: usize = 64 * 1024;
static NEXT_OUTPUT_REGISTRY_ID: AtomicU64 = AtomicU64::new(1);

const MIN_WEBHOOK_REQUEST_WITHOUT_CALLBACK_URL_WIRE: &[u8] =
    b"{\"type\":\"request\",\"requestId\":\"a\",\"ruleId\":\"a\",\"url\":\"http://a/\",\"method\":\"A\",\"clientIp\":\"::\",\"callbackUrl\":\"\",\"resumeToken\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";
const CALLBACK_RESPONSE_PREFIX_WIRE: &[u8] =
    b"{\"resumeToken\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",";
const MIN_CALLBACK_RESPONSE_WIRE: &[u8] = b"{\"resumeToken\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"type\":\"response\",\"decision\":\"deny\"}";

pub(crate) const MIN_WEBHOOK_REQUEST_WITHOUT_CALLBACK_URL_BYTES: usize =
    MIN_WEBHOOK_REQUEST_WITHOUT_CALLBACK_URL_WIRE.len();
pub(crate) const CALLBACK_RESPONSE_PREFIX_BYTES: usize = CALLBACK_RESPONSE_PREFIX_WIRE.len();
pub(crate) const MIN_CALLBACK_RESPONSE_BYTES: usize = MIN_CALLBACK_RESPONSE_WIRE.len();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProviderOutputIndex {
    registry_id: u64,
    ordinal: usize,
}

impl ProviderOutputIndex {
    pub(crate) fn get(self) -> usize {
        self.ordinal
    }

    pub(crate) fn registry_id(self) -> u64 {
        self.registry_id
    }
}

pub(crate) enum ProviderOutputDefinition {
    Bearer { required: bool },
    Basic { username: String, required: bool },
    CustomHeader { header: HeaderName, required: bool },
}

impl ProviderOutputDefinition {
    pub(crate) fn required(&self) -> bool {
        match self {
            Self::Bearer { required }
            | Self::Basic { required, .. }
            | Self::CustomHeader { required, .. } => *required,
        }
    }
}

pub(crate) struct ProviderOutputRegistry {
    id: u64,
    by_wire_name: BTreeMap<String, ProviderOutputIndex>,
    definitions: Box<[ProviderOutputDefinition]>,
}

impl ProviderOutputRegistry {
    pub(crate) fn activate(outputs: BTreeMap<String, ProviderOutputPlan>) -> Self {
        let id = NEXT_OUTPUT_REGISTRY_ID.fetch_add(1, Ordering::Relaxed);
        assert!(id != 0, "provider output registry ID overflow");
        let mut by_wire_name = BTreeMap::new();
        let mut definitions = Vec::with_capacity(outputs.len());
        for (index, (name, output)) in outputs.into_iter().enumerate() {
            by_wire_name.insert(
                name,
                ProviderOutputIndex {
                    registry_id: id,
                    ordinal: index,
                },
            );
            definitions.push(match output {
                ProviderOutputPlan::Bearer { required } => {
                    ProviderOutputDefinition::Bearer { required }
                }
                ProviderOutputPlan::Basic { username, required } => {
                    ProviderOutputDefinition::Basic { username, required }
                }
                ProviderOutputPlan::CustomHeader { header, required } => {
                    ProviderOutputDefinition::CustomHeader { header, required }
                }
            });
        }
        Self {
            id,
            by_wire_name,
            definitions: definitions.into_boxed_slice(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.definitions.len()
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn wire_names(&self) -> impl Iterator<Item = &str> {
        self.by_wire_name.keys().map(String::as_str)
    }

    pub(crate) fn index(&self, wire_name: &str) -> Option<ProviderOutputIndex> {
        self.by_wire_name.get(wire_name).copied()
    }

    #[cfg(test)]
    pub(crate) fn definition(
        &self,
        index: ProviderOutputIndex,
    ) -> Option<&ProviderOutputDefinition> {
        (index.registry_id == self.id)
            .then(|| self.definitions.get(index.get()))
            .flatten()
    }

    pub(crate) fn definitions(&self) -> &[ProviderOutputDefinition] {
        &self.definitions
    }

    pub(crate) fn compact_provider_credential_wire(
        &self,
        credentials: &ProviderCredentialSet,
        guard: &HttpWireBodyGuard,
    ) -> Result<ProviderCredentialWireStore, ProviderCredentialWireError> {
        if credentials.registry_id() != self.id {
            return Err(ProviderCredentialWireError::ForeignRegistry);
        }

        let range_bytes = projected_provider_credential_wire_metadata_bytes(self.definitions.len())
            .ok_or(ProviderCredentialWireError::AllocationFailed)?;
        let range_charge = guard
            .charge_exact_allocation(range_bytes)
            .map_err(|_| ProviderCredentialWireError::AllocationFailed)?;
        let mut ranges = FallibleBox::<[Option<ProcessEffectRange>]>::try_new_uninit_slice(
            self.definitions.len(),
        )
        .map_err(|_| ProviderCredentialWireError::AllocationFailed)?;
        let mut storage = guard.buffer();
        for ordinal in 0..self.definitions.len() {
            let index = ProviderOutputIndex {
                registry_id: self.id,
                ordinal,
            };
            let Some(segments) = credentials.value_segments(index) else {
                ranges[ordinal].write(None);
                continue;
            };
            let start = storage.len();
            let mut length = 0usize;
            for segment in segments {
                length = length
                    .checked_add(segment.len())
                    .filter(|length| *length <= MAX_PROVIDER_CREDENTIAL_BYTES)
                    .ok_or(ProviderCredentialWireError::InvalidCredential)?;
                storage
                    .try_extend_from_slice(segment)
                    .map_err(|_| ProviderCredentialWireError::AllocationFailed)?;
            }
            if length == 0 {
                return Err(ProviderCredentialWireError::InvalidCredential);
            }
            ranges[ordinal].write(Some(ProcessEffectRange {
                start,
                end: storage.len(),
            }));
        }

        // Every slot is initialized exactly once by the complete ordinal loop.
        let ranges = unsafe { ranges.assume_init() };
        Ok(ProviderCredentialWireStore {
            registry_id: self.id,
            ranges,
            storage: storage.finish(),
            _range_charge: range_charge,
        })
    }
}

pub(crate) fn projected_provider_credential_wire_metadata_bytes(
    output_count: usize,
) -> Option<usize> {
    output_count.checked_mul(std::mem::size_of::<Option<ProcessEffectRange>>())
}

/// Bounded raw provider-response ranges retained by the product wire adapter.
///
/// These bytes are not resolved credential-core material: they remain on the
/// request wire guard until the exact late resolver copies one selected range
/// into a session-branded credential-core writer immediately before send.
pub(crate) struct ProviderCredentialWireStore {
    registry_id: u64,
    ranges: FallibleBox<[Option<ProcessEffectRange>]>,
    storage: GuardedBody,
    _range_charge: GuardedAllocationCharge,
}

impl ProviderCredentialWireStore {
    pub(crate) fn output_len(&self, output: ProviderOutputIndex) -> Option<usize> {
        let range = self.output_range(output).ok()?;
        range.end.checked_sub(range.start)
    }

    pub(crate) fn copy_output(
        &self,
        output: ProviderOutputIndex,
        destination: &mut [u8],
    ) -> Result<(), ProviderCredentialWireError> {
        let range = self.output_range(output)?;
        let expected_len = range
            .end
            .checked_sub(range.start)
            .ok_or(ProviderCredentialWireError::InvalidCredential)?;
        if destination.len() != expected_len {
            return Err(ProviderCredentialWireError::BufferLengthMismatch);
        }
        let mut copied = 0usize;
        for segment in ProcessEffectSegments::new(&self.storage, range) {
            let end = copied
                .checked_add(segment.len())
                .ok_or(ProviderCredentialWireError::InvalidCredential)?;
            destination[copied..end].copy_from_slice(segment);
            copied = end;
        }
        (copied == destination.len())
            .then_some(())
            .ok_or(ProviderCredentialWireError::InvalidCredential)
    }

    #[cfg(test)]
    pub(crate) fn present_count(&self) -> usize {
        self.ranges.iter().filter(|range| range.is_some()).count()
    }

    fn output_range(
        &self,
        output: ProviderOutputIndex,
    ) -> Result<ProcessEffectRange, ProviderCredentialWireError> {
        if output.registry_id() != self.registry_id {
            return Err(ProviderCredentialWireError::ForeignRegistry);
        }
        self.ranges
            .get(output.get())
            .copied()
            .flatten()
            .ok_or(ProviderCredentialWireError::OutputUnavailable)
    }
}

impl fmt::Debug for ProviderCredentialWireStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCredentialWireStore")
            .field("output_count", &self.ranges.len())
            .field(
                "present_count",
                &self.ranges.iter().filter(|range| range.is_some()).count(),
            )
            .field("charged_bytes", &self.storage.charged_bytes())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum ProviderCredentialWireError {
    #[error("authorization provider is not active")]
    UnknownProvider,
    #[error("authorization credentials belong to another provider registry")]
    ForeignRegistry,
    #[error("authorization credential output is unavailable")]
    OutputUnavailable,
    #[error("authorization provider returned invalid credential material")]
    InvalidCredential,
    #[error("authorization credential material destination length is invalid")]
    BufferLengthMismatch,
    #[error("authorization credential material allocation failed")]
    AllocationFailed,
}

impl fmt::Debug for ProviderOutputRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderOutputRegistry")
            .field("count", &self.definitions.len())
            .finish()
    }
}

#[cfg(test)]
pub(crate) struct ContiguousProviderCredentials {
    registry_id: u64,
    values: Box<[Option<SecretBytes>]>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ProcessEffectRange {
    pub(super) start: usize,
    pub(super) end: usize,
}

pub(crate) struct ProcessProviderCredentials {
    registry_id: u64,
    values: Box<[Option<ProcessEffectRange>]>,
    storage: Arc<GuardedBody>,
}

impl ProcessProviderCredentials {
    pub(super) fn new(
        registry_id: u64,
        values: Box<[Option<ProcessEffectRange>]>,
        storage: Arc<GuardedBody>,
    ) -> Self {
        Self {
            registry_id,
            values,
            storage,
        }
    }

    fn get(&self, index: ProviderOutputIndex) -> Option<ProcessEffectSegments<'_>> {
        let range = self
            .values
            .get(index.get())
            .filter(|_| self.registry_id == index.registry_id())
            .and_then(|range| *range)?;
        Some(ProcessEffectSegments::new(&self.storage, range))
    }
}

pub(crate) enum ProviderCredentialSet {
    #[cfg(test)]
    Contiguous(ContiguousProviderCredentials),
    Segmented(crate::authorization::callback::CallbackCredentialSet),
    ProcessSegmented(ProcessProviderCredentials),
}

impl ProviderCredentialSet {
    pub(crate) fn registry_id(&self) -> u64 {
        match self {
            #[cfg(test)]
            Self::Contiguous(credentials) => credentials.registry_id,
            Self::Segmented(credentials) => credentials.registry_id(),
            Self::ProcessSegmented(credentials) => credentials.registry_id,
        }
    }

    pub(crate) fn contains_output(&self, index: ProviderOutputIndex) -> bool {
        self.value_segments(index).is_some()
    }

    #[cfg(test)]
    pub(crate) fn contiguous(&self, index: ProviderOutputIndex) -> Option<&[u8]> {
        let Self::Contiguous(credentials) = self else {
            return None;
        };
        if index.registry_id != credentials.registry_id {
            return None;
        }
        credentials
            .values
            .get(index.get())
            .and_then(Option::as_ref)
            .map(SecretBytes::as_bytes)
    }

    #[cfg(test)]
    pub(crate) fn segmented(
        &self,
        index: ProviderOutputIndex,
    ) -> Option<crate::authorization::callback::CallbackCredentialSegments<'_>> {
        match self {
            #[cfg(test)]
            Self::Contiguous(_) => None,
            Self::ProcessSegmented(_) => None,
            Self::Segmented(credentials) => credentials.get(index),
        }
    }

    pub(crate) fn from_segmented(
        credentials: crate::authorization::callback::CallbackCredentialSet,
    ) -> Self {
        Self::Segmented(credentials)
    }

    pub(super) fn from_process_segmented(credentials: ProcessProviderCredentials) -> Self {
        Self::ProcessSegmented(credentials)
    }

    #[cfg(test)]
    pub(crate) fn single_value_for_test(
        index: ProviderOutputIndex,
        output_count: usize,
        value: &[u8],
    ) -> Self {
        assert!(index.get() < output_count);
        let mut values = std::iter::repeat_with(|| None)
            .take(output_count)
            .collect::<Vec<_>>();
        values[index.get()] = Some(SecretBytes(value.to_vec()));
        Self::Contiguous(ContiguousProviderCredentials {
            registry_id: index.registry_id(),
            values: values.into_boxed_slice(),
        })
    }

    fn value_segments(&self, index: ProviderOutputIndex) -> Option<ProviderCredentialSegments<'_>> {
        match self {
            #[cfg(test)]
            Self::Contiguous(_) => self
                .contiguous(index)
                .map(|value| ProviderCredentialSegments::Contiguous(Some(value))),
            Self::Segmented(credentials) => credentials
                .get(index)
                .map(ProviderCredentialSegments::Callback),
            Self::ProcessSegmented(credentials) => credentials
                .get(index)
                .map(ProviderCredentialSegments::Process),
        }
    }
}

enum ProviderCredentialSegments<'a> {
    #[cfg(test)]
    Contiguous(Option<&'a [u8]>),
    Callback(crate::authorization::callback::CallbackCredentialSegments<'a>),
    Process(ProcessEffectSegments<'a>),
}

impl<'a> Iterator for ProviderCredentialSegments<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            #[cfg(test)]
            Self::Contiguous(value) => value.take(),
            Self::Callback(segments) => segments.next(),
            Self::Process(segments) => segments.next(),
        }
    }
}

impl fmt::Debug for ProviderCredentialSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(test)]
            Self::Contiguous(credentials) => formatter
                .debug_struct("ProviderCredentialSet")
                .field("representation", &"contiguous")
                .field("count", &credentials.values.len())
                .field(
                    "present_count",
                    &credentials
                        .values
                        .iter()
                        .filter(|value| value.is_some())
                        .count(),
                )
                .finish(),
            Self::Segmented(credentials) => formatter
                .debug_struct("ProviderCredentialSet")
                .field("representation", &"segmented")
                .field("credentials", credentials)
                .finish(),
            Self::ProcessSegmented(credentials) => formatter
                .debug_struct("ProviderCredentialSet")
                .field("representation", &"process-segmented")
                .field("count", &credentials.values.len())
                .field(
                    "present_count",
                    &credentials
                        .values
                        .iter()
                        .filter(|value| value.is_some())
                        .count(),
                )
                .field("charged_bytes", &credentials.storage.charged_bytes())
                .finish(),
        }
    }
}

pub(super) struct ProcessEffectSegments<'a> {
    segments: crate::safety::wire_body::GuardedBodySegments<'a>,
    skip: usize,
    remaining: usize,
}

impl<'a> ProcessEffectSegments<'a> {
    pub(super) fn new(storage: &'a GuardedBody, range: ProcessEffectRange) -> Self {
        Self {
            segments: storage.segments(),
            skip: range.start,
            remaining: range.end - range.start,
        }
    }
}

impl<'a> Iterator for ProcessEffectSegments<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining != 0 {
            let segment = self.segments.next()?;
            if self.skip >= segment.len() {
                self.skip -= segment.len();
                continue;
            }
            let available = &segment[self.skip..];
            self.skip = 0;
            let length = available.len().min(self.remaining);
            self.remaining -= length;
            return Some(&available[..length]);
        }
        None
    }
}

pub(crate) struct ProviderBodyReplacement {
    content_type: Option<String>,
    content_encoding: Option<String>,
    storage: ProviderBodyReplacementStorage,
}

enum ProviderBodyReplacementStorage {
    #[cfg(test)]
    Decoded(GuardedBody),
    Encoded {
        body: Arc<GuardedBody>,
        range: ProcessEffectRange,
        decoded_bytes: usize,
    },
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum ProviderBodyReplacementDecodeError {
    #[error("authorization provider replacement exceeds the provider body limit")]
    ProviderBodyLimit,
    #[error("authorization provider replacement exceeds the redaction body limit")]
    RedactionBodyLimit,
    #[error("authorization provider replacement decode failed")]
    InvalidBody,
}

impl ProviderBodyReplacement {
    pub(crate) fn decoded_size(&self) -> usize {
        match &self.storage {
            #[cfg(test)]
            ProviderBodyReplacementStorage::Decoded(bytes) => bytes.len(),
            ProviderBodyReplacementStorage::Encoded { decoded_bytes, .. } => *decoded_bytes,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_decoded_for_test(decoded: GuardedBody) -> Self {
        Self {
            content_type: None,
            content_encoding: None,
            storage: ProviderBodyReplacementStorage::Decoded(decoded),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_decoded_with_metadata_for_test(
        decoded: GuardedBody,
        content_type: Option<String>,
        content_encoding: Option<String>,
    ) -> Self {
        Self {
            content_type,
            content_encoding,
            storage: ProviderBodyReplacementStorage::Decoded(decoded),
        }
    }

    #[cfg(test)]
    pub(crate) fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn content_encoding(&self) -> Option<&str> {
        self.content_encoding.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn decoded_segments(&self) -> Option<impl Iterator<Item = &[u8]>> {
        match &self.storage {
            #[cfg(test)]
            ProviderBodyReplacementStorage::Decoded(bytes) => Some(bytes.segments()),
            ProviderBodyReplacementStorage::Encoded { .. } => None,
        }
    }

    pub(super) fn from_encoded(
        content_type: Option<String>,
        content_encoding: Option<String>,
        body: Arc<GuardedBody>,
        range: ProcessEffectRange,
        decoded_bytes: usize,
    ) -> Self {
        Self {
            content_type,
            content_encoding,
            storage: ProviderBodyReplacementStorage::Encoded {
                body,
                range,
                decoded_bytes,
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn decode(
        self,
        guard: &HttpWireBodyGuard,
    ) -> Result<(Option<String>, Option<String>, GuardedBody), ProviderBodyReplacementDecodeError>
    {
        self.decode_with_limits(guard, usize::MAX, usize::MAX)
    }

    pub(crate) fn decode_with_limits(
        self,
        guard: &HttpWireBodyGuard,
        provider_max_decoded_bytes: usize,
        redaction_max_decoded_bytes: usize,
    ) -> Result<(Option<String>, Option<String>, GuardedBody), ProviderBodyReplacementDecodeError>
    {
        let decoded_bytes = self.decoded_size();
        if decoded_bytes > provider_max_decoded_bytes {
            return Err(ProviderBodyReplacementDecodeError::ProviderBodyLimit);
        }
        if decoded_bytes > redaction_max_decoded_bytes {
            return Err(ProviderBodyReplacementDecodeError::RedactionBodyLimit);
        }
        let max_decoded_bytes = provider_max_decoded_bytes.min(redaction_max_decoded_bytes);
        let decoded = match self.storage {
            #[cfg(test)]
            ProviderBodyReplacementStorage::Decoded(bytes) => guard
                .transfer_body(bytes)
                .map_err(|_| ProviderBodyReplacementDecodeError::InvalidBody)?,
            ProviderBodyReplacementStorage::Encoded {
                body,
                range,
                decoded_bytes: _,
            } => decode_guarded_base64_range(guard, &body, range, max_decoded_bytes)
                .map_err(|_| ProviderBodyReplacementDecodeError::InvalidBody)?,
        };
        Ok((self.content_type, self.content_encoding, decoded))
    }
}

impl fmt::Debug for ProviderBodyReplacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderBodyReplacement")
            .field(
                "encoded",
                &matches!(self.storage, ProviderBodyReplacementStorage::Encoded { .. }),
            )
            .finish_non_exhaustive()
    }
}

fn decode_guarded_base64_range(
    guard: &HttpWireBodyGuard,
    storage: &GuardedBody,
    range: ProcessEffectRange,
    max_decoded_bytes: usize,
) -> Result<GuardedBody, AssignedResponseError> {
    let mut decoded = guard.buffer();
    let encoded = ProcessEffectReader::new(storage, range);
    let mut decoder = DecoderReader::new(encoded, &BASE64_STANDARD);
    let mut scratch = guard
        .stream_scratch()
        .map_err(|_| AssignedResponseError::InvalidBody)?;
    loop {
        let read = decoder
            .read(scratch.writable())
            .map_err(|_| AssignedResponseError::InvalidBody)?;
        if read == 0 {
            break;
        }
        scratch.set_initialized(read);
        if decoded
            .len()
            .checked_add(read)
            .is_none_or(|len| len > max_decoded_bytes)
        {
            return Err(AssignedResponseError::InvalidBody);
        }
        decoded
            .try_extend_from_slice(scratch.as_slice())
            .map_err(|_| AssignedResponseError::InvalidBody)?;
        scratch.reset();
    }
    Ok(decoded.finish())
}

struct ProcessEffectReader<'a> {
    segments: ProcessEffectSegments<'a>,
    current: &'a [u8],
    offset: usize,
}

impl<'a> ProcessEffectReader<'a> {
    fn new(storage: &'a GuardedBody, range: ProcessEffectRange) -> Self {
        Self {
            segments: ProcessEffectSegments::new(storage, range),
            current: &[],
            offset: 0,
        }
    }
}

impl Read for ProcessEffectReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        while self.offset == self.current.len() {
            let Some(segment) = self.segments.next() else {
                return Ok(0);
            };
            self.current = segment;
            self.offset = 0;
        }
        let copied = output.len().min(self.current.len() - self.offset);
        output[..copied].copy_from_slice(&self.current[self.offset..self.offset + copied]);
        self.offset += copied;
        Ok(copied)
    }
}

pub(crate) enum ProviderDecision {
    Allow {
        credentials: ProviderCredentialSet,
        replacement: Option<ProviderBodyReplacement>,
    },
    AllowWithoutEffects,
    Deny,
    Pass,
}

#[cfg(test)]
pub(crate) enum ResponseClassification {
    Assigned {
        id: String,
        result: Result<ProviderDecision, AssignedResponseError>,
    },
    Unassignable(UnassignableResponseError),
}

#[cfg(test)]
pub(crate) enum BodyReplacementAdmission<'a> {
    Denied,
    Allowed {
        guard: &'a dyn BodyReplacementGuard,
        max_decoded_bytes: usize,
    },
}

#[cfg(test)]
pub(crate) trait BodyReplacementGuard {
    fn replacement_buffer(&self) -> crate::safety::wire_body::GuardedBodyBuilder;
}

#[cfg(test)]
impl BodyReplacementGuard for HttpWireBodyGuard {
    fn replacement_buffer(&self) -> crate::safety::wire_body::GuardedBodyBuilder {
        self.buffer()
    }
}

#[cfg(test)]
impl BodyReplacementGuard for crate::safety::ProviderResponseCharge {
    fn replacement_buffer(&self) -> crate::safety::wire_body::GuardedBodyBuilder {
        self.buffer()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AssignedResponseError {
    InvalidShape,
    DuplicateField,
    UnknownOutput,
    DuplicateOutput,
    MissingRequiredOutput,
    InvalidCredential,
    BodyNotAllowed,
    InvalidBody,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) enum UnassignableResponseError {
    MalformedJson,
    MissingId,
    InvalidId,
    DuplicateId,
    UnsolicitedId,
}

pub(crate) struct IncludedHeader<'a> {
    name: &'a HeaderName,
    values: &'a [HeaderValue],
}

impl<'a> IncludedHeader<'a> {
    pub(crate) fn new(name: &'a HeaderName, values: &'a [HeaderValue]) -> Self {
        Self { name, values }
    }

    pub(crate) fn name(&self) -> &HeaderName {
        self.name
    }

    pub(crate) fn values(&self) -> &[HeaderValue] {
        self.values
    }
}

pub(crate) struct ProviderRequestHeaders<'a> {
    fields: &'a [IncludedHeader<'a>],
}

const MAX_INCLUDED_HEADER_VALUE_BYTES: usize = 64 * 1024;
const MAX_INCLUDED_HEADERS_BYTES: usize = 1024 * 1024;
const MAX_PROVIDER_REQUEST_ID_BYTES: usize = 4096;

impl<'a> ProviderRequestHeaders<'a> {
    pub(crate) fn new(fields: &'a [IncludedHeader<'a>]) -> Result<Self, RequestShapeError> {
        let mut names = BTreeSet::new();
        let mut aggregate_bytes = 0usize;
        for field in fields {
            if field.values.is_empty()
                || !names.insert(field.name.as_str())
                || field.values.iter().any(|value| value.to_str().is_err())
            {
                return Err(RequestShapeError::Headers);
            }
            aggregate_bytes = aggregate_bytes
                .checked_add(field.name.as_str().len())
                .ok_or(RequestShapeError::Headers)?;
            for value in field.values {
                if value.as_bytes().len() > MAX_INCLUDED_HEADER_VALUE_BYTES {
                    return Err(RequestShapeError::Headers);
                }
                aggregate_bytes = aggregate_bytes
                    .checked_add(value.as_bytes().len())
                    .ok_or(RequestShapeError::Headers)?;
            }
            if aggregate_bytes > MAX_INCLUDED_HEADERS_BYTES {
                return Err(RequestShapeError::Headers);
            }
        }
        Ok(Self { fields })
    }

    fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub(crate) fn fields(&self) -> &[IncludedHeader<'a>] {
        self.fields
    }
}

impl Serialize for ProviderRequestHeaders<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.fields.len()))?;
        for field in self.fields {
            map.serialize_entry(field.name.as_str(), &SerializableHeaderValues(field.values))?;
        }
        map.end()
    }
}

struct SerializableHeaderValues<'a>(&'a [HeaderValue]);

impl Serialize for SerializableHeaderValues<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for value in self.0 {
            sequence.serialize_element(value.to_str().map_err(serde::ser::Error::custom)?)?;
        }
        sequence.end()
    }
}

/// Borrowed decoded body whose storage remains charged to the request guard.
pub(crate) struct GuardedProviderBody<'a> {
    pub(crate) content_type: Option<&'a str>,
    pub(crate) content_encoding: Option<&'a str>,
    pub(crate) decoded: &'a GuardedBody,
}

pub(crate) struct ProviderRequest<'a> {
    pub(crate) request_id: &'a str,
    pub(crate) url: &'a str,
    pub(crate) method: &'a str,
    pub(crate) client_ip: &'a str,
    pub(crate) headers: Option<&'a ProviderRequestHeaders<'a>>,
    pub(crate) body: Option<GuardedProviderBody<'a>>,
}

impl ProviderRequest<'_> {
    /// Reference encoder used only to verify the guarded async production
    /// framing byte-for-byte in tests.
    #[cfg(test)]
    pub(crate) fn write_compact(
        &self,
        correlation_id: &str,
        mut writer: impl Write,
    ) -> Result<(), RequestShapeError> {
        self.prevalidate(correlation_id)?;

        writer.write_all(b"{\"id\":")?;
        write_json_string(&mut writer, correlation_id)?;
        writer.write_all(b",\"requestId\":")?;
        write_json_string(&mut writer, self.request_id)?;
        writer.write_all(b",\"type\":\"request\",\"url\":")?;
        write_json_string(&mut writer, self.url)?;
        writer.write_all(b",\"method\":")?;
        write_json_string(&mut writer, self.method)?;
        writer.write_all(b",\"clientIp\":")?;
        write_json_string(&mut writer, self.client_ip)?;
        if let Some(headers) = self.headers.filter(|headers| !headers.is_empty()) {
            writer.write_all(b",\"headers\":")?;
            serde_json::to_writer(&mut writer, headers)
                .map_err(|_| RequestShapeError::Serialization)?;
        }
        if let Some(body) = &self.body {
            writer.write_all(b",\"body\":{\"encoding\":\"base64\"")?;
            if let Some(content_type) = body.content_type {
                writer.write_all(b",\"contentType\":")?;
                write_json_string(&mut writer, content_type)?;
            }
            if let Some(content_encoding) = body.content_encoding {
                writer.write_all(b",\"contentEncoding\":")?;
                write_json_string(&mut writer, content_encoding)?;
            }
            writer.write_all(b",\"data\":\"")?;
            write_base64_stream(&mut writer, body.decoded)?;
            writer.write_all(b"\"}")?;
        }
        writer.write_all(b"}\n")?;
        Ok(())
    }

    pub(crate) async fn stream_before_commit<W>(
        &self,
        correlation_id: &str,
        writer: &mut W,
        scratch: &mut GuardedScratch,
    ) -> Result<ProviderRequestCommit, RequestStreamError>
    where
        W: AsyncWrite + Unpin,
    {
        self.prevalidate(correlation_id)
            .map_err(RequestStreamError::Shape)?;
        let mut writer = ScratchAsyncWriter { writer, scratch };

        writer.write_all(b"{\"id\":").await?;
        write_json_string_async(&mut writer, correlation_id).await?;
        writer.write_all(b",\"requestId\":").await?;
        write_json_string_async(&mut writer, self.request_id).await?;
        writer.write_all(b",\"type\":\"request\",\"url\":").await?;
        write_json_string_async(&mut writer, self.url).await?;
        writer.write_all(b",\"method\":").await?;
        write_json_string_async(&mut writer, self.method).await?;
        writer.write_all(b",\"clientIp\":").await?;
        write_json_string_async(&mut writer, self.client_ip).await?;
        if let Some(headers) = self.headers.filter(|headers| !headers.is_empty()) {
            writer.write_all(b",\"headers\":{").await?;
            for (field_index, field) in headers.fields.iter().enumerate() {
                if field_index != 0 {
                    writer.write_all(b",").await?;
                }
                write_json_string_async(&mut writer, field.name.as_str()).await?;
                writer.write_all(b":[").await?;
                for (value_index, value) in field.values.iter().enumerate() {
                    if value_index != 0 {
                        writer.write_all(b",").await?;
                    }
                    let value = value
                        .to_str()
                        .map_err(|_| RequestStreamError::Shape(RequestShapeError::Headers))?;
                    write_json_string_async(&mut writer, value).await?;
                }
                writer.write_all(b"]").await?;
            }
            writer.write_all(b"}").await?;
        }
        if let Some(body) = &self.body {
            writer
                .write_all(b",\"body\":{\"encoding\":\"base64\"")
                .await?;
            if let Some(content_type) = body.content_type {
                writer.write_all(b",\"contentType\":").await?;
                write_json_string_async(&mut writer, content_type).await?;
            }
            if let Some(content_encoding) = body.content_encoding {
                writer.write_all(b",\"contentEncoding\":").await?;
                write_json_string_async(&mut writer, content_encoding).await?;
            }
            writer.write_all(b",\"data\":\"").await?;
            write_base64_async(&mut writer, body.decoded).await?;
            writer.write_all(b"\"}").await?;
        }
        writer.write_all(b"}").await?;
        writer.flush().await?;
        Ok(ProviderRequestCommit { _private: () })
    }

    fn prevalidate(&self, correlation_id: &str) -> Result<(), RequestShapeError> {
        if self.request_id.is_empty() || self.request_id.len() > MAX_PROVIDER_REQUEST_ID_BYTES {
            return Err(RequestShapeError::RequestId);
        }
        if correlation_id.len() != PROCESS_PROVIDER_CORRELATION_ID_BYTES
            || correlation_id
                .bytes()
                .any(|byte| matches!(byte, b'\\' | b'"' | 0..=31 | 127..=u8::MAX))
        {
            return Err(RequestShapeError::RequestId);
        }
        if let Some(headers) = self.headers {
            ProviderRequestHeaders::new(headers.fields)?;
        }
        if let Some(body) = &self.body {
            validate_content_metadata(body.content_type, body.content_encoding)
                .map_err(|_| RequestShapeError::BodyMetadata)?;
        }
        Ok(())
    }
}

pub(crate) struct ProviderRequestCommit {
    _private: (),
}

impl ProviderRequestCommit {
    pub(crate) async fn commit<W>(self, writer: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        writer.write_all(b"\n").await?;
        writer.flush().await
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RequestStreamError {
    #[error("process-provider request shape is invalid")]
    Shape(RequestShapeError),
    #[error("process-provider stdin write failed")]
    Io(#[source] io::Error),
}

impl From<io::Error> for RequestStreamError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

struct ScratchAsyncWriter<'writer, W> {
    writer: &'writer mut W,
    scratch: &'writer mut GuardedScratch,
}

impl<W> Drop for ScratchAsyncWriter<'_, W> {
    fn drop(&mut self) {
        self.scratch.reset();
    }
}

impl<W> ScratchAsyncWriter<'_, W>
where
    W: AsyncWrite + Unpin,
{
    async fn write_all(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            if self.scratch.remaining() == 0 {
                self.flush().await?;
            }
            let copied = self.scratch.extend_from_slice(bytes);
            bytes = &bytes[copied..];
        }
        Ok(())
    }

    async fn flush(&mut self) -> io::Result<()> {
        if !self.scratch.is_empty() {
            let result = self.writer.write_all(self.scratch.as_slice()).await;
            self.scratch.reset();
            result?;
        }
        Ok(())
    }
}

async fn write_json_string_async<W>(
    writer: &mut ScratchAsyncWriter<'_, W>,
    value: &str,
) -> Result<(), RequestStreamError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(b"\"").await?;
    let mut run_start = 0;
    for (index, byte) in value.bytes().enumerate() {
        let escape = match byte {
            b'"' => Some(b"\\\"".as_slice()),
            b'\\' => Some(b"\\\\".as_slice()),
            b'\x08' => Some(b"\\b".as_slice()),
            b'\x0c' => Some(b"\\f".as_slice()),
            b'\n' => Some(b"\\n".as_slice()),
            b'\r' => Some(b"\\r".as_slice()),
            b'\t' => Some(b"\\t".as_slice()),
            0..=31 => None,
            _ => continue,
        };
        writer
            .write_all(&value.as_bytes()[run_start..index])
            .await?;
        if let Some(escape) = escape {
            writer.write_all(escape).await?;
        } else {
            let escaped = Zeroizing::new([
                b'\\',
                b'u',
                b'0',
                b'0',
                hex_digit(byte >> 4),
                hex_digit(byte & 0x0f),
            ]);
            writer.write_all(&escaped[..]).await?;
        }
        run_start = index + 1;
    }
    writer.write_all(&value.as_bytes()[run_start..]).await?;
    writer.write_all(b"\"").await?;
    Ok(())
}

fn hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'a' + nibble - 10,
    }
}

async fn write_base64_async<W>(
    writer: &mut ScratchAsyncWriter<'_, W>,
    decoded: &GuardedBody,
) -> Result<(), RequestStreamError>
where
    W: AsyncWrite + Unpin,
{
    let mut triple = Zeroizing::new([0u8; 3]);
    let mut triple_len = 0;
    let result = async {
        for segment in decoded.segments() {
            for byte in segment {
                triple[triple_len] = *byte;
                triple_len += 1;
                if triple_len == triple.len() {
                    let mut encoded = Zeroizing::new([0u8; 4]);
                    BASE64_STANDARD
                        .encode_slice(&triple[..], &mut encoded[..])
                        .expect("four output bytes fit one base64 quantum");
                    writer.write_all(&encoded[..]).await?;
                    triple_len = 0;
                }
            }
        }
        if triple_len != 0 {
            let mut encoded = Zeroizing::new([0u8; 4]);
            let encoded_len = BASE64_STANDARD
                .encode_slice(&triple[..triple_len], &mut encoded[..])
                .expect("four output bytes fit one base64 quantum");
            let result = writer.write_all(&encoded[..encoded_len]).await;
            result?;
        }
        Ok(())
    }
    .await;
    result
}

// Reference-only synchronous framing helpers. Production framing must use the
// guarded async path above.
#[cfg(test)]
fn write_json_string(writer: impl Write, value: &str) -> Result<(), RequestShapeError> {
    serde_json::to_writer(writer, value).map_err(|_| RequestShapeError::Serialization)
}

#[cfg(test)]
fn write_base64_stream(
    writer: &mut impl Write,
    decoded: &GuardedBody,
) -> Result<(), RequestShapeError> {
    let mut encoder = base64::write::EncoderWriter::new(writer, &BASE64_STANDARD);
    for segment in decoded.segments() {
        encoder.write_all(segment)?;
    }
    encoder.finish().map_err(RequestShapeError::from)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestShapeError {
    RequestId,
    Headers,
    BodyMetadata,
    #[cfg(test)]
    Serialization,
}

#[cfg(test)]
impl From<std::io::Error> for RequestShapeError {
    fn from(_: std::io::Error) -> Self {
        Self::Serialization
    }
}

pub(crate) const PROCESS_PROVIDER_CORRELATION_ID_BYTES: usize = 34;
pub(crate) const PROCESS_PROVIDER_RESPONSE_PREFIX_BYTES: usize =
    br#"{"id":""#.len() + PROCESS_PROVIDER_CORRELATION_ID_BYTES + 1;
pub(crate) const PROCESS_PROVIDER_RESPONSE_TERMINATOR_BYTES: usize = 1;
pub(crate) const PROCESS_PROVIDER_MIN_DECISION_RESPONSE_BYTES: usize =
    PROCESS_PROVIDER_RESPONSE_PREFIX_BYTES
        + br#","type":"response","decision":"pass"}"#.len()
        + PROCESS_PROVIDER_RESPONSE_TERMINATOR_BYTES;
const MAX_RESPONSE_ID_PREFIX_BYTES: usize = 4096;

const _: () = assert!(PROCESS_PROVIDER_RESPONSE_PREFIX_BYTES <= MAX_RESPONSE_ID_PREFIX_BYTES);

/// Unbuffered child stdout. Keeping construction at the authorization owner
/// prevents a prefetching reader from crossing the request-assignment boundary.
pub(super) struct DirectProviderStdout {
    inner: ChildStdout,
}

impl DirectProviderStdout {
    pub(super) fn new(inner: ChildStdout) -> Self {
        Self { inner }
    }
}

impl AsyncRead for DirectProviderStdout {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

pub(crate) struct ProviderResponseContinuation {
    id: String,
    consumed_bytes: usize,
    max_line_bytes: usize,
}

impl ProviderResponseContinuation {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    #[cfg(test)]
    pub(crate) fn consumed_bytes(&self) -> usize {
        self.consumed_bytes
    }

    pub(crate) fn remaining_line_bytes(&self) -> usize {
        self.max_line_bytes - self.consumed_bytes
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ResponsePrefixError {
    #[error("process-provider response prefix is invalid")]
    Invalid,
    #[error("process-provider response prefix exceeds its bound")]
    TooLong,
    #[error("process-provider stdout read failed")]
    Io(#[source] std::io::Error),
}

/// Reads only the first `id` member through its closing quote. The supervisor
/// must match that ID to a pending request and supply its body guard before the
/// delimiter or any continuation bytes are consumed. The direct stdout reader
/// must not be wrapped in a prefetching buffer.
pub(super) async fn read_provider_response_prefix(
    reader: &mut DirectProviderStdout,
    max_line_bytes: usize,
) -> Result<Option<ProviderResponseContinuation>, ResponsePrefixError> {
    read_provider_response_prefix_from(reader, max_line_bytes).await
}

#[cfg(test)]
pub(super) async fn read_provider_response_prefix_for_test<R>(
    reader: &mut R,
    max_line_bytes: usize,
) -> Result<Option<ProviderResponseContinuation>, ResponsePrefixError>
where
    R: AsyncRead + Unpin,
{
    read_provider_response_prefix_from(reader, max_line_bytes).await
}

async fn read_provider_response_prefix_from<R>(
    reader: &mut R,
    max_line_bytes: usize,
) -> Result<Option<ProviderResponseContinuation>, ResponsePrefixError>
where
    R: AsyncRead + Unpin,
{
    let prefix_limit = max_line_bytes.min(MAX_RESPONSE_ID_PREFIX_BYTES);
    let mut consumed = 0usize;
    let Some(first) = read_prefix_byte(reader, &mut consumed, prefix_limit).await? else {
        return Ok(None);
    };
    if first != b'{' {
        return Err(ResponsePrefixError::Invalid);
    }
    expect_prefix_bytes(reader, &mut consumed, prefix_limit, b"\"id\"").await?;
    expect_prefix_byte(reader, &mut consumed, prefix_limit, b':').await?;
    expect_prefix_byte(reader, &mut consumed, prefix_limit, b'\"').await?;

    let mut id = Zeroizing::new([0u8; MAX_RESPONSE_ID_PREFIX_BYTES]);
    let mut id_len = 0usize;
    loop {
        let byte = read_prefix_byte(reader, &mut consumed, prefix_limit)
            .await?
            .ok_or(ResponsePrefixError::Invalid)?;
        match byte {
            b'\"' => {
                if id_len == 0 {
                    return Err(ResponsePrefixError::Invalid);
                }
                break;
            }
            b'\\' | 0..=31 | 127..=u8::MAX => return Err(ResponsePrefixError::Invalid),
            byte => {
                if id_len == id.len() {
                    return Err(ResponsePrefixError::TooLong);
                }
                id[id_len] = byte;
                id_len += 1;
            }
        }
    }
    let parsed_id = std::str::from_utf8(&id[..id_len])
        .map_err(|_| ResponsePrefixError::Invalid)?
        .to_owned();
    Ok(Some(ProviderResponseContinuation {
        id: parsed_id,
        consumed_bytes: consumed,
        max_line_bytes,
    }))
}

async fn expect_prefix_bytes<R>(
    reader: &mut R,
    consumed: &mut usize,
    limit: usize,
    expected: &[u8],
) -> Result<(), ResponsePrefixError>
where
    R: AsyncRead + Unpin,
{
    for expected in expected {
        expect_prefix_byte(reader, consumed, limit, *expected).await?;
    }
    Ok(())
}

async fn expect_prefix_byte<R>(
    reader: &mut R,
    consumed: &mut usize,
    limit: usize,
    expected: u8,
) -> Result<(), ResponsePrefixError>
where
    R: AsyncRead + Unpin,
{
    if read_prefix_byte(reader, consumed, limit).await? != Some(expected) {
        return Err(ResponsePrefixError::Invalid);
    }
    Ok(())
}

async fn read_prefix_byte<R>(
    reader: &mut R,
    consumed: &mut usize,
    limit: usize,
) -> Result<Option<u8>, ResponsePrefixError>
where
    R: AsyncRead + Unpin,
{
    if *consumed == limit {
        return Err(ResponsePrefixError::TooLong);
    }
    let mut byte = [0u8; 1];
    if reader
        .read(&mut byte)
        .await
        .map_err(ResponsePrefixError::Io)?
        == 0
    {
        return Ok(None);
    }
    let byte = byte[0];
    if byte == b'\n' || byte == b'\r' {
        return Err(ResponsePrefixError::Invalid);
    }
    *consumed += 1;
    Ok(Some(byte))
}

#[cfg(test)]
fn parse_response(
    line: &str,
    outputs: &ProviderOutputRegistry,
    body_admission: BodyReplacementAdmission<'_>,
    is_pending: impl FnOnce(&str) -> bool,
) -> ResponseClassification {
    let raw: RawResponse = match serde_json::from_str(line) {
        Ok(raw) => raw,
        Err(_) => {
            return ResponseClassification::Unassignable(UnassignableResponseError::MalformedJson)
        }
    };

    if raw.duplicate_id {
        return ResponseClassification::Unassignable(UnassignableResponseError::DuplicateId);
    }
    let Some(id) = raw.id.as_ref() else {
        return ResponseClassification::Unassignable(UnassignableResponseError::MissingId);
    };
    let Some(id) = id.as_str().map(str::to_owned) else {
        return ResponseClassification::Unassignable(UnassignableResponseError::InvalidId);
    };
    if id.is_empty() {
        return ResponseClassification::Unassignable(UnassignableResponseError::InvalidId);
    }
    if !is_pending(&id) {
        return ResponseClassification::Unassignable(UnassignableResponseError::UnsolicitedId);
    }

    let result = validate_assigned_response(raw, outputs, body_admission);
    ResponseClassification::Assigned { id, result }
}

#[cfg(test)]
fn validate_assigned_response(
    raw: RawResponse,
    outputs: &ProviderOutputRegistry,
    body_admission: BodyReplacementAdmission<'_>,
) -> Result<ProviderDecision, AssignedResponseError> {
    if raw.duplicate_non_id {
        return Err(AssignedResponseError::DuplicateField);
    }
    if raw.unknown_field {
        return Err(AssignedResponseError::InvalidShape);
    }
    if raw.message_type.as_ref().and_then(CapturedScalar::as_str) != Some("response") {
        return Err(AssignedResponseError::InvalidShape);
    }
    let decision = raw
        .decision
        .as_ref()
        .and_then(CapturedScalar::as_str)
        .ok_or(AssignedResponseError::InvalidShape)?;

    match decision {
        "allow" => {
            let credentials = bind_output_values(raw.values, outputs)?;
            let replacement = match raw.body {
                Some(body) => Some(body.finish(body_admission)?),
                None => None,
            };
            Ok(ProviderDecision::Allow {
                credentials,
                replacement,
            })
        }
        "deny" => {
            if raw.values.is_some() || raw.body.is_some() {
                Err(AssignedResponseError::InvalidShape)
            } else {
                Ok(ProviderDecision::Deny)
            }
        }
        "pass" => {
            if raw.values.is_some() || raw.body.is_some() {
                Err(AssignedResponseError::InvalidShape)
            } else {
                Ok(ProviderDecision::Pass)
            }
        }
        _ => Err(AssignedResponseError::InvalidShape),
    }
}

#[cfg(test)]
fn bind_output_values(
    values: Option<CapturedValues>,
    outputs: &ProviderOutputRegistry,
) -> Result<ProviderCredentialSet, AssignedResponseError> {
    let mut bound: Vec<Option<SecretBytes>> = std::iter::repeat_with(|| None)
        .take(outputs.len())
        .collect();
    if let Some(values) = values {
        if values.duplicate {
            return Err(AssignedResponseError::DuplicateOutput);
        }
        if values.invalid {
            return Err(AssignedResponseError::InvalidCredential);
        }
        for (name, value) in values.entries {
            let index = outputs
                .by_wire_name
                .get(&name)
                .copied()
                .ok_or(AssignedResponseError::UnknownOutput)?;
            if value.is_empty()
                || value.len() > MAX_PROVIDER_CREDENTIAL_BYTES
                || !valid_header_value_bytes(value.as_bytes())
            {
                return Err(AssignedResponseError::InvalidCredential);
            }
            bound[index.get()] = Some(value);
        }
    }
    if outputs
        .definitions
        .iter()
        .zip(&bound)
        .any(|(definition, value)| definition.required() && value.is_none())
    {
        return Err(AssignedResponseError::MissingRequiredOutput);
    }
    Ok(ProviderCredentialSet::Contiguous(
        ContiguousProviderCredentials {
            registry_id: outputs.id,
            values: bound.into_boxed_slice(),
        },
    ))
}

#[cfg(test)]
fn valid_header_value_bytes(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| *byte == b'\t' || (*byte >= 32 && *byte != 127))
}

#[cfg(test)]
#[derive(Default)]
struct RawResponse {
    id: Option<CapturedScalar>,
    message_type: Option<CapturedScalar>,
    decision: Option<CapturedScalar>,
    values: Option<CapturedValues>,
    body: Option<CapturedBody>,
    duplicate_id: bool,
    duplicate_non_id: bool,
    unknown_field: bool,
}

#[cfg(test)]
impl<'de> Deserialize<'de> for RawResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RawResponseVisitor)
    }
}

#[cfg(test)]
struct RawResponseVisitor;

#[cfg(test)]
impl<'de> Visitor<'de> for RawResponseVisitor {
    type Value = RawResponse;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a process-provider response object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut response = RawResponse::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "id" => {
                    let value = map.next_value::<CapturedScalar>()?;
                    if response.id.replace(value).is_some() {
                        response.duplicate_id = true;
                    }
                }
                "type" => {
                    let value = map.next_value::<CapturedScalar>()?;
                    if response.message_type.replace(value).is_some() {
                        response.duplicate_non_id = true;
                    }
                }
                "decision" => {
                    let value = map.next_value::<CapturedScalar>()?;
                    if response.decision.replace(value).is_some() {
                        response.duplicate_non_id = true;
                    }
                }
                "values" => {
                    let value = map.next_value::<CapturedValues>()?;
                    if response.values.replace(value).is_some() {
                        response.duplicate_non_id = true;
                    }
                }
                "requestBody" => {
                    let value = map.next_value::<CapturedBody>()?;
                    if response.body.replace(value).is_some() {
                        response.duplicate_non_id = true;
                    }
                }
                _ => {
                    response.unknown_field = true;
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(response)
    }
}

#[cfg(test)]
enum CapturedScalar {
    String(String),
    Other,
}

#[cfg(test)]
impl CapturedScalar {
    fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            Self::Other => None,
        }
    }
}

#[cfg(test)]
impl<'de> Deserialize<'de> for CapturedScalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ScalarVisitor;
        impl<'de> Visitor<'de> for ScalarVisitor {
            type Value = CapturedScalar;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("any JSON value")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(CapturedScalar::String(value.to_string()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(CapturedScalar::String(value))
            }

            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(CapturedScalar::Other)
            }

            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                Ok(CapturedScalar::Other)
            }

            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                Ok(CapturedScalar::Other)
            }

            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(CapturedScalar::Other)
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(CapturedScalar::Other)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(CapturedScalar::Other)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                while sequence.next_element::<IgnoredAny>()?.is_some() {}
                Ok(CapturedScalar::Other)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(CapturedScalar::Other)
            }
        }
        deserializer.deserialize_any(ScalarVisitor)
    }
}

#[cfg(test)]
#[derive(Default)]
struct CapturedValues {
    entries: Vec<(String, SecretBytes)>,
    duplicate: bool,
    invalid: bool,
}

#[cfg(test)]
impl<'de> Deserialize<'de> for CapturedValues {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ValuesVisitor;
        impl<'de> Visitor<'de> for ValuesVisitor {
            type Value = CapturedValues;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a provider values object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut captured = CapturedValues::default();
                let mut names = BTreeSet::new();
                while let Some(name) = map.next_key::<String>()? {
                    if !names.insert(name.clone()) {
                        captured.duplicate = true;
                    }
                    match map.next_value::<SecretCapture>()? {
                        SecretCapture::Value(value) => captured.entries.push((name, value)),
                        SecretCapture::Invalid => captured.invalid = true,
                    }
                }
                Ok(captured)
            }

            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(invalid_values())
            }

            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                Ok(invalid_values())
            }

            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                Ok(invalid_values())
            }

            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(invalid_values())
            }

            fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
                Ok(invalid_values())
            }

            fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E> {
                value.zeroize();
                Ok(invalid_values())
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(invalid_values())
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                while sequence.next_element::<IgnoredAny>()?.is_some() {}
                Ok(invalid_values())
            }
        }
        deserializer.deserialize_any(ValuesVisitor)
    }
}

#[cfg(test)]
fn invalid_values() -> CapturedValues {
    CapturedValues {
        invalid: true,
        ..CapturedValues::default()
    }
}

#[cfg(test)]
enum SecretCapture {
    Value(SecretBytes),
    Invalid,
}

#[cfg(test)]
impl<'de> Deserialize<'de> for SecretCapture {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SecretVisitor;
        impl<'de> Visitor<'de> for SecretVisitor {
            type Value = SecretCapture;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a provider credential string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(SecretCapture::Value(SecretBytes(value.as_bytes().to_vec())))
            }

            fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E> {
                let secret = SecretBytes(value.as_bytes().to_vec());
                value.zeroize();
                Ok(SecretCapture::Value(secret))
            }

            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(SecretCapture::Invalid)
            }

            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                Ok(SecretCapture::Invalid)
            }

            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                Ok(SecretCapture::Invalid)
            }

            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(SecretCapture::Invalid)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(SecretCapture::Invalid)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                while sequence.next_element::<IgnoredAny>()?.is_some() {}
                Ok(SecretCapture::Invalid)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(SecretCapture::Invalid)
            }
        }
        deserializer.deserialize_any(SecretVisitor)
    }
}

#[cfg(test)]
#[derive(Default)]
struct CapturedBody {
    encoding: Option<CapturedScalar>,
    content_type: Option<CapturedScalar>,
    content_encoding: Option<CapturedScalar>,
    data: Option<SecretCapture>,
    duplicate: bool,
    unknown: bool,
    invalid_container: bool,
}

#[cfg(test)]
impl CapturedBody {
    fn finish(
        self,
        admission: BodyReplacementAdmission<'_>,
    ) -> Result<ProviderBodyReplacement, AssignedResponseError> {
        let BodyReplacementAdmission::Allowed {
            guard,
            max_decoded_bytes,
        } = admission
        else {
            return Err(AssignedResponseError::BodyNotAllowed);
        };
        if self.invalid_container || self.duplicate || self.unknown {
            return Err(AssignedResponseError::InvalidBody);
        }
        if self.encoding.as_ref().and_then(CapturedScalar::as_str) != Some("base64") {
            return Err(AssignedResponseError::InvalidBody);
        }
        let content_type = optional_string(self.content_type)?;
        let content_encoding = optional_string(self.content_encoding)?;
        validate_content_metadata(content_type.as_deref(), content_encoding.as_deref())?;
        let Some(SecretCapture::Value(mut encoded)) = self.data else {
            return Err(AssignedResponseError::InvalidBody);
        };
        let max_encoded_len = max_decoded_bytes
            .saturating_add(2)
            .saturating_div(3)
            .saturating_mul(4);
        if encoded.len() > max_encoded_len {
            return Err(AssignedResponseError::InvalidBody);
        }
        let mut decoded = guard.replacement_buffer();
        let mut decoder = DecoderReader::new(encoded.as_bytes(), &BASE64_STANDARD);
        let mut scratch = [0u8; PROVIDER_STREAM_SCRATCH_BYTES];
        loop {
            let read = match decoder.read(&mut scratch) {
                Ok(read) => read,
                Err(_) => {
                    scratch.zeroize();
                    return Err(AssignedResponseError::InvalidBody);
                }
            };
            if read == 0 {
                break;
            }
            let within_limit = decoded
                .len()
                .checked_add(read)
                .is_some_and(|length| length <= max_decoded_bytes);
            if !within_limit || decoded.try_extend_from_slice(&scratch[..read]).is_err() {
                scratch.zeroize();
                return Err(AssignedResponseError::InvalidBody);
            }
            scratch[..read].zeroize();
        }
        scratch.zeroize();
        encoded.zeroize();
        Ok(ProviderBodyReplacement {
            content_type,
            content_encoding,
            storage: ProviderBodyReplacementStorage::Decoded(decoded.finish()),
        })
    }
}

fn validate_content_metadata(
    content_type: Option<&str>,
    content_encoding: Option<&str>,
) -> Result<(), AssignedResponseError> {
    if content_type.is_some_and(|value| HeaderValue::from_str(value).is_err()) {
        return Err(AssignedResponseError::InvalidBody);
    }
    if let Some(value) = content_encoding {
        if HeaderValue::from_str(value).is_err() || !valid_canonical_content_encoding(value) {
            return Err(AssignedResponseError::InvalidBody);
        }
    }
    Ok(())
}

fn valid_canonical_content_encoding(value: &str) -> bool {
    value == "identity"
}

#[cfg(test)]
fn optional_string(value: Option<CapturedScalar>) -> Result<Option<String>, AssignedResponseError> {
    value
        .map(|value| match value {
            CapturedScalar::String(value) => Ok(value),
            CapturedScalar::Other => Err(AssignedResponseError::InvalidBody),
        })
        .transpose()
}

#[cfg(test)]
impl<'de> Deserialize<'de> for CapturedBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BodyVisitor;
        impl<'de> Visitor<'de> for BodyVisitor {
            type Value = CapturedBody;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a provider request-body replacement object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut body = CapturedBody::default();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "encoding" => {
                            let value = map.next_value::<CapturedScalar>()?;
                            if body.encoding.replace(value).is_some() {
                                body.duplicate = true;
                            }
                        }
                        "contentType" => {
                            let value = map.next_value::<CapturedScalar>()?;
                            if body.content_type.replace(value).is_some() {
                                body.duplicate = true;
                            }
                        }
                        "contentEncoding" => {
                            let value = map.next_value::<CapturedScalar>()?;
                            if body.content_encoding.replace(value).is_some() {
                                body.duplicate = true;
                            }
                        }
                        "data" => {
                            let value = map.next_value::<SecretCapture>()?;
                            if body.data.replace(value).is_some() {
                                body.duplicate = true;
                            }
                        }
                        _ => {
                            body.unknown = true;
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(body)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                while sequence.next_element::<IgnoredAny>()?.is_some() {}
                Ok(CapturedBody {
                    invalid_container: true,
                    ..CapturedBody::default()
                })
            }

            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(invalid_body())
            }

            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                Ok(invalid_body())
            }

            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                Ok(invalid_body())
            }

            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(invalid_body())
            }

            fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
                Ok(invalid_body())
            }

            fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E> {
                value.zeroize();
                Ok(invalid_body())
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(invalid_body())
            }
        }
        deserializer.deserialize_any(BodyVisitor)
    }
}

#[cfg(test)]
fn invalid_body() -> CapturedBody {
    CapturedBody {
        invalid_container: true,
        ..CapturedBody::default()
    }
}

#[cfg(test)]
struct SecretBytes(Vec<u8>);

#[cfg(test)]
impl SecretBytes {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::CONTENT_TYPE;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::safety::{WireBodyPool, WireBodyQuotaKey};

    const TEST_CORRELATION_ID: &str = "p0000000000000001-0000000000000001";

    #[test]
    fn webhook_callback_envelope_limits_follow_canonical_wire_literals() {
        assert_eq!(
            MIN_WEBHOOK_REQUEST_WITHOUT_CALLBACK_URL_BYTES,
            MIN_WEBHOOK_REQUEST_WITHOUT_CALLBACK_URL_WIRE.len()
        );
        assert_eq!(
            CALLBACK_RESPONSE_PREFIX_BYTES,
            CALLBACK_RESPONSE_PREFIX_WIRE.len()
        );
        assert_eq!(
            MIN_CALLBACK_RESPONSE_BYTES,
            MIN_CALLBACK_RESPONSE_WIRE.len()
        );
        assert!(MIN_CALLBACK_RESPONSE_WIRE.starts_with(CALLBACK_RESPONSE_PREFIX_WIRE));
    }

    struct PendingAsyncWriter {
        attempted: bool,
    }

    impl AsyncWrite for PendingAsyncWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.attempted = true;
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    fn outputs(required: bool) -> ProviderOutputRegistry {
        ProviderOutputRegistry::activate(BTreeMap::from([(
            "token".to_string(),
            ProviderOutputPlan::Bearer { required },
        )]))
    }

    fn staging_guard() -> HttpWireBodyGuard {
        let peak = crate::safety::wire_body::guarded_body_allocation_bytes(
            2 * MAX_PROVIDER_CREDENTIAL_BYTES,
        )
        .unwrap();
        WireBodyPool::new(peak, peak).begin_for_test(
            peak,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        )
    }

    fn assigned_result(
        line: &str,
        outputs: &ProviderOutputRegistry,
        allow_body: bool,
    ) -> Result<ProviderDecision, AssignedResponseError> {
        let peak = crate::safety::wire_body::guarded_body_allocation_bytes(64).unwrap();
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(
            peak,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );
        let admission = if allow_body {
            BodyReplacementAdmission::Allowed {
                guard: &guard,
                max_decoded_bytes: 64,
            }
        } else {
            BodyReplacementAdmission::Denied
        };
        match parse_response(line, outputs, admission, |id| id == "request-1") {
            ResponseClassification::Assigned { id, result } => {
                assert_eq!(id, "request-1");
                result
            }
            ResponseClassification::Unassignable(error) => {
                panic!("unexpected unassignable response: {error:?}")
            }
        }
    }

    #[test]
    fn request_serialization_is_compact_and_uses_header_arrays() {
        let values = [
            HeaderValue::from_static("first"),
            HeaderValue::from_static("second"),
        ];
        let fields = [IncludedHeader::new(&CONTENT_TYPE, &values)];
        let headers = ProviderRequestHeaders::new(&fields).unwrap();
        let peak = crate::safety::wire_body::guarded_body_allocation_bytes(2).unwrap();
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(
            peak,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );
        let mut decoded = guard.buffer();
        decoded.try_extend_from_slice(b"{}").unwrap();
        let decoded = decoded.finish();
        let request = ProviderRequest {
            request_id: "request-1",
            url: "https://example.test/path",
            method: "GET",
            client_ip: "127.0.0.1",
            headers: Some(&headers),
            body: Some(GuardedProviderBody {
                content_type: Some("application/json"),
                content_encoding: Some("identity"),
                decoded: &decoded,
            }),
        };
        let mut serialized = Vec::new();
        request
            .write_compact(TEST_CORRELATION_ID, &mut serialized)
            .unwrap();
        assert_eq!(
            String::from_utf8(serialized).unwrap(),
            format!(
                "{{\"id\":\"{TEST_CORRELATION_ID}\",\"requestId\":\"request-1\",\"type\":\"request\",\"url\":\"https://example.test/path\",\"method\":\"GET\",\"clientIp\":\"127.0.0.1\",\"headers\":{{\"content-type\":[\"first\",\"second\"]}},\"body\":{{\"encoding\":\"base64\",\"contentType\":\"application/json\",\"contentEncoding\":\"identity\",\"data\":\"e30=\"}}}}\n"
            )
        );
    }

    #[test]
    fn request_body_streams_across_linked_chunks() {
        let body_bytes = (0..=u16::MAX)
            .chain(std::iter::once(7))
            .map(|byte| byte as u8)
            .collect::<Vec<_>>();
        let peak = crate::safety::wire_body::guarded_body_allocation_bytes(body_bytes.len())
            .expect("bounded body allocation");
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(
            peak,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );
        let mut decoded = guard.buffer();
        decoded.try_extend_from_slice(&body_bytes).unwrap();
        let decoded = decoded.finish();
        assert_eq!(decoded.segments().count(), 2);

        let request = ProviderRequest {
            request_id: "request-1",
            url: "https://example.test/path",
            method: "POST",
            client_ip: "127.0.0.1",
            headers: None,
            body: Some(GuardedProviderBody {
                content_type: None,
                content_encoding: None,
                decoded: &decoded,
            }),
        };
        let mut serialized = Vec::new();
        request
            .write_compact(TEST_CORRELATION_ID, &mut serialized)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(
            json["body"]["data"],
            BASE64_STANDARD.encode(body_bytes.as_slice())
        );
    }

    #[tokio::test]
    async fn async_request_stream_reuses_one_guarded_chunk_and_commits_lf_separately() {
        let url = format!("https://example.test/{}", "x".repeat(2 * 64 * 1024 + 7));
        let request = ProviderRequest {
            request_id: "request-1",
            url: &url,
            method: "GET",
            client_ip: "127.0.0.1",
            headers: None,
            body: None,
        };
        let mut expected = Vec::new();
        request
            .write_compact(TEST_CORRELATION_ID, &mut expected)
            .unwrap();

        let allocation =
            crate::safety::wire_body::guarded_body_allocation_bytes(64 * 1024).unwrap();
        let pool = WireBodyPool::new(allocation, allocation);
        let guard = pool.begin_for_test(
            allocation,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );
        let mut scratch = guard.stream_scratch().unwrap();
        let mut streamed = Vec::new();
        let commit = request
            .stream_before_commit(TEST_CORRELATION_ID, &mut streamed, &mut scratch)
            .await
            .unwrap();

        assert_eq!(guard.live_bytes(), allocation);
        assert_eq!(pool.global_charge(), allocation);
        assert_eq!(streamed, expected[..expected.len() - 1]);
        drop(scratch);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);

        commit.commit(&mut streamed).await.unwrap();
        assert_eq!(streamed, expected);
    }

    #[tokio::test]
    async fn cancelling_pending_base64_stream_wipes_scratch_and_drop_owned_staging() {
        let one = crate::safety::wire_body::guarded_body_allocation_bytes(64 * 1024).unwrap();
        let peak = 2 * one;
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(
            peak,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );
        let mut body = guard.buffer();
        body.try_extend_from_slice(&vec![0xa5; 64 * 1024]).unwrap();
        let body = body.finish();
        let request = ProviderRequest {
            request_id: "request-1",
            url: "https://example.test/",
            method: "POST",
            client_ip: "127.0.0.1",
            headers: None,
            body: Some(GuardedProviderBody {
                content_type: None,
                content_encoding: None,
                decoded: &body,
            }),
        };
        let mut scratch = guard.stream_scratch().unwrap();
        let mut output = PendingAsyncWriter { attempted: false };

        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            request.stream_before_commit(TEST_CORRELATION_ID, &mut output, &mut scratch),
        )
        .await
        .is_err());
        assert!(output.attempted);
        assert!(scratch.is_empty());
        assert!(scratch.is_zeroed_for_test());
        assert_eq!(guard.live_bytes(), peak);

        drop(scratch);
        assert_eq!(guard.live_bytes(), one);
        drop(body);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn async_serializer_exactly_matches_sync_for_escapes_utf8_and_base64_tails() {
        for body_len in [64 * 1024 + 3, 1, 2] {
            let body_allocation =
                crate::safety::wire_body::guarded_body_allocation_bytes(body_len).unwrap();
            let scratch_allocation =
                crate::safety::wire_body::guarded_body_allocation_bytes(64 * 1024).unwrap();
            let peak = body_allocation + scratch_allocation;
            let pool = WireBodyPool::new(peak, peak);
            let guard = pool.begin_for_test(
                peak,
                WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
            );
            let body_bytes = (0..body_len)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            let mut body = guard.buffer();
            body.try_extend_from_slice(&body_bytes).unwrap();
            let body = body.finish();
            if body_len > 64 * 1024 {
                assert_eq!(body.segments().count(), 2);
                assert_eq!(body_len % 3, 1);
            }
            let header_value = HeaderValue::from_static("quote-\"-slash-\\-utf8-safe");
            let header_values = [header_value];
            let header_fields = [IncludedHeader::new(&CONTENT_TYPE, &header_values)];
            let headers = ProviderRequestHeaders::new(&header_fields).unwrap();
            let request = ProviderRequest {
                request_id: "id-\"-\\-\u{8}-\u{c}-\n-\r-\t-\u{1}-é-雪",
                url: "https://example.test/\"/\\/\u{8}/\u{c}/\n/\r/\t/\u{1}/é/雪",
                method: "MÉTHOD",
                client_ip: "雪",
                headers: Some(&headers),
                body: Some(GuardedProviderBody {
                    content_type: Some("application/octet-stream"),
                    content_encoding: Some("identity"),
                    decoded: &body,
                }),
            };

            let mut synchronous = Vec::new();
            request
                .write_compact(TEST_CORRELATION_ID, &mut synchronous)
                .unwrap();
            let mut asynchronous = Vec::new();
            let mut scratch = guard.stream_scratch().unwrap();
            let commit = request
                .stream_before_commit(TEST_CORRELATION_ID, &mut asynchronous, &mut scratch)
                .await
                .unwrap();
            drop(scratch);
            commit.commit(&mut asynchronous).await.unwrap();

            assert_eq!(asynchronous, synchronous, "body length {body_len}");
            drop(body);
            assert_eq!(guard.live_bytes(), 0);
            assert_eq!(pool.global_charge(), 0);
        }
    }

    #[test]
    fn invalid_body_metadata_fails_before_any_writer_byte() {
        let peak = crate::safety::wire_body::guarded_body_allocation_bytes(1).unwrap();
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(
            peak,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );
        let mut decoded = guard.buffer();
        decoded.try_extend_from_slice(b"x").unwrap();
        let decoded = decoded.finish();

        for (content_type, content_encoding) in [
            (Some("text/plain\n"), None),
            (None, Some("GZIP")),
            (None, Some("gzip\n")),
        ] {
            let request = ProviderRequest {
                request_id: "request-1",
                url: "https://example.test/",
                method: "POST",
                client_ip: "127.0.0.1",
                headers: None,
                body: Some(GuardedProviderBody {
                    content_type,
                    content_encoding,
                    decoded: &decoded,
                }),
            };
            let mut output = Vec::new();
            assert_eq!(
                request.write_compact(TEST_CORRELATION_ID, &mut output),
                Err(RequestShapeError::BodyMetadata)
            );
            assert!(output.is_empty());
        }
    }

    #[test]
    fn logical_and_correlation_ids_are_bounded_before_any_writer_byte() {
        let oversized = "x".repeat(MAX_PROVIDER_REQUEST_ID_BYTES + 1);
        for request_id in ["", oversized.as_str()] {
            let request = ProviderRequest {
                request_id,
                url: "https://example.test/",
                method: "GET",
                client_ip: "127.0.0.1",
                headers: None,
                body: None,
            };
            let mut output = Vec::new();
            assert_eq!(
                request.write_compact(TEST_CORRELATION_ID, &mut output),
                Err(RequestShapeError::RequestId)
            );
            assert!(output.is_empty());
        }

        let request = ProviderRequest {
            request_id: "request-1",
            url: "https://example.test/",
            method: "GET",
            client_ip: "127.0.0.1",
            headers: None,
            body: None,
        };
        let mut output = Vec::new();
        assert_eq!(
            request.write_compact("unsafe", &mut output),
            Err(RequestShapeError::RequestId)
        );
        assert!(output.is_empty());
    }

    #[test]
    fn non_utf8_included_header_fails_before_any_writer_byte() {
        let invalid = HeaderValue::from_bytes(&[0x80]).unwrap();
        let values = [invalid];
        let fields = [IncludedHeader::new(&CONTENT_TYPE, &values)];
        assert!(matches!(
            ProviderRequestHeaders::new(&fields),
            Err(RequestShapeError::Headers)
        ));
        let headers = ProviderRequestHeaders { fields: &fields };
        let request = ProviderRequest {
            request_id: "request-1",
            url: "https://example.test/",
            method: "GET",
            client_ip: "127.0.0.1",
            headers: Some(&headers),
            body: None,
        };
        let mut output = Vec::new();
        assert_eq!(
            request.write_compact(TEST_CORRELATION_ID, &mut output),
            Err(RequestShapeError::Headers)
        );
        assert!(output.is_empty());
    }

    #[test]
    fn included_header_value_limit_accepts_exact_and_rejects_plus_one() {
        let exact = HeaderValue::from_bytes(&vec![b'x'; MAX_INCLUDED_HEADER_VALUE_BYTES]).unwrap();
        let exact_values = [exact];
        let exact_fields = [IncludedHeader::new(&CONTENT_TYPE, &exact_values)];
        assert!(ProviderRequestHeaders::new(&exact_fields).is_ok());

        let over =
            HeaderValue::from_bytes(&vec![b'x'; MAX_INCLUDED_HEADER_VALUE_BYTES + 1]).unwrap();
        let over_values = [over];
        let over_fields = [IncludedHeader::new(&CONTENT_TYPE, &over_values)];
        assert!(matches!(
            ProviderRequestHeaders::new(&over_fields),
            Err(RequestShapeError::Headers)
        ));
    }

    #[tokio::test]
    async fn included_header_aggregate_limit_is_exact_and_precedes_async_writer_bytes() {
        let names = (0..16)
            .map(|index| HeaderName::from_bytes(format!("x-limit-{index}").as_bytes()).unwrap())
            .collect::<Vec<_>>();
        let name_bytes = names.iter().map(|name| name.as_str().len()).sum::<usize>();
        let total_value_bytes = MAX_INCLUDED_HEADERS_BYTES - name_bytes;
        let base_value_bytes = total_value_bytes / names.len();
        let remainder = total_value_bytes % names.len();
        let exact_values = (0..names.len())
            .map(|index| {
                let len = base_value_bytes + usize::from(index < remainder);
                assert!(len <= MAX_INCLUDED_HEADER_VALUE_BYTES);
                HeaderValue::from_bytes(&vec![b'x'; len]).unwrap()
            })
            .collect::<Vec<_>>();
        let exact_fields = names
            .iter()
            .zip(&exact_values)
            .map(|(name, value)| IncludedHeader::new(name, std::slice::from_ref(value)))
            .collect::<Vec<_>>();
        assert!(ProviderRequestHeaders::new(&exact_fields).is_ok());

        let mut over_values = exact_values.clone();
        let last_len = over_values.last().unwrap().as_bytes().len();
        *over_values.last_mut().unwrap() =
            HeaderValue::from_bytes(&vec![b'x'; last_len + 1]).unwrap();
        let over_fields = names
            .iter()
            .zip(&over_values)
            .map(|(name, value)| IncludedHeader::new(name, std::slice::from_ref(value)))
            .collect::<Vec<_>>();
        assert!(matches!(
            ProviderRequestHeaders::new(&over_fields),
            Err(RequestShapeError::Headers)
        ));

        let headers = ProviderRequestHeaders {
            fields: &over_fields,
        };
        let request = ProviderRequest {
            request_id: "request-1",
            url: "https://example.test/",
            method: "GET",
            client_ip: "127.0.0.1",
            headers: Some(&headers),
            body: None,
        };
        let allocation =
            crate::safety::wire_body::guarded_body_allocation_bytes(64 * 1024).unwrap();
        let pool = WireBodyPool::new(allocation, allocation);
        let guard = pool.begin_for_test(
            allocation,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );
        let mut scratch = guard.stream_scratch().unwrap();
        let mut output = Vec::new();
        assert!(matches!(
            request
                .stream_before_commit(TEST_CORRELATION_ID, &mut output, &mut scratch)
                .await,
            Err(RequestStreamError::Shape(RequestShapeError::Headers))
        ));
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn prefix_reader_stops_before_unadmitted_response_bytes() {
        let (mut writer, reader) = tokio::io::duplex(256);
        writer
            .write_all(b"{\"id\":\"request-1\",\"type\":\"response\",\"decision\":\"deny\"}\n")
            .await
            .unwrap();
        drop(writer);
        let mut reader = reader;
        let Some(prefix) = read_provider_response_prefix_for_test(&mut reader, 256)
            .await
            .unwrap()
        else {
            panic!("expected prefix");
        };
        assert_eq!(prefix.id(), "request-1");
        assert_eq!(prefix.consumed_bytes(), b"{\"id\":\"request-1\"".len());
        assert_eq!(prefix.remaining_line_bytes(), 256 - prefix.consumed_bytes());
        let mut remaining = Vec::new();
        AsyncReadExt::read_to_end(&mut reader, &mut remaining)
            .await
            .unwrap();
        assert_eq!(
            remaining,
            b",\"type\":\"response\",\"decision\":\"deny\"}\n"
        );
    }

    #[tokio::test]
    async fn prefix_reader_rejects_missing_first_id_unterminated_and_overlimit() {
        for bytes in [
            b"{\"type\":\"response\",\"id\":\"request-1\",\"decision\":\"deny\"}\n".as_slice(),
            b"{\"id\":\"request-1".as_slice(),
        ] {
            let mut reader = bytes;
            assert!(matches!(
                read_provider_response_prefix_for_test(&mut reader, 256).await,
                Err(ResponsePrefixError::Invalid)
            ));
        }
        let mut reader = b"{\"id\":\"request-1\",\"type\":\"response\"}\n".as_slice();
        assert!(matches!(
            read_provider_response_prefix_for_test(&mut reader, 8).await,
            Err(ResponsePrefixError::TooLong)
        ));
    }

    #[tokio::test]
    async fn prefix_reader_rejects_empty_id_before_consuming_the_next_member() {
        let bytes =
            b"{\"id\":\"\",\"id\":\"request-1\",\"type\":\"response\",\"decision\":\"deny\"}\n";
        let mut reader = bytes.as_slice();
        assert!(matches!(
            read_provider_response_prefix_for_test(&mut reader, 256).await,
            Err(ResponsePrefixError::Invalid)
        ));

        let mut remaining = Vec::new();
        AsyncReadExt::read_to_end(&mut reader, &mut remaining)
            .await
            .unwrap();
        assert_eq!(
            remaining,
            b",\"id\":\"request-1\",\"type\":\"response\",\"decision\":\"deny\"}\n"
        );
    }

    #[tokio::test]
    async fn prefix_reader_rejects_adversarial_id_encodings() {
        for bytes in [
            b"{\"id\":\"escaped\\\"id\",\"type\":\"response\"}\n".as_slice(),
            b"{\"id\":\"non-ASCII-\xc3\xa9\",\"type\":\"response\"}\n".as_slice(),
            b"{\"id\":\"line\nbreak\",\"type\":\"response\"}\n".as_slice(),
            b"{\"id\":\"line\rbreak\",\"type\":\"response\"}\n".as_slice(),
        ] {
            let mut reader = bytes;
            assert!(matches!(
                read_provider_response_prefix_for_test(&mut reader, 256).await,
                Err(ResponsePrefixError::Invalid)
            ));
        }
    }

    #[test]
    fn allow_binds_declared_values_without_disclosing_debug_material() {
        let outputs = outputs(true);
        let ProviderDecision::Allow { credentials, .. } = assigned_result(
            r#"{"id":"request-1","type":"response","decision":"allow","values":{"token":"secret-marker"}}"#,
            &outputs,
            false,
        )
        .unwrap()
        else {
            panic!("expected allow");
        };
        let index = outputs.by_wire_name["token"];
        assert_eq!(
            credentials.contiguous(index),
            Some(b"secret-marker".as_slice())
        );
        assert!(!format!("{credentials:?}").contains("secret-marker"));
        assert!(!format!("{outputs:?}").contains("token"));
    }

    #[test]
    fn output_indices_and_credential_sets_are_registry_branded() {
        let first = outputs(false);
        let second = outputs(false);
        let ProviderDecision::Allow { credentials, .. } = assigned_result(
            r#"{"id":"request-1","type":"response","decision":"allow","values":{"token":"secret-marker"}}"#,
            &first,
            false,
        )
        .unwrap()
        else {
            panic!("expected allow");
        };

        let first_index = first.by_wire_name["token"];
        let second_index = second.by_wire_name["token"];
        assert_eq!(first_index.get(), second_index.get());
        assert_eq!(
            credentials.contiguous(first_index),
            Some(b"secret-marker".as_slice())
        );
        assert_eq!(credentials.contiguous(second_index), None);
        assert!(first.definition(second_index).is_none());
    }

    #[test]
    fn provider_credentials_are_retained_as_raw_exact_material() {
        let outputs = ProviderOutputRegistry::activate(BTreeMap::from([
            (
                "password".to_string(),
                ProviderOutputPlan::Basic {
                    username: "agent".to_string(),
                    required: true,
                },
            ),
            (
                "trace".to_string(),
                ProviderOutputPlan::CustomHeader {
                    header: HeaderName::from_static("x-trace-token"),
                    required: true,
                },
            ),
        ]));
        let ProviderDecision::Allow { credentials, .. } = assigned_result(
            r#"{"id":"request-1","type":"response","decision":"allow","values":{"password":"secret-password","trace":"secret-trace"}}"#,
            &outputs,
            false,
        )
        .unwrap()
        else {
            panic!("expected allow");
        };
        let credential_charge = crate::safety::wire_body::guarded_body_allocation_bytes(1).unwrap();
        let peak = 2 * credential_charge;
        let pool = WireBodyPool::new(peak, peak);
        let quota_key = WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false);
        let guard = pool.begin_for_test(peak, quota_key.clone());
        let material = outputs
            .compact_provider_credential_wire(&credentials, &guard)
            .unwrap();
        let range_charge = projected_provider_credential_wire_metadata_bytes(2).unwrap();

        assert_eq!(material.present_count(), 2);
        assert_eq!(pool.global_charge(), credential_charge + range_charge);
        assert_eq!(
            pool.quota_charge(&quota_key),
            credential_charge + range_charge
        );
        let debug = format!("{material:?}");
        assert!(!debug.contains("secret-password"));
        assert!(!debug.contains("secret-trace"));

        let password = outputs.index("password").unwrap();
        let trace = outputs.index("trace").unwrap();
        assert_eq!(material.output_len(password), Some(15));
        assert_eq!(material.output_len(trace), Some(12));
        let mut password_bytes = [0; 15];
        material.copy_output(password, &mut password_bytes).unwrap();
        let mut trace_bytes = [0; 12];
        material.copy_output(trace, &mut trace_bytes).unwrap();
        assert_eq!(&password_bytes, b"secret-password");
        assert_eq!(&trace_bytes, b"secret-trace");

        let mut wrong_length = [b'x'; 14];
        assert_eq!(
            material.copy_output(password, &mut wrong_length),
            Err(ProviderCredentialWireError::BufferLengthMismatch)
        );
        assert_eq!(wrong_length, [b'x'; 14]);
        drop(material);
        assert_eq!(pool.global_charge(), 0);
        assert_eq!(pool.quota_charge(&quota_key), 0);
    }

    #[test]
    fn material_store_rejects_foreign_or_absent_outputs_without_rendering_destinations() {
        let first = outputs(true);
        let second = outputs(true);
        let ProviderDecision::Allow { credentials, .. } = assigned_result(
            r#"{"id":"request-1","type":"response","decision":"allow","values":{"token":"secret-marker"}}"#,
            &first,
            false,
        )
        .unwrap()
        else {
            panic!("expected allow");
        };
        let error = second
            .compact_provider_credential_wire(&credentials, &staging_guard())
            .unwrap_err();
        assert_eq!(error, ProviderCredentialWireError::ForeignRegistry);
        assert!(!format!("{error:?} {error}").contains("secret-marker"));

        let shared_destination = ProviderOutputRegistry::activate(BTreeMap::from([
            (
                "first".to_string(),
                ProviderOutputPlan::CustomHeader {
                    header: HeaderName::from_static("x-conflict"),
                    required: false,
                },
            ),
            (
                "second".to_string(),
                ProviderOutputPlan::CustomHeader {
                    header: HeaderName::from_static("x-conflict"),
                    required: false,
                },
            ),
        ]));
        let ProviderDecision::Allow { credentials, .. } = assigned_result(
            r#"{"id":"request-1","type":"response","decision":"allow","values":{"first":"secret-one"}}"#,
            &shared_destination,
            false,
        )
        .unwrap()
        else {
            panic!("expected allow");
        };
        let material = shared_destination
            .compact_provider_credential_wire(&credentials, &staging_guard())
            .unwrap();
        let first_output = shared_destination.index("first").unwrap();
        let second_output = shared_destination.index("second").unwrap();
        let mut first_bytes = [0; 10];
        material
            .copy_output(first_output, &mut first_bytes)
            .unwrap();
        assert_eq!(&first_bytes, b"secret-one");
        assert_eq!(material.output_len(second_output), None);
        assert_eq!(
            material.copy_output(second_output, &mut []),
            Err(ProviderCredentialWireError::OutputUnavailable)
        );
        assert_eq!(
            material.copy_output(first.index("token").unwrap(), &mut []),
            Err(ProviderCredentialWireError::ForeignRegistry)
        );
        assert!(!format!("{material:?}").contains("secret-one"));
    }

    #[test]
    fn assigned_shape_rejects_v2_fields_and_duplicate_non_id_fields() {
        let outputs = outputs(false);
        assert!(matches!(
            assigned_result(
                r#"{"id":"request-1","type":"response","decision":"deny","denyMessage":"no"}"#,
                &outputs,
                false,
            ),
            Err(AssignedResponseError::InvalidShape)
        ));
        assert!(matches!(
            assigned_result(
                r#"{"id":"request-1","type":"response","decision":"deny","decision":"pass"}"#,
                &outputs,
                false,
            ),
            Err(AssignedResponseError::DuplicateField)
        ));
    }

    #[test]
    fn duplicate_id_and_unusable_or_unsolicited_ids_are_unassignable() {
        let outputs = outputs(false);
        for (line, expected) in [
            (
                r#"{"id":"request-1","id":"request-1","type":"response","decision":"deny"}"#,
                UnassignableResponseError::DuplicateId,
            ),
            (
                r#"{"id":7,"type":"response","decision":"deny"}"#,
                UnassignableResponseError::InvalidId,
            ),
            (
                r#"{"id":"other","type":"response","decision":"deny"}"#,
                UnassignableResponseError::UnsolicitedId,
            ),
        ] {
            assert!(matches!(
                parse_response(line, &outputs, BodyReplacementAdmission::Denied, |id| id == "request-1"),
                ResponseClassification::Unassignable(error) if error == expected
            ));
        }
    }

    #[test]
    fn duplicate_unknown_and_missing_required_outputs_are_rejected() {
        let outputs = outputs(true);
        assert!(matches!(
            assigned_result(
                r#"{"id":"request-1","type":"response","decision":"allow","values":{"token":"a","token":"b"}}"#,
                &outputs,
                false,
            ),
            Err(AssignedResponseError::DuplicateOutput)
        ));
        assert!(matches!(
            assigned_result(
                r#"{"id":"request-1","type":"response","decision":"allow","values":{"other":"a"}}"#,
                &outputs,
                false,
            ),
            Err(AssignedResponseError::UnknownOutput)
        ));
        assert!(matches!(
            assigned_result(
                r#"{"id":"request-1","type":"response","decision":"allow"}"#,
                &outputs,
                false,
            ),
            Err(AssignedResponseError::MissingRequiredOutput)
        ));
    }

    #[test]
    fn body_replacement_requires_gate_and_strict_bounded_base64() {
        let outputs = outputs(false);
        let response = r#"{"id":"request-1","type":"response","decision":"allow","requestBody":{"encoding":"base64","contentType":"application/json","data":"e30="}}"#;
        assert!(matches!(
            assigned_result(response, &outputs, false),
            Err(AssignedResponseError::BodyNotAllowed)
        ));
        let ProviderDecision::Allow {
            replacement: Some(replacement),
            ..
        } = assigned_result(response, &outputs, true).unwrap()
        else {
            panic!("expected replacement");
        };
        assert_eq!(
            replacement
                .decoded_segments()
                .unwrap()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
            b"{}"
        );
        assert_eq!(replacement.content_type(), Some("application/json"));
        assert!(!format!("{replacement:?}").contains("{}"));

        assert!(matches!(
            assigned_result(
                r#"{"id":"request-1","type":"response","decision":"allow","requestBody":{"encoding":"base64","data":"%%%"}}"#,
                &outputs,
                true,
            ),
            Err(AssignedResponseError::InvalidBody)
        ));
    }

    #[test]
    fn nested_body_duplicates_and_noncanonical_metadata_are_rejected() {
        let outputs = outputs(false);
        for body in [
            r#"{"encoding":"base64","encoding":"base64","data":"eA=="}"#,
            r#"{"encoding":"base64","contentType":"text/plain","contentType":"text/plain","data":"eA=="}"#,
            r#"{"encoding":"base64","contentEncoding":"gzip","contentEncoding":"gzip","data":"eA=="}"#,
            r#"{"encoding":"base64","data":"eA==","data":"eA=="}"#,
            r#"{"encoding":"base64","contentType":"text/plain\n","data":"eA=="}"#,
            r#"{"encoding":"base64","contentEncoding":"GZIP","data":"eA=="}"#,
            r#"{"encoding":"base64","contentEncoding":"gzip\n","data":"eA=="}"#,
        ] {
            let line = format!(
                r#"{{"id":"request-1","type":"response","decision":"allow","requestBody":{body}}}"#
            );
            assert!(matches!(
                assigned_result(&line, &outputs, true),
                Err(AssignedResponseError::InvalidBody)
            ));
        }
    }

    #[test]
    fn pass_and_deny_reject_values_and_body_effects() {
        let outputs = outputs(false);
        for decision in ["pass", "deny"] {
            for effect in [
                r#","values":{"token":"secret"}"#,
                r#","requestBody":{"encoding":"base64","data":"eA=="}"#,
            ] {
                let line = format!(
                    r#"{{"id":"request-1","type":"response","decision":"{decision}"{effect}}}"#
                );
                assert!(matches!(
                    assigned_result(&line, &outputs, true),
                    Err(AssignedResponseError::InvalidShape)
                ));
            }
        }
    }

    #[test]
    fn invalid_base64_releases_guard_charge() {
        let outputs = outputs(false);
        let peak = crate::safety::wire_body::guarded_body_allocation_bytes(64).unwrap();
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(
            peak,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );
        let classification = parse_response(
            r#"{"id":"request-1","type":"response","decision":"allow","requestBody":{"encoding":"base64","data":"eA==%%%"}}"#,
            &outputs,
            BodyReplacementAdmission::Allowed {
                guard: &guard,
                max_decoded_bytes: 64,
            },
            |id| id == "request-1",
        );
        assert!(matches!(
            classification,
            ResponseClassification::Assigned {
                result: Err(AssignedResponseError::InvalidBody),
                ..
            }
        ));
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn malformed_json_is_unassignable() {
        assert!(matches!(
            parse_response(
                "{",
                &outputs(false),
                BodyReplacementAdmission::Denied,
                |_| true,
            ),
            ResponseClassification::Unassignable(UnassignableResponseError::MalformedJson)
        ));
    }
}
