use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
#[cfg(test)]
use std::io::Read;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
#[cfg(test)]
use base64::read::DecoderReader;
use http::{HeaderName, HeaderValue};
#[cfg(test)]
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
#[cfg(test)]
use serde::{Deserialize, Deserializer};
use serde::{Serialize, Serializer};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use zeroize::Zeroize;

use crate::config::v3_compile::ProviderOutputPlan;
use crate::safety::{GuardedBody, HttpWireBodyGuard};

#[cfg(test)]
const MAX_PROVIDER_CREDENTIAL_BYTES: usize = 64 * 1024;
#[cfg(test)]
const PROVIDER_STREAM_SCRATCH_BYTES: usize = 64 * 1024;
static NEXT_OUTPUT_REGISTRY_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProviderOutputIndex {
    registry_id: u64,
    ordinal: usize,
}

impl ProviderOutputIndex {
    pub(crate) fn get(self) -> usize {
        self.ordinal
    }
}

pub(crate) enum ProviderOutputDefinition {
    Bearer { required: bool },
    Basic { username: String, required: bool },
    CustomHeader { header: HeaderName, required: bool },
}

impl ProviderOutputDefinition {
    fn required(&self) -> bool {
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

    pub(crate) fn definition(
        &self,
        index: ProviderOutputIndex,
    ) -> Option<&ProviderOutputDefinition> {
        (index.registry_id == self.id)
            .then(|| self.definitions.get(index.get()))
            .flatten()
    }
}

impl fmt::Debug for ProviderOutputRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderOutputRegistry")
            .field("count", &self.definitions.len())
            .finish()
    }
}

pub(crate) struct ProviderCredentialSet {
    registry_id: u64,
    values: Box<[Option<SecretBytes>]>,
}

impl ProviderCredentialSet {
    pub(crate) fn get(&self, index: ProviderOutputIndex) -> Option<&[u8]> {
        if index.registry_id != self.registry_id {
            return None;
        }
        self.values
            .get(index.get())
            .and_then(Option::as_ref)
            .map(SecretBytes::as_bytes)
    }
}

impl fmt::Debug for ProviderCredentialSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCredentialSet")
            .field("count", &self.values.len())
            .field(
                "present_count",
                &self.values.iter().filter(|value| value.is_some()).count(),
            )
            .finish()
    }
}

pub(crate) struct ProviderBodyReplacement {
    content_type: Option<String>,
    content_encoding: Option<String>,
    bytes: GuardedBody,
}

impl ProviderBodyReplacement {
    pub(crate) fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    pub(crate) fn content_encoding(&self) -> Option<&str> {
        self.content_encoding.as_deref()
    }

    pub(crate) fn segments(&self) -> impl Iterator<Item = &[u8]> {
        self.bytes.segments()
    }
}

impl fmt::Debug for ProviderBodyReplacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderBodyReplacement")
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

pub(crate) enum ProviderDecision {
    Allow {
        credentials: ProviderCredentialSet,
        replacement: Option<ProviderBodyReplacement>,
    },
    Deny,
    Pass,
}

pub(crate) enum ResponseClassification {
    Assigned {
        id: String,
        result: Result<ProviderDecision, AssignedResponseError>,
    },
    Unassignable(UnassignableResponseError),
}

pub(crate) enum BodyReplacementAdmission<'a> {
    Denied,
    Allowed {
        guard: &'a HttpWireBodyGuard,
        max_decoded_bytes: usize,
    },
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
}

pub(crate) struct ProviderRequestHeaders<'a> {
    fields: &'a [IncludedHeader<'a>],
}

impl<'a> ProviderRequestHeaders<'a> {
    pub(crate) fn new(fields: &'a [IncludedHeader<'a>]) -> Result<Self, RequestShapeError> {
        let mut names = BTreeSet::new();
        for field in fields {
            if field.values.is_empty()
                || !names.insert(field.name.as_str())
                || field.values.iter().any(|value| value.to_str().is_err())
            {
                return Err(RequestShapeError::InvalidHeaders);
            }
        }
        Ok(Self { fields })
    }

    fn is_empty(&self) -> bool {
        self.fields.is_empty()
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
    pub(crate) id: &'a str,
    pub(crate) url: &'a str,
    pub(crate) method: &'a str,
    pub(crate) client_ip: &'a str,
    pub(crate) headers: Option<&'a ProviderRequestHeaders<'a>>,
    pub(crate) body: Option<GuardedProviderBody<'a>>,
}

impl ProviderRequest<'_> {
    pub(crate) fn write_compact(&self, mut writer: impl Write) -> Result<(), RequestShapeError> {
        self.prevalidate()?;

        writer.write_all(b"{\"id\":")?;
        write_json_string(&mut writer, self.id)?;
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
        writer.write_all(b"}")?;
        Ok(())
    }

    fn prevalidate(&self) -> Result<(), RequestShapeError> {
        if let Some(headers) = self.headers {
            ProviderRequestHeaders::new(headers.fields)?;
        }
        if let Some(body) = &self.body {
            validate_content_metadata(body.content_type, body.content_encoding)
                .map_err(|_| RequestShapeError::InvalidBodyMetadata)?;
        }
        Ok(())
    }
}

fn write_json_string(writer: impl Write, value: &str) -> Result<(), RequestShapeError> {
    serde_json::to_writer(writer, value).map_err(|_| RequestShapeError::Serialization)
}

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
    InvalidHeaders,
    InvalidBodyMetadata,
    Serialization,
}

impl From<std::io::Error> for RequestShapeError {
    fn from(_: std::io::Error) -> Self {
        Self::Serialization
    }
}

const MAX_RESPONSE_ID_PREFIX_BYTES: usize = 4096;

pub(crate) struct ProviderResponseContinuation {
    id: String,
    consumed_bytes: usize,
    max_line_bytes: usize,
}

impl ProviderResponseContinuation {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

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

/// Reads only the first `id` member and the following comma. The supervisor
/// must match that ID to a pending request and supply its body guard before any
/// continuation bytes are consumed.
pub(crate) async fn read_provider_response_prefix<R>(
    reader: &mut R,
    max_line_bytes: usize,
) -> Result<Option<ProviderResponseContinuation>, ResponsePrefixError>
where
    R: AsyncBufRead + Unpin,
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

    let mut id = [0u8; MAX_RESPONSE_ID_PREFIX_BYTES];
    let mut id_len = 0usize;
    loop {
        let byte = read_prefix_byte(reader, &mut consumed, prefix_limit)
            .await?
            .ok_or(ResponsePrefixError::Invalid)?;
        match byte {
            b'\"' if id_len != 0 => break,
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
    expect_prefix_byte(reader, &mut consumed, prefix_limit, b',').await?;
    let parsed_id = std::str::from_utf8(&id[..id_len])
        .map_err(|_| ResponsePrefixError::Invalid)?
        .to_owned();
    id[..id_len].zeroize();
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
    R: AsyncBufRead + Unpin,
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
    R: AsyncBufRead + Unpin,
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
    R: AsyncBufRead + Unpin,
{
    if *consumed == limit {
        return Err(ResponsePrefixError::TooLong);
    }
    let available = reader.fill_buf().await.map_err(ResponsePrefixError::Io)?;
    let Some(byte) = available.first().copied() else {
        return Ok(None);
    };
    if byte == b'\n' || byte == b'\r' {
        return Err(ResponsePrefixError::Invalid);
    }
    reader.consume(1);
    *consumed += 1;
    Ok(Some(byte))
}

// Schema reference only. Production response handling stops at the guarded
// continuation state above and must not materialize a full stdout line.
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
    Ok(ProviderCredentialSet {
        registry_id: outputs.id,
        values: bound.into_boxed_slice(),
    })
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
        let mut decoded = guard.buffer();
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
            bytes: decoded.finish(),
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
    matches!(value, "identity" | "gzip" | "deflate" | "br" | "zstd")
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

struct SecretBytes(Vec<u8>);

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

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use http::header::CONTENT_TYPE;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

    use crate::safety::{WireBodyPool, WireBodyQuotaKey};

    fn outputs(required: bool) -> ProviderOutputRegistry {
        ProviderOutputRegistry::activate(BTreeMap::from([(
            "token".to_string(),
            ProviderOutputPlan::Bearer { required },
        )]))
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
            id: "request-1",
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
        request.write_compact(&mut serialized).unwrap();
        assert_eq!(
            String::from_utf8(serialized).unwrap(),
            r#"{"id":"request-1","type":"request","url":"https://example.test/path","method":"GET","clientIp":"127.0.0.1","headers":{"content-type":["first","second"]},"body":{"encoding":"base64","contentType":"application/json","contentEncoding":"identity","data":"e30="}}"#
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
            id: "request-1",
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
        request.write_compact(&mut serialized).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(
            json["body"]["data"],
            BASE64_STANDARD.encode(body_bytes.as_slice())
        );
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
                id: "request-1",
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
                request.write_compact(&mut output),
                Err(RequestShapeError::InvalidBodyMetadata)
            );
            assert!(output.is_empty());
        }
    }

    #[test]
    fn non_utf8_included_header_fails_before_any_writer_byte() {
        let invalid = HeaderValue::from_bytes(&[0x80]).unwrap();
        let values = [invalid];
        let fields = [IncludedHeader::new(&CONTENT_TYPE, &values)];
        assert!(matches!(
            ProviderRequestHeaders::new(&fields),
            Err(RequestShapeError::InvalidHeaders)
        ));
        let headers = ProviderRequestHeaders { fields: &fields };
        let request = ProviderRequest {
            id: "request-1",
            url: "https://example.test/",
            method: "GET",
            client_ip: "127.0.0.1",
            headers: Some(&headers),
            body: None,
        };
        let mut output = Vec::new();
        assert_eq!(
            request.write_compact(&mut output),
            Err(RequestShapeError::InvalidHeaders)
        );
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
        let mut reader = BufReader::new(reader);
        let Some(prefix) = read_provider_response_prefix(&mut reader, 256)
            .await
            .unwrap()
        else {
            panic!("expected prefix");
        };
        assert_eq!(prefix.id(), "request-1");
        assert!(prefix.remaining_line_bytes() < 256);
        let mut remaining = Vec::new();
        reader.read_to_end(&mut remaining).await.unwrap();
        assert_eq!(remaining, b"\"type\":\"response\",\"decision\":\"deny\"}\n");
    }

    #[tokio::test]
    async fn prefix_reader_rejects_missing_first_id_unterminated_and_overlimit() {
        for bytes in [
            b"{\"type\":\"response\",\"id\":\"request-1\",\"decision\":\"deny\"}\n".as_slice(),
            b"{\"id\":\"request-1\"".as_slice(),
        ] {
            let mut reader = BufReader::new(bytes);
            assert!(matches!(
                read_provider_response_prefix(&mut reader, 256).await,
                Err(ResponsePrefixError::Invalid)
            ));
        }
        let mut reader =
            BufReader::new(b"{\"id\":\"request-1\",\"type\":\"response\"}\n".as_slice());
        assert!(matches!(
            read_provider_response_prefix(&mut reader, 8).await,
            Err(ResponsePrefixError::TooLong)
        ));
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
        assert_eq!(credentials.get(index), Some(b"secret-marker".as_slice()));
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
            credentials.get(first_index),
            Some(b"secret-marker".as_slice())
        );
        assert_eq!(credentials.get(second_index), None);
        assert!(first.definition(second_index).is_none());
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
                .segments()
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
