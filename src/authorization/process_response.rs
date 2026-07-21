use std::fmt;

use tokio::io::{AsyncRead, AsyncReadExt};

use super::process_effects::{
    AssignedProcessEffectsParser, AssignedTailSyntax, ProcessEffectsParseError,
};
use super::protocol::{
    AssignedResponseError, DirectProviderStdout, ProviderDecision, ProviderOutputRegistry,
    ProviderResponseContinuation,
};
use crate::config::compiler::ProcessProviderPlan;
use crate::runtime::AuthorizationInvocationMode;
use crate::safety::wire_body::{GuardedBodySegments, WireBodyBufferError};
#[cfg(test)]
use crate::safety::HttpWireBodyGuard;
use crate::safety::{GuardedBody, ProviderResponseCharge};

const MAX_JSON_DEPTH: usize = 128;
const MAX_JSON_KEY_BYTES: usize = 32;
const MAX_SCALAR_BYTES: usize = 16;

/// Proof that a provider cannot return outputs or a request-body replacement.
/// The process supervisor must obtain this during provider activation before it
/// can use the decision-only response parser.
pub(super) struct DecisionOnlyResponseSchema {
    _private: (),
}

pub(super) enum ProcessResponseSchema {
    DecisionOnly(DecisionOnlyResponseSchema),
    Expanded {
        outputs: ProviderOutputRegistry,
        max_decoded_replacement_bytes: Option<usize>,
    },
}

impl ProcessResponseSchema {
    pub(super) fn activate(plan: &ProcessProviderPlan) -> Self {
        match DecisionOnlyResponseSchema::activate(plan) {
            Some(schema) => Self::DecisionOnly(schema),
            None => Self::Expanded {
                outputs: ProviderOutputRegistry::activate(plan.outputs.clone()),
                max_decoded_replacement_bytes: plan
                    .allow_request_body_replacement
                    .then_some(plan.max_decoded_request_body_bytes),
            },
        }
    }

    pub(super) fn outputs(&self) -> Option<&ProviderOutputRegistry> {
        match self {
            Self::DecisionOnly(_) => None,
            Self::Expanded { outputs, .. } => Some(outputs),
        }
    }
}

impl DecisionOnlyResponseSchema {
    pub(super) fn activate(plan: &ProcessProviderPlan) -> Option<Self> {
        (plan.outputs.is_empty() && !plan.allow_request_body_replacement)
            .then_some(Self { _private: () })
    }

    fn for_invocation() -> Self {
        Self { _private: () }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DecisionOnlyProviderDecision {
    Allow,
    Deny,
    Pass,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DecisionOnlyResponse {
    Decision(DecisionOnlyProviderDecision),
    AssignedFailure(AssignedResponseError),
}

pub(super) enum ProcessResponse {
    DecisionOnly(DecisionOnlyProviderDecision),
    Expanded(ProviderDecision),
    AssignedFailure,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum FatalProcessResponseError {
    #[error("process-provider stdout read failed")]
    Io(#[source] std::io::Error),
    #[error("process-provider stdout response did not end in LF")]
    Unterminated,
    #[error("process-provider stdout response exceeded its line bound")]
    TooLong,
    #[error("process-provider stdout response could not be admitted")]
    Admission(#[source] WireBodyBufferError),
    #[error("process-provider stdout response is malformed JSON")]
    MalformedJson,
    #[error("process-provider stdout response contains invalid UTF-8")]
    InvalidUtf8,
    #[error("process-provider stdout response repeats its ID")]
    DuplicateId,
}

/// Completes one already-assigned response. The prefix is consumed by value so
/// no caller can reuse its line budget for another read.
pub(super) async fn read_decision_only_response(
    reader: &mut DirectProviderStdout,
    continuation: ProviderResponseContinuation,
    guard: &ProviderResponseCharge,
    _schema: &DecisionOnlyResponseSchema,
) -> Result<DecisionOnlyResponse, FatalProcessResponseError> {
    read_decision_only_response_from(reader, continuation, guard).await
}

pub(super) async fn read_process_response(
    reader: &mut DirectProviderStdout,
    continuation: ProviderResponseContinuation,
    guard: &ProviderResponseCharge,
    schema: &ProcessResponseSchema,
    invocation_mode: AuthorizationInvocationMode,
) -> Result<ProcessResponse, FatalProcessResponseError> {
    if invocation_mode == AuthorizationInvocationMode::DecisionOnly {
        return match read_decision_only_response(
            reader,
            continuation,
            guard,
            &DecisionOnlyResponseSchema::for_invocation(),
        )
        .await?
        {
            DecisionOnlyResponse::Decision(decision) => Ok(ProcessResponse::DecisionOnly(decision)),
            DecisionOnlyResponse::AssignedFailure(_) => Ok(ProcessResponse::AssignedFailure),
        };
    }
    match schema {
        ProcessResponseSchema::DecisionOnly(schema) => {
            match read_decision_only_response(reader, continuation, guard, schema).await? {
                DecisionOnlyResponse::Decision(decision) => {
                    Ok(ProcessResponse::DecisionOnly(decision))
                }
                DecisionOnlyResponse::AssignedFailure(_) => Ok(ProcessResponse::AssignedFailure),
            }
        }
        ProcessResponseSchema::Expanded {
            outputs,
            max_decoded_replacement_bytes,
        } => {
            read_expanded_response(
                reader,
                continuation,
                guard,
                outputs,
                *max_decoded_replacement_bytes,
            )
            .await
        }
    }
}

async fn read_expanded_response<R>(
    reader: &mut R,
    continuation: ProviderResponseContinuation,
    guard: &ProviderResponseCharge,
    outputs: &ProviderOutputRegistry,
    max_decoded_replacement_bytes: Option<usize>,
) -> Result<ProcessResponse, FatalProcessResponseError>
where
    R: AsyncRead + Unpin,
{
    let mut remaining = continuation.remaining_line_bytes();
    let mut parser = Some(AssignedProcessEffectsParser::new(
        outputs,
        max_decoded_replacement_bytes,
        guard,
    ));
    let mut assigned_error = None;
    let mut syntax = AssignedTailSyntax::new();
    let mut pending_cr = false;
    loop {
        if remaining == 0 {
            return Err(FatalProcessResponseError::TooLong);
        }
        let mut byte = [0u8; 1];
        let read = reader
            .read(&mut byte)
            .await
            .map_err(FatalProcessResponseError::Io)?;
        if read == 0 {
            return Err(FatalProcessResponseError::Unterminated);
        }
        remaining -= 1;
        if byte[0] == b'\n' {
            if syntax.duplicate_id() {
                return Err(FatalProcessResponseError::DuplicateId);
            }
            syntax
                .finish()
                .map_err(|_| FatalProcessResponseError::MalformedJson)?;
            if assigned_error.is_some() {
                return Ok(ProcessResponse::AssignedFailure);
            }
            return match parser
                .take()
                .expect("a semantic parser exists without an assigned error")
                .finish()
            {
                Ok(decision) => Ok(ProcessResponse::Expanded(decision)),
                Err(ProcessEffectsParseError::Assigned(_))
                | Err(ProcessEffectsParseError::Malformed) => Ok(ProcessResponse::AssignedFailure),
                Err(ProcessEffectsParseError::DuplicateId) => {
                    Err(FatalProcessResponseError::DuplicateId)
                }
                Err(ProcessEffectsParseError::Admission(error)) => {
                    Err(FatalProcessResponseError::Admission(error))
                }
            };
        }
        if remaining == 0 {
            return Err(FatalProcessResponseError::TooLong);
        }
        if pending_cr {
            push_expanded_byte(b'\r', &mut syntax, &mut parser, &mut assigned_error)?;
            pending_cr = false;
        }
        if byte[0] == b'\r' {
            pending_cr = true;
        } else {
            push_expanded_byte(byte[0], &mut syntax, &mut parser, &mut assigned_error)?;
        }
    }
}

fn push_expanded_byte(
    byte: u8,
    syntax: &mut AssignedTailSyntax,
    parser: &mut Option<AssignedProcessEffectsParser<'_>>,
    assigned_error: &mut Option<AssignedResponseError>,
) -> Result<(), FatalProcessResponseError> {
    syntax
        .push(byte)
        .map_err(|_| FatalProcessResponseError::MalformedJson)?;
    let Some(active) = parser.as_mut() else {
        return Ok(());
    };
    match active.push(byte) {
        Ok(()) => Ok(()),
        Err(ProcessEffectsParseError::Assigned(error)) => {
            *assigned_error = Some(error);
            parser.take();
            Ok(())
        }
        Err(ProcessEffectsParseError::Malformed) => {
            *assigned_error = Some(AssignedResponseError::InvalidShape);
            parser.take();
            Ok(())
        }
        Err(ProcessEffectsParseError::DuplicateId) => Err(FatalProcessResponseError::DuplicateId),
        Err(ProcessEffectsParseError::Admission(error)) => {
            Err(FatalProcessResponseError::Admission(error))
        }
    }
}

#[cfg(test)]
async fn read_decision_only_response_for_test<R>(
    reader: &mut R,
    continuation: ProviderResponseContinuation,
    guard: &HttpWireBodyGuard,
    _schema: &DecisionOnlyResponseSchema,
) -> Result<DecisionOnlyResponse, FatalProcessResponseError>
where
    R: AsyncRead + Unpin,
{
    let response_charge = guard.provider_response_charge();
    read_decision_only_response_from(reader, continuation, &response_charge).await
}

async fn read_decision_only_response_from<R>(
    reader: &mut R,
    continuation: ProviderResponseContinuation,
    guard: &ProviderResponseCharge,
) -> Result<DecisionOnlyResponse, FatalProcessResponseError>
where
    R: AsyncRead + Unpin,
{
    let line = read_guarded_suffix(reader, continuation, guard).await?;
    parse_decision_only(line)
}

struct GuardedResponseLine(GuardedBody);

async fn read_guarded_suffix<R>(
    reader: &mut R,
    continuation: ProviderResponseContinuation,
    guard: &ProviderResponseCharge,
) -> Result<GuardedResponseLine, FatalProcessResponseError>
where
    R: AsyncRead + Unpin,
{
    let mut remaining = continuation.remaining_line_bytes();
    let mut builder = guard.buffer();
    let mut pending_cr = false;

    loop {
        if remaining == 0 {
            return Err(FatalProcessResponseError::TooLong);
        }
        let mut byte = [0u8; 1];
        let read = reader
            .read(&mut byte)
            .await
            .map_err(FatalProcessResponseError::Io)?;
        if read == 0 {
            return Err(FatalProcessResponseError::Unterminated);
        }
        remaining -= 1;
        if byte[0] == b'\n' {
            // A pending CR is the optional CRLF delimiter and is deliberately
            // not copied into the guarded JSON bytes.
            return Ok(GuardedResponseLine(builder.finish()));
        }
        if remaining == 0 {
            return Err(FatalProcessResponseError::TooLong);
        }
        if pending_cr {
            append_byte(&mut builder, b'\r')?;
            pending_cr = false;
        }
        if byte[0] == b'\r' {
            pending_cr = true;
        } else {
            append_byte(&mut builder, byte[0])?;
        }
    }
}

fn append_byte(
    builder: &mut crate::safety::wire_body::GuardedBodyBuilder,
    byte: u8,
) -> Result<(), FatalProcessResponseError> {
    builder
        .try_extend_from_slice(std::slice::from_ref(&byte))
        .map_err(FatalProcessResponseError::Admission)
}

fn parse_decision_only(
    line: GuardedResponseLine,
) -> Result<DecisionOnlyResponse, FatalProcessResponseError> {
    let mut cursor = SegmentCursor::new(&line.0);
    let mut seen_type = false;
    let mut seen_decision = false;
    let mut seen_values = false;
    let mut seen_body = false;
    let mut duplicate_id = false;
    let mut duplicate = false;
    let mut invalid_shape = false;
    let mut message_type = None;
    let mut decision = None;

    match cursor.next_structural() {
        Some(b'}') if cursor.peek_structural().is_none() => {
            return Ok(DecisionOnlyResponse::AssignedFailure(
                AssignedResponseError::InvalidShape,
            ));
        }
        Some(b',') => {}
        _ => return Err(FatalProcessResponseError::MalformedJson),
    }

    loop {
        cursor.skip_whitespace();
        let key = parse_json_string::<MAX_JSON_KEY_BYTES>(&mut cursor).map_err(fatal)?;
        expect_structural_byte(&mut cursor, b':').map_err(fatal)?;
        match key.as_bytes() {
            Some(b"id") => {
                duplicate_id = true;
                skip_json_value(&mut cursor, 1).map_err(fatal)?;
            }
            Some(b"type") => {
                duplicate |= std::mem::replace(&mut seen_type, true);
                message_type = parse_scalar_string(&mut cursor)?;
                invalid_shape |= message_type.is_none();
            }
            Some(b"decision") => {
                duplicate |= std::mem::replace(&mut seen_decision, true);
                decision = parse_scalar_string(&mut cursor)?;
                invalid_shape |= decision.is_none();
            }
            Some(b"values") => {
                duplicate |= std::mem::replace(&mut seen_values, true);
                invalid_shape = true;
                skip_json_value(&mut cursor, 1).map_err(fatal)?;
            }
            Some(b"requestBody") => {
                duplicate |= std::mem::replace(&mut seen_body, true);
                invalid_shape = true;
                skip_json_value(&mut cursor, 1).map_err(fatal)?;
            }
            _ => {
                invalid_shape = true;
                skip_json_value(&mut cursor, 1).map_err(fatal)?;
            }
        }

        match cursor.next_structural() {
            Some(b',') => {}
            Some(b'}') => break,
            _ => return Err(FatalProcessResponseError::MalformedJson),
        }
    }

    if cursor.peek_structural().is_some() {
        return Err(FatalProcessResponseError::MalformedJson);
    }
    if duplicate_id {
        return Err(FatalProcessResponseError::DuplicateId);
    }
    if duplicate {
        return Ok(DecisionOnlyResponse::AssignedFailure(
            AssignedResponseError::DuplicateField,
        ));
    }
    if invalid_shape
        || !seen_type
        || !seen_decision
        || message_type.as_ref().and_then(ParsedString::as_bytes) != Some(b"response")
    {
        return Ok(DecisionOnlyResponse::AssignedFailure(
            AssignedResponseError::InvalidShape,
        ));
    }
    let decision = match decision.as_ref().and_then(ParsedString::as_bytes) {
        Some(b"allow") => DecisionOnlyProviderDecision::Allow,
        Some(b"deny") => DecisionOnlyProviderDecision::Deny,
        Some(b"pass") => DecisionOnlyProviderDecision::Pass,
        _ => {
            return Ok(DecisionOnlyResponse::AssignedFailure(
                AssignedResponseError::InvalidShape,
            ))
        }
    };
    Ok(DecisionOnlyResponse::Decision(decision))
}

fn parse_scalar_string(
    cursor: &mut SegmentCursor<'_>,
) -> Result<Option<ParsedString<MAX_SCALAR_BYTES>>, FatalProcessResponseError> {
    cursor.skip_whitespace();
    if cursor.peek() == Some(b'"') {
        Ok(Some(
            parse_json_string::<MAX_SCALAR_BYTES>(cursor).map_err(fatal)?,
        ))
    } else {
        skip_json_value(cursor, 1).map_err(fatal)?;
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JsonError {
    Malformed,
    InvalidUtf8,
}

fn fatal(error: JsonError) -> FatalProcessResponseError {
    match error {
        JsonError::Malformed => FatalProcessResponseError::MalformedJson,
        JsonError::InvalidUtf8 => FatalProcessResponseError::InvalidUtf8,
    }
}

fn expect_byte(cursor: &mut SegmentCursor<'_>, expected: u8) -> Result<(), JsonError> {
    (cursor.next() == Some(expected))
        .then_some(())
        .ok_or(JsonError::Malformed)
}

fn expect_structural_byte(cursor: &mut SegmentCursor<'_>, expected: u8) -> Result<(), JsonError> {
    (cursor.next_structural() == Some(expected))
        .then_some(())
        .ok_or(JsonError::Malformed)
}

fn skip_json_value(cursor: &mut SegmentCursor<'_>, depth: usize) -> Result<(), JsonError> {
    cursor.skip_whitespace();
    match cursor.peek() {
        Some(b'"') => {
            parse_json_string::<0>(cursor)?;
            Ok(())
        }
        Some(b'{') => skip_json_object(cursor, enter_json_container(depth)?),
        Some(b'[') => skip_json_array(cursor, enter_json_container(depth)?),
        Some(b't') => consume_literal(cursor, b"true"),
        Some(b'f') => consume_literal(cursor, b"false"),
        Some(b'n') => consume_literal(cursor, b"null"),
        Some(b'-' | b'0'..=b'9') => skip_json_number(cursor),
        _ => Err(JsonError::Malformed),
    }
}

fn enter_json_container(depth: usize) -> Result<usize, JsonError> {
    let depth = depth.checked_add(1).ok_or(JsonError::Malformed)?;
    (depth < MAX_JSON_DEPTH)
        .then_some(depth)
        .ok_or(JsonError::Malformed)
}

fn skip_json_object(cursor: &mut SegmentCursor<'_>, depth: usize) -> Result<(), JsonError> {
    expect_structural_byte(cursor, b'{')?;
    if cursor.peek_structural() == Some(b'}') {
        cursor.next_structural();
        return Ok(());
    }
    loop {
        cursor.skip_whitespace();
        parse_json_string::<0>(cursor)?;
        expect_structural_byte(cursor, b':')?;
        skip_json_value(cursor, depth)?;
        match cursor.next_structural() {
            Some(b',') => {}
            Some(b'}') => return Ok(()),
            _ => return Err(JsonError::Malformed),
        }
    }
}

fn skip_json_array(cursor: &mut SegmentCursor<'_>, depth: usize) -> Result<(), JsonError> {
    expect_structural_byte(cursor, b'[')?;
    if cursor.peek_structural() == Some(b']') {
        cursor.next_structural();
        return Ok(());
    }
    loop {
        skip_json_value(cursor, depth)?;
        match cursor.next_structural() {
            Some(b',') => {}
            Some(b']') => return Ok(()),
            _ => return Err(JsonError::Malformed),
        }
    }
}

fn consume_literal(cursor: &mut SegmentCursor<'_>, literal: &[u8]) -> Result<(), JsonError> {
    for expected in literal {
        expect_byte(cursor, *expected)?;
    }
    Ok(())
}

fn skip_json_number(cursor: &mut SegmentCursor<'_>) -> Result<(), JsonError> {
    if cursor.peek() == Some(b'-') {
        cursor.next();
    }
    match cursor.next() {
        Some(b'0') => {}
        Some(b'1'..=b'9') => {
            while matches!(cursor.peek(), Some(b'0'..=b'9')) {
                cursor.next();
            }
        }
        _ => return Err(JsonError::Malformed),
    }
    if cursor.peek() == Some(b'.') {
        cursor.next();
        consume_digits(cursor)?;
    }
    if matches!(cursor.peek(), Some(b'e' | b'E')) {
        cursor.next();
        if matches!(cursor.peek(), Some(b'+' | b'-')) {
            cursor.next();
        }
        consume_digits(cursor)?;
    }
    Ok(())
}

fn consume_digits(cursor: &mut SegmentCursor<'_>) -> Result<(), JsonError> {
    if !matches!(cursor.peek(), Some(b'0'..=b'9')) {
        return Err(JsonError::Malformed);
    }
    while matches!(cursor.peek(), Some(b'0'..=b'9')) {
        cursor.next();
    }
    Ok(())
}

struct ParsedString<const N: usize> {
    bytes: [u8; N],
    len: usize,
    overflow: bool,
}

impl<const N: usize> ParsedString<N> {
    fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
            overflow: false,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        if !self.overflow
            && self
                .len
                .checked_add(bytes.len())
                .is_some_and(|end| end <= N)
        {
            let end = self.len + bytes.len();
            self.bytes[self.len..end].copy_from_slice(bytes);
            self.len = end;
        } else {
            self.overflow = true;
        }
    }

    fn as_bytes(&self) -> Option<&[u8]> {
        (!self.overflow).then_some(&self.bytes[..self.len])
    }
}

fn parse_json_string<const N: usize>(
    cursor: &mut SegmentCursor<'_>,
) -> Result<ParsedString<N>, JsonError> {
    expect_byte(cursor, b'"')?;
    let mut parsed = ParsedString::new();
    loop {
        let byte = cursor.next().ok_or(JsonError::Malformed)?;
        match byte {
            b'"' => return Ok(parsed),
            b'\\' => parse_json_escape(cursor, &mut parsed)?,
            0..=31 => return Err(JsonError::Malformed),
            32..=127 => parsed.push(&[byte]),
            _ => parse_raw_utf8(cursor, byte, &mut parsed)?,
        }
    }
}

fn parse_json_escape<const N: usize>(
    cursor: &mut SegmentCursor<'_>,
    parsed: &mut ParsedString<N>,
) -> Result<(), JsonError> {
    match cursor.next().ok_or(JsonError::Malformed)? {
        b'"' => parsed.push(b"\""),
        b'\\' => parsed.push(b"\\"),
        b'/' => parsed.push(b"/"),
        b'b' => parsed.push(&[8]),
        b'f' => parsed.push(&[12]),
        b'n' => parsed.push(b"\n"),
        b'r' => parsed.push(b"\r"),
        b't' => parsed.push(b"\t"),
        b'u' => {
            let first = parse_hex_quad(cursor)?;
            let scalar = if (0xd800..=0xdbff).contains(&first) {
                expect_byte(cursor, b'\\')?;
                expect_byte(cursor, b'u')?;
                let second = parse_hex_quad(cursor)?;
                if !(0xdc00..=0xdfff).contains(&second) {
                    return Err(JsonError::Malformed);
                }
                0x1_0000 + (((first as u32 - 0xd800) << 10) | (second as u32 - 0xdc00))
            } else if (0xdc00..=0xdfff).contains(&first) {
                return Err(JsonError::Malformed);
            } else {
                first as u32
            };
            let character = char::from_u32(scalar).ok_or(JsonError::Malformed)?;
            let mut encoded = [0; 4];
            parsed.push(character.encode_utf8(&mut encoded).as_bytes());
        }
        _ => return Err(JsonError::Malformed),
    }
    Ok(())
}

fn parse_hex_quad(cursor: &mut SegmentCursor<'_>) -> Result<u16, JsonError> {
    let mut value = 0u16;
    for _ in 0..4 {
        let digit = match cursor.next().ok_or(JsonError::Malformed)? {
            byte @ b'0'..=b'9' => (byte - b'0') as u16,
            byte @ b'a'..=b'f' => (byte - b'a' + 10) as u16,
            byte @ b'A'..=b'F' => (byte - b'A' + 10) as u16,
            _ => return Err(JsonError::Malformed),
        };
        value = (value << 4) | digit;
    }
    Ok(value)
}

fn parse_raw_utf8<const N: usize>(
    cursor: &mut SegmentCursor<'_>,
    first: u8,
    parsed: &mut ParsedString<N>,
) -> Result<(), JsonError> {
    let width = match first {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return Err(JsonError::InvalidUtf8),
    };
    let mut encoded = [0; 4];
    encoded[0] = first;
    for slot in encoded.iter_mut().take(width).skip(1) {
        *slot = cursor.next().ok_or(JsonError::InvalidUtf8)?;
    }
    std::str::from_utf8(&encoded[..width]).map_err(|_| JsonError::InvalidUtf8)?;
    parsed.push(&encoded[..width]);
    Ok(())
}

struct SegmentCursor<'a> {
    segments: GuardedBodySegments<'a>,
    current: &'a [u8],
    offset: usize,
}

impl<'a> SegmentCursor<'a> {
    fn new(body: &'a GuardedBody) -> Self {
        let mut segments = body.segments();
        let current = segments.next().unwrap_or(&[]);
        Self {
            segments,
            current,
            offset: 0,
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.advance_segment();
        self.current.get(self.offset).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.offset += 1;
        Some(byte)
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.offset += 1;
        }
    }

    fn peek_structural(&mut self) -> Option<u8> {
        self.skip_whitespace();
        self.peek()
    }

    fn next_structural(&mut self) -> Option<u8> {
        self.skip_whitespace();
        self.next()
    }

    fn advance_segment(&mut self) {
        while self.offset == self.current.len() {
            let Some(next) = self.segments.next() else {
                break;
            };
            self.current = next;
            self.offset = 0;
        }
    }
}

impl fmt::Debug for DecisionOnlyResponseSchema {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecisionOnlyResponseSchema")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncRead, ReadBuf};

    use super::*;
    use crate::authorization::protocol::projected_provider_credential_wire_metadata_bytes;
    use crate::authorization::protocol::read_provider_response_prefix_for_test;
    use crate::config::compiler::{
        CompiledProviderFailureMode, ProviderOutputPlan, MAX_PROVIDER_OUTPUT_NAME_BYTES,
    };
    use crate::safety::wire_body::guarded_body_allocation_bytes;
    use crate::safety::{WireBodyPool, WireBodyQuotaKey};

    fn decision_schema() -> DecisionOnlyResponseSchema {
        DecisionOnlyResponseSchema::activate(&process_plan(BTreeMap::new(), false)).unwrap()
    }

    fn process_plan(
        outputs: BTreeMap<String, ProviderOutputPlan>,
        allow_request_body_replacement: bool,
    ) -> ProcessProviderPlan {
        ProcessProviderPlan {
            command: PathBuf::from("/bin/provider"),
            working_directory: PathBuf::from("/"),
            args: Vec::new(),
            timeout: Duration::from_secs(1),
            on_failure: CompiledProviderFailureMode::Deny,
            inherit_environment: false,
            pass_environment: Vec::new(),
            environment: BTreeMap::new(),
            include_headers: Vec::new(),
            include_request_body: false,
            allow_request_body_replacement,
            max_request_body_bytes: 1,
            max_decoded_request_body_bytes: 1,
            max_stdout_line_bytes: 1024,
            max_pending_requests: 1,
            restart_backoff: Duration::from_secs(1),
            retire_timeout: Duration::from_secs(1),
            outputs,
        }
    }

    struct RecordingReader<'bytes> {
        bytes: &'bytes [u8],
        offset: usize,
        requested: Vec<usize>,
    }

    impl<'bytes> RecordingReader<'bytes> {
        fn new(bytes: &'bytes [u8]) -> Self {
            Self {
                bytes,
                offset: 0,
                requested: Vec::new(),
            }
        }

        fn remaining(&self) -> &[u8] {
            &self.bytes[self.offset..]
        }

        fn assert_one_byte_reads(&self) {
            assert!(!self.requested.is_empty());
            assert!(self.requested.iter().all(|requested| *requested == 1));
        }
    }

    impl AsyncRead for RecordingReader<'_> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let requested = buffer.remaining();
            self.requested.push(requested);
            let available = self.bytes.len() - self.offset;
            let amount = requested.min(available);
            if amount != 0 {
                let end = self.offset + amount;
                buffer.put_slice(&self.bytes[self.offset..end]);
                self.offset = end;
            }
            Poll::Ready(Ok(()))
        }
    }

    fn guard_for(payload_bytes: usize) -> (Arc<WireBodyPool>, HttpWireBodyGuard, usize) {
        guard_for_with_additional_charge(payload_bytes, 0)
    }

    fn guard_for_with_additional_charge(
        payload_bytes: usize,
        additional_charge: usize,
    ) -> (Arc<WireBodyPool>, HttpWireBodyGuard, usize) {
        let allocation = guarded_body_allocation_bytes(payload_bytes.max(1))
            .unwrap()
            .checked_add(additional_charge)
            .unwrap();
        let pool = WireBodyPool::new(allocation, allocation);
        let guard = pool.begin_for_test(
            allocation,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );
        (pool, guard, allocation)
    }

    async fn run(
        bytes: &[u8],
        max_line_bytes: usize,
    ) -> (
        Result<DecisionOnlyResponse, FatalProcessResponseError>,
        usize,
        usize,
    ) {
        let mut reader = RecordingReader::new(bytes);
        let continuation = read_provider_response_prefix_for_test(&mut reader, max_line_bytes)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(continuation.id(), "r");
        let (pool, guard, _) = guard_for(max_line_bytes);
        let result = read_decision_only_response_for_test(
            &mut reader,
            continuation,
            &guard,
            &decision_schema(),
        )
        .await;
        reader.assert_one_byte_reads();
        (result, guard.live_bytes(), pool.global_charge())
    }

    #[tokio::test]
    async fn accepts_each_decision_with_lf_and_split_crlf() {
        for (decision, expected) in [
            ("allow", DecisionOnlyProviderDecision::Allow),
            ("deny", DecisionOnlyProviderDecision::Deny),
            ("pass", DecisionOnlyProviderDecision::Pass),
        ] {
            for ending in ["\n", "\r\n"] {
                let line = format!(
                    "{{\"id\":\"r\",\"type\":\"response\",\"decision\":\"{decision}\"}}{ending}"
                );
                let (result, live, global) = run(line.as_bytes(), line.len()).await;
                assert!(matches!(
                    result,
                    Ok(DecisionOnlyResponse::Decision(actual)) if actual == expected
                ));
                assert_eq!((live, global), (0, 0));
            }
        }
    }

    #[tokio::test]
    async fn exact_line_bound_succeeds_and_one_byte_less_is_fatal() {
        let line = b"{\"id\":\"r\",\"type\":\"response\",\"decision\":\"allow\"}\n";
        assert!(matches!(
            run(line, line.len()).await.0,
            Ok(DecisionOnlyResponse::Decision(
                DecisionOnlyProviderDecision::Allow
            ))
        ));
        let (result, live, global) = run(line, line.len() - 1).await;
        assert!(matches!(result, Err(FatalProcessResponseError::TooLong)));
        assert_eq!((live, global), (0, 0));
    }

    #[tokio::test]
    async fn missing_lf_at_64_kib_projection_never_attempts_a_second_chunk() {
        let stored_limit = 64 * 1024;
        let max_line_bytes = b"{\"id\":\"r\"".len() + stored_limit + 1;
        let mut line = b"{\"id\":\"r\",".to_vec();
        line.resize(max_line_bytes, b'x');
        let mut reader = RecordingReader::new(&line);
        let continuation = read_provider_response_prefix_for_test(&mut reader, max_line_bytes)
            .await
            .unwrap()
            .unwrap();
        let allocation = guarded_body_allocation_bytes(stored_limit).unwrap();
        let pool = WireBodyPool::new(allocation, allocation);
        let guard = pool.begin_for_test(
            allocation,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );

        assert!(matches!(
            read_decision_only_response_for_test(
                &mut reader,
                continuation,
                &guard,
                &decision_schema(),
            )
            .await,
            Err(FatalProcessResponseError::TooLong)
        ));
        reader.assert_one_byte_reads();
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn eof_without_lf_is_fatal_and_releases_charge() {
        let line = b"{\"id\":\"r\",\"type\":\"response\",\"decision\":\"allow\"}";
        let (result, live, global) = run(line, line.len() + 1).await;
        assert!(matches!(
            result,
            Err(FatalProcessResponseError::Unterminated)
        ));
        assert_eq!((live, global), (0, 0));
    }

    #[tokio::test]
    async fn admission_failure_is_fatal_and_rolls_back_every_charge() {
        let line = b"{\"id\":\"r\",\"type\":\"response\",\"decision\":\"allow\"}\n";
        let mut reader = RecordingReader::new(line);
        let continuation = read_provider_response_prefix_for_test(&mut reader, line.len())
            .await
            .unwrap()
            .unwrap();
        let allocation = guarded_body_allocation_bytes(1).unwrap();
        let pool = WireBodyPool::new(allocation, allocation);
        let guard = pool.begin_for_test(
            allocation - 1,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );
        let result = read_decision_only_response_for_test(
            &mut reader,
            continuation,
            &guard,
            &decision_schema(),
        )
        .await;
        reader.assert_one_byte_reads();
        assert!(matches!(
            result,
            Err(FatalProcessResponseError::Admission(
                WireBodyBufferError::CursorPeakExceeded
            ))
        ));
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn consumes_exactly_one_line() {
        let first = b"{\"id\":\"r\",\"type\":\"response\",\"decision\":\"deny\"}\r\n";
        let second = b"{\"id\":\"next\",\"type\":\"response\",\"decision\":\"allow\"}\n";
        let bytes = [first.as_slice(), second.as_slice()].concat();
        let mut reader = RecordingReader::new(&bytes);
        let continuation = read_provider_response_prefix_for_test(&mut reader, first.len())
            .await
            .unwrap()
            .unwrap();
        let (_, guard, _) = guard_for(first.len());
        assert!(matches!(
            read_decision_only_response_for_test(
                &mut reader,
                continuation,
                &guard,
                &decision_schema(),
            )
            .await,
            Ok(DecisionOnlyResponse::Decision(
                DecisionOnlyProviderDecision::Deny
            ))
        ));
        reader.assert_one_byte_reads();
        assert_eq!(reader.remaining(), second);
    }

    #[tokio::test]
    async fn duplicate_id_raw_or_escaped_is_fatal() {
        for line in [
            b"{\"id\":\"r\",\"id\":\"r\",\"type\":\"response\",\"decision\":\"allow\"}\n".as_slice(),
            b"{\"id\":\"r\",\"\\u0069\\u0064\":\"r\",\"type\":\"response\",\"decision\":\"allow\"}\n".as_slice(),
        ] {
            let (result, live, global) = run(line, line.len()).await;
            assert!(matches!(
                result,
                Err(FatalProcessResponseError::DuplicateId)
            ));
            assert_eq!((live, global), (0, 0));
        }
    }

    #[tokio::test]
    async fn malformed_content_wins_over_duplicate_id() {
        for (line, expected_invalid_utf8) in [
            (b"{\"id\":\"r\",\"id\":[}\n".as_slice(), false),
            (
                b"{\"id\":\"r\",\"id\":\"r\",\"unknown\":[}\n".as_slice(),
                false,
            ),
            (
                b"{\"id\":\"r\",\"id\":\"r\",\"unknown\":\"\xff\"}\n".as_slice(),
                true,
            ),
        ] {
            let result = run(line, line.len()).await.0;
            if expected_invalid_utf8 {
                assert!(matches!(
                    result,
                    Err(FatalProcessResponseError::InvalidUtf8)
                ));
            } else {
                assert!(matches!(
                    result,
                    Err(FatalProcessResponseError::MalformedJson)
                ));
            }
        }
    }

    #[tokio::test]
    async fn malformed_utf8_trailing_bytes_and_invalid_json_are_fatal() {
        for line in [
            b"{\"id\":\"r\",\"type\":\"res\xffponse\",\"decision\":\"allow\"}\n".as_slice(),
            b"{\"id\":\"r\",\"type\":\"response\",\"decision\":\"allow\"}x\n".as_slice(),
            b"{\"id\":\"r\",\"unknown\":[}\n".as_slice(),
            b"{\"id\":\"r\",\"type\":\"response\",\"decision\":\"allow\"\n".as_slice(),
        ] {
            let result = run(line, line.len()).await.0;
            assert!(matches!(
                result,
                Err(FatalProcessResponseError::MalformedJson)
                    | Err(FatalProcessResponseError::InvalidUtf8)
            ));
        }
    }

    #[tokio::test]
    async fn decision_only_and_expanded_accept_equivalent_json_whitespace() {
        let line = b" \t{ \t\"id\" \t: \t\"r\" \t, \"type\" : \"response\" , \"decision\" : \"allow\" \t } \r\n";
        assert_eq!(
            run(line, line.len()).await.0.unwrap(),
            DecisionOnlyResponse::Decision(DecisionOnlyProviderDecision::Allow)
        );

        let mut reader = RecordingReader::new(line);
        let continuation = read_provider_response_prefix_for_test(&mut reader, line.len())
            .await
            .unwrap()
            .unwrap();
        let (_, guard, _) = guard_for(line.len());
        let charge = guard.provider_response_charge();
        let outputs = ProviderOutputRegistry::activate(BTreeMap::from([(
            "token".to_string(),
            ProviderOutputPlan::Bearer {
                required: false,
                transport_security: crate::config::compiler::CompiledTransportSecurity::TlsRequired,
            },
        )]));
        let response = read_expanded_response(&mut reader, continuation, &charge, &outputs, None)
            .await
            .unwrap();

        assert!(matches!(
            response,
            ProcessResponse::Expanded(ProviderDecision::Allow { .. })
        ));
        drop(response);
        assert_eq!(guard.live_bytes(), 0);
    }

    #[tokio::test]
    async fn decision_only_and_expanded_accept_equivalent_required_field_order() {
        let line = b"{\"id\":\"r\",\"decision\":\"allow\",\"type\":\"response\"}\n";
        assert_eq!(
            run(line, line.len()).await.0.unwrap(),
            DecisionOnlyResponse::Decision(DecisionOnlyProviderDecision::Allow)
        );

        let mut reader = RecordingReader::new(line);
        let continuation = read_provider_response_prefix_for_test(&mut reader, line.len())
            .await
            .unwrap()
            .unwrap();
        let (_, guard, _) = guard_for(line.len());
        let charge = guard.provider_response_charge();
        let outputs = ProviderOutputRegistry::activate(BTreeMap::from([(
            "token".to_string(),
            ProviderOutputPlan::Bearer {
                required: false,
                transport_security: crate::config::compiler::CompiledTransportSecurity::TlsRequired,
            },
        )]));
        let response = read_expanded_response(&mut reader, continuation, &charge, &outputs, None)
            .await
            .unwrap();

        assert!(matches!(
            response,
            ProcessResponse::Expanded(ProviderDecision::Allow { .. })
        ));
        drop(response);
        assert_eq!(guard.live_bytes(), 0);
    }

    #[tokio::test]
    async fn expanded_parser_accepts_the_bounded_provider_output_name() {
        let output_name = "a".repeat(MAX_PROVIDER_OUTPUT_NAME_BYTES);
        let line = format!(
            "{{\"id\":\"r\",\"type\":\"response\",\"decision\":\"allow\",\"values\":{{\"{output_name}\":\"secret\"}}}}\n"
        );
        let mut reader = RecordingReader::new(line.as_bytes());
        let continuation = read_provider_response_prefix_for_test(&mut reader, line.len())
            .await
            .unwrap()
            .unwrap();
        let (_, guard, _) = guard_for(line.len());
        let charge = guard.provider_response_charge();
        let outputs = ProviderOutputRegistry::activate(BTreeMap::from([(
            output_name.clone(),
            ProviderOutputPlan::Bearer {
                required: true,
                transport_security: crate::config::compiler::CompiledTransportSecurity::TlsRequired,
            },
        )]));
        let response = read_expanded_response(&mut reader, continuation, &charge, &outputs, None)
            .await
            .unwrap();

        let ProcessResponse::Expanded(ProviderDecision::Allow { credentials, .. }) = response
        else {
            panic!("the exact-bound output name must be assigned");
        };
        let metadata = projected_provider_credential_wire_metadata_bytes(outputs.len()).unwrap();
        let (_, staging_guard, _) = guard_for_with_additional_charge(1, metadata);
        let staged = outputs
            .compact_provider_credential_wire(&credentials, &staging_guard)
            .unwrap();
        let output = outputs.index(&output_name).unwrap();
        let mut material = vec![0; staged.output_len(output).unwrap()];
        staged.copy_output(output, &mut material).unwrap();
        assert_eq!(material, b"secret");
        drop(staged);
        drop(credentials);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(staging_guard.live_bytes(), 0);
    }

    #[tokio::test]
    async fn valid_duplicate_non_id_is_assigned_only() {
        for line in [
            b"{\"id\":\"r\",\"type\":\"response\",\"type\":\"response\",\"decision\":\"allow\"}\n".as_slice(),
            b"{\"id\":\"r\",\"type\":\"response\",\"decision\":\"allow\",\"decision\":\"deny\"}\n".as_slice(),
            b"{\"id\":\"r\",\"values\":{},\"values\":{},\"type\":\"response\",\"decision\":\"allow\"}\n".as_slice(),
        ] {
            let (result, live, global) = run(line, line.len()).await;
            assert_eq!(
                result.unwrap(),
                DecisionOnlyResponse::AssignedFailure(AssignedResponseError::DuplicateField)
            );
            assert_eq!((live, global), (0, 0));
        }
    }

    #[tokio::test]
    async fn syntactically_valid_unsupported_or_wrong_shapes_are_assigned_only() {
        for line in [
            b"{\"id\":\"r\"}\n".as_slice(),
            b"{\"id\":\"r\",\"type\":\"response\",\"decision\":\"allow\",\"unknown\":{\"nested\":[true,false,null,-1.2e+3]}}\n".as_slice(),
            b"{\"id\":\"r\",\"type\":\"response\",\"decision\":\"allow\",\"values\":{}}\n".as_slice(),
            b"{\"id\":\"r\",\"type\":\"response\",\"decision\":\"allow\",\"requestBody\":{}}\n".as_slice(),
            b"{\"id\":\"r\",\"type\":7,\"decision\":\"allow\"}\n".as_slice(),
            b"{\"id\":\"r\",\"type\":\"response\",\"decision\":[]}\n".as_slice(),
            b"{\"id\":\"r\",\"type\":\"response\"}\n".as_slice(),
            b"{\"id\":\"r\",\"type\":\"response\",\"decision\":\"other\"}\n".as_slice(),
        ] {
            let (result, live, global) = run(line, line.len()).await;
            assert_eq!(
                result.unwrap(),
                DecisionOnlyResponse::AssignedFailure(AssignedResponseError::InvalidShape)
            );
            assert_eq!((live, global), (0, 0));
        }
    }

    #[tokio::test]
    async fn trailing_comma_is_fatal() {
        let line = b"{\"id\":\"r\",}\n";
        assert!(matches!(
            run(line, line.len()).await.0,
            Err(FatalProcessResponseError::MalformedJson)
        ));
    }

    #[tokio::test]
    async fn json_depth_limit_matches_serde_at_127_and_128_total_containers() {
        #[derive(Clone, Copy)]
        enum Innermost {
            Scalar,
            EmptyArray,
            EmptyObject,
        }

        fn nested_unknown(containers: usize, innermost: Innermost) -> Vec<u8> {
            let mut line = b"{\"id\":\"r\",\"unknown\":".to_vec();
            let array_depth = match innermost {
                Innermost::EmptyObject => containers - 1,
                Innermost::Scalar | Innermost::EmptyArray => containers,
            };
            line.extend(std::iter::repeat_n(b'[', array_depth));
            match innermost {
                Innermost::Scalar => line.extend_from_slice(b"null"),
                Innermost::EmptyArray => {}
                Innermost::EmptyObject => line.extend_from_slice(b"{}"),
            }
            line.extend(std::iter::repeat_n(b']', array_depth));
            line.extend_from_slice(b"}\n");
            line
        }

        for innermost in [
            Innermost::Scalar,
            Innermost::EmptyArray,
            Innermost::EmptyObject,
        ] {
            let exact = nested_unknown(MAX_JSON_DEPTH - 2, innermost);
            assert!(serde_json::from_slice::<serde_json::Value>(&exact[..exact.len() - 1]).is_ok());
            assert_eq!(
                run(&exact, exact.len()).await.0.unwrap(),
                DecisionOnlyResponse::AssignedFailure(AssignedResponseError::InvalidShape)
            );

            let over = nested_unknown(MAX_JSON_DEPTH - 1, innermost);
            assert!(serde_json::from_slice::<serde_json::Value>(&over[..over.len() - 1]).is_err());
            assert!(matches!(
                run(&over, over.len()).await.0,
                Err(FatalProcessResponseError::MalformedJson)
            ));
        }
    }

    #[tokio::test]
    async fn segmented_parser_crosses_guard_chunk_boundaries_without_concatenation() {
        let padding = "x".repeat(crate::safety::wire_body::MAX_BUFFER_GROWTH_BYTES + 17);
        let line = format!(
            "{{\"id\":\"r\",\"unknown\":\"{padding}\",\"type\":\"res\\u0070onse\",\"decision\":\"allow\"}}\n"
        );
        let (result, live, global) = run(line.as_bytes(), line.len()).await;
        assert_eq!(
            result.unwrap(),
            DecisionOnlyResponse::AssignedFailure(AssignedResponseError::InvalidShape)
        );
        assert_eq!((live, global), (0, 0));
    }

    #[test]
    fn schema_token_rejects_outputs_and_body_replacement() {
        assert!(
            DecisionOnlyResponseSchema::activate(&process_plan(BTreeMap::new(), true)).is_none()
        );
        let outputs = BTreeMap::from([(
            "token".to_string(),
            ProviderOutputPlan::Bearer {
                required: false,
                transport_security: crate::config::compiler::CompiledTransportSecurity::TlsRequired,
            },
        )]);
        assert!(DecisionOnlyResponseSchema::activate(&process_plan(outputs, false)).is_none());
    }

    struct ErrorAfterPrefix {
        bytes: &'static [u8],
        offset: usize,
    }

    impl AsyncRead for ErrorAfterPrefix {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.offset == self.bytes.len() {
                Poll::Ready(Err(io::Error::other("injected read failure")))
            } else {
                buffer.put_slice(&self.bytes[self.offset..self.offset + 1]);
                self.offset += 1;
                Poll::Ready(Ok(()))
            }
        }
    }

    #[tokio::test]
    async fn io_failure_after_prefix_is_fatal_without_charge() {
        let mut reader = ErrorAfterPrefix {
            bytes: b"{\"id\":\"r\"",
            offset: 0,
        };
        let continuation = read_provider_response_prefix_for_test(&mut reader, 64)
            .await
            .unwrap()
            .unwrap();
        let (_, guard, _) = guard_for(64);
        assert!(matches!(
            read_decision_only_response_for_test(
                &mut reader,
                continuation,
                &guard,
                &decision_schema(),
            )
            .await,
            Err(FatalProcessResponseError::Io(_))
        ));
        assert_eq!(guard.live_bytes(), 0);
    }
}
