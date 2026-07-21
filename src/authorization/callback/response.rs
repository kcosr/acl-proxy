use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use super::token::{ResumeTokenDigest, RESUME_TOKEN_ENCODED_BYTES};
use crate::authorization::protocol::{
    ProviderOutputIndex, ProviderOutputRegistry, CALLBACK_RESPONSE_PREFIX_BYTES,
    MIN_CALLBACK_RESPONSE_BYTES,
};
use crate::config::compiler::MAX_PROVIDER_CREDENTIAL_BYTES;
use crate::safety::wire_body::{GuardedBodyBuilder, GuardedBodySegments, WireBodyBufferError};
use crate::safety::{GuardedBody, ProviderResponseCharge};

const CALLBACK_PREFIX_START: &[u8] = b"{\"resumeToken\":\"";
const MAX_PROVIDER_OUTPUTS: usize = 256;
const OUTPUT_MATCH_WORDS: usize = MAX_PROVIDER_OUTPUTS / u64::BITS as usize;

const _: () = assert!(
    CALLBACK_PREFIX_START.len() + RESUME_TOKEN_ENCODED_BYTES + 2 == CALLBACK_RESPONSE_PREFIX_BYTES
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallbackPrefixError {
    Invalid,
}

/// Validated capability prefix. It carries only the token digest, never the
/// bearer value that appeared on the wire.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallbackResponsePrefix {
    digest: ResumeTokenDigest,
}

impl CallbackResponsePrefix {
    pub(crate) fn parse(
        prefix: &[u8; CALLBACK_RESPONSE_PREFIX_BYTES],
    ) -> Result<Self, CallbackPrefixError> {
        let token_start = CALLBACK_PREFIX_START.len();
        let token_end = token_start + RESUME_TOKEN_ENCODED_BYTES;
        if &prefix[..token_start] != CALLBACK_PREFIX_START
            || &prefix[token_end..] != b"\","
            || prefix[token_start..token_end]
                .iter()
                .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_'))
        {
            return Err(CallbackPrefixError::Invalid);
        }
        let encoded: &[u8; RESUME_TOKEN_ENCODED_BYTES] = prefix[token_start..token_end]
            .try_into()
            .expect("the canonical token range has one fixed length");
        Ok(Self {
            digest: ResumeTokenDigest::from_encoded(encoded),
        })
    }

    pub(crate) fn digest(self) -> ResumeTokenDigest {
        self.digest
    }
}

impl fmt::Debug for CallbackResponsePrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CallbackResponsePrefix([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallbackDecisionKind {
    Allow,
    Deny,
    Pass,
}

pub(crate) enum CallbackResponseDecision {
    Allow(CallbackCredentialSet),
    AllowWithoutEffects,
    Deny,
    Pass,
}

impl fmt::Debug for CallbackResponseDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow(credentials) => formatter.debug_tuple("Allow").field(credentials).finish(),
            Self::AllowWithoutEffects => formatter.write_str("AllowWithoutEffects"),
            Self::Deny => formatter.write_str("Deny"),
            Self::Pass => formatter.write_str("Pass"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct CredentialRange {
    start: usize,
    end: usize,
}

pub(crate) struct CallbackCredentialSet {
    registry_id: u64,
    values: Box<[Option<CredentialRange>]>,
    storage: GuardedBody,
}

impl CallbackCredentialSet {
    pub(crate) fn registry_id(&self) -> u64 {
        self.registry_id
    }

    pub(crate) fn get(&self, index: ProviderOutputIndex) -> Option<CallbackCredentialSegments<'_>> {
        let range = self
            .values
            .get(index.get())
            .filter(|_| self.registry_id == index.registry_id())
            .and_then(|range| *range)?;
        Some(CallbackCredentialSegments {
            segments: self.storage.segments(),
            skip: range.start,
            remaining: range.end - range.start,
        })
    }

    #[cfg(test)]
    pub(crate) fn charged_bytes(&self) -> usize {
        self.storage.charged_bytes()
    }
}

impl fmt::Debug for CallbackCredentialSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallbackCredentialSet")
            .field("count", &self.values.len())
            .field(
                "present_count",
                &self.values.iter().filter(|value| value.is_some()).count(),
            )
            .field("charged_bytes", &self.storage.charged_bytes())
            .finish()
    }
}

pub(crate) struct CallbackCredentialSegments<'a> {
    segments: GuardedBodySegments<'a>,
    skip: usize,
    remaining: usize,
}

impl<'a> Iterator for CallbackCredentialSegments<'a> {
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

#[derive(Debug, thiserror::Error)]
pub(crate) enum CallbackResponseError {
    #[error("callback response exceeded its assigned entity bound")]
    LimitExceeded,
    #[error("callback response storage could not be charged")]
    Charge(#[source] WireBodyBufferError),
    #[error("callback response JSON is malformed")]
    Malformed,
    #[error("callback response shape is invalid")]
    InvalidShape,
    #[error("callback response contains an unknown output")]
    UnknownOutput,
    #[error("callback response repeats an output")]
    DuplicateOutput,
    #[error("callback response omits a required output")]
    MissingRequiredOutput,
    #[error("callback response contains invalid credential material")]
    InvalidCredential,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    TypeKey(usize),
    TypeColon,
    TypeValue(usize),
    TypeComma,
    DecisionKey(usize),
    DecisionColon,
    DecisionValueStart,
    DecisionValue,
    AfterDecision,
    ValuesKey(usize),
    ValuesColon,
    ValuesObjectStart,
    ValuesEntryOrEnd { after_comma: bool },
    OutputKey,
    OutputColon,
    OutputValueStart,
    OutputValue,
    AfterOutputValue,
    AfterValues,
    Trailing,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecisionOnlyPhase {
    TypeKey(usize),
    TypeColon,
    TypeValue(usize),
    TypeComma,
    DecisionKey(usize),
    DecisionColon,
    DecisionValueStart,
    DecisionValue,
    AfterDecision,
    Trailing,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EscapeState {
    Normal,
    Escaped,
    Unicode { value: u16, digits: u8 },
    LowBackslash { high: u16 },
    LowU { high: u16 },
    LowUnicode { high: u16, value: u16, digits: u8 },
}

struct OutputNameMatcher {
    candidates: [u64; OUTPUT_MATCH_WORDS],
    offset: usize,
}

impl OutputNameMatcher {
    fn new(outputs: &ProviderOutputRegistry) -> Self {
        let mut candidates = [0u64; OUTPUT_MATCH_WORDS];
        for ordinal in 0..outputs.len() {
            candidates[ordinal / 64] |= 1u64 << (ordinal % 64);
        }
        Self {
            candidates,
            offset: 0,
        }
    }

    fn push(&mut self, byte: u8, outputs: &ProviderOutputRegistry) {
        for (ordinal, name) in outputs.wire_names().enumerate() {
            let word = &mut self.candidates[ordinal / 64];
            let bit = 1u64 << (ordinal % 64);
            if *word & bit != 0 && name.as_bytes().get(self.offset) != Some(&byte) {
                *word &= !bit;
            }
        }
        self.offset += 1;
    }

    fn finish(&self, outputs: &ProviderOutputRegistry) -> Option<usize> {
        outputs
            .wire_names()
            .enumerate()
            .find_map(|(ordinal, name)| {
                (self.candidates[ordinal / 64] & (1u64 << (ordinal % 64)) != 0
                    && name.len() == self.offset)
                    .then_some(ordinal)
            })
    }
}

/// Incremental parser for the assigned portion of a callback entity. The
/// caller has already consumed and claimed `CallbackResponsePrefix`.
pub(crate) struct AssignedCallbackResponseParser<'a> {
    outputs: &'a ProviderOutputRegistry,
    builder: Option<GuardedBodyBuilder>,
    values: Vec<Option<CredentialRange>>,
    max_entity_bytes: usize,
    entity_bytes: usize,
    phase: Phase,
    decision: Option<CallbackDecisionKind>,
    scalar: Zeroizing<[u8; 8]>,
    scalar_len: usize,
    name_matcher: Option<OutputNameMatcher>,
    output_index: Option<usize>,
    output_start: usize,
    output_valid: bool,
    escape: EscapeState,
    utf8: Zeroizing<[u8; 4]>,
    utf8_len: usize,
    utf8_need: usize,
    semantic_error: Option<CallbackResponseError>,
}

impl<'a> AssignedCallbackResponseParser<'a> {
    pub(crate) fn new(
        outputs: &'a ProviderOutputRegistry,
        charge: &ProviderResponseCharge,
        provider_max_response_bytes: usize,
        control_max_request_body_bytes: usize,
    ) -> Result<Self, CallbackResponseError> {
        let max_entity_bytes = provider_max_response_bytes.min(control_max_request_body_bytes);
        if max_entity_bytes < MIN_CALLBACK_RESPONSE_BYTES || outputs.len() > MAX_PROVIDER_OUTPUTS {
            return Err(CallbackResponseError::LimitExceeded);
        }
        Ok(Self {
            outputs,
            builder: Some(charge.buffer()),
            values: std::iter::repeat_with(|| None)
                .take(outputs.len())
                .collect(),
            max_entity_bytes,
            entity_bytes: CALLBACK_RESPONSE_PREFIX_BYTES,
            phase: Phase::TypeKey(0),
            decision: None,
            scalar: Zeroizing::new([0; 8]),
            scalar_len: 0,
            name_matcher: None,
            output_index: None,
            output_start: 0,
            output_valid: true,
            escape: EscapeState::Normal,
            utf8: Zeroizing::new([0; 4]),
            utf8_len: 0,
            utf8_need: 0,
            semantic_error: None,
        })
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<(), CallbackResponseError> {
        if self.phase == Phase::Failed {
            return Err(CallbackResponseError::Malformed);
        }
        for byte in bytes {
            self.entity_bytes = self
                .entity_bytes
                .checked_add(1)
                .ok_or(CallbackResponseError::LimitExceeded)?;
            if self.entity_bytes > self.max_entity_bytes {
                self.fail();
                return Err(CallbackResponseError::LimitExceeded);
            }
            if let Err(error) = self.consume(*byte) {
                self.fail();
                return Err(error);
            }
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<CallbackResponseDecision, CallbackResponseError> {
        if self.phase != Phase::Trailing {
            self.fail();
            return Err(CallbackResponseError::Malformed);
        }
        if let Some(error) = self.semantic_error.take() {
            self.fail();
            return Err(error);
        }
        if self.decision == Some(CallbackDecisionKind::Allow)
            && self
                .outputs
                .definitions()
                .iter()
                .zip(&self.values)
                .any(|(definition, value)| definition.required() && value.is_none())
        {
            self.fail();
            return Err(CallbackResponseError::MissingRequiredOutput);
        }
        let storage = self
            .builder
            .take()
            .expect("an active callback parser owns its guarded builder")
            .finish();
        match self.decision.expect("a complete response has a decision") {
            CallbackDecisionKind::Allow => {
                Ok(CallbackResponseDecision::Allow(CallbackCredentialSet {
                    registry_id: self.outputs.id(),
                    values: self.values.into_boxed_slice(),
                    storage,
                }))
            }
            CallbackDecisionKind::Deny => Ok(CallbackResponseDecision::Deny),
            CallbackDecisionKind::Pass => Ok(CallbackResponseDecision::Pass),
        }
    }

    fn consume(&mut self, byte: u8) -> Result<(), CallbackResponseError> {
        let phase = self.phase;
        self.phase = match phase {
            Phase::TypeKey(position) => match_fixed(byte, position, b"\"type\"", Phase::TypeColon)?,
            Phase::TypeColon => {
                expect_punctuation(byte, b':', Phase::TypeValue(0), Phase::TypeColon)?
            }
            Phase::TypeValue(position) => {
                match_fixed(byte, position, b"\"response\"", Phase::TypeComma)?
            }
            Phase::TypeComma => {
                expect_punctuation(byte, b',', Phase::DecisionKey(0), Phase::TypeComma)?
            }
            Phase::DecisionKey(position) => {
                match_fixed(byte, position, b"\"decision\"", Phase::DecisionColon)?
            }
            Phase::DecisionColon => {
                expect_punctuation(byte, b':', Phase::DecisionValueStart, Phase::DecisionColon)?
            }
            Phase::DecisionValueStart if is_json_whitespace(byte) => Phase::DecisionValueStart,
            Phase::DecisionValueStart if byte == b'"' => {
                self.scalar.zeroize();
                self.scalar_len = 0;
                Phase::DecisionValue
            }
            Phase::DecisionValueStart => return Err(CallbackResponseError::InvalidShape),
            Phase::DecisionValue if byte == b'"' => {
                self.decision = match &self.scalar[..self.scalar_len] {
                    b"allow" => Some(CallbackDecisionKind::Allow),
                    b"deny" => Some(CallbackDecisionKind::Deny),
                    b"pass" => Some(CallbackDecisionKind::Pass),
                    _ => return Err(CallbackResponseError::InvalidShape),
                };
                Phase::AfterDecision
            }
            Phase::DecisionValue if byte.is_ascii() && !matches!(byte, b'\\' | 0..=31) => {
                if self.scalar_len == self.scalar.len() {
                    return Err(CallbackResponseError::InvalidShape);
                }
                self.scalar[self.scalar_len] = byte;
                self.scalar_len += 1;
                Phase::DecisionValue
            }
            Phase::DecisionValue => return Err(CallbackResponseError::InvalidShape),
            Phase::AfterDecision if is_json_whitespace(byte) => Phase::AfterDecision,
            Phase::AfterDecision if byte == b'}' => Phase::Trailing,
            Phase::AfterDecision
                if byte == b',' && self.decision == Some(CallbackDecisionKind::Allow) =>
            {
                Phase::ValuesKey(0)
            }
            Phase::AfterDecision => return Err(CallbackResponseError::InvalidShape),
            Phase::ValuesKey(position) => {
                match_fixed(byte, position, b"\"values\"", Phase::ValuesColon)?
            }
            Phase::ValuesColon => {
                expect_punctuation(byte, b':', Phase::ValuesObjectStart, Phase::ValuesColon)?
            }
            Phase::ValuesObjectStart => expect_punctuation(
                byte,
                b'{',
                Phase::ValuesEntryOrEnd { after_comma: false },
                Phase::ValuesObjectStart,
            )?,
            Phase::ValuesEntryOrEnd { after_comma } if is_json_whitespace(byte) => {
                Phase::ValuesEntryOrEnd { after_comma }
            }
            Phase::ValuesEntryOrEnd { after_comma: false } if byte == b'}' => Phase::AfterValues,
            Phase::ValuesEntryOrEnd { .. } if byte == b'"' => {
                self.name_matcher = Some(OutputNameMatcher::new(self.outputs));
                Phase::OutputKey
            }
            Phase::ValuesEntryOrEnd { .. } => return Err(CallbackResponseError::Malformed),
            Phase::OutputKey if byte == b'"' => {
                let ordinal = self
                    .name_matcher
                    .take()
                    .and_then(|matcher| matcher.finish(self.outputs));
                self.output_index = ordinal;
                if let Some(ordinal) = ordinal {
                    if self.values[ordinal].is_some() {
                        self.record_semantic(CallbackResponseError::DuplicateOutput);
                    }
                } else {
                    self.record_semantic(CallbackResponseError::UnknownOutput);
                }
                Phase::OutputColon
            }
            Phase::OutputKey
                if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.') =>
            {
                self.name_matcher
                    .as_mut()
                    .expect("output-key parsing owns a matcher")
                    .push(byte, self.outputs);
                Phase::OutputKey
            }
            Phase::OutputKey => return Err(CallbackResponseError::Malformed),
            Phase::OutputColon => {
                expect_punctuation(byte, b':', Phase::OutputValueStart, Phase::OutputColon)?
            }
            Phase::OutputValueStart if is_json_whitespace(byte) => Phase::OutputValueStart,
            Phase::OutputValueStart if byte == b'"' => {
                self.output_start = self.builder().len();
                self.output_valid = true;
                self.escape = EscapeState::Normal;
                self.utf8_len = 0;
                self.utf8_need = 0;
                Phase::OutputValue
            }
            Phase::OutputValueStart => return Err(CallbackResponseError::InvalidCredential),
            Phase::OutputValue => {
                if self.consume_output_string(byte)? {
                    self.finish_output();
                    Phase::AfterOutputValue
                } else {
                    Phase::OutputValue
                }
            }
            Phase::AfterOutputValue if is_json_whitespace(byte) => Phase::AfterOutputValue,
            Phase::AfterOutputValue if byte == b',' => {
                Phase::ValuesEntryOrEnd { after_comma: true }
            }
            Phase::AfterOutputValue if byte == b'}' => Phase::AfterValues,
            Phase::AfterOutputValue => return Err(CallbackResponseError::Malformed),
            Phase::AfterValues if is_json_whitespace(byte) => Phase::AfterValues,
            Phase::AfterValues if byte == b'}' => Phase::Trailing,
            Phase::AfterValues => return Err(CallbackResponseError::InvalidShape),
            Phase::Trailing if is_json_whitespace(byte) => Phase::Trailing,
            Phase::Trailing => return Err(CallbackResponseError::Malformed),
            Phase::Failed => return Err(CallbackResponseError::Malformed),
        };
        Ok(())
    }

    fn consume_output_string(&mut self, byte: u8) -> Result<bool, CallbackResponseError> {
        if self.utf8_need != 0 {
            if !matches!(byte, 0x80..=0xbf) {
                return Err(CallbackResponseError::Malformed);
            }
            self.utf8[self.utf8_len] = byte;
            self.utf8_len += 1;
            if self.utf8_len == self.utf8_need {
                std::str::from_utf8(&self.utf8[..self.utf8_len])
                    .map_err(|_| CallbackResponseError::Malformed)?;
                let encoded = *self.utf8;
                let len = self.utf8_len;
                self.append_output(&encoded[..len])?;
                self.utf8_len = 0;
                self.utf8_need = 0;
            }
            return Ok(false);
        }
        match self.escape {
            EscapeState::Normal => match byte {
                b'"' => return Ok(true),
                b'\\' => self.escape = EscapeState::Escaped,
                0..=31 => return Err(CallbackResponseError::Malformed),
                32..=127 => self.append_output(&[byte])?,
                0xc2..=0xdf => self.begin_utf8(byte, 2),
                0xe0..=0xef => self.begin_utf8(byte, 3),
                0xf0..=0xf4 => self.begin_utf8(byte, 4),
                _ => return Err(CallbackResponseError::Malformed),
            },
            EscapeState::Escaped => match byte {
                b'"' | b'\\' | b'/' => {
                    self.append_output(&[byte])?;
                    self.escape = EscapeState::Normal;
                }
                b'b' => self.append_escaped(&[8])?,
                b'f' => self.append_escaped(&[12])?,
                b'n' => self.append_escaped(b"\n")?,
                b'r' => self.append_escaped(b"\r")?,
                b't' => self.append_escaped(b"\t")?,
                b'u' => {
                    self.escape = EscapeState::Unicode {
                        value: 0,
                        digits: 0,
                    }
                }
                _ => return Err(CallbackResponseError::Malformed),
            },
            EscapeState::Unicode {
                mut value,
                mut digits,
            } => {
                value = (value << 4) | hex_digit(byte).ok_or(CallbackResponseError::Malformed)?;
                digits += 1;
                if digits != 4 {
                    self.escape = EscapeState::Unicode { value, digits };
                } else if (0xd800..=0xdbff).contains(&value) {
                    self.escape = EscapeState::LowBackslash { high: value };
                } else if (0xdc00..=0xdfff).contains(&value) {
                    return Err(CallbackResponseError::Malformed);
                } else {
                    self.append_scalar(value as u32)?;
                }
            }
            EscapeState::LowBackslash { high } if byte == b'\\' => {
                self.escape = EscapeState::LowU { high };
            }
            EscapeState::LowBackslash { .. } => return Err(CallbackResponseError::Malformed),
            EscapeState::LowU { high } if byte == b'u' => {
                self.escape = EscapeState::LowUnicode {
                    high,
                    value: 0,
                    digits: 0,
                };
            }
            EscapeState::LowU { .. } => return Err(CallbackResponseError::Malformed),
            EscapeState::LowUnicode {
                high,
                mut value,
                mut digits,
            } => {
                value = (value << 4) | hex_digit(byte).ok_or(CallbackResponseError::Malformed)?;
                digits += 1;
                if digits != 4 {
                    self.escape = EscapeState::LowUnicode {
                        high,
                        value,
                        digits,
                    };
                } else if (0xdc00..=0xdfff).contains(&value) {
                    let scalar =
                        0x1_0000 + (((high as u32 - 0xd800) << 10) | (value as u32 - 0xdc00));
                    self.append_scalar(scalar)?;
                } else {
                    return Err(CallbackResponseError::Malformed);
                }
            }
        }
        Ok(false)
    }

    fn begin_utf8(&mut self, byte: u8, width: usize) {
        self.utf8[0] = byte;
        self.utf8_len = 1;
        self.utf8_need = width;
    }

    fn append_escaped(&mut self, bytes: &[u8]) -> Result<(), CallbackResponseError> {
        self.append_output(bytes)?;
        self.escape = EscapeState::Normal;
        Ok(())
    }

    fn append_scalar(&mut self, scalar: u32) -> Result<(), CallbackResponseError> {
        let character = char::from_u32(scalar).ok_or(CallbackResponseError::Malformed)?;
        let mut encoded = [0u8; 4];
        self.append_output(character.encode_utf8(&mut encoded).as_bytes())?;
        self.escape = EscapeState::Normal;
        Ok(())
    }

    fn append_output(&mut self, bytes: &[u8]) -> Result<(), CallbackResponseError> {
        let current = self.builder().len() - self.output_start;
        if current
            .checked_add(bytes.len())
            .is_none_or(|length| length > MAX_PROVIDER_CREDENTIAL_BYTES)
            || bytes
                .iter()
                .any(|byte| *byte != b'\t' && (*byte < 32 || *byte == 127))
        {
            self.output_valid = false;
        }
        self.builder()
            .try_extend_from_slice(bytes)
            .map_err(CallbackResponseError::Charge)
    }

    fn finish_output(&mut self) {
        let end = self.builder().len();
        if end == self.output_start {
            self.output_valid = false;
        }
        if !self.output_valid {
            self.record_semantic(CallbackResponseError::InvalidCredential);
        }
        if let Some(index) = self.output_index.take() {
            if self.values[index].is_none() {
                self.values[index] = Some(CredentialRange {
                    start: self.output_start,
                    end,
                });
            }
        }
    }

    fn builder(&mut self) -> &mut GuardedBodyBuilder {
        self.builder
            .as_mut()
            .expect("an active callback parser owns its guarded builder")
    }

    fn record_semantic(&mut self, error: CallbackResponseError) {
        if self.semantic_error.is_none() {
            self.semantic_error = Some(error);
        }
    }

    fn fail(&mut self) {
        self.phase = Phase::Failed;
        self.scalar.zeroize();
        self.utf8.zeroize();
        self.builder.take();
    }
}

/// Incremental parser for callbacks whose invocation may authorize a request
/// but may not return provider effects. It deliberately owns no output
/// registry, response charge, or credential storage.
pub(crate) struct DecisionOnlyCallbackResponseParser {
    max_entity_bytes: usize,
    entity_bytes: usize,
    phase: DecisionOnlyPhase,
    decision: Option<CallbackDecisionKind>,
    scalar: Zeroizing<[u8; 8]>,
    scalar_len: usize,
}

impl DecisionOnlyCallbackResponseParser {
    pub(crate) fn new(
        provider_max_response_bytes: usize,
        control_max_request_body_bytes: usize,
    ) -> Result<Self, CallbackResponseError> {
        let max_entity_bytes = provider_max_response_bytes.min(control_max_request_body_bytes);
        if max_entity_bytes < MIN_CALLBACK_RESPONSE_BYTES {
            return Err(CallbackResponseError::LimitExceeded);
        }
        Ok(Self {
            max_entity_bytes,
            entity_bytes: CALLBACK_RESPONSE_PREFIX_BYTES,
            phase: DecisionOnlyPhase::TypeKey(0),
            decision: None,
            scalar: Zeroizing::new([0; 8]),
            scalar_len: 0,
        })
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<(), CallbackResponseError> {
        if self.phase == DecisionOnlyPhase::Failed {
            return Err(CallbackResponseError::Malformed);
        }
        for byte in bytes {
            self.entity_bytes = self
                .entity_bytes
                .checked_add(1)
                .ok_or(CallbackResponseError::LimitExceeded)?;
            if self.entity_bytes > self.max_entity_bytes {
                self.fail();
                return Err(CallbackResponseError::LimitExceeded);
            }
            if let Err(error) = self.consume(*byte) {
                self.fail();
                return Err(error);
            }
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<CallbackResponseDecision, CallbackResponseError> {
        if self.phase != DecisionOnlyPhase::Trailing {
            self.fail();
            return Err(CallbackResponseError::Malformed);
        }
        match self.decision.expect("a complete response has a decision") {
            CallbackDecisionKind::Allow => Ok(CallbackResponseDecision::AllowWithoutEffects),
            CallbackDecisionKind::Deny => Ok(CallbackResponseDecision::Deny),
            CallbackDecisionKind::Pass => Ok(CallbackResponseDecision::Pass),
        }
    }

    fn consume(&mut self, byte: u8) -> Result<(), CallbackResponseError> {
        let phase = self.phase;
        self.phase = match phase {
            DecisionOnlyPhase::TypeKey(position) => decision_only_match_fixed(
                byte,
                position,
                b"\"type\"",
                DecisionOnlyPhase::TypeColon,
            )?,
            DecisionOnlyPhase::TypeColon => decision_only_expect_punctuation(
                byte,
                b':',
                DecisionOnlyPhase::TypeValue(0),
                DecisionOnlyPhase::TypeColon,
            )?,
            DecisionOnlyPhase::TypeValue(position) => decision_only_match_fixed(
                byte,
                position,
                b"\"response\"",
                DecisionOnlyPhase::TypeComma,
            )?,
            DecisionOnlyPhase::TypeComma => decision_only_expect_punctuation(
                byte,
                b',',
                DecisionOnlyPhase::DecisionKey(0),
                DecisionOnlyPhase::TypeComma,
            )?,
            DecisionOnlyPhase::DecisionKey(position) => decision_only_match_fixed(
                byte,
                position,
                b"\"decision\"",
                DecisionOnlyPhase::DecisionColon,
            )?,
            DecisionOnlyPhase::DecisionColon => decision_only_expect_punctuation(
                byte,
                b':',
                DecisionOnlyPhase::DecisionValueStart,
                DecisionOnlyPhase::DecisionColon,
            )?,
            DecisionOnlyPhase::DecisionValueStart if is_json_whitespace(byte) => {
                DecisionOnlyPhase::DecisionValueStart
            }
            DecisionOnlyPhase::DecisionValueStart if byte == b'"' => {
                self.scalar.zeroize();
                self.scalar_len = 0;
                DecisionOnlyPhase::DecisionValue
            }
            DecisionOnlyPhase::DecisionValueStart => {
                return Err(CallbackResponseError::InvalidShape)
            }
            DecisionOnlyPhase::DecisionValue if byte == b'"' => {
                self.decision = match &self.scalar[..self.scalar_len] {
                    b"allow" => Some(CallbackDecisionKind::Allow),
                    b"deny" => Some(CallbackDecisionKind::Deny),
                    b"pass" => Some(CallbackDecisionKind::Pass),
                    _ => return Err(CallbackResponseError::InvalidShape),
                };
                DecisionOnlyPhase::AfterDecision
            }
            DecisionOnlyPhase::DecisionValue
                if byte.is_ascii() && !matches!(byte, b'\\' | 0..=31) =>
            {
                if self.scalar_len == self.scalar.len() {
                    return Err(CallbackResponseError::InvalidShape);
                }
                self.scalar[self.scalar_len] = byte;
                self.scalar_len += 1;
                DecisionOnlyPhase::DecisionValue
            }
            DecisionOnlyPhase::DecisionValue => return Err(CallbackResponseError::InvalidShape),
            DecisionOnlyPhase::AfterDecision if is_json_whitespace(byte) => {
                DecisionOnlyPhase::AfterDecision
            }
            DecisionOnlyPhase::AfterDecision if byte == b'}' => DecisionOnlyPhase::Trailing,
            DecisionOnlyPhase::AfterDecision => return Err(CallbackResponseError::InvalidShape),
            DecisionOnlyPhase::Trailing if is_json_whitespace(byte) => DecisionOnlyPhase::Trailing,
            DecisionOnlyPhase::Trailing => return Err(CallbackResponseError::Malformed),
            DecisionOnlyPhase::Failed => return Err(CallbackResponseError::Malformed),
        };
        Ok(())
    }

    fn fail(&mut self) {
        self.phase = DecisionOnlyPhase::Failed;
        self.scalar.zeroize();
    }
}

fn decision_only_match_fixed(
    byte: u8,
    position: usize,
    literal: &[u8],
    complete: DecisionOnlyPhase,
) -> Result<DecisionOnlyPhase, CallbackResponseError> {
    if position == 0 && is_json_whitespace(byte) {
        return Ok(match complete {
            DecisionOnlyPhase::TypeColon => DecisionOnlyPhase::TypeKey(0),
            DecisionOnlyPhase::TypeComma => DecisionOnlyPhase::TypeValue(0),
            DecisionOnlyPhase::DecisionColon => DecisionOnlyPhase::DecisionKey(0),
            _ => return Err(CallbackResponseError::Malformed),
        });
    }
    if literal.get(position) != Some(&byte) {
        return Err(CallbackResponseError::InvalidShape);
    }
    Ok(if position + 1 == literal.len() {
        complete
    } else {
        match complete {
            DecisionOnlyPhase::TypeColon => DecisionOnlyPhase::TypeKey(position + 1),
            DecisionOnlyPhase::TypeComma => DecisionOnlyPhase::TypeValue(position + 1),
            DecisionOnlyPhase::DecisionColon => DecisionOnlyPhase::DecisionKey(position + 1),
            _ => return Err(CallbackResponseError::Malformed),
        }
    })
}

fn decision_only_expect_punctuation(
    byte: u8,
    expected: u8,
    complete: DecisionOnlyPhase,
    waiting: DecisionOnlyPhase,
) -> Result<DecisionOnlyPhase, CallbackResponseError> {
    if is_json_whitespace(byte) {
        Ok(waiting)
    } else if byte == expected {
        Ok(complete)
    } else {
        Err(CallbackResponseError::Malformed)
    }
}

fn match_fixed(
    byte: u8,
    position: usize,
    literal: &[u8],
    complete: Phase,
) -> Result<Phase, CallbackResponseError> {
    if position == 0 && is_json_whitespace(byte) {
        return Ok(match complete {
            Phase::TypeColon => Phase::TypeKey(0),
            Phase::TypeComma => Phase::TypeValue(0),
            Phase::DecisionColon => Phase::DecisionKey(0),
            Phase::ValuesColon => Phase::ValuesKey(0),
            _ => return Err(CallbackResponseError::Malformed),
        });
    }
    if literal.get(position) != Some(&byte) {
        return Err(CallbackResponseError::InvalidShape);
    }
    Ok(if position + 1 == literal.len() {
        complete
    } else {
        match complete {
            Phase::TypeColon => Phase::TypeKey(position + 1),
            Phase::TypeComma => Phase::TypeValue(position + 1),
            Phase::DecisionColon => Phase::DecisionKey(position + 1),
            Phase::ValuesColon => Phase::ValuesKey(position + 1),
            _ => return Err(CallbackResponseError::Malformed),
        }
    })
}

fn expect_punctuation(
    byte: u8,
    expected: u8,
    complete: Phase,
    waiting: Phase,
) -> Result<Phase, CallbackResponseError> {
    if is_json_whitespace(byte) {
        Ok(waiting)
    } else if byte == expected {
        Ok(complete)
    } else {
        Err(CallbackResponseError::Malformed)
    }
}

fn is_json_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn hex_digit(byte: u8) -> Option<u16> {
    match byte {
        b'0'..=b'9' => Some((byte - b'0') as u16),
        b'a'..=b'f' => Some((byte - b'a' + 10) as u16),
        b'A'..=b'F' => Some((byte - b'A' + 10) as u16),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};

    use http::HeaderName;

    use super::*;
    use crate::authorization::protocol::{
        projected_provider_credential_wire_metadata_bytes, ProviderCredentialSet,
    };
    use crate::config::compiler::ProviderOutputPlan;
    use crate::safety::wire_body::guarded_body_allocation_bytes;
    use crate::safety::{HttpWireBodyGuard, WireBodyPool, WireBodyQuotaKey};

    const PREFIX: &[u8; CALLBACK_RESPONSE_PREFIX_BYTES] =
        b"{\"resumeToken\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",";

    fn outputs(required: bool) -> ProviderOutputRegistry {
        ProviderOutputRegistry::activate(BTreeMap::from([
            (
                "api_token".to_string(),
                ProviderOutputPlan::Bearer {
                    required,
                    transport_security:
                        crate::config::compiler::CompiledTransportSecurity::TlsRequired,
                },
            ),
            (
                "trace_id".to_string(),
                ProviderOutputPlan::CustomHeader {
                    header: HeaderName::from_static("x-trace-id"),
                    required: false,
                    transport_security:
                        crate::config::compiler::CompiledTransportSecurity::TlsRequired,
                },
            ),
        ]))
    }

    fn guard(limit: usize) -> (std::sync::Arc<WireBodyPool>, HttpWireBodyGuard) {
        guard_with_additional_charge(limit, 0)
    }

    fn guard_with_additional_charge(
        limit: usize,
        additional_charge: usize,
    ) -> (std::sync::Arc<WireBodyPool>, HttpWireBodyGuard) {
        let allocation = guarded_body_allocation_bytes(limit)
            .unwrap()
            .max(1)
            .checked_add(additional_charge)
            .unwrap();
        let pool = WireBodyPool::new(allocation * 2, allocation * 2);
        let guard = pool.begin_for_test(
            allocation,
            WireBodyQuotaKey::Peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        );
        (pool, guard)
    }

    fn parse(
        body: &[u8],
        outputs: &ProviderOutputRegistry,
        charge: &ProviderResponseCharge,
        provider_limit: usize,
        control_limit: usize,
    ) -> Result<CallbackResponseDecision, CallbackResponseError> {
        let prefix: [u8; CALLBACK_RESPONSE_PREFIX_BYTES] = body
            .get(..CALLBACK_RESPONSE_PREFIX_BYTES)
            .unwrap_or(&[])
            .try_into()
            .map_err(|_| CallbackResponseError::Malformed)?;
        CallbackResponsePrefix::parse(&prefix).map_err(|_| CallbackResponseError::Malformed)?;
        let mut parser =
            AssignedCallbackResponseParser::new(outputs, charge, provider_limit, control_limit)?;
        for chunk in body[CALLBACK_RESPONSE_PREFIX_BYTES..].chunks(3) {
            parser.push(chunk)?;
        }
        parser.finish()
    }

    fn parse_decision_only(
        body: &[u8],
        provider_limit: usize,
        control_limit: usize,
    ) -> Result<CallbackResponseDecision, CallbackResponseError> {
        let prefix: [u8; CALLBACK_RESPONSE_PREFIX_BYTES] = body
            .get(..CALLBACK_RESPONSE_PREFIX_BYTES)
            .unwrap_or(&[])
            .try_into()
            .map_err(|_| CallbackResponseError::Malformed)?;
        CallbackResponsePrefix::parse(&prefix).map_err(|_| CallbackResponseError::Malformed)?;
        let mut parser = DecisionOnlyCallbackResponseParser::new(provider_limit, control_limit)?;
        for chunk in body[CALLBACK_RESPONSE_PREFIX_BYTES..].chunks(2) {
            parser.push(chunk)?;
        }
        parser.finish()
    }

    fn body(suffix: &str) -> Vec<u8> {
        let mut body = PREFIX.to_vec();
        body.extend_from_slice(suffix.as_bytes());
        body
    }

    fn credential_bytes(
        credentials: &CallbackCredentialSet,
        name: &str,
        outputs: &ProviderOutputRegistry,
    ) -> Vec<u8> {
        credentials
            .get(outputs.index(name).unwrap())
            .unwrap()
            .flatten()
            .copied()
            .collect()
    }

    #[test]
    fn callback_token_prefix_budget_and_canonical_encoding() {
        let parsed = CallbackResponsePrefix::parse(PREFIX).unwrap();
        let replay = CallbackResponsePrefix::parse(PREFIX).unwrap();
        assert_eq!(parsed.digest(), replay.digest());
        assert!(!format!("{parsed:?}").contains("AAAA"));

        let mut leading_whitespace = *PREFIX;
        leading_whitespace[0] = b' ';
        let mut padded = *PREFIX;
        padded[CALLBACK_PREFIX_START.len() + RESUME_TOKEN_ENCODED_BYTES - 1] = b'=';
        let mut alternate_alphabet = *PREFIX;
        alternate_alphabet[CALLBACK_PREFIX_START.len() + RESUME_TOKEN_ENCODED_BYTES - 1] = b'/';
        let mut noncanonical_delimiter = *PREFIX;
        noncanonical_delimiter[CALLBACK_RESPONSE_PREFIX_BYTES - 1] = b' ';
        for invalid in [
            leading_whitespace,
            padded,
            alternate_alphabet,
            noncanonical_delimiter,
        ] {
            assert_eq!(
                CallbackResponsePrefix::parse(&invalid),
                Err(CallbackPrefixError::Invalid)
            );
        }
    }

    #[test]
    fn callback_response_body_and_parser_limits_are_exact() {
        let outputs = outputs(false);
        let response = body("\"type\":\"response\",\"decision\":\"deny\"}");
        let (_, guard) = guard(response.len());
        let charge = guard.provider_response_charge();

        assert!(matches!(
            parse(&response, &outputs, &charge, response.len(), response.len()),
            Ok(CallbackResponseDecision::Deny)
        ));
        assert!(matches!(
            parse(
                &response,
                &outputs,
                &charge,
                response.len() - 1,
                response.len()
            ),
            Err(CallbackResponseError::LimitExceeded)
        ));
        assert!(matches!(
            parse(
                &response,
                &outputs,
                &charge,
                response.len(),
                response.len() - 1
            ),
            Err(CallbackResponseError::LimitExceeded)
        ));
    }

    #[test]
    fn decision_only_callback_accepts_only_effect_free_decisions() {
        for (wire, expected) in [
            (
                body("\"type\":\"response\",\"decision\":\"allow\"}"),
                CallbackDecisionKind::Allow,
            ),
            (
                body(" \"type\" : \"response\" , \"decision\" : \"deny\" } \r\n"),
                CallbackDecisionKind::Deny,
            ),
            (
                body("\"type\":\"response\",\"decision\":\"pass\"}"),
                CallbackDecisionKind::Pass,
            ),
        ] {
            let decision = parse_decision_only(&wire, wire.len(), wire.len()).unwrap();
            assert!(matches!(
                (expected, decision),
                (
                    CallbackDecisionKind::Allow,
                    CallbackResponseDecision::AllowWithoutEffects
                ) | (CallbackDecisionKind::Deny, CallbackResponseDecision::Deny)
                    | (CallbackDecisionKind::Pass, CallbackResponseDecision::Pass)
            ));
        }

        for wire in [
            body("\"type\":\"response\",\"decision\":\"allow\",\"values\":{}}"),
            body("\"type\":\"response\",\"decision\":\"deny\",\"replacement\":\"x\"}"),
            body("\"type\":\"response\",\"decision\":\"pass\",\"extra\":null}"),
        ] {
            assert!(matches!(
                parse_decision_only(&wire, wire.len(), wire.len()),
                Err(CallbackResponseError::InvalidShape) | Err(CallbackResponseError::Malformed)
            ));
        }
    }

    #[test]
    fn decision_only_callback_enforces_entity_bounds_without_a_response_charge() {
        let response = body("\"type\":\"response\",\"decision\":\"allow\"}");
        assert!(matches!(
            parse_decision_only(&response, response.len(), response.len()),
            Ok(CallbackResponseDecision::AllowWithoutEffects)
        ));
        assert!(matches!(
            parse_decision_only(&response, response.len() - 1, response.len()),
            Err(CallbackResponseError::LimitExceeded)
        ));
        assert!(matches!(
            parse_decision_only(&response, response.len(), response.len() - 1),
            Err(CallbackResponseError::LimitExceeded)
        ));
    }

    #[test]
    fn deny_and_pass_do_not_require_allow_only_outputs() {
        let outputs = outputs(true);
        for (wire, expected) in [
            (
                body("\"type\":\"response\",\"decision\":\"deny\"}"),
                CallbackDecisionKind::Deny,
            ),
            (
                body("\"type\":\"response\",\"decision\":\"pass\"}"),
                CallbackDecisionKind::Pass,
            ),
        ] {
            let (_, guard) = guard(wire.len());
            let parsed = parse(
                &wire,
                &outputs,
                &guard.provider_response_charge(),
                wire.len(),
                wire.len(),
            )
            .unwrap();
            assert!(matches!(
                (expected, parsed),
                (CallbackDecisionKind::Deny, CallbackResponseDecision::Deny)
                    | (CallbackDecisionKind::Pass, CallbackResponseDecision::Pass)
            ));
        }
    }

    #[test]
    fn webhook_response_limit_and_typed_output_matrix() {
        let outputs = outputs(true);
        let response = body(
            " \"type\" : \"response\" , \"decision\" : \"allow\" , \"values\" : {\"api_token\":\"sec\\u0072et-\\ud83d\\ude80\",\"trace_id\":\"trace\\tvalue\"} } \r\n",
        );
        let (pool, guard) = guard(response.len());
        let decision = parse(
            &response,
            &outputs,
            &guard.provider_response_charge(),
            response.len(),
            response.len(),
        )
        .unwrap();
        let CallbackResponseDecision::Allow(credentials) = decision else {
            panic!("allow response expected");
        };
        assert_eq!(
            credential_bytes(&credentials, "api_token", &outputs),
            "secret-🚀".as_bytes()
        );
        assert_eq!(
            credential_bytes(&credentials, "trace_id", &outputs),
            b"trace\tvalue"
        );
        assert!(credentials.charged_bytes() > 0);
        assert_eq!(pool.global_charge(), credentials.charged_bytes());
        drop(credentials);
        assert_eq!(pool.global_charge(), 0);
        assert_eq!(guard.live_bytes(), 0);

        for (provider_limit, control_limit) in [
            (response.len() - 1, response.len()),
            (response.len(), response.len() - 1),
        ] {
            assert!(matches!(
                parse(
                    &response,
                    &outputs,
                    &guard.provider_response_charge(),
                    provider_limit,
                    control_limit,
                ),
                Err(CallbackResponseError::LimitExceeded)
            ));
            assert_eq!(guard.live_bytes(), 0);
        }
    }

    #[test]
    fn callback_secret_material_is_not_observable() {
        let outputs = outputs(true);
        let response = body(
            "\"type\":\"response\",\"decision\":\"allow\",\"values\":{\"api_token\":\"secret-marker\"}}",
        );
        let metadata = projected_provider_credential_wire_metadata_bytes(outputs.len()).unwrap();
        let (_, guard) = guard_with_additional_charge(64 * 1024 + 1, metadata);
        let CallbackResponseDecision::Allow(credentials) = parse(
            &response,
            &outputs,
            &guard.provider_response_charge(),
            response.len(),
            response.len(),
        )
        .unwrap() else {
            panic!("allow response expected");
        };
        let index = outputs.index("api_token").unwrap();
        let provider_credentials = ProviderCredentialSet::from_segmented(credentials);

        assert!(provider_credentials.contiguous(index).is_none());
        assert_eq!(
            provider_credentials
                .segmented(index)
                .unwrap()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
            b"secret-marker"
        );
        assert!(!format!("{provider_credentials:?}").contains("secret-marker"));

        let staged = outputs
            .compact_provider_credential_wire(&provider_credentials, &guard)
            .unwrap();
        let mut material = vec![0; staged.output_len(index).unwrap()];
        staged.copy_output(index, &mut material).unwrap();
        assert_eq!(material, b"secret-marker");
        drop(staged);
        drop(provider_credentials);
        assert_eq!(guard.live_bytes(), 0);
    }

    #[test]
    fn callback_malformed_duplicate_unknown_and_required_outputs_are_rejected() {
        let required = outputs(true);
        let optional = outputs(false);
        let (_, guard) = guard(64 * 1024);
        let charge = guard.provider_response_charge();
        let cases = [
            (
                body("\"type\":\"response\",\"decision\":\"allow\",\"values\":{\"api_token\":\"a\",\"api_token\":\"b\"}}"),
                "duplicate",
            ),
            (
                body("\"type\":\"response\",\"decision\":\"allow\",\"values\":{\"undeclared\":\"a\"}}"),
                "unknown",
            ),
            (
                body("\"type\":\"response\",\"decision\":\"allow\"}"),
                "required",
            ),
            (
                body("\"type\":\"response\",\"decision\":\"deny\",\"denyMessage\":\"no\"}"),
                "shape",
            ),
            (
                body("\"type\":\"response\",\"decision\":\"pass\",\"values\":{}}"),
                "shape",
            ),
            (
                body("\"type\":\"response\",\"decision\":\"allow\",\"values\":{\"api_token\":\"\\ud800x\"}}"),
                "malformed",
            ),
        ];
        for (response, expected) in cases {
            let schema = if expected == "required" {
                &required
            } else {
                &optional
            };
            let error = parse(&response, schema, &charge, 64 * 1024, 64 * 1024).unwrap_err();
            assert!(
                matches!(
                    (expected, error),
                    ("duplicate", CallbackResponseError::DuplicateOutput)
                        | ("unknown", CallbackResponseError::UnknownOutput)
                        | ("required", CallbackResponseError::MissingRequiredOutput)
                        | ("shape", CallbackResponseError::InvalidShape)
                        | ("malformed", CallbackResponseError::Malformed)
                ),
                "unexpected result for {expected}"
            );
            assert_eq!(guard.live_bytes(), 0);
        }
    }

    #[test]
    fn callback_response_allocation_is_guarded_and_aggregate_bounded() {
        let outputs = outputs(false);
        let response = body(
            "\"type\":\"response\",\"decision\":\"allow\",\"values\":{\"api_token\":\"secret\"}}",
        );
        let pool = WireBodyPool::new(64 * 1024, 64 * 1024);
        let guard = pool.begin_for_test(1, WireBodyQuotaKey::Peer(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(matches!(
            parse(
                &response,
                &outputs,
                &guard.provider_response_charge(),
                response.len(),
                response.len()
            ),
            Err(CallbackResponseError::Charge(_))
        ));
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }
}
