use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use http::HeaderValue;
use zeroize::{Zeroize, Zeroizing};

use super::protocol::{
    AssignedResponseError, ProcessEffectRange, ProcessEffectSegments, ProcessProviderCredentials,
    ProviderBodyReplacement, ProviderCredentialSet, ProviderDecision, ProviderOutputRegistry,
};
use crate::config::compiler::MAX_PROVIDER_CREDENTIAL_BYTES;
use crate::safety::wire_body::{GuardedBodyBuilder, WireBodyBufferError};
use crate::safety::ProviderResponseCharge;

const MAX_KEY_BYTES: usize = 64;
const MAX_METADATA_BYTES: usize = 1024;

pub(super) enum ProcessEffectsParseError {
    Assigned(AssignedResponseError),
    Malformed,
    DuplicateId,
    Admission(WireBodyBufferError),
}

#[derive(Clone, Copy)]
enum AfterString {
    OutputValue,
    BodyEncoding,
    BodyContentType,
    BodyContentEncoding,
    BodyData,
}

#[derive(Clone, Copy)]
enum Phase {
    CommaAfterId,
    TypeKey(usize),
    TypeColon,
    TypeValue(usize),
    TypeComma,
    DecisionKey(usize),
    DecisionColon,
    DecisionValueStart,
    DecisionValue,
    AfterDecision,
    EffectKeyStart,
    EffectKey,
    ValuesColon,
    ValuesStart,
    ValuesEntryOrEnd,
    OutputKey,
    OutputColon,
    OutputValueStart,
    OutputValue,
    AfterOutputValue,
    AfterValues,
    BodyColon,
    BodyStart,
    BodyKeyStart,
    BodyKey,
    BodyValueColon,
    BodyValueStart,
    BodyString,
    AfterBodyValue,
    AfterBody,
    Trailing,
    Failed,
}

#[derive(Clone, Copy)]
enum EscapeState {
    Normal,
    Escaped,
    Unicode { value: u16, digits: u8 },
    LowBackslash { high: u16 },
    LowU { high: u16 },
    LowUnicode { high: u16, value: u16, digits: u8 },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Decision {
    Allow,
    Deny,
    Pass,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EffectKey {
    Values,
    Body,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BodyKey {
    Encoding,
    ContentType,
    ContentEncoding,
    Data,
}

pub(super) struct AssignedProcessEffectsParser<'a> {
    outputs: &'a ProviderOutputRegistry,
    max_decoded_replacement_bytes: Option<usize>,
    builder: Option<GuardedBodyBuilder>,
    values: Vec<Option<ProcessEffectRange>>,
    phase: Phase,
    decision: Option<Decision>,
    effect_key: Option<EffectKey>,
    body_key: Option<BodyKey>,
    seen_values: bool,
    seen_body: bool,
    seen_encoding: bool,
    seen_content_type: bool,
    seen_content_encoding: bool,
    seen_data: bool,
    key: Zeroizing<[u8; MAX_KEY_BYTES]>,
    key_len: usize,
    scalar: Zeroizing<[u8; 16]>,
    scalar_len: usize,
    output_index: Option<usize>,
    capture_start: usize,
    capture_valid: bool,
    replacement_range: Option<ProcessEffectRange>,
    content_type: Option<String>,
    content_encoding: Option<String>,
    metadata: Zeroizing<[u8; MAX_METADATA_BYTES]>,
    metadata_len: usize,
    escape: EscapeState,
    utf8: Zeroizing<[u8; 4]>,
    utf8_len: usize,
    utf8_need: usize,
    semantic_error: Option<AssignedResponseError>,
}

impl<'a> AssignedProcessEffectsParser<'a> {
    pub(super) fn new(
        outputs: &'a ProviderOutputRegistry,
        max_decoded_replacement_bytes: Option<usize>,
        charge: &ProviderResponseCharge,
    ) -> Self {
        Self {
            outputs,
            max_decoded_replacement_bytes,
            builder: Some(charge.buffer()),
            values: std::iter::repeat_with(|| None)
                .take(outputs.len())
                .collect(),
            phase: Phase::CommaAfterId,
            decision: None,
            effect_key: None,
            body_key: None,
            seen_values: false,
            seen_body: false,
            seen_encoding: false,
            seen_content_type: false,
            seen_content_encoding: false,
            seen_data: false,
            key: Zeroizing::new([0; MAX_KEY_BYTES]),
            key_len: 0,
            scalar: Zeroizing::new([0; 16]),
            scalar_len: 0,
            output_index: None,
            capture_start: 0,
            capture_valid: true,
            replacement_range: None,
            content_type: None,
            content_encoding: None,
            metadata: Zeroizing::new([0; MAX_METADATA_BYTES]),
            metadata_len: 0,
            escape: EscapeState::Normal,
            utf8: Zeroizing::new([0; 4]),
            utf8_len: 0,
            utf8_need: 0,
            semantic_error: None,
        }
    }

    pub(super) fn push(&mut self, byte: u8) -> Result<(), ProcessEffectsParseError> {
        let phase = self.phase;
        if is_whitespace(byte) && phase_accepts_whitespace(phase) {
            return Ok(());
        }
        self.phase = match phase {
            Phase::CommaAfterId if byte == b',' => Phase::TypeKey(0),
            Phase::CommaAfterId => return self.malformed(),
            Phase::TypeKey(position) => match_fixed(byte, position, b"\"type\"", Phase::TypeColon)?,
            Phase::TypeColon if byte == b':' => Phase::TypeValue(0),
            Phase::TypeColon => return self.malformed(),
            Phase::TypeValue(position) => {
                match_fixed(byte, position, b"\"response\"", Phase::TypeComma)?
            }
            Phase::TypeComma if byte == b',' => Phase::DecisionKey(0),
            Phase::TypeComma => return self.malformed(),
            Phase::DecisionKey(position) => {
                match_fixed(byte, position, b"\"decision\"", Phase::DecisionColon)?
            }
            Phase::DecisionColon if byte == b':' => Phase::DecisionValueStart,
            Phase::DecisionColon => return self.malformed(),
            Phase::DecisionValueStart if byte == b'"' => {
                self.scalar_len = 0;
                Phase::DecisionValue
            }
            Phase::DecisionValueStart => return self.malformed(),
            Phase::DecisionValue if byte == b'"' => {
                self.decision = match &self.scalar[..self.scalar_len] {
                    b"allow" => Some(Decision::Allow),
                    b"deny" => Some(Decision::Deny),
                    b"pass" => Some(Decision::Pass),
                    _ => {
                        self.record(AssignedResponseError::InvalidShape);
                        None
                    }
                };
                Phase::AfterDecision
            }
            Phase::DecisionValue
                if byte.is_ascii_lowercase() && self.scalar_len < self.scalar.len() =>
            {
                self.scalar[self.scalar_len] = byte;
                self.scalar_len += 1;
                Phase::DecisionValue
            }
            Phase::DecisionValue => return self.malformed(),
            Phase::AfterDecision if byte == b'}' => Phase::Trailing,
            Phase::AfterDecision if byte == b',' => {
                if self.decision != Some(Decision::Allow) {
                    self.record(AssignedResponseError::InvalidShape);
                }
                Phase::EffectKeyStart
            }
            Phase::AfterDecision => return self.malformed(),
            Phase::EffectKeyStart if byte == b'"' => {
                self.key_len = 0;
                Phase::EffectKey
            }
            Phase::EffectKeyStart => return self.malformed(),
            Phase::EffectKey if byte == b'"' => {
                self.effect_key = match &self.key[..self.key_len] {
                    b"values" if !self.seen_values && !self.seen_body => {
                        self.seen_values = true;
                        Some(EffectKey::Values)
                    }
                    b"requestBody" if !self.seen_body => {
                        self.seen_body = true;
                        Some(EffectKey::Body)
                    }
                    b"id" => return Err(ProcessEffectsParseError::DuplicateId),
                    _ => {
                        self.record(AssignedResponseError::InvalidShape);
                        None
                    }
                };
                match self.effect_key {
                    Some(EffectKey::Values) => Phase::ValuesColon,
                    Some(EffectKey::Body) => Phase::BodyColon,
                    None => Phase::Failed,
                }
            }
            Phase::EffectKey if valid_key_byte(byte) => {
                self.append_key(byte)?;
                Phase::EffectKey
            }
            Phase::EffectKey => return self.malformed(),
            Phase::ValuesColon if byte == b':' => Phase::ValuesStart,
            Phase::ValuesColon => return self.malformed(),
            Phase::ValuesStart if byte == b'{' => Phase::ValuesEntryOrEnd,
            Phase::ValuesStart => return self.malformed(),
            Phase::ValuesEntryOrEnd if byte == b'}' => Phase::AfterValues,
            Phase::ValuesEntryOrEnd if byte == b'"' => {
                self.key_len = 0;
                Phase::OutputKey
            }
            Phase::ValuesEntryOrEnd => return self.malformed(),
            Phase::OutputKey if byte == b'"' => {
                let name = std::str::from_utf8(&self.key[..self.key_len])
                    .map_err(|_| ProcessEffectsParseError::Malformed)?;
                self.output_index = self.outputs.index(name).map(|index| index.get());
                if let Some(index) = self.output_index {
                    if self.values[index].is_some() {
                        self.record(AssignedResponseError::DuplicateOutput);
                    }
                } else {
                    self.record(AssignedResponseError::UnknownOutput);
                }
                Phase::OutputColon
            }
            Phase::OutputKey if valid_key_byte(byte) => {
                self.append_key(byte)?;
                Phase::OutputKey
            }
            Phase::OutputKey => return self.malformed(),
            Phase::OutputColon if byte == b':' => Phase::OutputValueStart,
            Phase::OutputColon => return self.malformed(),
            Phase::OutputValueStart if byte == b'"' => {
                self.begin_capture();
                Phase::OutputValue
            }
            Phase::OutputValueStart => {
                self.record(AssignedResponseError::InvalidCredential);
                return self.malformed();
            }
            Phase::OutputValue => {
                if self.consume_string(byte, AfterString::OutputValue)? {
                    self.finish_output();
                    Phase::AfterOutputValue
                } else {
                    Phase::OutputValue
                }
            }
            Phase::AfterOutputValue if byte == b',' => Phase::ValuesEntryOrEnd,
            Phase::AfterOutputValue if byte == b'}' => Phase::AfterValues,
            Phase::AfterOutputValue => return self.malformed(),
            Phase::AfterValues if byte == b'}' => Phase::Trailing,
            Phase::AfterValues if byte == b',' => Phase::EffectKeyStart,
            Phase::AfterValues => return self.malformed(),
            Phase::BodyColon if byte == b':' => Phase::BodyStart,
            Phase::BodyColon => return self.malformed(),
            Phase::BodyStart if byte == b'{' => Phase::BodyKeyStart,
            Phase::BodyStart => return self.malformed(),
            Phase::BodyKeyStart if byte == b'"' => {
                self.key_len = 0;
                Phase::BodyKey
            }
            Phase::BodyKeyStart => return self.malformed(),
            Phase::BodyKey if byte == b'"' => {
                self.body_key = match &self.key[..self.key_len] {
                    b"encoding" if !self.seen_encoding => {
                        self.seen_encoding = true;
                        Some(BodyKey::Encoding)
                    }
                    b"contentType" if !self.seen_content_type => {
                        self.seen_content_type = true;
                        Some(BodyKey::ContentType)
                    }
                    b"contentEncoding" if !self.seen_content_encoding => {
                        self.seen_content_encoding = true;
                        Some(BodyKey::ContentEncoding)
                    }
                    b"data" if !self.seen_data => {
                        self.seen_data = true;
                        Some(BodyKey::Data)
                    }
                    _ => {
                        self.record(AssignedResponseError::InvalidBody);
                        None
                    }
                };
                Phase::BodyValueColon
            }
            Phase::BodyKey if valid_key_byte(byte) => {
                self.append_key(byte)?;
                Phase::BodyKey
            }
            Phase::BodyKey => return self.malformed(),
            Phase::BodyValueColon if byte == b':' => Phase::BodyValueStart,
            Phase::BodyValueColon => return self.malformed(),
            Phase::BodyValueStart if byte == b'"' => {
                match self.body_key {
                    Some(BodyKey::Data) => self.begin_capture(),
                    _ => self.begin_metadata(),
                }
                Phase::BodyString
            }
            Phase::BodyValueStart => return self.malformed(),
            Phase::BodyString => {
                let after = match self.body_key {
                    Some(BodyKey::Encoding) => AfterString::BodyEncoding,
                    Some(BodyKey::ContentType) => AfterString::BodyContentType,
                    Some(BodyKey::ContentEncoding) => AfterString::BodyContentEncoding,
                    Some(BodyKey::Data) => AfterString::BodyData,
                    None => return self.malformed(),
                };
                if self.consume_string(byte, after)? {
                    self.finish_body_value()?;
                    Phase::AfterBodyValue
                } else {
                    Phase::BodyString
                }
            }
            Phase::AfterBodyValue if byte == b',' => Phase::BodyKeyStart,
            Phase::AfterBodyValue if byte == b'}' => Phase::AfterBody,
            Phase::AfterBodyValue => return self.malformed(),
            Phase::AfterBody if byte == b'}' => Phase::Trailing,
            Phase::AfterBody => return self.malformed(),
            Phase::Trailing => return self.malformed(),
            Phase::Failed => return self.malformed(),
        };
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<ProviderDecision, ProcessEffectsParseError> {
        if !matches!(self.phase, Phase::Trailing) {
            return Err(ProcessEffectsParseError::Malformed);
        }
        if let Some(error) = self.semantic_error.take() {
            return Err(ProcessEffectsParseError::Assigned(error));
        }
        let decision = self.decision.ok_or(ProcessEffectsParseError::Assigned(
            AssignedResponseError::InvalidShape,
        ))?;
        if decision != Decision::Allow {
            return Ok(match decision {
                Decision::Deny => ProviderDecision::Deny,
                Decision::Pass => ProviderDecision::Pass,
                Decision::Allow => unreachable!(),
            });
        }
        if self
            .outputs
            .definitions()
            .iter()
            .zip(&self.values)
            .any(|(definition, value)| definition.required() && value.is_none())
        {
            return Err(ProcessEffectsParseError::Assigned(
                AssignedResponseError::MissingRequiredOutput,
            ));
        }
        if self.seen_body && (!self.seen_encoding || !self.seen_data) {
            return Err(ProcessEffectsParseError::Assigned(
                AssignedResponseError::InvalidBody,
            ));
        }
        let storage = Arc::new(
            self.builder
                .take()
                .expect("an active parser owns guarded effect storage")
                .finish(),
        );
        let replacement = if let Some(range) = self.replacement_range {
            let max =
                self.max_decoded_replacement_bytes
                    .ok_or(ProcessEffectsParseError::Assigned(
                        AssignedResponseError::BodyNotAllowed,
                    ))?;
            validate_base64(&storage, range, max).map_err(ProcessEffectsParseError::Assigned)?;
            Some(ProviderBodyReplacement::from_encoded(
                self.content_type,
                self.content_encoding,
                storage.clone(),
                range,
                max,
            ))
        } else {
            None
        };
        let credentials =
            ProviderCredentialSet::from_process_segmented(ProcessProviderCredentials::new(
                self.outputs.id(),
                self.values.into_boxed_slice(),
                storage,
            ));
        Ok(ProviderDecision::Allow {
            credentials,
            replacement,
        })
    }

    fn begin_capture(&mut self) {
        self.capture_start = self.builder().len();
        self.capture_valid = true;
        self.begin_string();
    }

    fn begin_metadata(&mut self) {
        self.metadata_len = 0;
        self.begin_string();
    }

    fn begin_string(&mut self) {
        self.escape = EscapeState::Normal;
        self.utf8_len = 0;
        self.utf8_need = 0;
    }

    fn consume_string(
        &mut self,
        byte: u8,
        target: AfterString,
    ) -> Result<bool, ProcessEffectsParseError> {
        if self.utf8_need != 0 {
            if !matches!(byte, 0x80..=0xbf) {
                return self.malformed();
            }
            self.utf8[self.utf8_len] = byte;
            self.utf8_len += 1;
            if self.utf8_len == self.utf8_need {
                std::str::from_utf8(&self.utf8[..self.utf8_len])
                    .map_err(|_| ProcessEffectsParseError::Malformed)?;
                let encoded = *self.utf8;
                let len = self.utf8_len;
                self.append_string(&encoded[..len], target)?;
                self.utf8_len = 0;
                self.utf8_need = 0;
            }
            return Ok(false);
        }
        match self.escape {
            EscapeState::Normal => match byte {
                b'"' => return Ok(true),
                b'\\' => self.escape = EscapeState::Escaped,
                0..=31 => return self.malformed(),
                32..=127 => self.append_string(&[byte], target)?,
                0xc2..=0xdf => self.begin_utf8(byte, 2),
                0xe0..=0xef => self.begin_utf8(byte, 3),
                0xf0..=0xf4 => self.begin_utf8(byte, 4),
                _ => return self.malformed(),
            },
            EscapeState::Escaped => match byte {
                b'"' | b'\\' | b'/' => self.append_escaped(&[byte], target)?,
                b'b' => self.append_escaped(&[8], target)?,
                b'f' => self.append_escaped(&[12], target)?,
                b'n' => self.append_escaped(b"\n", target)?,
                b'r' => self.append_escaped(b"\r", target)?,
                b't' => self.append_escaped(b"\t", target)?,
                b'u' => {
                    self.escape = EscapeState::Unicode {
                        value: 0,
                        digits: 0,
                    }
                }
                _ => return self.malformed(),
            },
            EscapeState::Unicode {
                mut value,
                mut digits,
            } => {
                value = (value << 4) | hex(byte).ok_or(ProcessEffectsParseError::Malformed)?;
                digits += 1;
                if digits != 4 {
                    self.escape = EscapeState::Unicode { value, digits };
                } else if (0xd800..=0xdbff).contains(&value) {
                    self.escape = EscapeState::LowBackslash { high: value };
                } else if (0xdc00..=0xdfff).contains(&value) {
                    return self.malformed();
                } else {
                    self.append_scalar(value as u32, target)?;
                }
            }
            EscapeState::LowBackslash { high } if byte == b'\\' => {
                self.escape = EscapeState::LowU { high };
            }
            EscapeState::LowBackslash { .. } => return self.malformed(),
            EscapeState::LowU { high } if byte == b'u' => {
                self.escape = EscapeState::LowUnicode {
                    high,
                    value: 0,
                    digits: 0,
                };
            }
            EscapeState::LowU { .. } => return self.malformed(),
            EscapeState::LowUnicode {
                high,
                mut value,
                mut digits,
            } => {
                value = (value << 4) | hex(byte).ok_or(ProcessEffectsParseError::Malformed)?;
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
                    self.append_scalar(scalar, target)?;
                } else {
                    return self.malformed();
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

    fn append_escaped(
        &mut self,
        bytes: &[u8],
        target: AfterString,
    ) -> Result<(), ProcessEffectsParseError> {
        self.append_string(bytes, target)?;
        self.escape = EscapeState::Normal;
        Ok(())
    }

    fn append_scalar(
        &mut self,
        scalar: u32,
        target: AfterString,
    ) -> Result<(), ProcessEffectsParseError> {
        let character = char::from_u32(scalar).ok_or(ProcessEffectsParseError::Malformed)?;
        let mut encoded = [0u8; 4];
        self.append_string(character.encode_utf8(&mut encoded).as_bytes(), target)?;
        self.escape = EscapeState::Normal;
        Ok(())
    }

    fn append_string(
        &mut self,
        bytes: &[u8],
        target: AfterString,
    ) -> Result<(), ProcessEffectsParseError> {
        match target {
            AfterString::OutputValue | AfterString::BodyData => {
                let current = self.builder().len() - self.capture_start;
                if matches!(target, AfterString::OutputValue)
                    && (current
                        .checked_add(bytes.len())
                        .is_none_or(|len| len > MAX_PROVIDER_CREDENTIAL_BYTES)
                        || bytes
                            .iter()
                            .any(|byte| *byte != b'\t' && (*byte < 32 || *byte == 127)))
                {
                    self.capture_valid = false;
                }
                self.builder()
                    .try_extend_from_slice(bytes)
                    .map_err(ProcessEffectsParseError::Admission)
            }
            _ => {
                let end = self
                    .metadata_len
                    .checked_add(bytes.len())
                    .filter(|end| *end <= self.metadata.len())
                    .ok_or(ProcessEffectsParseError::Assigned(
                        AssignedResponseError::InvalidBody,
                    ))?;
                self.metadata[self.metadata_len..end].copy_from_slice(bytes);
                self.metadata_len = end;
                Ok(())
            }
        }
    }

    fn finish_output(&mut self) {
        let end = self.builder().len();
        if end == self.capture_start || !self.capture_valid {
            self.record(AssignedResponseError::InvalidCredential);
        }
        if let Some(index) = self.output_index.take() {
            if self.values[index].is_none() {
                self.values[index] = Some(ProcessEffectRange {
                    start: self.capture_start,
                    end,
                });
            }
        }
    }

    fn finish_body_value(&mut self) -> Result<(), ProcessEffectsParseError> {
        match self.body_key.take() {
            Some(BodyKey::Encoding) => {
                if &self.metadata[..self.metadata_len] != b"base64" {
                    self.record(AssignedResponseError::InvalidBody);
                }
            }
            Some(BodyKey::ContentType) => {
                let value =
                    std::str::from_utf8(&self.metadata[..self.metadata_len]).map_err(|_| {
                        ProcessEffectsParseError::Assigned(AssignedResponseError::InvalidBody)
                    })?;
                if HeaderValue::from_str(value).is_err() {
                    self.record(AssignedResponseError::InvalidBody);
                } else {
                    self.content_type = Some(value.to_owned());
                }
            }
            Some(BodyKey::ContentEncoding) => {
                let value =
                    std::str::from_utf8(&self.metadata[..self.metadata_len]).map_err(|_| {
                        ProcessEffectsParseError::Assigned(AssignedResponseError::InvalidBody)
                    })?;
                if HeaderValue::from_str(value).is_err() || value != "identity" {
                    self.record(AssignedResponseError::InvalidBody);
                } else {
                    self.content_encoding = Some(value.to_owned());
                }
            }
            Some(BodyKey::Data) => {
                let end = self.builder().len();
                self.replacement_range = Some(ProcessEffectRange {
                    start: self.capture_start,
                    end,
                });
            }
            None => return self.malformed(),
        }
        self.metadata[..self.metadata_len].zeroize();
        self.metadata_len = 0;
        Ok(())
    }

    fn append_key(&mut self, byte: u8) -> Result<(), ProcessEffectsParseError> {
        if self.key_len == self.key.len() {
            return Err(ProcessEffectsParseError::Assigned(
                AssignedResponseError::InvalidShape,
            ));
        }
        self.key[self.key_len] = byte;
        self.key_len += 1;
        Ok(())
    }

    fn builder(&mut self) -> &mut GuardedBodyBuilder {
        self.builder
            .as_mut()
            .expect("an active parser owns guarded effect storage")
    }

    fn record(&mut self, error: AssignedResponseError) {
        if self.semantic_error.is_none() {
            self.semantic_error = Some(error);
        }
    }

    fn malformed<T>(&mut self) -> Result<T, ProcessEffectsParseError> {
        self.phase = Phase::Failed;
        self.builder.take();
        Err(ProcessEffectsParseError::Malformed)
    }
}

fn phase_accepts_whitespace(phase: Phase) -> bool {
    matches!(
        phase,
        Phase::CommaAfterId
            | Phase::TypeKey(0)
            | Phase::TypeColon
            | Phase::TypeValue(0)
            | Phase::TypeComma
            | Phase::DecisionKey(0)
            | Phase::DecisionColon
            | Phase::DecisionValueStart
            | Phase::AfterDecision
            | Phase::EffectKeyStart
            | Phase::ValuesColon
            | Phase::ValuesStart
            | Phase::ValuesEntryOrEnd
            | Phase::OutputColon
            | Phase::OutputValueStart
            | Phase::AfterOutputValue
            | Phase::AfterValues
            | Phase::BodyColon
            | Phase::BodyStart
            | Phase::BodyKeyStart
            | Phase::BodyValueColon
            | Phase::BodyValueStart
            | Phase::AfterBodyValue
            | Phase::AfterBody
            | Phase::Trailing
    )
}

fn match_fixed(
    byte: u8,
    position: usize,
    literal: &[u8],
    complete: Phase,
) -> Result<Phase, ProcessEffectsParseError> {
    if literal.get(position) != Some(&byte) {
        return Err(ProcessEffectsParseError::Assigned(
            AssignedResponseError::InvalidShape,
        ));
    }
    Ok(if position + 1 == literal.len() {
        complete
    } else {
        match complete {
            Phase::TypeColon => Phase::TypeKey(position + 1),
            Phase::TypeComma => Phase::TypeValue(position + 1),
            Phase::DecisionColon => Phase::DecisionKey(position + 1),
            _ => return Err(ProcessEffectsParseError::Malformed),
        }
    })
}

fn valid_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

fn hex(byte: u8) -> Option<u16> {
    match byte {
        b'0'..=b'9' => Some((byte - b'0') as u16),
        b'a'..=b'f' => Some((byte - b'a' + 10) as u16),
        b'A'..=b'F' => Some((byte - b'A' + 10) as u16),
        _ => None,
    }
}

fn validate_base64(
    storage: &crate::safety::GuardedBody,
    range: ProcessEffectRange,
    max_decoded_bytes: usize,
) -> Result<(), AssignedResponseError> {
    let mut quartet = [0u8; 4];
    let mut quartet_len = 0usize;
    let mut decoded_len = 0usize;
    let mut terminal = false;
    for byte in ProcessEffectSegments::new(storage, range)
        .flatten()
        .copied()
    {
        if terminal || !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')) {
            return Err(AssignedResponseError::InvalidBody);
        }
        quartet[quartet_len] = byte;
        quartet_len += 1;
        if quartet_len == 4 {
            let padding = match quartet {
                [_, _, b'=', b'='] => 2,
                [_, _, _, b'='] => 1,
                [_, _, _, _] if quartet.iter().all(|byte| *byte != b'=') => 0,
                _ => return Err(AssignedResponseError::InvalidBody),
            };
            decoded_len = decoded_len
                .checked_add(3 - padding)
                .filter(|len| *len <= max_decoded_bytes)
                .ok_or(AssignedResponseError::InvalidBody)?;
            let mut decoded = [0u8; 3];
            let written = BASE64_STANDARD
                .decode_slice(quartet, &mut decoded)
                .map_err(|_| AssignedResponseError::InvalidBody)?;
            if written != 3 - padding {
                return Err(AssignedResponseError::InvalidBody);
            }
            decoded.zeroize();
            terminal = padding != 0;
            quartet_len = 0;
        }
    }
    if quartet_len != 0 {
        return Err(AssignedResponseError::InvalidBody);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum JsonExpect {
    ObjectKeyOrEnd,
    ObjectKeyRequired,
    ObjectColon,
    ObjectValue,
    ObjectCommaOrEnd,
    ArrayValueOrEnd,
    ArrayValueRequired,
    ArrayCommaOrEnd,
}

#[derive(Clone, Copy)]
enum JsonMode {
    Structural,
    String {
        key: bool,
    },
    Number(NumberState),
    Literal {
        expected: &'static [u8],
        offset: usize,
    },
    Complete,
}

#[derive(Clone, Copy)]
enum NumberState {
    Minus,
    Zero,
    Integer,
    Dot,
    Fraction,
    Exponent,
    ExponentSign,
    ExponentDigits,
}

pub(super) struct AssignedTailSyntax {
    stack: [JsonExpect; 128],
    depth: usize,
    mode: JsonMode,
    escape: EscapeState,
    utf8: [u8; 4],
    utf8_len: usize,
    utf8_need: usize,
    key: [u8; MAX_KEY_BYTES],
    key_len: usize,
    key_overflow: bool,
    duplicate_id: bool,
}

impl AssignedTailSyntax {
    pub(super) fn new() -> Self {
        let mut stack = [JsonExpect::ObjectCommaOrEnd; 128];
        stack[0] = JsonExpect::ObjectCommaOrEnd;
        Self {
            stack,
            depth: 1,
            mode: JsonMode::Structural,
            escape: EscapeState::Normal,
            utf8: [0; 4],
            utf8_len: 0,
            utf8_need: 0,
            key: [0; MAX_KEY_BYTES],
            key_len: 0,
            key_overflow: false,
            duplicate_id: false,
        }
    }

    pub(super) fn push(&mut self, byte: u8) -> Result<(), ()> {
        let mut current = Some(byte);
        while let Some(byte) = current.take() {
            match self.mode {
                JsonMode::Complete => {
                    if !is_whitespace(byte) {
                        return Err(());
                    }
                }
                JsonMode::String { key } => self.push_string(byte, key)?,
                JsonMode::Literal { expected, offset } => {
                    if expected.get(offset) != Some(&byte) {
                        return Err(());
                    }
                    if offset + 1 == expected.len() {
                        self.mode = JsonMode::Structural;
                    } else {
                        self.mode = JsonMode::Literal {
                            expected,
                            offset: offset + 1,
                        };
                    }
                }
                JsonMode::Number(state) => match number_step(state, byte)? {
                    Some(next) => self.mode = JsonMode::Number(next),
                    None => {
                        self.mode = JsonMode::Structural;
                        current = Some(byte);
                    }
                },
                JsonMode::Structural => self.push_structural(byte)?,
            }
        }
        Ok(())
    }

    pub(super) fn finish(&self) -> Result<(), ()> {
        if self.duplicate_id {
            return Err(());
        }
        match self.mode {
            JsonMode::Complete => Ok(()),
            JsonMode::Number(
                NumberState::Zero
                | NumberState::Integer
                | NumberState::Fraction
                | NumberState::ExponentDigits,
            ) if self.depth == 0 => Ok(()),
            _ => Err(()),
        }
    }

    pub(super) fn duplicate_id(&self) -> bool {
        self.duplicate_id
    }

    fn push_structural(&mut self, byte: u8) -> Result<(), ()> {
        if is_whitespace(byte) {
            return Ok(());
        }
        let expect = *self
            .stack
            .get(self.depth.checked_sub(1).ok_or(())?)
            .ok_or(())?;
        match expect {
            JsonExpect::ObjectCommaOrEnd => match byte {
                b',' => self.stack[self.depth - 1] = JsonExpect::ObjectKeyRequired,
                b'}' => self.close_container()?,
                _ => return Err(()),
            },
            JsonExpect::ObjectKeyOrEnd => match byte {
                b'}' => self.close_container()?,
                b'"' => {
                    self.key_len = 0;
                    self.key_overflow = false;
                    self.begin_json_string(true);
                }
                _ => return Err(()),
            },
            JsonExpect::ObjectKeyRequired => {
                if byte != b'"' {
                    return Err(());
                }
                self.key_len = 0;
                self.key_overflow = false;
                self.begin_json_string(true);
            }
            JsonExpect::ObjectColon => {
                if byte != b':' {
                    return Err(());
                }
                self.stack[self.depth - 1] = JsonExpect::ObjectValue;
            }
            JsonExpect::ObjectValue => self.begin_value(byte, JsonExpect::ObjectCommaOrEnd)?,
            JsonExpect::ArrayValueOrEnd => {
                if byte == b']' {
                    self.close_container()?;
                } else {
                    self.begin_value(byte, JsonExpect::ArrayCommaOrEnd)?;
                }
            }
            JsonExpect::ArrayValueRequired => {
                self.begin_value(byte, JsonExpect::ArrayCommaOrEnd)?;
            }
            JsonExpect::ArrayCommaOrEnd => match byte {
                b',' => self.stack[self.depth - 1] = JsonExpect::ArrayValueRequired,
                b']' => self.close_container()?,
                _ => return Err(()),
            },
        }
        Ok(())
    }

    fn begin_value(&mut self, byte: u8, after: JsonExpect) -> Result<(), ()> {
        self.stack[self.depth - 1] = after;
        match byte {
            b'"' => self.begin_json_string(false),
            b'{' => self.push_container(JsonExpect::ObjectKeyOrEnd)?,
            b'[' => self.push_container(JsonExpect::ArrayValueOrEnd)?,
            b't' => {
                self.mode = JsonMode::Literal {
                    expected: b"true",
                    offset: 1,
                }
            }
            b'f' => {
                self.mode = JsonMode::Literal {
                    expected: b"false",
                    offset: 1,
                }
            }
            b'n' => {
                self.mode = JsonMode::Literal {
                    expected: b"null",
                    offset: 1,
                }
            }
            b'-' => self.mode = JsonMode::Number(NumberState::Minus),
            b'0' => self.mode = JsonMode::Number(NumberState::Zero),
            b'1'..=b'9' => self.mode = JsonMode::Number(NumberState::Integer),
            _ => return Err(()),
        }
        Ok(())
    }

    fn push_container(&mut self, expect: JsonExpect) -> Result<(), ()> {
        if self.depth == 127 {
            return Err(());
        }
        self.stack[self.depth] = expect;
        self.depth += 1;
        Ok(())
    }

    fn close_container(&mut self) -> Result<(), ()> {
        self.depth = self.depth.checked_sub(1).ok_or(())?;
        if self.depth == 0 {
            self.mode = JsonMode::Complete;
        }
        Ok(())
    }

    fn begin_json_string(&mut self, key: bool) {
        self.escape = EscapeState::Normal;
        self.utf8_len = 0;
        self.utf8_need = 0;
        self.mode = JsonMode::String { key };
    }

    fn push_string(&mut self, byte: u8, key: bool) -> Result<(), ()> {
        if self.utf8_need != 0 {
            if !matches!(byte, 0x80..=0xbf) {
                return Err(());
            }
            self.utf8[self.utf8_len] = byte;
            self.utf8_len += 1;
            if self.utf8_len == self.utf8_need {
                std::str::from_utf8(&self.utf8[..self.utf8_len]).map_err(|_| ())?;
                let utf8 = self.utf8;
                let len = self.utf8_len;
                self.capture_key(&utf8[..len], key);
                self.utf8_len = 0;
                self.utf8_need = 0;
            }
            return Ok(());
        }
        match self.escape {
            EscapeState::Normal => match byte {
                b'"' => {
                    if key {
                        if self.depth == 1
                            && !self.key_overflow
                            && &self.key[..self.key_len] == b"id"
                        {
                            self.duplicate_id = true;
                        }
                        self.stack[self.depth - 1] = JsonExpect::ObjectColon;
                    }
                    self.mode = JsonMode::Structural;
                }
                b'\\' => self.escape = EscapeState::Escaped,
                0..=31 => return Err(()),
                32..=127 => self.capture_key(&[byte], key),
                0xc2..=0xdf => self.begin_syntax_utf8(byte, 2),
                0xe0..=0xef => self.begin_syntax_utf8(byte, 3),
                0xf0..=0xf4 => self.begin_syntax_utf8(byte, 4),
                _ => return Err(()),
            },
            EscapeState::Escaped => match byte {
                b'"' | b'\\' | b'/' => {
                    self.capture_key(&[byte], key);
                    self.escape = EscapeState::Normal;
                }
                b'b' | b'f' | b'n' | b'r' | b't' => {
                    let decoded = match byte {
                        b'b' => 8,
                        b'f' => 12,
                        b'n' => b'\n',
                        b'r' => b'\r',
                        _ => b'\t',
                    };
                    self.capture_key(&[decoded], key);
                    self.escape = EscapeState::Normal;
                }
                b'u' => {
                    self.escape = EscapeState::Unicode {
                        value: 0,
                        digits: 0,
                    }
                }
                _ => return Err(()),
            },
            EscapeState::Unicode {
                mut value,
                mut digits,
            } => {
                value = (value << 4) | hex(byte).ok_or(())?;
                digits += 1;
                if digits != 4 {
                    self.escape = EscapeState::Unicode { value, digits };
                } else if (0xd800..=0xdbff).contains(&value) {
                    self.escape = EscapeState::LowBackslash { high: value };
                } else if (0xdc00..=0xdfff).contains(&value) {
                    return Err(());
                } else {
                    self.capture_scalar(value as u32, key)?;
                }
            }
            EscapeState::LowBackslash { high } if byte == b'\\' => {
                self.escape = EscapeState::LowU { high };
            }
            EscapeState::LowBackslash { .. } => return Err(()),
            EscapeState::LowU { high } if byte == b'u' => {
                self.escape = EscapeState::LowUnicode {
                    high,
                    value: 0,
                    digits: 0,
                };
            }
            EscapeState::LowU { .. } => return Err(()),
            EscapeState::LowUnicode {
                high,
                mut value,
                mut digits,
            } => {
                value = (value << 4) | hex(byte).ok_or(())?;
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
                    self.capture_scalar(scalar, key)?;
                } else {
                    return Err(());
                }
            }
        }
        Ok(())
    }

    fn begin_syntax_utf8(&mut self, byte: u8, width: usize) {
        self.utf8[0] = byte;
        self.utf8_len = 1;
        self.utf8_need = width;
    }

    fn capture_scalar(&mut self, scalar: u32, key: bool) -> Result<(), ()> {
        let character = char::from_u32(scalar).ok_or(())?;
        let mut encoded = [0u8; 4];
        self.capture_key(character.encode_utf8(&mut encoded).as_bytes(), key);
        self.escape = EscapeState::Normal;
        Ok(())
    }

    fn capture_key(&mut self, bytes: &[u8], key: bool) {
        if !key || self.depth != 1 || self.key_overflow {
            return;
        }
        let Some(end) = self.key_len.checked_add(bytes.len()) else {
            self.key_overflow = true;
            return;
        };
        if end > self.key.len() {
            self.key_overflow = true;
            return;
        }
        self.key[self.key_len..end].copy_from_slice(bytes);
        self.key_len = end;
    }
}

fn is_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t')
}

fn number_step(state: NumberState, byte: u8) -> Result<Option<NumberState>, ()> {
    let next = match (state, byte) {
        (NumberState::Minus, b'0') => Some(NumberState::Zero),
        (NumberState::Minus, b'1'..=b'9') => Some(NumberState::Integer),
        (NumberState::Zero | NumberState::Integer, b'.') => Some(NumberState::Dot),
        (NumberState::Integer, b'0'..=b'9') => Some(NumberState::Integer),
        (NumberState::Dot, b'0'..=b'9') => Some(NumberState::Fraction),
        (NumberState::Fraction, b'0'..=b'9') => Some(NumberState::Fraction),
        (NumberState::Zero | NumberState::Integer | NumberState::Fraction, b'e' | b'E') => {
            Some(NumberState::Exponent)
        }
        (NumberState::Exponent, b'+' | b'-') => Some(NumberState::ExponentSign),
        (NumberState::Exponent | NumberState::ExponentSign, b'0'..=b'9') => {
            Some(NumberState::ExponentDigits)
        }
        (NumberState::ExponentDigits, b'0'..=b'9') => Some(NumberState::ExponentDigits),
        (
            NumberState::Zero
            | NumberState::Integer
            | NumberState::Fraction
            | NumberState::ExponentDigits,
            _,
        ) => None,
        _ => return Err(()),
    };
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::AssignedTailSyntax;

    fn validate(tail: &[u8]) -> Result<AssignedTailSyntax, ()> {
        let mut syntax = AssignedTailSyntax::new();
        for byte in tail {
            syntax.push(*byte)?;
        }
        syntax.finish()?;
        Ok(syntax)
    }

    #[test]
    fn assigned_tail_rejects_trailing_commas_and_duplicate_id_escapes() {
        for tail in [
            br#","type":"response",}"#.as_slice(),
            br#","type":"response","unknown":[1,]}"#.as_slice(),
        ] {
            assert!(validate(tail).is_err());
        }

        let mut duplicate = AssignedTailSyntax::new();
        for byte in br#","\u0069d":"again"}"# {
            duplicate.push(*byte).unwrap();
        }
        assert!(duplicate.duplicate_id());
    }

    #[test]
    fn assigned_tail_accepts_127_containers_and_rejects_reaching_128() {
        fn nested(arrays: usize) -> Vec<u8> {
            let mut tail = br#","unknown":"#.to_vec();
            tail.extend(std::iter::repeat_n(b'[', arrays));
            tail.push(b'0');
            tail.extend(std::iter::repeat_n(b']', arrays));
            tail.push(b'}');
            tail
        }

        assert!(validate(&nested(126)).is_ok());
        assert!(validate(&nested(127)).is_err());
    }
}
