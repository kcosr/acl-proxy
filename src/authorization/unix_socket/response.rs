use access_rpc_framing::SensitiveFrameBody;
use allocator_api2::boxed::Box as FallibleBox;
use zeroize::Zeroizing;

use super::super::protocol::{
    projected_provider_credential_wire_metadata_bytes, ProcessEffectRange, ProviderCredentialSet,
    ProviderDecision, ProviderOutputRegistry, UnixProviderCredentials,
};
use crate::config::compiler::MAX_PROVIDER_CREDENTIAL_BYTES;
use crate::runtime::AuthorizationInvocationMode;
use crate::safety::ProviderResponseCharge;

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum AwapResponseError {
    #[error("Unix authorization response is malformed JSON")]
    MalformedJson,
    #[error("Unix authorization response contains a duplicate field")]
    DuplicateField,
    #[error("Unix authorization response contains an unknown field")]
    UnknownField,
    #[error("Unix authorization response contains a request body")]
    BodyNotAllowed,
    #[error("Unix authorization response has an invalid typed field")]
    InvalidShape,
    #[error("Unix authorization response ID does not match its request")]
    RequestIdMismatch,
    #[error("Unix authorization response values are not allowed for this invocation")]
    ValuesNotAllowed,
    #[error("Unix authorization response contains an unknown output")]
    UnknownOutput,
    #[error("Unix authorization response repeats an output")]
    DuplicateOutput,
    #[error("Unix authorization response omits a required output")]
    MissingRequiredOutput,
    #[error("Unix authorization response contains invalid credential material")]
    InvalidCredential,
    #[error("Unix authorization response has trailing data")]
    TrailingData,
    #[error("Unix authorization response storage could not be allocated")]
    Allocation,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Decision {
    Allow,
    Deny,
    Pass,
}

#[derive(Clone, Copy)]
struct JsonStringToken {
    raw: ProcessEffectRange,
    decoded_len: usize,
    credential_valid: bool,
}

struct ParsedResponse {
    decision: Decision,
    values_present: bool,
    material_bytes: usize,
}

/// Parses one sensitive AWAP response while its zeroizing frame remains alive.
///
/// Credential values are never materialized as ordinary strings. The first
/// pass retains only source ranges, then exact guarded zeroizing storage is
/// allocated and filled directly from the sensitive frame.
pub(crate) fn parse_sensitive_response(
    body: &SensitiveFrameBody,
    expected_request_id: &str,
    invocation: AuthorizationInvocationMode,
    outputs: &ProviderOutputRegistry,
    charge: &ProviderResponseCharge,
) -> Result<ProviderDecision, AwapResponseError> {
    body.expose(|bytes| {
        parse_response_bytes(bytes, expected_request_id, invocation, outputs, charge)
    })
}

fn parse_response_bytes(
    bytes: &[u8],
    expected_request_id: &str,
    invocation: AuthorizationInvocationMode,
    outputs: &ProviderOutputRegistry,
    charge: &ProviderResponseCharge,
) -> Result<ProviderDecision, AwapResponseError> {
    let metadata_bytes = projected_provider_credential_wire_metadata_bytes(outputs.len())
        .ok_or(AwapResponseError::Allocation)?;
    let metadata_charge = charge
        .charge_exact_allocation(metadata_bytes)
        .map_err(|_| AwapResponseError::Allocation)?;
    let mut values = allocate_slots(outputs.len())?;
    let mut cursor = JsonCursor::new(bytes);
    let parsed = cursor.parse_response(expected_request_id, outputs, &mut values)?;

    match (invocation, parsed.decision, parsed.values_present) {
        (AuthorizationInvocationMode::DecisionOnly, _, true)
        | (AuthorizationInvocationMode::EffectsAllowed, Decision::Deny | Decision::Pass, true) => {
            return Err(AwapResponseError::ValuesNotAllowed)
        }
        _ => {}
    }

    match parsed.decision {
        Decision::Deny => Ok(ProviderDecision::Deny),
        Decision::Pass => Ok(ProviderDecision::Pass),
        Decision::Allow if invocation == AuthorizationInvocationMode::DecisionOnly => {
            Ok(ProviderDecision::AllowWithoutEffects)
        }
        Decision::Allow => {
            if outputs
                .definitions()
                .iter()
                .zip(values.iter())
                .any(|(definition, value)| definition.required() && value.is_none())
            {
                return Err(AwapResponseError::MissingRequiredOutput);
            }
            let mut storage = charge
                .exact_bytes(parsed.material_bytes)
                .map_err(|_| AwapResponseError::Allocation)?;
            let mut destination_offset = 0usize;
            for slot in values.iter_mut().flatten() {
                let source = *slot;
                let written = decode_string(
                    bytes
                        .get(source.start..source.end)
                        .ok_or(AwapResponseError::MalformedJson)?,
                    storage
                        .as_mut_slice()
                        .get_mut(destination_offset..)
                        .ok_or(AwapResponseError::Allocation)?,
                )?;
                let end = destination_offset
                    .checked_add(written)
                    .ok_or(AwapResponseError::Allocation)?;
                *slot = ProcessEffectRange {
                    start: destination_offset,
                    end,
                };
                destination_offset = end;
            }
            if destination_offset != parsed.material_bytes {
                return Err(AwapResponseError::MalformedJson);
            }
            Ok(ProviderDecision::Allow {
                credentials: ProviderCredentialSet::from_unix(UnixProviderCredentials::new(
                    outputs.id(),
                    values,
                    storage,
                    metadata_charge,
                )),
                replacement: None,
            })
        }
    }
}

fn allocate_slots(
    count: usize,
) -> Result<FallibleBox<[Option<ProcessEffectRange>]>, AwapResponseError> {
    let mut slots = FallibleBox::<[Option<ProcessEffectRange>]>::try_new_uninit_slice(count)
        .map_err(|_| AwapResponseError::Allocation)?;
    for slot in slots.iter_mut() {
        slot.write(None);
    }
    // Every element is initialized in the complete loop above.
    Ok(unsafe { slots.assume_init() })
}

struct JsonCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> JsonCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn parse_response(
        &mut self,
        expected_request_id: &str,
        outputs: &ProviderOutputRegistry,
        values: &mut [Option<ProcessEffectRange>],
    ) -> Result<ParsedResponse, AwapResponseError> {
        self.skip_whitespace();
        self.expect(b'{')?;
        let mut seen_id = false;
        let mut seen_type = false;
        let mut seen_decision = false;
        let mut seen_values = false;
        let mut decision = None;
        let mut material_bytes = 0usize;
        self.skip_whitespace();
        if self.consume(b'}') {
            return Err(AwapResponseError::InvalidShape);
        }
        loop {
            let key = self.parse_string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            if self.token_equals(key, b"id")? {
                if seen_id {
                    return Err(AwapResponseError::DuplicateField);
                }
                seen_id = true;
                let id = self.parse_string()?;
                if !self.token_equals(id, expected_request_id.as_bytes())? {
                    return Err(AwapResponseError::RequestIdMismatch);
                }
            } else if self.token_equals(key, b"type")? {
                if seen_type {
                    return Err(AwapResponseError::DuplicateField);
                }
                seen_type = true;
                let value = self.parse_string()?;
                if !self.token_equals(value, b"response")? {
                    return Err(AwapResponseError::InvalidShape);
                }
            } else if self.token_equals(key, b"decision")? {
                if seen_decision {
                    return Err(AwapResponseError::DuplicateField);
                }
                seen_decision = true;
                let value = self.parse_string()?;
                decision = if self.token_equals(value, b"allow")? {
                    Some(Decision::Allow)
                } else if self.token_equals(value, b"deny")? {
                    Some(Decision::Deny)
                } else if self.token_equals(value, b"pass")? {
                    Some(Decision::Pass)
                } else {
                    return Err(AwapResponseError::InvalidShape);
                };
            } else if self.token_equals(key, b"values")? {
                if seen_values {
                    return Err(AwapResponseError::DuplicateField);
                }
                seen_values = true;
                material_bytes = self.parse_values(outputs, values, material_bytes)?;
            } else if self.token_equals(key, b"body")? {
                return Err(AwapResponseError::BodyNotAllowed);
            } else {
                return Err(AwapResponseError::UnknownField);
            }

            self.skip_whitespace();
            if self.consume(b'}') {
                break;
            }
            self.expect(b',')?;
            self.skip_whitespace();
        }
        self.skip_whitespace();
        if self.position != self.bytes.len() {
            return Err(AwapResponseError::TrailingData);
        }
        if !seen_id || !seen_type || !seen_decision {
            return Err(AwapResponseError::InvalidShape);
        }
        Ok(ParsedResponse {
            decision: decision.ok_or(AwapResponseError::InvalidShape)?,
            values_present: seen_values,
            material_bytes,
        })
    }

    fn parse_values(
        &mut self,
        outputs: &ProviderOutputRegistry,
        values: &mut [Option<ProcessEffectRange>],
        mut material_bytes: usize,
    ) -> Result<usize, AwapResponseError> {
        self.expect(b'{')?;
        self.skip_whitespace();
        if self.consume(b'}') {
            return Ok(material_bytes);
        }
        loop {
            let name = self.parse_string()?;
            let mut output = None;
            for candidate in outputs.wire_names() {
                if self.token_equals(name, candidate.as_bytes())? {
                    output = outputs.index(candidate);
                    break;
                }
            }
            let output = output.ok_or(AwapResponseError::UnknownOutput)?;
            let slot = values
                .get_mut(output.get())
                .ok_or(AwapResponseError::UnknownOutput)?;
            if slot.is_some() {
                return Err(AwapResponseError::DuplicateOutput);
            }
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let value = self.parse_string()?;
            if value.decoded_len == 0
                || value.decoded_len > MAX_PROVIDER_CREDENTIAL_BYTES
                || !value.credential_valid
            {
                return Err(AwapResponseError::InvalidCredential);
            }
            material_bytes = material_bytes
                .checked_add(value.decoded_len)
                .ok_or(AwapResponseError::Allocation)?;
            *slot = Some(value.raw);

            self.skip_whitespace();
            if self.consume(b'}') {
                return Ok(material_bytes);
            }
            self.expect(b',')?;
            self.skip_whitespace();
        }
    }

    fn parse_string(&mut self) -> Result<JsonStringToken, AwapResponseError> {
        self.expect(b'"')?;
        let raw_start = self.position;
        let mut decoded_len = 0usize;
        let mut credential_valid = true;
        loop {
            let byte = *self
                .bytes
                .get(self.position)
                .ok_or(AwapResponseError::MalformedJson)?;
            match byte {
                b'"' => {
                    let raw_end = self.position;
                    self.position += 1;
                    return Ok(JsonStringToken {
                        raw: ProcessEffectRange {
                            start: raw_start,
                            end: raw_end,
                        },
                        decoded_len,
                        credential_valid,
                    });
                }
                b'\\' => {
                    self.position += 1;
                    let escaped = *self
                        .bytes
                        .get(self.position)
                        .ok_or(AwapResponseError::MalformedJson)?;
                    self.position += 1;
                    match escaped {
                        b'"' | b'\\' | b'/' => {
                            decoded_len = checked_add(decoded_len, 1)?;
                        }
                        b'b' | b'f' | b'n' | b'r' => {
                            decoded_len = checked_add(decoded_len, 1)?;
                            credential_valid = false;
                        }
                        b't' => {
                            decoded_len = checked_add(decoded_len, 1)?;
                        }
                        b'u' => {
                            let scalar = self.parse_unicode_escape()?;
                            let character =
                                char::from_u32(scalar).ok_or(AwapResponseError::MalformedJson)?;
                            decoded_len = checked_add(decoded_len, character.len_utf8())?;
                            if (scalar < 32 && scalar != 9) || scalar == 127 {
                                credential_valid = false;
                            }
                        }
                        _ => return Err(AwapResponseError::MalformedJson),
                    }
                }
                0..=31 => return Err(AwapResponseError::MalformedJson),
                32..=126 => {
                    self.position += 1;
                    decoded_len = checked_add(decoded_len, 1)?;
                    if byte == 127 {
                        credential_valid = false;
                    }
                }
                127 => {
                    self.position += 1;
                    decoded_len = checked_add(decoded_len, 1)?;
                    credential_valid = false;
                }
                _ => {
                    let width = utf8_width(byte).ok_or(AwapResponseError::MalformedJson)?;
                    let end = self
                        .position
                        .checked_add(width)
                        .filter(|end| *end <= self.bytes.len())
                        .ok_or(AwapResponseError::MalformedJson)?;
                    std::str::from_utf8(&self.bytes[self.position..end])
                        .map_err(|_| AwapResponseError::MalformedJson)?;
                    self.position = end;
                    decoded_len = checked_add(decoded_len, width)?;
                }
            }
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<u32, AwapResponseError> {
        let high = self.parse_hex_quad()?;
        if (0xd800..=0xdbff).contains(&high) {
            if self.bytes.get(self.position..self.position + 2) != Some(b"\\u") {
                return Err(AwapResponseError::MalformedJson);
            }
            self.position += 2;
            let low = self.parse_hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&low) {
                return Err(AwapResponseError::MalformedJson);
            }
            Ok(0x1_0000 + (((u32::from(high) - 0xd800) << 10) | (u32::from(low) - 0xdc00)))
        } else if (0xdc00..=0xdfff).contains(&high) {
            Err(AwapResponseError::MalformedJson)
        } else {
            Ok(u32::from(high))
        }
    }

    fn parse_hex_quad(&mut self) -> Result<u16, AwapResponseError> {
        let end = self
            .position
            .checked_add(4)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(AwapResponseError::MalformedJson)?;
        let mut value = 0u16;
        for byte in &self.bytes[self.position..end] {
            value = (value << 4) | hex(*byte).ok_or(AwapResponseError::MalformedJson)?;
        }
        self.position = end;
        Ok(value)
    }

    fn token_equals(
        &self,
        token: JsonStringToken,
        expected: &[u8],
    ) -> Result<bool, AwapResponseError> {
        if token.decoded_len != expected.len() {
            return Ok(false);
        }
        let mut offset = 0usize;
        decode_chunks(
            self.bytes
                .get(token.raw.start..token.raw.end)
                .ok_or(AwapResponseError::MalformedJson)?,
            |chunk| {
                let end = offset
                    .checked_add(chunk.len())
                    .ok_or(AwapResponseError::MalformedJson)?;
                if expected.get(offset..end) != Some(chunk) {
                    return Err(AwapResponseError::InvalidShape);
                }
                offset = end;
                Ok(())
            },
        )
        .map(|_| offset == expected.len())
        .or_else(|error| match error {
            AwapResponseError::InvalidShape => Ok(false),
            _ => Err(error),
        })
    }

    fn skip_whitespace(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.position += 1;
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), AwapResponseError> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(AwapResponseError::MalformedJson)
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.bytes.get(self.position) == Some(&expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }
}

fn checked_add(value: usize, increment: usize) -> Result<usize, AwapResponseError> {
    value
        .checked_add(increment)
        .ok_or(AwapResponseError::MalformedJson)
}

fn utf8_width(byte: u8) -> Option<usize> {
    match byte {
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

fn hex(byte: u8) -> Option<u16> {
    match byte {
        b'0'..=b'9' => Some(u16::from(byte - b'0')),
        b'a'..=b'f' => Some(u16::from(byte - b'a' + 10)),
        b'A'..=b'F' => Some(u16::from(byte - b'A' + 10)),
        _ => None,
    }
}

fn decode_string(raw: &[u8], destination: &mut [u8]) -> Result<usize, AwapResponseError> {
    let mut written = 0usize;
    decode_chunks(raw, |chunk| {
        let end = written
            .checked_add(chunk.len())
            .ok_or(AwapResponseError::MalformedJson)?;
        let target = destination
            .get_mut(written..end)
            .ok_or(AwapResponseError::Allocation)?;
        target.copy_from_slice(chunk);
        written = end;
        Ok(())
    })?;
    Ok(written)
}

fn decode_chunks(
    raw: &[u8],
    mut output: impl FnMut(&[u8]) -> Result<(), AwapResponseError>,
) -> Result<(), AwapResponseError> {
    let mut position = 0usize;
    while position < raw.len() {
        match raw[position] {
            b'\\' => {
                position += 1;
                let escaped = *raw.get(position).ok_or(AwapResponseError::MalformedJson)?;
                position += 1;
                match escaped {
                    b'"' | b'\\' | b'/' => output(&[escaped])?,
                    b'b' => output(&[8])?,
                    b'f' => output(&[12])?,
                    b'n' => output(b"\n")?,
                    b'r' => output(b"\r")?,
                    b't' => output(b"\t")?,
                    b'u' => {
                        let (scalar, consumed) = decode_unicode_escape(&raw[position..])?;
                        position = position
                            .checked_add(consumed)
                            .ok_or(AwapResponseError::MalformedJson)?;
                        let character =
                            char::from_u32(scalar).ok_or(AwapResponseError::MalformedJson)?;
                        let mut encoded = Zeroizing::new([0u8; 4]);
                        let encoded = character.encode_utf8(&mut encoded[..]).as_bytes();
                        output(encoded)?;
                    }
                    _ => return Err(AwapResponseError::MalformedJson),
                }
            }
            0..=31 | b'"' => return Err(AwapResponseError::MalformedJson),
            byte @ 32..=127 => {
                output(&[byte])?;
                position += 1;
            }
            byte => {
                let width = utf8_width(byte).ok_or(AwapResponseError::MalformedJson)?;
                let end = position
                    .checked_add(width)
                    .filter(|end| *end <= raw.len())
                    .ok_or(AwapResponseError::MalformedJson)?;
                std::str::from_utf8(&raw[position..end])
                    .map_err(|_| AwapResponseError::MalformedJson)?;
                output(&raw[position..end])?;
                position = end;
            }
        }
    }
    Ok(())
}

fn decode_unicode_escape(raw: &[u8]) -> Result<(u32, usize), AwapResponseError> {
    let high = decode_hex_quad(raw.get(..4).ok_or(AwapResponseError::MalformedJson)?)?;
    if (0xd800..=0xdbff).contains(&high) {
        if raw.get(4..6) != Some(b"\\u") {
            return Err(AwapResponseError::MalformedJson);
        }
        let low = decode_hex_quad(raw.get(6..10).ok_or(AwapResponseError::MalformedJson)?)?;
        if !(0xdc00..=0xdfff).contains(&low) {
            return Err(AwapResponseError::MalformedJson);
        }
        Ok((
            0x1_0000 + (((u32::from(high) - 0xd800) << 10) | (u32::from(low) - 0xdc00)),
            10,
        ))
    } else if (0xdc00..=0xdfff).contains(&high) {
        Err(AwapResponseError::MalformedJson)
    } else {
        Ok((u32::from(high), 4))
    }
}

fn decode_hex_quad(raw: &[u8]) -> Result<u16, AwapResponseError> {
    if raw.len() != 4 {
        return Err(AwapResponseError::MalformedJson);
    }
    raw.iter().try_fold(0u16, |value, byte| {
        hex(*byte)
            .map(|digit| (value << 4) | digit)
            .ok_or(AwapResponseError::MalformedJson)
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::config::compiler::{
        CompiledTransportSecurity, ProviderOutputPlan, MAX_PROVIDER_CREDENTIAL_BYTES,
    };
    use crate::safety::{HttpWireBodyGuard, WireBodyPool, WireBodyQuotaKey};

    fn outputs(required: bool) -> ProviderOutputRegistry {
        ProviderOutputRegistry::activate(BTreeMap::from([(
            "api_token".to_string(),
            ProviderOutputPlan::Bearer {
                required,
                transport_security: CompiledTransportSecurity::TlsRequired,
            },
        )]))
    }

    fn guard(peak: usize) -> (std::sync::Arc<WireBodyPool>, HttpWireBodyGuard) {
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(
            peak,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );
        (pool, guard)
    }

    fn parse(
        json: &[u8],
        invocation: AuthorizationInvocationMode,
        outputs: &ProviderOutputRegistry,
        guard: &HttpWireBodyGuard,
    ) -> Result<ProviderDecision, AwapResponseError> {
        let body = SensitiveFrameBody::new(json.to_vec()).unwrap();
        parse_sensitive_response(
            &body,
            "protocol-1",
            invocation,
            outputs,
            &guard.provider_response_charge(),
        )
    }

    #[test]
    fn production_response_parser_accepts_every_language_neutral_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/awap/v1.json"
        )))
        .unwrap();
        let outputs = outputs(true);
        for (index, expected) in ["allow", "deny", "pass"].into_iter().enumerate() {
            let body = fixture["vectors"][index + 1]["body"].as_str().unwrap();
            let (pool, guard) = guard(4096);
            let sensitive = SensitiveFrameBody::new(body.as_bytes().to_vec()).unwrap();
            let decision = parse_sensitive_response(
                &sensitive,
                "u0000000000000001",
                AuthorizationInvocationMode::EffectsAllowed,
                &outputs,
                &guard.provider_response_charge(),
            )
            .unwrap();
            match (expected, decision) {
                ("allow", ProviderDecision::Allow { credentials, .. }) => {
                    let output = outputs.index("api_token").unwrap();
                    assert_eq!(
                        credentials.unix_contiguous(output),
                        Some(b"secret".as_slice())
                    );
                }
                ("deny", ProviderDecision::Deny) | ("pass", ProviderDecision::Pass) => {}
                _ => panic!("fixture response decision did not match its inventory"),
            }
            assert_eq!(pool.global_charge(), 0);
        }
    }

    #[test]
    fn arbitrary_order_whitespace_and_escaped_secret_bind_exact_charged_material() {
        let outputs = outputs(true);
        let metadata = projected_provider_credential_wire_metadata_bytes(outputs.len()).unwrap();
        let material = b"secret".len();
        let (pool, guard) = guard(metadata + material);
        let decision = parse(
            br#" { "values" : { "api_token" : "s\u0065cret" }, "decision" : "allow", "type" : "response", "id" : "protocol-1" } "#,
            AuthorizationInvocationMode::EffectsAllowed,
            &outputs,
            &guard,
        )
        .unwrap();
        let ProviderDecision::Allow {
            credentials,
            replacement,
        } = decision
        else {
            panic!("expected allow")
        };
        assert!(replacement.is_none());
        let index = outputs.index("api_token").unwrap();
        assert_eq!(
            credentials.unix_contiguous(index),
            Some(b"secret".as_slice())
        );
        assert_eq!(pool.global_charge(), metadata + material);
        drop(credentials);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn invocation_and_decision_effect_matrix_is_closed() {
        let outputs = outputs(false);
        for (invocation, json, expected) in [
            (
                AuthorizationInvocationMode::DecisionOnly,
                br#"{"id":"protocol-1","type":"response","decision":"allow"}"#.as_slice(),
                "allow_without_effects",
            ),
            (
                AuthorizationInvocationMode::DecisionOnly,
                br#"{"id":"protocol-1","type":"response","decision":"deny"}"#.as_slice(),
                "deny",
            ),
            (
                AuthorizationInvocationMode::DecisionOnly,
                br#"{"id":"protocol-1","type":"response","decision":"pass"}"#.as_slice(),
                "pass",
            ),
            (
                AuthorizationInvocationMode::EffectsAllowed,
                br#"{"id":"protocol-1","type":"response","decision":"allow"}"#.as_slice(),
                "allow_optional_omitted",
            ),
            (
                AuthorizationInvocationMode::EffectsAllowed,
                br#"{"id":"protocol-1","type":"response","decision":"deny"}"#.as_slice(),
                "deny",
            ),
            (
                AuthorizationInvocationMode::EffectsAllowed,
                br#"{"id":"protocol-1","type":"response","decision":"pass"}"#.as_slice(),
                "pass",
            ),
        ] {
            let (pool, guard) = guard(4096);
            let decision = parse(json, invocation, &outputs, &guard).unwrap();
            assert!(match (expected, &decision) {
                ("allow_without_effects", ProviderDecision::AllowWithoutEffects)
                | ("deny", ProviderDecision::Deny)
                | ("pass", ProviderDecision::Pass) => true,
                ("allow_optional_omitted", ProviderDecision::Allow { credentials, .. }) => {
                    credentials
                        .unix_contiguous(outputs.index("api_token").unwrap())
                        .is_none()
                }
                _ => false,
            });
            drop(decision);
            assert_eq!(pool.global_charge(), 0);
        }

        for (invocation, json) in [
            (
                AuthorizationInvocationMode::DecisionOnly,
                br#"{"id":"protocol-1","type":"response","decision":"allow","values":{}}"#
                    .as_slice(),
            ),
            (
                AuthorizationInvocationMode::EffectsAllowed,
                br#"{"id":"protocol-1","type":"response","decision":"deny","values":{}}"#
                    .as_slice(),
            ),
            (
                AuthorizationInvocationMode::EffectsAllowed,
                br#"{"id":"protocol-1","type":"response","decision":"pass","values":{}}"#
                    .as_slice(),
            ),
        ] {
            let (pool, guard) = guard(4096);
            assert_eq!(
                parse(json, invocation, &outputs, &guard).err(),
                Some(AwapResponseError::ValuesNotAllowed)
            );
            assert_eq!(pool.global_charge(), 0);
        }
    }

    #[test]
    fn strict_shape_output_and_required_rules_use_fixed_secret_free_errors() {
        let outputs = outputs(true);
        let cases = [
            (
                br#"{"id":"wrong-secret-id","type":"response","decision":"deny"}"#.as_slice(),
                AwapResponseError::RequestIdMismatch,
            ),
            (
                br#"{"id":"protocol-1","id":"protocol-1","type":"response","decision":"deny"}"#
                    .as_slice(),
                AwapResponseError::DuplicateField,
            ),
            (
                br#"{"id":"protocol-1","type":"response","decision":"allow","values":{"unknown-secret-name":"secret"}}"#
                    .as_slice(),
                AwapResponseError::UnknownOutput,
            ),
            (
                br#"{"id":"protocol-1","type":"response","decision":"allow","values":{"api_token":"one","api_token":"two"}}"#
                    .as_slice(),
                AwapResponseError::DuplicateOutput,
            ),
            (
                br#"{"id":"protocol-1","type":"response","decision":"allow"}"#.as_slice(),
                AwapResponseError::MissingRequiredOutput,
            ),
            (
                br#"{"id":"protocol-1","type":"response","decision":"allow","body":{}}"#
                    .as_slice(),
                AwapResponseError::BodyNotAllowed,
            ),
            (
                br#"{"id":"protocol-1","type":"response","decision":"deny","unknown":"secret"}"#
                    .as_slice(),
                AwapResponseError::UnknownField,
            ),
            (
                br#"{"id":"protocol-1","type":"response","decision":"deny"} trailing-secret"#
                    .as_slice(),
                AwapResponseError::TrailingData,
            ),
        ];
        for (json, expected) in cases {
            let (pool, guard) = guard(4096);
            let error = parse(
                json,
                AuthorizationInvocationMode::EffectsAllowed,
                &outputs,
                &guard,
            )
            .err()
            .unwrap();
            assert_eq!(error, expected);
            let rendered = error.to_string();
            assert!(!rendered.contains("secret"), "{rendered}");
            assert_eq!(pool.global_charge(), 0);
        }
    }

    #[test]
    fn malformed_empty_control_and_oversize_credentials_are_rejected() {
        let outputs = outputs(true);
        let mut oversize = Vec::new();
        oversize.extend_from_slice(
            br#"{"id":"protocol-1","type":"response","decision":"allow","values":{"api_token":""#,
        );
        oversize.extend(std::iter::repeat_n(b'a', MAX_PROVIDER_CREDENTIAL_BYTES + 1));
        oversize.extend_from_slice(br#""}}"#);
        for (json, expected) in [
            (
                br#"{"id":"protocol-1","type":"response","decision":"allow","values":{"api_token":}}"#
                    .as_slice(),
                AwapResponseError::MalformedJson,
            ),
            (
                br#"{"id":"protocol-1","type":"response","decision":"allow","values":{"api_token":""}}"#
                    .as_slice(),
                AwapResponseError::InvalidCredential,
            ),
            (
                br#"{"id":"protocol-1","type":"response","decision":"allow","values":{"api_token":"bad\u0001value"}}"#
                    .as_slice(),
                AwapResponseError::InvalidCredential,
            ),
            (oversize.as_slice(), AwapResponseError::InvalidCredential),
        ] {
            let (pool, guard) = guard(2 * MAX_PROVIDER_CREDENTIAL_BYTES);
            assert_eq!(
                parse(
                    json,
                    AuthorizationInvocationMode::EffectsAllowed,
                    &outputs,
                    &guard,
                )
                .err(),
                Some(expected)
            );
            assert_eq!(pool.global_charge(), 0);
        }
    }
}
