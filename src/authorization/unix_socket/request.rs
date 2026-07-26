use access_identity::ProviderIdentityProjection;
use access_rpc_framing::FrameBody;
use http::HeaderValue;

use super::super::protocol::{
    IncludedHeader, ProviderRequest, ProviderRequestHeaders, MAX_PROVIDER_REQUEST_ID_BYTES,
};
use crate::runtime::AuthorizationInvocationMode;
use crate::safety::wire_body::{
    guarded_body_allocation_bytes, GuardedAllocationCharge, WireBodyBufferError,
};
use crate::safety::HttpWireBodyGuard;

const AWAP_CLIENT: &str = "127.0.0.1:0";
const MAX_AWAP_PROTOCOL_REQUEST_ID_BYTES: usize = 4096;

/// Canonical body-free AWAP request projected from the shared provider input.
pub(crate) struct AwapRequest<'a> {
    protocol_request_id: &'a str,
    request: ProviderRequest<'a>,
    invocation: AuthorizationInvocationMode,
}

/// One encoded request whose ordinary frame allocation remains exactly charged.
pub(crate) struct PreparedAwapRequest {
    body: FrameBody,
    _charge: GuardedAllocationCharge,
}

impl PreparedAwapRequest {
    pub(crate) fn body(&self) -> &FrameBody {
        &self.body
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum AwapRequestError {
    #[error("Unix authorization request has an invalid typed field")]
    InvalidShape,
    #[error("Unix authorization requests cannot contain a body")]
    BodyNotAllowed,
    #[error("Unix authorization request length overflowed")]
    LengthOverflow,
    #[error("Unix authorization request exceeds its configured limit")]
    TooLarge,
    #[error("Unix authorization request storage could not be allocated")]
    Allocation,
}

impl From<WireBodyBufferError> for AwapRequestError {
    fn from(_: WireBodyBufferError) -> Self {
        Self::Allocation
    }
}

impl<'a> AwapRequest<'a> {
    pub(crate) fn new(
        protocol_request_id: &'a str,
        request: ProviderRequest<'a>,
        invocation: AuthorizationInvocationMode,
    ) -> Self {
        Self {
            protocol_request_id,
            request,
            invocation,
        }
    }

    pub(crate) fn encoded_len(&self) -> Result<usize, AwapRequestError> {
        self.validate()?;
        let mut length = 0usize;
        add_literal(&mut length, b"{\"id\":")?;
        add_json_string_len(&mut length, self.protocol_request_id)?;
        add_literal(&mut length, b",\"type\":\"request\",\"requestId\":")?;
        add_json_string_len(&mut length, self.request.request_id)?;
        add_literal(&mut length, b",\"ruleId\":")?;
        add_json_string_len(&mut length, self.request.rule_id)?;
        add_literal(&mut length, b",\"invocation\":")?;
        add_json_string_len(&mut length, invocation_name(self.invocation))?;
        add_literal(&mut length, b",\"url\":")?;
        add_json_string_len(&mut length, self.request.url)?;
        add_literal(&mut length, b",\"method\":")?;
        add_json_string_len(&mut length, self.request.method)?;
        add_literal(&mut length, b",\"client\":")?;
        add_json_string_len(&mut length, AWAP_CLIENT)?;
        add_literal(&mut length, b",\"headers\":{")?;
        add_headers_len(&mut length, self.request.headers)?;
        add_literal(&mut length, b"}")?;
        if let Some(identity) = self.request.identity {
            add_literal(&mut length, b",\"identity\":")?;
            add_identity_len(&mut length, identity)?;
        }
        add_literal(&mut length, b"}")?;
        Ok(length)
    }

    pub(crate) fn prepare(
        &self,
        max_request_bytes: usize,
        guard: &HttpWireBodyGuard,
    ) -> Result<PreparedAwapRequest, AwapRequestError> {
        let expected = self.encoded_len()?;
        if expected > max_request_bytes {
            return Err(AwapRequestError::TooLarge);
        }
        let allocation_bytes =
            guarded_body_allocation_bytes(expected).ok_or(AwapRequestError::LengthOverflow)?;
        let charge = guard.charge_exact_allocation(allocation_bytes)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(expected)
            .map_err(|_| AwapRequestError::Allocation)?;

        append(&mut output, b"{\"id\":");
        append_json_string(&mut output, self.protocol_request_id);
        append(&mut output, b",\"type\":\"request\",\"requestId\":");
        append_json_string(&mut output, self.request.request_id);
        append(&mut output, b",\"ruleId\":");
        append_json_string(&mut output, self.request.rule_id);
        append(&mut output, b",\"invocation\":");
        append_json_string(&mut output, invocation_name(self.invocation));
        append(&mut output, b",\"url\":");
        append_json_string(&mut output, self.request.url);
        append(&mut output, b",\"method\":");
        append_json_string(&mut output, self.request.method);
        append(&mut output, b",\"client\":");
        append_json_string(&mut output, AWAP_CLIENT);
        append(&mut output, b",\"headers\":{");
        append_headers(&mut output, self.request.headers);
        append(&mut output, b"}");
        if let Some(identity) = self.request.identity {
            append(&mut output, b",\"identity\":");
            append_identity(&mut output, identity);
        }
        append(&mut output, b"}");
        debug_assert_eq!(output.len(), expected);
        let body = FrameBody::new(output).map_err(|_| AwapRequestError::InvalidShape)?;
        Ok(PreparedAwapRequest {
            body,
            _charge: charge,
        })
    }

    fn validate(&self) -> Result<(), AwapRequestError> {
        if self.protocol_request_id.is_empty()
            || self.protocol_request_id.len() > MAX_AWAP_PROTOCOL_REQUEST_ID_BYTES
            || self.request.request_id.is_empty()
            || self.request.request_id.len() > MAX_PROVIDER_REQUEST_ID_BYTES
            || self.request.rule_id.is_empty()
            || self.request.rule_id.len() > crate::authorization::MAX_PROVIDER_RULE_ID_BYTES
            || self.request.url.is_empty()
            || !valid_method(self.request.method)
        {
            return Err(AwapRequestError::InvalidShape);
        }
        if self.request.body.is_some() {
            return Err(AwapRequestError::BodyNotAllowed);
        }
        Ok(())
    }
}

fn invocation_name(invocation: AuthorizationInvocationMode) -> &'static str {
    match invocation {
        AuthorizationInvocationMode::EffectsAllowed => "effects_allowed",
        AuthorizationInvocationMode::DecisionOnly => "decision_only",
    }
}

fn valid_method(method: &str) -> bool {
    !method.is_empty()
        && method.bytes().all(|byte| {
            byte.is_ascii_uppercase()
                || matches!(
                    byte,
                    b'0'..=b'9'
                        | b'!'
                        | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn add_headers_len(
    length: &mut usize,
    headers: Option<&ProviderRequestHeaders<'_>>,
) -> Result<(), AwapRequestError> {
    let fields = headers
        .map(ProviderRequestHeaders::fields)
        .unwrap_or_default();
    let mut previous = None;
    for field_index in 0..fields.len() {
        let field = next_sorted_header(fields, previous).ok_or(AwapRequestError::InvalidShape)?;
        if field_index != 0 {
            add_literal(length, b",")?;
        }
        add_json_string_len(length, field.name().as_str())?;
        add_literal(length, b":[")?;
        for (value_index, value) in field.values().iter().enumerate() {
            if value_index != 0 {
                add_literal(length, b",")?;
            }
            add_json_string_len(length, header_text(value)?)?;
        }
        add_literal(length, b"]")?;
        previous = Some(field.name().as_str());
    }
    Ok(())
}

fn append_headers(output: &mut Vec<u8>, headers: Option<&ProviderRequestHeaders<'_>>) {
    let fields = headers
        .map(ProviderRequestHeaders::fields)
        .unwrap_or_default();
    let mut previous = None;
    for field_index in 0..fields.len() {
        let field =
            next_sorted_header(fields, previous).expect("validated provider headers are unique");
        if field_index != 0 {
            append(output, b",");
        }
        append_json_string(output, field.name().as_str());
        append(output, b":[");
        for (value_index, value) in field.values().iter().enumerate() {
            if value_index != 0 {
                append(output, b",");
            }
            append_json_string(
                output,
                value
                    .to_str()
                    .expect("validated included header value remains textual"),
            );
        }
        append(output, b"]");
        previous = Some(field.name().as_str());
    }
}

fn next_sorted_header<'a>(
    fields: &'a [IncludedHeader<'a>],
    previous: Option<&str>,
) -> Option<&'a IncludedHeader<'a>> {
    fields
        .iter()
        .filter(|field| previous.is_none_or(|name| field.name().as_str() > name))
        .min_by(|left, right| left.name().as_str().cmp(right.name().as_str()))
}

fn header_text(value: &HeaderValue) -> Result<&str, AwapRequestError> {
    value.to_str().map_err(|_| AwapRequestError::InvalidShape)
}

fn add_identity_len(
    length: &mut usize,
    identity: &ProviderIdentityProjection,
) -> Result<(), AwapRequestError> {
    match identity {
        ProviderIdentityProjection::Disabled => {
            add_literal(length, b"{\"state\":\"disabled\"}")?;
        }
        ProviderIdentityProjection::Anonymous => {
            add_literal(length, b"{\"state\":\"anonymous\"}")?;
        }
        ProviderIdentityProjection::Authenticated { principal, groups } => {
            add_literal(
                length,
                b"{\"state\":\"authenticated\",\"principal\":{\"authority\":",
            )?;
            add_json_string_len(length, principal.authority.as_str())?;
            add_literal(length, b",\"id\":")?;
            add_json_string_len(length, principal.id.as_str())?;
            add_literal(length, b",\"kind\":")?;
            add_json_string_len(length, principal.kind.as_str())?;
            add_literal(length, b"},\"groups\":[")?;
            for (index, group) in groups.iter().enumerate() {
                if index != 0 {
                    add_literal(length, b",")?;
                }
                add_literal(length, b"{\"authority\":")?;
                add_json_string_len(length, group.authority().as_str())?;
                add_literal(length, b",\"id\":")?;
                add_json_string_len(length, group.id().as_str())?;
                add_literal(length, b"}")?;
            }
            add_literal(length, b"]}")?;
        }
    }
    Ok(())
}

fn append_identity(output: &mut Vec<u8>, identity: &ProviderIdentityProjection) {
    match identity {
        ProviderIdentityProjection::Disabled => {
            append(output, b"{\"state\":\"disabled\"}");
        }
        ProviderIdentityProjection::Anonymous => {
            append(output, b"{\"state\":\"anonymous\"}");
        }
        ProviderIdentityProjection::Authenticated { principal, groups } => {
            append(
                output,
                b"{\"state\":\"authenticated\",\"principal\":{\"authority\":",
            );
            append_json_string(output, principal.authority.as_str());
            append(output, b",\"id\":");
            append_json_string(output, principal.id.as_str());
            append(output, b",\"kind\":");
            append_json_string(output, principal.kind.as_str());
            append(output, b"},\"groups\":[");
            for (index, group) in groups.iter().enumerate() {
                if index != 0 {
                    append(output, b",");
                }
                append(output, b"{\"authority\":");
                append_json_string(output, group.authority().as_str());
                append(output, b",\"id\":");
                append_json_string(output, group.id().as_str());
                append(output, b"}");
            }
            append(output, b"]}");
        }
    }
}

fn add_literal(length: &mut usize, bytes: &[u8]) -> Result<(), AwapRequestError> {
    *length = length
        .checked_add(bytes.len())
        .ok_or(AwapRequestError::LengthOverflow)?;
    Ok(())
}

fn add_json_string_len(length: &mut usize, value: &str) -> Result<(), AwapRequestError> {
    add_literal(length, b"\"")?;
    for byte in value.as_bytes() {
        let encoded = if matches!(byte, b'\"' | b'\\' | b'\n' | b'\r' | b'\t' | 0x08 | 0x0c) {
            2
        } else if *byte < 0x20 {
            6
        } else {
            1
        };
        *length = length
            .checked_add(encoded)
            .ok_or(AwapRequestError::LengthOverflow)?;
    }
    add_literal(length, b"\"")
}

fn append(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(bytes);
}

fn append_json_string(output: &mut Vec<u8>, value: &str) {
    append(output, b"\"");
    let mut plain_start = 0usize;
    for (index, byte) in value.bytes().enumerate() {
        let escape: Option<&[u8]> = match byte {
            b'\"' => Some(b"\\\""),
            b'\\' => Some(b"\\\\"),
            b'\n' => Some(b"\\n"),
            b'\r' => Some(b"\\r"),
            b'\t' => Some(b"\\t"),
            0x08 => Some(b"\\b"),
            0x0c => Some(b"\\f"),
            0x00..=0x1f => {
                append(output, &value.as_bytes()[plain_start..index]);
                append(
                    output,
                    &[b'\\', b'u', b'0', b'0', hex(byte >> 4), hex(byte & 0x0f)],
                );
                plain_start = index + 1;
                continue;
            }
            _ => None,
        };
        if let Some(escape) = escape {
            append(output, &value.as_bytes()[plain_start..index]);
            append(output, escape);
            plain_start = index + 1;
        }
    }
    append(output, &value.as_bytes()[plain_start..]);
    append(output, b"\"");
}

fn hex(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        10..=15 => b'a' + value - 10,
        _ => unreachable!("nibble is in range"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use access_identity::{
        AuthorityId, GroupId, GroupRef, PrincipalId, PrincipalKind, ProviderPrincipalProjection,
    };
    use access_rpc_framing::{FrameBodyLimit, FrameKind, FrameProtocol};
    use http::{HeaderName, HeaderValue};
    use std::net::{IpAddr, Ipv4Addr};

    use crate::safety::{WireBodyPool, WireBodyQuotaKey};

    fn guard(peak: usize) -> (std::sync::Arc<WireBodyPool>, HttpWireBodyGuard) {
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(
            peak,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );
        (pool, guard)
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn production_request_codec_exactly_matches_the_language_neutral_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/awap/v1.json"
        )))
        .unwrap();
        let vector = &fixture["vectors"][0];
        let body = vector["body"].as_str().unwrap().as_bytes();
        let authority = AuthorityId::new("aw-workstation").unwrap();
        let identity = ProviderIdentityProjection::Authenticated {
            principal: ProviderPrincipalProjection {
                authority: authority.clone(),
                id: PrincipalId::new("container-a").unwrap(),
                kind: PrincipalKind::ServiceAccount,
            },
            groups: vec![GroupRef::new(authority, GroupId::new("git-users").unwrap())]
                .into_boxed_slice(),
        };
        let request = AwapRequest::new(
            "u0000000000000001",
            ProviderRequest {
                request_id: "acl-request-0001",
                rule_id: "engineering-gitlab",
                url: "https://gitlab.example.test/a",
                method: "GET",
                client_ip: "198.51.100.8",
                headers: None,
                identity: Some(&identity),
                body: None,
            },
            AuthorizationInvocationMode::EffectsAllowed,
        );
        let allocation = guarded_body_allocation_bytes(body.len()).unwrap();
        let (_, guard) = guard(allocation);
        let prepared = request.prepare(body.len(), &guard).unwrap();
        assert_eq!(prepared.body().as_bytes(), body);

        let protocol = FrameProtocol::new(
            *b"AWAP",
            1,
            FrameBodyLimit::new(262_144).unwrap(),
            FrameBodyLimit::new(65_536).unwrap(),
        );
        let header = protocol
            .header(FrameKind::Request, body.len())
            .unwrap()
            .encode(protocol);
        let mut frame = header.to_vec();
        frame.extend_from_slice(prepared.body().as_bytes());
        assert_eq!(frame, decode_hex(vector["frame_hex"].as_str().unwrap()));
    }

    #[test]
    fn canonical_request_has_mandatory_sorted_header_object_and_fixed_client() {
        let a = HeaderName::from_static("a-header");
        let z = HeaderName::from_static("z-header");
        let a_values = [
            HeaderValue::from_static("first"),
            HeaderValue::from_static("second"),
        ];
        let z_values = [HeaderValue::from_static("last")];
        let fields = [
            IncludedHeader::new(&z, &z_values),
            IncludedHeader::new(&a, &a_values),
        ];
        let headers = ProviderRequestHeaders::new(&fields).unwrap();
        let identity = ProviderIdentityProjection::Anonymous;
        let request = ProviderRequest {
            request_id: "logical-1",
            rule_id: "rule-1",
            url: "https://example.test/a",
            method: "GET",
            client_ip: "203.0.113.10",
            headers: Some(&headers),
            identity: Some(&identity),
            body: None,
        };
        let request = AwapRequest::new(
            "protocol-1",
            request,
            AuthorizationInvocationMode::EffectsAllowed,
        );
        let expected = b"{\"id\":\"protocol-1\",\"type\":\"request\",\"requestId\":\"logical-1\",\"ruleId\":\"rule-1\",\"invocation\":\"effects_allowed\",\"url\":\"https://example.test/a\",\"method\":\"GET\",\"client\":\"127.0.0.1:0\",\"headers\":{\"a-header\":[\"first\",\"second\"],\"z-header\":[\"last\"]},\"identity\":{\"state\":\"anonymous\"}}";
        assert_eq!(request.encoded_len().unwrap(), expected.len());
        let allocation = guarded_body_allocation_bytes(expected.len()).unwrap();
        let (pool, guard) = guard(allocation);
        let prepared = request.prepare(expected.len(), &guard).unwrap();
        assert_eq!(prepared.body().as_bytes(), expected);
        assert_eq!(pool.global_charge(), allocation);
        drop(prepared);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn empty_headers_are_braces_and_decision_only_is_canonical() {
        let request = ProviderRequest {
            request_id: "logical-1",
            rule_id: "rule-1",
            url: "https://example.test/",
            method: "HEAD",
            client_ip: "::1",
            headers: None,
            identity: None,
            body: None,
        };
        let request = AwapRequest::new(
            "protocol-1",
            request,
            AuthorizationInvocationMode::DecisionOnly,
        );
        let expected = b"{\"id\":\"protocol-1\",\"type\":\"request\",\"requestId\":\"logical-1\",\"ruleId\":\"rule-1\",\"invocation\":\"decision_only\",\"url\":\"https://example.test/\",\"method\":\"HEAD\",\"client\":\"127.0.0.1:0\",\"headers\":{}}";
        let (_, guard) = guard(guarded_body_allocation_bytes(expected.len()).unwrap());
        let prepared = request.prepare(expected.len(), &guard).unwrap();
        assert_eq!(prepared.body().as_bytes(), expected);
    }

    #[test]
    fn body_and_limit_fail_before_frame_publication() {
        let (pool, guard) = guard(guarded_body_allocation_bytes(4096).unwrap());
        let mut body = guard.buffer();
        body.try_extend_from_slice(b"x").unwrap();
        let body = body.finish();
        let request = ProviderRequest {
            request_id: "logical-1",
            rule_id: "rule-1",
            url: "https://example.test/",
            method: "POST",
            client_ip: "127.0.0.1",
            headers: None,
            identity: None,
            body: Some(crate::authorization::protocol::GuardedProviderBody {
                content_type: None,
                content_encoding: None,
                decoded: &body,
            }),
        };
        let request = AwapRequest::new(
            "protocol-1",
            request,
            AuthorizationInvocationMode::EffectsAllowed,
        );
        assert_eq!(
            request.prepare(4096, &guard).err(),
            Some(AwapRequestError::BodyNotAllowed)
        );
        assert_eq!(pool.global_charge(), body.charged_bytes());

        drop(body);
        let request = ProviderRequest {
            request_id: "logical-1",
            rule_id: "rule-1",
            url: "https://example.test/",
            method: "GET",
            client_ip: "127.0.0.1",
            headers: None,
            identity: None,
            body: None,
        };
        let request = AwapRequest::new(
            "protocol-1",
            request,
            AuthorizationInvocationMode::EffectsAllowed,
        );
        assert_eq!(
            request.prepare(1, &guard).err(),
            Some(AwapRequestError::TooLarge)
        );
        assert_eq!(pool.global_charge(), 0);
    }
}
