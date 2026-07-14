use http::HeaderValue;

use crate::authorization::callback::ResumeToken;
use crate::authorization::protocol::{ProviderRequest, ProviderRequestHeaders};
use crate::safety::wire_body::{ReservedGuardedBodyBuilder, WireBodyBufferError};
use crate::safety::{GuardedBody, HttpWireBodyGuard};

const MAX_IDENTIFIER_BYTES: usize = 4096;

/// Body-free request projected specifically for the callback webhook protocol.
pub(crate) struct WebhookRequest<'a> {
    pub(crate) request_id: &'a str,
    pub(crate) rule_id: &'a str,
    pub(crate) url: &'a str,
    pub(crate) method: &'a str,
    pub(crate) client_ip: &'a str,
    pub(crate) headers: Option<&'a ProviderRequestHeaders<'a>>,
}

pub(crate) struct PreparedWebhookRequest {
    output: ReservedGuardedBodyBuilder,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum WebhookRequestError {
    #[error("webhook request has an invalid typed field")]
    InvalidShape,
    #[error("webhook request exceeds the provider request limit")]
    TooLarge,
    #[error("webhook request length overflowed")]
    LengthOverflow,
    #[error("webhook request storage could not be allocated")]
    Allocation(#[from] WireBodyBufferError),
}

impl WebhookRequest<'_> {
    pub(crate) fn encoded_len(&self, callback_url: &str) -> Result<usize, WebhookRequestError> {
        self.validate()?;
        let mut length = 0usize;
        add_literal(&mut length, b"{\"type\":\"request\",\"requestId\":")?;
        add_json_string_len(&mut length, self.request_id)?;
        add_literal(&mut length, b",\"ruleId\":")?;
        add_json_string_len(&mut length, self.rule_id)?;
        add_literal(&mut length, b",\"url\":")?;
        add_json_string_len(&mut length, self.url)?;
        add_literal(&mut length, b",\"method\":")?;
        add_json_string_len(&mut length, self.method)?;
        add_literal(&mut length, b",\"clientIp\":")?;
        add_json_string_len(&mut length, self.client_ip)?;
        if let Some(headers) = self.headers.filter(|headers| !headers.fields().is_empty()) {
            add_literal(&mut length, b",\"headers\":{")?;
            for (field_index, field) in headers.fields().iter().enumerate() {
                if field_index != 0 {
                    add_literal(&mut length, b",")?;
                }
                add_json_string_len(&mut length, field.name().as_str())?;
                add_literal(&mut length, b":[")?;
                for (value_index, value) in field.values().iter().enumerate() {
                    if value_index != 0 {
                        add_literal(&mut length, b",")?;
                    }
                    add_json_string_len(&mut length, header_text(value)?)?;
                }
                add_literal(&mut length, b"]")?;
            }
            add_literal(&mut length, b"}")?;
        }
        add_literal(&mut length, b",\"callbackUrl\":")?;
        add_json_string_len(&mut length, callback_url)?;
        add_literal(&mut length, b",\"resumeToken\":\"")?;
        add_literal(&mut length, &[b'A'; 43])?;
        add_literal(&mut length, b"\"}")?;
        Ok(length)
    }

    pub(crate) fn prepare(
        &self,
        callback_url: &str,
        max_request_bytes: usize,
        guard: &HttpWireBodyGuard,
    ) -> Result<PreparedWebhookRequest, WebhookRequestError> {
        let expected = self.encoded_len(callback_url)?;
        if expected > max_request_bytes {
            return Err(WebhookRequestError::TooLarge);
        }

        let mut output = guard.reserve_exact_buffer(expected)?;
        append(&mut output, b"{\"type\":\"request\",\"requestId\":")?;
        append_json_string(&mut output, self.request_id)?;
        append(&mut output, b",\"ruleId\":")?;
        append_json_string(&mut output, self.rule_id)?;
        append(&mut output, b",\"url\":")?;
        append_json_string(&mut output, self.url)?;
        append(&mut output, b",\"method\":")?;
        append_json_string(&mut output, self.method)?;
        append(&mut output, b",\"clientIp\":")?;
        append_json_string(&mut output, self.client_ip)?;
        if let Some(headers) = self.headers.filter(|headers| !headers.fields().is_empty()) {
            append(&mut output, b",\"headers\":{")?;
            for (field_index, field) in headers.fields().iter().enumerate() {
                if field_index != 0 {
                    append(&mut output, b",")?;
                }
                append_json_string(&mut output, field.name().as_str())?;
                append(&mut output, b":[")?;
                for (value_index, value) in field.values().iter().enumerate() {
                    if value_index != 0 {
                        append(&mut output, b",")?;
                    }
                    append_json_string(&mut output, header_text(value)?)?;
                }
                append(&mut output, b"]")?;
            }
            append(&mut output, b"}")?;
        }
        append(&mut output, b",\"callbackUrl\":")?;
        append_json_string(&mut output, callback_url)?;
        append(&mut output, b",\"resumeToken\":\"")?;
        debug_assert_eq!(output.len() + 45, expected);
        Ok(PreparedWebhookRequest { output })
    }

    fn validate(&self) -> Result<(), WebhookRequestError> {
        if self.request_id.is_empty()
            || self.request_id.len() > MAX_IDENTIFIER_BYTES
            || self.rule_id.is_empty()
            || self.rule_id.len() > MAX_IDENTIFIER_BYTES
            || self.url.is_empty()
            || self.method.is_empty()
            || !self.method.bytes().all(|byte| {
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
            || self.client_ip.parse::<std::net::IpAddr>().is_err()
        {
            return Err(WebhookRequestError::InvalidShape);
        }
        if let Some(headers) = self.headers {
            for field in headers.fields() {
                if field.values().is_empty()
                    || field.values().iter().any(|value| value.to_str().is_err())
                {
                    return Err(WebhookRequestError::InvalidShape);
                }
            }
        }
        Ok(())
    }
}

impl<'a> WebhookRequest<'a> {
    pub(crate) fn from_provider(rule_id: &'a str, request: ProviderRequest<'a>) -> Self {
        let ProviderRequest {
            request_id,
            url,
            method,
            client_ip,
            headers,
            body: _,
        } = request;
        Self {
            request_id,
            rule_id,
            url,
            method,
            client_ip,
            headers,
        }
    }
}

impl PreparedWebhookRequest {
    pub(crate) fn finish(
        mut self,
        token: &ResumeToken,
    ) -> Result<GuardedBody, WebhookRequestError> {
        append(&mut self.output, token.as_bytes())?;
        append(&mut self.output, b"\"}")?;
        self.output.finish().map_err(Into::into)
    }
}

fn header_text(value: &HeaderValue) -> Result<&str, WebhookRequestError> {
    value
        .to_str()
        .map_err(|_| WebhookRequestError::InvalidShape)
}

fn add_literal(length: &mut usize, bytes: &[u8]) -> Result<(), WebhookRequestError> {
    *length = length
        .checked_add(bytes.len())
        .ok_or(WebhookRequestError::LengthOverflow)?;
    Ok(())
}

fn add_json_string_len(length: &mut usize, value: &str) -> Result<(), WebhookRequestError> {
    add_literal(length, b"\"")?;
    for byte in value.as_bytes() {
        add_literal(
            length,
            if matches!(byte, b'\"' | b'\\' | b'\n' | b'\r' | b'\t' | 0x08 | 0x0c) {
                &[0; 2]
            } else if *byte < 0x20 {
                &[0; 6]
            } else {
                &[0; 1]
            },
        )?;
    }
    add_literal(length, b"\"")
}

fn append(
    output: &mut ReservedGuardedBodyBuilder,
    bytes: &[u8],
) -> Result<(), WebhookRequestError> {
    output.try_extend_from_slice(bytes).map_err(Into::into)
}

fn append_json_string(
    output: &mut ReservedGuardedBodyBuilder,
    value: &str,
) -> Result<(), WebhookRequestError> {
    append(output, b"\"")?;
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
                if plain_start < index {
                    append(output, &value.as_bytes()[plain_start..index])?;
                }
                let encoded = [b'\\', b'u', b'0', b'0', hex(byte >> 4), hex(byte & 0x0f)];
                append(output, &encoded)?;
                plain_start = index + 1;
                continue;
            }
            _ => None,
        };
        if let Some(escape) = escape {
            if plain_start < index {
                append(output, &value.as_bytes()[plain_start..index])?;
            }
            append(output, escape)?;
            plain_start = index + 1;
        }
    }
    if plain_start < value.len() {
        append(output, &value.as_bytes()[plain_start..])?;
    }
    append(output, b"\"")
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
    use std::net::{IpAddr, Ipv4Addr};

    use http::{HeaderName, HeaderValue};

    use super::*;
    use crate::authorization::protocol::IncludedHeader;
    use crate::safety::{WireBodyPool, WireBodyQuotaKey};

    fn guard(peak: usize) -> HttpWireBodyGuard {
        WireBodyPool::new(2 * 1024 * 1024, 2 * 1024 * 1024).begin_for_test(
            peak,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        )
    }

    #[test]
    fn webhook_wire_contract_is_strict_and_body_free() {
        let name = HeaderName::from_static("x-example");
        let values = [
            HeaderValue::from_static("first"),
            HeaderValue::from_static("second"),
        ];
        let fields = [IncludedHeader::new(&name, &values)];
        let headers = ProviderRequestHeaders::new(&fields).unwrap();
        let request = WebhookRequest {
            request_id: "request-1",
            rule_id: "rule-1",
            url: "https://example.test/a?b=c",
            method: "GET",
            client_ip: "127.0.0.1",
            headers: Some(&headers),
        };
        let token =
            ResumeToken::from_encoded_for_test(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let expected_prefix = b"{\"type\":\"request\",\"requestId\":\"request-1\",\"ruleId\":\"rule-1\",\"url\":\"https://example.test/a?b=c\",\"method\":\"GET\",\"clientIp\":\"127.0.0.1\",\"headers\":{\"x-example\":[\"first\",\"second\"]},\"callbackUrl\":\"https://proxy.test/_acl/external-auth/callback\",\"resumeToken\":\"";
        let guard = guard(128 * 1024);
        let body = request
            .prepare(
                "https://proxy.test/_acl/external-auth/callback",
                16 * 1024,
                &guard,
            )
            .unwrap()
            .finish(&token)
            .unwrap();
        let bytes = body.segments().flatten().copied().collect::<Vec<_>>();
        assert!(bytes.starts_with(expected_prefix));
        assert!(bytes.ends_with(b"\"}"));
        assert_eq!(
            bytes.len(),
            request
                .encoded_len("https://proxy.test/_acl/external-auth/callback")
                .unwrap()
        );
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed.get("body").is_none());
        assert_eq!(parsed.as_object().unwrap().len(), 9);
    }

    #[test]
    fn webhook_request_body_never_disclosed() {
        use crate::authorization::protocol::GuardedProviderBody;

        let guard = guard(256 * 1024);
        let marker = b"request-body-marker-must-not-cross-webhook-boundary";
        let mut body = guard.buffer();
        body.try_extend_from_slice(marker).unwrap();
        let body = body.finish();
        let provider = ProviderRequest {
            request_id: "request-1",
            url: "https://example.test/resource",
            method: "POST",
            client_ip: "127.0.0.1",
            headers: None,
            body: Some(GuardedProviderBody {
                content_type: Some("application/octet-stream"),
                content_encoding: Some("identity"),
                decoded: &body,
            }),
        };
        let request = WebhookRequest::from_provider("rule-1", provider);
        let token =
            ResumeToken::from_encoded_for_test(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let encoded = request
            .prepare(
                "https://proxy.test/_acl/external-auth/callback",
                16 * 1024,
                &guard,
            )
            .unwrap()
            .finish(&token)
            .unwrap();
        let bytes = encoded.segments().flatten().copied().collect::<Vec<_>>();
        assert!(!bytes.windows(marker.len()).any(|window| window == marker));
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed.get("body").is_none());
        assert!(parsed.get("requestBody").is_none());
        assert!(parsed.get("contentType").is_none());
        assert!(parsed.get("contentEncoding").is_none());
    }

    #[test]
    fn webhook_request_allocation_is_bounded_and_charged() {
        let request = WebhookRequest {
            request_id: "a\\\"\n",
            rule_id: "b",
            url: "http://localhost/",
            method: "A",
            client_ip: "::",
            headers: None,
        };
        let callback = "http://localhost/_acl/external-auth/callback";
        let token =
            ResumeToken::from_encoded_for_test(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let exact = request.encoded_len(callback).unwrap();
        let guard = guard(128 * 1024);
        assert!(matches!(
            request.prepare(callback, exact - 1, &guard),
            Err(WebhookRequestError::TooLarge)
        ));
        assert_eq!(guard.live_bytes(), 0);
        let prepared = request.prepare(callback, exact, &guard).unwrap();
        assert!(
            guard.live_bytes() > 0,
            "request storage is charged before token use"
        );
        let body = prepared.finish(&token).unwrap();
        let bytes = body.segments().flatten().copied().collect::<Vec<_>>();
        assert_eq!(bytes.len(), exact);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["requestId"],
            "a\\\"\n"
        );
    }
}
