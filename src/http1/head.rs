use std::fmt;

use super::framing::BodyFraming;
use super::store::{HeadScanError, ParserStore, ParserStoreError, PARSER_STORE_BYTES};

pub(crate) const MAX_HEADER_FIELDS: usize = 128;
pub(crate) const MAX_FIELD_LINE_BYTES: usize = 16 * 1024;
pub(crate) const MAX_REQUEST_TARGET_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeadParse<T> {
    Incomplete,
    Complete(T),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestMethod {
    Get,
    Post,
    Other,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RequestTarget {
    bytes: [u8; MAX_REQUEST_TARGET_BYTES],
    len: usize,
}

impl fmt::Debug for RequestTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestTarget")
            .field("bytes", &"<elided>")
            .field("len", &self.len)
            .finish()
    }
}

impl RequestTarget {
    fn new(input: &[u8]) -> Result<Self, HeadError> {
        if input.len() > MAX_REQUEST_TARGET_BYTES {
            return Err(HeadError::RequestTargetTooLong);
        }
        let mut bytes = [0; MAX_REQUEST_TARGET_BYTES];
        bytes[..input.len()].copy_from_slice(input);
        Ok(Self {
            bytes,
            len: input.len(),
        })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Drop for RequestTarget {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
        self.len = 0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContentType {
    Absent,
    ApplicationJson,
    Other,
    Multiple,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequestHead {
    pub(crate) method: RequestMethod,
    pub(crate) target: RequestTarget,
    pub(crate) content_type: ContentType,
    pub(crate) content_encoding_present: bool,
    pub(crate) expect_present: bool,
    pub(crate) connection_close: bool,
    pub(crate) framing: BodyFraming,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResponseHead {
    pub(crate) status: u16,
    pub(crate) connection_close: bool,
    pub(crate) framing: BodyFraming,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IngressRequestKind {
    Ordinary,
    Upgrade,
    Connect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IngressRequestHead {
    pub(crate) framing: BodyFraming,
    pub(crate) kind: IngressRequestKind,
}

pub(crate) fn parse_request_head(
    store: &mut ParserStore,
) -> Result<HeadParse<RequestHead>, HeadError> {
    let Some(head_len) = complete_head_len(store)? else {
        return Ok(HeadParse::Incomplete);
    };
    validate_field_lines(&store.initialized()[..head_len])?;

    let metadata = {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADER_FIELDS];
        let mut request = httparse::Request::new(&mut headers);
        let parsed = request
            .parse(&store.initialized()[..head_len])
            .map_err(map_parse_error)?;
        if parsed != httparse::Status::Complete(head_len) || request.version != Some(1) {
            return Err(HeadError::Http11Required);
        }
        let method = match request.method.ok_or(HeadError::MalformedHead)? {
            "GET" => RequestMethod::Get,
            "POST" => RequestMethod::Post,
            _ => RequestMethod::Other,
        };
        let target = RequestTarget::new(request.path.ok_or(HeadError::MalformedHead)?.as_bytes())?;
        let summary = summarize_headers(request.headers, MessageKind::Request)?;
        RequestHead {
            method,
            target,
            content_type: summary.content_type,
            content_encoding_present: summary.content_encoding_present,
            expect_present: summary.expect_present,
            connection_close: summary.connection_close,
            framing: summary.framing,
        }
    };
    store.consume_prefix(head_len).map_err(HeadError::Store)?;
    Ok(HeadParse::Complete(metadata))
}

pub(crate) fn parse_response_head(
    store: &mut ParserStore,
) -> Result<HeadParse<ResponseHead>, HeadError> {
    let Some(head_len) = complete_head_len(store)? else {
        return Ok(HeadParse::Incomplete);
    };
    validate_field_lines(&store.initialized()[..head_len])?;

    let metadata = {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADER_FIELDS];
        let mut response = httparse::Response::new(&mut headers);
        let parsed = response
            .parse(&store.initialized()[..head_len])
            .map_err(map_parse_error)?;
        if parsed != httparse::Status::Complete(head_len) || response.version != Some(1) {
            return Err(HeadError::Http11Required);
        }
        let status = response.code.ok_or(HeadError::MalformedHead)?;
        if (100..200).contains(&status) {
            return Err(HeadError::InterimResponseForbidden);
        }
        let summary = summarize_headers(response.headers, MessageKind::Response)?;
        ResponseHead {
            status,
            connection_close: summary.connection_close,
            framing: summary.framing,
        }
    };
    store.consume_prefix(head_len).map_err(HeadError::Store)?;
    Ok(HeadParse::Complete(metadata))
}

fn complete_head_len(store: &mut ParserStore) -> Result<Option<usize>, HeadError> {
    match store.scan_head_end() {
        Ok(Some(head_len)) if head_len <= PARSER_STORE_BYTES => Ok(Some(head_len)),
        Ok(Some(_)) => Err(HeadError::HeadTooLarge),
        Ok(None) => incomplete_or_too_large(store.initialized_len()),
        Err(HeadScanError::NonCanonicalLineEnding) => Err(HeadError::NonCanonicalLineEnding),
    }
}

fn incomplete_or_too_large(len: usize) -> Result<Option<usize>, HeadError> {
    if len >= PARSER_STORE_BYTES {
        Err(HeadError::HeadTooLarge)
    } else {
        Ok(None)
    }
}

fn validate_field_lines(head: &[u8]) -> Result<(), HeadError> {
    let first_line_end = find_crlf(head, 0).ok_or(HeadError::MalformedHead)?;
    let mut line_start = first_line_end + 2;
    let mut field_count = 0_usize;
    loop {
        let line_end = find_crlf(head, line_start).ok_or(HeadError::MalformedHead)?;
        if line_end == line_start {
            return Ok(());
        }
        let line_bytes = line_end
            .checked_add(2)
            .and_then(|end| end.checked_sub(line_start))
            .ok_or(HeadError::ArithmeticOverflow)?;
        if line_bytes > MAX_FIELD_LINE_BYTES {
            return Err(HeadError::FieldLineTooLong);
        }
        field_count = field_count
            .checked_add(1)
            .ok_or(HeadError::ArithmeticOverflow)?;
        if field_count > MAX_HEADER_FIELDS {
            return Err(HeadError::TooManyFields);
        }
        line_start = line_end + 2;
    }
}

fn find_crlf(input: &[u8], start: usize) -> Option<usize> {
    input[start..]
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|relative| start + relative)
}

#[derive(Clone, Copy)]
enum MessageKind {
    Request,
    Response,
}

struct HeaderSummary {
    content_type: ContentType,
    content_encoding_present: bool,
    expect_present: bool,
    connection_close: bool,
    framing: BodyFraming,
}

fn summarize_headers(
    headers: &[httparse::Header<'_>],
    kind: MessageKind,
) -> Result<HeaderSummary, HeadError> {
    let mut content_length = None;
    let mut transfer_encoding = None;
    let mut content_type = ContentType::Absent;
    let mut content_encoding_present = false;
    let mut expect_present = false;
    let mut connection_close = false;

    for header in headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(HeadError::DuplicateContentLength);
            }
            content_length = Some(parse_content_length(header.value)?);
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding.is_some() {
                return Err(HeadError::DuplicateTransferEncoding);
            }
            if !trim_ows(header.value).eq_ignore_ascii_case(b"chunked") {
                return Err(HeadError::UnsupportedTransferCoding);
            }
            transfer_encoding = Some(());
        } else if header.name.eq_ignore_ascii_case("upgrade")
            || header.name.eq_ignore_ascii_case("trailer")
        {
            return Err(HeadError::UpgradeOrTrailersForbidden);
        } else if header.name.eq_ignore_ascii_case("connection") {
            for token in comma_tokens(header.value) {
                if token.eq_ignore_ascii_case(b"upgrade") {
                    return Err(HeadError::UpgradeOrTrailersForbidden);
                }
                if token.eq_ignore_ascii_case(b"close") {
                    connection_close = true;
                }
            }
        } else if header.name.eq_ignore_ascii_case("content-type") {
            content_type = match content_type {
                ContentType::Absent => {
                    if trim_ows(header.value).eq_ignore_ascii_case(b"application/json") {
                        ContentType::ApplicationJson
                    } else {
                        ContentType::Other
                    }
                }
                _ => ContentType::Multiple,
            };
        } else if header.name.eq_ignore_ascii_case("content-encoding") {
            content_encoding_present = true;
        } else if header.name.eq_ignore_ascii_case("expect") {
            expect_present = true;
        }
    }

    if content_length.is_some() && transfer_encoding.is_some() {
        return Err(HeadError::ConflictingFraming);
    }
    let framing = match (content_length, transfer_encoding, kind) {
        (Some(length), None, _) => BodyFraming::ContentLength(length),
        (None, Some(()), _) => BodyFraming::Chunked,
        (None, None, MessageKind::Request) => BodyFraming::None,
        (None, None, MessageKind::Response) => BodyFraming::CloseDelimited,
        (Some(_), Some(()), _) => return Err(HeadError::ConflictingFraming),
    };
    Ok(HeaderSummary {
        content_type,
        content_encoding_present,
        expect_present,
        connection_close,
        framing,
    })
}

pub(super) fn parse_content_length(value: &[u8]) -> Result<u64, HeadError> {
    let value = trim_ows(value);
    if value.is_empty()
        || !value.iter().all(u8::is_ascii_digit)
        || (value.len() > 1 && value[0] == b'0')
    {
        return Err(HeadError::NonCanonicalContentLength);
    }
    value.iter().try_fold(0_u64, |length, byte| {
        length
            .checked_mul(10)
            .and_then(|length| length.checked_add(u64::from(*byte - b'0')))
            .ok_or(HeadError::ArithmeticOverflow)
    })
}

pub(super) fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn comma_tokens(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value.split(|byte| *byte == b',').map(trim_ows)
}

fn map_parse_error(error: httparse::Error) -> HeadError {
    match error {
        httparse::Error::TooManyHeaders => HeadError::TooManyFields,
        _ => HeadError::MalformedHead,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeadError {
    ArithmeticOverflow,
    ConflictingFraming,
    DuplicateContentLength,
    DuplicateTransferEncoding,
    FieldLineTooLong,
    HeadTooLarge,
    Http11Required,
    InterimResponseForbidden,
    MalformedHead,
    NonCanonicalContentLength,
    NonCanonicalLineEnding,
    RequestTargetTooLong,
    Store(ParserStoreError),
    TooManyFields,
    UnsupportedTransferCoding,
    UpgradeOrTrailersForbidden,
}

impl fmt::Display for HeadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ArithmeticOverflow => "HTTP/1 head arithmetic overflow",
            Self::ConflictingFraming => "conflicting HTTP/1 entity framing",
            Self::DuplicateContentLength => "duplicate HTTP/1 Content-Length",
            Self::DuplicateTransferEncoding => "duplicate HTTP/1 Transfer-Encoding",
            Self::FieldLineTooLong => "HTTP/1 field line exceeds 16 KiB",
            Self::HeadTooLarge => "HTTP/1 head exceeds 64 KiB",
            Self::Http11Required => "HTTP/1.1 is required",
            Self::InterimResponseForbidden => "interim HTTP/1 responses are forbidden",
            Self::MalformedHead => "malformed HTTP/1 head",
            Self::NonCanonicalContentLength => "noncanonical HTTP/1 Content-Length",
            Self::NonCanonicalLineEnding => "HTTP/1 head requires exact CRLF line endings",
            Self::RequestTargetTooLong => "HTTP/1 request target exceeds 8 KiB",
            Self::Store(error) => return error.fmt(formatter),
            Self::TooManyFields => "HTTP/1 head exceeds 128 fields",
            Self::UnsupportedTransferCoding => "unsupported HTTP/1 transfer coding",
            Self::UpgradeOrTrailersForbidden => "HTTP/1 Upgrade and trailers are forbidden",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for HeadError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http1::framing::{BodyFramer, BodyProgress, FramingProcessError};

    #[test]
    fn webhook_acknowledgement_head_and_framing_are_bounded() {
        let mut store = ParserStore::try_new().unwrap();
        store
            .append(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4;note=safe\r\nbody\r\n0\r\n\r\n")
            .unwrap();
        let HeadParse::Complete(head) = parse_response_head(&mut store).unwrap() else {
            panic!("response head was incomplete");
        };
        assert_eq!(head.status, 200);
        assert_eq!(head.framing, BodyFraming::Chunked);
        assert!(head.connection_close);
        assert_eq!(store.initialized(), b"4;note=safe\r\nbody\r\n0\r\n\r\n");

        let mut body = Vec::new();
        let mut framer = BodyFramer::new(head.framing);
        assert_eq!(
            framer.process(&mut store, false, |bytes| {
                body.extend_from_slice(bytes);
                Ok::<_, ()>(())
            }),
            Ok(BodyProgress::Complete)
        );
        assert_eq!(body, b"body");
        assert!(store.complete_storage().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn callback_http_contract_framing_and_parser_bounds() {
        let mut store = ParserStore::try_new().unwrap();
        store
            .append(b"POST /_acl-proxy/external-auth/callback HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 97\r\n\r\n")
            .unwrap();
        let HeadParse::Complete(head) = parse_request_head(&mut store).unwrap() else {
            panic!("request head was incomplete");
        };
        assert_eq!(head.method, RequestMethod::Post);
        assert_eq!(
            head.target.as_bytes(),
            b"/_acl-proxy/external-auth/callback"
        );
        assert_eq!(head.content_type, ContentType::ApplicationJson);
        assert_eq!(head.framing, BodyFraming::ContentLength(97));

        for malformed in [
            b"POST / HTTP/1.1\nContent-Length: 1\n\n".as_slice(),
            b"POST / HTTP/1.1\r\nContent-Length: 01\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"
                .as_slice(),
            b"POST / HTTP/1.1\r\nTrailer: X-Secret\r\nTransfer-Encoding: chunked\r\n\r\n"
                .as_slice(),
        ] {
            store.wipe();
            store.append(malformed).unwrap();
            assert!(parse_request_head(&mut store).is_err());
        }

        let mut too_many = b"GET / HTTP/1.1\r\n".to_vec();
        for _ in 0..=MAX_HEADER_FIELDS {
            too_many.extend_from_slice(b"X: y\r\n");
        }
        too_many.extend_from_slice(b"\r\n");
        store.wipe();
        store.append(&too_many).unwrap();
        assert_eq!(
            parse_request_head(&mut store),
            Err(HeadError::TooManyFields)
        );

        let _type_check: Option<FramingProcessError<()>> = None;
    }

    #[test]
    fn request_head_limits_accept_exact_boundaries_and_reject_one_more() {
        let exact_fields = request_with_fields(MAX_HEADER_FIELDS);
        let mut store = ParserStore::try_new().unwrap();
        store.append(&exact_fields).unwrap();
        assert!(matches!(
            parse_request_head(&mut store),
            Ok(HeadParse::Complete(_))
        ));

        let too_many_fields = request_with_fields(MAX_HEADER_FIELDS + 1);
        store.wipe();
        store.append(&too_many_fields).unwrap();
        assert_eq!(
            parse_request_head(&mut store),
            Err(HeadError::TooManyFields)
        );

        let exact_field_line = request_with_field_line(MAX_FIELD_LINE_BYTES);
        store.wipe();
        store.append(&exact_field_line).unwrap();
        assert!(matches!(
            parse_request_head(&mut store),
            Ok(HeadParse::Complete(_))
        ));

        let oversized_field_line = request_with_field_line(MAX_FIELD_LINE_BYTES + 1);
        store.wipe();
        store.append(&oversized_field_line).unwrap();
        assert_eq!(
            parse_request_head(&mut store),
            Err(HeadError::FieldLineTooLong)
        );

        let exact_target = request_with_target(MAX_REQUEST_TARGET_BYTES);
        store.wipe();
        store.append(&exact_target).unwrap();
        let HeadParse::Complete(head) = parse_request_head(&mut store).unwrap() else {
            panic!("exact-limit request target was incomplete");
        };
        assert_eq!(head.target.as_bytes().len(), MAX_REQUEST_TARGET_BYTES);

        let oversized_target = request_with_target(MAX_REQUEST_TARGET_BYTES + 1);
        store.wipe();
        store.append(&oversized_target).unwrap();
        assert_eq!(
            parse_request_head(&mut store),
            Err(HeadError::RequestTargetTooLong)
        );
    }

    #[test]
    fn request_anti_smuggling_and_metadata_matrix_is_exact() {
        let cases: &[(&[u8], HeadError)] = &[
            (
                b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
                HeadError::DuplicateContentLength,
            ),
            (
                b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
                HeadError::DuplicateTransferEncoding,
            ),
            (
                b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
                HeadError::UnsupportedTransferCoding,
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
                HeadError::ConflictingFraming,
            ),
            (
                b"POST / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n",
                HeadError::UpgradeOrTrailersForbidden,
            ),
            (
                b"POST / HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\n\r\n",
                HeadError::UpgradeOrTrailersForbidden,
            ),
            (b"POST / HTTP/1.0\r\n\r\n", HeadError::Http11Required),
            (
                b"POST / HTTP/1.1\r\nContent-Length: 18446744073709551616\r\n\r\n",
                HeadError::ArithmeticOverflow,
            ),
        ];
        for (wire, expected) in cases {
            let mut store = ParserStore::try_new().unwrap();
            store.append(wire).unwrap();
            assert_eq!(parse_request_head(&mut store), Err(*expected), "{wire:?}");
        }

        let mut full_unterminated = ParserStore::try_new().unwrap();
        full_unterminated
            .append(&vec![b'a'; PARSER_STORE_BYTES])
            .unwrap();
        assert_eq!(
            parse_request_head(&mut full_unterminated),
            Err(HeadError::HeadTooLarge)
        );

        let mut store = ParserStore::try_new().unwrap();
        store
            .append(
                b"POST / HTTP/1.1\r\nContent-Type: application/json; charset=utf-8\r\nContent-Encoding: gzip\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n",
            )
            .unwrap();
        let HeadParse::Complete(other_media) = parse_request_head(&mut store).unwrap() else {
            panic!("metadata request was incomplete");
        };
        assert_eq!(other_media.content_type, ContentType::Other);
        assert!(other_media.content_encoding_present);
        assert!(other_media.expect_present);

        store.wipe();
        store
            .append(
                b"POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n",
            )
            .unwrap();
        let HeadParse::Complete(multiple_media) = parse_request_head(&mut store).unwrap() else {
            panic!("multiple media-type request was incomplete");
        };
        assert_eq!(multiple_media.content_type, ContentType::Multiple);
        assert!(!multiple_media.content_encoding_present);
        assert!(!multiple_media.expect_present);
    }

    #[test]
    fn acknowledgement_response_rejection_matrix_is_exact() {
        let cases: &[(&[u8], HeadError)] = &[
            (
                b"HTTP/1.1 100 Continue\r\n\r\n",
                HeadError::InterimResponseForbidden,
            ),
            (b"HTTP/1.0 200 OK\r\n\r\n", HeadError::Http11Required),
            (
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                HeadError::InterimResponseForbidden,
            ),
            (
                b"HTTP/1.1 200 OK\r\nUpgrade: websocket\r\n\r\n",
                HeadError::UpgradeOrTrailersForbidden,
            ),
            (
                b"HTTP/1.1 200 OK\r\nConnection: keep-alive, upgrade\r\n\r\n",
                HeadError::UpgradeOrTrailersForbidden,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
                HeadError::DuplicateContentLength,
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
                HeadError::DuplicateTransferEncoding,
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
                HeadError::UnsupportedTransferCoding,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
                HeadError::ConflictingFraming,
            ),
        ];
        for (wire, expected) in cases {
            let mut store = ParserStore::try_new().unwrap();
            store.append(wire).unwrap();
            assert_eq!(parse_response_head(&mut store), Err(*expected), "{wire:?}");
        }

        let mut full_unterminated = ParserStore::try_new().unwrap();
        full_unterminated
            .append(&vec![b'a'; PARSER_STORE_BYTES])
            .unwrap();
        assert_eq!(
            parse_response_head(&mut full_unterminated),
            Err(HeadError::HeadTooLarge)
        );
    }

    #[test]
    fn request_target_debug_output_elides_wire_bytes() {
        let target = RequestTarget::new(b"/secret-bearing-target").unwrap();
        let rendered = format!("{target:?}");
        assert!(rendered.contains("<elided>"));
        assert!(rendered.contains("22"));
        assert!(!rendered.contains("secret-bearing-target"));
    }

    #[test]
    fn control_parser_head_reclamation_is_exact() {
        let head = exact_capacity_request_head();
        assert_eq!(head.len(), PARSER_STORE_BYTES);
        let mut store = ParserStore::try_new().unwrap();
        store.append(&head).unwrap();

        let HeadParse::Complete(parsed) = parse_request_head(&mut store).unwrap() else {
            panic!("exact-capacity request head was incomplete");
        };
        assert_eq!(parsed.method, RequestMethod::Post);
        assert_eq!(store.initialized_len(), 0);
        assert!(store.complete_storage().iter().all(|byte| *byte == 0));

        let mut maximum_chunk_line = b"4;edge=".to_vec();
        maximum_chunk_line.extend(std::iter::repeat_n(
            b'a',
            crate::http1::framing::MAX_CHUNK_LINE_BYTES - maximum_chunk_line.len() - 2,
        ));
        maximum_chunk_line.extend_from_slice(b"\r\n");
        assert_eq!(
            maximum_chunk_line.len(),
            crate::http1::framing::MAX_CHUNK_LINE_BYTES
        );
        store.append(&maximum_chunk_line).unwrap();
        store.append(b"body\r\n0\r\n\r\n").unwrap();
        let mut output = Vec::new();
        let mut framer = BodyFramer::new(BodyFraming::Chunked);
        assert_eq!(
            framer.process(&mut store, false, |bytes| {
                output.extend_from_slice(bytes);
                Ok::<_, ()>(())
            }),
            Ok(BodyProgress::Complete)
        );
        assert_eq!(output, b"body");
    }

    #[test]
    fn exact_limit_head_scanning_is_linear_when_fragmented() {
        let head = exact_capacity_request_head();
        let mut store = ParserStore::try_new().unwrap();
        for (index, byte) in head.iter().copied().enumerate() {
            store.append(&[byte]).unwrap();
            let parsed = parse_request_head(&mut store).unwrap();
            if index + 1 == head.len() {
                assert!(matches!(parsed, HeadParse::Complete(_)));
            } else {
                assert_eq!(parsed, HeadParse::Incomplete);
            }
        }
        assert_eq!(store.inspected_head_bytes_for_test(), head.len());
    }

    #[test]
    fn incomplete_head_scan_survives_lazy_store_compaction() {
        let head = exact_capacity_request_head();
        let split = PARSER_STORE_BYTES / 2;
        let discard = vec![b'x'; 1024];
        let mut store = ParserStore::try_new().unwrap();
        store.append(&discard).unwrap();
        store.append(&head[..split]).unwrap();
        store.consume_prefix(discard.len()).unwrap();
        assert_eq!(
            parse_request_head(&mut store).unwrap(),
            HeadParse::Incomplete
        );

        store.append(&head[split..]).unwrap();
        assert!(matches!(
            parse_request_head(&mut store),
            Ok(HeadParse::Complete(_))
        ));
        assert_eq!(store.inspected_head_bytes_for_test(), head.len());
        assert_eq!(store.moved_bytes_for_test(), split);
    }

    #[test]
    fn response_without_explicit_length_is_close_delimited() {
        let mut store = ParserStore::try_new().unwrap();
        store
            .append(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody")
            .unwrap();
        let HeadParse::Complete(head) = parse_response_head(&mut store).unwrap() else {
            panic!("response head was incomplete");
        };
        assert_eq!(head.framing, BodyFraming::CloseDelimited);
        assert_eq!(store.initialized(), b"body");
    }

    fn exact_capacity_request_head() -> Vec<u8> {
        let mut head = b"POST /_acl-proxy/external-auth/callback HTTP/1.1\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n".to_vec();
        let mut field = 0;
        while PARSER_STORE_BYTES - head.len() > MAX_FIELD_LINE_BYTES + 2 {
            let prefix = format!("X-Pad-{field}: ");
            head.extend_from_slice(prefix.as_bytes());
            head.extend(std::iter::repeat_n(
                b'a',
                MAX_FIELD_LINE_BYTES - prefix.len() - 2,
            ));
            head.extend_from_slice(b"\r\n");
            field += 1;
        }
        let remaining = PARSER_STORE_BYTES - head.len();
        assert!(remaining >= b"X: \r\n\r\n".len());
        head.extend_from_slice(b"X: ");
        head.extend(std::iter::repeat_n(b'b', remaining - b"X: \r\n\r\n".len()));
        head.extend_from_slice(b"\r\n\r\n");
        head
    }

    fn request_with_fields(count: usize) -> Vec<u8> {
        let mut head = b"GET / HTTP/1.1\r\n".to_vec();
        for index in 0..count {
            head.extend_from_slice(format!("X-{index}: value\r\n").as_bytes());
        }
        head.extend_from_slice(b"\r\n");
        head
    }

    fn request_with_field_line(line_bytes: usize) -> Vec<u8> {
        let mut head = b"GET / HTTP/1.1\r\nX: ".to_vec();
        head.extend(std::iter::repeat_n(b'a', line_bytes - b"X: \r\n".len()));
        head.extend_from_slice(b"\r\n\r\n");
        head
    }

    fn request_with_target(target_bytes: usize) -> Vec<u8> {
        let mut head = b"GET /".to_vec();
        head.extend(std::iter::repeat_n(b'a', target_bytes - 1));
        head.extend_from_slice(b" HTTP/1.1\r\n\r\n");
        head
    }
}
