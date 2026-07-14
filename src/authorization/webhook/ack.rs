use std::fmt;

use crate::http1::framing::{
    BodyFramer, BodyFraming, BodyProgress, FramingError, FramingProcessError,
};
use crate::http1::head::{parse_response_head, HeadError, HeadParse};
use crate::http1::store::ParserStore;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WebhookAcknowledgement {
    pub(crate) status: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AcknowledgementProgress {
    NeedInput,
    Complete(WebhookAcknowledgement),
}

pub(crate) struct AcknowledgementParser {
    max_response_bytes: u64,
    state: ParserState,
}

enum ParserState {
    Head,
    Body { status: u16, framer: BodyFramer },
    Complete(WebhookAcknowledgement),
    Failed,
}

impl AcknowledgementParser {
    pub(crate) fn new(max_response_bytes: usize) -> Result<Self, AcknowledgementError> {
        let max_response_bytes = u64::try_from(max_response_bytes)
            .map_err(|_| AcknowledgementError::ResponseLimitUnrepresentable)?;
        Ok(Self {
            max_response_bytes,
            state: ParserState::Head,
        })
    }

    pub(crate) fn process(
        &mut self,
        store: &mut ParserStore,
        end_of_stream: bool,
    ) -> Result<AcknowledgementProgress, AcknowledgementError> {
        let result = self.process_inner(store, end_of_stream);
        if result.is_err() {
            self.state = ParserState::Failed;
        }
        result
    }

    fn process_inner(
        &mut self,
        store: &mut ParserStore,
        end_of_stream: bool,
    ) -> Result<AcknowledgementProgress, AcknowledgementError> {
        if matches!(self.state, ParserState::Head) {
            let head = match parse_response_head(store).map_err(AcknowledgementError::Head)? {
                HeadParse::Incomplete if end_of_stream => {
                    return Err(AcknowledgementError::UnexpectedEndOfStream);
                }
                HeadParse::Incomplete => return Ok(AcknowledgementProgress::NeedInput),
                HeadParse::Complete(head) => head,
            };
            match head.framing {
                BodyFraming::ContentLength(length) => {
                    if length > self.max_response_bytes {
                        return Err(AcknowledgementError::ResponseBodyTooLarge);
                    }
                }
                BodyFraming::Chunked | BodyFraming::CloseDelimited | BodyFraming::None => {}
            }
            self.state = ParserState::Body {
                status: head.status,
                framer: BodyFramer::new(head.framing),
            };
        }

        let ParserState::Body { status, framer } = &mut self.state else {
            return match &self.state {
                ParserState::Complete(acknowledgement) => {
                    if store.initialized_len() == 0 {
                        Ok(AcknowledgementProgress::Complete(*acknowledgement))
                    } else {
                        Err(AcknowledgementError::BytesAfterResponse)
                    }
                }
                ParserState::Failed => Err(AcknowledgementError::ParserFailed),
                ParserState::Head | ParserState::Body { .. } => unreachable!(),
            };
        };

        let max_response_bytes = self.max_response_bytes;
        let mut entity_bytes = framer.entity_bytes();
        let progress = framer
            .process(store, end_of_stream, |bytes| {
                let bytes = u64::try_from(bytes.len()).map_err(|_| ResponseLimitExceeded)?;
                let remaining = max_response_bytes
                    .checked_sub(entity_bytes)
                    .ok_or(ResponseLimitExceeded)?;
                if bytes > remaining {
                    return Err(ResponseLimitExceeded);
                }
                entity_bytes += bytes;
                Ok(())
            })
            .map_err(|error| match error {
                FramingProcessError::Framing(FramingError::UnexpectedEndOfStream) => {
                    AcknowledgementError::UnexpectedEndOfStream
                }
                FramingProcessError::Framing(error) => AcknowledgementError::Framing(error),
                FramingProcessError::Sink(ResponseLimitExceeded) => {
                    AcknowledgementError::ResponseBodyTooLarge
                }
            })?;
        match progress {
            BodyProgress::NeedInput if end_of_stream => {
                Err(AcknowledgementError::UnexpectedEndOfStream)
            }
            BodyProgress::NeedInput | BodyProgress::Paused => {
                Ok(AcknowledgementProgress::NeedInput)
            }
            BodyProgress::Complete => {
                if store.initialized_len() != 0 {
                    return Err(AcknowledgementError::BytesAfterResponse);
                }
                if !(200..300).contains(status) {
                    return Err(AcknowledgementError::NonSuccessStatus(*status));
                }
                let acknowledgement = WebhookAcknowledgement { status: *status };
                self.state = ParserState::Complete(acknowledgement);
                Ok(AcknowledgementProgress::Complete(acknowledgement))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResponseLimitExceeded;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AcknowledgementError {
    BytesAfterResponse,
    Cancelled,
    Framing(FramingError),
    Head(HeadError),
    NonSuccessStatus(u16),
    ParserFailed,
    Read,
    ResponseBodyTooLarge,
    ResponseLimitUnrepresentable,
    StoreCapacityExceeded,
    UnexpectedEndOfStream,
}

impl fmt::Display for AcknowledgementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BytesAfterResponse => {
                formatter.write_str("bytes follow the framed webhook acknowledgement")
            }
            Self::Cancelled => formatter.write_str("webhook acknowledgement read was cancelled"),
            Self::Framing(error) => error.fmt(formatter),
            Self::Head(error) => error.fmt(formatter),
            Self::NonSuccessStatus(status) => {
                write!(
                    formatter,
                    "webhook acknowledgement returned status {status}"
                )
            }
            Self::ParserFailed => formatter.write_str("webhook acknowledgement parser failed"),
            Self::Read => formatter.write_str("webhook acknowledgement socket read failed"),
            Self::ResponseBodyTooLarge => {
                formatter.write_str("webhook acknowledgement entity exceeds its configured limit")
            }
            Self::ResponseLimitUnrepresentable => formatter
                .write_str("webhook acknowledgement entity limit is not representable as u64"),
            Self::StoreCapacityExceeded => {
                formatter.write_str("webhook acknowledgement parser store capacity was exceeded")
            }
            Self::UnexpectedEndOfStream => {
                formatter.write_str("webhook acknowledgement ended before framing completed")
            }
        }
    }
}

impl std::error::Error for AcknowledgementError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http1::framing::MAX_CHUNK_LINE_BYTES;
    use crate::http1::head::{MAX_FIELD_LINE_BYTES, MAX_HEADER_FIELDS};
    use crate::http1::store::PARSER_STORE_BYTES;

    #[test]
    fn webhook_delivery_ack_and_failure_matrix() {
        for wire in [
            b"HTTP/1.1 204 No Content\r\n\r\n".as_slice(),
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\n\r\nbody".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody".as_slice(),
            b"HTTP/1.1 299 Fine\r\nTransfer-Encoding: chunked\r\n\r\n4;safe=yes\r\nbody\r\n0\r\n\r\n"
                .as_slice(),
        ] {
            assert!(matches!(
                parse_complete(wire, 4),
                Ok(AcknowledgementProgress::Complete(_))
            ));
        }

        let cases = [
            (
                b"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n".as_slice(),
                AcknowledgementError::Head(HeadError::InterimResponseForbidden),
            ),
            (
                b"HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: h2c\r\nContent-Length: 0\r\n\r\n"
                    .as_slice(),
                AcknowledgementError::Head(HeadError::UpgradeOrTrailersForbidden),
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"
                    .as_slice(),
                AcknowledgementError::Head(HeadError::DuplicateContentLength),
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n".as_slice(),
                AcknowledgementError::Head(HeadError::UnsupportedTransferCoding),
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n".as_slice(),
                AcknowledgementError::Head(HeadError::ArithmeticOverflow),
            ),
            (
                b"HTTP/1.1 503 Unavailable\r\nContent-Length: 4\r\n\r\nbody".as_slice(),
                AcknowledgementError::NonSuccessStatus(503),
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nbody".as_slice(),
                AcknowledgementError::UnexpectedEndOfStream,
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\nX: y\r\n\r\n"
                    .as_slice(),
                AcknowledgementError::Framing(FramingError::TrailersForbidden),
            ),
        ];
        for (wire, expected) in cases {
            assert_eq!(parse_complete(wire, 64), Err(expected), "{wire:?}");
        }
    }

    #[test]
    fn acknowledgement_entity_limit_is_cumulative_and_allocation_free() {
        assert_eq!(
            parse_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n12345", 4,),
            Err(AcknowledgementError::ResponseBodyTooLarge)
        );
        assert_eq!(
            parse_complete(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
                4,
            ),
            Err(AcknowledgementError::ResponseBodyTooLarge)
        );
        assert_eq!(
            parse_complete(b"HTTP/1.1 200 OK\r\n\r\n12345", 4),
            Err(AcknowledgementError::ResponseBodyTooLarge)
        );
    }

    #[test]
    fn acknowledgement_parser_is_incremental_and_rejects_following_bytes() {
        let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody";
        let mut store = ParserStore::try_with_capacity(PARSER_STORE_BYTES + 128).unwrap();
        let mut parser = AcknowledgementParser::new(4).unwrap();
        for (index, byte) in wire.iter().copied().enumerate() {
            store.append(&[byte]).unwrap();
            let progress = parser.process(&mut store, false).unwrap();
            if index + 1 == wire.len() {
                assert!(matches!(progress, AcknowledgementProgress::Complete(_)));
            } else {
                assert_eq!(progress, AcknowledgementProgress::NeedInput);
            }
        }

        store
            .append(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        assert_eq!(
            parser.process(&mut store, false),
            Err(AcknowledgementError::BytesAfterResponse)
        );
    }

    #[test]
    fn webhook_ack_parser_head_reclamation_is_exact() {
        let head = exact_response_head(PARSER_STORE_BYTES);
        let mut store = ParserStore::try_with_capacity(PARSER_STORE_BYTES + 1).unwrap();
        store.append(&head).unwrap();
        let mut parser = AcknowledgementParser::new(4).unwrap();

        assert_eq!(
            parser.process(&mut store, false),
            Ok(AcknowledgementProgress::NeedInput)
        );
        assert_eq!(store.initialized_len(), 0);
        assert_eq!(store.zeroized_bytes_for_test(), PARSER_STORE_BYTES);
        assert!(store.complete_storage().iter().all(|byte| *byte == 0));

        let mut chunk_line = b"4;edge=".to_vec();
        chunk_line.extend(std::iter::repeat_n(
            b'a',
            MAX_CHUNK_LINE_BYTES - chunk_line.len() - 2,
        ));
        chunk_line.extend_from_slice(b"\r\n");
        assert_eq!(chunk_line.len(), MAX_CHUNK_LINE_BYTES);
        store.append(&chunk_line).unwrap();
        store.append(b"body\r\n0\r\n\r\n").unwrap();
        assert!(matches!(
            parser.process(&mut store, false),
            Ok(AcknowledgementProgress::Complete(_))
        ));

        let oversized = exact_response_head(PARSER_STORE_BYTES + 1);
        store.append(&oversized).unwrap();
        let mut parser = AcknowledgementParser::new(4).unwrap();
        assert_eq!(
            parser.process(&mut store, false),
            Err(AcknowledgementError::Head(HeadError::HeadTooLarge))
        );
    }

    fn parse_complete(
        wire: &[u8],
        max_response_bytes: usize,
    ) -> Result<AcknowledgementProgress, AcknowledgementError> {
        let capacity = PARSER_STORE_BYTES.max(wire.len());
        let mut store = ParserStore::try_with_capacity(capacity).unwrap();
        store.append(wire).unwrap();
        AcknowledgementParser::new(max_response_bytes)?.process(&mut store, true)
    }

    fn exact_response_head(target_bytes: usize) -> Vec<u8> {
        let mut head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n".to_vec();
        let mut field = 0;
        while target_bytes - head.len() > MAX_FIELD_LINE_BYTES + 2 {
            let prefix = format!("X-Pad-{field}: ");
            head.extend_from_slice(prefix.as_bytes());
            head.extend(std::iter::repeat_n(
                b'a',
                MAX_FIELD_LINE_BYTES - prefix.len() - 2,
            ));
            head.extend_from_slice(b"\r\n");
            field += 1;
        }
        assert!(field < MAX_HEADER_FIELDS);
        let remaining = target_bytes - head.len();
        assert!(remaining >= b"X: \r\n\r\n".len());
        head.extend_from_slice(b"X: ");
        head.extend(std::iter::repeat_n(b'b', remaining - b"X: \r\n\r\n".len()));
        head.extend_from_slice(b"\r\n\r\n");
        assert_eq!(head.len(), target_bytes);
        head
    }
}
