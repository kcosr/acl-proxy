use std::fmt;

use super::store::{ParserStore, ParserStoreError};

pub(crate) const MAX_CHUNK_LINE_BYTES: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BodyFraming {
    None,
    ContentLength(u64),
    Chunked,
    CloseDelimited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BodyProgress {
    NeedInput,
    Paused,
    Complete,
}

pub(crate) struct BodyFramer {
    state: FramingState,
    entity_bytes: u64,
    chunk_scan_cursor: usize,
    chunk_pending_cr: Option<usize>,
    #[cfg(test)]
    chunk_scan_inspected: usize,
}

enum FramingState {
    None,
    ContentLength(u64),
    ChunkSize,
    ChunkData(u64),
    ChunkDataTerminator,
    ChunkTrailerTerminator,
    CloseDelimited,
    Complete,
}

impl BodyFramer {
    pub(crate) fn new(framing: BodyFraming) -> Self {
        let state = match framing {
            BodyFraming::None => FramingState::None,
            BodyFraming::ContentLength(remaining) => FramingState::ContentLength(remaining),
            BodyFraming::Chunked => FramingState::ChunkSize,
            BodyFraming::CloseDelimited => FramingState::CloseDelimited,
        };
        Self {
            state,
            entity_bytes: 0,
            chunk_scan_cursor: 0,
            chunk_pending_cr: None,
            #[cfg(test)]
            chunk_scan_inspected: 0,
        }
    }

    pub(crate) fn entity_bytes(&self) -> u64 {
        self.entity_bytes
    }

    #[cfg(test)]
    pub(crate) fn inspected_chunk_line_bytes_for_test(&self) -> usize {
        self.chunk_scan_inspected
    }

    pub(crate) fn process<E>(
        &mut self,
        store: &mut ParserStore,
        end_of_stream: bool,
        consume_entity: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<BodyProgress, FramingProcessError<E>> {
        self.process_inner(store, end_of_stream, None, consume_entity)
    }

    pub(crate) fn process_up_to<E>(
        &mut self,
        store: &mut ParserStore,
        end_of_stream: bool,
        entity_octet_limit: u64,
        consume_entity: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<BodyProgress, FramingProcessError<E>> {
        if entity_octet_limit < self.entity_bytes {
            return Err(FramingError::EntityLimitBehindProgress.into());
        }
        self.process_inner(
            store,
            end_of_stream,
            Some(entity_octet_limit),
            consume_entity,
        )
    }

    fn process_inner<E>(
        &mut self,
        store: &mut ParserStore,
        end_of_stream: bool,
        entity_octet_limit: Option<u64>,
        mut consume_entity: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<BodyProgress, FramingProcessError<E>> {
        loop {
            match self.state {
                FramingState::None => {
                    self.state = FramingState::Complete;
                }
                FramingState::ContentLength(0) => {
                    self.state = FramingState::Complete;
                }
                FramingState::ContentLength(remaining) => {
                    if self.at_entity_limit(entity_octet_limit) {
                        return Ok(BodyProgress::Paused);
                    }
                    if store.initialized_len() == 0 {
                        return if end_of_stream {
                            Err(FramingError::UnexpectedEndOfStream.into())
                        } else {
                            Ok(BodyProgress::NeedInput)
                        };
                    }
                    let available = u64::try_from(store.initialized_len())
                        .map_err(|_| FramingError::ArithmeticOverflow)?;
                    let consumed =
                        self.limit_consumption(remaining.min(available), entity_octet_limit)?;
                    self.consume(store, consumed, &mut consume_entity)?;
                    self.state = FramingState::ContentLength(remaining - consumed);
                    if self.at_entity_limit(entity_octet_limit) {
                        return Ok(BodyProgress::Paused);
                    }
                }
                FramingState::CloseDelimited => {
                    if self.at_entity_limit(entity_octet_limit) {
                        return Ok(BodyProgress::Paused);
                    }
                    if store.initialized_len() != 0 {
                        let available = u64::try_from(store.initialized_len())
                            .map_err(|_| FramingError::ArithmeticOverflow)?;
                        let consumed = self.limit_consumption(available, entity_octet_limit)?;
                        self.consume(store, consumed, &mut consume_entity)?;
                        if self.at_entity_limit(entity_octet_limit) {
                            return Ok(BodyProgress::Paused);
                        }
                    }
                    if end_of_stream {
                        self.state = FramingState::Complete;
                    } else {
                        return Ok(BodyProgress::NeedInput);
                    }
                }
                FramingState::ChunkSize => {
                    if self.at_entity_limit(entity_octet_limit) {
                        return Ok(BodyProgress::Paused);
                    }
                    let Some(line_end) = self.chunk_line_end(store.initialized())? else {
                        return if end_of_stream {
                            Err(FramingError::UnexpectedEndOfStream.into())
                        } else {
                            Ok(BodyProgress::NeedInput)
                        };
                    };
                    let chunk_size = parse_chunk_line(&store.initialized()[..line_end])?;
                    store
                        .consume_prefix(line_end + 2)
                        .map_err(FramingError::Store)?;
                    self.reset_chunk_scan();
                    self.state = if chunk_size == 0 {
                        FramingState::ChunkTrailerTerminator
                    } else {
                        FramingState::ChunkData(chunk_size)
                    };
                }
                FramingState::ChunkData(0) => {
                    if self.at_entity_limit(entity_octet_limit) {
                        return Ok(BodyProgress::Paused);
                    }
                    self.state = FramingState::ChunkDataTerminator;
                }
                FramingState::ChunkData(remaining) => {
                    if self.at_entity_limit(entity_octet_limit) {
                        return Ok(BodyProgress::Paused);
                    }
                    if store.initialized_len() == 0 {
                        return if end_of_stream {
                            Err(FramingError::UnexpectedEndOfStream.into())
                        } else {
                            Ok(BodyProgress::NeedInput)
                        };
                    }
                    let available = u64::try_from(store.initialized_len())
                        .map_err(|_| FramingError::ArithmeticOverflow)?;
                    let consumed =
                        self.limit_consumption(remaining.min(available), entity_octet_limit)?;
                    self.consume(store, consumed, &mut consume_entity)?;
                    self.state = FramingState::ChunkData(remaining - consumed);
                    if self.at_entity_limit(entity_octet_limit) {
                        return Ok(BodyProgress::Paused);
                    }
                }
                FramingState::ChunkDataTerminator => {
                    if self.at_entity_limit(entity_octet_limit) {
                        return Ok(BodyProgress::Paused);
                    }
                    if store.initialized_len() < 2 {
                        return if end_of_stream {
                            Err(FramingError::UnexpectedEndOfStream.into())
                        } else {
                            Ok(BodyProgress::NeedInput)
                        };
                    }
                    if &store.initialized()[..2] != b"\r\n" {
                        return Err(FramingError::MalformedChunkTerminator.into());
                    }
                    store.consume_prefix(2).map_err(FramingError::Store)?;
                    self.state = FramingState::ChunkSize;
                }
                FramingState::ChunkTrailerTerminator => {
                    if self.at_entity_limit(entity_octet_limit) {
                        return Ok(BodyProgress::Paused);
                    }
                    if store.initialized_len() < 2 {
                        if store
                            .initialized()
                            .first()
                            .is_some_and(|byte| *byte != b'\r')
                        {
                            return Err(FramingError::TrailersForbidden.into());
                        }
                        return if end_of_stream {
                            Err(FramingError::UnexpectedEndOfStream.into())
                        } else {
                            Ok(BodyProgress::NeedInput)
                        };
                    }
                    if &store.initialized()[..2] != b"\r\n" {
                        return Err(FramingError::TrailersForbidden.into());
                    }
                    store.consume_prefix(2).map_err(FramingError::Store)?;
                    self.state = FramingState::Complete;
                }
                FramingState::Complete => return Ok(BodyProgress::Complete),
            }
        }
    }

    fn at_entity_limit(&self, entity_octet_limit: Option<u64>) -> bool {
        entity_octet_limit.is_some_and(|limit| self.entity_bytes == limit)
    }

    fn limit_consumption(
        &self,
        available: u64,
        entity_octet_limit: Option<u64>,
    ) -> Result<u64, FramingError> {
        match entity_octet_limit {
            Some(limit) => {
                let remaining = limit
                    .checked_sub(self.entity_bytes)
                    .ok_or(FramingError::EntityLimitBehindProgress)?;
                Ok(available.min(remaining))
            }
            None => Ok(available),
        }
    }

    fn consume<E>(
        &mut self,
        store: &mut ParserStore,
        count: u64,
        consume_entity: &mut impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), FramingProcessError<E>> {
        let count = usize::try_from(count).map_err(|_| FramingError::ArithmeticOverflow)?;
        let next_total = self
            .entity_bytes
            .checked_add(u64::try_from(count).map_err(|_| FramingError::ArithmeticOverflow)?)
            .ok_or(FramingError::ArithmeticOverflow)?;
        consume_entity(&store.initialized()[..count]).map_err(FramingProcessError::Sink)?;
        store.consume_prefix(count).map_err(FramingError::Store)?;
        self.entity_bytes = next_total;
        Ok(())
    }

    fn chunk_line_end(&mut self, input: &[u8]) -> Result<Option<usize>, FramingError> {
        while self.chunk_scan_cursor < input.len() {
            let byte = input[self.chunk_scan_cursor];
            self.chunk_scan_cursor += 1;
            #[cfg(test)]
            {
                self.chunk_scan_inspected += 1;
            }

            if let Some(cr_index) = self.chunk_pending_cr {
                if byte != b'\n' {
                    return Err(FramingError::MalformedChunkLine);
                }
                let total = cr_index
                    .checked_add(2)
                    .ok_or(FramingError::ArithmeticOverflow)?;
                if total > MAX_CHUNK_LINE_BYTES {
                    return Err(FramingError::ChunkLineTooLong);
                }
                return Ok(Some(cr_index));
            }
            match byte {
                b'\r' => self.chunk_pending_cr = Some(self.chunk_scan_cursor - 1),
                b'\n' => return Err(FramingError::MalformedChunkLine),
                _ => {}
            }
        }
        if input.len() >= MAX_CHUNK_LINE_BYTES
            || (input.len() == MAX_CHUNK_LINE_BYTES - 1 && self.chunk_pending_cr.is_none())
        {
            return Err(FramingError::ChunkLineTooLong);
        }
        Ok(None)
    }

    fn reset_chunk_scan(&mut self) {
        self.chunk_scan_cursor = 0;
        self.chunk_pending_cr = None;
    }
}

fn parse_chunk_line(line: &[u8]) -> Result<u64, FramingError> {
    let (size, extensions) = match line.iter().position(|byte| *byte == b';') {
        Some(index) => (&line[..index], &line[index..]),
        None => (line, &[][..]),
    };
    if size.is_empty() {
        return Err(FramingError::MalformedChunkLine);
    }
    let mut parsed = 0_u64;
    for byte in size.iter().copied() {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a' + 10),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return Err(FramingError::MalformedChunkLine),
        };
        parsed = parsed
            .checked_mul(16)
            .and_then(|value| value.checked_add(digit))
            .ok_or(FramingError::ArithmeticOverflow)?;
    }
    validate_chunk_extensions(extensions)?;
    Ok(parsed)
}

fn validate_chunk_extensions(mut input: &[u8]) -> Result<(), FramingError> {
    while !input.is_empty() {
        if input[0] != b';' {
            return Err(FramingError::MalformedChunkLine);
        }
        input = &input[1..];
        let name_len = input.iter().take_while(|byte| is_token(**byte)).count();
        if name_len == 0 {
            return Err(FramingError::MalformedChunkLine);
        }
        input = &input[name_len..];
        if input.first() == Some(&b'=') {
            input = &input[1..];
            if input.first() == Some(&b'"') {
                input = consume_quoted_string(input)?;
            } else {
                let value_len = input.iter().take_while(|byte| is_token(**byte)).count();
                if value_len == 0 {
                    return Err(FramingError::MalformedChunkLine);
                }
                input = &input[value_len..];
            }
        }
    }
    Ok(())
}

fn consume_quoted_string(input: &[u8]) -> Result<&[u8], FramingError> {
    let mut escaped = false;
    for (index, byte) in input.iter().copied().enumerate().skip(1) {
        if escaped {
            if !matches!(byte, b'\t' | 0x20..=0x7e | 0x80..=0xff) {
                return Err(FramingError::MalformedChunkLine);
            }
            escaped = false;
        } else {
            match byte {
                b'\\' => escaped = true,
                b'"' => return Ok(&input[index + 1..]),
                b'\t' | b' ' | 0x21 | 0x23..=0x5b | 0x5d..=0x7e | 0x80..=0xff => {}
                _ => return Err(FramingError::MalformedChunkLine),
            }
        }
    }
    Err(FramingError::MalformedChunkLine)
}

fn is_token(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'0'..=b'9' | b'A'..=b'Z'
            | b'^'..=b'z' | b'|' | b'~'
    )
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FramingProcessError<E> {
    Framing(FramingError),
    Sink(E),
}

impl<E> From<FramingError> for FramingProcessError<E> {
    fn from(error: FramingError) -> Self {
        Self::Framing(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FramingError {
    ArithmeticOverflow,
    ChunkLineTooLong,
    MalformedChunkLine,
    MalformedChunkTerminator,
    TrailersForbidden,
    UnexpectedEndOfStream,
    EntityLimitBehindProgress,
    Store(ParserStoreError),
}

impl fmt::Display for FramingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArithmeticOverflow => formatter.write_str("HTTP/1 framing arithmetic overflow"),
            Self::ChunkLineTooLong => formatter.write_str("HTTP/1 chunk-size line exceeds 4 KiB"),
            Self::MalformedChunkLine => formatter.write_str("malformed HTTP/1 chunk-size line"),
            Self::MalformedChunkTerminator => {
                formatter.write_str("malformed HTTP/1 chunk-data terminator")
            }
            Self::TrailersForbidden => formatter.write_str("HTTP/1 trailers are forbidden"),
            Self::UnexpectedEndOfStream => formatter.write_str("incomplete HTTP/1 entity framing"),
            Self::EntityLimitBehindProgress => {
                formatter.write_str("HTTP/1 entity limit is behind consumed progress")
            }
            Self::Store(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for FramingError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_chunk_framing_accepts_extensions_and_rejects_trailers() {
        let mut store = ParserStore::try_new().unwrap();
        store
            .append(b"4;name=token;quoted=\"safe value\"\r\ntest\r\n0\r\n\r\n")
            .unwrap();
        let mut body = Vec::new();
        let mut framer = BodyFramer::new(BodyFraming::Chunked);
        assert_eq!(
            framer.process(&mut store, false, |bytes| {
                body.extend_from_slice(bytes);
                Ok::<_, ()>(())
            }),
            Ok(BodyProgress::Complete)
        );
        assert_eq!(body, b"test");
        assert_eq!(framer.entity_bytes(), 4);

        store.append(b"0\r\nX-Trailer: forbidden\r\n\r\n").unwrap();
        let mut framer = BodyFramer::new(BodyFraming::Chunked);
        assert!(matches!(
            framer.process(&mut store, false, |_| Ok::<_, ()>(())),
            Err(FramingProcessError::Framing(
                FramingError::TrailersForbidden
            ))
        ));
    }

    #[test]
    fn chunk_line_limit_and_size_overflow_are_rejected() {
        let mut store = ParserStore::try_new().unwrap();
        store.append(&vec![b'a'; MAX_CHUNK_LINE_BYTES - 1]).unwrap();
        let mut framer = BodyFramer::new(BodyFraming::Chunked);
        assert!(matches!(
            framer.process(&mut store, false, |_| Ok::<_, ()>(())),
            Err(FramingProcessError::Framing(FramingError::ChunkLineTooLong))
        ));

        store.wipe();
        store.append(b"10000000000000000\r\n").unwrap();
        let mut framer = BodyFramer::new(BodyFraming::Chunked);
        assert!(matches!(
            framer.process(&mut store, false, |_| Ok::<_, ()>(())),
            Err(FramingProcessError::Framing(
                FramingError::ArithmeticOverflow
            ))
        ));
    }

    #[test]
    fn exact_chunk_line_limit_survives_fragmented_crlf() {
        let mut store = ParserStore::try_new().unwrap();
        let mut exact_prefix = b"1;edge=".to_vec();
        exact_prefix.extend(std::iter::repeat_n(
            b'a',
            MAX_CHUNK_LINE_BYTES - exact_prefix.len() - 2,
        ));
        exact_prefix.push(b'\r');
        assert_eq!(exact_prefix.len(), MAX_CHUNK_LINE_BYTES - 1);
        store.append(&exact_prefix).unwrap();
        let mut framer = BodyFramer::new(BodyFraming::Chunked);
        assert_eq!(
            framer.process(&mut store, false, |_| Ok::<_, ()>(())),
            Ok(BodyProgress::NeedInput)
        );

        store.append(b"\na\r\n0\r\n\r\n").unwrap();
        let mut body = Vec::new();
        assert_eq!(
            framer.process(&mut store, false, |bytes| {
                body.extend_from_slice(bytes);
                Ok::<_, ()>(())
            }),
            Ok(BodyProgress::Complete)
        );
        assert_eq!(body, b"a");

        store.wipe();
        let mut too_long = b"1;edge=".to_vec();
        too_long.extend(std::iter::repeat_n(
            b'a',
            MAX_CHUNK_LINE_BYTES - too_long.len() - 1,
        ));
        too_long.extend_from_slice(b"\r\n");
        assert_eq!(too_long.len(), MAX_CHUNK_LINE_BYTES + 1);
        store.append(&too_long).unwrap();
        let mut framer = BodyFramer::new(BodyFraming::Chunked);
        assert!(matches!(
            framer.process(&mut store, false, |_| Ok::<_, ()>(())),
            Err(FramingProcessError::Framing(FramingError::ChunkLineTooLong))
        ));
    }

    #[test]
    fn repeated_chunk_line_scanning_is_linear_when_fragmented() {
        let mut wire = Vec::new();
        let mut expected_scanned = 0;
        for _ in 0..128 {
            let line = b"1;fixed-extension=abcdefghijklmnopqrstuvwxyz\r\n";
            expected_scanned += line.len();
            wire.extend_from_slice(line);
            wire.extend_from_slice(b"x\r\n");
        }
        expected_scanned += b"0\r\n".len();
        wire.extend_from_slice(b"0\r\n\r\n");

        let mut store = ParserStore::try_new().unwrap();
        let mut framer = BodyFramer::new(BodyFraming::Chunked);
        let mut body = Vec::new();
        for (index, byte) in wire.iter().copied().enumerate() {
            store.append(&[byte]).unwrap();
            let progress = framer
                .process(&mut store, false, |bytes| {
                    body.extend_from_slice(bytes);
                    Ok::<_, ()>(())
                })
                .unwrap();
            if index + 1 == wire.len() {
                assert_eq!(progress, BodyProgress::Complete);
            } else {
                assert_eq!(progress, BodyProgress::NeedInput);
            }
        }
        assert_eq!(body, vec![b'x'; 128]);
        assert_eq!(
            framer.inspected_chunk_line_bytes_for_test(),
            expected_scanned
        );
        assert_eq!(store.zeroized_bytes_for_test(), wire.len());
    }

    #[test]
    fn buffered_small_chunks_do_not_trigger_quadratic_movement() {
        let mut wire = Vec::new();
        for _ in 0..8_000 {
            wire.extend_from_slice(b"1\r\nx\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        assert!(wire.len() < super::super::store::PARSER_STORE_BYTES);

        let mut store = ParserStore::try_new().unwrap();
        store.append(&wire).unwrap();
        let mut entity_bytes = 0_usize;
        let mut framer = BodyFramer::new(BodyFraming::Chunked);
        assert_eq!(
            framer.process(&mut store, false, |bytes| {
                entity_bytes += bytes.len();
                Ok::<_, ()>(())
            }),
            Ok(BodyProgress::Complete)
        );
        assert_eq!(entity_bytes, 8_000);
        assert_eq!(store.moved_bytes_for_test(), 0);
        assert_eq!(store.zeroized_bytes_for_test(), wire.len());
        assert!(store.inactive_storage_is_zeroed_for_test());
    }

    #[test]
    fn content_length_and_close_delimited_framing_are_incremental() {
        let mut store = ParserStore::try_new().unwrap();
        store.append(b"bodynext").unwrap();
        let mut body = Vec::new();
        let mut framer = BodyFramer::new(BodyFraming::ContentLength(4));
        assert_eq!(
            framer.process(&mut store, false, |bytes| {
                body.extend_from_slice(bytes);
                Ok::<_, ()>(())
            }),
            Ok(BodyProgress::Complete)
        );
        assert_eq!(body, b"body");
        assert_eq!(store.initialized(), b"next");

        let mut close = BodyFramer::new(BodyFraming::CloseDelimited);
        assert_eq!(
            close.process(&mut store, true, |_| Ok::<_, ()>(())),
            Ok(BodyProgress::Complete)
        );
    }

    #[test]
    fn malformed_and_truncated_framing_errors_are_exact() {
        let cases: &[(BodyFraming, &[u8], bool, FramingError)] = &[
            (
                BodyFraming::Chunked,
                b"z\r\n",
                false,
                FramingError::MalformedChunkLine,
            ),
            (
                BodyFraming::Chunked,
                b"1;name=\"unterminated\r\n",
                false,
                FramingError::MalformedChunkLine,
            ),
            (
                BodyFraming::Chunked,
                b"1;=x\r\n",
                false,
                FramingError::MalformedChunkLine,
            ),
            (
                BodyFraming::Chunked,
                b"1\r\nxXY",
                false,
                FramingError::MalformedChunkTerminator,
            ),
            (
                BodyFraming::Chunked,
                b"2\r\nx",
                true,
                FramingError::UnexpectedEndOfStream,
            ),
            (
                BodyFraming::Chunked,
                b"1",
                true,
                FramingError::UnexpectedEndOfStream,
            ),
            (
                BodyFraming::Chunked,
                b"0\r\n\r",
                true,
                FramingError::UnexpectedEndOfStream,
            ),
            (
                BodyFraming::ContentLength(2),
                b"x",
                true,
                FramingError::UnexpectedEndOfStream,
            ),
        ];
        for (framing, wire, end_of_stream, expected) in cases {
            let mut store = ParserStore::try_new().unwrap();
            store.append(wire).unwrap();
            let mut framer = BodyFramer::new(*framing);
            assert_eq!(
                framer.process(&mut store, *end_of_stream, |_| Ok::<_, ()>(())),
                Err(FramingProcessError::Framing(*expected)),
                "{wire:?}"
            );
        }
    }

    #[test]
    fn content_length_prefix_boundary_is_cumulative_across_fragmented_input() {
        const PREFIX_BYTES: u64 = 61;
        let body = [vec![b'p'; PREFIX_BYTES as usize], b"suffix".to_vec()].concat();
        let mut store = ParserStore::try_new().unwrap();
        let mut framer = BodyFramer::new(BodyFraming::ContentLength(body.len() as u64));
        let mut exposed = Vec::new();

        for byte in &body[..PREFIX_BYTES as usize - 1] {
            store.append(&[*byte]).unwrap();
            assert_eq!(
                framer.process_up_to(&mut store, false, PREFIX_BYTES, |bytes| {
                    exposed.extend_from_slice(bytes);
                    Ok::<_, ()>(())
                }),
                Ok(BodyProgress::NeedInput)
            );
        }
        store.append(&body[PREFIX_BYTES as usize - 1..]).unwrap();
        assert_eq!(
            framer.process_up_to(&mut store, true, PREFIX_BYTES, |bytes| {
                exposed.extend_from_slice(bytes);
                Ok::<_, ()>(())
            }),
            Ok(BodyProgress::Paused)
        );
        assert_eq!(exposed, vec![b'p'; PREFIX_BYTES as usize]);
        assert_eq!(framer.entity_bytes(), PREFIX_BYTES);
        assert_eq!(store.initialized(), b"suffix");
        assert_eq!(store.zeroized_bytes_for_test(), PREFIX_BYTES as usize);

        let retained = store.initialized().to_vec();
        assert_eq!(
            framer.process_up_to(&mut store, true, PREFIX_BYTES, |_| Ok::<_, ()>(())),
            Ok(BodyProgress::Paused)
        );
        assert_eq!(store.initialized(), retained);

        assert_eq!(
            framer.process(&mut store, true, |bytes| {
                exposed.extend_from_slice(bytes);
                Ok::<_, ()>(())
            }),
            Ok(BodyProgress::Complete)
        );
        assert_eq!(exposed, body);
        assert_eq!(framer.entity_bytes(), body.len() as u64);
    }

    #[test]
    fn exact_content_length_prefix_pauses_before_terminal_completion() {
        const PREFIX_BYTES: u64 = 61;
        let body = vec![b'p'; PREFIX_BYTES as usize];
        let mut store = ParserStore::try_new().unwrap();
        store.append(&body).unwrap();
        let mut framer = BodyFramer::new(BodyFraming::ContentLength(PREFIX_BYTES));
        let mut exposed = Vec::new();

        assert_eq!(
            framer.process_up_to(&mut store, true, PREFIX_BYTES, |bytes| {
                exposed.extend_from_slice(bytes);
                Ok::<_, ()>(())
            }),
            Ok(BodyProgress::Paused)
        );
        assert_eq!(exposed, body);
        assert!(store.initialized().is_empty());

        assert_eq!(
            framer.process(&mut store, true, |_| Ok::<_, ()>(())),
            Ok(BodyProgress::Complete)
        );
        assert_eq!(framer.entity_bytes(), PREFIX_BYTES);
    }

    #[test]
    fn chunked_prefix_boundary_inside_data_leaves_buffered_suffix_unexposed() {
        const PREFIX_BYTES: u64 = 61;
        let first_chunk = vec![b'a'; 64];
        let mut wire = b"40\r\n".to_vec();
        wire.extend_from_slice(&first_chunk);
        wire.extend_from_slice(b"\r\n1\r\nb\r\n0\r\n\r\n");
        let mut store = ParserStore::try_new().unwrap();
        store.append(&wire).unwrap();
        let mut framer = BodyFramer::new(BodyFraming::Chunked);
        let mut exposed = Vec::new();

        assert_eq!(
            framer.process_up_to(&mut store, false, PREFIX_BYTES, |bytes| {
                exposed.extend_from_slice(bytes);
                Ok::<_, ()>(())
            }),
            Ok(BodyProgress::Paused)
        );
        assert_eq!(exposed, vec![b'a'; PREFIX_BYTES as usize]);
        assert_eq!(framer.entity_bytes(), PREFIX_BYTES);
        assert!(store.initialized().starts_with(b"aaa\r\n1\r\nb"));

        assert_eq!(
            framer.process(&mut store, false, |bytes| {
                exposed.extend_from_slice(bytes);
                Ok::<_, ()>(())
            }),
            Ok(BodyProgress::Complete)
        );
        assert_eq!(exposed, [first_chunk, b"b".to_vec()].concat());
    }

    #[test]
    fn chunked_prefix_boundary_at_chunk_end_defers_terminal_metadata() {
        const PREFIX_BYTES: u64 = 61;
        let mut wire = b"3d\r\n".to_vec();
        wire.extend(std::iter::repeat_n(b'p', PREFIX_BYTES as usize));
        wire.extend_from_slice(b"\r\n1\r\ns\r\n0\r\n\r\n");
        let mut store = ParserStore::try_new().unwrap();
        store.append(&wire).unwrap();
        let mut framer = BodyFramer::new(BodyFraming::Chunked);
        let mut exposed = Vec::new();

        assert_eq!(
            framer.process_up_to(&mut store, false, PREFIX_BYTES, |bytes| {
                exposed.extend_from_slice(bytes);
                Ok::<_, ()>(())
            }),
            Ok(BodyProgress::Paused)
        );
        assert_eq!(store.initialized(), b"\r\n1\r\ns\r\n0\r\n\r\n");

        assert_eq!(
            framer.process(&mut store, false, |bytes| {
                exposed.extend_from_slice(bytes);
                Ok::<_, ()>(())
            }),
            Ok(BodyProgress::Complete)
        );
        assert_eq!(
            exposed,
            [vec![b'p'; PREFIX_BYTES as usize], b"s".to_vec()].concat()
        );

        let mut malformed = ParserStore::try_new().unwrap();
        let mut malformed_wire = b"3d\r\n".to_vec();
        malformed_wire.extend(std::iter::repeat_n(b'p', PREFIX_BYTES as usize));
        malformed_wire.extend_from_slice(b"XY");
        malformed.append(&malformed_wire).unwrap();
        let mut framer = BodyFramer::new(BodyFraming::Chunked);
        assert_eq!(
            framer.process_up_to(&mut malformed, false, PREFIX_BYTES, |_| Ok::<_, ()>(())),
            Ok(BodyProgress::Paused)
        );
        assert_eq!(malformed.initialized(), b"XY");
        assert_eq!(
            framer.process(&mut malformed, false, |_| Ok::<_, ()>(())),
            Err(FramingProcessError::Framing(
                FramingError::MalformedChunkTerminator
            ))
        );
    }

    #[test]
    fn close_delimited_prefix_boundary_resumes_to_eof() {
        const PREFIX_BYTES: u64 = 61;
        let body = [vec![b'p'; PREFIX_BYTES as usize], b"tail".to_vec()].concat();
        let mut store = ParserStore::try_new().unwrap();
        store.append(&body).unwrap();
        let mut framer = BodyFramer::new(BodyFraming::CloseDelimited);
        let mut exposed = Vec::new();

        assert_eq!(
            framer.process_up_to(&mut store, true, PREFIX_BYTES, |bytes| {
                exposed.extend_from_slice(bytes);
                Ok::<_, ()>(())
            }),
            Ok(BodyProgress::Paused)
        );
        assert_eq!(store.initialized(), b"tail");
        assert_eq!(
            framer.process(&mut store, true, |bytes| {
                exposed.extend_from_slice(bytes);
                Ok::<_, ()>(())
            }),
            Ok(BodyProgress::Complete)
        );
        assert_eq!(exposed, body);
    }

    #[test]
    fn bounded_resume_still_validates_truncation_and_rejects_retrograde_limit() {
        const PREFIX_BYTES: u64 = 61;
        let mut store = ParserStore::try_new().unwrap();
        store.append(&vec![b'p'; PREFIX_BYTES as usize]).unwrap();
        let mut framer = BodyFramer::new(BodyFraming::ContentLength(PREFIX_BYTES + 1));
        assert_eq!(
            framer.process_up_to(&mut store, true, PREFIX_BYTES, |_| Ok::<_, ()>(())),
            Ok(BodyProgress::Paused)
        );
        assert_eq!(
            framer.process_up_to(&mut store, true, PREFIX_BYTES - 1, |_| Ok::<_, ()>(())),
            Err(FramingProcessError::Framing(
                FramingError::EntityLimitBehindProgress
            ))
        );
        assert_eq!(
            framer.process(&mut store, true, |_| Ok::<_, ()>(())),
            Err(FramingProcessError::Framing(
                FramingError::UnexpectedEndOfStream
            ))
        );
    }
}
