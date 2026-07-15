use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use allocator_api2::boxed::Box as FallibleBox;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroize;

use super::framing::{parse_chunk_line, BodyFraming, MAX_CHUNK_LINE_BYTES};
use super::head::{
    parse_content_length, trim_ows, IngressRequestHead, IngressRequestKind, MAX_FIELD_LINE_BYTES,
    MAX_HEADER_FIELDS, MAX_REQUEST_TARGET_BYTES,
};
use super::store::PARSER_STORE_BYTES;

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestDisposition {
    ContinueHttp,
    SwitchProtocol,
    Close,
}

#[derive(Clone)]
pub(crate) struct IngressValidationControl {
    shared: Arc<Mutex<SharedState>>,
}

impl IngressValidationControl {
    pub(crate) fn claim(
        &self,
        observed: Option<IngressRequestKind>,
    ) -> Result<Option<IngressValidationTicket>, ValidationControlError> {
        let mut shared = self
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(record) = shared.record.as_mut() else {
            if observed.is_none() && shared.h2 {
                return Ok(None);
            }
            shared.forced_close = true;
            shared.wake();
            return Err(ValidationControlError::MissingTicket);
        };
        let Some(observed) = observed else {
            record.claimed = true;
            record.disposition = Some(RequestDisposition::Close);
            shared.forced_close = true;
            shared.wake();
            return Err(ValidationControlError::UnexpectedHttp2);
        };
        if record.claimed || record.kind != observed {
            record.claimed = true;
            record.disposition = Some(RequestDisposition::Close);
            shared.forced_close = true;
            shared.wake();
            return Err(ValidationControlError::TicketMismatch);
        }
        record.claimed = true;
        let ticket = IngressValidationTicket {
            id: record.id,
            kind: record.kind,
            control: self.clone(),
            resolved: false,
        };
        shared.wake();
        Ok(Some(ticket))
    }

    fn install(&self, kind: IngressRequestKind) -> Result<(), io::Error> {
        let mut shared = self
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if shared.record.is_some() {
            return Err(invalid_data("HTTP/1 validation ticket overlap"));
        }
        let id = shared.next_id;
        shared.next_id = shared
            .next_id
            .checked_add(1)
            .ok_or_else(|| invalid_data("HTTP/1 validation ticket overflow"))?;
        shared.record = Some(TicketRecord {
            id,
            kind,
            claimed: false,
            disposition: None,
        });
        Ok(())
    }

    fn boundary(
        &self,
        cx: &Context<'_>,
        kind: IngressRequestKind,
    ) -> Poll<Result<RequestDisposition, io::Error>> {
        let mut shared = self
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(record) = shared.record.as_ref() else {
            return Poll::Ready(Err(invalid_data("HTTP/1 validation ticket disappeared")));
        };
        if record.kind != kind {
            return Poll::Ready(Err(invalid_data("HTTP/1 validation ticket changed kind")));
        }
        let ready = record.disposition;
        if let Some(disposition) = ready {
            shared.record = None;
            Poll::Ready(Ok(disposition))
        } else {
            shared.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn mark_h2(&self) {
        let mut shared = self
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        shared.h2 = true;
    }

    fn close_requested(&self) -> bool {
        self.shared
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .forced_close
    }

    fn register(&self, waker: &Waker) {
        self.shared
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .waker = Some(waker.clone());
    }

    fn resolve(
        &self,
        id: u64,
        kind: IngressRequestKind,
        disposition: RequestDisposition,
    ) -> Result<(), ValidationControlError> {
        let mut shared = self
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(record) = shared.record.as_mut() else {
            return Err(ValidationControlError::MissingTicket);
        };
        if record.id != id || record.kind != kind || !record.claimed || record.disposition.is_some()
        {
            return Err(ValidationControlError::TicketMismatch);
        }
        record.disposition = Some(disposition);
        if disposition == RequestDisposition::Close {
            shared.forced_close = true;
        }
        shared.wake();
        Ok(())
    }

    fn abort(&self, id: u64) {
        let mut shared = self
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        shared.forced_close = true;
        if let Some(record) = shared.record.as_mut() {
            if record.id == id && record.disposition.is_none() {
                record.disposition = Some(RequestDisposition::Close);
            }
        }
        shared.wake();
    }
}

struct SharedState {
    next_id: u64,
    record: Option<TicketRecord>,
    waker: Option<Waker>,
    h2: bool,
    forced_close: bool,
}

impl SharedState {
    fn wake(&mut self) {
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

struct TicketRecord {
    id: u64,
    kind: IngressRequestKind,
    claimed: bool,
    disposition: Option<RequestDisposition>,
}

pub(crate) struct IngressValidationTicket {
    id: u64,
    kind: IngressRequestKind,
    control: IngressValidationControl,
    resolved: bool,
}

impl IngressValidationTicket {
    pub(crate) fn resolve(
        mut self,
        disposition: RequestDisposition,
    ) -> Result<(), ValidationControlError> {
        self.control.resolve(self.id, self.kind, disposition)?;
        self.resolved = true;
        Ok(())
    }
}

impl Drop for IngressValidationTicket {
    fn drop(&mut self) {
        if !self.resolved {
            self.control.abort(self.id);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValidationControlError {
    MissingTicket,
    TicketMismatch,
    UnexpectedHttp2,
}

impl fmt::Display for ValidationControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTicket => formatter.write_str("HTTP/1 validation ticket is missing"),
            Self::TicketMismatch => formatter.write_str("HTTP/1 validation ticket does not match"),
            Self::UnexpectedHttp2 => {
                formatter.write_str("HTTP/2 request has an HTTP/1 validation ticket")
            }
        }
    }
}

impl std::error::Error for ValidationControlError {}

#[derive(Clone, Copy)]
enum ProtocolState {
    Detect,
    Http1,
    Http2,
    Opaque,
    Closed,
}

enum Http1State {
    Head(IngressHeadTracker),
    Body {
        body: BodyState,
        kind: IngressRequestKind,
    },
    Boundary(IngressRequestKind),
}

#[derive(Default)]
struct IngressHeadTracker {
    line: HeadLine,
    line_scanner: HeadLineScanner,
    connection_scanner: ConnectionValueScanner,
    header_name_inspected: usize,
    fields: usize,
    content_length: Option<u64>,
    transfer_encoding: bool,
    connection_upgrade: bool,
    upgrade: bool,
    connect: bool,
    http10: bool,
}

#[derive(Default)]
struct HeadLineScanner {
    inspected: usize,
    pending_cr: Option<usize>,
}

#[derive(Default)]
enum HeadLine {
    #[default]
    Request,
    HeaderName,
    Relevant {
        name: RelevantHeader,
        value_start: usize,
    },
    Connection,
    Irrelevant,
}

#[derive(Clone, Copy)]
enum RelevantHeader {
    ContentLength,
    TransferEncoding,
}

#[derive(Default)]
struct ConnectionValueScanner {
    inspected: usize,
    token_match: usize,
    token_mismatch: bool,
    trailing_ows: bool,
    found_upgrade: bool,
}

enum ConnectionProgress {
    NeedInput,
    Release(usize),
    Complete(usize, bool),
}

enum HeadProgress {
    NeedInput,
    Release(usize),
    Complete(usize, IngressRequestHead),
}

enum BodyState {
    None,
    ContentLength(u64),
    ChunkSize(ChunkLineScanner),
    ChunkData(u64),
    ChunkDataTerminator,
    ChunkTrailers(TrailerScanner),
}

#[derive(Default)]
struct ChunkLineScanner {
    inspected: usize,
    pending_cr: Option<usize>,
}

#[derive(Default)]
struct TrailerScanner {
    inspected: usize,
    pending_cr: bool,
    current_line_bytes: usize,
    fields: usize,
    colon_seen: bool,
}

enum TrailerProgress {
    NeedInput,
    Release(usize),
    Complete(usize),
}

pub(crate) struct ValidatedIngressIo<T> {
    inner: T,
    bytes: FallibleBox<[u8]>,
    emitted: usize,
    validated: usize,
    end: usize,
    protocol: ProtocolState,
    h1: Http1State,
    control: IngressValidationControl,
    eof: bool,
}

impl<T> ValidatedIngressIo<T> {
    pub(crate) fn try_new(
        inner: T,
        detect_h2: bool,
    ) -> Result<(Self, IngressValidationControl), IngressValidatorAllocationError> {
        let mut bytes = FallibleBox::<[u8]>::try_new_uninit_slice(PARSER_STORE_BYTES)
            .map_err(|_| IngressValidatorAllocationError)?;
        for byte in bytes.iter_mut() {
            byte.write(0);
        }
        let bytes = unsafe { bytes.assume_init() };
        let control = IngressValidationControl {
            shared: Arc::new(Mutex::new(SharedState {
                next_id: 0,
                record: None,
                waker: None,
                h2: false,
                forced_close: false,
            })),
        };
        Ok((
            Self {
                inner,
                bytes,
                emitted: 0,
                validated: 0,
                end: 0,
                protocol: if detect_h2 {
                    ProtocolState::Detect
                } else {
                    ProtocolState::Http1
                },
                h1: Http1State::Head(IngressHeadTracker::default()),
                control: control.clone(),
                eof: false,
            },
            control,
        ))
    }

    fn compact(&mut self) {
        if self.emitted == 0 {
            return;
        }
        let retained = self.end - self.emitted;
        self.bytes.copy_within(self.emitted..self.end, 0);
        self.bytes[retained..self.end].zeroize();
        self.validated -= self.emitted;
        self.end = retained;
        self.emitted = 0;
    }

    fn expose(&mut self, output: &mut ReadBuf<'_>) -> bool {
        let count = (self.validated - self.emitted).min(output.remaining());
        if count == 0 {
            return false;
        }
        output.put_slice(&self.bytes[self.emitted..self.emitted + count]);
        self.bytes[self.emitted..self.emitted + count].zeroize();
        self.emitted += count;
        if self.emitted == self.validated {
            self.compact();
        }
        true
    }

    fn validate(&mut self, cx: &Context<'_>) -> Poll<Result<(), io::Error>> {
        loop {
            match self.protocol {
                ProtocolState::Detect => {
                    let input = &self.bytes[self.validated..self.end];
                    let compared = input.len().min(H2_PREFACE.len());
                    if input[..compared] != H2_PREFACE[..compared] {
                        self.protocol = ProtocolState::Http1;
                        continue;
                    }
                    if input.len() >= H2_PREFACE.len() {
                        self.protocol = ProtocolState::Http2;
                        self.control.mark_h2();
                        self.validated = self.end;
                        return Poll::Ready(Ok(()));
                    }
                    return self.need_input();
                }
                ProtocolState::Http2 | ProtocolState::Opaque => {
                    self.validated = self.end;
                    return Poll::Ready(Ok(()));
                }
                ProtocolState::Closed => {
                    self.bytes[..self.end].zeroize();
                    self.emitted = 0;
                    self.validated = 0;
                    self.end = 0;
                    return Poll::Ready(Ok(()));
                }
                ProtocolState::Http1 => {}
            }

            match &mut self.h1 {
                Http1State::Head(tracker) => {
                    match tracker.validate(&self.bytes[self.validated..self.end])? {
                        HeadProgress::NeedInput => return self.need_input(),
                        HeadProgress::Release(length) => self.validated += length,
                        HeadProgress::Complete(length, head) => {
                            self.control.install(head.kind)?;
                            self.validated += length;
                            self.h1 = Http1State::Body {
                                body: BodyState::new(head.framing),
                                kind: head.kind,
                            };
                        }
                    }
                }
                Http1State::Body { body, kind } => {
                    let complete = body.validate(&self.bytes, &mut self.validated, self.end)?;
                    if !complete {
                        return if self.validated != self.emitted {
                            Poll::Ready(Ok(()))
                        } else {
                            self.need_input()
                        };
                    }
                    self.h1 = Http1State::Boundary(*kind);
                }
                Http1State::Boundary(kind) => {
                    let kind = *kind;
                    let disposition = match self.control.boundary(cx, kind) {
                        Poll::Ready(result) => result?,
                        Poll::Pending => return Poll::Pending,
                    };
                    match disposition {
                        RequestDisposition::ContinueHttp => {
                            self.h1 = Http1State::Head(IngressHeadTracker::default());
                        }
                        RequestDisposition::SwitchProtocol => {
                            self.protocol = ProtocolState::Opaque;
                        }
                        RequestDisposition::Close => {
                            self.protocol = ProtocolState::Closed;
                        }
                    }
                }
            }
            if self.validated != self.emitted {
                return Poll::Ready(Ok(()));
            }
        }
    }

    fn need_input(&self) -> Poll<Result<(), io::Error>> {
        if self.eof {
            if matches!(
                self.protocol,
                ProtocolState::Http2 | ProtocolState::Opaque | ProtocolState::Closed
            ) || (matches!(&self.h1, Http1State::Head(tracker) if tracker.is_pristine())
                && self.end == self.validated)
            {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(invalid_data("incomplete HTTP/1 request framing")))
            }
        } else {
            Poll::Pending
        }
    }
}

impl BodyState {
    fn new(framing: BodyFraming) -> Self {
        match framing {
            BodyFraming::None => Self::None,
            BodyFraming::ContentLength(length) => Self::ContentLength(length),
            BodyFraming::Chunked => Self::ChunkSize(ChunkLineScanner::default()),
            BodyFraming::CloseDelimited => Self::None,
        }
    }

    fn validate(
        &mut self,
        bytes: &[u8],
        validated: &mut usize,
        end: usize,
    ) -> Result<bool, io::Error> {
        loop {
            let available = end - *validated;
            match self {
                Self::None | Self::ContentLength(0) => return Ok(true),
                Self::ContentLength(remaining) => {
                    if available == 0 {
                        return Ok(false);
                    }
                    let count = usize::try_from((*remaining).min(available as u64))
                        .map_err(|_| invalid_data("HTTP/1 Content-Length overflow"))?;
                    *validated += count;
                    *remaining -= count as u64;
                }
                Self::ChunkSize(scanner) => {
                    let Some(length) = scanner.scan(&bytes[*validated..end])? else {
                        return Ok(false);
                    };
                    let size = parse_chunk_line(&bytes[*validated..*validated + length - 2])
                        .map_err(|error| invalid_data(error.to_string()))?;
                    *validated += length;
                    *self = if size == 0 {
                        Self::ChunkTrailers(TrailerScanner::default())
                    } else {
                        Self::ChunkData(size)
                    };
                }
                Self::ChunkData(remaining) => {
                    if *remaining == 0 {
                        *self = Self::ChunkDataTerminator;
                        continue;
                    }
                    if available == 0 {
                        return Ok(false);
                    }
                    let count = usize::try_from((*remaining).min(available as u64))
                        .map_err(|_| invalid_data("HTTP/1 chunk length overflow"))?;
                    *validated += count;
                    *remaining -= count as u64;
                }
                Self::ChunkDataTerminator => {
                    if available < 2 {
                        return Ok(false);
                    }
                    if &bytes[*validated..*validated + 2] != b"\r\n" {
                        return Err(invalid_data("malformed HTTP/1 chunk terminator"));
                    }
                    *validated += 2;
                    *self = Self::ChunkSize(ChunkLineScanner::default());
                }
                Self::ChunkTrailers(scanner) => match scanner.scan(&bytes[*validated..end])? {
                    TrailerProgress::NeedInput => return Ok(false),
                    TrailerProgress::Release(length) => *validated += length,
                    TrailerProgress::Complete(length) => {
                        *validated += length;
                        return Ok(true);
                    }
                },
            }
        }
    }
}

impl IngressHeadTracker {
    fn is_pristine(&self) -> bool {
        matches!(self.line, HeadLine::Request)
            && self.line_scanner.inspected == 0
            && self.header_name_inspected == 0
            && self.fields == 0
    }

    fn validate(&mut self, input: &[u8]) -> Result<HeadProgress, io::Error> {
        loop {
            match self.line {
                HeadLine::Request => {
                    let Some(length) = self.line_scanner.scan(input)? else {
                        return Ok(HeadProgress::NeedInput);
                    };
                    let line = &input[..length - 2];
                    let mut parts = line.split(|byte| *byte == b' ');
                    let method = parts
                        .next()
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| invalid_data("malformed HTTP/1 request line"))?;
                    let target = parts
                        .next()
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| invalid_data("malformed HTTP/1 request line"))?;
                    let version = parts
                        .next()
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| invalid_data("malformed HTTP/1 request line"))?;
                    if parts.next().is_some() || target.len() > MAX_REQUEST_TARGET_BYTES {
                        return Err(invalid_data("invalid HTTP/1 request target"));
                    }
                    self.http10 = match version {
                        b"HTTP/1.0" => true,
                        b"HTTP/1.1" => false,
                        _ => return Err(invalid_data("unsupported HTTP version")),
                    };
                    self.connect = method == b"CONNECT";
                    self.line = HeadLine::HeaderName;
                    self.line_scanner = HeadLineScanner::default();
                    self.header_name_inspected = 0;
                    return Ok(HeadProgress::Release(length));
                }
                HeadLine::HeaderName => {
                    if input.is_empty() {
                        return Ok(HeadProgress::NeedInput);
                    }
                    if input[0] == b'\r' {
                        if input.len() == 1 {
                            return Ok(HeadProgress::NeedInput);
                        }
                        if input[1] != b'\n' {
                            return Err(invalid_data("HTTP/1 head requires CRLF"));
                        }
                        if self.content_length.is_some() && self.transfer_encoding {
                            return Err(invalid_data("conflicting HTTP/1 entity framing"));
                        }
                        let framing = match (self.content_length, self.transfer_encoding) {
                            (Some(length), false) => BodyFraming::ContentLength(length),
                            (None, true) => BodyFraming::Chunked,
                            (None, false) => BodyFraming::None,
                            (Some(_), true) => unreachable!("conflicting framing returned above"),
                        };
                        let kind = if self.connect {
                            IngressRequestKind::Connect
                        } else if self.connection_upgrade && self.upgrade {
                            IngressRequestKind::Upgrade
                        } else {
                            IngressRequestKind::Ordinary
                        };
                        return Ok(HeadProgress::Complete(
                            2,
                            IngressRequestHead { framing, kind },
                        ));
                    }
                    if matches!(input[0], b' ' | b'\t') {
                        return Err(invalid_data("obsolete HTTP/1 line folding"));
                    }
                    let mut colon = None;
                    for (index, byte) in input
                        .iter()
                        .copied()
                        .enumerate()
                        .skip(self.header_name_inspected)
                    {
                        self.header_name_inspected = index + 1;
                        match byte {
                            b':' => {
                                colon = Some(index);
                                break;
                            }
                            b'\r' | b'\n' => {
                                return Err(invalid_data("malformed HTTP/1 header field"));
                            }
                            _ => {}
                        }
                    }
                    let Some(colon) = colon else {
                        return Ok(HeadProgress::NeedInput);
                    };
                    if colon == 0 {
                        return Err(invalid_data("empty HTTP/1 header name"));
                    }
                    self.fields += 1;
                    if self.fields > MAX_HEADER_FIELDS {
                        return Err(invalid_data("too many HTTP/1 header fields"));
                    }
                    let name = &input[..colon];
                    self.line = if name.eq_ignore_ascii_case(b"content-length") {
                        HeadLine::Relevant {
                            name: RelevantHeader::ContentLength,
                            value_start: colon + 1,
                        }
                    } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
                        HeadLine::Relevant {
                            name: RelevantHeader::TransferEncoding,
                            value_start: colon + 1,
                        }
                    } else if name.eq_ignore_ascii_case(b"connection") {
                        self.connection_scanner = ConnectionValueScanner {
                            inspected: colon + 1,
                            ..ConnectionValueScanner::default()
                        };
                        HeadLine::Connection
                    } else if name.eq_ignore_ascii_case(b"upgrade") {
                        self.upgrade = true;
                        HeadLine::Irrelevant
                    } else {
                        HeadLine::Irrelevant
                    };
                    self.line_scanner = HeadLineScanner {
                        inspected: colon + 1,
                        pending_cr: None,
                    };
                }
                HeadLine::Relevant { name, value_start } => {
                    let Some(length) = self.line_scanner.scan(input)? else {
                        return Ok(HeadProgress::NeedInput);
                    };
                    let value = &input[value_start..length - 2];
                    match name {
                        RelevantHeader::ContentLength => {
                            if self.content_length.is_some() {
                                return Err(invalid_data("duplicate HTTP/1 Content-Length"));
                            }
                            self.content_length = Some(
                                parse_content_length(value)
                                    .map_err(|error| invalid_data(error.to_string()))?,
                            );
                        }
                        RelevantHeader::TransferEncoding => {
                            if self.transfer_encoding {
                                return Err(invalid_data("duplicate HTTP/1 Transfer-Encoding"));
                            }
                            if self.http10 || !trim_ows(value).eq_ignore_ascii_case(b"chunked") {
                                return Err(invalid_data("unsupported HTTP/1 transfer coding"));
                            }
                            self.transfer_encoding = true;
                        }
                    }
                    self.line = HeadLine::HeaderName;
                    self.line_scanner = HeadLineScanner::default();
                    self.header_name_inspected = 0;
                    return Ok(HeadProgress::Release(length));
                }
                HeadLine::Connection => match self.connection_scanner.scan(input)? {
                    ConnectionProgress::NeedInput => return Ok(HeadProgress::NeedInput),
                    ConnectionProgress::Release(length) => {
                        return Ok(HeadProgress::Release(length));
                    }
                    ConnectionProgress::Complete(length, found_upgrade) => {
                        self.connection_upgrade |= found_upgrade;
                        self.line = HeadLine::HeaderName;
                        self.line_scanner = HeadLineScanner::default();
                        self.connection_scanner = ConnectionValueScanner::default();
                        self.header_name_inspected = 0;
                        return Ok(HeadProgress::Release(length));
                    }
                },
                HeadLine::Irrelevant => {
                    for (index, byte) in input.iter().copied().enumerate() {
                        match byte {
                            b'\r' => {
                                if index + 1 == input.len() {
                                    return if index == 0 {
                                        Ok(HeadProgress::NeedInput)
                                    } else {
                                        Ok(HeadProgress::Release(index))
                                    };
                                }
                                if input[index + 1] != b'\n' {
                                    return Err(invalid_data("HTTP/1 head requires CRLF"));
                                }
                                self.line = HeadLine::HeaderName;
                                self.line_scanner = HeadLineScanner::default();
                                self.header_name_inspected = 0;
                                return Ok(HeadProgress::Release(index + 2));
                            }
                            b'\n' => return Err(invalid_data("HTTP/1 head requires CRLF")),
                            _ => {}
                        }
                    }
                    return if input.is_empty() {
                        Ok(HeadProgress::NeedInput)
                    } else {
                        Ok(HeadProgress::Release(input.len()))
                    };
                }
            }
        }
    }
}

impl ConnectionValueScanner {
    fn scan(&mut self, input: &[u8]) -> Result<ConnectionProgress, io::Error> {
        while self.inspected < input.len() {
            let index = self.inspected;
            match input[index] {
                b'\r' => {
                    if index + 1 == input.len() {
                        if index == 0 {
                            return Ok(ConnectionProgress::NeedInput);
                        }
                        self.inspected = 0;
                        return Ok(ConnectionProgress::Release(index));
                    }
                    if input[index + 1] != b'\n' {
                        return Err(invalid_data("HTTP/1 head requires CRLF"));
                    }
                    self.finish_token();
                    return Ok(ConnectionProgress::Complete(index + 2, self.found_upgrade));
                }
                b'\n' => return Err(invalid_data("HTTP/1 head requires CRLF")),
                b',' => self.finish_token(),
                byte => self.consume_token_byte(byte),
            }
            self.inspected += 1;
        }
        if input.is_empty() {
            Ok(ConnectionProgress::NeedInput)
        } else {
            self.inspected = 0;
            Ok(ConnectionProgress::Release(input.len()))
        }
    }

    fn consume_token_byte(&mut self, byte: u8) {
        const UPGRADE: &[u8] = b"upgrade";
        if matches!(byte, b' ' | b'\t') {
            if self.token_match == UPGRADE.len() && !self.token_mismatch {
                self.trailing_ows = true;
            } else if self.token_match != 0 {
                self.token_mismatch = true;
            }
            return;
        }
        if self.trailing_ows
            || self.token_mismatch
            || self.token_match == UPGRADE.len()
            || !byte.eq_ignore_ascii_case(&UPGRADE[self.token_match])
        {
            self.token_mismatch = true;
            return;
        }
        self.token_match += 1;
    }

    fn finish_token(&mut self) {
        self.found_upgrade |= self.token_match == b"upgrade".len() && !self.token_mismatch;
        self.token_match = 0;
        self.token_mismatch = false;
        self.trailing_ows = false;
    }
}

impl HeadLineScanner {
    fn scan(&mut self, input: &[u8]) -> Result<Option<usize>, io::Error> {
        while self.inspected < input.len() {
            let byte = input[self.inspected];
            self.inspected += 1;
            if let Some(cr) = self.pending_cr {
                if byte != b'\n' {
                    return Err(invalid_data("HTTP/1 head requires CRLF"));
                }
                return Ok(Some(cr + 2));
            }
            match byte {
                b'\r' => self.pending_cr = Some(self.inspected - 1),
                b'\n' => return Err(invalid_data("HTTP/1 head requires CRLF")),
                _ => {}
            }
        }
        Ok(None)
    }
}

impl ChunkLineScanner {
    fn scan(&mut self, input: &[u8]) -> Result<Option<usize>, io::Error> {
        while self.inspected < input.len() {
            let byte = input[self.inspected];
            self.inspected += 1;
            if let Some(cr) = self.pending_cr {
                if byte != b'\n' {
                    return Err(invalid_data("malformed HTTP/1 chunk-size line"));
                }
                if self.inspected > MAX_CHUNK_LINE_BYTES {
                    return Err(invalid_data("HTTP/1 chunk-size line is too long"));
                }
                return Ok(Some(cr + 2));
            }
            match byte {
                b'\r' => self.pending_cr = Some(self.inspected - 1),
                b'\n' => return Err(invalid_data("malformed HTTP/1 chunk-size line")),
                _ => {}
            }
        }
        if input.len() >= MAX_CHUNK_LINE_BYTES {
            return Err(invalid_data("HTTP/1 chunk-size line is too long"));
        }
        Ok(None)
    }
}

impl TrailerScanner {
    fn scan(&mut self, input: &[u8]) -> Result<TrailerProgress, io::Error> {
        while self.inspected < input.len() {
            let byte = input[self.inspected];
            self.inspected += 1;
            self.current_line_bytes += 1;
            if self.pending_cr {
                if byte != b'\n' {
                    return Err(invalid_data("HTTP/1 trailers require CRLF"));
                }
                self.pending_cr = false;
                if self.current_line_bytes == 2 {
                    let length = self.inspected;
                    self.inspected = 0;
                    self.current_line_bytes = 0;
                    return Ok(TrailerProgress::Complete(length));
                }
                if !self.colon_seen {
                    return Err(invalid_data("malformed HTTP/1 trailer field"));
                }
                let name_end = input[..self.inspected - 2]
                    .iter()
                    .position(|byte| *byte == b':')
                    .expect("validated trailer field has a colon");
                let name = &input[..name_end];
                if name.eq_ignore_ascii_case(b"content-length")
                    || name.eq_ignore_ascii_case(b"transfer-encoding")
                {
                    return Err(invalid_data(
                        "HTTP/1 framing field is forbidden in trailers",
                    ));
                }
                self.fields += 1;
                if self.fields > MAX_HEADER_FIELDS {
                    return Err(invalid_data("too many HTTP/1 trailer fields"));
                }
                let length = self.inspected;
                self.inspected = 0;
                self.current_line_bytes = 0;
                self.colon_seen = false;
                return Ok(TrailerProgress::Release(length));
            } else {
                match byte {
                    b'\r' => self.pending_cr = true,
                    b'\n' => return Err(invalid_data("HTTP/1 trailers require CRLF")),
                    b':' if !self.colon_seen => {
                        if self.current_line_bytes == 1 {
                            return Err(invalid_data("empty HTTP/1 trailer name"));
                        }
                        self.colon_seen = true;
                    }
                    b' ' | b'\t' if self.current_line_bytes == 1 => {
                        return Err(invalid_data("obsolete HTTP/1 trailer line folding"));
                    }
                    byte if !self.colon_seen && !is_header_name_byte(byte) => {
                        return Err(invalid_data("invalid HTTP/1 trailer name"));
                    }
                    byte if self.colon_seen
                        && !matches!(byte, b'\t' | 0x20..=0x7e | 0x80..=0xff) =>
                    {
                        return Err(invalid_data("invalid HTTP/1 trailer value"));
                    }
                    _ => {}
                }
            }
            if self.current_line_bytes > MAX_FIELD_LINE_BYTES {
                return Err(invalid_data("HTTP/1 trailer field line is too long"));
            }
        }
        Ok(TrailerProgress::NeedInput)
    }
}

fn is_header_name_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
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
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

impl<T: AsyncRead + Unpin> AsyncRead for ValidatedIngressIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            self.control.register(cx.waker());
            if self.control.close_requested() {
                self.protocol = ProtocolState::Closed;
                let end = self.end;
                self.bytes[..end].zeroize();
                self.emitted = 0;
                self.validated = 0;
                self.end = 0;
            }
            if output.remaining() == 0 || self.expose(output) {
                return Poll::Ready(Ok(()));
            }
            match self.validate(cx) {
                Poll::Ready(Ok(())) => {
                    if self.expose(output) {
                        return Poll::Ready(Ok(()));
                    }
                    if matches!(self.protocol, ProtocolState::Closed) || self.eof {
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending if self.end == self.bytes.len() => {
                    return Poll::Ready(Err(invalid_data("HTTP/1 validation buffer exceeded")));
                }
                Poll::Pending => {}
            }

            let this = self.as_mut().get_mut();
            let start = this.end;
            let mut read = ReadBuf::new(&mut this.bytes[start..]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) => {
                    let count = read.filled().len();
                    if count == 0 {
                        this.eof = true;
                    } else {
                        this.end += count;
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ValidatedIngressIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<T> Drop for ValidatedIngressIo<T> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IngressValidatorAllocationError;

impl fmt::Display for IngressValidatorAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("could not allocate the HTTP/1 ingress validation buffer")
    }
}

impl std::error::Error for IngressValidatorAllocationError {}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use http_access_conformance::{load_raw_h1_suite, RawOutcome};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn parse_ingress_head(input: &[u8]) -> Result<IngressRequestHead, io::Error> {
        let mut tracker = IngressHeadTracker::default();
        let mut released = 0;
        loop {
            match tracker.validate(&input[released..])? {
                HeadProgress::NeedInput => {
                    return Err(invalid_data("incomplete test HTTP/1 head"));
                }
                HeadProgress::Release(length) => released += length,
                HeadProgress::Complete(_, head) => return Ok(head),
            }
        }
    }

    #[test]
    fn validator_consumes_the_shared_raw_h1_corpus() {
        let suite = load_raw_h1_suite().unwrap();
        for case in suite.cases() {
            let wire = case.wire_hex.as_bytes();
            let head_len = wire
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
                .expect("raw H1 fixture has a complete head");
            let parsed = parse_ingress_head(&wire[..head_len]);
            let rejected_at_wire_guard = matches!(
                case.id.as_str(),
                "h1-content-length-plus-transfer-encoding-rejected"
                    | "h1-conflicting-content-length-rejected"
                    | "h1-duplicate-content-length-rejected"
                    | "h1-obs-fold-rejected"
            );
            if rejected_at_wire_guard {
                assert!(parsed.is_err(), "{} reached Hyper", case.id);
            } else {
                assert!(parsed.is_ok(), "{}: {parsed:?}", case.id);
            }
            if matches!(&case.expected, RawOutcome::Accepted { .. }) {
                assert!(parsed.is_ok(), "accepted corpus case {}", case.id);
            }
        }
    }

    #[test]
    fn validator_rejects_both_cl_te_orders_and_accepts_http10() {
        for head in [
            b"POST / HTTP/1.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"
                .as_slice(),
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n"
                .as_slice(),
        ] {
            assert!(parse_ingress_head(head).is_err());
        }
        assert_eq!(
            parse_ingress_head(
                b"GET / HTTP/1.0\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n"
            )
            .unwrap()
            .framing,
            BodyFraming::ContentLength(0)
        );
    }

    #[tokio::test]
    async fn validated_cl0_head_is_replayed_before_boundary_gating() {
        let wire = b"POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n";
        let (mut client, server) = tokio::io::duplex(PARSER_STORE_BYTES);
        let (mut validated, control) = ValidatedIngressIo::try_new(server, false).unwrap();
        client.write_all(wire).await.unwrap();

        let mut replayed = vec![0_u8; wire.len()];
        tokio::time::timeout(Duration::from_secs(1), validated.read_exact(&mut replayed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(replayed, wire);
        assert_eq!(validated.bytes.len(), PARSER_STORE_BYTES);
        assert!(validated.bytes.iter().all(|byte| *byte == 0));
        control
            .claim(Some(IngressRequestKind::Ordinary))
            .unwrap()
            .unwrap()
            .resolve(RequestDisposition::ContinueHttp)
            .unwrap();
    }

    #[tokio::test]
    async fn pipelined_chunked_trailers_leave_the_next_head_gated_and_exact() {
        let first_head =
            b"POST /one HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n";
        let first_body = b"4;safe=yes\r\ntest\r\n0\r\nX-Sum: ok\r\n\r\n";
        let second_head = b"GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let (mut client, server) = tokio::io::duplex(PARSER_STORE_BYTES);
        let (mut validated, control) = ValidatedIngressIo::try_new(server, false).unwrap();
        let mut wire = Vec::new();
        wire.extend_from_slice(first_head);
        wire.extend_from_slice(first_body);
        wire.extend_from_slice(second_head);
        client.write_all(&wire).await.unwrap();

        let mut replayed_head = vec![0; first_head.len()];
        validated.read_exact(&mut replayed_head).await.unwrap();
        assert_eq!(replayed_head, first_head);
        control
            .claim(Some(IngressRequestKind::Ordinary))
            .unwrap()
            .unwrap()
            .resolve(RequestDisposition::ContinueHttp)
            .unwrap();

        let mut replayed_body = vec![0; first_body.len()];
        validated.read_exact(&mut replayed_body).await.unwrap();
        assert_eq!(replayed_body, first_body);
        let mut replayed_second = vec![0; second_head.len()];
        validated.read_exact(&mut replayed_second).await.unwrap();
        assert_eq!(replayed_second, second_head);
        control
            .claim(Some(IngressRequestKind::Ordinary))
            .unwrap()
            .unwrap()
            .resolve(RequestDisposition::ContinueHttp)
            .unwrap();
    }

    #[tokio::test]
    async fn upgrade_bytes_wait_for_an_explicit_switch_disposition() {
        let head = b"GET /socket HTTP/1.1\r\nHost: example.test\r\nConnection: upgrade\r\nUpgrade: test-echo/1\r\n\r\n";
        let opaque = b"opaque-protocol-bytes";
        let (mut client, server) = tokio::io::duplex(PARSER_STORE_BYTES);
        let (mut validated, control) = ValidatedIngressIo::try_new(server, false).unwrap();
        client.write_all(head).await.unwrap();
        client.write_all(opaque).await.unwrap();

        let mut replayed_head = vec![0; head.len()];
        validated.read_exact(&mut replayed_head).await.unwrap();
        assert_eq!(replayed_head, head);
        let ticket = control
            .claim(Some(IngressRequestKind::Upgrade))
            .unwrap()
            .unwrap();

        let mut replayed_opaque = vec![0; opaque.len()];
        assert!(tokio::time::timeout(
            Duration::from_millis(20),
            validated.read_exact(&mut replayed_opaque)
        )
        .await
        .is_err());
        ticket.resolve(RequestDisposition::SwitchProtocol).unwrap();
        validated.read_exact(&mut replayed_opaque).await.unwrap();
        assert_eq!(replayed_opaque, opaque);
    }

    #[tokio::test]
    async fn service_close_interrupts_an_incomplete_declared_body() {
        let head = b"POST /bounded HTTP/1.1\r\nHost: example.test\r\nContent-Length: 32\r\n\r\n";
        let (mut client, server) = tokio::io::duplex(PARSER_STORE_BYTES);
        let (mut validated, control) = ValidatedIngressIo::try_new(server, false).unwrap();
        client.write_all(head).await.unwrap();
        client.write_all(b"12345678").await.unwrap();

        let mut replayed_head = vec![0; head.len()];
        validated.read_exact(&mut replayed_head).await.unwrap();
        let ticket = control
            .claim(Some(IngressRequestKind::Ordinary))
            .unwrap()
            .unwrap();
        let mut prefix = [0; 8];
        validated.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"12345678");
        ticket.resolve(RequestDisposition::Close).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), validated.read(&mut prefix))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn closing_first_request_never_exposes_a_pipelined_second_head() {
        let first_head = b"POST /one HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\n";
        let first_body = b"body";
        let second_head = b"GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let (mut client, server) = tokio::io::duplex(PARSER_STORE_BYTES);
        let (mut validated, control) = ValidatedIngressIo::try_new(server, false).unwrap();
        let mut wire = Vec::new();
        wire.extend_from_slice(first_head);
        wire.extend_from_slice(first_body);
        wire.extend_from_slice(second_head);
        client.write_all(&wire).await.unwrap();

        let mut replayed_first = vec![0; first_head.len() + first_body.len()];
        validated.read_exact(&mut replayed_first).await.unwrap();
        assert_eq!(replayed_first, wire[..replayed_first.len()]);
        let ticket = control
            .claim(Some(IngressRequestKind::Ordinary))
            .unwrap()
            .unwrap();
        let mut replayed_second = vec![0; second_head.len()];
        assert!(tokio::time::timeout(
            Duration::from_millis(20),
            validated.read_exact(&mut replayed_second),
        )
        .await
        .is_err());

        ticket.resolve(RequestDisposition::Close).unwrap();
        assert_eq!(validated.read(&mut replayed_second).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn ordinary_field_larger_than_the_replay_buffer_streams_before_head_completion() {
        let mut wire = b"GET /large HTTP/1.1\r\nHost: example.test\r\nX-Large: ".to_vec();
        wire.extend(std::iter::repeat_n(b'x', PARSER_STORE_BYTES));
        wire.extend_from_slice(b"\r\n\r\n");
        let (mut client, server) = tokio::io::duplex(PARSER_STORE_BYTES);
        let (mut validated, control) = ValidatedIngressIo::try_new(server, false).unwrap();
        let expected = wire.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&wire).await.unwrap();
        });

        let mut replayed = vec![0; expected.len()];
        tokio::time::timeout(Duration::from_secs(1), validated.read_exact(&mut replayed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(replayed, expected);
        control
            .claim(Some(IngressRequestKind::Ordinary))
            .unwrap()
            .unwrap()
            .resolve(RequestDisposition::ContinueHttp)
            .unwrap();
        writer.await.unwrap();
    }

    #[test]
    fn connection_token_match_survives_stream_and_cr_boundaries() {
        let prefix = b"Connection:";
        let mut scanner = ConnectionValueScanner {
            inspected: prefix.len(),
            ..ConnectionValueScanner::default()
        };
        let mut first = prefix.to_vec();
        first.extend_from_slice(b" keep-alive,\tup");
        assert!(matches!(
            scanner.scan(&first).unwrap(),
            ConnectionProgress::Release(length) if length == first.len()
        ));
        assert!(matches!(
            scanner.scan(b"GRade \t, close\r").unwrap(),
            ConnectionProgress::Release(length) if length == b"GRade \t, close".len()
        ));
        assert!(matches!(
            scanner.scan(b"\r").unwrap(),
            ConnectionProgress::NeedInput
        ));
        assert!(matches!(
            scanner.scan(b"\r\n").unwrap(),
            ConnectionProgress::Complete(2, true)
        ));

        let mut scanner = ConnectionValueScanner::default();
        assert!(matches!(
            scanner.scan(b"up").unwrap(),
            ConnectionProgress::Release(2)
        ));
        assert!(matches!(
            scanner.scan(b"grade-x\r\n").unwrap(),
            ConnectionProgress::Complete(_, false)
        ));
    }

    #[tokio::test]
    async fn large_connection_and_upgrade_fields_stream_with_exact_classification() {
        for (connection_token, expected_kind) in [
            ("UpGrAdE \t, close", IngressRequestKind::Upgrade),
            ("upgrade-x, close", IngressRequestKind::Ordinary),
        ] {
            let mut wire =
                b"GET /large-relevant HTTP/1.1\r\nHost: example.test\r\nConnection: ".to_vec();
            wire.extend(std::iter::repeat_n(b' ', PARSER_STORE_BYTES + 17));
            wire.extend_from_slice(connection_token.as_bytes());
            wire.extend_from_slice(b"\r\nUpgrade: test-");
            wire.extend(std::iter::repeat_n(b'x', PARSER_STORE_BYTES + 19));
            wire.extend_from_slice(b"\r\n\r\n");
            let expected = wire.clone();

            let (mut client, server) = tokio::io::duplex(PARSER_STORE_BYTES);
            let (mut validated, control) = ValidatedIngressIo::try_new(server, false).unwrap();
            let writer = tokio::spawn(async move {
                client.write_all(&wire).await.unwrap();
            });
            let mut replayed = vec![0; expected.len()];
            tokio::time::timeout(Duration::from_secs(1), validated.read_exact(&mut replayed))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(replayed, expected);
            control
                .claim(Some(expected_kind))
                .unwrap()
                .unwrap()
                .resolve(RequestDisposition::Close)
                .unwrap();
            writer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn content_length_body_larger_than_the_buffer_streams_incrementally() {
        let body = vec![b'b'; PARSER_STORE_BYTES * 2 + 17];
        let head = format!(
            "POST /large-body HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let (mut client, server) = tokio::io::duplex(PARSER_STORE_BYTES);
        let (mut validated, control) = ValidatedIngressIo::try_new(server, false).unwrap();
        let expected_body = body.clone();
        let wire_head = head.clone();
        let writer = tokio::spawn(async move {
            client.write_all(wire_head.as_bytes()).await.unwrap();
            client.write_all(&body).await.unwrap();
        });

        let mut replayed_head = vec![0; head.len()];
        validated.read_exact(&mut replayed_head).await.unwrap();
        assert_eq!(replayed_head, head.as_bytes());
        let ticket = control
            .claim(Some(IngressRequestKind::Ordinary))
            .unwrap()
            .unwrap();
        let mut replayed_body = vec![0; expected_body.len()];
        tokio::time::timeout(
            Duration::from_secs(1),
            validated.read_exact(&mut replayed_body),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(replayed_body, expected_body);
        ticket.resolve(RequestDisposition::ContinueHttp).unwrap();
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn trailer_section_larger_than_the_buffer_streams_complete_fields() {
        let head =
            b"POST /trailers HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut body = b"1\r\nx\r\n0\r\n".to_vec();
        for index in 0..8 {
            body.extend_from_slice(format!("X-Trailer-{index}: ").as_bytes());
            body.extend(std::iter::repeat_n(b't', 12 * 1024));
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"\r\n");
        assert!(body.len() > PARSER_STORE_BYTES);

        let (mut client, server) = tokio::io::duplex(PARSER_STORE_BYTES);
        let (mut validated, control) = ValidatedIngressIo::try_new(server, false).unwrap();
        let expected_body = body.clone();
        let writer = tokio::spawn(async move {
            client.write_all(head).await.unwrap();
            client.write_all(&body).await.unwrap();
        });

        let mut replayed_head = vec![0; head.len()];
        validated.read_exact(&mut replayed_head).await.unwrap();
        assert_eq!(replayed_head, head);
        let ticket = control
            .claim(Some(IngressRequestKind::Ordinary))
            .unwrap()
            .unwrap();
        let mut replayed_body = vec![0; expected_body.len()];
        tokio::time::timeout(
            Duration::from_secs(1),
            validated.read_exact(&mut replayed_body),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(replayed_body, expected_body);
        ticket.resolve(RequestDisposition::ContinueHttp).unwrap();
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_and_obs_folded_trailers_are_rejected() {
        for trailer in [
            b" missing: value\r\n\r\n".as_slice(),
            b"missing-colon\r\n\r\n",
            b"Content-Length: 0\r\n\r\n",
            b"transfer-ENCODING: chunked\r\n\r\n",
        ] {
            let head = b"POST /trailers HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n";
            let mut wire = head.to_vec();
            wire.extend_from_slice(b"0\r\n");
            wire.extend_from_slice(trailer);
            let (mut client, server) = tokio::io::duplex(PARSER_STORE_BYTES);
            let (mut validated, control) = ValidatedIngressIo::try_new(server, false).unwrap();
            client.write_all(&wire).await.unwrap();

            let mut replayed_head = vec![0; head.len()];
            validated.read_exact(&mut replayed_head).await.unwrap();
            control
                .claim(Some(IngressRequestKind::Ordinary))
                .unwrap()
                .unwrap()
                .resolve(RequestDisposition::ContinueHttp)
                .unwrap();
            let mut body = Vec::new();
            assert!(validated.read_to_end(&mut body).await.is_err());
        }
    }

    #[tokio::test]
    async fn eof_after_released_head_prefix_is_incomplete() {
        for wire in [
            b"GET / HTTP/1.1\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: example.test\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nX-Streamed: value-without-crlf".as_slice(),
        ] {
            let (mut client, server) = tokio::io::duplex(PARSER_STORE_BYTES);
            let (mut validated, _) = ValidatedIngressIo::try_new(server, false).unwrap();
            client.write_all(wire).await.unwrap();
            client.shutdown().await.unwrap();
            let mut replayed = Vec::new();
            assert!(validated.read_to_end(&mut replayed).await.is_err());
        }
    }
}
