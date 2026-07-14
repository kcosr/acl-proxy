use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;

use bytes::Buf;
use http::header::{HeaderMap, CONTENT_ENCODING, TRAILER};
use hyper::body::HttpBody;
use miniz_oxide::inflate::stream::{inflate, InflateState};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};
use tokio::time::Instant;

use crate::config::compiler::HttpBodyReadLimits;
use crate::safety::wire_body::{
    GuardedBodyBuilder, GuardedBodySegments, GuardedWorkspace, WireBodyBufferError,
};
use crate::safety::{GuardedBody, HttpWireBodyGuard};

pub(crate) const HTTP_DECODER_OUTPUT_STAGING_BYTES: usize = 64 * 1024;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const BROTLI_MIN_WINDOW_BYTES: usize = KIB;
const BROTLI_MAX_WINDOW_BYTES: usize = 16 * MIB;
const BROTLI_RING_WRITE_AHEAD_SLACK_BYTES: usize = 542;
// Three simultaneously live Huffman groups account for less than 2.5 MiB.
// The remainder covers context maps, block trees, decoder state, and arena
// allocation headers for a standard-window stream with no dictionary.
const BROTLI_FIXED_WORKSPACE_BYTES: usize = 3 * MIB;
const ZSTD_MIN_WINDOW_BYTES: usize = KIB;
const CONTENT_DECODING_FLOOR_BYTES: usize = MIB;
const GZIP_HEADER_MAX_BYTES: usize = 16 * KIB;
const ARENA_ALIGNMENT: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HttpDecoderWorkspaceSizes {
    pub(crate) deflate: usize,
    pub(crate) brotli: usize,
    pub(crate) zstd: usize,
}

impl HttpDecoderWorkspaceSizes {
    pub(crate) fn maximum(self) -> usize {
        self.deflate.max(self.brotli).max(self.zstd)
    }
}

pub(crate) fn http_decoder_workspace_sizes(
    max_decoded_bytes: usize,
) -> Option<HttpDecoderWorkspaceSizes> {
    let brotli_window = brotli_window_limit(max_decoded_bytes)?;
    let brotli = BROTLI_FIXED_WORKSPACE_BYTES
        .checked_add(brotli_window)?
        .checked_add(BROTLI_RING_WRITE_AHEAD_SLACK_BYTES)?;
    let zstd_window = zstd_window_limit(max_decoded_bytes)?;
    // This estimator and `ZSTD_initStaticDStream` are a paired API. The
    // returned reservation contains the context and the bounded history window
    // and therefore performs no allocator callback while decoding.
    let zstd = unsafe { zstd_sys::ZSTD_estimateDStreamSize(zstd_window) };
    if unsafe { zstd_sys::ZSTD_isError(zstd) } != 0 {
        return None;
    }
    Some(HttpDecoderWorkspaceSizes {
        deflate: size_of::<miniz_oxide::inflate::stream::InflateState>(),
        brotli,
        zstd,
    })
}

pub(crate) fn brotli_window_limit(max_decoded_bytes: usize) -> Option<usize> {
    max_decoded_bytes
        .max(BROTLI_MIN_WINDOW_BYTES)
        .checked_next_power_of_two()
        .map(|bytes| bytes.min(BROTLI_MAX_WINDOW_BYTES))
}

fn zstd_window_limit(max_decoded_bytes: usize) -> Option<usize> {
    max_decoded_bytes
        .max(ZSTD_MIN_WINDOW_BYTES)
        .checked_next_power_of_two()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContentEncoding {
    Identity,
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CanonicalContentEncoding {
    Identity,
}

pub(crate) struct GuardedRequestBody {
    body: GuardedBody,
}

impl GuardedRequestBody {
    pub(crate) fn content_encoding(&self) -> CanonicalContentEncoding {
        CanonicalContentEncoding::Identity
    }

    pub(crate) fn len(&self) -> usize {
        self.body.len()
    }

    pub(crate) fn into_guarded_body(self) -> GuardedBody {
        self.body
    }
}

impl std::fmt::Debug for GuardedRequestBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuardedRequestBody")
            .field("len", &self.body.len())
            .field("content_encoding", &CanonicalContentEncoding::Identity)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum HttpBodyReadError {
    #[error("request content encoding is unsupported")]
    UnsupportedContentEncoding,
    #[error("stacked request content encodings are unsupported")]
    StackedContentEncoding,
    #[error("request body read failed")]
    ReadFailed,
    #[error("request trailers are unsupported for mandatory body normalization")]
    RequestTrailersUnsupported,
    #[error("request body processing timed out")]
    TimedOut,
    #[error("encoded request body limit exceeded")]
    EncodedLimitExceeded,
    #[error("decoded request body limit exceeded")]
    DecodedLimitExceeded,
    #[error("request content-decoding expansion ratio exceeded")]
    ExpansionRatioExceeded,
    #[error("request content encoding is invalid")]
    InvalidContentEncoding,
    #[error("request content-encoding window exceeds the bounded decoder workspace")]
    DecoderWindowExceeded,
    #[error("request body resource capacity exhausted")]
    ResourceExhausted,
}

impl From<WireBodyBufferError> for HttpBodyReadError {
    fn from(_: WireBodyBufferError) -> Self {
        Self::ResourceExhausted
    }
}

pub(crate) async fn read_mandatory_request_body<B>(
    headers: &HeaderMap,
    mut body: B,
    limits: HttpBodyReadLimits,
    max_expansion_ratio: usize,
    deadline: Instant,
    guard: &HttpWireBodyGuard,
) -> Result<GuardedRequestBody, HttpBodyReadError>
where
    B: HttpBody + Unpin,
    B::Data: Buf,
{
    let encoding = parse_content_encoding(headers)?;
    if headers.contains_key(TRAILER) {
        return Err(HttpBodyReadError::RequestTrailersUnsupported);
    }
    let mut encoded = guard.buffer();
    loop {
        let next = tokio::time::timeout_at(deadline, body.data())
            .await
            .map_err(|_| HttpBodyReadError::TimedOut)?;
        let Some(chunk) = next else {
            break;
        };
        let mut chunk = chunk.map_err(|_| HttpBodyReadError::ReadFailed)?;
        while chunk.has_remaining() {
            let bytes = chunk.chunk();
            if bytes.is_empty() {
                return Err(HttpBodyReadError::ReadFailed);
            }
            let next_len = encoded
                .len()
                .checked_add(bytes.len())
                .ok_or(HttpBodyReadError::EncodedLimitExceeded)?;
            if next_len > limits.max_encoded_bytes() {
                return Err(HttpBodyReadError::EncodedLimitExceeded);
            }
            encoded.try_extend_from_slice(bytes)?;
            chunk.advance(bytes.len());
        }
    }
    let trailers = tokio::time::timeout_at(deadline, body.trailers())
        .await
        .map_err(|_| HttpBodyReadError::TimedOut)?
        .map_err(|_| HttpBodyReadError::ReadFailed)?;
    if trailers.is_some_and(|trailers| !trailers.is_empty()) {
        return Err(HttpBodyReadError::RequestTrailersUnsupported);
    }

    let encoded = encoded.finish();
    if encoding == ContentEncoding::Identity {
        if encoded.len() > limits.max_decoded_bytes() {
            return Err(HttpBodyReadError::DecodedLimitExceeded);
        }
        return Ok(GuardedRequestBody { body: encoded });
    }

    let workspace_sizes = http_decoder_workspace_sizes(limits.max_decoded_bytes())
        .ok_or(HttpBodyReadError::ResourceExhausted)?;
    let decoded = match encoding {
        ContentEncoding::Identity => unreachable!("identity returned above"),
        ContentEncoding::Gzip => {
            decode_gzip(
                &encoded,
                guard,
                workspace_sizes.deflate,
                limits.max_decoded_bytes(),
                max_expansion_ratio,
                deadline,
            )
            .await?
        }
        ContentEncoding::Deflate => {
            decode_deflate(
                &encoded,
                guard,
                workspace_sizes.deflate,
                limits.max_decoded_bytes(),
                max_expansion_ratio,
                deadline,
            )
            .await?
        }
        ContentEncoding::Brotli => {
            decode_brotli(
                &encoded,
                guard,
                workspace_sizes.brotli,
                limits.max_decoded_bytes(),
                max_expansion_ratio,
                deadline,
            )
            .await?
        }
        ContentEncoding::Zstd => {
            decode_zstd(
                &encoded,
                guard,
                workspace_sizes.zstd,
                limits.max_decoded_bytes(),
                max_expansion_ratio,
                deadline,
            )
            .await?
        }
    };
    drop(encoded);
    Ok(GuardedRequestBody { body: decoded })
}

fn parse_content_encoding(headers: &HeaderMap) -> Result<ContentEncoding, HttpBodyReadError> {
    let mut values = headers.get_all(CONTENT_ENCODING).iter();
    let Some(value) = values.next() else {
        return Ok(ContentEncoding::Identity);
    };
    if values.next().is_some() {
        return Err(HttpBodyReadError::StackedContentEncoding);
    }
    let value = value
        .to_str()
        .map_err(|_| HttpBodyReadError::UnsupportedContentEncoding)?;
    let value = value.trim_matches([' ', '\t']);
    if value.contains(',') {
        return Err(HttpBodyReadError::StackedContentEncoding);
    }
    if value.eq_ignore_ascii_case("identity") {
        Ok(ContentEncoding::Identity)
    } else if value.eq_ignore_ascii_case("gzip") {
        Ok(ContentEncoding::Gzip)
    } else if value.eq_ignore_ascii_case("deflate") {
        Ok(ContentEncoding::Deflate)
    } else if value.eq_ignore_ascii_case("br") {
        Ok(ContentEncoding::Brotli)
    } else if value.eq_ignore_ascii_case("zstd") {
        Ok(ContentEncoding::Zstd)
    } else {
        Err(HttpBodyReadError::UnsupportedContentEncoding)
    }
}

struct EncodedCursor<'a> {
    segments: GuardedBodySegments<'a>,
    current: &'a [u8],
    offset: usize,
    consumed: usize,
    total: usize,
}

impl<'a> EncodedCursor<'a> {
    fn new(body: &'a GuardedBody) -> Self {
        let mut segments = body.segments();
        let current = segments.next().unwrap_or_default();
        Self {
            segments,
            current,
            offset: 0,
            consumed: 0,
            total: body.len(),
        }
    }

    fn current(&self) -> &'a [u8] {
        &self.current[self.offset..]
    }

    fn advance(&mut self, mut bytes: usize) -> Result<(), HttpBodyReadError> {
        while bytes != 0 {
            let available = self.current.len().saturating_sub(self.offset);
            if available == 0 {
                self.current = self.segments.next().unwrap_or_default();
                self.offset = 0;
                if self.current.is_empty() {
                    return Err(HttpBodyReadError::InvalidContentEncoding);
                }
                continue;
            }
            let taken = bytes.min(available);
            self.offset += taken;
            self.consumed = self
                .consumed
                .checked_add(taken)
                .ok_or(HttpBodyReadError::InvalidContentEncoding)?;
            bytes -= taken;
        }
        if self.offset == self.current.len() {
            self.current = self.segments.next().unwrap_or_default();
            self.offset = 0;
        }
        Ok(())
    }

    fn read_byte(&mut self) -> Result<u8, HttpBodyReadError> {
        let byte = *self
            .current()
            .first()
            .ok_or(HttpBodyReadError::InvalidContentEncoding)?;
        self.advance(1)?;
        Ok(byte)
    }

    fn is_end(&self) -> bool {
        self.consumed == self.total
    }

    fn consumed(&self) -> usize {
        self.consumed
    }
}

struct DecodeProgress {
    decoded: usize,
    max_decoded: usize,
    ratio: usize,
    deadline: Instant,
}

impl DecodeProgress {
    async fn emit(
        &mut self,
        output: &[u8],
        encoded_consumed: usize,
        builder: &mut GuardedBodyBuilder,
    ) -> Result<(), HttpBodyReadError> {
        if output.is_empty() {
            return self.check_deadline();
        }
        let next = validate_decoded_growth(
            self.decoded,
            output.len(),
            self.max_decoded,
            self.ratio,
            encoded_consumed,
        )?;
        builder.try_extend_from_slice(output)?;
        self.decoded = next;
        self.check_deadline()?;
        tokio::task::yield_now().await;
        self.check_deadline()
    }

    fn check_deadline(&self) -> Result<(), HttpBodyReadError> {
        if Instant::now() >= self.deadline {
            Err(HttpBodyReadError::TimedOut)
        } else {
            Ok(())
        }
    }
}

fn validate_decoded_growth(
    decoded: usize,
    increment: usize,
    max_decoded: usize,
    ratio: usize,
    encoded_consumed: usize,
) -> Result<usize, HttpBodyReadError> {
    let next = decoded
        .checked_add(increment)
        .ok_or(HttpBodyReadError::DecodedLimitExceeded)?;
    if next > max_decoded {
        return Err(HttpBodyReadError::DecodedLimitExceeded);
    }
    let proportional = ratio
        .checked_mul(encoded_consumed)
        .ok_or(HttpBodyReadError::ExpansionRatioExceeded)?;
    if next > CONTENT_DECODING_FLOOR_BYTES.max(proportional) {
        return Err(HttpBodyReadError::ExpansionRatioExceeded);
    }
    Ok(next)
}

struct InflateSession {
    state: *mut InflateState,
    workspace: GuardedWorkspace,
}

// The pointer targets this session's heap-stable guarded workspace. Decoder
// access is synchronous and exclusive even if the owning future moves threads.
unsafe impl Send for InflateSession {}

impl InflateSession {
    fn new(
        guard: &HttpWireBodyGuard,
        workspace_bytes: usize,
        format: DataFormat,
    ) -> Result<Self, HttpBodyReadError> {
        let mut workspace = guard.codec_workspace(workspace_bytes)?;
        if workspace.len() < size_of::<InflateState>()
            || !(workspace.as_mut_ptr() as usize)
                .is_multiple_of(std::mem::align_of::<InflateState>())
        {
            return Err(HttpBodyReadError::ResourceExhausted);
        }
        let state = workspace.as_mut_ptr().cast::<InflateState>();
        // The workspace is aligned, exclusively owned, and large enough for the
        // fixed miniz state. It remains live until `state` is dropped below.
        unsafe { state.write(InflateState::new(format)) };
        Ok(Self { state, workspace })
    }

    fn state(&mut self) -> &mut InflateState {
        // `state` points into the live, exclusively borrowed workspace.
        unsafe { &mut *self.state }
    }
}

impl Drop for InflateSession {
    fn drop(&mut self) {
        // InflateState owns no external allocation. Drop it before the backing
        // workspace is wiped and released.
        unsafe { ptr::drop_in_place(self.state) };
        self.workspace.reset();
    }
}

async fn inflate_cursor(
    cursor: &mut EncodedCursor<'_>,
    guard: &HttpWireBodyGuard,
    workspace_bytes: usize,
    format: DataFormat,
    output: &mut GuardedBodyBuilder,
    progress: &mut DecodeProgress,
    mut crc: Option<&mut crc32fast::Hasher>,
) -> Result<(), HttpBodyReadError> {
    let mut session = InflateSession::new(guard, workspace_bytes, format)?;
    let mut staging = guard.stream_scratch()?;
    loop {
        progress.check_deadline()?;
        let result = {
            let input = cursor.current();
            let flush = if cursor.is_end() {
                MZFlush::Finish
            } else {
                MZFlush::None
            };
            inflate(session.state(), input, staging.writable(), flush)
        };
        cursor.advance(result.bytes_consumed)?;
        staging.set_initialized(result.bytes_written);
        if let Some(hasher) = crc.as_deref_mut() {
            hasher.update(staging.as_slice());
        }
        progress
            .emit(staging.as_slice(), cursor.consumed(), output)
            .await?;
        match result.status {
            Ok(MZStatus::StreamEnd) => return Ok(()),
            Ok(MZStatus::Ok) => {
                if result.bytes_consumed == 0 && result.bytes_written == 0 {
                    return Err(HttpBodyReadError::InvalidContentEncoding);
                }
            }
            Ok(MZStatus::NeedDict) | Err(_) => {
                return Err(HttpBodyReadError::InvalidContentEncoding)
            }
        }
    }
}

async fn decode_deflate(
    encoded: &GuardedBody,
    guard: &HttpWireBodyGuard,
    workspace_bytes: usize,
    max_decoded: usize,
    ratio: usize,
    deadline: Instant,
) -> Result<GuardedBody, HttpBodyReadError> {
    match decode_deflate_attempt(
        encoded,
        guard,
        workspace_bytes,
        max_decoded,
        ratio,
        deadline,
        DataFormat::Zlib,
    )
    .await
    {
        Err(HttpBodyReadError::InvalidContentEncoding) => {
            decode_deflate_attempt(
                encoded,
                guard,
                workspace_bytes,
                max_decoded,
                ratio,
                deadline,
                DataFormat::Raw,
            )
            .await
        }
        result => result,
    }
}

async fn decode_deflate_attempt(
    encoded: &GuardedBody,
    guard: &HttpWireBodyGuard,
    workspace_bytes: usize,
    max_decoded: usize,
    ratio: usize,
    deadline: Instant,
    format: DataFormat,
) -> Result<GuardedBody, HttpBodyReadError> {
    let mut cursor = EncodedCursor::new(encoded);
    let mut output = guard.buffer();
    let mut progress = DecodeProgress {
        decoded: 0,
        max_decoded,
        ratio,
        deadline,
    };
    inflate_cursor(
        &mut cursor,
        guard,
        workspace_bytes,
        format,
        &mut output,
        &mut progress,
        None,
    )
    .await?;
    if !cursor.is_end() {
        return Err(HttpBodyReadError::InvalidContentEncoding);
    }
    Ok(output.finish())
}

async fn decode_gzip(
    encoded: &GuardedBody,
    guard: &HttpWireBodyGuard,
    workspace_bytes: usize,
    max_decoded: usize,
    ratio: usize,
    deadline: Instant,
) -> Result<GuardedBody, HttpBodyReadError> {
    let mut cursor = EncodedCursor::new(encoded);
    let mut output = guard.buffer();
    let mut progress = DecodeProgress {
        decoded: 0,
        max_decoded,
        ratio,
        deadline,
    };
    let mut members = 0usize;
    while !cursor.is_end() {
        progress.check_deadline()?;
        parse_gzip_header(&mut cursor)?;
        let member_start = progress.decoded;
        let mut crc = crc32fast::Hasher::new();
        inflate_cursor(
            &mut cursor,
            guard,
            workspace_bytes,
            DataFormat::Raw,
            &mut output,
            &mut progress,
            Some(&mut crc),
        )
        .await?;
        let expected_crc = read_u32_le(&mut cursor)?;
        let expected_size = read_u32_le(&mut cursor)?;
        if crc.finalize() != expected_crc
            || (progress.decoded - member_start) as u32 != expected_size
        {
            return Err(HttpBodyReadError::InvalidContentEncoding);
        }
        members += 1;
    }
    if members == 0 {
        return Err(HttpBodyReadError::InvalidContentEncoding);
    }
    Ok(output.finish())
}

fn parse_gzip_header(cursor: &mut EncodedCursor<'_>) -> Result<(), HttpBodyReadError> {
    let header_start = cursor.consumed();
    let mut header_crc = crc32fast::Hasher::new();
    let id1 = read_gzip_header_byte(cursor, &mut header_crc, header_start)?;
    let id2 = read_gzip_header_byte(cursor, &mut header_crc, header_start)?;
    let method = read_gzip_header_byte(cursor, &mut header_crc, header_start)?;
    let flags = read_gzip_header_byte(cursor, &mut header_crc, header_start)?;
    if id1 != 0x1f || id2 != 0x8b || method != 8 || flags & 0xe0 != 0 {
        return Err(HttpBodyReadError::InvalidContentEncoding);
    }
    for _ in 0..6 {
        read_gzip_header_byte(cursor, &mut header_crc, header_start)?;
    }
    if flags & 0x04 != 0 {
        let low = read_gzip_header_byte(cursor, &mut header_crc, header_start)?;
        let high = read_gzip_header_byte(cursor, &mut header_crc, header_start)?;
        let length = u16::from_le_bytes([low, high]) as usize;
        for _ in 0..length {
            read_gzip_header_byte(cursor, &mut header_crc, header_start)?;
        }
    }
    for mask in [0x08, 0x10] {
        if flags & mask != 0 {
            loop {
                if read_gzip_header_byte(cursor, &mut header_crc, header_start)? == 0 {
                    break;
                }
            }
        }
    }
    if flags & 0x02 != 0 {
        let expected = u16::from_le_bytes([cursor.read_byte()?, cursor.read_byte()?]);
        if header_crc.finalize() as u16 != expected {
            return Err(HttpBodyReadError::InvalidContentEncoding);
        }
    }
    Ok(())
}

fn read_gzip_header_byte(
    cursor: &mut EncodedCursor<'_>,
    crc: &mut crc32fast::Hasher,
    header_start: usize,
) -> Result<u8, HttpBodyReadError> {
    if cursor.consumed().saturating_sub(header_start) >= GZIP_HEADER_MAX_BYTES {
        return Err(HttpBodyReadError::InvalidContentEncoding);
    }
    let byte = cursor.read_byte()?;
    crc.update(&[byte]);
    Ok(byte)
}

fn read_u32_le(cursor: &mut EncodedCursor<'_>) -> Result<u32, HttpBodyReadError> {
    Ok(u32::from_le_bytes([
        cursor.read_byte()?,
        cursor.read_byte()?,
        cursor.read_byte()?,
        cursor.read_byte()?,
    ]))
}

#[repr(C, align(16))]
struct BrotliArenaState {
    base: *mut u8,
    len: usize,
}

#[repr(C, align(16))]
struct BrotliArenaBlock {
    size: usize,
    used: usize,
}

fn initialize_brotli_arena(workspace: &mut GuardedWorkspace) -> Option<*mut BrotliArenaState> {
    let base = workspace.as_mut_ptr();
    let len = workspace.len();
    let first_block = align_up(size_of::<BrotliArenaState>(), ARENA_ALIGNMENT)?;
    let payload = len
        .checked_sub(first_block)?
        .checked_sub(size_of::<BrotliArenaBlock>())?
        / ARENA_ALIGNMENT
        * ARENA_ALIGNMENT;
    if payload == 0 {
        return None;
    }
    let state = base.cast::<BrotliArenaState>();
    let block = unsafe { base.add(first_block).cast::<BrotliArenaBlock>() };
    // Both structures live in the aligned guarded workspace and are wiped with it.
    unsafe {
        state.write(BrotliArenaState { base, len });
        block.write(BrotliArenaBlock {
            size: payload,
            used: 0,
        });
    }
    Some(state)
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment - 1)
        .map(|value| value / alignment * alignment)
}

unsafe extern "C" fn brotli_arena_alloc(opaque: *mut c_void, size: usize) -> *mut c_void {
    if opaque.is_null() || size == 0 {
        return ptr::null_mut();
    }
    let arena = unsafe { &mut *opaque.cast::<BrotliArenaState>() };
    let Some(requested) = align_up(size, ARENA_ALIGNMENT) else {
        return ptr::null_mut();
    };
    let Some(mut offset) = align_up(size_of::<BrotliArenaState>(), ARENA_ALIGNMENT) else {
        return ptr::null_mut();
    };
    while offset
        .checked_add(size_of::<BrotliArenaBlock>())
        .is_some_and(|end| end <= arena.len)
    {
        let block = unsafe { &mut *arena.base.add(offset).cast::<BrotliArenaBlock>() };
        if block.size == 0
            || offset
                .checked_add(size_of::<BrotliArenaBlock>())
                .and_then(|end| end.checked_add(block.size))
                .is_none_or(|end| end > arena.len)
        {
            return ptr::null_mut();
        }
        if block.used == 0 && block.size >= requested {
            let remaining = block.size - requested;
            if remaining >= size_of::<BrotliArenaBlock>() + ARENA_ALIGNMENT {
                let next_offset = offset + size_of::<BrotliArenaBlock>() + requested;
                let next = unsafe { &mut *arena.base.add(next_offset).cast::<BrotliArenaBlock>() };
                next.size = remaining - size_of::<BrotliArenaBlock>();
                next.used = 0;
                block.size = requested;
            }
            block.used = 1;
            let payload = unsafe { arena.base.add(offset + size_of::<BrotliArenaBlock>()) };
            unsafe { payload.write_bytes(0, block.size) };
            return payload.cast::<c_void>();
        }
        offset += size_of::<BrotliArenaBlock>() + block.size;
    }
    ptr::null_mut()
}

unsafe extern "C" fn brotli_arena_free(opaque: *mut c_void, address: *mut c_void) {
    if opaque.is_null() || address.is_null() {
        return;
    }
    let arena = unsafe { &mut *opaque.cast::<BrotliArenaState>() };
    let address = address.cast::<u8>();
    let base = arena.base as usize;
    let Some(end) = base.checked_add(arena.len) else {
        return;
    };
    if (address as usize) < base + size_of::<BrotliArenaBlock>() || address as usize >= end {
        return;
    }
    let block = unsafe { address.sub(size_of::<BrotliArenaBlock>()) }.cast::<BrotliArenaBlock>();
    let block = unsafe { &mut *block };
    if block.used != 1 || (address as usize).saturating_add(block.size) > end {
        return;
    }
    unsafe { address.write_bytes(0, block.size) };
    block.used = 0;
    coalesce_brotli_arena(arena);
}

fn coalesce_brotli_arena(arena: &mut BrotliArenaState) {
    let Some(mut offset) = align_up(size_of::<BrotliArenaState>(), ARENA_ALIGNMENT) else {
        return;
    };
    while offset + size_of::<BrotliArenaBlock>() <= arena.len {
        let block = unsafe { &mut *arena.base.add(offset).cast::<BrotliArenaBlock>() };
        if block.size == 0 || offset + size_of::<BrotliArenaBlock>() + block.size > arena.len {
            return;
        }
        let next_offset = offset + size_of::<BrotliArenaBlock>() + block.size;
        if next_offset + size_of::<BrotliArenaBlock>() > arena.len {
            return;
        }
        let next = unsafe { &mut *arena.base.add(next_offset).cast::<BrotliArenaBlock>() };
        if block.used == 0 && next.used == 0 {
            block.size += size_of::<BrotliArenaBlock>() + next.size;
            continue;
        }
        offset = next_offset;
    }
}

struct BrotliSession {
    state: *mut compu_brotli_sys::BrotliDecoderState,
    workspace: GuardedWorkspace,
}

// The C state and allocator metadata both live in the heap-stable guarded
// workspace and are touched only by the owning future.
unsafe impl Send for BrotliSession {}

impl BrotliSession {
    fn new(guard: &HttpWireBodyGuard, workspace_bytes: usize) -> Result<Self, HttpBodyReadError> {
        let mut workspace = guard.codec_workspace(workspace_bytes)?;
        let arena =
            initialize_brotli_arena(&mut workspace).ok_or(HttpBodyReadError::ResourceExhausted)?;
        let state = unsafe {
            compu_brotli_sys::BrotliDecoderCreateInstance(
                Some(brotli_arena_alloc),
                Some(brotli_arena_free),
                arena.cast::<c_void>(),
            )
        };
        if state.is_null() {
            return Err(HttpBodyReadError::ResourceExhausted);
        }
        let configured = unsafe {
            compu_brotli_sys::BrotliDecoderSetParameter(
                state,
                compu_brotli_sys::BrotliDecoderParameter_BROTLI_DECODER_PARAM_DISABLE_RING_BUFFER_REALLOCATION,
                1,
            )
        };
        if configured == 0 {
            unsafe { compu_brotli_sys::BrotliDecoderDestroyInstance(state) };
            return Err(HttpBodyReadError::ResourceExhausted);
        }
        Ok(Self { state, workspace })
    }
}

impl Drop for BrotliSession {
    fn drop(&mut self) {
        unsafe { compu_brotli_sys::BrotliDecoderDestroyInstance(self.state) };
        self.state = ptr::null_mut();
        self.workspace.reset();
    }
}

async fn decode_brotli(
    encoded: &GuardedBody,
    guard: &HttpWireBodyGuard,
    workspace_bytes: usize,
    max_decoded: usize,
    ratio: usize,
    deadline: Instant,
) -> Result<GuardedBody, HttpBodyReadError> {
    let first = EncodedCursor::new(encoded)
        .current()
        .first()
        .copied()
        .ok_or(HttpBodyReadError::InvalidContentEncoding)?;
    let window_bits = brotli_window_bits(first)?;
    let window_limit =
        brotli_window_limit(max_decoded).ok_or(HttpBodyReadError::ResourceExhausted)?;
    if 1usize
        .checked_shl(window_bits)
        .is_none_or(|window| window > window_limit)
    {
        return Err(HttpBodyReadError::DecoderWindowExceeded);
    }

    let session = BrotliSession::new(guard, workspace_bytes)?;
    let mut cursor = EncodedCursor::new(encoded);
    let mut staging = guard.stream_scratch()?;
    let mut output = guard.buffer();
    let mut progress = DecodeProgress {
        decoded: 0,
        max_decoded,
        ratio,
        deadline,
    };
    loop {
        progress.check_deadline()?;
        let (result, consumed, written) = {
            let input = cursor.current();
            let mut available_in = input.len();
            let mut next_in = input.as_ptr();
            let writable = staging.writable();
            let mut available_out = writable.len();
            let mut next_out = writable.as_mut_ptr();
            let mut total_out = progress.decoded;
            let result = unsafe {
                compu_brotli_sys::BrotliDecoderDecompressStream(
                    session.state,
                    &mut available_in,
                    &mut next_in,
                    &mut available_out,
                    &mut next_out,
                    &mut total_out,
                )
            };
            (
                result,
                input.len() - available_in,
                staging.capacity() - available_out,
            )
        };
        cursor.advance(consumed)?;
        staging.set_initialized(written);
        progress
            .emit(staging.as_slice(), cursor.consumed(), &mut output)
            .await?;
        match result {
            compu_brotli_sys::BrotliDecoderResult_BROTLI_DECODER_RESULT_SUCCESS => {
                if !cursor.is_end() {
                    return Err(HttpBodyReadError::InvalidContentEncoding);
                }
                return Ok(output.finish());
            }
            compu_brotli_sys::BrotliDecoderResult_BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT
            | compu_brotli_sys::BrotliDecoderResult_BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT => {
                if consumed == 0 && written == 0 {
                    return Err(HttpBodyReadError::InvalidContentEncoding);
                }
            }
            _ => return Err(HttpBodyReadError::InvalidContentEncoding),
        }
    }
}

fn brotli_window_bits(first: u8) -> Result<u32, HttpBodyReadError> {
    if first & 1 == 0 {
        return Ok(16);
    }
    let first_code = (first >> 1) & 7;
    if first_code != 0 {
        return Ok(17 + u32::from(first_code));
    }
    let second_code = (first >> 4) & 7;
    if second_code == 1 {
        return Err(HttpBodyReadError::InvalidContentEncoding);
    }
    if second_code != 0 {
        Ok(8 + u32::from(second_code))
    } else {
        Ok(17)
    }
}

struct ZstdSession {
    stream: *mut zstd_sys::ZSTD_DStream,
    workspace: GuardedWorkspace,
}

// The static DStream pointer targets the session's heap-stable guarded
// workspace and is used exclusively by the owning future.
unsafe impl Send for ZstdSession {}

impl ZstdSession {
    fn new(
        guard: &HttpWireBodyGuard,
        workspace_bytes: usize,
        max_decoded: usize,
    ) -> Result<Self, HttpBodyReadError> {
        let mut workspace = guard.codec_workspace(workspace_bytes)?;
        let stream = unsafe {
            zstd_sys::ZSTD_initStaticDStream(
                workspace.as_mut_ptr().cast::<c_void>(),
                workspace.len(),
            )
        };
        if stream.is_null() {
            return Err(HttpBodyReadError::ResourceExhausted);
        }
        let window = zstd_window_limit(max_decoded).ok_or(HttpBodyReadError::ResourceExhausted)?;
        let window_log = (usize::BITS - window.leading_zeros() - 1) as i32;
        let result = unsafe {
            zstd_sys::ZSTD_DCtx_setParameter(
                stream,
                zstd_sys::ZSTD_dParameter::ZSTD_d_windowLogMax,
                window_log,
            )
        };
        if unsafe { zstd_sys::ZSTD_isError(result) } != 0 {
            return Err(HttpBodyReadError::ResourceExhausted);
        }
        Ok(Self { stream, workspace })
    }
}

impl Drop for ZstdSession {
    fn drop(&mut self) {
        // Static DStreams have no free call. Wiping their caller-owned backing
        // store destroys all state and history before the guard releases it.
        self.stream = ptr::null_mut();
        self.workspace.reset();
    }
}

async fn decode_zstd(
    encoded: &GuardedBody,
    guard: &HttpWireBodyGuard,
    workspace_bytes: usize,
    max_decoded: usize,
    ratio: usize,
    deadline: Instant,
) -> Result<GuardedBody, HttpBodyReadError> {
    let session = ZstdSession::new(guard, workspace_bytes, max_decoded)?;
    let mut cursor = EncodedCursor::new(encoded);
    let mut staging = guard.stream_scratch()?;
    let mut output = guard.buffer();
    let mut progress = DecodeProgress {
        decoded: 0,
        max_decoded,
        ratio,
        deadline,
    };
    loop {
        progress.check_deadline()?;
        let (result, input_pos, output_pos) = {
            let input = cursor.current();
            let mut input_buffer = zstd_sys::ZSTD_inBuffer {
                src: input.as_ptr().cast::<c_void>(),
                size: input.len(),
                pos: 0,
            };
            let writable = staging.writable();
            let mut output_buffer = zstd_sys::ZSTD_outBuffer {
                dst: writable.as_mut_ptr().cast::<c_void>(),
                size: writable.len(),
                pos: 0,
            };
            let result = unsafe {
                zstd_sys::ZSTD_decompressStream(
                    session.stream,
                    &mut output_buffer,
                    &mut input_buffer,
                )
            };
            (result, input_buffer.pos, output_buffer.pos)
        };
        if unsafe { zstd_sys::ZSTD_isError(result) } != 0 {
            return Err(HttpBodyReadError::InvalidContentEncoding);
        }
        cursor.advance(input_pos)?;
        staging.set_initialized(output_pos);
        progress
            .emit(staging.as_slice(), cursor.consumed(), &mut output)
            .await?;
        if result == 0 && cursor.is_end() {
            return Ok(output.finish());
        }
        if input_pos == 0 && output_pos == 0 {
            return Err(HttpBodyReadError::InvalidContentEncoding);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
    use flate2::Compression;
    use http::HeaderValue;
    use hyper::Body;
    use tokio_stream::StreamExt;

    use crate::safety::wire_body::{
        guarded_body_allocation_bytes, guarded_workspace_allocation_bytes, WireBodyPool,
        WireBodyQuotaKey,
    };

    use super::*;

    fn key() -> WireBodyQuotaKey {
        WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8)), |_| false)
    }

    fn limits(encoded: usize, decoded: usize) -> HttpBodyReadLimits {
        HttpBodyReadLimits::try_new(encoded, decoded).unwrap()
    }

    fn compiled_peak(encoded: usize, decoded: usize) -> usize {
        guarded_body_allocation_bytes(encoded).unwrap()
            + guarded_body_allocation_bytes(decoded).unwrap()
            + guarded_body_allocation_bytes(HTTP_DECODER_OUTPUT_STAGING_BYTES).unwrap()
            + guarded_workspace_allocation_bytes(
                http_decoder_workspace_sizes(decoded).unwrap().maximum(),
            )
            .unwrap()
    }

    async fn invoke(
        encoded: Vec<u8>,
        encoding: Option<&str>,
        max_encoded: usize,
        max_decoded: usize,
        ratio: usize,
    ) -> (
        Result<GuardedRequestBody, HttpBodyReadError>,
        HttpWireBodyGuard,
        Arc<WireBodyPool>,
    ) {
        let peak = compiled_peak(max_encoded, max_decoded);
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(peak, key());
        let mut headers = HeaderMap::new();
        if let Some(encoding) = encoding {
            headers.insert(CONTENT_ENCODING, HeaderValue::from_str(encoding).unwrap());
        }
        let result = read_mandatory_request_body(
            &headers,
            Body::from(encoded),
            limits(max_encoded, max_decoded),
            ratio,
            Instant::now() + Duration::from_secs(5),
            &guard,
        )
        .await;
        (result, guard, pool)
    }

    fn body_bytes(body: &GuardedRequestBody) -> Vec<u8> {
        body.body.segments().flatten().copied().collect()
    }

    fn gzip(input: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    }

    fn zlib(input: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    }

    fn raw_deflate(input: &[u8]) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    }

    fn brotli(input: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::new(&mut output, 4096, 5, 10);
            encoder.write_all(input).unwrap();
        }
        output
    }

    fn zstd(input: &[u8]) -> Vec<u8> {
        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 1).unwrap();
        let window = input.len().max(ZSTD_MIN_WINDOW_BYTES).next_power_of_two();
        let window_log = usize::BITS - window.leading_zeros() - 1;
        encoder.window_log(window_log).unwrap();
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn workspace_selection_includes_each_bounded_codec() {
        let small = http_decoder_workspace_sizes(KIB).unwrap();
        assert_eq!(small.maximum(), small.brotli.max(small.zstd));
        assert!(small.deflate > 0);
        assert!(small.brotli > BROTLI_FIXED_WORKSPACE_BYTES);
        assert!(small.zstd > ZSTD_MIN_WINDOW_BYTES);

        let large = http_decoder_workspace_sizes(32 * MIB).unwrap();
        assert_eq!(brotli_window_limit(32 * MIB), Some(BROTLI_MAX_WINDOW_BYTES));
        assert!(large.zstd > small.zstd);
        assert!(large.maximum() >= large.zstd);
    }

    #[tokio::test]
    async fn identity_and_all_supported_codecs_return_canonical_bytes() {
        let plain = b"canonical request body".repeat(512);
        let cases = [
            (None, plain.clone()),
            (Some("identity"), plain.clone()),
            (Some("gzip"), gzip(&plain)),
            (Some("deflate"), zlib(&plain)),
            (Some("deflate"), raw_deflate(&plain)),
            (Some("br"), brotli(&plain)),
            (Some("zstd"), zstd(&plain)),
        ];
        for (encoding, encoded) in cases {
            let max_encoded = encoded.len();
            let (result, guard, pool) =
                invoke(encoded, encoding, max_encoded, plain.len(), 128).await;
            let body = result.unwrap_or_else(|error| panic!("encoding {encoding:?}: {error:?}"));
            assert_eq!(body.content_encoding(), CanonicalContentEncoding::Identity);
            assert_eq!(body.len(), plain.len());
            assert_eq!(body_bytes(&body), plain, "encoding {encoding:?}");
            drop(body);
            assert_eq!(guard.live_bytes(), 0);
            assert_eq!(pool.global_charge(), 0);
        }
    }

    #[tokio::test]
    async fn encoded_and_decoded_boundaries_are_exact() {
        let exact = vec![0x41; 1024];
        let (result, guard, pool) = invoke(exact.clone(), None, exact.len(), exact.len(), 1).await;
        assert_eq!(body_bytes(&result.unwrap()), exact);
        drop(guard);
        assert_eq!(pool.global_charge(), 0);

        let (result, guard, pool) =
            invoke(exact.clone(), None, exact.len() - 1, exact.len(), 1).await;
        assert_eq!(result.unwrap_err(), HttpBodyReadError::EncodedLimitExceeded);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);

        let compressed = gzip(&exact);
        let (result, guard, pool) = invoke(
            compressed.clone(),
            Some("gzip"),
            compressed.len(),
            exact.len(),
            128,
        )
        .await;
        assert_eq!(body_bytes(&result.unwrap()), exact);
        drop(guard);
        assert_eq!(pool.global_charge(), 0);

        let (result, guard, pool) = invoke(
            compressed.clone(),
            Some("gzip"),
            compressed.len(),
            exact.len() - 1,
            128,
        )
        .await;
        assert_eq!(result.unwrap_err(), HttpBodyReadError::DecodedLimitExceeded);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn content_decoding_expansion_bound_is_proportional() {
        assert_eq!(validate_decoded_growth(0, MIB, 2 * MIB, 1, 1), Ok(MIB));
        assert_eq!(
            validate_decoded_growth(MIB, 1, 2 * MIB, 1, MIB + 1),
            Ok(MIB + 1)
        );
        assert_eq!(
            validate_decoded_growth(MIB, 1, 2 * MIB, 1, MIB),
            Err(HttpBodyReadError::ExpansionRatioExceeded)
        );
    }

    #[tokio::test]
    async fn compressed_bomb_above_floor_is_rejected_and_restores_charge() {
        let plain = vec![b'x'; 2 * MIB];
        let compressed = gzip(&plain);
        let (result, guard, pool) = invoke(
            compressed.clone(),
            Some("gzip"),
            compressed.len(),
            plain.len(),
            2,
        )
        .await;
        assert_eq!(
            result.unwrap_err(),
            HttpBodyReadError::ExpansionRatioExceeded
        );
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn unsupported_and_stacked_content_encoding_are_rejected_without_reflection() {
        let (result, guard, pool) = invoke(vec![1], Some("private-attacker-codec"), 1, 1, 1).await;
        let error = result.unwrap_err();
        assert_eq!(error, HttpBodyReadError::UnsupportedContentEncoding);
        assert!(!error.to_string().contains("private-attacker-codec"));
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);

        let (result, guard, pool) = invoke(vec![1], Some("gzip, br"), 1, 1, 1).await;
        assert_eq!(
            result.unwrap_err(),
            HttpBodyReadError::StackedContentEncoding
        );
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn mandatory_normalization_rejects_declared_and_delivered_trailers() {
        let max = 1024;
        let peak = compiled_peak(max, max);
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(peak, key());
        let mut headers = HeaderMap::new();
        headers.insert(TRAILER, HeaderValue::from_static("x-checksum"));
        let error = read_mandatory_request_body(
            &headers,
            Body::from("body"),
            limits(max, max),
            1,
            Instant::now() + Duration::from_secs(1),
            &guard,
        )
        .await
        .unwrap_err();
        assert_eq!(error, HttpBodyReadError::RequestTrailersUnsupported);
        assert_eq!(pool.global_charge(), 0);

        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(peak, key());
        let (mut sender, body) = Body::channel();
        let producer = tokio::spawn(async move {
            sender.send_data(Bytes::from_static(b"body")).await.unwrap();
            let mut trailers = HeaderMap::new();
            trailers.insert("x-checksum", HeaderValue::from_static("private"));
            sender.send_trailers(trailers).await.unwrap();
        });
        let error = read_mandatory_request_body(
            &HeaderMap::new(),
            body,
            limits(max, max),
            1,
            Instant::now() + Duration::from_secs(1),
            &guard,
        )
        .await
        .unwrap_err();
        producer.await.unwrap();
        assert_eq!(error, HttpBodyReadError::RequestTrailersUnsupported);
        assert!(!error.to_string().contains("private"));
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn timeout_and_read_error_restore_every_charge() {
        let max = 1024;
        let peak = compiled_peak(max, max);
        let headers = HeaderMap::new();

        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(peak, key());
        let pending = tokio_stream::pending::<Result<Bytes, std::io::Error>>();
        let error = read_mandatory_request_body(
            &headers,
            Body::wrap_stream(pending),
            limits(max, max),
            1,
            Instant::now() + Duration::from_millis(10),
            &guard,
        )
        .await
        .unwrap_err();
        assert_eq!(error, HttpBodyReadError::TimedOut);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);

        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(peak, key());
        let failed = tokio_stream::iter([Err::<Bytes, _>(std::io::Error::other("private"))]);
        let error = read_mandatory_request_body(
            &headers,
            Body::wrap_stream(failed),
            limits(max, max),
            1,
            Instant::now() + Duration::from_secs(1),
            &guard,
        )
        .await
        .unwrap_err();
        assert_eq!(error, HttpBodyReadError::ReadFailed);
        assert!(!error.to_string().contains("private"));
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn cancellation_restores_encoded_input_charge() {
        let max = 1024;
        let peak = compiled_peak(max, max);
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(peak, key());
        let observed_pool = pool.clone();
        let stream = tokio_stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(b"held"))])
            .chain(tokio_stream::pending());
        let task = tokio::spawn(async move {
            read_mandatory_request_body(
                &HeaderMap::new(),
                Body::wrap_stream(stream),
                limits(max, max),
                1,
                Instant::now() + Duration::from_secs(30),
                &guard,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while observed_pool.global_charge() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(observed_pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn http_decoder_workspace_is_bounded_and_charged() {
        let plain = b"workspace accounting".repeat(4096);
        let cases = [
            (
                "gzip",
                gzip(&plain),
                http_decoder_workspace_sizes(plain.len()).unwrap().deflate,
            ),
            (
                "deflate",
                raw_deflate(&plain),
                http_decoder_workspace_sizes(plain.len()).unwrap().deflate,
            ),
            (
                "br",
                brotli(&plain),
                http_decoder_workspace_sizes(plain.len()).unwrap().brotli,
            ),
            (
                "zstd",
                zstd(&plain),
                http_decoder_workspace_sizes(plain.len()).unwrap().zstd,
            ),
        ];
        for (encoding, encoded, workspace) in cases {
            let expected_peak = guarded_body_allocation_bytes(encoded.len()).unwrap()
                + guarded_body_allocation_bytes(plain.len()).unwrap()
                + guarded_body_allocation_bytes(HTTP_DECODER_OUTPUT_STAGING_BYTES).unwrap()
                + guarded_workspace_allocation_bytes(workspace).unwrap();
            let pool = WireBodyPool::new(expected_peak, expected_peak);
            let guard = pool.begin_for_test(expected_peak, key());
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_ENCODING, HeaderValue::from_str(encoding).unwrap());
            let body = read_mandatory_request_body(
                &headers,
                Body::from(encoded.clone()),
                limits(encoded.len(), plain.len()),
                128,
                Instant::now() + Duration::from_secs(5),
                &guard,
            )
            .await
            .unwrap_or_else(|error| panic!("encoding {encoding}: {error:?}"));
            assert_eq!(pool.peak_global_charge(), expected_peak, "{encoding}");
            drop(body);
            assert_eq!(guard.live_bytes(), 0);
            assert_eq!(pool.global_charge(), 0);
        }
    }

    #[tokio::test]
    async fn http_wire_body_guard_terminal_restoration_matrix() {
        let invalid_cases = [
            (
                Some("gzip"),
                vec![0u8; 32],
                HttpBodyReadError::InvalidContentEncoding,
            ),
            (
                Some("br"),
                vec![0xff; 32],
                HttpBodyReadError::DecoderWindowExceeded,
            ),
            (
                Some("zstd"),
                vec![0u8; 32],
                HttpBodyReadError::InvalidContentEncoding,
            ),
        ];
        for (encoding, encoded, expected) in invalid_cases {
            let (result, guard, pool) = invoke(encoded, encoding, 32, 32, 128).await;
            assert_eq!(result.unwrap_err(), expected, "{encoding:?}");
            assert_eq!(guard.live_bytes(), 0);
            assert_eq!(pool.global_charge(), 0);
        }
    }

    #[tokio::test]
    async fn gzip_header_work_is_capped_before_payload_decoding() {
        let mut encoded = vec![0x1f, 0x8b, 8, 0x08, 0, 0, 0, 0, 0, 255];
        encoded.extend(std::iter::repeat_n(b'a', GZIP_HEADER_MAX_BYTES));
        let limit = encoded.len();
        let (result, guard, pool) = invoke(encoded, Some("gzip"), limit, limit, 128).await;
        assert_eq!(
            result.unwrap_err(),
            HttpBodyReadError::InvalidContentEncoding
        );
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn every_codec_rejects_corruption_and_truncation() {
        let plain = b"codec corruption vector".repeat(512);
        let mut gzip_corrupt = gzip(&plain);
        *gzip_corrupt.last_mut().unwrap() ^= 1;
        let mut deflate_corrupt = zlib(&plain);
        *deflate_corrupt.last_mut().unwrap() ^= 1;
        let mut zstd_corrupt = zstd(&plain);
        zstd_corrupt[0] ^= 1;
        let cases = [
            ("gzip", gzip_corrupt),
            ("gzip", gzip(&plain)[..gzip(&plain).len() - 1].to_vec()),
            ("deflate", deflate_corrupt),
            (
                "deflate",
                raw_deflate(&plain)[..raw_deflate(&plain).len() - 1].to_vec(),
            ),
            ("br", brotli(&plain)[..brotli(&plain).len() - 1].to_vec()),
            ("zstd", zstd_corrupt),
            ("zstd", zstd(&plain)[..zstd(&plain).len() - 1].to_vec()),
        ];
        for (encoding, encoded) in cases {
            let (result, guard, pool) = invoke(
                encoded.clone(),
                Some(encoding),
                encoded.len(),
                plain.len(),
                128,
            )
            .await;
            assert!(
                matches!(
                    result,
                    Err(HttpBodyReadError::InvalidContentEncoding)
                        | Err(HttpBodyReadError::DecoderWindowExceeded)
                ),
                "encoding {encoding}: {result:?}"
            );
            assert_eq!(guard.live_bytes(), 0);
            assert_eq!(pool.global_charge(), 0);
        }
    }

    #[tokio::test]
    async fn codec_concatenation_semantics_are_explicit() {
        let first = b"first member";
        let second = b"second member";
        let expected = [&first[..], &second[..]].concat();
        for (encoding, encoded) in [
            ("gzip", [gzip(first), gzip(second)].concat()),
            ("zstd", [zstd(first), zstd(second)].concat()),
        ] {
            let decoded_limit = encoded.len().max(expected.len());
            let (result, guard, pool) = invoke(
                encoded.clone(),
                Some(encoding),
                encoded.len(),
                decoded_limit,
                128,
            )
            .await;
            assert_eq!(body_bytes(&result.unwrap()), expected, "{encoding}");
            drop(guard);
            assert_eq!(pool.global_charge(), 0);
        }

        for (encoding, encoded) in [
            ("deflate", [zlib(first), zlib(second)].concat()),
            ("br", [brotli(first), brotli(second)].concat()),
        ] {
            let decoded_limit = encoded.len().max(expected.len());
            let (result, guard, pool) = invoke(
                encoded.clone(),
                Some(encoding),
                encoded.len(),
                decoded_limit,
                128,
            )
            .await;
            assert_eq!(
                result.unwrap_err(),
                HttpBodyReadError::InvalidContentEncoding,
                "{encoding}"
            );
            assert_eq!(guard.live_bytes(), 0);
            assert_eq!(pool.global_charge(), 0);
        }
    }

    #[tokio::test]
    async fn decoded_limit_is_enforced_for_every_compressed_codec() {
        let plain = b"decoded limit vector".repeat(512);
        for (encoding, encoded) in [
            ("gzip", gzip(&plain)),
            ("deflate", zlib(&plain)),
            ("br", brotli(&plain)),
            ("zstd", zstd(&plain)),
        ] {
            let (result, guard, pool) = invoke(
                encoded.clone(),
                Some(encoding),
                encoded.len(),
                plain.len() - 1,
                128,
            )
            .await;
            assert_eq!(
                result.unwrap_err(),
                HttpBodyReadError::DecodedLimitExceeded,
                "{encoding}"
            );
            assert_eq!(guard.live_bytes(), 0);
            assert_eq!(pool.global_charge(), 0);
        }
    }

    #[tokio::test]
    async fn decode_deadline_is_checked_by_every_codec() {
        let plain = b"deadline vector".repeat(512);
        let cases = [
            (ContentEncoding::Gzip, gzip(&plain)),
            (ContentEncoding::Deflate, zlib(&plain)),
            (ContentEncoding::Brotli, brotli(&plain)),
            (ContentEncoding::Zstd, zstd(&plain)),
        ];
        for (encoding, bytes) in cases {
            let sizes = http_decoder_workspace_sizes(plain.len()).unwrap();
            let peak = compiled_peak(bytes.len(), plain.len());
            let pool = WireBodyPool::new(peak, peak);
            let guard = pool.begin_for_test(peak, key());
            let mut encoded = guard.buffer();
            encoded.try_extend_from_slice(&bytes).unwrap();
            let encoded = encoded.finish();
            let result = match encoding {
                ContentEncoding::Gzip => {
                    decode_gzip(
                        &encoded,
                        &guard,
                        sizes.deflate,
                        plain.len(),
                        128,
                        Instant::now(),
                    )
                    .await
                }
                ContentEncoding::Deflate => {
                    decode_deflate(
                        &encoded,
                        &guard,
                        sizes.deflate,
                        plain.len(),
                        128,
                        Instant::now(),
                    )
                    .await
                }
                ContentEncoding::Brotli => {
                    decode_brotli(
                        &encoded,
                        &guard,
                        sizes.brotli,
                        plain.len(),
                        128,
                        Instant::now(),
                    )
                    .await
                }
                ContentEncoding::Zstd => {
                    decode_zstd(
                        &encoded,
                        &guard,
                        sizes.zstd,
                        plain.len(),
                        128,
                        Instant::now(),
                    )
                    .await
                }
                ContentEncoding::Identity => unreachable!(),
            };
            assert_eq!(result.unwrap_err(), HttpBodyReadError::TimedOut);
            drop(encoded);
            assert_eq!(guard.live_bytes(), 0);
            assert_eq!(pool.global_charge(), 0);
        }
    }
}
