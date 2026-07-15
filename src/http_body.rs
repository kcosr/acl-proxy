use std::ffi::c_void;
use std::future::Future;
use std::mem::{size_of, MaybeUninit};
use std::pin::pin;
use std::ptr;
use std::task::{Context, Poll};

#[cfg(test)]
use bytes::Buf;
use http::header::{HeaderMap, CONTENT_ENCODING, TRAILER};
use http_access_runtime::{RuntimeError, RuntimeRequest};
use http_access_types::{BodyFraming, BodyObservationState};
#[cfg(test)]
use hyper::body::HttpBody;
use miniz_oxide::inflate::stream::{inflate, InflateState};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};
use tokio::time::Instant;

use crate::config::compiler::HttpBodyReadLimits;
use crate::observation::{
    CaptureBody, CaptureBodyBuilder, CaptureOperation, CaptureScratch, CaptureWorkspace,
    CaptureWorkspaceAllocation,
};
use crate::redaction::ProfileHandle;
use crate::safety::allocation::{
    AllocationAuthority, StableBody, StableBodyBuilder, StableScratch, StableWorkspace,
    StableWorkspaceAllocation,
};
use crate::safety::wire_body::{
    GuardedBodyBuilder, GuardedBodySegments, GuardedScratch, GuardedWorkspaceAllocation,
    WireAllocationAuthority, WireBodyBufferError, MAX_BUFFER_GROWTH_BYTES,
};
use crate::safety::{GuardedBody, HttpWireBodyGuard};

pub(crate) const HTTP_DECODER_OUTPUT_STAGING_BYTES: usize = 64 * 1024;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const BROTLI_MAX_WINDOW_BYTES: usize = 16 * MIB;
const BROTLI_RING_WRITE_AHEAD_SLACK_BYTES: usize = 542;
const BROTLI_FIXED_WORKSPACE_BYTES: usize = 4 * MIB;
#[cfg(test)]
const BROTLI_MAX_TREE_COUNT: usize = 256;
#[cfg(test)]
const BROTLI_HUFFMAN_CODE_BYTES: usize = 4;
#[cfg(test)]
const BROTLI_HUFFMAN_POINTER_BYTES: usize = size_of::<usize>();
#[cfg(test)]
const BROTLI_HUFFMAN_ALLOCATOR_OVERHEAD_ENTRIES: usize = 376;
#[cfg(test)]
const BROTLI_LITERAL_HUFFMAN_ALLOCATED_ENTRIES: usize =
    256 + BROTLI_HUFFMAN_ALLOCATOR_OVERHEAD_ENTRIES;
#[cfg(test)]
const BROTLI_COMMAND_HUFFMAN_ALLOCATED_ENTRIES: usize =
    704 + BROTLI_HUFFMAN_ALLOCATOR_OVERHEAD_ENTRIES;
#[cfg(test)]
const BROTLI_DISTANCE_HUFFMAN_ALLOCATED_ENTRIES: usize =
    520 + BROTLI_HUFFMAN_ALLOCATOR_OVERHEAD_ENTRIES;
#[cfg(test)]
const BROTLI_DISTANCE_HUFFMAN_BUDGET_ENTRIES: usize = 920;
#[cfg(test)]
const BROTLI_DECODER_STATE_BUDGET_BYTES: usize = 8 * KIB;
#[cfg(test)]
const BROTLI_SHARED_DICTIONARY_BUDGET_BYTES: usize = 2 * KIB;
#[cfg(test)]
const BROTLI_BLOCK_TREE_BUDGET_BYTES: usize = 16 * KIB;
#[cfg(test)]
const BROTLI_CONTEXT_BUDGET_BYTES: usize = 18 * KIB;
#[cfg(test)]
const BROTLI_ARENA_ALLOCATION_COUNT: usize = 10;
const ZSTD_STANDARD_WINDOW_BYTES: usize = 8 * MIB;
const ZSTD_LIBRARY_WINDOW_LOG_MAX: u32 = if usize::BITS == 32 {
    zstd_sys::ZSTD_WINDOWLOG_MAX_32
} else {
    zstd_sys::ZSTD_WINDOWLOG_MAX_64
};
const CONTENT_DECODING_FLOOR_BYTES: usize = MIB;
const ARENA_ALIGNMENT: usize = 16;
const ZSTD_FRAME_HEADER_MAX_BYTES: usize = zstd_sys::ZSTD_FRAMEHEADERSIZE_MAX as usize;
const WEBSOCKET_DEFLATE_SCRATCH_BYTES: usize = 64 * 1024;
const PERMESSAGE_DEFLATE_TAIL: &[u8] = &[0x00, 0x00, 0xff, 0xff];

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

pub(crate) fn http_decoder_workspace_sizes() -> Option<HttpDecoderWorkspaceSizes> {
    let brotli = BROTLI_FIXED_WORKSPACE_BYTES
        .checked_add(BROTLI_MAX_WINDOW_BYTES)?
        .checked_add(BROTLI_RING_WRITE_AHEAD_SLACK_BYTES)?;
    let zstd_window = zstd_window_limit()?;
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

#[cfg(test)]
const fn brotli_huffman_group_budget(maximum_table_entries: usize) -> usize {
    BROTLI_MAX_TREE_COUNT * maximum_table_entries * BROTLI_HUFFMAN_CODE_BYTES
        + BROTLI_MAX_TREE_COUNT * BROTLI_HUFFMAN_POINTER_BYTES
}

#[cfg(test)]
const fn brotli_fixed_workspace_required_bytes() -> usize {
    size_of::<BrotliArenaState>()
        + size_of::<BrotliArenaBlock>()
        + BROTLI_DECODER_STATE_BUDGET_BYTES
        + BROTLI_SHARED_DICTIONARY_BUDGET_BYTES
        + BROTLI_BLOCK_TREE_BUDGET_BYTES
        + BROTLI_CONTEXT_BUDGET_BYTES
        + brotli_huffman_group_budget(BROTLI_LITERAL_HUFFMAN_ALLOCATED_ENTRIES)
        + brotli_huffman_group_budget(BROTLI_COMMAND_HUFFMAN_ALLOCATED_ENTRIES)
        + brotli_huffman_group_budget(BROTLI_DISTANCE_HUFFMAN_BUDGET_ENTRIES)
        + BROTLI_ARENA_ALLOCATION_COUNT * size_of::<BrotliArenaBlock>()
}

pub(crate) fn zstd_window_limit() -> Option<usize> {
    let library = 1usize.checked_shl(ZSTD_LIBRARY_WINDOW_LOG_MAX)?;
    (ZSTD_STANDARD_WINDOW_BYTES <= library).then_some(ZSTD_STANDARD_WINDOW_BYTES)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CaptureContentEncoding {
    Identity,
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

type ContentEncoding = CaptureContentEncoding;

trait DecodeContext {
    type Authority: AllocationAuthority + Send + Sync;

    fn validate_body(&self, body: &StableBody<Self::Authority>) -> Result<(), HttpBodyReadError>;
    fn body_buffer(&self) -> StableBodyBuilder<Self::Authority>;
    fn scratch(&self) -> Result<StableScratch<Self::Authority>, HttpBodyReadError>;
    fn workspace_allocation(
        &self,
        bytes: usize,
    ) -> Result<StableWorkspaceAllocation<Self::Authority>, HttpBodyReadError>;
}

impl DecodeContext for HttpWireBodyGuard {
    type Authority = WireAllocationAuthority;

    fn validate_body(&self, body: &GuardedBody) -> Result<(), HttpBodyReadError> {
        HttpWireBodyGuard::validate_body(self, body).map_err(Into::into)
    }

    fn body_buffer(&self) -> GuardedBodyBuilder {
        self.buffer()
    }

    fn scratch(&self) -> Result<GuardedScratch, HttpBodyReadError> {
        self.stream_scratch().map_err(Into::into)
    }

    fn workspace_allocation(
        &self,
        bytes: usize,
    ) -> Result<GuardedWorkspaceAllocation, HttpBodyReadError> {
        self.codec_workspace_allocation(bytes).map_err(Into::into)
    }
}

impl DecodeContext for CaptureOperation {
    type Authority = crate::observation::CaptureAllocationAuthority;

    fn validate_body(&self, body: &CaptureBody) -> Result<(), HttpBodyReadError> {
        CaptureOperation::validate_body(self, body)
            .map_err(|_| HttpBodyReadError::ResourceExhausted)
    }

    fn body_buffer(&self) -> CaptureBodyBuilder {
        self.body_buffer()
    }

    fn scratch(&self) -> Result<CaptureScratch, HttpBodyReadError> {
        self.scratch()
            .map_err(|_| HttpBodyReadError::ResourceExhausted)
    }

    fn workspace_allocation(
        &self,
        bytes: usize,
    ) -> Result<CaptureWorkspaceAllocation, HttpBodyReadError> {
        self.workspace_allocation(bytes)
            .map_err(|_| HttpBodyReadError::ResourceExhausted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CanonicalContentEncoding {
    Identity,
}

pub(crate) struct GuardedRequestBody {
    encoded_len: usize,
    body: GuardedBody,
}

impl GuardedRequestBody {
    #[cfg(test)]
    pub(crate) fn content_encoding(&self) -> CanonicalContentEncoding {
        CanonicalContentEncoding::Identity
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.body.len()
    }

    pub(crate) fn encoded_len(&self) -> usize {
        self.encoded_len
    }

    pub(crate) fn into_guarded_body(self) -> GuardedBody {
        self.body
    }
}

impl std::fmt::Debug for GuardedRequestBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuardedRequestBody")
            .field("encoded_len", &self.encoded_len)
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

/// Sanitized capture-only outcome. Every variant omits the observed payload;
/// none is allowed to affect the wire request or response.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum CaptureHttpDecodeError {
    #[error("capture payload content encoding is unsupported")]
    UnsupportedContentEncoding,
    #[error("capture payload uses stacked content encodings")]
    StackedContentEncoding,
    #[error("capture payload exceeds the encoded profile limit")]
    EncodedLimitExceeded,
    #[error("capture payload exceeds the decoded profile limit")]
    DecodedLimitExceeded,
    #[error("capture payload exceeds the content-decoding expansion ratio")]
    ExpansionRatioExceeded,
    #[error("capture payload content encoding is invalid")]
    InvalidContentEncoding,
    #[error("capture payload content-encoding window is too large")]
    DecoderWindowExceeded,
    #[error("capture payload resources are exhausted")]
    ResourceExhausted,
}

impl From<HttpBodyReadError> for CaptureHttpDecodeError {
    fn from(error: HttpBodyReadError) -> Self {
        match error {
            HttpBodyReadError::UnsupportedContentEncoding => Self::UnsupportedContentEncoding,
            HttpBodyReadError::StackedContentEncoding => Self::StackedContentEncoding,
            HttpBodyReadError::EncodedLimitExceeded => Self::EncodedLimitExceeded,
            HttpBodyReadError::DecodedLimitExceeded => Self::DecodedLimitExceeded,
            HttpBodyReadError::ExpansionRatioExceeded => Self::ExpansionRatioExceeded,
            HttpBodyReadError::InvalidContentEncoding => Self::InvalidContentEncoding,
            HttpBodyReadError::DecoderWindowExceeded => Self::DecoderWindowExceeded,
            HttpBodyReadError::ReadFailed
            | HttpBodyReadError::RequestTrailersUnsupported
            | HttpBodyReadError::TimedOut
            | HttpBodyReadError::ResourceExhausted => Self::ResourceExhausted,
        }
    }
}

impl From<WireBodyBufferError> for HttpBodyReadError {
    fn from(_: WireBodyBufferError) -> Self {
        Self::ResourceExhausted
    }
}

fn check_deadline(deadline: Instant) -> Result<(), HttpBodyReadError> {
    if Instant::now() >= deadline {
        Err(HttpBodyReadError::TimedOut)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct DecodeControl {
    deadline: Option<Instant>,
}

impl DecodeControl {
    fn wire(deadline: Instant) -> Self {
        Self {
            deadline: Some(deadline),
        }
    }

    fn capture() -> Self {
        Self { deadline: None }
    }

    fn check(self) -> Result<(), HttpBodyReadError> {
        self.deadline.map_or(Ok(()), check_deadline)
    }

    async fn checkpoint(self) -> Result<(), HttpBodyReadError> {
        self.check()?;
        if self.deadline.is_some() {
            tokio::task::yield_now().await;
        } else {
            std::thread::yield_now();
        }
        self.check()
    }
}

async fn cooperative_checkpoint(deadline: Instant) -> Result<(), HttpBodyReadError> {
    check_deadline(deadline)?;
    tokio::task::yield_now().await;
    check_deadline(deadline)
}

async fn allocate_codec_workspace<C: DecodeContext>(
    guard: &C,
    bytes: usize,
    control: DecodeControl,
) -> Result<StableWorkspace<C::Authority>, HttpBodyReadError> {
    control.check()?;
    let mut allocation = guard.workspace_allocation(bytes)?;
    while !allocation.is_initialized() {
        control.check()?;
        allocation.initialize_next(MAX_BUFFER_GROWTH_BYTES);
        control.checkpoint().await?;
    }
    Ok(allocation.finish())
}

#[cfg(test)]
async fn read_mandatory_request_body<B>(
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
        check_deadline(deadline)?;
        let next = tokio::time::timeout_at(deadline, body.data())
            .await
            .map_err(|_| HttpBodyReadError::TimedOut)?;
        let Some(chunk) = next else {
            break;
        };
        let mut chunk = chunk.map_err(|_| HttpBodyReadError::ReadFailed)?;
        if !chunk.has_remaining() {
            cooperative_checkpoint(deadline).await?;
            continue;
        }
        while chunk.has_remaining() {
            check_deadline(deadline)?;
            let available = chunk.chunk();
            let bytes = &available[..available.len().min(MAX_BUFFER_GROWTH_BYTES)];
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
            cooperative_checkpoint(deadline).await?;
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
    let encoded_len = encoded.len();
    let decoded = decode_complete_http_body(
        encoding,
        encoded,
        guard,
        limits.max_decoded_bytes(),
        max_expansion_ratio,
        DecodeControl::wire(deadline),
    )
    .await?;
    Ok(GuardedRequestBody {
        encoded_len,
        body: decoded,
    })
}

pub(crate) async fn read_mandatory_runtime_request_body(
    request: &mut RuntimeRequest,
    limits: HttpBodyReadLimits,
    max_expansion_ratio: usize,
    deadline: Instant,
    guard: &HttpWireBodyGuard,
) -> Result<GuardedRequestBody, HttpBodyReadError> {
    if let BodyFraming::ContentLength(length) = request.facts().body().framing() {
        if usize::try_from(length).map_or(true, |length| length > limits.max_encoded_bytes()) {
            return Err(HttpBodyReadError::EncodedLimitExceeded);
        }
    }
    if request
        .body_observation()
        .map_err(map_runtime_body_error)?
        .state()
        != BodyObservationState::Unobserved
    {
        return Err(HttpBodyReadError::ReadFailed);
    }
    let headers = crate::proxy::facts::product_headers(request.facts().headers())
        .map_err(|_| HttpBodyReadError::ReadFailed)?;
    let encoding = parse_content_encoding(&headers)?;
    if headers.contains_key(TRAILER) {
        return Err(HttpBodyReadError::RequestTrailersUnsupported);
    }

    let mut encoded = guard.buffer();
    loop {
        check_deadline(deadline)?;
        let next = tokio::time::timeout_at(
            deadline,
            std::future::poll_fn(|context| request.poll_body_chunk(context)),
        )
        .await
        .map_err(|_| HttpBodyReadError::TimedOut)?
        .map_err(map_runtime_body_error)?;
        let Some(chunk) = next else {
            break;
        };
        for bytes in chunk.as_bytes().chunks(MAX_BUFFER_GROWTH_BYTES) {
            check_deadline(deadline)?;
            let next_len = encoded
                .len()
                .checked_add(bytes.len())
                .ok_or(HttpBodyReadError::EncodedLimitExceeded)?;
            if next_len > limits.max_encoded_bytes() {
                return Err(HttpBodyReadError::EncodedLimitExceeded);
            }
            encoded.try_extend_from_slice(bytes)?;
            cooperative_checkpoint(deadline).await?;
        }
    }

    let trailers = tokio::time::timeout_at(
        deadline,
        std::future::poll_fn(|context| request.poll_trailers(context)),
    )
    .await
    .map_err(|_| HttpBodyReadError::TimedOut)?
    .map_err(map_runtime_trailer_error)?;
    if trailers.is_some_and(|trailers| trailers.iter().next().is_some()) {
        return Err(HttpBodyReadError::RequestTrailersUnsupported);
    }

    let encoded = encoded.finish();
    let encoded_len = encoded.len();
    let decoded = decode_complete_http_body(
        encoding,
        encoded,
        guard,
        limits.max_decoded_bytes(),
        max_expansion_ratio,
        DecodeControl::wire(deadline),
    )
    .await?;
    Ok(GuardedRequestBody {
        encoded_len,
        body: decoded,
    })
}

fn map_runtime_body_error(error: RuntimeError) -> HttpBodyReadError {
    match error {
        RuntimeError::DeadlineExceeded => HttpBodyReadError::TimedOut,
        RuntimeError::LimitExceeded => HttpBodyReadError::EncodedLimitExceeded,
        _ => HttpBodyReadError::ReadFailed,
    }
}

fn map_runtime_trailer_error(error: RuntimeError) -> HttpBodyReadError {
    match error {
        RuntimeError::DeadlineExceeded => HttpBodyReadError::TimedOut,
        RuntimeError::LimitExceeded => HttpBodyReadError::RequestTrailersUnsupported,
        _ => HttpBodyReadError::ReadFailed,
    }
}

pub(crate) fn decode_capture_http_body(
    encoding: CaptureContentEncoding,
    encoded: CaptureBody,
    operation: &CaptureOperation,
    profile: &ProfileHandle,
    max_expansion_ratio: usize,
) -> Result<CaptureBody, CaptureHttpDecodeError> {
    poll_capture_decode(decode_capture_http_body_inner(
        encoding,
        encoded,
        operation,
        profile,
        max_expansion_ratio,
    ))
}

async fn decode_capture_http_body_inner(
    encoding: CaptureContentEncoding,
    encoded: CaptureBody,
    operation: &CaptureOperation,
    profile: &ProfileHandle,
    max_expansion_ratio: usize,
) -> Result<CaptureBody, CaptureHttpDecodeError> {
    operation
        .validate_body(&encoded)
        .map_err(|_| CaptureHttpDecodeError::ResourceExhausted)?;
    let limits = profile.limits();
    if encoded.len() > limits.max_body_bytes {
        return Err(CaptureHttpDecodeError::EncodedLimitExceeded);
    }
    decode_complete_http_body(
        encoding,
        encoded,
        operation,
        limits.max_decoded_body_bytes,
        max_expansion_ratio,
        DecodeControl::capture(),
    )
    .await
    .map_err(Into::into)
}

pub(crate) fn parse_capture_content_encoding(
    headers: &HeaderMap,
) -> Result<CaptureContentEncoding, CaptureHttpDecodeError> {
    parse_content_encoding(headers).map_err(Into::into)
}

pub(crate) fn decode_capture_websocket_permessage_deflate(
    encoded: CaptureBody,
    operation: &CaptureOperation,
    max_message_bytes: usize,
) -> Result<CaptureBody, CaptureHttpDecodeError> {
    poll_capture_decode(decode_capture_websocket_permessage_deflate_inner(
        encoded,
        operation,
        max_message_bytes,
    ))
}

async fn decode_capture_websocket_permessage_deflate_inner(
    encoded: CaptureBody,
    operation: &CaptureOperation,
    max_message_bytes: usize,
) -> Result<CaptureBody, CaptureHttpDecodeError> {
    operation
        .validate_body(&encoded)
        .map_err(|_| CaptureHttpDecodeError::ResourceExhausted)?;
    if encoded.len() > max_message_bytes {
        return Err(CaptureHttpDecodeError::EncodedLimitExceeded);
    }

    let control = DecodeControl::capture();
    let mut session = CaptureWebSocketInflateSession::new(operation, control).await?;
    let mut cursor = EncodedCursor::with_suffix(&encoded, PERMESSAGE_DEFLATE_TAIL)?;
    let mut output = operation.body_buffer();
    let mut decoded = 0usize;
    loop {
        control.check()?;
        let (result, output_bytes, output_capacity) = session.inflate(cursor.current());
        cursor.advance(result.bytes_consumed)?;
        decoded = decoded
            .checked_add(output_bytes.len())
            .filter(|decoded| *decoded <= max_message_bytes)
            .ok_or(CaptureHttpDecodeError::DecodedLimitExceeded)?;
        output
            .try_extend_from_slice(output_bytes)
            .map_err(|_| CaptureHttpDecodeError::ResourceExhausted)?;

        match result.status {
            Ok(MZStatus::StreamEnd) if cursor.is_end() => break,
            Ok(MZStatus::Ok) if cursor.is_end() && output_bytes.len() < output_capacity => break,
            Ok(MZStatus::Ok) => {
                if result.bytes_consumed == 0 && output_bytes.is_empty() {
                    return Err(CaptureHttpDecodeError::InvalidContentEncoding);
                }
            }
            Ok(MZStatus::NeedDict) | Err(_) => {
                return Err(CaptureHttpDecodeError::InvalidContentEncoding)
            }
            Ok(MZStatus::StreamEnd) => return Err(CaptureHttpDecodeError::InvalidContentEncoding),
        }
        control.checkpoint().await?;
    }
    drop(session);
    drop(encoded);
    Ok(output.finish())
}

fn poll_capture_decode<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(std::task::Waker::noop());
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

struct CaptureWebSocketInflateSession {
    output_offset: usize,
    workspace: CaptureWorkspace,
}

impl CaptureWebSocketInflateSession {
    async fn new(
        operation: &CaptureOperation,
        control: DecodeControl,
    ) -> Result<Self, CaptureHttpDecodeError> {
        let mut workspace =
            allocate_codec_workspace(operation, WEBSOCKET_DEFLATE_SCRATCH_BYTES, control)
                .await
                .map_err(CaptureHttpDecodeError::from)?;
        let output_offset = align_up(size_of::<InflateState>(), std::mem::align_of::<u128>())
            .filter(|offset| *offset < workspace.len())
            .ok_or(CaptureHttpDecodeError::ResourceExhausted)?;
        if !(workspace.as_mut_ptr() as usize).is_multiple_of(std::mem::align_of::<InflateState>()) {
            return Err(CaptureHttpDecodeError::ResourceExhausted);
        }
        let (state_bytes, _) = workspace.as_mut_bytes().split_at_mut(output_offset);
        let state = state_bytes.as_mut_ptr().cast::<InflateState>();
        // The aligned state region is large enough for InflateState and remains
        // exclusively owned by this session until Drop destroys it.
        unsafe { state.write(InflateState::new(DataFormat::Raw)) };
        Ok(Self {
            output_offset,
            workspace,
        })
    }

    fn inflate(&mut self, input: &[u8]) -> (miniz_oxide::StreamResult, &[u8], usize) {
        let (state_bytes, output) = self
            .workspace
            .as_mut_bytes()
            .split_at_mut(self.output_offset);
        let state = state_bytes.as_mut_ptr().cast::<InflateState>();
        let capacity = output.len();
        // split_at_mut proves that the live state and output ranges are disjoint.
        let result = inflate(unsafe { &mut *state }, input, output, MZFlush::Sync);
        (result, &output[..result.bytes_written], capacity)
    }
}

impl Drop for CaptureWebSocketInflateSession {
    fn drop(&mut self) {
        let (state_bytes, _) = self
            .workspace
            .as_mut_bytes()
            .split_at_mut(self.output_offset);
        unsafe { ptr::drop_in_place(state_bytes.as_mut_ptr().cast::<InflateState>()) };
        self.workspace.reset();
    }
}

async fn decode_complete_http_body<C: DecodeContext>(
    encoding: ContentEncoding,
    encoded: StableBody<C::Authority>,
    context: &C,
    max_decoded: usize,
    max_expansion_ratio: usize,
    control: DecodeControl,
) -> Result<StableBody<C::Authority>, HttpBodyReadError> {
    context.validate_body(&encoded)?;
    if encoding == ContentEncoding::Identity {
        if encoded.len() > max_decoded {
            return Err(HttpBodyReadError::DecodedLimitExceeded);
        }
        return Ok(encoded);
    }

    let workspace_sizes =
        http_decoder_workspace_sizes().ok_or(HttpBodyReadError::ResourceExhausted)?;
    let decoded = match encoding {
        ContentEncoding::Identity => unreachable!("identity returned above"),
        ContentEncoding::Gzip => {
            decode_gzip(
                &encoded,
                context,
                workspace_sizes.deflate,
                max_decoded,
                max_expansion_ratio,
                control,
            )
            .await?
        }
        ContentEncoding::Deflate => {
            decode_deflate(
                &encoded,
                context,
                workspace_sizes.deflate,
                max_decoded,
                max_expansion_ratio,
                control,
            )
            .await?
        }
        ContentEncoding::Brotli => {
            decode_brotli(
                &encoded,
                context,
                workspace_sizes.brotli,
                max_decoded,
                max_expansion_ratio,
                control,
            )
            .await?
        }
        ContentEncoding::Zstd => {
            decode_zstd(
                &encoded,
                context,
                workspace_sizes.zstd,
                max_decoded,
                max_expansion_ratio,
                control,
            )
            .await?
        }
    };
    drop(encoded);
    Ok(decoded)
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

#[derive(Clone)]
struct EncodedCursor<'a> {
    segments: GuardedBodySegments<'a>,
    current: &'a [u8],
    offset: usize,
    consumed: usize,
    total: usize,
    suffix: Option<&'static [u8]>,
}

impl<'a> EncodedCursor<'a> {
    fn new<A: AllocationAuthority>(body: &'a StableBody<A>) -> Self {
        let mut segments = body.segments();
        let current = segments.next().unwrap_or_default();
        Self {
            segments,
            current,
            offset: 0,
            consumed: 0,
            total: body.len(),
            suffix: None,
        }
    }

    fn with_suffix<A: AllocationAuthority>(
        body: &'a StableBody<A>,
        suffix: &'static [u8],
    ) -> Result<Self, HttpBodyReadError> {
        let mut cursor = Self::new(body);
        cursor.total = cursor
            .total
            .checked_add(suffix.len())
            .ok_or(HttpBodyReadError::InvalidContentEncoding)?;
        cursor.suffix = Some(suffix);
        if cursor.current.is_empty() {
            cursor.current = cursor.suffix.take().unwrap_or_default();
        }
        Ok(cursor)
    }

    fn current(&self) -> &'a [u8] {
        &self.current[self.offset..]
    }

    fn advance(&mut self, mut bytes: usize) -> Result<(), HttpBodyReadError> {
        while bytes != 0 {
            let available = self.current.len().saturating_sub(self.offset);
            if available == 0 {
                self.current = self
                    .segments
                    .next()
                    .or_else(|| self.suffix.take())
                    .unwrap_or_default();
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
            self.current = self
                .segments
                .next()
                .or_else(|| self.suffix.take())
                .unwrap_or_default();
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

    fn copy_prefix(&self, destination: &mut [u8]) -> usize {
        let mut cursor = self.clone();
        let mut written = 0usize;
        while written < destination.len() && !cursor.is_end() {
            let current = cursor.current();
            if current.is_empty() {
                break;
            }
            let copied = current.len().min(destination.len() - written);
            destination[written..written + copied].copy_from_slice(&current[..copied]);
            if cursor.advance(copied).is_err() {
                break;
            }
            written += copied;
        }
        written
    }
}

struct DecodeProgress {
    decoded: usize,
    max_decoded: usize,
    ratio: usize,
    control: DecodeControl,
}

impl DecodeProgress {
    async fn emit<A: AllocationAuthority>(
        &mut self,
        output: &[u8],
        encoded_consumed: usize,
        builder: &mut StableBodyBuilder<A>,
    ) -> Result<(), HttpBodyReadError> {
        if output.is_empty() {
            return self.control.checkpoint().await;
        }
        let next = validate_decoded_growth(
            self.decoded,
            output.len(),
            self.max_decoded,
            self.ratio,
            encoded_consumed,
        )?;
        builder
            .try_extend_from_slice(output)
            .map_err(|_| HttpBodyReadError::ResourceExhausted)?;
        self.decoded = next;
        self.control.checkpoint().await
    }

    fn check_deadline(&self) -> Result<(), HttpBodyReadError> {
        self.control.check()
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

struct InflateSession<A: AllocationAuthority> {
    state: *mut InflateState,
    workspace: StableWorkspace<A>,
}

// The pointer targets this session's heap-stable guarded workspace. Decoder
// access is synchronous and exclusive even if the owning future moves threads.
unsafe impl<A: AllocationAuthority + Send> Send for InflateSession<A> {}

impl<A: AllocationAuthority + Send + Sync> InflateSession<A> {
    async fn new<C: DecodeContext<Authority = A>>(
        guard: &C,
        workspace_bytes: usize,
        format: DataFormat,
        control: DecodeControl,
    ) -> Result<Self, HttpBodyReadError> {
        let mut workspace = allocate_codec_workspace(guard, workspace_bytes, control).await?;
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

    fn reset(&mut self, format: DataFormat) {
        self.state().reset(format);
    }
}

impl<A: AllocationAuthority> Drop for InflateSession<A> {
    fn drop(&mut self) {
        // InflateState owns no external allocation. Drop it before the backing
        // workspace is wiped and released.
        unsafe { ptr::drop_in_place(self.state) };
        self.workspace.reset();
    }
}

async fn inflate_cursor<A: AllocationAuthority + Send + Sync>(
    cursor: &mut EncodedCursor<'_>,
    session: &mut InflateSession<A>,
    staging: &mut StableScratch<A>,
    output: &mut StableBodyBuilder<A>,
    progress: &mut DecodeProgress,
    mut crc: Option<&mut crc32fast::Hasher>,
) -> Result<(), HttpBodyReadError> {
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

async fn decode_deflate<C: DecodeContext>(
    encoded: &StableBody<C::Authority>,
    guard: &C,
    workspace_bytes: usize,
    max_decoded: usize,
    ratio: usize,
    control: DecodeControl,
) -> Result<StableBody<C::Authority>, HttpBodyReadError> {
    match decode_deflate_attempt(
        encoded,
        guard,
        workspace_bytes,
        max_decoded,
        ratio,
        control,
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
                control,
                DataFormat::Raw,
            )
            .await
        }
        result => result,
    }
}

async fn decode_deflate_attempt<C: DecodeContext>(
    encoded: &StableBody<C::Authority>,
    guard: &C,
    workspace_bytes: usize,
    max_decoded: usize,
    ratio: usize,
    control: DecodeControl,
    format: DataFormat,
) -> Result<StableBody<C::Authority>, HttpBodyReadError> {
    control.check()?;
    let mut cursor = EncodedCursor::new(encoded);
    let mut output = guard.body_buffer();
    let mut progress = DecodeProgress {
        decoded: 0,
        max_decoded,
        ratio,
        control,
    };
    let mut session = InflateSession::new(guard, workspace_bytes, format, control).await?;
    control.check()?;
    let mut staging = guard.scratch()?;
    inflate_cursor(
        &mut cursor,
        &mut session,
        &mut staging,
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

async fn decode_gzip<C: DecodeContext>(
    encoded: &StableBody<C::Authority>,
    guard: &C,
    workspace_bytes: usize,
    max_decoded: usize,
    ratio: usize,
    control: DecodeControl,
) -> Result<StableBody<C::Authority>, HttpBodyReadError> {
    let mut cursor = EncodedCursor::new(encoded);
    let mut output = guard.body_buffer();
    let mut progress = DecodeProgress {
        decoded: 0,
        max_decoded,
        ratio,
        control,
    };
    control.check()?;
    let mut session = InflateSession::new(guard, workspace_bytes, DataFormat::Raw, control).await?;
    control.check()?;
    let mut staging = guard.scratch()?;
    let mut members = 0usize;
    while !cursor.is_end() {
        progress.check_deadline()?;
        parse_gzip_header(&mut cursor, control).await?;
        let member_start = progress.decoded;
        let mut crc = crc32fast::Hasher::new();
        session.reset(DataFormat::Raw);
        inflate_cursor(
            &mut cursor,
            &mut session,
            &mut staging,
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
        control.checkpoint().await?;
    }
    if members == 0 {
        return Err(HttpBodyReadError::InvalidContentEncoding);
    }
    Ok(output.finish())
}

async fn parse_gzip_header(
    cursor: &mut EncodedCursor<'_>,
    control: DecodeControl,
) -> Result<(), HttpBodyReadError> {
    control.check()?;
    let mut header_crc = crc32fast::Hasher::new();
    let id1 = read_gzip_header_byte(cursor, &mut header_crc)?;
    let id2 = read_gzip_header_byte(cursor, &mut header_crc)?;
    let method = read_gzip_header_byte(cursor, &mut header_crc)?;
    let flags = read_gzip_header_byte(cursor, &mut header_crc)?;
    if id1 != 0x1f || id2 != 0x8b || method != 8 || flags & 0xe0 != 0 {
        return Err(HttpBodyReadError::InvalidContentEncoding);
    }
    for _ in 0..6 {
        read_gzip_header_byte(cursor, &mut header_crc)?;
    }
    if flags & 0x04 != 0 {
        let low = read_gzip_header_byte(cursor, &mut header_crc)?;
        let high = read_gzip_header_byte(cursor, &mut header_crc)?;
        let length = u16::from_le_bytes([low, high]) as usize;
        read_gzip_header_bytes(cursor, &mut header_crc, length, control).await?;
    }
    for mask in [0x08, 0x10] {
        if flags & mask != 0 {
            read_zero_terminated_gzip_header_field(cursor, &mut header_crc, control).await?;
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
) -> Result<u8, HttpBodyReadError> {
    let byte = cursor.read_byte()?;
    crc.update(&[byte]);
    Ok(byte)
}

async fn read_gzip_header_bytes(
    cursor: &mut EncodedCursor<'_>,
    crc: &mut crc32fast::Hasher,
    mut remaining: usize,
    control: DecodeControl,
) -> Result<(), HttpBodyReadError> {
    while remaining != 0 {
        control.check()?;
        let current = cursor.current();
        if current.is_empty() {
            return Err(HttpBodyReadError::InvalidContentEncoding);
        }
        let consumed = current.len().min(remaining).min(MAX_BUFFER_GROWTH_BYTES);
        crc.update(&current[..consumed]);
        cursor.advance(consumed)?;
        remaining -= consumed;
        control.checkpoint().await?;
    }
    Ok(())
}

async fn read_zero_terminated_gzip_header_field(
    cursor: &mut EncodedCursor<'_>,
    crc: &mut crc32fast::Hasher,
    control: DecodeControl,
) -> Result<(), HttpBodyReadError> {
    loop {
        control.check()?;
        let current = cursor.current();
        if current.is_empty() {
            return Err(HttpBodyReadError::InvalidContentEncoding);
        }
        let bounded = &current[..current.len().min(MAX_BUFFER_GROWTH_BYTES)];
        let consumed = bounded
            .iter()
            .position(|byte| *byte == 0)
            .map_or(bounded.len(), |index| index + 1);
        let terminated = bounded[consumed - 1] == 0;
        crc.update(&bounded[..consumed]);
        cursor.advance(consumed)?;
        control.checkpoint().await?;
        if terminated {
            return Ok(());
        }
    }
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
    exhausted: bool,
}

#[repr(C, align(16))]
struct BrotliArenaBlock {
    size: usize,
    used: usize,
}

fn initialize_brotli_arena<A: AllocationAuthority>(
    workspace: &mut StableWorkspace<A>,
) -> Option<*mut BrotliArenaState> {
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
        state.write(BrotliArenaState {
            base,
            len,
            exhausted: false,
        });
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
        arena.exhausted = true;
        return ptr::null_mut();
    };
    let Some(mut offset) = align_up(size_of::<BrotliArenaState>(), ARENA_ALIGNMENT) else {
        arena.exhausted = true;
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
            arena.exhausted = true;
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
    arena.exhausted = true;
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

struct BrotliSession<A: AllocationAuthority> {
    state: *mut compu_brotli_sys::BrotliDecoderState,
    arena: *mut BrotliArenaState,
    workspace: StableWorkspace<A>,
}

// The C state and allocator metadata both live in the heap-stable guarded
// workspace and are touched only by the owning future.
unsafe impl<A: AllocationAuthority + Send> Send for BrotliSession<A> {}

impl<A: AllocationAuthority + Send + Sync> BrotliSession<A> {
    async fn new<C: DecodeContext<Authority = A>>(
        guard: &C,
        workspace_bytes: usize,
        control: DecodeControl,
    ) -> Result<Self, HttpBodyReadError> {
        let mut workspace = allocate_codec_workspace(guard, workspace_bytes, control).await?;
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
        Ok(Self {
            state,
            arena,
            workspace,
        })
    }

    fn arena_exhausted(&self) -> bool {
        unsafe { (*self.arena).exhausted }
    }
}

impl<A: AllocationAuthority> Drop for BrotliSession<A> {
    fn drop(&mut self) {
        unsafe { compu_brotli_sys::BrotliDecoderDestroyInstance(self.state) };
        self.state = ptr::null_mut();
        self.workspace.reset();
    }
}

async fn decode_brotli<C: DecodeContext>(
    encoded: &StableBody<C::Authority>,
    guard: &C,
    workspace_bytes: usize,
    max_decoded: usize,
    ratio: usize,
    control: DecodeControl,
) -> Result<StableBody<C::Authority>, HttpBodyReadError> {
    let first = EncodedCursor::new(encoded)
        .current()
        .first()
        .copied()
        .ok_or(HttpBodyReadError::InvalidContentEncoding)?;
    let window_bits = brotli_window_bits(first)?;
    if 1usize
        .checked_shl(window_bits)
        .is_none_or(|window| window > BROTLI_MAX_WINDOW_BYTES)
    {
        return Err(HttpBodyReadError::DecoderWindowExceeded);
    }

    control.check()?;
    let session = BrotliSession::new(guard, workspace_bytes, control).await?;
    let mut cursor = EncodedCursor::new(encoded);
    control.check()?;
    let mut staging = guard.scratch()?;
    let mut output = guard.body_buffer();
    let mut progress = DecodeProgress {
        decoded: 0,
        max_decoded,
        ratio,
        control,
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
            _ if session.arena_exhausted() => return Err(HttpBodyReadError::ResourceExhausted),
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

struct ZstdSession<A: AllocationAuthority> {
    stream: *mut zstd_sys::ZSTD_DStream,
    workspace: StableWorkspace<A>,
}

// The static DStream pointer targets the session's heap-stable guarded
// workspace and is used exclusively by the owning future.
unsafe impl<A: AllocationAuthority + Send> Send for ZstdSession<A> {}

impl<A: AllocationAuthority + Send + Sync> ZstdSession<A> {
    async fn new<C: DecodeContext<Authority = A>>(
        guard: &C,
        workspace_bytes: usize,
        control: DecodeControl,
    ) -> Result<Self, HttpBodyReadError> {
        let mut workspace = allocate_codec_workspace(guard, workspace_bytes, control).await?;
        let stream = unsafe {
            zstd_sys::ZSTD_initStaticDStream(
                workspace.as_mut_ptr().cast::<c_void>(),
                workspace.len(),
            )
        };
        if stream.is_null() {
            return Err(HttpBodyReadError::ResourceExhausted);
        }
        let window = zstd_window_limit().ok_or(HttpBodyReadError::ResourceExhausted)?;
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

impl<A: AllocationAuthority> Drop for ZstdSession<A> {
    fn drop(&mut self) {
        // Static DStreams have no free call. Wiping their caller-owned backing
        // store destroys all state and history before the guard releases it.
        self.stream = ptr::null_mut();
        self.workspace.reset();
    }
}

async fn decode_zstd<C: DecodeContext>(
    encoded: &StableBody<C::Authority>,
    guard: &C,
    workspace_bytes: usize,
    max_decoded: usize,
    ratio: usize,
    control: DecodeControl,
) -> Result<StableBody<C::Authority>, HttpBodyReadError> {
    control.check()?;
    let session = ZstdSession::new(guard, workspace_bytes, control).await?;
    let mut cursor = EncodedCursor::new(encoded);
    control.check()?;
    let mut staging = guard.scratch()?;
    let mut output = guard.body_buffer();
    let mut progress = DecodeProgress {
        decoded: 0,
        max_decoded,
        ratio,
        control,
    };
    let window_limit = zstd_window_limit().ok_or(HttpBodyReadError::ResourceExhausted)?;
    let mut at_frame_start = true;
    loop {
        progress.check_deadline()?;
        if at_frame_start {
            validate_zstd_frame_window(&cursor, window_limit)?;
            at_frame_start = false;
        }
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
        if result == 0 {
            at_frame_start = true;
            control.checkpoint().await?;
        }
        if input_pos == 0 && output_pos == 0 {
            return Err(HttpBodyReadError::InvalidContentEncoding);
        }
    }
}

fn validate_zstd_frame_window(
    cursor: &EncodedCursor<'_>,
    window_limit: usize,
) -> Result<(), HttpBodyReadError> {
    let mut prefix = [0u8; ZSTD_FRAME_HEADER_MAX_BYTES];
    let prefix_len = cursor.copy_prefix(&mut prefix);
    let mut header = MaybeUninit::<zstd_sys::ZSTD_FrameHeader>::uninit();
    let result = unsafe {
        zstd_sys::ZSTD_getFrameHeader(
            header.as_mut_ptr(),
            prefix.as_ptr().cast::<c_void>(),
            prefix_len,
        )
    };
    if unsafe { zstd_sys::ZSTD_isError(result) } != 0 || result != 0 {
        return Err(HttpBodyReadError::InvalidContentEncoding);
    }
    // A zero return guarantees the library initialized the complete header.
    let header = unsafe { header.assume_init() };
    let window =
        usize::try_from(header.windowSize).map_err(|_| HttpBodyReadError::DecoderWindowExceeded)?;
    if window > window_limit {
        return Err(HttpBodyReadError::DecoderWindowExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use bytes::Bytes;
    use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
    use flate2::{Compress, Compression, FlushCompress, Status};
    use http::HeaderValue;
    use http_access_runtime::{
        BodyBounds, BodyBudget, BodySource, BodySourceEvent, BodyTrailerCopy, BoxFuture, Clock,
        RuntimeBody, RuntimeTrailers,
    };
    use http_access_types::{
        BodyFraming, BodyMetadata, BodyRepresentation, HeaderField,
        HeaderName as NeutralHeaderName, HeaderValue as NeutralHeaderValue, HttpMethod,
        HttpVersion, IngressMode, InterceptedRequestFacts, PolicyHeaderFacts,
    };
    use http_access_url::canonicalize_http_url;
    use hyper::Body;
    use tokio_stream::StreamExt;

    use crate::capture::CaptureSinkSpec;
    use crate::config::compiler::{
        CapturePlan, CaptureWorkingSetPlan, CompiledCaptureEvent, CompiledRedactionPayloads,
        ObservationPlan, RedactionPlan, RedactionProfilePlan, RedactionRulePlan,
    };
    use crate::observation::{CapturePool, ProductObservationSnapshot};
    use crate::redaction::RedactionSnapshot;
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
            + guarded_workspace_allocation_bytes(http_decoder_workspace_sizes().unwrap().maximum())
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

    struct RuntimeTestClock;

    impl Clock for RuntimeTestClock {
        fn monotonic_millis(&self) -> u64 {
            1
        }

        fn unix_millis(&self) -> u64 {
            1
        }

        fn sleep_until(&self, _deadline_millis: u64) -> BoxFuture<'static, ()> {
            Box::pin(std::future::pending())
        }
    }

    fn runtime_request(source: impl BodySource + 'static, bounds: BodyBounds) -> RuntimeRequest {
        runtime_request_with_headers(source, bounds, Vec::new())
    }

    fn runtime_request_with_headers(
        source: impl BodySource + 'static,
        bounds: BodyBounds,
        headers: Vec<HeaderField>,
    ) -> RuntimeRequest {
        runtime_request_with_headers_and_framing(
            source,
            bounds,
            headers,
            BodyFraming::ContentLength(0),
        )
    }

    fn runtime_request_with_headers_and_framing(
        source: impl BodySource + 'static,
        bounds: BodyBounds,
        headers: Vec<HeaderField>,
        framing: BodyFraming,
    ) -> RuntimeRequest {
        let body = RuntimeBody::new(
            Box::pin(source),
            bounds,
            Arc::new(RuntimeTestClock),
            BodyBudget::new(1024 * 1024).unwrap(),
            1_000,
        )
        .unwrap();
        let facts = InterceptedRequestFacts::new(
            IngressMode::ExplicitHttp,
            HttpVersion::Http11,
            HttpMethod::new("POST").unwrap(),
            canonicalize_http_url("http://example.test/resource").unwrap(),
            headers,
            BodyMetadata::new(framing),
            None,
        )
        .unwrap();
        RuntimeRequest::new(
            facts.clone(),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8)),
            PolicyHeaderFacts::new(facts.headers().to_vec(), Vec::new()).unwrap(),
            BodyRepresentation::PreservedContentCoded,
            body,
            1_000,
        )
        .unwrap()
    }

    fn runtime_request_from_chunks(chunks: Vec<Vec<u8>>, body_bytes: u64) -> RuntimeRequest {
        runtime_request_from_chunks_with_headers(chunks, body_bytes, Vec::new())
    }

    fn runtime_request_from_chunks_with_headers(
        chunks: Vec<Vec<u8>>,
        body_bytes: u64,
        headers: Vec<HeaderField>,
    ) -> RuntimeRequest {
        struct Chunks {
            chunks: std::collections::VecDeque<Vec<u8>>,
            pending: Option<http_access_runtime::BodyChunkCopy>,
        }

        impl BodySource for Chunks {
            fn poll_next(
                mut self: Pin<&mut Self>,
                _context: &mut Context<'_>,
                budget: &BodyBudget,
            ) -> Poll<Result<BodySourceEvent, RuntimeError>> {
                let Some(bytes) = self.chunks.pop_front() else {
                    return Poll::Ready(Ok(BodySourceEvent::End));
                };
                let mut copy = budget.begin_chunk_copy(bytes.len() as u64)?;
                copy.push_fragment(&bytes)?;
                self.pending = Some(copy);
                Poll::Ready(
                    self.pending
                        .take()
                        .expect("pending runtime chunk copy")
                        .finish()
                        .map(BodySourceEvent::Chunk),
                )
            }

            fn poll_trailers(
                self: Pin<&mut Self>,
                _context: &mut Context<'_>,
                _budget: &BodyBudget,
            ) -> Poll<Result<Option<RuntimeTrailers>, RuntimeError>> {
                Poll::Ready(Ok(None))
            }
        }

        runtime_request_with_headers(
            Chunks {
                chunks: chunks.into(),
                pending: None,
            },
            BodyBounds::new(body_bytes, body_bytes, body_bytes.max(1), 0, 0, 100).unwrap(),
            headers,
        )
    }

    struct TrailerSource {
        ended: bool,
        copy: Option<BodyTrailerCopy>,
    }

    impl BodySource for TrailerSource {
        fn poll_next(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _budget: &BodyBudget,
        ) -> Poll<Result<BodySourceEvent, RuntimeError>> {
            if self.ended {
                return Poll::Ready(Err(RuntimeError::InvalidInput));
            }
            self.ended = true;
            Poll::Ready(Ok(BodySourceEvent::End))
        }

        fn poll_trailers(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            budget: &BodyBudget,
        ) -> Poll<Result<Option<RuntimeTrailers>, RuntimeError>> {
            if self.copy.is_none() {
                let mut copy = budget.begin_trailer_copy(1, 32)?;
                copy.start_field("x-checksum", 7)?;
                copy.push_value_fragment(b"private")?;
                copy.finish_field()?;
                self.copy = Some(copy);
            }
            match self
                .copy
                .as_mut()
                .expect("runtime trailer copy")
                .poll_finish(context)
            {
                Poll::Pending => Poll::Pending,
                Poll::Ready(result) => Poll::Ready(result.map(Some)),
            }
        }
    }

    struct ErrorSource;

    impl BodySource for ErrorSource {
        fn poll_next(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _budget: &BodyBudget,
        ) -> Poll<Result<BodySourceEvent, RuntimeError>> {
            Poll::Ready(Err(RuntimeError::ServiceFailure))
        }

        fn poll_trailers(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _budget: &BodyBudget,
        ) -> Poll<Result<Option<RuntimeTrailers>, RuntimeError>> {
            Poll::Ready(Ok(None))
        }
    }

    struct PendingSource;

    impl BodySource for PendingSource {
        fn poll_next(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _budget: &BodyBudget,
        ) -> Poll<Result<BodySourceEvent, RuntimeError>> {
            Poll::Pending
        }

        fn poll_trailers(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _budget: &BodyBudget,
        ) -> Poll<Result<Option<RuntimeTrailers>, RuntimeError>> {
            Poll::Pending
        }
    }

    fn body_bytes(body: &GuardedRequestBody) -> Vec<u8> {
        body.body.segments().flatten().copied().collect()
    }

    fn capture_body_bytes(body: &CaptureBody) -> Vec<u8> {
        body.segments().flatten().copied().collect()
    }

    fn capture_context(
        limit: usize,
        max_encoded: usize,
        max_decoded: usize,
    ) -> (CaptureOperation, ProfileHandle, Arc<CapturePool>) {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "capture".to_owned(),
            RedactionProfilePlan {
                replacement: b"[REDACTED]".to_vec(),
                max_body_bytes: max_encoded,
                max_decoded_body_bytes: max_decoded,
                max_frame_bytes: max_encoded,
                max_message_bytes: max_decoded,
                allow_permessage_deflate: false,
                max_environment_literal_sources: 1,
                max_environment_literal_bytes: 64,
                max_environment_literal_total_bytes: 64,
                rules: vec![RedactionRulePlan {
                    literals: vec![b"secret".to_vec()],
                    literal_environment_variables: Vec::new(),
                    expressions: Vec::new(),
                    payloads: CompiledRedactionPayloads::Both,
                }],
            },
        );
        let redaction = RedactionSnapshot::activate(RedactionPlan { profiles }, || false).unwrap();
        let profile = redaction.profile("capture").unwrap();
        let pool = CapturePool::new();
        let activation = ProductObservationSnapshot::activate(
            ObservationPlan {
                capture: Some(CapturePlan {
                    events: vec![CompiledCaptureEvent::RequestDenied],
                    redaction_profile: "capture".to_owned(),
                    sink: CaptureSinkSpec::new(
                        PathBuf::from("/capture-http-decode-tests"),
                        "capture-{requestId}-{suffix}.json".to_owned(),
                        1,
                        1,
                    )
                    .unwrap(),
                    max_body_bytes: max_decoded,
                    max_inflight_body_bytes: limit,
                    working_set: CaptureWorkingSetPlan::default(),
                }),
            },
            &redaction,
            pool.clone(),
        )
        .unwrap();
        let (_, owner) = activation.into_parts();
        owner.publication_guard().unwrap().commit();
        let operation = pool.try_admit().unwrap();
        (operation, profile, pool)
    }

    fn capture_body(operation: &CaptureOperation, bytes: &[u8]) -> CaptureBody {
        let mut body = operation.body_buffer();
        body.try_extend_from_slice(bytes).unwrap();
        body.finish()
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

    fn permessage_deflate(input: &[u8]) -> Vec<u8> {
        let mut encoder = Compress::new(Compression::default(), false);
        let mut output = Vec::with_capacity(input.len() + 64);
        assert_eq!(
            encoder
                .compress_vec(input, &mut output, FlushCompress::Sync)
                .unwrap(),
            Status::Ok
        );
        assert!(output.ends_with(PERMESSAGE_DEFLATE_TAIL));
        output.truncate(output.len() - PERMESSAGE_DEFLATE_TAIL.len());
        output
    }

    fn brotli_with_window(input: &[u8], window_bits: u32) -> Vec<u8> {
        let mut output = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::new(&mut output, 4096, 5, window_bits);
            encoder.write_all(input).unwrap();
        }
        output
    }

    fn brotli(input: &[u8]) -> Vec<u8> {
        brotli_with_window(input, 22)
    }

    fn zstd(input: &[u8]) -> Vec<u8> {
        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 1).unwrap();
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    }

    fn zstd_with_window(input: &[u8], window_log: u32) -> Vec<u8> {
        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 1).unwrap();
        encoder.window_log(window_log).unwrap();
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    }

    fn gzip_with_extra(input: &[u8], extra_len: usize) -> Vec<u8> {
        let mut encoded = vec![0x1f, 0x8b, 8, 0x04, 0, 0, 0, 0, 0, 255];
        encoded.extend_from_slice(&(extra_len as u16).to_le_bytes());
        encoded.extend(std::iter::repeat_n(0x5a, extra_len));
        encoded.extend_from_slice(&raw_deflate(input));
        encoded.extend_from_slice(&crc32fast::hash(input).to_le_bytes());
        encoded.extend_from_slice(&(input.len() as u32).to_le_bytes());
        encoded
    }

    #[test]
    fn workspace_selection_includes_each_bounded_codec() {
        let small = http_decoder_workspace_sizes().unwrap();
        assert_eq!(small.maximum(), small.brotli);
        assert!(small.deflate > 0);
        assert_eq!(
            small.brotli,
            BROTLI_FIXED_WORKSPACE_BYTES
                + BROTLI_MAX_WINDOW_BYTES
                + BROTLI_RING_WRITE_AHEAD_SLACK_BYTES
        );
        assert!(small.zstd > ZSTD_STANDARD_WINDOW_BYTES);

        let large = http_decoder_workspace_sizes().unwrap();
        assert_eq!(large.brotli, small.brotli);
        assert_eq!(large.zstd, small.zstd);
        assert_eq!(large.maximum(), large.brotli);
    }

    #[test]
    fn capture_content_encoding_is_parsed_before_queueing() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            parse_capture_content_encoding(&headers).unwrap(),
            CaptureContentEncoding::Identity
        );
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("br"));
        assert_eq!(
            parse_capture_content_encoding(&headers).unwrap(),
            CaptureContentEncoding::Brotli
        );
        headers.append(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert_eq!(
            parse_capture_content_encoding(&headers).unwrap_err(),
            CaptureHttpDecodeError::StackedContentEncoding
        );
    }

    #[tokio::test]
    async fn capture_identity_decode_transfers_input_without_copy() {
        let bytes = b"identity capture body";
        let charge = guarded_body_allocation_bytes(bytes.len()).unwrap();
        let (operation, profile, pool) = capture_context(charge, bytes.len(), bytes.len());
        let encoded = capture_body(&operation, bytes);
        let pointer = encoded.segments().next().unwrap().as_ptr();
        let charged = operation.charged_bytes();

        let decoded = decode_capture_http_body(
            CaptureContentEncoding::Identity,
            encoded,
            &operation,
            &profile,
            128,
        )
        .unwrap();

        assert_eq!(decoded.segments().next().unwrap().as_ptr(), pointer);
        assert_eq!(capture_body_bytes(&decoded), bytes);
        assert_eq!(operation.charged_bytes(), charged);
        drop(decoded);
        assert_eq!(operation.charged_bytes(), 0);
        assert_eq!(pool.used(), 0);
    }

    #[tokio::test]
    async fn capture_decode_supports_every_http_codec_with_exact_restoration() {
        let plain = b"capture codec body".repeat(4096);
        let sizes = http_decoder_workspace_sizes().unwrap();
        let cases = [
            (CaptureContentEncoding::Gzip, gzip(&plain), sizes.deflate),
            (
                CaptureContentEncoding::Deflate,
                raw_deflate(&plain),
                sizes.deflate,
            ),
            (CaptureContentEncoding::Brotli, brotli(&plain), sizes.brotli),
            (CaptureContentEncoding::Zstd, zstd(&plain), sizes.zstd),
        ];

        for (encoding, encoded_bytes, workspace) in cases {
            let limit = guarded_body_allocation_bytes(encoded_bytes.len()).unwrap()
                + guarded_body_allocation_bytes(plain.len()).unwrap()
                + guarded_body_allocation_bytes(HTTP_DECODER_OUTPUT_STAGING_BYTES).unwrap()
                + guarded_workspace_allocation_bytes(workspace).unwrap();
            let (operation, profile, pool) =
                capture_context(limit, encoded_bytes.len(), plain.len());
            let encoded = capture_body(&operation, &encoded_bytes);

            let decoded = decode_capture_http_body(encoding, encoded, &operation, &profile, 128)
                .unwrap_or_else(|error| panic!("encoding {encoding:?}: {error:?}"));
            assert_eq!(capture_body_bytes(&decoded), plain, "{encoding:?}");
            drop(decoded);
            assert_eq!(operation.charged_bytes(), 0, "{encoding:?}");
            assert_eq!(pool.used(), 0, "{encoding:?}");
        }
    }

    #[tokio::test]
    async fn capture_decode_failures_restore_every_charge() {
        let invalid = vec![0u8; 128];
        let limit = compiled_peak(invalid.len(), 1024);
        let (operation, profile, pool) = capture_context(limit, invalid.len(), 1024);
        let encoded = capture_body(&operation, &invalid);
        let error = decode_capture_http_body(
            CaptureContentEncoding::Gzip,
            encoded,
            &operation,
            &profile,
            128,
        )
        .unwrap_err();
        assert_eq!(error, CaptureHttpDecodeError::InvalidContentEncoding);
        assert_eq!(operation.charged_bytes(), 0);
        assert_eq!(pool.used(), 0);

        let input_charge = guarded_body_allocation_bytes(invalid.len()).unwrap();
        let (operation, profile, pool) = capture_context(input_charge, invalid.len(), 1024);
        let encoded = capture_body(&operation, &invalid);
        let error = decode_capture_http_body(
            CaptureContentEncoding::Gzip,
            encoded,
            &operation,
            &profile,
            128,
        )
        .unwrap_err();
        assert_eq!(error, CaptureHttpDecodeError::ResourceExhausted);
        assert_eq!(operation.charged_bytes(), 0);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn capture_websocket_permessage_deflate_uses_one_bounded_scratch() {
        let plain = b"websocket capture message".repeat(4096);
        let encoded_bytes = permessage_deflate(&plain);
        let limit = guarded_body_allocation_bytes(encoded_bytes.len()).unwrap()
            + guarded_body_allocation_bytes(plain.len()).unwrap()
            + guarded_workspace_allocation_bytes(WEBSOCKET_DEFLATE_SCRATCH_BYTES).unwrap();
        let (operation, _profile, pool) = capture_context(limit, encoded_bytes.len(), plain.len());
        let encoded = capture_body(&operation, &encoded_bytes);

        let decoded =
            decode_capture_websocket_permessage_deflate(encoded, &operation, plain.len()).unwrap();

        assert_eq!(capture_body_bytes(&decoded), plain);
        drop(decoded);
        assert_eq!(operation.charged_bytes(), 0);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn capture_websocket_deflate_failures_restore_every_charge() {
        let plain = b"bounded websocket message".repeat(1024);
        let encoded_bytes = permessage_deflate(&plain);
        let limit = guarded_body_allocation_bytes(encoded_bytes.len()).unwrap()
            + guarded_body_allocation_bytes(plain.len()).unwrap()
            + guarded_workspace_allocation_bytes(WEBSOCKET_DEFLATE_SCRATCH_BYTES).unwrap();
        let (operation, _profile, pool) = capture_context(limit, encoded_bytes.len(), plain.len());
        let encoded = capture_body(&operation, &encoded_bytes);
        let error =
            decode_capture_websocket_permessage_deflate(encoded, &operation, plain.len() - 1)
                .unwrap_err();
        assert_eq!(error, CaptureHttpDecodeError::DecodedLimitExceeded);
        assert_eq!(operation.charged_bytes(), 0);
        assert_eq!(pool.used(), 0);

        let input_charge = guarded_body_allocation_bytes(encoded_bytes.len()).unwrap();
        let (operation, _profile, pool) =
            capture_context(input_charge, encoded_bytes.len(), plain.len());
        let encoded = capture_body(&operation, &encoded_bytes);
        let error = decode_capture_websocket_permessage_deflate(encoded, &operation, plain.len())
            .unwrap_err();
        assert_eq!(error, CaptureHttpDecodeError::ResourceExhausted);
        assert_eq!(operation.charged_bytes(), 0);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn pinned_brotli_arena_budget_covers_derived_standard_decoder_maximum() {
        let required = brotli_fixed_workspace_required_bytes();
        assert_eq!(BROTLI_HUFFMAN_POINTER_BYTES, size_of::<usize>());
        assert_eq!(BROTLI_LITERAL_HUFFMAN_ALLOCATED_ENTRIES, 632);
        assert_eq!(BROTLI_COMMAND_HUFFMAN_ALLOCATED_ENTRIES, 1080);
        assert_eq!(BROTLI_DISTANCE_HUFFMAN_ALLOCATED_ENTRIES, 896);
        const {
            assert!(
                BROTLI_DISTANCE_HUFFMAN_BUDGET_ENTRIES >= BROTLI_DISTANCE_HUFFMAN_ALLOCATED_ENTRIES
            );
        }
        assert!(required <= BROTLI_FIXED_WORKSPACE_BYTES);
        assert!(BROTLI_FIXED_WORKSPACE_BYTES - required >= MIB);
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
            assert_eq!(body.encoded_len(), max_encoded, "encoding {encoding:?}");
            assert_eq!(body.len(), plain.len());
            assert_eq!(body_bytes(&body), plain, "encoding {encoding:?}");
            drop(body);
            assert_eq!(guard.live_bytes(), 0);
            assert_eq!(pool.global_charge(), 0);
        }
    }

    #[tokio::test]
    async fn runtime_request_identity_body_uses_guarded_decode_pipeline() {
        let expected = b"runtime request body".to_vec();
        let peak = compiled_peak(expected.len(), expected.len());
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(peak, key());
        let mut request = runtime_request_from_chunks(
            vec![b"runtime ".to_vec(), b"request body".to_vec()],
            expected.len() as u64,
        );

        let body = read_mandatory_runtime_request_body(
            &mut request,
            limits(expected.len(), expected.len()),
            1,
            Instant::now() + Duration::from_secs(1),
            &guard,
        )
        .await
        .unwrap();

        assert_eq!(body.encoded_len(), expected.len());
        assert_eq!(body.content_encoding(), CanonicalContentEncoding::Identity);
        assert_eq!(body_bytes(&body), expected);
        drop(body);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn runtime_request_reader_uses_authoritative_content_encoding() {
        let expected = b"authoritative compressed request".repeat(64);
        let encoded = gzip(&expected);
        let peak = compiled_peak(encoded.len(), expected.len());
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(peak, key());
        let header = HeaderField::new(
            NeutralHeaderName::new("content-encoding").unwrap(),
            NeutralHeaderValue::new(b"gzip".to_vec()).unwrap(),
        );
        let mut request = runtime_request_from_chunks_with_headers(
            vec![encoded.clone()],
            encoded.len().max(expected.len()) as u64,
            vec![header],
        );

        let body = read_mandatory_runtime_request_body(
            &mut request,
            limits(encoded.len(), expected.len()),
            128,
            Instant::now() + Duration::from_secs(1),
            &guard,
        )
        .await
        .unwrap();

        assert_eq!(body_bytes(&body), expected);
    }

    #[tokio::test]
    async fn runtime_request_reader_rejects_partial_and_complete_reentry() {
        let peak = compiled_peak(4, 4);
        let pool = WireBodyPool::new(peak * 2, peak * 2);

        let partial_guard = pool.begin_for_test(peak, key());
        let mut partial = runtime_request_from_chunks(vec![b"ab".to_vec(), b"cd".to_vec()], 4);
        let first = std::future::poll_fn(|context| partial.poll_body_chunk(context))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.as_bytes(), b"ab");
        assert_eq!(
            read_mandatory_runtime_request_body(
                &mut partial,
                limits(4, 4),
                1,
                Instant::now() + Duration::from_secs(1),
                &partial_guard,
            )
            .await
            .unwrap_err(),
            HttpBodyReadError::ReadFailed
        );

        let complete_guard = pool.begin_for_test(peak, key());
        let mut complete = runtime_request_from_chunks(vec![b"body".to_vec()], 4);
        let observed = read_mandatory_runtime_request_body(
            &mut complete,
            limits(4, 4),
            1,
            Instant::now() + Duration::from_secs(1),
            &complete_guard,
        )
        .await
        .unwrap();
        drop(observed);
        assert_eq!(
            read_mandatory_runtime_request_body(
                &mut complete,
                limits(4, 4),
                1,
                Instant::now() + Duration::from_secs(1),
                &complete_guard,
            )
            .await
            .unwrap_err(),
            HttpBodyReadError::ReadFailed
        );
    }

    #[tokio::test]
    async fn runtime_request_reader_enforces_encoded_limit_incrementally() {
        let peak = compiled_peak(3, 4);
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(peak, key());
        let mut request = runtime_request_from_chunks(vec![b"ab".to_vec(), b"cd".to_vec()], 4);

        let error = read_mandatory_runtime_request_body(
            &mut request,
            limits(3, 4),
            1,
            Instant::now() + Duration::from_secs(1),
            &guard,
        )
        .await
        .unwrap_err();

        assert_eq!(error, HttpBodyReadError::EncodedLimitExceeded);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn runtime_request_reader_rejects_oversized_declared_length_before_polling() {
        let max = 64;
        let declared = max + 1;
        let peak = compiled_peak(max, max);
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(peak, key());
        let mut request = runtime_request_with_headers_and_framing(
            PendingSource,
            BodyBounds::new(declared as u64, declared as u64, declared as u64, 0, 0, 100).unwrap(),
            Vec::new(),
            BodyFraming::ContentLength(declared as u64),
        );

        let error = read_mandatory_runtime_request_body(
            &mut request,
            limits(max, max),
            1,
            Instant::now() + Duration::from_secs(1),
            &guard,
        )
        .await
        .unwrap_err();

        assert_eq!(error, HttpBodyReadError::EncodedLimitExceeded);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn runtime_request_reader_rejects_delivered_trailers() {
        let max = 64;
        let peak = compiled_peak(max, max);
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(peak, key());
        let mut request = runtime_request(
            TrailerSource {
                ended: false,
                copy: None,
            },
            BodyBounds::new(1, 1, 1, 1, 32, 100).unwrap(),
        );

        let error = read_mandatory_runtime_request_body(
            &mut request,
            limits(max, max),
            1,
            Instant::now() + Duration::from_secs(1),
            &guard,
        )
        .await
        .unwrap_err();

        assert_eq!(error, HttpBodyReadError::RequestTrailersUnsupported);
        assert!(!error.to_string().contains("private"));
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn runtime_request_reader_sanitizes_runtime_source_errors() {
        let max = 64;
        let peak = compiled_peak(max, max);
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(peak, key());
        let mut request = runtime_request(
            ErrorSource,
            BodyBounds::new(max as u64, max as u64, max as u64, 0, 0, 100).unwrap(),
        );

        let error = read_mandatory_runtime_request_body(
            &mut request,
            limits(max, max),
            1,
            Instant::now() + Duration::from_secs(1),
            &guard,
        )
        .await
        .unwrap_err();

        assert_eq!(error, HttpBodyReadError::ReadFailed);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
    }

    #[tokio::test]
    async fn runtime_request_reader_enforces_product_deadline() {
        let max = 64;
        let peak = compiled_peak(max, max);
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(peak, key());
        let mut request = runtime_request(
            PendingSource,
            BodyBounds::new(max as u64, max as u64, max as u64, 0, 0, 100).unwrap(),
        );

        let error = read_mandatory_runtime_request_body(
            &mut request,
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
    }

    #[tokio::test]
    async fn brotli_standard_windows_are_independent_of_decoded_body_limit() {
        let plain = b"small standard-window brotli body".repeat(64);
        for window_bits in [22, 24] {
            let encoded = brotli_with_window(&plain, window_bits);
            let (result, guard, pool) =
                invoke(encoded.clone(), Some("br"), encoded.len(), plain.len(), 128).await;
            assert_eq!(body_bytes(&result.unwrap()), plain, "window {window_bits}");
            drop(guard);
            assert_eq!(pool.global_charge(), 0);
        }
    }

    #[tokio::test]
    async fn zstd_standard_window_is_independent_of_decoded_body_limit() {
        let plain = b"default streaming zstd body".repeat(4096);
        let decoded_limit = MIB;
        for encoded in [zstd(&plain), zstd_with_window(&plain, 23)] {
            let (result, guard, pool) = invoke(
                encoded.clone(),
                Some("zstd"),
                encoded.len(),
                decoded_limit,
                128,
            )
            .await;
            assert_eq!(body_bytes(&result.unwrap()), plain);
            drop(guard);
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

    #[tokio::test(flavor = "current_thread")]
    async fn immediately_ready_large_data_chunk_is_cooperatively_cancellable() {
        let max = 8 * MIB;
        let peak = compiled_peak(max, max);
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(peak, key());
        let observed_pool = pool.clone();
        let task = tokio::spawn(async move {
            read_mandatory_request_body(
                &HeaderMap::new(),
                Body::from(vec![0x41; max]),
                limits(max, max),
                1,
                Instant::now() + Duration::from_secs(30),
                &guard,
            )
            .await
        });
        while observed_pool.global_charge() == 0 {
            tokio::task::yield_now().await;
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(observed_pool.global_charge(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn partially_initialized_workspace_is_cooperatively_cancellable() {
        let requested = 20 * MIB;
        let charged = guarded_workspace_allocation_bytes(requested).unwrap();
        let pool = WireBodyPool::new(charged, charged);
        let guard = pool.begin_for_test(charged, key());
        let observed_pool = pool.clone();
        let task = tokio::spawn(async move {
            allocate_codec_workspace(
                &guard,
                requested,
                DecodeControl::wire(Instant::now() + Duration::from_secs(30)),
            )
            .await
        });
        while observed_pool.global_charge() == 0 {
            tokio::task::yield_now().await;
        }
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
                http_decoder_workspace_sizes().unwrap().deflate,
            ),
            (
                "deflate",
                raw_deflate(&plain),
                http_decoder_workspace_sizes().unwrap().deflate,
            ),
            (
                "br",
                brotli(&plain),
                http_decoder_workspace_sizes().unwrap().brotli,
            ),
            (
                "zstd",
                zstd(&plain),
                http_decoder_workspace_sizes().unwrap().zstd,
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
    async fn brotli_arena_exhaustion_is_not_classified_as_corrupt_input() {
        let plain = b"valid brotli with an intentionally undersized arena";
        let encoded_bytes = brotli_with_window(plain, 22);
        let workspace_bytes = 64 * KIB;
        let peak = guarded_body_allocation_bytes(encoded_bytes.len()).unwrap()
            + guarded_body_allocation_bytes(plain.len()).unwrap()
            + guarded_body_allocation_bytes(HTTP_DECODER_OUTPUT_STAGING_BYTES).unwrap()
            + guarded_workspace_allocation_bytes(workspace_bytes).unwrap();
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(peak, key());
        let mut encoded = guard.buffer();
        encoded.try_extend_from_slice(&encoded_bytes).unwrap();
        let encoded = encoded.finish();

        let error = decode_brotli(
            &encoded,
            &guard,
            workspace_bytes,
            plain.len(),
            128,
            DecodeControl::wire(Instant::now() + Duration::from_secs(5)),
        )
        .await
        .unwrap_err();
        assert_eq!(error, HttpBodyReadError::ResourceExhausted);
        drop(encoded);
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
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
                HttpBodyReadError::InvalidContentEncoding,
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
    async fn gzip_accepts_large_valid_extra_header_with_bounded_work() {
        let plain = b"large gzip extra field";
        let encoded = gzip_with_extra(plain, 48 * KIB);
        let (result, guard, pool) = invoke(
            encoded.clone(),
            Some("gzip"),
            encoded.len(),
            encoded.len(),
            128,
        )
        .await;
        assert_eq!(body_bytes(&result.unwrap()), plain);
        drop(guard);
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

    #[tokio::test(flavor = "current_thread")]
    async fn many_empty_gzip_members_reuse_workspace_and_yield() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let members = 512usize;
        let encoded = gzip(&[]).repeat(members);
        let finished = Arc::new(AtomicBool::new(false));
        let ticks = Arc::new(AtomicUsize::new(0));
        let observer_finished = finished.clone();
        let observer_ticks = ticks.clone();
        let observer = async move {
            while !observer_finished.load(Ordering::Acquire) {
                observer_ticks.fetch_add(1, Ordering::AcqRel);
                tokio::task::yield_now().await;
            }
        };
        let decode_finished = finished.clone();
        let decode = async move {
            let limit = encoded.len();
            let (result, guard, pool) = invoke(encoded, Some("gzip"), limit, limit, 128).await;
            assert_eq!(body_bytes(&result.unwrap()), b"");
            drop(guard);
            assert_eq!(pool.global_charge(), 0);
            decode_finished.store(true, Ordering::Release);
        };

        tokio::join!(decode, observer);
        assert!(ticks.load(Ordering::Acquire) >= members);
    }

    #[tokio::test]
    async fn every_concatenated_zstd_frame_enforces_the_standard_window() {
        let first = zstd(b"first");
        let oversized = zstd_with_window(b"second", 24);
        let encoded = [first, oversized].concat();
        let decoded_limit = 64 * KIB;
        let (result, guard, pool) = invoke(
            encoded.clone(),
            Some("zstd"),
            encoded.len(),
            decoded_limit,
            128,
        )
        .await;

        assert_eq!(
            result.unwrap_err(),
            HttpBodyReadError::DecoderWindowExceeded
        );
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
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
            let sizes = http_decoder_workspace_sizes().unwrap();
            let peak = compiled_peak(bytes.len(), plain.len());
            let pool = WireBodyPool::new(peak, peak);
            let guard = pool.begin_for_test(peak, key());
            let mut encoded = guard.buffer();
            encoded.try_extend_from_slice(&bytes).unwrap();
            let encoded = encoded.finish();
            let peak_before_decode = pool.peak_global_charge();
            let result = match encoding {
                ContentEncoding::Gzip => {
                    decode_gzip(
                        &encoded,
                        &guard,
                        sizes.deflate,
                        plain.len(),
                        128,
                        DecodeControl::wire(Instant::now()),
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
                        DecodeControl::wire(Instant::now()),
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
                        DecodeControl::wire(Instant::now()),
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
                        DecodeControl::wire(Instant::now()),
                    )
                    .await
                }
                ContentEncoding::Identity => unreachable!(),
            };
            assert_eq!(result.unwrap_err(), HttpBodyReadError::TimedOut);
            assert_eq!(pool.peak_global_charge(), peak_before_decode);
            drop(encoded);
            assert_eq!(guard.live_bytes(), 0);
            assert_eq!(pool.global_charge(), 0);
        }
    }
}
