use std::future::Future;
use std::io::Read;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use allocator_api2::boxed::Box as FallibleBox;
use chrono::Utc;
use flate2::read::DeflateDecoder;
use flate2::{Compress, Compression, FlushCompress};
use http::header::{HeaderName, HeaderValue};
use http::HeaderMap;
use hyper::upgrade::Upgraded;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::capture::{CaptureArtifactJob, CaptureKind, SanitizedCaptureMetadata};
use crate::observation::{CaptureBodyBuilder, CaptureEvent, ProductObservationRuntime};
use crate::redaction::{PayloadClass, ProfileHandle};
use crate::upgrade::{UpgradeRelayPair, UpgradeTerminalCause, UpgradedStreamSnapshot};

const SEC_WEBSOCKET_EXTENSIONS: &str = "sec-websocket-extensions";
const WEBSOCKET_CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const CLOSE_PROTOCOL_ERROR: u16 = 1002;
const CLOSE_MESSAGE_TOO_BIG: u16 = 1009;
const DEFLATE_TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

#[derive(Debug)]
pub(crate) enum EstablishedUpgradeKind {
    Opaque,
    ObservedWebSocket {
        negotiation: Option<WebSocketNegotiation>,
    },
    WebSocket {
        negotiation: WebSocketNegotiation,
        profile: ProfileHandle,
    },
}

impl EstablishedUpgradeKind {
    pub(crate) fn from_handshake(
        protocol: &HeaderValue,
        request: &HeaderMap,
        switching_protocols: &HeaderMap,
        profile: Option<&ProfileHandle>,
    ) -> Result<Self, UpgradeRelayBuildError> {
        let is_websocket = protocol
            .to_str()
            .is_ok_and(|value| value.eq_ignore_ascii_case("websocket"));
        if !is_websocket {
            return Ok(Self::Opaque);
        }
        let Some(profile) = profile else {
            return Ok(Self::ObservedWebSocket {
                negotiation: WebSocketNegotiation::from_headers(request, switching_protocols).ok(),
            });
        };
        let negotiation = WebSocketNegotiation::from_headers(request, switching_protocols)?;
        if negotiation.permessage_deflate && !profile.limits().allow_permessage_deflate {
            return Err(UpgradeRelayBuildError::CompressionNotAllowed);
        }
        Ok(Self::WebSocket {
            negotiation,
            profile: profile.clone(),
        })
    }

    pub(crate) fn prepare(
        self,
        relay_buffer_bytes: usize,
        capture: Option<UpgradeCaptureContext>,
    ) -> Result<PreparedUpgradeRelay, UpgradeRelayBuildError> {
        self.prepare_with(relay_buffer_bytes, capture, RelayBuffer::try_new)
    }

    fn prepare_with<Allocate>(
        self,
        relay_buffer_bytes: usize,
        capture: Option<UpgradeCaptureContext>,
        mut allocate: Allocate,
    ) -> Result<PreparedUpgradeRelay, UpgradeRelayBuildError>
    where
        Allocate: FnMut(usize) -> Result<RelayBuffer, UpgradeRelayBuildError>,
    {
        let kind = match self {
            Self::Opaque => PreparedUpgradeKind::Opaque {
                client_to_upstream: allocate(relay_buffer_bytes)?,
                upstream_to_client: allocate(relay_buffer_bytes)?,
            },
            Self::ObservedWebSocket { negotiation } => {
                let client_to_upstream = allocate(relay_buffer_bytes)?;
                let upstream_to_client = allocate(relay_buffer_bytes)?;
                match capture {
                    Some(capture) => PreparedUpgradeKind::ObservedWebSocket {
                        negotiation,
                        capture,
                        client_to_upstream,
                        upstream_to_client,
                    },
                    None => PreparedUpgradeKind::Opaque {
                        client_to_upstream,
                        upstream_to_client,
                    },
                }
            }
            Self::WebSocket {
                negotiation,
                profile,
            } => PreparedUpgradeKind::WebSocket {
                negotiation,
                profile,
                capture,
            },
        };
        Ok(PreparedUpgradeRelay { kind })
    }
}

#[derive(Clone)]
pub(crate) struct UpgradeCaptureContext {
    runtime: Arc<ProductObservationRuntime>,
    base: SanitizedCaptureMetadata,
    max_expansion_ratio: usize,
    request_sequence: Arc<AtomicU64>,
    response_sequence: Arc<AtomicU64>,
}

impl UpgradeCaptureContext {
    pub(crate) fn new(
        runtime: Arc<ProductObservationRuntime>,
        base: SanitizedCaptureMetadata,
        max_expansion_ratio: usize,
    ) -> Self {
        Self {
            runtime,
            base: base.without_headers(),
            max_expansion_ratio,
            request_sequence: Arc::new(AtomicU64::new(0)),
            response_sequence: Arc::new(AtomicU64::new(0)),
        }
    }

    fn begin_message(
        &self,
        direction: WebSocketDirection,
        compressed: bool,
        class: PayloadClass,
    ) -> Option<WebSocketMessageCapture> {
        let (event, kind, label, sequence) = match direction {
            WebSocketDirection::ClientToUpstream => (
                CaptureEvent::RequestAllowed,
                CaptureKind::Request,
                "request",
                self.request_sequence.fetch_add(1, Ordering::Relaxed),
            ),
            WebSocketDirection::UpstreamToClient => (
                CaptureEvent::ResponseAllowed,
                CaptureKind::Response,
                "response",
                self.response_sequence.fetch_add(1, Ordering::Relaxed),
            ),
        };
        let epoch = self.runtime.current_capture_epoch();
        let policy = epoch.capture()?;
        let operation = policy.try_admit(event)?;
        let limits = policy.profile().limits();
        let metadata =
            self.base
                .for_websocket_message(Utc::now().to_rfc3339(), label, sequence, kind);
        let job = CaptureArtifactJob::begin_admitted(
            epoch,
            operation,
            metadata,
            self.max_expansion_ratio,
        )
        .ok()?;
        let body = job.operation().body_buffer();
        Some(WebSocketMessageCapture {
            runtime: self.runtime.clone(),
            job,
            body,
            compressed,
            class,
            max_frame_bytes: limits.max_frame_bytes,
            max_message_bytes: limits.max_message_bytes,
            encoded_bytes: 0,
            omitted: false,
        })
    }
}

struct WebSocketMessageCapture {
    runtime: Arc<ProductObservationRuntime>,
    job: CaptureArtifactJob,
    body: CaptureBodyBuilder,
    compressed: bool,
    class: PayloadClass,
    max_frame_bytes: usize,
    max_message_bytes: usize,
    encoded_bytes: usize,
    omitted: bool,
}

impl WebSocketMessageCapture {
    fn begin_frame(&mut self, bytes: usize) -> bool {
        if bytes > self.max_frame_bytes {
            self.omitted = true;
            return false;
        }
        let Some(total) = self.encoded_bytes.checked_add(bytes) else {
            self.omitted = true;
            return false;
        };
        if total > self.max_message_bytes {
            self.omitted = true;
            return false;
        }
        self.encoded_bytes = total;
        true
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> bool {
        if self.omitted || self.body.try_extend_from_slice(bytes).is_err() {
            self.omitted = true;
            false
        } else {
            true
        }
    }

    fn finish(mut self) {
        if self.omitted {
            return;
        }
        let encoded = self.body.finish();
        if self
            .job
            .complete_websocket_message(encoded, self.compressed, self.class)
            .is_ok()
        {
            let _ = self.runtime.try_submit_capture(self.job);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WebSocketNegotiation {
    permessage_deflate: bool,
}

impl WebSocketNegotiation {
    fn from_headers(
        request: &HeaderMap,
        switching_protocols: &HeaderMap,
    ) -> Result<Self, UpgradeRelayBuildError> {
        let offered = parse_request_extensions(request)?;
        let negotiated = parse_response_extensions(switching_protocols, offered)?;
        Ok(Self {
            permessage_deflate: negotiated,
        })
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub(crate) enum UpgradeRelayBuildError {
    #[error("upgrade relay buffer allocation failed")]
    Allocation,
    #[error("invalid WebSocket extension header")]
    InvalidExtensionHeader,
    #[error("unsupported WebSocket extension in the protected request")]
    UnsupportedRequestExtension,
    #[error("unsupported WebSocket extension negotiated by the upstream")]
    UnsupportedResponseExtension,
    #[error("WebSocket compression is not enabled by the wire redaction profile")]
    CompressionNotAllowed,
}

pub(crate) struct PreparedUpgradeRelay {
    kind: PreparedUpgradeKind,
}

#[derive(Clone, Copy)]
pub(crate) struct UpgradeRelayDeadlines {
    idle: Duration,
    absolute: Instant,
}

impl UpgradeRelayDeadlines {
    pub(crate) fn new(idle: Duration, absolute: Instant) -> Self {
        Self { idle, absolute }
    }
}

struct RelayActivity {
    sequence: AtomicU64,
    changed: Notify,
}

impl RelayActivity {
    fn record(&self) {
        self.sequence.fetch_add(1, Ordering::Release);
        self.changed.notify_waiters();
    }
}

struct ActivityIo<T> {
    inner: T,
    activity: Option<Arc<RelayActivity>>,
}

impl<T> ActivityIo<T> {
    fn new(inner: T, activity: Option<Arc<RelayActivity>>) -> Self {
        Self { inner, activity }
    }

    fn record(&self, bytes: usize) {
        if bytes != 0 {
            if let Some(activity) = self.activity.as_ref() {
                activity.record();
            }
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ActivityIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.record(buffer.filled().len().saturating_sub(before));
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ActivityIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(context, buffer);
        if let Poll::Ready(Ok(bytes)) = result {
            self.record(bytes);
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

enum PreparedUpgradeKind {
    Opaque {
        client_to_upstream: RelayBuffer,
        upstream_to_client: RelayBuffer,
    },
    ObservedWebSocket {
        negotiation: Option<WebSocketNegotiation>,
        capture: UpgradeCaptureContext,
        client_to_upstream: RelayBuffer,
        upstream_to_client: RelayBuffer,
    },
    WebSocket {
        negotiation: WebSocketNegotiation,
        profile: ProfileHandle,
        capture: Option<UpgradeCaptureContext>,
    },
}

impl PreparedUpgradeRelay {
    /// Transfers the established streams and pre-commit state into the two
    /// coordinator-owned relay directions. This step performs no semantic
    /// validation or fallible opaque-buffer allocation.
    pub(crate) fn establish(
        self,
        downstream: Upgraded,
        upstream: Upgraded,
        snapshot: UpgradedStreamSnapshot,
        deadlines: UpgradeRelayDeadlines,
    ) -> UpgradeRelayPair {
        debug_assert!(
            !matches!(&self.kind, PreparedUpgradeKind::WebSocket { .. })
                || snapshot.wire_redaction().is_some()
        );
        build_relay_tasks_with_deadlines(downstream, upstream, self.kind, Some(deadlines))
            .into_pair()
    }
}

type RelayFuture = Pin<Box<dyn Future<Output = UpgradeTerminalCause> + Send + 'static>>;

struct RelayTasks {
    client_to_upstream: RelayFuture,
    upstream_to_client: RelayFuture,
    graceful_drain_timeout: Option<Duration>,
}

impl RelayTasks {
    fn into_pair(self) -> UpgradeRelayPair {
        UpgradeRelayPair::new_with_graceful_drain_timeout(
            self.client_to_upstream,
            self.upstream_to_client,
            self.graceful_drain_timeout,
        )
    }

    fn with_deadlines(
        self,
        deadlines: UpgradeRelayDeadlines,
        activity: Arc<RelayActivity>,
    ) -> Self {
        Self {
            client_to_upstream: Box::pin(relay_with_deadlines(
                self.client_to_upstream,
                deadlines,
                activity.clone(),
            )),
            upstream_to_client: Box::pin(relay_with_deadlines(
                self.upstream_to_client,
                deadlines,
                activity,
            )),
            graceful_drain_timeout: self.graceful_drain_timeout,
        }
    }
}

#[cfg(test)]
fn build_relay_tasks<Downstream, Upstream>(
    downstream: Downstream,
    upstream: Upstream,
    kind: PreparedUpgradeKind,
) -> RelayTasks
where
    Downstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Upstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    build_relay_tasks_with_deadlines(downstream, upstream, kind, None)
}

async fn relay_with_deadlines(
    relay: RelayFuture,
    deadlines: UpgradeRelayDeadlines,
    activity: Arc<RelayActivity>,
) -> UpgradeTerminalCause {
    let mut relay = relay;
    let absolute = tokio::time::sleep_until(deadlines.absolute);
    tokio::pin!(absolute);
    let mut observed = activity.sequence.load(Ordering::Acquire);
    let idle = tokio::time::sleep(deadlines.idle);
    tokio::pin!(idle);

    loop {
        let changed = activity.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let current = activity.sequence.load(Ordering::Acquire);
        if current != observed {
            observed = current;
            idle.as_mut().reset(Instant::now() + deadlines.idle);
            continue;
        }
        tokio::select! {
            cause = relay.as_mut() => return cause,
            () = absolute.as_mut() => return UpgradeTerminalCause::LifetimeExpired,
            () = idle.as_mut() => return UpgradeTerminalCause::IdleTimeout,
            () = changed.as_mut() => {
                let current = activity.sequence.load(Ordering::Acquire);
                if current != observed {
                    observed = current;
                    idle.as_mut().reset(Instant::now() + deadlines.idle);
                }
            }
        }
    }
}

fn build_relay_tasks_with_deadlines<Downstream, Upstream>(
    downstream: Downstream,
    upstream: Upstream,
    kind: PreparedUpgradeKind,
    deadlines: Option<UpgradeRelayDeadlines>,
) -> RelayTasks
where
    Downstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Upstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let activity = deadlines.map(|_| {
        Arc::new(RelayActivity {
            sequence: AtomicU64::new(0),
            changed: Notify::new(),
        })
    });
    let downstream = ActivityIo::new(downstream, activity.clone());
    let upstream = ActivityIo::new(upstream, activity.clone());
    let tasks = match kind {
        PreparedUpgradeKind::Opaque {
            client_to_upstream,
            upstream_to_client,
        } => {
            let (downstream_read, downstream_write) = tokio::io::split(downstream);
            let (upstream_read, upstream_write) = tokio::io::split(upstream);
            RelayTasks {
                client_to_upstream: Box::pin(relay_opaque_direction(
                    downstream_read,
                    upstream_write,
                    client_to_upstream,
                    false,
                )),
                upstream_to_client: Box::pin(relay_opaque_direction(
                    upstream_read,
                    downstream_write,
                    upstream_to_client,
                    true,
                )),
                graceful_drain_timeout: None,
            }
        }
        PreparedUpgradeKind::ObservedWebSocket {
            negotiation,
            capture,
            client_to_upstream,
            upstream_to_client,
        } => {
            let (downstream_read, downstream_write) = tokio::io::split(downstream);
            let (upstream_read, upstream_write) = tokio::io::split(upstream);
            RelayTasks {
                client_to_upstream: Box::pin(relay_observed_websocket_direction(
                    downstream_read,
                    upstream_write,
                    client_to_upstream,
                    WebSocketDirection::ClientToUpstream,
                    negotiation,
                    capture.clone(),
                )),
                upstream_to_client: Box::pin(relay_observed_websocket_direction(
                    upstream_read,
                    downstream_write,
                    upstream_to_client,
                    WebSocketDirection::UpstreamToClient,
                    negotiation,
                    capture,
                )),
                graceful_drain_timeout: Some(WEBSOCKET_CLOSE_DRAIN_TIMEOUT),
            }
        }
        PreparedUpgradeKind::WebSocket {
            negotiation: extensions,
            profile,
            capture,
        } => {
            let (downstream_read, downstream_write) = tokio::io::split(downstream);
            let (upstream_read, upstream_write) = tokio::io::split(upstream);
            RelayTasks {
                client_to_upstream: Box::pin(relay_websocket_direction(
                    downstream_read,
                    upstream_write,
                    profile.clone(),
                    extensions,
                    WebSocketDirection::ClientToUpstream,
                    capture.clone(),
                )),
                upstream_to_client: Box::pin(relay_websocket_direction(
                    upstream_read,
                    downstream_write,
                    profile,
                    extensions,
                    WebSocketDirection::UpstreamToClient,
                    capture,
                )),
                graceful_drain_timeout: Some(WEBSOCKET_CLOSE_DRAIN_TIMEOUT),
            }
        }
    };
    match (deadlines, activity) {
        (Some(deadlines), Some(activity)) => tasks.with_deadlines(deadlines, activity),
        _ => tasks,
    }
}

struct RelayBuffer(FallibleBox<[u8]>);

impl RelayBuffer {
    fn try_new(len: usize) -> Result<Self, UpgradeRelayBuildError> {
        let mut storage = FallibleBox::<[u8]>::try_new_uninit_slice(len)
            .map_err(|_| UpgradeRelayBuildError::Allocation)?;
        for byte in storage.iter_mut() {
            byte.write(0);
        }
        // Every element was initialized in the loop above.
        let storage = unsafe { storage.assume_init() };
        Ok(Self(storage))
    }
}

impl Drop for RelayBuffer {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

async fn relay_opaque_direction<Reader, Writer>(
    mut reader: Reader,
    mut writer: Writer,
    mut buffer: RelayBuffer,
    writes_downstream: bool,
) -> UpgradeTerminalCause
where
    Reader: AsyncRead + Unpin,
    Writer: AsyncWrite + Unpin,
{
    loop {
        let read = match reader.read(&mut buffer.0).await {
            Ok(0) => {
                let _ = writer.shutdown().await;
                return UpgradeTerminalCause::PeerClosed;
            }
            Ok(read) => read,
            Err(_) => return UpgradeTerminalCause::RelayError,
        };
        if writer.write_all(&buffer.0[..read]).await.is_err() {
            return write_failure_cause(writes_downstream);
        }
    }
}

struct ObservedMessage {
    capture: Option<WebSocketMessageCapture>,
}

async fn relay_observed_websocket_direction<Reader, Writer>(
    mut reader: Reader,
    mut writer: Writer,
    mut buffer: RelayBuffer,
    direction: WebSocketDirection,
    negotiation: Option<WebSocketNegotiation>,
    capture_context: UpgradeCaptureContext,
) -> UpgradeTerminalCause
where
    Reader: AsyncRead + Unpin,
    Writer: AsyncWrite + Unpin,
{
    let mut pending: Option<ObservedMessage> = None;
    loop {
        let mut fixed = [0_u8; 2];
        match reader.read(&mut fixed[..1]).await {
            Ok(0) => {
                let _ = writer.shutdown().await;
                return UpgradeTerminalCause::PeerClosed;
            }
            Ok(1) => {}
            Ok(_) => unreachable!("one-byte WebSocket read returned more than one byte"),
            Err(_) => return UpgradeTerminalCause::RelayError,
        }
        if reader.read_exact(&mut fixed[1..]).await.is_err() {
            return UpgradeTerminalCause::RelayError;
        }
        if writer.write_all(&fixed).await.is_err() {
            return write_failure_cause(direction.writes_downstream());
        }

        let fin = fixed[0] & 0x80 != 0;
        let compressed = fixed[0] & 0x40 != 0;
        let reserved_invalid = fixed[0] & 0x30 != 0;
        let opcode = OpCode::parse(fixed[0] & 0x0f).ok();
        let masked = fixed[1] & 0x80 != 0;
        let mut payload_len = u64::from(fixed[1] & 0x7f);
        let mut canonical_length = true;
        if payload_len == 126 {
            let mut extended = [0_u8; 2];
            if reader.read_exact(&mut extended).await.is_err() {
                return UpgradeTerminalCause::RelayError;
            }
            if writer.write_all(&extended).await.is_err() {
                return write_failure_cause(direction.writes_downstream());
            }
            payload_len = u64::from(u16::from_be_bytes(extended));
            canonical_length = payload_len >= 126;
        } else if payload_len == 127 {
            let mut extended = [0_u8; 8];
            if reader.read_exact(&mut extended).await.is_err() {
                return UpgradeTerminalCause::RelayError;
            }
            if writer.write_all(&extended).await.is_err() {
                return write_failure_cause(direction.writes_downstream());
            }
            payload_len = u64::from_be_bytes(extended);
            canonical_length = payload_len > u64::from(u16::MAX) && payload_len & (1 << 63) == 0;
        }

        let mask = if masked {
            let mut mask = [0_u8; 4];
            if reader.read_exact(&mut mask).await.is_err() {
                return UpgradeTerminalCause::RelayError;
            }
            if writer.write_all(&mask).await.is_err() {
                return write_failure_cause(direction.writes_downstream());
            }
            Some(mask)
        } else {
            None
        };

        let frame_observable = canonical_length
            && masked == direction.reads_masked()
            && !reserved_invalid
            && opcode.is_some();
        let closes_direction =
            frame_observable && fin && payload_len <= 125 && opcode == Some(OpCode::Close);
        let mut completed_capture = None;
        let mut frame_capture = match opcode {
            Some(opcode) if opcode.is_control() => {
                if !fin || compressed || payload_len > 125 {
                    pending = None;
                }
                None
            }
            Some(opcode) if opcode.is_data() => {
                let conflicts_with_pending = pending.is_some();
                if conflicts_with_pending {
                    pending = None;
                }
                let class = if opcode == OpCode::Text {
                    PayloadClass::Text
                } else {
                    PayloadClass::Binary
                };
                let compression_valid = negotiation
                    .is_some_and(|negotiation| !compressed || negotiation.permessage_deflate);
                let mut capture =
                    (frame_observable && compression_valid && !conflicts_with_pending)
                        .then(|| capture_context.begin_message(direction, compressed, class))
                        .flatten();
                if capture.as_mut().is_some_and(|capture| {
                    usize::try_from(payload_len)
                        .ok()
                        .is_none_or(|bytes| !capture.begin_frame(bytes))
                }) {
                    capture = None;
                }
                if fin {
                    completed_capture = capture.take();
                } else {
                    pending = Some(ObservedMessage { capture });
                }
                completed_capture.as_mut()
            }
            Some(OpCode::Continuation) => {
                if compressed || !frame_observable {
                    pending = None;
                    None
                } else if fin {
                    completed_capture = pending.take().and_then(|message| message.capture);
                    if completed_capture.as_mut().is_some_and(|capture| {
                        usize::try_from(payload_len)
                            .ok()
                            .is_none_or(|bytes| !capture.begin_frame(bytes))
                    }) {
                        completed_capture = None;
                    }
                    completed_capture.as_mut()
                } else {
                    if let Some(message) = pending.as_mut() {
                        if message.capture.as_mut().is_some_and(|capture| {
                            usize::try_from(payload_len)
                                .ok()
                                .is_none_or(|bytes| !capture.begin_frame(bytes))
                        }) {
                            message.capture = None;
                        }
                        message.capture.as_mut()
                    } else {
                        None
                    }
                }
            }
            _ => {
                pending = None;
                None
            }
        };

        let mut remaining = payload_len;
        let mut offset = 0_u64;
        while remaining != 0 {
            if buffer.0.is_empty() {
                return UpgradeTerminalCause::RelayError;
            }
            let chunk = usize::try_from(remaining.min(buffer.0.len() as u64))
                .expect("relay buffer length fits usize");
            if reader.read_exact(&mut buffer.0[..chunk]).await.is_err() {
                return UpgradeTerminalCause::RelayError;
            }
            if writer.write_all(&buffer.0[..chunk]).await.is_err() {
                return write_failure_cause(direction.writes_downstream());
            }
            if let Some(capture) = frame_capture.as_mut() {
                if let Some(mask) = mask {
                    for (index, byte) in buffer.0[..chunk].iter_mut().enumerate() {
                        *byte ^= mask[((offset as usize) + index) % mask.len()];
                    }
                }
                capture.push_bytes(&buffer.0[..chunk]);
            }
            remaining -= chunk as u64;
            offset += chunk as u64;
        }
        if let Some(capture) = completed_capture {
            capture.finish();
        }
        if closes_direction {
            return UpgradeTerminalCause::PeerClosed;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WebSocketDirection {
    ClientToUpstream,
    UpstreamToClient,
}

impl WebSocketDirection {
    fn reads_masked(self) -> bool {
        self == Self::ClientToUpstream
    }

    fn writes_masked(self) -> bool {
        self == Self::ClientToUpstream
    }

    fn writes_downstream(self) -> bool {
        self == Self::UpstreamToClient
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpCode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl OpCode {
    fn parse(value: u8) -> Result<Self, RelayProtocolError> {
        match value {
            0x0 => Ok(Self::Continuation),
            0x1 => Ok(Self::Text),
            0x2 => Ok(Self::Binary),
            0x8 => Ok(Self::Close),
            0x9 => Ok(Self::Ping),
            0xa => Ok(Self::Pong),
            _ => Err(RelayProtocolError::Protocol),
        }
    }

    fn value(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xa,
        }
    }

    fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }

    fn is_data(self) -> bool {
        matches!(self, Self::Text | Self::Binary)
    }
}

struct Frame {
    fin: bool,
    compressed: bool,
    rsv2: bool,
    rsv3: bool,
    opcode: OpCode,
    payload: Vec<u8>,
}

struct PendingMessage {
    opcode: OpCode,
    compressed: bool,
    payload: Vec<u8>,
    capture: Option<WebSocketMessageCapture>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelayProtocolError {
    Io,
    Protocol,
    FrameTooLarge,
    MessageTooLarge,
    Compression,
    Allocation,
}

async fn relay_websocket_direction<Reader, Writer>(
    reader: Reader,
    writer: Writer,
    profile: ProfileHandle,
    extensions: WebSocketNegotiation,
    direction: WebSocketDirection,
    capture_context: Option<UpgradeCaptureContext>,
) -> UpgradeTerminalCause
where
    Reader: AsyncRead + Unpin,
    Writer: AsyncWrite + Unpin,
{
    relay_websocket_direction_with_boundary(
        reader,
        writer,
        profile,
        extensions,
        direction,
        capture_context,
        || {},
    )
    .await
}

async fn relay_websocket_direction_with_boundary<Reader, Writer, Boundary>(
    mut reader: Reader,
    mut writer: Writer,
    profile: ProfileHandle,
    extensions: WebSocketNegotiation,
    direction: WebSocketDirection,
    capture_context: Option<UpgradeCaptureContext>,
    mut on_message_boundary: Boundary,
) -> UpgradeTerminalCause
where
    Reader: AsyncRead + Unpin,
    Writer: AsyncWrite + Unpin,
    Boundary: FnMut(),
{
    let mut pending: Option<PendingMessage> = None;
    loop {
        let header = match read_frame_header(&mut reader, direction.reads_masked(), &profile).await
        {
            Ok(Some(header)) => header,
            Ok(None) => {
                let _ = writer.shutdown().await;
                return UpgradeTerminalCause::PeerClosed;
            }
            Err(error) => {
                let _ =
                    write_close(&mut writer, direction.writes_masked(), close_code(error)).await;
                return UpgradeTerminalCause::RelayError;
            }
        };

        if header.opcode.is_control() {
            if !header.fin
                || header.payload_len > 125
                || header.compressed
                || header.rsv2
                || header.rsv3
            {
                let _ =
                    write_close(&mut writer, direction.writes_masked(), CLOSE_PROTOCOL_ERROR).await;
                return UpgradeTerminalCause::RelayError;
            }
            let frame = match read_frame_payload(&mut reader, header).await {
                Ok(frame) => frame,
                Err(error) => {
                    let _ = write_close(&mut writer, direction.writes_masked(), close_code(error))
                        .await;
                    return UpgradeTerminalCause::RelayError;
                }
            };
            let frame = if direction == WebSocketDirection::ClientToUpstream {
                match redact_client_control_frame(frame, &profile) {
                    Ok(frame) => frame,
                    Err(error) => {
                        let _ =
                            write_close(&mut writer, direction.writes_masked(), close_code(error))
                                .await;
                        return UpgradeTerminalCause::RelayError;
                    }
                }
            } else {
                frame
            };
            let closing = frame.opcode == OpCode::Close;
            if write_frame(&mut writer, frame, direction.writes_masked())
                .await
                .is_err()
            {
                return write_failure_cause(direction.writes_downstream());
            }
            if closing {
                return UpgradeTerminalCause::PeerClosed;
            }
            continue;
        }

        if header.rsv2 || header.rsv3 {
            let _ = write_close(&mut writer, direction.writes_masked(), CLOSE_PROTOCOL_ERROR).await;
            return UpgradeTerminalCause::RelayError;
        }

        if header.opcode.is_data() {
            if pending.is_some() || (header.compressed && !extensions.permessage_deflate) {
                let _ =
                    write_close(&mut writer, direction.writes_masked(), CLOSE_PROTOCOL_ERROR).await;
                return UpgradeTerminalCause::RelayError;
            }
            if profile
                .validate_encoded_websocket_message_size(header.payload_len)
                .is_err()
            {
                let _ = write_close(
                    &mut writer,
                    direction.writes_masked(),
                    CLOSE_MESSAGE_TOO_BIG,
                )
                .await;
                return UpgradeTerminalCause::RelayError;
            }
            let class = if header.opcode == OpCode::Text {
                PayloadClass::Text
            } else {
                PayloadClass::Binary
            };
            let mut message_capture = capture_context
                .as_ref()
                .and_then(|capture| capture.begin_message(direction, header.compressed, class));
            if message_capture
                .as_mut()
                .is_some_and(|capture| !capture.begin_frame(header.payload_len))
            {
                message_capture = None;
            }
            on_message_boundary();
            let frame = match read_frame_payload(&mut reader, header).await {
                Ok(frame) => frame,
                Err(error) => {
                    let _ = write_close(&mut writer, direction.writes_masked(), close_code(error))
                        .await;
                    return UpgradeTerminalCause::RelayError;
                }
            };
            if message_capture
                .as_mut()
                .is_some_and(|capture| !capture.push_bytes(&frame.payload))
            {
                message_capture = None;
            }
            if frame.fin {
                if forward_websocket_message(
                    &mut writer,
                    frame.opcode,
                    frame.compressed,
                    frame.payload,
                    &profile,
                    extensions,
                    direction,
                )
                .await
                .is_err()
                {
                    return UpgradeTerminalCause::RelayError;
                }
                if let Some(capture) = message_capture {
                    capture.finish();
                }
            } else {
                pending = Some(PendingMessage {
                    opcode: frame.opcode,
                    compressed: frame.compressed,
                    payload: frame.payload,
                    capture: message_capture,
                });
            }
            continue;
        }

        let Some(message) = pending.as_ref() else {
            let _ = write_close(&mut writer, direction.writes_masked(), CLOSE_PROTOCOL_ERROR).await;
            return UpgradeTerminalCause::RelayError;
        };
        if header.compressed {
            let _ = write_close(&mut writer, direction.writes_masked(), CLOSE_PROTOCOL_ERROR).await;
            return UpgradeTerminalCause::RelayError;
        }
        let Some(message_len) = message.payload.len().checked_add(header.payload_len) else {
            let _ = write_close(
                &mut writer,
                direction.writes_masked(),
                CLOSE_MESSAGE_TOO_BIG,
            )
            .await;
            return UpgradeTerminalCause::RelayError;
        };
        if profile
            .validate_encoded_websocket_message_size(message_len)
            .is_err()
        {
            let _ = write_close(
                &mut writer,
                direction.writes_masked(),
                CLOSE_MESSAGE_TOO_BIG,
            )
            .await;
            return UpgradeTerminalCause::RelayError;
        }
        let message = pending.as_mut().expect("pending WebSocket message exists");
        if message
            .capture
            .as_mut()
            .is_some_and(|capture| !capture.begin_frame(header.payload_len))
        {
            message.capture = None;
        }
        let frame = match read_frame_payload(&mut reader, header).await {
            Ok(frame) => frame,
            Err(error) => {
                let _ =
                    write_close(&mut writer, direction.writes_masked(), close_code(error)).await;
                return UpgradeTerminalCause::RelayError;
            }
        };
        if message
            .capture
            .as_mut()
            .is_some_and(|capture| !capture.push_bytes(&frame.payload))
        {
            message.capture = None;
        }
        if message
            .payload
            .try_reserve_exact(frame.payload.len())
            .is_err()
        {
            let _ = write_close(&mut writer, direction.writes_masked(), CLOSE_PROTOCOL_ERROR).await;
            return UpgradeTerminalCause::RelayError;
        }
        message.payload.extend_from_slice(&frame.payload);
        if frame.fin {
            let message = pending.take().expect("pending WebSocket message exists");
            let message_capture = message.capture;
            if forward_websocket_message(
                &mut writer,
                message.opcode,
                message.compressed,
                message.payload,
                &profile,
                extensions,
                direction,
            )
            .await
            .is_err()
            {
                return UpgradeTerminalCause::RelayError;
            }
            if let Some(capture) = message_capture {
                capture.finish();
            }
        }
    }
}

fn redact_client_control_frame(
    mut frame: Frame,
    profile: &ProfileHandle,
) -> Result<Frame, RelayProtocolError> {
    let payload = std::mem::take(&mut frame.payload);
    frame.payload = match frame.opcode {
        OpCode::Ping | OpCode::Pong => {
            redact_control_payload(profile, payload, PayloadClass::Binary)?
        }
        OpCode::Close => match payload.len() {
            0 => Vec::new(),
            1 => return Err(RelayProtocolError::Protocol),
            _ => {
                let mut output = payload[..2].to_vec();
                let reason = payload[2..].to_vec();
                std::str::from_utf8(&reason).map_err(|_| RelayProtocolError::Protocol)?;
                let reason = redact_control_payload(profile, reason, PayloadClass::Text)?;
                output.extend_from_slice(&reason);
                output
            }
        },
        _ => return Err(RelayProtocolError::Protocol),
    };
    if frame.payload.len() > 125 {
        return Err(RelayProtocolError::FrameTooLarge);
    }
    Ok(frame)
}

fn redact_control_payload(
    profile: &ProfileHandle,
    payload: Vec<u8>,
    class: PayloadClass,
) -> Result<Vec<u8>, RelayProtocolError> {
    let mut redacted = profile
        .redact_websocket_message(payload, class)
        .map_err(|_| RelayProtocolError::MessageTooLarge)?;
    Ok(std::mem::take(&mut redacted.bytes))
}

async fn forward_websocket_message<Writer>(
    writer: &mut Writer,
    opcode: OpCode,
    compressed: bool,
    encoded: Vec<u8>,
    profile: &ProfileHandle,
    extensions: WebSocketNegotiation,
    direction: WebSocketDirection,
) -> Result<(), RelayProtocolError>
where
    Writer: AsyncWrite + Unpin,
{
    let decoded = if compressed {
        if !extensions.permessage_deflate {
            return Err(RelayProtocolError::Protocol);
        }
        decompress_message(&encoded, profile.limits().max_message_bytes)?
    } else {
        encoded.clone()
    };
    profile
        .validate_encoded_websocket_message_size(decoded.len())
        .map_err(|_| RelayProtocolError::MessageTooLarge)?;
    let class = match opcode {
        OpCode::Text => {
            std::str::from_utf8(&decoded).map_err(|_| RelayProtocolError::Protocol)?;
            PayloadClass::Text
        }
        OpCode::Binary => PayloadClass::Binary,
        _ => return Err(RelayProtocolError::Protocol),
    };

    let output = if direction == WebSocketDirection::ClientToUpstream {
        let mut redacted = profile
            .redact_websocket_message(decoded, class)
            .map_err(|_| RelayProtocolError::MessageTooLarge)?;
        let redacted_bytes = std::mem::take(&mut redacted.bytes);
        if compressed {
            compress_message(&redacted_bytes)?
        } else {
            redacted_bytes
        }
    } else {
        encoded
    };

    write_frame(
        writer,
        Frame {
            fin: true,
            compressed,
            rsv2: false,
            rsv3: false,
            opcode,
            payload: output,
        },
        direction.writes_masked(),
    )
    .await
}

struct FrameHeader {
    fin: bool,
    compressed: bool,
    rsv2: bool,
    rsv3: bool,
    opcode: OpCode,
    payload_len: usize,
    mask: Option<[u8; 4]>,
}

async fn read_frame_header<Reader>(
    reader: &mut Reader,
    expect_masked: bool,
    profile: &ProfileHandle,
) -> Result<Option<FrameHeader>, RelayProtocolError>
where
    Reader: AsyncRead + Unpin,
{
    let mut header = [0_u8; 2];
    match reader.read(&mut header[..1]).await {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!("one-byte WebSocket read returned more than one byte"),
        Err(_) => return Err(RelayProtocolError::Io),
    }
    reader
        .read_exact(&mut header[1..])
        .await
        .map_err(|_| RelayProtocolError::Io)?;

    let fin = header[0] & 0x80 != 0;
    let compressed = header[0] & 0x40 != 0;
    let rsv2 = header[0] & 0x20 != 0;
    let rsv3 = header[0] & 0x10 != 0;
    let opcode = OpCode::parse(header[0] & 0x0f)?;
    let masked = header[1] & 0x80 != 0;
    if masked != expect_masked {
        return Err(RelayProtocolError::Protocol);
    }

    let mut len = u64::from(header[1] & 0x7f);
    if len == 126 {
        let mut extended = [0_u8; 2];
        reader
            .read_exact(&mut extended)
            .await
            .map_err(|_| RelayProtocolError::Io)?;
        len = u64::from(u16::from_be_bytes(extended));
        if len < 126 {
            return Err(RelayProtocolError::Protocol);
        }
    } else if len == 127 {
        let mut extended = [0_u8; 8];
        reader
            .read_exact(&mut extended)
            .await
            .map_err(|_| RelayProtocolError::Io)?;
        len = u64::from_be_bytes(extended);
        if len <= u64::from(u16::MAX) || len & (1 << 63) != 0 {
            return Err(RelayProtocolError::Protocol);
        }
    }
    let payload_len = usize::try_from(len).map_err(|_| RelayProtocolError::FrameTooLarge)?;
    profile
        .validate_websocket_frame_size(payload_len)
        .map_err(|_| RelayProtocolError::FrameTooLarge)?;

    let mask = if masked {
        let mut mask = [0_u8; 4];
        reader
            .read_exact(&mut mask)
            .await
            .map_err(|_| RelayProtocolError::Io)?;
        Some(mask)
    } else {
        None
    };
    Ok(Some(FrameHeader {
        fin,
        compressed,
        rsv2,
        rsv3,
        opcode,
        payload_len,
        mask,
    }))
}

async fn read_frame_payload<Reader>(
    reader: &mut Reader,
    header: FrameHeader,
) -> Result<Frame, RelayProtocolError>
where
    Reader: AsyncRead + Unpin,
{
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(header.payload_len)
        .map_err(|_| RelayProtocolError::Allocation)?;
    payload.resize(header.payload_len, 0);
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| RelayProtocolError::Io)?;
    if let Some(mask) = header.mask {
        apply_mask(&mut payload, mask);
    }
    Ok(Frame {
        fin: header.fin,
        compressed: header.compressed,
        rsv2: header.rsv2,
        rsv3: header.rsv3,
        opcode: header.opcode,
        payload,
    })
}

async fn write_frame<Writer>(
    writer: &mut Writer,
    mut frame: Frame,
    masked: bool,
) -> Result<(), RelayProtocolError>
where
    Writer: AsyncWrite + Unpin,
{
    let mut header = [0_u8; 14];
    let mut first = (frame.fin as u8) << 7 | frame.opcode.value();
    if frame.compressed {
        first |= 0x40;
    }
    if frame.rsv2 {
        first |= 0x20;
    }
    if frame.rsv3 {
        first |= 0x10;
    }
    header[0] = first;
    let mask_bit = if masked { 0x80 } else { 0 };
    let mut header_len = 2;
    if frame.payload.len() < 126 {
        header[1] = mask_bit | frame.payload.len() as u8;
    } else if frame.payload.len() <= usize::from(u16::MAX) {
        header[1] = mask_bit | 126;
        header[2..4].copy_from_slice(&(frame.payload.len() as u16).to_be_bytes());
        header_len = 4;
    } else {
        header[1] = mask_bit | 127;
        header[2..10].copy_from_slice(&(frame.payload.len() as u64).to_be_bytes());
        header_len = 10;
    }
    if masked {
        let mask = rand::random::<[u8; 4]>();
        apply_mask(&mut frame.payload, mask);
        header[header_len..header_len + 4].copy_from_slice(&mask);
        header_len += 4;
    }
    writer
        .write_all(&header[..header_len])
        .await
        .map_err(|_| RelayProtocolError::Io)?;
    writer
        .write_all(&frame.payload)
        .await
        .map_err(|_| RelayProtocolError::Io)?;
    writer.flush().await.map_err(|_| RelayProtocolError::Io)
}

async fn write_close<Writer>(
    writer: &mut Writer,
    masked: bool,
    code: u16,
) -> Result<(), RelayProtocolError>
where
    Writer: AsyncWrite + Unpin,
{
    write_frame(
        writer,
        Frame {
            fin: true,
            compressed: false,
            rsv2: false,
            rsv3: false,
            opcode: OpCode::Close,
            payload: code.to_be_bytes().to_vec(),
        },
        masked,
    )
    .await
}

fn close_code(error: RelayProtocolError) -> u16 {
    match error {
        RelayProtocolError::FrameTooLarge | RelayProtocolError::MessageTooLarge => {
            CLOSE_MESSAGE_TOO_BIG
        }
        RelayProtocolError::Io
        | RelayProtocolError::Protocol
        | RelayProtocolError::Compression
        | RelayProtocolError::Allocation => CLOSE_PROTOCOL_ERROR,
    }
}

fn write_failure_cause(writes_downstream: bool) -> UpgradeTerminalCause {
    if writes_downstream {
        UpgradeTerminalCause::DownstreamWriteFailed
    } else {
        UpgradeTerminalCause::RelayError
    }
}

fn apply_mask(payload: &mut [u8], mask: [u8; 4]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % mask.len()];
    }
}

fn decompress_message(payload: &[u8], limit: usize) -> Result<Vec<u8>, RelayProtocolError> {
    let capacity = payload
        .len()
        .checked_add(DEFLATE_TAIL.len())
        .ok_or(RelayProtocolError::MessageTooLarge)?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(capacity)
        .map_err(|_| RelayProtocolError::Allocation)?;
    input.extend_from_slice(payload);
    input.extend_from_slice(&DEFLATE_TAIL);
    let mut decoder = DeflateDecoder::new(input.as_slice());
    let mut output = Vec::new();
    let read = decoder
        .by_ref()
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut output)
        .map_err(|_| RelayProtocolError::Compression)?;
    if read > limit {
        return Err(RelayProtocolError::MessageTooLarge);
    }
    Ok(output)
}

fn compress_message(payload: &[u8]) -> Result<Vec<u8>, RelayProtocolError> {
    let mut encoder = Compress::new(Compression::default(), false);
    let mut output = Vec::new();
    output
        .try_reserve_exact(payload.len().saturating_add(64))
        .map_err(|_| RelayProtocolError::Allocation)?;
    for _ in 0..8 {
        if output.capacity() == output.len() {
            output
                .try_reserve(payload.len().max(64))
                .map_err(|_| RelayProtocolError::Allocation)?;
        }
        let consumed =
            usize::try_from(encoder.total_in()).map_err(|_| RelayProtocolError::Compression)?;
        let input = payload
            .get(consumed..)
            .ok_or(RelayProtocolError::Compression)?;
        encoder
            .compress_vec(input, &mut output, FlushCompress::Sync)
            .map_err(|_| RelayProtocolError::Compression)?;
        if encoder.total_in() == payload.len() as u64 && output.ends_with(&DEFLATE_TAIL) {
            output.truncate(output.len() - DEFLATE_TAIL.len());
            return Ok(output);
        }
    }
    Err(RelayProtocolError::Compression)
}

struct ParsedExtension {
    name: String,
    parameters: Vec<(String, Option<String>)>,
}

fn parse_request_extensions(headers: &HeaderMap) -> Result<bool, UpgradeRelayBuildError> {
    let extensions = parse_extensions(headers)?;
    let mut permessage_deflate = false;
    for extension in extensions {
        if extension.name != "permessage-deflate" {
            return Err(UpgradeRelayBuildError::UnsupportedRequestExtension);
        }
        if permessage_deflate {
            return Err(UpgradeRelayBuildError::InvalidExtensionHeader);
        }
        permessage_deflate = true;
        let mut seen = Vec::new();
        for (name, value) in extension.parameters {
            if seen.iter().any(|existing| existing == &name) {
                return Err(UpgradeRelayBuildError::InvalidExtensionHeader);
            }
            seen.push(name.clone());
            match name.as_str() {
                "client_no_context_takeover" | "server_no_context_takeover" if value.is_none() => {}
                "client_max_window_bits" | "server_max_window_bits" => {}
                _ => return Err(UpgradeRelayBuildError::UnsupportedRequestExtension),
            }
        }
    }
    Ok(permessage_deflate)
}

fn parse_response_extensions(
    headers: &HeaderMap,
    offered: bool,
) -> Result<bool, UpgradeRelayBuildError> {
    let extensions = parse_extensions(headers)?;
    if extensions.is_empty() {
        return Ok(false);
    }
    if !offered || extensions.len() != 1 || extensions[0].name != "permessage-deflate" {
        return Err(UpgradeRelayBuildError::UnsupportedResponseExtension);
    }
    let mut client_no_context_takeover = false;
    let mut server_no_context_takeover = false;
    for (name, value) in &extensions[0].parameters {
        if value.is_some() {
            return Err(UpgradeRelayBuildError::UnsupportedResponseExtension);
        }
        match name.as_str() {
            "client_no_context_takeover" if !client_no_context_takeover => {
                client_no_context_takeover = true;
            }
            "server_no_context_takeover" if !server_no_context_takeover => {
                server_no_context_takeover = true;
            }
            _ => return Err(UpgradeRelayBuildError::UnsupportedResponseExtension),
        }
    }
    if !client_no_context_takeover || !server_no_context_takeover {
        return Err(UpgradeRelayBuildError::UnsupportedResponseExtension);
    }
    Ok(true)
}

fn parse_extensions(headers: &HeaderMap) -> Result<Vec<ParsedExtension>, UpgradeRelayBuildError> {
    let mut parsed = Vec::new();
    let header = HeaderName::from_static(SEC_WEBSOCKET_EXTENSIONS);
    for value in headers.get_all(header) {
        let value = value
            .to_str()
            .map_err(|_| UpgradeRelayBuildError::InvalidExtensionHeader)?;
        for raw_extension in value.split(',') {
            let mut parts = raw_extension.split(';').map(str::trim);
            let name = parts
                .next()
                .filter(|name| is_token(name))
                .ok_or(UpgradeRelayBuildError::InvalidExtensionHeader)?;
            let mut parameters = Vec::new();
            for parameter in parts {
                if parameter.is_empty() {
                    return Err(UpgradeRelayBuildError::InvalidExtensionHeader);
                }
                let (name, value) = match parameter.split_once('=') {
                    Some((name, value)) if is_token(name.trim()) && is_token(value.trim()) => {
                        (name.trim(), Some(value.trim().to_ascii_lowercase()))
                    }
                    Some(_) => return Err(UpgradeRelayBuildError::InvalidExtensionHeader),
                    None if is_token(parameter) => (parameter, None),
                    None => return Err(UpgradeRelayBuildError::InvalidExtensionHeader),
                };
                parameters.push((name.to_ascii_lowercase(), value));
            }
            parsed.push(ParsedExtension {
                name: name.to_ascii_lowercase(),
                parameters,
            });
        }
    }
    Ok(parsed)
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
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
                    | b'a'..=b'z'
                    | b'A'..=b'Z'
            )
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;
    use crate::capture::{
        CaptureDecision, CaptureEndpoint, CaptureMode, CaptureRecord, CaptureSinkSpec,
    };
    use crate::config::compiler::{
        CapturePlan, CaptureWorkingSetPlan, CompiledCaptureEvent, CompiledRedactionPayloads,
        ObservationPlan, RedactionPlan, RedactionProfilePlan, RedactionRulePlan,
    };
    use crate::observation::ProductObservationRuntime;
    use crate::redaction::{RedactionActivation, RedactionSnapshot};
    use crate::runtime::GenerationOwner;

    fn profile(
        max_frame_bytes: usize,
        max_message_bytes: usize,
        allow_permessage_deflate: bool,
    ) -> ProfileHandle {
        let plan = RedactionPlan {
            profiles: BTreeMap::from([(
                "wire".to_owned(),
                RedactionProfilePlan {
                    replacement: b"[MASKED]".to_vec(),
                    max_body_bytes: max_message_bytes,
                    max_decoded_body_bytes: max_message_bytes,
                    max_frame_bytes,
                    max_message_bytes,
                    allow_permessage_deflate,
                    max_environment_literal_sources: 0,
                    max_environment_literal_bytes: 1,
                    max_environment_literal_total_bytes: 1,
                    rules: vec![RedactionRulePlan {
                        literals: vec![b"secret".to_vec()],
                        literal_environment_variables: Vec::new(),
                        expressions: Vec::new(),
                        payloads: CompiledRedactionPayloads::Both,
                    }],
                },
            )]),
        };
        RedactionSnapshot::activate(plan, || false)
            .unwrap()
            .profile("wire")
            .unwrap()
    }

    fn redaction_activation(name: &str, replacement: &[u8], literal: &[u8]) -> RedactionActivation {
        RedactionSnapshot::activate(
            RedactionPlan {
                profiles: BTreeMap::from([(
                    name.to_owned(),
                    RedactionProfilePlan {
                        replacement: replacement.to_vec(),
                        max_body_bytes: 1024,
                        max_decoded_body_bytes: 1024,
                        max_frame_bytes: 1024,
                        max_message_bytes: 1024,
                        allow_permessage_deflate: true,
                        max_environment_literal_sources: 0,
                        max_environment_literal_bytes: 1,
                        max_environment_literal_total_bytes: 1,
                        rules: vec![RedactionRulePlan {
                            literals: vec![literal.to_vec()],
                            literal_environment_variables: Vec::new(),
                            expressions: Vec::new(),
                            payloads: CompiledRedactionPayloads::Both,
                        }],
                    },
                )]),
            },
            || false,
        )
        .unwrap()
    }

    fn publish_capture_epoch(
        runtime: &ProductObservationRuntime,
        directory: &Path,
        limit: usize,
        replacement: &[u8],
    ) -> (RedactionActivation, Arc<dyn GenerationOwner>) {
        let redaction = redaction_activation("capture", replacement, b"secret");
        let activation = runtime
            .activate(
                ObservationPlan {
                    capture: Some(CapturePlan {
                        events: vec![
                            CompiledCaptureEvent::RequestAllowed,
                            CompiledCaptureEvent::ResponseAllowed,
                        ],
                        redaction_profile: "capture".to_owned(),
                        sink: CaptureSinkSpec::new(
                            directory.to_path_buf(),
                            "{requestId}-{suffix}.json".to_owned(),
                            32,
                            1024 * 1024,
                        )
                        .unwrap(),
                        max_body_bytes: 1024,
                        max_inflight_body_bytes: limit,
                        working_set: CaptureWorkingSetPlan::default(),
                    }),
                    ..ObservationPlan::default()
                },
                &redaction,
            )
            .unwrap();
        let (_snapshot, owner) = activation.into_parts();
        owner.publication_guard().unwrap().commit();
        (redaction, owner)
    }

    fn upgrade_capture_context(runtime: Arc<ProductObservationRuntime>) -> UpgradeCaptureContext {
        UpgradeCaptureContext::new(
            runtime,
            SanitizedCaptureMetadata::from_test_record(CaptureRecord {
                timestamp: "not-retained".to_owned(),
                request_id: "upgrade".to_owned(),
                kind: CaptureKind::Request,
                decision: CaptureDecision::Allow,
                mode: CaptureMode::HttpProxy,
                url: "http://example.test/socket".to_owned(),
                method: "GET".to_owned(),
                status_code: None,
                status_message: None,
                client: CaptureEndpoint {
                    address: Some("192.0.2.1".to_owned()),
                    port: Some(41000),
                },
                target: Some(CaptureEndpoint {
                    address: Some("example.test".to_owned()),
                    port: Some(80),
                }),
                http_version: Some("1.1".to_owned()),
                headers: None,
                body: None,
                body_truncated: None,
                provider_replacement_omitted: None,
                provider_replacement_size: None,
            }),
            16,
        )
    }

    fn capture_records(directory: &Path) -> Vec<CaptureRecord> {
        let mut records = fs::read_dir(directory)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|value| value == "json")
            })
            .map(|entry| serde_json::from_slice(&fs::read(entry.path()).unwrap()).unwrap())
            .collect::<Vec<_>>();
        records.sort_by(|left: &CaptureRecord, right| left.request_id.cmp(&right.request_id));
        records
    }

    fn headers(value: Option<&'static str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = value {
            headers.insert(
                HeaderName::from_static(SEC_WEBSOCKET_EXTENSIONS),
                HeaderValue::from_static(value),
            );
        }
        headers
    }

    fn websocket_kind(profile: &ProfileHandle, compressed: bool) -> EstablishedUpgradeKind {
        let request = headers(compressed.then_some("permessage-deflate"));
        let response = headers(compressed.then_some(
            "permessage-deflate; client_no_context_takeover; server_no_context_takeover",
        ));
        EstablishedUpgradeKind::from_handshake(
            &HeaderValue::from_static("websocket"),
            &request,
            &response,
            Some(profile),
        )
        .unwrap()
    }

    fn observed_websocket_kind(
        request_extensions: Option<&'static str>,
        response_extensions: Option<&'static str>,
    ) -> EstablishedUpgradeKind {
        EstablishedUpgradeKind::from_handshake(
            &HeaderValue::from_static("websocket"),
            &headers(request_extensions),
            &headers(response_extensions),
            None,
        )
        .unwrap()
    }

    fn establish_test_streams(
        kind: EstablishedUpgradeKind,
        relay_buffer_bytes: usize,
    ) -> (DuplexStream, DuplexStream, RelayTasks) {
        establish_test_streams_with_capture(kind, relay_buffer_bytes, None)
    }

    fn establish_test_streams_with_capture(
        kind: EstablishedUpgradeKind,
        relay_buffer_bytes: usize,
        capture: Option<UpgradeCaptureContext>,
    ) -> (DuplexStream, DuplexStream, RelayTasks) {
        let prepared = kind.prepare(relay_buffer_bytes, capture).unwrap();
        let (downstream_peer, downstream_relay) = duplex(4096);
        let (upstream_peer, upstream_relay) = duplex(4096);
        let tasks = build_relay_tasks(downstream_relay, upstream_relay, prepared.kind);
        (downstream_peer, upstream_peer, tasks)
    }

    fn establish_timed_opaque_streams(
        deadlines: UpgradeRelayDeadlines,
    ) -> (DuplexStream, DuplexStream, RelayTasks) {
        let prepared = EstablishedUpgradeKind::Opaque.prepare(8, None).unwrap();
        let (downstream_peer, downstream_relay) = duplex(4096);
        let (upstream_peer, upstream_relay) = duplex(4096);
        let tasks = build_relay_tasks_with_deadlines(
            downstream_relay,
            upstream_relay,
            prepared.kind,
            Some(deadlines),
        );
        (downstream_peer, upstream_peer, tasks)
    }

    fn wire_frame(
        fin: bool,
        compressed: bool,
        opcode: u8,
        masked: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        assert!(payload.len() <= usize::from(u16::MAX));
        let mut frame =
            vec![(if fin { 0x80 } else { 0 }) | (if compressed { 0x40 } else { 0 }) | opcode];
        let mask_bit = if masked { 0x80 } else { 0 };
        if payload.len() < 126 {
            frame.push(mask_bit | payload.len() as u8);
        } else {
            frame.push(mask_bit | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        if masked {
            let mask = [0x11, 0x22, 0x33, 0x44];
            frame.extend_from_slice(&mask);
            frame.extend(
                payload
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ mask[index % 4]),
            );
        } else {
            frame.extend_from_slice(payload);
        }
        frame
    }

    async fn read_wire_frame(stream: &mut DuplexStream) -> (bool, bool, u8, Vec<u8>) {
        let mut header = [0_u8; 2];
        stream.read_exact(&mut header).await.unwrap();
        let mut len = usize::from(header[1] & 0x7f);
        if len == 126 {
            let mut extended = [0_u8; 2];
            stream.read_exact(&mut extended).await.unwrap();
            len = usize::from(u16::from_be_bytes(extended));
        }
        assert_ne!(len, 127);
        let masked = header[1] & 0x80 != 0;
        let mask = if masked {
            let mut mask = [0_u8; 4];
            stream.read_exact(&mut mask).await.unwrap();
            Some(mask)
        } else {
            None
        };
        let mut payload = vec![0_u8; len];
        stream.read_exact(&mut payload).await.unwrap();
        if let Some(mask) = mask {
            apply_mask(&mut payload, mask);
        }
        (
            header[0] & 0x80 != 0,
            header[0] & 0x40 != 0,
            header[0] & 0x0f,
            payload,
        )
    }

    #[tokio::test]
    async fn opaque_relay_is_bidirectional_and_closes_without_detached_work() {
        let (mut downstream, mut upstream, tasks) =
            establish_test_streams(EstablishedUpgradeKind::Opaque, 7);
        let client_to_upstream = tokio::spawn(tasks.client_to_upstream);
        let upstream_to_client = tokio::spawn(tasks.upstream_to_client);

        downstream.write_all(b"client payload").await.unwrap();
        let mut received = [0_u8; 14];
        upstream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"client payload");

        downstream.shutdown().await.unwrap();
        assert_eq!(
            client_to_upstream.await.unwrap(),
            UpgradeTerminalCause::PeerClosed
        );

        upstream.write_all(b"server payload").await.unwrap();
        let mut received = [0_u8; 14];
        downstream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"server payload");

        upstream.shutdown().await.unwrap();
        assert_eq!(
            upstream_to_client.await.unwrap(),
            UpgradeTerminalCause::PeerClosed
        );
        drop((downstream, upstream));
    }

    #[tokio::test]
    async fn upgrade_idle_is_shared_across_both_relay_directions() {
        let deadlines = UpgradeRelayDeadlines::new(
            Duration::from_millis(40),
            Instant::now() + Duration::from_secs(2),
        );
        let (mut downstream, mut upstream, tasks) = establish_timed_opaque_streams(deadlines);
        let mut client_to_upstream = tokio::spawn(tasks.client_to_upstream);
        let mut upstream_to_client = tokio::spawn(tasks.upstream_to_client);

        for byte in 0_u8..5 {
            downstream.write_all(&[byte]).await.unwrap();
            let mut relayed = [0_u8; 1];
            upstream.read_exact(&mut relayed).await.unwrap();
            assert_eq!(relayed, [byte]);
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(!client_to_upstream.is_finished());
            assert!(!upstream_to_client.is_finished());
        }

        let (first, client_finished) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                cause = &mut client_to_upstream => (cause.unwrap(), true),
                cause = &mut upstream_to_client => (cause.unwrap(), false),
            }
        })
        .await
        .unwrap();
        assert_eq!(first, UpgradeTerminalCause::IdleTimeout);
        if client_finished {
            upstream_to_client.abort();
            let _ = upstream_to_client.await;
        } else {
            client_to_upstream.abort();
            let _ = client_to_upstream.await;
        }
    }

    #[tokio::test]
    async fn upgrade_absolute_deadline_is_not_reset_by_activity() {
        let absolute = Instant::now() + Duration::from_millis(120);
        let deadlines = UpgradeRelayDeadlines::new(Duration::from_secs(1), absolute);
        let (mut downstream, mut upstream, tasks) = establish_timed_opaque_streams(deadlines);
        let mut client_to_upstream = tokio::spawn(tasks.client_to_upstream);
        let mut upstream_to_client = tokio::spawn(tasks.upstream_to_client);
        let traffic = tokio::spawn(async move {
            loop {
                if downstream.write_all(b"x").await.is_err() {
                    break;
                }
                let mut relayed = [0_u8; 1];
                if upstream.read_exact(&mut relayed).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        let (first, client_finished) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                cause = &mut client_to_upstream => (cause.unwrap(), true),
                cause = &mut upstream_to_client => (cause.unwrap(), false),
            }
        })
        .await
        .unwrap();
        assert_eq!(first, UpgradeTerminalCause::LifetimeExpired);
        if client_finished {
            upstream_to_client.abort();
            let _ = upstream_to_client.await;
        } else {
            client_to_upstream.abort();
            let _ = client_to_upstream.await;
        }
        traffic.abort();
        let _ = traffic.await;
    }

    #[tokio::test]
    async fn dropping_unpolled_relay_futures_closes_both_owned_streams() {
        let (mut downstream, mut upstream, tasks) =
            establish_test_streams(EstablishedUpgradeKind::Opaque, 8);
        drop(tasks);
        let mut byte = [0_u8; 1];
        assert_eq!(downstream.read(&mut byte).await.unwrap(), 0);
        assert_eq!(upstream.read(&mut byte).await.unwrap(), 0);
    }

    #[test]
    fn opaque_preparation_allocates_two_exact_buffers_and_is_atomic_on_failure() {
        let requested = Arc::new(Mutex::new(Vec::new()));
        let observed = requested.clone();
        let result = EstablishedUpgradeKind::Opaque.prepare_with(37, None, move |len| {
            let mut requested = observed.lock().unwrap();
            requested.push(len);
            if requested.len() == 2 {
                Err(UpgradeRelayBuildError::Allocation)
            } else {
                RelayBuffer::try_new(len)
            }
        });
        let error = match result {
            Ok(_) => panic!("the injected second allocation must fail"),
            Err(error) => error,
        };
        assert_eq!(error, UpgradeRelayBuildError::Allocation);
        assert_eq!(*requested.lock().unwrap(), vec![37, 37]);
    }

    #[tokio::test]
    async fn protected_websocket_redacts_only_client_to_upstream_messages() {
        let profile = profile(128, 256, true);
        let (mut downstream, mut upstream, tasks) =
            establish_test_streams(websocket_kind(&profile, true), 8);
        let client_to_upstream = tokio::spawn(tasks.client_to_upstream);
        let upstream_to_client = tokio::spawn(tasks.upstream_to_client);

        let compressed = compress_message(b"client secret").unwrap();
        downstream
            .write_all(&wire_frame(true, true, 0x1, true, &compressed))
            .await
            .unwrap();
        let (_, compressed, opcode, payload) = read_wire_frame(&mut upstream).await;
        assert!(compressed);
        assert_eq!(opcode, 0x1);
        assert_eq!(
            decompress_message(&payload, 256).unwrap(),
            b"client [MASKED]"
        );

        upstream
            .write_all(&wire_frame(true, false, 0x1, false, b"server secret"))
            .await
            .unwrap();
        let (_, compressed, opcode, payload) = read_wire_frame(&mut downstream).await;
        assert!(!compressed);
        assert_eq!(opcode, 0x1);
        assert_eq!(payload, b"server secret");

        drop(downstream);
        drop(upstream);
        client_to_upstream.await.unwrap();
        upstream_to_client.await.unwrap();
    }

    #[tokio::test]
    async fn protected_websocket_redacts_client_control_frame_application_data() {
        let profile = profile(128, 256, false);
        let (mut downstream, mut upstream, tasks) =
            establish_test_streams(websocket_kind(&profile, false), 8);
        let client_to_upstream = tokio::spawn(tasks.client_to_upstream);

        for opcode in [0x9, 0xa] {
            downstream
                .write_all(&wire_frame(true, false, opcode, true, b"secret"))
                .await
                .unwrap();
            let (_, _, relayed_opcode, payload) = read_wire_frame(&mut upstream).await;
            assert_eq!(relayed_opcode, opcode);
            assert_eq!(payload, b"[MASKED]");
        }

        let mut close = 1000_u16.to_be_bytes().to_vec();
        close.extend_from_slice(b"secret");
        downstream
            .write_all(&wire_frame(true, false, 0x8, true, &close))
            .await
            .unwrap();
        let (_, _, opcode, payload) = read_wire_frame(&mut upstream).await;
        assert_eq!(opcode, 0x8);
        let mut expected = 1000_u16.to_be_bytes().to_vec();
        expected.extend_from_slice(b"[MASKED]");
        assert_eq!(payload, expected);
        assert_eq!(
            client_to_upstream.await.unwrap(),
            UpgradeTerminalCause::PeerClosed
        );
        drop(tasks.upstream_to_client);
    }

    #[tokio::test]
    async fn websocket_frame_and_fragmented_message_limits_fail_closed() {
        let profile = profile(8, 12, false);

        let (mut downstream, mut upstream, tasks) =
            establish_test_streams(websocket_kind(&profile, false), 8);
        let client_to_upstream = tokio::spawn(tasks.client_to_upstream);
        downstream
            .write_all(&wire_frame(true, false, 0x2, true, b"123456789"))
            .await
            .unwrap();
        let (_, _, opcode, payload) = read_wire_frame(&mut upstream).await;
        assert_eq!(opcode, 0x8);
        assert_eq!(payload, CLOSE_MESSAGE_TOO_BIG.to_be_bytes());
        assert_eq!(
            client_to_upstream.await.unwrap(),
            UpgradeTerminalCause::RelayError
        );
        drop(tasks.upstream_to_client);

        let (mut downstream, mut upstream, tasks) =
            establish_test_streams(websocket_kind(&profile, false), 8);
        let client_to_upstream = tokio::spawn(tasks.client_to_upstream);
        downstream
            .write_all(&wire_frame(false, false, 0x1, true, b"1234567"))
            .await
            .unwrap();
        downstream
            .write_all(&wire_frame(true, false, 0x0, true, b"123456"))
            .await
            .unwrap();
        let (_, _, opcode, payload) = read_wire_frame(&mut upstream).await;
        assert_eq!(opcode, 0x8);
        assert_eq!(payload, CLOSE_MESSAGE_TOO_BIG.to_be_bytes());
        assert_eq!(
            client_to_upstream.await.unwrap(),
            UpgradeTerminalCause::RelayError
        );
        drop(tasks.upstream_to_client);
    }

    #[test]
    fn websocket_handshake_rejects_invalid_extensions_and_disallowed_compression() {
        let enabled = profile(128, 256, true);
        let disabled = profile(128, 256, false);
        let protocol = HeaderValue::from_static("websocket");

        assert_eq!(
            EstablishedUpgradeKind::from_handshake(
                &protocol,
                &headers(Some("x-unknown")),
                &HeaderMap::new(),
                Some(&enabled),
            )
            .unwrap_err(),
            UpgradeRelayBuildError::UnsupportedRequestExtension
        );
        assert_eq!(
            EstablishedUpgradeKind::from_handshake(
                &protocol,
                &headers(Some("permessage-deflate")),
                &headers(Some("permessage-deflate; client_no_context_takeover")),
                Some(&enabled),
            )
            .unwrap_err(),
            UpgradeRelayBuildError::UnsupportedResponseExtension
        );
        assert_eq!(
            EstablishedUpgradeKind::from_handshake(
                &protocol,
                &headers(Some("permessage-deflate")),
                &headers(Some(
                    "permessage-deflate; client_no_context_takeover; server_no_context_takeover",
                )),
                Some(&disabled),
            )
            .unwrap_err(),
            UpgradeRelayBuildError::CompressionNotAllowed
        );

        assert!(matches!(
            EstablishedUpgradeKind::from_handshake(
                &protocol,
                &headers(Some("x-unvalidated")),
                &headers(Some("x-unvalidated")),
                None,
            )
            .unwrap(),
            EstablishedUpgradeKind::ObservedWebSocket { negotiation: None }
        ));
    }

    #[tokio::test]
    async fn websocket_close_is_forwarded_and_finishes_the_direction() {
        let profile = profile(128, 256, false);
        let (mut downstream, mut upstream, tasks) =
            establish_test_streams(websocket_kind(&profile, false), 8);
        let client_to_upstream = tokio::spawn(tasks.client_to_upstream);
        downstream
            .write_all(&wire_frame(true, false, 0x8, true, &1000_u16.to_be_bytes()))
            .await
            .unwrap();
        let (_, _, opcode, payload) = read_wire_frame(&mut upstream).await;
        assert_eq!(opcode, 0x8);
        assert_eq!(payload, 1000_u16.to_be_bytes());
        assert_eq!(
            client_to_upstream.await.unwrap(),
            UpgradeTerminalCause::PeerClosed
        );
        drop(tasks.upstream_to_client);
    }

    #[tokio::test]
    async fn websocket_capture_rotates_epochs_only_at_logical_message_boundaries() {
        let first_directory = tempfile::tempdir().unwrap();
        let second_directory = tempfile::tempdir().unwrap();
        let runtime = Arc::new(ProductObservationRuntime::try_new(8).unwrap());
        let (_first_redaction, first_owner) =
            publish_capture_epoch(&runtime, first_directory.path(), 1024 * 1024, b"FIRST");
        let wire = profile(1024, 1024, false);
        let context = upgrade_capture_context(runtime.clone());
        let (mut downstream, downstream_relay) = duplex(4096);
        let (mut upstream, upstream_relay) = duplex(4096);
        let (boundary_sender, boundary_receiver) = tokio::sync::oneshot::channel();
        let mut boundary_sender = Some(boundary_sender);
        let client_to_upstream = tokio::spawn(relay_websocket_direction_with_boundary(
            downstream_relay,
            upstream_relay,
            wire,
            WebSocketNegotiation {
                permessage_deflate: false,
            },
            WebSocketDirection::ClientToUpstream,
            Some(context),
            move || {
                if let Some(sender) = boundary_sender.take() {
                    let _ = sender.send(());
                }
            },
        ));

        let first_frame = wire_frame(false, false, 0x1, true, b"before secret ");
        let payload_offset = 6;
        downstream
            .write_all(&first_frame[..payload_offset])
            .await
            .unwrap();
        boundary_receiver
            .await
            .expect("relay must acquire the capture epoch at the frame boundary");
        let (_second_redaction, second_owner) =
            publish_capture_epoch(&runtime, second_directory.path(), 1024 * 1024, b"SECOND");
        downstream
            .write_all(&first_frame[payload_offset..])
            .await
            .unwrap();
        downstream
            .write_all(&wire_frame(true, false, 0x0, true, b"after"))
            .await
            .unwrap();
        let (_, _, _, relayed) = read_wire_frame(&mut upstream).await;
        assert_eq!(relayed, b"before [MASKED] after");

        downstream
            .write_all(&wire_frame(true, false, 0x1, true, b"next secret"))
            .await
            .unwrap();
        let (_, _, _, relayed) = read_wire_frame(&mut upstream).await;
        assert_eq!(relayed, b"next [MASKED]");

        drop(downstream);
        drop(upstream);
        client_to_upstream.await.unwrap();
        runtime.shutdown().await;
        drop((first_owner, second_owner));

        let first = capture_records(first_directory.path());
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].decode_body_bytes().unwrap(), b"before FIRST after");
        let second = capture_records(second_directory.path());
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].decode_body_bytes().unwrap(), b"next SECOND");
    }

    #[tokio::test]
    async fn unprotected_websocket_relays_raw_messages_and_captures_both_directions() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = Arc::new(ProductObservationRuntime::try_new(4).unwrap());
        let (_redaction, owner) =
            publish_capture_epoch(&runtime, directory.path(), 1024 * 1024, b"CAPTURED");
        let context = upgrade_capture_context(runtime.clone());
        let (mut downstream, mut upstream, tasks) = establish_test_streams_with_capture(
            observed_websocket_kind(None, None),
            8,
            Some(context),
        );
        let client_to_upstream = tokio::spawn(tasks.client_to_upstream);
        let upstream_to_client = tokio::spawn(tasks.upstream_to_client);

        downstream
            .write_all(&wire_frame(true, false, 0x1, true, b"client secret"))
            .await
            .unwrap();
        let (_, _, _, relayed) = read_wire_frame(&mut upstream).await;
        assert_eq!(relayed, b"client secret");

        upstream
            .write_all(&wire_frame(true, false, 0x1, false, b"server secret"))
            .await
            .unwrap();
        let (_, _, _, relayed) = read_wire_frame(&mut downstream).await;
        assert_eq!(relayed, b"server secret");

        drop(downstream);
        drop(upstream);
        client_to_upstream.await.unwrap();
        upstream_to_client.await.unwrap();
        runtime.shutdown().await;
        drop(owner);

        let records = capture_records(directory.path());
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, CaptureKind::Request);
        assert_eq!(records[0].decode_body_bytes().unwrap(), b"client CAPTURED");
        assert_eq!(records[1].kind, CaptureKind::Response);
        assert_eq!(records[1].decode_body_bytes().unwrap(), b"server CAPTURED");
    }

    #[tokio::test]
    async fn unprotected_websocket_close_finishes_after_forwarding_the_full_frame() {
        let runtime = Arc::new(ProductObservationRuntime::try_new(1).unwrap());
        let context = upgrade_capture_context(runtime.clone());
        let (mut downstream, mut upstream, tasks) = establish_test_streams_with_capture(
            observed_websocket_kind(None, None),
            8,
            Some(context),
        );
        let client_to_upstream = tokio::spawn(tasks.client_to_upstream);
        let close = wire_frame(true, false, 0x8, true, &1000_u16.to_be_bytes());

        downstream.write_all(&close).await.unwrap();

        let (_, _, opcode, payload) = read_wire_frame(&mut upstream).await;
        assert_eq!(opcode, 0x8);
        assert_eq!(payload, 1000_u16.to_be_bytes());
        assert_eq!(
            client_to_upstream.await.unwrap(),
            UpgradeTerminalCause::PeerClosed
        );
        drop(tasks.upstream_to_client);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn unprotected_websocket_observes_capture_enabled_after_the_upgrade() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = Arc::new(ProductObservationRuntime::try_new(2).unwrap());
        let context = upgrade_capture_context(runtime.clone());
        let (mut downstream, mut upstream, tasks) = establish_test_streams_with_capture(
            observed_websocket_kind(None, None),
            8,
            Some(context),
        );
        let client_to_upstream = tokio::spawn(tasks.client_to_upstream);
        drop(tasks.upstream_to_client);

        downstream
            .write_all(&wire_frame(true, false, 0x1, true, b"before secret"))
            .await
            .unwrap();
        let (_, _, _, relayed) = read_wire_frame(&mut upstream).await;
        assert_eq!(relayed, b"before secret");

        let (_redaction, owner) =
            publish_capture_epoch(&runtime, directory.path(), 1024 * 1024, b"ENABLED");
        downstream
            .write_all(&wire_frame(true, false, 0x1, true, b"after secret"))
            .await
            .unwrap();
        let (_, _, _, relayed) = read_wire_frame(&mut upstream).await;
        assert_eq!(relayed, b"after secret");

        drop(downstream);
        drop(upstream);
        client_to_upstream.await.unwrap();
        runtime.shutdown().await;
        drop(owner);

        let records = capture_records(directory.path());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].request_id, "upgrade-ws-request-1");
        assert_eq!(records[0].decode_body_bytes().unwrap(), b"after ENABLED");
    }

    #[tokio::test]
    async fn capture_only_scanner_omits_unsupported_malformed_and_oversized_messages() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = Arc::new(ProductObservationRuntime::try_new(4).unwrap());
        let (_redaction, owner) =
            publish_capture_epoch(&runtime, directory.path(), 1024 * 1024, b"CAPTURED");
        let context = upgrade_capture_context(runtime.clone());

        let (mut downstream, mut upstream, tasks) = establish_test_streams_with_capture(
            observed_websocket_kind(Some("x-unsupported"), Some("x-unsupported")),
            8,
            Some(context.clone()),
        );
        let invalid_extensions = tokio::spawn(tasks.client_to_upstream);
        drop(tasks.upstream_to_client);
        downstream
            .write_all(&wire_frame(true, false, 0x1, true, b"unsupported secret"))
            .await
            .unwrap();
        let (_, _, _, relayed) = read_wire_frame(&mut upstream).await;
        assert_eq!(relayed, b"unsupported secret");
        drop(downstream);
        drop(upstream);
        invalid_extensions.await.unwrap();

        let (mut downstream, mut upstream, tasks) = establish_test_streams_with_capture(
            observed_websocket_kind(None, None),
            8,
            Some(context),
        );
        let observed = tokio::spawn(tasks.client_to_upstream);
        drop(tasks.upstream_to_client);

        let oversized = vec![b'x'; 1025];
        downstream
            .write_all(&wire_frame(true, false, 0x2, true, &oversized))
            .await
            .unwrap();
        let (_, _, _, relayed) = read_wire_frame(&mut upstream).await;
        assert_eq!(relayed, oversized);

        downstream
            .write_all(&wire_frame(false, false, 0x1, true, b"partial secret"))
            .await
            .unwrap();
        let (_, _, _, relayed) = read_wire_frame(&mut upstream).await;
        assert_eq!(relayed, b"partial secret");
        downstream
            .write_all(&wire_frame(true, false, 0x1, true, b"conflict secret"))
            .await
            .unwrap();
        let (_, _, _, relayed) = read_wire_frame(&mut upstream).await;
        assert_eq!(relayed, b"conflict secret");

        downstream
            .write_all(&wire_frame(true, false, 0x1, true, b"valid secret"))
            .await
            .unwrap();
        let (_, _, _, relayed) = read_wire_frame(&mut upstream).await;
        assert_eq!(relayed, b"valid secret");

        drop(downstream);
        drop(upstream);
        observed.await.unwrap();
        runtime.shutdown().await;
        drop(owner);

        let records = capture_records(directory.path());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].decode_body_bytes().unwrap(), b"valid CAPTURED");
    }

    #[tokio::test]
    async fn capture_saturation_omits_message_without_delaying_websocket_relay() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = Arc::new(ProductObservationRuntime::try_new(1).unwrap());
        let (_redaction, owner) = publish_capture_epoch(&runtime, directory.path(), 1, b"CAPTURED");
        let context = upgrade_capture_context(runtime.clone());
        let (mut downstream, mut upstream, tasks) = establish_test_streams_with_capture(
            observed_websocket_kind(None, None),
            8,
            Some(context),
        );
        let client_to_upstream = tokio::spawn(tasks.client_to_upstream);
        drop(tasks.upstream_to_client);

        downstream
            .write_all(&wire_frame(true, false, 0x1, true, b"fast secret"))
            .await
            .unwrap();
        let (_, _, _, relayed) =
            tokio::time::timeout(Duration::from_millis(100), read_wire_frame(&mut upstream))
                .await
                .expect("capture saturation must not delay the relay");
        assert_eq!(relayed, b"fast secret");

        drop(downstream);
        drop(upstream);
        client_to_upstream.await.unwrap();
        runtime.shutdown().await;
        drop(owner);
        assert!(capture_records(directory.path()).is_empty());
    }

    #[tokio::test]
    async fn abandoned_fragmented_capture_releases_budget_for_the_next_message() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = Arc::new(ProductObservationRuntime::try_new(2).unwrap());
        let (_redaction, owner) =
            publish_capture_epoch(&runtime, directory.path(), 128 * 1024 + 1024, b"CAPTURED");
        let wire = profile(128, 256, false);
        let context = upgrade_capture_context(runtime.clone());

        let (mut downstream, _upstream, tasks) = establish_test_streams_with_capture(
            websocket_kind(&wire, false),
            8,
            Some(context.clone()),
        );
        let mut first = Box::pin(tasks.client_to_upstream);
        downstream
            .write_all(&wire_frame(false, false, 0x1, true, b"partial secret"))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), first.as_mut())
                .await
                .is_err()
        );
        drop(first);
        drop(tasks.upstream_to_client);
        drop(downstream);

        let (mut downstream, mut upstream, tasks) =
            establish_test_streams_with_capture(websocket_kind(&wire, false), 8, Some(context));
        let client_to_upstream = tokio::spawn(tasks.client_to_upstream);
        drop(tasks.upstream_to_client);
        downstream
            .write_all(&wire_frame(true, false, 0x1, true, b"complete secret"))
            .await
            .unwrap();
        let (_, _, _, relayed) = read_wire_frame(&mut upstream).await;
        assert_eq!(relayed, b"complete [MASKED]");
        drop(downstream);
        drop(upstream);
        client_to_upstream.await.unwrap();

        runtime.shutdown().await;
        drop(owner);
        let records = capture_records(directory.path());
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].decode_body_bytes().unwrap(),
            b"complete CAPTURED"
        );
    }
}
