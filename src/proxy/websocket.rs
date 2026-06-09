use crate::redaction::{self, RedactionProfile, RedactionUnsupportedExtensions};
use flate2::read::DeflateDecoder;
use flate2::{Compress, Compression, FlushCompress};
use http::header::{HeaderName, HeaderValue};
use http::HeaderMap;
use std::fmt;
use std::io::Read;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinHandle;

const SEC_WEBSOCKET_EXTENSIONS: &str = "sec-websocket-extensions";
const CLOSE_PROTOCOL_ERROR: u16 = 1002;
const CLOSE_MESSAGE_TOO_BIG: u16 = 1009;
const CLOSE_INTERNAL_ERROR: u16 = 1011;
const DEFLATE_TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];
const CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy)]
pub(crate) struct ClientExtensionOffer {
    pub permessage_deflate: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SessionExtensions {
    pub permessage_deflate: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WebSocketHandshakeError {
    #[error("unsupported WebSocket extension in protected request")]
    UnsupportedRequestExtension,
    #[error("unsupported WebSocket extension negotiated by upstream")]
    UnsupportedResponseExtension,
    #[error("invalid WebSocket extension header")]
    InvalidExtensionHeader,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WebSocketRelayError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("WebSocket protocol error: {0}")]
    Protocol(&'static str),
    #[error("WebSocket frame exceeded configured limit")]
    FrameTooLarge,
    #[error("WebSocket message exceeded configured limit")]
    MessageTooLarge,
    #[error("WebSocket compression error: {0}")]
    Compression(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    ClientToUpstream,
    UpstreamToClient,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::ClientToUpstream => f.write_str("client_to_upstream"),
            Direction::UpstreamToClient => f.write_str("upstream_to_client"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpCode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl OpCode {
    fn from_u8(value: u8) -> Result<Self, WebSocketRelayError> {
        match value {
            0x0 => Ok(Self::Continuation),
            0x1 => Ok(Self::Text),
            0x2 => Ok(Self::Binary),
            0x8 => Ok(Self::Close),
            0x9 => Ok(Self::Ping),
            0xA => Ok(Self::Pong),
            _ => Err(WebSocketRelayError::Protocol("invalid opcode")),
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
        }
    }

    fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }

    fn is_data(self) -> bool {
        matches!(self, Self::Text | Self::Binary)
    }
}

#[derive(Debug)]
struct Frame {
    fin: bool,
    rsv1: bool,
    rsv2: bool,
    rsv3: bool,
    opcode: OpCode,
    payload: Vec<u8>,
}

struct PendingMessage {
    opcode: OpCode,
    compressed: bool,
    payload: Vec<u8>,
}

pub(crate) fn is_websocket_upgrade(headers: &HeaderMap<HeaderValue>) -> bool {
    headers
        .get(http::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

pub(crate) fn sanitize_request_extensions(
    headers: &mut HeaderMap<HeaderValue>,
    profile: &RedactionProfile,
) -> Result<ClientExtensionOffer, WebSocketHandshakeError> {
    let extensions = parse_extensions(headers)?;
    let mut saw_permessage_deflate = false;

    for extension in &extensions {
        if extension.name == "permessage-deflate" {
            if profile.allow_permessage_deflate {
                saw_permessage_deflate = true;
            }
            continue;
        }

        if profile.unsupported_extensions == RedactionUnsupportedExtensions::Deny {
            return Err(WebSocketHandshakeError::UnsupportedRequestExtension);
        }
    }

    let header = HeaderName::from_static(SEC_WEBSOCKET_EXTENSIONS);
    headers.remove(&header);
    if saw_permessage_deflate {
        headers.insert(
            header,
            HeaderValue::from_static(
                "permessage-deflate; client_no_context_takeover; server_no_context_takeover",
            ),
        );
    }

    Ok(ClientExtensionOffer {
        permessage_deflate: saw_permessage_deflate,
    })
}

pub(crate) fn validate_response_extensions(
    headers: &HeaderMap<HeaderValue>,
    profile: &RedactionProfile,
    offer: ClientExtensionOffer,
) -> Result<SessionExtensions, WebSocketHandshakeError> {
    let extensions = parse_extensions(headers)?;
    let mut permessage_deflate = false;

    for extension in extensions {
        if extension.name != "permessage-deflate" {
            return Err(WebSocketHandshakeError::UnsupportedResponseExtension);
        }

        if !profile.allow_permessage_deflate || !offer.permessage_deflate || permessage_deflate {
            return Err(WebSocketHandshakeError::UnsupportedResponseExtension);
        }

        let mut client_no_context_takeover = false;
        let mut server_no_context_takeover = false;
        for param in extension.params {
            match param.as_str() {
                "client_no_context_takeover" => client_no_context_takeover = true,
                "server_no_context_takeover" => server_no_context_takeover = true,
                _ => return Err(WebSocketHandshakeError::UnsupportedResponseExtension),
            }
        }

        if !client_no_context_takeover || !server_no_context_takeover {
            return Err(WebSocketHandshakeError::UnsupportedResponseExtension);
        }
        permessage_deflate = true;
    }

    Ok(SessionExtensions { permessage_deflate })
}

pub(crate) async fn relay_websocket<S1, S2>(
    downstream: S1,
    upstream: S2,
    request_id: String,
    url: String,
    profile: RedactionProfile,
    extensions: SessionExtensions,
) -> Result<(), WebSocketRelayError>
where
    S1: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S2: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tracing::debug!(
        target: "acl_proxy::redaction",
        request_id = %request_id,
        url = %url,
        profile = %profile.name,
        permessage_deflate = extensions.permessage_deflate,
        "websocket redaction relay started"
    );

    let (downstream_read, downstream_write) = tokio::io::split(downstream);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let downstream_profile = profile.clone();
    let upstream_profile = profile.clone();
    let downstream_request_id = request_id.clone();
    let upstream_request_id = request_id.clone();
    let downstream_url = url.clone();
    let upstream_url = url.clone();

    let mut client_to_upstream = tokio::spawn(relay_direction(
        downstream_read,
        upstream_write,
        downstream_profile,
        extensions,
        Direction::ClientToUpstream,
        downstream_request_id,
        downstream_url,
    ));
    let mut upstream_to_client = tokio::spawn(relay_direction(
        upstream_read,
        downstream_write,
        upstream_profile,
        extensions,
        Direction::UpstreamToClient,
        upstream_request_id,
        upstream_url,
    ));

    let (first, second) = tokio::select! {
        result = &mut client_to_upstream => {
            let first = relay_join_result(result);
            let second = await_peer_relay(
                &mut upstream_to_client,
                &request_id,
                &url,
                &profile.name,
                Direction::UpstreamToClient,
            ).await;
            (first, second)
        }
        result = &mut upstream_to_client => {
            let first = relay_join_result(result);
            let second = await_peer_relay(
                &mut client_to_upstream,
                &request_id,
                &url,
                &profile.name,
                Direction::ClientToUpstream,
            ).await;
            (first, second)
        }
    };

    match first {
        Err(err) => Err(err),
        Ok(()) => second.unwrap_or(Ok(())),
    }
}

async fn await_peer_relay(
    handle: &mut JoinHandle<Result<(), WebSocketRelayError>>,
    request_id: &str,
    url: &str,
    profile: &str,
    direction: Direction,
) -> Option<Result<(), WebSocketRelayError>> {
    match tokio::time::timeout(CLOSE_DRAIN_TIMEOUT, &mut *handle).await {
        Ok(result) => Some(relay_join_result(result)),
        Err(_) => {
            tracing::debug!(
                target: "acl_proxy::redaction",
                request_id = %request_id,
                url = %url,
                profile = %profile,
                direction = %direction,
                timeout_ms = CLOSE_DRAIN_TIMEOUT.as_millis() as u64,
                "websocket peer relay did not close within drain timeout"
            );
            handle.abort();
            None
        }
    }
}

fn relay_join_result(
    result: Result<Result<(), WebSocketRelayError>, tokio::task::JoinError>,
) -> Result<(), WebSocketRelayError> {
    result.unwrap_or_else(|err| {
        Err(WebSocketRelayError::Io(std::io::Error::other(
            err.to_string(),
        )))
    })
}

async fn relay_direction<R, W>(
    mut reader: R,
    mut writer: W,
    profile: RedactionProfile,
    extensions: SessionExtensions,
    direction: Direction,
    request_id: String,
    url: String,
) -> Result<(), WebSocketRelayError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut pending: Option<PendingMessage> = None;
    loop {
        let frame = match read_frame(
            &mut reader,
            direction == Direction::ClientToUpstream,
            profile.max_frame_bytes,
        )
        .await
        {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()),
            Err(err) => {
                let code = close_code_for_error(&err);
                let _ =
                    write_close(&mut writer, direction == Direction::ClientToUpstream, code).await;
                log_close(&request_id, &url, &profile.name, direction, &err);
                return Err(err);
            }
        };

        if frame.opcode.is_control() {
            if !frame.fin || frame.payload.len() > 125 || frame.rsv1 || frame.rsv2 || frame.rsv3 {
                let err = WebSocketRelayError::Protocol("invalid control frame");
                let _ = write_close(
                    &mut writer,
                    direction == Direction::ClientToUpstream,
                    CLOSE_PROTOCOL_ERROR,
                )
                .await;
                log_close(&request_id, &url, &profile.name, direction, &err);
                return Err(err);
            }
            let is_close = frame.opcode == OpCode::Close;
            write_frame(&mut writer, frame, direction == Direction::ClientToUpstream).await?;
            if is_close {
                return Ok(());
            }
            continue;
        }

        if frame.rsv2 || frame.rsv3 {
            let err = WebSocketRelayError::Protocol("unsupported reserved bits");
            let _ = write_close(
                &mut writer,
                direction == Direction::ClientToUpstream,
                CLOSE_PROTOCOL_ERROR,
            )
            .await;
            log_close(&request_id, &url, &profile.name, direction, &err);
            return Err(err);
        }

        if frame.opcode.is_data() {
            if pending.is_some() {
                let err =
                    WebSocketRelayError::Protocol("new data message before continuation completed");
                let _ = write_close(
                    &mut writer,
                    direction == Direction::ClientToUpstream,
                    CLOSE_PROTOCOL_ERROR,
                )
                .await;
                log_close(&request_id, &url, &profile.name, direction, &err);
                return Err(err);
            }
            if frame.rsv1 && !extensions.permessage_deflate {
                let err = WebSocketRelayError::Protocol(
                    "compressed message without negotiated extension",
                );
                let _ = write_close(
                    &mut writer,
                    direction == Direction::ClientToUpstream,
                    CLOSE_PROTOCOL_ERROR,
                )
                .await;
                log_close(&request_id, &url, &profile.name, direction, &err);
                return Err(err);
            }
            if frame.payload.len() > profile.max_message_bytes {
                let err = WebSocketRelayError::MessageTooLarge;
                let _ = write_close(
                    &mut writer,
                    direction == Direction::ClientToUpstream,
                    CLOSE_MESSAGE_TOO_BIG,
                )
                .await;
                log_close(&request_id, &url, &profile.name, direction, &err);
                return Err(err);
            }
            if frame.fin {
                forward_message(
                    &mut writer,
                    frame.opcode,
                    frame.rsv1,
                    frame.payload,
                    &profile,
                    extensions,
                    direction,
                    &request_id,
                    &url,
                )
                .await?;
            } else {
                pending = Some(PendingMessage {
                    opcode: frame.opcode,
                    compressed: frame.rsv1,
                    payload: frame.payload,
                });
            }
            continue;
        }

        let Some(message) = pending.as_mut() else {
            let err = WebSocketRelayError::Protocol("continuation without active message");
            let _ = write_close(
                &mut writer,
                direction == Direction::ClientToUpstream,
                CLOSE_PROTOCOL_ERROR,
            )
            .await;
            log_close(&request_id, &url, &profile.name, direction, &err);
            return Err(err);
        };
        if frame.rsv1 {
            let err = WebSocketRelayError::Protocol("reserved bit on continuation frame");
            let _ = write_close(
                &mut writer,
                direction == Direction::ClientToUpstream,
                CLOSE_PROTOCOL_ERROR,
            )
            .await;
            log_close(&request_id, &url, &profile.name, direction, &err);
            return Err(err);
        }
        if message.payload.len().saturating_add(frame.payload.len()) > profile.max_message_bytes {
            let err = WebSocketRelayError::MessageTooLarge;
            let _ = write_close(
                &mut writer,
                direction == Direction::ClientToUpstream,
                CLOSE_MESSAGE_TOO_BIG,
            )
            .await;
            log_close(&request_id, &url, &profile.name, direction, &err);
            return Err(err);
        }
        message.payload.extend_from_slice(&frame.payload);
        if frame.fin {
            let message = pending.take().expect("pending message");
            forward_message(
                &mut writer,
                message.opcode,
                message.compressed,
                message.payload,
                &profile,
                extensions,
                direction,
                &request_id,
                &url,
            )
            .await?;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_message<W>(
    writer: &mut W,
    opcode: OpCode,
    compressed: bool,
    payload: Vec<u8>,
    profile: &RedactionProfile,
    extensions: SessionExtensions,
    direction: Direction,
    request_id: &str,
    url: &str,
) -> Result<(), WebSocketRelayError>
where
    W: AsyncWrite + Unpin,
{
    if direction == Direction::UpstreamToClient {
        return write_frame(
            writer,
            Frame {
                fin: true,
                rsv1: compressed,
                rsv2: false,
                rsv3: false,
                opcode,
                payload,
            },
            false,
        )
        .await;
    }

    let mut decoded = if compressed {
        decompress_message(&payload, profile.max_message_bytes)?
    } else {
        payload
    };

    if decoded.len() > profile.max_message_bytes {
        let err = WebSocketRelayError::MessageTooLarge;
        let _ = write_close(
            writer,
            direction == Direction::ClientToUpstream,
            CLOSE_MESSAGE_TOO_BIG,
        )
        .await;
        log_close(request_id, url, &profile.name, direction, &err);
        return Err(err);
    }

    if opcode == OpCode::Text && std::str::from_utf8(&decoded).is_err() {
        let err = WebSocketRelayError::Protocol("invalid UTF-8 text message");
        let _ = write_close(
            writer,
            direction == Direction::ClientToUpstream,
            CLOSE_PROTOCOL_ERROR,
        )
        .await;
        log_close(request_id, url, &profile.name, direction, &err);
        return Err(err);
    }

    let (redacted, redactions) =
        redaction::redact_payload(&decoded, opcode == OpCode::Text, profile).map_err(|err| {
            match err {
                redaction::RedactionError::InvalidUtf8 => {
                    WebSocketRelayError::Protocol("invalid UTF-8 text message")
                }
            }
        })?;
    decoded = redacted;
    if decoded.len() > profile.max_message_bytes {
        let err = WebSocketRelayError::MessageTooLarge;
        let _ = write_close(
            writer,
            direction == Direction::ClientToUpstream,
            CLOSE_MESSAGE_TOO_BIG,
        )
        .await;
        log_close(request_id, url, &profile.name, direction, &err);
        return Err(err);
    }

    if redactions > 0 {
        tracing::debug!(
            target: "acl_proxy::redaction",
            request_id = %request_id,
            url = %url,
            profile = %profile.name,
            direction = %direction,
            redactions,
            "websocket message redacted"
        );
    }

    let output = if compressed {
        if !extensions.permessage_deflate {
            return Err(WebSocketRelayError::Protocol(
                "compressed message without negotiated extension",
            ));
        }
        compress_message(&decoded)?
    } else {
        decoded
    };

    write_frame(
        writer,
        Frame {
            fin: true,
            rsv1: compressed,
            rsv2: false,
            rsv3: false,
            opcode,
            payload: output,
        },
        direction == Direction::ClientToUpstream,
    )
    .await
}

async fn read_frame<R>(
    reader: &mut R,
    expect_masked: bool,
    max_frame_bytes: usize,
) -> Result<Option<Frame>, WebSocketRelayError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    match reader.read(&mut header[..1]).await {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!("single-byte read returned more than one byte"),
        Err(err) => return Err(WebSocketRelayError::Io(err)),
    }
    reader.read_exact(&mut header[1..]).await?;

    let fin = header[0] & 0x80 != 0;
    let rsv1 = header[0] & 0x40 != 0;
    let rsv2 = header[0] & 0x20 != 0;
    let rsv3 = header[0] & 0x10 != 0;
    let opcode = OpCode::from_u8(header[0] & 0x0f)?;
    let masked = header[1] & 0x80 != 0;
    if masked != expect_masked {
        return Err(WebSocketRelayError::Protocol(
            "unexpected WebSocket masking",
        ));
    }

    let mut len = u64::from(header[1] & 0x7f);
    if len == 126 {
        let mut extended = [0u8; 2];
        reader.read_exact(&mut extended).await?;
        len = u64::from(u16::from_be_bytes(extended));
    } else if len == 127 {
        let mut extended = [0u8; 8];
        reader.read_exact(&mut extended).await?;
        len = u64::from_be_bytes(extended);
        if len & (1 << 63) != 0 {
            return Err(WebSocketRelayError::Protocol(
                "invalid WebSocket payload length",
            ));
        }
    }

    let payload_len = usize::try_from(len).map_err(|_| WebSocketRelayError::FrameTooLarge)?;
    if payload_len > max_frame_bytes {
        return Err(WebSocketRelayError::FrameTooLarge);
    }

    let mask = if masked {
        let mut mask = [0u8; 4];
        reader.read_exact(&mut mask).await?;
        Some(mask)
    } else {
        None
    };

    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;
    if let Some(mask) = mask {
        apply_mask(&mut payload, mask);
    }

    Ok(Some(Frame {
        fin,
        rsv1,
        rsv2,
        rsv3,
        opcode,
        payload,
    }))
}

async fn write_frame<W>(
    writer: &mut W,
    mut frame: Frame,
    mask_payload: bool,
) -> Result<(), WebSocketRelayError>
where
    W: AsyncWrite + Unpin,
{
    let mut header = Vec::with_capacity(14);
    let mut first = (frame.fin as u8) << 7 | frame.opcode.as_u8();
    if frame.rsv1 {
        first |= 0x40;
    }
    if frame.rsv2 {
        first |= 0x20;
    }
    if frame.rsv3 {
        first |= 0x10;
    }
    header.push(first);

    let len = frame.payload.len();
    let mask_bit = if mask_payload { 0x80 } else { 0 };
    if len < 126 {
        header.push(mask_bit | len as u8);
    } else if len <= u16::MAX as usize {
        header.push(mask_bit | 126);
        header.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        header.push(mask_bit | 127);
        header.extend_from_slice(&(len as u64).to_be_bytes());
    }

    if mask_payload {
        let mask = rand::random::<[u8; 4]>();
        apply_mask(&mut frame.payload, mask);
        header.extend_from_slice(&mask);
    }

    writer.write_all(&header).await?;
    writer.write_all(&frame.payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn write_close<W>(
    writer: &mut W,
    mask_payload: bool,
    code: u16,
) -> Result<(), WebSocketRelayError>
where
    W: AsyncWrite + Unpin,
{
    write_frame(
        writer,
        Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: OpCode::Close,
            payload: code.to_be_bytes().to_vec(),
        },
        mask_payload,
    )
    .await
}

fn apply_mask(payload: &mut [u8], mask: [u8; 4]) {
    for (idx, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[idx % 4];
    }
}

fn decompress_message(payload: &[u8], limit: usize) -> Result<Vec<u8>, WebSocketRelayError> {
    let mut input = Vec::with_capacity(payload.len() + DEFLATE_TAIL.len());
    input.extend_from_slice(payload);
    input.extend_from_slice(&DEFLATE_TAIL);
    let mut decoder = DeflateDecoder::new(input.as_slice());
    let mut output = Vec::new();
    let read = decoder
        .by_ref()
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut output)
        .map_err(|err| WebSocketRelayError::Compression(err.to_string()))?;
    if read > limit {
        return Err(WebSocketRelayError::MessageTooLarge);
    }
    Ok(output)
}

fn compress_message(payload: &[u8]) -> Result<Vec<u8>, WebSocketRelayError> {
    let mut encoder = Compress::new(Compression::default(), false);
    let mut output = Vec::with_capacity(payload.len() + (payload.len() / 16) + 64);

    for _ in 0..8 {
        if output.capacity() == output.len() {
            output.reserve(payload.len().max(64));
        }

        let consumed = usize::try_from(encoder.total_in())
            .map_err(|err| WebSocketRelayError::Compression(err.to_string()))?;
        let input = payload.get(consumed..).ok_or_else(|| {
            WebSocketRelayError::Compression("deflate encoder consumed too much input".to_string())
        })?;

        encoder
            .compress_vec(input, &mut output, FlushCompress::Sync)
            .map_err(|err| WebSocketRelayError::Compression(err.to_string()))?;

        if encoder.total_in() == payload.len() as u64 && output.ends_with(&DEFLATE_TAIL) {
            output.truncate(output.len() - DEFLATE_TAIL.len());
            return Ok(output);
        }
    }

    Err(WebSocketRelayError::Compression(
        "deflate encoder did not produce sync-flush tail".to_string(),
    ))
}

fn close_code_for_error(err: &WebSocketRelayError) -> u16 {
    match err {
        WebSocketRelayError::FrameTooLarge | WebSocketRelayError::MessageTooLarge => {
            CLOSE_MESSAGE_TOO_BIG
        }
        WebSocketRelayError::Compression(_) => CLOSE_INTERNAL_ERROR,
        WebSocketRelayError::Io(_) | WebSocketRelayError::Protocol(_) => CLOSE_PROTOCOL_ERROR,
    }
}

fn log_close(
    request_id: &str,
    url: &str,
    profile: &str,
    direction: Direction,
    err: &WebSocketRelayError,
) {
    tracing::debug!(
        target: "acl_proxy::redaction",
        request_id = %request_id,
        url = %url,
        profile = %profile,
        direction = %direction,
        reason = %err,
        "websocket redaction relay closing"
    );
}

struct ParsedExtension {
    name: String,
    params: Vec<String>,
}

fn parse_extensions(
    headers: &HeaderMap<HeaderValue>,
) -> Result<Vec<ParsedExtension>, WebSocketHandshakeError> {
    let mut parsed = Vec::new();
    let header = HeaderName::from_static(SEC_WEBSOCKET_EXTENSIONS);
    for value in headers.get_all(&header) {
        let raw = value
            .to_str()
            .map_err(|_| WebSocketHandshakeError::InvalidExtensionHeader)?;
        for extension in raw.split(',') {
            let mut parts = extension
                .split(';')
                .map(str::trim)
                .filter(|part| !part.is_empty());
            let Some(name) = parts.next() else {
                continue;
            };
            if !is_token(name) {
                return Err(WebSocketHandshakeError::InvalidExtensionHeader);
            }
            let mut params = Vec::new();
            for param in parts {
                let key = param
                    .split_once('=')
                    .map(|(key, _)| key.trim())
                    .unwrap_or(param);
                if !is_token(key) {
                    return Err(WebSocketHandshakeError::InvalidExtensionHeader);
                }
                params.push(key.to_ascii_lowercase());
            }
            parsed.push(ParsedExtension {
                name: name.to_ascii_lowercase(),
                params,
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
    use super::*;
    use crate::config::{RedactionMatch, RedactionProfileConfig, RedactionRuleConfig};

    fn profile() -> RedactionProfile {
        RedactionProfile::from_config(
            "test",
            &RedactionProfileConfig {
                replacement: "[REDACTED]".to_string(),
                max_frame_bytes: 128,
                max_message_bytes: 1024,
                allow_permessage_deflate: true,
                unsupported_extensions: RedactionUnsupportedExtensions::Deny,
                rules: vec![RedactionRuleConfig {
                    literals: vec!["secret".to_string()],
                    expressions: Vec::new(),
                    match_mode: RedactionMatch::Both,
                }],
                ..Default::default()
            },
        )
    }

    #[test]
    fn redacts_literal_in_payload() {
        let profile = profile();
        let (payload, count) =
            redaction::redact_payload(b"send secret now", true, &profile).expect("redact");
        assert_eq!(count, 1);
        assert_eq!(payload, b"send [REDACTED] now");
    }

    #[test]
    fn permessage_deflate_round_trips_without_tail() {
        let compressed = compress_message(b"hello secret").expect("compress");
        assert!(!compressed.ends_with(&DEFLATE_TAIL));
        let mut canonical = compressed.clone();
        canonical.extend_from_slice(&DEFLATE_TAIL);
        let mut decoder = DeflateDecoder::new(canonical.as_slice());
        let mut independently_decoded = Vec::new();
        decoder
            .read_to_end(&mut independently_decoded)
            .expect("independent decode");
        assert_eq!(independently_decoded, b"hello secret");

        let decompressed = decompress_message(&compressed, 128).expect("decompress");
        assert_eq!(decompressed, b"hello secret");
    }

    #[test]
    fn strips_unsupported_request_extensions_when_configured() {
        let mut profile = profile();
        profile.unsupported_extensions = RedactionUnsupportedExtensions::Strip;
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(SEC_WEBSOCKET_EXTENSIONS),
            HeaderValue::from_static("x-test, permessage-deflate"),
        );
        let offer = sanitize_request_extensions(&mut headers, &profile).expect("sanitize");
        assert!(offer.permessage_deflate);
        assert_eq!(
            headers
                .get(HeaderName::from_static(SEC_WEBSOCKET_EXTENSIONS))
                .and_then(|value| value.to_str().ok()),
            Some("permessage-deflate; client_no_context_takeover; server_no_context_takeover")
        );
    }

    #[test]
    fn rejects_response_deflate_without_no_context_takeover() {
        let profile = profile();
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(SEC_WEBSOCKET_EXTENSIONS),
            HeaderValue::from_static("permessage-deflate"),
        );
        assert!(matches!(
            validate_response_extensions(
                &headers,
                &profile,
                ClientExtensionOffer {
                    permessage_deflate: true,
                },
            ),
            Err(WebSocketHandshakeError::UnsupportedResponseExtension)
        ));
    }

    #[tokio::test]
    async fn read_frame_returns_none_on_clean_initial_eof() {
        let (client, mut proxy_side) = tokio::io::duplex(64);
        drop(client);

        let frame = read_frame(&mut proxy_side, true, 128)
            .await
            .expect("clean eof should not be an error");

        assert!(frame.is_none());
    }

    #[tokio::test]
    async fn relay_waits_for_peer_close_after_first_direction_closes() {
        let (mut client, downstream) = tokio::io::duplex(1024);
        let (upstream, mut server) = tokio::io::duplex(1024);

        let relay = tokio::spawn(relay_websocket(
            downstream,
            upstream,
            "test-request".to_string(),
            "ws://example.test/chat".to_string(),
            profile(),
            SessionExtensions {
                permessage_deflate: false,
            },
        ));

        write_close(&mut client, true, 1000)
            .await
            .expect("client close");
        let server_close = read_frame(&mut server, true, 128)
            .await
            .expect("server reads close")
            .expect("close frame");
        assert_eq!(server_close.opcode, OpCode::Close);

        write_close(&mut server, false, 1000)
            .await
            .expect("server close");
        let client_close = read_frame(&mut client, false, 128)
            .await
            .expect("client reads close")
            .expect("close frame");
        assert_eq!(client_close.opcode, OpCode::Close);

        tokio::time::timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay should finish after close handshake")
            .expect("relay task should not panic")
            .expect("relay should finish cleanly");
    }
}
