use std::future::poll_fn;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

use bytes::Bytes;
use http::{Request, Response, StatusCode, Version};
use http_access_runtime::{ForwardingDevHarness, ForwardingNetworkFacts};
#[cfg(target_os = "linux")]
use tempfile::tempdir;
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinHandle;

use super::*;

const WORKLOAD_SEED: u64 = 0x5031_3353_5452_4553;
const WARMUP_BATCHES: usize = 2;
const MEASURED_BATCHES: usize = 8;
const H1_STREAMS_PER_SHAPE: usize = 4;
const H2_STREAMS: usize = 16;
const WEBSOCKET_RELAYS: usize = 4;
const H1_BODY_BYTES: usize = 8 * 1024 * 1024;
const H2_BODY_BYTES: usize = 1024 * 1024;
const H2_SUCCESS_BODY_BYTES: usize = 8 * 1024;
const H2_INITIAL_WINDOW_BYTES: usize = 16 * 1024;
const WEBSOCKET_BODY_BYTES: usize = 1024 * 1024;
const BATCH_TIMEOUT: Duration = Duration::from_secs(30);
const QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const REBIND_TIMEOUT: Duration = Duration::from_secs(2);
const FINAL_FD_ALLOWANCE: usize = 2;
const FINAL_RSS_ALLOWANCE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_RSS_SLOPE_BYTES_PER_BATCH: f64 = 1024.0 * 1024.0;
const BACKPRESSURE_HOLD: Duration = Duration::from_millis(1_250);
#[cfg(target_os = "linux")]
const EXTERNAL_TOKIO_WORKER_THREADS: &str = "4";

#[derive(Clone, Copy, Debug)]
struct ProcessSample {
    file_descriptors: usize,
    rss_bytes: u64,
    active_origin_sockets: usize,
    data_address: SocketAddr,
    listener_probe_succeeded: bool,
    child_live: bool,
}

#[derive(Clone)]
struct OriginActivity(Arc<AtomicUsize>);

impl OriginActivity {
    fn new() -> Self {
        Self(Arc::new(AtomicUsize::new(0)))
    }

    fn enter(&self) -> OriginSocketGuard {
        self.0.fetch_add(1, Ordering::AcqRel);
        OriginSocketGuard(self.clone())
    }

    fn count(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }
}

struct OriginSocketGuard(OriginActivity);

impl Drop for OriginSocketGuard {
    fn drop(&mut self) {
        let previous = self.0 .0.fetch_sub(1, Ordering::AcqRel);
        assert!(previous > 0, "origin socket accounting underflowed");
    }
}

struct StressOrigins {
    request_address: SocketAddr,
    response_address: SocketAddr,
    h2_address: SocketAddr,
    websocket_address: SocketAddr,
    activities: [OriginActivity; 4],
    tasks: Vec<JoinHandle<()>>,
}

impl StressOrigins {
    async fn start(batch_count: usize) -> Self {
        let activities = std::array::from_fn(|_| OriginActivity::new());
        let request_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let response_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let h2_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let websocket_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let request_address = request_listener.local_addr().unwrap();
        let response_address = response_listener.local_addr().unwrap();
        let h2_address = h2_listener.local_addr().unwrap();
        let websocket_address = websocket_listener.local_addr().unwrap();

        let request_activity = activities[0].clone();
        let request_task = tokio::spawn(async move {
            let expected = batch_count * H1_STREAMS_PER_SHAPE;
            let mut connections = Vec::with_capacity(expected);
            for _ in 0..expected {
                let (stream, _) = request_listener.accept().await.unwrap();
                let activity = request_activity.clone();
                connections.push(tokio::spawn(async move {
                    let _active = activity.enter();
                    set_small_receive_buffer(&stream);
                    h1_request_backpressure_origin(stream).await;
                }));
            }
            for connection in connections {
                connection.await.unwrap();
            }
        });

        let response_activity = activities[1].clone();
        let response_task = tokio::spawn(async move {
            let expected = batch_count * H1_STREAMS_PER_SHAPE;
            let mut connections = Vec::with_capacity(expected);
            for _ in 0..expected {
                let (stream, _) = response_listener.accept().await.unwrap();
                let activity = response_activity.clone();
                connections.push(tokio::spawn(async move {
                    let _active = activity.enter();
                    h1_response_backpressure_origin(stream).await;
                }));
            }
            for connection in connections {
                connection.await.unwrap();
            }
        });

        let h2_activity = activities[2].clone();
        let h2_task = tokio::spawn(async move {
            let expected = batch_count * H2_STREAMS;
            let cancelled_body = Bytes::from(deterministic_bytes(H2_BODY_BYTES, 0xc2));
            let success_body = Bytes::from(deterministic_bytes(H2_SUCCESS_BODY_BYTES, 0x52));
            let mut connections = Vec::with_capacity(expected);
            for _ in 0..expected {
                let (stream, _) = h2_listener.accept().await.unwrap();
                let activity = h2_activity.clone();
                let cancelled_body = cancelled_body.clone();
                let success_body = success_body.clone();
                connections.push(tokio::spawn(async move {
                    let _active = activity.enter();
                    serve_h2_origin_connection(stream, cancelled_body, success_body).await;
                }));
            }
            for connection in connections {
                connection.await.unwrap();
            }
        });

        let websocket_activity = activities[3].clone();
        let websocket_task = tokio::spawn(async move {
            let expected = batch_count * WEBSOCKET_RELAYS;
            let mut connections = Vec::with_capacity(expected);
            for _ in 0..expected {
                let (stream, _) = websocket_listener.accept().await.unwrap();
                let activity = websocket_activity.clone();
                connections.push(tokio::spawn(async move {
                    let _active = activity.enter();
                    websocket_origin(stream).await;
                }));
            }
            for connection in connections {
                connection.await.unwrap();
            }
        });

        Self {
            request_address,
            response_address,
            h2_address,
            websocket_address,
            activities,
            tasks: vec![request_task, response_task, h2_task, websocket_task],
        }
    }

    fn mappings(&self) -> [(String, SocketAddr); 4] {
        [
            (
                format!("http://{}/", self.request_address),
                self.request_address,
            ),
            (
                format!("http://{}/", self.response_address),
                self.response_address,
            ),
            (format!("http://{}/", self.h2_address), self.h2_address),
            (
                format!("http://{}/", self.websocket_address),
                self.websocket_address,
            ),
        ]
    }

    async fn finish(mut self) {
        for task in self.tasks.drain(..) {
            tokio::time::timeout(BATCH_TIMEOUT, task)
                .await
                .expect("stress origin supervisor did not finish")
                .unwrap();
        }
        assert_eq!(self.active_count(), 0);
    }

    fn active_count(&self) -> usize {
        self.activities.iter().map(OriginActivity::count).sum()
    }

    fn active_counts(&self) -> [usize; 4] {
        self.activities.each_ref().map(OriginActivity::count)
    }
}

#[cfg(target_os = "linux")]
fn set_small_receive_buffer(stream: &tokio::net::TcpStream) {
    let bytes: libc::c_int = 4096;
    let result = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&raw const bytes).cast(),
            std::mem::size_of_val(&bytes) as libc::socklen_t,
        )
    };
    assert_eq!(
        result, 0,
        "failed to constrain stress socket receive buffer"
    );
}

#[cfg(not(target_os = "linux"))]
fn set_small_receive_buffer(_stream: &tokio::net::TcpStream) {}

#[cfg(target_os = "linux")]
fn set_small_send_buffer(stream: &tokio::net::TcpStream) {
    let bytes: libc::c_int = 4096;
    let result = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&raw const bytes).cast(),
            std::mem::size_of_val(&bytes) as libc::socklen_t,
        )
    };
    assert_eq!(result, 0, "failed to constrain stress socket send buffer");
}

#[cfg(not(target_os = "linux"))]
fn set_small_send_buffer(_stream: &tokio::net::TcpStream) {}

async fn read_http_head(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut byte))
            .await
            .expect("stress HTTP head read timed out")
            .expect("stress HTTP head ended early");
        head.push(byte[0]);
        assert!(head.len() <= 32 * 1024, "stress HTTP head exceeded bound");
    }
    head
}

#[cfg(target_os = "linux")]
async fn wait_for_tcp_close_without_reading(stream: &mut tokio::net::TcpStream, message: &str) {
    let deadline = Instant::now() + QUIESCENCE_TIMEOUT;
    loop {
        assert!(Instant::now() < deadline, "{message}");
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        let result = unsafe { libc::poll(&raw mut descriptor, 1, 0) };
        assert!(result >= 0, "{message}: {}", io::Error::last_os_error());
        if descriptor.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR) != 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[cfg(not(target_os = "linux"))]
async fn wait_for_tcp_close_without_reading(stream: &mut tokio::net::TcpStream, message: &str) {
    let mut sink = Vec::new();
    tokio::time::timeout(QUIESCENCE_TIMEOUT, stream.read_to_end(&mut sink))
        .await
        .unwrap_or_else(|_| panic!("{message}"))
        .expect("stress TCP close observation failed");
}

#[cfg(target_os = "linux")]
fn unread_socket_bytes(stream: &tokio::net::TcpStream) -> usize {
    let mut bytes: libc::c_int = 0;
    let result = unsafe { libc::ioctl(stream.as_raw_fd(), libc::FIONREAD, &raw mut bytes) };
    assert_eq!(result, 0, "failed to sample unread origin bytes");
    usize::try_from(bytes).expect("unread origin byte count was negative")
}

#[cfg(not(target_os = "linux"))]
fn unread_socket_bytes(_stream: &tokio::net::TcpStream) -> usize {
    1
}

async fn h1_request_backpressure_origin(mut stream: tokio::net::TcpStream) {
    set_small_send_buffer(&stream);
    let head = read_http_head(&mut stream).await;
    assert!(head.starts_with(b"POST /request-backpressure/"));
    tokio::time::sleep(BACKPRESSURE_HOLD).await;
    let received = unread_socket_bytes(&stream);
    assert!(received > 0, "request backpressure made no origin progress");
    assert!(
        received < H1_BODY_BYTES,
        "origin socket received the complete body despite stopped reads"
    );
    stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {H1_BODY_BYTES}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let body = deterministic_bytes(H1_BODY_BYTES, 0x31);
    let mut written = 0;
    let _ = tokio::time::timeout(BACKPRESSURE_HOLD, async {
        while written < body.len() {
            match stream.write(&body[written..]).await {
                Ok(0) | Err(_) => break,
                Ok(count) => written += count,
            }
        }
    })
    .await;
    assert!(written > 0, "request-backpressure response made no progress");
    assert!(
        written < H1_BODY_BYTES,
        "request-backpressure response was completely buffered"
    );
    wait_for_tcp_close_without_reading(&mut stream, "request-backpressure origin was not closed")
        .await;
}

async fn h1_response_backpressure_origin(mut stream: tokio::net::TcpStream) {
    set_small_send_buffer(&stream);
    let head = read_http_head(&mut stream).await;
    assert!(head.starts_with(b"GET /response-backpressure/"));
    stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {H1_BODY_BYTES}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let body = deterministic_bytes(H1_BODY_BYTES, 0x52);
    let mut written = 0;
    let _ = tokio::time::timeout(BACKPRESSURE_HOLD, async {
        while written < body.len() {
            match stream.write(&body[written..]).await {
                Ok(0) | Err(_) => break,
                Ok(count) => written += count,
            }
        }
    })
    .await;
    assert!(written > 0, "response backpressure made no origin progress");
    assert!(
        written < H1_BODY_BYTES,
        "response backpressure buffered the complete origin body"
    );
    wait_for_tcp_close_without_reading(&mut stream, "response-backpressure origin was not closed")
        .await;
}

async fn serve_h2_origin_connection(
    stream: tokio::net::TcpStream,
    cancelled_body: Bytes,
    success_body: Bytes,
) {
    let mut connection = h2::server::handshake(stream).await.unwrap();
    let (request, respond) = tokio::time::timeout(BATCH_TIMEOUT, connection.accept())
        .await
        .expect("H2 origin did not receive its request")
        .expect("H2 origin connection failed")
        .expect("H2 origin closed before its request");
    let cancelled = request.uri().path().contains("/cancel/");
    let driver = tokio::spawn(async move {
        if let Some(Ok(_)) = connection.accept().await {
            panic!("H2 origin connection received more than one request");
        }
    });
    send_h2_response(respond, cancelled, cancelled_body, success_body).await;
    tokio::time::timeout(BATCH_TIMEOUT, driver)
        .await
        .expect("H2 origin connection was not closed after its response")
        .unwrap();
}

async fn send_h2_response(
    mut respond: h2::server::SendResponse<Bytes>,
    cancelled: bool,
    cancelled_body: Bytes,
    success_body: Bytes,
) {
    let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
    let mut body = respond.send_response(response, false).unwrap();
    let bytes = if cancelled {
        cancelled_body
    } else {
        success_body
    };
    let expected = bytes.len();
    let mut offset = 0;
    body.reserve_capacity(expected);
    while offset < expected {
        let capacity = match poll_fn(|cx| body.poll_capacity(cx)).await {
            Some(Ok(capacity)) => capacity,
            Some(Err(error)) => {
                assert!(cancelled, "successful H2 response lost capacity: {error}");
                assert_eq!(error.reason(), Some(h2::Reason::CANCEL));
                return;
            }
            None => {
                assert!(cancelled, "successful H2 response closed early");
                return;
            }
        };
        let count = capacity.min(expected - offset).min(16 * 1024);
        if let Err(error) = body.send_data(
            bytes.slice(offset..offset + count),
            offset + count == expected,
        ) {
            assert!(cancelled, "successful H2 response failed: {error}");
            assert_eq!(error.reason(), Some(h2::Reason::CANCEL));
            return;
        }
        offset += count;
    }
}

struct WebSocketFrame {
    opcode: u8,
    payload: Vec<u8>,
}

async fn write_websocket_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    opcode: u8,
    payload: &[u8],
    masked: bool,
) -> io::Result<()> {
    let mut frame = vec![0x80 | opcode];
    match payload.len() {
        length @ 0..=125 => frame.push(u8::try_from(length).unwrap()),
        length @ 126..=65_535 => {
            frame.push(126);
            frame.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
        }
        length => {
            frame.push(127);
            frame.extend_from_slice(&u64::try_from(length).unwrap().to_be_bytes());
        }
    }
    if masked {
        frame[1] |= 0x80;
        let seed = WORKLOAD_SEED.to_be_bytes();
        let mask = [seed[0], seed[1], seed[2], seed[3]];
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % mask.len()]),
        );
    } else {
        frame.extend_from_slice(payload);
    }
    writer.write_all(&frame).await
}

async fn read_websocket_frame(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<WebSocketFrame> {
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header).await?;
    let masked = header[1] & 0x80 != 0;
    let mut length = u64::from(header[1] & 0x7f);
    if length == 126 {
        let mut extended = [0_u8; 2];
        reader.read_exact(&mut extended).await?;
        length = u64::from(u16::from_be_bytes(extended));
    } else if length == 127 {
        let mut extended = [0_u8; 8];
        reader.read_exact(&mut extended).await?;
        length = u64::from_be_bytes(extended);
    }
    let length = usize::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "WebSocket frame is too large"))?;
    assert!(
        length <= WEBSOCKET_BODY_BYTES,
        "stress WebSocket frame exceeded bound"
    );
    let mut mask = [0_u8; 4];
    if masked {
        reader.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % mask.len()];
        }
    }
    Ok(WebSocketFrame {
        opcode: header[0] & 0x0f,
        payload,
    })
}

async fn websocket_origin(mut stream: tokio::net::TcpStream) {
    let head = read_http_head(&mut stream).await;
    let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
    assert!(head.starts_with("get /websocket/"));
    assert!(head.contains("\r\nupgrade: websocket\r\n"));
    stream
        .write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        )
        .await
        .unwrap();
    let inbound = read_websocket_frame(&mut stream).await.unwrap();
    assert_eq!(inbound.opcode, 0x2);
    assert_eq!(
        inbound.payload,
        deterministic_bytes(WEBSOCKET_BODY_BYTES, 0xa1)
    );
    write_websocket_frame(
        &mut stream,
        0x2,
        &deterministic_bytes(WEBSOCKET_BODY_BYTES, 0xb2),
        false,
    )
    .await
    .unwrap();
    let close = read_websocket_frame(&mut stream).await.unwrap();
    assert_eq!(close.opcode, 0x8);
    write_websocket_frame(&mut stream, 0x8, &[], false)
        .await
        .unwrap();
}

fn deterministic_bytes(length: usize, salt: u8) -> Vec<u8> {
    (0..length)
        .map(|index| {
            let mixed = (index as u64)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(WORKLOAD_SEED);
            (mixed as u8) ^ salt
        })
        .collect()
}

fn stress_config(bind: SocketAddr, origins: &StressOrigins) -> String {
    format!(
        r#"schema_version = 3

[service]
request_timeout = "25s"
shutdown_drain_timeout = "2s"
max_active_upgrades = 16
max_inflight_wire_body_bytes = 4294967296
max_inflight_wire_body_bytes_per_quota_key = 1073741824
min_wire_body_concurrency = 32

[service.forwarding]
connect_timeout = "10s"
response_head_timeout = "10s"
body_idle_timeout = "3s"
upgrade_idle_timeout = "2s"
max_request_wire_bytes = 16777216
max_request_decoded_bytes = 16777216
max_response_wire_bytes = 16777216
max_response_decoded_bytes = 16777216
chunk_bytes = 65536
preserve_request_trailers = false
max_trailer_count = 16
max_trailer_bytes = 8192

[listeners.explicit_http]
bind = "{bind}"
http_versions = ["http1", "http2"]
max_connections = 128
max_concurrent_streams = 64

[listeners.explicit_http.connect]
http1 = "deny"
http2 = "deny"

[egress]
route = "direct"

[egress.origin_tls]
trust = "insecure"
http_versions = ["http1", "http2"]

[policy]
default = "deny"

[[policy.rules]]
id = "stress-request"
decision = "allow"
urls = ["http://{}/**"]

[[policy.rules]]
id = "stress-response"
decision = "allow"
urls = ["http://{}/**"]

[[policy.rules]]
id = "stress-h2"
decision = "allow"
urls = ["http://{}/**"]

[[policy.rules]]
id = "stress-websocket"
decision = "allow"
urls = ["http://{}/**"]
allow_upgrades = true

[safety.loop_detection]
inject = true
header = "x-stress-loop"
"#,
        origins.request_address,
        origins.response_address,
        origins.h2_address,
        origins.websocket_address,
    )
}

async fn start_in_process_product(
    listener: StdTcpListener,
    origins: &StressOrigins,
) -> (TempDir, Arc<ProductRuntime>) {
    let bind = listener.local_addr().unwrap();
    let (directory, loaded) = loaded(&stress_config(bind, origins));
    let facts = ForwardingNetworkFacts::new(vec![bind], None, None, None).unwrap();
    let mut harness = ForwardingDevHarness::new(facts);
    for (url, address) in origins.mappings() {
        let url = http_access_url::canonicalize_http_url(&url).unwrap();
        harness = harness.map_prebound(&url, address).unwrap();
    }
    let product = ProductRuntime::prepare_from_prebound_with_forwarding_network(
        loaded,
        vec![listener],
        Arc::new(harness.into_standalone_guard()),
    )
    .await
    .unwrap();
    product.activate_initial().await.unwrap();
    product.start_listeners().await.unwrap();
    (directory, product)
}

async fn h1_request_client(proxy: SocketAddr, origin: SocketAddr, batch: usize, index: usize) {
    let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    set_small_send_buffer(&stream);
    set_small_receive_buffer(&stream);
    let head = format!(
        "POST http://{origin}/request-backpressure/{batch}/{index} HTTP/1.1\r\nHost: {origin}\r\nContent-Length: {H1_BODY_BYTES}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let block = deterministic_bytes(64 * 1024, 0x41);
    let mut written = 0;
    let _ = tokio::time::timeout(BACKPRESSURE_HOLD, async {
        while written < H1_BODY_BYTES {
            let count = match stream.write(&block).await {
                Ok(0) | Err(_) => break,
                Ok(count) => count,
            };
            written += count;
        }
    })
    .await;
    assert!(written > 0, "request backpressure made no bounded progress");
    assert!(
        written < H1_BODY_BYTES,
        "request backpressure client sent the complete declared body"
    );
    let head = read_http_head(&mut stream).await;
    assert!(head.starts_with(b"HTTP/1.1 200"));
    drop(stream);
}

async fn h1_response_client(proxy: SocketAddr, origin: SocketAddr, batch: usize, index: usize) {
    let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    set_small_receive_buffer(&stream);
    stream
        .write_all(
            format!(
                "GET http://{origin}/response-backpressure/{batch}/{index} HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let head = read_http_head(&mut stream).await;
    assert!(head.starts_with(b"HTTP/1.1 200"));
    tokio::time::sleep(BACKPRESSURE_HOLD).await;
    drop(stream);
}

async fn h2_clients(proxy: SocketAddr, origin: SocketAddr, batch: usize) {
    let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let mut builder = h2::client::Builder::new();
    builder.initial_window_size(H2_INITIAL_WINDOW_BYTES as u32);
    builder.initial_connection_window_size(H2_STREAMS as u32 * H2_INITIAL_WINDOW_BYTES as u32);
    let (mut sender, connection) = builder.handshake::<_, Bytes>(stream).await.unwrap();
    let connection = tokio::spawn(connection);
    let response_heads = Arc::new(tokio::sync::Barrier::new(H2_STREAMS + 1));
    let mut responses = Vec::with_capacity(H2_STREAMS);
    for index in 0..H2_STREAMS {
        sender.clone().ready().await.unwrap();
        let cancelled = index % 2 == 1;
        let mode = if cancelled { "cancel" } else { "success" };
        let request = Request::builder()
            .method("GET")
            .version(Version::HTTP_2)
            .uri(format!("http://{origin}/h2/{mode}/{batch}/{index}"))
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(request, true).unwrap();
        let response_heads = Arc::clone(&response_heads);
        responses.push(tokio::spawn(async move {
            let response = response.await.unwrap_or_else(|error| {
                panic!("H2 stress response head failed for batch {batch} stream {index} ({mode}): {error}")
            });
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "H2 stress response failed for batch {batch} stream {index} ({mode})"
            );
            response_heads.wait().await;
            let mut body = response.into_body();
            let expected_prefix = if cancelled {
                H2_INITIAL_WINDOW_BYTES
            } else {
                H2_SUCCESS_BODY_BYTES
            };
            let mut received = Vec::with_capacity(expected_prefix);
            while received.len() < expected_prefix {
                let chunk = body
                    .data()
                    .await
                    .expect("H2 stress response omitted its window data")
                    .unwrap();
                received.extend_from_slice(&chunk);
                assert!(
                    received.len() <= expected_prefix,
                    "H2 stress response exceeded its expected prefix for batch {batch} stream {index} ({mode})"
                );
            }
            if cancelled {
                assert!(!body.is_end_stream());
                let reset = tokio::time::timeout(QUIESCENCE_TIMEOUT, body.data())
                    .await
                    .expect("zero-window H2 response was not cancelled")
                    .expect("zero-window H2 response ended without RST_STREAM")
                    .expect_err("zero-window H2 response produced data past its window");
                assert!(reset.is_reset());
                assert_eq!(reset.reason(), Some(h2::Reason::CANCEL));
                return;
            }
            while let Some(chunk) = body.data().await {
                received.extend_from_slice(&chunk.unwrap());
            }
            assert_eq!(received, deterministic_bytes(H2_SUCCESS_BODY_BYTES, 0x52));
        }));
    }
    response_heads.wait().await;
    for response in responses {
        response.await.unwrap();
    }
    drop(sender);
    connection.abort();
    let result = tokio::time::timeout(Duration::from_secs(3), connection)
        .await
        .expect("H2 stress connection did not close");
    if let Err(error) = result {
        assert!(error.is_cancelled());
    }
}

async fn websocket_client(proxy: SocketAddr, origin: SocketAddr, batch: usize, index: usize) {
    let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(
            format!(
                "GET http://{origin}/websocket/{batch}/{index} HTTP/1.1\r\nHost: {origin}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let head = read_http_head(&mut stream).await;
    assert!(head.starts_with(b"HTTP/1.1 101"));
    write_websocket_frame(
        &mut stream,
        0x2,
        &deterministic_bytes(WEBSOCKET_BODY_BYTES, 0xa1),
        true,
    )
    .await
    .unwrap();
    let response = read_websocket_frame(&mut stream).await.unwrap();
    assert_eq!(response.opcode, 0x2);
    assert_eq!(
        response.payload,
        deterministic_bytes(WEBSOCKET_BODY_BYTES, 0xb2)
    );
    write_websocket_frame(&mut stream, 0x8, &[], true)
        .await
        .unwrap();
    let close = read_websocket_frame(&mut stream).await.unwrap();
    assert_eq!(close.opcode, 0x8);
    wait_for_tcp_close_without_reading(&mut stream, "WebSocket downstream was not closed").await;
}

async fn run_stress_batch(proxy: SocketAddr, origins: &StressOrigins, batch: usize) {
    tokio::time::timeout(BATCH_TIMEOUT, async {
        let mut request_tasks = Vec::new();
        for index in 0..H1_STREAMS_PER_SHAPE {
            request_tasks.push(tokio::spawn(h1_request_client(
                proxy,
                origins.request_address,
                batch,
                index,
            )));
        }
        for task in request_tasks {
            task.await.unwrap();
        }

        let mut response_tasks = Vec::new();
        for index in 0..H1_STREAMS_PER_SHAPE {
            response_tasks.push(tokio::spawn(h1_response_client(
                proxy,
                origins.response_address,
                batch,
                index,
            )));
        }
        for task in response_tasks {
            task.await.unwrap();
        }

        h2_clients(proxy, origins.h2_address, batch).await;

        let mut websocket_tasks = Vec::new();
        for index in 0..WEBSOCKET_RELAYS {
            websocket_tasks.push(tokio::spawn(websocket_client(
                proxy,
                origins.websocket_address,
                batch,
                index,
            )));
        }
        for task in websocket_tasks {
            task.await.unwrap();
        }
    })
    .await
    .unwrap_or_else(|_| panic!("stress batch {batch} exceeded {BATCH_TIMEOUT:?}"));
}

async fn wait_for_quiescence(origins: &StressOrigins, product: Option<&ProductRuntime>) {
    let result = tokio::time::timeout(QUIESCENCE_TIMEOUT, async {
        loop {
            let pool_is_empty =
                product.is_none_or(|product| product.wire_body_pool().global_charge() == 0);
            if origins.active_count() == 0 && pool_is_empty {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "stress resources did not quiesce: active origin sockets={:?} (request, response, H2, WebSocket), wire body charge={}",
        origins.active_counts(),
        product.map_or(0, |product| product.wire_body_pool().global_charge())
    );
}

fn reserve_external_address() -> (SocketAddr, StdTcpListener) {
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    (listener.local_addr().unwrap(), listener)
}

fn prebound_listener() -> (SocketAddr, StdTcpListener) {
    reserve_external_address()
}

#[cfg(target_os = "linux")]
fn process_fd_count(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap_or_else(|error| panic!("could not sample child file descriptors: {error}"))
        .count()
}

#[cfg(target_os = "linux")]
fn process_sample(
    pid: u32,
    active_origin_sockets: usize,
    data_address: SocketAddr,
    listener_probe_succeeded: bool,
    child_live: bool,
) -> ProcessSample {
    let file_descriptors = process_fd_count(pid);
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap_or_else(|error| panic!("could not sample child RSS: {error}"));
    let rss_kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .expect("child status omitted VmRSS");
    ProcessSample {
        file_descriptors,
        rss_bytes: rss_kib * 1024,
        active_origin_sockets,
        data_address,
        listener_probe_succeeded,
        child_live,
    }
}

fn ordinary_least_squares_slope(samples: &[ProcessSample]) -> f64 {
    assert_eq!(samples.len(), MEASURED_BATCHES);
    let count = samples.len() as f64;
    let sum_x: f64 = (0..samples.len()).map(|index| index as f64).sum();
    let sum_y: f64 = samples.iter().map(|sample| sample.rss_bytes as f64).sum();
    let sum_xy: f64 = samples
        .iter()
        .enumerate()
        .map(|(index, sample)| index as f64 * sample.rss_bytes as f64)
        .sum();
    let sum_x_squared: f64 = (0..samples.len()).map(|index| (index * index) as f64).sum();
    (count * sum_xy - sum_x * sum_y) / (count * sum_x_squared - sum_x * sum_x)
}

fn assert_process_envelope(
    baseline_fds: usize,
    data_address: SocketAddr,
    samples: &[ProcessSample],
) {
    assert_eq!(samples.len(), MEASURED_BATCHES);
    assert!(samples
        .iter()
        .all(|sample| sample.active_origin_sockets == 0));
    assert!(samples
        .iter()
        .all(|sample| sample.data_address == data_address));
    assert!(samples.iter().all(|sample| sample.listener_probe_succeeded));
    assert!(samples.iter().all(|sample| sample.child_live));
    let first_rss = samples[0].rss_bytes;
    let final_sample = samples.last().unwrap();
    assert!(
        final_sample.file_descriptors <= baseline_fds + FINAL_FD_ALLOWANCE,
        "final FD count {} exceeded baseline {} plus {}",
        final_sample.file_descriptors,
        baseline_fds,
        FINAL_FD_ALLOWANCE
    );
    assert!(
        final_sample.rss_bytes <= first_rss + FINAL_RSS_ALLOWANCE_BYTES,
        "final RSS {} exceeded first measured RSS {} plus {}",
        final_sample.rss_bytes,
        first_rss,
        FINAL_RSS_ALLOWANCE_BYTES
    );
    let slope = ordinary_least_squares_slope(samples);
    assert!(
        slope <= MAX_RSS_SLOPE_BYTES_PER_BATCH,
        "RSS slope {slope} exceeded {MAX_RSS_SLOPE_BYTES_PER_BATCH} bytes per batch"
    );
}

#[cfg(target_os = "linux")]
struct ExternalChild {
    child: Option<Child>,
}

#[cfg(target_os = "linux")]
impl ExternalChild {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("stress child is still owned")
    }

    fn id(&self) -> u32 {
        self.child
            .as_ref()
            .expect("stress child is still owned")
            .id()
    }

    fn terminate_gracefully(mut self) {
        let child = self.child.as_mut().expect("stress child is still owned");
        #[cfg(unix)]
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }
        let deadline = Instant::now() + QUIESCENCE_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "stress proxy exited unsuccessfully: {status}"
                );
                self.child.take();
                return;
            }
            assert!(
                Instant::now() < deadline,
                "stress proxy did not exit gracefully within {QUIESCENCE_TIMEOUT:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ExternalChild {
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(target_os = "linux")]
fn assert_rebind(address: SocketAddr) {
    let deadline = Instant::now() + REBIND_TIMEOUT;
    loop {
        match StdTcpListener::bind(address) {
            Ok(_) => return,
            Err(error) if error.kind() == io::ErrorKind::AddrInUse && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("stress data address {address} did not rebind: {error}"),
        }
    }
}

#[cfg(target_os = "linux")]
fn external_binary() -> PathBuf {
    std::env::var_os("ACL_PROXY_STRESS_BINARY")
        .map(PathBuf::from)
        .expect("explicit external stress requires ACL_PROXY_STRESS_BINARY")
}

#[cfg(target_os = "linux")]
fn spawn_external(binary: &Path, config: &Path) -> Child {
    Command::new(binary)
        .arg("run")
        .arg("--config")
        .arg(config)
        .env("TOKIO_WORKER_THREADS", EXTERNAL_TOKIO_WORKER_THREADS)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|error| {
            panic!("could not start stress proxy {}: {error}", binary.display())
        })
}

#[cfg(target_os = "linux")]
async fn wait_for_listener(child: &mut Child, address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "stress proxy exited during startup"
        );
        if let Ok(stream) = tokio::net::TcpStream::connect(address).await {
            drop(stream);
            if child_owns_listener(child.id(), address) {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "stress proxy did not adopt {address}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[cfg(target_os = "linux")]
fn child_owns_listener(pid: u32, address: SocketAddr) -> bool {
    let SocketAddr::V4(address) = address else {
        return false;
    };
    let local = format!(
        "{:08X}:{:04X}",
        u32::from_le_bytes(address.ip().octets()),
        address.port()
    );
    let table = match std::fs::read_to_string(format!("/proc/{pid}/net/tcp")) {
        Ok(table) => table,
        Err(_) => return false,
    };
    let inode = table.lines().skip(1).find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        (fields.get(1) == Some(&local.as_str()) && fields.get(3) == Some(&"0A"))
            .then(|| fields.get(9)?.parse::<u64>().ok())
            .flatten()
    });
    let Some(inode) = inode else {
        return false;
    };
    let expected = std::ffi::OsString::from(format!("socket:[{inode}]"));
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .any(|target| target.as_os_str() == expected)
}

#[cfg(target_os = "linux")]
async fn probe_listener_and_wait_for_fd_quiescence(pid: u32, address: SocketAddr) {
    let before = process_fd_count(pid);
    let stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("stress listener probe failed");
    tokio::time::timeout(QUIESCENCE_TIMEOUT, async {
        while process_fd_count(pid) <= before {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("stress child did not accept its listener probe");
    drop(stream);
    tokio::time::timeout(QUIESCENCE_TIMEOUT, async {
        while process_fd_count(pid) > before {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("stress child retained its accepted listener probe");
}

#[test]
fn process_resource_thresholds_are_exact_and_non_vacuous() {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
    let samples: [ProcessSample; MEASURED_BATCHES] = std::array::from_fn(|index| ProcessSample {
        file_descriptors: 10 + usize::from(index == MEASURED_BATCHES - 1),
        rss_bytes: 64 * 1024 * 1024 + index as u64 * 512 * 1024,
        active_origin_sockets: 0,
        data_address: address,
        listener_probe_succeeded: true,
        child_live: true,
    });
    assert_process_envelope(10, address, &samples);
    assert!(ordinary_least_squares_slope(&samples) > 0.0);

    let rejects = |mutated: [ProcessSample; MEASURED_BATCHES]| {
        std::panic::catch_unwind(|| assert_process_envelope(10, address, &mutated)).is_err()
    };
    let mut fd = samples;
    fd[MEASURED_BATCHES - 1].file_descriptors = 13;
    assert!(rejects(fd));
    let mut rss = samples;
    rss[MEASURED_BATCHES - 1].rss_bytes = rss[0].rss_bytes + FINAL_RSS_ALLOWANCE_BYTES + 1;
    assert!(rejects(rss));
    let mut slope = samples;
    for (index, sample) in slope.iter_mut().enumerate() {
        sample.rss_bytes = 64 * 1024 * 1024 + index as u64 * 2 * 1024 * 1024;
    }
    assert!(rejects(slope));
    let mut origin = samples;
    origin[3].active_origin_sockets = 1;
    assert!(rejects(origin));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn in_process_resource_stress_releases_body_and_origin_ownership() {
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let batch_count = WARMUP_BATCHES + MEASURED_BATCHES;
    let origins = StressOrigins::start(batch_count).await;
    let (proxy, listener) = prebound_listener();
    let (_directory, product) = start_in_process_product(listener, &origins).await;
    let pool = product.wire_body_pool();
    assert_eq!(pool.global_charge(), 0);
    assert_eq!(pool.peak_global_charge(), 0);
    for batch in 0..batch_count {
        let completions_before = product.forwarding_terminal_completions_for_test();
        let outcomes_before = product.forwarding_terminal_outcomes_for_test();
        run_stress_batch(proxy, &origins, batch).await;
        wait_for_quiescence(&origins, Some(&product)).await;
        assert_eq!(pool.global_charge(), 0);
        assert!(pool.peak_global_charge() > 0);
        assert_eq!(
            product.forwarding_terminal_completions_for_test() - completions_before,
            2 * H1_STREAMS_PER_SHAPE + H2_STREAMS + WEBSOCKET_RELAYS,
            "stress batch {batch} did not complete every forwarding terminal owner"
        );
        let outcomes = product.forwarding_terminal_outcomes_for_test();
        assert_eq!(outcomes.completed - outcomes_before.completed, 12);
        assert_eq!(
            outcomes.cancelled - outcomes_before.cancelled + outcomes.failed
                - outcomes_before.failed,
            16
        );
        assert_eq!(outcomes.abandoned - outcomes_before.abandoned, 0);
        let probe = tokio::net::TcpStream::connect(proxy).await.unwrap();
        drop(probe);
    }
    product.shutdown().await;
    crate::activation::assert_listener_addresses_released(&_serial, [proxy]);
    origins.finish().await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[ignore = "run explicitly against the current release candidate binary"]
async fn external_release_candidate_resource_stress_obeys_linux_envelope() {
    let binary = external_binary();
    assert!(
        binary.is_file(),
        "stress binary does not exist: {}",
        binary.display()
    );
    let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let batch_count = WARMUP_BATCHES + MEASURED_BATCHES;
    let origins = StressOrigins::start(batch_count).await;
    let (proxy, reservation) = reserve_external_address();
    let directory = tempdir().unwrap();
    let config = directory.path().join("acl-proxy.toml");
    std::fs::write(&config, stress_config(proxy, &origins)).unwrap();
    drop(reservation);
    let mut child = ExternalChild::new(spawn_external(&binary, &config));
    wait_for_listener(child.child_mut(), proxy).await;
    let pid = child.id();
    for batch in 0..WARMUP_BATCHES {
        run_stress_batch(proxy, &origins, batch).await;
        wait_for_quiescence(&origins, None).await;
    }
    let baseline_fds =
        process_sample(pid, origins.active_count(), proxy, false, true).file_descriptors;
    eprintln!(
        "resource stress child pid={pid} data_address={proxy} tokio_worker_threads={EXTERNAL_TOKIO_WORKER_THREADS} baseline_fds={baseline_fds}"
    );
    let mut samples = Vec::with_capacity(MEASURED_BATCHES);
    for measured in 0..MEASURED_BATCHES {
        run_stress_batch(proxy, &origins, WARMUP_BATCHES + measured).await;
        wait_for_quiescence(&origins, None).await;
        probe_listener_and_wait_for_fd_quiescence(pid, proxy).await;
        let child_live = child.child_mut().try_wait().unwrap().is_none();
        assert!(child_live, "stress proxy exited during sampling");
        let sample = process_sample(pid, origins.active_count(), proxy, true, child_live);
        eprintln!(
            "resource stress sample measured={measured} data_address={} listener_probe_succeeded={} child_live={} fds={} rss_bytes={} active_origin_sockets={}",
            sample.data_address,
            sample.listener_probe_succeeded,
            sample.child_live,
            sample.file_descriptors,
            sample.rss_bytes,
            sample.active_origin_sockets
        );
        samples.push(sample);
    }
    assert_process_envelope(baseline_fds, proxy, &samples);
    eprintln!(
        "resource stress envelope rss_slope_bytes_per_batch={}",
        ordinary_least_squares_slope(&samples)
    );
    child.terminate_gracefully();
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "stress child process residue remained after exit"
    );
    assert_rebind(proxy);
    origins.finish().await;
}
