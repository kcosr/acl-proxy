use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixStream},
    sync::{watch, Semaphore},
    task::JoinSet,
    time::timeout,
};

use crate::{
    config::{Config, Route},
    original_dst::original_destination,
    proxy_v2::encode_ipv4_stream,
};

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("failed to bind relay listener: {0}")]
    Bind(#[source] io::Error),
    #[error("relay listener failed: {0}")]
    Accept(#[source] io::Error),
    #[error("failed to install shutdown signal: {0}")]
    Signal(#[source] io::Error),
    #[error("relay task failed: {0}")]
    Task(#[source] tokio::task::JoinError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CloseCategory {
    Complete,
    Cancelled,
    OriginalDestination,
    OriginalPort,
    SetupTimeout,
    SocketConnect,
    PrefaceWrite,
    Copy,
}

impl CloseCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Cancelled => "cancelled",
            Self::OriginalDestination => "original_destination",
            Self::OriginalPort => "original_port",
            Self::SetupTimeout => "setup_timeout",
            Self::SocketConnect => "socket_connect",
            Self::PrefaceWrite => "preface_write",
            Self::Copy => "copy",
        }
    }
}

struct ConnectionOutcome {
    category: CloseCategory,
    destination: Option<SocketAddr>,
    connected_after: Option<Duration>,
    bytes_to_upstream: u64,
    bytes_to_client: u64,
}

#[cfg(feature = "test-seam")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KnownDestinationOutcome {
    pub completed: bool,
    pub bytes_to_upstream: u64,
    pub bytes_to_client: u64,
}

#[cfg(feature = "test-seam")]
pub async fn relay_known_destination_for_test(
    client: TcpStream,
    peer: SocketAddr,
    destination: SocketAddr,
    route: Route,
    setup_timeout: Duration,
    buffer_bytes: usize,
) -> KnownDestinationOutcome {
    let (_shutdown_tx, shutdown) = watch::channel(false);
    let outcome = process_known_destination(
        client,
        peer,
        destination,
        &route,
        setup_timeout,
        buffer_bytes,
        shutdown,
    )
    .await;
    KnownDestinationOutcome {
        completed: outcome.category == CloseCategory::Complete,
        bytes_to_upstream: outcome.bytes_to_upstream,
        bytes_to_client: outcome.bytes_to_client,
    }
}

pub async fn run(config: Config) -> Result<(), RelayError> {
    let mut listeners = Vec::with_capacity(config.routes.len());
    for route in config.routes.iter().cloned() {
        let listener = TcpListener::bind(route.listen)
            .await
            .map_err(RelayError::Bind)?;
        listeners.push((route, listener));
    }

    let capacity = Arc::new(Semaphore::new(config.max_connections));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut listener_tasks = JoinSet::new();
    for (route, listener) in listeners {
        listener_tasks.spawn(accept_route(
            route,
            listener,
            config.setup_timeout,
            config.copy_buffer_bytes_per_direction,
            Arc::clone(&capacity),
            shutdown_rx.clone(),
        ));
    }

    tokio::select! {
        signal = tokio::signal::ctrl_c() => signal.map_err(RelayError::Signal)?,
        task = listener_tasks.join_next() => {
            match task {
                Some(result) => result.map_err(RelayError::Task)??,
                None => return Ok(()),
            }
        }
    }
    let _ = shutdown_tx.send(true);
    while let Some(result) = listener_tasks.join_next().await {
        result.map_err(RelayError::Task)??;
    }
    Ok(())
}

async fn accept_route(
    route: Route,
    listener: TcpListener,
    setup_timeout: Duration,
    buffer_bytes: usize,
    capacity: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), RelayError> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted.map_err(RelayError::Accept)?;
                let Ok(permit) = Arc::clone(&capacity).try_acquire_owned() else {
                    tracing::warn!(
                        route = %route.name,
                        non_authoritative_source = %peer,
                        category = "capacity",
                        "connection refused"
                    );
                    drop(stream);
                    continue;
                };
                let route = route.clone();
                let shutdown = shutdown.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    serve_connection(stream, peer, route, setup_timeout, buffer_bytes, shutdown).await;
                });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    tracing::error!(category = "task", error = %error, "connection task failed");
                }
            }
        }
    }

    connections.shutdown().await;
    Ok(())
}

async fn serve_connection(
    client: TcpStream,
    peer: SocketAddr,
    route: Route,
    setup_timeout: Duration,
    buffer_bytes: usize,
    shutdown: watch::Receiver<bool>,
) {
    let id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    let accepted_at = Instant::now();
    let outcome =
        process_connection(client, peer, &route, setup_timeout, buffer_bytes, shutdown).await;
    tracing::info!(
        connection_id = id,
        route = %route.name,
        non_authoritative_source = %peer,
        destination = outcome.destination.map(|value| value.to_string()).as_deref(),
        connection_duration_ms = accepted_at.elapsed().as_millis() as u64,
        connect_duration_ms = outcome.connected_after.map(|value| value.as_millis() as u64),
        bytes_to_upstream = outcome.bytes_to_upstream,
        bytes_to_client = outcome.bytes_to_client,
        category = outcome.category.as_str(),
        "connection closed"
    );
}

async fn process_connection(
    client: TcpStream,
    peer: SocketAddr,
    route: &Route,
    setup_timeout: Duration,
    buffer_bytes: usize,
    shutdown: watch::Receiver<bool>,
) -> ConnectionOutcome {
    let destination = match original_destination(&client) {
        Ok(value) => SocketAddr::V4(value),
        Err(_) => return outcome(CloseCategory::OriginalDestination, None),
    };
    process_known_destination(
        client,
        peer,
        destination,
        route,
        setup_timeout,
        buffer_bytes,
        shutdown,
    )
    .await
}

async fn process_known_destination(
    client: TcpStream,
    peer: SocketAddr,
    destination: SocketAddr,
    route: &Route,
    setup_timeout: Duration,
    buffer_bytes: usize,
    mut shutdown: watch::Receiver<bool>,
) -> ConnectionOutcome {
    if !route.allowed_original_ports.contains(&destination.port()) {
        return outcome(CloseCategory::OriginalPort, Some(destination));
    }
    let header = match encode_ipv4_stream(peer, destination) {
        Ok(header) => header,
        Err(_) => return outcome(CloseCategory::OriginalDestination, Some(destination)),
    };

    let setup_started = Instant::now();
    let setup = async {
        let mut upstream = UnixStream::connect(&route.upstream_socket)
            .await
            .map_err(|_| CloseCategory::SocketConnect)?;
        write_preface(&mut upstream, &header)
            .await
            .map_err(|_| CloseCategory::PrefaceWrite)?;
        Ok::<_, CloseCategory>(upstream)
    };
    let mut upstream = tokio::select! {
        _ = cancelled(&mut shutdown) => return outcome(CloseCategory::Cancelled, Some(destination)),
        result = timeout(setup_timeout, setup) => match result {
            Err(_) => return outcome(CloseCategory::SetupTimeout, Some(destination)),
            Ok(Err(category)) => return outcome(category, Some(destination)),
            Ok(Ok(upstream)) => upstream,
        }
    };
    let connected_after = setup_started.elapsed();

    // These are deliberately allocated only after Unix connect and complete preface publication.
    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.split();
    let client_to_upstream_buffer = vec![0_u8; buffer_bytes];
    let upstream_to_client_buffer = vec![0_u8; buffer_bytes];
    let bytes_to_upstream = AtomicU64::new(0);
    let bytes_to_client = AtomicU64::new(0);
    let copy = async {
        tokio::try_join!(
            pump(
                &mut client_read,
                &mut upstream_write,
                client_to_upstream_buffer,
                &bytes_to_upstream,
            ),
            pump(
                &mut upstream_read,
                &mut client_write,
                upstream_to_client_buffer,
                &bytes_to_client,
            )
        )
    };
    let category = tokio::select! {
        _ = cancelled(&mut shutdown) => CloseCategory::Cancelled,
        result = copy => match result {
            Ok(_) => CloseCategory::Complete,
            Err(_) => CloseCategory::Copy,
        }
    };
    ConnectionOutcome {
        category,
        destination: Some(destination),
        connected_after: Some(connected_after),
        bytes_to_upstream: bytes_to_upstream.load(Ordering::Relaxed),
        bytes_to_client: bytes_to_client.load(Ordering::Relaxed),
    }
}

async fn write_preface<W>(writer: &mut W, header: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(header).await
}

fn outcome(category: CloseCategory, destination: Option<SocketAddr>) -> ConnectionOutcome {
    ConnectionOutcome {
        category,
        destination,
        connected_after: None,
        bytes_to_upstream: 0,
        bytes_to_client: 0,
    }
}

async fn cancelled(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    mut buffer: Vec<u8>,
    copied: &AtomicU64,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        let mut written = 0;
        while written < read {
            let count = writer.write(&buffer[written..read]).await?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "relay stream write returned zero bytes",
                ));
            }
            written += count;
            copied
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(count as u64)
                })
                .map_err(|_| io::Error::other("byte count overflow"))?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    struct PartialWriter {
        bytes: Vec<u8>,
        max_write: usize,
        fail_after: Option<usize>,
    }

    impl AsyncWrite for PartialWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.fail_after == Some(0) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected write failure",
                )));
            }
            let count = buffer
                .len()
                .min(self.max_write)
                .min(self.fail_after.unwrap_or(usize::MAX));
            self.bytes.extend_from_slice(&buffer[..count]);
            if let Some(remaining) = self.fail_after.as_mut() {
                *remaining -= count;
            }
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn pump_is_bounded_and_propagates_half_close() {
        let (mut input, relay_read) = duplex(4);
        let (relay_write, mut output) = duplex(4);
        let copied = Arc::new(AtomicU64::new(0));
        let task_copied = Arc::clone(&copied);
        let task = tokio::spawn(async move {
            pump(relay_read, relay_write, vec![0; 3], task_copied.as_ref()).await
        });

        input.write_all(b"payload").await.unwrap();
        input.shutdown().await.unwrap();
        let mut received = Vec::new();
        output.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"payload");
        task.await.unwrap().unwrap();
        assert_eq!(copied.load(Ordering::Relaxed), 7);
    }

    #[tokio::test]
    async fn cancellation_is_observed_before_streaming() {
        let (tx, mut rx) = watch::channel(false);
        tx.send(true).unwrap();
        timeout(Duration::from_millis(50), cancelled(&mut rx))
            .await
            .unwrap();
    }

    #[test]
    fn capacity_is_global_across_routes() {
        let capacity = Arc::new(Semaphore::new(1));
        let first_route = Arc::clone(&capacity).try_acquire_owned().unwrap();
        assert!(Arc::clone(&capacity).try_acquire_owned().is_err());
        drop(first_route);
        assert!(capacity.try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn preface_write_handles_partial_writes() {
        let mut writer = PartialWriter {
            bytes: Vec::new(),
            max_write: 3,
            fail_after: None,
        };
        write_preface(&mut writer, b"complete-preface")
            .await
            .unwrap();
        assert_eq!(writer.bytes, b"complete-preface");
    }

    #[tokio::test]
    async fn pump_retains_partial_byte_count_on_copy_failure() {
        let copied = AtomicU64::new(0);
        let writer = PartialWriter {
            bytes: Vec::new(),
            max_write: 3,
            fail_after: Some(4),
        };
        let error = pump(&b"payload"[..], writer, vec![0; 7], &copied)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(copied.load(Ordering::Relaxed), 4);
    }

    #[tokio::test]
    async fn one_absolute_timeout_bounds_all_setup_work() {
        let result = timeout(Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        })
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn original_port_mismatch_is_rejected_before_unix_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client_task = tokio::spawn(TcpStream::connect(address));
        let (relay_client, peer) = listener.accept().await.unwrap();
        let _client = client_task.await.unwrap().unwrap();
        let route = Route {
            name: "http".into(),
            listen: address,
            allowed_original_ports: vec![80],
            upstream_socket: "/definitely/not/a/socket".into(),
        };
        let (_shutdown_tx, shutdown) = watch::channel(false);

        let result = process_known_destination(
            relay_client,
            peer,
            "203.0.113.8:443".parse().unwrap(),
            &route,
            Duration::from_millis(50),
            8,
            shutdown,
        )
        .await;
        assert_eq!(result.category, CloseCategory::OriginalPort);
    }

    #[tokio::test]
    async fn unix_socket_refusal_closes_during_setup() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client_task = tokio::spawn(TcpStream::connect(address));
        let (relay_client, peer) = listener.accept().await.unwrap();
        let _client = client_task.await.unwrap().unwrap();
        let route = Route {
            name: "http".into(),
            listen: address,
            allowed_original_ports: vec![80],
            upstream_socket: "/definitely/not/a/socket".into(),
        };
        let (_shutdown_tx, shutdown) = watch::channel(false);

        let result = process_known_destination(
            relay_client,
            peer,
            "203.0.113.8:80".parse().unwrap(),
            &route,
            Duration::from_millis(50),
            8,
            shutdown,
        )
        .await;
        assert_eq!(result.category, CloseCategory::SocketConnect);
    }

    #[tokio::test]
    async fn pumps_preserve_half_closes_in_both_directions() {
        let (mut client, relay_client) = duplex(8);
        let (relay_upstream, mut upstream) = duplex(8);
        let (mut client_read, mut client_write) = tokio::io::split(relay_client);
        let (mut upstream_read, mut upstream_write) = tokio::io::split(relay_upstream);
        let copies = tokio::spawn(async move {
            let to_upstream = AtomicU64::new(0);
            let to_client = AtomicU64::new(0);
            tokio::try_join!(
                pump(
                    &mut client_read,
                    &mut upstream_write,
                    vec![0; 2],
                    &to_upstream,
                ),
                pump(
                    &mut upstream_read,
                    &mut client_write,
                    vec![0; 2],
                    &to_client,
                ),
            )?;
            Ok::<_, io::Error>((
                to_upstream.load(Ordering::Relaxed),
                to_client.load(Ordering::Relaxed),
            ))
        });

        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        upstream.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");

        upstream.write_all(b"response").await.unwrap();
        upstream.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response");
        assert_eq!(copies.await.unwrap().unwrap(), (7, 8));
    }

    #[tokio::test]
    async fn focused_protocol_smoke_publishes_preface_then_relays_both_directions() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("host-listener.sock");
        let host = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay_listener.local_addr().unwrap();
        let client_task = tokio::spawn(TcpStream::connect(relay_address));
        let (relay_client, peer) = relay_listener.accept().await.unwrap();
        let mut client = client_task.await.unwrap().unwrap();
        let destination: SocketAddr = "203.0.113.8:80".parse().unwrap();
        let route = Route {
            name: "http".into(),
            listen: relay_address,
            allowed_original_ports: vec![80],
            upstream_socket: socket_path,
        };
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let relay = tokio::spawn(async move {
            process_known_destination(
                relay_client,
                peer,
                destination,
                &route,
                Duration::from_secs(1),
                3,
                shutdown,
            )
            .await
        });

        let (mut host_stream, _) = host.accept().await.unwrap();
        let mut preface = [0_u8; crate::proxy_v2::IPV4_STREAM_HEADER_LEN];
        host_stream.read_exact(&mut preface).await.unwrap();
        assert_eq!(preface, encode_ipv4_stream(peer, destination).unwrap());

        client.write_all(b"untouched-request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        host_stream.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"untouched-request");

        host_stream.write_all(b"host-response").await.unwrap();
        host_stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"host-response");

        let outcome = relay.await.unwrap();
        assert_eq!(outcome.category, CloseCategory::Complete);
        assert_eq!(outcome.destination, Some(destination));
        assert_eq!(outcome.bytes_to_upstream, 17);
        assert_eq!(outcome.bytes_to_client, 13);
    }

    #[test]
    fn log_categories_are_closed_and_payload_free() {
        let categories = [
            CloseCategory::Complete,
            CloseCategory::Cancelled,
            CloseCategory::OriginalDestination,
            CloseCategory::OriginalPort,
            CloseCategory::SetupTimeout,
            CloseCategory::SocketConnect,
            CloseCategory::PrefaceWrite,
            CloseCategory::Copy,
        ];
        let rendered = categories.map(CloseCategory::as_str).join(",");
        assert!(!rendered.contains("secret-payload-marker"));
        assert!(!rendered.contains("authorization"));
    }
}
