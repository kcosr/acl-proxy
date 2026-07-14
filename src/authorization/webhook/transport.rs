use std::future::Future;
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tokio::task::JoinError;
use tokio_rustls::TlsConnector;

use super::ack::{
    AcknowledgementError, AcknowledgementParser, AcknowledgementProgress, WebhookAcknowledgement,
};
use super::pool::{WebhookInboundBuffer, WebhookOutboundBuffer, WebhookTransportLease};
use super::provider::WebhookProvider;
use super::wire::{encode_request_head, WebhookRequestHeadError};
use crate::destination::{DestinationGuard, DestinationGuardError, DestinationTarget};
use crate::http1::store::ParserStoreError;
use crate::safety::GuardedBody;
use crate::url::CanonicalUrl;

pub(crate) async fn connect_and_deliver<C>(
    destination_guard: &DestinationGuard,
    provider: &WebhookProvider,
    lease: WebhookTransportLease,
    request_body: GuardedBody,
    cancellation: C,
) -> Result<WebhookAcknowledgement, WebhookDeliveryError>
where
    C: Future<Output = ()> + Send,
{
    tokio::pin!(cancellation);
    let resolved = tokio::select! {
        biased;
        _ = cancellation.as_mut() => return Err(WebhookDeliveryError::Cancelled),
        result = destination_guard.resolve(DestinationTarget::webhook(provider.url())) => result?,
    };
    let connected = tokio::select! {
        biased;
        _ = cancellation.as_mut() => return Err(WebhookDeliveryError::Cancelled),
        result = destination_guard.connect_system(resolved) => result?,
    };
    let stream: Box<dyn WebhookIo> = if let Some(config) = provider.tls() {
        let server_name = rustls::ServerName::try_from(connected.resolution_host())
            .map_err(|_| WebhookDeliveryError::TlsServerName)?;
        let stream = connected.into_stream();
        let tls = tokio::select! {
            biased;
            _ = cancellation.as_mut() => return Err(WebhookDeliveryError::Cancelled),
            result = TlsConnector::from(config).connect(server_name, stream) => {
                result.map_err(WebhookDeliveryError::TlsHandshake)?
            },
        };
        Box::new(tls)
    } else {
        Box::new(connected.into_stream())
    };
    deliver_one(
        stream,
        lease,
        provider.url(),
        request_body,
        provider.max_response_bytes(),
        cancellation.as_mut(),
    )
    .await
}

trait WebhookIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> WebhookIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(crate) async fn deliver_one<S, C>(
    stream: S,
    mut lease: WebhookTransportLease,
    provider_url: &CanonicalUrl,
    request_body: GuardedBody,
    max_response_bytes: usize,
    cancellation: C,
) -> Result<WebhookAcknowledgement, WebhookDeliveryError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C: Future<Output = ()> + Send,
{
    let request_head_bytes =
        encode_request_head(lease.outbound_mut(), provider_url, request_body.len())?;
    let (outbound, inbound) = lease.split();
    let (reader, writer) = tokio::io::split(stream);
    let (stop, stop_rx) = watch::channel(false);
    let mut writer_task = tokio::spawn(run_writer(
        writer,
        outbound,
        request_body,
        request_head_bytes,
        stop_rx.clone(),
    ));
    let mut reader_task = tokio::spawn(run_reader(reader, inbound, max_response_bytes, stop_rx));
    tokio::pin!(cancellation);

    let mut writer_completion = None;
    let mut reader_completion = None;
    let mut acknowledgement = None;
    let mut writer_done = false;
    let mut reader_done = false;
    let terminal = loop {
        tokio::select! {
            biased;
            _ = &mut cancellation => break Err(WebhookDeliveryError::Cancelled),
            joined = &mut writer_task, if !writer_done => {
                writer_done = true;
                match joined {
                    Ok(completion) => {
                        let WriterCompletion { outbound, request_body, result } = completion;
                        writer_completion = Some((outbound, request_body));
                        if let Err(error) = result {
                            break Err(WebhookDeliveryError::Write(error));
                        }
                    }
                    Err(error) => break Err(WebhookDeliveryError::Task(error)),
                }
                if reader_completion.is_some() {
                    break Ok(acknowledgement.expect("successful reader completed"));
                }
            }
            joined = &mut reader_task, if !reader_done => {
                reader_done = true;
                match joined {
                    Ok(completion) => {
                        reader_completion = Some(completion.inbound);
                        match completion.result {
                            Ok(value) => acknowledgement = Some(value),
                            Err(error) => break Err(WebhookDeliveryError::Acknowledgement(error)),
                        }
                    }
                    Err(error) => break Err(WebhookDeliveryError::Task(error)),
                }
                if writer_completion.is_some() {
                    break Ok(acknowledgement.expect("successful reader completed"));
                }
            }
        }
    };

    let _ = stop.send(true);
    if !writer_done {
        match writer_task.await {
            Ok(completion) => {
                let WriterCompletion {
                    outbound,
                    request_body,
                    ..
                } = completion;
                writer_completion = Some((outbound, request_body));
            }
            Err(error) if terminal.is_ok() => return Err(WebhookDeliveryError::Task(error)),
            Err(_) => {}
        }
    }
    if !reader_done {
        match reader_task.await {
            Ok(completion) => reader_completion = Some(completion.inbound),
            Err(error) if terminal.is_ok() => return Err(WebhookDeliveryError::Task(error)),
            Err(_) => {}
        }
    }

    // These values own all sensitive delivery allocations. Their explicit
    // teardown occurs only after both task joins above have completed.
    drop(writer_completion);
    drop(reader_completion);
    terminal
}

struct WriterCompletion {
    outbound: WebhookOutboundBuffer,
    request_body: GuardedBody,
    result: io::Result<()>,
}

async fn run_writer<W>(
    mut writer: W,
    outbound: WebhookOutboundBuffer,
    request_body: GuardedBody,
    request_head_bytes: usize,
    mut stop: watch::Receiver<bool>,
) -> WriterCompletion
where
    W: AsyncWrite + Unpin,
{
    let result = async {
        write_all_or_stop(
            &mut writer,
            &outbound.as_ref()[..request_head_bytes],
            &mut stop,
        )
        .await?;
        for segment in request_body.segments() {
            write_all_or_stop(&mut writer, segment, &mut stop).await?;
        }
        shutdown_or_stop(&mut writer, &mut stop).await
    }
    .await;
    WriterCompletion {
        outbound,
        request_body,
        result,
    }
}

async fn write_all_or_stop<W>(
    writer: &mut W,
    mut bytes: &[u8],
    stop: &mut watch::Receiver<bool>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while !bytes.is_empty() {
        if *stop.borrow() {
            return Err(cancelled_io());
        }
        let written = tokio::select! {
            biased;
            changed = stop.changed() => {
                let _ = changed;
                return Err(cancelled_io());
            }
            written = writer.write(bytes) => written?,
        };
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "webhook socket write returned zero",
            ));
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

async fn shutdown_or_stop<W>(writer: &mut W, stop: &mut watch::Receiver<bool>) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if *stop.borrow() {
        return Err(cancelled_io());
    }
    tokio::select! {
        biased;
        changed = stop.changed() => {
            let _ = changed;
            Err(cancelled_io())
        }
        result = writer.shutdown() => result,
    }
}

struct ReaderTaskCompletion {
    inbound: WebhookInboundBuffer,
    result: Result<WebhookAcknowledgement, AcknowledgementError>,
}

async fn run_reader<R>(
    mut reader: R,
    mut inbound: WebhookInboundBuffer,
    max_response_bytes: usize,
    mut stop: watch::Receiver<bool>,
) -> ReaderTaskCompletion
where
    R: AsyncRead + Unpin,
{
    let result = async {
        let mut parser = AcknowledgementParser::new(max_response_bytes)?;
        loop {
            match parser.process(inbound.parser_store_mut(), false)? {
                AcknowledgementProgress::Complete(acknowledgement) => return Ok(acknowledgement),
                AcknowledgementProgress::NeedInput => {}
            }
            if *stop.borrow() {
                return Err(AcknowledgementError::Cancelled);
            }
            let writable = inbound.parser_store_mut().writable();
            if writable.is_empty() {
                return Err(AcknowledgementError::StoreCapacityExceeded);
            }
            let read = tokio::select! {
                biased;
                changed = stop.changed() => {
                    let _ = changed;
                    return Err(AcknowledgementError::Cancelled);
                }
                read = reader.read(writable) => read.map_err(|_| AcknowledgementError::Read)?,
            };
            inbound
                .parser_store_mut()
                .commit_written(read)
                .map_err(map_store_error)?;
            if read == 0 {
                return match parser.process(inbound.parser_store_mut(), true)? {
                    AcknowledgementProgress::Complete(acknowledgement) => Ok(acknowledgement),
                    AcknowledgementProgress::NeedInput => {
                        Err(AcknowledgementError::UnexpectedEndOfStream)
                    }
                };
            }
        }
    }
    .await;
    ReaderTaskCompletion { inbound, result }
}

fn map_store_error(_: ParserStoreError) -> AcknowledgementError {
    AcknowledgementError::StoreCapacityExceeded
}

fn cancelled_io() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "webhook delivery stopped")
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WebhookDeliveryError {
    #[error("webhook delivery was cancelled")]
    Cancelled,
    #[error("webhook destination validation or connection failed")]
    Destination(#[from] DestinationGuardError),
    #[error("webhook request head construction failed")]
    RequestHead(#[from] WebhookRequestHeadError),
    #[error("webhook request write failed")]
    Write(#[source] io::Error),
    #[error("webhook acknowledgement failed")]
    Acknowledgement(#[source] AcknowledgementError),
    #[error("webhook delivery task failed")]
    Task(#[source] JoinError),
    #[error("webhook TLS server name is invalid")]
    TlsServerName,
    #[error("webhook TLS handshake failed")]
    TlsHandshake(#[source] io::Error),
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use tokio::sync::oneshot;

    use super::*;
    use crate::authorization::webhook::pool::WebhookTransportArena;
    use crate::safety::{HttpWireBodyGuard, WireBodyPool, WireBodyQuotaKey};
    use crate::url::canonicalize_http_url;

    fn guard() -> HttpWireBodyGuard {
        WireBodyPool::new(1024 * 1024, 1024 * 1024).begin_for_test(
            128 * 1024,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        )
    }

    fn body(guard: &HttpWireBodyGuard, bytes: &[u8]) -> GuardedBody {
        let mut body = guard.buffer();
        body.try_extend_from_slice(bytes).unwrap();
        body.finish()
    }

    fn arena() -> WebhookTransportArena {
        WebhookTransportArena::try_new(1, 64 * 1024, 128 * 1024).unwrap()
    }

    #[tokio::test]
    async fn webhook_transport_is_one_shot_nonpooled_and_joined() {
        for status in [200, 204, 299] {
            let arena = arena();
            let lease = arena.try_acquire().unwrap();
            let guard = guard();
            let request_body = body(&guard, b"{\"safe\":true}");
            let (client, mut server) = tokio::io::duplex(256 * 1024);
            let server_task = tokio::spawn(async move {
                let mut request = Vec::new();
                let mut scratch = [0u8; 1024];
                loop {
                    let read = server.read(&mut scratch).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&scratch[..read]);
                }
                assert!(request.starts_with(b"POST /authorize?mode=one HTTP/1.1\r\n"));
                assert!(request
                    .windows(19)
                    .any(|window| window == b"Connection: close\r\n"));
                server
                    .write_all(
                        format!("HTTP/1.1 {status} Ack\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
            });
            let acknowledgement = deliver_one(
                client,
                lease,
                &canonicalize_http_url("http://localhost/authorize?mode=one").unwrap(),
                request_body,
                64,
                std::future::pending(),
            )
            .await
            .unwrap();
            assert_eq!(acknowledgement.status, status);
            server_task.await.unwrap();
            assert_eq!(arena.counts().live_deliveries, 0);
            assert_eq!(guard.live_bytes(), 0);
        }
    }

    #[tokio::test]
    async fn cancellation_joins_both_tasks_before_releasing_delivery_resources() {
        let arena = arena();
        let lease = arena.try_acquire().unwrap();
        let guard = guard();
        let request_body = body(&guard, b"{}");
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let (cancel, cancelled) = oneshot::channel();
        let delivery = tokio::spawn(async move {
            deliver_one(
                client,
                lease,
                &canonicalize_http_url("http://localhost/authorize").unwrap(),
                request_body,
                64,
                async {
                    let _ = cancelled.await;
                },
            )
            .await
        });
        let mut request = [0u8; 256];
        assert!(server.read(&mut request).await.unwrap() > 0);
        cancel.send(()).unwrap();
        assert!(matches!(
            delivery.await.unwrap(),
            Err(WebhookDeliveryError::Cancelled)
        ));
        let eof = tokio::time::timeout(Duration::from_secs(1), server.read(&mut request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(eof, 0);
        assert_eq!(arena.counts().live_deliveries, 0);
        assert_eq!(guard.live_bytes(), 0);
    }

    #[tokio::test]
    async fn malformed_acknowledgement_closes_and_releases_everything() {
        let arena = arena();
        let lease = arena.try_acquire().unwrap();
        let guard = guard();
        let request_body = body(&guard, b"{}");
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut scratch = [0u8; 1024];
            while server.read(&mut scratch).await.unwrap() != 0 {}
            server
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n")
                .await
                .unwrap();
        });
        let result = deliver_one(
            client,
            lease,
            &canonicalize_http_url("http://localhost/authorize").unwrap(),
            request_body,
            64,
            std::future::pending(),
        )
        .await;
        assert!(matches!(
            result,
            Err(WebhookDeliveryError::Acknowledgement(_))
        ));
        server_task.await.unwrap();
        assert_eq!(arena.counts().live_deliveries, 0);
        assert_eq!(guard.live_bytes(), 0);
    }
}
