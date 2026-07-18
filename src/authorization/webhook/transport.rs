use std::future::Future;
use std::io;

use http_access_types::CanonicalUrl;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tokio_rustls::TlsConnector;

use super::ack::{
    AcknowledgementError, AcknowledgementParser, AcknowledgementProgress, WebhookAcknowledgement,
};
use super::connector::{WebhookConnector, WebhookConnectorError};
use super::pool::{WebhookInboundBuffer, WebhookOutboundBuffer, WebhookTransportLease};
use super::provider::WebhookProvider;
use super::wire::{encode_request_head, WebhookRequestHeadError};
use crate::safety::GuardedBody;
use http_access_runtime::http1::ParserStoreError;

pub(crate) async fn connect_and_deliver<C>(
    connector: &WebhookConnector,
    provider: &WebhookProvider,
    lease: WebhookTransportLease,
    request_body: GuardedBody,
    cancellation: C,
) -> Result<WebhookAcknowledgement, WebhookDeliveryError>
where
    C: Future<Output = ()> + Send,
{
    let deadline = tokio::time::Instant::now() + provider.timeout();
    let effective_cancellation = async move {
        tokio::select! {
            biased;
            _ = cancellation => {}
            _ = tokio::time::sleep_until(deadline) => {}
        }
    };
    tokio::pin!(effective_cancellation);
    let connected = connector
        .connect(provider.url(), effective_cancellation.as_mut())
        .await
        .map_err(|error| match error {
            WebhookConnectorError::Cancelled => WebhookDeliveryError::Cancelled,
            error => WebhookDeliveryError::Connector(error),
        })?;
    let stream: Box<dyn WebhookIo> = if let Some(config) = provider.tls() {
        let server_name =
            rustls::pki_types::ServerName::try_from(connected.resolution_host().to_owned())
                .map_err(|_| WebhookDeliveryError::TlsServerName)?;
        let stream = connected.into_stream();
        let tls = tokio::select! {
            biased;
            _ = effective_cancellation.as_mut() => return Err(WebhookDeliveryError::Cancelled),
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
        effective_cancellation.as_mut(),
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
    S: AsyncRead + AsyncWrite + Unpin + Send,
    C: Future<Output = ()> + Send,
{
    let request_head_bytes =
        encode_request_head(lease.outbound_mut(), provider_url, request_body.len())?;
    let (outbound, inbound) = lease.split();
    let (reader, writer) = tokio::io::split(stream);
    let (stop, stop_rx) = watch::channel(false);
    let writer = run_writer(
        writer,
        outbound,
        request_body,
        request_head_bytes,
        stop_rx.clone(),
    );
    let reader = run_reader(reader, inbound, max_response_bytes, stop_rx);
    tokio::pin!(writer);
    tokio::pin!(reader);
    tokio::pin!(cancellation);

    enum FirstCompletion {
        Cancelled,
        Writer(WriterCompletion),
        Reader(ReaderTaskCompletion),
    }

    let first = tokio::select! {
        biased;
        _ = &mut cancellation => FirstCompletion::Cancelled,
        completion = &mut writer => FirstCompletion::Writer(completion),
        completion = &mut reader => FirstCompletion::Reader(completion),
    };

    match first {
        FirstCompletion::Cancelled => {
            let _ = stop.send(true);
            let (writer_completion, reader_completion) = tokio::join!(writer, reader);
            drop(writer_completion);
            drop(reader_completion);
            Err(WebhookDeliveryError::Cancelled)
        }
        FirstCompletion::Writer(writer_completion) => {
            let WriterCompletion {
                outbound,
                request_body,
                result: writer_result,
            } = writer_completion;
            if let Err(error) = writer_result {
                let _ = stop.send(true);
                let reader_completion = reader.await;
                drop(outbound);
                drop(request_body);
                drop(reader_completion);
                return Err(WebhookDeliveryError::Write(error));
            }
            let reader_completion = tokio::select! {
                biased;
                _ = &mut cancellation => {
                    let _ = stop.send(true);
                    let reader_completion = reader.await;
                    drop(outbound);
                    drop(request_body);
                    drop(reader_completion);
                    return Err(WebhookDeliveryError::Cancelled);
                }
                completion = &mut reader => completion,
            };
            let result = reader_completion
                .result
                .map_err(WebhookDeliveryError::Acknowledgement);
            drop(outbound);
            drop(request_body);
            drop(reader_completion);
            result
        }
        FirstCompletion::Reader(reader_completion) => {
            let ReaderTaskCompletion {
                inbound,
                result: reader_result,
            } = reader_completion;
            let acknowledgement = match reader_result {
                Ok(acknowledgement) => acknowledgement,
                Err(error) => {
                    let _ = stop.send(true);
                    let writer_completion = writer.await;
                    drop(writer_completion);
                    drop(inbound);
                    return Err(WebhookDeliveryError::Acknowledgement(error));
                }
            };
            let writer_completion = tokio::select! {
                biased;
                _ = &mut cancellation => {
                    let _ = stop.send(true);
                    let writer_completion = writer.await;
                    drop(writer_completion);
                    drop(inbound);
                    return Err(WebhookDeliveryError::Cancelled);
                }
                completion = &mut writer => completion,
            };
            let WriterCompletion {
                outbound,
                request_body,
                result: writer_result,
            } = writer_completion;
            let result = writer_result
                .map(|()| acknowledgement)
                .map_err(WebhookDeliveryError::Write);
            drop(outbound);
            drop(request_body);
            drop(inbound);
            result
        }
    }
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
    Connector(#[from] WebhookConnectorError),
    #[error("webhook request head construction failed")]
    RequestHead(#[from] WebhookRequestHeadError),
    #[error("webhook request write failed")]
    Write(#[source] io::Error),
    #[error("webhook acknowledgement failed")]
    Acknowledgement(#[source] AcknowledgementError),
    #[error("webhook TLS server name is invalid")]
    TlsServerName,
    #[error("webhook TLS handshake failed")]
    TlsHandshake(#[source] io::Error),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use tempfile::TempDir;
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::authorization::webhook::connector::{
        WebhookDestinationFacts, WebhookLocalAddressSnapshot, WebhookLocalAddressSource,
        WebhookResolveFuture, WebhookResolver,
    };
    use crate::authorization::webhook::pool::WebhookTransportArena;
    use crate::authorization::webhook::provider::WebhookProvider;
    use crate::config::compiler::{
        CompiledProviderFailureMode, CompiledTlsTrust, WebhookProviderPlan, WebhookTlsPlan,
    };
    use crate::safety::{HttpWireBodyGuard, WireBodyPool, WireBodyQuotaKey};
    use crate::test_certificates::TestTlsIdentity;
    use http_access_url::canonicalize_http_url;

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

    struct HangingResolver;

    impl WebhookResolver for HangingResolver {
        fn resolve(
            &self,
            _host: &str,
            _port: u16,
            _max_addresses: usize,
        ) -> WebhookResolveFuture<'_> {
            Box::pin(std::future::pending())
        }
    }

    struct FixedResolver(SocketAddr);

    impl WebhookResolver for FixedResolver {
        fn resolve(
            &self,
            _host: &str,
            _port: u16,
            _max_addresses: usize,
        ) -> WebhookResolveFuture<'_> {
            let endpoint = self.0;
            Box::pin(async move { Ok(vec![endpoint]) })
        }
    }

    struct EmptyLocalAddresses;

    impl WebhookLocalAddressSource for EmptyLocalAddresses {
        fn snapshot(&self) -> io::Result<WebhookLocalAddressSnapshot> {
            Ok(WebhookLocalAddressSnapshot::default())
        }
    }

    struct TlsFixture {
        _directory: TempDir,
        ca_certificate: PathBuf,
        acceptor: TlsAcceptor,
    }

    fn tls_fixture(hostname: &str) -> TlsFixture {
        let directory = TempDir::new().unwrap();
        let identity = TestTlsIdentity::new(hostname);
        let ca_certificate = directory.path().join("ca.pem");
        crate::filesystem::write_public_file(&ca_certificate, identity.root_certificate_pem())
            .unwrap();

        TlsFixture {
            _directory: directory,
            ca_certificate,
            acceptor: TlsAcceptor::from(Arc::new(identity.server_config(&[b"h2", b"http/1.1"]))),
        }
    }

    fn tls_provider(
        host: &str,
        port: u16,
        trust: CompiledTlsTrust,
        ca_certificate: Option<PathBuf>,
    ) -> Arc<WebhookProvider> {
        WebhookProvider::activate(
            WebhookProviderPlan {
                url: format!("https://{host}:{port}/authorize"),
                timeout: Duration::from_secs(2),
                on_failure: CompiledProviderFailureMode::Deny,
                include_headers: vec![],
                max_request_bytes: 4096,
                max_response_bytes: 64,
                outputs: BTreeMap::new(),
                tls: Some(WebhookTlsPlan {
                    trust,
                    ca_certificate,
                }),
            },
            || false,
        )
        .unwrap()
    }

    fn loopback_destination(endpoint: SocketAddr) -> WebhookConnector {
        WebhookConnector::with_sources(
            WebhookDestinationFacts::for_test([], None, None, 1).unwrap(),
            Arc::new(FixedResolver(endpoint)),
            Arc::new(EmptyLocalAddresses),
        )
    }

    async fn deliver_over_loopback(
        endpoint: SocketAddr,
        provider: &WebhookProvider,
    ) -> Result<WebhookAcknowledgement, WebhookDeliveryError> {
        let destination = loopback_destination(endpoint);
        let arena = arena();
        let lease = arena.try_acquire().unwrap();
        let guard = guard();
        let result = connect_and_deliver(
            &destination,
            provider,
            lease,
            body(&guard, b"{\"requestId\":\"tls-matrix\"}"),
            std::future::pending(),
        )
        .await;
        assert_eq!(arena.counts().live_deliveries, 0);
        assert_eq!(guard.live_bytes(), 0);
        result
    }

    fn spawn_tls_acknowledgement(
        listener: tokio::net::TcpListener,
        acceptor: TlsAcceptor,
    ) -> tokio::task::JoinHandle<(Option<Vec<u8>>, Vec<u8>)> {
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let negotiated = stream.get_ref().1.alpn_protocol().map(ToOwned::to_owned);
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            let _ = stream.shutdown().await;
            (negotiated, request)
        })
    }

    fn spawn_rejected_tls_handshake(
        listener: tokio::net::TcpListener,
        acceptor: TlsAcceptor,
    ) -> tokio::task::JoinHandle<io::Result<()>> {
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            acceptor.accept(stream).await.map(|_| ())
        })
    }

    #[tokio::test]
    async fn webhook_tls_activation_and_transport_matrix() {
        let trusted = tls_fixture("localhost");
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = spawn_tls_acknowledgement(listener, trusted.acceptor.clone());
        let provider = tls_provider(
            "localhost",
            endpoint.port(),
            CompiledTlsTrust::Custom,
            Some(trusted.ca_certificate.clone()),
        );
        assert_eq!(
            provider.tls().unwrap().alpn_protocols,
            [b"http/1.1".to_vec()]
        );
        assert_eq!(
            deliver_over_loopback(endpoint, &provider)
                .await
                .unwrap()
                .status,
            204
        );
        let (negotiated, request) = server.await.unwrap();
        assert_eq!(negotiated.as_deref(), Some(b"http/1.1".as_slice()));
        assert!(request.starts_with(b"POST /authorize HTTP/1.1\r\n"));

        let untrusted = tls_fixture("not-localhost.invalid");
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = spawn_tls_acknowledgement(listener, untrusted.acceptor.clone());
        let provider = tls_provider(
            "localhost",
            endpoint.port(),
            CompiledTlsTrust::Insecure,
            None,
        );
        assert_eq!(
            deliver_over_loopback(endpoint, &provider)
                .await
                .unwrap()
                .status,
            204
        );
        let (negotiated, _) = server.await.unwrap();
        assert_eq!(negotiated.as_deref(), Some(b"http/1.1".as_slice()));

        let wrong_trust = tls_fixture("wrong-trust.invalid");
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = spawn_rejected_tls_handshake(listener, trusted.acceptor.clone());
        let provider = tls_provider(
            "localhost",
            endpoint.port(),
            CompiledTlsTrust::Custom,
            Some(wrong_trust.ca_certificate.clone()),
        );
        assert!(matches!(
            deliver_over_loopback(endpoint, &provider).await,
            Err(WebhookDeliveryError::TlsHandshake(_))
        ));
        assert!(server.await.unwrap().is_err());

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = spawn_rejected_tls_handshake(listener, trusted.acceptor.clone());
        let provider = tls_provider(
            "wrong-name.invalid",
            endpoint.port(),
            CompiledTlsTrust::Custom,
            Some(trusted.ca_certificate.clone()),
        );
        assert!(matches!(
            deliver_over_loopback(endpoint, &provider).await,
            Err(WebhookDeliveryError::TlsHandshake(_))
        ));
        assert!(server.await.unwrap().is_err());

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let endpoint = listener.local_addr().unwrap();
        let plaintext_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = vec![0u8; 4096];
            let count = stream.read(&mut received).await.unwrap();
            received.truncate(count);
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            let _ = stream.shutdown().await;
            received
        });
        let provider = tls_provider(
            "localhost",
            endpoint.port(),
            CompiledTlsTrust::Insecure,
            None,
        );
        assert!(matches!(
            deliver_over_loopback(endpoint, &provider).await,
            Err(WebhookDeliveryError::TlsHandshake(_))
        ));
        let received = plaintext_server.await.unwrap();
        assert_eq!(received.first().copied(), Some(0x16));
        assert!(!received.windows(5).any(|bytes| bytes == b"POST "));
        assert!(!received
            .windows(b"tls-matrix".len())
            .any(|bytes| bytes == b"tls-matrix"));
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
    async fn dropped_delivery_synchronously_releases_every_owned_resource() {
        let arena = arena();
        let lease = arena.try_acquire().unwrap();
        let guard = guard();
        let request_body = body(&guard, b"{}");
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let timed_out = tokio::time::timeout(
            Duration::from_millis(10),
            deliver_one(
                client,
                lease,
                &canonicalize_http_url("http://localhost/authorize").unwrap(),
                request_body,
                64,
                std::future::pending(),
            ),
        )
        .await;
        assert!(timed_out.is_err());
        assert_eq!(arena.counts().live_deliveries, 0);
        assert_eq!(guard.live_bytes(), 0);
        tokio::time::timeout(Duration::from_secs(1), async {
            let mut byte = [0u8; 1];
            while server.read(&mut byte).await.unwrap() != 0 {}
        })
        .await
        .unwrap();
        assert!(arena.try_acquire().is_ok());
    }

    #[tokio::test]
    async fn provider_deadline_covers_resolution_and_releases_admission() {
        let provider = WebhookProvider::activate(
            WebhookProviderPlan {
                url: "http://localhost/authorize".to_owned(),
                timeout: Duration::from_millis(10),
                on_failure: CompiledProviderFailureMode::Deny,
                include_headers: vec![],
                max_request_bytes: 4096,
                max_response_bytes: 64,
                outputs: BTreeMap::new(),
                tls: None,
            },
            || false,
        )
        .unwrap();
        let destination = WebhookConnector::with_sources(
            WebhookDestinationFacts::for_test([], None, None, 1).unwrap(),
            Arc::new(HangingResolver),
            Arc::new(EmptyLocalAddresses),
        );
        let arena = arena();
        let lease = arena.try_acquire().unwrap();
        let guard = guard();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            connect_and_deliver(
                &destination,
                &provider,
                lease,
                body(&guard, b"{}"),
                std::future::pending(),
            ),
        )
        .await
        .unwrap();
        assert!(matches!(result, Err(WebhookDeliveryError::Cancelled)));
        assert_eq!(arena.counts().live_deliveries, 0);
        assert_eq!(guard.live_bytes(), 0);
    }

    #[tokio::test]
    async fn provider_deadline_bounds_close_delimited_acknowledgement_drain() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let endpoint = listener.local_addr().unwrap();
        let (release_server, hold_server) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            while stream.read(&mut request).await.unwrap() != 0 {}
            stream
                .write_all(b"HTTP/1.1 200 OK\r\n\r\npartial")
                .await
                .unwrap();
            let _ = hold_server.await;
            drop(stream);
        });
        let provider = WebhookProvider::activate(
            WebhookProviderPlan {
                url: format!("http://localhost:{}/authorize", endpoint.port()),
                timeout: Duration::from_millis(100),
                on_failure: CompiledProviderFailureMode::Deny,
                include_headers: vec![],
                max_request_bytes: 4096,
                max_response_bytes: 64,
                outputs: BTreeMap::new(),
                tls: None,
            },
            || false,
        )
        .unwrap();
        let destination = WebhookConnector::with_sources(
            WebhookDestinationFacts::for_test([], None, None, 1).unwrap(),
            Arc::new(FixedResolver(endpoint)),
            Arc::new(EmptyLocalAddresses),
        );
        let arena = arena();
        let lease = arena.try_acquire().unwrap();
        let guard = guard();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            connect_and_deliver(
                &destination,
                &provider,
                lease,
                body(&guard, b"{}"),
                std::future::pending(),
            ),
        )
        .await
        .unwrap();
        assert!(matches!(result, Err(WebhookDeliveryError::Cancelled)));
        release_server.send(()).unwrap();
        server.await.unwrap();
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
