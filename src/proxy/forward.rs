use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use http::header::{HeaderValue, HOST};
use http::{Method, Request, Response, StatusCode, Version};
use hyper::body::{Bytes, HttpBody, SizeHint};
use hyper::client::conn;
use hyper::Body;
use rustls::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::destination::{
    DestinationConnector, DestinationGuard, DestinationGuardError, DestinationTarget,
    ResolvedDestination, TcpDestinationConnector,
};
use crate::egress::{
    EgressRoute, OriginProtocol, OriginProtocolError, ParentAlpnError, ParentEndpoint,
    ParentTransport,
};
use crate::runtime::EgressSnapshot;
use crate::url::CanonicalUrl;

use super::headers::{
    prepare_origin_request, strip_response_hop_by_hop, HeaderPreparationError, RequestTargetForm,
    SanitizedRequest,
};

const TERMINAL_DRIVER_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub(crate) enum ForwardError {
    #[error("destination validation or connection failed")]
    Destination(#[from] DestinationGuardError),
    #[error(transparent)]
    Header(#[from] HeaderPreparationError),
    #[error("the canonical TLS server name is invalid")]
    TlsServerName,
    #[error("TLS connection failed")]
    Tls(#[source] std::io::Error),
    #[error(transparent)]
    OriginProtocol(#[from] OriginProtocolError),
    #[error(transparent)]
    ParentProtocol(#[from] ParentAlpnError),
    #[error("HTTP forwarding failed")]
    Http(#[source] hyper::Error),
    #[error("HTTP forwarding task failed")]
    Task(#[source] tokio::task::JoinError),
    #[error("parent proxy rejected CONNECT with status {0}")]
    ParentConnect(StatusCode),
    #[error("the resolved forwarding target does not belong to this request and egress route")]
    ResolvedTargetMismatch,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ResolveForwardingError {
    #[error(transparent)]
    Destination(#[from] DestinationGuardError),
}

#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum ForwardBodyError {
    #[error("upstream response body failed")]
    Body(#[source] std::sync::Arc<hyper::Error>),
    #[error("upstream connection failed")]
    Connection(#[source] std::sync::Arc<hyper::Error>),
    #[error("upstream connection task failed")]
    Task(#[source] std::sync::Arc<tokio::task::JoinError>),
    #[error("upstream connection did not finish before the terminal drain deadline")]
    Timeout,
}

pub(crate) struct ForwardBody {
    body: Option<Body>,
    data_done: bool,
    trailers: Option<Option<http::HeaderMap>>,
    terminal_error: Option<ForwardBodyError>,
    terminal_drain_timeout: Duration,
    terminal_drain_deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    terminal_driver_abort_started: bool,
    driver: DriverTask,
}

struct DriverTask {
    handle: Option<tokio::task::JoinHandle<Result<(), hyper::Error>>>,
}

impl DriverTask {
    fn spawn<F>(driver: F) -> Self
    where
        F: Future<Output = Result<(), hyper::Error>> + Send + 'static,
    {
        Self {
            handle: Some(tokio::spawn(driver)),
        }
    }

    fn from_handle(handle: tokio::task::JoinHandle<Result<(), hyper::Error>>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    fn poll(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<Result<(), hyper::Error>, tokio::task::JoinError>> {
        let Some(handle) = self.handle.as_mut() else {
            return Poll::Ready(Ok(Ok(())));
        };
        match Pin::new(handle).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.handle.take();
                Poll::Ready(result)
            }
        }
    }

    fn abort(&mut self) {
        if let Some(handle) = self.handle.as_ref() {
            handle.abort();
        }
    }

    async fn abort_and_join(mut self) {
        self.abort();
        let _ = std::future::poll_fn(|context| self.poll(context)).await;
    }

    async fn join(mut self) -> Result<Result<(), hyper::Error>, tokio::task::JoinError> {
        std::future::poll_fn(|context| self.poll(context)).await
    }

    fn is_finished(&self) -> bool {
        self.handle.is_none()
    }
}

impl Drop for DriverTask {
    fn drop(&mut self) {
        self.abort();
    }
}

impl ForwardBody {
    fn new(body: Body, driver: DriverTask) -> Self {
        Self {
            body: Some(body),
            data_done: false,
            trailers: None,
            terminal_error: None,
            terminal_drain_timeout: TERMINAL_DRIVER_DRAIN_TIMEOUT,
            terminal_drain_deadline: None,
            terminal_driver_abort_started: false,
            driver,
        }
    }

    #[cfg(test)]
    fn with_terminal_drain_timeout(mut self, timeout: Duration) -> Self {
        self.terminal_drain_timeout = timeout;
        self
    }

    fn begin_terminal_drain(&mut self) {
        if self.terminal_drain_deadline.is_none() {
            self.terminal_drain_deadline =
                Some(Box::pin(tokio::time::sleep(self.terminal_drain_timeout)));
        }
    }

    fn poll_incomplete_response_timeout(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<ForwardBodyError> {
        let Some(deadline) = self.terminal_drain_deadline.as_mut() else {
            return Poll::Pending;
        };
        if deadline.as_mut().poll(context).is_pending() {
            return Poll::Pending;
        }

        self.body.take();
        self.trailers.take();
        self.terminal_error.get_or_insert(ForwardBodyError::Timeout);
        self.poll_terminal_error_join(context)
    }

    fn poll_aborted_terminal_driver_join(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), ForwardBodyError>> {
        match self.driver.poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(_) => Poll::Ready(Ok(())),
        }
    }

    fn poll_driver_drain_timeout(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), ForwardBodyError>> {
        let Some(deadline) = self.terminal_drain_deadline.as_mut() else {
            return Poll::Pending;
        };
        if deadline.as_mut().poll(context).is_pending() {
            return Poll::Pending;
        }

        self.terminal_driver_abort_started = true;
        self.driver.abort();
        self.poll_aborted_terminal_driver_join(context)
    }

    fn poll_response_trailers(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), ForwardBodyError>> {
        if self.trailers.is_some() {
            return Poll::Ready(Ok(()));
        }
        let trailers = match self.body.as_mut() {
            Some(body) => match Pin::new(body).poll_trailers(context) {
                Poll::Pending => return self.poll_incomplete_response_timeout(context).map(Err),
                Poll::Ready(Ok(trailers)) => trailers,
                Poll::Ready(Err(error)) => {
                    self.body.take();
                    self.terminal_error = Some(ForwardBodyError::Body(std::sync::Arc::new(error)));
                    return Poll::Ready(Err(self
                        .terminal_error
                        .as_ref()
                        .expect("terminal response-body error was stored")
                        .clone()));
                }
            },
            None => None,
        };
        self.body.take();
        self.trailers = Some(trailers.map(|mut headers| {
            strip_response_hop_by_hop(&mut headers);
            headers
        }));
        Poll::Ready(Ok(()))
    }

    fn poll_terminal_error_join(&mut self, context: &mut Context<'_>) -> Poll<ForwardBodyError> {
        self.driver.abort();
        match self.driver.poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(_) => Poll::Ready(
                self.terminal_error
                    .as_ref()
                    .expect("terminal response-body error is present while joining")
                    .clone(),
            ),
        }
    }

    fn poll_driver_completion(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), ForwardBodyError>> {
        if self.terminal_error.is_some() {
            return self.poll_terminal_error_join(context).map(Err);
        }
        if self.terminal_driver_abort_started {
            return self.poll_aborted_terminal_driver_join(context);
        }
        match self.driver.poll(context) {
            Poll::Pending => self.poll_driver_drain_timeout(context),
            Poll::Ready(Ok(Ok(()))) => Poll::Ready(Ok(())),
            Poll::Ready(Ok(Err(error))) => {
                let error = ForwardBodyError::Connection(std::sync::Arc::new(error));
                self.terminal_error = Some(error.clone());
                Poll::Ready(Err(error))
            }
            Poll::Ready(Err(error)) => {
                let error = ForwardBodyError::Task(std::sync::Arc::new(error));
                self.terminal_error = Some(error.clone());
                Poll::Ready(Err(error))
            }
        }
    }
}

impl HttpBody for ForwardBody {
    type Data = Bytes;
    type Error = ForwardBodyError;

    fn poll_data(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        if self.terminal_error.is_some() {
            return match self.poll_terminal_error_join(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(error) => Poll::Ready(Some(Err(error))),
            };
        }
        if !self.data_done {
            if let Some(body) = self.body.as_mut() {
                match Pin::new(body).poll_data(context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Ok(bytes))) => return Poll::Ready(Some(Ok(bytes))),
                    Poll::Ready(Some(Err(error))) => {
                        self.body.take();
                        self.trailers.take();
                        self.terminal_error =
                            Some(ForwardBodyError::Body(std::sync::Arc::new(error)));
                        return match self.poll_terminal_error_join(context) {
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(error) => Poll::Ready(Some(Err(error))),
                        };
                    }
                    Poll::Ready(None) => {
                        self.data_done = true;
                        self.begin_terminal_drain();
                    }
                }
            } else {
                self.data_done = true;
                self.begin_terminal_drain();
            }
        }
        match self.poll_response_trailers(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => {
                return match self.poll_terminal_error_join(context) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(error) => Poll::Ready(Some(Err(error))),
                };
            }
        }
        match self.poll_driver_completion(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(None),
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
        }
    }

    fn poll_trailers(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<Option<http::HeaderMap>, Self::Error>> {
        if self.terminal_error.is_some() {
            return match self.poll_terminal_error_join(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(error) => Poll::Ready(Err(error)),
            };
        }
        match self.poll_response_trailers(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => {
                return match self.poll_terminal_error_join(context) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(error) => Poll::Ready(Err(error)),
                };
            }
        }

        match self.poll_driver_completion(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(self.trailers.take().flatten())),
            Poll::Ready(Err(error)) => {
                self.trailers.take();
                Poll::Ready(Err(error))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.terminal_error.is_none()
            && self.data_done
            && self.body.is_none()
            && self.driver.is_finished()
            && self
                .trailers
                .as_ref()
                .is_none_or(|trailers| trailers.is_none())
    }

    fn size_hint(&self) -> SizeHint {
        if self.data_done {
            return SizeHint::with_exact(0);
        }
        self.body
            .as_ref()
            .map(HttpBody::size_hint)
            .unwrap_or_default()
    }
}

pub(crate) type ForwardedResponse = Response<ForwardBody>;

pub(crate) struct ResolvedForwardingTarget<'egress> {
    canonical_url: String,
    ingress_protocol: OriginProtocol,
    origin_protocol: OriginProtocol,
    egress_identity: usize,
    route: ResolvedForwardingRoute,
    _egress: std::marker::PhantomData<&'egress dyn EgressSnapshot>,
}

enum ResolvedForwardingRoute {
    Direct(ResolvedDestination),
    Parent {
        parent_url: String,
        destination: ResolvedDestination,
    },
}

/// Resolves and validates the destination before policy or provider dispatch.
/// The opaque result is consumed exactly once by `forward_request`.
pub(crate) async fn resolve_forwarding_target<'egress>(
    canonical: &CanonicalUrl,
    request: &SanitizedRequest<impl Sized>,
    egress: &'egress dyn EgressSnapshot,
    destinations: &DestinationGuard,
) -> Result<ResolvedForwardingTarget<'egress>, ResolveForwardingError> {
    let ingress_protocol = request.protocol();
    let origin_protocol = egress.origin_tls().select_protocol(ingress_protocol);
    let egress_identity = egress.route() as *const EgressRoute as usize;
    let route = match egress.route() {
        EgressRoute::Direct => ResolvedForwardingRoute::Direct(
            destinations
                .resolve(DestinationTarget::direct(canonical))
                .await?,
        ),
        EgressRoute::Parent(parent) => ResolvedForwardingRoute::Parent {
            parent_url: parent.canonical_url().to_owned(),
            destination: destinations
                .resolve(DestinationTarget::parent(parent.authority(), canonical))
                .await?,
        },
    };
    Ok(ResolvedForwardingTarget {
        canonical_url: canonical.url.clone(),
        ingress_protocol,
        origin_protocol,
        egress_identity,
        route,
        _egress: std::marker::PhantomData,
    })
}

/// Sends one already-authorized logical origin request without connection reuse.
/// The destination token carries the only DNS result; connect performs the
/// synchronous pre- and post-connect validation before any outbound bytes.
pub(crate) async fn forward_request<'egress, B>(
    request: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    egress: &'egress dyn EgressSnapshot,
    destinations: &DestinationGuard,
    target: ResolvedForwardingTarget<'egress>,
) -> Result<ForwardedResponse, ForwardError>
where
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    forward_with_connector(
        request,
        canonical,
        egress,
        destinations,
        target,
        &TcpDestinationConnector,
    )
    .await
}

async fn forward_with_connector<'egress, C, B>(
    request: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    egress: &'egress dyn EgressSnapshot,
    destinations: &DestinationGuard,
    target: ResolvedForwardingTarget<'egress>,
    connector: &C,
) -> Result<ForwardedResponse, ForwardError>
where
    C: DestinationConnector,
    C::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let selected_origin_protocol = egress.origin_tls().select_protocol(request.protocol());
    if target.canonical_url != canonical.url
        || target.ingress_protocol != request.protocol()
        || target.origin_protocol != selected_origin_protocol
        || target.egress_identity != egress.route() as *const EgressRoute as usize
    {
        return Err(ForwardError::ResolvedTargetMismatch);
    }

    match (egress.route(), target.route) {
        (EgressRoute::Direct, ResolvedForwardingRoute::Direct(resolved)) => {
            let stream = destinations
                .connect(resolved, connector)
                .await?
                .into_stream();
            forward_direct(request, canonical, egress, selected_origin_protocol, stream).await
        }
        (
            EgressRoute::Parent(parent),
            ResolvedForwardingRoute::Parent {
                parent_url,
                destination: resolved,
            },
        ) if parent_url == parent.canonical_url() => {
            let stream = destinations
                .connect(resolved, connector)
                .await?
                .into_stream();
            forward_via_parent(
                request,
                canonical,
                egress,
                parent,
                selected_origin_protocol,
                stream,
            )
            .await
        }
        _ => Err(ForwardError::ResolvedTargetMismatch),
    }
}

async fn forward_direct<S, B>(
    request: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    egress: &dyn EgressSnapshot,
    protocol: OriginProtocol,
    stream: S,
) -> Result<ForwardedResponse, ForwardError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if canonical.scheme == "https" {
        let stream = connect_origin_tls(stream, canonical, egress, protocol).await?;
        let request =
            prepare_origin_request(request, canonical, RequestTargetForm::Origin, protocol)?;
        send_request(stream, request, protocol).await
    } else {
        let request =
            prepare_origin_request(request, canonical, RequestTargetForm::Origin, protocol)?;
        send_request(stream, request, protocol).await
    }
}

async fn forward_via_parent<S, B>(
    request: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    egress: &dyn EgressSnapshot,
    parent: &ParentEndpoint,
    protocol: OriginProtocol,
    stream: S,
) -> Result<ForwardedResponse, ForwardError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if canonical.scheme == "https" {
        // CONNECT is deliberately HTTP/1.1 and contains no logical-origin
        // headers. The selected origin protocol applies inside the tunnel.
        match parent.transport() {
            ParentTransport::Http => {
                let tunnel = connect_parent_tunnel(stream, canonical).await?;
                let origin = connect_origin_tls(tunnel, canonical, egress, protocol).await?;
                let request = prepare_origin_request(
                    request,
                    canonical,
                    RequestTargetForm::Origin,
                    protocol,
                )?;
                send_request(origin, request, protocol).await
            }
            ParentTransport::Https(tls) => {
                let parent_stream = connect_parent_tls(stream, tls, false).await?;
                let tunnel = connect_parent_tunnel(parent_stream, canonical).await?;
                let origin = connect_origin_tls(tunnel, canonical, egress, protocol).await?;
                let request = prepare_origin_request(
                    request,
                    canonical,
                    RequestTargetForm::Origin,
                    protocol,
                )?;
                send_request(origin, request, protocol).await
            }
        }
    } else {
        let request =
            prepare_origin_request(request, canonical, RequestTargetForm::Absolute, protocol)?;
        match parent.transport() {
            ParentTransport::Http => send_request(stream, request, protocol).await,
            ParentTransport::Https(tls) => {
                let stream = connect_parent_tls(stream, tls, protocol.is_http2()).await?;
                send_request(stream, request, protocol).await
            }
        }
    }
}

async fn connect_origin_tls<S>(
    stream: S,
    canonical: &CanonicalUrl,
    egress: &dyn EgressSnapshot,
    protocol: OriginProtocol,
) -> Result<TlsStream<S>, ForwardError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let name =
        ServerName::try_from(canonical.host.as_str()).map_err(|_| ForwardError::TlsServerName)?;
    let connector = TlsConnector::from(egress.origin_tls().client_config(protocol)?);
    let stream = connector
        .connect(name, stream)
        .await
        .map_err(ForwardError::Tls)?;
    egress
        .origin_tls()
        .validate_negotiated_alpn(protocol, stream.get_ref().1.alpn_protocol())?;
    Ok(stream)
}

async fn connect_parent_tls<S>(
    stream: S,
    tls: &crate::egress::ParentTls,
    use_http2: bool,
) -> Result<TlsStream<S>, ForwardError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let name = ServerName::try_from(tls.server_name()).map_err(|_| ForwardError::TlsServerName)?;
    let connector = TlsConnector::from(tls.client_config(use_http2));
    let stream = connector
        .connect(name, stream)
        .await
        .map_err(ForwardError::Tls)?;
    tls.validate_negotiated_alpn(use_http2, stream.get_ref().1.alpn_protocol())?;
    Ok(stream)
}

async fn connect_parent_tunnel<S>(
    stream: S,
    canonical: &CanonicalUrl,
) -> Result<hyper::upgrade::Upgraded, ForwardError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let authority = format!("{}:{}", canonical.host_for_capture, canonical.port);
    let uri: http::Uri = authority
        .parse()
        .map_err(|_| HeaderPreparationError::Target)?;
    let host = HeaderValue::from_str(&authority).map_err(|_| HeaderPreparationError::Authority)?;
    let request = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_11)
        .uri(uri)
        .header(HOST, host)
        .body(Body::empty())
        .map_err(|_| HeaderPreparationError::Target)?;

    let (mut sender, connection) = conn::Builder::new()
        .handshake(stream)
        .await
        .map_err(ForwardError::Http)?;
    let driver = DriverTask::spawn(connection);

    let mut response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(error) => {
            driver.abort_and_join().await;
            return Err(ForwardError::Http(error));
        }
    };
    if !response.status().is_success() {
        driver.abort_and_join().await;
        return Err(ForwardError::ParentConnect(response.status()));
    }
    let upgraded = match hyper::upgrade::on(&mut response).await {
        Ok(upgraded) => upgraded,
        Err(error) => {
            driver.abort_and_join().await;
            return Err(ForwardError::Http(error));
        }
    };
    match driver.join().await {
        Ok(Ok(())) => Ok(upgraded),
        Ok(Err(error)) => Err(ForwardError::Http(error)),
        Err(error) => Err(ForwardError::Task(error)),
    }
}

async fn send_request<S, B>(
    stream: S,
    request: Request<B>,
    protocol: OriginProtocol,
) -> Result<ForwardedResponse, ForwardError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut builder = conn::Builder::new();
    if protocol.is_http2() {
        builder.http2_only(true);
    }
    let (mut sender, connection) = builder
        .handshake(stream)
        .await
        .map_err(ForwardError::Http)?;
    let driver = DriverTask::spawn(connection);
    let response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(error) => {
            driver.abort_and_join().await;
            return Err(ForwardError::Http(error));
        }
    };
    let (mut parts, body) = response.into_parts();
    strip_response_hop_by_hop(&mut parts.headers);
    Ok(Response::from_parts(parts, ForwardBody::new(body, driver)))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::io;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use http::header::TE;
    use hyper::server::conn::Http;
    use hyper::service::service_fn;
    use rcgen::generate_simple_self_signed;
    use rustls::{Certificate, PrivateKey, ServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::config::compiler::{
        CompiledEgressRoute, CompiledHttpVersion, CompiledParentProxyKind, CompiledTlsTrust,
        EgressPlan, ParentProxyPlan, ParentProxyTlsPlan, TransportTlsPlan,
    };
    use crate::destination::{
        DestinationFacts, DestinationResolver, LocalAddressSnapshot, LocalAddressSource,
        ResolveFuture,
    };
    use crate::egress::EgressSnapshot as ProductEgressSnapshot;
    use crate::runtime::CredentialSourceRegistry;
    use crate::url::canonicalize_http_url;

    const CANDIDATE: &str = "192.0.2.20:8443";

    struct FixedResolver {
        endpoint: SocketAddr,
        calls: AtomicUsize,
    }

    impl DestinationResolver for FixedResolver {
        fn resolve(&self, _host: &str, _port: u16, _limit: usize) -> ResolveFuture<'_> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let endpoint = self.endpoint;
            Box::pin(async move { Ok(vec![endpoint]) })
        }
    }

    struct EmptyLocalAddresses;

    impl LocalAddressSource for EmptyLocalAddresses {
        fn snapshot(&self) -> io::Result<LocalAddressSnapshot> {
            Ok(LocalAddressSnapshot::default())
        }
    }

    struct FakeConnector {
        peer: SocketAddr,
        streams: Mutex<VecDeque<DuplexStream>>,
        calls: AtomicUsize,
    }

    impl FakeConnector {
        fn new(peer: SocketAddr, stream: DuplexStream) -> Self {
            Self {
                peer,
                streams: Mutex::new(VecDeque::from([stream])),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl DestinationConnector for FakeConnector {
        type Stream = DuplexStream;

        fn connect(
            &self,
            _endpoint: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + Send + '_>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let stream = self
                .streams
                .lock()
                .unwrap()
                .pop_front()
                .expect("one fake connection");
            Box::pin(async move { Ok(stream) })
        }

        fn peer_addr(&self, _stream: &Self::Stream) -> io::Result<SocketAddr> {
            Ok(self.peer)
        }
    }

    fn guard() -> (DestinationGuard, Arc<FixedResolver>) {
        let endpoint = CANDIDATE.parse().unwrap();
        let resolver = Arc::new(FixedResolver {
            endpoint,
            calls: AtomicUsize::new(0),
        });
        let facts = DestinationFacts::for_test([], None, None, 8).unwrap();
        let guard =
            DestinationGuard::with_sources(facts, resolver.clone(), Arc::new(EmptyLocalAddresses));
        (guard, resolver)
    }

    fn activate(parent: Option<(&str, bool)>) -> ProductEgressSnapshot {
        activate_with_versions(
            parent,
            vec![CompiledHttpVersion::Http1, CompiledHttpVersion::Http2],
        )
    }

    fn activate_with_versions(
        parent: Option<(&str, bool)>,
        http_versions: Vec<CompiledHttpVersion>,
    ) -> ProductEgressSnapshot {
        let parent_proxy = parent.map(|(url, tls)| ParentProxyPlan {
            kind: CompiledParentProxyKind::Generic,
            url: url.to_owned(),
            host: "parent.example".to_owned(),
            port: 8443,
            tls: tls.then(|| ParentProxyTlsPlan {
                trust: CompiledTlsTrust::Insecure,
                ca_certificate: None,
                server_name: "parent.example".to_owned(),
            }),
        });
        ProductEgressSnapshot::activate(
            EgressPlan {
                route: if parent_proxy.is_some() {
                    CompiledEgressRoute::ParentProxy
                } else {
                    CompiledEgressRoute::Direct
                },
                origin_tls: TransportTlsPlan {
                    trust: CompiledTlsTrust::Insecure,
                    ca_certificate: None,
                    http_versions,
                },
                parent_proxy,
                request_headers: vec![],
                credential_actions: vec![],
            },
            &CredentialSourceRegistry::from_names([]),
            || false,
        )
        .unwrap()
    }

    fn request() -> SanitizedRequest {
        request_with_version(Version::HTTP_11)
    }

    fn request_with_version(version: Version) -> SanitizedRequest {
        let request = Request::builder()
            .method(Method::POST)
            .version(version)
            .uri("/untrusted-client-target")
            .header(HOST, "untrusted-client.example")
            .header("authorization", "Bearer origin-secret")
            .header("cookie", "origin-session=secret")
            .header("x-workload-identity", "workload-42")
            .header("x-loop-marker", "request-42")
            .header("proxy-authorization", "Basic parent-secret")
            .body(Body::from("request-body"))
            .unwrap();
        crate::proxy::headers::sanitize_untrusted_request(request).unwrap()
    }

    fn tls_acceptor(alpn: &[u8]) -> TlsAcceptor {
        let generated = generate_simple_self_signed(vec!["origin.example".to_owned()]).unwrap();
        let certificate = Certificate(generated.cert.der().to_vec());
        let key = PrivateKey(generated.key_pair.serialize_der());
        let mut config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap();
        if !alpn.is_empty() {
            config.alpn_protocols = vec![alpn.to_vec()];
        }
        TlsAcceptor::from(Arc::new(config))
    }

    async fn serve_h1(
        stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        captured: oneshot::Sender<(String, http::HeaderMap, Vec<u8>)>,
    ) {
        let captured = Arc::new(Mutex::new(Some(captured)));
        let _ = Http::new()
            .http1_only(true)
            .serve_connection(
                stream,
                service_fn(move |request: Request<Body>| {
                    let uri = request.uri().to_string();
                    let headers = request.headers().clone();
                    let captured = Arc::clone(&captured);
                    async move {
                        let body = hyper::body::to_bytes(request.into_body()).await.unwrap();
                        captured
                            .lock()
                            .unwrap()
                            .take()
                            .unwrap()
                            .send((uri, headers, body.to_vec()))
                            .ok();
                        let mut response = Response::new(Body::from("upstream-response"));
                        response
                            .headers_mut()
                            .insert("x-end-to-end", HeaderValue::from_static("visible"));
                        response.headers_mut().insert(
                            "proxy-authenticate",
                            HeaderValue::from_static("Basic realm=parent"),
                        );
                        Ok::<_, std::convert::Infallible>(response)
                    }
                }),
            )
            .await;
    }

    async fn serve_h2(
        stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        captured: oneshot::Sender<(String, http::HeaderMap, Vec<u8>)>,
    ) {
        let captured = Arc::new(Mutex::new(Some(captured)));
        let _ = Http::new()
            .http2_only(true)
            .serve_connection(
                stream,
                service_fn(move |request: Request<Body>| {
                    let uri = request.uri().to_string();
                    let headers = request.headers().clone();
                    let captured = Arc::clone(&captured);
                    async move {
                        let body = hyper::body::to_bytes(request.into_body()).await.unwrap();
                        captured
                            .lock()
                            .unwrap()
                            .take()
                            .unwrap()
                            .send((uri, headers, body.to_vec()))
                            .ok();
                        let mut response = Response::new(Body::from("upstream-response"));
                        response
                            .headers_mut()
                            .insert("x-end-to-end", HeaderValue::from_static("visible"));
                        Ok::<_, std::convert::Infallible>(response)
                    }
                }),
            )
            .await;
    }

    async fn serve_selected_protocol(
        stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        protocol: CompiledHttpVersion,
        captured: oneshot::Sender<(Version, String, http::HeaderMap, Vec<u8>)>,
    ) {
        let captured = Arc::new(Mutex::new(Some(captured)));
        let mut http = Http::new();
        match protocol {
            CompiledHttpVersion::Http1 => {
                http.http1_only(true);
            }
            CompiledHttpVersion::Http2 => {
                http.http2_only(true);
            }
        }
        let _ = http
            .serve_connection(
                stream,
                service_fn(move |request: Request<Body>| {
                    let version = request.version();
                    let uri = request.uri().to_string();
                    let headers = request.headers().clone();
                    let captured = Arc::clone(&captured);
                    async move {
                        let body = hyper::body::to_bytes(request.into_body()).await.unwrap();
                        captured
                            .lock()
                            .unwrap()
                            .take()
                            .unwrap()
                            .send((version, uri, headers, body.to_vec()))
                            .ok();
                        let mut response = Response::new(Body::from("upstream-response"));
                        response
                            .headers_mut()
                            .insert("x-end-to-end", HeaderValue::from_static("visible"));
                        Ok::<_, std::convert::Infallible>(response)
                    }
                }),
            )
            .await;
    }

    fn protocol_alpn(protocol: CompiledHttpVersion) -> &'static [u8] {
        match protocol {
            CompiledHttpVersion::Http1 => b"http/1.1",
            CompiledHttpVersion::Http2 => b"h2",
        }
    }

    async fn accept_connect<S>(mut stream: S) -> S
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut head = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
            assert!(head.len() < 8 * 1024);
        }
        let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
        assert!(head.starts_with("connect origin.example:443 http/1.1\r\n"));
        assert!(head.contains("\r\nhost: origin.example:443\r\n"));
        for forbidden in [
            "authorization",
            "proxy-authorization",
            "cookie",
            "x-workload-identity",
            "x-loop-marker",
            "request-body",
            "/translate",
        ] {
            assert!(!head.contains(forbidden), "CONNECT leaked {forbidden}");
        }
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        stream
    }

    #[derive(Clone, Copy, Debug)]
    enum TranslationRoute {
        DirectClear,
        DirectTls,
        HttpParentClearOrigin,
        HttpsParentClearOrigin,
        HttpParentTlsOrigin,
        HttpsParentTlsOrigin,
    }

    async fn assert_protocol_translation(
        route: TranslationRoute,
        ingress_version: Version,
        enabled_versions: Vec<CompiledHttpVersion>,
    ) {
        let tls_origin = matches!(
            route,
            TranslationRoute::DirectTls
                | TranslationRoute::HttpParentTlsOrigin
                | TranslationRoute::HttpsParentTlsOrigin
        );
        let canonical = canonicalize_http_url(if tls_origin {
            "https://origin.example/translate?q=1"
        } else {
            "http://origin.example:8080/translate?q=1"
        })
        .unwrap();
        let parent = match route {
            TranslationRoute::DirectClear | TranslationRoute::DirectTls => None,
            TranslationRoute::HttpParentClearOrigin | TranslationRoute::HttpParentTlsOrigin => {
                Some(("http://parent.example:8443/", false))
            }
            TranslationRoute::HttpsParentClearOrigin | TranslationRoute::HttpsParentTlsOrigin => {
                Some(("https://parent.example:8443/", true))
            }
        };
        let ingress_protocol = if ingress_version == Version::HTTP_2 {
            CompiledHttpVersion::Http2
        } else {
            CompiledHttpVersion::Http1
        };
        let selected_version = if enabled_versions.contains(&ingress_protocol) {
            ingress_protocol
        } else {
            enabled_versions[0]
        };
        let egress = activate_with_versions(parent, enabled_versions);
        let mut request = request_with_version(ingress_version);
        if ingress_version == Version::HTTP_2 {
            request
                .headers_mut()
                .insert(TE, HeaderValue::from_static("trailers"));
        }
        let expected_ingress = if ingress_version == Version::HTTP_2 {
            OriginProtocol::Http2
        } else {
            OriginProtocol::Http1
        };
        let expected_origin = if selected_version == CompiledHttpVersion::Http2 {
            OriginProtocol::Http2
        } else {
            OriginProtocol::Http1
        };
        let (guard, _) = guard();
        let (client, server) = tokio::io::duplex(256 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let (captured_tx, captured_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            match route {
                TranslationRoute::DirectClear | TranslationRoute::HttpParentClearOrigin => {
                    serve_selected_protocol(server, selected_version, captured_tx).await;
                }
                TranslationRoute::DirectTls => {
                    let tls = tls_acceptor(protocol_alpn(selected_version))
                        .accept(server)
                        .await
                        .unwrap();
                    serve_selected_protocol(tls, selected_version, captured_tx).await;
                }
                TranslationRoute::HttpsParentClearOrigin => {
                    let parent = tls_acceptor(protocol_alpn(selected_version))
                        .accept(server)
                        .await
                        .unwrap();
                    serve_selected_protocol(parent, selected_version, captured_tx).await;
                }
                TranslationRoute::HttpParentTlsOrigin => {
                    let tunnel = accept_connect(server).await;
                    let origin = tls_acceptor(protocol_alpn(selected_version))
                        .accept(tunnel)
                        .await
                        .unwrap();
                    serve_selected_protocol(origin, selected_version, captured_tx).await;
                }
                TranslationRoute::HttpsParentTlsOrigin => {
                    let parent = tls_acceptor(b"http/1.1").accept(server).await.unwrap();
                    let tunnel = accept_connect(parent).await;
                    let origin = tls_acceptor(protocol_alpn(selected_version))
                        .accept(tunnel)
                        .await
                        .unwrap();
                    serve_selected_protocol(origin, selected_version, captured_tx).await;
                }
            }
        });
        let target = resolve_forwarding_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();
        assert_eq!(target.ingress_protocol, expected_ingress, "{route:?}");
        assert_eq!(target.origin_protocol, expected_origin, "{route:?}");

        let response =
            forward_with_connector(request, &canonical, &egress, &guard, target, &connector)
                .await
                .unwrap();
        finish_response(response).await;
        let (version, uri, headers, body) = captured_rx.await.unwrap();
        let expected_version = if selected_version == CompiledHttpVersion::Http2 {
            Version::HTTP_2
        } else {
            Version::HTTP_11
        };
        assert_eq!(version, expected_version, "{route:?}");
        let ordinary_parent = matches!(
            route,
            TranslationRoute::HttpParentClearOrigin | TranslationRoute::HttpsParentClearOrigin
        );
        let expected_uri = if expected_origin.is_http2() || ordinary_parent {
            canonical.url.as_str()
        } else {
            "/translate?q=1"
        };
        assert_eq!(uri, expected_uri, "{route:?}");
        if expected_origin.is_http2() {
            assert!(!headers.contains_key(HOST), "{route:?}");
            if ingress_version == Version::HTTP_2 {
                assert_eq!(headers[TE], "trailers", "{route:?}");
            }
        } else {
            assert_eq!(headers[HOST], canonical.authority, "{route:?}");
            assert!(!headers.contains_key(TE), "{route:?}");
        }
        assert_eq!(headers["authorization"], "Bearer origin-secret");
        assert!(!headers.contains_key("proxy-authorization"));
        assert_eq!(body, b"request-body");
        server.await.unwrap();
    }

    async fn finish_response(response: ForwardedResponse) {
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-end-to-end"], "visible");
        assert!(!response.headers().contains_key("proxy-authenticate"));
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        assert!(body.trailers().await.unwrap().is_none());
        assert_eq!(bytes, b"upstream-response");
    }

    struct DropSignal(Option<oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(signal) = self.0.take() {
                signal.send(()).ok();
            }
        }
    }

    #[tokio::test]
    async fn forward_body_joins_driver_after_clean_completion() {
        let completed = Arc::new(AtomicUsize::new(0));
        let completed_for_driver = completed.clone();
        let driver = tokio::spawn(async move {
            tokio::task::yield_now().await;
            completed_for_driver.store(1, Ordering::SeqCst);
            Ok(())
        });
        let body = ForwardBody::new(Body::from("complete"), DriverTask::from_handle(driver));

        let mut body = body;
        assert_eq!(body.data().await.unwrap().unwrap(), "complete");
        assert!(body.data().await.is_none());
        assert!(body.trailers().await.unwrap().is_none());
        assert_eq!(completed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dropping_forward_body_aborts_owned_driver() {
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let signal = DropSignal(Some(dropped_tx));
        let driver = tokio::spawn(async move {
            let _signal = signal;
            std::future::pending::<Result<(), hyper::Error>>().await
        });
        let body = ForwardBody::new(Body::empty(), DriverTask::from_handle(driver));

        drop(body);
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn cancelling_driver_join_aborts_owned_task() {
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let signal = DropSignal(Some(dropped_tx));
        let driver = DriverTask::from_handle(tokio::spawn(async move {
            let _signal = signal;
            std::future::pending::<Result<(), hyper::Error>>().await
        }));
        let (started_tx, started_rx) = oneshot::channel();
        let join = tokio::spawn(async move {
            started_tx.send(()).ok();
            driver.join().await
        });

        started_rx.await.unwrap();
        tokio::task::yield_now().await;
        join.abort();
        assert!(join.await.unwrap_err().is_cancelled());
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn response_body_error_aborts_owned_driver() {
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let signal = DropSignal(Some(dropped_tx));
        let driver = tokio::spawn(async move {
            let _signal = signal;
            std::future::pending::<Result<(), hyper::Error>>().await
        });
        let stream = tokio_stream::once(Err::<Bytes, _>(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "injected body failure",
        )));
        let body = ForwardBody::new(Body::wrap_stream(stream), DriverTask::from_handle(driver));

        assert!(hyper::body::to_bytes(body).await.is_err());
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn response_body_error_remains_sticky_after_driver_join() {
        let stream = tokio_stream::once(Err::<Bytes, _>(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "injected body failure",
        )));
        let driver =
            tokio::spawn(async { std::future::pending::<Result<(), hyper::Error>>().await });
        let mut body = ForwardBody::new(Body::wrap_stream(stream), DriverTask::from_handle(driver));

        for _ in 0..2 {
            let error = body.data().await.unwrap().unwrap_err();
            assert!(matches!(error, ForwardBodyError::Body(_)));
        }
        let error = body.trailers().await.unwrap_err();
        assert!(matches!(error, ForwardBodyError::Body(_)));
        assert!(!body.is_end_stream());
    }

    #[tokio::test]
    async fn forward_body_preserves_sanitized_trailers_until_driver_join() {
        let (mut sender, body) = Body::channel();
        tokio::spawn(async move {
            sender
                .send_data(Bytes::from_static(b"with-trailer"))
                .await
                .unwrap();
            let mut trailers = http::HeaderMap::new();
            trailers.insert("x-checksum", HeaderValue::from_static("verified"));
            trailers.insert(
                "proxy-authenticate",
                HeaderValue::from_static("Basic realm=parent"),
            );
            sender.send_trailers(trailers).await.unwrap();
        });
        let driver = tokio::spawn(async { Ok(()) });
        let mut body = ForwardBody::new(body, DriverTask::from_handle(driver));

        assert_eq!(body.data().await.unwrap().unwrap(), "with-trailer");
        assert!(body.data().await.is_none());
        assert!(!body.is_end_stream());
        let trailers = body.trailers().await.unwrap().unwrap();
        assert_eq!(trailers["x-checksum"], "verified");
        assert!(!trailers.contains_key("proxy-authenticate"));
        assert!(body.is_end_stream());
    }

    #[tokio::test]
    async fn dropping_after_data_before_trailers_aborts_driver() {
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let signal = DropSignal(Some(dropped_tx));
        let driver = tokio::spawn(async move {
            let _signal = signal;
            std::future::pending::<Result<(), hyper::Error>>().await
        });
        let mut body = ForwardBody::new(Body::empty(), DriverTask::from_handle(driver));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), body.data())
                .await
                .is_err()
        );

        drop(body);
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn pending_trailer_timeout_is_sticky_and_aborts_driver() {
        let (started_tx, started_rx) = oneshot::channel();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let signal = DropSignal(Some(dropped_tx));
        let driver = tokio::spawn(async move {
            let _signal = signal;
            started_tx.send(()).ok();
            std::future::pending::<Result<(), hyper::Error>>().await
        });
        started_rx.await.unwrap();
        let (pending_sender, pending_body) = Body::channel();
        let mut body = ForwardBody::new(pending_body, DriverTask::from_handle(driver))
            .with_terminal_drain_timeout(Duration::ZERO);
        body.data_done = true;
        body.begin_terminal_drain();

        let error = body.data().await.unwrap().unwrap_err();
        drop(pending_sender);
        assert!(matches!(error, ForwardBodyError::Timeout));
        let error = body.data().await.unwrap().unwrap_err();
        assert!(matches!(error, ForwardBodyError::Timeout));
        let error = body.trailers().await.unwrap_err();
        assert!(matches!(error, ForwardBodyError::Timeout));
        assert!(!body.is_end_stream());
        tokio::time::timeout(Duration::from_secs(1), dropped_rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn driver_drain_timeout_preserves_complete_body_and_trailers() {
        let (mut sender, upstream_body) = Body::channel();
        tokio::spawn(async move {
            sender
                .send_data(Bytes::from_static(b"complete"))
                .await
                .unwrap();
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", HeaderValue::from_static("0"));
            sender.send_trailers(trailers).await.unwrap();
        });
        let (started_tx, started_rx) = oneshot::channel();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let signal = DropSignal(Some(dropped_tx));
        let driver = tokio::spawn(async move {
            let _signal = signal;
            started_tx.send(()).ok();
            std::future::pending::<Result<(), hyper::Error>>().await
        });
        started_rx.await.unwrap();
        let mut body = ForwardBody::new(upstream_body, DriverTask::from_handle(driver))
            .with_terminal_drain_timeout(Duration::ZERO);

        assert_eq!(body.data().await.unwrap().unwrap(), "complete");
        assert!(body.data().await.is_none());
        assert!(!body.is_end_stream());
        let trailers = body.trailers().await.unwrap().unwrap();
        assert_eq!(trailers["grpc-status"], "0");
        assert!(body.is_end_stream());
        tokio::time::timeout(Duration::from_secs(1), dropped_rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn h1_driver_error_is_sticky_and_does_not_require_trailer_polling() {
        let (client, server) = tokio::io::duplex(1024);
        let (_sender, connection) = conn::Builder::new()
            .handshake::<_, Body>(client)
            .await
            .unwrap();
        drop(server);
        let mut body = ForwardBody::new(Body::empty(), DriverTask::spawn(connection));
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), body.data())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(matches!(error, ForwardBodyError::Connection(_)));
        let error = body.data().await.unwrap().unwrap_err();
        assert!(matches!(error, ForwardBodyError::Connection(_)));
        let error = body.trailers().await.unwrap_err();
        assert!(matches!(error, ForwardBodyError::Connection(_)));
        assert!(!body.is_end_stream());
    }

    #[tokio::test]
    async fn origin_protocol_translation_matrix() {
        for route in [
            TranslationRoute::DirectClear,
            TranslationRoute::DirectTls,
            TranslationRoute::HttpParentClearOrigin,
            TranslationRoute::HttpsParentClearOrigin,
            TranslationRoute::HttpParentTlsOrigin,
            TranslationRoute::HttpsParentTlsOrigin,
        ] {
            assert_protocol_translation(route, Version::HTTP_2, vec![CompiledHttpVersion::Http1])
                .await;
            assert_protocol_translation(route, Version::HTTP_11, vec![CompiledHttpVersion::Http2])
                .await;
            for ingress in [Version::HTTP_11, Version::HTTP_2] {
                assert_protocol_translation(
                    route,
                    ingress,
                    vec![CompiledHttpVersion::Http1, CompiledHttpVersion::Http2],
                )
                .await;
            }
        }
    }

    #[tokio::test]
    async fn ordinary_parent_hop_uses_selected_origin_protocol_per_d061() {
        for route in [
            TranslationRoute::HttpParentClearOrigin,
            TranslationRoute::HttpsParentClearOrigin,
        ] {
            assert_protocol_translation(route, Version::HTTP_11, vec![CompiledHttpVersion::Http2])
                .await;
        }
    }

    #[tokio::test]
    async fn h2_authorized_request_remains_h2_on_plaintext_origin() {
        let canonical = canonicalize_http_url("http://origin.example:8080/h2").unwrap();
        let egress = activate_with_versions(None, vec![CompiledHttpVersion::Http2]);
        let request = request_with_version(Version::HTTP_2);
        let (guard, _) = guard();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let (captured_tx, captured_rx) = oneshot::channel();
        let server = tokio::spawn(serve_h2(server, captured_tx));
        let target = resolve_forwarding_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();

        let response =
            forward_with_connector(request, &canonical, &egress, &guard, target, &connector)
                .await
                .unwrap();
        finish_response(response).await;
        let (uri, headers, body) = captured_rx.await.unwrap();
        assert_eq!(uri, canonical.url);
        assert!(!headers.contains_key(HOST));
        assert_eq!(headers["authorization"], "Bearer origin-secret");
        assert_eq!(body, b"request-body");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn direct_https_rejects_incompatible_origin_alpn_before_http() {
        let canonical = canonicalize_http_url("https://origin.example/alpn").unwrap();
        let egress = activate(None);
        let request = request_with_version(Version::HTTP_2);
        let (guard, _) = guard();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let server = tokio::spawn(async move {
            match tls_acceptor(b"").accept(server).await {
                Ok(tls) => assert!(tls.get_ref().1.alpn_protocol().is_none()),
                Err(error) => assert_eq!(error.kind(), io::ErrorKind::BrokenPipe),
            }
        });
        let target = resolve_forwarding_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();

        assert!(matches!(
            forward_with_connector(request, &canonical, &egress, &guard, target, &connector).await,
            Err(ForwardError::OriginProtocol(
                OriginProtocolError::IncompatibleAlpn
            ))
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn resolved_target_rejects_an_identical_but_foreign_egress_snapshot() {
        let canonical = canonicalize_http_url("http://origin.example/resource").unwrap();
        let original = activate(None);
        let foreign = activate(None);
        let request = request();
        let (guard, _) = guard();
        let (client, _server) = tokio::io::duplex(1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let target = resolve_forwarding_target(&canonical, &request, &original, &guard)
            .await
            .unwrap();

        assert!(matches!(
            forward_with_connector(request, &canonical, &foreign, &guard, target, &connector).await,
            Err(ForwardError::ResolvedTargetMismatch)
        ));
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn resolved_target_binds_ingress_and_selected_origin_protocols() {
        let canonical = canonicalize_http_url("http://origin.example/resource").unwrap();
        let egress = activate_with_versions(None, vec![CompiledHttpVersion::Http1]);
        let (guard, _) = guard();

        let resolved_for_h2 = request_with_version(Version::HTTP_2);
        let target = resolve_forwarding_target(&canonical, &resolved_for_h2, &egress, &guard)
            .await
            .unwrap();
        let (client, _server) = tokio::io::duplex(1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        assert!(matches!(
            forward_with_connector(
                request_with_version(Version::HTTP_11),
                &canonical,
                &egress,
                &guard,
                target,
                &connector,
            )
            .await,
            Err(ForwardError::ResolvedTargetMismatch)
        ));
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);

        let request = request_with_version(Version::HTTP_2);
        let mut target = resolve_forwarding_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();
        target.origin_protocol = OriginProtocol::Http2;
        let (client, _server) = tokio::io::duplex(1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        assert!(matches!(
            forward_with_connector(request, &canonical, &egress, &guard, target, &connector).await,
            Err(ForwardError::ResolvedTargetMismatch)
        ));
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancelling_forward_aborts_driver_and_writes_no_later_body_bytes() {
        let canonical = canonicalize_http_url("http://origin.example/cancel").unwrap();
        let egress = activate(None);
        let (body_sender, body_receiver) =
            tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(1);
        let request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_11)
            .uri("/untrusted")
            .body(Body::wrap_stream(
                tokio_stream::wrappers::ReceiverStream::new(body_receiver),
            ))
            .unwrap();
        let request = crate::proxy::headers::sanitize_untrusted_request(request).unwrap();
        let (guard, _) = guard();
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let (head_tx, head_rx) = oneshot::channel();
        let (tail_tx, tail_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut head = Vec::new();
            loop {
                let mut byte = [0_u8; 1];
                server.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            head_tx.send(head).ok();
            let mut tail = Vec::new();
            server.read_to_end(&mut tail).await.unwrap();
            tail_tx.send(tail).ok();
        });
        let target = resolve_forwarding_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();
        let mut forwarding = Box::pin(forward_with_connector(
            request, &canonical, &egress, &guard, target, &connector,
        ));

        tokio::select! {
            _ = &mut forwarding => panic!("forward unexpectedly completed"),
            head = head_rx => assert!(head.unwrap().starts_with(b"POST /cancel HTTP/1.1\r\n")),
        }
        drop(forwarding);
        drop(body_sender);
        let tail = tokio::time::timeout(std::time::Duration::from_secs(1), tail_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(
            tail.is_empty(),
            "cancelled request wrote bytes after its head"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn direct_route_resolves_before_forward_and_never_resolves_again() {
        let canonical =
            canonicalize_http_url("http://origin.example:8080/canonical?q=%7e").unwrap();
        let egress = activate(None);
        let (guard, resolver) = guard();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let (captured_tx, captured_rx) = oneshot::channel();
        let server = tokio::spawn(serve_h1(server, captured_tx));

        let request = request();
        let target = resolve_forwarding_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);

        let response =
            forward_with_connector(request, &canonical, &egress, &guard, target, &connector)
                .await
                .unwrap();
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        finish_response(response).await;

        let (uri, headers, body) = captured_rx.await.unwrap();
        assert_eq!(uri, "/canonical?q=~");
        assert_eq!(headers[HOST], "origin.example:8080");
        assert_eq!(headers["authorization"], "Bearer origin-secret");
        assert!(!headers.contains_key("proxy-authorization"));
        assert_eq!(body, b"request-body");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_parent_receives_canonical_absolute_form() {
        let canonical = canonicalize_http_url("http://origin.example:8080/canonical?q=1").unwrap();
        let egress = activate(Some(("http://parent.example:8443/", false)));
        let (guard, _) = guard();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let (captured_tx, captured_rx) = oneshot::channel();
        let server = tokio::spawn(serve_h1(server, captured_tx));
        let request = request();
        let target = resolve_forwarding_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();

        let response =
            forward_with_connector(request, &canonical, &egress, &guard, target, &connector)
                .await
                .unwrap();
        finish_response(response).await;
        let (uri, headers, _) = captured_rx.await.unwrap();
        assert_eq!(uri, canonical.url);
        assert_eq!(headers[HOST], canonical.authority);
        assert_eq!(headers["authorization"], "Bearer origin-secret");
        assert!(!headers.contains_key("proxy-authorization"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn https_parent_uses_tls_before_absolute_form_forwarding() {
        let canonical = canonicalize_http_url("http://origin.example:8080/through-tls").unwrap();
        let egress = activate(Some(("https://parent.example:8443/", true)));
        let (guard, _) = guard();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let (captured_tx, captured_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let tls = tls_acceptor(b"http/1.1").accept(server).await.unwrap();
            serve_h1(tls, captured_tx).await;
        });
        let request = request();
        let target = resolve_forwarding_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();

        let response =
            forward_with_connector(request, &canonical, &egress, &guard, target, &connector)
                .await
                .unwrap();
        finish_response(response).await;
        let (uri, headers, _) = captured_rx.await.unwrap();
        assert_eq!(uri, canonical.url);
        assert_eq!(headers[HOST], canonical.authority);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn https_parent_rejects_incompatible_alpn_before_http() {
        let canonical = canonicalize_http_url("http://origin.example:8080/alpn").unwrap();
        let egress = activate(Some(("https://parent.example:8443/", true)));
        let request = request_with_version(Version::HTTP_2);
        let (guard, _) = guard();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let server = tokio::spawn(async move {
            match tls_acceptor(b"").accept(server).await {
                Ok(tls) => assert!(tls.get_ref().1.alpn_protocol().is_none()),
                Err(error) => assert_eq!(error.kind(), io::ErrorKind::BrokenPipe),
            }
        });
        let target = resolve_forwarding_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();

        assert!(matches!(
            forward_with_connector(request, &canonical, &egress, &guard, target, &connector).await,
            Err(ForwardError::ParentProtocol(ParentAlpnError::Incompatible))
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn parent_connect_carries_no_origin_credentials() {
        let canonical = canonicalize_http_url("https://origin.example/secure").unwrap();
        let egress = activate(Some(("http://parent.example:8443/", false)));
        let (guard, _) = guard();
        let (client, mut server) = tokio::io::duplex(128 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let (connect_tx, connect_rx) = oneshot::channel();
        let (origin_tx, origin_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut head = Vec::new();
            loop {
                let mut byte = [0_u8; 1];
                server.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
                assert!(head.len() < 8 * 1024);
            }
            connect_tx.send(String::from_utf8(head).unwrap()).ok();
            server
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let tls = tls_acceptor(b"http/1.1").accept(server).await.unwrap();
            serve_h1(tls, origin_tx).await;
        });
        let request = request();
        let target = resolve_forwarding_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();

        let response =
            forward_with_connector(request, &canonical, &egress, &guard, target, &connector)
                .await
                .unwrap();
        finish_response(response).await;

        let connect = connect_rx.await.unwrap().to_ascii_lowercase();
        assert!(connect.starts_with("connect origin.example:443 http/1.1\r\n"));
        assert!(connect.contains("\r\nhost: origin.example:443\r\n"));
        for forbidden in [
            "authorization",
            "proxy-authorization",
            "cookie",
            "x-workload-identity",
            "x-loop-marker",
            "request-body",
            "/secure",
        ] {
            assert!(!connect.contains(forbidden), "CONNECT leaked {forbidden}");
        }

        let (uri, headers, body) = origin_rx.await.unwrap();
        assert_eq!(uri, "/secure");
        assert_eq!(headers[HOST], "origin.example");
        assert_eq!(headers["authorization"], "Bearer origin-secret");
        assert_eq!(headers["cookie"], "origin-session=secret");
        assert_eq!(headers["x-workload-identity"], "workload-42");
        assert_eq!(headers["x-loop-marker"], "request-42");
        assert_eq!(body, b"request-body");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn https_parent_connect_keeps_origin_credentials_inside_nested_tls() {
        let canonical = canonicalize_http_url("https://origin.example/secure").unwrap();
        let egress = activate(Some(("https://parent.example:8443/", true)));
        let (guard, _) = guard();
        let (client, server) = tokio::io::duplex(256 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let (connect_tx, connect_rx) = oneshot::channel();
        let (origin_tx, origin_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut parent_tls = tls_acceptor(b"http/1.1").accept(server).await.unwrap();
            let mut head = Vec::new();
            loop {
                let mut byte = [0_u8; 1];
                parent_tls.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
                assert!(head.len() < 8 * 1024);
            }
            connect_tx.send(String::from_utf8(head).unwrap()).ok();
            parent_tls
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let origin_tls = tls_acceptor(b"http/1.1").accept(parent_tls).await.unwrap();
            serve_h1(origin_tls, origin_tx).await;
        });
        let request = request();
        let target = resolve_forwarding_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();

        let response =
            forward_with_connector(request, &canonical, &egress, &guard, target, &connector)
                .await
                .unwrap();
        finish_response(response).await;

        let connect = connect_rx.await.unwrap().to_ascii_lowercase();
        assert!(connect.starts_with("connect origin.example:443 http/1.1\r\n"));
        assert!(connect.contains("\r\nhost: origin.example:443\r\n"));
        for forbidden in [
            "authorization",
            "proxy-authorization",
            "cookie",
            "x-workload-identity",
            "x-loop-marker",
            "request-body",
            "/secure",
        ] {
            assert!(!connect.contains(forbidden), "CONNECT leaked {forbidden}");
        }

        let (uri, headers, body) = origin_rx.await.unwrap();
        assert_eq!(uri, "/secure");
        assert_eq!(headers[HOST], "origin.example");
        assert_eq!(headers["authorization"], "Bearer origin-secret");
        assert_eq!(headers["cookie"], "origin-session=secret");
        assert_eq!(headers["x-workload-identity"], "workload-42");
        assert_eq!(headers["x-loop-marker"], "request-42");
        assert!(!headers.contains_key("proxy-authorization"));
        assert_eq!(body, b"request-body");
        server.await.unwrap();
    }
}
