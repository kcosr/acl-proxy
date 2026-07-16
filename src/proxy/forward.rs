use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Buf;
use http::header::{HeaderValue, HOST};
use http::{Method, Request, Response, StatusCode, Version};
use http_access_types::{CanonicalUrl, HttpScheme};
use hyper::body::{Bytes, HttpBody, SizeHint};
use hyper::client::conn;
use hyper::Body;
use rustls::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{oneshot, watch};
use tokio::time::Instant;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::credential_resolver::ProductCredentialExecution;
use crate::destination::{
    DestinationConnector, DestinationGuard, DestinationGuardError, DestinationTarget,
    PreparedDestination, ResolvedDestination, TcpDestinationConnector,
};
use crate::egress::{
    EgressRoute, OriginProtocol, OriginProtocolError, ParentAlpnError, ParentEndpoint,
    ParentTransport,
};
use crate::runtime::{EgressSnapshot, GenerationRetention};
use crate::safety::ForwardResponseAdmission;

use super::h2_stream_cancellation::H2StreamCancellation;
use super::headers::{
    prepare_downstream_upgrade_response, prepare_origin_request, prepare_origin_upgrade_request,
    strip_response_hop_by_hop, HeaderPreparationError, RequestTargetForm, SanitizedRequest,
    UpgradeIntent,
};

const TERMINAL_DRIVER_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_EMPTY_RESPONSE_FRAMES: u64 = 65_536;
const MAX_INTERNAL_RESPONSE_EVENTS_PER_POLL: usize = 64;

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
    #[error("upstream returned unexpected informational status {0}")]
    UnexpectedInformationalResponse(StatusCode),
    #[error("parent proxy rejected CONNECT with status {0}")]
    ParentConnect(StatusCode),
    #[error("the resolved forwarding target does not belong to this request and egress route")]
    ResolvedTargetMismatch,
    #[error("HTTP upgrades require an HTTP/1 origin connection")]
    UpgradeRequiresHttp1,
    #[error("the upstream switched protocols before the request body completed")]
    UpgradeRequestBodyIncomplete,
    #[error("upstream connection setup timed out")]
    ConnectTimeout,
    #[error("upstream response head timed out")]
    ResponseHeadTimeout,
    #[error("credential finalization failed")]
    Credential(#[source] credential_core::CredentialError),
}

#[derive(Clone, Copy)]
pub(crate) struct ForwardingTimeouts {
    connect_timeout: Duration,
    response_head_timeout: Duration,
    absolute: Instant,
}

impl ForwardingTimeouts {
    pub(crate) fn new(
        absolute: Instant,
        connect_timeout: Duration,
        response_head_timeout: Duration,
    ) -> Self {
        Self {
            connect_timeout,
            response_head_timeout,
            absolute,
        }
    }

    fn begin_connect(self) -> ForwardingDeadlines {
        ForwardingDeadlines {
            connect: Instant::now()
                .checked_add(self.connect_timeout)
                .unwrap_or(self.absolute)
                .min(self.absolute),
            response_head_timeout: self.response_head_timeout,
            absolute: self.absolute,
        }
    }

    #[cfg(test)]
    fn for_test() -> Self {
        let timeout = Duration::from_secs(3_600);
        Self::new(Instant::now() + timeout, timeout, timeout)
    }
}

struct ForwardExecutionOptions {
    timeouts: ForwardingTimeouts,
    credentials: Option<ProductCredentialExecution>,
}

impl ForwardExecutionOptions {
    fn new(timeouts: ForwardingTimeouts, credentials: Option<ProductCredentialExecution>) -> Self {
        Self {
            timeouts,
            credentials,
        }
    }

    fn begin_connect(self) -> EstablishedForwardExecution {
        EstablishedForwardExecution {
            deadlines: self.timeouts.begin_connect(),
            credentials: self.credentials,
        }
    }
}

struct EstablishedForwardExecution {
    deadlines: ForwardingDeadlines,
    credentials: Option<ProductCredentialExecution>,
}

#[derive(Clone, Copy)]
struct ForwardingDeadlines {
    connect: Instant,
    response_head_timeout: Duration,
    absolute: Instant,
}

impl ForwardingDeadlines {
    fn response_head(self) -> Instant {
        Instant::now()
            .checked_add(self.response_head_timeout)
            .unwrap_or(self.absolute)
            .min(self.absolute)
    }
}

async fn connect_stage<F, T, E>(
    deadlines: ForwardingDeadlines,
    future: F,
) -> Result<T, ForwardError>
where
    F: Future<Output = Result<T, E>>,
    ForwardError: From<E>,
{
    match tokio::time::timeout_at(deadlines.connect, future).await {
        Ok(result) => result.map_err(ForwardError::from),
        Err(_) => Err(ForwardError::ConnectTimeout),
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ResolveForwardingError {
    #[error(transparent)]
    Destination(#[from] DestinationGuardError),
    #[error("the forwarding preflight does not belong to this request and egress route")]
    Binding,
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
    #[error("upstream response body exceeded configured limits")]
    Limit,
}

#[derive(Clone, Copy)]
struct ForwardResponseLimits {
    wire_bytes: u64,
    chunk_bytes: usize,
    trailer_count: u64,
    trailer_bytes: u64,
    idle: Duration,
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
    request_deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    response_limits: Option<ForwardResponseLimits>,
    response_idle_deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    response_idle_updates: Option<watch::Sender<Option<Instant>>>,
    pending_data: Option<Bytes>,
    observed_wire_bytes: u64,
    empty_frames: u64,
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

    #[cfg(test)]
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
            request_deadline: None,
            response_limits: None,
            response_idle_deadline: None,
            response_idle_updates: None,
            pending_data: None,
            observed_wire_bytes: 0,
            empty_frames: 0,
        }
    }

    pub(crate) async fn bind_response_lifetime(
        mut self,
        deadline: Instant,
        generation: GenerationRetention,
        response_admission: ForwardResponseAdmission,
        policy: http_access_types::ResponsePolicy,
        h2_stream: Option<H2StreamCancellation>,
    ) -> ForwardedDownstreamBody {
        debug_assert!(self.request_deadline.is_none());
        self.request_deadline = Some(Box::pin(tokio::time::sleep_until(deadline)));
        let idle_updates = self.configure_response_policy(policy);
        ForwardedDownstreamBody::spawn(
            self,
            deadline,
            idle_updates,
            generation,
            response_admission,
            h2_stream,
        )
        .await
    }

    fn configure_response_policy(
        &mut self,
        policy: http_access_types::ResponsePolicy,
    ) -> watch::Receiver<Option<Instant>> {
        debug_assert!(self.response_limits.is_none());
        let limits = policy.limits();
        let response_limits = ForwardResponseLimits {
            wire_bytes: limits.wire_bytes(),
            chunk_bytes: usize::try_from(limits.chunk_bytes())
                .expect("checked response chunk limit fits the product target"),
            trailer_count: limits.trailer_count(),
            trailer_bytes: limits.trailer_bytes(),
            idle: Duration::from_millis(policy.idle_ms()),
        };
        let idle_deadline = Instant::now() + response_limits.idle;
        self.response_idle_deadline = Some(Box::pin(tokio::time::sleep_until(idle_deadline)));
        let (idle_updates, idle_receiver) = watch::channel(Some(idle_deadline));
        self.response_idle_updates = Some(idle_updates);
        self.response_limits = Some(response_limits);
        idle_receiver
    }

    #[cfg(test)]
    fn with_response_policy(mut self, policy: http_access_types::ResponsePolicy) -> Self {
        let _ = self.configure_response_policy(policy);
        self
    }

    #[cfg(test)]
    fn with_terminal_drain_timeout(mut self, timeout: Duration) -> Self {
        self.terminal_drain_timeout = timeout;
        self
    }

    #[cfg(test)]
    fn with_request_deadline(mut self, deadline: Instant) -> Self {
        self.request_deadline = Some(Box::pin(tokio::time::sleep_until(deadline)));
        self
    }

    fn begin_terminal_drain(&mut self) {
        if self.terminal_drain_deadline.is_none() {
            self.terminal_drain_deadline =
                Some(Box::pin(tokio::time::sleep(self.terminal_drain_timeout)));
        }
    }

    fn release_response_lifetime(&mut self) {
        self.request_deadline.take();
        self.response_idle_deadline.take();
        self.response_idle_updates.take();
    }

    fn reset_response_idle_deadline(&mut self) {
        let Some(limits) = self.response_limits else {
            return;
        };
        let next = Instant::now() + limits.idle;
        if let Some(deadline) = self.response_idle_deadline.as_mut() {
            deadline.as_mut().reset(next);
        }
        if let Some(updates) = self.response_idle_updates.as_ref() {
            updates.send_replace(Some(next));
        }
    }

    fn poll_response_idle_deadline(&mut self, context: &mut Context<'_>) -> Poll<ForwardBodyError> {
        let Some(deadline) = self.response_idle_deadline.as_mut() else {
            return Poll::Pending;
        };
        if deadline.as_mut().poll(context).is_pending() {
            return Poll::Pending;
        }

        self.body.take();
        self.pending_data.take();
        self.trailers.take();
        self.terminal_error.get_or_insert(ForwardBodyError::Timeout);
        self.poll_terminal_error_join(context)
    }

    fn fail_body(
        &mut self,
        context: &mut Context<'_>,
        error: ForwardBodyError,
    ) -> Poll<ForwardBodyError> {
        self.body.take();
        self.pending_data.take();
        self.trailers.take();
        self.terminal_error.get_or_insert(error);
        self.poll_terminal_error_join(context)
    }

    fn next_data_slice(&mut self) -> Option<Bytes> {
        let Some(limits) = self.response_limits else {
            return self.pending_data.take();
        };
        let pending = self.pending_data.as_mut()?;
        if pending.len() > limits.chunk_bytes {
            return Some(pending.split_to(limits.chunk_bytes));
        }
        self.pending_data.take()
    }

    fn admit_response_data(&mut self, bytes: Bytes) -> Result<(), ForwardBodyError> {
        let Some(limits) = self.response_limits else {
            self.pending_data = Some(bytes);
            return Ok(());
        };
        let frame_bytes = u64::try_from(bytes.len()).map_err(|_| ForwardBodyError::Limit)?;
        self.observed_wire_bytes = self
            .observed_wire_bytes
            .checked_add(frame_bytes)
            .ok_or(ForwardBodyError::Limit)?;
        if self.observed_wire_bytes > limits.wire_bytes {
            return Err(ForwardBodyError::Limit);
        }
        self.reset_response_idle_deadline();
        self.pending_data = Some(bytes);
        Ok(())
    }

    fn admit_response_trailers(
        &mut self,
        trailers: &http::HeaderMap,
    ) -> Result<(), ForwardBodyError> {
        let Some(limits) = self.response_limits else {
            return Ok(());
        };
        let count = u64::try_from(trailers.len()).map_err(|_| ForwardBodyError::Limit)?;
        let bytes = trailers.iter().try_fold(0_u64, |total, (name, value)| {
            let entry = name
                .as_str()
                .len()
                .checked_add(value.as_bytes().len())
                .and_then(|size| u64::try_from(size).ok())
                .ok_or(ForwardBodyError::Limit)?;
            total.checked_add(entry).ok_or(ForwardBodyError::Limit)
        })?;
        if count > limits.trailer_count || bytes > limits.trailer_bytes {
            return Err(ForwardBodyError::Limit);
        }
        if count != 0 {
            self.reset_response_idle_deadline();
        }
        Ok(())
    }

    fn poll_request_deadline(&mut self, context: &mut Context<'_>) -> Poll<ForwardBodyError> {
        let Some(deadline) = self.request_deadline.as_mut() else {
            return Poll::Pending;
        };
        if deadline.as_mut().poll(context).is_pending() {
            return Poll::Pending;
        }

        self.body.take();
        self.pending_data.take();
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
            Poll::Ready(_) => {
                self.release_response_lifetime();
                Poll::Ready(Ok(()))
            }
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
                Poll::Pending => return Poll::Pending,
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
        let trailers = match trailers {
            Some(mut headers) => {
                if let Err(error) = self.admit_response_trailers(&headers) {
                    self.terminal_error = Some(error.clone());
                    return Poll::Ready(Err(error));
                }
                strip_response_hop_by_hop(&mut headers);
                Some(headers)
            }
            None => None,
        };
        self.response_idle_deadline.take();
        if let Some(updates) = self.response_idle_updates.as_ref() {
            updates.send_replace(None);
        }
        self.trailers = Some(trailers);
        self.begin_terminal_drain();
        Poll::Ready(Ok(()))
    }

    fn poll_terminal_error_join(&mut self, context: &mut Context<'_>) -> Poll<ForwardBodyError> {
        self.driver.abort();
        match self.driver.poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(_) => {
                self.release_response_lifetime();
                Poll::Ready(
                    self.terminal_error
                        .as_ref()
                        .expect("terminal response-body error is present while joining")
                        .clone(),
                )
            }
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
            Poll::Ready(Ok(Ok(()))) => {
                self.release_response_lifetime();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(Err(error))) => {
                let error = ForwardBodyError::Connection(std::sync::Arc::new(error));
                self.terminal_error = Some(error.clone());
                self.release_response_lifetime();
                Poll::Ready(Err(error))
            }
            Poll::Ready(Err(error)) => {
                let error = ForwardBodyError::Task(std::sync::Arc::new(error));
                self.terminal_error = Some(error.clone());
                self.release_response_lifetime();
                Poll::Ready(Err(error))
            }
        }
    }

    async fn abort_and_join(&mut self) {
        self.body.take();
        self.pending_data.take();
        self.trailers.take();
        self.driver.abort();
        let _ = std::future::poll_fn(|context| self.driver.poll(context)).await;
        self.release_response_lifetime();
    }
}

struct ForwardResponseResources {
    _generation: GenerationRetention,
    _response_admission: ForwardResponseAdmission,
}

pub(crate) struct ForwardedDownstreamBody {
    body: Body,
    exact_remaining: Option<u64>,
    resources: Option<Arc<ForwardResponseResources>>,
    cancel: Option<oneshot::Sender<()>>,
}

impl ForwardedDownstreamBody {
    async fn spawn(
        mut upstream: ForwardBody,
        absolute: Instant,
        idle_updates: watch::Receiver<Option<Instant>>,
        generation: GenerationRetention,
        response_admission: ForwardResponseAdmission,
        h2_stream: Option<H2StreamCancellation>,
    ) -> Self {
        let exact_remaining = upstream.size_hint().exact();
        let resources = Arc::new(ForwardResponseResources {
            _generation: generation,
            _response_admission: response_admission,
        });
        let pump_resources = resources.clone();
        let (sender, body) = Body::channel();
        let declared_over_limit = exact_remaining.is_some_and(|declared| {
            declared
                > upstream
                    .response_limits
                    .expect("the checked response policy was installed")
                    .wire_bytes
        });
        if declared_over_limit {
            if let Some(h2_stream) = h2_stream.as_ref() {
                h2_stream.cancel();
            }
            sender.abort();
            drop(tokio::spawn(async move {
                upstream.abort_and_join().await;
                drop(pump_resources);
            }));
            if h2_stream.is_some() {
                tokio::task::yield_now().await;
            }
            return Self {
                body,
                exact_remaining,
                resources: Some(resources),
                cancel: None,
            };
        }
        let (cancel, cancelled) = oneshot::channel();
        drop(tokio::spawn(async move {
            run_forward_response_pump(
                upstream,
                sender,
                h2_stream,
                absolute,
                idle_updates,
                cancelled,
            )
            .await;
            drop(pump_resources);
        }));
        Self {
            body,
            exact_remaining,
            resources: Some(resources),
            cancel: Some(cancel),
        }
    }

    fn finish(&mut self) {
        self.cancel.take();
        self.resources.take();
    }
}

impl Drop for ForwardedDownstreamBody {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }
}

impl HttpBody for ForwardedDownstreamBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_data(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        let result = Pin::new(&mut self.body).poll_data(context);
        if let Poll::Ready(Some(Ok(data))) = &result {
            self.exact_remaining = self
                .exact_remaining
                .and_then(|remaining| remaining.checked_sub(data.len() as u64));
        }
        if matches!(result, Poll::Ready(Some(Err(_))) | Poll::Ready(None)) {
            self.finish();
        }
        result
    }

    fn poll_trailers(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<Option<http::HeaderMap>, Self::Error>> {
        let result = Pin::new(&mut self.body).poll_trailers(context);
        if result.is_ready() {
            self.finish();
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.exact_remaining
            .map(SizeHint::with_exact)
            .unwrap_or_else(|| self.body.size_hint())
    }
}

enum PumpEvent<T> {
    Output(T),
    DeadlineChanged,
    Cancelled,
    Timeout,
}

async fn wait_for_upstream<F, T>(
    future: F,
    absolute: Instant,
    idle_updates: &mut watch::Receiver<Option<Instant>>,
    cancelled: &mut oneshot::Receiver<()>,
) -> PumpEvent<T>
where
    F: Future<Output = T>,
{
    tokio::pin!(future);
    let idle_deadline = *idle_updates.borrow();
    let idle_wake = idle_deadline.unwrap_or(absolute);
    tokio::select! {
        biased;
        _ = tokio::time::sleep_until(absolute) => PumpEvent::Timeout,
        output = &mut future => PumpEvent::Output(output),
        _ = &mut *cancelled => PumpEvent::Cancelled,
        _ = idle_updates.changed() => PumpEvent::DeadlineChanged,
        _ = tokio::time::sleep_until(idle_wake), if idle_deadline.is_some() => PumpEvent::Timeout,
    }
}

async fn send_downstream_data(
    sender: &mut hyper::body::Sender,
    data: Bytes,
    absolute: Instant,
    idle_deadline: Option<Instant>,
    cancelled: &mut oneshot::Receiver<()>,
) -> PumpEvent<Result<(), hyper::Error>> {
    let idle_wake = idle_deadline.unwrap_or(absolute);
    let send = sender.send_data(data);
    tokio::pin!(send);
    tokio::select! {
        biased;
        _ = tokio::time::sleep_until(absolute) => PumpEvent::Timeout,
        result = &mut send => PumpEvent::Output(result),
        _ = &mut *cancelled => PumpEvent::Cancelled,
        _ = tokio::time::sleep_until(idle_wake), if idle_deadline.is_some() => PumpEvent::Timeout,
    }
}

async fn terminate_forward_response(
    upstream: &mut ForwardBody,
    sender: &mut Option<hyper::body::Sender>,
    h2_stream: Option<&H2StreamCancellation>,
) {
    if let Some(h2_stream) = h2_stream {
        h2_stream.cancel();
    }
    if let Some(sender) = sender.take() {
        sender.abort();
    }
    upstream.abort_and_join().await;
}

async fn run_forward_response_pump(
    mut upstream: ForwardBody,
    sender: hyper::body::Sender,
    h2_stream: Option<H2StreamCancellation>,
    absolute: Instant,
    mut idle_updates: watch::Receiver<Option<Instant>>,
    mut cancelled: oneshot::Receiver<()>,
) {
    let mut sender = Some(sender);
    loop {
        let event =
            wait_for_upstream(upstream.data(), absolute, &mut idle_updates, &mut cancelled).await;
        match event {
            PumpEvent::DeadlineChanged => continue,
            PumpEvent::Cancelled => {
                terminate_forward_response(&mut upstream, &mut sender, None).await;
                return;
            }
            PumpEvent::Timeout => {
                terminate_forward_response(&mut upstream, &mut sender, h2_stream.as_ref()).await;
                return;
            }
            PumpEvent::Output(Some(Ok(data))) => {
                let sender_ref = sender
                    .as_mut()
                    .expect("the active response pump owns its downstream sender");
                let data = match sender_ref.try_send_data(data) {
                    Ok(()) => continue,
                    Err(data) => data,
                };
                let idle_deadline = *idle_updates.borrow();
                match send_downstream_data(
                    sender_ref,
                    data,
                    absolute,
                    idle_deadline,
                    &mut cancelled,
                )
                .await
                {
                    PumpEvent::Output(Ok(())) => {}
                    PumpEvent::Output(Err(_)) | PumpEvent::Cancelled => {
                        terminate_forward_response(&mut upstream, &mut sender, None).await;
                        return;
                    }
                    PumpEvent::Timeout | PumpEvent::DeadlineChanged => {
                        terminate_forward_response(&mut upstream, &mut sender, h2_stream.as_ref())
                            .await;
                        return;
                    }
                }
            }
            PumpEvent::Output(Some(Err(_))) => {
                if let Some(h2_stream) = h2_stream.as_ref() {
                    h2_stream.cancel();
                }
                if let Some(sender) = sender.take() {
                    sender.abort();
                }
                return;
            }
            PumpEvent::Output(None) => {
                match upstream.trailers().await {
                    Ok(Some(trailers)) => {
                        if let Some(sender) = sender.as_mut() {
                            if sender.send_trailers(trailers).await.is_err() {
                                return;
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(_) => {
                        if let Some(h2_stream) = h2_stream.as_ref() {
                            h2_stream.cancel();
                        }
                        if let Some(sender) = sender.take() {
                            sender.abort();
                        }
                        return;
                    }
                }
                return;
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
        if let Poll::Ready(error) = self.poll_request_deadline(context) {
            return Poll::Ready(Some(Err(error)));
        }
        if let Some(bytes) = self.next_data_slice() {
            return Poll::Ready(Some(Ok(bytes)));
        }
        if let Poll::Ready(error) = self.poll_response_idle_deadline(context) {
            return Poll::Ready(Some(Err(error)));
        }
        if !self.data_done {
            for _ in 0..MAX_INTERNAL_RESPONSE_EVENTS_PER_POLL {
                let Some(body) = self.body.as_mut() else {
                    self.data_done = true;
                    break;
                };
                match Pin::new(body).poll_data(context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Ok(bytes))) if bytes.is_empty() => {
                        self.empty_frames = self.empty_frames.saturating_add(1);
                        if self.empty_frames > MAX_EMPTY_RESPONSE_FRAMES {
                            return match self.fail_body(context, ForwardBodyError::Limit) {
                                Poll::Pending => Poll::Pending,
                                Poll::Ready(error) => Poll::Ready(Some(Err(error))),
                            };
                        }
                    }
                    Poll::Ready(Some(Ok(bytes))) => {
                        if let Err(error) = self.admit_response_data(bytes) {
                            return match self.fail_body(context, error) {
                                Poll::Pending => Poll::Pending,
                                Poll::Ready(error) => Poll::Ready(Some(Err(error))),
                            };
                        }
                        return Poll::Ready(Some(Ok(self
                            .next_data_slice()
                            .expect("admitted response data is pending"))));
                    }
                    Poll::Ready(Some(Err(error))) => {
                        return match self
                            .fail_body(context, ForwardBodyError::Body(std::sync::Arc::new(error)))
                        {
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(error) => Poll::Ready(Some(Err(error))),
                        };
                    }
                    Poll::Ready(None) => {
                        self.data_done = true;
                        break;
                    }
                }
            }
            if !self.data_done {
                context.waker().wake_by_ref();
                return Poll::Pending;
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
        if let Poll::Ready(error) = self.poll_request_deadline(context) {
            return Poll::Ready(Err(error));
        }
        if let Poll::Ready(error) = self.poll_response_idle_deadline(context) {
            return Poll::Ready(Err(error));
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

pub(crate) enum ForwardUpgradeResult {
    Response(Box<ForwardedResponse>),
    SwitchingProtocols(ForwardedUpgrade),
}

pub(crate) struct ForwardedUpgrade {
    response: Response<Body>,
    upstream: PendingUpstreamUpgrade,
}

impl ForwardedUpgrade {
    pub(crate) fn into_parts(self) -> (Response<Body>, PendingUpstreamUpgrade) {
        (self.response, self.upstream)
    }
}

pub(crate) struct PendingUpstreamUpgrade {
    on_upgrade: hyper::upgrade::OnUpgrade,
    driver: DriverTask,
}

impl PendingUpstreamUpgrade {
    pub(crate) async fn complete(self) -> Result<hyper::upgrade::Upgraded, ForwardError> {
        let upgraded = match self.on_upgrade.await {
            Ok(upgraded) => upgraded,
            Err(error) => {
                self.driver.abort_and_join().await;
                return Err(ForwardError::Http(error));
            }
        };
        match self.driver.join().await {
            Ok(Ok(())) => Ok(upgraded),
            Ok(Err(error)) => Err(ForwardError::Http(error)),
            Err(error) => Err(ForwardError::Task(error)),
        }
    }
}

pub(crate) struct PreflightForwardingTarget {
    canonical_url: String,
    ingress_protocol: OriginProtocol,
    origin_protocol: OriginProtocol,
    egress_identity: std::sync::Arc<()>,
    route: PreparedForwardingRoute,
}

pub(crate) struct PreparedForwardingTarget(PreflightForwardingTarget);

enum PreparedForwardingRoute {
    Direct(PreparedDestination),
    Parent {
        parent_url: String,
        destination: PreparedDestination,
    },
}

pub(crate) struct ResolvedForwardingTarget {
    canonical_url: String,
    ingress_protocol: OriginProtocol,
    origin_protocol: OriginProtocol,
    egress_identity: std::sync::Arc<()>,
    route: ResolvedForwardingRoute,
}

enum ResolvedForwardingRoute {
    Direct(ResolvedDestination),
    Parent {
        parent_url: String,
        destination: ResolvedDestination,
    },
}

/// Performs synchronous semantic destination checks before initial policy matching.
pub(crate) fn preflight_forwarding_target(
    canonical: &CanonicalUrl,
    request: &SanitizedRequest<impl Sized>,
    egress: &dyn EgressSnapshot,
    destinations: &DestinationGuard,
) -> Result<PreflightForwardingTarget, ResolveForwardingError> {
    let ingress_protocol = request.protocol();
    let origin_protocol = egress.origin_tls().select_protocol(ingress_protocol);
    let egress_identity = egress.identity().clone();
    let route = match egress.route() {
        EgressRoute::Direct => PreparedForwardingRoute::Direct(
            destinations.preflight(DestinationTarget::direct(canonical))?,
        ),
        EgressRoute::Parent(parent) => PreparedForwardingRoute::Parent {
            parent_url: parent.canonical_url().to_owned(),
            destination: destinations
                .preflight(DestinationTarget::parent(parent.authority(), canonical))?,
        },
    };
    Ok(PreflightForwardingTarget {
        canonical_url: canonical.as_str().to_owned(),
        ingress_protocol,
        origin_protocol,
        egress_identity,
        route,
    })
}

impl PreflightForwardingTarget {
    /// Binds semantic preflight to the exact request, egress snapshot, and
    /// destination guard before DNS or provider work can begin.
    pub(crate) fn bind_for_request(
        self,
        canonical: &CanonicalUrl,
        ingress_protocol: OriginProtocol,
        egress: &dyn EgressSnapshot,
        destinations: &DestinationGuard,
    ) -> Result<PreparedForwardingTarget, ResolveForwardingError> {
        let origin_protocol = egress.origin_tls().select_protocol(ingress_protocol);
        let route_matches = match (&self.route, egress.route()) {
            (PreparedForwardingRoute::Direct(destination), EgressRoute::Direct) => {
                destination.belongs_to(destinations)
            }
            (
                PreparedForwardingRoute::Parent {
                    parent_url,
                    destination,
                },
                EgressRoute::Parent(parent),
            ) => parent_url == parent.canonical_url() && destination.belongs_to(destinations),
            _ => false,
        };
        if self.canonical_url != canonical.as_str()
            || self.ingress_protocol != ingress_protocol
            || self.origin_protocol != origin_protocol
            || !std::sync::Arc::ptr_eq(&self.egress_identity, egress.identity())
            || !route_matches
        {
            return Err(ResolveForwardingError::Binding);
        }
        Ok(PreparedForwardingTarget(self))
    }
}

/// Completes one pinned destination resolution under the request deadline.
pub(crate) async fn resolve_forwarding_target(
    prepared: PreparedForwardingTarget,
    destinations: &DestinationGuard,
) -> Result<ResolvedForwardingTarget, ResolveForwardingError> {
    let PreparedForwardingTarget(PreflightForwardingTarget {
        canonical_url,
        ingress_protocol,
        origin_protocol,
        egress_identity,
        route,
    }) = prepared;
    let route = match route {
        PreparedForwardingRoute::Direct(destination) => {
            ResolvedForwardingRoute::Direct(destinations.complete_resolution(destination).await?)
        }
        PreparedForwardingRoute::Parent {
            parent_url,
            destination,
        } => ResolvedForwardingRoute::Parent {
            parent_url,
            destination: destinations.complete_resolution(destination).await?,
        },
    };
    Ok(ResolvedForwardingTarget {
        canonical_url,
        ingress_protocol,
        origin_protocol,
        egress_identity,
        route,
    })
}

/// Sends one already-authorized logical origin request without connection reuse.
/// The resolved token carries the only DNS result; connect performs synchronous
/// pre- and post-connect validation before any outbound bytes.
pub(crate) async fn forward_request<B>(
    request: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    egress: &dyn EgressSnapshot,
    destinations: &DestinationGuard,
    target: ResolvedForwardingTarget,
    timeouts: ForwardingTimeouts,
    credentials: Option<ProductCredentialExecution>,
) -> Result<ForwardedResponse, ForwardError>
where
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    forward_with_connector_timed(
        request,
        canonical,
        egress,
        destinations,
        target,
        &TcpDestinationConnector,
        ForwardExecutionOptions::new(timeouts, credentials),
    )
    .await
}

async fn forward_with_connector_timed<C, B>(
    request: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    egress: &dyn EgressSnapshot,
    destinations: &DestinationGuard,
    target: ResolvedForwardingTarget,
    connector: &C,
    execution: ForwardExecutionOptions,
) -> Result<ForwardedResponse, ForwardError>
where
    C: DestinationConnector,
    C::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let selected_origin_protocol = egress.origin_tls().select_protocol(request.protocol());
    if target.canonical_url != canonical.as_str()
        || target.ingress_protocol != request.protocol()
        || target.origin_protocol != selected_origin_protocol
        || !std::sync::Arc::ptr_eq(&target.egress_identity, egress.identity())
    {
        return Err(ForwardError::ResolvedTargetMismatch);
    }

    let execution = execution.begin_connect();
    let deadlines = execution.deadlines;
    match (egress.route(), target.route) {
        (EgressRoute::Direct, ResolvedForwardingRoute::Direct(resolved)) => {
            let stream = connect_stage(deadlines, destinations.connect(resolved, connector))
                .await?
                .into_stream();
            forward_direct(
                request,
                canonical,
                egress,
                selected_origin_protocol,
                stream,
                execution,
            )
            .await
        }
        (
            EgressRoute::Parent(parent),
            ResolvedForwardingRoute::Parent {
                parent_url,
                destination: resolved,
            },
        ) if parent_url == parent.canonical_url() => {
            let stream = connect_stage(deadlines, destinations.connect(resolved, connector))
                .await?
                .into_stream();
            forward_via_parent(
                request,
                canonical,
                egress,
                parent,
                selected_origin_protocol,
                stream,
                execution,
            )
            .await
        }
        _ => Err(ForwardError::ResolvedTargetMismatch),
    }
}

#[cfg(test)]
async fn forward_with_connector<C, B>(
    request: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    egress: &dyn EgressSnapshot,
    destinations: &DestinationGuard,
    target: ResolvedForwardingTarget,
    connector: &C,
) -> Result<ForwardedResponse, ForwardError>
where
    C: DestinationConnector,
    C::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    forward_with_connector_timed(
        request,
        canonical,
        egress,
        destinations,
        target,
        connector,
        ForwardExecutionOptions::new(ForwardingTimeouts::for_test(), None),
    )
    .await
}

/// Sends one already-authorized HTTP/1 upgrade request without connection
/// reuse. A non-101 response remains an ordinary forwarded response. A valid
/// 101 returns the canonical response head and an owned upstream upgrade whose
/// connection driver remains live until `complete` joins it.
pub(crate) async fn forward_upgrade_request<B>(
    request: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    generation: &GenerationRetention,
    destinations: std::sync::Arc<DestinationGuard>,
    target: ResolvedForwardingTarget,
    timeouts: ForwardingTimeouts,
    credentials: Option<ProductCredentialExecution>,
) -> Result<ForwardUpgradeResult, ForwardError>
where
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let egress = generation.egress();
    forward_upgrade_with_connector_timed(
        request,
        canonical,
        egress,
        &destinations,
        target,
        &TcpDestinationConnector,
        ForwardExecutionOptions::new(timeouts, credentials),
    )
    .await
}

async fn forward_upgrade_with_connector_timed<C, B>(
    request: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    egress: &dyn EgressSnapshot,
    destinations: &DestinationGuard,
    target: ResolvedForwardingTarget,
    connector: &C,
    execution: ForwardExecutionOptions,
) -> Result<ForwardUpgradeResult, ForwardError>
where
    C: DestinationConnector,
    C::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let intent = request
        .upgrade_intent()
        .cloned()
        .ok_or(HeaderPreparationError::InvalidUpgrade)?;
    let selected_origin_protocol = egress.origin_tls().select_protocol(request.protocol());
    if selected_origin_protocol.is_http2() {
        return Err(ForwardError::UpgradeRequiresHttp1);
    }
    if target.canonical_url != canonical.as_str()
        || target.ingress_protocol != request.protocol()
        || target.origin_protocol != selected_origin_protocol
        || !std::sync::Arc::ptr_eq(&target.egress_identity, egress.identity())
    {
        return Err(ForwardError::ResolvedTargetMismatch);
    }

    let execution = execution.begin_connect();
    let deadlines = execution.deadlines;
    match (egress.route(), target.route) {
        (EgressRoute::Direct, ResolvedForwardingRoute::Direct(resolved)) => {
            let stream = connect_stage(deadlines, destinations.connect(resolved, connector))
                .await?
                .into_stream();
            forward_upgrade_direct(request, canonical, egress, stream, intent, execution).await
        }
        (
            EgressRoute::Parent(parent),
            ResolvedForwardingRoute::Parent {
                parent_url,
                destination: resolved,
            },
        ) if parent_url == parent.canonical_url() => {
            let stream = connect_stage(deadlines, destinations.connect(resolved, connector))
                .await?
                .into_stream();
            forward_upgrade_via_parent(
                request, canonical, egress, parent, stream, intent, execution,
            )
            .await
        }
        _ => Err(ForwardError::ResolvedTargetMismatch),
    }
}

#[cfg(test)]
async fn forward_upgrade_with_connector<C, B>(
    request: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    egress: &dyn EgressSnapshot,
    destinations: &DestinationGuard,
    target: ResolvedForwardingTarget,
    connector: &C,
) -> Result<ForwardUpgradeResult, ForwardError>
where
    C: DestinationConnector,
    C::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    forward_upgrade_with_connector_timed(
        request,
        canonical,
        egress,
        destinations,
        target,
        connector,
        ForwardExecutionOptions::new(ForwardingTimeouts::for_test(), None),
    )
    .await
}

async fn forward_upgrade_direct<S, B>(
    request: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    egress: &dyn EgressSnapshot,
    stream: S,
    intent: UpgradeIntent,
    execution: EstablishedForwardExecution,
) -> Result<ForwardUpgradeResult, ForwardError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let EstablishedForwardExecution {
        deadlines,
        credentials,
    } = execution;
    if canonical.scheme() == HttpScheme::Https {
        let stream = connect_stage(
            deadlines,
            connect_origin_tls(stream, canonical, egress, OriginProtocol::Http1),
        )
        .await?;
        let request = prepare_origin_upgrade_request(
            request,
            canonical,
            RequestTargetForm::Origin,
            OriginProtocol::Http1,
        )?;
        send_upgrade_request(stream, request, intent, deadlines, credentials).await
    } else {
        let request = prepare_origin_upgrade_request(
            request,
            canonical,
            RequestTargetForm::Origin,
            OriginProtocol::Http1,
        )?;
        send_upgrade_request(stream, request, intent, deadlines, credentials).await
    }
}

async fn forward_upgrade_via_parent<S, B>(
    request: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    egress: &dyn EgressSnapshot,
    parent: &ParentEndpoint,
    stream: S,
    intent: UpgradeIntent,
    execution: EstablishedForwardExecution,
) -> Result<ForwardUpgradeResult, ForwardError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let EstablishedForwardExecution {
        deadlines,
        credentials,
    } = execution;
    if canonical.scheme() == HttpScheme::Https {
        match parent.transport() {
            ParentTransport::Http => {
                let tunnel =
                    connect_stage(deadlines, connect_parent_tunnel(stream, canonical)).await?;
                let origin = connect_stage(
                    deadlines,
                    connect_origin_tls(tunnel, canonical, egress, OriginProtocol::Http1),
                )
                .await?;
                let request = prepare_origin_upgrade_request(
                    request,
                    canonical,
                    RequestTargetForm::Origin,
                    OriginProtocol::Http1,
                )?;
                send_upgrade_request(origin, request, intent, deadlines, credentials).await
            }
            ParentTransport::Https(tls) => {
                let parent_stream =
                    connect_stage(deadlines, connect_parent_tls(stream, tls, false)).await?;
                let tunnel =
                    connect_stage(deadlines, connect_parent_tunnel(parent_stream, canonical))
                        .await?;
                let origin = connect_stage(
                    deadlines,
                    connect_origin_tls(tunnel, canonical, egress, OriginProtocol::Http1),
                )
                .await?;
                let request = prepare_origin_upgrade_request(
                    request,
                    canonical,
                    RequestTargetForm::Origin,
                    OriginProtocol::Http1,
                )?;
                send_upgrade_request(origin, request, intent, deadlines, credentials).await
            }
        }
    } else {
        let request = prepare_origin_upgrade_request(
            request,
            canonical,
            RequestTargetForm::Absolute,
            OriginProtocol::Http1,
        )?;
        match parent.transport() {
            ParentTransport::Http => {
                send_upgrade_request(stream, request, intent, deadlines, credentials).await
            }
            ParentTransport::Https(tls) => {
                let stream =
                    connect_stage(deadlines, connect_parent_tls(stream, tls, false)).await?;
                send_upgrade_request(stream, request, intent, deadlines, credentials).await
            }
        }
    }
}

async fn forward_direct<S, B>(
    request: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    egress: &dyn EgressSnapshot,
    protocol: OriginProtocol,
    stream: S,
    execution: EstablishedForwardExecution,
) -> Result<ForwardedResponse, ForwardError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let EstablishedForwardExecution {
        deadlines,
        credentials,
    } = execution;
    if canonical.scheme() == HttpScheme::Https {
        let stream = connect_stage(
            deadlines,
            connect_origin_tls(stream, canonical, egress, protocol),
        )
        .await?;
        let request =
            prepare_origin_request(request, canonical, RequestTargetForm::Origin, protocol)?;
        send_request(stream, request, protocol, deadlines, credentials).await
    } else {
        let request =
            prepare_origin_request(request, canonical, RequestTargetForm::Origin, protocol)?;
        send_request(stream, request, protocol, deadlines, credentials).await
    }
}

async fn forward_via_parent<S, B>(
    request: SanitizedRequest<B>,
    canonical: &CanonicalUrl,
    egress: &dyn EgressSnapshot,
    parent: &ParentEndpoint,
    protocol: OriginProtocol,
    stream: S,
    execution: EstablishedForwardExecution,
) -> Result<ForwardedResponse, ForwardError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let EstablishedForwardExecution {
        deadlines,
        credentials,
    } = execution;
    if canonical.scheme() == HttpScheme::Https {
        // CONNECT is deliberately HTTP/1.1 and contains no logical-origin
        // headers. The selected origin protocol applies inside the tunnel.
        match parent.transport() {
            ParentTransport::Http => {
                let tunnel =
                    connect_stage(deadlines, connect_parent_tunnel(stream, canonical)).await?;
                let origin = connect_stage(
                    deadlines,
                    connect_origin_tls(tunnel, canonical, egress, protocol),
                )
                .await?;
                let request = prepare_origin_request(
                    request,
                    canonical,
                    RequestTargetForm::Origin,
                    protocol,
                )?;
                send_request(origin, request, protocol, deadlines, credentials).await
            }
            ParentTransport::Https(tls) => {
                let parent_stream =
                    connect_stage(deadlines, connect_parent_tls(stream, tls, false)).await?;
                let tunnel =
                    connect_stage(deadlines, connect_parent_tunnel(parent_stream, canonical))
                        .await?;
                let origin = connect_stage(
                    deadlines,
                    connect_origin_tls(tunnel, canonical, egress, protocol),
                )
                .await?;
                let request = prepare_origin_request(
                    request,
                    canonical,
                    RequestTargetForm::Origin,
                    protocol,
                )?;
                send_request(origin, request, protocol, deadlines, credentials).await
            }
        }
    } else {
        let request =
            prepare_origin_request(request, canonical, RequestTargetForm::Absolute, protocol)?;
        match parent.transport() {
            ParentTransport::Http => {
                send_request(stream, request, protocol, deadlines, credentials).await
            }
            ParentTransport::Https(tls) => {
                let stream = connect_stage(
                    deadlines,
                    connect_parent_tls(stream, tls, protocol.is_http2()),
                )
                .await?;
                send_request(stream, request, protocol, deadlines, credentials).await
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
    let name = ServerName::try_from(canonical.authority().host().as_str())
        .map_err(|_| ForwardError::TlsServerName)?;
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
    let authority = canonical.authority().connect_authority();
    let uri: http::Uri = authority
        .parse()
        .map_err(|_| HeaderPreparationError::Target)?;
    let host = HeaderValue::from_str(authority).map_err(|_| HeaderPreparationError::Authority)?;
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

struct UpgradeRequestWriteState {
    body_complete: std::sync::atomic::AtomicBool,
    post_completion_bytes_written: std::sync::atomic::AtomicBool,
    request_flushed: std::sync::atomic::AtomicBool,
}

impl UpgradeRequestWriteState {
    fn new(body_complete: bool) -> Self {
        Self {
            body_complete: std::sync::atomic::AtomicBool::new(body_complete),
            post_completion_bytes_written: std::sync::atomic::AtomicBool::new(false),
            request_flushed: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

struct UpgradeFlushTrackedIo<S> {
    inner: S,
    state: Arc<UpgradeRequestWriteState>,
}

impl<S> UpgradeFlushTrackedIo<S> {
    fn new(inner: S, state: Arc<UpgradeRequestWriteState>) -> Self {
        Self { inner, state }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for UpgradeFlushTrackedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for UpgradeFlushTrackedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(context, buffer);
        if matches!(result, Poll::Ready(Ok(written)) if written != 0)
            && this
                .state
                .body_complete
                .load(std::sync::atomic::Ordering::Acquire)
        {
            this.state
                .post_completion_bytes_written
                .store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_flush(context);
        if matches!(&result, Poll::Ready(Ok(())))
            && this
                .state
                .post_completion_bytes_written
                .load(std::sync::atomic::Ordering::Acquire)
        {
            this.state
                .request_flushed
                .store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(context, buffers);
        if matches!(result, Poll::Ready(Ok(written)) if written != 0)
            && this
                .state
                .body_complete
                .load(std::sync::atomic::Ordering::Acquire)
        {
            this.state
                .post_completion_bytes_written
                .store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }
}

async fn send_upgrade_request<S, B>(
    stream: S,
    request: Request<B>,
    intent: UpgradeIntent,
    deadlines: ForwardingDeadlines,
    credentials: Option<ProductCredentialExecution>,
) -> Result<ForwardUpgradeResult, ForwardError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (parts, body) = request.into_parts();
    let (body, write_state) = UpgradeRequestBody::new(body);
    let mut request = Request::from_parts(parts, body);
    let stream = UpgradeFlushTrackedIo::new(stream, write_state.clone());
    let (mut sender, connection) = connect_stage(deadlines, async {
        conn::Builder::new()
            .handshake(stream)
            .await
            .map_err(ForwardError::Http)
    })
    .await?;
    let driver = DriverTask::spawn(connection);
    if let Some(credentials) = credentials {
        if let Err(error) = credentials.finalize(&mut request).await {
            driver.abort_and_join().await;
            return Err(ForwardError::Credential(error));
        }
    }
    let mut response = match tokio::time::timeout_at(
        deadlines.response_head(),
        sender.send_request(request),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            driver.abort_and_join().await;
            return Err(ForwardError::Http(error));
        }
        Err(_) => {
            driver.abort_and_join().await;
            return Err(ForwardError::ResponseHeadTimeout);
        }
    };

    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        let (mut parts, body) = response.into_parts();
        strip_response_hop_by_hop(&mut parts.headers);
        return Ok(ForwardUpgradeResult::Response(Box::new(
            Response::from_parts(parts, ForwardBody::new(body, driver)),
        )));
    }

    if !write_state
        .request_flushed
        .load(std::sync::atomic::Ordering::Acquire)
    {
        driver.abort_and_join().await;
        return Err(ForwardError::UpgradeRequestBodyIncomplete);
    }

    if let Err(error) =
        prepare_downstream_upgrade_response(response.status(), response.headers_mut(), &intent)
    {
        driver.abort_and_join().await;
        return Err(ForwardError::Header(error));
    }
    let on_upgrade = hyper::upgrade::on(&mut response);
    let (parts, body) = response.into_parts();
    drop(body);
    Ok(ForwardUpgradeResult::SwitchingProtocols(ForwardedUpgrade {
        response: Response::from_parts(parts, Body::empty()),
        upstream: PendingUpstreamUpgrade { on_upgrade, driver },
    }))
}

struct UpgradeRequestBody<B> {
    inner: Pin<Box<B>>,
    write_state: Arc<UpgradeRequestWriteState>,
    exact_remaining: Option<u64>,
}

impl<B: HttpBody> UpgradeRequestBody<B> {
    fn new(body: B) -> (Self, Arc<UpgradeRequestWriteState>) {
        let exact_remaining = body.size_hint().exact();
        let write_state = Arc::new(UpgradeRequestWriteState::new(
            body.is_end_stream() || exact_remaining == Some(0),
        ));
        (
            Self {
                inner: Box::pin(body),
                write_state: write_state.clone(),
                exact_remaining,
            },
            write_state,
        )
    }
}

impl<B: HttpBody> HttpBody for UpgradeRequestBody<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_data(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        let result = self.inner.as_mut().poll_data(context);
        if let Poll::Ready(Some(Ok(data))) = &result {
            if let Some(remaining) = self.exact_remaining.as_mut() {
                *remaining = remaining
                    .checked_sub(u64::try_from(data.remaining()).unwrap_or(u64::MAX))
                    .unwrap_or(u64::MAX);
            }
        }
        let complete = match self.exact_remaining {
            Some(remaining) => remaining == 0,
            None => {
                matches!(&result, Poll::Ready(Some(Ok(_))) | Poll::Ready(None))
                    && self.inner.as_ref().is_end_stream()
            }
        };
        if complete {
            self.write_state
                .body_complete
                .store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }

    fn poll_trailers(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<Option<http::HeaderMap>, Self::Error>> {
        let result = self.inner.as_mut().poll_trailers(context);
        if matches!(result, Poll::Ready(Ok(_)))
            && self.exact_remaining.is_none_or(|remaining| remaining == 0)
        {
            self.write_state
                .body_complete
                .store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.as_ref().is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.as_ref().size_hint()
    }
}

async fn send_request<S, B>(
    stream: S,
    request: Request<B>,
    protocol: OriginProtocol,
    deadlines: ForwardingDeadlines,
    credentials: Option<ProductCredentialExecution>,
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
    let (mut sender, connection) = connect_stage(deadlines, async {
        builder.handshake(stream).await.map_err(ForwardError::Http)
    })
    .await?;
    let driver = DriverTask::spawn(connection);
    let mut request = request;
    if let Some(credentials) = credentials {
        if let Err(error) = credentials.finalize(&mut request).await {
            driver.abort_and_join().await;
            return Err(ForwardError::Credential(error));
        }
    }
    let response = match tokio::time::timeout_at(
        deadlines.response_head(),
        sender.send_request(request),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            driver.abort_and_join().await;
            return Err(ForwardError::Http(error));
        }
        Err(_) => {
            driver.abort_and_join().await;
            return Err(ForwardError::ResponseHeadTimeout);
        }
    };
    if response.status().is_informational() {
        let status = response.status();
        driver.abort_and_join().await;
        return Err(ForwardError::UnexpectedInformationalResponse(status));
    }
    let (mut parts, body) = response.into_parts();
    strip_response_hop_by_hop(&mut parts.headers);
    Ok(Response::from_parts(parts, ForwardBody::new(body, driver)))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::future::Future;
    use std::io;
    use std::net::SocketAddr;
    use std::net::{IpAddr, Ipv4Addr};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use http::header::{CONNECTION, CONTENT_LENGTH, TE, UPGRADE};
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
    use crate::safety::{GuardedBody, WireBodyPool, WireBodyQuotaKey};
    use http_access_url::canonicalize_http_url;

    const CANDIDATE: &str = "192.0.2.20:8443";

    fn expect_forward_error<T>(result: Result<T, ForwardError>, message: &str) -> ForwardError {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

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

    struct FailingConnector {
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

    impl DestinationConnector for FailingConnector {
        type Stream = DuplexStream;

        fn connect(
            &self,
            _endpoint: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + Send + '_>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(io::Error::new(io::ErrorKind::ConnectionRefused, "rejected")) })
        }

        fn peer_addr(&self, _stream: &Self::Stream) -> io::Result<SocketAddr> {
            unreachable!("a failed connector never returns a stream")
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

    fn credential_guard() -> crate::safety::HttpWireBodyGuard {
        let peak = 8 * 1024 * 1024;
        WireBodyPool::new(peak, peak).begin_for_test(
            peak,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        )
    }

    async fn prepare_and_resolve_target<B>(
        canonical: &CanonicalUrl,
        request: &SanitizedRequest<B>,
        egress: &dyn EgressSnapshot,
        destinations: &DestinationGuard,
    ) -> Result<ResolvedForwardingTarget, ResolveForwardingError> {
        let prepared = preflight_forwarding_target(canonical, request, egress, destinations)?;
        let prepared =
            prepared.bind_for_request(canonical, request.protocol(), egress, destinations)?;
        resolve_forwarding_target(prepared, destinations).await
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

    fn upgrade_request() -> SanitizedRequest {
        let request = Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_11)
            .uri("/untrusted-client-target")
            .header(HOST, "untrusted-client.example")
            .header(CONNECTION, "keep-alive, Upgrade, x-private")
            .header(UPGRADE, "WebSocket")
            .header("x-private", "remove-me")
            .body(Body::empty())
            .unwrap();
        crate::proxy::headers::sanitize_untrusted_request(request).unwrap()
    }

    async fn read_http_head(stream: &mut DuplexStream) -> String {
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
        String::from_utf8(head).unwrap()
    }

    async fn read_http_line(stream: &mut DuplexStream) -> Vec<u8> {
        let mut line = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            line.push(byte[0]);
            if line.ends_with(b"\r\n") {
                line.truncate(line.len() - 2);
                return line;
            }
            assert!(line.len() < 8 * 1024);
        }
    }

    async fn read_chunked_http_body(stream: &mut DuplexStream) -> Vec<u8> {
        let mut body = Vec::new();
        loop {
            let line = read_http_line(stream).await;
            let size = line.split(|byte| *byte == b';').next().unwrap();
            let size = usize::from_str_radix(std::str::from_utf8(size).unwrap(), 16).unwrap();
            if size == 0 {
                assert!(read_http_line(stream).await.is_empty());
                return body;
            }
            let start = body.len();
            body.resize(start + size, 0);
            stream.read_exact(&mut body[start..]).await.unwrap();
            let mut terminator = [0_u8; 2];
            stream.read_exact(&mut terminator).await.unwrap();
            assert_eq!(&terminator, b"\r\n");
        }
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
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
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
            canonical.as_str()
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
            assert_eq!(headers[HOST], canonical.authority().as_str(), "{route:?}");
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

    fn response_policy(
        wire_bytes: u64,
        chunk_bytes: u64,
        trailer_count: u64,
        trailer_bytes: u64,
        idle_ms: u64,
    ) -> http_access_types::ResponsePolicy {
        let limits = http_access_types::BodyLimits::new(
            wire_bytes,
            wire_bytes,
            1,
            1,
            chunk_bytes,
            trailer_count,
            trailer_bytes,
        )
        .unwrap();
        http_access_types::ResponsePolicy::new(
            limits,
            idle_ms,
            http_access_types::RedirectPolicy::ReturnToCaller,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn ordinary_forwarding_rejects_unsolicited_switching_protocols() {
        let canonical = canonicalize_http_url("http://origin.example/ordinary").unwrap();
        let egress = activate(None);
        let request = request();
        let (guard, _) = guard();
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();
        let server = tokio::spawn(async move {
            let _ = read_http_head(&mut server).await;
            let mut request_body = [0_u8; 12];
            server.read_exact(&mut request_body).await.unwrap();
            assert_eq!(&request_body, b"request-body");
            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .await
                .unwrap();
            let mut byte = [0_u8; 1];
            assert_eq!(server.read(&mut byte).await.unwrap(), 0);
        });

        let error = expect_forward_error(
            forward_with_connector(request, &canonical, &egress, &guard, target, &connector).await,
            "an ordinary request must reject an unsolicited 101",
        );
        assert!(matches!(
            error,
            ForwardError::UnexpectedInformationalResponse(StatusCode::SWITCHING_PROTOCOLS)
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn upgrade_handshake_preserves_driver_and_returns_canonical_owned_parts() {
        const VARIABLE: &str = "ACL_PROXY_UPGRADE_LATE_TOKEN";
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        std::env::set_var(VARIABLE, "upgrade-secret");
        let canonical = canonicalize_http_url("http://origin.example/socket?q=1").unwrap();
        let egress = activate(None);
        let mut request = upgrade_request();
        let wire_guard = credential_guard();
        let (mut credentials, io) = crate::credential_resolver::environment_execution_for_test(
            &wire_guard,
            VARIABLE,
            "x-late-token",
        );
        credentials
            .reserve_transport(request.headers_mut())
            .unwrap();
        let (guard, _) = guard();
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();
        let server = tokio::spawn(async move {
            let head = read_http_head(&mut server).await;
            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: x-private, Upgrade\r\nUpgrade: websocket\r\nx-private: remove-me\r\n\r\n",
                )
                .await
                .unwrap();
            let mut ping = [0_u8; 4];
            server.read_exact(&mut ping).await.unwrap();
            assert_eq!(&ping, b"ping");
            server.write_all(b"pong").await.unwrap();
            head
        });

        let result = forward_upgrade_with_connector_timed(
            request,
            &canonical,
            &egress,
            &guard,
            target,
            &connector,
            ForwardExecutionOptions::new(ForwardingTimeouts::for_test(), Some(credentials)),
        )
        .await
        .unwrap();
        let ForwardUpgradeResult::SwitchingProtocols(upgrade) = result else {
            panic!("a valid 101 must return owned upgrade state");
        };
        let (response, pending) = upgrade.into_parts();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(response.headers()[CONNECTION], "upgrade");
        assert_eq!(response.headers()[UPGRADE], "WebSocket");
        assert!(!response.headers().contains_key("x-private"));

        let mut upstream = tokio::time::timeout(Duration::from_secs(2), pending.complete())
            .await
            .expect("upstream OnUpgrade and its driver must complete")
            .unwrap();
        upstream.write_all(b"ping").await.unwrap();
        let mut pong = [0_u8; 4];
        upstream.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
        drop(upstream);

        let head = server.await.unwrap().to_ascii_lowercase();
        assert!(head.starts_with("get /socket?q=1 http/1.1\r\n"));
        assert!(head.contains("\r\nhost: origin.example\r\n"));
        assert!(head.contains("\r\nconnection: upgrade\r\n"));
        assert!(head.contains("\r\nupgrade: websocket\r\n"));
        assert_eq!(
            head.matches("\r\nx-late-token: upgrade-secret\r\n").count(),
            1
        );
        assert!(!head.contains("x-private"));
        io.shutdown_and_wait(None).await;
        std::env::remove_var(VARIABLE);
    }

    #[tokio::test]
    async fn upgrade_waits_for_content_length_and_chunked_request_bodies_before_101() {
        struct UpgradeTestBody {
            data: Option<Bytes>,
            chunked: bool,
            complete: bool,
        }

        impl HttpBody for UpgradeTestBody {
            type Data = Bytes;
            type Error = io::Error;

            fn poll_data(
                mut self: Pin<&mut Self>,
                _context: &mut Context<'_>,
            ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
                if let Some(data) = self.data.take() {
                    return Poll::Ready(Some(Ok(data)));
                }
                self.complete = true;
                Poll::Ready(None)
            }

            fn poll_trailers(
                self: Pin<&mut Self>,
                _context: &mut Context<'_>,
            ) -> Poll<Result<Option<http::HeaderMap>, Self::Error>> {
                Poll::Ready(Ok(None))
            }

            fn is_end_stream(&self) -> bool {
                self.chunked && self.complete
            }

            fn size_hint(&self) -> SizeHint {
                if self.chunked {
                    SizeHint::default()
                } else {
                    SizeHint::with_exact(4)
                }
            }
        }

        let canonical = canonicalize_http_url("http://origin.example/socket").unwrap();

        for chunked in [false, true] {
            let body = UpgradeTestBody {
                data: Some(Bytes::from_static(b"body")),
                chunked,
                complete: false,
            };
            let mut builder = Request::builder()
                .method(Method::POST)
                .version(Version::HTTP_11)
                .uri("/untrusted-client-target")
                .header(HOST, "untrusted-client.example")
                .header(CONNECTION, "upgrade")
                .header(UPGRADE, "test-echo");
            if !chunked {
                builder = builder.header(CONTENT_LENGTH, "4");
            }
            let request =
                crate::proxy::headers::sanitize_untrusted_request(builder.body(body).unwrap())
                    .unwrap();
            let intent = request.upgrade_intent().unwrap().clone();
            let request = prepare_origin_upgrade_request(
                request,
                &canonical,
                RequestTargetForm::Origin,
                OriginProtocol::Http1,
            )
            .unwrap();
            let (client, mut server) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(async move {
                let head = read_http_head(&mut server).await.to_ascii_lowercase();
                assert!(head.contains("\r\nconnection: upgrade\r\n"));
                assert!(head.contains("\r\nupgrade: test-echo\r\n"));
                let body = if chunked {
                    assert!(head.contains("\r\ntransfer-encoding: chunked\r\n"));
                    read_chunked_http_body(&mut server).await
                } else {
                    assert!(head.contains("\r\ncontent-length: 4\r\n"));
                    let mut body = vec![0_u8; 4];
                    server.read_exact(&mut body).await.unwrap();
                    body
                };
                assert_eq!(body, b"body");
                server
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n",
                    )
                    .await
                    .unwrap();
                let mut ping = [0_u8; 4];
                server.read_exact(&mut ping).await.unwrap();
                assert_eq!(&ping, b"ping");
                server.write_all(b"pong").await.unwrap();
            });

            let result = send_upgrade_request(
                client,
                request,
                intent,
                ForwardingTimeouts::for_test().begin_connect(),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("chunked={chunked}: {error:?}"));
            let ForwardUpgradeResult::SwitchingProtocols(upgrade) = result else {
                panic!("a complete body-bearing upgrade must accept a valid 101");
            };
            let (_, pending) = upgrade.into_parts();
            let mut upstream = pending.complete().await.unwrap();
            upstream.write_all(b"ping").await.unwrap();
            let mut pong = [0_u8; 4];
            upstream.read_exact(&mut pong).await.unwrap();
            assert_eq!(&pong, b"pong");
            drop(upstream);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn upgrade_rejects_101_before_request_flush_completes() {
        struct FlushPendingIo {
            inner: DuplexStream,
        }

        impl AsyncRead for FlushPendingIo {
            fn poll_read(
                self: Pin<&mut Self>,
                context: &mut Context<'_>,
                buffer: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().inner).poll_read(context, buffer)
            }
        }

        impl AsyncWrite for FlushPendingIo {
            fn poll_write(
                self: Pin<&mut Self>,
                context: &mut Context<'_>,
                buffer: &[u8],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.get_mut().inner).poll_write(context, buffer)
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _context: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                context: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
            }

            fn is_write_vectored(&self) -> bool {
                self.inner.is_write_vectored()
            }

            fn poll_write_vectored(
                self: Pin<&mut Self>,
                context: &mut Context<'_>,
                buffers: &[io::IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.get_mut().inner).poll_write_vectored(context, buffers)
            }
        }

        let request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_11)
            .uri("/socket")
            .header(HOST, "origin.example")
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, "test-echo")
            .header(CONTENT_LENGTH, "4")
            .body(Body::from("body"))
            .unwrap();
        let request = crate::proxy::headers::sanitize_untrusted_request(request).unwrap();
        let intent = request.upgrade_intent().unwrap().clone();
        let canonical = canonicalize_http_url("http://origin.example/socket").unwrap();
        let request = prepare_origin_upgrade_request(
            request,
            &canonical,
            RequestTargetForm::Origin,
            OriginProtocol::Http1,
        )
        .unwrap();
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let head = read_http_head(&mut server).await.to_ascii_lowercase();
            assert!(head.contains("\r\ncontent-length: 4\r\n"));
            let mut body = [0_u8; 4];
            server.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"body");
            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n",
                )
                .await
                .unwrap();
            let mut tail = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), server.read_to_end(&mut tail))
                .await
                .expect("the unflushed upgrade did not close the origin connection")
                .unwrap();
        });

        let error = expect_forward_error(
            send_upgrade_request(
                FlushPendingIo { inner: client },
                request,
                intent,
                ForwardingTimeouts::for_test().begin_connect(),
                None,
            )
            .await,
            "a 101 received before request flush must fail",
        );
        assert!(matches!(error, ForwardError::UpgradeRequestBodyIncomplete));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejected_upgrade_remains_an_owned_ordinary_response() {
        let canonical = canonicalize_http_url("http://origin.example/socket").unwrap();
        let egress = activate(None);
        let request = upgrade_request();
        let (guard, _) = guard();
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();
        let server = tokio::spawn(async move {
            let _ = read_http_head(&mut server).await;
            server
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nConnection: x-private\r\nx-private: remove-me\r\n\r\ndenied",
                )
                .await
                .unwrap();
        });

        let result = forward_upgrade_with_connector(
            request, &canonical, &egress, &guard, target, &connector,
        )
        .await
        .unwrap();
        let ForwardUpgradeResult::Response(response) = result else {
            panic!("a non-101 response must remain an ordinary response");
        };
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!response.headers().contains_key(CONNECTION));
        assert!(!response.headers().contains_key("x-private"));
        let body = hyper::body::to_bytes((*response).into_body())
            .await
            .unwrap();
        assert_eq!(body, "denied");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_switching_protocols_response_aborts_the_driver() {
        let canonical = canonicalize_http_url("http://origin.example/socket").unwrap();
        let egress = activate(None);
        let request = upgrade_request();
        let (guard, _) = guard();
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();
        let server = tokio::spawn(async move {
            let _ = read_http_head(&mut server).await;
            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
                )
                .await
                .unwrap();
            let mut byte = [0_u8; 1];
            assert_eq!(server.read(&mut byte).await.unwrap(), 0);
        });

        let error = expect_forward_error(
            forward_upgrade_with_connector(
                request, &canonical, &egress, &guard, target, &connector,
            )
            .await,
            "mismatched 101 protocol must fail",
        );
        assert!(matches!(
            error,
            ForwardError::Header(HeaderPreparationError::InvalidUpgrade)
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn upgrade_early_101_and_shutdown_restore_body_budget() {
        struct PrefixThenPendingBody {
            prefix: Option<Bytes>,
            _charged_body: GuardedBody,
        }

        impl HttpBody for PrefixThenPendingBody {
            type Data = Bytes;
            type Error = std::convert::Infallible;

            fn poll_data(
                self: Pin<&mut Self>,
                _context: &mut Context<'_>,
            ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
                match self.get_mut().prefix.take() {
                    Some(prefix) => Poll::Ready(Some(Ok(prefix))),
                    None => Poll::Pending,
                }
            }

            fn poll_trailers(
                self: Pin<&mut Self>,
                _context: &mut Context<'_>,
            ) -> Poll<Result<Option<http::HeaderMap>, Self::Error>> {
                Poll::Ready(Ok(None))
            }

            fn size_hint(&self) -> SizeHint {
                let mut hint = SizeHint::new();
                hint.set_exact(64 * 1024);
                hint
            }
        }

        let pool = WireBodyPool::new(1024 * 1024, 1024 * 1024);
        let guard = pool.begin_for_test(
            1024 * 1024,
            WireBodyQuotaKey::from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), |_| false),
        );
        let mut charged_body = guard.buffer();
        charged_body
            .try_extend_from_slice(b"budget-owned-upgrade-body")
            .unwrap();
        let charged_body = charged_body.finish();
        let charged_bytes = charged_body.charged_bytes();
        assert!(charged_bytes > 0);
        assert_eq!(pool.global_charge(), charged_bytes);

        let request = Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_11)
            .uri("/socket")
            .header(HOST, "origin.example")
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, "WebSocket")
            .body(PrefixThenPendingBody {
                prefix: Some(Bytes::from(
                    [b"body-prefix".as_slice(), &vec![b'x'; 32 * 1024]].concat(),
                )),
                _charged_body: charged_body,
            })
            .unwrap();
        let sanitized = crate::proxy::headers::sanitize_untrusted_request(request).unwrap();
        let intent = sanitized.upgrade_intent().unwrap().clone();
        let canonical = canonicalize_http_url("http://origin.example/socket").unwrap();
        let request = prepare_origin_upgrade_request(
            sanitized,
            &canonical,
            RequestTargetForm::Origin,
            OriginProtocol::Http1,
        )
        .unwrap();
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let _ = read_http_head(&mut server).await;
            let mut request_body = Vec::new();
            while !request_body
                .windows(b"body-prefix".len())
                .any(|window| window == b"body-prefix")
            {
                let mut buffer = [0_u8; 128];
                let read = server.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0, "request closed before writing the body prefix");
                request_body.extend_from_slice(&buffer[..read]);
                assert!(request_body.len() < 8 * 1024);
            }
            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: WebSocket\r\n\r\n",
                )
                .await
                .unwrap();
            let mut tail = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), server.read_to_end(&mut tail))
                .await
                .expect("the rejected upgrade did not close the origin connection")
                .unwrap();
        });

        let error = expect_forward_error(
            send_upgrade_request(
                client,
                request,
                intent,
                ForwardingTimeouts::for_test().begin_connect(),
                None,
            )
            .await,
            "an early 101 cannot establish an upgrade",
        );
        assert!(matches!(error, ForwardError::UpgradeRequestBodyIncomplete));
        server.await.unwrap();
        assert_eq!(guard.live_bytes(), 0);
        assert_eq!(pool.global_charge(), 0);
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
    async fn response_body_slices_wire_frames_without_copying_or_recounting() {
        let driver = tokio::spawn(async { Ok(()) });
        let mut body = ForwardBody::new(
            Body::from(Bytes::from_static(b"abcdef")),
            DriverTask::from_handle(driver),
        )
        .with_response_policy(response_policy(6, 2, 4, 128, 1_000));

        assert_eq!(body.data().await.unwrap().unwrap(), "ab");
        assert_eq!(body.data().await.unwrap().unwrap(), "cd");
        assert_eq!(body.data().await.unwrap().unwrap(), "ef");
        assert!(body.data().await.is_none());
        assert_eq!(body.observed_wire_bytes, 6);
    }

    #[tokio::test]
    async fn buffered_response_slice_precedes_idle_timeout_without_resetting_it() {
        let (mut sender, upstream_body) = Body::channel();
        sender.send_data(Bytes::from_static(b"abcd")).await.unwrap();
        let driver =
            tokio::spawn(async { std::future::pending::<Result<(), hyper::Error>>().await });
        let mut body = ForwardBody::new(upstream_body, DriverTask::from_handle(driver))
            .with_response_policy(response_policy(8, 2, 4, 128, 20));

        assert_eq!(body.data().await.unwrap().unwrap(), "ab");
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(body.data().await.unwrap().unwrap(), "cd");
        let error = body.data().await.unwrap().unwrap_err();
        assert!(matches!(error, ForwardBodyError::Timeout));
        drop(sender);
    }

    #[tokio::test]
    async fn response_body_rejects_wire_bytes_above_the_checked_limit() {
        let driver = tokio::spawn(async { Ok(()) });
        let mut body = ForwardBody::new(
            Body::from(Bytes::from_static(b"abcdef")),
            DriverTask::from_handle(driver),
        )
        .with_response_policy(response_policy(5, 5, 4, 128, 1_000));

        let error = body.data().await.unwrap().unwrap_err();
        assert!(matches!(error, ForwardBodyError::Limit));
    }

    #[tokio::test]
    async fn response_body_idle_timeout_does_not_require_origin_eof() {
        let driver =
            tokio::spawn(async { std::future::pending::<Result<(), hyper::Error>>().await });
        let (_sender, pending_body) = Body::channel();
        let mut body = ForwardBody::new(pending_body, DriverTask::from_handle(driver))
            .with_response_policy(response_policy(8, 4, 4, 128, 20));

        let error = body.data().await.unwrap().unwrap_err();
        assert!(matches!(error, ForwardBodyError::Timeout));
    }

    #[tokio::test]
    async fn response_trailers_are_bounded_before_hop_header_cleanup() {
        let (mut sender, upstream_body) = Body::channel();
        tokio::spawn(async move {
            let mut trailers = http::HeaderMap::new();
            trailers.append("x-one", HeaderValue::from_static("a"));
            trailers.append("x-one", HeaderValue::from_static("b"));
            sender.send_trailers(trailers).await.unwrap();
        });
        let driver = tokio::spawn(async { Ok(()) });
        let mut body = ForwardBody::new(upstream_body, DriverTask::from_handle(driver))
            .with_response_policy(response_policy(8, 4, 1, 128, 1_000));

        let error = body.data().await.unwrap().unwrap_err();
        assert!(matches!(error, ForwardBodyError::Limit));
    }

    #[tokio::test]
    async fn response_body_caps_empty_frames_with_cooperative_polling() {
        let frames = tokio_stream::iter(
            (0..=MAX_EMPTY_RESPONSE_FRAMES).map(|_| Ok::<Bytes, io::Error>(Bytes::new())),
        );
        let driver = tokio::spawn(async { Ok(()) });
        let mut body = ForwardBody::new(Body::wrap_stream(frames), DriverTask::from_handle(driver))
            .with_response_policy(response_policy(8, 4, 4, 128, 600_000));

        let error = body.data().await.unwrap().unwrap_err();
        assert!(matches!(error, ForwardBodyError::Limit));
    }

    #[tokio::test]
    async fn connect_stage_reports_its_own_timeout() {
        let deadlines = ForwardingTimeouts::new(
            Instant::now() + Duration::from_secs(1),
            Duration::from_millis(1),
            Duration::from_secs(1),
        )
        .begin_connect();
        let error = expect_forward_error(
            connect_stage(
                deadlines,
                std::future::pending::<Result<(), ForwardError>>(),
            )
            .await,
            "connection failure must reject forwarding",
        );

        assert!(matches!(error, ForwardError::ConnectTimeout));
    }

    #[tokio::test]
    async fn preconnect_work_does_not_age_the_connect_timeout() {
        let timeouts = ForwardingTimeouts::new(
            Instant::now() + Duration::from_secs(1),
            Duration::from_millis(20),
            Duration::from_secs(1),
        );
        tokio::time::sleep(Duration::from_millis(30)).await;

        connect_stage(
            timeouts.begin_connect(),
            std::future::ready(Ok::<_, ForwardError>(())),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn response_head_timeout_aborts_the_started_connection_driver() {
        let (client, mut server) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let head = read_http_head(&mut server).await;
            assert!(head.starts_with("GET /wait HTTP/1.1\r\n"));
            let mut byte = [0_u8; 1];
            assert_eq!(server.read(&mut byte).await.unwrap(), 0);
        });
        let request = Request::builder()
            .method(Method::GET)
            .uri("/wait")
            .header(HOST, "origin.example")
            .body(Body::empty())
            .unwrap();
        let deadlines = ForwardingTimeouts::new(
            Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_millis(20),
        )
        .begin_connect();

        let error =
            match send_request(client, request, OriginProtocol::Http1, deadlines, None).await {
                Ok(_) => panic!("a missing upstream response head must time out"),
                Err(error) => error,
            };
        assert!(matches!(error, ForwardError::ResponseHeadTimeout));
        server.await.unwrap();
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
    async fn absolute_request_deadline_aborts_pending_response_and_driver() {
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let signal = DropSignal(Some(dropped_tx));
        let driver = tokio::spawn(async move {
            let _signal = signal;
            std::future::pending::<Result<(), hyper::Error>>().await
        });
        let (_sender, pending_body) = Body::channel();
        let mut body = ForwardBody::new(pending_body, DriverTask::from_handle(driver))
            .with_request_deadline(Instant::now() + Duration::from_millis(20));

        let error = body.data().await.unwrap().unwrap_err();
        assert!(matches!(error, ForwardBodyError::Timeout));
        dropped_rx.await.unwrap();
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
            .with_response_policy(response_policy(8, 4, 4, 128, 20));
        body.data_done = true;

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
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();

        let response =
            forward_with_connector(request, &canonical, &egress, &guard, target, &connector)
                .await
                .unwrap();
        finish_response(response).await;
        let (uri, headers, body) = captured_rx.await.unwrap();
        assert_eq!(uri, canonical.as_str());
        assert!(!headers.contains_key(HOST));
        assert_eq!(headers["authorization"], "Bearer origin-secret");
        assert_eq!(body, b"request-body");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn h2_credentials_finalize_after_handshake_and_send_once() {
        const VARIABLE: &str = "ACL_PROXY_H2_LATE_TOKEN";
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        std::env::set_var(VARIABLE, "h2-secret");
        let canonical = canonicalize_http_url("http://origin.example:8080/h2-credential").unwrap();
        let egress = activate_with_versions(None, vec![CompiledHttpVersion::Http2]);
        let mut request = request_with_version(Version::HTTP_2);
        let wire_guard = credential_guard();
        let (mut credentials, io) = crate::credential_resolver::environment_execution_for_test(
            &wire_guard,
            VARIABLE,
            "x-late-token",
        );
        credentials
            .reserve_transport(request.headers_mut())
            .unwrap();
        let (guard, _) = guard();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let (captured_tx, captured_rx) = oneshot::channel();
        let server = tokio::spawn(serve_h2(server, captured_tx));
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();

        let response = forward_with_connector_timed(
            request,
            &canonical,
            &egress,
            &guard,
            target,
            &connector,
            ForwardExecutionOptions::new(ForwardingTimeouts::for_test(), Some(credentials)),
        )
        .await
        .unwrap();
        finish_response(response).await;
        let (_, headers, _) = captured_rx.await.unwrap();
        assert_eq!(headers.get_all("x-late-token").iter().count(), 1);
        assert_eq!(headers["x-late-token"], "h2-secret");
        server.await.unwrap();
        io.shutdown_and_wait(None).await;
        std::env::remove_var(VARIABLE);
    }

    #[tokio::test]
    async fn h2_missing_credential_fails_after_handshake_without_request_stream() {
        const VARIABLE: &str = "ACL_PROXY_H2_MISSING_TOKEN";
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        std::env::remove_var(VARIABLE);
        let canonical = canonicalize_http_url("http://origin.example:8080/h2-missing").unwrap();
        let egress = activate_with_versions(None, vec![CompiledHttpVersion::Http2]);
        let mut request = request_with_version(Version::HTTP_2);
        let wire_guard = credential_guard();
        let (mut credentials, io) = crate::credential_resolver::environment_execution_for_test(
            &wire_guard,
            VARIABLE,
            "x-late-token",
        );
        credentials
            .reserve_transport(request.headers_mut())
            .unwrap();
        let (guard, _) = guard();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let (captured_tx, captured_rx) = oneshot::channel();
        let server = tokio::spawn(serve_h2(server, captured_tx));
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();

        let error = expect_forward_error(
            forward_with_connector_timed(
                request,
                &canonical,
                &egress,
                &guard,
                target,
                &connector,
                ForwardExecutionOptions::new(ForwardingTimeouts::for_test(), Some(credentials)),
            )
            .await,
            "missing H2 credential must reject forwarding",
        );
        assert!(matches!(
            error,
            ForwardError::Credential(credential_core::CredentialError::ServiceUnavailable)
        ));
        assert!(captured_rx.await.is_err());
        server.await.unwrap();
        io.shutdown_and_wait(None).await;
    }

    #[test]
    fn preflight_binding_rejects_foreign_request_protocol_and_egress_before_resolution() {
        let canonical = canonicalize_http_url("http://origin.example:8080/resource").unwrap();
        let foreign_canonical =
            canonicalize_http_url("http://foreign.example:8080/resource").unwrap();
        let egress = activate(None);
        let foreign_egress = activate(None);
        let (guard, resolver) = guard();
        let request = request();

        let foreign_request =
            preflight_forwarding_target(&canonical, &request, &egress, &guard).unwrap();
        assert!(matches!(
            foreign_request.bind_for_request(
                &foreign_canonical,
                request.protocol(),
                &egress,
                &guard,
            ),
            Err(ResolveForwardingError::Binding)
        ));

        let foreign_protocol =
            preflight_forwarding_target(&canonical, &request, &egress, &guard).unwrap();
        assert!(matches!(
            foreign_protocol.bind_for_request(&canonical, OriginProtocol::Http2, &egress, &guard,),
            Err(ResolveForwardingError::Binding)
        ));

        let foreign_snapshot =
            preflight_forwarding_target(&canonical, &request, &egress, &guard).unwrap();
        assert!(matches!(
            foreign_snapshot.bind_for_request(
                &canonical,
                request.protocol(),
                &foreign_egress,
                &guard,
            ),
            Err(ResolveForwardingError::Binding)
        ));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
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
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
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
        let target = prepare_and_resolve_target(&canonical, &request, &original, &guard)
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
        let target = prepare_and_resolve_target(&canonical, &resolved_for_h2, &egress, &guard)
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
        let mut target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
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
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
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
    async fn direct_route_preflight_is_synchronous_and_resolution_runs_exactly_once() {
        let canonical =
            canonicalize_http_url("http://origin.example:8080/canonical?q=%7e").unwrap();
        let egress = activate(None);
        let (guard, resolver) = guard();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let (captured_tx, captured_rx) = oneshot::channel();
        let server = tokio::spawn(serve_h1(server, captured_tx));

        let request = request();
        let prepared = preflight_forwarding_target(&canonical, &request, &egress, &guard)
            .expect("semantic preflight");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);

        let prepared = prepared
            .bind_for_request(&canonical, request.protocol(), &egress, &guard)
            .unwrap();
        let target = resolve_forwarding_target(prepared, &guard).await.unwrap();
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
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();

        let response =
            forward_with_connector(request, &canonical, &egress, &guard, target, &connector)
                .await
                .unwrap();
        finish_response(response).await;
        let (uri, headers, _) = captured_rx.await.unwrap();
        assert_eq!(uri, canonical.as_str());
        assert_eq!(headers[HOST], canonical.authority().as_str());
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
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();

        let response =
            forward_with_connector(request, &canonical, &egress, &guard, target, &connector)
                .await
                .unwrap();
        finish_response(response).await;
        let (uri, headers, _) = captured_rx.await.unwrap();
        assert_eq!(uri, canonical.as_str());
        assert_eq!(headers[HOST], canonical.authority().as_str());
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
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();

        assert!(matches!(
            forward_with_connector(request, &canonical, &egress, &guard, target, &connector).await,
            Err(ForwardError::ParentProtocol(ParentAlpnError::Incompatible))
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connect_failure_precedes_environment_credential_resolution() {
        const VARIABLE: &str = "ACL_PROXY_FORWARD_CONNECT_FAILURE_TOKEN";
        std::env::remove_var(VARIABLE);
        let canonical = canonicalize_http_url("http://origin.example/fail").unwrap();
        let egress = activate(None);
        let mut request = request();
        let (destinations, _) = guard();
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &destinations)
            .await
            .unwrap();
        let wire_guard = credential_guard();
        let (mut credentials, io) = crate::credential_resolver::environment_execution_for_test(
            &wire_guard,
            VARIABLE,
            "x-late-token",
        );
        credentials
            .reserve_transport(request.headers_mut())
            .unwrap();
        let connector = FailingConnector {
            calls: AtomicUsize::new(0),
        };

        let error = expect_forward_error(
            forward_with_connector_timed(
                request,
                &canonical,
                &egress,
                &destinations,
                target,
                &connector,
                ForwardExecutionOptions::new(ForwardingTimeouts::for_test(), Some(credentials)),
            )
            .await,
            "missing credential source must reject forwarding",
        );

        assert!(matches!(error, ForwardError::Destination(_)));
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        io.shutdown_and_wait(None).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn credential_rotation_and_disappearance_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        let mut prepared = Vec::new();
        for _ in 0..3 {
            let wire_guard = credential_guard();
            let execution = crate::credential_resolver::file_execution_for_test(
                &wire_guard,
                path.clone(),
                "x-late-token",
            );
            prepared.push((wire_guard, execution));
        }

        for expected in ["old-secret", "new-secret"] {
            let replacement = directory.path().join(format!("replacement-{expected}"));
            fs::write(&replacement, expected).unwrap();
            fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
            fs::rename(&replacement, &path).unwrap();
            let (_wire_guard, (mut credentials, io)) = prepared.remove(0);
            let canonical = canonicalize_http_url("http://origin.example/rotated").unwrap();
            let egress = activate(None);
            let mut request = request();
            credentials
                .reserve_transport(request.headers_mut())
                .unwrap();
            let (destinations, _) = guard();
            let target = prepare_and_resolve_target(&canonical, &request, &egress, &destinations)
                .await
                .unwrap();
            let (client, mut server) = tokio::io::duplex(64 * 1024);
            let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
            let expected = expected.to_owned();
            let server = tokio::spawn(async move {
                let head = read_http_head(&mut server).await.to_ascii_lowercase();
                let field = format!("\r\nx-late-token: {expected}\r\n");
                assert_eq!(head.matches(&field).count(), 1, "{head}");
                server
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            });

            let response = forward_with_connector_timed(
                request,
                &canonical,
                &egress,
                &destinations,
                target,
                &connector,
                ForwardExecutionOptions::new(ForwardingTimeouts::for_test(), Some(credentials)),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let mut body = response.into_body();
            assert!(body.data().await.is_none());
            server.await.unwrap();
            io.shutdown_and_wait(None).await;
        }

        fs::remove_file(&path).unwrap();
        let (_wire_guard, (mut credentials, io)) = prepared.remove(0);
        let canonical = canonicalize_http_url("http://origin.example/missing").unwrap();
        let egress = activate(None);
        let mut request = request();
        credentials
            .reserve_transport(request.headers_mut())
            .unwrap();
        let (destinations, _) = guard();
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &destinations)
            .await
            .unwrap();
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let server = tokio::spawn(async move {
            let mut bytes = Vec::new();
            server.read_to_end(&mut bytes).await.unwrap();
            assert!(bytes.is_empty(), "credential failure emitted request bytes");
        });

        let error = expect_forward_error(
            forward_with_connector_timed(
                request,
                &canonical,
                &egress,
                &destinations,
                target,
                &connector,
                ForwardExecutionOptions::new(ForwardingTimeouts::for_test(), Some(credentials)),
            )
            .await,
            "missing credential source must reject forwarding",
        );
        assert!(matches!(
            error,
            ForwardError::Credential(credential_core::CredentialError::ServiceUnavailable)
        ));
        server.await.unwrap();
        io.shutdown_and_wait(None).await;
    }

    #[tokio::test]
    async fn parent_connect_carries_no_origin_credentials() {
        const VARIABLE: &str = "ACL_PROXY_PARENT_TUNNEL_TOKEN";
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        std::env::set_var(VARIABLE, "late-parent-secret");
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
        let mut request = request();
        let wire_guard = credential_guard();
        let (mut credentials, io) = crate::credential_resolver::environment_execution_for_test(
            &wire_guard,
            VARIABLE,
            "x-late-token",
        );
        credentials
            .reserve_transport(request.headers_mut())
            .unwrap();
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();

        let response = forward_with_connector_timed(
            request,
            &canonical,
            &egress,
            &guard,
            target,
            &connector,
            ForwardExecutionOptions::new(ForwardingTimeouts::for_test(), Some(credentials)),
        )
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
            "x-late-token",
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
        assert_eq!(headers["x-late-token"], "late-parent-secret");
        assert_eq!(body, b"request-body");
        server.await.unwrap();
        io.shutdown_and_wait(None).await;
        std::env::remove_var(VARIABLE);
    }

    #[tokio::test]
    async fn parent_connect_rejection_precedes_environment_credential_resolution() {
        const VARIABLE: &str = "ACL_PROXY_PARENT_REJECTION_TOKEN";
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        std::env::remove_var(VARIABLE);
        let canonical = canonicalize_http_url("https://origin.example/rejected").unwrap();
        let egress = activate(Some(("http://parent.example:8443/", false)));
        let (guard, _) = guard();
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let connector = FakeConnector::new(CANDIDATE.parse().unwrap(), client);
        let server = tokio::spawn(async move {
            let head = read_http_head(&mut server).await.to_ascii_lowercase();
            assert!(!head.contains("x-late-token"), "{head}");
            server
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let mut request = request();
        let wire_guard = credential_guard();
        let (mut credentials, io) = crate::credential_resolver::environment_execution_for_test(
            &wire_guard,
            VARIABLE,
            "x-late-token",
        );
        credentials
            .reserve_transport(request.headers_mut())
            .unwrap();
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
            .await
            .unwrap();

        let error = expect_forward_error(
            forward_with_connector_timed(
                request,
                &canonical,
                &egress,
                &guard,
                target,
                &connector,
                ForwardExecutionOptions::new(ForwardingTimeouts::for_test(), Some(credentials)),
            )
            .await,
            "parent rejection must fail forwarding",
        );
        assert!(matches!(
            error,
            ForwardError::ParentConnect(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        ));
        server.await.unwrap();
        io.shutdown_and_wait(None).await;
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
        let target = prepare_and_resolve_target(&canonical, &request, &egress, &guard)
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
