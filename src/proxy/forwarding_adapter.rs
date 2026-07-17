use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use http::header::{CONTENT_ENCODING, TRAILER};
use http::{HeaderMap, HeaderValue, Response, StatusCode, Version};
use http_access_runtime::{
    BoxFuture, ForwardingAdmission, ForwardingError, ForwardingObservation, ForwardingOutcome,
    ForwardingRequestHead, ForwardingResources, ForwardingResponseHead, ForwardingRetention,
    ForwardingTerminal, ForwardingTerminalOutcome, ForwardingTerminalOwner, PreparedUpgradeHandoff,
    RuntimeError, UpgradeHandoff, UpgradeOffer, UpstreamUpgradeBounds,
};
use http_access_types::{HeaderField, UpgradePolicy, UpgradeProtocol};
use hyper::Body;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::capture::CaptureDecision;
use crate::http1::ingress::RequestDisposition;
use crate::observation::CaptureEvent;
use crate::proxy::h2_stream_cancellation::H2StreamCancellation;
use crate::proxy::ingress::{
    CaptureSubmission, HandledResponse, HttpCaptureContext, ProxyResponseBody,
    StandaloneHttpTerminal, TerminalRequestBodyProvenance,
};
use crate::proxy::upgrade_relay::{
    EstablishedUpgradeKind, UpgradeCaptureContext, UpgradeRelayDeadlines,
};
use crate::standalone_policy_provider::{
    ProductForwardingCancellation, StandaloneForwardDispatch, StandaloneIngressTransport,
};
use crate::standalone_provider_result::{StandaloneCaptureBody, StandaloneUpgradeBinding};
use crate::upgrade::{
    UpgradeEntryPlan, UpgradeRuntime, UpgradeTerminalCause, UpgradeTerminalControl,
};

pub(super) struct ProductObservationState {
    capture: HttpCaptureContext,
    request_provenance: TerminalRequestBodyProvenance,
    canonical_identity: bool,
    request_headers: Option<HeaderMap>,
    request: Option<CaptureSubmission>,
    response: Option<CaptureSubmission>,
}

impl ProductObservationState {
    fn new(
        capture: HttpCaptureContext,
        request_provenance: TerminalRequestBodyProvenance,
        canonical_identity: bool,
    ) -> Self {
        Self {
            capture,
            request_provenance,
            canonical_identity,
            request_headers: None,
            request: None,
            response: None,
        }
    }

    fn finish_request(&mut self) {
        if let Some(mut request) = self.request.take() {
            request.finish();
        }
    }

    fn finish_response(&mut self) {
        if let Some(mut response) = self.response.take() {
            response.finish();
        }
    }

    fn abandon(&mut self) {
        if let Some(mut request) = self.request.take() {
            request.abandon();
        }
        if let Some(mut response) = self.response.take() {
            response.abandon();
        }
    }
}

fn lock_observation(
    state: &Arc<Mutex<ProductObservationState>>,
) -> std::sync::MutexGuard<'_, ProductObservationState> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(super) fn finish_response_observation(state: &Arc<Mutex<ProductObservationState>>) {
    lock_observation(state).finish_response();
}

pub(super) fn abandon_observation(state: &Arc<Mutex<ProductObservationState>>) {
    lock_observation(state).abandon();
}

struct ProductForwardingObservation {
    state: Arc<Mutex<ProductObservationState>>,
}

impl ForwardingObservation for ProductForwardingObservation {
    fn request_head(&mut self, head: &ForwardingRequestHead) -> Result<(), RuntimeError> {
        let headers = crate::proxy::facts::product_headers(head.headers())
            .map_err(|_| RuntimeError::InvalidInput)?;
        let mut body_headers = body_headers(&headers);
        let mut state = lock_observation(&self.state);
        if state.canonical_identity {
            body_headers.insert(CONTENT_ENCODING, HeaderValue::from_static("identity"));
        }
        state.request_headers = Some(headers.clone());
        state.request =
            state
                .capture
                .begin_allowed_request(&headers, &body_headers, state.request_provenance);
        Ok(())
    }

    fn request_body(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if let Some(request) = lock_observation(&self.state).request.as_mut() {
            request.push(bytes);
        }
        Ok(())
    }

    fn request_trailers(&mut self, _trailers: &[HeaderField]) -> Result<(), RuntimeError> {
        Ok(())
    }

    fn request_complete(&mut self) -> Result<(), RuntimeError> {
        lock_observation(&self.state).finish_request();
        Ok(())
    }

    fn response_head(&mut self, head: &ForwardingResponseHead) -> Result<(), RuntimeError> {
        let version = product_version(head.version());
        let status = StatusCode::from_u16(head.status()).map_err(|_| RuntimeError::InvalidInput)?;
        let headers = crate::proxy::facts::product_headers(head.headers())
            .map_err(|_| RuntimeError::InvalidInput)?;
        let mut state = lock_observation(&self.state);
        state.response = state.capture.begin(
            CaptureEvent::ResponseAllowed,
            || {
                state.capture.response_record(
                    CaptureDecision::Allow,
                    version,
                    Some(&headers),
                    status,
                    false,
                )
            },
            &headers,
        );
        Ok(())
    }

    fn response_body(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if let Some(response) = lock_observation(&self.state).response.as_mut() {
            response.push(bytes);
        }
        Ok(())
    }

    fn response_trailers(&mut self, _trailers: &[HeaderField]) -> Result<(), RuntimeError> {
        Ok(())
    }
}

struct ProductForwardingTerminal {
    cancellation: Option<ProductForwardingCancellation>,
    observation: Arc<Mutex<ProductObservationState>>,
}

impl ForwardingTerminal for ProductForwardingTerminal {
    fn finish(
        &mut self,
        outcome: ForwardingTerminalOutcome,
    ) -> BoxFuture<'static, Result<(), RuntimeError>> {
        if !matches!(outcome, ForwardingTerminalOutcome::Completed) {
            abandon_observation(&self.observation);
        }
        let cancellation = self.cancellation.take();
        Box::pin(async move {
            drop(cancellation);
            Ok(())
        })
    }

    fn abandon(&mut self) {
        abandon_observation(&self.observation);
        self.cancellation.take();
    }
}

pub(super) async fn execute(
    terminal: StandaloneHttpTerminal,
    mut dispatch: StandaloneForwardDispatch,
) -> HandledResponse {
    let StandaloneIngressTransport::Ordinary {
        mut parts,
        head: _,
        downstream_upgrade,
    } = dispatch.transport
    else {
        return terminal.capture.fixed_response(
            CaptureDecision::Allow,
            StatusCode::INTERNAL_SERVER_ERROR,
            "request failed\n",
            true,
        );
    };
    let h2_stream = parts.extensions.remove::<H2StreamCancellation>();
    let plan = dispatch.exchange.plan_arc();
    let upgrade_policy = plan.upgrade().clone();
    let upgrade_binding = match dispatch.sidecar.take_upgrade_binding(plan.binding()) {
        Ok(binding) => binding,
        Err(_) => return internal_failure(&terminal.capture),
    };
    let capture_body = dispatch.sidecar.capture_body();
    let canonical_identity = matches!(
        capture_body,
        StandaloneCaptureBody::Stream {
            canonical_identity: true
        }
    );
    let provenance = match capture_body {
        StandaloneCaptureBody::ProviderReplacement { size } => {
            TerminalRequestBodyProvenance::ProviderReplacement { size }
        }
        StandaloneCaptureBody::Stream { .. } if plan.redaction().is_some() => {
            TerminalRequestBodyProvenance::CompleteWireRedacted
        }
        StandaloneCaptureBody::Stream { .. } => TerminalRequestBodyProvenance::CompleteOriginal,
    };
    let observation = Arc::new(Mutex::new(ProductObservationState::new(
        terminal.capture.clone(),
        provenance,
        canonical_identity,
    )));
    let response_admission = match dispatch.services.begin_response(dispatch.quota_key) {
        Ok(admission) => admission,
        Err(_) => {
            return terminal.capture.fixed_response(
                CaptureDecision::Allow,
                StatusCode::SERVICE_UNAVAILABLE,
                "service unavailable\n",
                true,
            );
        }
    };
    let credentials = match dispatch.credentials {
        Some(preparation) => match preparation.admit_for_plan(&plan) {
            Ok(credentials) => Some(credentials),
            Err(_) => {
                return terminal.capture.fixed_response(
                    CaptureDecision::Allow,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service unavailable\n",
                    true,
                );
            }
        },
        None => None,
    };
    let loop_marker = match dispatch.services.loop_marker(&plan, &dispatch.request_id) {
        Ok(marker) => marker,
        Err(_) => return internal_failure(&terminal.capture),
    };
    let cancellation = dispatch.cancellation.capability();
    let terminal_owner = ForwardingTerminalOwner::new(ProductForwardingTerminal {
        cancellation: Some(dispatch.cancellation),
        observation: Arc::clone(&observation),
    });
    let admission = ForwardingAdmission::new(&plan, response_admission);
    let retention = ForwardingRetention::new(&plan, (dispatch.retention, dispatch.sidecar));
    let mut resources =
        ForwardingResources::new(admission, retention, cancellation, terminal_owner)
            .with_observation(ProductForwardingObservation {
                state: Arc::clone(&observation),
            });
    if let Some(marker) = loop_marker {
        resources = resources.with_loop_marker(marker);
    }
    if let Some(credentials) = credentials {
        resources = resources.with_credentials(credentials);
    }
    match (&upgrade_policy, upgrade_binding, downstream_upgrade) {
        (UpgradePolicy::Deny, None, None) => {}
        (UpgradePolicy::Deny, _, _) => return internal_failure(&terminal.capture),
        (policy, Some(binding), Some(downstream_upgrade)) => {
            let protocol = upgrade_protocol(policy);
            let relay_buffer_bytes = terminal.upgrade_runtime.limits().relay_buffer_bytes();
            let bounds = match UpstreamUpgradeBounds::new(
                relay_buffer_bytes as u64,
                relay_buffer_bytes as u64,
            ) {
                Ok(bounds) => bounds,
                Err(_) => return internal_failure(&terminal.capture),
            };
            let handoff = ProductUpgradeHandoff {
                runtime: terminal.upgrade_runtime.clone(),
                binding,
                downstream_upgrade,
                deadline: dispatch.deadline,
                deadlines: UpgradeRelayDeadlines::new(
                    Duration::from_millis(plan.timeouts().upgrade_idle_ms()),
                    dispatch.deadline,
                ),
                protocol,
                observation: Arc::clone(&observation),
                capture: terminal.capture.upgrade_capture_context(plan.origin()),
            };
            resources = resources.with_upgrade_handoff(handoff, bounds);
        }
        _ => return internal_failure(&terminal.capture),
    }

    dispatch.decision.submit_now();
    let executor = dispatch.services.executor().clone();
    match executor
        .execute(dispatch.exchange, dispatch.resolved, resources)
        .await
    {
        Ok(ForwardingOutcome::Response(response)) => {
            let (head, body) = response.into_parts();
            let response = match product_response(
                &head,
                ProxyResponseBody::forwarded(body, Arc::clone(&observation), h2_stream),
            ) {
                Ok(response) => response,
                Err(_) => return internal_failure(&terminal.capture),
            };
            HandledResponse {
                response,
                close_connection: false,
                request_disposition: RequestDisposition::ContinueHttp,
            }
        }
        Ok(ForwardingOutcome::Upgrade(head)) => {
            finish_response_observation(&observation);
            let response = match product_response(&head, ProxyResponseBody::Local(Body::empty())) {
                Ok(response) => response,
                Err(_) => return internal_failure(&terminal.capture),
            };
            HandledResponse {
                response,
                close_connection: false,
                request_disposition: RequestDisposition::SwitchProtocol,
            }
        }
        Err(ForwardingError::Timeout) => terminal.capture.fixed_response(
            CaptureDecision::Allow,
            StatusCode::GATEWAY_TIMEOUT,
            "request timed out\n",
            true,
        ),
        Err(ForwardingError::Cancelled) => terminal.capture.fixed_response(
            CaptureDecision::Allow,
            StatusCode::SERVICE_UNAVAILABLE,
            "service unavailable\n",
            true,
        ),
        Err(error) => {
            tracing::error!(error = ?error, "upstream request failed");
            terminal.capture.fixed_response(
                CaptureDecision::Allow,
                StatusCode::BAD_GATEWAY,
                "upstream failed\n",
                true,
            )
        }
    }
}

fn internal_failure(capture: &HttpCaptureContext) -> HandledResponse {
    capture.fixed_response(
        CaptureDecision::Allow,
        StatusCode::INTERNAL_SERVER_ERROR,
        "request failed\n",
        true,
    )
}

fn body_headers(headers: &HeaderMap) -> HeaderMap {
    let mut selected = HeaderMap::new();
    for name in [CONTENT_ENCODING, TRAILER] {
        for value in headers.get_all(&name).iter() {
            selected.append(name.clone(), value.clone());
        }
    }
    selected
}

fn product_version(version: http_access_types::HttpVersion) -> Version {
    match version {
        http_access_types::HttpVersion::Http10 => Version::HTTP_10,
        http_access_types::HttpVersion::Http11 => Version::HTTP_11,
        http_access_types::HttpVersion::Http2 => Version::HTTP_2,
    }
}

fn product_response(
    head: &ForwardingResponseHead,
    body: ProxyResponseBody,
) -> Result<Response<ProxyResponseBody>, ()> {
    let status = StatusCode::from_u16(head.status()).map_err(|_| ())?;
    let headers = crate::proxy::facts::product_headers(head.headers()).map_err(|_| ())?;
    let mut response = Response::builder()
        .version(product_version(head.version()))
        .status(status)
        .body(body)
        .map_err(|_| ())?;
    *response.headers_mut() = headers;
    Ok(response)
}

fn upgrade_protocol(policy: &UpgradePolicy) -> UpgradeProtocol {
    match policy {
        UpgradePolicy::WebSocket => {
            UpgradeProtocol::new("websocket").expect("the static WebSocket protocol token is valid")
        }
        UpgradePolicy::Opaque(protocol) => protocol.clone(),
        UpgradePolicy::Deny => unreachable!("upgrade handoff requires upgrade intent"),
    }
}

struct ProductUpgradeHandoff {
    runtime: Arc<UpgradeRuntime>,
    binding: StandaloneUpgradeBinding,
    downstream_upgrade: hyper::upgrade::OnUpgrade,
    deadline: Instant,
    deadlines: UpgradeRelayDeadlines,
    protocol: UpgradeProtocol,
    observation: Arc<Mutex<ProductObservationState>>,
    capture: Option<UpgradeCaptureContext>,
}

impl UpgradeHandoff for ProductUpgradeHandoff {
    fn prepare(
        self: Box<Self>,
        head: ForwardingResponseHead,
    ) -> BoxFuture<'static, Result<Box<dyn PreparedUpgradeHandoff>, RuntimeError>> {
        Box::pin(async move {
            let response_headers = crate::proxy::facts::product_headers(head.headers())
                .map_err(|_| RuntimeError::InvalidInput)?;
            let request_headers = lock_observation(&self.observation)
                .request_headers
                .clone()
                .ok_or(RuntimeError::BindingMismatch)?;
            let protocol = HeaderValue::from_str(self.protocol.as_str())
                .map_err(|_| RuntimeError::InvalidInput)?;
            let kind = EstablishedUpgradeKind::from_handshake(
                &protocol,
                &request_headers,
                &response_headers,
                self.binding.wire_redaction.as_ref(),
            )
            .map_err(|_| RuntimeError::InvalidInput)?;
            let prepared_relay = kind
                .prepare(self.runtime.limits().relay_buffer_bytes(), self.capture)
                .map_err(|_| RuntimeError::LimitExceeded)?;
            let offer = Arc::new(Mutex::new(None));
            let (offer_tx, offer_rx) = oneshot::channel();
            let established_offer = Arc::clone(&offer);
            // Setup owns every raw resource; this supervised task stays pending
            // so coordinator cleanup can cancel and join it exactly once.
            let terminal_control =
                UpgradeTerminalControl::new(std::future::pending::<()>, move |cause| {
                    finish_upgrade_offer(established_offer, Some(cause))
                });
            let setup_offer = Arc::clone(&offer);
            let downstream_upgrade = self.downstream_upgrade;
            let deadline = self.deadline;
            let deadlines = self.deadlines;
            let entry_plan = UpgradeEntryPlan::new(terminal_control, move |snapshot| async move {
                let received = offer_rx
                    .await
                    .map_err(|_| UpgradeTerminalCause::SetupFailed)?;
                *lock_offer(&setup_offer) = Some(received);
                let downstream = tokio::time::timeout_at(deadline, downstream_upgrade)
                    .await
                    .map_err(|_| UpgradeTerminalCause::LifetimeExpired)?
                    .map_err(|_| UpgradeTerminalCause::DownstreamWriteFailed)?;
                Ok(prepared_relay.establish(
                    downstream,
                    ProductUpstreamUpgradeIo { offer: setup_offer },
                    snapshot,
                    deadlines,
                ))
            });
            let (committed_tx, committed_rx) = oneshot::channel();
            let wire_redaction = self.binding.wire_redaction;
            self.runtime
                .try_spawn_handshake(self.binding.allocation, move |handshake| async move {
                    let committed = handshake.commit(wire_redaction, entry_plan).is_ok();
                    let _ = committed_tx.send(committed);
                })
                .map_err(|_| RuntimeError::ServiceFailure)?;
            match committed_rx.await {
                Ok(true) => Ok(Box::new(PreparedProductUpgrade { offer_tx })
                    as Box<dyn PreparedUpgradeHandoff>),
                _ => Err(RuntimeError::ServiceFailure),
            }
        })
    }
}

struct PreparedProductUpgrade {
    offer_tx: oneshot::Sender<UpgradeOffer>,
}

impl PreparedUpgradeHandoff for PreparedProductUpgrade {
    fn commit(self: Box<Self>, offer: UpgradeOffer) -> Result<(), UpgradeOffer> {
        self.offer_tx.send(offer)
    }
}

fn lock_offer(
    offer: &Arc<Mutex<Option<UpgradeOffer>>>,
) -> std::sync::MutexGuard<'_, Option<UpgradeOffer>> {
    offer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn finish_upgrade_offer(
    offer: Arc<Mutex<Option<UpgradeOffer>>>,
    cause: Option<UpgradeTerminalCause>,
) {
    let offer = lock_offer(&offer).take();
    let Some(offer) = offer else {
        return;
    };
    let outcome = if offer.is_cancelled() {
        ForwardingTerminalOutcome::Cancelled
    } else if cause == Some(UpgradeTerminalCause::PeerClosed) {
        ForwardingTerminalOutcome::Completed
    } else {
        ForwardingTerminalOutcome::Failed
    };
    let _ = offer.finish(outcome).await;
}

struct ProductUpstreamUpgradeIo {
    offer: Arc<Mutex<Option<UpgradeOffer>>>,
}

impl AsyncRead for ProductUpstreamUpgradeIo {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut offer = lock_offer(&self.offer);
        let Some(offer) = offer.as_mut() else {
            return Poll::Ready(Err(closed_upgrade()));
        };
        let unfilled = destination.initialize_unfilled();
        match offer.session().poll_read(context, unfilled) {
            Poll::Ready(Ok(count)) if count <= unfilled.len() => {
                destination.advance(count);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Err(closed_upgrade())),
            Poll::Ready(Err(_)) => Poll::Ready(Err(closed_upgrade())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ProductUpstreamUpgradeIo {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut offer = lock_offer(&self.offer);
        let Some(offer) = offer.as_mut() else {
            return Poll::Ready(Err(closed_upgrade()));
        };
        offer
            .session()
            .poll_write(context, source)
            .map_err(|_| closed_upgrade())
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut offer = lock_offer(&self.offer);
        let Some(offer) = offer.as_mut() else {
            return Poll::Ready(Err(closed_upgrade()));
        };
        offer
            .session()
            .poll_flush(context)
            .map_err(|_| closed_upgrade())
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut offer = lock_offer(&self.offer);
        let Some(offer) = offer.as_mut() else {
            return Poll::Ready(Err(closed_upgrade()));
        };
        offer
            .session()
            .poll_shutdown(context)
            .map_err(|_| closed_upgrade())
    }
}

fn closed_upgrade() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "upstream upgrade closed")
}
