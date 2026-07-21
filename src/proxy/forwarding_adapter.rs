use std::sync::{Arc, Mutex};

use http::header::CONTENT_ENCODING;
use http::{HeaderMap, HeaderValue, StatusCode, Version};
use http_access_runtime::{
    BoxFuture, ForwardingAdmission, ForwardingLocalResponse, ForwardingObservation,
    ForwardingRequestHead, ForwardingResources, ForwardingResponseHead, ForwardingRetention,
    ForwardingTerminal, ForwardingTerminalOutcome, ForwardingTerminalOwner, RuntimeError,
    StandaloneForwarding, UpgradeCaptureFactory,
};
use http_access_types::HeaderField;

use crate::capture::CaptureDecision;
use crate::observation::CaptureEvent;
use crate::proxy::observation_adapter::{
    CaptureSubmission, HttpCaptureContext, TerminalRequestBodyProvenance,
};
use crate::standalone_policy_provider::{
    ProductBodyResources, ProductForwardingCancellation, ProductPrivateFields,
    StandaloneForwardDispatch,
};
use crate::standalone_provider_result::{StandaloneCaptureBody, StandaloneRequestSidecar};
use crate::{runtime::GenerationRetention, safety::WireBodyPool};

struct ProductForwardingSidecar {
    _generation: GenerationRetention,
    _request: StandaloneRequestSidecar,
    _private_fields: ProductPrivateFields,
    _body_resources: ProductBodyResources,
    _stable_wire_body_pool: Arc<WireBodyPool>,
}

struct AllowDecisionGuard(Option<crate::observation::PendingDecisionSubmission>);

impl AllowDecisionGuard {
    fn submit(mut self) {
        if let Some(mut decision) = self.0.take() {
            decision.submit_now();
        }
    }
}

impl Drop for AllowDecisionGuard {
    fn drop(&mut self) {
        if let Some(decision) = self.0.take() {
            decision.discard();
        }
    }
}

pub(super) struct ProductObservationState {
    capture: HttpCaptureContext,
    request_provenance: TerminalRequestBodyProvenance,
    canonical_identity: bool,
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

pub(super) fn abandon_observation(state: &Arc<Mutex<ProductObservationState>>) {
    lock_observation(state).abandon();
}

struct ProductForwardingObservation {
    state: Arc<Mutex<ProductObservationState>>,
}

impl ForwardingObservation for ProductForwardingObservation {
    fn request_head_preparation_failed(&mut self) -> Result<(), RuntimeError> {
        lock_observation(&self.state)
            .capture
            .submit_request_head_preparation_failed();
        Ok(())
    }

    fn request_head(&mut self, head: &ForwardingRequestHead) -> Result<(), RuntimeError> {
        let headers = crate::proxy::private_fields::product_headers(head.headers())
            .map_err(|_| RuntimeError::InvalidInput)?;
        let mut body_headers = body_headers(&headers);
        let mut state = lock_observation(&self.state);
        if state.canonical_identity {
            body_headers.insert(CONTENT_ENCODING, HeaderValue::from_static("identity"));
        }
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

    fn request_trailers(&mut self, trailers: &[HeaderField]) -> Result<(), RuntimeError> {
        if !trailers.is_empty() {
            if let Some(request) = lock_observation(&self.state).request.as_mut() {
                request.mark_trailers_omitted();
            }
        }
        Ok(())
    }

    fn request_complete(&mut self) -> Result<(), RuntimeError> {
        lock_observation(&self.state).finish_request();
        Ok(())
    }

    fn local_response(&mut self, response: &ForwardingLocalResponse) -> Result<(), RuntimeError> {
        let status =
            StatusCode::from_u16(response.status()).map_err(|_| RuntimeError::InvalidInput)?;
        let state = lock_observation(&self.state);
        state
            .capture
            .submit_local_response(CaptureDecision::Allow, status, response.body());
        Ok(())
    }

    fn response_head(&mut self, head: &ForwardingResponseHead) -> Result<(), RuntimeError> {
        let version = product_version(head.version());
        let status = StatusCode::from_u16(head.status()).map_err(|_| RuntimeError::InvalidInput)?;
        let headers = crate::proxy::private_fields::product_headers(head.headers())
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

    fn response_trailers(&mut self, trailers: &[HeaderField]) -> Result<(), RuntimeError> {
        if !trailers.is_empty() {
            if let Some(response) = lock_observation(&self.state).response.as_mut() {
                response.mark_trailers_omitted();
            }
        }
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
        #[cfg(test)]
        lock_observation(&self.observation)
            .capture
            .record_forwarding_terminal_completion();
        #[cfg(test)]
        lock_observation(&self.observation)
            .capture
            .record_forwarding_terminal_outcome(outcome);
        if matches!(outcome, ForwardingTerminalOutcome::Completed) {
            let mut observation = lock_observation(&self.observation);
            observation.finish_request();
            observation.finish_response();
        } else {
            abandon_observation(&self.observation);
        }
        let cancellation = self.cancellation.take();
        Box::pin(async move {
            drop(cancellation);
            Ok(())
        })
    }

    fn abandon(&mut self) {
        #[cfg(test)]
        lock_observation(&self.observation)
            .capture
            .record_forwarding_terminal_completion();
        #[cfg(test)]
        lock_observation(&self.observation)
            .capture
            .record_forwarding_terminal_abandonment();
        abandon_observation(&self.observation);
        self.cancellation.take();
    }
}

/// Admits all product-owned resources and returns the sole shared forwarding owner.
pub(crate) fn prepare(
    mut dispatch: StandaloneForwardDispatch,
) -> Result<StandaloneForwarding, RuntimeError> {
    let decision = AllowDecisionGuard(Some(dispatch.decision));
    let plan = dispatch.exchange.plan_arc();
    if dispatch.sidecar.plan_binding() != plan.binding()
        || !dispatch
            .private_fields
            .validates_visible(dispatch.exchange.facts().headers())
    {
        return Err(RuntimeError::BindingMismatch);
    }
    let upgrade_admission = dispatch
        .sidecar
        .take_upgrade_admission(plan.binding())
        .map_err(|_| RuntimeError::BindingMismatch)?;
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
        dispatch.capture.clone(),
        provenance,
        canonical_identity,
    )));
    let response_admission = dispatch
        .services
        .begin_response(dispatch.quota_key)
        .map_err(|_| RuntimeError::ServiceFailure)?;
    let credentials = dispatch
        .credentials
        .take()
        .map(|preparation| preparation.admit_for_plan(&plan))
        .transpose()
        .map_err(|_| RuntimeError::ServiceFailure)?;
    let loop_marker = dispatch
        .services
        .loop_marker(&plan, &dispatch.request_id)
        .map_err(|_| RuntimeError::BindingMismatch)?;
    let cancellation = dispatch.cancellation.capability();
    let terminal = ForwardingTerminalOwner::new(ProductForwardingTerminal {
        cancellation: Some(dispatch.cancellation),
        observation: Arc::clone(&observation),
    });
    let admission = ForwardingAdmission::new(&plan, response_admission);
    let retention = ForwardingRetention::new(&plan, ());
    let mut resources = ForwardingResources::new(admission, retention, cancellation, terminal)
        .with_observation(ProductForwardingObservation {
            state: Arc::clone(&observation),
        });
    if let Some(marker) = loop_marker {
        resources = resources.with_loop_marker(marker);
    }
    if let Some(credentials) = credentials {
        resources = resources.with_credentials(credentials);
    }

    let upgrade_capture: Option<Arc<dyn UpgradeCaptureFactory>> = dispatch
        .capture
        .upgrade_capture_context(plan.origin())
        .map(|capture| Arc::new(capture) as Arc<dyn UpgradeCaptureFactory>);
    let forwarding = StandaloneForwarding::new(
        dispatch.services.executor().clone(),
        dispatch.exchange,
        dispatch.resolved,
        resources,
        ProductForwardingSidecar {
            _generation: dispatch.retention,
            _request: dispatch.sidecar,
            _private_fields: dispatch.private_fields,
            _body_resources: dispatch.body_resources,
            _stable_wire_body_pool: dispatch.stable_wire_body_pool,
        },
        upgrade_admission,
        upgrade_capture,
    );
    match forwarding {
        Ok(forwarding) => {
            decision.submit();
            Ok(forwarding)
        }
        Err(error) => Err(error),
    }
}

fn body_headers(headers: &HeaderMap) -> HeaderMap {
    let mut selected = HeaderMap::new();
    for name in [http::header::CONTENT_ENCODING, http::header::TRAILER] {
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

#[cfg(test)]
pub(crate) fn exercise_trailer_observation_for_test(
    runtime: Arc<crate::observation::ProductObservationRuntime>,
    epoch: Arc<crate::observation::CaptureEpoch>,
    request_id: &str,
    target: &http_access_url::CanonicalUrl,
    with_trailers: bool,
) {
    let capture =
        HttpCaptureContext::for_forwarding_trailer_test(runtime, epoch, request_id, target);
    let headers = HeaderMap::new();
    let request = capture.begin_allowed_request(
        &headers,
        &headers,
        TerminalRequestBodyProvenance::CompleteOriginal,
    );
    let response = capture.begin(
        CaptureEvent::ResponseAllowed,
        || {
            capture.response_record(
                CaptureDecision::Allow,
                Version::HTTP_2,
                Some(&headers),
                StatusCode::OK,
                false,
            )
        },
        &headers,
    );
    assert!(request.is_some(), "request capture was not admitted");
    assert!(response.is_some(), "response capture was not admitted");

    let state = Arc::new(Mutex::new(ProductObservationState {
        capture,
        request_provenance: TerminalRequestBodyProvenance::CompleteOriginal,
        canonical_identity: false,
        request,
        response,
    }));
    let mut observer = ProductForwardingObservation {
        state: Arc::clone(&state),
    };
    let trailers = with_trailers.then(|| {
        HeaderField::new(
            http_access_types::HeaderName::new("x-capture-trailer".to_owned()).unwrap(),
            http_access_types::HeaderValue::new(b"present".to_vec()).unwrap(),
        )
    });
    let trailers = trailers.as_slice();
    observer.request_trailers(trailers).unwrap();
    observer.request_complete().unwrap();
    observer.response_trailers(trailers).unwrap();
    lock_observation(&state).finish_response();
}
