use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::Utc;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Method, StatusCode, Version};
use http_access_redaction::PayloadClass;
use http_access_runtime::{
    UpgradeCaptureAttempt, UpgradeCaptureCompletion, UpgradeCaptureDirection,
    UpgradeCaptureFactory, UpgradeCaptureMessage,
};
use http_access_types::{
    CaptureFacts, CaptureFactsInput, HeaderName as NeutralHeaderName,
    HeaderValue as NeutralHeaderValue, IngressMode, SanitizedHeaderField, SensitiveHeaderPolicy,
    SinkSafeUrl, StableId,
};

use crate::capture::{
    CaptureArtifactJob, CaptureBodyOmission, CaptureDecision, CaptureKind, HttpCaptureTap,
    SanitizedCaptureMetadata,
};
use crate::observation::{
    CaptureBodyBuilder, CaptureEpoch, CaptureEvent, ProductObservationRuntime,
};
use crate::safety::GuardedBody;

#[derive(Clone)]
pub(crate) struct HttpCaptureContext {
    runtime: Arc<ProductObservationRuntime>,
    epoch: Arc<CaptureEpoch>,
    sensitive_headers: SensitiveHeaderPolicy,
    request_id: String,
    url: Option<SinkSafeUrl>,
    canonical_url: Option<http_access_url::CanonicalUrl>,
    method: Method,
    client: SocketAddr,
    ingress_mode: IngressMode,
    request_version: Version,
    max_expansion_ratio: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalRequestBodyProvenance {
    Unconsumed,
    CompleteOriginal,
    CompleteWireRedacted,
    ProviderReplacement { size: usize },
}

pub(crate) struct DeniedCaptureBody {
    pub(crate) headers: HeaderMap,
    pub(crate) decoded: GuardedBody,
}

impl HttpCaptureContext {
    #[cfg(test)]
    pub(super) fn for_forwarding_trailer_test(
        runtime: Arc<ProductObservationRuntime>,
        epoch: Arc<CaptureEpoch>,
        request_id: &str,
        target: &http_access_url::CanonicalUrl,
    ) -> Self {
        let mut capture = Self {
            runtime,
            epoch,
            sensitive_headers: SensitiveHeaderPolicy::new([], [], [])
                .expect("fixed sensitive headers are valid"),
            request_id: request_id.to_owned(),
            url: None,
            canonical_url: None,
            method: Method::POST,
            client: SocketAddr::from(([127, 0, 0, 1], 42_000)),
            ingress_mode: IngressMode::ExplicitHttp,
            request_version: Version::HTTP_2,
            max_expansion_ratio: 100,
        };
        capture.bind_target(target);
        capture
    }

    #[cfg(test)]
    pub(super) fn record_forwarding_terminal_completion(&self) {
        self.runtime.record_forwarding_terminal_completion();
    }

    #[cfg(test)]
    pub(super) fn record_forwarding_terminal_outcome(
        &self,
        outcome: http_access_runtime::ForwardingTerminalOutcome,
    ) {
        self.runtime.record_forwarding_terminal_outcome(outcome);
    }

    #[cfg(test)]
    pub(super) fn record_forwarding_terminal_abandonment(&self) {
        self.runtime.record_forwarding_terminal_abandonment();
    }

    pub(crate) fn from_checked_standalone(
        runtime: Arc<ProductObservationRuntime>,
        epoch: Arc<CaptureEpoch>,
        sensitive_headers: SensitiveHeaderPolicy,
        request_id: String,
        peer: SocketAddr,
        facts: &http_access_types::InterceptedRequestFacts,
        max_expansion_ratio: usize,
    ) -> Result<Self, ()> {
        let method = Method::from_bytes(facts.method().as_str().as_bytes()).map_err(|_| ())?;
        let request_version = match facts.version() {
            http_access_types::HttpVersion::Http10 => Version::HTTP_10,
            http_access_types::HttpVersion::Http11 => Version::HTTP_11,
            http_access_types::HttpVersion::Http2 => Version::HTTP_2,
        };
        let canonical_url = facts.url().clone();
        let mut capture = Self {
            runtime,
            epoch,
            sensitive_headers,
            request_id,
            url: None,
            canonical_url: None,
            method,
            client: peer,
            ingress_mode: facts.ingress_mode(),
            request_version,
            max_expansion_ratio,
        };
        capture.bind_target(&canonical_url);
        Ok(capture)
    }

    fn bind_target(&mut self, target: &http_access_url::CanonicalUrl) {
        if !self.epoch.is_enabled() {
            return;
        }
        self.url = Some(SinkSafeUrl::from_canonical(target));
        self.canonical_url = Some(target.clone());
    }

    pub(super) fn upgrade_capture_context(
        &self,
        target: &http_access_url::CanonicalUrl,
    ) -> Option<ProductUpgradeCaptureContext> {
        let base = self.record(
            CaptureKind::Request,
            CaptureDecision::Allow,
            self.request_version,
            None,
            None,
            false,
            Some(target),
        )?;
        Some(ProductUpgradeCaptureContext::new(
            self.runtime.clone(),
            base,
            self.max_expansion_ratio,
        ))
    }

    pub(super) fn begin(
        &self,
        event: CaptureEvent,
        record: impl FnOnce() -> Option<SanitizedCaptureMetadata>,
        body_headers: &HeaderMap,
    ) -> Option<CaptureSubmission> {
        HttpCaptureTap::try_begin(
            self.epoch.clone(),
            event,
            record,
            body_headers,
            self.max_expansion_ratio,
        )
        .map(|tap| CaptureSubmission::new(self.runtime.clone(), tap))
    }

    fn request_record(
        &self,
        decision: CaptureDecision,
        headers: Option<&HeaderMap>,
    ) -> Option<SanitizedCaptureMetadata> {
        self.record(
            CaptureKind::Request,
            decision,
            self.request_version,
            headers,
            None,
            false,
            self.canonical_url.as_ref(),
        )
    }

    pub(super) fn response_record(
        &self,
        decision: CaptureDecision,
        version: Version,
        headers: Option<&HeaderMap>,
        status: StatusCode,
        include_status_message: bool,
    ) -> Option<SanitizedCaptureMetadata> {
        self.record(
            CaptureKind::Response,
            decision,
            version,
            headers,
            Some(status),
            include_status_message,
            self.canonical_url.as_ref(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        kind: CaptureKind,
        decision: CaptureDecision,
        version: Version,
        headers: Option<&HeaderMap>,
        status: Option<StatusCode>,
        include_status_message: bool,
        canonical_url: Option<&http_access_url::CanonicalUrl>,
    ) -> Option<SanitizedCaptureMetadata> {
        let event = match (kind, decision) {
            (CaptureKind::Request, CaptureDecision::Allow) => CaptureEvent::RequestAllowed,
            (CaptureKind::Response, CaptureDecision::Allow) => CaptureEvent::ResponseAllowed,
            (CaptureKind::Request, CaptureDecision::Deny) => CaptureEvent::RequestDenied,
            (CaptureKind::Response, CaptureDecision::Deny) => CaptureEvent::ResponseDenied,
        };
        let request_id = StableId::new(&self.request_id)
            .expect("product request identifiers are stable identifiers");
        let method = crate::proxy::private_fields::http_method(&self.method).ok();
        let sanitized_headers = headers
            .map(|headers| sanitize_capture_headers(headers, &self.sensitive_headers))
            .unwrap_or_default();
        let facts = CaptureFacts::new(
            &self.sensitive_headers,
            CaptureFactsInput {
                request_id: &request_id,
                event,
                ingress_mode: self.ingress_mode,
                method: method.as_ref(),
                url: canonical_url,
                client_ip: Some(self.client.ip()),
                target: canonical_url.map(http_access_url::CanonicalUrl::authority),
                version: crate::proxy::private_fields::http_version(version).ok(),
                status: status.map(|status| status.as_u16()),
                headers: &sanitized_headers,
            },
        )
        .ok()?;
        if canonical_url == self.canonical_url.as_ref() {
            debug_assert_eq!(
                facts.url().map(http_access_types::SinkSafeUrl::as_str),
                self.url.as_ref().map(SinkSafeUrl::as_str)
            );
        }
        Some(SanitizedCaptureMetadata::from_facts(
            facts,
            Utc::now().to_rfc3339(),
            Some(self.client.port()),
            headers.is_some(),
            include_status_message
                .then(|| {
                    status
                        .and_then(|status| status.canonical_reason())
                        .map(str::to_owned)
                })
                .flatten(),
        ))
    }

    pub(super) fn begin_allowed_request(
        &self,
        headers: &HeaderMap,
        body_headers: &HeaderMap,
        provenance: TerminalRequestBodyProvenance,
    ) -> Option<CaptureSubmission> {
        if let TerminalRequestBodyProvenance::ProviderReplacement { size } = provenance {
            if let Some(mut submission) = self.begin(
                CaptureEvent::RequestAllowed,
                || {
                    let mut record = self.request_record(CaptureDecision::Allow, Some(headers))?;
                    record.omit_provider_replacement(size);
                    Some(record)
                },
                body_headers,
            ) {
                submission.abandon();
            }
            return None;
        }
        self.begin(
            CaptureEvent::RequestAllowed,
            || self.request_record(CaptureDecision::Allow, Some(headers)),
            body_headers,
        )
    }

    pub(super) fn submit_request_head_preparation_failed(&self) {
        let body_headers = HeaderMap::new();
        if let Some(mut submission) = self.begin(
            CaptureEvent::RequestAllowed,
            || {
                let mut record = self.request_record(CaptureDecision::Allow, None)?;
                record.omit_body(CaptureBodyOmission::HeadPreparationFailed {});
                Some(record)
            },
            &body_headers,
        ) {
            submission.abandon();
        }
    }

    pub(crate) fn submit_denied_request(
        &self,
        headers: Option<&HeaderMap>,
        body: Option<DeniedCaptureBody>,
        provenance: TerminalRequestBodyProvenance,
    ) {
        let body_headers = body
            .as_ref()
            .map(|body| body.headers.clone())
            .unwrap_or_default();
        let Some(mut submission) = self.begin(
            CaptureEvent::RequestDenied,
            || {
                let mut record = self.request_record(CaptureDecision::Deny, headers)?;
                if let TerminalRequestBodyProvenance::ProviderReplacement { size } = provenance {
                    record.omit_provider_replacement(size);
                }
                Some(record)
            },
            &body_headers,
        ) else {
            return;
        };
        match (provenance, body) {
            (
                TerminalRequestBodyProvenance::CompleteOriginal
                | TerminalRequestBodyProvenance::CompleteWireRedacted,
                Some(body),
            ) => {
                for segment in body.decoded.segments() {
                    submission.push(segment);
                }
                submission.finish();
            }
            _ => submission.abandon(),
        }
    }

    pub(crate) fn submit_local_response(
        &self,
        decision: CaptureDecision,
        status: StatusCode,
        message: &'static str,
    ) {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&message.len().to_string())
                .expect("fixed response length is a valid header"),
        );
        let event = match decision {
            CaptureDecision::Allow => CaptureEvent::ResponseAllowed,
            CaptureDecision::Deny => CaptureEvent::ResponseDenied,
        };
        if let Some(mut submission) = self.begin(
            event,
            || self.response_record(decision, self.request_version, Some(&headers), status, true),
            &headers,
        ) {
            submission.push(message.as_bytes());
            submission.finish();
        }
    }
}

pub(super) struct CaptureSubmission {
    runtime: Arc<ProductObservationRuntime>,
    tap: Option<HttpCaptureTap>,
}

impl CaptureSubmission {
    fn new(runtime: Arc<ProductObservationRuntime>, tap: HttpCaptureTap) -> Self {
        Self {
            runtime,
            tap: Some(tap),
        }
    }

    pub(super) fn push(&mut self, bytes: &[u8]) {
        if let Some(tap) = self.tap.as_mut() {
            tap.push(bytes);
        }
    }

    pub(super) fn finish(&mut self) {
        if let Some(tap) = self.tap.take() {
            self.submit(tap.finish());
        }
    }

    pub(super) fn abandon(&mut self) {
        if let Some(tap) = self.tap.take() {
            self.submit(tap.abandon());
        }
    }

    pub(super) fn mark_trailers_omitted(&mut self) {
        if let Some(tap) = self.tap.as_mut() {
            tap.mark_trailers_omitted();
        }
    }

    fn submit(&self, job: CaptureArtifactJob) {
        if let Err(error) = self.runtime.try_submit_capture(job) {
            tracing::debug!(error = ?error, "capture artifact queue omitted record");
        }
    }
}

impl Drop for CaptureSubmission {
    fn drop(&mut self) {
        self.abandon();
    }
}

#[derive(Clone)]
pub(super) struct ProductUpgradeCaptureContext {
    runtime: Arc<ProductObservationRuntime>,
    base: SanitizedCaptureMetadata,
    max_expansion_ratio: usize,
    request_sequence: Arc<AtomicU64>,
    response_sequence: Arc<AtomicU64>,
}

impl ProductUpgradeCaptureContext {
    fn new(
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
        direction: UpgradeCaptureDirection,
        compressed: bool,
        class: PayloadClass,
    ) -> Option<WebSocketMessageCapture> {
        let (event, kind, label, sequence) = match direction {
            UpgradeCaptureDirection::ClientToUpstream => (
                CaptureEvent::RequestAllowed,
                CaptureKind::Request,
                "request",
                self.request_sequence.fetch_add(1, Ordering::Relaxed),
            ),
            UpgradeCaptureDirection::UpstreamToClient => (
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
        let body = Some(job.operation().body_buffer());
        Some(WebSocketMessageCapture {
            runtime: self.runtime.clone(),
            job,
            body,
            compressed,
            class,
            max_frame_bytes: limits.max_frame_bytes(),
            max_message_bytes: limits.max_message_bytes(),
            encoded_bytes: 0,
        })
    }
}

impl UpgradeCaptureFactory for ProductUpgradeCaptureContext {
    fn try_begin(&self, message: UpgradeCaptureMessage) -> Option<Box<dyn UpgradeCaptureAttempt>> {
        self.begin_message(message.direction(), message.compressed(), message.class())
            .map(|capture| Box::new(capture) as Box<dyn UpgradeCaptureAttempt>)
    }
}

struct WebSocketMessageCapture {
    runtime: Arc<ProductObservationRuntime>,
    job: CaptureArtifactJob,
    body: Option<CaptureBodyBuilder>,
    compressed: bool,
    class: PayloadClass,
    max_frame_bytes: usize,
    max_message_bytes: usize,
    encoded_bytes: usize,
}

impl UpgradeCaptureAttempt for WebSocketMessageCapture {
    fn omit_body(&mut self) {
        self.omit_body_with(CaptureBodyOmission::Incomplete {});
    }

    fn try_begin_frame(&mut self, encoded_payload_bytes: usize) -> bool {
        if encoded_payload_bytes > self.max_frame_bytes {
            self.omit_body_with(CaptureBodyOmission::LimitExceeded {});
            return false;
        }
        let Some(total) = self.encoded_bytes.checked_add(encoded_payload_bytes) else {
            self.omit_body_with(CaptureBodyOmission::LimitExceeded {});
            return false;
        };
        if total > self.max_message_bytes {
            self.omit_body_with(CaptureBodyOmission::LimitExceeded {});
            return false;
        }
        self.encoded_bytes = total;
        true
    }

    fn try_push_fragment(&mut self, fragment: &[u8]) -> bool {
        let appended = self
            .body
            .as_mut()
            .is_some_and(|body| body.try_extend_from_slice(fragment).is_ok());
        if !appended && self.body.is_some() {
            self.omit_body_with(CaptureBodyOmission::ResourceExhausted {});
        }
        appended
    }

    fn finish(mut self: Box<Self>, completion: UpgradeCaptureCompletion) {
        if completion == UpgradeCaptureCompletion::Complete {
            let Some(body) = self.body.take() else {
                return self.submit();
            };
            let encoded = body.finish();
            if self
                .job
                .complete_websocket_message(encoded, self.compressed, self.class)
                .is_err()
            {
                self.job
                    .omit_body(CaptureBodyOmission::ResourceExhausted {});
            }
        } else {
            self.omit_body();
        }
        self.submit();
    }
}

impl WebSocketMessageCapture {
    fn omit_body_with(&mut self, reason: CaptureBodyOmission) {
        if self.body.take().is_some() {
            self.job.omit_body(reason);
        }
    }

    fn submit(self: Box<Self>) {
        if let Err(error) = self.runtime.try_submit_capture(self.job) {
            tracing::debug!(error = ?error, "WebSocket capture queue omitted record");
        }
    }
}

#[cfg(test)]
pub(crate) fn exercise_upgrade_allocation_failure_for_test(
    runtime: Arc<ProductObservationRuntime>,
    epoch: Arc<CaptureEpoch>,
    request_id: &str,
    target: &http_access_url::CanonicalUrl,
) {
    let capture = HttpCaptureContext::for_forwarding_trailer_test(
        Arc::clone(&runtime),
        epoch,
        request_id,
        target,
    );
    let upgrade = capture
        .upgrade_capture_context(target)
        .expect("upgrade capture is enabled");
    let mut attempt = upgrade
        .begin_message(
            UpgradeCaptureDirection::ClientToUpstream,
            false,
            PayloadClass::Text,
        )
        .expect("upgrade capture is admitted");
    runtime.fail_next_capture_allocation();
    assert!(attempt.try_begin_frame(7));
    assert!(!attempt.try_push_fragment(b"payload"));
    Box::new(attempt).finish(UpgradeCaptureCompletion::Complete);
}

fn sanitize_capture_headers(
    headers: &HeaderMap,
    sensitive_headers: &SensitiveHeaderPolicy,
) -> Vec<SanitizedHeaderField> {
    let mut captured = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        let name = name.as_str().to_ascii_lowercase();
        let neutral_name = NeutralHeaderName::new(name.as_str())
            .expect("http header names are canonical neutral header names");
        let field = if sensitive_headers.contains(&neutral_name) {
            SanitizedHeaderField::redacted(neutral_name)
        } else {
            let neutral_value = NeutralHeaderValue::new(value.as_bytes().to_vec())
                .expect("http header values are valid neutral header values");
            SanitizedHeaderField::visible(sensitive_headers, neutral_name, neutral_value)
                .expect("non-sensitive header classification remains non-sensitive")
        };
        captured.push(field);
    }
    captured
}
