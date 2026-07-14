use std::future::Future;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::authorization::callback::{
    AssignedCallbackResponseParser, CallbackClaim, CallbackClaimError, CallbackClaimResult,
    CallbackResponseDecision, CallbackResponseError, CallbackResponsePrefix,
    PendingCapabilityStore, PendingTerminalCause,
};
use crate::authorization::protocol::CALLBACK_RESPONSE_PREFIX_BYTES;
use crate::authorization::webhook::provider::WebhookProvider;
use crate::authorization::webhook::runtime::{
    PendingWebhookOperation, WebhookAuthorizationRuntime, WebhookCompletionError,
};
use crate::http1::framing::{BodyFramer, BodyFraming, BodyProgress, FramingProcessError};
use crate::http1::store::ParserStore;
use crate::safety::ProviderResponseCharge;

use super::response::{ControlResponse, EmptyResponseStatus};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CallbackApplicationOutcome {
    response: Option<ControlResponse>,
    connection_reusable: bool,
}

impl CallbackApplicationOutcome {
    pub(crate) const fn response(self) -> Option<ControlResponse> {
        self.response
    }

    pub(crate) const fn connection_reusable(self) -> bool {
        self.connection_reusable
    }

    const fn respond(status: EmptyResponseStatus, connection_reusable: bool) -> Self {
        Self {
            response: Some(ControlResponse::empty(status)),
            connection_reusable,
        }
    }

    const fn close_without_response() -> Self {
        Self {
            response: None,
            connection_reusable: false,
        }
    }
}

/// Consumes one callback entity without spawning or retaining work outside the
/// calling connection task. `store` may already contain entity or pipelined
/// bytes left after request-head reclamation.
pub(crate) async fn handle_callback_entity<R>(
    reader: &mut R,
    store: &mut ParserStore,
    framing: BodyFraming,
    runtime: &WebhookAuthorizationRuntime,
    control_max_request_body_bytes: usize,
    body_deadline: Instant,
) -> CallbackApplicationOutcome
where
    R: AsyncRead + Unpin,
{
    handle_callback_entity_with_store(
        reader,
        store,
        framing,
        runtime.pending_store(),
        control_max_request_body_bytes,
        body_deadline,
    )
    .await
}

async fn handle_callback_entity_with_store<R, P>(
    reader: &mut R,
    store: &mut ParserStore,
    framing: BodyFraming,
    pending: &PendingCapabilityStore<P>,
    control_max_request_body_bytes: usize,
    body_deadline: Instant,
) -> CallbackApplicationOutcome
where
    R: AsyncRead + Unpin,
    P: CallbackPayload,
{
    if let (BodyFraming::ContentLength(length), Ok(control_limit)) =
        (framing, u64::try_from(control_max_request_body_bytes))
    {
        if length > control_limit {
            return CallbackApplicationOutcome::respond(
                EmptyResponseStatus::PayloadTooLarge,
                false,
            );
        }
    }

    let mut framer = BodyFramer::new(framing);
    let mut end_of_stream = false;
    let mut prefix = Zeroizing::new([0u8; CALLBACK_RESPONSE_PREFIX_BYTES]);
    let mut prefix_len = 0usize;

    loop {
        let progress = framer.process_up_to(
            store,
            end_of_stream,
            CALLBACK_RESPONSE_PREFIX_BYTES as u64,
            |bytes| {
                let end = prefix_len + bytes.len();
                prefix[prefix_len..end].copy_from_slice(bytes);
                prefix_len = end;
                Ok::<_, std::convert::Infallible>(())
            },
        );
        match progress {
            Ok(BodyProgress::Paused) => break,
            Ok(BodyProgress::Complete) => {
                return CallbackApplicationOutcome::respond(EmptyResponseStatus::NotFound, false)
            }
            Ok(BodyProgress::NeedInput) => {
                end_of_stream = match fill_store(reader, store, body_deadline).await {
                    ReadResult::Read => false,
                    ReadResult::EndOfStream => true,
                    ReadResult::Failed => {
                        return CallbackApplicationOutcome::close_without_response()
                    }
                };
            }
            Err(_) => return CallbackApplicationOutcome::close_without_response(),
        }
    }

    let prefix = match CallbackResponsePrefix::parse(*prefix) {
        Ok(prefix) => prefix,
        Err(_) => return CallbackApplicationOutcome::respond(EmptyResponseStatus::NotFound, false),
    };
    let claim = match pending.try_claim(prefix.digest()) {
        Ok(CallbackClaimResult::Claimed(claim)) => claim,
        Ok(CallbackClaimResult::Expired(terminal)) => {
            let cause = terminal.cause();
            terminal.into_payload().complete_terminal(cause);
            return CallbackApplicationOutcome::respond(EmptyResponseStatus::NotFound, false);
        }
        Err(CallbackClaimError::Unknown) => {
            return CallbackApplicationOutcome::respond(EmptyResponseStatus::NotFound, false)
        }
        Err(CallbackClaimError::Poisoned) => {
            return CallbackApplicationOutcome::respond(
                EmptyResponseStatus::ServiceUnavailable,
                false,
            )
        }
    };

    let teardown_result = {
        let teardown = claim.payload().wait_for_delivery_teardown();
        tokio::pin!(teardown);
        tokio::select! {
            biased;
            _ = claim.wait_for_terminal_signal() => TeardownResult::Terminal,
            _ = tokio::time::sleep_until(body_deadline) => TeardownResult::BodyTimeout,
            _ = &mut teardown => TeardownResult::Complete,
        }
    };
    match teardown_result {
        TeardownResult::Complete => {}
        TeardownResult::Terminal => {
            complete_claim(claim, PayloadCompletion::Terminal);
            return CallbackApplicationOutcome::respond(EmptyResponseStatus::NotFound, false);
        }
        TeardownResult::BodyTimeout => {
            complete_claim(claim, PayloadCompletion::Invalid);
            return CallbackApplicationOutcome::close_without_response();
        }
    }

    let parse_result = parse_claimed_entity(
        reader,
        store,
        &mut framer,
        end_of_stream,
        &claim,
        control_max_request_body_bytes,
        body_deadline,
    )
    .await;

    match parse_result {
        ClaimedEntityResult::Decision(decision) => {
            let terminal = complete_claim(claim, PayloadCompletion::Decision(decision));
            if terminal {
                CallbackApplicationOutcome::respond(EmptyResponseStatus::NotFound, false)
            } else {
                CallbackApplicationOutcome::respond(EmptyResponseStatus::NoContent, true)
            }
        }
        ClaimedEntityResult::Rejected(status) => {
            let terminal = complete_claim(claim, PayloadCompletion::Invalid);
            if terminal {
                CallbackApplicationOutcome::respond(EmptyResponseStatus::NotFound, false)
            } else {
                CallbackApplicationOutcome::respond(status, false)
            }
        }
        ClaimedEntityResult::Terminal => {
            complete_claim(claim, PayloadCompletion::Terminal);
            CallbackApplicationOutcome::respond(EmptyResponseStatus::NotFound, false)
        }
        ClaimedEntityResult::Failed => {
            complete_claim(claim, PayloadCompletion::Invalid);
            CallbackApplicationOutcome::close_without_response()
        }
    }
}

async fn parse_claimed_entity<R, P>(
    reader: &mut R,
    store: &mut ParserStore,
    framer: &mut BodyFramer,
    mut end_of_stream: bool,
    claim: &CallbackClaim<P>,
    control_max_request_body_bytes: usize,
    body_deadline: Instant,
) -> ClaimedEntityResult
where
    R: AsyncRead + Unpin,
    P: CallbackPayload,
{
    let payload = claim.payload();
    let provider_limit = payload.provider().max_response_bytes();
    let entity_limit = provider_limit.min(control_max_request_body_bytes);
    let mut parser = match AssignedCallbackResponseParser::new(
        payload.provider().outputs(),
        payload.response_charge(),
        provider_limit,
        control_max_request_body_bytes,
    ) {
        Ok(parser) => Some(parser),
        Err(error) => return ClaimedEntityResult::Rejected(parser_status(&error)),
    };
    let mut rejected = None;

    loop {
        let progress = if let Some(active) = parser.as_mut() {
            match framer.process(store, end_of_stream, |bytes| active.push(bytes)) {
                Ok(progress) => Ok(progress),
                Err(FramingProcessError::Framing(_)) => return ClaimedEntityResult::Failed,
                Err(FramingProcessError::Sink(error)) => {
                    let status = parser_status(&error);
                    let terminate_early = matches!(
                        error,
                        CallbackResponseError::Charge(_) | CallbackResponseError::LimitExceeded
                    );
                    parser.take();
                    if terminate_early {
                        return ClaimedEntityResult::Rejected(status);
                    }
                    rejected = Some(status);
                    continue;
                }
            }
        } else {
            let drain_limit = match u64::try_from(entity_limit)
                .ok()
                .and_then(|limit| limit.checked_add(1))
            {
                Some(limit) => limit,
                None => return ClaimedEntityResult::Failed,
            };
            match framer.process_up_to(store, end_of_stream, drain_limit, |_| {
                Ok::<_, std::convert::Infallible>(())
            }) {
                Ok(BodyProgress::Paused) => {
                    return ClaimedEntityResult::Rejected(EmptyResponseStatus::BadRequest)
                }
                other => other,
            }
        };

        match progress {
            Ok(BodyProgress::Complete) => {
                if let Some(status) = rejected {
                    return ClaimedEntityResult::Rejected(status);
                }
                return match parser
                    .take()
                    .expect("an unrejected callback owns its parser")
                    .finish()
                {
                    Ok(decision) => ClaimedEntityResult::Decision(decision),
                    Err(error) => ClaimedEntityResult::Rejected(parser_status(&error)),
                };
            }
            Ok(BodyProgress::NeedInput) => {
                end_of_stream = tokio::select! {
                    biased;
                    _ = claim.wait_for_terminal_signal() => return ClaimedEntityResult::Terminal,
                    _ = tokio::time::sleep_until(body_deadline) => return ClaimedEntityResult::Failed,
                    read = fill_store(reader, store, body_deadline) => match read {
                        ReadResult::Read => false,
                        ReadResult::EndOfStream => true,
                        ReadResult::Failed => return ClaimedEntityResult::Failed,
                    },
                };
            }
            Ok(BodyProgress::Paused) => {
                return ClaimedEntityResult::Rejected(EmptyResponseStatus::BadRequest)
            }
            Err(_) => return ClaimedEntityResult::Failed,
        }
    }
}

fn parser_status(error: &CallbackResponseError) -> EmptyResponseStatus {
    match error {
        CallbackResponseError::Charge(_) => EmptyResponseStatus::ServiceUnavailable,
        CallbackResponseError::LimitExceeded
        | CallbackResponseError::Malformed
        | CallbackResponseError::InvalidShape
        | CallbackResponseError::UnknownOutput
        | CallbackResponseError::DuplicateOutput
        | CallbackResponseError::MissingRequiredOutput
        | CallbackResponseError::InvalidCredential => EmptyResponseStatus::BadRequest,
    }
}

fn complete_claim<P>(claim: CallbackClaim<P>, completion: PayloadCompletion) -> bool
where
    P: CallbackPayload,
{
    match claim.complete() {
        Ok(payload) => {
            let _ = match completion {
                PayloadCompletion::Decision(decision) => payload.complete_callback(decision),
                PayloadCompletion::Invalid => payload.complete_invalid(),
                PayloadCompletion::Terminal => {
                    payload.complete_terminal(PendingTerminalCause::RequestCancelled)
                }
            };
            false
        }
        Err(terminal) => {
            let cause = terminal.cause();
            terminal.into_payload().complete_terminal(cause);
            true
        }
    }
}

async fn fill_store<R>(reader: &mut R, store: &mut ParserStore, deadline: Instant) -> ReadResult
where
    R: AsyncRead + Unpin,
{
    if store.writable().is_empty() {
        return ReadResult::Failed;
    }
    match tokio::time::timeout_at(deadline, reader.read(store.writable())).await {
        Ok(Ok(0)) => ReadResult::EndOfStream,
        Ok(Ok(read)) if store.commit_written(read).is_ok() => ReadResult::Read,
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => ReadResult::Failed,
    }
}

enum ReadResult {
    Read,
    EndOfStream,
    Failed,
}

enum ClaimedEntityResult {
    Decision(CallbackResponseDecision),
    Rejected(EmptyResponseStatus),
    Terminal,
    Failed,
}

enum PayloadCompletion {
    Decision(CallbackResponseDecision),
    Invalid,
    Terminal,
}

enum TeardownResult {
    Complete,
    Terminal,
    BodyTimeout,
}

trait CallbackPayload: Sized {
    fn provider(&self) -> &WebhookProvider;
    fn response_charge(&self) -> &ProviderResponseCharge;
    fn wait_for_delivery_teardown(&self) -> impl Future<Output = ()> + Send;
    fn complete_callback(self, decision: CallbackResponseDecision) -> bool;
    fn complete_invalid(self) -> bool;
    fn complete_terminal(self, cause: PendingTerminalCause) -> bool;
}

impl CallbackPayload for PendingWebhookOperation {
    fn provider(&self) -> &WebhookProvider {
        self.provider()
    }

    fn response_charge(&self) -> &ProviderResponseCharge {
        self.response_charge()
    }

    fn wait_for_delivery_teardown(&self) -> impl Future<Output = ()> + Send {
        self.wait_for_delivery_teardown()
    }

    fn complete_callback(self, decision: CallbackResponseDecision) -> bool {
        self.complete_callback(decision)
    }

    fn complete_invalid(self) -> bool {
        self.complete(Err(WebhookCompletionError::InvalidResponse))
    }

    fn complete_terminal(self, cause: PendingTerminalCause) -> bool {
        self.complete(Err(WebhookCompletionError::Terminal(cause)))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::oneshot;

    use super::*;
    use crate::authorization::callback::{PendingDeadline, PendingOperationGuard};
    use crate::authorization::webhook::runtime::DeliveryTeardown;
    use crate::config::compiler::{
        CompiledProviderFailureMode, PendingOperationLimit, ProviderOutputPlan, WebhookProviderPlan,
    };
    use crate::safety::{HttpWireBodyGuard, WireBodyPool, WireBodyQuotaKey};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RecordedCompletion {
        Allow,
        Deny,
        Pass,
        Invalid,
        Terminal(PendingTerminalCause),
    }

    struct FakePayload {
        provider: Arc<WebhookProvider>,
        response_charge: ProviderResponseCharge,
        teardown: DeliveryTeardown,
        completion: oneshot::Sender<RecordedCompletion>,
    }

    impl CallbackPayload for FakePayload {
        fn provider(&self) -> &WebhookProvider {
            &self.provider
        }

        fn response_charge(&self) -> &ProviderResponseCharge {
            &self.response_charge
        }

        fn wait_for_delivery_teardown(&self) -> impl Future<Output = ()> + Send {
            self.teardown.wait()
        }

        fn complete_callback(self, decision: CallbackResponseDecision) -> bool {
            let completion = match decision {
                CallbackResponseDecision::Allow(_) => RecordedCompletion::Allow,
                CallbackResponseDecision::Deny => RecordedCompletion::Deny,
                CallbackResponseDecision::Pass => RecordedCompletion::Pass,
            };
            self.completion.send(completion).is_ok()
        }

        fn complete_invalid(self) -> bool {
            self.completion.send(RecordedCompletion::Invalid).is_ok()
        }

        fn complete_terminal(self, cause: PendingTerminalCause) -> bool {
            self.completion
                .send(RecordedCompletion::Terminal(cause))
                .is_ok()
        }
    }

    struct AdmittedCallback {
        store: PendingCapabilityStore<FakePayload>,
        token: String,
        operation: PendingOperationGuard<FakePayload>,
        completion: oneshot::Receiver<RecordedCompletion>,
        guard: HttpWireBodyGuard,
        teardown: DeliveryTeardown,
    }

    fn provider(max_response_bytes: usize) -> Arc<WebhookProvider> {
        let mut outputs = BTreeMap::new();
        outputs.insert(
            "api_token".to_string(),
            ProviderOutputPlan::Bearer { required: true },
        );
        WebhookProvider::activate(
            WebhookProviderPlan {
                url: "http://provider.test/authorize".to_string(),
                timeout: Duration::from_secs(30),
                on_failure: CompiledProviderFailureMode::Deny,
                include_headers: Vec::new(),
                max_request_bytes: 8 * 1024,
                max_response_bytes,
                outputs,
                tls: None,
            },
            || false,
        )
        .unwrap()
    }

    fn admit(max_response_bytes: usize, cursor_peak_bytes: usize) -> AdmittedCallback {
        let store = PendingCapabilityStore::new();
        let pool = WireBodyPool::new(cursor_peak_bytes, cursor_peak_bytes);
        let guard = pool.begin_for_test(
            cursor_peak_bytes,
            WireBodyQuotaKey::Peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        );
        let teardown = DeliveryTeardown::new();
        let (completion_tx, completion) = oneshot::channel();
        let now = Instant::now();
        let payload = FakePayload {
            provider: provider(max_response_bytes),
            response_charge: guard.provider_response_charge(),
            teardown: teardown.clone(),
            completion: completion_tx,
        };
        let admission = store
            .try_admit(
                PendingOperationLimit::try_new(4).unwrap(),
                PendingDeadline::earliest(
                    now,
                    now + Duration::from_secs(30),
                    Duration::from_secs(30),
                    Duration::from_secs(30),
                ),
                payload,
            )
            .unwrap();
        let (token, operation) = admission.into_parts();
        AdmittedCallback {
            store,
            token: token.as_str().to_string(),
            operation,
            completion,
            guard,
            teardown,
        }
    }

    fn allow_body(token: &str) -> Vec<u8> {
        format!(
            "{{\"resumeToken\":\"{token}\",\"type\":\"response\",\"decision\":\"allow\",\"values\":{{\"api_token\":\"secret\"}}}}"
        )
        .into_bytes()
    }

    fn deny_body(token: &str) -> Vec<u8> {
        format!("{{\"resumeToken\":\"{token}\",\"type\":\"response\",\"decision\":\"deny\"}}")
            .into_bytes()
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[tokio::test]
    async fn callback_claim_waits_for_delivery_teardown_then_completes_once() {
        let admitted = admit(4096, 128 * 1024);
        let body = allow_body(&admitted.token);
        let mut store = ParserStore::try_new().unwrap();
        store.append(&body).unwrap();
        let mut reader = tokio::io::empty();
        let future = handle_callback_entity_with_store(
            &mut reader,
            &mut store,
            BodyFraming::ContentLength(body.len() as u64),
            &admitted.store,
            4096,
            deadline(),
        );
        tokio::pin!(future);

        assert!(tokio::time::timeout(Duration::from_millis(20), &mut future)
            .await
            .is_err());
        assert_eq!(admitted.store.counts().claimed, 1);
        assert_eq!(admitted.guard.live_bytes(), 0);

        admitted.teardown.complete();
        let outcome = future.await;
        assert_eq!(outcome.response().unwrap().status(), 204);
        assert!(outcome.connection_reusable());
        assert_eq!(
            admitted.completion.await.unwrap(),
            RecordedCompletion::Allow
        );
        assert_eq!(admitted.store.counts().occupancy, 0);
        assert_eq!(admitted.guard.live_bytes(), 0);

        let mut replay_store = ParserStore::try_new().unwrap();
        replay_store.append(&body).unwrap();
        let mut replay_reader = tokio::io::empty();
        let replay = handle_callback_entity_with_store(
            &mut replay_reader,
            &mut replay_store,
            BodyFraming::ContentLength(body.len() as u64),
            &admitted.store,
            4096,
            deadline(),
        )
        .await;
        assert_eq!(replay.response().unwrap().status(), 404);
        drop(admitted.operation);
    }

    #[tokio::test]
    async fn malformed_or_unknown_prefix_never_claims_an_operation() {
        let admitted = admit(4096, 128 * 1024);
        admitted.teardown.complete();
        let unknown = deny_body("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        let mut store = ParserStore::try_new().unwrap();
        store.append(&unknown).unwrap();
        let mut reader = tokio::io::empty();

        let outcome = handle_callback_entity_with_store(
            &mut reader,
            &mut store,
            BodyFraming::ContentLength(unknown.len() as u64),
            &admitted.store,
            4096,
            deadline(),
        )
        .await;
        assert_eq!(outcome.response().unwrap().status(), 404);
        assert_eq!(admitted.store.counts().pending, 1);
        assert_eq!(admitted.store.counts().claimed, 0);
        drop(admitted.operation);
        assert!(admitted.completion.await.is_err());
    }

    #[tokio::test]
    async fn claimed_shape_and_framing_failures_have_distinct_terminal_outcomes() {
        let malformed = admit(4096, 128 * 1024);
        malformed.teardown.complete();
        let body = format!(
            "{{\"resumeToken\":\"{}\",\"type\":\"response\",\"decision\":\"allow\",\"values\":{{\"unknown\":\"secret\"}}}}",
            malformed.token
        )
        .into_bytes();
        let mut store = ParserStore::try_new().unwrap();
        store.append(&body).unwrap();
        let mut reader = tokio::io::empty();
        let outcome = handle_callback_entity_with_store(
            &mut reader,
            &mut store,
            BodyFraming::ContentLength(body.len() as u64),
            &malformed.store,
            4096,
            deadline(),
        )
        .await;
        assert_eq!(outcome.response().unwrap().status(), 400);
        assert_eq!(
            malformed.completion.await.unwrap(),
            RecordedCompletion::Invalid
        );
        assert_eq!(malformed.store.counts().occupancy, 0);
        assert_eq!(malformed.guard.live_bytes(), 0);
        drop(malformed.operation);

        let bad_framing = admit(4096, 128 * 1024);
        bad_framing.teardown.complete();
        let entity = deny_body(&bad_framing.token);
        let chunked = format!(
            "{:x}\r\n{}\r\n0\r\nforbidden: trailer\r\n\r\n",
            entity.len(),
            String::from_utf8(entity).unwrap()
        );
        let mut store = ParserStore::try_new().unwrap();
        store.append(chunked.as_bytes()).unwrap();
        let outcome = handle_callback_entity_with_store(
            &mut reader,
            &mut store,
            BodyFraming::Chunked,
            &bad_framing.store,
            4096,
            deadline(),
        )
        .await;
        assert_eq!(outcome.response(), None);
        assert_eq!(
            bad_framing.completion.await.unwrap(),
            RecordedCompletion::Invalid
        );
        assert_eq!(bad_framing.store.counts().occupancy, 0);
        drop(bad_framing.operation);
    }

    #[tokio::test]
    async fn callback_static_limit_and_charge_failure_map_to_fixed_statuses() {
        let oversized = admit(4096, 128 * 1024);
        let mut store = ParserStore::try_new().unwrap();
        let mut reader = tokio::io::empty();
        let outcome = handle_callback_entity_with_store(
            &mut reader,
            &mut store,
            BodyFraming::ContentLength(4097),
            &oversized.store,
            4096,
            deadline(),
        )
        .await;
        assert_eq!(outcome.response().unwrap().status(), 413);
        assert_eq!(oversized.store.counts().pending, 1);
        drop(oversized.operation);

        let charge_failure = admit(4096, 1);
        charge_failure.teardown.complete();
        let body = allow_body(&charge_failure.token);
        store.append(&body).unwrap();
        let outcome = handle_callback_entity_with_store(
            &mut reader,
            &mut store,
            BodyFraming::ContentLength(body.len() as u64),
            &charge_failure.store,
            4096,
            deadline(),
        )
        .await;
        assert_eq!(outcome.response().unwrap().status(), 503);
        assert_eq!(
            charge_failure.completion.await.unwrap(),
            RecordedCompletion::Invalid
        );
        assert_eq!(charge_failure.store.counts().occupancy, 0);
        assert_eq!(charge_failure.guard.live_bytes(), 0);
        drop(charge_failure.operation);
    }

    #[tokio::test]
    async fn callback_body_timeout_consumes_a_claim_without_an_application_response() {
        let admitted = admit(4096, 128 * 1024);
        admitted.teardown.complete();
        let prefix = format!("{{\"resumeToken\":\"{}\",", admitted.token);
        let mut store = ParserStore::try_new().unwrap();
        store.append(prefix.as_bytes()).unwrap();
        let (_writer, mut reader) = tokio::io::duplex(64);

        let outcome = handle_callback_entity_with_store(
            &mut reader,
            &mut store,
            BodyFraming::ContentLength(97),
            &admitted.store,
            4096,
            Instant::now() + Duration::from_millis(20),
        )
        .await;
        assert_eq!(outcome.response(), None);
        assert_eq!(
            admitted.completion.await.unwrap(),
            RecordedCompletion::Invalid
        );
        assert_eq!(admitted.store.counts().occupancy, 0);
        drop(admitted.operation);
    }

    #[tokio::test]
    async fn post_claim_terminal_signal_owns_completion_and_returns_not_found() {
        let admitted = admit(4096, 128 * 1024);
        let body = deny_body(&admitted.token);
        let mut store = ParserStore::try_new().unwrap();
        store.append(&body).unwrap();
        let mut reader = tokio::io::empty();
        let future = handle_callback_entity_with_store(
            &mut reader,
            &mut store,
            BodyFraming::ContentLength(body.len() as u64),
            &admitted.store,
            4096,
            deadline(),
        );
        tokio::pin!(future);

        assert!(tokio::time::timeout(Duration::from_millis(20), &mut future)
            .await
            .is_err());
        assert!(matches!(
            admitted
                .operation
                .finish_pending(PendingTerminalCause::RequestDeadline),
            crate::authorization::callback::PendingTerminalResult::ClaimOwns {
                signal_recorded: true
            }
        ));

        let outcome = future.await;
        assert_eq!(outcome.response().unwrap().status(), 404);
        assert_eq!(
            admitted.completion.await.unwrap(),
            RecordedCompletion::Terminal(PendingTerminalCause::RequestDeadline)
        );
        assert_eq!(admitted.store.counts().occupancy, 0);
        drop(admitted.operation);
    }
}
