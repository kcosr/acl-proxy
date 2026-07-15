use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use http_access_types::CanonicalUrl;
use http_access_url::{canonicalize_http_url, UrlError};
use tokio::sync::{oneshot, Notify};

#[cfg(test)]
use super::pool::WebhookTransportArenaCounts;
use super::pool::{
    WebhookTransportAdmissionError, WebhookTransportArena, WebhookTransportArenaError,
    WebhookTransportLease,
};
use super::provider::WebhookProvider;
use super::request::{WebhookRequest, WebhookRequestError};
use super::transport::{connect_and_deliver, WebhookDeliveryError};
use crate::authorization::callback::{
    CallbackResponseDecision, PendingCapabilityStore, PendingDeadline, PendingTerminalCause,
    PendingTerminalResult,
};
use crate::authorization::protocol::{ProviderCredentialSet, ProviderDecision};
use crate::config::compiler::AuthorizationCallbackPlan;
use crate::config::StaticProductConfig;
#[cfg(test)]
use crate::destination::DestinationFacts;
use crate::destination::{DestinationGuard, DestinationGuardError};
use crate::runtime::{AuthorizationDispatchContext, GenerationRetention, GenerationRetentionError};
use crate::safety::wire_body::ProviderResponseCharge;
use crate::safety::HttpWireBodyGuard;

pub(crate) struct WebhookAuthorizationRuntime {
    transport: WebhookTransportArena,
    destination: Arc<DestinationGuard>,
    pending: PendingCapabilityStore<PendingWebhookOperation>,
    callback_url: Option<CanonicalUrl>,
    accepting: Mutex<bool>,
}

pub(crate) struct PendingWebhookOperation {
    _retention: GenerationRetention,
    provider: Arc<WebhookProvider>,
    response_charge: ProviderResponseCharge,
    delivery_teardown: DeliveryTeardown,
    completion: oneshot::Sender<Result<ProviderDecision, WebhookCompletionError>>,
}

#[derive(Clone)]
pub(crate) struct DeliveryTeardown {
    inner: Arc<DeliveryTeardownInner>,
}

pub(crate) struct DeliveryTeardownGuard {
    teardown: DeliveryTeardown,
}

struct DeliveryTeardownInner {
    complete: AtomicBool,
    changed: Notify,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum WebhookCompletionError {
    #[error("webhook callback response was invalid")]
    InvalidResponse,
    #[error("webhook operation ended before a callback response: {0:?}")]
    Terminal(PendingTerminalCause),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WebhookAuthorizationRuntimeError {
    #[error("webhook transport arena configuration is invalid")]
    Transport(#[from] WebhookTransportArenaError),
    #[error("webhook destination facts are invalid")]
    Destination(#[from] DestinationGuardError),
    #[error("callback public URL is invalid")]
    CallbackUrl(#[from] UrlError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WebhookDispatchError {
    #[error("webhook callback configuration is unavailable")]
    CallbackUnavailable,
    #[error("webhook generation retention failed")]
    Retention(#[from] GenerationRetentionError),
    #[error("webhook transport admission failed")]
    Transport(#[from] WebhookTransportAdmissionError),
    #[error("webhook request preparation failed")]
    Request(#[from] WebhookRequestError),
    #[error("webhook pending operation admission failed")]
    PendingAdmission,
    #[error("webhook delivery failed")]
    Delivery(#[from] WebhookDeliveryError),
    #[error("webhook acknowledgement status was not successful: {0}")]
    AcknowledgementStatus(u16),
    #[error("webhook operation ended: {0:?}")]
    Terminal(PendingTerminalCause),
    #[error("webhook callback failed")]
    Callback(#[from] WebhookCompletionError),
    #[error("webhook callback completion channel closed")]
    CompletionClosed,
    #[error("webhook authorization admission is closed")]
    AdmissionClosed,
    #[error("webhook authorization admission gate failed")]
    AdmissionPoisoned,
}

impl WebhookAuthorizationRuntime {
    pub(crate) fn try_new(
        static_config: &StaticProductConfig,
        destination: Arc<DestinationGuard>,
    ) -> Result<Arc<Self>, WebhookAuthorizationRuntimeError> {
        let callback_url = static_config
            .callback_public_url
            .as_deref()
            .map(canonicalize_http_url)
            .transpose()?;
        Ok(Arc::new(Self {
            transport: WebhookTransportArena::try_new(
                static_config.service.max_active_webhook_deliveries,
                static_config.service.webhook_transport_buffer_bytes,
                static_config.service.max_webhook_transport_bytes,
            )?,
            destination,
            pending: PendingCapabilityStore::new(),
            callback_url,
            accepting: Mutex::new(true),
        }))
    }

    #[cfg(test)]
    pub(crate) fn for_test(callback_url: Option<&str>) -> Arc<Self> {
        Self::for_test_with_destination(
            callback_url,
            DestinationGuard::system(DestinationFacts::for_test([], None, None, 16).unwrap()),
        )
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_destination(
        callback_url: Option<&str>,
        destination: DestinationGuard,
    ) -> Arc<Self> {
        Arc::new(Self {
            transport: WebhookTransportArena::try_new(1, 64 * 1024, 128 * 1024).unwrap(),
            destination: Arc::new(destination),
            pending: PendingCapabilityStore::new(),
            callback_url: callback_url.map(|url| canonicalize_http_url(url).unwrap()),
            accepting: Mutex::new(true),
        })
    }

    pub(crate) fn try_acquire_transport(
        &self,
    ) -> Result<WebhookTransportLease, WebhookTransportAdmissionError> {
        self.transport.try_acquire()
    }

    #[cfg(test)]
    pub(crate) fn transport_counts(&self) -> WebhookTransportArenaCounts {
        self.transport.counts()
    }

    pub(crate) fn begin_shutdown(&self, drain_deadline: Option<tokio::time::Instant>) {
        let mut accepting = self
            .accepting
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *accepting = false;
        self.transport.begin_shutdown();
        self.pending.begin_shutdown(drain_deadline);
    }

    pub(crate) async fn wait_until_drained(&self) {
        self.transport.wait_until_empty().await;
        self.pending.wait_until_empty().await;
    }

    pub(crate) fn final_cancel_all(&self, cause: PendingTerminalCause) {
        for terminal in self.pending.final_cancel_all(cause) {
            let cause = terminal.cause();
            let payload = terminal.into_payload();
            payload.complete(Err(WebhookCompletionError::Terminal(cause)));
        }
    }

    #[cfg(test)]
    pub(crate) fn destination_guard(&self) -> &Arc<DestinationGuard> {
        &self.destination
    }

    pub(crate) fn pending_store(&self) -> &PendingCapabilityStore<PendingWebhookOperation> {
        &self.pending
    }

    pub(crate) fn callback_url(&self) -> Option<&CanonicalUrl> {
        self.callback_url.as_ref()
    }

    pub(crate) async fn dispatch(
        &self,
        provider: Arc<WebhookProvider>,
        callback: &AuthorizationCallbackPlan,
        context: AuthorizationDispatchContext<'_>,
        guard: &HttpWireBodyGuard,
        request_deadline: tokio::time::Instant,
    ) -> Result<ProviderDecision, WebhookDispatchError> {
        let dispatch_start = tokio::time::Instant::now();
        let (transport, deadline, teardown_guard, receiver, operation, request_body) = {
            let accepting = self
                .accepting
                .lock()
                .map_err(|_| WebhookDispatchError::AdmissionPoisoned)?;
            if !*accepting {
                return Err(WebhookDispatchError::AdmissionClosed);
            }
            let transport = self.try_acquire_transport()?;
            let callback_url = self
                .callback_url()
                .ok_or(WebhookDispatchError::CallbackUnavailable)?;
            let (rule_id, request, retention) = context.into_webhook_parts()?;
            let request = WebhookRequest::from_provider(rule_id, request);
            let prepared =
                request.prepare(callback_url.as_str(), provider.max_request_bytes(), guard)?;
            let deadline = PendingDeadline::earliest(
                dispatch_start,
                request_deadline,
                provider.timeout(),
                callback.resume_token_ttl,
            );
            let teardown = DeliveryTeardown::new();
            let teardown_guard = teardown.completion_guard();
            let (completion, receiver) = oneshot::channel();
            let payload = PendingWebhookOperation::new(
                retention,
                provider.clone(),
                guard.provider_response_charge(),
                teardown,
                completion,
            );
            let admission = self
                .pending
                .try_admit(callback.max_pending_operations, deadline, payload)
                .map_err(|_| WebhookDispatchError::PendingAdmission)?;
            let (token, operation) = admission.into_parts();
            let request_body = prepared.finish(&token)?;
            drop(token);
            (
                transport,
                deadline,
                teardown_guard,
                receiver,
                operation,
                request_body,
            )
        };

        let signal = operation.signal_handle();
        let cancellation_signal = signal.clone();
        let cancellation = async {
            tokio::select! {
                biased;
                _ = cancellation_signal.wait_until_not_pending() => {}
                _ = tokio::time::sleep_until(deadline.at()) => {}
            }
        };
        let delivery = connect_and_deliver(
            &self.destination,
            &provider,
            transport,
            request_body,
            cancellation,
        )
        .await;
        drop(teardown_guard);

        match delivery {
            Ok(acknowledgement) if (200..300).contains(&acknowledgement.status) => {}
            Ok(acknowledgement) => {
                return terminal_delivery_result(
                    operation,
                    receiver,
                    PendingTerminalCause::DeliveryFailed,
                    WebhookDispatchError::AcknowledgementStatus(acknowledgement.status),
                )
                .await;
            }
            Err(WebhookDeliveryError::Cancelled) if !signal.is_pending() => {}
            Err(WebhookDeliveryError::Cancelled) => {
                return terminal_delivery_result(
                    operation,
                    receiver,
                    deadline.cause(),
                    WebhookDispatchError::Terminal(deadline.cause()),
                )
                .await;
            }
            Err(error) => {
                return terminal_delivery_result(
                    operation,
                    receiver,
                    PendingTerminalCause::DeliveryFailed,
                    WebhookDispatchError::Delivery(error),
                )
                .await;
            }
        }

        await_callback(operation, receiver).await
    }
}

async fn terminal_delivery_result(
    operation: crate::authorization::callback::PendingOperationGuard<PendingWebhookOperation>,
    receiver: oneshot::Receiver<Result<ProviderDecision, WebhookCompletionError>>,
    cause: PendingTerminalCause,
    error: WebhookDispatchError,
) -> Result<ProviderDecision, WebhookDispatchError> {
    match operation.finish_pending(cause) {
        PendingTerminalResult::Won(terminal) => {
            drop(terminal);
            Err(error)
        }
        PendingTerminalResult::ClaimOwns { .. } => await_callback(operation, receiver).await,
        PendingTerminalResult::AlreadyTerminal => await_callback(operation, receiver).await,
    }
}

async fn await_callback(
    operation: crate::authorization::callback::PendingOperationGuard<PendingWebhookOperation>,
    mut receiver: oneshot::Receiver<Result<ProviderDecision, WebhookCompletionError>>,
) -> Result<ProviderDecision, WebhookDispatchError> {
    tokio::select! {
        biased;
        result = &mut receiver => {
            drop(operation);
            result
                .map_err(|_| WebhookDispatchError::CompletionClosed)?
                .map_err(map_completion_error)
        }
        terminal = operation.expire_at_deadline() => {
            match terminal {
                PendingTerminalResult::Won(terminal) => {
                    let cause = terminal.cause();
                    drop(terminal);
                    Err(WebhookDispatchError::Terminal(cause))
                }
                PendingTerminalResult::ClaimOwns { .. }
                | PendingTerminalResult::AlreadyTerminal => receiver
                    .await
                    .map_err(|_| WebhookDispatchError::CompletionClosed)?
                    .map_err(map_completion_error),
            }
        }
    }
}

fn map_completion_error(error: WebhookCompletionError) -> WebhookDispatchError {
    match error {
        WebhookCompletionError::Terminal(cause) => WebhookDispatchError::Terminal(cause),
        other => WebhookDispatchError::Callback(other),
    }
}

impl PendingWebhookOperation {
    pub(crate) fn new(
        retention: GenerationRetention,
        provider: Arc<WebhookProvider>,
        response_charge: ProviderResponseCharge,
        delivery_teardown: DeliveryTeardown,
        completion: oneshot::Sender<Result<ProviderDecision, WebhookCompletionError>>,
    ) -> Self {
        Self {
            _retention: retention,
            provider,
            response_charge,
            delivery_teardown,
            completion,
        }
    }

    pub(crate) fn provider(&self) -> &Arc<WebhookProvider> {
        &self.provider
    }

    pub(crate) fn response_charge(&self) -> &ProviderResponseCharge {
        &self.response_charge
    }

    pub(crate) async fn wait_for_delivery_teardown(&self) {
        self.delivery_teardown.wait().await;
    }

    pub(crate) fn complete(self, result: Result<ProviderDecision, WebhookCompletionError>) -> bool {
        self.completion.send(result).is_ok()
    }

    pub(crate) fn complete_callback(self, decision: CallbackResponseDecision) -> bool {
        let decision = match decision {
            CallbackResponseDecision::Allow(credentials) => ProviderDecision::Allow {
                credentials: ProviderCredentialSet::from_segmented(credentials),
                replacement: None,
            },
            CallbackResponseDecision::Deny => ProviderDecision::Deny,
            CallbackResponseDecision::Pass => ProviderDecision::Pass,
        };
        self.complete(Ok(decision))
    }
}

impl DeliveryTeardown {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(DeliveryTeardownInner {
                complete: AtomicBool::new(false),
                changed: Notify::new(),
            }),
        }
    }

    pub(crate) fn complete(&self) {
        if !self.inner.complete.swap(true, Ordering::AcqRel) {
            self.inner.changed.notify_waiters();
        }
    }

    pub(crate) fn completion_guard(&self) -> DeliveryTeardownGuard {
        DeliveryTeardownGuard {
            teardown: self.clone(),
        }
    }

    pub(crate) async fn wait(&self) {
        loop {
            let changed = self.inner.changed.notified();
            if self.inner.complete.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
}

impl Drop for DeliveryTeardownGuard {
    fn drop(&mut self) {
        self.teardown.complete();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn delivery_teardown_guard_releases_callback_waiter_on_drop() {
        let teardown = DeliveryTeardown::new();
        let guard = teardown.completion_guard();
        let waiter_teardown = teardown.clone();
        let waiter = tokio::spawn(async move { waiter_teardown.wait().await });

        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(guard);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("teardown completion wakes callback waiter")
            .unwrap();
    }
}
