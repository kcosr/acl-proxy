use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::{oneshot, Notify};

use super::pool::{
    WebhookTransportAdmissionError, WebhookTransportArena, WebhookTransportArenaCounts,
    WebhookTransportArenaError, WebhookTransportLease,
};
use super::provider::WebhookProvider;
use crate::authorization::callback::PendingCapabilityStore;
use crate::authorization::protocol::ProviderDecision;
use crate::config::StaticProductConfig;
use crate::destination::{DestinationFacts, DestinationGuard, DestinationGuardError};
use crate::runtime::GenerationRetention;
use crate::safety::wire_body::ProviderResponseCharge;
use crate::url::{canonicalize_http_url, CanonicalUrl, UrlError};

pub(crate) struct WebhookAuthorizationRuntime {
    transport: WebhookTransportArena,
    destination: DestinationGuard,
    pending: PendingCapabilityStore<PendingWebhookOperation>,
    callback_url: Option<CanonicalUrl>,
}

pub(crate) struct PendingWebhookOperation {
    retention: GenerationRetention,
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
    #[error("webhook operation ended before a callback response")]
    Terminal,
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

impl WebhookAuthorizationRuntime {
    pub(crate) fn try_new(
        static_config: &StaticProductConfig,
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
            destination: DestinationGuard::system(DestinationFacts::from_static(static_config)?),
            pending: PendingCapabilityStore::new(),
            callback_url,
        }))
    }

    pub(crate) fn try_acquire_transport(
        &self,
    ) -> Result<WebhookTransportLease, WebhookTransportAdmissionError> {
        self.transport.try_acquire()
    }

    pub(crate) fn transport_counts(&self) -> WebhookTransportArenaCounts {
        self.transport.counts()
    }

    pub(crate) fn begin_transport_shutdown(&self) {
        self.transport.begin_shutdown();
    }

    pub(crate) async fn wait_for_transport_shutdown(&self) {
        self.transport.wait_until_empty().await;
    }

    pub(crate) fn destination_guard(&self) -> &DestinationGuard {
        &self.destination
    }

    pub(crate) fn pending_store(&self) -> &PendingCapabilityStore<PendingWebhookOperation> {
        &self.pending
    }

    pub(crate) fn callback_url(&self) -> Option<&CanonicalUrl> {
        self.callback_url.as_ref()
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
            retention,
            provider,
            response_charge,
            delivery_teardown,
            completion,
        }
    }

    pub(crate) fn generation(&self) -> crate::runtime::GenerationId {
        self.retention.id()
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

    pub(crate) fn complete(
        self,
        result: Result<ProviderDecision, WebhookCompletionError>,
    ) -> Result<(), Result<ProviderDecision, WebhookCompletionError>> {
        self.completion.send(result)
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
