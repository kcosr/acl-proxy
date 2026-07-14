use std::sync::Arc;

use tokio::sync::oneshot;

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

pub(crate) struct WebhookAuthorizationRuntime {
    transport: WebhookTransportArena,
    destination: DestinationGuard,
    pending: PendingCapabilityStore<PendingWebhookOperation>,
}

pub(crate) struct PendingWebhookOperation {
    retention: GenerationRetention,
    provider: Arc<WebhookProvider>,
    response_charge: ProviderResponseCharge,
    completion: oneshot::Sender<Result<ProviderDecision, WebhookCompletionError>>,
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
}

impl WebhookAuthorizationRuntime {
    pub(crate) fn try_new(
        static_config: &StaticProductConfig,
    ) -> Result<Arc<Self>, WebhookAuthorizationRuntimeError> {
        Ok(Arc::new(Self {
            transport: WebhookTransportArena::try_new(
                static_config.service.max_active_webhook_deliveries,
                static_config.service.webhook_transport_buffer_bytes,
                static_config.service.max_webhook_transport_bytes,
            )?,
            destination: DestinationGuard::system(DestinationFacts::from_static(static_config)?),
            pending: PendingCapabilityStore::new(),
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

    pub(crate) fn destination_guard(&self) -> &DestinationGuard {
        &self.destination
    }

    pub(crate) fn pending_store(&self) -> &PendingCapabilityStore<PendingWebhookOperation> {
        &self.pending
    }
}

impl PendingWebhookOperation {
    pub(crate) fn new(
        retention: GenerationRetention,
        provider: Arc<WebhookProvider>,
        response_charge: ProviderResponseCharge,
        completion: oneshot::Sender<Result<ProviderDecision, WebhookCompletionError>>,
    ) -> Self {
        Self {
            retention,
            provider,
            response_charge,
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

    pub(crate) fn complete(
        self,
        result: Result<ProviderDecision, WebhookCompletionError>,
    ) -> Result<(), Result<ProviderDecision, WebhookCompletionError>> {
        self.completion.send(result)
    }
}
