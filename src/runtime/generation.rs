use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use http::header::HeaderMap;

use tokio::sync::Notify;

use crate::config::compiler::CompiledResourcePlan;
use crate::standalone::StandaloneGenerationPlan;

use super::activation::{BoxFuture, RuntimeError};

const RETIRING_BIT: usize = 1usize << (usize::BITS - 1);
const LEASE_COUNT_MASK: usize = !RETIRING_BIT;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct GenerationId(u64);

impl GenerationId {
    pub(crate) fn get(self) -> u64 {
        self.0
    }

    pub(super) fn new(value: u64) -> Self {
        Self(value)
    }

    #[cfg(test)]
    pub(crate) fn for_test(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ProviderIndex(usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CredentialSourceIndex(usize);

macro_rules! index_registry {
    ($registry:ident, $index:ident, $label:literal) => {
        pub(crate) struct $registry {
            indices: BTreeMap<String, $index>,
        }

        impl $registry {
            pub(crate) fn from_names(names: impl IntoIterator<Item = String>) -> Self {
                let names: BTreeSet<_> = names.into_iter().collect();
                let indices = names
                    .into_iter()
                    .enumerate()
                    .map(|(index, name)| (name, $index(index)))
                    .collect();
                Self { indices }
            }

            pub(crate) fn get(&self, name: &str) -> Option<$index> {
                self.indices.get(name).copied()
            }
        }

        impl fmt::Debug for $registry {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct($label)
                    .field("count", &self.indices.len())
                    .finish()
            }
        }

        impl $index {
            pub(crate) fn get(self) -> usize {
                self.0
            }
        }
    };
}

index_registry!(ProviderRegistry, ProviderIndex, "ProviderRegistry");

impl ProviderRegistry {
    pub(crate) fn len(&self) -> usize {
        self.indices.len()
    }
}
index_registry!(
    CredentialSourceRegistry,
    CredentialSourceIndex,
    "CredentialSourceRegistry"
);

#[cfg(test)]
mod index_registry_tests {
    use super::*;

    #[test]
    fn registries_assign_dense_indices_independent_of_input_order() {
        let forward = ProviderRegistry::from_names([
            "alpha-provider".to_string(),
            "omega-provider".to_string(),
        ]);
        let reverse = ProviderRegistry::from_names([
            "omega-provider".to_string(),
            "alpha-provider".to_string(),
            "alpha-provider".to_string(),
        ]);

        assert_eq!(forward.len(), 2);
        assert_eq!(reverse.len(), 2);
        assert_eq!(forward.get("alpha-provider"), reverse.get("alpha-provider"));
        assert_eq!(forward.get("omega-provider"), reverse.get("omega-provider"));
        assert_eq!(forward.get("alpha-provider").unwrap().get(), 0);
        assert_eq!(forward.get("omega-provider").unwrap().get(), 1);
        assert!(!format!("{forward:?}").contains("alpha-provider"));
    }
}

pub(crate) trait EgressSnapshot: Send + Sync {
    fn identity(&self) -> &Arc<()>;

    fn route(&self) -> &crate::egress::EgressRoute;

    fn origin_tls(&self) -> &crate::egress::OriginTls;
}

pub(crate) trait CredentialResolver: Send + Sync {
    fn inject(
        &self,
        actions: &[crate::credentials::ResolvedCredentialAction],
        headers: &mut HeaderMap,
    ) -> Result<(), crate::credentials::CredentialError>;

    fn extract_inbound(
        &self,
        headers: &mut HeaderMap,
    ) -> Result<crate::credentials::InboundCredentials, crate::credentials::CredentialError>;
}

pub(crate) trait ObservationSnapshot: Send + Sync {
    fn capture_epoch(&self) -> &Arc<crate::observation::CaptureEpoch>;

    fn decision_level(
        &self,
        disposition: http_access_types::DecisionDisposition,
    ) -> Option<crate::config::compiler::CompiledDecisionLogLevel>;
}
pub(crate) trait AuthorizationSnapshot: Send + Sync {
    fn internal_context_headers(&self) -> &[http::HeaderName];

    fn provider_metadata(
        &self,
        provider: ProviderIndex,
    ) -> Option<crate::authorization::AuthorizationProviderMetadata<'_>>;

    fn stage_provider_credentials(
        &self,
        provider: ProviderIndex,
        credentials: &crate::authorization::protocol::ProviderCredentialSet,
        guard: &crate::safety::HttpWireBodyGuard,
    ) -> Result<
        crate::authorization::protocol::StagedProviderCredentialMutation,
        crate::authorization::protocol::ProviderCredentialInjectionError,
    >;

    fn consume_allow_output(
        &self,
        provider: ProviderIndex,
        output: crate::authorization::AuthorizationAllowOutput,
    ) -> Option<(
        Option<crate::authorization::protocol::ProviderCredentialSet>,
        Option<crate::authorization::protocol::ProviderBodyReplacement>,
    )>;

    #[cfg(test)]
    fn bind_allow_output_for_test(
        &self,
        provider: ProviderIndex,
        credentials: Option<crate::authorization::protocol::ProviderCredentialSet>,
        replacement: Option<crate::authorization::protocol::ProviderBodyReplacement>,
    ) -> crate::authorization::AuthorizationAllowOutput;

    fn dispatch<'a>(
        &'a self,
        provider: ProviderIndex,
        context: AuthorizationDispatchContext<'a>,
        guard: &'a crate::safety::HttpWireBodyGuard,
        request_deadline: tokio::time::Instant,
    ) -> BoxFuture<
        'a,
        Result<
            crate::authorization::AuthorizationDecision,
            crate::authorization::AuthorizationDispatchError,
        >,
    >;
}

pub(crate) struct AuthorizationDispatchContext<'a> {
    rule_id: &'a str,
    request: crate::authorization::protocol::ProviderRequest<'a>,
    generation: &'a GenerationLease,
}

impl<'a> AuthorizationDispatchContext<'a> {
    pub(crate) fn into_request(self) -> crate::authorization::protocol::ProviderRequest<'a> {
        self.request
    }

    pub(crate) fn into_webhook_parts(
        self,
    ) -> Result<
        (
            &'a str,
            crate::authorization::protocol::ProviderRequest<'a>,
            GenerationRetention,
        ),
        GenerationRetentionError,
    > {
        let retention = self.generation.retain_for_operation()?;
        Ok((self.rule_id, self.request, retention))
    }
}
pub(crate) trait SafetySnapshot: Send + Sync {
    fn contains_loop_marker(&self, headers: &HeaderMap) -> bool;

    fn inject_loop_marker(
        &self,
        headers: &mut HeaderMap,
        request_id: &str,
    ) -> Result<(), crate::safety::InvalidLoopMarker>;

    fn begin_http_body(
        &self,
        plan: crate::policy::HttpWireBodyPlanIndex,
        quota_key: crate::safety::WireBodyQuotaKey,
    ) -> Result<crate::safety::HttpBodyAdmission, crate::safety::HttpBodyAdmissionError>;

    fn begin_forward_response(
        &self,
        quota_key: crate::safety::WireBodyQuotaKey,
    ) -> Result<crate::safety::ForwardResponseAdmission, crate::safety::ForwardResponseAdmissionError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CleanupReason {
    CandidateRejected,
    Retired,
    Shutdown,
}

pub(crate) trait PublicationGuard {
    /// Transfers candidate-owned resources into the published generation.
    /// This must be infallible because the active snapshot has already swapped.
    fn commit(&mut self);
}

pub(crate) trait GenerationOwner: Send + Sync {
    /// Holds the adapter's final liveness lock until publication commits or the
    /// returned guard is dropped.
    fn publication_guard(&self) -> Result<Box<dyn PublicationGuard + '_>, RuntimeError>;

    /// Notifies owned resources that their generation has begun retirement.
    /// This is called exactly once, synchronously after new lease admission is
    /// closed, so adapters can establish deadlines before lease draining.
    /// Rejected unpublished candidates do not receive this notification.
    /// Implementations must not block or panic.
    fn retirement_started(&self, reason: CleanupReason);

    /// Idempotently stops and joins resources owned by this candidate or
    /// generation. Implementations must remain cancellation-safe themselves.
    fn cleanup(&self, reason: CleanupReason) -> BoxFuture<'_, ()>;
}

pub(crate) struct ActivatedGeneration {
    pub(crate) standalone: StandaloneGenerationPlan,
    pub(crate) request_timeout: Duration,
    pub(crate) max_content_decoding_expansion_ratio: usize,
    pub(crate) resource_plan: CompiledResourcePlan,
    pub(crate) egress: Arc<dyn EgressSnapshot>,
    pub(crate) authorization: Arc<dyn AuthorizationSnapshot>,
    pub(crate) credentials: Arc<dyn CredentialResolver>,
    pub(crate) observation: Arc<dyn ObservationSnapshot>,
    pub(crate) safety: Arc<dyn SafetySnapshot>,
    pub(crate) owner: Arc<dyn GenerationOwner>,
}

pub(crate) struct Generation {
    id: GenerationId,
    standalone: StandaloneGenerationPlan,
    request_timeout: Duration,
    max_content_decoding_expansion_ratio: usize,
    resource_plan: CompiledResourcePlan,
    egress: Arc<dyn EgressSnapshot>,
    authorization: Arc<dyn AuthorizationSnapshot>,
    credentials: Arc<dyn CredentialResolver>,
    observation: Arc<dyn ObservationSnapshot>,
    safety: Arc<dyn SafetySnapshot>,
    pub(super) owner: Arc<dyn GenerationOwner>,
    leases: AtomicUsize,
    leases_drained: Notify,
}

impl fmt::Debug for Generation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Generation")
            .field("id", &self.id)
            .field("request_timeout", &self.request_timeout)
            .field(
                "max_content_decoding_expansion_ratio",
                &self.max_content_decoding_expansion_ratio,
            )
            .finish_non_exhaustive()
    }
}

impl Generation {
    pub(super) fn from_activated(id: GenerationId, value: ActivatedGeneration) -> Self {
        Self {
            id,
            standalone: value.standalone,
            request_timeout: value.request_timeout,
            max_content_decoding_expansion_ratio: value.max_content_decoding_expansion_ratio,
            resource_plan: value.resource_plan,
            egress: value.egress,
            authorization: value.authorization,
            credentials: value.credentials,
            observation: value.observation,
            safety: value.safety,
            owner: value.owner,
            leases: AtomicUsize::new(0),
            leases_drained: Notify::new(),
        }
    }

    pub(crate) fn id(&self) -> GenerationId {
        self.id
    }

    #[cfg(test)]
    pub(crate) fn standalone(&self) -> &StandaloneGenerationPlan {
        &self.standalone
    }

    pub(crate) fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    pub(crate) fn max_content_decoding_expansion_ratio(&self) -> usize {
        self.max_content_decoding_expansion_ratio
    }

    pub(crate) fn resource_plan(&self) -> &CompiledResourcePlan {
        &self.resource_plan
    }

    pub(crate) fn egress(&self) -> &dyn EgressSnapshot {
        self.egress.as_ref()
    }

    pub(crate) fn authorization(&self) -> &dyn AuthorizationSnapshot {
        self.authorization.as_ref()
    }

    pub(crate) fn credentials(&self) -> &dyn CredentialResolver {
        self.credentials.as_ref()
    }

    pub(crate) fn observation(&self) -> &dyn ObservationSnapshot {
        self.observation.as_ref()
    }

    pub(crate) fn safety(&self) -> &dyn SafetySnapshot {
        self.safety.as_ref()
    }

    pub(super) fn try_lease(self: &Arc<Self>) -> Option<GenerationLease> {
        let mut state = self.leases.load(Ordering::Acquire);
        loop {
            if state & RETIRING_BIT != 0 {
                return None;
            }
            let count = state & LEASE_COUNT_MASK;
            assert!(count < LEASE_COUNT_MASK, "generation lease count overflow");
            match self.leases.compare_exchange_weak(
                state,
                state + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(GenerationLease {
                        generation: self.clone(),
                    })
                }
                Err(current) => state = current,
            }
        }
    }

    fn retain_existing(self: &Arc<Self>) -> Result<GenerationRetention, GenerationRetentionError> {
        let mut state = self.leases.load(Ordering::Acquire);
        loop {
            let count = state & LEASE_COUNT_MASK;
            debug_assert!(
                count > 0,
                "an operation retention is derived from a live generation lease"
            );
            if count == LEASE_COUNT_MASK {
                return Err(GenerationRetentionError::CountExhausted);
            }
            match self.leases.compare_exchange_weak(
                state,
                state + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(GenerationRetention {
                        generation: self.clone(),
                    })
                }
                Err(current) => state = current,
            }
        }
    }

    pub(super) fn begin_retirement(&self) {
        let previous = self.leases.fetch_or(RETIRING_BIT, Ordering::AcqRel);
        if previous & RETIRING_BIT == 0 && previous & LEASE_COUNT_MASK == 0 {
            self.leases_drained.notify_waiters();
        }
    }

    pub(super) async fn wait_for_leases(&self) {
        loop {
            let notified = self.leases_drained.notified();
            let state = self.leases.load(Ordering::Acquire);
            if state & RETIRING_BIT != 0 && state & LEASE_COUNT_MASK == 0 {
                return;
            }
            notified.await;
        }
    }
}

pub(crate) struct GenerationLease {
    generation: Arc<Generation>,
}

pub(crate) struct ForwardingGenerationServices {
    egress: Arc<dyn EgressSnapshot>,
    credentials: Arc<dyn CredentialResolver>,
    safety: Arc<dyn SafetySnapshot>,
}

impl ForwardingGenerationServices {
    pub(crate) fn egress(&self) -> &dyn EgressSnapshot {
        self.egress.as_ref()
    }

    pub(crate) fn inject_credentials(
        &self,
        actions: &[crate::credentials::ResolvedCredentialAction],
        headers: &mut HeaderMap,
    ) -> Result<(), crate::credentials::CredentialError> {
        self.credentials.inject(actions, headers)
    }

    pub(crate) fn inject_loop_marker(
        &self,
        headers: &mut HeaderMap,
        request_id: &str,
    ) -> Result<(), crate::safety::InvalidLoopMarker> {
        self.safety.inject_loop_marker(headers, request_id)
    }

    pub(crate) fn begin_response(
        &self,
        quota_key: crate::safety::WireBodyQuotaKey,
    ) -> Result<crate::safety::ForwardResponseAdmission, crate::safety::ForwardResponseAdmissionError>
    {
        self.safety.begin_forward_response(quota_key)
    }
}

impl GenerationLease {
    pub(crate) fn standalone(&self) -> &StandaloneGenerationPlan {
        &self.generation.standalone
    }

    /// Retains this exact generation for an operation admitted by the current
    /// request. Retirement may already have started; the live request lease is
    /// the authority to extend only its captured generation.
    pub(crate) fn retain_for_operation(
        &self,
    ) -> Result<GenerationRetention, GenerationRetentionError> {
        self.generation.retain_existing()
    }

    pub(crate) fn into_forwarding_services(self) -> ForwardingGenerationServices {
        ForwardingGenerationServices {
            egress: Arc::clone(&self.generation.egress),
            credentials: Arc::clone(&self.generation.credentials),
            safety: Arc::clone(&self.generation.safety),
        }
    }

    pub(crate) fn dispatch_authorization<'a>(
        &'a self,
        provider: ProviderIndex,
        rule_id: &'a str,
        request: crate::authorization::protocol::ProviderRequest<'a>,
        guard: &'a crate::safety::HttpWireBodyGuard,
        request_deadline: tokio::time::Instant,
    ) -> BoxFuture<
        'a,
        Result<
            crate::authorization::AuthorizationDecision,
            crate::authorization::AuthorizationDispatchError,
        >,
    > {
        self.generation.authorization.dispatch(
            provider,
            AuthorizationDispatchContext {
                rule_id,
                request,
                generation: self,
            },
            guard,
            request_deadline,
        )
    }
}

impl Deref for GenerationLease {
    type Target = Generation;

    fn deref(&self) -> &Self::Target {
        &self.generation
    }
}

impl Drop for GenerationLease {
    fn drop(&mut self) {
        release_retention(&self.generation);
    }
}

/// Opaque operation-owned liveness for one captured generation. It exposes no
/// snapshot cloning or admission path and can only be derived from a live lease.
pub(crate) struct GenerationRetention {
    generation: Arc<Generation>,
}

impl GenerationRetention {
    pub(crate) fn id(&self) -> GenerationId {
        self.generation.id()
    }

    pub(crate) fn egress(&self) -> &dyn EgressSnapshot {
        self.generation.egress()
    }
}

impl fmt::Debug for GenerationRetention {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationRetention")
            .field("generation", &self.id())
            .finish()
    }
}

impl Drop for GenerationRetention {
    fn drop(&mut self) {
        release_retention(&self.generation);
    }
}

fn release_retention(generation: &Generation) {
    let previous = generation.leases.fetch_sub(1, Ordering::AcqRel);
    debug_assert_ne!(previous & LEASE_COUNT_MASK, 0);
    if previous & RETIRING_BIT != 0 && previous & LEASE_COUNT_MASK == 1 {
        generation.leases_drained.notify_waiters();
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum GenerationRetentionError {
    #[error("generation operation-retention count is exhausted")]
    CountExhausted,
}
