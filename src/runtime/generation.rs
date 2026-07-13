use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

use crate::config::v3_compile::CompiledResourcePlan;

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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ProviderIndex(pub(crate) usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RedactionProfileIndex(pub(crate) usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CredentialIndex(pub(crate) usize);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedRuleBindings {
    pub(crate) authorization_provider: Option<ProviderIndex>,
    pub(crate) redaction_profile: Option<RedactionProfileIndex>,
    pub(crate) credentials: Box<[CredentialIndex]>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ResolvedBindings {
    pub(crate) provider_count: usize,
    pub(crate) redaction_profile_count: usize,
    pub(crate) credential_count: usize,
    pub(crate) rules: Box<[ResolvedRuleBindings]>,
}

macro_rules! snapshot_handle {
    ($name:ident) => {
        pub(crate) trait $name: Send + Sync {}
    };
}

snapshot_handle!(PolicySnapshot);
snapshot_handle!(EgressSnapshot);
snapshot_handle!(AuthorizationSnapshot);
snapshot_handle!(CredentialResolver);
snapshot_handle!(RedactionSnapshot);
snapshot_handle!(ObservationSnapshot);
snapshot_handle!(SafetySnapshot);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CleanupReason {
    CandidateRejected,
    Retired,
    Shutdown,
}

pub(crate) trait PublicationGuard: Send {
    /// Transfers candidate-owned resources into the published generation.
    /// This must be infallible because the active snapshot has already swapped.
    fn commit(&mut self);
}

pub(crate) trait GenerationOwner: Send + Sync {
    /// Holds the adapter's final liveness lock until publication commits or the
    /// returned guard is dropped.
    fn publication_guard(&self) -> Result<Box<dyn PublicationGuard + '_>, RuntimeError>;

    /// Idempotently stops and joins resources owned by this candidate or
    /// generation. Implementations must remain cancellation-safe themselves.
    fn cleanup(&self, reason: CleanupReason) -> BoxFuture<'_, ()>;
}

pub(crate) struct ActivatedGeneration {
    pub(crate) request_timeout: Duration,
    pub(crate) max_content_decoding_expansion_ratio: usize,
    pub(crate) resource_plan: CompiledResourcePlan,
    pub(crate) bindings: ResolvedBindings,
    pub(crate) policy: Arc<dyn PolicySnapshot>,
    pub(crate) egress: Arc<dyn EgressSnapshot>,
    pub(crate) authorization: Arc<dyn AuthorizationSnapshot>,
    pub(crate) credentials: Arc<dyn CredentialResolver>,
    pub(crate) redaction: Arc<dyn RedactionSnapshot>,
    pub(crate) observation: Arc<dyn ObservationSnapshot>,
    pub(crate) safety: Arc<dyn SafetySnapshot>,
    pub(crate) owner: Arc<dyn GenerationOwner>,
}

pub(crate) struct Generation {
    id: GenerationId,
    request_timeout: Duration,
    max_content_decoding_expansion_ratio: usize,
    resource_plan: CompiledResourcePlan,
    bindings: ResolvedBindings,
    policy: Arc<dyn PolicySnapshot>,
    egress: Arc<dyn EgressSnapshot>,
    authorization: Arc<dyn AuthorizationSnapshot>,
    credentials: Arc<dyn CredentialResolver>,
    redaction: Arc<dyn RedactionSnapshot>,
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
            .field("bindings", &self.bindings)
            .finish_non_exhaustive()
    }
}

impl Generation {
    pub(super) fn from_activated(id: GenerationId, value: ActivatedGeneration) -> Self {
        Self {
            id,
            request_timeout: value.request_timeout,
            max_content_decoding_expansion_ratio: value.max_content_decoding_expansion_ratio,
            resource_plan: value.resource_plan,
            bindings: value.bindings,
            policy: value.policy,
            egress: value.egress,
            authorization: value.authorization,
            credentials: value.credentials,
            redaction: value.redaction,
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

    pub(crate) fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    pub(crate) fn max_content_decoding_expansion_ratio(&self) -> usize {
        self.max_content_decoding_expansion_ratio
    }

    pub(crate) fn resource_plan(&self) -> &CompiledResourcePlan {
        &self.resource_plan
    }

    pub(crate) fn bindings(&self) -> &ResolvedBindings {
        &self.bindings
    }

    pub(crate) fn policy(&self) -> &dyn PolicySnapshot {
        self.policy.as_ref()
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

    pub(crate) fn redaction(&self) -> &dyn RedactionSnapshot {
        self.redaction.as_ref()
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

impl Deref for GenerationLease {
    type Target = Generation;

    fn deref(&self) -> &Self::Target {
        &self.generation
    }
}

impl Drop for GenerationLease {
    fn drop(&mut self) {
        let previous = self.generation.leases.fetch_sub(1, Ordering::AcqRel);
        debug_assert_ne!(previous & LEASE_COUNT_MASK, 0);
        if previous & RETIRING_BIT != 0 && previous & LEASE_COUNT_MASK == 1 {
            self.generation.leases_drained.notify_waiters();
        }
    }
}
