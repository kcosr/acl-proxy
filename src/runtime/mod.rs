mod activation;
mod core;
mod generation;
mod readiness;

pub(crate) use activation::{
    ActivationCancellation, BoxFuture, CandidateActivator, CandidateSource, RuntimeError,
};
#[cfg(test)]
pub(crate) use core::LifecycleState;
pub(crate) use core::{
    ReloadTriggerResult, Runtime, StaticOwnership, StaticResourceBrand, StaticResources,
};
#[cfg(test)]
pub(crate) use generation::Generation;
pub(crate) use generation::{
    ActivatedGeneration, AuthorizationDispatchContext, AuthorizationInvocationMode,
    AuthorizationSnapshot, CleanupReason, ForwardingGenerationServices, GenerationId,
    GenerationLease, GenerationOwner, GenerationRetention, GenerationRetentionError,
    ObservationSnapshot, ProviderIndex, ProviderRegistry, PublicationGuard, SafetySnapshot,
};
pub(crate) use readiness::ServiceReadiness;

#[cfg(test)]
mod tests;
