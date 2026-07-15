pub(crate) mod callback;
pub(crate) mod process;
mod process_effects;
pub(crate) mod process_response;
pub(crate) mod protocol;
mod snapshot;
pub(crate) mod webhook;

pub(crate) use snapshot::{
    ActivatedProviderOutputBinding, AuthorizationActivation, AuthorizationActivationError,
    AuthorizationAllowOutput, AuthorizationDecision, AuthorizationDispatchError,
    AuthorizationProviderMetadata, ProductAuthorizationSnapshot,
};
