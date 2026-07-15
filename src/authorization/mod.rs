pub(crate) mod callback;
pub(crate) mod process;
mod process_effects;
pub(crate) mod process_response;
pub(crate) mod protocol;
mod snapshot;
pub(crate) mod webhook;

pub(crate) use snapshot::{
    AuthorizationActivation, AuthorizationActivationError, AuthorizationDecision,
    AuthorizationDispatchError, AuthorizationProviderMetadata, ProductAuthorizationSnapshot,
};
