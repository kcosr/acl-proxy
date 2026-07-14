pub(crate) mod callback;
pub(crate) mod process;
mod process_effects;
pub(crate) mod process_response;
pub(crate) mod protocol;
mod snapshot;
pub(crate) mod webhook;

#[allow(unused_imports)]
pub(crate) use snapshot::{
    AuthorizationActivation, AuthorizationActivationError, AuthorizationDecision,
    AuthorizationDispatchError, AuthorizationProviderMetadata, ProductAuthorizationSnapshot,
};
