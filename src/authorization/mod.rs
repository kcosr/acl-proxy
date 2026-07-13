pub(crate) mod process;
pub(crate) mod process_response;
pub(crate) mod protocol;
mod snapshot;

#[allow(unused_imports)]
pub(crate) use snapshot::{
    AuthorizationActivation, AuthorizationActivationError, AuthorizationDecision,
    AuthorizationDispatchError, AuthorizationProviderMetadata, ProductAuthorizationSnapshot,
};
