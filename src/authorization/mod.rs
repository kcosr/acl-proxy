pub(crate) mod callback;
pub(crate) mod process;
mod process_effects;
pub(crate) mod process_response;
pub(crate) mod protocol;
mod snapshot;
pub(crate) mod unix_socket;
pub(crate) mod webhook;

pub(crate) const MAX_PROVIDER_RULE_ID_BYTES: usize = http_access_types::StableId::MAX_LEN;

pub(crate) use snapshot::{
    ActivatedProviderOutputBinding, AuthorizationActivation, AuthorizationActivationError,
    AuthorizationAllowOutput, AuthorizationDecision, AuthorizationDispatchError,
    AuthorizationProviderMetadata, ProductAuthorizationSnapshot,
};
