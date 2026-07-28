use access_tls_trust::{PreparedTlsClientTrust, TlsTrustLoadError};
use rustls::ClientConfig;

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum TlsActivationError {
    #[error("TLS activation was cancelled")]
    ActivationCancelled,
    #[error("system TLS trust store is empty")]
    SystemStoreEmpty,
    #[error("system TLS trust store is unavailable")]
    SystemStoreUnavailable,
    #[error("custom TLS trust source is untrusted")]
    UntrustedSource,
    #[error("TLS trust material is invalid")]
    InvalidMaterial,
    #[error("TLS trust resource limit was exceeded")]
    ResourceLimit,
    #[error("TLS trust generation limit was exceeded")]
    TrustGenerationLimit,
    #[error("TLS trust plan is invalid")]
    InvalidPlan,
    #[error("TLS trust loader is unavailable")]
    LoaderUnavailable,
    #[error("TLS trust reload is blocked by a late operation")]
    ReloadBlocked,
    #[error("TLS client configuration is unavailable")]
    Internal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientAlpn {
    Http1,
}

impl ClientAlpn {
    fn protocols(self) -> Vec<Vec<u8>> {
        match self {
            Self::Http1 => vec![b"http/1.1".to_vec()],
        }
    }
}

pub(crate) fn build_client_config(
    trust: &PreparedTlsClientTrust,
    alpn: ClientAlpn,
    enable_sni: bool,
) -> Result<ClientConfig, TlsActivationError> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsActivationError::Internal)?;
    let mut config = trust
        .install_into_rustls_builder(builder)
        .map_err(TlsActivationError::from)?
        .with_no_client_auth();
    config.alpn_protocols = alpn.protocols();
    config.enable_sni = enable_sni;
    Ok(config)
}

impl From<TlsTrustLoadError> for TlsActivationError {
    fn from(error: TlsTrustLoadError) -> Self {
        match error {
            TlsTrustLoadError::SystemStoreEmpty => Self::SystemStoreEmpty,
            TlsTrustLoadError::SystemStoreUnavailable => Self::SystemStoreUnavailable,
            TlsTrustLoadError::UntrustedSource => Self::UntrustedSource,
            TlsTrustLoadError::InvalidMaterial => Self::InvalidMaterial,
            TlsTrustLoadError::ResourceLimit => Self::ResourceLimit,
            TlsTrustLoadError::InvalidPlan => Self::InvalidPlan,
            TlsTrustLoadError::Cancelled => Self::ActivationCancelled,
            TlsTrustLoadError::Internal => Self::Internal,
        }
    }
}
