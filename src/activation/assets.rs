use std::sync::Arc;

use tokio_rustls::TlsAcceptor;

use http_access_runtime::{ForwardingNetworkError, ForwardingNetworkFacts, ForwardingNetworkGuard};
use http_access_url::canonicalize_http_url;

use crate::certs::{CertError, MitmCertificateManager};
use crate::config::compiler::{CompiledHttpVersion, StaticProductConfig};
use crate::tls_identity::{load_static_tls_acceptor, StaticTlsIdentityError};

pub(crate) struct ProductIngressAssets {
    forwarding_network: Arc<ForwardingNetworkGuard>,
    explicit_https_tls: Option<TlsAcceptor>,
    transparent_https_alpn: Box<[Vec<u8>]>,
    mitm: Option<Arc<MitmCertificateManager>>,
}

impl ProductIngressAssets {
    pub(crate) fn from_static(
        config: &StaticProductConfig,
    ) -> Result<Arc<Self>, ProductIngressAssetsError> {
        let facts = forwarding_network_facts(config)?;
        let forwarding_network = Arc::new(ForwardingNetworkGuard::system(facts));
        Self::from_static_with_forwarding_network(config, forwarding_network)
    }

    fn from_static_with_forwarding_network(
        config: &StaticProductConfig,
        forwarding_network: Arc<ForwardingNetworkGuard>,
    ) -> Result<Arc<Self>, ProductIngressAssetsError> {
        let explicit_https_alpn = config
            .listeners
            .explicit_https
            .as_ref()
            .map(|listener| alpn_protocols(&listener.http_versions))
            .unwrap_or_default();
        let explicit_https_tls = config
            .listeners
            .explicit_https
            .as_ref()
            .map(|listener| {
                load_static_tls_acceptor(
                    &listener.tls.certificate_chain,
                    &listener.tls.private_key,
                    explicit_https_alpn.clone(),
                )
            })
            .transpose()?;
        let transparent_https_alpn = config
            .listeners
            .transparent_https
            .as_ref()
            .map(|listener| alpn_protocols(&listener.http_versions))
            .unwrap_or_default();
        let mitm = config
            .mitm
            .as_ref()
            .map(MitmCertificateManager::from_static)
            .transpose()?
            .map(Arc::new);
        if config.listeners.transparent_https.is_some() && mitm.is_none() {
            return Err(ProductIngressAssetsError::MissingMitmManager);
        }

        Ok(Arc::new(Self {
            forwarding_network,
            explicit_https_tls,
            transparent_https_alpn: transparent_https_alpn.into_boxed_slice(),
            mitm,
        }))
    }

    #[cfg(test)]
    pub(crate) fn with_forwarding_network(
        config: &StaticProductConfig,
        forwarding_network: Arc<ForwardingNetworkGuard>,
    ) -> Result<Arc<Self>, ProductIngressAssetsError> {
        Self::from_static_with_forwarding_network(config, forwarding_network)
    }

    pub(crate) fn forwarding_network(&self) -> &Arc<ForwardingNetworkGuard> {
        &self.forwarding_network
    }

    pub(crate) fn explicit_https_tls(&self) -> Option<&TlsAcceptor> {
        self.explicit_https_tls.as_ref()
    }

    pub(crate) fn transparent_https_alpn(&self) -> &[Vec<u8>] {
        &self.transparent_https_alpn
    }

    pub(crate) fn mitm(&self) -> Option<&Arc<MitmCertificateManager>> {
        self.mitm.as_ref()
    }
}

fn forwarding_network_facts(
    config: &StaticProductConfig,
) -> Result<ForwardingNetworkFacts, ForwardingNetworkError> {
    let listeners = &config.listeners;
    let listener_binds = [
        listeners
            .explicit_http
            .as_ref()
            .map(|listener| listener.bind),
        listeners
            .transparent_http
            .as_ref()
            .map(|listener| listener.bind),
        listeners
            .explicit_https
            .as_ref()
            .map(|listener| listener.bind),
        listeners
            .transparent_https
            .as_ref()
            .map(|listener| listener.bind),
    ]
    .into_iter()
    .flatten()
    .collect();
    let control_bind = config.control.as_ref().map(|control| control.bind);
    let reserved_control_url = config
        .callback_public_url
        .as_deref()
        .map(canonicalize_http_url)
        .transpose()
        .map_err(|_| ForwardingNetworkError::InvalidFacts)?;
    let reserved_control_base_path = reserved_control_url
        .as_ref()
        .and_then(|_| config.control.as_ref())
        .map(|control| control.base_path.clone());

    ForwardingNetworkFacts::new(
        listener_binds,
        control_bind,
        reserved_control_url,
        reserved_control_base_path,
    )
}

fn alpn_protocols(versions: &[CompiledHttpVersion]) -> Vec<Vec<u8>> {
    versions
        .iter()
        .map(|version| match version {
            CompiledHttpVersion::Http1 => b"http/1.1".to_vec(),
            CompiledHttpVersion::Http2 => b"h2".to_vec(),
        })
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductIngressAssetsError {
    #[error(transparent)]
    ForwardingNetwork(#[from] ForwardingNetworkError),
    #[error(transparent)]
    TlsIdentity(#[from] StaticTlsIdentityError),
    #[error(transparent)]
    Mitm(#[from] CertError),
    #[error("transparent HTTPS requires an activated MITM manager")]
    MissingMitmManager,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use http_access_types::{HttpProtocol, Route};
    use rcgen::{CertificateParams, KeyPair};
    use tempfile::tempdir;

    use super::*;
    use crate::config::{compile_config_text, ConfigTextInput};

    #[test]
    fn https_assets_use_each_listeners_exact_compiled_alpn_set() {
        let directory = tempdir().unwrap();
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        fs::write(directory.path().join("server.pem"), certificate.pem()).unwrap();
        fs::write(directory.path().join("server-key.pem"), key.serialize_pem()).unwrap();
        let text = r#"schema_version = 3

[listeners.explicit_https]
bind = "127.0.0.2:31881"
http_versions = ["http2", "http1"]

[listeners.explicit_https.connect]
http1 = "deny"
http2 = "deny"

[listeners.explicit_https.tls]
certificate_chain = "server.pem"
private_key = "server-key.pem"

[listeners.transparent_https]
bind = "127.0.0.2:31882"
http_versions = ["http1"]

[mitm]
mode = "generated"
directory = "mitm"
persist_leaf_certificates = true

[policy]
default = "deny"
"#;
        let source_path = directory.path().join("acl-proxy.toml");
        let compiled = compile_config_text(ConfigTextInput {
            text,
            source_path: &source_path,
            config_root: directory.path(),
        })
        .unwrap();

        let assets = ProductIngressAssets::from_static(&compiled.static_config).unwrap();

        assert!(assets.explicit_https_tls().is_some());
        assert_eq!(assets.transparent_https_alpn(), [b"http/1.1".to_vec()]);
        assert!(assets.mitm().is_some());
        let dynamic_certificates = directory.path().join("mitm/dynamic");
        assert!(dynamic_certificates.is_dir());
        assert_eq!(
            fs::read_dir(dynamic_certificates)
                .expect("read dynamic certificate directory")
                .count(),
            0
        );
        assert_eq!(Arc::strong_count(assets.forwarding_network()), 1);
    }

    #[test]
    fn forwarding_network_facts_derive_from_compiled_static_config() {
        let mut compiled = crate::config::compile_config_text(crate::config::ConfigTextInput {
            text: include_str!("../../tests/fixtures/production/host-proxy.toml"),
            source_path: Path::new("host-proxy.toml"),
            config_root: Path::new("/etc/acl-proxy"),
        })
        .expect("production fixture compiles");
        compiled.static_config.callback_public_url =
            Some("https://control.example/_acl-proxy/external-auth/callback".to_string());

        let guard = ForwardingNetworkGuard::system(
            forwarding_network_facts(&compiled.static_config)
                .expect("validated static forwarding facts derive"),
        );
        let callback =
            canonicalize_http_url("https://control.example/_acl-proxy/external-auth/callback")
                .expect("canonical callback URL");
        assert!(matches!(
            guard.preflight(
                &callback,
                HttpProtocol::Http1,
                HttpProtocol::Http1,
                &Route::Direct,
            ),
            Err(ForwardingNetworkError::ReservedControl)
        ));
        let listener =
            canonicalize_http_url("http://127.0.0.1:8881/").expect("canonical listener URL");
        assert!(matches!(
            guard.preflight(
                &listener,
                HttpProtocol::Http1,
                HttpProtocol::Http1,
                &Route::Direct,
            ),
            Err(ForwardingNetworkError::ProtectedDestination)
        ));

        let mut callback_without_control = compiled.static_config.clone();
        callback_without_control.control = None;
        assert!(matches!(
            forwarding_network_facts(&callback_without_control),
            Err(ForwardingNetworkError::InvalidFacts)
        ));

        let mut overlapping = compiled.static_config;
        overlapping
            .listeners
            .explicit_http
            .as_mut()
            .expect("explicit HTTP listener")
            .bind = "127.0.0.1:8898".parse().expect("test bind");
        assert!(matches!(
            forwarding_network_facts(&overlapping),
            Err(ForwardingNetworkError::InvalidFacts)
        ));
    }
}
