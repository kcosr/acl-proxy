use std::sync::Arc;

use tokio_rustls::TlsAcceptor;

use crate::certs::{CertError, MitmCertificateManager};
use crate::config::compiler::{CompiledHttpVersion, StaticProductConfig};
use crate::destination::{DestinationFacts, DestinationGuard, DestinationGuardError};
use crate::tls_identity::{load_static_tls_acceptor, StaticTlsIdentityError};

pub(crate) struct ProductIngressAssets {
    destination_guard: Arc<DestinationGuard>,
    explicit_https_tls: Option<TlsAcceptor>,
    explicit_https_alpn: Box<[Vec<u8>]>,
    transparent_https_alpn: Box<[Vec<u8>]>,
    mitm: Option<Arc<MitmCertificateManager>>,
}

impl ProductIngressAssets {
    pub(crate) fn from_static(
        config: &StaticProductConfig,
    ) -> Result<Arc<Self>, ProductIngressAssetsError> {
        let destination_guard = Arc::new(DestinationGuard::system(DestinationFacts::from_static(
            config,
        )?));
        Self::from_static_with_destination_guard(config, destination_guard)
    }

    fn from_static_with_destination_guard(
        config: &StaticProductConfig,
        destination_guard: Arc<DestinationGuard>,
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
            destination_guard,
            explicit_https_tls,
            explicit_https_alpn: explicit_https_alpn.into_boxed_slice(),
            transparent_https_alpn: transparent_https_alpn.into_boxed_slice(),
            mitm,
        }))
    }

    #[cfg(test)]
    pub(crate) fn with_destination_guard(
        config: &StaticProductConfig,
        destination_guard: Arc<DestinationGuard>,
    ) -> Result<Arc<Self>, ProductIngressAssetsError> {
        Self::from_static_with_destination_guard(config, destination_guard)
    }

    pub(crate) fn destination_guard(&self) -> &Arc<DestinationGuard> {
        &self.destination_guard
    }

    pub(crate) fn explicit_https_tls(&self) -> Option<&TlsAcceptor> {
        self.explicit_https_tls.as_ref()
    }

    pub(crate) fn explicit_https_alpn(&self) -> &[Vec<u8>] {
        &self.explicit_https_alpn
    }

    pub(crate) fn transparent_https_alpn(&self) -> &[Vec<u8>] {
        &self.transparent_https_alpn
    }

    pub(crate) fn mitm(&self) -> Option<&Arc<MitmCertificateManager>> {
        self.mitm.as_ref()
    }
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
    Destination(#[from] DestinationGuardError),
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
        assert_eq!(
            assets.explicit_https_alpn(),
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
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
        assert_eq!(Arc::strong_count(assets.destination_guard()), 1);
    }
}
