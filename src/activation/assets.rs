use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use http_access_mitm::{
    GeneratedCertificateAuthority, GeneratedStorageError, MitmError, MitmIdentityManager,
    MitmLimits, MitmTlsAcceptor, MitmTlsError, PrivateStorageRoot, StandaloneCaError,
    StandaloneCertificateAuthority, StaticTlsAcceptor, StaticTlsIdentity, StorageError,
    TrustedIdentityFiles,
};
use http_access_runtime::{ForwardingNetworkError, ForwardingNetworkFacts, ForwardingNetworkGuard};
use http_access_types::{HttpProtocol, HttpProtocolSet};
use http_access_url::canonicalize_http_url;

use crate::config::compiler::{
    CompiledHttp1ConnectPolicy, CompiledHttpVersion, StaticMitmConfig, StaticProductConfig,
};

pub(crate) struct ProductIngressAssets {
    forwarding_network: Arc<ForwardingNetworkGuard>,
    static_https: Option<Arc<StaticTlsAcceptor>>,
    mitm_manager: Option<Arc<MitmIdentityManager>>,
    plaintext_connect: Option<Arc<MitmTlsAcceptor>>,
    tls_connect: Option<Arc<MitmTlsAcceptor>>,
    transparent_https: Option<Arc<MitmTlsAcceptor>>,
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
        let static_https = config
            .listeners
            .explicit_https
            .as_ref()
            .map(|listener| {
                let files = TrustedIdentityFiles::open(
                    &listener.tls.certificate_chain,
                    &listener.tls.private_key,
                )?;
                let identity = StaticTlsIdentity::from_files(files)?;
                let protocols = protocol_set(&listener.http_versions)?;
                StaticTlsAcceptor::new(identity, protocols)
                    .map(Arc::new)
                    .map_err(ProductIngressAssetsError::Tls)
            })
            .transpose()?;

        let plaintext_connect_protocols = config
            .listeners
            .explicit_http
            .as_ref()
            .filter(|listener| {
                matches!(
                    listener.connect.as_ref().and_then(|connect| connect.http1),
                    Some(CompiledHttp1ConnectPolicy::Mitm)
                )
            })
            .map(|listener| protocol_set(&listener.http_versions))
            .transpose()?;
        let tls_connect_protocols = config
            .listeners
            .explicit_https
            .as_ref()
            .filter(|listener| {
                matches!(
                    listener.connect.http1,
                    Some(CompiledHttp1ConnectPolicy::Mitm)
                )
            })
            .map(|listener| protocol_set(&listener.http_versions))
            .transpose()?;
        let transparent_https_protocols = config
            .listeners
            .transparent_https
            .as_ref()
            .map(|listener| protocol_set(&listener.http_versions))
            .transpose()?;
        let requires_mitm = plaintext_connect_protocols.is_some()
            || tls_connect_protocols.is_some()
            || transparent_https_protocols.is_some();
        if requires_mitm && config.mitm.is_none() {
            return Err(ProductIngressAssetsError::MissingMitmManager);
        }
        let mitm_manager = config
            .mitm
            .as_ref()
            .map(activate_mitm_manager)
            .transpose()?
            .map(Arc::new);
        let plaintext_connect = plaintext_connect_protocols
            .map(|protocols| mitm_acceptor(mitm_manager.as_ref().unwrap(), protocols));
        let tls_connect = tls_connect_protocols
            .map(|protocols| mitm_acceptor(mitm_manager.as_ref().unwrap(), protocols));
        let transparent_https = transparent_https_protocols
            .map(|protocols| mitm_acceptor(mitm_manager.as_ref().unwrap(), protocols));

        Ok(Arc::new(Self {
            forwarding_network,
            static_https,
            mitm_manager,
            plaintext_connect,
            tls_connect,
            transparent_https,
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

    pub(crate) fn static_https(&self) -> Option<Arc<StaticTlsAcceptor>> {
        self.static_https.clone()
    }

    pub(crate) fn plaintext_connect(&self) -> Option<Arc<MitmTlsAcceptor>> {
        self.plaintext_connect.clone()
    }

    pub(crate) fn tls_connect(&self) -> Option<Arc<MitmTlsAcceptor>> {
        self.tls_connect.clone()
    }

    pub(crate) fn transparent_https(&self) -> Option<Arc<MitmTlsAcceptor>> {
        self.transparent_https.clone()
    }

    pub(crate) fn mitm_manager(&self) -> Option<&Arc<MitmIdentityManager>> {
        self.mitm_manager.as_ref()
    }
}

fn activate_mitm_manager(
    config: &StaticMitmConfig,
) -> Result<MitmIdentityManager, ProductIngressAssetsError> {
    let (directory, max_cached_certificates, persist_leaf_certificates) = match config {
        StaticMitmConfig::Generated {
            directory,
            max_cached_certificates,
            persist_leaf_certificates,
        }
        | StaticMitmConfig::Files {
            directory,
            max_cached_certificates,
            persist_leaf_certificates,
            ..
        } => (
            directory,
            *max_cached_certificates,
            *persist_leaf_certificates,
        ),
    };
    let limits = MitmLimits::new(max_cached_certificates)?;
    let root = PrivateStorageRoot::open_or_create(directory)?;
    match config {
        StaticMitmConfig::Generated { .. } => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ProductIngressAssetsError::Clock)?
                .as_secs();
            let now = i64::try_from(now).map_err(|_| ProductIngressAssetsError::Clock)?;
            let authority = GeneratedCertificateAuthority::open_or_generate(root, now)?;
            if persist_leaf_certificates {
                authority.into_persisting_identity_manager(limits)
            } else {
                authority.into_identity_manager(limits)
            }
        }
        StaticMitmConfig::Files {
            ca_certificate,
            ca_private_key,
            ..
        } => {
            let files = TrustedIdentityFiles::open(ca_certificate, ca_private_key)?;
            let authority = StandaloneCertificateAuthority::from_files(files)?;
            if persist_leaf_certificates {
                authority.into_persisting_identity_manager(&root, limits)
            } else {
                authority.into_identity_manager(&root, limits)
            }
        }
    }
    .map_err(Into::into)
}

fn mitm_acceptor(
    manager: &Arc<MitmIdentityManager>,
    protocols: HttpProtocolSet,
) -> Arc<MitmTlsAcceptor> {
    Arc::new(MitmTlsAcceptor::new(Arc::clone(manager), protocols))
}

pub(super) fn protocol_set(
    versions: &[CompiledHttpVersion],
) -> Result<HttpProtocolSet, ProductIngressAssetsError> {
    HttpProtocolSet::new(
        versions
            .iter()
            .map(|version| match version {
                CompiledHttpVersion::Http1 => HttpProtocol::Http1,
                CompiledHttpVersion::Http2 => HttpProtocol::Http2,
            })
            .collect(),
    )
    .map_err(|_| ProductIngressAssetsError::InvalidListenerProtocols)
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
        .and(config.control.as_ref())
        .map(|control| control.base_path.clone());

    ForwardingNetworkFacts::new(
        listener_binds,
        control_bind,
        reserved_control_url,
        reserved_control_base_path,
    )
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductIngressAssetsError {
    #[error(transparent)]
    ForwardingNetwork(#[from] ForwardingNetworkError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    GeneratedStorage(#[from] GeneratedStorageError),
    #[error(transparent)]
    StandaloneCa(#[from] StandaloneCaError),
    #[error(transparent)]
    Mitm(#[from] MitmError),
    #[error(transparent)]
    Tls(#[from] MitmTlsError),
    #[error("system clock is unavailable")]
    Clock,
    #[error("compiled listener protocols are invalid")]
    InvalidListenerProtocols,
    #[error("a MITM listener requires an activated MITM manager")]
    MissingMitmManager,
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use http_access_types::{HttpProtocol, Route};
    use tempfile::tempdir;

    use super::*;
    use crate::config::{compile_config_text, ConfigTextInput};
    use crate::test_certificates::TestTlsIdentity;

    #[tokio::test]
    async fn listener_tls_assets_preserve_each_exact_role_and_protocol_set() {
        let directory = tempdir().unwrap();
        let identity = TestTlsIdentity::new("localhost");
        crate::filesystem::write_public_file(
            &directory.path().join("server.pem"),
            identity.certificate_chain_pem(),
        )
        .unwrap();
        crate::filesystem::write_private_file(
            &directory.path().join("server-key.pem"),
            identity.private_key_pem(),
        )
        .unwrap();
        let text = r#"schema_version = 3

[listeners.explicit_http]
bind = "127.0.0.2:31880"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "mitm"

[listeners.explicit_https]
bind = "127.0.0.2:31881"
http_versions = ["http2", "http1"]

[listeners.explicit_https.connect]
http1 = "mitm"
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

        assert_eq!(
            assets
                .static_https()
                .expect("explicit HTTPS acceptor")
                .protocols()
                .protocols(),
            [HttpProtocol::Http2, HttpProtocol::Http1]
        );
        assert_eq!(
            assets
                .transparent_https()
                .expect("transparent HTTPS acceptor")
                .protocols()
                .protocols(),
            [HttpProtocol::Http1]
        );
        assert!(assets.mitm_manager().is_some());
        let plaintext_connect = assets
            .plaintext_connect()
            .expect("plaintext CONNECT acceptor");
        let tls_connect = assets.tls_connect().expect("TLS CONNECT acceptor");
        let transparent_https = assets
            .transparent_https()
            .expect("transparent HTTPS acceptor");
        assert_eq!(
            plaintext_connect.protocols().protocols(),
            [HttpProtocol::Http1]
        );
        assert_eq!(
            tls_connect.protocols().protocols(),
            [HttpProtocol::Http2, HttpProtocol::Http1]
        );
        assert!(!Arc::ptr_eq(&plaintext_connect, &tls_connect));
        assert!(!Arc::ptr_eq(&tls_connect, &transparent_https));
        assert_eq!(Arc::strong_count(assets.forwarding_network()), 1);
        assets
            .mitm_manager()
            .expect("MITM identity manager")
            .shutdown_and_join()
            .await;
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
