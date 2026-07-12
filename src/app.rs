use crate::auth_plugin::AuthPluginManager;
use crate::certs::CertManager;
use crate::config::{
    Config, ConfigError, EgressTargetConfig, EgressTlsTrust, EgressTransport, TlsConfig,
};
use crate::external_auth::ExternalAuthManager;
use crate::logging::{LoggingError, LoggingSettings};
use crate::loop_protection::{LoopProtectionError, LoopProtectionSettings};
use crate::policy::{
    compile_egress_request_header_actions, CompiledHeaderAction, PolicyEngine, PolicyError,
};
use arc_swap::ArcSwap;
use hyper::Client;
use hyper_rustls::{ConfigBuilderExt, HttpsConnectorBuilder};
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, ClientConfig, Error as RustlsError, RootCertStore, ServerName};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::SystemTime;
use tokio::task::JoinSet;

#[derive(Debug, thiserror::Error)]
pub enum AppStateError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Logging(#[from] LoggingError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    LoopProtection(#[from] LoopProtectionError),
    #[error(transparent)]
    Certs(#[from] crate::certs::CertError),
}

/// Shared, reloadable application state used by proxy listeners.
///
/// The inner `ArcSwap` allows the configuration and derived components
/// (policy engine, loop protection, HTTP client, cert manager, etc.)
/// to be atomically swapped on reload while existing requests keep
/// using the previous snapshot.
pub type SharedAppState = Arc<ArcSwap<AppState>>;

#[derive(Clone, Default)]
pub struct UpgradeSessionTracker {
    tasks: Arc<Mutex<JoinSet<()>>>,
}

impl UpgradeSessionTracker {
    pub fn spawn<F>(&self, future: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while let Some(result) = tasks.try_join_next() {
            crate::proxy::listener::log_connection_task_result("upgraded_session", result);
        }
        tasks.spawn(future);
    }

    pub async fn drain(&self, timeout: Option<Duration>) {
        let mut tasks = {
            let mut tasks = self
                .tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *tasks)
        };
        crate::proxy::listener::drain_connections("upgraded_session", &mut tasks, timeout).await;
    }
}

#[derive(Clone)]
pub struct ParentEgressTls {
    pub server_name: String,
    http1_config: Arc<ClientConfig>,
    h2_config: Arc<ClientConfig>,
}

impl ParentEgressTls {
    pub fn client_config(&self, use_http2: bool) -> Arc<ClientConfig> {
        if use_http2 {
            self.h2_config.clone()
        } else {
            self.http1_config.clone()
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub logging: LoggingSettings,
    pub policy: PolicyEngine,
    pub egress_request_header_actions: Vec<CompiledHeaderAction>,
    pub loop_protection: LoopProtectionSettings,
    pub http_client: Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>,
    pub parent_egress_tls: Option<ParentEgressTls>,
    pub cert_manager: CertManager,
    pub external_auth: ExternalAuthManager,
    pub auth_plugins: AuthPluginManager,
    pub upgrade_sessions: UpgradeSessionTracker,
}

impl AppState {
    pub fn from_config(config: Config) -> Result<Self, AppStateError> {
        Self::from_config_with_previous(config, None)
    }

    fn from_config_with_previous(
        config: Config,
        previous: Option<&AppState>,
    ) -> Result<Self, AppStateError> {
        config.validate_basic()?;
        let logging = LoggingSettings::from_config(&config.logging)?;
        let policy = PolicyEngine::from_config(&config.policy)?;
        let egress_request_header_actions =
            compile_egress_request_header_actions(&config.proxy.egress.request_header_actions)?;
        let loop_protection = LoopProtectionSettings::from_config(&config.loop_protection)?;

        let http_client = build_http_client(&config.tls);
        let parent_egress_tls = build_parent_egress_tls(&config)?;
        let cert_manager = CertManager::from_config(&config.certificates)?;
        let external_auth = if let Some(previous) = previous {
            ExternalAuthManager::reconfigured_from(
                &config.policy.external_auth_profiles,
                config.external_auth.callback_url.clone(),
                http_client.clone(),
                &previous.external_auth,
            )
        } else {
            ExternalAuthManager::new_with_callback(
                &config.policy.external_auth_profiles,
                config.external_auth.callback_url.clone(),
                http_client.clone(),
            )
        };
        let auth_plugins = AuthPluginManager::new(&config.policy.external_auth_profiles);
        let upgrade_sessions = previous
            .map(|state| state.upgrade_sessions.clone())
            .unwrap_or_default();

        Ok(AppState {
            config,
            logging,
            policy,
            egress_request_header_actions,
            loop_protection,
            http_client,
            parent_egress_tls,
            cert_manager,
            external_auth,
            auth_plugins,
            upgrade_sessions,
        })
    }

    /// Build a new shared, reloadable application state from configuration.
    pub fn shared_from_config(config: Config) -> Result<SharedAppState, AppStateError> {
        let state = AppState::from_config(config)?;
        Ok(Arc::new(ArcSwap::from_pointee(state)))
    }

    /// Rebuild and atomically swap the shared application state from
    /// the provided configuration.
    ///
    /// On success, new requests will observe the updated state,
    /// while in-flight requests continue using their existing snapshot.
    pub fn reload_shared_from_config(
        shared: &SharedAppState,
        config: Config,
    ) -> Result<(), AppStateError> {
        let previous = shared.load_full();
        if previous.config.proxy.listeners != config.proxy.listeners {
            return Err(AppStateError::Config(ConfigError::Invalid(
                "listener configuration changed; restart required for proxy.listeners changes"
                    .to_string(),
            )));
        }
        let new_state = AppState::from_config_with_previous(config, Some(previous.as_ref()))?;
        shared.store(Arc::new(new_state));
        Ok(())
    }
}

fn build_parent_egress_tls(config: &Config) -> Result<Option<ParentEgressTls>, AppStateError> {
    let Some(target) = config.proxy.egress.default.as_ref() else {
        return Ok(None);
    };
    if target.transport != EgressTransport::Https {
        return Ok(None);
    }

    let server_name = normalized_tls_server_name(target.tls_server_name());
    ServerName::try_from(server_name.as_str()).map_err(|err| {
        ConfigError::Invalid(format!(
            "proxy.egress.default.tls.server_name must be a valid TLS server name: {err}"
        ))
    })?;

    let http1_config = build_parent_tls_client_config(target, b"http/1.1")?;
    let h2_config = build_parent_tls_client_config(target, b"h2")?;

    Ok(Some(ParentEgressTls {
        server_name,
        http1_config: Arc::new(http1_config),
        h2_config: Arc::new(h2_config),
    }))
}

fn build_parent_tls_client_config(
    target: &EgressTargetConfig,
    alpn: &'static [u8],
) -> Result<ClientConfig, ConfigError> {
    let tls = target.tls.as_ref();
    let trust = target.effective_tls_trust();
    let mut config = match trust {
        EgressTlsTrust::System => {
            let roots = root_store_with_native_roots()?;
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        EgressTlsTrust::CustomCa => {
            let roots = root_store_from_custom_ca(
                tls.and_then(|tls| tls.ca_cert_path.as_deref())
                    .ok_or_else(|| {
                        ConfigError::Invalid(
                            "proxy.egress.default.tls.ca_cert_path is required".to_string(),
                        )
                    })?,
            )?;
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        EgressTlsTrust::SystemPlusCustomCa => {
            let mut roots = root_store_with_native_roots()?;
            let ca_path = tls
                .and_then(|tls| tls.ca_cert_path.as_deref())
                .ok_or_else(|| {
                    ConfigError::Invalid(
                        "proxy.egress.default.tls.ca_cert_path is required".to_string(),
                    )
                })?;
            add_custom_ca_to_root_store(&mut roots, ca_path)?;
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        EgressTlsTrust::Disabled => {
            if alpn == b"http/1.1" {
                tracing::warn!(
                    target: "acl_proxy::transport",
                    egress_host = %target.host,
                    egress_port = target.port,
                    egress_tls_server_name = %target.tls_server_name(),
                    "HTTPS parent egress certificate verification is disabled"
                );
            }
            let mut config = ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth();
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoVerifyServerCert));
            config
        }
    };

    config.alpn_protocols = vec![alpn.to_vec()];
    config.enable_sni = normalized_tls_server_name(target.tls_server_name())
        .parse::<IpAddr>()
        .is_err();

    Ok(config)
}

fn root_store_with_native_roots() -> Result<RootCertStore, ConfigError> {
    let mut roots = RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs().map_err(|err| {
        ConfigError::Invalid(format!("failed to load system certificate roots: {err}"))
    })?;
    for cert in certs {
        roots.add(&Certificate(cert.0)).map_err(|err| {
            ConfigError::Invalid(format!(
                "failed to add system certificate root to HTTPS parent egress trust store: {err}"
            ))
        })?;
    }
    Ok(roots)
}

fn root_store_from_custom_ca(path: &Path) -> Result<RootCertStore, ConfigError> {
    let mut roots = RootCertStore::empty();
    add_custom_ca_to_root_store(&mut roots, path)?;
    Ok(roots)
}

fn add_custom_ca_to_root_store(roots: &mut RootCertStore, path: &Path) -> Result<(), ConfigError> {
    let file = std::fs::File::open(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = std::io::BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).map_err(|err| {
        ConfigError::Invalid(format!(
            "proxy.egress.default.tls.ca_cert_path {} must contain valid PEM certificates: {err}",
            path.display()
        ))
    })?;
    if certs.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "proxy.egress.default.tls.ca_cert_path {} must contain at least one PEM certificate",
            path.display()
        )));
    }

    for cert in certs {
        roots.add(&Certificate(cert)).map_err(|err| {
            ConfigError::Invalid(format!(
                "failed to add proxy.egress.default.tls.ca_cert_path {} certificate: {err}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn normalized_tls_server_name(value: &str) -> String {
    value
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(value)
        .to_string()
}

fn build_http_client(
    tls: &TlsConfig,
) -> Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>> {
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_native_roots()
        .with_no_client_auth();

    if !tls.verify_upstream {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifyServerCert));
    }

    let builder = HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_or_http()
        .enable_http1();

    // Upstream HTTP/2 is opt-in and controlled by configuration.
    // The recommended default is HTTP/1.1-only upstream for maximum
    // compatibility; when enabled, hyper negotiates HTTP/2 via ALPN
    // where supported by the origin.
    let https = if tls.enable_http2_upstream {
        builder.enable_http2().build()
    } else {
        builder.build()
    };

    Client::builder().build::<_, hyper::Body>(https)
}

struct NoVerifyServerCert;

impl ServerCertVerifier for NoVerifyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }
}

#[cfg(test)]
mod tests {
    use super::UpgradeSessionTracker;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn upgrade_session_drain_aborts_tasks_after_timeout() {
        let tracker = UpgradeSessionTracker::default();
        let dropped = Arc::new(AtomicBool::new(false));
        let signal = DropSignal(dropped.clone());
        tracker.spawn(async move {
            let _signal = signal;
            std::future::pending::<()>().await;
        });

        tracker.drain(Some(Duration::from_millis(10))).await;
        assert!(dropped.load(Ordering::SeqCst));
    }
}
