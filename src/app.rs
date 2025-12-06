use crate::certs::CertManager;
use crate::config::{Config, TlsConfig};
use crate::external_auth::ExternalAuthManager;
use crate::logging::{LoggingError, LoggingSettings};
use crate::loop_protection::{LoopProtectionError, LoopProtectionSettings};
use crate::policy::{PolicyEngine, PolicyError};
use arc_swap::ArcSwap;
use hyper::Client;
use hyper_rustls::{ConfigBuilderExt, HttpsConnectorBuilder};
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, ClientConfig, Error as RustlsError, ServerName};
use std::sync::Arc;
use std::time::SystemTime;

#[derive(Debug, thiserror::Error)]
pub enum AppStateError {
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

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub logging: LoggingSettings,
    pub policy: PolicyEngine,
    pub loop_protection: LoopProtectionSettings,
    pub http_client: Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>,
    pub cert_manager: CertManager,
    pub external_auth: ExternalAuthManager,
}

impl AppState {
    pub fn from_config(config: Config) -> Result<Self, AppStateError> {
        let logging = LoggingSettings::from_config(&config.logging)?;
        let policy = PolicyEngine::from_config(&config.policy)?;
        let loop_protection = LoopProtectionSettings::from_config(&config.loop_protection)?;

        let http_client = build_http_client(&config.tls);
        let cert_manager = CertManager::from_config(&config.certificates)?;
        let external_auth = ExternalAuthManager::new_with_callback(
            &config.policy.external_auth_profiles,
            config.external_auth.callback_url.clone(),
            http_client.clone(),
        );

        Ok(AppState {
            config,
            logging,
            policy,
            loop_protection,
            http_client,
            cert_manager,
            external_auth,
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
    /// On success, new connections will observe the updated state,
    /// while in-flight requests continue using their existing snapshot.
    pub fn reload_shared_from_config(
        shared: &SharedAppState,
        config: Config,
    ) -> Result<(), AppStateError> {
        let new_state = AppState::from_config(config)?;
        shared.store(Arc::new(new_state));
        Ok(())
    }
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
