use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use http::header::HeaderMap;
use http::Uri;
use hyper::client::HttpConnector;
use hyper::{Body, Client};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, ClientConfig, Error as RustlsError, RootCertStore, ServerName};

use crate::config::v3_compile::{
    CompiledEgressRoute, CompiledHttpVersion, CompiledParentProxyKind, CompiledTlsTrust,
    EgressPlan, HeaderEffectPlan, ParentProxyPlan, ParentProxyTlsPlan, TransportTlsPlan,
};
use crate::credentials::{
    resolve_credential_action, CredentialBindingError, ResolvedCredentialAction,
};
use crate::policy::{apply_header_effects, HeaderEffectError};
use crate::runtime::CredentialSourceRegistry;
use crate::url::canonicalize_tls_server_name;

pub(crate) type OriginClient = Client<HttpsConnector<HttpConnector>, Body>;

/// Generation-owned outbound transport policy and material.
///
/// Activation consumes every path and logical credential name from the pure
/// plan. Requests receive only clients, canonical parent metadata, compiled
/// header effects, and runtime credential indices.
pub(crate) struct EgressSnapshot {
    route: EgressRoute,
    origin_client: OriginClient,
    origin_trust: CompiledTlsTrust,
    origin_http_versions: Box<[CompiledHttpVersion]>,
    request_headers: Box<[HeaderEffectPlan]>,
    credential_actions: Box<[ResolvedCredentialAction]>,
}

pub(crate) enum EgressRoute {
    Direct,
    Parent(ParentEndpoint),
}

pub(crate) struct ParentEndpoint {
    kind: CompiledParentProxyKind,
    canonical_url: String,
    uri: Uri,
    host: String,
    port: u16,
    transport: ParentTransport,
}

pub(crate) enum ParentTransport {
    Http,
    Https(ParentTls),
}

pub(crate) struct ParentTls {
    trust: CompiledTlsTrust,
    server_name: String,
    http1_config: Arc<ClientConfig>,
    http2_config: Arc<ClientConfig>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum EgressActivationError {
    #[error("egress activation was cancelled")]
    ActivationCancelled,
    #[error("egress plan route and parent metadata are inconsistent")]
    Route,
    #[error("egress parent URL is invalid")]
    ParentUrl,
    #[error("egress parent TLS server name is invalid")]
    ParentServerName,
    #[error("system certificate roots are unavailable")]
    NativeRoots,
    #[error("custom CA certificate bundle is unavailable")]
    CaUnavailable,
    #[error("custom CA certificate bundle is invalid")]
    CaInvalid,
    #[error("custom CA certificate bundle is empty")]
    CaEmpty,
    #[error("custom CA certificate bundle contains an unusable certificate")]
    CaUnusable,
    #[error("egress credential action is invalid: {0}")]
    Credential(#[from] CredentialBindingError),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum ParentAlpnError {
    #[error("parent proxy did not negotiate the required HTTP protocol")]
    Incompatible,
}

#[derive(Clone)]
enum LoadedTlsTrust {
    Roots(RootCertStore),
    Insecure,
}

impl EgressSnapshot {
    pub(crate) fn activate(
        plan: EgressPlan,
        credential_sources: &CredentialSourceRegistry,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<Self, EgressActivationError> {
        let EgressPlan {
            route,
            origin_tls,
            parent_proxy,
            request_headers,
            credential_actions,
        } = plan;
        let origin_trust = origin_tls.trust;
        let origin_http_versions = origin_tls.http_versions.clone().into_boxed_slice();
        let origin_client = build_origin_client(origin_tls, &mut is_cancelled)?;
        let route = match (route, parent_proxy) {
            (CompiledEgressRoute::Direct, None) => EgressRoute::Direct,
            (CompiledEgressRoute::ParentProxy, Some(parent)) => {
                EgressRoute::Parent(ParentEndpoint::activate(parent, &mut is_cancelled)?)
            }
            _ => return Err(EgressActivationError::Route),
        };
        let credential_actions = credential_actions
            .into_iter()
            .map(|action| resolve_credential_action(action, credential_sources))
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();

        Ok(Self {
            route,
            origin_client,
            origin_trust,
            origin_http_versions,
            request_headers: request_headers.into_boxed_slice(),
            credential_actions,
        })
    }

    pub(crate) fn route(&self) -> &EgressRoute {
        &self.route
    }

    pub(crate) fn origin_client(&self) -> OriginClient {
        self.origin_client.clone()
    }

    pub(crate) fn origin_trust(&self) -> CompiledTlsTrust {
        self.origin_trust
    }

    pub(crate) fn origin_http_versions(&self) -> &[CompiledHttpVersion] {
        &self.origin_http_versions
    }

    pub(crate) fn apply_request_headers(
        &self,
        headers: &mut HeaderMap,
    ) -> Result<(), HeaderEffectError> {
        apply_header_effects(&self.request_headers, headers)
    }

    pub(crate) fn credential_actions(&self) -> &[ResolvedCredentialAction] {
        &self.credential_actions
    }
}

impl crate::runtime::EgressSnapshot for EgressSnapshot {}

impl ParentEndpoint {
    fn activate(
        plan: ParentProxyPlan,
        is_cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<Self, EgressActivationError> {
        let ParentProxyPlan {
            kind,
            url,
            host,
            port,
            tls,
        } = plan;
        let uri = url
            .parse::<Uri>()
            .map_err(|_| EgressActivationError::ParentUrl)?;
        let scheme = uri.scheme_str().ok_or(EgressActivationError::ParentUrl)?;
        let transport = match (scheme, tls) {
            ("http", None) => ParentTransport::Http,
            ("https", Some(tls)) => ParentTransport::Https(ParentTls::activate(tls, is_cancelled)?),
            _ => return Err(EgressActivationError::Route),
        };
        Ok(Self {
            kind,
            canonical_url: url,
            uri,
            host,
            port,
            transport,
        })
    }

    pub(crate) fn kind(&self) -> CompiledParentProxyKind {
        self.kind
    }

    pub(crate) fn canonical_url(&self) -> &str {
        &self.canonical_url
    }

    pub(crate) fn uri(&self) -> &Uri {
        &self.uri
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn transport(&self) -> &ParentTransport {
        &self.transport
    }
}

impl ParentTls {
    fn activate(
        plan: ParentProxyTlsPlan,
        is_cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<Self, EgressActivationError> {
        Self::activate_with_loader(plan, |trust, ca_certificate| {
            load_tls_trust(trust, ca_certificate, is_cancelled)
        })
    }

    fn activate_with_loader<F>(
        plan: ParentProxyTlsPlan,
        load: F,
    ) -> Result<Self, EgressActivationError>
    where
        F: FnOnce(CompiledTlsTrust, Option<&Path>) -> Result<LoadedTlsTrust, EgressActivationError>,
    {
        let server_name = canonicalize_tls_server_name(&plan.server_name)
            .map_err(|_| EgressActivationError::ParentServerName)?;
        ServerName::try_from(server_name.as_str())
            .map_err(|_| EgressActivationError::ParentServerName)?;
        let enable_sni = server_name.parse::<IpAddr>().is_err();
        let loaded_trust = load(plan.trust, plan.ca_certificate.as_deref())?;
        warn_if_insecure("parent", plan.trust);
        let http1_config = Arc::new(build_tls_config(
            &loaded_trust,
            vec![b"http/1.1".to_vec()],
            enable_sni,
        ));
        let http2_config = Arc::new(build_tls_config(
            &loaded_trust,
            vec![b"h2".to_vec()],
            enable_sni,
        ));
        Ok(Self {
            trust: plan.trust,
            server_name,
            http1_config,
            http2_config,
        })
    }

    pub(crate) fn trust(&self) -> CompiledTlsTrust {
        self.trust
    }

    pub(crate) fn server_name(&self) -> &str {
        &self.server_name
    }

    pub(crate) fn client_config(&self, use_http2: bool) -> Arc<ClientConfig> {
        if use_http2 {
            self.http2_config.clone()
        } else {
            self.http1_config.clone()
        }
    }

    /// Enforces the no-downgrade protocol contract after the TLS handshake.
    pub(crate) fn validate_negotiated_alpn(
        &self,
        use_http2: bool,
        negotiated: Option<&[u8]>,
    ) -> Result<(), ParentAlpnError> {
        let compatible = if use_http2 {
            negotiated == Some(b"h2")
        } else {
            negotiated.is_none() || negotiated == Some(b"http/1.1")
        };
        compatible
            .then_some(())
            .ok_or(ParentAlpnError::Incompatible)
    }
}

fn build_origin_client(
    plan: TransportTlsPlan,
    is_cancelled: &mut dyn FnMut() -> bool,
) -> Result<OriginClient, EgressActivationError> {
    let http1 = plan.http_versions.contains(&CompiledHttpVersion::Http1);
    let http2 = plan.http_versions.contains(&CompiledHttpVersion::Http2);
    if !http1 && !http2 {
        return Err(EgressActivationError::Route);
    }
    // hyper-rustls owns origin ALPN construction from the enabled protocol
    // set and requires the supplied rustls config to start with no ALPN list.
    let loaded_trust = load_tls_trust(plan.trust, plan.ca_certificate.as_deref(), is_cancelled)?;
    warn_if_insecure("origin", plan.trust);
    let tls = build_tls_config(&loaded_trust, Vec::new(), true);
    let protocols = HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http();
    let connector = match (http1, http2) {
        (true, true) => protocols.enable_http1().enable_http2().build(),
        (true, false) => protocols.enable_http1().build(),
        (false, true) => protocols.enable_http2().build(),
        (false, false) => unreachable!("empty protocol list rejected above"),
    };
    Ok(Client::builder().build(connector))
}

fn load_tls_trust(
    trust: CompiledTlsTrust,
    ca_certificate: Option<&Path>,
    is_cancelled: &mut dyn FnMut() -> bool,
) -> Result<LoadedTlsTrust, EgressActivationError> {
    match trust {
        CompiledTlsTrust::System => Ok(LoadedTlsTrust::Roots(root_store_with_native_roots(
            is_cancelled,
        )?)),
        CompiledTlsTrust::Custom => Ok(LoadedTlsTrust::Roots(root_store_from_custom_ca(
            ca_certificate.ok_or(EgressActivationError::CaUnavailable)?,
            is_cancelled,
        )?)),
        CompiledTlsTrust::SystemPlusCustom => {
            let mut roots = root_store_with_native_roots(is_cancelled)?;
            add_custom_ca(
                &mut roots,
                ca_certificate.ok_or(EgressActivationError::CaUnavailable)?,
                is_cancelled,
            )?;
            Ok(LoadedTlsTrust::Roots(roots))
        }
        CompiledTlsTrust::Insecure => Ok(LoadedTlsTrust::Insecure),
    }
}

fn build_tls_config(
    trust: &LoadedTlsTrust,
    alpn_protocols: Vec<Vec<u8>>,
    enable_sni: bool,
) -> ClientConfig {
    let mut config = match trust {
        LoadedTlsTrust::Roots(roots) => ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots.clone())
            .with_no_client_auth(),
        LoadedTlsTrust::Insecure => {
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
    config.alpn_protocols = alpn_protocols;
    config.enable_sni = enable_sni;
    config
}

fn warn_if_insecure(scope: &'static str, trust: CompiledTlsTrust) {
    if trust == CompiledTlsTrust::Insecure {
        tracing::warn!(
            target: "acl_proxy::transport",
            tls_scope = scope,
            "TLS certificate verification is disabled"
        );
    }
}

fn root_store_with_native_roots(
    is_cancelled: &mut dyn FnMut() -> bool,
) -> Result<RootCertStore, EgressActivationError> {
    let mut roots = RootCertStore::empty();
    check_activation_cancellation(is_cancelled)?;
    let certificates = rustls_native_certs::load_native_certs();
    check_activation_cancellation(is_cancelled)?;
    let certificates = certificates.map_err(|_| EgressActivationError::NativeRoots)?;
    for certificate in certificates {
        roots
            .add(&Certificate(certificate.0))
            .map_err(|_| EgressActivationError::NativeRoots)?;
    }
    validate_native_root_store(roots)
}

fn validate_native_root_store(
    roots: RootCertStore,
) -> Result<RootCertStore, EgressActivationError> {
    if roots.is_empty() {
        Err(EgressActivationError::NativeRoots)
    } else {
        Ok(roots)
    }
}

fn root_store_from_custom_ca(
    path: &Path,
    is_cancelled: &mut dyn FnMut() -> bool,
) -> Result<RootCertStore, EgressActivationError> {
    let mut roots = RootCertStore::empty();
    add_custom_ca(&mut roots, path, is_cancelled)?;
    Ok(roots)
}

fn add_custom_ca(
    roots: &mut RootCertStore,
    path: &Path,
    is_cancelled: &mut dyn FnMut() -> bool,
) -> Result<(), EgressActivationError> {
    check_activation_cancellation(is_cancelled)?;
    let file = File::open(path);
    check_activation_cancellation(is_cancelled)?;
    let file = file.map_err(|_| EgressActivationError::CaUnavailable)?;
    check_activation_cancellation(is_cancelled)?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(file));
    check_activation_cancellation(is_cancelled)?;
    let certificates = certificates.map_err(|_| EgressActivationError::CaInvalid)?;
    if certificates.is_empty() {
        return Err(EgressActivationError::CaEmpty);
    }
    for certificate in certificates {
        roots
            .add(&Certificate(certificate))
            .map_err(|_| EgressActivationError::CaUnusable)?;
    }
    Ok(())
}

fn check_activation_cancellation(
    is_cancelled: &mut dyn FnMut() -> bool,
) -> Result<(), EgressActivationError> {
    if is_cancelled() {
        Err(EgressActivationError::ActivationCancelled)
    } else {
        Ok(())
    }
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
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use http::header::AUTHORIZATION;
    use rcgen::generate_simple_self_signed;
    use tempfile::TempDir;
    use tracing::subscriber::with_default;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;
    use crate::config::v3_compile::{CredentialActionPlan, ParentProxyTlsPlan};
    use crate::config::{compile_config_text, ConfigTextInput};

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    struct CapturedLogWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedLogWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for CapturedLogs {
        type Writer = CapturedLogWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            CapturedLogWriter(self.0.clone())
        }
    }

    impl CapturedLogs {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    fn capture_logs(operation: impl FnOnce()) -> String {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(logs.clone())
            .finish();
        with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            operation();
        });
        logs.text()
    }

    fn direct_plan(
        trust: CompiledTlsTrust,
        ca_certificate: Option<PathBuf>,
        http_versions: Vec<CompiledHttpVersion>,
    ) -> EgressPlan {
        EgressPlan {
            route: CompiledEgressRoute::Direct,
            origin_tls: TransportTlsPlan {
                trust,
                ca_certificate,
                http_versions,
            },
            parent_proxy: None,
            request_headers: Vec::new(),
            credential_actions: Vec::new(),
        }
    }

    fn parent_plan(parent: ParentProxyPlan) -> EgressPlan {
        EgressPlan {
            route: CompiledEgressRoute::ParentProxy,
            origin_tls: TransportTlsPlan {
                trust: CompiledTlsTrust::Insecure,
                ca_certificate: None,
                http_versions: vec![CompiledHttpVersion::Http1, CompiledHttpVersion::Http2],
            },
            parent_proxy: Some(parent),
            request_headers: Vec::new(),
            credential_actions: Vec::new(),
        }
    }

    fn write_ca(directory: &TempDir) -> PathBuf {
        let generated = generate_simple_self_signed(vec!["test-ca.example".to_string()]).unwrap();
        let path = directory.path().join("ca.pem");
        std::fs::write(&path, generated.cert.pem()).unwrap();
        path
    }

    fn activate(plan: EgressPlan) -> EgressSnapshot {
        EgressSnapshot::activate(plan, &CredentialSourceRegistry::from_names([]), || false).unwrap()
    }

    fn activation_error(plan: EgressPlan) -> EgressActivationError {
        activation_error_with_cancellation(plan, || false)
    }

    fn activation_error_with_cancellation(
        plan: EgressPlan,
        is_cancelled: impl FnMut() -> bool,
    ) -> EgressActivationError {
        match EgressSnapshot::activate(
            plan,
            &CredentialSourceRegistry::from_names([]),
            is_cancelled,
        ) {
            Ok(_) => panic!("egress activation unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    fn compile_egress(config_root: &Path, definitions: &str) -> EgressPlan {
        let text = format!(
            r#"
schema_version = 3

[listeners.explicit_http]
bind = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

{definitions}

[policy]
default = "deny"
"#
        );
        compile_config_text(ConfigTextInput {
            text: &text,
            source_path: &config_root.join("acl-proxy.toml"),
            config_root,
        })
        .unwrap()
        .reloadable_plan
        .egress
    }

    #[test]
    fn direct_route_activates_every_origin_trust_variant_offline() {
        let directory = TempDir::new().unwrap();
        let ca = write_ca(&directory);
        let cases = [
            (CompiledTlsTrust::System, None),
            (CompiledTlsTrust::Custom, Some(ca.clone())),
            (CompiledTlsTrust::SystemPlusCustom, Some(ca)),
            (CompiledTlsTrust::Insecure, None),
        ];

        for (trust, ca_certificate) in cases {
            let snapshot = activate(direct_plan(
                trust,
                ca_certificate,
                vec![CompiledHttpVersion::Http1, CompiledHttpVersion::Http2],
            ));
            assert!(matches!(snapshot.route(), EgressRoute::Direct));
            assert!(snapshot.origin_trust() == trust);
            assert_eq!(
                snapshot.origin_http_versions(),
                [CompiledHttpVersion::Http1, CompiledHttpVersion::Http2]
            );
            drop(snapshot.origin_client());
        }
    }

    #[test]
    fn direct_route_honors_single_origin_protocols() {
        for version in [CompiledHttpVersion::Http1, CompiledHttpVersion::Http2] {
            let snapshot = activate(direct_plan(CompiledTlsTrust::Insecure, None, vec![version]));
            assert_eq!(snapshot.origin_http_versions(), [version]);
        }
    }

    #[test]
    fn http_parent_owns_canonical_endpoint_and_kind() {
        let snapshot = activate(parent_plan(ParentProxyPlan {
            kind: CompiledParentProxyKind::AclProxy,
            url: "http://parent.example:8080/".to_string(),
            host: "parent.example".to_string(),
            port: 8080,
            tls: None,
        }));
        let EgressRoute::Parent(parent) = snapshot.route() else {
            panic!("expected parent route");
        };
        assert!(matches!(parent.kind(), CompiledParentProxyKind::AclProxy));
        assert_eq!(parent.canonical_url(), "http://parent.example:8080/");
        assert_eq!(parent.uri().scheme_str(), Some("http"));
        assert_eq!(parent.host(), "parent.example");
        assert_eq!(parent.port(), 8080);
        assert!(matches!(parent.transport(), ParentTransport::Http));
    }

    #[test]
    fn https_parent_builds_distinct_h1_h2_configs_and_dns_sni() {
        let directory = TempDir::new().unwrap();
        let snapshot = activate(parent_plan(ParentProxyPlan {
            kind: CompiledParentProxyKind::Generic,
            url: "https://parent.example:8443/".to_string(),
            host: "parent.example".to_string(),
            port: 8443,
            tls: Some(ParentProxyTlsPlan {
                trust: CompiledTlsTrust::Custom,
                ca_certificate: Some(write_ca(&directory)),
                server_name: "PARENT.EXAMPLE.".to_string(),
            }),
        }));
        let EgressRoute::Parent(parent) = snapshot.route() else {
            panic!("expected parent route");
        };
        assert!(matches!(parent.kind(), CompiledParentProxyKind::Generic));
        let ParentTransport::Https(tls) = parent.transport() else {
            panic!("expected HTTPS parent");
        };
        assert!(matches!(tls.trust(), CompiledTlsTrust::Custom));
        assert_eq!(tls.server_name(), "parent.example");
        let h1 = tls.client_config(false);
        let h2 = tls.client_config(true);
        assert_eq!(h1.alpn_protocols, [b"http/1.1".to_vec()]);
        assert_eq!(h2.alpn_protocols, [b"h2".to_vec()]);
        assert!(h1.enable_sni);
        assert!(h2.enable_sni);
        assert!(!Arc::ptr_eq(&h1, &h2));
    }

    #[test]
    fn https_parent_disables_sni_for_ip_server_name() {
        let snapshot = activate(parent_plan(ParentProxyPlan {
            kind: CompiledParentProxyKind::Generic,
            url: "https://192.0.2.20:8443/".to_string(),
            host: "192.0.2.20".to_string(),
            port: 8443,
            tls: Some(ParentProxyTlsPlan {
                trust: CompiledTlsTrust::Insecure,
                ca_certificate: None,
                server_name: "192.0.2.20".to_string(),
            }),
        }));
        let EgressRoute::Parent(parent) = snapshot.route() else {
            panic!("expected parent route");
        };
        let ParentTransport::Https(tls) = parent.transport() else {
            panic!("expected HTTPS parent");
        };
        assert!(!tls.client_config(false).enable_sni);
        assert!(!tls.client_config(true).enable_sni);
    }

    #[test]
    fn parent_tls_loads_trust_once_for_both_protocol_configs() {
        let directory = TempDir::new().unwrap();
        let load_count = Cell::new(0);
        let tls = ParentTls::activate_with_loader(
            ParentProxyTlsPlan {
                trust: CompiledTlsTrust::Custom,
                ca_certificate: Some(write_ca(&directory)),
                server_name: "parent.example".to_string(),
            },
            |trust, ca_certificate| {
                load_count.set(load_count.get() + 1);
                load_tls_trust(trust, ca_certificate, &mut || false)
            },
        )
        .unwrap();

        assert_eq!(load_count.get(), 1);
        assert_eq!(
            tls.client_config(false).alpn_protocols,
            [b"http/1.1".to_vec()]
        );
        assert_eq!(tls.client_config(true).alpn_protocols, [b"h2".to_vec()]);
    }

    #[test]
    fn parent_alpn_validation_enforces_exact_h2_without_downgrading_h1() {
        let tls = ParentTls::activate(
            ParentProxyTlsPlan {
                trust: CompiledTlsTrust::Insecure,
                ca_certificate: None,
                server_name: "parent.example".to_string(),
            },
            &mut || false,
        )
        .unwrap();

        assert_eq!(tls.validate_negotiated_alpn(false, None), Ok(()));
        assert_eq!(
            tls.validate_negotiated_alpn(false, Some(b"http/1.1")),
            Ok(())
        );
        assert_eq!(
            tls.validate_negotiated_alpn(false, Some(b"h2")),
            Err(ParentAlpnError::Incompatible)
        );
        assert_eq!(tls.validate_negotiated_alpn(true, Some(b"h2")), Ok(()));
        assert_eq!(
            tls.validate_negotiated_alpn(true, None),
            Err(ParentAlpnError::Incompatible)
        );
        assert_eq!(
            tls.validate_negotiated_alpn(true, Some(b"http/1.1")),
            Err(ParentAlpnError::Incompatible)
        );
    }

    #[test]
    fn insecure_origin_and_parent_each_emit_one_sanitized_warning() {
        let origin_logs = capture_logs(|| {
            activate(direct_plan(
                CompiledTlsTrust::Insecure,
                None,
                vec![CompiledHttpVersion::Http1],
            ));
        });
        assert_eq!(
            origin_logs
                .matches("TLS certificate verification is disabled")
                .count(),
            1
        );
        assert!(origin_logs.contains("tls_scope=\"origin\""));

        let parent_logs = capture_logs(|| {
            ParentTls::activate(
                ParentProxyTlsPlan {
                    trust: CompiledTlsTrust::Insecure,
                    ca_certificate: None,
                    server_name: "sensitive-parent-name.example".to_string(),
                },
                &mut || false,
            )
            .unwrap();
        });
        assert_eq!(
            parent_logs
                .matches("TLS certificate verification is disabled")
                .count(),
            1
        );
        assert!(parent_logs.contains("tls_scope=\"parent\""));
        assert!(!parent_logs.contains("sensitive-parent-name.example"));
    }

    #[test]
    fn empty_native_root_store_fails_activation() {
        assert_eq!(
            validate_native_root_store(RootCertStore::empty()).unwrap_err(),
            EgressActivationError::NativeRoots
        );
    }

    #[test]
    fn custom_ca_failures_are_classified_without_exposing_paths() {
        let directory = TempDir::new().unwrap();
        let missing = directory.path().join("missing.pem");
        assert_eq!(
            activation_error(direct_plan(
                CompiledTlsTrust::Custom,
                Some(missing),
                vec![CompiledHttpVersion::Http1],
            )),
            EgressActivationError::CaUnavailable
        );

        let empty = directory.path().join("empty.pem");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(
            activation_error(direct_plan(
                CompiledTlsTrust::Custom,
                Some(empty),
                vec![CompiledHttpVersion::Http1],
            )),
            EgressActivationError::CaEmpty
        );

        let invalid = directory.path().join("invalid.pem");
        std::fs::write(
            &invalid,
            b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let error = activation_error(direct_plan(
            CompiledTlsTrust::Custom,
            Some(invalid),
            vec![CompiledHttpVersion::Http1],
        ));
        assert!(matches!(
            error,
            EgressActivationError::CaInvalid | EgressActivationError::CaUnusable
        ));
        assert!(!error
            .to_string()
            .contains(directory.path().to_str().unwrap()));
    }

    #[test]
    fn custom_ca_material_reads_are_bracketed_by_cancellation_checks() {
        let directory = TempDir::new().unwrap();
        let ca = write_ca(&directory);
        let plan = direct_plan(
            CompiledTlsTrust::Custom,
            Some(ca.clone()),
            vec![CompiledHttpVersion::Http1],
        );
        let checks = Cell::new(0usize);
        let error =
            match EgressSnapshot::activate(plan, &CredentialSourceRegistry::from_names([]), || {
                let next = checks.get() + 1;
                checks.set(next);
                next == 4
            }) {
                Ok(_) => panic!("post-read cancellation unexpectedly activated egress"),
                Err(error) => error,
            };

        assert_eq!(error, EgressActivationError::ActivationCancelled);
        assert_eq!(checks.get(), 4);
        assert!(!error.to_string().contains(ca.to_str().unwrap()));

        let missing = directory.path().join("unopened-sensitive-ca.pem");
        let error = activation_error_with_cancellation(
            direct_plan(
                CompiledTlsTrust::Custom,
                Some(missing.clone()),
                vec![CompiledHttpVersion::Http1],
            ),
            || true,
        );
        assert_eq!(error, EgressActivationError::ActivationCancelled);
        assert!(!error.to_string().contains(missing.to_str().unwrap()));
    }

    #[test]
    fn native_root_reads_are_bracketed_by_cancellation_checks() {
        let checks = Cell::new(0usize);
        let error = activation_error_with_cancellation(
            direct_plan(
                CompiledTlsTrust::System,
                None,
                vec![CompiledHttpVersion::Http1],
            ),
            || {
                let next = checks.get() + 1;
                checks.set(next);
                next == 2
            },
        );

        assert_eq!(error, EgressActivationError::ActivationCancelled);
        assert_eq!(checks.get(), 2);
    }

    #[test]
    fn compiled_global_header_effects_apply_in_authored_order() {
        let directory = TempDir::new().unwrap();
        let plan = compile_egress(
            directory.path(),
            r#"
[egress]

[[egress.request_headers]]
operation = "set"
when = "always"
name = "x-chain"
value = "one"

[[egress.request_headers]]
operation = "append"
when = "always"
name = "x-chain"
value = "two"

[[egress.request_headers]]
operation = "replace"
when = "always"
name = "x-chain"
search = "one"
replace = "three"
"#,
        );
        let snapshot = activate(plan);
        let mut headers = HeaderMap::new();
        snapshot.apply_request_headers(&mut headers).unwrap();
        assert_eq!(
            headers
                .get_all("x-chain")
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["three", "two"]
        );
    }

    #[test]
    fn credential_actions_resolve_to_indices_and_unknown_names_fail() {
        let directory = TempDir::new().unwrap();
        let plan = compile_egress(
            directory.path(),
            r#"
[credentials]
allowed_custom_headers = ["x-api-key"]

[credentials.sources.token]
source = "environment"
variable = "TEST_TOKEN"

[credentials.sources.api]
source = "environment"
variable = "TEST_API_KEY"

[egress]

[[egress.credential_actions]]
kind = "bearer"
credential = "token"

[[egress.credential_actions]]
kind = "custom_header"
header = "x-api-key"
credential = "api"
"#,
        );
        let sources =
            CredentialSourceRegistry::from_names(["token".to_string(), "api".to_string()]);
        let token = sources.get("token").unwrap();
        let api = sources.get("api").unwrap();
        let snapshot = EgressSnapshot::activate(plan.clone(), &sources, || false).unwrap();
        assert_eq!(
            snapshot.credential_actions(),
            [
                ResolvedCredentialAction::Bearer { source: token },
                ResolvedCredentialAction::CustomHeader {
                    header: "x-api-key".parse().unwrap(),
                    source: api
                }
            ]
        );

        let missing_api = CredentialSourceRegistry::from_names(["token".to_string()]);
        let error = match EgressSnapshot::activate(plan, &missing_api, || false) {
            Ok(_) => panic!("unknown credential name unexpectedly activated"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            EgressActivationError::Credential(CredentialBindingError::UnknownSource)
        );
    }

    #[test]
    fn candidate_activations_do_not_share_owned_material() {
        let directory = TempDir::new().unwrap();
        let plan = compile_egress(
            directory.path(),
            r#"
[credentials.sources.token]
source = "environment"
variable = "TEST_TOKEN"

[egress]

[[egress.request_headers]]
operation = "set"
when = "always"
name = "x-generation"
value = "candidate"

[[egress.credential_actions]]
kind = "bearer"
credential = "token"
"#,
        );
        let sources = CredentialSourceRegistry::from_names(["token".to_string()]);
        let first = EgressSnapshot::activate(plan.clone(), &sources, || false).unwrap();
        let second = EgressSnapshot::activate(plan, &sources, || false).unwrap();

        assert_ne!(
            first.request_headers.as_ptr(),
            second.request_headers.as_ptr()
        );
        assert_ne!(
            first.credential_actions.as_ptr(),
            second.credential_actions.as_ptr()
        );
        let mut first_headers = HeaderMap::new();
        let mut second_headers = HeaderMap::new();
        first.apply_request_headers(&mut first_headers).unwrap();
        second.apply_request_headers(&mut second_headers).unwrap();
        assert_eq!(first_headers, second_headers);
        assert_eq!(first.credential_actions(), second.credential_actions());
        assert!(first_headers.get(AUTHORIZATION).is_none());
    }

    #[test]
    fn route_matrix_rejects_inconsistent_parent_metadata() {
        let mut direct_with_parent = parent_plan(ParentProxyPlan {
            kind: CompiledParentProxyKind::Generic,
            url: "http://parent.example:8080/".to_string(),
            host: "parent.example".to_string(),
            port: 8080,
            tls: None,
        });
        direct_with_parent.route = CompiledEgressRoute::Direct;
        assert_eq!(
            activation_error(direct_with_parent),
            EgressActivationError::Route
        );

        let parent_without_metadata = EgressPlan {
            route: CompiledEgressRoute::ParentProxy,
            origin_tls: TransportTlsPlan {
                trust: CompiledTlsTrust::Insecure,
                ca_certificate: None,
                http_versions: vec![CompiledHttpVersion::Http1],
            },
            parent_proxy: None,
            request_headers: Vec::new(),
            credential_actions: Vec::<CredentialActionPlan>::new(),
        };
        assert_eq!(
            activation_error(parent_without_metadata),
            EgressActivationError::Route
        );
    }
}
