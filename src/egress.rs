use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use http::Uri;
use rustls::{ClientConfig, ServerName};

#[cfg(test)]
use crate::config::compiler::CompiledParentProxyKind;
use crate::config::compiler::{
    CompiledEgressRoute, CompiledHttpVersion, CompiledTlsTrust, EgressPlan, ParentProxyPlan,
    ParentProxyTlsPlan, TransportTlsPlan,
};
use crate::credentials::{
    resolve_credential_action, CredentialBindingError, ResolvedCredentialAction,
};
use crate::runtime::CredentialSourceRegistry;
use crate::tls::{
    build_client_config, load_client_trust, ClientAlpn, ClientTrust, TlsActivationError,
};
use http_access_types::{CanonicalAuthority, HttpScheme};
use http_access_url::{canonicalize_http_authority, canonicalize_tls_server_name};

/// Generation-owned outbound transport policy and material.
///
/// Activation consumes every path and logical credential name from the pure
/// plan. The standalone generation binds runtime credential indices during
/// activation; requests receive only the resulting neutral forwarding plan.
pub(crate) struct EgressSnapshot {
    identity: Arc<()>,
    route: EgressRoute,
    origin_tls: OriginTls,
    credential_actions: Box<[ResolvedCredentialAction]>,
}

pub(crate) enum EgressRoute {
    Direct,
    Parent(Box<ParentEndpoint>),
}

pub(crate) struct ParentEndpoint {
    #[cfg(test)]
    kind: CompiledParentProxyKind,
    canonical_url: String,
    #[cfg(test)]
    uri: Uri,
    authority: CanonicalAuthority,
    transport: ParentTransport,
}

pub(crate) enum ParentTransport {
    Http,
    Https(ParentTls),
}

pub(crate) struct OriginTls {
    #[cfg(test)]
    trust: CompiledTlsTrust,
    http_versions: Box<[CompiledHttpVersion]>,
    http1_config: Option<Arc<ClientConfig>>,
    http2_config: Option<Arc<ClientConfig>>,
    custom_roots: Option<ActivatedTlsRoots>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OriginProtocol {
    Http1,
    Http2,
}

impl OriginProtocol {
    pub(crate) fn is_http2(self) -> bool {
        self == Self::Http2
    }

    fn from_compiled(version: CompiledHttpVersion) -> Self {
        match version {
            CompiledHttpVersion::Http1 => Self::Http1,
            CompiledHttpVersion::Http2 => Self::Http2,
        }
    }
}

pub(crate) struct ParentTls {
    #[cfg(test)]
    trust: CompiledTlsTrust,
    server_name: String,
    http1_config: Arc<ClientConfig>,
    http2_config: Arc<ClientConfig>,
    custom_roots: Option<ActivatedTlsRoots>,
}

#[derive(Clone)]
pub(crate) struct ActivatedTlsRoots {
    trust: CompiledTlsTrust,
    _store: Arc<ClientTrust>,
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

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum OriginProtocolError {
    #[error("the authorized origin HTTP protocol is not enabled")]
    Disabled,
    #[error("origin TLS did not negotiate an enabled HTTP protocol")]
    IncompatibleAlpn,
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
            request_headers: _,
            credential_actions,
        } = plan;
        let origin_tls = OriginTls::activate(origin_tls, &mut is_cancelled)?;
        let route = match (route, parent_proxy) {
            (CompiledEgressRoute::Direct, None) => EgressRoute::Direct,
            (CompiledEgressRoute::ParentProxy, Some(parent)) => EgressRoute::Parent(Box::new(
                ParentEndpoint::activate(parent, &mut is_cancelled)?,
            )),
            _ => return Err(EgressActivationError::Route),
        };
        let credential_actions = credential_actions
            .into_iter()
            .map(|action| resolve_credential_action(action, credential_sources))
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();

        Ok(Self {
            identity: Arc::new(()),
            route,
            origin_tls,
            credential_actions,
        })
    }

    pub(crate) fn route(&self) -> &EgressRoute {
        &self.route
    }

    pub(crate) fn origin_tls(&self) -> &OriginTls {
        &self.origin_tls
    }

    pub(crate) fn origin_custom_roots(&self) -> Option<ActivatedTlsRoots> {
        self.origin_tls.custom_roots.clone()
    }

    pub(crate) fn parent_custom_roots(&self) -> Option<ActivatedTlsRoots> {
        let EgressRoute::Parent(parent) = &self.route else {
            return None;
        };
        let ParentTransport::Https(tls) = parent.transport() else {
            return None;
        };
        tls.custom_roots.clone()
    }

    pub(crate) fn credential_actions(&self) -> &[ResolvedCredentialAction] {
        &self.credential_actions
    }
}

impl crate::runtime::EgressSnapshot for EgressSnapshot {
    fn identity(&self) -> &Arc<()> {
        &self.identity
    }

    fn route(&self) -> &EgressRoute {
        EgressSnapshot::route(self)
    }

    fn origin_tls(&self) -> &OriginTls {
        EgressSnapshot::origin_tls(self)
    }
}

impl ParentEndpoint {
    fn activate(
        plan: ParentProxyPlan,
        is_cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<Self, EgressActivationError> {
        #[cfg(test)]
        let kind = plan.kind;
        let ParentProxyPlan {
            url,
            host,
            port,
            tls,
            ..
        } = plan;
        let uri = url
            .parse::<Uri>()
            .map_err(|_| EgressActivationError::ParentUrl)?;
        let scheme = match uri.scheme_str() {
            Some("http") => HttpScheme::Http,
            Some("https") => HttpScheme::Https,
            _ => return Err(EgressActivationError::ParentUrl),
        };
        let transport = match (scheme, tls) {
            (HttpScheme::Http, None) => ParentTransport::Http,
            (HttpScheme::Https, Some(tls)) => {
                ParentTransport::Https(ParentTls::activate(tls, is_cancelled)?)
            }
            _ => return Err(EgressActivationError::Route),
        };
        let authority = canonicalize_http_authority(
            scheme,
            uri.authority()
                .ok_or(EgressActivationError::ParentUrl)?
                .as_str(),
        )
        .map_err(|_| EgressActivationError::ParentUrl)?;
        if authority.host().as_str() != host || authority.effective_port() != port {
            return Err(EgressActivationError::Route);
        }
        Ok(Self {
            #[cfg(test)]
            kind,
            canonical_url: url,
            #[cfg(test)]
            uri,
            authority,
            transport,
        })
    }

    #[cfg(test)]
    pub(crate) fn kind(&self) -> CompiledParentProxyKind {
        self.kind
    }

    pub(crate) fn canonical_url(&self) -> &str {
        &self.canonical_url
    }

    #[cfg(test)]
    pub(crate) fn uri(&self) -> &Uri {
        &self.uri
    }

    #[cfg(test)]
    pub(crate) fn host(&self) -> &str {
        self.authority.host().as_str()
    }

    #[cfg(test)]
    pub(crate) fn port(&self) -> u16 {
        self.authority.effective_port()
    }

    pub(crate) fn authority(&self) -> &CanonicalAuthority {
        &self.authority
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
            load_client_trust(trust, ca_certificate, is_cancelled).map_err(Into::into)
        })
    }

    fn activate_with_loader<F>(
        plan: ParentProxyTlsPlan,
        load: F,
    ) -> Result<Self, EgressActivationError>
    where
        F: FnOnce(CompiledTlsTrust, Option<&Path>) -> Result<ClientTrust, EgressActivationError>,
    {
        let server_name = canonicalize_tls_server_name(&plan.server_name)
            .map_err(|_| EgressActivationError::ParentServerName)?;
        ServerName::try_from(server_name.as_str())
            .map_err(|_| EgressActivationError::ParentServerName)?;
        let enable_sni = server_name.as_str().parse::<IpAddr>().is_err();
        let loaded_trust = Arc::new(load(plan.trust, plan.ca_certificate.as_deref())?);
        let custom_roots = matches!(
            plan.trust,
            CompiledTlsTrust::Custom | CompiledTlsTrust::SystemPlusCustom
        )
        .then(|| ActivatedTlsRoots {
            trust: plan.trust,
            _store: loaded_trust.clone(),
        });
        warn_if_insecure("parent", plan.trust);
        let http1_config = Arc::new(build_client_config(
            loaded_trust.as_ref(),
            ClientAlpn::Http1,
            enable_sni,
        ));
        let http2_config = Arc::new(build_client_config(
            loaded_trust.as_ref(),
            ClientAlpn::Http2,
            enable_sni,
        ));
        Ok(Self {
            #[cfg(test)]
            trust: plan.trust,
            server_name: server_name.into(),
            http1_config,
            http2_config,
            custom_roots,
        })
    }

    #[cfg(test)]
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

impl OriginTls {
    fn activate(
        plan: TransportTlsPlan,
        is_cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<Self, EgressActivationError> {
        Self::activate_with_loader(plan, |trust, ca_certificate| {
            load_client_trust(trust, ca_certificate, is_cancelled).map_err(Into::into)
        })
    }

    fn activate_with_loader<F>(
        plan: TransportTlsPlan,
        load: F,
    ) -> Result<Self, EgressActivationError>
    where
        F: FnOnce(CompiledTlsTrust, Option<&Path>) -> Result<ClientTrust, EgressActivationError>,
    {
        let TransportTlsPlan {
            trust,
            ca_certificate,
            http_versions,
        } = plan;
        let http1 = http_versions.contains(&CompiledHttpVersion::Http1);
        let http2 = http_versions.contains(&CompiledHttpVersion::Http2);
        if !http1 && !http2 {
            return Err(EgressActivationError::Route);
        }

        let loaded_trust = Arc::new(load(trust, ca_certificate.as_deref())?);
        let custom_roots = matches!(
            trust,
            CompiledTlsTrust::Custom | CompiledTlsTrust::SystemPlusCustom
        )
        .then(|| ActivatedTlsRoots {
            trust,
            _store: loaded_trust.clone(),
        });
        warn_if_insecure("origin", trust);
        Ok(Self {
            #[cfg(test)]
            trust,
            http_versions: http_versions.into_boxed_slice(),
            http1_config: http1.then(|| {
                Arc::new(build_client_config(
                    loaded_trust.as_ref(),
                    ClientAlpn::Http1,
                    true,
                ))
            }),
            http2_config: http2.then(|| {
                Arc::new(build_client_config(
                    loaded_trust.as_ref(),
                    ClientAlpn::Http2,
                    true,
                ))
            }),
            custom_roots,
        })
    }

    #[cfg(test)]
    pub(crate) fn trust(&self) -> CompiledTlsTrust {
        self.trust
    }

    #[cfg(test)]
    pub(crate) fn http_versions(&self) -> &[CompiledHttpVersion] {
        &self.http_versions
    }

    pub(crate) fn select_protocol(&self, ingress: OriginProtocol) -> OriginProtocol {
        let ingress_enabled = if ingress.is_http2() {
            self.http2_config.is_some()
        } else {
            self.http1_config.is_some()
        };
        if ingress_enabled {
            return ingress;
        }

        OriginProtocol::from_compiled(
            *self
                .http_versions
                .first()
                .expect("activated origin TLS has an enabled HTTP protocol"),
        )
    }

    pub(crate) fn client_config(
        &self,
        protocol: OriginProtocol,
    ) -> Result<Arc<ClientConfig>, OriginProtocolError> {
        let config = if protocol.is_http2() {
            &self.http2_config
        } else {
            &self.http1_config
        };
        config.clone().ok_or(OriginProtocolError::Disabled)
    }

    pub(crate) fn validate_negotiated_alpn(
        &self,
        protocol: OriginProtocol,
        negotiated: Option<&[u8]>,
    ) -> Result<(), OriginProtocolError> {
        self.client_config(protocol)?;
        let compatible = if protocol.is_http2() {
            negotiated == Some(b"h2")
        } else {
            negotiated.is_none() || negotiated == Some(b"http/1.1")
        };
        compatible
            .then_some(())
            .ok_or(OriginProtocolError::IncompatibleAlpn)
    }
}

impl ActivatedTlsRoots {
    pub(crate) fn trust(&self) -> CompiledTlsTrust {
        self.trust
    }
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

impl From<TlsActivationError> for EgressActivationError {
    fn from(error: TlsActivationError) -> Self {
        match error {
            TlsActivationError::ActivationCancelled => Self::ActivationCancelled,
            TlsActivationError::NativeRoots => Self::NativeRoots,
            TlsActivationError::CaUnavailable => Self::CaUnavailable,
            TlsActivationError::CaInvalid => Self::CaInvalid,
            TlsActivationError::CaEmpty => Self::CaEmpty,
            TlsActivationError::CaUnusable => Self::CaUnusable,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, Once};

    use rcgen::generate_simple_self_signed;
    use tempfile::TempDir;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;
    use crate::config::compiler::{CredentialActionPlan, ParentProxyTlsPlan};
    use crate::config::{compile_config_text, ConfigTextInput};

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    #[derive(Clone, Copy)]
    struct TestLogWriterFactory;

    struct TestLogWriter(Option<CapturedLogs>);

    thread_local! {
        static ACTIVE_LOG_CAPTURE: RefCell<Option<CapturedLogs>> = const { RefCell::new(None) };
    }

    static TEST_LOG_SUBSCRIBER: Once = Once::new();

    impl Write for TestLogWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(logs) = &self.0 {
                logs.0.lock().unwrap().extend_from_slice(bytes);
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for TestLogWriterFactory {
        type Writer = TestLogWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            TestLogWriter(ACTIVE_LOG_CAPTURE.with(|capture| capture.borrow().clone()))
        }
    }

    impl CapturedLogs {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    struct ActiveLogCapture;

    impl Drop for ActiveLogCapture {
        fn drop(&mut self) {
            ACTIVE_LOG_CAPTURE.with(|capture| {
                capture.borrow_mut().take();
            });
        }
    }

    fn initialize_test_log_subscriber() {
        TEST_LOG_SUBSCRIBER.call_once(|| {
            let subscriber = tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_max_level(tracing::Level::WARN)
                .with_writer(TestLogWriterFactory)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("test tracing subscriber must be installed only once");
        });
    }

    fn capture_logs(operation: impl FnOnce()) -> String {
        initialize_test_log_subscriber();
        let logs = CapturedLogs::default();
        ACTIVE_LOG_CAPTURE.with(|capture| {
            let previous = capture.borrow_mut().replace(logs.clone());
            assert!(previous.is_none(), "test log captures must not be nested");
        });
        let capture = ActiveLogCapture;
        operation();
        drop(capture);
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
            assert!(snapshot.origin_tls().trust() == trust);
            assert_eq!(
                snapshot.origin_tls().http_versions(),
                [CompiledHttpVersion::Http1, CompiledHttpVersion::Http2]
            );
            assert_eq!(
                snapshot
                    .origin_tls()
                    .client_config(OriginProtocol::Http1)
                    .unwrap()
                    .alpn_protocols,
                [b"http/1.1".to_vec()]
            );
            assert_eq!(
                snapshot
                    .origin_tls()
                    .client_config(OriginProtocol::Http2)
                    .unwrap()
                    .alpn_protocols,
                [b"h2".to_vec()]
            );
        }
    }

    #[test]
    fn direct_route_honors_single_origin_protocols() {
        for version in [CompiledHttpVersion::Http1, CompiledHttpVersion::Http2] {
            let snapshot = activate(direct_plan(CompiledTlsTrust::Insecure, None, vec![version]));
            assert_eq!(snapshot.origin_tls().http_versions(), [version]);
            let expected = if version == CompiledHttpVersion::Http2 {
                OriginProtocol::Http2
            } else {
                OriginProtocol::Http1
            };
            let expected_alpn: &[u8] = if version == CompiledHttpVersion::Http2 {
                b"h2"
            } else {
                b"http/1.1"
            };
            assert_eq!(
                snapshot
                    .origin_tls()
                    .client_config(expected)
                    .unwrap()
                    .alpn_protocols,
                [expected_alpn.to_vec()]
            );
            assert_eq!(
                snapshot
                    .origin_tls()
                    .client_config(if expected.is_http2() {
                        OriginProtocol::Http1
                    } else {
                        OriginProtocol::Http2
                    })
                    .err(),
                Some(OriginProtocolError::Disabled)
            );
            let ingress = if expected.is_http2() {
                OriginProtocol::Http1
            } else {
                OriginProtocol::Http2
            };
            assert_eq!(snapshot.origin_tls().select_protocol(ingress), expected);
            assert_eq!(snapshot.origin_tls().select_protocol(expected), expected);
            let incompatible: &[u8] = if version == CompiledHttpVersion::Http2 {
                b"http/1.1"
            } else {
                b"h2"
            };
            assert_eq!(
                snapshot
                    .origin_tls()
                    .validate_negotiated_alpn(expected, Some(incompatible)),
                Err(OriginProtocolError::IncompatibleAlpn)
            );
            assert_eq!(
                snapshot
                    .origin_tls()
                    .validate_negotiated_alpn(expected, Some(expected_alpn)),
                Ok(())
            );
        }
    }

    #[test]
    fn origin_protocol_selection_preserves_enabled_ingress_and_falls_back_to_enabled_protocol() {
        let snapshot = activate(direct_plan(
            CompiledTlsTrust::Insecure,
            None,
            vec![CompiledHttpVersion::Http1, CompiledHttpVersion::Http2],
        ));
        assert_eq!(
            snapshot.origin_tls().select_protocol(OriginProtocol::Http1),
            OriginProtocol::Http1
        );
        assert_eq!(
            snapshot.origin_tls().select_protocol(OriginProtocol::Http2),
            OriginProtocol::Http2
        );

        for (versions, ingress, expected) in [
            (
                vec![CompiledHttpVersion::Http1],
                OriginProtocol::Http2,
                OriginProtocol::Http1,
            ),
            (
                vec![CompiledHttpVersion::Http2],
                OriginProtocol::Http1,
                OriginProtocol::Http2,
            ),
        ] {
            let snapshot = activate(direct_plan(CompiledTlsTrust::Insecure, None, versions));
            assert_eq!(snapshot.origin_tls().select_protocol(ingress), expected);
        }
    }

    #[test]
    fn origin_tls_loads_trust_once_and_validates_exact_protocol() {
        let load_count = Cell::new(0);
        let tls = OriginTls::activate_with_loader(
            direct_plan(
                CompiledTlsTrust::Insecure,
                None,
                vec![CompiledHttpVersion::Http1, CompiledHttpVersion::Http2],
            )
            .origin_tls,
            |_trust, _ca_certificate| {
                load_count.set(load_count.get() + 1);
                Ok(ClientTrust::Insecure)
            },
        )
        .unwrap();

        assert_eq!(load_count.get(), 1);
        assert_eq!(
            tls.client_config(OriginProtocol::Http1)
                .unwrap()
                .alpn_protocols,
            [b"http/1.1".to_vec()]
        );
        assert_eq!(
            tls.client_config(OriginProtocol::Http2)
                .unwrap()
                .alpn_protocols,
            [b"h2".to_vec()]
        );
        assert_eq!(
            tls.validate_negotiated_alpn(OriginProtocol::Http1, None),
            Ok(())
        );
        assert_eq!(
            tls.validate_negotiated_alpn(OriginProtocol::Http1, Some(b"h2")),
            Err(OriginProtocolError::IncompatibleAlpn)
        );
        assert_eq!(
            tls.validate_negotiated_alpn(OriginProtocol::Http2, Some(b"h2")),
            Ok(())
        );
        assert_eq!(
            tls.validate_negotiated_alpn(OriginProtocol::Http2, None),
            Err(OriginProtocolError::IncompatibleAlpn)
        );
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
                load_client_trust(trust, ca_certificate, &mut || false).map_err(Into::into)
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
    fn candidate_activations_do_not_share_bound_credentials() {
        let directory = TempDir::new().unwrap();
        let plan = compile_egress(
            directory.path(),
            r#"
[credentials.sources.token]
source = "environment"
variable = "TEST_TOKEN"

[egress]

[[egress.credential_actions]]
kind = "bearer"
credential = "token"
"#,
        );
        let sources = CredentialSourceRegistry::from_names(["token".to_string()]);
        let first = EgressSnapshot::activate(plan.clone(), &sources, || false).unwrap();
        let second = EgressSnapshot::activate(plan, &sources, || false).unwrap();

        assert_ne!(
            first.credential_actions.as_ptr(),
            second.credential_actions.as_ptr()
        );
        assert_eq!(first.credential_actions(), second.credential_actions());
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
