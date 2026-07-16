use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(test)]
use http::Uri;
use rustls::{ClientConfig, ServerName};

#[cfg(test)]
use crate::config::compiler::CompiledParentProxyKind;
use crate::config::compiler::{
    CompiledEgressRoute, CompiledHttpVersion, CompiledTlsTrust, EgressPlan, ParentProxyPlan,
    ParentProxyTlsPlan, TransportTlsPlan,
};
#[cfg(test)]
use crate::tls::ClientTrust;
use crate::tls::{
    build_client_config, load_client_trust_with_cached_material, ClientAlpn, LoadedClientTrust,
    TlsActivationError,
};
use http_access_runtime::{TlsRootCertificate, TlsRootSet, TlsRootsRegistration};
use http_access_types::{
    CanonicalAuthority, ClientTlsIntent, HttpProtocol, HttpProtocolSet, HttpScheme, HttpVersion,
    PolicyGeneration, Route, SnapshotIdentity, StableId, TlsRootsRef, TlsTrust, TransportSecurity,
};
use http_access_url::{canonicalize_http_url, canonicalize_tls_server_name};

/// Generation-owned outbound transport policy and material.
///
/// Credential policy never enters this transport snapshot.
pub(crate) struct EgressSnapshot {
    identity: Arc<()>,
    route: EgressRoute,
    origin_tls: OriginTls,
}

pub(crate) struct EgressActivation {
    snapshot: EgressSnapshot,
    neutral: NeutralEgressBindings,
    #[cfg(test)]
    custom_ca_file_reads: usize,
}

pub(crate) struct NeutralEgressBindings {
    protocols: HttpProtocolSet,
    origin_https_trust: TlsTrust,
    route: Route,
    tls_roots: Vec<TlsRootsRegistration>,
}

struct EgressTrustLoader<'a> {
    custom_ca_der: Vec<(PathBuf, Vec<Vec<u8>>)>,
    is_cancelled: &'a mut dyn FnMut() -> bool,
    #[cfg(test)]
    custom_ca_file_reads: usize,
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
    protocols: HttpProtocolSet,
    http1_config: Option<Arc<ClientConfig>>,
    http2_config: Option<Arc<ClientConfig>>,
}

pub(crate) struct ParentTls {
    #[cfg(test)]
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
    #[error("egress neutral TLS bindings are invalid")]
    NeutralTls,
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
        identity: &SnapshotIdentity,
        generation: PolicyGeneration,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<EgressActivation, EgressActivationError> {
        let EgressPlan {
            route,
            origin_tls,
            parent_proxy,
            ..
        } = plan;
        let mut trust_loader = EgressTrustLoader {
            custom_ca_der: Vec::new(),
            is_cancelled: &mut is_cancelled,
            #[cfg(test)]
            custom_ca_file_reads: 0,
        };
        let (origin_tls, protocols, origin_https_trust, origin_roots) =
            OriginTls::activate(origin_tls, identity, generation, &mut trust_loader)?;
        let (route, neutral_route, parent_roots) = match (route, parent_proxy) {
            (CompiledEgressRoute::Direct, None) => (EgressRoute::Direct, Route::Direct, None),
            (CompiledEgressRoute::ParentProxy, Some(parent)) => {
                let (endpoint, neutral_route, roots) =
                    ParentEndpoint::activate(parent, identity, generation, &mut trust_loader)?;
                (
                    EgressRoute::Parent(Box::new(endpoint)),
                    neutral_route,
                    roots,
                )
            }
            _ => return Err(EgressActivationError::Route),
        };
        let tls_roots = origin_roots.into_iter().chain(parent_roots).collect();
        Ok(EgressActivation {
            snapshot: Self {
                identity: Arc::new(()),
                route,
                origin_tls,
            },
            neutral: NeutralEgressBindings {
                protocols,
                origin_https_trust,
                route: neutral_route,
                tls_roots,
            },
            #[cfg(test)]
            custom_ca_file_reads: trust_loader.custom_ca_file_reads,
        })
    }

    pub(crate) fn route(&self) -> &EgressRoute {
        &self.route
    }

    pub(crate) fn origin_tls(&self) -> &OriginTls {
        &self.origin_tls
    }
}

impl EgressActivation {
    pub(crate) fn into_parts(self) -> (EgressSnapshot, NeutralEgressBindings) {
        (self.snapshot, self.neutral)
    }

    #[cfg(test)]
    fn custom_ca_file_reads(&self) -> usize {
        self.custom_ca_file_reads
    }
}

impl EgressTrustLoader<'_> {
    fn load(
        &mut self,
        trust: CompiledTlsTrust,
        ca_certificate: Option<&Path>,
    ) -> Result<LoadedClientTrust, EgressActivationError> {
        let cached = ca_certificate.and_then(|path| {
            self.custom_ca_der
                .iter()
                .find(|(candidate, _)| candidate == path)
                .map(|(_, certificates)| certificates.clone())
        });
        #[cfg(test)]
        if ca_certificate.is_some()
            && cached.is_none()
            && matches!(
                trust,
                CompiledTlsTrust::Custom | CompiledTlsTrust::SystemPlusCustom
            )
        {
            self.custom_ca_file_reads += 1;
        }
        let loaded = load_client_trust_with_cached_material(
            trust,
            ca_certificate,
            cached,
            self.is_cancelled,
        )?;
        if let (Some(path), Some(certificates)) = (ca_certificate, loaded.custom_ca_der()) {
            if !self
                .custom_ca_der
                .iter()
                .any(|(candidate, _)| candidate == path)
            {
                self.custom_ca_der
                    .push((path.to_path_buf(), certificates.to_vec()));
            }
        }
        Ok(loaded)
    }
}

impl NeutralEgressBindings {
    pub(crate) fn into_parts(
        self,
    ) -> (HttpProtocolSet, TlsTrust, Route, Vec<TlsRootsRegistration>) {
        (
            self.protocols,
            self.origin_https_trust,
            self.route,
            self.tls_roots,
        )
    }

    #[cfg(test)]
    pub(crate) fn direct_system_for_test() -> Self {
        Self {
            protocols: HttpProtocolSet::new(vec![HttpProtocol::Http1, HttpProtocol::Http2])
                .unwrap(),
            origin_https_trust: TlsTrust::SystemRoots,
            route: Route::Direct,
            tls_roots: Vec::new(),
        }
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
        identity: &SnapshotIdentity,
        generation: PolicyGeneration,
        trust_loader: &mut EgressTrustLoader<'_>,
    ) -> Result<(Self, Route, Option<TlsRootsRegistration>), EgressActivationError> {
        #[cfg(test)]
        let kind = plan.kind;
        let ParentProxyPlan {
            url,
            host,
            port,
            tls,
            ..
        } = plan;
        let target = canonicalize_http_url(&url).map_err(|_| EgressActivationError::ParentUrl)?;
        if target.path() != "/" || target.query().is_some() {
            return Err(EgressActivationError::ParentUrl);
        }
        let scheme = target.scheme();
        let (transport, security, roots) = match (scheme, tls) {
            (HttpScheme::Http, None) => (ParentTransport::Http, TransportSecurity::Cleartext, None),
            (HttpScheme::Https, Some(tls)) => {
                let (tls, intent, roots) =
                    ParentTls::activate(tls, identity, generation, trust_loader)?;
                (
                    ParentTransport::Https(tls),
                    TransportSecurity::Tls(intent),
                    roots,
                )
            }
            _ => return Err(EgressActivationError::Route),
        };
        let authority = target.authority().clone();
        if authority.host().as_str() != host || authority.effective_port() != port {
            return Err(EgressActivationError::Route);
        }
        #[cfg(test)]
        let uri = url
            .parse::<Uri>()
            .map_err(|_| EgressActivationError::ParentUrl)?;
        Ok((
            Self {
                #[cfg(test)]
                kind,
                canonical_url: url,
                #[cfg(test)]
                uri,
                authority,
                transport,
            },
            Route::Parent { target, security },
            roots,
        ))
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
        identity: &SnapshotIdentity,
        generation: PolicyGeneration,
        trust_loader: &mut EgressTrustLoader<'_>,
    ) -> Result<(Self, ClientTlsIntent, Option<TlsRootsRegistration>), EgressActivationError> {
        Self::activate_with_loader(
            plan,
            |trust, ca_certificate| trust_loader.load(trust, ca_certificate),
            identity,
            generation,
        )
    }

    fn activate_with_loader<F>(
        plan: ParentProxyTlsPlan,
        load: F,
        identity: &SnapshotIdentity,
        generation: PolicyGeneration,
    ) -> Result<(Self, ClientTlsIntent, Option<TlsRootsRegistration>), EgressActivationError>
    where
        F: FnOnce(
            CompiledTlsTrust,
            Option<&Path>,
        ) -> Result<LoadedClientTrust, EgressActivationError>,
    {
        let server_name = canonicalize_tls_server_name(&plan.server_name)
            .map_err(|_| EgressActivationError::ParentServerName)?;
        ServerName::try_from(server_name.as_str())
            .map_err(|_| EgressActivationError::ParentServerName)?;
        let enable_sni = server_name.as_str().parse::<IpAddr>().is_err();
        let loaded = load(plan.trust, plan.ca_certificate.as_deref())?;
        let (loaded_trust, custom_ca_der) = loaded.into_parts();
        let (neutral_trust, roots) = neutral_tls_trust(
            plan.trust,
            identity,
            generation,
            "egress-parent-roots",
            custom_ca_der,
        )?;
        let loaded_trust = Arc::new(loaded_trust);
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
        let intent = ClientTlsIntent::new(server_name.clone(), neutral_trust);
        Ok((
            Self {
                #[cfg(test)]
                trust: plan.trust,
                server_name: server_name.into(),
                http1_config,
                http2_config,
            },
            intent,
            roots,
        ))
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
        identity: &SnapshotIdentity,
        generation: PolicyGeneration,
        trust_loader: &mut EgressTrustLoader<'_>,
    ) -> Result<
        (
            Self,
            HttpProtocolSet,
            TlsTrust,
            Option<TlsRootsRegistration>,
        ),
        EgressActivationError,
    > {
        Self::activate_with_loader(
            plan,
            |trust, ca_certificate| trust_loader.load(trust, ca_certificate),
            identity,
            generation,
        )
    }

    fn activate_with_loader<F>(
        plan: TransportTlsPlan,
        load: F,
        identity: &SnapshotIdentity,
        generation: PolicyGeneration,
    ) -> Result<
        (
            Self,
            HttpProtocolSet,
            TlsTrust,
            Option<TlsRootsRegistration>,
        ),
        EgressActivationError,
    >
    where
        F: FnOnce(
            CompiledTlsTrust,
            Option<&Path>,
        ) -> Result<LoadedClientTrust, EgressActivationError>,
    {
        let TransportTlsPlan {
            trust,
            ca_certificate,
            http_versions,
        } = plan;
        let protocols = HttpProtocolSet::new(
            http_versions
                .into_iter()
                .map(|version| match version {
                    CompiledHttpVersion::Http1 => HttpProtocol::Http1,
                    CompiledHttpVersion::Http2 => HttpProtocol::Http2,
                })
                .collect(),
        )
        .map_err(|_| EgressActivationError::Route)?;
        let http1 = protocols.protocols().contains(&HttpProtocol::Http1);
        let http2 = protocols.protocols().contains(&HttpProtocol::Http2);
        let loaded = load(trust, ca_certificate.as_deref())?;
        let (loaded_trust, custom_ca_der) = loaded.into_parts();
        let (neutral_trust, roots) = neutral_tls_trust(
            trust,
            identity,
            generation,
            "egress-origin-roots",
            custom_ca_der,
        )?;
        let loaded_trust = Arc::new(loaded_trust);
        warn_if_insecure("origin", trust);
        Ok((
            Self {
                #[cfg(test)]
                trust,
                protocols: protocols.clone(),
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
            },
            protocols,
            neutral_trust,
            roots,
        ))
    }

    #[cfg(test)]
    pub(crate) fn trust(&self) -> CompiledTlsTrust {
        self.trust
    }

    #[cfg(test)]
    pub(crate) fn protocols(&self) -> &HttpProtocolSet {
        &self.protocols
    }

    pub(crate) fn select_protocol(&self, ingress: HttpProtocol) -> HttpProtocol {
        let version = match ingress {
            HttpProtocol::Http1 => HttpVersion::Http11,
            HttpProtocol::Http2 => HttpVersion::Http2,
        };
        self.protocols.select(version)
    }

    pub(crate) fn client_config(
        &self,
        protocol: HttpProtocol,
    ) -> Result<Arc<ClientConfig>, OriginProtocolError> {
        let config = if protocol == HttpProtocol::Http2 {
            &self.http2_config
        } else {
            &self.http1_config
        };
        config.clone().ok_or(OriginProtocolError::Disabled)
    }

    pub(crate) fn validate_negotiated_alpn(
        &self,
        protocol: HttpProtocol,
        negotiated: Option<&[u8]>,
    ) -> Result<(), OriginProtocolError> {
        self.client_config(protocol)?;
        let compatible = if protocol == HttpProtocol::Http2 {
            negotiated == Some(b"h2")
        } else {
            negotiated.is_none() || negotiated == Some(b"http/1.1")
        };
        compatible
            .then_some(())
            .ok_or(OriginProtocolError::IncompatibleAlpn)
    }
}

fn neutral_tls_trust(
    trust: CompiledTlsTrust,
    identity: &SnapshotIdentity,
    generation: PolicyGeneration,
    id: &'static str,
    custom_ca_der: Option<Vec<Vec<u8>>>,
) -> Result<(TlsTrust, Option<TlsRootsRegistration>), EgressActivationError> {
    match (trust, custom_ca_der) {
        (CompiledTlsTrust::System, None) => Ok((TlsTrust::SystemRoots, None)),
        (CompiledTlsTrust::Insecure, None) => Ok((TlsTrust::Insecure, None)),
        (CompiledTlsTrust::Custom | CompiledTlsTrust::SystemPlusCustom, Some(certificates)) => {
            let certificates = certificates
                .into_iter()
                .map(TlsRootCertificate::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| EgressActivationError::NeutralTls)?;
            let roots = TlsRootSet::new(generation, certificates)
                .map_err(|_| EgressActivationError::NeutralTls)?;
            let reference = TlsRootsRef::new(
                identity.clone(),
                StableId::new(id.to_owned()).map_err(|_| EgressActivationError::NeutralTls)?,
                generation.get(),
                roots.binding(),
            )
            .map_err(|_| EgressActivationError::NeutralTls)?;
            let neutral_trust = match trust {
                CompiledTlsTrust::Custom => TlsTrust::CustomRoots(reference.clone()),
                CompiledTlsTrust::SystemPlusCustom => {
                    TlsTrust::SystemAndCustomRoots(reference.clone())
                }
                _ => unreachable!(),
            };
            let registration = TlsRootsRegistration::new(reference, roots)
                .map_err(|_| EgressActivationError::NeutralTls)?;
            Ok((neutral_trust, Some(registration)))
        }
        _ => Err(EgressActivationError::NeutralTls),
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
    use std::path::PathBuf;
    use std::sync::{Mutex, Once};

    use rcgen::generate_simple_self_signed;
    use tempfile::TempDir;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;
    use crate::config::compiler::ParentProxyTlsPlan;

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

    fn test_identity() -> SnapshotIdentity {
        SnapshotIdentity::new()
    }

    fn test_generation() -> PolicyGeneration {
        PolicyGeneration::new(7).unwrap()
    }

    fn activate_bundle(plan: EgressPlan) -> EgressActivation {
        let identity = test_identity();
        EgressSnapshot::activate(plan, &identity, test_generation(), || false).unwrap()
    }

    fn activate(plan: EgressPlan) -> EgressSnapshot {
        activate_bundle(plan).into_parts().0
    }

    fn activation_error(plan: EgressPlan) -> EgressActivationError {
        activation_error_with_cancellation(plan, || false)
    }

    fn activation_error_with_cancellation(
        plan: EgressPlan,
        is_cancelled: impl FnMut() -> bool,
    ) -> EgressActivationError {
        let identity = test_identity();
        match EgressSnapshot::activate(plan, &identity, test_generation(), is_cancelled) {
            Ok(_) => panic!("egress activation unexpectedly succeeded"),
            Err(error) => error,
        }
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
                snapshot.origin_tls().protocols().protocols(),
                [HttpProtocol::Http1, HttpProtocol::Http2]
            );
            assert_eq!(
                snapshot
                    .origin_tls()
                    .client_config(HttpProtocol::Http1)
                    .unwrap()
                    .alpn_protocols,
                [b"http/1.1".to_vec()]
            );
            assert_eq!(
                snapshot
                    .origin_tls()
                    .client_config(HttpProtocol::Http2)
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
            let expected = if version == CompiledHttpVersion::Http2 {
                HttpProtocol::Http2
            } else {
                HttpProtocol::Http1
            };
            assert_eq!(snapshot.origin_tls().protocols().protocols(), [expected]);
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
                    .client_config(if expected == HttpProtocol::Http2 {
                        HttpProtocol::Http1
                    } else {
                        HttpProtocol::Http2
                    })
                    .err(),
                Some(OriginProtocolError::Disabled)
            );
            let ingress = if expected == HttpProtocol::Http2 {
                HttpProtocol::Http1
            } else {
                HttpProtocol::Http2
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
            snapshot.origin_tls().select_protocol(HttpProtocol::Http1),
            HttpProtocol::Http1
        );
        assert_eq!(
            snapshot.origin_tls().select_protocol(HttpProtocol::Http2),
            HttpProtocol::Http2
        );

        for (versions, ingress, expected) in [
            (
                vec![CompiledHttpVersion::Http1],
                HttpProtocol::Http2,
                HttpProtocol::Http1,
            ),
            (
                vec![CompiledHttpVersion::Http2],
                HttpProtocol::Http1,
                HttpProtocol::Http2,
            ),
        ] {
            let snapshot = activate(direct_plan(CompiledTlsTrust::Insecure, None, versions));
            assert_eq!(snapshot.origin_tls().select_protocol(ingress), expected);
        }
    }

    #[test]
    fn neutral_root_bindings_change_for_content_and_generation_and_preserve_trust_mode() {
        let first_directory = TempDir::new().unwrap();
        let second_directory = TempDir::new().unwrap();
        let first_ca = write_ca(&first_directory);
        let second_ca = write_ca(&second_directory);
        let identity = test_identity();
        let activate_trust = |trust, ca: PathBuf, generation| {
            EgressSnapshot::activate(
                direct_plan(trust, Some(ca), vec![CompiledHttpVersion::Http1]),
                &identity,
                generation,
                || false,
            )
            .unwrap()
            .neutral
        };

        let custom = activate_trust(
            CompiledTlsTrust::Custom,
            first_ca.clone(),
            test_generation(),
        );
        let TlsTrust::CustomRoots(custom_ref) = &custom.origin_https_trust else {
            panic!("custom trust must remain custom-only")
        };
        assert_eq!(custom.tls_roots.len(), 1);

        let combined = activate_trust(
            CompiledTlsTrust::SystemPlusCustom,
            first_ca.clone(),
            test_generation(),
        );
        let TlsTrust::SystemAndCustomRoots(combined_ref) = &combined.origin_https_trust else {
            panic!("combined trust must retain system roots")
        };
        assert_eq!(custom_ref.binding(), combined_ref.binding());

        let substituted = activate_trust(CompiledTlsTrust::Custom, second_ca, test_generation());
        let TlsTrust::CustomRoots(substituted_ref) = &substituted.origin_https_trust else {
            panic!("substituted trust remains custom-only")
        };
        assert_ne!(custom_ref.binding(), substituted_ref.binding());

        let rotated_generation = PolicyGeneration::new(8).unwrap();
        let rotated = activate_trust(CompiledTlsTrust::Custom, first_ca, rotated_generation);
        let TlsTrust::CustomRoots(rotated_ref) = &rotated.origin_https_trust else {
            panic!("rotated trust remains custom-only")
        };
        assert_eq!(custom_ref.version(), 7);
        assert_eq!(rotated_ref.version(), 8);
        assert_ne!(custom_ref.binding(), rotated_ref.binding());
    }

    #[test]
    fn one_custom_ca_read_feeds_origin_parent_and_exact_registrations() {
        let directory = TempDir::new().unwrap();
        let ca = write_ca(&directory);
        let plan = EgressPlan {
            route: CompiledEgressRoute::ParentProxy,
            origin_tls: TransportTlsPlan {
                trust: CompiledTlsTrust::Custom,
                ca_certificate: Some(ca.clone()),
                http_versions: vec![CompiledHttpVersion::Http2, CompiledHttpVersion::Http1],
            },
            parent_proxy: Some(ParentProxyPlan {
                kind: CompiledParentProxyKind::Generic,
                url: "https://parent.example:8443/".to_owned(),
                host: "parent.example".to_owned(),
                port: 8443,
                tls: Some(ParentProxyTlsPlan {
                    trust: CompiledTlsTrust::Custom,
                    ca_certificate: Some(ca),
                    server_name: "authenticated-parent.example".to_owned(),
                }),
            }),
            request_headers: Vec::new(),
            credential_actions: Vec::new(),
        };
        let identity = test_identity();
        let activation =
            EgressSnapshot::activate(plan, &identity, test_generation(), || false).unwrap();

        assert_eq!(activation.custom_ca_file_reads(), 1);
        assert_eq!(activation.neutral.tls_roots.len(), 2);
        assert_eq!(
            activation.neutral.protocols.protocols(),
            [HttpProtocol::Http2, HttpProtocol::Http1]
        );
        let Route::Parent { target, security } = &activation.neutral.route else {
            panic!("neutral route must retain parent")
        };
        assert_eq!(target.as_str(), "https://parent.example:8443/");
        let TransportSecurity::Tls(intent) = security else {
            panic!("HTTPS parent must retain TLS intent")
        };
        assert_eq!(
            intent.authenticated_name().as_str(),
            "authenticated-parent.example"
        );
        assert!(matches!(intent.trust(), TlsTrust::CustomRoots(_)));
    }

    #[test]
    fn origin_tls_loads_trust_once_and_validates_exact_protocol() {
        let load_count = Cell::new(0);
        let identity = test_identity();
        let (tls, _, _, _) = OriginTls::activate_with_loader(
            direct_plan(
                CompiledTlsTrust::Insecure,
                None,
                vec![CompiledHttpVersion::Http1, CompiledHttpVersion::Http2],
            )
            .origin_tls,
            |_trust, _ca_certificate| {
                load_count.set(load_count.get() + 1);
                Ok(LoadedClientTrust::new(ClientTrust::Insecure, None))
            },
            &identity,
            test_generation(),
        )
        .unwrap();

        assert_eq!(load_count.get(), 1);
        assert_eq!(
            tls.client_config(HttpProtocol::Http1)
                .unwrap()
                .alpn_protocols,
            [b"http/1.1".to_vec()]
        );
        assert_eq!(
            tls.client_config(HttpProtocol::Http2)
                .unwrap()
                .alpn_protocols,
            [b"h2".to_vec()]
        );
        assert_eq!(
            tls.validate_negotiated_alpn(HttpProtocol::Http1, None),
            Ok(())
        );
        assert_eq!(
            tls.validate_negotiated_alpn(HttpProtocol::Http1, Some(b"h2")),
            Err(OriginProtocolError::IncompatibleAlpn)
        );
        assert_eq!(
            tls.validate_negotiated_alpn(HttpProtocol::Http2, Some(b"h2")),
            Ok(())
        );
        assert_eq!(
            tls.validate_negotiated_alpn(HttpProtocol::Http2, None),
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
        let identity = test_identity();
        let (tls, _, _) = ParentTls::activate_with_loader(
            ParentProxyTlsPlan {
                trust: CompiledTlsTrust::Custom,
                ca_certificate: Some(write_ca(&directory)),
                server_name: "parent.example".to_string(),
            },
            |trust, ca_certificate| {
                load_count.set(load_count.get() + 1);
                load_client_trust_with_cached_material(trust, ca_certificate, None, &mut || false)
                    .map_err(Into::into)
            },
            &identity,
            test_generation(),
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
        let snapshot = activate(parent_plan(ParentProxyPlan {
            kind: CompiledParentProxyKind::Generic,
            url: "https://parent.example/".to_owned(),
            host: "parent.example".to_owned(),
            port: 443,
            tls: Some(ParentProxyTlsPlan {
                trust: CompiledTlsTrust::Insecure,
                ca_certificate: None,
                server_name: "parent.example".to_string(),
            }),
        }));
        let EgressRoute::Parent(parent) = snapshot.route() else {
            panic!("expected parent route");
        };
        let ParentTransport::Https(tls) = parent.transport() else {
            panic!("expected parent TLS");
        };

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
            activate(parent_plan(ParentProxyPlan {
                kind: CompiledParentProxyKind::Generic,
                url: "https://parent.example/".to_owned(),
                host: "parent.example".to_owned(),
                port: 443,
                tls: Some(ParentProxyTlsPlan {
                    trust: CompiledTlsTrust::Insecure,
                    ca_certificate: None,
                    server_name: "sensitive-parent-name.example".to_string(),
                }),
            }));
        });
        assert_eq!(
            parent_logs
                .matches("TLS certificate verification is disabled")
                .count(),
            2
        );
        assert!(parent_logs.contains("tls_scope=\"origin\""));
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
        let identity = test_identity();
        let error = match EgressSnapshot::activate(plan, &identity, test_generation(), || {
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
            credential_actions: Vec::new(),
        };
        assert_eq!(
            activation_error(parent_without_metadata),
            EgressActivationError::Route
        );

        for url in [
            "http://parent.example:8080/not-root",
            "http://parent.example:8080/?mode=unsafe",
        ] {
            assert_eq!(
                activation_error(parent_plan(ParentProxyPlan {
                    kind: CompiledParentProxyKind::Generic,
                    url: url.to_owned(),
                    host: "parent.example".to_owned(),
                    port: 8080,
                    tls: None,
                })),
                EgressActivationError::ParentUrl
            );
        }
    }
}
