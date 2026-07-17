use std::path::{Path, PathBuf};

use http_access_runtime::{TlsRootCertificate, TlsRootSet, TlsRootsRegistration};
use http_access_types::{
    ClientTlsIntent, HttpProtocol, HttpProtocolSet, HttpScheme, PolicyGeneration, Route,
    SnapshotIdentity, StableId, TlsRootsRef, TlsTrust, TransportSecurity,
};
use http_access_url::{canonicalize_http_url, canonicalize_tls_server_name};

use crate::config::compiler::{
    CompiledEgressRoute, CompiledHttpVersion, CompiledTlsTrust, EgressPlan, ParentProxyPlan,
    ParentProxyTlsPlan, TransportTlsPlan,
};
use crate::tls::{load_custom_ca_der, TlsActivationError};

/// Exact neutral egress inputs produced from one compiled product generation.
pub(crate) struct EgressActivation {
    neutral: NeutralEgressBindings,
    executor: ForwardingExecutorBindings,
    #[cfg(test)]
    custom_ca_file_reads: usize,
}

/// Snapshot material consumed exactly once during standalone finalization.
pub(crate) struct NeutralEgressBindings {
    protocols: HttpProtocolSet,
    origin_https_trust: TlsTrust,
    route: Route,
    tls_roots: Vec<TlsRootsRegistration>,
}

/// Cloneable non-secret inputs retained until shared executor activation.
pub(crate) struct ForwardingExecutorBindings {
    protocols: HttpProtocolSet,
    origin_https_trust: TlsTrust,
    route: Route,
}

struct EgressTrustLoader<'a> {
    custom_ca_der: Vec<(PathBuf, Vec<Vec<u8>>)>,
    is_cancelled: &'a mut dyn FnMut() -> bool,
    #[cfg(test)]
    custom_ca_file_reads: usize,
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
    #[error("custom CA certificate bundle is unavailable")]
    CaUnavailable,
    #[error("custom CA certificate bundle is invalid")]
    CaInvalid,
    #[error("custom CA certificate bundle is empty")]
    CaEmpty,
    #[error("egress neutral TLS bindings are invalid")]
    NeutralTls,
}

impl EgressActivation {
    pub(crate) fn activate(
        plan: EgressPlan,
        identity: &SnapshotIdentity,
        generation: PolicyGeneration,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<Self, EgressActivationError> {
        check_cancellation(&mut is_cancelled)?;
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
        let (protocols, origin_https_trust, origin_roots) =
            activate_origin_tls(origin_tls, identity, generation, &mut trust_loader)?;
        let (route, parent_roots) = match (route, parent_proxy) {
            (CompiledEgressRoute::Direct, None) => (Route::Direct, None),
            (CompiledEgressRoute::ParentProxy, Some(parent)) => {
                activate_parent(parent, identity, generation, &mut trust_loader)?
            }
            _ => return Err(EgressActivationError::Route),
        };
        check_cancellation(trust_loader.is_cancelled)?;

        let executor = ForwardingExecutorBindings {
            protocols: protocols.clone(),
            origin_https_trust: origin_https_trust.clone(),
            route: route.clone(),
        };
        Ok(Self {
            neutral: NeutralEgressBindings {
                protocols,
                origin_https_trust,
                route,
                tls_roots: origin_roots.into_iter().chain(parent_roots).collect(),
            },
            executor,
            #[cfg(test)]
            custom_ca_file_reads: trust_loader.custom_ca_file_reads,
        })
    }

    pub(crate) fn into_parts(self) -> (NeutralEgressBindings, ForwardingExecutorBindings) {
        (self.neutral, self.executor)
    }

    #[cfg(test)]
    fn custom_ca_file_reads(&self) -> usize {
        self.custom_ca_file_reads
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

impl ForwardingExecutorBindings {
    pub(crate) fn into_parts(self) -> (HttpProtocolSet, TlsTrust, Route) {
        (self.protocols, self.origin_https_trust, self.route)
    }
}

impl EgressTrustLoader<'_> {
    fn load_custom(
        &mut self,
        trust: CompiledTlsTrust,
        ca_certificate: Option<&Path>,
    ) -> Result<Option<Vec<Vec<u8>>>, EgressActivationError> {
        if !matches!(
            trust,
            CompiledTlsTrust::Custom | CompiledTlsTrust::SystemPlusCustom
        ) {
            return Ok(None);
        }
        let path = ca_certificate.ok_or(EgressActivationError::CaUnavailable)?;
        if let Some((_, certificates)) = self
            .custom_ca_der
            .iter()
            .find(|(candidate, _)| candidate == path)
        {
            return Ok(Some(certificates.clone()));
        }
        #[cfg(test)]
        {
            self.custom_ca_file_reads += 1;
        }
        let certificates = load_custom_ca_der(path, self.is_cancelled)?;
        self.custom_ca_der
            .push((path.to_path_buf(), certificates.clone()));
        Ok(Some(certificates))
    }
}

fn activate_origin_tls(
    plan: TransportTlsPlan,
    identity: &SnapshotIdentity,
    generation: PolicyGeneration,
    trust_loader: &mut EgressTrustLoader<'_>,
) -> Result<(HttpProtocolSet, TlsTrust, Option<TlsRootsRegistration>), EgressActivationError> {
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
    let custom_ca_der = trust_loader.load_custom(trust, ca_certificate.as_deref())?;
    let (neutral_trust, roots) = neutral_tls_trust(
        trust,
        identity,
        generation,
        "egress-origin-roots",
        custom_ca_der,
    )?;
    warn_if_insecure("origin", trust);
    Ok((protocols, neutral_trust, roots))
}

fn activate_parent(
    plan: ParentProxyPlan,
    identity: &SnapshotIdentity,
    generation: PolicyGeneration,
    trust_loader: &mut EgressTrustLoader<'_>,
) -> Result<(Route, Option<TlsRootsRegistration>), EgressActivationError> {
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
    if target.authority().host().as_str() != host || target.authority().effective_port() != port {
        return Err(EgressActivationError::Route);
    }
    let (security, roots) = match (target.scheme(), tls) {
        (HttpScheme::Http, None) => (TransportSecurity::Cleartext, None),
        (HttpScheme::Https, Some(tls)) => {
            let (intent, roots) = activate_parent_tls(tls, identity, generation, trust_loader)?;
            (TransportSecurity::Tls(intent), roots)
        }
        _ => return Err(EgressActivationError::Route),
    };
    Ok((Route::Parent { target, security }, roots))
}

fn activate_parent_tls(
    plan: ParentProxyTlsPlan,
    identity: &SnapshotIdentity,
    generation: PolicyGeneration,
    trust_loader: &mut EgressTrustLoader<'_>,
) -> Result<(ClientTlsIntent, Option<TlsRootsRegistration>), EgressActivationError> {
    let server_name = canonicalize_tls_server_name(&plan.server_name)
        .map_err(|_| EgressActivationError::ParentServerName)?;
    let custom_ca_der = trust_loader.load_custom(plan.trust, plan.ca_certificate.as_deref())?;
    let (trust, roots) = neutral_tls_trust(
        plan.trust,
        identity,
        generation,
        "egress-parent-roots",
        custom_ca_der,
    )?;
    warn_if_insecure("parent", plan.trust);
    Ok((ClientTlsIntent::new(server_name, trust), roots))
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

fn check_cancellation(is_cancelled: &mut dyn FnMut() -> bool) -> Result<(), EgressActivationError> {
    if is_cancelled() {
        Err(EgressActivationError::ActivationCancelled)
    } else {
        Ok(())
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
            TlsActivationError::CaUnavailable => Self::CaUnavailable,
            TlsActivationError::CaInvalid => Self::CaInvalid,
            TlsActivationError::CaEmpty => Self::CaEmpty,
            TlsActivationError::NativeRoots | TlsActivationError::CaUnusable => Self::NeutralTls,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::io::{self, Write};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex, Once};

    use http_access_types::CanonicalHost;
    use rcgen::generate_simple_self_signed;
    use tempfile::TempDir;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

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

    fn capture_logs(operation: impl FnOnce()) -> String {
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
        let logs = CapturedLogs::default();
        ACTIVE_LOG_CAPTURE.with(|capture| {
            let previous = capture.borrow_mut().replace(logs.clone());
            assert!(previous.is_none(), "test log captures must not be nested");
        });
        let active = ActiveLogCapture;
        operation();
        drop(active);
        logs.text()
    }

    fn origin(trust: CompiledTlsTrust, ca_certificate: Option<PathBuf>) -> TransportTlsPlan {
        TransportTlsPlan {
            trust,
            ca_certificate,
            http_versions: vec![CompiledHttpVersion::Http2, CompiledHttpVersion::Http1],
        }
    }

    fn direct(trust: CompiledTlsTrust, ca_certificate: Option<PathBuf>) -> EgressPlan {
        EgressPlan {
            route: CompiledEgressRoute::Direct,
            origin_tls: origin(trust, ca_certificate),
            parent_proxy: None,
            request_headers: Vec::new(),
            credential_actions: Vec::new(),
        }
    }

    fn activate(plan: EgressPlan) -> EgressActivation {
        EgressActivation::activate(
            plan,
            &SnapshotIdentity::new(),
            PolicyGeneration::new(7).unwrap(),
            || false,
        )
        .unwrap()
    }

    fn write_ca(directory: &TempDir) -> PathBuf {
        let generated = generate_simple_self_signed(vec!["test-ca.example".to_string()]).unwrap();
        let path = directory.path().join("ca.pem");
        std::fs::write(&path, generated.cert.pem()).unwrap();
        path
    }

    #[test]
    fn direct_mapping_preserves_authored_protocol_order_and_trust() {
        let activation = activate(direct(CompiledTlsTrust::System, None));
        let (_, executor) = activation.into_parts();
        let (protocols, trust, route) = executor.into_parts();
        assert_eq!(
            protocols.protocols(),
            [HttpProtocol::Http2, HttpProtocol::Http1]
        );
        assert_eq!(trust, TlsTrust::SystemRoots);
        assert_eq!(route, Route::Direct);
    }

    #[test]
    fn repeated_custom_ca_path_is_read_once_per_generation() {
        let directory = TempDir::new().unwrap();
        let ca = write_ca(&directory);
        let plan = EgressPlan {
            route: CompiledEgressRoute::ParentProxy,
            origin_tls: origin(CompiledTlsTrust::Custom, Some(ca.clone())),
            parent_proxy: Some(ParentProxyPlan {
                #[cfg(test)]
                kind: crate::config::compiler::CompiledParentProxyKind::Generic,
                url: "https://parent.example:8443/".to_owned(),
                host: "parent.example".to_owned(),
                port: 8443,
                tls: Some(ParentProxyTlsPlan {
                    trust: CompiledTlsTrust::Custom,
                    ca_certificate: Some(ca),
                    server_name: "parent.example".to_owned(),
                }),
            }),
            request_headers: Vec::new(),
            credential_actions: Vec::new(),
        };
        let activation = activate(plan);
        assert_eq!(activation.custom_ca_file_reads(), 1);
        let (_, executor) = activation.into_parts();
        let (_, origin_trust, route) = executor.into_parts();
        assert!(matches!(origin_trust, TlsTrust::CustomRoots(_)));
        let Route::Parent { target, security } = route else {
            panic!("expected parent route");
        };
        assert_eq!(target.as_str(), "https://parent.example:8443/");
        let TransportSecurity::Tls(intent) = security else {
            panic!("expected TLS parent");
        };
        assert_eq!(
            intent.authenticated_name(),
            &CanonicalHost::new("parent.example").unwrap()
        );
        assert!(matches!(intent.trust(), TlsTrust::CustomRoots(_)));
    }

    #[test]
    fn neutral_root_bindings_change_for_content_and_generation_and_preserve_trust_mode() {
        let first_directory = TempDir::new().unwrap();
        let second_directory = TempDir::new().unwrap();
        let first_ca = write_ca(&first_directory);
        let second_ca = write_ca(&second_directory);
        let identity = SnapshotIdentity::new();
        let activate_trust = |trust, ca: PathBuf, generation| {
            EgressActivation::activate(direct(trust, Some(ca)), &identity, generation, || false)
                .unwrap()
                .neutral
        };

        let custom = activate_trust(
            CompiledTlsTrust::Custom,
            first_ca.clone(),
            PolicyGeneration::new(7).unwrap(),
        );
        let TlsTrust::CustomRoots(custom_ref) = &custom.origin_https_trust else {
            panic!("custom trust must remain custom-only")
        };
        assert_eq!(custom.tls_roots.len(), 1);

        let combined = activate_trust(
            CompiledTlsTrust::SystemPlusCustom,
            first_ca.clone(),
            PolicyGeneration::new(7).unwrap(),
        );
        let TlsTrust::SystemAndCustomRoots(combined_ref) = &combined.origin_https_trust else {
            panic!("combined trust must retain system roots")
        };
        assert_eq!(custom_ref.binding(), combined_ref.binding());

        let substituted = activate_trust(
            CompiledTlsTrust::Custom,
            second_ca,
            PolicyGeneration::new(7).unwrap(),
        );
        let TlsTrust::CustomRoots(substituted_ref) = &substituted.origin_https_trust else {
            panic!("substituted trust remains custom-only")
        };
        assert_ne!(custom_ref.binding(), substituted_ref.binding());

        let rotated = activate_trust(
            CompiledTlsTrust::Custom,
            first_ca,
            PolicyGeneration::new(8).unwrap(),
        );
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
            origin_tls: origin(CompiledTlsTrust::Custom, Some(ca.clone())),
            parent_proxy: Some(ParentProxyPlan {
                #[cfg(test)]
                kind: crate::config::compiler::CompiledParentProxyKind::Generic,
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
        let identity = SnapshotIdentity::new();
        let activation =
            EgressActivation::activate(plan, &identity, PolicyGeneration::new(7).unwrap(), || {
                false
            })
            .unwrap();

        assert_eq!(activation.custom_ca_file_reads(), 1);
        assert_eq!(activation.neutral.tls_roots.len(), 2);
        assert_eq!(
            activation.neutral.protocols.protocols(),
            [HttpProtocol::Http2, HttpProtocol::Http1]
        );
        let TlsTrust::CustomRoots(origin_ref) = &activation.neutral.origin_https_trust else {
            panic!("origin must retain custom-only trust")
        };
        assert_eq!(origin_ref.id().as_str(), "egress-origin-roots");
        assert!(origin_ref.belongs_to(&identity));
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
        let TlsTrust::CustomRoots(parent_ref) = intent.trust() else {
            panic!("parent must retain custom-only trust")
        };
        assert_eq!(parent_ref.id().as_str(), "egress-parent-roots");
        assert!(parent_ref.belongs_to(&identity));
        assert_eq!(origin_ref.binding(), parent_ref.binding());
    }

    #[test]
    fn http_parent_owns_canonical_endpoint_and_kind() {
        let parent = ParentProxyPlan {
            #[cfg(test)]
            kind: crate::config::compiler::CompiledParentProxyKind::AclProxy,
            url: "http://parent.example:8080/".to_owned(),
            host: "parent.example".to_owned(),
            port: 8080,
            tls: None,
        };
        #[cfg(test)]
        assert!(matches!(
            parent.kind,
            crate::config::compiler::CompiledParentProxyKind::AclProxy
        ));
        let activation = activate(EgressPlan {
            route: CompiledEgressRoute::ParentProxy,
            origin_tls: origin(CompiledTlsTrust::System, None),
            parent_proxy: Some(parent),
            request_headers: Vec::new(),
            credential_actions: Vec::new(),
        });
        let (_, executor) = activation.into_parts();
        let (_, _, Route::Parent { target, security }) = executor.into_parts() else {
            panic!("expected parent route")
        };
        assert_eq!(target.as_str(), "http://parent.example:8080/");
        assert_eq!(security, TransportSecurity::Cleartext);
    }

    #[test]
    fn insecure_origin_and_parent_each_emit_one_sanitized_warning() {
        let origin_logs = capture_logs(|| {
            activate(direct(CompiledTlsTrust::Insecure, None));
        });
        assert_eq!(
            origin_logs
                .matches("TLS certificate verification is disabled")
                .count(),
            1
        );
        assert!(origin_logs.contains("tls_scope=\"origin\""));

        let parent_logs = capture_logs(|| {
            activate(EgressPlan {
                route: CompiledEgressRoute::ParentProxy,
                origin_tls: origin(CompiledTlsTrust::Insecure, None),
                parent_proxy: Some(ParentProxyPlan {
                    #[cfg(test)]
                    kind: crate::config::compiler::CompiledParentProxyKind::Generic,
                    url: "https://parent.example/".to_owned(),
                    host: "parent.example".to_owned(),
                    port: 443,
                    tls: Some(ParentProxyTlsPlan {
                        trust: CompiledTlsTrust::Insecure,
                        ca_certificate: None,
                        server_name: "sensitive-parent-name.example".to_owned(),
                    }),
                }),
                request_headers: Vec::new(),
                credential_actions: Vec::new(),
            });
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
        let cases = [
            (directory.path().join("missing-sensitive.pem"), None),
            (directory.path().join("empty-sensitive.pem"), Some(&b""[..])),
            (
                directory.path().join("invalid-sensitive.pem"),
                Some(&b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"[..]),
            ),
        ];

        for (index, (path, contents)) in cases.into_iter().enumerate() {
            if let Some(contents) = contents {
                std::fs::write(&path, contents).unwrap();
            }
            let error = EgressActivation::activate(
                direct(CompiledTlsTrust::Custom, Some(path.clone())),
                &SnapshotIdentity::new(),
                PolicyGeneration::new(7).unwrap(),
                || false,
            )
            .err()
            .expect("invalid CA input must fail activation");
            match index {
                0 => assert_eq!(error, EgressActivationError::CaUnavailable),
                1 => assert_eq!(error, EgressActivationError::CaEmpty),
                2 => assert!(matches!(
                    error,
                    EgressActivationError::CaInvalid | EgressActivationError::NeutralTls
                )),
                _ => unreachable!(),
            }
            assert!(!error.to_string().contains(path.to_str().unwrap()));
            assert!(!error
                .to_string()
                .contains(directory.path().to_str().unwrap()));
        }
    }

    #[test]
    fn custom_ca_material_reads_are_bracketed_by_cancellation_checks() {
        let directory = TempDir::new().unwrap();
        let ca = write_ca(&directory);

        let pre_read_checks = Cell::new(0_usize);
        let missing = directory.path().join("unopened-sensitive-ca.pem");
        let pre_read_error = EgressActivation::activate(
            direct(CompiledTlsTrust::Custom, Some(missing.clone())),
            &SnapshotIdentity::new(),
            PolicyGeneration::new(7).unwrap(),
            || {
                let next = pre_read_checks.get() + 1;
                pre_read_checks.set(next);
                next == 2
            },
        )
        .err()
        .expect("pre-read cancellation must win over missing-file failure");
        assert_eq!(pre_read_error, EgressActivationError::ActivationCancelled);
        assert_eq!(pre_read_checks.get(), 2);
        assert!(!pre_read_error
            .to_string()
            .contains(missing.to_str().unwrap()));

        let post_read_checks = Cell::new(0_usize);
        let post_read_error = EgressActivation::activate(
            direct(CompiledTlsTrust::Custom, Some(ca.clone())),
            &SnapshotIdentity::new(),
            PolicyGeneration::new(7).unwrap(),
            || {
                let next = post_read_checks.get() + 1;
                post_read_checks.set(next);
                next == 5
            },
        )
        .err()
        .expect("post-read cancellation must prevent activation");
        assert_eq!(post_read_error, EgressActivationError::ActivationCancelled);
        assert_eq!(post_read_checks.get(), 5);
        assert!(!post_read_error.to_string().contains(ca.to_str().unwrap()));
    }

    #[test]
    fn cancellation_precedes_ca_file_io() {
        let error = EgressActivation::activate(
            direct(
                CompiledTlsTrust::Custom,
                Some("/sensitive/missing/ca.pem".into()),
            ),
            &SnapshotIdentity::new(),
            PolicyGeneration::new(7).unwrap(),
            || true,
        )
        .err()
        .expect("cancelled activation must fail");
        assert_eq!(error, EgressActivationError::ActivationCancelled);
        assert!(!error.to_string().contains("/sensitive/"));
    }

    #[test]
    fn invalid_parent_metadata_is_rejected_without_reflecting_values() {
        let plan = EgressPlan {
            route: CompiledEgressRoute::ParentProxy,
            origin_tls: origin(CompiledTlsTrust::System, None),
            parent_proxy: Some(ParentProxyPlan {
                #[cfg(test)]
                kind: crate::config::compiler::CompiledParentProxyKind::Generic,
                url: "http://parent.example:8080/".to_owned(),
                host: "different.example".to_owned(),
                port: 8080,
                tls: None,
            }),
            request_headers: Vec::new(),
            credential_actions: Vec::new(),
        };
        let error = EgressActivation::activate(
            plan,
            &SnapshotIdentity::new(),
            PolicyGeneration::new(7).unwrap(),
            || false,
        )
        .err()
        .expect("inconsistent parent metadata must fail");
        assert_eq!(error, EgressActivationError::Route);
        assert!(!error.to_string().contains("different.example"));
    }
}
