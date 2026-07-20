use std::path::Path;

use http_access_runtime::{TlsRootCertificate, TlsRootSet, TlsRootsRegistration};
use http_access_types::{
    ClientTlsIntent, HttpProtocol, HttpProtocolSet, HttpScheme, PolicyGeneration, Route,
    SnapshotIdentity, StableId, TlsRootsRef, TlsTrust, TransportSecurity,
};
use http_access_url::canonicalize_tls_server_name;

use crate::candidate_ca::CandidateCaResolver;
use crate::config::compiler::{
    CompiledEgressRoute, CompiledHttpVersion, CompiledTlsTrust, EgressPlan, ParentProxyPlan,
    ParentProxyTlsPlan, TransportTlsPlan,
};
use crate::tls::TlsActivationError;

/// Exact neutral egress inputs produced from one compiled product generation.
pub(crate) struct EgressActivation {
    neutral: NeutralEgressBindings,
    executor: ForwardingExecutorBindings,
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

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum EgressActivationError {
    #[error("egress activation was cancelled")]
    ActivationCancelled,
    #[error("egress plan route is inconsistent")]
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
    #[error("custom CA certificate bundle exceeds the shared TLS root limits")]
    CaLimit,
    #[error("custom CA certificate loader is unavailable")]
    CaLoaderUnavailable,
    #[error("egress neutral TLS bindings are invalid")]
    NeutralTls,
}

impl EgressActivation {
    pub(crate) async fn activate(
        plan: EgressPlan,
        identity: &SnapshotIdentity,
        ca_resolver: &mut CandidateCaResolver,
    ) -> Result<Self, EgressActivationError> {
        check_cancellation(ca_resolver)?;
        let EgressPlan {
            route,
            origin_tls,
            parent_proxy,
            ..
        } = plan;
        let generation = ca_resolver.generation();
        let (protocols, origin_https_trust, origin_roots) =
            activate_origin_tls(origin_tls, identity, generation, ca_resolver).await?;
        let (route, parent_roots) = match (route, parent_proxy) {
            (CompiledEgressRoute::Direct, None) => (Route::Direct, None),
            (CompiledEgressRoute::ParentProxy, Some(parent)) => {
                activate_parent(parent, identity, generation, ca_resolver).await?
            }
            _ => return Err(EgressActivationError::Route),
        };
        check_cancellation(ca_resolver)?;

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
        })
    }

    pub(crate) fn into_parts(self) -> (NeutralEgressBindings, ForwardingExecutorBindings) {
        (self.neutral, self.executor)
    }

    #[cfg(test)]
    pub(crate) fn activate_for_test(
        plan: EgressPlan,
        identity: &SnapshotIdentity,
        generation: PolicyGeneration,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<Self, EgressActivationError> {
        assert!(
            !matches!(
                plan.origin_tls.trust,
                CompiledTlsTrust::Custom | CompiledTlsTrust::SystemPlusCustom
            ) && !plan.parent_proxy.as_ref().is_some_and(|parent| {
                parent.tls.as_ref().is_some_and(|tls| {
                    matches!(
                        tls.trust,
                        CompiledTlsTrust::Custom | CompiledTlsTrust::SystemPlusCustom
                    )
                })
            }),
            "custom-CA egress plans must use async production activation"
        );
        if is_cancelled() {
            return Err(EgressActivationError::ActivationCancelled);
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test TLS I/O runtime builds");
        runtime.block_on(async {
            let tls_io =
                crate::tls_io_runtime::TlsIoRuntime::new().expect("test TLS I/O supervisor starts");
            let mut ca_resolver = CandidateCaResolver::new(
                std::sync::Arc::clone(&tls_io),
                crate::runtime::ActivationCancellation::new_for_test(),
                generation,
            );
            let result = Self::activate(plan, identity, &mut ca_resolver).await;
            let _ = tls_io.shutdown_and_wait(None).await;
            result
        })
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

async fn load_custom(
    trust: CompiledTlsTrust,
    ca_certificate: Option<&Path>,
    ca_resolver: &mut CandidateCaResolver,
) -> Result<Option<std::sync::Arc<[Vec<u8>]>>, EgressActivationError> {
    if !matches!(
        trust,
        CompiledTlsTrust::Custom | CompiledTlsTrust::SystemPlusCustom
    ) {
        return Ok(None);
    }
    let path = ca_certificate.ok_or(EgressActivationError::CaUnavailable)?;
    ca_resolver
        .resolve(path)
        .await
        .map(Some)
        .map_err(Into::into)
}

async fn activate_origin_tls(
    plan: TransportTlsPlan,
    identity: &SnapshotIdentity,
    generation: PolicyGeneration,
    ca_resolver: &mut CandidateCaResolver,
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
    let custom_ca_der = load_custom(trust, ca_certificate.as_deref(), ca_resolver).await?;
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

async fn activate_parent(
    plan: ParentProxyPlan,
    identity: &SnapshotIdentity,
    generation: PolicyGeneration,
    ca_resolver: &mut CandidateCaResolver,
) -> Result<(Route, Option<TlsRootsRegistration>), EgressActivationError> {
    let ParentProxyPlan { target, tls, .. } = plan;
    if target.path() != "/" || target.query().is_some() {
        return Err(EgressActivationError::ParentUrl);
    }
    let (security, roots) = match (target.scheme(), tls) {
        (HttpScheme::Http, None) => (TransportSecurity::Cleartext, None),
        (HttpScheme::Https, Some(tls)) => {
            let (intent, roots) =
                activate_parent_tls(tls, identity, generation, ca_resolver).await?;
            (TransportSecurity::Tls(intent), roots)
        }
        _ => return Err(EgressActivationError::Route),
    };
    Ok((Route::Parent { target, security }, roots))
}

async fn activate_parent_tls(
    plan: ParentProxyTlsPlan,
    identity: &SnapshotIdentity,
    generation: PolicyGeneration,
    ca_resolver: &mut CandidateCaResolver,
) -> Result<(ClientTlsIntent, Option<TlsRootsRegistration>), EgressActivationError> {
    let server_name = canonicalize_tls_server_name(&plan.server_name)
        .map_err(|_| EgressActivationError::ParentServerName)?;
    let custom_ca_der =
        load_custom(plan.trust, plan.ca_certificate.as_deref(), ca_resolver).await?;
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
    custom_ca_der: Option<std::sync::Arc<[Vec<u8>]>>,
) -> Result<(TlsTrust, Option<TlsRootsRegistration>), EgressActivationError> {
    match (trust, custom_ca_der) {
        (CompiledTlsTrust::System, None) => Ok((TlsTrust::SystemRoots, None)),
        (CompiledTlsTrust::Insecure, None) => Ok((TlsTrust::Insecure, None)),
        (CompiledTlsTrust::Custom | CompiledTlsTrust::SystemPlusCustom, Some(certificates)) => {
            let certificates = certificates
                .iter()
                .cloned()
                .map(TlsRootCertificate::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(map_shared_root_error)?;
            let roots = TlsRootSet::new(generation, certificates).map_err(map_shared_root_error)?;
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

fn map_shared_root_error(error: http_access_runtime::RuntimeError) -> EgressActivationError {
    match error {
        http_access_runtime::RuntimeError::LimitExceeded => EgressActivationError::CaLimit,
        _ => EgressActivationError::CaInvalid,
    }
}

fn check_cancellation(ca_resolver: &CandidateCaResolver) -> Result<(), EgressActivationError> {
    if ca_resolver.cancellation().is_cancelled() {
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
            TlsActivationError::CaLimit => Self::CaLimit,
            TlsActivationError::CaLoaderUnavailable => Self::CaLoaderUnavailable,
            TlsActivationError::NativeRoots
            | TlsActivationError::CaUnusable
            | TlsActivationError::Configuration => Self::NeutralTls,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::io::{self, Write};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex, Once};
    use std::time::Duration;

    use http_access_types::CanonicalHost;
    use http_access_url::canonicalize_http_url;
    use tempfile::TempDir;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;
    use crate::authorization::webhook::provider::{WebhookActivationError, WebhookProvider};
    use crate::config::compiler::{
        CompiledProviderFailureMode, WebhookProviderPlan, WebhookTlsPlan,
    };
    use crate::test_certificates::TestTlsIdentity;
    use crate::tls::TlsActivationError;

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
        EgressActivation::activate_for_test(
            plan,
            &SnapshotIdentity::new(),
            PolicyGeneration::new(7).unwrap(),
            || false,
        )
        .unwrap()
    }

    async fn activate_candidate(
        plan: EgressPlan,
        identity: &SnapshotIdentity,
        generation: PolicyGeneration,
        cancellation: crate::runtime::ActivationCancellation,
    ) -> (Result<EgressActivation, EgressActivationError>, usize) {
        let tls_io = crate::tls_io_runtime::TlsIoRuntime::new().unwrap();
        let mut ca_resolver =
            CandidateCaResolver::new(std::sync::Arc::clone(&tls_io), cancellation, generation);
        let result = EgressActivation::activate(plan, identity, &mut ca_resolver).await;
        let reads = ca_resolver.file_reads();
        tls_io.shutdown_and_wait(None).await;
        (result, reads)
    }

    fn write_ca(directory: &TempDir) -> PathBuf {
        let generated = TestTlsIdentity::new("test-ca.example");
        let path = directory.path().join("ca.pem");
        crate::filesystem::write_public_file(&path, generated.root_certificate_pem()).unwrap();
        path
    }

    async fn webhook_ca_error(trust: CompiledTlsTrust, path: PathBuf) -> TlsActivationError {
        let tls_io = crate::tls_io_runtime::TlsIoRuntime::new().unwrap();
        let mut ca_resolver = CandidateCaResolver::new(
            std::sync::Arc::clone(&tls_io),
            crate::runtime::ActivationCancellation::new_for_test(),
            PolicyGeneration::new(7).unwrap(),
        );
        let error = WebhookProvider::activate(
            WebhookProviderPlan {
                url: canonicalize_http_url("https://provider.test/authorize").unwrap(),
                timeout: Duration::from_secs(3),
                on_failure: CompiledProviderFailureMode::Deny,
                include_headers: Vec::new(),
                max_request_bytes: 8192,
                max_response_bytes: 4096,
                outputs: BTreeMap::new(),
                tls: Some(WebhookTlsPlan {
                    trust,
                    ca_certificate: Some(path),
                }),
            },
            &mut ca_resolver,
        )
        .await
        .err()
        .expect("invalid webhook roots must fail");
        tls_io.shutdown_and_wait(None).await;
        match error {
            WebhookActivationError::Tls(error) => error,
            WebhookActivationError::Cancelled => panic!("test activation is not cancelled"),
        }
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

    #[tokio::test]
    async fn repeated_custom_ca_path_is_read_once_per_generation() {
        let directory = TempDir::new().unwrap();
        let ca = write_ca(&directory);
        let plan = EgressPlan {
            route: CompiledEgressRoute::ParentProxy,
            origin_tls: origin(CompiledTlsTrust::Custom, Some(ca.clone())),
            parent_proxy: Some(ParentProxyPlan {
                #[cfg(test)]
                kind: crate::config::compiler::CompiledParentProxyKind::Generic,
                target: canonicalize_http_url("https://parent.example:8443/").unwrap(),
                tls: Some(ParentProxyTlsPlan {
                    trust: CompiledTlsTrust::Custom,
                    ca_certificate: Some(ca),
                    server_name: "parent.example".to_owned(),
                }),
            }),
            request_headers: Vec::new(),
            credential_actions: Vec::new(),
        };
        let (activation, reads) = activate_candidate(
            plan,
            &SnapshotIdentity::new(),
            PolicyGeneration::new(7).unwrap(),
            crate::runtime::ActivationCancellation::new_for_test(),
        )
        .await;
        let activation = activation.unwrap();
        assert_eq!(reads, 1);
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

    #[tokio::test]
    async fn egress_and_webhook_share_one_immutable_candidate_ca_snapshot() {
        let directory = TempDir::new().unwrap();
        let ca = write_ca(&directory);
        let tls_io = crate::tls_io_runtime::TlsIoRuntime::new().unwrap();
        let mut ca_resolver = CandidateCaResolver::new(
            std::sync::Arc::clone(&tls_io),
            crate::runtime::ActivationCancellation::new_for_test(),
            PolicyGeneration::new(7).unwrap(),
        );

        EgressActivation::activate(
            direct(CompiledTlsTrust::Custom, Some(ca.clone())),
            &SnapshotIdentity::new(),
            &mut ca_resolver,
        )
        .await
        .expect("egress consumes the candidate CA snapshot");
        crate::filesystem::write_public_file(&ca, b"not a certificate").unwrap();

        let webhook = WebhookProvider::activate(
            WebhookProviderPlan {
                url: canonicalize_http_url("https://provider.test/authorize").unwrap(),
                timeout: Duration::from_secs(3),
                on_failure: CompiledProviderFailureMode::Deny,
                include_headers: Vec::new(),
                max_request_bytes: 8192,
                max_response_bytes: 4096,
                outputs: BTreeMap::new(),
                tls: Some(WebhookTlsPlan {
                    trust: CompiledTlsTrust::Custom,
                    ca_certificate: Some(ca),
                }),
            },
            &mut ca_resolver,
        )
        .await
        .expect("webhook reuses the egress CA snapshot");

        assert!(webhook.tls().is_some());
        assert_eq!(ca_resolver.file_reads(), 1);
        tls_io.shutdown_and_wait(None).await;
    }

    #[tokio::test]
    async fn neutral_root_bindings_change_for_content_and_generation_and_preserve_trust_mode() {
        let first_directory = TempDir::new().unwrap();
        let second_directory = TempDir::new().unwrap();
        let first_ca = write_ca(&first_directory);
        let second_ca = write_ca(&second_directory);
        let identity = SnapshotIdentity::new();
        async fn activate_trust(
            trust: CompiledTlsTrust,
            ca: PathBuf,
            identity: &SnapshotIdentity,
            generation: PolicyGeneration,
        ) -> NeutralEgressBindings {
            activate_candidate(
                direct(trust, Some(ca)),
                identity,
                generation,
                crate::runtime::ActivationCancellation::new_for_test(),
            )
            .await
            .0
            .unwrap()
            .neutral
        }

        let custom = activate_trust(
            CompiledTlsTrust::Custom,
            first_ca.clone(),
            &identity,
            PolicyGeneration::new(7).unwrap(),
        )
        .await;
        let TlsTrust::CustomRoots(custom_ref) = &custom.origin_https_trust else {
            panic!("custom trust must remain custom-only")
        };
        assert_eq!(custom.tls_roots.len(), 1);

        let combined = activate_trust(
            CompiledTlsTrust::SystemPlusCustom,
            first_ca.clone(),
            &identity,
            PolicyGeneration::new(7).unwrap(),
        )
        .await;
        let TlsTrust::SystemAndCustomRoots(combined_ref) = &combined.origin_https_trust else {
            panic!("combined trust must retain system roots")
        };
        assert_eq!(custom_ref.binding(), combined_ref.binding());

        let substituted = activate_trust(
            CompiledTlsTrust::Custom,
            second_ca,
            &identity,
            PolicyGeneration::new(7).unwrap(),
        )
        .await;
        let TlsTrust::CustomRoots(substituted_ref) = &substituted.origin_https_trust else {
            panic!("substituted trust remains custom-only")
        };
        assert_ne!(custom_ref.binding(), substituted_ref.binding());

        let rotated = activate_trust(
            CompiledTlsTrust::Custom,
            first_ca,
            &identity,
            PolicyGeneration::new(8).unwrap(),
        )
        .await;
        let TlsTrust::CustomRoots(rotated_ref) = &rotated.origin_https_trust else {
            panic!("rotated trust remains custom-only")
        };
        assert_eq!(custom_ref.version(), 7);
        assert_eq!(rotated_ref.version(), 8);
        assert_ne!(custom_ref.binding(), rotated_ref.binding());
    }

    #[tokio::test]
    async fn one_custom_ca_read_feeds_origin_parent_and_exact_registrations() {
        let directory = TempDir::new().unwrap();
        let ca = write_ca(&directory);
        let plan = EgressPlan {
            route: CompiledEgressRoute::ParentProxy,
            origin_tls: origin(CompiledTlsTrust::Custom, Some(ca.clone())),
            parent_proxy: Some(ParentProxyPlan {
                #[cfg(test)]
                kind: crate::config::compiler::CompiledParentProxyKind::Generic,
                target: canonicalize_http_url("https://parent.example:8443/").unwrap(),
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
        let (activation, reads) = activate_candidate(
            plan,
            &identity,
            PolicyGeneration::new(7).unwrap(),
            crate::runtime::ActivationCancellation::new_for_test(),
        )
        .await;
        let activation = activation.unwrap();

        assert_eq!(reads, 1);
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
            target: canonicalize_http_url("http://parent.example:8080/").unwrap(),
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
                    target: canonicalize_http_url("https://parent.example/").unwrap(),
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

    #[tokio::test]
    async fn custom_ca_failures_are_classified_without_exposing_paths() {
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
            let error = activate_candidate(
                direct(CompiledTlsTrust::Custom, Some(path.clone())),
                &SnapshotIdentity::new(),
                PolicyGeneration::new(7).unwrap(),
                crate::runtime::ActivationCancellation::new_for_test(),
            )
            .await
            .0
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

    #[tokio::test]
    async fn webhook_and_egress_reject_duplicate_and_excess_root_bundles_identically() {
        let directory = TempDir::new().unwrap();
        let certificate = TestTlsIdentity::new("shared-bounds.example").root_certificate_pem();
        let cases = [
            (
                directory.path().join("duplicate-sensitive.pem"),
                [certificate.clone(), certificate.clone()].concat(),
                EgressActivationError::CaInvalid,
            ),
            (
                directory.path().join("excess-sensitive.pem"),
                certificate.repeat(http_access_runtime::MAX_TLS_ROOT_CERTIFICATES + 1),
                EgressActivationError::CaLimit,
            ),
        ];

        for (path, contents, expected_egress) in cases {
            crate::filesystem::write_public_file(&path, &contents).unwrap();
            for trust in [CompiledTlsTrust::Custom, CompiledTlsTrust::SystemPlusCustom] {
                let egress = activate_candidate(
                    direct(trust, Some(path.clone())),
                    &SnapshotIdentity::new(),
                    PolicyGeneration::new(7).unwrap(),
                    crate::runtime::ActivationCancellation::new_for_test(),
                )
                .await
                .0
                .err()
                .expect("invalid egress roots must fail");
                let webhook = webhook_ca_error(trust, path.clone()).await;

                assert_eq!(egress, expected_egress);
                assert_eq!(egress.to_string(), webhook.to_string());
                assert!(!egress.to_string().contains(path.to_str().unwrap()));
            }
        }
    }

    #[tokio::test]
    async fn cancellation_precedes_ca_file_io() {
        let cancellation = crate::runtime::ActivationCancellation::new_for_test();
        cancellation.cancel_for_test();
        let (error, reads) = activate_candidate(
            direct(
                CompiledTlsTrust::Custom,
                Some("/sensitive/missing/ca.pem".into()),
            ),
            &SnapshotIdentity::new(),
            PolicyGeneration::new(7).unwrap(),
            cancellation,
        )
        .await;
        let error = error.err().expect("cancelled activation must fail");
        assert_eq!(error, EgressActivationError::ActivationCancelled);
        assert_eq!(reads, 0);
        assert!(!error.to_string().contains("/sensitive/"));
    }

    #[test]
    fn parent_target_path_and_query_are_rejected() {
        for target in [
            "http://parent.example:8080/proxy",
            "http://parent.example:8080/?mode=proxy",
        ] {
            let plan = EgressPlan {
                route: CompiledEgressRoute::ParentProxy,
                origin_tls: origin(CompiledTlsTrust::System, None),
                parent_proxy: Some(ParentProxyPlan {
                    #[cfg(test)]
                    kind: crate::config::compiler::CompiledParentProxyKind::Generic,
                    target: canonicalize_http_url(target).unwrap(),
                    tls: None,
                }),
                request_headers: Vec::new(),
                credential_actions: Vec::new(),
            };
            let error = EgressActivation::activate_for_test(
                plan,
                &SnapshotIdentity::new(),
                PolicyGeneration::new(7).unwrap(),
                || false,
            )
            .err()
            .expect("parent target shape must fail");
            assert_eq!(error, EgressActivationError::ParentUrl);
            assert!(!error.to_string().contains(target));
        }
    }
}
