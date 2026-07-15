use std::sync::{Arc, Mutex};

use crate::config::{CompiledConfig, LoadedCompiledConfig};
use crate::observation::ProductObservationRuntime;
use crate::runtime::{GenerationId, Runtime, RuntimeError, StaticOwnership, StaticResources};
use crate::upgrade::UpgradeRuntime;

use super::listeners::{
    PreparedProxyListeners, ProxySupervisor, ProxySupervisorFailure,
    ProxySupervisorFailureObserver, ProxySupervisorStartError, ProxySupervisorStarter,
};
use super::source::FileCandidateSource;
use super::static_resources::{ProductStaticResources, ProductStaticResourcesError};

/// Staged ownership for one product runtime.
///
/// Preparation reserves every configured ingress socket, but deliberately does
/// not assert that proxy supervisors are serving them. Initial publication and
/// ingress confirmation remain separate gates so neither ordering can expose a
/// prematurely ready process.
pub(crate) struct ProductRuntime {
    runtime: Arc<Runtime>,
    static_resources: Arc<ProductStaticResources>,
    observation_runtime: Arc<ProductObservationRuntime>,
    initial: Mutex<Option<CompiledConfig>>,
}

struct ProductProxyFailureObserver {
    static_resources: std::sync::Weak<ProductStaticResources>,
}

impl ProxySupervisorFailureObserver for ProductProxyFailureObserver {
    fn failed(&self, error: Arc<ProxySupervisorFailure>) {
        let Some(static_resources) = self.static_resources.upgrade() else {
            return;
        };
        tracing::error!(error = %error, "proxy supervisor failed");
        static_resources.record_proxy_failure(error);
        StaticResources::begin_shutdown(static_resources.as_ref());
    }
}

impl ProductRuntime {
    pub(crate) async fn prepare(
        loaded: LoadedCompiledConfig,
    ) -> Result<Arc<Self>, ProductRuntimeError> {
        Self::prepare_inner(loaded, None, None).await
    }

    #[cfg(test)]
    pub(crate) async fn prepare_from_prebound(
        loaded: LoadedCompiledConfig,
        listeners: Vec<std::net::TcpListener>,
    ) -> Result<Arc<Self>, ProductRuntimeError> {
        Self::prepare_inner(loaded, Some(listeners), None).await
    }

    #[cfg(test)]
    pub(crate) async fn prepare_from_prebound_with_destination_guard(
        loaded: LoadedCompiledConfig,
        listeners: Vec<std::net::TcpListener>,
        destination_guard: Arc<crate::destination::DestinationGuard>,
    ) -> Result<Arc<Self>, ProductRuntimeError> {
        Self::prepare_inner(loaded, Some(listeners), Some(destination_guard)).await
    }

    async fn prepare_inner(
        loaded: LoadedCompiledConfig,
        #[cfg_attr(not(test), allow(unused_variables))] prebound: Option<
            Vec<std::net::TcpListener>,
        >,
        #[cfg_attr(not(test), allow(unused_variables))] destination_guard: Option<
            Arc<crate::destination::DestinationGuard>,
        >,
    ) -> Result<Arc<Self>, ProductRuntimeError> {
        let LoadedCompiledConfig { metadata, compiled } = loaded;
        #[cfg(test)]
        let static_resources = match destination_guard {
            Some(destination_guard) => ProductStaticResources::try_new_with_destination_guard(
                &compiled.static_config,
                destination_guard,
            )?,
            None => ProductStaticResources::try_new(&compiled.static_config)?,
        };
        #[cfg(not(test))]
        let static_resources = ProductStaticResources::try_new(&compiled.static_config)?;
        let observation_runtime = static_resources.observation_runtime();

        #[cfg(test)]
        let prepared = match prebound {
            Some(listeners) => static_resources.prepare_ingress_from_prebound(listeners),
            None => static_resources.prepare_ingress(),
        };
        #[cfg(not(test))]
        let prepared = static_resources.prepare_ingress();
        if let Err(error) = prepared {
            StaticResources::shutdown(static_resources.as_ref()).await;
            return Err(error.into());
        }

        let source = Arc::new(FileCandidateSource::new(&metadata));
        let activator = static_resources.activator();
        let static_ownership = StaticOwnership::new(
            compiled.static_config.clone(),
            compiled.static_fingerprint.clone(),
            static_resources.clone(),
        );
        let runtime = Runtime::new(static_ownership, source, activator).await?;

        Ok(Arc::new(Self {
            runtime,
            static_resources,
            observation_runtime,
            initial: Mutex::new(Some(compiled)),
        }))
    }

    pub(crate) fn runtime(&self) -> &Arc<Runtime> {
        &self.runtime
    }

    pub(crate) fn observation_runtime(&self) -> &Arc<ProductObservationRuntime> {
        &self.observation_runtime
    }

    pub(crate) fn upgrade_runtime(&self) -> Arc<UpgradeRuntime> {
        self.static_resources.upgrade_runtime()
    }

    /// Transfers the atomically prepared proxy socket bundle to the future
    /// synchronous supervisor-start path. That path must retain joined
    /// supervisor ownership before it confirms ingress startup.
    pub(super) fn take_prepared_proxy_listeners_for_supervisor_start(
        &self,
    ) -> Result<PreparedProxyListeners, ProductRuntimeError> {
        self.static_resources
            .take_prepared_proxy_listeners_for_supervisor_start()
            .map_err(Into::into)
    }

    pub(crate) async fn start_proxy_supervisors(
        self: &Arc<Self>,
        starter: &mut dyn ProxySupervisorStarter,
    ) -> Result<(), ProductRuntimeError> {
        let prepared = self.take_prepared_proxy_listeners_for_supervisor_start()?;
        let observer: Arc<dyn ProxySupervisorFailureObserver> =
            Arc::new(ProductProxyFailureObserver {
                static_resources: Arc::downgrade(&self.static_resources),
            });
        let mut supervisors = Vec::new();
        for listener in prepared.into_entries() {
            match starter.start(
                listener,
                self.static_resources.ingress_assets(),
                observer.clone(),
            ) {
                Ok(supervisor) => supervisors.push(supervisor),
                Err(error) => {
                    rollback_proxy_supervisors(supervisors).await;
                    self.shutdown().await;
                    return Err(error.into());
                }
            }
        }
        if let Err(error) = self
            .static_resources
            .adopt_proxy_supervisors(&mut supervisors)
        {
            rollback_proxy_supervisors(supervisors).await;
            self.shutdown().await;
            return Err(error.into());
        }
        StaticResources::readiness(self.static_resources.as_ref()).mark_ingress_started();
        Ok(())
    }

    pub(crate) async fn wait_for_proxy_failure(&self) -> Option<Arc<ProxySupervisorFailure>> {
        self.static_resources.wait_for_proxy_failure().await
    }

    pub(crate) async fn wait_for_control_failure(
        &self,
    ) -> Option<Arc<crate::control::server::ControlServerRunError>> {
        self.static_resources.wait_for_control_failure().await
    }

    pub(crate) async fn activate_initial(&self) -> Result<GenerationId, ProductRuntimeError> {
        let initial = self
            .initial
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .ok_or(ProductRuntimeError::InitialActivationAlreadyAttempted)?;
        let runtime = self.runtime.clone();
        let activation_runtime = runtime.clone();

        let activation = tokio::spawn(async move {
            match activation_runtime.start(initial).await {
                Ok(generation) => Ok(generation),
                Err(error) => {
                    activation_runtime.shutdown().await;
                    Err(error)
                }
            }
        });

        match activation.await {
            Ok(result) => result.map_err(Into::into),
            Err(_) => {
                runtime.shutdown().await;
                Err(ProductRuntimeError::InitialActivationCoordinator)
            }
        }
    }

    pub(crate) async fn shutdown(&self) {
        self.runtime.shutdown().await;
    }

    pub(crate) fn shutdown_diagnostic(&self) -> Option<String> {
        let control = self.static_resources.control_shutdown_error();
        let proxy = self.static_resources.proxy_shutdown_error();
        match (control, proxy) {
            (None, None) => None,
            (Some(control), None) => Some(format!("control server shutdown failed: {control}")),
            (None, Some(proxy)) => Some(format!("proxy supervisor shutdown failed: {proxy}")),
            (Some(control), Some(proxy)) => Some(format!(
                "control server shutdown failed: {control}; proxy supervisor shutdown failed: {proxy}"
            )),
        }
    }
}

async fn rollback_proxy_supervisors(supervisors: Vec<Arc<dyn ProxySupervisor>>) {
    for supervisor in &supervisors {
        supervisor.begin_shutdown();
    }
    let mut joins = tokio::task::JoinSet::new();
    for supervisor in supervisors {
        joins.spawn(async move { supervisor.abort_and_join().await });
    }
    while let Some(result) = joins.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::error!(%error, "proxy startup rollback failed"),
            Err(error) => tracing::error!(%error, "proxy startup rollback coordinator failed"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductRuntimeError {
    #[error(transparent)]
    StaticResources(#[from] ProductStaticResourcesError),
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    #[error(transparent)]
    ProxySupervisorStart(#[from] ProxySupervisorStartError),
    #[error("initial activation has already been attempted")]
    InitialActivationAlreadyAttempted,
    #[error("initial activation coordinator did not complete")]
    InitialActivationCoordinator,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{SocketAddr, TcpListener};
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tempfile::tempdir;

    use super::*;
    use crate::activation::listeners::{PreparedProxyListener, ProxyListenerConfig};
    use crate::config::compiler::{CompiledHttp1ConnectPolicy, CompiledHttpVersion};
    use crate::config::load_and_compile_exact_config;

    struct FakeSupervisor {
        observer: Arc<dyn ProxySupervisorFailureObserver>,
        kind: super::super::listeners::ProxyListenerKind,
        shutdowns: AtomicUsize,
        graceful_joins: AtomicUsize,
        abort_joins: AtomicUsize,
        fail_shutdown: bool,
    }

    impl FakeSupervisor {
        fn fail(&self) {
            self.observer.failed(Arc::new(ProxySupervisorFailure {
                listener: self.kind,
                message: "injected terminal failure".to_string(),
            }));
        }

        fn joins(&self) -> usize {
            self.graceful_joins.load(Ordering::Acquire) + self.abort_joins.load(Ordering::Acquire)
        }
    }

    impl ProxySupervisor for FakeSupervisor {
        fn begin_shutdown(&self) {
            self.shutdowns.fetch_add(1, Ordering::AcqRel);
        }

        fn close_and_join(
            &self,
        ) -> crate::runtime::BoxFuture<'_, Result<(), ProxySupervisorFailure>> {
            Box::pin(async move {
                self.graceful_joins.fetch_add(1, Ordering::AcqRel);
                if self.fail_shutdown {
                    Err(ProxySupervisorFailure {
                        listener: self.kind,
                        message: "injected shutdown failure".to_string(),
                    })
                } else {
                    Ok(())
                }
            })
        }

        fn abort_and_join(
            &self,
        ) -> crate::runtime::BoxFuture<'_, Result<(), ProxySupervisorFailure>> {
            Box::pin(async move {
                self.abort_joins.fetch_add(1, Ordering::AcqRel);
                if self.fail_shutdown {
                    Err(ProxySupervisorFailure {
                        listener: self.kind,
                        message: "injected shutdown failure".to_string(),
                    })
                } else {
                    Ok(())
                }
            })
        }
    }

    #[derive(Default)]
    struct FakeStarter {
        fail_at: Option<usize>,
        supervisors: Vec<Arc<FakeSupervisor>>,
        configs: Vec<ProxyListenerConfig>,
        fail_shutdown: bool,
    }

    impl ProxySupervisorStarter for FakeStarter {
        fn start(
            &mut self,
            listener: PreparedProxyListener,
            _assets: &Arc<super::super::assets::ProductIngressAssets>,
            observer: Arc<dyn ProxySupervisorFailureObserver>,
        ) -> Result<Arc<dyn ProxySupervisor>, ProxySupervisorStartError> {
            let kind = listener.kind();
            if self.fail_at == Some(self.supervisors.len()) {
                return Err(ProxySupervisorStartError {
                    listener: kind,
                    message: "injected startup failure".to_string(),
                });
            }
            self.configs.push(listener.config);
            let supervisor = Arc::new(FakeSupervisor {
                observer,
                kind,
                shutdowns: AtomicUsize::new(0),
                graceful_joins: AtomicUsize::new(0),
                abort_joins: AtomicUsize::new(0),
                fail_shutdown: self.fail_shutdown,
            });
            self.supervisors.push(supervisor.clone());
            Ok(supervisor)
        }
    }

    fn config(explicit_http: SocketAddr, control: SocketAddr, extra: &str) -> String {
        format!(
            r#"schema_version = 3

[service]
shutdown_drain_timeout = "1s"

[control]
bind = "{control}"
base_path = "/_acl-proxy"
request_header_timeout = "1s"
request_body_timeout = "1s"
max_connections = 2
max_request_body_bytes = 65536

[listeners.explicit_http]
bind = "{explicit_http}"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

{extra}
"#
        )
    }

    fn loaded(text: &str) -> (tempfile::TempDir, LoadedCompiledConfig) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("acl-proxy.toml");
        fs::write(&path, text).unwrap();
        let loaded = load_and_compile_exact_config(&path).unwrap();
        (directory, loaded)
    }

    #[tokio::test]
    async fn publication_before_ingress_confirmation_stays_not_ready() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], ""));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();

        assert!(!product.runtime().is_ready());
        for address in addresses {
            assert!(TcpListener::bind(address).is_err());
        }
        product.activate_initial().await.unwrap();
        assert!(!product.runtime().is_ready());

        let mut starter = FakeStarter::default();
        product.start_proxy_supervisors(&mut starter).await.unwrap();
        assert!(product.runtime().is_ready());
        let [ProxyListenerConfig::ExplicitHttp(config)] = starter.configs.as_slice() else {
            panic!("expected the exact explicit HTTP listener config");
        };
        assert_eq!(config.bind, addresses[0]);
        assert_eq!(config.http_versions, [CompiledHttpVersion::Http1]);
        let connect = config.connect.as_ref().expect("compiled CONNECT policy");
        assert_eq!(connect.http1, Some(CompiledHttp1ConnectPolicy::Deny));
        assert!(!connect.http2_denied);

        product.shutdown().await;
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn ingress_confirmation_before_publication_stays_not_ready() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], ""));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();

        let mut starter = FakeStarter::default();
        product.start_proxy_supervisors(&mut starter).await.unwrap();
        assert!(!product.runtime().is_ready());

        product.activate_initial().await.unwrap();
        assert!(product.runtime().is_ready());

        product.shutdown().await;
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn failed_initial_activation_joins_shutdown_and_releases_every_socket() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let missing_variable = "ACL_PROXY_RUNNER_TEST_MISSING_REDACTION_LITERAL";
        std::env::remove_var(missing_variable);
        let extra = format!(
            r#"[redaction.profiles.secrets]
rules = [{{ literal_environment_variables = ["{missing_variable}"] }}]
"#
        );
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], &extra));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();

        let result = product.activate_initial().await;

        assert!(matches!(
            result,
            Err(ProductRuntimeError::Runtime(
                RuntimeError::CandidateActivation(_)
            ))
        ));
        assert_eq!(
            product.runtime().lifecycle(),
            crate::runtime::LifecycleState::Stopped
        );
        assert!(!product.runtime().is_ready());
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn later_prebind_failure_releases_earlier_proxy_and_control_sockets() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let mut listeners = reservations.into_listeners();
        let blocker = listeners.remove(1);
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], ""));

        let result = ProductRuntime::prepare_from_prebound(loaded, listeners).await;

        assert!(matches!(
            result,
            Err(ProductRuntimeError::StaticResources(
                ProductStaticResourcesError::Control(_)
            ))
        ));
        super::super::assert_listener_addresses_released(&_test, [addresses[0]]);
        drop(blocker);
        super::super::assert_listener_addresses_released(&_test, [addresses[1]]);
    }

    #[tokio::test]
    async fn static_asset_failure_occurs_before_prebinding_and_leaves_every_socket_free() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<3>(&_test);
        let addresses = reservations.addresses();
        let extra = format!(
            r#"[listeners.explicit_https]
bind = "{}"
http_versions = ["http1"]

[listeners.explicit_https.connect]
http1 = "deny"

[listeners.explicit_https.tls]
certificate_chain = "missing-server.pem"
private_key = "missing-server-key.pem"
"#,
            addresses[2]
        );
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], &extra));

        let result =
            ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners()).await;

        assert!(matches!(
            result,
            Err(ProductRuntimeError::StaticResources(
                ProductStaticResourcesError::IngressAssets(_)
            ))
        ));
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn partial_proxy_startup_rolls_back_and_joins_before_returning() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<3>(&_test);
        let addresses = reservations.addresses();
        let extra = format!(
            r#"[listeners.transparent_http]
bind = "{}"
http_versions = ["http1"]
"#,
            addresses[2]
        );
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], &extra));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();
        let mut starter = FakeStarter {
            fail_at: Some(1),
            supervisors: Vec::new(),
            configs: Vec::new(),
            fail_shutdown: false,
        };

        let result = product.start_proxy_supervisors(&mut starter).await;

        assert!(matches!(
            result,
            Err(ProductRuntimeError::ProxySupervisorStart(_))
        ));
        assert_eq!(starter.supervisors.len(), 1);
        assert_eq!(starter.supervisors[0].shutdowns.load(Ordering::Acquire), 1);
        assert_eq!(
            starter.supervisors[0].abort_joins.load(Ordering::Acquire),
            1
        );
        assert_eq!(
            product.runtime().lifecycle(),
            crate::runtime::LifecycleState::Stopped
        );
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn terminal_proxy_failure_is_observed_and_coordinated_shutdown_joins_once() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], ""));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        let mut starter = FakeStarter::default();
        product.start_proxy_supervisors(&mut starter).await.unwrap();
        assert!(product.runtime().is_ready());

        starter.supervisors[0].fail();
        let failure =
            tokio::time::timeout(Duration::from_secs(1), product.wait_for_proxy_failure())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            failure.listener,
            super::super::listeners::ProxyListenerKind::ExplicitHttp
        );
        assert!(!product.runtime().is_ready());
        assert_eq!(
            product.runtime().lifecycle(),
            crate::runtime::LifecycleState::Running
        );
        assert_eq!(starter.supervisors[0].joins(), 0);

        product.shutdown().await;
        product.shutdown().await;
        assert_eq!(starter.supervisors[0].joins(), 1);
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn proxy_join_failure_is_exposed_after_shutdown() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<2>(&_test);
        let addresses = reservations.addresses();
        let (_directory, loaded) = loaded(&config(addresses[0], addresses[1], ""));
        let product = ProductRuntime::prepare_from_prebound(loaded, reservations.into_listeners())
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        let mut starter = FakeStarter {
            fail_shutdown: true,
            ..FakeStarter::default()
        };
        product.start_proxy_supervisors(&mut starter).await.unwrap();

        product.shutdown().await;

        let diagnostic = product
            .shutdown_diagnostic()
            .expect("failed proxy join must remain observable");
        assert!(diagnostic.contains("proxy supervisor shutdown failed"));
        assert!(diagnostic.contains("injected shutdown failure"));
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[test]
    fn runner_module_and_api_names_are_versionless() {
        assert_eq!(Path::new(file!()).file_name().unwrap(), "runner.rs");
        assert!(!std::any::type_name::<ProductRuntime>().contains("V3"));
    }
}
