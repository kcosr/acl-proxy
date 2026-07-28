use std::net::{SocketAddr, TcpListener};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use tokio::sync::watch;

use http_access_runtime::{
    LocalAddressProvider, UpgradeRuntime, UpgradeRuntimeError, UpgradeRuntimeLimits,
};

use crate::authorization::callback::PendingTerminalCause;
use crate::authorization::webhook::runtime::{
    WebhookAuthorizationRuntime, WebhookAuthorizationRuntimeError,
};
use crate::config::{StaticFingerprint, StaticFingerprintError, StaticProductConfig};
use crate::control::server::{
    ControlServer, ControlServerError, ControlServerFailureObserver, ControlServerRunError,
    ControlServerShutdownError,
};
use crate::credential_io_runtime::{
    CredentialIoRuntime, CredentialIoRuntimeError, CredentialIoShutdownOutcome,
};
use crate::identity::{IdentityActivationError, IdentityPublisher, IdentitySourceRegistry};
use crate::logging::{process_logging_level_control, LoggingLevelControl};
use crate::observation::{
    ProductObservationRuntime, ProductObservationRuntimeStartError,
    ProductObservationShutdownOutcome,
};
use crate::runtime::{BoxFuture, ServiceReadiness, StaticResourceBrand, StaticResources};
use crate::safety::WireBodyPool;
use crate::tls_io_runtime::{TlsIoRuntime, TlsIoRuntimeError, TlsIoShutdownOutcome};

use super::access_flow_security::{
    AccessFlowSecurityMaterialError, AccessFlowSecurityMaterialRuntime,
    AccessFlowSecuritySubscription,
};
use super::assets::{ProductIngressAssets, ProductIngressAssetsError};
use super::listeners::{
    LocalAddressRefreshFailureObserver, PreparedProxyListeners, ProductListenerRuntime,
    ProductLocalAddressRuntime, ProxyListenerBindError, ProxyListenerFailure, UnixSocketLifetime,
};
use super::product::ProductActivator;

/// One process-lifetime owner for all static product state.
///
/// Listener and handler supervisors join this owner as they are activated; the
/// authorization and allocation state already lives here so generations cannot
/// accidentally bind to an independently constructed process-wide arena.
pub(crate) struct ProductStaticResources {
    readiness: Arc<ServiceReadiness>,
    brand: StaticResourceBrand,
    static_fingerprint: StaticFingerprint,
    shutdown_drain_timeout: Option<std::time::Duration>,
    shutdown_started: AtomicBool,
    shutdown_deadline: Mutex<Option<tokio::time::Instant>>,
    control_failure: watch::Sender<Option<Arc<ControlServerRunError>>>,
    control_shutdown_error: Mutex<Option<Arc<ControlServerShutdownError>>>,
    listener_failure: watch::Sender<Option<Arc<ProxyListenerFailure>>>,
    #[cfg(test)]
    listener_failure_notifications: AtomicUsize,
    listener_runtime: Mutex<Option<Arc<ProductListenerRuntime>>>,
    unix_socket_lifetimes: Mutex<Vec<Arc<UnixSocketLifetime>>>,
    listener_shutdown_started: AtomicBool,
    #[cfg(test)]
    listener_shutdown_pause: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
    listener_admission_closed: tokio::sync::OnceCell<()>,
    listener_shutdown: tokio::sync::OnceCell<()>,
    access_flow_security_shutdown: tokio::sync::OnceCell<()>,
    local_addresses_shutdown: tokio::sync::OnceCell<()>,
    upgrade_shutdown: tokio::sync::OnceCell<()>,
    mitm_shutdown: tokio::sync::OnceCell<()>,
    ingress_assets: Arc<ProductIngressAssets>,
    access_flow_security: Arc<AccessFlowSecurityMaterialRuntime>,
    ingress: Mutex<IngressOwnership>,
    control: Mutex<ControlOwnership>,
    wire_body_pool: Arc<WireBodyPool>,
    observation_runtime: Arc<ProductObservationRuntime>,
    logging_level: LoggingLevelControl,
    credential_io_runtime: Arc<CredentialIoRuntime>,
    tls_io_runtime: Arc<TlsIoRuntime>,
    authorization_runtime: Arc<WebhookAuthorizationRuntime>,
    upgrade_runtime: Arc<UpgradeRuntime>,
    identity_sources: Arc<IdentitySourceRegistry>,
    identity_publisher: Arc<IdentityPublisher>,
    local_addresses: OnceLock<Arc<ProductLocalAddressRuntime>>,
}

struct IngressOwnership {
    config: crate::config::compiler::StaticListenersConfig,
    state: IngressState,
}

enum IngressState {
    Unprepared,
    Prepared(Box<PreparedProxyListeners>),
    Adopted,
}

struct ControlOwnership {
    config: Option<crate::config::compiler::StaticControlConfig>,
    server: Option<Arc<ControlServer>>,
}

struct ProductControlFailureObserver {
    owner: Weak<ProductStaticResources>,
}

struct ProductLocalAddressFailureObserver {
    owner: Weak<ProductStaticResources>,
}

enum ProductIngressAssetSource {
    System,
    #[cfg(test)]
    ForwardingNetwork(Arc<http_access_runtime::ForwardingNetworkGuard>),
}

enum ConstructionControl {
    Continue,
    #[cfg(test)]
    FailAfterObservationActivation,
    #[cfg(test)]
    PauseAfterObservationActivation {
        reached: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
        coordinator_complete: Arc<tokio::sync::Notify>,
    },
}

struct ProductStaticResourceStages {
    ingress_assets: Option<Arc<ProductIngressAssets>>,
    authorization_runtime: Option<Arc<WebhookAuthorizationRuntime>>,
    upgrade_runtime: Option<Arc<UpgradeRuntime>>,
    credential_io_runtime: Option<Arc<CredentialIoRuntime>>,
    tls_io_runtime: Option<Arc<TlsIoRuntime>>,
    observation_runtime: Option<Arc<ProductObservationRuntime>>,
}

impl ProductStaticResourceStages {
    fn new() -> Self {
        Self {
            ingress_assets: None,
            authorization_runtime: None,
            upgrade_runtime: None,
            credential_io_runtime: None,
            tls_io_runtime: None,
            observation_runtime: None,
        }
    }

    async fn shutdown(&mut self) {
        if let Some(observation) = self.observation_runtime.take() {
            observation.shutdown().await;
        }
        if let Some(credential_io) = self.credential_io_runtime.take() {
            let _ = credential_io
                .shutdown_and_wait(Some(tokio::time::Instant::now()))
                .await;
        }
        if let Some(tls_io) = self.tls_io_runtime.take() {
            let _ = tls_io
                .shutdown_and_wait(Some(tokio::time::Instant::now()))
                .await;
        }
        if let Some(upgrade) = self.upgrade_runtime.take() {
            upgrade
                .shutdown_and_wait(Some(std::time::Instant::now()))
                .await;
        }
        if let Some(authorization) = self.authorization_runtime.take() {
            authorization.begin_shutdown(Some(tokio::time::Instant::now()));
            authorization.final_cancel_all(PendingTerminalCause::Shutdown);
            authorization.wait_until_drained().await;
        }
        if let Some(assets) = self.ingress_assets.take() {
            if let Some(mitm) = assets.mitm_manager() {
                mitm.shutdown_and_join().await;
            }
        }
    }
}

impl LocalAddressRefreshFailureObserver for ProductLocalAddressFailureObserver {
    fn failed(&self, error: Arc<ProxyListenerFailure>) {
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        tracing::error!(error = %error, "local-address refresh failed");
        owner.record_listener_failure(error);
        StaticResources::begin_shutdown(owner.as_ref());
    }
}

impl ControlServerFailureObserver for ProductControlFailureObserver {
    fn failed(&self, error: Arc<ControlServerRunError>) {
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        tracing::error!(error = %error, "control server supervisor failed");
        owner.record_control_failure(error);
        StaticResources::begin_shutdown(owner.as_ref());
    }
}

impl ProductStaticResources {
    #[cfg(test)]
    pub(crate) async fn try_new(
        static_config: &StaticProductConfig,
    ) -> Result<Arc<Self>, ProductStaticResourcesError> {
        Self::try_new_coordinated(
            static_config.clone(),
            ProductIngressAssetSource::System,
            None,
            None,
            ConstructionControl::Continue,
        )
        .await
    }

    pub(crate) async fn try_new_with_identity_sources(
        static_config: &StaticProductConfig,
        identity_sources: Arc<IdentitySourceRegistry>,
    ) -> Result<Arc<Self>, ProductStaticResourcesError> {
        Self::try_new_coordinated(
            static_config.clone(),
            ProductIngressAssetSource::System,
            None,
            Some(identity_sources),
            ConstructionControl::Continue,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn try_new_with_forwarding_network(
        static_config: &StaticProductConfig,
        forwarding_network: Arc<http_access_runtime::ForwardingNetworkGuard>,
    ) -> Result<Arc<Self>, ProductStaticResourcesError> {
        Self::try_new_coordinated(
            static_config.clone(),
            ProductIngressAssetSource::ForwardingNetwork(forwarding_network),
            None,
            None,
            ConstructionControl::Continue,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn try_new_with_forwarding_network_and_identity_sources(
        static_config: &StaticProductConfig,
        forwarding_network: Arc<http_access_runtime::ForwardingNetworkGuard>,
        identity_sources: Arc<IdentitySourceRegistry>,
    ) -> Result<Arc<Self>, ProductStaticResourcesError> {
        Self::try_new_coordinated(
            static_config.clone(),
            ProductIngressAssetSource::ForwardingNetwork(forwarding_network),
            None,
            Some(identity_sources),
            ConstructionControl::Continue,
        )
        .await
    }

    #[cfg(test)]
    async fn try_new_failing_after_worker_activation(
        static_config: &StaticProductConfig,
    ) -> Result<Arc<Self>, ProductStaticResourcesError> {
        Self::try_new_coordinated(
            static_config.clone(),
            ProductIngressAssetSource::System,
            None,
            None,
            ConstructionControl::FailAfterObservationActivation,
        )
        .await
    }

    async fn try_new_coordinated(
        static_config: StaticProductConfig,
        asset_source: ProductIngressAssetSource,
        webhook_connector: Option<Arc<crate::authorization::webhook::connector::WebhookConnector>>,
        identity_sources: Option<Arc<IdentitySourceRegistry>>,
        construction_control: ConstructionControl,
    ) -> Result<Arc<Self>, ProductStaticResourcesError> {
        let (result_send, result_receive) = tokio::sync::oneshot::channel();
        #[cfg(test)]
        let coordinator_complete = match &construction_control {
            ConstructionControl::PauseAfterObservationActivation {
                coordinator_complete,
                ..
            } => Some(Arc::clone(coordinator_complete)),
            _ => None,
        };
        tokio::spawn(async move {
            let result = Self::try_new_staged(
                static_config,
                asset_source,
                webhook_connector,
                identity_sources,
                construction_control,
            )
            .await;
            if let Err(Ok(resources)) = result_send.send(result) {
                StaticResources::shutdown(resources.as_ref()).await;
            }
            #[cfg(test)]
            if let Some(complete) = coordinator_complete {
                complete.notify_waiters();
            }
        });
        result_receive
            .await
            .map_err(|_| ProductStaticResourcesError::ConstructionCoordinator)?
    }

    async fn try_new_staged(
        static_config: StaticProductConfig,
        asset_source: ProductIngressAssetSource,
        webhook_connector: Option<Arc<crate::authorization::webhook::connector::WebhookConnector>>,
        identity_sources: Option<Arc<IdentitySourceRegistry>>,
        construction_control: ConstructionControl,
    ) -> Result<Arc<Self>, ProductStaticResourcesError> {
        let static_fingerprint = StaticFingerprint::from_config(&static_config)?;
        let identity_sources = match identity_sources {
            Some(sources) => sources,
            None => IdentitySourceRegistry::activate()?,
        };
        let identity_publisher = IdentityPublisher::activate()?;
        let webhook_connector = match webhook_connector {
            Some(connector) => connector,
            None => {
                crate::authorization::webhook::connector::WebhookConnector::system(&static_config)?
            }
        };
        let mut stages = ProductStaticResourceStages::new();
        let ingress_assets = match asset_source {
            ProductIngressAssetSource::System => ProductIngressAssets::from_static(&static_config),
            #[cfg(test)]
            ProductIngressAssetSource::ForwardingNetwork(network) => {
                ProductIngressAssets::with_forwarding_network(&static_config, network)
            }
        }?;
        stages.ingress_assets = Some(Arc::clone(&ingress_assets));
        let (control_failure, _) = watch::channel(None);
        let (listener_failure, _) = watch::channel(None);
        let authorization_runtime = match WebhookAuthorizationRuntime::try_new_with_connector(
            &static_config,
            webhook_connector,
        ) {
            Ok(runtime) => runtime,
            Err(error) => {
                stages.shutdown().await;
                return Err(error.into());
            }
        };
        stages.authorization_runtime = Some(Arc::clone(&authorization_runtime));
        let upgrade_runtime = match UpgradeRuntime::activate(UpgradeRuntimeLimits::new(
            static_config.service.max_active_upgrades,
            static_config.service.max_upgrade_buffer_bytes,
            static_config.service.upgrade_relay_buffer_bytes,
            static_config.service.max_upgrade_lifetime,
        )) {
            Ok(runtime) => runtime,
            Err(error) => {
                stages.shutdown().await;
                return Err(error.into());
            }
        };
        stages.upgrade_runtime = Some(Arc::clone(&upgrade_runtime));
        let credential_io_runtime = match CredentialIoRuntime::new() {
            Ok(runtime) => runtime,
            Err(error) => {
                stages.shutdown().await;
                return Err(error.into());
            }
        };
        stages.credential_io_runtime = Some(Arc::clone(&credential_io_runtime));
        let tls_io_runtime = match TlsIoRuntime::new() {
            Ok(runtime) => runtime,
            Err(error) => {
                stages.shutdown().await;
                return Err(error.into());
            }
        };
        stages.tls_io_runtime = Some(Arc::clone(&tls_io_runtime));
        let logging_level = process_logging_level_control();
        let observation_runtime =
            match ProductObservationRuntime::try_new(static_config.capture.max_pending_records) {
                Ok(runtime) => Arc::new(runtime),
                Err(error) => {
                    stages.shutdown().await;
                    return Err(error.into());
                }
            };
        stages.observation_runtime = Some(Arc::clone(&observation_runtime));
        match construction_control {
            ConstructionControl::Continue => {}
            #[cfg(test)]
            ConstructionControl::FailAfterObservationActivation => {
                stages.shutdown().await;
                return Err(ProductStaticResourcesError::InjectedConstructionFailure);
            }
            #[cfg(test)]
            ConstructionControl::PauseAfterObservationActivation {
                reached, release, ..
            } => {
                let _ = reached.send(());
                if release.await.is_err() {
                    stages.shutdown().await;
                    return Err(ProductStaticResourcesError::InjectedConstructionFailure);
                }
            }
        }
        let readiness = Arc::new(ServiceReadiness::new());
        let access_flow_security = match AccessFlowSecurityMaterialRuntime::activate(
            &static_config.listeners,
            readiness.clone(),
        )
        .await
        {
            Ok(runtime) => runtime,
            Err(error) => {
                stages.shutdown().await;
                return Err(error.into());
            }
        };
        let resources = Arc::new(Self {
            readiness,
            brand: StaticResourceBrand::new(),
            static_fingerprint,
            shutdown_drain_timeout: static_config.service.shutdown_drain_timeout,
            shutdown_started: AtomicBool::new(false),
            shutdown_deadline: Mutex::new(None),
            control_failure,
            control_shutdown_error: Mutex::new(None),
            listener_failure,
            #[cfg(test)]
            listener_failure_notifications: AtomicUsize::new(0),
            listener_runtime: Mutex::new(None),
            unix_socket_lifetimes: Mutex::new(Vec::new()),
            listener_shutdown_started: AtomicBool::new(false),
            #[cfg(test)]
            listener_shutdown_pause: Mutex::new(None),
            listener_admission_closed: tokio::sync::OnceCell::new(),
            listener_shutdown: tokio::sync::OnceCell::new(),
            access_flow_security_shutdown: tokio::sync::OnceCell::new(),
            local_addresses_shutdown: tokio::sync::OnceCell::new(),
            upgrade_shutdown: tokio::sync::OnceCell::new(),
            mitm_shutdown: tokio::sync::OnceCell::new(),
            ingress_assets,
            access_flow_security,
            ingress: Mutex::new(IngressOwnership {
                config: static_config.listeners.clone(),
                state: IngressState::Unprepared,
            }),
            control: Mutex::new(ControlOwnership {
                config: static_config.control.clone(),
                server: None,
            }),
            wire_body_pool: WireBodyPool::new(
                static_config.service.max_inflight_wire_body_bytes,
                static_config
                    .service
                    .max_inflight_wire_body_bytes_per_quota_key,
            ),
            observation_runtime,
            logging_level,
            credential_io_runtime,
            tls_io_runtime,
            authorization_runtime,
            upgrade_runtime,
            identity_sources,
            identity_publisher,
            local_addresses: OnceLock::new(),
        });
        let local_addresses = match ProductLocalAddressRuntime::activate(Arc::new(
            ProductLocalAddressFailureObserver {
                owner: Arc::downgrade(&resources),
            },
        ))
        .await
        {
            Ok(runtime) => runtime,
            Err(error) => {
                StaticResources::shutdown(resources.as_ref()).await;
                return Err(error.into());
            }
        };
        resources
            .local_addresses
            .set(local_addresses)
            .unwrap_or_else(|_| panic!("local-address runtime is installed exactly once"));
        stages.ingress_assets = None;
        stages.authorization_runtime = None;
        stages.upgrade_runtime = None;
        stages.credential_io_runtime = None;
        stages.tls_io_runtime = None;
        stages.observation_runtime = None;
        Ok(resources)
    }

    pub(crate) fn static_fingerprint(&self) -> &StaticFingerprint {
        &self.static_fingerprint
    }

    pub(crate) fn static_resource_brand(&self) -> &StaticResourceBrand {
        &self.brand
    }

    pub(crate) fn wire_body_pool(&self) -> Arc<WireBodyPool> {
        self.wire_body_pool.clone()
    }

    pub(crate) fn observation_runtime(&self) -> Arc<ProductObservationRuntime> {
        self.observation_runtime.clone()
    }

    pub(crate) fn logging_level(&self) -> LoggingLevelControl {
        self.logging_level.clone()
    }

    pub(crate) fn authorization_runtime(&self) -> Arc<WebhookAuthorizationRuntime> {
        self.authorization_runtime.clone()
    }

    pub(crate) fn credential_io_runtime(&self) -> Arc<CredentialIoRuntime> {
        self.credential_io_runtime.clone()
    }

    pub(crate) fn tls_io_runtime(&self) -> Arc<TlsIoRuntime> {
        self.tls_io_runtime.clone()
    }

    pub(crate) fn upgrade_runtime(&self) -> Arc<UpgradeRuntime> {
        self.upgrade_runtime.clone()
    }

    pub(crate) fn identity_sources(&self) -> Arc<IdentitySourceRegistry> {
        Arc::clone(&self.identity_sources)
    }

    pub(crate) fn identity_publisher(&self) -> Arc<IdentityPublisher> {
        Arc::clone(&self.identity_publisher)
    }

    pub(crate) fn access_flow_security_subscription(&self) -> AccessFlowSecuritySubscription {
        self.access_flow_security.subscribe()
    }

    pub(crate) async fn reload_access_flow_security(
        &self,
    ) -> Result<(), AccessFlowSecurityMaterialError> {
        self.access_flow_security.reload().await
    }

    pub(crate) fn ingress_assets(&self) -> &Arc<ProductIngressAssets> {
        &self.ingress_assets
    }

    pub(crate) fn local_address_provider(&self) -> Arc<dyn LocalAddressProvider> {
        self.local_addresses
            .get()
            .expect("local-address runtime is activated before publication")
            .provider()
    }

    pub(crate) fn activator(self: &Arc<Self>) -> Arc<ProductActivator> {
        Arc::new(ProductActivator::new(self.clone()))
    }

    pub(crate) fn prepare_ingress(self: &Arc<Self>) -> Result<(), ProductStaticResourcesError> {
        self.prepare_ingress_with(TcpListener::bind, |config, listener, failure_observer| {
            ControlServer::from_prebound(
                config,
                listener,
                self.authorization_runtime.clone(),
                self.readiness.clone(),
                failure_observer,
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn prepare_ingress_from_prebound(
        self: &Arc<Self>,
        listeners: Vec<TcpListener>,
    ) -> Result<(), ProductStaticResourcesError> {
        let mut listeners = listeners
            .into_iter()
            .map(|listener| {
                let address = listener
                    .local_addr()
                    .expect("an injected prebound listener has a local address");
                (address, listener)
            })
            .collect::<std::collections::HashMap<_, _>>();
        self.prepare_ingress_with(
            move |address| {
                listeners.remove(&address).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        format!("no injected prebound listener for {address}"),
                    )
                })
            },
            |config, listener, failure_observer| {
                ControlServer::from_prebound(
                    config,
                    listener,
                    self.authorization_runtime.clone(),
                    self.readiness.clone(),
                    failure_observer,
                )
            },
        )
    }

    fn prepare_ingress_with(
        self: &Arc<Self>,
        mut bind: impl FnMut(SocketAddr) -> std::io::Result<TcpListener>,
        start_control: impl FnOnce(
            &crate::config::compiler::StaticControlConfig,
            TcpListener,
            Arc<dyn ControlServerFailureObserver>,
        ) -> Result<Arc<ControlServer>, ControlServerError>,
    ) -> Result<(), ProductStaticResourcesError> {
        let mut ingress = self
            .ingress
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.shutdown_started.load(Ordering::Acquire) {
            return Err(ProductStaticResourcesError::ShuttingDown);
        }
        if !matches!(ingress.state, IngressState::Unprepared) {
            return Err(ProductStaticResourcesError::IngressAlreadyPrepared);
        }

        let listeners = PreparedProxyListeners::bind(&ingress.config, &mut bind)?;
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if control.server.is_some() {
            return Err(ProductStaticResourcesError::ControlAlreadyStarted);
        }
        if let Some(config) = control.config.as_ref() {
            let listener = bind(config.bind).map_err(|source| ControlServerError::Bind {
                address: config.bind,
                source,
            })?;
            let failure_observer = Arc::new(ProductControlFailureObserver {
                owner: Arc::downgrade(self),
            });
            control.server = Some(start_control(config, listener, failure_observer)?);
        }

        ingress.state = IngressState::Prepared(Box::new(listeners));
        Ok(())
    }

    /// Transfers the complete listener bundle into synchronous supervisor startup.
    ///
    /// The caller must return the successfully started supervisors to this owner
    /// before yielding so shutdown continues to own and join every ingress task.
    pub(super) fn take_prepared_listener_bundle(
        &self,
    ) -> Result<PreparedProxyListeners, ProductStaticResourcesError> {
        let mut ingress = self
            .ingress
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let IngressState::Prepared(_) = &ingress.state else {
            return Err(match ingress.state {
                IngressState::Unprepared => ProductStaticResourcesError::IngressNotPrepared,
                IngressState::Adopted => ProductStaticResourcesError::IngressAlreadyAdopted,
                IngressState::Prepared(_) => unreachable!(),
            });
        };
        let IngressState::Prepared(listeners) =
            std::mem::replace(&mut ingress.state, IngressState::Adopted)
        else {
            unreachable!();
        };
        Ok(*listeners)
    }

    #[cfg(test)]
    pub(crate) fn start_control(
        self: &Arc<Self>,
    ) -> Result<Option<std::net::SocketAddr>, ProductStaticResourcesError> {
        self.start_control_with(|config, failure_observer| {
            ControlServer::bind(
                config,
                self.authorization_runtime.clone(),
                self.readiness.clone(),
                failure_observer,
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn start_control_with_listener(
        self: &Arc<Self>,
        listener: std::net::TcpListener,
    ) -> Result<Option<std::net::SocketAddr>, ProductStaticResourcesError> {
        self.start_control_with(|config, failure_observer| {
            ControlServer::from_prebound(
                config,
                listener,
                self.authorization_runtime.clone(),
                self.readiness.clone(),
                failure_observer,
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn start_control_with_accept_errors(
        self: &Arc<Self>,
        listener: std::net::TcpListener,
        errors: impl IntoIterator<Item = std::io::Error>,
    ) -> Result<Option<std::net::SocketAddr>, ProductStaticResourcesError> {
        self.start_control_with(|config, failure_observer| {
            ControlServer::from_prebound_with_accept_errors(
                config,
                listener,
                self.authorization_runtime.clone(),
                self.readiness.clone(),
                errors,
                failure_observer,
            )
        })
    }

    #[cfg(test)]
    fn start_control_with(
        self: &Arc<Self>,
        start: impl FnOnce(
            &crate::config::compiler::StaticControlConfig,
            Arc<dyn ControlServerFailureObserver>,
        ) -> Result<Arc<ControlServer>, ControlServerError>,
    ) -> Result<Option<std::net::SocketAddr>, ProductStaticResourcesError> {
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.shutdown_started.load(Ordering::Acquire) {
            return Err(ProductStaticResourcesError::ShuttingDown);
        }
        if control.server.is_some() {
            return Err(ProductStaticResourcesError::ControlAlreadyStarted);
        }
        let Some(config) = control.config.as_ref() else {
            return Ok(None);
        };
        let failure_observer = Arc::new(ProductControlFailureObserver {
            owner: Arc::downgrade(self),
        });
        let server = start(config, failure_observer)?;
        let local_addr = server.local_addr();
        control.server = Some(server);
        Ok(Some(local_addr))
    }

    pub(crate) fn control_server(&self) -> Option<Arc<ControlServer>> {
        self.control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .server
            .clone()
    }

    pub(crate) async fn wait_for_control_failure(&self) -> Option<Arc<ControlServerRunError>> {
        let started = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .server
            .is_some();
        if !started {
            return None;
        }
        let mut failure = self.control_failure.subscribe();
        loop {
            if let Some(error) = failure.borrow().clone() {
                return Some(error);
            }
            if failure.changed().await.is_err() {
                return failure.borrow().clone();
            }
        }
    }

    pub(crate) fn control_shutdown_error(&self) -> Option<Arc<ControlServerShutdownError>> {
        self.control_shutdown_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(super) fn adopt_listener_runtime(
        &self,
        runtime: ProductListenerRuntime,
        unix_socket_lifetimes: Vec<Arc<UnixSocketLifetime>>,
    ) -> Result<(), ProductStaticResourcesError> {
        let mut owned = self
            .listener_runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if owned.is_some() {
            return Err(ProductStaticResourcesError::ListenerRuntimeAlreadyAdopted);
        }
        *owned = Some(Arc::new(runtime));
        *self
            .unix_socket_lifetimes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = unix_socket_lifetimes;
        if self.shutdown_started.load(Ordering::Acquire) {
            owned
                .as_ref()
                .expect("listener runtime was just installed")
                .begin_shutdown();
            return Err(ProductStaticResourcesError::ShuttingDown);
        }
        Ok(())
    }

    pub(super) fn record_listener_failure(&self, error: Arc<ProxyListenerFailure>) {
        #[cfg(test)]
        self.listener_failure_notifications
            .fetch_add(1, Ordering::AcqRel);
        let _ = self.listener_failure.send_if_modified(|recorded| {
            if recorded.is_some() {
                return false;
            }
            *recorded = Some(error);
            true
        });
    }

    #[cfg(test)]
    pub(crate) fn listener_failure_notifications_for_test(&self) -> usize {
        self.listener_failure_notifications.load(Ordering::Acquire)
    }

    pub(crate) async fn wait_for_listener_failure(&self) -> Option<Arc<ProxyListenerFailure>> {
        let mut failure = self.listener_failure.subscribe();
        loop {
            if let Some(error) = failure.borrow().clone() {
                return Some(error);
            }
            if failure.changed().await.is_err() {
                return failure.borrow().clone();
            }
        }
    }

    async fn shutdown_listener_runtime(&self) {
        let runtime = self
            .listener_runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(runtime) = runtime {
            self.listener_shutdown_started
                .store(true, Ordering::Release);
            #[cfg(test)]
            let shutdown_pause = {
                self.listener_shutdown_pause
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
            };
            #[cfg(test)]
            if let Some((reached, release)) = shutdown_pause {
                let _ = reached.send(());
                let _ = release.await;
            }
            let deadline = *self
                .shutdown_deadline
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            runtime
                .shutdown_and_wait(deadline.map(tokio::time::Instant::into_std))
                .await;
        }
        self.unix_socket_lifetimes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    #[cfg(test)]
    pub(crate) fn shutdown_started_for_test(&self) -> bool {
        self.shutdown_started.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn listener_shutdown_started_for_test(&self) -> bool {
        self.listener_shutdown_started.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn pause_listener_shutdown_for_test(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (reached_send, reached_receive) = tokio::sync::oneshot::channel();
        let (release_send, release_receive) = tokio::sync::oneshot::channel();
        *self
            .listener_shutdown_pause
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some((reached_send, release_receive));
        (reached_receive, release_send)
    }

    #[cfg(test)]
    pub(crate) fn owns_listener_runtime_for_test(&self) -> bool {
        self.listener_runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    }

    #[cfg(test)]
    pub(super) fn listener_runtime_for_test(&self) -> Arc<ProductListenerRuntime> {
        self.listener_runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .cloned()
            .expect("listener runtime is not active")
    }

    fn record_control_shutdown_error(&self, error: Arc<ControlServerShutdownError>) {
        let mut recorded = self
            .control_shutdown_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if recorded.is_none() {
            *recorded = Some(error);
        }
    }

    fn record_control_failure(&self, error: Arc<ControlServerRunError>) {
        let _ = self.control_failure.send_if_modified(|recorded| {
            if recorded.is_some() {
                return false;
            }
            *recorded = Some(error);
            true
        });
    }
}

impl StaticResources for ProductStaticResources {
    fn brand(&self) -> &StaticResourceBrand {
        self.static_resource_brand()
    }

    fn readiness(&self) -> &Arc<ServiceReadiness> {
        &self.readiness
    }

    fn begin_shutdown(&self) {
        let mut ingress = self
            .ingress
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.readiness.begin_shutdown();
        self.identity_publisher.begin_shutdown();
        if self.shutdown_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let listener_runtime = self
            .listener_runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(runtime) = listener_runtime.as_ref() {
            runtime.begin_shutdown();
        }
        if matches!(ingress.state, IngressState::Prepared(_)) {
            ingress.state = IngressState::Adopted;
        }
        let deadline = self
            .shutdown_drain_timeout
            .map(|timeout| tokio::time::Instant::now() + timeout);
        *self
            .shutdown_deadline
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = deadline;
        self.observation_runtime.begin_shutdown();
        self.access_flow_security.begin_shutdown();
        self.credential_io_runtime.begin_shutdown();
        self.tls_io_runtime.begin_shutdown();
        self.authorization_runtime.begin_shutdown(deadline);
        if listener_runtime.is_none() {
            self.upgrade_runtime
                .begin_shutdown(deadline.map(tokio::time::Instant::into_std));
        }
        if let Some(local_addresses) = self.local_addresses.get() {
            local_addresses.begin_shutdown();
        }
        if let Some(mitm) = self.ingress_assets.mitm_manager() {
            mitm.begin_shutdown();
        }
    }

    fn shutdown(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.begin_shutdown();
            let control = self.control_server();
            let deadline = *self
                .shutdown_deadline
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let listener_runtime = self
                .listener_runtime
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            if let Some(runtime) = listener_runtime {
                self.listener_admission_closed
                    .get_or_init(|| runtime.stop_admission_and_wait_closed())
                    .await;
                self.upgrade_runtime
                    .begin_shutdown(deadline.map(tokio::time::Instant::into_std));
            }
            let deadline_won = if let Some(deadline) = deadline {
                tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(deadline) => true,
                    _ = self.authorization_runtime.wait_until_drained() => false,
                }
            } else {
                self.authorization_runtime.wait_until_drained().await;
                false
            };
            if deadline_won {
                self.authorization_runtime
                    .final_cancel_all(PendingTerminalCause::Shutdown);
            }
            if let Some(control) = control {
                let result = if deadline_won {
                    control.abort_and_join().await
                } else if let Some(deadline) = deadline {
                    let graceful = tokio::select! {
                        biased;
                        _ = tokio::time::sleep_until(deadline) => None,
                        result = control.close_and_join() => Some(result),
                    };
                    match graceful {
                        Some(result) => result,
                        None => {
                            self.authorization_runtime
                                .final_cancel_all(PendingTerminalCause::Shutdown);
                            control.abort_and_join().await
                        }
                    }
                } else {
                    control.close_and_join().await
                };
                if let Err(error) = result {
                    tracing::error!(error = %error, "control server shutdown failed");
                    self.record_control_shutdown_error(error);
                }
            }
            self.authorization_runtime.wait_until_drained().await;
            if let CredentialIoShutdownOutcome::DeadlineExceeded {
                detached_operations,
            } = self.credential_io_runtime.shutdown_and_wait(deadline).await
            {
                tracing::warn!(
                    detached_operations,
                    "credential I/O shutdown deadline reached; blocking operating-system workers remain detached"
                );
            }
            if let TlsIoShutdownOutcome::DeadlineExceeded {
                detached_operations,
            } = self.tls_io_runtime.shutdown_and_wait(deadline).await
            {
                tracing::warn!(
                    detached_operations,
                    "TLS I/O shutdown deadline reached; blocking operating-system workers remain detached"
                );
            }
            self.upgrade_shutdown
                .get_or_init(|| {
                    self.upgrade_runtime
                        .shutdown_and_wait(deadline.map(tokio::time::Instant::into_std))
                })
                .await;
            self.listener_shutdown
                .get_or_init(|| self.shutdown_listener_runtime())
                .await;
            self.access_flow_security_shutdown
                .get_or_init(|| self.access_flow_security.shutdown())
                .await;
            if let Some(local_addresses) = self.local_addresses.get() {
                self.local_addresses_shutdown
                    .get_or_init(|| local_addresses.shutdown_and_join())
                    .await;
            }
            self.mitm_shutdown
                .get_or_init(|| async {
                    if let Some(mitm) = self.ingress_assets.mitm_manager() {
                        mitm.shutdown_and_join().await;
                    }
                })
                .await;
            if self.observation_runtime.shutdown_until(deadline).await
                == ProductObservationShutdownOutcome::DeadlineExceeded
            {
                tracing::warn!(
                    "capture worker did not exit before the shutdown deadline; queued records were marked for discard and blocking record processing may remain detached"
                );
            }
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductStaticResourcesError {
    #[error("static resource construction coordinator did not complete")]
    ConstructionCoordinator,
    #[cfg(test)]
    #[error("injected failure after static worker activation")]
    InjectedConstructionFailure,
    #[error(transparent)]
    IngressAssets(#[from] ProductIngressAssetsError),
    #[error("static fingerprint derivation failed")]
    StaticFingerprint(#[from] StaticFingerprintError),
    #[error("static authorization runtime construction failed")]
    Authorization(#[from] WebhookAuthorizationRuntimeError),
    #[error("static webhook connector construction failed")]
    WebhookConnector(#[from] crate::authorization::webhook::connector::WebhookConnectorError),
    #[error("static credential I/O runtime construction failed")]
    CredentialIo(#[from] CredentialIoRuntimeError),
    #[error("static TLS I/O runtime construction failed")]
    TlsIo(#[from] TlsIoRuntimeError),
    #[error("static upgrade runtime construction failed")]
    Upgrade(#[from] UpgradeRuntimeError),
    #[error("static local-address runtime construction failed")]
    LocalAddress(#[from] http_access_runtime::RuntimeError),
    #[error("static observation runtime construction failed")]
    Observation(#[from] ProductObservationRuntimeStartError),
    #[error("static identity runtime construction failed")]
    Identity(#[from] IdentityActivationError),
    #[error("static Access Flow TLS security material construction failed")]
    AccessFlowSecurity(#[from] AccessFlowSecurityMaterialError),
    #[error("control server construction failed")]
    Control(#[from] ControlServerError),
    #[error(transparent)]
    ProxyListenerBind(#[from] ProxyListenerBindError),
    #[error("static ingress has already been prepared")]
    IngressAlreadyPrepared,
    #[error("static ingress has not been prepared")]
    IngressNotPrepared,
    #[error("prepared proxy listeners have already been adopted or released")]
    IngressAlreadyAdopted,
    #[error("control server has already started")]
    ControlAlreadyStarted,
    #[error("the listener runtime has already been adopted")]
    ListenerRuntimeAlreadyAdopted,
    #[error("static resources are shutting down")]
    ShuttingDown,
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::mpsc as std_mpsc;
    use std::sync::Condvar;
    use std::time::Duration;

    use super::*;
    use crate::config::compiler::{
        CompiledTlsIdentity, StaticCleartextListener, StaticExplicitHttpsListener,
        StaticMitmConfig, StaticTransparentHttpsListener,
    };
    use crate::config::{compile_config_text, ConfigTextInput};
    fn static_config(addresses: [SocketAddr; 5], identity_directory: &Path) -> StaticProductConfig {
        let [explicit_http, transparent_http, explicit_https, transparent_https, control] =
            addresses;
        let text = format!(
            r#"schema_version = 4

[service]
request_timeout = "30s"
shutdown_drain_timeout = "1s"
max_retiring_generations = 2
max_active_upgrades = 256
upgrade_relay_buffer_bytes = 65536
max_upgrade_buffer_bytes = 2147483648
max_upgrade_lifetime = "8h"
max_inflight_wire_body_bytes = 8589934592
max_inflight_wire_body_bytes_per_quota_key = 1073741824
min_wire_body_concurrency = 64
max_content_decoding_expansion_ratio = 128

[control]
bind = "{control}"
base_path = "/_acl-proxy"
request_header_timeout = "1s"
request_body_timeout = "1s"
max_connections = 2
max_request_body_bytes = 65536

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "{explicit_http}"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[observation.logging]
level = "info"
console = true

[safety.loop_detection]
inject = true
header = "x-acl-proxy-request-id"
"#
        );
        let mut config = compile_config_text(ConfigTextInput {
            text: &text,
            source_path: Path::new("/tmp/static-ingress/acl-proxy.toml"),
            config_root: Path::new("/tmp/static-ingress"),
        })
        .unwrap()
        .static_config;
        let explicit = config.listeners.explicit_http.as_ref().unwrap();
        let versions = explicit.http_versions.clone();
        let connect = explicit.connect.clone().unwrap();
        let request_header_timeout = explicit.request_header_timeout;
        let max_connections = explicit.max_connections;
        let max_concurrent_streams = explicit.max_concurrent_streams;
        config.listeners.transparent_http = Some(StaticCleartextListener {
            endpoint: crate::config::compiler::StaticListenerEndpoint::Tcp {
                address: transparent_http,
            },
            http_versions: versions.clone(),
            request_header_timeout,
            max_connections,
            max_concurrent_streams,
            identity_mode: crate::config::compiler::CompiledListenerIdentityMode::Disabled,
            connect: None,
        });
        std::fs::create_dir_all(identity_directory).unwrap();
        let identity = crate::test_certificates::TestTlsIdentity::new("localhost");
        let certificate_chain = identity_directory.join("server.pem");
        let private_key = identity_directory.join("server-key.pem");
        crate::filesystem::write_public_file(&certificate_chain, identity.certificate_chain_pem())
            .unwrap();
        crate::filesystem::write_private_file(&private_key, identity.private_key_pem()).unwrap();
        config.listeners.explicit_https = Some(StaticExplicitHttpsListener {
            endpoint: crate::config::compiler::StaticListenerEndpoint::Tcp {
                address: explicit_https,
            },
            http_versions: versions.clone(),
            handshake_timeout: Duration::from_secs(1),
            request_header_timeout: Duration::from_secs(1),
            max_connections: 2,
            max_concurrent_streams: 8,
            identity_mode: crate::config::compiler::CompiledListenerIdentityMode::Disabled,
            connect,
            tls: CompiledTlsIdentity {
                certificate_chain,
                private_key,
            },
        });
        config.listeners.transparent_https = Some(StaticTransparentHttpsListener {
            endpoint: crate::config::compiler::StaticListenerEndpoint::Tcp {
                address: transparent_https,
            },
            http_versions: versions,
            handshake_timeout: Duration::from_secs(1),
            request_header_timeout: Duration::from_secs(1),
            max_connections: 2,
            max_concurrent_streams: 8,
            identity_mode: crate::config::compiler::CompiledListenerIdentityMode::Disabled,
        });
        config.mitm = Some(StaticMitmConfig::Generated {
            directory: identity_directory.join("mitm"),
            max_cached_certificates: 4,
            persist_leaf_certificates: false,
        });
        config
    }

    #[tokio::test]
    async fn preparation_reserves_every_configured_listener_and_is_one_shot() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<5>(&_test);
        let addresses = reservations.addresses();
        let directory = tempfile::tempdir().unwrap();
        let resources =
            ProductStaticResources::try_new(&static_config(addresses, directory.path()))
                .await
                .unwrap();

        resources
            .prepare_ingress_from_prebound(reservations.into_listeners())
            .unwrap();
        for address in addresses {
            assert!(
                TcpListener::bind(address).is_err(),
                "prepared listener {address} was not reserved"
            );
        }
        assert!(matches!(
            resources.prepare_ingress(),
            Err(ProductStaticResourcesError::IngressAlreadyPrepared)
        ));

        StaticResources::shutdown(resources.as_ref()).await;
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn later_proxy_bind_failure_releases_earlier_sockets() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<5>(&_test);
        let addresses = reservations.addresses();
        let mut listeners = reservations.into_listeners();
        let blocker = listeners.remove(2);
        let directory = tempfile::tempdir().unwrap();
        let resources =
            ProductStaticResources::try_new(&static_config(addresses, directory.path()))
                .await
                .unwrap();

        assert!(matches!(
            resources.prepare_ingress_from_prebound(listeners),
            Err(ProductStaticResourcesError::ProxyListenerBind(error))
                if error.name == "explicit_https" && error.address == Some(addresses[2])
        ));
        super::super::assert_listener_addresses_released(
            &_test,
            [addresses[0], addresses[1], addresses[3], addresses[4]],
        );

        drop(blocker);
        StaticResources::shutdown(resources.as_ref()).await;
    }

    #[tokio::test]
    async fn control_adoption_failure_releases_all_prebound_sockets() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<5>(&_test);
        let addresses = reservations.addresses();
        let directory = tempfile::tempdir().unwrap();
        let resources =
            ProductStaticResources::try_new(&static_config(addresses, directory.path()))
                .await
                .unwrap();

        assert!(matches!(
            resources.prepare_ingress_with(
                reservations.into_binder(),
                |_config, _listener, _observer| Err(ControlServerError::RuntimeUnavailable)
            ),
            Err(ProductStaticResourcesError::Control(
                ControlServerError::RuntimeUnavailable
            ))
        ));
        super::super::assert_listener_addresses_released(&_test, addresses);

        StaticResources::shutdown(resources.as_ref()).await;
    }

    #[tokio::test]
    async fn shutdown_releases_prepared_but_unstarted_proxy_sockets() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<5>(&_test);
        let addresses = reservations.addresses();
        let directory = tempfile::tempdir().unwrap();
        let resources =
            ProductStaticResources::try_new(&static_config(addresses, directory.path()))
                .await
                .unwrap();
        resources
            .prepare_ingress_from_prebound(reservations.into_listeners())
            .unwrap();

        StaticResources::shutdown(resources.as_ref()).await;

        super::super::assert_listener_addresses_released(&_test, addresses);
        assert!(matches!(
            resources.take_prepared_listener_bundle(),
            Err(ProductStaticResourcesError::IngressAlreadyAdopted)
        ));
    }

    #[tokio::test]
    async fn construction_does_not_bind_configured_sockets() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<5>(&_test);
        let addresses = reservations.addresses();
        let directory = tempfile::tempdir().unwrap();
        let resources =
            ProductStaticResources::try_new(&static_config(addresses, directory.path()))
                .await
                .unwrap();

        for address in addresses {
            assert!(
                TcpListener::bind(address).is_err(),
                "fixture reservation for {address} was lost during construction"
            );
        }
        drop(resources);
        drop(reservations);
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn later_construction_failure_joins_every_activated_worker() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<5>(&_test);
        let addresses = reservations.addresses();
        let directory = tempfile::tempdir().unwrap();
        let config = static_config(addresses, directory.path());

        assert!(matches!(
            ProductStaticResources::try_new_failing_after_worker_activation(&config).await,
            Err(ProductStaticResourcesError::InjectedConstructionFailure)
        ));

        let resources = ProductStaticResources::try_new(&config)
            .await
            .expect("a later failure left a process worker or MITM storage owner active");
        StaticResources::shutdown(resources.as_ref()).await;
        drop(reservations);
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn cancelled_constructor_recovers_and_joins_every_activated_worker() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<5>(&_test);
        let addresses = reservations.addresses();
        let directory = tempfile::tempdir().unwrap();
        let config = static_config(addresses, directory.path());
        let (reached_send, reached_receive) = tokio::sync::oneshot::channel();
        let (release_send, release_receive) = tokio::sync::oneshot::channel();
        let coordinator_complete = Arc::new(tokio::sync::Notify::new());
        let completion_observer = Arc::clone(&coordinator_complete);
        let completion = completion_observer.notified();
        let construction_config = config.clone();
        let constructor = tokio::spawn(async move {
            ProductStaticResources::try_new_coordinated(
                construction_config,
                ProductIngressAssetSource::System,
                None,
                None,
                ConstructionControl::PauseAfterObservationActivation {
                    reached: reached_send,
                    release: release_receive,
                    coordinator_complete,
                },
            )
            .await
        });
        reached_receive
            .await
            .expect("construction did not activate every worker");

        constructor.abort();
        assert!(matches!(
            constructor.await,
            Err(error) if error.is_cancelled()
        ));
        release_send
            .send(())
            .expect("construction coordinator stopped before cleanup");
        tokio::time::timeout(Duration::from_secs(2), completion)
            .await
            .expect("construction coordinator did not recover and join resources");

        let resources = ProductStaticResources::try_new(&config)
            .await
            .expect("canceled construction left a process worker active");
        StaticResources::shutdown(resources.as_ref()).await;
        drop(reservations);
        super::super::assert_listener_addresses_released(&_test, addresses);
    }

    #[tokio::test]
    async fn static_owner_activates_and_joins_shared_upgrade_runtime() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<5>(&_test);
        let addresses = reservations.addresses();
        let directory = tempfile::tempdir().unwrap();
        let resources =
            ProductStaticResources::try_new(&static_config(addresses, directory.path()))
                .await
                .unwrap();
        let runtime = resources.upgrade_runtime();
        let limits = runtime.limits();
        assert_eq!(limits.max_active_upgrades(), 256);
        assert_eq!(limits.max_upgrade_buffer_bytes(), 2_147_483_648);
        assert_eq!(limits.relay_buffer_bytes(), 65_536);
        assert_eq!(
            limits.max_upgrade_lifetime(),
            Duration::from_secs(8 * 60 * 60)
        );

        StaticResources::begin_shutdown(resources.as_ref());
        tokio::time::timeout(
            Duration::from_secs(2),
            StaticResources::shutdown(resources.as_ref()),
        )
        .await
        .expect("static shutdown did not join the shared upgrade runtime");
    }

    #[tokio::test]
    async fn static_shutdown_closes_owned_tls_io_admission() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<5>(&_test);
        let addresses = reservations.addresses();
        let directory = tempfile::tempdir().unwrap();
        let resources =
            ProductStaticResources::try_new(&static_config(addresses, directory.path()))
                .await
                .unwrap();
        let tls_io = resources.tls_io_runtime();

        StaticResources::begin_shutdown(resources.as_ref());
        let sensitive_path = directory.path().join("closed-sensitive-ca.pem");
        let generation = access_tls_trust::TlsTrustGeneration::new(7).unwrap();
        let plan = access_tls_trust::TlsClientTrustPlan::new(
            access_tls_trust::TlsClientTrustMode::Insecure,
            None,
        )
        .unwrap();
        let error = tls_io
            .prepare_candidate(
                generation,
                vec![plan],
                Vec::new(),
                &crate::runtime::ActivationCancellation::new_for_test(),
            )
            .await
            .expect_err("static shutdown must close TLS I/O admission");
        assert_eq!(error, crate::tls::TlsActivationError::LoaderUnavailable);
        assert!(!error.to_string().contains(sensitive_path.to_str().unwrap()));

        tokio::time::timeout(
            Duration::from_secs(2),
            StaticResources::shutdown(resources.as_ref()),
        )
        .await
        .expect("static shutdown did not join the TLS I/O supervisor");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn static_shutdown_deadline_detaches_blocked_tls_io() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<5>(&_test);
        let addresses = reservations.addresses();
        let directory = tempfile::tempdir().unwrap();
        let mut config = static_config(addresses, directory.path());
        config.service.shutdown_drain_timeout = Some(Duration::from_millis(20));
        let resources = ProductStaticResources::try_new(&config).await.unwrap();
        let tls_io = resources.tls_io_runtime();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let gate_for_job = Arc::clone(&gate);
        let (started_tx, started_rx) = std_mpsc::channel();
        let (finished_tx, finished_rx) = std_mpsc::channel();
        let operation_runtime = Arc::clone(&tls_io);
        let operation = tokio::spawn(async move {
            operation_runtime
                .run_for_test(move |_| {
                    started_tx.send(()).unwrap();
                    let (open, changed) = &*gate_for_job;
                    let mut open = open.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    while !*open {
                        open = changed
                            .wait(open)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                    finished_tx.send(()).unwrap();
                    Ok(Vec::new())
                })
                .await
        });
        tokio::task::spawn_blocking(move || started_rx.recv().unwrap())
            .await
            .unwrap();

        tokio::time::timeout(
            Duration::from_secs(1),
            StaticResources::shutdown(resources.as_ref()),
        )
        .await
        .expect("static shutdown waited for blocked TLS I/O");
        assert_eq!(
            operation.await.unwrap(),
            Err(crate::tls::TlsActivationError::ActivationCancelled)
        );
        assert!(matches!(
            finished_rx.try_recv(),
            Err(std_mpsc::TryRecvError::Empty)
        ));

        let (open, changed) = &*gate;
        *open.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        changed.notify_all();
        tokio::task::spawn_blocking(move || finished_rx.recv().unwrap())
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), tls_io.shutdown_and_wait(None))
                .await
                .expect("detached TLS worker did not release after process shutdown"),
            TlsIoShutdownOutcome::Drained
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn static_shutdown_deadline_detaches_blocked_credential_io() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<5>(&_test);
        let addresses = reservations.addresses();
        let directory = tempfile::tempdir().unwrap();
        let mut config = static_config(addresses, directory.path());
        config.service.shutdown_drain_timeout = Some(Duration::from_millis(20));
        let resources = ProductStaticResources::try_new(&config).await.unwrap();
        let credential_runtime = resources.credential_io_runtime();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let gate_for_job = Arc::clone(&gate);
        let (started_tx, started_rx) = std_mpsc::channel();
        let (finished_tx, finished_rx) = std_mpsc::channel();
        let operation = credential_runtime
            .submit(Box::new(move |_| {
                started_tx.send(()).unwrap();
                let (open, changed) = &*gate_for_job;
                let mut open = open.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                while !*open {
                    open = changed
                        .wait(open)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
                finished_tx.send(()).unwrap();
                Err(credential_core::CredentialError::UnknownReference)
            }))
            .unwrap();
        tokio::task::spawn_blocking(move || started_rx.recv().unwrap())
            .await
            .unwrap();

        tokio::time::timeout(
            Duration::from_secs(1),
            StaticResources::shutdown(resources.as_ref()),
        )
        .await
        .expect("static shutdown waited for blocked credential I/O");
        assert!(matches!(
            operation.await,
            Err(credential_core::CredentialError::Cancelled)
        ));
        assert!(matches!(
            finished_rx.try_recv(),
            Err(std_mpsc::TryRecvError::Empty)
        ));

        let (open, changed) = &*gate;
        *open.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        changed.notify_all();
        tokio::task::spawn_blocking(move || finished_rx.recv().unwrap())
            .await
            .unwrap();
        assert_eq!(
            credential_runtime.shutdown_and_wait(None).await,
            CredentialIoShutdownOutcome::Drained
        );
    }
}
