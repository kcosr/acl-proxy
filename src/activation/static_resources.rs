use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::watch;

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
use crate::logging::{process_logging_level_control, LoggingLevelControl};
use crate::observation::{ProductObservationRuntime, ProductObservationRuntimeStartError};
use crate::runtime::{BoxFuture, ServiceReadiness, StaticResourceBrand, StaticResources};
use crate::safety::WireBodyPool;
use crate::upgrade::{UpgradeRuntime, UpgradeRuntimeError, UpgradeRuntimeLimits};

use super::assets::{ProductIngressAssets, ProductIngressAssetsError};
use super::listeners::{
    PreparedProxyListeners, ProxyListenerBindError, ProxySupervisor, ProxySupervisorFailure,
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
    proxy_failure: watch::Sender<Option<Arc<ProxySupervisorFailure>>>,
    proxy_shutdown_error: Mutex<Option<Arc<ProxySupervisorFailure>>>,
    proxy_supervisors: Mutex<Vec<Arc<dyn ProxySupervisor>>>,
    proxy_shutdown: tokio::sync::OnceCell<()>,
    upgrade_shutdown: tokio::sync::OnceCell<()>,
    mitm_shutdown: tokio::sync::OnceCell<()>,
    ingress_assets: Arc<ProductIngressAssets>,
    ingress: Mutex<IngressOwnership>,
    control: Mutex<ControlOwnership>,
    wire_body_pool: Arc<WireBodyPool>,
    observation_runtime: Arc<ProductObservationRuntime>,
    logging_level: LoggingLevelControl,
    credential_io_runtime: Arc<CredentialIoRuntime>,
    authorization_runtime: Arc<WebhookAuthorizationRuntime>,
    upgrade_runtime: Arc<UpgradeRuntime>,
}

struct IngressOwnership {
    config: crate::config::compiler::StaticListenersConfig,
    state: IngressState,
}

enum IngressState {
    Unprepared,
    Prepared(PreparedProxyListeners),
    Adopted,
}

struct ControlOwnership {
    config: Option<crate::config::compiler::StaticControlConfig>,
    server: Option<Arc<ControlServer>>,
}

struct ProductControlFailureObserver {
    owner: Weak<ProductStaticResources>,
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
    pub(crate) fn try_new(
        static_config: &StaticProductConfig,
    ) -> Result<Arc<Self>, ProductStaticResourcesError> {
        let ingress_assets = ProductIngressAssets::from_static(static_config)?;
        Self::try_new_with_ingress_assets(static_config, ingress_assets)
    }

    #[cfg(test)]
    pub(crate) fn try_new_with_destination_guard(
        static_config: &StaticProductConfig,
        destination_guard: Arc<crate::destination::DestinationGuard>,
    ) -> Result<Arc<Self>, ProductStaticResourcesError> {
        let ingress_assets =
            ProductIngressAssets::with_destination_guard(static_config, destination_guard)?;
        Self::try_new_with_ingress_assets(static_config, ingress_assets)
    }

    fn try_new_with_ingress_assets(
        static_config: &StaticProductConfig,
        ingress_assets: Arc<ProductIngressAssets>,
    ) -> Result<Arc<Self>, ProductStaticResourcesError> {
        let (control_failure, _) = watch::channel(None);
        let (proxy_failure, _) = watch::channel(None);
        let authorization_runtime = WebhookAuthorizationRuntime::try_new(
            static_config,
            ingress_assets.destination_guard().clone(),
        )?;
        let upgrade_runtime = UpgradeRuntime::try_new(UpgradeRuntimeLimits::new(
            static_config.service.max_active_upgrades,
            static_config.service.max_upgrade_buffer_bytes,
            static_config.service.upgrade_relay_buffer_bytes,
            static_config.service.max_upgrade_lifetime,
        ))?;
        let credential_io_runtime = CredentialIoRuntime::new()?;
        let static_fingerprint = StaticFingerprint::from_config(static_config)?;
        let logging_level = process_logging_level_control();
        // Start the process-owned worker last so construction cannot return an
        // error after a worker thread has been created.
        let observation_runtime = Arc::new(ProductObservationRuntime::try_new(
            static_config.capture.max_pending_records,
        )?);
        Ok(Arc::new(Self {
            readiness: Arc::new(ServiceReadiness::new()),
            brand: StaticResourceBrand::new(),
            static_fingerprint,
            shutdown_drain_timeout: static_config.service.shutdown_drain_timeout,
            shutdown_started: AtomicBool::new(false),
            shutdown_deadline: Mutex::new(None),
            control_failure,
            control_shutdown_error: Mutex::new(None),
            proxy_failure,
            proxy_shutdown_error: Mutex::new(None),
            proxy_supervisors: Mutex::new(Vec::new()),
            proxy_shutdown: tokio::sync::OnceCell::new(),
            upgrade_shutdown: tokio::sync::OnceCell::new(),
            mitm_shutdown: tokio::sync::OnceCell::new(),
            ingress_assets,
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
            authorization_runtime,
            upgrade_runtime,
        }))
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

    pub(crate) fn upgrade_runtime(&self) -> Arc<UpgradeRuntime> {
        self.upgrade_runtime.clone()
    }

    pub(crate) fn ingress_assets(&self) -> &Arc<ProductIngressAssets> {
        &self.ingress_assets
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

        ingress.state = IngressState::Prepared(listeners);
        Ok(())
    }

    /// Transfers the complete listener bundle into synchronous supervisor startup.
    ///
    /// The caller must return the successfully started supervisors to this owner
    /// before yielding so shutdown continues to own and join every ingress task.
    pub(super) fn take_prepared_proxy_listeners_for_supervisor_start(
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
        Ok(listeners)
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

    pub(super) fn adopt_proxy_supervisors(
        &self,
        supervisors: &mut Vec<Arc<dyn ProxySupervisor>>,
    ) -> Result<(), ProductStaticResourcesError> {
        let mut owned = self
            .proxy_supervisors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.shutdown_started.load(Ordering::Acquire) {
            return Err(ProductStaticResourcesError::ShuttingDown);
        }
        if !owned.is_empty() {
            return Err(ProductStaticResourcesError::ProxySupervisorsAlreadyAdopted);
        }
        owned.append(supervisors);
        Ok(())
    }

    pub(super) fn record_proxy_failure(&self, error: Arc<ProxySupervisorFailure>) {
        let _ = self.proxy_failure.send_if_modified(|recorded| {
            if recorded.is_some() {
                return false;
            }
            *recorded = Some(error);
            true
        });
    }

    pub(crate) async fn wait_for_proxy_failure(&self) -> Option<Arc<ProxySupervisorFailure>> {
        let mut failure = self.proxy_failure.subscribe();
        loop {
            if let Some(error) = failure.borrow().clone() {
                return Some(error);
            }
            if failure.changed().await.is_err() {
                return failure.borrow().clone();
            }
        }
    }

    pub(crate) fn proxy_shutdown_error(&self) -> Option<Arc<ProxySupervisorFailure>> {
        self.proxy_shutdown_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    async fn shutdown_proxy_supervisors(&self) {
        let supervisors = self
            .proxy_supervisors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let deadline = *self
            .shutdown_deadline
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut joins = tokio::task::JoinSet::new();
        for supervisor in supervisors {
            joins.spawn(async move {
                if let Some(deadline) = deadline {
                    tokio::select! {
                        biased;
                        _ = tokio::time::sleep_until(deadline) => supervisor.abort_and_join().await,
                        result = supervisor.close_and_join() => result,
                    }
                } else {
                    supervisor.close_and_join().await
                }
            });
        }
        while let Some(result) = joins.join_next().await {
            let error = match result {
                Ok(Ok(())) => continue,
                Ok(Err(error)) => Arc::new(error),
                Err(error) => {
                    tracing::error!(%error, "proxy supervisor shutdown coordinator failed");
                    continue;
                }
            };
            tracing::error!(error = %error, "proxy supervisor shutdown failed");
            let mut recorded = self
                .proxy_shutdown_error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if recorded.is_none() {
                *recorded = Some(error);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn shutdown_started_for_test(&self) -> bool {
        self.shutdown_started.load(Ordering::Acquire)
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
        if self.shutdown_started.swap(true, Ordering::AcqRel) {
            return;
        }
        for supervisor in self
            .proxy_supervisors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
        {
            supervisor.begin_shutdown();
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
        self.credential_io_runtime.begin_shutdown();
        self.authorization_runtime.begin_shutdown(deadline);
        self.upgrade_runtime.begin_shutdown(deadline);
        if let Some(mitm) = self.ingress_assets.mitm() {
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
            self.upgrade_shutdown
                .get_or_init(|| self.upgrade_runtime.shutdown_and_wait(deadline))
                .await;
            self.proxy_shutdown
                .get_or_init(|| self.shutdown_proxy_supervisors())
                .await;
            self.mitm_shutdown
                .get_or_init(|| async {
                    if let Some(mitm) = self.ingress_assets.mitm() {
                        mitm.shutdown_and_join().await;
                    }
                })
                .await;
            self.observation_runtime.shutdown().await;
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductStaticResourcesError {
    #[error(transparent)]
    IngressAssets(#[from] ProductIngressAssetsError),
    #[error("static fingerprint derivation failed")]
    StaticFingerprint(#[from] StaticFingerprintError),
    #[error("static authorization runtime construction failed")]
    Authorization(#[from] WebhookAuthorizationRuntimeError),
    #[error("static credential I/O runtime construction failed")]
    CredentialIo(#[from] CredentialIoRuntimeError),
    #[error("static upgrade runtime construction failed")]
    Upgrade(#[from] UpgradeRuntimeError),
    #[error("static observation runtime construction failed")]
    Observation(#[from] ProductObservationRuntimeStartError),
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
    #[error("proxy supervisors have already been adopted")]
    ProxySupervisorsAlreadyAdopted,
    #[error("static resources are shutting down")]
    ShuttingDown,
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::mpsc as std_mpsc;
    use std::sync::Condvar;
    use std::time::Duration;

    use tokio::sync::oneshot;

    use super::*;
    use crate::config::compiler::{
        CompiledTlsIdentity, StaticCleartextListener, StaticExplicitHttpsListener,
        StaticMitmConfig, StaticTransparentHttpsListener,
    };
    use crate::config::{compile_config_text, ConfigTextInput};
    use crate::upgrade::UpgradeAllocation;

    struct DropSignal(Option<oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(signal) = self.0.take() {
                let _ = signal.send(());
            }
        }
    }

    fn static_config(addresses: [SocketAddr; 5], identity_directory: &Path) -> StaticProductConfig {
        let [explicit_http, transparent_http, explicit_https, transparent_https, control] =
            addresses;
        let text = format!(
            r#"schema_version = 3

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
bind = "{explicit_http}"
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
            bind: transparent_http,
            http_versions: versions.clone(),
            request_header_timeout,
            max_connections,
            max_concurrent_streams,
            connect: None,
        });
        std::fs::create_dir_all(identity_directory).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let certificate_chain = identity_directory.join("server.pem");
        let private_key = identity_directory.join("server-key.pem");
        std::fs::write(&certificate_chain, certificate.pem()).unwrap();
        std::fs::write(&private_key, key.serialize_pem()).unwrap();
        config.listeners.explicit_https = Some(StaticExplicitHttpsListener {
            bind: explicit_https,
            http_versions: versions.clone(),
            handshake_timeout: Duration::from_secs(1),
            request_header_timeout: Duration::from_secs(1),
            max_connections: 2,
            max_concurrent_streams: 8,
            connect,
            tls: CompiledTlsIdentity {
                certificate_chain,
                private_key,
            },
        });
        config.listeners.transparent_https = Some(StaticTransparentHttpsListener {
            bind: transparent_https,
            http_versions: versions,
            handshake_timeout: Duration::from_secs(1),
            request_header_timeout: Duration::from_secs(1),
            max_connections: 2,
            max_concurrent_streams: 8,
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
            ProductStaticResources::try_new(&static_config(addresses, directory.path())).unwrap();

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
            ProductStaticResources::try_new(&static_config(addresses, directory.path())).unwrap();

        assert!(matches!(
            resources.prepare_ingress_from_prebound(listeners),
            Err(ProductStaticResourcesError::ProxyListenerBind(error))
                if error.name == "explicit_https" && error.address == addresses[2]
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
            ProductStaticResources::try_new(&static_config(addresses, directory.path())).unwrap();

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
            ProductStaticResources::try_new(&static_config(addresses, directory.path())).unwrap();
        resources
            .prepare_ingress_from_prebound(reservations.into_listeners())
            .unwrap();

        StaticResources::shutdown(resources.as_ref()).await;

        super::super::assert_listener_addresses_released(&_test, addresses);
        assert!(matches!(
            resources.take_prepared_proxy_listeners_for_supervisor_start(),
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
            ProductStaticResources::try_new(&static_config(addresses, directory.path())).unwrap();

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
    async fn static_owner_closes_and_joins_runtime_owned_upgrade_tasks() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<5>(&_test);
        let addresses = reservations.addresses();
        let directory = tempfile::tempdir().unwrap();
        let resources =
            ProductStaticResources::try_new(&static_config(addresses, directory.path())).unwrap();
        let runtime = resources.upgrade_runtime();
        let counts = runtime.counts();
        assert_eq!(counts.maximum_slots, 256);
        assert_eq!(counts.maximum_bytes, 2_147_483_648);

        let (started_tx, started_rx) = oneshot::channel();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        runtime
            .try_spawn_handshake(
                UpgradeAllocation::from_compiled_rule(0, Some(0)).unwrap(),
                move |_| async move {
                    let _drop = DropSignal(Some(dropped_tx));
                    let _ = started_tx.send(());
                    std::future::pending::<()>().await;
                },
            )
            .unwrap();
        started_rx.await.unwrap();

        StaticResources::begin_shutdown(resources.as_ref());
        assert!(!runtime.counts().accepting);
        tokio::time::timeout(
            Duration::from_secs(2),
            StaticResources::shutdown(resources.as_ref()),
        )
        .await
        .expect("static shutdown did not join the upgrade task");
        dropped_rx.await.unwrap();

        let counts = runtime.counts();
        assert_eq!(counts.reserved_slots, 0);
        assert_eq!(counts.reserved_bytes, 0);
        assert_eq!(counts.uncommitted, 0);
        assert_eq!(counts.committed, 0);
        assert_eq!(counts.tracked_tasks, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn static_shutdown_deadline_detaches_blocked_credential_io() {
        let _test = super::super::LISTENER_TEST_LOCK.lock().await;
        let reservations = super::super::reserve_listeners::<5>(&_test);
        let addresses = reservations.addresses();
        let directory = tempfile::tempdir().unwrap();
        let mut config = static_config(addresses, directory.path());
        config.service.shutdown_drain_timeout = Some(Duration::from_millis(20));
        let resources = ProductStaticResources::try_new(&config).unwrap();
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
