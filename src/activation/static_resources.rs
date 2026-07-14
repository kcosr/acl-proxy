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
use crate::observation::ProductObservationRuntime;
use crate::runtime::{BoxFuture, ServiceReadiness, StaticResourceBrand, StaticResources};
use crate::safety::WireBodyPool;

use super::listeners::{PreparedProxyListeners, ProxyListenerBindError};
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
    ingress: Mutex<IngressOwnership>,
    control: Mutex<ControlOwnership>,
    wire_body_pool: Arc<WireBodyPool>,
    observation_runtime: Arc<ProductObservationRuntime>,
    authorization_runtime: Arc<WebhookAuthorizationRuntime>,
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
        let (control_failure, _) = watch::channel(None);
        Ok(Arc::new(Self {
            readiness: Arc::new(ServiceReadiness::new()),
            brand: StaticResourceBrand::new(),
            static_fingerprint: StaticFingerprint::from_config(static_config)?,
            shutdown_drain_timeout: static_config.service.shutdown_drain_timeout,
            shutdown_started: AtomicBool::new(false),
            shutdown_deadline: Mutex::new(None),
            control_failure,
            control_shutdown_error: Mutex::new(None),
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
            observation_runtime: Arc::new(ProductObservationRuntime::new()),
            authorization_runtime: WebhookAuthorizationRuntime::try_new(static_config)?,
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

    pub(crate) fn authorization_runtime(&self) -> Arc<WebhookAuthorizationRuntime> {
        self.authorization_runtime.clone()
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

    fn prepare_ingress_with(
        self: &Arc<Self>,
        bind: impl FnMut(SocketAddr) -> std::io::Result<TcpListener>,
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

        let listeners = PreparedProxyListeners::bind(&ingress.config, bind)?;
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if control.server.is_some() {
            return Err(ProductStaticResourcesError::ControlAlreadyStarted);
        }
        if let Some(config) = control.config.as_ref() {
            let listener =
                TcpListener::bind(config.bind).map_err(|source| ControlServerError::Bind {
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
        self.authorization_runtime.begin_shutdown(deadline);
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
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductStaticResourcesError {
    #[error("static fingerprint derivation failed")]
    StaticFingerprint(#[from] StaticFingerprintError),
    #[error("static authorization runtime construction failed")]
    Authorization(#[from] WebhookAuthorizationRuntimeError),
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
    #[error("static resources are shutting down")]
    ShuttingDown,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use super::*;
    use crate::config::compiler::{
        CompiledTlsIdentity, StaticCleartextListener, StaticExplicitHttpsListener,
        StaticTransparentHttpsListener,
    };
    use crate::config::{compile_config_text, ConfigTextInput};

    static LISTENER_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn available_addresses<const N: usize>() -> [SocketAddr; N] {
        let listeners: Vec<_> = (0..N)
            .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
            .collect();
        let addresses = listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        drop(listeners);
        addresses
    }

    fn static_config(addresses: [SocketAddr; 5]) -> StaticProductConfig {
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
        config.listeners.transparent_http = Some(StaticCleartextListener {
            bind: transparent_http,
            http_versions: versions.clone(),
            connect: None,
        });
        config.listeners.explicit_https = Some(StaticExplicitHttpsListener {
            bind: explicit_https,
            http_versions: versions.clone(),
            handshake_timeout: Duration::from_secs(1),
            request_header_timeout: Duration::from_secs(1),
            max_connections: 2,
            max_concurrent_streams: 8,
            connect,
            tls: CompiledTlsIdentity {
                certificate_chain: PathBuf::from("/tmp/static-ingress/server.pem"),
                private_key: PathBuf::from("/tmp/static-ingress/server-key.pem"),
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
        config
    }

    fn assert_bindable(addresses: impl IntoIterator<Item = SocketAddr>) {
        for address in addresses {
            TcpListener::bind(address)
                .unwrap_or_else(|error| panic!("expected {address} to be released: {error}"));
        }
    }

    #[tokio::test]
    async fn preparation_reserves_every_configured_listener_and_is_one_shot() {
        let _test = LISTENER_TEST_LOCK.lock().await;
        let addresses = available_addresses::<5>();
        let resources = ProductStaticResources::try_new(&static_config(addresses)).unwrap();

        resources.prepare_ingress().unwrap();
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
        assert_bindable(addresses);
    }

    #[tokio::test]
    async fn later_proxy_bind_failure_releases_earlier_sockets() {
        let _test = LISTENER_TEST_LOCK.lock().await;
        let addresses = available_addresses::<5>();
        let blocker = TcpListener::bind(addresses[2]).unwrap();
        let resources = ProductStaticResources::try_new(&static_config(addresses)).unwrap();

        assert!(matches!(
            resources.prepare_ingress(),
            Err(ProductStaticResourcesError::ProxyListenerBind(error))
                if error.name == "explicit_https" && error.address == addresses[2]
        ));
        assert_bindable([addresses[0], addresses[1], addresses[3], addresses[4]]);

        drop(blocker);
        StaticResources::shutdown(resources.as_ref()).await;
    }

    #[tokio::test]
    async fn control_adoption_failure_releases_all_prebound_sockets() {
        let _test = LISTENER_TEST_LOCK.lock().await;
        let addresses = available_addresses::<5>();
        let resources = ProductStaticResources::try_new(&static_config(addresses)).unwrap();

        assert!(matches!(
            resources.prepare_ingress_with(TcpListener::bind, |_config, _listener, _observer| {
                Err(ControlServerError::RuntimeUnavailable)
            }),
            Err(ProductStaticResourcesError::Control(
                ControlServerError::RuntimeUnavailable
            ))
        ));
        assert_bindable(addresses);

        StaticResources::shutdown(resources.as_ref()).await;
    }

    #[tokio::test]
    async fn shutdown_releases_prepared_but_unstarted_proxy_sockets() {
        let _test = LISTENER_TEST_LOCK.lock().await;
        let addresses = available_addresses::<5>();
        let resources = ProductStaticResources::try_new(&static_config(addresses)).unwrap();
        resources.prepare_ingress().unwrap();

        StaticResources::shutdown(resources.as_ref()).await;

        assert_bindable(addresses);
        assert!(matches!(
            resources.take_prepared_proxy_listeners_for_supervisor_start(),
            Err(ProductStaticResourcesError::IngressAlreadyAdopted)
        ));
    }

    #[tokio::test]
    async fn construction_does_not_bind_configured_sockets() {
        let _test = LISTENER_TEST_LOCK.lock().await;
        let addresses = available_addresses::<5>();
        let resources = ProductStaticResources::try_new(&static_config(addresses)).unwrap();

        assert_bindable(addresses);
        drop(resources);
    }
}
