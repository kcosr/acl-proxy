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
    control: Mutex<ControlOwnership>,
    wire_body_pool: Arc<WireBodyPool>,
    observation_runtime: Arc<ProductObservationRuntime>,
    authorization_runtime: Arc<WebhookAuthorizationRuntime>,
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
        let _control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.readiness.begin_shutdown();
        if self.shutdown_started.swap(true, Ordering::AcqRel) {
            return;
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
    #[error("control server has already started")]
    ControlAlreadyStarted,
    #[error("static resources are shutting down")]
    ShuttingDown,
}
