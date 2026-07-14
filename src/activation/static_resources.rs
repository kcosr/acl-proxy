use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::authorization::callback::PendingTerminalCause;
use crate::authorization::webhook::runtime::{
    WebhookAuthorizationRuntime, WebhookAuthorizationRuntimeError,
};
use crate::config::{StaticFingerprint, StaticFingerprintError, StaticProductConfig};
use crate::control::server::{ControlServer, ControlServerError};
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
    control: Mutex<ControlOwnership>,
    wire_body_pool: Arc<WireBodyPool>,
    observation_runtime: Arc<ProductObservationRuntime>,
    authorization_runtime: Arc<WebhookAuthorizationRuntime>,
}

struct ControlOwnership {
    config: Option<crate::config::compiler::StaticControlConfig>,
    server: Option<Arc<ControlServer>>,
}

impl ProductStaticResources {
    pub(crate) fn try_new(
        static_config: &StaticProductConfig,
    ) -> Result<Arc<Self>, ProductStaticResourcesError> {
        Ok(Arc::new(Self {
            readiness: Arc::new(ServiceReadiness::new()),
            brand: StaticResourceBrand::new(),
            static_fingerprint: StaticFingerprint::from_config(static_config)?,
            shutdown_drain_timeout: static_config.service.shutdown_drain_timeout,
            shutdown_started: AtomicBool::new(false),
            shutdown_deadline: Mutex::new(None),
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
        self.start_control_with(|config| {
            ControlServer::bind(
                config,
                self.authorization_runtime.clone(),
                self.readiness.clone(),
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn start_control_with_listener(
        self: &Arc<Self>,
        listener: std::net::TcpListener,
    ) -> Result<Option<std::net::SocketAddr>, ProductStaticResourcesError> {
        self.start_control_with(|config| {
            ControlServer::from_prebound(
                config,
                listener,
                self.authorization_runtime.clone(),
                self.readiness.clone(),
            )
        })
    }

    fn start_control_with(
        &self,
        start: impl FnOnce(
            &crate::config::compiler::StaticControlConfig,
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
        let server = start(config)?;
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
                } else {
                    control.close_and_join().await
                };
                if let Err(error) = result {
                    panic!("control-server shutdown failed: {error}");
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
