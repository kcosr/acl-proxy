use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use access_flow_tls::{
    TlsAccessFlowGeneration, TlsAccessFlowHandshakeTimeout, TlsAccessFlowServerAdapter,
    TlsAccessFlowServerLimits,
};
use tokio::sync::{watch, Mutex as AsyncMutex};

use crate::access_flow_tls_identity::{
    load_access_flow_tls_server_identity, AccessFlowTlsIdentityValidity,
};
use crate::config::compiler::{
    CompiledAccessFlowTlsAbuseControl, CompiledAccessFlowTlsServerIdentity,
    StaticAccessFlowTransport, StaticListenerEndpoint, StaticListenersConfig,
};
use crate::runtime::ServiceReadiness;

const WALL_VALIDITY_CHECK_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum AccessFlowTlsRouteId {
    TransparentHttp,
    TransparentHttps,
}

#[derive(Clone)]
struct AccessFlowTlsRouteSource {
    id: AccessFlowTlsRouteId,
    identity: CompiledAccessFlowTlsServerIdentity,
    handshake_timeout: Duration,
    limits: CompiledAccessFlowTlsAbuseControl,
}

#[derive(Clone)]
struct ActivatedAccessFlowTlsRoute {
    adapter: Arc<TlsAccessFlowServerAdapter>,
    validity: AccessFlowTlsIdentityValidity,
}

struct LoadedAccessFlowTlsGeneration {
    id: TlsAccessFlowGeneration,
    routes: HashMap<AccessFlowTlsRouteId, ActivatedAccessFlowTlsRoute>,
    earliest_expiry_unix_seconds: Option<u64>,
}

struct AccessFlowTlsGeneration {
    id: TlsAccessFlowGeneration,
    routes: HashMap<AccessFlowTlsRouteId, ActivatedAccessFlowTlsRoute>,
    expiry_deadline: Option<tokio::time::Instant>,
}

#[derive(Clone)]
enum AccessFlowSecurityState {
    Healthy(Arc<AccessFlowTlsGeneration>),
    Unhealthy(Arc<AccessFlowTlsGeneration>),
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AccessFlowSecurityAdmissionState {
    Healthy(TlsAccessFlowGeneration),
    Unhealthy,
    Closed,
}

pub(crate) struct AccessFlowSecurityMaterialRuntime {
    sources: Box<[AccessFlowTlsRouteSource]>,
    state: watch::Sender<AccessFlowSecurityState>,
    readiness: Arc<ServiceReadiness>,
    next_generation: AtomicU64,
    reload: AsyncMutex<()>,
    publication: Mutex<()>,
    shutdown_started: AtomicBool,
    expiry_supervisor: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[derive(Clone)]
pub(crate) struct AccessFlowSecuritySubscription {
    state: watch::Receiver<AccessFlowSecurityState>,
    runtime: Option<Weak<AccessFlowSecurityMaterialRuntime>>,
}

#[cfg(test)]
pub(super) struct AccessFlowSecurityTestGuard {
    _state: watch::Sender<AccessFlowSecurityState>,
}

pub(super) struct CurrentAccessFlowTlsRoute {
    pub(super) generation: TlsAccessFlowGeneration,
    pub(super) adapter: Arc<TlsAccessFlowServerAdapter>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum AccessFlowSecurityMaterialError {
    #[error("Access Flow TLS security material is unavailable")]
    Unavailable,
    #[error("Access Flow TLS security material is invalid")]
    Invalid,
    #[error("Access Flow TLS security material coordinator failed")]
    Coordinator,
    #[error("Access Flow TLS security material is shutting down")]
    ShuttingDown,
}

impl AccessFlowSecurityMaterialRuntime {
    pub(super) async fn activate(
        config: &StaticListenersConfig,
        readiness: Arc<ServiceReadiness>,
    ) -> Result<Arc<Self>, AccessFlowSecurityMaterialError> {
        let sources = route_sources(config).into_boxed_slice();
        let initial = load_generation(sources.to_vec(), 1)
            .await?
            .publish(SystemTime::now(), tokio::time::Instant::now())?;
        let (state, _) = watch::channel(AccessFlowSecurityState::Healthy(Arc::new(initial)));
        let runtime = Arc::new(Self {
            sources,
            state,
            readiness,
            next_generation: AtomicU64::new(2),
            reload: AsyncMutex::new(()),
            publication: Mutex::new(()),
            shutdown_started: AtomicBool::new(false),
            expiry_supervisor: Mutex::new(None),
        });
        runtime.start_expiry_supervisor();
        Ok(runtime)
    }

    pub(super) fn subscribe(self: &Arc<Self>) -> AccessFlowSecuritySubscription {
        AccessFlowSecuritySubscription {
            state: self.state.subscribe(),
            runtime: Some(Arc::downgrade(self)),
        }
    }

    pub(super) async fn reload(&self) -> Result<(), AccessFlowSecurityMaterialError> {
        self.reload_after_load(std::future::ready(())).await
    }

    async fn reload_after_load(
        &self,
        after_load: impl std::future::Future<Output = ()>,
    ) -> Result<(), AccessFlowSecurityMaterialError> {
        let _reload = self.reload.lock().await;
        if self.shutdown_started.load(Ordering::Acquire) {
            return Err(AccessFlowSecurityMaterialError::ShuttingDown);
        }
        if self.sources.is_empty() {
            let _publication = self
                .publication
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.shutdown_started.load(Ordering::Acquire) {
                return Err(AccessFlowSecurityMaterialError::ShuttingDown);
            }
            self.readiness.mark_access_flow_security_healthy();
            return Ok(());
        }
        let generation = self.next_generation.fetch_add(1, Ordering::AcqRel);
        let loaded = load_generation(self.sources.to_vec(), generation).await;
        after_load.await;
        if self.shutdown_started.load(Ordering::Acquire) {
            return Err(AccessFlowSecurityMaterialError::ShuttingDown);
        }
        match loaded {
            Ok(generation) => {
                let _publication = self
                    .publication
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if self.shutdown_started.load(Ordering::Acquire) {
                    return Err(AccessFlowSecurityMaterialError::ShuttingDown);
                }
                let generation = match generation
                    .publish(SystemTime::now(), tokio::time::Instant::now())
                {
                    Ok(generation) => generation,
                    Err(error) => {
                        self.readiness.mark_access_flow_security_unhealthy();
                        self.preserve_generation_as_unhealthy();
                        tracing::error!(
                            target: "acl_proxy::access_flow",
                            category = "security_material_reload_failed",
                            "Access Flow security material is unhealthy; new Access Flow admission is closed"
                        );
                        return Err(error);
                    }
                };
                self.state
                    .send_replace(AccessFlowSecurityState::Healthy(Arc::new(generation)));
                self.readiness.mark_access_flow_security_healthy();
                tracing::info!(
                    target: "acl_proxy::access_flow",
                    category = "security_material_reloaded",
                    "Access Flow TLS security material reloaded"
                );
                Ok(())
            }
            Err(error) => {
                self.mark_unhealthy(None, "security_material_reload_failed");
                Err(error)
            }
        }
    }

    pub(super) fn begin_shutdown(&self) {
        let _publication = self
            .publication
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.shutdown_started.swap(true, Ordering::AcqRel) {
            self.state.send_replace(AccessFlowSecurityState::Closed);
        }
    }

    pub(super) async fn shutdown(&self) {
        self.begin_shutdown();
        let task = self
            .expiry_supervisor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }

    fn start_expiry_supervisor(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let state = self.state.subscribe();
        let task = tokio::spawn(async move { supervise_expiry(weak, state).await });
        *self
            .expiry_supervisor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(task);
    }

    fn mark_unhealthy(
        &self,
        expected_generation: Option<TlsAccessFlowGeneration>,
        category: &'static str,
    ) {
        let _publication = self
            .publication
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.shutdown_started.load(Ordering::Acquire) {
            return;
        }
        if let Some(expected) = expected_generation {
            let current_matches = matches!(
                &*self.state.borrow(),
                AccessFlowSecurityState::Healthy(current) if current.id == expected
            );
            if !current_matches {
                return;
            }
        }
        self.readiness.mark_access_flow_security_unhealthy();
        self.preserve_generation_as_unhealthy();
        tracing::error!(
            target: "acl_proxy::access_flow",
            category,
            "Access Flow security material is unhealthy; new Access Flow admission is closed"
        );
    }

    fn preserve_generation_as_unhealthy(&self) {
        let current = match self.state.borrow().clone() {
            AccessFlowSecurityState::Healthy(generation)
            | AccessFlowSecurityState::Unhealthy(generation) => generation,
            AccessFlowSecurityState::Closed => return,
        };
        self.state
            .send_replace(AccessFlowSecurityState::Unhealthy(current));
    }
}

pub(crate) fn validate_access_flow_security_material(
    config: &StaticListenersConfig,
) -> Result<(), AccessFlowSecurityMaterialError> {
    load_generation_blocking(&route_sources(config), 1).map(|_| ())
}

impl AccessFlowSecuritySubscription {
    #[cfg(test)]
    pub(super) fn closed_for_test() -> Self {
        let (_state, receiver) = watch::channel(AccessFlowSecurityState::Closed);
        Self {
            state: receiver,
            runtime: None,
        }
    }

    #[cfg(test)]
    pub(super) fn healthy_for_test() -> (AccessFlowSecurityTestGuard, Self) {
        let generation = Arc::new(AccessFlowTlsGeneration {
            id: TlsAccessFlowGeneration::new(1).expect("test generation is nonzero"),
            routes: HashMap::new(),
            expiry_deadline: None,
        });
        let (state, receiver) = watch::channel(AccessFlowSecurityState::Healthy(generation));
        (
            AccessFlowSecurityTestGuard { _state: state },
            Self {
                state: receiver,
                runtime: None,
            },
        )
    }

    pub(super) fn admission_state(&self) -> AccessFlowSecurityAdmissionState {
        self.admission_state_at(unix_time_seconds())
    }

    fn admission_state_at(&self, unix_seconds: u64) -> AccessFlowSecurityAdmissionState {
        let snapshot = self.state.borrow().clone();
        match snapshot {
            AccessFlowSecurityState::Healthy(generation)
                if routes_are_current_at(&generation.routes, unix_seconds) =>
            {
                AccessFlowSecurityAdmissionState::Healthy(generation.id)
            }
            AccessFlowSecurityState::Healthy(generation) => {
                self.report_wall_invalid(generation.id);
                AccessFlowSecurityAdmissionState::Unhealthy
            }
            AccessFlowSecurityState::Unhealthy(_) => AccessFlowSecurityAdmissionState::Unhealthy,
            AccessFlowSecurityState::Closed => AccessFlowSecurityAdmissionState::Closed,
        }
    }

    pub(super) fn current_tls_route(
        &self,
        id: AccessFlowTlsRouteId,
    ) -> Option<CurrentAccessFlowTlsRoute> {
        let snapshot = self.state.borrow().clone();
        let AccessFlowSecurityState::Healthy(generation) = snapshot else {
            return None;
        };
        if !generation_is_current(&generation) {
            self.report_wall_invalid(generation.id);
            return None;
        }
        let route = generation.routes.get(&id)?;
        Some(CurrentAccessFlowTlsRoute {
            generation: generation.id,
            adapter: Arc::clone(&route.adapter),
        })
    }

    pub(super) fn tls_rejection_adapter(
        &self,
        id: AccessFlowTlsRouteId,
    ) -> Option<Arc<TlsAccessFlowServerAdapter>> {
        let state = self.state.borrow();
        let generation = match &*state {
            AccessFlowSecurityState::Healthy(generation)
            | AccessFlowSecurityState::Unhealthy(generation) => generation,
            AccessFlowSecurityState::Closed => return None,
        };
        generation
            .routes
            .get(&id)
            .map(|route| Arc::clone(&route.adapter))
    }

    pub(super) fn is_current(&self, generation: TlsAccessFlowGeneration) -> bool {
        let snapshot = self.state.borrow().clone();
        let AccessFlowSecurityState::Healthy(current) = snapshot else {
            return false;
        };
        if current.id != generation {
            return false;
        }
        if !generation_is_current(&current) {
            self.report_wall_invalid(current.id);
            return false;
        }
        true
    }

    pub(super) async fn changed(&mut self) -> bool {
        self.state.changed().await.is_ok()
    }

    fn report_wall_invalid(&self, generation: TlsAccessFlowGeneration) {
        if let Some(runtime) = self.runtime.as_ref().and_then(Weak::upgrade) {
            runtime.mark_unhealthy(Some(generation), "security_material_wall_invalid");
        }
    }
}

fn route_sources(config: &StaticListenersConfig) -> Vec<AccessFlowTlsRouteSource> {
    let mut sources = Vec::new();
    for (id, endpoint) in [
        (
            AccessFlowTlsRouteId::TransparentHttp,
            config
                .transparent_http
                .as_ref()
                .map(|listener| &listener.endpoint),
        ),
        (
            AccessFlowTlsRouteId::TransparentHttps,
            config
                .transparent_https
                .as_ref()
                .map(|listener| &listener.endpoint),
        ),
    ] {
        let Some(StaticListenerEndpoint::AccessFlow {
            transport:
                StaticAccessFlowTransport::TlsTcp {
                    handshake_timeout,
                    server_identity,
                    abuse_control,
                    ..
                },
            ..
        }) = endpoint
        else {
            continue;
        };
        sources.push(AccessFlowTlsRouteSource {
            id,
            identity: server_identity.clone(),
            handshake_timeout: *handshake_timeout,
            limits: *abuse_control,
        });
    }
    sources
}

async fn load_generation(
    sources: Vec<AccessFlowTlsRouteSource>,
    generation: u64,
) -> Result<LoadedAccessFlowTlsGeneration, AccessFlowSecurityMaterialError> {
    tokio::task::spawn_blocking(move || load_generation_blocking(&sources, generation))
        .await
        .map_err(|_| AccessFlowSecurityMaterialError::Coordinator)?
}

fn load_generation_blocking(
    sources: &[AccessFlowTlsRouteSource],
    generation: u64,
) -> Result<LoadedAccessFlowTlsGeneration, AccessFlowSecurityMaterialError> {
    let id = TlsAccessFlowGeneration::new(generation)
        .map_err(|_| AccessFlowSecurityMaterialError::Invalid)?;
    let mut routes = HashMap::with_capacity(sources.len());
    let mut earliest_expiry = None;
    for source in sources {
        let loaded = load_access_flow_tls_server_identity(
            &source.identity.certificate_chain,
            &source.identity.private_key,
            id,
        )
        .map_err(|error| match error {
            crate::access_flow_tls_identity::AccessFlowTlsIdentityError::Unavailable => {
                AccessFlowSecurityMaterialError::Unavailable
            }
            _ => AccessFlowSecurityMaterialError::Invalid,
        })?;
        let handshake_timeout = TlsAccessFlowHandshakeTimeout::new(source.handshake_timeout)
            .map_err(|_| AccessFlowSecurityMaterialError::Invalid)?;
        let limits = TlsAccessFlowServerLimits::new(
            source.limits.max_handshakes,
            source.limits.max_connections_per_source,
            source.limits.handshakes_per_second,
            source.limits.handshake_burst,
            source.limits.source_table_capacity,
        )
        .map_err(|_| AccessFlowSecurityMaterialError::Invalid)?;
        let activated = loaded
            .activate(handshake_timeout, limits)
            .map_err(|_| AccessFlowSecurityMaterialError::Invalid)?;
        earliest_expiry = Some(
            earliest_expiry.map_or(activated.validity.not_after_unix_seconds, |current: u64| {
                current.min(activated.validity.not_after_unix_seconds)
            }),
        );
        routes.insert(
            source.id,
            ActivatedAccessFlowTlsRoute {
                adapter: Arc::new(activated.adapter),
                validity: activated.validity,
            },
        );
    }
    Ok(LoadedAccessFlowTlsGeneration {
        id,
        routes,
        earliest_expiry_unix_seconds: earliest_expiry,
    })
}

impl LoadedAccessFlowTlsGeneration {
    fn publish(
        self,
        wall_now: SystemTime,
        monotonic_now: tokio::time::Instant,
    ) -> Result<AccessFlowTlsGeneration, AccessFlowSecurityMaterialError> {
        let wall_now_seconds = unix_time_seconds_at(wall_now);
        if !routes_are_current_at(&self.routes, wall_now_seconds) {
            return Err(AccessFlowSecurityMaterialError::Invalid);
        }
        let expiry_deadline = self
            .earliest_expiry_unix_seconds
            .map(|expiry| publication_expiry_deadline(expiry, wall_now, monotonic_now))
            .transpose()?;
        Ok(AccessFlowTlsGeneration {
            id: self.id,
            routes: self.routes,
            expiry_deadline,
        })
    }
}

async fn supervise_expiry(
    runtime: Weak<AccessFlowSecurityMaterialRuntime>,
    mut state: watch::Receiver<AccessFlowSecurityState>,
) {
    loop {
        let snapshot = state.borrow().clone();
        match snapshot {
            AccessFlowSecurityState::Closed => return,
            AccessFlowSecurityState::Unhealthy(_) => {
                if state.changed().await.is_err() {
                    return;
                }
            }
            AccessFlowSecurityState::Healthy(generation) => {
                let Some(expiry_deadline) = generation.expiry_deadline else {
                    if state.changed().await.is_err() {
                        return;
                    }
                    continue;
                };
                tokio::select! {
                    biased;
                    changed = state.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                    () = tokio::time::sleep_until(expiry_deadline) => {
                        let Some(runtime) = runtime.upgrade() else {
                            return;
                        };
                        runtime.mark_unhealthy(
                            Some(generation.id),
                            "security_material_expired",
                        );
                    }
                    () = tokio::time::sleep(WALL_VALIDITY_CHECK_INTERVAL) => {
                        let Some(runtime) = runtime.upgrade() else {
                            return;
                        };
                        if !generation_is_current(&generation) {
                            runtime.mark_unhealthy(
                                Some(generation.id),
                                "security_material_wall_invalid",
                            );
                        }
                    }
                }
            }
        }
    }
}

fn generation_is_current(generation: &AccessFlowTlsGeneration) -> bool {
    routes_are_current_at(&generation.routes, unix_time_seconds())
}

fn routes_are_current_at(
    routes: &HashMap<AccessFlowTlsRouteId, ActivatedAccessFlowTlsRoute>,
    unix_seconds: u64,
) -> bool {
    routes.values().all(|route| {
        unix_seconds >= route.validity.not_before_unix_seconds
            && unix_seconds <= route.validity.not_after_unix_seconds
    })
}

fn unix_time_seconds() -> u64 {
    unix_time_seconds_at(SystemTime::now())
}

fn unix_time_seconds_at(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn publication_expiry_deadline(
    not_after_unix_seconds: u64,
    wall_now: SystemTime,
    monotonic_now: tokio::time::Instant,
) -> Result<tokio::time::Instant, AccessFlowSecurityMaterialError> {
    let expiry_exclusive = UNIX_EPOCH
        .checked_add(Duration::from_secs(not_after_unix_seconds))
        .and_then(|expiry| expiry.checked_add(Duration::from_secs(1)))
        .ok_or(AccessFlowSecurityMaterialError::Invalid)?;
    let remaining = expiry_exclusive
        .duration_since(wall_now)
        .unwrap_or(Duration::ZERO);
    monotonic_now
        .checked_add(remaining)
        .ok_or(AccessFlowSecurityMaterialError::Invalid)
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use crate::config::{compile_config_text, ConfigTextInput};
    use crate::test_certificates::TestTlsIdentity;

    use super::*;

    fn trusted_tempdir() -> tempfile::TempDir {
        let home = std::env::var_os("HOME").expect("HOME is configured");
        let directory = tempfile::Builder::new()
            .prefix(".acl-proxy-security-material-")
            .tempdir_in(home)
            .expect("create trusted security-material test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn write_identity(
        directory: &Path,
        identity: &TestTlsIdentity,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let certificate = directory.join("server-chain.pem");
        let private_key = directory.join("server-key.pem");
        crate::filesystem::write_public_file(&certificate, identity.certificate_chain_pem())
            .unwrap();
        crate::filesystem::write_private_file(&private_key, identity.private_key_pem()).unwrap();
        (certificate, private_key)
    }

    fn listeners(
        certificate: &Path,
        private_key: &Path,
    ) -> crate::config::compiler::StaticListenersConfig {
        let text = format!(
            r#"schema_version = 4

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]

[listeners.transparent_http.identity]
mode = "required"

[listeners.transparent_http.endpoint.transport]
kind = "tls_tcp"
bind = "127.0.0.2:7443"
handshake_timeout = "2s"

[listeners.transparent_http.endpoint.transport.server_identity]
certificate_chain = {:?}
private_key = {:?}

[identity]
max_pending_authentications = 8
max_pending_authentications_per_connection = 2

[identity.resolver]
kind = "static"
authority = "security-material-test"

[[identity.resolver.principals]]
id = "test-workload"
kind = "service_account"

[[identity.resolver.tokens]]
id = "test-token"
principal = "test-workload"
source = "environment"
variable = "AW_SECURITY_MATERIAL_IDENTITY_TOKEN"

[policy]
default = "deny"
"#,
            certificate, private_key
        );
        compile_config_text(ConfigTextInput {
            text: &text,
            source_path: Path::new("/tmp/security-material-test/acl-proxy.toml"),
            config_root: Path::new("/tmp/security-material-test"),
        })
        .unwrap()
        .static_config
        .listeners
    }

    #[tokio::test]
    async fn failed_reload_closes_admission_and_successful_reload_reopens_new_generation() {
        let directory = trusted_tempdir();
        let first_identity = TestTlsIdentity::new("localhost");
        let (certificate, private_key) = write_identity(directory.path(), &first_identity);
        let listeners = listeners(&certificate, &private_key);
        let readiness = Arc::new(ServiceReadiness::new());
        readiness.mark_ready_for_test();
        let runtime = AccessFlowSecurityMaterialRuntime::activate(&listeners, readiness.clone())
            .await
            .unwrap();
        let subscription = runtime.subscribe();
        let first = subscription
            .current_tls_route(AccessFlowTlsRouteId::TransparentHttp)
            .unwrap();
        assert!(readiness.is_ready());

        fs::write(&private_key, b"invalid private key").unwrap();
        assert_eq!(
            runtime.reload().await,
            Err(AccessFlowSecurityMaterialError::Invalid)
        );
        assert!(!readiness.is_ready());
        assert!(!subscription.is_current(first.generation));
        assert!(subscription
            .current_tls_route(AccessFlowTlsRouteId::TransparentHttp)
            .is_none());

        let second_identity = TestTlsIdentity::new("localhost");
        fs::write(&certificate, second_identity.certificate_chain_pem()).unwrap();
        fs::write(&private_key, second_identity.private_key_pem()).unwrap();
        runtime.reload().await.unwrap();
        let second = subscription
            .current_tls_route(AccessFlowTlsRouteId::TransparentHttp)
            .unwrap();
        assert_ne!(first.generation, second.generation);
        assert!(readiness.is_ready());
        assert!(!subscription.is_current(first.generation));
        assert!(subscription.is_current(second.generation));
        runtime.mark_unhealthy(
            Some(first.generation),
            "injected_expired_retired_generation",
        );
        assert!(readiness.is_ready());
        assert!(subscription.is_current(second.generation));

        drop(first);
        drop(second);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn monotonic_generation_expiry_closes_admission_despite_current_wall_validity() {
        let directory = trusted_tempdir();
        let identity = TestTlsIdentity::new("localhost");
        let (certificate, private_key) = write_identity(directory.path(), &identity);
        let listeners = listeners(&certificate, &private_key);
        let readiness = Arc::new(ServiceReadiness::new());
        readiness.mark_ready_for_test();
        let runtime = AccessFlowSecurityMaterialRuntime::activate(&listeners, readiness.clone())
            .await
            .unwrap();
        let current = match runtime.state.borrow().clone() {
            AccessFlowSecurityState::Healthy(current) => current,
            AccessFlowSecurityState::Unhealthy(_) | AccessFlowSecurityState::Closed => {
                panic!("initial security material is not healthy")
            }
        };
        let now = unix_time_seconds();
        let routes = current
            .routes
            .iter()
            .map(|(id, route)| {
                let mut route = route.clone();
                route.validity = AccessFlowTlsIdentityValidity {
                    not_before_unix_seconds: now.saturating_sub(2),
                    not_after_unix_seconds: now.saturating_add(60),
                };
                (*id, route)
            })
            .collect();
        runtime
            .state
            .send_replace(AccessFlowSecurityState::Healthy(Arc::new(
                AccessFlowTlsGeneration {
                    id: current.id,
                    routes,
                    expiry_deadline: Some(tokio::time::Instant::now() + Duration::from_millis(20)),
                },
            )));

        tokio::time::timeout(Duration::from_secs(2), async {
            while readiness.is_ready() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("expired Access Flow TLS identity did not close readiness");
        assert!(runtime
            .subscribe()
            .current_tls_route(AccessFlowTlsRouteId::TransparentHttp)
            .is_none());
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn observed_wall_invalidity_latches_generation_unhealthy_and_clears_readiness() {
        let directory = trusted_tempdir();
        let identity = TestTlsIdentity::new("localhost");
        let (certificate, private_key) = write_identity(directory.path(), &identity);
        let listeners = listeners(&certificate, &private_key);
        let readiness = Arc::new(ServiceReadiness::new());
        readiness.mark_ready_for_test();
        let runtime = AccessFlowSecurityMaterialRuntime::activate(&listeners, readiness.clone())
            .await
            .unwrap();
        let original = match runtime.state.borrow().clone() {
            AccessFlowSecurityState::Healthy(current) => current,
            AccessFlowSecurityState::Unhealthy(_) | AccessFlowSecurityState::Closed => {
                panic!("initial security material is not healthy")
            }
        };
        let now = unix_time_seconds();

        for validity in [
            AccessFlowTlsIdentityValidity {
                not_before_unix_seconds: now.saturating_sub(2),
                not_after_unix_seconds: now.saturating_sub(1),
            },
            AccessFlowTlsIdentityValidity {
                not_before_unix_seconds: now.saturating_add(1),
                not_after_unix_seconds: now.saturating_add(60),
            },
        ] {
            let routes = original
                .routes
                .iter()
                .map(|(id, route)| {
                    let mut route = route.clone();
                    route.validity = validity;
                    (*id, route)
                })
                .collect();
            runtime
                .state
                .send_replace(AccessFlowSecurityState::Healthy(Arc::new(
                    AccessFlowTlsGeneration {
                        id: original.id,
                        routes,
                        expiry_deadline: Some(
                            tokio::time::Instant::now() + Duration::from_secs(60),
                        ),
                    },
                )));
            readiness.mark_access_flow_security_healthy();
            assert!(readiness.is_ready());

            assert_eq!(
                runtime.subscribe().admission_state_at(now),
                AccessFlowSecurityAdmissionState::Unhealthy
            );
            assert!(!readiness.is_ready());
            assert!(matches!(
                &*runtime.state.borrow(),
                AccessFlowSecurityState::Unhealthy(current) if current.id == original.id
            ));
        }

        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn idle_wall_invalidity_clears_readiness_without_listener_admission() {
        let directory = trusted_tempdir();
        let identity = TestTlsIdentity::new("localhost");
        let (certificate, private_key) = write_identity(directory.path(), &identity);
        let listeners = listeners(&certificate, &private_key);
        let readiness = Arc::new(ServiceReadiness::new());
        readiness.mark_ready_for_test();
        let runtime = AccessFlowSecurityMaterialRuntime::activate(&listeners, readiness.clone())
            .await
            .unwrap();
        let current = match runtime.state.borrow().clone() {
            AccessFlowSecurityState::Healthy(current) => current,
            AccessFlowSecurityState::Unhealthy(_) | AccessFlowSecurityState::Closed => {
                panic!("initial security material is not healthy")
            }
        };
        let now = unix_time_seconds();
        let routes = current
            .routes
            .iter()
            .map(|(id, route)| {
                let mut route = route.clone();
                route.validity = AccessFlowTlsIdentityValidity {
                    not_before_unix_seconds: now.saturating_sub(2),
                    not_after_unix_seconds: now,
                };
                (*id, route)
            })
            .collect();
        runtime
            .state
            .send_replace(AccessFlowSecurityState::Healthy(Arc::new(
                AccessFlowTlsGeneration {
                    id: current.id,
                    routes,
                    expiry_deadline: Some(tokio::time::Instant::now() + Duration::from_secs(60)),
                },
            )));

        tokio::time::timeout(Duration::from_secs(3), async {
            while readiness.is_ready() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("idle wall-invalid generation did not clear readiness");
        assert!(matches!(
            &*runtime.state.borrow(),
            AccessFlowSecurityState::Unhealthy(generation) if generation.id == current.id
        ));

        runtime.shutdown().await;
    }

    #[test]
    fn publication_pins_expiry_against_later_wall_clock_rollback() {
        let wall_at_publication = UNIX_EPOCH + Duration::from_secs(1_000);
        let monotonic_at_publication = tokio::time::Instant::now();
        let pinned =
            publication_expiry_deadline(1_009, wall_at_publication, monotonic_at_publication)
                .unwrap();
        assert_eq!(
            pinned.duration_since(monotonic_at_publication),
            Duration::from_secs(10)
        );

        let rolled_back_wall = wall_at_publication - Duration::from_secs(100);
        let deadline_if_incorrectly_recomputed =
            publication_expiry_deadline(1_009, rolled_back_wall, monotonic_at_publication).unwrap();
        assert_eq!(
            pinned.duration_since(monotonic_at_publication),
            Duration::from_secs(10),
            "the published generation owns its original monotonic deadline"
        );
        assert_eq!(
            deadline_if_incorrectly_recomputed.duration_since(monotonic_at_publication),
            Duration::from_secs(110),
            "a wall-clock rollback would postpone expiry if the deadline were recomputed"
        );
    }

    #[tokio::test]
    async fn shutdown_is_terminal_when_reload_finishes_after_shutdown_begins() {
        let directory = trusted_tempdir();
        let identity = TestTlsIdentity::new("localhost");
        let (certificate, private_key) = write_identity(directory.path(), &identity);
        let listeners = listeners(&certificate, &private_key);
        let readiness = Arc::new(ServiceReadiness::new());
        readiness.mark_ready_for_test();
        let runtime = AccessFlowSecurityMaterialRuntime::activate(&listeners, readiness.clone())
            .await
            .unwrap();
        let (loaded_send, loaded_receive) = tokio::sync::oneshot::channel();
        let (publish_send, publish_receive) = tokio::sync::oneshot::channel();
        let reload_runtime = Arc::clone(&runtime);
        let reload = tokio::spawn(async move {
            reload_runtime
                .reload_after_load(async move {
                    loaded_send.send(()).unwrap();
                    publish_receive.await.unwrap();
                })
                .await
        });

        loaded_receive.await.unwrap();
        runtime.begin_shutdown();
        publish_send.send(()).unwrap();
        assert_eq!(
            reload.await.unwrap(),
            Err(AccessFlowSecurityMaterialError::ShuttingDown)
        );
        assert!(matches!(
            &*runtime.state.borrow(),
            AccessFlowSecurityState::Closed
        ));
        assert!(runtime
            .subscribe()
            .current_tls_route(AccessFlowTlsRouteId::TransparentHttp)
            .is_none());
        runtime.mark_unhealthy(None, "injected_post_shutdown_failure");
        assert!(matches!(
            &*runtime.state.borrow(),
            AccessFlowSecurityState::Closed
        ));
        runtime.shutdown().await;
    }
}
