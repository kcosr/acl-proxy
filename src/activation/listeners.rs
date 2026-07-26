use std::collections::{HashMap, HashSet};
#[cfg(unix)]
use std::fs::{File, OpenOptions};
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::UnixListener;
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use access_flow::{AccessFlowAcceptor, AccessFlowPresentationMode};
use access_flow_unix::UnixAccessFlowListenerAdapter;
use http_access_runtime::{
    ForwardingCancellation, Http1ConnectPolicy, HttpAccessFlowService, ListenerConfig,
    ListenerIdentityMode, ListenerLimits, ListenerMode, ListenerRuntime, LocalAddressProvider,
    OriginalDestinationProvider, PreboundListener, PreboundListenerBundle,
    PreboundListenerEndpoint, RuntimeError as SharedRuntimeError,
};
use http_access_types::{HttpProtocol, HttpProtocolSet};

use crate::config::compiler::{
    unix_listener_lock_path, CompiledHttp1ConnectPolicy, CompiledHttpVersion,
    CompiledListenerIdentityMode, StaticAccessFlowTransport, StaticCleartextListener,
    StaticExplicitHttpsListener, StaticListenerEndpoint, StaticListenersConfig,
    StaticTransparentHttpsListener,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProxyListenerKind {
    ExplicitHttp,
    TransparentHttp,
    ExplicitHttps,
    TransparentHttps,
    LocalAddressRefresh,
}

impl ProxyListenerKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitHttp => "explicit_http",
            Self::TransparentHttp => "transparent_http",
            Self::ExplicitHttps => "explicit_https",
            Self::TransparentHttps => "transparent_https",
            Self::LocalAddressRefresh => "local_address_refresh",
        }
    }

    pub(crate) fn from_shared(mode: ListenerMode) -> Self {
        match mode {
            ListenerMode::ExplicitHttp => Self::ExplicitHttp,
            ListenerMode::TransparentHttp => Self::TransparentHttp,
            ListenerMode::ExplicitHttps => Self::ExplicitHttps,
            ListenerMode::TransparentHttps => Self::TransparentHttps,
        }
    }
}

impl std::fmt::Display for ProxyListenerKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{listener} proxy listener failed: {message}")]
pub(crate) struct ProxyListenerFailure {
    pub(crate) listener: ProxyListenerKind,
    pub(crate) message: String,
}

pub(super) trait LocalAddressRefreshFailureObserver: Send + Sync {
    fn failed(&self, error: Arc<ProxyListenerFailure>);
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum ProxyListenerConfig {
    ExplicitHttp(Box<StaticCleartextListener>),
    TransparentHttp(Box<StaticCleartextListener>),
    ExplicitHttps(Box<StaticExplicitHttpsListener>),
    TransparentHttps(Box<StaticTransparentHttpsListener>),
}

impl ProxyListenerConfig {
    pub(crate) fn kind(&self) -> ProxyListenerKind {
        match self {
            Self::ExplicitHttp(_) => ProxyListenerKind::ExplicitHttp,
            Self::TransparentHttp(_) => ProxyListenerKind::TransparentHttp,
            Self::ExplicitHttps(_) => ProxyListenerKind::ExplicitHttps,
            Self::TransparentHttps(_) => ProxyListenerKind::TransparentHttps,
        }
    }

    fn endpoint(&self) -> &StaticListenerEndpoint {
        match self {
            Self::ExplicitHttp(config) | Self::TransparentHttp(config) => &config.endpoint,
            Self::ExplicitHttps(config) => &config.endpoint,
            Self::TransparentHttps(config) => &config.endpoint,
        }
    }
}

pub(crate) struct PreparedProxyListener {
    pub(crate) config: ProxyListenerConfig,
    endpoint: PreparedListenerEndpoint,
}

enum PreparedListenerEndpoint {
    Tcp(TcpListener),
    #[cfg(unix)]
    AccessFlow {
        listener: UnixListener,
        lifetime: Arc<UnixSocketLifetime>,
        admission_timeout: Duration,
        allowed_destination_ports: Vec<u16>,
    },
}

#[cfg(unix)]
pub(super) struct UnixSocketLifetime {
    _lock: File,
}

#[cfg(not(unix))]
pub(super) struct UnixSocketLifetime;

#[derive(Default)]
pub(super) struct PreparedProxyListeners {
    pub(super) explicit_http: Option<PreparedProxyListener>,
    pub(super) transparent_http: Option<PreparedProxyListener>,
    pub(super) explicit_https: Option<PreparedProxyListener>,
    pub(super) transparent_https: Option<PreparedProxyListener>,
}

pub(super) struct PreparedListenerRuntimeInputs {
    pub(super) tcp: Option<PreboundListenerBundle>,
    pub(super) access_flow: Vec<PreparedAccessFlowListener>,
    pub(super) unix_socket_lifetimes: Vec<Arc<UnixSocketLifetime>>,
}

impl PreparedProxyListeners {
    pub(super) fn bind(
        config: &StaticListenersConfig,
        mut bind: impl FnMut(SocketAddr) -> io::Result<TcpListener>,
    ) -> Result<Self, ProxyListenerBindError> {
        let explicit_http = bind_configured(
            config
                .explicit_http
                .clone()
                .map(Box::new)
                .map(ProxyListenerConfig::ExplicitHttp),
            &mut bind,
        )?;
        let transparent_http = bind_configured(
            config
                .transparent_http
                .clone()
                .map(Box::new)
                .map(ProxyListenerConfig::TransparentHttp),
            &mut bind,
        )?;
        let explicit_https = bind_configured(
            config
                .explicit_https
                .clone()
                .map(Box::new)
                .map(ProxyListenerConfig::ExplicitHttps),
            &mut bind,
        )?;
        let transparent_https = bind_configured(
            config
                .transparent_https
                .clone()
                .map(Box::new)
                .map(ProxyListenerConfig::TransparentHttps),
            &mut bind,
        )?;

        Ok(Self {
            explicit_http,
            transparent_http,
            explicit_https,
            transparent_https,
        })
    }

    pub(super) fn into_entries(self) -> Vec<PreparedProxyListener> {
        [
            self.explicit_http,
            self.transparent_http,
            self.explicit_https,
            self.transparent_https,
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    pub(super) fn into_runtime_inputs_with_transparent_support(
        self,
        transparent_supported: bool,
    ) -> Result<PreparedListenerRuntimeInputs, SharedRuntimeError> {
        if !transparent_supported
            && [
                self.transparent_http.as_ref(),
                self.transparent_https.as_ref(),
            ]
            .into_iter()
            .flatten()
            .any(|listener| {
                matches!(
                    listener.config.endpoint(),
                    StaticListenerEndpoint::Tcp { .. }
                )
            })
        {
            return Err(SharedRuntimeError::InvalidInput);
        }
        let mut tcp = Vec::new();
        let mut access_flow = Vec::new();
        let mut lifetimes = Vec::new();
        for listener in self.into_entries() {
            match listener.into_runtime_input()? {
                PreparedRuntimeInput::Tcp(listener) => tcp.push(listener),
                PreparedRuntimeInput::AccessFlow(listener, lifetime) => {
                    access_flow.push(listener);
                    lifetimes.push(lifetime);
                }
            }
        }
        let tcp = if tcp.is_empty() {
            None
        } else {
            Some(PreboundListenerBundle::new(tcp)?)
        };
        Ok(PreparedListenerRuntimeInputs {
            tcp,
            access_flow,
            unix_socket_lifetimes: lifetimes,
        })
    }
}

impl PreparedProxyListener {
    fn into_runtime_input(self) -> Result<PreparedRuntimeInput, SharedRuntimeError> {
        let kind = self.config.kind();
        let config = match self.config {
            ProxyListenerConfig::ExplicitHttp(config) => ListenerConfig::explicit_http(
                protocol_set(&config.http_versions)?,
                connect_policy(config.connect.as_ref().and_then(|connect| connect.http1)),
                listener_identity_mode(config.identity_mode),
                listener_limits(
                    config.max_connections,
                    config.max_concurrent_streams,
                    config.request_header_timeout,
                )?,
            )?,
            ProxyListenerConfig::TransparentHttp(config) => ListenerConfig::transparent_http(
                protocol_set(&config.http_versions)?,
                listener_identity_mode(config.identity_mode),
                listener_limits(
                    config.max_connections,
                    config.max_concurrent_streams,
                    config.request_header_timeout,
                )?,
            )?,
            ProxyListenerConfig::ExplicitHttps(config) => ListenerConfig::explicit_https(
                protocol_set(&config.http_versions)?,
                connect_policy(config.connect.http1),
                listener_identity_mode(config.identity_mode),
                config.handshake_timeout,
                listener_limits(
                    config.max_connections,
                    config.max_concurrent_streams,
                    config.request_header_timeout,
                )?,
            )?,
            ProxyListenerConfig::TransparentHttps(config) => ListenerConfig::transparent_https(
                protocol_set(&config.http_versions)?,
                listener_identity_mode(config.identity_mode),
                config.handshake_timeout,
                listener_limits(
                    config.max_connections,
                    config.max_concurrent_streams,
                    config.request_header_timeout,
                )?,
            )?,
        };
        match self.endpoint {
            PreparedListenerEndpoint::Tcp(listener) => Ok(PreparedRuntimeInput::Tcp(
                PreboundListener::new(config, PreboundListenerEndpoint::Tcp(listener))?,
            )),
            #[cfg(unix)]
            PreparedListenerEndpoint::AccessFlow {
                listener,
                lifetime,
                admission_timeout,
                allowed_destination_ports,
            } => {
                listener
                    .set_nonblocking(true)
                    .map_err(|_| SharedRuntimeError::InvalidInput)?;
                let listener = tokio::net::UnixListener::from_std(listener)
                    .map_err(|_| SharedRuntimeError::InvalidInput)?;
                let ports = allowed_destination_ports
                    .into_iter()
                    .map(|port| {
                        std::num::NonZeroU16::new(port).ok_or(SharedRuntimeError::InvalidInput)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let acceptor = AccessFlowAcceptor::new(
                    access_flow_presentation_mode(config.identity_mode()),
                    ports,
                )
                .map_err(|_| SharedRuntimeError::InvalidInput)?;
                let adapter =
                    UnixAccessFlowListenerAdapter::from_prebound(listener, admission_timeout)
                        .map_err(|_| SharedRuntimeError::InvalidInput)?;
                Ok(PreparedRuntimeInput::AccessFlow(
                    PreparedAccessFlowListener {
                        kind,
                        config,
                        adapter,
                        acceptor,
                    },
                    lifetime,
                ))
            }
        }
    }

    #[cfg(test)]
    fn into_shared(self) -> Result<PreboundListener, SharedRuntimeError> {
        match self.into_runtime_input()? {
            PreparedRuntimeInput::Tcp(listener) => Ok(listener),
            PreparedRuntimeInput::AccessFlow(..) => Err(SharedRuntimeError::InvalidInput),
        }
    }
}

enum PreparedRuntimeInput {
    Tcp(PreboundListener),
    AccessFlow(PreparedAccessFlowListener, Arc<UnixSocketLifetime>),
}

pub(super) struct PreparedAccessFlowListener {
    kind: ProxyListenerKind,
    config: ListenerConfig,
    adapter: UnixAccessFlowListenerAdapter,
    acceptor: AccessFlowAcceptor,
}

struct AccessFlowAdmissionLatch {
    open: std::sync::atomic::AtomicUsize,
    closed: tokio::sync::Notify,
}

impl AccessFlowAdmissionLatch {
    fn new(listeners: usize) -> Self {
        Self {
            open: std::sync::atomic::AtomicUsize::new(listeners),
            closed: tokio::sync::Notify::new(),
        }
    }

    fn close_one(&self) {
        if self.open.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.closed.notify_waiters();
        }
    }

    async fn wait_closed(&self) {
        loop {
            let notified = self.closed.notified();
            if self.open.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

struct AccessFlowAdmissionGuard(Arc<AccessFlowAdmissionLatch>);

impl Drop for AccessFlowAdmissionGuard {
    fn drop(&mut self) {
        self.0.close_one();
    }
}

pub(super) struct AccessFlowListenerRuntime {
    admission: ForwardingCancellation,
    force: ForwardingCancellation,
    admission_latch: Arc<AccessFlowAdmissionLatch>,
    supervisor: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl AccessFlowListenerRuntime {
    pub(super) fn start(
        listeners: Vec<PreparedAccessFlowListener>,
        service: HttpAccessFlowService,
        identity_admission: Arc<crate::identity::IdentityPublisher>,
        failure_observer: Arc<dyn Fn(Arc<ProxyListenerFailure>) + Send + Sync>,
    ) -> Option<Self> {
        if listeners.is_empty() {
            return None;
        }
        let admission = ForwardingCancellation::new();
        let force = ForwardingCancellation::new();
        let admission_latch = Arc::new(AccessFlowAdmissionLatch::new(listeners.len()));
        let supervisor_admission = admission.clone();
        let supervisor_force = force.clone();
        let supervisor_latch = Arc::clone(&admission_latch);
        let supervisor = tokio::spawn(async move {
            let mut routes = tokio::task::JoinSet::new();
            let mut route_kinds = HashMap::new();
            for listener in listeners {
                let kind = listener.kind;
                let task = routes.spawn(run_access_flow_listener(
                    listener,
                    service.clone(),
                    Arc::clone(&identity_admission),
                    supervisor_admission.clone(),
                    supervisor_force.clone(),
                    AccessFlowAdmissionGuard(Arc::clone(&supervisor_latch)),
                ));
                route_kinds.insert(task.id(), kind);
            }

            tokio::select! {
                biased;
                _ = supervisor_admission.cancelled() => {}
                result = routes.join_next_with_id() => {
                    let failure = access_flow_route_failure(
                        result.expect("the Access Flow route set is nonempty"),
                        &mut route_kinds,
                    );
                    failure_observer(failure);
                    supervisor_admission.cancel();
                    supervisor_force.cancel();
                }
            }
            while let Some(result) = routes.join_next().await {
                if let Ok(Err(failure)) = result {
                    tracing::error!(error = %failure, "Access Flow listener failed during shutdown");
                }
            }
        });
        Some(Self {
            admission,
            force,
            admission_latch,
            supervisor: std::sync::Mutex::new(Some(supervisor)),
        })
    }

    pub(super) fn begin_shutdown(&self) {
        self.admission.cancel();
    }

    pub(super) async fn stop_admission_and_wait_closed(&self) {
        self.begin_shutdown();
        self.admission_latch.wait_closed().await;
    }

    pub(super) async fn shutdown_and_wait(&self, deadline: Option<std::time::Instant>) {
        self.begin_shutdown();
        let supervisor = self
            .supervisor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let Some(mut supervisor) = supervisor else {
            return;
        };
        if let Some(deadline) = deadline {
            if tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), &mut supervisor)
                .await
                .is_err()
            {
                self.force.cancel();
                let _ = supervisor.await;
            }
        } else {
            let _ = supervisor.await;
        }
    }
}

impl Drop for AccessFlowListenerRuntime {
    fn drop(&mut self) {
        self.admission.cancel();
        self.force.cancel();
        let supervisor = self
            .supervisor
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(supervisor) = supervisor {
            supervisor.abort();
        }
    }
}

pub(super) struct ProductListenerRuntime {
    shared: Option<Arc<ListenerRuntime>>,
    access_flow: Option<Arc<AccessFlowListenerRuntime>>,
}

impl ProductListenerRuntime {
    pub(super) fn new(
        shared: Option<ListenerRuntime>,
        access_flow: Option<AccessFlowListenerRuntime>,
    ) -> Result<Self, SharedRuntimeError> {
        if shared.is_none() && access_flow.is_none() {
            return Err(SharedRuntimeError::InvalidInput);
        }
        Ok(Self {
            shared: shared.map(Arc::new),
            access_flow: access_flow.map(Arc::new),
        })
    }

    pub(super) fn begin_shutdown(&self) {
        if let Some(shared) = &self.shared {
            shared.begin_shutdown();
        }
        if let Some(access_flow) = &self.access_flow {
            access_flow.begin_shutdown();
        }
    }

    pub(super) async fn stop_admission_and_wait_closed(&self) {
        if let Some(shared) = &self.shared {
            shared.stop_admission_and_wait_closed().await;
        }
        if let Some(access_flow) = &self.access_flow {
            access_flow.stop_admission_and_wait_closed().await;
        }
    }

    pub(super) async fn shutdown_and_wait(&self, deadline: Option<std::time::Instant>) {
        if let Some(shared) = &self.shared {
            shared.shutdown_and_wait(deadline).await;
        }
        if let Some(access_flow) = &self.access_flow {
            access_flow.shutdown_and_wait(deadline).await;
        }
    }
}

type AccessFlowRouteJoinResult = Result<
    (
        tokio::task::Id,
        Result<ProxyListenerKind, Arc<ProxyListenerFailure>>,
    ),
    tokio::task::JoinError,
>;

fn access_flow_route_failure(
    result: AccessFlowRouteJoinResult,
    route_kinds: &mut HashMap<tokio::task::Id, ProxyListenerKind>,
) -> Arc<ProxyListenerFailure> {
    match result {
        Ok((id, Err(failure))) => {
            route_kinds.remove(&id);
            failure
        }
        Err(error) => {
            let kind = route_kinds
                .remove(&error.id())
                .expect("every Access Flow listener task retains its listener kind");
            listener_failure(kind, "Access Flow listener task failed")
        }
        Ok((id, Ok(kind))) => {
            route_kinds.remove(&id);
            listener_failure(kind, "Access Flow listener exited unexpectedly")
        }
    }
}

async fn run_access_flow_listener(
    listener: PreparedAccessFlowListener,
    service: HttpAccessFlowService,
    identity_admission: Arc<crate::identity::IdentityPublisher>,
    admission_cancellation: ForwardingCancellation,
    force_cancellation: ForwardingCancellation,
    admission_guard: AccessFlowAdmissionGuard,
) -> Result<ProxyListenerKind, Arc<ProxyListenerFailure>> {
    let kind = listener.kind;
    let capacity = Arc::new(tokio::sync::Semaphore::new(
        listener.config.limits().max_connections(),
    ));
    let mut connections = tokio::task::JoinSet::new();
    let admission_result: Result<(), Arc<ProxyListenerFailure>> = {
        let _admission_guard = admission_guard;
        let PreparedAccessFlowListener {
            kind: _,
            config,
            adapter,
            acceptor,
        } = listener;
        async {
            loop {
                let permit = tokio::select! {
                    biased;
                    _ = admission_cancellation.cancelled() => break,
                    joined = connections.join_next(), if !connections.is_empty() => {
                        inspect_access_flow_connection(kind, joined, false)?;
                        continue;
                    }
                    permit = Arc::clone(&capacity).acquire_owned() => {
                        permit.map_err(|_| listener_failure(
                            kind,
                            "Access Flow listener capacity closed unexpectedly",
                        ))?
                    }
                };
                let (accepted, permit) = match wait_for_access_flow_accept(
                    &adapter,
                    &admission_cancellation,
                    &mut connections,
                    permit,
                    kind,
                )
                .await
                {
                    Ok(AccessFlowAcceptEvent::Accepted(accepted, permit)) => (accepted, permit),
                    Ok(AccessFlowAcceptEvent::ConnectionCompleted) => continue,
                    Ok(AccessFlowAcceptEvent::Cancelled) => break,
                    Err(failure) => return Err(failure),
                };
                let acceptor = acceptor.clone();
                let service = service.clone();
                let config = config.clone();
                let admission_cancellation = admission_cancellation.clone();
                let connection_cancellation = force_cancellation.clone();
                let identity_admission = Arc::clone(&identity_admission);
                connections.spawn(async move {
                    let _permit = permit;
                    let (channel, deadline) = accepted.into_access_flow();
                    let accepted = match acceptor
                        .accept(
                            channel,
                            deadline,
                            &admission_cancellation,
                            identity_admission.as_ref(),
                        )
                        .await
                    {
                        Ok(accepted) => accepted,
                        Err(_error) if admission_cancellation.is_cancelled() => return Ok(()),
                        Err(error) => {
                            tracing::warn!(
                                target: "acl_proxy::traffic",
                                listener = %kind,
                                listener_transport = "access_flow",
                                category = "connection_rejected",
                                error = %error,
                                "proxy listener rejected an Access Flow before HTTP/TLS processing"
                            );
                            return Ok(());
                        }
                    };
                    match service
                        .serve_access_flow(accepted, config, &connection_cancellation)
                        .await
                    {
                        Ok(_) => Ok(()),
                        Err(http_access_runtime::HttpAccessConnectionError::ConnectionRejected) => {
                            tracing::warn!(
                                target: "acl_proxy::traffic",
                                listener = %kind,
                                listener_transport = "access_flow",
                                category = "connection_rejected",
                                "Access Flow HTTP/TLS connection was rejected"
                            );
                            Ok(())
                        }
                        Err(error) => Err(listener_failure(kind, error.to_string())),
                    }
                });
            }
            Ok(())
        }
        .await
    };

    if let Err(failure) = admission_result {
        admission_cancellation.cancel();
        force_cancellation.cancel();
        connections.abort_all();
        let _ = drain_access_flow_connections(kind, &force_cancellation, &mut connections).await;
        return Err(failure);
    }
    if let Err(failure) =
        drain_access_flow_connections(kind, &force_cancellation, &mut connections).await
    {
        force_cancellation.cancel();
        connections.abort_all();
        let _ = drain_access_flow_connections(kind, &force_cancellation, &mut connections).await;
        return Err(failure);
    }
    Ok(kind)
}

enum AccessFlowAcceptEvent {
    Accepted(
        access_flow_unix::AcceptedUnixAccessFlowChannel,
        tokio::sync::OwnedSemaphorePermit,
    ),
    ConnectionCompleted,
    Cancelled,
}

async fn wait_for_access_flow_accept(
    adapter: &UnixAccessFlowListenerAdapter,
    admission_cancellation: &ForwardingCancellation,
    connections: &mut tokio::task::JoinSet<Result<(), Arc<ProxyListenerFailure>>>,
    permit: tokio::sync::OwnedSemaphorePermit,
    kind: ProxyListenerKind,
) -> Result<AccessFlowAcceptEvent, Arc<ProxyListenerFailure>> {
    tokio::select! {
        biased;
        _ = admission_cancellation.cancelled() => {
            drop(permit);
            Ok(AccessFlowAcceptEvent::Cancelled)
        }
        joined = connections.join_next(), if !connections.is_empty() => {
            drop(permit);
            inspect_access_flow_connection(kind, joined, false)?;
            Ok(AccessFlowAcceptEvent::ConnectionCompleted)
        }
        accepted = adapter.accept(admission_cancellation) => match accepted {
            Ok(accepted) => Ok(AccessFlowAcceptEvent::Accepted(accepted, permit)),
            Err(_error) if admission_cancellation.is_cancelled() => {
                drop(permit);
                Ok(AccessFlowAcceptEvent::Cancelled)
            }
            Err(error) => {
                drop(permit);
                Err(listener_failure(kind, error.to_string()))
            }
        }
    }
}

async fn drain_access_flow_connections(
    kind: ProxyListenerKind,
    force_cancellation: &ForwardingCancellation,
    connections: &mut tokio::task::JoinSet<Result<(), Arc<ProxyListenerFailure>>>,
) -> Result<(), Arc<ProxyListenerFailure>> {
    let mut forced = force_cancellation.is_cancelled();
    if forced {
        connections.abort_all();
    }
    while !connections.is_empty() {
        if forced {
            let joined = connections.join_next().await;
            inspect_access_flow_connection(kind, joined, true)?;
            continue;
        }
        tokio::select! {
            biased;
            _ = force_cancellation.cancelled() => {
                forced = true;
                connections.abort_all();
            }
            joined = connections.join_next() => {
                inspect_access_flow_connection(kind, joined, false)?;
            }
        }
    }
    Ok(())
}

fn inspect_access_flow_connection(
    kind: ProxyListenerKind,
    joined: Option<Result<Result<(), Arc<ProxyListenerFailure>>, tokio::task::JoinError>>,
    cancelled_task_is_expected: bool,
) -> Result<(), Arc<ProxyListenerFailure>> {
    match joined {
        Some(Ok(Ok(_))) | None => Ok(()),
        Some(Ok(Err(failure))) => Err(failure),
        Some(Err(error)) if cancelled_task_is_expected && error.is_cancelled() => Ok(()),
        Some(Err(_)) => Err(listener_failure(kind, "Access Flow connection task failed")),
    }
}

fn listener_failure(
    listener: ProxyListenerKind,
    message: impl Into<String>,
) -> Arc<ProxyListenerFailure> {
    Arc::new(ProxyListenerFailure {
        listener,
        message: message.into(),
    })
}

fn protocol_set(versions: &[CompiledHttpVersion]) -> Result<HttpProtocolSet, SharedRuntimeError> {
    HttpProtocolSet::new(
        versions
            .iter()
            .map(|version| match version {
                CompiledHttpVersion::Http1 => HttpProtocol::Http1,
                CompiledHttpVersion::Http2 => HttpProtocol::Http2,
            })
            .collect(),
    )
    .map_err(|_| SharedRuntimeError::InvalidInput)
}

fn connect_policy(policy: Option<CompiledHttp1ConnectPolicy>) -> Http1ConnectPolicy {
    match policy {
        Some(CompiledHttp1ConnectPolicy::Mitm) => Http1ConnectPolicy::Mitm,
        Some(CompiledHttp1ConnectPolicy::Deny) | None => Http1ConnectPolicy::Deny,
    }
}

fn listener_limits(
    max_connections: usize,
    max_concurrent_streams: u32,
    request_header_timeout: std::time::Duration,
) -> Result<ListenerLimits, SharedRuntimeError> {
    ListenerLimits::new(
        max_connections,
        max_concurrent_streams,
        request_header_timeout,
    )
}

fn listener_identity_mode(mode: CompiledListenerIdentityMode) -> ListenerIdentityMode {
    match mode {
        CompiledListenerIdentityMode::Disabled => ListenerIdentityMode::Disabled,
        CompiledListenerIdentityMode::Optional => ListenerIdentityMode::Optional,
        CompiledListenerIdentityMode::Required => ListenerIdentityMode::Required,
    }
}

fn access_flow_presentation_mode(mode: ListenerIdentityMode) -> AccessFlowPresentationMode {
    match mode {
        ListenerIdentityMode::Disabled => AccessFlowPresentationMode::Disabled,
        ListenerIdentityMode::Optional => AccessFlowPresentationMode::Optional,
        ListenerIdentityMode::Required => AccessFlowPresentationMode::Required,
    }
}

#[derive(Default)]
pub(super) struct SystemOriginalDestinationProvider;

impl OriginalDestinationProvider for SystemOriginalDestinationProvider {
    fn original_destination(&self, stream: &TcpStream) -> Result<SocketAddr, SharedRuntimeError> {
        system_original_destination(stream)
    }
}

#[cfg(target_os = "linux")]
fn system_original_destination(stream: &TcpStream) -> Result<SocketAddr, SharedRuntimeError> {
    let local = stream
        .local_addr()
        .map_err(|_| SharedRuntimeError::ServiceFailure)?;
    let destination = match local {
        SocketAddr::V4(_) => socket2::SockRef::from(stream)
            .original_dst_v4()
            .map(|address| address.as_socket()),
        SocketAddr::V6(_) => socket2::SockRef::from(stream)
            .original_dst_v6()
            .map(|address| address.as_socket()),
    }
    .map_err(|_| SharedRuntimeError::ServiceFailure)?
    .ok_or(SharedRuntimeError::ServiceFailure)?;
    let destination = crate::network::canonical_socket_addr(destination);
    if destination.port() == 0 {
        return Err(SharedRuntimeError::InvalidInput);
    }
    Ok(destination)
}

#[cfg(not(target_os = "linux"))]
fn system_original_destination(_stream: &TcpStream) -> Result<SocketAddr, SharedRuntimeError> {
    Err(SharedRuntimeError::ServiceFailure)
}

pub(super) struct ProductLocalAddressRuntime {
    provider: Arc<SystemLocalAddressProvider>,
    shutdown_requested: Arc<AtomicBool>,
    stop: tokio::sync::watch::Sender<bool>,
    supervisor: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ProductLocalAddressRuntime {
    pub(super) async fn activate(
        failure_observer: Arc<dyn LocalAddressRefreshFailureObserver>,
    ) -> Result<Arc<Self>, SharedRuntimeError> {
        Self::activate_with(
            Arc::new(SystemLocalAddressSnapshotSource),
            Duration::from_secs(1),
            failure_observer,
        )
        .await
    }

    async fn activate_with(
        source: Arc<dyn LocalAddressSnapshotSource>,
        refresh_interval: Duration,
        failure_observer: Arc<dyn LocalAddressRefreshFailureObserver>,
    ) -> Result<Arc<Self>, SharedRuntimeError> {
        let handle =
            tokio::runtime::Handle::try_current().map_err(|_| SharedRuntimeError::InvalidInput)?;
        let initial_source = Arc::clone(&source);
        let initial_snapshot = tokio::task::spawn_blocking(move || initial_source.snapshot())
            .await
            .map_err(|_| SharedRuntimeError::ServiceFailure)??;
        let provider = SystemLocalAddressProvider::from_snapshot(initial_snapshot)?;
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let (stop, stop_receive) = tokio::sync::watch::channel(false);
        let worker_provider = Arc::clone(&provider);
        let worker = handle.spawn(refresh_local_addresses(
            worker_provider,
            source,
            refresh_interval,
            stop_receive,
        ));
        let supervisor_shutdown = Arc::clone(&shutdown_requested);
        let supervisor = handle.spawn(async move {
            let failure = match worker.await {
                Ok(Ok(())) if supervisor_shutdown.load(Ordering::Acquire) => None,
                Ok(Ok(())) => Some("local-address refresh worker stopped unexpectedly"),
                Ok(Err(())) => Some("local-address refresh worker failed"),
                Err(_) => Some("local-address refresh worker panicked"),
            };
            if let Some(message) = failure {
                failure_observer.failed(Arc::new(ProxyListenerFailure {
                    listener: ProxyListenerKind::LocalAddressRefresh,
                    message: message.to_string(),
                }));
            }
        });
        Ok(Arc::new(Self {
            provider,
            shutdown_requested,
            stop,
            supervisor: tokio::sync::Mutex::new(Some(supervisor)),
        }))
    }

    pub(super) fn provider(&self) -> Arc<SystemLocalAddressProvider> {
        Arc::clone(&self.provider)
    }

    pub(super) fn begin_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::Release);
        self.stop.send_replace(true);
    }

    #[cfg(test)]
    fn stop_without_shutdown_for_test(&self) {
        self.stop.send_replace(true);
    }

    pub(super) async fn shutdown_and_join(&self) {
        self.begin_shutdown();
        let mut supervisor = self.supervisor.lock().await;
        if let Some(task) = supervisor.as_mut() {
            let _ = task.await;
        }
        *supervisor = None;
    }
}

pub(super) struct SystemLocalAddressProvider {
    addresses: RwLock<HashSet<IpAddr>>,
}

impl SystemLocalAddressProvider {
    fn from_snapshot(addresses: HashSet<IpAddr>) -> Result<Arc<Self>, SharedRuntimeError> {
        if addresses.is_empty() {
            return Err(SharedRuntimeError::ServiceFailure);
        }
        Ok(Arc::new(Self {
            addresses: RwLock::new(addresses),
        }))
    }

    fn replace(&self, addresses: HashSet<IpAddr>) -> Result<(), SharedRuntimeError> {
        if addresses.is_empty() {
            return Err(SharedRuntimeError::ServiceFailure);
        }
        *self
            .addresses
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = addresses;
        Ok(())
    }
}

impl LocalAddressProvider for SystemLocalAddressProvider {
    fn is_local_address(&self, address: IpAddr) -> Result<bool, SharedRuntimeError> {
        let address = crate::network::canonical_ip(address);
        Ok(address.is_loopback()
            || self
                .addresses
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains(&address))
    }
}

trait LocalAddressSnapshotSource: Send + Sync {
    fn snapshot(&self) -> Result<HashSet<IpAddr>, SharedRuntimeError>;
}

struct SystemLocalAddressSnapshotSource;

impl LocalAddressSnapshotSource for SystemLocalAddressSnapshotSource {
    fn snapshot(&self) -> Result<HashSet<IpAddr>, SharedRuntimeError> {
        let interfaces =
            if_addrs::get_if_addrs().map_err(|_| SharedRuntimeError::ServiceFailure)?;
        let mut addresses = HashSet::new();
        addresses
            .try_reserve(interfaces.len())
            .map_err(|_| SharedRuntimeError::LimitExceeded)?;
        addresses.extend(
            interfaces
                .into_iter()
                .map(|interface| crate::network::canonical_ip(interface.ip())),
        );
        Ok(addresses)
    }
}

async fn refresh_local_addresses(
    provider: Arc<SystemLocalAddressProvider>,
    source: Arc<dyn LocalAddressSnapshotSource>,
    refresh_interval: Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), ()> {
    loop {
        tokio::select! {
            biased;
            changed = stop.changed() => {
                return if changed.is_ok() && *stop.borrow() { Ok(()) } else { Err(()) };
            }
            _ = tokio::time::sleep(refresh_interval) => {}
        }
        let refresh_source = Arc::clone(&source);
        let snapshot = tokio::task::spawn_blocking(move || refresh_source.snapshot())
            .await
            .map_err(|_| ())?;
        if *stop.borrow() {
            return Ok(());
        }
        match snapshot {
            Ok(addresses) => {
                if provider.replace(addresses).is_err() {
                    tracing::warn!("local-address refresh returned an empty snapshot");
                }
            }
            Err(error) => {
                tracing::warn!(%error, "cannot refresh local-address snapshot");
            }
        }
    }
}

fn bind_configured(
    config: Option<ProxyListenerConfig>,
    bind: &mut impl FnMut(SocketAddr) -> io::Result<TcpListener>,
) -> Result<Option<PreparedProxyListener>, ProxyListenerBindError> {
    config
        .map(|config| {
            let name = config.kind().as_str();
            let endpoint = match config.endpoint() {
                StaticListenerEndpoint::Tcp { address } => bind(*address)
                    .map(PreparedListenerEndpoint::Tcp)
                    .map_err(|source| ProxyListenerBindError {
                        name,
                        endpoint: address.to_string(),
                        address: Some(*address),
                        source,
                    })?,
                StaticListenerEndpoint::AccessFlow {
                    admission_timeout,
                    allowed_destination_ports,
                    transport: StaticAccessFlowTransport::Unix { path, mode },
                } => bind_access_flow_unix(
                    path,
                    *mode,
                    *admission_timeout,
                    allowed_destination_ports.clone(),
                )
                .map_err(|source| ProxyListenerBindError {
                    name,
                    endpoint: path.display().to_string(),
                    address: None,
                    source,
                })?,
            };
            Ok(PreparedProxyListener { config, endpoint })
        })
        .transpose()
}

#[cfg(unix)]
fn bind_access_flow_unix(
    path: &Path,
    mode: u32,
    admission_timeout: Duration,
    allowed_destination_ports: Vec<u16>,
) -> io::Result<PreparedListenerEndpoint> {
    use fs2::FileExt;

    let effective_uid = rustix::process::geteuid().as_raw();
    validate_private_unix_parent(path, effective_uid)?;

    let lock_path = unix_listener_lock_path(path);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)?;
    let lock_metadata = lock.metadata()?;
    if !lock_metadata.file_type().is_file() || lock_metadata.uid() != effective_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unix proxy listener lock must be a regular file owned by the current user",
        ));
    }
    lock.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    lock.try_lock_exclusive().map_err(|error| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("Unix proxy listener lock is held: {error}"),
        )
    })?;

    reject_preexisting_unix_socket(path, effective_uid, probe_existing_unix_socket)?;

    let (listener, private_path) = bind_private_unix_socket(path)?;
    if let Err(error) =
        std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(mode))
    {
        let _ = std::fs::remove_file(&private_path);
        return Err(error);
    }
    let private_metadata = std::fs::symlink_metadata(&private_path)?;
    if let Err(error) = verify_staged_unix_socket(&private_metadata, effective_uid, mode) {
        let _ = std::fs::remove_file(&private_path);
        return Err(error);
    }
    if let Err(error) = publish_unix_socket_noreplace(&private_path, path) {
        let _ = std::fs::remove_file(&private_path);
        return Err(error);
    }

    let lifetime = Arc::new(UnixSocketLifetime { _lock: lock });
    Ok(PreparedListenerEndpoint::AccessFlow {
        listener,
        lifetime,
        admission_timeout,
        allowed_destination_ports,
    })
}

#[cfg(unix)]
fn verify_staged_unix_socket(
    metadata: &std::fs::Metadata,
    effective_uid: u32,
    mode: u32,
) -> io::Result<()> {
    if metadata.file_type().is_socket()
        && metadata.uid() == effective_uid
        && metadata.permissions().mode() & 0o777 == mode
    {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Unix proxy listener staging socket mode or ownership verification failed",
    ))
}

#[cfg(unix)]
fn validate_private_unix_parent(path: &Path, effective_uid: u32) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unix proxy listener path has no parent directory",
        )
    })?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unix proxy listener parent must be a directory owned by the current user with no group or other permissions",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn bind_private_unix_socket(final_path: &Path) -> io::Result<(UnixListener, PathBuf)> {
    use rand::RngCore;

    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const MAX_ATTEMPTS: usize = 128;

    let parent = final_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unix proxy listener path has no parent directory",
        )
    })?;
    let name_length = final_path
        .file_name()
        .map(OsStrExt::as_bytes)
        .map(<[u8]>::len)
        .filter(|length| *length > 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unix proxy listener path has no file name",
            )
        })?;

    let mut random = vec![0_u8; name_length];
    for _ in 0..MAX_ATTEMPTS {
        rand::rngs::OsRng.fill_bytes(&mut random);
        let mut name = random
            .iter()
            .map(|value| ALPHABET[usize::from(*value) % ALPHABET.len()])
            .collect::<Vec<_>>();
        if name.len() > 1 {
            name[0] = b'.';
        }
        let private_path = parent.join(std::ffi::OsString::from_vec(name));
        if private_path == final_path {
            continue;
        }
        match UnixListener::bind(&private_path) {
            Ok(listener) => return Ok((listener, private_path)),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::AlreadyExists
                ) => {}
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "could not reserve a private Unix proxy listener staging path",
    ))
}

#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "redox"
))]
fn publish_unix_socket_noreplace(private_path: &Path, final_path: &Path) -> io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        private_path,
        rustix::fs::CWD,
        final_path,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        let error = io::Error::from_raw_os_error(error.raw_os_error());
        if error.kind() == io::ErrorKind::AlreadyExists {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                "Unix proxy listener path became occupied before publication",
            )
        } else {
            error
        }
    })
}

#[cfg(all(
    unix,
    not(any(
        target_os = "android",
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "redox"
    ))
))]
fn publish_unix_socket_noreplace(_private_path: &Path, _final_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "this Unix platform has no supported atomic no-replace socket publication primitive",
    ))
}

#[cfg(unix)]
fn reject_preexisting_unix_socket(
    path: &Path,
    effective_uid: u32,
    probe: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    validate_owned_socket(&metadata, effective_uid)?;

    match probe(path) {
        Ok(()) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "Unix proxy listener socket is live",
        )),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "Unix proxy listener socket is stale; remove it explicitly before startup",
        )),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) || matches!(
                error.raw_os_error(),
                Some(libc::EINPROGRESS) | Some(libc::EAGAIN)
            ) =>
        {
            Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "Unix proxy listener socket is live or its accept backlog is unavailable",
            ))
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn probe_existing_unix_socket(path: &Path) -> io::Result<()> {
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    let address = socket2::SockAddr::unix(path)?;
    socket.connect_timeout(&address, Duration::from_millis(100))
}

#[cfg(unix)]
fn validate_owned_socket(metadata: &std::fs::Metadata, effective_uid: u32) -> io::Result<()> {
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Unix proxy listener path exists and is not a socket",
        ));
    }
    if metadata.uid() != effective_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unix proxy listener socket is not owned by the current user",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn bind_access_flow_unix(
    _path: &std::path::Path,
    _mode: u32,
    _admission_timeout: Duration,
    _allowed_destination_ports: Vec<u16>,
) -> io::Result<PreparedListenerEndpoint> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Unix proxy listeners are not supported on this platform",
    ))
}

#[derive(Debug, thiserror::Error)]
#[error("failed to bind {name} proxy listener {endpoint}: {source}")]
pub(crate) struct ProxyListenerBindError {
    pub(crate) name: &'static str,
    pub(crate) endpoint: String,
    pub(crate) address: Option<SocketAddr>,
    #[source]
    pub(crate) source: io::Error,
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    use super::*;
    use crate::config::compiler::{
        CompiledHttp1ConnectPolicy, CompiledHttpVersion, CompiledTlsIdentity, StaticConnectPolicy,
    };

    fn prebound_listeners<const N: usize>() -> [TcpListener; N] {
        (0..N)
            .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap()
    }

    fn transparent_http_listener(listener: TcpListener) -> PreparedProxyListener {
        let address = listener.local_addr().unwrap();
        PreparedProxyListener {
            config: ProxyListenerConfig::TransparentHttp(Box::new(StaticCleartextListener {
                endpoint: StaticListenerEndpoint::Tcp { address },
                http_versions: vec![CompiledHttpVersion::Http1],
                request_header_timeout: Duration::from_secs(1),
                max_connections: 1,
                max_concurrent_streams: 1,
                identity_mode: CompiledListenerIdentityMode::Disabled,
                connect: None,
            })),
            endpoint: PreparedListenerEndpoint::Tcp(listener),
        }
    }

    enum SnapshotBehavior {
        Addresses(HashSet<IpAddr>),
        Error,
        Panic,
        Block(Arc<(Mutex<bool>, Condvar)>),
    }

    struct MutableSnapshotSource {
        behavior: Mutex<SnapshotBehavior>,
        calls: AtomicUsize,
        called: tokio::sync::Notify,
    }

    impl MutableSnapshotSource {
        fn new(addresses: impl IntoIterator<Item = IpAddr>) -> Arc<Self> {
            Arc::new(Self {
                behavior: Mutex::new(SnapshotBehavior::Addresses(addresses.into_iter().collect())),
                calls: AtomicUsize::new(0),
                called: tokio::sync::Notify::new(),
            })
        }

        fn set(&self, behavior: SnapshotBehavior) {
            *self
                .behavior
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = behavior;
        }

        async fn wait_for_call_after(&self, prior_calls: usize) {
            tokio::time::timeout(Duration::from_secs(1), async {
                while self.calls.load(Ordering::Acquire) <= prior_calls {
                    self.called.notified().await;
                }
            })
            .await
            .expect("local-address source was not called");
        }
    }

    impl LocalAddressSnapshotSource for MutableSnapshotSource {
        fn snapshot(&self) -> Result<HashSet<IpAddr>, SharedRuntimeError> {
            let behavior = {
                let behavior = self
                    .behavior
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match &*behavior {
                    SnapshotBehavior::Addresses(addresses) => {
                        SnapshotBehavior::Addresses(addresses.clone())
                    }
                    SnapshotBehavior::Error => SnapshotBehavior::Error,
                    SnapshotBehavior::Panic => SnapshotBehavior::Panic,
                    SnapshotBehavior::Block(gate) => SnapshotBehavior::Block(Arc::clone(gate)),
                }
            };
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.called.notify_waiters();
            match behavior {
                SnapshotBehavior::Addresses(addresses) => Ok(addresses),
                SnapshotBehavior::Error => Err(SharedRuntimeError::ServiceFailure),
                SnapshotBehavior::Panic => panic!("injected local-address source panic"),
                SnapshotBehavior::Block(gate) => {
                    let (open, changed) = &*gate;
                    let mut open = open.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    while !*open {
                        open = changed
                            .wait(open)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                    Err(SharedRuntimeError::ServiceFailure)
                }
            }
        }
    }

    #[derive(Default)]
    struct RecordingRefreshObserver {
        failures: Mutex<VecDeque<Arc<ProxyListenerFailure>>>,
        failed: tokio::sync::Notify,
    }

    impl LocalAddressRefreshFailureObserver for RecordingRefreshObserver {
        fn failed(&self, error: Arc<ProxyListenerFailure>) {
            self.failures
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push_back(error);
            self.failed.notify_waiters();
        }
    }

    impl RecordingRefreshObserver {
        async fn next_failure(&self) -> Arc<ProxyListenerFailure> {
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    let notified = self.failed.notified();
                    if let Some(failure) = self
                        .failures
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .pop_front()
                    {
                        return failure;
                    }
                    notified.await;
                }
            })
            .await
            .expect("local-address failure was not reported")
        }
    }

    #[test]
    fn prepared_entries_retain_each_exact_compiled_listener_config() {
        let listeners = prebound_listeners::<4>();
        let addresses: [SocketAddr; 4] =
            std::array::from_fn(|index| listeners[index].local_addr().unwrap());
        let cleartext_connect = StaticConnectPolicy {
            http1: Some(CompiledHttp1ConnectPolicy::Deny),
            http2_denied: true,
        };
        let config = StaticListenersConfig {
            explicit_http: Some(StaticCleartextListener {
                endpoint: StaticListenerEndpoint::Tcp {
                    address: addresses[0],
                },
                http_versions: vec![CompiledHttpVersion::Http1, CompiledHttpVersion::Http2],
                request_header_timeout: Duration::from_secs(5),
                max_connections: 17,
                max_concurrent_streams: 19,
                identity_mode: CompiledListenerIdentityMode::Disabled,
                connect: Some(cleartext_connect.clone()),
            }),
            transparent_http: Some(StaticCleartextListener {
                endpoint: StaticListenerEndpoint::Tcp {
                    address: addresses[1],
                },
                http_versions: vec![CompiledHttpVersion::Http1],
                request_header_timeout: Duration::from_secs(7),
                max_connections: 23,
                max_concurrent_streams: 29,
                identity_mode: CompiledListenerIdentityMode::Disabled,
                connect: None,
            }),
            explicit_https: Some(StaticExplicitHttpsListener {
                endpoint: StaticListenerEndpoint::Tcp {
                    address: addresses[2],
                },
                http_versions: vec![CompiledHttpVersion::Http2],
                handshake_timeout: Duration::from_secs(3),
                request_header_timeout: Duration::from_secs(5),
                max_connections: 17,
                max_concurrent_streams: 19,
                identity_mode: CompiledListenerIdentityMode::Disabled,
                connect: cleartext_connect,
                tls: CompiledTlsIdentity {
                    certificate_chain: PathBuf::from("server.pem"),
                    private_key: PathBuf::from("server-key.pem"),
                },
            }),
            transparent_https: Some(StaticTransparentHttpsListener {
                endpoint: StaticListenerEndpoint::Tcp {
                    address: addresses[3],
                },
                http_versions: vec![CompiledHttpVersion::Http1],
                handshake_timeout: Duration::from_secs(7),
                request_header_timeout: Duration::from_secs(11),
                max_connections: 23,
                max_concurrent_streams: 29,
                identity_mode: CompiledListenerIdentityMode::Disabled,
            }),
        };

        let mut listeners = listeners.into_iter();
        let entries = PreparedProxyListeners::bind(&config, |_| {
            Ok(listeners.next().expect("one prebound listener per config"))
        })
        .unwrap()
        .into_entries();
        assert_eq!(entries.len(), 4);
        for (index, entry) in entries.iter().enumerate() {
            assert_eq!(
                entry.config.kind(),
                [
                    ProxyListenerKind::ExplicitHttp,
                    ProxyListenerKind::TransparentHttp,
                    ProxyListenerKind::ExplicitHttps,
                    ProxyListenerKind::TransparentHttps,
                ][index]
            );
            let PreparedListenerEndpoint::Tcp(listener) = &entry.endpoint else {
                panic!("test config uses only TCP endpoints");
            };
            assert_eq!(listener.local_addr().unwrap(), addresses[index]);
        }
        assert!(matches!(
            &entries[0].config,
            ProxyListenerConfig::ExplicitHttp(actual)
                if Some(actual.as_ref()) == config.explicit_http.as_ref()
        ));
        assert!(matches!(
            &entries[1].config,
            ProxyListenerConfig::TransparentHttp(actual)
                if Some(actual.as_ref()) == config.transparent_http.as_ref()
        ));
        assert!(matches!(
            &entries[2].config,
            ProxyListenerConfig::ExplicitHttps(actual)
                if Some(actual.as_ref()) == config.explicit_https.as_ref()
        ));
        assert!(matches!(
            &entries[3].config,
            ProxyListenerConfig::TransparentHttps(actual)
                if Some(actual.as_ref()) == config.transparent_https.as_ref()
        ));

        let shared = entries
            .into_iter()
            .map(PreparedProxyListener::into_shared)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            shared
                .iter()
                .map(|listener| listener.config().mode())
                .collect::<Vec<_>>(),
            [
                ListenerMode::ExplicitHttp,
                ListenerMode::TransparentHttp,
                ListenerMode::ExplicitHttps,
                ListenerMode::TransparentHttps,
            ]
        );
        assert_eq!(
            shared[0].config().protocols().protocols(),
            [HttpProtocol::Http1, HttpProtocol::Http2]
        );
        assert_eq!(
            shared[0].config().http1_connect_policy(),
            Http1ConnectPolicy::Deny
        );
        assert_eq!(shared[0].config().limits().max_connections(), 17);
        assert_eq!(shared[0].config().limits().max_concurrent_streams(), 19);
        assert_eq!(
            shared[2].config().handshake_timeout(),
            Some(Duration::from_secs(3))
        );
        assert_eq!(
            shared[3].config().handshake_timeout(),
            Some(Duration::from_secs(7))
        );
    }

    #[test]
    fn transparent_listener_is_rejected_when_the_platform_cannot_support_it() {
        let [listener] = prebound_listeners::<1>();
        let prepared = PreparedProxyListeners {
            transparent_http: Some(transparent_http_listener(listener)),
            ..PreparedProxyListeners::default()
        };

        assert!(matches!(
            prepared.into_runtime_inputs_with_transparent_support(false),
            Err(SharedRuntimeError::InvalidInput)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn panicked_access_flow_route_reports_its_exact_https_listener_kind() {
        let mut routes = tokio::task::JoinSet::new();
        let task = routes.spawn(async {
            panic!("injected Access Flow route panic");
            #[allow(unreachable_code)]
            Ok::<ProxyListenerKind, Arc<ProxyListenerFailure>>(ProxyListenerKind::ExplicitHttps)
        });
        let mut route_kinds = HashMap::from([(task.id(), ProxyListenerKind::ExplicitHttps)]);
        let joined = routes
            .join_next_with_id()
            .await
            .expect("injected route task must complete");

        let failure = access_flow_route_failure(joined, &mut route_kinds);

        assert_eq!(failure.listener, ProxyListenerKind::ExplicitHttps);
        assert_eq!(failure.message, "Access Flow listener task failed");
        assert!(route_kinds.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn access_flow_accept_wait_observes_fatal_connection_without_a_later_client() {
        let directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::UnixListener::bind(directory.path().join("listener.sock"))
            .expect("bind test Unix listener");
        let adapter =
            UnixAccessFlowListenerAdapter::from_prebound(listener, Duration::from_secs(2)).unwrap();
        let cancellation = ForwardingCancellation::new();
        let permit = Arc::new(tokio::sync::Semaphore::new(1))
            .acquire_owned()
            .await
            .unwrap();
        let mut connections = tokio::task::JoinSet::new();
        connections.spawn(async {
            tokio::task::yield_now().await;
            Err(listener_failure(
                ProxyListenerKind::TransparentHttp,
                "injected connection failure",
            ))
        });

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_access_flow_accept(
                &adapter,
                &cancellation,
                &mut connections,
                permit,
                ProxyListenerKind::TransparentHttp,
            ),
        )
        .await
        .expect("fatal connection completion was hidden behind Unix accept");

        let failure = match result {
            Err(failure) => failure,
            Ok(_) => panic!("fatal connection completion was not propagated"),
        };
        assert_eq!(failure.listener, ProxyListenerKind::TransparentHttp);
        assert_eq!(failure.message, "injected connection failure");
    }

    #[tokio::test]
    async fn forced_access_flow_drain_joins_aborted_connection_resources() {
        struct DropWitness(Arc<AtomicBool>);

        impl Drop for DropWitness {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let witness = DropWitness(Arc::clone(&dropped));
        let mut connections = tokio::task::JoinSet::new();
        connections.spawn(async move {
            let _witness = witness;
            std::future::pending::<()>().await;
            Ok(())
        });
        let force = ForwardingCancellation::new();
        force.cancel();

        drain_access_flow_connections(ProxyListenerKind::TransparentHttp, &force, &mut connections)
            .await
            .unwrap();

        assert!(connections.is_empty());
        assert!(
            dropped.load(Ordering::Acquire),
            "forced drain returned before the aborted connection resource dropped"
        );
    }

    #[test]
    fn local_address_provider_reads_only_the_retained_snapshot() {
        let provider = SystemLocalAddressProvider::from_snapshot(HashSet::from(["192.0.2.1"
            .parse()
            .unwrap()]))
        .unwrap();

        assert!(provider
            .is_local_address("192.0.2.1".parse().unwrap())
            .unwrap());
        assert!(provider
            .is_local_address("127.42.0.9".parse().unwrap())
            .unwrap());
        assert!(!provider
            .is_local_address("198.51.100.1".parse().unwrap())
            .unwrap());
    }

    #[test]
    fn successful_local_address_refresh_replaces_the_complete_snapshot() {
        let provider = SystemLocalAddressProvider::from_snapshot(HashSet::from([
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
        ]))
        .unwrap();

        provider
            .replace(HashSet::from(["198.51.100.7".parse().unwrap()]))
            .unwrap();

        assert!(!provider
            .is_local_address("192.0.2.1".parse().unwrap())
            .unwrap());
        assert!(!provider
            .is_local_address("192.0.2.2".parse().unwrap())
            .unwrap());
        assert!(provider
            .is_local_address("198.51.100.7".parse().unwrap())
            .unwrap());
    }

    #[test]
    fn local_address_activation_rejects_an_empty_snapshot() {
        assert!(matches!(
            SystemLocalAddressProvider::from_snapshot(HashSet::new()),
            Err(SharedRuntimeError::ServiceFailure)
        ));
    }

    #[tokio::test]
    async fn refresh_error_retains_prior_snapshot_and_later_success_replaces_it() {
        let old: IpAddr = "192.0.2.1".parse().unwrap();
        let new: IpAddr = "198.51.100.1".parse().unwrap();
        let source = MutableSnapshotSource::new([old]);
        let observer = Arc::new(RecordingRefreshObserver::default());
        let runtime = ProductLocalAddressRuntime::activate_with(
            source.clone(),
            Duration::from_millis(10),
            observer.clone(),
        )
        .await
        .unwrap();
        let provider = runtime.provider();

        source.set(SnapshotBehavior::Error);
        source.wait_for_call_after(1).await;
        assert!(provider.is_local_address(old).unwrap());

        let prior_calls = source.calls.load(Ordering::Acquire);
        source.set(SnapshotBehavior::Addresses(HashSet::from([new])));
        source.wait_for_call_after(prior_calls).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while provider.is_local_address(old).unwrap()
                || !provider.is_local_address(new).unwrap()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("refreshed local-address snapshot was not published");
        assert!(!provider.is_local_address(old).unwrap());
        assert!(provider.is_local_address(new).unwrap());

        runtime.shutdown_and_join().await;
        assert!(observer
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty());
    }

    #[tokio::test]
    async fn refresh_worker_panic_is_reported_as_listener_failure() {
        let source = MutableSnapshotSource::new(["192.0.2.1".parse().unwrap()]);
        let observer = Arc::new(RecordingRefreshObserver::default());
        let runtime = ProductLocalAddressRuntime::activate_with(
            source.clone(),
            Duration::from_millis(10),
            observer.clone(),
        )
        .await
        .unwrap();
        source.set(SnapshotBehavior::Panic);

        let failure = observer.next_failure().await;

        assert_eq!(failure.listener, ProxyListenerKind::LocalAddressRefresh);
        assert!(failure.message.contains("failed"));
        runtime.shutdown_and_join().await;
    }

    #[tokio::test]
    async fn unexpected_refresh_worker_completion_is_reported_as_listener_failure() {
        let source = MutableSnapshotSource::new(["192.0.2.1".parse().unwrap()]);
        let observer = Arc::new(RecordingRefreshObserver::default());
        let runtime = ProductLocalAddressRuntime::activate_with(
            source,
            Duration::from_secs(60),
            observer.clone(),
        )
        .await
        .unwrap();

        runtime.stop_without_shutdown_for_test();
        let failure = observer.next_failure().await;

        assert_eq!(failure.listener, ProxyListenerKind::LocalAddressRefresh);
        assert!(failure.message.contains("unexpectedly"));
        runtime.shutdown_and_join().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_local_address_shutdown_retains_the_supervisor_join_handle() {
        let source = MutableSnapshotSource::new(["192.0.2.1".parse().unwrap()]);
        let observer = Arc::new(RecordingRefreshObserver::default());
        let runtime = ProductLocalAddressRuntime::activate_with(
            source.clone(),
            Duration::from_millis(10),
            observer.clone(),
        )
        .await
        .unwrap();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        source.set(SnapshotBehavior::Block(Arc::clone(&gate)));
        source.wait_for_call_after(1).await;

        let first_runtime = Arc::clone(&runtime);
        let first_shutdown = tokio::spawn(async move {
            first_runtime.shutdown_and_join().await;
        });
        tokio::task::yield_now().await;
        first_shutdown.abort();
        assert!(first_shutdown.await.unwrap_err().is_cancelled());

        let (open, changed) = &*gate;
        *open.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        changed.notify_all();
        tokio::time::timeout(Duration::from_secs(1), runtime.shutdown_and_join())
            .await
            .expect("retry did not recover and join the retained supervisor");
        assert!(observer
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty());
    }

    #[cfg(unix)]
    fn unix_transparent_config(path: &Path, mode: u32) -> StaticListenersConfig {
        StaticListenersConfig {
            explicit_http: None,
            transparent_http: Some(StaticCleartextListener {
                endpoint: StaticListenerEndpoint::AccessFlow {
                    admission_timeout: Duration::from_secs(1),
                    allowed_destination_ports: vec![80],
                    transport: StaticAccessFlowTransport::Unix {
                        path: path.to_path_buf(),
                        mode,
                    },
                },
                http_versions: vec![CompiledHttpVersion::Http1],
                request_header_timeout: Duration::from_secs(1),
                max_connections: 4,
                max_concurrent_streams: 4,
                identity_mode: CompiledListenerIdentityMode::Disabled,
                connect: None,
            }),
            explicit_https: None,
            transparent_https: None,
        }
    }

    #[cfg(unix)]
    fn private_unix_tempdir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[cfg(unix)]
    #[test]
    fn unix_listener_lock_mode_and_explicit_cleanup_contract() {
        let directory = private_unix_tempdir();
        let path = directory.path().join("transparent-http.sock");
        let config = unix_transparent_config(&path, 0o606);
        let first = PreparedProxyListeners::bind(&config, |_| {
            panic!("Unix config must not invoke the TCP binder")
        })
        .unwrap();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o606);
        let first_inode = metadata.ino();

        let error = match PreparedProxyListeners::bind(&config, |_| unreachable!()) {
            Ok(_) => panic!("second process must not acquire a held Unix listener lock"),
            Err(error) => error,
        };
        assert_eq!(error.name, "transparent_http");
        assert_eq!(error.address, None);
        assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), first_inode);

        drop(first);
        assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), first_inode);
        let error = match PreparedProxyListeners::bind(&config, |_| unreachable!()) {
            Ok(_) => panic!("stale Unix socket must require explicit cleanup"),
            Err(error) => error,
        };
        assert_eq!(error.source.kind(), io::ErrorKind::AddrInUse);
        assert!(error.source.to_string().contains("remove it explicitly"));

        std::fs::remove_file(&path).unwrap();
        let rebound = PreparedProxyListeners::bind(&config, |_| unreachable!()).unwrap();
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_socket());

        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"external replacement").unwrap();
        drop(rebound);
        assert_eq!(std::fs::read(&path).unwrap(), b"external replacement");
    }

    #[cfg(unix)]
    #[test]
    fn unix_listener_never_unlinks_preexisting_paths() {
        use std::os::unix::fs::symlink;

        let directory = private_unix_tempdir();
        let path = directory.path().join("traffic.sock");
        drop(UnixListener::bind(&path).unwrap());
        let stale_inode = std::fs::symlink_metadata(&path).unwrap().ino();
        let error = match PreparedProxyListeners::bind(
            &unix_transparent_config(&path, 0o600),
            |_| unreachable!(),
        ) {
            Ok(_) => panic!("stale Unix socket must require explicit cleanup"),
            Err(error) => error,
        };
        assert_eq!(error.source.kind(), io::ErrorKind::AddrInUse);
        assert!(error.source.to_string().contains("remove it explicitly"));
        assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), stale_inode);

        std::fs::remove_file(&path).unwrap();
        let prepared = PreparedProxyListeners::bind(
            &unix_transparent_config(&path, 0o600),
            |_| unreachable!(),
        )
        .unwrap();
        drop(prepared);
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_socket());
        std::fs::remove_file(&path).unwrap();

        std::fs::write(&path, b"collision").unwrap();
        assert!(PreparedProxyListeners::bind(
            &unix_transparent_config(&path, 0o600),
            |_| unreachable!(),
        )
        .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"collision");
        std::fs::remove_file(&path).unwrap();

        let target = directory.path().join("target");
        std::fs::write(&target, b"target").unwrap();
        symlink(&target, &path).unwrap();
        assert!(PreparedProxyListeners::bind(
            &unix_transparent_config(&path, 0o600),
            |_| unreachable!(),
        )
        .is_err());
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn unix_listener_requires_a_private_owned_parent_directory() {
        let directory = private_unix_tempdir();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = directory.path().join("traffic.sock");

        let error = match PreparedProxyListeners::bind(
            &unix_transparent_config(&path, 0o600),
            |_| unreachable!(),
        ) {
            Ok(_) => panic!("non-private Unix socket parent must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.source.kind(), io::ErrorKind::PermissionDenied);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn unix_listener_filesystem_ownership_uses_the_effective_uid() {
        let directory = private_unix_tempdir();
        let socket_path = directory.path().join("owned.sock");
        let socket = UnixListener::bind(&socket_path).unwrap();
        let effective_uid = rustix::process::geteuid().as_raw();
        let other_uid = effective_uid.wrapping_add(1);

        validate_private_unix_parent(&socket_path, effective_uid).unwrap();
        assert_eq!(
            validate_private_unix_parent(&socket_path, other_uid)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        let metadata = std::fs::symlink_metadata(&socket_path).unwrap();
        validate_owned_socket(&metadata, effective_uid).unwrap();
        assert_eq!(
            validate_owned_socket(&metadata, other_uid)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(socket);
    }

    #[cfg(unix)]
    #[test]
    fn staged_unix_listener_verification_rejects_wrong_type_owner_and_mode() {
        let directory = private_unix_tempdir();
        let socket_path = directory.path().join("staged.sock");
        let socket = UnixListener::bind(&socket_path).unwrap();
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o620)).unwrap();
        let socket_metadata = std::fs::symlink_metadata(&socket_path).unwrap();
        let effective_uid = rustix::process::geteuid().as_raw();

        verify_staged_unix_socket(&socket_metadata, effective_uid, 0o620).unwrap();
        assert_eq!(
            verify_staged_unix_socket(&socket_metadata, effective_uid, 0o600)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            verify_staged_unix_socket(&socket_metadata, effective_uid.wrapping_add(1), 0o620)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        let regular_path = directory.path().join("regular");
        std::fs::write(&regular_path, b"not a socket").unwrap();
        let regular_metadata = std::fs::symlink_metadata(regular_path).unwrap();
        assert_eq!(
            verify_staged_unix_socket(&regular_metadata, effective_uid, 0o600)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(socket);
    }

    #[cfg(unix)]
    #[test]
    fn unix_listener_refuses_a_live_same_user_socket_without_unlinking_it() {
        let directory = private_unix_tempdir();
        let path = directory.path().join("live.sock");
        let live = UnixListener::bind(&path).unwrap();
        let inode = std::fs::symlink_metadata(&path).unwrap().ino();

        let error = match PreparedProxyListeners::bind(
            &unix_transparent_config(&path, 0o600),
            |_| unreachable!(),
        ) {
            Ok(_) => panic!("live Unix socket must not be replaced"),
            Err(error) => error,
        };
        assert_eq!(error.source.kind(), io::ErrorKind::AddrInUse);
        assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), inode);
        let (connected, _) = live.accept().unwrap();
        drop(connected);
    }

    #[cfg(unix)]
    #[test]
    fn preexisting_socket_probe_classification_is_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("existing.sock");
        drop(UnixListener::bind(&path).unwrap());
        let inode = std::fs::symlink_metadata(&path).unwrap().ino();
        let effective_uid = rustix::process::geteuid().as_raw();

        for (probe_error, expected_fragment) in [
            (
                io::Error::from(io::ErrorKind::ConnectionRefused),
                "remove it explicitly",
            ),
            (
                io::Error::from(io::ErrorKind::TimedOut),
                "backlog is unavailable",
            ),
            (
                io::Error::from(io::ErrorKind::WouldBlock),
                "backlog is unavailable",
            ),
        ] {
            let error = reject_preexisting_unix_socket(&path, effective_uid, |_| Err(probe_error))
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
            assert!(error.to_string().contains(expected_fragment));
            assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), inode);
        }

        let error = reject_preexisting_unix_socket(&path, effective_uid, |_| {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), inode);
    }

    #[cfg(any(
        target_os = "android",
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "redox"
    ))]
    #[test]
    fn unix_listener_publication_never_replaces_an_occupied_final_path() {
        let directory = tempfile::tempdir().unwrap();
        let private_path = directory.path().join("private.sock");
        let final_path = directory.path().join("final.sock");
        let private = UnixListener::bind(&private_path).unwrap();
        std::fs::write(&final_path, b"occupied").unwrap();

        let error = publish_unix_socket_noreplace(&private_path, &final_path).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert_eq!(std::fs::read(&final_path).unwrap(), b"occupied");
        assert!(std::fs::symlink_metadata(&private_path)
            .unwrap()
            .file_type()
            .is_socket());
        drop(private);
    }
}
