use std::collections::HashSet;
use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Buf;
use chrono::Utc;
use http::header::{CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRAILER};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Version};
use hyper::body::{Bytes, HttpBody, SizeHint};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::Body;
use rustls::server::Acceptor as RustlsAcceptor;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{
    mpsc, oneshot, watch, Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore,
};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor};

use crate::activation::assets::ProductIngressAssets;
use crate::activation::listeners::{
    PreparedProxyListener, ProxyListenerConfig, ProxyListenerKind, ProxySupervisor,
    ProxySupervisorFailure, ProxySupervisorFailureObserver, ProxySupervisorStartError,
    ProxySupervisorStarter,
};
use crate::capture::{
    CaptureDecision, CaptureEndpoint, CaptureKind, CaptureMode, CaptureRecord, HttpCaptureTap,
};
use crate::certs::MitmCertificateManager;
use crate::config::compiler::{
    CompiledHttp1ConnectPolicy, CompiledHttpVersion, HeaderEffectPlan, HttpBodyReadPlan,
    StaticCleartextListener, StaticExplicitHttpsListener, StaticTransparentHttpsListener,
};
use crate::destination::DestinationTarget;
use crate::http_body::{read_mandatory_request_body, HttpBodyReadError};
use crate::observation::{CaptureEpoch, CaptureEvent, ProductObservationRuntime};
use crate::policy::apply_header_effects;
use crate::proxy::authority::{
    reconcile_connect_inner_request, reconcile_connect_outer_request, reconcile_connect_sni,
    reconcile_explicit_request, reconcile_transparent_http_request, CanonicalConnectTarget,
};
use crate::proxy::forward::{
    forward_request, forward_upgrade_request, preflight_forwarding_target,
    resolve_forwarding_target, ForwardBody, ForwardBodyError, ForwardUpgradeResult,
    ForwardedResponse, ResolvedForwardingTarget,
};
use crate::proxy::headers::{
    sanitize_untrusted_connect_request, sanitize_untrusted_request, HeaderPreparationError,
    SanitizedRequest,
};
use crate::proxy::original_destination::{
    OriginalDestinationResolver, SystemOriginalDestinationResolver,
};
use crate::proxy::upgrade_relay::{EstablishedUpgradeKind, UpgradeCaptureContext};
use crate::request_decision::{
    prepare_request, AllowedRequest, GuardedRequestBody as DecisionBody, RequestDecision,
    RequestInput, TerminalRequestBodyProvenance, UpgradeBinding,
};
use crate::runtime::{BoxFuture, GenerationRetention, Runtime};
use crate::safety::wire_body::{GuardedBodyData, GuardedHttpBody};
use crate::safety::{InvalidLoopMarker, WireBodyQuotaKey};
use crate::sensitive::{is_sensitive_header_name, REDACTED};
use crate::upgrade::{
    UpgradeEntryPlan, UpgradeRuntime, UpgradeTerminalCause, UpgradeTerminalControl,
};
use crate::url::canonicalize_tls_server_name;

/// Concrete process-runtime starter for the prebound product listener bundle.
pub(crate) struct ProductProxySupervisorStarter {
    runtime: Arc<Runtime>,
    observation_runtime: Arc<ProductObservationRuntime>,
    upgrade_runtime: Arc<UpgradeRuntime>,
    original_destination: Arc<dyn OriginalDestinationResolver>,
}

impl ProductProxySupervisorStarter {
    pub(crate) fn new(
        runtime: Arc<Runtime>,
        observation_runtime: Arc<ProductObservationRuntime>,
        upgrade_runtime: Arc<UpgradeRuntime>,
    ) -> Self {
        Self {
            runtime,
            observation_runtime,
            upgrade_runtime,
            original_destination: Arc::new(SystemOriginalDestinationResolver),
        }
    }

    #[cfg(test)]
    fn with_original_destination_resolver(
        runtime: Arc<Runtime>,
        observation_runtime: Arc<ProductObservationRuntime>,
        upgrade_runtime: Arc<UpgradeRuntime>,
        original_destination: Arc<dyn OriginalDestinationResolver>,
    ) -> Self {
        Self {
            runtime,
            observation_runtime,
            upgrade_runtime,
            original_destination,
        }
    }
}

impl ProxySupervisorStarter for ProductProxySupervisorStarter {
    fn start(
        &mut self,
        listener: PreparedProxyListener,
        assets: &Arc<ProductIngressAssets>,
        failure_observer: Arc<dyn ProxySupervisorFailureObserver>,
    ) -> Result<Arc<dyn ProxySupervisor>, ProxySupervisorStartError> {
        let kind = listener.kind();
        match listener.config {
            ProxyListenerConfig::ExplicitHttp(config) => {
                require_connect_mitm_asset(kind, config.connect.as_ref(), assets)?;
                ProductIngressSupervisor::start(
                    IngressListenerConfig::cleartext(
                        kind,
                        ConfiguredRequestAuthority::Explicit,
                        *config,
                    ),
                    listener.listener,
                    self.runtime.clone(),
                    self.observation_runtime.clone(),
                    self.upgrade_runtime.clone(),
                    assets.clone(),
                    failure_observer,
                )
                .map(|supervisor| supervisor as Arc<dyn ProxySupervisor>)
            }
            ProxyListenerConfig::TransparentHttp(config) => ProductIngressSupervisor::start(
                IngressListenerConfig::cleartext(
                    kind,
                    ConfiguredRequestAuthority::TransparentHttp,
                    *config,
                ),
                listener.listener,
                self.runtime.clone(),
                self.observation_runtime.clone(),
                self.upgrade_runtime.clone(),
                assets.clone(),
                failure_observer,
            )
            .map(|supervisor| supervisor as Arc<dyn ProxySupervisor>),
            ProxyListenerConfig::ExplicitHttps(config) => {
                require_connect_mitm_asset(kind, Some(&config.connect), assets)?;
                let config = *config;
                let acceptor = assets.explicit_https_tls().cloned().ok_or_else(|| {
                    ProxySupervisorStartError {
                        listener: kind,
                        message: "the activated explicit HTTPS identity is missing".to_owned(),
                    }
                })?;
                ProductIngressSupervisor::start(
                    IngressListenerConfig::explicit_https(kind, config, acceptor),
                    listener.listener,
                    self.runtime.clone(),
                    self.observation_runtime.clone(),
                    self.upgrade_runtime.clone(),
                    assets.clone(),
                    failure_observer,
                )
                .map(|supervisor| supervisor as Arc<dyn ProxySupervisor>)
            }
            ProxyListenerConfig::TransparentHttps(config) => {
                let mitm = assets
                    .mitm()
                    .cloned()
                    .ok_or_else(|| ProxySupervisorStartError {
                        listener: kind,
                        message: "the activated MITM certificate manager is missing".to_owned(),
                    })?;
                ProductIngressSupervisor::start(
                    IngressListenerConfig::transparent_https(
                        kind,
                        *config,
                        mitm,
                        assets.transparent_https_alpn().to_vec(),
                        self.original_destination.clone(),
                    ),
                    listener.listener,
                    self.runtime.clone(),
                    self.observation_runtime.clone(),
                    self.upgrade_runtime.clone(),
                    assets.clone(),
                    failure_observer,
                )
                .map(|supervisor| supervisor as Arc<dyn ProxySupervisor>)
            }
        }
    }
}

fn require_connect_mitm_asset(
    kind: ProxyListenerKind,
    connect: Option<&crate::config::compiler::StaticConnectPolicy>,
    assets: &ProductIngressAssets,
) -> Result<(), ProxySupervisorStartError> {
    if connect.is_some_and(|connect| connect.http1 == Some(CompiledHttp1ConnectPolicy::Mitm))
        && assets.mitm().is_none()
    {
        return Err(ProxySupervisorStartError {
            listener: kind,
            message: "HTTP/1 CONNECT MITM requires an activated MITM certificate manager"
                .to_owned(),
        });
    }
    Ok(())
}

#[derive(Clone)]
enum RequestAuthority {
    Explicit,
    TransparentHttp,
    ConnectInner(Box<CanonicalConnectTarget>),
    TransparentHttps {
        destination_port: u16,
        sni: Arc<str>,
    },
}

#[derive(Clone, Copy)]
enum ConfiguredRequestAuthority {
    Explicit,
    TransparentHttp,
    DynamicTransparentHttps,
}

#[derive(Clone)]
enum IngressTransport {
    Cleartext,
    StaticTls {
        acceptor: TlsAcceptor,
        handshake_timeout: Duration,
    },
    DynamicMitmTls {
        manager: Arc<MitmCertificateManager>,
        alpn_protocols: Arc<[Vec<u8>]>,
        handshake_timeout: Duration,
        original_destination: Arc<dyn OriginalDestinationResolver>,
    },
}

#[derive(Clone)]
struct IngressListenerConfig {
    kind: ProxyListenerKind,
    authority: ConfiguredRequestAuthority,
    transport: IngressTransport,
    http_versions: Vec<CompiledHttpVersion>,
    request_header_timeout: Duration,
    max_connections: usize,
    max_concurrent_streams: u32,
    connect: Option<crate::config::compiler::StaticConnectPolicy>,
}

impl IngressListenerConfig {
    fn cleartext(
        kind: ProxyListenerKind,
        authority: ConfiguredRequestAuthority,
        config: StaticCleartextListener,
    ) -> Self {
        Self {
            kind,
            authority,
            transport: IngressTransport::Cleartext,
            http_versions: config.http_versions,
            request_header_timeout: config.request_header_timeout,
            max_connections: config.max_connections,
            max_concurrent_streams: config.max_concurrent_streams,
            connect: config.connect,
        }
    }

    fn explicit_https(
        kind: ProxyListenerKind,
        config: StaticExplicitHttpsListener,
        acceptor: TlsAcceptor,
    ) -> Self {
        Self {
            kind,
            authority: ConfiguredRequestAuthority::Explicit,
            transport: IngressTransport::StaticTls {
                acceptor,
                handshake_timeout: config.handshake_timeout,
            },
            http_versions: config.http_versions,
            request_header_timeout: config.request_header_timeout,
            max_connections: config.max_connections,
            max_concurrent_streams: config.max_concurrent_streams,
            connect: Some(config.connect),
        }
    }

    fn transparent_https(
        kind: ProxyListenerKind,
        config: StaticTransparentHttpsListener,
        manager: Arc<MitmCertificateManager>,
        alpn_protocols: Vec<Vec<u8>>,
        original_destination: Arc<dyn OriginalDestinationResolver>,
    ) -> Self {
        Self {
            kind,
            authority: ConfiguredRequestAuthority::DynamicTransparentHttps,
            transport: IngressTransport::DynamicMitmTls {
                manager,
                alpn_protocols: alpn_protocols.into(),
                handshake_timeout: config.handshake_timeout,
                original_destination,
            },
            http_versions: config.http_versions,
            request_header_timeout: config.request_header_timeout,
            max_connections: config.max_connections,
            max_concurrent_streams: config.max_concurrent_streams,
            connect: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum SupervisorStop {
    Running,
    CloseAndJoin,
    AbortAndJoin,
}

struct ProductIngressSupervisor {
    kind: ProxyListenerKind,
    stop: watch::Sender<SupervisorStop>,
    stop_gate: Arc<StdMutex<SupervisorStop>>,
    task: AsyncMutex<SupervisorTaskState>,
}

struct SupervisorTaskState {
    handle: Option<JoinHandle<Result<(), Arc<ProxySupervisorFailure>>>>,
    terminal: Option<Result<(), Arc<ProxySupervisorFailure>>>,
}

#[derive(Clone)]
struct IngressRuntime {
    runtime: Arc<Runtime>,
    observation: Arc<ProductObservationRuntime>,
    upgrade: Arc<UpgradeRuntime>,
    assets: Arc<ProductIngressAssets>,
}

impl ProductIngressSupervisor {
    fn start(
        config: IngressListenerConfig,
        listener: std::net::TcpListener,
        runtime: Arc<Runtime>,
        observation_runtime: Arc<ProductObservationRuntime>,
        upgrade_runtime: Arc<UpgradeRuntime>,
        assets: Arc<ProductIngressAssets>,
        failure_observer: Arc<dyn ProxySupervisorFailureObserver>,
    ) -> Result<Arc<Self>, ProxySupervisorStartError> {
        let kind = config.kind;
        listener
            .set_nonblocking(true)
            .map_err(|error| start_error(kind, "cannot mark the listener nonblocking", error))?;
        let listener = TcpListener::from_std(listener)
            .map_err(|error| start_error(kind, "cannot adopt the prebound listener", error))?;
        let executor =
            tokio::runtime::Handle::try_current().map_err(|error| ProxySupervisorStartError {
                listener: kind,
                message: format!("Tokio runtime is unavailable: {error}"),
            })?;
        let (stop, stop_rx) = watch::channel(SupervisorStop::Running);
        let stop_gate = Arc::new(StdMutex::new(SupervisorStop::Running));
        let quota_classifier = LocalQuotaClassifier::new().map_err(|error| {
            start_error(
                kind,
                "cannot snapshot local addresses for quota classification",
                error,
            )
        })?;
        let listener_task = executor.spawn(run_listener(
            config,
            listener,
            IngressRuntime {
                runtime,
                observation: observation_runtime,
                upgrade: upgrade_runtime,
                assets,
            },
            quota_classifier,
            stop_rx,
        ));
        let task = executor.spawn(observe_listener_task(kind, listener_task, failure_observer));
        Ok(Arc::new(Self {
            kind,
            stop,
            stop_gate,
            task: AsyncMutex::new(SupervisorTaskState {
                handle: Some(task),
                terminal: None,
            }),
        }))
    }

    async fn stop_and_join(&self, requested: SupervisorStop) -> Result<(), ProxySupervisorFailure> {
        request_stop(&self.stop_gate, &self.stop, requested);
        let mut task = self.task.lock().await;
        let terminal = if let Some(terminal) = &task.terminal {
            terminal.clone()
        } else {
            let terminal = match task
                .handle
                .as_mut()
                .expect("a nonterminal proxy supervisor owns its task")
                .await
            {
                Ok(result) => result,
                Err(error) => Err(Arc::new(ProxySupervisorFailure {
                    listener: self.kind,
                    message: format!("supervisor task did not join: {error}"),
                })),
            };
            task.handle.take();
            task.terminal = Some(terminal.clone());
            terminal
        };
        terminal.map_err(|error| ProxySupervisorFailure {
            listener: error.listener,
            message: error.message.clone(),
        })
    }
}

async fn observe_listener_task(
    kind: ProxyListenerKind,
    listener_task: JoinHandle<Result<(), Arc<ProxySupervisorFailure>>>,
    failure_observer: Arc<dyn ProxySupervisorFailureObserver>,
) -> Result<(), Arc<ProxySupervisorFailure>> {
    let result = match listener_task.await {
        Ok(result) => result,
        Err(error) => Err(Arc::new(ProxySupervisorFailure {
            listener: kind,
            message: format!("supervisor task did not join: {error}"),
        })),
    };
    if let Err(error) = result.as_ref() {
        failure_observer.failed(error.clone());
    }
    result
}

impl ProxySupervisor for ProductIngressSupervisor {
    fn begin_shutdown(&self) {
        request_stop(&self.stop_gate, &self.stop, SupervisorStop::CloseAndJoin);
    }

    fn close_and_join(&self) -> BoxFuture<'_, Result<(), ProxySupervisorFailure>> {
        Box::pin(self.stop_and_join(SupervisorStop::CloseAndJoin))
    }

    fn abort_and_join(&self) -> BoxFuture<'_, Result<(), ProxySupervisorFailure>> {
        Box::pin(self.stop_and_join(SupervisorStop::AbortAndJoin))
    }
}

fn request_stop(
    gate: &StdMutex<SupervisorStop>,
    sender: &watch::Sender<SupervisorStop>,
    requested: SupervisorStop,
) {
    let mut stop = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if requested > *stop {
        *stop = requested;
        sender.send_replace(requested);
    }
}

fn start_error(
    kind: ProxyListenerKind,
    context: &str,
    error: impl std::fmt::Display,
) -> ProxySupervisorStartError {
    ProxySupervisorStartError {
        listener: kind,
        message: format!("{context}: {error}"),
    }
}

async fn run_listener(
    config: IngressListenerConfig,
    listener: TcpListener,
    ingress: IngressRuntime,
    quota_classifier: LocalQuotaClassifier,
    mut stop: watch::Receiver<SupervisorStop>,
) -> Result<(), Arc<ProxySupervisorFailure>> {
    let IngressRuntime {
        runtime,
        observation: observation_runtime,
        upgrade: upgrade_runtime,
        assets,
    } = ingress;
    let kind = config.kind;
    let connection_slots = Arc::new(Semaphore::new(config.max_connections));
    let (refresh_stop, refresh_stop_rx) = watch::channel(false);
    let mut refresh_task = tokio::spawn(refresh_local_addresses(
        kind,
        quota_classifier.clone(),
        refresh_stop_rx,
    ));
    let (tunnel_tx, mut tunnel_rx) = mpsc::channel::<ConnectTunnelPlan>(config.max_connections);
    let mut connections = JoinSet::new();
    let mut tunnels = JoinSet::new();
    let mut terminal_failure = None;
    'accept: loop {
        let permit = tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() != SupervisorStop::Running {
                    break 'accept;
                }
                continue;
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    tracing::debug!(listener = %kind, %error, "ingress connection task failed");
                }
                continue;
            }
            Some(result) = tunnels.join_next(), if !tunnels.is_empty() => {
                if let Err(error) = result {
                    tracing::debug!(listener = %kind, %error, "CONNECT tunnel task failed");
                }
                continue;
            }
            Some(plan) = tunnel_rx.recv() => {
                tunnels.spawn(plan.run());
                continue;
            }
            result = &mut refresh_task => {
                terminal_failure = Some(Arc::new(ProxySupervisorFailure {
                    listener: kind,
                    message: match result {
                        Ok(Ok(())) => "local-address refresh task stopped unexpectedly".to_owned(),
                        Ok(Err(error)) => error,
                        Err(error) => format!("local-address refresh task did not join: {error}"),
                    },
                }));
                break 'accept;
            }
            permit = connection_slots.clone().acquire_owned() => {
                permit.expect("the listener owns its connection-admission semaphore")
            }
        };

        let accepted = tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() != SupervisorStop::Running {
                    break 'accept;
                }
                continue;
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    tracing::debug!(listener = %kind, %error, "ingress connection task failed");
                }
                continue;
            }
            Some(result) = tunnels.join_next(), if !tunnels.is_empty() => {
                if let Err(error) = result {
                    tracing::debug!(listener = %kind, %error, "CONNECT tunnel task failed");
                }
                continue;
            }
            Some(plan) = tunnel_rx.recv() => {
                tunnels.spawn(plan.run());
                continue;
            }
            result = &mut refresh_task => {
                terminal_failure = Some(Arc::new(ProxySupervisorFailure {
                    listener: kind,
                    message: match result {
                        Ok(Ok(())) => "local-address refresh task stopped unexpectedly".to_owned(),
                        Ok(Err(error)) => error,
                        Err(error) => format!("local-address refresh task did not join: {error}"),
                    },
                }));
                break 'accept;
            }
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                drop(permit);
                match classify_accept_error(&error) {
                    AcceptErrorAction::Retry => tokio::task::yield_now().await,
                    AcceptErrorAction::Backoff => {
                        tracing::warn!(listener = %kind, %error, "listener accept error; backing off before retry");
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                            _ = wait_for_supervisor_stop(&mut stop) => break 'accept,
                        }
                    }
                    AcceptErrorAction::Fail => {
                        terminal_failure = Some(Arc::new(ProxySupervisorFailure {
                            listener: kind,
                            message: format!("terminal listener accept error: {error}"),
                        }));
                        break 'accept;
                    }
                }
                continue;
            }
        };
        let quota_key = quota_classifier.classify(peer.ip());
        let runtime = runtime.clone();
        let observation_runtime = observation_runtime.clone();
        let upgrade_runtime = upgrade_runtime.clone();
        let assets = assets.clone();
        let connection_config = config.clone();
        let connection_stop = stop.clone();
        let connection_tunnels = tunnel_tx.clone();
        connections.spawn(async move {
            serve_connection(AcceptedConnection {
                kind,
                config: connection_config,
                stream,
                peer,
                quota_key,
                ingress: IngressRuntime {
                    runtime,
                    observation: observation_runtime,
                    upgrade: upgrade_runtime,
                    assets,
                },
                supervisor_stop: connection_stop,
                tunnel_tx: connection_tunnels,
                admission: permit,
            })
            .await;
        });
    }

    drop(listener);
    drop(tunnel_tx);
    refresh_stop.send_replace(true);
    if !refresh_task.is_finished() {
        let _ = refresh_task.await;
    }

    let mut abort = terminal_failure.is_some() || *stop.borrow() == SupervisorStop::AbortAndJoin;
    if abort {
        connections.abort_all();
        tunnels.abort_all();
        tunnel_rx.close();
    }
    while !connections.is_empty()
        || !tunnels.is_empty()
        || (!abort && (!tunnel_rx.is_closed() || !tunnel_rx.is_empty()))
    {
        tokio::select! {
            changed = stop.changed(), if !abort => {
                if changed.is_ok() && *stop.borrow() == SupervisorStop::AbortAndJoin {
                    abort = true;
                    connections.abort_all();
                    tunnels.abort_all();
                    tunnel_rx.close();
                }
            }
            Some(plan) = tunnel_rx.recv(), if !abort => {
                tunnels.spawn(plan.run());
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::debug!(listener = %kind, %error, "ingress connection task failed while joining");
                }
            }
            result = tunnels.join_next(), if !tunnels.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::debug!(listener = %kind, %error, "CONNECT tunnel task failed while joining");
                }
            }
        }
    }
    terminal_failure.map_or(Ok(()), Err)
}

#[derive(Clone)]
struct LocalQuotaClassifier {
    addresses: Arc<RwLock<HashSet<IpAddr>>>,
}

impl LocalQuotaClassifier {
    fn new() -> io::Result<Self> {
        Ok(Self {
            addresses: Arc::new(RwLock::new(snapshot_local_ips()?)),
        })
    }

    fn classify(&self, peer: IpAddr) -> WireBodyQuotaKey {
        let addresses = self
            .addresses
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        WireBodyQuotaKey::from_peer(peer, |peer| addresses.contains(&peer))
    }

    fn replace(&self, addresses: HashSet<IpAddr>) {
        *self
            .addresses
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = addresses;
    }
}

fn snapshot_local_ips() -> io::Result<HashSet<IpAddr>> {
    let interfaces = if_addrs::get_if_addrs()?;
    let mut addresses = HashSet::new();
    addresses.try_reserve(interfaces.len()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            format!("cannot reserve local-address quota cache: {error}"),
        )
    })?;
    addresses.extend(
        interfaces
            .into_iter()
            .map(|interface| crate::network::canonical_ip(interface.ip())),
    );
    Ok(addresses)
}

async fn refresh_local_addresses(
    kind: ProxyListenerKind,
    classifier: LocalQuotaClassifier,
    mut stop: watch::Receiver<bool>,
) -> Result<(), String> {
    loop {
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(());
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
        match tokio::task::spawn_blocking(snapshot_local_ips).await {
            Ok(Ok(addresses)) => classifier.replace(addresses),
            Ok(Err(error)) => {
                tracing::warn!(listener = %kind, %error, "cannot refresh local-address quota cache");
            }
            Err(error) => {
                return Err(format!(
                    "local-address refresh worker did not join: {error}"
                ))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcceptErrorAction {
    Retry,
    Backoff,
    Fail,
}

fn classify_accept_error(error: &io::Error) -> AcceptErrorAction {
    match error.kind() {
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::Interrupted
        | io::ErrorKind::WouldBlock => AcceptErrorAction::Retry,
        io::ErrorKind::InvalidInput
        | io::ErrorKind::InvalidData
        | io::ErrorKind::NotConnected
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::PermissionDenied
        | io::ErrorKind::Unsupported => AcceptErrorAction::Fail,
        _ => AcceptErrorAction::Backoff,
    }
}

struct AcceptedConnection {
    kind: ProxyListenerKind,
    config: IngressListenerConfig,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    quota_key: WireBodyQuotaKey,
    ingress: IngressRuntime,
    supervisor_stop: watch::Receiver<SupervisorStop>,
    tunnel_tx: mpsc::Sender<ConnectTunnelPlan>,
    admission: OwnedSemaphorePermit,
}

async fn serve_connection(connection: AcceptedConnection) {
    let AcceptedConnection {
        kind,
        config,
        stream,
        peer,
        quota_key,
        ingress,
        mut supervisor_stop,
        tunnel_tx,
        admission,
    } = connection;
    let Some((stream, versions, authority)) = prepare_ingress_transport(
        &config.transport,
        config.authority,
        &config.http_versions,
        stream,
        &mut supervisor_stop,
    )
    .await
    else {
        return;
    };
    let admission = Arc::new(StdMutex::new(Some(admission)));
    serve_http_connection(HttpConnection {
        kind,
        config,
        stream,
        versions,
        authority,
        peer,
        quota_key,
        ingress,
        supervisor_stop,
        tunnel_tx,
        admission: Some(admission),
    })
    .await;
}

struct HttpConnection {
    kind: ProxyListenerKind,
    config: IngressListenerConfig,
    stream: BoxedIngressIo,
    versions: Vec<CompiledHttpVersion>,
    authority: RequestAuthority,
    peer: SocketAddr,
    quota_key: WireBodyQuotaKey,
    ingress: IngressRuntime,
    supervisor_stop: watch::Receiver<SupervisorStop>,
    tunnel_tx: mpsc::Sender<ConnectTunnelPlan>,
    admission: Option<Arc<StdMutex<Option<OwnedSemaphorePermit>>>>,
}

async fn serve_http_connection(connection: HttpConnection) {
    let HttpConnection {
        kind,
        config,
        stream,
        versions,
        authority,
        peer,
        quota_key,
        ingress:
            IngressRuntime {
                runtime,
                observation: observation_runtime,
                upgrade: upgrade_runtime,
                assets,
            },
        mut supervisor_stop,
        tunnel_tx,
        admission,
    } = connection;
    let close = Arc::new(ConnectionClose::default());
    let service_close = close.clone();
    let service_config = config.clone();
    let service_stop = supervisor_stop.clone();
    let service = service_fn(move |mut request| {
        let runtime = runtime.clone();
        let observation_runtime = observation_runtime.clone();
        let upgrade_runtime = upgrade_runtime.clone();
        let assets = assets.clone();
        let close = service_close.clone();
        let quota_key = quota_key.clone();
        let authority = authority.clone();
        let config = service_config.clone();
        let tunnel_tx = tunnel_tx.clone();
        let admission = admission.clone();
        let tunnel_stop = service_stop.clone();
        async move {
            let close_entire_connection = request.version() != http::Version::HTTP_2;
            let downstream_upgrade = hyper::upgrade::on(&mut request);
            let handled = if request.method() == Method::CONNECT
                && matches!(&authority, RequestAuthority::Explicit)
            {
                execute_connect_request(
                    ConnectRequestExecution {
                        config,
                        peer,
                        quota_key,
                        ingress: IngressRuntime {
                            runtime,
                            observation: observation_runtime,
                            upgrade: upgrade_runtime,
                            assets,
                        },
                        tunnel_tx,
                        admission: admission.expect("an outer explicit connection owns admission"),
                        tunnel_stop,
                    },
                    request,
                    downstream_upgrade,
                )
                .await
            } else {
                execute_request(
                    RequestExecution {
                        authority,
                        peer,
                        quota_key,
                        runtime,
                        observation_runtime,
                        upgrade_runtime,
                        assets,
                    },
                    request,
                    downstream_upgrade,
                )
                .await
            };
            let mut handled = handled;
            if handled.close_connection && close_entire_connection {
                handled
                    .response
                    .headers_mut()
                    .insert(CONNECTION, HeaderValue::from_static("close"));
                close.close();
            }
            Ok::<_, Infallible>(handled.response)
        }
    });

    let mut http = Http::new();
    http.http1_keep_alive(true);
    http.http1_header_read_timeout(config.request_header_timeout);
    http.http2_max_concurrent_streams(config.max_concurrent_streams);
    let http1 = versions.contains(&CompiledHttpVersion::Http1);
    let http2 = versions.contains(&CompiledHttpVersion::Http2);
    if http2 {
        http.http2_keep_alive_interval(config.request_header_timeout);
        http.http2_keep_alive_timeout(config.request_header_timeout);
    }
    match (http1, http2) {
        (true, false) => {
            http.http1_only(true);
        }
        (false, true) => {
            http.http2_only(true);
        }
        (true, true) => {}
        (false, false) => return,
    }

    let connection = http.serve_connection(stream, service).with_upgrades();
    tokio::pin!(connection);
    let result = tokio::select! {
        result = &mut connection => result,
        _ = close.notified() => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
        _ = wait_for_supervisor_stop(&mut supervisor_stop) => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    };
    if let Err(error) = result {
        tracing::debug!(listener = %kind, %peer, %error, "HTTP ingress connection ended");
    }
}

trait IngressIo: AsyncRead + AsyncWrite {}

impl<T> IngressIo for T where T: AsyncRead + AsyncWrite {}

type BoxedIngressIo = Box<dyn IngressIo + Send + Unpin>;

async fn prepare_ingress_transport(
    transport: &IngressTransport,
    configured_authority: ConfiguredRequestAuthority,
    configured_versions: &[CompiledHttpVersion],
    stream: tokio::net::TcpStream,
    stop: &mut watch::Receiver<SupervisorStop>,
) -> Option<(BoxedIngressIo, Vec<CompiledHttpVersion>, RequestAuthority)> {
    match transport {
        IngressTransport::Cleartext => Some((
            Box::new(stream),
            configured_versions.to_vec(),
            establish_configured_authority(configured_authority)?,
        )),
        IngressTransport::StaticTls {
            acceptor,
            handshake_timeout,
        } => {
            let deadline = Instant::now().checked_add(*handshake_timeout)?;
            let handshake = acceptor.accept(stream);
            tokio::pin!(handshake);
            let tls = tokio::select! {
                biased;
                _ = wait_for_supervisor_stop(stop) => return None,
                _ = tokio::time::sleep_until(deadline) => return None,
                result = &mut handshake => result.ok()?,
            };
            let selected =
                select_tls_http_version(tls.get_ref().1.alpn_protocol(), configured_versions)?;
            Some((
                Box::new(tls),
                vec![selected],
                establish_configured_authority(configured_authority)?,
            ))
        }
        IngressTransport::DynamicMitmTls {
            manager,
            alpn_protocols,
            handshake_timeout,
            original_destination,
        } => {
            let deadline = Instant::now().checked_add(*handshake_timeout)?;
            let destination = original_destination.resolve(&stream).ok()?;
            let hello = LazyConfigAcceptor::new(RustlsAcceptor::default(), stream);
            tokio::pin!(hello);
            let start = tokio::select! {
                biased;
                _ = wait_for_supervisor_stop(stop) => return None,
                _ = tokio::time::sleep_until(deadline) => return None,
                result = &mut hello => result.ok()?,
            };
            let sni = canonicalize_tls_server_name(start.client_hello().server_name()?).ok()?;
            let server_config = {
                let config_activation = manager.server_config_for_host(&sni, alpn_protocols);
                tokio::pin!(config_activation);
                tokio::select! {
                    biased;
                    _ = wait_for_supervisor_stop(stop) => return None,
                    _ = tokio::time::sleep_until(deadline) => return None,
                    result = &mut config_activation => result.ok()?,
                }
            };
            let handshake = start.into_stream(server_config);
            tokio::pin!(handshake);
            let tls = tokio::select! {
                biased;
                _ = wait_for_supervisor_stop(stop) => return None,
                _ = tokio::time::sleep_until(deadline) => return None,
                result = &mut handshake => result.ok()?,
            };
            let selected =
                select_tls_http_version(tls.get_ref().1.alpn_protocol(), configured_versions)?;
            Some((
                Box::new(tls),
                vec![selected],
                RequestAuthority::TransparentHttps {
                    destination_port: destination.port(),
                    sni: sni.into(),
                },
            ))
        }
    }
}

fn establish_configured_authority(
    authority: ConfiguredRequestAuthority,
) -> Option<RequestAuthority> {
    match authority {
        ConfiguredRequestAuthority::Explicit => Some(RequestAuthority::Explicit),
        ConfiguredRequestAuthority::TransparentHttp => Some(RequestAuthority::TransparentHttp),
        ConfiguredRequestAuthority::DynamicTransparentHttps => None,
    }
}

fn select_tls_http_version(
    negotiated: Option<&[u8]>,
    configured: &[CompiledHttpVersion],
) -> Option<CompiledHttpVersion> {
    let selected = match negotiated {
        Some(b"h2") => CompiledHttpVersion::Http2,
        Some(b"http/1.1") => CompiledHttpVersion::Http1,
        Some(_) => return None,
        None if configured.contains(&CompiledHttpVersion::Http1) => CompiledHttpVersion::Http1,
        None => return None,
    };
    configured.contains(&selected).then_some(selected)
}

async fn wait_for_supervisor_stop(stop: &mut watch::Receiver<SupervisorStop>) {
    if *stop.borrow() != SupervisorStop::Running {
        return;
    }
    while stop.changed().await.is_ok() {
        if *stop.borrow() != SupervisorStop::Running {
            return;
        }
    }
}

#[derive(Default)]
struct ConnectionClose {
    closed: AtomicBool,
    notify: Notify,
}

impl ConnectionClose {
    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.notify.notify_one();
        }
    }

    async fn notified(&self) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        self.notify.notified().await;
    }
}

struct HandledResponse {
    response: Response<ProxyResponseBody>,
    close_connection: bool,
}

enum UpgradeHandshakeResponse {
    Ordinary(ForwardedResponse),
    SwitchingProtocols(Response<Body>),
    Failed(StatusCode),
}

impl HandledResponse {
    fn fixed(status: StatusCode, message: &'static str, close_connection: bool) -> Self {
        let response = Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(http::header::CONTENT_LENGTH, message.len())
            .body(ProxyResponseBody::Local(Body::from(message)))
            .expect("fixed proxy responses are valid");
        Self {
            response,
            close_connection,
        }
    }
}

struct ConnectTunnelPlan {
    kind: ProxyListenerKind,
    config: IngressListenerConfig,
    target: CanonicalConnectTarget,
    server_config: Arc<rustls::ServerConfig>,
    downstream_upgrade: hyper::upgrade::OnUpgrade,
    peer: SocketAddr,
    quota_key: WireBodyQuotaKey,
    runtime: Arc<Runtime>,
    observation_runtime: Arc<ProductObservationRuntime>,
    upgrade_runtime: Arc<UpgradeRuntime>,
    assets: Arc<ProductIngressAssets>,
    stop: watch::Receiver<SupervisorStop>,
    tunnel_tx: mpsc::Sender<ConnectTunnelPlan>,
    _admission: OwnedSemaphorePermit,
}

impl ConnectTunnelPlan {
    async fn run(mut self) {
        let Some(deadline) = Instant::now().checked_add(self.config.request_header_timeout) else {
            return;
        };
        let upgraded = tokio::select! {
            biased;
            _ = wait_for_supervisor_stop(&mut self.stop) => return,
            _ = tokio::time::sleep_until(deadline) => return,
            result = &mut self.downstream_upgrade => match result {
                Ok(upgraded) => upgraded,
                Err(_) => return,
            },
        };

        let hello = LazyConfigAcceptor::new(RustlsAcceptor::default(), upgraded);
        tokio::pin!(hello);
        let start = tokio::select! {
            biased;
            _ = wait_for_supervisor_stop(&mut self.stop) => return,
            _ = tokio::time::sleep_until(deadline) => return,
            result = &mut hello => match result {
                Ok(start) => start,
                Err(_) => return,
            },
        };
        if reconcile_connect_sni(&self.target, start.client_hello().server_name()).is_err() {
            return;
        }
        let handshake = start.into_stream(self.server_config);
        tokio::pin!(handshake);
        let tls = tokio::select! {
            biased;
            _ = wait_for_supervisor_stop(&mut self.stop) => return,
            _ = tokio::time::sleep_until(deadline) => return,
            result = &mut handshake => match result {
                Ok(tls) => tls,
                Err(_) => return,
            },
        };
        let Some(selected) =
            select_tls_http_version(tls.get_ref().1.alpn_protocol(), &self.config.http_versions)
        else {
            return;
        };
        self.config.connect = None;
        serve_http_connection(HttpConnection {
            kind: self.kind,
            config: self.config,
            stream: Box::new(tls),
            versions: vec![selected],
            authority: RequestAuthority::ConnectInner(Box::new(self.target)),
            peer: self.peer,
            quota_key: self.quota_key,
            ingress: IngressRuntime {
                runtime: self.runtime,
                observation: self.observation_runtime,
                upgrade: self.upgrade_runtime,
                assets: self.assets,
            },
            supervisor_stop: self.stop,
            tunnel_tx: self.tunnel_tx,
            admission: None,
        })
        .await;
    }
}

struct ConnectRequestExecution {
    config: IngressListenerConfig,
    peer: SocketAddr,
    quota_key: WireBodyQuotaKey,
    ingress: IngressRuntime,
    tunnel_tx: mpsc::Sender<ConnectTunnelPlan>,
    admission: Arc<StdMutex<Option<OwnedSemaphorePermit>>>,
    tunnel_stop: watch::Receiver<SupervisorStop>,
}

async fn execute_connect_request(
    execution: ConnectRequestExecution,
    mut request: Request<Body>,
    downstream_upgrade: hyper::upgrade::OnUpgrade,
) -> HandledResponse {
    let ConnectRequestExecution {
        config,
        peer,
        quota_key,
        ingress:
            IngressRuntime {
                runtime,
                observation: observation_runtime,
                upgrade: upgrade_runtime,
                assets,
            },
        tunnel_tx,
        admission,
        tunnel_stop,
    } = execution;
    let policy = match request.version() {
        Version::HTTP_10 | Version::HTTP_11 => {
            config.connect.as_ref().and_then(|connect| connect.http1)
        }
        Version::HTTP_2 => {
            return HandledResponse::fixed(StatusCode::FORBIDDEN, "CONNECT denied\n", true)
        }
        _ => None,
    };
    match policy {
        Some(CompiledHttp1ConnectPolicy::Deny) => {
            return HandledResponse::fixed(StatusCode::FORBIDDEN, "CONNECT denied\n", true)
        }
        Some(CompiledHttp1ConnectPolicy::Mitm) => {}
        None => {
            return HandledResponse::fixed(StatusCode::BAD_REQUEST, "CONNECT unsupported\n", true)
        }
    }
    if !request.body().is_end_stream() {
        return HandledResponse::fixed(
            StatusCode::BAD_REQUEST,
            "CONNECT body is not allowed\n",
            true,
        );
    }

    let target = match reconcile_connect_outer_request(&mut request) {
        Ok(target) => target,
        Err(_) => {
            return HandledResponse::fixed(
                StatusCode::BAD_REQUEST,
                "invalid CONNECT target\n",
                true,
            )
        }
    };
    let prepared_destination = match assets
        .destination_guard()
        .preflight(DestinationTarget::direct(&target.url))
    {
        Ok(destination) => destination,
        Err(_) => {
            return HandledResponse::fixed(StatusCode::FORBIDDEN, "destination denied\n", true)
        }
    };
    let sanitized = match sanitize_untrusted_connect_request(request) {
        Ok(request) => request,
        Err(_) => {
            return HandledResponse::fixed(
                StatusCode::BAD_REQUEST,
                "invalid CONNECT request\n",
                true,
            )
        }
    };
    let (parts, _body, _protocol) = sanitized.into_parts();
    let Some(lease) = runtime.lease().await else {
        return HandledResponse::fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "service unavailable\n",
            true,
        );
    };
    let request_id = request_id();
    let started_at = Instant::now();
    let prepared = match prepare_request(
        &lease,
        RequestInput {
            request_id: &request_id,
            url: &target.url,
            method: &parts.method,
            peer_ip: peer.ip(),
            headers: parts.headers,
            quota_key: quota_key.clone(),
            started_at,
            upgrade_intent: false,
        },
    ) {
        Ok(prepared) => prepared,
        Err(_) => {
            return HandledResponse::fixed(
                StatusCode::INTERNAL_SERVER_ERROR,
                "request failed\n",
                true,
            )
        }
    };
    let deadline = prepared.deadline();
    if prepared.denies_without_resolution() {
        return match prepared.decide(None).await {
            Ok(RequestDecision::Deny(_)) => {
                HandledResponse::fixed(StatusCode::FORBIDDEN, "request denied\n", true)
            }
            _ => {
                HandledResponse::fixed(StatusCode::INTERNAL_SERVER_ERROR, "request failed\n", true)
            }
        };
    }
    match tokio::time::timeout_at(
        deadline,
        assets
            .destination_guard()
            .complete_resolution(prepared_destination),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => {
            return HandledResponse::fixed(StatusCode::FORBIDDEN, "destination denied\n", true)
        }
        Err(_) => {
            return HandledResponse::fixed(StatusCode::GATEWAY_TIMEOUT, "request timed out\n", true)
        }
    }
    match tokio::time::timeout_at(deadline, prepared.decide(None)).await {
        Ok(Ok(RequestDecision::Allow(allowed))) => drop(allowed),
        Ok(Ok(RequestDecision::Deny(_))) => {
            return HandledResponse::fixed(StatusCode::FORBIDDEN, "request denied\n", true)
        }
        Ok(Err(_)) => {
            return HandledResponse::fixed(
                StatusCode::INTERNAL_SERVER_ERROR,
                "request failed\n",
                true,
            )
        }
        Err(_) => {
            return HandledResponse::fixed(StatusCode::GATEWAY_TIMEOUT, "request timed out\n", true)
        }
    }
    drop(lease);

    let Some(manager) = assets.mitm().cloned() else {
        return HandledResponse::fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "service unavailable\n",
            true,
        );
    };
    let alpn_protocols = connect_alpn_protocols(&config.http_versions);
    let server_config = match tokio::time::timeout_at(
        deadline,
        manager.server_config_for_host(&target.authority.host, &alpn_protocols),
    )
    .await
    {
        Ok(Ok(config)) => config,
        Ok(Err(_)) => {
            return HandledResponse::fixed(
                StatusCode::SERVICE_UNAVAILABLE,
                "service unavailable\n",
                true,
            )
        }
        Err(_) => {
            return HandledResponse::fixed(StatusCode::GATEWAY_TIMEOUT, "request timed out\n", true)
        }
    };
    let Some(admission) = admission
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
    else {
        return HandledResponse::fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "service unavailable\n",
            true,
        );
    };
    let plan = ConnectTunnelPlan {
        kind: config.kind,
        config,
        target,
        server_config,
        downstream_upgrade,
        peer,
        quota_key,
        runtime,
        observation_runtime,
        upgrade_runtime,
        assets,
        stop: tunnel_stop,
        tunnel_tx: tunnel_tx.clone(),
        _admission: admission,
    };
    if tunnel_tx.try_send(plan).is_err() {
        return HandledResponse::fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "service unavailable\n",
            true,
        );
    }
    HandledResponse {
        response: Response::builder()
            .status(StatusCode::OK)
            .version(Version::HTTP_11)
            .body(ProxyResponseBody::Local(Body::empty()))
            .expect("CONNECT response is valid"),
        close_connection: false,
    }
}

fn connect_alpn_protocols(versions: &[CompiledHttpVersion]) -> Vec<Vec<u8>> {
    versions
        .iter()
        .map(|version| match version {
            CompiledHttpVersion::Http1 => b"http/1.1".to_vec(),
            CompiledHttpVersion::Http2 => b"h2".to_vec(),
        })
        .collect()
}

struct HttpCaptureContext {
    runtime: Arc<ProductObservationRuntime>,
    epoch: Arc<CaptureEpoch>,
    request_id: String,
    url: String,
    method: Method,
    client: SocketAddr,
    target: Option<CaptureEndpoint>,
    request_version: Version,
    max_expansion_ratio: usize,
}

impl HttpCaptureContext {
    fn new(
        runtime: Arc<ProductObservationRuntime>,
        epoch: Arc<CaptureEpoch>,
        request_id: String,
        peer: SocketAddr,
        method: Method,
        request_version: Version,
        max_expansion_ratio: usize,
    ) -> Self {
        Self {
            runtime,
            epoch,
            request_id,
            url: String::new(),
            method,
            client: peer,
            target: None,
            request_version,
            max_expansion_ratio,
        }
    }

    fn bind_target(&mut self, target: &crate::url::CanonicalUrl) {
        if !self.epoch.is_enabled() {
            return;
        }
        self.url.clone_from(&target.url);
        self.target = Some(CaptureEndpoint {
            address: Some(target.host_for_capture.clone()),
            port: Some(target.port),
        });
    }

    fn upgrade_capture_context(&self, target: &crate::url::CanonicalUrl) -> UpgradeCaptureContext {
        let mut base = self.request_record(CaptureDecision::Allow, None);
        base.url.clone_from(&target.url);
        base.target = Some(CaptureEndpoint {
            address: Some(target.host_for_capture.clone()),
            port: Some(target.port),
        });
        UpgradeCaptureContext::new(self.runtime.clone(), base, self.max_expansion_ratio)
    }

    fn captures(&self, event: CaptureEvent) -> bool {
        self.epoch
            .capture()
            .is_some_and(|policy| policy.captures(event))
    }

    fn begin(
        &self,
        event: CaptureEvent,
        record: impl FnOnce() -> CaptureRecord,
        body_headers: &HeaderMap,
    ) -> Option<CaptureSubmission> {
        HttpCaptureTap::try_begin(
            self.epoch.clone(),
            event,
            record,
            body_headers,
            self.max_expansion_ratio,
        )
        .map(|tap| {
            CaptureSubmission::new(
                self.runtime.clone(),
                tap,
                body_headers.contains_key(TRAILER),
            )
        })
    }

    fn request_record(
        &self,
        decision: CaptureDecision,
        headers: Option<&HeaderMap>,
    ) -> CaptureRecord {
        self.record(
            CaptureKind::Request,
            decision,
            self.request_version,
            headers,
            None,
            false,
        )
    }

    fn response_record(
        &self,
        decision: CaptureDecision,
        version: Version,
        headers: Option<&HeaderMap>,
        status: StatusCode,
        include_status_message: bool,
    ) -> CaptureRecord {
        self.record(
            CaptureKind::Response,
            decision,
            version,
            headers,
            Some(status),
            include_status_message,
        )
    }

    fn record(
        &self,
        kind: CaptureKind,
        decision: CaptureDecision,
        version: Version,
        headers: Option<&HeaderMap>,
        status: Option<StatusCode>,
        include_status_message: bool,
    ) -> CaptureRecord {
        CaptureRecord {
            timestamp: Utc::now().to_rfc3339(),
            request_id: self.request_id.clone(),
            kind,
            decision,
            mode: CaptureMode::HttpProxy,
            url: self.url.clone(),
            method: self.method.to_string(),
            status_code: status.map(|status| status.as_u16()),
            status_message: if include_status_message {
                status
                    .and_then(|status| status.canonical_reason())
                    .map(str::to_owned)
            } else {
                None
            },
            client: CaptureEndpoint {
                address: Some(self.client.ip().to_string()),
                port: Some(self.client.port()),
            },
            target: self.target.clone(),
            http_version: Some(http_version(version).to_owned()),
            headers: headers.map(headers_to_capture_map),
            body: None,
            body_truncated: None,
            provider_replacement_omitted: None,
            provider_replacement_size: None,
        }
    }

    fn begin_allowed_request(
        &self,
        headers: &HeaderMap,
        body_headers: &HeaderMap,
        provenance: TerminalRequestBodyProvenance,
    ) -> Option<CaptureSubmission> {
        if let TerminalRequestBodyProvenance::ProviderReplacement { size } = provenance {
            if let Some(mut submission) = self.begin(
                CaptureEvent::RequestAllowed,
                || {
                    let mut record = self.request_record(CaptureDecision::Allow, Some(headers));
                    record.mark_provider_replacement_omitted(size);
                    record
                },
                body_headers,
            ) {
                submission.abandon();
            }
            return None;
        }
        self.begin(
            CaptureEvent::RequestAllowed,
            || self.request_record(CaptureDecision::Allow, Some(headers)),
            body_headers,
        )
    }

    fn submit_denied_request(
        &self,
        headers: Option<&HeaderMap>,
        body: Option<DecisionBody>,
        provenance: TerminalRequestBodyProvenance,
    ) {
        let body_headers = body.as_ref().map(terminal_body_headers).unwrap_or_default();
        let Some(mut submission) = self.begin(
            CaptureEvent::RequestDenied,
            || {
                let mut record = self.request_record(CaptureDecision::Deny, headers);
                if let TerminalRequestBodyProvenance::ProviderReplacement { size } = provenance {
                    record.mark_provider_replacement_omitted(size);
                }
                record
            },
            &body_headers,
        ) else {
            return;
        };
        match (provenance, body) {
            (
                TerminalRequestBodyProvenance::CompleteOriginal
                | TerminalRequestBodyProvenance::CompleteWireRedacted,
                Some(body),
            ) => {
                for segment in body.decoded.segments() {
                    submission.push(segment);
                }
                submission.finish();
            }
            _ => submission.abandon(),
        }
    }

    fn fixed_response(
        &self,
        decision: CaptureDecision,
        status: StatusCode,
        message: &'static str,
        close_connection: bool,
    ) -> HandledResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&message.len().to_string())
                .expect("fixed response length is a valid header"),
        );
        let event = match decision {
            CaptureDecision::Allow => CaptureEvent::ResponseAllowed,
            CaptureDecision::Deny => CaptureEvent::ResponseDenied,
        };
        if let Some(mut submission) = self.begin(
            event,
            || self.response_record(decision, self.request_version, Some(&headers), status, true),
            &headers,
        ) {
            submission.push(message.as_bytes());
            submission.finish();
        }
        HandledResponse::fixed(status, message, close_connection)
    }

    fn deny_metadata_only(
        &self,
        status: StatusCode,
        message: &'static str,
        close_connection: bool,
    ) -> HandledResponse {
        self.submit_denied_request(None, None, TerminalRequestBodyProvenance::Unconsumed);
        self.fixed_response(CaptureDecision::Deny, status, message, close_connection)
    }
}

struct CaptureSubmission {
    runtime: Arc<ProductObservationRuntime>,
    tap: Option<HttpCaptureTap>,
    expect_trailers: bool,
}

impl CaptureSubmission {
    fn new(
        runtime: Arc<ProductObservationRuntime>,
        tap: HttpCaptureTap,
        expect_trailers: bool,
    ) -> Self {
        Self {
            runtime,
            tap: Some(tap),
            expect_trailers,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        if let Some(tap) = self.tap.as_mut() {
            tap.push(bytes);
        }
    }

    fn finish(&mut self) {
        if let Some(tap) = self.tap.take() {
            self.submit(tap.finish());
        }
    }

    fn finish_data_if_complete(&mut self, complete: bool) {
        if complete && !self.expect_trailers {
            self.finish();
        }
    }

    fn abandon(&mut self) {
        if let Some(tap) = self.tap.take() {
            self.submit(tap.abandon());
        }
    }

    fn submit(&self, job: crate::capture::CaptureArtifactJob) {
        if let Err(error) = self.runtime.try_submit_capture(job) {
            tracing::debug!(error = ?error, "capture artifact queue omitted record");
        }
    }
}

impl Drop for CaptureSubmission {
    fn drop(&mut self) {
        self.abandon();
    }
}

fn terminal_body_headers(body: &DecisionBody) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(content_type) = body
        .content_type
        .as_deref()
        .and_then(|value| HeaderValue::from_str(value).ok())
    {
        headers.insert(CONTENT_TYPE, content_type);
    }
    if let Some(content_encoding) = body
        .content_encoding
        .as_deref()
        .and_then(|value| HeaderValue::from_str(value).ok())
    {
        headers.insert(CONTENT_ENCODING, content_encoding);
    }
    headers
}

fn headers_to_capture_map(headers: &HeaderMap) -> crate::capture::HeaderMap {
    let mut captured = crate::capture::HeaderMap::new();
    for (name, value) in headers {
        let name = name.as_str().to_ascii_lowercase();
        let value = if is_sensitive_header_name(&name) {
            serde_json::Value::String(REDACTED.to_owned())
        } else if let Ok(value) = value.to_str() {
            serde_json::Value::String(value.to_owned())
        } else {
            continue;
        };
        match captured.entry(name) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(value);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => match entry.get_mut() {
                serde_json::Value::String(existing) => {
                    *entry.get_mut() = serde_json::Value::Array(vec![
                        serde_json::Value::String(existing.clone()),
                        value,
                    ]);
                }
                serde_json::Value::Array(values) => values.push(value),
                _ => unreachable!("capture headers contain only strings and string arrays"),
            },
        }
    }
    captured
}

fn http_version(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2",
        Version::HTTP_3 => "3",
        _ => "unknown",
    }
}

struct AuthorizedUpgradeExecution {
    runtime: Arc<UpgradeRuntime>,
    capture: UpgradeCaptureContext,
    binding: UpgradeBinding,
    request: SanitizedRequest<OriginRequestBody>,
    canonical: crate::url::CanonicalUrl,
    resolved: ResolvedForwardingTarget,
    destinations: Arc<crate::destination::DestinationGuard>,
    retention: GenerationRetention,
    downstream_upgrade: hyper::upgrade::OnUpgrade,
    deadline: Instant,
    response_effects: Vec<HeaderEffectPlan>,
    request_headers: HeaderMap,
    protocol: HeaderValue,
}

async fn execute_authorized_upgrade(
    execution: AuthorizedUpgradeExecution,
) -> Result<UpgradeHandshakeResponse, StatusCode> {
    let AuthorizedUpgradeExecution {
        runtime: upgrade_runtime,
        capture: upgrade_capture,
        binding,
        request,
        canonical,
        resolved,
        destinations,
        retention,
        downstream_upgrade,
        deadline,
        response_effects,
        request_headers,
        protocol,
    } = execution;
    let (response_tx, response_rx) = oneshot::channel();
    let allocation = binding.allocation;
    let wire_redaction = binding.wire_redaction;
    let task_profile = wire_redaction.clone();
    let runtime_for_task = upgrade_runtime.clone();
    upgrade_runtime
        .try_spawn_handshake(allocation, move |handshake| async move {
            let forwarded = tokio::time::timeout_at(
                deadline,
                forward_upgrade_request(request, &canonical, &retention, destinations, resolved),
            )
            .await;
            match forwarded {
                Ok(Ok(ForwardUpgradeResult::Response(mut response))) => {
                    if apply_header_effects(&response_effects, response.headers_mut()).is_err() {
                        let _ = response_tx.send(UpgradeHandshakeResponse::Failed(
                            StatusCode::INTERNAL_SERVER_ERROR,
                        ));
                        return;
                    }
                    response
                        .body_mut()
                        .bind_request_lifetime(deadline, retention);
                    let _ = response_tx.send(UpgradeHandshakeResponse::Ordinary(response));
                }
                Ok(Ok(ForwardUpgradeResult::SwitchingProtocols(upgrade))) => {
                    let (mut response, upstream_upgrade) = upgrade.into_parts();
                    if apply_header_effects(&response_effects, response.headers_mut()).is_err() {
                        let _ = response_tx.send(UpgradeHandshakeResponse::Failed(
                            StatusCode::INTERNAL_SERVER_ERROR,
                        ));
                        return;
                    }
                    let kind = match EstablishedUpgradeKind::from_handshake(
                        &protocol,
                        &request_headers,
                        response.headers(),
                        task_profile.as_ref(),
                    ) {
                        Ok(kind) => kind,
                        Err(_) => {
                            let _ = response_tx
                                .send(UpgradeHandshakeResponse::Failed(StatusCode::BAD_GATEWAY));
                            return;
                        }
                    };
                    let prepared_relay = match kind.prepare(
                        runtime_for_task.limits().relay_buffer_bytes(),
                        Some(upgrade_capture),
                    ) {
                        Ok(prepared_relay) => prepared_relay,
                        Err(_) => {
                            let _ = response_tx.send(UpgradeHandshakeResponse::Failed(
                                StatusCode::SERVICE_UNAVAILABLE,
                            ));
                            return;
                        }
                    };
                    let terminal_control =
                        UpgradeTerminalControl::new(std::future::pending::<()>, |_| async {});
                    let entry_plan =
                        UpgradeEntryPlan::new(terminal_control, move |snapshot| async move {
                            response_tx
                                .send(UpgradeHandshakeResponse::SwitchingProtocols(response))
                                .map_err(|_| UpgradeTerminalCause::DownstreamWriteFailed)?;
                            let (downstream, upstream) =
                                tokio::join!(downstream_upgrade, upstream_upgrade.complete(),);
                            let downstream = downstream
                                .map_err(|_| UpgradeTerminalCause::DownstreamWriteFailed)?;
                            let upstream =
                                upstream.map_err(|_| UpgradeTerminalCause::SetupFailed)?;
                            Ok(prepared_relay.establish(downstream, upstream, snapshot))
                        });
                    if handshake.commit(wire_redaction, entry_plan).is_err() {
                        return;
                    }
                    drop(retention);
                }
                Ok(Err(_)) => {
                    let _ =
                        response_tx.send(UpgradeHandshakeResponse::Failed(StatusCode::BAD_GATEWAY));
                }
                Err(_) => {
                    let _ = response_tx.send(UpgradeHandshakeResponse::Failed(
                        StatusCode::GATEWAY_TIMEOUT,
                    ));
                }
            }
        })
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    match tokio::time::timeout_at(deadline, response_rx).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(_)) => Err(StatusCode::SERVICE_UNAVAILABLE),
        Err(_) => Err(StatusCode::GATEWAY_TIMEOUT),
    }
}

struct RequestExecution {
    authority: RequestAuthority,
    peer: SocketAddr,
    quota_key: WireBodyQuotaKey,
    runtime: Arc<Runtime>,
    observation_runtime: Arc<ProductObservationRuntime>,
    upgrade_runtime: Arc<UpgradeRuntime>,
    assets: Arc<ProductIngressAssets>,
}

async fn execute_request(
    execution: RequestExecution,
    mut request: Request<Body>,
    downstream_upgrade: hyper::upgrade::OnUpgrade,
) -> HandledResponse {
    let RequestExecution {
        authority,
        peer,
        quota_key,
        runtime,
        observation_runtime,
        upgrade_runtime,
        assets,
    } = execution;
    let started_at = Instant::now();
    let request_id = request_id();
    let request_method = request.method().clone();
    let request_version = request.version();
    let Some(lease) = runtime.lease().await else {
        return HandledResponse::fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "service unavailable\n",
            true,
        );
    };
    let mut capture = HttpCaptureContext::new(
        observation_runtime,
        lease.observation().capture_epoch().clone(),
        request_id.clone(),
        peer,
        request_method,
        request_version,
        lease.max_content_decoding_expansion_ratio(),
    );
    let target = match authority {
        RequestAuthority::Explicit => reconcile_explicit_request(&mut request),
        RequestAuthority::TransparentHttp => reconcile_transparent_http_request(&mut request),
        RequestAuthority::ConnectInner(target) => {
            reconcile_connect_inner_request(&mut request, &target)
        }
        RequestAuthority::TransparentHttps {
            destination_port,
            sni,
        } => crate::proxy::authority::reconcile_transparent_https_request(
            &mut request,
            destination_port,
            Some(&sni),
        ),
    };
    let target = match target {
        Ok(target) => target,
        Err(_) => {
            return capture.deny_metadata_only(
                StatusCode::BAD_REQUEST,
                "invalid request target\n",
                true,
            )
        }
    };
    capture.bind_target(&target.url);
    let sanitized = match sanitize_untrusted_request(request) {
        Ok(request) => request,
        Err(error) => {
            let status = match error {
                HeaderPreparationError::UpgradeUnsupported
                | HeaderPreparationError::ConnectUnsupported => StatusCode::NOT_IMPLEMENTED,
                _ => StatusCode::BAD_REQUEST,
            };
            return capture.deny_metadata_only(status, "invalid request\n", true);
        }
    };
    let prepared_target = match preflight_forwarding_target(
        &target.url,
        &sanitized,
        lease.egress(),
        assets.destination_guard(),
    ) {
        Ok(target) => target,
        Err(_) => {
            return capture.deny_metadata_only(StatusCode::FORBIDDEN, "destination denied\n", true)
        }
    };

    let upgrade_protocol = sanitized
        .upgrade_intent()
        .map(|intent| intent.protocol().clone());
    let upgrade_intent = upgrade_protocol.is_some();
    let (mut parts, ingress_body, protocol) = sanitized.into_parts();
    let ingress_was_complete = ingress_body.is_end_stream();
    let mut body_headers = body_headers(&parts.headers);
    for value in parts.headers.get_all(CONTENT_TYPE).iter() {
        body_headers.append(CONTENT_TYPE, value.clone());
    }
    let content_type = parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let headers = std::mem::take(&mut parts.headers);
    let prepared = match prepare_request(
        &lease,
        RequestInput {
            request_id: &request_id,
            url: &target.url,
            method: &parts.method,
            peer_ip: peer.ip(),
            headers,
            quota_key,
            started_at,
            upgrade_intent,
        },
    ) {
        Ok(prepared) => prepared,
        Err(_) => {
            return capture.deny_metadata_only(
                StatusCode::INTERNAL_SERVER_ERROR,
                "request failed\n",
                true,
            )
        }
    };
    let deadline = prepared.deadline();
    if prepared.denies_without_resolution() {
        let decision = match prepared.decide(None).await {
            Ok(decision) => decision,
            Err(_) => {
                return capture.deny_metadata_only(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "request failed\n",
                    true,
                )
            }
        };
        let RequestDecision::Deny(mut denied) = decision else {
            return capture.deny_metadata_only(
                StatusCode::INTERNAL_SERVER_ERROR,
                "request failed\n",
                true,
            );
        };
        let body = denied.take_body_for_observation();
        capture.submit_denied_request(Some(&denied.common.headers), body, denied.body_provenance);
        return capture.fixed_response(
            CaptureDecision::Deny,
            StatusCode::FORBIDDEN,
            "request denied\n",
            !ingress_was_complete,
        );
    }
    let resolved = match tokio::time::timeout_at(
        deadline,
        resolve_forwarding_target(prepared_target, assets.destination_guard()),
    )
    .await
    {
        Ok(Ok(resolved)) => resolved,
        Ok(Err(_)) => {
            return capture.deny_metadata_only(StatusCode::FORBIDDEN, "destination denied\n", true)
        }
        Err(_) => {
            return capture.deny_metadata_only(
                StatusCode::GATEWAY_TIMEOUT,
                "request timed out\n",
                true,
            )
        }
    };
    let body_plan = prepared.body_read_plan();
    let (decision_body, origin_body, normalized) = match body_plan {
        HttpBodyReadPlan::Disabled => (None, Some(ingress_body), false),
        HttpBodyReadPlan::Mandatory(limits) => {
            let body = match read_mandatory_request_body(
                &body_headers,
                ingress_body,
                limits,
                lease.max_content_decoding_expansion_ratio(),
                deadline,
                prepared.body_guard(),
            )
            .await
            {
                Ok(body) => body,
                Err(error) => {
                    capture.submit_denied_request(
                        Some(prepared.headers_for_observation()),
                        None,
                        TerminalRequestBodyProvenance::Unconsumed,
                    );
                    return capture.fixed_response(
                        CaptureDecision::Deny,
                        body_failure_status(error),
                        "request body denied\n",
                        true,
                    );
                }
            };
            let encoded_len = body.encoded_len();
            (
                Some(DecisionBody {
                    content_type,
                    content_encoding: Some("identity".to_owned()),
                    encoded_len,
                    decoded: body.into_guarded_body(),
                }),
                None,
                true,
            )
        }
    };
    let decision_error_headers = capture
        .captures(CaptureEvent::RequestDenied)
        .then(|| sanitized_capture_headers(prepared.headers_for_observation()));
    let decision = match prepared.decide(decision_body).await {
        Ok(decision) => decision,
        Err(error) => {
            capture.submit_denied_request(
                decision_error_headers.as_ref(),
                None,
                error
                    .body_provenance()
                    .unwrap_or(TerminalRequestBodyProvenance::Unconsumed),
            );
            return capture.fixed_response(
                CaptureDecision::Deny,
                StatusCode::INTERNAL_SERVER_ERROR,
                "request failed\n",
                true,
            );
        }
    };
    let mut allowed = match decision {
        RequestDecision::Allow(allowed) => allowed,
        RequestDecision::Deny(mut denied) => {
            let body = denied.take_body_for_observation();
            capture.submit_denied_request(
                Some(&denied.common.headers),
                body,
                denied.body_provenance,
            );
            return capture.fixed_response(
                CaptureDecision::Deny,
                StatusCode::FORBIDDEN,
                "request denied\n",
                !normalized && !ingress_was_complete,
            );
        }
    };

    let allowed_body_headers = if normalized {
        allowed
            .body
            .as_ref()
            .map(terminal_body_headers)
            .unwrap_or_default()
    } else {
        body_headers
    };
    let mut observable =
        match prepare_observable_allowed_request(&lease, &mut allowed, origin_body, normalized) {
            Ok(prepared) => prepared,
            Err((_error, headers)) => {
                if let Some(mut submission) = capture.begin_allowed_request(
                    &headers,
                    &allowed_body_headers,
                    allowed.body_provenance,
                ) {
                    submission.abandon();
                }
                return capture.fixed_response(
                    CaptureDecision::Allow,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "request failed\n",
                    true,
                );
            }
        };
    let mut request_capture = capture.begin_allowed_request(
        &observable.headers,
        &allowed_body_headers,
        allowed.body_provenance,
    );
    if finalize_allowed_request(
        &lease,
        &request_id,
        &mut parts,
        &mut allowed,
        &mut observable,
    )
    .is_err()
    {
        if let Some(submission) = request_capture.as_mut() {
            submission.abandon();
        }
        return capture.fixed_response(
            CaptureDecision::Allow,
            StatusCode::INTERNAL_SERVER_ERROR,
            "request failed\n",
            true,
        );
    }
    let mut origin_body = observable.body;
    origin_body.set_capture(request_capture);
    let request_headers = parts.headers.clone();
    let request = SanitizedRequest::from_parts(parts, origin_body, protocol);
    if let Some(binding) = allowed.upgrade.take() {
        let Some(upgrade_protocol) = upgrade_protocol else {
            return capture.fixed_response(
                CaptureDecision::Allow,
                StatusCode::INTERNAL_SERVER_ERROR,
                "request failed\n",
                true,
            );
        };
        let retention = match lease.retain_for_operation() {
            Ok(retention) => retention,
            Err(_) => {
                return capture.fixed_response(
                    CaptureDecision::Allow,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service unavailable\n",
                    true,
                )
            }
        };
        let response_effects = allowed.response_header_effects().to_vec();
        let upgrade_capture = capture.upgrade_capture_context(&target.url);
        drop(allowed);
        drop(lease);
        let outcome = execute_authorized_upgrade(AuthorizedUpgradeExecution {
            runtime: upgrade_runtime,
            capture: upgrade_capture,
            binding,
            request,
            canonical: target.url.clone(),
            resolved,
            destinations: assets.destination_guard().clone(),
            retention,
            downstream_upgrade,
            deadline,
            response_effects,
            request_headers,
            protocol: upgrade_protocol,
        })
        .await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(StatusCode::GATEWAY_TIMEOUT) => {
                return capture.fixed_response(
                    CaptureDecision::Allow,
                    StatusCode::GATEWAY_TIMEOUT,
                    "request timed out\n",
                    true,
                )
            }
            Err(status) => {
                return capture.fixed_response(
                    CaptureDecision::Allow,
                    status,
                    "upgrade failed\n",
                    true,
                )
            }
        };
        return match outcome {
            UpgradeHandshakeResponse::Ordinary(response) => {
                let response_capture = capture.begin(
                    CaptureEvent::ResponseAllowed,
                    || {
                        capture.response_record(
                            CaptureDecision::Allow,
                            response.version(),
                            Some(response.headers()),
                            response.status(),
                            false,
                        )
                    },
                    response.headers(),
                );
                HandledResponse {
                    response: response
                        .map(|body| ProxyResponseBody::forwarded(body, response_capture)),
                    close_connection: false,
                }
            }
            UpgradeHandshakeResponse::SwitchingProtocols(response) => {
                if let Some(mut submission) = capture.begin(
                    CaptureEvent::ResponseAllowed,
                    || {
                        capture.response_record(
                            CaptureDecision::Allow,
                            response.version(),
                            Some(response.headers()),
                            response.status(),
                            false,
                        )
                    },
                    response.headers(),
                ) {
                    submission.finish();
                }
                HandledResponse {
                    response: response.map(ProxyResponseBody::Local),
                    close_connection: false,
                }
            }
            UpgradeHandshakeResponse::Failed(status) => {
                capture.fixed_response(CaptureDecision::Allow, status, "upgrade failed\n", true)
            }
        };
    }
    let mut response = match tokio::time::timeout_at(
        deadline,
        forward_request(
            request,
            &target.url,
            lease.egress(),
            assets.destination_guard(),
            resolved,
        ),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            tracing::error!(error = ?error, "upstream request failed");
            return capture.fixed_response(
                CaptureDecision::Allow,
                StatusCode::BAD_GATEWAY,
                "upstream failed\n",
                true,
            );
        }
        Err(_) => {
            return capture.fixed_response(
                CaptureDecision::Allow,
                StatusCode::GATEWAY_TIMEOUT,
                "request timed out\n",
                true,
            )
        }
    };
    let retention = match lease.retain_for_operation() {
        Ok(retention) => retention,
        Err(_) => {
            return capture.fixed_response(
                CaptureDecision::Allow,
                StatusCode::SERVICE_UNAVAILABLE,
                "service unavailable\n",
                true,
            )
        }
    };
    response
        .body_mut()
        .bind_request_lifetime(deadline, retention);
    if apply_header_effects(allowed.response_header_effects(), response.headers_mut()).is_err() {
        return capture.fixed_response(
            CaptureDecision::Allow,
            StatusCode::INTERNAL_SERVER_ERROR,
            "response failed\n",
            true,
        );
    }
    let response_capture = capture.begin(
        CaptureEvent::ResponseAllowed,
        || {
            capture.response_record(
                CaptureDecision::Allow,
                response.version(),
                Some(response.headers()),
                response.status(),
                false,
            )
        },
        response.headers(),
    );
    HandledResponse {
        response: response.map(|body| ProxyResponseBody::forwarded(body, response_capture)),
        close_connection: false,
    }
}

fn body_headers(headers: &HeaderMap) -> HeaderMap {
    let mut selected = HeaderMap::new();
    for name in [CONTENT_ENCODING, TRAILER] {
        for value in headers.get_all(&name).iter() {
            selected.append(name.clone(), value.clone());
        }
    }
    selected
}

fn sanitized_capture_headers(headers: &HeaderMap) -> HeaderMap {
    let mut sanitized = HeaderMap::new();
    for (name, value) in headers {
        if is_sensitive_header_name(name.as_str()) {
            sanitized.append(name.clone(), HeaderValue::from_static(REDACTED));
        } else {
            sanitized.append(name.clone(), value.clone());
        }
    }
    sanitized
}

#[derive(Debug, thiserror::Error)]
enum FinalRequestError {
    #[error(transparent)]
    Header(#[from] crate::policy::HeaderEffectError),
    #[error(transparent)]
    Credential(#[from] crate::credentials::CredentialError),
    #[error(transparent)]
    ProviderCredential(#[from] crate::authorization::protocol::ProviderCredentialInjectionError),
    #[error(transparent)]
    LoopMarker(#[from] InvalidLoopMarker),
    #[error("normalized request body is missing")]
    MissingNormalizedBody,
    #[error("an opaque request unexpectedly produced a normalized body")]
    UnexpectedNormalizedBody,
    #[error("normalized content type is invalid")]
    ContentType,
}

struct ObservableAllowedRequest {
    headers: HeaderMap,
    body: OriginRequestBody,
}

fn prepare_observable_allowed_request(
    lease: &crate::runtime::GenerationLease,
    allowed: &mut AllowedRequest<'_>,
    opaque_body: Option<Body>,
    normalized: bool,
) -> Result<ObservableAllowedRequest, (FinalRequestError, HeaderMap)> {
    let mut headers = std::mem::take(&mut allowed.common.headers);
    if let Err(error) = apply_header_effects(allowed.request_header_effects(), &mut headers) {
        return Err((error.into(), headers));
    }
    if let Err(error) = lease.egress().apply_request_headers(&mut headers) {
        return Err((error.into(), headers));
    }

    let body = if normalized {
        let Some(body) = allowed.body.take() else {
            return Err((FinalRequestError::MissingNormalizedBody, headers));
        };
        headers.remove(CONTENT_ENCODING);
        headers.remove(CONTENT_LENGTH);
        match body.content_type.as_deref() {
            Some(value) => {
                let value = match HeaderValue::from_str(value) {
                    Ok(value) => value,
                    Err(_) => return Err((FinalRequestError::ContentType, headers)),
                };
                headers.insert(CONTENT_TYPE, value);
            }
            None => {
                headers.remove(CONTENT_TYPE);
            }
        }
        OriginRequestBody::Guarded {
            body: GuardedHttpBody::new(body.decoded),
            capture: None,
        }
    } else {
        if allowed.body.is_some() {
            return Err((FinalRequestError::UnexpectedNormalizedBody, headers));
        }
        OriginRequestBody::Opaque {
            body: opaque_body.expect("the opaque ingress body is retained"),
            capture: None,
        }
    };
    Ok(ObservableAllowedRequest { headers, body })
}

fn finalize_allowed_request(
    lease: &crate::runtime::GenerationLease,
    request_id: &str,
    parts: &mut http::request::Parts,
    allowed: &mut AllowedRequest<'_>,
    prepared: &mut ObservableAllowedRequest,
) -> Result<(), FinalRequestError> {
    lease
        .credentials()
        .inject(allowed.credential_actions(), &mut prepared.headers)?;
    if let Some(provider_credentials) = allowed.provider_credentials.take() {
        provider_credentials.apply(&mut prepared.headers)?;
    }
    lease
        .credentials()
        .inject(lease.egress().credential_actions(), &mut prepared.headers)?;
    lease
        .safety()
        .inject_loop_marker(&mut prepared.headers, request_id)?;
    parts.headers = std::mem::take(&mut prepared.headers);
    Ok(())
}

fn body_failure_status(error: HttpBodyReadError) -> StatusCode {
    match error {
        HttpBodyReadError::UnsupportedContentEncoding
        | HttpBodyReadError::StackedContentEncoding
        | HttpBodyReadError::InvalidContentEncoding
        | HttpBodyReadError::DecoderWindowExceeded => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        HttpBodyReadError::EncodedLimitExceeded
        | HttpBodyReadError::DecodedLimitExceeded
        | HttpBodyReadError::ExpansionRatioExceeded => StatusCode::PAYLOAD_TOO_LARGE,
        HttpBodyReadError::TimedOut => StatusCode::REQUEST_TIMEOUT,
        HttpBodyReadError::ReadFailed | HttpBodyReadError::RequestTrailersUnsupported => {
            StatusCode::BAD_REQUEST
        }
        HttpBodyReadError::ResourceExhausted => StatusCode::SERVICE_UNAVAILABLE,
    }
}

fn request_id() -> String {
    use rand::RngCore;
    use std::fmt::Write;

    let mut token = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut token);
    let mut id = String::with_capacity(36);
    id.push_str("req-");
    for byte in token {
        let _ = write!(&mut id, "{byte:02x}");
    }
    id
}

enum OriginRequestBody {
    Opaque {
        body: Body,
        capture: Option<CaptureSubmission>,
    },
    Guarded {
        body: GuardedHttpBody,
        capture: Option<CaptureSubmission>,
    },
}

impl OriginRequestBody {
    fn set_capture(&mut self, submission: Option<CaptureSubmission>) {
        match self {
            Self::Opaque { capture, .. } | Self::Guarded { capture, .. } => {
                *capture = submission;
            }
        }
    }
}

enum OriginRequestData {
    Opaque(Bytes),
    Guarded(GuardedBodyData),
}

impl Buf for OriginRequestData {
    fn remaining(&self) -> usize {
        match self {
            Self::Opaque(data) => data.remaining(),
            Self::Guarded(data) => data.remaining(),
        }
    }

    fn chunk(&self) -> &[u8] {
        match self {
            Self::Opaque(data) => data.chunk(),
            Self::Guarded(data) => data.chunk(),
        }
    }

    fn advance(&mut self, count: usize) {
        match self {
            Self::Opaque(data) => data.advance(count),
            Self::Guarded(data) => data.advance(count),
        }
    }
}

impl HttpBody for OriginRequestBody {
    type Data = OriginRequestData;
    type Error = hyper::Error;

    fn poll_data(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        match self.get_mut() {
            Self::Opaque { body, capture } => {
                let exact_remaining = body.size_hint().exact();
                match Pin::new(&mut *body).poll_data(context) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Some(Ok(data))) => {
                        let data_len = data.remaining();
                        if let Some(capture) = capture.as_mut() {
                            capture.push(data.chunk());
                            capture.finish_data_if_complete(
                                body.is_end_stream() || exact_remaining == Some(data_len as u64),
                            );
                        }
                        Poll::Ready(Some(Ok(OriginRequestData::Opaque(data))))
                    }
                    Poll::Ready(Some(Err(error))) => {
                        if let Some(capture) = capture.as_mut() {
                            capture.abandon();
                        }
                        Poll::Ready(Some(Err(error)))
                    }
                    Poll::Ready(None) => {
                        if let Some(capture) = capture.as_mut() {
                            capture.finish_data_if_complete(true);
                        }
                        Poll::Ready(None)
                    }
                }
            }
            Self::Guarded { body, capture } => {
                let exact_remaining = body.size_hint().exact();
                match Pin::new(&mut *body).poll_data(context) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Some(Ok(data))) => {
                        let data_len = data.remaining();
                        if let Some(capture) = capture.as_mut() {
                            for segment in data.capture_segments() {
                                capture.push(segment);
                            }
                            capture.finish_data_if_complete(
                                body.is_end_stream() || exact_remaining == Some(data_len as u64),
                            );
                        }
                        Poll::Ready(Some(Ok(OriginRequestData::Guarded(data))))
                    }
                    Poll::Ready(Some(Err(never))) => match never {},
                    Poll::Ready(None) => {
                        if let Some(capture) = capture.as_mut() {
                            capture.finish_data_if_complete(true);
                        }
                        Poll::Ready(None)
                    }
                }
            }
        }
    }

    fn poll_trailers(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, Self::Error>> {
        match self.get_mut() {
            Self::Opaque { body, capture } => match Pin::new(body).poll_trailers(context) {
                Poll::Ready(Ok(trailers)) => {
                    if let Some(capture) = capture.as_mut() {
                        capture.finish();
                    }
                    Poll::Ready(Ok(trailers))
                }
                Poll::Ready(Err(error)) => {
                    if let Some(capture) = capture.as_mut() {
                        capture.abandon();
                    }
                    Poll::Ready(Err(error))
                }
                Poll::Pending => Poll::Pending,
            },
            Self::Guarded { body, capture } => match Pin::new(body).poll_trailers(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(trailers)) => {
                    if let Some(capture) = capture.as_mut() {
                        capture.finish();
                    }
                    Poll::Ready(Ok(trailers))
                }
                Poll::Ready(Err(never)) => match never {},
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Opaque { body, .. } => body.is_end_stream(),
            Self::Guarded { body, .. } => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Opaque { body, .. } => body.size_hint(),
            Self::Guarded { body, .. } => body.size_hint(),
        }
    }
}

enum ProxyResponseBody {
    Local(Body),
    Forwarded {
        body: ForwardBody,
        capture: Option<Box<CaptureSubmission>>,
    },
}

impl ProxyResponseBody {
    fn forwarded(body: ForwardBody, capture: Option<CaptureSubmission>) -> Self {
        Self::Forwarded {
            body,
            capture: capture.map(Box::new),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum ProxyResponseBodyError {
    #[error(transparent)]
    Local(#[from] hyper::Error),
    #[error(transparent)]
    Forwarded(#[from] ForwardBodyError),
}

impl HttpBody for ProxyResponseBody {
    type Data = Bytes;
    type Error = ProxyResponseBodyError;

    fn poll_data(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        match self.get_mut() {
            Self::Local(body) => Pin::new(body)
                .poll_data(context)
                .map(|item| item.map(|item| item.map_err(ProxyResponseBodyError::Local))),
            Self::Forwarded { body, capture } => {
                let exact_remaining = body.size_hint().exact();
                match Pin::new(&mut *body).poll_data(context) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Some(Ok(data))) => {
                        let data_len = data.remaining();
                        if let Some(capture) = capture.as_mut() {
                            capture.push(data.chunk());
                            capture.finish_data_if_complete(
                                body.is_end_stream() || exact_remaining == Some(data_len as u64),
                            );
                        }
                        Poll::Ready(Some(Ok(data)))
                    }
                    Poll::Ready(Some(Err(error))) => {
                        if let Some(capture) = capture.as_mut() {
                            capture.abandon();
                        }
                        Poll::Ready(Some(Err(ProxyResponseBodyError::Forwarded(error))))
                    }
                    Poll::Ready(None) => {
                        if let Some(capture) = capture.as_mut() {
                            capture.finish_data_if_complete(true);
                        }
                        Poll::Ready(None)
                    }
                }
            }
        }
    }

    fn poll_trailers(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, Self::Error>> {
        match self.get_mut() {
            Self::Local(body) => Pin::new(body)
                .poll_trailers(context)
                .map_err(ProxyResponseBodyError::Local),
            Self::Forwarded { body, capture } => match Pin::new(body).poll_trailers(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(trailers)) => {
                    if let Some(capture) = capture.as_mut() {
                        capture.finish();
                    }
                    Poll::Ready(Ok(trailers))
                }
                Poll::Ready(Err(error)) => {
                    if let Some(capture) = capture.as_mut() {
                        capture.abandon();
                    }
                    Poll::Ready(Err(ProxyResponseBodyError::Forwarded(error)))
                }
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Local(body) => body.is_end_stream(),
            Self::Forwarded { body, .. } => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Local(body) => body.size_hint(),
            Self::Forwarded { body, .. } => body.size_hint(),
        }
    }
}

#[cfg(test)]
// Full parent-hop topology tests live separately from the focused ingress unit suite.
mod parent_tests {
    include!("ingress_parent_tests.rs");

    #[tokio::test]
    async fn unprotected_websocket_relays_through_https_acl_proxy_parent() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let root = tempdir().unwrap();
        let origin_directory = root.path().join("origin");
        let parent_directory = root.path().join("parent");
        let child_directory = root.path().join("child");
        fs::create_dir_all(&origin_directory).unwrap();
        fs::create_dir_all(&parent_directory).unwrap();
        fs::create_dir_all(&child_directory).unwrap();

        let origin_identity = write_identity(&origin_directory, "origin", ORIGIN_HOST);
        let parent_identity = write_identity(&parent_directory, "parent", PARENT_HOST);
        let (origin, websocket_origin) = spawn_websocket_origin(&origin_identity).await;
        let (parent, parent_listener) = prebound_listener();
        let parent_product = start_product(
            &parent_directory,
            parent_config(
                parent,
                &parent_identity,
                origin,
                &origin_identity.certificate_path,
            ),
            parent_listener,
        )
        .await;
        let parent_mitm_ca = parent_directory.join("mitm/ca-cert.pem");
        let (child, child_listener) = prebound_listener();
        let child_configuration = child_config(
            child,
            parent,
            &parent_identity,
            &parent_mitm_ca,
            origin,
            false,
        )
        .replace("allow_upgrades = false", "allow_upgrades = true");
        let child_product = start_child_product(
            &child_directory,
            child_configuration,
            child_listener,
            parent,
            origin,
        )
        .await;

        let connector = tls_connector(&child_directory.join("mitm/ca-cert.pem"));
        let stream = tokio::net::TcpStream::connect(child).await.unwrap();
        let mut stream = connector
            .connect(ServerName::try_from(ORIGIN_HOST).unwrap(), stream)
            .await
            .unwrap();
        stream
            .write_all(
                format!(
                    "GET /socket HTTP/1.1\r\nHost: {ORIGIN_HOST}:{}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGVzdC13ZWJzb2NrZXQta2V5\r\n\r\n",
                    origin.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_head(&mut stream).await;
        assert!(
            response.starts_with(b"HTTP/1.1 101 "),
            "{}",
            String::from_utf8_lossy(&response)
        );
        write_websocket_frame(&mut stream, 0x1, b"client password", true)
            .await
            .unwrap();
        let reply = read_websocket_frame(&mut stream).await.unwrap();
        let seen = websocket_origin.await.unwrap();
        drop(stream);

        child_product.shutdown().await;
        parent_product.shutdown().await;
        assert_eq!(seen.opcode, 0x1);
        assert_eq!(seen.payload, b"client password");
        assert_eq!(reply.opcode, 0x1);
        assert_eq!(reply.payload, b"server password");
        assert!(child_product.shutdown_diagnostic().is_none());
        assert!(parent_product.shutdown_diagnostic().is_none());
    }
}

#[cfg(test)]
mod explicit_https_tests {
    include!("ingress_explicit_https_tests.rs");

    #[tokio::test]
    async fn explicit_https_shutdown_closes_idle_keep_alive_connection() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let (listener_address, listener) = prebound_listener();
        let origin = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            hyper::server::conn::Http::new()
                .http1_only(true)
                .serve_connection(
                    stream,
                    hyper::service::service_fn(|_request| async {
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(Body::from(
                            "keep-alive response",
                        )))
                    }),
                )
                .await
                .unwrap();
        });
        let (identity, certificate) = test_tls_identity();
        let config = strict_config(listener_address, "http1", origin_address, &identity);
        let (_directory, product) = start_product(config, listener).await;
        let connector = test_tls_connector(certificate, b"http/1.1");
        let stream = tokio::net::TcpStream::connect(listener_address)
            .await
            .unwrap();
        let mut stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        stream
            .write_all(
                format!(
                    "GET http://{origin_address}/keep-alive HTTP/1.1\r\nHost: {origin_address}\r\nConnection: keep-alive\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let head = read_http_head(&mut stream).await;
        assert!(head.starts_with(b"HTTP/1.1 200 "));
        let content_length = String::from_utf8_lossy(&head)
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap();
        let mut body = vec![0; content_length];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(body, b"keep-alive response");

        tokio::time::timeout(std::time::Duration::from_secs(2), product.shutdown())
            .await
            .expect("explicit HTTPS shutdown must join an idle keep-alive connection");
        let mut byte = [0_u8; 1];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        origin_task.await.unwrap();
        assert!(StdTcpListener::bind(listener_address).is_ok());
    }

    #[tokio::test]
    async fn explicit_https_shutdown_interrupts_stalled_client_hello() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let (listener_address, listener) = prebound_listener();
        let origin_address = SocketAddr::from(([192, 0, 2, 10], 80));
        let (identity, _certificate) = test_tls_identity();
        let config = strict_config(listener_address, "http1", origin_address, &identity).replacen(
            "http_versions = [\"http1\"]",
            "http_versions = [\"http1\"]\nhandshake_timeout = \"1h\"",
            1,
        );
        let (_directory, product) = start_product(config, listener).await;
        let mut stalled = tokio::net::TcpStream::connect(listener_address)
            .await
            .unwrap();
        tokio::task::yield_now().await;

        tokio::time::timeout(std::time::Duration::from_secs(2), product.shutdown())
            .await
            .expect("explicit HTTPS shutdown must interrupt a stalled ClientHello");
        let mut byte = [0_u8; 1];
        assert_eq!(stalled.read(&mut byte).await.unwrap(), 0);
        assert!(StdTcpListener::bind(listener_address).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::net::{Ipv4Addr, TcpListener as StdTcpListener};
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use hyper::body::to_bytes;
    use hyper::client::conn;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::{Certificate, ClientConfig, RootCertStore, ServerName};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;
    use tokio_rustls::TlsConnector;

    use super::*;
    use crate::activation::runner::ProductRuntime;
    use crate::config::load_and_compile_exact_config;
    use crate::destination::{
        DestinationFacts, DestinationGuard, DestinationResolveError, DestinationResolver,
        LocalAddressSnapshot, LocalAddressSource, ResolveFuture,
    };

    struct ChannelFailureObserver(StdMutex<Option<oneshot::Sender<Arc<ProxySupervisorFailure>>>>);

    impl ProxySupervisorFailureObserver for ChannelFailureObserver {
        fn failed(&self, error: Arc<ProxySupervisorFailure>) {
            if let Some(sender) = self.0.lock().unwrap().take() {
                sender.send(error).ok();
            }
        }
    }

    fn prebound_listeners<const N: usize>() -> ([SocketAddr; N], Vec<StdTcpListener>) {
        let listeners = (0..N)
            .map(|_| StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
            .collect::<Vec<_>>();
        let addresses = listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        (addresses, listeners)
    }

    async fn product(
        text: String,
        listeners: Vec<StdTcpListener>,
    ) -> (tempfile::TempDir, Arc<ProductRuntime>) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("acl-proxy.toml");
        fs::write(&path, text).unwrap();
        let loaded = load_and_compile_exact_config(&path).unwrap();
        let product = ProductRuntime::prepare_from_prebound(loaded, listeners)
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        let mut starter = ProductProxySupervisorStarter::new(
            product.runtime().clone(),
            product.observation_runtime().clone(),
            product.upgrade_runtime(),
        );
        product.start_proxy_supervisors(&mut starter).await.unwrap();
        (directory, product)
    }

    async fn product_with_original_destination(
        text: String,
        listeners: Vec<StdTcpListener>,
        resolver: Arc<dyn OriginalDestinationResolver>,
    ) -> (tempfile::TempDir, Arc<ProductRuntime>) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("acl-proxy.toml");
        fs::write(&path, text).unwrap();
        let loaded = load_and_compile_exact_config(&path).unwrap();
        let product = ProductRuntime::prepare_from_prebound(loaded, listeners)
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        let mut starter = ProductProxySupervisorStarter::with_original_destination_resolver(
            product.runtime().clone(),
            product.observation_runtime().clone(),
            product.upgrade_runtime(),
            resolver,
        );
        product.start_proxy_supervisors(&mut starter).await.unwrap();
        (directory, product)
    }

    async fn product_with_destination_guard(
        text: String,
        listeners: Vec<StdTcpListener>,
        destination_guard: Arc<DestinationGuard>,
    ) -> (
        tempfile::TempDir,
        Arc<ProductRuntime>,
        Arc<ProductIngressAssets>,
    ) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("acl-proxy.toml");
        fs::write(&path, text).unwrap();
        let loaded = load_and_compile_exact_config(&path).unwrap();
        let assets = ProductIngressAssets::with_destination_guard(
            &loaded.compiled.static_config,
            destination_guard,
        )
        .unwrap();
        let product = ProductRuntime::prepare_from_prebound(loaded, listeners)
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        (directory, product, assets)
    }

    #[derive(Default)]
    struct EmptyLocalAddresses;

    impl LocalAddressSource for EmptyLocalAddresses {
        fn snapshot(&self) -> io::Result<LocalAddressSnapshot> {
            Ok(LocalAddressSnapshot::default())
        }
    }

    struct ResolverDrop(Arc<AtomicBool>);

    impl Drop for ResolverDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    struct PendingResolver {
        calls: AtomicUsize,
        dropped: Arc<AtomicBool>,
    }

    impl PendingResolver {
        fn new() -> (Arc<Self>, Arc<AtomicBool>) {
            let dropped = Arc::new(AtomicBool::new(false));
            (
                Arc::new(Self {
                    calls: AtomicUsize::new(0),
                    dropped: dropped.clone(),
                }),
                dropped,
            )
        }
    }

    impl DestinationResolver for PendingResolver {
        fn resolve(&self, _host: &str, _port: u16, _max_addresses: usize) -> ResolveFuture<'_> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let dropped = self.dropped.clone();
            Box::pin(async move {
                let _drop = ResolverDrop(dropped);
                std::future::pending::<Result<Vec<SocketAddr>, DestinationResolveError>>().await
            })
        }
    }

    struct DelayedResolver {
        calls: AtomicUsize,
        delay: Duration,
        endpoint: SocketAddr,
    }

    impl DestinationResolver for DelayedResolver {
        fn resolve(&self, _host: &str, _port: u16, _max_addresses: usize) -> ResolveFuture<'_> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let delay = self.delay;
            let endpoint = self.endpoint;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Ok(vec![endpoint])
            })
        }
    }

    fn test_destination_guard(
        proxy: SocketAddr,
        resolver: Arc<dyn DestinationResolver>,
    ) -> Arc<DestinationGuard> {
        let facts = DestinationFacts::for_test([proxy], None, None, 8).unwrap();
        Arc::new(DestinationGuard::with_sources(
            facts,
            resolver,
            Arc::new(EmptyLocalAddresses),
        ))
    }

    async fn execute_direct(
        product: &Arc<ProductRuntime>,
        assets: Arc<ProductIngressAssets>,
        mut request: Request<Body>,
    ) -> HandledResponse {
        let peer = SocketAddr::from(([192, 0, 2, 44], 41_000));
        let downstream_upgrade = hyper::upgrade::on(&mut request);
        execute_request(
            RequestExecution {
                authority: RequestAuthority::Explicit,
                peer,
                quota_key: WireBodyQuotaKey::from_peer(peer.ip(), |_| false),
                runtime: product.runtime().clone(),
                observation_runtime: product.observation_runtime().clone(),
                upgrade_runtime: product.upgrade_runtime(),
                assets,
            },
            request,
            downstream_upgrade,
        )
        .await
    }

    fn base_config(listener: SocketAddr, listener_table: &str, policy: &str) -> String {
        format!(
            r#"schema_version = 3

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.{listener_table}]
bind = "{listener}"
http_versions = ["http1"]

[egress]
route = "direct"

[egress.origin_tls]
trust = "system"
http_versions = ["http1"]

[[egress.request_headers]]
operation = "append"
when = "always"
name = "x-mutation-order"
value = "global"

[safety.loop_detection]
inject = true
header = "x-test-loop"

{policy}
"#
        )
    }

    async fn send_request(address: SocketAddr, request: Request<Body>) -> Response<Body> {
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) = conn::handshake(stream).await.unwrap();
        let driver = tokio::spawn(connection);
        let response = sender.send_request(request).await.unwrap();
        drop(sender);
        let (parts, body) = response.into_parts();
        let body = to_bytes(body).await.unwrap();
        driver.await.unwrap().unwrap();
        Response::from_parts(parts, Body::from(body))
    }

    async fn read_http_head(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut byte))
                .await
                .expect("HTTP head read timed out")
                .expect("HTTP head ended early");
            head.push(byte[0]);
            assert!(head.len() <= 32 * 1024, "HTTP head exceeded the test bound");
        }
        head
    }

    #[derive(Debug)]
    struct TestWebSocketFrame {
        fin: bool,
        opcode: u8,
        payload: Vec<u8>,
    }

    fn websocket_frame(fin: bool, opcode: u8, payload: &[u8], masked: bool) -> Vec<u8> {
        assert!(payload.len() < 126, "test WebSocket payload is too large");
        let mut frame = vec![(u8::from(fin) << 7) | opcode];
        frame.push((u8::from(masked) << 7) | payload.len() as u8);
        if masked {
            let mask = [0x11, 0x22, 0x33, 0x44];
            frame.extend_from_slice(&mask);
            frame.extend(
                payload
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ mask[index % mask.len()]),
            );
        } else {
            frame.extend_from_slice(payload);
        }
        frame
    }

    async fn read_websocket_frame(
        stream: &mut (impl AsyncRead + Unpin),
    ) -> io::Result<TestWebSocketFrame> {
        let mut header = [0_u8; 2];
        stream.read_exact(&mut header).await?;
        let fin = header[0] & 0x80 != 0;
        let opcode = header[0] & 0x0f;
        let masked = header[1] & 0x80 != 0;
        let length = usize::from(header[1] & 0x7f);
        if length >= 126 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "extended WebSocket payload is unsupported in this test",
            ));
        }
        let mut mask = [0_u8; 4];
        if masked {
            stream.read_exact(&mut mask).await?;
        }
        let mut payload = vec![0_u8; length];
        stream.read_exact(&mut payload).await?;
        if masked {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % mask.len()];
            }
        }
        Ok(TestWebSocketFrame {
            fin,
            opcode,
            payload,
        })
    }

    fn test_tls_identity() -> (tempfile::TempDir, Vec<u8>) {
        let directory = tempdir().unwrap();
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        fs::write(directory.path().join("server.pem"), certificate.pem()).unwrap();
        fs::write(directory.path().join("server-key.pem"), key.serialize_pem()).unwrap();
        (directory, certificate.der().to_vec())
    }

    fn test_tls_connector(certificate: Vec<u8>, alpn: Vec<Vec<u8>>) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        roots.add(&Certificate(certificate)).unwrap();
        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = alpn;
        TlsConnector::from(Arc::new(config))
    }

    fn read_first_pem_certificate(path: &std::path::Path) -> Vec<u8> {
        let mut reader = std::io::BufReader::new(fs::File::open(path).unwrap());
        rustls_pemfile::certs(&mut reader).unwrap().remove(0)
    }

    struct FixedOriginalDestination(SocketAddr);

    impl OriginalDestinationResolver for FixedOriginalDestination {
        fn resolve(
            &self,
            _socket: &tokio::net::TcpStream,
        ) -> Result<SocketAddr, crate::proxy::original_destination::OriginalDestinationError>
        {
            Ok(self.0)
        }
    }

    fn capture_config() -> &'static str {
        r#"
[redaction.profiles.capture]
replacement = "[MASKED]"
rules = [{ literals = ["capture-redaction-sentinel"], payloads = "both" }]

[observation.capture]
events = ["request.allowed", "response.allowed", "request.denied", "response.denied"]
redaction_profile = "capture"
directory = "captures"
max_body_bytes = 1048576
max_inflight_body_bytes = 134217728
max_pending_records = 32
max_files = 32
max_total_bytes = 16777216
"#
    }

    #[tokio::test]
    async fn immediate_policy_denial_precedes_dns_resolution() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let (resolver, dropped) = PendingResolver::new();
        let guard = test_destination_guard(proxy, resolver.clone());
        let policy = r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"
"#;
        let (_directory, product, assets) = product_with_destination_guard(
            base_config(proxy, "explicit_http", policy),
            listeners,
            guard,
        )
        .await;

        let handled = tokio::time::timeout(
            Duration::from_secs(1),
            execute_direct(
                &product,
                assets,
                Request::builder()
                    .uri("http://deny.example/resource")
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .expect("policy denial must not poll the pending resolver");

        assert_eq!(handled.response.status(), StatusCode::FORBIDDEN);
        assert_eq!(resolver.calls.load(Ordering::Acquire), 0);
        assert!(!dropped.load(Ordering::Acquire));
        product.shutdown().await;
    }

    #[tokio::test]
    async fn fixed_policy_denial_and_upstream_failure_wire_response_corpus() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let closed = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let unavailable_origin = closed.local_addr().unwrap();
        drop(closed);
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "allow-unavailable-origin"
decision = "allow"
urls = ["http://{unavailable_origin}/failure"]
"#,
        );
        let (_directory, product) =
            product(base_config(proxy, "explicit_http", &policy), listeners).await;

        let corpus = [
            (
                "http://deny.example/resource".to_owned(),
                StatusCode::FORBIDDEN,
                b"request denied\n".as_slice(),
            ),
            (
                format!("http://{unavailable_origin}/failure"),
                StatusCode::BAD_GATEWAY,
                b"upstream failed\n".as_slice(),
            ),
        ];
        for (uri, expected_status, expected_body) in corpus {
            let response = send_request(
                proxy,
                Request::builder().uri(uri).body(Body::empty()).unwrap(),
            )
            .await;
            assert_eq!(response.status(), expected_status);
            assert_eq!(
                response.headers().get(CONTENT_TYPE).unwrap(),
                "text/plain; charset=utf-8"
            );
            assert_eq!(to_bytes(response.into_body()).await.unwrap(), expected_body);
        }

        product.shutdown().await;
    }

    #[tokio::test]
    async fn matched_rule_deadline_cancels_pending_resolution() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let (resolver, dropped) = PendingResolver::new();
        let guard = test_destination_guard(proxy, resolver.clone());
        let policy = r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "short-resolution"
decision = "allow"
urls = ["http://slow.example/**"]
request_timeout = "40ms"
"#;
        let (_directory, product, assets) = product_with_destination_guard(
            base_config(proxy, "explicit_http", policy),
            listeners,
            guard,
        )
        .await;

        let handled = tokio::time::timeout(
            Duration::from_secs(1),
            execute_direct(
                &product,
                assets,
                Request::builder()
                    .uri("http://slow.example/resource")
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .expect("the matched rule deadline must bound resolution");

        assert_eq!(handled.response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(resolver.calls.load(Ordering::Acquire), 1);
        assert!(dropped.load(Ordering::Acquire));
        product.shutdown().await;
    }

    #[tokio::test]
    async fn matched_rule_deadline_can_exceed_service_default_during_resolution() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            Http::new()
                .http1_only(true)
                .serve_connection(
                    stream,
                    service_fn(|_request| async {
                        Ok::<_, Infallible>(Response::new(Body::from("resolved")))
                    }),
                )
                .await
                .unwrap();
        });
        let resolver = Arc::new(DelayedResolver {
            calls: AtomicUsize::new(0),
            delay: Duration::from_millis(75),
            endpoint: origin,
        });
        let guard = test_destination_guard(proxy, resolver.clone());
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "long-resolution"
decision = "allow"
urls = ["http://slow.example:{}/resource"]
request_timeout = "500ms"
"#,
            origin.port()
        );
        let config = base_config(proxy, "explicit_http", &policy).replacen(
            "request_timeout = \"5s\"",
            "request_timeout = \"20ms\"",
            1,
        );
        let (_directory, product, assets) =
            product_with_destination_guard(config, listeners, guard).await;

        let handled = execute_direct(
            &product,
            assets,
            Request::builder()
                .uri(format!("http://slow.example:{}/resource", origin.port()))
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(handled.response.status(), StatusCode::OK);
        assert_eq!(resolver.calls.load(Ordering::Acquire), 1);
        assert_eq!(
            to_bytes(handled.response.into_body()).await.unwrap(),
            "resolved"
        );
        product.shutdown().await;
        origin_task.await.unwrap();
    }

    fn read_capture_records(directory: &std::path::Path) -> Vec<CaptureRecord> {
        let mut records = fs::read_dir(directory.join("captures"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|value| value == "json")
            })
            .map(|entry| {
                serde_json::from_slice::<CaptureRecord>(&fs::read(entry.path()).unwrap()).unwrap()
            })
            .collect::<Vec<_>>();
        records.sort_by_key(|record| match record.kind {
            CaptureKind::Request => 0,
            CaptureKind::Response => 1,
        });
        records
    }

    async fn captured_success_round_trip() -> (Vec<CaptureRecord>, HeaderMap) {
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (headers_tx, headers_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            let headers_tx = Arc::new(StdMutex::new(Some(headers_tx)));
            Http::new()
                .http1_only(true)
                .serve_connection(
                    stream,
                    service_fn(move |request: Request<Body>| {
                        let headers_tx = headers_tx.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            assert_eq!(
                                to_bytes(body).await.unwrap(),
                                "request-capture-redaction-sentinel-body"
                            );
                            headers_tx
                                .lock()
                                .unwrap()
                                .take()
                                .unwrap()
                                .send(parts.headers)
                                .ok();
                            let (mut response_sender, response_body) = Body::channel();
                            tokio::spawn(async move {
                                response_sender
                                    .send_data(Bytes::from_static(b"response-"))
                                    .await
                                    .unwrap();
                                response_sender
                                    .send_data(Bytes::from_static(b"body"))
                                    .await
                                    .unwrap();
                            });
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .header(http::header::SET_COOKIE, "origin-cookie-secret")
                                    .header("x-origin-response", "visible")
                                    .body(response_body)
                                    .unwrap(),
                            )
                        }
                    }),
                )
                .await
                .unwrap();
        });
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "capture-allow"
decision = "allow"
urls = ["http://{origin}/capture"]
methods = ["POST"]

[[policy.rules.request_headers]]
operation = "set"
when = "always"
name = "x-rule-visible"
value = "yes"

{}"#,
            capture_config()
        );
        let config = base_config(proxy, "explicit_http", &policy);
        let (directory, product) = product(config, listeners).await;
        let (mut body_sender, body) = Body::channel();
        body_sender
            .send_data(Bytes::from_static(
                b"request-capture-redaction-sentinel-body",
            ))
            .await
            .unwrap();
        drop(body_sender);
        let response = send_request(
            proxy,
            Request::builder()
                .method(http::Method::POST)
                .uri(format!("http://{origin}/capture?secret=query"))
                .header(http::header::AUTHORIZATION, "Bearer inbound-secret")
                .header(http::header::COOKIE, "cookie-secret")
                .body(body)
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body()).await.unwrap(),
            "response-body"
        );
        let origin_headers = headers_rx.await.unwrap();
        product.shutdown().await;
        origin_task.await.unwrap();
        (read_capture_records(directory.path()), origin_headers)
    }

    #[tokio::test]
    async fn active_executor_capture_event_and_secret_boundary_matrix() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;

        let (records, origin_headers) = captured_success_round_trip().await;
        assert_eq!(records.len(), 2);
        let request = &records[0];
        let response = &records[1];
        assert_eq!(
            (request.kind, request.decision),
            (CaptureKind::Request, CaptureDecision::Allow)
        );
        assert_eq!(
            (response.kind, response.decision),
            (CaptureKind::Response, CaptureDecision::Allow)
        );
        assert_eq!(
            request.decode_body_bytes().unwrap(),
            b"request-[MASKED]-body"
        );
        assert_eq!(response.decode_body_bytes().unwrap(), b"response-body");
        assert!(!request.url.contains("secret=query"));
        let request_headers = request.headers.as_ref().unwrap();
        assert_eq!(request_headers["authorization"], REDACTED);
        assert_eq!(request_headers["cookie"], REDACTED);
        assert_eq!(request_headers["x-rule-visible"], "yes");
        assert_eq!(request_headers["x-mutation-order"], "global");
        assert!(!request_headers.contains_key("x-test-loop"));
        assert!(origin_headers.contains_key("x-test-loop"));
        assert_eq!(response.headers.as_ref().unwrap()["set-cookie"], REDACTED);
        assert!(response.status_message.is_none());

        let ([proxy], listeners) = prebound_listeners::<1>();
        let denied_origin = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let denied_origin_address = denied_origin.local_addr().unwrap();
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

{}"#,
            capture_config(),
        );
        let (directory, runtime_product) =
            product(base_config(proxy, "explicit_http", &policy), listeners).await;
        let response = send_request(
            proxy,
            Request::builder()
                .method(http::Method::POST)
                .uri(format!("http://{denied_origin_address}/denied"))
                .body(Body::from("must-not-be-drained"))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        runtime_product.shutdown().await;
        drop(denied_origin);
        let records = read_capture_records(directory.path());
        assert_eq!(records.len(), 2);
        assert!(records
            .iter()
            .all(|record| record.decision == CaptureDecision::Deny));
        assert!(records
            .iter()
            .find(|record| record.kind == CaptureKind::Request && record.url.ends_with("/denied"))
            .unwrap()
            .body
            .is_none());
        assert_eq!(
            records
                .iter()
                .find(|record| {
                    record.kind == CaptureKind::Response && record.url.ends_with("/denied")
                })
                .unwrap()
                .decode_body_bytes()
                .unwrap(),
            b"request denied\n"
        );

        let ([proxy], listeners) = prebound_listeners::<1>();
        let closed = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let origin = closed.local_addr().unwrap();
        drop(closed);
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "post-allow-failure"
decision = "allow"
urls = ["http://{origin}/failure"]

[[policy.rules]]
id = "observable-header-failure"
decision = "allow"
urls = ["http://{origin}/header-failure"]

[[policy.rules.request_headers]]
operation = "replace"
when = "always"
name = "x-large"
search = "x"
replace = "xx"

{}"#,
            capture_config()
        );
        let (directory, runtime_product) =
            product(base_config(proxy, "explicit_http", &policy), listeners).await;
        let response = send_request(
            proxy,
            Request::builder()
                .uri(format!("http://{origin}/failure"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let response = send_request(
            proxy,
            Request::builder()
                .uri(format!("http://{origin}/header-failure"))
                .header(
                    "x-large",
                    HeaderValue::from_bytes(&vec![b'x'; 64 * 1024]).unwrap(),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        runtime_product.shutdown().await;
        let records = read_capture_records(directory.path());
        assert_eq!(records.len(), 4);
        assert!(records
            .iter()
            .all(|record| record.decision == CaptureDecision::Allow));
        assert_eq!(
            records
                .iter()
                .find(|record| {
                    record.kind == CaptureKind::Response && record.url.ends_with("/failure")
                })
                .unwrap()
                .status_code,
            Some(502)
        );
        let header_failure = records
            .iter()
            .find(|record| {
                record.kind == CaptureKind::Request && record.url.ends_with("/header-failure")
            })
            .unwrap();
        assert_eq!(
            header_failure.headers.as_ref().unwrap()["x-large"]
                .as_str()
                .unwrap()
                .len(),
            64 * 1024
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn capture_profile_redacts_all_denial_paths() {
        use std::os::unix::fs::PermissionsExt;

        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let provider_directory = tempdir().unwrap();
        let provider_path = provider_directory.path().join("replacement.sh");
        fs::write(
            &provider_path,
            r#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf "%s" "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  if [ -n "$id" ]; then
    case "$line" in
      *complete-denied*) printf '{"id":"%s","type":"response","decision":"deny"}\n' "$id" ;;
      *) printf '{"id":"%s","type":"response","decision":"allow","values":{"token":"secret-marker"},"requestBody":{"encoding":"base64","contentType":"text/plain","data":"cmVwbGFjZW1lbnQgc2VjcmV0"}}\n' "$id" ;;
    esac
  fi
done
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&provider_path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&provider_path, permissions).unwrap();

        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (origin_tx, origin_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            let origin_tx = Arc::new(StdMutex::new(Some(origin_tx)));
            Http::new()
                .http1_only(true)
                .serve_connection(
                    stream,
                    service_fn(move |request: Request<Body>| {
                        let origin_tx = origin_tx.clone();
                        async move {
                            let authorization =
                                request.headers().get(http::header::AUTHORIZATION).cloned();
                            let body = to_bytes(request.into_body()).await.unwrap();
                            origin_tx
                                .lock()
                                .unwrap()
                                .take()
                                .unwrap()
                                .send((authorization, body))
                                .ok();
                            Ok::<_, Infallible>(Response::new(Body::from("accepted")))
                        }
                    }),
                )
                .await
                .unwrap();
        });
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[authorization.providers.replacing]
kind = "process"
command = "{}"
timeout = "2s"
retire_timeout = "6s"
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 128
max_decoded_request_body_bytes = 128
max_stdout_line_bytes = 1024

[authorization.providers.replacing.outputs.token]
kind = "bearer"
required = true

[redaction.profiles.wire]
replacement = "[MASKED]"
max_body_bytes = 128
max_decoded_body_bytes = 128
rules = [{{ literals = ["secret"], payloads = "text" }}]

[policy]
default = "deny"

[[policy.rules]]
id = "replacement"
decision = "delegate"
urls = ["http://{origin}/replacement", "http://{origin}/loop"]
methods = ["POST"]
authorization_provider = "replacing"
redaction_profile = "wire"

[[policy.rules]]
id = "complete-denied"
decision = "delegate"
urls = ["http://{origin}/complete-denied", "http://{origin}/too-large"]
methods = ["POST"]
authorization_provider = "replacing"
redaction_profile = "wire"

{}"#,
            provider_path.display(),
            capture_config().replace(
                "literals = [\"capture-redaction-sentinel\"]",
                "literals = [\"capture-redaction-sentinel\", \"denied\", \"invalid\"]",
            ),
        );
        let (directory, product) =
            product(base_config(proxy, "explicit_http", &policy), listeners).await;
        let response = send_request(
            proxy,
            Request::builder()
                .method(http::Method::POST)
                .uri(format!("http://{origin}/replacement"))
                .body(Body::from("original"))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let (authorization, body) = origin_rx.await.unwrap();
        assert_eq!(authorization.unwrap(), "Bearer secret-marker");
        assert_eq!(body, "replacement [MASKED]");
        let response = send_request(
            proxy,
            Request::builder()
                .method(http::Method::POST)
                .uri(format!("http://{origin}/complete-denied"))
                .body(Body::from(
                    "capture-redaction-sentinel complete original body",
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let default_denied = send_request(
            proxy,
            Request::builder()
                .method(http::Method::POST)
                .uri(format!("http://{origin}/default-denied"))
                .body(Body::from("capture-redaction-sentinel unread default body"))
                .unwrap(),
        )
        .await;
        assert_eq!(default_denied.status(), StatusCode::FORBIDDEN);

        let loop_denied = send_request(
            proxy,
            Request::builder()
                .method(http::Method::POST)
                .uri(format!("http://{origin}/loop"))
                .header("x-test-loop", "already-seen")
                .body(Body::from("capture-redaction-sentinel unread loop body"))
                .unwrap(),
        )
        .await;
        assert_eq!(loop_denied.status(), StatusCode::FORBIDDEN);

        let limit_denied = send_request(
            proxy,
            Request::builder()
                .method(http::Method::POST)
                .uri(format!("http://{origin}/too-large"))
                .body(Body::from(vec![b'x'; 256]))
                .unwrap(),
        )
        .await;
        assert_eq!(limit_denied.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let destination_denied = send_request(
            proxy,
            Request::builder()
                .uri(format!("http://{proxy}/destination-denied"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(destination_denied.status(), StatusCode::FORBIDDEN);

        let authority_denied = send_request(
            proxy,
            Request::builder()
                .method(http::Method::POST)
                .uri(format!("http://{origin}/authority-denied"))
                .header(http::header::HOST, "example.invalid")
                .body(Body::from(
                    "capture-redaction-sentinel unread authority body",
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(authority_denied.status(), StatusCode::BAD_REQUEST);

        let invalid_url_denied = send_request(
            proxy,
            Request::builder()
                .method(http::Method::POST)
                .uri(format!("http://user@{origin}/invalid-url"))
                .body(Body::from("capture-redaction-sentinel unread URL body"))
                .unwrap(),
        )
        .await;
        assert_eq!(invalid_url_denied.status(), StatusCode::BAD_REQUEST);
        product.shutdown().await;
        origin_task.await.unwrap();

        let records = read_capture_records(directory.path());
        let request = records
            .iter()
            .find(|record| {
                record.kind == CaptureKind::Request && record.url.ends_with("/replacement")
            })
            .unwrap();
        assert_eq!(request.provider_replacement_omitted, Some(true));
        assert_eq!(
            request.provider_replacement_size,
            Some(b"replacement secret".len())
        );
        assert!(request.body.is_none());
        assert!(!request
            .headers
            .as_ref()
            .unwrap()
            .contains_key("authorization"));
        let denied = records
            .iter()
            .find(|record| {
                record.kind == CaptureKind::Request && record.url.ends_with("/complete-denied")
            })
            .unwrap();
        assert_eq!(denied.decision, CaptureDecision::Deny);
        assert_eq!(
            denied.decode_body_bytes().unwrap(),
            b"[MASKED] complete original body"
        );
        assert!(!denied
            .decode_body_bytes()
            .unwrap()
            .windows(b"capture-redaction-sentinel".len())
            .any(|window| window == b"capture-redaction-sentinel"));

        for path in [
            "/default-denied",
            "/loop",
            "/too-large",
            "/destination-denied",
        ] {
            let request = records
                .iter()
                .find(|record| record.kind == CaptureKind::Request && record.url.ends_with(path))
                .unwrap_or_else(|| panic!("missing request capture for {path}"));
            assert_eq!(request.decision, CaptureDecision::Deny);
            assert!(
                request.body.is_none(),
                "an unread denial body must not be drained for capture: {path}"
            );

            let response = records
                .iter()
                .find(|record| record.kind == CaptureKind::Response && record.url.ends_with(path))
                .unwrap_or_else(|| panic!("missing response capture for {path}"));
            assert_eq!(response.decision, CaptureDecision::Deny);
            let response_body = response.decode_body_bytes().unwrap();
            assert!(response_body
                .windows(b"[MASKED]".len())
                .any(|window| window == b"[MASKED]"));
            assert!(!response_body
                .windows(b"denied".len())
                .any(|window| window == b"denied"));
        }

        let pre_policy_records = records
            .iter()
            .filter(|record| record.url.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(
            pre_policy_records.len(),
            4,
            "URL and authority denials must each capture request and response metadata"
        );
        for record in pre_policy_records {
            assert_eq!(record.decision, CaptureDecision::Deny);
            match record.kind {
                CaptureKind::Request => assert!(record.body.is_none()),
                CaptureKind::Response => {
                    assert_eq!(record.status_code, Some(StatusCode::BAD_REQUEST.as_u16()));
                    assert_eq!(
                        record.decode_body_bytes().unwrap(),
                        b"[MASKED] request target\n"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn capture_only_decoding_preserves_upstream_content_coding() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (captured_tx, captured_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            let captured_tx = Arc::new(StdMutex::new(Some(captured_tx)));
            Http::new()
                .http1_only(true)
                .serve_connection(
                    stream,
                    service_fn(move |request: Request<Body>| {
                        let captured_tx = captured_tx.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let body = to_bytes(body).await.unwrap();
                            captured_tx
                                .lock()
                                .unwrap()
                                .take()
                                .unwrap()
                                .send((parts.headers, body))
                                .ok();
                            Ok::<_, Infallible>(Response::new(Body::from("accepted")))
                        }
                    }),
                )
                .await
                .unwrap();
        });
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "capture-only"
decision = "allow"
urls = ["http://{origin}/compressed"]
methods = ["POST"]

{}"#,
            capture_config()
        );
        let (directory, product) =
            product(base_config(proxy, "explicit_http", &policy), listeners).await;
        let plain = b"opaque capture-redaction-sentinel payload";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plain).unwrap();
        let encoded = encoder.finish().unwrap();
        let response = send_request(
            proxy,
            Request::builder()
                .method(http::Method::POST)
                .uri(format!("http://{origin}/compressed"))
                .header(CONTENT_TYPE, "application/json")
                .header(CONTENT_ENCODING, "gzip")
                .header(CONTENT_LENGTH, encoded.len().to_string())
                .body(Body::from(encoded.clone()))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(to_bytes(response.into_body()).await.unwrap(), "accepted");
        let (origin_headers, origin_body) = captured_rx.await.unwrap();
        assert_eq!(origin_body, encoded);
        assert_eq!(origin_headers[CONTENT_ENCODING], "gzip");
        assert_eq!(
            origin_headers[CONTENT_LENGTH],
            origin_body.len().to_string()
        );

        product.shutdown().await;
        origin_task.await.unwrap();
        let records = read_capture_records(directory.path());
        let request = records
            .iter()
            .find(|record| record.kind == CaptureKind::Request)
            .unwrap();
        assert_eq!(
            request.decode_body_bytes().unwrap(),
            b"opaque [MASKED] payload"
        );
        assert_eq!(
            request.body.as_ref().unwrap().content_encoding.as_deref(),
            Some("identity")
        );
    }

    #[tokio::test]
    async fn capture_redaction_failure_is_observation_only() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (captured_tx, captured_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            let captured_tx = Arc::new(StdMutex::new(Some(captured_tx)));
            Http::new()
                .http1_only(true)
                .serve_connection(
                    stream,
                    service_fn(move |request: Request<Body>| {
                        let captured_tx = captured_tx.clone();
                        async move {
                            let body = to_bytes(request.into_body()).await.unwrap();
                            captured_tx.lock().unwrap().take().unwrap().send(body).ok();
                            Ok::<_, Infallible>(Response::new(Body::from("accepted")))
                        }
                    }),
                )
                .await
                .unwrap();
        });
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[redaction.profiles.capture_failure]
replacement = "replacement-exceeds-limit"
max_body_bytes = 8
max_decoded_body_bytes = 8
rules = [{{ literals = ["secret"], payloads = "text" }}]

[observation.capture]
events = ["request.allowed", "response.allowed"]
redaction_profile = "capture_failure"
directory = "captures"
max_body_bytes = 8
max_inflight_body_bytes = 134217728
max_pending_records = 8
max_files = 8
max_total_bytes = 1048576

[policy]
default = "deny"

[[policy.rules]]
id = "capture-failure"
decision = "allow"
urls = ["http://{origin}/capture-failure"]
methods = ["POST"]
"#
        );
        let (directory, product) =
            product(base_config(proxy, "explicit_http", &policy), listeners).await;
        let response = send_request(
            proxy,
            Request::builder()
                .method(http::Method::POST)
                .uri(format!("http://{origin}/capture-failure"))
                .body(Body::from("secret"))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(to_bytes(response.into_body()).await.unwrap(), "accepted");
        assert_eq!(captured_rx.await.unwrap(), "secret");

        product.shutdown().await;
        origin_task.await.unwrap();
        let records = read_capture_records(directory.path());
        let request = records
            .iter()
            .find(|record| record.kind == CaptureKind::Request)
            .unwrap();
        assert_eq!(request.decision, CaptureDecision::Allow);
        assert!(request.body.is_none());
        assert!(request.body_truncated.is_none());
        let response = records
            .iter()
            .find(|record| record.kind == CaptureKind::Response)
            .unwrap();
        assert_eq!(response.decode_body_bytes().unwrap(), b"accepted");
    }

    #[tokio::test]
    async fn proxy_listener_cannot_reach_control_callback() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy, control], listeners) = prebound_listeners::<2>();
        let config = format!(
            r#"schema_version = 3

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"
max_active_webhook_deliveries = 8
webhook_transport_buffer_bytes = 65536
max_webhook_transport_bytes = 1048576

[control]
bind = "{control}"
base_path = "/_acl-proxy"
request_body_timeout = "1s"
max_connections = 8
max_request_body_bytes = 65536

[authorization.callback]
public_url = "http://{control}/_acl-proxy/external-auth/callback"
max_pending_operations = 8

[authorization.providers.unused]
kind = "webhook"
url = "https://approval.example.test/authorize"
max_request_bytes = 4097
max_response_bytes = 97

[listeners.explicit_http]
bind = "{proxy}"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "allow"
"#
        );
        let (_directory, product) = product(config, listeners).await;
        let uri = format!("http://{control}/_acl-proxy/external-auth/callback");
        let response = send_request(
            proxy,
            Request::builder().uri(uri).body(Body::empty()).unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        product.shutdown().await;
        assert!(StdTcpListener::bind(proxy).is_ok());
        assert!(StdTcpListener::bind(control).is_ok());
    }

    #[tokio::test]
    async fn proxy_listener_cannot_reach_itself() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let policy = r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "allow"
"#;
        let (_directory, product) =
            product(base_config(proxy, "explicit_http", policy), listeners).await;
        let response = send_request(
            proxy,
            Request::builder()
                .uri(format!("http://{proxy}/self"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        product.shutdown().await;
        assert!(StdTcpListener::bind(proxy).is_ok());
    }

    struct CapturedRoundTrip {
        headers: HeaderMap,
        body: Bytes,
        response_headers: HeaderMap,
        capture_records: Vec<CaptureRecord>,
    }

    #[derive(Clone, Copy)]
    enum TestCleartextMode {
        Explicit,
        Transparent,
    }

    async fn normalized_round_trip(mode: TestCleartextMode) -> CapturedRoundTrip {
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (captured_tx, captured_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            let captured_tx = Arc::new(StdMutex::new(Some(captured_tx)));
            Http::new()
                .http1_only(true)
                .serve_connection(
                    stream,
                    service_fn(move |request: Request<Body>| {
                        let captured_tx = captured_tx.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let body = to_bytes(body).await.unwrap();
                            captured_tx
                                .lock()
                                .unwrap()
                                .take()
                                .unwrap()
                                .send(CapturedRoundTrip {
                                    headers: parts.headers,
                                    body,
                                    response_headers: HeaderMap::new(),
                                    capture_records: Vec::new(),
                                })
                                .ok();
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .header("x-shaped-response", "origin")
                                    .body(Body::from("accepted"))
                                    .unwrap(),
                            )
                        }
                    }),
                )
                .await
                .unwrap();
        });
        let listener_table = match mode {
            TestCleartextMode::Explicit => "explicit_http",
            TestCleartextMode::Transparent => "transparent_http",
        };
        let listener_connect = if matches!(mode, TestCleartextMode::Explicit) {
            r#"
[listeners.explicit_http.connect]
http1 = "deny"
"#
            .to_owned()
        } else {
            String::new()
        };
        let policy = format!(
            r#"{listener_connect}
[redaction.profiles.wire]
replacement = "[MASKED]"
max_body_bytes = 1048576
max_decoded_body_bytes = 1048576
rules = [{{ literals = ["absent-test-marker"], payloads = "text" }}]

[policy]
default = "deny"

[[policy.rules]]
id = "normalized"
decision = "allow"
urls = ["http://{origin}/**"]
methods = ["POST"]
redaction_profile = "wire"

[[policy.rules.request_headers]]
operation = "set"
when = "always"
name = "x-mutation-order"
value = "rule"

[[policy.rules.response_headers]]
operation = "set"
when = "always"
name = "x-shaped-response"
value = "policy"
{capture}
"#,
            capture = capture_config(),
        );
        let config = base_config(proxy, listener_table, &policy);
        let (directory, product) = product(config, listeners).await;

        let plain = b"canonical decoded request bytes";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plain).unwrap();
        let encoded = encoder.finish().unwrap();
        assert_ne!(encoded, plain);
        let uri = match mode {
            TestCleartextMode::Explicit => format!("http://{origin}/ingest"),
            TestCleartextMode::Transparent => "/ingest".to_owned(),
        };
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .header(http::header::HOST, origin.to_string())
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_ENCODING, "gzip")
            .header(CONTENT_LENGTH, encoded.len().to_string())
            .body(Body::from(encoded))
            .unwrap();
        let response = send_request(proxy, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        let response_headers = response.headers().clone();
        assert_eq!(to_bytes(response.into_body()).await.unwrap(), "accepted");
        let mut captured = tokio::time::timeout(Duration::from_secs(2), captured_rx)
            .await
            .unwrap()
            .unwrap();
        captured.response_headers = response_headers;

        product.shutdown().await;
        captured.capture_records = read_capture_records(directory.path());
        origin_task.await.unwrap();
        captured
    }

    #[tokio::test]
    async fn normalized_http_body_forwards_identity_without_recompression() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let captured = normalized_round_trip(TestCleartextMode::Explicit).await;

        assert_eq!(captured.body, &b"canonical decoded request bytes"[..]);
        assert_eq!(
            captured
                .headers
                .get_all("x-mutation-order")
                .iter()
                .collect::<Vec<_>>(),
            ["rule", "global"]
        );
        assert!(captured.headers.contains_key("x-test-loop"));
        assert_eq!(captured.response_headers["x-shaped-response"], "policy");
        let request_capture = captured
            .capture_records
            .iter()
            .find(|record| record.kind == CaptureKind::Request)
            .unwrap();
        assert_eq!(
            request_capture.decode_body_bytes().unwrap(),
            b"canonical decoded request bytes"
        );
        assert_eq!(
            request_capture
                .body
                .as_ref()
                .unwrap()
                .content_encoding
                .as_deref(),
            Some("identity")
        );
    }

    #[tokio::test]
    async fn normalized_http_body_removes_stale_coding_and_length() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let captured = normalized_round_trip(TestCleartextMode::Transparent).await;

        assert_eq!(captured.body, &b"canonical decoded request bytes"[..]);
        assert!(!captured.headers.contains_key(CONTENT_ENCODING));
        assert_eq!(
            captured.headers[CONTENT_LENGTH],
            b"canonical decoded request bytes".len().to_string()
        );
        assert_eq!(captured.headers[CONTENT_TYPE], "application/octet-stream");
    }

    fn deterministic_telemetry_body(entropy_bytes: usize, repeated_bytes: usize) -> Vec<u8> {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut state = 0x0123_4567_89ab_cdef_u64;
        let entropy = (0..entropy_bytes).map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            ALPHABET[(state & 63) as usize]
        });
        b"{\"entropy\":\""
            .iter()
            .copied()
            .chain(entropy)
            .chain(b"\",\"telemetry\":\"".iter().copied())
            .chain(std::iter::repeat_n(b'a', repeated_bytes))
            .chain(b"\",\"secret\":\"synthetic-safe-literal\"}".iter().copied())
            .collect()
    }

    fn gzip_body(body: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    #[tokio::test]
    async fn production_compressed_telemetry_body_compatibility() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let production_fixture: toml::Value = toml::from_str(include_str!(
            "../../tests/fixtures/production/host-proxy.toml"
        ))
        .unwrap();
        let production_rules = production_fixture["policy"]["rules"].as_array().unwrap();
        let production_telemetry = production_rules
            .iter()
            .find(|rule| rule["id"].as_str() == Some("prod-host-r13-telemetry"))
            .unwrap();
        assert_eq!(
            production_telemetry["redaction_profile"].as_str(),
            Some("sensitive_strings")
        );
        assert_eq!(
            production_telemetry["urls"].as_array().unwrap(),
            &[
                toml::Value::String("https://statsig.anthropic.com/**".to_owned()),
                toml::Value::String("https://**.sentry.io/**".to_owned()),
                toml::Value::String("https://**.datadoghq.com/**".to_owned()),
            ]
        );
        let production_profile = &production_fixture["redaction"]["profiles"]["sensitive_strings"];
        assert_eq!(
            production_profile["max_body_bytes"].as_integer(),
            Some(10_485_760)
        );
        assert_eq!(
            production_profile["max_decoded_body_bytes"].as_integer(),
            Some(52_428_800)
        );

        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (origin_identity, _) = test_tls_identity();
        let origin_acceptor = crate::tls_identity::load_static_tls_acceptor(
            &origin_identity.path().join("server.pem"),
            &origin_identity.path().join("server-key.pem"),
            vec![b"http/1.1".to_vec()],
        )
        .unwrap();
        let (captured_tx, captured_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            let stream = origin_acceptor.accept(stream).await.unwrap();
            let captured_tx = Arc::new(StdMutex::new(Some(captured_tx)));
            Http::new()
                .http1_only(true)
                .serve_connection(
                    stream,
                    service_fn(move |request: Request<Body>| {
                        let captured_tx = captured_tx.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let body = to_bytes(body).await.unwrap();
                            captured_tx
                                .lock()
                                .unwrap()
                                .take()
                                .unwrap()
                                .send((parts.headers, body))
                                .ok();
                            Ok::<_, Infallible>(Response::new(Body::from("accepted telemetry")))
                        }
                    }),
                )
                .await
                .unwrap();
        });
        let resolver = Arc::new(DelayedResolver {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
            endpoint: origin,
        });
        let destination_guard = test_destination_guard(proxy, resolver.clone());
        let policy = r#"[listeners.explicit_http.connect]
http1 = "deny"

[authorization.providers.telemetry]
kind = "process"
command = "/usr/bin/python3"
args = ["-u", "-c", '''
import json, sys
for line in sys.stdin:
    request = json.loads(line)
    body = request.get("body")
    allowed = body is not None and body.get("encoding") == "base64" and len(body.get("data", "")) > 1000000
    print(json.dumps({"id": request["id"], "type": "response", "decision": "allow" if allowed else "deny"}, separators=(",", ":")), flush=True)
''']
timeout = "2s"
retire_timeout = "6s"
inherit_environment = false
environment = { PATH = "/usr/bin:/bin" }
include_request_body = true
max_request_body_bytes = 10485760
max_decoded_request_body_bytes = 52428800
max_stdout_line_bytes = 4096

[redaction.profiles.sensitive_strings]
replacement = "[REDACTED]"
max_body_bytes = 10485760
max_decoded_body_bytes = 52428800
max_frame_bytes = 262144
max_message_bytes = 1048576
allow_permessage_deflate = false
max_environment_literal_sources = 64
max_environment_literal_bytes = 65536
max_environment_literal_total_bytes = 1048576
rules = [{ literals = ["synthetic-safe-literal"], payloads = "text" }]

[policy]
default = "deny"

[[policy.rules]]
id = "prod-host-r13-telemetry"
decision = "delegate"
urls = ["https://**.sentry.io/**", "https://**.datadoghq.com/**"]
methods = ["POST"]
authorization_provider = "telemetry"
redaction_profile = "sensitive_strings"
"#;
        let config = base_config(proxy, "explicit_http", policy)
            .replacen("trust = \"system\"", "trust = \"insecure\"", 1)
            .replacen(
                "shutdown_drain_timeout = \"1s\"",
                "shutdown_drain_timeout = \"1s\"\nmax_content_decoding_expansion_ratio = 128",
                1,
            );
        let (_directory, product, assets) =
            product_with_destination_guard(config, listeners, destination_guard).await;
        let wire_body_pool = product.wire_body_pool();

        let telemetry = deterministic_telemetry_body(16_000, 1_200_000);
        let encoded = gzip_body(&telemetry);
        assert!(telemetry.len() > 1024 * 1024);
        assert!(telemetry.len() > 64 * encoded.len());
        assert!(telemetry.len() <= 128 * encoded.len());
        let handled = execute_direct(
            &product,
            assets,
            Request::builder()
                .method(http::Method::POST)
                .uri("https://ingest.sentry.io/api/telemetry")
                .header(CONTENT_TYPE, "application/json")
                .header(CONTENT_ENCODING, "gzip")
                .header(CONTENT_LENGTH, encoded.len().to_string())
                .body(Body::from(encoded))
                .unwrap(),
        )
        .await;
        assert_eq!(handled.response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(handled.response.into_body()).await.unwrap(),
            "accepted telemetry"
        );
        let (origin_headers, origin_body) = captured_rx.await.unwrap();
        let expected = String::from_utf8(telemetry)
            .unwrap()
            .replace("synthetic-safe-literal", "[REDACTED]");
        assert_eq!(origin_body, expected.as_bytes());
        assert!(!origin_headers.contains_key(CONTENT_ENCODING));
        assert_eq!(
            origin_headers[CONTENT_LENGTH],
            origin_body.len().to_string()
        );
        assert_eq!(origin_headers[CONTENT_TYPE], "application/json");
        assert_eq!(resolver.calls.load(Ordering::Acquire), 1);
        assert_eq!(wire_body_pool.global_charge(), 0);

        product.shutdown().await;
        origin_task.await.unwrap();
    }

    #[tokio::test]
    async fn cleartext_h2_idle_connection_releases_admission_for_waiting_client() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let policy = r#"[listeners.explicit_http.connect]
http2 = "deny"

[policy]
default = "allow"
"#;
        let config = base_config(proxy, "explicit_http", policy).replacen(
            "http_versions = [\"http1\"]",
            "http_versions = [\"http2\"]\nrequest_header_timeout = \"250ms\"\nmax_connections = 1\nmax_concurrent_streams = 1",
            1,
        );
        let (_directory, product) = product(config, listeners).await;

        let mut idle = tokio::net::TcpStream::connect(proxy).await.unwrap();
        idle.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
            .await
            .unwrap();
        let mut settings_header = [0_u8; 9];
        tokio::time::timeout(
            Duration::from_secs(1),
            idle.read_exact(&mut settings_header),
        )
        .await
        .unwrap()
        .unwrap();
        let settings_length = usize::from(settings_header[0]) << 16
            | usize::from(settings_header[1]) << 8
            | usize::from(settings_header[2]);
        assert_eq!(settings_header[3], 0x04, "server must begin with SETTINGS");
        assert_eq!(
            settings_header[4], 0x00,
            "server SETTINGS was already ACKed"
        );
        let mut settings_payload = vec![0_u8; settings_length];
        tokio::time::timeout(
            Duration::from_secs(1),
            idle.read_exact(&mut settings_payload),
        )
        .await
        .unwrap()
        .unwrap();
        idle.write_all(b"\x00\x00\x00\x04\x01\x00\x00\x00\x00")
            .await
            .unwrap();

        let waiting = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let mut builder = conn::Builder::new();
        builder.http2_only(true);
        let (mut sender, connection) = builder.handshake(waiting).await.unwrap();
        let driver = tokio::spawn(connection);
        let response = sender.send_request(
            Request::builder()
                .uri(format!("http://{proxy}/self"))
                .body(Body::empty())
                .unwrap(),
        );
        tokio::pin!(response);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), response.as_mut())
                .await
                .is_err(),
            "a second H2 connection bypassed the sole connection permit"
        );

        let response = tokio::time::timeout(Duration::from_secs(3), response.as_mut())
            .await
            .expect("the idle H2 connection must be reaped")
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        to_bytes(response.into_body()).await.unwrap();

        let mut idle_tail = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), idle.read_to_end(&mut idle_tail))
            .await
            .expect("the idle H2 transport must close")
            .unwrap();
        drop(sender);
        product.shutdown().await;
        driver.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn cleartext_h2_prior_knowledge_translation_and_stream_local_body_failure() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (captured_tx, captured_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            let captured_tx = Arc::new(StdMutex::new(Some(captured_tx)));
            Http::new()
                .http1_only(true)
                .serve_connection(
                    stream,
                    service_fn(move |request: Request<Body>| {
                        let captured_tx = captured_tx.clone();
                        async move {
                            let version = request.version();
                            let body = to_bytes(request.into_body()).await.unwrap();
                            captured_tx
                                .lock()
                                .unwrap()
                                .take()
                                .unwrap()
                                .send((version, body))
                                .ok();
                            Ok::<_, Infallible>(Response::new(Body::from("h2 accepted")))
                        }
                    }),
                )
                .await
                .unwrap();
        });
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http2 = "deny"

[redaction.profiles.wire]
max_body_bytes = 8
max_decoded_body_bytes = 8
rules = [{{ literals = ["marker"], payloads = "text" }}]

[policy]
default = "allow"

[[policy.rules]]
id = "bounded-h2-body"
decision = "allow"
urls = ["http://{origin}/**"]
methods = ["POST"]
redaction_profile = "wire"
"#
        );
        let config = base_config(proxy, "explicit_http", &policy).replacen(
            "http_versions = [\"http1\"]",
            "http_versions = [\"http2\"]",
            1,
        );
        let (_directory, product) = product(config, listeners).await;
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let mut builder = conn::Builder::new();
        builder.http2_only(true);
        let (mut sender, connection) = builder.handshake(stream).await.unwrap();
        let driver = tokio::spawn(connection);

        let rejected = sender
            .send_request(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("http://{origin}/too-large"))
                    .body(Body::from("0123456789abcdef"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            to_bytes(rejected.into_body()).await.unwrap(),
            "request body denied\n"
        );

        let accepted = sender
            .send_request(
                Request::builder()
                    .uri(format!("http://{origin}/sibling"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        assert_eq!(to_bytes(accepted.into_body()).await.unwrap(), "h2 accepted");
        let (version, body) = captured_rx.await.unwrap();
        assert_eq!(version, http::Version::HTTP_11);
        assert!(body.is_empty());

        drop(sender);
        product.shutdown().await;
        driver.await.unwrap().unwrap();
        origin_task.await.unwrap();
    }

    #[tokio::test]
    async fn unbounded_shutdown_finishes_at_the_finite_request_deadline() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let release_rx = Arc::new(StdMutex::new(Some(release_rx)));
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            Http::new()
                .http1_only(true)
                .serve_connection(
                    stream,
                    service_fn(move |_request: Request<Body>| {
                        let release_rx = release_rx.clone();
                        async move {
                            let (sender, body) = Body::channel();
                            let release = release_rx.lock().unwrap().take().unwrap();
                            tokio::spawn(async move {
                                let _sender = sender;
                                release.await.ok();
                            });
                            Ok::<_, Infallible>(Response::new(body))
                        }
                    }),
                )
                .await
                .ok();
        });
        let policy = r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "allow"
"#;
        let config = base_config(proxy, "explicit_http", policy)
            .replace("request_timeout = \"5s\"", "request_timeout = \"100ms\"")
            .replace(
                "shutdown_drain_timeout = \"1s\"",
                "shutdown_drain_timeout = \"unbounded\"",
            );
        let (_directory, product) = product(config, listeners).await;
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let (mut sender, connection) = conn::handshake(stream).await.unwrap();
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::builder()
                    .uri(format!("http://{origin}/pending"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        tokio::time::timeout(Duration::from_secs(1), product.shutdown())
            .await
            .expect("unbounded drain must still finish at the request deadline");
        assert!(to_bytes(response.into_body()).await.is_err());
        drop(sender);
        release_tx.send(()).ok();
        driver.await.unwrap().ok();
        origin_task.await.unwrap();
    }

    #[tokio::test]
    async fn cleartext_supervisor_joins_and_releases_its_prebound_socket() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let config = base_config(
            proxy,
            "explicit_http",
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"
"#,
        );
        let (_directory, product) = product(config, listeners).await;
        assert!(StdTcpListener::bind(proxy).is_err());

        product.shutdown().await;
        product.shutdown().await;
        assert!(StdTcpListener::bind(proxy).is_ok());
    }

    #[tokio::test]
    async fn explicit_https_uses_prebound_socket_static_identity_and_exact_alpn() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let (identity, certificate) = test_tls_identity();
        let policy = r#"[listeners.explicit_https.connect]
http1 = "deny"

[listeners.explicit_https.tls]
certificate_chain = "CERTIFICATE"
private_key = "PRIVATE_KEY"

[policy]
default = "deny"
"#
        .replace(
            "CERTIFICATE",
            &identity.path().join("server.pem").display().to_string(),
        )
        .replace(
            "PRIVATE_KEY",
            &identity.path().join("server-key.pem").display().to_string(),
        );
        let config = base_config(proxy, "explicit_https", &policy).replacen(
            "http_versions = [\"http1\"]",
            "http_versions = [\"http1\"]\nhandshake_timeout = \"1s\"",
            1,
        );
        let (_directory, product) = product(config, listeners).await;
        let connector = test_tls_connector(certificate, vec![b"http/1.1".to_vec()]);
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        assert_eq!(
            stream.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        let (mut sender, connection) = conn::handshake(stream).await.unwrap();
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::builder()
                    .uri("https://example.test/denied")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            to_bytes(response.into_body()).await.unwrap(),
            "request denied\n"
        );
        drop(sender);
        product.shutdown().await;
        driver.await.unwrap().unwrap();
        assert!(StdTcpListener::bind(proxy).is_ok());
    }

    #[tokio::test]
    async fn explicit_https_rejects_unsupported_alpn_and_accepts_no_alpn_as_http1() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let (identity, certificate) = test_tls_identity();
        let policy = r#"[listeners.explicit_https.connect]
http1 = "deny"

[listeners.explicit_https.tls]
certificate_chain = "CERTIFICATE"
private_key = "PRIVATE_KEY"

[policy]
default = "deny"
"#
        .replace(
            "CERTIFICATE",
            &identity.path().join("server.pem").display().to_string(),
        )
        .replace(
            "PRIVATE_KEY",
            &identity.path().join("server-key.pem").display().to_string(),
        );
        let config = base_config(proxy, "explicit_https", &policy).replacen(
            "http_versions = [\"http1\"]",
            "http_versions = [\"http1\"]\nhandshake_timeout = \"1s\"",
            1,
        );
        let (_directory, product) = product(config, listeners).await;

        let unsupported = test_tls_connector(certificate.clone(), vec![b"acme/1".to_vec()]);
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        assert!(unsupported
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .is_err());

        let no_alpn = test_tls_connector(certificate, Vec::new());
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let stream = no_alpn
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        assert_eq!(stream.get_ref().1.alpn_protocol(), None);
        let (mut sender, connection) = conn::handshake(stream).await.unwrap();
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::builder()
                    .uri("https://example.test/denied")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            to_bytes(response.into_body()).await.unwrap(),
            "request denied\n"
        );

        drop(sender);
        product.shutdown().await;
        driver.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn explicit_https_negotiates_http2_and_serves_an_http2_request() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let (identity, certificate) = test_tls_identity();
        let policy = r#"[listeners.explicit_https.connect]
http2 = "deny"

[listeners.explicit_https.tls]
certificate_chain = "CERTIFICATE"
private_key = "PRIVATE_KEY"

[policy]
default = "deny"
"#
        .replace(
            "CERTIFICATE",
            &identity.path().join("server.pem").display().to_string(),
        )
        .replace(
            "PRIVATE_KEY",
            &identity.path().join("server-key.pem").display().to_string(),
        );
        let config = base_config(proxy, "explicit_https", &policy).replacen(
            "http_versions = [\"http1\"]",
            "http_versions = [\"http2\"]\nhandshake_timeout = \"1s\"",
            1,
        );
        let (_directory, product) = product(config, listeners).await;
        let connector = test_tls_connector(certificate, vec![b"h2".to_vec()]);
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let mut builder = conn::Builder::new();
        builder.http2_only(true);
        let (mut sender, connection) = builder.handshake(stream).await.unwrap();
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::builder()
                    .uri("https://example.test/denied")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.version(), Version::HTTP_2);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        to_bytes(response.into_body()).await.unwrap();

        drop(sender);
        product.shutdown().await;
        driver.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn transparent_https_closes_a_stalled_client_hello_at_the_handshake_deadline() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let config = base_config(
            proxy,
            "transparent_https",
            r#"[mitm]
mode = "generated"
directory = "mitm"

[policy]
default = "deny"
"#,
        )
        .replacen(
            "http_versions = [\"http1\"]",
            "http_versions = [\"http1\"]\nhandshake_timeout = \"50ms\"",
            1,
        );
        let original_destination = SocketAddr::from(([198, 51, 100, 17], 443));
        let (_directory, product) = product_with_original_destination(
            config,
            listeners,
            Arc::new(FixedOriginalDestination(original_destination)),
        )
        .await;
        let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
            .await
            .expect("stalled ClientHello must be closed at its handshake deadline")
            .unwrap();
        assert_eq!(read, 0);

        product.shutdown().await;
    }

    #[tokio::test]
    async fn transparent_https_uses_sni_and_original_destination_port() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let config = base_config(
            proxy,
            "transparent_https",
            r#"[mitm]
mode = "generated"
directory = "mitm"

[policy]
default = "deny"
"#,
        )
        .replacen(
            "http_versions = [\"http1\"]",
            "http_versions = [\"http1\"]\nhandshake_timeout = \"1s\"",
            1,
        );
        let original_destination = SocketAddr::from(([198, 51, 100, 17], 8443));
        let (directory, product) = product_with_original_destination(
            config,
            listeners,
            Arc::new(FixedOriginalDestination(original_destination)),
        )
        .await;
        let certificate = read_first_pem_certificate(&directory.path().join("mitm/ca-cert.pem"));
        let connector = test_tls_connector(certificate, vec![b"http/1.1".to_vec()]);
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let stream = connector
            .connect(ServerName::try_from("transparent.test").unwrap(), stream)
            .await
            .unwrap();
        let (mut sender, connection) = conn::handshake(stream).await.unwrap();
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::builder()
                    .uri("/denied")
                    .header(http::header::HOST, "transparent.test:8443")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            to_bytes(response.into_body()).await.unwrap(),
            "request denied\n"
        );
        drop(sender);
        product.shutdown().await;
        driver.await.unwrap().unwrap();
        assert!(StdTcpListener::bind(proxy).is_ok());
    }

    #[tokio::test]
    async fn transparent_https_rejects_sni_and_host_authority_mismatch_through_listener() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let config = base_config(
            proxy,
            "transparent_https",
            r#"[mitm]
mode = "generated"
directory = "mitm"

[policy]
default = "deny"
"#,
        )
        .replacen(
            "http_versions = [\"http1\"]",
            "http_versions = [\"http1\"]\nhandshake_timeout = \"1s\"",
            1,
        );
        let original_destination = SocketAddr::from(([198, 51, 100, 17], 8443));
        let (directory, product) = product_with_original_destination(
            config,
            listeners,
            Arc::new(FixedOriginalDestination(original_destination)),
        )
        .await;
        let certificate = read_first_pem_certificate(&directory.path().join("mitm/ca-cert.pem"));
        let connector = test_tls_connector(certificate, vec![b"http/1.1".to_vec()]);
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let stream = connector
            .connect(ServerName::try_from("transparent.test").unwrap(), stream)
            .await
            .unwrap();
        let (mut sender, connection) = conn::handshake(stream).await.unwrap();
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::builder()
                    .uri("/denied")
                    .header(http::header::HOST, "other.test:8443")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            to_bytes(response.into_body()).await.unwrap(),
            "invalid request target\n"
        );

        drop(sender);
        product.shutdown().await;
        driver.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn transparent_https_negotiates_http2_and_serves_an_http2_request() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let config = base_config(
            proxy,
            "transparent_https",
            r#"[mitm]
mode = "generated"
directory = "mitm"

[policy]
default = "deny"
"#,
        )
        .replacen(
            "http_versions = [\"http1\"]",
            "http_versions = [\"http2\"]\nhandshake_timeout = \"1s\"",
            1,
        );
        let original_destination = SocketAddr::from(([198, 51, 100, 17], 443));
        let (directory, product) = product_with_original_destination(
            config,
            listeners,
            Arc::new(FixedOriginalDestination(original_destination)),
        )
        .await;
        let certificate = read_first_pem_certificate(&directory.path().join("mitm/ca-cert.pem"));
        let connector = test_tls_connector(certificate, vec![b"h2".to_vec()]);
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let stream = connector
            .connect(ServerName::try_from("transparent.test").unwrap(), stream)
            .await
            .unwrap();
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let mut builder = conn::Builder::new();
        builder.http2_only(true);
        let (mut sender, connection) = builder.handshake(stream).await.unwrap();
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::builder()
                    .uri("https://transparent.test/denied")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.version(), Version::HTTP_2);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        to_bytes(response.into_body()).await.unwrap();

        drop(sender);
        product.shutdown().await;
        driver.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn concurrent_http2_streams_keep_mixed_allow_and_deny_decisions_isolated() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (origin_identity, _) = test_tls_identity();
        let origin_acceptor = crate::tls_identity::load_static_tls_acceptor(
            &origin_identity.path().join("server.pem"),
            &origin_identity.path().join("server-key.pem"),
            vec![b"http/1.1".to_vec()],
        )
        .unwrap();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            let stream = origin_acceptor.accept(stream).await.unwrap();
            Http::new()
                .http1_only(true)
                .serve_connection(
                    stream,
                    service_fn(|request: Request<Body>| async move {
                        assert_eq!(request.uri().path(), "/ok");
                        Ok::<_, Infallible>(Response::new(Body::from("allowed stream")))
                    }),
                )
                .await
                .unwrap();
        });
        let policy = format!(
            r#"[mitm]
mode = "generated"
directory = "mitm"

[policy]
default = "deny"

[[policy.rules]]
id = "allowed-stream"
decision = "allow"
urls = ["https://localhost:{}/ok"]
"#,
            origin.port()
        );
        let config = base_config(proxy, "transparent_https", &policy)
            .replacen("trust = \"system\"", "trust = \"insecure\"", 1)
            .replacen(
                "http_versions = [\"http1\"]",
                "http_versions = [\"http2\"]\nhandshake_timeout = \"1s\"\nmax_concurrent_streams = 8",
                1,
            );
        let (directory, product) = product_with_original_destination(
            config,
            listeners,
            Arc::new(FixedOriginalDestination(origin)),
        )
        .await;
        let certificate = read_first_pem_certificate(&directory.path().join("mitm/ca-cert.pem"));
        let connector = test_tls_connector(certificate, vec![b"h2".to_vec()]);
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        let mut builder = conn::Builder::new();
        builder.http2_only(true);
        let (mut sender, connection) = builder.handshake(stream).await.unwrap();
        let driver = tokio::spawn(connection);
        std::future::poll_fn(|context| sender.poll_ready(context))
            .await
            .unwrap();
        let allowed = sender.send_request(
            Request::builder()
                .uri(format!("https://localhost:{}/ok", origin.port()))
                .body(Body::empty())
                .unwrap(),
        );
        std::future::poll_fn(|context| sender.poll_ready(context))
            .await
            .unwrap();
        let denied = sender.send_request(
            Request::builder()
                .uri(format!("https://localhost:{}/denied", origin.port()))
                .body(Body::empty())
                .unwrap(),
        );
        let (allowed, denied) = tokio::join!(allowed, denied);
        let allowed = allowed.unwrap();
        let denied = denied.unwrap();

        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(allowed.into_body()).await.unwrap(),
            "allowed stream"
        );
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            to_bytes(denied.into_body()).await.unwrap(),
            "request denied\n"
        );

        product.shutdown().await;
        driver.await.unwrap().ok();
        origin_task.await.unwrap();
    }

    #[tokio::test]
    async fn terminal_supervisor_panic_is_observed_promptly() {
        let (failure_tx, failure_rx) = oneshot::channel();
        let observer = Arc::new(ChannelFailureObserver(StdMutex::new(Some(failure_tx))));
        let listener_task = tokio::spawn(async move {
            panic!("injected listener failure");
            #[allow(unreachable_code)]
            Ok(())
        });

        let result =
            observe_listener_task(ProxyListenerKind::ExplicitHttp, listener_task, observer).await;
        let failure = failure_rx.await.unwrap();
        assert!(result.is_err());
        assert!(failure.message.contains("did not join"));
    }

    #[test]
    fn accept_error_classification_separates_retry_backoff_and_terminal_failures() {
        assert_eq!(
            classify_accept_error(&io::Error::from(io::ErrorKind::Interrupted)),
            AcceptErrorAction::Retry
        );
        assert_eq!(
            classify_accept_error(&io::Error::from(io::ErrorKind::OutOfMemory)),
            AcceptErrorAction::Backoff
        );
        assert_eq!(
            classify_accept_error(&io::Error::from(io::ErrorKind::InvalidInput)),
            AcceptErrorAction::Fail
        );
    }

    #[test]
    fn tls_alpn_selection_obeys_the_exact_compiled_protocol_set() {
        let both = [CompiledHttpVersion::Http2, CompiledHttpVersion::Http1];
        assert_eq!(
            select_tls_http_version(Some(b"h2"), &both),
            Some(CompiledHttpVersion::Http2)
        );
        assert_eq!(
            select_tls_http_version(Some(b"http/1.1"), &both),
            Some(CompiledHttpVersion::Http1)
        );
        assert_eq!(
            select_tls_http_version(None, &both),
            Some(CompiledHttpVersion::Http1)
        );
        assert_eq!(
            select_tls_http_version(None, &[CompiledHttpVersion::Http2]),
            None
        );
        assert_eq!(
            select_tls_http_version(Some(b"h2"), &[CompiledHttpVersion::Http1]),
            None
        );
        assert_eq!(select_tls_http_version(Some(b"http/1.0"), &both), None);
    }

    #[test]
    fn local_quota_cache_replaces_complete_live_snapshot_under_churn() {
        let first = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10));
        let second = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 11));
        let classifier = LocalQuotaClassifier {
            addresses: Arc::new(RwLock::new(HashSet::from([first]))),
        };
        let accepted_key = classifier.classify(first);
        assert!(matches!(accepted_key, WireBodyQuotaKey::LocalHost));

        classifier.replace(HashSet::from([second]));

        assert!(matches!(accepted_key, WireBodyQuotaKey::LocalHost));
        assert!(matches!(
            classifier.classify(first),
            WireBodyQuotaKey::Peer(address) if address == first
        ));
        assert!(matches!(
            classifier.classify(second),
            WireBodyQuotaKey::LocalHost
        ));
        assert_eq!(classifier.addresses.read().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn connect_deny_policy_returns_forbidden_without_mitm_activation() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let policy = r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "allow"
"#;
        let (_directory, product) =
            product(base_config(proxy, "explicit_http", policy), listeners).await;
        let response = send_request(
            proxy,
            Request::builder()
                .method(Method::CONNECT)
                .uri("192.0.2.10:443")
                .header(http::header::HOST, "192.0.2.10:443")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            to_bytes(response.into_body()).await.unwrap(),
            "CONNECT denied\n"
        );
        product.shutdown().await;
    }

    #[tokio::test]
    async fn denied_connect_with_body_closes_before_pipelined_request() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let policy = r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "allow"
"#;
        let (_directory, product) =
            product(base_config(proxy, "explicit_http", policy), listeners).await;
        let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        stream
            .write_all(
                b"CONNECT 192.0.2.10:443 HTTP/1.1\r\n\
Host: 192.0.2.10:443\r\n\
Content-Length: 4\r\n\
\r\n\
bodyGET http://192.0.2.11/ HTTP/1.1\r\n\
Host: 192.0.2.11\r\n\
Connection: close\r\n\
\r\n",
            )
            .await
            .unwrap();

        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .expect("denied CONNECT did not close the connection")
            .unwrap();
        let response_text = String::from_utf8(response).unwrap();
        assert!(
            response_text.starts_with("HTTP/1.1 403 "),
            "{response_text}"
        );
        assert!(
            response_text
                .to_ascii_lowercase()
                .contains("connection: close\r\n"),
            "{response_text}"
        );
        assert_eq!(
            response_text.matches("HTTP/1.1 ").count(),
            1,
            "{response_text}"
        );
        assert!(
            response_text.ends_with("CONNECT denied\n"),
            "{response_text}"
        );

        product.shutdown().await;
    }

    fn connect_mitm_policy(target: &str) -> String {
        format!(
            r#"[listeners.explicit_http.connect]
http1 = "mitm"

[mitm]
mode = "generated"
directory = "mitm"

[policy]
default = "deny"

[[policy.rules]]
id = "connect-target"
decision = "allow"
urls = ["https://{target}/**"]
"#
        )
    }

    async fn open_connect(proxy: SocketAddr, target: &str) -> tokio::net::TcpStream {
        let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        stream
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let head = read_http_head(&mut stream).await;
        assert!(
            head.starts_with(b"HTTP/1.1 200 "),
            "unexpected CONNECT response: {}",
            String::from_utf8_lossy(&head)
        );
        stream
    }

    #[tokio::test]
    async fn connect_mitm_forwards_inner_request_and_rejects_nested_connect() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (origin_identity, _) = test_tls_identity();
        let origin_acceptor = crate::tls_identity::load_static_tls_acceptor(
            &origin_identity.path().join("server.pem"),
            &origin_identity.path().join("server-key.pem"),
            vec![b"http/1.1".to_vec()],
        )
        .unwrap();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            let tls = origin_acceptor.accept(stream).await.unwrap();
            Http::new()
                .http1_only(true)
                .serve_connection(
                    tls,
                    service_fn(|_request| async {
                        Ok::<_, Infallible>(Response::new(Body::from("connect origin")))
                    }),
                )
                .await
                .unwrap();
        });
        let target = origin.to_string();
        let config = base_config(proxy, "explicit_http", &connect_mitm_policy(&target)).replacen(
            "trust = \"system\"",
            "trust = \"insecure\"",
            1,
        );
        let (directory, product) = product(config, listeners).await;

        let stream = open_connect(proxy, &target).await;
        let certificate = read_first_pem_certificate(&directory.path().join("mitm/ca-cert.pem"));
        let connector = test_tls_connector(certificate, vec![b"http/1.1".to_vec()]);
        let tls = connector
            .connect(ServerName::try_from("127.0.0.1").unwrap(), stream)
            .await
            .unwrap();
        let (mut sender, connection) = conn::handshake(tls).await.unwrap();
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::builder()
                    .uri("/allowed")
                    .header(http::header::HOST, &target)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body()).await.unwrap(),
            "connect origin"
        );

        let nested = sender
            .send_request(
                Request::builder()
                    .method(Method::CONNECT)
                    .uri(&target)
                    .header(http::header::HOST, &target)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(nested.status(), StatusCode::BAD_REQUEST);
        to_bytes(nested.into_body()).await.unwrap();
        drop(sender);
        driver.await.unwrap().unwrap();
        origin_task.await.unwrap();
        product.shutdown().await;
        assert!(StdTcpListener::bind(proxy).is_ok());
    }

    #[tokio::test]
    async fn connect_mitm_websocket_applies_wire_redaction() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (origin_identity, _) = test_tls_identity();
        let origin_acceptor = crate::tls_identity::load_static_tls_acceptor(
            &origin_identity.path().join("server.pem"),
            &origin_identity.path().join("server-key.pem"),
            vec![b"http/1.1".to_vec()],
        )
        .unwrap();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            let mut stream = origin_acceptor.accept(stream).await.unwrap();
            let request = read_http_head(&mut stream).await;
            let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(request.contains("\r\nupgrade: websocket\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .await
                .unwrap();
            let frame = read_websocket_frame(&mut stream).await.unwrap();
            stream
                .write_all(&websocket_frame(true, 0x1, b"server response", false))
                .await
                .unwrap();
            frame
        });
        let target = origin.to_string();
        let policy = connect_mitm_policy(&target).replace(
            &format!("urls = [\"https://{target}/**\"]"),
            &format!(
                "urls = [\"https://{target}/**\"]\nallow_upgrades = true\nredaction_profile = \"wire\""
            ),
        );
        let policy = format!(
            r#"{policy}

[redaction.profiles.wire]
replacement = "[REDACTED]"
max_frame_bytes = 1024
max_message_bytes = 1024
rules = [{{ literals = ["password"], payloads = "text" }}]
"#
        );
        let config = base_config(proxy, "explicit_http", &policy).replacen(
            "trust = \"system\"",
            "trust = \"insecure\"",
            1,
        );
        let (directory, product) = product(config, listeners).await;
        let stream = open_connect(proxy, &target).await;
        let certificate = read_first_pem_certificate(&directory.path().join("mitm/ca-cert.pem"));
        let connector = test_tls_connector(certificate, vec![b"http/1.1".to_vec()]);
        let mut stream = connector
            .connect(ServerName::try_from("127.0.0.1").unwrap(), stream)
            .await
            .unwrap();
        stream
            .write_all(
                format!(
                    "GET /socket HTTP/1.1\r\nHost: {target}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGVzdC13ZWJzb2NrZXQta2V5\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_head(&mut stream).await;
        assert!(response.starts_with(b"HTTP/1.1 101 "));
        stream
            .write_all(&websocket_frame(true, 0x1, b"client password", true))
            .await
            .unwrap();
        let response = read_websocket_frame(&mut stream).await.unwrap();
        let seen = origin_task.await.unwrap();

        assert!(seen.fin);
        assert_eq!(seen.opcode, 0x1);
        assert_eq!(seen.payload, b"client [REDACTED]");
        assert_eq!(response.opcode, 0x1);
        assert_eq!(response.payload, b"server response");
        drop(stream);
        product.shutdown().await;
    }

    #[tokio::test]
    async fn connect_mitm_rejects_listener_loop_before_200() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let target = proxy.to_string();
        let (_directory, product) = product(
            base_config(proxy, "explicit_http", &connect_mitm_policy(&target)),
            listeners,
        )
        .await;
        let response = send_request(
            proxy,
            Request::builder()
                .method(Method::CONNECT)
                .uri(&target)
                .header(http::header::HOST, &target)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        product.shutdown().await;
    }

    #[tokio::test]
    async fn connect_mitm_rejects_mismatched_tls_sni() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let target = "192.0.2.10:443";
        let (directory, product) = product(
            base_config(proxy, "explicit_http", &connect_mitm_policy(target)),
            listeners,
        )
        .await;
        let stream = open_connect(proxy, target).await;
        let certificate = read_first_pem_certificate(&directory.path().join("mitm/ca-cert.pem"));
        let connector = test_tls_connector(certificate, vec![b"http/1.1".to_vec()]);
        assert!(connector
            .connect(ServerName::try_from("other.example").unwrap(), stream)
            .await
            .is_err());
        product.shutdown().await;
    }

    #[tokio::test]
    async fn connect_mitm_rejects_outer_and_inner_authority_mismatch() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let target = "192.0.2.10:443";
        let (directory, product) = product(
            base_config(proxy, "explicit_http", &connect_mitm_policy(target)),
            listeners,
        )
        .await;

        let outer = send_request(
            proxy,
            Request::builder()
                .method(Method::CONNECT)
                .uri(target)
                .header(http::header::HOST, "other.example:443")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(outer.status(), StatusCode::BAD_REQUEST);

        let stream = open_connect(proxy, target).await;
        let certificate = read_first_pem_certificate(&directory.path().join("mitm/ca-cert.pem"));
        let connector = test_tls_connector(certificate, vec![b"http/1.1".to_vec()]);
        let tls = connector
            .connect(ServerName::try_from("192.0.2.10").unwrap(), stream)
            .await
            .unwrap();
        let (mut sender, connection) = conn::handshake(tls).await.unwrap();
        let driver = tokio::spawn(connection);
        let inner = sender
            .send_request(
                Request::builder()
                    .uri("https://other.example/denied")
                    .header(http::header::HOST, target)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(inner.status(), StatusCode::BAD_REQUEST);
        to_bytes(inner.into_body()).await.unwrap();
        drop(sender);
        driver.await.unwrap().unwrap();
        product.shutdown().await;
    }

    #[tokio::test]
    async fn explicit_https_listener_supports_http1_connect_mitm() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let target = "192.0.2.10:443";
        let (identity, identity_certificate) = test_tls_identity();
        let policy = format!(
            "{}\n[listeners.explicit_https.tls]\ncertificate_chain = \"{}\"\nprivate_key = \"{}\"\n",
            connect_mitm_policy(target)
                .replace("listeners.explicit_http", "listeners.explicit_https"),
            identity.path().join("server.pem").display(),
            identity.path().join("server-key.pem").display(),
        );
        let (directory, product) =
            product(base_config(proxy, "explicit_https", &policy), listeners).await;

        let outer_connector = test_tls_connector(identity_certificate, vec![b"http/1.1".to_vec()]);
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let mut outer_tls = outer_connector
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        outer_tls
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let head = read_http_head(&mut outer_tls).await;
        assert!(head.starts_with(b"HTTP/1.1 200 "));

        let certificate = read_first_pem_certificate(&directory.path().join("mitm/ca-cert.pem"));
        let inner_connector = test_tls_connector(certificate, vec![b"http/1.1".to_vec()]);
        let inner_tls = inner_connector
            .connect(ServerName::try_from("192.0.2.10").unwrap(), outer_tls)
            .await
            .unwrap();
        let (mut sender, connection) = conn::handshake(inner_tls).await.unwrap();
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::builder()
                    .uri("https://other.example/denied")
                    .header(http::header::HOST, target)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        to_bytes(response.into_body()).await.unwrap();
        drop(sender);
        let _ = driver.await.unwrap();
        product.shutdown().await;
    }

    #[tokio::test]
    async fn connect_mitm_closes_stalled_client_hello_at_listener_deadline() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let target = "192.0.2.10:443";
        let config = base_config(proxy, "explicit_http", &connect_mitm_policy(target)).replacen(
            "http_versions = [\"http1\"]",
            "http_versions = [\"http1\"]\nrequest_header_timeout = \"50ms\"",
            1,
        );
        let (_directory, product) = product(config, listeners).await;
        let mut stream = open_connect(proxy, target).await;
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
            .await
            .expect("stalled CONNECT ClientHello must be closed")
            .unwrap();
        assert_eq!(read, 0);
        product.shutdown().await;
    }

    #[tokio::test]
    async fn connect_mitm_shutdown_joins_pending_tunnel_and_releases_listener() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let target = "192.0.2.10:443";
        let (_directory, product) = product(
            base_config(proxy, "explicit_http", &connect_mitm_policy(target)),
            listeners,
        )
        .await;
        let mut stream = open_connect(proxy, target).await;
        tokio::time::timeout(Duration::from_secs(2), product.shutdown())
            .await
            .expect("shutdown must join a pending CONNECT tunnel");
        let mut byte = [0_u8; 1];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        assert!(StdTcpListener::bind(proxy).is_ok());
    }

    #[tokio::test]
    async fn connect_tunnel_retains_connection_admission_until_terminal_join() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let target = "192.0.2.10:443";
        let config = base_config(proxy, "explicit_http", &connect_mitm_policy(target)).replacen(
            "http_versions = [\"http1\"]",
            "http_versions = [\"http1\"]\nmax_connections = 1",
            1,
        );
        let (_directory, product) = product(config, listeners).await;
        let first = open_connect(proxy, target).await;

        let mut second = tokio::net::TcpStream::connect(proxy).await.unwrap();
        second
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut byte = [0_u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), second.read(&mut byte))
                .await
                .is_err(),
            "a second connection bypassed the CONNECT tunnel's admission permit"
        );

        drop(first);
        let head = tokio::time::timeout(Duration::from_secs(2), read_http_head(&mut second))
            .await
            .expect("the waiting connection must be admitted after tunnel join");
        assert!(head.starts_with(b"HTTP/1.1 200 "));
        drop(second);
        product.shutdown().await;
    }

    #[tokio::test]
    async fn cleartext_connection_admission_and_h1_head_deadline_are_bounded() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let policy = r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "allow"
"#;
        let config = base_config(proxy, "explicit_http", policy).replacen(
            "http_versions = [\"http1\"]",
            "http_versions = [\"http1\"]\nrequest_header_timeout = \"100ms\"\nmax_connections = 1\nmax_concurrent_streams = 1",
            1,
        );
        let (_directory, product) = product(config, listeners).await;
        let mut first = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let mut second = tokio::net::TcpStream::connect(proxy).await.unwrap();
        second
            .write_all(
                format!(
                    "GET http://{proxy}/self HTTP/1.1\r\nHost: {proxy}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut early = [0_u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(30), second.read(&mut early))
                .await
                .is_err(),
            "a second connection bypassed the single admitted slot"
        );
        let mut first_end = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), first.read_to_end(&mut first_end))
            .await
            .unwrap()
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), second.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 403"));
        product.shutdown().await;
    }

    #[tokio::test]
    async fn http_body_failure_terminates_unread_framing() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let policy = r#"[listeners.explicit_http.connect]
http1 = "deny"

[redaction.profiles.wire]
max_body_bytes = 8
max_decoded_body_bytes = 8
rules = [{ literals = ["marker"], payloads = "text" }]

[policy]
default = "deny"

[[policy.rules]]
id = "bounded"
decision = "allow"
methods = ["POST"]
redaction_profile = "wire"
"#;
        let config = base_config(proxy, "explicit_http", policy);
        let (_directory, product) = product(config, listeners).await;
        let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        stream
            .write_all(
                b"POST http://192.0.2.1/ HTTP/1.1\r\nHost: 192.0.2.1\r\nContent-Length: 32\r\n\r\n0123456789abcdef",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(
            response.starts_with(b"HTTP/1.1 413"),
            "unexpected terminal response: {:?}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            String::from_utf8_lossy(&response)
                .to_ascii_lowercase()
                .contains("\r\nconnection: close\r\n"),
            "terminal HTTP/1 response omitted Connection: close"
        );

        product.shutdown().await;
    }

    #[tokio::test]
    async fn upgrade_requires_explicit_rule_opt_in_before_origin_connect() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let policy = r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "allow"
"#;
        let (_directory, product) =
            product(base_config(proxy, "explicit_http", policy), listeners).await;

        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://{origin}/socket HTTP/1.1\r\nHost: {origin}\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_head(&mut client).await;
        assert!(
            response.starts_with(b"HTTP/1.1 403"),
            "unexpected upgrade denial: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), origin_listener.accept())
                .await
                .is_err(),
            "an upgrade without rule opt-in reached the origin"
        );

        product.shutdown().await;
    }

    #[tokio::test]
    async fn opted_in_opaque_upgrade_relays_both_directions_and_releases_runtime() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await.unwrap();
            let request = read_http_head(&mut stream).await;
            let request_text = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(request_text.contains("\r\nconnection: upgrade\r\n"));
            assert!(request_text.contains("\r\nupgrade: test-echo\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n",
                )
                .await
                .unwrap();
            let mut inbound = [0_u8; 4];
            stream.read_exact(&mut inbound).await.unwrap();
            assert_eq!(&inbound, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "opaque-upgrade"
decision = "allow"
methods = ["GET"]
urls = ["http://{origin}/socket"]
allow_upgrades = true
"#
        );
        let (_directory, product) =
            product(base_config(proxy, "explicit_http", &policy), listeners).await;

        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://{origin}/socket HTTP/1.1\r\nHost: {origin}\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_head(&mut client).await;
        assert!(
            response.starts_with(b"HTTP/1.1 101"),
            "unexpected upgrade response: {}",
            String::from_utf8_lossy(&response)
        );
        client.write_all(b"ping").await.unwrap();
        let mut reply = [0_u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
        drop(client);
        origin_task.await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let counts = product.upgrade_runtime().counts();
                if counts.reserved_slots == 0
                    && counts.reserved_bytes == 0
                    && counts.uncommitted == 0
                    && counts.committed == 0
                    && counts.tracked_tasks == 0
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the completed upgrade retained runtime resources");
        product.shutdown().await;
    }

    #[tokio::test]
    async fn fragmented_websocket_message_is_buffered_and_redacted_before_forwarding() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await.unwrap();
            let request = read_http_head(&mut stream).await;
            let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(request.contains("\r\nupgrade: websocket\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .await
                .unwrap();
            let frame = read_websocket_frame(&mut stream).await.unwrap();
            seen_tx.send(frame).unwrap();
        });
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[redaction.profiles.wire]
replacement = "[REDACTED]"
max_frame_bytes = 1024
max_message_bytes = 1024
rules = [{{ literals = ["password"], payloads = "text" }}]

[policy]
default = "deny"

[[policy.rules]]
id = "fragmented-websocket"
decision = "allow"
methods = ["GET"]
urls = ["http://{origin}/socket"]
allow_upgrades = true
redaction_profile = "wire"
"#
        );
        let (_directory, product) =
            product(base_config(proxy, "explicit_http", &policy), listeners).await;
        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://{origin}/socket HTTP/1.1\r\nHost: {origin}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGVzdC13ZWJzb2NrZXQta2V5\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_head(&mut client).await;
        assert!(response.starts_with(b"HTTP/1.1 101 "));

        client
            .write_all(&websocket_frame(false, 0x1, b"client pass", true))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(75), seen_rx.recv())
                .await
                .is_err(),
            "a partial WebSocket message reached the origin"
        );
        client
            .write_all(&websocket_frame(true, 0x0, b"word", true))
            .await
            .unwrap();
        let seen = tokio::time::timeout(Duration::from_secs(2), seen_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(seen.fin);
        assert_eq!(seen.opcode, 0x1);
        assert_eq!(seen.payload, b"client [REDACTED]");

        drop(client);
        origin_task.await.unwrap();
        product.shutdown().await;
    }

    #[tokio::test]
    async fn opted_in_websocket_applies_wire_redaction_and_captures_the_logical_message() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await.unwrap();
            let request = read_http_head(&mut stream).await;
            let request_text = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(request_text.contains("\r\nconnection: upgrade\r\n"));
            assert!(request_text.contains("\r\nupgrade: websocket\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .await
                .unwrap();

            let mut header = [0_u8; 2];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 0x81);
            assert_ne!(header[1] & 0x80, 0, "client WebSocket frame was not masked");
            let payload_len = usize::from(header[1] & 0x7f);
            assert!(payload_len < 126);
            let mut mask = [0_u8; 4];
            stream.read_exact(&mut mask).await.unwrap();
            let mut payload = vec![0_u8; payload_len];
            stream.read_exact(&mut payload).await.unwrap();
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % mask.len()];
            }
            payload
        });
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[redaction.profiles.wire]
replacement = "[WIRE]"
max_frame_bytes = 1024
max_message_bytes = 1024
rules = [{{ literals = ["wire-redaction-sentinel"], payloads = "both" }}]

[redaction.profiles.capture]
replacement = "[CAPTURE]"
max_frame_bytes = 1024
max_message_bytes = 1024
rules = [{{ literals = ["capture-redaction-sentinel"], payloads = "both" }}]

[observation.capture]
events = ["request.allowed"]
redaction_profile = "capture"
directory = "captures"
max_body_bytes = 1048576
max_inflight_body_bytes = 134217728
max_pending_records = 32
max_files = 32
max_total_bytes = 16777216

[policy]
default = "deny"

[[policy.rules]]
id = "observed-websocket"
decision = "allow"
methods = ["GET"]
urls = ["http://{origin}/socket"]
allow_upgrades = true
redaction_profile = "wire"
"#
        );
        let (directory, product) =
            product(base_config(proxy, "explicit_http", &policy), listeners).await;

        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://{origin}/socket HTTP/1.1\r\nHost: {origin}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGVzdC13ZWJzb2NrZXQta2V5\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_head(&mut client).await;
        assert!(
            response.starts_with(b"HTTP/1.1 101"),
            "unexpected WebSocket response: {}",
            String::from_utf8_lossy(&response)
        );

        let logical_message = b"wire-redaction-sentinel capture-redaction-sentinel";
        let mask = [0x11, 0x22, 0x33, 0x44];
        let mut frame = vec![0x81, 0x80 | logical_message.len() as u8];
        frame.extend_from_slice(&mask);
        frame.extend(
            logical_message
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % mask.len()]),
        );
        client.write_all(&frame).await.unwrap();

        let origin_payload = origin_task.await.unwrap();
        assert_eq!(
            origin_payload, b"[WIRE] capture-redaction-sentinel",
            "the origin did not receive the wire-profile redaction"
        );
        assert!(!origin_payload
            .windows(b"wire-redaction-sentinel".len())
            .any(|window| window == b"wire-redaction-sentinel"));
        drop(client);

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let counts = product.upgrade_runtime().counts();
                if counts.reserved_slots == 0
                    && counts.reserved_bytes == 0
                    && counts.uncommitted == 0
                    && counts.committed == 0
                    && counts.tracked_tasks == 0
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the captured WebSocket retained upgrade runtime resources");
        product.shutdown().await;

        let records = read_capture_records(directory.path());
        let message = records
            .iter()
            .find(|record| record.request_id.contains("-ws-request-"))
            .expect("the WebSocket message capture artifact is missing");
        let captured = message.decode_body_bytes().unwrap();
        assert_eq!(captured, b"wire-redaction-sentinel [CAPTURE]");
        assert!(!captured
            .windows(b"capture-redaction-sentinel".len())
            .any(|window| window == b"capture-redaction-sentinel"));
    }

    #[tokio::test]
    async fn upstream_non_switching_response_remains_an_ordinary_http_response() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await.unwrap();
            let _request = read_http_head(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 7\r\nConnection: close\r\n\r\nupgrade",
                )
                .await
                .unwrap();
        });
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "upgrade-rejected"
decision = "allow"
urls = ["http://{origin}/socket"]
allow_upgrades = true
"#
        );
        let (_directory, product) =
            product(base_config(proxy, "explicit_http", &policy), listeners).await;

        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://{origin}/socket HTTP/1.1\r\nHost: {origin}\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_head(&mut client).await;
        assert!(
            response.starts_with(b"HTTP/1.1 426"),
            "unexpected ordinary response: {}",
            String::from_utf8_lossy(&response)
        );
        let mut body = [0_u8; 7];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"upgrade");

        origin_task.await.unwrap();
        product.shutdown().await;
    }

    #[tokio::test]
    async fn upgrade_admission_saturation_rejects_before_second_origin_connect() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (established_tx, established_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await.unwrap();
            let _request = read_http_head(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n",
                )
                .await
                .unwrap();
            established_tx.send(()).unwrap();
            release_rx.await.ok();
            let second =
                tokio::time::timeout(Duration::from_millis(100), origin_listener.accept()).await;
            assert!(
                second.is_err(),
                "the saturated upgrade opened a second origin connection"
            );
        });
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "one-upgrade"
decision = "allow"
urls = ["http://{origin}/**"]
allow_upgrades = true
"#
        );
        let config = base_config(proxy, "explicit_http", &policy).replacen(
            "shutdown_drain_timeout = \"1s\"",
            "shutdown_drain_timeout = \"1s\"\nmax_active_upgrades = 1",
            1,
        );
        let (_directory, product) = product(config, listeners).await;

        let mut first = tokio::net::TcpStream::connect(proxy).await.unwrap();
        first
            .write_all(
                format!(
                    "GET http://{origin}/first HTTP/1.1\r\nHost: {origin}\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let first_response = read_http_head(&mut first).await;
        assert!(first_response.starts_with(b"HTTP/1.1 101"));
        established_rx.await.unwrap();

        let mut second = tokio::net::TcpStream::connect(proxy).await.unwrap();
        second
            .write_all(
                format!(
                    "GET http://{origin}/second HTTP/1.1\r\nHost: {origin}\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let second_response = read_http_head(&mut second).await;
        assert!(
            second_response.starts_with(b"HTTP/1.1 503"),
            "unexpected saturation response: {}",
            String::from_utf8_lossy(&second_response)
        );
        release_tx.send(()).unwrap();
        drop(first);
        origin_task.await.unwrap();
        product.shutdown().await;
    }
}
