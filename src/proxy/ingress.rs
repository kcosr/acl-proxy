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
use http::header::{CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRAILER, UPGRADE};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Version};
use hyper::body::{Bytes, HttpBody, SizeHint};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::Body;
use rustls::server::Acceptor as RustlsAcceptor;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch, Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor};

use crate::activation::assets::ProductIngressAssets;
use crate::activation::listeners::{
    PreparedProxyListener, ProxyListenerConfig, ProxyListenerKind, ProxySupervisor,
    ProxySupervisorFailure, ProxySupervisorFailureObserver, ProxySupervisorStartError,
    ProxySupervisorStarter,
};
#[cfg(test)]
use crate::capture::REDACTED;
use crate::capture::{CaptureDecision, CaptureKind, HttpCaptureTap, SanitizedCaptureMetadata};
use crate::certs::MitmCertificateManager;
use crate::config::compiler::{
    CompiledDecisionLogLevel, CompiledHttpVersion, StaticCleartextListener,
    StaticExplicitHttpsListener, StaticTransparentHttpsListener,
};
use crate::http1::head::IngressRequestKind;
use crate::http1::ingress::{RequestDisposition, ValidatedIngressIo};
use crate::observation::{
    CaptureEpoch, CaptureEvent, DecisionSubmissionTarget, PendingDecisionSubmission,
    ProductObservationRuntime,
};
use crate::proxy::authority::{reconcile_connect_outer_request, reconcile_request};
use crate::proxy::facts::{
    validate_standalone_connect_ingress_request, validate_standalone_ingress_request,
    IngressPartitionPolicy,
};
use crate::proxy::forward::{preflight_forwarding_target, ForwardedDownstreamBody};
use crate::proxy::forwarding_executor::ForwardingExecutor;
use crate::proxy::h2_stream_cancellation::{H2StreamCancellation, H2StreamExecutor};
use crate::proxy::original_destination::{
    OriginalDestinationResolver, SystemOriginalDestinationResolver,
};
use crate::proxy::upgrade_relay::UpgradeCaptureContext;
use crate::runtime::{BoxFuture, GenerationLease, Runtime};
use crate::safety::{GuardedBody, WireBodyQuotaKey};
use crate::standalone_policy_provider::{
    StandaloneForwardDispatch, StandaloneIngressTransport, StandalonePolicyProvider,
    StandaloneProviderInput, StandaloneResponseBodyProvenance, StandaloneResponseDispatch,
    StandaloneTerminalService, TokioRuntimeClock,
};
use crate::upgrade::UpgradeRuntime;
use http_access_runtime::{RequestPipeline, RequestPipelineError};
use http_access_types::{
    CanonicalHost, CaptureFacts, CaptureFactsInput, DecisionAuditFacts, DecisionAuditFactsInput,
    DecisionAuditSource, DecisionDisposition, DecisionReason, DecisionReasonCategory,
    HeaderName as NeutralHeaderName, HeaderValue as NeutralHeaderValue, HttpMethod, IngressMode,
    SanitizedHeaderField, SensitiveHeaderPolicy, SinkSafeUrl, StableId, UpgradePolicy,
};
use http_access_url::{
    canonicalize_tls_server_name, reconcile_connect_sni, CanonicalConnectTarget,
};

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
                require_connect_mitm_asset(
                    kind,
                    config.connect.as_ref().and_then(
                        crate::config::compiler::StaticConnectPolicy::http1_listener_denied,
                    ) == Some(false),
                    assets,
                )?;
                ProductIngressSupervisor::start(
                    IngressListenerConfig::cleartext(
                        kind,
                        ConfiguredRequestAuthority::ExplicitHttp,
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
                require_connect_mitm_asset(
                    kind,
                    config.connect.http1_listener_denied() == Some(false),
                    assets,
                )?;
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
    connect_mitm: bool,
    assets: &ProductIngressAssets,
) -> Result<(), ProxySupervisorStartError> {
    if connect_mitm && assets.mitm().is_none() {
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
    ExplicitHttp,
    ExplicitHttps,
    TransparentHttp,
    ConnectInner {
        target: Box<CanonicalConnectTarget>,
        sni: Option<CanonicalHost>,
    },
    TransparentHttps {
        destination_port: u16,
        sni: CanonicalHost,
    },
}

impl RequestAuthority {
    fn ingress_mode(&self) -> IngressMode {
        match self {
            Self::ExplicitHttp => IngressMode::ExplicitHttp,
            Self::ExplicitHttps => IngressMode::ExplicitHttps,
            Self::TransparentHttp => IngressMode::TransparentHttp,
            Self::ConnectInner { .. } => IngressMode::ConnectMitmInner,
            Self::TransparentHttps { .. } => IngressMode::TransparentHttps,
        }
    }

    fn is_explicit(&self) -> bool {
        matches!(self, Self::ExplicitHttp | Self::ExplicitHttps)
    }
}

#[derive(Clone, Copy)]
enum ConfiguredRequestAuthority {
    ExplicitHttp,
    ExplicitHttps,
    TransparentHttp,
    DynamicTransparentHttps,
}

impl ConfiguredRequestAuthority {
    fn ingress_mode(self) -> Option<IngressMode> {
        match self {
            Self::ExplicitHttp => Some(IngressMode::ExplicitHttp),
            Self::ExplicitHttps => Some(IngressMode::ExplicitHttps),
            Self::TransparentHttp => Some(IngressMode::TransparentHttp),
            Self::DynamicTransparentHttps => None,
        }
    }
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
    connect_http1_denied: Option<bool>,
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
            connect_http1_denied: config
                .connect
                .as_ref()
                .and_then(crate::config::compiler::StaticConnectPolicy::http1_listener_denied),
        }
    }

    fn explicit_https(
        kind: ProxyListenerKind,
        config: StaticExplicitHttpsListener,
        acceptor: TlsAcceptor,
    ) -> Self {
        Self {
            kind,
            authority: ConfiguredRequestAuthority::ExplicitHttps,
            transport: IngressTransport::StaticTls {
                acceptor,
                handshake_timeout: config.handshake_timeout,
            },
            http_versions: config.http_versions,
            request_header_timeout: config.request_header_timeout,
            max_connections: config.max_connections,
            max_concurrent_streams: config.max_concurrent_streams,
            connect_http1_denied: config.connect.http1_listener_denied(),
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
            connect_http1_denied: None,
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
        mut stream,
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
    let http1 = versions.contains(&CompiledHttpVersion::Http1);
    let http2 = versions.contains(&CompiledHttpVersion::Http2);
    let validation = if http1 {
        let (validated, control) = match ValidatedIngressIo::try_new(stream, http2) {
            Ok(validated) => validated,
            Err(error) => {
                tracing::warn!(listener = %kind, %peer, %error, "HTTP/1 ingress validation allocation failed");
                return;
            }
        };
        stream = Box::new(validated);
        Some(control)
    } else {
        None
    };

    let close = Arc::new(ConnectionClose::default());
    let service_close = close.clone();
    let service_config = config.clone();
    let service_stop = supervisor_stop.clone();
    let service_validation = validation.clone();
    let service = service_fn(move |request| {
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
        let validation_ticket = match &service_validation {
            Some(control) => control.claim(observed_ingress_request_kind(&request)),
            None => Ok(None),
        };
        async move {
            let validation_ticket = match validation_ticket {
                Ok(ticket) => ticket,
                Err(_) => {
                    if let Some(lease) = runtime.lease().await {
                        PreProviderDecisionAudit::new(
                            observation_runtime.clone().into(),
                            &lease,
                            &request_id(),
                            peer.ip(),
                            &request,
                        )
                        .submit_deny(DecisionReasonCategory::InvalidPlan, 400);
                    }
                    let mut rejected = HandledResponse::fixed(
                        StatusCode::BAD_REQUEST,
                        "invalid request framing\n",
                        true,
                    );
                    rejected
                        .response
                        .headers_mut()
                        .insert(CONNECTION, HeaderValue::from_static("close"));
                    close.close();
                    return Ok::<_, Infallible>(rejected.response);
                }
            };
            let close_entire_connection = request.version() != http::Version::HTTP_2;
            let handled = if request.method() == Method::CONNECT && authority.is_explicit() {
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
                )
                .await
            } else {
                execute_request_via_pipeline(
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
            if let Some(ticket) = validation_ticket {
                if ticket.resolve(handled.request_disposition).is_err() {
                    handled = HandledResponse::fixed(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "request failed\n",
                        true,
                    );
                    handled
                        .response
                        .headers_mut()
                        .insert(CONNECTION, HeaderValue::from_static("close"));
                    close.close();
                }
            }
            Ok::<_, Infallible>(handled.response)
        }
    });

    let mut http = Http::new().with_executor(H2StreamExecutor);
    http.http1_keep_alive(true);
    http.http1_header_read_timeout(config.request_header_timeout);
    http.http2_max_header_list_size(
        u32::try_from(crate::http1::store::PARSER_STORE_BYTES)
            .expect("the fixed parser store size fits the H2 settings field"),
    );
    http.http2_max_concurrent_streams(config.max_concurrent_streams);
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

fn observed_ingress_request_kind(request: &Request<Body>) -> Option<IngressRequestKind> {
    if request.version() == Version::HTTP_2 {
        return None;
    }
    if request.method() == Method::CONNECT {
        return Some(IngressRequestKind::Connect);
    }
    let connection_upgrade = request.headers().get_all(CONNECTION).iter().any(|value| {
        value
            .as_bytes()
            .split(|byte| *byte == b',')
            .any(|token| trim_http_ows(token).eq_ignore_ascii_case(b"upgrade"))
    });
    Some(
        if connection_upgrade && request.headers().contains_key(UPGRADE) {
            IngressRequestKind::Upgrade
        } else {
            IngressRequestKind::Ordinary
        },
    )
}

fn trim_http_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
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
                let config_activation =
                    manager.server_config_for_host(sni.as_str(), alpn_protocols);
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
                    sni,
                },
            ))
        }
    }
}

fn establish_configured_authority(
    authority: ConfiguredRequestAuthority,
) -> Option<RequestAuthority> {
    match authority {
        ConfiguredRequestAuthority::ExplicitHttp => Some(RequestAuthority::ExplicitHttp),
        ConfiguredRequestAuthority::ExplicitHttps => Some(RequestAuthority::ExplicitHttps),
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

pub(super) struct HandledResponse {
    pub(super) response: Response<ProxyResponseBody>,
    pub(super) close_connection: bool,
    pub(super) request_disposition: RequestDisposition,
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
            request_disposition: if close_connection {
                RequestDisposition::Close
            } else {
                RequestDisposition::ContinueHttp
            },
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
        let sni = match start
            .client_hello()
            .server_name()
            .map(canonicalize_tls_server_name)
            .transpose()
        {
            Ok(sni) => sni,
            Err(_) => return,
        };
        if reconcile_connect_sni(&self.target, sni.as_ref()).is_err() {
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
        self.config.connect_http1_denied = None;
        serve_http_connection(HttpConnection {
            kind: self.kind,
            config: self.config,
            stream: Box::new(tls),
            versions: vec![selected],
            authority: RequestAuthority::ConnectInner {
                target: Box::new(self.target),
                sni,
            },
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

struct PreProviderDecisionAudit {
    target: DecisionSubmissionTarget,
    level: Option<CompiledDecisionLogLevel>,
    request_id: StableId,
    method: Option<HttpMethod>,
    url: Option<http_access_types::CanonicalUrl>,
    peer_ip: IpAddr,
    sensitive_header_presence: Box<[NeutralHeaderName]>,
}

impl PreProviderDecisionAudit {
    fn new(
        target: DecisionSubmissionTarget,
        lease: &GenerationLease,
        request_id: &str,
        peer_ip: IpAddr,
        request: &Request<Body>,
    ) -> Self {
        Self::from_policy(
            target,
            lease
                .observation()
                .decision_level(DecisionDisposition::Deny),
            lease.standalone().sensitive_header_policy(),
            request_id,
            peer_ip,
            request,
        )
    }

    fn from_policy<B>(
        target: DecisionSubmissionTarget,
        level: Option<CompiledDecisionLogLevel>,
        sensitive: &SensitiveHeaderPolicy,
        request_id: &str,
        peer_ip: IpAddr,
        request: &Request<B>,
    ) -> Self {
        let sensitive_header_presence = sensitive
            .names()
            .iter()
            .filter(|name| request.headers().contains_key(name.as_str()))
            .cloned()
            .collect();
        Self {
            target,
            level,
            request_id: StableId::new(request_id)
                .expect("product request identifiers are checked at construction"),
            method: HttpMethod::new(request.method().as_str()).ok(),
            url: None,
            peer_ip,
            sensitive_header_presence,
        }
    }

    fn bind_url(&mut self, url: &http_access_types::CanonicalUrl) {
        self.url = Some(url.clone());
    }

    fn submit_deny(self, category: DecisionReasonCategory, code: u16) {
        let source = DecisionAuditSource::Local(DecisionReason::new(category, code));
        let facts = DecisionAuditFacts::new(DecisionAuditFactsInput {
            request_id: &self.request_id,
            disposition: DecisionDisposition::Deny,
            method: self.method.as_ref(),
            url: self.url.as_ref(),
            peer_ip: Some(self.peer_ip),
            source: &source,
            sensitive_header_presence: &self.sensitive_header_presence,
        });
        let mut pending = match facts {
            Ok(facts) => PendingDecisionSubmission::new(self.target, self.level, facts),
            Err(_) => PendingDecisionSubmission::omitted(self.target, self.level),
        };
        pending.submit_now();
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

struct StandaloneConnectTerminal {
    config: IngressListenerConfig,
    target: CanonicalConnectTarget,
    peer: SocketAddr,
    quota_key: WireBodyQuotaKey,
    runtime: Arc<Runtime>,
    observation_runtime: Arc<ProductObservationRuntime>,
    upgrade_runtime: Arc<UpgradeRuntime>,
    assets: Arc<ProductIngressAssets>,
    tunnel_tx: mpsc::Sender<ConnectTunnelPlan>,
    admission: Arc<StdMutex<Option<OwnedSemaphorePermit>>>,
    tunnel_stop: watch::Receiver<SupervisorStop>,
    listener_denied: bool,
}

impl StandaloneTerminalService for StandaloneConnectTerminal {
    type Output = HandledResponse;

    fn fail_closed(self, _error: RequestPipelineError) -> BoxFuture<'static, Self::Output> {
        Box::pin(async {
            HandledResponse::fixed(StatusCode::INTERNAL_SERVER_ERROR, "request failed\n", true)
        })
    }

    fn respond(self, mut dispatch: StandaloneResponseDispatch) -> BoxFuture<'static, Self::Output> {
        dispatch.decision.submit_now();
        Box::pin(async move {
            let status = StatusCode::from_u16(dispatch.response.status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let message = match status {
                StatusCode::FORBIDDEN if self.listener_denied => "CONNECT denied\n",
                StatusCode::FORBIDDEN => "request denied\n",
                StatusCode::GATEWAY_TIMEOUT => "request timed out\n",
                StatusCode::SERVICE_UNAVAILABLE => "service unavailable\n",
                _ => "request failed\n",
            };
            HandledResponse::fixed(status, message, true)
        })
    }

    fn forward(self, dispatch: StandaloneForwardDispatch) -> BoxFuture<'static, Self::Output> {
        Box::pin(execute_connect_terminal(self, dispatch))
    }
}

async fn execute_connect_terminal(
    terminal: StandaloneConnectTerminal,
    dispatch: StandaloneForwardDispatch,
) -> HandledResponse {
    let StandaloneForwardDispatch {
        exchange,
        services,
        request_id: _,
        quota_key: _,
        retention,
        deadline,
        destinations: _,
        resolved: _,
        sidecar,
        credentials,
        transport,
        mut decision,
    } = dispatch;
    let StandaloneIngressTransport::OuterConnect {
        head,
        downstream_upgrade,
    } = transport
    else {
        return HandledResponse::fixed(StatusCode::INTERNAL_SERVER_ERROR, "request failed\n", true);
    };
    if crate::proxy::headers::product_protocol(head.ingress_version())
        != http_access_types::HttpProtocol::Http1
        || exchange.facts().method().as_str() != "CONNECT"
        || exchange.plan().origin() != terminal.target.url()
        || !matches!(exchange.plan().upgrade(), UpgradePolicy::Deny)
        || credentials.is_some()
    {
        return HandledResponse::fixed(StatusCode::INTERNAL_SERVER_ERROR, "request failed\n", true);
    }
    decision.submit_now();
    drop((exchange, sidecar, credentials, retention, services));

    let Some(manager) = terminal.assets.mitm().cloned() else {
        return HandledResponse::fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "service unavailable\n",
            true,
        );
    };
    let alpn_protocols = connect_alpn_protocols(&terminal.config.http_versions);
    let server_config = match tokio::time::timeout_at(
        deadline,
        manager
            .server_config_for_host(terminal.target.authority().host().as_str(), &alpn_protocols),
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
    let Some(admission) = terminal
        .admission
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
        kind: terminal.config.kind,
        config: terminal.config,
        target: terminal.target,
        server_config,
        downstream_upgrade,
        peer: terminal.peer,
        quota_key: terminal.quota_key,
        runtime: terminal.runtime,
        observation_runtime: terminal.observation_runtime,
        upgrade_runtime: terminal.upgrade_runtime,
        assets: terminal.assets,
        stop: terminal.tunnel_stop,
        tunnel_tx: terminal.tunnel_tx.clone(),
        _admission: admission,
    };
    if terminal.tunnel_tx.try_send(plan).is_err() {
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
        request_disposition: RequestDisposition::SwitchProtocol,
    }
}

async fn execute_connect_request(
    execution: ConnectRequestExecution,
    mut request: Request<Body>,
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
    let ingress_mode = config
        .authority
        .ingress_mode()
        .expect("outer CONNECT is only dispatched on an explicit listener");
    let request_id = request_id();
    let started_at = Instant::now();
    let Some(lease) = runtime.lease().await else {
        return HandledResponse::fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "service unavailable\n",
            true,
        );
    };
    let mut decision_audit = PreProviderDecisionAudit::new(
        observation_runtime.clone().into(),
        &lease,
        &request_id,
        peer.ip(),
        &request,
    );
    let target = match reconcile_connect_outer_request(&mut request) {
        Ok(target) => target,
        Err(_) => {
            decision_audit.submit_deny(DecisionReasonCategory::InvalidPlan, 400);
            return HandledResponse::fixed(
                StatusCode::BAD_REQUEST,
                "invalid CONNECT target\n",
                true,
            );
        }
    };
    decision_audit.bind_url(target.url());
    let listener_denied = match request.version() {
        Version::HTTP_10 | Version::HTTP_11 => config.connect_http1_denied,
        _ => None,
    };
    let listener_denied = match listener_denied {
        Some(denied) => denied,
        None => {
            decision_audit.submit_deny(DecisionReasonCategory::InvalidPlan, 400);
            return HandledResponse::fixed(StatusCode::BAD_REQUEST, "CONNECT unsupported\n", true);
        }
    };
    let validated = match validate_standalone_connect_ingress_request(
        IngressPartitionPolicy::from_lease(&lease),
        ingress_mode,
        target.url().clone(),
        request,
    ) {
        Ok(validated) => validated,
        Err(_) => {
            decision_audit.submit_deny(DecisionReasonCategory::InvalidPlan, 400);
            return HandledResponse::fixed(
                StatusCode::BAD_REQUEST,
                "invalid CONNECT request\n",
                true,
            );
        }
    };
    let preflight_target = match preflight_forwarding_target(
        target.url(),
        validated.ingress().protocol(),
        lease.egress(),
        assets.destination_guard(),
    ) {
        Ok(target) => target,
        Err(_) => {
            decision_audit.submit_deny(DecisionReasonCategory::InvalidPlan, 403);
            return HandledResponse::fixed(StatusCode::FORBIDDEN, "destination denied\n", true);
        }
    };
    let terminal = StandaloneConnectTerminal {
        config,
        target,
        peer,
        quota_key: quota_key.clone(),
        runtime,
        observation_runtime: observation_runtime.clone(),
        upgrade_runtime,
        assets: assets.clone(),
        tunnel_tx,
        admission,
        tunnel_stop,
        listener_denied,
    };
    let input = StandaloneProviderInput {
        request_id,
        validated,
        peer_ip: peer.ip(),
        quota_key,
        started_at,
        preflight_target,
        destinations: assets.destination_guard().clone(),
        clock: TokioRuntimeClock::new(started_at),
        listener_denied,
        decision_target: observation_runtime.into(),
    };
    let (provider, request) = match StandalonePolicyProvider::prepare(lease, terminal, input) {
        Ok(prepared) => prepared,
        Err(_) => {
            decision_audit.submit_deny(DecisionReasonCategory::InvalidPlan, 500);
            return HandledResponse::fixed(
                StatusCode::INTERNAL_SERVER_ERROR,
                "request failed\n",
                true,
            );
        }
    };
    RequestPipeline::new().execute(provider, request).await
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

pub(super) struct HttpCaptureContext {
    runtime: Arc<ProductObservationRuntime>,
    epoch: Arc<CaptureEpoch>,
    sensitive_headers: SensitiveHeaderPolicy,
    request_id: String,
    url: Option<SinkSafeUrl>,
    canonical_url: Option<http_access_url::CanonicalUrl>,
    method: Method,
    client: SocketAddr,
    ingress_mode: IngressMode,
    request_version: Version,
    max_expansion_ratio: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TerminalRequestBodyProvenance {
    Unconsumed,
    CompleteOriginal,
    CompleteWireRedacted,
    ProviderReplacement { size: usize },
}

struct DeniedCaptureBody {
    headers: HeaderMap,
    decoded: GuardedBody,
}

impl HttpCaptureContext {
    #[allow(clippy::too_many_arguments)]
    fn new<B>(
        runtime: Arc<ProductObservationRuntime>,
        epoch: Arc<CaptureEpoch>,
        sensitive_headers: SensitiveHeaderPolicy,
        request_id: String,
        peer: SocketAddr,
        request: &Request<B>,
        ingress_mode: IngressMode,
        max_expansion_ratio: usize,
    ) -> Self {
        Self {
            runtime,
            epoch,
            sensitive_headers,
            request_id,
            url: None,
            canonical_url: None,
            method: request.method().clone(),
            client: peer,
            ingress_mode,
            request_version: request.version(),
            max_expansion_ratio,
        }
    }

    fn bind_target(&mut self, target: &http_access_url::CanonicalUrl) {
        if !self.epoch.is_enabled() {
            return;
        }
        self.url = Some(SinkSafeUrl::from_canonical(target));
        self.canonical_url = Some(target.clone());
    }

    pub(super) fn upgrade_capture_context(
        &self,
        target: &http_access_url::CanonicalUrl,
    ) -> Option<UpgradeCaptureContext> {
        let base = self.record(
            CaptureKind::Request,
            CaptureDecision::Allow,
            self.request_version,
            None,
            None,
            false,
            Some(target),
        )?;
        Some(UpgradeCaptureContext::new(
            self.runtime.clone(),
            base,
            self.max_expansion_ratio,
        ))
    }

    pub(super) fn begin(
        &self,
        event: CaptureEvent,
        record: impl FnOnce() -> Option<SanitizedCaptureMetadata>,
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
    ) -> Option<SanitizedCaptureMetadata> {
        self.record(
            CaptureKind::Request,
            decision,
            self.request_version,
            headers,
            None,
            false,
            self.canonical_url.as_ref(),
        )
    }

    pub(super) fn response_record(
        &self,
        decision: CaptureDecision,
        version: Version,
        headers: Option<&HeaderMap>,
        status: StatusCode,
        include_status_message: bool,
    ) -> Option<SanitizedCaptureMetadata> {
        self.record(
            CaptureKind::Response,
            decision,
            version,
            headers,
            Some(status),
            include_status_message,
            self.canonical_url.as_ref(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        kind: CaptureKind,
        decision: CaptureDecision,
        version: Version,
        headers: Option<&HeaderMap>,
        status: Option<StatusCode>,
        include_status_message: bool,
        canonical_url: Option<&http_access_url::CanonicalUrl>,
    ) -> Option<SanitizedCaptureMetadata> {
        let event = match (kind, decision) {
            (CaptureKind::Request, CaptureDecision::Allow) => CaptureEvent::RequestAllowed,
            (CaptureKind::Response, CaptureDecision::Allow) => CaptureEvent::ResponseAllowed,
            (CaptureKind::Request, CaptureDecision::Deny) => CaptureEvent::RequestDenied,
            (CaptureKind::Response, CaptureDecision::Deny) => CaptureEvent::ResponseDenied,
        };
        let request_id = StableId::new(&self.request_id)
            .expect("product request identifiers are stable identifiers");
        let method = crate::proxy::facts::http_method(&self.method).ok();
        let sanitized_headers = headers
            .map(|headers| sanitize_capture_headers(headers, &self.sensitive_headers))
            .unwrap_or_default();
        let facts = CaptureFacts::new(
            &self.sensitive_headers,
            CaptureFactsInput {
                request_id: &request_id,
                event,
                ingress_mode: self.ingress_mode,
                method: method.as_ref(),
                url: canonical_url,
                client_ip: Some(self.client.ip()),
                target: canonical_url.map(http_access_url::CanonicalUrl::authority),
                version: crate::proxy::facts::http_version(version).ok(),
                status: status.map(|status| status.as_u16()),
                headers: &sanitized_headers,
            },
        )
        .ok()?;
        if canonical_url == self.canonical_url.as_ref() {
            debug_assert_eq!(
                facts.url().map(http_access_types::SinkSafeUrl::as_str),
                self.url.as_ref().map(SinkSafeUrl::as_str)
            );
        }
        Some(SanitizedCaptureMetadata::from_facts(
            facts,
            Utc::now().to_rfc3339(),
            Some(self.client.port()),
            headers.is_some(),
            include_status_message
                .then(|| {
                    status
                        .and_then(|status| status.canonical_reason())
                        .map(str::to_owned)
                })
                .flatten(),
        ))
    }

    pub(super) fn begin_allowed_request(
        &self,
        headers: &HeaderMap,
        body_headers: &HeaderMap,
        provenance: TerminalRequestBodyProvenance,
    ) -> Option<CaptureSubmission> {
        if let TerminalRequestBodyProvenance::ProviderReplacement { size } = provenance {
            if let Some(mut submission) = self.begin(
                CaptureEvent::RequestAllowed,
                || {
                    let mut record = self.request_record(CaptureDecision::Allow, Some(headers))?;
                    record.mark_provider_replacement_omitted(size);
                    Some(record)
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
        body: Option<DeniedCaptureBody>,
        provenance: TerminalRequestBodyProvenance,
    ) {
        let body_headers = body
            .as_ref()
            .map(|body| body.headers.clone())
            .unwrap_or_default();
        let Some(mut submission) = self.begin(
            CaptureEvent::RequestDenied,
            || {
                let mut record = self.request_record(CaptureDecision::Deny, headers)?;
                if let TerminalRequestBodyProvenance::ProviderReplacement { size } = provenance {
                    record.mark_provider_replacement_omitted(size);
                }
                Some(record)
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

    pub(super) fn fixed_response(
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

pub(super) struct CaptureSubmission {
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

    pub(super) fn push(&mut self, bytes: &[u8]) {
        if let Some(tap) = self.tap.as_mut() {
            tap.push(bytes);
        }
    }

    pub(super) fn finish(&mut self) {
        if let Some(tap) = self.tap.take() {
            self.submit(tap.finish());
        }
    }

    pub(super) fn finish_data_if_complete(&mut self, complete: bool) {
        if complete && !self.expect_trailers {
            self.finish();
        }
    }

    pub(super) fn abandon(&mut self) {
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

fn sanitize_capture_headers(
    headers: &HeaderMap,
    sensitive_headers: &SensitiveHeaderPolicy,
) -> Vec<SanitizedHeaderField> {
    let mut captured = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        let name = name.as_str().to_ascii_lowercase();
        let neutral_name = NeutralHeaderName::new(name.as_str())
            .expect("http header names are canonical neutral header names");
        let field = if sensitive_headers.contains(&neutral_name) {
            SanitizedHeaderField::redacted(neutral_name)
        } else {
            let neutral_value = NeutralHeaderValue::new(value.as_bytes().to_vec())
                .expect("http header values are valid neutral header values");
            SanitizedHeaderField::visible(sensitive_headers, neutral_name, neutral_value)
                .expect("non-sensitive header classification remains non-sensitive")
        };
        captured.push(field);
    }
    captured
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

pub(super) struct StandaloneHttpTerminal {
    pub(super) capture: HttpCaptureContext,
    pub(super) upgrade_runtime: Arc<UpgradeRuntime>,
}

impl StandaloneTerminalService for StandaloneHttpTerminal {
    type Output = HandledResponse;

    fn fail_closed(self, _error: RequestPipelineError) -> BoxFuture<'static, Self::Output> {
        Box::pin(async move {
            self.capture.fixed_response(
                CaptureDecision::Deny,
                StatusCode::INTERNAL_SERVER_ERROR,
                "request failed\n",
                true,
            )
        })
    }

    fn respond(self, mut dispatch: StandaloneResponseDispatch) -> BoxFuture<'static, Self::Output> {
        dispatch.decision.submit_now();
        Box::pin(async move {
            let status = StatusCode::from_u16(dispatch.response.status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let message = match status {
                StatusCode::FORBIDDEN => "request denied\n",
                StatusCode::GATEWAY_TIMEOUT => "request timed out\n",
                StatusCode::REQUEST_TIMEOUT => "request body denied\n",
                StatusCode::PAYLOAD_TOO_LARGE => "request body denied\n",
                StatusCode::UNSUPPORTED_MEDIA_TYPE => "request body denied\n",
                StatusCode::BAD_REQUEST => "request body denied\n",
                StatusCode::SERVICE_UNAVAILABLE => "service unavailable\n",
                _ => "request failed\n",
            };
            let close_connection = dispatch
                .observation
                .as_ref()
                .is_none_or(|observation| observation.close_connection);
            match dispatch.observation {
                Some(observation) => {
                    let (body, provenance) = match (
                        observation.body,
                        observation.body_provenance,
                    ) {
                        (
                            Some(body),
                            body_provenance @ (
                                StandaloneResponseBodyProvenance::CompleteOriginal
                                | StandaloneResponseBodyProvenance::CompleteWireRedacted
                            ),
                        ) => {
                            let mut body_headers = HeaderMap::new();
                            if let Some(content_type) = body
                                .content_type
                                .as_deref()
                                .and_then(|value| HeaderValue::from_str(value).ok())
                            {
                                body_headers.insert(CONTENT_TYPE, content_type);
                            }
                            body_headers
                                .insert(CONTENT_ENCODING, HeaderValue::from_static("identity"));
                            let provenance = match body_provenance {
                                StandaloneResponseBodyProvenance::CompleteOriginal => {
                                    TerminalRequestBodyProvenance::CompleteOriginal
                                }
                                StandaloneResponseBodyProvenance::CompleteWireRedacted => {
                                    TerminalRequestBodyProvenance::CompleteWireRedacted
                                }
                                _ => unreachable!("the match arm restricts response provenance"),
                            };
                            (
                                Some(DeniedCaptureBody {
                                    headers: body_headers,
                                    decoded: body.decoded,
                                }),
                                provenance,
                            )
                        }
                        (
                            None,
                            StandaloneResponseBodyProvenance::ProviderReplacement { size },
                        ) => (
                            None,
                            TerminalRequestBodyProvenance::ProviderReplacement { size },
                        ),
                        (None, StandaloneResponseBodyProvenance::Unconsumed) => {
                            (None, TerminalRequestBodyProvenance::Unconsumed)
                        }
                        (None, StandaloneResponseBodyProvenance::CompleteOriginal) => {
                            (None, TerminalRequestBodyProvenance::CompleteOriginal)
                        }
                        (None, StandaloneResponseBodyProvenance::CompleteWireRedacted) => {
                            (None, TerminalRequestBodyProvenance::CompleteWireRedacted)
                        }
                        _ => (None, TerminalRequestBodyProvenance::Unconsumed),
                    };
                    self.capture.submit_denied_request(
                        Some(&observation.headers),
                        body,
                        provenance,
                    );
                }
                None => self.capture.submit_denied_request(
                    None,
                    None,
                    TerminalRequestBodyProvenance::Unconsumed,
                ),
            }
            self.capture
                .fixed_response(CaptureDecision::Deny, status, message, close_connection)
        })
    }

    fn forward(self, dispatch: StandaloneForwardDispatch) -> BoxFuture<'static, Self::Output> {
        Box::pin(ForwardingExecutor::execute(self, dispatch))
    }
}

async fn execute_request_via_pipeline(
    execution: RequestExecution,
    mut request: Request<Body>,
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
    if let Some(h2_stream) = H2StreamCancellation::current() {
        request.extensions_mut().insert(h2_stream);
    }
    let started_at = Instant::now();
    let request_id = request_id();
    let ingress_mode = authority.ingress_mode();
    let Some(lease) = runtime.lease().await else {
        return HandledResponse::fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "service unavailable\n",
            true,
        );
    };
    let mut decision_audit = PreProviderDecisionAudit::new(
        observation_runtime.clone().into(),
        &lease,
        &request_id,
        peer.ip(),
        &request,
    );
    let mut capture = HttpCaptureContext::new(
        observation_runtime.clone(),
        lease.observation().capture_epoch().clone(),
        lease.standalone().sensitive_header_policy().clone(),
        request_id.clone(),
        peer,
        &request,
        ingress_mode,
        lease.max_content_decoding_expansion_ratio(),
    );
    let (connect_target, sni, destination_port) = match &authority {
        RequestAuthority::ExplicitHttp
        | RequestAuthority::ExplicitHttps
        | RequestAuthority::TransparentHttp => (None, None, None),
        RequestAuthority::ConnectInner { target, sni } => {
            (Some(target.as_ref()), sni.as_ref(), None)
        }
        RequestAuthority::TransparentHttps {
            destination_port,
            sni,
        } => (None, Some(sni), Some(*destination_port)),
    };
    let target = match reconcile_request(
        &mut request,
        ingress_mode,
        connect_target,
        sni,
        destination_port,
    ) {
        Ok(target) => target,
        Err(_) => {
            decision_audit.submit_deny(DecisionReasonCategory::InvalidPlan, 400);
            return capture.deny_metadata_only(
                StatusCode::BAD_REQUEST,
                "invalid request target\n",
                true,
            );
        }
    };
    decision_audit.bind_url(target.url());
    capture.bind_target(target.url());
    let validated = match validate_standalone_ingress_request(
        IngressPartitionPolicy::from_lease(&lease),
        ingress_mode,
        target.url().clone(),
        request,
    ) {
        Ok(validated) => validated,
        Err(_) => {
            decision_audit.submit_deny(DecisionReasonCategory::InvalidPlan, 400);
            return capture.deny_metadata_only(StatusCode::BAD_REQUEST, "invalid request\n", true);
        }
    };
    let preflight_target = match preflight_forwarding_target(
        target.url(),
        validated.ingress().protocol(),
        lease.egress(),
        assets.destination_guard(),
    ) {
        Ok(target) => target,
        Err(_) => {
            decision_audit.submit_deny(DecisionReasonCategory::InvalidPlan, 403);
            return capture.deny_metadata_only(StatusCode::FORBIDDEN, "destination denied\n", true);
        }
    };
    let terminal = StandaloneHttpTerminal {
        capture,
        upgrade_runtime,
    };
    let input = StandaloneProviderInput {
        request_id,
        validated,
        peer_ip: peer.ip(),
        quota_key,
        started_at,
        preflight_target,
        destinations: assets.destination_guard().clone(),
        clock: TokioRuntimeClock::new(started_at),
        listener_denied: false,
        decision_target: observation_runtime.into(),
    };
    let (provider, request) = match StandalonePolicyProvider::prepare(lease, terminal, input) {
        Ok(prepared) => prepared,
        Err(_) => {
            decision_audit.submit_deny(DecisionReasonCategory::InvalidPlan, 500);
            return HandledResponse::fixed(
                StatusCode::INTERNAL_SERVER_ERROR,
                "request failed\n",
                true,
            );
        }
    };
    RequestPipeline::new().execute(provider, request).await
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

pub(super) enum ProxyResponseBody {
    Local(Body),
    Forwarded {
        body: Box<ForwardedDownstreamBody>,
        capture: Option<Box<CaptureSubmission>>,
    },
}

impl ProxyResponseBody {
    pub(super) fn forwarded(
        body: ForwardedDownstreamBody,
        capture: Option<CaptureSubmission>,
    ) -> Self {
        Self::Forwarded {
            body: Box::new(body),
            capture: capture.map(Box::new),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum ProxyResponseBodyError {
    #[error(transparent)]
    Local(#[from] hyper::Error),
    #[error(transparent)]
    Forwarded(hyper::Error),
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
                match Pin::new(&mut **body).poll_data(context) {
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
            Self::Forwarded { body, capture } => match Pin::new(&mut **body).poll_trailers(context)
            {
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
    use tokio::sync::{mpsc, oneshot};
    use tokio_rustls::TlsConnector;

    use super::*;
    use crate::activation::runner::ProductRuntime;
    use crate::capture::CaptureRecord;
    use crate::config::{compile_config_text, load_and_compile_exact_config, ConfigTextInput};
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

    #[test]
    fn request_authority_variants_map_to_exact_ingress_modes() {
        let mut connect = Request::builder()
            .method(Method::CONNECT)
            .uri("example.test:443")
            .header(http::header::HOST, "example.test:443")
            .body(())
            .unwrap();
        let target = reconcile_connect_outer_request(&mut connect).unwrap();
        let sni = canonicalize_tls_server_name("example.test").unwrap();
        let cases = [
            (RequestAuthority::ExplicitHttp, IngressMode::ExplicitHttp),
            (RequestAuthority::ExplicitHttps, IngressMode::ExplicitHttps),
            (
                RequestAuthority::TransparentHttp,
                IngressMode::TransparentHttp,
            ),
            (
                RequestAuthority::ConnectInner {
                    target: Box::new(target),
                    sni: Some(sni.clone()),
                },
                IngressMode::ConnectMitmInner,
            ),
            (
                RequestAuthority::TransparentHttps {
                    destination_port: 8443,
                    sni,
                },
                IngressMode::TransparentHttps,
            ),
        ];
        for (authority, expected) in cases {
            assert_eq!(authority.ingress_mode(), expected);
        }
    }

    #[test]
    fn pre_provider_denials_submit_one_checked_fact_per_failure_boundary() {
        let policy = SensitiveHeaderPolicy::new([], [], []).unwrap();
        let request = Request::builder()
            .method(Method::from_bytes(b"lowercase").unwrap())
            .uri("/")
            .header("authorization", "never-copied")
            .header("cookie", "session=never-copied")
            .body(())
            .unwrap();
        let submissions = Arc::new(StdMutex::new(Vec::new()));
        let target = DecisionSubmissionTarget::FactsProbe(submissions.clone());

        PreProviderDecisionAudit::from_policy(
            target.clone(),
            Some(CompiledDecisionLogLevel::Warn),
            &policy,
            "pre-normalization",
            "192.0.2.10".parse().unwrap(),
            &request,
        )
        .submit_deny(DecisionReasonCategory::InvalidPlan, 400);

        let canonical =
            http_access_url::canonicalize_http_url("https://example.test/path").unwrap();
        for (request_id, code) in [("validation", 400), ("preflight", 403), ("prepare", 500)] {
            let mut audit = PreProviderDecisionAudit::from_policy(
                target.clone(),
                Some(CompiledDecisionLogLevel::Warn),
                &policy,
                request_id,
                "192.0.2.10".parse().unwrap(),
                &request,
            );
            audit.bind_url(&canonical);
            audit.submit_deny(DecisionReasonCategory::InvalidPlan, code);
        }

        let facts = submissions.lock().unwrap();
        assert_eq!(facts.len(), 4);
        assert!(facts[0].method().is_none());
        assert!(facts[0].url().is_none());
        assert_eq!(
            facts[0].sensitive_header_presence(),
            &[
                NeutralHeaderName::new("authorization").unwrap(),
                NeutralHeaderName::new("cookie").unwrap(),
            ]
        );
        assert!(facts[1..].iter().all(|fact| fact.url().is_some()));
        assert_eq!(
            facts
                .iter()
                .map(|fact| fact.reason().code())
                .collect::<Vec<_>>(),
            vec![400, 400, 403, 500]
        );
    }

    #[test]
    fn oversized_pre_provider_decision_is_omitted_without_affecting_the_next_request() {
        let policy = SensitiveHeaderPolicy::new([], [], []).unwrap();
        let request = Request::builder().uri("/").body(()).unwrap();
        let submissions = Arc::new(AtomicUsize::new(0));
        let target = DecisionSubmissionTarget::Probe(submissions.clone());
        let oversized = http_access_url::canonicalize_http_url(&format!(
            "https://example.test/{}",
            "x".repeat(1024 * 1024)
        ))
        .unwrap();
        let bounded = http_access_url::canonicalize_http_url("https://example.test/next").unwrap();

        for (request_id, url) in [("oversized", &oversized), ("bounded", &bounded)] {
            let mut audit = PreProviderDecisionAudit::from_policy(
                target.clone(),
                Some(CompiledDecisionLogLevel::Warn),
                &policy,
                request_id,
                "192.0.2.10".parse().unwrap(),
                &request,
            );
            audit.bind_url(url);
            audit.submit_deny(DecisionReasonCategory::InvalidPlan, 400);
        }

        assert_eq!(submissions.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn oversized_h2_capture_metadata_is_omitted_without_affecting_the_next_record() {
        let runtime = Arc::new(ProductObservationRuntime::try_new(1).unwrap());
        let request = Request::builder()
            .version(Version::HTTP_2)
            .uri("http://example.test/")
            .body(())
            .unwrap();
        let capture = HttpCaptureContext::new(
            runtime.clone(),
            runtime.current_capture_epoch(),
            SensitiveHeaderPolicy::new([], [], []).unwrap(),
            "capture-bounds".to_owned(),
            "192.0.2.10:1234".parse().unwrap(),
            &request,
            IngressMode::ExplicitHttp,
            16,
        );
        let mut oversized_headers = HeaderMap::new();
        oversized_headers.insert(
            "x-large",
            HeaderValue::from_bytes(&vec![b'x'; 1024 * 1024 + 1]).unwrap(),
        );

        assert!(capture
            .request_record(CaptureDecision::Allow, Some(&oversized_headers))
            .is_none());
        assert!(capture
            .request_record(CaptureDecision::Allow, Some(&HeaderMap::new()))
            .is_some());

        runtime.shutdown().await;
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

    struct OverrideIngressAssetsStarter {
        inner: ProductProxySupervisorStarter,
        assets: Arc<ProductIngressAssets>,
    }

    impl ProxySupervisorStarter for OverrideIngressAssetsStarter {
        fn start(
            &mut self,
            listener: PreparedProxyListener,
            _assets: &Arc<ProductIngressAssets>,
            failure_observer: Arc<dyn ProxySupervisorFailureObserver>,
        ) -> Result<Arc<dyn ProxySupervisor>, ProxySupervisorStartError> {
            self.inner.start(listener, &self.assets, failure_observer)
        }
    }

    async fn listener_product_with_destination_guard(
        text: String,
        listeners: Vec<StdTcpListener>,
        destination_guard: Arc<DestinationGuard>,
    ) -> (tempfile::TempDir, Arc<ProductRuntime>) {
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
        let mut starter = OverrideIngressAssetsStarter {
            inner: ProductProxySupervisorStarter::new(
                product.runtime().clone(),
                product.observation_runtime().clone(),
                product.upgrade_runtime(),
            ),
            assets,
        };
        product.start_proxy_supervisors(&mut starter).await.unwrap();
        (directory, product)
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
        request: Request<Body>,
    ) -> HandledResponse {
        let peer = SocketAddr::from(([192, 0, 2, 44], 41_000));
        execute_request_via_pipeline(
            RequestExecution {
                authority: RequestAuthority::ExplicitHttp,
                peer,
                quota_key: WireBodyQuotaKey::from_peer(peer.ip(), |_| false),
                runtime: product.runtime().clone(),
                observation_runtime: product.observation_runtime().clone(),
                upgrade_runtime: product.upgrade_runtime(),
                assets,
            },
            request,
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

    async fn send_raw_http(address: SocketAddr, wire: &[u8]) -> Vec<u8> {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(wire).await.unwrap();
        read_raw_http_response(stream).await
    }

    async fn read_raw_http_response(mut stream: impl AsyncRead + AsyncWrite + Unpin) -> Vec<u8> {
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .expect("raw HTTP response timed out")
            .unwrap();
        response
    }

    fn assert_forbidden_http10(response: &[u8], mode: &str) {
        assert!(
            response.starts_with(b"HTTP/1.0 403 ") || response.starts_with(b"HTTP/1.1 403 "),
            "unexpected {mode} HTTP/1.0 response: {}",
            String::from_utf8_lossy(response)
        );
        assert!(
            response.ends_with(b"request denied\n"),
            "{mode} HTTP/1.0 request did not reach policy: {}",
            String::from_utf8_lossy(response)
        );
    }

    #[tokio::test]
    async fn http10_requests_reach_policy_in_all_five_ingress_modes() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let deny_policy = r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"
"#;

        let ([proxy], listeners) = prebound_listeners::<1>();
        let (_directory, runtime) =
            product(base_config(proxy, "explicit_http", deny_policy), listeners).await;
        let response = send_raw_http(
            proxy,
            b"GET http://explicit.test/denied HTTP/1.0\r\nHost: explicit.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_forbidden_http10(&response, "explicit HTTP");
        runtime.shutdown().await;

        let ([proxy], listeners) = prebound_listeners::<1>();
        let transparent_policy = r#"[policy]
default = "deny"
"#;
        let (_directory, runtime) = product_with_original_destination(
            base_config(proxy, "transparent_http", transparent_policy),
            listeners,
            Arc::new(FixedOriginalDestination(SocketAddr::from((
                [198, 51, 100, 17],
                8080,
            )))),
        )
        .await;
        let response = send_raw_http(
            proxy,
            b"GET /denied HTTP/1.0\r\nHost: transparent.test:8080\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_forbidden_http10(&response, "transparent HTTP");
        runtime.shutdown().await;

        let ([proxy], listeners) = prebound_listeners::<1>();
        let (identity, certificate) = test_tls_identity();
        let explicit_https_policy = format!(
            r#"[listeners.explicit_https.connect]
http1 = "deny"

[listeners.explicit_https.tls]
certificate_chain = "{}"
private_key = "{}"

[policy]
default = "deny"
"#,
            identity.path().join("server.pem").display(),
            identity.path().join("server-key.pem").display(),
        );
        let (_directory, runtime) = product(
            base_config(proxy, "explicit_https", &explicit_https_policy),
            listeners,
        )
        .await;
        let connector = test_tls_connector(certificate, vec![b"http/1.1".to_vec()]);
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let mut stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        stream
            .write_all(b"GET https://explicit.test/denied HTTP/1.0\r\nHost: explicit.test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let response = read_raw_http_response(stream).await;
        assert_forbidden_http10(&response, "explicit HTTPS");
        runtime.shutdown().await;

        let ([proxy], listeners) = prebound_listeners::<1>();
        let transparent_https_policy = r#"[mitm]
mode = "generated"
directory = "mitm"

[policy]
default = "deny"
"#;
        let (directory, runtime) = product_with_original_destination(
            base_config(proxy, "transparent_https", transparent_https_policy),
            listeners,
            Arc::new(FixedOriginalDestination(SocketAddr::from((
                [198, 51, 100, 17],
                8443,
            )))),
        )
        .await;
        let certificate = read_first_pem_certificate(&directory.path().join("mitm/ca-cert.pem"));
        let connector = test_tls_connector(certificate, vec![b"http/1.1".to_vec()]);
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let mut stream = connector
            .connect(ServerName::try_from("transparent.test").unwrap(), stream)
            .await
            .unwrap();
        stream
            .write_all(
                b"GET /denied HTTP/1.0\r\nHost: transparent.test:8443\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_raw_http_response(stream).await;
        assert_forbidden_http10(&response, "transparent HTTPS");
        runtime.shutdown().await;

        let ([proxy], listeners) = prebound_listeners::<1>();
        let target = "192.0.2.10:443";
        let connect_policy = connect_mitm_policy(target).replacen(
            &format!("urls = [\"https://{target}/**\"]"),
            &format!("urls = [\"https://{target}/**\"]\nmethods = [\"CONNECT\"]"),
            1,
        );
        let (directory, runtime) = product(
            base_config(proxy, "explicit_http", &connect_policy),
            listeners,
        )
        .await;
        let outer = open_connect(proxy, target).await;
        let certificate = read_first_pem_certificate(&directory.path().join("mitm/ca-cert.pem"));
        let connector = test_tls_connector(certificate, vec![b"http/1.1".to_vec()]);
        let mut inner = connector
            .connect(ServerName::try_from("192.0.2.10").unwrap(), outer)
            .await
            .unwrap();
        inner
            .write_all(b"GET /denied HTTP/1.0\r\nHost: 192.0.2.10\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let response = read_raw_http_response(inner).await;
        assert_forbidden_http10(&response, "CONNECT MITM inner");
        runtime.shutdown().await;
    }

    #[cfg(unix)]
    #[derive(Clone, Copy, Debug)]
    enum ProviderIngressCase {
        ExplicitHttp,
        ExplicitHttps,
        TransparentHttp,
        ConnectMitmInner,
        TransparentHttps,
    }

    #[cfg(unix)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ProviderIngressProtocol {
        Http1,
        Http2,
    }

    #[cfg(unix)]
    impl ProviderIngressProtocol {
        fn alpn(self) -> Vec<u8> {
            match self {
                Self::Http1 => b"http/1.1".to_vec(),
                Self::Http2 => b"h2".to_vec(),
            }
        }
    }

    #[cfg(unix)]
    trait ProviderTestIo: AsyncRead + AsyncWrite + Unpin + Send {}

    #[cfg(unix)]
    impl<T> ProviderTestIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

    #[cfg(unix)]
    struct ProviderIngressFixture {
        case: ProviderIngressCase,
        proxy: SocketAddr,
        origin: SocketAddr,
        client_certificate: Vec<u8>,
        _directory: tempfile::TempDir,
        _marker_directory: tempfile::TempDir,
        product: Arc<ProductRuntime>,
        origin_task: tokio::task::JoinHandle<()>,
    }

    #[cfg(unix)]
    impl ProviderIngressFixture {
        async fn open_stream(&self) -> Box<dyn ProviderTestIo> {
            self.open_stream_for(ProviderIngressProtocol::Http1).await
        }

        async fn open_stream_for(
            &self,
            protocol: ProviderIngressProtocol,
        ) -> Box<dyn ProviderTestIo> {
            match self.case {
                ProviderIngressCase::ExplicitHttp | ProviderIngressCase::TransparentHttp => {
                    Box::new(tokio::net::TcpStream::connect(self.proxy).await.unwrap())
                }
                ProviderIngressCase::ExplicitHttps | ProviderIngressCase::TransparentHttps => {
                    let connector =
                        test_tls_connector(self.client_certificate.clone(), vec![protocol.alpn()]);
                    let stream = tokio::net::TcpStream::connect(self.proxy).await.unwrap();
                    Box::new(
                        connector
                            .connect(ServerName::try_from("localhost").unwrap(), stream)
                            .await
                            .unwrap(),
                    )
                }
                ProviderIngressCase::ConnectMitmInner => {
                    let connector =
                        test_tls_connector(self.client_certificate.clone(), vec![protocol.alpn()]);
                    let stream = open_connect(self.proxy, &self.origin.to_string()).await;
                    Box::new(
                        connector
                            .connect(ServerName::try_from("127.0.0.1").unwrap(), stream)
                            .await
                            .unwrap(),
                    )
                }
            }
        }

        fn request_target(&self, path: &str) -> String {
            match self.case {
                ProviderIngressCase::ExplicitHttp => {
                    format!("http://localhost:{}{path}", self.origin.port())
                }
                ProviderIngressCase::ExplicitHttps => {
                    format!("https://localhost:{}{path}", self.origin.port())
                }
                ProviderIngressCase::TransparentHttp
                | ProviderIngressCase::ConnectMitmInner
                | ProviderIngressCase::TransparentHttps => path.to_owned(),
            }
        }

        fn request_target_for(&self, path: &str, protocol: ProviderIngressProtocol) -> String {
            if protocol == ProviderIngressProtocol::Http1 {
                return self.request_target(path);
            }
            match self.case {
                ProviderIngressCase::ExplicitHttp | ProviderIngressCase::TransparentHttp => {
                    format!("http://localhost:{}{path}", self.origin.port())
                }
                ProviderIngressCase::ExplicitHttps | ProviderIngressCase::TransparentHttps => {
                    format!("https://localhost:{}{path}", self.origin.port())
                }
                ProviderIngressCase::ConnectMitmInner => {
                    format!("https://{}{path}", self.origin)
                }
            }
        }

        fn request_host(&self) -> String {
            match self.case {
                ProviderIngressCase::ConnectMitmInner => self.origin.to_string(),
                _ => format!("localhost:{}", self.origin.port()),
            }
        }

        async fn request(&self, path: &str, body: &'static str) -> Response<Body> {
            let stream = self.open_stream().await;
            let (mut sender, connection) = conn::handshake(stream).await.unwrap();
            let driver = tokio::spawn(connection);
            let response = sender
                .send_request(
                    Request::builder()
                        .method(Method::POST)
                        .uri(self.request_target(path))
                        .header(http::header::HOST, self.request_host())
                        .header(CONTENT_TYPE, "text/plain")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            drop(sender);
            let (parts, body) = response.into_parts();
            let body = to_bytes(body).await.unwrap();
            driver.await.unwrap().unwrap();
            Response::from_parts(parts, Body::from(body))
        }

        async fn request_upgrade(&self) -> Vec<u8> {
            let mut stream = self.open_stream().await;
            stream
                .write_all(
                    format!(
                        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: upgrade\r\nUpgrade: obs-text\r\n\r\n",
                        self.request_target("/upgrade"),
                        self.request_host(),
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            read_http_head(&mut stream).await
        }

        async fn begin_cancelled_request(&self) -> Box<dyn ProviderTestIo> {
            let mut stream = self.open_stream().await;
            let target = self.request_target("/cancel");
            stream
                .write_all(
                    format!(
                        "POST {target} HTTP/1.1\r\nHost: {}\r\nContent-Length: 4\r\nContent-Type: text/plain\r\n\r\nbody",
                        self.request_host()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream
        }
    }

    #[cfg(unix)]
    fn provider_policy(origin: SocketAddr, marker: &std::path::Path) -> String {
        format!(
            r#"[authorization.providers.corpus]
kind = "process"
command = "/usr/bin/python3"
args = ["-u", "-c", '''
import json, sys, threading, time
marker = {marker:?}
lock = threading.Lock()

def send(response):
    with lock:
        print(json.dumps(response, separators=(",", ":")), flush=True)

def complete(request):
    url = request["url"]
    if request["method"] == "CONNECT":
        send({{"id": request["id"], "type": "response", "decision": "allow"}})
    elif url.endswith("/timeout") or url.endswith("/cancel"):
        time.sleep(30)
        send({{"id": request["id"], "type": "response", "decision": "allow", "values": {{"token": "late"}}}})
    elif url.endswith("/pass"):
        send({{"id": request["id"], "type": "response", "decision": "pass"}})
    elif url.endswith("/deny"):
        send({{"id": request["id"], "type": "response", "decision": "deny"}})
    elif url.endswith("/error"):
        send({{"id": request["id"], "type": "response", "decision": "invalid"}})
    elif url.endswith("/invalid-encoding"):
        send({{"id": request["id"], "type": "response", "decision": "allow", "values": {{"token": "typed-secret"}}, "requestBody": {{"encoding": "base64", "contentType": "text/plain", "contentEncoding": "gzip", "data": "cmVwbGFjZW1lbnQtYm9keQ=="}}}})
    elif url.endswith("/upgrade"):
        send({{"id": request["id"], "type": "response", "decision": "allow", "values": {{"token": "typed-secret"}}}})
    else:
        send({{"id": request["id"], "type": "response", "decision": "allow", "values": {{"token": "typed-secret"}}, "requestBody": {{"encoding": "base64", "contentType": "text/plain", "data": "cmVwbGFjZW1lbnQtYm9keQ=="}}}})

for line in sys.stdin:
    request = json.loads(line)
    with open(marker, "a", encoding="utf-8") as output:
        output.write(request["url"] + "\n")
        output.flush()
    threading.Thread(target=complete, args=(request,), daemon=True).start()
''']
timeout = "5s"
retire_timeout = "6s"
on_failure = "error"
inherit_environment = false
environment = {{ PATH = "/usr/bin:/bin" }}
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 1024
max_decoded_request_body_bytes = 1024
max_stdout_line_bytes = 4096

[authorization.providers.corpus.outputs.token]
kind = "bearer"
required = true

[policy]
default = "deny"

[[policy.rules]]
id = "provider-timeout"
decision = "delegate"
urls = ["http://localhost:{port}/timeout", "https://localhost:{port}/timeout", "https://{origin}/timeout"]
methods = ["POST"]
authorization_provider = "corpus"
request_timeout = "100ms"

[[policy.rules]]
id = "provider-corpus"
decision = "delegate"
urls = ["http://localhost:{port}/**", "https://localhost:{port}/**", "https://{origin}/**"]
methods = ["POST"]
authorization_provider = "corpus"

[[policy.rules]]
id = "provider-upgrade"
decision = "delegate"
urls = ["http://localhost:{port}/upgrade", "https://localhost:{port}/upgrade", "https://{origin}/upgrade"]
methods = ["GET"]
authorization_provider = "corpus"
allow_upgrades = true

[[policy.rules]]
id = "after-provider-pass"
decision = "allow"
urls = ["http://localhost:{port}/pass", "https://localhost:{port}/pass", "https://{origin}/pass"]
methods = ["POST"]
"#,
            marker = marker.display().to_string(),
            port = origin.port(),
        )
    }

    #[cfg(unix)]
    async fn start_provider_origin(
        tls: bool,
    ) -> (
        SocketAddr,
        tempfile::TempDir,
        tokio::sync::mpsc::UnboundedReceiver<(String, HeaderMap, Bytes)>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (identity, _) = test_tls_identity();
        let acceptor = tls.then(|| {
            crate::tls_identity::load_static_tls_acceptor(
                &identity.path().join("server.pem"),
                &identity.path().join("server-key.pem"),
                vec![b"http/1.1".to_vec()],
            )
            .unwrap()
        });
        let (seen_tx, seen_rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let seen_tx = seen_tx.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |mut request: Request<Body>| {
                        let seen_tx = seen_tx.clone();
                        async move {
                            let upgrade = request.headers().get(UPGRADE).cloned();
                            let _on_upgrade =
                                upgrade.as_ref().map(|_| hyper::upgrade::on(&mut request));
                            let (parts, body) = request.into_parts();
                            let body = to_bytes(body).await.unwrap();
                            seen_tx
                                .send((parts.uri.path().to_owned(), parts.headers, body))
                                .unwrap();
                            match upgrade {
                                Some(upgrade) => Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::SWITCHING_PROTOCOLS)
                                        .header(CONNECTION, "upgrade")
                                        .header(UPGRADE, upgrade)
                                        .body(Body::empty())
                                        .unwrap(),
                                ),
                                None => Ok(Response::new(Body::from("origin accepted"))),
                            }
                        }
                    });
                    if let Some(acceptor) = acceptor {
                        let stream = acceptor.accept(stream).await.unwrap();
                        Http::new()
                            .http1_only(true)
                            .serve_connection(stream, service)
                            .with_upgrades()
                            .await
                            .unwrap();
                    } else {
                        Http::new()
                            .http1_only(true)
                            .serve_connection(stream, service)
                            .with_upgrades()
                            .await
                            .unwrap();
                    }
                });
            }
        });
        (address, identity, seen_rx, task)
    }

    #[cfg(unix)]
    async fn provider_ingress_fixture(
        case: ProviderIngressCase,
    ) -> (
        ProviderIngressFixture,
        tokio::sync::mpsc::UnboundedReceiver<(String, HeaderMap, Bytes)>,
        std::path::PathBuf,
    ) {
        provider_ingress_fixture_for(case, ProviderIngressProtocol::Http1).await
    }

    #[cfg(unix)]
    async fn provider_ingress_fixture_for(
        case: ProviderIngressCase,
        protocol: ProviderIngressProtocol,
    ) -> (
        ProviderIngressFixture,
        tokio::sync::mpsc::UnboundedReceiver<(String, HeaderMap, Bytes)>,
        std::path::PathBuf,
    ) {
        let tls_origin = matches!(
            case,
            ProviderIngressCase::ExplicitHttps
                | ProviderIngressCase::ConnectMitmInner
                | ProviderIngressCase::TransparentHttps
        );
        let (origin, origin_identity, seen, origin_task) = start_provider_origin(tls_origin).await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let marker_directory = tempdir().unwrap();
        let marker = marker_directory.path().join("provider-calls");
        let policy = provider_policy(origin, &marker);
        let (incoming_identity, incoming_certificate) = test_tls_identity();
        let listener_table;
        let mut listener_policy;
        match case {
            ProviderIngressCase::ExplicitHttp => {
                listener_table = "explicit_http";
                listener_policy =
                    format!("[listeners.explicit_http.connect]\nhttp1 = \"deny\"\n\n{policy}");
            }
            ProviderIngressCase::ExplicitHttps => {
                listener_table = "explicit_https";
                listener_policy = format!(
                    "[listeners.explicit_https.connect]\nhttp1 = \"deny\"\n\n[listeners.explicit_https.tls]\ncertificate_chain = \"{}\"\nprivate_key = \"{}\"\n\n{policy}",
                    incoming_identity.path().join("server.pem").display(),
                    incoming_identity.path().join("server-key.pem").display(),
                );
            }
            ProviderIngressCase::TransparentHttp => {
                listener_table = "transparent_http";
                listener_policy = policy;
            }
            ProviderIngressCase::ConnectMitmInner => {
                listener_table = "explicit_http";
                listener_policy = format!(
                    "[listeners.explicit_http.connect]\nhttp1 = \"mitm\"\n\n[mitm]\nmode = \"generated\"\ndirectory = \"mitm\"\n\n[[policy.rules]]\nid = \"connect-target\"\ndecision = \"delegate\"\nurls = [\"https://{origin}/**\"]\nmethods = [\"CONNECT\"]\nauthorization_provider = \"corpus\"\n\n{policy}"
                );
            }
            ProviderIngressCase::TransparentHttps => {
                listener_table = "transparent_https";
                listener_policy =
                    format!("[mitm]\nmode = \"generated\"\ndirectory = \"mitm\"\n\n{policy}");
            }
        }
        if protocol == ProviderIngressProtocol::Http2 {
            match case {
                ProviderIngressCase::ExplicitHttp | ProviderIngressCase::ExplicitHttps => {
                    listener_policy = listener_policy.replacen(
                        "http1 = \"deny\"",
                        "http1 = \"deny\"\nhttp2 = \"deny\"",
                        1,
                    );
                }
                ProviderIngressCase::ConnectMitmInner => {
                    listener_policy = listener_policy.replacen(
                        "http1 = \"mitm\"",
                        "http1 = \"mitm\"\nhttp2 = \"deny\"",
                        1,
                    );
                }
                ProviderIngressCase::TransparentHttp | ProviderIngressCase::TransparentHttps => {}
            }
        }
        let mut config = base_config(proxy, listener_table, &listener_policy).replacen(
            "trust = \"system\"",
            "trust = \"insecure\"",
            1,
        );
        if protocol == ProviderIngressProtocol::Http2 {
            config = config.replacen(
                "http_versions = [\"http1\"]",
                "http_versions = [\"http1\", \"http2\"]",
                1,
            );
        }
        let (directory, product) = match case {
            ProviderIngressCase::TransparentHttp | ProviderIngressCase::TransparentHttps => {
                product_with_original_destination(
                    config,
                    listeners,
                    Arc::new(FixedOriginalDestination(origin)),
                )
                .await
            }
            _ => product(config, listeners).await,
        };
        let client_certificate = match case {
            ProviderIngressCase::ExplicitHttps => incoming_certificate,
            ProviderIngressCase::ConnectMitmInner | ProviderIngressCase::TransparentHttps => {
                read_first_pem_certificate(&directory.path().join("mitm/ca-cert.pem"))
            }
            _ => Vec::new(),
        };
        drop((origin_identity, incoming_identity));
        (
            ProviderIngressFixture {
                case,
                proxy,
                origin,
                client_certificate,
                _directory: directory,
                _marker_directory: marker_directory,
                product,
                origin_task,
            },
            seen,
            marker,
        )
    }

    #[cfg(unix)]
    async fn wait_for_provider_call(marker: &std::path::Path, suffix: &str) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let calls = fs::read_to_string(marker).unwrap_or_default();
                if calls.lines().any(|line| line.ends_with(suffix)) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("provider did not receive {suffix}"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn provider_effects_and_release_corpus_covers_all_five_ingress_modes() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        for case in [
            ProviderIngressCase::ExplicitHttp,
            ProviderIngressCase::ExplicitHttps,
            ProviderIngressCase::TransparentHttp,
            ProviderIngressCase::ConnectMitmInner,
            ProviderIngressCase::TransparentHttps,
        ] {
            let (fixture, mut seen, marker) = provider_ingress_fixture(case).await;
            let pool = fixture.product.wire_body_pool();

            let response = fixture.request("/pass", "pass-body").await;
            assert_eq!(response.status(), StatusCode::OK, "{case:?} pass");
            let (path, headers, body) = seen.recv().await.unwrap();
            assert_eq!(path, "/pass", "{case:?}");
            assert!(
                !headers.contains_key(http::header::AUTHORIZATION),
                "{case:?}"
            );
            assert_eq!(body, "pass-body", "{case:?}");
            assert_eq!(pool.global_charge(), 0, "{case:?} pass leaked body charge");

            let response = fixture.request("/replace", "original-body").await;
            assert_eq!(response.status(), StatusCode::OK, "{case:?} replacement");
            let (path, headers, body) = seen.recv().await.unwrap();
            assert_eq!(path, "/replace", "{case:?}");
            assert_eq!(
                headers.get(http::header::AUTHORIZATION).unwrap(),
                "Bearer typed-secret",
                "{case:?}"
            );
            assert_eq!(headers.get(CONTENT_TYPE).unwrap(), "text/plain", "{case:?}");
            assert_eq!(
                headers.get(CONTENT_LENGTH).unwrap().to_str().unwrap(),
                b"replacement-body".len().to_string(),
                "{case:?}"
            );
            assert!(!headers.contains_key(CONTENT_ENCODING), "{case:?}");
            assert_eq!(body, "replacement-body", "{case:?}");
            assert_eq!(
                pool.global_charge(),
                0,
                "{case:?} replacement leaked body charge"
            );

            for (path, status) in [
                ("/deny", StatusCode::FORBIDDEN),
                ("/error", StatusCode::INTERNAL_SERVER_ERROR),
                ("/invalid-encoding", StatusCode::INTERNAL_SERVER_ERROR),
            ] {
                let response = fixture.request(path, "terminal-body").await;
                assert_eq!(response.status(), status, "{case:?} {path}");
                let expected_body = if status == StatusCode::FORBIDDEN {
                    "request denied\n"
                } else {
                    "request failed\n"
                };
                assert_eq!(
                    to_bytes(response.into_body()).await.unwrap(),
                    expected_body,
                    "{case:?} {path} response bytes"
                );
                assert!(seen.try_recv().is_err(), "{case:?} {path} reached origin");
                assert_eq!(
                    pool.global_charge(),
                    0,
                    "{case:?} {path} leaked body charge"
                );
            }

            let response = fixture.request_upgrade().await;
            assert!(
                response.starts_with(b"HTTP/1.1 101 "),
                "unexpected {case:?} upgrade response: {}",
                String::from_utf8_lossy(&response)
            );
            let (path, headers, body) = seen.recv().await.unwrap();
            assert_eq!(path, "/upgrade", "{case:?}");
            assert_eq!(
                headers.get(http::header::AUTHORIZATION).unwrap(),
                "Bearer typed-secret",
                "{case:?}"
            );
            assert!(body.is_empty(), "{case:?}");

            let response = fixture.request("/timeout", "timeout-body").await;
            assert_eq!(
                response.status(),
                StatusCode::GATEWAY_TIMEOUT,
                "{case:?} timeout"
            );
            assert!(seen.try_recv().is_err(), "{case:?} timeout reached origin");
            assert_eq!(
                pool.global_charge(),
                0,
                "{case:?} timeout leaked body charge"
            );
            let calls = fs::read_to_string(&marker).unwrap();
            let connect_mitm = matches!(case, ProviderIngressCase::ConnectMitmInner);
            assert_eq!(
                calls.lines().count(),
                if connect_mitm { 14 } else { 7 },
                "{case:?} provider call count"
            );
            for suffix in [
                "/pass",
                "/replace",
                "/deny",
                "/error",
                "/invalid-encoding",
                "/upgrade",
                "/timeout",
            ] {
                assert_eq!(
                    calls.lines().filter(|line| line.ends_with(suffix)).count(),
                    1,
                    "{case:?} {suffix} call count"
                );
            }
            if connect_mitm {
                let outer_url = format!("https://{}/", fixture.origin);
                assert_eq!(
                    calls.lines().filter(|line| *line == outer_url).count(),
                    7,
                    "{case:?} outer CONNECT provider call count"
                );
            }

            tokio::time::timeout(Duration::from_secs(2), fixture.product.shutdown())
                .await
                .unwrap_or_else(|_| panic!("{case:?} timeout shutdown did not complete"));
            fixture.origin_task.abort();
            let _ = fixture.origin_task.await;
            assert!(
                StdTcpListener::bind(fixture.proxy).is_ok(),
                "{case:?} did not release its listener"
            );

            let (cancel_fixture, _cancel_seen, cancel_marker) =
                provider_ingress_fixture(case).await;
            let cancel_pool = cancel_fixture.product.wire_body_pool();
            let cancelled = cancel_fixture.begin_cancelled_request().await;
            wait_for_provider_call(&cancel_marker, "/cancel").await;
            let cancel_calls = fs::read_to_string(&cancel_marker).unwrap();
            assert_eq!(
                cancel_calls.lines().count(),
                if matches!(case, ProviderIngressCase::ConnectMitmInner) {
                    2
                } else {
                    1
                },
                "{case:?} cancellation provider call count"
            );
            if matches!(case, ProviderIngressCase::ConnectMitmInner) {
                let outer_url = format!("https://{}/", cancel_fixture.origin);
                assert_eq!(
                    cancel_calls
                        .lines()
                        .filter(|line| *line == outer_url)
                        .count(),
                    1,
                    "{case:?} cancellation outer CONNECT provider call count"
                );
            }
            drop(cancelled);
            tokio::time::timeout(Duration::from_secs(2), cancel_fixture.product.shutdown())
                .await
                .unwrap_or_else(|_| panic!("{case:?} shutdown did not cancel provider work"));
            assert_eq!(
                cancel_pool.global_charge(),
                0,
                "{case:?} cancellation leaked body charge"
            );
            cancel_fixture.origin_task.abort();
            let _ = cancel_fixture.origin_task.await;
            assert!(
                StdTcpListener::bind(cancel_fixture.proxy).is_ok(),
                "{case:?} cancellation did not release its listener"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn http2_process_provider_equivalence_covers_all_five_ingress_modes() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        for case in [
            ProviderIngressCase::ExplicitHttp,
            ProviderIngressCase::ExplicitHttps,
            ProviderIngressCase::TransparentHttp,
            ProviderIngressCase::ConnectMitmInner,
            ProviderIngressCase::TransparentHttps,
        ] {
            let (fixture, mut seen, marker) =
                provider_ingress_fixture_for(case, ProviderIngressProtocol::Http2).await;
            let pool = fixture.product.wire_body_pool();
            let stream = fixture
                .open_stream_for(ProviderIngressProtocol::Http2)
                .await;
            let mut builder = conn::Builder::new();
            builder.http2_only(true);
            let (mut sender, connection) = builder.handshake(stream).await.unwrap();
            let driver = tokio::spawn(connection);

            let replacement = sender
                .send_request(
                    Request::builder()
                        .method(Method::POST)
                        .version(Version::HTTP_2)
                        .uri(fixture.request_target_for("/replace", ProviderIngressProtocol::Http2))
                        .header(http::header::HOST, fixture.request_host())
                        .header(CONTENT_TYPE, "text/plain")
                        .body(Body::from("original-body"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(replacement.version(), Version::HTTP_2, "{case:?}");
            assert_eq!(replacement.status(), StatusCode::OK, "{case:?}");
            assert_eq!(
                to_bytes(replacement.into_body()).await.unwrap(),
                "origin accepted",
                "{case:?} replacement response bytes"
            );
            let (path, headers, body) = seen.recv().await.unwrap();
            assert_eq!(path, "/replace", "{case:?}");
            assert_eq!(
                headers.get(http::header::AUTHORIZATION).unwrap(),
                "Bearer typed-secret",
                "{case:?}"
            );
            assert_eq!(headers.get(CONTENT_TYPE).unwrap(), "text/plain", "{case:?}");
            if let Some(length) = headers.get(CONTENT_LENGTH) {
                assert_eq!(
                    length.to_str().unwrap(),
                    b"replacement-body".len().to_string(),
                    "{case:?}"
                );
            }
            assert!(!headers.contains_key(CONTENT_ENCODING), "{case:?}");
            assert_eq!(body, "replacement-body", "{case:?}");
            assert_eq!(
                pool.global_charge(),
                0,
                "{case:?} replacement leaked body charge"
            );

            let denied = sender
                .send_request(
                    Request::builder()
                        .method(Method::POST)
                        .version(Version::HTTP_2)
                        .uri(fixture.request_target_for("/deny", ProviderIngressProtocol::Http2))
                        .header(http::header::HOST, fixture.request_host())
                        .header(CONTENT_TYPE, "text/plain")
                        .body(Body::from("denied-body"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(denied.version(), Version::HTTP_2, "{case:?}");
            assert_eq!(denied.status(), StatusCode::FORBIDDEN, "{case:?}");
            assert_eq!(
                to_bytes(denied.into_body()).await.unwrap(),
                "request denied\n",
                "{case:?} denial response bytes"
            );
            assert!(seen.try_recv().is_err(), "{case:?} denial reached origin");
            assert_eq!(
                pool.global_charge(),
                0,
                "{case:?} denial leaked body charge"
            );

            let calls = fs::read_to_string(&marker).unwrap();
            let connect_mitm = matches!(case, ProviderIngressCase::ConnectMitmInner);
            assert_eq!(
                calls.lines().count(),
                if connect_mitm { 3 } else { 2 },
                "{case:?} provider call count"
            );
            for suffix in ["/replace", "/deny"] {
                assert_eq!(
                    calls.lines().filter(|line| line.ends_with(suffix)).count(),
                    1,
                    "{case:?} {suffix} call count"
                );
            }
            if connect_mitm {
                let outer_url = format!("https://{}/", fixture.origin);
                assert_eq!(
                    calls.lines().filter(|line| *line == outer_url).count(),
                    1,
                    "{case:?} HTTP/2 outer CONNECT provider call count"
                );
            }

            drop(sender);
            tokio::time::timeout(Duration::from_secs(2), fixture.product.shutdown())
                .await
                .unwrap_or_else(|_| panic!("{case:?} HTTP/2 shutdown did not complete"));
            driver.await.unwrap().unwrap();
            assert_eq!(
                pool.global_charge(),
                0,
                "{case:?} shutdown leaked body charge"
            );
            fixture.origin_task.abort();
            let _ = fixture.origin_task.await;
            assert!(
                StdTcpListener::bind(fixture.proxy).is_ok(),
                "{case:?} did not release its HTTP/2 listener"
            );
        }
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
    async fn raw_h1_framing_is_validated_before_resolution_and_valid_bodies_pass() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            loop {
                let (stream, _) = origin_listener.accept().await.unwrap();
                tokio::spawn(async move {
                    Http::new()
                        .http1_only(true)
                        .serve_connection(
                            stream,
                            service_fn(|request| async move {
                                let body = to_bytes(request.into_body()).await.unwrap();
                                Ok::<_, Infallible>(Response::new(Body::from(format!(
                                    "body-bytes={}",
                                    body.len()
                                ))))
                            }),
                        )
                        .await
                        .unwrap();
                });
            }
        });
        let resolver = Arc::new(DelayedResolver {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
            endpoint: origin,
        });
        let guard = test_destination_guard(proxy, resolver.clone());
        let policy = r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "allow"
"#;
        let (_directory, product) = listener_product_with_destination_guard(
            base_config(proxy, "explicit_http", policy),
            listeners,
            guard,
        )
        .await;
        let authority = format!("wire.test:{}", origin.port());
        let target = format!("http://{authority}/body");
        let malformed = [
            format!(
                "POST {target} HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"
            ),
            format!(
                "POST {target} HTTP/1.1\r\nHost: {authority}\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n0\r\n\r\n"
            ),
            format!(
                "POST {target} HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
            format!(
                "POST {target} HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 0\r\nContent-Length: 1\r\nConnection: close\r\n\r\n"
            ),
        ];
        for wire in malformed {
            let response = send_raw_http(proxy, wire.as_bytes()).await;
            assert!(
                response.is_empty(),
                "invalid framing reached Hyper: {}",
                String::from_utf8_lossy(&response)
            );
            assert_eq!(
                resolver.calls.load(Ordering::Acquire),
                0,
                "invalid framing reached destination resolution"
            );
        }

        let content_length_zero = format!(
            "POST {target} HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let response = send_raw_http(proxy, content_length_zero.as_bytes()).await;
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "unexpected CL0 response (resolver calls={}): {}",
            resolver.calls.load(Ordering::Acquire),
            String::from_utf8_lossy(&response),
        );
        assert!(response.ends_with(b"body-bytes=0"));

        let chunked = format!(
            "POST {target} HTTP/1.1\r\nHost: {authority}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4;safe=yes\r\ntest\r\n0\r\n\r\n"
        );
        let response = send_raw_http(proxy, chunked.as_bytes()).await;
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "unexpected chunked response: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(response.ends_with(b"body-bytes=4"));

        let mut large_trailers = format!(
            "POST {target} HTTP/1.1\r\nHost: {authority}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nx\r\n0\r\n"
        )
        .into_bytes();
        for index in 0..8 {
            large_trailers.extend_from_slice(format!("X-Trailer-{index}: ").as_bytes());
            large_trailers.extend(std::iter::repeat_n(b't', 12 * 1024));
            large_trailers.extend_from_slice(b"\r\n");
        }
        large_trailers.extend_from_slice(b"\r\n");
        assert!(large_trailers.len() > crate::http1::store::PARSER_STORE_BYTES);
        let response = send_raw_http(proxy, &large_trailers).await;
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "unexpected large-trailer response: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(response.ends_with(b"body-bytes=1"));
        assert_eq!(resolver.calls.load(Ordering::Acquire), 3);

        product.shutdown().await;
        origin_task.abort();
        let _ = origin_task.await;
    }

    #[tokio::test]
    async fn close_disposition_interrupts_missing_body_and_blocks_pipelined_resolution() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let unused_origin = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let origin = unused_origin.local_addr().unwrap();
        let resolver = Arc::new(DelayedResolver {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
            endpoint: origin,
        });
        let guard = test_destination_guard(proxy, resolver.clone());
        let authority = format!("pipeline.test:{}", origin.port());
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "allow-second-only"
decision = "allow"
urls = ["http://{authority}/two"]
methods = ["GET"]
"#
        );
        let (_directory, product) = listener_product_with_destination_guard(
            base_config(proxy, "explicit_http", &policy),
            listeners,
            guard,
        )
        .await;

        let missing_body = format!(
            "POST http://{authority}/one HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 32\r\n\r\n"
        );
        let response = send_raw_http(proxy, missing_body.as_bytes()).await;
        assert!(
            response.starts_with(b"HTTP/1.1 403"),
            "declared body prevented close response: {}",
            String::from_utf8_lossy(&response)
        );
        assert_eq!(resolver.calls.load(Ordering::Acquire), 0);

        let pipelined = format!(
            "POST http://{authority}/one HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 4\r\n\r\nbodyGET http://{authority}/two HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        );
        let response = send_raw_http(proxy, pipelined.as_bytes()).await;
        assert!(
            response.starts_with(b"HTTP/1.1 403"),
            "unexpected first pipeline response: {}",
            String::from_utf8_lossy(&response)
        );
        assert_eq!(
            resolver.calls.load(Ordering::Acquire),
            0,
            "the second pipelined request reached destination resolution"
        );

        product.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn provider_denials_close_before_a_pipelined_request_can_execute() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let unused_origin = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let origin = unused_origin.local_addr().unwrap();
        let resolver = Arc::new(DelayedResolver {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
            endpoint: origin,
        });
        let guard = test_destination_guard(proxy, resolver.clone());
        let authority = format!("provider-pipeline.test:{}", origin.port());
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[authorization.providers.pipeline]
kind = "process"
command = "/usr/bin/python3"
args = ["-u", "-c", '''
import json, sys
for line in sys.stdin:
    request = json.loads(line)
    if request["url"].endswith("/deny"):
        decision = "deny"
    elif request["url"].endswith("/pass"):
        decision = "pass"
    else:
        decision = "invalid"
    print(json.dumps({{"id": request["id"], "type": "response", "decision": decision}}, separators=(",", ":")), flush=True)
''']
timeout = "2s"
retire_timeout = "6s"
on_failure = "deny"
inherit_environment = false
environment = {{ PATH = "/usr/bin:/bin" }}
include_request_body = false
max_request_body_bytes = 1024
max_decoded_request_body_bytes = 1024
max_stdout_line_bytes = 4096

[policy]
default = "deny"

[[policy.rules]]
id = "provider-first"
decision = "delegate"
urls = ["http://{authority}/deny", "http://{authority}/failure", "http://{authority}/pass"]
methods = ["POST"]
authorization_provider = "pipeline"

[[policy.rules]]
id = "deny-after-pass"
decision = "deny"
urls = ["http://{authority}/pass"]
methods = ["POST"]

[[policy.rules]]
id = "queued-second"
decision = "allow"
urls = ["http://{authority}/two"]
methods = ["GET"]
"#,
        );
        let (_directory, product) = listener_product_with_destination_guard(
            base_config(proxy, "explicit_http", &policy),
            listeners,
            guard,
        )
        .await;

        for path in ["deny", "failure", "pass"] {
            let pipelined = format!(
                "POST http://{authority}/{path} HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 4\r\n\r\nbodyGET http://{authority}/two HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
            );
            let response = send_raw_http(proxy, pipelined.as_bytes()).await;
            assert!(
                response.starts_with(b"HTTP/1.1 403"),
                "unexpected {path} response: {}",
                String::from_utf8_lossy(&response)
            );
            assert_eq!(
                response
                    .windows(b"HTTP/1.1 ".len())
                    .filter(|window| *window == b"HTTP/1.1 ")
                    .count(),
                1,
                "the queued request produced a second response after {path}"
            );
        }
        assert_eq!(
            resolver.calls.load(Ordering::Acquire),
            3,
            "only each provider-owned first request may resolve"
        );

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
	      *replacement-provider-limit*) printf '{"id":"%s","type":"response","decision":"allow","values":{"token":"secret-marker"},"requestBody":{"encoding":"base64","contentType":"text/plain","data":"eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4"}}\n' "$id" ;;
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

[redaction.profiles.strict_wire]
replacement = "[MASKED]"
max_body_bytes = 4
max_decoded_body_bytes = 4
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
id = "replacement-provider-limit"
decision = "delegate"
urls = ["http://{origin}/replacement-provider-limit"]
methods = ["POST"]
authorization_provider = "replacing"
redaction_profile = "wire"

[[policy.rules]]
id = "replacement-redaction-limit"
decision = "delegate"
urls = ["http://{origin}/replacement-redaction-limit"]
methods = ["POST"]
authorization_provider = "replacing"
redaction_profile = "strict_wire"

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

        for (path, expected_status) in [
            ("replacement-provider-limit", StatusCode::PAYLOAD_TOO_LARGE),
            ("replacement-redaction-limit", StatusCode::PAYLOAD_TOO_LARGE),
        ] {
            let response = send_request(
                proxy,
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("http://{origin}/{path}"))
                    .header("x-visible", "retained")
                    .body(Body::from("x"))
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), expected_status, "{path}");
        }

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
        for (path, expected_size) in [
            ("/replacement-provider-limit", 147),
            ("/replacement-redaction-limit", b"replacement secret".len()),
        ] {
            let failed = records
                .iter()
                .find(|record| record.kind == CaptureKind::Request && record.url.ends_with(path))
                .unwrap_or_else(|| panic!("missing replacement failure capture for {path}"));
            assert_eq!(failed.decision, CaptureDecision::Deny, "{path}");
            assert_eq!(failed.provider_replacement_omitted, Some(true), "{path}");
            assert_eq!(
                failed.provider_replacement_size,
                Some(expected_size),
                "{path}"
            );
            assert!(failed.body.is_none(), "{path}");
            let headers = failed.headers.as_ref().unwrap();
            assert_eq!(headers["x-visible"], "retained", "{path}");
            assert!(!headers.contains_key("authorization"), "{path}");
        }
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
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (captured_tx, mut captured_rx) = mpsc::unbounded_channel();
        let origin_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = origin_listener.accept().await.unwrap();
                let captured_tx = captured_tx.clone();
                Http::new()
                    .http1_only(true)
                    .serve_connection(
                        stream,
                        service_fn(move |request: Request<Body>| {
                            let captured_tx = captured_tx.clone();
                            async move {
                                let (parts, body) = request.into_parts();
                                let body = to_bytes(body).await.unwrap();
                                captured_tx.send((parts.headers, body)).unwrap();
                                Ok::<_, Infallible>(Response::new(Body::from("accepted")))
                            }
                        }),
                    )
                    .await
                    .unwrap();
            }
        });
        let plain = b"opaque capture-redaction-sentinel payload";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plain).unwrap();
        let encoded = encoder.finish().unwrap();
        let mut upstream = Vec::new();
        let mut capture_records = Vec::new();
        for capture_enabled in [false, true] {
            let ([proxy], listeners) = prebound_listeners::<1>();
            let capture = if capture_enabled {
                capture_config()
            } else {
                ""
            };
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

{capture}"#,
            );
            let (directory, product) =
                product(base_config(proxy, "explicit_http", &policy), listeners).await;
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
            upstream.push(captured_rx.recv().await.unwrap());
            product.shutdown().await;
            if capture_enabled {
                capture_records = read_capture_records(directory.path());
            } else {
                assert!(!directory.path().join("captures").exists());
            }
        }
        origin_task.await.unwrap();

        for (headers, _) in &mut upstream {
            headers.remove("x-test-loop");
        }
        assert_eq!(upstream[0], upstream[1]);
        let (origin_headers, origin_body) = &upstream[1];
        assert_eq!(origin_body, &encoded);
        assert_eq!(origin_headers[CONTENT_ENCODING], "gzip");
        assert_eq!(
            origin_headers[CONTENT_LENGTH],
            origin_body.len().to_string()
        );
        assert!(!origin_headers.contains_key(http::header::TRANSFER_ENCODING));

        let request = capture_records
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
    async fn cleartext_h2_oversized_header_block_is_stream_local() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let policy = r#"[listeners.explicit_http.connect]
http2 = "deny"

[policy]
default = "deny"
"#;
        let config = base_config(proxy, "explicit_http", policy).replacen(
            "http_versions = [\"http1\"]",
            "http_versions = [\"http2\"]\nmax_concurrent_streams = 2",
            1,
        );
        let (_directory, product) = product(config, listeners).await;
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let mut builder = conn::Builder::new();
        builder.http2_only(true);
        let (mut sender, connection) = builder.handshake(stream).await.unwrap();
        let driver = tokio::spawn(connection);

        let oversized = sender
            .send_request(
                Request::builder()
                    .uri(format!("http://{proxy}/oversized"))
                    .header(
                        "x-oversized",
                        HeaderValue::from_bytes(&vec![
                            b'x';
                            crate::http1::store::PARSER_STORE_BYTES
                        ])
                        .unwrap(),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            oversized.status(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
        assert!(to_bytes(oversized.into_body()).await.unwrap().is_empty());

        std::future::poll_fn(|context| sender.poll_ready(context))
            .await
            .unwrap();
        let bounded = sender
            .send_request(
                Request::builder()
                    .uri(format!("http://{proxy}/bounded"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bounded.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            to_bytes(bounded.into_body()).await.unwrap(),
            "destination denied\n"
        );

        drop(sender);
        product.shutdown().await;
        driver.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn transparent_http_h2_prior_knowledge_forwards_canonical_origin_request() {
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
                            let host = request
                                .headers()
                                .get(http::header::HOST)
                                .unwrap()
                                .to_str()
                                .unwrap()
                                .to_owned();
                            captured_tx
                                .lock()
                                .unwrap()
                                .take()
                                .unwrap()
                                .send((request.version(), request.uri().to_string(), host))
                                .ok();
                            Ok::<_, Infallible>(Response::new(Body::from(
                                "transparent h2 accepted",
                            )))
                        }
                    }),
                )
                .await
                .unwrap();
        });
        let policy = format!(
            r#"[policy]
default = "deny"

[[policy.rules]]
id = "transparent-h2"
decision = "allow"
urls = ["http://{origin}/transparent-h2?mode=one"]
methods = ["GET"]
"#
        );
        let config = base_config(proxy, "transparent_http", &policy).replacen(
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

        let response = sender
            .send_request(
                Request::builder()
                    .uri(format!("http://{origin}/transparent-h2?mode=one"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.version(), Version::HTTP_2);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body()).await.unwrap(),
            "transparent h2 accepted"
        );
        let (version, uri, host) = captured_rx.await.unwrap();
        assert_eq!(version, Version::HTTP_11);
        assert_eq!(uri, "/transparent-h2?mode=one");
        assert_eq!(host, origin.to_string());

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
    async fn connect_body_framing_closes_before_pipelined_request() {
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
            .expect("invalid CONNECT did not close the connection")
            .unwrap();
        assert!(response.is_empty(), "invalid CONNECT reached Hyper");

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
    async fn connect_mitm_outer_tunnel_omits_global_origin_credentials() {
        const VARIABLE: &str = "ACL_PROXY_OUTER_CONNECT_IDENTITY";
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        std::env::remove_var(VARIABLE);
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
        let (identity_tx, identity_rx) = oneshot::channel();
        let identity_tx = Arc::new(StdMutex::new(Some(identity_tx)));
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            let tls = origin_acceptor.accept(stream).await.unwrap();
            Http::new()
                .http1_only(true)
                .serve_connection(
                    tls,
                    service_fn(move |request| {
                        let identity_tx = identity_tx.clone();
                        let identity = request
                            .headers()
                            .get("x-aw-identity-token")
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_owned);
                        identity_tx
                            .lock()
                            .unwrap()
                            .take()
                            .unwrap()
                            .send(identity)
                            .ok();
                        async { Ok::<_, Infallible>(Response::new(Body::from("credentialized"))) }
                    }),
                )
                .await
                .unwrap();
        });
        let target = origin.to_string();
        let credential_config = format!(
            r#"
[[egress.credential_actions]]
kind = "custom_header"
header = "x-aw-identity-token"
credential = "outer_identity"

[credentials]
allowed_custom_headers = ["x-aw-identity-token"]

[credentials.sources.outer_identity]
source = "environment"
variable = "{VARIABLE}"
"#
        );
        let policy = format!("{}{}", connect_mitm_policy(&target), credential_config);
        let config = base_config(proxy, "explicit_http", &policy).replacen(
            "trust = \"system\"",
            "trust = \"insecure\"",
            1,
        );
        let (directory, product) = product(config, listeners).await;

        let stream = open_connect(proxy, &target).await;
        std::env::set_var(VARIABLE, "inner-identity");
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
                    .uri("/credentialized")
                    .header(http::header::HOST, &target)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body()).await.unwrap(),
            "credentialized"
        );
        assert_eq!(
            identity_rx.await.unwrap().as_deref(),
            Some("inner-identity")
        );
        drop(sender);
        driver.await.unwrap().unwrap();
        origin_task.await.unwrap();

        product.shutdown().await;
        assert!(StdTcpListener::bind(proxy).is_ok());
        std::env::remove_var(VARIABLE);
    }

    #[tokio::test]
    async fn connect_mitm_inner_h2_alpn_forwards_canonical_origin_request() {
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
        let (captured_tx, captured_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            let tls = origin_acceptor.accept(stream).await.unwrap();
            let captured_tx = Arc::new(StdMutex::new(Some(captured_tx)));
            Http::new()
                .http1_only(true)
                .serve_connection(
                    tls,
                    service_fn(move |request: Request<Body>| {
                        let captured_tx = captured_tx.clone();
                        let host = request
                            .headers()
                            .get(http::header::HOST)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_owned();
                        let captured = (request.version(), request.uri().to_string(), host);
                        captured_tx
                            .lock()
                            .unwrap()
                            .take()
                            .unwrap()
                            .send(captured)
                            .ok();
                        async {
                            Ok::<_, Infallible>(Response::new(Body::from(
                                "connect inner h2 accepted",
                            )))
                        }
                    }),
                )
                .await
                .unwrap();
        });
        let target = origin.to_string();
        let policy = connect_mitm_policy(&target).replacen(
            "http1 = \"mitm\"",
            "http1 = \"mitm\"\nhttp2 = \"deny\"",
            1,
        );
        let config = base_config(proxy, "explicit_http", &policy)
            .replacen(
                "http_versions = [\"http1\"]",
                "http_versions = [\"http1\", \"http2\"]",
                1,
            )
            .replacen("trust = \"system\"", "trust = \"insecure\"", 1);
        let (directory, product) = product(config, listeners).await;

        let stream = open_connect(proxy, &target).await;
        let certificate = read_first_pem_certificate(&directory.path().join("mitm/ca-cert.pem"));
        let connector = test_tls_connector(certificate, vec![b"h2".to_vec()]);
        let tls = connector
            .connect(ServerName::try_from("127.0.0.1").unwrap(), stream)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let mut builder = conn::Builder::new();
        builder.http2_only(true);
        let (mut sender, connection) = builder.handshake(tls).await.unwrap();
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::builder()
                    .uri(format!("https://{target}/inner-h2?mode=one"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.version(), Version::HTTP_2);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body()).await.unwrap(),
            "connect inner h2 accepted"
        );
        let (version, uri, host) = captured_rx.await.unwrap();
        assert_eq!(version, Version::HTTP_11);
        assert_eq!(uri, "/inner-h2?mode=one");
        assert_eq!(host, target);

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
        assert!(
            response.starts_with(b"HTTP/1.1 101 "),
            "unexpected WebSocket handshake response: {}",
            String::from_utf8_lossy(&response)
        );
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
    async fn large_connection_and_upgrade_lines_reach_policy_with_exact_classification() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let policy = r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"
"#;
        let (_directory, product) =
            product(base_config(proxy, "explicit_http", policy), listeners).await;

        let request = |connection_token: &str| {
            let mut wire = b"GET http://large-relevant.test/socket HTTP/1.1\r\nHost: large-relevant.test\r\nConnection: "
                .to_vec();
            wire.extend(std::iter::repeat_n(
                b' ',
                crate::http1::store::PARSER_STORE_BYTES + 17,
            ));
            wire.extend_from_slice(connection_token.as_bytes());
            wire.extend_from_slice(b"\r\nUpgrade: test-");
            wire.extend(std::iter::repeat_n(
                b'x',
                crate::http1::store::PARSER_STORE_BYTES + 19,
            ));
            wire.extend_from_slice(b"\r\n\r\n");
            wire
        };

        let response = send_raw_http(proxy, &request("UpGrAdE \t, close")).await;
        assert!(
            response.starts_with(b"HTTP/1.1 403") && response.ends_with(b"request denied\n"),
            "large upgrade request did not reach policy: {}",
            String::from_utf8_lossy(&response)
        );

        let response = send_raw_http(proxy, &request("upgrade-x, close")).await;
        assert!(
            response.starts_with(b"HTTP/1.1 400") && response.ends_with(b"invalid request\n"),
            "near-match Connection token was misclassified: {}",
            String::from_utf8_lossy(&response)
        );

        product.shutdown().await;
    }

    #[tokio::test]
    async fn obs_text_around_upgrade_fails_closed_before_downstream_switching() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let Ok(Ok((mut stream, _))) =
                tokio::time::timeout(Duration::from_millis(250), origin_listener.accept()).await
            else {
                return false;
            };
            let _ = read_http_head(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n",
                )
                .await
                .unwrap();
            true
        });
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "upgrade"
decision = "allow"
methods = ["GET"]
urls = ["http://{origin}/socket"]
allow_upgrades = true
"#
        );
        let (_directory, product) =
            product(base_config(proxy, "explicit_http", &policy), listeners).await;

        let mut wire =
            format!("GET http://{origin}/socket HTTP/1.1\r\nHost: {origin}\r\nConnection: ")
                .into_bytes();
        wire.extend_from_slice(b"\xc2\xa0Upgrade\xc2\xa0");
        wire.extend_from_slice(b"\r\nUpgrade: test-echo\r\n\r\n");
        let response = send_raw_http(proxy, &wire).await;
        assert!(
            response.starts_with(b"HTTP/1.1 400") && response.ends_with(b"invalid request\n"),
            "obs-text Connection token did not fail closed: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            !origin_task.await.unwrap(),
            "obs-text request reached a 101 origin"
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

    fn response_watchdog_config(
        proxy: SocketAddr,
        origin: SocketAddr,
        downstream_http2: bool,
    ) -> String {
        let connect_protocol = if downstream_http2 {
            "http2 = \"deny\""
        } else {
            "http1 = \"deny\""
        };
        let policy = format!(
            r#"[service.forwarding]
connect_timeout = "1s"
response_head_timeout = "1s"
body_idle_timeout = "200ms"
upgrade_idle_timeout = "1s"
max_request_wire_bytes = 65536
max_request_decoded_bytes = 65536
max_response_wire_bytes = 67108864
max_response_decoded_bytes = 67108864
chunk_bytes = 65536
preserve_request_trailers = false
max_trailer_count = 4
max_trailer_bytes = 256

[listeners.explicit_http.connect]
{connect_protocol}

[policy]
default = "deny"

[[policy.rules]]
id = "watchdog-response"
decision = "allow"
methods = ["GET"]
urls = ["http://{origin}/**"]
"#
        );
        let config = base_config(proxy, "explicit_http", &policy).replacen(
            "request_timeout = \"5s\"",
            "request_timeout = \"750ms\"",
            1,
        );
        if downstream_http2 {
            config.replacen(
                "http_versions = [\"http1\"]",
                "http_versions = [\"http2\"]\nmax_concurrent_streams = 1",
                1,
            )
        } else {
            config
        }
    }

    #[tokio::test]
    async fn h1_unread_response_body_watchdog_releases_admission_and_closes_origin() {
        const RESPONSE_BYTES: usize = 64 * 1024 * 1024;
        const CHUNK_BYTES: usize = 64 * 1024;

        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (origin_closed_tx, origin_closed_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await.unwrap();
            let request = read_http_head(&mut stream).await;
            assert!(String::from_utf8_lossy(&request).contains("/unread"));
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {RESPONSE_BYTES}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let chunk = vec![b'x'; CHUNK_BYTES];
            let mut sent = 0;
            while sent < RESPONSE_BYTES {
                match stream
                    .write(&chunk[..CHUNK_BYTES.min(RESPONSE_BYTES - sent)])
                    .await
                {
                    Ok(0) | Err(_) => break,
                    Ok(written) => sent += written,
                }
            }
            origin_closed_tx.send(sent).unwrap();
        });
        let (_directory, product) =
            product(response_watchdog_config(proxy, origin, false), listeners).await;
        let pool = product.wire_body_pool();

        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://{origin}/unread HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_head(&mut client).await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(
            pool.global_charge() > 0,
            "unread HTTP/1 response did not retain response admission"
        );

        let sent = tokio::time::timeout(Duration::from_secs(2), origin_closed_rx)
            .await
            .expect("the response watchdog did not close the HTTP/1 origin")
            .unwrap();
        assert!(
            sent < RESPONSE_BYTES,
            "the origin sent the complete body despite downstream backpressure"
        );
        let mut downstream_tail = Vec::new();
        let _downstream_close = tokio::time::timeout(
            Duration::from_secs(2),
            client.read_to_end(&mut downstream_tail),
        )
        .await
        .expect("the response watchdog did not terminate the HTTP/1 downstream");
        origin_task.await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while pool.global_charge() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the unread HTTP/1 response retained admission past its deadline");

        product.shutdown().await;
    }

    #[tokio::test]
    async fn h2_zero_window_watchdog_releases_admission_and_preserves_sibling_stream() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (origin_closed_tx, origin_closed_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (mut stalled, _) = origin_listener.accept().await.unwrap();
            let first = tokio::spawn(async move {
                let request = read_http_head(&mut stalled).await;
                assert!(String::from_utf8_lossy(&request).contains("/stalled"));
                stalled
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\nx")
                    .await
                    .unwrap();
                let mut byte = [0_u8; 1];
                let closed = tokio::time::timeout(Duration::from_secs(2), stalled.read(&mut byte))
                    .await
                    .expect("the response watchdog did not close the HTTP/2 origin");
                assert!(
                    matches!(closed, Ok(0) | Err(_)),
                    "the stalled origin received later request bytes"
                );
                origin_closed_tx.send(()).unwrap();
            });

            let (mut sibling, _) = origin_listener.accept().await.unwrap();
            let request = read_http_head(&mut sibling).await;
            assert!(String::from_utf8_lossy(&request).contains("/sibling"));
            sibling
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            first.await.unwrap();
        });
        let (_directory, product) =
            product(response_watchdog_config(proxy, origin, true), listeners).await;
        let pool = product.wire_body_pool();
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let mut builder = conn::Builder::new();
        builder.http2_only(true);
        builder.http2_initial_stream_window_size(0);
        let (mut sender, connection) = builder.handshake(stream).await.unwrap();
        let driver = tokio::spawn(connection);

        let stalled = sender
            .send_request(
                Request::builder()
                    .uri(format!("http://{origin}/stalled"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stalled.status(), StatusCode::OK);
        assert!(
            pool.global_charge() > 0,
            "zero-window HTTP/2 response did not retain response admission"
        );

        let sibling = tokio::time::timeout(
            Duration::from_secs(2),
            sender.send_request(
                Request::builder()
                    .uri(format!("http://{origin}/sibling"))
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .expect("the watchdog did not release the sole HTTP/2 stream slot")
        .expect("the stalled response failed the whole HTTP/2 connection");
        assert_eq!(sibling.status(), StatusCode::NO_CONTENT);

        drop(stalled);
        drop(sibling);
        tokio::time::timeout(Duration::from_secs(2), origin_closed_rx)
            .await
            .expect("the zero-window response watchdog did not close the origin")
            .unwrap();
        origin_task.await.unwrap();
        let released = tokio::time::timeout(Duration::from_secs(2), async {
            while pool.global_charge() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            released.is_ok(),
            "the zero-window HTTP/2 response retained {} admission bytes past its deadline",
            pool.global_charge()
        );

        drop(sender);
        product.shutdown().await;
        driver.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn h2_zero_window_watchdog_sends_stream_cancel() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await.unwrap();
            let request = read_http_head(&mut stream).await;
            assert!(String::from_utf8_lossy(&request).contains("/reset"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\nx")
                .await
                .unwrap();
            let mut byte = [0_u8; 1];
            let closed = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
                .await
                .expect("the response watchdog did not close the reset origin");
            assert!(matches!(closed, Ok(0) | Err(_)));
        });
        let (_directory, product) =
            product(response_watchdog_config(proxy, origin, true), listeners).await;
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let mut builder = h2::client::Builder::new();
        builder.initial_window_size(0);
        let (mut sender, connection) = builder.handshake::<_, Bytes>(stream).await.unwrap();
        let driver = tokio::spawn(connection);

        let (response, _request_body) = sender
            .send_request(
                Request::builder()
                    .uri(format!("http://{origin}/reset"))
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), response)
            .await
            .expect("the proxy did not send the HTTP/2 response head")
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let mut body = response.into_body();
        let reset = tokio::time::timeout(Duration::from_secs(2), body.data())
            .await
            .expect("the response watchdog did not terminate the HTTP/2 stream")
            .expect("the reset response body ended without RST_STREAM")
            .expect_err("the zero-window response unexpectedly produced data");
        assert!(reset.is_reset());
        assert_eq!(reset.reason(), Some(h2::Reason::CANCEL));

        origin_task.await.unwrap();
        drop(sender);
        product.shutdown().await;
        driver.await.unwrap().unwrap();
    }

    fn bounded_response_wire_config(
        proxy: SocketAddr,
        origin: SocketAddr,
        downstream_http2: bool,
    ) -> String {
        let connect_protocol = if downstream_http2 {
            "http2 = \"deny\""
        } else {
            "http1 = \"deny\""
        };
        let policy = format!(
            r#"[service.forwarding]
connect_timeout = "1s"
response_head_timeout = "1s"
body_idle_timeout = "1s"
upgrade_idle_timeout = "1s"
max_request_wire_bytes = 64
max_request_decoded_bytes = 64
max_response_wire_bytes = 5
max_response_decoded_bytes = 8
chunk_bytes = 2
preserve_request_trailers = true
max_trailer_count = 4
max_trailer_bytes = 32

[listeners.explicit_http.connect]
{connect_protocol}

[policy]
default = "deny"

[[policy.rules]]
id = "bounded-response"
decision = "allow"
methods = ["GET"]
urls = ["http://{origin}/**"]
"#
        );
        let config = base_config(proxy, "explicit_http", &policy);
        if downstream_http2 {
            config.replacen(
                "http_versions = [\"http1\"]",
                "http_versions = [\"http2\"]",
                1,
            )
        } else {
            config
        }
    }

    async fn serve_bounded_response_origin(listener: tokio::net::TcpListener, requests: usize) {
        for _ in 0..requests {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_head(&mut stream).await;
            let response = if request
                .windows(b"/oversized".len())
                .any(|window| window == b"/oversized")
            {
                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nabcdef"
                    .as_slice()
            } else {
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".as_slice()
            };
            stream.write_all(response).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn h1_response_wire_limit_closes_before_committing_a_partial_response() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(serve_bounded_response_origin(origin_listener, 1));
        let (_directory, product) = product(
            bounded_response_wire_config(proxy, origin, false),
            listeners,
        )
        .await;

        let response = send_raw_http(
            proxy,
            format!(
                "GET http://{origin}/oversized HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await;
        assert!(
            response.is_empty(),
            "over-limit response committed partial HTTP/1 bytes: {response:?}"
        );

        origin_task.await.unwrap();
        product.shutdown().await;
    }

    #[tokio::test]
    async fn h2_response_wire_limit_resets_only_the_failed_stream() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let origin_task = tokio::spawn(serve_bounded_response_origin(origin_listener, 2));
        let (_directory, product) =
            product(bounded_response_wire_config(proxy, origin, true), listeners).await;
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let mut builder = conn::Builder::new();
        builder.http2_only(true);
        let (mut sender, connection) = builder.handshake(stream).await.unwrap();
        let driver = tokio::spawn(connection);

        let oversized = sender
            .send_request(
                Request::builder()
                    .uri(format!("http://{origin}/oversized"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert!(
            oversized.is_err(),
            "over-limit HTTP/2 response committed a response head"
        );

        let sibling = sender
            .send_request(
                Request::builder()
                    .uri(format!("http://{origin}/sibling"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sibling.status(), StatusCode::OK);
        assert_eq!(to_bytes(sibling.into_body()).await.unwrap(), "ok");

        drop(sender);
        product.shutdown().await;
        driver.await.unwrap().unwrap();
        origin_task.await.unwrap();
    }

    #[tokio::test]
    async fn ordinary_response_admission_saturates_before_origin_connect_and_releases() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (first_head_tx, first_head_rx) = oneshot::channel();
        let (check_tx, check_rx) = oneshot::channel();
        let (checked_tx, checked_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (mut first, _) = origin_listener.accept().await.unwrap();
            let request = read_http_head(&mut first).await;
            assert!(String::from_utf8_lossy(&request).contains("/first"));
            first
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
                .await
                .unwrap();
            first_head_tx.send(()).unwrap();

            check_rx.await.unwrap();
            let escaped =
                tokio::time::timeout(Duration::from_millis(250), origin_listener.accept()).await;
            assert!(
                escaped.is_err(),
                "response-admission saturation opened a second origin connection"
            );
            checked_tx.send(()).unwrap();

            release_rx.await.unwrap();
            first.write_all(b"a").await.unwrap();
            drop(first);

            let (mut third, _) =
                tokio::time::timeout(Duration::from_secs(2), origin_listener.accept())
                    .await
                    .expect("released response admission did not permit another origin connection")
                    .unwrap();
            let request = read_http_head(&mut third).await;
            assert!(String::from_utf8_lossy(&request).contains("/third"));
            third
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nb")
                .await
                .unwrap();
        });
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "bounded-response"
decision = "allow"
methods = ["GET"]
urls = ["http://{origin}/**"]
"#
        );
        let forwarding = r#"
[service.forwarding]
max_request_wire_bytes = 1024
max_request_decoded_bytes = 1024
max_response_wire_bytes = 1024
max_response_decoded_bytes = 1024
chunk_bytes = 1024
preserve_request_trailers = false
max_trailer_count = 4
max_trailer_bytes = 256
"#;
        let sizing_config = base_config(proxy, "explicit_http", &policy).replacen(
            "\n[listeners.explicit_http]",
            &format!("{forwarding}\n[listeners.explicit_http]"),
            1,
        );
        let sizing_root = tempdir().unwrap();
        let source_path = sizing_root.path().join("sizing.toml");
        let compiled = compile_config_text(ConfigTextInput {
            text: &sizing_config,
            source_path: &source_path,
            config_root: sizing_root.path(),
        })
        .unwrap_or_else(|error| panic!("response-admission sizing failed: {error}"));
        let resources = &compiled.reloadable_plan.resource_plan;
        let response_peak = resources.forward_response_peak_bytes;
        let exchange_peak = resources.max_reachable_http_exchange_peak_bytes;
        assert!(response_peak > 0);
        assert!(exchange_peak >= response_peak);
        let global_peak = exchange_peak.checked_mul(4).unwrap();
        let config = sizing_config.replacen(
            "shutdown_drain_timeout = \"1s\"",
            &format!(
                "shutdown_drain_timeout = \"1s\"\nmax_inflight_wire_body_bytes = {global_peak}\nmax_inflight_wire_body_bytes_per_quota_key = {exchange_peak}\nmin_wire_body_concurrency = 1"
            ),
            1,
        );
        let (_directory, product) = product(config, listeners).await;
        let pool = product.wire_body_pool();

        let mut first = tokio::net::TcpStream::connect(proxy).await.unwrap();
        first
            .write_all(
                format!(
                    "GET http://{origin}/first HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let first_response = read_http_head(&mut first).await;
        assert!(first_response.starts_with(b"HTTP/1.1 200"));
        first_head_rx.await.unwrap();
        assert!(
            pool.global_charge() >= response_peak,
            "the pending first response did not retain its admission reservation"
        );

        check_tx.send(()).unwrap();
        let second_response = send_raw_http(
            proxy,
            format!(
                "GET http://{origin}/second HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await;
        assert!(
            second_response.starts_with(b"HTTP/1.1 503"),
            "unexpected saturated response: {}",
            String::from_utf8_lossy(&second_response)
        );
        checked_rx.await.unwrap();

        release_tx.send(()).unwrap();
        let mut first_body = [0_u8; 1];
        first.read_exact(&mut first_body).await.unwrap();
        assert_eq!(&first_body, b"a");
        drop(first);
        tokio::time::timeout(Duration::from_secs(2), async {
            while pool.global_charge() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed response retained wire-body admission");

        let third_response = send_raw_http(
            proxy,
            format!(
                "GET http://{origin}/third HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await;
        assert!(third_response.starts_with(b"HTTP/1.1 200"));
        assert!(third_response.ends_with(b"b"));
        origin_task.await.unwrap();
        assert_eq!(pool.global_charge(), 0);
        product.shutdown().await;
    }

    #[tokio::test]
    async fn abandoned_uncommitted_upgrade_is_bounded_by_the_request_deadline() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await.unwrap();
            let request = read_http_head(&mut stream).await;
            let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(request.contains("\r\nconnection: upgrade\r\n"));
            assert!(request.contains("\r\nupgrade: test-echo\r\n"));
            accepted_tx.send(()).unwrap();

            let mut byte = [0_u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
                .await
                .expect("deadline-bounded upgrade kept its origin connection open")
                .unwrap();
            assert_eq!(read, 0, "abandoned upgrade wrote later origin bytes");
        });
        let policy = format!(
            r#"[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "deadline-bounded-upgrade"
decision = "allow"
methods = ["GET"]
urls = ["http://{origin}/socket"]
allow_upgrades = true
"#
        );
        let config = base_config(proxy, "explicit_http", &policy).replacen(
            "request_timeout = \"5s\"",
            "request_timeout = \"500ms\"",
            1,
        );
        let (_directory, product) = product(config, listeners).await;
        let runtime = product.upgrade_runtime();
        let pool = product.wire_body_pool();

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
        accepted_rx.await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let counts = runtime.counts();
                if counts.reserved_slots == 1
                    && counts.reserved_bytes > 0
                    && counts.uncommitted == 1
                    && counts.committed == 0
                    && counts.tracked_tasks == 1
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("upgrade did not reach the uncommitted response-head wait");
        assert!(
            pool.global_charge() > 0,
            "uncommitted upgrade did not retain response admission"
        );

        drop(client);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let counts = runtime.counts();
                if counts.reserved_slots == 0
                    && counts.reserved_bytes == 0
                    && counts.uncommitted == 0
                    && counts.committed == 0
                    && counts.tracked_tasks == 0
                    && pool.global_charge() == 0
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("deadline-bounded upgrade retained runtime or wire-body admission");
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
