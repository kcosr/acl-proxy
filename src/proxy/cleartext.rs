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
use http::header::{CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRAILER};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use hyper::body::{Bytes, HttpBody, SizeHint};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::Body;
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;

use crate::activation::assets::ProductIngressAssets;
use crate::activation::listeners::{
    PreparedProxyListener, ProxyListenerConfig, ProxyListenerKind, ProxySupervisor,
    ProxySupervisorFailure, ProxySupervisorFailureObserver, ProxySupervisorStartError,
    ProxySupervisorStarter,
};
use crate::config::compiler::{
    CompiledHttp1ConnectPolicy, CompiledHttpVersion, HttpBodyReadPlan, StaticCleartextListener,
};
use crate::http_body::{read_mandatory_request_body, HttpBodyReadError};
use crate::observation::ProductObservationRuntime;
use crate::policy::apply_header_effects;
use crate::proxy::authority::{
    reconcile_explicit_request, reconcile_transparent_http_request, AuthorityError,
};
use crate::proxy::forward::{
    forward_request, resolve_forwarding_target, ForwardBody, ForwardBodyError, ForwardError,
    ResolveForwardingError,
};
use crate::proxy::headers::{sanitize_untrusted_request, HeaderPreparationError, SanitizedRequest};
use crate::request_decision::{
    prepare_request, AllowedRequest, GuardedRequestBody as DecisionBody, RequestDecision,
    RequestDecisionError, RequestInput,
};
use crate::runtime::{BoxFuture, GenerationRetentionError, Runtime};
use crate::safety::wire_body::{GuardedBodyData, GuardedHttpBody};
use crate::safety::{InvalidLoopMarker, WireBodyQuotaKey};

/// Concrete process-runtime starter for the prebound product listener bundle.
/// HTTPS variants are deliberately left for their dedicated executors.
pub(crate) struct ProductProxySupervisorStarter {
    runtime: Arc<Runtime>,
    observation_runtime: Arc<ProductObservationRuntime>,
}

impl ProductProxySupervisorStarter {
    pub(crate) fn new(
        runtime: Arc<Runtime>,
        observation_runtime: Arc<ProductObservationRuntime>,
    ) -> Self {
        Self {
            runtime,
            observation_runtime,
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
            ProxyListenerConfig::ExplicitHttp(config) => CleartextProxySupervisor::start(
                kind,
                CleartextMode::Explicit,
                ensure_cleartext_connect_supported(kind, *config)?,
                listener.listener,
                self.runtime.clone(),
                self.observation_runtime.clone(),
                assets.clone(),
                failure_observer,
            )
            .map(|supervisor| supervisor as Arc<dyn ProxySupervisor>),
            ProxyListenerConfig::TransparentHttp(config) => CleartextProxySupervisor::start(
                kind,
                CleartextMode::Transparent,
                *config,
                listener.listener,
                self.runtime.clone(),
                self.observation_runtime.clone(),
                assets.clone(),
                failure_observer,
            )
            .map(|supervisor| supervisor as Arc<dyn ProxySupervisor>),
            ProxyListenerConfig::ExplicitHttps(_) | ProxyListenerConfig::TransparentHttps(_) => {
                Err(ProxySupervisorStartError {
                    listener: kind,
                    message: "the HTTPS supervisor is not installed".to_owned(),
                })
            }
        }
    }
}

fn ensure_cleartext_connect_supported(
    kind: ProxyListenerKind,
    config: StaticCleartextListener,
) -> Result<StaticCleartextListener, ProxySupervisorStartError> {
    if config
        .connect
        .as_ref()
        .is_some_and(|connect| connect.http1 == Some(CompiledHttp1ConnectPolicy::Mitm))
    {
        return Err(ProxySupervisorStartError {
            listener: kind,
            message: "HTTP/1 CONNECT MITM requires the cleartext CONNECT executor".to_owned(),
        });
    }
    Ok(config)
}

#[derive(Clone, Copy)]
enum CleartextMode {
    Explicit,
    Transparent,
}

#[derive(Clone, Copy)]
struct ListenerIdentity {
    kind: ProxyListenerKind,
    mode: CleartextMode,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum SupervisorStop {
    Running,
    CloseAndJoin,
    AbortAndJoin,
}

struct CleartextProxySupervisor {
    kind: ProxyListenerKind,
    stop: watch::Sender<SupervisorStop>,
    stop_gate: Arc<StdMutex<SupervisorStop>>,
    task: AsyncMutex<SupervisorTaskState>,
}

struct SupervisorTaskState {
    handle: Option<JoinHandle<Result<(), Arc<ProxySupervisorFailure>>>>,
    terminal: Option<Result<(), Arc<ProxySupervisorFailure>>>,
}

impl CleartextProxySupervisor {
    fn start(
        kind: ProxyListenerKind,
        mode: CleartextMode,
        config: StaticCleartextListener,
        listener: std::net::TcpListener,
        runtime: Arc<Runtime>,
        observation_runtime: Arc<ProductObservationRuntime>,
        assets: Arc<ProductIngressAssets>,
        failure_observer: Arc<dyn ProxySupervisorFailureObserver>,
    ) -> Result<Arc<Self>, ProxySupervisorStartError> {
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
            ListenerIdentity { kind, mode },
            config,
            listener,
            runtime,
            observation_runtime,
            assets,
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

impl ProxySupervisor for CleartextProxySupervisor {
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
    identity: ListenerIdentity,
    config: StaticCleartextListener,
    listener: TcpListener,
    runtime: Arc<Runtime>,
    observation_runtime: Arc<ProductObservationRuntime>,
    assets: Arc<ProductIngressAssets>,
    quota_classifier: LocalQuotaClassifier,
    mut stop: watch::Receiver<SupervisorStop>,
) -> Result<(), Arc<ProxySupervisorFailure>> {
    let ListenerIdentity { kind, mode } = identity;
    let connection_slots = Arc::new(Semaphore::new(config.max_connections));
    let (refresh_stop, refresh_stop_rx) = watch::channel(false);
    let mut refresh_task = tokio::spawn(refresh_local_addresses(
        kind,
        quota_classifier.clone(),
        refresh_stop_rx,
    ));
    let mut connections = JoinSet::new();
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
                    tracing::debug!(listener = %kind, %error, "cleartext connection task failed");
                }
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
                    tracing::debug!(listener = %kind, %error, "cleartext connection task failed");
                }
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
        let assets = assets.clone();
        let versions = config.http_versions.clone();
        let request_header_timeout = config.request_header_timeout;
        let max_concurrent_streams = config.max_concurrent_streams;
        let connection_stop = stop.clone();
        connections.spawn(async move {
            serve_connection(
                kind,
                mode,
                versions,
                request_header_timeout,
                max_concurrent_streams,
                stream,
                peer,
                quota_key,
                runtime,
                observation_runtime,
                assets,
                connection_stop,
                permit,
            )
            .await;
        });
    }

    drop(listener);
    refresh_stop.send_replace(true);
    if !refresh_task.is_finished() {
        let _ = refresh_task.await;
    }

    let abort = terminal_failure.is_some() || *stop.borrow() == SupervisorStop::AbortAndJoin;
    if abort {
        connections.abort_all();
    }
    while !connections.is_empty() {
        tokio::select! {
            changed = stop.changed(), if !abort => {
                if changed.is_ok() && *stop.borrow() == SupervisorStop::AbortAndJoin {
                    connections.abort_all();
                }
            }
            result = connections.join_next() => {
                if let Some(Err(error)) = result {
                    tracing::debug!(listener = %kind, %error, "cleartext connection task failed while joining");
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

#[allow(clippy::too_many_arguments)]
async fn serve_connection(
    kind: ProxyListenerKind,
    mode: CleartextMode,
    versions: Vec<CompiledHttpVersion>,
    request_header_timeout: Duration,
    max_concurrent_streams: u32,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    quota_key: WireBodyQuotaKey,
    runtime: Arc<Runtime>,
    observation_runtime: Arc<ProductObservationRuntime>,
    assets: Arc<ProductIngressAssets>,
    mut supervisor_stop: watch::Receiver<SupervisorStop>,
    _admission: OwnedSemaphorePermit,
) {
    let close = Arc::new(ConnectionClose::default());
    let service_close = close.clone();
    let service = service_fn(move |request| {
        let runtime = runtime.clone();
        let observation_runtime = observation_runtime.clone();
        let assets = assets.clone();
        let close = service_close.clone();
        let quota_key = quota_key.clone();
        async move {
            let close_entire_connection = request.version() != http::Version::HTTP_2;
            let handled = execute_request(
                mode,
                peer,
                quota_key,
                runtime,
                observation_runtime,
                assets,
                request,
            )
            .await;
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
    http.http1_header_read_timeout(request_header_timeout);
    http.http2_max_concurrent_streams(max_concurrent_streams);
    let http1 = versions.contains(&CompiledHttpVersion::Http1);
    let http2 = versions.contains(&CompiledHttpVersion::Http2);
    if http2 {
        http.http2_keep_alive_interval(request_header_timeout);
        http.http2_keep_alive_timeout(request_header_timeout);
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

    let connection = http.serve_connection(stream, service);
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
        tracing::debug!(listener = %kind, %peer, %error, "cleartext HTTP connection ended");
    }
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

impl HandledResponse {
    fn fixed(status: StatusCode, message: &'static str, close_connection: bool) -> Self {
        let response = Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(ProxyResponseBody::Local(Body::from(message)))
            .expect("fixed proxy responses are valid");
        Self {
            response,
            close_connection,
        }
    }
}

async fn execute_request(
    mode: CleartextMode,
    peer: SocketAddr,
    quota_key: WireBodyQuotaKey,
    runtime: Arc<Runtime>,
    _observation_runtime: Arc<ProductObservationRuntime>,
    assets: Arc<ProductIngressAssets>,
    mut request: Request<Body>,
) -> HandledResponse {
    let started_at = Instant::now();
    let target = match mode {
        CleartextMode::Explicit => reconcile_explicit_request(&mut request),
        CleartextMode::Transparent => reconcile_transparent_http_request(&mut request),
    };
    let target = match target {
        Ok(target) => target,
        Err(error) => return authority_failure(error),
    };
    let sanitized = match sanitize_untrusted_request(request) {
        Ok(request) => request,
        Err(error) => return header_failure(error),
    };
    let Some(lease) = runtime.lease().await else {
        return HandledResponse::fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "service unavailable\n",
            true,
        );
    };
    let Some(service_deadline) = started_at.checked_add(lease.request_timeout()) else {
        return HandledResponse::fixed(StatusCode::INTERNAL_SERVER_ERROR, "request failed\n", true);
    };

    let resolved = match tokio::time::timeout_at(
        service_deadline,
        resolve_forwarding_target(
            &target.url,
            &sanitized,
            lease.egress(),
            assets.destination_guard(),
        ),
    )
    .await
    {
        Ok(Ok(resolved)) => resolved,
        Ok(Err(error)) => return resolve_failure(error),
        Err(_) => return timeout_failure(),
    };

    let (mut parts, ingress_body, protocol) = sanitized.into_parts();
    let ingress_was_complete = ingress_body.is_end_stream();
    let body_headers = body_headers(&parts.headers);
    let content_type = parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let headers = std::mem::take(&mut parts.headers);
    let request_id = request_id();
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
        },
    ) {
        Ok(prepared) => prepared,
        Err(error) => return decision_failure(error),
    };
    let deadline = prepared.deadline();
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
                Err(error) => return body_failure(error),
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
    let decision = match prepared.decide(decision_body).await {
        Ok(decision) => decision,
        Err(error) => return decision_failure(error),
    };
    let mut allowed = match decision {
        RequestDecision::Allow(allowed) => allowed,
        RequestDecision::Deny(_) => {
            return HandledResponse::fixed(
                StatusCode::FORBIDDEN,
                "request denied\n",
                !normalized && !ingress_was_complete,
            )
        }
    };

    let origin_body = match prepare_allowed_request(
        &lease,
        &request_id,
        &mut parts,
        &mut allowed,
        origin_body,
        normalized,
    ) {
        Ok(body) => body,
        Err(_) => {
            return HandledResponse::fixed(
                StatusCode::INTERNAL_SERVER_ERROR,
                "request failed\n",
                true,
            )
        }
    };
    let request = SanitizedRequest::from_parts(parts, origin_body, protocol);
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
        Ok(Err(error)) => return forward_failure(error),
        Err(_) => return timeout_failure(),
    };
    let retention = match lease.retain_for_operation() {
        Ok(retention) => retention,
        Err(error) => return generation_retention_failure(error),
    };
    response
        .body_mut()
        .bind_request_lifetime(deadline, retention);
    if apply_header_effects(allowed.response_header_effects(), response.headers_mut()).is_err() {
        return HandledResponse::fixed(
            StatusCode::INTERNAL_SERVER_ERROR,
            "response failed\n",
            true,
        );
    }
    HandledResponse {
        response: response.map(ProxyResponseBody::Forwarded),
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

fn prepare_allowed_request(
    lease: &crate::runtime::GenerationLease,
    request_id: &str,
    parts: &mut http::request::Parts,
    allowed: &mut AllowedRequest<'_>,
    opaque_body: Option<Body>,
    normalized: bool,
) -> Result<OriginRequestBody, FinalRequestError> {
    let mut headers = std::mem::take(&mut allowed.common.headers);
    apply_header_effects(allowed.request_header_effects(), &mut headers)?;
    lease
        .credentials()
        .inject(allowed.credential_actions(), &mut headers)?;
    if let Some(provider_credentials) = allowed.provider_credentials.take() {
        provider_credentials.apply(&mut headers)?;
    }
    lease.egress().apply_request_headers(&mut headers)?;
    lease
        .credentials()
        .inject(lease.egress().credential_actions(), &mut headers)?;
    lease
        .safety()
        .inject_loop_marker(&mut headers, request_id)?;

    let body = if normalized {
        let body = allowed
            .body
            .take()
            .ok_or(FinalRequestError::MissingNormalizedBody)?;
        headers.remove(CONTENT_ENCODING);
        headers.remove(CONTENT_LENGTH);
        match body.content_type.as_deref() {
            Some(value) => {
                let value =
                    HeaderValue::from_str(value).map_err(|_| FinalRequestError::ContentType)?;
                headers.insert(CONTENT_TYPE, value);
            }
            None => {
                headers.remove(CONTENT_TYPE);
            }
        }
        OriginRequestBody::Guarded(GuardedHttpBody::new(body.decoded))
    } else {
        if allowed.body.is_some() {
            return Err(FinalRequestError::UnexpectedNormalizedBody);
        }
        OriginRequestBody::Opaque(opaque_body.expect("the opaque ingress body is retained"))
    };
    parts.headers = headers;
    Ok(body)
}

fn authority_failure(_error: AuthorityError) -> HandledResponse {
    HandledResponse::fixed(StatusCode::BAD_REQUEST, "invalid request target\n", true)
}

fn header_failure(error: HeaderPreparationError) -> HandledResponse {
    let status = match error {
        HeaderPreparationError::UpgradeUnsupported | HeaderPreparationError::ConnectUnsupported => {
            StatusCode::NOT_IMPLEMENTED
        }
        _ => StatusCode::BAD_REQUEST,
    };
    HandledResponse::fixed(status, "invalid request\n", true)
}

fn resolve_failure(_error: ResolveForwardingError) -> HandledResponse {
    HandledResponse::fixed(StatusCode::FORBIDDEN, "destination denied\n", true)
}

fn decision_failure(_error: RequestDecisionError) -> HandledResponse {
    HandledResponse::fixed(StatusCode::INTERNAL_SERVER_ERROR, "request failed\n", true)
}

fn body_failure(error: HttpBodyReadError) -> HandledResponse {
    let status = match error {
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
    };
    HandledResponse::fixed(status, "request body denied\n", true)
}

fn forward_failure(_error: ForwardError) -> HandledResponse {
    HandledResponse::fixed(StatusCode::BAD_GATEWAY, "upstream failed\n", true)
}

fn timeout_failure() -> HandledResponse {
    HandledResponse::fixed(StatusCode::GATEWAY_TIMEOUT, "request timed out\n", true)
}

fn generation_retention_failure(_error: GenerationRetentionError) -> HandledResponse {
    HandledResponse::fixed(
        StatusCode::SERVICE_UNAVAILABLE,
        "service unavailable\n",
        true,
    )
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
    Opaque(Body),
    Guarded(GuardedHttpBody),
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
            Self::Opaque(body) => Pin::new(body)
                .poll_data(context)
                .map(|item| item.map(|item| item.map(OriginRequestData::Opaque))),
            Self::Guarded(body) => Pin::new(body).poll_data(context).map(|item| {
                item.map(|item| match item {
                    Ok(data) => Ok(OriginRequestData::Guarded(data)),
                    Err(never) => match never {},
                })
            }),
        }
    }

    fn poll_trailers(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, Self::Error>> {
        match self.get_mut() {
            Self::Opaque(body) => Pin::new(body).poll_trailers(context),
            Self::Guarded(body) => match Pin::new(body).poll_trailers(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(trailers)) => Poll::Ready(Ok(trailers)),
                Poll::Ready(Err(never)) => match never {},
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Opaque(body) => body.is_end_stream(),
            Self::Guarded(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Opaque(body) => body.size_hint(),
            Self::Guarded(body) => body.size_hint(),
        }
    }
}

enum ProxyResponseBody {
    Local(Body),
    Forwarded(ForwardBody),
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
            Self::Forwarded(body) => Pin::new(body)
                .poll_data(context)
                .map(|item| item.map(|item| item.map_err(ProxyResponseBodyError::Forwarded))),
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
            Self::Forwarded(body) => Pin::new(body)
                .poll_trailers(context)
                .map_err(ProxyResponseBodyError::Forwarded),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Local(body) => body.is_end_stream(),
            Self::Forwarded(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Local(body) => body.size_hint(),
            Self::Forwarded(body) => body.size_hint(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::net::{Ipv4Addr, TcpListener as StdTcpListener};
    use std::time::Duration;

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use hyper::body::to_bytes;
    use hyper::client::conn;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    use super::*;
    use crate::activation::runner::ProductRuntime;
    use crate::config::load_and_compile_exact_config;

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
        );
        product.start_proxy_supervisors(&mut starter).await.unwrap();
        (directory, product)
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

    #[tokio::test]
    async fn proxy_egress_cannot_target_self_or_control_plane() {
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
        assert!(StdTcpListener::bind(control).is_ok());
    }

    struct CapturedRoundTrip {
        headers: HeaderMap,
        body: Bytes,
        response_headers: HeaderMap,
    }

    async fn normalized_round_trip(mode: CleartextMode) -> CapturedRoundTrip {
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
            CleartextMode::Explicit => "explicit_http",
            CleartextMode::Transparent => "transparent_http",
        };
        let listener_connect = if matches!(mode, CleartextMode::Explicit) {
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
"#
        );
        let config = base_config(proxy, listener_table, &policy);
        let (_directory, product) = product(config, listeners).await;

        let plain = b"canonical decoded request bytes";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plain).unwrap();
        let encoded = encoder.finish().unwrap();
        assert_ne!(encoded, plain);
        let uri = match mode {
            CleartextMode::Explicit => format!("http://{origin}/ingest"),
            CleartextMode::Transparent => "/ingest".to_owned(),
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
        origin_task.await.unwrap();
        captured
    }

    #[tokio::test]
    async fn normalized_http_body_forwards_identity_without_recompression() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let captured = normalized_round_trip(CleartextMode::Explicit).await;

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
    }

    #[tokio::test]
    async fn normalized_http_body_removes_stale_coding_and_length() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let captured = normalized_round_trip(CleartextMode::Transparent).await;

        assert_eq!(captured.body, &b"canonical decoded request bytes"[..]);
        assert!(!captured.headers.contains_key(CONTENT_ENCODING));
        assert_eq!(
            captured.headers[CONTENT_LENGTH],
            b"canonical decoded request bytes".len().to_string()
        );
        assert_eq!(captured.headers[CONTENT_TYPE], "application/octet-stream");
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
    async fn cleartext_mitm_fails_activation_until_executor_is_installed() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        let ([proxy], listeners) = prebound_listeners::<1>();
        let directory = tempdir().unwrap();
        let config = format!(
            r#"schema_version = 3

[listeners.explicit_http]
bind = "{proxy}"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "mitm"

[mitm]
mode = "generated"
directory = "{}"

[policy]
default = "deny"
"#,
            directory.path().join("mitm").display()
        );
        let path = directory.path().join("acl-proxy.toml");
        fs::write(&path, config).unwrap();
        let loaded = load_and_compile_exact_config(&path).unwrap();
        let product = ProductRuntime::prepare_from_prebound(loaded, listeners)
            .await
            .unwrap();
        product.activate_initial().await.unwrap();
        let mut starter = ProductProxySupervisorStarter::new(
            product.runtime().clone(),
            product.observation_runtime().clone(),
        );
        let error = product
            .start_proxy_supervisors(&mut starter)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("CONNECT MITM"));
        assert!(StdTcpListener::bind(proxy).is_ok());
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
}
