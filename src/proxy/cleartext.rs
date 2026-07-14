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
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Version};
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
use crate::capture::{
    CaptureDecision, CaptureEndpoint, CaptureKind, CaptureMode, CaptureRecord, HttpCaptureTap,
};
use crate::config::compiler::{
    CompiledHttp1ConnectPolicy, CompiledHttpVersion, HttpBodyReadPlan, StaticCleartextListener,
};
use crate::http_body::{read_mandatory_request_body, HttpBodyReadError};
use crate::observation::{CaptureEpoch, CaptureEvent, ProductObservationRuntime};
use crate::policy::apply_header_effects;
use crate::proxy::authority::{reconcile_explicit_request, reconcile_transparent_http_request};
use crate::proxy::forward::{
    forward_request, resolve_forwarding_target, ForwardBody, ForwardBodyError,
};
use crate::proxy::headers::{sanitize_untrusted_request, HeaderPreparationError, SanitizedRequest};
use crate::request_decision::{
    prepare_request, AllowedRequest, GuardedRequestBody as DecisionBody, RequestDecision,
    RequestInput, TerminalRequestBodyProvenance,
};
use crate::runtime::{BoxFuture, Runtime};
use crate::safety::wire_body::{GuardedBodyData, GuardedHttpBody};
use crate::safety::{InvalidLoopMarker, WireBodyQuotaKey};
use crate::sensitive::{is_sensitive_header_name, REDACTED};

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
            .header(http::header::CONTENT_LENGTH, message.len())
            .body(ProxyResponseBody::Local(Body::from(message)))
            .expect("fixed proxy responses are valid");
        Self {
            response,
            close_connection,
        }
    }
}

struct HttpCaptureContext {
    runtime: Arc<ProductObservationRuntime>,
    epoch: Arc<CaptureEpoch>,
    request_id: String,
    url: String,
    method: String,
    client: CaptureEndpoint,
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
        method: String,
        request_version: Version,
        max_expansion_ratio: usize,
    ) -> Self {
        Self {
            runtime,
            epoch,
            request_id,
            url: String::new(),
            method,
            client: CaptureEndpoint {
                address: Some(peer.ip().to_string()),
                port: Some(peer.port()),
            },
            target: None,
            request_version,
            max_expansion_ratio,
        }
    }

    fn bind_target(&mut self, target: &crate::url::CanonicalUrl) {
        self.url.clone_from(&target.url);
        self.target = Some(CaptureEndpoint {
            address: Some(target.host_for_capture.clone()),
            port: Some(target.port),
        });
    }

    fn begin(
        &self,
        event: CaptureEvent,
        record: CaptureRecord,
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
            method: self.method.clone(),
            status_code: status.map(|status| status.as_u16()),
            status_message: if include_status_message {
                status
                    .and_then(|status| status.canonical_reason())
                    .map(str::to_owned)
            } else {
                None
            },
            client: self.client.clone(),
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
        let mut record = self.request_record(CaptureDecision::Allow, Some(headers));
        if let TerminalRequestBodyProvenance::ProviderReplacement { size } = provenance {
            record.mark_provider_replacement_omitted(size);
            if let Some(mut submission) =
                self.begin(CaptureEvent::RequestAllowed, record, body_headers)
            {
                submission.abandon();
            }
            return None;
        }
        self.begin(CaptureEvent::RequestAllowed, record, body_headers)
    }

    fn submit_denied_request(
        &self,
        headers: Option<&HeaderMap>,
        body: Option<DecisionBody>,
        provenance: TerminalRequestBodyProvenance,
    ) {
        let mut record = self.request_record(CaptureDecision::Deny, headers);
        let body_headers = body.as_ref().map(terminal_body_headers).unwrap_or_default();
        if let TerminalRequestBodyProvenance::ProviderReplacement { size } = provenance {
            record.mark_provider_replacement_omitted(size);
        }
        let Some(mut submission) = self.begin(CaptureEvent::RequestDenied, record, &body_headers)
        else {
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
        let record =
            self.response_record(decision, self.request_version, Some(&headers), status, true);
        let event = match decision {
            CaptureDecision::Allow => CaptureEvent::ResponseAllowed,
            CaptureDecision::Deny => CaptureEvent::ResponseDenied,
        };
        if let Some(mut submission) = self.begin(event, record, &headers) {
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

async fn execute_request(
    mode: CleartextMode,
    peer: SocketAddr,
    quota_key: WireBodyQuotaKey,
    runtime: Arc<Runtime>,
    observation_runtime: Arc<ProductObservationRuntime>,
    assets: Arc<ProductIngressAssets>,
    mut request: Request<Body>,
) -> HandledResponse {
    let started_at = Instant::now();
    let request_id = request_id();
    let request_method = request.method().to_string();
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
    let Some(service_deadline) = started_at.checked_add(lease.request_timeout()) else {
        return capture.deny_metadata_only(
            StatusCode::INTERNAL_SERVER_ERROR,
            "request failed\n",
            true,
        );
    };
    let target = match mode {
        CleartextMode::Explicit => reconcile_explicit_request(&mut request),
        CleartextMode::Transparent => reconcile_transparent_http_request(&mut request),
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
    let decision_error_headers = sanitized_capture_headers(prepared.headers_for_observation());
    let decision = match prepared.decide(decision_body).await {
        Ok(decision) => decision,
        Err(error) => {
            capture.submit_denied_request(
                Some(&decision_error_headers),
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
        Ok(Err(_)) => {
            return capture.fixed_response(
                CaptureDecision::Allow,
                StatusCode::BAD_GATEWAY,
                "upstream failed\n",
                true,
            )
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
        capture.response_record(
            CaptureDecision::Allow,
            response.version(),
            Some(response.headers()),
            response.status(),
            false,
        ),
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
        capture: Option<CaptureSubmission>,
    },
}

impl ProxyResponseBody {
    fn forwarded(body: ForwardBody, capture: Option<CaptureSubmission>) -> Self {
        Self::Forwarded { body, capture }
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
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .header(http::header::SET_COOKIE, "origin-cookie-secret")
                                    .header("x-origin-response", "visible")
                                    .body(Body::from("response-body"))
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
    async fn active_executor_capture_omits_provider_replacement_bytes() {
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
urls = ["http://{origin}/replacement"]
methods = ["POST"]
authorization_provider = "replacing"
redaction_profile = "wire"

[[policy.rules]]
id = "complete-denied"
decision = "delegate"
urls = ["http://{origin}/complete-denied"]
methods = ["POST"]
authorization_provider = "replacing"
redaction_profile = "wire"

{}"#,
            provider_path.display(),
            capture_config(),
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
                .body(Body::from("denied complete body"))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
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
        assert_eq!(denied.decode_body_bytes().unwrap(), b"denied complete body");
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
        capture_records: Vec<CaptureRecord>,
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
        captured.capture_records = read_capture_records(directory.path());
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
