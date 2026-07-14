use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

#[cfg(test)]
use std::collections::VecDeque;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex as AsyncMutex};
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

use crate::authorization::webhook::runtime::WebhookAuthorizationRuntime;
use crate::config::compiler::StaticControlConfig;
use crate::http1::store::PARSER_STORE_BYTES;
use crate::runtime::ServiceReadiness;
use crate::tls_identity::StaticTlsIdentityError;

use super::admission::{
    ControlAdmissionError, ControlArenaCounts, ControlArenaError, ControlConnectionLease,
    ControlParserArena,
};
use super::connection::{
    serve_control_connection, ControlConnectionContext, ControlConnectionSignal,
};
use super::router::{ControlRouter, ControlRouterError};

const HTTP1_ALPN: &[u8] = b"http/1.1";
const TRANSIENT_ACCEPT_RETRY: Duration = Duration::from_millis(10);
const RECOVERABLE_ACCEPT_RETRY: Duration = Duration::from_secs(1);
const MAX_CONSECUTIVE_BACKOFF_ACCEPT_FAILURES: usize = 30;
const MAX_IMMEDIATE_ACCEPT_FAILURES_BEFORE_BACKOFF: usize = 1_024;

pub(crate) struct ControlServer {
    stop: watch::Sender<ControlStop>,
    stop_gate: Arc<StdMutex<ControlStop>>,
    task: AsyncMutex<ControlTaskState>,
    arena: ControlParserArena,
    local_addr: SocketAddr,
    #[cfg(test)]
    spawned_connections: Arc<AtomicUsize>,
}

struct ControlTaskState {
    handle: Option<JoinHandle<Result<(), Arc<ControlServerRunError>>>>,
    terminal: Option<Result<(), Arc<ControlServerShutdownError>>>,
}

impl ControlServer {
    pub(crate) fn bind(
        config: &StaticControlConfig,
        authorization: Arc<WebhookAuthorizationRuntime>,
        readiness: Arc<ServiceReadiness>,
        failure_observer: Arc<dyn ControlServerFailureObserver>,
    ) -> Result<Arc<Self>, ControlServerError> {
        let prepared =
            PreparedControlServer::try_new(config, authorization, readiness, failure_observer)?;
        let listener =
            StdTcpListener::bind(config.bind).map_err(|source| ControlServerError::Bind {
                address: config.bind,
                source,
            })?;
        Self::start(prepared, listener)
    }

    pub(crate) fn from_prebound(
        config: &StaticControlConfig,
        listener: StdTcpListener,
        authorization: Arc<WebhookAuthorizationRuntime>,
        readiness: Arc<ServiceReadiness>,
        failure_observer: Arc<dyn ControlServerFailureObserver>,
    ) -> Result<Arc<Self>, ControlServerError> {
        let prepared =
            PreparedControlServer::try_new(config, authorization, readiness, failure_observer)?;
        Self::start(prepared, listener)
    }

    fn start(
        prepared: PreparedControlServer,
        listener: StdTcpListener,
    ) -> Result<Arc<Self>, ControlServerError> {
        let local_addr = listener
            .local_addr()
            .map_err(ControlServerError::ListenerAddress)?;
        listener
            .set_nonblocking(true)
            .map_err(ControlServerError::ListenerNonblocking)?;
        let listener =
            TcpListener::from_std(listener).map_err(ControlServerError::ListenerAdopt)?;
        Self::start_listener(prepared, ControlListener::new(listener), local_addr)
    }

    #[cfg(test)]
    pub(crate) fn from_prebound_with_accept_errors(
        config: &StaticControlConfig,
        listener: StdTcpListener,
        authorization: Arc<WebhookAuthorizationRuntime>,
        readiness: Arc<ServiceReadiness>,
        errors: impl IntoIterator<Item = io::Error>,
        failure_observer: Arc<dyn ControlServerFailureObserver>,
    ) -> Result<Arc<Self>, ControlServerError> {
        let prepared =
            PreparedControlServer::try_new(config, authorization, readiness, failure_observer)?;
        let local_addr = listener
            .local_addr()
            .map_err(ControlServerError::ListenerAddress)?;
        listener
            .set_nonblocking(true)
            .map_err(ControlServerError::ListenerNonblocking)?;
        let listener =
            TcpListener::from_std(listener).map_err(ControlServerError::ListenerAdopt)?;
        Self::start_listener(
            prepared,
            ControlListener::with_accept_errors(listener, errors),
            local_addr,
        )
    }

    #[cfg(test)]
    fn from_prebound_with_connection_panic(
        config: &StaticControlConfig,
        listener: StdTcpListener,
        authorization: Arc<WebhookAuthorizationRuntime>,
        readiness: Arc<ServiceReadiness>,
        failure_observer: Arc<dyn ControlServerFailureObserver>,
    ) -> Result<Arc<Self>, ControlServerError> {
        let prepared =
            PreparedControlServer::try_new(config, authorization, readiness, failure_observer)?;
        prepared
            .context
            .panic_next_connection
            .store(true, Ordering::Release);
        Self::start(prepared, listener)
    }

    fn start_listener(
        prepared: PreparedControlServer,
        listener: ControlListener,
        local_addr: SocketAddr,
    ) -> Result<Arc<Self>, ControlServerError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| ControlServerError::RuntimeUnavailable)?;
        let arena = prepared.context.arena.clone();
        let (stop, stop_rx) = watch::channel(ControlStop::Running);
        let stop_gate = Arc::new(StdMutex::new(ControlStop::Running));
        #[cfg(test)]
        let spawned_connections = Arc::new(AtomicUsize::new(0));
        #[cfg(test)]
        let task_spawned_connections = spawned_connections.clone();
        let task = runtime.spawn(run_control_supervisor(
            listener,
            prepared.context,
            stop_rx,
            stop_gate.clone(),
            #[cfg(test)]
            task_spawned_connections,
        ));
        Ok(Arc::new(Self {
            stop,
            stop_gate,
            task: AsyncMutex::new(ControlTaskState {
                handle: Some(task),
                terminal: None,
            }),
            arena,
            local_addr,
            #[cfg(test)]
            spawned_connections,
        }))
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(crate) fn arena_counts(&self) -> ControlArenaCounts {
        self.arena.counts()
    }

    pub(crate) async fn close_and_join(&self) -> Result<(), Arc<ControlServerShutdownError>> {
        self.stop_and_join(ControlStop::CloseAndJoin).await
    }

    pub(crate) async fn abort_and_join(&self) -> Result<(), Arc<ControlServerShutdownError>> {
        self.stop_and_join(ControlStop::AbortAndJoin).await
    }

    async fn stop_and_join(
        &self,
        requested: ControlStop,
    ) -> Result<(), Arc<ControlServerShutdownError>> {
        request_stop(&self.stop_gate, &self.stop, requested);
        let mut task = self.task.lock().await;
        if let Some(terminal) = &task.terminal {
            return terminal.clone();
        }
        let result = match task
            .handle
            .as_mut()
            .expect("a nonterminal control server owns its supervisor task")
            .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(Arc::new(ControlServerShutdownError::Supervisor(error))),
            Err(error) => Err(Arc::new(ControlServerShutdownError::Join(error))),
        };
        task.handle.take();
        task.terminal = Some(result.clone());
        result
    }

    #[cfg(test)]
    fn spawned_connections(&self) -> usize {
        self.spawned_connections.load(Ordering::Acquire)
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        // The product lifecycle must call close_and_join or abort_and_join.
        // This fallback leaves the supervisor alive long enough to own and
        // join its connection set after observing the terminal stop request.
        request_stop(&self.stop_gate, &self.stop, ControlStop::AbortAndJoin);
    }
}

struct PreparedControlServer {
    context: Arc<ControlServerContext>,
}

impl PreparedControlServer {
    fn try_new(
        config: &StaticControlConfig,
        authorization: Arc<WebhookAuthorizationRuntime>,
        readiness: Arc<ServiceReadiness>,
        failure_observer: Arc<dyn ControlServerFailureObserver>,
    ) -> Result<Self, ControlServerError> {
        let expected_arena_bytes = config
            .max_connections
            .checked_mul(PARSER_STORE_BYTES)
            .ok_or(ControlServerError::ArenaCapacityOverflow)?;
        if config.parser_arena_bytes != expected_arena_bytes {
            return Err(ControlServerError::ArenaCapacityMismatch {
                configured: config.parser_arena_bytes,
                expected: expected_arena_bytes,
            });
        }
        let router = ControlRouter::try_new(&config.base_path)?;
        let arena = ControlParserArena::try_new(config.max_connections)?;
        let tls = config
            .tls
            .as_ref()
            .map(|identity| {
                crate::tls_identity::load_static_tls_acceptor(
                    &identity.certificate_chain,
                    &identity.private_key,
                    vec![HTTP1_ALPN.to_vec()],
                )
            })
            .transpose()?;
        Ok(Self {
            context: Arc::new(ControlServerContext {
                arena,
                router,
                authorization,
                readiness,
                failure_observer,
                config: config.clone(),
                tls,
                #[cfg(test)]
                panic_next_connection: AtomicBool::new(false),
            }),
        })
    }
}

struct ControlServerContext {
    arena: ControlParserArena,
    router: ControlRouter,
    authorization: Arc<WebhookAuthorizationRuntime>,
    readiness: Arc<ServiceReadiness>,
    failure_observer: Arc<dyn ControlServerFailureObserver>,
    config: StaticControlConfig,
    tls: Option<TlsAcceptor>,
    #[cfg(test)]
    panic_next_connection: AtomicBool,
}

struct ControlListener {
    listener: TcpListener,
    #[cfg(test)]
    accept_errors: StdMutex<VecDeque<io::Error>>,
}

impl ControlListener {
    fn new(listener: TcpListener) -> Self {
        Self {
            listener,
            #[cfg(test)]
            accept_errors: StdMutex::new(VecDeque::new()),
        }
    }

    #[cfg(test)]
    fn with_accept_errors(
        listener: TcpListener,
        errors: impl IntoIterator<Item = io::Error>,
    ) -> Self {
        Self {
            listener,
            accept_errors: StdMutex::new(errors.into_iter().collect()),
        }
    }

    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        #[cfg(test)]
        if let Some(error) = self
            .accept_errors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
        {
            return Err(error);
        }
        self.listener.accept().await
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlStop {
    Running,
    CloseAndJoin,
    AbortAndJoin,
}

fn request_stop(
    gate: &StdMutex<ControlStop>,
    sender: &watch::Sender<ControlStop>,
    requested: ControlStop,
) {
    let mut current = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if stop_rank(requested) > stop_rank(*current) {
        *current = requested;
        let _ = sender.send(requested);
    }
}

const fn stop_rank(stop: ControlStop) -> u8 {
    match stop {
        ControlStop::Running => 0,
        ControlStop::CloseAndJoin => 1,
        ControlStop::AbortAndJoin => 2,
    }
}

async fn run_control_supervisor(
    listener: ControlListener,
    context: Arc<ControlServerContext>,
    mut stop: watch::Receiver<ControlStop>,
    stop_gate: Arc<StdMutex<ControlStop>>,
    #[cfg(test)] spawned_connections: Arc<AtomicUsize>,
) -> Result<(), Arc<ControlServerRunError>> {
    let mut connections = JoinSet::new();
    let (connection_stop, _) = watch::channel(ControlConnectionSignal::Running);
    let mut accept_failures = AcceptFailureTracker::default();
    let exit = loop {
        tokio::select! {
            biased;
            changed = stop.changed() => {
                let requested = *stop.borrow_and_update();
                if changed.is_err() || requested != ControlStop::Running {
                    break SupervisorExit::Stop(requested);
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        let retry_after = match accept_failures.on_error(&error) {
                            AcceptErrorDisposition::RetryNow => {
                                let consecutive =
                                    accept_failures.immediate_failures_since_backoff();
                                if consecutive == 1 || consecutive.is_power_of_two() {
                                    tracing::warn!(
                                        error = %error,
                                        consecutive,
                                        "control listener accept failed without backoff"
                                    );
                                }
                                tokio::task::yield_now().await;
                                continue;
                            }
                            AcceptErrorDisposition::RetryAfter(retry_after)
                            | AcceptErrorDisposition::RetryIndefinitely(retry_after) => {
                                retry_after
                            }
                            AcceptErrorDisposition::Fatal => {
                                break SupervisorExit::Error(Arc::new(ControlServerRunError::Accept(error)));
                            }
                        };
                        tracing::warn!(
                            error = %error,
                            retry_after_ms = retry_after.as_millis(),
                            "control listener accept failed transiently"
                        );
                        let retry = tokio::time::sleep(retry_after);
                        tokio::pin!(retry);
                        tokio::select! {
                            biased;
                            changed = stop.changed() => {
                                let requested = *stop.borrow_and_update();
                                if changed.is_err() || requested != ControlStop::Running {
                                    break SupervisorExit::Stop(requested);
                                }
                            }
                            _ = &mut retry => {}
                        }
                        continue;
                    }
                };
                accept_failures.on_success();
                let first_header_deadline = Instant::now() + context.config.request_header_timeout;
                let gate = stop_gate
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if *gate != ControlStop::Running {
                    break SupervisorExit::Stop(*gate);
                }
                let lease = match context.arena.try_acquire() {
                    Ok(lease) => lease,
                    Err(ControlAdmissionError::AtCapacity) => continue,
                    Err(ControlAdmissionError::Poisoned) => {
                        break SupervisorExit::Error(Arc::new(ControlServerRunError::AdmissionPoisoned))
                    }
                };
                #[cfg(test)]
                spawned_connections.fetch_add(1, Ordering::AcqRel);
                let context = context.clone();
                let connection_close = connection_stop.subscribe();
                let connection_abort = connection_stop.subscribe();
                connections.spawn(async move {
                    #[cfg(test)]
                    if context.panic_next_connection.swap(false, Ordering::AcqRel) {
                        panic!("injected control connection task panic");
                    }
                    serve_admitted_connection(
                        stream,
                        lease,
                        first_header_deadline,
                        context,
                        connection_close,
                        connection_abort,
                    ).await;
                });
                drop(gate);
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::error!(error = %error, "control connection task panicked");
                }
            }
        }
    };
    drop(listener);

    if let SupervisorExit::Error(error) = &exit {
        context.readiness.begin_shutdown();
        context.failure_observer.failed(error.clone());
    }

    let mut abort = matches!(
        exit,
        SupervisorExit::Error(_) | SupervisorExit::Stop(ControlStop::AbortAndJoin)
    );
    if abort {
        let _ = connection_stop.send(ControlConnectionSignal::Abort);
        connections.abort_all();
    } else {
        let _ = connection_stop.send(ControlConnectionSignal::CloseAfterRequest);
    }
    let mut cleanup_error = None;
    while !connections.is_empty() {
        let result = if abort {
            connections.join_next().await
        } else {
            tokio::select! {
                biased;
                changed = stop.changed() => {
                    let requested = *stop.borrow_and_update();
                    if changed.is_err() || requested == ControlStop::AbortAndJoin {
                        abort = true;
                        let _ = connection_stop.send(ControlConnectionSignal::Abort);
                        connections.abort_all();
                    }
                    continue;
                }
                result = connections.join_next() => result,
            }
        };
        let Some(result) = result else {
            break;
        };
        if let Err(error) = result {
            if !error.is_cancelled() && cleanup_error.is_none() {
                cleanup_error = Some(Arc::new(ControlServerRunError::ConnectionJoin(error)));
            }
        }
    }

    match exit {
        SupervisorExit::Error(error) => Err(error),
        SupervisorExit::Stop(_) => cleanup_error.map_or(Ok(()), Err),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcceptErrorDisposition {
    RetryNow,
    RetryAfter(Duration),
    RetryIndefinitely(Duration),
    Fatal,
}

#[derive(Default)]
struct AcceptFailureTracker {
    consecutive_backoff_failures: usize,
    immediate_failures_since_backoff: usize,
}

impl AcceptFailureTracker {
    fn on_error(&mut self, error: &io::Error) -> AcceptErrorDisposition {
        match classify_accept_error(error) {
            AcceptErrorDisposition::RetryNow => {
                self.immediate_failures_since_backoff += 1;
                if self.immediate_failures_since_backoff
                    >= MAX_IMMEDIATE_ACCEPT_FAILURES_BEFORE_BACKOFF
                {
                    self.immediate_failures_since_backoff = 0;
                    AcceptErrorDisposition::RetryAfter(TRANSIENT_ACCEPT_RETRY)
                } else {
                    AcceptErrorDisposition::RetryNow
                }
            }
            AcceptErrorDisposition::RetryAfter(retry_after) => {
                self.consecutive_backoff_failures += 1;
                if self.consecutive_backoff_failures >= MAX_CONSECUTIVE_BACKOFF_ACCEPT_FAILURES {
                    AcceptErrorDisposition::Fatal
                } else {
                    AcceptErrorDisposition::RetryAfter(retry_after)
                }
            }
            AcceptErrorDisposition::RetryIndefinitely(retry_after) => {
                AcceptErrorDisposition::RetryIndefinitely(retry_after)
            }
            AcceptErrorDisposition::Fatal => AcceptErrorDisposition::Fatal,
        }
    }

    fn on_success(&mut self) {
        self.consecutive_backoff_failures = 0;
        self.immediate_failures_since_backoff = 0;
    }

    fn immediate_failures_since_backoff(&self) -> usize {
        self.immediate_failures_since_backoff
    }
}

fn classify_accept_error(error: &io::Error) -> AcceptErrorDisposition {
    if is_fatal_accept_error(error) {
        return AcceptErrorDisposition::Fatal;
    }
    if is_indefinitely_retryable_accept_error(error) {
        return AcceptErrorDisposition::RetryIndefinitely(RECOVERABLE_ACCEPT_RETRY);
    }
    match error.kind() {
        io::ErrorKind::Interrupted
        | io::ErrorKind::WouldBlock
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionRefused => AcceptErrorDisposition::RetryNow,
        io::ErrorKind::TimedOut => AcceptErrorDisposition::RetryAfter(TRANSIENT_ACCEPT_RETRY),
        _ => AcceptErrorDisposition::RetryAfter(RECOVERABLE_ACCEPT_RETRY),
    }
}

fn is_indefinitely_retryable_accept_error(error: &io::Error) -> bool {
    is_resource_pressure_accept_error(error) || is_pending_network_accept_error(error)
}

fn is_resource_pressure_accept_error(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::OutOfMemory {
        return true;
    }
    is_platform_resource_pressure_accept_error(error)
}

fn is_pending_network_accept_error(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::NetworkDown
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
    ) {
        return true;
    }
    is_platform_pending_network_accept_error(error)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn is_platform_pending_network_accept_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::ENETDOWN
                | libc::EPROTO
                | libc::ENOPROTOOPT
                | libc::EHOSTDOWN
                | libc::ENONET
                | libc::EHOSTUNREACH
                | libc::EOPNOTSUPP
                | libc::ENETUNREACH
        )
    )
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn is_platform_pending_network_accept_error(_error: &io::Error) -> bool {
    false
}

#[cfg(unix)]
fn is_platform_resource_pressure_accept_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    )
}

#[cfg(windows)]
fn is_platform_resource_pressure_accept_error(error: &io::Error) -> bool {
    // WSAENOBUFS.
    error.raw_os_error() == Some(10055)
}

#[cfg(not(any(unix, windows)))]
fn is_platform_resource_pressure_accept_error(_error: &io::Error) -> bool {
    false
}

fn is_fatal_accept_error(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::InvalidInput {
        return true;
    }
    is_invalid_listener_error(error)
}

#[cfg(unix)]
fn is_invalid_listener_error(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EBADF | libc::ENOTSOCK))
}

#[cfg(windows)]
fn is_invalid_listener_error(error: &io::Error) -> bool {
    // WSAEINVAL, WSAENOTSOCK, and WSANOTINITIALISED respectively.
    matches!(error.raw_os_error(), Some(10022 | 10038 | 10093))
}

#[cfg(not(any(unix, windows)))]
fn is_invalid_listener_error(_error: &io::Error) -> bool {
    false
}

pub(crate) trait ControlServerFailureObserver: Send + Sync {
    fn failed(&self, error: Arc<ControlServerRunError>);
}

#[cfg(test)]
struct IgnoreControlServerFailure;

#[cfg(test)]
impl ControlServerFailureObserver for IgnoreControlServerFailure {
    fn failed(&self, _error: Arc<ControlServerRunError>) {}
}

async fn serve_admitted_connection(
    stream: TcpStream,
    lease: ControlConnectionLease,
    first_header_deadline: Instant,
    context: Arc<ControlServerContext>,
    mut close: watch::Receiver<ControlConnectionSignal>,
    mut abort: watch::Receiver<ControlConnectionSignal>,
) {
    let serving = async {
        if let Some(acceptor) = &context.tls {
            let mut stream =
                match tokio::time::timeout_at(first_header_deadline, acceptor.accept(stream)).await
                {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(_)) | Err(_) => return,
                };
            if stream
                .get_ref()
                .1
                .alpn_protocol()
                .is_some_and(|value| value != HTTP1_ALPN)
            {
                return;
            }
            let _ = serve_control_connection(
                &mut stream,
                lease,
                first_header_deadline,
                ControlConnectionContext {
                    router: &context.router,
                    authorization: &context.authorization,
                    readiness: &context.readiness,
                    config: &context.config,
                    shutdown: &mut close,
                },
            )
            .await;
            let _ = stream.shutdown().await;
        } else {
            let mut stream = stream;
            let _ = serve_control_connection(
                &mut stream,
                lease,
                first_header_deadline,
                ControlConnectionContext {
                    router: &context.router,
                    authorization: &context.authorization,
                    readiness: &context.readiness,
                    config: &context.config,
                    shutdown: &mut close,
                },
            )
            .await;
            let _ = stream.shutdown().await;
        }
    };
    tokio::pin!(serving);
    tokio::select! {
        biased;
        _ = wait_for_abort(&mut abort) => {}
        _ = &mut serving => {}
    }
}

async fn wait_for_abort(stop: &mut watch::Receiver<ControlConnectionSignal>) {
    if *stop.borrow() == ControlConnectionSignal::Abort {
        return;
    }
    while stop.changed().await.is_ok() {
        if *stop.borrow_and_update() == ControlConnectionSignal::Abort {
            return;
        }
    }
}

enum SupervisorExit {
    Stop(ControlStop),
    Error(Arc<ControlServerRunError>),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ControlServerError {
    #[error("control parser arena byte capacity overflowed")]
    ArenaCapacityOverflow,
    #[error(
        "control parser arena byte capacity mismatch: configured {configured}, expected {expected}"
    )]
    ArenaCapacityMismatch { configured: usize, expected: usize },
    #[error("control parser arena construction failed")]
    Arena(#[from] ControlArenaError),
    #[error("control router construction failed")]
    Router(#[from] ControlRouterError),
    #[error("control TLS identity activation failed")]
    Tls(#[from] StaticTlsIdentityError),
    #[error("no Tokio runtime is available for the control server")]
    RuntimeUnavailable,
    #[error("failed to bind control listener {address}: {source}")]
    Bind {
        address: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read the control listener address: {0}")]
    ListenerAddress(std::io::Error),
    #[error("failed to make the control listener nonblocking: {0}")]
    ListenerNonblocking(std::io::Error),
    #[error("failed to adopt the control listener: {0}")]
    ListenerAdopt(std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ControlServerRunError {
    #[error("control listener accept failed: {0}")]
    Accept(std::io::Error),
    #[error("control connection admission gate was poisoned")]
    AdmissionPoisoned,
    #[error("control connection task failed: {0}")]
    ConnectionJoin(JoinError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ControlServerShutdownError {
    #[error("control supervisor failed: {0}")]
    Supervisor(Arc<ControlServerRunError>),
    #[error("control supervisor task failed")]
    Join(#[source] JoinError),
}

impl fmt::Debug for ControlServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlServer")
            .field("local_addr", &self.local_addr)
            .field("arena_counts", &self.arena_counts())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use rcgen::{CertificateParams, KeyPair};
    use rustls::{Certificate, ClientConfig, RootCertStore, ServerName};
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Notify;
    use tokio_rustls::TlsConnector;

    use super::*;
    use crate::config::compiler::CompiledTlsIdentity;

    fn config(max_connections: usize) -> StaticControlConfig {
        StaticControlConfig {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8898),
            base_path: "/_acl-proxy".to_owned(),
            request_header_timeout: Duration::from_secs(1),
            request_body_timeout: Duration::from_secs(1),
            max_connections,
            parser_arena_bytes: max_connections * PARSER_STORE_BYTES,
            max_request_body_bytes: 64 * 1024,
            tls: None,
        }
    }

    fn prebound() -> StdTcpListener {
        StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap()
    }

    fn start(max_connections: usize) -> Arc<ControlServer> {
        start_with_config(config(max_connections))
    }

    fn start_with_config(config: StaticControlConfig) -> Arc<ControlServer> {
        ControlServer::from_prebound(
            &config,
            prebound(),
            WebhookAuthorizationRuntime::for_test(None),
            Arc::new(ServiceReadiness::new()),
            Arc::new(IgnoreControlServerFailure),
        )
        .unwrap()
    }

    fn tls_config(max_connections: usize) -> (StaticControlConfig, TempDir, Vec<u8>) {
        let directory = TempDir::new().unwrap();
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let certificate_path = directory.path().join("control-certificate.pem");
        let private_key_path = directory.path().join("control-private-key.pem");
        std::fs::write(&certificate_path, certificate.pem()).unwrap();
        std::fs::write(&private_key_path, key.serialize_pem()).unwrap();
        let mut config = config(max_connections);
        config.tls = Some(CompiledTlsIdentity {
            certificate_chain: certificate_path,
            private_key: private_key_path,
        });
        (config, directory, certificate.der().to_vec())
    }

    fn tls_connector(certificate: Vec<u8>, alpn_protocols: Vec<Vec<u8>>) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        roots.add(&Certificate(certificate)).unwrap();
        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = alpn_protocols;
        TlsConnector::from(Arc::new(config))
    }

    async fn wait_for(condition: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !condition() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("condition must become true");
    }

    fn server_with_blocked_supervisor(release: Arc<Notify>) -> Arc<ControlServer> {
        let arena = ControlParserArena::try_new(1).unwrap();
        let (stop, _) = watch::channel(ControlStop::Running);
        let handle = tokio::spawn(async move {
            release.notified().await;
            Ok(())
        });
        Arc::new(ControlServer {
            stop,
            stop_gate: Arc::new(StdMutex::new(ControlStop::Running)),
            task: AsyncMutex::new(ControlTaskState {
                handle: Some(handle),
                terminal: None,
            }),
            arena,
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            spawned_connections: Arc::new(AtomicUsize::new(0)),
        })
    }

    #[tokio::test]
    async fn prebound_test_listener_uses_ephemeral_port() {
        let server = start(2);
        assert_ne!(server.local_addr().port(), 0);
        assert_ne!(server.local_addr(), config(2).bind);

        let mut client = tokio::net::TcpStream::connect(server.local_addr())
            .await
            .unwrap();
        client
            .write_all(b"GET /_acl-proxy/ready HTTP/1.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("control response must complete")
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));

        server.close_and_join().await.unwrap();
        assert_eq!(server.arena_counts().live, 0);
    }

    #[tokio::test]
    async fn transient_accept_error_retries_and_serves_the_next_connection() {
        let config = config(1);
        let server = ControlServer::from_prebound_with_accept_errors(
            &config,
            prebound(),
            WebhookAuthorizationRuntime::for_test(None),
            Arc::new(ServiceReadiness::new()),
            [io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "injected transient accept failure",
            )],
            Arc::new(IgnoreControlServerFailure),
        )
        .unwrap();

        let mut client = tokio::net::TcpStream::connect(server.local_addr())
            .await
            .unwrap();
        client
            .write_all(b"GET /_acl-proxy/ready HTTP/1.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("the listener must recover after a transient accept error")
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
        server.close_and_join().await.unwrap();
    }

    #[tokio::test]
    async fn sustained_aborted_accepts_are_throttled_then_recover() {
        let config = config(1);
        let errors = std::iter::repeat_with(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "injected client-induced abort",
            )
        })
        .take(MAX_IMMEDIATE_ACCEPT_FAILURES_BEFORE_BACKOFF * 2);
        let server = ControlServer::from_prebound_with_accept_errors(
            &config,
            prebound(),
            WebhookAuthorizationRuntime::for_test(None),
            Arc::new(ServiceReadiness::new()),
            errors,
            Arc::new(IgnoreControlServerFailure),
        )
        .unwrap();

        let mut client = tokio::net::TcpStream::connect(server.local_addr())
            .await
            .unwrap();
        client
            .write_all(b"GET /_acl-proxy/ready HTTP/1.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("client-induced accept aborts must not terminate the listener")
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
        server.close_and_join().await.unwrap();
    }

    #[tokio::test]
    async fn one_connection_task_panic_does_not_fail_the_control_supervisor() {
        let config = config(1);
        let server = ControlServer::from_prebound_with_connection_panic(
            &config,
            prebound(),
            WebhookAuthorizationRuntime::for_test(None),
            Arc::new(ServiceReadiness::new()),
            Arc::new(IgnoreControlServerFailure),
        )
        .unwrap();

        let mut panicking = tokio::net::TcpStream::connect(server.local_addr())
            .await
            .unwrap();
        wait_for(|| server.spawned_connections() == 1).await;
        let mut trailing = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), panicking.read_to_end(&mut trailing))
            .await
            .expect("the panicking connection task must release its stream")
            .unwrap();
        assert!(trailing.is_empty());

        let mut healthy = tokio::net::TcpStream::connect(server.local_addr())
            .await
            .unwrap();
        healthy
            .write_all(b"GET /_acl-proxy/ready HTTP/1.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), healthy.read_to_end(&mut response))
            .await
            .expect("the supervisor must serve a connection after an isolated panic")
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
        server.close_and_join().await.unwrap();
    }

    #[tokio::test]
    async fn graceful_close_finishes_an_admitted_request_before_joining() {
        let server = start(1);
        let mut client = tokio::net::TcpStream::connect(server.local_addr())
            .await
            .unwrap();
        client.write_all(b"GET /_acl-proxy").await.unwrap();
        wait_for(|| server.arena_counts().live == 1).await;

        let joining_server = server.clone();
        let joining = tokio::spawn(async move { joining_server.close_and_join().await });
        tokio::task::yield_now().await;
        assert!(!joining.is_finished());

        client
            .write_all(b"/ready HTTP/1.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(response
            .windows(b"Connection: close".len())
            .any(|window| window == b"Connection: close"));
        joining.await.unwrap().unwrap();
        assert_eq!(server.arena_counts().live, 0);
    }

    #[test]
    fn accept_retry_policy_distinguishes_transient_capacity_and_fatal_errors() {
        assert_eq!(
            classify_accept_error(&io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "transient",
            )),
            AcceptErrorDisposition::RetryNow
        );
        assert_eq!(
            classify_accept_error(&io::Error::new(io::ErrorKind::InvalidInput, "fatal")),
            AcceptErrorDisposition::Fatal
        );
        assert_eq!(
            classify_accept_error(&io::Error::other("platform-specific accept failure")),
            AcceptErrorDisposition::RetryAfter(RECOVERABLE_ACCEPT_RETRY)
        );

        #[cfg(unix)]
        {
            assert_eq!(
                classify_accept_error(&io::Error::from_raw_os_error(libc::EMFILE)),
                AcceptErrorDisposition::RetryIndefinitely(RECOVERABLE_ACCEPT_RETRY)
            );
            assert_eq!(
                classify_accept_error(&io::Error::from_raw_os_error(libc::EBADF)),
                AcceptErrorDisposition::Fatal
            );
        }
    }

    #[test]
    fn persistent_backoff_accept_failures_exhaust_the_retry_budget() {
        let error = io::Error::other("persistent platform accept failure");
        let mut tracker = AcceptFailureTracker::default();
        for _ in 1..MAX_CONSECUTIVE_BACKOFF_ACCEPT_FAILURES {
            assert_eq!(
                tracker.on_error(&error),
                AcceptErrorDisposition::RetryAfter(RECOVERABLE_ACCEPT_RETRY)
            );
        }
        assert_eq!(tracker.on_error(&error), AcceptErrorDisposition::Fatal);

        tracker.on_success();
        assert_eq!(
            tracker.on_error(&error),
            AcceptErrorDisposition::RetryAfter(RECOVERABLE_ACCEPT_RETRY)
        );
    }

    #[test]
    fn persistent_immediate_accept_failures_are_throttled_without_becoming_fatal() {
        let error = io::Error::new(io::ErrorKind::ConnectionAborted, "persistent transient");
        let mut tracker = AcceptFailureTracker::default();
        for _ in 0..2 {
            for expected in 1..MAX_IMMEDIATE_ACCEPT_FAILURES_BEFORE_BACKOFF {
                assert_eq!(tracker.on_error(&error), AcceptErrorDisposition::RetryNow);
                assert_eq!(tracker.immediate_failures_since_backoff(), expected);
            }
            assert_eq!(
                tracker.on_error(&error),
                AcceptErrorDisposition::RetryAfter(TRANSIENT_ACCEPT_RETRY)
            );
            assert_eq!(tracker.immediate_failures_since_backoff(), 0);
        }

        tracker.on_success();
        assert_eq!(tracker.on_error(&error), AcceptErrorDisposition::RetryNow);
        assert_eq!(tracker.immediate_failures_since_backoff(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn resource_pressure_never_exhausts_the_accept_retry_budget() {
        let error = io::Error::from_raw_os_error(libc::EMFILE);
        let mut tracker = AcceptFailureTracker::default();
        for _ in 0..(MAX_CONSECUTIVE_BACKOFF_ACCEPT_FAILURES * 2) {
            assert_eq!(
                tracker.on_error(&error),
                AcceptErrorDisposition::RetryIndefinitely(RECOVERABLE_ACCEPT_RETRY)
            );
        }
        assert_eq!(tracker.immediate_failures_since_backoff(), 0);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn pending_network_accept_errors_never_exhaust_the_retry_budget() {
        for errno in [
            libc::ENETDOWN,
            libc::EPROTO,
            libc::ENOPROTOOPT,
            libc::EHOSTDOWN,
            libc::ENONET,
            libc::EHOSTUNREACH,
            libc::EOPNOTSUPP,
            libc::ENETUNREACH,
        ] {
            let error = io::Error::from_raw_os_error(errno);
            let mut tracker = AcceptFailureTracker::default();
            for _ in 0..(MAX_CONSECUTIVE_BACKOFF_ACCEPT_FAILURES * 2) {
                assert_eq!(
                    tracker.on_error(&error),
                    AcceptErrorDisposition::RetryIndefinitely(RECOVERABLE_ACCEPT_RETRY),
                    "errno {errno} must remain recoverable"
                );
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stop_interrupts_resource_exhaustion_accept_backoff() {
        let config = config(1);
        let server = ControlServer::from_prebound_with_accept_errors(
            &config,
            prebound(),
            WebhookAuthorizationRuntime::for_test(None),
            Arc::new(ServiceReadiness::new()),
            [io::Error::from_raw_os_error(libc::EMFILE)],
            Arc::new(IgnoreControlServerFailure),
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        tokio::time::timeout(Duration::from_millis(200), server.abort_and_join())
            .await
            .expect("stop must interrupt the one-second descriptor-pressure backoff")
            .unwrap();
    }

    #[tokio::test]
    async fn control_listener_never_spawns_before_combined_admission() {
        let server = start(1);
        let first = tokio::net::TcpStream::connect(server.local_addr())
            .await
            .unwrap();
        wait_for(|| server.arena_counts().live == 1).await;
        assert_eq!(server.spawned_connections(), 1);

        let mut second = tokio::net::TcpStream::connect(server.local_addr())
            .await
            .unwrap();
        wait_for(|| server.spawned_connections() == 1).await;
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), second.read(&mut byte));
        assert!(matches!(read.await, Ok(Ok(0))));
        assert_eq!(server.spawned_connections(), 1);

        drop(first);
        server.abort_and_join().await.unwrap();
        assert_eq!(server.arena_counts().live, 0);
        assert_eq!(server.arena_counts().available, 1);
    }

    #[tokio::test]
    async fn h2c_and_upgrade_requests_close_without_application_response() {
        for request in [
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice(),
            b"GET /_acl-proxy/ready HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                .as_slice(),
        ] {
            let server = start(1);
            let mut client = tokio::net::TcpStream::connect(server.local_addr())
                .await
                .unwrap();
            client.write_all(request).await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert!(response.is_empty());
            server.close_and_join().await.unwrap();
        }
    }

    #[tokio::test]
    async fn control_tls_accepts_only_http1_or_absent_alpn() {
        for offered in [vec![HTTP1_ALPN.to_vec()], Vec::new()] {
            let (config, _directory, certificate) = tls_config(1);
            let server = start_with_config(config);
            let stream = tokio::net::TcpStream::connect(server.local_addr())
                .await
                .unwrap();
            let mut stream = tls_connector(certificate, offered.clone())
                .connect(ServerName::try_from("localhost").unwrap(), stream)
                .await
                .unwrap();
            assert_eq!(
                stream.get_ref().1.alpn_protocol(),
                offered.first().map(Vec::as_slice)
            );
            stream
                .write_all(b"GET /_acl-proxy/ready HTTP/1.1\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
            server.close_and_join().await.unwrap();
        }
    }

    #[tokio::test]
    async fn control_tls_rejects_h2_only_client() {
        let (config, _directory, certificate) = tls_config(1);
        let server = start_with_config(config);
        let stream = tokio::net::TcpStream::connect(server.local_addr())
            .await
            .unwrap();
        let result = tls_connector(certificate, vec![b"h2".to_vec()])
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await;
        assert!(result.is_err());
        wait_for(|| server.arena_counts().live == 0).await;
        server.close_and_join().await.unwrap();
    }

    #[tokio::test]
    async fn control_tls_handshake_obeys_first_header_deadline() {
        let (mut config, _directory, _) = tls_config(1);
        config.request_header_timeout = Duration::from_millis(50);
        let server = start_with_config(config);
        let stream = tokio::net::TcpStream::connect(server.local_addr())
            .await
            .unwrap();
        wait_for(|| server.arena_counts().live == 1).await;
        tokio::time::timeout(Duration::from_millis(250), async {
            while server.arena_counts().live != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stalled TLS handshake must release its combined lease");
        drop(stream);
        server.close_and_join().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_shutdown_waiter_leaves_supervisor_joinable() {
        let release = Arc::new(Notify::new());
        let server = server_with_blocked_supervisor(release.clone());
        let joining_server = server.clone();
        let joining = tokio::spawn(async move { joining_server.close_and_join().await });
        wait_for(|| server.task.try_lock().is_err()).await;

        joining.abort();
        assert!(joining.await.unwrap_err().is_cancelled());
        {
            let state = server.task.lock().await;
            assert!(state.handle.is_some());
            assert!(state.terminal.is_none());
        }

        release.notify_one();
        server.abort_and_join().await.unwrap();
        let state = server.task.lock().await;
        assert!(state.handle.is_none());
        assert!(matches!(state.terminal, Some(Ok(()))));
    }

    #[test]
    fn parser_arena_capacity_is_rechecked_before_bind() {
        let mut invalid = config(2);
        invalid.parser_arena_bytes -= 1;
        let error = PreparedControlServer::try_new(
            &invalid,
            WebhookAuthorizationRuntime::for_test(None),
            Arc::new(ServiceReadiness::new()),
            Arc::new(IgnoreControlServerFailure),
        )
        .err()
        .expect("mismatched capacity must fail");
        assert!(matches!(
            error,
            ControlServerError::ArenaCapacityMismatch { .. }
        ));
    }
}
