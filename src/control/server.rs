use std::fmt;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex as StdMutex};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

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
use super::connection::serve_control_connection;
use super::router::{ControlRouter, ControlRouterError};

const HTTP1_ALPN: &[u8] = b"http/1.1";

pub(crate) struct ControlServer {
    stop: watch::Sender<ControlStop>,
    stop_gate: Arc<StdMutex<ControlStop>>,
    task: AsyncMutex<ControlTaskState>,
    failure: watch::Receiver<Option<Arc<ControlServerRunError>>>,
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
    ) -> Result<Arc<Self>, ControlServerError> {
        let prepared = PreparedControlServer::try_new(config, authorization, readiness)?;
        let listener =
            StdTcpListener::bind(config.bind).map_err(|source| ControlServerError::Bind {
                address: config.bind,
                source,
            })?;
        Self::start(prepared, listener)
    }

    #[cfg(test)]
    pub(crate) fn from_prebound(
        config: &StaticControlConfig,
        listener: StdTcpListener,
        authorization: Arc<WebhookAuthorizationRuntime>,
        readiness: Arc<ServiceReadiness>,
    ) -> Result<Arc<Self>, ControlServerError> {
        let prepared = PreparedControlServer::try_new(config, authorization, readiness)?;
        Self::start(prepared, listener)
    }

    fn start(
        prepared: PreparedControlServer,
        listener: StdTcpListener,
    ) -> Result<Arc<Self>, ControlServerError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| ControlServerError::RuntimeUnavailable)?;
        let local_addr = listener
            .local_addr()
            .map_err(ControlServerError::ListenerAddress)?;
        listener
            .set_nonblocking(true)
            .map_err(ControlServerError::ListenerNonblocking)?;
        let listener =
            TcpListener::from_std(listener).map_err(ControlServerError::ListenerAdopt)?;
        let arena = prepared.context.arena.clone();
        let (stop, stop_rx) = watch::channel(ControlStop::Running);
        let stop_gate = Arc::new(StdMutex::new(ControlStop::Running));
        let (failure_tx, failure) = watch::channel(None);
        #[cfg(test)]
        let spawned_connections = Arc::new(AtomicUsize::new(0));
        #[cfg(test)]
        let task_spawned_connections = spawned_connections.clone();
        let task = runtime.spawn(run_control_supervisor(
            listener,
            prepared.context,
            stop_rx,
            stop_gate.clone(),
            failure_tx,
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
            failure,
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

    pub(crate) fn failure(&self) -> Option<Arc<ControlServerRunError>> {
        self.failure.borrow().clone()
    }

    pub(crate) async fn wait_for_failure(&self) -> Option<Arc<ControlServerRunError>> {
        let mut failure = self.failure.clone();
        loop {
            if let Some(error) = failure.borrow().clone() {
                return Some(error);
            }
            if failure.changed().await.is_err() {
                return failure.borrow().clone();
            }
        }
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
                config: config.clone(),
                tls,
            }),
        })
    }
}

struct ControlServerContext {
    arena: ControlParserArena,
    router: ControlRouter,
    authorization: Arc<WebhookAuthorizationRuntime>,
    readiness: Arc<ServiceReadiness>,
    config: StaticControlConfig,
    tls: Option<TlsAcceptor>,
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
    listener: TcpListener,
    context: Arc<ControlServerContext>,
    mut stop: watch::Receiver<ControlStop>,
    stop_gate: Arc<StdMutex<ControlStop>>,
    failure: watch::Sender<Option<Arc<ControlServerRunError>>>,
    #[cfg(test)] spawned_connections: Arc<AtomicUsize>,
) -> Result<(), Arc<ControlServerRunError>> {
    let mut connections = JoinSet::new();
    let (connection_stop, _) = watch::channel(false);
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
                    Err(error) => break SupervisorExit::Error(Arc::new(ControlServerRunError::Accept(error))),
                };
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
                let connection_stop = connection_stop.subscribe();
                connections.spawn(async move {
                    serve_admitted_connection(
                        stream,
                        lease,
                        first_header_deadline,
                        context,
                        connection_stop,
                    ).await;
                });
                drop(gate);
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    break SupervisorExit::Error(Arc::new(ControlServerRunError::ConnectionJoin(error)));
                }
            }
        }
    };

    let _ = connection_stop.send(true);
    let abort = matches!(
        exit,
        SupervisorExit::Error(_) | SupervisorExit::Stop(ControlStop::AbortAndJoin)
    );
    if abort {
        connections.abort_all();
    }
    let mut cleanup_error = None;
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            if !error.is_cancelled() && cleanup_error.is_none() {
                cleanup_error = Some(Arc::new(ControlServerRunError::ConnectionJoin(error)));
            }
        }
    }

    let result = match exit {
        SupervisorExit::Error(error) => Err(error),
        SupervisorExit::Stop(_) => cleanup_error.map_or(Ok(()), Err),
    };
    if let Err(error) = &result {
        context.readiness.begin_shutdown();
        let _ = failure.send(Some(error.clone()));
    }
    result
}

async fn serve_admitted_connection(
    stream: TcpStream,
    lease: ControlConnectionLease,
    first_header_deadline: Instant,
    context: Arc<ControlServerContext>,
    mut stop: watch::Receiver<bool>,
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
                &context.router,
                &context.authorization,
                &context.readiness,
                &context.config,
            )
            .await;
            let _ = stream.shutdown().await;
        } else {
            let mut stream = stream;
            let _ = serve_control_connection(
                &mut stream,
                lease,
                first_header_deadline,
                &context.router,
                &context.authorization,
                &context.readiness,
                &context.config,
            )
            .await;
            let _ = stream.shutdown().await;
        }
    };
    tokio::pin!(serving);
    tokio::select! {
        biased;
        _ = wait_for_stop(&mut stop) => {}
        _ = &mut serving => {}
    }
}

async fn wait_for_stop(stop: &mut watch::Receiver<bool>) {
    if *stop.borrow() {
        return;
    }
    while stop.changed().await.is_ok() {
        if *stop.borrow_and_update() {
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
        let (_, failure) = watch::channel(None);
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
            failure,
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
        )
        .err()
        .expect("mismatched capacity must fail");
        assert!(matches!(
            error,
            ControlServerError::ArenaCapacityMismatch { .. }
        ));
    }
}
