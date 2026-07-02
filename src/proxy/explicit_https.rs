use std::io::BufReader;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::Body;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::Request;
use rustls::{Certificate, PrivateKey, ServerConfig};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::app::SharedAppState;
use crate::config::{parse_listener_bind, ExplicitHttpsListenerConfig};
use crate::proxy::http::{handle_http_request, HttpListenerMode};

#[derive(Debug, thiserror::Error)]
pub enum ExplicitHttpsError {
    #[error("invalid explicit HTTPS bind address {address}: {message}")]
    BindAddress { address: String, message: String },

    #[error("failed to bind explicit HTTPS listener on {addr}: {source}")]
    BindListener {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to create tokio listener from std listener: {0}")]
    FromStd(#[source] std::io::Error),

    #[error("explicit HTTPS TLS configuration error: {0}")]
    TlsConfig(String),

    #[error("accept error on explicit HTTPS listener: {0}")]
    Accept(#[source] std::io::Error),

    #[error("TLS handshake failed: {0}")]
    TlsHandshake(#[source] std::io::Error),

    #[error("TLS handshake timed out after {timeout_ms}ms")]
    TlsHandshakeTimeout { timeout_ms: u64 },

    #[error("hyper server error: {0}")]
    Hyper(#[from] hyper::Error),
}

#[derive(Clone, Copy, Debug)]
struct ExplicitHttpsConnectionLimits {
    handshake_timeout: Option<Duration>,
    handshake_timeout_ms: u64,
    request_header_timeout: Option<Duration>,
    http2_max_concurrent_streams: Option<u32>,
    enable_http2: bool,
}

impl ExplicitHttpsConnectionLimits {
    fn from_config(config: &ExplicitHttpsListenerConfig) -> Self {
        Self {
            handshake_timeout: duration_from_millis(config.handshake_timeout_ms),
            handshake_timeout_ms: config.handshake_timeout_ms,
            request_header_timeout: duration_from_millis(config.request_header_timeout_ms),
            http2_max_concurrent_streams: nonzero_u32(config.http2_max_concurrent_streams),
            enable_http2: config.enable_http2,
        }
    }
}

fn duration_from_millis(value: u64) -> Option<Duration> {
    if value == 0 {
        None
    } else {
        Some(Duration::from_millis(value))
    }
}

fn nonzero_u32(value: u32) -> Option<u32> {
    if value == 0 {
        None
    } else {
        Some(value)
    }
}

pub async fn run_explicit_https_proxy<F>(
    state: SharedAppState,
    shutdown: F,
) -> Result<(), ExplicitHttpsError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let initial = state.load();
    let listener_cfg = initial
        .config
        .proxy
        .listeners
        .explicit_https
        .as_ref()
        .expect("explicit_https listener must be configured before startup")
        .clone();

    let addr = parse_listener_bind("proxy.listeners.explicit_https.bind", &listener_cfg.bind)
        .map_err(|err| ExplicitHttpsError::BindAddress {
            address: listener_cfg.bind.clone(),
            message: err.to_string(),
        })?;

    let tls_acceptor = build_static_tls_acceptor(&listener_cfg)?;
    let listener = StdTcpListener::bind(addr)
        .map_err(|e| ExplicitHttpsError::BindListener { addr, source: e })?;
    listener
        .set_nonblocking(true)
        .map_err(ExplicitHttpsError::FromStd)?;

    run_explicit_https_proxy_on_listener(state, listener, tls_acceptor, listener_cfg, shutdown)
        .await
}

pub async fn run_explicit_https_proxy_on_listener<F>(
    state: SharedAppState,
    listener: StdTcpListener,
    tls_acceptor: TlsAcceptor,
    listener_cfg: ExplicitHttpsListenerConfig,
    shutdown: F,
) -> Result<(), ExplicitHttpsError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::from_std(listener).map_err(ExplicitHttpsError::FromStd)?;
    let connection_limit = listener_cfg.max_connections;
    let connection_semaphore = if connection_limit == 0 {
        None
    } else {
        Some(Arc::new(Semaphore::new(connection_limit)))
    };
    let limits = ExplicitHttpsConnectionLimits::from_config(&listener_cfg);
    let mut connections = JoinSet::new();

    tokio::pin!(shutdown);

    loop {
        let connection_permit = match connection_semaphore.as_ref() {
            Some(semaphore) => {
                let semaphore = semaphore.clone();
                match tokio::select! {
                    _ = &mut shutdown => {
                        break;
                    }
                    permit = semaphore.acquire_owned() => permit,
                } {
                    Ok(permit) => Some(permit),
                    Err(_) => break,
                }
            }
            None => None,
        };

        tokio::select! {
            _ = &mut shutdown => {
                break;
            }
            accept_res = listener.accept() => {
                let (socket, remote_addr) = match accept_res {
                    Ok(v) => v,
                    Err(e) => {
                        crate::proxy::listener::handle_accept_error("explicit_https", e).await;
                        continue;
                    }
                };

                let state = state.clone();
                let tls_acceptor = tls_acceptor.clone();
                connections.spawn(async move {
                    if let Err(err) =
                        handle_tls_connection(state, tls_acceptor, socket, remote_addr, limits).await
                    {
                        tracing::debug!(
                            "explicit HTTPS connection error from {}: {err}",
                            remote_addr
                        );
                    }
                    drop(connection_permit);
                });
            }
        }
    }

    while let Some(join_result) = connections.join_next().await {
        if let Err(err) = join_result {
            tracing::debug!("explicit HTTPS listener connection task failed: {err}");
        }
    }

    Ok(())
}

async fn handle_tls_connection(
    state: SharedAppState,
    tls_acceptor: TlsAcceptor,
    socket: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    limits: ExplicitHttpsConnectionLimits,
) -> Result<(), ExplicitHttpsError> {
    let accept = tls_acceptor.accept(socket);
    let tls_result = match limits.handshake_timeout {
        Some(timeout) => match tokio::time::timeout(timeout, accept).await {
            Ok(result) => result,
            Err(_) => {
                tracing::debug!(
                    target: "acl_proxy::tls",
                    peer_addr = %remote_addr,
                    listener = "explicit_https",
                    timeout_ms = limits.handshake_timeout_ms,
                    "TLS handshake timed out"
                );
                return Err(ExplicitHttpsError::TlsHandshakeTimeout {
                    timeout_ms: limits.handshake_timeout_ms,
                });
            }
        },
        None => accept.await,
    };

    let tls = match tls_result {
        Ok(tls) => tls,
        Err(e) => {
            tracing::debug!(
                target: "acl_proxy::tls",
                peer_addr = %remote_addr,
                listener = "explicit_https",
                error = %e,
                "TLS handshake failed"
            );
            return Err(ExplicitHttpsError::TlsHandshake(e));
        }
    };

    let (_, conn) = tls.get_ref();
    let alpn = conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).to_string());
    tracing::debug!(
        target: "acl_proxy::tls",
        peer_addr = %remote_addr,
        listener = "explicit_https",
        alpn = %alpn.as_deref().unwrap_or(""),
        "accepted TLS connection on explicit HTTPS listener"
    );

    let service = service_fn(move |req: Request<Body>| {
        let state = state.load_full();
        handle_http_request(state, remote_addr, HttpListenerMode::Explicit, req)
    });

    let mut http = Http::new();
    http.http1_keep_alive(true);
    if limits.enable_http2 {
        http.http2_max_concurrent_streams(limits.http2_max_concurrent_streams);
    } else {
        http.http1_only(true);
    }
    if let Some(timeout) = limits.request_header_timeout {
        http.http1_header_read_timeout(timeout);
        if limits.enable_http2 {
            http.http2_keep_alive_interval(timeout);
            http.http2_keep_alive_timeout(timeout);
        }
    }

    http.serve_connection(tls, service)
        .with_upgrades()
        .await
        .map_err(ExplicitHttpsError::Hyper)
}

pub fn build_static_tls_acceptor(
    config: &ExplicitHttpsListenerConfig,
) -> Result<TlsAcceptor, ExplicitHttpsError> {
    let certs = load_pem_certs(&config.cert_chain_path)?;
    let key = load_private_key(&config.key_path)?;
    let mut server = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| ExplicitHttpsError::TlsConfig(err.to_string()))?;

    server.alpn_protocols = if config.enable_http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };

    Ok(TlsAcceptor::from(Arc::new(server)))
}

fn load_pem_certs(path: &Path) -> Result<Vec<Certificate>, ExplicitHttpsError> {
    let file = std::fs::File::open(path).map_err(|err| {
        ExplicitHttpsError::TlsConfig(format!(
            "failed to read cert_chain_path {}: {err}",
            path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).map_err(|err| {
        ExplicitHttpsError::TlsConfig(format!(
            "cert_chain_path {} must contain valid PEM certificates: {err}",
            path.display()
        ))
    })?;
    if certs.is_empty() {
        return Err(ExplicitHttpsError::TlsConfig(format!(
            "cert_chain_path {} must contain at least one PEM certificate",
            path.display()
        )));
    }
    Ok(certs.into_iter().map(Certificate).collect())
}

fn load_private_key(path: &Path) -> Result<PrivateKey, ExplicitHttpsError> {
    for loader in [
        rustls_pemfile::pkcs8_private_keys
            as fn(&mut dyn std::io::BufRead) -> Result<Vec<Vec<u8>>, std::io::Error>,
        rustls_pemfile::rsa_private_keys
            as fn(&mut dyn std::io::BufRead) -> Result<Vec<Vec<u8>>, std::io::Error>,
        rustls_pemfile::ec_private_keys
            as fn(&mut dyn std::io::BufRead) -> Result<Vec<Vec<u8>>, std::io::Error>,
    ] {
        let file = std::fs::File::open(path).map_err(|err| {
            ExplicitHttpsError::TlsConfig(format!(
                "failed to read key_path {}: {err}",
                path.display()
            ))
        })?;
        let mut reader = BufReader::new(file);
        let mut keys = loader(&mut reader).map_err(|err| {
            ExplicitHttpsError::TlsConfig(format!(
                "key_path {} must contain a valid PEM private key: {err}",
                path.display()
            ))
        })?;
        if !keys.is_empty() {
            return Ok(PrivateKey(keys.remove(0)));
        }
    }

    Err(ExplicitHttpsError::TlsConfig(format!(
        "key_path {} must contain a supported PEM private key",
        path.display()
    )))
}
