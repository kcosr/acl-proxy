use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;

use http::header::HOST;
use http::StatusCode;
use hyper::body::Body;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Request, Response};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::app::{AppState, SharedAppState};
use crate::capture::{CaptureEndpoint, CaptureMode};
use crate::external_auth::ExternalDecision;
use crate::logging::PolicyDecisionLogContext;
use crate::proxy::http::{
    build_external_auth_denied_response,
    build_external_auth_error_response,
    build_external_auth_timeout_response,
    build_loop_detected_response,
    build_policy_denied_response_with_mode,
    generate_request_id,
    has_loop_header,
    proxy_allowed_request,
    send_external_auth_webhook,
};

#[derive(Debug, thiserror::Error)]
pub enum HttpsTransparentError {
    #[error("invalid HTTPS bind address {address}: {source}")]
    BindAddress {
        address: String,
        #[source]
        source: std::net::AddrParseError,
    },

    #[error("failed to bind HTTPS transparent listener on {addr}: {source}")]
    BindListener {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to create tokio listener from std listener: {0}")]
    FromStd(#[source] std::io::Error),

    #[error("TLS configuration error: {0}")]
    TlsConfig(#[from] crate::certs::CertError),

    #[error("accept error on HTTPS transparent listener: {0}")]
    Accept(#[source] std::io::Error),

    #[error("TLS handshake failed: {0}")]
    TlsHandshake(#[source] std::io::Error),

    #[error("hyper server error: {0}")]
    Hyper(#[from] hyper::Error),
}

/// Run the HTTPS transparent listener using the configured bind address/port.
///
/// This listener terminates TLS using the configured CA and per-host
/// certificates, parses decrypted HTTP/1.1 requests, applies URL policy,
/// and proxies allowed requests to upstream HTTPS servers.
pub async fn run_https_transparent_proxy<F>(
    state: SharedAppState,
    shutdown: F,
) -> Result<(), HttpsTransparentError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let initial = state.load();
    let bind_ip = initial
        .config
        .proxy
        .https_bind_address
        .parse()
        .map_err(|e| HttpsTransparentError::BindAddress {
            address: initial.config.proxy.https_bind_address.clone(),
            source: e,
        })?;
    let addr =
        SocketAddr::new(bind_ip, initial.config.proxy.https_port);

    let listener = StdTcpListener::bind(addr).map_err(|e| {
        HttpsTransparentError::BindListener { addr, source: e }
    })?;
    listener
        .set_nonblocking(true)
        .map_err(HttpsTransparentError::FromStd)?;

    run_https_transparent_proxy_on_listener(state, listener, shutdown).await
}

/// Run the HTTPS transparent proxy on an existing listener (useful for tests).
pub async fn run_https_transparent_proxy_on_listener<F>(
    state: SharedAppState,
    listener: StdTcpListener,
    shutdown: F,
) -> Result<(), HttpsTransparentError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let listener =
        TcpListener::from_std(listener).map_err(HttpsTransparentError::FromStd)?;

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                // Stop accepting new connections; in-flight TLS sessions
                // will complete naturally.
                break;
            }
            accept_res = listener.accept() => {
                let (socket, remote_addr) = match accept_res {
                    Ok(v) => v,
                    Err(e) => return Err(HttpsTransparentError::Accept(e)),
                };

                let state = state.clone();
                tokio::spawn(async move {
                    let state_snapshot = state.load_full();
                    let tls_acceptor = match state_snapshot
                        .cert_manager
                        .tls_acceptor_with_sni()
                    {
                        Ok(a) => a,
                        Err(err) => {
                            tracing::error!(
                                "failed to build TLS acceptor for HTTPS transparent proxy: {err}"
                            );
                            return;
                        }
                    };

                    if let Err(err) = handle_tls_connection(
                        state_snapshot, tls_acceptor, socket, remote_addr,
                    )
                    .await
                    {
                        tracing::debug!(
                            "HTTPS transparent connection error from {}: {err}",
                            remote_addr
                        );
                    }
                });
            }
        }
    }

    Ok(())
}

async fn handle_tls_connection(
    state: Arc<AppState>,
    tls_acceptor: TlsAcceptor,
    socket: tokio::net::TcpStream,
    remote_addr: SocketAddr,
) -> Result<(), HttpsTransparentError> {
    let tls = match tls_acceptor.accept(socket).await {
        Ok(tls) => tls,
        Err(e) => {
            let msg = e.to_string();
            let lower = msg.to_ascii_lowercase();
            if lower.contains("alpn") {
                tracing::warn!(
                    target: "acl_proxy::tls",
                    peer_addr = %remote_addr,
                    listener = "https_transparent",
                    error = %msg,
                    "TLS handshake failed during ALPN negotiation"
                );
            } else {
                tracing::debug!(
                    target: "acl_proxy::tls",
                    peer_addr = %remote_addr,
                    listener = "https_transparent",
                    error = %msg,
                    "TLS handshake failed"
                );
            }
            return Err(HttpsTransparentError::TlsHandshake(e));
        }
    };

    let (_, conn) = tls.get_ref();
    let alpn = conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).to_string());
    tracing::debug!(
        target: "acl_proxy::tls",
        peer_addr = %remote_addr,
        listener = "https_transparent",
        alpn = %alpn.as_deref().unwrap_or(""),
        "accepted TLS connection on transparent HTTPS listener"
    );

    let client_ip_for_policy = remote_addr.ip().to_string();

    let client = CaptureEndpoint {
        address: Some(remote_addr.ip().to_string()),
        port: Some(remote_addr.port()),
    };

    let state_for_svc = state.clone();
    let client_for_svc = client.clone();
    let client_ip = client_ip_for_policy.clone();

    let service = service_fn(move |req: Request<Body>| {
        let state = state_for_svc.clone();
        let client = client_for_svc.clone();
        let client_ip = client_ip.clone();
        async move {
            handle_inner_https_request(
                state,
                client,
                client_ip,
                req,
            )
            .await
        }
    });

    Http::new()
        .http1_keep_alive(true)
        .serve_connection(tls, service)
        .await
        .map_err(HttpsTransparentError::Hyper)
}

async fn handle_inner_https_request(
    state: Arc<AppState>,
    client: CaptureEndpoint,
    client_ip_for_policy: String,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    let request_id = generate_request_id();
    let method = req.method().clone();
    let version = req.version();

    let (full_url, target) = match build_https_url_for_transparent(&req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };

    // Loop protection on inbound decrypted requests.
    let loop_settings = &state.loop_protection;
    if loop_settings.enabled
        && has_loop_header(req.headers(), &loop_settings.header_name)
    {
        let resp = build_loop_detected_response(
            &state,
            &request_id,
            &full_url,
            &method,
            &client,
            target.clone(),
            version,
            req.headers(),
            CaptureMode::HttpsTransparent,
        )
        .await;
        return Ok(resp);
    }

    let decision = state.policy.evaluate(
        &full_url,
        Some(&client_ip_for_policy),
        Some(method.as_str()),
    );

    state.logging.log_policy_decision(PolicyDecisionLogContext {
        request_id: &request_id,
        url: &full_url,
        method: Some(method.as_str()),
        client_ip: Some(&client_ip_for_policy),
        decision: &decision,
    });

    if !decision.allowed {
        let resp = build_policy_denied_response_with_mode(
            &state,
            &request_id,
            &full_url,
            &method,
            &client,
            target.clone(),
            version,
            req.headers(),
            CaptureMode::HttpsTransparent,
        )
        .await;
        return Ok(resp);
    }

    let matched_rule = decision.matched.as_ref();
    let header_actions = matched_rule
        .map(|m| m.header_actions.clone())
        .unwrap_or_default();

    if let Some(rule) = matched_rule {
        if let Some(profile_name) = rule.external_auth_profile.as_ref()
        {
            if let Some(profile) =
                state.external_auth.get_profile(profile_name)
            {
                if let Some(target_endpoint) = target.clone() {
                    let resp =
                        handle_https_transparent_external_auth_gate(
                            state.clone(),
                            &request_id,
                            &full_url,
                            &method,
                            &client,
                            target_endpoint,
                            version,
                            req,
                            &client_ip_for_policy,
                            rule.index,
                            &profile,
                            profile_name,
                            header_actions,
                        )
                        .await;
                    return Ok(resp);
                } else {
                    let resp = build_external_auth_error_response(
                        &state,
                        &request_id,
                        &full_url,
                        &method,
                        &client,
                        target,
                        version,
                        req.headers(),
                        CaptureMode::HttpsTransparent,
                        "ExternalApprovalError",
                        "Missing target for transparent HTTPS request",
                    )
                    .await;
                    return Ok(resp);
                }
            } else {
                let resp = build_external_auth_error_response(
                    &state,
                    &request_id,
                    &full_url,
                    &method,
                    &client,
                    target,
                    version,
                    req.headers(),
                    CaptureMode::HttpsTransparent,
                    "ExternalApprovalError",
                    "External auth profile not found",
                )
                .await;
                return Ok(resp);
            }
        }
    }

    let resp = proxy_allowed_request(
        state.clone(),
        request_id,
        full_url,
        method,
        version,
        client,
        target,
        req,
        CaptureMode::HttpsTransparent,
        header_actions,
    )
    .await;

    Ok(resp)
}

async fn handle_https_transparent_external_auth_gate(
    state: Arc<AppState>,
    request_id: &str,
    url: &str,
    method: &http::Method,
    client: &CaptureEndpoint,
    target: CaptureEndpoint,
    version: http::Version,
    req: Request<Body>,
    client_ip_for_policy: &str,
    rule_index: usize,
    profile: &crate::external_auth::ExternalAuthProfile,
    profile_name: &str,
    header_actions: Vec<crate::policy::CompiledHeaderAction>,
) -> Response<Body> {
    let (guard, decision_rx) = state.external_auth.start_pending(
        request_id.to_string(),
        rule_index,
        None,
        profile_name.to_string(),
        url.to_string(),
        Some(method.to_string()),
        Some(client_ip_for_policy.to_string()),
    );

    let webhook_ok = send_external_auth_webhook(
        &state,
        profile,
        request_id,
        rule_index,
        profile_name,
        url,
        Some(method.as_str()),
        Some(client_ip_for_policy),
    )
    .await;

    if !webhook_ok {
        drop(guard);

        return match profile.on_webhook_failure {
            crate::external_auth::WebhookFailureMode::Deny => {
                build_external_auth_denied_response(
                    &state,
                    request_id,
                    url,
                    method,
                    client,
                    Some(target),
                    version,
                    req.headers(),
                    CaptureMode::HttpsTransparent,
                )
                .await
            }
            crate::external_auth::WebhookFailureMode::Error => {
                build_external_auth_error_response(
                    &state,
                    request_id,
                    url,
                    method,
                    client,
                    Some(target),
                    version,
                    req.headers(),
                    CaptureMode::HttpsTransparent,
                    "ExternalApprovalError",
                    "External approval webhook failed",
                )
                .await
            }
            crate::external_auth::WebhookFailureMode::Timeout => {
                build_external_auth_timeout_response(
                    &state,
                    request_id,
                    url,
                    method,
                    client,
                    Some(target),
                    version,
                    req.headers(),
                    CaptureMode::HttpsTransparent,
                )
                .await
            }
        };
    }

    let decision = tokio::time::timeout(profile.timeout, decision_rx).await;

    match decision {
        Ok(Ok(ExternalDecision::Allow)) => {
            drop(guard);
            proxy_allowed_request(
                state.clone(),
                request_id.to_string(),
                url.to_string(),
                method.clone(),
                version,
                client.clone(),
                Some(target),
                req,
                CaptureMode::HttpsTransparent,
                header_actions,
            )
            .await
        }
        Ok(Ok(ExternalDecision::Deny)) => {
            build_external_auth_denied_response(
                &state,
                request_id,
                url,
                method,
                client,
                Some(target),
                version,
                req.headers(),
                CaptureMode::HttpsTransparent,
            )
            .await
        }
        Ok(Err(_recv_closed)) => {
            build_external_auth_error_response(
                &state,
                request_id,
                url,
                method,
                client,
                Some(target),
                version,
                req.headers(),
                CaptureMode::HttpsTransparent,
                "ExternalApprovalError",
                "External approval channel closed",
            )
            .await
        }
        Err(_elapsed) => {
            build_external_auth_timeout_response(
                &state,
                request_id,
                url,
                method,
                client,
                Some(target),
                version,
                req.headers(),
                CaptureMode::HttpsTransparent,
            )
            .await
        }
    }
}

fn build_https_url_for_transparent(
    req: &Request<Body>,
) -> Result<(String, Option<CaptureEndpoint>), Response<Body>> {
    let headers = req.headers();

    let host_raw = if let Some(host_header) = headers.get(HOST) {
        match host_header.to_str() {
            Ok(h) => h.trim(),
            Err(_) => {
                let mut resp = Response::new(Body::from(
                    "Bad Request: invalid Host header",
                ));
                *resp.status_mut() = StatusCode::BAD_REQUEST;
                return Err(resp);
            }
        }
    } else if let Some(auth) = req.uri().authority() {
        auth.as_str()
    } else {
        let mut resp =
            Response::new(Body::from("Bad Request: missing Host header"));
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        return Err(resp);
    };

    if host_raw.is_empty() {
        let mut resp = Response::new(Body::from(
            "Bad Request: empty Host header",
        ));
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        return Err(resp);
    }

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let path = if path_and_query.starts_with('/') {
        path_and_query.to_string()
    } else {
        format!("/{}", path_and_query)
    };

    let full_url =
        format!("https://{host}{path}", host = host_raw, path = path);

    let (target_host, target_port) = split_host_and_port(host_raw);

    let target = CaptureEndpoint {
        address: Some(target_host.to_string()),
        port: Some(target_port),
    };

    Ok((full_url, Some(target)))
}

fn split_host_and_port(host: &str) -> (&str, u16) {
    // Bracketed IPv6: [::1]:443
    if let Some(idx) = host.rfind(']') {
        if host.starts_with('[') {
            let host_part = &host[..=idx];
            if let Some(port_str) = host[idx + 1..].strip_prefix(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    return (host_part, port);
                }
            }
            return (host_part, 443);
        }
    }

    if let Some((name, port_str)) = host.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (name, port);
        }
    }

    (host, 443)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Method, Version};
    use hyper::Body;

    #[test]
    fn builds_https_url_from_host_and_path() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/foo/bar?x=1")
            .header(HOST, "example.com")
            .body(Body::empty())
            .expect("request");

        let (url, target) =
            build_https_url_for_transparent(&req).expect("url");
        assert_eq!(url, "https://example.com/foo/bar?x=1");

        let target = target.expect("target");
        assert_eq!(target.address.as_deref(), Some("example.com"));
        assert_eq!(target.port, Some(443));
    }

    #[test]
    fn builds_https_url_from_host_with_port() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(HOST, "example.com:8443")
            .body(Body::empty())
            .expect("request");

        let (url, target) =
            build_https_url_for_transparent(&req).expect("url");
        assert_eq!(url, "https://example.com:8443/");

        let target = target.expect("target");
        assert_eq!(target.address.as_deref(), Some("example.com"));
        assert_eq!(target.port, Some(8443));
    }

    #[test]
    fn builds_https_url_from_authority_when_host_header_missing() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/foo")
            .version(Version::HTTP_2)
            .body(Body::empty())
            .expect("request");

        let (url, target) =
            build_https_url_for_transparent(&req).expect("url");
        assert_eq!(url, "https://example.com/foo");

        let target = target.expect("target");
        assert_eq!(target.address.as_deref(), Some("example.com"));
        assert_eq!(target.port, Some(443));
    }

    #[test]
    fn split_host_and_port_handles_ipv6() {
        let (host, port) = split_host_and_port("[::1]:8443");
        assert_eq!(host, "[::1]");
        assert_eq!(port, 8443);

        let (host2, port2) = split_host_and_port("[::1]");
        assert_eq!(host2, "[::1]");
        assert_eq!(port2, 443);
    }
}
