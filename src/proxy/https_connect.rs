use std::net::SocketAddr;
use std::sync::Arc;

use http::header::{HeaderMap as HttpHeaderMap, HeaderValue};
use http::{Method, StatusCode, Uri, Version};
use hyper::body::Body;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Request, Response};
use tokio_rustls::TlsAcceptor;

use crate::app::AppState;
use crate::capture::{CaptureDecision, CaptureEndpoint, CaptureMode};
use crate::logging::PolicyDecisionLogContext;
use crate::proxy::http::{
    build_loop_detected_response, generate_request_id, has_loop_header,
    proxy_allowed_request, run_external_auth_gate_lifecycle,
    build_external_auth_error_response,
};

/// Handle an incoming CONNECT request on the HTTP listener.
///
/// This function performs basic validation and loop protection and, for
/// allowed requests, upgrades the connection to a TLS tunnel and runs an
/// inner HTTP/1.1 server to inspect decrypted requests.
pub async fn handle_connect_request(
    state: Arc<AppState>,
    remote_addr: SocketAddr,
    mut req: Request<Body>,
) -> Response<Body> {
    let request_id = generate_request_id();
    let version = req.version();

    let uri = req.uri().clone();
    let authority = match uri.authority() {
        Some(a) => a.clone(),
        None => {
            let mut resp =
                Response::new(Body::from("Bad Request: CONNECT target must be host:port"));
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            return resp;
        }
    };

    let host = authority.host().to_string();
    if host.is_empty() {
        let mut resp =
            Response::new(Body::from("Bad Request: missing CONNECT host"));
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        return resp;
    }
    let port = authority.port_u16().unwrap_or(443);

    let full_url = format!("https://{host}:{port}/");

    let client_endpoint = CaptureEndpoint {
        address: Some(remote_addr.ip().to_string()),
        port: Some(remote_addr.port()),
    };
    let target_endpoint = CaptureEndpoint {
        address: Some(host.clone()),
        port: Some(port),
    };

    // Loop protection on the CONNECT request itself.
    let loop_settings = &state.loop_protection;
    if loop_settings.enabled
        && has_loop_header(req.headers(), &loop_settings.header_name)
    {
        let resp = build_loop_detected_response(
            &state,
            &request_id,
            &full_url,
            &Method::CONNECT,
            &client_endpoint,
            Some(target_endpoint.clone()),
            version,
            req.headers(),
            CaptureMode::HttpsConnect,
        )
        .await;
        return resp;
    }

    // Prepare TLS acceptor for the CONNECT target host.
    let tls_acceptor = match state.cert_manager.tls_acceptor_for_host(&host)
    {
        Ok(a) => a,
        Err(err) => {
            tracing::error!(
                "failed to build TLS acceptor for {host}: {err}"
            );
            let mut resp =
                Response::new(Body::from("Internal Server Error"));
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return resp;
        }
    };

    let on_upgrade = hyper::upgrade::on(&mut req);

    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::OK;
    *resp.version_mut() = Version::HTTP_11;
    resp.headers_mut().insert(
        http::header::CONNECTION,
        HeaderValue::from_static("keep-alive"),
    );

    let state_clone = state.clone();
    let client_ep = client_endpoint.clone();
    let target_ep = target_endpoint.clone();
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                if let Err(err) = run_tls_connect_tunnel(
                    state_clone,
                    tls_acceptor,
                    upgraded,
                    client_ep,
                    target_ep,
                )
                .await
                {
                    tracing::debug!(
                        "CONNECT tunnel error for {host}:{port}: {err}"
                    );
                }
            }
            Err(err) => {
                tracing::debug!(
                    "failed to upgrade CONNECT connection: {err}"
                );
            }
        }
    });

    resp
}

#[derive(Debug, thiserror::Error)]
enum HttpsConnectError {
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(#[source] std::io::Error),

    #[error("HTTP over TLS handling failed: {0}")]
    Hyper(#[from] hyper::Error),
}

async fn run_tls_connect_tunnel(
    state: Arc<AppState>,
    tls_acceptor: TlsAcceptor,
    upgraded: hyper::upgrade::Upgraded,
    client: CaptureEndpoint,
    target: CaptureEndpoint,
) -> Result<(), HttpsConnectError> {
    let tls = match tls_acceptor.accept(upgraded).await {
        Ok(tls) => tls,
        Err(e) => {
            let msg = e.to_string();
            let lower = msg.to_ascii_lowercase();
            let client_addr = client.address.as_deref().unwrap_or("");
            let client_port = client.port.unwrap_or(0);
            if lower.contains("alpn") {
                tracing::warn!(
                    target: "acl_proxy::tls",
                    client_addr = %client_addr,
                    client_port = client_port,
                    listener = "https_connect_inner",
                    error = %msg,
                    "TLS handshake failed during ALPN negotiation"
                );
            } else {
                tracing::debug!(
                    target: "acl_proxy::tls",
                    client_addr = %client_addr,
                    client_port = client_port,
                    listener = "https_connect_inner",
                    error = %msg,
                    "TLS handshake failed"
                );
            }
            return Err(HttpsConnectError::TlsHandshake(e));
        }
    };

    let (_, conn) = tls.get_ref();
    let alpn = conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).to_string());
    tracing::debug!(
        target: "acl_proxy::tls",
        client_addr = %client.address.as_deref().unwrap_or(""),
        client_port = client.port.unwrap_or(0),
        listener = "https_connect_inner",
        alpn = %alpn.as_deref().unwrap_or(""),
        "accepted TLS connection inside CONNECT tunnel"
    );

    let client_ip_for_policy =
        client.address.clone().unwrap_or_default();

    let state_for_svc = state.clone();
    let client_for_svc = client.clone();
    let target_for_svc = target.clone();

    let service = service_fn(move |req: Request<Body>| {
        let state = state_for_svc.clone();
        let client = client_for_svc.clone();
        let target = target_for_svc.clone();
        let client_ip = client_ip_for_policy.clone();
        async move {
            handle_inner_https_request(
                state, client, target, client_ip, req,
            )
            .await
        }
    });

    Http::new()
        .http1_only(true)
        .http1_keep_alive(true)
        .serve_connection(tls, service)
        .await?;

    Ok(())
}

async fn handle_inner_https_request(
    state: Arc<AppState>,
    client: CaptureEndpoint,
    target: CaptureEndpoint,
    client_ip_for_policy: String,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    let request_id = generate_request_id();
    let method = req.method().clone();
    let version = req.version();
    let uri = req.uri().clone();

    let full_url = build_https_url_for_inner_request(&target, &uri);

    // Loop protection inside the tunnel.
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
            Some(target.clone()),
            version,
            req.headers(),
            CaptureMode::HttpsConnect,
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
        let resp = build_connect_policy_denied_response(
            &state,
            &request_id,
            &full_url,
            &method,
            &client,
            target,
            version,
            req.headers(),
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
                let resp = handle_inner_external_auth_gate(
                    state.clone(),
                    &request_id,
                    &full_url,
                    &method,
                    &client,
                    target,
                    version,
                    req,
                    &client_ip_for_policy,
                    rule.index,
                    rule.rule_id.clone(),
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
                    Some(target),
                    version,
                    req.headers(),
                    CaptureMode::HttpsConnect,
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
        Some(target),
        req,
        CaptureMode::HttpsConnect,
        header_actions,
    )
    .await;

    Ok(resp)
}

async fn handle_inner_external_auth_gate(
    state: Arc<AppState>,
    request_id: &str,
    url: &str,
    method: &Method,
    client: &CaptureEndpoint,
    target: CaptureEndpoint,
    version: Version,
    req: Request<Body>,
    client_ip_for_policy: &str,
    rule_index: usize,
    rule_id: Option<String>,
    profile: &crate::external_auth::ExternalAuthProfile,
    profile_name: &str,
    header_actions: Vec<crate::policy::CompiledHeaderAction>,
) -> Response<Body> {
    run_external_auth_gate_lifecycle(
        state,
        request_id,
        url,
        method,
        client,
        Some(target),
        version,
        req,
        client_ip_for_policy,
        rule_index,
        rule_id,
        profile,
        profile_name,
        header_actions,
        CaptureMode::HttpsConnect,
    )
    .await
}

fn build_https_url_for_inner_request(
    target: &CaptureEndpoint,
    uri: &Uri,
) -> String {
    let host = target
        .address
        .as_deref()
        .unwrap_or("unknown-host");
    let host_with_port = match target.port {
        Some(443) | None => host.to_string(),
        Some(port) => format!("{host}:{port}"),
    };
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    format!("https://{host}{path}", host = host_with_port, path = path_and_query)
}

async fn build_connect_policy_denied_response(
    state: &AppState,
    request_id: &str,
    url: &str,
    method: &Method,
    client: &CaptureEndpoint,
    target: CaptureEndpoint,
    version: Version,
    req_headers: &HttpHeaderMap,
) -> Response<Body> {
    let body_bytes = b"Blocked by URL policy".to_vec();

    let mut response = Response::new(Body::from(body_bytes.clone()));
    *response.status_mut() = StatusCode::FORBIDDEN;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );

    crate::proxy::http::maybe_capture_static_response(
        state,
        request_id,
        url,
        method,
        client,
        Some(target),
        version,
        StatusCode::FORBIDDEN,
        "Forbidden",
        &body_bytes,
        CaptureDecision::Deny,
        Some(req_headers),
        CaptureMode::HttpsConnect,
    )
    .await;

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_https_url_from_target_and_path() {
        let target = CaptureEndpoint {
            address: Some("example.com".to_string()),
            port: Some(443),
        };

        let uri: Uri = "/foo/bar?x=1".parse().expect("uri parse");
        let url = build_https_url_for_inner_request(&target, &uri);
        assert_eq!(url, "https://example.com/foo/bar?x=1");
    }

    #[test]
    fn builds_https_url_for_root_path() {
        let target = CaptureEndpoint {
            address: Some("example.com".to_string()),
            port: Some(443),
        };

        let uri: Uri = "/".parse().expect("uri parse");
        let url = build_https_url_for_inner_request(&target, &uri);
        assert_eq!(url, "https://example.com/");
    }
}
