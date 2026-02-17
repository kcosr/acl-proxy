use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::convert::Infallible;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use http::header::{HeaderMap as HttpHeaderMap, HeaderName, HeaderValue, HOST};
use http::{Method, StatusCode, Uri, Version};
use hyper::body::{Bytes, HttpBody};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server};
use tokio::io::copy_bidirectional;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;

use serde::Deserialize;

use crate::app::{AppState, SharedAppState};
use crate::auth_plugin::{AuthPluginHandle, PluginDecision};
use crate::capture::{
    build_capture_record, should_capture, BodyCaptureBuffer, BodyCaptureResult, CaptureDecision,
    CaptureEndpoint, CaptureKind, CaptureMode, CaptureRecordOptions, HeaderMap,
    DEFAULT_MAX_BODY_BYTES,
};
use crate::config::{ExternalAuthProfileType, HeaderActionKind, HeaderDirection, HeaderWhen};
use crate::external_auth::{ApprovalMacroDescriptor, ExternalAuthProfile, ExternalDecision};
use crate::logging::PolicyDecisionLogContext;
use crate::policy::CompiledHeaderAction;
use crate::proxy::https_connect;

#[derive(Debug, thiserror::Error)]
pub enum HttpProxyError {
    #[error("invalid bind address {address}: {source}")]
    BindAddress {
        address: String,
        #[source]
        source: std::net::AddrParseError,
    },

    #[error("failed to bind HTTP proxy listener on {addr}: {source}")]
    BindListener {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to build server from listener: {0}")]
    FromTcp(std::io::Error),

    #[error("hyper server error: {0}")]
    Hyper(#[from] hyper::Error),
}

/// Run the HTTP/1.1 proxy listener using the configured bind address/port.
///
/// The listener uses the shared, reloadable application state; new
/// connections observe the latest configuration snapshot, while
/// in-flight requests continue using the state captured for that
/// request.
pub async fn run_http_proxy<F>(state: SharedAppState, shutdown: F) -> Result<(), HttpProxyError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let initial = state.load();
    let bind_ip =
        initial
            .config
            .proxy
            .bind_address
            .parse()
            .map_err(|e| HttpProxyError::BindAddress {
                address: initial.config.proxy.bind_address.clone(),
                source: e,
            })?;
    let addr = SocketAddr::new(bind_ip, initial.config.proxy.http_port);

    let listener =
        StdTcpListener::bind(addr).map_err(|e| HttpProxyError::BindListener { addr, source: e })?;
    listener
        .set_nonblocking(true)
        .map_err(HttpProxyError::FromTcp)?;

    run_http_proxy_on_listener(state, listener, shutdown).await
}

/// Run the HTTP/1.1 proxy on an existing listener (useful for tests).
pub async fn run_http_proxy_on_listener<F>(
    state: SharedAppState,
    listener: StdTcpListener,
    shutdown: F,
) -> Result<(), HttpProxyError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let make_svc = make_service_fn(move |conn: &AddrStream| {
        let state = state.clone();
        let remote_addr = conn.remote_addr();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let state = state.clone();
                let state_snapshot = state.load_full();
                handle_http_request(state_snapshot, remote_addr, req)
            }))
        }
    });

    let server = Server::from_tcp(listener)
        .map_err(HttpProxyError::Hyper)?
        .serve(make_svc)
        .with_graceful_shutdown(shutdown);

    server.await.map_err(HttpProxyError::Hyper)
}

async fn handle_http_request(
    state: Arc<AppState>,
    remote_addr: SocketAddr,
    req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    // Special-case HTTPS CONNECT requests, which are handled via a dedicated
    // MITM path in `https_connect`.
    if req.method() == Method::CONNECT {
        let resp = https_connect::handle_connect_request(state, remote_addr, req).await;
        return Ok(resp);
    }

    if is_internal_endpoint(
        req.uri(),
        &state.config.proxy.internal_base_path,
        "external-auth/callback",
    ) {
        let resp = handle_external_auth_callback_request(state, req).await;
        return Ok(resp);
    }

    let request_id = generate_request_id();
    let method = req.method().clone();
    let version = req.version();
    let (full_url, target) = match build_full_url(&req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };

    let client_endpoint = CaptureEndpoint {
        address: Some(remote_addr.ip().to_string()),
        port: Some(remote_addr.port()),
    };

    let client_ip_for_policy = remote_addr.ip().to_string();
    let loop_settings = &state.loop_protection;

    // Loop protection: reject requests that already carry the loop header.
    if loop_settings.enabled && has_loop_header(req.headers(), &loop_settings.header_name) {
        let resp = build_loop_detected_response(
            &state,
            &request_id,
            &full_url,
            &method,
            &client_endpoint,
            None,
            version,
            req.headers(),
            CaptureMode::HttpProxy,
        )
        .await;
        return Ok(resp);
    }

    let policy = &state.policy;
    let decision = policy.evaluate(
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
        let resp = build_policy_denied_response(
            &state,
            &request_id,
            &full_url,
            &method,
            &client_endpoint,
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
    let request_timeout_ms = matched_rule.and_then(|m| m.request_timeout_ms);

    if let Some(rule) = matched_rule {
        if let Some(profile_name) = rule.external_auth_profile.as_ref() {
            let profile_cfg = state.config.policy.external_auth_profiles.get(profile_name);

            match profile_cfg.map(|cfg| &cfg.profile_type) {
                Some(ExternalAuthProfileType::Http) => {
                    if let Some(profile) = state.external_auth.get_profile(profile_name) {
                        let resp = handle_external_auth_gate(
                            state.clone(),
                            &request_id,
                            &full_url,
                            &method,
                            &client_endpoint,
                            target,
                            version,
                            req,
                            &client_ip_for_policy,
                            rule.index,
                            rule.rule_id.clone(),
                            &profile,
                            profile_name,
                            request_timeout_ms,
                            header_actions,
                        )
                        .await;
                        return Ok(resp);
                    }
                }
                Some(ExternalAuthProfileType::Plugin) => {
                    if let Some(handler) = state.auth_plugins.get_handler(profile_name) {
                        let resp = handle_auth_plugin_gate(
                            state.clone(),
                            &request_id,
                            &full_url,
                            &method,
                            &client_endpoint,
                            target,
                            version,
                            req,
                            &client_ip_for_policy,
                            profile_name,
                            &handler,
                            request_timeout_ms,
                            header_actions,
                        )
                        .await;
                        return Ok(resp);
                    }
                }
                None => {}
            }

            let resp = build_external_auth_error_response(
                &state,
                &request_id,
                &full_url,
                &method,
                &client_endpoint,
                target,
                version,
                req.headers(),
                CaptureMode::HttpProxy,
                "ExternalApprovalError",
                "External auth profile not found",
            )
            .await;
            return Ok(resp);
        }
    }

    let response = proxy_allowed_request(
        state.clone(),
        request_id,
        full_url,
        method,
        version,
        client_endpoint,
        target,
        req,
        CaptureMode::HttpProxy,
        request_timeout_ms,
        header_actions,
    )
    .await;

    Ok(response)
}

fn is_internal_endpoint(uri: &Uri, base: &str, suffix: &str) -> bool {
    if uri.scheme().is_some() || uri.authority().is_some() {
        return false;
    }

    let path = uri.path();
    let suffix = suffix.trim_start_matches('/');

    if base == "/" {
        return path.strip_prefix('/') == Some(suffix);
    }

    if !path.starts_with(base) {
        return false;
    }

    let remainder = &path[base.len()..];
    if !remainder.starts_with('/') {
        return false;
    }

    &remainder[1..] == suffix
}

#[derive(Debug, Deserialize)]
struct ExternalAuthCallbackBody {
    #[serde(rename = "requestId")]
    request_id: String,
    decision: ExternalAuthCallbackDecision,

    #[serde(default)]
    macros: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ExternalAuthCallbackDecision {
    Allow,
    Deny,
}

async fn handle_external_auth_callback_request(
    state: Arc<AppState>,
    req: Request<Body>,
) -> Response<Body> {
    if req.method() != Method::POST {
        let payload = serde_json::json!({
            "error": "MethodNotAllowed",
            "message": "External auth callbacks must use POST",
        });
        let body_bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());

        let mut resp = Response::new(Body::from(body_bytes));
        *resp.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        resp.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return resp;
    }

    let body_bytes = match hyper::body::to_bytes(req.into_body()).await {
        Ok(b) => b,
        Err(_) => {
            let payload = serde_json::json!({
                "error": "InvalidRequest",
                "message": "Failed to read callback body",
            });
            let body_bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
            let mut resp = Response::new(Body::from(body_bytes));
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            resp.headers_mut().insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            return resp;
        }
    };

    let payload: ExternalAuthCallbackBody = match serde_json::from_slice(&body_bytes) {
        Ok(p) => p,
        Err(_) => {
            let payload = serde_json::json!({
                "error": "InvalidRequest",
                "message": "Callback body must be valid JSON with requestId and decision",
            });
            let body_bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
            let mut resp = Response::new(Body::from(body_bytes));
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            resp.headers_mut().insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            return resp;
        }
    };

    // For allow decisions, validate and (if applicable) store approval macros
    // before delivering the decision to the pending request.
    if let ExternalAuthCallbackDecision::Allow = payload.decision {
        let descriptors_opt = state
            .external_auth
            .get_macro_descriptors(&payload.request_id);

        let descriptors = match descriptors_opt {
            Some(d) => d,
            None => {
                let payload = serde_json::json!({
                    "error": "RequestNotFound",
                    "message": "No pending request for this requestId",
                });
                let body_bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
                let mut resp = Response::new(Body::from(body_bytes));
                *resp.status_mut() = StatusCode::NOT_FOUND;
                resp.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                return resp;
            }
        };

        if !descriptors.is_empty() {
            let provided_macros = payload.macros.clone();
            if provided_macros.is_none() {
                state.external_auth.finalize_internal_error(
                    &payload.request_id,
                    "Missing macros object in approval callback",
                );
                let payload = serde_json::json!({
                    "error": "MissingMacro",
                    "message": format!(
                        "Missing required macro: {}",
                        descriptors[0].name
                    ),
                });
                let body_bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
                let mut resp = Response::new(Body::from(body_bytes));
                *resp.status_mut() = StatusCode::BAD_REQUEST;
                resp.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                return resp;
            }

            let provided = provided_macros.unwrap_or_default();
            let mut filtered: BTreeMap<String, String> = BTreeMap::new();

            for desc in &descriptors {
                match provided.get(&desc.name) {
                    Some(raw) => {
                        if raw.is_empty() {
                            if desc.required {
                                state.external_auth.finalize_internal_error(
                                    &payload.request_id,
                                    &format!("Missing required macro value: {}", desc.name),
                                );
                                let payload = serde_json::json!({
                                    "error": "MissingMacro",
                                    "message": format!(
                                        "Missing required macro: {}",
                                        desc.name
                                    ),
                                });
                                let body_bytes =
                                    serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
                                let mut resp = Response::new(Body::from(body_bytes));
                                *resp.status_mut() = StatusCode::BAD_REQUEST;
                                resp.headers_mut().insert(
                                    http::header::CONTENT_TYPE,
                                    HeaderValue::from_static("application/json"),
                                );
                                return resp;
                            }
                            // Optional macro explicitly empty -> treat as not provided.
                        } else if raw
                            .chars()
                            .any(|c| (c as u32) < 0x20 && c != '\t' || c == '\u{007f}')
                        {
                            state.external_auth.finalize_internal_error(
                                &payload.request_id,
                                &format!("Invalid macro value for {}", desc.name),
                            );
                            let payload = serde_json::json!({
                                "error": "InvalidMacroValue",
                                "message": format!(
                                    "Macro {} contains invalid characters",
                                    desc.name
                                ),
                            });
                            let body_bytes =
                                serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
                            let mut resp = Response::new(Body::from(body_bytes));
                            *resp.status_mut() = StatusCode::BAD_REQUEST;
                            resp.headers_mut().insert(
                                http::header::CONTENT_TYPE,
                                HeaderValue::from_static("application/json"),
                            );
                            return resp;
                        } else {
                            filtered.insert(desc.name.clone(), raw.clone());
                        }
                    }
                    None => {
                        if desc.required {
                            state.external_auth.finalize_internal_error(
                                &payload.request_id,
                                &format!("Missing required macro: {}", desc.name),
                            );
                            let payload = serde_json::json!({
                                "error": "MissingMacro",
                                "message": format!(
                                    "Missing required macro: {}",
                                    desc.name
                                ),
                            });
                            let body_bytes =
                                serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
                            let mut resp = Response::new(Body::from(body_bytes));
                            *resp.status_mut() = StatusCode::BAD_REQUEST;
                            resp.headers_mut().insert(
                                http::header::CONTENT_TYPE,
                                HeaderValue::from_static("application/json"),
                            );
                            return resp;
                        }
                    }
                }
            }

            // Ignore extra keys not listed in descriptors.
            state
                .external_auth
                .store_macro_values(&payload.request_id, filtered);
        }
    }

    let decision = match payload.decision {
        ExternalAuthCallbackDecision::Allow => ExternalDecision::Allow,
        ExternalAuthCallbackDecision::Deny => ExternalDecision::Deny,
    };

    let found = state.external_auth.resolve(&payload.request_id, decision);

    if !found {
        let payload = serde_json::json!({
            "error": "RequestNotFound",
            "message": "No pending request for this requestId",
        });
        let body_bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
        let mut resp = Response::new(Body::from(body_bytes));
        *resp.status_mut() = StatusCode::NOT_FOUND;
        resp.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return resp;
    }

    let payload = serde_json::json!({ "status": "ok" });
    let body_bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::new(Body::from(body_bytes));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

pub(crate) async fn run_external_auth_gate_lifecycle(
    state: Arc<AppState>,
    request_id: &str,
    url: &str,
    method: &Method,
    client: &CaptureEndpoint,
    target: Option<CaptureEndpoint>,
    version: Version,
    req: Request<Body>,
    client_ip_for_policy: &str,
    rule_index: usize,
    rule_id: Option<String>,
    profile: &ExternalAuthProfile,
    profile_name: &str,
    request_timeout_ms: Option<u64>,
    header_actions: Vec<CompiledHeaderAction>,
    mode: CaptureMode,
) -> Response<Body> {
    let macro_descriptors =
        discover_approval_macros(&state.config.policy.approval_macros, &header_actions);

    let (guard, decision_rx) = state.external_auth.start_pending(
        request_id.to_string(),
        rule_index,
        rule_id,
        profile_name.to_string(),
        url.to_string(),
        Some(method.to_string()),
        Some(client_ip_for_policy.to_string()),
        macro_descriptors,
    );

    let webhook_result = state.external_auth.send_initial_webhook(request_id).await;

    if let Err((kind, http_status)) = webhook_result {
        state
            .external_auth
            .finalize_webhook_failed(request_id, kind, http_status);

        drop(guard);

        return match profile.on_webhook_failure {
            crate::external_auth::WebhookFailureMode::Deny => {
                build_external_auth_denied_response(
                    &state,
                    request_id,
                    url,
                    method,
                    client,
                    target.clone(),
                    version,
                    req.headers(),
                    mode,
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
                    target.clone(),
                    version,
                    req.headers(),
                    mode,
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
                    target.clone(),
                    version,
                    req.headers(),
                    mode,
                )
                .await
            }
        };
    }

    let decision = tokio::time::timeout(profile.timeout, decision_rx).await;

    match decision {
        Ok(Ok(ExternalDecision::Allow)) => {
            let macro_values = state.external_auth.take_macro_values(request_id);
            let header_actions = match interpolate_header_actions(header_actions, &macro_values) {
                Ok(actions) => actions,
                Err(msg) => {
                    state
                        .external_auth
                        .finalize_internal_error(request_id, &msg);
                    drop(guard);
                    return build_external_auth_error_response(
                        &state,
                        request_id,
                        url,
                        method,
                        client,
                        target,
                        version,
                        req.headers(),
                        mode,
                        "ExternalApprovalError",
                        "External approval macro interpolation failed",
                    )
                    .await;
                }
            };
            drop(guard);
            proxy_allowed_request(
                state.clone(),
                request_id.to_string(),
                url.to_string(),
                method.clone(),
                version,
                client.clone(),
                target,
                req,
                mode,
                request_timeout_ms,
                header_actions,
            )
            .await
        }
        Ok(Ok(ExternalDecision::Deny)) => {
            drop(guard);
            build_external_auth_denied_response(
                &state,
                request_id,
                url,
                method,
                client,
                target,
                version,
                req.headers(),
                mode,
            )
            .await
        }
        Ok(Err(_recv_closed)) => {
            state
                .external_auth
                .finalize_internal_error(request_id, "External approval channel closed");
            drop(guard);
            build_external_auth_error_response(
                &state,
                request_id,
                url,
                method,
                client,
                target,
                version,
                req.headers(),
                mode,
                "ExternalApprovalError",
                "External approval channel closed",
            )
            .await
        }
        Err(_elapsed) => {
            state.external_auth.finalize_timed_out(request_id);
            drop(guard);
            build_external_auth_timeout_response(
                &state,
                request_id,
                url,
                method,
                client,
                target,
                version,
                req.headers(),
                mode,
            )
            .await
        }
    }
}

async fn handle_external_auth_gate(
    state: Arc<AppState>,
    request_id: &str,
    url: &str,
    method: &Method,
    client: &CaptureEndpoint,
    target: Option<CaptureEndpoint>,
    version: Version,
    req: Request<Body>,
    client_ip_for_policy: &str,
    rule_index: usize,
    rule_id: Option<String>,
    profile: &ExternalAuthProfile,
    profile_name: &str,
    request_timeout_ms: Option<u64>,
    header_actions: Vec<CompiledHeaderAction>,
) -> Response<Body> {
    run_external_auth_gate_lifecycle(
        state,
        request_id,
        url,
        method,
        client,
        target,
        version,
        req,
        client_ip_for_policy,
        rule_index,
        rule_id,
        profile,
        profile_name,
        request_timeout_ms,
        header_actions,
        CaptureMode::HttpProxy,
    )
    .await
}

async fn handle_auth_plugin_gate(
    state: Arc<AppState>,
    request_id: &str,
    url: &str,
    method: &Method,
    client: &CaptureEndpoint,
    target: Option<CaptureEndpoint>,
    version: Version,
    req: Request<Body>,
    client_ip_for_policy: &str,
    profile_name: &str,
    handler: &AuthPluginHandle,
    request_timeout_ms: Option<u64>,
    header_actions: Vec<CompiledHeaderAction>,
) -> Response<Body> {
    run_auth_plugin_gate_lifecycle(
        state,
        request_id,
        url,
        method,
        client,
        target,
        version,
        req,
        client_ip_for_policy,
        profile_name,
        handler,
        request_timeout_ms,
        header_actions,
        CaptureMode::HttpProxy,
    )
    .await
}

pub(crate) async fn run_auth_plugin_gate_lifecycle(
    state: Arc<AppState>,
    request_id: &str,
    url: &str,
    method: &Method,
    client: &CaptureEndpoint,
    target: Option<CaptureEndpoint>,
    version: Version,
    req: Request<Body>,
    client_ip_for_policy: &str,
    profile_name: &str,
    handler: &AuthPluginHandle,
    request_timeout_ms: Option<u64>,
    header_actions: Vec<CompiledHeaderAction>,
    mode: CaptureMode,
) -> Response<Body> {
    let decision = handler
        .evaluate(request_id, url, method, client_ip_for_policy, req.headers())
        .await;

    match decision {
        Ok(PluginDecision::Allow {
            header_actions: plugin_actions,
        }) => {
            let mut combined = header_actions;
            combined.extend(plugin_actions);
            proxy_allowed_request(
                state.clone(),
                request_id.to_string(),
                url.to_string(),
                method.clone(),
                version,
                client.clone(),
                target,
                req,
                mode,
                request_timeout_ms,
                combined,
            )
            .await
        }
        Ok(PluginDecision::Deny) => {
            build_auth_plugin_denied_response(
                &state,
                request_id,
                url,
                method,
                client,
                target,
                version,
                req.headers(),
                mode,
            )
            .await
        }
        Err(err) => {
            let message = format!("Auth plugin '{}' failed: {}", profile_name, err.message());
            build_auth_plugin_error_response(
                &state,
                request_id,
                url,
                method,
                client,
                target,
                version,
                req.headers(),
                mode,
                &message,
            )
            .await
        }
    }
}

fn build_full_url(
    req: &Request<Body>,
) -> Result<(String, Option<CaptureEndpoint>), Response<Body>> {
    let uri = req.uri();

    // Absolute-form URLs (standard HTTP proxy mode).
    if let (Some(scheme), Some(authority)) = (uri.scheme_str(), uri.authority()) {
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let normalized = if path_and_query.starts_with('/') {
            format!("{scheme}://{authority}{path}", path = path_and_query)
        } else {
            format!("{scheme}://{authority}/{path}", path = path_and_query)
        };

        let target = extract_target_from_uri(uri);
        return Ok((normalized, target));
    }

    // For now, treat non-absolute-form as a client error.
    let mut resp = Response::new(Body::from("Bad Request"));
    *resp.status_mut() = StatusCode::BAD_REQUEST;
    Err(resp)
}

fn extract_target_from_uri(uri: &Uri) -> Option<CaptureEndpoint> {
    let authority = uri.authority()?;
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or_else(|| {
        if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        }
    });

    Some(CaptureEndpoint {
        address: Some(host),
        port: Some(port),
    })
}

pub(crate) fn has_loop_header(headers: &HttpHeaderMap, name: &HeaderName) -> bool {
    headers.contains_key(name)
}

fn is_upgrade_request(headers: &HttpHeaderMap) -> bool {
    let has_upgrade_token = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));

    if !has_upgrade_token {
        return false;
    }

    headers
        .get(http::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.trim().is_empty())
}

pub(crate) async fn build_loop_detected_response(
    state: &AppState,
    request_id: &str,
    url: &str,
    method: &Method,
    client: &CaptureEndpoint,
    target: Option<CaptureEndpoint>,
    version: Version,
    req_headers: &HttpHeaderMap,
    mode: CaptureMode,
) -> Response<Body> {
    let payload = serde_json::json!({
        "error": "LoopDetected",
        "message": "Proxy loop detected via loop protection header",
    });
    let body_bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());

    let mut response = Response::new(Body::from(body_bytes.clone()));
    *response.status_mut() = StatusCode::LOOP_DETECTED;
    let headers = response.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    maybe_capture_static_response(
        state,
        request_id,
        url,
        method,
        client,
        target,
        version,
        StatusCode::LOOP_DETECTED,
        "Loop Detected",
        &body_bytes,
        CaptureDecision::Deny,
        Some(req_headers),
        mode,
    )
    .await;

    response
}

async fn build_policy_denied_response(
    state: &AppState,
    request_id: &str,
    url: &str,
    method: &Method,
    client: &CaptureEndpoint,
    version: Version,
    req_headers: &HttpHeaderMap,
) -> Response<Body> {
    build_policy_denied_response_with_mode(
        state,
        request_id,
        url,
        method,
        client,
        None,
        version,
        req_headers,
        CaptureMode::HttpProxy,
    )
    .await
}

pub(crate) async fn build_policy_denied_response_with_mode(
    state: &AppState,
    request_id: &str,
    url: &str,
    method: &Method,
    client: &CaptureEndpoint,
    target: Option<CaptureEndpoint>,
    version: Version,
    req_headers: &HttpHeaderMap,
    mode: CaptureMode,
) -> Response<Body> {
    let payload = serde_json::json!({
        "error": "Forbidden",
        "message": "Blocked by URL policy",
    });
    let body_bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());

    let mut response = Response::new(Body::from(body_bytes.clone()));
    *response.status_mut() = StatusCode::FORBIDDEN;
    let headers = response.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    maybe_capture_static_response(
        state,
        request_id,
        url,
        method,
        client,
        target,
        version,
        StatusCode::FORBIDDEN,
        "Forbidden",
        &body_bytes,
        CaptureDecision::Deny,
        Some(req_headers),
        mode,
    )
    .await;

    response
}

async fn build_external_auth_response(
    state: &AppState,
    request_id: &str,
    url: &str,
    method: &Method,
    client: &CaptureEndpoint,
    target: Option<CaptureEndpoint>,
    version: Version,
    req_headers: &HttpHeaderMap,
    mode: CaptureMode,
    status: StatusCode,
    error: &str,
    message: &str,
) -> Response<Body> {
    let payload = serde_json::json!({
        "error": error,
        "message": message,
    });
    let body_bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());

    let mut response = Response::new(Body::from(body_bytes.clone()));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    maybe_capture_static_response(
        state,
        request_id,
        url,
        method,
        client,
        target,
        version,
        status,
        message,
        &body_bytes,
        CaptureDecision::Deny,
        Some(req_headers),
        mode,
    )
    .await;

    response
}

pub(crate) async fn build_auth_plugin_denied_response(
    state: &AppState,
    request_id: &str,
    url: &str,
    method: &Method,
    client: &CaptureEndpoint,
    target: Option<CaptureEndpoint>,
    version: Version,
    req_headers: &HttpHeaderMap,
    mode: CaptureMode,
) -> Response<Body> {
    build_external_auth_response(
        state,
        request_id,
        url,
        method,
        client,
        target,
        version,
        req_headers,
        mode,
        StatusCode::FORBIDDEN,
        "Forbidden",
        "Blocked by auth plugin",
    )
    .await
}

pub(crate) async fn build_auth_plugin_error_response(
    state: &AppState,
    request_id: &str,
    url: &str,
    method: &Method,
    client: &CaptureEndpoint,
    target: Option<CaptureEndpoint>,
    version: Version,
    req_headers: &HttpHeaderMap,
    mode: CaptureMode,
    message: &str,
) -> Response<Body> {
    build_external_auth_response(
        state,
        request_id,
        url,
        method,
        client,
        target,
        version,
        req_headers,
        mode,
        StatusCode::SERVICE_UNAVAILABLE,
        "AuthPluginError",
        message,
    )
    .await
}

pub(crate) async fn build_external_auth_denied_response(
    state: &AppState,
    request_id: &str,
    url: &str,
    method: &Method,
    client: &CaptureEndpoint,
    target: Option<CaptureEndpoint>,
    version: Version,
    req_headers: &HttpHeaderMap,
    mode: CaptureMode,
) -> Response<Body> {
    build_external_auth_response(
        state,
        request_id,
        url,
        method,
        client,
        target,
        version,
        req_headers,
        mode,
        StatusCode::FORBIDDEN,
        "Forbidden",
        "Blocked by external approval",
    )
    .await
}

pub(crate) async fn build_external_auth_timeout_response(
    state: &AppState,
    request_id: &str,
    url: &str,
    method: &Method,
    client: &CaptureEndpoint,
    target: Option<CaptureEndpoint>,
    version: Version,
    req_headers: &HttpHeaderMap,
    mode: CaptureMode,
) -> Response<Body> {
    build_external_auth_response(
        state,
        request_id,
        url,
        method,
        client,
        target,
        version,
        req_headers,
        mode,
        StatusCode::GATEWAY_TIMEOUT,
        "ExternalApprovalTimeout",
        "External approval timed out",
    )
    .await
}

pub(crate) async fn build_external_auth_error_response(
    state: &AppState,
    request_id: &str,
    url: &str,
    method: &Method,
    client: &CaptureEndpoint,
    target: Option<CaptureEndpoint>,
    version: Version,
    req_headers: &HttpHeaderMap,
    mode: CaptureMode,
    error: &str,
    message: &str,
) -> Response<Body> {
    build_external_auth_response(
        state,
        request_id,
        url,
        method,
        client,
        target,
        version,
        req_headers,
        mode,
        StatusCode::SERVICE_UNAVAILABLE,
        error,
        message,
    )
    .await
}

pub(crate) async fn maybe_capture_static_response(
    state: &AppState,
    request_id: &str,
    url: &str,
    method: &Method,
    client: &CaptureEndpoint,
    target: Option<CaptureEndpoint>,
    version: Version,
    status: StatusCode,
    status_message: &str,
    body: &[u8],
    decision: CaptureDecision,
    req_headers: Option<&HttpHeaderMap>,
    mode: CaptureMode,
) {
    let cfg = &state.config;
    let decision_label = decision;

    if should_capture(cfg, decision_label, CaptureKind::Request) {
        let headers = req_headers
            .map(headers_to_capture_map)
            .unwrap_or_else(HeaderMap::new);

        let record = build_capture_record(CaptureRecordOptions {
            timestamp: Utc::now().to_rfc3339(),
            request_id: request_id.to_string(),
            kind: CaptureKind::Request,
            decision,
            mode,
            url: url.to_string(),
            method: Some(method.to_string()),
            client: client.clone(),
            target: None,
            http_version: Some(version_to_string(version)),
            headers: Some(headers),
            status_code: None,
            status_message: None,
            body: None,
        });

        let _ = crate::capture::write_capture_record(cfg, &record);
    }

    if should_capture(cfg, decision_label, CaptureKind::Response) {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type".to_string(),
            serde_json::Value::String("application/json".to_string()),
        );
        headers.insert(
            "content-length".to_string(),
            serde_json::Value::String(body.len().to_string()),
        );

        let body_capture = if body.is_empty() {
            None
        } else {
            let mut buf = BodyCaptureBuffer::new(DEFAULT_MAX_BODY_BYTES);
            buf.push(body);
            Some(buf.finish())
        };

        let record = build_capture_record(CaptureRecordOptions {
            timestamp: Utc::now().to_rfc3339(),
            request_id: request_id.to_string(),
            kind: CaptureKind::Response,
            decision,
            mode,
            url: url.to_string(),
            method: Some(method.to_string()),
            client: client.clone(),
            target,
            http_version: Some(version_to_string(version)),
            headers: Some(headers),
            status_code: Some(status.as_u16()),
            status_message: Some(status_message.to_string()),
            body: body_capture,
        });

        let _ = crate::capture::write_capture_record(cfg, &record);
    }
}

fn resolve_request_timeout_ms(
    rule_timeout_ms: Option<u64>,
    default_timeout_ms: u64,
) -> Option<Duration> {
    let timeout_ms = rule_timeout_ms.unwrap_or(default_timeout_ms);
    if timeout_ms == 0 {
        return None;
    }
    Some(Duration::from_millis(timeout_ms))
}

pub(crate) async fn proxy_allowed_request(
    state: Arc<AppState>,
    request_id: String,
    full_url: String,
    method: Method,
    version: Version,
    client: CaptureEndpoint,
    target: Option<CaptureEndpoint>,
    mut req: Request<Body>,
    mode: CaptureMode,
    request_timeout_ms: Option<u64>,
    header_actions: Vec<CompiledHeaderAction>,
) -> Response<Body> {
    let upstream_uri: Uri = match full_url.parse() {
        Ok(u) => u,
        Err(_) => {
            let mut resp = Response::new(Body::from("Bad Request"));
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            return resp;
        }
    };

    let authority = match upstream_uri.authority().cloned() {
        Some(a) => a,
        None => {
            let mut resp = Response::new(Body::from("Bad Request"));
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            return resp;
        }
    };

    let req_headers_snapshot = req.headers().clone();
    let original_request_presence = snapshot_header_presence(req.headers());
    let downstream_upgrade = if is_upgrade_request(req.headers()) {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let mut builder = Request::builder()
        .method(method.clone())
        .uri(upstream_uri.clone());

    let cfg = &state.config;
    let decision = CaptureDecision::Allow;
    let capture_request = should_capture(cfg, decision, CaptureKind::Request);
    let capture_response = should_capture(cfg, decision, CaptureKind::Response);

    let req_headers_for_capture = if capture_request {
        Some(headers_to_capture_map(req.headers()))
    } else {
        None
    };

    {
        let headers = builder.headers_mut().expect("headers mut");
        for (name, value) in req.headers().iter() {
            if name == HOST {
                continue;
            }
            headers.append(name, value.clone());
        }

        headers.insert(
            HOST,
            HeaderValue::from_str(authority.as_str())
                .unwrap_or_else(|_| HeaderValue::from_static("")),
        );

        // Loop protection header injection on outbound allowed requests.
        let loop_settings = &state.loop_protection;
        if loop_settings.enabled
            && loop_settings.add_header
            && !headers.contains_key(&loop_settings.header_name)
        {
            if let Ok(value) = HeaderValue::from_str(&request_id) {
                headers.insert(loop_settings.header_name.clone(), value);
            }
        }

        apply_header_actions(
            headers,
            &header_actions,
            HeaderDirection::Request,
            &original_request_presence,
        );
    }

    let body = req.into_body();

    let (upstream_req, req_capture_rx) = if capture_request {
        let (body, handle) = tee_body(body).await;
        let upstream_req = builder
            .body(body)
            .unwrap_or_else(|_| Request::new(Body::empty()));
        (upstream_req, Some(handle))
    } else {
        let upstream_req = builder
            .body(body)
            .unwrap_or_else(|_| Request::new(Body::empty()));
        (upstream_req, None)
    };

    let client_http: Client<_> = state.http_client.clone();
    let request_timeout =
        resolve_request_timeout_ms(request_timeout_ms, state.config.proxy.request_timeout_ms);
    let upstream_resp = match request_timeout {
        Some(timeout) => {
            match tokio::time::timeout(timeout, client_http.request(upstream_req)).await {
                Ok(resp) => resp,
                Err(_) => {
                    tracing::debug!("upstream request timed out after {:?}", timeout);
                    let body_bytes = b"Gateway Timeout".to_vec();
                    let mut resp = Response::new(Body::from(body_bytes.clone()));
                    *resp.status_mut() = StatusCode::GATEWAY_TIMEOUT;
                    maybe_capture_static_response(
                        &state,
                        &request_id,
                        &full_url,
                        &method,
                        &client,
                        target.clone(),
                        version,
                        StatusCode::GATEWAY_TIMEOUT,
                        "Gateway Timeout",
                        &body_bytes,
                        decision,
                        Some(&req_headers_snapshot),
                        mode,
                    )
                    .await;
                    return resp;
                }
            }
        }
        None => client_http.request(upstream_req).await,
    };

    let mut upstream_resp = match upstream_resp {
        Ok(resp) => resp,
        Err(e) => {
            tracing::debug!("upstream request failed: {e}");
            let body_bytes = b"Bad Gateway".to_vec();
            let mut resp = Response::new(Body::from(body_bytes.clone()));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            maybe_capture_static_response(
                &state,
                &request_id,
                &full_url,
                &method,
                &client,
                target.clone(),
                version,
                StatusCode::BAD_GATEWAY,
                "Bad Gateway",
                &body_bytes,
                decision,
                Some(&req_headers_snapshot),
                mode,
            )
            .await;
            return resp;
        }
    };

    let original_response_presence = snapshot_header_presence(upstream_resp.headers());

    let status = upstream_resp.status();
    let resp_version = upstream_resp.version();
    let upstream_upgrade =
        if downstream_upgrade.is_some() && status == StatusCode::SWITCHING_PROTOCOLS {
            Some(hyper::upgrade::on(&mut upstream_resp))
        } else {
            None
        };

    let (resp, resp_capture_rx) = if capture_response {
        let (parts, upstream_body) = upstream_resp.into_parts();
        let (body, handle) = tee_body(upstream_body).await;

        let mut out = Response::builder().status(status).version(resp_version);
        {
            let headers = out.headers_mut().expect("headers mut");
            for (name, value) in parts.headers.iter() {
                headers.append(name.clone(), value.clone());
            }
            apply_header_actions(
                headers,
                &header_actions,
                HeaderDirection::Response,
                &original_response_presence,
            );
        }
        let resp = out
            .body(body)
            .unwrap_or_else(|_| Response::new(Body::empty()));
        (resp, Some(handle))
    } else {
        apply_header_actions(
            upstream_resp.headers_mut(),
            &header_actions,
            HeaderDirection::Response,
            &original_response_presence,
        );
        (upstream_resp, None)
    };

    let resp_headers_for_capture = if capture_response {
        Some(headers_to_capture_map(resp.headers()))
    } else {
        None
    };

    tracing::debug!(
        target: "acl_proxy::http_versions",
        request_id = %request_id,
        url = %full_url,
        client_http_version = %version_to_string(version),
        upstream_http_version = %version_to_string(resp_version),
        status = %status.as_u16(),
        "proxied request completed"
    );

    // Spawn capture writing in the background so the proxy response can
    // stream back to the client without waiting on full buffering.
    let cfg = state.config.clone();
    let method_str = method.to_string();
    let url = full_url.clone();
    let client_ep = client.clone();
    let target_ep = target.clone();
    let request_id_clone = request_id.clone();
    let req_headers_for_capture_clone = req_headers_for_capture.clone();
    let resp_headers_for_capture_clone = resp_headers_for_capture.clone();
    tokio::spawn(async move {
        let req_body = match req_capture_rx {
            Some(handle) => handle.await.ok(),
            None => None,
        };
        let resp_body = match resp_capture_rx {
            Some(handle) => handle.await.ok(),
            None => None,
        };

        if let Some(body) = req_body {
            if should_capture(&cfg, CaptureDecision::Allow, CaptureKind::Request) {
                let headers = req_headers_for_capture_clone
                    .clone()
                    .unwrap_or_else(HeaderMap::new);
                let record = build_capture_record(CaptureRecordOptions {
                    timestamp: Utc::now().to_rfc3339(),
                    request_id: request_id_clone.clone(),
                    kind: CaptureKind::Request,
                    decision: CaptureDecision::Allow,
                    mode,
                    url: url.clone(),
                    method: Some(method_str.clone()),
                    client: client_ep.clone(),
                    target: target_ep.clone(),
                    http_version: Some(version_to_string(version)),
                    headers: Some(headers),
                    status_code: None,
                    status_message: None,
                    body: Some(body),
                });
                let _ = crate::capture::write_capture_record(&cfg, &record);
            }
        }

        if let Some(body) = resp_body {
            if should_capture(&cfg, CaptureDecision::Allow, CaptureKind::Response) {
                let headers = resp_headers_for_capture_clone
                    .clone()
                    .unwrap_or_else(HeaderMap::new);
                let record = build_capture_record(CaptureRecordOptions {
                    timestamp: Utc::now().to_rfc3339(),
                    request_id: request_id_clone,
                    kind: CaptureKind::Response,
                    decision: CaptureDecision::Allow,
                    mode,
                    url,
                    method: Some(method_str),
                    client: client_ep,
                    target: target_ep,
                    http_version: Some(version_to_string(resp_version)),
                    headers: Some(headers),
                    status_code: Some(status.as_u16()),
                    status_message: None,
                    body: Some(body),
                });
                let _ = crate::capture::write_capture_record(&cfg, &record);
            }
        }
    });

    if let (Some(downstream_upgrade), Some(upstream_upgrade)) =
        (downstream_upgrade, upstream_upgrade)
    {
        let request_id_for_upgrade = request_id.clone();
        let full_url_for_upgrade = full_url.clone();
        tokio::spawn(async move {
            let mut downstream = match downstream_upgrade.await {
                Ok(stream) => stream,
                Err(err) => {
                    tracing::debug!(
                        "request upgrade failed for {request_id_for_upgrade} ({full_url_for_upgrade}): {err}"
                    );
                    return;
                }
            };

            let mut upstream = match upstream_upgrade.await {
                Ok(stream) => stream,
                Err(err) => {
                    tracing::debug!(
                        "upstream upgrade failed for {request_id_for_upgrade} ({full_url_for_upgrade}): {err}"
                    );
                    return;
                }
            };

            if let Err(err) = copy_bidirectional(&mut downstream, &mut upstream).await {
                tracing::debug!(
                    "upgraded tunnel ended with I/O error for {request_id_for_upgrade} ({full_url_for_upgrade}): {err}"
                );
            }
        });
    }

    resp
}

pub(crate) fn headers_to_capture_map(headers: &HttpHeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers.iter() {
        let key = name.as_str().to_ascii_lowercase();
        if let Ok(val_str) = value.to_str() {
            use serde_json::Value;
            match out.get_mut(&key) {
                None => {
                    out.insert(key, Value::String(val_str.to_string()));
                }
                Some(Value::String(existing)) => {
                    let mut arr = vec![Value::String(existing.clone())];
                    arr.push(Value::String(val_str.to_string()));
                    *out.get_mut(&key).unwrap() = Value::Array(arr);
                }
                Some(Value::Array(arr)) => {
                    arr.push(Value::String(val_str.to_string()));
                }
                _ => {}
            }
        }
    }
    out
}

fn snapshot_header_presence(headers: &HttpHeaderMap) -> HashSet<HeaderName> {
    let mut set = HashSet::new();
    for name in headers.keys() {
        set.insert(name.clone());
    }
    set
}

fn collect_approval_macros_from_str(s: &str, out: &mut BTreeSet<String>) {
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i + 3 < chars.len() {
        if chars[i] == '{' && chars[i + 1] == '{' {
            let start = i + 2;
            let mut j = start;
            while j + 1 < chars.len() && !(chars[j] == '}' && chars[j + 1] == '}') {
                j += 1;
            }
            if j + 1 >= chars.len() {
                break;
            }
            let inner: String = chars[start..j].iter().collect();
            if !inner.is_empty() && inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                out.insert(inner);
            }
            i = j + 2;
        } else {
            i += 1;
        }
    }
}

fn discover_approval_macros(
    macro_cfg: &crate::config::ApprovalMacroConfigMap,
    header_actions: &[CompiledHeaderAction],
) -> Vec<ApprovalMacroDescriptor> {
    let mut names = BTreeSet::new();

    for action in header_actions {
        match action.action {
            HeaderActionKind::Set | HeaderActionKind::Add => {
                for v in &action.values {
                    if let Ok(s) = v.to_str() {
                        collect_approval_macros_from_str(s, &mut names);
                    }
                }
            }
            _ => {}
        }
    }

    let mut descriptors = Vec::new();

    for name in names {
        let cfg = macro_cfg.get(&name);
        let label = cfg
            .and_then(|c| c.label.clone())
            .unwrap_or_else(|| name.clone());
        let required = cfg.map(|c| c.required).unwrap_or(true);
        let secret = cfg.map(|c| c.secret).unwrap_or(false);

        descriptors.push(ApprovalMacroDescriptor {
            name,
            label,
            required,
            secret,
        });
    }

    descriptors
}

fn interpolate_approval_macros(template: &str, values: &BTreeMap<String, String>) -> String {
    let chars: Vec<char> = template.chars().collect();
    let mut out = String::with_capacity(template.len());
    let mut i = 0;

    while i + 3 < chars.len() {
        if chars[i] == '{' && chars[i + 1] == '{' {
            let start = i + 2;
            let mut j = start;
            while j + 1 < chars.len() && !(chars[j] == '}' && chars[j + 1] == '}') {
                j += 1;
            }
            if j + 1 >= chars.len() {
                out.extend(chars[i..].iter());
                return out;
            }
            let inner: String = chars[start..j].iter().collect();
            if !inner.is_empty() && inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                if let Some(val) = values.get(&inner) {
                    out.push_str(val);
                }
            } else {
                out.extend(chars[i..=j + 1].iter());
            }
            i = j + 2;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }

    while i < chars.len() {
        out.push(chars[i]);
        i += 1;
    }

    out
}

fn interpolate_header_actions(
    header_actions: Vec<CompiledHeaderAction>,
    macro_values: &BTreeMap<String, String>,
) -> Result<Vec<CompiledHeaderAction>, String> {
    if macro_values.is_empty() {
        return Ok(header_actions);
    }

    let mut out = Vec::with_capacity(header_actions.len());

    for mut action in header_actions.into_iter() {
        match action.action {
            HeaderActionKind::Set | HeaderActionKind::Add => {
                let mut new_values = Vec::with_capacity(action.values.len());

                for hv in &action.values {
                    let original = match hv.to_str() {
                        Ok(s) => s,
                        Err(_) => {
                            new_values.push(hv.clone());
                            continue;
                        }
                    };
                    let interpolated = interpolate_approval_macros(original, macro_values);
                    match HeaderValue::from_str(&interpolated) {
                        Ok(parsed) => new_values.push(parsed),
                        Err(e) => {
                            tracing::debug!(
                                "invalid header value after macro interpolation for {}: {} ({})",
                                action.name,
                                interpolated,
                                e
                            );
                            return Err(format!(
                                "invalid header value after macro interpolation for {}",
                                action.name
                            ));
                        }
                    }
                }

                action.values = new_values;
                out.push(action);
            }
            _ => {
                out.push(action);
            }
        }
    }

    Ok(out)
}

fn apply_header_actions(
    headers: &mut HttpHeaderMap,
    actions: &[CompiledHeaderAction],
    direction: HeaderDirection,
    original_present: &HashSet<HeaderName>,
) {
    for action in actions {
        let applies_to_direction = match (&action.direction, &direction) {
            (HeaderDirection::Request, HeaderDirection::Request) => true,
            (HeaderDirection::Response, HeaderDirection::Response) => true,
            (HeaderDirection::Both, _) => true,
            _ => false,
        };
        if !applies_to_direction {
            continue;
        }

        let present_originally = original_present.contains(&action.name);
        let should_run = match action.when {
            HeaderWhen::Always => true,
            HeaderWhen::IfPresent => present_originally,
            HeaderWhen::IfAbsent => !present_originally,
        };
        if !should_run {
            continue;
        }

        match action.action {
            HeaderActionKind::Remove => {
                headers.remove(&action.name);
                log_header_action(action, &direction);
            }
            HeaderActionKind::Set => {
                headers.remove(&action.name);
                for v in &action.values {
                    headers.append(action.name.clone(), v.clone());
                }
                log_header_action(action, &direction);
            }
            HeaderActionKind::Add => {
                for v in &action.values {
                    headers.append(action.name.clone(), v.clone());
                }
                log_header_action(action, &direction);
            }
            HeaderActionKind::ReplaceSubstring => {
                let mut new_values = Vec::new();
                let all = headers.get_all(&action.name);

                let search = match &action.search {
                    Some(s) => s,
                    None => continue,
                };
                let replace = action.replace.as_deref().unwrap_or("");

                for val in all.iter() {
                    let s = match val.to_str() {
                        Ok(s) => s,
                        Err(_) => {
                            tracing::debug!(
                                "skipping non-UTF8 header value for {} in replace_substring",
                                action.name
                            );
                            continue;
                        }
                    };
                    let replaced = s.replace(search, replace);
                    match HeaderValue::from_str(&replaced) {
                        Ok(hv) => new_values.push(hv),
                        Err(e) => {
                            tracing::debug!(
                                "skipping invalid mutated header value for {} in replace_substring: {}",
                                action.name,
                                e
                            );
                        }
                    }
                }

                if !new_values.is_empty() {
                    headers.remove(&action.name);
                    for v in new_values {
                        headers.append(action.name.clone(), v);
                    }
                    log_header_action(action, &direction);
                }
            }
        }
    }
}

fn log_header_action(action: &CompiledHeaderAction, direction: &HeaderDirection) {
    let dir_str = match direction {
        HeaderDirection::Request => "request",
        HeaderDirection::Response => "response",
        HeaderDirection::Both => "both",
    };
    tracing::debug!(
        "applied header action {:?} on {} (direction={}, when={:?})",
        action.action,
        action.name,
        dir_str,
        action.when,
    );
}

pub(crate) async fn tee_body(mut body: Body) -> (Body, oneshot::Receiver<BodyCaptureResult>) {
    let (tx, rx) = mpsc::channel::<Result<Bytes, hyper::Error>>(16);
    let (capture_tx, capture_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut buf = BodyCaptureBuffer::new(DEFAULT_MAX_BODY_BYTES);
        while let Some(chunk) = body.data().await {
            match chunk {
                Ok(bytes) => {
                    buf.push(&bytes);
                    if tx.send(Ok(bytes)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    break;
                }
            }
        }
        let _ = capture_tx.send(buf.finish());
    });

    let stream = ReceiverStream::new(rx);
    let new_body = Body::wrap_stream(stream);
    (new_body, capture_rx)
}

pub(crate) fn version_to_string(version: Version) -> String {
    match version {
        Version::HTTP_09 => "0.9".to_string(),
        Version::HTTP_10 => "1.0".to_string(),
        Version::HTTP_11 => "1.1".to_string(),
        Version::HTTP_2 => "2".to_string(),
        Version::HTTP_3 => "3".to_string(),
        _ => "1.1".to_string(),
    }
}

pub(crate) fn generate_request_id() -> String {
    use once_cell::sync::Lazy;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::{process, time::Duration};

    static COUNTER: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(1));
    static PROCESS_TAG: Lazy<String> = Lazy::new(|| {
        let pid = process::id();
        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_nanos();
        format!("{pid:x}_{started:x}")
    });
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = Utc::now().timestamp_millis();
    format!("req-{}-{}-{}", PROCESS_TAG.as_str(), ts, seq)
}

#[cfg(test)]
mod tests {
    use super::{generate_request_id, is_internal_endpoint, is_upgrade_request};
    use http::{header, HeaderMap, HeaderValue, Uri};

    #[test]
    fn request_id_includes_process_tag_and_is_unique() {
        let first = generate_request_id();
        let second = generate_request_id();
        assert_ne!(first, second);

        let mut parts = first.splitn(4, '-');
        assert_eq!(parts.next(), Some("req"));
        let tag = parts.next().unwrap_or("");
        assert!(
            tag.contains('_'),
            "process tag should include an underscore separator"
        );
        assert!(parts.next().unwrap_or("").parse::<i64>().is_ok());
        assert!(!parts.next().unwrap_or("").is_empty());
    }

    #[test]
    fn internal_endpoint_requires_origin_form_and_base_path() {
        let uri: Uri = "/_acl-proxy/external-auth/callback"
            .parse()
            .expect("parse uri");
        assert!(is_internal_endpoint(
            &uri,
            "/_acl-proxy",
            "external-auth/callback"
        ));

        let uri: Uri = "http://example.com/_acl-proxy/external-auth/callback"
            .parse()
            .expect("parse uri");
        assert!(!is_internal_endpoint(
            &uri,
            "/_acl-proxy",
            "external-auth/callback"
        ));

        let uri: Uri = "/internal/external-auth/callback"
            .parse()
            .expect("parse uri");
        assert!(is_internal_endpoint(
            &uri,
            "/internal",
            "external-auth/callback"
        ));

        let uri: Uri = "/_acl-proxy/external-auth/callback"
            .parse()
            .expect("parse uri");
        assert!(!is_internal_endpoint(
            &uri,
            "/internal",
            "external-auth/callback"
        ));
    }

    #[test]
    fn upgrade_detection_requires_connection_token_and_upgrade_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, Upgrade"),
        );
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        assert!(is_upgrade_request(&headers));

        let mut missing_connection = HeaderMap::new();
        missing_connection.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        assert!(!is_upgrade_request(&missing_connection));

        let mut missing_upgrade = HeaderMap::new();
        missing_upgrade.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        assert!(!is_upgrade_request(&missing_upgrade));
    }
}
