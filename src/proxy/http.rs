use std::convert::Infallible;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;

use chrono::Utc;
use http::header::{HeaderMap as HttpHeaderMap, HeaderName, HeaderValue, HOST};
use http::{Method, StatusCode, Uri, Version};
use hyper::body::{Bytes, HttpBody};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;

use crate::app::{AppState, SharedAppState};
use crate::capture::{
    build_capture_record, should_capture, BodyCaptureBuffer, BodyCaptureResult,
    CaptureDecision, CaptureEndpoint, CaptureKind, CaptureMode,
    CaptureRecordOptions, HeaderMap, DEFAULT_MAX_BODY_BYTES,
};
use crate::logging::PolicyDecisionLogContext;
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
pub async fn run_http_proxy<F>(
    state: SharedAppState,
    shutdown: F,
) -> Result<(), HttpProxyError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let initial = state.load();
    let bind_ip = initial
        .config
        .proxy
        .bind_address
        .parse()
        .map_err(|e| HttpProxyError::BindAddress {
            address: initial.config.proxy.bind_address.clone(),
            source: e,
        })?;
    let addr = SocketAddr::new(bind_ip, initial.config.proxy.http_port);

    let listener = StdTcpListener::bind(addr).map_err(|e| {
        HttpProxyError::BindListener { addr, source: e }
    })?;
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
                handle_http_request(
                    state_snapshot,
                    remote_addr,
                    req,
                )
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
        let resp = https_connect::handle_connect_request(
            state,
            remote_addr,
            req,
        )
        .await;
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
    if loop_settings.enabled
        && has_loop_header(req.headers(), &loop_settings.header_name)
    {
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
    let decision =
        policy.evaluate(&full_url, Some(&client_ip_for_policy), Some(method.as_str()));

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
    )
    .await;

    Ok(response)
}

fn build_full_url(
    req: &Request<Body>,
) -> Result<(String, Option<CaptureEndpoint>), Response<Body>> {
    let uri = req.uri();

    // Absolute-form URLs (standard HTTP proxy mode).
    if let (Some(scheme), Some(authority)) = (uri.scheme_str(), uri.authority())
    {
        let path_and_query = uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

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
    let port = authority
        .port_u16()
        .unwrap_or_else(|| if uri.scheme_str() == Some("https") { 443 } else { 80 });

    Some(CaptureEndpoint {
        address: Some(host),
        port: Some(port),
    })
}

pub(crate) fn has_loop_header(
    headers: &HttpHeaderMap,
    name: &HeaderName,
) -> bool {
    headers.contains_key(name)
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
    let body_bytes =
        serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());

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
    let body_bytes =
        serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());

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

pub(crate) async fn proxy_allowed_request(
    state: Arc<AppState>,
    request_id: String,
    full_url: String,
    method: Method,
    version: Version,
    client: CaptureEndpoint,
    target: Option<CaptureEndpoint>,
    req: Request<Body>,
    mode: CaptureMode,
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

    let mut builder = Request::builder()
        .method(method.clone())
        .uri(upstream_uri.clone())
        // Always use HTTP/1.1 for upstream
        // connections to maximize compatibility,
        // regardless of the client-facing version.
        .version(Version::HTTP_11);

    let cfg = &state.config;
    let decision = CaptureDecision::Allow;
    let capture_request =
        should_capture(cfg, decision, CaptureKind::Request);
    let capture_response =
        should_capture(cfg, decision, CaptureKind::Response);

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
            HeaderValue::from_str(authority.as_str()).unwrap_or_else(
                |_| HeaderValue::from_static(""),
            ),
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
    let upstream_resp = client_http.request(upstream_req).await;

    let upstream_resp = match upstream_resp {
        Ok(resp) => resp,
        Err(e) => {
            tracing::debug!("upstream request failed: {e}");
            let mut resp =
                Response::new(Body::from("Bad Gateway"));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            return resp;
        }
    };

    let status = upstream_resp.status();
    let resp_version = upstream_resp.version();

    let resp_headers_for_capture = if capture_response {
        Some(headers_to_capture_map(upstream_resp.headers()))
    } else {
        None
    };

    let (resp, resp_capture_rx) = if capture_response {
        let (parts, upstream_body) = upstream_resp.into_parts();
        let (body, handle) = tee_body(upstream_body).await;

        let mut out =
            Response::builder().status(status).version(resp_version);
        {
            let headers = out.headers_mut().expect("headers mut");
            for (name, value) in parts.headers.iter() {
                headers.append(name.clone(), value.clone());
            }
        }
        let resp = out
            .body(body)
            .unwrap_or_else(|_| Response::new(Body::empty()));
        (resp, Some(handle))
    } else {
        (upstream_resp, None)
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
            if should_capture(
                &cfg,
                CaptureDecision::Allow,
                CaptureKind::Request,
            ) {
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
            if should_capture(
                &cfg,
                CaptureDecision::Allow,
                CaptureKind::Response,
            ) {
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

    resp
}

pub(crate) fn headers_to_capture_map(
    headers: &HttpHeaderMap,
) -> HeaderMap {
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

pub(crate) async fn tee_body(
    mut body: Body,
) -> (Body, oneshot::Receiver<BodyCaptureResult>) {
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

    static COUNTER: Lazy<AtomicU64> =
        Lazy::new(|| AtomicU64::new(1));
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = Utc::now().timestamp_millis();
    format!("req-{}-{}", ts.to_string(), seq)
}
