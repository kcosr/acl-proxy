use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use dashmap::DashMap;
use http::{header::HeaderValue, Method, StatusCode};
use hyper::client::HttpConnector;
use hyper::{Body, Client, Request};
use hyper_rustls::HttpsConnector;
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};

use crate::config::{
    ExternalAuthProfileConfig, ExternalAuthProfileConfigMap, ExternalAuthProfileType,
    ExternalAuthWebhookFailureMode,
};

#[derive(Debug, Clone)]
pub enum ExternalDecision {
    Allow,
    Deny,
}

/// Behavior to apply when the **initial** webhook fails.
#[derive(Debug, Clone, Copy)]
pub enum WebhookFailureMode {
    Deny,
    Error,
    Timeout,
}

impl WebhookFailureMode {
    fn from_config(mode: Option<ExternalAuthWebhookFailureMode>) -> Self {
        match mode.unwrap_or(ExternalAuthWebhookFailureMode::Error) {
            ExternalAuthWebhookFailureMode::Deny => WebhookFailureMode::Deny,
            ExternalAuthWebhookFailureMode::Error => WebhookFailureMode::Error,
            ExternalAuthWebhookFailureMode::Timeout => WebhookFailureMode::Timeout,
        }
    }
}

/// High-level classification of initial webhook delivery failures.
#[derive(Debug, Clone, Copy)]
pub enum WebhookFailureKind {
    Timeout,
    Non2xx,
    Transport,
}

#[derive(Debug, Clone)]
pub struct ExternalAuthProfile {
    pub webhook_url: String,
    pub timeout: Duration,
    pub webhook_timeout: Option<Duration>,
    pub on_webhook_failure: WebhookFailureMode,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalMacroDescriptor {
    pub name: String,
    pub label: String,
    pub required: bool,
    pub secret: bool,
}

#[derive(Debug)]
pub struct PendingRequest {
    pub rule_index: usize,
    pub rule_id: Option<String>,
    pub profile_name: String,
    pub created_at: Instant,
    pub deadline_at: Instant,
    pub decision_tx: oneshot::Sender<ExternalDecision>,
    pub url: String,
    pub method: Option<String>,
    pub client_ip: Option<String>,
    pub macros: Vec<ApprovalMacroDescriptor>,
}

#[derive(Debug, Clone, Copy)]
enum StatusWebhookStatus {
    WebhookFailed,
    TimedOut,
    Error,
    Cancelled,
}

#[derive(Debug, Clone)]
struct StatusWebhookEvent {
    request_id: String,
    profile_name: String,
    rule_index: usize,
    rule_id: Option<String>,
    url: String,
    method: Option<String>,
    client_ip: Option<String>,
    created_at: Instant,
    status: StatusWebhookStatus,
    reason: Option<String>,
    failure_kind: Option<WebhookFailureKind>,
    http_status: Option<u16>,
}

type SharedHttpClient = Client<HttpsConnector<HttpConnector>>;

#[derive(Clone)]
pub struct ExternalAuthManager {
    pending: Arc<DashMap<String, PendingRequest>>,
    macro_values: Arc<DashMap<String, BTreeMap<String, String>>>,
    profiles: Arc<BTreeMap<String, ExternalAuthProfile>>,
    callback_url: Option<String>,
    http_client: SharedHttpClient,
    status_tx: mpsc::Sender<StatusWebhookEvent>,
    status_rx: Arc<Mutex<Option<mpsc::Receiver<StatusWebhookEvent>>>>,
}

impl ExternalAuthManager {
    pub fn new(cfg: &ExternalAuthProfileConfigMap, http_client: SharedHttpClient) -> Self {
        Self::new_with_callback(cfg, None, http_client)
    }

    pub fn new_with_callback(
        cfg: &ExternalAuthProfileConfigMap,
        callback_url: Option<String>,
        http_client: SharedHttpClient,
    ) -> Self {
        let mut profiles: BTreeMap<String, ExternalAuthProfile> = BTreeMap::new();

        for (name, profile_cfg) in cfg {
            if profile_cfg.profile_type != ExternalAuthProfileType::Http {
                continue;
            }
            let webhook_url = match profile_cfg.webhook_url.clone() {
                Some(url) => url,
                None => {
                    tracing::warn!("external auth profile {name} missing webhook_url; skipping");
                    continue;
                }
            };
            let timeout = Duration::from_millis(profile_cfg.timeout_ms);
            let webhook_timeout = profile_cfg.webhook_timeout_ms.map(Duration::from_millis);
            let on_webhook_failure =
                WebhookFailureMode::from_config(profile_cfg.on_webhook_failure.clone());

            profiles.insert(
                name.clone(),
                ExternalAuthProfile {
                    webhook_url,
                    timeout,
                    webhook_timeout,
                    on_webhook_failure,
                },
            );
        }

        let (status_tx, status_rx) = mpsc::channel::<StatusWebhookEvent>(1024);

        ExternalAuthManager {
            pending: Arc::new(DashMap::new()),
            macro_values: Arc::new(DashMap::new()),
            profiles: Arc::new(profiles),
            callback_url,
            http_client,
            status_tx,
            status_rx: Arc::new(Mutex::new(Some(status_rx))),
        }
    }

    pub fn get_profile(&self, name: &str) -> Option<ExternalAuthProfile> {
        self.profiles.get(name).cloned()
    }

    pub fn start_pending(
        &self,
        request_id: String,
        rule_index: usize,
        rule_id: Option<String>,
        profile_name: String,
        url: String,
        method: Option<String>,
        client_ip: Option<String>,
        macros: Vec<ApprovalMacroDescriptor>,
    ) -> (PendingGuard, oneshot::Receiver<ExternalDecision>) {
        let (tx, rx) = oneshot::channel();
        let created_at = Instant::now();
        let timeout = self
            .profiles
            .get(&profile_name)
            .map(|p| p.timeout)
            .unwrap_or_else(|| Duration::from_secs(0));
        let deadline_at = created_at + timeout;

        let pending = PendingRequest {
            rule_index,
            rule_id,
            profile_name,
            created_at,
            deadline_at,
            decision_tx: tx,
            url,
            method,
            client_ip,
            macros,
        };

        self.pending.insert(request_id.clone(), pending);

        let guard = PendingGuard {
            request_id,
            manager: self.clone(),
        };

        (guard, rx)
    }

    /// Deliver an external decision callback.
    ///
    /// This removes the pending entry and wakes the waiting request task.
    pub fn resolve(&self, request_id: &str, decision: ExternalDecision) -> bool {
        if let Some((_key, pending)) = self.pending.remove(request_id) {
            let _ = pending.decision_tx.send(decision);
            true
        } else {
            false
        }
    }

    /// Return the approval macro descriptors for a pending request, if any.
    pub fn get_macro_descriptors(&self, request_id: &str) -> Option<Vec<ApprovalMacroDescriptor>> {
        self.pending.get(request_id).map(|p| p.macros.clone())
    }

    /// Store validated macro values for a request. These are later
    /// consumed when applying header actions after approval.
    pub fn store_macro_values(&self, request_id: &str, macros: BTreeMap<String, String>) {
        if macros.is_empty() {
            return;
        }
        self.macro_values.insert(request_id.to_string(), macros);
    }

    /// Take (and remove) macro values for a request, returning an
    /// empty map when none were stored.
    pub fn take_macro_values(&self, request_id: &str) -> BTreeMap<String, String> {
        self.macro_values
            .remove(request_id)
            .map(|(_, values)| values)
            .unwrap_or_default()
    }

    /// Send the initial "pending" webhook for a newly created pending entry.
    ///
    /// On failure, returns the failure kind and optional HTTP status
    /// code (for non-2xx responses).
    pub async fn send_initial_webhook(
        &self,
        request_id: &str,
    ) -> Result<(), (WebhookFailureKind, Option<StatusCode>)> {
        let snapshot = if let Some(p) = self.pending.get(request_id) {
            (
                p.profile_name.clone(),
                p.rule_index,
                p.rule_id.clone(),
                p.url.clone(),
                p.method.clone(),
                p.client_ip.clone(),
                p.created_at,
                p.macros.clone(),
            )
        } else {
            tracing::warn!("send_initial_webhook called for unknown request_id {request_id}");
            return Err((WebhookFailureKind::Transport, None));
        };

        let (profile_name, rule_index, rule_id, url, method, client_ip, created_at, macros) =
            snapshot;

        let profile = if let Some(p) = self.profiles.get(&profile_name) {
            p.clone()
        } else {
            tracing::warn!("external auth profile {profile_name} not found when sending webhook");
            return Err((WebhookFailureKind::Transport, None));
        };

        let event_ts = Utc::now();
        let elapsed_ms = Instant::now()
            .saturating_duration_since(created_at)
            .as_millis() as u64;

        let mut payload = serde_json::json!({
            "requestId": request_id,
            "profile": profile_name,
            "ruleIndex": rule_index,
            "ruleId": rule_id,
            "url": url,
            "method": method,
            "clientIp": client_ip,
            "status": "pending",
            "reason": serde_json::Value::Null,
            "timestamp": event_ts.to_rfc3339(),
            "elapsedMs": elapsed_ms,
            "terminal": false,
            "eventId": generate_event_id(),
            "failureKind": serde_json::Value::Null,
            "httpStatus": serde_json::Value::Null,
            "macros": macros,
        });

        if let Some(cb_url) = &self.callback_url {
            if let serde_json::Value::Object(ref mut map) = payload {
                map.insert(
                    "callbackUrl".to_string(),
                    serde_json::Value::String(cb_url.clone()),
                );
            }
        }

        let body_bytes = match serde_json::to_vec(&payload) {
            Ok(b) => b,
            Err(err) => {
                tracing::error!("failed to serialize external auth webhook payload: {err}");
                return Err((WebhookFailureKind::Transport, None));
            }
        };

        let req = match Request::builder()
            .method(Method::POST)
            .uri(&profile.webhook_url)
            .header(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )
            .header("X-Acl-Proxy-Event", HeaderValue::from_static("pending"))
            .body(Body::from(body_bytes))
        {
            Ok(r) => r,
            Err(err) => {
                tracing::error!("failed to build external auth webhook request: {err}");
                return Err((WebhookFailureKind::Transport, None));
            }
        };

        let client_http: SharedHttpClient = self.http_client.clone();
        let send_fut = client_http.request(req);

        let result = match profile.webhook_timeout {
            Some(timeout) => match tokio::time::timeout(timeout, send_fut).await {
                Ok(res) => res,
                Err(_elapsed) => {
                    tracing::warn!("external auth webhook timed out after {:?}", timeout);
                    return Err((WebhookFailureKind::Timeout, None));
                }
            },
            None => send_fut.await,
        };

        match result {
            Ok(resp) => {
                if resp.status().is_success() {
                    Ok(())
                } else {
                    let status = resp.status();
                    tracing::warn!(
                        "external auth webhook returned non-success status: {}",
                        status
                    );
                    Err((WebhookFailureKind::Non2xx, Some(status)))
                }
            }
            Err(err) => {
                tracing::warn!("external auth webhook request failed: {err}");
                Err((WebhookFailureKind::Transport, None))
            }
        }
    }

    /// Record a terminal "webhook_failed" status for the given request.
    pub fn finalize_webhook_failed(
        &self,
        request_id: &str,
        failure_kind: WebhookFailureKind,
        http_status: Option<StatusCode>,
    ) {
        if let Some((_key, pending)) = self.pending.remove(request_id) {
            // Best-effort cleanup of any stored macro values for this request.
            self.macro_values.remove(request_id);

            let reason = match failure_kind {
                WebhookFailureKind::Timeout => {
                    "External auth webhook delivery timed out".to_string()
                }
                WebhookFailureKind::Non2xx => format!(
                    "External auth webhook returned non-success status {}",
                    http_status.map(|s| s.as_u16()).unwrap_or_default()
                ),
                WebhookFailureKind::Transport => {
                    "External auth webhook delivery failed".to_string()
                }
            };

            let event = StatusWebhookEvent {
                request_id: request_id.to_string(),
                profile_name: pending.profile_name,
                rule_index: pending.rule_index,
                rule_id: pending.rule_id,
                url: pending.url,
                method: pending.method,
                client_ip: pending.client_ip,
                created_at: pending.created_at,
                status: StatusWebhookStatus::WebhookFailed,
                reason: Some(reason),
                failure_kind: Some(failure_kind),
                http_status: http_status.map(|s| s.as_u16()),
            };

            self.enqueue_status_event(event);
        }
    }

    /// Record a terminal "timed_out" status when approval times out.
    pub fn finalize_timed_out(&self, request_id: &str) {
        if let Some((_key, pending)) = self.pending.remove(request_id) {
            // Best-effort cleanup of any stored macro values for this request.
            self.macro_values.remove(request_id);

            let configured_ms = pending
                .deadline_at
                .saturating_duration_since(pending.created_at)
                .as_millis() as u64;
            let reason = format!("Approval timeout after {}ms", configured_ms);

            let event = StatusWebhookEvent {
                request_id: request_id.to_string(),
                profile_name: pending.profile_name,
                rule_index: pending.rule_index,
                rule_id: pending.rule_id,
                url: pending.url,
                method: pending.method,
                client_ip: pending.client_ip,
                created_at: pending.created_at,
                status: StatusWebhookStatus::TimedOut,
                reason: Some(reason),
                failure_kind: Some(WebhookFailureKind::Timeout),
                http_status: None,
            };

            self.enqueue_status_event(event);
        }
    }

    /// Record a terminal "error" status when the approval channel fails.
    pub fn finalize_internal_error(&self, request_id: &str, message: &str) {
        if let Some((_key, pending)) = self.pending.remove(request_id) {
            // Best-effort cleanup of any stored macro values for this request.
            self.macro_values.remove(request_id);

            let event = StatusWebhookEvent {
                request_id: request_id.to_string(),
                profile_name: pending.profile_name,
                rule_index: pending.rule_index,
                rule_id: pending.rule_id,
                url: pending.url,
                method: pending.method,
                client_ip: pending.client_ip,
                created_at: pending.created_at,
                status: StatusWebhookStatus::Error,
                reason: Some(message.to_string()),
                failure_kind: Some(WebhookFailureKind::Transport),
                http_status: None,
            };

            self.enqueue_status_event(event);
        }
    }

    /// Called from the RAII guard destructor to mark cancellations.
    pub fn finalize_cancelled_if_pending(&self, request_id: &str) {
        if let Some((_key, pending)) = self.pending.remove(request_id) {
            // Best-effort cleanup of any stored macro values for this request.
            self.macro_values.remove(request_id);

            let event = StatusWebhookEvent {
                request_id: request_id.to_string(),
                profile_name: pending.profile_name,
                rule_index: pending.rule_index,
                rule_id: pending.rule_id,
                url: pending.url,
                method: pending.method,
                client_ip: pending.client_ip,
                created_at: pending.created_at,
                status: StatusWebhookStatus::Cancelled,
                reason: Some("Client disconnected or request task aborted".to_string()),
                failure_kind: None,
                http_status: None,
            };

            self.enqueue_status_event(event);
        }
    }

    fn enqueue_status_event(&self, event: StatusWebhookEvent) {
        self.ensure_status_worker();

        if let Err(err) = self.status_tx.try_send(event) {
            match err {
                mpsc::error::TrySendError::Full(event) => {
                    tracing::warn!(
                        request_id = %event.request_id,
                        status = ?event.status,
                        "external auth status webhook queue full; dropping event"
                    );
                }
                mpsc::error::TrySendError::Closed(event) => {
                    tracing::warn!(
                        request_id = %event.request_id,
                        status = ?event.status,
                        "external auth status webhook queue closed; dropping event"
                    );
                }
            }
        }
    }

    fn ensure_status_worker(&self) {
        let rx_opt = {
            let mut guard = self.status_rx.lock().unwrap();
            guard.take()
        };

        if let Some(rx) = rx_opt {
            let client = self.http_client.clone();
            let profiles = self.profiles.clone();
            let callback_url = self.callback_url.clone();

            tokio::spawn(async move {
                run_status_worker(client, profiles, callback_url, rx).await;
            });
        }
    }
}

pub struct PendingGuard {
    request_id: String,
    manager: ExternalAuthManager,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.manager.finalize_cancelled_if_pending(&self.request_id);
    }
}

impl From<&ExternalAuthProfileConfig> for ExternalAuthProfile {
    fn from(cfg: &ExternalAuthProfileConfig) -> Self {
        let webhook_url = cfg.webhook_url.clone().unwrap_or_default();
        let timeout = Duration::from_millis(cfg.timeout_ms);
        let webhook_timeout = cfg.webhook_timeout_ms.map(Duration::from_millis);
        let on_webhook_failure = WebhookFailureMode::from_config(cfg.on_webhook_failure.clone());

        ExternalAuthProfile {
            webhook_url,
            timeout,
            webhook_timeout,
            on_webhook_failure,
        }
    }
}

fn generate_event_id() -> String {
    use once_cell::sync::Lazy;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(1));
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = Utc::now().timestamp_millis();
    format!("evt-{}-{}", ts, seq)
}

async fn run_status_worker(
    client: SharedHttpClient,
    profiles: Arc<BTreeMap<String, ExternalAuthProfile>>,
    callback_url: Option<String>,
    mut rx: mpsc::Receiver<StatusWebhookEvent>,
) {
    while let Some(event) = rx.recv().await {
        let profile = match profiles.get(&event.profile_name) {
            Some(p) => p.clone(),
            None => {
                tracing::debug!(
                    "dropping external auth status webhook for unknown profile {}",
                    event.profile_name
                );
                continue;
            }
        };

        let status_str = match event.status {
            StatusWebhookStatus::WebhookFailed => "webhook_failed",
            StatusWebhookStatus::TimedOut => "timed_out",
            StatusWebhookStatus::Error => "error",
            StatusWebhookStatus::Cancelled => "cancelled",
        };

        let failure_kind_str = match event.failure_kind {
            Some(WebhookFailureKind::Timeout) => Some("timeout"),
            Some(WebhookFailureKind::Non2xx) => Some("non_2xx"),
            Some(WebhookFailureKind::Transport) => Some("connect"),
            None => None,
        };

        let now = Utc::now();
        let elapsed_ms = Instant::now()
            .saturating_duration_since(event.created_at)
            .as_millis() as u64;

        let mut payload = serde_json::json!({
            "requestId": event.request_id,
            "profile": event.profile_name,
            "ruleIndex": event.rule_index,
            "ruleId": event.rule_id,
            "url": event.url,
            "method": event.method,
            "clientIp": event.client_ip,
            "status": status_str,
            "reason": event.reason,
            "timestamp": now.to_rfc3339(),
            "elapsedMs": elapsed_ms,
            "terminal": true,
            "eventId": generate_event_id(),
            "failureKind": failure_kind_str,
            "httpStatus": event.http_status,
        });

        if let Some(cb_url) = &callback_url {
            if let serde_json::Value::Object(ref mut map) = payload {
                map.insert(
                    "callbackUrl".to_string(),
                    serde_json::Value::String(cb_url.clone()),
                );
            }
        }

        let body_bytes = match serde_json::to_vec(&payload) {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!("failed to serialize external auth status webhook payload: {err}");
                continue;
            }
        };

        let req = match Request::builder()
            .method(Method::POST)
            .uri(&profile.webhook_url)
            .header(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )
            .header("X-Acl-Proxy-Event", HeaderValue::from_static("status"))
            .body(Body::from(body_bytes))
        {
            Ok(r) => r,
            Err(err) => {
                tracing::warn!("failed to build external auth status webhook request: {err}");
                continue;
            }
        };

        let send_fut = client.request(req);

        let result = match profile.webhook_timeout {
            Some(timeout) => match tokio::time::timeout(timeout, send_fut).await {
                Ok(res) => res,
                Err(_elapsed) => {
                    tracing::debug!("external auth status webhook timed out after {:?}", timeout);
                    continue;
                }
            },
            None => send_fut.await,
        };

        if let Err(err) = result {
            tracing::debug!("external auth status webhook request failed: {err}");
        }
    }
}
