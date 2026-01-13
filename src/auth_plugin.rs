use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use http::header::{HeaderName, HeaderValue};
use http::HeaderMap as HttpHeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::capture::HeaderMap;
use crate::config::{
    ExternalAuthProfileConfigMap, ExternalAuthProfileType, HeaderActionKind, HeaderDirection,
    HeaderWhen,
};
use crate::policy::CompiledHeaderAction;

const DEFAULT_RESTART_DELAY_MS: u64 = 10_000;

#[derive(Debug)]
pub struct PluginError {
    message: String,
}

impl PluginError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PluginError {}

#[derive(Debug)]
pub enum PluginDecision {
    Allow {
        header_actions: Vec<CompiledHeaderAction>,
    },
    Deny,
}

#[derive(Clone)]
pub struct AuthPluginHandle {
    config: AuthPluginConfig,
    runtime: std::sync::Arc<Mutex<Option<mpsc::Sender<PluginCommand>>>>,
}

#[derive(Clone)]
pub struct AuthPluginManager {
    handlers: BTreeMap<String, AuthPluginHandle>,
}

impl AuthPluginManager {
    pub fn new(cfg: &ExternalAuthProfileConfigMap) -> Self {
        let mut handlers = BTreeMap::new();

        for (name, profile) in cfg {
            if profile.profile_type != ExternalAuthProfileType::Plugin {
                continue;
            }

            let command = profile.command.as_deref().unwrap_or("").trim().to_string();
            if command.is_empty() {
                tracing::warn!(
                    handler = %name,
                    "auth plugin profile missing command; skipping"
                );
                continue;
            }
            let config = AuthPluginConfig {
                name: name.clone(),
                command,
                args: profile.args.clone(),
                timeout: Duration::from_millis(profile.timeout_ms),
                include_headers: profile.include_headers.clone(),
                env: profile.env.clone(),
                restart_delay: Duration::from_millis(
                    profile.restart_delay_ms.unwrap_or(DEFAULT_RESTART_DELAY_MS),
                ),
            };

            handlers.insert(
                name.clone(),
                AuthPluginHandle {
                    config,
                    runtime: std::sync::Arc::new(Mutex::new(None)),
                },
            );
        }

        Self { handlers }
    }

    pub fn get_handler(&self, name: &str) -> Option<AuthPluginHandle> {
        self.handlers.get(name).cloned()
    }
}

impl AuthPluginHandle {
    pub async fn evaluate(
        &self,
        request_id: &str,
        url: &str,
        method: &http::Method,
        client_ip: &str,
        headers: &HttpHeaderMap,
    ) -> Result<PluginDecision, PluginError> {
        let headers = collect_included_headers(headers, &self.config.include_headers);

        let payload = PluginRequest {
            id: request_id,
            message_type: "request",
            url,
            method: method.as_str(),
            client_ip,
            headers,
        };

        let message = serde_json::to_string(&payload).map_err(|err| {
            PluginError::new(format!("failed to serialize plugin request: {err}"))
        })?;

        let mut sender = self.ensure_runtime().await;
        let (mut response_tx, mut response_rx) = oneshot::channel();
        let mut command = PluginCommand::Request {
            request_id: request_id.to_string(),
            message,
            response_tx,
        };

        if sender.send(command).await.is_err() {
            self.reset_runtime().await;
            sender = self.ensure_runtime().await;
            let (next_tx, next_rx) = oneshot::channel();
            response_tx = next_tx;
            response_rx = next_rx;
            command = PluginCommand::Request {
                request_id: request_id.to_string(),
                message: serde_json::to_string(&payload).map_err(|err| {
                    PluginError::new(format!("failed to serialize plugin request: {err}"))
                })?,
                response_tx,
            };
            sender
                .send(command)
                .await
                .map_err(|_| PluginError::new("plugin runtime is unavailable"))?;
        }

        match tokio::time::timeout(self.config.timeout, response_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(PluginError::new("plugin response channel closed")),
            Err(_) => {
                let _ = sender
                    .send(PluginCommand::Cancel {
                        request_id: request_id.to_string(),
                    })
                    .await;
                Err(PluginError::new("plugin request timed out"))
            }
        }
    }

    async fn ensure_runtime(&self) -> mpsc::Sender<PluginCommand> {
        let mut guard = self.runtime.lock().await;
        if let Some(sender) = guard.as_ref() {
            return sender.clone();
        }

        let (tx, rx) = mpsc::channel(256);
        let config = self.config.clone();
        tokio::spawn(async move {
            run_plugin_worker(config, rx).await;
        });

        *guard = Some(tx.clone());
        tx
    }

    async fn reset_runtime(&self) {
        let mut guard = self.runtime.lock().await;
        *guard = None;
    }
}

#[derive(Clone)]
struct AuthPluginConfig {
    name: String,
    command: String,
    args: Vec<String>,
    timeout: Duration,
    include_headers: Vec<String>,
    env: BTreeMap<String, String>,
    restart_delay: Duration,
}

#[derive(Serialize)]
struct PluginRequest<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    message_type: &'a str,
    url: &'a str,
    method: &'a str,
    #[serde(rename = "clientIp")]
    client_ip: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<HeaderMap>,
}

#[derive(Deserialize)]
struct PluginResponse {
    id: String,
    #[serde(rename = "type")]
    message_type: String,
    decision: PluginDecisionKind,
    #[serde(default, rename = "requestHeaders")]
    request_headers: Vec<PluginHeaderAction>,
    #[serde(default, rename = "responseHeaders")]
    response_headers: Vec<PluginHeaderAction>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PluginDecisionKind {
    Allow,
    Deny,
}

#[derive(Debug, Deserialize)]
struct PluginHeaderAction {
    action: HeaderActionKind,
    name: String,
    #[serde(default)]
    when: HeaderWhen,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    values: Option<Vec<String>>,
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    replace: Option<String>,
}

enum PluginCommand {
    Request {
        request_id: String,
        message: String,
        response_tx: oneshot::Sender<Result<PluginDecision, PluginError>>,
    },
    Cancel {
        request_id: String,
    },
}

enum PluginEvent {
    Exited,
}

struct PluginProcess {
    stdin: tokio::process::ChildStdin,
    response_rx: mpsc::Receiver<String>,
    event_rx: mpsc::Receiver<PluginEvent>,
}

async fn run_plugin_worker(config: AuthPluginConfig, mut rx: mpsc::Receiver<PluginCommand>) {
    let mut pending: HashMap<String, oneshot::Sender<Result<PluginDecision, PluginError>>> =
        HashMap::new();
    let mut process: Option<PluginProcess> = None;
    let mut restart_at: Option<Instant> = None;

    loop {
        if let Some(proc_state) = process.as_mut() {
            tokio::select! {
                maybe_cmd = rx.recv() => {
                    let cmd = match maybe_cmd {
                        Some(cmd) => cmd,
                        None => break,
                    };
                    handle_plugin_command(&config, cmd, &mut process, &mut pending, &mut restart_at).await;
                }
                maybe_line = proc_state.response_rx.recv() => {
                    if let Some(line) = maybe_line {
                        handle_plugin_response(&config, line, &mut pending);
                    } else {
                        tracing::warn!(handler = %config.name, "auth plugin stdout closed; restarting after delay");
                        process = None;
                        restart_at = Some(Instant::now() + config.restart_delay);
                        let err = PluginError::new("auth plugin stdout closed");
                        drain_pending(&mut pending, &err);
                    }
                }
                maybe_event = proc_state.event_rx.recv() => {
                    if let Some(PluginEvent::Exited) = maybe_event {
                        tracing::warn!(handler = %config.name, "auth plugin exited; restarting after delay");
                        process = None;
                        restart_at = Some(Instant::now() + config.restart_delay);
                        let err = PluginError::new("auth plugin process exited");
                        drain_pending(&mut pending, &err);
                    } else {
                        tracing::warn!(handler = %config.name, "auth plugin event channel closed");
                        process = None;
                        restart_at = Some(Instant::now() + config.restart_delay);
                        let err = PluginError::new("auth plugin process exited");
                        drain_pending(&mut pending, &err);
                    }
                }
            }
        } else {
            let cmd = match rx.recv().await {
                Some(cmd) => cmd,
                None => break,
            };
            handle_plugin_command(&config, cmd, &mut process, &mut pending, &mut restart_at).await;
        }
    }
}

async fn handle_plugin_command(
    config: &AuthPluginConfig,
    cmd: PluginCommand,
    process: &mut Option<PluginProcess>,
    pending: &mut HashMap<String, oneshot::Sender<Result<PluginDecision, PluginError>>>,
    restart_at: &mut Option<Instant>,
) {
    match cmd {
        PluginCommand::Request {
            request_id,
            message,
            response_tx,
        } => {
            if process.is_none() {
                if let Some(deadline) = restart_at.as_ref() {
                    if Instant::now() < *deadline {
                        let _ = response_tx.send(Err(PluginError::new("auth plugin restarting")));
                        return;
                    }
                }

                match start_plugin_process(config).await {
                    Ok(proc_state) => {
                        *process = Some(proc_state);
                        *restart_at = None;
                    }
                    Err(err) => {
                        let _ = response_tx.send(Err(err));
                        *restart_at = Some(Instant::now() + config.restart_delay);
                        return;
                    }
                }
            }

            if let Some(proc_state) = process.as_mut() {
                pending.insert(request_id.clone(), response_tx);
                if let Err(err) = send_plugin_request(proc_state, &message).await {
                    if let Some(sender) = pending.remove(&request_id) {
                        let _ = sender.send(Err(err));
                    }
                    *process = None;
                    *restart_at = Some(Instant::now() + config.restart_delay);
                }
            } else {
                let _ = response_tx.send(Err(PluginError::new("auth plugin unavailable")));
            }
        }
        PluginCommand::Cancel { request_id } => {
            pending.remove(&request_id);
        }
    }
}

async fn send_plugin_request(
    process: &mut PluginProcess,
    message: &str,
) -> Result<(), PluginError> {
    process
        .stdin
        .write_all(message.as_bytes())
        .await
        .map_err(|err| PluginError::new(format!("failed to write plugin request: {err}")))?;
    process
        .stdin
        .write_all(b"\n")
        .await
        .map_err(|err| PluginError::new(format!("failed to write plugin request: {err}")))?;
    process
        .stdin
        .flush()
        .await
        .map_err(|err| PluginError::new(format!("failed to flush plugin request: {err}")))?;
    Ok(())
}

fn handle_plugin_response(
    config: &AuthPluginConfig,
    line: String,
    pending: &mut HashMap<String, oneshot::Sender<Result<PluginDecision, PluginError>>>,
) {
    let response: PluginResponse = match serde_json::from_str(&line) {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!(
                handler = %config.name,
                error = %err,
                "failed to parse auth plugin response"
            );
            return;
        }
    };

    if response.message_type != "response" {
        tracing::warn!(
            handler = %config.name,
            message_type = %response.message_type,
            "ignoring auth plugin message with unexpected type"
        );
        return;
    }

    let sender = match pending.remove(&response.id) {
        Some(sender) => sender,
        None => {
            tracing::debug!(
                handler = %config.name,
                request_id = %response.id,
                "auth plugin response for unknown request id"
            );
            return;
        }
    };

    let result = match response.decision {
        PluginDecisionKind::Allow => {
            tracing::debug!(
                handler = %config.name,
                request_id = %response.id,
                decision = "allow",
                "auth plugin decision"
            );
            let mut header_actions = Vec::new();
            match compile_plugin_actions(&response.request_headers, HeaderDirection::Request) {
                Ok(actions) => header_actions.extend(actions),
                Err(err) => {
                    let _ = sender.send(Err(err));
                    return;
                }
            }
            match compile_plugin_actions(&response.response_headers, HeaderDirection::Response) {
                Ok(actions) => header_actions.extend(actions),
                Err(err) => {
                    let _ = sender.send(Err(err));
                    return;
                }
            }

            Ok(PluginDecision::Allow { header_actions })
        }
        PluginDecisionKind::Deny => {
            tracing::debug!(
                handler = %config.name,
                request_id = %response.id,
                decision = "deny",
                "auth plugin decision"
            );
            Ok(PluginDecision::Deny)
        }
    };

    let _ = sender.send(result);
}

fn compile_plugin_actions(
    actions: &[PluginHeaderAction],
    direction: HeaderDirection,
) -> Result<Vec<CompiledHeaderAction>, PluginError> {
    let mut compiled = Vec::with_capacity(actions.len());

    for action_cfg in actions {
        let name = HeaderName::from_lowercase(action_cfg.name.to_ascii_lowercase().as_bytes())
            .map_err(|e| {
                PluginError::new(format!(
                    "invalid header name '{}' in plugin response: {e}",
                    action_cfg.name
                ))
            })?;

        let when = action_cfg.when.clone();
        let mut values: Vec<HeaderValue> = Vec::new();

        match action_cfg.action {
            HeaderActionKind::Set | HeaderActionKind::Add => {
                let source_values = match (&action_cfg.value, &action_cfg.values) {
                    (Some(v), None) => vec![v.clone()],
                    (None, Some(vs)) if !vs.is_empty() => vs.clone(),
                    (Some(_), Some(_)) => {
                        return Err(PluginError::new(format!(
                            "header action for '{}' must not set both value and values",
                            action_cfg.name
                        )))
                    }
                    _ => {
                        return Err(PluginError::new(format!(
                            "header action for '{}' must provide value or values",
                            action_cfg.name
                        )))
                    }
                };

                for v in source_values {
                    let hv = HeaderValue::from_str(&v).map_err(|e| {
                        PluginError::new(format!(
                            "invalid header value for '{}': {} ({e})",
                            action_cfg.name, v
                        ))
                    })?;
                    values.push(hv);
                }
            }
            HeaderActionKind::Remove | HeaderActionKind::ReplaceSubstring => {
                if action_cfg.value.is_some() || action_cfg.values.is_some() {
                    return Err(PluginError::new(format!(
                        "header action for '{}' with action {:?} must not set value/values",
                        action_cfg.name, action_cfg.action
                    )));
                }
            }
        }

        let (search, replace) = match action_cfg.action {
            HeaderActionKind::ReplaceSubstring => {
                let search = action_cfg.search.clone().ok_or_else(|| {
                    PluginError::new(format!(
                        "header action for '{}' with action replace_substring requires search",
                        action_cfg.name
                    ))
                })?;
                if search.is_empty() {
                    return Err(PluginError::new(format!(
                        "header action for '{}' with action replace_substring requires non-empty search",
                        action_cfg.name
                    )));
                }
                let replace = action_cfg.replace.clone().ok_or_else(|| {
                    PluginError::new(format!(
                        "header action for '{}' with action replace_substring requires replace",
                        action_cfg.name
                    ))
                })?;
                (Some(search), Some(replace))
            }
            _ => (None, None),
        };

        compiled.push(CompiledHeaderAction {
            direction: direction.clone(),
            action: action_cfg.action.clone(),
            name,
            values,
            when,
            search,
            replace,
        });
    }

    Ok(compiled)
}

async fn start_plugin_process(config: &AuthPluginConfig) -> Result<PluginProcess, PluginError> {
    let mut cmd = Command::new(&config.command);
    cmd.args(&config.args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .envs(&config.env);

    let mut child = cmd
        .spawn()
        .map_err(|err| PluginError::new(format!("failed to spawn auth plugin: {err}")))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| PluginError::new("failed to open auth plugin stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| PluginError::new("failed to open auth plugin stdout"))?;

    let (response_tx, response_rx) = mpsc::channel(256);
    let (event_tx, event_rx) = mpsc::channel(8);

    tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            if response_tx.send(line).await.is_err() {
                break;
            }
        }
    });

    tokio::spawn(async move {
        let _ = child.wait().await;
        let _ = event_tx.send(PluginEvent::Exited).await;
    });

    Ok(PluginProcess {
        stdin,
        response_rx,
        event_rx,
    })
}

fn collect_included_headers(headers: &HttpHeaderMap, patterns: &[String]) -> Option<HeaderMap> {
    if patterns.is_empty() {
        return None;
    }

    let mut out = HeaderMap::new();

    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if !patterns
            .iter()
            .any(|pattern| header_matches_pattern(name_str, pattern))
        {
            continue;
        }

        let key = name_str.to_ascii_lowercase();
        if let Ok(val_str) = value.to_str() {
            match out.get_mut(&key) {
                None => {
                    out.insert(key, JsonValue::String(val_str.to_string()));
                }
                Some(JsonValue::String(existing)) => {
                    let mut arr = vec![JsonValue::String(existing.clone())];
                    arr.push(JsonValue::String(val_str.to_string()));
                    *out.get_mut(&key).unwrap() = JsonValue::Array(arr);
                }
                Some(JsonValue::Array(arr)) => {
                    arr.push(JsonValue::String(val_str.to_string()));
                }
                _ => {}
            }
        }
    }

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn header_matches_pattern(header: &str, pattern: &str) -> bool {
    let header = header.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();

    if !pattern.contains('*') {
        return header == pattern;
    }

    let header_bytes = header.as_bytes();
    let pattern_bytes = pattern.as_bytes();
    let mut h_idx = 0;
    let mut p_idx = 0;
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0;

    while h_idx < header_bytes.len() {
        if p_idx < pattern_bytes.len() && pattern_bytes[p_idx] == header_bytes[h_idx] {
            h_idx += 1;
            p_idx += 1;
        } else if p_idx < pattern_bytes.len() && pattern_bytes[p_idx] == b'*' {
            star_idx = Some(p_idx);
            match_idx = h_idx;
            p_idx += 1;
        } else if let Some(star_pos) = star_idx {
            p_idx = star_pos + 1;
            match_idx += 1;
            h_idx = match_idx;
        } else {
            return false;
        }
    }

    while p_idx < pattern_bytes.len() && pattern_bytes[p_idx] == b'*' {
        p_idx += 1;
    }

    p_idx == pattern_bytes.len()
}

fn drain_pending(
    pending: &mut HashMap<String, oneshot::Sender<Result<PluginDecision, PluginError>>>,
    err: &PluginError,
) {
    for (_id, sender) in pending.drain() {
        let _ = sender.send(Err(PluginError::new(err.message())));
    }
}
