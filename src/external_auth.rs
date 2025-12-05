use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::oneshot;

use crate::config::{
    ExternalAuthProfileConfig, ExternalAuthProfileConfigMap,
    ExternalAuthWebhookFailureMode,
};

#[derive(Debug, Clone)]
pub enum ExternalDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy)]
pub enum WebhookFailureMode {
    Deny,
    Error,
    Timeout,
}

impl WebhookFailureMode {
    fn from_config(
        mode: Option<ExternalAuthWebhookFailureMode>,
    ) -> Self {
        match mode.unwrap_or(ExternalAuthWebhookFailureMode::Error) {
            ExternalAuthWebhookFailureMode::Deny => {
                WebhookFailureMode::Deny
            }
            ExternalAuthWebhookFailureMode::Error => {
                WebhookFailureMode::Error
            }
            ExternalAuthWebhookFailureMode::Timeout => {
                WebhookFailureMode::Timeout
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExternalAuthProfile {
    pub webhook_url: String,
    pub timeout: Duration,
    pub webhook_timeout: Option<Duration>,
    pub on_webhook_failure: WebhookFailureMode,
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
}

#[derive(Clone)]
pub struct ExternalAuthManager {
    pending: Arc<DashMap<String, PendingRequest>>,
    profiles: Arc<BTreeMap<String, ExternalAuthProfile>>,
}

impl ExternalAuthManager {
    pub fn new(cfg: &ExternalAuthProfileConfigMap) -> Self {
        let mut profiles: BTreeMap<String, ExternalAuthProfile> =
            BTreeMap::new();

        for (name, profile_cfg) in cfg {
            let timeout =
                Duration::from_millis(profile_cfg.timeout_ms);
            let webhook_timeout = profile_cfg
                .webhook_timeout_ms
                .map(Duration::from_millis);
            let on_webhook_failure =
                WebhookFailureMode::from_config(
                    profile_cfg.on_webhook_failure.clone(),
                );

            profiles.insert(
                name.clone(),
                ExternalAuthProfile {
                    webhook_url: profile_cfg.webhook_url.clone(),
                    timeout,
                    webhook_timeout,
                    on_webhook_failure,
                },
            );
        }

        ExternalAuthManager {
            pending: Arc::new(DashMap::new()),
            profiles: Arc::new(profiles),
        }
    }

    pub fn get_profile(
        &self,
        name: &str,
    ) -> Option<ExternalAuthProfile> {
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
        };

        self.pending.insert(request_id.clone(), pending);

        let guard = PendingGuard {
            request_id,
            manager: self.clone(),
        };

        (guard, rx)
    }

    pub fn resolve(
        &self,
        request_id: &str,
        decision: ExternalDecision,
    ) -> bool {
        if let Some((_key, pending)) =
            self.pending.remove(request_id)
        {
            let _ = pending.decision_tx.send(decision);
            true
        } else {
            false
        }
    }
}

pub struct PendingGuard {
    request_id: String,
    manager: ExternalAuthManager,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.manager.pending.remove(&self.request_id);
    }
}

impl From<&ExternalAuthProfileConfig>
    for ExternalAuthProfile
{
    fn from(cfg: &ExternalAuthProfileConfig) -> Self {
        let timeout = Duration::from_millis(cfg.timeout_ms);
        let webhook_timeout = cfg
            .webhook_timeout_ms
            .map(Duration::from_millis);
        let on_webhook_failure =
            WebhookFailureMode::from_config(
                cfg.on_webhook_failure.clone(),
            );

        ExternalAuthProfile {
            webhook_url: cfg.webhook_url.clone(),
            timeout,
            webhook_timeout,
            on_webhook_failure,
        }
    }
}

