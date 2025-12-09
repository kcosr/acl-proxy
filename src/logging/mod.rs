use std::{
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

use chrono::Utc;
use serde::Serialize;
use tracing::Level;
use tracing_subscriber::fmt::SubscriberBuilder;

use crate::config::{
    LoggingConfig, LoggingEvidenceConfig, LoggingPolicyDecisionsConfig, PolicyDefaultAction,
};
use crate::policy::PolicyDecision;

#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("invalid log level for {field}: {value}")]
    InvalidLevel { field: &'static str, value: String },

    #[error("failed to initialize global tracing subscriber: {0}")]
    InitFailed(#[from] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Debug, Clone)]
pub struct PolicyDecisionLogging {
    pub log_allows: bool,
    pub log_denies: bool,
    pub level_allows: Level,
    pub level_denies: Level,
}

#[derive(Debug, Clone)]
pub struct LoggingSettings {
    pub level: Level,
    pub policy_decisions: PolicyDecisionLogging,
    pub evidence: Option<EvidenceSink>,
}

impl LoggingSettings {
    pub fn from_config(cfg: &LoggingConfig) -> Result<Self, LoggingError> {
        let level = parse_level(&cfg.level).map_err(|value| LoggingError::InvalidLevel {
            field: "logging.level",
            value,
        })?;

        let policy_decisions = PolicyDecisionLogging::from_config(&cfg.policy_decisions)?;

        Ok(LoggingSettings {
            level,
            policy_decisions,
            evidence: EvidenceSink::from_config(&cfg.evidence),
        })
    }

    /// Configure a global tracing subscriber using the configured log level.
    ///
    /// This is kept separate from the pure configuration parsing so that
    /// higher-level code can manage when the global subscriber is installed.
    pub fn init_tracing(&self) -> Result<(), LoggingError> {
        let builder: SubscriberBuilder = tracing_subscriber::fmt()
            .with_max_level(self.level)
            .with_target(true)
            .with_ansi(false);

        builder.try_init().map_err(LoggingError::InitFailed)
    }

    /// Log a policy decision in a structured, configurable way.
    ///
    /// This helper does not assume where the subscriber sends events; it only
    /// emits structured fields that downstream subscribers can consume.
    pub fn log_policy_decision<'a>(&self, ctx: PolicyDecisionLogContext<'a>) {
        let allowed = ctx.decision.allowed;

        if allowed && !self.policy_decisions.log_allows {
            return;
        }
        if !allowed && !self.policy_decisions.log_denies {
            return;
        }

        let level = if allowed {
            self.policy_decisions.level_allows
        } else {
            self.policy_decisions.level_denies
        };
        let (rule_action, rule_pattern, rule_description) = match ctx.decision.matched.as_ref() {
            Some(m) => {
                let action = match m.action {
                    PolicyDefaultAction::Allow => "allow",
                    PolicyDefaultAction::Deny => "deny",
                };
                (Some(action), m.pattern.as_deref(), m.description.as_deref())
            }
            None => (None, None, None),
        };

        let method = ctx.method.unwrap_or_default();
        let client_ip = ctx.client_ip.unwrap_or_default();
        emit_policy_event(
            level,
            ctx.request_id,
            allowed,
            ctx.url,
            method,
            client_ip,
            rule_action,
            rule_pattern,
            rule_description,
        );

        if let Some(evidence) = &self.evidence {
            evidence.write(EvidenceLine {
                ts: Utc::now().to_rfc3339(),
                allowed,
                request_id: ctx.request_id,
                url: ctx.url,
                method,
                client_ip,
                rule_action,
                rule_pattern,
                rule_description,
            });
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyDecisionLogContext<'a> {
    pub request_id: &'a str,
    pub url: &'a str,
    pub method: Option<&'a str>,
    pub client_ip: Option<&'a str>,
    pub decision: &'a PolicyDecision,
}

impl PolicyDecisionLogging {
    pub fn from_config(cfg: &LoggingPolicyDecisionsConfig) -> Result<Self, LoggingError> {
        let level_allows =
            parse_level(&cfg.level_allows).map_err(|value| LoggingError::InvalidLevel {
                field: "logging.policy_decisions.level_allows",
                value,
            })?;

        let level_denies =
            parse_level(&cfg.level_denies).map_err(|value| LoggingError::InvalidLevel {
                field: "logging.policy_decisions.level_denies",
                value,
            })?;

        Ok(PolicyDecisionLogging {
            log_allows: cfg.log_allows,
            log_denies: cfg.log_denies,
            level_allows,
            level_denies,
        })
    }
}

fn parse_level(value: &str) -> Result<Level, String> {
    let upper = value.trim().to_ascii_uppercase();
    upper.parse::<Level>().map_err(|_| value.to_string())
}

fn emit_policy_event(
    level: Level,
    request_id: &str,
    allowed: bool,
    url: &str,
    method: &str,
    client_ip: &str,
    rule_action: Option<&str>,
    rule_pattern: Option<&str>,
    rule_description: Option<&str>,
) {
    match level {
        Level::TRACE => tracing::event!(
            target: "acl_proxy::policy",
            Level::TRACE,
            request_id,
            allowed,
            url,
            method,
            client_ip,
            rule_action,
            rule_pattern,
            rule_description,
            "policy decision"
        ),
        Level::DEBUG => tracing::event!(
            target: "acl_proxy::policy",
            Level::DEBUG,
            request_id,
            allowed,
            url,
            method,
            client_ip,
            rule_action,
            rule_pattern,
            rule_description,
            "policy decision"
        ),
        Level::INFO => tracing::event!(
            target: "acl_proxy::policy",
            Level::INFO,
            request_id,
            allowed,
            url,
            method,
            client_ip,
            rule_action,
            rule_pattern,
            rule_description,
            "policy decision"
        ),
        Level::WARN => tracing::event!(
            target: "acl_proxy::policy",
            Level::WARN,
            request_id,
            allowed,
            url,
            method,
            client_ip,
            rule_action,
            rule_pattern,
            rule_description,
            "policy decision"
        ),
        Level::ERROR => tracing::event!(
            target: "acl_proxy::policy",
            Level::ERROR,
            request_id,
            allowed,
            url,
            method,
            client_ip,
            rule_action,
            rule_pattern,
            rule_description,
            "policy decision"
        ),
    }
}

impl fmt::Display for PolicyDecisionLogging {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "allows={}, denies={}, level_allows={:?}, level_denies={:?}",
            self.log_allows, self.log_denies, self.level_allows, self.level_denies
        )
    }
}

#[derive(Debug, Clone)]
pub struct EvidenceSink {
    path: PathBuf,
}

impl EvidenceSink {
    fn from_config(cfg: &LoggingEvidenceConfig) -> Option<Self> {
        cfg.enabled.then_some(Self {
            path: PathBuf::from(&cfg.path),
        })
    }

    fn write(&self, line: EvidenceLine<'_>) {
        let json = match serde_json::to_string(&line) {
            Ok(value) => value,
            Err(err) => {
                eprintln!(
                    "failed to serialize evidence log line for {}: {err}",
                    self.path.display()
                );
                return;
            }
        };

        if let Some(parent) = self.path.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                eprintln!(
                    "failed to create evidence directory {}: {err}",
                    parent.display()
                );
                return;
            }
        }

        let mut file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(err) => {
                eprintln!("failed to open evidence log {}: {err}", self.path.display());
                return;
            }
        };

        if let Err(err) = writeln!(file, "{json}") {
            eprintln!(
                "failed to write evidence log {}: {err}",
                self.path.display()
            );
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct EvidenceLine<'a> {
    ts: String,
    allowed: bool,
    request_id: &'a str,
    url: &'a str,
    method: &'a str,
    client_ip: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_action: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_pattern: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_description: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LoggingEvidenceConfig, LoggingPolicyDecisionsConfig};

    #[test]
    fn logging_settings_parses_levels() {
        let cfg = LoggingConfig {
            directory: "logs".to_string(),
            level: "debug".to_string(),
            policy_decisions: LoggingPolicyDecisionsConfig {
                log_allows: true,
                log_denies: true,
                level_allows: "info".to_string(),
                level_denies: "warn".to_string(),
            },
            evidence: LoggingEvidenceConfig::default(),
        };

        let settings = LoggingSettings::from_config(&cfg).expect("parse logging config");
        assert_eq!(settings.level, Level::DEBUG);
        assert_eq!(settings.policy_decisions.level_allows, Level::INFO);
        assert_eq!(settings.policy_decisions.level_denies, Level::WARN);
    }

    #[test]
    fn invalid_base_level_fails() {
        let cfg = LoggingConfig {
            directory: "logs".to_string(),
            level: "notalevel".to_string(),
            policy_decisions: LoggingPolicyDecisionsConfig::default(),
            evidence: LoggingEvidenceConfig::default(),
        };

        let err = LoggingSettings::from_config(&cfg).expect_err("should fail");
        let msg = format!("{err}");
        assert!(msg.contains("invalid log level"), "unexpected error: {msg}");
    }
}
