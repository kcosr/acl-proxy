use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use url::Url;

const DEFAULT_CONFIG_PATH: &str = "config/acl-proxy.toml";
const DEFAULT_SCHEMA_VERSION: &str = "1";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config {path}: {source}")]
    ParseToml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigPathKind {
    Explicit,
    Env,
    Default,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExternalAuthConfig {
    /// Full callback URL external auth services should use when
    /// delivering approval decisions back to this proxy instance.
    ///
    /// When set, this is included in external auth webhooks as
    /// `callbackUrl` so that external services do not need to infer
    /// the callback endpoint from deployment-specific base URLs.
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,

    #[serde(default)]
    pub proxy: ProxyConfig,

    #[serde(default)]
    pub logging: LoggingConfig,

    #[serde(default)]
    pub capture: CaptureConfig,

    #[serde(default)]
    pub loop_protection: LoopProtectionConfig,

    #[serde(default)]
    pub certificates: CertificatesConfig,

    #[serde(default)]
    pub tls: TlsConfig,

    #[serde(default)]
    pub external_auth: ExternalAuthConfig,

    #[serde(default)]
    pub policy: PolicyConfig,
}

fn default_schema_version() -> String {
    DEFAULT_SCHEMA_VERSION.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    #[serde(default = "default_http_port")]
    pub http_port: u16,

    #[serde(default = "default_https_bind_address")]
    pub https_bind_address: String,

    #[serde(default = "default_https_port")]
    pub https_port: u16,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            http_port: default_http_port(),
            https_bind_address: default_https_bind_address(),
            https_port: default_https_port(),
        }
    }
}

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}

fn default_http_port() -> u16 {
    8881
}

fn default_https_bind_address() -> String {
    "0.0.0.0".to_string()
}

fn default_https_port() -> u16 {
    8889
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingPolicyDecisionsConfig {
    #[serde(default)]
    pub log_allows: bool,

    #[serde(default = "default_log_denies")]
    pub log_denies: bool,

    #[serde(default = "default_policy_allow_level")]
    pub level_allows: String,

    #[serde(default = "default_policy_deny_level")]
    pub level_denies: String,
}

impl Default for LoggingPolicyDecisionsConfig {
    fn default() -> Self {
        Self {
            log_allows: false,
            log_denies: default_log_denies(),
            level_allows: default_policy_allow_level(),
            level_denies: default_policy_deny_level(),
        }
    }
}

fn default_log_denies() -> bool {
    true
}

fn default_policy_allow_level() -> String {
    "info".to_string()
}

fn default_policy_deny_level() -> String {
    "warn".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_logging_directory")]
    pub directory: String,

    #[serde(default = "default_logging_level")]
    pub level: String,

    #[serde(default)]
    pub policy_decisions: LoggingPolicyDecisionsConfig,

    #[serde(default)]
    pub evidence: LoggingEvidenceConfig,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            directory: default_logging_directory(),
            level: default_logging_level(),
            policy_decisions: LoggingPolicyDecisionsConfig::default(),
            evidence: LoggingEvidenceConfig::default(),
        }
    }
}

fn default_logging_directory() -> String {
    "logs".to_string()
}

fn default_logging_level() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingEvidenceConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_evidence_path")]
    pub path: String,
}

impl Default for LoggingEvidenceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_evidence_path(),
        }
    }
}

fn default_evidence_path() -> String {
    "logs/acl_proxy_evidence.jsonl".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    #[serde(default)]
    pub allowed_request: bool,

    #[serde(default)]
    pub allowed_response: bool,

    #[serde(default)]
    pub denied_request: bool,

    #[serde(default)]
    pub denied_response: bool,

    #[serde(default = "default_capture_directory")]
    pub directory: String,

    #[serde(default = "default_capture_filename")]
    pub filename: String,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            allowed_request: false,
            allowed_response: false,
            denied_request: false,
            denied_response: false,
            directory: default_capture_directory(),
            filename: default_capture_filename(),
        }
    }
}

fn default_capture_directory() -> String {
    "logs-capture".to_string()
}

fn default_capture_filename() -> String {
    "{requestId}-{suffix}.json".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopProtectionConfig {
    #[serde(default = "default_loop_enabled")]
    pub enabled: bool,

    #[serde(default = "default_loop_add_header")]
    pub add_header: bool,

    #[serde(default = "default_loop_header_name")]
    pub header_name: String,
}

impl Default for LoopProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: default_loop_enabled(),
            add_header: default_loop_add_header(),
            header_name: default_loop_header_name(),
        }
    }
}

fn default_loop_enabled() -> bool {
    true
}

fn default_loop_add_header() -> bool {
    true
}

fn default_loop_header_name() -> String {
    "x-acl-proxy-request-id".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificatesConfig {
    #[serde(default = "default_certs_dir")]
    pub certs_dir: String,

    #[serde(default)]
    pub ca_key_path: Option<String>,

    #[serde(default)]
    pub ca_cert_path: Option<String>,

    /// Maximum number of distinct per-host certificates to keep in
    /// the in-memory LRU caches used by `CertManager` and
    /// `SniResolver`. When the cache is full, the least recently used
    /// entry is evicted.
    #[serde(default = "default_max_cached_certs")]
    pub max_cached_certs: usize,
}

impl Default for CertificatesConfig {
    fn default() -> Self {
        Self {
            certs_dir: default_certs_dir(),
            ca_key_path: None,
            ca_cert_path: None,
            max_cached_certs: default_max_cached_certs(),
        }
    }
}

fn default_certs_dir() -> String {
    "certs".to_string()
}

fn default_max_cached_certs() -> usize {
    1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default = "default_verify_upstream")]
    pub verify_upstream: bool,

    /// Enable HTTP/2 for upstream TLS connections when supported by
    /// the origin server.
    ///
    /// When `false` (the default), the proxy uses HTTP/1.1 for
    /// outbound connections, even if clients speak HTTP/2 to the
    /// proxy.
    ///
    /// When `true`, the shared HTTP client enables HTTP/2 and lets
    /// ALPN negotiate the protocol with each origin. This is intended
    /// for controlled environments that require upstream HTTP/2; the
    /// recommended default remains HTTP/1.1-only upstream for maximum
    /// compatibility.
    #[serde(default)]
    pub enable_http2_upstream: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            verify_upstream: default_verify_upstream(),
            enable_http2_upstream: false,
        }
    }
}

fn default_verify_upstream() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Config {
            schema_version: default_schema_version(),
            proxy: ProxyConfig::default(),
            logging: LoggingConfig::default(),
            capture: CaptureConfig::default(),
            loop_protection: LoopProtectionConfig::default(),
            certificates: CertificatesConfig::default(),
            tls: TlsConfig::default(),
            external_auth: ExternalAuthConfig::default(),
            policy: PolicyConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum PolicyDefaultAction {
    Allow,
    #[default]
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleTemplateConfig {
    pub action: PolicyDefaultAction,
    pub pattern: String,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default)]
    pub methods: Option<MethodList>,

    #[serde(default)]
    pub subnets: Vec<Ipv4Net>,

    #[serde(default)]
    pub header_actions: Vec<HeaderActionConfig>,

    #[serde(default)]
    pub external_auth_profile: Option<String>,

    /// Optional stable identifier for this rule.
    ///
    /// When set, this is included in external auth webhooks as
    /// `ruleId` alongside the numeric `ruleIndex`.
    #[serde(default)]
    pub rule_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleIncludeConfig {
    /// Name of the ruleset to include.
    pub include: String,

    /// Placeholder overrides for this include.
    #[serde(default)]
    pub with: Option<MacroOverrideMap>,

    /// Whether to add URL-encoded variants for placeholders.
    #[serde(default)]
    pub add_url_enc_variants: Option<UrlEncVariants>,

    /// Optional subnets/methods that override template-level values.
    #[serde(default)]
    pub methods: Option<MethodList>,

    #[serde(default)]
    pub subnets: Vec<Ipv4Net>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleDirectConfig {
    pub action: PolicyDefaultAction,

    #[serde(default)]
    pub pattern: Option<String>,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default)]
    pub methods: Option<MethodList>,

    #[serde(default)]
    pub subnets: Vec<Ipv4Net>,

    #[serde(default)]
    pub with: Option<MacroOverrideMap>,

    #[serde(default)]
    pub add_url_enc_variants: Option<UrlEncVariants>,

    #[serde(default)]
    pub header_actions: Vec<HeaderActionConfig>,

    #[serde(default)]
    pub external_auth_profile: Option<String>,

    /// Optional stable identifier for this rule.
    ///
    /// When set, this is included in external auth webhooks as
    /// `ruleId` alongside the numeric `ruleIndex`.
    #[serde(default)]
    pub rule_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolicyRuleConfig {
    Direct(PolicyRuleDirectConfig),
    Include(PolicyRuleIncludeConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub default: PolicyDefaultAction,

    #[serde(default)]
    pub macros: MacroMap,

    #[serde(default)]
    pub approval_macros: ApprovalMacroConfigMap,

    #[serde(default)]
    pub rulesets: RulesetMap,

    #[serde(default)]
    pub external_auth_profiles: ExternalAuthProfileConfigMap,

    #[serde(default)]
    pub rules: Vec<PolicyRuleConfig>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default: PolicyDefaultAction::Deny,
            macros: MacroMap::default(),
            approval_macros: ApprovalMacroConfigMap::default(),
            rulesets: RulesetMap::default(),
            external_auth_profiles: ExternalAuthProfileConfigMap::default(),
            rules: Vec::new(),
        }
    }
}

pub type MacroMap = std::collections::BTreeMap<String, MacroValues>;
pub type RulesetMap = std::collections::BTreeMap<String, Vec<PolicyRuleTemplateConfig>>;
pub type MacroOverrideMap = std::collections::BTreeMap<String, MacroValues>;

pub type ApprovalMacroConfigMap = std::collections::BTreeMap<String, ApprovalMacroConfig>;

pub type ExternalAuthProfileConfigMap =
    std::collections::BTreeMap<String, ExternalAuthProfileConfig>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalMacroConfig {
    #[serde(default)]
    pub label: Option<String>,

    #[serde(default = "default_approval_macro_required")]
    pub required: bool,

    #[serde(default)]
    pub secret: bool,
}

fn default_approval_macro_required() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExternalAuthWebhookFailureMode {
    Deny,
    Error,
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalAuthProfileConfig {
    pub webhook_url: String,
    pub timeout_ms: u64,

    #[serde(default)]
    pub webhook_timeout_ms: Option<u64>,

    #[serde(default)]
    pub on_webhook_failure: Option<ExternalAuthWebhookFailureMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HeaderDirection {
    Request,
    Response,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderActionKind {
    Remove,
    Set,
    Add,
    ReplaceSubstring,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum HeaderWhen {
    #[default]
    Always,
    IfPresent,
    IfAbsent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderActionConfig {
    pub direction: HeaderDirection,
    pub action: HeaderActionKind,
    pub name: String,

    #[serde(default)]
    pub when: HeaderWhen,

    // For set/add; allow value or values (but not both).
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub values: Option<Vec<String>>,

    // For replace_substring.
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub replace: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MacroValues {
    Single(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UrlEncVariants {
    All(bool),
    Names(Vec<String>),
}

#[derive(Debug, Clone, Serialize)]
/// HTTP method list, normalized to uppercase during deserialization.
#[serde(transparent)]
pub struct MethodList {
    methods: Vec<String>,
}

impl MethodList {
    pub fn as_slice(&self) -> &[String] {
        &self.methods
    }
}

impl<'de> Deserialize<'de> for MethodList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = MethodList;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "string or list of strings")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(MethodList {
                    methods: vec![v.to_ascii_uppercase()],
                })
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut methods = Vec::new();
                while let Some(value) = seq.next_element::<String>()? {
                    methods.push(value.to_ascii_uppercase());
                }
                Ok(MethodList { methods })
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

impl Config {
    /// Load configuration using CLI and environment overrides.
    ///
    /// Resolution order for the config path:
    /// - Explicit CLI path if provided.
    /// - `ACL_PROXY_CONFIG` environment variable.
    /// - Default path `config/acl-proxy.toml`.
    pub fn load_from_sources(cli_path: Option<&Path>) -> Result<Self, ConfigError> {
        let (path, _kind) = Self::resolve_path(cli_path);

        let raw = fs::read_to_string(&path).map_err(|source| ConfigError::Io {
            path: path.clone(),
            source,
        })?;

        let mut config: Config = toml::from_str(&raw).map_err(|source| ConfigError::ParseToml {
            path: path.clone(),
            source,
        })?;

        config.apply_env_overrides();
        config.validate_basic()?;

        Ok(config)
    }

    /// Resolve the config path and indicate whether it came from CLI, env, or default.
    pub fn resolve_path(cli_path: Option<&Path>) -> (PathBuf, ConfigPathKind) {
        if let Some(p) = cli_path {
            (p.to_path_buf(), ConfigPathKind::Explicit)
        } else if let Ok(env_path) = env::var("ACL_PROXY_CONFIG") {
            (PathBuf::from(env_path), ConfigPathKind::Env)
        } else {
            (PathBuf::from(DEFAULT_CONFIG_PATH), ConfigPathKind::Default)
        }
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(port) = env::var("PROXY_PORT") {
            if let Ok(port) = port.parse::<u16>() {
                self.proxy.http_port = port;
            }
        }
        if let Ok(host) = env::var("PROXY_HOST") {
            if !host.trim().is_empty() {
                self.proxy.bind_address = host;
            }
        }
        if let Ok(level) = env::var("LOG_LEVEL") {
            if !level.trim().is_empty() {
                self.logging.level = level;
            }
        }
    }

    fn validate_basic(&self) -> Result<(), ConfigError> {
        if self.schema_version != DEFAULT_SCHEMA_VERSION {
            return Err(ConfigError::Invalid(format!(
                "unsupported schema_version {}, expected {}",
                self.schema_version, DEFAULT_SCHEMA_VERSION
            )));
        }

        // Ensure policy rules are structurally valid.
        for (idx, rule) in self.policy.rules.iter().enumerate() {
            let has_match_criteria = match rule {
                PolicyRuleConfig::Direct(d) => {
                    d.pattern.is_some() || !d.subnets.is_empty() || d.methods.is_some()
                }
                PolicyRuleConfig::Include(i) => !i.include.trim().is_empty(),
            };

            if !has_match_criteria {
                return Err(ConfigError::Invalid(format!(
                    "policy.rules[{idx}] must specify at least one of pattern, subnets, methods, or include"
                )));
            }
        }
        // Ensure certificate paths are configured consistently.
        let ca_key = self
            .certificates
            .ca_key_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let ca_cert = self
            .certificates
            .ca_cert_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());

        match (ca_key, ca_cert) {
            (Some(_), Some(_)) | (None, None) => Ok(()),
            _ => Err(ConfigError::Invalid(
                "certificates.ca_key_path and certificates.ca_cert_path must both be set or both omitted"
                    .to_string(),
            )),
        }?;

        if self.certificates.max_cached_certs == 0 {
            return Err(ConfigError::Invalid(
                "certificates.max_cached_certs must be at least 1".to_string(),
            ));
        }

        // Validate policy semantics (macros, rulesets, includes).
        crate::policy::PolicyEngine::from_config(&self.policy)
            .map_err(|e| ConfigError::Invalid(format!("{e}")))?;

        validate_logging_config(&self.logging)?;
        validate_capture_config(&self.capture)?;
        validate_external_auth_config(&self.external_auth)?;

        Ok(())
    }
}

pub fn write_default_config(path: &Path) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent() {
        if let Err(source) = fs::create_dir_all(parent) {
            return Err(ConfigError::Io {
                path: parent.to_path_buf(),
                source,
            });
        }
    }

    let contents = r#"schema_version = "1"

[proxy]
bind_address = "0.0.0.0"
http_port = 8881
https_bind_address = "0.0.0.0"
https_port = 8889

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
"#;

    fs::write(path, contents).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn validate_logging_config(logging: &LoggingConfig) -> Result<(), ConfigError> {
    if let Err(e) = crate::logging::LoggingSettings::from_config(logging) {
        return Err(ConfigError::Invalid(format!("{e}")));
    }
    Ok(())
}

fn validate_capture_config(capture: &CaptureConfig) -> Result<(), ConfigError> {
    let dir = capture.directory.trim();
    if dir.is_empty() {
        return Err(ConfigError::Invalid(
            "capture.directory must not be empty".to_string(),
        ));
    }

    Ok(())
}

fn validate_external_auth_config(external_auth: &ExternalAuthConfig) -> Result<(), ConfigError> {
    if let Some(raw) = external_auth.callback_url.as_deref() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ConfigError::Invalid(
                "external_auth.callback_url must not be empty when set".to_string(),
            ));
        }

        let parsed = Url::parse(trimmed).map_err(|e| {
            ConfigError::Invalid(format!(
                "external_auth.callback_url is not a valid URL: {e}"
            ))
        })?;

        if !parsed.has_host() {
            return Err(ConfigError::Invalid(
                "external_auth.callback_url must be an absolute URL with host".to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PolicyDefaultAction;

    #[test]
    fn minimal_config_round_trip() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "debug"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse minimal config");
        assert_eq!(config.schema_version, "1");
        assert_eq!(config.proxy.http_port, 8080);
        assert_eq!(config.logging.level, "debug");
        assert!(matches!(config.policy.default, PolicyDefaultAction::Deny));
    }

    #[test]
    fn include_rule_requires_non_empty_name() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"

[[policy.rules]]
include = ""
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("policy.rules[0]"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn certificate_paths_must_be_both_or_neither() {
        let base = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
"#;

        // Only ca_key_path set.
        let toml_key_only = format!(
            r#"{base}

[certificates]
ca_key_path = "ca-key.pem"
"#
        );
        let config: Config = toml::from_str(&toml_key_only).expect("parse key-only config");
        assert!(config.validate_basic().is_err());

        // Only ca_cert_path set.
        let toml_cert_only = format!(
            r#"{base}

[certificates]
ca_cert_path = "ca-cert.pem"
"#
        );
        let config: Config = toml::from_str(&toml_cert_only).expect("parse cert-only config");
        assert!(config.validate_basic().is_err());

        // Both set is ok.
        let toml_both = format!(
            r#"{base}

[certificates]
ca_key_path = "ca-key.pem"
ca_cert_path = "ca-cert.pem"
"#
        );
        let config: Config = toml::from_str(&toml_both).expect("parse both config");
        assert!(config.validate_basic().is_ok());
    }

    #[test]
    fn certificate_max_cached_certs_must_be_at_least_one() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"

[certificates]
max_cached_certs = 0
"#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("certificates.max_cached_certs"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn direct_rule_without_match_criteria_fails() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("policy.rules[0]"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn invalid_logging_levels_fail_validation() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "notalevel"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("invalid log level for logging.level"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn empty_capture_directory_fails_validation() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[capture]
directory = ""

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("capture.directory must not be empty"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn empty_capture_filename_fails_validation() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

        [capture]
        directory = "logs-capture"
        filename = ""

        [policy]
        default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        // Empty filename is allowed; resolve_capture_path will fall back
        // to the default template.
        assert!(config.validate_basic().is_ok());
    }

    #[test]
    fn external_auth_callback_url_must_be_absolute_url() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"

[external_auth]
callback_url = "/relative/path"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config
            .validate_basic()
            .expect_err("validation should fail for relative callback_url");
        let msg = format!("{err}");
        assert!(
            msg.contains("external_auth.callback_url"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn external_auth_callback_url_valid_absolute_url_passes_validation() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"

[external_auth]
callback_url = "https://proxy.example.com/_acl-proxy/external-auth/callback"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        assert!(
            config.validate_basic().is_ok(),
            "validation should succeed for absolute callback_url"
        );
    }

    #[test]
    fn sample_config_in_repo_root_is_valid() {
        use std::fs;
        use std::path::PathBuf;

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let sample_path = manifest_dir.join("acl-proxy.sample.toml");
        let contents = fs::read_to_string(&sample_path).expect("read sample config");

        let config: Config = toml::from_str(&contents).expect("parse sample config");
        config
            .validate_basic()
            .expect("sample config should pass basic validation");

        let effective = crate::policy::EffectivePolicy::from_config(&config.policy)
            .expect("sample policy should produce effective rules");
        assert!(
            !effective.rules.is_empty(),
            "sample policy should produce at least one effective rule"
        );
    }

    #[test]
    fn external_auth_profile_must_exist() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "https://example.com/**"
external_auth_profile = "missing_profile"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("external_auth_profile 'missing_profile' not found"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn external_auth_profile_not_allowed_on_deny_rule() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"

[policy.external_auth_profiles.example]
webhook_url = "https://auth.internal/start"
timeout_ms = 1000

[[policy.rules]]
action = "deny"
pattern = "https://example.com/**"
external_auth_profile = "example"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("external_auth_profile is not allowed on deny rules"),
            "unexpected error: {msg}"
        );
    }
}
