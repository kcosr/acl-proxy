use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

use http::header::{HeaderName, HeaderValue};
use ipnet::IpNet;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigEnvPlaceholder<'a> {
    None,
    Exact { name: &'a str },
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExternalAuthProfileType {
    Http,
    Plugin,
}

fn default_external_auth_profile_type() -> ExternalAuthProfileType {
    ExternalAuthProfileType::Http
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(skip)]
    pub load_warnings: Vec<String>,

    #[serde(default = "default_schema_version")]
    pub schema_version: String,

    #[serde(default)]
    pub proxy: ProxyConfig,

    #[serde(default)]
    pub logging: LoggingConfig,

    #[serde(default)]
    pub capture: CaptureConfig,

    #[serde(default)]
    pub redaction: RedactionConfig,

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
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    #[serde(default = "default_http_port")]
    pub http_port: u16,

    #[serde(default = "default_https_bind_address")]
    pub https_bind_address: String,

    #[serde(default = "default_https_port")]
    pub https_port: u16,

    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,

    #[serde(default = "default_https_handshake_timeout_ms")]
    pub https_handshake_timeout_ms: u64,

    #[serde(default = "default_https_request_header_timeout_ms")]
    pub https_request_header_timeout_ms: u64,

    #[serde(default = "default_https_max_connections")]
    pub https_max_connections: usize,

    #[serde(default = "default_https_http2_max_concurrent_streams")]
    pub https_http2_max_concurrent_streams: u32,

    #[serde(default = "default_internal_base_path")]
    pub internal_base_path: String,

    #[serde(default)]
    pub egress: ProxyEgressConfig,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            http_port: default_http_port(),
            https_bind_address: default_https_bind_address(),
            https_port: default_https_port(),
            request_timeout_ms: default_request_timeout_ms(),
            https_handshake_timeout_ms: default_https_handshake_timeout_ms(),
            https_request_header_timeout_ms: default_https_request_header_timeout_ms(),
            https_max_connections: default_https_max_connections(),
            https_http2_max_concurrent_streams: default_https_http2_max_concurrent_streams(),
            internal_base_path: default_internal_base_path(),
            egress: ProxyEgressConfig::default(),
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

fn default_request_timeout_ms() -> u64 {
    30_000
}

fn default_https_handshake_timeout_ms() -> u64 {
    10_000
}

fn default_https_request_header_timeout_ms() -> u64 {
    10_000
}

fn default_https_max_connections() -> usize {
    1024
}

fn default_https_http2_max_concurrent_streams() -> u32 {
    128
}

fn default_internal_base_path() -> String {
    "/_acl-proxy".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProxyEgressConfig {
    #[serde(default)]
    pub default: Option<EgressTargetConfig>,

    #[serde(default)]
    pub request_header_actions: Vec<EgressRequestHeaderActionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EgressTargetConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EgressRequestHeaderActionConfig {
    pub action: HeaderActionKind,
    pub name: String,

    #[serde(default)]
    pub when: HeaderWhen,

    // For set/add; allow value or values (but not both).
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub values: Option<Vec<String>>,
    #[serde(skip)]
    pub value_from_env: bool,
    #[serde(skip)]
    pub values_from_env: Vec<bool>,

    // For replace_substring.
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub replace: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default, deserialize_with = "deserialize_optional_path")]
    pub directory: Option<PathBuf>,

    #[serde(default = "default_logging_level")]
    pub level: String,

    #[serde(default = "default_logging_max_bytes")]
    pub max_bytes: u64,

    #[serde(default = "default_logging_max_files")]
    pub max_files: usize,

    #[serde(default = "default_logging_console")]
    pub console: bool,

    #[serde(default)]
    pub policy_decisions: LoggingPolicyDecisionsConfig,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            directory: None,
            level: default_logging_level(),
            max_bytes: default_logging_max_bytes(),
            max_files: default_logging_max_files(),
            console: default_logging_console(),
            policy_decisions: LoggingPolicyDecisionsConfig::default(),
        }
    }
}

fn default_logging_level() -> String {
    "info".to_string()
}

fn default_logging_max_bytes() -> u64 {
    104_857_600
}

fn default_logging_max_files() -> usize {
    5
}

fn default_logging_console() -> bool {
    true
}

fn deserialize_optional_path<'de, D>(deserializer: D) -> Result<Option<PathBuf>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(PathBuf::from(trimmed))
        }
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

    /// Maximum number of body bytes to store per captured request/response.
    ///
    /// The capture record still stores full logical body length in
    /// `body.length`; this limit only bounds bytes serialized in `body.data`.
    /// Set to `0` to skip body payload bytes while preserving metadata.
    #[serde(default = "default_capture_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Maximum regular files to keep in the capture directory.
    #[serde(default = "default_capture_max_files")]
    pub max_files: usize,

    /// Maximum total bytes of regular files to keep in the capture directory.
    #[serde(default = "default_capture_max_total_bytes")]
    pub max_total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RedactionConfig {
    #[serde(default)]
    pub profiles: std::collections::BTreeMap<String, RedactionProfileConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionProfileConfig {
    #[serde(default = "default_redaction_replacement")]
    pub replacement: String,

    #[serde(default = "default_max_request_body_bytes")]
    pub max_body_bytes: usize,

    #[serde(default = "default_max_decompressed_request_body_bytes")]
    pub max_decoded_body_bytes: usize,

    #[serde(default = "default_websocket_max_frame_bytes")]
    pub max_frame_bytes: usize,

    #[serde(default = "default_websocket_max_message_bytes")]
    pub max_message_bytes: usize,

    #[serde(default)]
    pub allow_permessage_deflate: bool,

    #[serde(default)]
    pub unsupported_extensions: RedactionUnsupportedExtensions,

    #[serde(default)]
    pub rules: Vec<RedactionRuleConfig>,
}

impl Default for RedactionProfileConfig {
    fn default() -> Self {
        Self {
            replacement: default_redaction_replacement(),
            max_body_bytes: default_max_request_body_bytes(),
            max_decoded_body_bytes: default_max_decompressed_request_body_bytes(),
            max_frame_bytes: default_websocket_max_frame_bytes(),
            max_message_bytes: default_websocket_max_message_bytes(),
            allow_permessage_deflate: false,
            unsupported_extensions: RedactionUnsupportedExtensions::default(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionRuleConfig {
    #[serde(default)]
    pub literals: Vec<String>,

    #[serde(default)]
    pub expressions: Vec<String>,

    #[serde(default, rename = "match")]
    pub match_mode: RedactionMatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RedactionUnsupportedExtensions {
    #[default]
    Deny,
    Strip,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RedactionMatch {
    #[default]
    Text,
    Binary,
    Both,
}

fn default_websocket_max_frame_bytes() -> usize {
    256 * 1024
}

fn default_websocket_max_message_bytes() -> usize {
    1024 * 1024
}

fn default_redaction_replacement() -> String {
    "[REDACTED]".to_string()
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
            max_body_bytes: default_capture_max_body_bytes(),
            max_files: default_capture_max_files(),
            max_total_bytes: default_capture_max_total_bytes(),
        }
    }
}

fn default_capture_directory() -> String {
    "logs-capture".to_string()
}

fn default_capture_filename() -> String {
    "{requestId}-{suffix}.json".to_string()
}

fn default_capture_max_body_bytes() -> usize {
    crate::capture::DEFAULT_MAX_BODY_BYTES
}

fn default_capture_max_files() -> usize {
    10_000
}

fn default_capture_max_total_bytes() -> u64 {
    1024 * 1024 * 1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

    #[serde(default)]
    pub persist_dynamic_certs: bool,
}

impl Default for CertificatesConfig {
    fn default() -> Self {
        Self {
            certs_dir: default_certs_dir(),
            ca_key_path: None,
            ca_cert_path: None,
            max_cached_certs: default_max_cached_certs(),
            persist_dynamic_certs: false,
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
#[serde(deny_unknown_fields)]
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
            load_warnings: Vec::new(),
            schema_version: default_schema_version(),
            proxy: ProxyConfig::default(),
            logging: LoggingConfig::default(),
            capture: CaptureConfig::default(),
            redaction: RedactionConfig::default(),
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyRuleAction {
    Allow,
    Deny,
    Delegate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRuleTemplateConfig {
    pub action: PolicyRuleAction,

    #[serde(default)]
    pub pattern: Option<String>,

    #[serde(default)]
    pub patterns: Option<Vec<String>>,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default)]
    pub methods: Option<MethodList>,

    #[serde(default)]
    pub subnets: Vec<IpNet>,

    #[serde(default)]
    pub headers_absent: Option<Vec<String>>,

    #[serde(default)]
    pub headers_match: Option<HeaderMatchMap>,

    #[serde(default)]
    pub headers_not_match: Option<HeaderMatchMap>,

    #[serde(default)]
    pub request_timeout_ms: Option<u64>,

    #[serde(default = "default_allow_upgrades")]
    pub allow_upgrades: bool,

    #[serde(default)]
    pub redaction_profile: Option<String>,

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
#[serde(deny_unknown_fields)]
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
    pub subnets: Vec<IpNet>,

    /// Optional override for the upstream request timeout (milliseconds).
    #[serde(default)]
    pub request_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRuleDirectConfig {
    pub action: PolicyRuleAction,

    #[serde(default)]
    pub pattern: Option<String>,

    #[serde(default)]
    pub patterns: Option<Vec<String>>,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default)]
    pub methods: Option<MethodList>,

    #[serde(default)]
    pub subnets: Vec<IpNet>,

    #[serde(default)]
    pub headers_absent: Option<Vec<String>>,

    #[serde(default)]
    pub headers_match: Option<HeaderMatchMap>,

    #[serde(default)]
    pub headers_not_match: Option<HeaderMatchMap>,

    #[serde(default)]
    pub request_timeout_ms: Option<u64>,

    #[serde(default = "default_allow_upgrades")]
    pub allow_upgrades: bool,

    #[serde(default)]
    pub redaction_profile: Option<String>,

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
#[allow(clippy::large_enum_variant)]
pub enum PolicyRuleConfig {
    Direct(PolicyRuleDirectConfig),
    Include(PolicyRuleIncludeConfig),
}

fn default_allow_upgrades() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
pub type HeaderMatchMap = std::collections::BTreeMap<String, HeaderMatchValueConfig>;

pub type ApprovalMacroConfigMap = std::collections::BTreeMap<String, ApprovalMacroConfig>;

pub type ExternalAuthProfileConfigMap =
    std::collections::BTreeMap<String, ExternalAuthProfileConfig>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ExternalAuthProfileConfig {
    #[serde(rename = "type", default = "default_external_auth_profile_type")]
    pub profile_type: ExternalAuthProfileType,

    #[serde(default)]
    pub webhook_url: Option<String>,
    pub timeout_ms: u64,

    #[serde(default)]
    pub webhook_timeout_ms: Option<u64>,

    #[serde(default)]
    pub on_webhook_failure: Option<ExternalAuthWebhookFailureMode>,

    #[serde(default)]
    pub command: Option<String>,

    #[serde(default)]
    pub args: Vec<String>,

    #[serde(default)]
    pub include_headers: Vec<String>,

    #[serde(default)]
    pub include_request_body: bool,

    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,

    #[serde(default = "default_max_decompressed_request_body_bytes")]
    pub max_decompressed_request_body_bytes: usize,

    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,

    #[serde(default)]
    pub restart_delay_ms: Option<u64>,
}

fn default_max_request_body_bytes() -> usize {
    10 * 1024 * 1024
}

fn default_max_decompressed_request_body_bytes() -> usize {
    50 * 1024 * 1024
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HeaderDirection {
    Request,
    Response,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HeaderActionKind {
    Remove,
    Set,
    Add,
    ReplaceSubstring,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    #[serde(skip)]
    pub value_from_env: bool,
    #[serde(skip)]
    pub values_from_env: Vec<bool>,

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HeaderMatchValueConfig {
    Single(String),
    Many(Vec<String>),
}

impl HeaderMatchValueConfig {
    pub fn values(&self) -> Vec<String> {
        match self {
            HeaderMatchValueConfig::Single(value) => vec![value.clone()],
            HeaderMatchValueConfig::Many(values) => values.clone(),
        }
    }
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
        config.interpolate_header_action_env_vars()?;
        config.interpolate_redaction_env_vars()?;
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

    fn interpolate_header_action_env_vars(&mut self) -> Result<(), ConfigError> {
        for (rule_idx, rule) in self.policy.rules.iter_mut().enumerate() {
            let PolicyRuleConfig::Direct(rule) = rule else {
                continue;
            };

            let rule_location = format_direct_rule_location(rule_idx);
            interpolate_header_actions(&mut rule.header_actions, rule_location.as_str())?;
        }

        for (ruleset_name, rules) in self.policy.rulesets.iter_mut() {
            for (rule_idx, rule) in rules.iter_mut().enumerate() {
                let rule_location = format_ruleset_template_location(ruleset_name, rule_idx);
                interpolate_header_actions(&mut rule.header_actions, rule_location.as_str())?;
            }
        }

        interpolate_egress_request_header_actions(&mut self.proxy.egress.request_header_actions)?;

        Ok(())
    }

    fn interpolate_redaction_env_vars(&mut self) -> Result<(), ConfigError> {
        let load_warnings = &mut self.load_warnings;

        for (profile_name, profile) in self.redaction.profiles.iter_mut() {
            interpolate_redaction_env_value(
                &mut profile.replacement,
                format!("redaction.profiles.{profile_name}.replacement").as_str(),
                load_warnings,
            )?;

            for (rule_idx, rule) in profile.rules.iter_mut().enumerate() {
                for (literal_idx, literal) in rule.literals.iter_mut().enumerate() {
                    interpolate_redaction_env_value(
                        literal,
                        format!(
                            "redaction.profiles.{profile_name}.rules[{rule_idx}].literals[{literal_idx}]"
                        )
                        .as_str(),
                        load_warnings,
                    )?;
                }
            }
        }

        Ok(())
    }

    pub(crate) fn validate_basic(&self) -> Result<(), ConfigError> {
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
                    d.pattern.is_some()
                        || d.patterns.is_some()
                        || !d.subnets.is_empty()
                        || d.methods.is_some()
                        || d.headers_absent.is_some()
                        || d.headers_match.is_some()
                        || d.headers_not_match.is_some()
                }
                PolicyRuleConfig::Include(i) => !i.include.trim().is_empty(),
            };

            if !has_match_criteria {
                return Err(ConfigError::Invalid(format!(
                    "policy.rules[{idx}] must specify at least one of pattern, patterns, subnets, methods, headers_absent, headers_match, headers_not_match, or include"
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

        validate_proxy_config(&self.proxy)?;
        validate_loop_protection_config(&self.loop_protection)?;

        // Validate policy semantics (macros, rulesets, includes).
        crate::policy::PolicyEngine::from_config(&self.policy)
            .map_err(|e| ConfigError::Invalid(format!("{e}")))?;

        validate_logging_config(&self.logging)?;
        validate_capture_config(&self.capture)?;
        validate_redaction_config(&self.redaction)?;
        validate_redaction_policy_refs(&self.policy, &self.redaction)?;
        validate_external_auth_config(&self.external_auth)?;
        validate_external_auth_profiles(&self.policy.external_auth_profiles)?;

        Ok(())
    }
}

fn interpolate_header_actions(
    header_actions: &mut [HeaderActionConfig],
    rule_location: &str,
) -> Result<(), ConfigError> {
    for (header_action_idx, header_action) in header_actions.iter_mut().enumerate() {
        if !matches!(
            header_action.action,
            HeaderActionKind::Set | HeaderActionKind::Add
        ) {
            continue;
        }

        let action_location = format_header_action_location(
            rule_location,
            header_action_idx,
            header_action.name.as_str(),
        );

        if let Some(value) = header_action.value.as_mut() {
            header_action.value_from_env =
                interpolate_header_action_value(value, action_location.as_str())?;
        } else {
            header_action.value_from_env = false;
        }

        if let Some(values) = header_action.values.as_mut() {
            let mut values_from_env = Vec::with_capacity(values.len());
            for value in values.iter_mut() {
                values_from_env.push(interpolate_header_action_value(
                    value,
                    action_location.as_str(),
                )?);
            }
            header_action.values_from_env = values_from_env;
        } else {
            header_action.values_from_env.clear();
        }
    }

    Ok(())
}

fn interpolate_egress_request_header_actions(
    header_actions: &mut [EgressRequestHeaderActionConfig],
) -> Result<(), ConfigError> {
    for (header_action_idx, header_action) in header_actions.iter_mut().enumerate() {
        if !matches!(
            header_action.action,
            HeaderActionKind::Set | HeaderActionKind::Add
        ) {
            continue;
        }

        let action_location = format_egress_request_header_action_location(
            header_action_idx,
            header_action.name.as_str(),
        );

        if let Some(value) = header_action.value.as_mut() {
            header_action.value_from_env =
                interpolate_header_action_value(value, action_location.as_str())?;
        } else {
            header_action.value_from_env = false;
        }

        if let Some(values) = header_action.values.as_mut() {
            let mut values_from_env = Vec::with_capacity(values.len());
            for value in values.iter_mut() {
                values_from_env.push(interpolate_header_action_value(
                    value,
                    action_location.as_str(),
                )?);
            }
            header_action.values_from_env = values_from_env;
        } else {
            header_action.values_from_env.clear();
        }
    }

    Ok(())
}

fn interpolate_header_action_value(
    raw_value: &mut String,
    action_location: &str,
) -> Result<bool, ConfigError> {
    interpolate_config_env_value(raw_value, action_location)
}

fn interpolate_redaction_env_value(
    raw_value: &mut String,
    value_location: &str,
    load_warnings: &mut Vec<String>,
) -> Result<(), ConfigError> {
    if has_incomplete_config_env_marker(raw_value) {
        load_warnings.push(format!(
            "{value_location} contains '${{' but is not a complete placeholder; treating as literal text"
        ));
    }

    interpolate_config_env_value(raw_value, value_location)?;
    Ok(())
}

fn interpolate_config_env_value(
    raw_value: &mut String,
    value_location: &str,
) -> Result<bool, ConfigError> {
    match classify_config_env_placeholder(raw_value.as_str()) {
        ConfigEnvPlaceholder::None => Ok(false),
        ConfigEnvPlaceholder::Invalid => Err(ConfigError::Invalid(format!(
            "{value_location} uses invalid env interpolation syntax"
        ))),
        ConfigEnvPlaceholder::Exact { name } => {
            *raw_value = env::var(name).map_err(|_| {
                ConfigError::Invalid(format!(
                    "{value_location} references missing env var '{name}'"
                ))
            })?;
            Ok(true)
        }
    }
}

fn has_incomplete_config_env_marker(raw_value: &str) -> bool {
    let Some(open_idx) = raw_value.find("${") else {
        return false;
    };

    !raw_value[open_idx + 2..].contains('}')
}

fn classify_config_env_placeholder(raw_value: &str) -> ConfigEnvPlaceholder<'_> {
    let Some(open_idx) = raw_value.find("${") else {
        return ConfigEnvPlaceholder::None;
    };

    if !raw_value[open_idx + 2..].contains('}') {
        return ConfigEnvPlaceholder::None;
    }

    let Some(name) = raw_value
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return ConfigEnvPlaceholder::Invalid;
    };

    if name.is_empty() {
        return ConfigEnvPlaceholder::Invalid;
    }

    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return ConfigEnvPlaceholder::Invalid;
    };

    if !matches!(first, 'A'..='Z' | 'a'..='z' | '_') {
        return ConfigEnvPlaceholder::Invalid;
    }

    if !chars.all(|ch| matches!(ch, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_')) {
        return ConfigEnvPlaceholder::Invalid;
    }

    ConfigEnvPlaceholder::Exact { name }
}

fn format_direct_rule_location(rule_idx: usize) -> String {
    format!("policy.rules[{rule_idx}]")
}

fn format_ruleset_template_location(ruleset_name: &str, rule_idx: usize) -> String {
    format!("policy.rulesets.{ruleset_name}[{rule_idx}]")
}

fn format_header_action_location(
    rule_location: &str,
    header_action_idx: usize,
    header_name: &str,
) -> String {
    format!("{rule_location}.header_actions[{header_action_idx}] for header '{header_name}'")
}

fn format_egress_request_header_action_location(
    header_action_idx: usize,
    header_name: &str,
) -> String {
    format!("proxy.egress.request_header_actions[{header_action_idx}] for header '{header_name}'")
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
request_timeout_ms = 30000
https_handshake_timeout_ms = 10000
https_request_header_timeout_ms = 10000
https_max_connections = 1024
https_http2_max_concurrent_streams = 128
internal_base_path = "/_acl-proxy"

[logging]
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

fn validate_proxy_config(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    let bind_ip = parse_bind_address("proxy.bind_address", &proxy.bind_address)?;
    let https_bind_ip = parse_bind_address("proxy.https_bind_address", &proxy.https_bind_address)?;

    if proxy.http_port != 0
        && proxy.https_port != 0
        && proxy.http_port == proxy.https_port
        && listener_bind_addresses_overlap(bind_ip, https_bind_ip)
    {
        return Err(ConfigError::Invalid(format!(
            "proxy.http_port and proxy.https_port must not both be {} when bind addresses overlap",
            proxy.http_port
        )));
    }

    validate_internal_base_path(&proxy.internal_base_path)?;

    if let Some(target) = proxy.egress.default.as_ref() {
        validate_egress_target(target)?;
    }

    validate_egress_request_header_action_list(&proxy.egress.request_header_actions)?;

    Ok(())
}

fn parse_bind_address(location: &str, value: &str) -> Result<IpAddr, ConfigError> {
    value.parse::<IpAddr>().map_err(|err| {
        ConfigError::Invalid(format!("{location} must be a valid IP address: {err}"))
    })
}

fn listener_bind_addresses_overlap(left: IpAddr, right: IpAddr) -> bool {
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => {
            left == right || left.is_unspecified() || right.is_unspecified()
        }
        (IpAddr::V6(left), IpAddr::V6(right)) => {
            left == right || left.is_unspecified() || right.is_unspecified()
        }
        _ => false,
    }
}

fn validate_loop_protection_config(
    loop_protection: &LoopProtectionConfig,
) -> Result<(), ConfigError> {
    let raw = loop_protection.header_name.trim();
    if raw.is_empty() {
        return Err(ConfigError::Invalid(
            "loop_protection.header_name must not be empty".to_string(),
        ));
    }

    HeaderName::from_bytes(raw.as_bytes()).map_err(|_| {
        ConfigError::Invalid(format!(
            "loop_protection.header_name must be a valid HTTP header name: {raw}"
        ))
    })?;

    Ok(())
}

fn validate_egress_target(target: &EgressTargetConfig) -> Result<(), ConfigError> {
    validate_egress_host(&target.host)?;

    if target.port == 0 {
        return Err(ConfigError::Invalid(
            "proxy.egress.default.port must be in the inclusive range 1..65535".to_string(),
        ));
    }

    Ok(())
}

fn validate_egress_host(host: &str) -> Result<(), ConfigError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::Invalid(
            "proxy.egress.default.host must not be empty".to_string(),
        ));
    }
    if trimmed != host {
        return Err(ConfigError::Invalid(
            "proxy.egress.default.host must not include leading or trailing whitespace".to_string(),
        ));
    }

    if trimmed.starts_with('[') || trimmed.ends_with(']') {
        let inner = trimmed
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .ok_or_else(|| {
                ConfigError::Invalid(
                    "proxy.egress.default.host must be a valid DNS hostname or IP literal without a port suffix"
                        .to_string(),
                )
            })?;

        return inner.parse::<IpAddr>().map(|_| ()).map_err(|_| {
            ConfigError::Invalid(
                "proxy.egress.default.host must be a valid DNS hostname or IP literal without a port suffix"
                    .to_string(),
            )
        });
    }

    if trimmed.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    if trimmed.contains(':') {
        return Err(ConfigError::Invalid(
            "proxy.egress.default.host must not include a port suffix".to_string(),
        ));
    }

    url::Host::parse(trimmed).map(|_| ()).map_err(|_| {
        ConfigError::Invalid(
            "proxy.egress.default.host must be a valid DNS hostname or IP literal without a port suffix"
                .to_string(),
        )
    })
}

fn validate_egress_request_header_action_list(
    actions: &[EgressRequestHeaderActionConfig],
) -> Result<(), ConfigError> {
    for (idx, action) in actions.iter().enumerate() {
        validate_egress_request_header_action(action, idx)?;
    }

    Ok(())
}

fn validate_egress_request_header_action(
    action_cfg: &EgressRequestHeaderActionConfig,
    index: usize,
) -> Result<(), ConfigError> {
    let location = format_egress_request_header_action_location(index, action_cfg.name.as_str());

    HeaderName::from_lowercase(action_cfg.name.to_ascii_lowercase().as_bytes()).map_err(|e| {
        ConfigError::Invalid(format!(
            "{location} has invalid header name '{}': {e}",
            action_cfg.name
        ))
    })?;

    match action_cfg.action {
        HeaderActionKind::Set | HeaderActionKind::Add => {
            let source_values = match (&action_cfg.value, &action_cfg.values) {
                (Some(v), None) => vec![v.clone()],
                (None, Some(vs)) if !vs.is_empty() => vs.clone(),
                (Some(_), Some(_)) => {
                    return Err(ConfigError::Invalid(format!(
                        "{location} must not set both value and values"
                    )));
                }
                _ => {
                    return Err(ConfigError::Invalid(format!(
                        "{location} must provide value or values"
                    )));
                }
            };

            for value in source_values {
                HeaderValue::from_str(&value).map_err(|e| {
                    ConfigError::Invalid(format!("{location} has invalid header value: {e}"))
                })?;
            }
        }
        HeaderActionKind::Remove | HeaderActionKind::ReplaceSubstring => {
            if action_cfg.value.is_some() || action_cfg.values.is_some() {
                return Err(ConfigError::Invalid(format!(
                    "{location} with action {:?} must not set value/values",
                    action_cfg.action
                )));
            }
        }
    }

    if matches!(action_cfg.action, HeaderActionKind::ReplaceSubstring) {
        let Some(search) = action_cfg.search.as_deref() else {
            return Err(ConfigError::Invalid(format!(
                "{location} with action replace_substring requires search"
            )));
        };
        if search.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "{location} with action replace_substring requires non-empty search"
            )));
        }
        if action_cfg.replace.is_none() {
            return Err(ConfigError::Invalid(format!(
                "{location} with action replace_substring requires replace"
            )));
        }
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

    validate_capture_filename_template(&capture.filename)?;

    if capture.max_files == 0 {
        return Err(ConfigError::Invalid(
            "capture.max_files must be at least 1".to_string(),
        ));
    }

    if capture.max_total_bytes == 0 {
        return Err(ConfigError::Invalid(
            "capture.max_total_bytes must be at least 1".to_string(),
        ));
    }

    Ok(())
}

fn validate_capture_filename_template(filename: &str) -> Result<(), ConfigError> {
    let template = filename.trim();
    if template.is_empty() {
        return Ok(());
    }

    if template.contains('/') || template.contains('\\') {
        return Err(ConfigError::Invalid(
            "capture.filename must be a filename template, not a path".to_string(),
        ));
    }

    let mut components = Path::new(template).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(ConfigError::Invalid(
            "capture.filename must be a filename template, not a path".to_string(),
        )),
    }
}

fn validate_redaction_config(config: &RedactionConfig) -> Result<(), ConfigError> {
    for (profile_name, profile) in &config.profiles {
        if profile.max_body_bytes == 0 {
            return Err(ConfigError::Invalid(format!(
                "redaction.profiles.{profile_name}.max_body_bytes must be at least 1"
            )));
        }
        if profile.max_decoded_body_bytes == 0 {
            return Err(ConfigError::Invalid(format!(
                "redaction.profiles.{profile_name}.max_decoded_body_bytes must be at least 1"
            )));
        }
        if profile.max_frame_bytes == 0 {
            return Err(ConfigError::Invalid(format!(
                "redaction.profiles.{profile_name}.max_frame_bytes must be at least 1"
            )));
        }
        if profile.max_message_bytes == 0 {
            return Err(ConfigError::Invalid(format!(
                "redaction.profiles.{profile_name}.max_message_bytes must be at least 1"
            )));
        }
        if profile.rules.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "redaction.profiles.{profile_name}.rules must include at least one rule"
            )));
        }

        for (rule_idx, rule) in profile.rules.iter().enumerate() {
            if rule.literals.is_empty() && rule.expressions.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "redaction.profiles.{profile_name}.rules[{rule_idx}] must include at least one literal or expression"
                )));
            }
            for (literal_idx, literal) in rule.literals.iter().enumerate() {
                if literal.is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "redaction.profiles.{profile_name}.rules[{rule_idx}].literals[{literal_idx}] must not be empty"
                    )));
                }
            }
            for (expression_idx, expression) in rule.expressions.iter().enumerate() {
                if matches!(rule.match_mode, RedactionMatch::Binary) {
                    return Err(ConfigError::Invalid(format!(
                        "redaction.profiles.{profile_name}.rules[{rule_idx}].expressions[{expression_idx}] cannot be used with match = \"binary\""
                    )));
                }
                if expression.is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "redaction.profiles.{profile_name}.rules[{rule_idx}].expressions[{expression_idx}] must not be empty"
                    )));
                }
                let regex = Regex::new(expression).map_err(|_| {
                    ConfigError::Invalid(format!(
                        "redaction.profiles.{profile_name}.rules[{rule_idx}].expressions[{expression_idx}] is not a valid regex"
                    ))
                })?;
                if regex.find("").is_some_and(|matched| matched.is_empty()) {
                    return Err(ConfigError::Invalid(format!(
                        "redaction.profiles.{profile_name}.rules[{rule_idx}].expressions[{expression_idx}] must not match empty text"
                    )));
                }
            }
        }
    }

    Ok(())
}

fn validate_redaction_policy_refs(
    policy: &PolicyConfig,
    redaction: &RedactionConfig,
) -> Result<(), ConfigError> {
    for (idx, rule) in policy.rules.iter().enumerate() {
        if let PolicyRuleConfig::Direct(rule) = rule {
            validate_redaction_rule_ref(
                &format!("policy.rules[{idx}]"),
                rule.action,
                rule.redaction_profile.as_deref(),
                redaction,
            )?;
        }
    }

    for (ruleset_name, rules) in &policy.rulesets {
        for (idx, rule) in rules.iter().enumerate() {
            validate_redaction_rule_ref(
                &format!("policy.rulesets.{ruleset_name}[{idx}]"),
                rule.action,
                rule.redaction_profile.as_deref(),
                redaction,
            )?;
        }
    }

    Ok(())
}

fn validate_redaction_rule_ref(
    location: &str,
    action: PolicyRuleAction,
    profile: Option<&str>,
    redaction: &RedactionConfig,
) -> Result<(), ConfigError> {
    let Some(profile) = profile else {
        return Ok(());
    };

    if matches!(action, PolicyRuleAction::Deny) {
        return Err(ConfigError::Invalid(format!(
            "{location}.redaction_profile is only allowed on allow or delegate rules"
        )));
    }

    if !redaction.profiles.contains_key(profile) {
        return Err(ConfigError::Invalid(format!(
            "{location}.redaction_profile references unknown profile '{profile}'"
        )));
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

fn validate_external_auth_profiles(
    profiles: &ExternalAuthProfileConfigMap,
) -> Result<(), ConfigError> {
    for (name, profile) in profiles {
        if profile.timeout_ms == 0 {
            return Err(ConfigError::Invalid(format!(
                "external_auth_profiles.{name}.timeout_ms must be at least 1"
            )));
        }
        if matches!(profile.webhook_timeout_ms, Some(0)) {
            return Err(ConfigError::Invalid(format!(
                "external_auth_profiles.{name}.webhook_timeout_ms must be at least 1 when set"
            )));
        }

        match profile.profile_type {
            ExternalAuthProfileType::Http => {
                if profile.include_request_body {
                    return Err(ConfigError::Invalid(format!(
                        "external_auth_profiles.{name}.include_request_body is only supported for type=plugin"
                    )));
                }
                let raw = profile.webhook_url.as_deref().map(str::trim).unwrap_or("");
                if raw.is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "external_auth_profiles.{name}.webhook_url must not be empty for type=http"
                    )));
                }
                let parsed = Url::parse(raw).map_err(|e| {
                    ConfigError::Invalid(format!(
                        "external_auth_profiles.{name}.webhook_url is not a valid URL: {e}"
                    ))
                })?;
                if !parsed.has_host() {
                    return Err(ConfigError::Invalid(format!(
                        "external_auth_profiles.{name}.webhook_url must be an absolute URL with host"
                    )));
                }
            }
            ExternalAuthProfileType::Plugin => {
                let cmd = profile.command.as_deref().map(str::trim).unwrap_or("");
                if cmd.is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "external_auth_profiles.{name}.command must not be empty for type=plugin"
                    )));
                }
                for pattern in &profile.include_headers {
                    validate_header_pattern(name, pattern)?;
                }
                if profile.include_request_body {
                    if profile.max_request_body_bytes == 0 {
                        return Err(ConfigError::Invalid(format!(
                            "external_auth_profiles.{name}.max_request_body_bytes must be at least 1 when include_request_body is true"
                        )));
                    }
                    if profile.max_decompressed_request_body_bytes == 0 {
                        return Err(ConfigError::Invalid(format!(
                            "external_auth_profiles.{name}.max_decompressed_request_body_bytes must be at least 1 when include_request_body is true"
                        )));
                    }
                }
            }
        }
    }

    Ok(())
}

fn validate_header_pattern(profile: &str, pattern: &str) -> Result<(), ConfigError> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "external_auth_profiles.{profile}.include_headers entries must not be empty"
        )));
    }
    if trimmed.chars().any(|c| c.is_whitespace()) {
        return Err(ConfigError::Invalid(format!(
            "external_auth_profiles.{profile}.include_headers entries must not contain whitespace"
        )));
    }
    Ok(())
}

fn validate_internal_base_path(path: &str) -> Result<(), ConfigError> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::Invalid(
            "proxy.internal_base_path must not be empty".to_string(),
        ));
    }
    if trimmed != path {
        return Err(ConfigError::Invalid(
            "proxy.internal_base_path must not include leading or trailing whitespace".to_string(),
        ));
    }
    if !trimmed.starts_with('/') {
        return Err(ConfigError::Invalid(
            "proxy.internal_base_path must start with '/'".to_string(),
        ));
    }
    if trimmed.len() > 1 && trimmed.ends_with('/') {
        return Err(ConfigError::Invalid(
            "proxy.internal_base_path must not end with '/'".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PolicyDefaultAction;
    use std::io::Write;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    static CONFIG_ENV_TEST_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

    struct ConfigEnvTestGuard {
        _lock: MutexGuard<'static, ()>,
        saved_vars: Vec<(String, Option<String>)>,
    }

    impl ConfigEnvTestGuard {
        fn new(keys: &[&str]) -> Self {
            let lock = CONFIG_ENV_TEST_MUTEX
                .get_or_init(|| Mutex::new(()))
                .lock()
                .expect("lock env test mutex");

            let mut saved_vars = Vec::with_capacity(keys.len());
            for key in keys {
                saved_vars.push(((*key).to_string(), env::var(key).ok()));
            }

            Self {
                _lock: lock,
                saved_vars,
            }
        }

        fn set(&self, key: &str, value: &str) {
            #[allow(unused_unsafe)]
            unsafe {
                env::set_var(key, value);
            }
        }

        fn remove(&self, key: &str) {
            #[allow(unused_unsafe)]
            unsafe {
                env::remove_var(key);
            }
        }
    }

    impl Drop for ConfigEnvTestGuard {
        fn drop(&mut self) {
            for (key, saved_value) in self.saved_vars.iter().rev() {
                match saved_value {
                    Some(value) => {
                        #[allow(unused_unsafe)]
                        unsafe {
                            env::set_var(key, value);
                        }
                    }
                    None => {
                        #[allow(unused_unsafe)]
                        unsafe {
                            env::remove_var(key);
                        }
                    }
                }
            }
        }
    }

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
    fn unknown_section_fields_are_rejected() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_ports = 8080

[policy]
default = "deny"
        "#;

        let err = toml::from_str::<Config>(toml).expect_err("unknown field should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown field") && msg.contains("http_ports"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn policy_rule_typo_fields_are_rejected() {
        let toml = r#"
schema_version = "1"

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "https://example.com/**"
method = "GET"
        "#;

        let err = toml::from_str::<Config>(toml).expect_err("unknown rule field should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown field") || msg.contains("data did not match any variant"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn ruleset_template_typo_fields_are_rejected() {
        let toml = r#"
schema_version = "1"

[policy]
default = "deny"

[[policy.rules]]
include = "restricted"

[[policy.rulesets.restricted]]
action = "allow"
pattern = "https://example.com/**"
subnet = "10.0.0.0/8"
        "#;

        let err = toml::from_str::<Config>(toml).expect_err("unknown template field should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown field") && msg.contains("subnet"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn redaction_profile_reference_validates() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "debug"

	[redaction.profiles.secrets]
	replacement = "[REDACTED]"
	max_body_bytes = 2048
	max_decoded_body_bytes = 8192
	max_frame_bytes = 1024
	max_message_bytes = 4096
	allow_permessage_deflate = true
	unsupported_extensions = "strip"
	
	[[redaction.profiles.secrets.rules]]
	literals = ["password", "token"]
	expressions = ["(?i)bearer\\s+[a-z0-9._-]+"]
	match = "text"

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "https://example.com/ws/**"
redaction_profile = "secrets"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        config
            .validate_basic()
            .expect("valid websocket redaction profile should pass");
        let profile = config.redaction.profiles.get("secrets").expect("profile");
        assert_eq!(profile.replacement, "[REDACTED]");
        assert_eq!(profile.max_body_bytes, 2048);
        assert_eq!(profile.max_decoded_body_bytes, 8192);
        assert!(profile.allow_permessage_deflate);
        assert!(matches!(
            profile.unsupported_extensions,
            RedactionUnsupportedExtensions::Strip
        ));
    }

    #[test]
    fn redaction_profile_reference_must_exist() {
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

[[policy.rules]]
action = "allow"
pattern = "https://example.com/ws/**"
redaction_profile = "missing"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("references unknown profile 'missing'"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn redaction_profile_is_invalid_on_deny_rules() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "debug"

	[redaction.profiles.secrets]
	replacement = "[REDACTED]"
	
	[[redaction.profiles.secrets.rules]]
	literals = ["password"]

[policy]
default = "allow"

[[policy.rules]]
action = "deny"
pattern = "https://example.com/ws/**"
redaction_profile = "secrets"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("redaction_profile is only allowed on allow or delegate rules"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn redaction_expression_must_compile() {
        let toml = r#"
	schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "debug"

	[redaction.profiles.secrets]
	
	[[redaction.profiles.secrets.rules]]
	expressions = ["["]
	
	[policy]
	default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("is not a valid regex"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn redaction_expression_is_invalid_for_binary_only_rule() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "debug"

[redaction.profiles.secrets]

[[redaction.profiles.secrets.rules]]
expressions = ["token-[0-9]+"]
match = "binary"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("cannot be used with match = \"binary\""),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn redaction_expression_must_not_match_empty_text() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "debug"

[redaction.profiles.secrets]

[[redaction.profiles.secrets.rules]]
expressions = ["a*"]

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("must not match empty text"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn redaction_env_interpolation_resolves_replacement_and_literals() {
        let env_guard = ConfigEnvTestGuard::new(&[
            "ACL_PROXY_TEST_REDACTION_REPLACEMENT",
            "ACL_PROXY_TEST_REDACTION_LITERAL",
        ]);
        env_guard.set("ACL_PROXY_TEST_REDACTION_REPLACEMENT", "[MASKED]");
        env_guard.set("ACL_PROXY_TEST_REDACTION_LITERAL", "secret-token");

        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "debug"

[redaction.profiles.secrets]
replacement = "${ACL_PROXY_TEST_REDACTION_REPLACEMENT}"

[[redaction.profiles.secrets.rules]]
literals = ["${ACL_PROXY_TEST_REDACTION_LITERAL}", "static-secret"]
match = "text"

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "https://example.com/**"
redaction_profile = "secrets"
        "#;

        let mut config: Config = toml::from_str(toml).expect("parse config");
        config
            .interpolate_redaction_env_vars()
            .expect("interpolation should succeed");
        config.validate_basic().expect("config should validate");

        let profile = config.redaction.profiles.get("secrets").expect("profile");
        assert_eq!(profile.replacement, "[MASKED]");
        assert_eq!(
            profile.rules[0].literals,
            vec!["secret-token".to_string(), "static-secret".to_string()]
        );
    }

    #[test]
    fn redaction_env_interpolation_reports_missing_literal_env_var() {
        let env_guard = ConfigEnvTestGuard::new(&["ACL_PROXY_TEST_MISSING_REDACTION"]);
        env_guard.remove("ACL_PROXY_TEST_MISSING_REDACTION");

        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "debug"

[redaction.profiles.secrets]

[[redaction.profiles.secrets.rules]]
literals = ["${ACL_PROXY_TEST_MISSING_REDACTION}"]

[policy]
default = "deny"
        "#;

        let mut config: Config = toml::from_str(toml).expect("parse config");
        let err = config
            .interpolate_redaction_env_vars()
            .expect_err("missing env var should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains(
                "redaction.profiles.secrets.rules[0].literals[0] references missing env var 'ACL_PROXY_TEST_MISSING_REDACTION'"
            ),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn redaction_env_interpolation_rejects_mixed_literal_placeholder() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "debug"

[redaction.profiles.secrets]

[[redaction.profiles.secrets.rules]]
literals = ["secret-prefix-${ACL_PROXY_TEST_REDACTION_LITERAL}"]

[policy]
default = "deny"
        "#;

        let mut config: Config = toml::from_str(toml).expect("parse config");
        let err = config
            .interpolate_redaction_env_vars()
            .expect_err("mixed placeholder should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains(
                "redaction.profiles.secrets.rules[0].literals[0] uses invalid env interpolation syntax"
            ),
            "unexpected error message: {msg}"
        );
        assert!(
            !msg.contains("secret-prefix"),
            "error message should not echo redaction literal: {msg}"
        );
    }

    #[test]
    fn load_from_sources_resolves_redaction_env_placeholders() {
        let env_guard = ConfigEnvTestGuard::new(&[
            "ACL_PROXY_TEST_LOAD_REDACTION_REPLACEMENT",
            "ACL_PROXY_TEST_LOAD_REDACTION_LITERAL",
        ]);
        env_guard.set("ACL_PROXY_TEST_LOAD_REDACTION_REPLACEMENT", "[MASKED]");
        env_guard.set("ACL_PROXY_TEST_LOAD_REDACTION_LITERAL", "load-secret");

        let mut file = tempfile::NamedTempFile::new().expect("create temp config");
        write!(
            file,
            r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[redaction.profiles.secrets]
replacement = "${{ACL_PROXY_TEST_LOAD_REDACTION_REPLACEMENT}}"

[[redaction.profiles.secrets.rules]]
literals = ["${{ACL_PROXY_TEST_LOAD_REDACTION_LITERAL}}"]

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "https://example.com/**"
redaction_profile = "secrets"
            "#
        )
        .expect("write config");

        let config = Config::load_from_sources(Some(file.path()))
            .expect("load should resolve redaction placeholders");
        let profile = config.redaction.profiles.get("secrets").expect("profile");
        assert_eq!(profile.replacement, "[MASKED]");
        assert_eq!(profile.rules[0].literals, vec!["load-secret".to_string()]);
    }

    #[test]
    fn load_from_sources_preserves_incomplete_redaction_env_marker_literals() {
        let mut file = tempfile::NamedTempFile::new().expect("create temp config");
        write!(
            file,
            r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[redaction.profiles.secrets]

[[redaction.profiles.secrets.rules]]
literals = ["pass${{word"]

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "https://example.com/**"
redaction_profile = "secrets"
            "#
        )
        .expect("write config");

        let config = Config::load_from_sources(Some(file.path()))
            .expect("load should preserve incomplete marker literal");
        let profile = config.redaction.profiles.get("secrets").expect("profile");
        assert_eq!(profile.rules[0].literals, vec!["pass${word".to_string()]);
        assert_eq!(
            config.load_warnings,
            vec![
                "redaction.profiles.secrets.rules[0].literals[0] contains '${' but is not a complete placeholder; treating as literal text"
                    .to_string()
            ]
        );
    }

    #[test]
    fn proxy_internal_base_path_parse() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080
internal_base_path = "/internal"

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        assert_eq!(config.proxy.internal_base_path, "/internal");
    }

    #[test]
    fn proxy_egress_default_is_optional() {
        let config = Config::default();
        assert!(config.proxy.egress.default.is_none());
    }

    #[test]
    fn proxy_transparent_https_slow_client_limits_default_and_parse() {
        let default = ProxyConfig::default();
        assert_eq!(default.https_handshake_timeout_ms, 10_000);
        assert_eq!(default.https_request_header_timeout_ms, 10_000);
        assert_eq!(default.https_max_connections, 1024);
        assert_eq!(default.https_http2_max_concurrent_streams, 128);

        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080
https_handshake_timeout_ms = 250
https_request_header_timeout_ms = 500
https_max_connections = 8
https_http2_max_concurrent_streams = 16

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        assert_eq!(config.proxy.https_handshake_timeout_ms, 250);
        assert_eq!(config.proxy.https_request_header_timeout_ms, 500);
        assert_eq!(config.proxy.https_max_connections, 8);
        assert_eq!(config.proxy.https_http2_max_concurrent_streams, 16);
        config.validate_basic().expect("config should validate");
    }

    #[test]
    fn proxy_listener_bind_addresses_must_parse() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "localhost"
http_port = 8080

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("proxy.bind_address must be a valid IP address"),
            "unexpected error: {msg}"
        );

        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080
https_bind_address = "not-an-ip"
https_port = 8443

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("proxy.https_bind_address must be a valid IP address"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn proxy_listener_ports_must_not_collide_on_overlapping_binds() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "0.0.0.0"
http_port = 8443
https_bind_address = "127.0.0.1"
https_port = 8443

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("proxy.http_port and proxy.https_port must not both be 8443"),
            "unexpected error: {msg}"
        );

        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8443
https_bind_address = "127.0.0.2"
https_port = 8443

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        config
            .validate_basic()
            .expect("distinct listener bind addresses may share a port");
    }

    #[test]
    fn loop_protection_header_name_is_validated() {
        let toml = r#"
schema_version = "1"

[loop_protection]
header_name = "invalid header"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("loop_protection.header_name must be a valid HTTP header name"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn proxy_egress_default_parses_when_valid() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[proxy.egress.default]
host = "proxy.internal"
port = 9443

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let target = config
            .proxy
            .egress
            .default
            .as_ref()
            .expect("egress target should exist");
        assert_eq!(target.host, "proxy.internal");
        assert_eq!(target.port, 9443);
        config
            .validate_basic()
            .expect("valid egress target should pass validation");
    }

    #[test]
    fn proxy_egress_request_header_actions_default_to_empty() {
        let config = Config::default();
        assert!(config.proxy.egress.request_header_actions.is_empty());
    }

    #[test]
    fn proxy_egress_request_header_actions_parse_when_valid() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[[proxy.egress.request_header_actions]]
action = "remove"
name = "x-aw-identity-token"
when = "if_present"

[[proxy.egress.request_header_actions]]
action = "set"
name = "x-egress-tag"
value = "edge-a"

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        assert_eq!(config.proxy.egress.request_header_actions.len(), 2);
        config
            .validate_basic()
            .expect("valid egress request header actions should pass validation");
    }

    #[test]
    fn proxy_egress_request_header_actions_report_location_on_invalid_value_shape() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[[proxy.egress.request_header_actions]]
action = "set"
name = "x-egress-tag"

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("proxy.egress.request_header_actions[0] for header 'x-egress-tag'"),
            "unexpected error message: {msg}"
        );
        assert!(
            msg.contains("must provide value or values"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn proxy_internal_base_path_requires_leading_slash() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080
internal_base_path = "internal"

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("proxy.internal_base_path"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn proxy_internal_base_path_rejects_trailing_slash() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080
internal_base_path = "/internal/"

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("proxy.internal_base_path"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn proxy_egress_default_rejects_blank_host() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[proxy.egress.default]
host = "   "
port = 8889

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("proxy.egress.default.host must not be empty"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn proxy_egress_default_rejects_host_with_surrounding_whitespace() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[proxy.egress.default]
host = " proxy.internal "
port = 8889

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains(
                "proxy.egress.default.host must not include leading or trailing whitespace"
            ),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn proxy_egress_default_rejects_host_with_port_suffix() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[proxy.egress.default]
host = "proxy.internal:8889"
port = 8889

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("proxy.egress.default.host must not include a port suffix"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn proxy_egress_default_accepts_ip_literals() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[proxy.egress.default]
host = "::1"
port = 8889

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        config
            .validate_basic()
            .expect("IPv6 literals should pass validation");
    }

    #[test]
    fn proxy_egress_default_accepts_bracketed_ipv6_literals() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[proxy.egress.default]
host = "[::1]"
port = 8889

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        config
            .validate_basic()
            .expect("bracketed IPv6 literals should pass validation");
    }

    #[test]
    fn proxy_egress_default_rejects_malformed_bracketed_host() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[proxy.egress.default]
host = "[not-an-ip]"
port = 8889

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains(
                "proxy.egress.default.host must be a valid DNS hostname or IP literal without a port suffix"
            ),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn proxy_egress_default_rejects_zero_port() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[proxy.egress.default]
host = "proxy.internal"
port = 0

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("proxy.egress.default.port must be in the inclusive range 1..65535"),
            "unexpected error message: {msg}"
        );
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
    fn certificate_dynamic_persistence_defaults_false_and_parses() {
        assert!(!CertificatesConfig::default().persist_dynamic_certs);

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
persist_dynamic_certs = true
"#;

        let config: Config = toml::from_str(toml).expect("parse config");
        assert!(config.certificates.persist_dynamic_certs);
        config.validate_basic().expect("config should validate");
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
    fn direct_rule_with_headers_absent_counts_as_match_criteria() {
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
action = "deny"
headers_absent = ["x-workload-id"]
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        assert!(
            config.validate_basic().is_ok(),
            "validation should succeed for headers_absent-only rule"
        );
    }

    #[test]
    fn direct_rule_with_headers_match_counts_as_match_criteria() {
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
action = "deny"
headers_match = { "x-workload-id" = "worker-123" }
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        assert!(
            config.validate_basic().is_ok(),
            "validation should succeed for headers_match-only rule"
        );
    }

    #[test]
    fn direct_rule_with_headers_not_match_counts_as_match_criteria() {
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
action = "deny"
headers_not_match = { "x-aw-policy-context" = "internal" }
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        assert!(
            config.validate_basic().is_ok(),
            "validation should succeed for headers_not_match-only rule"
        );
    }

    #[test]
    fn headers_absent_must_not_be_empty_when_configured() {
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
action = "deny"
headers_absent = []
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("headers_absent must not be empty"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn headers_match_must_not_be_empty_when_configured() {
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
action = "deny"
headers_match = {}
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("headers_match must not be empty"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn headers_match_rejects_invalid_header_names() {
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
action = "deny"
headers_match = { "bad header" = "worker-123" }
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("invalid header name 'bad header' in headers_match"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn headers_match_rejects_duplicates_after_normalization() {
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
action = "deny"
headers_match = { "X-Workload-Id" = "worker-123", "x-workload-id" = "worker-456" }
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("duplicate header name"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn headers_match_rejects_empty_values() {
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
action = "deny"
headers_match = { "x-workload-id" = "" }
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("must not include empty-string values"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn headers_not_match_must_not_be_empty_when_configured() {
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
action = "deny"
headers_not_match = {}
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("headers_not_match must not be empty"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn headers_not_match_rejects_invalid_header_names() {
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
action = "deny"
headers_not_match = { "bad header" = "internal" }
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("invalid header name 'bad header' in headers_not_match"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn headers_not_match_rejects_duplicates_after_normalization() {
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
action = "deny"
headers_not_match = { "X-AW-Policy-Context" = "internal", "x-aw-policy-context" = "trusted" }
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("duplicate header name"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn headers_not_match_rejects_empty_values() {
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
action = "deny"
headers_not_match = { "x-aw-policy-context" = "" }
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("headers_not_match entry 'x-aw-policy-context' must not include empty-string values"),
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
    fn empty_logging_directory_is_none() {
        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = ""
level = "info"

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        assert!(config.logging.directory.is_none());
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
    fn empty_capture_filename_uses_default_template() {
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
    fn capture_filename_template_must_be_filename_only() {
        for filename in [
            "../outside-{suffix}.json",
            "/tmp/{requestId}.json",
            "nested/{requestId}.json",
            r"nested\{requestId}.json",
            "..",
            ".",
        ] {
            let toml = format!(
                r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[capture]
directory = "logs-capture"
filename = {filename:?}

[policy]
default = "deny"
"#
            );

            let config: Config = toml::from_str(&toml).expect("parse config");
            let err = config
                .validate_basic()
                .expect_err("filename path should be rejected");
            let msg = format!("{err}");
            assert!(
                msg.contains("capture.filename must be a filename template, not a path"),
                "unexpected error for {filename:?}: {msg}"
            );
        }
    }

    #[test]
    fn capture_max_body_bytes_defaults_to_1mib() {
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
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        assert_eq!(config.capture.max_body_bytes, 1024 * 1024);
        assert_eq!(config.capture.max_files, 10_000);
        assert_eq!(config.capture.max_total_bytes, 1024 * 1024 * 1024);
        assert!(config.validate_basic().is_ok());
    }

    #[test]
    fn capture_max_body_bytes_can_be_set_to_zero() {
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
max_body_bytes = 0

[policy]
default = "deny"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        assert_eq!(config.capture.max_body_bytes, 0);
        assert!(config.validate_basic().is_ok());
    }

    #[test]
    fn capture_retention_limits_must_be_nonzero() {
        for field in ["max_files", "max_total_bytes"] {
            let toml = format!(
                r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[capture]
directory = "logs-capture"
{field} = 0

[policy]
default = "deny"
"#
            );

            let config: Config = toml::from_str(&toml).expect("parse config");
            let err = config
                .validate_basic()
                .expect_err("zero retention limit should be rejected");
            let msg = format!("{err}");
            assert!(
                msg.contains(&format!("capture.{field} must be at least 1")),
                "unexpected error for {field}: {msg}"
            );
        }
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
action = "delegate"
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
    fn delegate_rule_with_external_auth_profile_is_valid() {
        let toml = r#"
schema_version = "1"

[policy]
default = "deny"

[policy.external_auth_profiles.example]
webhook_url = "https://auth.internal/start"
timeout_ms = 1000

[[policy.rules]]
action = "delegate"
pattern = "https://example.com/**"
external_auth_profile = "example"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        config
            .validate_basic()
            .expect("delegate rule should validate");
        let rule = match &config.policy.rules[0] {
            PolicyRuleConfig::Direct(rule) => rule,
            PolicyRuleConfig::Include(_) => panic!("expected direct rule"),
        };
        assert!(matches!(rule.action, PolicyRuleAction::Delegate));
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
            msg.contains("external_auth_profile is only allowed on delegate rules"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn external_auth_profile_not_allowed_on_allow_rule() {
        let toml = r#"
schema_version = "1"

[policy]
default = "deny"

[policy.external_auth_profiles.example]
webhook_url = "https://auth.internal/start"
timeout_ms = 1000

[[policy.rules]]
action = "allow"
pattern = "https://example.com/**"
external_auth_profile = "example"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("external_auth_profile is only allowed on delegate rules"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn plugin_external_auth_profile_can_include_request_body() {
        let toml = r#"
schema_version = "1"

[policy]
default = "deny"

[policy.external_auth_profiles.body_guard]
type = "plugin"
command = "/bin/true"
timeout_ms = 1000
include_request_body = true
max_request_body_bytes = 1024
max_decompressed_request_body_bytes = 4096

[[policy.rules]]
action = "delegate"
pattern = "https://example.com/**"
external_auth_profile = "body_guard"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        config.validate_basic().expect("body-aware plugin config");
        let profile = config
            .policy
            .external_auth_profiles
            .get("body_guard")
            .expect("profile");
        assert!(profile.include_request_body);
        assert_eq!(profile.max_request_body_bytes, 1024);
        assert_eq!(profile.max_decompressed_request_body_bytes, 4096);
    }

    #[test]
    fn http_external_auth_profile_rejects_request_body_inclusion() {
        let toml = r#"
schema_version = "1"

[policy]
default = "deny"

[policy.external_auth_profiles.body_guard]
type = "http"
webhook_url = "https://auth.example/start"
timeout_ms = 1000
include_request_body = true

[[policy.rules]]
action = "delegate"
pattern = "https://example.com/**"
external_auth_profile = "body_guard"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("include_request_body is only supported for type=plugin"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn external_auth_profiles_reject_zero_timeouts() {
        let toml = r#"
schema_version = "1"

[policy]
default = "deny"

[policy.external_auth_profiles.example]
webhook_url = "https://auth.example/start"
timeout_ms = 0
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("external_auth_profiles.example.timeout_ms must be at least 1"),
            "unexpected error: {msg}"
        );

        let toml = r#"
schema_version = "1"

[policy]
default = "deny"

[policy.external_auth_profiles.example]
webhook_url = "https://auth.example/start"
timeout_ms = 1000
webhook_timeout_ms = 0
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("external_auth_profiles.example.webhook_timeout_ms must be at least 1"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn body_aware_plugin_profile_rejects_zero_body_limits() {
        let toml = r#"
schema_version = "1"

[policy]
default = "deny"

[policy.external_auth_profiles.body_guard]
type = "plugin"
command = "/bin/true"
timeout_ms = 1000
include_request_body = true
max_request_body_bytes = 0

[[policy.rules]]
action = "delegate"
pattern = "https://example.com/**"
external_auth_profile = "body_guard"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("max_request_body_bytes must be at least 1"),
            "unexpected error: {msg}"
        );

        let toml = r#"
schema_version = "1"

[policy]
default = "deny"

[policy.external_auth_profiles.body_guard]
type = "plugin"
command = "/bin/true"
timeout_ms = 1000
include_request_body = true
max_decompressed_request_body_bytes = 0

[[policy.rules]]
action = "delegate"
pattern = "https://example.com/**"
external_auth_profile = "body_guard"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("max_decompressed_request_body_bytes must be at least 1"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn delegate_rule_requires_external_auth_profile() {
        let toml = r#"
schema_version = "1"

[policy]
default = "deny"

[[policy.rules]]
action = "delegate"
pattern = "https://example.com/**"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("external_auth_profile is required on delegate rules"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn ruleset_delegate_template_requires_external_auth_profile() {
        let toml = r#"
schema_version = "1"

[policy]
default = "deny"

[[policy.rules]]
include = "delegated"

[[policy.rulesets.delegated]]
action = "delegate"
pattern = "https://example.com/**"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("external_auth_profile is required on delegate rules"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn policy_default_rejects_delegate() {
        let toml = r#"
schema_version = "1"

[policy]
default = "delegate"
        "#;

        let err =
            ::toml::from_str::<Config>(toml).expect_err("parse should reject delegate default");
        let msg = format!("{err}");
        assert!(msg.contains("delegate"), "unexpected error: {msg}");
    }

    #[test]
    fn plugin_profile_requires_command() {
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
type = "plugin"
timeout_ms = 1000

[[policy.rules]]
action = "delegate"
pattern = "https://example.com/**"
external_auth_profile = "example"
        "#;

        let config: Config = toml::from_str(toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("external_auth_profiles.example.command"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn plugin_profile_rejects_header_patterns_with_whitespace() {
        let temp = tempfile::NamedTempFile::new().expect("temp plugin");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = temp
                .as_file()
                .metadata()
                .expect("stat plugin")
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(temp.path(), perms).expect("chmod plugin");
        }

        let toml = format!(
            r#"
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
type = "plugin"
command = "{command}"
timeout_ms = 1000
include_headers = ["authorization token"]

[[policy.rules]]
action = "delegate"
pattern = "https://example.com/**"
external_auth_profile = "example"
            "#,
            command = temp.path().to_string_lossy()
        );

        let config: Config = toml::from_str(&toml).expect("parse config");
        let err = config.validate_basic().expect_err("validation should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("include_headers entries must not contain whitespace"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn config_env_placeholder_classifier_is_exact_only() {
        assert_eq!(
            classify_config_env_placeholder("static-value"),
            ConfigEnvPlaceholder::None
        );
        assert_eq!(
            classify_config_env_placeholder("${API_TOKEN}"),
            ConfigEnvPlaceholder::Exact { name: "API_TOKEN" }
        );
        assert_eq!(
            classify_config_env_placeholder("${_TOKEN_2}"),
            ConfigEnvPlaceholder::Exact { name: "_TOKEN_2" }
        );
        assert_eq!(
            classify_config_env_placeholder("pass${word"),
            ConfigEnvPlaceholder::None
        );
        assert_eq!(
            classify_config_env_placeholder("${TOKEN"),
            ConfigEnvPlaceholder::None
        );

        for raw in [
            "Bearer ${TOKEN}",
            "${TOKEN}/suffix",
            "${}",
            "${1BAD}",
            "${BAD-NAME}",
        ] {
            assert_eq!(
                classify_config_env_placeholder(raw),
                ConfigEnvPlaceholder::Invalid,
                "expected invalid placeholder for {raw}"
            );
        }
    }

    #[test]
    fn header_action_env_interpolation_reports_direct_rule_location() {
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

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "authorization"
value = "Bearer ${TOKEN}"
        "#;

        let mut config: Config = toml::from_str(toml).expect("parse config");
        let err = config
            .interpolate_header_action_env_vars()
            .expect_err("interpolation should fail");
        let msg = format!("{err}");

        assert!(
            msg.contains("policy.rules[0].header_actions[0] for header 'authorization'"),
            "unexpected error message: {msg}"
        );
        assert!(
            !msg.contains("Bearer ${TOKEN}"),
            "error message should not echo configured header value: {msg}"
        );
    }

    #[test]
    fn header_action_env_interpolation_reports_ruleset_location() {
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

[[policy.rulesets.api_headers]]
action = "allow"
pattern = "https://api.internal/**"

[[policy.rulesets.api_headers.header_actions]]
direction = "request"
action = "add"
name = "x-env-tag"
values = ["${DEPLOYMENT}/prod"]

[[policy.rules]]
include = "api_headers"
        "#;

        let mut config: Config = toml::from_str(toml).expect("parse config");
        let err = config
            .interpolate_header_action_env_vars()
            .expect_err("interpolation should fail");
        let msg = format!("{err}");

        assert!(
            msg.contains("policy.rulesets.api_headers[0].header_actions[0] for header 'x-env-tag'"),
            "unexpected error message: {msg}"
        );
        assert!(
            !msg.contains("${DEPLOYMENT}/prod"),
            "error message should not echo configured header value: {msg}"
        );
    }

    #[test]
    fn load_from_sources_invokes_header_action_env_interpolation() {
        let mut file = tempfile::NamedTempFile::new().expect("create temp config");
        write!(
            file,
            r#"
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

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "authorization"
value = "Bearer ${{TOKEN}}"
            "#
        )
        .expect("write config");

        let err = Config::load_from_sources(Some(file.path()))
            .expect_err("load should fail on invalid interpolation syntax");
        let msg = format!("{err}");

        assert!(
            msg.contains("policy.rules[0].header_actions[0] for header 'authorization'"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn header_action_env_interpolation_resolves_exact_value_placeholder() {
        let env_guard = ConfigEnvTestGuard::new(&["ACL_PROXY_TEST_API_TOKEN"]);
        env_guard.set("ACL_PROXY_TEST_API_TOKEN", "Bearer abc123");

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

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "authorization"
value = "${ACL_PROXY_TEST_API_TOKEN}"
        "#;

        let mut config: Config = toml::from_str(toml).expect("parse config");
        config
            .interpolate_header_action_env_vars()
            .expect("interpolation should succeed");

        let PolicyRuleConfig::Direct(rule) = &config.policy.rules[0] else {
            panic!("expected direct rule");
        };
        assert_eq!(
            rule.header_actions[0].value.as_deref(),
            Some("Bearer abc123"),
            "expected resolved header action value"
        );
    }

    #[test]
    fn header_action_env_interpolation_resolves_mixed_values_and_repeated_placeholder() {
        let env_guard =
            ConfigEnvTestGuard::new(&["ACL_PROXY_TEST_DEPLOYMENT", "ACL_PROXY_TEST_REGION"]);
        env_guard.set("ACL_PROXY_TEST_DEPLOYMENT", "prod");
        env_guard.set("ACL_PROXY_TEST_REGION", "us-central1");

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

[[policy.rules.header_actions]]
direction = "request"
action = "add"
name = "x-env-tag"
values = ["static", "${ACL_PROXY_TEST_DEPLOYMENT}", "${ACL_PROXY_TEST_REGION}", "${ACL_PROXY_TEST_DEPLOYMENT}"]
        "#;

        let mut config: Config = toml::from_str(toml).expect("parse config");
        config
            .interpolate_header_action_env_vars()
            .expect("interpolation should succeed");

        let PolicyRuleConfig::Direct(rule) = &config.policy.rules[0] else {
            panic!("expected direct rule");
        };
        assert_eq!(
            rule.header_actions[0]
                .values
                .as_ref()
                .expect("expected resolved values"),
            &vec![
                "static".to_string(),
                "prod".to_string(),
                "us-central1".to_string(),
                "prod".to_string(),
            ]
        );
    }

    #[test]
    fn header_action_env_interpolation_resolves_ruleset_template_placeholders() {
        let env_guard = ConfigEnvTestGuard::new(&["ACL_PROXY_TEST_RULESET_TOKEN"]);
        env_guard.set("ACL_PROXY_TEST_RULESET_TOKEN", "token-123");

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

[[policy.rulesets.api_headers]]
action = "allow"
pattern = "https://api.internal/**"

[[policy.rulesets.api_headers.header_actions]]
direction = "request"
action = "set"
name = "authorization"
value = "${ACL_PROXY_TEST_RULESET_TOKEN}"

[[policy.rules]]
include = "api_headers"
        "#;

        let mut config: Config = toml::from_str(toml).expect("parse config");
        config
            .interpolate_header_action_env_vars()
            .expect("interpolation should succeed");

        let ruleset = config
            .policy
            .rulesets
            .get("api_headers")
            .expect("ruleset should exist");
        assert_eq!(
            ruleset[0].header_actions[0].value.as_deref(),
            Some("token-123"),
            "expected resolved ruleset header action value"
        );
    }

    #[test]
    fn header_action_env_interpolation_reports_missing_env_var() {
        let env_guard = ConfigEnvTestGuard::new(&["ACL_PROXY_TEST_MISSING"]);
        env_guard.remove("ACL_PROXY_TEST_MISSING");

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

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "authorization"
value = "${ACL_PROXY_TEST_MISSING}"
        "#;

        let mut config: Config = toml::from_str(toml).expect("parse config");
        let err = config
            .interpolate_header_action_env_vars()
            .expect_err("missing env var should fail");
        let msg = format!("{err}");

        assert!(
            msg.contains("policy.rules[0].header_actions[0] for header 'authorization'"),
            "unexpected error message: {msg}"
        );
        assert!(
            msg.contains("ACL_PROXY_TEST_MISSING"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn header_action_env_interpolation_resolves_egress_request_header_actions() {
        let env_guard = ConfigEnvTestGuard::new(&["ACL_PROXY_TEST_EGRESS_TAG"]);
        env_guard.set("ACL_PROXY_TEST_EGRESS_TAG", "edge-a");

        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[[proxy.egress.request_header_actions]]
action = "set"
name = "x-egress-tag"
value = "${ACL_PROXY_TEST_EGRESS_TAG}"

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#;

        let mut config: Config = toml::from_str(toml).expect("parse config");
        config
            .interpolate_header_action_env_vars()
            .expect("interpolation should succeed");

        assert_eq!(
            config.proxy.egress.request_header_actions[0]
                .value
                .as_deref(),
            Some("edge-a")
        );
    }

    #[test]
    fn header_action_env_interpolation_reports_egress_action_location() {
        let env_guard = ConfigEnvTestGuard::new(&["ACL_PROXY_TEST_MISSING_EGRESS"]);
        env_guard.remove("ACL_PROXY_TEST_MISSING_EGRESS");

        let toml = r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[[proxy.egress.request_header_actions]]
action = "set"
name = "x-egress-tag"
value = "${ACL_PROXY_TEST_MISSING_EGRESS}"

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#;

        let mut config: Config = toml::from_str(toml).expect("parse config");
        let err = config
            .interpolate_header_action_env_vars()
            .expect_err("missing env var should fail");
        let msg = format!("{err}");

        assert!(
            msg.contains("proxy.egress.request_header_actions[0] for header 'x-egress-tag'"),
            "unexpected error message: {msg}"
        );
        assert!(
            msg.contains("ACL_PROXY_TEST_MISSING_EGRESS"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn header_action_env_interpolation_leaves_static_and_approval_macro_values_unchanged() {
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

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "x-static"
value = "static-value"

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "x-approval"
value = "{{github_token}}"
        "#;

        let mut config: Config = toml::from_str(toml).expect("parse config");
        config
            .interpolate_header_action_env_vars()
            .expect("interpolation should succeed");

        let PolicyRuleConfig::Direct(rule) = &config.policy.rules[0] else {
            panic!("expected direct rule");
        };
        assert_eq!(
            rule.header_actions[0].value.as_deref(),
            Some("static-value")
        );
        assert_eq!(
            rule.header_actions[1].value.as_deref(),
            Some("{{github_token}}")
        );
    }

    #[test]
    fn header_action_env_interpolation_skips_non_set_add_actions() {
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

[[policy.rules.header_actions]]
direction = "request"
action = "replace_substring"
name = "authorization"
search = "${ACL_PROXY_TEST_SEARCH}"
replace = "${ACL_PROXY_TEST_REPLACE}"
        "#;

        let mut config: Config = toml::from_str(toml).expect("parse config");
        config
            .interpolate_header_action_env_vars()
            .expect("replace_substring fields should be untouched");

        let PolicyRuleConfig::Direct(rule) = &config.policy.rules[0] else {
            panic!("expected direct rule");
        };
        assert_eq!(
            rule.header_actions[0].search.as_deref(),
            Some("${ACL_PROXY_TEST_SEARCH}")
        );
        assert_eq!(
            rule.header_actions[0].replace.as_deref(),
            Some("${ACL_PROXY_TEST_REPLACE}")
        );
    }

    #[test]
    fn header_action_env_interpolation_skips_remove_actions() {
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

[[policy.rules.header_actions]]
direction = "request"
action = "remove"
name = "authorization"
        "#;

        let mut config: Config = toml::from_str(toml).expect("parse config");
        config
            .interpolate_header_action_env_vars()
            .expect("remove actions should be untouched");

        let PolicyRuleConfig::Direct(rule) = &config.policy.rules[0] else {
            panic!("expected direct rule");
        };
        assert!(matches!(
            rule.header_actions[0].action,
            HeaderActionKind::Remove
        ));
        assert!(rule.header_actions[0].value.is_none());
        assert!(rule.header_actions[0].values.is_none());
    }

    #[test]
    fn header_action_env_interpolation_allows_empty_resolved_value() {
        let env_guard = ConfigEnvTestGuard::new(&["ACL_PROXY_TEST_EMPTY"]);
        env_guard.set("ACL_PROXY_TEST_EMPTY", "");

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

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "x-empty"
value = "${ACL_PROXY_TEST_EMPTY}"
        "#;

        let mut config: Config = toml::from_str(toml).expect("parse config");
        config
            .interpolate_header_action_env_vars()
            .expect("empty env var should still interpolate");

        let PolicyRuleConfig::Direct(rule) = &config.policy.rules[0] else {
            panic!("expected direct rule");
        };
        assert_eq!(rule.header_actions[0].value.as_deref(), Some(""));
    }

    #[test]
    fn load_from_sources_resolves_header_action_env_placeholders() {
        let env_guard = ConfigEnvTestGuard::new(&["ACL_PROXY_TEST_LOAD_TOKEN"]);
        env_guard.set("ACL_PROXY_TEST_LOAD_TOKEN", "load-token");

        let mut file = tempfile::NamedTempFile::new().expect("create temp config");
        write!(
            file,
            r#"
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

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "authorization"
value = "${{ACL_PROXY_TEST_LOAD_TOKEN}}"
            "#
        )
        .expect("write config");

        let config = Config::load_from_sources(Some(file.path()))
            .expect("load should resolve header action placeholder");
        let PolicyRuleConfig::Direct(rule) = &config.policy.rules[0] else {
            panic!("expected direct rule");
        };
        assert_eq!(
            rule.header_actions[0].value.as_deref(),
            Some("load-token"),
            "expected resolved value after load_from_sources"
        );
    }

    #[test]
    fn policy_dump_masks_env_sourced_header_action_values() {
        let env_guard =
            ConfigEnvTestGuard::new(&["ACL_PROXY_TEST_DUMP_TOKEN", "ACL_PROXY_TEST_DUMP_REGION"]);
        env_guard.set("ACL_PROXY_TEST_DUMP_TOKEN", "secret-token");
        env_guard.set("ACL_PROXY_TEST_DUMP_REGION", "us-central1");

        let mut file = tempfile::NamedTempFile::new().expect("create temp config");
        write!(
            file,
            r#"
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

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "authorization"
value = "${{ACL_PROXY_TEST_DUMP_TOKEN}}"

[[policy.rules.header_actions]]
direction = "request"
action = "add"
name = "x-region"
values = ["static", "${{ACL_PROXY_TEST_DUMP_REGION}}"]
            "#
        )
        .expect("write config");

        let config = Config::load_from_sources(Some(file.path()))
            .expect("load should resolve header action placeholders");
        let effective = crate::policy::EffectivePolicy::from_config(&config.policy)
            .expect("build effective policy");

        let actions = &effective.rules[0].header_actions;
        assert_eq!(actions[0].values, vec!["[REDACTED]".to_string()]);
        assert_eq!(
            actions[1].values,
            vec!["static".to_string(), "[REDACTED]".to_string()]
        );

        let serialized = serde_json::to_string(&effective).expect("serialize effective policy");
        assert!(!serialized.contains("secret-token"));
        assert!(!serialized.contains("us-central1"));
    }

    #[test]
    fn resolved_env_header_validation_error_does_not_echo_value() {
        let env_guard = ConfigEnvTestGuard::new(&["ACL_PROXY_TEST_BAD_HEADER_VALUE"]);
        env_guard.set("ACL_PROXY_TEST_BAD_HEADER_VALUE", "secret\nvalue");

        let mut file = tempfile::NamedTempFile::new().expect("create temp config");
        write!(
            file,
            r#"
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

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "authorization"
value = "${{ACL_PROXY_TEST_BAD_HEADER_VALUE}}"
            "#
        )
        .expect("write config");

        let err = Config::load_from_sources(Some(file.path()))
            .expect_err("invalid resolved header value should fail validation");
        let msg = format!("{err}");
        assert!(msg.contains("invalid header value"));
        assert!(!msg.contains("secret"));
        assert!(!msg.contains("secret\nvalue"));
    }
}
