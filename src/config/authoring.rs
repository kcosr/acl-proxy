use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use ipnet::IpNet;
use serde::de;
use serde::{Deserialize, Deserializer};

use super::duration::{seconds, DrainTimeout, PositiveDuration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SchemaVersion;

impl SchemaVersion {
    pub(super) const NUMBER: u32 = 4;

    pub(super) fn number(self) -> u32 {
        Self::NUMBER
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = u32::deserialize(deserializer)?;
        if version != Self::NUMBER {
            return Err(de::Error::custom(format!(
                "unsupported schema_version {version}, expected {}",
                Self::NUMBER
            )));
        }
        Ok(Self)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthoringConfig {
    pub schema_version: SchemaVersion,

    #[serde(default)]
    pub service: ServiceConfig,

    #[serde(default)]
    pub control: Option<ControlConfig>,

    pub listeners: ListenersConfig,

    #[serde(default)]
    pub identity: Option<IdentityConfig>,

    #[serde(default)]
    pub mitm: Option<MitmConfig>,

    #[serde(default)]
    pub egress: EgressConfig,

    pub policy: PolicyConfig,

    #[serde(default)]
    pub authorization: AuthorizationConfig,

    #[serde(default)]
    pub credentials: CredentialsConfig,

    #[serde(default)]
    pub redaction: RedactionConfig,

    #[serde(default)]
    pub observation: ObservationConfig,

    #[serde(default)]
    pub safety: SafetyConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RulesFragmentConfig {
    pub schema_version: SchemaVersion,
    pub rules: Vec<PolicyRuleConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServiceConfig {
    #[serde(default = "default_request_timeout")]
    pub request_timeout: PositiveDuration,

    #[serde(default)]
    pub forwarding: ForwardingConfig,

    #[serde(default = "default_shutdown_drain_timeout")]
    pub shutdown_drain_timeout: DrainTimeout,

    #[serde(default = "default_max_retiring_generations")]
    pub max_retiring_generations: usize,

    #[serde(default = "default_max_active_upgrades")]
    pub max_active_upgrades: usize,

    #[serde(default = "default_max_active_webhook_deliveries")]
    pub max_active_webhook_deliveries: usize,

    #[serde(default = "default_webhook_transport_buffer_bytes")]
    pub webhook_transport_buffer_bytes: usize,

    #[serde(default = "default_max_webhook_transport_bytes")]
    pub max_webhook_transport_bytes: usize,

    #[serde(default = "default_upgrade_relay_buffer_bytes")]
    pub upgrade_relay_buffer_bytes: usize,

    #[serde(default = "default_max_upgrade_buffer_bytes")]
    pub max_upgrade_buffer_bytes: usize,

    #[serde(default = "default_max_upgrade_lifetime")]
    pub max_upgrade_lifetime: PositiveDuration,

    #[serde(default = "default_max_inflight_wire_body_bytes")]
    pub max_inflight_wire_body_bytes: usize,

    #[serde(default = "default_max_inflight_wire_body_bytes_per_quota_key")]
    pub max_inflight_wire_body_bytes_per_quota_key: usize,

    #[serde(default = "default_min_wire_body_concurrency")]
    pub min_wire_body_concurrency: usize,

    #[serde(default = "default_max_content_decoding_expansion_ratio")]
    pub max_content_decoding_expansion_ratio: usize,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            request_timeout: default_request_timeout(),
            forwarding: ForwardingConfig::default(),
            shutdown_drain_timeout: default_shutdown_drain_timeout(),
            max_retiring_generations: default_max_retiring_generations(),
            max_active_upgrades: default_max_active_upgrades(),
            max_active_webhook_deliveries: default_max_active_webhook_deliveries(),
            webhook_transport_buffer_bytes: default_webhook_transport_buffer_bytes(),
            max_webhook_transport_bytes: default_max_webhook_transport_bytes(),
            upgrade_relay_buffer_bytes: default_upgrade_relay_buffer_bytes(),
            max_upgrade_buffer_bytes: default_max_upgrade_buffer_bytes(),
            max_upgrade_lifetime: default_max_upgrade_lifetime(),
            max_inflight_wire_body_bytes: default_max_inflight_wire_body_bytes(),
            max_inflight_wire_body_bytes_per_quota_key:
                default_max_inflight_wire_body_bytes_per_quota_key(),
            min_wire_body_concurrency: default_min_wire_body_concurrency(),
            max_content_decoding_expansion_ratio: default_max_content_decoding_expansion_ratio(),
        }
    }
}

fn default_request_timeout() -> PositiveDuration {
    seconds(30)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ForwardingConfig {
    #[serde(default = "default_forwarding_timeout")]
    pub connect_timeout: PositiveDuration,
    #[serde(default = "default_forwarding_timeout")]
    pub response_head_timeout: PositiveDuration,
    #[serde(default = "default_forwarding_timeout")]
    pub body_idle_timeout: PositiveDuration,
    #[serde(default = "default_forwarding_timeout")]
    pub upgrade_idle_timeout: PositiveDuration,
    #[serde(default = "default_forwarding_max_request_bytes")]
    pub max_request_wire_bytes: usize,
    #[serde(default = "default_forwarding_max_request_bytes")]
    pub max_request_decoded_bytes: usize,
    #[serde(default = "default_forwarding_max_response_bytes")]
    pub max_response_wire_bytes: usize,
    #[serde(default = "default_forwarding_max_response_bytes")]
    pub max_response_decoded_bytes: usize,
    #[serde(default = "default_forwarding_chunk_bytes")]
    pub chunk_bytes: usize,
    #[serde(default = "default_forwarding_preserve_request_trailers")]
    pub preserve_request_trailers: bool,
    #[serde(default = "default_forwarding_max_trailer_count")]
    pub max_trailer_count: usize,
    #[serde(default = "default_forwarding_max_trailer_bytes")]
    pub max_trailer_bytes: usize,
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        Self {
            connect_timeout: default_forwarding_timeout(),
            response_head_timeout: default_forwarding_timeout(),
            body_idle_timeout: default_forwarding_timeout(),
            upgrade_idle_timeout: default_forwarding_timeout(),
            max_request_wire_bytes: default_forwarding_max_request_bytes(),
            max_request_decoded_bytes: default_forwarding_max_request_bytes(),
            max_response_wire_bytes: default_forwarding_max_response_bytes(),
            max_response_decoded_bytes: default_forwarding_max_response_bytes(),
            chunk_bytes: default_forwarding_chunk_bytes(),
            preserve_request_trailers: default_forwarding_preserve_request_trailers(),
            max_trailer_count: default_forwarding_max_trailer_count(),
            max_trailer_bytes: default_forwarding_max_trailer_bytes(),
        }
    }
}

fn default_forwarding_timeout() -> PositiveDuration {
    seconds(30)
}

fn default_forwarding_max_request_bytes() -> usize {
    50 * 1024 * 1024
}

fn default_forwarding_max_response_bytes() -> usize {
    64 * 1024 * 1024
}

fn default_forwarding_chunk_bytes() -> usize {
    64 * 1024
}

fn default_forwarding_preserve_request_trailers() -> bool {
    true
}

fn default_forwarding_max_trailer_count() -> usize {
    4_096
}

fn default_forwarding_max_trailer_bytes() -> usize {
    1024 * 1024
}

fn default_shutdown_drain_timeout() -> DrainTimeout {
    DrainTimeout::Bounded(seconds(30))
}

fn default_max_retiring_generations() -> usize {
    2
}

fn default_max_active_upgrades() -> usize {
    256
}

fn default_max_active_webhook_deliveries() -> usize {
    256
}

fn default_webhook_transport_buffer_bytes() -> usize {
    64 * 1024
}

fn default_max_webhook_transport_bytes() -> usize {
    64 * 1024 * 1024
}

fn default_upgrade_relay_buffer_bytes() -> usize {
    64 * 1024
}

fn default_max_upgrade_buffer_bytes() -> usize {
    2 * 1024 * 1024 * 1024
}

fn default_max_upgrade_lifetime() -> PositiveDuration {
    seconds(8 * 60 * 60)
}

fn default_max_inflight_wire_body_bytes() -> usize {
    16 * 1024 * 1024 * 1024
}

fn default_max_inflight_wire_body_bytes_per_quota_key() -> usize {
    2 * 1024 * 1024 * 1024
}

fn default_min_wire_body_concurrency() -> usize {
    64
}

fn default_max_content_decoding_expansion_ratio() -> usize {
    128
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControlConfig {
    pub bind: SocketAddr,

    #[serde(default = "default_control_base_path")]
    pub base_path: String,

    #[serde(default = "default_listener_timeout")]
    pub request_header_timeout: PositiveDuration,

    #[serde(default = "default_control_request_body_timeout")]
    pub request_body_timeout: PositiveDuration,

    #[serde(default = "default_control_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_control_max_request_body_bytes")]
    pub max_request_body_bytes: usize,

    #[serde(default)]
    pub tls: Option<StaticTlsIdentityConfig>,
}

fn default_control_base_path() -> String {
    "/_acl-proxy".to_string()
}

fn default_control_max_connections() -> usize {
    128
}

fn default_control_request_body_timeout() -> PositiveDuration {
    seconds(10)
}

fn default_control_max_request_body_bytes() -> usize {
    64 * 1024
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StaticTlsIdentityConfig {
    pub certificate_chain: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListenersConfig {
    #[serde(default)]
    pub explicit_http: Option<ExplicitHttpListenerConfig>,

    #[serde(default)]
    pub transparent_http: Option<TransparentHttpListenerConfig>,

    #[serde(default)]
    pub explicit_https: Option<ExplicitHttpsListenerConfig>,

    #[serde(default)]
    pub transparent_https: Option<TransparentHttpsListenerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IdentityConfig {
    pub max_pending_authentications: usize,
    pub max_pending_authentications_per_connection: usize,
    pub resolver: StaticIdentityResolverConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StaticIdentityResolverConfig {
    pub kind: StaticIdentityResolverKind,
    pub authority: String,
    pub principals: Vec<StaticIdentityPrincipalConfig>,
    #[serde(default)]
    pub groups: Vec<StaticIdentityGroupConfig>,
    pub tokens: Vec<StaticIdentityTokenConfig>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum StaticIdentityResolverKind {
    Static,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StaticIdentityPrincipalConfig {
    pub id: String,
    pub kind: IdentityPrincipalKindConfig,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum IdentityPrincipalKindConfig {
    User,
    ServiceAccount,
    System,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StaticIdentityGroupConfig {
    pub id: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum StaticIdentityTokenConfig {
    Environment {
        id: String,
        principal: String,
        variable: String,
    },
    File {
        id: String,
        principal: String,
        path: PathBuf,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListenerIdentityConfig {
    pub mode: ListenerIdentityModeConfig,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ListenerIdentityModeConfig {
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum HttpVersion {
    Http1,
    Http2,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ListenerEndpointConfig {
    Tcp {
        address: SocketAddr,
    },
    AccessFlow {
        admission_timeout: PositiveDuration,
        allowed_destination_ports: Vec<u16>,
        transport: AccessFlowTransportConfig,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum AccessFlowTransportConfig {
    Unix { path: PathBuf, mode: String },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExplicitHttpListenerConfig {
    pub endpoint: ListenerEndpointConfig,
    pub http_versions: Vec<HttpVersion>,

    #[serde(default = "default_listener_timeout")]
    pub request_header_timeout: PositiveDuration,

    #[serde(default = "default_listener_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_listener_max_concurrent_streams")]
    pub max_concurrent_streams: u32,

    pub connect: ConnectConfig,

    #[serde(default)]
    pub identity: Option<ListenerIdentityConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TransparentHttpListenerConfig {
    pub endpoint: ListenerEndpointConfig,
    pub http_versions: Vec<HttpVersion>,

    #[serde(default = "default_listener_timeout")]
    pub request_header_timeout: PositiveDuration,

    #[serde(default = "default_listener_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_listener_max_concurrent_streams")]
    pub max_concurrent_streams: u32,

    #[serde(default)]
    pub identity: Option<ListenerIdentityConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExplicitHttpsListenerConfig {
    pub endpoint: ListenerEndpointConfig,
    pub http_versions: Vec<HttpVersion>,

    #[serde(default = "default_listener_timeout")]
    pub handshake_timeout: PositiveDuration,

    #[serde(default = "default_listener_timeout")]
    pub request_header_timeout: PositiveDuration,

    #[serde(default = "default_listener_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_listener_max_concurrent_streams")]
    pub max_concurrent_streams: u32,

    pub connect: ConnectConfig,
    pub tls: StaticTlsIdentityConfig,

    #[serde(default)]
    pub identity: Option<ListenerIdentityConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TransparentHttpsListenerConfig {
    pub endpoint: ListenerEndpointConfig,
    pub http_versions: Vec<HttpVersion>,

    #[serde(default = "default_listener_timeout")]
    pub handshake_timeout: PositiveDuration,

    #[serde(default = "default_listener_timeout")]
    pub request_header_timeout: PositiveDuration,

    #[serde(default = "default_listener_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_listener_max_concurrent_streams")]
    pub max_concurrent_streams: u32,

    #[serde(default)]
    pub identity: Option<ListenerIdentityConfig>,
}

fn default_listener_timeout() -> PositiveDuration {
    seconds(10)
}

fn default_listener_max_connections() -> usize {
    1024
}

fn default_listener_max_concurrent_streams() -> u32 {
    128
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConnectConfig {
    #[serde(default)]
    pub http1: Option<Http1ConnectPolicy>,

    #[serde(default)]
    pub http2: Option<Http2ConnectPolicy>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum Http1ConnectPolicy {
    Deny,
    Mitm,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum Http2ConnectPolicy {
    Deny,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub(super) enum MitmConfig {
    Generated(GeneratedMitmConfig),
    Files(FileMitmConfig),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GeneratedMitmConfig {
    pub directory: PathBuf,

    #[serde(default = "default_max_cached_certificates")]
    pub max_cached_certificates: usize,

    #[serde(default)]
    pub persist_leaf_certificates: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileMitmConfig {
    pub ca_certificate: PathBuf,
    pub ca_private_key: PathBuf,

    pub directory: PathBuf,

    #[serde(default = "default_max_cached_certificates")]
    pub max_cached_certificates: usize,

    #[serde(default)]
    pub persist_leaf_certificates: bool,
}

fn default_max_cached_certificates() -> usize {
    1024
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EgressConfig {
    #[serde(default)]
    pub route: EgressRoute,

    #[serde(default)]
    pub origin_tls: TransportTlsConfig,

    #[serde(default)]
    pub parent_proxy: Option<ParentProxyConfig>,

    #[serde(default)]
    pub request_headers: Vec<HeaderEffectConfig>,

    #[serde(default)]
    pub credential_actions: Vec<CredentialActionConfig>,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            route: EgressRoute::Direct,
            origin_tls: TransportTlsConfig::default(),
            parent_proxy: None,
            request_headers: Vec::new(),
            credential_actions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum EgressRoute {
    #[default]
    Direct,
    ParentProxy,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TransportTlsConfig {
    #[serde(default)]
    pub trust: TlsTrust,

    #[serde(default)]
    pub ca_certificate: Option<PathBuf>,

    #[serde(default = "default_http_versions")]
    pub http_versions: Vec<HttpVersion>,
}

impl Default for TransportTlsConfig {
    fn default() -> Self {
        Self {
            trust: TlsTrust::System,
            ca_certificate: None,
            http_versions: default_http_versions(),
        }
    }
}

fn default_http_versions() -> Vec<HttpVersion> {
    vec![HttpVersion::Http1, HttpVersion::Http2]
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum TlsTrust {
    #[default]
    System,
    Custom,
    SystemPlusCustom,
    Insecure,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ParentProxyConfig {
    pub kind: ParentProxyKind,
    pub url: String,

    #[serde(default)]
    pub tls: Option<ParentProxyTlsConfig>,

    #[serde(default)]
    pub presentation: Option<ParentProxyPresentationConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ParentProxyPresentationConfig {
    BearerEnvironment { variable: String },
    BearerFile { path: PathBuf },
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ParentProxyKind {
    AclProxy,
    Generic,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ParentProxyTlsConfig {
    #[serde(default)]
    pub trust: TlsTrust,

    #[serde(default)]
    pub ca_certificate: Option<PathBuf>,

    #[serde(default)]
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyConfig {
    pub default: PolicyDefaultDecision,

    #[serde(default)]
    pub rules: Vec<PolicyRuleConfig>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum PolicyDefaultDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyRuleConfig {
    pub id: String,

    #[serde(default)]
    pub description: Option<String>,

    pub decision: RuleDecision,

    #[serde(default)]
    pub urls: Vec<String>,

    #[serde(default)]
    pub methods: Vec<String>,

    #[serde(default)]
    pub client_cidrs: Vec<IpNet>,

    #[serde(default)]
    pub identity_states: Option<Vec<IdentityStateConfig>>,

    #[serde(default)]
    pub identity_subjects: Option<Vec<IdentitySubjectConfig>>,

    #[serde(default)]
    pub headers: HeaderPredicatesConfig,

    #[serde(default)]
    pub request_timeout: Option<PositiveDuration>,

    #[serde(default)]
    pub allow_upgrades: bool,

    #[serde(default)]
    pub authorization_provider: Option<String>,

    #[serde(default)]
    pub redaction_profile: Option<String>,

    #[serde(default)]
    pub request_headers: Vec<HeaderEffectConfig>,

    #[serde(default)]
    pub response_headers: Vec<HeaderEffectConfig>,

    #[serde(default)]
    pub credential_actions: Vec<CredentialActionConfig>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub(super) enum IdentityStateConfig {
    Disabled,
    Anonymous,
    Authenticated,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum IdentitySubjectConfig {
    Principal { authority: String, id: String },
    Group { authority: String, id: String },
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum RuleDecision {
    Allow,
    Deny,
    Delegate,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct HeaderPredicatesConfig {
    #[serde(default)]
    pub absent_any: Vec<String>,

    #[serde(default)]
    pub present_all: Vec<String>,

    #[serde(default)]
    pub all: BTreeMap<String, Vec<String>>,

    #[serde(default)]
    pub none: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "operation", rename_all = "lowercase")]
pub(super) enum HeaderEffectConfig {
    Set(SetOrAppendHeaderEffectConfig),
    Append(SetOrAppendHeaderEffectConfig),
    Remove(RemoveHeaderEffectConfig),
    Replace(ReplaceHeaderEffectConfig),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SetOrAppendHeaderEffectConfig {
    pub when: HeaderEffectWhen,
    pub name: String,

    #[serde(default)]
    pub value: Option<String>,

    #[serde(default)]
    pub values: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RemoveHeaderEffectConfig {
    pub when: HeaderEffectWhen,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplaceHeaderEffectConfig {
    pub when: HeaderEffectWhen,
    pub name: String,
    pub search: String,
    pub replace: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum HeaderEffectWhen {
    Always,
    IfPresent,
    IfAbsent,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthorizationConfig {
    #[serde(default)]
    pub internal_context_headers: Vec<String>,

    #[serde(default)]
    pub callback: Option<AuthorizationCallbackConfig>,

    #[serde(default)]
    pub providers: BTreeMap<String, AuthorizationProviderConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthorizationCallbackConfig {
    pub public_url: String,

    #[serde(default = "default_resume_token_ttl")]
    pub resume_token_ttl: PositiveDuration,

    #[serde(default = "default_max_pending_operations")]
    pub max_pending_operations: usize,
}

fn default_resume_token_ttl() -> PositiveDuration {
    seconds(20)
}

fn default_max_pending_operations() -> usize {
    4096
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum AuthorizationProviderConfig {
    Webhook(WebhookProviderConfig),
    Process(ProcessProviderConfig),
    UnixSocket(UnixSocketProviderConfig),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WebhookProviderConfig {
    pub url: String,

    #[serde(default = "default_provider_timeout")]
    pub timeout: PositiveDuration,

    #[serde(default)]
    pub on_failure: ProviderFailureMode,

    #[serde(default)]
    pub include_headers: Vec<String>,

    #[serde(default)]
    pub include_identity: bool,

    #[serde(default = "default_webhook_max_request_bytes")]
    pub max_request_bytes: usize,

    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,

    #[serde(default)]
    pub outputs: BTreeMap<String, ProviderOutputConfig>,

    #[serde(default)]
    pub tls: Option<WebhookTlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WebhookTlsConfig {
    #[serde(default)]
    pub trust: TlsTrust,

    #[serde(default)]
    pub ca_certificate: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProcessProviderConfig {
    pub command: PathBuf,

    #[serde(default)]
    pub args: Vec<String>,

    #[serde(default = "default_provider_timeout")]
    pub timeout: PositiveDuration,

    #[serde(default)]
    pub on_failure: ProviderFailureMode,

    #[serde(default)]
    pub inherit_environment: bool,

    #[serde(default)]
    pub pass_environment: Vec<String>,

    #[serde(default)]
    pub environment: BTreeMap<String, String>,

    #[serde(default)]
    pub include_headers: Vec<String>,

    #[serde(default)]
    pub include_identity: bool,

    #[serde(default)]
    pub include_request_body: bool,

    #[serde(default)]
    pub allow_request_body_replacement: bool,

    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,

    #[serde(default = "default_max_decoded_request_body_bytes")]
    pub max_decoded_request_body_bytes: usize,

    #[serde(default = "default_max_stdout_line_bytes")]
    pub max_stdout_line_bytes: usize,

    #[serde(default = "default_max_pending_requests")]
    pub max_pending_requests: usize,

    #[serde(default = "default_restart_backoff")]
    pub restart_backoff: PositiveDuration,

    #[serde(default = "default_retire_timeout")]
    pub retire_timeout: PositiveDuration,

    #[serde(default)]
    pub outputs: BTreeMap<String, ProviderOutputConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UnixSocketProviderConfig {
    pub socket_path: PathBuf,
    pub timeout: PositiveDuration,
    pub on_failure: ProviderFailureMode,
    pub include_headers: Vec<String>,

    #[serde(default)]
    pub include_identity: bool,

    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_pending_requests: usize,

    #[serde(default)]
    pub peer_uid: Option<u32>,

    #[serde(default)]
    pub outputs: BTreeMap<String, ProviderOutputConfig>,
}

fn default_provider_timeout() -> PositiveDuration {
    seconds(30)
}

fn default_max_response_bytes() -> usize {
    64 * 1024
}

fn default_webhook_max_request_bytes() -> usize {
    64 * 1024
}

fn default_max_request_body_bytes() -> usize {
    10 * 1024 * 1024
}

fn default_max_decoded_request_body_bytes() -> usize {
    50 * 1024 * 1024
}

fn default_max_stdout_line_bytes() -> usize {
    1024 * 1024
}

fn default_max_pending_requests() -> usize {
    256
}

fn default_restart_backoff() -> PositiveDuration {
    seconds(1)
}

fn default_retire_timeout() -> PositiveDuration {
    seconds(30)
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum ProviderFailureMode {
    #[default]
    Deny,
    Error,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum ProviderOutputConfig {
    Bearer(BearerProviderOutputConfig),
    Basic(BasicProviderOutputConfig),
    CustomHeader(CustomHeaderProviderOutputConfig),
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum TransportSecurity {
    TlsRequired,
    CleartextAllowed,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BearerProviderOutputConfig {
    pub transport_security: TransportSecurity,

    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BasicProviderOutputConfig {
    pub username: String,
    pub transport_security: TransportSecurity,

    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CustomHeaderProviderOutputConfig {
    pub header: String,
    pub transport_security: TransportSecurity,

    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct CredentialsConfig {
    #[serde(default)]
    pub allowed_custom_headers: Vec<String>,

    #[serde(default)]
    pub inbound: BTreeMap<String, InboundCredentialConfig>,

    #[serde(default)]
    pub sources: BTreeMap<String, CredentialSourceConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InboundCredentialConfig {
    pub header: String,
    pub process_providers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "source", rename_all = "lowercase")]
pub(super) enum CredentialSourceConfig {
    Environment(EnvironmentCredentialSourceConfig),
    File(FileCredentialSourceConfig),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EnvironmentCredentialSourceConfig {
    pub variable: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileCredentialSourceConfig {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum CredentialActionConfig {
    Bearer(BearerCredentialActionConfig),
    Basic(BasicCredentialActionConfig),
    CustomHeader(CustomHeaderCredentialActionConfig),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BearerCredentialActionConfig {
    pub credential: String,
    pub transport_security: TransportSecurity,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BasicCredentialActionConfig {
    pub username: String,
    pub password_credential: String,
    pub transport_security: TransportSecurity,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CustomHeaderCredentialActionConfig {
    pub header: String,
    pub credential: String,
    pub transport_security: TransportSecurity,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct RedactionConfig {
    #[serde(default)]
    pub profiles: BTreeMap<String, RedactionProfileConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RedactionProfileConfig {
    #[serde(default = "default_redaction_replacement")]
    pub replacement: String,

    #[serde(default = "default_max_request_body_bytes")]
    pub max_body_bytes: usize,

    #[serde(default = "default_max_decoded_request_body_bytes")]
    pub max_decoded_body_bytes: usize,

    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,

    #[serde(default = "default_max_message_bytes")]
    pub max_message_bytes: usize,

    #[serde(default)]
    pub allow_permessage_deflate: bool,

    #[serde(default)]
    pub unsupported_extensions: UnsupportedExtensions,

    #[serde(default = "default_max_environment_literal_sources")]
    pub max_environment_literal_sources: usize,

    #[serde(default = "default_max_environment_literal_bytes")]
    pub max_environment_literal_bytes: usize,

    #[serde(default = "default_max_environment_literal_total_bytes")]
    pub max_environment_literal_total_bytes: usize,

    pub rules: Vec<RedactionRuleConfig>,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(super) enum UnsupportedExtensions {
    #[default]
    Deny,
    Strip,
}

fn default_redaction_replacement() -> String {
    "[REDACTED]".to_string()
}

fn default_max_frame_bytes() -> usize {
    256 * 1024
}

fn default_max_message_bytes() -> usize {
    1024 * 1024
}

fn default_max_environment_literal_sources() -> usize {
    64
}

fn default_max_environment_literal_bytes() -> usize {
    64 * 1024
}

fn default_max_environment_literal_total_bytes() -> usize {
    1024 * 1024
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RedactionRuleConfig {
    #[serde(default)]
    pub literals: Vec<String>,

    #[serde(default)]
    pub literal_environment_variables: Vec<String>,

    #[serde(default)]
    pub expressions: Vec<String>,

    #[serde(default)]
    pub payloads: RedactionPayloads,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum RedactionPayloads {
    #[default]
    Text,
    Binary,
    Both,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct ObservationConfig {
    #[serde(default)]
    pub logging: AuthoringLoggingConfig,

    #[serde(default)]
    pub capture: Option<AuthoringCaptureConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthoringLoggingConfig {
    #[serde(default = "default_logging_level")]
    pub level: String,

    #[serde(default)]
    pub directory: Option<PathBuf>,

    #[serde(default = "default_logging_max_bytes")]
    pub max_bytes: u64,

    #[serde(default = "default_logging_max_files")]
    pub max_files: usize,

    #[serde(default = "default_logging_console")]
    pub console: bool,

    #[serde(default)]
    pub policy_decisions: PolicyDecisionLoggingConfig,
}

impl Default for AuthoringLoggingConfig {
    fn default() -> Self {
        Self {
            level: default_logging_level(),
            directory: None,
            max_bytes: default_logging_max_bytes(),
            max_files: default_logging_max_files(),
            console: default_logging_console(),
            policy_decisions: PolicyDecisionLoggingConfig::default(),
        }
    }
}

fn default_logging_level() -> String {
    "info".to_string()
}

fn default_logging_max_bytes() -> u64 {
    100 * 1024 * 1024
}

fn default_logging_max_files() -> usize {
    5
}

fn default_logging_console() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyDecisionLoggingConfig {
    #[serde(default)]
    pub allows: bool,

    #[serde(default = "default_log_denies")]
    pub denies: bool,

    #[serde(default = "default_allow_log_level")]
    pub allow_level: String,

    #[serde(default = "default_deny_log_level")]
    pub deny_level: String,
}

impl Default for PolicyDecisionLoggingConfig {
    fn default() -> Self {
        Self {
            allows: false,
            denies: default_log_denies(),
            allow_level: default_allow_log_level(),
            deny_level: default_deny_log_level(),
        }
    }
}

fn default_log_denies() -> bool {
    true
}

fn default_allow_log_level() -> String {
    "info".to_owned()
}

fn default_deny_log_level() -> String {
    "warn".to_owned()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthoringCaptureConfig {
    pub events: Vec<CaptureEvent>,
    pub redaction_profile: String,
    pub directory: PathBuf,

    #[serde(default = "default_capture_filename")]
    pub filename: String,

    #[serde(default = "default_capture_max_body_bytes")]
    pub max_body_bytes: usize,

    #[serde(default = "default_capture_max_inflight_body_bytes")]
    pub max_inflight_body_bytes: usize,

    #[serde(default = "default_capture_max_pending_records")]
    pub max_pending_records: usize,

    #[serde(default = "default_capture_max_files")]
    pub max_files: usize,

    #[serde(default = "default_capture_max_total_bytes")]
    pub max_total_bytes: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub(super) enum CaptureEvent {
    #[serde(rename = "request.allowed")]
    RequestAllowed,
    #[serde(rename = "response.allowed")]
    ResponseAllowed,
    #[serde(rename = "request.denied")]
    RequestDenied,
    #[serde(rename = "response.denied")]
    ResponseDenied,
}

fn default_capture_filename() -> String {
    "{requestId}-{suffix}.json".to_string()
}

fn default_capture_max_body_bytes() -> usize {
    1024 * 1024
}

fn default_capture_max_inflight_body_bytes() -> usize {
    128 * 1024 * 1024
}

pub(super) fn default_capture_max_pending_records() -> usize {
    1024
}

fn default_capture_max_files() -> usize {
    10_000
}

fn default_capture_max_total_bytes() -> u64 {
    1024 * 1024 * 1024
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct SafetyConfig {
    #[serde(default)]
    pub loop_detection: LoopDetectionConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LoopDetectionConfig {
    #[serde(default = "default_true")]
    pub inject: bool,

    #[serde(default = "default_loop_header")]
    pub header: String,
}

impl Default for LoopDetectionConfig {
    fn default() -> Self {
        Self {
            inject: true,
            header: default_loop_header(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_loop_header() -> String {
    "x-acl-proxy-request-id".to_string()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const MINIMAL: &str = r#"
schema_version = 4

[service]
request_timeout = "30s"
shutdown_drain_timeout = "30s"

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[observation.logging]
level = "info"
console = true

[safety.loop_detection]
inject = true
header = "x-acl-proxy-request-id"
"#;

    #[test]
    fn minimal_authoring_config_parses_with_secure_defaults() {
        let config: AuthoringConfig = toml::from_str(MINIMAL).unwrap();
        assert_eq!(
            config.service.request_timeout.get(),
            Duration::from_secs(30)
        );
        assert_eq!(
            config.service.shutdown_drain_timeout.bounded(),
            Some(Duration::from_secs(30))
        );
        assert_eq!(config.service.max_retiring_generations, 2);
        assert_eq!(config.service.max_active_upgrades, 256);
        assert_eq!(config.service.upgrade_relay_buffer_bytes, 64 * 1024);
        assert_eq!(
            config.service.max_upgrade_buffer_bytes,
            2 * 1024 * 1024 * 1024
        );
        assert_eq!(
            config.service.max_upgrade_lifetime.get(),
            Duration::from_secs(8 * 60 * 60)
        );
        assert_eq!(
            config.service.max_inflight_wire_body_bytes,
            16 * 1024 * 1024 * 1024
        );
        assert_eq!(
            config.service.max_inflight_wire_body_bytes_per_quota_key,
            2 * 1024 * 1024 * 1024
        );
        assert_eq!(config.service.min_wire_body_concurrency, 64);
        assert!(!config.observation.logging.policy_decisions.allows);
        assert!(config.observation.logging.policy_decisions.denies);
        assert_eq!(
            config.observation.logging.policy_decisions.allow_level,
            "info"
        );
        assert_eq!(
            config.observation.logging.policy_decisions.deny_level,
            "warn"
        );
        assert_eq!(config.service.max_content_decoding_expansion_ratio, 128);
        let forwarding = &config.service.forwarding;
        assert_eq!(forwarding.connect_timeout.get(), Duration::from_secs(30));
        assert_eq!(
            forwarding.response_head_timeout.get(),
            Duration::from_secs(30)
        );
        assert_eq!(forwarding.body_idle_timeout.get(), Duration::from_secs(30));
        assert_eq!(
            forwarding.upgrade_idle_timeout.get(),
            Duration::from_secs(30)
        );
        assert_eq!(forwarding.max_request_wire_bytes, 50 * 1024 * 1024);
        assert_eq!(forwarding.max_request_decoded_bytes, 50 * 1024 * 1024);
        assert_eq!(forwarding.max_response_wire_bytes, 64 * 1024 * 1024);
        assert_eq!(forwarding.max_response_decoded_bytes, 64 * 1024 * 1024);
        assert_eq!(forwarding.chunk_bytes, 64 * 1024);
        assert!(forwarding.preserve_request_trailers);
        assert_eq!(forwarding.max_trailer_count, 4_096);
        assert_eq!(forwarding.max_trailer_bytes, 1024 * 1024);
        assert_eq!(config.policy.default, PolicyDefaultDecision::Deny);
        assert!(config.policy.rules.is_empty());
        assert!(config.safety.loop_detection.inject);
        assert_eq!(config.observation.logging.level, "info");
        assert!(config.observation.logging.console);
        assert!(config.mitm.is_none());
        assert!(config.credentials.inbound.is_empty());
        assert!(config.credentials.sources.is_empty());

        let listener = config.listeners.explicit_http.unwrap();
        assert!(matches!(
            listener.endpoint,
            ListenerEndpointConfig::Tcp { address }
                if address == "127.0.0.1:8881".parse().unwrap()
        ));
        assert_eq!(listener.http_versions, vec![HttpVersion::Http1]);
        assert_eq!(listener.connect.http1, Some(Http1ConnectPolicy::Deny));
        assert_eq!(listener.connect.http2, None);
    }

    #[test]
    fn policy_decision_logging_uses_one_strict_shape() {
        let authored = format!(
            "{MINIMAL}\n[observation.logging.policy_decisions]\nallows = true\ndenies = false\nallow_level = \"warn\"\ndeny_level = \"info\"\n"
        );
        let config: AuthoringConfig = toml::from_str(&authored).unwrap();
        let decisions = config.observation.logging.policy_decisions;
        assert!(decisions.allows);
        assert!(!decisions.denies);
        assert_eq!(decisions.allow_level, "warn");
        assert_eq!(decisions.deny_level, "info");

        for unknown in ["log_allows", "allow_severity", "enabled"] {
            let authored =
                format!("{MINIMAL}\n[observation.logging.policy_decisions]\n{unknown} = true\n");
            let error = toml::from_str::<AuthoringConfig>(&authored).unwrap_err();
            assert!(error.to_string().contains("unknown field"), "{error}");
        }
    }

    #[test]
    fn final_service_capacity_fields_are_authored_with_exact_names() {
        let authored = MINIMAL.replace(
            "shutdown_drain_timeout = \"30s\"",
            r#"shutdown_drain_timeout = "unbounded"
max_retiring_generations = 4
max_active_upgrades = 512
max_active_webhook_deliveries = 64
webhook_transport_buffer_bytes = 131072
max_webhook_transport_bytes = 16777216
upgrade_relay_buffer_bytes = 131072
max_upgrade_buffer_bytes = 3221225472
max_upgrade_lifetime = "12h"
max_inflight_wire_body_bytes = 17179869184
max_inflight_wire_body_bytes_per_quota_key = 2147483648
min_wire_body_concurrency = 128
max_content_decoding_expansion_ratio = 96"#,
        );

        let parsed: AuthoringConfig = toml::from_str(&authored).unwrap();
        assert_eq!(
            parsed.service.shutdown_drain_timeout,
            DrainTimeout::Unbounded
        );
        assert_eq!(parsed.service.max_retiring_generations, 4);
        assert_eq!(parsed.service.max_active_upgrades, 512);
        assert_eq!(parsed.service.max_active_webhook_deliveries, 64);
        assert_eq!(parsed.service.webhook_transport_buffer_bytes, 128 * 1024);
        assert_eq!(parsed.service.max_webhook_transport_bytes, 16 * 1024 * 1024);
        assert_eq!(parsed.service.upgrade_relay_buffer_bytes, 128 * 1024);
        assert_eq!(
            parsed.service.max_upgrade_buffer_bytes,
            3 * 1024 * 1024 * 1024
        );
        assert_eq!(
            parsed.service.max_upgrade_lifetime.get(),
            Duration::from_secs(12 * 60 * 60)
        );
        assert_eq!(
            parsed.service.max_inflight_wire_body_bytes,
            16 * 1024 * 1024 * 1024
        );
        assert_eq!(
            parsed.service.max_inflight_wire_body_bytes_per_quota_key,
            2 * 1024 * 1024 * 1024
        );
        assert_eq!(parsed.service.min_wire_body_concurrency, 128);
        assert_eq!(parsed.service.max_content_decoding_expansion_ratio, 96);
    }

    #[test]
    fn forwarding_fields_are_authored_with_exact_names() {
        let authored = MINIMAL.replace(
            "[listeners.explicit_http]",
            r#"[service.forwarding]
connect_timeout = "1s"
response_head_timeout = "2s"
body_idle_timeout = "3s"
upgrade_idle_timeout = "4s"
max_request_wire_bytes = 5
max_request_decoded_bytes = 6
max_response_wire_bytes = 7
max_response_decoded_bytes = 8
chunk_bytes = 9
preserve_request_trailers = false
max_trailer_count = 10
max_trailer_bytes = 11

[listeners.explicit_http]"#,
        );

        let parsed: AuthoringConfig = toml::from_str(&authored).unwrap();
        let forwarding = parsed.service.forwarding;
        assert_eq!(forwarding.connect_timeout.get(), Duration::from_secs(1));
        assert_eq!(
            forwarding.response_head_timeout.get(),
            Duration::from_secs(2)
        );
        assert_eq!(forwarding.body_idle_timeout.get(), Duration::from_secs(3));
        assert_eq!(
            forwarding.upgrade_idle_timeout.get(),
            Duration::from_secs(4)
        );
        assert_eq!(forwarding.max_request_wire_bytes, 5);
        assert_eq!(forwarding.max_request_decoded_bytes, 6);
        assert_eq!(forwarding.max_response_wire_bytes, 7);
        assert_eq!(forwarding.max_response_decoded_bytes, 8);
        assert_eq!(forwarding.chunk_bytes, 9);
        assert!(!forwarding.preserve_request_trailers);
        assert_eq!(forwarding.max_trailer_count, 10);
        assert_eq!(forwarding.max_trailer_bytes, 11);
    }

    #[test]
    fn schema_version_is_integer_four_only() {
        for invalid in [
            MINIMAL.replacen("schema_version = 4", "schema_version = 2", 1),
            MINIMAL.replacen("schema_version = 4", "schema_version = 3", 1),
            MINIMAL.replacen("schema_version = 4", "schema_version = 5", 1),
            MINIMAL.replacen("schema_version = 4", "schema_version = \"4\"", 1),
        ] {
            assert!(toml::from_str::<AuthoringConfig>(&invalid).is_err());
        }
    }

    #[test]
    fn unknown_fields_are_rejected_at_nested_and_top_levels() {
        let top = format!("{MINIMAL}\nlegacy = true\n");
        assert!(toml::from_str::<AuthoringConfig>(&top).is_err());

        let nested = MINIMAL.replace(
            "http_versions = [\"http1\"]",
            "http_versions = [\"http1\"]\nenable_http2 = true",
        );
        assert!(toml::from_str::<AuthoringConfig>(&nested).is_err());
    }

    #[test]
    fn strict_tagged_variants_reject_fields_from_other_variants() {
        let generated_with_file = format!(
            "{MINIMAL}\n[mitm]\nmode = \"generated\"\ndirectory = \"certs\"\nca_certificate = \"ca.pem\"\n"
        );
        assert!(toml::from_str::<AuthoringConfig>(&generated_with_file).is_err());

        let webhook_with_process_field = format!(
            "{MINIMAL}\n[authorization.providers.approval]\nkind = \"webhook\"\nurl = \"https://example.test/auth\"\ncommand = \"/bin/false\"\n"
        );
        assert!(toml::from_str::<AuthoringConfig>(&webhook_with_process_field).is_err());

        let bearer_with_basic_field = format!(
            "{MINIMAL}\n[[egress.credential_actions]]\nkind = \"bearer\"\ncredential = \"token\"\nusername = \"wrong\"\n"
        );
        assert!(toml::from_str::<AuthoringConfig>(&bearer_with_basic_field).is_err());

        let remove_with_value = format!(
            "{MINIMAL}\n[[egress.request_headers]]\noperation = \"remove\"\nwhen = \"always\"\nname = \"x-test\"\nvalue = \"wrong\"\n"
        );
        assert!(toml::from_str::<AuthoringConfig>(&remove_with_value).is_err());
    }

    #[test]
    fn every_credential_variant_requires_known_transport_security() {
        let variants = [
            (
                r#"[[egress.credential_actions]]
kind = "bearer"
credential = "token"
"#,
                "kind = \"bearer\"\n",
            ),
            (
                r#"[[egress.credential_actions]]
kind = "basic"
username = "agent"
password_credential = "token"
"#,
                "kind = \"basic\"\n",
            ),
            (
                r#"[[egress.credential_actions]]
kind = "custom_header"
header = "x-token"
credential = "token"
"#,
                "kind = \"custom_header\"\n",
            ),
            (
                r#"[authorization.providers.local]
kind = "process"
command = "/bin/false"

[authorization.providers.local.outputs.token]
kind = "bearer"
"#,
                "kind = \"bearer\"\n",
            ),
            (
                r#"[authorization.providers.local]
kind = "process"
command = "/bin/false"

[authorization.providers.local.outputs.token]
kind = "basic"
username = "agent"
"#,
                "kind = \"basic\"\n",
            ),
            (
                r#"[authorization.providers.local]
kind = "process"
command = "/bin/false"

[authorization.providers.local.outputs.token]
kind = "custom_header"
header = "x-token"
"#,
                "kind = \"custom_header\"\n",
            ),
        ];

        for (variant, credential_kind) in variants {
            let missing = format!("{MINIMAL}\n{variant}");
            let error = toml::from_str::<AuthoringConfig>(&missing)
                .expect_err("transport_security must be required on every variant");
            assert!(error.to_string().contains("transport_security"), "{error}");

            let unknown = variant.replacen(
                credential_kind,
                &format!("{credential_kind}transport_security = \"opportunistic\"\n"),
                1,
            );
            let error = toml::from_str::<AuthoringConfig>(&format!("{MINIMAL}\n{unknown}"))
                .expect_err("unknown transport_security must fail every variant");
            let rendered = error.to_string();
            assert!(
                rendered.contains("unknown variant `opportunistic`"),
                "{error}"
            );
            assert!(rendered.contains("cleartext_allowed"), "{error}");

            let boolean = variant.replacen(
                credential_kind,
                &format!("{credential_kind}transport_security = true\n"),
                1,
            );
            toml::from_str::<AuthoringConfig>(&format!("{MINIMAL}\n{boolean}"))
                .expect_err("boolean transport security must fail every variant");

            let alias = variant.replacen(
                credential_kind,
                &format!("{credential_kind}transport = \"cleartext_allowed\"\n"),
                1,
            );
            let error = toml::from_str::<AuthoringConfig>(&format!("{MINIMAL}\n{alias}"))
                .expect_err("transport aliases must fail every variant");
            assert!(error.to_string().contains("transport"), "{error}");
        }
    }

    #[test]
    fn complete_provider_and_observation_shapes_parse() {
        let config = format!(
            r#"{MINIMAL}

[control]
bind = "127.0.0.1:8898"
max_request_body_bytes = 65536

[authorization]
internal_context_headers = ["x-aw-policy-context"]

[authorization.callback]
public_url = "http://127.0.0.1:8898/_acl-proxy/external-auth/callback"
max_pending_operations = 4096

[authorization.providers.approval]
kind = "webhook"
url = "https://approval.example.test/authorize"
max_response_bytes = 65536

[authorization.providers.approval.outputs.session]
kind = "bearer"
transport_security = "tls_required"
required = true

[authorization.providers.local]
kind = "process"
command = "/usr/local/bin/approve"
args = ["--stdio"]
inherit_environment = false
pass_environment = ["PATH"]
environment = {{ APPROVAL_MODE = "interactive" }}
include_headers = ["content-type", "x-aw-identity-token"]
include_request_body = true
allow_request_body_replacement = true
max_pending_requests = 256
retire_timeout = "30s"

[authorization.providers.local.outputs.api_key]
kind = "custom_header"
transport_security = "tls_required"
header = "x-api-key"

[credentials]
allowed_custom_headers = ["x-api-key"]

[credentials.inbound.aw_identity]
header = "x-aw-identity-token"
process_providers = ["local"]

[credentials.sources.token]
source = "environment"
variable = "TOKEN"

[redaction.profiles.secrets]
max_environment_literal_sources = 64
max_environment_literal_bytes = 65536
max_environment_literal_total_bytes = 1048576

[[redaction.profiles.secrets.rules]]
literals = ["secret"]
literal_environment_variables = ["REDACT_TOKEN"]
payloads = "both"

[observation.capture]
events = ["request.denied", "response.denied"]
redaction_profile = "secrets"
directory = "captures"
max_inflight_body_bytes = 134217728
"#
        );

        let parsed: AuthoringConfig = toml::from_str(&config).unwrap();
        let control = parsed.control.as_ref().unwrap();
        assert_eq!(control.max_request_body_bytes, 64 * 1024);
        assert_eq!(control.request_body_timeout.get(), Duration::from_secs(10));
        assert_eq!(
            parsed
                .authorization
                .callback
                .as_ref()
                .unwrap()
                .resume_token_ttl
                .get(),
            Duration::from_secs(20)
        );
        assert_eq!(parsed.authorization.providers.len(), 2);
        assert_eq!(parsed.authorization.internal_context_headers.len(), 1);
        assert_eq!(parsed.credentials.inbound.len(), 1);
        let webhook = match &parsed.authorization.providers["approval"] {
            AuthorizationProviderConfig::Webhook(webhook) => webhook,
            AuthorizationProviderConfig::Process(_)
            | AuthorizationProviderConfig::UnixSocket(_) => {
                panic!("expected webhook provider")
            }
        };
        assert_eq!(webhook.timeout.get(), Duration::from_secs(30));
        assert_eq!(webhook.on_failure, ProviderFailureMode::Deny);
        assert_eq!(webhook.max_request_bytes, 64 * 1024);
        assert_eq!(webhook.max_response_bytes, 64 * 1024);

        let process = match &parsed.authorization.providers["local"] {
            AuthorizationProviderConfig::Process(process) => process,
            AuthorizationProviderConfig::Webhook(_)
            | AuthorizationProviderConfig::UnixSocket(_) => {
                panic!("expected process provider")
            }
        };
        assert!(process.include_request_body);
        assert!(process.allow_request_body_replacement);
        assert_eq!(process.max_request_body_bytes, 10 * 1024 * 1024);
        assert_eq!(process.max_decoded_request_body_bytes, 50 * 1024 * 1024);
        assert_eq!(process.max_stdout_line_bytes, 1024 * 1024);
        assert_eq!(process.max_pending_requests, 256);
        assert_eq!(process.restart_backoff.get(), Duration::from_secs(1));
        assert_eq!(process.retire_timeout.get(), Duration::from_secs(30));

        let redaction = &parsed.redaction.profiles["secrets"];
        assert_eq!(redaction.max_environment_literal_sources, 64);
        assert_eq!(redaction.max_environment_literal_bytes, 64 * 1024);
        assert_eq!(redaction.max_environment_literal_total_bytes, 1024 * 1024);
        assert_eq!(
            redaction.unsupported_extensions,
            UnsupportedExtensions::Deny
        );
        let capture = parsed.observation.capture.unwrap();
        assert_eq!(capture.events.len(), 2);
        assert_eq!(capture.redaction_profile, "secrets");
        assert_eq!(capture.max_inflight_body_bytes, 128 * 1024 * 1024);
        assert_eq!(capture.max_pending_records, 1024);
    }

    #[test]
    fn unix_socket_provider_has_one_strict_required_shape_and_closed_defaults() {
        let input = format!(
            r#"{MINIMAL}

[authorization.providers.local]
kind = "unix_socket"
socket_path = "/run/acl-proxy/authorization.sock"
timeout = "2s"
on_failure = "deny"
include_headers = []
max_request_bytes = 262144
max_response_bytes = 65536
max_pending_requests = 128
"#
        );
        let parsed: AuthoringConfig = toml::from_str(&input).unwrap();
        let provider = match &parsed.authorization.providers["local"] {
            AuthorizationProviderConfig::UnixSocket(provider) => provider,
            AuthorizationProviderConfig::Webhook(_) | AuthorizationProviderConfig::Process(_) => {
                panic!("expected Unix socket provider")
            }
        };
        assert_eq!(
            provider.socket_path,
            PathBuf::from("/run/acl-proxy/authorization.sock")
        );
        assert_eq!(provider.timeout.get(), Duration::from_secs(2));
        assert_eq!(provider.on_failure, ProviderFailureMode::Deny);
        assert!(provider.include_headers.is_empty());
        assert!(!provider.include_identity);
        assert_eq!(provider.max_request_bytes, 262_144);
        assert_eq!(provider.max_response_bytes, 65_536);
        assert_eq!(provider.max_pending_requests, 128);
        assert_eq!(provider.peer_uid, None);
        assert!(provider.outputs.is_empty());
    }

    #[test]
    fn unix_socket_provider_rejects_missing_alias_mixed_remote_and_body_fields() {
        const REQUIRED: &str = r#"
[authorization.providers.local]
kind = "unix_socket"
socket_path = "/run/acl-proxy/authorization.sock"
timeout = "2s"
on_failure = "deny"
include_headers = []
max_request_bytes = 262144
max_response_bytes = 65536
max_pending_requests = 128
"#;
        for field in [
            "socket_path",
            "timeout",
            "on_failure",
            "include_headers",
            "max_request_bytes",
            "max_response_bytes",
            "max_pending_requests",
        ] {
            let removed = REQUIRED
                .lines()
                .filter(|line| !line.starts_with(&format!("{field} =")))
                .collect::<Vec<_>>()
                .join("\n");
            toml::from_str::<AuthoringConfig>(&format!("{MINIMAL}\n{removed}"))
                .expect_err("every operational Unix provider field is required");
        }

        let alias = REQUIRED.replace("kind = \"unix_socket\"", "kind = \"unix\"");
        toml::from_str::<AuthoringConfig>(&format!("{MINIMAL}\n{alias}"))
            .expect_err("the Unix provider kind has no alias");

        for unsupported in [
            "socket = \"/run/provider.sock\"",
            "url = \"https://provider.example.test\"",
            "host = \"provider.example.test\"",
            "port = 443",
            "command = \"/bin/provider\"",
            "tls = {}",
            "include_request_body = true",
            "allow_request_body_replacement = true",
            "max_request_body_bytes = 1024",
            "max_stdout_line_bytes = 1024",
            "restart_backoff = \"1s\"",
        ] {
            let mixed = format!("{MINIMAL}\n{REQUIRED}\n{unsupported}\n");
            toml::from_str::<AuthoringConfig>(&mixed)
                .expect_err("unsupported Unix provider fields must remain closed");
        }
    }

    #[test]
    fn workload_identity_and_inbound_credentials_use_typed_shapes() {
        let config = format!(
            r#"{MINIMAL}

[[policy.rules]]
id = "identity"
decision = "allow"
urls = ["https://example.test/**"]

[policy.rules.headers]
present_all = ["x-aw-identity-token"]

[[policy.rules.credential_actions]]
kind = "custom_header"
transport_security = "tls_required"
header = "x-aw-identity-token"
credential = "identity"

[credentials]
allowed_custom_headers = ["x-aw-identity-token"]

[credentials.inbound.aw_identity]
header = "x-aw-identity-token"
process_providers = ["gitlab"]

[credentials.sources.identity]
source = "environment"
variable = "AW_IDENTITY_TOKEN"
"#
        );

        let parsed: AuthoringConfig = toml::from_str(&config).unwrap();
        let rule = &parsed.policy.rules[0];
        assert_eq!(rule.headers.present_all, ["x-aw-identity-token"]);
        assert!(matches!(
            &rule.credential_actions[0],
            CredentialActionConfig::CustomHeader(action)
                if action.header == "x-aw-identity-token" && action.credential == "identity"
        ));
        let inbound = &parsed.credentials.inbound["aw_identity"];
        assert_eq!(inbound.header, "x-aw-identity-token");
        assert_eq!(inbound.process_providers, ["gitlab"]);
        assert!(matches!(
            &parsed.credentials.sources["identity"],
            CredentialSourceConfig::Environment(source)
                if source.variable == "AW_IDENTITY_TOKEN"
        ));
    }

    #[test]
    fn parent_kind_and_required_mitm_directory_parse() {
        let config = MINIMAL.replace(
            "[policy]",
            r#"[egress]
route = "parent_proxy"

[egress.parent_proxy]
kind = "acl_proxy"
url = "https://parent.example.test:8443"

[egress.parent_proxy.tls]
trust = "system"

[policy]"#,
        ) + r#"

[mitm]
mode = "files"
ca_certificate = "ca-cert.pem"
ca_private_key = "ca-key.pem"
directory = "certs"
"#;

        let parsed: AuthoringConfig = toml::from_str(&config).unwrap();
        let parent = parsed.egress.parent_proxy.unwrap();
        assert_eq!(parent.kind, ParentProxyKind::AclProxy);

        let missing_parent_kind = config.replace("kind = \"acl_proxy\"\n", "");
        assert!(toml::from_str::<AuthoringConfig>(&missing_parent_kind).is_err());

        let missing_mitm_directory = config.replace("directory = \"certs\"\n", "");
        assert!(toml::from_str::<AuthoringConfig>(&missing_mitm_directory).is_err());
    }

    #[test]
    fn removed_v2_authoring_shapes_are_not_accepted() {
        let legacy_rule =
            format!("{MINIMAL}\n[[policy.rules]]\naction = \"allow\"\npattern = \"**\"\n");
        assert!(toml::from_str::<AuthoringConfig>(&legacy_rule).is_err());

        let legacy_top = MINIMAL.replace(
            "[listeners.explicit_http]",
            "[proxy.listeners.explicit_http]",
        );
        assert!(toml::from_str::<AuthoringConfig>(&legacy_top).is_err());

        let obsolete = MINIMAL.replace("inject = true", "enabled = true\ninject = true");
        assert!(toml::from_str::<AuthoringConfig>(&obsolete).is_err());
    }

    #[test]
    fn policy_identity_predicates_use_only_the_strict_plural_typed_shape() {
        let valid = format!(
            r#"{MINIMAL}

[[policy.rules]]
id = "identity"
decision = "allow"
identity_states = ["disabled", "anonymous", "authenticated"]
identity_subjects = [
  {{ kind = "principal", authority = "workstation", id = "agent" }},
  {{ kind = "group", authority = "workstation", id = "developers" }},
]
"#
        );
        let parsed: AuthoringConfig = toml::from_str(&valid).unwrap();
        assert_eq!(
            parsed.policy.rules[0].identity_states.as_deref(),
            Some(
                [
                    IdentityStateConfig::Disabled,
                    IdentityStateConfig::Anonymous,
                    IdentityStateConfig::Authenticated,
                ]
                .as_slice()
            )
        );
        assert_eq!(
            parsed.policy.rules[0]
                .identity_subjects
                .as_ref()
                .unwrap()
                .len(),
            2
        );

        for invalid in [
            valid.replace("identity_states =", "identity_state ="),
            valid.replace("\"authenticated\"", "\"unknown\""),
            valid.replace(
                "id = \"agent\" }",
                "id = \"agent\", unexpected = \"value\" }",
            ),
        ] {
            assert!(
                toml::from_str::<AuthoringConfig>(&invalid).is_err(),
                "invalid identity predicate shape was accepted"
            );
        }
    }

    #[test]
    fn static_identity_tokens_reject_literal_sources_and_values() {
        let environment = format!(
            r#"{MINIMAL}

[identity]
max_pending_authentications = 8
max_pending_authentications_per_connection = 2

[identity.resolver]
kind = "static"
authority = "workstation"

[[identity.resolver.principals]]
id = "agent"
kind = "service_account"

[[identity.resolver.tokens]]
id = "agent-primary"
principal = "agent"
source = "environment"
variable = "AW_IDENTITY_TOKEN"
"#
        );
        toml::from_str::<AuthoringConfig>(&environment)
            .expect("the environment descriptor is the canonical token source");

        for invalid in [
            environment.replace(
                "source = \"environment\"\nvariable = \"AW_IDENTITY_TOKEN\"",
                "source = \"literal\"\nvalue = \"not-allowed\"",
            ),
            environment.replace(
                "variable = \"AW_IDENTITY_TOKEN\"",
                "variable = \"AW_IDENTITY_TOKEN\"\nvalue = \"not-allowed\"",
            ),
        ] {
            assert!(
                toml::from_str::<AuthoringConfig>(&invalid).is_err(),
                "literal token material was accepted by the authoring schema"
            );
        }
    }

    #[test]
    fn redaction_unsupported_extensions_is_typed_and_defaults_to_deny() {
        for (authored, expected) in [
            ("", UnsupportedExtensions::Deny),
            (
                "unsupported_extensions = \"deny\"\n",
                UnsupportedExtensions::Deny,
            ),
            (
                "unsupported_extensions = \"strip\"\n",
                UnsupportedExtensions::Strip,
            ),
        ] {
            let config = format!(
                "{MINIMAL}\n[redaction.profiles.websocket]\n{authored}rules = [{{ literals = [\"secret\"] }}]\n"
            );
            let parsed: AuthoringConfig = toml::from_str(&config).unwrap();
            assert_eq!(
                parsed.redaction.profiles["websocket"].unsupported_extensions,
                expected
            );
        }

        let invalid = format!(
            "{MINIMAL}\n[redaction.profiles.websocket]\nunsupported_extensions = \"allow\"\nrules = [{{ literals = [\"secret\"] }}]\n"
        );
        assert!(toml::from_str::<AuthoringConfig>(&invalid).is_err());
    }
}
