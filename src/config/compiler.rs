use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use access_identity::{
    project_static_resolver_resources, AuthorityId, GroupId, IdentityAudience, IdentityState,
    IdentitySubject, PrincipalId, PrincipalKind, StaticGroup, StaticPrincipal, TokenId,
};
use access_rpc_framing::{FrameBodyLimit, FrameKind, FrameProtocol};
use base64::encoded_len as base64_encoded_len;
use credential_core::{
    project_credential_resources, CredentialDescriptor, CredentialLimits, CredentialProfile,
    CredentialPurpose,
};
use http::header::{HeaderName, HeaderValue};
use http::Method;
use http_access_policy_acl::MAX_IDENTITY_SUBJECTS_PER_SNAPSHOT;
#[cfg(test)]
use http_access_redaction::MAX_MATCHER_SCRATCH_BYTES;
use http_access_redaction::{
    ExternalLiteralSlot, PreparedRedactionSnapshot, RedactionLimits, RedactionProfileSpec,
    RedactionRuleSpec, RedactionSnapshotSpec, RulePayloads, UnsupportedWebSocketExtensions,
    MAX_AUTHORED_LITERALS_PER_PROFILE, MAX_AUTHORED_LITERAL_BYTES_PER_PROFILE,
    MAX_EXPRESSIONS_PER_PROFILE, MAX_EXPRESSION_BYTES_PER_PROFILE, MAX_EXTERNAL_LITERAL_BYTES,
    MAX_EXTERNAL_LITERAL_BYTES_PER_PROFILE, MAX_EXTERNAL_LITERAL_BYTES_PER_SNAPSHOT,
    MAX_EXTERNAL_SLOTS_PER_PROFILE, MAX_EXTERNAL_SLOTS_PER_SNAPSHOT, MAX_PROFILES,
    MAX_RULES_PER_PROFILE,
};
use http_access_runtime::{BodyBudget, HttpConnectionAuthenticationCapacity};
use http_access_types::{
    BodyLimits, CanonicalUrl, CredentialMutation, CredentialMutationKind, CredentialRef,
    HeaderName as NeutralHeaderName, HttpScheme, RedirectPolicy, ResponsePolicy, SnapshotIdentity,
    StableId,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::authorization::protocol::{
    projected_provider_credential_wire_metadata_bytes, CALLBACK_RESPONSE_PREFIX_BYTES,
    MIN_CALLBACK_RESPONSE_BYTES, MIN_WEBHOOK_REQUEST_WITHOUT_CALLBACK_URL_BYTES,
    PROCESS_PROVIDER_MIN_DECISION_RESPONSE_BYTES, PROCESS_PROVIDER_RESPONSE_PREFIX_BYTES,
    PROCESS_PROVIDER_RESPONSE_TERMINATOR_BYTES,
};
use crate::authorization::MAX_PROVIDER_RULE_ID_BYTES;
use crate::capture::{CaptureSinkSpec, CaptureSinkSpecError};
use crate::credential_buffers::ProductCredentialProjectionContext;
use crate::credential_resolver::projected_product_adapter_bytes;
use crate::credentials::{MAX_CREDENTIAL_BYTES, MAX_FILE_READ_BYTES};
use crate::http_body::{http_decoder_workspace_sizes, HTTP_DECODER_OUTPUT_STAGING_BYTES};
use crate::network::{canonical_socket_addr, socket_binds_overlap};
use crate::redaction::{
    ProductExternalLiteralSource, ProductRedactionPlan, ProductRedactionProfile,
};
#[cfg(test)]
use crate::safety::wire_body::MAX_BUFFER_GROWTH_BYTES;
use crate::safety::wire_body::{guarded_body_allocation_bytes, guarded_workspace_allocation_bytes};
use crate::standalone::UnboundStandaloneGenerationPlan;
use http_access_runtime::http1::PARSER_STORE_BYTES;
use http_access_url::{canonicalize_http_url, CompiledUrlPattern};

use super::authoring::{
    AccessFlowTransportConfig, AuthorizationConfig, AuthorizationProviderConfig,
    CredentialActionConfig, CredentialSourceConfig, CredentialsConfig, EgressConfig, EgressRoute,
    HeaderEffectConfig, HeaderEffectWhen, Http1ConnectPolicy, HttpVersion,
    IdentityPrincipalKindConfig, IdentityStateConfig, IdentitySubjectConfig,
    ListenerEndpointConfig, ListenerIdentityModeConfig, ListenersConfig, MitmConfig,
    ObservationConfig, ParentProxyKind, ParentProxyPresentationConfig, PolicyConfig,
    PolicyRuleConfig, RedactionConfig, RedactionPayloads, RuleDecision, SafetyConfig,
    StaticTlsIdentityConfig, TlsTrust, TransportSecurity, TransportTlsConfig,
    UnsupportedExtensions,
};

const MIB: usize = 1024 * 1024;
const GIB: usize = 1024 * MIB;
const MAX_CONFIG_BYTES: usize = 10 * MIB;
const MAX_CONTROL_CONNECTIONS: usize = 65_536;
const MAX_CONTROL_BODY_BYTES: usize = MIB;
const MAX_ENDPOINT_BYTES: usize = 8 * 1024;
const CALLBACK_ROUTE_SUFFIX: &str = "/external-auth/callback";
pub(crate) const MAX_PENDING_OPERATIONS: usize = 65_536;
const MAX_RETIRING_GENERATIONS: usize = 8;
const MAX_ACTIVE_UPGRADES: usize = 65_536;
const MAX_ACTIVE_WEBHOOK_DELIVERIES: usize = 4_096;
const MIN_WEBHOOK_TRANSPORT_BUFFER_BYTES: usize = 64 * 1024;
const MAX_WEBHOOK_TRANSPORT_BUFFER_BYTES: usize = MIB;
const MAX_WEBHOOK_TRANSPORT_BYTES: usize = 8 * GIB;
const MAX_WEBHOOK_BODY_BYTES: usize = MIB;
const MAX_UPGRADE_RELAY_BUFFER_BYTES: usize = 16 * MIB;
const MAX_UPGRADE_BUFFER_BYTES: usize = 4 * GIB;
const MAX_WIRE_BODY_BYTES: usize = 64 * GIB;
const MAX_WIRE_BODY_BYTES_PER_QUOTA_KEY: usize = 16 * GIB;
const MAX_MIN_WIRE_BODY_CONCURRENCY: usize = 4_096;
const MAX_CONTENT_DECODING_RATIO: usize = 128;
const MAX_LISTENER_CONNECTIONS: usize = 1_048_576;
const MAX_LISTENER_STREAMS: u32 = 65_535;
#[cfg(target_os = "linux")]
const MAX_UNIX_SOCKET_PATH_BYTES: usize = 107;
#[cfg(not(target_os = "linux"))]
const MAX_UNIX_SOCKET_PATH_BYTES: usize = 103;
const MAX_MITM_CERTIFICATES: usize = 1_000_000;
const MAX_PROVIDERS: usize = 256;
const MAX_PROCESS_PROVIDERS: usize = 64;
const MAX_PROCESS_BODY_BYTES: usize = GIB;
const MAX_PROCESS_STDOUT_LINE_BYTES: usize = 16 * MIB;
const MAX_PROCESS_PENDING_REQUESTS: usize = 4_096;
const MAX_UNIX_PROVIDER_BODY_BYTES: usize = MIB;
const MAX_UNIX_PROVIDER_PENDING_REQUESTS: usize = 4_096;
const MAX_UNIX_PROVIDER_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const UNIX_PROVIDER_MAGIC: [u8; 4] = *b"AWAP";
const UNIX_PROVIDER_WIRE_VERSION: u8 = 1;
const MIN_UNIX_PROVIDER_REQUEST_BYTES: usize = br#"{"id":"u0000000000000001","type":"request","requestId":"req-00000000000000000000000000000000","ruleId":"a","invocation":"decision_only","url":"http://a/","method":"A","client":"127.0.0.1:0","headers":{}}"#.len();
const MIN_UNIX_PROVIDER_RESPONSE_BYTES: usize =
    br#"{"id":"u0000000000000001","type":"response","decision":"deny"}"#.len();
const MAX_FORWARDING_BODY_BYTES: usize = GIB;
const MAX_FORWARDING_TRAILER_COUNT: usize = 65_536;
const MAX_RUNTIME_BODY_CHUNKS: usize = 65_536;
const MAX_FORWARDING_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_POLICY_RULES: usize = 100_000;
const MAX_URLS_PER_RULE: usize = 1_024;
const MAX_EFFECTS_PER_SCOPE: usize = 1_024;
const MAX_HEADER_PREDICATES_PER_RULE: usize = 4_096;
const MAX_HEADER_FIELD_BYTES: usize = 64 * 1024;
const MAX_PROVIDER_ITEMS: usize = 256;
const MAX_REDACTION_PROFILES: usize = MAX_PROFILES;
const MAX_REDACTION_RULES: usize = MAX_RULES_PER_PROFILE;
const MAX_REDACTION_EXPRESSIONS: usize = MAX_EXPRESSIONS_PER_PROFILE;
const MAX_REDACTION_EXPRESSION_BYTES_PER_PROFILE: usize = MAX_EXPRESSION_BYTES_PER_PROFILE;
const MAX_REDACTION_BODY_BYTES: usize = GIB;
const MAX_REDACTION_FRAME_BYTES: usize = 16 * MIB;
const MAX_REDACTION_MESSAGE_BYTES: usize = 256 * MIB;
const MAX_REDACTION_ENV_SOURCES_PER_PROFILE: usize = MAX_EXTERNAL_SLOTS_PER_PROFILE;
const MAX_REDACTION_ENV_BYTES: usize = MAX_EXTERNAL_LITERAL_BYTES;
const MAX_REDACTION_ENV_TOTAL_BYTES_PER_PROFILE: usize = MAX_EXTERNAL_LITERAL_BYTES_PER_PROFILE;
const MAX_REDACTION_ENV_SOURCES_PER_SNAPSHOT: usize = MAX_EXTERNAL_SLOTS_PER_SNAPSHOT;
const MAX_REDACTION_ENV_BYTES_PER_SNAPSHOT: usize = MAX_EXTERNAL_LITERAL_BYTES_PER_SNAPSHOT;
const MAX_TOML_REDACTION_LITERALS_PER_PROFILE: usize = MAX_AUTHORED_LITERALS_PER_PROFILE;
const MAX_TOML_REDACTION_LITERAL_BYTES_PER_PROFILE: usize = MAX_AUTHORED_LITERAL_BYTES_PER_PROFILE;
const MAX_LOG_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_LOG_FILES: usize = 1_000_000;
const MAX_CAPTURE_BODY_BYTES: usize = GIB;
const MAX_CAPTURE_INFLIGHT_BYTES: usize = 4 * GIB;
const MAX_CAPTURE_PENDING_RECORDS: usize = 65_536;
const MAX_CAPTURE_FILES: usize = 10_000_000;
const MAX_CAPTURE_TOTAL_BYTES: u64 = 64 * 1024 * 1024 * 1024 * 1024;
pub(crate) const MAX_PROVIDER_CREDENTIAL_BYTES: usize = 64 * 1024;
pub(crate) const MAX_PROVIDER_OUTPUT_NAME_BYTES: usize = 4 * 1024;
pub(crate) const MAX_ENVIRONMENT_CREDENTIAL_NAME_BYTES: usize = 255;
pub(crate) const MAX_CREDENTIAL_FILE_PATH_BYTES: usize = 4096;
pub(crate) const MAX_CREDENTIAL_FILE_COMPONENT_BYTES: usize = 255;
const MAX_PENDING_AUTHENTICATIONS: usize = 4_096;
const MAX_PENDING_AUTHENTICATIONS_PER_CONNECTION: usize = 256;
const MAX_IDENTITY_PRINCIPALS: usize = 4_096;
const MAX_IDENTITY_GROUPS: usize = 4_096;
const MAX_IDENTITY_TOKENS: usize = 8_192;
const MAX_IDENTITY_MEMBERSHIPS: usize = 65_536;
const MAX_IDENTITY_GROUPS_PER_PRINCIPAL: usize = 256;
const PROVIDER_REPLACEMENT_STAGING_BYTES: usize = 64 * 1024;
const WEBSOCKET_DEFLATE_SCRATCH_BYTES: usize = 64 * 1024;
const PROVIDER_REQUEST_STREAM_SCRATCH_BYTES: usize = 64 * 1024;

/// Static, product-owned values. File paths identify material but no material is
/// opened or parsed by this compiler.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StaticProductConfig {
    pub(crate) schema_version: u32,
    pub(crate) config_root: PathBuf,
    pub(crate) max_config_bytes: usize,
    pub(crate) service: StaticServiceConfig,
    pub(crate) control: Option<StaticControlConfig>,
    pub(crate) listeners: StaticListenersConfig,
    pub(crate) mitm: Option<StaticMitmConfig>,
    #[serde(serialize_with = "serialize_optional_canonical_url")]
    pub(crate) callback_public_url: Option<CanonicalUrl>,
    pub(crate) logging: StaticLoggingConfig,
    pub(crate) capture: StaticCaptureConfig,
}

fn serialize_optional_canonical_url<S>(
    value: &Option<CanonicalUrl>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    value
        .as_ref()
        .map(CanonicalUrl::as_str)
        .serialize(serializer)
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StaticServiceConfig {
    pub(crate) shutdown_drain_timeout: Option<Duration>,
    pub(crate) max_retiring_generations: usize,
    pub(crate) max_active_upgrades: usize,
    pub(crate) max_active_webhook_deliveries: usize,
    pub(crate) webhook_transport_buffer_bytes: usize,
    pub(crate) max_webhook_transport_bytes: usize,
    pub(crate) upgrade_relay_buffer_bytes: usize,
    pub(crate) max_upgrade_buffer_bytes: usize,
    pub(crate) max_upgrade_lifetime: Duration,
    pub(crate) max_inflight_wire_body_bytes: usize,
    pub(crate) max_inflight_wire_body_bytes_per_quota_key: usize,
    pub(crate) min_wire_body_concurrency: usize,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StaticControlConfig {
    pub(crate) bind: SocketAddr,
    pub(crate) base_path: String,
    pub(crate) request_header_timeout: Duration,
    pub(crate) request_body_timeout: Duration,
    pub(crate) max_connections: usize,
    pub(crate) parser_arena_bytes: usize,
    pub(crate) max_request_body_bytes: usize,
    pub(crate) tls: Option<CompiledTlsIdentity>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CompiledTlsIdentity {
    pub(crate) certificate_chain: PathBuf,
    pub(crate) private_key: PathBuf,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StaticListenersConfig {
    pub(crate) explicit_http: Option<StaticCleartextListener>,
    pub(crate) transparent_http: Option<StaticCleartextListener>,
    pub(crate) explicit_https: Option<StaticExplicitHttpsListener>,
    pub(crate) transparent_https: Option<StaticTransparentHttpsListener>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum StaticListenerEndpoint {
    Tcp {
        address: SocketAddr,
    },
    AccessFlow {
        admission_timeout: Duration,
        allowed_destination_ports: Vec<u16>,
        transport: StaticAccessFlowTransport,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum StaticAccessFlowTransport {
    Unix { path: PathBuf, mode: u32 },
}

pub(crate) fn unix_listener_lock_path(path: &Path) -> PathBuf {
    let mut lock_name = path.as_os_str().to_os_string();
    lock_name.push(".lock");
    PathBuf::from(lock_name)
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StaticCleartextListener {
    pub(crate) endpoint: StaticListenerEndpoint,
    pub(crate) http_versions: Vec<CompiledHttpVersion>,
    pub(crate) request_header_timeout: Duration,
    pub(crate) max_connections: usize,
    pub(crate) max_concurrent_streams: u32,
    pub(crate) identity_mode: CompiledListenerIdentityMode,
    pub(crate) connect: Option<StaticConnectPolicy>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StaticExplicitHttpsListener {
    pub(crate) endpoint: StaticListenerEndpoint,
    pub(crate) http_versions: Vec<CompiledHttpVersion>,
    pub(crate) handshake_timeout: Duration,
    pub(crate) request_header_timeout: Duration,
    pub(crate) max_connections: usize,
    pub(crate) max_concurrent_streams: u32,
    pub(crate) identity_mode: CompiledListenerIdentityMode,
    pub(crate) connect: StaticConnectPolicy,
    pub(crate) tls: CompiledTlsIdentity,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StaticTransparentHttpsListener {
    pub(crate) endpoint: StaticListenerEndpoint,
    pub(crate) http_versions: Vec<CompiledHttpVersion>,
    pub(crate) handshake_timeout: Duration,
    pub(crate) request_header_timeout: Duration,
    pub(crate) max_connections: usize,
    pub(crate) max_concurrent_streams: u32,
    pub(crate) identity_mode: CompiledListenerIdentityMode,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CompiledListenerIdentityMode {
    #[default]
    Disabled,
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum CompiledHttpVersion {
    Http1,
    Http2,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StaticConnectPolicy {
    pub(crate) http1: Option<CompiledHttp1ConnectPolicy>,
    pub(crate) http2_denied: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum CompiledHttp1ConnectPolicy {
    Deny,
    Mitm,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) enum StaticMitmConfig {
    Generated {
        directory: PathBuf,
        max_cached_certificates: usize,
        persist_leaf_certificates: bool,
    },
    Files {
        ca_certificate: PathBuf,
        ca_private_key: PathBuf,
        directory: PathBuf,
        max_cached_certificates: usize,
        persist_leaf_certificates: bool,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StaticLoggingConfig {
    pub(crate) directory: Option<PathBuf>,
    pub(crate) max_bytes: u64,
    pub(crate) max_files: usize,
    pub(crate) console: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) enum CompiledLogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StaticCaptureConfig {
    pub(crate) max_pending_records: usize,
}

/// Purely compiled, unresolved generation input. Runtime activation must turn
/// this into a snapshot by resolving redaction sources and eagerly starting
/// process providers. Activation consumes logical names and redaction source
/// locators. Credential environment/file locators survive only inside the
/// opaque late resolver that owns uncached final-injection reads; request paths
/// never consume this plan directly.
pub(crate) struct ReloadableProductPlan {
    pub(crate) request_timeout: Duration,
    pub(crate) max_content_decoding_expansion_ratio: usize,
    pub(crate) forwarding: ForwardingPlan,
    pub(crate) identity: Option<IdentityPlan>,
    pub(crate) identity_connection_capacity: HttpConnectionAuthenticationCapacity,
    pub(crate) egress: EgressPlan,
    pub(crate) policy: PolicyPlan,
    pub(crate) authorization: AuthorizationPlan,
    pub(crate) credentials: CredentialsPlan,
    pub(crate) redaction: ProductRedactionPlan,
    pub(crate) observation: ObservationPlan,
    pub(crate) safety: SafetyPlan,
    pub(crate) resource_plan: CompiledResourcePlan,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct IdentityPlan {
    pub(crate) max_pending_authentications: usize,
    pub(crate) authority: AuthorityId,
    pub(crate) audience: IdentityAudience,
    pub(crate) principals: Vec<IdentityPrincipalPlan>,
    pub(crate) groups: Vec<IdentityGroupPlan>,
    pub(crate) tokens: Vec<IdentityTokenPlan>,
    pub(crate) resources: access_identity::ResourceProjection,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct IdentityPrincipalPlan {
    pub(crate) id: PrincipalId,
    pub(crate) kind: PrincipalKind,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct IdentityGroupPlan {
    pub(crate) id: GroupId,
    pub(crate) members: Vec<PrincipalId>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct IdentityTokenPlan {
    pub(crate) id: TokenId,
    pub(crate) principal: PrincipalId,
    pub(crate) source: IdentitySourcePlan,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum IdentitySourcePlan {
    Environment { variable: String },
    File { path: PathBuf },
}

impl fmt::Debug for IdentitySourcePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Environment { .. } => formatter
                .debug_struct("Environment")
                .field("variable", &"[REDACTED]")
                .finish(),
            Self::File { .. } => formatter
                .debug_struct("File")
                .field("path", &"[REDACTED]")
                .finish(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ForwardingPlan {
    pub(crate) connect_timeout: Duration,
    pub(crate) response_head_timeout: Duration,
    pub(crate) body_idle_timeout: Duration,
    pub(crate) upgrade_idle_timeout: Duration,
    pub(crate) max_request_wire_bytes: usize,
    pub(crate) max_request_decoded_bytes: usize,
    pub(crate) max_response_wire_bytes: usize,
    pub(crate) max_response_decoded_bytes: usize,
    pub(crate) chunk_bytes: usize,
    pub(crate) preserve_request_trailers: bool,
    pub(crate) max_trailer_count: usize,
    pub(crate) max_trailer_bytes: usize,
}

impl fmt::Debug for ReloadableProductPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReloadableProductPlan")
            .field("request_timeout", &self.request_timeout)
            .field(
                "max_content_decoding_expansion_ratio",
                &self.max_content_decoding_expansion_ratio,
            )
            .field("forwarding", &self.forwarding)
            .field(
                "identity_connection_capacity",
                &self.identity_connection_capacity,
            )
            .field("policy_rule_count", &self.policy.rules.len())
            .field(
                "authorization_provider_count",
                &self.authorization.providers.len(),
            )
            .field("credential_source_count", &self.credentials.sources.len())
            .field("redaction_profile_count", &self.redaction.profiles.len())
            .field("capture_enabled", &self.observation.capture.is_some())
            .field("resource_plan", &self.resource_plan)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct EgressPlan {
    pub(crate) route: CompiledEgressRoute,
    pub(crate) origin_tls: TransportTlsPlan,
    pub(crate) parent_proxy: Option<ParentProxyPlan>,
    pub(crate) request_headers: Vec<HeaderEffectPlan>,
    pub(crate) credential_actions: Vec<CredentialActionPlan>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledEgressRoute {
    Direct,
    ParentProxy,
}

#[derive(Clone)]
pub(crate) struct TransportTlsPlan {
    pub(crate) trust: CompiledTlsTrust,
    pub(crate) ca_certificate: Option<PathBuf>,
    pub(crate) http_versions: Vec<CompiledHttpVersion>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledTlsTrust {
    System,
    Custom,
    SystemPlusCustom,
    Insecure,
}

#[derive(Clone)]
pub(crate) struct ParentProxyPlan {
    pub(crate) kind: CompiledParentProxyKind,
    pub(crate) target: CanonicalUrl,
    pub(crate) tls: Option<ParentProxyTlsPlan>,
    pub(crate) presentation: Option<IdentitySourcePlan>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledParentProxyKind {
    AclProxy,
    Generic,
}

#[derive(Clone)]
pub(crate) struct ParentProxyTlsPlan {
    pub(crate) trust: CompiledTlsTrust,
    pub(crate) ca_certificate: Option<PathBuf>,
    pub(crate) server_name: String,
}

#[derive(Clone)]
pub(crate) struct PolicyPlan {
    pub(crate) default: CompiledDefaultDecision,
    pub(crate) rules: Vec<PolicyRulePlan>,
    pub(crate) http_body_read_plans_by_cursor: Vec<HttpBodyReadPlan>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HttpBodyReadPlan {
    Disabled,
    Mandatory(HttpBodyReadLimits),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HttpBodyReadLimits {
    max_encoded_bytes: NonZeroUsize,
    max_decoded_bytes: NonZeroUsize,
}

impl HttpBodyReadPlan {
    #[cfg(test)]
    pub(crate) fn requires_mandatory_read(self) -> bool {
        matches!(self, Self::Mandatory(_))
    }

    pub(crate) fn limits(self) -> Option<HttpBodyReadLimits> {
        match self {
            Self::Disabled => None,
            Self::Mandatory(limits) => Some(limits),
        }
    }

    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Disabled, plan) | (plan, Self::Disabled) => plan,
            (Self::Mandatory(left), Self::Mandatory(right)) => Self::Mandatory(
                HttpBodyReadLimits::try_new(
                    left.max_encoded_bytes().max(right.max_encoded_bytes()),
                    left.max_decoded_bytes().max(right.max_decoded_bytes()),
                )
                .expect("maxima of validated HTTP body read limits remain valid"),
            ),
        }
    }
}

impl HttpBodyReadLimits {
    pub(crate) fn try_new(max_encoded_bytes: usize, max_decoded_bytes: usize) -> Option<Self> {
        let max_encoded_bytes = NonZeroUsize::new(max_encoded_bytes)?;
        let max_decoded_bytes = NonZeroUsize::new(max_decoded_bytes)?;
        (max_decoded_bytes >= max_encoded_bytes).then_some(Self {
            max_encoded_bytes,
            max_decoded_bytes,
        })
    }

    pub(crate) fn max_encoded_bytes(self) -> usize {
        self.max_encoded_bytes.get()
    }

    pub(crate) fn max_decoded_bytes(self) -> usize {
        self.max_decoded_bytes.get()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledDefaultDecision {
    Allow,
    Deny,
}

#[derive(Clone)]
pub(crate) struct PolicyRulePlan {
    pub(crate) id: String,
    pub(crate) description: Option<String>,
    pub(crate) decision: CompiledRuleDecision,
    pub(crate) urls: Vec<CompiledUrlPattern>,
    pub(crate) methods: Vec<Method>,
    pub(crate) client_cidrs: Vec<ipnet::IpNet>,
    pub(crate) identity: Option<IdentityPredicatePlan>,
    pub(crate) headers: HeaderPredicatesPlan,
    pub(crate) request_timeout: Option<Duration>,
    pub(crate) allow_upgrades: bool,
    pub(crate) authorization_provider: Option<String>,
    pub(crate) redaction_profile: Option<String>,
    pub(crate) request_headers: Vec<HeaderEffectPlan>,
    pub(crate) response_headers: Vec<HeaderEffectPlan>,
    pub(crate) credential_actions: Vec<CredentialActionPlan>,
}

#[derive(Clone)]
pub(crate) struct IdentityPredicatePlan {
    pub(crate) states: Vec<IdentityState>,
    pub(crate) subjects: Vec<IdentitySubject>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledRuleDecision {
    Allow,
    Deny,
    Delegate,
}

#[derive(Clone)]
pub(crate) struct HeaderPredicatesPlan {
    pub(crate) absent_any: Vec<HeaderName>,
    pub(crate) present_all: Vec<HeaderName>,
    pub(crate) all: Vec<HeaderValuePredicatePlan>,
    pub(crate) none: Vec<HeaderValuePredicatePlan>,
}

#[derive(Clone)]
pub(crate) struct HeaderValuePredicatePlan {
    pub(crate) name: HeaderName,
    pub(crate) values: Vec<HeaderValue>,
}

#[derive(Clone)]
pub(crate) enum HeaderEffectPlan {
    Set {
        when: CompiledHeaderEffectWhen,
        name: HeaderName,
        values: Vec<HeaderValue>,
    },
    Append {
        when: CompiledHeaderEffectWhen,
        name: HeaderName,
        values: Vec<HeaderValue>,
    },
    Remove {
        when: CompiledHeaderEffectWhen,
        name: HeaderName,
    },
    Replace {
        when: CompiledHeaderEffectWhen,
        name: HeaderName,
        search: String,
        replace: String,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledHeaderEffectWhen {
    Always,
    IfPresent,
    IfAbsent,
}

#[derive(Clone)]
pub(crate) enum CredentialActionPlan {
    Bearer {
        credential: String,
        transport_security: CompiledTransportSecurity,
    },
    Basic {
        username: String,
        password_credential: String,
        transport_security: CompiledTransportSecurity,
    },
    CustomHeader {
        header: HeaderName,
        credential: String,
        transport_security: CompiledTransportSecurity,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CompiledTransportSecurity {
    TlsRequired,
    CleartextAllowed,
}

impl CompiledTransportSecurity {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::TlsRequired => "tls_required",
            Self::CleartextAllowed => "cleartext_allowed",
        }
    }
}

#[derive(Clone)]
pub(crate) struct AuthorizationPlan {
    pub(crate) internal_context_headers: Vec<HeaderName>,
    pub(crate) callback: Option<AuthorizationCallbackPlan>,
    pub(crate) providers: BTreeMap<String, AuthorizationProviderPlan>,
}

#[derive(Clone)]
pub(crate) struct AuthorizationCallbackPlan {
    pub(crate) resume_token_ttl: Duration,
    pub(crate) max_pending_operations: PendingOperationLimit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingOperationLimit(usize);

impl PendingOperationLimit {
    pub(crate) fn try_new(value: usize) -> Option<Self> {
        (value > 0 && value <= MAX_PENDING_OPERATIONS).then_some(Self(value))
    }

    pub(crate) fn get(self) -> usize {
        self.0
    }
}

#[derive(Clone)]
pub(crate) enum AuthorizationProviderPlan {
    Webhook(WebhookProviderPlan),
    Process(ProcessProviderPlan),
    UnixSocket(UnixSocketProviderPlan),
}

#[derive(Clone)]
pub(crate) struct WebhookProviderPlan {
    pub(crate) url: CanonicalUrl,
    pub(crate) timeout: Duration,
    pub(crate) on_failure: CompiledProviderFailureMode,
    pub(crate) include_headers: Vec<HeaderName>,
    pub(crate) include_identity: bool,
    pub(crate) max_request_bytes: usize,
    pub(crate) max_response_bytes: usize,
    pub(crate) outputs: BTreeMap<String, ProviderOutputPlan>,
    pub(crate) tls: Option<WebhookTlsPlan>,
}

#[derive(Clone)]
pub(crate) struct WebhookTlsPlan {
    pub(crate) trust: CompiledTlsTrust,
    pub(crate) ca_certificate: Option<PathBuf>,
}

#[derive(Clone)]
pub(crate) struct ProcessProviderPlan {
    pub(crate) command: PathBuf,
    pub(crate) working_directory: PathBuf,
    pub(crate) args: Vec<String>,
    pub(crate) timeout: Duration,
    pub(crate) on_failure: CompiledProviderFailureMode,
    pub(crate) inherit_environment: bool,
    pub(crate) pass_environment: Vec<String>,
    pub(crate) environment: BTreeMap<String, String>,
    pub(crate) blocked_environment: Vec<String>,
    pub(crate) include_headers: Vec<HeaderName>,
    pub(crate) include_identity: bool,
    pub(crate) include_request_body: bool,
    pub(crate) allow_request_body_replacement: bool,
    pub(crate) max_request_body_bytes: usize,
    pub(crate) max_decoded_request_body_bytes: usize,
    pub(crate) max_stdout_line_bytes: usize,
    pub(crate) max_pending_requests: usize,
    pub(crate) restart_backoff: Duration,
    pub(crate) retire_timeout: Duration,
    pub(crate) outputs: BTreeMap<String, ProviderOutputPlan>,
}

#[derive(Clone)]
pub(crate) struct UnixSocketProviderPlan {
    pub(crate) socket_path: PathBuf,
    pub(crate) timeout: Duration,
    pub(crate) on_failure: CompiledProviderFailureMode,
    pub(crate) include_headers: Vec<HeaderName>,
    pub(crate) include_identity: bool,
    pub(crate) frame_protocol: FrameProtocol,
    pub(crate) request_frame_bytes: usize,
    pub(crate) response_frame_bytes: usize,
    pub(crate) request_allocation_bytes: usize,
    pub(crate) response_allocation_bytes: usize,
    pub(crate) max_pending_requests: usize,
    pub(crate) max_inflight_allocation_bytes: usize,
    pub(crate) peer_uid: Option<u32>,
    pub(crate) outputs: BTreeMap<String, ProviderOutputPlan>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledProviderFailureMode {
    Deny,
    Error,
}

#[derive(Clone)]
pub(crate) enum ProviderOutputPlan {
    Bearer {
        required: bool,
        transport_security: CompiledTransportSecurity,
    },
    Basic {
        username: String,
        required: bool,
        transport_security: CompiledTransportSecurity,
    },
    CustomHeader {
        header: HeaderName,
        required: bool,
        transport_security: CompiledTransportSecurity,
    },
}

#[derive(Clone)]
pub(crate) struct CredentialsPlan {
    pub(crate) inbound: BTreeMap<String, InboundCredentialPlan>,
    pub(crate) sources: BTreeMap<String, CredentialSourcePlan>,
}

#[derive(Clone)]
pub(crate) struct InboundCredentialPlan {
    pub(crate) header: HeaderName,
    pub(crate) process_providers: Vec<String>,
}

#[derive(Clone)]
pub(crate) enum CredentialSourcePlan {
    Environment { variable: String },
    File { path: PathBuf },
}

#[derive(Clone, Default)]
pub(crate) struct ObservationPlan {
    pub(crate) logging: ReloadableLoggingPlan,
    pub(crate) capture: Option<CapturePlan>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReloadableLoggingPlan {
    pub(crate) level: CompiledLogLevel,
    pub(crate) policy_decisions: PolicyDecisionLoggingPlan,
}

impl Default for ReloadableLoggingPlan {
    fn default() -> Self {
        Self {
            level: CompiledLogLevel::Info,
            policy_decisions: PolicyDecisionLoggingPlan::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PolicyDecisionLoggingPlan {
    pub(crate) allows: bool,
    pub(crate) denies: bool,
    pub(crate) allow_level: CompiledDecisionLogLevel,
    pub(crate) deny_level: CompiledDecisionLogLevel,
}

impl Default for PolicyDecisionLoggingPlan {
    fn default() -> Self {
        Self {
            allows: false,
            denies: true,
            allow_level: CompiledDecisionLogLevel::Info,
            deny_level: CompiledDecisionLogLevel::Warn,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompiledDecisionLogLevel {
    Info,
    Warn,
}

#[derive(Clone)]
pub(crate) struct CapturePlan {
    pub(crate) events: Vec<CompiledCaptureEvent>,
    pub(crate) redaction_profile: String,
    pub(crate) sink: CaptureSinkSpec,
    pub(crate) max_body_bytes: usize,
    pub(crate) max_inflight_body_bytes: usize,
    #[cfg(test)]
    pub(crate) working_set: CaptureWorkingSetPlan,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CaptureWorkingSetPlan {
    pub(crate) decode_peak_bytes: usize,
    pub(crate) literal_redaction_peak_bytes: usize,
    pub(crate) expression_successor_peak_bytes: usize,
    pub(crate) serialization_peak_bytes: usize,
    pub(crate) maximum_peak_bytes: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledCaptureEvent {
    RequestAllowed,
    ResponseAllowed,
    RequestDenied,
    ResponseDenied,
}

#[derive(Clone)]
pub(crate) struct SafetyPlan {
    pub(crate) loop_detection: LoopDetectionPlan,
}

#[derive(Clone)]
pub(crate) struct LoopDetectionPlan {
    pub(crate) inject: bool,
    pub(crate) header: HeaderName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledResourcePlan {
    pub(crate) http_body_resources_by_cursor: Vec<HttpBodyResourcePlan>,
    pub(crate) max_reachable_http_body_combined_peak_bytes: usize,
    pub(crate) forward_response_peak_bytes: usize,
    pub(crate) max_reachable_http_exchange_peak_bytes: usize,
    pub(crate) wire_body_full_peak_capacity: Capacity,
    pub(crate) wire_body_quota_key_full_peak_capacity: Capacity,
    pub(crate) webhook_request_allocation_bytes_by_rule: Vec<Option<usize>>,
    pub(crate) webhook_callback_allocation_bytes_by_rule: Vec<Option<usize>>,
    pub(crate) upgrade_wire_working_set_bytes_by_rule: Vec<Option<usize>>,
    pub(crate) max_upgrade_allocation_per_stream: usize,
    pub(crate) max_upgrade_allocation_all_streams: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HttpBodyResourcePlan {
    pub(crate) product_incremental_peak_bytes: usize,
    pub(crate) runtime_replay_capacity_bytes: usize,
    pub(crate) combined_peak_bytes: usize,
}

#[cfg(test)]
impl CompiledResourcePlan {
    pub(crate) fn combined_http_body_peaks_for_test(&self) -> Vec<usize> {
        self.http_body_resources_by_cursor
            .iter()
            .map(|resource| resource.combined_peak_bytes)
            .collect()
    }

    pub(crate) fn runtime_replay_capacities_for_test(&self) -> Vec<usize> {
        self.http_body_resources_by_cursor
            .iter()
            .map(|resource| resource.runtime_replay_capacity_bytes)
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Capacity {
    Unbounded,
    Finite(usize),
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct StaticFingerprint([u8; 32]);

#[derive(Debug, thiserror::Error)]
#[error("failed to fingerprint static product configuration: {0}")]
pub(crate) struct StaticFingerprintError(#[from] serde_json::Error);

impl StaticFingerprint {
    pub(crate) fn from_config(
        config: &StaticProductConfig,
    ) -> Result<Self, StaticFingerprintError> {
        let bytes = serde_json::to_vec(config)?;
        Ok(Self(Sha256::digest(bytes).into()))
    }
}

impl fmt::Debug for StaticFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticFingerprint(")?;
        for byte in &self.0[..8] {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str("...)")
    }
}

pub(super) struct CompiledProductConfig {
    pub(super) static_config: StaticProductConfig,
    pub(super) static_fingerprint: StaticFingerprint,
    pub(super) reloadable_plan: ReloadableProductPlan,
}

impl fmt::Debug for CompiledProductConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledProductConfig")
            .field("static_fingerprint", &self.static_fingerprint)
            .field("reloadable_plan", &self.reloadable_plan)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid configuration at {path}: {message}")]
pub(super) struct ConfigCompileError {
    path: String,
    message: String,
}

impl ConfigCompileError {
    fn at(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

pub(super) fn compile_config(
    mut config: super::authoring::AuthoringConfig,
    config_root: &Path,
) -> Result<CompiledProductConfig, ConfigCompileError> {
    let config_root = normalize_config_root(config_root)?;
    normalize_authored_paths(&mut config, &config_root)?;
    let endpoint_urls = canonical_endpoint_urls(&config)?;

    validate_positive_limits(&config)?;
    validate_identity(&config)?;
    validate_protected_identity_locators(&config)?;
    let listener_facts = validate_listener_control_mitm_matrix(&config)?;
    validate_tls_and_parent_matrix(&config, &listener_facts, &endpoint_urls)?;
    let validation = validate_references_and_security_boundaries(&config)?;
    let redaction = compile_redaction_plan(&config.redaction)?;
    let resource_plan = compile_resource_plan(&config, &redaction)?;

    let static_config =
        compile_static_config(&config, config_root.clone(), endpoint_urls.callback.clone())?;
    let ValidationFacts {
        compiled_urls_by_rule,
        capture_sink,
    } = validation;
    let reloadable_plan = compile_reloadable_plan(
        &config,
        &config_root,
        &endpoint_urls,
        compiled_urls_by_rule,
        capture_sink,
        resource_plan,
        redaction,
    )?;
    UnboundStandaloneGenerationPlan::preflight(&reloadable_plan)
        .map_err(|error| ConfigCompileError::at("compiled_generation", error.to_string()))?;
    let static_fingerprint = StaticFingerprint::from_config(&static_config)
        .map_err(|error| ConfigCompileError::at("schema_version", error.to_string()))?;

    Ok(CompiledProductConfig {
        static_fingerprint,
        static_config,
        reloadable_plan,
    })
}

struct CanonicalEndpointUrls {
    parent_proxy: Option<CanonicalUrl>,
    callback: Option<CanonicalUrl>,
    webhooks: BTreeMap<String, CanonicalUrl>,
}

fn canonical_endpoint_urls(
    config: &super::authoring::AuthoringConfig,
) -> Result<CanonicalEndpointUrls, ConfigCompileError> {
    let parent_proxy = config
        .egress
        .parent_proxy
        .as_ref()
        .map(|parent| canonical_endpoint_url(&parent.url, "egress.parent_proxy.url"))
        .transpose()?;
    let callback = config
        .authorization
        .callback
        .as_ref()
        .map(|callback| {
            canonical_endpoint_url(&callback.public_url, "authorization.callback.public_url")
        })
        .transpose()?;
    let mut webhooks = BTreeMap::new();
    for (name, provider) in &config.authorization.providers {
        if let AuthorizationProviderConfig::Webhook(webhook) = provider {
            webhooks.insert(
                name.clone(),
                canonical_endpoint_url(
                    &webhook.url,
                    &format!("authorization.providers.{name}.url"),
                )?,
            );
        }
    }
    Ok(CanonicalEndpointUrls {
        parent_proxy,
        callback,
        webhooks,
    })
}

fn canonical_endpoint_url(value: &str, path: &str) -> Result<CanonicalUrl, ConfigCompileError> {
    canonicalize_http_url(value).map_err(|error| ConfigCompileError::at(path, error.to_string()))
}

fn normalize_config_root(root: &Path) -> Result<PathBuf, ConfigCompileError> {
    if !root.is_absolute() {
        return Err(ConfigCompileError::at(
            "config root",
            "the loader must provide an absolute config-file directory",
        ));
    }
    lexical_normalize_absolute(root).ok_or_else(|| {
        ConfigCompileError::at(
            "config root",
            "could not normalize the config-file directory",
        )
    })
}

fn normalize_authored_paths(
    config: &mut super::authoring::AuthoringConfig,
    root: &Path,
) -> Result<(), ConfigCompileError> {
    for (endpoint, field) in [
        config
            .listeners
            .explicit_http
            .as_mut()
            .map(|listener| &mut listener.endpoint),
        config
            .listeners
            .transparent_http
            .as_mut()
            .map(|listener| &mut listener.endpoint),
        config
            .listeners
            .explicit_https
            .as_mut()
            .map(|listener| &mut listener.endpoint),
        config
            .listeners
            .transparent_https
            .as_mut()
            .map(|listener| &mut listener.endpoint),
    ]
    .into_iter()
    .zip([
        "listeners.explicit_http.endpoint.transport.path",
        "listeners.transparent_http.endpoint.transport.path",
        "listeners.explicit_https.endpoint.transport.path",
        "listeners.transparent_https.endpoint.transport.path",
    ]) {
        if let Some(ListenerEndpointConfig::AccessFlow {
            transport: AccessFlowTransportConfig::Unix { path, .. },
            ..
        }) = endpoint
        {
            if !path.is_absolute() {
                return Err(ConfigCompileError::at(field, "must be an absolute path"));
            }
            let normalized = lexical_normalize_absolute(path)
                .ok_or_else(|| ConfigCompileError::at(field, "could not be normalized"))?;
            if normalized != *path {
                return Err(ConfigCompileError::at(field, "must already be normalized"));
            }
        }
    }
    if let Some(control) = config.control.as_mut() {
        if let Some(tls) = control.tls.as_mut() {
            normalize_tls_identity_paths(tls, root, "control.tls")?;
        }
    }
    if let Some(listener) = config.listeners.explicit_https.as_mut() {
        normalize_tls_identity_paths(&mut listener.tls, root, "listeners.explicit_https.tls")?;
    }
    if let Some(mitm) = config.mitm.as_mut() {
        match mitm {
            MitmConfig::Generated(value) => {
                value.directory =
                    normalize_authored_path(root, &value.directory, "mitm.directory")?;
            }
            MitmConfig::Files(value) => {
                value.ca_certificate =
                    normalize_authored_path(root, &value.ca_certificate, "mitm.ca_certificate")?;
                value.ca_private_key =
                    normalize_authored_path(root, &value.ca_private_key, "mitm.ca_private_key")?;
                value.directory =
                    normalize_authored_path(root, &value.directory, "mitm.directory")?;
            }
        }
    }
    normalize_transport_tls_paths(&mut config.egress.origin_tls, root, "egress.origin_tls")?;
    if let Some(parent) = config.egress.parent_proxy.as_mut() {
        if let Some(tls) = parent.tls.as_mut() {
            if let Some(path) = tls.ca_certificate.as_mut() {
                *path =
                    normalize_authored_path(root, path, "egress.parent_proxy.tls.ca_certificate")?;
            }
        }
        if let Some(ParentProxyPresentationConfig::BearerFile { path }) =
            parent.presentation.as_ref()
        {
            validate_identity_file_locator(path, "egress.parent_proxy.presentation.path")?;
        }
    }
    if let Some(identity) = config.identity.as_mut() {
        for (index, token) in identity.resolver.tokens.iter().enumerate() {
            if let super::authoring::StaticIdentityTokenConfig::File { path, .. } = token {
                validate_identity_file_locator(
                    path,
                    &format!("identity.resolver.tokens[{index}].path"),
                )?;
            }
        }
    }
    for (name, provider) in &mut config.authorization.providers {
        match provider {
            AuthorizationProviderConfig::Webhook(value) => {
                if let Some(tls) = value.tls.as_mut() {
                    if let Some(path) = tls.ca_certificate.as_mut() {
                        *path = normalize_authored_path(
                            root,
                            path,
                            &format!("authorization.providers.{name}.tls.ca_certificate"),
                        )?;
                    }
                }
            }
            AuthorizationProviderConfig::Process(value) => {
                value.command = normalize_authored_path(
                    root,
                    &value.command,
                    &format!("authorization.providers.{name}.command"),
                )?;
            }
            AuthorizationProviderConfig::UnixSocket(_) => {}
        }
    }
    for (name, source) in &mut config.credentials.sources {
        if let CredentialSourceConfig::File(value) = source {
            value.path = normalize_authored_path(
                root,
                &value.path,
                &format!("credentials.sources.{name}.path"),
            )?;
        }
    }
    if let Some(capture) = config.observation.capture.as_mut() {
        capture.directory =
            normalize_authored_path(root, &capture.directory, "observation.capture.directory")?;
    }
    if let Some(directory) = config.observation.logging.directory.as_mut() {
        *directory = normalize_authored_path(root, directory, "observation.logging.directory")?;
    }
    Ok(())
}

fn normalize_tls_identity_paths(
    identity: &mut StaticTlsIdentityConfig,
    root: &Path,
    prefix: &str,
) -> Result<(), ConfigCompileError> {
    identity.certificate_chain = normalize_authored_path(
        root,
        &identity.certificate_chain,
        &format!("{prefix}.certificate_chain"),
    )?;
    identity.private_key = normalize_authored_path(
        root,
        &identity.private_key,
        &format!("{prefix}.private_key"),
    )?;
    Ok(())
}

fn normalize_transport_tls_paths(
    tls: &mut TransportTlsConfig,
    root: &Path,
    prefix: &str,
) -> Result<(), ConfigCompileError> {
    if let Some(path) = tls.ca_certificate.as_mut() {
        *path = normalize_authored_path(root, path, &format!("{prefix}.ca_certificate"))?;
    }
    Ok(())
}

fn normalize_authored_path(
    root: &Path,
    value: &Path,
    field: &str,
) -> Result<PathBuf, ConfigCompileError> {
    if value.as_os_str().is_empty() {
        return Err(ConfigCompileError::at(field, "path must not be empty"));
    }
    if value.is_absolute() {
        return lexical_normalize_absolute(value)
            .ok_or_else(|| ConfigCompileError::at(field, "absolute path could not be normalized"));
    }

    let mut relative = PathBuf::new();
    for component in value.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => relative.push(part),
            Component::ParentDir => {
                if !relative.pop() {
                    return Err(ConfigCompileError::at(
                        field,
                        "relative path must not escape the configuration directory",
                    ));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(ConfigCompileError::at(
                    field,
                    "invalid relative path component",
                ));
            }
        }
    }
    if relative.as_os_str().is_empty() {
        return Err(ConfigCompileError::at(
            field,
            "path must identify a child entry",
        ));
    }
    Ok(root.join(relative))
}

fn lexical_normalize_absolute(path: &Path) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
        }
    }
    normalized.is_absolute().then_some(normalized)
}

fn validate_positive_limits(
    config: &super::authoring::AuthoringConfig,
) -> Result<(), ConfigCompileError> {
    check_range(
        "service.max_retiring_generations",
        config.service.max_retiring_generations,
        MAX_RETIRING_GENERATIONS,
    )?;
    check_range(
        "service.max_active_upgrades",
        config.service.max_active_upgrades,
        MAX_ACTIVE_UPGRADES,
    )?;
    check_range(
        "service.max_active_webhook_deliveries",
        config.service.max_active_webhook_deliveries,
        MAX_ACTIVE_WEBHOOK_DELIVERIES,
    )?;
    if !(MIN_WEBHOOK_TRANSPORT_BUFFER_BYTES..=MAX_WEBHOOK_TRANSPORT_BUFFER_BYTES)
        .contains(&config.service.webhook_transport_buffer_bytes)
    {
        return Err(ConfigCompileError::at(
            "service.webhook_transport_buffer_bytes",
            format!(
                "must be between {MIN_WEBHOOK_TRANSPORT_BUFFER_BYTES} and {MAX_WEBHOOK_TRANSPORT_BUFFER_BYTES}"
            ),
        ));
    }
    check_range(
        "service.max_webhook_transport_bytes",
        config.service.max_webhook_transport_bytes,
        MAX_WEBHOOK_TRANSPORT_BYTES,
    )?;
    let webhook_transport_per_delivery = config
        .service
        .webhook_transport_buffer_bytes
        .checked_mul(2)
        .ok_or_else(|| {
            ConfigCompileError::at("service", "webhook transport arithmetic overflow")
        })?;
    let required_webhook_transport = config
        .service
        .max_active_webhook_deliveries
        .checked_mul(webhook_transport_per_delivery)
        .ok_or_else(|| {
            ConfigCompileError::at("service", "webhook transport arithmetic overflow")
        })?;
    if required_webhook_transport > config.service.max_webhook_transport_bytes {
        return Err(ConfigCompileError::at(
            "service.max_webhook_transport_bytes",
            "must hold two transport buffers for every active webhook delivery",
        ));
    }
    check_range(
        "service.upgrade_relay_buffer_bytes",
        config.service.upgrade_relay_buffer_bytes,
        MAX_UPGRADE_RELAY_BUFFER_BYTES,
    )?;
    check_range(
        "service.max_upgrade_buffer_bytes",
        config.service.max_upgrade_buffer_bytes,
        MAX_UPGRADE_BUFFER_BYTES,
    )?;
    check_range(
        "service.max_inflight_wire_body_bytes",
        config.service.max_inflight_wire_body_bytes,
        MAX_WIRE_BODY_BYTES,
    )?;
    check_range(
        "service.max_inflight_wire_body_bytes_per_quota_key",
        config.service.max_inflight_wire_body_bytes_per_quota_key,
        MAX_WIRE_BODY_BYTES_PER_QUOTA_KEY,
    )?;
    check_range(
        "service.min_wire_body_concurrency",
        config.service.min_wire_body_concurrency,
        MAX_MIN_WIRE_BODY_CONCURRENCY,
    )?;
    check_range(
        "service.max_content_decoding_expansion_ratio",
        config.service.max_content_decoding_expansion_ratio,
        MAX_CONTENT_DECODING_RATIO,
    )?;
    validate_forwarding_limits(&config.service.forwarding)?;
    let four_quota = config
        .service
        .max_inflight_wire_body_bytes_per_quota_key
        .checked_mul(4)
        .ok_or_else(|| ConfigCompileError::at("service", "wire-body quota arithmetic overflow"))?;
    if four_quota > config.service.max_inflight_wire_body_bytes {
        return Err(ConfigCompileError::at(
            "service.max_inflight_wire_body_bytes_per_quota_key",
            "four quota-key sub-limits must fit in the global wire-body pool",
        ));
    }
    if let Some(control) = &config.control {
        check_range(
            "control.max_connections",
            control.max_connections,
            MAX_CONTROL_CONNECTIONS,
        )?;
        check_range(
            "control.max_request_body_bytes",
            control.max_request_body_bytes,
            MAX_CONTROL_BODY_BYTES,
        )?;
        control_parser_arena_bytes(control)?;
    }
    if let Some(callback) = &config.authorization.callback {
        check_range(
            "authorization.callback.max_pending_operations",
            callback.max_pending_operations,
            MAX_PENDING_OPERATIONS,
        )?;
    }
    if config.authorization.providers.len() > MAX_PROVIDERS {
        return Err(ConfigCompileError::at(
            "authorization.providers",
            format!("must contain no more than {MAX_PROVIDERS} providers"),
        ));
    }
    let process_count = config
        .authorization
        .providers
        .values()
        .filter(|provider| matches!(provider, AuthorizationProviderConfig::Process(_)))
        .count();
    if process_count > MAX_PROCESS_PROVIDERS {
        return Err(ConfigCompileError::at(
            "authorization.providers",
            format!("must contain no more than {MAX_PROCESS_PROVIDERS} process providers"),
        ));
    }
    validate_logging_capture_limits(config)?;
    validate_provider_limits(config)?;
    validate_redaction_limits(config)?;
    Ok(())
}

fn validate_identity(config: &super::authoring::AuthoringConfig) -> Result<(), ConfigCompileError> {
    for (name, listener) in [
        (
            "listeners.transparent_http",
            config
                .listeners
                .transparent_http
                .as_ref()
                .map(|value| (&value.endpoint, value.identity.as_ref())),
        ),
        (
            "listeners.transparent_https",
            config
                .listeners
                .transparent_https
                .as_ref()
                .map(|value| (&value.endpoint, value.identity.as_ref())),
        ),
    ] {
        let Some((ListenerEndpointConfig::Tcp { .. }, Some(_identity))) = listener else {
            continue;
        };
        return Err(ConfigCompileError::at(
            format!("{name}.identity.mode"),
            "optional or required identity is supported only on a transparent access_flow endpoint",
        ));
    }
    let enabled_listener = [
        config
            .listeners
            .explicit_http
            .as_ref()
            .and_then(|value| value.identity.as_ref()),
        config
            .listeners
            .transparent_http
            .as_ref()
            .and_then(|value| value.identity.as_ref()),
        config
            .listeners
            .explicit_https
            .as_ref()
            .and_then(|value| value.identity.as_ref()),
        config
            .listeners
            .transparent_https
            .as_ref()
            .and_then(|value| value.identity.as_ref()),
    ]
    .into_iter()
    .flatten()
    .next()
    .is_some();
    let optional_listener = [
        config
            .listeners
            .explicit_http
            .as_ref()
            .and_then(|value| value.identity.as_ref()),
        config
            .listeners
            .transparent_http
            .as_ref()
            .and_then(|value| value.identity.as_ref()),
        config
            .listeners
            .explicit_https
            .as_ref()
            .and_then(|value| value.identity.as_ref()),
        config
            .listeners
            .transparent_https
            .as_ref()
            .and_then(|value| value.identity.as_ref()),
    ]
    .into_iter()
    .flatten()
    .any(|identity| matches!(identity.mode, ListenerIdentityModeConfig::Optional));

    validate_policy_identity_shapes(config, enabled_listener, optional_listener)?;

    let Some(identity) = &config.identity else {
        if enabled_listener {
            return Err(ConfigCompileError::at(
                "identity",
                "is required when a listener enables identity",
            ));
        }
        if config
            .policy
            .rules
            .iter()
            .any(|rule| rule.identity_subjects.is_some())
        {
            return Err(ConfigCompileError::at(
                "policy.rules.identity_subjects",
                "requires a configured identity resolver",
            ));
        }
        return Ok(());
    };
    if !enabled_listener {
        return Err(ConfigCompileError::at(
            "identity",
            "requires at least one optional or required identity listener",
        ));
    }
    check_range(
        "identity.max_pending_authentications",
        identity.max_pending_authentications,
        MAX_PENDING_AUTHENTICATIONS,
    )?;
    if identity.resolver.principals.len() > MAX_IDENTITY_PRINCIPALS {
        return Err(ConfigCompileError::at(
            "identity.resolver.principals",
            "exceeds the static identity principal limit",
        ));
    }
    if identity.resolver.groups.len() > MAX_IDENTITY_GROUPS {
        return Err(ConfigCompileError::at(
            "identity.resolver.groups",
            "exceeds the static identity group limit",
        ));
    }
    if identity.resolver.tokens.len() > MAX_IDENTITY_TOKENS {
        return Err(ConfigCompileError::at(
            "identity.resolver.tokens",
            "exceeds the static identity token-record limit",
        ));
    }
    check_range(
        "identity.max_pending_authentications_per_connection",
        identity.max_pending_authentications_per_connection,
        MAX_PENDING_AUTHENTICATIONS_PER_CONNECTION,
    )?;
    if identity.max_pending_authentications_per_connection > identity.max_pending_authentications {
        return Err(ConfigCompileError::at(
            "identity.max_pending_authentications_per_connection",
            "must not exceed identity.max_pending_authentications",
        ));
    }

    let authority = AuthorityId::new(identity.resolver.authority.clone()).map_err(|error| {
        ConfigCompileError::at("identity.resolver.authority", error.to_string())
    })?;
    IdentityAudience::new("acl-proxy.identity")
        .map_err(|error| ConfigCompileError::at("identity.resolver", error.to_string()))?;

    let mut principal_ids = BTreeSet::new();
    for (index, principal) in identity.resolver.principals.iter().enumerate() {
        let id = PrincipalId::new(principal.id.clone()).map_err(|error| {
            ConfigCompileError::at(
                format!("identity.resolver.principals[{index}].id"),
                error.to_string(),
            )
        })?;
        if !principal_ids.insert(id) {
            return Err(ConfigCompileError::at(
                format!("identity.resolver.principals[{index}].id"),
                "duplicates an earlier principal",
            ));
        }
    }
    if principal_ids.is_empty() {
        return Err(ConfigCompileError::at(
            "identity.resolver.principals",
            "must not be empty",
        ));
    }

    let mut group_ids = BTreeSet::new();
    let mut membership_count = 0usize;
    let mut groups_per_principal = BTreeMap::<PrincipalId, usize>::new();
    for (index, group) in identity.resolver.groups.iter().enumerate() {
        let id = GroupId::new(group.id.clone()).map_err(|error| {
            ConfigCompileError::at(
                format!("identity.resolver.groups[{index}].id"),
                error.to_string(),
            )
        })?;
        if !group_ids.insert(id) {
            return Err(ConfigCompileError::at(
                format!("identity.resolver.groups[{index}].id"),
                "duplicates an earlier group",
            ));
        }
        let mut members = BTreeSet::new();
        for (member_index, member) in group.members.iter().enumerate() {
            let member = PrincipalId::new(member.clone()).map_err(|error| {
                ConfigCompileError::at(
                    format!("identity.resolver.groups[{index}].members[{member_index}]"),
                    error.to_string(),
                )
            })?;
            if !principal_ids.contains(&member) {
                return Err(ConfigCompileError::at(
                    format!("identity.resolver.groups[{index}].members[{member_index}]"),
                    "references an unknown principal",
                ));
            }
            if !members.insert(member.clone()) {
                return Err(ConfigCompileError::at(
                    format!("identity.resolver.groups[{index}].members[{member_index}]"),
                    "duplicates an earlier member",
                ));
            }
            membership_count = membership_count.checked_add(1).ok_or_else(|| {
                ConfigCompileError::at(
                    "identity.resolver.groups",
                    "identity membership arithmetic overflow",
                )
            })?;
            let principal_group_count = groups_per_principal.entry(member).or_default();
            *principal_group_count = principal_group_count.checked_add(1).ok_or_else(|| {
                ConfigCompileError::at(
                    "identity.resolver.groups",
                    "identity membership arithmetic overflow",
                )
            })?;
            if *principal_group_count > MAX_IDENTITY_GROUPS_PER_PRINCIPAL {
                return Err(ConfigCompileError::at(
                    format!("identity.resolver.groups[{index}].members"),
                    "a principal exceeds the static identity group-membership limit",
                ));
            }
        }
    }
    if membership_count > MAX_IDENTITY_MEMBERSHIPS {
        return Err(ConfigCompileError::at(
            "identity.resolver.groups",
            "exceeds the static identity membership limit",
        ));
    }
    validate_policy_identity_subjects(config, &authority, &principal_ids, &group_ids)?;

    let mut token_ids = BTreeSet::new();
    let mut source_variables = BTreeSet::new();
    for (index, token) in identity.resolver.tokens.iter().enumerate() {
        let (id_value, principal_value, variable) = match token {
            super::authoring::StaticIdentityTokenConfig::Environment {
                id,
                principal,
                variable,
            } => (id, principal, Some(variable)),
            super::authoring::StaticIdentityTokenConfig::File { id, principal, .. } => {
                (id, principal, None)
            }
        };
        let id = TokenId::new(id_value.clone()).map_err(|error| {
            ConfigCompileError::at(
                format!("identity.resolver.tokens[{index}].id"),
                error.to_string(),
            )
        })?;
        if !token_ids.insert(id) {
            return Err(ConfigCompileError::at(
                format!("identity.resolver.tokens[{index}].id"),
                "duplicates an earlier token record",
            ));
        }
        let principal = PrincipalId::new(principal_value.clone()).map_err(|error| {
            ConfigCompileError::at(
                format!("identity.resolver.tokens[{index}].principal"),
                error.to_string(),
            )
        })?;
        if !principal_ids.contains(&principal) {
            return Err(ConfigCompileError::at(
                format!("identity.resolver.tokens[{index}].principal"),
                "references an unknown principal",
            ));
        }
        if let Some(variable) = variable {
            if !valid_identity_environment_name(variable) {
                return Err(ConfigCompileError::at(
                    format!("identity.resolver.tokens[{index}].variable"),
                    "must use the ACL Proxy identity-token environment namespace",
                ));
            }
            if !source_variables.insert(variable.as_str()) {
                return Err(ConfigCompileError::at(
                    format!("identity.resolver.tokens[{index}].variable"),
                    "duplicates an earlier identity environment source",
                ));
            }
        }
    }
    if token_ids.is_empty() {
        return Err(ConfigCompileError::at(
            "identity.resolver.tokens",
            "must not be empty",
        ));
    }

    let protected_source_variables = identity_environment_sources(config);
    for (name, provider) in &config.authorization.providers {
        let AuthorizationProviderConfig::Process(provider) = provider else {
            continue;
        };
        if provider.inherit_environment && !protected_source_variables.is_empty() {
            return Err(ConfigCompileError::at(
                format!("authorization.providers.{name}.inherit_environment"),
                "must be false when identity token sources are configured",
            ));
        }
        for variable in &provider.pass_environment {
            if protected_source_variables.contains(variable) {
                return Err(ConfigCompileError::at(
                    format!("authorization.providers.{name}.pass_environment"),
                    "must not expose an identity token source",
                ));
            }
        }
        for variable in provider.environment.keys() {
            if protected_source_variables.contains(variable) {
                return Err(ConfigCompileError::at(
                    format!("authorization.providers.{name}.environment"),
                    "must not define an identity token source",
                ));
            }
        }
    }

    for (name, listener) in [(
        "listeners.explicit_http",
        config
            .listeners
            .explicit_http
            .as_ref()
            .map(|value| (&value.endpoint, value.identity.as_ref())),
    )] {
        let Some((ListenerEndpointConfig::Tcp { address }, Some(_listener_identity))) = listener
        else {
            continue;
        };
        if !address.ip().is_loopback() {
            return Err(ConfigCompileError::at(
                format!("{name}.identity.mode"),
                "identity over cleartext TCP requires a loopback listener",
            ));
        }
    }
    Ok(())
}

fn validate_policy_identity_shapes(
    config: &super::authoring::AuthoringConfig,
    enabled_listener: bool,
    optional_listener: bool,
) -> Result<(), ConfigCompileError> {
    let mut aggregate_identity_subjects = 0usize;
    for (index, rule) in config.policy.rules.iter().enumerate() {
        let prefix = format!("policy.rules[{index}]");
        if let Some(states) = &rule.identity_states {
            if states.is_empty() {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.identity_states"),
                    "must not be empty when present",
                ));
            }
            let mut unique = BTreeSet::new();
            for state in states {
                if !unique.insert(*state) {
                    return Err(ConfigCompileError::at(
                        format!("{prefix}.identity_states"),
                        "must not contain duplicates",
                    ));
                }
            }
            if states.contains(&IdentityStateConfig::Anonymous) && !optional_listener {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.identity_states"),
                    "anonymous identity requires at least one optional identity listener",
                ));
            }
        }
        if let Some(subjects) = &rule.identity_subjects {
            aggregate_identity_subjects = aggregate_identity_subjects
                .checked_add(subjects.len())
                .ok_or_else(|| {
                ConfigCompileError::at(
                    format!("{prefix}.identity_subjects"),
                    "aggregate identity subject count overflowed",
                )
            })?;
            if aggregate_identity_subjects > MAX_IDENTITY_SUBJECTS_PER_SNAPSHOT {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.identity_subjects"),
                    format!(
                        "would exceed the aggregate policy limit of \
                         {MAX_IDENTITY_SUBJECTS_PER_SNAPSHOT} identity subjects"
                    ),
                ));
            }
            if subjects.is_empty() {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.identity_subjects"),
                    "must not be empty when present",
                ));
            }
            if rule.identity_states.as_deref() != Some(&[IdentityStateConfig::Authenticated]) {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.identity_subjects"),
                    "requires identity_states = [\"authenticated\"]",
                ));
            }
            if !enabled_listener {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.identity_subjects"),
                    "authenticated subjects require at least one identity-enabled listener",
                ));
            }
        }
    }
    Ok(())
}

fn validate_policy_identity_subjects(
    config: &super::authoring::AuthoringConfig,
    resolver_authority: &AuthorityId,
    principals: &BTreeSet<PrincipalId>,
    groups: &BTreeSet<GroupId>,
) -> Result<(), ConfigCompileError> {
    for (rule_index, rule) in config.policy.rules.iter().enumerate() {
        let Some(subjects) = &rule.identity_subjects else {
            continue;
        };
        let path = format!("policy.rules[{rule_index}].identity_subjects");
        let mut unique = BTreeSet::new();
        for (subject_index, subject) in subjects.iter().enumerate() {
            let subject_path = format!("{path}[{subject_index}]");
            let compiled = match subject {
                IdentitySubjectConfig::Principal { authority, id } => {
                    let authority = AuthorityId::new(authority.clone()).map_err(|error| {
                        ConfigCompileError::at(
                            format!("{subject_path}.authority"),
                            error.to_string(),
                        )
                    })?;
                    if &authority != resolver_authority {
                        return Err(ConfigCompileError::at(
                            format!("{subject_path}.authority"),
                            "must match the configured identity resolver authority",
                        ));
                    }
                    let id = PrincipalId::new(id.clone()).map_err(|error| {
                        ConfigCompileError::at(format!("{subject_path}.id"), error.to_string())
                    })?;
                    if !principals.contains(&id) {
                        return Err(ConfigCompileError::at(
                            format!("{subject_path}.id"),
                            "references an unknown identity principal",
                        ));
                    }
                    IdentitySubject::Principal { authority, id }
                }
                IdentitySubjectConfig::Group { authority, id } => {
                    let authority = AuthorityId::new(authority.clone()).map_err(|error| {
                        ConfigCompileError::at(
                            format!("{subject_path}.authority"),
                            error.to_string(),
                        )
                    })?;
                    if &authority != resolver_authority {
                        return Err(ConfigCompileError::at(
                            format!("{subject_path}.authority"),
                            "must match the configured identity resolver authority",
                        ));
                    }
                    let id = GroupId::new(id.clone()).map_err(|error| {
                        ConfigCompileError::at(format!("{subject_path}.id"), error.to_string())
                    })?;
                    if !groups.contains(&id) {
                        return Err(ConfigCompileError::at(
                            format!("{subject_path}.id"),
                            "references an unknown identity group",
                        ));
                    }
                    IdentitySubject::Group { authority, id }
                }
            };
            if !unique.insert(compiled) {
                return Err(ConfigCompileError::at(
                    subject_path,
                    "duplicates an earlier identity subject",
                ));
            }
        }
    }
    Ok(())
}

fn identity_environment_sources(config: &super::authoring::AuthoringConfig) -> BTreeSet<String> {
    config
        .identity
        .iter()
        .flat_map(|identity| identity.resolver.tokens.iter())
        .filter_map(|token| match token {
            super::authoring::StaticIdentityTokenConfig::Environment { variable, .. } => {
                Some(variable.clone())
            }
            super::authoring::StaticIdentityTokenConfig::File { .. } => None,
        })
        .chain(
            config
                .egress
                .parent_proxy
                .iter()
                .filter_map(|parent| match &parent.presentation {
                    Some(ParentProxyPresentationConfig::BearerEnvironment { variable }) => {
                        Some(variable.clone())
                    }
                    Some(ParentProxyPresentationConfig::BearerFile { .. }) | None => None,
                }),
        )
        .collect()
}

fn identity_file_sources(config: &super::authoring::AuthoringConfig) -> BTreeSet<PathBuf> {
    config
        .identity
        .iter()
        .flat_map(|identity| identity.resolver.tokens.iter())
        .filter_map(|token| match token {
            super::authoring::StaticIdentityTokenConfig::File { path, .. } => Some(path.clone()),
            super::authoring::StaticIdentityTokenConfig::Environment { .. } => None,
        })
        .chain(
            config
                .egress
                .parent_proxy
                .iter()
                .filter_map(|parent| match &parent.presentation {
                    Some(ParentProxyPresentationConfig::BearerFile { path }) => Some(path.clone()),
                    Some(ParentProxyPresentationConfig::BearerEnvironment { .. }) | None => None,
                }),
        )
        .collect()
}

fn validate_protected_identity_locators(
    config: &super::authoring::AuthoringConfig,
) -> Result<(), ConfigCompileError> {
    let protected_environment = identity_environment_sources(config);
    let protected_files = identity_file_sources(config);

    for (name, provider) in &config.authorization.providers {
        match provider {
            AuthorizationProviderConfig::Process(provider) => {
                if provider.inherit_environment && !protected_environment.is_empty() {
                    return Err(ConfigCompileError::at(
                        format!("authorization.providers.{name}.inherit_environment"),
                        "must be false when identity token sources are configured",
                    ));
                }
                if provider
                    .pass_environment
                    .iter()
                    .any(|source| protected_environment.contains(source))
                {
                    return Err(ConfigCompileError::at(
                        format!("authorization.providers.{name}.pass_environment"),
                        "must not expose an identity token source",
                    ));
                }
                if provider
                    .environment
                    .keys()
                    .any(|source| protected_environment.contains(source))
                {
                    return Err(ConfigCompileError::at(
                        format!("authorization.providers.{name}.environment"),
                        "must not define an identity token source",
                    ));
                }
                reject_protected_file_overlap(
                    &protected_files,
                    &provider.command,
                    &format!("authorization.providers.{name}.command"),
                )?;
            }
            AuthorizationProviderConfig::Webhook(provider) => {
                if let Some(path) = provider
                    .tls
                    .as_ref()
                    .and_then(|tls| tls.ca_certificate.as_ref())
                {
                    reject_protected_file_overlap(
                        &protected_files,
                        path,
                        &format!("authorization.providers.{name}.tls.ca_certificate"),
                    )?;
                }
            }
            AuthorizationProviderConfig::UnixSocket(_) => {}
        }
    }

    for (name, source) in &config.credentials.sources {
        let overlaps = match source {
            CredentialSourceConfig::Environment(source) => {
                protected_environment.contains(&source.variable)
            }
            CredentialSourceConfig::File(source) => protected_files.contains(&source.path),
        };
        if overlaps {
            return Err(ConfigCompileError::at(
                format!("credentials.sources.{name}"),
                "must not overlap an identity token source",
            ));
        }
    }

    for (profile_name, profile) in &config.redaction.profiles {
        for (rule_index, rule) in profile.rules.iter().enumerate() {
            if rule
                .literal_environment_variables
                .iter()
                .any(|source| protected_environment.contains(source))
            {
                return Err(ConfigCompileError::at(
                    format!("redaction.profiles.{profile_name}.rules[{rule_index}]"),
                    "must not use an identity token source",
                ));
            }
        }
    }

    if let Some(tls) = config
        .control
        .as_ref()
        .and_then(|control| control.tls.as_ref())
    {
        reject_protected_file_overlap(
            &protected_files,
            &tls.certificate_chain,
            "control.tls.certificate_chain",
        )?;
        reject_protected_file_overlap(
            &protected_files,
            &tls.private_key,
            "control.tls.private_key",
        )?;
    }
    if let Some(tls) = config
        .listeners
        .explicit_https
        .as_ref()
        .map(|listener| &listener.tls)
    {
        reject_protected_file_overlap(
            &protected_files,
            &tls.certificate_chain,
            "listeners.explicit_https.tls.certificate_chain",
        )?;
        reject_protected_file_overlap(
            &protected_files,
            &tls.private_key,
            "listeners.explicit_https.tls.private_key",
        )?;
    }
    if let Some(MitmConfig::Files(mitm)) = config.mitm.as_ref() {
        reject_protected_file_overlap(
            &protected_files,
            &mitm.ca_certificate,
            "mitm.ca_certificate",
        )?;
        reject_protected_file_overlap(
            &protected_files,
            &mitm.ca_private_key,
            "mitm.ca_private_key",
        )?;
    }
    if let Some(path) = config.egress.origin_tls.ca_certificate.as_ref() {
        reject_protected_file_overlap(&protected_files, path, "egress.origin_tls.ca_certificate")?;
    }
    if let Some(path) = config
        .egress
        .parent_proxy
        .as_ref()
        .and_then(|parent| parent.tls.as_ref())
        .and_then(|tls| tls.ca_certificate.as_ref())
    {
        reject_protected_file_overlap(
            &protected_files,
            path,
            "egress.parent_proxy.tls.ca_certificate",
        )?;
    }

    Ok(())
}

fn reject_protected_file_overlap(
    protected_files: &BTreeSet<PathBuf>,
    candidate: &Path,
    field: &str,
) -> Result<(), ConfigCompileError> {
    if protected_files.contains(candidate) {
        return Err(ConfigCompileError::at(
            field,
            "must not overlap an identity token source",
        ));
    }
    Ok(())
}

fn valid_identity_environment_name(value: &str) -> bool {
    if value.len() > 256 {
        return false;
    }
    let Some(middle) = value
        .strip_prefix("AW_")
        .and_then(|value| value.strip_suffix("IDENTITY_TOKEN"))
    else {
        return false;
    };
    let mut remaining = middle;
    while !remaining.is_empty() {
        let Some(separator) = remaining.find('_') else {
            return false;
        };
        let segment = &remaining[..separator];
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return false;
        }
        remaining = &remaining[separator + 1..];
    }
    true
}

fn validate_identity_file_locator(path: &Path, field: &str) -> Result<(), ConfigCompileError> {
    const MAX_IDENTITY_PATH_BYTES: usize = 4_096;
    const MAX_IDENTITY_COMPONENT_BYTES: usize = 255;

    if !path.is_absolute() {
        return Err(ConfigCompileError::at(
            field,
            "must be an already absolute, lexically normalized identity file path",
        ));
    }
    let normalized = lexical_normalize_absolute(path).ok_or_else(|| {
        ConfigCompileError::at(
            field,
            "must be an already absolute, lexically normalized identity file path",
        )
    })?;
    if normalized.as_os_str().as_encoded_bytes() != path.as_os_str().as_encoded_bytes() {
        return Err(ConfigCompileError::at(
            field,
            "must be an already absolute, lexically normalized identity file path",
        ));
    }
    if path.as_os_str().as_encoded_bytes().len() > MAX_IDENTITY_PATH_BYTES {
        return Err(ConfigCompileError::at(
            field,
            "exceeds the identity file path limit",
        ));
    }
    let mut has_leaf = false;
    for component in path.components() {
        if let Component::Normal(name) = component {
            has_leaf = true;
            if name.as_encoded_bytes().len() > MAX_IDENTITY_COMPONENT_BYTES {
                return Err(ConfigCompileError::at(
                    field,
                    "contains a component over the identity file path component limit",
                ));
            }
        }
    }
    if !has_leaf {
        return Err(ConfigCompileError::at(
            field,
            "must identify an identity file",
        ));
    }
    Ok(())
}

fn validate_forwarding_limits(
    forwarding: &super::authoring::ForwardingConfig,
) -> Result<(), ConfigCompileError> {
    for (field, timeout) in [
        ("connect_timeout", forwarding.connect_timeout.get()),
        (
            "response_head_timeout",
            forwarding.response_head_timeout.get(),
        ),
        ("body_idle_timeout", forwarding.body_idle_timeout.get()),
        (
            "upgrade_idle_timeout",
            forwarding.upgrade_idle_timeout.get(),
        ),
    ] {
        if timeout > MAX_FORWARDING_TIMEOUT {
            return Err(ConfigCompileError::at(
                format!("service.forwarding.{field}"),
                "must not exceed 10 minutes",
            ));
        }
    }
    for (field, bytes) in [
        ("max_request_wire_bytes", forwarding.max_request_wire_bytes),
        (
            "max_request_decoded_bytes",
            forwarding.max_request_decoded_bytes,
        ),
        (
            "max_response_wire_bytes",
            forwarding.max_response_wire_bytes,
        ),
        (
            "max_response_decoded_bytes",
            forwarding.max_response_decoded_bytes,
        ),
        ("chunk_bytes", forwarding.chunk_bytes),
        ("max_trailer_bytes", forwarding.max_trailer_bytes),
    ] {
        check_range(
            &format!("service.forwarding.{field}"),
            bytes,
            MAX_FORWARDING_BODY_BYTES,
        )?;
    }
    check_range(
        "service.forwarding.max_trailer_count",
        forwarding.max_trailer_count,
        MAX_FORWARDING_TRAILER_COUNT,
    )?;
    let smallest_body_limit = forwarding
        .max_request_wire_bytes
        .min(forwarding.max_request_decoded_bytes)
        .min(forwarding.max_response_wire_bytes)
        .min(forwarding.max_response_decoded_bytes);
    if forwarding.chunk_bytes > smallest_body_limit {
        return Err(ConfigCompileError::at(
            "service.forwarding.chunk_bytes",
            "must not exceed any forwarding body byte limit",
        ));
    }
    for (field, maximum_source_bytes) in [
        ("max_request_wire_bytes", forwarding.max_request_wire_bytes),
        (
            "max_request_decoded_bytes",
            forwarding.max_request_decoded_bytes,
        ),
        (
            "max_response_wire_bytes",
            forwarding.max_response_wire_bytes,
        ),
        (
            "max_response_decoded_bytes",
            forwarding.max_response_decoded_bytes,
        ),
    ] {
        validate_runtime_chunk_quotient(
            &format!("service.forwarding.{field}"),
            maximum_source_bytes,
            forwarding.chunk_bytes,
        )?;
    }
    Ok(())
}

fn validate_runtime_chunk_quotient(
    path: &str,
    maximum_source_bytes: usize,
    chunk_bytes: usize,
) -> Result<(), ConfigCompileError> {
    let allocation_count = maximum_source_bytes
        .checked_add(chunk_bytes - 1)
        .ok_or_else(|| ConfigCompileError::at(path, "runtime chunk quotient overflow"))?
        / chunk_bytes;
    if allocation_count > MAX_RUNTIME_BODY_CHUNKS {
        return Err(ConfigCompileError::at(
            path,
            format!(
                "requires more than {MAX_RUNTIME_BODY_CHUNKS} runtime body chunks at the configured service.forwarding.chunk_bytes"
            ),
        ));
    }
    Ok(())
}

fn check_range(path: &str, value: usize, maximum: usize) -> Result<(), ConfigCompileError> {
    if value == 0 || value > maximum {
        return Err(ConfigCompileError::at(
            path,
            format!("must be between 1 and {maximum}"),
        ));
    }
    Ok(())
}

fn control_parser_arena_bytes(
    control: &super::authoring::ControlConfig,
) -> Result<usize, ConfigCompileError> {
    control
        .max_connections
        .checked_mul(PARSER_STORE_BYTES)
        .ok_or_else(|| ConfigCompileError::at("control", "parser-arena arithmetic overflow"))
}

#[derive(Default)]
struct ListenerFacts {
    binds: BTreeSet<SocketAddr>,
    unix_artifact_paths: BTreeSet<PathBuf>,
    uses_access_flow: bool,
    mitm_required: bool,
}

fn validate_listener_control_mitm_matrix(
    config: &super::authoring::AuthoringConfig,
) -> Result<ListenerFacts, ConfigCompileError> {
    let mut facts = ListenerFacts::default();
    let listeners = &config.listeners;
    if listeners.explicit_http.is_none()
        && listeners.transparent_http.is_none()
        && listeners.explicit_https.is_none()
        && listeners.transparent_https.is_none()
    {
        return Err(ConfigCompileError::at(
            "listeners",
            "at least one proxy listener must be configured",
        ));
    }

    if let Some(listener) = &listeners.explicit_http {
        validate_listener_endpoint(
            &listener.endpoint,
            "listeners.explicit_http",
            false,
            &mut facts,
        )?;
        validate_http_versions(
            &listener.http_versions,
            "listeners.explicit_http.http_versions",
        )?;
        validate_listener_limits(
            listener.max_connections,
            listener.max_concurrent_streams,
            "listeners.explicit_http",
        )?;
        facts.mitm_required |= validate_connect(
            &listener.http_versions,
            &listener.connect,
            "listeners.explicit_http.connect",
        )?;
    }
    if let Some(listener) = &listeners.transparent_http {
        validate_listener_endpoint(
            &listener.endpoint,
            "listeners.transparent_http",
            true,
            &mut facts,
        )?;
        validate_http_versions(
            &listener.http_versions,
            "listeners.transparent_http.http_versions",
        )?;
        validate_listener_limits(
            listener.max_connections,
            listener.max_concurrent_streams,
            "listeners.transparent_http",
        )?;
    }
    if let Some(listener) = &listeners.explicit_https {
        validate_listener_endpoint(
            &listener.endpoint,
            "listeners.explicit_https",
            false,
            &mut facts,
        )?;
        validate_http_versions(
            &listener.http_versions,
            "listeners.explicit_https.http_versions",
        )?;
        validate_listener_limits(
            listener.max_connections,
            listener.max_concurrent_streams,
            "listeners.explicit_https",
        )?;
        facts.mitm_required |= validate_connect(
            &listener.http_versions,
            &listener.connect,
            "listeners.explicit_https.connect",
        )?;
    }
    if let Some(listener) = &listeners.transparent_https {
        validate_listener_endpoint(
            &listener.endpoint,
            "listeners.transparent_https",
            true,
            &mut facts,
        )?;
        validate_http_versions(
            &listener.http_versions,
            "listeners.transparent_https.http_versions",
        )?;
        validate_listener_limits(
            listener.max_connections,
            listener.max_concurrent_streams,
            "listeners.transparent_https",
        )?;
        facts.mitm_required = true;
    }
    if facts.uses_access_flow {
        for (index, rule) in config.policy.rules.iter().enumerate() {
            if !rule.client_cidrs.is_empty() {
                return Err(ConfigCompileError::at(
                    format!("policy.rules[{index}].client_cidrs"),
                    "must be empty when an access_flow listener uses the local-workstation principal",
                ));
            }
        }
    }
    if let Some(control) = &config.control {
        let bind = validate_bind(control.bind, "control.bind", true)?;
        if facts
            .binds
            .iter()
            .any(|listener| socket_binds_overlap(*listener, bind))
        {
            return Err(ConfigCompileError::at(
                "control.bind",
                "must differ from every proxy listener bind",
            ));
        }
        if !bind.ip().is_loopback() && control.tls.is_none() {
            return Err(ConfigCompileError::at(
                "control.tls",
                "is required for a non-loopback control bind",
            ));
        }
        validate_base_path(&control.base_path)?;
        let callback_target_bytes = control
            .base_path
            .len()
            .checked_add(CALLBACK_ROUTE_SUFFIX.len())
            .ok_or_else(|| {
                ConfigCompileError::at(
                    "control.base_path",
                    "encoded callback target length overflow",
                )
            })?;
        if callback_target_bytes > MAX_ENDPOINT_BYTES {
            return Err(ConfigCompileError::at(
                "control.base_path",
                format!("encoded callback target must be at most {MAX_ENDPOINT_BYTES} bytes"),
            ));
        }
    }

    match (&config.mitm, facts.mitm_required) {
        (None, true) => {
            return Err(ConfigCompileError::at(
                "mitm",
                "is required by transparent HTTPS or an HTTP/1 CONNECT MITM policy",
            ));
        }
        (Some(_), false) => {
            return Err(ConfigCompileError::at(
                "mitm",
                "must be absent when no listener uses MITM",
            ));
        }
        _ => {}
    }
    if let Some(mitm) = &config.mitm {
        let cache = match mitm {
            MitmConfig::Generated(value) => value.max_cached_certificates,
            MitmConfig::Files(value) => value.max_cached_certificates,
        };
        check_range("mitm.max_cached_certificates", cache, MAX_MITM_CERTIFICATES)?;
    }
    Ok(facts)
}

fn validate_listener_endpoint(
    endpoint: &ListenerEndpointConfig,
    prefix: &str,
    allow_unix: bool,
    facts: &mut ListenerFacts,
) -> Result<(), ConfigCompileError> {
    match endpoint {
        ListenerEndpointConfig::Tcp { address } => {
            let path = format!("{prefix}.endpoint.address");
            let bind = validate_bind(*address, &path, false)?;
            insert_unique_bind(&mut facts.binds, bind, &path)?;
        }
        ListenerEndpointConfig::AccessFlow {
            admission_timeout: _,
            allowed_destination_ports,
            transport,
        } => {
            if !allow_unix {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.endpoint.kind"),
                    "access_flow is valid only for transparent HTTP and HTTPS listeners",
                ));
            }
            if cfg!(not(unix)) {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.endpoint.kind"),
                    "access_flow with a Unix transport is not supported on this platform",
                ));
            }
            if allowed_destination_ports.is_empty() {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.endpoint.allowed_destination_ports"),
                    "must contain at least one destination port",
                ));
            }
            let unique_ports = allowed_destination_ports
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();
            if unique_ports.contains(&0) || unique_ports.len() != allowed_destination_ports.len() {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.endpoint.allowed_destination_ports"),
                    "must contain unique nonzero destination ports",
                ));
            }
            let AccessFlowTransportConfig::Unix { path, mode } = transport;
            let path_field = format!("{prefix}.endpoint.transport.path");
            if !path.is_absolute() {
                return Err(ConfigCompileError::at(
                    path_field,
                    "must be an absolute path",
                ));
            }
            if unix_socket_path_contains_nul(path) {
                return Err(ConfigCompileError::at(
                    path_field,
                    "must not contain a NUL byte",
                ));
            }
            if unix_socket_path_bytes(path) > MAX_UNIX_SOCKET_PATH_BYTES {
                return Err(ConfigCompileError::at(
                    path_field,
                    format!("must be at most {MAX_UNIX_SOCKET_PATH_BYTES} bytes"),
                ));
            }
            parse_socket_mode(mode, &format!("{prefix}.endpoint.transport.mode"))?;
            let lock_path = unix_listener_lock_path(path);
            if !facts.unix_artifact_paths.insert(path.clone())
                || !facts.unix_artifact_paths.insert(lock_path)
            {
                return Err(ConfigCompileError::at(
                    path_field,
                    "collides with another Unix proxy listener socket or lock path",
                ));
            }
            facts.uses_access_flow = true;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn unix_socket_path_bytes(path: &Path) -> usize {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().len()
}

#[cfg(not(unix))]
fn unix_socket_path_bytes(path: &Path) -> usize {
    path.as_os_str().to_string_lossy().len()
}

#[cfg(unix)]
fn unix_socket_path_contains_nul(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().contains(&0)
}

#[cfg(not(unix))]
fn unix_socket_path_contains_nul(_path: &Path) -> bool {
    false
}

fn parse_socket_mode(value: &str, path: &str) -> Result<u32, ConfigCompileError> {
    if value.len() != 4
        || !value.starts_with('0')
        || !value.bytes().all(|byte| matches!(byte, b'0'..=b'7'))
    {
        return Err(ConfigCompileError::at(
            path,
            "must be a four-digit octal mode such as \"0600\"",
        ));
    }
    u32::from_str_radix(value, 8)
        .map_err(|_| ConfigCompileError::at(path, "contains an invalid Unix socket mode"))
}

fn validate_bind(
    bind: SocketAddr,
    path: &str,
    forbid_unspecified: bool,
) -> Result<SocketAddr, ConfigCompileError> {
    let bind = canonical_socket_addr(bind);
    if bind.port() == 0 {
        return Err(ConfigCompileError::at(path, "port 0 is not allowed"));
    }
    if forbid_unspecified && bind.ip().is_unspecified() {
        return Err(ConfigCompileError::at(
            path,
            "an unspecified control address is not allowed",
        ));
    }
    Ok(bind)
}

fn insert_unique_bind(
    binds: &mut BTreeSet<SocketAddr>,
    bind: SocketAddr,
    path: &str,
) -> Result<(), ConfigCompileError> {
    if binds
        .iter()
        .any(|existing| socket_binds_overlap(*existing, bind))
    {
        return Err(ConfigCompileError::at(
            path,
            "overlaps another proxy listener bind",
        ));
    }
    binds.insert(canonical_socket_addr(bind));
    Ok(())
}

fn validate_http_versions(versions: &[HttpVersion], path: &str) -> Result<(), ConfigCompileError> {
    if versions.is_empty() {
        return Err(ConfigCompileError::at(path, "must not be empty"));
    }
    let mut seen = BTreeSet::new();
    for version in versions {
        let key = match version {
            HttpVersion::Http1 => 1,
            HttpVersion::Http2 => 2,
        };
        if !seen.insert(key) {
            return Err(ConfigCompileError::at(
                path,
                "must not contain duplicate versions",
            ));
        }
    }
    Ok(())
}

fn validate_connect(
    versions: &[HttpVersion],
    connect: &super::authoring::ConnectConfig,
    path: &str,
) -> Result<bool, ConfigCompileError> {
    let has_http1 = versions.iter().any(|v| matches!(v, HttpVersion::Http1));
    let has_http2 = versions.iter().any(|v| matches!(v, HttpVersion::Http2));
    if has_http1 != connect.http1.is_some() {
        return Err(ConfigCompileError::at(
            format!("{path}.http1"),
            "must be present exactly when HTTP/1 is enabled",
        ));
    }
    if has_http2 != connect.http2.is_some() {
        return Err(ConfigCompileError::at(
            format!("{path}.http2"),
            "must be present exactly when HTTP/2 is enabled",
        ));
    }
    Ok(matches!(connect.http1, Some(Http1ConnectPolicy::Mitm)))
}

fn validate_listener_limits(
    connections: usize,
    streams: u32,
    prefix: &str,
) -> Result<(), ConfigCompileError> {
    check_range(
        &format!("{prefix}.max_connections"),
        connections,
        MAX_LISTENER_CONNECTIONS,
    )?;
    if streams == 0 || streams > MAX_LISTENER_STREAMS {
        return Err(ConfigCompileError::at(
            format!("{prefix}.max_concurrent_streams"),
            format!("must be between 1 and {MAX_LISTENER_STREAMS}"),
        ));
    }
    Ok(())
}

fn validate_base_path(base: &str) -> Result<(), ConfigCompileError> {
    if !base.starts_with('/')
        || base == "/"
        || base.ends_with('/')
        || base.contains("//")
        || base.contains('\\')
        || base.contains('%')
    {
        return Err(ConfigCompileError::at(
            "control.base_path",
            "must be a normalized absolute non-root path without a trailing slash",
        ));
    }
    if base.split('/').any(|segment| matches!(segment, "." | ".."))
        || !base.bytes().all(is_canonical_control_path_byte)
    {
        return Err(ConfigCompileError::at(
            "control.base_path",
            "contains an unsafe path component",
        ));
    }
    Ok(())
}

fn is_canonical_control_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'/' | b'-'
                | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

fn validate_tls_and_parent_matrix(
    config: &super::authoring::AuthoringConfig,
    listeners: &ListenerFacts,
    endpoint_urls: &CanonicalEndpointUrls,
) -> Result<(), ConfigCompileError> {
    validate_transport_tls(&config.egress.origin_tls, "egress.origin_tls")?;
    match config.egress.route {
        EgressRoute::Direct => {
            if config.egress.parent_proxy.is_some() {
                return Err(ConfigCompileError::at(
                    "egress.parent_proxy",
                    "must be absent when egress.route is direct",
                ));
            }
            if !config.safety.loop_detection.inject {
                return Err(ConfigCompileError::at(
                    "safety.loop_detection.inject",
                    "must be true for direct egress",
                ));
            }
        }
        EgressRoute::ParentProxy => {
            let parent = config.egress.parent_proxy.as_ref().ok_or_else(|| {
                ConfigCompileError::at(
                    "egress.parent_proxy",
                    "is required when egress.route is parent_proxy",
                )
            })?;
            let url = endpoint_urls.parent_proxy.as_ref().ok_or_else(|| {
                ConfigCompileError::at("egress.parent_proxy.url", "canonical parent URL is missing")
            })?;
            if url.path() != "/" || url.query().is_some() {
                return Err(ConfigCompileError::at(
                    "egress.parent_proxy.url",
                    "parent URL must not contain a path or query",
                ));
            }
            match url.scheme() {
                HttpScheme::Http if parent.tls.is_some() => {
                    return Err(ConfigCompileError::at(
                        "egress.parent_proxy.tls",
                        "must be absent for an HTTP parent URL",
                    ));
                }
                HttpScheme::Https => {
                    let tls = parent.tls.as_ref().ok_or_else(|| {
                        ConfigCompileError::at(
                            "egress.parent_proxy.tls",
                            "is required for an HTTPS parent URL",
                        )
                    })?;
                    validate_trust_matrix(
                        tls.trust,
                        tls.ca_certificate.as_deref(),
                        "egress.parent_proxy.tls",
                    )?;
                    if let Some(server_name) = &tls.server_name {
                        validate_dns_server_name(
                            server_name,
                            "egress.parent_proxy.tls.server_name",
                        )?;
                    }
                }
                HttpScheme::Http => {}
            }
            if matches!(url.scheme(), HttpScheme::Http) && parent.presentation.is_some() {
                return Err(ConfigCompileError::at(
                    "egress.parent_proxy.presentation",
                    "requires an HTTPS parent URL",
                ));
            }
            if let Some(address) = literal_url_socket_addr(url) {
                if config.control.as_ref().is_some_and(|control| {
                    socket_binds_overlap(canonical_socket_addr(control.bind), address)
                }) {
                    return Err(ConfigCompileError::at(
                        "egress.parent_proxy.url",
                        "must not target the control listener",
                    ));
                }
                if listeners
                    .binds
                    .iter()
                    .any(|listener| socket_binds_overlap(*listener, address))
                {
                    return Err(ConfigCompileError::at(
                        "egress.parent_proxy.url",
                        "must not target a proxy listener",
                    ));
                }
                if address.ip().is_loopback() {
                    return Err(ConfigCompileError::at(
                        "egress.parent_proxy.url",
                        "must not target a literal loopback address",
                    ));
                }
            }
            if config
                .control
                .as_ref()
                .is_some_and(|control| !canonical_socket_addr(control.bind).ip().is_loopback())
            {
                return Err(ConfigCompileError::at(
                    "control.bind",
                    "parent routing requires a loopback control bind",
                ));
            }
            if matches!(parent.kind, ParentProxyKind::Generic)
                && !config.safety.loop_detection.inject
            {
                return Err(ConfigCompileError::at(
                    "safety.loop_detection.inject",
                    "must be true when the parent proxy kind is generic",
                ));
            }
            if matches!(parent.kind, ParentProxyKind::Generic) && parent.presentation.is_some() {
                return Err(ConfigCompileError::at(
                    "egress.parent_proxy.presentation",
                    "is valid only for an ACL Proxy parent",
                ));
            }
            if let Some(ParentProxyPresentationConfig::BearerEnvironment { variable }) =
                &parent.presentation
            {
                if !valid_identity_environment_name(variable) {
                    return Err(ConfigCompileError::at(
                        "egress.parent_proxy.presentation.variable",
                        "must use the ACL Proxy identity-token environment namespace",
                    ));
                }
            }
        }
    }

    for (name, provider) in &config.authorization.providers {
        if let AuthorizationProviderConfig::Webhook(webhook) = provider {
            let prefix = format!("authorization.providers.{name}");
            let url = endpoint_urls.webhooks.get(name).ok_or_else(|| {
                ConfigCompileError::at(format!("{prefix}.url"), "canonical webhook URL is missing")
            })?;
            validate_endpoint_length(url, &format!("{prefix}.url"))?;
            validate_encoded_target_length(url, &format!("{prefix}.url"))?;
            match url.scheme() {
                HttpScheme::Http => {
                    if !url_host_is_loopback(url) {
                        return Err(ConfigCompileError::at(
                            format!("{prefix}.url"),
                            "plain HTTP is allowed only for a loopback webhook",
                        ));
                    }
                    if webhook.tls.is_some() {
                        return Err(ConfigCompileError::at(
                            format!("{prefix}.tls"),
                            "must be absent for an HTTP webhook",
                        ));
                    }
                }
                HttpScheme::Https => {
                    if let Some(tls) = &webhook.tls {
                        validate_trust_matrix(
                            tls.trust,
                            tls.ca_certificate.as_deref(),
                            &format!("{prefix}.tls"),
                        )?;
                    }
                }
            }
        }
    }
    validate_callback_matrix(config, endpoint_urls)?;
    Ok(())
}

fn validate_transport_tls(
    tls: &TransportTlsConfig,
    prefix: &str,
) -> Result<(), ConfigCompileError> {
    validate_trust_matrix(tls.trust, tls.ca_certificate.as_deref(), prefix)?;
    validate_http_versions(&tls.http_versions, &format!("{prefix}.http_versions"))
}

fn validate_trust_matrix(
    trust: TlsTrust,
    ca: Option<&Path>,
    prefix: &str,
) -> Result<(), ConfigCompileError> {
    let requires_ca = matches!(trust, TlsTrust::Custom | TlsTrust::SystemPlusCustom);
    if requires_ca != ca.is_some() {
        return Err(ConfigCompileError::at(
            format!("{prefix}.ca_certificate"),
            if requires_ca {
                "is required for custom trust"
            } else {
                "must be absent for system or insecure trust"
            },
        ));
    }
    Ok(())
}

fn validate_dns_server_name(value: &str, path: &str) -> Result<(), ConfigCompileError> {
    if value.is_empty()
        || value.ends_with('.')
        || value.contains('*')
        || value.contains(':')
        || value.parse::<IpAddr>().is_ok()
    {
        return Err(ConfigCompileError::at(
            path,
            "must be a non-wildcard DNS name without a port or root dot",
        ));
    }
    if !dns_name_has_safe_ascii_shape(value) {
        return Err(ConfigCompileError::at(
            path,
            "must use valid lowercase ASCII DNS labels",
        ));
    }
    Ok(())
}

fn dns_name_has_safe_ascii_shape(value: &str) -> bool {
    value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn literal_url_socket_addr(url: &CanonicalUrl) -> Option<SocketAddr> {
    let host = url.authority().host().as_str().parse::<IpAddr>().ok()?;
    Some(canonical_socket_addr(SocketAddr::new(
        host,
        url.authority().effective_port(),
    )))
}

fn url_host_is_loopback(url: &CanonicalUrl) -> bool {
    let host = url.authority().host().as_str();
    host == "localhost"
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn validate_callback_matrix(
    config: &super::authoring::AuthoringConfig,
    endpoint_urls: &CanonicalEndpointUrls,
) -> Result<(), ConfigCompileError> {
    let webhook_delegated = config.policy.rules.iter().any(|rule| {
        rule.authorization_provider.as_ref().is_some_and(|name| {
            matches!(
                config.authorization.providers.get(name),
                Some(AuthorizationProviderConfig::Webhook(_))
            )
        })
    });
    if webhook_delegated && config.control.is_none() {
        return Err(ConfigCompileError::at(
            "control",
            "is required when a rule delegates to a webhook provider",
        ));
    }
    if webhook_delegated && config.authorization.callback.is_none() {
        return Err(ConfigCompileError::at(
            "authorization.callback",
            "is required when a rule delegates to a webhook provider",
        ));
    }
    let Some(_callback) = &config.authorization.callback else {
        return Ok(());
    };
    let control = config.control.as_ref().ok_or_else(|| {
        ConfigCompileError::at("authorization.callback", "requires the control listener")
    })?;
    if control.max_request_body_bytes < MIN_CALLBACK_RESPONSE_BYTES {
        return Err(ConfigCompileError::at(
            "control.max_request_body_bytes",
            format!("must be at least {MIN_CALLBACK_RESPONSE_BYTES} when callbacks are configured"),
        ));
    }
    let expected_path = format!("{}{CALLBACK_ROUTE_SUFFIX}", control.base_path);
    let url = endpoint_urls.callback.as_ref().ok_or_else(|| {
        ConfigCompileError::at(
            "authorization.callback.public_url",
            "canonical callback URL is missing",
        )
    })?;
    validate_endpoint_length(url, "authorization.callback.public_url")?;
    if url.path() != expected_path || url.query().is_some() {
        return Err(ConfigCompileError::at(
            "authorization.callback.public_url",
            format!("path must be exactly {expected_path} with no query"),
        ));
    }
    let control_bind = canonical_socket_addr(control.bind);
    if url.scheme() == HttpScheme::Http
        && (!url_host_is_loopback(url) || !control_bind.ip().is_loopback())
    {
        return Err(ConfigCompileError::at(
            "authorization.callback.public_url",
            "plain HTTP requires both a loopback URL host and loopback control bind",
        ));
    }
    for (name, provider) in &config.authorization.providers {
        let AuthorizationProviderConfig::Webhook(_provider) = provider else {
            continue;
        };
        let provider_url = endpoint_urls.webhooks.get(name).ok_or_else(|| {
            ConfigCompileError::at(
                format!("authorization.providers.{name}.url"),
                "canonical webhook URL is missing",
            )
        })?;
        let provider_in_control_subtree = provider_url.path() == control.base_path
            || provider_url
                .path()
                .strip_prefix(&control.base_path)
                .is_some_and(|suffix| suffix.starts_with('/'));
        if provider_url.authority().host() == url.authority().host()
            && provider_url.authority().effective_port() == url.authority().effective_port()
            && provider_in_control_subtree
        {
            return Err(ConfigCompileError::at(
                format!("authorization.providers.{name}.url"),
                "must not target the callback authority's control subtree",
            ));
        }
    }
    Ok(())
}

fn validate_endpoint_length(value: &CanonicalUrl, path: &str) -> Result<(), ConfigCompileError> {
    if value.as_str().len() > MAX_ENDPOINT_BYTES {
        return Err(ConfigCompileError::at(
            path,
            format!("canonical URL must be at most {MAX_ENDPOINT_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn validate_encoded_target_length(
    url: &CanonicalUrl,
    path: &str,
) -> Result<(), ConfigCompileError> {
    let query_length = url.query().map_or(Ok(0), |query| {
        query
            .len()
            .checked_add(1)
            .ok_or_else(|| ConfigCompileError::at(path, "request-target arithmetic overflow"))
    })?;
    let length = query_length
        .checked_add(url.path().len())
        .ok_or_else(|| ConfigCompileError::at(path, "request-target arithmetic overflow"))?;
    if length > MAX_ENDPOINT_BYTES {
        return Err(ConfigCompileError::at(
            path,
            format!("encoded request target must be at most {MAX_ENDPOINT_BYTES} bytes"),
        ));
    }
    Ok(())
}

struct ValidationFacts {
    compiled_urls_by_rule: Vec<Vec<CompiledUrlPattern>>,
    capture_sink: Option<CaptureSinkSpec>,
}

fn validate_references_and_security_boundaries(
    config: &super::authoring::AuthoringConfig,
) -> Result<ValidationFacts, ConfigCompileError> {
    validate_named_maps(config)?;
    let credential_destinations = validate_credentials(config)?;
    validate_internal_context(config)?;
    validate_provider_security(config, &credential_destinations)?;
    let compiled_urls_by_rule = validate_policy(config)?;
    validate_credential_transport_security(config, &compiled_urls_by_rule)?;
    let capture_sink = validate_capture(config)?;

    Ok(ValidationFacts {
        compiled_urls_by_rule,
        capture_sink,
    })
}

fn validate_named_maps(
    config: &super::authoring::AuthoringConfig,
) -> Result<(), ConfigCompileError> {
    for (prefix, names) in [
        (
            "authorization.providers",
            config.authorization.providers.keys().collect::<Vec<_>>(),
        ),
        (
            "credentials.sources",
            config.credentials.sources.keys().collect::<Vec<_>>(),
        ),
        (
            "credentials.inbound",
            config.credentials.inbound.keys().collect::<Vec<_>>(),
        ),
        (
            "redaction.profiles",
            config.redaction.profiles.keys().collect::<Vec<_>>(),
        ),
    ] {
        for name in names {
            validate_identifier(name, &format!("{prefix}.{name}"))?;
        }
    }
    Ok(())
}

fn validate_identifier(value: &str, path: &str) -> Result<(), ConfigCompileError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ConfigCompileError::at(
            path,
            "identifier must use only ASCII letters, digits, '_', '-', or '.'",
        ));
    }
    Ok(())
}

fn validate_credentials(
    config: &super::authoring::AuthoringConfig,
) -> Result<BTreeSet<String>, ConfigCompileError> {
    let loop_header = normalize_header_name(
        &config.safety.loop_detection.header,
        "safety.loop_detection.header",
    )?;
    let mut allowed_custom = BTreeSet::new();
    for (index, name) in config.credentials.allowed_custom_headers.iter().enumerate() {
        let header = normalize_header_name(
            name,
            &format!("credentials.allowed_custom_headers[{index}]"),
        )?;
        reject_base_protected_header(&header, &loop_header, "credentials.allowed_custom_headers")?;
        if !allowed_custom.insert(header) {
            return Err(ConfigCompileError::at(
                "credentials.allowed_custom_headers",
                "must be case-insensitively duplicate-free",
            ));
        }
    }
    for (name, source) in &config.credentials.sources {
        match source {
            CredentialSourceConfig::Environment(value) => {
                if !valid_environment_name(&value.variable) {
                    return Err(ConfigCompileError::at(
                        format!("credentials.sources.{name}.variable"),
                        "must be a valid environment variable name",
                    ));
                }
                if value.variable.len() > MAX_ENVIRONMENT_CREDENTIAL_NAME_BYTES {
                    return Err(ConfigCompileError::at(
                        format!("credentials.sources.{name}.variable"),
                        "exceeds the credential source locator limit",
                    ));
                }
            }
            CredentialSourceConfig::File(value) => {
                if !value.path.is_absolute() {
                    return Err(ConfigCompileError::at(
                        format!("credentials.sources.{name}.path"),
                        "must be normalized by the config-root compiler",
                    ));
                }
                if value.path.as_os_str().as_encoded_bytes().len() > MAX_CREDENTIAL_FILE_PATH_BYTES
                {
                    return Err(ConfigCompileError::at(
                        format!("credentials.sources.{name}.path"),
                        "exceeds the credential source locator limit",
                    ));
                }
                if !value
                    .path
                    .components()
                    .any(|component| matches!(component, Component::Normal(_)))
                {
                    return Err(ConfigCompileError::at(
                        format!("credentials.sources.{name}.path"),
                        "must identify a credential file",
                    ));
                }
                if value.path.components().any(|component| {
                    matches!(component, Component::Normal(name) if name.as_encoded_bytes().len() > MAX_CREDENTIAL_FILE_COMPONENT_BYTES)
                }) {
                    return Err(ConfigCompileError::at(
                        format!("credentials.sources.{name}.path"),
                        "contains a component over the credential path component limit",
                    ));
                }
            }
        }
    }

    let mut inbound_headers = BTreeSet::new();
    for (name, inbound) in &config.credentials.inbound {
        let header = normalize_header_name(
            &inbound.header,
            &format!("credentials.inbound.{name}.header"),
        )?;
        reject_base_protected_header(&header, &loop_header, "credentials.inbound")?;
        if !inbound_headers.insert(header.clone()) {
            return Err(ConfigCompileError::at(
                format!("credentials.inbound.{name}.header"),
                "duplicates another inbound credential header",
            ));
        }
        if inbound.process_providers.is_empty() {
            return Err(ConfigCompileError::at(
                format!("credentials.inbound.{name}.process_providers"),
                "must not be empty",
            ));
        }
        let mut providers = BTreeSet::new();
        for provider_name in &inbound.process_providers {
            if !providers.insert(provider_name) {
                return Err(ConfigCompileError::at(
                    format!("credentials.inbound.{name}.process_providers"),
                    "must not contain duplicates",
                ));
            }
            let Some(AuthorizationProviderConfig::Process(provider)) =
                config.authorization.providers.get(provider_name)
            else {
                return Err(ConfigCompileError::at(
                    format!("credentials.inbound.{name}.process_providers"),
                    format!("{provider_name:?} must name a process provider"),
                ));
            };
            if !contains_header(&provider.include_headers, &header) {
                return Err(ConfigCompileError::at(
                    format!("credentials.inbound.{name}.process_providers"),
                    format!("process provider {provider_name:?} must include the inbound header"),
                ));
            }
        }
    }

    let all_credential_destinations = collect_all_credential_destinations(config, &allowed_custom)?;
    for destination in &all_credential_destinations {
        if inbound_headers.contains(destination) {
            return Err(ConfigCompileError::at(
                "credentials.inbound",
                "outbound and inbound credential destinations must be disjoint",
            ));
        }
    }
    let internal_context_headers = config
        .authorization
        .internal_context_headers
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    validate_all_literal_effects(
        config,
        &loop_header,
        &all_credential_destinations,
        &inbound_headers,
        &internal_context_headers,
    )?;
    Ok(all_credential_destinations)
}

fn collect_all_credential_destinations(
    config: &super::authoring::AuthoringConfig,
    allowed_custom: &BTreeSet<String>,
) -> Result<BTreeSet<String>, ConfigCompileError> {
    let mut all = credential_action_destinations(
        &config.egress.credential_actions,
        &config.credentials,
        "egress.credential_actions",
        allowed_custom,
    )?;
    let global = all.clone();
    for (provider_name, provider) in &config.authorization.providers {
        all.extend(provider_output_destinations(
            provider,
            allowed_custom,
            &format!("authorization.providers.{provider_name}.outputs"),
        )?);
    }
    for (index, rule) in config.policy.rules.iter().enumerate() {
        let mut local = credential_action_destinations(
            &rule.credential_actions,
            &config.credentials,
            &format!("policy.rules[{index}].credential_actions"),
            allowed_custom,
        )?;
        if let Some(provider_name) = &rule.authorization_provider {
            if let Some(provider) = config.authorization.providers.get(provider_name) {
                for destination in provider_output_destinations(
                    provider,
                    allowed_custom,
                    &format!("authorization.providers.{provider_name}.outputs"),
                )? {
                    if !local.insert(destination) {
                        return Err(ConfigCompileError::at(
                            format!("policy.rules[{index}]"),
                            "credential destinations collide between rule actions and provider outputs",
                        ));
                    }
                }
            }
        }
        if local.iter().any(|destination| global.contains(destination)) {
            return Err(ConfigCompileError::at(
                format!("policy.rules[{index}]"),
                "credential destination collides with a global egress credential action",
            ));
        }
        all.extend(local);
    }
    Ok(all)
}

fn credential_action_destinations(
    actions: &[CredentialActionConfig],
    credentials: &CredentialsConfig,
    path: &str,
    allowed_custom: &BTreeSet<String>,
) -> Result<BTreeSet<String>, ConfigCompileError> {
    if actions.len() > MAX_EFFECTS_PER_SCOPE {
        return Err(ConfigCompileError::at(
            path,
            "contains too many credential actions",
        ));
    }
    let mut destinations = BTreeSet::new();
    for (index, action) in actions.iter().enumerate() {
        let destination = match action {
            CredentialActionConfig::Bearer(value) => {
                require_credential_source(credentials, &value.credential, path)?;
                "authorization".to_string()
            }
            CredentialActionConfig::Basic(value) => {
                if value.username.is_empty() || value.username.contains(':') {
                    return Err(ConfigCompileError::at(
                        format!("{path}[{index}].username"),
                        "must be nonempty and must not contain ':'",
                    ));
                }
                require_credential_source(credentials, &value.password_credential, path)?;
                "authorization".to_string()
            }
            CredentialActionConfig::CustomHeader(value) => {
                require_credential_source(credentials, &value.credential, path)?;
                let header =
                    normalize_header_name(&value.header, &format!("{path}[{index}].header"))?;
                if !allowed_custom.contains(&header) {
                    return Err(ConfigCompileError::at(
                        format!("{path}[{index}].header"),
                        "must be declared in credentials.allowed_custom_headers",
                    ));
                }
                header
            }
        };
        if !destinations.insert(destination) {
            return Err(ConfigCompileError::at(
                path,
                "contains duplicate credential destinations",
            ));
        }
    }
    Ok(destinations)
}

fn require_credential_source(
    credentials: &CredentialsConfig,
    source: &str,
    path: &str,
) -> Result<(), ConfigCompileError> {
    if !credentials.sources.contains_key(source) {
        return Err(ConfigCompileError::at(
            path,
            format!("references unknown credential source {source:?}"),
        ));
    }
    Ok(())
}

fn provider_output_destinations(
    provider: &AuthorizationProviderConfig,
    allowed_custom: &BTreeSet<String>,
    path: &str,
) -> Result<BTreeSet<String>, ConfigCompileError> {
    let outputs = match provider {
        AuthorizationProviderConfig::Webhook(value) => &value.outputs,
        AuthorizationProviderConfig::Process(value) => &value.outputs,
        AuthorizationProviderConfig::UnixSocket(value) => &value.outputs,
    };
    if outputs.len() > MAX_PROVIDER_ITEMS {
        return Err(ConfigCompileError::at(path, "contains too many outputs"));
    }
    let mut destinations = BTreeSet::new();
    for (name, output) in outputs {
        validate_identifier(name, &format!("{path}.{name}"))?;
        if name.len() > MAX_PROVIDER_OUTPUT_NAME_BYTES {
            return Err(ConfigCompileError::at(
                format!("{path}.{name}"),
                format!(
                    "provider output name must be at most {MAX_PROVIDER_OUTPUT_NAME_BYTES} bytes"
                ),
            ));
        }
        let destination = match output {
            super::authoring::ProviderOutputConfig::Bearer(_) => "authorization".to_string(),
            super::authoring::ProviderOutputConfig::Basic(value) => {
                if value.username.is_empty() || value.username.contains(':') {
                    return Err(ConfigCompileError::at(
                        format!("{path}.{name}.username"),
                        "must be nonempty and must not contain ':'",
                    ));
                }
                "authorization".to_string()
            }
            super::authoring::ProviderOutputConfig::CustomHeader(value) => {
                let header =
                    normalize_header_name(&value.header, &format!("{path}.{name}.header"))?;
                if !allowed_custom.contains(&header) {
                    return Err(ConfigCompileError::at(
                        format!("{path}.{name}.header"),
                        "must be declared in credentials.allowed_custom_headers",
                    ));
                }
                header
            }
        };
        if !destinations.insert(destination) {
            return Err(ConfigCompileError::at(
                path,
                "contains duplicate credential destinations",
            ));
        }
    }
    Ok(destinations)
}

fn validate_internal_context(
    config: &super::authoring::AuthoringConfig,
) -> Result<(), ConfigCompileError> {
    let mut names = BTreeSet::new();
    for (index, name) in config
        .authorization
        .internal_context_headers
        .iter()
        .enumerate()
    {
        let name = normalize_header_name(
            name,
            &format!("authorization.internal_context_headers[{index}]"),
        )?;
        if !names.insert(name.clone()) {
            return Err(ConfigCompileError::at(
                "authorization.internal_context_headers",
                "must be case-insensitively duplicate-free",
            ));
        }
        let matching: Vec<_> = config
            .egress
            .request_headers
            .iter()
            .filter(|effect| {
                effect_header_name(effect)
                    .is_some_and(|candidate| candidate.eq_ignore_ascii_case(&name))
            })
            .collect();
        if matching.len() != 1 {
            return Err(ConfigCompileError::at(
                "authorization.internal_context_headers",
                format!("{name:?} requires exactly one global egress literal action"),
            ));
        }
        match matching[0] {
            HeaderEffectConfig::Set(value) if matches!(value.when, HeaderEffectWhen::Always) => {}
            HeaderEffectConfig::Remove(value) if matches!(value.when, HeaderEffectWhen::Always) => {
            }
            _ => {
                return Err(ConfigCompileError::at(
                    "authorization.internal_context_headers",
                    format!("{name:?} requires an unconditional set or remove action"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_provider_security(
    config: &super::authoring::AuthoringConfig,
    credential_destinations: &BTreeSet<String>,
) -> Result<(), ConfigCompileError> {
    let loop_header = normalize_header_name(
        &config.safety.loop_detection.header,
        "safety.loop_detection.header",
    )?;
    let inbound: BTreeMap<String, BTreeSet<String>> = config
        .credentials
        .inbound
        .values()
        .map(|value| {
            (
                value.header.to_ascii_lowercase(),
                value.process_providers.iter().cloned().collect(),
            )
        })
        .collect();
    let contexts: BTreeSet<_> = config
        .authorization
        .internal_context_headers
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();

    for (name, provider) in &config.authorization.providers {
        let (headers, is_process) = match provider {
            AuthorizationProviderConfig::Webhook(value) => (&value.include_headers, false),
            AuthorizationProviderConfig::Process(value) => (&value.include_headers, true),
            AuthorizationProviderConfig::UnixSocket(value) => (&value.include_headers, false),
        };
        if headers.len() > MAX_PROVIDER_ITEMS {
            return Err(ConfigCompileError::at(
                format!("authorization.providers.{name}.include_headers"),
                "contains too many headers",
            ));
        }
        let mut seen = BTreeSet::new();
        for (index, header) in headers.iter().enumerate() {
            let path = format!("authorization.providers.{name}.include_headers[{index}]");
            let header = normalize_header_name(header, &path)?;
            if !seen.insert(header.clone()) {
                return Err(ConfigCompileError::at(path, "duplicates an earlier header"));
            }
            if base_protected_headers().contains(header.as_str()) || header == loop_header {
                return Err(ConfigCompileError::at(
                    path,
                    "provider may not receive a protected header",
                ));
            }
            if credential_destinations.contains(&header) {
                return Err(ConfigCompileError::at(
                    path,
                    "provider may not receive an outbound credential destination",
                ));
            }
            if let Some(providers) = inbound.get(&header) {
                if !is_process || !providers.contains(name) {
                    return Err(ConfigCompileError::at(
                        path,
                        "inbound credential header is not authorized for this provider",
                    ));
                }
            }
            if contexts.contains(&header) && (!is_process || !context_is_consuming(config, &header))
            {
                return Err(ConfigCompileError::at(
                    path,
                    "internal context headers may be sent only to a consuming process provider",
                ));
            }
        }
    }
    Ok(())
}

fn context_is_consuming(config: &super::authoring::AuthoringConfig, header: &str) -> bool {
    config.egress.request_headers.iter().any(|effect| {
        matches!(effect, HeaderEffectConfig::Remove(value)
            if value.name.eq_ignore_ascii_case(header)
                && matches!(value.when, HeaderEffectWhen::Always))
    })
}

fn validate_policy(
    config: &super::authoring::AuthoringConfig,
) -> Result<Vec<Vec<CompiledUrlPattern>>, ConfigCompileError> {
    if config.policy.rules.len() > MAX_POLICY_RULES {
        return Err(ConfigCompileError::at(
            "policy.rules",
            "contains too many rules",
        ));
    }
    let contexts: BTreeSet<_> = config
        .authorization
        .internal_context_headers
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    let inbound: BTreeSet<_> = config
        .credentials
        .inbound
        .values()
        .map(|value| value.header.to_ascii_lowercase())
        .collect();
    let mut ids = BTreeSet::new();
    let mut compiled_urls_by_rule = Vec::with_capacity(config.policy.rules.len());
    for (index, rule) in config.policy.rules.iter().enumerate() {
        let prefix = format!("policy.rules[{index}]");
        if rule.id.trim().is_empty() || !ids.insert(rule.id.clone()) {
            return Err(ConfigCompileError::at(
                format!("{prefix}.id"),
                "must be nonempty and unique",
            ));
        }
        if rule.id.len() > MAX_PROVIDER_RULE_ID_BYTES {
            return Err(ConfigCompileError::at(
                format!("{prefix}.id"),
                format!(
                    "must be at most {MAX_PROVIDER_RULE_ID_BYTES} bytes for authorization-provider dispatch"
                ),
            ));
        }
        let predicate_count = rule.urls.len()
            + rule.methods.len()
            + rule.client_cidrs.len()
            + rule.identity_states.as_ref().map_or(0, Vec::len)
            + rule.identity_subjects.as_ref().map_or(0, Vec::len)
            + rule.headers.absent_any.len()
            + rule.headers.present_all.len()
            + rule.headers.all.len()
            + rule.headers.none.len();
        if predicate_count == 0 {
            return Err(ConfigCompileError::at(
                &prefix,
                "must define at least one request predicate",
            ));
        }
        if rule.urls.len() > MAX_URLS_PER_RULE {
            return Err(ConfigCompileError::at(
                format!("{prefix}.urls"),
                "contains too many URL patterns",
            ));
        }
        let patterns = rule
            .urls
            .iter()
            .enumerate()
            .map(|(pattern_index, pattern)| {
                let path = format!("{prefix}.urls[{pattern_index}]");
                let compiled = CompiledUrlPattern::compile(pattern)
                    .map_err(|error| ConfigCompileError::at(&path, error.to_string()))?;
                if compiled
                    .path_pattern()
                    .is_some_and(|path_pattern| path_pattern.contains("//"))
                {
                    return Err(ConfigCompileError::at(
                        path,
                        "path must not contain an empty segment",
                    ));
                }
                Ok(compiled)
            })
            .collect::<Result<Vec<_>, _>>()?;
        compiled_urls_by_rule.push(patterns);
        validate_methods(&rule.methods, &format!("{prefix}.methods"))?;
        validate_header_predicates(rule, &prefix, &contexts, &inbound)?;

        match rule.decision {
            RuleDecision::Delegate => {
                let provider = rule.authorization_provider.as_ref().ok_or_else(|| {
                    ConfigCompileError::at(
                        format!("{prefix}.authorization_provider"),
                        "is required for a delegate rule",
                    )
                })?;
                if !config.authorization.providers.contains_key(provider) {
                    return Err(ConfigCompileError::at(
                        format!("{prefix}.authorization_provider"),
                        format!("references unknown provider {provider:?}"),
                    ));
                }
            }
            RuleDecision::Allow | RuleDecision::Deny => {
                if rule.authorization_provider.is_some() {
                    return Err(ConfigCompileError::at(
                        format!("{prefix}.authorization_provider"),
                        "is valid only for a delegate rule",
                    ));
                }
            }
        }
        if let Some(profile) = &rule.redaction_profile {
            if matches!(rule.decision, RuleDecision::Deny) {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.redaction_profile"),
                    "is forbidden on a deny rule",
                ));
            }
            if !config.redaction.profiles.contains_key(profile) {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.redaction_profile"),
                    format!("references unknown profile {profile:?}"),
                ));
            }
        }
        if matches!(rule.decision, RuleDecision::Deny)
            && (!rule.request_headers.is_empty()
                || !rule.response_headers.is_empty()
                || !rule.credential_actions.is_empty())
        {
            return Err(ConfigCompileError::at(
                &prefix,
                "deny rules cannot contain forwarding effects",
            ));
        }
        if rule.request_headers.len() > MAX_EFFECTS_PER_SCOPE
            || rule.response_headers.len() > MAX_EFFECTS_PER_SCOPE
            || rule.credential_actions.len() > MAX_EFFECTS_PER_SCOPE
        {
            return Err(ConfigCompileError::at(&prefix, "contains too many effects"));
        }
    }
    Ok(compiled_urls_by_rule)
}

fn validate_credential_transport_security(
    config: &super::authoring::AuthoringConfig,
    compiled_urls_by_rule: &[Vec<CompiledUrlPattern>],
) -> Result<(), ConfigCompileError> {
    if matches!(
        config.policy.default,
        super::authoring::PolicyDefaultDecision::Allow
    ) {
        require_cleartext_credential_actions(
            &config.egress.credential_actions,
            "egress.credential_actions",
        )?;
    }

    for (index, (rule, patterns)) in config
        .policy
        .rules
        .iter()
        .zip(compiled_urls_by_rule)
        .enumerate()
    {
        if matches!(rule.decision, RuleDecision::Deny) || !policy_rule_can_reach_http(patterns) {
            continue;
        }

        require_cleartext_credential_actions(
            &config.egress.credential_actions,
            "egress.credential_actions",
        )?;
        require_cleartext_credential_actions(
            &rule.credential_actions,
            &format!("policy.rules[{index}].credential_actions"),
        )?;

        let Some(provider_name) = &rule.authorization_provider else {
            continue;
        };
        let provider = config
            .authorization
            .providers
            .get(provider_name)
            .expect("policy provider reference was validated before transport security");
        let outputs = match provider {
            AuthorizationProviderConfig::Webhook(provider) => &provider.outputs,
            AuthorizationProviderConfig::Process(provider) => &provider.outputs,
            AuthorizationProviderConfig::UnixSocket(provider) => &provider.outputs,
        };
        for (name, output) in outputs {
            let transport_security = match output {
                super::authoring::ProviderOutputConfig::Bearer(output) => output.transport_security,
                super::authoring::ProviderOutputConfig::Basic(output) => output.transport_security,
                super::authoring::ProviderOutputConfig::CustomHeader(output) => {
                    output.transport_security
                }
            };
            require_cleartext_transport_security(
                transport_security,
                &format!(
                    "authorization.providers.{provider_name}.outputs.{name}.transport_security"
                ),
            )?;
        }
    }
    Ok(())
}

fn policy_rule_can_reach_http(patterns: &[CompiledUrlPattern]) -> bool {
    patterns.is_empty()
        || patterns
            .iter()
            .any(|pattern| pattern.scheme() != Some(HttpScheme::Https))
}

fn require_cleartext_credential_actions(
    actions: &[CredentialActionConfig],
    path: &str,
) -> Result<(), ConfigCompileError> {
    for (index, action) in actions.iter().enumerate() {
        let transport_security = match action {
            CredentialActionConfig::Bearer(action) => action.transport_security,
            CredentialActionConfig::Basic(action) => action.transport_security,
            CredentialActionConfig::CustomHeader(action) => action.transport_security,
        };
        require_cleartext_transport_security(
            transport_security,
            &format!("{path}[{index}].transport_security"),
        )?;
    }
    Ok(())
}

fn require_cleartext_transport_security(
    transport_security: TransportSecurity,
    path: &str,
) -> Result<(), ConfigCompileError> {
    if matches!(transport_security, TransportSecurity::TlsRequired) {
        return Err(ConfigCompileError::at(
            path,
            "must be cleartext_allowed because this credential can reach an HTTP origin",
        ));
    }
    Ok(())
}

fn validate_methods(methods: &[String], path: &str) -> Result<(), ConfigCompileError> {
    let mut seen = BTreeSet::new();
    for method in methods {
        if method.is_empty() || !method.bytes().all(is_http_token_byte) {
            return Err(ConfigCompileError::at(
                path,
                "contains an invalid HTTP token",
            ));
        }
        if !seen.insert(method.to_ascii_uppercase()) {
            return Err(ConfigCompileError::at(
                path,
                "contains duplicate methods after normalization",
            ));
        }
    }
    Ok(())
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn validate_header_predicates(
    rule: &PolicyRuleConfig,
    prefix: &str,
    contexts: &BTreeSet<String>,
    inbound: &BTreeSet<String>,
) -> Result<(), ConfigCompileError> {
    let count = rule.headers.absent_any.len()
        + rule.headers.present_all.len()
        + rule.headers.all.values().map(Vec::len).sum::<usize>()
        + rule.headers.none.values().map(Vec::len).sum::<usize>();
    if count > MAX_HEADER_PREDICATES_PER_RULE {
        return Err(ConfigCompileError::at(
            format!("{prefix}.headers"),
            "contains too many names",
        ));
    }
    let mut all_names = BTreeSet::new();
    for (kind, names) in [
        ("absent_any", &rule.headers.absent_any),
        ("present_all", &rule.headers.present_all),
    ] {
        for name in names {
            let header = normalize_header_name(name, &format!("{prefix}.headers.{kind}"))?;
            if contexts.contains(&header) {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.headers.{kind}"),
                    "internal context headers cannot be policy predicates",
                ));
            }
            if !all_names.insert(header) {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.headers"),
                    "predicate names must be unique across predicate kinds",
                ));
            }
        }
    }
    for (kind, values) in [("all", &rule.headers.all), ("none", &rule.headers.none)] {
        for (name, expected) in values {
            let header = normalize_header_name(name, &format!("{prefix}.headers.{kind}"))?;
            if contexts.contains(&header)
                || inbound.contains(&header)
                || base_sensitive_value_headers().contains(header.as_str())
            {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.headers.{kind}"),
                    "protected or credential-bearing headers cannot be value predicates",
                ));
            }
            if expected.is_empty() {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.headers.{kind}.{name}"),
                    "must contain at least one value",
                ));
            }
            for value in expected {
                HeaderValue::from_str(value).map_err(|error| {
                    ConfigCompileError::at(
                        format!("{prefix}.headers.{kind}.{name}"),
                        format!("contains an invalid header value: {error}"),
                    )
                })?;
            }
            if !all_names.insert(header) {
                return Err(ConfigCompileError::at(
                    format!("{prefix}.headers"),
                    "predicate names must be unique across predicate kinds",
                ));
            }
        }
    }
    Ok(())
}

fn validate_all_literal_effects(
    config: &super::authoring::AuthoringConfig,
    loop_header: &str,
    credential_destinations: &BTreeSet<String>,
    inbound_headers: &BTreeSet<String>,
    internal_context_headers: &BTreeSet<String>,
) -> Result<(), ConfigCompileError> {
    validate_literal_effects(
        &config.egress.request_headers,
        "egress.request_headers",
        loop_header,
        credential_destinations,
        inbound_headers,
        internal_context_headers,
        true,
    )?;
    for (index, rule) in config.policy.rules.iter().enumerate() {
        validate_literal_effects(
            &rule.request_headers,
            &format!("policy.rules[{index}].request_headers"),
            loop_header,
            credential_destinations,
            inbound_headers,
            internal_context_headers,
            false,
        )?;
        validate_literal_effects(
            &rule.response_headers,
            &format!("policy.rules[{index}].response_headers"),
            loop_header,
            credential_destinations,
            inbound_headers,
            internal_context_headers,
            false,
        )?;
    }
    Ok(())
}

fn validate_literal_effects(
    effects: &[HeaderEffectConfig],
    path: &str,
    loop_header: &str,
    credential_destinations: &BTreeSet<String>,
    inbound_headers: &BTreeSet<String>,
    internal_context_headers: &BTreeSet<String>,
    allow_internal_context_headers: bool,
) -> Result<(), ConfigCompileError> {
    if effects.len() > MAX_EFFECTS_PER_SCOPE {
        return Err(ConfigCompileError::at(path, "contains too many effects"));
    }
    for (index, effect) in effects.iter().enumerate() {
        let name = effect_header_name(effect).expect("every effect has a header name");
        let name = normalize_header_name(&name, &format!("{path}[{index}].name"))?;
        if base_protected_headers().contains(name.as_str())
            || name == loop_header
            || credential_destinations.contains(&name)
            || inbound_headers.contains(&name)
            || (!allow_internal_context_headers && internal_context_headers.contains(&name))
        {
            return Err(ConfigCompileError::at(
                format!("{path}[{index}].name"),
                "literal effects cannot target a protected or credential destination header",
            ));
        }
        match effect {
            HeaderEffectConfig::Set(value) | HeaderEffectConfig::Append(value) => {
                let values = match (&value.value, &value.values) {
                    (Some(value), None) => vec![value],
                    (None, Some(values)) if !values.is_empty() => values.iter().collect(),
                    _ => {
                        return Err(ConfigCompileError::at(
                            format!("{path}[{index}]"),
                            "must define exactly one of value or nonempty values",
                        ));
                    }
                };
                for value in values {
                    if value.len() > MAX_HEADER_FIELD_BYTES {
                        return Err(ConfigCompileError::at(
                            format!("{path}[{index}]"),
                            "header value exceeds the 64 KiB field limit",
                        ));
                    }
                    if value.contains("${") {
                        return Err(ConfigCompileError::at(
                            format!("{path}[{index}]"),
                            "generic environment interpolation is not valid in this schema",
                        ));
                    }
                    HeaderValue::from_str(value).map_err(|error| {
                        ConfigCompileError::at(
                            format!("{path}[{index}]"),
                            format!("contains an invalid header value: {error}"),
                        )
                    })?;
                }
            }
            HeaderEffectConfig::Remove(_) => {}
            HeaderEffectConfig::Replace(value) => {
                if value.search.len() > MAX_HEADER_FIELD_BYTES
                    || value.replace.len() > MAX_HEADER_FIELD_BYTES
                {
                    return Err(ConfigCompileError::at(
                        format!("{path}[{index}]"),
                        "header search or replacement text exceeds the 64 KiB field limit",
                    ));
                }
                if value.search.is_empty() {
                    return Err(ConfigCompileError::at(
                        format!("{path}[{index}].search"),
                        "must not be empty",
                    ));
                }
                if HeaderValue::from_str(&value.search).is_err()
                    || HeaderValue::from_str(&value.replace).is_err()
                {
                    return Err(ConfigCompileError::at(
                        format!("{path}[{index}]"),
                        "replacement text must contain only valid HTTP header-value bytes",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn effect_header_name(effect: &HeaderEffectConfig) -> Option<String> {
    Some(match effect {
        HeaderEffectConfig::Set(value) | HeaderEffectConfig::Append(value) => value.name.clone(),
        HeaderEffectConfig::Remove(value) => value.name.clone(),
        HeaderEffectConfig::Replace(value) => value.name.clone(),
    })
}

fn validate_capture(
    config: &super::authoring::AuthoringConfig,
) -> Result<Option<CaptureSinkSpec>, ConfigCompileError> {
    let Some(capture) = &config.observation.capture else {
        return Ok(None);
    };
    if capture.events.is_empty() {
        return Err(ConfigCompileError::at(
            "observation.capture.events",
            "must not be empty",
        ));
    }
    let mut events = BTreeSet::new();
    for event in &capture.events {
        let key = match event {
            super::authoring::CaptureEvent::RequestAllowed => 1,
            super::authoring::CaptureEvent::ResponseAllowed => 2,
            super::authoring::CaptureEvent::RequestDenied => 3,
            super::authoring::CaptureEvent::ResponseDenied => 4,
        };
        if !events.insert(key) {
            return Err(ConfigCompileError::at(
                "observation.capture.events",
                "must not contain duplicates",
            ));
        }
    }
    if !config
        .redaction
        .profiles
        .contains_key(&capture.redaction_profile)
    {
        return Err(ConfigCompileError::at(
            "observation.capture.redaction_profile",
            "must name an existing redaction profile",
        ));
    }
    CaptureSinkSpec::new(
        capture.directory.clone(),
        capture.filename.clone(),
        capture.max_files,
        capture.max_total_bytes,
    )
    .map(Some)
    .map_err(map_capture_sink_error)
}

fn map_capture_sink_error(error: CaptureSinkSpecError) -> ConfigCompileError {
    let path = match &error {
        CaptureSinkSpecError::EmptyDirectory => "observation.capture.directory",
        CaptureSinkSpecError::InvalidFilenameBasename
        | CaptureSinkSpecError::MissingRequestIdPlaceholder
        | CaptureSinkSpecError::MissingSuffixPlaceholder
        | CaptureSinkSpecError::UnknownFilenamePlaceholder => "observation.capture.filename",
        CaptureSinkSpecError::ZeroMaxFiles => "observation.capture.max_files",
        CaptureSinkSpecError::ZeroMaxTotalBytes => "observation.capture.max_total_bytes",
    };
    ConfigCompileError::at(path, error.to_string())
}

fn validate_provider_limits(
    config: &super::authoring::AuthoringConfig,
) -> Result<(), ConfigCompileError> {
    for (name, provider) in &config.authorization.providers {
        match provider {
            AuthorizationProviderConfig::Webhook(value) => {
                check_range(
                    &format!("authorization.providers.{name}.max_request_bytes"),
                    value.max_request_bytes,
                    MAX_WEBHOOK_BODY_BYTES,
                )?;
                check_range(
                    &format!("authorization.providers.{name}.max_response_bytes"),
                    value.max_response_bytes,
                    MAX_WEBHOOK_BODY_BYTES,
                )?;
                if value.max_response_bytes < MIN_CALLBACK_RESPONSE_BYTES {
                    return Err(ConfigCompileError::at(
                        format!("authorization.providers.{name}.max_response_bytes"),
                        format!(
                            "must be at least {MIN_CALLBACK_RESPONSE_BYTES} bytes to fit a callback response"
                        ),
                    ));
                }
                if let Some(callback) = &config.authorization.callback {
                    let identity_member_bytes = if value.include_identity {
                        maximum_provider_identity_member_bytes(config)?
                    } else {
                        0
                    };
                    let minimum =
                        minimum_webhook_request_bytes(&callback.public_url, identity_member_bytes)?;
                    if value.max_request_bytes < minimum {
                        return Err(ConfigCompileError::at(
                            format!("authorization.providers.{name}.max_request_bytes"),
                            format!(
                                "must be at least {minimum} bytes to fit the provider's minimum compact request envelope"
                            ),
                        ));
                    }
                }
            }
            AuthorizationProviderConfig::Process(value) => {
                check_range(
                    &format!("authorization.providers.{name}.max_request_body_bytes"),
                    value.max_request_body_bytes,
                    MAX_PROCESS_BODY_BYTES,
                )?;
                check_range(
                    &format!("authorization.providers.{name}.max_decoded_request_body_bytes"),
                    value.max_decoded_request_body_bytes,
                    MAX_PROCESS_BODY_BYTES,
                )?;
                check_range(
                    &format!("authorization.providers.{name}.max_stdout_line_bytes"),
                    value.max_stdout_line_bytes,
                    MAX_PROCESS_STDOUT_LINE_BYTES,
                )?;
                if value.max_stdout_line_bytes < PROCESS_PROVIDER_MIN_DECISION_RESPONSE_BYTES {
                    return Err(ConfigCompileError::at(
                        format!("authorization.providers.{name}.max_stdout_line_bytes"),
                        format!(
                            "must be at least {PROCESS_PROVIDER_MIN_DECISION_RESPONSE_BYTES} bytes to fit a process-provider decision response"
                        ),
                    ));
                }
                check_range(
                    &format!("authorization.providers.{name}.max_pending_requests"),
                    value.max_pending_requests,
                    MAX_PROCESS_PENDING_REQUESTS,
                )?;
                if value.max_decoded_request_body_bytes < value.max_request_body_bytes {
                    return Err(ConfigCompileError::at(
                        format!("authorization.providers.{name}"),
                        "decoded request-body limit must be at least the encoded limit",
                    ));
                }
                if value.allow_request_body_replacement && !value.include_request_body {
                    return Err(ConfigCompileError::at(
                        format!("authorization.providers.{name}.allow_request_body_replacement"),
                        "requires include_request_body = true",
                    ));
                }
                validate_process_environment(name, value)?;
                validate_ratio_pair(
                    value.max_request_body_bytes,
                    value.max_decoded_request_body_bytes,
                    config.service.max_content_decoding_expansion_ratio,
                    &format!("authorization.providers.{name}"),
                )?;
                let greatest_request_timeout = config
                    .policy
                    .rules
                    .iter()
                    .filter(|rule| rule.authorization_provider.as_deref() == Some(name))
                    .map(|rule| {
                        rule.request_timeout
                            .as_ref()
                            .map_or(config.service.request_timeout.get(), |timeout| {
                                timeout.get()
                            })
                    })
                    .max();
                if greatest_request_timeout
                    .is_some_and(|timeout| value.retire_timeout.get() < timeout)
                {
                    return Err(ConfigCompileError::at(
                        format!("authorization.providers.{name}.retire_timeout"),
                        "must cover the greatest effective request timeout of every referencing rule",
                    ));
                }
            }
            AuthorizationProviderConfig::UnixSocket(value) => {
                compile_unix_provider_projection(name, value)?;
                let identity_member_bytes = if value.include_identity {
                    maximum_provider_identity_member_bytes(config)?
                } else {
                    0
                };
                let minimum = MIN_UNIX_PROVIDER_REQUEST_BYTES
                    .checked_add(identity_member_bytes)
                    .ok_or_else(|| {
                        ConfigCompileError::at(
                            format!("authorization.providers.{name}.max_request_bytes"),
                            "minimum AWAP request-envelope arithmetic overflow",
                        )
                    })?;
                if value.max_request_bytes < minimum {
                    return Err(ConfigCompileError::at(
                        format!("authorization.providers.{name}.max_request_bytes"),
                        format!(
                            "must be at least {minimum} bytes to fit the provider's minimum AWAP request envelope and complete identity projection"
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct UnixProviderProjection {
    frame_protocol: FrameProtocol,
    request_frame_bytes: usize,
    response_frame_bytes: usize,
    request_allocation_bytes: usize,
    response_allocation_bytes: usize,
    per_request_allocation_bytes: usize,
    max_inflight_allocation_bytes: usize,
}

fn compile_unix_provider_projection(
    name: &str,
    value: &super::authoring::UnixSocketProviderConfig,
) -> Result<UnixProviderProjection, ConfigCompileError> {
    let prefix = format!("authorization.providers.{name}");
    validate_unix_provider_socket_path(&value.socket_path, &format!("{prefix}.socket_path"))?;
    if value.timeout.get() > MAX_UNIX_PROVIDER_TIMEOUT {
        return Err(ConfigCompileError::at(
            format!("{prefix}.timeout"),
            "must not exceed 10 minutes",
        ));
    }
    if value.max_request_bytes < MIN_UNIX_PROVIDER_REQUEST_BYTES {
        return Err(ConfigCompileError::at(
            format!("{prefix}.max_request_bytes"),
            format!(
                "must be at least {MIN_UNIX_PROVIDER_REQUEST_BYTES} bytes to hold the minimum AWAP request"
            ),
        ));
    }
    if value.max_response_bytes < MIN_UNIX_PROVIDER_RESPONSE_BYTES {
        return Err(ConfigCompileError::at(
            format!("{prefix}.max_response_bytes"),
            format!(
                "must be at least {MIN_UNIX_PROVIDER_RESPONSE_BYTES} bytes to hold the minimum AWAP response"
            ),
        ));
    }
    check_range(
        &format!("{prefix}.max_request_bytes"),
        value.max_request_bytes,
        MAX_UNIX_PROVIDER_BODY_BYTES,
    )?;
    check_range(
        &format!("{prefix}.max_response_bytes"),
        value.max_response_bytes,
        MAX_UNIX_PROVIDER_BODY_BYTES,
    )?;
    check_range(
        &format!("{prefix}.max_pending_requests"),
        value.max_pending_requests,
        MAX_UNIX_PROVIDER_PENDING_REQUESTS,
    )?;

    let request_limit = FrameBodyLimit::new(value.max_request_bytes).map_err(|_| {
        ConfigCompileError::at(
            format!("{prefix}.max_request_bytes"),
            "must be a positive AWAP frame body limit",
        )
    })?;
    let response_limit = FrameBodyLimit::new(value.max_response_bytes).map_err(|_| {
        ConfigCompileError::at(
            format!("{prefix}.max_response_bytes"),
            "must be a positive AWAP frame body limit",
        )
    })?;
    let frame_protocol = FrameProtocol::new(
        UNIX_PROVIDER_MAGIC,
        UNIX_PROVIDER_WIRE_VERSION,
        request_limit,
        response_limit,
    );
    let request_frame_bytes = frame_protocol
        .projected_frame_bytes(FrameKind::Request)
        .map_err(|_| {
            ConfigCompileError::at(
                format!("{prefix}.max_request_bytes"),
                "AWAP request-frame projection overflow",
            )
        })?;
    let response_frame_bytes = frame_protocol
        .projected_frame_bytes(FrameKind::Response)
        .map_err(|_| {
            ConfigCompileError::at(
                format!("{prefix}.max_response_bytes"),
                "AWAP response-frame projection overflow",
            )
        })?;
    let request_allocation_bytes = project_guarded_body_allocation(
        value.max_request_bytes,
        &format!("{prefix}.max_request_bytes"),
        "AWAP request allocation projection overflow",
    )?;
    let response_allocation_bytes = project_guarded_body_allocation(
        value.max_response_bytes,
        &format!("{prefix}.max_response_bytes"),
        "AWAP response allocation projection overflow",
    )?;
    let credential_allocation_bytes = if value.outputs.is_empty() {
        0
    } else {
        compact_provider_credential_allocation(value.outputs.len(), value.max_response_bytes)?
    };
    let per_request_allocation_bytes = request_allocation_bytes
        .checked_add(response_allocation_bytes)
        .and_then(|bytes| bytes.checked_add(credential_allocation_bytes))
        .ok_or_else(|| {
            ConfigCompileError::at(&prefix, "AWAP per-request allocation projection overflow")
        })?;
    let max_inflight_allocation_bytes = per_request_allocation_bytes
        .checked_mul(value.max_pending_requests)
        .ok_or_else(|| {
            ConfigCompileError::at(
                format!("{prefix}.max_pending_requests"),
                "AWAP in-flight allocation projection overflow",
            )
        })?;

    Ok(UnixProviderProjection {
        frame_protocol,
        request_frame_bytes,
        response_frame_bytes,
        request_allocation_bytes,
        response_allocation_bytes,
        per_request_allocation_bytes,
        max_inflight_allocation_bytes,
    })
}

fn validate_unix_provider_socket_path(path: &Path, field: &str) -> Result<(), ConfigCompileError> {
    if !path.is_absolute() {
        return Err(ConfigCompileError::at(field, "must be an absolute path"));
    }
    let normalized = lexical_normalize_absolute(path)
        .ok_or_else(|| ConfigCompileError::at(field, "absolute path could not be normalized"))?;
    if normalized.as_os_str() != path.as_os_str() || path == Path::new("/") {
        return Err(ConfigCompileError::at(
            field,
            "must be a normalized absolute path to a socket leaf",
        ));
    }
    if unix_socket_path_contains_nul(path) {
        return Err(ConfigCompileError::at(field, "must not contain a NUL byte"));
    }
    if unix_socket_path_bytes(path) > MAX_UNIX_SOCKET_PATH_BYTES {
        return Err(ConfigCompileError::at(
            field,
            format!("must be at most {MAX_UNIX_SOCKET_PATH_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn minimum_webhook_request_bytes(
    callback_url: &str,
    identity_member_bytes: usize,
) -> Result<usize, ConfigCompileError> {
    MIN_WEBHOOK_REQUEST_WITHOUT_CALLBACK_URL_BYTES
        .checked_add(callback_url.len())
        .and_then(|value| value.checked_add(identity_member_bytes))
        .ok_or_else(|| {
            ConfigCompileError::at(
                "authorization.callback.public_url",
                "minimum webhook request-envelope arithmetic overflow",
            )
        })
}

fn maximum_provider_identity_member_bytes(
    config: &super::authoring::AuthoringConfig,
) -> Result<usize, ConfigCompileError> {
    const DISABLED: &[u8] = br#"{"identity":{"state":"disabled"}}"#;
    const ANONYMOUS: &[u8] = br#"{"identity":{"state":"anonymous"}}"#;

    let complete_object_bytes = match compile_identity_plan(config.identity.as_ref())? {
        Some(identity) => usize::try_from(identity.resources.max_provider_projection_bytes)
            .map_err(|_| {
                ConfigCompileError::at(
                    "identity.resolver",
                    "provider identity projection cannot be represented",
                )
            })?,
        None => DISABLED.len().max(ANONYMOUS.len()),
    };
    complete_object_bytes.checked_sub(1).ok_or_else(|| {
        ConfigCompileError::at(
            "identity",
            "provider identity projection is missing its outer object",
        )
    })
}

fn validate_process_environment(
    name: &str,
    value: &super::authoring::ProcessProviderConfig,
) -> Result<(), ConfigCompileError> {
    let mut names = BTreeSet::new();
    for environment_name in &value.pass_environment {
        if !valid_environment_name(environment_name) || !names.insert(environment_name) {
            return Err(ConfigCompileError::at(
                format!("authorization.providers.{name}.pass_environment"),
                "must contain unique valid environment variable names",
            ));
        }
    }
    for environment_name in value.environment.keys() {
        if !valid_environment_name(environment_name) {
            return Err(ConfigCompileError::at(
                format!("authorization.providers.{name}.environment"),
                "contains an invalid environment variable name",
            ));
        }
        if names.contains(environment_name) {
            return Err(ConfigCompileError::at(
                format!("authorization.providers.{name}.environment"),
                "must not overlap pass_environment",
            ));
        }
    }
    Ok(())
}

fn validate_redaction_limits(
    config: &super::authoring::AuthoringConfig,
) -> Result<(), ConfigCompileError> {
    if config.redaction.profiles.len() > MAX_REDACTION_PROFILES {
        return Err(ConfigCompileError::at(
            "redaction.profiles",
            "contains too many profiles",
        ));
    }
    let mut snapshot_source_count = 0usize;
    let mut snapshot_source_byte_budget = 0usize;
    for (name, profile) in &config.redaction.profiles {
        let prefix = format!("redaction.profiles.{name}");
        check_range(
            &format!("{prefix}.max_body_bytes"),
            profile.max_body_bytes,
            MAX_REDACTION_BODY_BYTES,
        )?;
        check_range(
            &format!("{prefix}.max_decoded_body_bytes"),
            profile.max_decoded_body_bytes,
            MAX_REDACTION_BODY_BYTES,
        )?;
        check_range(
            &format!("{prefix}.max_frame_bytes"),
            profile.max_frame_bytes,
            MAX_REDACTION_FRAME_BYTES,
        )?;
        check_range(
            &format!("{prefix}.max_message_bytes"),
            profile.max_message_bytes,
            MAX_REDACTION_MESSAGE_BYTES,
        )?;
        check_range(
            &format!("{prefix}.max_environment_literal_sources"),
            profile.max_environment_literal_sources,
            MAX_REDACTION_ENV_SOURCES_PER_PROFILE,
        )?;
        check_range(
            &format!("{prefix}.max_environment_literal_bytes"),
            profile.max_environment_literal_bytes,
            MAX_REDACTION_ENV_BYTES,
        )?;
        check_range(
            &format!("{prefix}.max_environment_literal_total_bytes"),
            profile.max_environment_literal_total_bytes,
            MAX_REDACTION_ENV_TOTAL_BYTES_PER_PROFILE,
        )?;
        if profile.max_decoded_body_bytes < profile.max_body_bytes {
            return Err(ConfigCompileError::at(
                &prefix,
                "max_decoded_body_bytes must be at least max_body_bytes",
            ));
        }
        if profile.max_message_bytes < profile.max_frame_bytes {
            return Err(ConfigCompileError::at(
                &prefix,
                "max_message_bytes must be at least max_frame_bytes",
            ));
        }
        validate_ratio_pair(
            profile.max_body_bytes,
            profile.max_decoded_body_bytes,
            config.service.max_content_decoding_expansion_ratio,
            &prefix,
        )?;
        if profile.replacement.contains("${") {
            return Err(ConfigCompileError::at(
                format!("{prefix}.replacement"),
                "generic environment interpolation is not valid in this schema",
            ));
        }
        if profile.rules.is_empty() || profile.rules.len() > MAX_REDACTION_RULES {
            return Err(ConfigCompileError::at(
                format!("{prefix}.rules"),
                format!("must contain between 1 and {MAX_REDACTION_RULES} rules"),
            ));
        }
        let (expression_count, expression_bytes) = profile
            .rules
            .iter()
            .flat_map(|rule| &rule.expressions)
            .try_fold((0usize, 0usize), |(count, bytes), expression| {
                Some((count.checked_add(1)?, bytes.checked_add(expression.len())?))
            })
            .ok_or_else(|| {
                ConfigCompileError::at(&prefix, "expression budget arithmetic overflow")
            })?;
        if expression_count > MAX_REDACTION_EXPRESSIONS
            || expression_bytes > MAX_REDACTION_EXPRESSION_BYTES_PER_PROFILE
        {
            return Err(ConfigCompileError::at(
                &prefix,
                "regular-expression count or byte ceiling exceeded",
            ));
        }
        let mut profile_sources = 0usize;
        let mut literal_count = 0usize;
        let mut literal_bytes = 0usize;
        for (rule_index, rule) in profile.rules.iter().enumerate() {
            let rule_path = format!("{prefix}.rules[{rule_index}]");
            if rule.literals.is_empty()
                && rule.literal_environment_variables.is_empty()
                && rule.expressions.is_empty()
            {
                return Err(ConfigCompileError::at(
                    &rule_path,
                    "must define a literal, environment literal source, or expression",
                ));
            }
            if matches!(rule.payloads, RedactionPayloads::Binary) && !rule.expressions.is_empty() {
                return Err(ConfigCompileError::at(
                    format!("{rule_path}.expressions"),
                    "binary-only rules cannot contain regular expressions",
                ));
            }
            literal_count = literal_count
                .checked_add(rule.literals.len())
                .ok_or_else(|| {
                    ConfigCompileError::at(&rule_path, "literal count arithmetic overflow")
                })?;
            for literal in &rule.literals {
                if literal.is_empty() || literal.contains("${") {
                    return Err(ConfigCompileError::at(
                        format!("{rule_path}.literals"),
                        "literals must be nonempty and cannot use generic interpolation",
                    ));
                }
                literal_bytes = literal_bytes.checked_add(literal.len()).ok_or_else(|| {
                    ConfigCompileError::at(&rule_path, "literal byte arithmetic overflow")
                })?;
            }
            let mut sources = BTreeSet::new();
            for (source_index, source) in rule.literal_environment_variables.iter().enumerate() {
                if !valid_environment_name(source) || !sources.insert(source) {
                    return Err(ConfigCompileError::at(
                        format!("{rule_path}.literal_environment_variables[{source_index}]"),
                        "source metadata is invalid or duplicates another source in this rule",
                    ));
                }
            }
            profile_sources = profile_sources
                .checked_add(rule.literal_environment_variables.len())
                .ok_or_else(|| {
                    ConfigCompileError::at(&rule_path, "source count arithmetic overflow")
                })?;
        }
        if literal_count > MAX_TOML_REDACTION_LITERALS_PER_PROFILE
            || literal_bytes > MAX_TOML_REDACTION_LITERAL_BYTES_PER_PROFILE
        {
            return Err(ConfigCompileError::at(
                &prefix,
                "TOML literal count or byte ceiling exceeded",
            ));
        }
        if profile_sources > profile.max_environment_literal_sources {
            return Err(ConfigCompileError::at(
                &prefix,
                "environment literal source count exceeds the authored profile limit",
            ));
        }
        snapshot_source_count = snapshot_source_count
            .checked_add(profile_sources)
            .ok_or_else(|| {
                ConfigCompileError::at("redaction.profiles", "snapshot source count overflow")
            })?;
        if profile_sources != 0 {
            let source_byte_budget = profile_sources
                .checked_mul(profile.max_environment_literal_bytes)
                .ok_or_else(|| {
                    ConfigCompileError::at("redaction.profiles", "snapshot byte budget overflow")
                })?
                .min(profile.max_environment_literal_total_bytes);
            snapshot_source_byte_budget = snapshot_source_byte_budget
                .checked_add(source_byte_budget)
                .ok_or_else(|| {
                    ConfigCompileError::at("redaction.profiles", "snapshot byte budget overflow")
                })?;
        }
    }
    if snapshot_source_count > MAX_REDACTION_ENV_SOURCES_PER_SNAPSHOT
        || snapshot_source_byte_budget > MAX_REDACTION_ENV_BYTES_PER_SNAPSHOT
    {
        return Err(ConfigCompileError::at(
            "redaction.profiles",
            "snapshot-wide environment source or byte ceiling exceeded",
        ));
    }
    Ok(())
}

fn validate_ratio_pair(
    encoded: usize,
    decoded: usize,
    ratio: usize,
    path: &str,
) -> Result<(), ConfigCompileError> {
    let proportional = encoded.checked_mul(ratio).ok_or_else(|| {
        ConfigCompileError::at(path, "content-decoding ratio arithmetic overflow")
    })?;
    let maximum = proportional.max(MIB);
    if decoded > maximum {
        return Err(ConfigCompileError::at(
            path,
            "decoded limit exceeds the configured proportional decoding bound",
        ));
    }
    Ok(())
}

fn validate_logging_capture_limits(
    config: &super::authoring::AuthoringConfig,
) -> Result<(), ConfigCompileError> {
    let logging = &config.observation.logging;
    if logging.max_bytes == 0 || logging.max_bytes > MAX_LOG_BYTES {
        return Err(ConfigCompileError::at(
            "observation.logging.max_bytes",
            format!("must be between 1 and {MAX_LOG_BYTES}"),
        ));
    }
    check_range(
        "observation.logging.max_files",
        logging.max_files,
        MAX_LOG_FILES,
    )?;
    compile_log_level(&logging.level, "observation.logging.level")?;
    compile_decision_log_level(
        &logging.policy_decisions.allow_level,
        "observation.logging.policy_decisions.allow_level",
    )?;
    compile_decision_log_level(
        &logging.policy_decisions.deny_level,
        "observation.logging.policy_decisions.deny_level",
    )?;
    if let Some(capture) = &config.observation.capture {
        check_range(
            "observation.capture.max_body_bytes",
            capture.max_body_bytes,
            MAX_CAPTURE_BODY_BYTES,
        )?;
        check_range(
            "observation.capture.max_inflight_body_bytes",
            capture.max_inflight_body_bytes,
            MAX_CAPTURE_INFLIGHT_BYTES,
        )?;
        check_range(
            "observation.capture.max_pending_records",
            capture.max_pending_records,
            MAX_CAPTURE_PENDING_RECORDS,
        )?;
        check_range(
            "observation.capture.max_files",
            capture.max_files,
            MAX_CAPTURE_FILES,
        )?;
        if capture.max_total_bytes == 0 || capture.max_total_bytes > MAX_CAPTURE_TOTAL_BYTES {
            return Err(ConfigCompileError::at(
                "observation.capture.max_total_bytes",
                format!("must be between 1 and {MAX_CAPTURE_TOTAL_BYTES}"),
            ));
        }
        if capture.max_inflight_body_bytes < capture.max_body_bytes
            || capture.max_total_bytes < capture.max_body_bytes as u64
        {
            return Err(ConfigCompileError::at(
                "observation.capture",
                "in-flight and total limits must each hold at least one maximum capture body",
            ));
        }
        if let Some(profile) = config.redaction.profiles.get(&capture.redaction_profile) {
            let maximum_source_bytes = profile.max_body_bytes.max(profile.max_decoded_body_bytes);
            let chunk_bytes = config
                .service
                .forwarding
                .chunk_bytes
                .min(maximum_source_bytes);
            validate_runtime_chunk_quotient(
                "observation.capture.redaction_profile",
                maximum_source_bytes,
                chunk_bytes,
            )?;
        }
    }
    Ok(())
}

fn compile_resource_plan(
    config: &super::authoring::AuthoringConfig,
    redaction: &ProductRedactionPlan,
) -> Result<CompiledResourcePlan, ConfigCompileError> {
    let body_read_compilation = compile_http_body_read_plans(config)?;
    let body_read_plans = &body_read_compilation.published_by_cursor;
    let rule_schedules = config
        .policy
        .rules
        .iter()
        .map(|rule| compile_http_rule_schedule_with_redaction(config, redaction, rule))
        .collect::<Result<Vec<_>, _>>()?;
    validate_forwarding_request_bounds(config, body_read_plans, &rule_schedules)?;
    let webhook_request_allocation_bytes_by_rule = rule_schedules
        .iter()
        .map(|schedule| schedule.webhook_request_allocation)
        .collect();
    let webhook_callback_allocation_bytes_by_rule = rule_schedules
        .iter()
        .map(|schedule| schedule.webhook_callback_allocation)
        .collect();

    let forwarding = &config.service.forwarding;
    let staging_bytes = project_guarded_body_allocation(
        forwarding.chunk_bytes,
        "service.forwarding.chunk_bytes",
        "request coalescing staging arithmetic overflow",
    )?;
    let terminal_requires_runtime = matches!(
        config.policy.default,
        super::authoring::PolicyDefaultDecision::Allow
    );
    let terminal_replay = if terminal_requires_runtime {
        runtime_replay_capacity(config, None, "policy.default")?
    } else {
        0
    };
    let terminal_product_peak = if terminal_requires_runtime {
        checked_add(
            staging_bytes,
            compile_credential_finalization_peak(config, None)?,
            "policy.default",
            "default credential finalization projection overflow",
        )?
    } else {
        0
    };
    let terminal_combined = checked_add(
        terminal_product_peak,
        terminal_replay,
        "policy.default",
        "HTTP body combined peak arithmetic overflow",
    )?;
    let terminal_path = ReachableHttpPath {
        product_peak_bytes: terminal_product_peak,
        requires_runtime_body: terminal_requires_runtime,
        ..ReachableHttpPath::default()
    };
    let mut resources_by_cursor = vec![
        HttpBodyResourcePlan {
            product_incremental_peak_bytes: 0,
            runtime_replay_capacity_bytes: 0,
            combined_peak_bytes: 0,
        };
        rule_schedules.len() + 1
    ];
    resources_by_cursor[rule_schedules.len()] = HttpBodyResourcePlan {
        product_incremental_peak_bytes: terminal_product_peak,
        runtime_replay_capacity_bytes: terminal_replay,
        combined_peak_bytes: terminal_combined,
    };
    let method_domain = policy_method_domain(config);
    let mut later = MethodSuffix::new(&method_domain, terminal_path);

    for index in (0..rule_schedules.len()).rev() {
        let schedule = &rule_schedules[index];
        let rule = &config.policy.rules[index];
        let variants = rule_method_variants(rule, &method_domain);
        let mut specialized_paths = RuleMethodValues::default();
        for variant in &variants {
            let path = compile_reachable_http_path(
                config,
                schedule,
                rule,
                later.get(variant.as_deref()),
                body_read_compilation.specialized_by_rule[index].get(variant.as_deref()),
                staging_bytes,
                index,
            )?;
            specialized_paths.insert(variant.as_deref(), path);
        }

        let published_path = specialized_paths.merged(ReachableHttpPath::merge);
        resources_by_cursor[index] = finalize_http_body_resource(
            config,
            published_path,
            body_read_plans[index],
            staging_bytes,
            index,
        )?
        .1;

        for variant in &variants {
            let path = specialized_paths.get(variant.as_deref());
            later.merge_at(variant.as_deref(), path, ReachableHttpPath::merge);
        }
    }

    let max_combined_peak = resources_by_cursor
        .iter()
        .map(|resource| resource.combined_peak_bytes)
        .max()
        .unwrap_or(0);
    let forward_response_peak = compile_forward_response_peak(config)?;
    let max_exchange_peak = resources_by_cursor
        .iter()
        .filter(|resource| resource.combined_peak_bytes != 0)
        .try_fold(0_usize, |maximum, resource| {
            let peak = resource
                .combined_peak_bytes
                .checked_add(forward_response_peak)
                .ok_or_else(|| {
                    ConfigCompileError::at(
                        "service.forwarding",
                        "request/response admission arithmetic overflow",
                    )
                })?;
            Ok::<_, ConfigCompileError>(maximum.max(peak))
        })?;

    let wire_body_full_peak_capacity = if max_exchange_peak == 0 {
        Capacity::Unbounded
    } else {
        if max_exchange_peak > config.service.max_inflight_wire_body_bytes_per_quota_key {
            return Err(ConfigCompileError::at(
                "service.max_inflight_wire_body_bytes_per_quota_key",
                "must hold the largest pass-reachable request/response working set",
            ));
        }
        let required = max_exchange_peak
            .checked_mul(config.service.min_wire_body_concurrency)
            .ok_or_else(|| {
                ConfigCompileError::at("service", "wire-body capacity arithmetic overflow")
            })?;
        if required > config.service.max_inflight_wire_body_bytes {
            return Err(ConfigCompileError::at(
                "service.min_wire_body_concurrency",
                "the requested minimum concurrency does not fit the global wire-body pool",
            ));
        }
        Capacity::Finite(config.service.max_inflight_wire_body_bytes / max_exchange_peak)
    };
    let wire_body_quota_key_full_peak_capacity = config
        .service
        .max_inflight_wire_body_bytes_per_quota_key
        .checked_div(max_exchange_peak)
        .map_or(Capacity::Unbounded, Capacity::Finite);

    let transport = config
        .service
        .upgrade_relay_buffer_bytes
        .checked_mul(2)
        .ok_or_else(|| ConfigCompileError::at("service", "upgrade buffer arithmetic overflow"))?;
    let upgrade_wire_working_set_bytes_by_rule = config
        .policy
        .rules
        .iter()
        .map(|rule| {
            if !rule.allow_upgrades {
                return Ok(None);
            }
            let wire_working_set = rule
                .redaction_profile
                .as_ref()
                .map(|name| {
                    let profile = redaction
                        .profiles
                        .get(name)
                        .expect("profile references validated before resource compilation");
                    upgrade_wire_peak(
                        profile.limits.max_message_bytes(),
                        profile.limits.allow_permessage_deflate(),
                        profile.projection.matcher_scratch_bytes(),
                    )
                })
                .transpose()?
                .unwrap_or(0);
            Ok(Some(wire_working_set))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let max_wire_working_set = upgrade_wire_working_set_bytes_by_rule
        .iter()
        .flatten()
        .copied()
        .max();
    let per_stream = max_wire_working_set
        .map(|wire_working_set| {
            transport.checked_add(wire_working_set).ok_or_else(|| {
                ConfigCompileError::at("service", "upgrade buffer arithmetic overflow")
            })
        })
        .transpose()?
        .unwrap_or(0);
    let all_streams = per_stream
        .checked_mul(config.service.max_active_upgrades)
        .ok_or_else(|| {
            ConfigCompileError::at("service", "upgrade aggregate arithmetic overflow")
        })?;
    if all_streams > config.service.max_upgrade_buffer_bytes {
        return Err(ConfigCompileError::at(
            "service.max_upgrade_buffer_bytes",
            "cannot hold the configured transport and maximum reachable reassembly buffers",
        ));
    }

    Ok(CompiledResourcePlan {
        http_body_resources_by_cursor: resources_by_cursor,
        max_reachable_http_body_combined_peak_bytes: max_combined_peak,
        forward_response_peak_bytes: forward_response_peak,
        max_reachable_http_exchange_peak_bytes: max_exchange_peak,
        wire_body_full_peak_capacity,
        wire_body_quota_key_full_peak_capacity,
        webhook_request_allocation_bytes_by_rule,
        webhook_callback_allocation_bytes_by_rule,
        upgrade_wire_working_set_bytes_by_rule,
        max_upgrade_allocation_per_stream: per_stream,
        max_upgrade_allocation_all_streams: all_streams,
    })
}

fn compile_forward_response_peak(
    config: &super::authoring::AuthoringConfig,
) -> Result<usize, ConfigCompileError> {
    let forwarding = &config.service.forwarding;
    let ratio =
        u64::try_from(config.service.max_content_decoding_expansion_ratio).map_err(|_| {
            ConfigCompileError::at(
                "service.max_content_decoding_expansion_ratio",
                "forward response ratio cannot be represented",
            )
        })?;
    let limits = BodyLimits::new(
        u64::try_from(forwarding.max_response_wire_bytes).map_err(|_| {
            ConfigCompileError::at(
                "service.forwarding.max_response_wire_bytes",
                "forward response limit cannot be represented",
            )
        })?,
        u64::try_from(forwarding.max_response_decoded_bytes).map_err(|_| {
            ConfigCompileError::at(
                "service.forwarding.max_response_decoded_bytes",
                "forward response limit cannot be represented",
            )
        })?,
        ratio,
        1,
        u64::try_from(forwarding.chunk_bytes).map_err(|_| {
            ConfigCompileError::at(
                "service.forwarding.chunk_bytes",
                "forward response chunk limit cannot be represented",
            )
        })?,
        u64::try_from(forwarding.max_trailer_count).map_err(|_| {
            ConfigCompileError::at(
                "service.forwarding.max_trailer_count",
                "forward response trailer limit cannot be represented",
            )
        })?,
        u64::try_from(forwarding.max_trailer_bytes).map_err(|_| {
            ConfigCompileError::at(
                "service.forwarding.max_trailer_bytes",
                "forward response trailer limit cannot be represented",
            )
        })?,
    )
    .map_err(|_| {
        ConfigCompileError::at(
            "service.forwarding",
            "forward response limits are inconsistent",
        )
    })?;
    let idle_ms = u64::try_from(forwarding.body_idle_timeout.get().as_millis()).map_err(|_| {
        ConfigCompileError::at(
            "service.forwarding.body_idle_timeout",
            "forward response idle timeout cannot be represented",
        )
    })?;
    let policy =
        ResponsePolicy::new(limits, idle_ms, RedirectPolicy::ReturnToCaller).map_err(|_| {
            ConfigCompileError::at(
                "service.forwarding",
                "forward response policy is inconsistent",
            )
        })?;
    usize::try_from(policy.projection().simultaneous_peak_bytes()).map_err(|_| {
        ConfigCompileError::at(
            "service.forwarding",
            "forward response projection cannot be represented",
        )
    })
}

#[derive(Clone, Copy, Default)]
struct ReachableHttpPath {
    product_peak_bytes: usize,
    incoming_stage_peak_bytes: usize,
    body_free_stage_peak_bytes: usize,
    canonical_output_or_replacement_limit: usize,
    requires_runtime_body: bool,
}

impl ReachableHttpPath {
    fn merge(self, other: Self) -> Self {
        Self {
            product_peak_bytes: self.product_peak_bytes.max(other.product_peak_bytes),
            incoming_stage_peak_bytes: self
                .incoming_stage_peak_bytes
                .max(other.incoming_stage_peak_bytes),
            body_free_stage_peak_bytes: self
                .body_free_stage_peak_bytes
                .max(other.body_free_stage_peak_bytes),
            canonical_output_or_replacement_limit: self
                .canonical_output_or_replacement_limit
                .max(other.canonical_output_or_replacement_limit),
            requires_runtime_body: self.requires_runtime_body || other.requires_runtime_body,
        }
    }
}

fn compile_reachable_http_path(
    config: &super::authoring::AuthoringConfig,
    schedule: &HttpRuleAllocationSchedule,
    rule: &PolicyRuleConfig,
    compatible_later: ReachableHttpPath,
    body_read_plan: HttpBodyReadPlan,
    staging_bytes: usize,
    index: usize,
) -> Result<ReachableHttpPath, ConfigCompileError> {
    let local_stage = schedule.max_incoming_additional_bytes();
    let mut path = ReachableHttpPath {
        product_peak_bytes: schedule.initial_peak,
        incoming_stage_peak_bytes: local_stage,
        body_free_stage_peak_bytes: if schedule.local_body_allocation.is_none() {
            local_stage
        } else {
            0
        },
        canonical_output_or_replacement_limit: schedule.replacement_decoded_limit.unwrap_or(0),
        // A delegate provider can terminally allow even when it does not inspect
        // the body, so every non-deny rule has an opaque forward-allow path.
        requires_runtime_body: !matches!(rule.decision, RuleDecision::Deny),
    };
    if matches!(rule.decision, RuleDecision::Delegate) {
        path.incoming_stage_peak_bytes = path
            .incoming_stage_peak_bytes
            .max(compatible_later.incoming_stage_peak_bytes);
        path.body_free_stage_peak_bytes = path
            .body_free_stage_peak_bytes
            .max(compatible_later.body_free_stage_peak_bytes);
        path.canonical_output_or_replacement_limit = path
            .canonical_output_or_replacement_limit
            .max(compatible_later.canonical_output_or_replacement_limit);
        path.requires_runtime_body |= compatible_later.requires_runtime_body;
        path.product_peak_bytes = if let Some(retained) = schedule.retained_original_after_pass {
            path.product_peak_bytes.max(checked_add(
                retained,
                compatible_later.incoming_stage_peak_bytes,
                &format!("policy.rules[{index}]"),
                "delegate-pass body retention arithmetic overflow",
            )?)
        } else {
            path.product_peak_bytes
                .max(compatible_later.product_peak_bytes)
        };
    }
    finalize_http_body_resource(config, path, body_read_plan, staging_bytes, index)
        .map(|(path, _)| path)
}

fn finalize_http_body_resource(
    config: &super::authoring::AuthoringConfig,
    mut path: ReachableHttpPath,
    body_read_plan: HttpBodyReadPlan,
    staging_bytes: usize,
    index: usize,
) -> Result<(ReachableHttpPath, HttpBodyResourcePlan), ConfigCompileError> {
    if let Some(limits) = body_read_plan.limits() {
        path.canonical_output_or_replacement_limit = path
            .canonical_output_or_replacement_limit
            .max(limits.max_decoded_bytes());
        path.product_peak_bytes = path.product_peak_bytes.max(decode_peak(
            limits.max_encoded_bytes(),
            limits.max_decoded_bytes(),
        )?);
        let merged_original = project_guarded_body_allocation(
            limits.max_decoded_bytes(),
            &format!("policy.rules[{index}]"),
            "post-decode merged body allocation arithmetic overflow",
        )?;
        path.product_peak_bytes = path.product_peak_bytes.max(checked_add(
            merged_original,
            path.body_free_stage_peak_bytes,
            &format!("policy.rules[{index}]"),
            "post-decode body-free rule arithmetic overflow",
        )?);
    }
    if path.requires_runtime_body {
        path.product_peak_bytes = path.product_peak_bytes.max(staging_bytes);
    }
    let replay_capacity = if path.requires_runtime_body {
        runtime_replay_capacity(
            config,
            NonZeroUsize::new(path.canonical_output_or_replacement_limit),
            &format!("policy.rules[{index}]"),
        )?
    } else {
        0
    };
    let combined_peak = checked_add(
        path.product_peak_bytes,
        replay_capacity,
        &format!("policy.rules[{index}]"),
        "HTTP body combined peak arithmetic overflow",
    )?;
    Ok((
        path,
        HttpBodyResourcePlan {
            product_incremental_peak_bytes: path.product_peak_bytes,
            runtime_replay_capacity_bytes: replay_capacity,
            combined_peak_bytes: combined_peak,
        },
    ))
}

fn runtime_replay_capacity(
    config: &super::authoring::AuthoringConfig,
    canonical_output_or_replacement_limit: Option<NonZeroUsize>,
    path: &str,
) -> Result<usize, ConfigCompileError> {
    let forwarding = &config.service.forwarding;
    let source_payload_bytes = forwarding.max_request_wire_bytes;
    let (trailer_count, trailer_bytes) = if canonical_output_or_replacement_limit.is_none()
        && forwarding.preserve_request_trailers
    {
        (forwarding.max_trailer_count, forwarding.max_trailer_bytes)
    } else {
        (0, 0)
    };
    let required = BodyBudget::required_replay_storage_bytes(
        u64::try_from(source_payload_bytes).map_err(|_| {
            ConfigCompileError::at(path, "runtime replay source conversion overflow")
        })?,
        u64::try_from(forwarding.chunk_bytes).map_err(|_| {
            ConfigCompileError::at(path, "runtime replay chunk conversion overflow")
        })?,
        u64::try_from(trailer_count).map_err(|_| {
            ConfigCompileError::at(path, "runtime replay trailer conversion overflow")
        })?,
        u64::try_from(trailer_bytes).map_err(|_| {
            ConfigCompileError::at(path, "runtime replay trailer conversion overflow")
        })?,
        canonical_output_or_replacement_limit
            .map(|limit| u64::try_from(limit.get()))
            .transpose()
            .map_err(|_| ConfigCompileError::at(path, "runtime replacement conversion overflow"))?,
    )
    .map_err(|_| ConfigCompileError::at(path, "runtime replay projection is invalid"))?;
    usize::try_from(required)
        .map_err(|_| ConfigCompileError::at(path, "runtime replay projection overflow"))
}

#[derive(Debug)]
struct HttpRuleAllocationSchedule {
    initial_peak: usize,
    local_body_allocation: Option<usize>,
    retained_original_after_pass: Option<usize>,
    replacement_decoded_limit: Option<usize>,
    incoming_stages: Vec<IncomingBodyStage>,
    webhook_request_allocation: Option<usize>,
    webhook_callback_allocation: Option<usize>,
}

impl HttpRuleAllocationSchedule {
    fn max_incoming_additional_bytes(&self) -> usize {
        self.incoming_stages
            .iter()
            .map(|stage| stage.additional_bytes)
            .max()
            .unwrap_or(0)
    }
}

fn validate_forwarding_request_bounds(
    config: &super::authoring::AuthoringConfig,
    body_read_plans: &[HttpBodyReadPlan],
    rule_schedules: &[HttpRuleAllocationSchedule],
) -> Result<(), ConfigCompileError> {
    let forwarding = &config.service.forwarding;
    for limits in body_read_plans.iter().filter_map(|plan| plan.limits()) {
        if limits.max_encoded_bytes() > forwarding.max_request_wire_bytes {
            return Err(ConfigCompileError::at(
                "service.forwarding.max_request_wire_bytes",
                "must cover every reachable mandatory request wire-body limit",
            ));
        }
        if limits.max_decoded_bytes() > forwarding.max_request_decoded_bytes {
            return Err(ConfigCompileError::at(
                "service.forwarding.max_request_decoded_bytes",
                "must cover every reachable mandatory decoded request-body limit",
            ));
        }
    }
    if rule_schedules
        .iter()
        .filter_map(|schedule| schedule.replacement_decoded_limit)
        .any(|limit| limit > forwarding.max_request_decoded_bytes)
    {
        return Err(ConfigCompileError::at(
            "service.forwarding.max_request_decoded_bytes",
            "must cover every reachable provider replacement limit",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct IncomingBodyStage {
    additional_bytes: usize,
}

fn compile_http_rule_schedule_with_redaction(
    config: &super::authoring::AuthoringConfig,
    redaction: &ProductRedactionPlan,
    rule: &PolicyRuleConfig,
) -> Result<HttpRuleAllocationSchedule, ConfigCompileError> {
    let process_provider = rule.authorization_provider.as_ref().and_then(|name| {
        match config.authorization.providers.get(name) {
            Some(AuthorizationProviderConfig::Process(provider)) => Some(provider),
            _ => None,
        }
    });
    let webhook_provider = rule.authorization_provider.as_ref().and_then(|name| {
        match config.authorization.providers.get(name) {
            Some(AuthorizationProviderConfig::Webhook(provider)) => Some(provider),
            _ => None,
        }
    });
    let unix_provider = rule.authorization_provider.as_ref().and_then(|name| {
        match config.authorization.providers.get(name) {
            Some(AuthorizationProviderConfig::UnixSocket(provider)) => {
                Some((name.as_str(), provider))
            }
            _ => None,
        }
    });
    let process_body = process_provider.filter(|provider| provider.include_request_body);
    let profile = rule.redaction_profile.as_ref().map(|name| {
        config
            .redaction
            .profiles
            .get(name)
            .expect("profile references validated before resource compilation")
    });
    let profile_scratch_bytes = rule.redaction_profile.as_ref().map(|name| {
        redaction
            .profiles
            .get(name)
            .expect("profile references validated before resource compilation")
            .projection
            .matcher_scratch_bytes()
    });
    let effective_body_limits = effective_http_body_limits(process_body, profile);
    let replacement_decoded_limit = process_body
        .filter(|provider| provider.allow_request_body_replacement)
        .map(|_| {
            effective_body_limits
                .expect("request-body replacement has effective body limits")
                .1
        });
    let local_body_allocation = effective_body_limits
        .map(|(_, original_limit)| {
            project_guarded_body_allocation(
                original_limit,
                "policy.rules",
                "local decoded body allocation arithmetic overflow",
            )
        })
        .transpose()?;

    let mut initial_peak = 0usize;
    let mut incoming_stages = Vec::with_capacity(6);
    let webhook_request_allocation = webhook_provider
        .map(|provider| {
            project_guarded_body_allocation(
                provider.max_request_bytes,
                "policy.rules",
                "webhook request allocation arithmetic overflow",
            )
        })
        .transpose()?;
    let webhook_callback_bytes = webhook_provider
        .map(|provider| {
            let control = config
                .control
                .as_ref()
                .expect("reachable webhook provider requires validated control config");
            let full_body_limit = control
                .max_request_body_bytes
                .min(provider.max_response_bytes);
            let suffix_bytes = full_body_limit
                .checked_sub(CALLBACK_RESPONSE_PREFIX_BYTES)
                .ok_or_else(|| {
                    ConfigCompileError::at(
                        "control.max_request_body_bytes",
                        "cannot hold the fixed callback capability prefix",
                    )
                })?;
            Ok(suffix_bytes)
        })
        .transpose()?;
    let webhook_callback_allocation = webhook_callback_bytes
        .map(|suffix_bytes| {
            project_guarded_body_allocation(
                suffix_bytes,
                "policy.rules",
                "webhook callback allocation arithmetic overflow",
            )
        })
        .transpose()?;
    let webhook_credential_allocation = webhook_provider
        .zip(webhook_callback_bytes)
        .map(|(provider, callback_bytes)| {
            compact_provider_credential_allocation(provider.outputs.len(), callback_bytes)
        })
        .transpose()?;
    let unix_projection = unix_provider
        .map(|(name, provider)| compile_unix_provider_projection(name, provider))
        .transpose()?;
    let unix_provider_allocation =
        unix_projection.map(|projection| projection.per_request_allocation_bytes);
    for allocation in [webhook_request_allocation, webhook_callback_allocation]
        .into_iter()
        .flatten()
    {
        initial_peak = initial_peak.max(allocation);
        incoming_stages.push(IncomingBodyStage {
            additional_bytes: allocation,
        });
    }
    if let Some(allocation) = unix_provider_allocation {
        initial_peak = initial_peak.max(allocation);
        incoming_stages.push(IncomingBodyStage {
            additional_bytes: allocation,
        });
    }
    let request_stream_scratch_allocation = process_provider
        .map(|_| {
            project_guarded_body_allocation(
                PROVIDER_REQUEST_STREAM_SCRATCH_BYTES,
                "policy.rules",
                "HTTP provider request-stream plan arithmetic overflow",
            )
        })
        .transpose()?;
    if let Some(request_stream_scratch_allocation) = request_stream_scratch_allocation {
        initial_peak = initial_peak.max(request_stream_scratch_allocation);
        incoming_stages.push(IncomingBodyStage {
            additional_bytes: request_stream_scratch_allocation,
        });
    }
    let response_continuation_bytes = process_provider
        .map(|provider| {
            let provider_name = rule
                .authorization_provider
                .as_deref()
                .expect("process provider was resolved from the rule");
            provider_response_guarded_suffix_bytes(
                provider.max_stdout_line_bytes,
                &format!("authorization.providers.{provider_name}.max_stdout_line_bytes"),
            )
        })
        .transpose()?;
    let response_continuation_allocation = response_continuation_bytes
        .map(|bytes| {
            project_guarded_body_allocation(
                bytes,
                "policy.rules",
                "HTTP provider-response continuation arithmetic overflow",
            )
        })
        .transpose()?;
    let process_credential_allocation = process_provider
        .zip(response_continuation_bytes)
        .map(|(provider, continuation_bytes)| {
            compact_provider_credential_allocation(provider.outputs.len(), continuation_bytes)
        })
        .transpose()?;
    let unix_credential_allocation = unix_provider
        .filter(|(_, provider)| !provider.outputs.is_empty())
        .map(|(_, provider)| {
            compact_provider_credential_allocation(
                provider.outputs.len(),
                provider.max_response_bytes,
            )
        })
        .transpose()?;
    let credential_allocation = process_credential_allocation
        .or(webhook_credential_allocation)
        .or(unix_credential_allocation);
    if let Some(response_continuation_allocation) = response_continuation_allocation {
        initial_peak = initial_peak.max(response_continuation_allocation);
    }
    if let (Some(callback), Some(credentials)) =
        (webhook_callback_allocation, credential_allocation)
    {
        let rehome_peak = checked_add(
            callback,
            credentials,
            "policy.rules",
            "webhook credential rehome arithmetic overflow",
        )?;
        initial_peak = initial_peak.max(rehome_peak);
        incoming_stages.push(IncomingBodyStage {
            additional_bytes: rehome_peak,
        });
    }
    if let (Some(continuation), Some(credentials)) =
        (response_continuation_allocation, credential_allocation)
    {
        let rehome_peak = checked_add(
            continuation,
            credentials,
            "policy.rules",
            "process credential rehome arithmetic overflow",
        )?;
        initial_peak = initial_peak.max(rehome_peak);
        incoming_stages.push(IncomingBodyStage {
            additional_bytes: rehome_peak,
        });
    } else if let Some(continuation) = response_continuation_allocation {
        incoming_stages.push(IncomingBodyStage {
            additional_bytes: continuation,
        });
    }
    if let Some((encoded_limit, original_limit)) = effective_body_limits {
        initial_peak = initial_peak.max(decode_peak(encoded_limit, original_limit)?);
        let original_allocation =
            local_body_allocation.expect("effective body limits have a local allocation");
        for allocation in [webhook_request_allocation, webhook_callback_allocation]
            .into_iter()
            .flatten()
        {
            initial_peak = initial_peak.max(checked_add(
                original_allocation,
                allocation,
                "policy.rules",
                "webhook body-retention arithmetic overflow",
            )?);
        }
        if let Some(allocation) = unix_provider_allocation {
            initial_peak = initial_peak.max(checked_add(
                original_allocation,
                allocation,
                "policy.rules",
                "Unix provider body-retention arithmetic overflow",
            )?);
        }
        if let (Some(callback), Some(credentials)) =
            (webhook_callback_allocation, credential_allocation)
        {
            initial_peak = initial_peak.max(
                original_allocation
                    .checked_add(callback)
                    .and_then(|bytes| bytes.checked_add(credentials))
                    .ok_or_else(|| {
                        ConfigCompileError::at(
                            "policy.rules",
                            "webhook credential rehome arithmetic overflow",
                        )
                    })?,
            );
        }
        if process_provider.is_some() {
            initial_peak = initial_peak.max(guarded_body_stage_peak(
                [original_limit, PROVIDER_REQUEST_STREAM_SCRATCH_BYTES],
                "policy.rules",
                "HTTP provider request-stream plan arithmetic overflow",
            )?);
            initial_peak = initial_peak.max(guarded_body_stage_peak(
                [
                    original_limit,
                    response_continuation_bytes
                        .expect("process provider has a response continuation limit"),
                ],
                "policy.rules",
                "HTTP provider-response continuation arithmetic overflow",
            )?);
            if let (Some(continuation_bytes), Some(credentials)) =
                (response_continuation_bytes, credential_allocation)
            {
                let body_peak = guarded_body_stage_peak(
                    [original_limit, continuation_bytes],
                    "policy.rules",
                    "process credential rehome arithmetic overflow",
                )?;
                initial_peak = initial_peak.max(checked_add(
                    body_peak,
                    credentials,
                    "policy.rules",
                    "process credential rehome arithmetic overflow",
                )?);
            }
        }
    }
    if let Some(provider) = process_body {
        let original_limit = effective_body_limits
            .expect("process-body limits were derived with the process provider")
            .1;
        let response_continuation_bytes = response_continuation_bytes
            .expect("process-body provider has a response continuation limit");
        if provider.allow_request_body_replacement {
            // The original remains live until a structurally accepted
            // replacement irrevocably wins. Only then may replacement decode
            // and redaction proceed without the original allocation.
            initial_peak = initial_peak.max(replacement_decode_peak(
                response_continuation_bytes,
                original_limit,
            )?);
            if let Some(credentials) = credential_allocation {
                let body_peak = guarded_body_stage_peak(
                    [response_continuation_bytes, original_limit],
                    "policy.rules",
                    "process replacement credential rehome arithmetic overflow",
                )?;
                initial_peak = initial_peak.max(checked_add(
                    body_peak,
                    credentials,
                    "policy.rules",
                    "process replacement credential rehome arithmetic overflow",
                )?);
            }
        } else if let Some(credentials) = credential_allocation {
            let body_peak = guarded_body_stage_peak(
                [original_limit, response_continuation_bytes],
                "policy.rules",
                "process credential rehome arithmetic overflow",
            )?;
            initial_peak = initial_peak.max(checked_add(
                body_peak,
                credentials,
                "policy.rules",
                "process credential rehome arithmetic overflow",
            )?);
        }
    }
    if let Some(profile) = profile {
        let original_limit = effective_body_limits
            .expect("redaction profile has effective body limits")
            .1;
        let redaction_additional = guarded_body_stage_peak(
            [
                profile_scratch_bytes.expect("redaction profile scratch was derived"),
                profile.max_decoded_body_bytes,
            ],
            "policy.rules",
            "HTTP redaction plan arithmetic overflow",
        )?;
        let has_text_expressions = rule
            .redaction_profile
            .as_ref()
            .and_then(|name| redaction.profiles.get(name))
            .is_some_and(|profile| profile.has_text_expressions);
        let regex_peak = if has_text_expressions {
            guarded_body_stage_peak(
                [
                    profile.max_decoded_body_bytes,
                    profile.max_decoded_body_bytes,
                ],
                "policy.rules",
                "HTTP regex redaction plan arithmetic overflow",
            )?
        } else {
            0
        };
        let credential_allocation = credential_allocation.unwrap_or(0);
        let original_redaction_peak = checked_add(
            project_guarded_body_allocation(
                original_limit,
                "policy.rules",
                "HTTP redaction plan arithmetic overflow",
            )?,
            checked_add(
                redaction_additional,
                credential_allocation,
                "policy.rules",
                "HTTP credential-redaction plan arithmetic overflow",
            )?,
            "policy.rules",
            "HTTP redaction plan arithmetic overflow",
        )?
        .max(checked_add(
            regex_peak,
            credential_allocation,
            "policy.rules",
            "HTTP credential-regex redaction plan arithmetic overflow",
        )?);
        initial_peak = initial_peak.max(original_redaction_peak);
        // A prior delegate's retained body becomes the regex input. The
        // incoming stage therefore adds only matcher scratch and the output
        // buffer; the standalone peak above covers both regex buffers when
        // no prior body is retained.
        incoming_stages.push(IncomingBodyStage {
            additional_bytes: checked_add(
                redaction_additional,
                credential_allocation,
                "policy.rules",
                "HTTP incoming credential-redaction plan arithmetic overflow",
            )?,
        });
        if process_body.is_some_and(|provider| provider.allow_request_body_replacement) {
            let replacement_limit = effective_body_limits
                .expect("replacement limits were derived with the process provider")
                .1;
            let replacement_redaction_peak = checked_add(
                project_guarded_body_allocation(
                    replacement_limit,
                    "policy.rules",
                    "HTTP replacement-redaction plan arithmetic overflow",
                )?,
                checked_add(
                    redaction_additional,
                    credential_allocation,
                    "policy.rules",
                    "HTTP replacement credential-redaction plan arithmetic overflow",
                )?,
                "policy.rules",
                "HTTP replacement-redaction plan arithmetic overflow",
            )?
            .max(checked_add(
                regex_peak,
                credential_allocation,
                "policy.rules",
                "HTTP replacement credential-regex plan arithmetic overflow",
            )?);
            initial_peak = initial_peak.max(replacement_redaction_peak);
        }
    }

    let credential_finalization_peak = compile_credential_finalization_peak(config, Some(rule))?;
    if credential_finalization_peak != 0 {
        initial_peak = checked_add(
            initial_peak,
            credential_finalization_peak,
            "policy.rules",
            "credential finalization projection overflow",
        )?;
        if incoming_stages.is_empty() {
            incoming_stages.push(IncomingBodyStage {
                additional_bytes: credential_finalization_peak,
            });
        } else {
            for stage in &mut incoming_stages {
                stage.additional_bytes = checked_add(
                    stage.additional_bytes,
                    credential_finalization_peak,
                    "policy.rules",
                    "incoming credential finalization projection overflow",
                )?;
            }
        }
    }

    Ok(HttpRuleAllocationSchedule {
        initial_peak,
        local_body_allocation,
        retained_original_after_pass: if matches!(rule.decision, RuleDecision::Delegate) {
            local_body_allocation
        } else {
            None
        },
        replacement_decoded_limit,
        incoming_stages,
        webhook_request_allocation,
        webhook_callback_allocation,
    })
}

#[cfg(test)]
fn compile_http_rule_schedule(
    config: &super::authoring::AuthoringConfig,
    rule: &PolicyRuleConfig,
) -> Result<HttpRuleAllocationSchedule, ConfigCompileError> {
    let redaction = compile_redaction_plan(&config.redaction)?;
    compile_http_rule_schedule_with_redaction(config, &redaction, rule)
}

#[cfg(test)]
fn shared_matcher_scratch_bytes(horizon: usize) -> usize {
    let id = StableId::new("scratch-projection").unwrap();
    let limits = RedactionLimits::new(1, 1, 1, 1, false, 1, 1, 1).unwrap();
    let prepared = PreparedRedactionSnapshot::prepare(
        RedactionSnapshotSpec::new(vec![RedactionProfileSpec::new(
            id.clone(),
            b"x".to_vec(),
            limits,
            vec![RedactionRuleSpec::new(
                vec![vec![b'x'; horizon]],
                Vec::new(),
                Vec::new(),
                RulePayloads::Both,
            )],
        )]),
        || false,
    )
    .unwrap();
    prepared
        .profile_projection(&id)
        .unwrap()
        .matcher_scratch_bytes()
}

fn effective_http_body_limits(
    process_body: Option<&super::authoring::ProcessProviderConfig>,
    profile: Option<&super::authoring::RedactionProfileConfig>,
) -> Option<(usize, usize)> {
    match (process_body, profile) {
        (Some(provider), Some(profile)) => Some((
            provider.max_request_body_bytes.min(profile.max_body_bytes),
            provider
                .max_decoded_request_body_bytes
                .min(profile.max_decoded_body_bytes),
        )),
        (Some(provider), None) => Some((
            provider.max_request_body_bytes,
            provider.max_decoded_request_body_bytes,
        )),
        (None, Some(profile)) => Some((profile.max_body_bytes, profile.max_decoded_body_bytes)),
        (None, None) => None,
    }
}

#[derive(Clone)]
struct MethodSuffix<T: Copy> {
    fallback: T,
    by_method: BTreeMap<String, T>,
}

impl<T: Copy> MethodSuffix<T> {
    fn new(methods: &BTreeSet<String>, fallback: T) -> Self {
        Self {
            fallback,
            by_method: methods
                .iter()
                .map(|method| (method.clone(), fallback))
                .collect(),
        }
    }

    fn get(&self, method: Option<&str>) -> T {
        method
            .and_then(|method| self.by_method.get(method).copied())
            .unwrap_or(self.fallback)
    }

    fn merge_at(&mut self, method: Option<&str>, value: T, merge: impl FnOnce(T, T) -> T) {
        match method {
            Some(method) => {
                let current = self
                    .by_method
                    .get_mut(method)
                    .expect("policy method domain contains every authored method");
                *current = merge(*current, value);
            }
            None => self.fallback = merge(self.fallback, value),
        }
    }
}

#[derive(Clone)]
struct RuleMethodValues<T: Copy> {
    fallback: Option<T>,
    by_method: BTreeMap<String, T>,
}

impl<T: Copy> Default for RuleMethodValues<T> {
    fn default() -> Self {
        Self {
            fallback: None,
            by_method: BTreeMap::new(),
        }
    }
}

impl<T: Copy> RuleMethodValues<T> {
    fn insert(&mut self, method: Option<&str>, value: T) {
        match method {
            Some(method) => {
                self.by_method.insert(method.to_string(), value);
            }
            None => self.fallback = Some(value),
        }
    }

    fn get(&self, method: Option<&str>) -> T {
        method
            .and_then(|method| self.by_method.get(method).copied())
            .or(self.fallback)
            .expect("rule method specialization covers every matched method")
    }

    fn merged(&self, merge: impl Fn(T, T) -> T + Copy) -> T {
        self.fallback
            .into_iter()
            .chain(self.by_method.values().copied())
            .reduce(merge)
            .expect("every policy rule matches at least one method category")
    }
}

fn policy_method_domain(config: &super::authoring::AuthoringConfig) -> BTreeSet<String> {
    config
        .policy
        .rules
        .iter()
        .flat_map(|rule| rule.methods.iter())
        .map(|method| method.to_ascii_uppercase())
        .collect()
}

fn rule_method_variants(
    rule: &PolicyRuleConfig,
    method_domain: &BTreeSet<String>,
) -> Vec<Option<String>> {
    if rule.methods.is_empty() {
        std::iter::once(None)
            .chain(method_domain.iter().cloned().map(Some))
            .collect()
    } else {
        rule.methods
            .iter()
            .map(|method| Some(method.to_ascii_uppercase()))
            .collect()
    }
}

struct CompiledHttpBodyReadPlans {
    published_by_cursor: Vec<HttpBodyReadPlan>,
    specialized_by_rule: Vec<RuleMethodValues<HttpBodyReadPlan>>,
}

fn compile_http_body_read_plans(
    config: &super::authoring::AuthoringConfig,
) -> Result<CompiledHttpBodyReadPlans, ConfigCompileError> {
    let cursor_count = config.policy.rules.len().checked_add(1).ok_or_else(|| {
        ConfigCompileError::at("policy.rules", "HTTP body read cursor count overflow")
    })?;
    let mut plans = vec![HttpBodyReadPlan::Disabled; cursor_count];
    let mut specialized = vec![RuleMethodValues::default(); config.policy.rules.len()];
    let method_domain = policy_method_domain(config);
    let mut later = MethodSuffix::new(&method_domain, HttpBodyReadPlan::Disabled);

    for index in (0..config.policy.rules.len()).rev() {
        let rule = &config.policy.rules[index];
        let process_body = rule.authorization_provider.as_ref().and_then(|name| {
            match config.authorization.providers.get(name) {
                Some(AuthorizationProviderConfig::Process(provider))
                    if provider.include_request_body =>
                {
                    Some(provider)
                }
                _ => None,
            }
        });
        let profile = rule.redaction_profile.as_ref().map(|name| {
            config
                .redaction
                .profiles
                .get(name)
                .expect("profile references validated before body-read compilation")
        });
        let exact = effective_http_body_limits(process_body, profile)
            .map(|(max_encoded_bytes, max_decoded_bytes)| {
                HttpBodyReadLimits::try_new(max_encoded_bytes, max_decoded_bytes)
                    .map(HttpBodyReadPlan::Mandatory)
                    .ok_or_else(|| {
                        ConfigCompileError::at(
                            format!("policy.rules[{index}]"),
                            "mandatory HTTP body read limits must be nonzero and decoded must be at least encoded",
                        )
                    })
            })
            .transpose()?
            .unwrap_or(HttpBodyReadPlan::Disabled);
        let variants = rule_method_variants(rule, &method_domain);
        for variant in &variants {
            let path = if matches!(rule.decision, RuleDecision::Delegate) {
                exact.merge(later.get(variant.as_deref()))
            } else {
                exact
            };
            specialized[index].insert(variant.as_deref(), path);
        }
        plans[index] = specialized[index].merged(HttpBodyReadPlan::merge);
        for variant in &variants {
            let path = specialized[index].get(variant.as_deref());
            later.merge_at(variant.as_deref(), path, HttpBodyReadPlan::merge);
        }
    }

    Ok(CompiledHttpBodyReadPlans {
        published_by_cursor: plans,
        specialized_by_rule: specialized,
    })
}

fn provider_response_guarded_suffix_bytes(
    max_stdout_line_bytes: usize,
    path: &str,
) -> Result<usize, ConfigCompileError> {
    max_stdout_line_bytes
        .checked_sub(
            PROCESS_PROVIDER_RESPONSE_PREFIX_BYTES + PROCESS_PROVIDER_RESPONSE_TERMINATOR_BYTES,
        )
        .ok_or_else(|| {
            ConfigCompileError::at(
                path,
                "cannot hold the fixed process-provider response prefix and terminator",
            )
        })
}

fn compact_provider_credential_allocation(
    output_count: usize,
    response_bytes: usize,
) -> Result<usize, ConfigCompileError> {
    let payload = output_count
        .checked_mul(MAX_PROVIDER_CREDENTIAL_BYTES)
        .map(|declared_bytes| declared_bytes.min(response_bytes))
        .ok_or_else(|| {
            ConfigCompileError::at(
                "authorization.providers",
                "provider credential storage arithmetic overflow",
            )
        })?;
    let payload = project_guarded_body_allocation(
        payload,
        "authorization.providers",
        "provider credential storage arithmetic overflow",
    )?;
    let metadata =
        projected_provider_credential_wire_metadata_bytes(output_count).ok_or_else(|| {
            ConfigCompileError::at(
                "authorization.providers",
                "provider credential metadata arithmetic overflow",
            )
        })?;
    payload.checked_add(metadata).ok_or_else(|| {
        ConfigCompileError::at(
            "authorization.providers",
            "provider credential storage arithmetic overflow",
        )
    })
}

fn compile_credential_finalization_peak(
    config: &super::authoring::AuthoringConfig,
    rule: Option<&PolicyRuleConfig>,
) -> Result<usize, ConfigCompileError> {
    if rule.is_some_and(|rule| matches!(rule.decision, RuleDecision::Deny))
        || rule.is_none()
            && matches!(
                config.policy.default,
                super::authoring::PolicyDefaultDecision::Deny
            )
    {
        return Ok(0);
    }

    let identity = SnapshotIdentity::new();
    let rule_index = rule
        .map(|rule| {
            config
                .policy
                .rules
                .iter()
                .position(|candidate| std::ptr::eq(candidate, rule))
                .or_else(|| {
                    config
                        .policy
                        .rules
                        .iter()
                        .position(|candidate| candidate.id == rule.id)
                })
                .ok_or_else(|| {
                    ConfigCompileError::at("policy.rules", "credential projection rule is missing")
                })
        })
        .transpose()?;
    let provider = rule
        .filter(|rule| matches!(rule.decision, RuleDecision::Delegate))
        .and_then(|rule| rule.authorization_provider.as_ref())
        .map(|name| {
            let ordinal = config
                .authorization
                .providers
                .keys()
                .position(|candidate| candidate == name)
                .ok_or_else(|| {
                    ConfigCompileError::at(
                        "policy.rules.authorization_provider",
                        "credential projection provider is missing",
                    )
                })?;
            let outputs = match config.authorization.providers.get(name) {
                Some(AuthorizationProviderConfig::Webhook(provider)) => &provider.outputs,
                Some(AuthorizationProviderConfig::Process(provider)) => &provider.outputs,
                Some(AuthorizationProviderConfig::UnixSocket(provider)) => &provider.outputs,
                None => {
                    return Err(ConfigCompileError::at(
                        "policy.rules.authorization_provider",
                        "credential projection provider is missing",
                    ))
                }
            };
            Ok((ordinal, outputs))
        })
        .transpose()?;

    let rule_count = rule.map_or(0, |rule| rule.credential_actions.len());
    let provider_count = provider.map_or(0, |(_, outputs)| outputs.len());
    let total = rule_count
        .checked_add(provider_count)
        .and_then(|count| count.checked_add(config.egress.credential_actions.len()))
        .ok_or_else(|| {
            ConfigCompileError::at("credentials", "credential projection count overflow")
        })?;
    if total == 0 {
        return Ok(0);
    }

    let mut descriptors = Vec::with_capacity(total);
    let mut mutations = Vec::with_capacity(total);
    let mut reference_literal_bytes = 0usize;
    let mut maximum_environment_staging_bytes = 0usize;

    if let (Some(rule), Some(rule_index)) = (rule, rule_index) {
        for (action_index, action) in rule.credential_actions.iter().enumerate() {
            let id = format!("rule/{rule_index}/credential/{action_index}");
            push_source_projection(
                config,
                action,
                &identity,
                &id,
                &mut descriptors,
                &mut mutations,
                &mut reference_literal_bytes,
                &mut maximum_environment_staging_bytes,
            )?;
        }
    }
    if let Some((provider_ordinal, outputs)) = provider {
        for (output_ordinal, output) in outputs.values().enumerate() {
            let id = format!("provider/{provider_ordinal}/output/{output_ordinal}");
            let reference = projection_credential_ref(&identity, &id)?;
            let mutation = projection_provider_mutation(output, reference)?;
            push_projection_descriptor(
                &identity,
                id.len(),
                mutation,
                credential_core::MAX_CREDENTIAL_MATERIAL_BYTES,
                0,
                &mut descriptors,
                &mut mutations,
                &mut reference_literal_bytes,
            )?;
        }
    }
    for (action_index, action) in config.egress.credential_actions.iter().enumerate() {
        let id = format!("global/credential/{action_index}");
        push_source_projection(
            config,
            action,
            &identity,
            &id,
            &mut descriptors,
            &mut mutations,
            &mut reference_literal_bytes,
            &mut maximum_environment_staging_bytes,
        )?;
    }

    let shared = project_credential_resources(
        &identity,
        CredentialProfile::StandaloneTrusted,
        &descriptors,
        &mutations,
        &ProductCredentialProjectionContext,
    )
    .map_err(|error| {
        let message = if error == credential_core::CredentialError::ResourceLimit {
            "shared credential resource limits are exceeded"
        } else {
            "shared credential projection is invalid"
        };
        ConfigCompileError::at("credentials", message)
    })?;
    let product = projected_product_adapter_bytes(
        total,
        reference_literal_bytes,
        maximum_environment_staging_bytes,
        rule_count != 0 || !config.egress.credential_actions.is_empty(),
        provider_count != 0,
    )
    .map_err(|_| {
        ConfigCompileError::at("credentials", "product credential projection is invalid")
    })?;
    let peak = shared
        .simultaneous_peak_bytes()
        .checked_add(product)
        .ok_or_else(|| {
            ConfigCompileError::at("credentials", "credential projection peak overflow")
        })?;
    usize::try_from(peak).map_err(|_| {
        ConfigCompileError::at("credentials", "credential projection cannot be represented")
    })
}

#[allow(clippy::too_many_arguments)]
fn push_source_projection(
    config: &super::authoring::AuthoringConfig,
    action: &CredentialActionConfig,
    identity: &SnapshotIdentity,
    id: &str,
    descriptors: &mut Vec<CredentialDescriptor>,
    mutations: &mut Vec<CredentialMutation>,
    reference_literal_bytes: &mut usize,
    maximum_environment_staging_bytes: &mut usize,
) -> Result<(), ConfigCompileError> {
    let source_name = match action {
        CredentialActionConfig::Bearer(action) => &action.credential,
        CredentialActionConfig::Basic(action) => &action.password_credential,
        CredentialActionConfig::CustomHeader(action) => &action.credential,
    };
    let staging = match config.credentials.sources.get(source_name) {
        Some(CredentialSourceConfig::Environment(_)) => {
            *maximum_environment_staging_bytes =
                (*maximum_environment_staging_bytes).max(MAX_CREDENTIAL_BYTES);
            MAX_CREDENTIAL_BYTES
        }
        Some(CredentialSourceConfig::File(_)) => MAX_FILE_READ_BYTES as usize,
        None => {
            return Err(ConfigCompileError::at(
                "credentials.sources",
                "credential projection source is missing",
            ))
        }
    };
    let reference = projection_credential_ref(identity, id)?;
    let mutation = projection_source_mutation(action, reference)?;
    push_projection_descriptor(
        identity,
        id.len(),
        mutation,
        MAX_CREDENTIAL_BYTES,
        staging,
        descriptors,
        mutations,
        reference_literal_bytes,
    )
}

#[allow(clippy::too_many_arguments)]
fn push_projection_descriptor(
    identity: &SnapshotIdentity,
    reference_literal_len: usize,
    mutation: CredentialMutation,
    maximum_material_bytes: usize,
    maximum_staging_bytes: usize,
    descriptors: &mut Vec<CredentialDescriptor>,
    mutations: &mut Vec<CredentialMutation>,
    reference_literal_bytes: &mut usize,
) -> Result<(), ConfigCompileError> {
    let purpose = match mutation.kind() {
        CredentialMutationKind::Bearer(_) => CredentialPurpose::Bearer,
        CredentialMutationKind::Basic { .. } => CredentialPurpose::BasicPassword,
        CredentialMutationKind::CustomHeader { name, .. } => {
            CredentialPurpose::CustomHeader(name.clone())
        }
    };
    let limits =
        CredentialLimits::new(maximum_material_bytes, maximum_staging_bytes).map_err(|_| {
            ConfigCompileError::at("credentials", "credential projection limits are invalid")
        })?;
    let descriptor = CredentialDescriptor::new(
        mutation.credential().clone(),
        purpose,
        CredentialProfile::StandaloneTrusted,
        limits,
    )
    .map_err(|_| {
        ConfigCompileError::at("credentials", "credential projection descriptor is invalid")
    })?;
    if !descriptor.reference().belongs_to(identity) {
        return Err(ConfigCompileError::at(
            "credentials",
            "credential projection reference is foreign",
        ));
    }
    *reference_literal_bytes = reference_literal_bytes
        .checked_add(reference_literal_len)
        .ok_or_else(|| {
            ConfigCompileError::at("credentials", "credential reference projection overflow")
        })?;
    descriptors.push(descriptor);
    mutations.push(mutation);
    Ok(())
}

fn projection_credential_ref(
    identity: &SnapshotIdentity,
    id: &str,
) -> Result<CredentialRef, ConfigCompileError> {
    let id = StableId::new(id.to_owned()).map_err(|_| {
        ConfigCompileError::at("credentials", "credential projection reference is invalid")
    })?;
    CredentialRef::new(identity.clone(), id, 1).map_err(|_| {
        ConfigCompileError::at("credentials", "credential projection reference is invalid")
    })
}

fn projection_source_mutation(
    action: &CredentialActionConfig,
    reference: CredentialRef,
) -> Result<CredentialMutation, ConfigCompileError> {
    match action {
        CredentialActionConfig::Bearer(_) => Ok(CredentialMutation::bearer(reference)),
        CredentialActionConfig::Basic(action) => {
            CredentialMutation::basic(action.username.clone(), reference)
                .map_err(|_| ConfigCompileError::at("credentials", "basic credential is invalid"))
        }
        CredentialActionConfig::CustomHeader(action) => CredentialMutation::custom_header(
            NeutralHeaderName::new(action.header.clone()).map_err(|_| {
                ConfigCompileError::at("credentials", "credential destination is invalid")
            })?,
            reference,
        )
        .map_err(|_| ConfigCompileError::at("credentials", "custom-header credential is invalid")),
    }
}

fn projection_provider_mutation(
    output: &super::authoring::ProviderOutputConfig,
    reference: CredentialRef,
) -> Result<CredentialMutation, ConfigCompileError> {
    match output {
        super::authoring::ProviderOutputConfig::Bearer(_) => {
            Ok(CredentialMutation::bearer(reference))
        }
        super::authoring::ProviderOutputConfig::Basic(output) => {
            CredentialMutation::basic(output.username.clone(), reference).map_err(|_| {
                ConfigCompileError::at(
                    "authorization.providers.outputs",
                    "provider basic credential is invalid",
                )
            })
        }
        super::authoring::ProviderOutputConfig::CustomHeader(output) => {
            CredentialMutation::custom_header(
                NeutralHeaderName::new(output.header.clone()).map_err(|_| {
                    ConfigCompileError::at(
                        "authorization.providers.outputs",
                        "provider credential destination is invalid",
                    )
                })?,
                reference,
            )
            .map_err(|_| {
                ConfigCompileError::at(
                    "authorization.providers.outputs",
                    "provider custom-header credential is invalid",
                )
            })
        }
    }
}

fn replacement_decode_peak(
    response_continuation_bytes: usize,
    max_decoded_replacement_bytes: usize,
) -> Result<usize, ConfigCompileError> {
    guarded_body_stage_peak(
        [
            response_continuation_bytes,
            max_decoded_replacement_bytes,
            PROVIDER_REPLACEMENT_STAGING_BYTES,
        ],
        "service",
        "provider replacement decode arithmetic overflow",
    )
}

fn decode_peak(encoded: usize, decoded: usize) -> Result<usize, ConfigCompileError> {
    let body_and_staging = guarded_body_stage_peak(
        [encoded, decoded, HTTP_DECODER_OUTPUT_STAGING_BYTES],
        "service",
        "mandatory body-plan arithmetic overflow",
    )?;
    let workspace = http_decoder_workspace_sizes()
        .and_then(|sizes| guarded_workspace_allocation_bytes(sizes.maximum()))
        .ok_or_else(|| {
            ConfigCompileError::at("service", "mandatory decoder workspace arithmetic overflow")
        })?;
    checked_add(
        body_and_staging,
        workspace,
        "service",
        "mandatory body-plan arithmetic overflow",
    )
}

fn compile_capture_working_set(
    config: &super::authoring::AuthoringConfig,
    redaction: &ProductRedactionPlan,
) -> Result<Option<CaptureWorkingSetPlan>, ConfigCompileError> {
    let Some(capture) = &config.observation.capture else {
        return Ok(None);
    };
    let profile = redaction
        .profiles
        .get(&capture.redaction_profile)
        .expect("capture profile references validated before capture compilation");
    let plan = capture_working_set_plan(
        profile.limits.max_body_bytes(),
        profile.limits.max_decoded_body_bytes(),
        profile.limits.max_message_bytes(),
        profile.limits.allow_permessage_deflate(),
        profile.projection.matcher_scratch_bytes(),
        profile.has_text_expressions,
        capture.max_body_bytes,
    )?;
    if plan.maximum_peak_bytes > capture.max_inflight_body_bytes {
        return Err(ConfigCompileError::at(
            "observation.capture.max_inflight_body_bytes",
            format!(
                "must hold one maximum capture operation of {} bytes",
                plan.maximum_peak_bytes
            ),
        ));
    }
    Ok(Some(plan))
}

fn capture_working_set_plan(
    max_encoded_bytes: usize,
    max_decoded_bytes: usize,
    max_message_bytes: usize,
    allow_permessage_deflate: bool,
    matcher_scratch_bytes: usize,
    has_text_expressions: bool,
    max_stored_body_bytes: usize,
) -> Result<CaptureWorkingSetPlan, ConfigCompileError> {
    const PATH: &str = "observation.capture.max_inflight_body_bytes";
    const OVERFLOW: &str = "capture working-set arithmetic overflow";

    let encoded = project_guarded_body_allocation(max_encoded_bytes, PATH, OVERFLOW)?;
    let decoded = project_guarded_body_allocation(max_decoded_bytes, PATH, OVERFLOW)?;
    let staging =
        project_guarded_body_allocation(HTTP_DECODER_OUTPUT_STAGING_BYTES, PATH, OVERFLOW)?;
    let workspace = http_decoder_workspace_sizes()
        .and_then(|sizes| guarded_workspace_allocation_bytes(sizes.maximum()))
        .ok_or_else(|| ConfigCompileError::at(PATH, OVERFLOW))?;
    let http_decode_peak = [encoded, decoded, staging, workspace]
        .into_iter()
        .try_fold(0usize, |peak, allocation| {
            checked_add(peak, allocation, PATH, OVERFLOW)
        })?;
    let message = project_guarded_body_allocation(max_message_bytes, PATH, OVERFLOW)?;
    let websocket_decode_peak = if allow_permessage_deflate {
        let deflate_scratch =
            project_guarded_body_allocation(WEBSOCKET_DEFLATE_SCRATCH_BYTES, PATH, OVERFLOW)?;
        checked_add(
            checked_add(message, message, PATH, OVERFLOW)?,
            deflate_scratch,
            PATH,
            OVERFLOW,
        )?
    } else {
        message
    };
    let decode_peak_bytes = http_decode_peak.max(websocket_decode_peak);

    let maximum_decoded = decoded.max(message);
    let literal_redaction_peak_bytes = checked_add(
        checked_add(maximum_decoded, matcher_scratch_bytes, PATH, OVERFLOW)?,
        maximum_decoded,
        PATH,
        OVERFLOW,
    )?;
    let expression_successor_peak_bytes = if has_text_expressions {
        checked_add(maximum_decoded, maximum_decoded, PATH, OVERFLOW)?
    } else {
        0
    };

    let stored_prefix_bytes = max_stored_body_bytes.min(max_decoded_bytes.max(max_message_bytes));
    let stored_prefix = project_guarded_body_allocation(stored_prefix_bytes, PATH, OVERFLOW)?;
    let padded_base64 = base64_encoded_len(stored_prefix_bytes, true)
        .ok_or_else(|| ConfigCompileError::at(PATH, OVERFLOW))?;
    let serialization_peak_bytes = checked_add(stored_prefix, padded_base64, PATH, OVERFLOW)?;
    let maximum_peak_bytes = decode_peak_bytes
        .max(literal_redaction_peak_bytes)
        .max(expression_successor_peak_bytes)
        .max(serialization_peak_bytes);

    Ok(CaptureWorkingSetPlan {
        decode_peak_bytes,
        literal_redaction_peak_bytes,
        expression_successor_peak_bytes,
        serialization_peak_bytes,
        maximum_peak_bytes,
    })
}

fn guarded_body_stage_peak<const N: usize>(
    payload_bytes: [usize; N],
    path: &str,
    message: &str,
) -> Result<usize, ConfigCompileError> {
    payload_bytes.into_iter().try_fold(0usize, |peak, bytes| {
        checked_add(
            peak,
            project_guarded_body_allocation(bytes, path, message)?,
            path,
            message,
        )
    })
}

fn project_guarded_body_allocation(
    payload_bytes: usize,
    path: &str,
    message: &str,
) -> Result<usize, ConfigCompileError> {
    guarded_body_allocation_bytes(payload_bytes)
        .ok_or_else(|| ConfigCompileError::at(path, message))
}

fn checked_add(
    left: usize,
    right: usize,
    path: &str,
    message: &str,
) -> Result<usize, ConfigCompileError> {
    left.checked_add(right)
        .ok_or_else(|| ConfigCompileError::at(path, message))
}

fn upgrade_wire_peak(
    max_message_bytes: usize,
    allow_permessage_deflate: bool,
    matcher_scratch_bytes: usize,
) -> Result<usize, ConfigCompileError> {
    let mut peak = max_message_bytes;
    if allow_permessage_deflate {
        peak = checked_add(
            peak,
            max_message_bytes,
            "redaction.profiles",
            "upgrade wire-body plan arithmetic overflow",
        )?;
        peak = checked_add(
            peak,
            WEBSOCKET_DEFLATE_SCRATCH_BYTES,
            "redaction.profiles",
            "upgrade wire-body plan arithmetic overflow",
        )?;
    }
    for allocation in [max_message_bytes, matcher_scratch_bytes, max_message_bytes] {
        peak = checked_add(
            peak,
            allocation,
            "redaction.profiles",
            "upgrade wire-body plan arithmetic overflow",
        )?;
    }
    Ok(peak)
}

fn compile_reloadable_plan(
    config: &super::authoring::AuthoringConfig,
    working_directory: &Path,
    endpoint_urls: &CanonicalEndpointUrls,
    compiled_urls_by_rule: Vec<Vec<CompiledUrlPattern>>,
    capture_sink: Option<CaptureSinkSpec>,
    resource_plan: CompiledResourcePlan,
    redaction: ProductRedactionPlan,
) -> Result<ReloadableProductPlan, ConfigCompileError> {
    let http_body_read_plans_by_cursor = compile_http_body_read_plans(config)?.published_by_cursor;
    let capture_working_set = compile_capture_working_set(config, &redaction)?;
    Ok(ReloadableProductPlan {
        request_timeout: config.service.request_timeout.get(),
        max_content_decoding_expansion_ratio: config.service.max_content_decoding_expansion_ratio,
        forwarding: compile_forwarding_plan(&config.service.forwarding),
        identity: compile_identity_plan(config.identity.as_ref())?,
        identity_connection_capacity: HttpConnectionAuthenticationCapacity::new(
            config.identity.as_ref().map_or(1, |identity| {
                identity.max_pending_authentications_per_connection
            }),
        )
        .expect("identity connection capacity was validated"),
        egress: compile_egress_plan(&config.egress, endpoint_urls.parent_proxy.as_ref())?,
        policy: compile_policy_plan(
            &config.policy,
            compiled_urls_by_rule,
            http_body_read_plans_by_cursor,
        )?,
        authorization: compile_authorization_plan(
            &config.authorization,
            working_directory,
            &endpoint_urls.webhooks,
            &identity_environment_sources(config),
        )?,
        credentials: compile_credentials_plan(&config.credentials)?,
        redaction,
        observation: compile_observation_plan(
            &config.observation,
            capture_sink,
            capture_working_set,
        )?,
        safety: compile_safety_plan(&config.safety)?,
        resource_plan,
    })
}

fn compile_identity_plan(
    value: Option<&super::authoring::IdentityConfig>,
) -> Result<Option<IdentityPlan>, ConfigCompileError> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value.resolver.kind {
        super::authoring::StaticIdentityResolverKind::Static => {}
    }
    let principals = value
        .resolver
        .principals
        .iter()
        .map(|principal| {
            Ok(IdentityPrincipalPlan {
                id: PrincipalId::new(principal.id.clone()).map_err(|error| {
                    ConfigCompileError::at("identity.resolver.principals", error.to_string())
                })?,
                kind: match principal.kind {
                    IdentityPrincipalKindConfig::User => PrincipalKind::User,
                    IdentityPrincipalKindConfig::ServiceAccount => PrincipalKind::ServiceAccount,
                    IdentityPrincipalKindConfig::System => PrincipalKind::System,
                },
            })
        })
        .collect::<Result<Vec<_>, ConfigCompileError>>()?;
    let groups = value
        .resolver
        .groups
        .iter()
        .map(|group| {
            Ok(IdentityGroupPlan {
                id: GroupId::new(group.id.clone()).map_err(|error| {
                    ConfigCompileError::at("identity.resolver.groups", error.to_string())
                })?,
                members: group
                    .members
                    .iter()
                    .map(|member| {
                        PrincipalId::new(member.clone()).map_err(|error| {
                            ConfigCompileError::at(
                                "identity.resolver.groups.members",
                                error.to_string(),
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            })
        })
        .collect::<Result<Vec<_>, ConfigCompileError>>()?;
    let tokens = value
        .resolver
        .tokens
        .iter()
        .map(|token| {
            let (id, principal, source) = match token {
                super::authoring::StaticIdentityTokenConfig::Environment {
                    id,
                    principal,
                    variable,
                } => (
                    id,
                    principal,
                    IdentitySourcePlan::Environment {
                        variable: variable.clone(),
                    },
                ),
                super::authoring::StaticIdentityTokenConfig::File {
                    id,
                    principal,
                    path,
                } => (
                    id,
                    principal,
                    IdentitySourcePlan::File { path: path.clone() },
                ),
            };
            Ok(IdentityTokenPlan {
                id: TokenId::new(id.clone()).map_err(|error| {
                    ConfigCompileError::at("identity.resolver.tokens", error.to_string())
                })?,
                principal: PrincipalId::new(principal.clone()).map_err(|error| {
                    ConfigCompileError::at("identity.resolver.tokens", error.to_string())
                })?,
                source,
            })
        })
        .collect::<Result<Vec<_>, ConfigCompileError>>()?;
    let authority = AuthorityId::new(value.resolver.authority.clone()).map_err(|error| {
        ConfigCompileError::at("identity.resolver.authority", error.to_string())
    })?;
    let audience = IdentityAudience::new("acl-proxy.identity")
        .map_err(|error| ConfigCompileError::at("identity.resolver", error.to_string()))?;
    let resources =
        project_identity_resources(&authority, &audience, &principals, &groups, &tokens)?;
    Ok(Some(IdentityPlan {
        max_pending_authentications: value.max_pending_authentications,
        authority,
        audience,
        resources,
        principals,
        groups,
        tokens,
    }))
}

fn project_identity_resources(
    authority: &AuthorityId,
    audience: &IdentityAudience,
    principals: &[IdentityPrincipalPlan],
    groups: &[IdentityGroupPlan],
    tokens: &[IdentityTokenPlan],
) -> Result<access_identity::ResourceProjection, ConfigCompileError> {
    let principals = principals
        .iter()
        .map(|principal| StaticPrincipal {
            id: principal.id.clone(),
            kind: principal.kind,
        })
        .collect::<Vec<_>>();
    let groups = groups
        .iter()
        .map(|group| StaticGroup {
            id: group.id.clone(),
            members: group.members.clone().into_boxed_slice(),
        })
        .collect::<Vec<_>>();
    let token_principals = tokens
        .iter()
        .map(|token| token.principal.clone())
        .collect::<Vec<_>>();
    project_static_resolver_resources(authority, audience, &principals, &groups, &token_principals)
        .map_err(|error| {
            ConfigCompileError::at(
                "identity.resolver",
                format!("identity resource projection failed: {error}"),
            )
        })
}

#[cfg(test)]
pub(crate) fn project_identity_resources_for_test(
    authority: &AuthorityId,
    principals: &[IdentityPrincipalPlan],
    groups: &[IdentityGroupPlan],
    tokens: &[IdentityTokenPlan],
) -> access_identity::ResourceProjection {
    let audience = IdentityAudience::new("acl-proxy.identity")
        .expect("the product identity audience is a checked constant");
    project_identity_resources(authority, &audience, principals, groups, tokens)
        .expect("checked identity test metadata projects")
}

fn compile_forwarding_plan(value: &super::authoring::ForwardingConfig) -> ForwardingPlan {
    ForwardingPlan {
        connect_timeout: value.connect_timeout.get(),
        response_head_timeout: value.response_head_timeout.get(),
        body_idle_timeout: value.body_idle_timeout.get(),
        upgrade_idle_timeout: value.upgrade_idle_timeout.get(),
        max_request_wire_bytes: value.max_request_wire_bytes,
        max_request_decoded_bytes: value.max_request_decoded_bytes,
        max_response_wire_bytes: value.max_response_wire_bytes,
        max_response_decoded_bytes: value.max_response_decoded_bytes,
        chunk_bytes: value.chunk_bytes,
        preserve_request_trailers: value.preserve_request_trailers,
        max_trailer_count: value.max_trailer_count,
        max_trailer_bytes: value.max_trailer_bytes,
    }
}

fn compile_egress_plan(
    value: &EgressConfig,
    parent_target: Option<&CanonicalUrl>,
) -> Result<EgressPlan, ConfigCompileError> {
    Ok(EgressPlan {
        route: match value.route {
            EgressRoute::Direct => CompiledEgressRoute::Direct,
            EgressRoute::ParentProxy => CompiledEgressRoute::ParentProxy,
        },
        origin_tls: compile_transport_tls_plan(&value.origin_tls),
        parent_proxy: match (&value.parent_proxy, parent_target) {
            (Some(parent), Some(target)) => Some(compile_parent_proxy_plan(parent, target)),
            (None, None) => None,
            _ => {
                return Err(ConfigCompileError::at(
                    "egress.parent_proxy.url",
                    "canonical parent URL does not match the authored configuration",
                ));
            }
        },
        request_headers: compile_header_effects(&value.request_headers, "egress.request_headers")?,
        credential_actions: compile_credential_actions(
            &value.credential_actions,
            "egress.credential_actions",
        )?,
    })
}

fn compile_transport_tls_plan(value: &TransportTlsConfig) -> TransportTlsPlan {
    TransportTlsPlan {
        trust: compile_tls_trust(value.trust),
        ca_certificate: value.ca_certificate.clone(),
        http_versions: compile_http_versions(&value.http_versions),
    }
}

fn compile_tls_trust(value: TlsTrust) -> CompiledTlsTrust {
    match value {
        TlsTrust::System => CompiledTlsTrust::System,
        TlsTrust::Custom => CompiledTlsTrust::Custom,
        TlsTrust::SystemPlusCustom => CompiledTlsTrust::SystemPlusCustom,
        TlsTrust::Insecure => CompiledTlsTrust::Insecure,
    }
}

fn compile_parent_proxy_plan(
    value: &super::authoring::ParentProxyConfig,
    target: &CanonicalUrl,
) -> ParentProxyPlan {
    ParentProxyPlan {
        kind: match value.kind {
            ParentProxyKind::AclProxy => CompiledParentProxyKind::AclProxy,
            ParentProxyKind::Generic => CompiledParentProxyKind::Generic,
        },
        target: target.clone(),
        tls: value.tls.as_ref().map(|tls| ParentProxyTlsPlan {
            trust: compile_tls_trust(tls.trust),
            ca_certificate: tls.ca_certificate.clone(),
            server_name: tls
                .server_name
                .clone()
                .unwrap_or_else(|| target.authority().host().as_str().to_owned()),
        }),
        presentation: value
            .presentation
            .as_ref()
            .map(|presentation| match presentation {
                ParentProxyPresentationConfig::BearerEnvironment { variable } => {
                    IdentitySourcePlan::Environment {
                        variable: variable.clone(),
                    }
                }
                ParentProxyPresentationConfig::BearerFile { path } => {
                    IdentitySourcePlan::File { path: path.clone() }
                }
            }),
    }
}

fn compile_policy_plan(
    value: &PolicyConfig,
    compiled_urls_by_rule: Vec<Vec<CompiledUrlPattern>>,
    http_body_read_plans_by_cursor: Vec<HttpBodyReadPlan>,
) -> Result<PolicyPlan, ConfigCompileError> {
    if compiled_urls_by_rule.len() != value.rules.len() {
        return Err(ConfigCompileError::at(
            "policy.rules",
            "compiled URL rule count does not match the authored rule count",
        ));
    }
    let rules = value
        .rules
        .iter()
        .zip(compiled_urls_by_rule)
        .enumerate()
        .map(|(index, (rule, urls))| compile_policy_rule_plan(rule, urls, index))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PolicyPlan {
        default: match value.default {
            super::authoring::PolicyDefaultDecision::Allow => CompiledDefaultDecision::Allow,
            super::authoring::PolicyDefaultDecision::Deny => CompiledDefaultDecision::Deny,
        },
        rules,
        http_body_read_plans_by_cursor,
    })
}

fn compile_policy_rule_plan(
    value: &PolicyRuleConfig,
    urls: Vec<CompiledUrlPattern>,
    index: usize,
) -> Result<PolicyRulePlan, ConfigCompileError> {
    let prefix = format!("policy.rules[{index}]");
    Ok(PolicyRulePlan {
        id: value.id.clone(),
        description: value.description.clone(),
        decision: match value.decision {
            RuleDecision::Allow => CompiledRuleDecision::Allow,
            RuleDecision::Deny => CompiledRuleDecision::Deny,
            RuleDecision::Delegate => CompiledRuleDecision::Delegate,
        },
        urls,
        methods: value
            .methods
            .iter()
            .enumerate()
            .map(|(method_index, method)| {
                Method::from_bytes(method.to_ascii_uppercase().as_bytes()).map_err(|error| {
                    ConfigCompileError::at(
                        format!("{prefix}.methods[{method_index}]"),
                        format!("invalid method after validation: {error}"),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        client_cidrs: compile_client_cidrs(&value.client_cidrs, &format!("{prefix}.client_cidrs"))?,
        identity: compile_identity_predicate_plan(value, &prefix)?,
        headers: compile_header_predicates_plan(&value.headers, &prefix)?,
        request_timeout: value.request_timeout.as_ref().map(|timeout| timeout.get()),
        allow_upgrades: value.allow_upgrades,
        authorization_provider: value.authorization_provider.clone(),
        redaction_profile: value.redaction_profile.clone(),
        request_headers: compile_header_effects(
            &value.request_headers,
            &format!("{prefix}.request_headers"),
        )?,
        response_headers: compile_header_effects(
            &value.response_headers,
            &format!("{prefix}.response_headers"),
        )?,
        credential_actions: compile_credential_actions(
            &value.credential_actions,
            &format!("{prefix}.credential_actions"),
        )?,
    })
}

fn compile_identity_predicate_plan(
    value: &PolicyRuleConfig,
    prefix: &str,
) -> Result<Option<IdentityPredicatePlan>, ConfigCompileError> {
    let Some(authored_states) = &value.identity_states else {
        return Ok(None);
    };
    let mut states = authored_states
        .iter()
        .map(|state| match state {
            IdentityStateConfig::Disabled => IdentityState::Disabled,
            IdentityStateConfig::Anonymous => IdentityState::Anonymous,
            IdentityStateConfig::Authenticated => IdentityState::Authenticated,
        })
        .collect::<Vec<_>>();
    states.sort_by_key(|state| match state {
        IdentityState::Disabled => 0_u8,
        IdentityState::Anonymous => 1,
        IdentityState::Authenticated => 2,
    });

    let mut subjects = value
        .identity_subjects
        .as_deref()
        .unwrap_or_default()
        .iter()
        .enumerate()
        .map(|(index, subject)| {
            let path = format!("{prefix}.identity_subjects[{index}]");
            match subject {
                IdentitySubjectConfig::Principal { authority, id } => {
                    Ok(IdentitySubject::Principal {
                        authority: AuthorityId::new(authority.clone()).map_err(|error| {
                            ConfigCompileError::at(format!("{path}.authority"), error.to_string())
                        })?,
                        id: PrincipalId::new(id.clone()).map_err(|error| {
                            ConfigCompileError::at(format!("{path}.id"), error.to_string())
                        })?,
                    })
                }
                IdentitySubjectConfig::Group { authority, id } => Ok(IdentitySubject::Group {
                    authority: AuthorityId::new(authority.clone()).map_err(|error| {
                        ConfigCompileError::at(format!("{path}.authority"), error.to_string())
                    })?,
                    id: GroupId::new(id.clone()).map_err(|error| {
                        ConfigCompileError::at(format!("{path}.id"), error.to_string())
                    })?,
                }),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    subjects.sort();
    Ok(Some(IdentityPredicatePlan { states, subjects }))
}

/// Policy peers canonicalize IPv4-mapped socket addresses to IPv4. Authored
/// CIDRs wholly inside the mapped `/96` follow the same representation. A
/// broader IPv6 CIDR containing mapped space is rejected because it mixes
/// canonical IPv4 peers with native IPv6 addresses under one authored range.
fn compile_client_cidrs(
    values: &[ipnet::IpNet],
    path: &str,
) -> Result<Vec<ipnet::IpNet>, ConfigCompileError> {
    let mapped_base = std::net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped();
    values
        .iter()
        .enumerate()
        .map(|(index, network)| match network {
            ipnet::IpNet::V4(network) => Ok(ipnet::IpNet::V4(*network)),
            ipnet::IpNet::V6(network) => {
                if network.prefix_len() < 96 && network.contains(&mapped_base) {
                    return Err(ConfigCompileError::at(
                        format!("{path}[{index}]"),
                        "IPv6 CIDR ambiguously mixes mapped IPv4 and native IPv6 addresses",
                    ));
                }
                let Some(mapped) = network.network().to_ipv4_mapped() else {
                    return Ok(ipnet::IpNet::V6(*network));
                };
                let prefix = network.prefix_len().checked_sub(96).ok_or_else(|| {
                    ConfigCompileError::at(
                        format!("{path}[{index}]"),
                        "invalid mapped IPv4 CIDR prefix",
                    )
                })?;
                let canonical = ipnet::Ipv4Net::new(mapped, prefix).map_err(|_| {
                    ConfigCompileError::at(format!("{path}[{index}]"), "invalid mapped IPv4 CIDR")
                })?;
                Ok(ipnet::IpNet::V4(canonical))
            }
        })
        .collect()
}

fn compile_header_predicates_plan(
    value: &super::authoring::HeaderPredicatesConfig,
    prefix: &str,
) -> Result<HeaderPredicatesPlan, ConfigCompileError> {
    Ok(HeaderPredicatesPlan {
        absent_any: compile_header_names(
            &value.absent_any,
            &format!("{prefix}.headers.absent_any"),
        )?,
        present_all: compile_header_names(
            &value.present_all,
            &format!("{prefix}.headers.present_all"),
        )?,
        all: compile_header_value_predicates(&value.all, &format!("{prefix}.headers.all"))?,
        none: compile_header_value_predicates(&value.none, &format!("{prefix}.headers.none"))?,
    })
}

fn compile_header_value_predicates(
    values: &BTreeMap<String, Vec<String>>,
    path: &str,
) -> Result<Vec<HeaderValuePredicatePlan>, ConfigCompileError> {
    values
        .iter()
        .map(|(name, values)| {
            Ok(HeaderValuePredicatePlan {
                name: compile_header_name(name, path)?,
                values: values
                    .iter()
                    .map(|value| {
                        HeaderValue::from_bytes(value.as_bytes()).map_err(|error| {
                            ConfigCompileError::at(
                                path,
                                format!("invalid header value after validation: {error}"),
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            })
        })
        .collect()
}

fn compile_header_effects(
    values: &[HeaderEffectConfig],
    path: &str,
) -> Result<Vec<HeaderEffectPlan>, ConfigCompileError> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| compile_header_effect(value, &format!("{path}[{index}]")))
        .collect()
}

fn compile_header_effect(
    value: &HeaderEffectConfig,
    path: &str,
) -> Result<HeaderEffectPlan, ConfigCompileError> {
    match value {
        HeaderEffectConfig::Set(value) => Ok(HeaderEffectPlan::Set {
            when: compile_header_effect_when(value.when),
            name: compile_header_name(&value.name, path)?,
            values: compile_header_values(
                value.value.iter().chain(value.values.iter().flatten()),
                path,
            )?,
        }),
        HeaderEffectConfig::Append(value) => Ok(HeaderEffectPlan::Append {
            when: compile_header_effect_when(value.when),
            name: compile_header_name(&value.name, path)?,
            values: compile_header_values(
                value.value.iter().chain(value.values.iter().flatten()),
                path,
            )?,
        }),
        HeaderEffectConfig::Remove(value) => Ok(HeaderEffectPlan::Remove {
            when: compile_header_effect_when(value.when),
            name: compile_header_name(&value.name, path)?,
        }),
        HeaderEffectConfig::Replace(value) => Ok(HeaderEffectPlan::Replace {
            when: compile_header_effect_when(value.when),
            name: compile_header_name(&value.name, path)?,
            search: value.search.clone(),
            replace: value.replace.clone(),
        }),
    }
}

fn compile_header_values<'a>(
    values: impl Iterator<Item = &'a String>,
    path: &str,
) -> Result<Vec<HeaderValue>, ConfigCompileError> {
    values
        .map(|value| {
            HeaderValue::from_bytes(value.as_bytes()).map_err(|error| {
                ConfigCompileError::at(
                    path,
                    format!("invalid header value after validation: {error}"),
                )
            })
        })
        .collect()
}

fn compile_header_effect_when(value: HeaderEffectWhen) -> CompiledHeaderEffectWhen {
    match value {
        HeaderEffectWhen::Always => CompiledHeaderEffectWhen::Always,
        HeaderEffectWhen::IfPresent => CompiledHeaderEffectWhen::IfPresent,
        HeaderEffectWhen::IfAbsent => CompiledHeaderEffectWhen::IfAbsent,
    }
}

fn compile_credential_actions(
    values: &[CredentialActionConfig],
    path: &str,
) -> Result<Vec<CredentialActionPlan>, ConfigCompileError> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            Ok(match value {
                CredentialActionConfig::Bearer(value) => CredentialActionPlan::Bearer {
                    credential: value.credential.clone(),
                    transport_security: compile_transport_security(value.transport_security),
                },
                CredentialActionConfig::Basic(value) => CredentialActionPlan::Basic {
                    username: value.username.clone(),
                    password_credential: value.password_credential.clone(),
                    transport_security: compile_transport_security(value.transport_security),
                },
                CredentialActionConfig::CustomHeader(value) => CredentialActionPlan::CustomHeader {
                    header: compile_header_name(&value.header, &format!("{path}[{index}].header"))?,
                    credential: value.credential.clone(),
                    transport_security: compile_transport_security(value.transport_security),
                },
            })
        })
        .collect()
}

fn compile_authorization_plan(
    value: &AuthorizationConfig,
    working_directory: &Path,
    webhook_urls: &BTreeMap<String, CanonicalUrl>,
    blocked_environment: &BTreeSet<String>,
) -> Result<AuthorizationPlan, ConfigCompileError> {
    let providers = value
        .providers
        .iter()
        .map(|(name, provider)| {
            compile_provider_plan(
                name,
                provider,
                working_directory,
                webhook_urls,
                blocked_environment,
            )
            .map(|provider| (name.clone(), provider))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok(AuthorizationPlan {
        internal_context_headers: compile_header_names(
            &value.internal_context_headers,
            "authorization.internal_context_headers",
        )?,
        callback: value
            .callback
            .as_ref()
            .map(|callback| AuthorizationCallbackPlan {
                resume_token_ttl: callback.resume_token_ttl.get(),
                max_pending_operations: PendingOperationLimit::try_new(
                    callback.max_pending_operations,
                )
                .expect("callback pending-operation limit was validated before compilation"),
            }),
        providers,
    })
}

fn compile_provider_plan(
    name: &str,
    value: &AuthorizationProviderConfig,
    working_directory: &Path,
    webhook_urls: &BTreeMap<String, CanonicalUrl>,
    blocked_environment: &BTreeSet<String>,
) -> Result<AuthorizationProviderPlan, ConfigCompileError> {
    let prefix = format!("authorization.providers.{name}");
    Ok(match value {
        AuthorizationProviderConfig::Webhook(value) => {
            let url = webhook_urls.get(name).ok_or_else(|| {
                ConfigCompileError::at(format!("{prefix}.url"), "canonical webhook URL is missing")
            })?;
            AuthorizationProviderPlan::Webhook(WebhookProviderPlan {
                url: url.clone(),
                timeout: value.timeout.get(),
                on_failure: compile_provider_failure(value.on_failure),
                include_headers: compile_header_names(
                    &value.include_headers,
                    &format!("{prefix}.include_headers"),
                )?,
                include_identity: value.include_identity,
                max_request_bytes: value.max_request_bytes,
                max_response_bytes: value.max_response_bytes,
                outputs: compile_provider_outputs(&value.outputs, &format!("{prefix}.outputs"))?,
                tls: value.tls.as_ref().map(|tls| WebhookTlsPlan {
                    trust: compile_tls_trust(tls.trust),
                    ca_certificate: tls.ca_certificate.clone(),
                }),
            })
        }
        AuthorizationProviderConfig::Process(value) => {
            AuthorizationProviderPlan::Process(ProcessProviderPlan {
                command: value.command.clone(),
                working_directory: working_directory.to_path_buf(),
                args: value.args.clone(),
                timeout: value.timeout.get(),
                on_failure: compile_provider_failure(value.on_failure),
                inherit_environment: value.inherit_environment,
                pass_environment: value.pass_environment.clone(),
                environment: value.environment.clone(),
                blocked_environment: blocked_environment.iter().cloned().collect(),
                include_headers: compile_header_names(
                    &value.include_headers,
                    &format!("{prefix}.include_headers"),
                )?,
                include_identity: value.include_identity,
                include_request_body: value.include_request_body,
                allow_request_body_replacement: value.allow_request_body_replacement,
                max_request_body_bytes: value.max_request_body_bytes,
                max_decoded_request_body_bytes: value.max_decoded_request_body_bytes,
                max_stdout_line_bytes: value.max_stdout_line_bytes,
                max_pending_requests: value.max_pending_requests,
                restart_backoff: value.restart_backoff.get(),
                retire_timeout: value.retire_timeout.get(),
                outputs: compile_provider_outputs(&value.outputs, &format!("{prefix}.outputs"))?,
            })
        }
        AuthorizationProviderConfig::UnixSocket(value) => {
            let projection = compile_unix_provider_projection(name, value)?;
            AuthorizationProviderPlan::UnixSocket(UnixSocketProviderPlan {
                socket_path: value.socket_path.clone(),
                timeout: value.timeout.get(),
                on_failure: compile_provider_failure(value.on_failure),
                include_headers: compile_header_names(
                    &value.include_headers,
                    &format!("{prefix}.include_headers"),
                )?,
                include_identity: value.include_identity,
                frame_protocol: projection.frame_protocol,
                request_frame_bytes: projection.request_frame_bytes,
                response_frame_bytes: projection.response_frame_bytes,
                request_allocation_bytes: projection.request_allocation_bytes,
                response_allocation_bytes: projection.response_allocation_bytes,
                max_pending_requests: value.max_pending_requests,
                max_inflight_allocation_bytes: projection.max_inflight_allocation_bytes,
                peer_uid: value.peer_uid,
                outputs: compile_provider_outputs(&value.outputs, &format!("{prefix}.outputs"))?,
            })
        }
    })
}

fn compile_provider_failure(
    value: super::authoring::ProviderFailureMode,
) -> CompiledProviderFailureMode {
    match value {
        super::authoring::ProviderFailureMode::Deny => CompiledProviderFailureMode::Deny,
        super::authoring::ProviderFailureMode::Error => CompiledProviderFailureMode::Error,
    }
}

fn compile_transport_security(value: TransportSecurity) -> CompiledTransportSecurity {
    match value {
        TransportSecurity::TlsRequired => CompiledTransportSecurity::TlsRequired,
        TransportSecurity::CleartextAllowed => CompiledTransportSecurity::CleartextAllowed,
    }
}

fn compile_provider_outputs(
    values: &BTreeMap<String, super::authoring::ProviderOutputConfig>,
    path: &str,
) -> Result<BTreeMap<String, ProviderOutputPlan>, ConfigCompileError> {
    values
        .iter()
        .map(|(name, value)| {
            let output = match value {
                super::authoring::ProviderOutputConfig::Bearer(value) => {
                    ProviderOutputPlan::Bearer {
                        required: value.required,
                        transport_security: compile_transport_security(value.transport_security),
                    }
                }
                super::authoring::ProviderOutputConfig::Basic(value) => ProviderOutputPlan::Basic {
                    username: value.username.clone(),
                    required: value.required,
                    transport_security: compile_transport_security(value.transport_security),
                },
                super::authoring::ProviderOutputConfig::CustomHeader(value) => {
                    ProviderOutputPlan::CustomHeader {
                        header: compile_header_name(
                            &value.header,
                            &format!("{path}.{name}.header"),
                        )?,
                        required: value.required,
                        transport_security: compile_transport_security(value.transport_security),
                    }
                }
            };
            Ok((name.clone(), output))
        })
        .collect()
}

fn compile_credentials_plan(
    value: &CredentialsConfig,
) -> Result<CredentialsPlan, ConfigCompileError> {
    let inbound = value
        .inbound
        .iter()
        .map(|(name, value)| {
            Ok((
                name.clone(),
                InboundCredentialPlan {
                    header: compile_header_name(
                        &value.header,
                        &format!("credentials.inbound.{name}.header"),
                    )?,
                    process_providers: value.process_providers.clone(),
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>, ConfigCompileError>>()?;
    let sources = value
        .sources
        .iter()
        .map(|(name, value)| {
            let source = match value {
                CredentialSourceConfig::Environment(value) => CredentialSourcePlan::Environment {
                    variable: value.variable.clone(),
                },
                CredentialSourceConfig::File(value) => CredentialSourcePlan::File {
                    path: value.path.clone(),
                },
            };
            (name.clone(), source)
        })
        .collect();
    Ok(CredentialsPlan { inbound, sources })
}

fn compile_redaction_plan(
    value: &RedactionConfig,
) -> Result<ProductRedactionPlan, ConfigCompileError> {
    let mut specs = Vec::new();
    specs.try_reserve_exact(value.profiles.len()).map_err(|_| {
        ConfigCompileError::at(
            "redaction.profiles",
            "redaction preparation allocation failed",
        )
    })?;
    let mut profile_metadata = Vec::new();
    let mut sources = Vec::new();

    for (profile_index, (name, profile)) in value.profiles.iter().enumerate() {
        let prefix = format!("redaction.profiles.{name}");
        let id = StableId::new(name.clone())
            .map_err(|_| ConfigCompileError::at(&prefix, "invalid redaction profile name"))?;
        let limits = RedactionLimits::new(
            profile.max_body_bytes,
            profile.max_decoded_body_bytes,
            profile.max_frame_bytes,
            profile.max_message_bytes,
            profile.allow_permessage_deflate,
            profile.max_environment_literal_sources,
            profile.max_environment_literal_bytes,
            profile.max_environment_literal_total_bytes,
        )
        .map_err(|error| ConfigCompileError::at(&prefix, error.to_string()))?
        .with_unsupported_websocket_extensions(match profile.unsupported_extensions {
            UnsupportedExtensions::Deny => UnsupportedWebSocketExtensions::Deny,
            UnsupportedExtensions::Strip => UnsupportedWebSocketExtensions::Strip,
        });
        let mut rules = Vec::new();
        rules.try_reserve_exact(profile.rules.len()).map_err(|_| {
            ConfigCompileError::at(&prefix, "redaction preparation allocation failed")
        })?;
        for (rule_index, rule) in profile.rules.iter().enumerate() {
            let mut slots = Vec::new();
            slots
                .try_reserve_exact(rule.literal_environment_variables.len())
                .map_err(|_| {
                    ConfigCompileError::at(
                        format!("{prefix}.rules[{rule_index}]"),
                        "redaction preparation allocation failed",
                    )
                })?;
            for (source_index, variable) in rule.literal_environment_variables.iter().enumerate() {
                let slot = ExternalLiteralSlot::new();
                slots.push(slot.clone());
                sources.push(ProductExternalLiteralSource {
                    slot,
                    variable: variable.clone(),
                    profile: profile_index,
                    rule: rule_index,
                    source_index,
                    max_bytes: profile.max_environment_literal_bytes,
                });
            }
            rules.push(RedactionRuleSpec::new(
                rule.literals
                    .iter()
                    .map(|literal| literal.as_bytes().to_vec())
                    .collect(),
                slots,
                rule.expressions.clone(),
                match rule.payloads {
                    RedactionPayloads::Text => RulePayloads::Text,
                    RedactionPayloads::Binary => RulePayloads::Binary,
                    RedactionPayloads::Both => RulePayloads::Both,
                },
            ));
        }
        let has_text_expressions = profile.rules.iter().any(|rule| {
            !rule.expressions.is_empty() && !matches!(rule.payloads, RedactionPayloads::Binary)
        });
        profile_metadata.push((name.clone(), id.clone(), limits, has_text_expressions));
        specs.push(RedactionProfileSpec::new(
            id,
            profile.replacement.as_bytes().to_vec(),
            limits,
            rules,
        ));
    }

    let prepared = PreparedRedactionSnapshot::prepare(RedactionSnapshotSpec::new(specs), || false)
        .map_err(|error| {
            let profile_name = value
                .profiles
                .keys()
                .nth(error.profile)
                .map(String::as_str)
                .unwrap_or("<invalid>");
            let mut path = format!("redaction.profiles.{profile_name}");
            if let Some(rule) = error.rule {
                path.push_str(&format!(".rules[{rule}]"));
            }
            if let Some(item) = error.item {
                let collection = if matches!(
                    error.kind,
                    http_access_redaction::PrepareErrorKind::InvalidExpression
                ) {
                    "expressions"
                } else {
                    "literals"
                };
                path.push_str(&format!(".{collection}[{item}]"));
            }
            ConfigCompileError::at(path, error.kind.to_string())
        })?;
    let profiles = profile_metadata
        .into_iter()
        .map(|(name, id, limits, has_text_expressions)| {
            let projection = prepared
                .profile_projection(&id)
                .expect("prepared metadata contains every authored profile");
            (
                name,
                ProductRedactionProfile {
                    limits,
                    projection,
                    has_text_expressions,
                },
            )
        })
        .collect();

    Ok(ProductRedactionPlan {
        profiles,
        prepared,
        sources,
    })
}

fn compile_observation_plan(
    value: &ObservationConfig,
    capture_sink: Option<CaptureSinkSpec>,
    capture_working_set: Option<CaptureWorkingSetPlan>,
) -> Result<ObservationPlan, ConfigCompileError> {
    let capture = match (value.capture.as_ref(), capture_sink, capture_working_set) {
        (Some(value), Some(sink), Some(working_set)) => {
            Some(compile_capture_plan(value, sink, working_set))
        }
        (None, None, None) => None,
        _ => {
            return Err(ConfigCompileError::at(
                "observation.capture",
                "validated capture plan is inconsistent",
            ));
        }
    };
    Ok(ObservationPlan {
        logging: ReloadableLoggingPlan {
            level: compile_log_level(&value.logging.level, "observation.logging.level")?,
            policy_decisions: PolicyDecisionLoggingPlan {
                allows: value.logging.policy_decisions.allows,
                denies: value.logging.policy_decisions.denies,
                allow_level: compile_decision_log_level(
                    &value.logging.policy_decisions.allow_level,
                    "observation.logging.policy_decisions.allow_level",
                )?,
                deny_level: compile_decision_log_level(
                    &value.logging.policy_decisions.deny_level,
                    "observation.logging.policy_decisions.deny_level",
                )?,
            },
        },
        capture,
    })
}

fn compile_decision_log_level(
    value: &str,
    path: &str,
) -> Result<CompiledDecisionLogLevel, ConfigCompileError> {
    match value {
        "info" => Ok(CompiledDecisionLogLevel::Info),
        "warn" => Ok(CompiledDecisionLogLevel::Warn),
        _ => Err(ConfigCompileError::at(path, "must be info or warn")),
    }
}

fn compile_log_level(value: &str, path: &str) -> Result<CompiledLogLevel, ConfigCompileError> {
    match value {
        "trace" => Ok(CompiledLogLevel::Trace),
        "debug" => Ok(CompiledLogLevel::Debug),
        "info" => Ok(CompiledLogLevel::Info),
        "warn" => Ok(CompiledLogLevel::Warn),
        "error" => Ok(CompiledLogLevel::Error),
        _ => Err(ConfigCompileError::at(
            path,
            "must be trace, debug, info, warn, or error",
        )),
    }
}

fn compile_capture_plan(
    value: &super::authoring::AuthoringCaptureConfig,
    sink: CaptureSinkSpec,
    working_set: CaptureWorkingSetPlan,
) -> CapturePlan {
    #[cfg(not(test))]
    let _ = working_set;
    CapturePlan {
        events: value
            .events
            .iter()
            .map(|event| match event {
                super::authoring::CaptureEvent::RequestAllowed => {
                    CompiledCaptureEvent::RequestAllowed
                }
                super::authoring::CaptureEvent::ResponseAllowed => {
                    CompiledCaptureEvent::ResponseAllowed
                }
                super::authoring::CaptureEvent::RequestDenied => {
                    CompiledCaptureEvent::RequestDenied
                }
                super::authoring::CaptureEvent::ResponseDenied => {
                    CompiledCaptureEvent::ResponseDenied
                }
            })
            .collect(),
        redaction_profile: value.redaction_profile.clone(),
        sink,
        max_body_bytes: value.max_body_bytes,
        max_inflight_body_bytes: value.max_inflight_body_bytes,
        #[cfg(test)]
        working_set,
    }
}

fn compile_safety_plan(value: &SafetyConfig) -> Result<SafetyPlan, ConfigCompileError> {
    Ok(SafetyPlan {
        loop_detection: LoopDetectionPlan {
            inject: value.loop_detection.inject,
            header: compile_header_name(
                &value.loop_detection.header,
                "safety.loop_detection.header",
            )?,
        },
    })
}

fn compile_header_names(
    values: &[String],
    path: &str,
) -> Result<Vec<HeaderName>, ConfigCompileError> {
    values
        .iter()
        .map(|value| compile_header_name(value, path))
        .collect()
}

fn compile_header_name(value: &str, path: &str) -> Result<HeaderName, ConfigCompileError> {
    let normalized = normalize_header_name(value, path)?;
    HeaderName::from_bytes(normalized.as_bytes()).map_err(|error| {
        ConfigCompileError::at(
            path,
            format!("invalid header name after validation: {error}"),
        )
    })
}

fn compile_static_config(
    config: &super::authoring::AuthoringConfig,
    config_root: PathBuf,
    callback_public_url: Option<CanonicalUrl>,
) -> Result<StaticProductConfig, ConfigCompileError> {
    Ok(StaticProductConfig {
        schema_version: config.schema_version.number(),
        config_root,
        max_config_bytes: MAX_CONFIG_BYTES,
        service: StaticServiceConfig {
            shutdown_drain_timeout: config.service.shutdown_drain_timeout.bounded(),
            max_retiring_generations: config.service.max_retiring_generations,
            max_active_upgrades: config.service.max_active_upgrades,
            max_active_webhook_deliveries: config.service.max_active_webhook_deliveries,
            webhook_transport_buffer_bytes: config.service.webhook_transport_buffer_bytes,
            max_webhook_transport_bytes: config.service.max_webhook_transport_bytes,
            upgrade_relay_buffer_bytes: config.service.upgrade_relay_buffer_bytes,
            max_upgrade_buffer_bytes: config.service.max_upgrade_buffer_bytes,
            max_upgrade_lifetime: config.service.max_upgrade_lifetime.get(),
            max_inflight_wire_body_bytes: config.service.max_inflight_wire_body_bytes,
            max_inflight_wire_body_bytes_per_quota_key: config
                .service
                .max_inflight_wire_body_bytes_per_quota_key,
            min_wire_body_concurrency: config.service.min_wire_body_concurrency,
        },
        control: config.control.as_ref().map(compile_control),
        listeners: compile_listeners(&config.listeners),
        mitm: config.mitm.as_ref().map(compile_mitm),
        callback_public_url,
        logging: StaticLoggingConfig {
            directory: config.observation.logging.directory.clone(),
            max_bytes: config.observation.logging.max_bytes,
            max_files: config.observation.logging.max_files,
            console: config.observation.logging.console,
        },
        capture: StaticCaptureConfig {
            max_pending_records: config.observation.capture.as_ref().map_or_else(
                super::authoring::default_capture_max_pending_records,
                |capture| capture.max_pending_records,
            ),
        },
    })
}

fn compile_control(value: &super::authoring::ControlConfig) -> StaticControlConfig {
    StaticControlConfig {
        bind: canonical_socket_addr(value.bind),
        base_path: value.base_path.clone(),
        request_header_timeout: value.request_header_timeout.get(),
        request_body_timeout: value.request_body_timeout.get(),
        max_connections: value.max_connections,
        parser_arena_bytes: control_parser_arena_bytes(value)
            .expect("control parser-arena arithmetic was validated"),
        max_request_body_bytes: value.max_request_body_bytes,
        tls: value.tls.as_ref().map(compile_tls_identity),
    }
}

fn compile_tls_identity(value: &StaticTlsIdentityConfig) -> CompiledTlsIdentity {
    CompiledTlsIdentity {
        certificate_chain: value.certificate_chain.clone(),
        private_key: value.private_key.clone(),
    }
}

fn compile_listeners(value: &ListenersConfig) -> StaticListenersConfig {
    StaticListenersConfig {
        explicit_http: value
            .explicit_http
            .as_ref()
            .map(|listener| StaticCleartextListener {
                endpoint: compile_listener_endpoint(&listener.endpoint),
                http_versions: compile_http_versions(&listener.http_versions),
                request_header_timeout: listener.request_header_timeout.get(),
                max_connections: listener.max_connections,
                max_concurrent_streams: listener.max_concurrent_streams,
                identity_mode: compile_listener_identity_mode(listener.identity.as_ref()),
                connect: Some(compile_connect(&listener.connect)),
            }),
        transparent_http: value
            .transparent_http
            .as_ref()
            .map(|listener| StaticCleartextListener {
                endpoint: compile_listener_endpoint(&listener.endpoint),
                http_versions: compile_http_versions(&listener.http_versions),
                request_header_timeout: listener.request_header_timeout.get(),
                max_connections: listener.max_connections,
                max_concurrent_streams: listener.max_concurrent_streams,
                identity_mode: compile_listener_identity_mode(listener.identity.as_ref()),
                connect: None,
            }),
        explicit_https: value
            .explicit_https
            .as_ref()
            .map(|listener| StaticExplicitHttpsListener {
                endpoint: compile_listener_endpoint(&listener.endpoint),
                http_versions: compile_http_versions(&listener.http_versions),
                handshake_timeout: listener.handshake_timeout.get(),
                request_header_timeout: listener.request_header_timeout.get(),
                max_connections: listener.max_connections,
                max_concurrent_streams: listener.max_concurrent_streams,
                identity_mode: compile_listener_identity_mode(listener.identity.as_ref()),
                connect: compile_connect(&listener.connect),
                tls: compile_tls_identity(&listener.tls),
            }),
        transparent_https: value.transparent_https.as_ref().map(|listener| {
            StaticTransparentHttpsListener {
                endpoint: compile_listener_endpoint(&listener.endpoint),
                http_versions: compile_http_versions(&listener.http_versions),
                handshake_timeout: listener.handshake_timeout.get(),
                request_header_timeout: listener.request_header_timeout.get(),
                max_connections: listener.max_connections,
                max_concurrent_streams: listener.max_concurrent_streams,
                identity_mode: compile_listener_identity_mode(listener.identity.as_ref()),
            }
        }),
    }
}

fn compile_listener_identity_mode(
    value: Option<&super::authoring::ListenerIdentityConfig>,
) -> CompiledListenerIdentityMode {
    match value.map(|value| value.mode) {
        None => CompiledListenerIdentityMode::Disabled,
        Some(ListenerIdentityModeConfig::Optional) => CompiledListenerIdentityMode::Optional,
        Some(ListenerIdentityModeConfig::Required) => CompiledListenerIdentityMode::Required,
    }
}

fn compile_listener_endpoint(value: &ListenerEndpointConfig) -> StaticListenerEndpoint {
    match value {
        ListenerEndpointConfig::Tcp { address } => StaticListenerEndpoint::Tcp {
            address: canonical_socket_addr(*address),
        },
        ListenerEndpointConfig::AccessFlow {
            admission_timeout,
            allowed_destination_ports,
            transport,
        } => {
            let mut allowed_destination_ports = allowed_destination_ports.clone();
            allowed_destination_ports.sort_unstable();
            let transport = match transport {
                AccessFlowTransportConfig::Unix { path, mode } => StaticAccessFlowTransport::Unix {
                    path: path.clone(),
                    mode: u32::from_str_radix(mode, 8)
                        .expect("Unix listener mode was validated before compilation"),
                },
            };
            StaticListenerEndpoint::AccessFlow {
                admission_timeout: admission_timeout.get(),
                allowed_destination_ports,
                transport,
            }
        }
    }
}

fn compile_http_versions(values: &[HttpVersion]) -> Vec<CompiledHttpVersion> {
    values
        .iter()
        .map(|value| match value {
            HttpVersion::Http1 => CompiledHttpVersion::Http1,
            HttpVersion::Http2 => CompiledHttpVersion::Http2,
        })
        .collect()
}

fn compile_connect(value: &super::authoring::ConnectConfig) -> StaticConnectPolicy {
    StaticConnectPolicy {
        http1: value.http1.map(|policy| match policy {
            Http1ConnectPolicy::Deny => CompiledHttp1ConnectPolicy::Deny,
            Http1ConnectPolicy::Mitm => CompiledHttp1ConnectPolicy::Mitm,
        }),
        http2_denied: value.http2.is_some(),
    }
}

fn compile_mitm(value: &MitmConfig) -> StaticMitmConfig {
    match value {
        MitmConfig::Generated(value) => StaticMitmConfig::Generated {
            directory: value.directory.clone(),
            max_cached_certificates: value.max_cached_certificates,
            persist_leaf_certificates: value.persist_leaf_certificates,
        },
        MitmConfig::Files(value) => StaticMitmConfig::Files {
            ca_certificate: value.ca_certificate.clone(),
            ca_private_key: value.ca_private_key.clone(),
            directory: value.directory.clone(),
            max_cached_certificates: value.max_cached_certificates,
            persist_leaf_certificates: value.persist_leaf_certificates,
        },
    }
}

fn normalize_header_name(value: &str, path: &str) -> Result<String, ConfigCompileError> {
    if value.starts_with(':') {
        return Err(ConfigCompileError::at(
            path,
            "HTTP pseudo-headers are not authorable",
        ));
    }
    HeaderName::from_bytes(value.as_bytes())
        .map(|name| name.as_str().to_ascii_lowercase())
        .map_err(|error| ConfigCompileError::at(path, format!("invalid header name: {error}")))
}

fn contains_header(values: &[String], expected: &str) -> bool {
    values
        .iter()
        .any(|value| value.eq_ignore_ascii_case(expected))
}

fn base_protected_headers() -> BTreeSet<&'static str> {
    BTreeSet::from([
        "host",
        "authorization",
        "proxy-authorization",
        "proxy-authenticate",
        "cookie",
        "set-cookie",
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "content-length",
        "content-encoding",
        http_access_types::HTTP_IDENTITY_TOKEN_HEADER,
    ])
}

fn base_sensitive_value_headers() -> BTreeSet<&'static str> {
    BTreeSet::from([
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
    ])
}

fn reject_base_protected_header(
    name: &str,
    loop_header: &str,
    path: &str,
) -> Result<(), ConfigCompileError> {
    if base_protected_headers().contains(name) || name == loop_header {
        return Err(ConfigCompileError::at(
            path,
            "header is reserved by the proxy",
        ));
    }
    Ok(())
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_TEST_PROVIDER_OUTPUTS_WITHIN_SHARED_RAW_BATCH: usize =
        credential_core::MAX_CREDENTIAL_RAW_BATCH_BYTES / MAX_PROVIDER_CREDENTIAL_BYTES;

    fn evaluate_test_policy(
        snapshot: &crate::policy::ProductAclSnapshot,
        url: &http_access_types::CanonicalUrl,
        peer_ip: IpAddr,
    ) -> http_access_policy_acl::PolicyEvaluation<crate::policy::ProductRuleEffectsRef> {
        let facts = http_access_types::InterceptedRequestFacts::new(
            http_access_types::IngressMode::ExplicitHttps,
            http_access_types::HttpVersion::Http11,
            http_access_types::HttpMethod::new("GET").unwrap(),
            url.clone(),
            Vec::new(),
            http_access_types::BodyMetadata::new(http_access_types::BodyFraming::None),
            None,
        )
        .unwrap();
        let header_facts =
            http_access_types::PolicyHeaderFacts::new(Vec::new(), Vec::new()).unwrap();
        let input = http_access_policy_acl::EvaluationInput::new(
            &facts,
            peer_ip,
            &header_facts,
            1,
            http_access_types::BodyRepresentation::PreservedContentCoded,
            http_access_types::BodyObservation::unobserved(),
            &access_identity::IdentityContext::Disabled,
        )
        .unwrap();
        snapshot.snapshot().evaluate(&input).unwrap()
    }

    const MINIMAL: &str = r#"
schema_version = 3

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"
"#;

    #[test]
    fn credential_source_locators_enforce_exact_authored_bounds() {
        let exact_environment =
            format!("A{}", "B".repeat(MAX_ENVIRONMENT_CREDENTIAL_NAME_BYTES - 1));
        let exact_path = format!(
            "/{}",
            (0..16)
                .map(|_| "p".repeat(MAX_CREDENTIAL_FILE_COMPONENT_BYTES))
                .collect::<Vec<_>>()
                .join("/")
        );
        assert_eq!(exact_path.len(), MAX_CREDENTIAL_FILE_PATH_BYTES);
        let exact = MINIMAL.replace(
            "[policy]",
            &format!(
                r#"[credentials.sources.environment]
source = "environment"
variable = "{exact_environment}"

[credentials.sources.file]
source = "file"
path = "{exact_path}"

[policy]"#,
            ),
        );
        compile(&exact).unwrap();

        for root_only_path in ["/", "/credential/.."] {
            let error = compile(&MINIMAL.replace(
                "[policy]",
                &format!(
                    r#"[credentials.sources.file]
source = "file"
path = "{root_only_path}"

[policy]"#,
                ),
            ))
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("credentials.sources.file.path: must identify a credential file"),
                "unexpected error for {root_only_path}: {error}"
            );
        }

        let oversized_environment =
            format!("A{}", "B".repeat(MAX_ENVIRONMENT_CREDENTIAL_NAME_BYTES));
        let error = compile(&MINIMAL.replace(
            "[policy]",
            &format!(
                r#"[credentials.sources.environment]
source = "environment"
variable = "{oversized_environment}"

[policy]"#,
            ),
        ))
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("exceeds the credential source locator limit"));

        let oversized_path = format!(
            "/{}",
            (0..17)
                .map(|_| "p".repeat(240))
                .collect::<Vec<_>>()
                .join("/")
        );
        assert_eq!(oversized_path.len(), MAX_CREDENTIAL_FILE_PATH_BYTES + 1);
        let error = compile(&MINIMAL.replace(
            "[policy]",
            &format!(
                r#"[credentials.sources.file]
source = "file"
path = "{oversized_path}"

[policy]"#,
            ),
        ))
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("exceeds the credential source locator limit"));

        let oversized_component =
            format!("/{}", "p".repeat(MAX_CREDENTIAL_FILE_COMPONENT_BYTES + 1));
        let error = compile(&MINIMAL.replace(
            "[policy]",
            &format!(
                r#"[credentials.sources.file]
source = "file"
path = "{oversized_component}"

[policy]"#,
            ),
        ))
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("contains a component over the credential path component limit"));
    }

    fn identity_config(token_source: &str) -> String {
        format!(
            r#"
schema_version = 3

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.identity]
mode = "required"

[listeners.explicit_http.connect]
http1 = "deny"

[identity]
max_pending_authentications = 8
max_pending_authentications_per_connection = 2

[identity.resolver]
kind = "static"
authority = "test-authority"

[[identity.resolver.principals]]
id = "test-principal"
kind = "service_account"

[[identity.resolver.tokens]]
id = "test-token"
principal = "test-principal"
{token_source}

[policy]
default = "deny"
"#
        )
    }

    fn environment_identity_config(variable: &str) -> String {
        identity_config(&format!(
            "source = \"environment\"\nvariable = {variable:?}"
        ))
    }

    fn file_identity_config(path: &str) -> String {
        identity_config(&format!("source = \"file\"\npath = {path:?}"))
    }

    fn authored_identity_config() -> super::super::authoring::AuthoringConfig {
        toml::from_str(&environment_identity_config("AW_IDENTITY_TOKEN")).unwrap()
    }

    fn validate_and_project_identity(
        config: &super::super::authoring::AuthoringConfig,
    ) -> Result<(), ConfigCompileError> {
        validate_identity(config)?;
        compile_identity_plan(config.identity.as_ref()).map(|_| ())
    }

    fn identity_principal(
        id: impl Into<String>,
    ) -> super::super::authoring::StaticIdentityPrincipalConfig {
        super::super::authoring::StaticIdentityPrincipalConfig {
            id: id.into(),
            kind: IdentityPrincipalKindConfig::ServiceAccount,
        }
    }

    fn identity_group(
        id: impl Into<String>,
        members: Vec<String>,
    ) -> super::super::authoring::StaticIdentityGroupConfig {
        super::super::authoring::StaticIdentityGroupConfig {
            id: id.into(),
            members,
        }
    }

    fn identity_environment_token(
        id: impl Into<String>,
        principal: impl Into<String>,
        variable: impl Into<String>,
    ) -> super::super::authoring::StaticIdentityTokenConfig {
        super::super::authoring::StaticIdentityTokenConfig::Environment {
            id: id.into(),
            principal: principal.into(),
            variable: variable.into(),
        }
    }

    fn identity_principals(
        count: usize,
    ) -> Vec<super::super::authoring::StaticIdentityPrincipalConfig> {
        (0..count)
            .map(|index| {
                identity_principal(if index == 0 {
                    "test-principal".to_owned()
                } else {
                    format!("principal-{index}")
                })
            })
            .collect()
    }

    fn identity_policy_config(mode: &str, states: &str, subjects: Option<&str>) -> String {
        let subjects = subjects
            .map(|value| format!("identity_subjects = {value}\n"))
            .unwrap_or_default();
        environment_identity_config("AW_IDENTITY_TOKEN")
            .replace("mode = \"required\"", &format!("mode = {mode:?}"))
            .replace(
                "[policy]\ndefault = \"deny\"",
                &format!(
                    r#"[[identity.resolver.groups]]
id = "developers"
members = ["test-principal"]

[policy]
default = "deny"

[[policy.rules]]
id = "identity-rule"
decision = "allow"
identity_states = {states}
{subjects}"#
                ),
            )
    }

    fn aggregate_identity_subjects_config(subject_count: usize) -> String {
        let mut config = environment_identity_config("AW_IDENTITY_TOKEN").replace(
            "[policy]\ndefault = \"deny\"",
            r#"[[identity.resolver.groups]]
id = "developers"
members = ["test-principal"]

[policy]
default = "deny""#,
        );
        for index in 0..subject_count {
            config.push_str(&format!(
                r#"

[[policy.rules]]
id = "identity-{index}"
decision = "allow"
identity_states = ["authenticated"]
identity_subjects = [
  {{ kind = "group", authority = "test-authority", id = "developers" }},
]
"#
            ));
        }
        config
    }

    #[test]
    fn aggregate_policy_identity_subject_bound_is_validated_before_projection() {
        compile(&aggregate_identity_subjects_config(
            MAX_IDENTITY_SUBJECTS_PER_SNAPSHOT,
        ))
        .expect("the exact shared identity-subject aggregate bound must compile");

        let error = compile(&aggregate_identity_subjects_config(
            MAX_IDENTITY_SUBJECTS_PER_SNAPSHOT + 1,
        ))
        .expect_err("one identity subject over the shared aggregate bound must fail");
        let expected_path = format!(
            "policy.rules[{}].identity_subjects",
            MAX_IDENTITY_SUBJECTS_PER_SNAPSHOT
        );
        assert!(error.to_string().contains(&expected_path), "{error}");
        assert!(
            error.to_string().contains(&format!(
                "aggregate policy limit of {MAX_IDENTITY_SUBJECTS_PER_SNAPSHOT} identity subjects"
            )),
            "{error}"
        );
    }

    #[test]
    fn policy_identity_predicates_are_strict_canonical_or_sets() {
        let valid = identity_policy_config(
            "optional",
            r#"["authenticated", "disabled", "anonymous"]"#,
            None,
        );
        let compiled = compile(&valid).expect("all three identity states are a valid OR set");
        let identity = compiled.reloadable_plan.policy.rules[0]
            .identity
            .as_ref()
            .unwrap();
        assert_eq!(
            identity.states,
            [
                IdentityState::Disabled,
                IdentityState::Anonymous,
                IdentityState::Authenticated
            ]
        );
        assert!(identity.subjects.is_empty());

        for (input, expected) in [
            (
                identity_policy_config("required", "[]", None),
                "must not be empty",
            ),
            (
                identity_policy_config("required", r#"["authenticated", "authenticated"]"#, None),
                "must not contain duplicates",
            ),
            (
                identity_policy_config("required", r#"["authenticated"]"#, Some("[]")),
                "must not be empty",
            ),
            (
                identity_policy_config(
                    "required",
                    r#"["authenticated", "disabled"]"#,
                    Some(
                        r#"[{ kind = "principal", authority = "test-authority", id = "test-principal" }]"#,
                    ),
                ),
                "requires identity_states",
            ),
            (
                identity_policy_config(
                    "required",
                    r#"["authenticated"]"#,
                    Some(
                        r#"[
  { kind = "group", authority = "test-authority", id = "developers" },
  { kind = "group", authority = "test-authority", id = "developers" },
]"#,
                    ),
                ),
                "duplicates an earlier identity subject",
            ),
        ] {
            let error = compile(&input).expect_err("invalid identity predicate must fail");
            assert!(
                error.to_string().contains(expected),
                "expected {expected:?}, got {error}"
            );
        }
    }

    #[test]
    fn policy_identity_subjects_are_exact_resolver_qualified_values() {
        let valid = identity_policy_config(
            "required",
            r#"["authenticated"]"#,
            Some(
                r#"[
  { kind = "group", authority = "test-authority", id = "developers" },
  { kind = "principal", authority = "test-authority", id = "test-principal" },
]"#,
            ),
        );
        let compiled = compile(&valid).expect("known principal and group must compile");
        let subjects = &compiled.reloadable_plan.policy.rules[0]
            .identity
            .as_ref()
            .unwrap()
            .subjects;
        assert_eq!(subjects.len(), 2);
        assert!(subjects.windows(2).all(|pair| pair[0] < pair[1]));

        for (subjects, expected) in [
            (
                r#"[{ kind = "principal", authority = "other", id = "test-principal" }]"#,
                "must match the configured identity resolver authority",
            ),
            (
                r#"[{ kind = "principal", authority = "test-authority", id = "missing" }]"#,
                "unknown identity principal",
            ),
            (
                r#"[{ kind = "group", authority = "test-authority", id = "missing" }]"#,
                "unknown identity group",
            ),
        ] {
            let input = identity_policy_config("required", r#"["authenticated"]"#, Some(subjects));
            let error = compile(&input).expect_err("unknown identity subject must fail");
            assert!(
                error.to_string().contains(expected),
                "expected {expected:?}, got {error}"
            );
        }
    }

    #[test]
    fn policy_identity_subjects_reject_roles_wildcards_and_negative_ids() {
        let role = identity_policy_config(
            "required",
            r#"["authenticated"]"#,
            Some(r#"[{ kind = "role", authority = "test-authority", id = "operators" }]"#),
        );
        assert!(
            toml::from_str::<super::super::authoring::AuthoringConfig>(&role).is_err(),
            "identity role subjects must not be authored"
        );

        for id in ["*", "!test-principal"] {
            let subjects =
                format!(r#"[{{ kind = "principal", authority = "test-authority", id = "{id}" }}]"#);
            let input = identity_policy_config("required", r#"["authenticated"]"#, Some(&subjects));
            let error = compile(&input).expect_err("wildcard or negative subject ID must fail");
            assert!(
                error
                    .to_string()
                    .contains("policy.rules[0].identity_subjects[0].id"),
                "unexpected error for identity subject ID {id:?}: {error}"
            );
        }
    }

    #[test]
    fn policy_identity_anonymous_state_requires_an_optional_listener() {
        let required = identity_policy_config("required", r#"["anonymous"]"#, None);
        let error = compile(&required).expect_err("required listeners cannot produce anonymous");
        assert!(
            error
                .to_string()
                .contains("anonymous identity requires at least one optional identity listener"),
            "{error}"
        );
        compile(&identity_policy_config(
            "optional",
            r#"["anonymous"]"#,
            None,
        ))
        .expect("an optional listener can produce anonymous identity");

        let disabled_only = format!(
            r#"{MINIMAL}
[[policy.rules]]
id = "disabled"
decision = "allow"
identity_states = ["disabled"]
"#
        );
        compile(&disabled_only).expect("disabled identity has no reachability requirement");
    }

    #[test]
    fn identity_environment_names_enforce_the_acl_proxy_contract_and_bound() {
        let exact = format!(
            "AW_{}_IDENTITY_TOKEN",
            "A".repeat(256 - "AW__IDENTITY_TOKEN".len())
        );
        assert_eq!(exact.len(), 256);
        for accepted in [
            "AW_IDENTITY_TOKEN".to_owned(),
            "AW_CONTAINER_A_IDENTITY_TOKEN".to_owned(),
            "AW_7_IDENTITY_TOKEN".to_owned(),
            exact.clone(),
        ] {
            compile(&environment_identity_config(&accepted))
                .unwrap_or_else(|error| panic!("valid identity name {accepted} failed: {error}"));
        }

        for rejected in [
            "IDENTITY_TOKEN".to_owned(),
            "AW_ACCESS_FLOW_TOKEN".to_owned(),
            "AW_container_IDENTITY_TOKEN".to_owned(),
            "AW__IDENTITY_TOKEN".to_owned(),
            "AW_CONTAINER__IDENTITY_TOKEN".to_owned(),
            format!("{exact}A"),
        ] {
            let error = compile(&environment_identity_config(&rejected))
                .expect_err("invalid identity environment name must fail");
            assert!(
                error
                    .to_string()
                    .contains("identity.resolver.tokens[0].variable"),
                "unexpected error for {rejected}: {error}"
            );
            assert!(
                !error.to_string().contains(&rejected),
                "secret locator leaked in error: {error}"
            );
        }

        let parent_only = MINIMAL.replace(
            "[policy]",
            r#"[egress]
route = "parent_proxy"

[egress.parent_proxy]
kind = "acl_proxy"
url = "https://parent.example.test:8443"

[egress.parent_proxy.presentation]
kind = "bearer_environment"
variable = "AW_ACCESS_FLOW_TOKEN"

[egress.parent_proxy.tls]
trust = "system"

[policy]"#,
        );
        let error = compile(&parent_only).expect_err("typed parent uses the ACL Proxy name rule");
        assert!(
            error
                .to_string()
                .contains("egress.parent_proxy.presentation.variable"),
            "{error}"
        );
        assert!(!error.to_string().contains("AW_ACCESS_FLOW_TOKEN"));
    }

    #[test]
    fn identity_file_locators_require_exact_absolute_normalized_bounds() {
        let exact = format!(
            "/{}",
            (0..16)
                .map(|_| "p".repeat(MAX_CREDENTIAL_FILE_COMPONENT_BYTES))
                .collect::<Vec<_>>()
                .join("/")
        );
        assert_eq!(exact.len(), MAX_CREDENTIAL_FILE_PATH_BYTES);
        compile(&file_identity_config(&exact)).unwrap();

        for rejected in [
            "relative/token".to_owned(),
            "/etc/acl-proxy/../token".to_owned(),
            "/etc//acl-proxy/token".to_owned(),
            "/etc/./acl-proxy/token".to_owned(),
            "/etc/acl-proxy/token/".to_owned(),
            "/".to_owned(),
            format!("/{}", "p".repeat(MAX_CREDENTIAL_FILE_COMPONENT_BYTES + 1)),
            format!("{exact}p"),
        ] {
            let error = compile(&file_identity_config(&rejected))
                .expect_err("invalid identity file locator must fail");
            assert!(
                error
                    .to_string()
                    .contains("identity.resolver.tokens[0].path"),
                "unexpected error for identity path: {error}"
            );
            assert!(
                !error.to_string().contains(&rejected),
                "identity path leaked in error: {error}"
            );
        }

        let parent_relative = MINIMAL.replace(
            "[policy]",
            r#"[egress]
route = "parent_proxy"

[egress.parent_proxy]
kind = "acl_proxy"
url = "https://parent.example.test:8443"

[egress.parent_proxy.presentation]
kind = "bearer_file"
path = "relative/token"

[egress.parent_proxy.tls]
trust = "system"

[policy]"#,
        );
        let error = compile(&parent_relative)
            .expect_err("typed parent identity files are not rooted generically");
        assert!(
            error
                .to_string()
                .contains("egress.parent_proxy.presentation.path"),
            "{error}"
        );

        let parent_redundant_separator = parent_relative.replace(
            "path = \"relative/token\"",
            "path = \"/etc//acl-proxy/parent-token\"",
        );
        let error = compile(&parent_redundant_separator)
            .expect_err("typed parent identity paths require exact canonical bytes");
        assert!(
            error
                .to_string()
                .contains("egress.parent_proxy.presentation.path"),
            "{error}"
        );
        assert!(
            !error.to_string().contains("/etc//acl-proxy/parent-token"),
            "{error}"
        );
    }

    #[test]
    fn identity_capacity_and_listener_usage_are_strict() {
        let baseline = environment_identity_config("AW_IDENTITY_TOKEN");
        let explicit_disabled = baseline.replace("mode = \"required\"", "mode = \"disabled\"");
        assert!(
            toml::from_str::<super::super::authoring::AuthoringConfig>(&explicit_disabled).is_err(),
            "explicit disabled listener identity mode must be rejected"
        );
        for (needle, replacement, expected_path) in [
            (
                "max_pending_authentications = 8",
                "max_pending_authentications = 0",
                "identity.max_pending_authentications",
            ),
            (
                "max_pending_authentications = 8",
                "max_pending_authentications = 4097",
                "identity.max_pending_authentications",
            ),
            (
                "max_pending_authentications_per_connection = 2",
                "max_pending_authentications_per_connection = 257",
                "identity.max_pending_authentications_per_connection",
            ),
            (
                "max_pending_authentications_per_connection = 2",
                "max_pending_authentications_per_connection = 9",
                "identity.max_pending_authentications_per_connection",
            ),
        ] {
            let error = compile(&baseline.replacen(needle, replacement, 1))
                .expect_err("invalid identity capacity must fail");
            assert!(error.to_string().contains(expected_path), "{error}");
        }

        compile(
            &baseline
                .replace(
                    "max_pending_authentications = 8",
                    "max_pending_authentications = 4096",
                )
                .replace(
                    "max_pending_authentications_per_connection = 2",
                    "max_pending_authentications_per_connection = 256",
                ),
        )
        .expect("exact identity authentication capacity bounds must compile");
        let per_connection_zero = baseline.replace(
            "max_pending_authentications_per_connection = 2",
            "max_pending_authentications_per_connection = 0",
        );
        let error = compile(&per_connection_zero)
            .expect_err("zero per-connection identity authentication capacity must fail");
        assert!(
            error
                .to_string()
                .contains("identity.max_pending_authentications_per_connection"),
            "{error}"
        );

        let unused = baseline.replace(
            "\n[listeners.explicit_http.identity]\nmode = \"required\"\n",
            "",
        );
        let error = compile(&unused).expect_err("an unused resolver must fail");
        assert!(
            error
                .to_string()
                .contains("requires at least one optional or required identity listener"),
            "{error}"
        );
    }

    #[test]
    fn identity_listener_resolver_and_subject_cross_requirements_are_strict() {
        let baseline = authored_identity_config();
        validate_identity(&baseline).expect("the loopback identity baseline must validate");

        let mut missing_resolver = baseline.clone();
        missing_resolver.identity = None;
        let error = validate_identity(&missing_resolver)
            .expect_err("an identity-enabled listener requires a resolver");
        assert!(
            error
                .to_string()
                .contains("identity: is required when a listener enables identity"),
            "{error}"
        );

        let mut unused_resolver = baseline.clone();
        unused_resolver
            .listeners
            .explicit_http
            .as_mut()
            .unwrap()
            .identity = None;
        let error =
            validate_identity(&unused_resolver).expect_err("an unused resolver must be rejected");
        assert!(
            error
                .to_string()
                .contains("requires at least one optional or required identity listener"),
            "{error}"
        );

        let mut unreachable_subjects: super::super::authoring::AuthoringConfig =
            toml::from_str(&identity_policy_config(
                "required",
                r#"["authenticated"]"#,
                Some(
                    r#"[{ kind = "principal", authority = "test-authority", id = "test-principal" }]"#,
                ),
            ))
            .unwrap();
        unreachable_subjects
            .listeners
            .explicit_http
            .as_mut()
            .unwrap()
            .identity = None;
        let error = validate_identity(&unreachable_subjects)
            .expect_err("authenticated subjects require an identity-enabled listener");
        assert!(
            error
                .to_string()
                .contains("authenticated subjects require at least one identity-enabled listener"),
            "{error}"
        );
    }

    #[test]
    fn identity_subjects_reject_omitted_identity_states() {
        let input = identity_policy_config(
            "required",
            r#"["authenticated"]"#,
            Some(
                r#"[{ kind = "principal", authority = "test-authority", id = "test-principal" }]"#,
            ),
        )
        .replace("identity_states = [\"authenticated\"]\n", "");
        let error = compile(&input).expect_err("subjects without identity_states must fail");
        assert!(
            error
                .to_string()
                .contains("requires identity_states = [\"authenticated\"]"),
            "{error}"
        );
    }

    #[test]
    fn cleartext_identity_requires_loopback_and_accepts_loopback() {
        let loopback = authored_identity_config();
        validate_identity(&loopback).expect("loopback cleartext identity must validate");

        let mut non_loopback = loopback;
        let listener = non_loopback.listeners.explicit_http.as_mut().unwrap();
        listener.endpoint = ListenerEndpointConfig::Tcp {
            address: "192.0.2.10:8881".parse().unwrap(),
        };
        let error = validate_identity(&non_loopback)
            .expect_err("non-loopback cleartext identity must be rejected");
        assert!(
            error
                .to_string()
                .contains("identity over cleartext TCP requires a loopback listener"),
            "{error}"
        );
    }

    #[test]
    fn generic_parent_rejects_every_identity_presentation_source() {
        for presentation in [
            r#"
[egress.parent_proxy.presentation]
kind = "bearer_environment"
variable = "AW_IDENTITY_TOKEN"
"#,
            r#"
[egress.parent_proxy.presentation]
kind = "bearer_file"
path = "/etc/acl-proxy/identity-token"
"#,
        ] {
            let input = MINIMAL.replace(
                "[policy]",
                &format!(
                    r#"[egress]
route = "parent_proxy"

[egress.parent_proxy]
kind = "generic"
url = "https://parent.example.test:8443"
{presentation}
[egress.parent_proxy.tls]
trust = "system"

[policy]"#
                ),
            );
            let error = compile(&input).expect_err("generic parent presentation must be rejected");
            assert!(
                error
                    .to_string()
                    .contains("presentation: is valid only for an ACL Proxy parent"),
                "{error}"
            );
        }
    }

    #[test]
    fn cleartext_acl_parent_rejects_every_identity_presentation_source() {
        for presentation in [
            r#"
[egress.parent_proxy.presentation]
kind = "bearer_environment"
variable = "AW_IDENTITY_TOKEN"
"#,
            r#"
[egress.parent_proxy.presentation]
kind = "bearer_file"
path = "/etc/acl-proxy/identity-token"
"#,
        ] {
            let input = MINIMAL.replace(
                "[policy]",
                &format!(
                    r#"[egress]
route = "parent_proxy"

[egress.parent_proxy]
kind = "acl_proxy"
url = "http://192.0.2.10:8080"
{presentation}
[policy]"#
                ),
            );
            let error =
                compile(&input).expect_err("cleartext parent presentation must be rejected");
            assert!(
                error
                    .to_string()
                    .contains("egress.parent_proxy.presentation: requires an HTTPS parent URL"),
                "{error}"
            );
        }
    }

    #[test]
    fn static_identity_record_limits_accept_exact_bound_and_reject_bound_plus_one() {
        let mut principals = authored_identity_config();
        principals.identity.as_mut().unwrap().resolver.principals =
            identity_principals(MAX_IDENTITY_PRINCIPALS);
        validate_and_project_identity(&principals)
            .expect("the exact principal bound must validate and project");
        principals
            .identity
            .as_mut()
            .unwrap()
            .resolver
            .principals
            .push(identity_principal("principal-over-limit"));
        let error =
            validate_identity(&principals).expect_err("one principal over the bound must fail");
        assert!(
            error
                .to_string()
                .contains("exceeds the static identity principal limit"),
            "{error}"
        );

        let mut groups = authored_identity_config();
        groups.identity.as_mut().unwrap().resolver.groups = (0..MAX_IDENTITY_GROUPS)
            .map(|index| identity_group(format!("group-{index}"), Vec::new()))
            .collect();
        validate_and_project_identity(&groups)
            .expect("the exact group bound must validate and project");
        groups
            .identity
            .as_mut()
            .unwrap()
            .resolver
            .groups
            .push(identity_group("group-over-limit", Vec::new()));
        let error = validate_identity(&groups).expect_err("one group over the bound must fail");
        assert!(
            error
                .to_string()
                .contains("exceeds the static identity group limit"),
            "{error}"
        );

        let mut tokens = authored_identity_config();
        tokens.identity.as_mut().unwrap().resolver.tokens = (0..MAX_IDENTITY_TOKENS)
            .map(|index| {
                identity_environment_token(
                    format!("token-{index}"),
                    "test-principal",
                    format!("AW_T{index}_IDENTITY_TOKEN"),
                )
            })
            .collect();
        validate_and_project_identity(&tokens)
            .expect("the exact token-record bound must validate and project");
        tokens
            .identity
            .as_mut()
            .unwrap()
            .resolver
            .tokens
            .push(identity_environment_token(
                "token-over-limit",
                "test-principal",
                "AW_OVER_LIMIT_IDENTITY_TOKEN",
            ));
        let error =
            validate_identity(&tokens).expect_err("one token record over the bound must fail");
        assert!(
            error
                .to_string()
                .contains("exceeds the static identity token-record limit"),
            "{error}"
        );
    }

    #[test]
    fn static_identity_membership_limits_accept_exact_bound_and_reject_bound_plus_one() {
        let principal_ids = (0..=MAX_IDENTITY_GROUPS_PER_PRINCIPAL)
            .map(|index| format!("member-{index}"))
            .collect::<Vec<_>>();
        let exact_members = principal_ids[..MAX_IDENTITY_GROUPS_PER_PRINCIPAL].to_vec();
        let mut memberships = authored_identity_config();
        let resolver = &mut memberships.identity.as_mut().unwrap().resolver;
        resolver.principals = principal_ids
            .iter()
            .map(|id| identity_principal(id.clone()))
            .collect();
        resolver.tokens = vec![identity_environment_token(
            "member-primary",
            &principal_ids[0],
            "AW_MEMBERSHIP_IDENTITY_TOKEN",
        )];
        resolver.groups = (0..MAX_IDENTITY_GROUPS_PER_PRINCIPAL)
            .map(|index| identity_group(format!("membership-group-{index}"), exact_members.clone()))
            .collect();
        validate_and_project_identity(&memberships).expect(
            "the exact total and per-principal membership bounds must validate and project",
        );

        let mut total_over = memberships.clone();
        total_over
            .identity
            .as_mut()
            .unwrap()
            .resolver
            .groups
            .push(identity_group(
                "membership-over-limit",
                vec![principal_ids[MAX_IDENTITY_GROUPS_PER_PRINCIPAL].clone()],
            ));
        let error = validate_identity(&total_over)
            .expect_err("one aggregate membership over the bound must fail");
        assert!(
            error
                .to_string()
                .contains("exceeds the static identity membership limit"),
            "{error}"
        );

        let mut per_principal_over = authored_identity_config();
        per_principal_over
            .identity
            .as_mut()
            .unwrap()
            .resolver
            .groups = (0..=MAX_IDENTITY_GROUPS_PER_PRINCIPAL)
            .map(|index| {
                identity_group(
                    format!("principal-group-{index}"),
                    vec!["test-principal".to_owned()],
                )
            })
            .collect();
        let error = validate_identity(&per_principal_over)
            .expect_err("one group per principal over the bound must fail");
        assert!(
            error
                .to_string()
                .contains("exceeds the static identity group-membership limit"),
            "{error}"
        );
    }

    #[test]
    fn static_identity_records_reject_empty_duplicate_unknown_and_reused_sources() {
        let mut empty_principals = authored_identity_config();
        empty_principals
            .identity
            .as_mut()
            .unwrap()
            .resolver
            .principals
            .clear();
        let error =
            validate_identity(&empty_principals).expect_err("empty principals must be rejected");
        assert!(
            error
                .to_string()
                .contains("identity.resolver.principals: must not be empty"),
            "{error}"
        );

        let mut empty_tokens = authored_identity_config();
        empty_tokens
            .identity
            .as_mut()
            .unwrap()
            .resolver
            .tokens
            .clear();
        let error = validate_identity(&empty_tokens).expect_err("empty tokens must be rejected");
        assert!(
            error
                .to_string()
                .contains("identity.resolver.tokens: must not be empty"),
            "{error}"
        );

        let mut duplicate_principal = authored_identity_config();
        duplicate_principal
            .identity
            .as_mut()
            .unwrap()
            .resolver
            .principals
            .push(identity_principal("test-principal"));
        let error = validate_identity(&duplicate_principal)
            .expect_err("duplicate principal IDs must be rejected");
        assert!(error
            .to_string()
            .contains("duplicates an earlier principal"));

        let mut duplicate_group = authored_identity_config();
        duplicate_group.identity.as_mut().unwrap().resolver.groups = vec![
            identity_group("developers", vec!["test-principal".to_owned()]),
            identity_group("developers", Vec::new()),
        ];
        let error =
            validate_identity(&duplicate_group).expect_err("duplicate group IDs must be rejected");
        assert!(error.to_string().contains("duplicates an earlier group"));

        let mut duplicate_member = authored_identity_config();
        duplicate_member.identity.as_mut().unwrap().resolver.groups = vec![identity_group(
            "developers",
            vec!["test-principal".to_owned(), "test-principal".to_owned()],
        )];
        let error = validate_identity(&duplicate_member)
            .expect_err("duplicate group members must be rejected");
        assert!(error.to_string().contains("duplicates an earlier member"));

        let mut unknown_member = authored_identity_config();
        unknown_member.identity.as_mut().unwrap().resolver.groups = vec![identity_group(
            "developers",
            vec!["unknown-principal".to_owned()],
        )];
        let error =
            validate_identity(&unknown_member).expect_err("unknown group members must be rejected");
        assert!(error
            .to_string()
            .contains("references an unknown principal"));

        let mut duplicate_token = authored_identity_config();
        duplicate_token
            .identity
            .as_mut()
            .unwrap()
            .resolver
            .tokens
            .push(identity_environment_token(
                "test-token",
                "test-principal",
                "AW_SECONDARY_IDENTITY_TOKEN",
            ));
        let error =
            validate_identity(&duplicate_token).expect_err("duplicate token IDs must be rejected");
        assert!(error
            .to_string()
            .contains("duplicates an earlier token record"));

        let mut unknown_token_principal = authored_identity_config();
        unknown_token_principal
            .identity
            .as_mut()
            .unwrap()
            .resolver
            .tokens = vec![identity_environment_token(
            "unknown-principal-token",
            "unknown-principal",
            "AW_UNKNOWN_IDENTITY_TOKEN",
        )];
        let error = validate_identity(&unknown_token_principal)
            .expect_err("token records must reference known principals");
        assert!(error
            .to_string()
            .contains("references an unknown principal"));

        let mut duplicate_environment_source = authored_identity_config();
        duplicate_environment_source
            .identity
            .as_mut()
            .unwrap()
            .resolver
            .tokens
            .push(identity_environment_token(
                "secondary-token",
                "test-principal",
                "AW_IDENTITY_TOKEN",
            ));
        let error = validate_identity(&duplicate_environment_source)
            .expect_err("identity environment sources must be unique");
        assert!(error
            .to_string()
            .contains("duplicates an earlier identity environment source"));
    }

    #[test]
    fn static_identity_configuration_reserves_anonymous_ids() {
        let mut anonymous_principal = authored_identity_config();
        anonymous_principal
            .identity
            .as_mut()
            .unwrap()
            .resolver
            .principals[0]
            .id = "anonymous".to_owned();
        let error = validate_identity(&anonymous_principal)
            .expect_err("anonymous must remain reserved as a principal ID");
        assert!(
            error
                .to_string()
                .contains("reserved anonymous identity identifier"),
            "{error}"
        );

        let mut anonymous_group = authored_identity_config();
        anonymous_group.identity.as_mut().unwrap().resolver.groups =
            vec![identity_group("anonymous", Vec::new())];
        let error = validate_identity(&anonymous_group)
            .expect_err("anonymous must remain reserved as a group ID");
        assert!(
            error
                .to_string()
                .contains("reserved anonymous identity identifier"),
            "{error}"
        );
    }

    #[test]
    fn transparent_tcp_rejects_identity_before_static_listener_compilation() {
        let baseline = environment_identity_config("AW_TRANSPARENT_TCP_IDENTITY_TOKEN").replace(
            "\n[listeners.explicit_http.identity]\nmode = \"required\"\n",
            "",
        );
        for listener in ["transparent_http", "transparent_https"] {
            for mode in ["optional", "required"] {
                let candidate = baseline.replace(
                    "[policy]",
                    &format!(
                        r#"[listeners.{listener}]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8899"
http_versions = ["http1"]

[listeners.{listener}.identity]
mode = "{mode}"

[policy]"#
                    ),
                );
                let error = compile(&candidate)
                    .expect_err("transparent TCP cannot carry an authenticated identity");
                assert!(
                    error
                        .to_string()
                        .contains(&format!("listeners.{listener}.identity.mode")),
                    "{error}"
                );
                assert!(
                    error
                        .to_string()
                        .contains("only on a transparent access_flow endpoint"),
                    "{error}"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn transparent_access_flow_compiles_enabled_identity_into_static_listener() {
        let input = environment_identity_config("AW_TRANSPARENT_ACCESS_FLOW_IDENTITY_TOKEN")
            .replace(
                "\n[listeners.explicit_http.identity]\nmode = \"required\"\n",
                "",
            );
        let input = input.replace(
            "[policy]",
            r#"[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]

[listeners.transparent_http.identity]
mode = "required"

[listeners.transparent_http.endpoint.transport]
kind = "unix"
path = "/tmp/acl-proxy-identity-access-flow.sock"
mode = "0600"

[policy]"#,
        );
        let compiled = compile(&input).expect("transparent Access Flow supports identity");
        let listener = compiled
            .static_config
            .listeners
            .transparent_http
            .expect("compiled transparent listener");
        assert_eq!(
            listener.identity_mode,
            CompiledListenerIdentityMode::Required
        );
        assert!(matches!(
            listener.endpoint,
            StaticListenerEndpoint::AccessFlow { .. }
        ));
    }

    #[test]
    fn identity_locators_can_be_shared_only_by_resolver_and_typed_parent() {
        let variable = "AW_SHARED_IDENTITY_TOKEN";
        let baseline = environment_identity_config(variable);
        let parent = format!(
            r#"
[egress]
route = "parent_proxy"

[egress.parent_proxy]
kind = "acl_proxy"
url = "https://parent.example.test:8443"

[egress.parent_proxy.presentation]
kind = "bearer_environment"
variable = "{variable}"

[egress.parent_proxy.tls]
trust = "system"

"#
        );
        let shared = baseline.replace("[policy]", &format!("{parent}[policy]"));
        compile(&shared).expect("resolver and typed parent may share one locator");

        let ordinary_surfaces = [
            format!(
                r#"[credentials.sources.overlap]
source = "environment"
variable = "{variable}"

"#
            ),
            format!(
                r#"[redaction.profiles.overlap]
rules = [{{ literal_environment_variables = ["{variable}"] }}]

"#
            ),
            format!(
                r#"[authorization.providers.overlap]
kind = "process"
command = "/bin/true"
inherit_environment = false
pass_environment = ["{variable}"]

"#
            ),
            format!(
                r#"[authorization.providers.overlap]
kind = "process"
command = "/bin/true"
inherit_environment = false
environment = {{ {variable} = "not-the-bearer" }}

"#
            ),
        ];
        for ordinary in ordinary_surfaces {
            let error = compile(&shared.replace("[policy]", &format!("{ordinary}[policy]")))
                .expect_err("ordinary surfaces must not reuse identity locators");
            assert!(
                error.to_string().contains("must not"),
                "unexpected protected-locator error: {error}"
            );
            assert!(
                !error.to_string().contains(variable),
                "identity locator leaked in error: {error}"
            );
        }

        let inherited = r#"[authorization.providers.overlap]
kind = "process"
command = "/bin/true"
inherit_environment = true

"#;
        let error = compile(&shared.replace("[policy]", &format!("{inherited}[policy]")))
            .expect_err("whole-environment inheritance must fail with identity locators");
        assert!(
            error
                .to_string()
                .contains("inherit_environment: must be false"),
            "{error}"
        );

        let path = "/etc/acl-proxy/shared-identity-token";
        let file_baseline = file_identity_config(path);
        let file_parent = format!(
            r#"
[egress]
route = "parent_proxy"

[egress.parent_proxy]
kind = "acl_proxy"
url = "https://parent.example.test:8443"

[egress.parent_proxy.presentation]
kind = "bearer_file"
path = "{path}"

[egress.parent_proxy.tls]
trust = "system"

"#
        );
        let shared_file = file_baseline.replace("[policy]", &format!("{file_parent}[policy]"));
        compile(&shared_file).expect("resolver and typed parent may share one file locator");
        let generic_file = format!(
            r#"[credentials.sources.overlap]
source = "file"
path = "{path}"

"#
        );
        let error = compile(&shared_file.replace("[policy]", &format!("{generic_file}[policy]")))
            .expect_err("generic credential file must not reuse identity locator");
        assert!(
            error
                .to_string()
                .contains("must not overlap an identity token source"),
            "{error}"
        );
        assert!(!error.to_string().contains(path), "{error}");

        let process_command = r#"[authorization.providers.overlap]
kind = "process"
command = "shared-identity-token"

"#;
        let error =
            compile(&shared_file.replace("[policy]", &format!("{process_command}[policy]")))
                .expect_err("normalized process command must not reuse an identity locator");
        assert!(
            error
                .to_string()
                .contains("authorization.providers.overlap.command"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("must not overlap an identity token source"),
            "{error}"
        );
        assert!(!error.to_string().contains(path), "{error}");

        let origin_ca = r#"[egress.origin_tls]
trust = "custom"
ca_certificate = "shared-identity-token"
http_versions = ["http1"]

"#;
        let error = compile(&shared_file.replace("[policy]", &format!("{origin_ca}[policy]")))
            .expect_err("normalized TLS CA input must not reuse an identity locator");
        assert!(
            error
                .to_string()
                .contains("egress.origin_tls.ca_certificate"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("must not overlap an identity token source"),
            "{error}"
        );
        assert!(!error.to_string().contains(path), "{error}");
    }

    fn compile(toml: &str) -> Result<CompiledProductConfig, ConfigCompileError> {
        let config: super::super::authoring::AuthoringConfig =
            toml::from_str(toml).expect("test input should deserialize");
        compile_config(config, Path::new("/etc/acl-proxy"))
    }

    fn policy_rule_with_id(id: &str) -> String {
        format!(
            r#"{MINIMAL}
[[policy.rules]]
id = {id:?}
decision = "allow"
methods = ["GET"]
"#
        )
    }

    fn policy_rule_with_methods(methods: Vec<String>, include_url: bool) -> String {
        let urls = if include_url {
            r#"urls = ["https://example.test/**"]"#
        } else {
            ""
        };
        format!(
            r#"{MINIMAL}
[[policy.rules]]
id = "method-budget"
decision = "allow"
methods = {methods:?}
{urls}
"#
        )
    }

    fn header_predicate_config(kind: &str, values: Vec<String>) -> String {
        format!(
            r#"{MINIMAL}
[[policy.rules]]
id = "header-values"
decision = "allow"

[policy.rules.headers.{kind}]
x-contract = {values:?}
"#
        )
    }

    fn delegate_provider_config(provider: &str) -> String {
        format!(
            r#"{MINIMAL}
[authorization.providers.{provider}]
kind = "process"
command = "/bin/false"
retire_timeout = "30s"

[[policy.rules]]
id = "delegate-provider"
decision = "delegate"
methods = ["GET"]
authorization_provider = {provider:?}
"#
        )
    }

    fn literal_header_values_config(value_count: usize) -> String {
        let values = vec!["value".to_owned(); value_count];
        format!(
            r#"{MINIMAL}
[[egress.request_headers]]
operation = "set"
when = "always"
name = "x-many-values"
values = {values:?}
"#
        )
    }

    #[test]
    fn policy_validation_checks_provider_rule_id_boundaries() {
        assert_eq!(MAX_PROVIDER_RULE_ID_BYTES, StableId::MAX_LEN);
        let exact = "r".repeat(MAX_PROVIDER_RULE_ID_BYTES);
        compile(&policy_rule_with_id(&exact))
            .expect("the exact provider dispatch rule-ID boundary is valid");

        let oversized = "r".repeat(MAX_PROVIDER_RULE_ID_BYTES + 1);
        let error = compile(&policy_rule_with_id(&oversized))
            .expect_err("an oversized rule ID must fail policy validation");
        assert!(error.to_string().contains("policy.rules[0].id"), "{error}");
        assert!(
            error.to_string().contains(&format!(
                "at most {MAX_PROVIDER_RULE_ID_BYTES} bytes for authorization-provider dispatch"
            )),
            "{error}"
        );

        let error = compile(&policy_rule_with_id("bad\tid"))
            .expect_err("a control-containing rule stable ID must fail structural compilation");
        assert!(
            error.to_string().contains("invalid compiled ACL"),
            "{error}"
        );
    }

    #[test]
    fn structural_preflight_checks_provider_stable_id_boundaries() {
        let exact = "p".repeat(StableId::MAX_LEN);
        compile(&delegate_provider_config(&exact))
            .expect("the exact provider stable ID boundary is valid");

        let oversized = "p".repeat(StableId::MAX_LEN + 1);
        let error = compile(&delegate_provider_config(&oversized))
            .expect_err("an oversized provider stable ID must fail structural compilation");
        assert!(
            error.to_string().contains("invalid compiled ACL"),
            "{error}"
        );
    }

    #[test]
    fn structural_preflight_checks_combined_semantic_predicate_boundaries() {
        let exact_methods = (0..http_access_policy_acl::MAX_SEMANTIC_PREDICATES_PER_RULE - 1)
            .map(|index| format!("M{index}"))
            .collect();
        compile(&policy_rule_with_methods(exact_methods, true))
            .expect("one URL plus the remaining methods is the exact shared boundary");

        let oversized_methods = (0..http_access_policy_acl::MAX_SEMANTIC_PREDICATES_PER_RULE)
            .map(|index| format!("M{index}"))
            .collect();
        let error = compile(&policy_rule_with_methods(oversized_methods, true))
            .expect_err("combined semantic predicates above the shared bound must fail");
        assert!(
            error.to_string().contains("invalid compiled ACL"),
            "{error}"
        );
    }

    #[test]
    fn structural_preflight_checks_neutral_method_length_boundaries() {
        compile(&policy_rule_with_methods(vec!["M".repeat(64)], false))
            .expect("the exact neutral method length boundary is valid");

        let error = compile(&policy_rule_with_methods(vec!["M".repeat(65)], false))
            .expect_err("a method above the neutral length bound must fail");
        assert!(
            error.to_string().contains("invalid compiled ACL"),
            "{error}"
        );
    }

    #[test]
    fn structural_preflight_checks_header_predicate_value_boundaries() {
        compile(&header_predicate_config("all", vec!["v".repeat(64 * 1024)]))
            .expect("the exact shared header predicate value boundary is valid");

        let error = compile(&header_predicate_config(
            "none",
            vec!["v".repeat(64 * 1024 + 1)],
        ))
        .expect_err("a header predicate value above the shared bound must fail");
        assert!(
            error.to_string().contains("invalid compiled ACL"),
            "{error}"
        );
    }

    #[test]
    fn structural_preflight_checks_header_predicate_group_boundaries() {
        let exact = vec!["g".repeat(64 * 1024); 16];
        compile(&header_predicate_config("all", exact))
            .expect("the exact shared header predicate group boundary is valid");

        let mut oversized = vec!["g".repeat(64 * 1024); 16];
        oversized.push("x".to_owned());
        let error = compile(&header_predicate_config("none", oversized))
            .expect_err("a header predicate group above the shared bound must fail");
        assert!(
            error.to_string().contains("invalid compiled ACL"),
            "{error}"
        );
    }

    #[test]
    fn structural_preflight_covers_non_acl_generation_contracts() {
        compile(&literal_header_values_config(256))
            .expect("the exact shared header-mutation value-count boundary is valid");

        let error = compile(&literal_header_values_config(257))
            .expect_err("full preflight must reject a non-ACL generation contract violation");
        assert!(error.to_string().contains("header mutation"), "{error}");
    }

    #[test]
    fn pure_compiler_rejects_regexes_outside_the_bounded_dfa_subset() {
        let input = format!(
            r#"{MINIMAL}

[redaction.profiles.secrets]
rules = [{{ expressions = ['\bsecret-marker\b'] }}]
"#
        );
        let error = compile(&input).expect_err("Unicode word boundaries require runtime caches");
        let rendered = format!("{error:?} {error}");
        assert!(rendered.contains("redaction.profiles.secrets.rules[0].expressions[0]"));
        assert!(rendered.contains("invalid bounded redaction expression"));
        assert!(!rendered.contains("secret-marker"));
    }

    #[test]
    fn authored_literal_horizon_is_rejected_during_pure_compilation() {
        let literal =
            "x".repeat(MAX_MATCHER_SCRATCH_BYTES / (std::mem::size_of::<usize>() * 2) + 1);
        let input = format!(
            r#"{MINIMAL}

[redaction.profiles.secrets]
rules = [{{ literals = ["{literal}"] }}]
"#
        );
        let error = compile(&input)
            .expect_err("the literal exceeds the scratch-derived single-literal ceiling");
        let rendered = format!("{error:?} {error}");
        assert_eq!(
            error.path,
            "redaction.profiles.secrets.rules[0].literals[0]"
        );
        assert_eq!(error.message, "invalid redaction literal");
        assert!(!rendered.contains(&literal));
    }

    #[test]
    fn configured_environment_horizon_is_rejected_during_pure_compilation() {
        let input = format!(
            r#"{MINIMAL}

[redaction.profiles.secrets]
max_environment_literal_bytes = 65537
rules = [{{ literal_environment_variables = ["TEST_REDACTION_SECRET"] }}]
"#
        );
        let error = compile(&input).expect_err("the configured source horizon exceeds scratch");
        assert_eq!(
            error.path,
            "redaction.profiles.secrets.max_environment_literal_bytes"
        );
        assert_eq!(error.message, "must be between 1 and 65536");
    }

    fn resource_config(service: &str, definitions: &str, rules: &str) -> String {
        format!(
            r#"
schema_version = 3

[service]
request_timeout = "1s"
{service}

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

{definitions}

[policy]
default = "deny"

{rules}
"#
        )
    }

    fn guarded(payload_bytes: usize) -> usize {
        guarded_body_allocation_bytes(payload_bytes)
            .expect("test payload must have a guarded allocation projection")
    }

    fn default_runtime_replay_storage() -> usize {
        usize::try_from(
            BodyBudget::required_replay_storage_bytes(
                u64::try_from(50 * MIB).unwrap(),
                u64::try_from(64 * 1024).unwrap(),
                4_096,
                u64::try_from(MIB).unwrap(),
                None,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn canonical_runtime_replay_storage(decoded_bytes: usize) -> usize {
        canonical_runtime_replay_storage_for(50 * MIB, 64 * 1024, decoded_bytes)
    }

    fn canonical_runtime_replay_storage_for(
        source_bytes: usize,
        chunk_bytes: usize,
        decoded_bytes: usize,
    ) -> usize {
        usize::try_from(
            BodyBudget::required_replay_storage_bytes(
                u64::try_from(source_bytes).unwrap(),
                u64::try_from(chunk_bytes).unwrap(),
                0,
                0,
                Some(u64::try_from(decoded_bytes).unwrap()),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn body_read_limits(plan: HttpBodyReadPlan) -> Option<(usize, usize)> {
        plan.limits()
            .map(|limits| (limits.max_encoded_bytes(), limits.max_decoded_bytes()))
    }

    #[test]
    fn forwarding_plan_compiles_exact_reloadable_fields() {
        let compiled = compile(&resource_config(
            r#"
[service.forwarding]
connect_timeout = "1s"
response_head_timeout = "2s"
body_idle_timeout = "3s"
upgrade_idle_timeout = "4s"
max_request_wire_bytes = 1048576
max_request_decoded_bytes = 2097152
max_response_wire_bytes = 3145728
max_response_decoded_bytes = 4194304
chunk_bytes = 65536
preserve_request_trailers = false
max_trailer_count = 128
max_trailer_bytes = 131072
"#,
            "",
            "",
        ))
        .unwrap();

        assert_eq!(
            compiled.reloadable_plan.forwarding,
            ForwardingPlan {
                connect_timeout: Duration::from_secs(1),
                response_head_timeout: Duration::from_secs(2),
                body_idle_timeout: Duration::from_secs(3),
                upgrade_idle_timeout: Duration::from_secs(4),
                max_request_wire_bytes: MIB,
                max_request_decoded_bytes: 2 * MIB,
                max_response_wire_bytes: 3 * MIB,
                max_response_decoded_bytes: 4 * MIB,
                chunk_bytes: 64 * 1024,
                preserve_request_trailers: false,
                max_trailer_count: 128,
                max_trailer_bytes: 128 * 1024,
            }
        );
    }

    #[test]
    fn runtime_replay_budget_exists_only_for_forwarding_or_observing_paths() {
        let allow = compile(&resource_config(
            "",
            "",
            r#"
[[policy.rules]]
id = "allow"
decision = "allow"
methods = ["GET"]
"#,
        ))
        .unwrap();
        let replay = default_runtime_replay_storage();
        assert_eq!(
            allow
                .reloadable_plan
                .resource_plan
                .runtime_replay_capacities_for_test(),
            [replay, 0]
        );

        let default_allow = compile(
            &resource_config("", "", "").replace("default = \"deny\"", "default = \"allow\""),
        )
        .unwrap();
        assert_eq!(
            default_allow
                .reloadable_plan
                .resource_plan
                .runtime_replay_capacities_for_test(),
            [replay]
        );

        let deny = compile(&resource_config("", "", "")).unwrap();
        assert_eq!(
            deny.reloadable_plan
                .resource_plan
                .runtime_replay_capacities_for_test(),
            [0]
        );
        assert_eq!(
            deny.reloadable_plan
                .resource_plan
                .wire_body_full_peak_capacity,
            Capacity::Unbounded
        );
    }

    #[test]
    fn forwarding_limits_and_mandatory_request_bounds_fail_closed() {
        for (assignment, expected) in [
            ("connect_timeout = \"601s\"", "must not exceed 10 minutes"),
            (
                "max_response_wire_bytes = 1073741825",
                "must be between 1 and 1073741824",
            ),
        ] {
            let input = resource_config(&format!("[service.forwarding]\n{assignment}"), "", "");
            let error = compile(&input).expect_err("forwarding ceiling must be enforced");
            assert!(error.to_string().contains(expected), "{error}");
        }

        let definitions = r#"
[authorization.providers.body]
kind = "process"
command = "/bin/body-provider"
include_request_body = true
max_request_body_bytes = 2
max_decoded_request_body_bytes = 3
retire_timeout = "1s"
"#;
        let rules = r#"
[[policy.rules]]
id = "body"
decision = "delegate"
methods = ["POST"]
authorization_provider = "body"
"#;
        for (field, expected) in [
            (
                "max_request_wire_bytes",
                "must cover every reachable mandatory request wire-body limit",
            ),
            (
                "max_request_decoded_bytes",
                "must cover every reachable mandatory decoded request-body limit",
            ),
        ] {
            let wire = if field == "max_request_wire_bytes" {
                1
            } else {
                3
            };
            let decoded = if field == "max_request_decoded_bytes" {
                1
            } else {
                3
            };
            let service = format!(
                "[service.forwarding]\nmax_request_wire_bytes = {wire}\nmax_request_decoded_bytes = {decoded}\nmax_response_wire_bytes = 3\nmax_response_decoded_bytes = 3\nchunk_bytes = 1"
            );
            let error = compile(&resource_config(&service, definitions, rules))
                .expect_err("undersized forwarding request bound must fail");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn runtime_chunk_quotient_accepts_equality_and_rejects_excess_and_overflow() {
        let equality = resource_config(
            r#"
[service.forwarding]
max_request_wire_bytes = 65536
max_request_decoded_bytes = 65536
max_response_wire_bytes = 65536
max_response_decoded_bytes = 65536
chunk_bytes = 1
"#,
            "",
            "",
        );
        compile(&equality).expect("exactly 65,536 runtime chunks are representable");

        for (field, replacement) in [
            (
                "max_request_wire_bytes = 65536",
                "max_request_wire_bytes = 65537",
            ),
            (
                "max_response_decoded_bytes = 65536",
                "max_response_decoded_bytes = 65537",
            ),
        ] {
            let excess = equality.replace(field, replacement);
            let error = compile(&excess).expect_err("a 65,537th runtime chunk must be rejected");
            assert!(error
                .to_string()
                .contains("more than 65536 runtime body chunks"));
        }

        let overflow = validate_runtime_chunk_quotient("test.body", usize::MAX, 2)
            .expect_err("chunk quotient arithmetic must be checked");
        assert!(overflow
            .to_string()
            .contains("runtime chunk quotient overflow"));
    }

    #[test]
    fn capture_runtime_chunk_quotient_is_validated_independently() {
        let input = resource_config(
            r#"
[service.forwarding]
max_request_wire_bytes = 1
max_request_decoded_bytes = 1
max_response_wire_bytes = 1
max_response_decoded_bytes = 1
chunk_bytes = 1
"#,
            r#"
[redaction.profiles.capture]
max_body_bytes = 65537
max_decoded_body_bytes = 65537
rules = [{ literals = ["secret"] }]

[observation.capture]
events = ["request.allowed"]
redaction_profile = "capture"
directory = "captures"
max_inflight_body_bytes = 134217728
"#,
            "",
        );
        let error = compile(&input).expect_err("capture must obey the runtime chunk ceiling");
        assert!(error
            .to_string()
            .contains("more than 65536 runtime body chunks"));
    }

    #[test]
    fn body_read_plans_are_explicitly_disabled_without_mandatory_inspection() {
        let compiled = compile(&resource_config(
            "",
            "",
            r#"
[[policy.rules]]
id = "metadata-only"
decision = "allow"
methods = ["GET"]
"#,
        ))
        .unwrap();
        let plans = &compiled
            .reloadable_plan
            .policy
            .http_body_read_plans_by_cursor;

        assert_eq!(plans, &[HttpBodyReadPlan::Disabled; 2]);
        assert!(!plans[0].requires_mandatory_read());
        assert_eq!(plans[0].limits(), None);
    }

    #[test]
    fn exact_rule_body_read_plan_uses_provider_profile_minima() {
        let compiled = compile(&resource_config(
            "",
            r#"
[authorization.providers.body]
kind = "process"
command = "/bin/body-provider"
include_request_body = true
max_request_body_bytes = 16
max_decoded_request_body_bytes = 32
retire_timeout = "1s"

[redaction.profiles.strict]
max_body_bytes = 8
max_decoded_body_bytes = 24
rules = [{ literals = ["secret"] }]
"#,
            r#"
[[policy.rules]]
id = "combined"
decision = "delegate"
authorization_provider = "body"
redaction_profile = "strict"
methods = ["POST"]
"#,
        ))
        .unwrap();
        let plans = &compiled
            .reloadable_plan
            .policy
            .http_body_read_plans_by_cursor;

        assert!(plans[0].requires_mandatory_read());
        assert_eq!(body_read_limits(plans[0]), Some((8, 24)));
        assert_eq!(plans[1], HttpBodyReadPlan::Disabled);
    }

    #[test]
    fn delegate_suffix_body_read_plan_uses_independent_component_maxima() {
        let compiled = compile(&resource_config(
            "",
            r#"
[authorization.providers.wide-encoded]
kind = "process"
command = "/bin/wide-encoded"
include_request_body = true
max_request_body_bytes = 16
max_decoded_request_body_bytes = 16
retire_timeout = "1s"

[authorization.providers.wide-decoded]
kind = "process"
command = "/bin/wide-decoded"
include_request_body = true
max_request_body_bytes = 8
max_decoded_request_body_bytes = 32
retire_timeout = "1s"
"#,
            r#"
[[policy.rules]]
id = "first"
decision = "delegate"
authorization_provider = "wide-encoded"
methods = ["POST"]

[[policy.rules]]
id = "continuation"
decision = "delegate"
authorization_provider = "wide-decoded"
methods = ["POST"]
"#,
        ))
        .unwrap();
        let plans = &compiled
            .reloadable_plan
            .policy
            .http_body_read_plans_by_cursor;

        assert_eq!(body_read_limits(plans[0]), Some((16, 32)));
        assert_eq!(body_read_limits(plans[1]), Some((8, 32)));
        assert_eq!(plans[2], HttpBodyReadPlan::Disabled);
    }

    #[test]
    fn merged_suffix_body_read_plan_is_folded_into_cursor_peak() {
        let first_encoded = 16 * MIB;
        let first_decoded = 16 * MIB;
        let later_encoded = 8 * MIB;
        let later_decoded = 32 * MIB;
        let definitions = format!(
            r#"
[authorization.providers.wide-encoded]
kind = "process"
command = "/bin/wide-encoded"
include_request_body = true
max_request_body_bytes = {first_encoded}
max_decoded_request_body_bytes = {first_decoded}
retire_timeout = "1s"

[authorization.providers.wide-decoded]
kind = "process"
command = "/bin/wide-decoded"
include_request_body = true
max_request_body_bytes = {later_encoded}
max_decoded_request_body_bytes = {later_decoded}
retire_timeout = "1s"
"#
        );
        let compiled = compile(&resource_config(
            "",
            &definitions,
            r#"
[[policy.rules]]
id = "first"
decision = "delegate"
authorization_provider = "wide-encoded"
methods = ["POST"]

[[policy.rules]]
id = "continuation"
decision = "delegate"
authorization_provider = "wide-decoded"
methods = ["POST"]
"#,
        ))
        .unwrap();
        let peaks = &compiled
            .reloadable_plan
            .resource_plan
            .combined_http_body_peaks_for_test();
        let merged = decode_peak(first_encoded, later_decoded).unwrap();
        let replay = canonical_runtime_replay_storage(later_decoded);

        assert!(peaks[0] >= merged);
        assert!(peaks[0] >= replay);
        assert!(peaks[1] >= decode_peak(later_encoded, later_decoded).unwrap());
        assert!(merged > decode_peak(first_encoded, first_decoded).unwrap());
        assert!(peaks[0] >= peaks[1]);
    }

    #[test]
    fn upstream_body_free_delegate_holds_merged_body_across_provider_stages() {
        let later_limit = 1;
        let input = resource_config(
            "",
            &format!(
                r#"
[authorization.providers.first]
kind = "process"
command = "/bin/first-provider"
max_stdout_line_bytes = {MAX_PROCESS_STDOUT_LINE_BYTES}
retire_timeout = "1s"

[authorization.providers.later]
kind = "process"
command = "/bin/later-provider"
include_request_body = true
max_request_body_bytes = {later_limit}
max_decoded_request_body_bytes = {later_limit}
max_stdout_line_bytes = 80
retire_timeout = "1s"
"#,
            ),
            r#"
[[policy.rules]]
id = "first"
decision = "delegate"
methods = ["POST"]
authorization_provider = "first"

[[policy.rules]]
id = "later"
decision = "delegate"
methods = ["POST"]
authorization_provider = "later"
"#,
        );
        let authored: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let first = compile_http_rule_schedule(&authored, &authored.policy.rules[0]).unwrap();
        let later = compile_http_rule_schedule(&authored, &authored.policy.rules[1]).unwrap();
        let compiled = compile(&input).unwrap();
        let merged_original = guarded(later_limit);
        let decode = decode_peak(later_limit, later_limit).unwrap();
        let body_free_provider_stage = first.max_incoming_additional_bytes();
        let required_overlap = merged_original
            + body_free_provider_stage
            + canonical_runtime_replay_storage(later_limit);

        assert_eq!(first.local_body_allocation, None);
        assert_eq!(later.local_body_allocation, Some(merged_original));
        assert_eq!(
            body_free_provider_stage,
            guarded(
                provider_response_guarded_suffix_bytes(
                    MAX_PROCESS_STDOUT_LINE_BYTES,
                    "authorization.providers.first.max_stdout_line_bytes",
                )
                .unwrap()
            )
        );
        assert!(body_free_provider_stage > guarded(PROVIDER_REQUEST_STREAM_SCRATCH_BYTES));
        let first_peak = compiled
            .reloadable_plan
            .resource_plan
            .combined_http_body_peaks_for_test()[0];
        assert!(
            first_peak >= required_overlap,
            "compiled peak {first_peak} omitted merged body-free overlap {required_overlap}"
        );
        assert!(first_peak >= decode + canonical_runtime_replay_storage(later_limit));
    }

    #[test]
    fn dominant_body_free_stage_adds_the_merged_body_allocation() {
        let input = resource_config(
            "",
            "",
            r#"
[[policy.rules]]
id = "body-free-delegate"
decision = "delegate"
methods = ["POST"]
"#,
        );
        let authored: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let merged_original = guarded(MIB);
        let decode = decode_peak(MIB, MIB).unwrap();
        let body_free_provider_stage = decode + guarded(1);
        let schedule = HttpRuleAllocationSchedule {
            initial_peak: 0,
            local_body_allocation: None,
            retained_original_after_pass: None,
            replacement_decoded_limit: None,
            incoming_stages: vec![IncomingBodyStage {
                additional_bytes: body_free_provider_stage,
            }],
            webhook_request_allocation: None,
            webhook_callback_allocation: None,
        };
        let limits = HttpBodyReadLimits::try_new(MIB, MIB).unwrap();

        let path = compile_reachable_http_path(
            &authored,
            &schedule,
            &authored.policy.rules[0],
            ReachableHttpPath::default(),
            HttpBodyReadPlan::Mandatory(limits),
            0,
            0,
        )
        .unwrap();

        assert_eq!(
            path.product_peak_bytes,
            merged_original + body_free_provider_stage
        );
        assert_eq!(path.body_free_stage_peak_bytes, body_free_provider_stage);
    }

    #[test]
    fn provider_outputs_over_shared_raw_batch_limit_are_rejected() {
        let output_count = MAX_TEST_PROVIDER_OUTPUTS_WITHIN_SHARED_RAW_BATCH + 1;
        let output_headers = (0..output_count)
            .map(|index| format!("\"x-output-{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let outputs = (0..output_count)
            .map(|index| {
                format!(
                    r#"
[authorization.providers.provider.outputs.value_{index}]
kind = "custom_header"
transport_security = "cleartext_allowed"
header = "x-output-{index}"
"#,
                )
            })
            .collect::<String>();
        let definitions = format!(
            r#"
[credentials]
allowed_custom_headers = [{output_headers}]

[authorization.providers.provider]
kind = "process"
command = "/bin/provider"
retire_timeout = "1s"
{outputs}
"#,
        );
        let input = resource_config(
            "",
            &definitions,
            r#"
[[policy.rules]]
id = "provider"
decision = "delegate"
authorization_provider = "provider"
methods = ["GET"]
"#,
        );

        let error = compile(&input).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("shared credential resource limits are exceeded"),
            "{error}"
        );
    }

    #[test]
    fn method_incompatible_skipped_rule_does_not_inherit_later_body_read() {
        let compiled = compile(&resource_config(
            "",
            r#"
[authorization.providers.body]
kind = "process"
command = "/bin/body-provider"
include_request_body = true
max_request_body_bytes = 12
max_decoded_request_body_bytes = 36
retire_timeout = "1s"
"#,
            r#"
[[policy.rules]]
id = "get-only"
decision = "deny"
methods = ["GET"]

[[policy.rules]]
id = "post-provider"
decision = "delegate"
authorization_provider = "body"
methods = ["POST"]
"#,
        ))
        .unwrap();
        let plans = &compiled
            .reloadable_plan
            .policy
            .http_body_read_plans_by_cursor;

        assert_eq!(plans[0], HttpBodyReadPlan::Disabled);
        assert_eq!(body_read_limits(plans[1]), Some((12, 36)));
        assert_eq!(plans[2], HttpBodyReadPlan::Disabled);
    }

    #[test]
    fn body_read_limits_reject_zero_and_inverted_bounds() {
        assert!(HttpBodyReadLimits::try_new(0, 1).is_none());
        assert!(HttpBodyReadLimits::try_new(1, 0).is_none());
        assert!(HttpBodyReadLimits::try_new(2, 1).is_none());
        assert_eq!(
            HttpBodyReadLimits::try_new(1, 1)
                .map(|limits| (limits.max_encoded_bytes(), limits.max_decoded_bytes(),)),
            Some((1, 1))
        );
    }

    fn webhook_config(max_request_bytes: usize, max_response_bytes: usize) -> String {
        format!(
            r#"
schema_version = 3

[control]
bind = "127.0.0.1:8898"
max_request_body_bytes = 65536

[authorization.callback]
public_url = "http://127.0.0.1:8898/_acl-proxy/external-auth/callback"

[authorization.providers.approval]
kind = "webhook"
url = "https://approval.example.test/authorize"
max_request_bytes = {max_request_bytes}
max_response_bytes = {max_response_bytes}

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "approval"
decision = "delegate"
authorization_provider = "approval"
methods = ["POST"]
"#
        )
    }

    fn identity_webhook_config(max_request_bytes: usize) -> String {
        webhook_config(max_request_bytes, MIN_CALLBACK_RESPONSE_BYTES)
            .replace(
                "url = \"https://approval.example.test/authorize\"",
                "url = \"https://approval.example.test/authorize\"\ninclude_identity = true",
            )
            .replace(
                "[listeners.explicit_http.connect]",
                r#"[listeners.explicit_http.identity]
mode = "required"

[identity]
max_pending_authentications = 8
max_pending_authentications_per_connection = 2

[identity.resolver]
kind = "static"
authority = "test-authority"

[[identity.resolver.principals]]
id = "test-principal"
kind = "service_account"

[[identity.resolver.groups]]
id = "developers"
members = ["test-principal"]

[[identity.resolver.tokens]]
id = "test-token"
principal = "test-principal"
source = "environment"
variable = "AW_IDENTITY_TOKEN"

[listeners.explicit_http.connect]"#,
            )
    }

    #[test]
    fn l05_provider_identity_projection_is_strictly_opt_in() {
        for explicit_false in [false, true] {
            let mut webhook = webhook_config(65_536, MIN_CALLBACK_RESPONSE_BYTES);
            if explicit_false {
                webhook = webhook.replace(
                    "url = \"https://approval.example.test/authorize\"",
                    "url = \"https://approval.example.test/authorize\"\ninclude_identity = false",
                );
            }
            let compiled = compile(&webhook).expect("webhook provider must compile");
            let AuthorizationProviderPlan::Webhook(provider) =
                &compiled.reloadable_plan.authorization.providers["approval"]
            else {
                panic!("expected webhook provider");
            };
            assert!(!provider.include_identity);

            let include_identity = if explicit_false {
                "include_identity = false\n"
            } else {
                ""
            };
            let process = MINIMAL.replace(
                "[policy]",
                &format!(
                    r#"[authorization.providers.local]
kind = "process"
command = "/bin/authorize"
{include_identity}
[policy]"#
                ),
            );
            let compiled = compile(&process).expect("process provider must compile");
            let AuthorizationProviderPlan::Process(provider) =
                &compiled.reloadable_plan.authorization.providers["local"]
            else {
                panic!("expected process provider");
            };
            assert!(!provider.include_identity);
        }
    }

    fn unix_socket_provider_config() -> String {
        MINIMAL.replace(
            "[policy]",
            r#"[authorization.providers.local]
kind = "unix_socket"
socket_path = "/run/acl-proxy/authorization.sock"
timeout = "2s"
on_failure = "deny"
include_headers = ["x-safe-provider-input"]
include_identity = true
max_request_bytes = 262144
max_response_bytes = 65536
max_pending_requests = 128
peer_uid = 501

[authorization.providers.local.outputs.api_token]
kind = "bearer"
transport_security = "tls_required"
required = true

[policy]"#,
        )
    }

    fn identity_unix_socket_provider_config(max_request_bytes: usize) -> String {
        unix_socket_provider_config()
            .replace(
                "max_request_bytes = 262144",
                &format!("max_request_bytes = {max_request_bytes}"),
            )
            .replace(
                "[listeners.explicit_http.connect]",
                r#"[listeners.explicit_http.identity]
mode = "required"

[identity]
max_pending_authentications = 8
max_pending_authentications_per_connection = 2

[identity.resolver]
kind = "static"
authority = "test-authority"

[[identity.resolver.principals]]
id = "test-principal"
kind = "service_account"

[[identity.resolver.groups]]
id = "developers"
members = ["test-principal"]

[[identity.resolver.tokens]]
id = "test-token"
principal = "test-principal"
source = "environment"
variable = "AW_IDENTITY_TOKEN"

[listeners.explicit_http.connect]"#,
            )
    }

    #[test]
    fn unix_socket_provider_compiles_exact_path_framing_allocations_and_outputs() {
        let compiled = compile(&unix_socket_provider_config()).unwrap();
        let provider = match &compiled.reloadable_plan.authorization.providers["local"] {
            AuthorizationProviderPlan::UnixSocket(provider) => provider,
            AuthorizationProviderPlan::Webhook(_) | AuthorizationProviderPlan::Process(_) => {
                panic!("expected Unix socket provider")
            }
        };
        assert_eq!(
            provider.socket_path,
            PathBuf::from("/run/acl-proxy/authorization.sock")
        );
        assert_eq!(provider.timeout, Duration::from_secs(2));
        assert!(provider.on_failure == CompiledProviderFailureMode::Deny);
        assert_eq!(
            provider.include_headers,
            [HeaderName::from_static("x-safe-provider-input")]
        );
        assert!(provider.include_identity);
        assert_eq!(provider.frame_protocol.magic(), UNIX_PROVIDER_MAGIC);
        assert_eq!(
            provider.frame_protocol.version(),
            UNIX_PROVIDER_WIRE_VERSION
        );
        assert_eq!(provider.frame_protocol.request_limit().get(), 262_144);
        assert_eq!(provider.frame_protocol.response_limit().get(), 65_536);
        assert_eq!(provider.request_frame_bytes, 262_144 + 10);
        assert_eq!(provider.response_frame_bytes, 65_536 + 10);
        assert_eq!(provider.request_allocation_bytes, guarded(262_144));
        assert_eq!(provider.response_allocation_bytes, guarded(65_536));
        assert_eq!(provider.max_pending_requests, 128);
        assert_eq!(provider.peer_uid, Some(501));
        assert_eq!(provider.outputs.len(), 1);
        assert!(matches!(
            provider.outputs["api_token"],
            ProviderOutputPlan::Bearer {
                required: true,
                transport_security: CompiledTransportSecurity::TlsRequired
            }
        ));
        let credential_allocation = compact_provider_credential_allocation(1, 65_536).unwrap();
        assert_eq!(
            provider.max_inflight_allocation_bytes,
            128 * (guarded(262_144) + guarded(65_536) + credential_allocation)
        );
    }

    #[test]
    fn unix_socket_provider_schedule_adds_request_response_and_credential_relocation() {
        let input = format!(
            r#"{}

[[policy.rules]]
id = "unix-provider"
decision = "delegate"
methods = ["GET"]
authorization_provider = "local"
"#,
            unix_socket_provider_config()
                .replace("include_identity = true", "include_identity = false")
                .replace(
                    "max_request_bytes = 262144",
                    &format!("max_request_bytes = {MIN_UNIX_PROVIDER_REQUEST_BYTES}"),
                )
                .replace(
                    "max_response_bytes = 65536",
                    &format!("max_response_bytes = {MIN_UNIX_PROVIDER_RESPONSE_BYTES}"),
                )
        );
        let authored: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let schedule = compile_http_rule_schedule(&authored, &authored.policy.rules[0]).unwrap();
        let credential_allocation =
            compact_provider_credential_allocation(1, MIN_UNIX_PROVIDER_RESPONSE_BYTES).unwrap();
        let provider_peak = guarded(MIN_UNIX_PROVIDER_REQUEST_BYTES)
            + guarded(MIN_UNIX_PROVIDER_RESPONSE_BYTES)
            + credential_allocation;
        let finalization_peak =
            compile_credential_finalization_peak(&authored, Some(&authored.policy.rules[0]))
                .unwrap();

        assert_eq!(schedule.initial_peak, provider_peak + finalization_peak);
        assert_eq!(
            schedule.max_incoming_additional_bytes(),
            provider_peak + finalization_peak
        );
    }

    #[test]
    fn unix_socket_provider_rejects_path_limit_header_and_nonprocess_crossovers() {
        let baseline = unix_socket_provider_config();
        for (name, input, path) in [
            (
                "relative path",
                baseline.replace(
                    "/run/acl-proxy/authorization.sock",
                    "run/acl-proxy/authorization.sock",
                ),
                "authorization.providers.local.socket_path",
            ),
            (
                "non-normalized path",
                baseline.replace(
                    "/run/acl-proxy/authorization.sock",
                    "/run/acl-proxy/../authorization.sock",
                ),
                "authorization.providers.local.socket_path",
            ),
            (
                "path with duplicate separator",
                baseline.replace(
                    "/run/acl-proxy/authorization.sock",
                    "/run//acl-proxy/authorization.sock",
                ),
                "authorization.providers.local.socket_path",
            ),
            (
                "path with current-directory component",
                baseline.replace(
                    "/run/acl-proxy/authorization.sock",
                    "/run/./acl-proxy/authorization.sock",
                ),
                "authorization.providers.local.socket_path",
            ),
            (
                "path with trailing separator",
                baseline.replace(
                    "/run/acl-proxy/authorization.sock",
                    "/run/acl-proxy/authorization.sock/",
                ),
                "authorization.providers.local.socket_path",
            ),
            (
                "root path",
                baseline.replace("/run/acl-proxy/authorization.sock", "/"),
                "authorization.providers.local.socket_path",
            ),
            (
                "request limit below minimum envelope",
                baseline.replace(
                    "max_request_bytes = 262144",
                    &format!(
                        "max_request_bytes = {}",
                        MIN_UNIX_PROVIDER_REQUEST_BYTES - 1
                    ),
                ),
                "authorization.providers.local.max_request_bytes",
            ),
            (
                "oversized request limit",
                baseline.replace(
                    "max_request_bytes = 262144",
                    &format!("max_request_bytes = {}", MAX_UNIX_PROVIDER_BODY_BYTES + 1),
                ),
                "authorization.providers.local.max_request_bytes",
            ),
            (
                "response limit below minimum envelope",
                baseline.replace(
                    "max_response_bytes = 65536",
                    &format!(
                        "max_response_bytes = {}",
                        MIN_UNIX_PROVIDER_RESPONSE_BYTES - 1
                    ),
                ),
                "authorization.providers.local.max_response_bytes",
            ),
            (
                "zero pending limit",
                baseline.replace("max_pending_requests = 128", "max_pending_requests = 0"),
                "authorization.providers.local.max_pending_requests",
            ),
            (
                "oversized pending limit",
                baseline.replace(
                    "max_pending_requests = 128",
                    &format!(
                        "max_pending_requests = {}",
                        MAX_UNIX_PROVIDER_PENDING_REQUESTS + 1
                    ),
                ),
                "authorization.providers.local.max_pending_requests",
            ),
            (
                "oversized timeout",
                baseline.replace("timeout = \"2s\"", "timeout = \"601s\""),
                "authorization.providers.local.timeout",
            ),
            (
                "protected header",
                baseline.replace("x-safe-provider-input", "authorization"),
                "authorization.providers.local.include_headers[0]",
            ),
        ] {
            let error = compile(&input).expect_err(name);
            assert_eq!(error.path, path, "{name}: {error}");
        }

        compile(
            &baseline
                .replace("include_identity = true", "include_identity = false")
                .replace(
                    "max_request_bytes = 262144",
                    &format!("max_request_bytes = {MIN_UNIX_PROVIDER_REQUEST_BYTES}"),
                )
                .replace(
                    "max_response_bytes = 65536",
                    &format!("max_response_bytes = {MIN_UNIX_PROVIDER_RESPONSE_BYTES}"),
                ),
        )
        .expect("exact minimum AWAP envelopes compile");

        let oversized_path = format!("/{}", "p".repeat(MAX_UNIX_SOCKET_PATH_BYTES));
        let error =
            compile(&baseline.replace("/run/acl-proxy/authorization.sock", &oversized_path))
                .expect_err("Unix socket paths are target bounded");
        assert_eq!(error.path, "authorization.providers.local.socket_path");

        let inbound = baseline.replace(
            "[policy]",
            r#"[credentials.inbound.provider_input]
header = "x-safe-provider-input"
process_providers = ["local"]

[policy]"#,
        );
        let error = compile(&inbound)
            .expect_err("Unix providers do not acquire process-only inbound credentials");
        assert_eq!(
            error.path,
            "credentials.inbound.provider_input.process_providers"
        );
        assert!(error.message.contains("must name a process provider"));
    }

    #[test]
    fn unix_socket_provider_identity_projection_uses_the_shared_exact_outer_object_bound() {
        let authored: super::super::authoring::AuthoringConfig =
            toml::from_str(&identity_unix_socket_provider_config(262_144)).unwrap();
        let projection = compile_identity_plan(authored.identity.as_ref())
            .unwrap()
            .unwrap()
            .resources
            .max_provider_projection_bytes;
        let identity_member = maximum_provider_identity_member_bytes(&authored).unwrap();
        assert_eq!(u64::try_from(identity_member + 1).unwrap(), projection);

        let minimum = MIN_UNIX_PROVIDER_REQUEST_BYTES
            .checked_add(identity_member)
            .unwrap();
        compile(&identity_unix_socket_provider_config(minimum))
            .expect("the exact complete identity projection boundary must compile");
        let error = compile(&identity_unix_socket_provider_config(minimum - 1))
            .expect_err("one byte below the complete identity projection must fail");
        assert!(
            error.to_string().contains(&format!("at least {minimum}")),
            "{error}"
        );
    }

    #[test]
    fn webhook_minimum_request_envelope_limits_compile() {
        const CALLBACK_URL: &str = "http://127.0.0.1:8898/_acl-proxy/external-auth/callback";
        let minimum = MIN_WEBHOOK_REQUEST_WITHOUT_CALLBACK_URL_BYTES + CALLBACK_URL.len();
        let compiled = compile(&webhook_config(minimum, MIN_CALLBACK_RESPONSE_BYTES))
            .expect("the exact compact request-envelope floor must compile");
        let provider = match &compiled.reloadable_plan.authorization.providers["approval"] {
            AuthorizationProviderPlan::Webhook(provider) => provider,
            AuthorizationProviderPlan::Process(_) | AuthorizationProviderPlan::UnixSocket(_) => {
                panic!("expected webhook provider")
            }
        };
        assert_eq!(provider.max_request_bytes, minimum);

        let error = compile(&webhook_config(minimum - 1, MIN_CALLBACK_RESPONSE_BYTES))
            .expect_err("one byte below the exact compact request envelope must fail");
        assert!(error.to_string().contains(&format!("at least {minimum}")));
    }

    #[test]
    fn l05_webhook_identity_projection_uses_the_shared_exact_outer_object_bound() {
        const CALLBACK_URL: &str = "http://127.0.0.1:8898/_acl-proxy/external-auth/callback";
        let authored: super::super::authoring::AuthoringConfig =
            toml::from_str(&identity_webhook_config(65_536)).unwrap();
        let projection = compile_identity_plan(authored.identity.as_ref())
            .unwrap()
            .unwrap()
            .resources
            .max_provider_projection_bytes;
        let identity_member = maximum_provider_identity_member_bytes(&authored).unwrap();
        assert_eq!(u64::try_from(identity_member + 1).unwrap(), projection);

        let minimum = minimum_webhook_request_bytes(CALLBACK_URL, identity_member).unwrap();
        compile(&identity_webhook_config(minimum))
            .expect("the exact complete identity projection boundary must compile");
        let error = compile(&identity_webhook_config(minimum - 1))
            .expect_err("one byte below the complete identity projection must fail");
        assert!(
            error.to_string().contains(&format!("at least {minimum}")),
            "{error}"
        );
    }

    #[test]
    fn webhook_request_configured_limit_drives_resource_plan() {
        let configured_request_limit = 4_097;
        let compiled = compile(&webhook_config(
            configured_request_limit,
            MIN_CALLBACK_RESPONSE_BYTES,
        ))
        .unwrap();
        let resources = &compiled.reloadable_plan.resource_plan;
        let request_allocation = guarded(configured_request_limit);
        let callback_allocation =
            guarded(MIN_CALLBACK_RESPONSE_BYTES - CALLBACK_RESPONSE_PREFIX_BYTES);
        assert_eq!(
            resources.webhook_request_allocation_bytes_by_rule,
            [Some(request_allocation)]
        );
        assert_eq!(
            resources.webhook_callback_allocation_bytes_by_rule,
            [Some(callback_allocation)]
        );
        assert_eq!(
            resources.combined_http_body_peaks_for_test(),
            [request_allocation + default_runtime_replay_storage(), 0]
        );
        assert_eq!(
            resources.max_reachable_http_body_combined_peak_bytes,
            request_allocation + default_runtime_replay_storage()
        );
    }

    #[test]
    fn callback_minimum_envelope_limits_compile() {
        let control_error = compile(&webhook_config(4_097, MIN_CALLBACK_RESPONSE_BYTES).replace(
            "max_request_body_bytes = 65536",
            &format!(
                "max_request_body_bytes = {}",
                MIN_CALLBACK_RESPONSE_BYTES - 1
            ),
        ))
        .expect_err("callback control limit cannot be one byte below the envelope floor");
        assert_eq!(control_error.path, "control.max_request_body_bytes");

        let provider_error = compile(&webhook_config(4_097, MIN_CALLBACK_RESPONSE_BYTES - 1))
            .expect_err("provider response limit cannot be one byte below the envelope floor");
        assert_eq!(
            provider_error.path,
            "authorization.providers.approval.max_response_bytes"
        );
    }

    #[test]
    fn webhook_delivery_static_limits_are_checked() {
        let input = MINIMAL.replace(
            "[policy]",
            r#"[service]
max_active_webhook_deliveries = 2
webhook_transport_buffer_bytes = 65536
max_webhook_transport_bytes = 262143

[policy]"#,
        );
        let error = compile(&input).expect_err("two buffers per delivery must fit the pool");
        assert_eq!(error.path, "service.max_webhook_transport_bytes");

        let exact = compile(&input.replace("262143", "262144")).unwrap();
        assert_eq!(
            exact.static_config.service.max_webhook_transport_bytes,
            262_144
        );
    }

    #[test]
    fn webhook_public_callback_route_is_never_provider_endpoint() {
        let input = webhook_config(4_097, MIN_CALLBACK_RESPONSE_BYTES)
            .replace("127.0.0.1:8898/_acl-proxy", "LOCALHOST:8898/_acl-proxy")
            .replace(
                "https://approval.example.test/authorize",
                "http://localhost:8898/_acl-proxy/provider?mode=approval",
            );
        let error = compile(&input)
            .expect_err("canonical callback authority and control subtree must be reserved");
        assert_eq!(error.path, "authorization.providers.approval.url");
        assert!(error.to_string().contains("control subtree"));
    }

    #[test]
    fn callback_and_webhook_endpoint_lengths_are_bounded() {
        let oversized_provider = format!(
            "https://approval.example.test/{}",
            "a".repeat(MAX_ENDPOINT_BYTES)
        );
        let provider_error = compile(&webhook_config(4_097, MIN_CALLBACK_RESPONSE_BYTES).replace(
            "https://approval.example.test/authorize",
            &oversized_provider,
        ))
        .expect_err("the complete canonical provider URL must fit its fixed ceiling");
        assert_eq!(provider_error.path, "authorization.providers.approval.url");
        assert!(provider_error.to_string().contains("canonical URL"));

        let maximum_base_path = format!(
            "/{}",
            "a".repeat(MAX_ENDPOINT_BYTES - CALLBACK_ROUTE_SUFFIX.len() - 1)
        );
        let control_config = |base_path: &str| {
            MINIMAL.replace(
                "[policy]",
                &format!(
                    "[control]\nbind = \"127.0.0.1:8898\"\nbase_path = {base_path:?}\n\n[policy]"
                ),
            )
        };
        compile(&control_config(&maximum_base_path))
            .expect("the exact generated callback target ceiling must compile");

        let oversized_base = format!("{maximum_base_path}a");
        let target_error = compile(&control_config(&oversized_base))
            .expect_err("one byte beyond the generated callback target ceiling must fail");
        assert_eq!(target_error.path, "control.base_path");
        assert!(target_error.to_string().contains("encoded callback target"));

        for noncanonical in ["/_acl proxy", "/_acl-proxy/é"] {
            let error = compile(&control_config(noncanonical))
                .expect_err("base paths that require percent encoding must fail");
            assert_eq!(error.path, "control.base_path");
            assert!(error.to_string().contains("unsafe path component"));
        }
    }

    fn one_byte_body_provider_config(service: &str) -> String {
        resource_config(
            service,
            r#"
[authorization.providers.body]
kind = "process"
command = "/bin/body-provider"
include_request_body = true
max_request_body_bytes = 1
max_decoded_request_body_bytes = 1
max_stdout_line_bytes = 80
retire_timeout = "1s"
"#,
            r#"
[[policy.rules]]
id = "body"
decision = "delegate"
methods = ["POST"]
authorization_provider = "body"
"#,
        )
    }

    #[test]
    fn guarded_stage_projects_each_partial_buffer_independently() {
        let peak = guarded_body_stage_peak(
            [1, 1],
            "test",
            "guarded stage projection arithmetic overflow",
        )
        .unwrap();

        assert_eq!(peak, 2 * guarded(1));
        assert!(peak > guarded(2));
    }

    #[test]
    fn provider_schedule_projects_original_stream_scratch_and_retention() {
        let input = one_byte_body_provider_config("");
        let config: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let schedule = compile_http_rule_schedule(&config, &config.policy.rules[0]).unwrap();

        assert_eq!(schedule.initial_peak, decode_peak(1, 1).unwrap());
        assert_eq!(
            schedule.incoming_stages[0].additional_bytes,
            guarded(64 * 1024)
        );
        assert_eq!(schedule.retained_original_after_pass, Some(guarded(1)));
    }

    #[test]
    fn header_only_provider_schedules_request_scratch_separately_from_response() {
        let response_bytes = 64 * 1024 + 1;
        let max_stdout_line_bytes = response_bytes
            + PROCESS_PROVIDER_RESPONSE_PREFIX_BYTES
            + PROCESS_PROVIDER_RESPONSE_TERMINATOR_BYTES;
        let input = resource_config(
            "",
            &format!(
                r#"
[authorization.providers.decision]
kind = "process"
command = "/bin/decision-provider"
max_stdout_line_bytes = {max_stdout_line_bytes}
retire_timeout = "1s"
"#
            ),
            r#"
[[policy.rules]]
id = "decision"
decision = "delegate"
methods = ["GET"]
authorization_provider = "decision"
"#,
        );
        let config: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let schedule = compile_http_rule_schedule(&config, &config.policy.rules[0]).unwrap();
        let request_scratch = guarded(PROVIDER_REQUEST_STREAM_SCRATCH_BYTES);
        let response = guarded(response_bytes);

        assert_eq!(schedule.initial_peak, response);
        assert_eq!(
            schedule
                .incoming_stages
                .iter()
                .map(|stage| stage.additional_bytes)
                .collect::<Vec<_>>(),
            [request_scratch, response]
        );
        assert_eq!(request_scratch, guarded(1));
        assert_eq!(response, 2 * guarded(1));
    }

    #[test]
    fn process_credential_rehome_overlaps_the_raw_response_continuation() {
        let continuation_bytes = 64 * 1024 + 1;
        let max_stdout_line_bytes = continuation_bytes
            + PROCESS_PROVIDER_RESPONSE_PREFIX_BYTES
            + PROCESS_PROVIDER_RESPONSE_TERMINATOR_BYTES;
        let input = resource_config(
            "",
            &format!(
                r#"
[authorization.providers.decision]
kind = "process"
command = "/bin/decision-provider"
max_stdout_line_bytes = {max_stdout_line_bytes}
retire_timeout = "1s"

[authorization.providers.decision.outputs.token]
kind = "bearer"
transport_security = "tls_required"
"#
            ),
            r#"
[[policy.rules]]
id = "decision"
decision = "delegate"
methods = ["GET"]
authorization_provider = "decision"
"#,
        );
        let config: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let schedule = compile_http_rule_schedule(&config, &config.policy.rules[0]).unwrap();
        let continuation = guarded(continuation_bytes);
        let compact_credentials =
            compact_provider_credential_allocation(1, MAX_PROVIDER_CREDENTIAL_BYTES).unwrap();
        let finalization =
            compile_credential_finalization_peak(&config, Some(&config.policy.rules[0])).unwrap();

        assert_eq!(continuation, 2 * guarded(1));
        assert_eq!(
            compact_credentials,
            guarded(1) + projected_provider_credential_wire_metadata_bytes(1).unwrap()
        );
        assert_eq!(
            schedule.initial_peak,
            continuation + compact_credentials + finalization
        );
    }

    #[test]
    fn compact_credentials_remain_live_through_terminal_redaction() {
        let input = resource_config(
            "",
            r#"
[authorization.providers.replacing]
kind = "process"
command = "/bin/replacing-provider"
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 1
max_decoded_request_body_bytes = 1
max_stdout_line_bytes = 80
retire_timeout = "1s"

[authorization.providers.replacing.outputs.token]
kind = "bearer"
transport_security = "tls_required"

[redaction.profiles.small]
max_body_bytes = 1
max_decoded_body_bytes = 1
rules = [{ literals = ["x"] }]
"#,
            r#"
[[policy.rules]]
id = "combined"
decision = "delegate"
methods = ["POST"]
authorization_provider = "replacing"
redaction_profile = "small"
"#,
        );
        let config: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let schedule = compile_http_rule_schedule(&config, &config.policy.rules[0]).unwrap();
        let literal_scratch = shared_matcher_scratch_bytes(1);
        let continuation_bytes = provider_response_guarded_suffix_bytes(80, "test").unwrap();
        let compact_credentials =
            compact_provider_credential_allocation(1, continuation_bytes).unwrap();
        let terminal_redaction =
            guarded(1) + guarded(literal_scratch) + guarded(1) + compact_credentials;
        let finalization =
            compile_credential_finalization_peak(&config, Some(&config.policy.rules[0])).unwrap();
        let expected = decode_peak(1, 1).unwrap().max(terminal_redaction) + finalization;

        assert_eq!(
            terminal_redaction,
            4 * guarded(1) + projected_provider_credential_wire_metadata_bytes(1).unwrap()
        );
        assert_eq!(schedule.initial_peak, expected);
    }

    #[test]
    fn retained_delegate_body_overlaps_later_response_and_compact_credentials() {
        let continuation_bytes = 4 * MIB + 1;
        let max_stdout_line_bytes = continuation_bytes
            + PROCESS_PROVIDER_RESPONSE_PREFIX_BYTES
            + PROCESS_PROVIDER_RESPONSE_TERMINATOR_BYTES;
        let input = resource_config(
            "",
            &format!(
                r#"
[credentials]
allowed_custom_headers = ["x-trace-token"]

[authorization.providers.first]
kind = "process"
command = "/bin/first-provider"
include_request_body = true
max_request_body_bytes = 1
max_decoded_request_body_bytes = 1
max_stdout_line_bytes = 80
retire_timeout = "1s"

[authorization.providers.later]
kind = "process"
command = "/bin/later-provider"
max_stdout_line_bytes = {max_stdout_line_bytes}
retire_timeout = "1s"

[authorization.providers.later.outputs.token]
kind = "bearer"
transport_security = "cleartext_allowed"

[authorization.providers.later.outputs.trace]
kind = "custom_header"
transport_security = "cleartext_allowed"
header = "x-trace-token"
"#
            ),
            r#"
[[policy.rules]]
id = "first"
decision = "delegate"
methods = ["POST"]
authorization_provider = "first"

[[policy.rules]]
id = "later"
decision = "delegate"
methods = ["POST"]
authorization_provider = "later"
"#,
        );
        let plan = compile(&input).unwrap().reloadable_plan.resource_plan;
        let retained = guarded(1);
        let continuation = guarded(continuation_bytes);
        let compact_credentials =
            compact_provider_credential_allocation(2, 2 * MAX_PROVIDER_CREDENTIAL_BYTES).unwrap();
        let rehome = continuation + compact_credentials;
        let config: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let later_finalization =
            compile_credential_finalization_peak(&config, Some(&config.policy.rules[1])).unwrap();

        assert_eq!(continuation, 65 * guarded(1));
        assert_eq!(
            compact_credentials,
            2 * guarded(1) + projected_provider_credential_wire_metadata_bytes(2).unwrap()
        );
        let initial_peak = (retained + rehome).max(decode_peak(1, 1).unwrap());
        assert_eq!(initial_peak, decode_peak(1, 1).unwrap());
        let first_replay = canonical_runtime_replay_storage(1);
        let later_replay = default_runtime_replay_storage();
        assert_eq!(
            plan.combined_http_body_peaks_for_test(),
            [
                initial_peak.max(retained + rehome + later_finalization) + first_replay,
                rehome + later_finalization + later_replay,
                0
            ]
        );
    }

    #[test]
    fn retained_delegate_body_overlaps_later_credentials_and_redaction_scratch() {
        let input = resource_config(
            "",
            r#"
[authorization.providers.first]
kind = "process"
command = "/bin/first-provider"
include_request_body = true
max_request_body_bytes = 65537
max_decoded_request_body_bytes = 65537
max_stdout_line_bytes = 80
retire_timeout = "1s"

[authorization.providers.later]
kind = "process"
command = "/bin/later-provider"
max_stdout_line_bytes = 80
retire_timeout = "1s"

[authorization.providers.later.outputs.token]
kind = "bearer"
transport_security = "cleartext_allowed"

[redaction.profiles.small]
max_body_bytes = 1
max_decoded_body_bytes = 1
rules = [{ literals = ["x"] }]
"#,
            r#"
[[policy.rules]]
id = "first"
decision = "delegate"
methods = ["POST"]
authorization_provider = "first"

[[policy.rules]]
id = "later"
decision = "delegate"
methods = ["POST"]
authorization_provider = "later"
redaction_profile = "small"
"#,
        );
        let authored: super::super::authoring::AuthoringConfig =
            toml::from_str(&input).expect("test input should deserialize");
        let later_schedule =
            compile_http_rule_schedule(&authored, &authored.policy.rules[1]).unwrap();
        let plan = compile(&input).unwrap().reloadable_plan.resource_plan;
        let retained = guarded(65_537);
        let literal_scratch = guarded(shared_matcher_scratch_bytes(1));
        let redaction_output = guarded(1);
        let compact_credentials = compact_provider_credential_allocation(
            1,
            provider_response_guarded_suffix_bytes(80, "test").unwrap(),
        )
        .unwrap();
        let incoming_redaction = literal_scratch + redaction_output + compact_credentials;
        let credential_finalization =
            compile_credential_finalization_peak(&authored, Some(&authored.policy.rules[1]))
                .unwrap();

        assert_eq!(
            later_schedule.max_incoming_additional_bytes(),
            incoming_redaction + credential_finalization
        );
        assert_eq!(retained, 2 * guarded(1));
        assert_eq!(
            incoming_redaction,
            3 * guarded(1) + projected_provider_credential_wire_metadata_bytes(1).unwrap()
        );
        assert!(plan.combined_http_body_peaks_for_test()[0] >= retained + incoming_redaction);
        assert_eq!(plan.combined_http_body_peaks_for_test()[2], 0);
    }

    #[test]
    fn redacted_original_overlaps_decision_only_request_and_response_stages() {
        let response_bytes = 2 * 64 * 1024 + 1;
        let max_stdout_line_bytes = response_bytes
            + PROCESS_PROVIDER_RESPONSE_PREFIX_BYTES
            + PROCESS_PROVIDER_RESPONSE_TERMINATOR_BYTES;
        let input = resource_config(
            "",
            &format!(
                r#"
[authorization.providers.decision]
kind = "process"
command = "/bin/decision-provider"
max_stdout_line_bytes = {max_stdout_line_bytes}
retire_timeout = "1s"

[redaction.profiles.small]
max_body_bytes = 1
max_decoded_body_bytes = 1
rules = [{{ literals = ["x"] }}]
"#
            ),
            r#"
[[policy.rules]]
id = "redacted-decision"
decision = "delegate"
methods = ["POST"]
authorization_provider = "decision"
redaction_profile = "small"
"#,
        );
        let config: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let schedule = compile_http_rule_schedule(&config, &config.policy.rules[0]).unwrap();
        let retained = guarded(1);
        let response = guarded(response_bytes);
        let decoder_peak = decode_peak(1, 1).unwrap();

        assert_eq!(response, 3 * guarded(1));
        assert_eq!(schedule.initial_peak, decoder_peak.max(retained + response));
        assert_eq!(schedule.retained_original_after_pass, Some(retained));
        assert_eq!(schedule.max_incoming_additional_bytes(), response);
    }

    #[test]
    fn redaction_only_delegate_retains_original_for_a_later_provider() {
        let response_bytes = 2 * 64 * 1024 + 1;
        let max_stdout_line_bytes = response_bytes
            + PROCESS_PROVIDER_RESPONSE_PREFIX_BYTES
            + PROCESS_PROVIDER_RESPONSE_TERMINATOR_BYTES;
        let input = resource_config(
            "",
            &format!(
                r#"
[authorization.providers.first]
kind = "process"
command = "/bin/first-provider"
max_stdout_line_bytes = 80
retire_timeout = "1s"

[authorization.providers.later]
kind = "process"
command = "/bin/later-provider"
max_stdout_line_bytes = {max_stdout_line_bytes}
retire_timeout = "1s"

[redaction.profiles.small]
max_body_bytes = 1
max_decoded_body_bytes = 1
rules = [{{ literals = ["x"] }}]
"#
            ),
            r#"
[[policy.rules]]
id = "redact-and-pass"
decision = "delegate"
methods = ["POST"]
authorization_provider = "first"
redaction_profile = "small"

[[policy.rules]]
id = "later-provider"
decision = "delegate"
methods = ["POST"]
authorization_provider = "later"
"#,
        );
        let config: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let first = compile_http_rule_schedule(&config, &config.policy.rules[0]).unwrap();
        let second = compile_http_rule_schedule(&config, &config.policy.rules[1]).unwrap();
        let resources = compile(&input).unwrap().reloadable_plan.resource_plan;
        let retained = guarded(1);
        let response = guarded(response_bytes);
        let decoder_peak = decode_peak(1, 1).unwrap();
        let first_replay = canonical_runtime_replay_storage(1);
        let later_replay = default_runtime_replay_storage();

        assert_eq!(first.retained_original_after_pass, Some(retained));
        assert_eq!(second.initial_peak, response);
        assert_eq!(second.max_incoming_additional_bytes(), response);
        assert_eq!(
            resources.combined_http_body_peaks_for_test(),
            [
                decoder_peak.max(retained + response) + first_replay,
                response + later_replay,
                0
            ]
        );
    }

    #[test]
    fn direct_schedule_rejects_stdout_smaller_than_the_fixed_prefix() {
        let too_small =
            PROCESS_PROVIDER_RESPONSE_PREFIX_BYTES + PROCESS_PROVIDER_RESPONSE_TERMINATOR_BYTES - 1;
        let input = resource_config(
            "",
            &format!(
                r#"
[authorization.providers.decision]
kind = "process"
command = "/bin/decision-provider"
max_stdout_line_bytes = {too_small}
retire_timeout = "1s"
"#
            ),
            r#"
[[policy.rules]]
id = "decision"
decision = "delegate"
methods = ["GET"]
authorization_provider = "decision"
"#,
        );
        let config: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let error = compile_http_rule_schedule(&config, &config.policy.rules[0]).unwrap_err();

        assert_eq!(
            error.path,
            "authorization.providers.decision.max_stdout_line_bytes"
        );
        assert_eq!(
            error.message,
            "cannot hold the fixed process-provider response prefix and terminator"
        );
    }

    #[test]
    fn retained_body_accounts_for_later_header_only_request_scratch() {
        let input = resource_config(
            "",
            r#"
[authorization.providers.body]
kind = "process"
command = "/bin/body-provider"
include_request_body = true
max_request_body_bytes = 1
max_decoded_request_body_bytes = 1
max_stdout_line_bytes = 80
retire_timeout = "1s"

[authorization.providers.later]
kind = "process"
command = "/bin/later-provider"
max_stdout_line_bytes = 80
retire_timeout = "1s"
"#,
            r#"
[[policy.rules]]
id = "body"
decision = "delegate"
methods = ["POST"]
authorization_provider = "body"

[[policy.rules]]
id = "later"
decision = "delegate"
methods = ["POST"]
authorization_provider = "later"
"#,
        );
        let config: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let first = compile_http_rule_schedule(&config, &config.policy.rules[0]).unwrap();
        let second = compile_http_rule_schedule(&config, &config.policy.rules[1]).unwrap();
        let resources = compile(&input).unwrap().reloadable_plan.resource_plan;
        let retained = first.retained_original_after_pass.unwrap();
        let request_scratch = guarded(PROVIDER_REQUEST_STREAM_SCRATCH_BYTES);

        assert_eq!(second.max_incoming_additional_bytes(), request_scratch);
        assert!(resources.combined_http_body_peaks_for_test()[0] >= retained + request_scratch);
        assert_eq!(
            resources.combined_http_body_peaks_for_test()[1],
            request_scratch + default_runtime_replay_storage()
        );
    }

    #[test]
    fn replacement_projection_charges_each_chunk_and_node_at_boundary() {
        let continuation_bytes = 64 * 1024 + 1;
        let peak = replacement_decode_peak(continuation_bytes, 1).unwrap();

        assert_eq!(
            peak,
            guarded(continuation_bytes) + guarded(1) + guarded(PROVIDER_REPLACEMENT_STAGING_BYTES)
        );
        assert_eq!(guarded(continuation_bytes), 2 * guarded(1));
    }

    #[test]
    fn decision_only_response_continuation_uses_exact_chunk_boundaries() {
        assert_eq!(PROCESS_PROVIDER_RESPONSE_PREFIX_BYTES, 42);
        assert_eq!(PROCESS_PROVIDER_RESPONSE_TERMINATOR_BYTES, 1);
        for continuation_bytes in [64 * 1024, 64 * 1024 + 1] {
            let max_stdout_line_bytes = continuation_bytes
                + PROCESS_PROVIDER_RESPONSE_PREFIX_BYTES
                + PROCESS_PROVIDER_RESPONSE_TERMINATOR_BYTES;
            let input = resource_config(
                "",
                &format!(
                    r#"
[authorization.providers.decision]
kind = "process"
command = "/bin/decision-provider"
max_stdout_line_bytes = {max_stdout_line_bytes}
retire_timeout = "1s"
"#
                ),
                r#"
[[policy.rules]]
id = "decision"
decision = "delegate"
methods = ["GET"]
authorization_provider = "decision"
"#,
            );
            let resources = compile(&input).unwrap().reloadable_plan.resource_plan;
            let combined = guarded(continuation_bytes) + default_runtime_replay_storage();

            assert_eq!(resources.combined_http_body_peaks_for_test(), [combined, 0]);
            assert_eq!(
                resources.max_reachable_http_body_combined_peak_bytes,
                combined
            );
        }
        assert_eq!(guarded(64 * 1024), guarded(1));
        assert_eq!(guarded(64 * 1024 + 1), 2 * guarded(1));
    }

    #[test]
    fn process_stdout_limit_must_fit_the_smallest_generated_id_response() {
        assert_eq!(PROCESS_PROVIDER_MIN_DECISION_RESPONSE_BYTES, 80);
        let input = resource_config(
            "",
            &format!(
                r#"
[authorization.providers.decision]
kind = "process"
command = "/bin/decision-provider"
max_stdout_line_bytes = {}
retire_timeout = "1s"
"#,
                PROCESS_PROVIDER_MIN_DECISION_RESPONSE_BYTES - 1
            ),
            "",
        );
        let error = compile(&input).unwrap_err();
        assert!(error
            .to_string()
            .contains("authorization.providers.decision.max_stdout_line_bytes"));
    }

    #[test]
    fn retained_body_overlaps_a_pass_reachable_response_continuation() {
        let later_continuation_bytes = 2 * 64 * 1024 + 1;
        let later_line_bytes = later_continuation_bytes
            + PROCESS_PROVIDER_RESPONSE_PREFIX_BYTES
            + PROCESS_PROVIDER_RESPONSE_TERMINATOR_BYTES;
        let input = resource_config(
            "",
            &format!(
                r#"
[authorization.providers.body]
kind = "process"
command = "/bin/body-provider"
include_request_body = true
max_request_body_bytes = 1
max_decoded_request_body_bytes = 1
max_stdout_line_bytes = 80
retire_timeout = "1s"

[authorization.providers.later]
kind = "process"
command = "/bin/later-provider"
max_stdout_line_bytes = {later_line_bytes}
retire_timeout = "1s"
"#
            ),
            r#"
[[policy.rules]]
id = "body"
decision = "delegate"
methods = ["POST"]
authorization_provider = "body"

[[policy.rules]]
id = "later"
decision = "delegate"
methods = ["POST"]
authorization_provider = "later"
"#,
        );
        let resources = compile(&input).unwrap().reloadable_plan.resource_plan;
        let retained_original = guarded(1);
        let later_continuation = guarded(later_continuation_bytes);
        let decoder_peak = decode_peak(1, 1).unwrap();
        let first_replay = canonical_runtime_replay_storage(1);
        let later_replay = default_runtime_replay_storage();

        assert_eq!(later_continuation, 3 * guarded(1));
        assert_eq!(
            resources.combined_http_body_peaks_for_test(),
            [
                decoder_peak.max(retained_original + later_continuation) + first_replay,
                later_continuation + later_replay,
                0,
            ]
        );
    }

    #[test]
    fn default_decision_only_response_preserves_compiled_capacity() {
        let input = resource_config(
            "",
            r#"
[authorization.providers.decision]
kind = "process"
command = "/bin/decision-provider"
retire_timeout = "1s"
"#,
            r#"
[[policy.rules]]
id = "decision"
decision = "delegate"
methods = ["GET"]
authorization_provider = "decision"
"#,
        );
        let resources = compile(&input).unwrap().reloadable_plan.resource_plan;
        let peak = guarded(
            provider_response_guarded_suffix_bytes(MIB, "test.provider.max_stdout_line_bytes")
                .unwrap(),
        );
        let combined = peak + default_runtime_replay_storage();
        let exchange = combined + resources.forward_response_peak_bytes;

        assert_eq!(resources.combined_http_body_peaks_for_test(), [combined, 0]);
        assert_eq!(
            resources.max_reachable_http_body_combined_peak_bytes,
            combined
        );
        assert_eq!(resources.max_reachable_http_exchange_peak_bytes, exchange);
        assert_eq!(
            resources.wire_body_full_peak_capacity,
            Capacity::Finite(16 * GIB / exchange)
        );
        assert_eq!(
            resources.wire_body_quota_key_full_peak_capacity,
            Capacity::Finite(2 * GIB / exchange)
        );
    }

    #[test]
    fn delegate_pass_retention_adds_later_partial_buffers_separately() {
        let input = resource_config(
            "",
            r#"
[authorization.providers.body]
kind = "process"
command = "/bin/body-provider"
include_request_body = true
max_request_body_bytes = 1
max_decoded_request_body_bytes = 1
max_stdout_line_bytes = 80
retire_timeout = "1s"

[redaction.profiles.terminal]
max_body_bytes = 1
max_decoded_body_bytes = 1
rules = [{ literals = ["x"] }]
"#,
            r#"
[[policy.rules]]
id = "delegate"
decision = "delegate"
methods = ["POST"]
authorization_provider = "body"

[[policy.rules]]
id = "terminal"
decision = "allow"
methods = ["POST"]
redaction_profile = "terminal"
"#,
        );
        let config: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let first = compile_http_rule_schedule(&config, &config.policy.rules[0]).unwrap();
        let second = compile_http_rule_schedule(&config, &config.policy.rules[1]).unwrap();
        let retained = first.retained_original_after_pass.unwrap();
        let later_additional = second.max_incoming_additional_bytes();
        let decoder_peak = decode_peak(1, 1).unwrap();
        let compiled = compile(&input).unwrap();

        assert_eq!(retained, guarded(1));
        assert_eq!(later_additional, 2 * guarded(1));
        assert_eq!(
            compiled
                .reloadable_plan
                .resource_plan
                .combined_http_body_peaks_for_test()[0],
            decoder_peak.max(retained + later_additional) + canonical_runtime_replay_storage(1)
        );
    }

    #[test]
    fn http_wire_body_incremental_permits_preserve_minimum_concurrency() {
        use crate::safety::{WireBodyPool, WireBodyQuotaKey};

        let baseline = compile(&one_byte_body_provider_config("")).unwrap();
        let request_peak = baseline
            .reloadable_plan
            .resource_plan
            .max_reachable_http_body_combined_peak_bytes;
        let peak = baseline
            .reloadable_plan
            .resource_plan
            .max_reachable_http_exchange_peak_bytes;
        let exact_service = format!(
            "max_inflight_wire_body_bytes = {}\nmax_inflight_wire_body_bytes_per_quota_key = {peak}\nmin_wire_body_concurrency = 5",
            5 * peak
        );
        let exact = compile(&one_byte_body_provider_config(&exact_service)).unwrap();
        assert_eq!(
            exact
                .reloadable_plan
                .resource_plan
                .wire_body_full_peak_capacity,
            Capacity::Finite(5)
        );

        let insufficient_service = format!(
            "max_inflight_wire_body_bytes = {}\nmax_inflight_wire_body_bytes_per_quota_key = {peak}\nmin_wire_body_concurrency = 5",
            5 * peak - 1
        );
        let error = compile(&one_byte_body_provider_config(&insufficient_service))
            .expect_err("one byte below the projected product must fail");
        assert_eq!(error.path, "service.min_wire_body_concurrency");

        let pool = WireBodyPool::new(5 * request_peak, request_peak);
        let small_charge = guarded(1);
        let mut live = Vec::new();
        for peer_suffix in 1..=6 {
            let guard = pool.begin_for_test(
                request_peak,
                WireBodyQuotaKey::from_peer(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, peer_suffix)),
                    |_| false,
                ),
            );
            let mut body = guard.buffer();
            body.try_extend_from_slice(b"x").unwrap();
            live.push((guard, body.finish()));
        }
        assert!(small_charge < request_peak);
        assert_eq!(pool.global_charge(), 6 * small_charge);
        assert!(pool.global_charge() < 5 * peak);
        drop(live);
        assert_eq!(pool.global_charge(), 0);
    }

    #[test]
    fn compiled_decode_peak_matches_live_chunk_charge() {
        use crate::safety::{WireBodyPool, WireBodyQuotaKey};

        let compiled = compile(&one_byte_body_provider_config("")).unwrap();
        let guarded_peak = compiled
            .reloadable_plan
            .resource_plan
            .http_body_resources_by_cursor[0]
            .product_incremental_peak_bytes;
        let pool = WireBodyPool::new(guarded_peak, guarded_peak);
        let guard = pool.begin_for_test(
            guarded_peak,
            WireBodyQuotaKey::from_peer(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                |_| false,
            ),
        );
        let mut encoded = guard.buffer();
        let mut decoded = guard.buffer();
        let decoder_sizes = crate::http_body::http_decoder_workspace_sizes().unwrap();
        let decoder_workspace = guard
            .codec_workspace_allocation(decoder_sizes.maximum())
            .unwrap();
        let decoder_staging = guard.stream_scratch().unwrap();
        encoded.try_extend_from_slice(&[1]).unwrap();
        decoded.try_extend_from_slice(&[2]).unwrap();

        assert_eq!(guard.live_bytes(), guarded_peak);
        assert_eq!(pool.global_charge(), guarded_peak);
        assert_eq!(
            decoder_workspace.len(),
            guarded_workspace_allocation_bytes(decoder_sizes.maximum()).unwrap()
        );
        assert_eq!(
            decoder_staging.capacity(),
            HTTP_DECODER_OUTPUT_STAGING_BYTES
        );
    }

    #[test]
    fn fixed_zstd_standard_window_fits_the_library() {
        assert_eq!(crate::http_body::zstd_window_limit(), Some(8 * MIB));
    }

    #[test]
    fn mandatory_decoder_peak_selects_largest_codec_workspace() {
        let encoded = 10 * MIB;
        let decoded = 50 * MIB;
        let sizes = crate::http_body::http_decoder_workspace_sizes().unwrap();
        let expected = guarded(encoded)
            + guarded(decoded)
            + guarded(HTTP_DECODER_OUTPUT_STAGING_BYTES)
            + guarded_workspace_allocation_bytes(sizes.maximum()).unwrap();

        assert_eq!(decode_peak(encoded, decoded).unwrap(), expected);
        assert_eq!(sizes.maximum(), sizes.brotli);
        assert!(sizes.brotli > sizes.zstd);
        assert!(sizes.zstd > sizes.deflate);
    }

    #[test]
    fn capture_working_set_projects_each_required_peak_exactly() {
        let encoded_bytes = 3 * HTTP_DECODER_OUTPUT_STAGING_BYTES + 1;
        let decoded_bytes = 5 * HTTP_DECODER_OUTPUT_STAGING_BYTES + 1;
        let matcher_scratch_bytes = 3 * std::mem::size_of::<usize>() * 2;
        let stored_bytes = 2 * HTTP_DECODER_OUTPUT_STAGING_BYTES + 1;
        let encoded = guarded(encoded_bytes);
        let decoded = guarded(decoded_bytes);
        let staging = guarded(HTTP_DECODER_OUTPUT_STAGING_BYTES);
        let workspace =
            guarded_workspace_allocation_bytes(http_decoder_workspace_sizes().unwrap().maximum())
                .unwrap();
        let padded_base64 = base64_encoded_len(stored_bytes, true).unwrap();

        let plan = capture_working_set_plan(
            encoded_bytes,
            decoded_bytes,
            decoded_bytes,
            false,
            matcher_scratch_bytes,
            true,
            stored_bytes,
        )
        .unwrap();

        assert_eq!(
            plan.decode_peak_bytes,
            encoded + decoded + staging + workspace
        );
        assert_eq!(
            plan.literal_redaction_peak_bytes,
            decoded + matcher_scratch_bytes + decoded
        );
        assert_eq!(plan.expression_successor_peak_bytes, decoded + decoded);
        assert_eq!(
            plan.serialization_peak_bytes,
            guarded(stored_bytes) + padded_base64
        );
        assert_eq!(
            plan.maximum_peak_bytes,
            [
                plan.decode_peak_bytes,
                plan.literal_redaction_peak_bytes,
                plan.expression_successor_peak_bytes,
                plan.serialization_peak_bytes,
            ]
            .into_iter()
            .max()
            .unwrap()
        );
    }

    #[test]
    fn capture_working_set_omits_unreachable_expression_successor_and_caps_stored_prefix() {
        let decoded_bytes = HTTP_DECODER_OUTPUT_STAGING_BYTES;
        let plan =
            capture_working_set_plan(1, decoded_bytes, decoded_bytes, false, 0, false, usize::MAX)
                .unwrap();

        assert_eq!(plan.expression_successor_peak_bytes, 0);
        assert_eq!(
            plan.serialization_peak_bytes,
            guarded(decoded_bytes) + base64_encoded_len(decoded_bytes, true).unwrap()
        );
    }

    #[test]
    fn capture_working_set_covers_maximum_websocket_decode_redaction_and_serialization() {
        let message_bytes = 256 * MIB;
        let stored_bytes = MIB;
        let matcher_scratch = shared_matcher_scratch_bytes("secret".len());
        let expected = capture_working_set_plan(
            1,
            1,
            message_bytes,
            true,
            matcher_scratch,
            false,
            stored_bytes,
        )
        .unwrap();
        let message = guarded(message_bytes);
        let deflate_scratch = guarded(WEBSOCKET_DEFLATE_SCRATCH_BYTES);
        assert_eq!(expected.decode_peak_bytes, 2 * message + deflate_scratch);
        assert_eq!(
            expected.literal_redaction_peak_bytes,
            2 * message + matcher_scratch
        );
        assert_eq!(
            expected.serialization_peak_bytes,
            guarded(stored_bytes) + base64_encoded_len(stored_bytes, true).unwrap()
        );
        assert_eq!(
            expected.maximum_peak_bytes,
            expected
                .decode_peak_bytes
                .max(expected.literal_redaction_peak_bytes)
        );

        let input = format!(
            r#"{MINIMAL}

[redaction.profiles.capture]
max_body_bytes = 1
max_decoded_body_bytes = 1
max_frame_bytes = 1
max_message_bytes = {message_bytes}
allow_permessage_deflate = true
rules = [{{ literals = ["secret"] }}]

[observation.capture]
events = ["request.denied"]
redaction_profile = "capture"
directory = "captures"
filename = "{{requestId}}-{{suffix}}.json"
max_body_bytes = {stored_bytes}
max_inflight_body_bytes = {}
max_pending_records = 1
max_files = 1
max_total_bytes = {stored_bytes}
"#,
            128 * MIB
        );
        let error = compile(&input).expect_err("the HTTP-only pool projection underfits WebSocket");
        assert_eq!(error.path, "observation.capture.max_inflight_body_bytes");
        assert_eq!(
            error.message,
            format!(
                "must hold one maximum capture operation of {} bytes",
                expected.maximum_peak_bytes
            )
        );

        let input = input.replace(
            &format!("max_inflight_body_bytes = {}", 128 * MIB),
            &format!("max_inflight_body_bytes = {}", expected.maximum_peak_bytes),
        );
        let compiled = compile(&input).unwrap();
        let capture = compiled.reloadable_plan.observation.capture.unwrap();
        assert_eq!(capture.working_set, expected);
    }

    #[test]
    fn capture_working_set_overflow_is_a_config_error() {
        let error = capture_working_set_plan(usize::MAX, 1, 1, false, 0, false, 1).unwrap_err();

        assert_eq!(error.path, "observation.capture.max_inflight_body_bytes");
        assert_eq!(error.message, "capture working-set arithmetic overflow");
    }

    fn one_byte_capture_config(max_inflight_body_bytes: usize) -> String {
        format!(
            r#"{MINIMAL}

[redaction.profiles.capture]
max_body_bytes = 1
max_decoded_body_bytes = 1
rules = [{{ literals = ["secret"] }}]

[observation.capture]
events = ["request.denied"]
redaction_profile = "capture"
directory = "captures"
filename = "{{requestId}}-{{suffix}}.json"
max_body_bytes = 1
max_inflight_body_bytes = {max_inflight_body_bytes}
max_pending_records = 1
max_files = 1
max_total_bytes = 1
"#
        )
    }

    #[test]
    fn capture_requires_capacity_for_one_compiled_maximum_operation() {
        let expected = capture_working_set_plan(
            1,
            1,
            MIB,
            false,
            shared_matcher_scratch_bytes("secret".len()),
            false,
            1,
        )
        .unwrap();
        let error = compile(&one_byte_capture_config(1))
            .expect_err("the old stored-body-only capacity check was underprovisioned");
        assert_eq!(error.path, "observation.capture.max_inflight_body_bytes");
        assert_eq!(
            error.message,
            format!(
                "must hold one maximum capture operation of {} bytes",
                expected.maximum_peak_bytes
            )
        );

        let compiled = compile(&one_byte_capture_config(expected.maximum_peak_bytes)).unwrap();
        let capture = compiled.reloadable_plan.observation.capture.unwrap();
        assert_eq!(capture.working_set, expected);
        assert_eq!(capture.max_inflight_body_bytes, expected.maximum_peak_bytes);
    }

    #[test]
    fn capture_expression_profile_publishes_successor_peak() {
        let expected = capture_working_set_plan(1, 1, MIB, false, 0, true, 1).unwrap();
        let input = one_byte_capture_config(expected.maximum_peak_bytes).replace(
            "rules = [{ literals = [\"secret\"] }]",
            "rules = [{ expressions = [\"s\"] }]",
        );

        let compiled = compile(&input).unwrap();
        let plan = compiled
            .reloadable_plan
            .observation
            .capture
            .unwrap()
            .working_set;

        assert_eq!(plan, expected);
        assert_eq!(plan.expression_successor_peak_bytes, 2 * guarded(MIB));
    }

    #[test]
    fn default_capture_pool_fits_default_environment_profile_working_set() {
        let input = format!(
            r#"{MINIMAL}

[redaction.profiles.capture]
rules = [{{ literal_environment_variables = ["CAPTURE_SECRET"] }}]

[observation.capture]
events = ["request.denied"]
redaction_profile = "capture"
directory = "captures"
filename = "{{requestId}}-{{suffix}}.json"
"#
        );

        let authored: super::super::authoring::AuthoringConfig =
            toml::from_str(&input).expect("default capture input deserializes");
        let profile = &authored.redaction.profiles["capture"];
        let authored_capture = authored
            .observation
            .capture
            .as_ref()
            .expect("capture is enabled");
        let expected = capture_working_set_plan(
            profile.max_body_bytes,
            profile.max_decoded_body_bytes,
            profile.max_message_bytes,
            profile.allow_permessage_deflate,
            shared_matcher_scratch_bytes(profile.max_environment_literal_bytes),
            false,
            authored_capture.max_body_bytes,
        )
        .unwrap();
        let compiled = compile(&input).unwrap();
        let capture = compiled.reloadable_plan.observation.capture.unwrap();

        assert_eq!(capture.working_set, expected);
        assert_eq!(expected.maximum_peak_bytes, 105_957_376);
        assert_eq!(capture.max_inflight_body_bytes, 128 * MIB);
        assert!(capture.max_inflight_body_bytes >= expected.maximum_peak_bytes);
    }

    fn reloadable_ownership_observations(plan: &ReloadableProductPlan) -> Vec<String> {
        let egress_route = match plan.egress.route {
            CompiledEgressRoute::Direct => "direct",
            CompiledEgressRoute::ParentProxy => "parent",
        };
        let origin_trust = match plan.egress.origin_tls.trust {
            CompiledTlsTrust::System => "system",
            CompiledTlsTrust::Custom => "custom",
            CompiledTlsTrust::SystemPlusCustom => "system+custom",
            CompiledTlsTrust::Insecure => "insecure",
        };
        let policy_default = match plan.policy.default {
            CompiledDefaultDecision::Allow => "allow",
            CompiledDefaultDecision::Deny => "deny",
        };
        let providers = plan
            .authorization
            .providers
            .iter()
            .map(|(name, provider)| match provider {
                AuthorizationProviderPlan::Webhook(provider) => format!(
                    "{name}:webhook:{}:{}:{}",
                    provider.url.as_str(),
                    provider.max_request_bytes,
                    provider.max_response_bytes
                ),
                AuthorizationProviderPlan::Process(provider) => format!(
                    "{name}:process:{}:{}",
                    provider.command.display(),
                    provider.max_pending_requests
                ),
                AuthorizationProviderPlan::UnixSocket(provider) => format!(
                    "{name}:unix_socket:{}:{}:{}",
                    provider.frame_protocol.request_limit().get(),
                    provider.frame_protocol.response_limit().get(),
                    provider.max_pending_requests
                ),
            })
            .collect::<Vec<_>>()
            .join(",");
        vec![
            format!("request_timeout={:?}", plan.request_timeout),
            format!("decode_ratio={}", plan.max_content_decoding_expansion_ratio),
            format!("egress={egress_route}:{origin_trust}"),
            format!(
                "egress_effects={}:{}",
                plan.egress.request_headers.len(),
                plan.egress.credential_actions.len()
            ),
            format!("policy={policy_default}:{}", plan.policy.rules.len()),
            format!(
                "authorization={}:{}:{}:{providers}",
                plan.authorization.internal_context_headers.len(),
                plan.authorization.providers.len(),
                plan.authorization
                    .callback
                    .as_ref()
                    .map(|callback| format!(
                        "{:?}:{}",
                        callback.resume_token_ttl,
                        callback.max_pending_operations.get()
                    ))
                    .unwrap_or_default()
            ),
            format!(
                "credentials={}:{}",
                plan.credentials.inbound.len(),
                plan.credentials.sources.len()
            ),
            format!("redaction={}", plan.redaction.profiles.len()),
            format!(
                "observation={:?}:{}:{}:{:?}:{:?}:{}:{}",
                plan.observation.logging.level,
                plan.observation.logging.policy_decisions.allows,
                plan.observation.logging.policy_decisions.denies,
                plan.observation.logging.policy_decisions.allow_level,
                plan.observation.logging.policy_decisions.deny_level,
                plan.observation.capture.is_some(),
                plan.observation
                    .capture
                    .as_ref()
                    .map(|capture| capture.events.len())
                    .unwrap_or(0)
            ),
            format!(
                "safety={}:{}",
                plan.safety.loop_detection.inject, plan.safety.loop_detection.header
            ),
            format!(
                "resources={}:{}",
                plan.resource_plan
                    .max_reachable_http_body_combined_peak_bytes,
                plan.resource_plan.max_upgrade_allocation_all_streams
            ),
        ]
    }

    #[test]
    fn minimal_config_compiles_without_runtime_side_effects() {
        let compiled = compile(MINIMAL).expect("minimal config should compile");
        assert_eq!(compiled.static_config.max_config_bytes, 10 * MIB);
        assert_eq!(
            compiled
                .reloadable_plan
                .resource_plan
                .wire_body_full_peak_capacity,
            Capacity::Unbounded
        );
        assert_eq!(
            compiled
                .reloadable_plan
                .resource_plan
                .max_upgrade_allocation_per_stream,
            0
        );
    }

    #[test]
    fn static_fingerprint_ignores_reloadable_policy_changes() {
        let first = compile(MINIMAL).unwrap();
        let changed =
            compile(&MINIMAL.replace("default = \"deny\"", "default = \"allow\"")).unwrap();
        assert_eq!(first.static_fingerprint, changed.static_fingerprint);
    }

    #[test]
    fn per_connection_identity_capacity_is_reloadable_not_resolver_metadata() {
        let first = compile(&environment_identity_config("AW_IDENTITY_TOKEN")).unwrap();
        let changed = compile(&environment_identity_config("AW_IDENTITY_TOKEN").replace(
            "max_pending_authentications_per_connection = 2",
            "max_pending_authentications_per_connection = 7",
        ))
        .unwrap();
        assert_eq!(first.static_fingerprint, changed.static_fingerprint);
        assert!(first.reloadable_plan.identity == changed.reloadable_plan.identity);
        assert_eq!(first.reloadable_plan.identity_connection_capacity.get(), 2);
        assert_eq!(
            changed.reloadable_plan.identity_connection_capacity.get(),
            7
        );
    }

    #[test]
    fn static_fingerprint_changes_with_listener_bind() {
        let first = compile(MINIMAL).unwrap();
        let changed = compile(&MINIMAL.replace("127.0.0.1:8881", "127.0.0.1:9999")).unwrap();
        assert_ne!(first.static_fingerprint, changed.static_fingerprint);
    }

    #[test]
    fn static_fingerprint_is_a_fixed_sha256_digest() {
        let compiled = compile(MINIMAL).unwrap();
        let serialized = serde_json::to_vec(&compiled.static_config).unwrap();
        let expected: [u8; 32] = Sha256::digest(serialized).into();
        assert_eq!(compiled.static_fingerprint.0, expected);
    }

    fn capture_config(max_pending_records: Option<usize>) -> String {
        let pending = max_pending_records
            .map(|value| format!("max_pending_records = {value}\n"))
            .unwrap_or_default();
        format!(
            r#"{MINIMAL}

[redaction.profiles.audit]
rules = [{{ literals = ["marker"] }}]

[redaction.profiles.next]
rules = [{{ literals = ["next"] }}]

[observation.capture]
events = ["request.denied"]
redaction_profile = "audit"
directory = "captures-a"
filename = "{{requestId}}-{{suffix}}.json"
max_body_bytes = 1024
max_inflight_body_bytes = 134217728
{pending}max_files = 10
max_total_bytes = 16384
"#
        )
    }

    #[test]
    fn capture_pending_records_is_defaulted_into_the_always_present_static_model() {
        let absent = compile(MINIMAL).unwrap();
        let enabled = compile(&capture_config(None)).unwrap();

        assert_eq!(absent.static_config.capture.max_pending_records, 1024);
        assert_eq!(enabled.static_config.capture.max_pending_records, 1024);
        assert_eq!(absent.static_fingerprint, enabled.static_fingerprint);
    }

    #[test]
    fn capture_pending_records_is_validated_and_changes_the_static_fingerprint() {
        let baseline = compile(&capture_config(None)).unwrap();
        let configured = compile(&capture_config(Some(2048))).unwrap();

        assert_eq!(configured.static_config.capture.max_pending_records, 2048);
        assert_ne!(baseline.static_fingerprint, configured.static_fingerprint);

        for value in [0, MAX_CAPTURE_PENDING_RECORDS + 1] {
            let error = compile(&capture_config(Some(value))).unwrap_err();
            assert_eq!(error.path, "observation.capture.max_pending_records");
            assert_eq!(
                error.message,
                format!("must be between 1 and {MAX_CAPTURE_PENDING_RECORDS}")
            );
        }
    }

    #[test]
    fn capture_filename_accepts_the_runtime_kind_placeholder() {
        let input = capture_config(None).replace(
            "{requestId}-{suffix}.json",
            "{requestId}-{kind}-{suffix}.json",
        );
        let compiled = compile(&input).unwrap();
        let capture = compiled.reloadable_plan.observation.capture.unwrap();

        assert_eq!(
            capture.sink.filename_template(),
            "{requestId}-{kind}-{suffix}.json"
        );
    }

    #[test]
    fn capture_filename_failures_are_typed_by_the_authoritative_sink_validator() {
        for (filename, expected) in [
            (
                "C:{requestId}-{suffix}.json",
                CaptureSinkSpecError::InvalidFilenameBasename,
            ),
            (
                "capture-{suffix}.json",
                CaptureSinkSpecError::MissingRequestIdPlaceholder,
            ),
            (
                "{requestId}.json",
                CaptureSinkSpecError::MissingSuffixPlaceholder,
            ),
            (
                "{requestId}-{unknown}-{suffix}.json",
                CaptureSinkSpecError::UnknownFilenamePlaceholder,
            ),
        ] {
            let input = capture_config(None).replace("{requestId}-{suffix}.json", filename);
            let error = compile(&input).expect_err("invalid capture filename must not compile");

            assert_eq!(error.path, "observation.capture.filename");
            assert_eq!(error.message, expected.to_string());
        }
    }

    #[test]
    fn capture_sink_and_body_policy_fields_remain_reloadable() {
        let baseline = compile(&capture_config(None)).unwrap();
        let changed_input = capture_config(None)
            .replace("request.denied", "response.denied")
            .replace(
                "redaction_profile = \"audit\"",
                "redaction_profile = \"next\"",
            )
            .replace("directory = \"captures-a\"", "directory = \"captures-b\"")
            .replace(
                "filename = \"{requestId}-{suffix}.json\"",
                "filename = \"capture-{requestId}.next-{suffix}.json\"",
            )
            .replace("max_body_bytes = 1024", "max_body_bytes = 2048")
            .replace(
                "max_inflight_body_bytes = 134217728",
                "max_inflight_body_bytes = 268435456",
            )
            .replace("max_files = 10", "max_files = 11")
            .replace("max_total_bytes = 16384", "max_total_bytes = 32768");
        let changed = compile(&changed_input).unwrap();

        assert_eq!(baseline.static_fingerprint, changed.static_fingerprint);
        let capture = changed.reloadable_plan.observation.capture.unwrap();
        assert!(matches!(
            capture.events.as_slice(),
            [CompiledCaptureEvent::ResponseDenied]
        ));
        assert_eq!(capture.redaction_profile, "next");
        assert!(capture.sink.directory().ends_with("captures-b"));
        assert_eq!(
            capture.sink.filename_template(),
            "capture-{requestId}.next-{suffix}.json"
        );
        assert_eq!(capture.max_body_bytes, 2048);
        assert_eq!(capture.max_inflight_body_bytes, 268435456);
        assert_eq!(capture.sink.max_files(), 11);
        assert_eq!(capture.sink.max_total_bytes(), 32768);
    }

    #[test]
    fn policy_decision_logging_defaults_and_levels_compile_exactly() {
        let defaults = compile(MINIMAL).unwrap();
        assert_eq!(
            defaults.reloadable_plan.observation.logging,
            ReloadableLoggingPlan {
                level: CompiledLogLevel::Info,
                policy_decisions: PolicyDecisionLoggingPlan {
                    allows: false,
                    denies: true,
                    allow_level: CompiledDecisionLogLevel::Info,
                    deny_level: CompiledDecisionLogLevel::Warn,
                },
            }
        );

        let explicit = compile(&format!(
            "{MINIMAL}\n[observation.logging.policy_decisions]\nallows = true\ndenies = false\nallow_level = \"warn\"\ndeny_level = \"info\"\n"
        ))
        .unwrap();
        assert_eq!(
            explicit
                .reloadable_plan
                .observation
                .logging
                .policy_decisions,
            PolicyDecisionLoggingPlan {
                allows: true,
                denies: false,
                allow_level: CompiledDecisionLogLevel::Warn,
                deny_level: CompiledDecisionLogLevel::Info,
            }
        );

        for (field, invalid) in [("allow_level", "debug"), ("deny_level", "error")] {
            let error = compile(&format!(
                "{MINIMAL}\n[observation.logging.policy_decisions]\n{field} = \"{invalid}\"\n"
            ))
            .unwrap_err();
            assert_eq!(
                error.path,
                format!("observation.logging.policy_decisions.{field}")
            );
            assert_eq!(error.message, "must be info or warn");
        }
    }

    #[test]
    fn static_and_reloadable_ownership_controls_the_fingerprint() {
        let callback = MINIMAL.replace(
            "[policy]",
            r#"[control]
bind = "127.0.0.1:8898"

[authorization.callback]
public_url = "http://127.0.0.1:8898/_acl-proxy/external-auth/callback"
resume_token_ttl = "5m"
max_pending_operations = 32

[observation.logging]
level = "info"
directory = "logs-a"
max_bytes = 1048576
max_files = 2
console = false

[policy]"#,
        );
        let baseline = compile(&callback).unwrap();

        let callback_url_changed = compile(&callback.replace(
            "http://127.0.0.1:8898/_acl-proxy/external-auth/callback",
            "https://callback.example.test/_acl-proxy/external-auth/callback",
        ))
        .unwrap();
        assert_ne!(
            baseline.static_fingerprint,
            callback_url_changed.static_fingerprint
        );

        let callback_ttl_changed = compile(&callback.replace("5m", "10m")).unwrap();
        assert_eq!(
            baseline.static_fingerprint,
            callback_ttl_changed.static_fingerprint
        );
        assert_eq!(
            callback_ttl_changed
                .reloadable_plan
                .authorization
                .callback
                .as_ref()
                .unwrap()
                .resume_token_ttl,
            Duration::from_secs(10 * 60)
        );

        let log_sink_changed = compile(&callback.replace("logs-a", "logs-b")).unwrap();
        assert_ne!(
            baseline.static_fingerprint,
            log_sink_changed.static_fingerprint
        );

        let log_level_changed =
            compile(&callback.replace("level = \"info\"", "level = \"debug\"")).unwrap();
        assert_eq!(
            baseline.static_fingerprint,
            log_level_changed.static_fingerprint
        );
        assert_eq!(
            log_level_changed.reloadable_plan.observation.logging.level,
            CompiledLogLevel::Debug
        );
    }

    #[test]
    fn static_and_reloadable_ownership_matrix_covers_every_field_family() {
        let baseline = r#"
schema_version = 3

[service]
request_timeout = "30s"
shutdown_drain_timeout = "30s"
max_retiring_generations = 2
max_active_upgrades = 256
max_active_webhook_deliveries = 256
webhook_transport_buffer_bytes = 65536
max_webhook_transport_bytes = 67108864
upgrade_relay_buffer_bytes = 65536
max_upgrade_buffer_bytes = 2147483648
max_upgrade_lifetime = "8h"
max_inflight_wire_body_bytes = 8589934592
max_inflight_wire_body_bytes_per_quota_key = 1073741824
min_wire_body_concurrency = 64
max_content_decoding_expansion_ratio = 128

[control]
bind = "127.0.0.1:8898"
base_path = "/_acl-proxy"
request_header_timeout = "10s"
request_body_timeout = "10s"
max_connections = 128
max_request_body_bytes = 65536

[authorization]
internal_context_headers = []

[authorization.callback]
public_url = "http://127.0.0.1:8898/_acl-proxy/external-auth/callback"
resume_token_ttl = "5m"
max_pending_operations = 32

[authorization.providers.approval]
kind = "webhook"
url = "https://approval.example.test/authorize"
max_request_bytes = 65536
max_response_bytes = 65536

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[egress]
route = "direct"

[egress.origin_tls]
trust = "system"
http_versions = ["http1", "http2"]

[policy]
default = "deny"

[observation.logging]
level = "info"
directory = "logs"
max_bytes = 104857600
max_files = 5
console = true

[safety.loop_detection]
inject = true
header = "x-acl-proxy-request-id"
"#;
        let baseline_compiled = compile(baseline).unwrap();
        let baseline_fingerprint = baseline_compiled.static_fingerprint.clone();
        let baseline_reload = reloadable_ownership_observations(&baseline_compiled.reloadable_plan);

        let static_mutations = [
            ("service shutdown", baseline.replace("shutdown_drain_timeout = \"30s\"", "shutdown_drain_timeout = \"31s\"")),
            ("retiring generations", baseline.replace("max_retiring_generations = 2", "max_retiring_generations = 3")),
            ("upgrade admission", baseline.replace("max_active_upgrades = 256", "max_active_upgrades = 255")),
            ("webhook admission", baseline.replace("max_active_webhook_deliveries = 256", "max_active_webhook_deliveries = 255")),
            ("webhook transport buffer", baseline.replace("webhook_transport_buffer_bytes = 65536", "webhook_transport_buffer_bytes = 65537")),
            ("webhook transport aggregate", baseline.replace("max_webhook_transport_bytes = 67108864", "max_webhook_transport_bytes = 67108865")),
            ("upgrade relay", baseline.replace("upgrade_relay_buffer_bytes = 65536", "upgrade_relay_buffer_bytes = 65537")),
            ("upgrade aggregate", baseline.replace("max_upgrade_buffer_bytes = 2147483648", "max_upgrade_buffer_bytes = 2147483649")),
            ("upgrade lifetime", baseline.replace("max_upgrade_lifetime = \"8h\"", "max_upgrade_lifetime = \"9h\"")),
            ("wire global pool", baseline.replace("max_inflight_wire_body_bytes = 8589934592", "max_inflight_wire_body_bytes = 8589934593")),
            ("wire quota pool", baseline.replace("max_inflight_wire_body_bytes_per_quota_key = 1073741824", "max_inflight_wire_body_bytes_per_quota_key = 1073741825")),
            ("wire concurrency", baseline.replace("min_wire_body_concurrency = 64", "min_wire_body_concurrency = 63")),
            ("control tuple", baseline.replace("8898", "8897")),
            ("control route", baseline.replace("/_acl-proxy", "/_control")),
            ("control timeout", baseline.replace("request_header_timeout = \"10s\"", "request_header_timeout = \"11s\"")),
            ("control body timeout", baseline.replace("request_body_timeout = \"10s\"", "request_body_timeout = \"11s\"")),
            ("control connections", baseline.replace("max_connections = 128", "max_connections = 129")),
            ("control body limit", baseline.replace("max_request_body_bytes = 65536", "max_request_body_bytes = 65537")),
            ("control identity", baseline.replace(
                "[authorization]",
                "[control.tls]\ncertificate_chain = \"control.pem\"\nprivate_key = \"control-key.pem\"\n\n[authorization]",
            )),
            ("listener tuple", baseline.replace("127.0.0.1:8881", "127.0.0.1:8882")),
            ("listener topology", format!(
                "{baseline}\n[listeners.transparent_http]\nendpoint.kind = \"tcp\"\nendpoint.address = \"127.0.0.1:8882\"\nhttp_versions = [\"http1\"]\n"
            )),
            ("MITM ownership", format!(
                "{baseline}\n[listeners.transparent_https]\nendpoint.kind = \"tcp\"\nendpoint.address = \"127.0.0.1:8883\"\nhttp_versions = [\"http1\"]\n\n[mitm]\nmode = \"generated\"\ndirectory = \"mitm\"\n"
            )),
            ("callback public URL", baseline.replace("127.0.0.1:8898/_acl-proxy", "localhost:8898/_acl-proxy")),
            ("logging directory", baseline.replace("directory = \"logs\"", "directory = \"logs-next\"")),
            ("logging rotation bytes", baseline.replace("max_bytes = 104857600", "max_bytes = 104857601")),
            ("logging rotation files", baseline.replace("max_files = 5", "max_files = 6")),
            ("logging console", baseline.replace("console = true", "console = false")),
        ];
        for (name, mutation) in static_mutations {
            let compiled = compile(&mutation)
                .unwrap_or_else(|error| panic!("static mutation {name} failed: {error}"));
            assert_ne!(
                compiled.static_fingerprint, baseline_fingerprint,
                "static family {name} was omitted from the fingerprint"
            );
        }

        let reloadable_mutations = [
            ("request timeout", baseline.replace("request_timeout = \"30s\"", "request_timeout = \"31s\"")),
            ("decode ratio", baseline.replace("max_content_decoding_expansion_ratio = 128", "max_content_decoding_expansion_ratio = 64")),
            ("origin TLS", baseline.replace("trust = \"system\"", "trust = \"insecure\"")),
            ("policy default", baseline.replace("default = \"deny\"", "default = \"allow\"")),
            ("callback TTL", baseline.replace("resume_token_ttl = \"5m\"", "resume_token_ttl = \"6m\"")),
            ("callback admission", baseline.replace("max_pending_operations = 32", "max_pending_operations = 33")),
            ("webhook request limit", baseline.replace("max_request_bytes = 65536", "max_request_bytes = 65535")),
            ("webhook response limit", baseline.replace("max_response_bytes = 65536", "max_response_bytes = 65535")),
            ("loop header", baseline.replace("x-acl-proxy-request-id", "x-acl-proxy-next-id")),
            ("logging level", baseline.replace("level = \"info\"", "level = \"debug\"")),
            ("policy decision logging", baseline.replace(
                "console = true",
                "console = true\n\n[observation.logging.policy_decisions]\nallows = true\ndenies = false\nallow_level = \"warn\"\ndeny_level = \"info\"",
            )),
            ("policy rules", baseline.replace(
                "[observation.logging]",
                "[[policy.rules]]\nid = \"health\"\ndecision = \"allow\"\nmethods = [\"GET\"]\n\n[observation.logging]",
            )),
            ("authorization providers", format!(
                "{baseline}\n[authorization.providers.local]\nkind = \"process\"\ncommand = \"/bin/authorize\"\n"
            )),
            ("credential metadata", format!(
                "{baseline}\n[credentials.sources.token]\nsource = \"environment\"\nvariable = \"TEST_TOKEN\"\n"
            )),
            ("redaction and capture", format!(
                "{baseline}\n[redaction.profiles.audit]\nrules = [{{ literals = [\"marker\"] }}]\n\n[observation.capture]\nevents = [\"request.denied\"]\nredaction_profile = \"audit\"\ndirectory = \"captures\"\nmax_inflight_body_bytes = 134217728\n"
            )),
            ("egress effects", format!(
                "{baseline}\n[[egress.request_headers]]\noperation = \"remove\"\nwhen = \"always\"\nname = \"x-test-header\"\n"
            )),
            ("parent routing", baseline.replace(
                "[egress]\nroute = \"direct\"",
                "[egress]\nroute = \"parent_proxy\"\n\n[egress.parent_proxy]\nkind = \"acl_proxy\"\nurl = \"http://192.0.2.10:8080\"",
            )),
        ];
        for (name, mutation) in reloadable_mutations {
            let compiled = compile(&mutation)
                .unwrap_or_else(|error| panic!("reloadable mutation {name} failed: {error}"));
            assert_eq!(
                compiled.static_fingerprint, baseline_fingerprint,
                "reloadable family {name} changed the static fingerprint"
            );
            assert_ne!(
                reloadable_ownership_observations(&compiled.reloadable_plan),
                baseline_reload,
                "reloadable family {name} was dropped from the compiled plan"
            );
        }
    }

    #[test]
    fn compiled_url_patterns_are_owned_by_their_policy_rule() {
        let input = MINIMAL.replace(
            "[policy]\ndefault = \"deny\"",
            r#"[policy]
default = "deny"

[[policy.rules]]
id = "api"
decision = "allow"
urls = ["https://**.example.test/v1/**"]"#,
        );
        let compiled = compile(&input).unwrap();
        let rule = &compiled.reloadable_plan.policy.rules[0];
        assert_eq!(rule.id, "api");
        assert_eq!(rule.urls.len(), 1);
        assert!(rule.urls[0]
            .is_match(&canonicalize_http_url("https://a.b.example.test/v1/resources").unwrap()));
        assert!(!rule.urls[0]
            .is_match(&canonicalize_http_url("https://example.test/v1/resources").unwrap()));
    }

    #[test]
    fn policy_url_patterns_reject_empty_path_segments_only() {
        for pattern in [
            "https://example.test//admin",
            "https://example.test/a//b",
            "https://example.test///",
        ] {
            let input = format!(
                r#"{MINIMAL}
[[policy.rules]]
id = "empty-path-segment"
decision = "deny"
urls = [{pattern:?}]
"#
            );
            let error = compile(&input).expect_err("an empty path segment must be rejected");
            assert_eq!(error.path, "policy.rules[0].urls[0]");
            assert!(
                error.message.contains("empty segment"),
                "unexpected error for {pattern}: {error}"
            );
        }

        for pattern in [
            "**",
            "https://example.test/",
            "https://example.test/a/",
            "https://example.test/%2F",
            "https://example.test/callback?next=//",
        ] {
            let input = format!(
                r#"{MINIMAL}
[[policy.rules]]
id = "valid-path-shape"
decision = "deny"
urls = [{pattern:?}]
"#
            );
            compile(&input)
                .unwrap_or_else(|error| panic!("valid pattern {pattern} failed: {error}"));
        }
    }

    #[test]
    fn shared_url_contract_crosses_compiled_product_policy_evaluation() {
        use http_access_conformance::{load_matching_suite, MatchOutcome, UrlErrorCode};
        use http_access_policy_acl::PolicyEvaluation;
        use http_access_types::EffectivePolicy;

        for case in load_matching_suite().unwrap().into_cases() {
            let input = format!(
                r#"{MINIMAL}
[[policy.rules]]
id = "url-contract"
decision = "allow"
urls = [{:?}]
"#,
                case.input.pattern
            );
            let compiled = compile(&input);
            if matches!(
                case.expected,
                MatchOutcome::Rejected {
                    error: UrlErrorCode::Pattern
                }
            ) {
                let error = compiled.expect_err("invalid corpus pattern must fail compilation");
                assert!(
                    error.to_string().contains("policy.rules[0].urls[0]"),
                    "{}: compiler did not locate the invalid pattern: {error}",
                    case.id
                );
                continue;
            }

            let compiled = compiled.unwrap_or_else(|error| {
                panic!(
                    "{}: valid corpus pattern failed compilation: {error}",
                    case.id
                )
            });
            let canonical = canonicalize_http_url(&case.input.url);
            let MatchOutcome::Accepted { matches } = case.expected else {
                assert!(
                    canonical.is_err(),
                    "{}: invalid corpus request URL crossed the facts boundary",
                    case.id
                );
                continue;
            };
            let canonical = canonical.unwrap_or_else(|error| {
                panic!("{}: accepted corpus request URL failed: {error}", case.id)
            });
            let snapshot = crate::policy::ProductAclSnapshot::compile(
                &compiled.reloadable_plan.policy,
                http_access_types::PolicyGeneration::new(1).unwrap(),
                http_access_types::SnapshotIdentity::new(),
                &[],
            )
            .unwrap_or_else(|error| panic!("{}: compiled product policy failed: {error}", case.id));
            let decision =
                evaluate_test_policy(&snapshot, &canonical, "192.0.2.10".parse().unwrap());

            match (decision, matches) {
                (PolicyEvaluation::Allow { provenance, .. }, true) => assert!(matches!(
                    provenance.effective_policy(),
                    EffectivePolicy::Rule { id, ordinal: 0 } if id.as_str() == "url-contract"
                )),
                (PolicyEvaluation::Deny { provenance }, false) => assert!(matches!(
                    provenance.effective_policy(),
                    EffectivePolicy::Default
                )),
                (_, expected) => panic!(
                    "{}: compiled product decision disagreed with matches={expected}",
                    case.id
                ),
            }
        }
    }

    #[test]
    fn dns_glob_denies_do_not_capture_ip_literals_under_default_allow() {
        use http_access_policy_acl::PolicyEvaluation;
        use http_access_types::EffectivePolicy;

        let input = MINIMAL.replace(
            "[policy]\ndefault = \"deny\"",
            r#"[policy]
default = "allow"

[[policy.rules]]
id = "dns-deny"
decision = "deny"
urls = ["https://*.example.test/**"]

[[policy.rules]]
id = "ip-deny"
decision = "deny"
urls = ["https://192.0.2.10/**"]"#,
        );
        let compiled = compile(&input).unwrap();
        let snapshot = crate::policy::ProductAclSnapshot::compile(
            &compiled.reloadable_plan.policy,
            http_access_types::PolicyGeneration::new(1).unwrap(),
            SnapshotIdentity::new(),
            &[],
        )
        .unwrap();

        for (url, expected_rule) in [
            ("https://api.example.test/resource", Some("dns-deny")),
            ("https://192.0.2.10/resource", Some("ip-deny")),
            ("https://192.0.2.11/resource", None),
        ] {
            let decision = evaluate_test_policy(
                &snapshot,
                &canonicalize_http_url(url).unwrap(),
                "192.0.2.20".parse().unwrap(),
            );
            match (decision, expected_rule) {
                (PolicyEvaluation::Deny { provenance }, Some(expected)) => assert!(matches!(
                    provenance.effective_policy(),
                    EffectivePolicy::Rule { id, .. } if id.as_str() == expected
                )),
                (PolicyEvaluation::Allow { provenance, .. }, None) => assert!(matches!(
                    provenance.effective_policy(),
                    EffectivePolicy::Default
                )),
                (_, expected) => panic!("unexpected decision for expected rule {expected:?}"),
            }
        }
    }

    #[test]
    fn unresolved_secret_and_source_locators_are_redacted_from_debug() {
        const ENV_LOCATOR: &str = "CREDENTIAL_ENV_LOCATOR_7B31";
        const FILE_LOCATOR: &str = "credential-file-locator-4d92";
        const PROVIDER_VALUE: &str = "provider-environment-value-86ac";
        const REDACTION_LITERAL: &str = "redaction-authored-literal-153e";
        const REDACTION_SOURCE: &str = "REDACTION_ENV_SOURCE_24F8";
        const IDENTITY_ENV_LOCATOR: &str = "AW_REDACTION_TEST_IDENTITY_TOKEN";
        const PARENT_FILE_LOCATOR: &str = "/etc/acl-proxy/parent-identity-file-locator-a45e";

        let input = MINIMAL.replace(
            "[policy]",
            &format!(
                r#"[listeners.explicit_http.identity]
mode = "required"

[authorization.providers.local]
kind = "process"
command = "/bin/true"
environment = {{ PROVIDER_MARKER = "{PROVIDER_VALUE}" }}

[identity]
max_pending_authentications = 8
max_pending_authentications_per_connection = 2

[identity.resolver]
kind = "static"
authority = "redaction-test"

[[identity.resolver.principals]]
id = "redaction-test-principal"
kind = "system"

[[identity.resolver.tokens]]
id = "redaction-test-token"
principal = "redaction-test-principal"
source = "environment"
variable = "{IDENTITY_ENV_LOCATOR}"

[egress]
route = "parent_proxy"

[egress.parent_proxy]
kind = "acl_proxy"
url = "https://parent.example.test:8443"

[egress.parent_proxy.presentation]
kind = "bearer_file"
path = "{PARENT_FILE_LOCATOR}"

[egress.parent_proxy.tls]
trust = "system"

[credentials.sources.environment]
source = "environment"
variable = "{ENV_LOCATOR}"

[credentials.sources.file]
source = "file"
path = "{FILE_LOCATOR}"

[redaction.profiles.secrets]
rules = [{{ literals = ["{REDACTION_LITERAL}"], literal_environment_variables = ["{REDACTION_SOURCE}"] }}]

[policy]"#
            ),
        );
        let compiled = compile(&input).unwrap();
        let candidate_debug = format!("{compiled:?}");
        let plan_debug = format!("{:?}", compiled.reloadable_plan);
        for marker in [
            ENV_LOCATOR,
            FILE_LOCATOR,
            PROVIDER_VALUE,
            REDACTION_LITERAL,
            REDACTION_SOURCE,
            IDENTITY_ENV_LOCATOR,
            PARENT_FILE_LOCATOR,
        ] {
            assert!(!candidate_debug.contains(marker), "{candidate_debug}");
            assert!(!plan_debug.contains(marker), "{plan_debug}");
        }
        let identity_debug = format!(
            "{:?} {:?}",
            IdentitySourcePlan::Environment {
                variable: IDENTITY_ENV_LOCATOR.to_owned()
            },
            IdentitySourcePlan::File {
                path: PathBuf::from(PARENT_FILE_LOCATOR)
            }
        );
        assert!(!identity_debug.contains(IDENTITY_ENV_LOCATOR));
        assert!(!identity_debug.contains(PARENT_FILE_LOCATOR));
        assert_eq!(
            identity_debug,
            "Environment { variable: \"[REDACTED]\" } File { path: \"[REDACTED]\" }"
        );
        assert!(candidate_debug.contains("credential_source_count"));
        assert!(candidate_debug.contains("redaction_profile_count"));
    }

    #[test]
    fn relative_paths_are_rooted_without_opening_them() {
        let input = MINIMAL.replace(
            "[policy]",
            r#"[authorization.providers.local]
kind = "process"
command = "bin/authorize"

[observation.logging]
directory = "logs"

[policy]"#,
        );
        let compiled = compile(&input).unwrap();
        assert_eq!(
            compiled.static_config.logging.directory.as_deref(),
            Some(Path::new("/etc/acl-proxy/logs"))
        );
        let AuthorizationProviderPlan::Process(provider) = compiled
            .reloadable_plan
            .authorization
            .providers
            .get("local")
            .unwrap()
        else {
            panic!("local provider should compile as a process provider");
        };
        assert_eq!(provider.command, Path::new("/etc/acl-proxy/bin/authorize"));
        assert_eq!(provider.working_directory, Path::new("/etc/acl-proxy"));
    }

    #[test]
    fn connect_and_mitm_matrix_is_fail_closed() {
        let input = MINIMAL.replace("http1 = \"deny\"", "http1 = \"mitm\"");
        let error = compile(&input).expect_err("MITM policy must require MITM configuration");
        assert!(error.to_string().contains("mitm"));
    }

    #[test]
    fn parent_proxy_url_validation_matrix() {
        fn parent_config(base: &str, url: &str) -> String {
            format!(
                r#"{base}

[egress]
route = "parent_proxy"

[egress.parent_proxy]
kind = "acl_proxy"
url = "{url}"
"#
            )
        }

        compile(&parent_config(MINIMAL, "http://192.0.2.10:8080"))
            .expect("a nonlocal literal parent should compile");

        for (name, input, expected) in [
            (
                "IPv4 proxy listener",
                parent_config(MINIMAL, "http://127.0.0.1:8881"),
                "proxy listener",
            ),
            (
                "IPv6 proxy listener",
                parent_config(
                    &MINIMAL.replace("127.0.0.1:8881", "[::1]:8881"),
                    "http://[::1]:8881",
                ),
                "proxy listener",
            ),
            (
                "literal loopback",
                parent_config(MINIMAL, "http://127.0.0.2:8080"),
                "literal loopback",
            ),
            (
                "control tuple",
                parent_config(
                    &format!("{MINIMAL}\n\n[control]\nbind = \"127.0.0.1:8898\""),
                    "http://127.0.0.1:8898",
                ),
                "control listener",
            ),
            (
                "parent path",
                parent_config(MINIMAL, "http://192.0.2.10:8080/path"),
                "path or query",
            ),
            (
                "parent query",
                parent_config(MINIMAL, "http://192.0.2.10:8080/?mode=proxy"),
                "path or query",
            ),
        ] {
            let error = compile(&input).unwrap_err();
            assert!(error.to_string().contains(expected), "{name}: {error}");
        }
    }

    #[test]
    fn ipv6_parent_without_authored_server_name_validates_and_activates() {
        let input = format!(
            r#"{MINIMAL}

[egress]
route = "parent_proxy"

[egress.parent_proxy]
kind = "acl_proxy"
url = "https://[2001:db8::10]:8443"

[egress.parent_proxy.tls]
trust = "insecure"
"#
        );
        let compiled = compile(&input).expect("canonical IPv6 parent must validate");
        let activation = crate::egress::EgressActivation::activate_for_test(
            compiled.reloadable_plan.egress,
            &SnapshotIdentity::new(),
            http_access_types::PolicyGeneration::new(1).unwrap(),
            || false,
        )
        .expect("a validated canonical IPv6 parent must activate");

        let (neutral, _) = activation.into_parts();
        let (_, _, route, _, _) = neutral.into_parts();
        assert!(matches!(
            route,
            http_access_types::Route::AclProxyParent { .. }
        ));
    }

    #[test]
    fn ipv6_loopback_endpoints_are_recognized_without_bracket_reparsing() {
        let webhook = format!(
            r#"{MINIMAL}

[authorization.providers.local]
kind = "webhook"
url = "http://[::1]:9000/authorize"
"#
        );
        compile(&webhook).expect("an IPv6 loopback HTTP webhook should compile");

        let callback = format!(
            r#"{MINIMAL}

[control]
bind = "[::1]:8898"

[authorization.callback]
public_url = "http://[::1]:8898/_acl-proxy/external-auth/callback"
"#
        );
        compile(&callback).expect("an IPv6 loopback HTTP callback should compile");
    }

    #[test]
    fn framing_and_sensitive_headers_are_centrally_protected() {
        assert_eq!(
            base_protected_headers(),
            BTreeSet::from([
                "host",
                "authorization",
                "proxy-authorization",
                "proxy-authenticate",
                "cookie",
                "set-cookie",
                "connection",
                "proxy-connection",
                "keep-alive",
                "transfer-encoding",
                "te",
                "trailer",
                "upgrade",
                "content-length",
                "content-encoding",
                "x-aw-identity-token",
            ])
        );
        for header in ["proxy-authenticate", "content-length", "content-encoding"] {
            let input = MINIMAL.replace(
                "[policy]\ndefault = \"deny\"",
                &format!(
                    r#"[policy]
default = "deny"

[[policy.rules]]
id = "challenge"
decision = "allow"
methods = ["GET"]

[[policy.rules.response_headers]]
operation = "set"
when = "always"
name = "{header}"
value = "invalid-framing""#
                ),
            );
            let error = compile(&input).expect_err("protected header must fail compilation");
            assert!(error.to_string().contains("protected"), "{header}: {error}");
        }
    }

    #[test]
    fn l05_identity_carrier_is_rejected_from_each_provider_header_projection() {
        for provider in [
            r#"[authorization.providers.local]
kind = "process"
command = "/bin/authorize"
include_headers = ["x-aw-identity-token"]
"#,
            r#"[authorization.providers.local]
kind = "webhook"
url = "https://approval.example.test/authorize"
include_headers = ["x-aw-identity-token"]
"#,
            r#"[authorization.providers.local]
kind = "unix_socket"
socket_path = "/run/acl-proxy/authorization.sock"
timeout = "2s"
on_failure = "deny"
include_headers = ["x-aw-identity-token"]
max_request_bytes = 262144
max_response_bytes = 65536
max_pending_requests = 128
"#,
        ] {
            let input = MINIMAL.replace("[policy]", &format!("{provider}\n[policy]"));
            let error =
                compile(&input).expect_err("identity bearer must not enter provider headers");
            assert!(
                error
                    .to_string()
                    .contains("provider may not receive a protected header"),
                "{error}"
            );
        }

        let provider_output = MINIMAL.replace(
            "[policy]",
            r#"[credentials]
allowed_custom_headers = ["x-aw-identity-token"]

[authorization.providers.local]
kind = "process"
command = "/bin/authorize"

[authorization.providers.local.outputs.identity]
kind = "custom_header"
header = "x-aw-identity-token"
transport_security = "tls_required"

[policy]"#,
        );
        let error = compile(&provider_output)
            .expect_err("provider output cannot target the identity carrier");
        assert!(
            error.to_string().contains("reserved by the proxy"),
            "{error}"
        );
    }

    #[test]
    fn tls_owner_and_trust_validation_matrix() {
        compile(&format!(
            r#"{MINIMAL}

[egress.origin_tls]
trust = "custom"
ca_certificate = "origin-ca.pem"
http_versions = ["http1"]
"#
        ))
        .expect("custom origin trust with a CA should compile");

        for (name, suffix, expected) in [
            (
                "custom trust without CA",
                r#"
[egress.origin_tls]
trust = "custom"
"#,
                "required for custom trust",
            ),
            (
                "system trust with CA",
                r#"
[egress.origin_tls]
trust = "system"
ca_certificate = "unexpected.pem"
"#,
                "must be absent",
            ),
            (
                "HTTPS parent without TLS policy",
                r#"
[egress]
route = "parent_proxy"

[egress.parent_proxy]
kind = "acl_proxy"
url = "https://192.0.2.10:8443"
"#,
                "is required for an HTTPS parent",
            ),
            (
                "HTTP parent with TLS policy",
                r#"
[egress]
route = "parent_proxy"

[egress.parent_proxy]
kind = "acl_proxy"
url = "http://192.0.2.10:8080"

[egress.parent_proxy.tls]
trust = "system"
"#,
                "must be absent for an HTTP parent",
            ),
        ] {
            let error = compile(&format!("{MINIMAL}\n{suffix}")).unwrap_err();
            assert!(error.to_string().contains(expected), "{name}: {error}");
        }
    }

    #[test]
    fn authored_bind_requires_nonzero_socket_addr() {
        let hostname = MINIMAL.replace("127.0.0.1:8881", "proxy.example.test:8881");
        assert!(
            toml::from_str::<super::super::authoring::AuthoringConfig>(&hostname).is_err(),
            "bind hostnames must be rejected by the authored SocketAddr type"
        );

        for (name, input) in [
            (
                "proxy listener",
                MINIMAL.replace("127.0.0.1:8881", "127.0.0.1:0"),
            ),
            (
                "control listener",
                format!("{MINIMAL}\n\n[control]\nbind = \"127.0.0.1:0\""),
            ),
        ] {
            let error = compile(&input).unwrap_err();
            assert!(error.to_string().contains("port 0"), "{name}: {error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn access_flow_listener_contract_is_strict_and_fingerprinted() {
        let socket = "/tmp/acl-proxy-transparent-http.sock";
        let unix = format!(
            r#"{MINIMAL}

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80, 8080]
http_versions = ["http1"]

[listeners.transparent_http.endpoint.transport]
kind = "unix"
path = "{socket}"
mode = "0606"
"#
        );
        let compiled = compile(&unix).expect("valid Unix transparent endpoint should compile");
        let listener = compiled
            .static_config
            .listeners
            .transparent_http
            .as_ref()
            .unwrap();
        assert!(matches!(
            &listener.endpoint,
            StaticListenerEndpoint::AccessFlow {
                admission_timeout,
                allowed_destination_ports,
                transport: StaticAccessFlowTransport::Unix { path, mode },
            } if *admission_timeout == Duration::from_secs(2)
                && allowed_destination_ports == &[80, 8080]
                && path == Path::new(socket)
                && *mode == 0o606
        ));

        let tcp_only = compile(MINIMAL).unwrap();
        assert_ne!(tcp_only.static_fingerprint, compiled.static_fingerprint);

        for (name, input, expected) in [
            (
                "missing timeout",
                unix.replace("endpoint.admission_timeout = \"2s\"\n", ""),
                "admission_timeout",
            ),
            (
                "missing destination ports",
                unix.replace("endpoint.allowed_destination_ports = [80, 8080]\n", ""),
                "allowed_destination_ports",
            ),
            (
                "obsolete sibling timeout",
                MINIMAL.replace(
                    "http_versions = [\"http1\"]",
                    "admission_timeout = \"1s\"\nhttp_versions = [\"http1\"]",
                ),
                "admission_timeout",
            ),
        ] {
            let error =
                toml::from_str::<super::super::authoring::AuthoringConfig>(&input).unwrap_err();
            assert!(error.to_string().contains(expected), "{name}: {error}");
        }

        for (name, input, expected) in [
            (
                "removed endpoint kind",
                unix.replace("endpoint.kind = \"access_flow\"", "endpoint.kind = \"unix_proxy_v2\""),
                "unix_proxy_v2",
            ),
            (
                "mixed flat path",
                unix.replace(
                    "endpoint.allowed_destination_ports = [80, 8080]",
                    "endpoint.allowed_destination_ports = [80, 8080]\nendpoint.path = \"/tmp/legacy.sock\"",
                ),
                "path",
            ),
            (
                "remote transport",
                unix.replace(
                    "kind = \"unix\"\npath =",
                    "kind = \"tls_tcp\"\ncertificate = \"secret.pem\"\npath =",
                ),
                "tls_tcp",
            ),
        ] {
            let error =
                toml::from_str::<super::super::authoring::AuthoringConfig>(&input).unwrap_err();
            assert!(error.to_string().contains(expected), "{name}: {error}");
        }

        for (name, input, expected) in [
            (
                "duplicate destination ports",
                unix.replace(
                    "endpoint.allowed_destination_ports = [80, 8080]",
                    "endpoint.allowed_destination_ports = [80, 80]",
                ),
                "unique nonzero",
            ),
            (
                "zero destination port",
                unix.replace(
                    "endpoint.allowed_destination_ports = [80, 8080]",
                    "endpoint.allowed_destination_ports = [0]",
                ),
                "unique nonzero",
            ),
            (
                "invalid mode",
                unix.replace("mode = \"0606\"", "mode = \"606\""),
                "four-digit octal",
            ),
            (
                "relative path",
                unix.replace(socket, "transparent-http.sock"),
                "absolute path",
            ),
            (
                "non-normalized path",
                unix.replace(socket, "/tmp/../tmp/acl-proxy-transparent-http.sock"),
                "already be normalized",
            ),
            (
                "explicit Unix endpoint",
                MINIMAL
                    .replace(
                        "endpoint.kind = \"tcp\"\nendpoint.address = \"127.0.0.1:8881\"",
                        &format!(
                            "endpoint.kind = \"access_flow\"\nendpoint.admission_timeout = \"2s\"\nendpoint.allowed_destination_ports = [80]\nendpoint.transport = {{ kind = \"unix\", path = \"{socket}\", mode = \"0600\" }}"
                        ),
                    ),
                "valid only for transparent",
            ),
        ] {
            let error = compile(&input).unwrap_err();
            assert!(error.to_string().contains(expected), "{name}: {error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn access_flow_rejects_duplicate_paths_and_client_cidr_identity() {
        let listeners = r#"
[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
endpoint.transport = { kind = "unix", path = "/tmp/acl-proxy-traffic.sock", mode = "0600" }
http_versions = ["http1"]

[listeners.transparent_https]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [443]
endpoint.transport = { kind = "unix", path = "/tmp/acl-proxy-traffic.sock", mode = "0600" }
http_versions = ["http1"]

[mitm]
mode = "generated"
directory = "mitm"
"#;
        let duplicate = format!("{MINIMAL}\n{listeners}");
        let error = compile(&duplicate).unwrap_err();
        assert!(
            error.to_string().contains("collides with another Unix"),
            "{error}"
        );

        let lock_collision = duplicate.replace(
            "path = \"/tmp/acl-proxy-traffic.sock\"",
            "path = \"/tmp/acl-proxy-traffic.sock.lock\"",
        );
        let lock_collision = lock_collision.replacen(
            "path = \"/tmp/acl-proxy-traffic.sock.lock\"",
            "path = \"/tmp/acl-proxy-traffic.sock\"",
            1,
        );
        let error = compile(&lock_collision).unwrap_err();
        assert!(error.to_string().contains("socket or lock path"), "{error}");

        let cidr = r#"
[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
endpoint.transport = { kind = "unix", path = "/tmp/acl-proxy-traffic.sock", mode = "0600" }
http_versions = ["http1"]

[[policy.rules]]
id = "source-sensitive"
decision = "deny"
client_cidrs = ["127.0.0.0/8"]
"#;
        let error = compile(&format!("{MINIMAL}\n{cidr}")).unwrap_err();
        assert!(
            error.to_string().contains("local-workstation principal"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn shipped_unix_host_example_compiles_strictly() {
        compile(include_str!("../../examples/acl-proxy-access-flow.toml"))
            .expect("shipped Unix host example should remain a strict valid config");
    }

    #[test]
    fn listener_protocol_connect_matrix() {
        let valid_h1_h2 = MINIMAL
            .replace(
                "http_versions = [\"http1\"]",
                "http_versions = [\"http1\", \"http2\"]",
            )
            .replace("http1 = \"deny\"", "http1 = \"deny\"\nhttp2 = \"deny\"");
        compile(&valid_h1_h2).expect("CONNECT entries should cover enabled protocols exactly");

        for (name, input, expected) in [
            (
                "missing HTTP/1 CONNECT policy",
                MINIMAL.replace("http1 = \"deny\"", "http2 = \"deny\""),
                "connect.http1",
            ),
            (
                "missing HTTP/2 CONNECT policy",
                MINIMAL.replace(
                    "http_versions = [\"http1\"]",
                    "http_versions = [\"http1\", \"http2\"]",
                ),
                "connect.http2",
            ),
            (
                "disabled HTTP/2 CONNECT policy",
                MINIMAL.replace("http1 = \"deny\"", "http1 = \"deny\"\nhttp2 = \"deny\""),
                "connect.http2",
            ),
            (
                "duplicate HTTP version",
                MINIMAL.replace(
                    "http_versions = [\"http1\"]",
                    "http_versions = [\"http1\", \"http1\"]",
                ),
                "duplicate",
            ),
        ] {
            let error = compile(&input).unwrap_err();
            assert!(error.to_string().contains(expected), "{name}: {error}");
        }
    }

    #[test]
    fn cleartext_listener_limits_are_defaulted_validated_and_fingerprinted() {
        let baseline = compile(MINIMAL).unwrap();
        let listener = baseline
            .static_config
            .listeners
            .explicit_http
            .as_ref()
            .unwrap();
        assert_eq!(listener.request_header_timeout, Duration::from_secs(10));
        assert_eq!(listener.max_connections, 1024);
        assert_eq!(listener.max_concurrent_streams, 128);

        let configured = MINIMAL.replace(
            "http_versions = [\"http1\"]",
            "http_versions = [\"http1\"]\nrequest_header_timeout = \"3s\"\nmax_connections = 7\nmax_concurrent_streams = 11",
        );
        let configured = compile(&configured).unwrap();
        let listener = configured
            .static_config
            .listeners
            .explicit_http
            .as_ref()
            .unwrap();
        assert_eq!(listener.request_header_timeout, Duration::from_secs(3));
        assert_eq!(listener.max_connections, 7);
        assert_eq!(listener.max_concurrent_streams, 11);
        assert_ne!(baseline.static_fingerprint, configured.static_fingerprint);

        for (field, value) in [("max_connections", "0"), ("max_concurrent_streams", "0")] {
            let invalid = MINIMAL.replace(
                "http_versions = [\"http1\"]",
                &format!("http_versions = [\"http1\"]\n{field} = {value}"),
            );
            let error = compile(&invalid).unwrap_err();
            assert!(error.to_string().contains(field), "{field}: {error}");
        }
    }

    #[test]
    fn control_tls_and_public_url_matrix() {
        let loopback = format!("{MINIMAL}\n\n[control]\nbind = \"127.0.0.1:8898\"");
        compile(&loopback).expect("loopback control may use plaintext");

        let nonloopback_tls = format!(
            r#"{MINIMAL}

[control]
bind = "192.0.2.20:8898"

[control.tls]
certificate_chain = "control.pem"
private_key = "control-key.pem"
"#
        );
        compile(&nonloopback_tls).expect("nonloopback control with TLS should compile");

        for (name, suffix, expected) in [
            (
                "nonloopback control without TLS",
                r#"
[control]
bind = "192.0.2.20:8898"
"#,
                "control.tls",
            ),
            (
                "callback without control",
                r#"
[authorization.callback]
public_url = "https://callback.example.test/_acl-proxy/external-auth/callback"
"#,
                "requires the control listener",
            ),
            (
                "plaintext nonloopback callback",
                r#"
[control]
bind = "127.0.0.1:8898"

[authorization.callback]
public_url = "http://192.0.2.20:8898/_acl-proxy/external-auth/callback"
"#,
                "plain HTTP requires",
            ),
            (
                "callback path mismatch",
                r#"
[control]
bind = "127.0.0.1:8898"

[authorization.callback]
public_url = "http://127.0.0.1:8898/not-the-callback"
"#,
                "path must be exactly",
            ),
        ] {
            let error = compile(&format!("{MINIMAL}\n{suffix}")).unwrap_err();
            assert!(error.to_string().contains(expected), "{name}: {error}");
        }
    }

    #[test]
    fn mapped_ipv6_unspecified_control_bind_is_rejected() {
        let input = format!(
            r#"{MINIMAL}

[control]
bind = "[::ffff:0.0.0.0]:8898"
"#
        );
        let error = compile(&input).expect_err("mapped unspecified control bind must be rejected");
        assert_eq!(error.path, "control.bind");
        assert!(error.to_string().contains("unspecified"));
    }

    #[test]
    fn mapped_ipv6_loopback_control_and_callback_compile_canonically() {
        let input = format!(
            r#"{MINIMAL}

[control]
bind = "[::ffff:127.0.0.1]:8898"

[authorization.callback]
public_url = "http://[::ffff:127.0.0.1]:8898/_acl-proxy/external-auth/callback"
"#
        );
        let compiled =
            compile(&input).expect("mapped loopback control and plaintext callback must compile");
        let canonical = compile(&input.replace("[::ffff:127.0.0.1]", "127.0.0.1"))
            .expect("equivalent canonical callback spelling must compile");
        assert_eq!(
            compiled.static_config.control.as_ref().unwrap().bind,
            "127.0.0.1:8898".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            compiled
                .static_config
                .callback_public_url
                .as_ref()
                .map(CanonicalUrl::as_str),
            Some("http://127.0.0.1:8898/_acl-proxy/external-auth/callback")
        );
        assert!(compiled.static_config == canonical.static_config);
        assert_eq!(
            serde_json::to_vec(&compiled.static_config).unwrap(),
            serde_json::to_vec(&canonical.static_config).unwrap()
        );
        assert_eq!(compiled.static_fingerprint, canonical.static_fingerprint);
    }

    #[test]
    fn inbound_credential_header_is_rejected_in_value_predicates() {
        let input = MINIMAL.replace(
            "[policy]\ndefault = \"deny\"",
            r#"[authorization.providers.local]
kind = "process"
command = "/bin/authorize"
include_headers = ["x-aw-identity-token"]

[credentials.inbound.identity]
header = "x-aw-identity-token"
process_providers = ["local"]

[policy]
default = "deny"

[[policy.rules]]
id = "identity-value"
decision = "allow"

[policy.rules.headers.all]
x-aw-identity-token = ["secret"]"#,
        );
        let error = compile(&input).expect_err("inbound credential values are not predicates");
        assert!(error.to_string().contains("reserved by the proxy"));
    }

    #[test]
    fn sanitized_production_roles_compile_as_strict_schema() {
        for (name, fixture) in [
            (
                "host TCP",
                include_str!("../../tests/fixtures/production/host-proxy-tcp.toml"),
            ),
            (
                "host UDS",
                include_str!("../../tests/fixtures/production/host-proxy-uds.toml"),
            ),
            (
                "common container",
                include_str!("../../tests/fixtures/production/common-container-proxy.toml"),
            ),
            (
                "internal container",
                include_str!("../../tests/fixtures/production/internal-container-proxy.toml"),
            ),
        ] {
            let compiled =
                compile(fixture).unwrap_or_else(|error| panic!("{name} fixture failed: {error}"));
            assert_eq!(
                compiled.static_config.service.max_active_webhook_deliveries,
                256
            );
            assert_eq!(
                compiled
                    .static_config
                    .service
                    .webhook_transport_buffer_bytes,
                64 * 1024
            );
            let control = compiled
                .static_config
                .control
                .as_ref()
                .expect("production fixture must retain its control topology");
            assert_eq!(control.request_body_timeout, Duration::from_secs(10));
            assert_eq!(
                control.parser_arena_bytes,
                control.max_connections * PARSER_STORE_BYTES
            );
            assert!(
                compiled
                    .reloadable_plan
                    .resource_plan
                    .max_reachable_http_body_combined_peak_bytes
                    <= 231 * MIB,
                "{name} fixture exceeds the production HTTP body-plan ceiling"
            );
        }
    }

    #[test]
    fn method_incompatible_delegate_paths_do_not_accumulate_body_plans() {
        let input = resource_config(
            "",
            r#"
[authorization.providers.body]
kind = "process"
command = "/bin/body-provider"
include_request_body = true
max_request_body_bytes = 1048576
max_decoded_request_body_bytes = 1048576
retire_timeout = "1h"

[redaction.profiles.large]
max_body_bytes = 8388608
max_decoded_body_bytes = 8388608
rules = [{ literals = ["safe-test-literal"] }]
"#,
            r#"
[[policy.rules]]
id = "get-delegate"
decision = "delegate"
methods = ["GET"]
authorization_provider = "body"

[[policy.rules]]
id = "post-redaction"
decision = "allow"
methods = ["POST"]
redaction_profile = "large"
"#,
        );
        let compiled = compile(&input).unwrap();
        let plan = &compiled.reloadable_plan.resource_plan;
        let get_peak = decode_peak(MIB, MIB).unwrap();
        let redaction_peak = decode_peak(8 * MIB, 8 * MIB).unwrap();
        assert_eq!(
            plan.combined_http_body_peaks_for_test()[0],
            get_peak + canonical_runtime_replay_storage(MIB)
        );
        assert_eq!(
            plan.combined_http_body_peaks_for_test()[1],
            redaction_peak + canonical_runtime_replay_storage(8 * MIB)
        );
    }

    #[test]
    fn multi_method_delegate_preserves_method_specialized_successor_resources() {
        let definitions = r#"
[authorization.providers.first]
kind = "process"
command = "/bin/first-provider"
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 2097152
max_decoded_request_body_bytes = 2097152
max_stdout_line_bytes = 3145728
retire_timeout = "1s"

[authorization.providers.middle]
kind = "process"
command = "/bin/middle-provider"
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 1048576
max_decoded_request_body_bytes = 1048576
max_stdout_line_bytes = 2097152
retire_timeout = "1s"

[authorization.providers.large-post]
kind = "process"
command = "/bin/large-post-provider"
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 33554432
max_decoded_request_body_bytes = 33554432
max_stdout_line_bytes = 16777216
retire_timeout = "1s"
"#;
        let rules = r#"
[[policy.rules]]
id = "first-get"
decision = "delegate"
methods = ["GET"]
authorization_provider = "first"

[[policy.rules]]
id = "middle-get-post"
decision = "delegate"
methods = ["GET", "POST"]
authorization_provider = "middle"

[[policy.rules]]
id = "large-post"
decision = "delegate"
methods = ["POST"]
authorization_provider = "large-post"
"#;
        let input = resource_config("", definitions, rules);
        let authored: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let compiled = compile(&input).unwrap();
        let body_reads = &compiled
            .reloadable_plan
            .policy
            .http_body_read_plans_by_cursor;
        let resources = &compiled.reloadable_plan.resource_plan;

        assert_eq!(body_read_limits(body_reads[0]), Some((2 * MIB, 2 * MIB)));
        assert_eq!(body_read_limits(body_reads[1]), Some((32 * MIB, 32 * MIB)));

        let first = compile_http_rule_schedule(&authored, &authored.policy.rules[0]).unwrap();
        let middle = compile_http_rule_schedule(&authored, &authored.policy.rules[1]).unwrap();
        let expected_product_peak = first
            .initial_peak
            .max(
                first.retained_original_after_pass.unwrap()
                    + middle.max_incoming_additional_bytes(),
            )
            .max(decode_peak(2 * MIB, 2 * MIB).unwrap())
            .max(guarded(64 * 1024));
        assert_eq!(
            resources.http_body_resources_by_cursor[0],
            HttpBodyResourcePlan {
                product_incremental_peak_bytes: expected_product_peak,
                runtime_replay_capacity_bytes: canonical_runtime_replay_storage(2 * MIB),
                combined_peak_bytes: expected_product_peak
                    + canonical_runtime_replay_storage(2 * MIB),
            }
        );
        assert_eq!(
            resources.http_body_resources_by_cursor[1].runtime_replay_capacity_bytes,
            canonical_runtime_replay_storage(32 * MIB)
        );
        assert!(
            resources.http_body_resources_by_cursor[0].combined_peak_bytes
                < resources.http_body_resources_by_cursor[1].combined_peak_bytes
        );
    }

    #[test]
    fn delegate_continuation_keeps_only_the_original_allocation_live() {
        let input = resource_config(
            "",
            r#"
[authorization.providers.first]
kind = "process"
command = "/bin/first-provider"
include_request_body = true
max_request_body_bytes = 1048576
max_decoded_request_body_bytes = 16777216
retire_timeout = "1h"

[redaction.profiles.terminal]
max_body_bytes = 1048576
max_decoded_body_bytes = 8388608
rules = [{ literals = ["terminal-test-literal"] }]
"#,
            r#"
[[policy.rules]]
id = "delegate"
decision = "delegate"
methods = ["POST"]
authorization_provider = "first"

[[policy.rules]]
id = "terminal"
decision = "allow"
methods = ["POST"]
redaction_profile = "terminal"
"#,
        );
        let compiled = compile(&input).unwrap();
        let scratch = shared_matcher_scratch_bytes("terminal-test-literal".len());
        let first_decode = decode_peak(MIB, 16 * MIB).unwrap();
        let terminal_decode = decode_peak(MIB, 8 * MIB).unwrap();
        let first_retained_terminal = guarded(16 * MIB) + guarded(8 * MIB) + guarded(scratch);
        let terminal_stage = 2 * guarded(8 * MIB) + guarded(scratch);
        let first_replay = canonical_runtime_replay_storage(16 * MIB);
        let terminal_replay = canonical_runtime_replay_storage(8 * MIB);
        assert_eq!(
            compiled
                .reloadable_plan
                .resource_plan
                .combined_http_body_peaks_for_test(),
            vec![
                first_decode.max(first_retained_terminal) + first_replay,
                terminal_decode.max(terminal_stage) + terminal_replay,
                0,
            ]
        );
    }

    #[test]
    fn decoded_original_survives_multiple_compatible_delegate_passes() {
        let input = resource_config(
            "",
            r#"
[authorization.providers.first]
kind = "process"
command = "/bin/first-provider"
include_request_body = true
max_request_body_bytes = 1048576
max_decoded_request_body_bytes = 16777216
retire_timeout = "1h"

[authorization.providers.second]
kind = "process"
command = "/bin/second-provider"
include_request_body = true
max_request_body_bytes = 1048576
max_decoded_request_body_bytes = 4194304
retire_timeout = "1h"

[redaction.profiles.terminal]
max_body_bytes = 1048576
max_decoded_body_bytes = 8388608
rules = [{ literals = ["terminal-test-literal"] }]
"#,
            r#"
[[policy.rules]]
id = "first"
decision = "delegate"
methods = ["GET"]
authorization_provider = "first"

[[policy.rules]]
id = "second"
decision = "delegate"
methods = ["GET"]
authorization_provider = "second"

[[policy.rules]]
id = "terminal"
decision = "allow"
methods = ["GET"]
redaction_profile = "terminal"
"#,
        );
        let compiled = compile(&input).unwrap();
        let scratch = shared_matcher_scratch_bytes("terminal-test-literal".len());
        let first_decode = decode_peak(MIB, 16 * MIB).unwrap();
        let terminal_decode = decode_peak(MIB, 8 * MIB).unwrap();
        let first_retained_terminal = guarded(16 * MIB) + guarded(8 * MIB) + guarded(scratch);
        let terminal_stage = 2 * guarded(8 * MIB) + guarded(scratch);
        let first_replay = canonical_runtime_replay_storage(16 * MIB);
        let terminal_replay = canonical_runtime_replay_storage(8 * MIB);
        assert_eq!(
            compiled
                .reloadable_plan
                .resource_plan
                .combined_http_body_peaks_for_test(),
            vec![
                first_decode.max(first_retained_terminal) + first_replay,
                terminal_decode.max(terminal_stage) + terminal_replay,
                terminal_decode.max(terminal_stage) + terminal_replay,
                0,
            ]
        );
    }

    #[test]
    fn large_provider_replacement_is_planned_after_small_encoded_input() {
        let input = resource_config(
            "",
            r#"
[authorization.providers.replacing]
kind = "process"
command = "/bin/replacing-provider"
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 1048576
max_decoded_request_body_bytes = 16777216
max_stdout_line_bytes = 16777216
retire_timeout = "1h"
"#,
            r#"
[[policy.rules]]
id = "replacement"
decision = "delegate"
methods = ["POST"]
authorization_provider = "replacing"
"#,
        );
        let compiled = compile(&input).unwrap();
        let mandatory_decode = decode_peak(MIB, 16 * MIB).unwrap();
        let replacement_decode = replacement_decode_peak(16 * MIB, 16 * MIB).unwrap();
        let runtime_budget = canonical_runtime_replay_storage(16 * MIB);
        assert_eq!(
            compiled
                .reloadable_plan
                .resource_plan
                .max_reachable_http_body_combined_peak_bytes,
            mandatory_decode.max(replacement_decode) + runtime_budget
        );
    }

    #[test]
    fn process_replacement_projects_exact_runtime_budget_without_webhook_resources() {
        let decoded_limit = MAX_BUFFER_GROWTH_BYTES + 1;
        let input = resource_config(
            "",
            &format!(
                r#"
[authorization.providers.replacing]
kind = "process"
command = "/bin/replacing-provider"
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = {decoded_limit}
max_decoded_request_body_bytes = {decoded_limit}
max_stdout_line_bytes = 1048576
retire_timeout = "1s"
"#
            ),
            r#"
[[policy.rules]]
id = "replacement"
decision = "delegate"
methods = ["POST"]
authorization_provider = "replacing"
"#,
        );
        let authored: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let schedule = compile_http_rule_schedule(&authored, &authored.policy.rules[0]).unwrap();
        let compiled = compile(&input).unwrap();
        let resources = &compiled.reloadable_plan.resource_plan;
        let runtime_budget = canonical_runtime_replay_storage(decoded_limit);
        let guarded_peak = schedule
            .initial_peak
            .max(decode_peak(decoded_limit, decoded_limit).unwrap());

        assert_eq!(
            resources.runtime_replay_capacities_for_test(),
            [runtime_budget, 0]
        );
        assert_eq!(
            resources.combined_http_body_peaks_for_test(),
            [guarded_peak + runtime_budget, 0]
        );
        assert_eq!(resources.webhook_request_allocation_bytes_by_rule, [None]);
        assert_eq!(resources.webhook_callback_allocation_bytes_by_rule, [None]);
    }

    #[test]
    fn delegate_pass_keeps_later_replacement_budget_reachable() {
        let first_limit = 2 * MAX_BUFFER_GROWTH_BYTES;
        let replacement_limit = MAX_BUFFER_GROWTH_BYTES + 1;
        let input = resource_config(
            "",
            &format!(
                r#"
[authorization.providers.first]
kind = "process"
command = "/bin/first-provider"
include_request_body = true
max_request_body_bytes = {first_limit}
max_decoded_request_body_bytes = {first_limit}
max_stdout_line_bytes = 1048576
retire_timeout = "1s"

[authorization.providers.replacing]
kind = "process"
command = "/bin/replacing-provider"
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = {replacement_limit}
max_decoded_request_body_bytes = {replacement_limit}
max_stdout_line_bytes = 1048576
retire_timeout = "1s"
"#
            ),
            r#"
[[policy.rules]]
id = "first"
decision = "delegate"
methods = ["POST"]
authorization_provider = "first"

[[policy.rules]]
id = "replacement"
decision = "delegate"
methods = ["POST"]
authorization_provider = "replacing"
"#,
        );
        let compiled = compile(&input).unwrap();
        let first_cursor_budget = canonical_runtime_replay_storage(first_limit);
        let later_cursor_budget = canonical_runtime_replay_storage(replacement_limit);

        assert_eq!(
            compiled
                .reloadable_plan
                .resource_plan
                .runtime_replay_capacities_for_test(),
            [first_cursor_budget, later_cursor_budget, 0]
        );
    }

    #[test]
    fn disjoint_method_path_does_not_combine_replacement_reserve_with_larger_stage() {
        let input = resource_config(
            "",
            r#"
[authorization.providers.get-replacement]
kind = "process"
command = "/bin/get-provider"
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 1048576
max_decoded_request_body_bytes = 1048576
max_stdout_line_bytes = 2097152
retire_timeout = "1s"

[redaction.profiles.post-stage]
max_body_bytes = 33554432
max_decoded_body_bytes = 33554432
rules = [{ literals = ["post-stage"] }]
"#,
            r#"
[[policy.rules]]
id = "get-replacement"
decision = "delegate"
methods = ["GET"]
authorization_provider = "get-replacement"

[[policy.rules]]
id = "post-stage"
decision = "allow"
methods = ["POST"]
redaction_profile = "post-stage"
"#,
        );
        let authored: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let post_schedule =
            compile_http_rule_schedule(&authored, &authored.policy.rules[1]).unwrap();
        let replacement_budget = canonical_runtime_replay_storage(MIB);
        let post_replay = canonical_runtime_replay_storage(32 * MIB);
        let post_decode_peak = decode_peak(32 * MIB, 32 * MIB).unwrap();
        let post_path_peak = post_schedule.initial_peak.max(post_decode_peak);
        let compiled = compile(&input).unwrap();
        let resources = &compiled.reloadable_plan.resource_plan;

        assert_eq!(
            resources.runtime_replay_capacities_for_test(),
            [replacement_budget, post_replay, 0]
        );
        let combined_post_path = post_path_peak + post_replay;
        let exchange_peak = resources.max_reachable_http_exchange_peak_bytes;
        assert_eq!(
            resources.max_reachable_http_body_combined_peak_bytes,
            combined_post_path
        );
        assert!(
            resources.http_body_resources_by_cursor[0].combined_peak_bytes < combined_post_path
        );

        let exact_service = format!(
            "max_inflight_wire_body_bytes = {}\nmax_inflight_wire_body_bytes_per_quota_key = {}\nmin_wire_body_concurrency = 1",
            4 * exchange_peak,
            exchange_peak
        );
        let exact = input.replacen(
            "request_timeout = \"1s\"",
            &format!("request_timeout = \"1s\"\n{exact_service}"),
            1,
        );
        compile(&exact).expect("disjoint methods fit the exact compatible-path capacity");
    }

    #[test]
    fn runtime_replacement_reserve_participates_in_quota_capacity_rejection() {
        let definitions = r#"
[authorization.providers.replacing]
kind = "process"
command = "/bin/replacing-provider"
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 1
max_decoded_request_body_bytes = 1
max_stdout_line_bytes = 65536
retire_timeout = "1s"
"#;
        let rules = r#"
[[policy.rules]]
id = "replacement"
decision = "delegate"
methods = ["POST"]
authorization_provider = "replacing"
"#;
        let compiled = compile(&resource_config("", definitions, rules)).unwrap();
        let resources = &compiled.reloadable_plan.resource_plan;
        let combined_peak = resources.max_reachable_http_body_combined_peak_bytes;
        let exchange_peak = resources.max_reachable_http_exchange_peak_bytes;
        assert_eq!(
            exchange_peak,
            combined_peak + resources.forward_response_peak_bytes
        );
        let service = format!(
            "max_inflight_wire_body_bytes = {}\nmax_inflight_wire_body_bytes_per_quota_key = {}\nmin_wire_body_concurrency = 1",
            4 * exchange_peak,
            exchange_peak - 1
        );

        let error = compile(&resource_config(&service, definitions, rules))
            .expect_err("the quota must hold the guarded peak plus runtime admission reserve");

        assert!(
            error
                .to_string()
                .contains("largest pass-reachable request/response working set"),
            "{error}"
        );
    }

    #[test]
    fn stricter_profile_limits_every_combined_provider_body_stage() {
        let guarded_peak = decode_peak(1, 1).unwrap();
        let runtime_budget = canonical_runtime_replay_storage(1);
        let combined_peak = guarded_peak + runtime_budget;
        let response_peak = compile(&resource_config("", "", ""))
            .unwrap()
            .reloadable_plan
            .resource_plan
            .forward_response_peak_bytes;
        let exchange_peak = combined_peak + response_peak;
        let input = resource_config(
            &format!(
                "max_inflight_wire_body_bytes = {}\nmax_inflight_wire_body_bytes_per_quota_key = {exchange_peak}\nmin_wire_body_concurrency = 5",
                5 * exchange_peak
            ),
            r#"
[authorization.providers.large]
kind = "process"
command = "/bin/large-provider"
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 16777216
max_decoded_request_body_bytes = 16777216
max_stdout_line_bytes = 65536
retire_timeout = "1s"

[redaction.profiles.small]
max_body_bytes = 1
max_decoded_body_bytes = 1
rules = [{ literals = ["x"] }]
"#,
            r#"
[[policy.rules]]
id = "combined"
decision = "delegate"
methods = ["POST"]
authorization_provider = "large"
redaction_profile = "small"
"#,
        );
        let compiled = compile(&input)
            .expect("the exact pool holds every stage reachable through the stricter profile");
        let resources = &compiled.reloadable_plan.resource_plan;

        assert_eq!(
            resources.runtime_replay_capacities_for_test(),
            [runtime_budget, 0]
        );
        assert_eq!(
            resources.max_reachable_http_body_combined_peak_bytes,
            combined_peak
        );
        assert_eq!(
            resources.max_reachable_http_exchange_peak_bytes,
            exchange_peak
        );
        assert_eq!(
            resources.combined_http_body_peaks_for_test(),
            [combined_peak, 0]
        );
        assert_eq!(resources.wire_body_full_peak_capacity, Capacity::Finite(5));
        assert_eq!(
            resources.wire_body_quota_key_full_peak_capacity,
            Capacity::Finite(1)
        );
    }

    #[test]
    fn runtime_enforced_local_minimum_excludes_merged_body_from_large_provider_rehome() {
        let output_headers = (0..MAX_TEST_PROVIDER_OUTPUTS_WITHIN_SHARED_RAW_BATCH)
            .map(|index| format!("\"x-output-{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let outputs = (0..MAX_TEST_PROVIDER_OUTPUTS_WITHIN_SHARED_RAW_BATCH)
            .map(|index| {
                format!(
                    r#"
[authorization.providers.current.outputs.value_{index}]
kind = "custom_header"
transport_security = "cleartext_allowed"
header = "x-output-{index}"
"#
                )
            })
            .collect::<String>();
        let definitions = format!(
            r#"
[credentials]
allowed_custom_headers = [{output_headers}]

[authorization.providers.current]
kind = "process"
command = "/bin/current-provider"
include_request_body = true
max_request_body_bytes = {MIB}
max_decoded_request_body_bytes = {}
max_stdout_line_bytes = {MAX_PROCESS_STDOUT_LINE_BYTES}
retire_timeout = "1s"
{outputs}

[authorization.providers.larger]
kind = "process"
command = "/bin/larger-provider"
include_request_body = true
max_request_body_bytes = {MIB}
max_decoded_request_body_bytes = {}
max_stdout_line_bytes = 80
retire_timeout = "1s"

[redaction.profiles.strict]
max_body_bytes = 33554432
max_decoded_body_bytes = 33554432
rules = [{{ literals = ["x"] }}]
"#,
            64 * MIB,
            64 * MIB,
        );
        let input = resource_config(
            r#"
[service.forwarding]
max_request_wire_bytes = 67108864
max_request_decoded_bytes = 67108864
"#,
            &definitions,
            r#"
[[policy.rules]]
id = "current"
decision = "delegate"
methods = ["POST"]
authorization_provider = "current"
redaction_profile = "strict"

[[policy.rules]]
id = "larger"
decision = "delegate"
methods = ["POST"]
authorization_provider = "larger"
"#,
        );
        let authored: super::super::authoring::AuthoringConfig = toml::from_str(&input).unwrap();
        let current = compile_http_rule_schedule(&authored, &authored.policy.rules[0]).unwrap();
        let merged_decode = decode_peak(MIB, 64 * MIB).unwrap();
        let merged_original = guarded(64 * MIB);
        assert_eq!(current.local_body_allocation, Some(guarded(32 * MIB)));
        assert!(
            merged_original + current.max_incoming_additional_bytes() > merged_decode,
            "without pre-stage local enforcement the merged body would exceed the compiled peak: original={merged_original}, incoming={}, decode={merged_decode}",
            current.max_incoming_additional_bytes(),
        );

        let compiled = compile(&input).unwrap();
        let replay = canonical_runtime_replay_storage_for(64 * MIB, 64 * 1024, 64 * MIB);
        assert_eq!(
            compiled
                .reloadable_plan
                .resource_plan
                .combined_http_body_peaks_for_test(),
            [merged_decode + replay, merged_decode + replay, 0]
        );
    }

    #[test]
    fn expanding_regex_passes_cover_two_profile_limit_buffers() {
        let input = resource_config(
            "",
            r#"
[authorization.providers.expanding]
kind = "process"
command = "/bin/expanding-provider"
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 1048576
max_decoded_request_body_bytes = 1048576
max_stdout_line_bytes = 1048576
retire_timeout = "1h"

[redaction.profiles.expanding]
replacement = "expanded-value"
max_body_bytes = 1048576
max_decoded_body_bytes = 8388608
rules = [{ expressions = ["a", "e"] }]
"#,
            r#"
[[policy.rules]]
id = "retain-provider-input"
decision = "delegate"
methods = ["POST"]
authorization_provider = "expanding"

[[policy.rules]]
id = "replace-and-redact"
decision = "delegate"
methods = ["POST"]
authorization_provider = "expanding"
redaction_profile = "expanding"
"#,
        );
        let compiled = compile(&input).unwrap();
        let merged_decode_peak = decode_peak(MIB, MIB).unwrap();
        let runtime_budget = canonical_runtime_replay_storage(MIB);

        assert_eq!(
            compiled
                .reloadable_plan
                .resource_plan
                .combined_http_body_peaks_for_test(),
            vec![
                merged_decode_peak + runtime_budget,
                merged_decode_peak + runtime_budget,
                0,
            ]
        );
        assert!(merged_decode_peak > 2 * guarded(8 * MIB));
    }

    #[test]
    fn upgrade_rules_publish_wire_only_working_sets_and_total_capacity() {
        let input = resource_config(
            "",
            r#"
[redaction.profiles.plain]
max_message_bytes = 1048576
allow_permessage_deflate = false
rules = [{ literals = ["plain-test-literal"] }]

[redaction.profiles.deflate]
max_message_bytes = 1048576
allow_permessage_deflate = true
unsupported_extensions = "strip"
rules = [{ literals = ["deflate-test-literal"] }]
"#,
            r#"
[[policy.rules]]
id = "unredacted-upgrade"
decision = "allow"
methods = ["GET"]
allow_upgrades = true

[[policy.rules]]
id = "plain-upgrade"
decision = "allow"
methods = ["POST"]
allow_upgrades = true
redaction_profile = "plain"

[[policy.rules]]
id = "deflate-upgrade"
decision = "allow"
methods = ["PUT"]
allow_upgrades = true
redaction_profile = "deflate"

[[policy.rules]]
id = "ordinary-http"
decision = "allow"
methods = ["DELETE"]
"#,
        );
        let compiled = compile(&input).unwrap();
        assert_eq!(
            compiled.reloadable_plan.redaction.profiles["plain"]
                .limits
                .unsupported_websocket_extensions(),
            UnsupportedWebSocketExtensions::Deny
        );
        assert_eq!(
            compiled.reloadable_plan.redaction.profiles["deflate"]
                .limits
                .unsupported_websocket_extensions(),
            UnsupportedWebSocketExtensions::Strip
        );
        let plan = &compiled.reloadable_plan.resource_plan;
        let transport = 2 * 64 * 1024;
        let plain_scratch = shared_matcher_scratch_bytes("plain-test-literal".len());
        let deflate_scratch = shared_matcher_scratch_bytes("deflate-test-literal".len());
        assert_eq!(
            plan.upgrade_wire_working_set_bytes_by_rule,
            vec![
                Some(0),
                Some(3 * MIB + plain_scratch),
                Some(4 * MIB + deflate_scratch + WEBSOCKET_DEFLATE_SCRATCH_BYTES),
                None,
            ]
        );
        assert_eq!(
            plan.max_upgrade_allocation_per_stream,
            transport + 4 * MIB + deflate_scratch + WEBSOCKET_DEFLATE_SCRATCH_BYTES
        );
        assert_eq!(
            plan.max_upgrade_allocation_all_streams,
            compiled.static_config.service.max_active_upgrades
                * (transport + 4 * MIB + deflate_scratch + WEBSOCKET_DEFLATE_SCRATCH_BYTES)
        );

        let no_upgrades = compile(&resource_config(
            "",
            "",
            r#"
[[policy.rules]]
id = "ordinary-http"
decision = "allow"
methods = ["GET"]
"#,
        ))
        .unwrap();
        let no_upgrades = &no_upgrades.reloadable_plan.resource_plan;
        assert_eq!(
            no_upgrades.upgrade_wire_working_set_bytes_by_rule,
            vec![None]
        );
        assert_eq!(no_upgrades.max_upgrade_allocation_per_stream, 0);
        assert_eq!(no_upgrades.max_upgrade_allocation_all_streams, 0);
    }

    #[test]
    fn upgrade_aggregate_rejects_a_two_mib_pool() {
        let input = resource_config(
            "max_active_upgrades = 1\nmax_upgrade_buffer_bytes = 2097152",
            r#"
[redaction.profiles.plain]
max_message_bytes = 1048576
allow_permessage_deflate = false
rules = [{ literals = ["plain-test-literal"] }]
"#,
            r#"
[[policy.rules]]
id = "upgrade"
decision = "allow"
methods = ["GET"]
allow_upgrades = true
redaction_profile = "plain"
"#,
        );
        let error = compile(&input).expect_err("the exact upgrade share must fit the pool");
        assert!(error.to_string().contains("max_upgrade_buffer_bytes"));
    }

    #[test]
    fn process_retirement_covers_every_effective_request_deadline() {
        let fixture = include_str!("../../tests/fixtures/production/host-proxy-tcp.toml");
        let too_short = fixture.replacen("retire_timeout = \"2h\"", "retire_timeout = \"1s\"", 1);
        let error = compile(&too_short).expect_err("retirement must cover the service timeout");
        assert!(error.to_string().contains("retire_timeout"));

        let long_rule = fixture.replacen(
            "decision = \"delegate\"",
            "decision = \"delegate\"\nrequest_timeout = \"3h\"",
            1,
        );
        let error = compile(&long_rule).expect_err("retirement must cover a rule override");
        assert!(error.to_string().contains("retire_timeout"));
    }

    #[test]
    fn unused_provider_outputs_are_still_strictly_validated() {
        let input = format!(
            r#"{MINIMAL}

[authorization.providers.unused]
kind = "webhook"
url = "https://approval.example.test/authorize"

[authorization.providers.unused.outputs.bad]
kind = "custom_header"
transport_security = "tls_required"
header = "x-not-allowed"
"#
        );
        let error = compile(&input).expect_err("unused provider outputs remain configured input");
        assert!(error.to_string().contains("allowed_custom_headers"));
    }

    fn transport_security_config(definitions: &str, policy: &str) -> String {
        MINIMAL
            .replace("[policy]", &format!("{definitions}\n[policy]"))
            .replace("[policy]\ndefault = \"deny\"", policy)
    }

    const TOKEN_SOURCE: &str = r#"[credentials.sources.token]
source = "environment"
variable = "TEST_TOKEN"
"#;

    fn bearer_action(scope: &str, transport_security: &str) -> String {
        format!(
            r#"[[{scope}.credential_actions]]
kind = "bearer"
transport_security = "{transport_security}"
credential = "token"
"#
        )
    }

    #[test]
    fn cleartext_transport_security_covers_global_local_provider_and_default_allow() {
        let http_allow = r#"[policy]
default = "deny"

[[policy.rules]]
id = "http"
decision = "allow"
urls = ["http://example.test/**"]
"#;
        for scope in ["egress", "policy.rules"] {
            let definitions = if scope == "egress" {
                format!("{TOKEN_SOURCE}\n{}", bearer_action(scope, "tls_required"))
            } else {
                TOKEN_SOURCE.to_string()
            };
            let policy = if scope == "egress" {
                http_allow.to_string()
            } else {
                format!("{http_allow}\n{}", bearer_action(scope, "tls_required"))
            };
            let error = compile(&transport_security_config(&definitions, &policy))
                .expect_err("an HTTP-reachable TLS-only action must fail");
            assert!(error.to_string().contains("cleartext_allowed"), "{error}");

            let clear = transport_security_config(&definitions, &policy).replace(
                "transport_security = \"tls_required\"",
                "transport_security = \"cleartext_allowed\"",
            );
            compile(&clear).expect("the explicit cleartext opt-in must compile");
        }

        let provider = r#"[authorization.providers.auth]
kind = "process"
command = "/bin/authorize"

[authorization.providers.auth.outputs.token]
kind = "bearer"
transport_security = "tls_required"
"#;
        let delegate = r#"[policy]
default = "deny"

[[policy.rules]]
id = "http-provider"
decision = "delegate"
urls = ["http://example.test/**"]
authorization_provider = "auth"
"#;
        let input = transport_security_config(provider, delegate);
        let error = compile(&input).expect_err("selected TLS-only output must fail on HTTP");
        assert!(error.to_string().contains("cleartext_allowed"), "{error}");
        compile(&input.replace("tls_required", "cleartext_allowed"))
            .expect("selected cleartext provider output must compile");

        let definitions = format!(
            "{TOKEN_SOURCE}\n{}",
            bearer_action("egress", "tls_required")
        );
        let default_allow = "[policy]\ndefault = \"allow\"";
        let error = compile(&transport_security_config(&definitions, default_allow))
            .expect_err("default allow can reach HTTP");
        assert!(error.to_string().contains("cleartext_allowed"), "{error}");
        compile(&transport_security_config(
            &definitions.replace("tls_required", "cleartext_allowed"),
            default_allow,
        ))
        .expect("default allow accepts an explicit global cleartext opt-in");
    }

    #[test]
    fn cleartext_transport_security_covers_mixed_unconstrained_and_match_all_rules() {
        let definitions = format!(
            r#"[credentials]
allowed_custom_headers = ["x-local-token"]

{TOKEN_SOURCE}
[credentials.sources.local]
source = "environment"
variable = "LOCAL_TOKEN"

{}
"#,
            bearer_action("egress", "cleartext_allowed")
        );
        let local_tls = r#"[[policy.rules.credential_actions]]
kind = "custom_header"
transport_security = "tls_required"
header = "x-local-token"
credential = "local"
"#;
        for predicate in ["methods = [\"GET\"]", "urls = [\"**\"]"] {
            let policy = format!(
                r#"[policy]
default = "deny"

[[policy.rules]]
id = "http-reachable"
decision = "allow"
{predicate}

{local_tls}"#
            );
            let error = compile(&transport_security_config(&definitions, &policy))
                .expect_err("URL-less and match-all rules can reach HTTP");
            assert!(error.to_string().contains("cleartext_allowed"), "{error}");
        }
    }

    #[test]
    fn tls_required_credentials_accept_https_even_through_an_http_parent() {
        let definitions = format!(
            r#"{TOKEN_SOURCE}
[egress]
route = "parent_proxy"

[egress.parent_proxy]
kind = "acl_proxy"
url = "http://192.0.2.10:8080"

{}"#,
            bearer_action("egress", "tls_required")
        );
        let policy = r#"[policy]
default = "deny"

[[policy.rules]]
id = "https"
decision = "allow"
urls = ["https://example.test/**"]
"#;
        compile(&transport_security_config(&definitions, policy))
            .expect("HTTPS origin credentials remain TLS-protected through an HTTP parent");
    }

    #[test]
    fn deny_rules_and_unselected_provider_outputs_do_not_inject_credentials() {
        let provider = r#"[authorization.providers.unused]
kind = "process"
command = "/bin/authorize"

[authorization.providers.unused.outputs.token]
kind = "bearer"
transport_security = "tls_required"
"#;
        let policy = r#"[policy]
default = "deny"

[[policy.rules]]
id = "deny-http"
decision = "deny"
urls = ["http://blocked.example.test/**"]

[[policy.rules]]
id = "allow-http"
decision = "allow"
urls = ["http://example.test/**"]
"#;
        compile(&transport_security_config(provider, policy))
            .expect("an unused provider output must not become an effective credential");
    }

    #[test]
    fn provider_output_name_bound_matches_the_process_parser() {
        fn provider_with_output(name: &str) -> String {
            format!(
                r#"{MINIMAL}

[authorization.providers.auth]
kind = "process"
command = "/bin/authorize"

[authorization.providers.auth.outputs.{name}]
kind = "bearer"
transport_security = "tls_required"
"#
            )
        }

        let exact = "a".repeat(MAX_PROVIDER_OUTPUT_NAME_BYTES);
        compile(&provider_with_output(&exact)).expect("the documented name bound must compile");

        let over = "a".repeat(MAX_PROVIDER_OUTPUT_NAME_BYTES + 1);
        let error = compile(&provider_with_output(&over))
            .expect_err("the parser cannot admit output names beyond its fixed bound");
        assert!(error
            .to_string()
            .contains(&format!("at most {MAX_PROVIDER_OUTPUT_NAME_BYTES} bytes")));
    }

    #[test]
    fn credential_destination_collision_matrix() {
        let source = r#"
[credentials.sources.token]
source = "environment"
variable = "TEST_TOKEN"

[credentials.sources.password]
source = "environment"
variable = "TEST_PASSWORD"
"#;
        let provider = r#"
[authorization.providers.auth]
kind = "process"
command = "/bin/authorize"

[authorization.providers.auth.outputs.bearer]
kind = "bearer"
transport_security = "tls_required"
"#;
        let cases = [
            (
                "stable/stable",
                source.to_string(),
                r#"
[[policy.rules]]
id = "stable-stable"
decision = "allow"
methods = ["GET"]

[[policy.rules.credential_actions]]
kind = "bearer"
transport_security = "tls_required"
credential = "token"

[[policy.rules.credential_actions]]
kind = "basic"
transport_security = "tls_required"
username = "agent"
password_credential = "password"
"#
                .to_string(),
            ),
            (
                "stable/provider",
                format!("{source}{provider}"),
                r#"
[[policy.rules]]
id = "stable-provider"
decision = "delegate"
methods = ["GET"]
authorization_provider = "auth"

[[policy.rules.credential_actions]]
kind = "bearer"
transport_security = "tls_required"
credential = "token"
"#
                .to_string(),
            ),
            (
                "provider/provider",
                format!(
                    r#"{source}
[authorization.providers.auth]
kind = "process"
command = "/bin/authorize"

[authorization.providers.auth.outputs.first]
kind = "bearer"
transport_security = "tls_required"

[authorization.providers.auth.outputs.second]
kind = "basic"
transport_security = "tls_required"
username = "agent"
"#
                ),
                String::new(),
            ),
            (
                "egress/rule",
                format!(
                    r#"{source}
[egress]

[[egress.credential_actions]]
kind = "bearer"
transport_security = "tls_required"
credential = "token"
"#
                ),
                r#"
[[policy.rules]]
id = "egress-rule"
decision = "allow"
methods = ["GET"]

[[policy.rules.credential_actions]]
kind = "basic"
transport_security = "tls_required"
username = "agent"
password_credential = "password"
"#
                .to_string(),
            ),
            (
                "egress/provider",
                format!(
                    r#"{source}{provider}
[egress]

[[egress.credential_actions]]
kind = "bearer"
transport_security = "tls_required"
credential = "token"
"#
                ),
                r#"
[[policy.rules]]
id = "egress-provider"
decision = "delegate"
methods = ["GET"]
authorization_provider = "auth"
"#
                .to_string(),
            ),
            (
                "custom-header",
                format!(
                    r#"[credentials]
allowed_custom_headers = ["x-api-key"]

{source}
"#
                ),
                r#"
[[policy.rules]]
id = "custom-header"
decision = "allow"
methods = ["GET"]

[[policy.rules.credential_actions]]
kind = "custom_header"
transport_security = "tls_required"
header = "X-Api-Key"
credential = "token"

[[policy.rules.credential_actions]]
kind = "custom_header"
transport_security = "tls_required"
header = "x-api-key"
credential = "password"
"#
                .to_string(),
            ),
        ];

        for (name, definitions, rules) in cases {
            let input = resource_config("", &definitions, &rules);
            let error = match compile(&input) {
                Ok(_) => panic!("{name} collision must be rejected"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("credential destination"),
                "{name}: {error}"
            );
        }
    }

    #[test]
    fn providers_cannot_include_custom_credential_destinations() {
        for (kind, provider) in [
            (
                "webhook",
                r#"kind = "webhook"
url = "https://approval.example.test/authorize""#,
            ),
            (
                "process",
                r#"kind = "process"
command = "/bin/authorize""#,
            ),
        ] {
            let definitions = format!(
                r#"
[credentials]
allowed_custom_headers = ["x-api-key"]

[credentials.sources.token]
source = "environment"
variable = "TEST_TOKEN"

[authorization.providers.auth]
{provider}
include_headers = ["X-Api-Key"]
"#
            );
            let rules = r#"
[[policy.rules]]
id = "credential-destination"
decision = "allow"
methods = ["GET"]

[[policy.rules.credential_actions]]
kind = "custom_header"
transport_security = "tls_required"
header = "x-api-key"
credential = "token"
"#;
            let error = match compile(&resource_config("", &definitions, rules)) {
                Ok(_) => panic!("{kind} provider must not receive a credential"),
                Err(error) => error,
            };
            assert!(
                error
                    .to_string()
                    .contains("outbound credential destination"),
                "{kind}: {error}"
            );
        }
    }

    #[test]
    fn literal_header_effect_strings_respect_per_field_limit() {
        let oversized = "x".repeat(MAX_HEADER_FIELD_BYTES + 1);
        let cases = [
            format!(
                r#"[[egress.request_headers]]
operation = "set"
when = "always"
name = "x-limit"
value = {oversized:?}
"#
            ),
            format!(
                r#"[[egress.request_headers]]
operation = "append"
when = "always"
name = "x-limit"
values = [{oversized:?}]
"#
            ),
            format!(
                r#"[[egress.request_headers]]
operation = "replace"
when = "always"
name = "x-limit"
search = {oversized:?}
replace = "x"
"#
            ),
            format!(
                r#"[[egress.request_headers]]
operation = "replace"
when = "always"
name = "x-limit"
search = "x"
replace = {oversized:?}
"#
            ),
        ];

        for effect in cases {
            let error = compile(&format!("{MINIMAL}\n{effect}"))
                .expect_err("oversized static header text must fail");
            assert!(error.to_string().contains("64 KiB"), "{error}");
        }

        let boundary = "x".repeat(MAX_HEADER_FIELD_BYTES);
        compile(&format!(
            r#"{MINIMAL}
[[egress.request_headers]]
operation = "set"
when = "always"
name = "x-limit"
value = {boundary:?}
"#
        ))
        .expect("the exact per-field boundary is valid");
    }

    #[test]
    fn mapped_ipv6_cidr_compiles_to_ipv4_and_allows_both_peer_forms() {
        let input = format!(
            r#"{MINIMAL}
[[policy.rules]]
id = "mapped-allow"
decision = "allow"
client_cidrs = ["::ffff:192.0.2.0/120"]
"#
        );
        let compiled = compile(&input).expect("mapped CIDR should compile");
        assert_eq!(
            compiled.reloadable_plan.policy.rules[0].client_cidrs,
            vec!["192.0.2.0/24".parse::<ipnet::IpNet>().unwrap()]
        );
        let snapshot = crate::policy::ProductAclSnapshot::compile(
            &compiled.reloadable_plan.policy,
            http_access_types::PolicyGeneration::new(1).unwrap(),
            http_access_types::SnapshotIdentity::new(),
            &[],
        )
        .unwrap();
        let url = canonicalize_http_url("https://example.com/").unwrap();
        for peer in ["192.0.2.44", "::ffff:192.0.2.44"] {
            let decision = evaluate_test_policy(&snapshot, &url, peer.parse().unwrap());
            assert!(matches!(
                decision,
                http_access_policy_acl::PolicyEvaluation::Allow { .. }
            ));
        }
        let outside = evaluate_test_policy(&snapshot, &url, "198.51.100.44".parse().unwrap());
        assert!(matches!(
            outside,
            http_access_policy_acl::PolicyEvaluation::Deny { .. }
        ));
    }

    #[test]
    fn mapped_ipv6_cidr_denies_both_peer_forms_before_allow_default() {
        let input = MINIMAL.replace("default = \"deny\"", "default = \"allow\"");
        let input = format!(
            r#"{input}
[[policy.rules]]
id = "mapped-deny"
decision = "deny"
client_cidrs = ["::ffff:192.0.2.0/120"]
"#
        );
        let compiled = compile(&input).expect("mapped CIDR should compile");
        let snapshot = crate::policy::ProductAclSnapshot::compile(
            &compiled.reloadable_plan.policy,
            http_access_types::PolicyGeneration::new(1).unwrap(),
            http_access_types::SnapshotIdentity::new(),
            &[],
        )
        .unwrap();
        let url = canonicalize_http_url("https://example.com/").unwrap();
        for peer in ["192.0.2.44", "::ffff:192.0.2.44"] {
            let decision = evaluate_test_policy(&snapshot, &url, peer.parse().unwrap());
            let http_access_policy_acl::PolicyEvaluation::Deny { provenance } = decision else {
                panic!("mapped peer should be denied")
            };
            let http_access_types::EffectivePolicy::Rule { id, .. } = provenance.effective_policy()
            else {
                panic!("mapped peer should match the deny rule")
            };
            assert_eq!(id.as_str(), "mapped-deny");
        }
        let outside = evaluate_test_policy(&snapshot, &url, "198.51.100.44".parse().unwrap());
        let http_access_policy_acl::PolicyEvaluation::Allow { provenance, .. } = outside else {
            panic!("outside peer should be allowed by the default")
        };
        assert!(matches!(
            provenance.effective_policy(),
            http_access_types::EffectivePolicy::Default
        ));
    }

    #[test]
    fn ipv6_cidr_spanning_mapped_and_native_space_is_rejected() {
        for cidr in ["::/0", "::fffe:0:0/95"] {
            let input = format!(
                r#"{MINIMAL}
[[policy.rules]]
id = "mixed"
decision = "allow"
client_cidrs = [{cidr:?}]
"#
            );
            let error = compile(&input).expect_err("mixed mapped/native CIDR must fail");
            assert!(error.to_string().contains("ambiguously mixes"), "{error}");
        }
    }

    #[test]
    fn control_paths_reject_encoded_or_platform_specific_ambiguity() {
        for base_path in ["/_acl/%2e%2e/admin", "/_acl\\admin"] {
            let input = MINIMAL.replace(
                "[policy]",
                &format!(
                    "[control]\nbind = \"127.0.0.1:8898\"\nbase_path = {base_path:?}\n\n[policy]"
                ),
            );
            let error = compile(&input).expect_err("ambiguous control paths must fail");
            assert!(error.to_string().contains("control.base_path"));
        }
    }
}
