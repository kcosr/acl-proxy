use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use http::Method;
use regex_automata::{
    dfa::{dense, regex::Regex as DfaRegex, StartKind},
    nfa::thompson::{self, WhichCaptures, NFA},
    MatchKind as RegexMatchKind,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use url::{Host, Url};

use crate::safety::wire_body::guarded_body_allocation_bytes;
use crate::url::{canonicalize_http_url, CompiledUrlPattern};

use super::authoring::{
    AuthorizationConfig, AuthorizationProviderConfig, CredentialActionConfig,
    CredentialSourceConfig, CredentialsConfig, EgressConfig, EgressRoute, HeaderEffectConfig,
    HeaderEffectWhen, Http1ConnectPolicy, HttpVersion, ListenersConfig, MitmConfig,
    ObservationConfig, ParentProxyKind, PolicyConfig, PolicyRuleConfig, RedactionConfig,
    RedactionPayloads, RuleDecision, SafetyConfig, StaticTlsIdentityConfig, TlsTrust,
    TransportTlsConfig,
};

const MIB: usize = 1024 * 1024;
const GIB: usize = 1024 * MIB;
const MAX_CONFIG_BYTES: usize = 10 * MIB;
const MAX_CONTROL_CONNECTIONS: usize = 65_536;
const MAX_CONTROL_BODY_BYTES: usize = MIB;
const MAX_PENDING_CALLBACKS: usize = 65_536;
const MAX_RETIRING_GENERATIONS: usize = 8;
const MAX_ACTIVE_UPGRADES: usize = 65_536;
const MAX_UPGRADE_RELAY_BUFFER_BYTES: usize = 16 * MIB;
const MAX_UPGRADE_BUFFER_BYTES: usize = 4 * GIB;
const MAX_WIRE_BODY_BYTES: usize = 64 * GIB;
const MAX_WIRE_BODY_BYTES_PER_QUOTA_KEY: usize = 16 * GIB;
const MAX_MIN_WIRE_BODY_CONCURRENCY: usize = 4_096;
const MAX_CONTENT_DECODING_RATIO: usize = 128;
const MAX_LISTENER_CONNECTIONS: usize = 1_048_576;
const MAX_LISTENER_STREAMS: u32 = 65_535;
const MAX_MITM_CERTIFICATES: usize = 1_000_000;
const MAX_PROVIDERS: usize = 256;
const MAX_PROCESS_PROVIDERS: usize = 64;
const MAX_PROCESS_BODY_BYTES: usize = GIB;
const MAX_PROCESS_STDOUT_LINE_BYTES: usize = 16 * MIB;
const MAX_PROCESS_PENDING_REQUESTS: usize = 4_096;
const MAX_POLICY_RULES: usize = 100_000;
const MAX_URLS_PER_RULE: usize = 1_024;
const MAX_EFFECTS_PER_SCOPE: usize = 1_024;
const MAX_HEADER_PREDICATES_PER_RULE: usize = 4_096;
const MAX_HEADER_FIELD_BYTES: usize = 64 * 1024;
const MAX_PROVIDER_ITEMS: usize = 256;
const MAX_REDACTION_PROFILES: usize = 256;
const MAX_REDACTION_RULES: usize = 1_024;
const MAX_REDACTION_EXPRESSIONS: usize = 1_024;
const MAX_REDACTION_EXPRESSION_BYTES_PER_PROFILE: usize = MAX_CONFIG_BYTES;
const MAX_REDACTION_BODY_BYTES: usize = GIB;
const MAX_REDACTION_FRAME_BYTES: usize = 16 * MIB;
const MAX_REDACTION_MESSAGE_BYTES: usize = 256 * MIB;
const MAX_REDACTION_ENV_SOURCES_PER_PROFILE: usize = 1_024;
const MAX_REDACTION_ENV_BYTES: usize = MIB;
const MAX_REDACTION_ENV_TOTAL_BYTES_PER_PROFILE: usize = 16 * MIB;
const MAX_REDACTION_ENV_SOURCES_PER_SNAPSHOT: usize = 4_096;
const MAX_REDACTION_ENV_BYTES_PER_SNAPSHOT: usize = 64 * MIB;
pub(crate) const MAX_REDACTION_REGEX_DFA_BYTES: usize = MIB;
pub(crate) const MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_PROFILE: usize = 16 * MIB;
pub(crate) const MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_SNAPSHOT: usize = 64 * MIB;
const MAX_TOML_REDACTION_LITERALS_PER_PROFILE: usize = 4_096;
const MAX_TOML_REDACTION_LITERAL_BYTES_PER_PROFILE: usize = 16 * MIB;
const MAX_LOG_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_LOG_FILES: usize = 1_000_000;
const MAX_CAPTURE_BODY_BYTES: usize = GIB;
const MAX_CAPTURE_INFLIGHT_BYTES: usize = 4 * GIB;
const MAX_CAPTURE_FILES: usize = 10_000_000;
const MAX_CAPTURE_TOTAL_BYTES: u64 = 64 * 1024 * 1024 * 1024 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
pub(crate) const MAX_REDACTION_MATCHER_SCRATCH_BYTES: usize = MIB;
const DECODER_SCRATCH_BYTES: usize = 64 * 1024;
const PROVIDER_STREAM_SCRATCH_BYTES: usize = 64 * 1024;

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
    pub(crate) callback_public_url: Option<String>,
    pub(crate) logging: StaticLoggingConfig,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StaticServiceConfig {
    pub(crate) shutdown_drain_timeout: Option<Duration>,
    pub(crate) max_retiring_generations: usize,
    pub(crate) max_active_upgrades: usize,
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
    pub(crate) max_connections: usize,
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

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StaticCleartextListener {
    pub(crate) bind: SocketAddr,
    pub(crate) http_versions: Vec<CompiledHttpVersion>,
    pub(crate) connect: Option<StaticConnectPolicy>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StaticExplicitHttpsListener {
    pub(crate) bind: SocketAddr,
    pub(crate) http_versions: Vec<CompiledHttpVersion>,
    pub(crate) handshake_timeout: Duration,
    pub(crate) request_header_timeout: Duration,
    pub(crate) max_connections: usize,
    pub(crate) max_concurrent_streams: u32,
    pub(crate) connect: StaticConnectPolicy,
    pub(crate) tls: CompiledTlsIdentity,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StaticTransparentHttpsListener {
    pub(crate) bind: SocketAddr,
    pub(crate) http_versions: Vec<CompiledHttpVersion>,
    pub(crate) handshake_timeout: Duration,
    pub(crate) request_header_timeout: Duration,
    pub(crate) max_connections: usize,
    pub(crate) max_concurrent_streams: u32,
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

/// Purely compiled, unresolved generation input. Runtime activation must turn
/// this into a snapshot by resolving redaction sources and eagerly starting
/// process providers. Activation consumes logical names and redaction source
/// locators. Credential environment/file locators survive only inside the
/// opaque late resolver that owns uncached final-injection reads; request paths
/// never consume this plan directly.
pub(crate) struct ReloadableProductPlan {
    pub(crate) request_timeout: Duration,
    pub(crate) max_content_decoding_expansion_ratio: usize,
    pub(crate) egress: EgressPlan,
    pub(crate) policy: PolicyPlan,
    pub(crate) authorization: AuthorizationPlan,
    pub(crate) credentials: CredentialsPlan,
    pub(crate) redaction: RedactionPlan,
    pub(crate) observation: ObservationPlan,
    pub(crate) safety: SafetyPlan,
    pub(crate) resource_plan: CompiledResourcePlan,
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
    pub(crate) url: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) tls: Option<ParentProxyTlsPlan>,
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
    pub(crate) headers: HeaderPredicatesPlan,
    pub(crate) request_timeout: Option<Duration>,
    pub(crate) allow_upgrades: bool,
    pub(crate) authorization_provider: Option<String>,
    pub(crate) redaction_profile: Option<String>,
    pub(crate) request_headers: Vec<HeaderEffectPlan>,
    pub(crate) response_headers: Vec<HeaderEffectPlan>,
    pub(crate) credential_actions: Vec<CredentialActionPlan>,
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
    },
    Basic {
        username: String,
        password_credential: String,
    },
    CustomHeader {
        header: HeaderName,
        credential: String,
    },
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
    pub(crate) max_pending_operations: usize,
}

#[derive(Clone)]
pub(crate) enum AuthorizationProviderPlan {
    Webhook(WebhookProviderPlan),
    Process(ProcessProviderPlan),
}

#[derive(Clone)]
pub(crate) struct WebhookProviderPlan {
    pub(crate) url: String,
    pub(crate) timeout: Duration,
    pub(crate) on_failure: CompiledProviderFailureMode,
    pub(crate) include_headers: Vec<HeaderName>,
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
    pub(crate) include_headers: Vec<HeaderName>,
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledProviderFailureMode {
    Deny,
    Error,
}

#[derive(Clone)]
pub(crate) enum ProviderOutputPlan {
    Bearer { required: bool },
    Basic { username: String, required: bool },
    CustomHeader { header: HeaderName, required: bool },
}

#[derive(Clone)]
pub(crate) struct CredentialsPlan {
    pub(crate) allowed_custom_headers: Vec<HeaderName>,
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

#[derive(Clone)]
pub(crate) struct RedactionPlan {
    pub(crate) profiles: BTreeMap<String, RedactionProfilePlan>,
}

#[derive(Clone)]
pub(crate) struct RedactionProfilePlan {
    pub(crate) replacement: Vec<u8>,
    pub(crate) max_body_bytes: usize,
    pub(crate) max_decoded_body_bytes: usize,
    pub(crate) max_frame_bytes: usize,
    pub(crate) max_message_bytes: usize,
    pub(crate) allow_permessage_deflate: bool,
    pub(crate) max_environment_literal_sources: usize,
    pub(crate) max_environment_literal_bytes: usize,
    pub(crate) max_environment_literal_total_bytes: usize,
    pub(crate) rules: Vec<RedactionRulePlan>,
}

#[derive(Clone)]
pub(crate) struct RedactionRulePlan {
    pub(crate) literals: Vec<Vec<u8>>,
    pub(crate) literal_environment_variables: Vec<String>,
    pub(crate) expressions: Vec<String>,
    pub(crate) payloads: CompiledRedactionPayloads,
}

pub(crate) fn build_redaction_regex(
    expression: &str,
    remaining_matcher_budget: usize,
) -> Result<DfaRegex, ()> {
    // This ceiling covers the compiler's accounted NFA, DFA, and determinizer
    // state. Parser/finalization auxiliaries, Vec capacity, and allocator
    // metadata are outside regex-automata's public size accounting.
    let forward_limit = MAX_REDACTION_REGEX_DFA_BYTES.min(remaining_matcher_budget / 3);
    if forward_limit == 0 {
        return Err(());
    }
    let forward_nfa = build_redaction_nfa(expression, false, forward_limit)?;
    let forward = build_redaction_dfa(&forward_nfa, false, forward_limit)?;
    drop(forward_nfa);

    let forward_bytes = forward.memory_usage();
    let reverse_budget = remaining_matcher_budget
        .checked_sub(forward_bytes)
        .ok_or(())?;
    let reverse_limit = MAX_REDACTION_REGEX_DFA_BYTES.min(reverse_budget / 3);
    if reverse_limit == 0 {
        return Err(());
    }
    let reverse_nfa = build_redaction_nfa(expression, true, reverse_limit)?;
    let reverse = build_redaction_dfa(&reverse_nfa, true, reverse_limit)?;
    drop(reverse_nfa);

    let resident_bytes = forward_bytes
        .checked_add(reverse.memory_usage())
        .ok_or(())?;
    if resident_bytes > remaining_matcher_budget {
        return Err(());
    }
    Ok(DfaRegex::builder().build_from_dfas(forward, reverse))
}

fn build_redaction_nfa(expression: &str, reverse: bool, limit: usize) -> Result<NFA, ()> {
    let mut compiler = NFA::compiler();
    compiler.configure(
        thompson::Config::new()
            .utf8(true)
            .reverse(reverse)
            .shrink(false)
            .which_captures(WhichCaptures::None)
            .nfa_size_limit(Some(limit)),
    );
    compiler.build(expression).map_err(|_| ())
}

fn build_redaction_dfa(nfa: &NFA, reverse: bool, limit: usize) -> Result<dense::DFA<Vec<u32>>, ()> {
    let config = dense::Config::new()
        .accelerate(false)
        .minimize(false)
        .prefilter(None)
        .dfa_size_limit(Some(limit))
        .determinize_size_limit(Some(limit));
    let config = if reverse {
        config
            .specialize_start_states(false)
            .start_kind(StartKind::Anchored)
            .match_kind(RegexMatchKind::All)
    } else {
        config
            .specialize_start_states(true)
            .start_kind(StartKind::Both)
            .match_kind(RegexMatchKind::LeftmostFirst)
    };
    dense::Builder::new()
        .configure(config)
        .build_from_nfa(nfa)
        .map_err(|_| ())
}

pub(crate) fn redaction_regex_resident_bytes(expression: &DfaRegex) -> Option<usize> {
    expression
        .forward()
        .memory_usage()
        .checked_add(expression.reverse().memory_usage())
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RedactionLiteralEdge {
    pub(crate) source: usize,
    pub(crate) byte: u8,
    pub(crate) target: usize,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RedactionLiteralNode {
    pub(crate) edge_start: usize,
    pub(crate) edge_len: usize,
    pub(crate) failure: usize,
    pub(crate) output_len: usize,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct RedactionLiteralInterval {
    pub(crate) start: usize,
    pub(crate) end: usize,
}

pub(crate) struct RedactionLiteralProjection {
    pub(crate) state_count: usize,
    pub(crate) edge_count: usize,
    pub(crate) max_pattern_len: usize,
    pub(crate) resident_bytes: usize,
    pub(crate) reference_build_bytes: usize,
    pub(crate) trie_build_bytes: usize,
    pub(crate) failure_build_bytes: usize,
    pub(crate) build_bytes: usize,
}

pub(crate) fn redaction_literal_reference_bytes(
    staging_capacity: usize,
    final_len: usize,
) -> Option<(usize, usize)> {
    let element_bytes = std::mem::size_of::<&[u8]>();
    let staging_bytes = staging_capacity.checked_mul(element_bytes)?;
    let final_bytes = final_len.checked_mul(element_bytes)?;
    let construction_bytes = staging_bytes.checked_add(final_bytes)?;
    Some((final_bytes, construction_bytes))
}

pub(crate) fn redaction_literal_projection(
    patterns: &mut [&[u8]],
    pattern_reference_bytes: usize,
    pattern_reference_construction_bytes: usize,
) -> Option<RedactionLiteralProjection> {
    if patterns.is_empty() {
        if pattern_reference_bytes != 0 || pattern_reference_construction_bytes != 0 {
            return None;
        }
        return Some(RedactionLiteralProjection {
            state_count: 0,
            edge_count: 0,
            max_pattern_len: 0,
            resident_bytes: 0,
            reference_build_bytes: 0,
            trie_build_bytes: 0,
            failure_build_bytes: 0,
            build_bytes: 0,
        });
    }
    let minimum_reference_bytes = patterns.len().checked_mul(std::mem::size_of::<&[u8]>())?;
    if pattern_reference_bytes != minimum_reference_bytes
        || pattern_reference_construction_bytes < pattern_reference_bytes
    {
        return None;
    }
    patterns.sort_unstable();

    let mut state_count = 1usize;
    let mut max_pattern_len = 0usize;
    for index in 0..patterns.len() {
        let pattern = patterns[index];
        let previous = index
            .checked_sub(1)
            .map(|previous| patterns[previous])
            .unwrap_or(&[]);
        if index != 0 && pattern == previous {
            continue;
        }
        let shared = pattern_common_prefix_len(previous, pattern);
        state_count = state_count.checked_add(pattern.len() - shared)?;
        max_pattern_len = max_pattern_len.max(pattern.len());
    }
    let edge_count = state_count.checked_sub(1)?;
    let resident_bytes = state_count
        .checked_mul(std::mem::size_of::<RedactionLiteralNode>())?
        .checked_add(edge_count.checked_mul(std::mem::size_of::<RedactionLiteralEdge>())?)?;
    let terminal_and_path_bytes = state_count
        .checked_mul(std::mem::size_of::<usize>())?
        .checked_add(
            max_pattern_len
                .checked_add(1)?
                .checked_mul(std::mem::size_of::<usize>())?,
        )?;
    let shared_build_bytes = resident_bytes.checked_add(terminal_and_path_bytes)?;
    // Reference-array conversion, trie construction, and failure-link BFS are
    // distinct peaks. The reference box is wiped before the BFS queue exists.
    let trie_build_bytes = shared_build_bytes.checked_add(pattern_reference_bytes)?;
    let failure_build_bytes =
        shared_build_bytes.checked_add(state_count.checked_mul(std::mem::size_of::<usize>())?)?;
    Some(RedactionLiteralProjection {
        state_count,
        edge_count,
        max_pattern_len,
        resident_bytes,
        reference_build_bytes: pattern_reference_construction_bytes,
        trie_build_bytes,
        failure_build_bytes,
        build_bytes: pattern_reference_construction_bytes
            .max(trie_build_bytes)
            .max(failure_build_bytes),
    })
}

pub(crate) fn redaction_literal_scratch_bytes(max_pattern_len: usize) -> Option<usize> {
    max_pattern_len
        .checked_mul(std::mem::size_of::<RedactionLiteralInterval>())
        .filter(|bytes| *bytes <= MAX_REDACTION_MATCHER_SCRATCH_BYTES)
}

fn pattern_common_prefix_len(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right)
        .take_while(|(left, right)| left == right)
        .count()
}

pub(crate) fn checked_redaction_matcher_resident_bytes(
    profile_bytes: usize,
    snapshot_bytes: usize,
    additional_bytes: usize,
) -> Option<(usize, usize)> {
    let profile_bytes = profile_bytes.checked_add(additional_bytes)?;
    let snapshot_bytes = snapshot_bytes.checked_add(additional_bytes)?;
    (profile_bytes <= MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_PROFILE
        && snapshot_bytes <= MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_SNAPSHOT)
        .then_some((profile_bytes, snapshot_bytes))
}

pub(crate) fn remaining_redaction_matcher_resident_bytes(
    profile_bytes: usize,
    snapshot_bytes: usize,
) -> Option<usize> {
    let profile_remaining =
        MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_PROFILE.checked_sub(profile_bytes)?;
    let snapshot_remaining =
        MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_SNAPSHOT.checked_sub(snapshot_bytes)?;
    Some(profile_remaining.min(snapshot_remaining))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledRedactionPayloads {
    Text,
    Binary,
    Both,
}

#[derive(Clone)]
pub(crate) struct ObservationPlan {
    pub(crate) logging: ReloadableLoggingPlan,
    pub(crate) capture: Option<CapturePlan>,
}

#[derive(Clone)]
pub(crate) struct ReloadableLoggingPlan {
    pub(crate) level: CompiledLogLevel,
    pub(crate) policy_decisions: PolicyDecisionLoggingPlan,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledLogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone)]
pub(crate) struct PolicyDecisionLoggingPlan {
    pub(crate) allows: bool,
    pub(crate) denies: bool,
    pub(crate) allow_level: CompiledLogLevel,
    pub(crate) deny_level: CompiledLogLevel,
}

#[derive(Clone)]
pub(crate) struct CapturePlan {
    pub(crate) events: Vec<CompiledCaptureEvent>,
    pub(crate) redaction_profile: String,
    pub(crate) directory: PathBuf,
    pub(crate) filename: String,
    pub(crate) max_body_bytes: usize,
    pub(crate) max_inflight_body_bytes: usize,
    pub(crate) max_files: usize,
    pub(crate) max_total_bytes: u64,
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
    pub(crate) http_wire_body_peak_bytes_by_cursor: Vec<usize>,
    pub(crate) max_reachable_http_wire_body_peak_bytes: usize,
    pub(crate) wire_body_full_peak_capacity: Capacity,
    pub(crate) wire_body_quota_key_full_peak_capacity: Capacity,
    pub(crate) upgrade_allocation_bytes_by_rule: Vec<Option<usize>>,
    pub(crate) max_upgrade_allocation_per_stream: usize,
    pub(crate) max_upgrade_allocation_all_streams: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Capacity {
    Unbounded,
    Finite(usize),
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct StaticFingerprint([u8; 32]);

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
#[error("invalid v3 configuration at {path}: {message}")]
pub(super) struct V3CompileError {
    path: String,
    message: String,
}

impl V3CompileError {
    fn at(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

pub(super) fn compile_v3(
    mut config: super::authoring::ConfigV3,
    config_root: &Path,
) -> Result<CompiledProductConfig, V3CompileError> {
    let config_root = normalize_config_root(config_root)?;
    normalize_authored_paths(&mut config, &config_root)?;
    normalize_endpoint_urls(&mut config)?;

    validate_positive_limits(&config)?;
    let listener_facts = validate_listener_control_mitm_matrix(&config)?;
    validate_tls_and_parent_matrix(&config, &listener_facts)?;
    let validation = validate_references_and_security_boundaries(&config)?;
    let resource_plan = compile_resource_plan(&config)?;

    let static_config = compile_static_config(&config, config_root.clone())?;
    let reloadable_plan = compile_reloadable_plan(
        &config,
        &config_root,
        validation.compiled_urls_by_rule,
        resource_plan,
    )?;
    let fingerprint_bytes = serde_json::to_vec(&static_config).map_err(|error| {
        V3CompileError::at(
            "schema_version",
            format!("failed to fingerprint static config: {error}"),
        )
    })?;

    Ok(CompiledProductConfig {
        static_fingerprint: StaticFingerprint(Sha256::digest(&fingerprint_bytes).into()),
        static_config,
        reloadable_plan,
    })
}

fn normalize_endpoint_urls(config: &mut super::authoring::ConfigV3) -> Result<(), V3CompileError> {
    if let Some(parent) = config.egress.parent_proxy.as_mut() {
        parent.url = canonical_endpoint_url(&parent.url, "egress.parent_proxy.url")?;
    }
    if let Some(callback) = config.authorization.callback.as_mut() {
        callback.public_url =
            canonical_endpoint_url(&callback.public_url, "authorization.callback.public_url")?;
    }
    for (name, provider) in &mut config.authorization.providers {
        if let AuthorizationProviderConfig::Webhook(webhook) = provider {
            webhook.url = canonical_endpoint_url(
                &webhook.url,
                &format!("authorization.providers.{name}.url"),
            )?;
        }
    }
    Ok(())
}

fn canonical_endpoint_url(value: &str, path: &str) -> Result<String, V3CompileError> {
    canonicalize_http_url(value)
        .map(|url| url.url)
        .map_err(|error| V3CompileError::at(path, error.to_string()))
}

fn normalize_config_root(root: &Path) -> Result<PathBuf, V3CompileError> {
    if !root.is_absolute() {
        return Err(V3CompileError::at(
            "config root",
            "the loader must provide an absolute config-file directory",
        ));
    }
    lexical_normalize_absolute(root).ok_or_else(|| {
        V3CompileError::at(
            "config root",
            "could not normalize the config-file directory",
        )
    })
}

fn normalize_authored_paths(
    config: &mut super::authoring::ConfigV3,
    root: &Path,
) -> Result<(), V3CompileError> {
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
) -> Result<(), V3CompileError> {
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
) -> Result<(), V3CompileError> {
    if let Some(path) = tls.ca_certificate.as_mut() {
        *path = normalize_authored_path(root, path, &format!("{prefix}.ca_certificate"))?;
    }
    Ok(())
}

fn normalize_authored_path(
    root: &Path,
    value: &Path,
    field: &str,
) -> Result<PathBuf, V3CompileError> {
    if value.as_os_str().is_empty() {
        return Err(V3CompileError::at(field, "path must not be empty"));
    }
    if value.is_absolute() {
        return lexical_normalize_absolute(value)
            .ok_or_else(|| V3CompileError::at(field, "absolute path could not be normalized"));
    }

    let mut relative = PathBuf::new();
    for component in value.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => relative.push(part),
            Component::ParentDir => {
                if !relative.pop() {
                    return Err(V3CompileError::at(
                        field,
                        "relative path must not escape the configuration directory",
                    ));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(V3CompileError::at(field, "invalid relative path component"));
            }
        }
    }
    if relative.as_os_str().is_empty() {
        return Err(V3CompileError::at(
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

fn validate_positive_limits(config: &super::authoring::ConfigV3) -> Result<(), V3CompileError> {
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
    let four_quota = config
        .service
        .max_inflight_wire_body_bytes_per_quota_key
        .checked_mul(4)
        .ok_or_else(|| V3CompileError::at("service", "wire-body quota arithmetic overflow"))?;
    if four_quota > config.service.max_inflight_wire_body_bytes {
        return Err(V3CompileError::at(
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
    }
    if let Some(callback) = &config.authorization.callback {
        check_range(
            "authorization.callback.max_pending_operations",
            callback.max_pending_operations,
            MAX_PENDING_CALLBACKS,
        )?;
    }
    if config.authorization.providers.len() > MAX_PROVIDERS {
        return Err(V3CompileError::at(
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
        return Err(V3CompileError::at(
            "authorization.providers",
            format!("must contain no more than {MAX_PROCESS_PROVIDERS} process providers"),
        ));
    }
    validate_logging_capture_limits(config)?;
    validate_provider_limits(config)?;
    validate_redaction_limits(config)?;
    Ok(())
}

fn check_range(path: &str, value: usize, maximum: usize) -> Result<(), V3CompileError> {
    if value == 0 || value > maximum {
        return Err(V3CompileError::at(
            path,
            format!("must be between 1 and {maximum}"),
        ));
    }
    Ok(())
}

#[derive(Default)]
struct ListenerFacts {
    binds: BTreeSet<SocketAddr>,
    mitm_required: bool,
}

fn validate_listener_control_mitm_matrix(
    config: &super::authoring::ConfigV3,
) -> Result<ListenerFacts, V3CompileError> {
    let mut facts = ListenerFacts::default();
    let listeners = &config.listeners;
    if listeners.explicit_http.is_none()
        && listeners.transparent_http.is_none()
        && listeners.explicit_https.is_none()
        && listeners.transparent_https.is_none()
    {
        return Err(V3CompileError::at(
            "listeners",
            "at least one proxy listener must be configured",
        ));
    }

    if let Some(listener) = &listeners.explicit_http {
        validate_bind(listener.bind, "listeners.explicit_http.bind", false)?;
        insert_unique_bind(
            &mut facts.binds,
            listener.bind,
            "listeners.explicit_http.bind",
        )?;
        validate_http_versions(
            &listener.http_versions,
            "listeners.explicit_http.http_versions",
        )?;
        facts.mitm_required |= validate_connect(
            &listener.http_versions,
            &listener.connect,
            "listeners.explicit_http.connect",
        )?;
    }
    if let Some(listener) = &listeners.transparent_http {
        validate_bind(listener.bind, "listeners.transparent_http.bind", false)?;
        insert_unique_bind(
            &mut facts.binds,
            listener.bind,
            "listeners.transparent_http.bind",
        )?;
        validate_http_versions(
            &listener.http_versions,
            "listeners.transparent_http.http_versions",
        )?;
    }
    if let Some(listener) = &listeners.explicit_https {
        validate_bind(listener.bind, "listeners.explicit_https.bind", false)?;
        insert_unique_bind(
            &mut facts.binds,
            listener.bind,
            "listeners.explicit_https.bind",
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
        validate_bind(listener.bind, "listeners.transparent_https.bind", false)?;
        insert_unique_bind(
            &mut facts.binds,
            listener.bind,
            "listeners.transparent_https.bind",
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
    if let Some(control) = &config.control {
        validate_bind(control.bind, "control.bind", true)?;
        if facts
            .binds
            .iter()
            .any(|listener| socket_binds_overlap(*listener, control.bind))
        {
            return Err(V3CompileError::at(
                "control.bind",
                "must differ from every proxy listener bind",
            ));
        }
        if !canonical_socket_addr(control.bind).ip().is_loopback() && control.tls.is_none() {
            return Err(V3CompileError::at(
                "control.tls",
                "is required for a non-loopback control bind",
            ));
        }
        validate_base_path(&control.base_path)?;
    }

    match (&config.mitm, facts.mitm_required) {
        (None, true) => {
            return Err(V3CompileError::at(
                "mitm",
                "is required by transparent HTTPS or an HTTP/1 CONNECT MITM policy",
            ));
        }
        (Some(_), false) => {
            return Err(V3CompileError::at(
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

fn validate_bind(
    bind: SocketAddr,
    path: &str,
    forbid_unspecified: bool,
) -> Result<(), V3CompileError> {
    if bind.port() == 0 {
        return Err(V3CompileError::at(path, "port 0 is not allowed"));
    }
    if forbid_unspecified && bind.ip().is_unspecified() {
        return Err(V3CompileError::at(
            path,
            "an unspecified control address is not allowed",
        ));
    }
    Ok(())
}

fn insert_unique_bind(
    binds: &mut BTreeSet<SocketAddr>,
    bind: SocketAddr,
    path: &str,
) -> Result<(), V3CompileError> {
    if binds
        .iter()
        .any(|existing| socket_binds_overlap(*existing, bind))
    {
        return Err(V3CompileError::at(
            path,
            "overlaps another proxy listener bind",
        ));
    }
    binds.insert(canonical_socket_addr(bind));
    Ok(())
}

fn socket_binds_overlap(left: SocketAddr, right: SocketAddr) -> bool {
    let left = canonical_socket_addr(left);
    let right = canonical_socket_addr(right);
    left.port() == right.port()
        && (left.ip() == right.ip() || left.ip().is_unspecified() || right.ip().is_unspecified())
}

fn canonical_socket_addr(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(address) => address
            .ip()
            .to_ipv4_mapped()
            .map(|mapped| SocketAddr::new(IpAddr::V4(mapped), address.port()))
            .unwrap_or(SocketAddr::V6(address)),
        address => address,
    }
}

fn validate_http_versions(versions: &[HttpVersion], path: &str) -> Result<(), V3CompileError> {
    if versions.is_empty() {
        return Err(V3CompileError::at(path, "must not be empty"));
    }
    let mut seen = BTreeSet::new();
    for version in versions {
        let key = match version {
            HttpVersion::Http1 => 1,
            HttpVersion::Http2 => 2,
        };
        if !seen.insert(key) {
            return Err(V3CompileError::at(
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
) -> Result<bool, V3CompileError> {
    let has_http1 = versions.iter().any(|v| matches!(v, HttpVersion::Http1));
    let has_http2 = versions.iter().any(|v| matches!(v, HttpVersion::Http2));
    if has_http1 != connect.http1.is_some() {
        return Err(V3CompileError::at(
            format!("{path}.http1"),
            "must be present exactly when HTTP/1 is enabled",
        ));
    }
    if has_http2 != connect.http2.is_some() {
        return Err(V3CompileError::at(
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
) -> Result<(), V3CompileError> {
    check_range(
        &format!("{prefix}.max_connections"),
        connections,
        MAX_LISTENER_CONNECTIONS,
    )?;
    if streams == 0 || streams > MAX_LISTENER_STREAMS {
        return Err(V3CompileError::at(
            format!("{prefix}.max_concurrent_streams"),
            format!("must be between 1 and {MAX_LISTENER_STREAMS}"),
        ));
    }
    Ok(())
}

fn validate_base_path(base: &str) -> Result<(), V3CompileError> {
    if !base.starts_with('/')
        || base == "/"
        || base.ends_with('/')
        || base.contains("//")
        || base.contains('\\')
        || base.contains('%')
    {
        return Err(V3CompileError::at(
            "control.base_path",
            "must be a normalized absolute non-root path without a trailing slash",
        ));
    }
    if base.split('/').any(|segment| matches!(segment, "." | ".."))
        || base
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'?' || byte == b'#')
    {
        return Err(V3CompileError::at(
            "control.base_path",
            "contains an unsafe path component",
        ));
    }
    Ok(())
}

fn validate_tls_and_parent_matrix(
    config: &super::authoring::ConfigV3,
    listeners: &ListenerFacts,
) -> Result<(), V3CompileError> {
    validate_transport_tls(&config.egress.origin_tls, "egress.origin_tls")?;
    match config.egress.route {
        EgressRoute::Direct => {
            if config.egress.parent_proxy.is_some() {
                return Err(V3CompileError::at(
                    "egress.parent_proxy",
                    "must be absent when egress.route is direct",
                ));
            }
            if !config.safety.loop_detection.inject {
                return Err(V3CompileError::at(
                    "safety.loop_detection.inject",
                    "must be true for direct egress",
                ));
            }
        }
        EgressRoute::ParentProxy => {
            let parent = config.egress.parent_proxy.as_ref().ok_or_else(|| {
                V3CompileError::at(
                    "egress.parent_proxy",
                    "is required when egress.route is parent_proxy",
                )
            })?;
            let url = validate_endpoint_url(&parent.url, "egress.parent_proxy.url", true)?;
            match url.scheme() {
                "http" if parent.tls.is_some() => {
                    return Err(V3CompileError::at(
                        "egress.parent_proxy.tls",
                        "must be absent for an HTTP parent URL",
                    ));
                }
                "https" => {
                    let tls = parent.tls.as_ref().ok_or_else(|| {
                        V3CompileError::at(
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
                _ => {}
            }
            if let Some(address) = literal_url_socket_addr(&url) {
                if config.control.as_ref().is_some_and(|control| {
                    socket_binds_overlap(canonical_socket_addr(control.bind), address)
                }) {
                    return Err(V3CompileError::at(
                        "egress.parent_proxy.url",
                        "must not target the control listener",
                    ));
                }
                if listeners
                    .binds
                    .iter()
                    .any(|listener| socket_binds_overlap(*listener, address))
                {
                    return Err(V3CompileError::at(
                        "egress.parent_proxy.url",
                        "must not target a proxy listener",
                    ));
                }
                if address.ip().is_loopback() {
                    return Err(V3CompileError::at(
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
                return Err(V3CompileError::at(
                    "control.bind",
                    "parent routing requires a loopback control bind",
                ));
            }
            if matches!(parent.kind, ParentProxyKind::Generic)
                && !config.safety.loop_detection.inject
            {
                return Err(V3CompileError::at(
                    "safety.loop_detection.inject",
                    "must be true when the parent proxy kind is generic",
                ));
            }
        }
    }

    for (name, provider) in &config.authorization.providers {
        if let AuthorizationProviderConfig::Webhook(webhook) = provider {
            let prefix = format!("authorization.providers.{name}");
            let url = validate_endpoint_url(&webhook.url, &format!("{prefix}.url"), false)?;
            match url.scheme() {
                "http" => {
                    if !url_host_is_loopback(&url) {
                        return Err(V3CompileError::at(
                            format!("{prefix}.url"),
                            "plain HTTP is allowed only for a loopback webhook",
                        ));
                    }
                    if webhook.tls.is_some() {
                        return Err(V3CompileError::at(
                            format!("{prefix}.tls"),
                            "must be absent for an HTTP webhook",
                        ));
                    }
                }
                "https" => {
                    if let Some(tls) = &webhook.tls {
                        validate_trust_matrix(
                            tls.trust,
                            tls.ca_certificate.as_deref(),
                            &format!("{prefix}.tls"),
                        )?;
                    }
                }
                _ => unreachable!("validated endpoint URL scheme"),
            }
        }
    }
    validate_callback_matrix(config)?;
    Ok(())
}

fn validate_transport_tls(tls: &TransportTlsConfig, prefix: &str) -> Result<(), V3CompileError> {
    validate_trust_matrix(tls.trust, tls.ca_certificate.as_deref(), prefix)?;
    validate_http_versions(&tls.http_versions, &format!("{prefix}.http_versions"))
}

fn validate_trust_matrix(
    trust: TlsTrust,
    ca: Option<&Path>,
    prefix: &str,
) -> Result<(), V3CompileError> {
    let requires_ca = matches!(trust, TlsTrust::Custom | TlsTrust::SystemPlusCustom);
    if requires_ca != ca.is_some() {
        return Err(V3CompileError::at(
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

fn validate_endpoint_url(value: &str, path: &str, parent: bool) -> Result<Url, V3CompileError> {
    let url = Url::parse(value)
        .map_err(|error| V3CompileError::at(path, format!("must be an absolute URL: {error}")))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(V3CompileError::at(
            path,
            "must use HTTP or HTTPS and include a host",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(V3CompileError::at(
            path,
            "must not contain userinfo or a fragment",
        ));
    }
    if parent && (url.path() != "/" || url.query().is_some()) {
        return Err(V3CompileError::at(
            path,
            "parent URL must not contain a path or query",
        ));
    }
    Ok(url)
}

fn validate_dns_server_name(value: &str, path: &str) -> Result<(), V3CompileError> {
    if value.is_empty()
        || value.ends_with('.')
        || value.contains('*')
        || value.contains(':')
        || value.parse::<IpAddr>().is_ok()
    {
        return Err(V3CompileError::at(
            path,
            "must be a non-wildcard DNS name without a port or root dot",
        ));
    }
    if !dns_name_has_safe_ascii_shape(value) {
        return Err(V3CompileError::at(
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

fn literal_url_socket_addr(url: &Url) -> Option<SocketAddr> {
    let host = match url.host()? {
        Host::Ipv4(address) => IpAddr::V4(address),
        Host::Ipv6(address) => IpAddr::V6(address),
        Host::Domain(_) => return None,
    };
    Some(canonical_socket_addr(SocketAddr::new(
        host,
        url.port_or_known_default()?,
    )))
}

fn url_host_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => domain == "localhost",
        None => false,
    }
}

fn validate_callback_matrix(config: &super::authoring::ConfigV3) -> Result<(), V3CompileError> {
    let webhook_delegated = config.policy.rules.iter().any(|rule| {
        rule.authorization_provider.as_ref().is_some_and(|name| {
            matches!(
                config.authorization.providers.get(name),
                Some(AuthorizationProviderConfig::Webhook(_))
            )
        })
    });
    if webhook_delegated && config.control.is_none() {
        return Err(V3CompileError::at(
            "control",
            "is required when a rule delegates to a webhook provider",
        ));
    }
    if webhook_delegated && config.authorization.callback.is_none() {
        return Err(V3CompileError::at(
            "authorization.callback",
            "is required when a rule delegates to a webhook provider",
        ));
    }
    let Some(callback) = &config.authorization.callback else {
        return Ok(());
    };
    let control = config.control.as_ref().ok_or_else(|| {
        V3CompileError::at("authorization.callback", "requires the control listener")
    })?;
    let url = validate_endpoint_url(
        &callback.public_url,
        "authorization.callback.public_url",
        false,
    )?;
    let expected_path = format!("{}/external-auth/callback", control.base_path);
    if url.path() != expected_path || url.query().is_some() {
        return Err(V3CompileError::at(
            "authorization.callback.public_url",
            format!("path must be exactly {expected_path} with no query"),
        ));
    }
    if url.scheme() == "http" && (!url_host_is_loopback(&url) || !control.bind.ip().is_loopback()) {
        return Err(V3CompileError::at(
            "authorization.callback.public_url",
            "plain HTTP requires both a loopback URL host and loopback control bind",
        ));
    }
    Ok(())
}

struct ValidationFacts {
    compiled_urls_by_rule: Vec<Vec<CompiledUrlPattern>>,
}

fn validate_references_and_security_boundaries(
    config: &super::authoring::ConfigV3,
) -> Result<ValidationFacts, V3CompileError> {
    validate_named_maps(config)?;
    let credential_destinations = validate_credentials(config)?;
    validate_internal_context(config)?;
    validate_provider_security(config, &credential_destinations)?;
    let compiled_urls_by_rule = validate_policy(config)?;
    validate_capture(config)?;

    Ok(ValidationFacts {
        compiled_urls_by_rule,
    })
}

fn validate_named_maps(config: &super::authoring::ConfigV3) -> Result<(), V3CompileError> {
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

fn validate_identifier(value: &str, path: &str) -> Result<(), V3CompileError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(V3CompileError::at(
            path,
            "identifier must use only ASCII letters, digits, '_', '-', or '.'",
        ));
    }
    Ok(())
}

fn validate_credentials(
    config: &super::authoring::ConfigV3,
) -> Result<BTreeSet<String>, V3CompileError> {
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
            return Err(V3CompileError::at(
                "credentials.allowed_custom_headers",
                "must be case-insensitively duplicate-free",
            ));
        }
    }
    for (name, source) in &config.credentials.sources {
        match source {
            CredentialSourceConfig::Environment(value) => {
                if !valid_environment_name(&value.variable) {
                    return Err(V3CompileError::at(
                        format!("credentials.sources.{name}.variable"),
                        "must be a valid environment variable name",
                    ));
                }
            }
            CredentialSourceConfig::File(value) => {
                if !value.path.is_absolute() {
                    return Err(V3CompileError::at(
                        format!("credentials.sources.{name}.path"),
                        "must be normalized by the config-root compiler",
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
            return Err(V3CompileError::at(
                format!("credentials.inbound.{name}.header"),
                "duplicates another inbound credential header",
            ));
        }
        if inbound.process_providers.is_empty() {
            return Err(V3CompileError::at(
                format!("credentials.inbound.{name}.process_providers"),
                "must not be empty",
            ));
        }
        let mut providers = BTreeSet::new();
        for provider_name in &inbound.process_providers {
            if !providers.insert(provider_name) {
                return Err(V3CompileError::at(
                    format!("credentials.inbound.{name}.process_providers"),
                    "must not contain duplicates",
                ));
            }
            let Some(AuthorizationProviderConfig::Process(provider)) =
                config.authorization.providers.get(provider_name)
            else {
                return Err(V3CompileError::at(
                    format!("credentials.inbound.{name}.process_providers"),
                    format!("{provider_name:?} must name a process provider"),
                ));
            };
            if !contains_header(&provider.include_headers, &header) {
                return Err(V3CompileError::at(
                    format!("credentials.inbound.{name}.process_providers"),
                    format!("process provider {provider_name:?} must include the inbound header"),
                ));
            }
        }
    }

    let all_credential_destinations = collect_all_credential_destinations(config, &allowed_custom)?;
    for destination in &all_credential_destinations {
        if inbound_headers.contains(destination) {
            return Err(V3CompileError::at(
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
    config: &super::authoring::ConfigV3,
    allowed_custom: &BTreeSet<String>,
) -> Result<BTreeSet<String>, V3CompileError> {
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
                        return Err(V3CompileError::at(
                            format!("policy.rules[{index}]"),
                            "credential destinations collide between rule actions and provider outputs",
                        ));
                    }
                }
            }
        }
        if local.iter().any(|destination| global.contains(destination)) {
            return Err(V3CompileError::at(
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
) -> Result<BTreeSet<String>, V3CompileError> {
    if actions.len() > MAX_EFFECTS_PER_SCOPE {
        return Err(V3CompileError::at(
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
                    return Err(V3CompileError::at(
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
                    return Err(V3CompileError::at(
                        format!("{path}[{index}].header"),
                        "must be declared in credentials.allowed_custom_headers",
                    ));
                }
                header
            }
        };
        if !destinations.insert(destination) {
            return Err(V3CompileError::at(
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
) -> Result<(), V3CompileError> {
    if !credentials.sources.contains_key(source) {
        return Err(V3CompileError::at(
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
) -> Result<BTreeSet<String>, V3CompileError> {
    let outputs = match provider {
        AuthorizationProviderConfig::Webhook(value) => &value.outputs,
        AuthorizationProviderConfig::Process(value) => &value.outputs,
    };
    if outputs.len() > MAX_PROVIDER_ITEMS {
        return Err(V3CompileError::at(path, "contains too many outputs"));
    }
    let mut destinations = BTreeSet::new();
    for (name, output) in outputs {
        validate_identifier(name, &format!("{path}.{name}"))?;
        let destination = match output {
            super::authoring::ProviderOutputConfig::Bearer(_) => "authorization".to_string(),
            super::authoring::ProviderOutputConfig::Basic(value) => {
                if value.username.is_empty() || value.username.contains(':') {
                    return Err(V3CompileError::at(
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
                    return Err(V3CompileError::at(
                        format!("{path}.{name}.header"),
                        "must be declared in credentials.allowed_custom_headers",
                    ));
                }
                header
            }
        };
        if !destinations.insert(destination) {
            return Err(V3CompileError::at(
                path,
                "contains duplicate credential destinations",
            ));
        }
    }
    Ok(destinations)
}

fn validate_internal_context(config: &super::authoring::ConfigV3) -> Result<(), V3CompileError> {
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
            return Err(V3CompileError::at(
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
            return Err(V3CompileError::at(
                "authorization.internal_context_headers",
                format!("{name:?} requires exactly one global egress literal action"),
            ));
        }
        match matching[0] {
            HeaderEffectConfig::Set(value) if matches!(value.when, HeaderEffectWhen::Always) => {}
            HeaderEffectConfig::Remove(value) if matches!(value.when, HeaderEffectWhen::Always) => {
            }
            _ => {
                return Err(V3CompileError::at(
                    "authorization.internal_context_headers",
                    format!("{name:?} requires an unconditional set or remove action"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_provider_security(
    config: &super::authoring::ConfigV3,
    credential_destinations: &BTreeSet<String>,
) -> Result<(), V3CompileError> {
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
        };
        if headers.len() > MAX_PROVIDER_ITEMS {
            return Err(V3CompileError::at(
                format!("authorization.providers.{name}.include_headers"),
                "contains too many headers",
            ));
        }
        let mut seen = BTreeSet::new();
        for (index, header) in headers.iter().enumerate() {
            let path = format!("authorization.providers.{name}.include_headers[{index}]");
            let header = normalize_header_name(header, &path)?;
            if !seen.insert(header.clone()) {
                return Err(V3CompileError::at(path, "duplicates an earlier header"));
            }
            if base_protected_headers().contains(header.as_str()) || header == loop_header {
                return Err(V3CompileError::at(
                    path,
                    "provider may not receive a protected header",
                ));
            }
            if credential_destinations.contains(&header) {
                return Err(V3CompileError::at(
                    path,
                    "provider may not receive an outbound credential destination",
                ));
            }
            if let Some(providers) = inbound.get(&header) {
                if !is_process || !providers.contains(name) {
                    return Err(V3CompileError::at(
                        path,
                        "inbound credential header is not authorized for this provider",
                    ));
                }
            }
            if contexts.contains(&header) && (!is_process || !context_is_consuming(config, &header))
            {
                return Err(V3CompileError::at(
                    path,
                    "internal context headers may be sent only to a consuming process provider",
                ));
            }
        }
    }
    Ok(())
}

fn context_is_consuming(config: &super::authoring::ConfigV3, header: &str) -> bool {
    config.egress.request_headers.iter().any(|effect| {
        matches!(effect, HeaderEffectConfig::Remove(value)
            if value.name.eq_ignore_ascii_case(header)
                && matches!(value.when, HeaderEffectWhen::Always))
    })
}

fn validate_policy(
    config: &super::authoring::ConfigV3,
) -> Result<Vec<Vec<CompiledUrlPattern>>, V3CompileError> {
    if config.policy.rules.len() > MAX_POLICY_RULES {
        return Err(V3CompileError::at(
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
            return Err(V3CompileError::at(
                format!("{prefix}.id"),
                "must be nonempty and unique",
            ));
        }
        let predicate_count = rule.urls.len()
            + rule.methods.len()
            + rule.client_cidrs.len()
            + rule.headers.absent_any.len()
            + rule.headers.present_all.len()
            + rule.headers.all.len()
            + rule.headers.none.len();
        if predicate_count == 0 {
            return Err(V3CompileError::at(
                &prefix,
                "must define at least one request predicate",
            ));
        }
        if rule.urls.len() > MAX_URLS_PER_RULE {
            return Err(V3CompileError::at(
                format!("{prefix}.urls"),
                "contains too many URL patterns",
            ));
        }
        let patterns = rule
            .urls
            .iter()
            .enumerate()
            .map(|(pattern_index, pattern)| {
                CompiledUrlPattern::compile(pattern).map_err(|error| {
                    V3CompileError::at(format!("{prefix}.urls[{pattern_index}]"), error.to_string())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        compiled_urls_by_rule.push(patterns);
        validate_methods(&rule.methods, &format!("{prefix}.methods"))?;
        validate_header_predicates(rule, &prefix, &contexts, &inbound)?;

        match rule.decision {
            RuleDecision::Delegate => {
                let provider = rule.authorization_provider.as_ref().ok_or_else(|| {
                    V3CompileError::at(
                        format!("{prefix}.authorization_provider"),
                        "is required for a delegate rule",
                    )
                })?;
                if !config.authorization.providers.contains_key(provider) {
                    return Err(V3CompileError::at(
                        format!("{prefix}.authorization_provider"),
                        format!("references unknown provider {provider:?}"),
                    ));
                }
            }
            RuleDecision::Allow | RuleDecision::Deny => {
                if rule.authorization_provider.is_some() {
                    return Err(V3CompileError::at(
                        format!("{prefix}.authorization_provider"),
                        "is valid only for a delegate rule",
                    ));
                }
            }
        }
        if let Some(profile) = &rule.redaction_profile {
            if matches!(rule.decision, RuleDecision::Deny) {
                return Err(V3CompileError::at(
                    format!("{prefix}.redaction_profile"),
                    "is forbidden on a deny rule",
                ));
            }
            if !config.redaction.profiles.contains_key(profile) {
                return Err(V3CompileError::at(
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
            return Err(V3CompileError::at(
                &prefix,
                "deny rules cannot contain forwarding effects",
            ));
        }
        if rule.request_headers.len() > MAX_EFFECTS_PER_SCOPE
            || rule.response_headers.len() > MAX_EFFECTS_PER_SCOPE
            || rule.credential_actions.len() > MAX_EFFECTS_PER_SCOPE
        {
            return Err(V3CompileError::at(&prefix, "contains too many effects"));
        }
    }
    Ok(compiled_urls_by_rule)
}

fn validate_methods(methods: &[String], path: &str) -> Result<(), V3CompileError> {
    let mut seen = BTreeSet::new();
    for method in methods {
        if method.is_empty() || !method.bytes().all(is_http_token_byte) {
            return Err(V3CompileError::at(path, "contains an invalid HTTP token"));
        }
        if !seen.insert(method.to_ascii_uppercase()) {
            return Err(V3CompileError::at(
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
) -> Result<(), V3CompileError> {
    let count = rule.headers.absent_any.len()
        + rule.headers.present_all.len()
        + rule.headers.all.values().map(Vec::len).sum::<usize>()
        + rule.headers.none.values().map(Vec::len).sum::<usize>();
    if count > MAX_HEADER_PREDICATES_PER_RULE {
        return Err(V3CompileError::at(
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
                return Err(V3CompileError::at(
                    format!("{prefix}.headers.{kind}"),
                    "internal context headers cannot be policy predicates",
                ));
            }
            if !all_names.insert(header) {
                return Err(V3CompileError::at(
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
                return Err(V3CompileError::at(
                    format!("{prefix}.headers.{kind}"),
                    "protected or credential-bearing headers cannot be value predicates",
                ));
            }
            if expected.is_empty() {
                return Err(V3CompileError::at(
                    format!("{prefix}.headers.{kind}.{name}"),
                    "must contain at least one value",
                ));
            }
            for value in expected {
                HeaderValue::from_str(value).map_err(|error| {
                    V3CompileError::at(
                        format!("{prefix}.headers.{kind}.{name}"),
                        format!("contains an invalid header value: {error}"),
                    )
                })?;
            }
            if !all_names.insert(header) {
                return Err(V3CompileError::at(
                    format!("{prefix}.headers"),
                    "predicate names must be unique across predicate kinds",
                ));
            }
        }
    }
    Ok(())
}

fn validate_all_literal_effects(
    config: &super::authoring::ConfigV3,
    loop_header: &str,
    credential_destinations: &BTreeSet<String>,
    inbound_headers: &BTreeSet<String>,
    internal_context_headers: &BTreeSet<String>,
) -> Result<(), V3CompileError> {
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
) -> Result<(), V3CompileError> {
    if effects.len() > MAX_EFFECTS_PER_SCOPE {
        return Err(V3CompileError::at(path, "contains too many effects"));
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
            return Err(V3CompileError::at(
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
                        return Err(V3CompileError::at(
                            format!("{path}[{index}]"),
                            "must define exactly one of value or nonempty values",
                        ));
                    }
                };
                for value in values {
                    if value.len() > MAX_HEADER_FIELD_BYTES {
                        return Err(V3CompileError::at(
                            format!("{path}[{index}]"),
                            "header value exceeds the 64 KiB field limit",
                        ));
                    }
                    if value.contains("${") {
                        return Err(V3CompileError::at(
                            format!("{path}[{index}]"),
                            "generic environment interpolation is not valid in v3",
                        ));
                    }
                    HeaderValue::from_str(value).map_err(|error| {
                        V3CompileError::at(
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
                    return Err(V3CompileError::at(
                        format!("{path}[{index}]"),
                        "header search or replacement text exceeds the 64 KiB field limit",
                    ));
                }
                if value.search.is_empty() {
                    return Err(V3CompileError::at(
                        format!("{path}[{index}].search"),
                        "must not be empty",
                    ));
                }
                if HeaderValue::from_str(&value.search).is_err()
                    || HeaderValue::from_str(&value.replace).is_err()
                {
                    return Err(V3CompileError::at(
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

fn validate_capture(config: &super::authoring::ConfigV3) -> Result<(), V3CompileError> {
    let Some(capture) = &config.observation.capture else {
        return Ok(());
    };
    if capture.events.is_empty() {
        return Err(V3CompileError::at(
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
            return Err(V3CompileError::at(
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
        return Err(V3CompileError::at(
            "observation.capture.redaction_profile",
            "must name an existing redaction profile",
        ));
    }
    validate_capture_filename(&capture.filename)?;
    Ok(())
}

fn validate_capture_filename(filename: &str) -> Result<(), V3CompileError> {
    if filename.is_empty()
        || filename.contains('/')
        || filename.contains('\\')
        || filename.contains("..")
        || filename.chars().any(char::is_control)
        || !filename.contains("{requestId}")
        || !filename.contains("{suffix}")
    {
        return Err(V3CompileError::at(
            "observation.capture.filename",
            "must be a basename containing {requestId} and {suffix}",
        ));
    }
    let stripped = filename.replace("{requestId}", "").replace("{suffix}", "");
    if stripped.contains('{') || stripped.contains('}') {
        return Err(V3CompileError::at(
            "observation.capture.filename",
            "contains an unknown template variable",
        ));
    }
    Ok(())
}

fn validate_provider_limits(config: &super::authoring::ConfigV3) -> Result<(), V3CompileError> {
    for (name, provider) in &config.authorization.providers {
        match provider {
            AuthorizationProviderConfig::Webhook(value) => {
                check_range(
                    &format!("authorization.providers.{name}.max_response_bytes"),
                    value.max_response_bytes,
                    MAX_CONTROL_BODY_BYTES,
                )?;
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
                check_range(
                    &format!("authorization.providers.{name}.max_pending_requests"),
                    value.max_pending_requests,
                    MAX_PROCESS_PENDING_REQUESTS,
                )?;
                if value.max_decoded_request_body_bytes < value.max_request_body_bytes {
                    return Err(V3CompileError::at(
                        format!("authorization.providers.{name}"),
                        "decoded request-body limit must be at least the encoded limit",
                    ));
                }
                if value.allow_request_body_replacement && !value.include_request_body {
                    return Err(V3CompileError::at(
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
                    return Err(V3CompileError::at(
                        format!("authorization.providers.{name}.retire_timeout"),
                        "must cover the greatest effective request timeout of every referencing rule",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_process_environment(
    name: &str,
    value: &super::authoring::ProcessProviderConfig,
) -> Result<(), V3CompileError> {
    let mut names = BTreeSet::new();
    for environment_name in &value.pass_environment {
        if !valid_environment_name(environment_name) || !names.insert(environment_name) {
            return Err(V3CompileError::at(
                format!("authorization.providers.{name}.pass_environment"),
                "must contain unique valid environment variable names",
            ));
        }
    }
    for environment_name in value.environment.keys() {
        if !valid_environment_name(environment_name) {
            return Err(V3CompileError::at(
                format!("authorization.providers.{name}.environment"),
                "contains an invalid environment variable name",
            ));
        }
        if names.contains(environment_name) {
            return Err(V3CompileError::at(
                format!("authorization.providers.{name}.environment"),
                "must not overlap pass_environment",
            ));
        }
    }
    Ok(())
}

fn validate_redaction_limits(config: &super::authoring::ConfigV3) -> Result<(), V3CompileError> {
    if config.redaction.profiles.len() > MAX_REDACTION_PROFILES {
        return Err(V3CompileError::at(
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
        configured_profile_literal_scratch_bytes(profile, &prefix)?;
        if profile.max_decoded_body_bytes < profile.max_body_bytes {
            return Err(V3CompileError::at(
                &prefix,
                "max_decoded_body_bytes must be at least max_body_bytes",
            ));
        }
        if profile.max_message_bytes < profile.max_frame_bytes {
            return Err(V3CompileError::at(
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
            return Err(V3CompileError::at(
                format!("{prefix}.replacement"),
                "generic environment interpolation is not valid in v3",
            ));
        }
        if profile.rules.is_empty() || profile.rules.len() > MAX_REDACTION_RULES {
            return Err(V3CompileError::at(
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
            .ok_or_else(|| V3CompileError::at(&prefix, "expression budget arithmetic overflow"))?;
        if expression_count > MAX_REDACTION_EXPRESSIONS
            || expression_bytes > MAX_REDACTION_EXPRESSION_BYTES_PER_PROFILE
        {
            return Err(V3CompileError::at(
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
                return Err(V3CompileError::at(
                    &rule_path,
                    "must define a literal, environment literal source, or expression",
                ));
            }
            if matches!(rule.payloads, RedactionPayloads::Binary) && !rule.expressions.is_empty() {
                return Err(V3CompileError::at(
                    format!("{rule_path}.expressions"),
                    "binary-only rules cannot contain regular expressions",
                ));
            }
            literal_count = literal_count
                .checked_add(rule.literals.len())
                .ok_or_else(|| {
                    V3CompileError::at(&rule_path, "literal count arithmetic overflow")
                })?;
            for literal in &rule.literals {
                if literal.is_empty() || literal.contains("${") {
                    return Err(V3CompileError::at(
                        format!("{rule_path}.literals"),
                        "literals must be nonempty and cannot use generic interpolation",
                    ));
                }
                literal_bytes = literal_bytes.checked_add(literal.len()).ok_or_else(|| {
                    V3CompileError::at(&rule_path, "literal byte arithmetic overflow")
                })?;
            }
            let mut sources = BTreeSet::new();
            for (source_index, source) in rule.literal_environment_variables.iter().enumerate() {
                if !valid_environment_name(source) || !sources.insert(source) {
                    return Err(V3CompileError::at(
                        format!("{rule_path}.literal_environment_variables[{source_index}]"),
                        "source metadata is invalid or duplicates another source in this rule",
                    ));
                }
            }
            profile_sources = profile_sources
                .checked_add(rule.literal_environment_variables.len())
                .ok_or_else(|| {
                    V3CompileError::at(&rule_path, "source count arithmetic overflow")
                })?;
        }
        if literal_count > MAX_TOML_REDACTION_LITERALS_PER_PROFILE
            || literal_bytes > MAX_TOML_REDACTION_LITERAL_BYTES_PER_PROFILE
        {
            return Err(V3CompileError::at(
                &prefix,
                "TOML literal count or byte ceiling exceeded",
            ));
        }
        if profile_sources > profile.max_environment_literal_sources {
            return Err(V3CompileError::at(
                &prefix,
                "environment literal source count exceeds the authored profile limit",
            ));
        }
        snapshot_source_count = snapshot_source_count
            .checked_add(profile_sources)
            .ok_or_else(|| {
                V3CompileError::at("redaction.profiles", "snapshot source count overflow")
            })?;
        if profile_sources != 0 {
            let source_byte_budget = profile_sources
                .checked_mul(profile.max_environment_literal_bytes)
                .ok_or_else(|| {
                    V3CompileError::at("redaction.profiles", "snapshot byte budget overflow")
                })?
                .min(profile.max_environment_literal_total_bytes);
            snapshot_source_byte_budget = snapshot_source_byte_budget
                .checked_add(source_byte_budget)
                .ok_or_else(|| {
                    V3CompileError::at("redaction.profiles", "snapshot byte budget overflow")
                })?;
        }
    }
    if snapshot_source_count > MAX_REDACTION_ENV_SOURCES_PER_SNAPSHOT
        || snapshot_source_byte_budget > MAX_REDACTION_ENV_BYTES_PER_SNAPSHOT
    {
        return Err(V3CompileError::at(
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
) -> Result<(), V3CompileError> {
    let proportional = encoded
        .checked_mul(ratio)
        .ok_or_else(|| V3CompileError::at(path, "content-decoding ratio arithmetic overflow"))?;
    let maximum = proportional.max(MIB);
    if decoded > maximum {
        return Err(V3CompileError::at(
            path,
            "decoded limit exceeds the configured proportional decoding bound",
        ));
    }
    Ok(())
}

fn validate_logging_capture_limits(
    config: &super::authoring::ConfigV3,
) -> Result<(), V3CompileError> {
    let logging = &config.observation.logging;
    if logging.max_bytes == 0 || logging.max_bytes > MAX_LOG_BYTES {
        return Err(V3CompileError::at(
            "observation.logging.max_bytes",
            format!("must be between 1 and {MAX_LOG_BYTES}"),
        ));
    }
    check_range(
        "observation.logging.max_files",
        logging.max_files,
        MAX_LOG_FILES,
    )?;
    for (path, level) in [
        ("observation.logging.level", logging.level.as_str()),
        (
            "observation.logging.policy_decisions.allow_level",
            logging.policy_decisions.allow_level.as_str(),
        ),
        (
            "observation.logging.policy_decisions.deny_level",
            logging.policy_decisions.deny_level.as_str(),
        ),
    ] {
        if !matches!(level, "trace" | "debug" | "info" | "warn" | "error") {
            return Err(V3CompileError::at(
                path,
                "must be trace, debug, info, warn, or error",
            ));
        }
    }
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
            "observation.capture.max_files",
            capture.max_files,
            MAX_CAPTURE_FILES,
        )?;
        if capture.max_total_bytes == 0 || capture.max_total_bytes > MAX_CAPTURE_TOTAL_BYTES {
            return Err(V3CompileError::at(
                "observation.capture.max_total_bytes",
                format!("must be between 1 and {MAX_CAPTURE_TOTAL_BYTES}"),
            ));
        }
        if capture.max_inflight_body_bytes < capture.max_body_bytes
            || capture.max_total_bytes < capture.max_body_bytes as u64
        {
            return Err(V3CompileError::at(
                "observation.capture",
                "in-flight and total limits must each hold at least one maximum capture body",
            ));
        }
    }
    Ok(())
}

fn configured_profile_literal_scratch_bytes(
    profile: &super::authoring::RedactionProfileConfig,
    path: &str,
) -> Result<usize, V3CompileError> {
    let mut max_pattern_len = 0usize;
    let mut has_environment_source = false;
    for rule in &profile.rules {
        max_pattern_len = max_pattern_len.max(
            rule.literals
                .iter()
                .map(|literal| literal.len())
                .max()
                .unwrap_or(0),
        );
        has_environment_source |= !rule.literal_environment_variables.is_empty();
    }
    if has_environment_source {
        max_pattern_len = max_pattern_len.max(profile.max_environment_literal_bytes);
    }
    redaction_literal_scratch_bytes(max_pattern_len).ok_or_else(|| {
        V3CompileError::at(
            path,
            "configured literal horizon exceeds the matcher scratch ceiling",
        )
    })
}

fn compile_resource_plan(
    config: &super::authoring::ConfigV3,
) -> Result<CompiledResourcePlan, V3CompileError> {
    let rule_schedules = config
        .policy
        .rules
        .iter()
        .map(|rule| compile_http_rule_schedule(config, rule))
        .collect::<Result<Vec<_>, _>>()?;
    // Rule-local schedules describe live allocations, not cumulative work.
    // A provider pass retains only the decoded original. A later compatible
    // rule reuses that allocation and adds only its simultaneously live stage.
    // The reverse indexes hold the largest later stage reachable by any
    // request method. This covers an arbitrary number of delegate passes in
    // O(rules + total method entries), without weakening the policy-rule cap.
    let mut path_peaks = vec![0usize; rule_schedules.len()];
    let mut all_later_stage_bytes = 0usize;
    let mut wildcard_later_stage_bytes = 0usize;
    let mut later_stage_bytes_by_method = BTreeMap::<String, usize>::new();
    for index in (0..rule_schedules.len()).rev() {
        let schedule = &rule_schedules[index];
        path_peaks[index] = schedule.initial_peak;
        if let Some(retained) = schedule.retained_original_after_pass {
            let compatible_later_stage_bytes = if config.policy.rules[index].methods.is_empty() {
                all_later_stage_bytes
            } else {
                config.policy.rules[index].methods.iter().fold(
                    wildcard_later_stage_bytes,
                    |peak, method| {
                        peak.max(
                            later_stage_bytes_by_method
                                .get(&method.to_ascii_uppercase())
                                .copied()
                                .unwrap_or(0),
                        )
                    },
                )
            };
            path_peaks[index] = path_peaks[index].max(checked_add(
                retained,
                compatible_later_stage_bytes,
                &format!("policy.rules[{index}]"),
                "delegate-pass body retention arithmetic overflow",
            )?);
        }

        let stage_bytes = schedule.max_incoming_additional_bytes();
        all_later_stage_bytes = all_later_stage_bytes.max(stage_bytes);
        if config.policy.rules[index].methods.is_empty() {
            wildcard_later_stage_bytes = wildcard_later_stage_bytes.max(stage_bytes);
        } else {
            for method in &config.policy.rules[index].methods {
                later_stage_bytes_by_method
                    .entry(method.to_ascii_uppercase())
                    .and_modify(|peak| *peak = (*peak).max(stage_bytes))
                    .or_insert(stage_bytes);
            }
        }
    }

    let mut cursor_peaks = vec![0usize; config.policy.rules.len() + 1];
    for index in (0..config.policy.rules.len()).rev() {
        cursor_peaks[index] = cursor_peaks[index + 1].max(path_peaks[index]);
    }
    let max_wire_peak = cursor_peaks.iter().copied().max().unwrap_or(0);

    let wire_body_full_peak_capacity = if max_wire_peak == 0 {
        Capacity::Unbounded
    } else {
        if max_wire_peak > config.service.max_inflight_wire_body_bytes_per_quota_key {
            return Err(V3CompileError::at(
                "service.max_inflight_wire_body_bytes_per_quota_key",
                "must hold the largest pass-reachable mandatory body working set",
            ));
        }
        let required = max_wire_peak
            .checked_mul(config.service.min_wire_body_concurrency)
            .ok_or_else(|| {
                V3CompileError::at("service", "wire-body capacity arithmetic overflow")
            })?;
        if required > config.service.max_inflight_wire_body_bytes {
            return Err(V3CompileError::at(
                "service.min_wire_body_concurrency",
                "the requested minimum concurrency does not fit the global wire-body pool",
            ));
        }
        Capacity::Finite(config.service.max_inflight_wire_body_bytes / max_wire_peak)
    };
    let wire_body_quota_key_full_peak_capacity = config
        .service
        .max_inflight_wire_body_bytes_per_quota_key
        .checked_div(max_wire_peak)
        .map_or(Capacity::Unbounded, Capacity::Finite);

    let transport = config
        .service
        .upgrade_relay_buffer_bytes
        .checked_mul(2)
        .ok_or_else(|| V3CompileError::at("service", "upgrade buffer arithmetic overflow"))?;
    let upgrade_allocation_bytes_by_rule = config
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
                    let profile = config
                        .redaction
                        .profiles
                        .get(name)
                        .expect("profile references validated before resource compilation");
                    let scratch_bytes = configured_profile_literal_scratch_bytes(
                        profile,
                        &format!("redaction.profiles.{name}"),
                    )?;
                    upgrade_wire_peak(
                        profile.max_message_bytes,
                        profile.allow_permessage_deflate,
                        scratch_bytes,
                    )
                })
                .transpose()?
                .unwrap_or(0);
            transport
                .checked_add(wire_working_set)
                .map(Some)
                .ok_or_else(|| V3CompileError::at("service", "upgrade buffer arithmetic overflow"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let per_stream = upgrade_allocation_bytes_by_rule
        .iter()
        .flatten()
        .copied()
        .max()
        .unwrap_or(0);
    let all_streams = per_stream
        .checked_mul(config.service.max_active_upgrades)
        .ok_or_else(|| V3CompileError::at("service", "upgrade aggregate arithmetic overflow"))?;
    if all_streams > config.service.max_upgrade_buffer_bytes {
        return Err(V3CompileError::at(
            "service.max_upgrade_buffer_bytes",
            "cannot hold the configured transport and maximum reachable reassembly buffers",
        ));
    }

    Ok(CompiledResourcePlan {
        http_wire_body_peak_bytes_by_cursor: cursor_peaks,
        max_reachable_http_wire_body_peak_bytes: max_wire_peak,
        wire_body_full_peak_capacity,
        wire_body_quota_key_full_peak_capacity,
        upgrade_allocation_bytes_by_rule,
        max_upgrade_allocation_per_stream: per_stream,
        max_upgrade_allocation_all_streams: all_streams,
    })
}

#[derive(Debug)]
struct HttpRuleAllocationSchedule {
    initial_peak: usize,
    retained_original_after_pass: Option<usize>,
    incoming_stages: Vec<IncomingBodyStage>,
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

#[derive(Debug)]
struct IncomingBodyStage {
    additional_bytes: usize,
}

fn compile_http_rule_schedule(
    config: &super::authoring::ConfigV3,
    rule: &PolicyRuleConfig,
) -> Result<HttpRuleAllocationSchedule, V3CompileError> {
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
            .expect("profile references validated before resource compilation")
    });
    let profile_scratch_bytes = rule
        .redaction_profile
        .as_ref()
        .zip(profile)
        .map(|(name, profile)| {
            configured_profile_literal_scratch_bytes(profile, &format!("redaction.profiles.{name}"))
        })
        .transpose()?;
    let effective_process_body_limits = process_body.map(|provider| {
        profile.map_or(
            (
                provider.max_request_body_bytes,
                provider.max_decoded_request_body_bytes,
            ),
            |profile| {
                (
                    provider.max_request_body_bytes.min(profile.max_body_bytes),
                    provider
                        .max_decoded_request_body_bytes
                        .min(profile.max_decoded_body_bytes),
                )
            },
        )
    });

    let mut initial_peak = 0usize;
    let mut incoming_stages = Vec::with_capacity(3);
    if let Some(provider) = process_body {
        let (encoded_limit, original_limit) = effective_process_body_limits
            .expect("process-body limits were derived with the process provider");
        initial_peak = initial_peak.max(decode_peak(encoded_limit, original_limit)?);
        let provider_stream_scratch = project_guarded_body_allocation(
            PROVIDER_STREAM_SCRATCH_BYTES,
            "policy.rules",
            "HTTP provider-stream plan arithmetic overflow",
        )?;
        initial_peak = initial_peak.max(guarded_body_stage_peak(
            [original_limit, PROVIDER_STREAM_SCRATCH_BYTES],
            "policy.rules",
            "HTTP provider-stream plan arithmetic overflow",
        )?);
        incoming_stages.push(IncomingBodyStage {
            additional_bytes: provider_stream_scratch,
        });
        if provider.allow_request_body_replacement {
            // The original remains live until a structurally accepted
            // replacement irrevocably wins. Only then may replacement decode
            // and redaction proceed without the original allocation.
            let response_framing = project_guarded_body_allocation(
                provider.max_stdout_line_bytes,
                "policy.rules",
                "HTTP provider-response framing arithmetic overflow",
            )?;
            initial_peak = initial_peak.max(guarded_body_stage_peak(
                [original_limit, provider.max_stdout_line_bytes],
                "policy.rules",
                "HTTP provider-response framing arithmetic overflow",
            )?);
            incoming_stages.push(IncomingBodyStage {
                additional_bytes: response_framing,
            });
            initial_peak = initial_peak.max(replacement_decode_peak(
                provider.max_stdout_line_bytes,
                original_limit,
            )?);
        }
    }
    if let Some(profile) = profile {
        let (encoded_limit, original_limit) = effective_process_body_limits
            .unwrap_or((profile.max_body_bytes, profile.max_decoded_body_bytes));
        if process_body.is_none() {
            initial_peak = initial_peak.max(decode_peak(encoded_limit, original_limit)?);
        }
        let redaction_additional = guarded_body_stage_peak(
            [
                profile_scratch_bytes.expect("redaction profile scratch was derived"),
                profile.max_decoded_body_bytes,
            ],
            "policy.rules",
            "HTTP redaction plan arithmetic overflow",
        )?;
        let has_text_expressions = profile.rules.iter().any(|rule| {
            !rule.expressions.is_empty() && !matches!(rule.payloads, RedactionPayloads::Binary)
        });
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
        let original_redaction_peak = checked_add(
            project_guarded_body_allocation(
                original_limit,
                "policy.rules",
                "HTTP redaction plan arithmetic overflow",
            )?,
            redaction_additional,
            "policy.rules",
            "HTTP redaction plan arithmetic overflow",
        )?
        .max(regex_peak);
        initial_peak = initial_peak.max(original_redaction_peak);
        // A prior delegate's retained body becomes the regex input. The
        // incoming stage therefore adds only matcher scratch and the output
        // buffer; the standalone peak above covers both regex buffers when
        // no prior body is retained.
        incoming_stages.push(IncomingBodyStage {
            additional_bytes: redaction_additional,
        });
        if process_body.is_some_and(|provider| provider.allow_request_body_replacement) {
            let replacement_limit = effective_process_body_limits
                .expect("replacement limits were derived with the process provider")
                .1;
            let replacement_redaction_peak = checked_add(
                project_guarded_body_allocation(
                    replacement_limit,
                    "policy.rules",
                    "HTTP replacement-redaction plan arithmetic overflow",
                )?,
                redaction_additional,
                "policy.rules",
                "HTTP replacement-redaction plan arithmetic overflow",
            )?
            .max(regex_peak);
            initial_peak = initial_peak.max(replacement_redaction_peak);
        }
    }

    Ok(HttpRuleAllocationSchedule {
        initial_peak,
        retained_original_after_pass: if matches!(rule.decision, RuleDecision::Delegate) {
            effective_process_body_limits
                .map(|(_, original_limit)| {
                    project_guarded_body_allocation(
                        original_limit,
                        "policy.rules",
                        "delegate-pass body retention arithmetic overflow",
                    )
                })
                .transpose()?
        } else {
            None
        },
        incoming_stages,
    })
}

fn replacement_decode_peak(
    max_stdout_line_bytes: usize,
    max_decoded_replacement_bytes: usize,
) -> Result<usize, V3CompileError> {
    guarded_body_stage_peak(
        [
            max_stdout_line_bytes,
            max_decoded_replacement_bytes,
            DECODER_SCRATCH_BYTES,
        ],
        "service",
        "provider replacement decode arithmetic overflow",
    )
}

fn decode_peak(encoded: usize, decoded: usize) -> Result<usize, V3CompileError> {
    guarded_body_stage_peak(
        [encoded, decoded, DECODER_SCRATCH_BYTES],
        "service",
        "mandatory body-plan arithmetic overflow",
    )
}

fn guarded_body_stage_peak<const N: usize>(
    payload_bytes: [usize; N],
    path: &str,
    message: &str,
) -> Result<usize, V3CompileError> {
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
) -> Result<usize, V3CompileError> {
    guarded_body_allocation_bytes(payload_bytes).ok_or_else(|| V3CompileError::at(path, message))
}

fn checked_add(
    left: usize,
    right: usize,
    path: &str,
    message: &str,
) -> Result<usize, V3CompileError> {
    left.checked_add(right)
        .ok_or_else(|| V3CompileError::at(path, message))
}

fn upgrade_wire_peak(
    max_message_bytes: usize,
    allow_permessage_deflate: bool,
    matcher_scratch_bytes: usize,
) -> Result<usize, V3CompileError> {
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
            DECODER_SCRATCH_BYTES,
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
    config: &super::authoring::ConfigV3,
    working_directory: &Path,
    compiled_urls_by_rule: Vec<Vec<CompiledUrlPattern>>,
    resource_plan: CompiledResourcePlan,
) -> Result<ReloadableProductPlan, V3CompileError> {
    Ok(ReloadableProductPlan {
        request_timeout: config.service.request_timeout.get(),
        max_content_decoding_expansion_ratio: config.service.max_content_decoding_expansion_ratio,
        egress: compile_egress_plan(&config.egress)?,
        policy: compile_policy_plan(&config.policy, compiled_urls_by_rule)?,
        authorization: compile_authorization_plan(&config.authorization, working_directory)?,
        credentials: compile_credentials_plan(&config.credentials)?,
        redaction: compile_redaction_plan(&config.redaction)?,
        observation: compile_observation_plan(&config.observation)?,
        safety: compile_safety_plan(&config.safety)?,
        resource_plan,
    })
}

fn compile_egress_plan(value: &EgressConfig) -> Result<EgressPlan, V3CompileError> {
    Ok(EgressPlan {
        route: match value.route {
            EgressRoute::Direct => CompiledEgressRoute::Direct,
            EgressRoute::ParentProxy => CompiledEgressRoute::ParentProxy,
        },
        origin_tls: compile_transport_tls_plan(&value.origin_tls),
        parent_proxy: value
            .parent_proxy
            .as_ref()
            .map(compile_parent_proxy_plan)
            .transpose()?,
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
) -> Result<ParentProxyPlan, V3CompileError> {
    let canonical = canonicalize_http_url(&value.url).map_err(|error| {
        V3CompileError::at("egress.parent_proxy.url", format!("invalid URL: {error}"))
    })?;
    Ok(ParentProxyPlan {
        kind: match value.kind {
            ParentProxyKind::AclProxy => CompiledParentProxyKind::AclProxy,
            ParentProxyKind::Generic => CompiledParentProxyKind::Generic,
        },
        url: canonical.url,
        host: canonical.host.clone(),
        port: canonical.port,
        tls: value.tls.as_ref().map(|tls| ParentProxyTlsPlan {
            trust: compile_tls_trust(tls.trust),
            ca_certificate: tls.ca_certificate.clone(),
            server_name: tls
                .server_name
                .clone()
                .unwrap_or_else(|| canonical.host.clone()),
        }),
    })
}

fn compile_policy_plan(
    value: &PolicyConfig,
    compiled_urls_by_rule: Vec<Vec<CompiledUrlPattern>>,
) -> Result<PolicyPlan, V3CompileError> {
    if compiled_urls_by_rule.len() != value.rules.len() {
        return Err(V3CompileError::at(
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
    })
}

fn compile_policy_rule_plan(
    value: &PolicyRuleConfig,
    urls: Vec<CompiledUrlPattern>,
    index: usize,
) -> Result<PolicyRulePlan, V3CompileError> {
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
                    V3CompileError::at(
                        format!("{prefix}.methods[{method_index}]"),
                        format!("invalid method after validation: {error}"),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        client_cidrs: compile_client_cidrs(&value.client_cidrs, &format!("{prefix}.client_cidrs"))?,
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

/// Policy peers canonicalize IPv4-mapped socket addresses to IPv4. Authored
/// CIDRs wholly inside the mapped `/96` follow the same representation. A
/// broader IPv6 CIDR containing mapped space is rejected because it mixes
/// canonical IPv4 peers with native IPv6 addresses under one authored range.
fn compile_client_cidrs(
    values: &[ipnet::IpNet],
    path: &str,
) -> Result<Vec<ipnet::IpNet>, V3CompileError> {
    let mapped_base = std::net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped();
    values
        .iter()
        .enumerate()
        .map(|(index, network)| match network {
            ipnet::IpNet::V4(network) => Ok(ipnet::IpNet::V4(*network)),
            ipnet::IpNet::V6(network) => {
                if network.prefix_len() < 96 && network.contains(&mapped_base) {
                    return Err(V3CompileError::at(
                        format!("{path}[{index}]"),
                        "IPv6 CIDR ambiguously mixes mapped IPv4 and native IPv6 addresses",
                    ));
                }
                let Some(mapped) = network.network().to_ipv4_mapped() else {
                    return Ok(ipnet::IpNet::V6(*network));
                };
                let prefix = network.prefix_len().checked_sub(96).ok_or_else(|| {
                    V3CompileError::at(
                        format!("{path}[{index}]"),
                        "invalid mapped IPv4 CIDR prefix",
                    )
                })?;
                let canonical = ipnet::Ipv4Net::new(mapped, prefix).map_err(|_| {
                    V3CompileError::at(format!("{path}[{index}]"), "invalid mapped IPv4 CIDR")
                })?;
                Ok(ipnet::IpNet::V4(canonical))
            }
        })
        .collect()
}

fn compile_header_predicates_plan(
    value: &super::authoring::HeaderPredicatesConfig,
    prefix: &str,
) -> Result<HeaderPredicatesPlan, V3CompileError> {
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
) -> Result<Vec<HeaderValuePredicatePlan>, V3CompileError> {
    values
        .iter()
        .map(|(name, values)| {
            Ok(HeaderValuePredicatePlan {
                name: compile_header_name(name, path)?,
                values: values
                    .iter()
                    .map(|value| {
                        HeaderValue::from_bytes(value.as_bytes()).map_err(|error| {
                            V3CompileError::at(
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
) -> Result<Vec<HeaderEffectPlan>, V3CompileError> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| compile_header_effect(value, &format!("{path}[{index}]")))
        .collect()
}

fn compile_header_effect(
    value: &HeaderEffectConfig,
    path: &str,
) -> Result<HeaderEffectPlan, V3CompileError> {
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
) -> Result<Vec<HeaderValue>, V3CompileError> {
    values
        .map(|value| {
            HeaderValue::from_bytes(value.as_bytes()).map_err(|error| {
                V3CompileError::at(
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
) -> Result<Vec<CredentialActionPlan>, V3CompileError> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            Ok(match value {
                CredentialActionConfig::Bearer(value) => CredentialActionPlan::Bearer {
                    credential: value.credential.clone(),
                },
                CredentialActionConfig::Basic(value) => CredentialActionPlan::Basic {
                    username: value.username.clone(),
                    password_credential: value.password_credential.clone(),
                },
                CredentialActionConfig::CustomHeader(value) => CredentialActionPlan::CustomHeader {
                    header: compile_header_name(&value.header, &format!("{path}[{index}].header"))?,
                    credential: value.credential.clone(),
                },
            })
        })
        .collect()
}

fn compile_authorization_plan(
    value: &AuthorizationConfig,
    working_directory: &Path,
) -> Result<AuthorizationPlan, V3CompileError> {
    let providers = value
        .providers
        .iter()
        .map(|(name, provider)| {
            compile_provider_plan(name, provider, working_directory)
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
                max_pending_operations: callback.max_pending_operations,
            }),
        providers,
    })
}

fn compile_provider_plan(
    name: &str,
    value: &AuthorizationProviderConfig,
    working_directory: &Path,
) -> Result<AuthorizationProviderPlan, V3CompileError> {
    let prefix = format!("authorization.providers.{name}");
    Ok(match value {
        AuthorizationProviderConfig::Webhook(value) => {
            AuthorizationProviderPlan::Webhook(WebhookProviderPlan {
                url: value.url.clone(),
                timeout: value.timeout.get(),
                on_failure: compile_provider_failure(value.on_failure),
                include_headers: compile_header_names(
                    &value.include_headers,
                    &format!("{prefix}.include_headers"),
                )?,
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
                include_headers: compile_header_names(
                    &value.include_headers,
                    &format!("{prefix}.include_headers"),
                )?,
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

fn compile_provider_outputs(
    values: &BTreeMap<String, super::authoring::ProviderOutputConfig>,
    path: &str,
) -> Result<BTreeMap<String, ProviderOutputPlan>, V3CompileError> {
    values
        .iter()
        .map(|(name, value)| {
            let output = match value {
                super::authoring::ProviderOutputConfig::Bearer(value) => {
                    ProviderOutputPlan::Bearer {
                        required: value.required,
                    }
                }
                super::authoring::ProviderOutputConfig::Basic(value) => ProviderOutputPlan::Basic {
                    username: value.username.clone(),
                    required: value.required,
                },
                super::authoring::ProviderOutputConfig::CustomHeader(value) => {
                    ProviderOutputPlan::CustomHeader {
                        header: compile_header_name(
                            &value.header,
                            &format!("{path}.{name}.header"),
                        )?,
                        required: value.required,
                    }
                }
            };
            Ok((name.clone(), output))
        })
        .collect()
}

fn compile_credentials_plan(value: &CredentialsConfig) -> Result<CredentialsPlan, V3CompileError> {
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
        .collect::<Result<BTreeMap<_, _>, V3CompileError>>()?;
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
    Ok(CredentialsPlan {
        allowed_custom_headers: compile_header_names(
            &value.allowed_custom_headers,
            "credentials.allowed_custom_headers",
        )?,
        inbound,
        sources,
    })
}

enum AuthoredLiteralProjectionError {
    Scratch,
    Matcher,
}

fn authored_literal_resident_bytes(
    value: &super::authoring::RedactionProfileConfig,
    class: CompiledRedactionPayloads,
    build_budget: usize,
) -> Result<usize, AuthoredLiteralProjectionError> {
    let pattern_count = value
        .rules
        .iter()
        .filter(|rule| {
            matches!(
                (rule.payloads, class),
                (RedactionPayloads::Text, CompiledRedactionPayloads::Text)
                    | (RedactionPayloads::Binary, CompiledRedactionPayloads::Binary)
                    | (RedactionPayloads::Both, _)
            )
        })
        .map(|rule| rule.literals.len())
        .try_fold(0usize, usize::checked_add)
        .ok_or(AuthoredLiteralProjectionError::Matcher)?;
    let mut patterns = Vec::new();
    patterns
        .try_reserve_exact(pattern_count)
        .map_err(|_| AuthoredLiteralProjectionError::Matcher)?;
    for rule in &value.rules {
        let applies = matches!(
            (rule.payloads, class),
            (RedactionPayloads::Text, CompiledRedactionPayloads::Text)
                | (RedactionPayloads::Binary, CompiledRedactionPayloads::Binary)
                | (RedactionPayloads::Both, _)
        );
        if !applies {
            continue;
        }
        for literal in &rule.literals {
            patterns.push(literal.as_bytes());
        }
    }
    debug_assert_eq!(patterns.len(), pattern_count);
    let (pattern_reference_bytes, pattern_reference_construction_bytes) =
        redaction_literal_reference_bytes(patterns.capacity(), patterns.len())
            .ok_or(AuthoredLiteralProjectionError::Matcher)?;
    let mut patterns = patterns.into_boxed_slice();
    if std::mem::size_of_val(patterns.as_ref()) != pattern_reference_bytes {
        return Err(AuthoredLiteralProjectionError::Matcher);
    }
    let projection = redaction_literal_projection(
        &mut patterns,
        pattern_reference_bytes,
        pattern_reference_construction_bytes,
    );
    let projection = projection.ok_or(AuthoredLiteralProjectionError::Matcher)?;
    redaction_literal_scratch_bytes(projection.max_pattern_len)
        .ok_or(AuthoredLiteralProjectionError::Scratch)?;
    (projection.build_bytes <= build_budget && projection.resident_bytes <= build_budget)
        .then_some(projection.resident_bytes)
        .ok_or(AuthoredLiteralProjectionError::Matcher)
}

fn compile_redaction_plan(value: &RedactionConfig) -> Result<RedactionPlan, V3CompileError> {
    let mut snapshot_matcher_resident_bytes = 0usize;
    let profiles = value
        .profiles
        .iter()
        .map(|(name, value)| {
            let prefix = format!("redaction.profiles.{name}");
            let snapshot_remaining = MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_SNAPSHOT
                .checked_sub(snapshot_matcher_resident_bytes)
                .ok_or_else(|| {
                    V3CompileError::at(&prefix, "compiled matcher snapshot memory ceiling exceeded")
                })?;
            let text_literal_bytes = authored_literal_resident_bytes(
                value,
                CompiledRedactionPayloads::Text,
                MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_PROFILE.min(snapshot_remaining),
            )
            .map_err(|error| {
                let message = match error {
                    AuthoredLiteralProjectionError::Scratch => {
                        "text literal exceeds the matcher scratch horizon"
                    }
                    AuthoredLiteralProjectionError::Matcher => {
                        "bounded text literal matcher build ceiling exceeded"
                    }
                };
                V3CompileError::at(&prefix, message)
            })?;
            let binary_literal_budget = MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_PROFILE
                .checked_sub(text_literal_bytes)
                .map(|profile_remaining| {
                    profile_remaining.min(snapshot_remaining.saturating_sub(text_literal_bytes))
                })
                .ok_or_else(|| {
                    V3CompileError::at(&prefix, "compiled matcher profile memory ceiling exceeded")
                })?;
            let binary_literal_bytes = authored_literal_resident_bytes(
                value,
                CompiledRedactionPayloads::Binary,
                binary_literal_budget,
            )
            .map_err(|error| {
                let message = match error {
                    AuthoredLiteralProjectionError::Scratch => {
                        "binary literal exceeds the matcher scratch horizon"
                    }
                    AuthoredLiteralProjectionError::Matcher => {
                        "bounded binary literal matcher build ceiling exceeded"
                    }
                };
                V3CompileError::at(&prefix, message)
            })?;
            let literal_bytes = text_literal_bytes
                .checked_add(binary_literal_bytes)
                .ok_or_else(|| {
                    V3CompileError::at(&prefix, "compiled matcher size accounting overflow")
                })?;
            let (mut profile_matcher_resident_bytes, new_snapshot_bytes) =
                checked_redaction_matcher_resident_bytes(
                    0,
                    snapshot_matcher_resident_bytes,
                    literal_bytes,
                )
                .ok_or_else(|| {
                    V3CompileError::at(&prefix, "compiled matcher memory ceiling exceeded")
                })?;
            snapshot_matcher_resident_bytes = new_snapshot_bytes;
            let rules = value
                .rules
                .iter()
                .enumerate()
                .map(|(index, rule)| {
                    let path = format!("{prefix}.rules[{index}]");
                    Ok(RedactionRulePlan {
                        literals: rule
                            .literals
                            .iter()
                            .map(|literal| literal.as_bytes().to_vec())
                            .collect(),
                        literal_environment_variables: rule.literal_environment_variables.clone(),
                        expressions: rule
                            .expressions
                            .iter()
                            .enumerate()
                            .map(|(expression_index, expression)| {
                                let expression_path =
                                    format!("{path}.expressions[{expression_index}]");
                                let remaining_budget =
                                    remaining_redaction_matcher_resident_bytes(
                                        profile_matcher_resident_bytes,
                                        snapshot_matcher_resident_bytes,
                                    )
                                    .ok_or_else(|| {
                                        V3CompileError::at(
                                            &expression_path,
                                            "compiled matcher memory ceiling exceeded",
                                        )
                                    })?;
                                let matcher = build_redaction_regex(expression, remaining_budget)
                                    .map_err(|_| {
                                    V3CompileError::at(
                                        &expression_path,
                                        "invalid regular expression or unsupported by the bounded matcher",
                                    )
                                })?;
                                let bytes = redaction_regex_resident_bytes(&matcher)
                                    .ok_or_else(|| {
                                        V3CompileError::at(
                                            &expression_path,
                                            "bounded regular-expression size accounting overflow",
                                        )
                                    })?;
                                let (profile_bytes, snapshot_bytes) =
                                    checked_redaction_matcher_resident_bytes(
                                        profile_matcher_resident_bytes,
                                        snapshot_matcher_resident_bytes,
                                        bytes,
                                    )
                                    .ok_or_else(|| {
                                        V3CompileError::at(
                                            &expression_path,
                                            "compiled matcher memory ceiling exceeded",
                                        )
                                    })?;
                                profile_matcher_resident_bytes = profile_bytes;
                                snapshot_matcher_resident_bytes = snapshot_bytes;
                                Ok(expression.clone())
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                        payloads: match rule.payloads {
                            RedactionPayloads::Text => CompiledRedactionPayloads::Text,
                            RedactionPayloads::Binary => CompiledRedactionPayloads::Binary,
                            RedactionPayloads::Both => CompiledRedactionPayloads::Both,
                        },
                    })
                })
                .collect::<Result<Vec<_>, V3CompileError>>()?;
            Ok((
                name.clone(),
                RedactionProfilePlan {
                    replacement: value.replacement.as_bytes().to_vec(),
                    max_body_bytes: value.max_body_bytes,
                    max_decoded_body_bytes: value.max_decoded_body_bytes,
                    max_frame_bytes: value.max_frame_bytes,
                    max_message_bytes: value.max_message_bytes,
                    allow_permessage_deflate: value.allow_permessage_deflate,
                    max_environment_literal_sources: value.max_environment_literal_sources,
                    max_environment_literal_bytes: value.max_environment_literal_bytes,
                    max_environment_literal_total_bytes: value.max_environment_literal_total_bytes,
                    rules,
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>, V3CompileError>>()?;
    Ok(RedactionPlan { profiles })
}

fn compile_observation_plan(value: &ObservationConfig) -> Result<ObservationPlan, V3CompileError> {
    Ok(ObservationPlan {
        logging: ReloadableLoggingPlan {
            level: compile_log_level(&value.logging.level, "observation.logging.level")?,
            policy_decisions: PolicyDecisionLoggingPlan {
                allows: value.logging.policy_decisions.allows,
                denies: value.logging.policy_decisions.denies,
                allow_level: compile_log_level(
                    &value.logging.policy_decisions.allow_level,
                    "observation.logging.policy_decisions.allow_level",
                )?,
                deny_level: compile_log_level(
                    &value.logging.policy_decisions.deny_level,
                    "observation.logging.policy_decisions.deny_level",
                )?,
            },
        },
        capture: value.capture.as_ref().map(compile_capture_plan),
    })
}

fn compile_log_level(value: &str, path: &str) -> Result<CompiledLogLevel, V3CompileError> {
    match value {
        "trace" => Ok(CompiledLogLevel::Trace),
        "debug" => Ok(CompiledLogLevel::Debug),
        "info" => Ok(CompiledLogLevel::Info),
        "warn" => Ok(CompiledLogLevel::Warn),
        "error" => Ok(CompiledLogLevel::Error),
        _ => Err(V3CompileError::at(
            path,
            "invalid log level after validation",
        )),
    }
}

fn compile_capture_plan(value: &super::authoring::CaptureConfigV3) -> CapturePlan {
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
        directory: value.directory.clone(),
        filename: value.filename.clone(),
        max_body_bytes: value.max_body_bytes,
        max_inflight_body_bytes: value.max_inflight_body_bytes,
        max_files: value.max_files,
        max_total_bytes: value.max_total_bytes,
    }
}

fn compile_safety_plan(value: &SafetyConfig) -> Result<SafetyPlan, V3CompileError> {
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

fn compile_header_names(values: &[String], path: &str) -> Result<Vec<HeaderName>, V3CompileError> {
    values
        .iter()
        .map(|value| compile_header_name(value, path))
        .collect()
}

fn compile_header_name(value: &str, path: &str) -> Result<HeaderName, V3CompileError> {
    let normalized = normalize_header_name(value, path)?;
    HeaderName::from_bytes(normalized.as_bytes()).map_err(|error| {
        V3CompileError::at(
            path,
            format!("invalid header name after validation: {error}"),
        )
    })
}

fn compile_static_config(
    config: &super::authoring::ConfigV3,
    config_root: PathBuf,
) -> Result<StaticProductConfig, V3CompileError> {
    Ok(StaticProductConfig {
        schema_version: config.schema_version.number(),
        config_root,
        max_config_bytes: MAX_CONFIG_BYTES,
        service: StaticServiceConfig {
            shutdown_drain_timeout: config.service.shutdown_drain_timeout.bounded(),
            max_retiring_generations: config.service.max_retiring_generations,
            max_active_upgrades: config.service.max_active_upgrades,
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
        callback_public_url: config
            .authorization
            .callback
            .as_ref()
            .map(|callback| callback.public_url.clone()),
        logging: StaticLoggingConfig {
            directory: config.observation.logging.directory.clone(),
            max_bytes: config.observation.logging.max_bytes,
            max_files: config.observation.logging.max_files,
            console: config.observation.logging.console,
        },
    })
}

fn compile_control(value: &super::authoring::ControlConfig) -> StaticControlConfig {
    StaticControlConfig {
        bind: canonical_socket_addr(value.bind),
        base_path: value.base_path.clone(),
        request_header_timeout: value.request_header_timeout.get(),
        max_connections: value.max_connections,
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
                bind: canonical_socket_addr(listener.bind),
                http_versions: compile_http_versions(&listener.http_versions),
                connect: Some(compile_connect(&listener.connect)),
            }),
        transparent_http: value
            .transparent_http
            .as_ref()
            .map(|listener| StaticCleartextListener {
                bind: canonical_socket_addr(listener.bind),
                http_versions: compile_http_versions(&listener.http_versions),
                connect: None,
            }),
        explicit_https: value
            .explicit_https
            .as_ref()
            .map(|listener| StaticExplicitHttpsListener {
                bind: canonical_socket_addr(listener.bind),
                http_versions: compile_http_versions(&listener.http_versions),
                handshake_timeout: listener.handshake_timeout.get(),
                request_header_timeout: listener.request_header_timeout.get(),
                max_connections: listener.max_connections,
                max_concurrent_streams: listener.max_concurrent_streams,
                connect: compile_connect(&listener.connect),
                tls: compile_tls_identity(&listener.tls),
            }),
        transparent_https: value.transparent_https.as_ref().map(|listener| {
            StaticTransparentHttpsListener {
                bind: canonical_socket_addr(listener.bind),
                http_versions: compile_http_versions(&listener.http_versions),
                handshake_timeout: listener.handshake_timeout.get(),
                request_header_timeout: listener.request_header_timeout.get(),
                max_connections: listener.max_connections,
                max_concurrent_streams: listener.max_concurrent_streams,
            }
        }),
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

fn normalize_header_name(value: &str, path: &str) -> Result<String, V3CompileError> {
    if value.starts_with(':') {
        return Err(V3CompileError::at(
            path,
            "HTTP pseudo-headers are not authorable",
        ));
    }
    HeaderName::from_bytes(value.as_bytes())
        .map(|name| name.as_str().to_ascii_lowercase())
        .map_err(|error| V3CompileError::at(path, format!("invalid header name: {error}")))
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
) -> Result<(), V3CompileError> {
    if base_protected_headers().contains(name) || name == loop_header {
        return Err(V3CompileError::at(path, "header is reserved by the proxy"));
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

    const MINIMAL: &str = r#"
schema_version = 3

[listeners.explicit_http]
bind = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"
"#;

    fn compile(toml: &str) -> Result<CompiledProductConfig, V3CompileError> {
        let config: super::super::authoring::ConfigV3 =
            toml::from_str(toml).expect("test input should deserialize");
        compile_v3(config, Path::new("/etc/acl-proxy"))
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
        assert!(rendered.contains("unsupported by the bounded matcher"));
        assert!(!rendered.contains("secret-marker"));
    }

    #[test]
    fn compiled_matcher_accounting_aggregates_across_profiles() {
        let mut snapshot_bytes = 0usize;
        for _ in 0..4 {
            let (profile_bytes, next_snapshot_bytes) = checked_redaction_matcher_resident_bytes(
                0,
                snapshot_bytes,
                MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_PROFILE,
            )
            .expect("four full profile budgets fit the snapshot ceiling");
            assert_eq!(
                profile_bytes,
                MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_PROFILE
            );
            snapshot_bytes = next_snapshot_bytes;
        }
        assert_eq!(
            snapshot_bytes,
            MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_SNAPSHOT
        );
        assert!(checked_redaction_matcher_resident_bytes(0, snapshot_bytes, 1).is_none());
        assert!(checked_redaction_matcher_resident_bytes(usize::MAX, 0, 1).is_none());
    }

    #[test]
    fn regex_build_is_bounded_by_matcher_budget_remaining_after_prior_state() {
        let after_earlier_profiles = remaining_redaction_matcher_resident_bytes(
            0,
            MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_SNAPSHOT - 2,
        )
        .unwrap();
        assert_eq!(after_earlier_profiles, 2);
        assert!(build_redaction_regex("token-[0-9]+", after_earlier_profiles).is_err());

        let after_earlier_profile_matchers = remaining_redaction_matcher_resident_bytes(
            MAX_REDACTION_COMPILED_MATCHER_BYTES_PER_PROFILE - 2,
            0,
        )
        .unwrap();
        assert_eq!(after_earlier_profile_matchers, 2);
        assert!(build_redaction_regex("token-[0-9]+", after_earlier_profile_matchers).is_err());

        let matcher = build_redaction_regex("token-[0-9]+", 3 * 1024 * 1024)
            .expect("the absolute one-MiB direction cap remains usable");
        assert!(redaction_regex_resident_bytes(&matcher).unwrap() <= 2 * 1024 * 1024);

        assert!(build_redaction_regex(r"\w{100}", 96 * 1024).is_err());
        let large_expression = "a".repeat(32 * 1024);
        assert!(build_redaction_regex(&large_expression, 96 * 1024).is_err());
    }

    #[test]
    fn authored_literal_horizon_is_rejected_during_pure_compilation() {
        let literal = "x".repeat(
            MAX_REDACTION_MATCHER_SCRATCH_BYTES / std::mem::size_of::<RedactionLiteralInterval>()
                + 1,
        );
        let input = format!(
            r#"{MINIMAL}

[redaction.profiles.secrets]
rules = [{{ literals = ["{literal}"] }}]
"#
        );
        let error = compile(&input).expect_err("the literal horizon exceeds one MiB of scratch");
        let rendered = format!("{error:?} {error}");
        assert!(rendered.contains("redaction.profiles.secrets"));
        assert!(rendered.contains("configured literal horizon exceeds"));
        assert!(!rendered.contains(&literal));
    }

    #[test]
    fn sparse_literal_projection_is_exact_after_sorting_and_deduplication() {
        let abc = b"abc".as_slice();
        let abd = b"abd".as_slice();
        let mut patterns = Vec::new();
        patterns.try_reserve_exact(3).unwrap();
        patterns.extend([abd, abc, abc]);
        let (pattern_reference_bytes, pattern_reference_construction_bytes) =
            redaction_literal_reference_bytes(patterns.capacity(), patterns.len()).unwrap();
        assert_eq!(
            pattern_reference_construction_bytes,
            (patterns.capacity() + patterns.len()) * std::mem::size_of::<&[u8]>()
        );
        let mut patterns = patterns.into_boxed_slice();
        let projection = redaction_literal_projection(
            &mut patterns,
            pattern_reference_bytes,
            pattern_reference_construction_bytes,
        )
        .unwrap();

        assert_eq!(patterns[0], abc);
        assert_eq!(patterns[1], abc);
        assert_eq!(patterns[2], abd);
        assert_eq!(projection.state_count, 5);
        assert_eq!(projection.edge_count, 4);
        assert_eq!(projection.max_pattern_len, 3);
        assert_eq!(
            projection.resident_bytes,
            5 * std::mem::size_of::<RedactionLiteralNode>()
                + 4 * std::mem::size_of::<RedactionLiteralEdge>()
        );
        let shared_build_bytes = projection.resident_bytes
            + 5 * std::mem::size_of::<usize>()
            + 4 * std::mem::size_of::<usize>();
        assert_eq!(
            projection.reference_build_bytes,
            pattern_reference_construction_bytes
        );
        assert_eq!(
            projection.trie_build_bytes,
            shared_build_bytes + pattern_reference_bytes
        );
        assert_eq!(
            projection.failure_build_bytes,
            shared_build_bytes + 5 * std::mem::size_of::<usize>()
        );
        assert_eq!(
            projection.build_bytes,
            projection
                .reference_build_bytes
                .max(projection.trie_build_bytes)
                .max(projection.failure_build_bytes)
        );
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
        assert!(error
            .to_string()
            .contains("configured literal horizon exceeds"));
    }

    fn resource_config(service: &str, definitions: &str, rules: &str) -> String {
        format!(
            r#"
schema_version = 3

[service]
request_timeout = "1s"
{service}

[listeners.explicit_http]
bind = "127.0.0.1:8881"
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
        let config: super::super::authoring::ConfigV3 = toml::from_str(&input).unwrap();
        let schedule = compile_http_rule_schedule(&config, &config.policy.rules[0]).unwrap();

        assert_eq!(schedule.initial_peak, 3 * guarded(1));
        assert_eq!(
            schedule.incoming_stages[0].additional_bytes,
            guarded(64 * 1024)
        );
        assert_eq!(schedule.retained_original_after_pass, Some(guarded(1)));
    }

    #[test]
    fn replacement_projection_charges_each_chunk_and_node_at_boundary() {
        let line_bytes = 64 * 1024 + 1;
        let peak = replacement_decode_peak(line_bytes, 1).unwrap();

        assert_eq!(
            peak,
            guarded(line_bytes) + guarded(1) + guarded(DECODER_SCRATCH_BYTES)
        );
        assert_eq!(guarded(line_bytes), 2 * guarded(1));
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
        let config: super::super::authoring::ConfigV3 = toml::from_str(&input).unwrap();
        let first = compile_http_rule_schedule(&config, &config.policy.rules[0]).unwrap();
        let second = compile_http_rule_schedule(&config, &config.policy.rules[1]).unwrap();
        let retained = first.retained_original_after_pass.unwrap();
        let later_additional = second.max_incoming_additional_bytes();
        let compiled = compile(&input).unwrap();

        assert_eq!(retained, guarded(1));
        assert_eq!(later_additional, 2 * guarded(1));
        assert_eq!(
            compiled
                .reloadable_plan
                .resource_plan
                .http_wire_body_peak_bytes_by_cursor[0],
            retained + later_additional
        );
    }

    #[test]
    fn minimum_concurrency_uses_the_projected_allocation_peak() {
        let baseline = compile(&one_byte_body_provider_config("")).unwrap();
        let peak = baseline
            .reloadable_plan
            .resource_plan
            .max_reachable_http_wire_body_peak_bytes;
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
    }

    #[test]
    fn compiled_decode_peak_matches_live_chunk_charge() {
        use crate::safety::{WireBodyPool, WireBodyQuotaKey};

        let compiled = compile(&one_byte_body_provider_config("")).unwrap();
        let peak = compiled
            .reloadable_plan
            .resource_plan
            .max_reachable_http_wire_body_peak_bytes;
        let pool = WireBodyPool::new(peak, peak);
        let guard = pool.begin_for_test(
            peak,
            WireBodyQuotaKey::from_peer(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                |_| false,
            ),
        );
        let mut encoded = guard.buffer();
        let mut decoded = guard.buffer();
        let mut decoder_scratch = guard.buffer();
        encoded.try_extend_from_slice(&[1]).unwrap();
        decoded.try_extend_from_slice(&[2]).unwrap();
        decoder_scratch
            .try_extend_from_slice(&[0; 64 * 1024])
            .unwrap();

        assert_eq!(guard.live_bytes(), peak);
        assert_eq!(pool.global_charge(), peak);
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
        let log_level = match plan.observation.logging.level {
            CompiledLogLevel::Trace => "trace",
            CompiledLogLevel::Debug => "debug",
            CompiledLogLevel::Info => "info",
            CompiledLogLevel::Warn => "warn",
            CompiledLogLevel::Error => "error",
        };
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
                "authorization={}:{}:{}",
                plan.authorization.internal_context_headers.len(),
                plan.authorization.providers.len(),
                plan.authorization
                    .callback
                    .as_ref()
                    .map(|callback| format!(
                        "{:?}:{}",
                        callback.resume_token_ttl, callback.max_pending_operations
                    ))
                    .unwrap_or_default()
            ),
            format!(
                "credentials={}:{}:{}",
                plan.credentials.allowed_custom_headers.len(),
                plan.credentials.inbound.len(),
                plan.credentials.sources.len()
            ),
            format!("redaction={}", plan.redaction.profiles.len()),
            format!(
                "observation={log_level}:{}:{}:{}:{}",
                plan.observation.logging.policy_decisions.allows,
                plan.observation.logging.policy_decisions.denies,
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
                plan.resource_plan.max_reachable_http_wire_body_peak_bytes,
                plan.resource_plan.max_upgrade_allocation_all_streams
            ),
        ]
    }

    #[test]
    fn minimal_config_compiles_without_runtime_side_effects() {
        let compiled = compile(MINIMAL).expect("minimal v3 config should compile");
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
        assert!(matches!(
            log_level_changed.reloadable_plan.observation.logging.level,
            CompiledLogLevel::Debug
        ));
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
max_connections = 128
max_request_body_bytes = 65536

[authorization]
internal_context_headers = []

[authorization.callback]
public_url = "http://127.0.0.1:8898/_acl-proxy/external-auth/callback"
resume_token_ttl = "5m"
max_pending_operations = 32

[listeners.explicit_http]
bind = "127.0.0.1:8881"
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

[observation.logging.policy_decisions]
allows = false
denies = true
allow_level = "info"
deny_level = "warn"

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
            ("upgrade relay", baseline.replace("upgrade_relay_buffer_bytes = 65536", "upgrade_relay_buffer_bytes = 65537")),
            ("upgrade aggregate", baseline.replace("max_upgrade_buffer_bytes = 2147483648", "max_upgrade_buffer_bytes = 2147483649")),
            ("upgrade lifetime", baseline.replace("max_upgrade_lifetime = \"8h\"", "max_upgrade_lifetime = \"9h\"")),
            ("wire global pool", baseline.replace("max_inflight_wire_body_bytes = 8589934592", "max_inflight_wire_body_bytes = 8589934593")),
            ("wire quota pool", baseline.replace("max_inflight_wire_body_bytes_per_quota_key = 1073741824", "max_inflight_wire_body_bytes_per_quota_key = 1073741825")),
            ("wire concurrency", baseline.replace("min_wire_body_concurrency = 64", "min_wire_body_concurrency = 63")),
            ("control tuple", baseline.replace("8898", "8897")),
            ("control route", baseline.replace("/_acl-proxy", "/_control")),
            ("control timeout", baseline.replace("request_header_timeout = \"10s\"", "request_header_timeout = \"11s\"")),
            ("control connections", baseline.replace("max_connections = 128", "max_connections = 129")),
            ("control body limit", baseline.replace("max_request_body_bytes = 65536", "max_request_body_bytes = 65537")),
            ("control identity", baseline.replace(
                "[authorization]",
                "[control.tls]\ncertificate_chain = \"control.pem\"\nprivate_key = \"control-key.pem\"\n\n[authorization]",
            )),
            ("listener tuple", baseline.replace("127.0.0.1:8881", "127.0.0.1:8882")),
            ("listener topology", format!(
                "{baseline}\n[listeners.transparent_http]\nbind = \"127.0.0.1:8882\"\nhttp_versions = [\"http1\"]\n"
            )),
            ("MITM ownership", format!(
                "{baseline}\n[listeners.transparent_https]\nbind = \"127.0.0.1:8883\"\nhttp_versions = [\"http1\"]\n\n[mitm]\nmode = \"generated\"\ndirectory = \"mitm\"\n"
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
            ("logging level", baseline.replace("level = \"info\"", "level = \"debug\"")),
            ("decision logging", baseline.replace("allows = false", "allows = true")),
            ("loop header", baseline.replace("x-acl-proxy-request-id", "x-acl-proxy-next-id")),
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
                "{baseline}\n[redaction.profiles.audit]\nrules = [{{ literals = [\"marker\"] }}]\n\n[observation.capture]\nevents = [\"request.denied\"]\nredaction_profile = \"audit\"\ndirectory = \"captures\"\n"
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
    fn unresolved_secret_and_source_locators_are_redacted_from_debug() {
        const ENV_LOCATOR: &str = "CREDENTIAL_ENV_LOCATOR_7B31";
        const FILE_LOCATOR: &str = "credential-file-locator-4d92";
        const PROVIDER_VALUE: &str = "provider-environment-value-86ac";
        const REDACTION_LITERAL: &str = "redaction-authored-literal-153e";
        const REDACTION_SOURCE: &str = "REDACTION_ENV_SOURCE_24F8";

        let input = MINIMAL.replace(
            "[policy]",
            &format!(
                r#"[authorization.providers.local]
kind = "process"
command = "/bin/true"
environment = {{ PROVIDER_MARKER = "{PROVIDER_VALUE}" }}

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
        ] {
            assert!(!candidate_debug.contains(marker), "{candidate_debug}");
            assert!(!plan_debug.contains(marker), "{plan_debug}");
        }
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
    fn centralized_protected_headers_cover_proxy_authenticate() {
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
            ])
        );
        let input = MINIMAL.replace(
            "[policy]\ndefault = \"deny\"",
            r#"[policy]
default = "deny"

[[policy.rules]]
id = "challenge"
decision = "allow"
methods = ["GET"]

[[policy.rules.response_headers]]
operation = "set"
when = "always"
name = "proxy-authenticate"
value = "Basic realm=test""#,
        );
        let error = compile(&input).expect_err("proxy-authenticate must be protected");
        assert!(error.to_string().contains("protected"));
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
            toml::from_str::<super::super::authoring::ConfigV3>(&hostname).is_err(),
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
        assert!(error.to_string().contains("credential-bearing"));
    }

    #[test]
    fn sanitized_production_roles_compile_as_strict_v3() {
        for (name, fixture) in [
            (
                "host",
                include_str!("../../tests/fixtures/production/host-proxy.toml"),
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
            assert!(
                compiled
                    .reloadable_plan
                    .resource_plan
                    .max_reachable_http_wire_body_peak_bytes
                    <= 128 * MIB,
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
        let redaction_peak = 2 * guarded(8 * MIB) + guarded(DECODER_SCRATCH_BYTES);
        assert_eq!(plan.http_wire_body_peak_bytes_by_cursor[0], redaction_peak);
        assert_eq!(plan.http_wire_body_peak_bytes_by_cursor[1], redaction_peak);
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
        let scratch = redaction_literal_scratch_bytes("terminal-test-literal".len()).unwrap();
        assert_eq!(
            compiled
                .reloadable_plan
                .resource_plan
                .http_wire_body_peak_bytes_by_cursor,
            vec![
                guarded(16 * MIB) + guarded(8 * MIB) + guarded(scratch),
                2 * guarded(8 * MIB) + guarded(scratch),
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
        let scratch = redaction_literal_scratch_bytes("terminal-test-literal".len()).unwrap();
        assert_eq!(
            compiled
                .reloadable_plan
                .resource_plan
                .http_wire_body_peak_bytes_by_cursor,
            vec![
                guarded(16 * MIB) + guarded(8 * MIB) + guarded(scratch),
                2 * guarded(8 * MIB) + guarded(scratch),
                2 * guarded(8 * MIB) + guarded(scratch),
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
        assert_eq!(
            compiled
                .reloadable_plan
                .resource_plan
                .max_reachable_http_wire_body_peak_bytes,
            2 * guarded(16 * MIB) + guarded(DECODER_SCRATCH_BYTES)
        );
    }

    #[test]
    fn stricter_profile_limits_every_combined_provider_body_stage() {
        let peak = 3 * guarded(1);
        let input = resource_config(
            &format!(
                "max_inflight_wire_body_bytes = {}\nmax_inflight_wire_body_bytes_per_quota_key = {peak}\nmin_wire_body_concurrency = 5",
                5 * peak
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

        assert_eq!(resources.max_reachable_http_wire_body_peak_bytes, peak);
        assert_eq!(resources.http_wire_body_peak_bytes_by_cursor, [peak, 0]);
        assert_eq!(resources.wire_body_full_peak_capacity, Capacity::Finite(5));
        assert_eq!(
            resources.wire_body_quota_key_full_peak_capacity,
            Capacity::Finite(1)
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

        assert_eq!(
            compiled
                .reloadable_plan
                .resource_plan
                .http_wire_body_peak_bytes_by_cursor,
            vec![2 * guarded(8 * MIB), 2 * guarded(8 * MIB), 0]
        );
    }

    #[test]
    fn upgrade_rules_publish_exact_transport_and_wire_shares() {
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
"#,
        );
        let compiled = compile(&input).unwrap();
        let plan = &compiled.reloadable_plan.resource_plan;
        let transport = 2 * 64 * 1024;
        let plain_scratch = redaction_literal_scratch_bytes("plain-test-literal".len()).unwrap();
        let deflate_scratch =
            redaction_literal_scratch_bytes("deflate-test-literal".len()).unwrap();
        assert_eq!(
            plan.upgrade_allocation_bytes_by_rule,
            vec![
                Some(transport),
                Some(transport + 3 * MIB + plain_scratch),
                Some(transport + 4 * MIB + deflate_scratch + DECODER_SCRATCH_BYTES),
            ]
        );
        assert_eq!(
            plan.max_upgrade_allocation_per_stream,
            transport + 4 * MIB + deflate_scratch + DECODER_SCRATCH_BYTES
        );
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
        let fixture = include_str!("../../tests/fixtures/production/host-proxy.toml");
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
header = "x-not-allowed"
"#
        );
        let error = compile(&input).expect_err("unused provider outputs remain configured input");
        assert!(error.to_string().contains("allowed_custom_headers"));
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
credential = "token"

[[policy.rules.credential_actions]]
kind = "basic"
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

[authorization.providers.auth.outputs.second]
kind = "basic"
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
header = "X-Api-Key"
credential = "token"

[[policy.rules.credential_actions]]
kind = "custom_header"
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
        let snapshot =
            crate::policy::CompiledPolicySnapshot::from_plan(compiled.reloadable_plan.policy);
        let url = canonicalize_http_url("https://example.com/").unwrap();
        for peer in ["192.0.2.44", "::ffff:192.0.2.44"] {
            let decision = snapshot.evaluate(
                &url,
                peer.parse().unwrap(),
                &Method::GET,
                &http::HeaderMap::new(),
                |_| false,
            );
            assert_eq!(decision.outcome, crate::policy::PolicyOutcome::Allow);
        }
        let outside = snapshot.evaluate(
            &url,
            "198.51.100.44".parse().unwrap(),
            &Method::GET,
            &http::HeaderMap::new(),
            |_| false,
        );
        assert_eq!(outside.outcome, crate::policy::PolicyOutcome::Deny);
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
        let snapshot =
            crate::policy::CompiledPolicySnapshot::from_plan(compiled.reloadable_plan.policy);
        let url = canonicalize_http_url("https://example.com/").unwrap();
        for peer in ["192.0.2.44", "::ffff:192.0.2.44"] {
            let decision = snapshot.evaluate(
                &url,
                peer.parse().unwrap(),
                &Method::GET,
                &http::HeaderMap::new(),
                |_| false,
            );
            assert_eq!(decision.outcome, crate::policy::PolicyOutcome::Deny);
            assert_eq!(decision.matched.as_ref().unwrap().id(), "mapped-deny");
        }
        let outside = snapshot.evaluate(
            &url,
            "198.51.100.44".parse().unwrap(),
            &Method::GET,
            &http::HeaderMap::new(),
            |_| false,
        );
        assert_eq!(outside.outcome, crate::policy::PolicyOutcome::Allow);
        assert!(outside.matched.is_none());
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
