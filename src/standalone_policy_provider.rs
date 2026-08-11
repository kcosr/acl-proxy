use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_ENCODING, CONTENT_TYPE};
use http::StatusCode;
use http_access_policy_acl::{
    EvaluationInput, MatchedEffects, PolicyEvaluation, ProviderDisposition,
};
use http_access_runtime::{
    BodyBounds, BodyBudget, BodyBudgetActivation, BoxFuture, Clock, DecisionProvider,
    ForwardingCancellation, ForwardingNetworkGuard, ForwardingTargetPreflight,
    PreparedForwardingTarget, PreparedStandaloneRequest, ProviderOutcome, RequestPipelineError,
    ResolvedForwardingTarget, RuntimeBody, RuntimeRequest, RuntimeResponse, StandaloneDispatch,
    StandaloneExchange, StandaloneIngress, StandaloneIngressBody, StandaloneRequestFactory,
    StandaloneTerminal,
};
use http_access_types::{
    BodyFraming, BodyObservation, BodyObservationState, BodyRepresentation, DecisionAuditFacts,
    DecisionAuditFactsInput, DecisionAuditSource, DecisionDisposition, DecisionProvenance,
    DecisionReason, DecisionReasonCategory, EffectivePolicy, HeaderName as NeutralHeaderName,
    HttpMethod, HttpVersion, PolicyHeaderFacts, RequestBinding, StableId, TrailerPolicy,
};
use tokio::time::Instant;

use crate::activation::assets::ProductIngressAssets;
use crate::authorization::protocol::{
    GuardedProviderBody, IncludedHeader, ProviderBodyReplacementDecodeError, ProviderRequest,
    ProviderRequestHeaders,
};
use crate::authorization::AuthorizationDecision;
use crate::capture::CaptureDecision;
use crate::config::compiler::{
    CompiledDecisionLogLevel, CompiledProviderFailureMode, HttpBodyReadPlan,
};
use crate::credential_resolver::ProductCredentialPreparation;
use crate::credentials::InboundCredentials;
use crate::http_body::{read_mandatory_runtime_request_body, HttpBodyReadError};
use crate::observation::{
    DecisionSubmissionTarget, PendingDecisionSubmission, ProductObservationRuntime,
};
use crate::policy::{HttpWireBodyPlanIndex, ProductRuleEffectsRef};
use crate::proxy::observation_adapter::{
    DeniedCaptureBody, HttpCaptureContext, TerminalRequestBodyProvenance,
};
use crate::proxy::private_fields::{
    partition_standalone_private_fields, rebuild_standalone_facts, IngressPartitionPolicy,
    PartitionedIngressHeaders, ProductPartitionError,
};
use crate::runtime::{
    AuthorizationInvocationMode, ForwardingGenerationServices, GenerationLease,
    GenerationRetention, ProviderIndex, Runtime,
};
use crate::safety::{GuardedBody, WireBodyPool, WireBodyQuotaKey};
use crate::standalone_provider_result::{
    adapt_local_allow, adapt_provider_allow, StandaloneAllowMode, StandaloneProviderAllowError,
    StandaloneRequestSidecar,
};
use http_access_types::HttpProtocol;

pub(crate) struct TokioRuntimeClock {
    epoch: Instant,
    unix_epoch_millis: u64,
}

/// Reusable product owner for neutral standalone request preparation.
pub(crate) struct ProductStandaloneRequestFactory {
    runtime: Arc<Runtime>,
    observation: Arc<ProductObservationRuntime>,
    assets: Arc<ProductIngressAssets>,
    wire_body_pool: Arc<WireBodyPool>,
}

impl ProductStandaloneRequestFactory {
    pub(crate) fn new(
        runtime: Arc<Runtime>,
        observation: Arc<ProductObservationRuntime>,
        assets: Arc<ProductIngressAssets>,
        wire_body_pool: Arc<WireBodyPool>,
    ) -> Arc<Self> {
        Arc::new(Self {
            runtime,
            observation,
            assets,
            wire_body_pool,
        })
    }
}

impl StandaloneRequestFactory for ProductStandaloneRequestFactory {
    fn prepare(
        &self,
        ingress: StandaloneIngress,
    ) -> BoxFuture<'_, Result<PreparedStandaloneRequest, http_access_runtime::RuntimeError>> {
        Box::pin(async move {
            let started_at = Instant::now();
            let listener_transport = ingress.listener_transport();
            let (
                facts,
                projection,
                listener_connect_denied,
                identity,
                execution_context,
                body,
                private_fields,
            ) = ingress.into_parts();
            let client = projection.client();
            let request_binding_peer_ip =
                projection.checked_request_binding_peer_ip(identity.as_ref())?;
            let policy_peer_ip = projection.policy_peer_ip();
            let quota_key = WireBodyQuotaKey::from_subject(projection.wire_body_quota_subject());
            let lease = self
                .runtime
                .lease()
                .await
                .ok_or(http_access_runtime::RuntimeError::ServiceFailure)?;
            let request_id = request_id();
            tracing::debug!(
                target: "acl_proxy::traffic",
                request_id,
                listener_transport = match listener_transport {
                    http_access_runtime::ListenerTransport::Tcp => "tcp",
                    http_access_runtime::ListenerTransport::AccessFlow => "access_flow",
                },
                ingress_mode = ?facts.ingress_mode(),
                "proxy request admitted"
            );
            let (visible_fields, mut partitioned) = partition_standalone_private_fields(
                &IngressPartitionPolicy::from_lease(&lease),
                private_fields,
            )
            .map_err(|_| http_access_runtime::RuntimeError::InvalidInput)?;
            let execution_context = resolve_ingress_execution_context(
                listener_transport,
                identity.as_ref(),
                execution_context,
                lease.authorization().legacy_execution_context_header(),
                &mut partitioned.internal_context,
            )?;
            let facts =
                rebuild_standalone_facts(facts, visible_fields).map_err(|error| match error {
                    ProductPartitionError::EmptyPathSegment => {
                        http_access_runtime::RuntimeError::RequestRejected
                    }
                    _ => http_access_runtime::RuntimeError::InvalidInput,
                })?;
            let ingress_protocol = ingress_protocol(facts.version());
            let preflight_target = self
                .assets
                .forwarding_network()
                .preflight(
                    facts.url(),
                    ingress_protocol,
                    lease.standalone().origin_protocol(facts.version()),
                    lease.standalone().route(),
                )
                .ok();
            let clock = TokioRuntimeClock::new(started_at);
            let capture = HttpCaptureContext::from_checked_standalone(
                Arc::clone(&self.observation),
                lease.observation().capture_epoch().clone(),
                lease.standalone().sensitive_header_policy().clone(),
                request_id.clone(),
                client,
                &facts,
                lease.max_content_decoding_expansion_ratio(),
            )
            .map_err(|_| http_access_runtime::RuntimeError::InvalidInput)?;
            let input = StandaloneProviderInput {
                request_id,
                facts,
                client,
                request_binding_peer_ip,
                policy_peer_ip,
                quota_key,
                body,
                partitioned,
                started_at,
                preflight_target,
                network: Arc::clone(self.assets.forwarding_network()),
                cancellation: ProductForwardingCancellation::new(),
                clock,
                listener_denied: listener_connect_denied,
                identity,
                execution_context,
                decision_target: Arc::clone(&self.observation).into(),
                capture,
            };
            let (context, request) =
                StandalonePolicyProvider::prepare(lease, Arc::clone(&self.wire_body_pool), input)
                    .map_err(|_| http_access_runtime::RuntimeError::InvalidInput)?;
            Ok(PreparedStandaloneRequest::new(request, context))
        })
    }
}

fn resolve_ingress_execution_context(
    listener_transport: http_access_runtime::ListenerTransport,
    identity: &access_identity::IdentityContext,
    access_flow_context: Option<access_execution_context::ExecutionContext>,
    legacy_header: Option<&HeaderName>,
    internal_context: &mut HeaderMap,
) -> Result<Option<access_execution_context::ExecutionContext>, http_access_runtime::RuntimeError> {
    let Some(legacy_header) = legacy_header else {
        return Ok(access_flow_context);
    };
    match listener_transport {
        http_access_runtime::ListenerTransport::AccessFlow => {
            internal_context.remove(legacy_header);
            Ok(access_flow_context)
        }
        http_access_runtime::ListenerTransport::Tcp => {
            if access_flow_context.is_some() {
                return Err(http_access_runtime::RuntimeError::InvalidInput);
            }
            let mut values = internal_context.get_all(legacy_header).iter();
            let Some(value) = values.next() else {
                return Ok(None);
            };
            if values.next().is_some()
                || !matches!(identity, access_identity::IdentityContext::Authenticated(_))
            {
                return Err(http_access_runtime::RuntimeError::RequestRejected);
            }
            let value = value
                .to_str()
                .map_err(|_| http_access_runtime::RuntimeError::RequestRejected)?;
            access_execution_context::ExecutionContext::new(value.to_owned())
                .map(Some)
                .map_err(|_| http_access_runtime::RuntimeError::RequestRejected)
        }
    }
}

impl TokioRuntimeClock {
    pub(crate) fn new(epoch: Instant) -> Arc<Self> {
        let now = Instant::now();
        let elapsed_millis = now
            .checked_duration_since(epoch)
            .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
            .unwrap_or(0);
        Arc::new(Self {
            epoch,
            unix_epoch_millis: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX)
                .saturating_sub(elapsed_millis),
        })
    }

    fn deadline_millis(&self, deadline: Instant) -> Option<u64> {
        let elapsed = deadline.checked_duration_since(self.epoch)?;
        let whole = u64::try_from(elapsed.as_millis()).ok()?;
        let rounded = u64::from(elapsed.subsec_nanos() % 1_000_000 != 0);
        whole.checked_add(rounded)
    }

    fn monotonic_duration_millis(elapsed: Duration) -> Option<u64> {
        u64::try_from(elapsed.as_millis()).ok()
    }
}

impl Clock for TokioRuntimeClock {
    fn monotonic_millis(&self) -> u64 {
        Self::monotonic_duration_millis(self.epoch.elapsed()).unwrap_or(u64::MAX)
    }

    fn unix_millis(&self) -> u64 {
        self.unix_epoch_millis
            .saturating_add(self.monotonic_millis())
    }

    fn sleep_until(&self, deadline_millis: u64) -> BoxFuture<'static, ()> {
        let deadline = self.epoch + Duration::from_millis(deadline_millis);
        Box::pin(tokio::time::sleep_until(deadline))
    }
}

struct StandaloneProviderInput {
    pub(crate) request_id: String,
    pub(crate) facts: http_access_types::InterceptedRequestFacts,
    pub(crate) client: SocketAddr,
    pub(crate) request_binding_peer_ip: IpAddr,
    pub(crate) policy_peer_ip: Option<IpAddr>,
    pub(crate) quota_key: WireBodyQuotaKey,
    pub(crate) body: StandaloneIngressBody,
    pub(crate) partitioned: PartitionedIngressHeaders,
    pub(crate) started_at: Instant,
    pub(crate) preflight_target: Option<ForwardingTargetPreflight>,
    pub(crate) network: Arc<ForwardingNetworkGuard>,
    pub(crate) cancellation: ProductForwardingCancellation,
    pub(crate) clock: Arc<TokioRuntimeClock>,
    pub(crate) listener_denied: bool,
    pub(crate) identity: Arc<access_identity::IdentityContext>,
    pub(crate) execution_context: Option<access_execution_context::ExecutionContext>,
    pub(crate) decision_target: DecisionSubmissionTarget,
    pub(crate) capture: HttpCaptureContext,
}

pub(crate) struct StandalonePolicyProvider {
    decision: Mutex<Option<PreparedDecision>>,
    dispatch: Mutex<Option<PreparedDispatch>>,
    responses: Mutex<PreparedResponses>,
    response_observation: Mutex<Option<StandaloneResponseObservation>>,
    decision_source: Mutex<Option<DecisionAuditSource>>,
    response_decision: Mutex<Option<PendingDecisionSubmission>>,
    audit: DecisionAuditContext,
    capture: HttpCaptureContext,
}

pub(crate) struct StandaloneResponseObservation {
    pub(crate) headers: HeaderMap,
    pub(crate) body: Option<StandaloneDeniedBody>,
    pub(crate) body_provenance: StandaloneResponseBodyProvenance,
    pub(crate) close_connection: bool,
}

pub(crate) struct StandaloneDeniedBody {
    pub(crate) content_type: Option<String>,
    pub(crate) decoded: GuardedBody,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StandaloneResponseBodyProvenance {
    Unconsumed,
    CompleteOriginal,
    CompleteWireRedacted,
    ProviderReplacement { size: usize },
}

struct PreparedDecision {
    terminal: Option<PreparedTerminalState>,
    initial_binding: RequestBinding,
    evaluation: PolicyEvaluation<ProductRuleEffectsRef>,
    body_read_plan: HttpBodyReadPlan,
    wire_body_plan: HttpWireBodyPlanIndex,
    request_id: String,
    headers: HeaderMap,
    inbound: InboundCredentials,
    internal_context: HeaderMap,
    request_binding_peer_ip: IpAddr,
    policy_peer_ip: Option<IpAddr>,
    quota_key: WireBodyQuotaKey,
    body_budget: BodyBudget,
    body_budget_activation: BodyBudgetActivation,
    prepared_target: Option<PreparedForwardingTarget>,
    early_deny_source: Option<DecisionAuditSource>,
    ingress_body_complete: bool,
}

struct PreparedTerminalState {
    generation: GenerationLease,
    stable_wire_body_pool: Arc<WireBodyPool>,
    request_id: String,
    quota_key: WireBodyQuotaKey,
    deadline: Instant,
    network: Arc<ForwardingNetworkGuard>,
    cancellation: ProductForwardingCancellation,
    allow_mode: StandaloneAllowMode,
    private_fields: Option<HeaderMap>,
}

struct PreparedDispatch {
    services: ForwardingGenerationServices,
    request_id: String,
    quota_key: WireBodyQuotaKey,
    retention: GenerationRetention,
    resolved: ResolvedForwardingTarget,
    cancellation: ProductForwardingCancellation,
    sidecar: StandaloneRequestSidecar,
    credentials: Option<ProductCredentialPreparation>,
    private_fields: ProductPrivateFields,
    decision: PendingDecisionSubmission,
    capture: HttpCaptureContext,
    body_resources: ProductBodyResources,
    stable_wire_body_pool: Arc<WireBodyPool>,
}

pub(crate) struct ProductBodyResources {
    _replay: crate::safety::RuntimeReplayLease,
    _staging: crate::safety::RequestStagingAuthority,
}

pub(crate) struct ProductPrivateFields {
    _inbound: InboundCredentials,
    _internal_context: HeaderMap,
    _retained: HeaderMap,
}

impl ProductPrivateFields {
    pub(crate) fn validates_visible(&self, visible: &[http_access_types::HeaderField]) -> bool {
        visible.iter().all(|field| {
            let name = field.name().as_str();
            !self._inbound.reserves_header(name)
                && !self._internal_context.contains_key(name)
                && !self._retained.contains_key(name)
                && !http_access_runtime::is_prepartition_caller_credential_header(name)
        })
    }
}

pub(crate) struct StandaloneForwardDispatch {
    pub(crate) exchange: StandaloneExchange,
    pub(crate) services: ForwardingGenerationServices,
    pub(crate) request_id: String,
    pub(crate) quota_key: WireBodyQuotaKey,
    pub(crate) retention: GenerationRetention,
    pub(crate) resolved: ResolvedForwardingTarget,
    pub(crate) cancellation: ProductForwardingCancellation,
    pub(crate) sidecar: StandaloneRequestSidecar,
    pub(crate) credentials: Option<ProductCredentialPreparation>,
    pub(crate) private_fields: ProductPrivateFields,
    pub(crate) decision: PendingDecisionSubmission,
    pub(crate) capture: HttpCaptureContext,
    pub(crate) body_resources: ProductBodyResources,
    pub(crate) stable_wire_body_pool: Arc<WireBodyPool>,
}

pub(crate) struct ProductForwardingCancellation {
    capability: ForwardingCancellation,
}

impl ProductForwardingCancellation {
    pub(crate) fn new() -> Self {
        Self {
            capability: ForwardingCancellation::new(),
        }
    }

    pub(crate) fn capability(&self) -> ForwardingCancellation {
        self.capability.clone()
    }
}

impl Drop for ProductForwardingCancellation {
    fn drop(&mut self) {
        self.capability.cancel();
    }
}

struct DecisionAuditContext {
    target: DecisionSubmissionTarget,
    request_id: StableId,
    method: HttpMethod,
    url: http_access_types::CanonicalUrl,
    peer_ip: IpAddr,
    sensitive_header_presence: Vec<NeutralHeaderName>,
    allow_level: Option<CompiledDecisionLogLevel>,
    deny_level: Option<CompiledDecisionLogLevel>,
}

impl DecisionAuditContext {
    fn pending(
        &self,
        disposition: DecisionDisposition,
        source: DecisionAuditSource,
    ) -> PendingDecisionSubmission {
        let facts = DecisionAuditFacts::new(DecisionAuditFactsInput {
            request_id: &self.request_id,
            disposition,
            method: Some(&self.method),
            url: Some(&self.url),
            peer_ip: Some(self.peer_ip),
            source: &source,
            sensitive_header_presence: &self.sensitive_header_presence,
        });
        let level = match disposition {
            DecisionDisposition::Allow => self.allow_level,
            DecisionDisposition::Deny => self.deny_level,
        };
        match facts {
            Ok(facts) => PendingDecisionSubmission::new(self.target.clone(), level, facts),
            Err(_) => PendingDecisionSubmission::omitted(self.target.clone(), level),
        }
    }
}

struct PreparedResponses {
    policy: http_access_runtime::LocalResponsePolicy,
    context: LocalResponseContext,
    bounds: BodyBounds,
    clock: Arc<dyn Clock>,
    budget: Option<BodyBudget>,
}

const LOCAL_RESPONSE_BODY_BYTES: u64 = 64;
const CONNECT_DENIAL_RESPONSE_BODY: &str = "CONNECT denied\n";
const DENIAL_RESPONSE_BODY: &str = "request denied\n";
const TIMEOUT_RESPONSE_BODY: &str = "request timed out\n";
const BODY_DENIAL_RESPONSE_BODY: &str = "request body denied\n";
const UNAVAILABLE_RESPONSE_BODY: &str = "service unavailable\n";
const FAILURE_RESPONSE_BODY: &str = "request failed\n";

#[derive(Clone, Copy)]
enum LocalResponseBodyKind {
    ConnectDenial,
    Denial,
    Timeout,
    BodyDenial,
    Unavailable,
    Failure,
}

impl LocalResponseBodyKind {
    const fn text(self) -> &'static str {
        match self {
            Self::ConnectDenial => CONNECT_DENIAL_RESPONSE_BODY,
            Self::Denial => DENIAL_RESPONSE_BODY,
            Self::Timeout => TIMEOUT_RESPONSE_BODY,
            Self::BodyDenial => BODY_DENIAL_RESPONSE_BODY,
            Self::Unavailable => UNAVAILABLE_RESPONSE_BODY,
            Self::Failure => FAILURE_RESPONSE_BODY,
        }
    }
}

#[derive(Clone, Copy)]
enum LocalResponseContext {
    Standard,
    ListenerDeniedConnect,
}

const fn local_response_body_kind(
    status: u16,
    context: LocalResponseContext,
) -> LocalResponseBodyKind {
    match status {
        403 if matches!(context, LocalResponseContext::ListenerDeniedConnect) => {
            LocalResponseBodyKind::ConnectDenial
        }
        403 => LocalResponseBodyKind::Denial,
        504 => LocalResponseBodyKind::Timeout,
        400 | 408 | 413 | 415 => LocalResponseBodyKind::BodyDenial,
        503 => LocalResponseBodyKind::Unavailable,
        _ => LocalResponseBodyKind::Failure,
    }
}

fn local_response_capture_body(status: u16, context: LocalResponseContext) -> &'static str {
    local_response_body_kind(status, context).text()
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StandaloneProviderPrepareError {
    #[error("request identifier is invalid")]
    RequestId,
    #[error("request header facts are invalid")]
    HeaderFacts,
    #[error("request credential extraction failed")]
    Credential(#[from] crate::credentials::CredentialError),
    #[error("request facts are invalid")]
    Facts(#[from] ProductPartitionError),
    #[error("ingress transport does not match checked request facts")]
    Transport,
    #[error("request deadline cannot be represented")]
    Deadline,
    #[error("request body contract is invalid")]
    Body(#[from] http_access_runtime::RuntimeError),
    #[error("request policy evaluation failed")]
    Policy,
}

impl StandalonePolicyProvider {
    fn prepare(
        lease: GenerationLease,
        stable_wire_body_pool: Arc<WireBodyPool>,
        input: StandaloneProviderInput,
    ) -> Result<(Self, RuntimeRequest), StandaloneProviderPrepareError> {
        let StandaloneProviderInput {
            request_id,
            facts,
            client,
            request_binding_peer_ip,
            policy_peer_ip,
            quota_key,
            body: ingress_body,
            partitioned,
            started_at,
            preflight_target,
            network,
            cancellation,
            clock,
            listener_denied,
            identity,
            execution_context,
            decision_target,
            capture,
        } = input;
        let ingress_body_complete = ingress_body.is_end_stream();
        let audit_request_id = StableId::new(request_id.clone())
            .map_err(|_| StandaloneProviderPrepareError::RequestId)?;
        let audit_sensitive_header_presence = partitioned.audit_sensitive_presence;
        let sensitive_headers = lease.standalone().sensitive_headers().to_vec();
        let sensitive_header_presence = partitioned.sensitive_presence;
        let inbound = partitioned.inbound;
        let internal_context = partitioned.internal_context;
        let private_fields = partitioned.retained_private;
        let headers = crate::proxy::private_fields::product_headers(facts.headers())?;
        let audit_method = facts.method().clone();
        let audit_url = facts.url().clone();
        let allow_mode = if facts.method().as_str() == "CONNECT"
            && ingress_protocol(facts.version()) == HttpProtocol::Http1
            && facts.upgrade().is_none()
            && matches!(
                facts.ingress_mode(),
                http_access_types::IngressMode::ExplicitHttp
                    | http_access_types::IngressMode::ExplicitHttps
            ) {
            StandaloneAllowMode::OuterConnect
        } else {
            StandaloneAllowMode::OriginRequest
        };
        if listener_denied && allow_mode != StandaloneAllowMode::OuterConnect {
            return Err(StandaloneProviderPrepareError::Transport);
        }
        let header_facts = PolicyHeaderFacts::from_partitioned(
            facts.headers().to_vec(),
            sensitive_header_presence,
            sensitive_headers,
        )
        .map_err(|_| StandaloneProviderPrepareError::HeaderFacts)?;
        let evaluation_input = policy_evaluation_input(
            &facts,
            request_binding_peer_ip,
            policy_peer_ip,
            &header_facts,
            identity.as_ref(),
            execution_context.as_ref(),
        )
        .map_err(|_| StandaloneProviderPrepareError::Policy)?;
        let initial_binding = evaluation_input.request_binding();
        let evaluation = lease
            .standalone()
            .product_acl()
            .snapshot()
            .evaluate(&evaluation_input)
            .map_err(|_| StandaloneProviderPrepareError::Policy)?;
        let resource_cursor = lease
            .standalone()
            .product_acl()
            .resource_cursor(policy_provenance(&evaluation))
            .map_err(|_| StandaloneProviderPrepareError::Policy)?;
        let body_read_plan = lease
            .standalone()
            .product_acl()
            .resources()
            .body_read_plan(resource_cursor)
            .ok_or(StandaloneProviderPrepareError::Policy)?;
        let wire_body_plan = lease
            .standalone()
            .product_acl()
            .resources()
            .wire_body_plan(resource_cursor)
            .ok_or(StandaloneProviderPrepareError::Policy)?;
        let request_timeout = policy_rule_ordinal(policy_provenance(&evaluation))
            .and_then(|ordinal| lease.standalone().rules().get(ordinal))
            .and_then(crate::standalone::StandaloneRuleTemplate::request_timeout)
            .unwrap_or_else(|| lease.request_timeout());
        let deadline = started_at
            .checked_add(request_timeout)
            .ok_or(StandaloneProviderPrepareError::Deadline)?;
        let absolute_deadline_millis = clock
            .deadline_millis(deadline)
            .ok_or(StandaloneProviderPrepareError::Deadline)?;
        let mut early_deny_source = if listener_denied {
            Some(local_source(DecisionReasonCategory::Policy, 1))
        } else if lease.safety().contains_loop_marker(&headers) {
            Some(local_source(DecisionReasonCategory::Loop, 1))
        } else if let PolicyEvaluation::Deny { provenance } = &evaluation {
            Some(DecisionAuditSource::Policy(provenance.clone()))
        } else if upgrade_is_disallowed(lease.standalone(), facts.upgrade().is_some(), &evaluation)
        {
            Some(local_source(DecisionReasonCategory::InvalidPlan, 2))
        } else {
            None
        };

        let body_policy = if facts.upgrade().is_some() {
            lease.standalone().upgrade_request_body()
        } else {
            lease.standalone().ordinary_request_body()
        };
        let limits = body_policy.limits();
        let (trailer_count, trailer_bytes) = match body_policy.trailer_policy() {
            TrailerPolicy::Allow => (limits.trailer_count(), limits.trailer_bytes()),
            TrailerPolicy::Deny => (0, 0),
        };
        let bounds = BodyBounds::new(
            limits.wire_bytes(),
            limits.decoded_bytes(),
            limits.chunk_bytes(),
            trailer_count,
            trailer_bytes,
            lease.standalone().timeouts().body_idle_ms(),
        )?;
        let (body_budget, body_budget_activation) = BodyBudget::unarmed();
        let runtime_clock: Arc<dyn Clock> = clock.clone();
        let body = ingress_body.into_runtime_body(
            bounds,
            runtime_clock,
            body_budget.clone(),
            absolute_deadline_millis,
        )?;
        let request = RuntimeRequest::new(
            facts,
            request_binding_peer_ip,
            header_facts,
            BodyRepresentation::PreservedContentCoded,
            body,
            absolute_deadline_millis,
            identity,
            execution_context,
        )?;
        let prepared_target = preflight_target.and_then(|preflight_target| {
            preflight_target
                .bind_for_request(
                    &request,
                    lease
                        .standalone()
                        .origin_protocol(request.facts().version()),
                    lease.standalone().route(),
                    &network,
                )
                .ok()
        });
        if prepared_target.is_none() && early_deny_source.is_none() {
            early_deny_source = Some(local_source(DecisionReasonCategory::InvalidPlan, 3));
        }
        if request.binding()? != initial_binding
            || request.body_observation()?.state() != BodyObservationState::Unobserved
        {
            return Err(StandaloneProviderPrepareError::Body(
                http_access_runtime::RuntimeError::InvalidInput,
            ));
        }
        let local_response_context = if listener_denied {
            LocalResponseContext::ListenerDeniedConnect
        } else {
            LocalResponseContext::Standard
        };
        let responses = PreparedResponses::new(&request, clock.clone(), local_response_context)?;
        let audit = DecisionAuditContext {
            target: decision_target,
            request_id: audit_request_id,
            method: audit_method,
            url: audit_url,
            peer_ip: client.ip(),
            sensitive_header_presence: audit_sensitive_header_presence,
            allow_level: lease
                .observation()
                .decision_level(DecisionDisposition::Allow),
            deny_level: lease
                .observation()
                .decision_level(DecisionDisposition::Deny),
        };
        let prepared = PreparedDecision {
            terminal: Some(PreparedTerminalState {
                generation: lease,
                stable_wire_body_pool,
                request_id: request_id.clone(),
                quota_key: quota_key.clone(),
                deadline,
                network,
                cancellation,
                allow_mode,
                private_fields: Some(private_fields),
            }),
            initial_binding,
            evaluation,
            body_read_plan,
            wire_body_plan,
            request_id,
            headers,
            inbound,
            internal_context,
            request_binding_peer_ip,
            policy_peer_ip,
            quota_key,
            body_budget,
            body_budget_activation,
            prepared_target,
            early_deny_source,
            ingress_body_complete,
        };
        Ok((
            Self {
                decision: Mutex::new(Some(prepared)),
                dispatch: Mutex::new(None),
                responses: Mutex::new(responses),
                response_observation: Mutex::new(None),
                decision_source: Mutex::new(None),
                response_decision: Mutex::new(None),
                audit,
                capture,
            },
            request,
        ))
    }

    async fn decide_owned(
        &self,
        mut state: PreparedDecision,
        facts: &http_access_types::InterceptedRequestFacts,
        mut request: RuntimeRequest,
    ) -> Result<ProviderOutcome, u16> {
        let terminal = state.terminal.as_ref().ok_or(500_u16)?;
        let generation = &terminal.generation;
        let deadline = terminal.deadline;
        let allow_mode = terminal.allow_mode;
        if facts != request.facts()
            || request.binding().map_err(|_| 500_u16)? != state.initial_binding
            || request.body_observation().map_err(|_| 500_u16)?.state()
                != BodyObservationState::Unobserved
        {
            return Err(500);
        }
        let mut evaluation = state.evaluation;
        if let Some(source) = state.early_deny_source.take() {
            self.set_decision_source(source);
            let close_connection = early_deny_close_connection(state.ingress_body_complete);
            self.record_denial(
                &mut state.headers,
                None,
                StandaloneResponseBodyProvenance::Unconsumed,
                close_connection,
            );
            return Err(403);
        }
        if Instant::now() >= deadline {
            return Err(504);
        }

        let prepared_target = state.prepared_target.ok_or(500_u16)?;
        let resolution = terminal
            .network
            .resolve(prepared_target, &terminal.cancellation.capability)
            .await;
        if Instant::now() >= deadline {
            return Err(504);
        }
        let resolved = match resolution {
            Ok(resolved) => resolved,
            Err(http_access_runtime::ForwardingNetworkError::DeadlineExceeded) => return Err(504),
            Err(http_access_runtime::ForwardingNetworkError::Cancelled) => return Err(503),
            Err(_) => return Err(403),
        };

        let admission = generation
            .safety()
            .begin_http_body(state.wire_body_plan, state.quota_key)
            .map_err(|error| match error {
                crate::safety::HttpBodyAdmissionError::Resource(_) => 503_u16,
                crate::safety::HttpBodyAdmissionError::UnknownPlan => 500_u16,
            })?;
        if Instant::now() >= deadline {
            return Err(504);
        }
        let (guard, replay_lease, staging) = admission.into_parts();
        let replay_capacity = u64::try_from(replay_lease.capacity_bytes()).map_err(|_| 500_u16)?;
        state
            .body_budget_activation
            .activate(&state.body_budget, replay_capacity)
            .map_err(|_| 500_u16)?;
        let body_resources = ProductBodyResources {
            _replay: replay_lease,
            _staging: staging,
        };

        let content_type = state
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body_read_plan = if request.facts().upgrade().is_some() {
            HttpBodyReadPlan::Disabled
        } else {
            state.body_read_plan
        };
        let mut inspected = match body_read_plan {
            HttpBodyReadPlan::Disabled => None,
            HttpBodyReadPlan::Mandatory(limits) => {
                let body = read_mandatory_runtime_request_body(
                    &mut request,
                    limits,
                    generation.max_content_decoding_expansion_ratio(),
                    deadline,
                    &guard,
                )
                .await
                .map_err(body_error_status)?;
                Some(InspectedBody {
                    content_type: content_type.clone(),
                    encoded_len: body.encoded_len(),
                    decoded: body.into_guarded_body(),
                })
            }
        };

        loop {
            if Instant::now() >= deadline {
                return Err(504);
            }
            if upgrade_is_disallowed(
                generation.standalone(),
                request.facts().upgrade().is_some(),
                &evaluation,
            ) {
                self.set_decision_source(local_source(DecisionReasonCategory::InvalidPlan, 2));
                return Err(403);
            }
            match evaluation {
                PolicyEvaluation::Allow {
                    provenance,
                    effects,
                } => {
                    let ordinal = policy_rule_ordinal(&provenance);
                    validate_redaction_limits(generation, ordinal, inspected.as_ref())?;
                    let inspected_body = if request.facts().upgrade().is_some() {
                        drop(inspected.take());
                        None
                    } else {
                        inspected.take().map(|body| body.decoded)
                    };
                    let allowed = adapt_local_allow(
                        generation,
                        effects,
                        &provenance,
                        allow_mode,
                        inspected_body,
                        guard,
                        request,
                    )
                    .map_err(adapter_error_status)?;
                    self.set_decision_source(DecisionAuditSource::Policy(provenance));
                    let mut terminal = state.terminal.take().ok_or(500_u16)?;
                    let private_fields = ProductPrivateFields {
                        _inbound: state.inbound,
                        _internal_context: state.internal_context,
                        _retained: terminal.private_fields.take().ok_or(500_u16)?,
                    };
                    return self.finish_forward(
                        resolved,
                        allowed,
                        terminal,
                        body_resources,
                        private_fields,
                    );
                }
                PolicyEvaluation::Deny { provenance } => {
                    self.set_decision_source(DecisionAuditSource::Policy(provenance.clone()));
                    let ordinal = policy_rule_ordinal(&provenance);
                    self.record_inspected_denial(
                        &mut state.headers,
                        generation,
                        ordinal,
                        &guard,
                        inspected.take(),
                        !state.ingress_body_complete,
                    );
                    return Err(403);
                }
                PolicyEvaluation::Delegate(delegated) => {
                    let ordinal = policy_rule_ordinal(delegated.provenance()).ok_or(500_u16)?;
                    let action = generation
                        .standalone()
                        .product_acl()
                        .delegated_action(&delegated)
                        .map_err(|_| 500_u16)?;
                    let rule_id = match delegated.provenance().effective_policy() {
                        EffectivePolicy::Rule { id, .. } => id.as_str(),
                        EffectivePolicy::Default => return Err(500),
                    };
                    let provider = generation
                        .standalone()
                        .activated()
                        .provider_for_action(ordinal, action)
                        .ok_or(500_u16)?;
                    let metadata = generation
                        .authorization()
                        .provider_metadata(provider)
                        .ok_or(500_u16)?;
                    let invocation_mode = match allow_mode {
                        StandaloneAllowMode::OriginRequest => {
                            AuthorizationInvocationMode::EffectsAllowed
                        }
                        StandaloneAllowMode::OuterConnect => {
                            AuthorizationInvocationMode::DecisionOnly
                        }
                    };
                    if invocation_mode == AuthorizationInvocationMode::EffectsAllowed
                        && metadata.include_request_body
                        && inspected.is_none()
                    {
                        if request.facts().upgrade().is_some()
                            && matches!(
                                request.facts().body().framing(),
                                BodyFraming::None | BodyFraming::ContentLength(0)
                            )
                        {
                            inspected = Some(InspectedBody {
                                content_type: content_type.clone(),
                                encoded_len: 0,
                                decoded: guard.buffer().finish(),
                            });
                        } else {
                            return Err(500);
                        }
                    }
                    validate_provider_limits(
                        generation,
                        ordinal,
                        metadata,
                        invocation_mode == AuthorizationInvocationMode::EffectsAllowed,
                        inspected.as_ref(),
                    )?;
                    let selected = provider_header_values(
                        metadata.include_headers,
                        &state.headers,
                        &state.internal_context,
                        &state.inbound,
                        provider,
                    )
                    .map_err(|_| 500_u16)?;
                    let included = selected
                        .iter()
                        .map(|(name, values)| IncludedHeader::new(name, values))
                        .collect::<Vec<_>>();
                    let provider_headers =
                        ProviderRequestHeaders::new(&included).map_err(|_| 500_u16)?;
                    let peer_ip = state.request_binding_peer_ip.to_string();
                    let provider_identity = metadata.include_identity.then(|| {
                        access_identity::ProviderIdentityProjection::from(request.identity())
                    });
                    let provider_body = (invocation_mode
                        == AuthorizationInvocationMode::EffectsAllowed
                        && metadata.include_request_body)
                        .then(|| {
                            let body = inspected
                                .as_ref()
                                .expect("body-including providers require mandatory inspection");
                            GuardedProviderBody {
                                content_type: body.content_type.as_deref(),
                                content_encoding: Some("identity"),
                                decoded: &body.decoded,
                            }
                        });
                    let provider_request = ProviderRequest {
                        request_id: &state.request_id,
                        rule_id,
                        url: request.facts().url().as_str(),
                        method: request.facts().method().as_str(),
                        client_ip: &peer_ip,
                        headers: (!included.is_empty()).then_some(&provider_headers),
                        identity: provider_identity.as_ref(),
                        body: provider_body,
                    };
                    let decision = generation
                        .dispatch_authorization(
                            provider,
                            provider_request,
                            invocation_mode,
                            terminal.cancellation.capability(),
                            &guard,
                            deadline,
                        )
                        .await;
                    if Instant::now() >= deadline {
                        return Err(504);
                    }
                    let decision = match decision {
                        Ok(decision) => decision,
                        Err(error) if error.is_cancelled() => return Err(503),
                        Err(_) if metadata.failure_mode == CompiledProviderFailureMode::Deny => {
                            let policy_result = resolve_delegate(
                                generation,
                                delegated,
                                ProviderDisposition::Deny,
                                &request,
                                state.request_binding_peer_ip,
                                state.policy_peer_ip,
                            )?;
                            let PolicyEvaluation::Deny { provenance } = policy_result else {
                                return Err(500);
                            };
                            self.set_decision_source(DecisionAuditSource::Policy(provenance));
                            self.record_inspected_denial(
                                &mut state.headers,
                                generation,
                                Some(ordinal),
                                &guard,
                                inspected.take(),
                                !state.ingress_body_complete,
                            );
                            return Err(403);
                        }
                        Err(error) if error.is_timeout() || Instant::now() >= deadline => {
                            return Err(504)
                        }
                        Err(_) => return Err(500),
                    };

                    match decision {
                        AuthorizationDecision::Allow(output) => {
                            let policy_result = resolve_delegate(
                                generation,
                                delegated,
                                ProviderDisposition::Allow,
                                &request,
                                state.request_binding_peer_ip,
                                state.policy_peer_ip,
                            )?;
                            let PolicyEvaluation::Allow {
                                provenance,
                                effects: MatchedEffects::Rule(effects),
                            } = policy_result
                            else {
                                return Err(500);
                            };
                            let original_body_consumed =
                                inspected.is_some() || state.ingress_body_complete;
                            let inspected_body = if request.facts().upgrade().is_some() {
                                drop(inspected.take());
                                None
                            } else {
                                inspected.take().map(|body| body.decoded)
                            };
                            let allowed =
                                match adapt_provider_allow(
                                    generation,
                                    effects,
                                    &provenance,
                                    provider,
                                    output,
                                    allow_mode,
                                    inspected_body,
                                    guard,
                                    request,
                                ) {
                                    Ok(allowed) => allowed,
                                    Err(failure) => {
                                        let provenance = failure.provider_replacement_size().map_or(
                                StandaloneResponseBodyProvenance::Unconsumed,
                                |size| StandaloneResponseBodyProvenance::ProviderReplacement {
                                    size,
                                },
                            );
                                        let status = adapter_error_status(failure.into_error());
                                        self.record_denial(
                                            &mut state.headers,
                                            None,
                                            provenance,
                                            !original_body_consumed,
                                        );
                                        return Err(status);
                                    }
                                };
                            let mut terminal = state.terminal.take().ok_or(500_u16)?;
                            self.set_decision_source(DecisionAuditSource::Policy(provenance));
                            let private_fields = ProductPrivateFields {
                                _inbound: state.inbound,
                                _internal_context: state.internal_context,
                                _retained: terminal.private_fields.take().ok_or(500_u16)?,
                            };
                            return self.finish_forward(
                                resolved,
                                allowed,
                                terminal,
                                body_resources,
                                private_fields,
                            );
                        }
                        AuthorizationDecision::Deny => {
                            let policy_result = resolve_delegate(
                                generation,
                                delegated,
                                ProviderDisposition::Deny,
                                &request,
                                state.request_binding_peer_ip,
                                state.policy_peer_ip,
                            )?;
                            let PolicyEvaluation::Deny { provenance } = policy_result else {
                                return Err(500);
                            };
                            self.set_decision_source(DecisionAuditSource::Policy(provenance));
                            self.record_inspected_denial(
                                &mut state.headers,
                                generation,
                                Some(ordinal),
                                &guard,
                                inspected.take(),
                                !state.ingress_body_complete,
                            );
                            return Err(403);
                        }
                        AuthorizationDecision::Pass => {
                            evaluation = resolve_delegate(
                                generation,
                                delegated,
                                ProviderDisposition::Pass,
                                &request,
                                state.request_binding_peer_ip,
                                state.policy_peer_ip,
                            )?;
                        }
                    }
                }
            }
        }
    }

    fn finish_forward(
        &self,
        resolved: ResolvedForwardingTarget,
        allowed: crate::standalone_provider_result::StandaloneProviderAllow,
        terminal: PreparedTerminalState,
        body_resources: ProductBodyResources,
        private_fields: ProductPrivateFields,
    ) -> Result<ProviderOutcome, u16> {
        let crate::standalone_provider_result::StandaloneProviderAllow {
            plan,
            request,
            mut sidecar,
            credentials,
        } = allowed;
        if terminal.allow_mode == StandaloneAllowMode::OuterConnect {
            if credentials.is_some()
                || sidecar
                    .take_upgrade_admission(plan.binding())
                    .map_err(|_| 500_u16)?
                    .is_some()
            {
                return Err(500);
            }
            let source = self
                .take_decision_source()
                .expect("allowed CONNECT owns final policy provenance");
            let decision = self.audit.pending(DecisionDisposition::Allow, source);
            let previous = lock(&self.response_decision).replace(decision);
            debug_assert!(previous.is_none());
            drop((
                resolved,
                plan,
                request,
                sidecar,
                terminal,
                body_resources,
                private_fields,
            ));
            return Ok(ProviderOutcome::Respond(
                lock(&self.responses).build(200).map_err(|_| 500_u16)?,
            ));
        }
        let mut dispatch = lock(&self.dispatch);
        if dispatch.is_some() {
            return Err(500);
        }
        let retention = terminal
            .generation
            .retain_for_operation()
            .map_err(|_| 503_u16)?;
        let services = terminal.generation.into_forwarding_services();
        let source = self
            .take_decision_source()
            .expect("forward outcome owns final policy provenance");
        let decision = self.audit.pending(DecisionDisposition::Allow, source);
        *dispatch = Some(PreparedDispatch {
            services,
            request_id: terminal.request_id,
            quota_key: terminal.quota_key,
            retention,
            resolved,
            cancellation: terminal.cancellation,
            sidecar,
            credentials,
            private_fields,
            decision,
            capture: self.capture.clone(),
            body_resources,
            stable_wire_body_pool: terminal.stable_wire_body_pool,
        });
        Ok(ProviderOutcome::Forward { plan, request })
    }

    fn response(&self, status: u16) -> ProviderOutcome {
        let source = self
            .take_decision_source()
            .unwrap_or_else(|| local_status_source(status));
        let decision = self.audit.pending(DecisionDisposition::Deny, source);
        let previous = lock(&self.response_decision).replace(decision);
        debug_assert!(
            previous.is_none(),
            "one provider invocation has one response decision"
        );
        ProviderOutcome::Respond(
            lock(&self.responses)
                .build(status)
                .expect("the consuming request pipeline invokes its provider exactly once"),
        )
    }

    fn record_denial(
        &self,
        headers: &mut HeaderMap,
        body: Option<StandaloneDeniedBody>,
        body_provenance: StandaloneResponseBodyProvenance,
        close_connection: bool,
    ) {
        let mut observation = lock(&self.response_observation);
        if observation.is_none() {
            *observation = Some(StandaloneResponseObservation {
                headers: std::mem::take(headers),
                body,
                body_provenance,
                close_connection,
            });
        }
    }

    fn record_inspected_denial(
        &self,
        headers: &mut HeaderMap,
        generation: &GenerationLease,
        ordinal: Option<usize>,
        guard: &crate::safety::HttpWireBodyGuard,
        inspected: Option<InspectedBody>,
        unread_body_closes: bool,
    ) {
        let close_connection = inspected.is_none() && unread_body_closes;
        let (body, body_provenance) = inspected.map_or(
            (None, StandaloneResponseBodyProvenance::Unconsumed),
            |body| {
                let redaction = ordinal.and_then(|ordinal| {
                    generation.standalone().activated().rule_redaction(ordinal)
                });
                match redaction {
                    Some(binding) => binding
                        .handle()
                        .redact_http_body(guard, body.decoded)
                        .ok()
                        .map_or(
                            (None, StandaloneResponseBodyProvenance::CompleteOriginal),
                            |redacted| {
                                (
                                    Some(StandaloneDeniedBody {
                                        content_type: body.content_type,
                                        decoded: redacted.into_body(),
                                    }),
                                    StandaloneResponseBodyProvenance::CompleteWireRedacted,
                                )
                            },
                        ),
                    None => (
                        Some(StandaloneDeniedBody {
                            content_type: body.content_type,
                            decoded: body.decoded,
                        }),
                        StandaloneResponseBodyProvenance::CompleteOriginal,
                    ),
                }
            },
        );
        self.record_denial(headers, body, body_provenance, close_connection);
    }

    fn submit_local_capture(
        &self,
        status: u16,
        observation: Option<StandaloneResponseObservation>,
    ) {
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        if let Some(observation) = observation {
            let (body, provenance) = match (observation.body, observation.body_provenance) {
                (
                    Some(body),
                    body_provenance @ (StandaloneResponseBodyProvenance::CompleteOriginal
                    | StandaloneResponseBodyProvenance::CompleteWireRedacted),
                ) => {
                    let mut headers = HeaderMap::new();
                    if let Some(content_type) = body
                        .content_type
                        .as_deref()
                        .and_then(|value| HeaderValue::from_str(value).ok())
                    {
                        headers.insert(CONTENT_TYPE, content_type);
                    }
                    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("identity"));
                    let provenance = match body_provenance {
                        StandaloneResponseBodyProvenance::CompleteOriginal => {
                            TerminalRequestBodyProvenance::CompleteOriginal
                        }
                        StandaloneResponseBodyProvenance::CompleteWireRedacted => {
                            TerminalRequestBodyProvenance::CompleteWireRedacted
                        }
                        _ => unreachable!("the match arm restricts body provenance"),
                    };
                    (
                        Some(DeniedCaptureBody {
                            headers,
                            decoded: body.decoded,
                        }),
                        provenance,
                    )
                }
                (None, StandaloneResponseBodyProvenance::ProviderReplacement { size }) => (
                    None,
                    TerminalRequestBodyProvenance::ProviderReplacement { size },
                ),
                (None, StandaloneResponseBodyProvenance::CompleteOriginal) => {
                    (None, TerminalRequestBodyProvenance::CompleteOriginal)
                }
                (None, StandaloneResponseBodyProvenance::CompleteWireRedacted) => {
                    (None, TerminalRequestBodyProvenance::CompleteWireRedacted)
                }
                _ => (None, TerminalRequestBodyProvenance::Unconsumed),
            };
            self.capture
                .submit_denied_request(Some(&observation.headers), body, provenance);
        } else if status != StatusCode::OK {
            self.capture.submit_denied_request(
                None,
                None,
                TerminalRequestBodyProvenance::Unconsumed,
            );
        }
        if status != StatusCode::OK {
            let context = lock(&self.responses).context;
            self.capture.submit_local_response(
                CaptureDecision::Deny,
                status,
                local_response_capture_body(status.as_u16(), context),
            );
        }
    }

    fn set_decision_source(&self, source: DecisionAuditSource) {
        let previous = lock(&self.decision_source).replace(source);
        debug_assert!(
            previous.is_none(),
            "one provider invocation has one final source"
        );
    }

    fn take_decision_source(&self) -> Option<DecisionAuditSource> {
        lock(&self.decision_source).take()
    }
}

impl PreparedResponses {
    fn new(
        request: &RuntimeRequest,
        clock: Arc<TokioRuntimeClock>,
        context: LocalResponseContext,
    ) -> Result<Self, http_access_runtime::RuntimeError> {
        let bounds = BodyBounds::new(
            LOCAL_RESPONSE_BODY_BYTES,
            LOCAL_RESPONSE_BODY_BYTES,
            LOCAL_RESPONSE_BODY_BYTES,
            0,
            0,
            600_000,
        )?;
        let policy = request.local_response_policy(bounds, 8, 4_096)?;
        let runtime_clock: Arc<dyn Clock> = clock;
        let maximum_payload_bytes = [
            LocalResponseBodyKind::ConnectDenial,
            LocalResponseBodyKind::Denial,
            LocalResponseBodyKind::Timeout,
            LocalResponseBodyKind::BodyDenial,
            LocalResponseBodyKind::Unavailable,
            LocalResponseBodyKind::Failure,
        ]
        .into_iter()
        .map(|kind| kind.text().len())
        .max()
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(http_access_runtime::RuntimeError::LimitExceeded)?;
        let response_budget = BodyBudget::new(BodyBudget::required_storage_bytes(
            maximum_payload_bytes,
            1,
        )?)?;
        Ok(Self {
            policy,
            context,
            bounds,
            clock: runtime_clock,
            budget: Some(response_budget),
        })
    }

    fn build(&mut self, status: u16) -> Result<RuntimeResponse, http_access_runtime::RuntimeError> {
        let (headers, chunks) = if status == 200 {
            (Vec::new(), Vec::new())
        } else {
            let headers = vec![http_access_types::HeaderField::new(
                http_access_types::HeaderName::new("content-type")
                    .expect("the static header name is valid"),
                http_access_types::HeaderValue::new(b"text/plain; charset=utf-8".to_vec())
                    .expect("the static header value is valid"),
            )];
            let payload = local_response_body_kind(status, self.context).text();
            (headers, vec![payload.as_bytes().to_vec()])
        };
        let deadline_millis = self
            .clock
            .monotonic_millis()
            .checked_add(self.policy.max_delivery_millis())
            .ok_or(http_access_runtime::RuntimeError::LimitExceeded)?;
        let body = RuntimeBody::from_chunks(
            chunks,
            self.bounds,
            Arc::clone(&self.clock),
            self.budget
                .take()
                .ok_or(http_access_runtime::RuntimeError::InvalidInput)?,
            deadline_millis,
        )?;
        RuntimeResponse::new(status, headers, body, self.policy)
    }
}

impl DecisionProvider for StandalonePolicyProvider {
    fn decide<'a>(
        &'a self,
        facts: &'a http_access_types::InterceptedRequestFacts,
        request: RuntimeRequest,
    ) -> BoxFuture<'a, ProviderOutcome> {
        let state = lock(&self.decision).take();
        Box::pin(async move {
            let cancelled = self.audit.pending(
                DecisionDisposition::Deny,
                local_source(DecisionReasonCategory::Transport, 1),
            );
            let Some(state) = state else {
                let outcome = self.response(500);
                cancelled.discard();
                return outcome;
            };
            let outcome = match self.decide_owned(state, facts, request).await {
                Ok(outcome) => outcome,
                Err(status) => self.response(status),
            };
            cancelled.discard();
            outcome
        })
    }
}

impl StandaloneDispatch for StandalonePolicyProvider {
    type Output = StandaloneTerminal;

    fn fail_closed(&self, _error: RequestPipelineError) -> BoxFuture<'_, Self::Output> {
        if let Some(dispatch) = lock(&self.dispatch).take() {
            dispatch.decision.discard();
        }
        if let Some(decision) = lock(&self.response_decision).take() {
            decision.discard();
        }
        let mut decision = self.audit.pending(
            DecisionDisposition::Deny,
            local_source(DecisionReasonCategory::InvalidPlan, 4),
        );
        decision.submit_now();
        let response = lock(&self.responses)
            .build(500)
            .expect("the consuming request pipeline owns one local response");
        self.submit_local_capture(500, None);
        Box::pin(async move {
            StandaloneTerminal::Local {
                response: Box::new(response),
                close_connection: true,
            }
        })
    }

    fn respond(&self, response: RuntimeResponse) -> BoxFuture<'_, Self::Output> {
        if let Some(dispatch) = lock(&self.dispatch).take() {
            dispatch.decision.discard();
        }
        let observation = lock(&self.response_observation).take();
        let close_connection = local_terminal_close_connection(
            response.status(),
            observation
                .as_ref()
                .map(|observation| observation.close_connection),
        );
        let mut decision = lock(&self.response_decision).take().unwrap_or_else(|| {
            self.audit.pending(
                DecisionDisposition::Deny,
                local_source(DecisionReasonCategory::InvalidPlan, 5),
            )
        });
        decision.submit_now();
        self.submit_local_capture(response.status(), observation);
        Box::pin(async move {
            StandaloneTerminal::Local {
                response: Box::new(response),
                close_connection,
            }
        })
    }

    fn forward(&self, exchange: StandaloneExchange) -> BoxFuture<'_, Self::Output> {
        let dispatch = lock(&self.dispatch).take();
        let Some(dispatch) = dispatch else {
            return self.fail_closed(RequestPipelineError::InvalidProviderOutput);
        };
        if dispatch.sidecar.plan_binding() != exchange.plan().binding() {
            dispatch.decision.discard();
            return self.fail_closed(RequestPipelineError::InvalidProviderOutput);
        }
        let forwarding = crate::proxy::forwarding_adapter::prepare(StandaloneForwardDispatch {
            exchange,
            services: dispatch.services,
            request_id: dispatch.request_id,
            quota_key: dispatch.quota_key,
            retention: dispatch.retention,
            resolved: dispatch.resolved,
            cancellation: dispatch.cancellation,
            sidecar: dispatch.sidecar,
            credentials: dispatch.credentials,
            private_fields: dispatch.private_fields,
            decision: dispatch.decision,
            capture: dispatch.capture,
            body_resources: dispatch.body_resources,
            stable_wire_body_pool: dispatch.stable_wire_body_pool,
        });
        match forwarding {
            Ok(forwarding) => {
                Box::pin(async move { StandaloneTerminal::Forward(Box::new(forwarding)) })
            }
            Err(error) => {
                let status = match error {
                    http_access_runtime::RuntimeError::ServiceFailure
                    | http_access_runtime::RuntimeError::LimitExceeded => 503,
                    _ => 500,
                };
                let mut decision = self
                    .audit
                    .pending(DecisionDisposition::Deny, local_status_source(status));
                decision.submit_now();
                let response = lock(&self.responses)
                    .build(status)
                    .expect("the consuming request pipeline owns one local response");
                self.submit_local_capture(status, None);
                Box::pin(async move {
                    StandaloneTerminal::Local {
                        response: Box::new(response),
                        close_connection: true,
                    }
                })
            }
        }
    }
}

struct InspectedBody {
    content_type: Option<String>,
    encoded_len: usize,
    decoded: GuardedBody,
}

fn validate_provider_limits(
    lease: &GenerationLease,
    ordinal: usize,
    metadata: crate::authorization::AuthorizationProviderMetadata<'_>,
    include_provider_body: bool,
    body: Option<&InspectedBody>,
) -> Result<(), u16> {
    if let Some(body) = body {
        if include_provider_body
            && metadata.include_request_body
            && (body.encoded_len > metadata.max_request_body_bytes
                || body.decoded.len() > metadata.max_decoded_request_body_bytes)
        {
            return Err(413);
        }
    }
    validate_redaction_limits(lease, Some(ordinal), body)
}

fn validate_redaction_limits(
    lease: &GenerationLease,
    ordinal: Option<usize>,
    body: Option<&InspectedBody>,
) -> Result<(), u16> {
    let Some(body) = body else {
        return Ok(());
    };
    let Some(redaction) =
        ordinal.and_then(|ordinal| lease.standalone().activated().rule_redaction(ordinal))
    else {
        return Ok(());
    };
    let limits = redaction.handle().limits();
    if body.encoded_len > limits.max_body_bytes()
        || body.decoded.len() > limits.max_decoded_body_bytes()
    {
        return Err(413);
    }
    Ok(())
}

fn body_error_status(error: HttpBodyReadError) -> u16 {
    match error {
        HttpBodyReadError::ReadFailed | HttpBodyReadError::RequestTrailersUnsupported => 400,
        HttpBodyReadError::TimedOut => 408,
        HttpBodyReadError::EncodedLimitExceeded
        | HttpBodyReadError::DecodedLimitExceeded
        | HttpBodyReadError::ExpansionRatioExceeded => 413,
        HttpBodyReadError::UnsupportedContentEncoding
        | HttpBodyReadError::StackedContentEncoding
        | HttpBodyReadError::InvalidContentEncoding
        | HttpBodyReadError::DecoderWindowExceeded => 415,
        HttpBodyReadError::ResourceExhausted => 503,
    }
}

fn local_source(category: DecisionReasonCategory, code: u16) -> DecisionAuditSource {
    DecisionAuditSource::Local(DecisionReason::new(category, code))
}

fn local_status_source(status: u16) -> DecisionAuditSource {
    let category = match status {
        408 | 504 => DecisionReasonCategory::Expired,
        500 => DecisionReasonCategory::InvalidPlan,
        502 | 503 => DecisionReasonCategory::Transport,
        _ => DecisionReasonCategory::InvalidPlan,
    };
    local_source(category, status)
}

const fn early_deny_close_connection(ingress_body_complete: bool) -> bool {
    !ingress_body_complete
}

const fn local_terminal_close_connection(status: u16, observed_close: Option<bool>) -> bool {
    match observed_close {
        Some(close) => close,
        None => status != 200,
    }
}

fn adapter_error_status(error: StandaloneProviderAllowError) -> u16 {
    match error {
        StandaloneProviderAllowError::ProviderReplacement(
            ProviderBodyReplacementDecodeError::ProviderBodyLimit
            | ProviderBodyReplacementDecodeError::RedactionBodyLimit,
        ) => 413,
        StandaloneProviderAllowError::ProviderReplacement(
            ProviderBodyReplacementDecodeError::InvalidBody,
        ) => 415,
        StandaloneProviderAllowError::ContentType
        | StandaloneProviderAllowError::ExecutionContextProjection => 500,
        StandaloneProviderAllowError::Runtime(http_access_runtime::RuntimeError::LimitExceeded) => {
            503
        }
        StandaloneProviderAllowError::Runtime(
            http_access_runtime::RuntimeError::DeadlineExceeded,
        ) => 504,
        StandaloneProviderAllowError::ProviderCredential(
            crate::authorization::protocol::ProviderCredentialWireError::AllocationFailed,
        ) => 503,
        StandaloneProviderAllowError::Binding
        | StandaloneProviderAllowError::ProviderCredential(_)
        | StandaloneProviderAllowError::Credential(_)
        | StandaloneProviderAllowError::Runtime(_)
        | StandaloneProviderAllowError::Plan(_)
        | StandaloneProviderAllowError::Upgrade(_) => 500,
        StandaloneProviderAllowError::Redaction => 403,
    }
}

fn provider_header_values(
    include_headers: &[HeaderName],
    request_headers: &HeaderMap,
    internal_context: &HeaderMap,
    inbound: &InboundCredentials,
    provider: ProviderIndex,
) -> Result<Vec<(HeaderName, Vec<http::HeaderValue>)>, crate::credentials::CredentialError> {
    let mut selected = HeaderMap::new();
    for name in include_headers {
        for value in request_headers
            .get_all(name)
            .iter()
            .chain(internal_context.get_all(name))
        {
            selected.append(name.clone(), value.clone());
        }
    }
    inbound.copy_for_process_provider(provider, &mut selected)?;
    Ok(selected
        .keys()
        .map(|name| {
            (
                name.clone(),
                selected.get_all(name).iter().cloned().collect(),
            )
        })
        .collect())
}

fn ingress_protocol(version: HttpVersion) -> HttpProtocol {
    match version {
        HttpVersion::Http10 | HttpVersion::Http11 => HttpProtocol::Http1,
        HttpVersion::Http2 => HttpProtocol::Http2,
    }
}

fn request_id() -> String {
    use rand::RngCore;
    use std::fmt::Write;

    let mut token = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut token);
    let mut id = String::with_capacity(36);
    id.push_str("req-");
    for byte in token {
        let _ = write!(&mut id, "{byte:02x}");
    }
    id
}

fn policy_provenance(evaluation: &PolicyEvaluation<ProductRuleEffectsRef>) -> &DecisionProvenance {
    match evaluation {
        PolicyEvaluation::Allow { provenance, .. } | PolicyEvaluation::Deny { provenance } => {
            provenance
        }
        PolicyEvaluation::Delegate(delegated) => delegated.provenance(),
    }
}

fn policy_rule_ordinal(provenance: &DecisionProvenance) -> Option<usize> {
    match provenance.effective_policy() {
        EffectivePolicy::Default => None,
        EffectivePolicy::Rule { ordinal, .. } => usize::try_from(*ordinal).ok(),
    }
}

fn resolve_delegate(
    generation: &GenerationLease,
    delegated: http_access_policy_acl::DelegateMatch<ProductRuleEffectsRef>,
    disposition: ProviderDisposition,
    request: &RuntimeRequest,
    request_binding_peer_ip: IpAddr,
    policy_peer_ip: Option<IpAddr>,
) -> Result<PolicyEvaluation<ProductRuleEffectsRef>, u16> {
    let input = policy_evaluation_input(
        request.facts(),
        request_binding_peer_ip,
        policy_peer_ip,
        request.policy_header_facts(),
        request.identity(),
        request.execution_context(),
    )
    .map_err(|_| 500_u16)?;
    generation
        .standalone()
        .product_acl()
        .snapshot()
        .resolve_delegate(delegated, disposition, &input)
        .map_err(|_| 500_u16)
}

fn policy_evaluation_input<'a>(
    facts: &'a http_access_types::InterceptedRequestFacts,
    request_binding_peer_ip: IpAddr,
    policy_peer_ip: Option<IpAddr>,
    header_facts: &'a PolicyHeaderFacts,
    identity: &'a access_identity::IdentityContext,
    execution_context: Option<&'a access_execution_context::ExecutionContext>,
) -> Result<EvaluationInput<'a>, http_access_policy_acl::AclError> {
    EvaluationInput::new(
        facts,
        request_binding_peer_ip,
        policy_peer_ip,
        header_facts,
        RuntimeRequest::INITIAL_REVISION,
        BodyRepresentation::PreservedContentCoded,
        BodyObservation::unobserved(),
        identity,
        execution_context,
    )
}

fn upgrade_is_disallowed(
    generation: &crate::standalone::StandaloneGenerationPlan,
    upgrade_intent: bool,
    evaluation: &PolicyEvaluation<ProductRuleEffectsRef>,
) -> bool {
    upgrade_intent
        && !matches!(evaluation, PolicyEvaluation::Deny { .. })
        && !policy_rule_ordinal(policy_provenance(evaluation))
            .and_then(|ordinal| generation.rules().get(ordinal))
            .is_some_and(crate::standalone::StandaloneRuleTemplate::allow_upgrades)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod local_response_contract_tests {
    use std::net::Ipv4Addr;

    use http_access_policy_acl::{
        DefaultDecision, PeerCidr, ProductActionRef, Rule, RulePredicates, TrafficPolicySnapshot,
    };
    use http_access_types::{PolicyGeneration, SnapshotIdentity};

    use super::*;

    #[test]
    fn legacy_context_admission_is_tcp_authenticated_exactly_once_and_access_flow_disjoint() {
        let header = HeaderName::from_static("x-aw-policy-context");
        let authenticated = access_identity::authenticated_identity_context_fixture();

        let mut absent = HeaderMap::new();
        assert!(resolve_ingress_execution_context(
            http_access_runtime::ListenerTransport::Tcp,
            &authenticated,
            None,
            Some(&header),
            &mut absent,
        )
        .unwrap()
        .is_none());

        let mut internal = HeaderMap::new();
        internal.append(header.clone(), HeaderValue::from_static("internal"));
        let admitted = resolve_ingress_execution_context(
            http_access_runtime::ListenerTransport::Tcp,
            &authenticated,
            None,
            Some(&header),
            &mut internal,
        )
        .unwrap()
        .unwrap();
        assert_eq!(admitted.as_str(), "internal");
        assert_eq!(internal[&header], "internal");

        for values in [
            vec!["internal", "external"],
            vec!["internal,external"],
            vec!["Internal"],
        ] {
            let mut invalid = HeaderMap::new();
            for value in values {
                invalid.append(header.clone(), HeaderValue::from_str(value).unwrap());
            }
            assert!(matches!(
                resolve_ingress_execution_context(
                    http_access_runtime::ListenerTransport::Tcp,
                    &authenticated,
                    None,
                    Some(&header),
                    &mut invalid,
                ),
                Err(http_access_runtime::RuntimeError::RequestRejected)
            ));
        }
        let mut non_utf8 = HeaderMap::new();
        non_utf8.append(
            header.clone(),
            HeaderValue::from_bytes(&[0xff]).expect("opaque header bytes are structurally valid"),
        );
        assert!(matches!(
            resolve_ingress_execution_context(
                http_access_runtime::ListenerTransport::Tcp,
                &authenticated,
                None,
                Some(&header),
                &mut non_utf8,
            ),
            Err(http_access_runtime::RuntimeError::RequestRejected)
        ));

        for identity in [
            access_identity::IdentityContext::Disabled,
            access_identity::IdentityContext::Anonymous,
        ] {
            let mut untrusted = HeaderMap::new();
            untrusted.append(header.clone(), HeaderValue::from_static("internal"));
            assert!(matches!(
                resolve_ingress_execution_context(
                    http_access_runtime::ListenerTransport::Tcp,
                    &identity,
                    None,
                    Some(&header),
                    &mut untrusted,
                ),
                Err(http_access_runtime::RuntimeError::RequestRejected)
            ));
        }

        let external = access_execution_context::ExecutionContext::new("external").unwrap();
        let mut spoofed_access_flow = HeaderMap::new();
        spoofed_access_flow.append(header.clone(), HeaderValue::from_static("internal"));
        let admitted = resolve_ingress_execution_context(
            http_access_runtime::ListenerTransport::AccessFlow,
            &authenticated,
            Some(external),
            Some(&header),
            &mut spoofed_access_flow,
        )
        .unwrap()
        .unwrap();
        assert_eq!(admitted.as_str(), "external");
        assert!(!spoofed_access_flow.contains_key(&header));
    }

    #[test]
    fn absolute_deadline_millis_rounds_submillisecond_remainders_up() {
        let epoch = Instant::now();
        let clock = TokioRuntimeClock::new(epoch);
        assert_eq!(clock.deadline_millis(epoch), Some(0));
        assert_eq!(
            clock.deadline_millis(epoch + Duration::from_nanos(999_999)),
            Some(1)
        );
        assert_eq!(
            clock.deadline_millis(epoch + Duration::from_millis(1)),
            Some(1)
        );
        assert_eq!(
            clock.deadline_millis(epoch + Duration::from_nanos(1_000_001)),
            Some(2)
        );
        assert_eq!(clock.deadline_millis(epoch - Duration::from_nanos(1)), None);
    }

    #[test]
    fn remote_projection_sentinels_survive_delegate_resume_without_becoming_policy_source() {
        let identity = access_identity::authenticated_identity_context_fixture();
        let projection = http_access_runtime::StandaloneIngressProjection::from_access_flow(
            access_flow::AccessFlowIngressOrigin::RemoteAccessFlow,
            &identity,
        )
        .unwrap();
        let client = projection.client();
        let request_binding_peer_ip = projection
            .checked_request_binding_peer_ip(&identity)
            .unwrap();
        assert_eq!(client, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        assert_eq!(request_binding_peer_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(projection.policy_peer_ip(), None);

        let provider_client_ip = request_binding_peer_ip.to_string();
        let provider_request = ProviderRequest {
            request_id: "request",
            rule_id: "delegate",
            url: "http://example.test/resource",
            method: "GET",
            client_ip: &provider_client_ip,
            headers: None,
            identity: None,
            body: None,
        };
        assert_eq!(provider_request.client_ip, "0.0.0.0");

        let facts = http_access_types::InterceptedRequestFacts::new(
            http_access_types::IngressMode::TransparentHttp,
            HttpVersion::Http11,
            HttpMethod::new("GET").unwrap(),
            http_access_url::canonicalize_http_url("http://example.test/resource").unwrap(),
            Vec::new(),
            http_access_types::BodyMetadata::new(BodyFraming::None),
            None,
        )
        .unwrap();
        let header_facts =
            PolicyHeaderFacts::from_partitioned(Vec::new(), Vec::new(), Vec::new()).unwrap();
        let input = policy_evaluation_input(
            &facts,
            request_binding_peer_ip,
            projection.policy_peer_ip(),
            &header_facts,
            &identity,
            None,
        )
        .unwrap();
        assert_eq!(input.policy_peer_ip(), None);
        assert_eq!(
            input.request_binding_peer_ip(),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );

        let snapshot_identity = SnapshotIdentity::new();
        let action = ProductActionRef::new(&snapshot_identity, StableId::new("provider").unwrap());
        let snapshot = TrafficPolicySnapshot::new(
            PolicyGeneration::new(1).unwrap(),
            snapshot_identity,
            DefaultDecision::Deny,
            Vec::new(),
            vec![
                Rule::delegate(
                    StableId::new("delegate").unwrap(),
                    RulePredicates::any(),
                    action,
                    "delegate",
                ),
                Rule::allow(
                    StableId::new("peer-default").unwrap(),
                    RulePredicates::new(
                        Vec::new(),
                        Vec::new(),
                        vec![PeerCidr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap()],
                        Vec::new(),
                        None,
                        None,
                    )
                    .unwrap(),
                    "peer",
                ),
            ],
        )
        .unwrap();
        let PolicyEvaluation::Delegate(delegated) = snapshot.evaluate(&input).unwrap() else {
            panic!("expected the first rule to delegate");
        };
        assert!(matches!(
            snapshot
                .resolve_delegate(delegated, ProviderDisposition::Pass, &input)
                .unwrap(),
            PolicyEvaluation::Deny { .. }
        ));
        assert_eq!(input.policy_peer_ip(), None);
        assert_eq!(provider_request.client_ip, "0.0.0.0");
    }

    fn request_and_clock() -> (RuntimeRequest, Arc<TokioRuntimeClock>) {
        request_and_clock_with_deadline(60_000)
    }

    fn request_and_clock_with_deadline(
        deadline_after_millis: u64,
    ) -> (RuntimeRequest, Arc<TokioRuntimeClock>) {
        let clock = TokioRuntimeClock::new(Instant::now());
        let deadline = clock
            .monotonic_millis()
            .saturating_add(deadline_after_millis);
        let bounds = BodyBounds::new(64, 64, 64, 0, 0, 60_000).unwrap();
        let runtime_clock: Arc<dyn Clock> = clock.clone();
        let body = RuntimeBody::from_chunks(
            Vec::new(),
            bounds,
            runtime_clock,
            BodyBudget::new(64).unwrap(),
            deadline,
        )
        .unwrap();
        let facts = http_access_types::InterceptedRequestFacts::new(
            http_access_types::IngressMode::ExplicitHttp,
            HttpVersion::Http11,
            HttpMethod::new("GET").unwrap(),
            http_access_url::canonicalize_http_url("http://example.test/resource").unwrap(),
            Vec::new(),
            http_access_types::BodyMetadata::new(BodyFraming::None),
            None,
        )
        .unwrap();
        let header_facts =
            PolicyHeaderFacts::from_partitioned(Vec::new(), Vec::new(), Vec::new()).unwrap();
        let request = RuntimeRequest::new(
            facts,
            "127.0.0.1".parse().unwrap(),
            header_facts,
            BodyRepresentation::PreservedContentCoded,
            body,
            deadline,
            Arc::new(access_identity::IdentityContext::Disabled),
            None,
        )
        .unwrap();
        (request, clock)
    }

    #[tokio::test]
    async fn local_status_responses_leave_framing_to_shared_runtime() {
        for (status, context, expected_body) in [
            (
                403,
                LocalResponseContext::ListenerDeniedConnect,
                CONNECT_DENIAL_RESPONSE_BODY,
            ),
            (403, LocalResponseContext::Standard, DENIAL_RESPONSE_BODY),
            (504, LocalResponseContext::Standard, TIMEOUT_RESPONSE_BODY),
            (
                400,
                LocalResponseContext::Standard,
                BODY_DENIAL_RESPONSE_BODY,
            ),
            (
                408,
                LocalResponseContext::Standard,
                BODY_DENIAL_RESPONSE_BODY,
            ),
            (
                413,
                LocalResponseContext::Standard,
                BODY_DENIAL_RESPONSE_BODY,
            ),
            (
                415,
                LocalResponseContext::Standard,
                BODY_DENIAL_RESPONSE_BODY,
            ),
            (
                503,
                LocalResponseContext::Standard,
                UNAVAILABLE_RESPONSE_BODY,
            ),
            (500, LocalResponseContext::Standard, FAILURE_RESPONSE_BODY),
        ] {
            let (request, clock) = request_and_clock();
            let mut response = PreparedResponses::new(&request, clock, context)
                .unwrap()
                .build(status)
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers().len(), 1);
            assert_eq!(response.headers()[0].name().as_str(), "content-type");

            let mut task_context = std::task::Context::from_waker(std::task::Waker::noop());
            let chunk = match response.poll_body_chunk(&mut task_context) {
                std::task::Poll::Ready(Ok(Some(chunk))) => chunk,
                other => panic!("expected the local failure body, got {other:?}"),
            };
            assert_eq!(chunk.as_bytes(), expected_body.as_bytes());
            assert_eq!(local_response_capture_body(status, context), expected_body);
            assert!(matches!(
                response.poll_body_chunk(&mut task_context),
                std::task::Poll::Ready(Ok(None))
            ));
        }
    }

    #[tokio::test]
    async fn local_response_body_rejects_a_budget_one_byte_below_exact_storage() {
        let (request, clock) = request_and_clock();
        let bounds = BodyBounds::new(
            LOCAL_RESPONSE_BODY_BYTES,
            LOCAL_RESPONSE_BODY_BYTES,
            LOCAL_RESPONSE_BODY_BYTES,
            0,
            0,
            600_000,
        )
        .unwrap();
        for payload in [
            CONNECT_DENIAL_RESPONSE_BODY,
            DENIAL_RESPONSE_BODY,
            TIMEOUT_RESPONSE_BODY,
            BODY_DENIAL_RESPONSE_BODY,
            UNAVAILABLE_RESPONSE_BODY,
            FAILURE_RESPONSE_BODY,
        ] {
            let payload_bytes = u64::try_from(payload.len()).unwrap();
            let exact = BodyBudget::required_storage_bytes(payload_bytes, 1).unwrap();
            let runtime_clock: Arc<dyn Clock> = clock.clone();
            let mut body = RuntimeBody::from_chunks(
                vec![payload.as_bytes().to_vec()],
                bounds,
                runtime_clock,
                BodyBudget::new(exact - 1).unwrap(),
                request.absolute_deadline_millis(),
            )
            .unwrap();

            assert!(matches!(
                body.poll_next_chunk(&mut std::task::Context::from_waker(std::task::Waker::noop())),
                std::task::Poll::Ready(Err(http_access_runtime::RuntimeError::LimitExceeded))
            ));
        }
    }

    #[tokio::test]
    async fn selected_timeout_body_gets_a_bounded_delivery_window_after_request_expiry() {
        let (request, clock) = request_and_clock_with_deadline(20);
        let mut responses =
            PreparedResponses::new(&request, clock, LocalResponseContext::Standard).unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;

        let mut response = responses.build(504).unwrap();
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        let std::task::Poll::Ready(Ok(Some(chunk))) = response.poll_body_chunk(&mut context) else {
            panic!("expected a timeout response body after the request deadline");
        };
        assert_eq!(chunk.as_bytes(), TIMEOUT_RESPONSE_BODY.as_bytes());
        assert!(matches!(
            response.poll_body_chunk(&mut context),
            std::task::Poll::Ready(Ok(None))
        ));
    }

    #[test]
    fn unread_early_deny_closes_but_allowed_connect_reuses_http1() {
        let unread_early_deny = early_deny_close_connection(false);
        assert!(unread_early_deny);
        assert!(local_terminal_close_connection(
            403,
            Some(unread_early_deny)
        ));
        assert!(!early_deny_close_connection(true));
        assert!(!local_terminal_close_connection(200, None));
    }
}
