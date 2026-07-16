use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::header::{HeaderMap, HeaderName, CONTENT_TYPE};
use http_access_policy_acl::{
    EvaluationInput, MatchedEffects, PolicyEvaluation, ProviderDisposition,
};
use http_access_runtime::{
    BodyBounds, BodyBudget, BodyBudgetActivation, BoxFuture, Clock, DecisionProvider,
    ProviderOutcome, RuntimeBody, RuntimeRequest, RuntimeResponse, StandaloneExchange,
};
use http_access_types::{
    BodyFraming, BodyObservation, BodyObservationState, BodyRepresentation, DecisionAuditFacts,
    DecisionAuditFactsInput, DecisionAuditSource, DecisionDisposition, DecisionProvenance,
    DecisionReason, DecisionReasonCategory, EffectivePolicy, HeaderName as NeutralHeaderName,
    HttpMethod, HttpVersion, PolicyHeaderFacts, RequestBinding, StableId, TrailerPolicy,
};
use hyper::body::HttpBody;
use tokio::time::Instant;

use crate::authorization::protocol::{
    GuardedProviderBody, IncludedHeader, ProviderBodyReplacementDecodeError, ProviderRequest,
    ProviderRequestHeaders,
};
use crate::authorization::AuthorizationDecision;
use crate::config::compiler::{
    CompiledDecisionLogLevel, CompiledProviderFailureMode, HttpBodyReadPlan,
};
use crate::credential_resolver::ProductCredentialPreparation;
use crate::credentials::InboundCredentials;
use crate::destination::DestinationGuard;
use crate::egress::OriginProtocol;
use crate::http_body::{read_mandatory_runtime_request_body, HttpBodyReadError};
use crate::observation::{DecisionSubmissionTarget, PendingDecisionSubmission};
use crate::policy::{HttpWireBodyPlanIndex, ProductRuleEffectsRef};
use crate::proxy::facts::{FactsError, SanitizedStandaloneIngress, ValidatedStandaloneIngress};
use crate::proxy::forward::{
    resolve_forwarding_target, PreflightForwardingTarget, PreparedForwardingTarget,
    ResolvedForwardingTarget,
};
use crate::request_pipeline::{RequestPipelineError, StandaloneDispatch};
use crate::runtime::{
    AuthorizationInvocationMode, ForwardingGenerationServices, GenerationLease,
    GenerationRetention, ProviderIndex,
};
use crate::runtime_body_source::{ProductBodySource, ProductBodySourceActivation};
use crate::safety::{GuardedBody, WireBodyQuotaKey};
use crate::standalone_provider_result::{
    adapt_local_allow, adapt_provider_allow, StandaloneAllowMode, StandaloneProviderAllowError,
    StandaloneRequestSidecar,
};

pub(crate) struct TokioRuntimeClock {
    epoch: Instant,
    unix_epoch_millis: u64,
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
        let rounded = u64::from(!elapsed.subsec_nanos().is_multiple_of(1_000_000));
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

pub(crate) struct StandaloneProviderInput {
    pub(crate) request_id: String,
    pub(crate) validated: ValidatedStandaloneIngress,
    pub(crate) peer_ip: IpAddr,
    pub(crate) quota_key: WireBodyQuotaKey,
    pub(crate) started_at: Instant,
    pub(crate) preflight_target: PreflightForwardingTarget,
    pub(crate) destinations: Arc<DestinationGuard>,
    pub(crate) clock: Arc<TokioRuntimeClock>,
    pub(crate) listener_denied: bool,
    pub(crate) decision_target: DecisionSubmissionTarget,
}

pub(crate) trait StandaloneTerminalService: Send + 'static {
    type Output: Send + 'static;

    fn fail_closed(self, error: RequestPipelineError) -> BoxFuture<'static, Self::Output>;

    fn respond(self, dispatch: StandaloneResponseDispatch) -> BoxFuture<'static, Self::Output>;

    fn forward(self, dispatch: StandaloneForwardDispatch) -> BoxFuture<'static, Self::Output>;
}

pub(crate) struct StandalonePolicyProvider<T> {
    terminal: Mutex<Option<T>>,
    decision: Mutex<Option<PreparedDecision>>,
    dispatch: Mutex<Option<PreparedDispatch>>,
    responses: Mutex<PreparedResponses>,
    response_observation: Mutex<Option<StandaloneResponseObservation>>,
    decision_source: Mutex<Option<DecisionAuditSource>>,
    response_decision: Mutex<Option<PendingDecisionSubmission>>,
    audit: DecisionAuditContext,
}

pub(crate) struct StandaloneResponseDispatch {
    pub(crate) response: RuntimeResponse,
    pub(crate) observation: Option<StandaloneResponseObservation>,
    pub(crate) decision: PendingDecisionSubmission,
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
    peer_ip: IpAddr,
    quota_key: WireBodyQuotaKey,
    body_budget: BodyBudget,
    body_budget_activation: BodyBudgetActivation,
    body_source_activation: ProductBodySourceActivation,
    prepared_target: PreparedForwardingTarget,
    early_deny_source: Option<DecisionAuditSource>,
    ingress_body_complete: bool,
}

struct PreparedTerminalState {
    generation: GenerationLease,
    request_id: String,
    quota_key: WireBodyQuotaKey,
    deadline: Instant,
    destinations: Arc<DestinationGuard>,
    transport: StandaloneIngressTransport,
}

struct PreparedDispatch {
    services: ForwardingGenerationServices,
    request_id: String,
    quota_key: WireBodyQuotaKey,
    retention: GenerationRetention,
    deadline: Instant,
    destinations: Arc<DestinationGuard>,
    resolved: ResolvedForwardingTarget,
    sidecar: StandaloneRequestSidecar,
    credentials: Option<ProductCredentialPreparation>,
    transport: StandaloneIngressTransport,
    decision: PendingDecisionSubmission,
}

pub(crate) enum StandaloneIngressTransport {
    Ordinary {
        parts: Box<http::request::Parts>,
        protocol: OriginProtocol,
        downstream_upgrade: Option<hyper::upgrade::OnUpgrade>,
    },
    OuterConnect {
        protocol: OriginProtocol,
        downstream_upgrade: hyper::upgrade::OnUpgrade,
    },
}

impl StandaloneIngressTransport {
    fn protocol(&self) -> OriginProtocol {
        match self {
            Self::Ordinary { protocol, .. } | Self::OuterConnect { protocol, .. } => *protocol,
        }
    }

    fn matches_facts(&self, facts: &http_access_types::InterceptedRequestFacts) -> bool {
        match self {
            Self::Ordinary {
                downstream_upgrade, ..
            } => downstream_upgrade.is_some() == facts.upgrade().is_some(),
            Self::OuterConnect { protocol, .. } => {
                *protocol == OriginProtocol::Http1
                    && facts.method().as_str() == "CONNECT"
                    && facts.upgrade().is_none()
            }
        }
    }

    fn allow_mode(&self) -> StandaloneAllowMode {
        match self {
            Self::Ordinary { .. } => StandaloneAllowMode::OriginRequest,
            Self::OuterConnect { .. } => StandaloneAllowMode::OuterConnect,
        }
    }
}

pub(crate) struct StandaloneForwardDispatch {
    pub(crate) exchange: StandaloneExchange,
    pub(crate) services: ForwardingGenerationServices,
    pub(crate) request_id: String,
    pub(crate) quota_key: WireBodyQuotaKey,
    pub(crate) retention: GenerationRetention,
    pub(crate) deadline: Instant,
    pub(crate) destinations: Arc<DestinationGuard>,
    pub(crate) resolved: ResolvedForwardingTarget,
    pub(crate) sidecar: StandaloneRequestSidecar,
    pub(crate) credentials: Option<ProductCredentialPreparation>,
    pub(crate) transport: StandaloneIngressTransport,
    pub(crate) decision: PendingDecisionSubmission,
}

struct DecisionAuditContext {
    target: DecisionSubmissionTarget,
    request_id: StableId,
    method: HttpMethod,
    url: http_access_types::CanonicalUrl,
    peer_ip: IpAddr,
    sensitive_header_presence: Box<[NeutralHeaderName]>,
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
    body: Option<RuntimeBody>,
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
    Facts(#[from] FactsError),
    #[error("forwarding target does not belong to this request")]
    Target,
    #[error("ingress transport does not match checked request facts")]
    Transport,
    #[error("request deadline cannot be represented")]
    Deadline,
    #[error("request body contract is invalid")]
    Body(#[from] http_access_runtime::RuntimeError),
    #[error("request policy evaluation failed")]
    Policy,
}

impl<T> StandalonePolicyProvider<T>
where
    T: StandaloneTerminalService,
{
    pub(crate) fn prepare(
        lease: GenerationLease,
        terminal: T,
        input: StandaloneProviderInput,
    ) -> Result<(Self, RuntimeRequest), StandaloneProviderPrepareError> {
        let (shape, ingress) = input.validated.into_parts();
        let (mut headers, ingress_body, transport) = match ingress {
            SanitizedStandaloneIngress::Ordinary(ingress) => {
                let (mut parts, body, protocol, downstream_upgrade) = ingress.into_parts();
                let headers = std::mem::take(&mut parts.headers);
                (
                    headers,
                    body,
                    StandaloneIngressTransport::Ordinary {
                        parts: Box::new(parts),
                        protocol,
                        downstream_upgrade,
                    },
                )
            }
            SanitizedStandaloneIngress::OuterConnect(ingress) => {
                let (mut parts, body, protocol, downstream_upgrade) = ingress.into_parts();
                let headers = std::mem::take(&mut parts.headers);
                (
                    headers,
                    body,
                    StandaloneIngressTransport::OuterConnect {
                        protocol,
                        downstream_upgrade,
                    },
                )
            }
        };
        let ingress_body_complete = ingress_body.is_end_stream();
        let audit_request_id = StableId::new(input.request_id.clone())
            .map_err(|_| StandaloneProviderPrepareError::RequestId)?;
        let transport_protocol = transport.protocol();
        let audit_sensitive_header_presence = lease
            .standalone()
            .sensitive_header_policy()
            .names()
            .iter()
            .filter(|name| headers.contains_key(name.as_str()))
            .cloned()
            .collect();
        let sensitive_headers = lease.standalone().sensitive_headers().to_vec();
        let mut sensitive_header_presence = Vec::new();
        sensitive_header_presence
            .try_reserve_exact(sensitive_headers.len())
            .map_err(|_| StandaloneProviderPrepareError::HeaderFacts)?;
        for name in &sensitive_headers {
            if headers.contains_key(name.as_str()) {
                sensitive_header_presence.push(name.clone());
            }
        }
        let inbound = lease.credentials().extract(&mut headers)?;
        let internal_context = take_internal_context(
            &mut headers,
            lease.authorization().internal_context_headers(),
        )?;
        if sensitive_headers
            .iter()
            .any(|name| headers.contains_key(name.as_str()))
        {
            return Err(StandaloneProviderPrepareError::HeaderFacts);
        }
        let facts = shape.into_facts(&headers)?;
        let audit_method = facts.method().clone();
        let audit_url = facts.url().clone();
        if transport_protocol != ingress_protocol(facts.version())
            || !transport.matches_facts(&facts)
        {
            return Err(StandaloneProviderPrepareError::Transport);
        }
        let header_facts = PolicyHeaderFacts::from_partitioned(
            facts.headers().to_vec(),
            sensitive_header_presence,
            sensitive_headers,
        )
        .map_err(|_| StandaloneProviderPrepareError::HeaderFacts)?;
        let prepared_target = input
            .preflight_target
            .bind_for_request(
                facts.url(),
                transport_protocol,
                lease.egress(),
                &input.destinations,
            )
            .map_err(|_| StandaloneProviderPrepareError::Target)?;

        let evaluation_input = EvaluationInput::new(
            &facts,
            input.peer_ip,
            &header_facts,
            RuntimeRequest::INITIAL_REVISION,
            BodyRepresentation::PreservedContentCoded,
            BodyObservation::unobserved(),
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
        let deadline = input
            .started_at
            .checked_add(request_timeout)
            .ok_or(StandaloneProviderPrepareError::Deadline)?;
        let absolute_deadline_millis = input
            .clock
            .deadline_millis(deadline)
            .ok_or(StandaloneProviderPrepareError::Deadline)?;
        let early_deny_source = if input.listener_denied {
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
        let (source, body_source_activation) = ProductBodySource::unarmed(
            ingress_body,
            limits.chunk_bytes(),
            trailer_count,
            trailer_bytes,
        )?;
        let (body_budget, body_budget_activation) = BodyBudget::unarmed();
        let runtime_clock: Arc<dyn Clock> = input.clock.clone();
        let body = RuntimeBody::new(
            Box::pin(source),
            bounds,
            runtime_clock,
            body_budget.clone(),
            absolute_deadline_millis,
        )?;
        let request = RuntimeRequest::new(
            facts,
            input.peer_ip,
            header_facts,
            BodyRepresentation::PreservedContentCoded,
            body,
            absolute_deadline_millis,
        )?;
        if request.binding()? != initial_binding
            || request.body_observation()?.state() != BodyObservationState::Unobserved
        {
            return Err(StandaloneProviderPrepareError::Body(
                http_access_runtime::RuntimeError::InvalidInput,
            ));
        }
        let responses = PreparedResponses::new(&request, input.clock.clone())?;
        let audit = DecisionAuditContext {
            target: input.decision_target,
            request_id: audit_request_id,
            method: audit_method,
            url: audit_url,
            peer_ip: input.peer_ip,
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
                request_id: input.request_id.clone(),
                quota_key: input.quota_key.clone(),
                deadline,
                destinations: input.destinations,
                transport,
            }),
            initial_binding,
            evaluation,
            body_read_plan,
            wire_body_plan,
            request_id: input.request_id,
            headers,
            inbound,
            internal_context,
            peer_ip: input.peer_ip,
            quota_key: input.quota_key,
            body_budget,
            body_budget_activation,
            body_source_activation,
            prepared_target,
            early_deny_source,
            ingress_body_complete,
        };
        Ok((
            Self {
                terminal: Mutex::new(Some(terminal)),
                decision: Mutex::new(Some(prepared)),
                dispatch: Mutex::new(None),
                responses: Mutex::new(responses),
                response_observation: Mutex::new(None),
                decision_source: Mutex::new(None),
                response_decision: Mutex::new(None),
                audit,
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
        let allow_mode = terminal.transport.allow_mode();
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
            let close_connection = !state.ingress_body_complete;
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

        let resolution = tokio::time::timeout_at(
            deadline,
            resolve_forwarding_target(state.prepared_target, &terminal.destinations),
        )
        .await;
        if Instant::now() >= deadline {
            return Err(504);
        }
        let resolved = match resolution {
            Ok(Ok(resolved)) => resolved,
            Ok(Err(_)) => return Err(403),
            Err(_) => return Err(504),
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
        state
            .body_source_activation
            .activate(&guard, staging)
            .map_err(|_| 500_u16)?;

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
                        replay_lease,
                        request,
                    )
                    .map_err(adapter_error_status)?;
                    self.set_decision_source(DecisionAuditSource::Policy(provenance));
                    let terminal = state.terminal.take().ok_or(500_u16)?;
                    return self.finish_forward(resolved, allowed, terminal);
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
                    let peer_ip = state.peer_ip.to_string();
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
                        url: request.facts().url().as_str(),
                        method: request.facts().method().as_str(),
                        client_ip: &peer_ip,
                        headers: (!included.is_empty()).then_some(&provider_headers),
                        body: provider_body,
                    };
                    let decision = generation
                        .dispatch_authorization(
                            provider,
                            rule_id,
                            provider_request,
                            invocation_mode,
                            &guard,
                            deadline,
                        )
                        .await;
                    if Instant::now() >= deadline {
                        return Err(504);
                    }
                    let decision = match decision {
                        Ok(decision) => decision,
                        Err(_) if metadata.failure_mode == CompiledProviderFailureMode::Deny => {
                            let policy_result = resolve_delegate(
                                generation,
                                delegated,
                                ProviderDisposition::Deny,
                                &request,
                                state.peer_ip,
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
                                state.peer_ip,
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
                                    replay_lease,
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
                            let terminal = state.terminal.take().ok_or(500_u16)?;
                            self.set_decision_source(DecisionAuditSource::Policy(provenance));
                            return self.finish_forward(resolved, allowed, terminal);
                        }
                        AuthorizationDecision::Deny => {
                            let policy_result = resolve_delegate(
                                generation,
                                delegated,
                                ProviderDisposition::Deny,
                                &request,
                                state.peer_ip,
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
                                state.peer_ip,
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
    ) -> Result<ProviderOutcome, u16> {
        let crate::standalone_provider_result::StandaloneProviderAllow {
            plan,
            request,
            sidecar,
            credentials,
        } = allowed;
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
            deadline: terminal.deadline,
            destinations: terminal.destinations,
            resolved,
            sidecar,
            credentials,
            transport: terminal.transport,
            decision,
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

    fn take_terminal(&self) -> T {
        lock(&self.terminal)
            .take()
            .expect("the consumed request context owns one terminal service")
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
    ) -> Result<Self, http_access_runtime::RuntimeError> {
        let bounds = BodyBounds::new(1, 1, 1, 0, 0, 600_000)?;
        let policy = request.local_response_policy(bounds, 8, 4_096)?;
        let runtime_clock: Arc<dyn Clock> = clock;
        let mut body = RuntimeBody::from_chunks(
            Vec::new(),
            bounds,
            runtime_clock,
            BodyBudget::new(1)?,
            request.absolute_deadline_millis(),
        )?;
        let mut context = Context::from_waker(std::task::Waker::noop());
        if !matches!(body.poll_next_chunk(&mut context), Poll::Ready(Ok(None)))
            || !matches!(body.poll_trailers(&mut context), Poll::Ready(Ok(None)))
        {
            return Err(http_access_runtime::RuntimeError::InvalidInput);
        }
        Ok(Self {
            policy,
            body: Some(body),
        })
    }

    fn build(&mut self, status: u16) -> Result<RuntimeResponse, http_access_runtime::RuntimeError> {
        let body = self
            .body
            .take()
            .ok_or(http_access_runtime::RuntimeError::InvalidInput)?;
        RuntimeResponse::new(status, Vec::new(), body, self.policy)
    }
}

impl<T> DecisionProvider for StandalonePolicyProvider<T>
where
    T: StandaloneTerminalService,
{
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

impl<T> StandaloneDispatch for StandalonePolicyProvider<T>
where
    T: StandaloneTerminalService,
{
    type Output = T::Output;

    fn fail_closed(&self, error: RequestPipelineError) -> BoxFuture<'_, Self::Output> {
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
        self.take_terminal().fail_closed(error)
    }

    fn respond(&self, response: RuntimeResponse) -> BoxFuture<'_, Self::Output> {
        if let Some(dispatch) = lock(&self.dispatch).take() {
            dispatch.decision.discard();
        }
        let observation = lock(&self.response_observation).take();
        self.take_terminal().respond(StandaloneResponseDispatch {
            response,
            observation,
            decision: lock(&self.response_decision).take().unwrap_or_else(|| {
                self.audit.pending(
                    DecisionDisposition::Deny,
                    local_source(DecisionReasonCategory::InvalidPlan, 5),
                )
            }),
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
        let terminal = self.take_terminal();
        terminal.forward(StandaloneForwardDispatch {
            exchange,
            services: dispatch.services,
            request_id: dispatch.request_id,
            quota_key: dispatch.quota_key,
            retention: dispatch.retention,
            deadline: dispatch.deadline,
            destinations: dispatch.destinations,
            resolved: dispatch.resolved,
            sidecar: dispatch.sidecar,
            credentials: dispatch.credentials,
            transport: dispatch.transport,
            decision: dispatch.decision,
        })
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

fn adapter_error_status(error: StandaloneProviderAllowError) -> u16 {
    match error {
        StandaloneProviderAllowError::ProviderReplacement(
            ProviderBodyReplacementDecodeError::ProviderBodyLimit
            | ProviderBodyReplacementDecodeError::RedactionBodyLimit,
        ) => 413,
        StandaloneProviderAllowError::ProviderReplacement(
            ProviderBodyReplacementDecodeError::InvalidBody,
        ) => 415,
        StandaloneProviderAllowError::ContentType => 500,
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
        | StandaloneProviderAllowError::Plan(_) => 500,
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

fn take_internal_context(
    headers: &mut HeaderMap,
    names: &[HeaderName],
) -> Result<HeaderMap, StandaloneProviderPrepareError> {
    let mut ordinary = HeaderMap::new();
    ordinary
        .try_reserve(headers.len())
        .map_err(|_| StandaloneProviderPrepareError::HeaderFacts)?;
    let mut internal = HeaderMap::new();
    internal
        .try_reserve(names.len())
        .map_err(|_| StandaloneProviderPrepareError::HeaderFacts)?;
    let mut current_name = None;
    for (name, value) in headers.drain() {
        if let Some(name) = name {
            current_name = Some(name);
        }
        let name = current_name
            .as_ref()
            .ok_or(StandaloneProviderPrepareError::HeaderFacts)?;
        let target = if names.contains(name) {
            &mut internal
        } else {
            &mut ordinary
        };
        target
            .try_append(name.clone(), value)
            .map_err(|_| StandaloneProviderPrepareError::HeaderFacts)?;
    }
    *headers = ordinary;
    Ok(internal)
}

fn ingress_protocol(version: HttpVersion) -> OriginProtocol {
    match version {
        HttpVersion::Http10 | HttpVersion::Http11 => OriginProtocol::Http1,
        HttpVersion::Http2 => OriginProtocol::Http2,
    }
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
    peer_ip: IpAddr,
) -> Result<PolicyEvaluation<ProductRuleEffectsRef>, u16> {
    let input = EvaluationInput::new(
        request.facts(),
        peer_ip,
        request.policy_header_facts(),
        RuntimeRequest::INITIAL_REVISION,
        BodyRepresentation::PreservedContentCoded,
        BodyObservation::unobserved(),
    )
    .map_err(|_| 500_u16)?;
    generation
        .standalone()
        .product_acl()
        .snapshot()
        .resolve_delegate(delegated, disposition, &input)
        .map_err(|_| 500_u16)
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
mod tests {
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use http::{Method, Request, Version};
    use http_access_types::IngressMode;
    use hyper::Body;

    use super::*;
    use crate::activation::static_resources::ProductStaticResources;
    use crate::config::{compile_config_text, CompiledConfig, ConfigTextInput};
    use crate::destination::{
        DestinationFacts, DestinationResolver, LocalAddressSnapshot, LocalAddressSource,
        ResolveFuture,
    };
    use crate::proxy::facts::{
        validate_standalone_connect_ingress_request, validate_standalone_ingress_request,
    };
    use crate::proxy::forward::preflight_forwarding_target;
    use crate::request_pipeline::RequestPipeline;
    use crate::runtime::{
        ActivationCancellation, CandidateSource, Runtime, RuntimeError, StaticOwnership,
    };

    const CONFIG_PREFIX: &str = r#"schema_version = 3

[service]
request_timeout = "5s"
max_retiring_generations = 4

[listeners.explicit_http]
bind = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[egress]
route = "direct"

[egress.origin_tls]
trust = "system"

[observation.logging]
level = "info"
console = true

[safety.loop_detection]
inject = true
header = "x-test-loop"
"#;

    struct EmptySource;

    impl CandidateSource for EmptySource {
        fn load_latest(
            &self,
            _cancellation: ActivationCancellation,
        ) -> BoxFuture<'_, Result<CompiledConfig, RuntimeError>> {
            Box::pin(async { Err(RuntimeError::CandidateSource("unused".into())) })
        }
    }

    struct FixedResolver {
        calls: Arc<AtomicUsize>,
    }

    impl DestinationResolver for FixedResolver {
        fn resolve(&self, _host: &str, port: u16, _max_addresses: usize) -> ResolveFuture<'_> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Ok(vec![SocketAddr::new(
                    Ipv4Addr::new(203, 0, 113, 10).into(),
                    port,
                )])
            })
        }
    }

    struct NoLocalAddresses;

    impl LocalAddressSource for NoLocalAddresses {
        fn snapshot(&self) -> io::Result<LocalAddressSnapshot> {
            Ok(LocalAddressSnapshot::default())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Terminal {
        Response(u16),
        Forward,
        FailClosed,
    }

    struct TestTerminal;

    impl StandaloneTerminalService for TestTerminal {
        type Output = Terminal;

        fn fail_closed(self, _error: RequestPipelineError) -> BoxFuture<'static, Self::Output> {
            Box::pin(async { Terminal::FailClosed })
        }

        fn respond(self, dispatch: StandaloneResponseDispatch) -> BoxFuture<'static, Self::Output> {
            let status = dispatch.response.status();
            Box::pin(async move { Terminal::Response(status) })
        }

        fn forward(self, dispatch: StandaloneForwardDispatch) -> BoxFuture<'static, Self::Output> {
            Box::pin(async move {
                drop((self, dispatch));
                Terminal::Forward
            })
        }
    }

    #[derive(Debug)]
    enum AuditedTerminal {
        Response(u16, DecisionAuditSource, Box<[String]>),
        Forward(DecisionAuditSource, Box<[String]>),
        FailClosed,
    }

    struct AuditTerminal;

    impl StandaloneTerminalService for AuditTerminal {
        type Output = AuditedTerminal;

        fn fail_closed(self, _error: RequestPipelineError) -> BoxFuture<'static, Self::Output> {
            Box::pin(async { AuditedTerminal::FailClosed })
        }

        fn respond(self, dispatch: StandaloneResponseDispatch) -> BoxFuture<'static, Self::Output> {
            let status = dispatch.response.status();
            let facts = dispatch
                .decision
                .facts()
                .expect("response carries one pending decision");
            assert_eq!(facts.disposition(), DecisionDisposition::Deny);
            let source = facts.source().clone();
            let presence = facts
                .sensitive_header_presence()
                .iter()
                .map(|name| name.as_str().to_owned())
                .collect();
            Box::pin(async move { AuditedTerminal::Response(status, source, presence) })
        }

        fn forward(self, dispatch: StandaloneForwardDispatch) -> BoxFuture<'static, Self::Output> {
            let facts = dispatch
                .decision
                .facts()
                .expect("forward carries one pending decision");
            assert_eq!(facts.disposition(), DecisionDisposition::Allow);
            let source = facts.source().clone();
            let presence = facts
                .sensitive_header_presence()
                .iter()
                .map(|name| name.as_str().to_owned())
                .collect();
            Box::pin(async move { AuditedTerminal::Forward(source, presence) })
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct ObservedResponse {
        status: u16,
        close_connection: bool,
        body_provenance: StandaloneResponseBodyProvenance,
    }

    struct ObservationTerminal;

    impl StandaloneTerminalService for ObservationTerminal {
        type Output = ObservedResponse;

        fn fail_closed(self, _error: RequestPipelineError) -> BoxFuture<'static, Self::Output> {
            Box::pin(async {
                ObservedResponse {
                    status: 500,
                    close_connection: true,
                    body_provenance: StandaloneResponseBodyProvenance::Unconsumed,
                }
            })
        }

        fn respond(self, dispatch: StandaloneResponseDispatch) -> BoxFuture<'static, Self::Output> {
            Box::pin(async move {
                let observation = dispatch
                    .observation
                    .expect("the policy provider records denial state");
                ObservedResponse {
                    status: dispatch.response.status(),
                    close_connection: observation.close_connection,
                    body_provenance: observation.body_provenance,
                }
            })
        }

        fn forward(self, _dispatch: StandaloneForwardDispatch) -> BoxFuture<'static, Self::Output> {
            Box::pin(async {
                ObservedResponse {
                    status: 200,
                    close_connection: false,
                    body_provenance: StandaloneResponseBodyProvenance::Unconsumed,
                }
            })
        }
    }

    struct ConnectTerminal;

    impl StandaloneTerminalService for ConnectTerminal {
        type Output = Terminal;

        fn fail_closed(self, _error: RequestPipelineError) -> BoxFuture<'static, Self::Output> {
            Box::pin(async { Terminal::FailClosed })
        }

        fn respond(self, dispatch: StandaloneResponseDispatch) -> BoxFuture<'static, Self::Output> {
            let status = dispatch.response.status();
            Box::pin(async move { Terminal::Response(status) })
        }

        fn forward(self, dispatch: StandaloneForwardDispatch) -> BoxFuture<'static, Self::Output> {
            Box::pin(async move {
                assert_eq!(dispatch.exchange.facts().method().as_str(), "CONNECT");
                assert!(dispatch.exchange.facts().upgrade().is_none());
                assert!(matches!(
                    &dispatch.transport,
                    StandaloneIngressTransport::OuterConnect {
                        protocol: OriginProtocol::Http1,
                        ..
                    }
                ));
                drop((self, dispatch));
                Terminal::Forward
            })
        }
    }

    struct UpgradeTerminal;

    impl StandaloneTerminalService for UpgradeTerminal {
        type Output = Terminal;

        fn fail_closed(self, _error: RequestPipelineError) -> BoxFuture<'static, Self::Output> {
            Box::pin(async move { Terminal::FailClosed })
        }

        fn respond(self, dispatch: StandaloneResponseDispatch) -> BoxFuture<'static, Self::Output> {
            Box::pin(async move {
                let status = dispatch.response.status();
                Terminal::Response(status)
            })
        }

        fn forward(self, dispatch: StandaloneForwardDispatch) -> BoxFuture<'static, Self::Output> {
            Box::pin(async move {
                assert_eq!(
                    dispatch.exchange.plan().request_body().trailer_policy(),
                    TrailerPolicy::Deny
                );
                assert_eq!(
                    dispatch.exchange.plan().request_body().representation(),
                    BodyRepresentation::PreservedContentCoded
                );
                assert!(matches!(
                    &dispatch.transport,
                    StandaloneIngressTransport::Ordinary {
                        downstream_upgrade: Some(_),
                        ..
                    }
                ));
                drop(dispatch);
                Terminal::Forward
            })
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    enum BodyTerminalOutcome {
        Response(u16),
        Forward(Vec<u8>, DecisionAuditSource),
        FailClosed,
    }

    struct BodyTerminal;

    impl StandaloneTerminalService for BodyTerminal {
        type Output = BodyTerminalOutcome;

        fn fail_closed(self, _error: RequestPipelineError) -> BoxFuture<'static, Self::Output> {
            Box::pin(async { BodyTerminalOutcome::FailClosed })
        }

        fn respond(self, dispatch: StandaloneResponseDispatch) -> BoxFuture<'static, Self::Output> {
            let status = dispatch.response.status();
            Box::pin(async move { BodyTerminalOutcome::Response(status) })
        }

        fn forward(
            self,
            mut dispatch: StandaloneForwardDispatch,
        ) -> BoxFuture<'static, Self::Output> {
            let facts = dispatch
                .decision
                .facts()
                .expect("forward carries one pending decision");
            assert_eq!(facts.disposition(), DecisionDisposition::Allow);
            let source = facts.source().clone();
            Box::pin(async move {
                let mut bytes = Vec::new();
                while let Some(chunk) =
                    std::future::poll_fn(|context| dispatch.exchange.poll_body_chunk(context))
                        .await
                        .unwrap()
                {
                    bytes.extend_from_slice(chunk.as_bytes());
                }
                drop((self, dispatch));
                BodyTerminalOutcome::Forward(bytes, source)
            })
        }
    }

    fn compiled(default: &str) -> CompiledConfig {
        compiled_text(&format!("[policy]\ndefault = \"{default}\"\n"))
    }

    fn compiled_text(suffix: &str) -> CompiledConfig {
        let directory = Path::new("/tmp/p06-standalone-policy-provider");
        std::fs::create_dir_all(directory).unwrap();
        let text = format!("{CONFIG_PREFIX}\n{suffix}");
        compile_config_text(ConfigTextInput {
            text: &text,
            source_path: &directory.join("acl-proxy.toml"),
            config_root: directory,
        })
        .unwrap()
    }

    async fn runtime(
        default: &str,
        resolver_calls: Arc<AtomicUsize>,
    ) -> (Arc<Runtime>, Arc<DestinationGuard>) {
        runtime_from(compiled(default), resolver_calls).await
    }

    async fn runtime_with_allow_observation(
        default: &str,
        resolver_calls: Arc<AtomicUsize>,
    ) -> (Arc<Runtime>, Arc<DestinationGuard>) {
        runtime_from(
            compiled_text(&format!(
                "[policy]\ndefault = \"{default}\"\n\n[observation.logging.policy_decisions]\nallows = true\n"
            )),
            resolver_calls,
        )
        .await
    }

    async fn runtime_from(
        initial: CompiledConfig,
        resolver_calls: Arc<AtomicUsize>,
    ) -> (Arc<Runtime>, Arc<DestinationGuard>) {
        let facts = DestinationFacts::from_static(&initial.static_config).unwrap();
        let destinations = Arc::new(DestinationGuard::with_sources(
            facts,
            Arc::new(FixedResolver {
                calls: resolver_calls,
            }),
            Arc::new(NoLocalAddresses),
        ));
        let resources = ProductStaticResources::try_new_with_destination_guard(
            &initial.static_config,
            destinations.clone(),
        )
        .unwrap();
        let activator = resources.activator();
        let ownership = StaticOwnership::new(
            initial.static_config.clone(),
            initial.static_fingerprint.clone(),
            resources,
        );
        let runtime = Runtime::new(ownership, Arc::new(EmptySource), activator)
            .await
            .unwrap();
        runtime.start(initial).await.unwrap();
        (runtime, destinations)
    }

    #[cfg(unix)]
    fn process_provider_config(command: &Path, decision: &str) -> CompiledConfig {
        compiled_text(&format!(
            r#"[authorization.providers.provider]
kind = "process"
command = "{}"
timeout = "2s"
retire_timeout = "6s"
include_request_body = true
max_request_body_bytes = 4096
max_decoded_request_body_bytes = 4096

[policy]
default = "deny"

[observation.logging.policy_decisions]
allows = true

[[policy.rules]]
id = "delegate"
decision = "delegate"
methods = ["GET"]
authorization_provider = "provider"

[[policy.rules]]
id = "after-pass"
decision = "{}"
methods = ["GET"]
"#,
            command.display(),
            decision
        ))
    }

    #[cfg(unix)]
    fn process_provider_without_body_config(command: &Path, decision: &str) -> CompiledConfig {
        compiled_text(&format!(
            r#"[authorization.providers.provider]
kind = "process"
command = "{}"
timeout = "2s"
retire_timeout = "6s"
on_failure = "deny"
include_request_body = false
max_request_body_bytes = 4096
max_decoded_request_body_bytes = 4096

[policy]
default = "deny"

[[policy.rules]]
id = "delegate"
decision = "delegate"
methods = ["GET"]
authorization_provider = "provider"

[[policy.rules]]
id = "after-pass"
decision = "{}"
methods = ["GET"]
"#,
            command.display(),
            decision
        ))
    }

    #[cfg(unix)]
    fn outer_connect_process_provider_config(command: &Path, after_pass: &str) -> CompiledConfig {
        compiled_text(&format!(
            r#"[authorization.providers.provider]
kind = "process"
command = "{}"
timeout = "2s"
retire_timeout = "6s"
on_failure = "error"
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 4096
max_decoded_request_body_bytes = 4096
max_stdout_line_bytes = 4096

[authorization.providers.provider.outputs.token]
kind = "bearer"
required = true

[policy]
default = "deny"

[[policy.rules]]
id = "delegate-connect"
decision = "delegate"
methods = ["CONNECT"]
authorization_provider = "provider"

[[policy.rules]]
id = "after-pass"
decision = "{}"
methods = ["CONNECT"]
"#,
            command.display(),
            after_pass
        ))
    }

    #[cfg(unix)]
    fn process_script(
        directory: &Path,
        decision: &str,
        marker: Option<&Path>,
    ) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = directory.join("provider.sh");
        let marker_write = marker
            .map(|path| format!("printf x >> '{}'\n", path.display()))
            .unwrap_or_default();
        std::fs::write(
            &path,
            format!(
                r#"#!/bin/sh
while IFS= read -r line; do
  {marker_write}  id=$(printf "%s" "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  [ -n "$id" ] && printf '{{"id":"%s","type":"response","decision":"{decision}"}}\n' "$id"
done
"#
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).unwrap();
        path
    }

    #[cfg(unix)]
    fn recording_process_script(
        directory: &Path,
        decision: &str,
        marker: &Path,
    ) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = directory.join("recording-provider.sh");
        std::fs::write(
            &path,
            format!(
                r#"#!/bin/sh
while IFS= read -r line; do
  printf '%s\n' "$line" >> '{}'
  id=$(printf "%s" "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  [ -n "$id" ] && printf '{{"id":"%s","type":"response","decision":"{decision}"}}\n' "$id"
done
"#,
                marker.display()
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn prepared_input(
        lease: &GenerationLease,
        destinations: Arc<DestinationGuard>,
        body: Body,
        extra_headers: &[(&str, &str)],
    ) -> StandaloneProviderInput {
        let mut request = Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_11)
            .uri("/resource")
            .header("host", "standalone-provider.example.test")
            .body(body)
            .unwrap();
        for (name, value) in extra_headers {
            request.headers_mut().insert(
                http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                http::HeaderValue::from_str(value).unwrap(),
            );
        }
        prepared_input_from_request(lease, destinations, request)
    }

    fn prepared_input_from_request(
        lease: &GenerationLease,
        destinations: Arc<DestinationGuard>,
        request: Request<Body>,
    ) -> StandaloneProviderInput {
        let canonical = http_access_url::canonicalize_http_url(
            "http://standalone-provider.example.test/resource",
        )
        .unwrap();
        let validated = validate_standalone_ingress_request(
            IngressMode::ExplicitHttp,
            canonical.clone(),
            request,
        )
        .unwrap();
        let preflight_target = preflight_forwarding_target(
            &canonical,
            validated.ingress().sanitized(),
            lease.egress(),
            &destinations,
        )
        .unwrap();
        let peer_ip = "192.0.2.10".parse().unwrap();
        let started_at = Instant::now();
        StandaloneProviderInput {
            request_id: "p06-provider-test".to_owned(),
            validated,
            peer_ip,
            quota_key: WireBodyQuotaKey::from_peer(peer_ip, |_| false),
            started_at,
            preflight_target,
            destinations,
            clock: TokioRuntimeClock::new(started_at),
            listener_denied: false,
            decision_target: DecisionSubmissionTarget::Disabled,
        }
    }

    fn prepared_connect_input(
        lease: &GenerationLease,
        destinations: Arc<DestinationGuard>,
    ) -> StandaloneProviderInput {
        let canonical =
            http_access_url::canonicalize_http_url("https://standalone-provider.example.test/")
                .unwrap();
        let request = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_11)
            .uri("standalone-provider.example.test:443")
            .header("host", "standalone-provider.example.test:443")
            .body(Body::empty())
            .unwrap();
        let validated = validate_standalone_connect_ingress_request(
            IngressMode::ExplicitHttp,
            canonical.clone(),
            request,
        )
        .unwrap();
        let preflight_target = preflight_forwarding_target(
            &canonical,
            validated.ingress().sanitized(),
            lease.egress(),
            &destinations,
        )
        .unwrap();
        let peer_ip = "192.0.2.10".parse().unwrap();
        let started_at = Instant::now();
        StandaloneProviderInput {
            request_id: "p06-connect-provider-test".to_owned(),
            validated,
            peer_ip,
            quota_key: WireBodyQuotaKey::from_peer(peer_ip, |_| false),
            started_at,
            preflight_target,
            destinations,
            clock: TokioRuntimeClock::new(started_at),
            listener_denied: false,
            decision_target: DecisionSubmissionTarget::Disabled,
        }
    }

    #[tokio::test]
    async fn default_allow_resolves_once_and_forwards_through_the_common_pipeline() {
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let (runtime, destinations) =
            runtime_with_allow_observation("allow", resolver_calls.clone()).await;
        let lease = runtime.lease().await.unwrap();
        let mut input = prepared_input(&lease, destinations, Body::empty(), &[]);
        let submissions = Arc::new(AtomicUsize::new(0));
        input.decision_target = DecisionSubmissionTarget::Probe(submissions.clone());
        let (provider, request) =
            StandalonePolicyProvider::prepare(lease, AuditTerminal, input).unwrap();

        let terminal = RequestPipeline::new().execute(provider, request).await;

        let AuditedTerminal::Forward(DecisionAuditSource::Policy(provenance), presence) = terminal
        else {
            panic!("default allow must retain policy provenance");
        };
        assert_eq!(provenance.effective_policy(), &EffectivePolicy::Default);
        assert!(presence.is_empty());
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
        assert_eq!(submissions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn oversized_provider_decision_is_omitted_without_affecting_the_next_submission() {
        let submissions = Arc::new(AtomicUsize::new(0));
        let context = |url| DecisionAuditContext {
            target: DecisionSubmissionTarget::Probe(submissions.clone()),
            request_id: StableId::new("provider-observation-bounds").unwrap(),
            method: HttpMethod::new("GET").unwrap(),
            url,
            peer_ip: "192.0.2.10".parse().unwrap(),
            sensitive_header_presence: Box::new([]),
            allow_level: Some(CompiledDecisionLogLevel::Info),
            deny_level: Some(CompiledDecisionLogLevel::Warn),
        };
        let source = || {
            DecisionAuditSource::Local(DecisionReason::new(
                DecisionReasonCategory::InvalidPlan,
                500,
            ))
        };
        let oversized = http_access_url::canonicalize_http_url(&format!(
            "https://example.test/{}",
            "x".repeat(1024 * 1024)
        ))
        .unwrap();
        let bounded = http_access_url::canonicalize_http_url("https://example.test/next").unwrap();

        context(oversized)
            .pending(DecisionDisposition::Deny, source())
            .submit_now();
        context(bounded)
            .pending(DecisionDisposition::Deny, source())
            .submit_now();

        assert_eq!(submissions.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fail_closed_replaces_pending_allow_with_one_deny_submission() {
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let (runtime, destinations) = runtime("allow", resolver_calls).await;
        let lease = runtime.lease().await.unwrap();
        let mut input = prepared_input(&lease, destinations, Body::empty(), &[]);
        let submissions = Arc::new(AtomicUsize::new(0));
        input.decision_target = DecisionSubmissionTarget::Probe(submissions.clone());
        let (provider, request) =
            StandalonePolicyProvider::prepare(lease, AuditTerminal, input).unwrap();
        let facts = request.facts().clone();

        let outcome = provider.decide(&facts, request).await;
        assert!(matches!(outcome, ProviderOutcome::Forward { .. }));
        let terminal = provider
            .fail_closed(RequestPipelineError::InvalidProviderOutput)
            .await;

        assert!(matches!(terminal, AuditedTerminal::FailClosed));
        assert_eq!(submissions.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn decision_presence_uses_full_observation_sensitive_union() {
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let (runtime, destinations) = runtime("deny", resolver_calls).await;
        let lease = runtime.lease().await.unwrap();
        let input = prepared_input(
            &lease,
            destinations,
            Body::empty(),
            &[("authorization", "secret"), ("cookie", "session=secret")],
        );
        let (provider, request) =
            StandalonePolicyProvider::prepare(lease, AuditTerminal, input).unwrap();

        let terminal = RequestPipeline::new().execute(provider, request).await;

        let AuditedTerminal::Response(403, _, presence) = terminal else {
            panic!("default deny must retain full sensitive-name presence");
        };
        assert_eq!(
            presence.as_ref(),
            &["authorization".to_owned(), "cookie".to_owned()]
        );
    }

    #[tokio::test]
    async fn outer_connect_owner_reaches_the_common_pipeline_without_becoming_an_ordinary_request()
    {
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let (runtime, destinations) = runtime("allow", resolver_calls.clone()).await;
        let lease = runtime.lease().await.unwrap();
        let input = prepared_connect_input(&lease, destinations);
        let (provider, request) =
            StandalonePolicyProvider::prepare(lease, ConnectTerminal, input).unwrap();

        let terminal = RequestPipeline::new().execute(provider, request).await;

        assert_eq!(terminal, Terminal::Forward);
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn delegated_outer_connect_uses_decision_only_process_dispatch() {
        for (provider_decision, after_pass, expected) in [
            ("allow", "deny", Terminal::Forward),
            ("deny", "allow", Terminal::Response(403)),
            ("pass", "allow", Terminal::Forward),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let marker = directory.path().join("requests.jsonl");
            let provider_script =
                recording_process_script(directory.path(), provider_decision, &marker);
            let resolver_calls = Arc::new(AtomicUsize::new(0));
            let config = outer_connect_process_provider_config(&provider_script, after_pass);
            let (runtime, destinations) = runtime_from(config, resolver_calls.clone()).await;
            let lease = runtime.lease().await.unwrap();
            let input = prepared_connect_input(&lease, destinations);
            let (provider, request) =
                StandalonePolicyProvider::prepare(lease, ConnectTerminal, input).unwrap();

            let terminal = RequestPipeline::new().execute(provider, request).await;

            assert_eq!(terminal, expected, "provider decision {provider_decision}");
            assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
            let requests = std::fs::read_to_string(&marker).unwrap();
            let mut lines = requests.lines();
            let request: serde_json::Value =
                serde_json::from_str(lines.next().expect("one provider request")).unwrap();
            assert!(lines.next().is_none());
            assert_eq!(request["type"], "request");
            assert_eq!(request["method"], "CONNECT");
            assert_eq!(request["url"], "https://standalone-provider.example.test/");
            assert!(request.get("body").is_none());
            runtime.shutdown().await;
        }
    }

    #[tokio::test]
    async fn policy_and_loop_denials_do_not_resolve_or_poll_the_body() {
        for (default, headers, policy_source) in [
            ("deny", &[][..], true),
            ("allow", &[("x-test-loop", "loop")][..], false),
        ] {
            let resolver_calls = Arc::new(AtomicUsize::new(0));
            let (runtime, destinations) = runtime(default, resolver_calls.clone()).await;
            let lease = runtime.lease().await.unwrap();
            let mut input = prepared_input(&lease, destinations, Body::empty(), headers);
            let submissions = Arc::new(AtomicUsize::new(0));
            input.decision_target = DecisionSubmissionTarget::Probe(submissions.clone());
            let (provider, request) =
                StandalonePolicyProvider::prepare(lease, AuditTerminal, input).unwrap();

            let terminal = RequestPipeline::new().execute(provider, request).await;

            let AuditedTerminal::Response(403, source, _) = terminal else {
                panic!("early denial must retain one audit source");
            };
            if policy_source {
                let DecisionAuditSource::Policy(provenance) = source else {
                    panic!("policy denial must retain policy provenance");
                };
                assert_eq!(provenance.effective_policy(), &EffectivePolicy::Default);
            } else {
                let DecisionAuditSource::Local(reason) = source else {
                    panic!("loop denial must be identified as local");
                };
                assert_eq!(reason.category(), DecisionReasonCategory::Loop);
            }
            assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
            assert_eq!(submissions.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn one_millisecond_deadline_ceil_does_not_round_current_time_up() {
        let epoch = Instant::now();
        let clock = TokioRuntimeClock::new(epoch);

        assert_eq!(
            clock.deadline_millis(epoch + Duration::from_millis(1)),
            Some(1)
        );
        assert_eq!(
            TokioRuntimeClock::monotonic_duration_millis(Duration::from_nanos(999_999)),
            Some(0)
        );
        assert_eq!(clock.epoch, epoch);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unread_declared_body_closes_for_provider_deny_failure_and_pass_resumed_deny() {
        for (provider_decision, resumed_decision) in
            [("deny", "allow"), ("invalid", "allow"), ("pass", "deny")]
        {
            let directory = tempfile::tempdir().unwrap();
            let provider_script = process_script(directory.path(), provider_decision, None);
            let resolver_calls = Arc::new(AtomicUsize::new(0));
            let config = process_provider_without_body_config(&provider_script, resumed_decision);
            let (runtime, destinations) = runtime_from(config, resolver_calls.clone()).await;
            let lease = runtime.lease().await.unwrap();
            let (mut sender, body) = Body::channel();
            let mut input = prepared_input(
                &lease,
                destinations,
                body,
                &[("content-length", "4"), ("content-type", "text/plain")],
            );
            let submissions = Arc::new(AtomicUsize::new(0));
            input.decision_target = DecisionSubmissionTarget::Probe(submissions.clone());
            let (provider, request) =
                StandalonePolicyProvider::prepare(lease, ObservationTerminal, input).unwrap();

            let response = RequestPipeline::new().execute(provider, request).await;

            assert_eq!(
                response,
                ObservedResponse {
                    status: 403,
                    close_connection: true,
                    body_provenance: StandaloneResponseBodyProvenance::Unconsumed,
                },
                "provider decision {provider_decision}, resumed decision {resumed_decision}"
            );
            assert!(sender
                .send_data(bytes::Bytes::from_static(b"late"))
                .await
                .is_err());
            assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
            assert_eq!(submissions.load(Ordering::SeqCst), 1);
            runtime.shutdown().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn foreign_preflight_guard_fails_before_resolution_or_provider_dispatch() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("provider-dispatched");
        let provider_script = process_script(directory.path(), "allow", Some(&marker));
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let config = process_provider_config(&provider_script, "deny");
        let (runtime, destinations) = runtime_from(config, resolver_calls.clone()).await;
        let lease = runtime.lease().await.unwrap();
        let mut input = prepared_input(&lease, destinations, Body::empty(), &[]);
        input.destinations = Arc::new(DestinationGuard::with_sources(
            DestinationFacts::for_test([], None, None, 8).unwrap(),
            Arc::new(FixedResolver {
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(NoLocalAddresses),
        ));

        assert!(matches!(
            StandalonePolicyProvider::prepare(lease, TestTerminal, input),
            Err(StandaloneProviderPrepareError::Target)
        ));
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
        assert!(!marker.exists());
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn upgrade_uses_trailer_deny_bounds_even_when_ordinary_trailers_are_preserved() {
        let config = compiled_text(
            r#"[service.forwarding]
preserve_request_trailers = true

[policy]
default = "deny"

[[policy.rules]]
id = "upgrade"
decision = "allow"
methods = ["GET"]
allow_upgrades = true
redaction_profile = "wire"

[redaction.profiles.wire]
replacement = "[REDACTED]"
max_frame_bytes = 1024
max_message_bytes = 1024
rules = [{ literals = ["password"], payloads = "text" }]
"#,
        );
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let (runtime, destinations) = runtime_from(config, resolver_calls.clone()).await;
        let lease = runtime.lease().await.unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_11)
            .uri("/resource")
            .header("host", "standalone-provider.example.test")
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .body(Body::empty())
            .unwrap();
        let input = prepared_input_from_request(&lease, destinations, request);
        let terminal = UpgradeTerminal;
        let (provider, request) =
            StandalonePolicyProvider::prepare(lease, terminal, input).unwrap();

        let outcome = RequestPipeline::new().execute(provider, request).await;

        assert_eq!(outcome, Terminal::Forward);
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn expired_local_response_body_remains_a_complete_empty_stream() {
        let config = compiled_text(
            r#"[policy]
default = "deny"

[[policy.rules]]
id = "short-lived"
decision = "allow"
methods = ["GET"]
request_timeout = "20ms"
"#,
        );
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let (runtime, destinations) = runtime_from(config, resolver_calls.clone()).await;
        let lease = runtime.lease().await.unwrap();
        let input = prepared_input(&lease, destinations, Body::empty(), &[]);
        let (provider, request) =
            StandalonePolicyProvider::prepare(lease, TestTerminal, input).unwrap();
        let facts = request.facts().clone();
        tokio::time::sleep(Duration::from_millis(30)).await;

        let ProviderOutcome::Respond(mut response) = provider.decide(&facts, request).await else {
            panic!("expired request must return a local response");
        };
        assert_eq!(response.status(), 504);
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            response.poll_body_chunk(&mut context),
            Poll::Ready(Ok(None))
        ));
        assert!(matches!(
            response.poll_trailers(&mut context),
            Poll::Ready(Ok(None))
        ));
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
        drop((response, provider));
        runtime.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn process_provider_pass_resumes_at_the_later_rule_and_rehomes_the_inspected_body() {
        let directory = tempfile::tempdir().unwrap();
        let provider_script = process_script(directory.path(), "pass", None);
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let config = process_provider_config(&provider_script, "allow");
        let (runtime, destinations) = runtime_from(config, resolver_calls.clone()).await;
        let lease = runtime.lease().await.unwrap();
        let mut input = prepared_input(
            &lease,
            destinations,
            Body::from("inspected request body"),
            &[("content-length", "22"), ("content-type", "text/plain")],
        );
        let submissions = Arc::new(AtomicUsize::new(0));
        input.decision_target = DecisionSubmissionTarget::Probe(submissions.clone());
        let (provider, request) =
            StandalonePolicyProvider::prepare(lease, BodyTerminal, input).unwrap();

        let terminal = RequestPipeline::new().execute(provider, request).await;

        let BodyTerminalOutcome::Forward(body, DecisionAuditSource::Policy(provenance)) = terminal
        else {
            panic!("resumed allow must retain policy provenance");
        };
        assert_eq!(body, b"inspected request body");
        let EffectivePolicy::Rule { id, .. } = provenance.effective_policy() else {
            panic!("resumed allow must identify its matched rule");
        };
        assert_eq!(id.as_str(), "after-pass");
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
        assert_eq!(submissions.load(Ordering::SeqCst), 1);
        runtime.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn process_provider_allow_is_a_terminal_typed_allow() {
        let directory = tempfile::tempdir().unwrap();
        let provider_script = process_script(directory.path(), "allow", None);
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let config = process_provider_config(&provider_script, "deny");
        let (runtime, destinations) = runtime_from(config, resolver_calls.clone()).await;
        let lease = runtime.lease().await.unwrap();
        let mut input = prepared_input(
            &lease,
            destinations,
            Body::from("provider-visible"),
            &[("content-length", "16"), ("content-type", "text/plain")],
        );
        let submissions = Arc::new(AtomicUsize::new(0));
        input.decision_target = DecisionSubmissionTarget::Probe(submissions.clone());
        let (provider, request) =
            StandalonePolicyProvider::prepare(lease, BodyTerminal, input).unwrap();

        let terminal = RequestPipeline::new().execute(provider, request).await;

        let BodyTerminalOutcome::Forward(body, DecisionAuditSource::Policy(provenance)) = terminal
        else {
            panic!("provider allow must retain policy provenance");
        };
        assert_eq!(body, b"provider-visible");
        let EffectivePolicy::Rule { id, .. } = provenance.effective_policy() else {
            panic!("provider allow must identify its delegated rule");
        };
        assert_eq!(id.as_str(), "delegate");
        assert_eq!(
            provenance.reason().category(),
            DecisionReasonCategory::Provider
        );
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
        assert_eq!(submissions.load(Ordering::SeqCst), 1);
        runtime.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelling_a_mandatory_body_read_releases_the_ingress_body_before_dispatch() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("provider-dispatched");
        let provider_script = process_script(directory.path(), "allow", Some(&marker));
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let config = process_provider_config(&provider_script, "deny");
        let (runtime, destinations) = runtime_from(config, resolver_calls.clone()).await;
        let lease = runtime.lease().await.unwrap();
        let (mut sender, body) = Body::channel();
        let mut input = prepared_input(
            &lease,
            destinations,
            body,
            &[("content-length", "16"), ("content-type", "text/plain")],
        );
        let submissions = Arc::new(AtomicUsize::new(0));
        input.decision_target = DecisionSubmissionTarget::Probe(submissions.clone());
        let (provider, request) =
            StandalonePolicyProvider::prepare(lease, TestTerminal, input).unwrap();
        let facts = request.facts().clone();
        let decision = provider.decide(&facts, request);

        assert!(tokio::time::timeout(Duration::from_millis(20), decision)
            .await
            .is_err());
        assert!(sender
            .send_data(bytes::Bytes::from_static(b"late"))
            .await
            .is_err());
        assert!(!marker.exists());
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
        assert_eq!(submissions.load(Ordering::SeqCst), 1);
        drop(provider);
        runtime.shutdown().await;
    }

    #[test]
    fn status_mapping_is_closed_and_sanitized() {
        assert_eq!(
            body_error_status(HttpBodyReadError::RequestTrailersUnsupported),
            400
        );
        assert_eq!(body_error_status(HttpBodyReadError::TimedOut), 408);
        assert_eq!(
            body_error_status(HttpBodyReadError::DecodedLimitExceeded),
            413
        );
        assert_eq!(
            body_error_status(HttpBodyReadError::UnsupportedContentEncoding),
            415
        );
        assert_eq!(body_error_status(HttpBodyReadError::ResourceExhausted), 503);
    }

    #[test]
    fn internal_context_partition_moves_duplicate_values_out_of_ordinary_headers() {
        let internal_name = http::header::HeaderName::from_static("x-internal");
        let mut headers = HeaderMap::new();
        headers.append(
            internal_name.clone(),
            http::HeaderValue::from_static("first"),
        );
        headers.append(
            internal_name.clone(),
            http::HeaderValue::from_static("second"),
        );
        headers.insert("x-visible", http::HeaderValue::from_static("ordinary"));

        let internal = take_internal_context(&mut headers, std::slice::from_ref(&internal_name))
            .expect("partition");

        assert!(!headers.contains_key(&internal_name));
        assert_eq!(headers["x-visible"], "ordinary");
        assert_eq!(
            internal
                .get_all(&internal_name)
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
    }
}
