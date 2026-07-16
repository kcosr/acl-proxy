use http_access_policy_acl::MatchedEffects;
#[cfg(all(test, unix))]
use http_access_policy_acl::{EvaluationInput, PolicyEvaluation, ProviderDisposition};
use http_access_runtime::{RuntimeRequest, StandalonePlan, StandaloneTrusted};
#[cfg(all(test, unix))]
use http_access_types::BodyObservation;
use http_access_types::{
    BodyRepresentation, CredentialMutation, CredentialMutationKind, CredentialRef,
    DecisionProvenance, ForwardingPlan, ForwardingPlanInput, HeaderMutation, HeaderMutationBatch,
    HeaderMutationCondition, HeaderName, HeaderValue, PlanBinding, UpgradeIntent, UpgradePolicy,
};

use crate::authorization::protocol::{
    ProviderBodyReplacementDecodeError, ProviderCredentialInjectionError,
    StagedProviderCredentialMutation,
};
use crate::authorization::AuthorizationAllowOutput;
use crate::credentials::ResolvedCredentialAction;
use crate::policy::ProductRuleEffectsRef;
use crate::runtime::{CredentialSourceIndex, GenerationLease, ProviderIndex};
use crate::safety::{GuardedBody, HttpWireBodyGuard, RuntimeReplayLease};
use crate::standalone::{
    BoundCredentialSource, ProviderCredentialTemplates, StandaloneCaptureEvent,
    StandaloneGenerationPlan,
};
use crate::upgrade::UpgradeAllocation;

pub(crate) struct StandaloneUpgradeBinding {
    pub(crate) allocation: UpgradeAllocation,
    pub(crate) wire_redaction: Option<http_access_redaction::RedactionProfile>,
}

pub(crate) struct StandaloneProviderAllow {
    pub(crate) plan: StandalonePlan,
    pub(crate) request: RuntimeRequest,
    pub(crate) sidecar: StandaloneRequestSidecar,
}

/// Product-only resources and secret bindings for one validated forwarding pair.
///
/// The shared plan contains only opaque credential references. Provider values
/// stay guarded here until the terminal dispatcher consumes them for the exact
/// plan binding.
pub(crate) struct StandaloneRequestSidecar {
    plan_binding: PlanBinding,
    _guard: HttpWireBodyGuard,
    _replay_lease: RuntimeReplayLease,
    rule_credential_sources: Option<Box<[StandaloneCredentialSourceBinding]>>,
    global_credential_sources: Option<Box<[StandaloneCredentialSourceBinding]>>,
    provider_credentials: Option<StagedProviderCredentialMutation>,
    provider_credential_mutations: Option<Box<[CredentialMutation]>>,
    credential_program_taken: bool,
    capture_body: StandaloneCaptureBody,
    upgrade: Option<StandaloneUpgradeBinding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StandaloneCaptureBody {
    Stream { canonical_identity: bool },
    ProviderReplacement { size: usize },
}

pub(crate) struct StandaloneCredentialSourceBinding {
    reference: CredentialRef,
    source: CredentialSourceIndex,
}

struct StandaloneCredentialSourceStages {
    rule: Box<[StandaloneCredentialSourceBinding]>,
    global: Box<[StandaloneCredentialSourceBinding]>,
}

pub(crate) struct StandaloneCredentialProgram {
    plan_binding: PlanBinding,
    rule_sources: Box<[StandaloneCredentialSourceBinding]>,
    provider_credentials: Option<StagedProviderCredentialMutation>,
    provider_mutations: Box<[CredentialMutation]>,
    global_sources: Box<[StandaloneCredentialSourceBinding]>,
}

pub(crate) trait StandaloneCredentialInjector {
    fn inject(
        &self,
        actions: &[ResolvedCredentialAction],
        headers: &mut http::HeaderMap,
    ) -> Result<(), crate::credentials::CredentialError>;
}

impl<T> StandaloneCredentialInjector for T
where
    T: crate::runtime::CredentialResolver + ?Sized,
{
    fn inject(
        &self,
        actions: &[ResolvedCredentialAction],
        headers: &mut http::HeaderMap,
    ) -> Result<(), crate::credentials::CredentialError> {
        crate::runtime::CredentialResolver::inject(self, actions, headers)
    }
}

impl StandaloneCredentialInjector for crate::runtime::ForwardingGenerationServices {
    fn inject(
        &self,
        actions: &[ResolvedCredentialAction],
        headers: &mut http::HeaderMap,
    ) -> Result<(), crate::credentials::CredentialError> {
        self.inject_credentials(actions, headers)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StandaloneProviderAllowError {
    #[error("provider allow result does not match the activated standalone binding")]
    Binding,
    #[error("provider credential output could not be staged")]
    ProviderCredential(#[source] ProviderCredentialInjectionError),
    #[error("credential source resolution or injection failed")]
    Credential(#[source] crate::credentials::CredentialError),
    #[error("provider body replacement could not be decoded")]
    ProviderReplacement(#[source] ProviderBodyReplacementDecodeError),
    #[error("provider body replacement could not be redacted")]
    Redaction,
    #[error("provider Content-Type is invalid")]
    ContentType,
    #[error("provider allow request rebuilding failed")]
    Runtime(#[source] http_access_runtime::RuntimeError),
    #[error("provider allow forwarding intent is invalid")]
    Plan(#[source] http_access_types::ContractError),
    #[error("the standalone credential program has already been consumed")]
    CredentialProgramConsumed,
}

#[derive(Debug, thiserror::Error)]
#[error("provider allow adaptation failed")]
pub(crate) struct StandaloneProviderAllowFailure {
    #[source]
    error: StandaloneProviderAllowError,
    provider_replacement_size: Option<usize>,
}

impl StandaloneProviderAllowFailure {
    pub(crate) fn into_error(self) -> StandaloneProviderAllowError {
        self.error
    }

    pub(crate) fn provider_replacement_size(&self) -> Option<usize> {
        self.provider_replacement_size
    }
}

impl StandaloneRequestSidecar {
    pub(crate) fn plan_binding(&self) -> PlanBinding {
        self.plan_binding
    }

    pub(crate) fn capture_body(&self) -> StandaloneCaptureBody {
        self.capture_body
    }

    pub(crate) fn take_upgrade_binding(
        &mut self,
        plan_binding: PlanBinding,
    ) -> Result<Option<StandaloneUpgradeBinding>, StandaloneProviderAllowError> {
        if plan_binding != self.plan_binding {
            return Err(StandaloneProviderAllowError::Binding);
        }
        Ok(self.upgrade.take())
    }

    pub(crate) fn take_credential_program(
        &mut self,
        plan_binding: PlanBinding,
    ) -> Result<StandaloneCredentialProgram, StandaloneProviderAllowError> {
        if plan_binding != self.plan_binding {
            return Err(StandaloneProviderAllowError::Binding);
        }
        if self.credential_program_taken {
            return Err(StandaloneProviderAllowError::CredentialProgramConsumed);
        }
        self.credential_program_taken = true;
        Ok(StandaloneCredentialProgram {
            plan_binding: self.plan_binding,
            rule_sources: self
                .rule_credential_sources
                .take()
                .expect("an unconsumed sidecar owns its rule credential source bindings"),
            provider_credentials: self.provider_credentials.take(),
            provider_mutations: self
                .provider_credential_mutations
                .take()
                .expect("an unconsumed sidecar owns its provider credential mutations"),
            global_sources: self
                .global_credential_sources
                .take()
                .expect("an unconsumed sidecar owns its global credential source bindings"),
        })
    }
}

impl StandaloneCredentialSourceBinding {
    pub(crate) fn reference(&self) -> &CredentialRef {
        &self.reference
    }

    pub(crate) fn source(&self) -> CredentialSourceIndex {
        self.source
    }
}

impl StandaloneCredentialProgram {
    pub(crate) fn apply<Credentials>(
        self,
        plan: &ForwardingPlan,
        credentials: &Credentials,
        headers: &mut http::HeaderMap,
    ) -> Result<(), StandaloneProviderAllowError>
    where
        Credentials: StandaloneCredentialInjector + ?Sized,
    {
        if plan.binding() != self.plan_binding {
            return Err(StandaloneProviderAllowError::Binding);
        }
        let mutations = plan.credential_mutations();
        let rule_end = self.rule_sources.len();
        let provider_end = rule_end
            .checked_add(self.provider_mutations.len())
            .ok_or(StandaloneProviderAllowError::Binding)?;
        let total = provider_end
            .checked_add(self.global_sources.len())
            .ok_or(StandaloneProviderAllowError::Binding)?;
        if mutations.len() != total
            || mutations.get(rule_end..provider_end) != Some(&self.provider_mutations)
            || !provider_shape_matches(self.provider_credentials.as_ref(), &self.provider_mutations)
        {
            return Err(StandaloneProviderAllowError::Binding);
        }

        let rule = resolved_credential_actions(&mutations[..rule_end], &self.rule_sources)?;
        let global = resolved_credential_actions(&mutations[provider_end..], &self.global_sources)?;

        let mut staged = http::HeaderMap::new();
        staged.try_reserve(total).map_err(|_| {
            StandaloneProviderAllowError::Credential(crate::credentials::CredentialError::Capacity)
        })?;
        credentials
            .inject(&rule, &mut staged)
            .map_err(StandaloneProviderAllowError::Credential)?;
        if let Some(provider) = self.provider_credentials {
            provider
                .apply(&mut staged)
                .map_err(StandaloneProviderAllowError::ProviderCredential)?;
        }
        credentials
            .inject(&global, &mut staged)
            .map_err(StandaloneProviderAllowError::Credential)?;

        let additional = staged
            .keys()
            .filter(|name| !headers.contains_key(*name))
            .count();
        headers.try_reserve(additional).map_err(|_| {
            StandaloneProviderAllowError::Credential(crate::credentials::CredentialError::Capacity)
        })?;
        for (name, value) in staged.drain() {
            headers.insert(
                name.expect("a checked credential plan has unique destinations"),
                value,
            );
        }
        Ok(())
    }
}

fn provider_shape_matches(
    staged: Option<&StagedProviderCredentialMutation>,
    mutations: &[CredentialMutation],
) -> bool {
    match staged {
        Some(staged) => staged.matches_mutations(mutations),
        None => mutations.is_empty(),
    }
}

fn resolved_credential_actions(
    mutations: &[CredentialMutation],
    bindings: &[StandaloneCredentialSourceBinding],
) -> Result<Vec<ResolvedCredentialAction>, StandaloneProviderAllowError> {
    if mutations.len() != bindings.len() {
        return Err(StandaloneProviderAllowError::Binding);
    }
    let mut actions = Vec::new();
    actions.try_reserve_exact(bindings.len()).map_err(|_| {
        StandaloneProviderAllowError::Credential(crate::credentials::CredentialError::Capacity)
    })?;
    for (mutation, binding) in mutations.iter().zip(bindings) {
        if mutation.credential() != binding.reference() {
            return Err(StandaloneProviderAllowError::Binding);
        }
        actions.push(match mutation.kind() {
            CredentialMutationKind::Bearer(_) => ResolvedCredentialAction::Bearer {
                source: binding.source(),
            },
            CredentialMutationKind::Basic { username, .. } => ResolvedCredentialAction::Basic {
                username: username.clone(),
                source: binding.source(),
            },
            CredentialMutationKind::CustomHeader { name, .. } => {
                ResolvedCredentialAction::CustomHeader {
                    header: http::HeaderName::from_bytes(name.as_str().as_bytes())
                        .map_err(|_| StandaloneProviderAllowError::Binding)?,
                    source: binding.source(),
                }
            }
        });
    }
    Ok(actions)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn adapt_provider_allow(
    lease: &GenerationLease,
    effects: ProductRuleEffectsRef,
    provenance: &DecisionProvenance,
    provider: ProviderIndex,
    output: AuthorizationAllowOutput,
    inspected_body: Option<GuardedBody>,
    guard: HttpWireBodyGuard,
    replay_lease: RuntimeReplayLease,
    request: RuntimeRequest,
) -> Result<StandaloneProviderAllow, StandaloneProviderAllowFailure> {
    let mut provider_replacement_size = None;
    adapt_provider_allow_inner(
        lease,
        effects,
        provenance,
        provider,
        output,
        inspected_body,
        guard,
        replay_lease,
        request,
        &mut provider_replacement_size,
    )
    .map_err(|error| StandaloneProviderAllowFailure {
        error,
        provider_replacement_size,
    })
}

#[allow(clippy::too_many_arguments)]
fn adapt_provider_allow_inner(
    lease: &GenerationLease,
    effects: ProductRuleEffectsRef,
    provenance: &DecisionProvenance,
    provider: ProviderIndex,
    output: AuthorizationAllowOutput,
    inspected_body: Option<GuardedBody>,
    guard: HttpWireBodyGuard,
    replay_lease: RuntimeReplayLease,
    mut request: RuntimeRequest,
    failure_replacement_size: &mut Option<usize>,
) -> Result<StandaloneProviderAllow, StandaloneProviderAllowError> {
    let generation = lease.standalone();
    let authorization = lease.authorization();
    let rule_ordinal = effects.ordinal();
    let rule = generation
        .rules()
        .get(rule_ordinal)
        .filter(|rule| rule.ordinal() as usize == rule_ordinal)
        .ok_or(StandaloneProviderAllowError::Binding)?;
    let (credentials, replacement) = authorization
        .consume_allow_output(provider, output)
        .ok_or(StandaloneProviderAllowError::Binding)?;
    let provider_replacement_size = replacement
        .as_ref()
        .map(|replacement| replacement.decoded_size());
    *failure_replacement_size = provider_replacement_size;
    let metadata = authorization
        .provider_metadata(provider)
        .ok_or(StandaloneProviderAllowError::Binding)?;
    let provider_templates = generation
        .provider_credentials()
        .get(provider.get())
        .filter(|templates| templates.ordinal() == provider.get())
        .ok_or(StandaloneProviderAllowError::Binding)?;
    let upgrade_binding = compile_upgrade_binding(lease, Some(rule_ordinal), &request)?;

    let provider_credential_mutations = collect_provider_credential_mutations(
        generation,
        provider,
        provider_templates,
        credentials.as_ref(),
    )?;
    let staged_provider_credentials = credentials
        .as_ref()
        .map(|credentials| authorization.stage_provider_credentials(provider, credentials, &guard))
        .transpose()
        .map_err(StandaloneProviderAllowError::ProviderCredential)?;
    drop(credentials);

    let provider_content_type = if let Some(replacement) = replacement {
        drop(inspected_body);
        let redaction = generation.activated().rule_redaction(rule_ordinal);
        let redaction_limit = redaction
            .map(|binding| binding.handle().limits().max_decoded_body_bytes())
            .unwrap_or(usize::MAX);
        let (content_type, content_encoding, decoded) = replacement
            .decode_with_limits(
                &guard,
                metadata.max_decoded_request_body_bytes,
                redaction_limit,
            )
            .map_err(StandaloneProviderAllowError::ProviderReplacement)?;
        if content_encoding
            .as_deref()
            .is_some_and(|value| value != "identity")
        {
            return Err(StandaloneProviderAllowError::ProviderReplacement(
                ProviderBodyReplacementDecodeError::InvalidBody,
            ));
        }
        let content_type = content_type_batch(content_type)?;
        let replacement = match redaction {
            Some(binding) => binding
                .handle()
                .redact_http_body(&guard, decoded)
                .map_err(|_| StandaloneProviderAllowError::Redaction)?
                .into_body(),
            None => decoded,
        };
        let replacement_length =
            u64::try_from(replacement.len()).map_err(|_| StandaloneProviderAllowError::Binding)?;
        request
            .replace_body_fragments(replacement_length, replacement.segments())
            .map_err(StandaloneProviderAllowError::Runtime)?;
        Some(content_type)
    } else {
        if let Some(inspected_body) = inspected_body {
            redact_and_rehome(
                generation,
                Some(rule_ordinal),
                &guard,
                &mut request,
                inspected_body,
            )?;
        }
        None
    };

    finish_allow(
        generation,
        Some((rule_ordinal, rule)),
        provenance,
        provider_credential_mutations,
        staged_provider_credentials,
        provider_content_type,
        provider_replacement_size,
        upgrade_binding,
        guard,
        replay_lease,
        request,
    )
}

pub(crate) fn adapt_local_allow(
    lease: &GenerationLease,
    effects: MatchedEffects<ProductRuleEffectsRef>,
    provenance: &DecisionProvenance,
    inspected_body: Option<GuardedBody>,
    guard: HttpWireBodyGuard,
    replay_lease: RuntimeReplayLease,
    mut request: RuntimeRequest,
) -> Result<StandaloneProviderAllow, StandaloneProviderAllowError> {
    let generation = lease.standalone();
    let rule_ordinal = match effects {
        MatchedEffects::Empty => None,
        MatchedEffects::Rule(effects) => Some(effects.ordinal()),
    };
    let rule = rule_ordinal
        .map(|ordinal| {
            generation
                .rules()
                .get(ordinal)
                .filter(|rule| rule.ordinal() as usize == ordinal)
                .map(|rule| (ordinal, rule))
                .ok_or(StandaloneProviderAllowError::Binding)
        })
        .transpose()?;
    if let Some(inspected_body) = inspected_body {
        redact_and_rehome(
            generation,
            rule_ordinal,
            &guard,
            &mut request,
            inspected_body,
        )?;
    }
    let upgrade_binding = compile_upgrade_binding(lease, rule_ordinal, &request)?;
    finish_allow(
        generation,
        rule,
        provenance,
        Vec::new(),
        None,
        None,
        None,
        upgrade_binding,
        guard,
        replay_lease,
        request,
    )
}

fn redact_and_rehome(
    generation: &StandaloneGenerationPlan,
    rule_ordinal: Option<usize>,
    guard: &HttpWireBodyGuard,
    request: &mut RuntimeRequest,
    body: GuardedBody,
) -> Result<(), StandaloneProviderAllowError> {
    let body = match rule_ordinal.and_then(|ordinal| generation.activated().rule_redaction(ordinal))
    {
        Some(binding) => binding
            .handle()
            .redact_http_body(guard, body)
            .map_err(|_| StandaloneProviderAllowError::Redaction)?
            .into_body(),
        None => body,
    };
    let length = u64::try_from(body.len()).map_err(|_| StandaloneProviderAllowError::Binding)?;
    request
        .replace_body_fragments(length, body.segments())
        .map_err(StandaloneProviderAllowError::Runtime)
}

#[allow(clippy::too_many_arguments)]
fn finish_allow(
    generation: &StandaloneGenerationPlan,
    rule: Option<(usize, &crate::standalone::StandaloneRuleTemplate)>,
    provenance: &http_access_types::DecisionProvenance,
    provider_credential_mutations: Vec<CredentialMutation>,
    staged_provider_credentials: Option<StagedProviderCredentialMutation>,
    provider_content_type: Option<HeaderMutationBatch>,
    provider_replacement_size: Option<usize>,
    upgrade_binding: Option<StandaloneUpgradeBinding>,
    guard: HttpWireBodyGuard,
    replay_lease: RuntimeReplayLease,
    request: RuntimeRequest,
) -> Result<StandaloneProviderAllow, StandaloneProviderAllowError> {
    let rule_template = rule.map(|(_, rule)| rule);

    let mut request_mutation_batches = Vec::new();
    if let Some(batch) = rule_template.and_then(|rule| rule.request_headers()) {
        request_mutation_batches.push(batch.clone());
    }
    if let Some(batch) = generation.global_request_headers() {
        request_mutation_batches.push(batch.clone());
    }
    if let Some(batch) = provider_content_type {
        request_mutation_batches.push(batch);
    }

    let mut response_mutation_batches = Vec::new();
    if let Some(batch) = rule_template.and_then(|rule| rule.response_headers()) {
        response_mutation_batches.push(batch.clone());
    }

    let credential_sources = collect_credential_sources(generation, rule)?;
    let mut credential_mutations = rule_template
        .map(|rule| rule.credentials().to_vec())
        .unwrap_or_default();
    credential_mutations.extend_from_slice(&provider_credential_mutations);
    credential_mutations.extend_from_slice(generation.global_credentials());

    let upgrade = compile_upgrade(
        &request,
        rule_template.is_some_and(|rule| rule.allow_upgrades()),
    )?;
    let request_body = match request.body_representation() {
        BodyRepresentation::CanonicalIdentity => generation.normalized_request_body(),
        BodyRepresentation::PreservedContentCoded if request.facts().upgrade().is_some() => {
            generation.upgrade_request_body()
        }
        BodyRepresentation::PreservedContentCoded => generation.ordinary_request_body(),
    };
    let request_binding = request
        .binding()
        .map_err(StandaloneProviderAllowError::Runtime)?;
    let capture_body = match provider_replacement_size {
        Some(size) => StandaloneCaptureBody::ProviderReplacement { size },
        None => StandaloneCaptureBody::Stream {
            canonical_identity: request.body_representation()
                == BodyRepresentation::CanonicalIdentity,
        },
    };
    let capture = generation.capture().and_then(|capture| {
        capture
            .events()
            .iter()
            .any(|event| {
                matches!(
                    event,
                    StandaloneCaptureEvent::RequestAllowed
                        | StandaloneCaptureEvent::ResponseAllowed
                )
            })
            .then(|| capture.intent().clone())
    });
    let plan = ForwardingPlan::new(ForwardingPlanInput {
        snapshot_identity: generation.identity().clone(),
        request_binding,
        origin: request.facts().url().clone(),
        route: generation.route().clone(),
        origin_tls: generation.origin_tls(request.facts().url().scheme()),
        timeouts: generation.timeouts(),
        request_body,
        response: generation.response(),
        request_mutation_batches,
        response_mutation_batches,
        redaction: rule_template.and_then(|rule| rule.redaction().cloned()),
        capture,
        upgrade,
        provenance: provenance.clone(),
        credential_mutations,
    })
    .map_err(StandaloneProviderAllowError::Plan)?;
    let plan_binding = plan.binding();
    let plan = StandaloneTrusted::validate(plan, &request, generation.snapshot_lease())
        .map_err(StandaloneProviderAllowError::Runtime)?;
    let sidecar = StandaloneRequestSidecar {
        plan_binding,
        _guard: guard,
        _replay_lease: replay_lease,
        rule_credential_sources: Some(credential_sources.rule),
        global_credential_sources: Some(credential_sources.global),
        provider_credentials: staged_provider_credentials,
        provider_credential_mutations: Some(provider_credential_mutations.into_boxed_slice()),
        credential_program_taken: false,
        capture_body,
        upgrade: upgrade_binding,
    };
    Ok(StandaloneProviderAllow {
        plan,
        request,
        sidecar,
    })
}

fn collect_provider_credential_mutations(
    generation: &StandaloneGenerationPlan,
    provider: ProviderIndex,
    templates: &ProviderCredentialTemplates,
    credentials: Option<&crate::authorization::protocol::ProviderCredentialSet>,
) -> Result<Vec<CredentialMutation>, StandaloneProviderAllowError> {
    let bindings = generation
        .activated()
        .provider_outputs()
        .iter()
        .filter(|binding| binding.provider() == provider)
        .collect::<Vec<_>>();
    if bindings.len() != templates.outputs().len() {
        return Err(StandaloneProviderAllowError::Binding);
    }
    let mut mutations = Vec::new();
    for template in templates.outputs() {
        let binding = bindings
            .iter()
            .copied()
            .find(|binding| binding.output().get() == template.ordinal())
            .filter(|binding| binding.reference() == template.mutation().credential())
            .ok_or(StandaloneProviderAllowError::Binding)?;
        let present =
            credentials.is_some_and(|credentials| credentials.contains_output(binding.output()));
        if template.required() && !present {
            return Err(StandaloneProviderAllowError::Binding);
        }
        if present {
            mutations.push(template.mutation().clone());
        }
    }
    Ok(mutations)
}

fn collect_credential_sources(
    generation: &StandaloneGenerationPlan,
    rule: Option<(usize, &crate::standalone::StandaloneRuleTemplate)>,
) -> Result<StandaloneCredentialSourceStages, StandaloneProviderAllowError> {
    let mut rule_sources = Vec::new();
    if let Some((rule_ordinal, rule)) = rule {
        let rule_bindings = generation
            .activated()
            .rule_credentials(rule_ordinal)
            .ok_or(StandaloneProviderAllowError::Binding)?;
        if rule_bindings.len() != rule.credentials().len() {
            return Err(StandaloneProviderAllowError::Binding);
        }
        rule_sources = Vec::with_capacity(rule_bindings.len());
        for (binding, mutation) in rule_bindings.iter().zip(rule.credentials()) {
            push_credential_source(&mut rule_sources, binding, mutation)?;
        }
    }
    if generation.activated().global_credentials().len() != generation.global_credentials().len() {
        return Err(StandaloneProviderAllowError::Binding);
    }
    let mut global_sources = Vec::with_capacity(generation.activated().global_credentials().len());
    for (binding, mutation) in generation
        .activated()
        .global_credentials()
        .iter()
        .zip(generation.global_credentials())
    {
        push_credential_source(&mut global_sources, binding, mutation)?;
    }
    Ok(StandaloneCredentialSourceStages {
        rule: rule_sources.into_boxed_slice(),
        global: global_sources.into_boxed_slice(),
    })
}

fn push_credential_source(
    result: &mut Vec<StandaloneCredentialSourceBinding>,
    binding: &BoundCredentialSource,
    mutation: &CredentialMutation,
) -> Result<(), StandaloneProviderAllowError> {
    if binding.reference() != mutation.credential() {
        return Err(StandaloneProviderAllowError::Binding);
    }
    result.push(StandaloneCredentialSourceBinding {
        reference: binding.reference().clone(),
        source: binding.source(),
    });
    Ok(())
}

fn content_type_batch(
    content_type: Option<String>,
) -> Result<HeaderMutationBatch, StandaloneProviderAllowError> {
    let name = HeaderName::new("content-type".to_owned())
        .map_err(|_| StandaloneProviderAllowError::ContentType)?;
    let mutation = match content_type {
        Some(value) => HeaderMutation::set(
            HeaderMutationCondition::Always,
            name,
            vec![HeaderValue::new(value.into_bytes())
                .map_err(|_| StandaloneProviderAllowError::ContentType)?],
        ),
        None => HeaderMutation::remove(HeaderMutationCondition::Always, name),
    }
    .map_err(|_| StandaloneProviderAllowError::ContentType)?;
    HeaderMutationBatch::new(vec![mutation]).map_err(|_| StandaloneProviderAllowError::ContentType)
}

fn compile_upgrade(
    request: &RuntimeRequest,
    allow: bool,
) -> Result<UpgradePolicy, StandaloneProviderAllowError> {
    match request.facts().upgrade() {
        None => Ok(UpgradePolicy::Deny),
        Some(_) if !allow => Err(StandaloneProviderAllowError::Binding),
        Some(UpgradeIntent::WebSocket) => Ok(UpgradePolicy::WebSocket),
        Some(UpgradeIntent::Other(protocol)) => Ok(UpgradePolicy::Opaque(protocol.clone())),
    }
}

fn compile_upgrade_binding(
    lease: &GenerationLease,
    rule_ordinal: Option<usize>,
    request: &RuntimeRequest,
) -> Result<Option<StandaloneUpgradeBinding>, StandaloneProviderAllowError> {
    if request.facts().upgrade().is_none() {
        return Ok(None);
    }
    let ordinal = rule_ordinal.ok_or(StandaloneProviderAllowError::Binding)?;
    let compiled_wire_bytes = lease
        .resource_plan()
        .upgrade_wire_working_set_bytes_by_rule
        .get(ordinal)
        .copied()
        .flatten();
    let allocation = UpgradeAllocation::from_compiled_rule(ordinal, compiled_wire_bytes)
        .map_err(|_| StandaloneProviderAllowError::Binding)?;
    let wire_redaction = lease
        .standalone()
        .activated()
        .rule_redaction(ordinal)
        .map(|binding| binding.handle().clone());
    Ok(Some(StandaloneUpgradeBinding {
        allocation,
        wire_redaction,
    }))
}

#[cfg(all(test, unix))]
mod tests {
    use std::future;
    use std::net::IpAddr;
    use std::path::Path;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use http::HeaderMap;
    use http_access_runtime::{
        prepare_standalone_exchange, BodyBounds, BodyBudget, BoxFuture, Clock, RuntimeBody,
        StandaloneExchange,
    };
    use http_access_types::{
        BodyFraming, BodyMetadata, HeaderField, HeaderMutationOperation, HttpMethod, HttpVersion,
        IngressMode, PolicyHeaderFacts,
    };

    use super::*;
    use crate::activation::static_resources::ProductStaticResources;
    use crate::authorization::protocol::{ProviderBodyReplacement, ProviderCredentialSet};
    use crate::config::{compile_config_text, CompiledConfig, ConfigTextInput};
    use crate::runtime::{
        ActivationCancellation, CandidateSource, GenerationLease, Runtime, RuntimeError,
        StaticOwnership,
    };
    use crate::safety::WireBodyQuotaKey;

    const CONFIG: &str = r#"schema_version = 3

[service]
request_timeout = "30s"
max_retiring_generations = 2

[service.forwarding]
connect_timeout = "1s"
response_head_timeout = "1s"
body_idle_timeout = "1s"
upgrade_idle_timeout = "1s"
max_request_wire_bytes = 4096
max_request_decoded_bytes = 4096
max_response_wire_bytes = 4096
max_response_decoded_bytes = 4096
chunk_bytes = 1024
preserve_request_trailers = false
max_trailer_count = 8
max_trailer_bytes = 1024

[listeners.explicit_http]
bind = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[credentials]
allowed_custom_headers = ["x-provider-token", "x-rule-token", "x-global-token"]

[credentials.sources.rule]
source = "environment"
variable = "P06_RULE_TOKEN"

[credentials.sources.global]
source = "environment"
variable = "P06_GLOBAL_TOKEN"

[authorization.providers.approval]
kind = "process"
command = "/bin/cat"
retire_timeout = "31s"
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 4096
max_decoded_request_body_bytes = 4096

[authorization.providers.approval.outputs.token]
kind = "custom_header"
header = "x-provider-token"
required = false

[egress]
route = "direct"

[egress.origin_tls]
trust = "system"

[redaction.profiles.wire]
replacement = "[MASKED]"
max_body_bytes = 4096
max_decoded_body_bytes = 4096
rules = [{ literals = ["secret"], payloads = "text" }]

[[egress.request_headers]]
operation = "set"
when = "always"
name = "content-type"
value = "application/global"

[[egress.credential_actions]]
kind = "custom_header"
header = "x-global-token"
credential = "global"

[policy]
default = "deny"

[[policy.rules]]
id = "delegate"
decision = "delegate"
methods = ["POST"]
urls = ["https://example.test/**"]
authorization_provider = "approval"
redaction_profile = "wire"

[[policy.rules.request_headers]]
operation = "set"
when = "always"
name = "content-type"
value = "application/rule"

[[policy.rules.response_headers]]
operation = "remove"
when = "always"
name = "x-private"

[[policy.rules.credential_actions]]
kind = "custom_header"
header = "x-rule-token"
credential = "rule"

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

    struct TestClock;

    impl Clock for TestClock {
        fn monotonic_millis(&self) -> u64 {
            1
        }

        fn unix_millis(&self) -> u64 {
            1
        }

        fn sleep_until(&self, _deadline_millis: u64) -> BoxFuture<'static, ()> {
            Box::pin(future::pending())
        }
    }

    fn compiled_text(text: &str) -> CompiledConfig {
        std::fs::create_dir_all("/tmp/p06-provider-result").unwrap();
        compile_config_text(ConfigTextInput {
            text,
            source_path: Path::new("/tmp/p06-provider-result/acl-proxy.toml"),
            config_root: Path::new("/tmp/p06-provider-result"),
        })
        .unwrap()
    }

    async fn runtime() -> (
        Arc<Runtime>,
        GenerationLease,
        Arc<crate::safety::WireBodyPool>,
    ) {
        runtime_from_config(CONFIG).await
    }

    async fn runtime_from_config(
        text: &str,
    ) -> (
        Arc<Runtime>,
        GenerationLease,
        Arc<crate::safety::WireBodyPool>,
    ) {
        let initial = compiled_text(text);
        let resources = ProductStaticResources::try_new(&initial.static_config).unwrap();
        let pool = resources.wire_body_pool();
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
        let lease = runtime.lease().await.unwrap();
        (runtime, lease, pool)
    }

    fn body_bounds(generation: &StandaloneGenerationPlan) -> BodyBounds {
        let limits = generation.ordinary_request_body().limits();
        BodyBounds::new(
            limits.wire_bytes(),
            limits.decoded_bytes(),
            limits.chunk_bytes(),
            limits.trailer_count(),
            limits.trailer_bytes(),
            generation.timeouts().body_idle_ms(),
        )
        .unwrap()
    }

    fn request(generation: &StandaloneGenerationPlan, chunks: Vec<Vec<u8>>) -> RuntimeRequest {
        let length = chunks.iter().map(Vec::len).sum::<usize>();
        let content_type = HeaderField::new(
            HeaderName::new("content-type".to_owned()).unwrap(),
            HeaderValue::new(b"application/original".to_vec()).unwrap(),
        );
        let facts = http_access_types::InterceptedRequestFacts::new(
            IngressMode::ExplicitHttps,
            HttpVersion::Http11,
            HttpMethod::new("POST").unwrap(),
            http_access_url::canonicalize_http_url("https://example.test/resource").unwrap(),
            vec![content_type],
            BodyMetadata::new(BodyFraming::ContentLength(length as u64)),
            None,
        )
        .unwrap();
        let body = RuntimeBody::from_chunks(
            chunks,
            body_bounds(generation),
            Arc::new(TestClock),
            BodyBudget::new(32 * 1024 * 1024).unwrap(),
            30_001,
        )
        .unwrap();
        let mut request = RuntimeRequest::new(
            facts.clone(),
            "192.0.2.10".parse().unwrap(),
            PolicyHeaderFacts::new(facts.headers().to_vec(), Vec::new()).unwrap(),
            BodyRepresentation::PreservedContentCoded,
            body,
            30_001,
        )
        .unwrap();
        observe_body(&mut request);
        request
    }

    fn observe_body(request: &mut RuntimeRequest) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            match request.poll_body_chunk(&mut Context::from_waker(std::task::Waker::noop())) {
                Poll::Ready(Ok(Some(chunk))) => bytes.extend_from_slice(chunk.as_bytes()),
                Poll::Ready(Ok(None)) => break,
                Poll::Ready(Err(error)) => panic!("body observation failed: {error}"),
                Poll::Pending => {}
            }
        }
        loop {
            match request.poll_trailers(&mut Context::from_waker(std::task::Waker::noop())) {
                Poll::Ready(Ok(_)) => break,
                Poll::Ready(Err(error)) => panic!("trailer observation failed: {error}"),
                Poll::Pending => {}
            }
        }
        bytes
    }

    fn replay_exchange(exchange: &mut StandaloneExchange) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            match exchange.poll_body_chunk(&mut Context::from_waker(std::task::Waker::noop())) {
                Poll::Ready(Ok(Some(chunk))) => bytes.extend_from_slice(chunk.as_bytes()),
                Poll::Ready(Ok(None)) => break,
                Poll::Ready(Err(error)) => panic!("body replay failed: {error}"),
                Poll::Pending => {}
            }
        }
        loop {
            match exchange.poll_trailers(&mut Context::from_waker(std::task::Waker::noop())) {
                Poll::Ready(Ok(_)) => break,
                Poll::Ready(Err(error)) => panic!("trailer replay failed: {error}"),
                Poll::Pending => {}
            }
        }
        bytes
    }

    fn admission(
        lease: &GenerationLease,
    ) -> (HttpWireBodyGuard, RuntimeReplayLease, ProviderIndex) {
        let (guard, replay) = local_admission(lease);
        let provider = lease
            .standalone()
            .activated()
            .rule_provider_for_test(0)
            .unwrap();
        (guard, replay, provider)
    }

    fn local_admission(lease: &GenerationLease) -> (HttpWireBodyGuard, RuntimeReplayLease) {
        let peer: IpAddr = "192.0.2.10".parse().unwrap();
        let request = request(lease.standalone(), Vec::new());
        let input = EvaluationInput::new(
            request.facts(),
            peer,
            request.policy_header_facts(),
            RuntimeRequest::INITIAL_REVISION,
            BodyRepresentation::PreservedContentCoded,
            BodyObservation::unobserved(),
        )
        .unwrap();
        let evaluation = lease
            .standalone()
            .product_acl()
            .snapshot()
            .evaluate(&input)
            .unwrap();
        let cursor = lease
            .standalone()
            .product_acl()
            .resource_cursor(match &evaluation {
                PolicyEvaluation::Allow { provenance, .. }
                | PolicyEvaluation::Deny { provenance } => provenance,
                PolicyEvaluation::Delegate(delegated) => delegated.provenance(),
            })
            .unwrap();
        let wire_body_plan = lease
            .standalone()
            .product_acl()
            .resources()
            .wire_body_plan(cursor)
            .unwrap();
        let admission = lease
            .safety()
            .begin_http_body(wire_body_plan, WireBodyQuotaKey::from_peer(peer, |_| false))
            .unwrap();
        let (guard, replay, staging) = admission.into_parts();
        drop(staging);
        (guard, replay)
    }

    fn replacement(
        guard: &HttpWireBodyGuard,
        fragments: &[&[u8]],
        content_type: Option<&str>,
    ) -> ProviderBodyReplacement {
        let mut body = guard.buffer();
        for fragment in fragments {
            body.try_extend_from_slice(fragment).unwrap();
        }
        ProviderBodyReplacement::from_decoded_with_metadata_for_test(
            body.finish(),
            content_type.map(str::to_owned),
            Some("identity".to_owned()),
        )
    }

    fn replacement_with_encoding(
        guard: &HttpWireBodyGuard,
        body: &[u8],
        content_encoding: &str,
    ) -> ProviderBodyReplacement {
        let mut staged = guard.buffer();
        staged.try_extend_from_slice(body).unwrap();
        ProviderBodyReplacement::from_decoded_with_metadata_for_test(
            staged.finish(),
            Some("application/provider".to_owned()),
            Some(content_encoding.to_owned()),
        )
    }

    fn output(
        lease: &GenerationLease,
        provider: ProviderIndex,
        credentials: bool,
        replacement: Option<ProviderBodyReplacement>,
    ) -> AuthorizationAllowOutput {
        let generation = lease.standalone();
        let binding = &generation.activated().provider_outputs()[0];
        let credentials = credentials.then(|| {
            ProviderCredentialSet::single_value_for_test(binding.output(), 1, b"secret-token")
        });
        lease
            .authorization()
            .bind_allow_output_for_test(provider, credentials, replacement)
    }

    fn test_policy_rule_ordinal(provenance: &DecisionProvenance) -> Option<usize> {
        match provenance.effective_policy() {
            http_access_types::EffectivePolicy::Default => None,
            http_access_types::EffectivePolicy::Rule { ordinal, .. } => {
                usize::try_from(*ordinal).ok()
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn adapt_provider_allow(
        lease: &GenerationLease,
        rule_ordinal: usize,
        provider: ProviderIndex,
        output: AuthorizationAllowOutput,
        inspected_body: Option<GuardedBody>,
        guard: HttpWireBodyGuard,
        replay_lease: RuntimeReplayLease,
        request: RuntimeRequest,
    ) -> Result<StandaloneProviderAllow, StandaloneProviderAllowFailure> {
        let input = EvaluationInput::new(
            request.facts(),
            "192.0.2.10".parse().unwrap(),
            request.policy_header_facts(),
            RuntimeRequest::INITIAL_REVISION,
            BodyRepresentation::PreservedContentCoded,
            BodyObservation::unobserved(),
        )
        .unwrap();
        let PolicyEvaluation::Delegate(delegated) = lease
            .standalone()
            .product_acl()
            .snapshot()
            .evaluate(&input)
            .unwrap()
        else {
            panic!("test request must select a delegated rule");
        };
        assert_eq!(
            test_policy_rule_ordinal(delegated.provenance()),
            Some(rule_ordinal)
        );
        let resolved = lease
            .standalone()
            .product_acl()
            .snapshot()
            .resolve_delegate(delegated, ProviderDisposition::Allow, &input)
            .unwrap();
        let PolicyEvaluation::Allow {
            provenance,
            effects: MatchedEffects::Rule(effects),
        } = resolved
        else {
            panic!("provider allow must release the delegated effects");
        };
        super::adapt_provider_allow(
            lease,
            effects,
            &provenance,
            provider,
            output,
            inspected_body,
            guard,
            replay_lease,
            request,
        )
    }

    fn adapt_local_allow(
        lease: &GenerationLease,
        rule_ordinal: Option<usize>,
        inspected_body: Option<GuardedBody>,
        guard: HttpWireBodyGuard,
        replay_lease: RuntimeReplayLease,
        request: RuntimeRequest,
    ) -> Result<StandaloneProviderAllow, StandaloneProviderAllowError> {
        let input = EvaluationInput::new(
            request.facts(),
            "192.0.2.10".parse().unwrap(),
            request.policy_header_facts(),
            RuntimeRequest::INITIAL_REVISION,
            BodyRepresentation::PreservedContentCoded,
            BodyObservation::unobserved(),
        )
        .unwrap();
        let PolicyEvaluation::Allow {
            provenance,
            effects,
        } = lease
            .standalone()
            .product_acl()
            .snapshot()
            .evaluate(&input)
            .unwrap()
        else {
            panic!("test request must select a local allow");
        };
        assert_eq!(test_policy_rule_ordinal(&provenance), rule_ordinal);
        super::adapt_local_allow(
            lease,
            effects,
            &provenance,
            inspected_body,
            guard,
            replay_lease,
            request,
        )
    }

    #[tokio::test]
    async fn replacement_shapes_rehome_once_and_bind_the_exact_result() {
        let cases: Vec<Vec<&[u8]>> = vec![
            Vec::new(),
            vec![b"one"],
            vec![b"multi", b"-segment"],
            vec![b"", b"empty", b"", b"-interleaved", b""],
            std::iter::repeat_n(&b"x"[..], 512).collect(),
        ];
        for fragments in cases {
            let (runtime, lease, pool) = runtime().await;
            let generation = lease.standalone();
            let (guard, replay, provider) = admission(&lease);
            let replacement = replacement(&guard, &fragments, Some("application/provider"));
            let expected = fragments.concat();
            let before = request(generation, vec![b"original".to_vec()]);
            let before_revision = before.revision();
            let lineage = before.begin_provider_invocation();
            let result = adapt_provider_allow(
                &lease,
                0,
                provider,
                output(&lease, provider, true, Some(replacement)),
                None,
                guard,
                replay,
                before,
            )
            .unwrap();

            assert_eq!(result.request.revision(), before_revision + 1);
            assert_eq!(
                result.request.body_representation(),
                BodyRepresentation::CanonicalIdentity
            );
            result.plan.validate_request(&result.request).unwrap();
            assert_eq!(result.sidecar.plan_binding(), result.plan.binding());
            assert_eq!(
                result
                    .sidecar
                    .rule_credential_sources
                    .as_ref()
                    .expect("rule credential program is unconsumed")
                    .len(),
                1
            );
            assert_eq!(
                result
                    .sidecar
                    .global_credential_sources
                    .as_ref()
                    .expect("global credential program is unconsumed")
                    .len(),
                1
            );
            let credential_mutations = result.plan.forwarding_plan().credential_mutations();
            assert_eq!(credential_mutations.len(), 3);
            assert_eq!(
                credential_mutations[0].credential(),
                generation.rules()[0].credentials()[0].credential()
            );
            assert_eq!(
                credential_mutations[1].credential(),
                generation.provider_credentials()[provider.get()].outputs()[0]
                    .mutation()
                    .credential()
            );
            assert_eq!(
                credential_mutations[2].credential(),
                generation.global_credentials()[0].credential()
            );
            assert_eq!(
                result
                    .plan
                    .forwarding_plan()
                    .request_mutation_batches()
                    .len(),
                3
            );
            assert_eq!(
                result.plan.forwarding_plan().request_mutation_batches()[2].mutations()[0]
                    .operation(),
                HeaderMutationOperation::Set
            );
            let forwarding = result.plan.forwarding_plan();
            assert_eq!(forwarding.route(), generation.route());
            assert_eq!(
                forwarding.origin_tls(),
                &generation.origin_tls(result.request.facts().url().scheme())
            );
            assert_eq!(
                forwarding.request_body(),
                generation.normalized_request_body()
            );
            assert_eq!(forwarding.response(), generation.response());
            assert_eq!(forwarding.capture(), None);
            assert_eq!(forwarding.upgrade(), &UpgradePolicy::Deny);
            assert_eq!(
                forwarding.provenance().reason().category(),
                http_access_types::DecisionReasonCategory::Provider
            );
            let StandaloneProviderAllow {
                plan,
                request,
                sidecar,
            } = result;
            let mut exchange = prepare_standalone_exchange(lineage, plan, request).unwrap();
            assert_eq!(replay_exchange(&mut exchange), expected);
            drop(exchange);
            drop(sidecar);
            assert_eq!(pool.global_charge(), 0);
            drop(lease);
            runtime.shutdown().await;
        }
    }

    #[tokio::test]
    async fn content_type_preserve_remove_set_and_sidecar_use_are_exact() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        std::env::set_var("P06_RULE_TOKEN", "rule-secret");
        std::env::set_var("P06_GLOBAL_TOKEN", "global-secret");
        let mut foreign_binding = None;
        for (replacement_type, expected, operation) in [
            (None, Some("application/global"), None),
            (Some(None), None, Some(HeaderMutationOperation::Remove)),
            (
                Some(Some("application/provider")),
                Some("application/provider"),
                Some(HeaderMutationOperation::Set),
            ),
        ] {
            let (runtime, lease, _pool) = runtime().await;
            let generation = lease.standalone();
            let (guard, replay, provider) = admission(&lease);
            let replacement =
                replacement_type.map(|content_type| replacement(&guard, &[b"body"], content_type));
            let mut result = adapt_provider_allow(
                &lease,
                0,
                provider,
                output(&lease, provider, true, replacement),
                None,
                guard,
                replay,
                request(generation, vec![b"original".to_vec()]),
            )
            .unwrap();
            let batches = result.plan.forwarding_plan().request_mutation_batches();
            assert_eq!(batches.len(), if operation.is_some() { 3 } else { 2 });
            if let Some(operation) = operation {
                assert_eq!(
                    batches.last().unwrap().mutations()[0].operation(),
                    operation
                );
            }
            let mut headers = HeaderMap::new();
            headers.insert(
                "content-type",
                http::HeaderValue::from_static("application/original"),
            );
            let neutral = headers
                .iter()
                .map(|(name, value)| {
                    HeaderField::new(
                        HeaderName::new(name.as_str().to_owned()).unwrap(),
                        HeaderValue::new(value.as_bytes().to_vec()).unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            let applied =
                http_access_types::apply_header_mutation_batches(&neutral, batches).unwrap();
            assert_eq!(
                applied
                    .iter()
                    .find(|field| field.name().as_str() == "content-type")
                    .map(|field| std::str::from_utf8(field.value().as_bytes()).unwrap()),
                expected
            );

            let binding = result.plan.binding();
            if let Some(foreign_binding) = foreign_binding {
                assert!(matches!(
                    result.sidecar.take_credential_program(foreign_binding),
                    Err(StandaloneProviderAllowError::Binding)
                ));
            }
            let program = result.sidecar.take_credential_program(binding).unwrap();
            assert_eq!(program.rule_sources.len(), 1);
            assert_eq!(program.global_sources.len(), 1);
            program
                .apply(
                    result.plan.forwarding_plan(),
                    lease.credentials(),
                    &mut headers,
                )
                .unwrap();
            assert_eq!(headers["x-rule-token"], "rule-secret");
            assert_eq!(headers["x-provider-token"], "secret-token");
            assert_eq!(headers["x-global-token"], "global-secret");
            assert!(matches!(
                result.sidecar.take_credential_program(binding),
                Err(StandaloneProviderAllowError::CredentialProgramConsumed)
            ));
            foreign_binding = Some(binding);
            drop(result);
            drop(lease);
            runtime.shutdown().await;
        }
        std::env::remove_var("P06_RULE_TOKEN");
        std::env::remove_var("P06_GLOBAL_TOKEN");
    }

    #[tokio::test]
    async fn credential_program_applies_exact_rule_provider_global_order_once() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        std::env::set_var("P06_RULE_TOKEN", "rule-secret");
        std::env::set_var("P06_GLOBAL_TOKEN", "global-secret");

        let (primary_runtime, lease, _pool) = runtime().await;
        let generation = lease.standalone();
        let (guard, replay, provider) = admission(&lease);
        let mut result = adapt_provider_allow(
            &lease,
            0,
            provider,
            output(&lease, provider, true, None),
            None,
            guard,
            replay,
            request(generation, vec![b"original".to_vec()]),
        )
        .unwrap();
        let binding = result.plan.binding();
        let program = result.sidecar.take_credential_program(binding).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-visible", http::HeaderValue::from_static("retained"));
        headers.insert("x-rule-token", http::HeaderValue::from_static("replaced"));
        program
            .apply(
                result.plan.forwarding_plan(),
                lease.credentials(),
                &mut headers,
            )
            .unwrap();

        assert_eq!(headers["x-visible"], "retained");
        assert_eq!(headers["x-rule-token"], "rule-secret");
        assert_eq!(headers["x-provider-token"], "secret-token");
        assert_eq!(headers["x-global-token"], "global-secret");
        for name in ["x-rule-token", "x-provider-token", "x-global-token"] {
            assert!(headers[name].is_sensitive());
        }
        assert!(matches!(
            result.sidecar.take_credential_program(binding),
            Err(StandaloneProviderAllowError::CredentialProgramConsumed)
        ));

        drop(result);
        drop(lease);
        primary_runtime.shutdown().await;
        std::env::remove_var("P06_RULE_TOKEN");
        std::env::remove_var("P06_GLOBAL_TOKEN");
    }

    #[tokio::test]
    async fn credential_program_rejects_foreign_plan_before_header_mutation() {
        let (primary_runtime, lease, _pool) = runtime().await;
        let generation = lease.standalone();
        let (guard, replay, provider) = admission(&lease);
        let mut result = adapt_provider_allow(
            &lease,
            0,
            provider,
            output(&lease, provider, true, None),
            None,
            guard,
            replay,
            request(generation, vec![b"original".to_vec()]),
        )
        .unwrap();
        let program = result
            .sidecar
            .take_credential_program(result.plan.binding())
            .unwrap();

        let (foreign_runtime, foreign_lease, _foreign_pool) = runtime().await;
        let foreign_generation = foreign_lease.standalone();
        let (foreign_guard, foreign_replay, foreign_provider) = admission(&foreign_lease);
        let foreign = adapt_provider_allow(
            &foreign_lease,
            0,
            foreign_provider,
            output(&foreign_lease, foreign_provider, true, None),
            None,
            foreign_guard,
            foreign_replay,
            request(foreign_generation, vec![b"original".to_vec()]),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-visible", http::HeaderValue::from_static("unchanged"));
        assert!(matches!(
            program.apply(
                foreign.plan.forwarding_plan(),
                lease.credentials(),
                &mut headers,
            ),
            Err(StandaloneProviderAllowError::Binding)
        ));
        assert_eq!(headers.len(), 1);
        assert_eq!(headers["x-visible"], "unchanged");

        drop(foreign);
        drop(foreign_lease);
        foreign_runtime.shutdown().await;
        drop(result);
        drop(lease);
        primary_runtime.shutdown().await;
    }

    #[tokio::test]
    async fn late_credential_source_failure_rolls_back_all_header_mutations() {
        let _serial = crate::activation::LISTENER_TEST_LOCK.lock().await;
        std::env::set_var("P06_RULE_TOKEN", "rule-secret");
        std::env::remove_var("P06_GLOBAL_TOKEN");

        let (runtime, lease, _pool) = runtime().await;
        let generation = lease.standalone();
        let (guard, replay, provider) = admission(&lease);
        let mut result = adapt_provider_allow(
            &lease,
            0,
            provider,
            output(&lease, provider, true, None),
            None,
            guard,
            replay,
            request(generation, vec![b"original".to_vec()]),
        )
        .unwrap();
        let program = result
            .sidecar
            .take_credential_program(result.plan.binding())
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-visible", http::HeaderValue::from_static("unchanged"));
        headers.insert("x-rule-token", http::HeaderValue::from_static("original"));
        assert!(matches!(
            program.apply(
                result.plan.forwarding_plan(),
                lease.credentials(),
                &mut headers,
            ),
            Err(StandaloneProviderAllowError::Credential(
                crate::credentials::CredentialError::SourceUnavailable
            ))
        ));
        assert_eq!(headers.len(), 2);
        assert_eq!(headers["x-visible"], "unchanged");
        assert_eq!(headers["x-rule-token"], "original");
        assert!(!headers.contains_key("x-provider-token"));
        assert!(!headers.contains_key("x-global-token"));

        drop(result);
        drop(lease);
        runtime.shutdown().await;
        std::env::remove_var("P06_RULE_TOKEN");
        std::env::remove_var("P06_GLOBAL_TOKEN");
    }

    #[tokio::test]
    async fn provider_replacement_is_redacted_before_the_single_runtime_commit() {
        let (runtime, lease, _pool) = runtime().await;
        let generation = lease.standalone();
        let (guard, replay, provider) = admission(&lease);
        let replacement = replacement(&guard, &[b"before secret after"], Some("text/plain"));
        let request = request(generation, vec![b"original".to_vec()]);
        let original_revision = request.revision();
        let lineage = request.begin_provider_invocation();
        let result = adapt_provider_allow(
            &lease,
            0,
            provider,
            output(&lease, provider, false, Some(replacement)),
            None,
            guard,
            replay,
            request,
        )
        .unwrap();

        assert_eq!(result.request.revision(), original_revision + 1);
        assert_eq!(
            result.request.body_representation(),
            BodyRepresentation::CanonicalIdentity
        );
        result.plan.validate_request(&result.request).unwrap();
        let StandaloneProviderAllow {
            plan,
            request,
            sidecar,
        } = result;
        let mut exchange = prepare_standalone_exchange(lineage, plan, request).unwrap();
        assert_eq!(replay_exchange(&mut exchange), b"before [MASKED] after");
        drop(exchange);
        drop(sidecar);
        drop(lease);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn provider_allow_without_replacement_rehomes_and_redacts_the_inspected_body_once() {
        let (runtime, lease, pool) = runtime().await;
        let generation = lease.standalone();
        let (guard, replay, provider) = admission(&lease);
        let mut inspected = guard.buffer();
        inspected
            .try_extend_from_slice(b"before secret after")
            .unwrap();
        let request = request(generation, vec![b"before secret after".to_vec()]);
        let original_revision = request.revision();
        let lineage = request.begin_provider_invocation();

        let result = adapt_provider_allow(
            &lease,
            0,
            provider,
            output(&lease, provider, true, None),
            Some(inspected.finish()),
            guard,
            replay,
            request,
        )
        .unwrap();

        assert_eq!(result.request.revision(), original_revision + 1);
        assert_eq!(
            result.request.body_representation(),
            BodyRepresentation::CanonicalIdentity
        );
        let StandaloneProviderAllow {
            plan,
            request,
            sidecar,
        } = result;
        let mut exchange = prepare_standalone_exchange(lineage, plan, request).unwrap();
        assert_eq!(replay_exchange(&mut exchange), b"before [MASKED] after");
        drop((exchange, sidecar, lease));
        assert_eq!(pool.global_charge(), 0);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn local_allow_rehomes_and_redacts_with_local_rule_provenance() {
        let local_config = CONFIG
            .replace("decision = \"delegate\"", "decision = \"allow\"")
            .replace("authorization_provider = \"approval\"\n", "");
        let (runtime, lease, pool) = runtime_from_config(&local_config).await;
        let generation = lease.standalone();
        let (guard, replay) = local_admission(&lease);
        let mut inspected = guard.buffer();
        inspected
            .try_extend_from_slice(b"local secret body")
            .unwrap();
        let request = request(generation, vec![b"local secret body".to_vec()]);
        let original_revision = request.revision();
        let lineage = request.begin_provider_invocation();

        let result = adapt_local_allow(
            &lease,
            Some(0),
            Some(inspected.finish()),
            guard,
            replay,
            request,
        )
        .unwrap();

        assert_eq!(result.request.revision(), original_revision + 1);
        assert_eq!(
            result
                .plan
                .forwarding_plan()
                .provenance()
                .reason()
                .category(),
            http_access_types::DecisionReasonCategory::Policy
        );
        let StandaloneProviderAllow {
            plan,
            request,
            sidecar,
        } = result;
        let mut exchange = prepare_standalone_exchange(lineage, plan, request).unwrap();
        assert_eq!(replay_exchange(&mut exchange), b"local [MASKED] body");
        drop((exchange, sidecar, lease));
        assert_eq!(pool.global_charge(), 0);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn foreign_generation_allow_outputs_fail_before_interpretation_or_staging() {
        let (primary_runtime, lease, pool) = runtime().await;
        let (foreign_runtime, foreign_lease, foreign_pool) = runtime().await;
        let generation = lease.standalone();
        let foreign_provider = foreign_lease
            .standalone()
            .activated()
            .rule_provider_for_test(0)
            .unwrap();
        let foreign_output = output(&foreign_lease, foreign_provider, true, None);
        let (guard, replay, provider) = admission(&lease);

        let error = adapt_provider_allow(
            &lease,
            0,
            provider,
            foreign_output,
            None,
            guard,
            replay,
            request(generation, vec![b"original".to_vec()]),
        )
        .err()
        .expect("a foreign provider-output registry must fail closed");

        assert!(matches!(error.error, StandaloneProviderAllowError::Binding));
        assert_eq!(pool.global_charge(), 0);

        let (guard, replay, provider) = admission(&lease);
        let foreign_plain_allow = output(&foreign_lease, foreign_provider, false, None);
        assert!(adapt_provider_allow(
            &lease,
            0,
            provider,
            foreign_plain_allow,
            None,
            guard,
            replay,
            request(generation, vec![b"original".to_vec()]),
        )
        .is_err_and(|failure| matches!(failure.error, StandaloneProviderAllowError::Binding)));
        assert_eq!(pool.global_charge(), 0);

        let (foreign_guard, foreign_replay, _) = admission(&foreign_lease);
        let foreign_replacement = replacement(
            &foreign_guard,
            &[b"foreign replacement"],
            Some("application/foreign"),
        );
        drop(foreign_guard);
        drop(foreign_replay);
        let foreign_replacement_allow = output(
            &foreign_lease,
            foreign_provider,
            false,
            Some(foreign_replacement),
        );
        let (guard, replay, provider) = admission(&lease);
        assert!(adapt_provider_allow(
            &lease,
            0,
            provider,
            foreign_replacement_allow,
            None,
            guard,
            replay,
            request(generation, vec![b"original".to_vec()]),
        )
        .is_err_and(|failure| matches!(failure.error, StandaloneProviderAllowError::Binding)));
        assert_eq!(pool.global_charge(), 0);
        assert_eq!(foreign_pool.global_charge(), 0);
        drop(foreign_lease);
        foreign_runtime.shutdown().await;
        drop(lease);
        primary_runtime.shutdown().await;
    }

    #[tokio::test]
    async fn non_identity_provider_replacement_fails_before_commit_and_releases_charges() {
        let (runtime, lease, pool) = runtime().await;
        let generation = lease.standalone();
        let (guard, replay, provider) = admission(&lease);
        let replacement = replacement_with_encoding(&guard, b"replacement", "gzip");
        let request = request(generation, vec![b"original".to_vec()]);

        let error = adapt_provider_allow(
            &lease,
            0,
            provider,
            output(&lease, provider, true, Some(replacement)),
            None,
            guard,
            replay,
            request,
        )
        .err()
        .expect("a non-identity provider replacement must fail closed");

        assert_eq!(
            error.provider_replacement_size(),
            Some(b"replacement".len())
        );
        assert!(matches!(
            error.error,
            StandaloneProviderAllowError::ProviderReplacement(
                ProviderBodyReplacementDecodeError::InvalidBody
            )
        ));
        assert_eq!(pool.global_charge(), 0);
        drop(lease);
        runtime.shutdown().await;
    }

    #[test]
    fn invalid_content_type_is_rejected_by_pure_precommit_preparation() {
        assert!(matches!(
            content_type_batch(Some("invalid\nvalue".to_owned())),
            Err(StandaloneProviderAllowError::ContentType)
        ));
    }

    #[tokio::test]
    async fn invalid_content_type_releases_all_product_charges() {
        let (runtime, lease, pool) = runtime().await;
        let generation = lease.standalone();
        let (guard, replay, provider) = admission(&lease);
        let replacement = replacement(&guard, &[b"replacement"], Some("invalid\nvalue"));
        let error = adapt_provider_allow(
            &lease,
            0,
            provider,
            output(&lease, provider, true, Some(replacement)),
            None,
            guard,
            replay,
            request(generation, vec![b"original".to_vec()]),
        )
        .err()
        .expect("invalid Content-Type must fail before request replacement");
        assert_eq!(
            error.provider_replacement_size(),
            Some(b"replacement".len())
        );
        assert!(matches!(
            error.error,
            StandaloneProviderAllowError::ContentType
        ));
        assert_eq!(pool.global_charge(), 0);
        drop(lease);
        runtime.shutdown().await;
    }
}
