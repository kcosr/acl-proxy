use credential_core::{
    CredentialDescriptor, CredentialLimits, CredentialProfile, CredentialPurpose,
};
use std::sync::Arc;

use http_access_policy_acl::MatchedEffects;
#[cfg(all(test, unix))]
use http_access_policy_acl::{EvaluationInput, PolicyEvaluation, ProviderDisposition};
use http_access_redaction::{PayloadClass, RedactionProfile};
use http_access_runtime::{
    RuntimeRequest, StandalonePlan, StandaloneTrusted, UpgradeAdmissionPlan,
    UpgradeAdmissionPlanError,
};
#[cfg(all(test, unix))]
use http_access_types::BodyObservation;
use http_access_types::{
    BodyRepresentation, CredentialMutation, CredentialMutationKind, DecisionProvenance,
    ForwardingPlan, ForwardingPlanInput, HeaderMutation, HeaderMutationBatch,
    HeaderMutationCondition, HeaderName, HeaderValue, PlanBinding, UpgradeIntent, UpgradePolicy,
};

use crate::authorization::protocol::{
    ProviderBodyReplacementDecodeError, ProviderCredentialWireError, ProviderCredentialWireStore,
};
use crate::authorization::AuthorizationAllowOutput;
use crate::credential_buffers::ProductCredentialBufferContext;
use crate::credential_resolver::{ProductCredentialBinding, ProductCredentialPreparation};
use crate::credentials::OutboundCredentialSource;
use crate::policy::ProductRuleEffectsRef;
use crate::runtime::{GenerationLease, ProviderIndex};
use crate::safety::{GuardedBody, HttpWireBodyGuard};
use crate::standalone::{
    BoundCredentialSource, ProviderCredentialTemplates, StandaloneCaptureEvent,
    StandaloneGenerationPlan,
};

pub(crate) struct StandaloneProviderAllow {
    pub(crate) plan: StandalonePlan,
    pub(crate) request: RuntimeRequest,
    pub(crate) sidecar: StandaloneRequestSidecar,
    pub(crate) credentials: Option<ProductCredentialPreparation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StandaloneAllowMode {
    OriginRequest,
    OuterConnect,
}

/// Product-only resources and secret bindings for one validated forwarding pair.
///
/// The shared plan contains only opaque credential references. Provider values
/// stay guarded here until the terminal dispatcher consumes them for the exact
/// plan binding.
pub(crate) struct StandaloneRequestSidecar {
    plan_binding: PlanBinding,
    capture_body: StandaloneCaptureBody,
    upgrade: Option<UpgradeAdmissionPlan>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StandaloneCaptureBody {
    Stream { canonical_identity: bool },
    ProviderReplacement { size: usize },
}

struct ProductSourceCredential {
    descriptor: CredentialDescriptor,
    source: OutboundCredentialSource,
}

struct ProductSourceCredentials {
    rule: Vec<ProductSourceCredential>,
    global: Vec<ProductSourceCredential>,
}

struct SelectedProviderCredential {
    descriptor: CredentialDescriptor,
    mutation: CredentialMutation,
    output: crate::authorization::protocol::ProviderOutputIndex,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StandaloneProviderAllowError {
    #[error("provider allow result does not match the activated standalone binding")]
    Binding,
    #[error("provider credential output could not be staged")]
    ProviderCredential(#[source] ProviderCredentialWireError),
    #[error("credential preparation failed")]
    Credential(#[source] credential_core::CredentialError),
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
    #[error("provider allow upgrade admission is invalid")]
    Upgrade(#[source] UpgradeAdmissionPlanError),
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

    pub(crate) fn take_upgrade_admission(
        &mut self,
        plan_binding: PlanBinding,
    ) -> Result<Option<UpgradeAdmissionPlan>, StandaloneProviderAllowError> {
        if plan_binding != self.plan_binding {
            return Err(StandaloneProviderAllowError::Binding);
        }
        Ok(self.upgrade.take())
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn adapt_provider_allow(
    lease: &GenerationLease,
    effects: ProductRuleEffectsRef,
    provenance: &DecisionProvenance,
    provider: ProviderIndex,
    output: AuthorizationAllowOutput,
    allow_mode: StandaloneAllowMode,
    inspected_body: Option<GuardedBody>,
    guard: HttpWireBodyGuard,
    request: RuntimeRequest,
) -> Result<StandaloneProviderAllow, StandaloneProviderAllowFailure> {
    let mut provider_replacement_size = None;
    adapt_provider_allow_inner(
        lease,
        effects,
        provenance,
        provider,
        output,
        allow_mode,
        inspected_body,
        guard,
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
    allow_mode: StandaloneAllowMode,
    inspected_body: Option<GuardedBody>,
    guard: HttpWireBodyGuard,
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
    let outer_connect = allow_mode == StandaloneAllowMode::OuterConnect;
    let (credentials, replacement) = authorization
        .consume_allow_output(provider, output)
        .ok_or(StandaloneProviderAllowError::Binding)?;
    if outer_connect && (credentials.is_some() || replacement.is_some()) {
        return Err(StandaloneProviderAllowError::Binding);
    }
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
    let upgrade_redaction = compile_upgrade_redaction(lease, Some(rule_ordinal), &request)?;

    let (provider_credentials, provider_wire) = if outer_connect {
        (Vec::new(), None)
    } else {
        let selected = collect_provider_credentials(
            generation,
            provider,
            provider_templates,
            credentials.as_ref(),
        )?;
        let wire = credentials
            .as_ref()
            .map(|credentials| {
                authorization.compact_provider_credential_wire(provider, credentials, &guard)
            })
            .transpose()
            .map_err(StandaloneProviderAllowError::ProviderCredential)?;
        (selected, wire)
    };
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
            Some(binding) => redact_required_wire_body(binding.handle(), &guard, decoded)?,
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
        allow_mode,
        provider_credentials,
        provider_wire,
        provider_content_type,
        provider_replacement_size,
        upgrade_redaction,
        guard,
        request,
        lease.credential_io_runtime(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn adapt_local_allow(
    lease: &GenerationLease,
    effects: MatchedEffects<ProductRuleEffectsRef>,
    provenance: &DecisionProvenance,
    allow_mode: StandaloneAllowMode,
    inspected_body: Option<GuardedBody>,
    guard: HttpWireBodyGuard,
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
    let upgrade_redaction = compile_upgrade_redaction(lease, rule_ordinal, &request)?;
    finish_allow(
        generation,
        rule,
        provenance,
        allow_mode,
        Vec::new(),
        None,
        None,
        None,
        upgrade_redaction,
        guard,
        request,
        lease.credential_io_runtime(),
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
        Some(binding) => redact_required_wire_body(binding.handle(), guard, body)?,
        None => body,
    };
    let length = u64::try_from(body.len()).map_err(|_| StandaloneProviderAllowError::Binding)?;
    request
        .replace_body_fragments(length, body.segments())
        .map_err(StandaloneProviderAllowError::Runtime)
}

fn redact_required_wire_body(
    profile: &RedactionProfile,
    guard: &HttpWireBodyGuard,
    body: GuardedBody,
) -> Result<GuardedBody, StandaloneProviderAllowError> {
    let outcome = profile
        .redact_http_body(guard, body)
        .map_err(|_| StandaloneProviderAllowError::Redaction)?;
    if outcome.class() == PayloadClass::Binary && profile.requires_text_class() {
        return Err(StandaloneProviderAllowError::Redaction);
    }
    Ok(outcome.into_body())
}

#[allow(clippy::too_many_arguments)]
fn finish_allow(
    generation: &StandaloneGenerationPlan,
    rule: Option<(usize, &crate::standalone::StandaloneRuleTemplate)>,
    provenance: &http_access_types::DecisionProvenance,
    allow_mode: StandaloneAllowMode,
    provider_credentials: Vec<SelectedProviderCredential>,
    provider_wire: Option<ProviderCredentialWireStore>,
    provider_content_type: Option<HeaderMutationBatch>,
    provider_replacement_size: Option<usize>,
    upgrade_redaction: Option<http_access_redaction::RedactionProfile>,
    guard: HttpWireBodyGuard,
    request: RuntimeRequest,
    credential_io_runtime: Arc<crate::credential_io_runtime::CredentialIoRuntime>,
) -> Result<StandaloneProviderAllow, StandaloneProviderAllowError> {
    let rule_template = rule.map(|(_, rule)| rule);
    let outer_connect = allow_mode == StandaloneAllowMode::OuterConnect;

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

    // Outer CONNECT is a credential-free tunnel bootstrap. The logical request
    // inside the MITM tunnel receives its own plan and credential execution.
    let mut credential_mutations: Vec<CredentialMutation> = if outer_connect {
        Vec::new()
    } else {
        rule_template
            .map(|rule| {
                rule.credentials()
                    .iter()
                    .map(|template| template.mutation().clone())
                    .collect()
            })
            .unwrap_or_default()
    };
    if !outer_connect {
        credential_mutations.extend(
            provider_credentials
                .iter()
                .map(|credential| credential.mutation.clone()),
        );
        credential_mutations.extend(
            generation
                .global_credentials()
                .iter()
                .map(|template| template.mutation().clone()),
        );
    }

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
        origin_protocol: generation.origin_protocol(request.facts().version()),
        route: generation.route().clone(),
        origin_security: generation.origin_security(
            request.facts().url().scheme(),
            request.facts().url().authority().host().clone(),
        ),
        managed_network_policy: None,
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
    let upgrade_admission = if matches!(plan.forwarding_plan().upgrade(), UpgradePolicy::Deny) {
        if upgrade_redaction.is_some() {
            return Err(StandaloneProviderAllowError::Binding);
        }
        None
    } else {
        Some(
            UpgradeAdmissionPlan::new(plan.forwarding_plan(), upgrade_redaction)
                .map_err(StandaloneProviderAllowError::Upgrade)?,
        )
    };
    let credential_preparation = if outer_connect {
        None
    } else {
        prepare_credentials(
            &plan,
            collect_credential_sources(generation, rule)?,
            provider_credentials,
            provider_wire,
            &guard,
            credential_io_runtime,
        )?
    };
    let sidecar = StandaloneRequestSidecar {
        plan_binding,
        capture_body,
        upgrade: upgrade_admission,
    };
    Ok(StandaloneProviderAllow {
        plan,
        request,
        sidecar,
        credentials: credential_preparation,
    })
}

fn collect_provider_credentials(
    generation: &StandaloneGenerationPlan,
    provider: ProviderIndex,
    templates: &ProviderCredentialTemplates,
    credentials: Option<&crate::authorization::protocol::ProviderCredentialSet>,
) -> Result<Vec<SelectedProviderCredential>, StandaloneProviderAllowError> {
    let bindings = generation
        .activated()
        .provider_outputs()
        .iter()
        .filter(|binding| binding.provider() == provider)
        .collect::<Vec<_>>();
    if bindings.len() != templates.outputs().len() {
        return Err(StandaloneProviderAllowError::Binding);
    }
    let mut selected = Vec::new();
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
            selected.push(SelectedProviderCredential {
                descriptor: descriptor_for_mutation(
                    template.mutation(),
                    CredentialLimits::new(credential_core::MAX_CREDENTIAL_MATERIAL_BYTES, 0)
                        .map_err(StandaloneProviderAllowError::Credential)?,
                )?,
                mutation: template.mutation().clone(),
                output: binding.output(),
            });
        }
    }
    Ok(selected)
}

fn collect_credential_sources(
    generation: &StandaloneGenerationPlan,
    rule: Option<(usize, &crate::standalone::StandaloneRuleTemplate)>,
) -> Result<ProductSourceCredentials, StandaloneProviderAllowError> {
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
        for (binding, template) in rule_bindings.iter().zip(rule.credentials()) {
            push_credential_source(&mut rule_sources, binding, template.mutation())?;
        }
    }
    if generation.activated().global_credentials().len() != generation.global_credentials().len() {
        return Err(StandaloneProviderAllowError::Binding);
    }
    let mut global_sources = Vec::with_capacity(generation.activated().global_credentials().len());
    for (binding, template) in generation
        .activated()
        .global_credentials()
        .iter()
        .zip(generation.global_credentials())
    {
        push_credential_source(&mut global_sources, binding, template.mutation())?;
    }
    Ok(ProductSourceCredentials {
        rule: rule_sources,
        global: global_sources,
    })
}

fn push_credential_source(
    result: &mut Vec<ProductSourceCredential>,
    binding: &BoundCredentialSource,
    mutation: &CredentialMutation,
) -> Result<(), StandaloneProviderAllowError> {
    if binding.reference() != mutation.credential() {
        return Err(StandaloneProviderAllowError::Binding);
    }
    result.push(ProductSourceCredential {
        descriptor: binding.descriptor().clone(),
        source: binding.source().clone(),
    });
    Ok(())
}

fn prepare_credentials(
    plan: &StandalonePlan,
    sources: ProductSourceCredentials,
    provider_credentials: Vec<SelectedProviderCredential>,
    provider_wire: Option<ProviderCredentialWireStore>,
    guard: &HttpWireBodyGuard,
    io: Arc<crate::credential_io_runtime::CredentialIoRuntime>,
) -> Result<Option<ProductCredentialPreparation>, StandaloneProviderAllowError> {
    let total = sources
        .rule
        .len()
        .checked_add(provider_credentials.len())
        .and_then(|count| count.checked_add(sources.global.len()))
        .ok_or(StandaloneProviderAllowError::Credential(
            credential_core::CredentialError::ResourceLimit,
        ))?;
    if total == 0 {
        return Ok(None);
    }
    let provider_wire = provider_wire.map(Arc::new);
    if !provider_credentials.is_empty() && provider_wire.is_none() {
        return Err(StandaloneProviderAllowError::Binding);
    }
    let mut descriptors = Vec::new();
    descriptors.try_reserve_exact(total).map_err(|_| {
        StandaloneProviderAllowError::Credential(credential_core::CredentialError::ResourceLimit)
    })?;
    let mut bindings = Vec::new();
    bindings.try_reserve_exact(total).map_err(|_| {
        StandaloneProviderAllowError::Credential(credential_core::CredentialError::ResourceLimit)
    })?;

    let ProductSourceCredentials { rule, global } = sources;
    for source in rule {
        let reference = source.descriptor.reference().compact_clone();
        descriptors.push(source.descriptor);
        bindings.push(ProductCredentialBinding::source(reference, source.source));
    }
    if !provider_credentials.is_empty() {
        let store = provider_wire.ok_or(StandaloneProviderAllowError::Binding)?;
        for provider in provider_credentials {
            let reference = provider.descriptor.reference().compact_clone();
            descriptors.push(provider.descriptor);
            bindings.push(ProductCredentialBinding::provider(
                reference,
                provider.output,
                Arc::clone(&store),
            ));
        }
    }
    for source in global {
        let reference = source.descriptor.reference().compact_clone();
        descriptors.push(source.descriptor);
        bindings.push(ProductCredentialBinding::source(reference, source.source));
    }

    let buffers = ProductCredentialBufferContext::new(guard.clone());
    ProductCredentialPreparation::prepare(
        plan.forwarding_plan_arc(),
        descriptors,
        bindings,
        buffers,
        io,
    )
    .map(Some)
    .map_err(StandaloneProviderAllowError::Credential)
}

fn descriptor_for_mutation(
    mutation: &CredentialMutation,
    limits: CredentialLimits,
) -> Result<CredentialDescriptor, StandaloneProviderAllowError> {
    let purpose = match mutation.kind() {
        CredentialMutationKind::Bearer(_) => CredentialPurpose::Bearer,
        CredentialMutationKind::Basic { .. } => CredentialPurpose::BasicPassword,
        CredentialMutationKind::CustomHeader { name, .. } => {
            CredentialPurpose::CustomHeader(name.compact_clone())
        }
    };
    CredentialDescriptor::new(
        mutation.credential().compact_clone(),
        purpose,
        CredentialProfile::StandaloneTrusted,
        limits,
    )
    .map_err(StandaloneProviderAllowError::Credential)
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

fn compile_upgrade_redaction(
    lease: &GenerationLease,
    rule_ordinal: Option<usize>,
    request: &RuntimeRequest,
) -> Result<Option<http_access_redaction::RedactionProfile>, StandaloneProviderAllowError> {
    if request.facts().upgrade().is_none() {
        return Ok(None);
    }
    let ordinal = rule_ordinal.ok_or(StandaloneProviderAllowError::Binding)?;
    let wire_redaction = lease
        .standalone()
        .activated()
        .rule_redaction(ordinal)
        .map(|binding| binding.handle().clone());
    Ok(wire_redaction)
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
    use crate::config::{compile_config_text, CompiledConfig, ConfigTextInput, RuntimeCandidate};
    use crate::runtime::{
        ActivationCancellation, CandidateSource, GenerationLease, Runtime, RuntimeError,
        StaticOwnership,
    };
    use crate::safety::WireBodyQuotaKey;

    const CONFIG: &str = r#"schema_version = 4

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
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
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
transport_security = "tls_required"
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
transport_security = "tls_required"
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
transport_security = "tls_required"
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
        ) -> BoxFuture<'_, Result<RuntimeCandidate, RuntimeError>> {
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
        let resources = ProductStaticResources::try_new(&initial.static_config)
            .await
            .unwrap();
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
        runtime
            .start(initial.into_runtime_candidate())
            .await
            .unwrap();
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
            PolicyHeaderFacts::new(
                facts.headers().to_vec(),
                generation.sensitive_headers().to_vec(),
            )
            .unwrap(),
            BodyRepresentation::PreservedContentCoded,
            body,
            30_001,
            Arc::new(access_identity::IdentityContext::Disabled),
        )
        .unwrap();
        observe_body(&mut request);
        request
    }

    fn connect_request(generation: &StandaloneGenerationPlan) -> RuntimeRequest {
        let facts = http_access_types::InterceptedRequestFacts::new(
            IngressMode::ExplicitHttp,
            HttpVersion::Http11,
            HttpMethod::new("CONNECT").unwrap(),
            http_access_url::canonicalize_http_url("https://example.test/").unwrap(),
            Vec::new(),
            BodyMetadata::new(BodyFraming::None),
            None,
        )
        .unwrap();
        let body = RuntimeBody::from_chunks(
            Vec::new(),
            body_bounds(generation),
            Arc::new(TestClock),
            BodyBudget::new(32 * 1024 * 1024).unwrap(),
            30_001,
        )
        .unwrap();
        let mut request = RuntimeRequest::new(
            facts.clone(),
            "192.0.2.10".parse().unwrap(),
            PolicyHeaderFacts::new(
                facts.headers().to_vec(),
                generation.sensitive_headers().to_vec(),
            )
            .unwrap(),
            BodyRepresentation::PreservedContentCoded,
            body,
            30_001,
            Arc::new(access_identity::IdentityContext::Disabled),
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

    fn admission(lease: &GenerationLease) -> (HttpWireBodyGuard, ProviderIndex) {
        let guard = local_admission(lease);
        let provider = lease
            .standalone()
            .activated()
            .rule_provider_for_test(0)
            .unwrap();
        (guard, provider)
    }

    fn local_admission(lease: &GenerationLease) -> HttpWireBodyGuard {
        let peer: IpAddr = "192.0.2.10".parse().unwrap();
        let request = request(lease.standalone(), Vec::new());
        admission_for_request(lease, &request, peer)
    }

    fn admission_for_request(
        lease: &GenerationLease,
        request: &RuntimeRequest,
        peer: IpAddr,
    ) -> HttpWireBodyGuard {
        let input = EvaluationInput::new(
            request.facts(),
            peer,
            Some(peer),
            request.policy_header_facts(),
            RuntimeRequest::INITIAL_REVISION,
            BodyRepresentation::PreservedContentCoded,
            BodyObservation::unobserved(),
            request.identity(),
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
        drop(replay);
        guard
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
        request: RuntimeRequest,
    ) -> Result<StandaloneProviderAllow, StandaloneProviderAllowFailure> {
        adapt_provider_allow_with_mode(
            lease,
            rule_ordinal,
            provider,
            output,
            StandaloneAllowMode::OriginRequest,
            inspected_body,
            guard,
            request,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn adapt_provider_allow_with_mode(
        lease: &GenerationLease,
        rule_ordinal: usize,
        provider: ProviderIndex,
        output: AuthorizationAllowOutput,
        allow_mode: StandaloneAllowMode,
        inspected_body: Option<GuardedBody>,
        guard: HttpWireBodyGuard,
        request: RuntimeRequest,
    ) -> Result<StandaloneProviderAllow, StandaloneProviderAllowFailure> {
        let input = EvaluationInput::new(
            request.facts(),
            "192.0.2.10".parse().unwrap(),
            Some("192.0.2.10".parse().unwrap()),
            request.policy_header_facts(),
            RuntimeRequest::INITIAL_REVISION,
            BodyRepresentation::PreservedContentCoded,
            BodyObservation::unobserved(),
            request.identity(),
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
            allow_mode,
            inspected_body,
            guard,
            request,
        )
    }

    fn adapt_local_allow(
        lease: &GenerationLease,
        rule_ordinal: Option<usize>,
        inspected_body: Option<GuardedBody>,
        guard: HttpWireBodyGuard,
        request: RuntimeRequest,
    ) -> Result<StandaloneProviderAllow, StandaloneProviderAllowError> {
        let input = EvaluationInput::new(
            request.facts(),
            "192.0.2.10".parse().unwrap(),
            Some("192.0.2.10".parse().unwrap()),
            request.policy_header_facts(),
            RuntimeRequest::INITIAL_REVISION,
            BodyRepresentation::PreservedContentCoded,
            BodyObservation::unobserved(),
            request.identity(),
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
            StandaloneAllowMode::OriginRequest,
            inspected_body,
            guard,
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
            let (guard, provider) = admission(&lease);
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
            assert!(result.credentials.is_some());
            let credential_mutations = result.plan.forwarding_plan().credential_mutations();
            assert_eq!(credential_mutations.len(), 3);
            assert_eq!(
                credential_mutations[0].credential(),
                generation.rules()[0].credentials()[0]
                    .mutation()
                    .credential()
            );
            assert_eq!(
                credential_mutations[1].credential(),
                generation.provider_credentials()[provider.get()].outputs()[0]
                    .mutation()
                    .credential()
            );
            assert_eq!(
                credential_mutations[2].credential(),
                generation.global_credentials()[0].mutation().credential()
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
                forwarding.origin_protocol(),
                generation.origin_protocol(result.request.facts().version())
            );
            assert_eq!(
                forwarding.origin_security(),
                &generation.origin_security(
                    result.request.facts().url().scheme(),
                    result.request.facts().url().authority().host().clone(),
                )
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
                credentials,
            } = result;
            let mut exchange = prepare_standalone_exchange(lineage, plan, request).unwrap();
            assert_eq!(replay_exchange(&mut exchange), expected);
            drop(exchange);
            drop(credentials);
            drop(sidecar);
            assert_eq!(pool.global_charge(), 0);
            drop(lease);
            runtime.shutdown().await;
        }
    }

    #[tokio::test]
    async fn content_type_preserve_remove_set_and_credential_ownership_are_exact() {
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
            let (guard, provider) = admission(&lease);
            let replacement =
                replacement_type.map(|content_type| replacement(&guard, &[b"body"], content_type));
            let mut result = adapt_provider_allow(
                &lease,
                0,
                provider,
                output(&lease, provider, true, replacement),
                None,
                guard,
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

            let plan = result.plan.forwarding_plan_arc();
            let preparation = result.credentials.take().unwrap();
            if let Some(foreign_plan) = foreign_binding.as_ref() {
                assert!(matches!(
                    preparation.admit_for_plan(foreign_plan),
                    Err(credential_core::CredentialError::BindingMismatch)
                ));
            } else {
                drop(preparation.admit_for_plan(&plan).unwrap());
            }
            foreign_binding = Some(plan);
            drop(result);
            drop(lease);
            runtime.shutdown().await;
        }
        std::env::remove_var("P06_RULE_TOKEN");
        std::env::remove_var("P06_GLOBAL_TOKEN");
    }

    #[tokio::test]
    async fn delegated_outer_connect_skips_required_provider_origin_credentials() {
        let config = CONFIG
            .replace("methods = [\"POST\"]", "methods = [\"CONNECT\"]")
            .replace("required = false", "required = true");
        let (runtime, lease, _pool) = runtime_from_config(&config).await;
        let request = connect_request(lease.standalone());
        let peer = "192.0.2.10".parse().unwrap();
        let guard = admission_for_request(&lease, &request, peer);
        let provider = lease
            .standalone()
            .activated()
            .rule_provider_for_test(0)
            .unwrap();
        let lineage = request.begin_provider_invocation();

        let result = adapt_provider_allow_with_mode(
            &lease,
            0,
            provider,
            output(&lease, provider, false, None),
            StandaloneAllowMode::OuterConnect,
            None,
            guard,
            request,
        )
        .expect("outer CONNECT must not require origin credential outputs");

        assert!(result.credentials.is_none());
        assert!(result
            .plan
            .forwarding_plan()
            .credential_mutations()
            .is_empty());
        drop((result, lineage));

        let request = connect_request(lease.standalone());
        let guard = admission_for_request(&lease, &request, peer);
        let output_with_effects = output(&lease, provider, true, None);
        assert!(adapt_provider_allow_with_mode(
            &lease,
            0,
            provider,
            output_with_effects,
            StandaloneAllowMode::OuterConnect,
            None,
            guard,
            request,
        )
        .is_err_and(|failure| matches!(failure.error, StandaloneProviderAllowError::Binding)));
        drop(lease);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn credential_preparation_rejects_same_binding_with_different_plan_allocation() {
        let (primary_runtime, lease, _pool) = runtime().await;
        let generation = lease.standalone();
        let (guard, provider) = admission(&lease);
        let mut result = adapt_provider_allow(
            &lease,
            0,
            provider,
            output(&lease, provider, true, None),
            None,
            guard,
            request(generation, vec![b"original".to_vec()]),
        )
        .unwrap();
        let plan = result.plan.forwarding_plan_arc();
        let copied_plan = Arc::new(plan.as_ref().clone());
        assert_eq!(copied_plan.binding(), plan.binding());
        assert!(!Arc::ptr_eq(&copied_plan, &plan));
        let preparation = result.credentials.take().unwrap();
        assert!(matches!(
            preparation.admit_for_plan(&copied_plan),
            Err(credential_core::CredentialError::BindingMismatch)
        ));

        drop(result);
        drop(lease);
        primary_runtime.shutdown().await;
    }

    #[tokio::test]
    async fn provider_replacement_is_redacted_before_the_single_runtime_commit() {
        let (runtime, lease, _pool) = runtime().await;
        let generation = lease.standalone();
        let (guard, provider) = admission(&lease);
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
            request: forwarded_request,
            sidecar,
            credentials,
        } = result;
        let mut exchange = prepare_standalone_exchange(lineage, plan, forwarded_request).unwrap();
        assert_eq!(replay_exchange(&mut exchange), b"before [MASKED] after");
        drop(exchange);
        drop(credentials);
        drop(sidecar);
        drop(lease);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn provider_allow_without_replacement_rehomes_and_redacts_the_inspected_body_once() {
        let (runtime, lease, pool) = runtime().await;
        let generation = lease.standalone();
        let (guard, provider) = admission(&lease);
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
            credentials,
        } = result;
        let mut exchange = prepare_standalone_exchange(lineage, plan, request).unwrap();
        assert_eq!(replay_exchange(&mut exchange), b"before [MASKED] after");
        drop((exchange, sidecar, credentials, lease));
        assert_eq!(pool.global_charge(), 0);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn text_only_wire_redaction_rejects_binary_inspected_and_provider_bodies() {
        let local_config = CONFIG
            .replace("decision = \"delegate\"", "decision = \"allow\"")
            .replace("authorization_provider = \"approval\"\n", "");
        let (local_runtime, lease, pool) = runtime_from_config(&local_config).await;
        let generation = lease.standalone();
        let guard = local_admission(&lease);
        let mut inspected = guard.buffer();
        inspected.try_extend_from_slice(b"secret\xff").unwrap();
        let error = adapt_local_allow(
            &lease,
            Some(0),
            Some(inspected.finish()),
            guard,
            request(generation, vec![b"secret\xff".to_vec()]),
        )
        .err()
        .expect("text-only wire protection must reject a binary inspected body");
        assert!(matches!(error, StandaloneProviderAllowError::Redaction));
        assert_eq!(pool.global_charge(), 0);
        drop(lease);
        local_runtime.shutdown().await;

        let (runtime, lease, pool) = runtime().await;
        let generation = lease.standalone();
        let (guard, provider) = admission(&lease);
        let replacement = replacement(&guard, &[b"secret\xff"], Some("application/octet-stream"));
        let error = adapt_provider_allow(
            &lease,
            0,
            provider,
            output(&lease, provider, false, Some(replacement)),
            None,
            guard,
            request(generation, vec![b"original".to_vec()]),
        )
        .err()
        .expect("text-only wire protection must reject a binary provider replacement");
        assert_eq!(error.provider_replacement_size(), Some(b"secret\xff".len()));
        assert!(matches!(
            error.into_error(),
            StandaloneProviderAllowError::Redaction
        ));
        assert_eq!(pool.global_charge(), 0);
        drop(lease);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn both_wire_redaction_protects_binary_inspected_and_provider_bodies() {
        let both_config = CONFIG.replace("payloads = \"text\"", "payloads = \"both\"");
        let local_config = both_config
            .replace("decision = \"delegate\"", "decision = \"allow\"")
            .replace("authorization_provider = \"approval\"\n", "");
        let (local_runtime, lease, pool) = runtime_from_config(&local_config).await;
        let generation = lease.standalone();
        let guard = local_admission(&lease);
        let mut inspected = guard.buffer();
        inspected.try_extend_from_slice(b"secret\xff").unwrap();
        let local_request = request(generation, vec![b"secret\xff".to_vec()]);
        let lineage = local_request.begin_provider_invocation();
        let result = adapt_local_allow(
            &lease,
            Some(0),
            Some(inspected.finish()),
            guard,
            local_request,
        )
        .unwrap();
        let StandaloneProviderAllow {
            plan,
            request: forwarded_request,
            sidecar,
            credentials,
        } = result;
        let mut exchange = prepare_standalone_exchange(lineage, plan, forwarded_request).unwrap();
        assert_eq!(replay_exchange(&mut exchange), b"[MASKED]\xff");
        drop((exchange, sidecar, credentials, lease));
        assert_eq!(pool.global_charge(), 0);
        local_runtime.shutdown().await;

        let (runtime, lease, pool) = runtime_from_config(&both_config).await;
        let generation = lease.standalone();
        let (guard, provider) = admission(&lease);
        let replacement = replacement(&guard, &[b"secret\xff"], Some("application/octet-stream"));
        let request = request(generation, vec![b"original".to_vec()]);
        let lineage = request.begin_provider_invocation();
        let result = adapt_provider_allow(
            &lease,
            0,
            provider,
            output(&lease, provider, false, Some(replacement)),
            None,
            guard,
            request,
        )
        .unwrap();
        let StandaloneProviderAllow {
            plan,
            request,
            sidecar,
            credentials,
        } = result;
        let mut exchange = prepare_standalone_exchange(lineage, plan, request).unwrap();
        assert_eq!(replay_exchange(&mut exchange), b"[MASKED]\xff");
        drop((exchange, sidecar, credentials, lease));
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
        let guard = local_admission(&lease);
        let mut inspected = guard.buffer();
        inspected
            .try_extend_from_slice(b"local secret body")
            .unwrap();
        let request = request(generation, vec![b"local secret body".to_vec()]);
        let original_revision = request.revision();
        let lineage = request.begin_provider_invocation();

        let result =
            adapt_local_allow(&lease, Some(0), Some(inspected.finish()), guard, request).unwrap();

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
            credentials,
        } = result;
        let mut exchange = prepare_standalone_exchange(lineage, plan, request).unwrap();
        assert_eq!(replay_exchange(&mut exchange), b"local [MASKED] body");
        drop((exchange, sidecar, credentials, lease));
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
        let (guard, provider) = admission(&lease);

        let error = adapt_provider_allow(
            &lease,
            0,
            provider,
            foreign_output,
            None,
            guard,
            request(generation, vec![b"original".to_vec()]),
        )
        .err()
        .expect("a foreign provider-output registry must fail closed");

        assert!(matches!(error.error, StandaloneProviderAllowError::Binding));
        assert_eq!(pool.global_charge(), 0);

        let (guard, provider) = admission(&lease);
        let foreign_plain_allow = output(&foreign_lease, foreign_provider, false, None);
        assert!(adapt_provider_allow(
            &lease,
            0,
            provider,
            foreign_plain_allow,
            None,
            guard,
            request(generation, vec![b"original".to_vec()]),
        )
        .is_err_and(|failure| matches!(failure.error, StandaloneProviderAllowError::Binding)));
        assert_eq!(pool.global_charge(), 0);

        let (foreign_guard, _) = admission(&foreign_lease);
        let foreign_replacement = replacement(
            &foreign_guard,
            &[b"foreign replacement"],
            Some("application/foreign"),
        );
        drop(foreign_guard);
        let foreign_replacement_allow = output(
            &foreign_lease,
            foreign_provider,
            false,
            Some(foreign_replacement),
        );
        let (guard, provider) = admission(&lease);
        assert!(adapt_provider_allow(
            &lease,
            0,
            provider,
            foreign_replacement_allow,
            None,
            guard,
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
        let (guard, provider) = admission(&lease);
        let replacement = replacement_with_encoding(&guard, b"replacement", "gzip");
        let request = request(generation, vec![b"original".to_vec()]);

        let error = adapt_provider_allow(
            &lease,
            0,
            provider,
            output(&lease, provider, true, Some(replacement)),
            None,
            guard,
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
        let (guard, provider) = admission(&lease);
        let replacement = replacement(&guard, &[b"replacement"], Some("invalid\nvalue"));
        let error = adapt_provider_allow(
            &lease,
            0,
            provider,
            output(&lease, provider, true, Some(replacement)),
            None,
            guard,
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
