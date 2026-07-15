use std::collections::BTreeMap;
use std::time::Duration;

use http_access_runtime::{RuntimeResourceLimits, SnapshotLease, SnapshotRegistries};
use http_access_types::{
    BodyLimits, BodyRepresentation, CaptureIntent, CaptureRef, CredentialMutation,
    CredentialMutationKind, CredentialRef, DecisionProvenance, DecisionReason,
    DecisionReasonCategory, EffectivePolicy, HeaderMutation, HeaderMutationBatch,
    HeaderMutationCondition, HeaderName, HeaderValue, HttpScheme, PolicyGeneration, RedactionRef,
    RedirectPolicy, RequestBodyPolicy, Route, SnapshotIdentity, StableId, StageTimeouts, TlsIntent,
    TlsRootsRef, TrailerPolicy,
};
use http_access_url::canonicalize_http_url;

use crate::authorization::protocol::{ProviderOutputDefinition, ProviderOutputIndex};
use crate::authorization::{ActivatedProviderOutputBinding, ProductAuthorizationSnapshot};
use crate::config::compiler::{
    AuthorizationProviderPlan, CompiledCaptureEvent, CompiledEgressRoute, CompiledHeaderEffectWhen,
    CompiledRuleDecision, CompiledTlsTrust, CredentialActionPlan, ForwardingPlan, HeaderEffectPlan,
    HttpBodyReadPlan, PolicyRulePlan, ProviderOutputPlan, ReloadableProductPlan, TransportTlsPlan,
};
use crate::credentials::ResolvedCredentialAction;
use crate::egress::{ActivatedTlsRoots, EgressSnapshot};
use crate::observation::{CaptureEpoch, CaptureEvent, ProductObservationSnapshot};
use crate::redaction::{ProfileHandle, RedactionSnapshot};
use crate::runtime::{
    CredentialSourceIndex, CredentialSourceRegistry, GenerationId, ProviderIndex, ProviderRegistry,
    RedactionProfileIndex, RedactionProfileRegistry, ResolvedBindings,
};

/// Snapshot-local immutable inputs needed by the standalone request adapter.
///
/// This is deliberately generation metadata, not another policy evaluator. The
/// existing product snapshot remains authoritative for matching and pass/resume.
pub(crate) struct UnboundStandaloneGenerationPlan {
    core: StandaloneGenerationCore,
    manifest: StandaloneBindingManifest,
}

pub(crate) struct StandaloneGenerationPlan {
    core: StandaloneGenerationCore,
    activated: StandaloneActivatedBindings,
}

pub(crate) struct StandaloneGenerationCore {
    identity: SnapshotIdentity,
    generation: PolicyGeneration,
    timeouts: StageTimeouts,
    ordinary_request_body: RequestBodyPolicy,
    normalized_request_body: RequestBodyPolicy,
    upgrade_request_body: RequestBodyPolicy,
    response: http_access_types::ResponsePolicy,
    route: Route,
    origin_https_tls: TlsIntent,
    capture: Option<StandaloneCaptureIntent>,
    sensitive_headers: Box<[HeaderName]>,
    rules: Box<[StandaloneRuleTemplate]>,
    default_provenance: DecisionProvenance,
    body_reads_by_cursor: Box<[StandaloneBodyReadPlan]>,
    global_request_headers: Option<HeaderMutationBatch>,
    global_credentials: Box<[CredentialMutation]>,
    provider_credentials: Box<[ProviderCredentialTemplates]>,
    resource_projections: StandaloneResourceProjections,
    resource_limits: RuntimeResourceLimits,
    snapshot_lease: SnapshotLease,
}

struct StandaloneBindingManifest {
    global_credentials: Box<[StandaloneCredentialBindingManifest]>,
    rules: Box<[StandaloneRuleBindingManifest]>,
    provider_outputs: Box<[StandaloneProviderOutputManifest]>,
    redactions: Box<[StandaloneRedactionBindingManifest]>,
    capture_redaction: Option<String>,
    tls: Box<[StandaloneTlsBindingManifest]>,
    resources: StandaloneResourceProof,
}

struct StandaloneCredentialBindingManifest {
    source: String,
    reference: CredentialRef,
}

struct StandaloneRedactionBindingManifest {
    profile: String,
    reference: RedactionRef,
}

struct StandaloneRuleBindingManifest {
    provider: Option<String>,
    redaction: Option<String>,
    credentials: Box<[StandaloneCredentialBindingManifest]>,
}

struct StandaloneProviderOutputManifest {
    provider: String,
    output: String,
    expected: StandaloneProviderOutputShape,
    reference: CredentialRef,
}

#[derive(Clone, PartialEq, Eq)]
enum StandaloneProviderOutputShape {
    Bearer {
        required: bool,
    },
    Basic {
        username: String,
        required: bool,
    },
    CustomHeader {
        header: http::HeaderName,
        required: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StandaloneTlsRole {
    Origin,
    Parent,
}

struct StandaloneTlsBindingManifest {
    role: StandaloneTlsRole,
    trust: CompiledTlsTrust,
    reference: TlsRootsRef,
}

pub(crate) struct StandaloneActivatedBindings {
    global_credentials: Box<[BoundCredentialSource]>,
    rule_credentials: Box<[Box<[BoundCredentialSource]>]>,
    rule_providers: Box<[Option<ProviderIndex>]>,
    rule_redactions: Box<[Option<BoundRedaction>]>,
    provider_outputs: Box<[BoundProviderOutput]>,
    redactions: Box<[BoundRedaction]>,
    capture_epoch: Option<std::sync::Arc<CaptureEpoch>>,
    tls_roots: Box<[BoundTlsRoots]>,
    resources: StandaloneResourceProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StandaloneResourceProof {
    cursors: Box<[StandaloneCursorResourceProof]>,
    max_reachable_combined_peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StandaloneCursorResourceProof {
    product_incremental_peak_bytes: usize,
    runtime_replay_capacity_bytes: usize,
    combined_peak_bytes: usize,
}

pub(crate) struct BoundCredentialSource {
    reference: CredentialRef,
    source: CredentialSourceIndex,
}

pub(crate) struct BoundProviderOutput {
    reference: CredentialRef,
    provider: ProviderIndex,
    output: ProviderOutputIndex,
}

pub(crate) struct BoundRedaction {
    reference: RedactionRef,
    profile: RedactionProfileIndex,
    handle: ProfileHandle,
}

pub(crate) struct BoundTlsRoots {
    reference: TlsRootsRef,
    role: StandaloneTlsRole,
    roots: ActivatedTlsRoots,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StandaloneBodyReadPlan {
    Disabled,
    Mandatory {
        max_encoded_bytes: usize,
        max_decoded_bytes: usize,
    },
}

pub(crate) struct StandaloneRuleTemplate {
    id: StableId,
    ordinal: u32,
    decision: StandaloneRuleDecision,
    request_timeout: Option<Duration>,
    allow_upgrades: bool,
    request_headers: Option<HeaderMutationBatch>,
    response_headers: Option<HeaderMutationBatch>,
    credentials: Box<[CredentialMutation]>,
    redaction: Option<RedactionRef>,
    local_provenance: DecisionProvenance,
    provider_provenance: Option<DecisionProvenance>,
}

pub(crate) struct ProviderCredentialTemplates {
    ordinal: usize,
    outputs: Box<[ProviderCredentialTemplate]>,
}

pub(crate) struct ProviderCredentialTemplate {
    ordinal: usize,
    required: bool,
    mutation: CredentialMutation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StandaloneRuleDecision {
    Allow,
    Deny,
    Delegate,
}

pub(crate) struct StandaloneCaptureIntent {
    intent: CaptureIntent,
    redaction: RedactionRef,
    events: Box<[StandaloneCaptureEvent]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StandaloneCaptureEvent {
    RequestAllowed,
    ResponseAllowed,
    RequestDenied,
    ResponseDenied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StandaloneResourceProjections {
    request_peak_bytes: u64,
    response_peak_bytes: u64,
    capture_peak_bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StandaloneCompileError {
    #[error("invalid published generation")]
    Generation,
    #[error("invalid checked standalone {0}")]
    Checked(&'static str),
    #[error("inconsistent standalone {0}")]
    Inconsistent(&'static str),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum StandaloneBindError {
    #[error("standalone activation is missing {0}")]
    Missing(&'static str),
    #[error("standalone activation has inconsistent {0}")]
    Inconsistent(&'static str),
}

impl UnboundStandaloneGenerationPlan {
    pub(crate) fn compile(
        plan: &ReloadableProductPlan,
        id: GenerationId,
    ) -> Result<Self, StandaloneCompileError> {
        let generation =
            PolicyGeneration::new(id.get()).map_err(|_| StandaloneCompileError::Generation)?;
        let identity = SnapshotIdentity::new();
        let version = generation.get();

        let timeouts = compile_timeouts(&plan.forwarding)?;
        let (ordinary_request_body, normalized_request_body, upgrade_request_body, response) =
            compile_body_policies(&plan.forwarding, plan.max_content_decoding_expansion_ratio)?;

        let mut tls_roots = Vec::new();
        let origin_https_tls = compile_tls_intent(
            &plan.egress.origin_tls,
            "egress.origin_tls",
            &identity,
            version,
            &mut tls_roots,
        )?;
        let route = compile_route(plan, &identity, version, &mut tls_roots)?;

        let redactions = plan
            .redaction
            .profiles
            .keys()
            .map(|name| {
                Ok((
                    name.clone(),
                    RedactionRef::new(identity.clone(), stable_id(name)?, version)
                        .map_err(|_| StandaloneCompileError::Checked("redaction reference"))?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, StandaloneCompileError>>()?;

        let capture = compile_capture(plan, &identity, version, &redactions)?;
        let sensitive_headers = compile_sensitive_headers(plan)?;
        let global_request_headers = compile_header_batch(&plan.egress.request_headers)?;

        let mut credential_refs = Vec::new();
        let global_credentials = plan
            .egress
            .credential_actions
            .iter()
            .enumerate()
            .map(|(index, action)| {
                compile_credential(
                    action,
                    credential_ref(&identity, version, &format!("global/credential/{index}"))?,
                    &mut credential_refs,
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();

        let mut rules = Vec::with_capacity(plan.policy.rules.len());
        for (ordinal, rule) in plan.policy.rules.iter().enumerate() {
            rules.push(compile_rule_template(
                rule,
                ordinal,
                generation,
                &identity,
                version,
                &redactions,
                &mut credential_refs,
            )?);
        }

        let provider_credentials =
            compile_provider_credentials(plan, &identity, version, &mut credential_refs)?;
        let body_reads_by_cursor = compile_body_reads(plan)?;
        let default_provenance = DecisionProvenance::new(
            generation,
            EffectivePolicy::Default,
            DecisionReason::new(DecisionReasonCategory::Policy, 0),
            None,
        );

        let resource_projections = compile_resource_projections(
            ordinary_request_body,
            normalized_request_body,
            upgrade_request_body,
            response,
            capture.as_ref(),
        );
        let resource_limits = RuntimeResourceLimits::new(
            resource_projections.request_peak_bytes,
            resource_projections.response_peak_bytes,
            resource_projections.capture_peak_bytes,
        )
        .map_err(|_| StandaloneCompileError::Checked("resource limits"))?;

        let redaction_refs = redactions.values().cloned().collect::<Vec<_>>();
        let capture_refs = capture
            .iter()
            .map(|capture| capture.intent.reference().clone())
            .collect::<Vec<_>>();
        let registries = SnapshotRegistries::new(
            &identity,
            &credential_refs,
            &redaction_refs,
            &capture_refs,
            &tls_roots,
        )
        .map_err(|_| StandaloneCompileError::Checked("snapshot registries"))?;
        let snapshot_lease = SnapshotLease::new(
            identity.clone(),
            generation,
            sensitive_headers.to_vec(),
            registries,
            resource_limits,
            Vec::new(),
            Vec::new(),
        )
        .map_err(|_| StandaloneCompileError::Checked("snapshot lease"))?;

        let core = StandaloneGenerationCore {
            identity,
            generation,
            timeouts,
            ordinary_request_body,
            normalized_request_body,
            upgrade_request_body,
            response,
            route,
            origin_https_tls,
            capture,
            sensitive_headers,
            rules: rules.into_boxed_slice(),
            default_provenance,
            body_reads_by_cursor,
            global_request_headers,
            global_credentials,
            provider_credentials,
            resource_projections,
            resource_limits,
            snapshot_lease,
        };
        let manifest = compile_binding_manifest(plan, &core, &redactions)?;
        Ok(Self { core, manifest })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bind(
        self,
        credentials: &CredentialSourceRegistry,
        redaction_snapshot: &RedactionSnapshot,
        redactions: &RedactionProfileRegistry,
        authorization: &ProductAuthorizationSnapshot,
        providers: &ProviderRegistry,
        egress: &EgressSnapshot,
        observation: &ProductObservationSnapshot,
        policy_bindings: &ResolvedBindings,
    ) -> Result<StandaloneGenerationPlan, StandaloneBindError> {
        let activated = bind_activated(
            &self.core,
            &self.manifest,
            credentials,
            redaction_snapshot,
            redactions,
            authorization,
            providers,
            egress,
            observation,
            policy_bindings,
        )?;
        Ok(StandaloneGenerationPlan {
            core: self.core,
            activated,
        })
    }

    #[cfg(test)]
    pub(crate) fn invalidate_first_provider_output_for_test(&mut self) {
        self.manifest
            .provider_outputs
            .first_mut()
            .expect("test plan has a provider output")
            .output = "missing-output".to_owned();
    }

    #[cfg(test)]
    pub(crate) fn into_bound_for_runtime_test(self) -> StandaloneGenerationPlan {
        StandaloneGenerationPlan {
            activated: StandaloneActivatedBindings {
                global_credentials: Box::new([]),
                rule_credentials: Box::new([]),
                rule_providers: Box::new([]),
                rule_redactions: Box::new([]),
                provider_outputs: Box::new([]),
                redactions: Box::new([]),
                capture_epoch: None,
                tls_roots: Box::new([]),
                resources: self.manifest.resources.clone(),
            },
            core: self.core,
        }
    }
}

impl StandaloneGenerationCore {
    pub(crate) fn identity(&self) -> &SnapshotIdentity {
        &self.identity
    }

    pub(crate) fn generation(&self) -> PolicyGeneration {
        self.generation
    }

    pub(crate) fn timeouts(&self) -> StageTimeouts {
        self.timeouts
    }

    pub(crate) fn ordinary_request_body(&self) -> RequestBodyPolicy {
        self.ordinary_request_body
    }

    pub(crate) fn normalized_request_body(&self) -> RequestBodyPolicy {
        self.normalized_request_body
    }

    pub(crate) fn upgrade_request_body(&self) -> RequestBodyPolicy {
        self.upgrade_request_body
    }

    pub(crate) fn response(&self) -> http_access_types::ResponsePolicy {
        self.response
    }

    pub(crate) fn route(&self) -> &Route {
        &self.route
    }

    pub(crate) fn origin_tls(&self, scheme: HttpScheme) -> TlsIntent {
        match scheme {
            HttpScheme::Http => TlsIntent::Disabled,
            HttpScheme::Https => self.origin_https_tls.clone(),
        }
    }

    pub(crate) fn capture(&self) -> Option<&StandaloneCaptureIntent> {
        self.capture.as_ref()
    }

    pub(crate) fn sensitive_headers(&self) -> &[HeaderName] {
        &self.sensitive_headers
    }

    pub(crate) fn rules(&self) -> &[StandaloneRuleTemplate] {
        &self.rules
    }

    pub(crate) fn default_provenance(&self) -> &DecisionProvenance {
        &self.default_provenance
    }

    pub(crate) fn body_reads_by_cursor(&self) -> &[StandaloneBodyReadPlan] {
        &self.body_reads_by_cursor
    }

    pub(crate) fn global_request_headers(&self) -> Option<&HeaderMutationBatch> {
        self.global_request_headers.as_ref()
    }

    pub(crate) fn global_credentials(&self) -> &[CredentialMutation] {
        &self.global_credentials
    }

    pub(crate) fn provider_credentials(&self) -> &[ProviderCredentialTemplates] {
        &self.provider_credentials
    }

    pub(crate) fn resource_projections(&self) -> StandaloneResourceProjections {
        self.resource_projections
    }

    pub(crate) fn resource_limits(&self) -> RuntimeResourceLimits {
        self.resource_limits
    }

    pub(crate) fn snapshot_lease(&self) -> &SnapshotLease {
        &self.snapshot_lease
    }
}

impl std::ops::Deref for UnboundStandaloneGenerationPlan {
    type Target = StandaloneGenerationCore;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl std::ops::Deref for StandaloneGenerationPlan {
    type Target = StandaloneGenerationCore;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl StandaloneGenerationPlan {
    pub(crate) fn activated(&self) -> &StandaloneActivatedBindings {
        &self.activated
    }
}

impl StandaloneActivatedBindings {
    pub(crate) fn global_credentials(&self) -> &[BoundCredentialSource] {
        &self.global_credentials
    }

    pub(crate) fn rule_credentials(&self, ordinal: usize) -> Option<&[BoundCredentialSource]> {
        self.rule_credentials.get(ordinal).map(AsRef::as_ref)
    }

    pub(crate) fn rule_provider(&self, ordinal: usize) -> Option<ProviderIndex> {
        self.rule_providers.get(ordinal).copied().flatten()
    }

    pub(crate) fn rule_redaction(&self, ordinal: usize) -> Option<&BoundRedaction> {
        self.rule_redactions.get(ordinal).and_then(Option::as_ref)
    }

    pub(crate) fn provider_outputs(&self) -> &[BoundProviderOutput] {
        &self.provider_outputs
    }

    pub(crate) fn redactions(&self) -> &[BoundRedaction] {
        &self.redactions
    }

    pub(crate) fn capture_epoch(&self) -> Option<&std::sync::Arc<CaptureEpoch>> {
        self.capture_epoch.as_ref()
    }

    pub(crate) fn tls_roots(&self) -> &[BoundTlsRoots] {
        &self.tls_roots
    }

    pub(crate) fn resources(&self) -> &StandaloneResourceProof {
        &self.resources
    }
}

impl StandaloneResourceProof {
    pub(crate) fn cursors(&self) -> &[StandaloneCursorResourceProof] {
        &self.cursors
    }

    pub(crate) fn max_reachable_combined_peak_bytes(&self) -> usize {
        self.max_reachable_combined_peak_bytes
    }

    fn is_valid(&self) -> bool {
        self.cursors.iter().all(|record| {
            record
                .product_incremental_peak_bytes
                .checked_add(record.runtime_replay_capacity_bytes)
                == Some(record.combined_peak_bytes)
        }) && self
            .cursors
            .iter()
            .map(|record| record.combined_peak_bytes)
            .max()
            .unwrap_or(0)
            == self.max_reachable_combined_peak_bytes
    }
}

impl StandaloneCursorResourceProof {
    pub(crate) fn product_incremental_peak_bytes(self) -> usize {
        self.product_incremental_peak_bytes
    }

    pub(crate) fn runtime_replay_capacity_bytes(self) -> usize {
        self.runtime_replay_capacity_bytes
    }

    pub(crate) fn combined_peak_bytes(self) -> usize {
        self.combined_peak_bytes
    }
}

impl BoundCredentialSource {
    pub(crate) fn reference(&self) -> &CredentialRef {
        &self.reference
    }

    pub(crate) fn source(&self) -> CredentialSourceIndex {
        self.source
    }
}

impl BoundProviderOutput {
    pub(crate) fn reference(&self) -> &CredentialRef {
        &self.reference
    }

    pub(crate) fn provider(&self) -> ProviderIndex {
        self.provider
    }

    pub(crate) fn output(&self) -> ProviderOutputIndex {
        self.output
    }
}

impl BoundRedaction {
    pub(crate) fn reference(&self) -> &RedactionRef {
        &self.reference
    }

    pub(crate) fn profile(&self) -> RedactionProfileIndex {
        self.profile
    }

    pub(crate) fn handle(&self) -> &ProfileHandle {
        &self.handle
    }
}

impl BoundTlsRoots {
    pub(crate) fn reference(&self) -> &TlsRootsRef {
        &self.reference
    }

    pub(crate) fn roots(&self) -> &ActivatedTlsRoots {
        &self.roots
    }
}

fn compile_binding_manifest(
    plan: &ReloadableProductPlan,
    core: &StandaloneGenerationCore,
    redaction_refs: &BTreeMap<String, RedactionRef>,
) -> Result<StandaloneBindingManifest, StandaloneCompileError> {
    if plan.egress.credential_actions.len() != core.global_credentials.len()
        || plan.policy.rules.len() != core.rules.len()
        || plan.redaction.profiles.len() != redaction_refs.len()
    {
        return Err(StandaloneCompileError::Inconsistent(
            "standalone binding manifest shape",
        ));
    }
    if plan
        .policy
        .rules
        .iter()
        .zip(core.rules.iter())
        .any(|(rule, core_rule)| rule.credential_actions.len() != core_rule.credentials.len())
    {
        return Err(StandaloneCompileError::Inconsistent(
            "standalone rule credential manifest shape",
        ));
    }
    let global_credentials = plan
        .egress
        .credential_actions
        .iter()
        .zip(core.global_credentials.iter())
        .map(|(action, mutation)| StandaloneCredentialBindingManifest {
            source: credential_source_name(action).to_owned(),
            reference: mutation.credential().clone(),
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let rules = plan
        .policy
        .rules
        .iter()
        .enumerate()
        .map(|(ordinal, rule)| StandaloneRuleBindingManifest {
            provider: rule.authorization_provider.clone(),
            redaction: rule.redaction_profile.clone(),
            credentials: rule
                .credential_actions
                .iter()
                .zip(core.rules[ordinal].credentials.iter())
                .map(|(action, mutation)| StandaloneCredentialBindingManifest {
                    source: credential_source_name(action).to_owned(),
                    reference: mutation.credential().clone(),
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let neutral_provider_outputs = core
        .provider_credentials
        .iter()
        .flat_map(|provider| provider.outputs.iter())
        .map(|output| output.mutation.credential().clone())
        .collect::<Vec<_>>();
    let provider_output_count = plan
        .authorization
        .providers
        .values()
        .map(|provider| match provider {
            AuthorizationProviderPlan::Webhook(provider) => provider.outputs.len(),
            AuthorizationProviderPlan::Process(provider) => provider.outputs.len(),
        })
        .sum::<usize>();
    if provider_output_count != neutral_provider_outputs.len() {
        return Err(StandaloneCompileError::Inconsistent(
            "standalone provider output manifest shape",
        ));
    }
    let provider_outputs = plan
        .authorization
        .providers
        .iter()
        .flat_map(|(provider_name, provider)| {
            let outputs = match provider {
                AuthorizationProviderPlan::Webhook(provider) => &provider.outputs,
                AuthorizationProviderPlan::Process(provider) => &provider.outputs,
            };
            outputs.iter().map(move |(output_name, output)| {
                (
                    provider_name.clone(),
                    output_name.clone(),
                    StandaloneProviderOutputShape::from_plan(output),
                )
            })
        })
        .zip(neutral_provider_outputs)
        .map(
            |((provider, output, expected), reference)| StandaloneProviderOutputManifest {
                provider,
                output,
                expected,
                reference,
            },
        )
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let redactions = plan
        .redaction
        .profiles
        .keys()
        .map(|profile| {
            Ok(StandaloneRedactionBindingManifest {
                profile: profile.clone(),
                reference: redaction_refs.get(profile).cloned().ok_or(
                    StandaloneCompileError::Inconsistent("redaction binding manifest"),
                )?,
            })
        })
        .collect::<Result<Vec<_>, StandaloneCompileError>>()?
        .into_boxed_slice();
    let mut tls = Vec::new();
    if custom_trust(plan.egress.origin_tls.trust) {
        let TlsIntent::CustomRoots(reference) = &core.origin_https_tls else {
            return Err(StandaloneCompileError::Inconsistent(
                "origin TLS binding manifest",
            ));
        };
        tls.push(StandaloneTlsBindingManifest {
            role: StandaloneTlsRole::Origin,
            trust: plan.egress.origin_tls.trust,
            reference: reference.clone(),
        });
    }
    if let Some(parent) = plan.egress.parent_proxy.as_ref() {
        if let Some(parent_tls) = parent.tls.as_ref() {
            if custom_trust(parent_tls.trust) {
                let Route::Parent {
                    tls: TlsIntent::CustomRoots(reference),
                    ..
                } = &core.route
                else {
                    return Err(StandaloneCompileError::Inconsistent(
                        "parent TLS binding manifest",
                    ));
                };
                tls.push(StandaloneTlsBindingManifest {
                    role: StandaloneTlsRole::Parent,
                    trust: parent_tls.trust,
                    reference: reference.clone(),
                });
            }
        }
    }
    Ok(StandaloneBindingManifest {
        global_credentials,
        rules,
        provider_outputs,
        redactions,
        capture_redaction: plan
            .observation
            .capture
            .as_ref()
            .map(|capture| capture.redaction_profile.clone()),
        tls: tls.into_boxed_slice(),
        resources: compile_resource_proof(plan)?,
    })
}

fn compile_resource_proof(
    plan: &ReloadableProductPlan,
) -> Result<StandaloneResourceProof, StandaloneCompileError> {
    if plan.resource_plan.http_body_resources_by_cursor.len() != plan.policy.rules.len() + 1 {
        return Err(StandaloneCompileError::Inconsistent(
            "standalone resource cursor count",
        ));
    }
    let cursors = plan
        .resource_plan
        .http_body_resources_by_cursor
        .iter()
        .map(|record| {
            if record
                .product_incremental_peak_bytes
                .checked_add(record.runtime_replay_capacity_bytes)
                != Some(record.combined_peak_bytes)
            {
                return Err(StandaloneCompileError::Inconsistent(
                    "standalone resource cursor sum",
                ));
            }
            Ok(StandaloneCursorResourceProof {
                product_incremental_peak_bytes: record.product_incremental_peak_bytes,
                runtime_replay_capacity_bytes: record.runtime_replay_capacity_bytes,
                combined_peak_bytes: record.combined_peak_bytes,
            })
        })
        .collect::<Result<Vec<_>, StandaloneCompileError>>()?;
    let maximum = cursors
        .iter()
        .map(|record| record.combined_peak_bytes)
        .max()
        .unwrap_or(0);
    if maximum
        != plan
            .resource_plan
            .max_reachable_http_body_combined_peak_bytes
    {
        return Err(StandaloneCompileError::Inconsistent(
            "standalone resource maximum",
        ));
    }
    Ok(StandaloneResourceProof {
        cursors: cursors.into_boxed_slice(),
        max_reachable_combined_peak_bytes: maximum,
    })
}

fn credential_source_name(action: &CredentialActionPlan) -> &str {
    match action {
        CredentialActionPlan::Bearer { credential }
        | CredentialActionPlan::CustomHeader { credential, .. } => credential,
        CredentialActionPlan::Basic {
            password_credential,
            ..
        } => password_credential,
    }
}

impl StandaloneProviderOutputShape {
    fn from_plan(plan: &ProviderOutputPlan) -> Self {
        match plan {
            ProviderOutputPlan::Bearer { required } => Self::Bearer {
                required: *required,
            },
            ProviderOutputPlan::Basic { username, required } => Self::Basic {
                username: username.clone(),
                required: *required,
            },
            ProviderOutputPlan::CustomHeader { header, required } => Self::CustomHeader {
                header: header.clone(),
                required: *required,
            },
        }
    }

    fn matches(&self, definition: &ProviderOutputDefinition) -> bool {
        match (self, definition) {
            (
                Self::Bearer { required: left },
                ProviderOutputDefinition::Bearer { required: right },
            ) => left == right,
            (
                Self::Basic {
                    username: left_username,
                    required: left_required,
                },
                ProviderOutputDefinition::Basic {
                    username: right_username,
                    required: right_required,
                },
            ) => left_username == right_username && left_required == right_required,
            (
                Self::CustomHeader {
                    header: left_header,
                    required: left_required,
                },
                ProviderOutputDefinition::CustomHeader {
                    header: right_header,
                    required: right_required,
                },
            ) => left_header == right_header && left_required == right_required,
            _ => false,
        }
    }
}

const fn custom_trust(trust: CompiledTlsTrust) -> bool {
    matches!(
        trust,
        CompiledTlsTrust::Custom | CompiledTlsTrust::SystemPlusCustom
    )
}

#[allow(clippy::too_many_arguments)]
fn bind_activated(
    core: &StandaloneGenerationCore,
    manifest: &StandaloneBindingManifest,
    credentials: &CredentialSourceRegistry,
    redaction_snapshot: &RedactionSnapshot,
    redactions: &RedactionProfileRegistry,
    authorization: &ProductAuthorizationSnapshot,
    providers: &ProviderRegistry,
    egress: &EgressSnapshot,
    observation: &ProductObservationSnapshot,
    policy_bindings: &ResolvedBindings,
) -> Result<StandaloneActivatedBindings, StandaloneBindError> {
    if !manifest.resources.is_valid() {
        return Err(StandaloneBindError::Inconsistent(
            "standalone resource proof",
        ));
    }
    if policy_bindings.rules.len() != manifest.rules.len()
        || core.rules.len() != manifest.rules.len()
        || policy_bindings.provider_count != providers.len()
        || policy_bindings.redaction_profile_count != redactions.len()
        || policy_bindings.credential_count != credentials.len()
    {
        return Err(StandaloneBindError::Inconsistent("policy registry shape"));
    }

    if manifest.global_credentials.len() != core.global_credentials.len()
        || manifest.global_credentials.len() != egress.credential_actions().len()
    {
        return Err(StandaloneBindError::Inconsistent("global credential shape"));
    }
    let global_credentials = manifest
        .global_credentials
        .iter()
        .zip(core.global_credentials.iter())
        .zip(egress.credential_actions().iter())
        .map(|((binding, mutation), activated)| {
            let bound = bind_credential_source(binding, credentials, "credential source")?;
            if mutation.credential() != &binding.reference
                || !credential_action_matches(mutation, bound.source, activated)
            {
                return Err(StandaloneBindError::Inconsistent(
                    "global credential binding",
                ));
            }
            Ok(bound)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_boxed_slice();

    let mut rule_credentials = Vec::with_capacity(manifest.rules.len());
    let mut rule_providers = Vec::with_capacity(manifest.rules.len());
    let mut rule_redactions = Vec::with_capacity(manifest.rules.len());
    for (ordinal, ((binding, core_rule), policy_rule)) in manifest
        .rules
        .iter()
        .zip(core.rules.iter())
        .zip(policy_bindings.rules.iter())
        .enumerate()
    {
        if binding.credentials.len() != core_rule.credentials.len()
            || binding.credentials.len() != policy_rule.credentials.len()
        {
            return Err(StandaloneBindError::Inconsistent("rule credential shape"));
        }
        let credentials_for_rule = binding
            .credentials
            .iter()
            .zip(core_rule.credentials.iter())
            .zip(policy_rule.credentials.iter())
            .map(|((binding, mutation), activated)| {
                let bound = bind_credential_source(binding, credentials, "rule credential source")?;
                if mutation.credential() != &binding.reference || bound.source != *activated {
                    return Err(StandaloneBindError::Inconsistent("rule credential binding"));
                }
                Ok(bound)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();
        rule_credentials.push(credentials_for_rule);

        let provider = binding
            .provider
            .as_deref()
            .map(|name| {
                providers
                    .get(name)
                    .ok_or(StandaloneBindError::Missing("rule provider"))
            })
            .transpose()?;
        if provider != policy_rule.authorization_provider
            || (core_rule.decision == StandaloneRuleDecision::Delegate) != provider.is_some()
        {
            return Err(StandaloneBindError::Inconsistent("rule provider binding"));
        }
        rule_providers.push(provider);

        let redaction = binding
            .redaction
            .as_deref()
            .map(|name| {
                bind_redaction(
                    name,
                    core_rule.redaction.as_ref(),
                    redaction_snapshot,
                    redactions,
                )
            })
            .transpose()?;
        if redaction.as_ref().map(BoundRedaction::profile) != policy_rule.redaction_profile {
            return Err(StandaloneBindError::Inconsistent("rule redaction binding"));
        }
        rule_redactions.push(redaction);

        if usize::try_from(core_rule.ordinal).ok() != Some(ordinal) {
            return Err(StandaloneBindError::Inconsistent("rule ordinal"));
        }
    }

    let provider_outputs = manifest
        .provider_outputs
        .iter()
        .map(|binding| {
            let activated = authorization
                .provider_output_binding(providers, &binding.provider, &binding.output)
                .ok_or(StandaloneBindError::Missing("provider output"))?;
            bind_provider_output(binding, &activated)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_boxed_slice();

    let redaction_bindings = manifest
        .redactions
        .iter()
        .map(|binding| {
            let profile = redactions
                .get(&binding.profile)
                .ok_or(StandaloneBindError::Missing("redaction profile"))?;
            let handle = redaction_snapshot
                .profile(profile)
                .ok_or(StandaloneBindError::Missing("redaction profile handle"))?;
            Ok(BoundRedaction {
                reference: binding.reference.clone(),
                profile,
                handle,
            })
        })
        .collect::<Result<Vec<_>, StandaloneBindError>>()?
        .into_boxed_slice();

    let capture_epoch = bind_capture(core, manifest, redaction_snapshot, redactions, observation)?;

    let tls_roots = manifest
        .tls
        .iter()
        .map(|binding| bind_tls_roots(binding, egress))
        .collect::<Result<Vec<_>, _>>()?
        .into_boxed_slice();
    if egress.origin_custom_roots().is_some()
        != manifest
            .tls
            .iter()
            .any(|binding| binding.role == StandaloneTlsRole::Origin)
        || egress.parent_custom_roots().is_some()
            != manifest
                .tls
                .iter()
                .any(|binding| binding.role == StandaloneTlsRole::Parent)
    {
        return Err(StandaloneBindError::Inconsistent("TLS roots shape"));
    }

    Ok(StandaloneActivatedBindings {
        global_credentials,
        rule_credentials: rule_credentials.into_boxed_slice(),
        rule_providers: rule_providers.into_boxed_slice(),
        rule_redactions: rule_redactions.into_boxed_slice(),
        provider_outputs,
        redactions: redaction_bindings,
        capture_epoch,
        tls_roots,
        resources: manifest.resources.clone(),
    })
}

fn bind_credential_source(
    binding: &StandaloneCredentialBindingManifest,
    credentials: &CredentialSourceRegistry,
    missing: &'static str,
) -> Result<BoundCredentialSource, StandaloneBindError> {
    let source = credentials
        .get(&binding.source)
        .ok_or(StandaloneBindError::Missing(missing))?;
    Ok(BoundCredentialSource {
        reference: binding.reference.clone(),
        source,
    })
}

fn bind_tls_roots(
    binding: &StandaloneTlsBindingManifest,
    egress: &EgressSnapshot,
) -> Result<BoundTlsRoots, StandaloneBindError> {
    let roots = match binding.role {
        StandaloneTlsRole::Origin => egress.origin_custom_roots(),
        StandaloneTlsRole::Parent => egress.parent_custom_roots(),
    }
    .ok_or(StandaloneBindError::Missing("TLS roots"))?;
    if roots.trust() != binding.trust {
        return Err(StandaloneBindError::Inconsistent("TLS roots role"));
    }
    Ok(BoundTlsRoots {
        reference: binding.reference.clone(),
        role: binding.role,
        roots,
    })
}

fn bind_provider_output(
    manifest: &StandaloneProviderOutputManifest,
    activated: &ActivatedProviderOutputBinding<'_>,
) -> Result<BoundProviderOutput, StandaloneBindError> {
    if !manifest.expected.matches(activated.definition()) {
        return Err(StandaloneBindError::Inconsistent("provider output shape"));
    }
    Ok(BoundProviderOutput {
        reference: manifest.reference.clone(),
        provider: activated.provider(),
        output: activated.output(),
    })
}

fn bind_redaction(
    name: &str,
    reference: Option<&RedactionRef>,
    redaction_snapshot: &RedactionSnapshot,
    redactions: &RedactionProfileRegistry,
) -> Result<BoundRedaction, StandaloneBindError> {
    let reference = reference
        .cloned()
        .ok_or(StandaloneBindError::Inconsistent("redaction reference"))?;
    let profile = redactions
        .get(name)
        .ok_or(StandaloneBindError::Missing("redaction profile"))?;
    let handle = redaction_snapshot
        .profile(profile)
        .ok_or(StandaloneBindError::Missing("redaction profile handle"))?;
    Ok(BoundRedaction {
        reference,
        profile,
        handle,
    })
}

fn bind_capture(
    core: &StandaloneGenerationCore,
    manifest: &StandaloneBindingManifest,
    redaction_snapshot: &RedactionSnapshot,
    redactions: &RedactionProfileRegistry,
    observation: &ProductObservationSnapshot,
) -> Result<Option<std::sync::Arc<CaptureEpoch>>, StandaloneBindError> {
    match (
        core.capture.as_ref(),
        manifest.capture_redaction.as_deref(),
        observation.capture_epoch().capture(),
    ) {
        (None, None, None) => Ok(None),
        (Some(neutral), Some(profile_name), Some(activated)) => {
            let profile_index = redactions
                .get(profile_name)
                .ok_or(StandaloneBindError::Missing("capture redaction profile"))?;
            let profile =
                redaction_snapshot
                    .profile(profile_index)
                    .ok_or(StandaloneBindError::Missing(
                        "capture redaction profile handle",
                    ))?;
            if !profile.same_profile(activated.profile())
                || !capture_events_match(neutral.events(), activated)
            {
                return Err(StandaloneBindError::Inconsistent("capture binding"));
            }
            Ok(Some(observation.capture_epoch().clone()))
        }
        _ => Err(StandaloneBindError::Inconsistent("capture shape")),
    }
}

fn capture_events_match(
    neutral: &[StandaloneCaptureEvent],
    activated: &crate::observation::CapturePolicy,
) -> bool {
    const EVENTS: [(StandaloneCaptureEvent, CaptureEvent); 4] = [
        (
            StandaloneCaptureEvent::RequestAllowed,
            CaptureEvent::RequestAllowed,
        ),
        (
            StandaloneCaptureEvent::ResponseAllowed,
            CaptureEvent::ResponseAllowed,
        ),
        (
            StandaloneCaptureEvent::RequestDenied,
            CaptureEvent::RequestDenied,
        ),
        (
            StandaloneCaptureEvent::ResponseDenied,
            CaptureEvent::ResponseDenied,
        ),
    ];
    EVENTS.into_iter().all(|(neutral_event, product_event)| {
        neutral.contains(&neutral_event) == activated.captures(product_event)
    })
}

fn credential_action_matches(
    mutation: &CredentialMutation,
    source: CredentialSourceIndex,
    activated: &ResolvedCredentialAction,
) -> bool {
    match (mutation.kind(), activated) {
        (
            CredentialMutationKind::Bearer(_),
            ResolvedCredentialAction::Bearer { source: actual },
        ) => source == *actual,
        (
            CredentialMutationKind::Basic { username, .. },
            ResolvedCredentialAction::Basic {
                username: actual_username,
                source: actual,
            },
        ) => source == *actual && username == actual_username,
        (
            CredentialMutationKind::CustomHeader { name, .. },
            ResolvedCredentialAction::CustomHeader {
                header,
                source: actual,
            },
        ) => source == *actual && name.as_str() == header.as_str(),
        _ => false,
    }
}

impl StandaloneRuleTemplate {
    pub(crate) fn id(&self) -> &StableId {
        &self.id
    }

    pub(crate) fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub(crate) fn decision(&self) -> StandaloneRuleDecision {
        self.decision
    }

    pub(crate) fn request_timeout(&self) -> Option<Duration> {
        self.request_timeout
    }

    pub(crate) fn allow_upgrades(&self) -> bool {
        self.allow_upgrades
    }

    pub(crate) fn request_headers(&self) -> Option<&HeaderMutationBatch> {
        self.request_headers.as_ref()
    }

    pub(crate) fn response_headers(&self) -> Option<&HeaderMutationBatch> {
        self.response_headers.as_ref()
    }

    pub(crate) fn credentials(&self) -> &[CredentialMutation] {
        &self.credentials
    }

    pub(crate) fn redaction(&self) -> Option<&RedactionRef> {
        self.redaction.as_ref()
    }

    pub(crate) fn local_provenance(&self) -> &DecisionProvenance {
        &self.local_provenance
    }

    pub(crate) fn provider_provenance(&self) -> Option<&DecisionProvenance> {
        self.provider_provenance.as_ref()
    }
}

impl ProviderCredentialTemplates {
    pub(crate) fn ordinal(&self) -> usize {
        self.ordinal
    }

    pub(crate) fn outputs(&self) -> &[ProviderCredentialTemplate] {
        &self.outputs
    }
}

impl ProviderCredentialTemplate {
    pub(crate) fn ordinal(&self) -> usize {
        self.ordinal
    }

    pub(crate) fn required(&self) -> bool {
        self.required
    }

    pub(crate) fn mutation(&self) -> &CredentialMutation {
        &self.mutation
    }
}

impl StandaloneCaptureIntent {
    pub(crate) fn intent(&self) -> &CaptureIntent {
        &self.intent
    }

    pub(crate) fn redaction(&self) -> &RedactionRef {
        &self.redaction
    }

    pub(crate) fn events(&self) -> &[StandaloneCaptureEvent] {
        &self.events
    }
}

impl StandaloneResourceProjections {
    pub(crate) fn request_peak_bytes(self) -> u64 {
        self.request_peak_bytes
    }

    pub(crate) fn response_peak_bytes(self) -> u64 {
        self.response_peak_bytes
    }

    pub(crate) fn capture_peak_bytes(self) -> u64 {
        self.capture_peak_bytes
    }
}

fn compile_timeouts(plan: &ForwardingPlan) -> Result<StageTimeouts, StandaloneCompileError> {
    StageTimeouts::new(
        duration_millis(plan.connect_timeout)?,
        duration_millis(plan.response_head_timeout)?,
        duration_millis(plan.body_idle_timeout)?,
        duration_millis(plan.upgrade_idle_timeout)?,
    )
    .map_err(|_| StandaloneCompileError::Checked("stage timeouts"))
}

fn duration_millis(value: Duration) -> Result<u64, StandaloneCompileError> {
    u64::try_from(value.as_millis())
        .map_err(|_| StandaloneCompileError::Checked("timeout conversion"))
}

fn compile_body_policies(
    forwarding: &ForwardingPlan,
    expansion_ratio: usize,
) -> Result<
    (
        RequestBodyPolicy,
        RequestBodyPolicy,
        RequestBodyPolicy,
        http_access_types::ResponsePolicy,
    ),
    StandaloneCompileError,
> {
    let ratio = u64::try_from(expansion_ratio)
        .map_err(|_| StandaloneCompileError::Checked("body expansion ratio"))?;
    let (request_trailer_count, request_trailer_bytes) = if forwarding.preserve_request_trailers {
        (forwarding.max_trailer_count, forwarding.max_trailer_bytes)
    } else {
        (0, 0)
    };
    let request_limits = body_limits(
        forwarding.max_request_wire_bytes,
        forwarding.max_request_decoded_bytes,
        ratio,
        forwarding.chunk_bytes,
        request_trailer_count,
        request_trailer_bytes,
    )?;
    let preserved_request_without_trailers = body_limits(
        forwarding.max_request_wire_bytes,
        forwarding.max_request_decoded_bytes,
        ratio,
        forwarding.chunk_bytes,
        0,
        0,
    )?;
    let canonical_request_limits = body_limits(
        forwarding.max_request_decoded_bytes,
        forwarding.max_request_decoded_bytes,
        ratio,
        forwarding.chunk_bytes,
        0,
        0,
    )?;
    let response_limits = body_limits(
        forwarding.max_response_wire_bytes,
        forwarding.max_response_decoded_bytes,
        ratio,
        forwarding.chunk_bytes,
        forwarding.max_trailer_count,
        forwarding.max_trailer_bytes,
    )?;
    let ordinary_request_body = RequestBodyPolicy::new(
        BodyRepresentation::PreservedContentCoded,
        request_limits,
        if forwarding.preserve_request_trailers {
            TrailerPolicy::Allow
        } else {
            TrailerPolicy::Deny
        },
    )
    .map_err(|_| StandaloneCompileError::Checked("ordinary request body policy"))?;
    let normalized_request_body = RequestBodyPolicy::new(
        BodyRepresentation::CanonicalIdentity,
        canonical_request_limits,
        TrailerPolicy::Deny,
    )
    .map_err(|_| StandaloneCompileError::Checked("normalized request body policy"))?;
    let upgrade_request_body = RequestBodyPolicy::new(
        BodyRepresentation::PreservedContentCoded,
        preserved_request_without_trailers,
        TrailerPolicy::Deny,
    )
    .map_err(|_| StandaloneCompileError::Checked("upgrade request body policy"))?;
    let response = http_access_types::ResponsePolicy::new(
        response_limits,
        duration_millis(forwarding.body_idle_timeout)?,
        RedirectPolicy::ReturnToCaller,
    )
    .map_err(|_| StandaloneCompileError::Checked("response policy"))?;
    Ok((
        ordinary_request_body,
        normalized_request_body,
        upgrade_request_body,
        response,
    ))
}

fn body_limits(
    wire_bytes: usize,
    decoded_bytes: usize,
    expansion_ratio: u64,
    chunk_bytes: usize,
    trailer_count: usize,
    trailer_bytes: usize,
) -> Result<BodyLimits, StandaloneCompileError> {
    BodyLimits::new(
        u64::try_from(wire_bytes)
            .map_err(|_| StandaloneCompileError::Checked("wire body limit"))?,
        u64::try_from(decoded_bytes)
            .map_err(|_| StandaloneCompileError::Checked("decoded body limit"))?,
        expansion_ratio,
        1,
        u64::try_from(chunk_bytes)
            .map_err(|_| StandaloneCompileError::Checked("body chunk limit"))?,
        u64::try_from(trailer_count)
            .map_err(|_| StandaloneCompileError::Checked("trailer count limit"))?,
        u64::try_from(trailer_bytes)
            .map_err(|_| StandaloneCompileError::Checked("trailer byte limit"))?,
    )
    .map_err(|_| StandaloneCompileError::Checked("body limits"))
}

fn compile_route(
    plan: &ReloadableProductPlan,
    identity: &SnapshotIdentity,
    version: u64,
    tls_roots: &mut Vec<TlsRootsRef>,
) -> Result<Route, StandaloneCompileError> {
    match (&plan.egress.route, &plan.egress.parent_proxy) {
        (CompiledEgressRoute::Direct, None) => Ok(Route::Direct),
        (CompiledEgressRoute::ParentProxy, Some(parent)) => {
            let target = canonicalize_http_url(&parent.url)
                .map_err(|_| StandaloneCompileError::Checked("parent route URL"))?;
            let tls = match (target.scheme(), parent.tls.as_ref()) {
                (HttpScheme::Http, None) => TlsIntent::Disabled,
                (HttpScheme::Https, Some(tls)) => compile_tls_intent_parts(
                    tls.trust,
                    "egress.parent_proxy.tls",
                    identity,
                    version,
                    tls_roots,
                )?,
                _ => return Err(StandaloneCompileError::Inconsistent("parent route")),
            };
            Ok(Route::Parent { target, tls })
        }
        _ => Err(StandaloneCompileError::Inconsistent("egress route")),
    }
}

fn compile_tls_intent(
    plan: &TransportTlsPlan,
    role: &'static str,
    identity: &SnapshotIdentity,
    version: u64,
    tls_roots: &mut Vec<TlsRootsRef>,
) -> Result<TlsIntent, StandaloneCompileError> {
    compile_tls_intent_parts(plan.trust, role, identity, version, tls_roots)
}

fn compile_tls_intent_parts(
    trust: CompiledTlsTrust,
    role: &'static str,
    identity: &SnapshotIdentity,
    version: u64,
    tls_roots: &mut Vec<TlsRootsRef>,
) -> Result<TlsIntent, StandaloneCompileError> {
    match trust {
        CompiledTlsTrust::System => Ok(TlsIntent::SystemRoots),
        CompiledTlsTrust::Insecure => Ok(TlsIntent::Insecure),
        CompiledTlsTrust::Custom | CompiledTlsTrust::SystemPlusCustom => {
            let suffix = match trust {
                CompiledTlsTrust::Custom => "custom",
                CompiledTlsTrust::SystemPlusCustom => "system-plus-custom",
                _ => unreachable!(),
            };
            let reference = TlsRootsRef::new(
                identity.clone(),
                stable_id(&format!("{role}/{suffix}"))?,
                version,
            )
            .map_err(|_| StandaloneCompileError::Checked("TLS roots reference"))?;
            tls_roots.push(reference.clone());
            Ok(TlsIntent::CustomRoots(reference))
        }
    }
}

fn compile_capture(
    plan: &ReloadableProductPlan,
    identity: &SnapshotIdentity,
    version: u64,
    redactions: &BTreeMap<String, RedactionRef>,
) -> Result<Option<StandaloneCaptureIntent>, StandaloneCompileError> {
    let Some(capture) = &plan.observation.capture else {
        return Ok(None);
    };
    let profile = plan
        .redaction
        .profiles
        .get(&capture.redaction_profile)
        .ok_or(StandaloneCompileError::Inconsistent(
            "capture redaction profile",
        ))?;
    let ratio = u64::try_from(plan.max_content_decoding_expansion_ratio)
        .map_err(|_| StandaloneCompileError::Checked("capture expansion ratio"))?;
    let chunk_bytes = plan
        .forwarding
        .chunk_bytes
        .min(profile.max_body_bytes.max(profile.max_decoded_body_bytes));
    let limits = body_limits(
        profile.max_body_bytes,
        profile.max_decoded_body_bytes,
        ratio,
        chunk_bytes,
        0,
        0,
    )?;
    let reference = CaptureRef::new(identity.clone(), stable_id("observation.capture")?, version)
        .map_err(|_| StandaloneCompileError::Checked("capture reference"))?;
    let intent = CaptureIntent::new(reference, limits)
        .map_err(|_| StandaloneCompileError::Checked("capture intent"))?;
    if intent.projection().simultaneous_peak_bytes()
        > u64::try_from(capture.max_inflight_body_bytes)
            .map_err(|_| StandaloneCompileError::Checked("capture pool limit"))?
    {
        return Err(StandaloneCompileError::Inconsistent(
            "capture resource projection",
        ));
    }
    let redaction = redactions.get(&capture.redaction_profile).cloned().ok_or(
        StandaloneCompileError::Inconsistent("capture redaction reference"),
    )?;
    let events = capture
        .events
        .iter()
        .map(|event| match event {
            CompiledCaptureEvent::RequestAllowed => StandaloneCaptureEvent::RequestAllowed,
            CompiledCaptureEvent::ResponseAllowed => StandaloneCaptureEvent::ResponseAllowed,
            CompiledCaptureEvent::RequestDenied => StandaloneCaptureEvent::RequestDenied,
            CompiledCaptureEvent::ResponseDenied => StandaloneCaptureEvent::ResponseDenied,
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    Ok(Some(StandaloneCaptureIntent {
        intent,
        redaction,
        events,
    }))
}

fn compile_sensitive_headers(
    plan: &ReloadableProductPlan,
) -> Result<Box<[HeaderName]>, StandaloneCompileError> {
    let mut headers = plan
        .credentials
        .inbound
        .values()
        .map(|inbound| neutral_header_name(&inbound.header))
        .chain(
            plan.authorization
                .internal_context_headers
                .iter()
                .map(neutral_header_name),
        )
        .collect::<Result<Vec<_>, _>>()?;
    headers.sort();
    if headers.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(StandaloneCompileError::Inconsistent(
            "standalone sensitive headers",
        ));
    }
    Ok(headers.into_boxed_slice())
}

#[allow(clippy::too_many_arguments)]
fn compile_rule_template(
    rule: &PolicyRulePlan,
    ordinal: usize,
    generation: PolicyGeneration,
    identity: &SnapshotIdentity,
    version: u64,
    redactions: &BTreeMap<String, RedactionRef>,
    credential_refs: &mut Vec<CredentialRef>,
) -> Result<StandaloneRuleTemplate, StandaloneCompileError> {
    let id = stable_id(&rule.id)?;
    let checked_ordinal =
        u32::try_from(ordinal).map_err(|_| StandaloneCompileError::Checked("rule ordinal"))?;
    let effective_policy = EffectivePolicy::Rule {
        id: id.clone(),
        ordinal: checked_ordinal,
    };
    let local_provenance = DecisionProvenance::new(
        generation,
        effective_policy.clone(),
        DecisionReason::new(DecisionReasonCategory::Policy, 0),
        None,
    );
    let provider_provenance = matches!(rule.decision, CompiledRuleDecision::Delegate).then(|| {
        DecisionProvenance::new(
            generation,
            effective_policy,
            DecisionReason::new(DecisionReasonCategory::Provider, 0),
            None,
        )
    });
    let credentials = rule
        .credential_actions
        .iter()
        .enumerate()
        .map(|(action, value)| {
            compile_credential(
                value,
                credential_ref(
                    identity,
                    version,
                    &format!("rule/{ordinal}/credential/{action}"),
                )?,
                credential_refs,
            )
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_boxed_slice();
    let redaction = rule
        .redaction_profile
        .as_ref()
        .map(|name| {
            redactions
                .get(name)
                .cloned()
                .ok_or(StandaloneCompileError::Inconsistent(
                    "rule redaction reference",
                ))
        })
        .transpose()?;
    Ok(StandaloneRuleTemplate {
        id,
        ordinal: checked_ordinal,
        decision: match rule.decision {
            CompiledRuleDecision::Allow => StandaloneRuleDecision::Allow,
            CompiledRuleDecision::Deny => StandaloneRuleDecision::Deny,
            CompiledRuleDecision::Delegate => StandaloneRuleDecision::Delegate,
        },
        request_timeout: rule.request_timeout,
        allow_upgrades: rule.allow_upgrades,
        request_headers: compile_header_batch(&rule.request_headers)?,
        response_headers: compile_header_batch(&rule.response_headers)?,
        credentials,
        redaction,
        local_provenance,
        provider_provenance,
    })
}

fn compile_provider_credentials(
    plan: &ReloadableProductPlan,
    identity: &SnapshotIdentity,
    version: u64,
    credential_refs: &mut Vec<CredentialRef>,
) -> Result<Box<[ProviderCredentialTemplates]>, StandaloneCompileError> {
    plan.authorization
        .providers
        .iter()
        .enumerate()
        .map(|(provider_ordinal, (_provider_name, provider))| {
            let outputs = match provider {
                AuthorizationProviderPlan::Webhook(provider) => &provider.outputs,
                AuthorizationProviderPlan::Process(provider) => &provider.outputs,
            };
            let outputs = outputs
                .iter()
                .enumerate()
                .map(|(output_ordinal, (_output_name, output))| {
                    let reference = credential_ref(
                        identity,
                        version,
                        &format!("provider/{provider_ordinal}/output/{output_ordinal}"),
                    )?;
                    let (required, mutation) = compile_provider_credential(output, reference)?;
                    credential_refs.push(mutation.credential().clone());
                    Ok(ProviderCredentialTemplate {
                        ordinal: output_ordinal,
                        required,
                        mutation,
                    })
                })
                .collect::<Result<Vec<_>, StandaloneCompileError>>()?
                .into_boxed_slice();
            Ok(ProviderCredentialTemplates {
                ordinal: provider_ordinal,
                outputs,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_boxed_slice)
}

fn compile_provider_credential(
    output: &ProviderOutputPlan,
    reference: CredentialRef,
) -> Result<(bool, CredentialMutation), StandaloneCompileError> {
    match output {
        ProviderOutputPlan::Bearer { required } => {
            Ok((*required, CredentialMutation::bearer(reference)))
        }
        ProviderOutputPlan::Basic { username, required } => Ok((
            *required,
            CredentialMutation::basic(username.clone(), reference)
                .map_err(|_| StandaloneCompileError::Checked("provider basic credential"))?,
        )),
        ProviderOutputPlan::CustomHeader { header, required } => Ok((
            *required,
            CredentialMutation::custom_header(neutral_header_name(header)?, reference).map_err(
                |_| StandaloneCompileError::Checked("provider custom-header credential"),
            )?,
        )),
    }
}

fn compile_credential(
    action: &CredentialActionPlan,
    reference: CredentialRef,
    credential_refs: &mut Vec<CredentialRef>,
) -> Result<CredentialMutation, StandaloneCompileError> {
    let mutation = match action {
        CredentialActionPlan::Bearer { .. } => CredentialMutation::bearer(reference),
        CredentialActionPlan::Basic { username, .. } => {
            CredentialMutation::basic(username.clone(), reference)
                .map_err(|_| StandaloneCompileError::Checked("basic credential"))?
        }
        CredentialActionPlan::CustomHeader { header, .. } => {
            CredentialMutation::custom_header(neutral_header_name(header)?, reference)
                .map_err(|_| StandaloneCompileError::Checked("custom-header credential"))?
        }
    };
    credential_refs.push(mutation.credential().clone());
    Ok(mutation)
}

fn credential_ref(
    identity: &SnapshotIdentity,
    version: u64,
    id: &str,
) -> Result<CredentialRef, StandaloneCompileError> {
    CredentialRef::new(identity.clone(), stable_id(id)?, version)
        .map_err(|_| StandaloneCompileError::Checked("credential reference"))
}

fn compile_body_reads(
    plan: &ReloadableProductPlan,
) -> Result<Box<[StandaloneBodyReadPlan]>, StandaloneCompileError> {
    if plan.policy.http_body_read_plans_by_cursor.len() != plan.policy.rules.len() + 1 {
        return Err(StandaloneCompileError::Inconsistent("body-read cursors"));
    }
    Ok(plan
        .policy
        .http_body_read_plans_by_cursor
        .iter()
        .map(|read| match read {
            HttpBodyReadPlan::Disabled => StandaloneBodyReadPlan::Disabled,
            HttpBodyReadPlan::Mandatory(limits) => StandaloneBodyReadPlan::Mandatory {
                max_encoded_bytes: limits.max_encoded_bytes(),
                max_decoded_bytes: limits.max_decoded_bytes(),
            },
        })
        .collect::<Vec<_>>()
        .into_boxed_slice())
}

fn compile_resource_projections(
    ordinary_request_body: RequestBodyPolicy,
    normalized_request_body: RequestBodyPolicy,
    upgrade_request_body: RequestBodyPolicy,
    response: http_access_types::ResponsePolicy,
    capture: Option<&StandaloneCaptureIntent>,
) -> StandaloneResourceProjections {
    let request_peak_bytes = [
        ordinary_request_body.projection().simultaneous_peak_bytes(),
        normalized_request_body
            .projection()
            .simultaneous_peak_bytes(),
        upgrade_request_body.projection().simultaneous_peak_bytes(),
    ]
    .into_iter()
    .max()
    .expect("the three checked request policies are nonempty");
    StandaloneResourceProjections {
        request_peak_bytes,
        response_peak_bytes: response.projection().simultaneous_peak_bytes(),
        capture_peak_bytes: capture
            .map(|capture| capture.intent.projection().simultaneous_peak_bytes())
            .unwrap_or(0),
    }
}

fn compile_header_batch(
    effects: &[HeaderEffectPlan],
) -> Result<Option<HeaderMutationBatch>, StandaloneCompileError> {
    if effects.is_empty() {
        return Ok(None);
    }
    HeaderMutationBatch::new(
        effects
            .iter()
            .map(compile_header_mutation)
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map(Some)
    .map_err(|_| StandaloneCompileError::Checked("header mutation batch"))
}

fn compile_header_mutation(
    effect: &HeaderEffectPlan,
) -> Result<HeaderMutation, StandaloneCompileError> {
    match effect {
        HeaderEffectPlan::Set { when, name, values } => HeaderMutation::set(
            mutation_condition(*when),
            neutral_header_name(name)?,
            values
                .iter()
                .map(neutral_header_value)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        HeaderEffectPlan::Append { when, name, values } => HeaderMutation::append(
            mutation_condition(*when),
            neutral_header_name(name)?,
            values
                .iter()
                .map(neutral_header_value)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        HeaderEffectPlan::Remove { when, name } => {
            HeaderMutation::remove(mutation_condition(*when), neutral_header_name(name)?)
        }
        HeaderEffectPlan::Replace {
            when,
            name,
            search,
            replace,
        } => HeaderMutation::replace(
            mutation_condition(*when),
            neutral_header_name(name)?,
            search.as_bytes().to_vec(),
            replace.as_bytes().to_vec(),
        ),
    }
    .map_err(|_| StandaloneCompileError::Checked("header mutation"))
}

const fn mutation_condition(value: CompiledHeaderEffectWhen) -> HeaderMutationCondition {
    match value {
        CompiledHeaderEffectWhen::Always => HeaderMutationCondition::Always,
        CompiledHeaderEffectWhen::IfPresent => HeaderMutationCondition::IfPresent,
        CompiledHeaderEffectWhen::IfAbsent => HeaderMutationCondition::IfAbsent,
    }
}

fn neutral_header_name(value: &http::HeaderName) -> Result<HeaderName, StandaloneCompileError> {
    HeaderName::new(value.as_str().to_owned())
        .map_err(|_| StandaloneCompileError::Checked("header name"))
}

fn neutral_header_value(value: &http::HeaderValue) -> Result<HeaderValue, StandaloneCompileError> {
    HeaderValue::new(value.as_bytes().to_vec())
        .map_err(|_| StandaloneCompileError::Checked("header value"))
}

fn stable_id(value: &str) -> Result<StableId, StandaloneCompileError> {
    StableId::new(value.to_owned()).map_err(|_| StandaloneCompileError::Checked("stable ID"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use http_access_types::{
        CredentialMutationKind, DecisionReasonCategory, EffectivePolicy, HeaderField,
        PolicyHeaderFacts,
    };

    use super::*;
    use crate::config::compiler::{CompiledParentProxyKind, ParentProxyPlan, ParentProxyTlsPlan};
    use crate::config::{compile_config_text, ConfigTextInput};

    const PLAN: &str = r#"schema_version = 3

[service]
request_timeout = "30s"

[service.forwarding]
connect_timeout = "3s"
response_head_timeout = "4s"
body_idle_timeout = "5s"
upgrade_idle_timeout = "6s"
max_request_wire_bytes = 1048576
max_request_decoded_bytes = 2097152
max_response_wire_bytes = 3145728
max_response_decoded_bytes = 4194304
chunk_bytes = 65536
preserve_request_trailers = true
max_trailer_count = 32
max_trailer_bytes = 4096

[listeners.explicit_http]
bind = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[credentials]
allowed_custom_headers = ["x-rule-token", "x-provider-token", "x-global-token"]

[credentials.inbound.zeta]
header = "x-zeta-secret"
process_providers = ["approval"]

[credentials.inbound.alpha]
header = "x-alpha-secret"
process_providers = ["approval"]

[credentials.sources.rule]
source = "environment"
variable = "RULE_TOKEN"

[credentials.sources.global]
source = "environment"
variable = "GLOBAL_TOKEN"

[authorization]
internal_context_headers = ["x-internal-context"]

[authorization.providers.approval]
kind = "process"
command = "/bin/true"
include_headers = ["x-zeta-secret", "x-alpha-secret", "x-internal-context"]

[authorization.providers.approval.outputs.token]
kind = "custom_header"
header = "x-provider-token"
required = true

[egress]
route = "direct"

[egress.origin_tls]
trust = "system_plus_custom"
ca_certificate = "root.pem"

[[egress.request_headers]]
operation = "set"
when = "always"
name = "x-global"
value = "global"

[[egress.request_headers]]
operation = "remove"
when = "always"
name = "x-internal-context"

[[egress.credential_actions]]
kind = "custom_header"
header = "x-global-token"
credential = "global"

[redaction.profiles.capture]
max_body_bytes = 1048576
max_decoded_body_bytes = 2097152
rules = [{ literals = ["secret"] }]

[observation.capture]
events = ["request.allowed", "response.denied"]
redaction_profile = "capture"
directory = "captures"
filename = "{requestId}-{suffix}.json"

[policy]
default = "allow"

[[policy.rules]]
id = "delegate"
decision = "delegate"
urls = ["https://example.test/**"]
authorization_provider = "approval"
redaction_profile = "capture"
allow_upgrades = true

[[policy.rules.request_headers]]
operation = "append"
when = "always"
name = "x-rule"
value = "request"

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
header = "x-acl-proxy-request-id"
"#;

    fn compiled() -> crate::config::CompiledConfig {
        compile_config_text(ConfigTextInput {
            text: PLAN,
            source_path: Path::new("/tmp/standalone-plan/acl-proxy.toml"),
            config_root: Path::new("/tmp/standalone-plan"),
        })
        .expect("standalone generation fixture compiles")
    }

    #[test]
    fn compile_retains_exact_checked_generation_intent() {
        let compiled = compiled();
        let plan = UnboundStandaloneGenerationPlan::compile(
            &compiled.reloadable_plan,
            GenerationId::for_test(17),
        )
        .unwrap();

        assert_eq!(plan.generation().get(), 17);
        assert!(plan.snapshot_lease().owns(plan.identity()));
        assert_eq!(plan.snapshot_lease().generation(), plan.generation());
        assert_eq!(plan.timeouts().connect_ms(), 3_000);
        assert_eq!(plan.timeouts().response_head_ms(), 4_000);
        assert_eq!(plan.timeouts().body_idle_ms(), 5_000);
        assert_eq!(plan.timeouts().upgrade_idle_ms(), 6_000);
        assert_eq!(
            plan.ordinary_request_body().representation(),
            BodyRepresentation::PreservedContentCoded
        );
        assert_eq!(
            plan.ordinary_request_body().trailer_policy(),
            TrailerPolicy::Allow
        );
        let request_limits = plan.ordinary_request_body().limits();
        assert_eq!(request_limits.wire_bytes(), 1_048_576);
        assert_eq!(request_limits.decoded_bytes(), 2_097_152);
        assert_eq!(request_limits.expansion_numerator(), 128);
        assert_eq!(request_limits.expansion_denominator(), 1);
        assert_eq!(request_limits.chunk_bytes(), 65_536);
        assert_eq!(request_limits.trailer_count(), 32);
        assert_eq!(request_limits.trailer_bytes(), 4_096);
        assert_eq!(
            plan.normalized_request_body().representation(),
            BodyRepresentation::CanonicalIdentity
        );
        assert_eq!(
            plan.normalized_request_body().limits().wire_bytes(),
            2_097_152
        );
        assert_eq!(
            plan.normalized_request_body().limits().decoded_bytes(),
            2_097_152
        );
        assert_eq!(plan.upgrade_request_body().limits().wire_bytes(), 1_048_576);
        assert_eq!(
            plan.upgrade_request_body().limits().decoded_bytes(),
            2_097_152
        );
        assert_eq!(
            plan.upgrade_request_body().trailer_policy(),
            TrailerPolicy::Deny
        );
        assert_eq!(plan.response().idle_ms(), 5_000);
        assert_eq!(plan.response().limits().wire_bytes(), 3_145_728);
        assert_eq!(plan.response().limits().decoded_bytes(), 4_194_304);
        assert_eq!(
            plan.sensitive_headers()
                .iter()
                .map(HeaderName::as_str)
                .collect::<Vec<_>>(),
            ["x-alpha-secret", "x-internal-context", "x-zeta-secret"]
        );
        assert!(matches!(plan.route(), Route::Direct));
        assert!(matches!(
            plan.origin_tls(HttpScheme::Http),
            TlsIntent::Disabled
        ));
        let TlsIntent::CustomRoots(roots) = plan.origin_tls(HttpScheme::Https) else {
            panic!("system-plus-custom HTTPS trust uses the merged roots reference")
        };
        assert!(roots.belongs_to(plan.identity()));

        let capture = plan.capture().expect("capture intent is retained");
        assert!(capture.intent().reference().belongs_to(plan.identity()));
        assert!(capture.redaction().belongs_to(plan.identity()));
        assert_eq!(
            capture.events(),
            [
                StandaloneCaptureEvent::RequestAllowed,
                StandaloneCaptureEvent::ResponseDenied
            ]
        );
        assert_eq!(plan.rules().len(), 1);
        let rule = &plan.rules()[0];
        assert_eq!(rule.id().as_str(), "delegate");
        assert_eq!(rule.ordinal(), 0);
        assert_eq!(rule.decision(), StandaloneRuleDecision::Delegate);
        assert_eq!(rule.request_timeout(), None);
        assert!(rule.allow_upgrades());
        assert!(rule.request_headers().is_some());
        assert!(rule.response_headers().is_some());
        assert!(rule.redaction().unwrap().belongs_to(plan.identity()));
        assert_eq!(rule.credentials().len(), 1);
        assert!(rule.credentials()[0]
            .credential()
            .belongs_to(plan.identity()));
        assert!(matches!(
            rule.local_provenance().effective_policy(),
            EffectivePolicy::Rule { ordinal: 0, .. }
        ));
        assert_eq!(
            rule.local_provenance().reason().category(),
            DecisionReasonCategory::Policy
        );
        assert_eq!(rule.local_provenance().reason().code(), 0);
        assert!(rule.local_provenance().trace_id().is_none());
        assert_eq!(
            rule.provider_provenance().unwrap().reason().category(),
            DecisionReasonCategory::Provider
        );
        assert!(matches!(
            plan.default_provenance().effective_policy(),
            EffectivePolicy::Default
        ));
        assert_eq!(
            plan.default_provenance().reason().category(),
            DecisionReasonCategory::Policy
        );
        assert_eq!(plan.default_provenance().reason().code(), 0);
        assert!(plan.default_provenance().trace_id().is_none());
        assert_eq!(plan.global_credentials().len(), 1);
        assert!(matches!(
            plan.global_credentials()[0].kind(),
            CredentialMutationKind::CustomHeader { name, .. } if name.as_str() == "x-global-token"
        ));
        assert!(plan.global_request_headers().is_some());
        assert_eq!(plan.provider_credentials().len(), 1);
        assert_eq!(plan.provider_credentials()[0].ordinal(), 0);
        assert_eq!(plan.provider_credentials()[0].outputs().len(), 1);
        assert_eq!(plan.provider_credentials()[0].outputs()[0].ordinal(), 0);
        assert!(plan.provider_credentials()[0].outputs()[0].required());
        assert!(plan.provider_credentials()[0].outputs()[0]
            .mutation()
            .credential()
            .belongs_to(plan.identity()));
        assert_eq!(
            plan.body_reads_by_cursor().len(),
            compiled.reloadable_plan.policy.rules.len() + 1
        );

        let projections = plan.resource_projections();
        assert_eq!(
            projections.request_peak_bytes(),
            [
                plan.ordinary_request_body()
                    .projection()
                    .simultaneous_peak_bytes(),
                plan.normalized_request_body()
                    .projection()
                    .simultaneous_peak_bytes(),
                plan.upgrade_request_body()
                    .projection()
                    .simultaneous_peak_bytes(),
            ]
            .into_iter()
            .max()
            .unwrap()
        );
        assert_eq!(
            projections.response_peak_bytes(),
            plan.response().projection().simultaneous_peak_bytes()
        );
        assert_eq!(
            projections.capture_peak_bytes(),
            capture.intent().projection().simultaneous_peak_bytes()
        );
        assert_eq!(
            plan.resource_limits(),
            RuntimeResourceLimits::new(
                projections.request_peak_bytes(),
                projections.response_peak_bytes(),
                projections.capture_peak_bytes(),
            )
            .unwrap()
        );
    }

    #[test]
    fn each_compile_creates_a_fresh_snapshot_identity() {
        let compiled = compiled();
        let first = UnboundStandaloneGenerationPlan::compile(
            &compiled.reloadable_plan,
            GenerationId::for_test(21),
        )
        .unwrap();
        let second = UnboundStandaloneGenerationPlan::compile(
            &compiled.reloadable_plan,
            GenerationId::for_test(21),
        )
        .unwrap();

        assert!(!first.identity().same_snapshot(second.identity()));
        assert!(!first.snapshot_lease().owns(second.identity()));
        assert!(!second.snapshot_lease().owns(first.identity()));
    }

    #[test]
    fn complete_headers_partition_inbound_and_internal_context_before_extraction() {
        let compiled = compiled();
        let plan = UnboundStandaloneGenerationPlan::compile(
            &compiled.reloadable_plan,
            GenerationId::for_test(22),
        )
        .unwrap();
        let complete_headers = [
            ("x-alpha-secret", b"alpha".as_slice()),
            ("x-internal-context", b"context".as_slice()),
            ("x-ordinary", b"ordinary".as_slice()),
            ("x-zeta-secret", b"zeta".as_slice()),
        ]
        .into_iter()
        .map(|(name, value)| {
            HeaderField::new(
                HeaderName::new(name.to_owned()).unwrap(),
                HeaderValue::new(value.to_vec()).unwrap(),
            )
        })
        .collect();

        let partition =
            PolicyHeaderFacts::new(complete_headers, plan.sensitive_headers().to_vec()).unwrap();

        assert_eq!(
            partition
                .sensitive_headers()
                .iter()
                .map(HeaderName::as_str)
                .collect::<Vec<_>>(),
            ["x-alpha-secret", "x-internal-context", "x-zeta-secret"]
        );
        assert_eq!(
            partition
                .sensitive_header_presence()
                .iter()
                .map(HeaderName::as_str)
                .collect::<Vec<_>>(),
            ["x-alpha-secret", "x-internal-context", "x-zeta-secret"]
        );
        assert_eq!(partition.ordinary_headers().len(), 1);
        assert_eq!(
            partition.ordinary_headers()[0].name().as_str(),
            "x-ordinary"
        );
        assert_eq!(
            partition.ordinary_headers()[0].value().as_bytes(),
            b"ordinary"
        );
    }

    #[test]
    fn compile_rejects_overlap_between_inbound_and_internal_context_headers() {
        let mut compiled = compiled();
        let inbound = compiled
            .reloadable_plan
            .credentials
            .inbound
            .values()
            .next()
            .unwrap()
            .header
            .clone();
        compiled
            .reloadable_plan
            .authorization
            .internal_context_headers
            .push(inbound);

        assert!(matches!(
            UnboundStandaloneGenerationPlan::compile(
                &compiled.reloadable_plan,
                GenerationId::for_test(23),
            ),
            Err(StandaloneCompileError::Inconsistent(
                "standalone sensitive headers"
            ))
        ));
    }

    #[test]
    fn parent_route_retains_canonical_target_and_exact_custom_root_role() {
        let mut compiled = compiled();
        compiled.reloadable_plan.egress.route = CompiledEgressRoute::ParentProxy;
        compiled.reloadable_plan.egress.parent_proxy = Some(ParentProxyPlan {
            kind: CompiledParentProxyKind::Generic,
            url: "https://parent.example.test:8443/".to_owned(),
            host: "parent.example.test".to_owned(),
            port: 8443,
            tls: Some(ParentProxyTlsPlan {
                trust: CompiledTlsTrust::Custom,
                ca_certificate: Some("parent-root.pem".into()),
                server_name: "parent.example.test".to_owned(),
            }),
        });

        let plan = UnboundStandaloneGenerationPlan::compile(
            &compiled.reloadable_plan,
            GenerationId::for_test(31),
        )
        .unwrap();
        let Route::Parent { target, tls } = plan.route() else {
            panic!("parent route intent is retained")
        };
        assert_eq!(target.as_str(), "https://parent.example.test:8443/");
        let TlsIntent::CustomRoots(roots) = tls else {
            panic!("custom parent trust is represented by an opaque roots reference")
        };
        assert!(roots.belongs_to(plan.identity()));
        assert!(plan.snapshot_lease().owns(plan.identity()));
    }

    #[test]
    fn missing_activated_credential_source_is_rejected_by_semantic_name() {
        let compiled = compiled();
        let plan = UnboundStandaloneGenerationPlan::compile(
            &compiled.reloadable_plan,
            GenerationId::for_test(41),
        )
        .unwrap();

        assert_eq!(
            bind_credential_source(
                &plan.manifest.global_credentials[0],
                &CredentialSourceRegistry::from_names([]),
                "credential source",
            )
            .err(),
            Some(StandaloneBindError::Missing("credential source"))
        );
    }

    #[test]
    fn provider_output_binding_rejects_a_different_activated_shape() {
        let expected = StandaloneProviderOutputShape::CustomHeader {
            header: http::HeaderName::from_static("x-provider-token"),
            required: true,
        };
        assert!(!expected.matches(&ProviderOutputDefinition::Bearer { required: true }));
        assert!(!expected.matches(&ProviderOutputDefinition::CustomHeader {
            header: http::HeaderName::from_static("x-other-token"),
            required: true,
        }));
        assert!(!expected.matches(&ProviderOutputDefinition::CustomHeader {
            header: http::HeaderName::from_static("x-provider-token"),
            required: false,
        }));
    }

    #[test]
    fn custom_root_binding_rejects_an_activation_with_different_trust() {
        let mut compiled = compiled();
        let plan = UnboundStandaloneGenerationPlan::compile(
            &compiled.reloadable_plan,
            GenerationId::for_test(42),
        )
        .unwrap();
        compiled.reloadable_plan.egress.origin_tls.trust = CompiledTlsTrust::Insecure;
        compiled.reloadable_plan.egress.origin_tls.ca_certificate = None;
        let sources = CredentialSourceRegistry::from_names(["global".to_owned()]);
        let egress =
            EgressSnapshot::activate(compiled.reloadable_plan.egress, &sources, || false).unwrap();

        assert_eq!(
            bind_tls_roots(&plan.manifest.tls[0], &egress).err(),
            Some(StandaloneBindError::Missing("TLS roots"))
        );
    }

    #[test]
    fn malformed_compiler_owned_resource_proof_is_rejected() {
        let mut invalid_sum = compiled();
        invalid_sum
            .reloadable_plan
            .resource_plan
            .http_body_resources_by_cursor[0]
            .combined_peak_bytes += 1;
        assert!(matches!(
            UnboundStandaloneGenerationPlan::compile(
                &invalid_sum.reloadable_plan,
                GenerationId::for_test(43),
            ),
            Err(StandaloneCompileError::Inconsistent(
                "standalone resource cursor sum"
            ))
        ));

        let mut invalid_maximum = compiled();
        invalid_maximum
            .reloadable_plan
            .resource_plan
            .max_reachable_http_body_combined_peak_bytes += 1;
        assert!(matches!(
            UnboundStandaloneGenerationPlan::compile(
                &invalid_maximum.reloadable_plan,
                GenerationId::for_test(44),
            ),
            Err(StandaloneCompileError::Inconsistent(
                "standalone resource maximum"
            ))
        ));
    }
}
