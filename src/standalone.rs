use std::collections::BTreeMap;
use std::time::Duration;

use credential_core::{
    CredentialDescriptor, CredentialLimits, CredentialProfile, CredentialPurpose,
};
use http_access_policy_acl::ProductActionRef;
use http_access_runtime::{RuntimeResourceLimits, SnapshotLease, SnapshotRegistries};
use http_access_types::{
    BodyLimits, BodyRepresentation, CanonicalHost, CaptureIntent, CaptureRef, ClientTlsIntent,
    CredentialMutation, CredentialMutationKind, CredentialRef, HeaderMutation, HeaderMutationBatch,
    HeaderMutationCondition, HeaderName, HeaderValue, HttpProtocol, HttpProtocolSet, HttpScheme,
    HttpVersion, PolicyGeneration, RedactionRef, RedirectPolicy, RequestBodyPolicy, Route,
    SensitiveHeaderPolicy, SnapshotIdentity, StableId, StageTimeouts, TlsTrust, TrailerPolicy,
    TransportSecurity,
};

use crate::authorization::protocol::{ProviderOutputDefinition, ProviderOutputIndex};
use crate::authorization::{ActivatedProviderOutputBinding, ProductAuthorizationSnapshot};
use crate::config::compiler::{
    AuthorizationProviderPlan, CompiledCaptureEvent, CompiledHeaderEffectWhen,
    CredentialActionPlan, ForwardingPlan, HeaderEffectPlan, PolicyRulePlan, ProviderOutputPlan,
    ReloadableProductPlan,
};
use crate::credentials::OutboundCredentialSource;
use crate::egress::NeutralEgressBindings;
use crate::observation::{CaptureEvent, ProductObservationSnapshot};
use crate::policy::{ProductAclCompileError, ProductAclSnapshot};
use crate::runtime::{GenerationId, ProviderIndex, ProviderRegistry};
use http_access_redaction::{RedactionProfile, RedactionSnapshot};

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
    route: Option<Route>,
    origin_protocols: Option<HttpProtocolSet>,
    origin_https_trust: Option<TlsTrust>,
    capture: Option<StandaloneCaptureIntent>,
    sensitive_headers: Box<[HeaderName]>,
    sensitive_header_policy: SensitiveHeaderPolicy,
    product_acl: ProductAclSnapshot,
    rules: Box<[StandaloneRuleTemplate]>,
    global_request_headers: Option<HeaderMutationBatch>,
    global_credentials: Box<[StandaloneCredentialTemplate]>,
    provider_credentials: Box<[ProviderCredentialTemplates]>,
    snapshot_lease: Option<SnapshotLease>,
    pending_registries: Option<SnapshotRegistries>,
    resource_limits: RuntimeResourceLimits,
}

struct StandaloneBindingManifest {
    provider_outputs: Box<[StandaloneProviderOutputManifest]>,
    capture_redaction: Option<RedactionRef>,
    resources: StandaloneResourceProof,
}

pub(crate) struct StandaloneCredentialTemplate {
    source: String,
    mutation: CredentialMutation,
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

pub(crate) struct StandaloneActivatedBindings {
    global_credentials: Box<[BoundCredentialSource]>,
    rule_credentials: Box<[Box<[BoundCredentialSource]>]>,
    rule_providers: Box<[Option<BoundRuleProvider>]>,
    rule_redactions: Box<[Option<BoundRedaction>]>,
    provider_outputs: Box<[BoundProviderOutput]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StandaloneResourceProof {
    cursors: Box<[StandaloneCursorResourceProof]>,
    max_reachable_combined_peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StandaloneCursorResourceProof {
    product_incremental_peak_bytes: usize,
    runtime_replay_capacity_bytes: usize,
    combined_peak_bytes: usize,
}

pub(crate) struct BoundCredentialSource {
    descriptor: CredentialDescriptor,
    source: OutboundCredentialSource,
}

struct BoundRuleProvider {
    action_id: StableId,
    provider: ProviderIndex,
}

pub(crate) struct BoundProviderOutput {
    reference: CredentialRef,
    provider: ProviderIndex,
    output: ProviderOutputIndex,
}

pub(crate) struct BoundRedaction {
    handle: RedactionProfile,
}

pub(crate) struct StandaloneRuleTemplate {
    ordinal: u32,
    request_timeout: Option<Duration>,
    allow_upgrades: bool,
    request_headers: Option<HeaderMutationBatch>,
    response_headers: Option<HeaderMutationBatch>,
    credentials: Box<[StandaloneCredentialTemplate]>,
    redaction: Option<RedactionRef>,
    redaction_profile: Option<String>,
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

pub(crate) struct StandaloneCaptureIntent {
    intent: CaptureIntent,
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
struct StandaloneResourceProjections {
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
    #[error("invalid compiled ACL")]
    Policy(#[from] ProductAclCompileError),
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

        let capture = compile_capture(plan, &identity, version)?;
        let sensitive_headers = compile_sensitive_headers(plan)?;
        let sensitive_header_policy = compile_observation_sensitive_header_policy(plan)?;
        let product_acl = ProductAclSnapshot::compile(
            &plan.policy,
            generation,
            identity.clone(),
            &sensitive_headers,
        )?;
        let global_request_headers = compile_header_batch(&plan.egress.request_headers)?;

        let mut credential_refs = Vec::new();
        let global_credentials = plan
            .egress
            .credential_actions
            .iter()
            .enumerate()
            .map(|(index, action)| {
                let mutation = compile_credential(
                    action,
                    credential_ref(&identity, version, &format!("global/credential/{index}"))?,
                    &mut credential_refs,
                )?;
                Ok(StandaloneCredentialTemplate {
                    source: credential_source_name(action).to_owned(),
                    mutation,
                })
            })
            .collect::<Result<Vec<_>, StandaloneCompileError>>()?
            .into_boxed_slice();

        let mut rules = Vec::with_capacity(plan.policy.rules.len());
        for (ordinal, rule) in plan.policy.rules.iter().enumerate() {
            rules.push(compile_rule_template(
                rule,
                ordinal,
                &identity,
                version,
                &redactions,
                &mut credential_refs,
            )?);
        }

        let provider_credentials =
            compile_provider_credentials(plan, &identity, version, &mut credential_refs)?;
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
        let registries =
            SnapshotRegistries::new(&identity, &credential_refs, &redaction_refs, &capture_refs)
                .map_err(|_| StandaloneCompileError::Checked("snapshot registries"))?;
        let core = StandaloneGenerationCore {
            identity,
            generation,
            timeouts,
            ordinary_request_body,
            normalized_request_body,
            upgrade_request_body,
            response,
            route: None,
            origin_protocols: None,
            origin_https_trust: None,
            capture,
            sensitive_headers,
            sensitive_header_policy,
            product_acl,
            rules: rules.into_boxed_slice(),
            global_request_headers,
            global_credentials,
            provider_credentials,
            snapshot_lease: None,
            pending_registries: Some(registries),
            resource_limits,
        };
        let manifest = compile_binding_manifest(plan, &core, &redactions)?;
        Ok(Self { core, manifest })
    }

    pub(crate) fn finalize(
        mut self,
        neutral_egress: NeutralEgressBindings,
    ) -> Result<Self, StandaloneCompileError> {
        let (origin_protocols, origin_https_trust, route, tls_roots) = neutral_egress.into_parts();
        let registries =
            self.core
                .pending_registries
                .take()
                .ok_or(StandaloneCompileError::Inconsistent(
                    "standalone generation finalization",
                ))?;
        let snapshot_lease = SnapshotLease::new(http_access_runtime::SnapshotLeaseInput {
            identity: self.core.identity.clone(),
            generation: self.core.generation,
            sensitive_headers: self.core.sensitive_headers.to_vec(),
            registries,
            managed_network_policies: Vec::new(),
            tls_roots,
            resource_limits: self.core.resource_limits,
            templates: Vec::new(),
            handles: Vec::new(),
        })
        .map_err(|_| StandaloneCompileError::Checked("snapshot lease"))?;
        self.core.route = Some(route);
        self.core.origin_protocols = Some(origin_protocols);
        self.core.origin_https_trust = Some(origin_https_trust);
        self.core.snapshot_lease = Some(snapshot_lease);
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bind(
        self,
        credentials: &BTreeMap<String, OutboundCredentialSource>,
        redaction_snapshot: &RedactionSnapshot,
        authorization: &ProductAuthorizationSnapshot,
        providers: &ProviderRegistry,
        observation: &ProductObservationSnapshot,
    ) -> Result<StandaloneGenerationPlan, StandaloneBindError> {
        if self.core.snapshot_lease.is_none()
            || self.core.pending_registries.is_some()
            || self.core.route.is_none()
            || self.core.origin_protocols.is_none()
            || self.core.origin_https_trust.is_none()
        {
            return Err(StandaloneBindError::Inconsistent(
                "standalone generation finalization",
            ));
        }
        let activated = bind_activated(
            &self.core,
            &self.manifest,
            credentials,
            redaction_snapshot,
            authorization,
            providers,
            observation,
        )?;
        Ok(StandaloneGenerationPlan {
            core: self.core,
            activated,
        })
    }

    pub(crate) fn identity(&self) -> &SnapshotIdentity {
        self.core.identity()
    }

    pub(crate) fn version(&self) -> u64 {
        self.core.generation.get()
    }

    pub(crate) fn capture_redaction(&self) -> Option<&RedactionRef> {
        self.manifest.capture_redaction.as_ref()
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
        let finalized = self
            .finalize(crate::egress::NeutralEgressBindings::direct_system_for_test())
            .expect("runtime test standalone generation finalizes");
        StandaloneGenerationPlan {
            activated: StandaloneActivatedBindings {
                global_credentials: Box::new([]),
                rule_credentials: Box::new([]),
                rule_providers: Box::new([]),
                rule_redactions: Box::new([]),
                provider_outputs: Box::new([]),
            },
            core: finalized.core,
        }
    }
}

impl StandaloneGenerationCore {
    pub(crate) fn identity(&self) -> &SnapshotIdentity {
        &self.identity
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
        self.route
            .as_ref()
            .expect("standalone generation route is finalized before publication")
    }

    pub(crate) fn origin_protocol(&self, ingress: HttpVersion) -> HttpProtocol {
        self.origin_protocols
            .as_ref()
            .expect("standalone generation protocols are finalized before publication")
            .select(ingress)
    }

    pub(crate) fn origin_security(
        &self,
        scheme: HttpScheme,
        authenticated_name: CanonicalHost,
    ) -> TransportSecurity {
        match scheme {
            HttpScheme::Http => TransportSecurity::Cleartext,
            HttpScheme::Https => TransportSecurity::Tls(ClientTlsIntent::new(
                authenticated_name,
                self.origin_https_trust
                    .as_ref()
                    .expect("standalone generation trust is finalized before publication")
                    .clone(),
            )),
        }
    }

    pub(crate) fn capture(&self) -> Option<&StandaloneCaptureIntent> {
        self.capture.as_ref()
    }

    pub(crate) fn sensitive_headers(&self) -> &[HeaderName] {
        &self.sensitive_headers
    }

    pub(crate) const fn sensitive_header_policy(&self) -> &SensitiveHeaderPolicy {
        &self.sensitive_header_policy
    }

    pub(crate) fn rules(&self) -> &[StandaloneRuleTemplate] {
        &self.rules
    }

    pub(crate) const fn product_acl(&self) -> &ProductAclSnapshot {
        &self.product_acl
    }

    pub(crate) fn global_request_headers(&self) -> Option<&HeaderMutationBatch> {
        self.global_request_headers.as_ref()
    }

    pub(crate) fn global_credentials(&self) -> &[StandaloneCredentialTemplate] {
        &self.global_credentials
    }

    pub(crate) fn provider_credentials(&self) -> &[ProviderCredentialTemplates] {
        &self.provider_credentials
    }

    pub(crate) fn snapshot_lease(&self) -> &SnapshotLease {
        self.snapshot_lease
            .as_ref()
            .expect("standalone generation lease is finalized before publication")
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

    pub(crate) fn provider_for_action(
        &self,
        ordinal: usize,
        action: &ProductActionRef,
    ) -> Option<ProviderIndex> {
        let bound = self.rule_providers.get(ordinal)?.as_ref()?;
        (action.id() == &bound.action_id).then_some(bound.provider)
    }

    #[cfg(test)]
    pub(crate) fn rule_provider_for_test(&self, ordinal: usize) -> Option<ProviderIndex> {
        self.rule_providers
            .get(ordinal)?
            .as_ref()
            .map(|bound| bound.provider)
    }

    pub(crate) fn rule_redaction(&self, ordinal: usize) -> Option<&BoundRedaction> {
        self.rule_redactions.get(ordinal).and_then(Option::as_ref)
    }

    pub(crate) fn provider_outputs(&self) -> &[BoundProviderOutput] {
        &self.provider_outputs
    }
}

impl StandaloneResourceProof {
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

impl BoundCredentialSource {
    pub(crate) fn reference(&self) -> &CredentialRef {
        self.descriptor.reference()
    }

    pub(crate) fn descriptor(&self) -> &CredentialDescriptor {
        &self.descriptor
    }

    pub(crate) fn source(&self) -> &OutboundCredentialSource {
        &self.source
    }
}

impl StandaloneCredentialTemplate {
    pub(crate) fn source(&self) -> &str {
        &self.source
    }

    pub(crate) fn mutation(&self) -> &CredentialMutation {
        &self.mutation
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
    pub(crate) fn handle(&self) -> &RedactionProfile {
        &self.handle
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
    Ok(StandaloneBindingManifest {
        provider_outputs,
        capture_redaction: plan
            .observation
            .capture
            .as_ref()
            .and_then(|capture| redaction_refs.get(&capture.redaction_profile).cloned()),
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

#[allow(clippy::too_many_arguments)]
fn bind_activated(
    core: &StandaloneGenerationCore,
    manifest: &StandaloneBindingManifest,
    credentials: &BTreeMap<String, OutboundCredentialSource>,
    redaction_snapshot: &RedactionSnapshot,
    authorization: &ProductAuthorizationSnapshot,
    providers: &ProviderRegistry,
    observation: &ProductObservationSnapshot,
) -> Result<StandaloneActivatedBindings, StandaloneBindError> {
    if !manifest.resources.is_valid() {
        return Err(StandaloneBindError::Inconsistent(
            "standalone resource proof",
        ));
    }
    let global_credentials = core
        .global_credentials
        .iter()
        .map(|template| bind_credential_source(template, credentials, "credential source"))
        .collect::<Result<Vec<_>, _>>()?
        .into_boxed_slice();

    let mut rule_credentials = Vec::with_capacity(core.rules.len());
    let mut rule_providers = Vec::with_capacity(core.rules.len());
    let mut rule_redactions = Vec::with_capacity(core.rules.len());
    for (ordinal, core_rule) in core.rules.iter().enumerate() {
        let credentials_for_rule = core_rule
            .credentials
            .iter()
            .map(|template| bind_credential_source(template, credentials, "rule credential source"))
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();
        rule_credentials.push(credentials_for_rule);

        let provider = core
            .product_acl
            .provider_action_id(ordinal)
            .map(|action_id| {
                let provider = providers
                    .get(action_id.as_str())
                    .ok_or(StandaloneBindError::Missing("rule provider"))?;
                Ok(BoundRuleProvider {
                    action_id: action_id.clone(),
                    provider,
                })
            })
            .transpose()?;
        rule_providers.push(provider);

        let redaction = core_rule
            .redaction_profile
            .as_deref()
            .map(|name| bind_redaction(name, core_rule.redaction.as_ref(), redaction_snapshot))
            .transpose()?;
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

    bind_capture(core, manifest, redaction_snapshot, observation)?;

    Ok(StandaloneActivatedBindings {
        global_credentials,
        rule_credentials: rule_credentials.into_boxed_slice(),
        rule_providers: rule_providers.into_boxed_slice(),
        rule_redactions: rule_redactions.into_boxed_slice(),
        provider_outputs,
    })
}

fn bind_credential_source(
    template: &StandaloneCredentialTemplate,
    credentials: &BTreeMap<String, OutboundCredentialSource>,
    missing: &'static str,
) -> Result<BoundCredentialSource, StandaloneBindError> {
    let source = credentials
        .get(template.source())
        .cloned()
        .ok_or(StandaloneBindError::Missing(missing))?;
    let mutation = template.mutation();
    let purpose = match mutation.kind() {
        CredentialMutationKind::Bearer(_) => CredentialPurpose::Bearer,
        CredentialMutationKind::Basic { .. } => CredentialPurpose::BasicPassword,
        CredentialMutationKind::CustomHeader { name, .. } => {
            CredentialPurpose::CustomHeader(name.clone())
        }
    };
    let limits = CredentialLimits::new(
        source.maximum_material_bytes(),
        source.maximum_staging_bytes(),
    )
    .map_err(|_| StandaloneBindError::Inconsistent("credential source limits"))?;
    let descriptor = CredentialDescriptor::new(
        mutation.credential().clone(),
        purpose,
        CredentialProfile::StandaloneTrusted,
        limits,
    )
    .map_err(|_| StandaloneBindError::Inconsistent("credential descriptor"))?;
    Ok(BoundCredentialSource { descriptor, source })
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
    _name: &str,
    reference: Option<&RedactionRef>,
    redaction_snapshot: &RedactionSnapshot,
) -> Result<BoundRedaction, StandaloneBindError> {
    let reference = reference.ok_or(StandaloneBindError::Inconsistent("redaction reference"))?;
    let handle = redaction_snapshot
        .profile(reference)
        .map_err(|_| StandaloneBindError::Missing("redaction profile handle"))?;
    Ok(BoundRedaction { handle })
}

fn bind_capture(
    core: &StandaloneGenerationCore,
    manifest: &StandaloneBindingManifest,
    redaction_snapshot: &RedactionSnapshot,
    observation: &ProductObservationSnapshot,
) -> Result<(), StandaloneBindError> {
    match (
        core.capture.as_ref(),
        manifest.capture_redaction.as_ref(),
        observation.capture_epoch().capture(),
    ) {
        (None, None, None) => Ok(()),
        (Some(neutral), Some(reference), Some(activated)) => {
            let profile = redaction_snapshot
                .profile(reference)
                .map_err(|_| StandaloneBindError::Missing("capture redaction profile handle"))?;
            if !profile.same_profile(activated.profile())
                || !capture_events_match(neutral.events(), activated)
            {
                return Err(StandaloneBindError::Inconsistent("capture binding"));
            }
            Ok(())
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

impl StandaloneRuleTemplate {
    pub(crate) fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub(crate) const fn request_timeout(&self) -> Option<Duration> {
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

    pub(crate) fn credentials(&self) -> &[StandaloneCredentialTemplate] {
        &self.credentials
    }

    pub(crate) fn redaction(&self) -> Option<&RedactionRef> {
        self.redaction.as_ref()
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

    pub(crate) fn events(&self) -> &[StandaloneCaptureEvent] {
        &self.events
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

fn compile_capture(
    plan: &ReloadableProductPlan,
    identity: &SnapshotIdentity,
    version: u64,
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
    let chunk_bytes = plan.forwarding.chunk_bytes.min(
        profile
            .limits
            .max_body_bytes()
            .max(profile.limits.max_decoded_body_bytes()),
    );
    let limits = body_limits(
        profile.limits.max_body_bytes(),
        profile.limits.max_decoded_body_bytes(),
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
    Ok(Some(StandaloneCaptureIntent { intent, events }))
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

fn compile_observation_sensitive_header_policy(
    plan: &ReloadableProductPlan,
) -> Result<SensitiveHeaderPolicy, StandaloneCompileError> {
    let inbound = plan
        .credentials
        .inbound
        .values()
        .map(|inbound| neutral_header_name(&inbound.header))
        .collect::<Result<Vec<_>, _>>()?;
    let internal_context = plan
        .authorization
        .internal_context_headers
        .iter()
        .map(neutral_header_name)
        .collect::<Result<Vec<_>, _>>()?;
    let credential_destinations = plan
        .egress
        .credential_actions
        .iter()
        .chain(
            plan.policy
                .rules
                .iter()
                .flat_map(|rule| rule.credential_actions.iter()),
        )
        .map(credential_action_destination)
        .chain(
            plan.authorization
                .providers
                .values()
                .flat_map(|provider| match provider {
                    AuthorizationProviderPlan::Webhook(provider) => provider.outputs.values(),
                    AuthorizationProviderPlan::Process(provider) => provider.outputs.values(),
                })
                .map(provider_output_destination),
        )
        .collect::<Result<Vec<_>, _>>()?;

    SensitiveHeaderPolicy::new(inbound, internal_context, credential_destinations)
        .map_err(|_| StandaloneCompileError::Checked("sensitive header policy"))
}

fn credential_action_destination(
    action: &CredentialActionPlan,
) -> Result<HeaderName, StandaloneCompileError> {
    match action {
        CredentialActionPlan::Bearer { .. } | CredentialActionPlan::Basic { .. } => {
            HeaderName::new("authorization").map_err(|_| {
                StandaloneCompileError::Checked("authorization credential destination")
            })
        }
        CredentialActionPlan::CustomHeader { header, .. } => neutral_header_name(header),
    }
}

fn provider_output_destination(
    output: &ProviderOutputPlan,
) -> Result<HeaderName, StandaloneCompileError> {
    match output {
        ProviderOutputPlan::Bearer { .. } | ProviderOutputPlan::Basic { .. } => {
            HeaderName::new("authorization").map_err(|_| {
                StandaloneCompileError::Checked("authorization provider output destination")
            })
        }
        ProviderOutputPlan::CustomHeader { header, .. } => neutral_header_name(header),
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_rule_template(
    rule: &PolicyRulePlan,
    ordinal: usize,
    identity: &SnapshotIdentity,
    version: u64,
    redactions: &BTreeMap<String, RedactionRef>,
    credential_refs: &mut Vec<CredentialRef>,
) -> Result<StandaloneRuleTemplate, StandaloneCompileError> {
    let checked_ordinal =
        u32::try_from(ordinal).map_err(|_| StandaloneCompileError::Checked("rule ordinal"))?;
    let credentials = rule
        .credential_actions
        .iter()
        .enumerate()
        .map(|(action, value)| {
            let mutation = compile_credential(
                value,
                credential_ref(
                    identity,
                    version,
                    &format!("rule/{ordinal}/credential/{action}"),
                )?,
                credential_refs,
            )?;
            Ok(StandaloneCredentialTemplate {
                source: credential_source_name(value).to_owned(),
                mutation,
            })
        })
        .collect::<Result<Vec<_>, StandaloneCompileError>>()?
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
        ordinal: checked_ordinal,
        request_timeout: rule.request_timeout,
        allow_upgrades: rule.allow_upgrades,
        request_headers: compile_header_batch(&rule.request_headers)?,
        response_headers: compile_header_batch(&rule.response_headers)?,
        credentials,
        redaction,
        redaction_profile: rule.redaction_profile.clone(),
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

    use http_access_types::{CredentialMutationKind, HeaderField, PolicyHeaderFacts};
    use tempfile::TempDir;

    use super::*;
    use crate::config::compiler::{
        CompiledEgressRoute, CompiledParentProxyKind, CompiledTlsTrust, ParentProxyPlan,
        ParentProxyTlsPlan,
    };
    use crate::config::{compile_config_text, ConfigTextInput};
    use crate::egress::EgressActivation;
    use crate::test_certificates::TestTlsIdentity;

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

    fn finalized(
        plan: &ReloadableProductPlan,
        id: GenerationId,
    ) -> UnboundStandaloneGenerationPlan {
        let directory = TempDir::new().unwrap();
        let certificate = TestTlsIdentity::new("standalone-root.example");
        let ca = directory.path().join("root.pem");
        crate::filesystem::write_public_file(&ca, certificate.root_certificate_pem()).unwrap();
        let mut egress = plan.egress.clone();
        if matches!(
            egress.origin_tls.trust,
            CompiledTlsTrust::Custom | CompiledTlsTrust::SystemPlusCustom
        ) {
            egress.origin_tls.ca_certificate = Some(ca.clone());
        }
        if let Some(parent_tls) = egress
            .parent_proxy
            .as_mut()
            .and_then(|parent| parent.tls.as_mut())
        {
            if matches!(
                parent_tls.trust,
                CompiledTlsTrust::Custom | CompiledTlsTrust::SystemPlusCustom
            ) {
                parent_tls.ca_certificate = Some(ca);
            }
        }
        let draft = UnboundStandaloneGenerationPlan::compile(plan, id).unwrap();
        let activation = EgressActivation::activate(
            egress,
            draft.identity(),
            PolicyGeneration::new(draft.version()).unwrap(),
            || false,
        )
        .unwrap();
        let (neutral, _) = activation.into_parts();
        draft.finalize(neutral).unwrap()
    }

    fn outbound_sources(
        plan: &ReloadableProductPlan,
    ) -> BTreeMap<String, OutboundCredentialSource> {
        let providers = ProviderRegistry::from_names(plan.authorization.providers.keys().cloned());
        let activation = crate::credentials::CredentialActivation::activate(
            plan.credentials.clone(),
            &providers,
        )
        .expect("credential sources activate");
        let (_inbound, sources) = activation.into_parts();
        sources
    }

    #[test]
    fn compile_retains_exact_checked_generation_intent() {
        let compiled = compiled();
        let plan = finalized(&compiled.reloadable_plan, GenerationId::for_test(17));

        assert!(plan.snapshot_lease().owns(plan.identity()));
        assert_eq!(plan.snapshot_lease().generation().get(), 17);
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
        assert_eq!(
            plan.sensitive_header_policy()
                .names()
                .iter()
                .map(HeaderName::as_str)
                .collect::<Vec<_>>(),
            [
                "authorization",
                "cookie",
                "proxy-authorization",
                "set-cookie",
                "x-alpha-secret",
                "x-global-token",
                "x-internal-context",
                "x-provider-token",
                "x-rule-token",
                "x-zeta-secret"
            ]
        );
        assert!(matches!(plan.route(), Route::Direct));
        assert!(matches!(
            plan.origin_security(
                HttpScheme::Http,
                CanonicalHost::new("origin.example").unwrap()
            ),
            TransportSecurity::Cleartext
        ));
        let TransportSecurity::Tls(intent) = plan.origin_security(
            HttpScheme::Https,
            CanonicalHost::new("origin.example").unwrap(),
        ) else {
            panic!("HTTPS origin retains TLS security")
        };
        let TlsTrust::SystemAndCustomRoots(roots) = intent.trust() else {
            panic!("system-plus-custom HTTPS trust uses the merged roots reference")
        };
        assert_eq!(intent.authenticated_name().as_str(), "origin.example");
        assert!(roots.belongs_to(plan.identity()));

        let capture = plan.capture().expect("capture intent is retained");
        assert!(capture.intent().reference().belongs_to(plan.identity()));
        assert_eq!(
            capture.events(),
            [
                StandaloneCaptureEvent::RequestAllowed,
                StandaloneCaptureEvent::ResponseDenied
            ]
        );
        assert_eq!(plan.rules().len(), 1);
        let rule = &plan.rules()[0];
        assert_eq!(rule.ordinal(), 0);
        assert_eq!(rule.request_timeout(), None);
        assert!(rule.allow_upgrades());
        assert!(rule.request_headers().is_some());
        assert!(rule.response_headers().is_some());
        assert!(rule.redaction().unwrap().belongs_to(plan.identity()));
        assert_eq!(rule.redaction_profile.as_deref(), Some("capture"));
        assert_eq!(rule.credentials().len(), 1);
        assert_eq!(rule.credentials()[0].source(), "rule");
        assert!(rule.credentials()[0]
            .mutation()
            .credential()
            .belongs_to(plan.identity()));
        assert_eq!(
            plan.product_acl()
                .provider_action_id(0)
                .map(StableId::as_str),
            Some("approval")
        );
        assert_eq!(plan.global_credentials().len(), 1);
        assert!(matches!(
            plan.global_credentials()[0].mutation().kind(),
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
    }

    #[test]
    fn bound_provider_requires_the_exact_acl_action_id() {
        let identity = SnapshotIdentity::new();
        let providers = ProviderRegistry::from_names(["alpha".to_owned(), "beta".to_owned()]);
        let bindings = StandaloneActivatedBindings {
            global_credentials: Box::new([]),
            rule_credentials: Box::new([]),
            rule_providers: vec![Some(BoundRuleProvider {
                action_id: stable_id("alpha").unwrap(),
                provider: providers.get("alpha").unwrap(),
            })]
            .into_boxed_slice(),
            rule_redactions: Box::new([]),
            provider_outputs: Box::new([]),
        };
        let alpha = ProductActionRef::new(&identity, stable_id("alpha").unwrap());
        let beta = ProductActionRef::new(&identity, stable_id("beta").unwrap());

        assert_eq!(
            bindings.provider_for_action(0, &alpha),
            providers.get("alpha")
        );
        assert_eq!(bindings.provider_for_action(0, &beta), None);
        assert_eq!(bindings.provider_for_action(1, &alpha), None);
    }

    #[test]
    fn each_compile_creates_a_fresh_snapshot_identity() {
        let compiled = compiled();
        let first = finalized(&compiled.reloadable_plan, GenerationId::for_test(21));
        let second = finalized(&compiled.reloadable_plan, GenerationId::for_test(21));

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

        let plan = finalized(&compiled.reloadable_plan, GenerationId::for_test(31));
        let Route::Parent { target, security } = plan.route() else {
            panic!("parent route intent is retained")
        };
        assert_eq!(target.as_str(), "https://parent.example.test:8443/");
        let TransportSecurity::Tls(intent) = security else {
            panic!("custom parent route retains TLS security")
        };
        let TlsTrust::CustomRoots(roots) = intent.trust() else {
            panic!("custom parent trust retains exact root material")
        };
        assert_eq!(intent.authenticated_name().as_str(), "parent.example.test");
        assert!(roots.belongs_to(plan.identity()));
        assert!(plan.snapshot_lease().owns(plan.identity()));
    }

    #[test]
    fn missing_activated_credential_source_is_rejected_by_template() {
        let compiled = compiled();
        let plan = UnboundStandaloneGenerationPlan::compile(
            &compiled.reloadable_plan,
            GenerationId::for_test(41),
        )
        .unwrap();

        assert_eq!(
            bind_credential_source(
                &plan.global_credentials()[0],
                &BTreeMap::new(),
                "credential source",
            )
            .err(),
            Some(StandaloneBindError::Missing("credential source"))
        );
    }

    #[test]
    fn direct_source_binding_retains_exact_descriptor_and_locator() {
        let compiled = compiled();
        let sources = outbound_sources(&compiled.reloadable_plan);
        let plan = UnboundStandaloneGenerationPlan::compile(
            &compiled.reloadable_plan,
            GenerationId::for_test(42),
        )
        .unwrap();
        let template = &plan.global_credentials()[0];
        let mutation = template.mutation();
        let bound = bind_credential_source(template, &sources, "credential source").unwrap();

        assert_eq!(bound.reference(), mutation.credential());
        assert_eq!(
            bound.descriptor().profile(),
            CredentialProfile::StandaloneTrusted
        );
        assert!(matches!(
            bound.descriptor().purpose(),
            CredentialPurpose::CustomHeader(name) if name.as_str() == "x-global-token"
        ));
        assert_eq!(
            bound.descriptor().limits().maximum_material_bytes(),
            bound.source().maximum_material_bytes()
        );
        assert_eq!(
            bound.descriptor().limits().maximum_resolver_staging_bytes(),
            bound.source().maximum_staging_bytes()
        );
    }

    #[test]
    fn direct_source_binding_uses_the_template_reference() {
        let compiled = compiled();
        let sources = outbound_sources(&compiled.reloadable_plan);
        let plan = UnboundStandaloneGenerationPlan::compile(
            &compiled.reloadable_plan,
            GenerationId::for_test(43),
        )
        .unwrap();

        let global =
            bind_credential_source(&plan.global_credentials()[0], &sources, "credential source")
                .unwrap();
        let rule = bind_credential_source(
            &plan.rules()[0].credentials()[0],
            &sources,
            "rule credential source",
        )
        .unwrap();

        assert_ne!(global.reference(), rule.reference());
        assert_eq!(
            global.reference(),
            plan.global_credentials()[0].mutation().credential()
        );
        assert_eq!(
            rule.reference(),
            plan.rules()[0].credentials()[0].mutation().credential()
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
