#![cfg(test)]

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

use http_access_policy_acl::{
    AclError, DefaultDecision, HeaderPredicate, MatchedEffects, PeerCidr, ProductActionRef, Rule,
    RulePredicates, TrafficPolicySnapshot,
};
use http_access_types::{
    CaptureRef, ContractError, CredentialMutation, CredentialMutationKind, CredentialRef,
    HeaderMutation, HeaderMutationBatch, HeaderMutationCondition, HeaderName as NeutralHeaderName,
    HeaderValue as NeutralHeaderValue, HttpMethod, MutationError, PolicyGeneration, RedactionRef,
    SnapshotIdentity, StableId,
};

use crate::config::compiler::{
    CapturePlan, CompiledCaptureEvent, CompiledDefaultDecision, CompiledHeaderEffectWhen,
    CompiledRuleDecision, CredentialActionPlan, EgressPlan, HeaderEffectPlan, HeaderPredicatesPlan,
    HeaderValuePredicatePlan, HttpBodyReadPlan, ObservationPlan, PolicyPlan, PolicyRulePlan,
};

const ADAPTER_REFERENCE_VERSION: u64 = 1;

#[derive(Clone)]
struct NeutralRuleEffects {
    request_timeout: Option<Duration>,
    allow_upgrades: bool,
    request_headers: Option<HeaderMutationBatch>,
    response_headers: Option<HeaderMutationBatch>,
    redaction: Option<RedactionRef>,
    credentials: Vec<CredentialMutation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NeutralBodyReadPlan {
    Disabled,
    Mandatory {
        max_encoded_bytes: usize,
        max_decoded_bytes: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NeutralCaptureEvent {
    RequestAllowed,
    ResponseAllowed,
    RequestDenied,
    ResponseDenied,
}

struct NeutralCaptureMetadata {
    reference: CaptureRef,
    redaction: RedactionRef,
    events: Vec<NeutralCaptureEvent>,
    max_body_bytes: usize,
    max_inflight_body_bytes: usize,
}

struct CompiledNeutralPolicy {
    snapshot: TrafficPolicySnapshot<NeutralRuleEffects>,
    global_request_headers: Option<HeaderMutationBatch>,
    global_credentials: Vec<CredentialMutation>,
    body_reads_by_cursor: Vec<NeutralBodyReadPlan>,
    capture: Option<NeutralCaptureMetadata>,
}

struct NeutralOutboundEffects {
    request_header_batches: Vec<HeaderMutationBatch>,
    credentials: Vec<CredentialMutation>,
}

impl CompiledNeutralPolicy {
    fn outbound_effects(
        &self,
        matched: &MatchedEffects<NeutralRuleEffects>,
        provider_credentials: Vec<CredentialMutation>,
    ) -> Result<NeutralOutboundEffects, AdapterError> {
        let (rule_request_headers, rule_credentials) = match matched {
            MatchedEffects::Empty => (None, &[][..]),
            MatchedEffects::Rule(rule) => {
                (rule.request_headers.as_ref(), rule.credentials.as_slice())
            }
        };
        validate_credential_stages([
            rule_credentials,
            provider_credentials.as_slice(),
            self.global_credentials.as_slice(),
        ])?;
        let mut request_header_batches = Vec::with_capacity(2);
        request_header_batches.extend(rule_request_headers.cloned());
        request_header_batches.extend(self.global_request_headers.iter().cloned());
        let mut credentials = Vec::with_capacity(
            rule_credentials.len() + provider_credentials.len() + self.global_credentials.len(),
        );
        credentials.extend_from_slice(rule_credentials);
        credentials.extend(provider_credentials);
        credentials.extend(self.global_credentials.iter().cloned());
        validate_batch_credential_destinations(&request_header_batches, &credentials)?;
        Ok(NeutralOutboundEffects {
            request_header_batches,
            credentials,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdapterError {
    InvalidPlan,
    SharedBound,
    InvalidCheckedValue,
    MutationInvalidShape,
    MutationForbiddenHeader,
    MutationInvalidValue,
}

fn compile_neutral_policy(
    plan: &PolicyPlan,
    egress: &EgressPlan,
    observation: &ObservationPlan,
    generation: PolicyGeneration,
    identity: SnapshotIdentity,
    sensitive_headers: &[http::HeaderName],
) -> Result<CompiledNeutralPolicy, AdapterError> {
    let body_reads_by_cursor = compile_body_reads(plan)?;
    let capture = observation
        .capture
        .as_ref()
        .map(|capture| compile_capture(capture, &identity))
        .transpose()?;
    let mut neutral_sensitive = sensitive_headers
        .iter()
        .map(neutral_header_name)
        .collect::<Result<Vec<_>, _>>()?;
    neutral_sensitive.sort();
    neutral_sensitive.dedup();

    let global_credentials = egress
        .credential_actions
        .iter()
        .map(|action| compile_credential(action, &identity))
        .collect::<Result<Vec<_>, _>>()?;
    validate_credential_stages([global_credentials.as_slice()])?;
    let mut configured_credential_destinations = global_credentials
        .iter()
        .map(|credential| credential_destination(credential).to_owned())
        .collect::<BTreeSet<_>>();
    let mut rules = Vec::with_capacity(plan.rules.len());
    for rule in &plan.rules {
        let rule_credentials = rule
            .credential_actions
            .iter()
            .map(|action| compile_credential(action, &identity))
            .collect::<Result<Vec<_>, _>>()?;
        validate_credential_stages([rule_credentials.as_slice(), global_credentials.as_slice()])?;
        configured_credential_destinations.extend(
            rule_credentials
                .iter()
                .map(|credential| credential_destination(credential).to_owned()),
        );
        rules.push(compile_rule(rule, &identity)?);
    }
    validate_effect_credential_destinations(
        &egress.request_headers,
        &configured_credential_destinations,
    )?;
    for rule in &plan.rules {
        validate_effect_credential_destinations(
            &rule.request_headers,
            &configured_credential_destinations,
        )?;
        validate_effect_credential_destinations(
            &rule.response_headers,
            &configured_credential_destinations,
        )?;
    }
    let snapshot = TrafficPolicySnapshot::new(
        generation,
        identity.clone(),
        match plan.default {
            CompiledDefaultDecision::Allow => DefaultDecision::Allow,
            CompiledDefaultDecision::Deny => DefaultDecision::Deny,
        },
        neutral_sensitive,
        rules,
    )
    .map_err(map_acl_error)?;
    Ok(CompiledNeutralPolicy {
        snapshot,
        global_request_headers: compile_header_batch(&egress.request_headers)?,
        global_credentials,
        body_reads_by_cursor,
        capture,
    })
}

fn compile_rule(
    rule: &PolicyRulePlan,
    identity: &SnapshotIdentity,
) -> Result<Rule<NeutralRuleEffects>, AdapterError> {
    let id = stable_id(&rule.id)?;
    let predicates = compile_predicates(rule)?;
    match rule.decision {
        CompiledRuleDecision::Allow => Ok(Rule::allow(
            id,
            predicates,
            compile_effects(rule, identity)?,
        )),
        CompiledRuleDecision::Deny => {
            if rule.authorization_provider.is_some()
                || rule.redaction_profile.is_some()
                || !rule.request_headers.is_empty()
                || !rule.response_headers.is_empty()
                || !rule.credential_actions.is_empty()
                || rule.allow_upgrades
            {
                return Err(AdapterError::InvalidPlan);
            }
            Ok(Rule::deny(id, predicates))
        }
        CompiledRuleDecision::Delegate => {
            let provider = rule
                .authorization_provider
                .as_deref()
                .ok_or(AdapterError::InvalidPlan)?;
            let action = ProductActionRef::new(identity, stable_id(provider)?);
            Ok(Rule::delegate(
                id,
                predicates,
                action,
                compile_effects(rule, identity)?,
            ))
        }
    }
}

fn compile_predicates(rule: &PolicyRulePlan) -> Result<RulePredicates, AdapterError> {
    let urls = rule.urls.clone();
    let methods = rule
        .methods
        .iter()
        .map(|method| {
            HttpMethod::new(method.as_str().to_owned())
                .map_err(|_| AdapterError::InvalidCheckedValue)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let peers = rule
        .client_cidrs
        .iter()
        .map(|network| PeerCidr::new(network.network(), network.prefix_len()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_acl_error)?;
    let headers = compile_header_predicates(&rule.headers)?;
    RulePredicates::new(urls, methods, peers, headers).map_err(map_acl_error)
}

fn compile_header_predicates(
    plan: &HeaderPredicatesPlan,
) -> Result<Vec<HeaderPredicate>, AdapterError> {
    let mut predicates = Vec::with_capacity(
        usize::from(!plan.absent_any.is_empty())
            + plan.present_all.len()
            + plan.all.len()
            + plan.none.len(),
    );
    if !plan.absent_any.is_empty() {
        predicates.push(
            HeaderPredicate::absent_any(
                plan.absent_any
                    .iter()
                    .map(neutral_header_name)
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .map_err(map_acl_error)?,
        );
    }
    predicates.extend(
        plan.present_all
            .iter()
            .map(neutral_header_name)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(HeaderPredicate::present),
    );
    for predicate in &plan.all {
        predicates.push(compile_value_predicate(predicate, true)?);
    }
    for predicate in &plan.none {
        predicates.push(compile_value_predicate(predicate, false)?);
    }
    Ok(predicates)
}

fn compile_value_predicate(
    plan: &HeaderValuePredicatePlan,
    any: bool,
) -> Result<HeaderPredicate, AdapterError> {
    let name = neutral_header_name(&plan.name)?;
    let values = plan
        .values
        .iter()
        .map(neutral_header_value)
        .collect::<Result<Vec<_>, _>>()?;
    if any {
        HeaderPredicate::any_value(name, values).map_err(map_acl_error)
    } else {
        HeaderPredicate::no_values(name, values).map_err(map_acl_error)
    }
}

fn compile_effects(
    rule: &PolicyRulePlan,
    identity: &SnapshotIdentity,
) -> Result<NeutralRuleEffects, AdapterError> {
    Ok(NeutralRuleEffects {
        request_timeout: rule.request_timeout,
        allow_upgrades: rule.allow_upgrades,
        request_headers: compile_header_batch(&rule.request_headers)?,
        response_headers: compile_header_batch(&rule.response_headers)?,
        redaction: rule
            .redaction_profile
            .as_deref()
            .map(|name| {
                RedactionRef::new(
                    identity.clone(),
                    stable_id(name)?,
                    ADAPTER_REFERENCE_VERSION,
                )
                .map_err(map_contract_error)
            })
            .transpose()?,
        credentials: rule
            .credential_actions
            .iter()
            .map(|action| compile_credential(action, identity))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn compile_header_batch(
    plans: &[HeaderEffectPlan],
) -> Result<Option<HeaderMutationBatch>, AdapterError> {
    let mutations = plans
        .iter()
        .map(compile_header_mutation)
        .collect::<Result<Vec<_>, _>>()?;
    if mutations.is_empty() {
        Ok(None)
    } else {
        HeaderMutationBatch::new(mutations)
            .map(Some)
            .map_err(map_mutation_error)
    }
}

fn compile_header_mutation(plan: &HeaderEffectPlan) -> Result<HeaderMutation, AdapterError> {
    match plan {
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
    .map_err(map_mutation_error)
}

const fn mutation_condition(value: CompiledHeaderEffectWhen) -> HeaderMutationCondition {
    match value {
        CompiledHeaderEffectWhen::Always => HeaderMutationCondition::Always,
        CompiledHeaderEffectWhen::IfPresent => HeaderMutationCondition::IfPresent,
        CompiledHeaderEffectWhen::IfAbsent => HeaderMutationCondition::IfAbsent,
    }
}

fn compile_credential(
    action: &CredentialActionPlan,
    identity: &SnapshotIdentity,
) -> Result<CredentialMutation, AdapterError> {
    match action {
        CredentialActionPlan::Bearer { credential } => Ok(CredentialMutation::bearer(
            credential_ref(identity, credential)?,
        )),
        CredentialActionPlan::Basic {
            username,
            password_credential,
        } => CredentialMutation::basic(
            username.clone(),
            credential_ref(identity, password_credential)?,
        )
        .map_err(map_contract_error),
        CredentialActionPlan::CustomHeader { header, credential } => {
            CredentialMutation::custom_header(
                neutral_header_name(header)?,
                credential_ref(identity, credential)?,
            )
            .map_err(map_contract_error)
        }
    }
}

fn credential_ref(identity: &SnapshotIdentity, name: &str) -> Result<CredentialRef, AdapterError> {
    CredentialRef::new(
        identity.clone(),
        stable_id(name)?,
        ADAPTER_REFERENCE_VERSION,
    )
    .map_err(map_contract_error)
}

fn validate_credential_stages<'a>(
    stages: impl IntoIterator<Item = &'a [CredentialMutation]>,
) -> Result<(), AdapterError> {
    let mut destinations = BTreeSet::new();
    for credential in stages.into_iter().flatten() {
        if !destinations.insert(credential_destination(credential)) {
            return Err(AdapterError::InvalidPlan);
        }
    }
    Ok(())
}

fn credential_destination(credential: &CredentialMutation) -> &str {
    match credential.kind() {
        CredentialMutationKind::Bearer(_) | CredentialMutationKind::Basic { .. } => "authorization",
        CredentialMutationKind::CustomHeader { name, .. } => name.as_str(),
    }
}

fn validate_effect_credential_destinations(
    effects: &[HeaderEffectPlan],
    credential_destinations: &BTreeSet<String>,
) -> Result<(), AdapterError> {
    if effects.iter().any(|effect| {
        credential_destinations.contains(match effect {
            HeaderEffectPlan::Set { name, .. }
            | HeaderEffectPlan::Append { name, .. }
            | HeaderEffectPlan::Remove { name, .. }
            | HeaderEffectPlan::Replace { name, .. } => name.as_str(),
        })
    }) {
        return Err(AdapterError::InvalidPlan);
    }
    Ok(())
}

fn validate_batch_credential_destinations(
    batches: &[HeaderMutationBatch],
    credentials: &[CredentialMutation],
) -> Result<(), AdapterError> {
    if batches.iter().any(|batch| {
        batch.mutations().iter().any(|mutation| {
            credentials
                .iter()
                .any(|credential| mutation.name().as_str() == credential_destination(credential))
        })
    }) {
        return Err(AdapterError::InvalidPlan);
    }
    Ok(())
}

fn compile_body_reads(plan: &PolicyPlan) -> Result<Vec<NeutralBodyReadPlan>, AdapterError> {
    if plan.http_body_read_plans_by_cursor.len() != plan.rules.len() + 1 {
        return Err(AdapterError::InvalidPlan);
    }
    Ok(plan
        .http_body_read_plans_by_cursor
        .iter()
        .map(|plan| match plan {
            HttpBodyReadPlan::Disabled => NeutralBodyReadPlan::Disabled,
            HttpBodyReadPlan::Mandatory(limits) => NeutralBodyReadPlan::Mandatory {
                max_encoded_bytes: limits.max_encoded_bytes(),
                max_decoded_bytes: limits.max_decoded_bytes(),
            },
        })
        .collect())
}

fn compile_capture(
    capture: &CapturePlan,
    identity: &SnapshotIdentity,
) -> Result<NeutralCaptureMetadata, AdapterError> {
    let redaction_id = stable_id(&capture.redaction_profile)?;
    Ok(NeutralCaptureMetadata {
        reference: CaptureRef::new(
            identity.clone(),
            stable_id("observation.capture")?,
            ADAPTER_REFERENCE_VERSION,
        )
        .map_err(map_contract_error)?,
        redaction: RedactionRef::new(identity.clone(), redaction_id, ADAPTER_REFERENCE_VERSION)
            .map_err(map_contract_error)?,
        events: capture
            .events
            .iter()
            .map(|event| match event {
                CompiledCaptureEvent::RequestAllowed => NeutralCaptureEvent::RequestAllowed,
                CompiledCaptureEvent::ResponseAllowed => NeutralCaptureEvent::ResponseAllowed,
                CompiledCaptureEvent::RequestDenied => NeutralCaptureEvent::RequestDenied,
                CompiledCaptureEvent::ResponseDenied => NeutralCaptureEvent::ResponseDenied,
            })
            .collect(),
        max_body_bytes: capture.max_body_bytes,
        max_inflight_body_bytes: capture.max_inflight_body_bytes,
    })
}

fn neutral_header_name(value: &http::HeaderName) -> Result<NeutralHeaderName, AdapterError> {
    NeutralHeaderName::new(value.as_str().to_owned()).map_err(|_| AdapterError::InvalidCheckedValue)
}

fn neutral_header_value(value: &http::HeaderValue) -> Result<NeutralHeaderValue, AdapterError> {
    NeutralHeaderValue::new(value.as_bytes().to_vec())
        .map_err(|_| AdapterError::InvalidCheckedValue)
}

fn stable_id(value: &str) -> Result<StableId, AdapterError> {
    StableId::new(value.to_owned()).map_err(map_contract_error)
}

const fn map_acl_error(error: AclError) -> AdapterError {
    match error {
        AclError::InvalidCollection => AdapterError::SharedBound,
        AclError::InvalidPredicate | AclError::ForeignSnapshot | AclError::InputBindingMismatch => {
            AdapterError::InvalidCheckedValue
        }
        _ => AdapterError::InvalidCheckedValue,
    }
}

const fn map_contract_error(_error: ContractError) -> AdapterError {
    AdapterError::InvalidCheckedValue
}

const fn map_mutation_error(error: MutationError) -> AdapterError {
    match error {
        MutationError::LimitExceeded => AdapterError::SharedBound,
        MutationError::InvalidShape => AdapterError::MutationInvalidShape,
        MutationError::ForbiddenHeader => AdapterError::MutationForbiddenHeader,
        MutationError::InvalidValue => AdapterError::MutationInvalidValue,
        _ => AdapterError::InvalidCheckedValue,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use http::{HeaderName, HeaderValue, Method};
    use http_access_conformance::{
        load_cursor_scenario_suite, load_header_mutation_suite, load_request_binding_suite,
        CursorScenarioCase, CursorScenarioOutcome, FixtureBodyFraming, FixtureBodyObservation,
        FixtureBodyRepresentation, FixtureCursorError, FixtureEffectivePolicy, FixtureHeaderField,
        FixtureHeaderMutation, FixtureHttpVersion, FixtureIngressMode, FixtureMutationCondition,
        FixtureMutationError, FixtureMutationOperation, FixturePolicyDecision,
        FixtureRequestBindingInput, FixtureUpgrade, HeaderMutationOutcome,
    };
    use http_access_policy_acl::{
        AclError, EvaluationInput, PolicyEvaluation, ProviderDisposition,
    };
    use http_access_types::{
        BodyFraming, BodyMetadata, BodyObservation, BodyRepresentation, EffectivePolicy,
        HeaderField, HttpVersion, IngressMode, InterceptedRequestFacts, PolicyHeaderFacts,
        UpgradeIntent, UpgradeProtocol,
    };
    use http_access_url::{canonicalize_http_url, CompiledUrlPattern};

    use super::*;
    use crate::capture::CaptureSinkSpec;
    use crate::config::compiler::{
        CaptureWorkingSetPlan, CompiledEgressRoute, CompiledHttpVersion, CompiledTlsTrust,
        HttpBodyReadLimits, TransportTlsPlan,
    };

    fn product_name(value: &'static str) -> HeaderName {
        HeaderName::from_static(value)
    }

    fn product_value(value: &'static str) -> HeaderValue {
        HeaderValue::from_static(value)
    }

    fn header_predicates() -> HeaderPredicatesPlan {
        HeaderPredicatesPlan {
            absent_any: vec![product_name("x-present"), product_name("x-absent")],
            present_all: vec![product_name("x-present"), product_name("x-sensitive")],
            all: vec![HeaderValuePredicatePlan {
                name: product_name("x-environment"),
                values: vec![product_value("stage"), product_value("prod")],
            }],
            none: vec![HeaderValuePredicatePlan {
                name: product_name("x-block"),
                values: vec![product_value("deny"), product_value("blocked")],
            }],
        }
    }

    fn request_effects() -> Vec<HeaderEffectPlan> {
        vec![
            HeaderEffectPlan::Set {
                when: CompiledHeaderEffectWhen::Always,
                name: product_name("x-mutation-order"),
                values: vec![product_value("rule")],
            },
            HeaderEffectPlan::Set {
                when: CompiledHeaderEffectWhen::IfAbsent,
                name: product_name("x-set"),
                values: vec![product_value("new")],
            },
            HeaderEffectPlan::Append {
                when: CompiledHeaderEffectWhen::Always,
                name: product_name("x-list"),
                values: vec![product_value("b")],
            },
            HeaderEffectPlan::Replace {
                when: CompiledHeaderEffectWhen::IfPresent,
                name: product_name("x-replace"),
                search: "old".to_owned(),
                replace: "new".to_owned(),
            },
            HeaderEffectPlan::Remove {
                when: CompiledHeaderEffectWhen::IfPresent,
                name: product_name("x-remove"),
            },
        ]
    }

    fn delegate_rule() -> PolicyRulePlan {
        PolicyRulePlan {
            id: "delegate-rule".to_owned(),
            description: Some("adapter exercise".to_owned()),
            decision: CompiledRuleDecision::Delegate,
            urls: vec![
                CompiledUrlPattern::compile("https://unrelated.test/**").unwrap(),
                CompiledUrlPattern::compile("https://*.example.test/app/**").unwrap(),
            ],
            methods: vec![Method::GET, Method::POST],
            client_cidrs: vec![
                "198.51.100.0/24".parse().unwrap(),
                "192.0.2.0/24".parse().unwrap(),
            ],
            headers: header_predicates(),
            request_timeout: Some(Duration::from_secs(17)),
            allow_upgrades: true,
            authorization_provider: Some("approval-provider".to_owned()),
            redaction_profile: Some("wire-redaction".to_owned()),
            request_headers: request_effects(),
            response_headers: vec![HeaderEffectPlan::Remove {
                when: CompiledHeaderEffectWhen::Always,
                name: product_name("x-internal"),
            }],
            credential_actions: vec![
                CredentialActionPlan::Bearer {
                    credential: "bearer-token".to_owned(),
                },
                CredentialActionPlan::CustomHeader {
                    header: product_name("x-api-key"),
                    credential: "api-key".to_owned(),
                },
            ],
        }
    }

    fn simple_rule(id: &str, decision: CompiledRuleDecision, url: &str) -> PolicyRulePlan {
        PolicyRulePlan {
            id: id.to_owned(),
            description: None,
            decision,
            urls: vec![CompiledUrlPattern::compile(url).unwrap()],
            methods: vec![],
            client_cidrs: vec![],
            headers: HeaderPredicatesPlan {
                absent_any: vec![],
                present_all: vec![],
                all: vec![],
                none: vec![],
            },
            request_timeout: None,
            allow_upgrades: false,
            authorization_provider: None,
            redaction_profile: None,
            request_headers: vec![],
            response_headers: vec![],
            credential_actions: vec![],
        }
    }

    fn product_plan() -> PolicyPlan {
        PolicyPlan {
            default: CompiledDefaultDecision::Allow,
            rules: vec![
                delegate_rule(),
                simple_rule(
                    "deny-rule",
                    CompiledRuleDecision::Deny,
                    "https://example.test/denied",
                ),
                simple_rule(
                    "allow-rule",
                    CompiledRuleDecision::Allow,
                    "https://example.test/allowed",
                ),
            ],
            http_body_read_plans_by_cursor: vec![
                HttpBodyReadPlan::Mandatory(HttpBodyReadLimits::try_new(1024, 2048).unwrap()),
                HttpBodyReadPlan::Disabled,
                HttpBodyReadPlan::Disabled,
                HttpBodyReadPlan::Disabled,
            ],
        }
    }

    fn product_egress_plan() -> EgressPlan {
        EgressPlan {
            route: CompiledEgressRoute::Direct,
            origin_tls: TransportTlsPlan {
                trust: CompiledTlsTrust::System,
                ca_certificate: None,
                http_versions: vec![CompiledHttpVersion::Http1, CompiledHttpVersion::Http2],
            },
            parent_proxy: None,
            request_headers: vec![
                HeaderEffectPlan::Append {
                    when: CompiledHeaderEffectWhen::Always,
                    name: product_name("x-list"),
                    values: vec![product_value("global")],
                },
                HeaderEffectPlan::Set {
                    when: CompiledHeaderEffectWhen::Always,
                    name: product_name("x-mutation-order"),
                    values: vec![product_value("global")],
                },
            ],
            credential_actions: vec![CredentialActionPlan::CustomHeader {
                header: product_name("x-global-token"),
                credential: "global-token".to_owned(),
            }],
        }
    }

    fn provider_credentials(identity: &SnapshotIdentity) -> Vec<CredentialMutation> {
        vec![compile_credential(
            &CredentialActionPlan::CustomHeader {
                header: product_name("x-provider-token"),
                credential: "provider-token".to_owned(),
            },
            identity,
        )
        .unwrap()]
    }

    fn observation_plan() -> ObservationPlan {
        ObservationPlan {
            capture: Some(CapturePlan {
                events: vec![
                    CompiledCaptureEvent::RequestAllowed,
                    CompiledCaptureEvent::RequestDenied,
                ],
                redaction_profile: "capture-redaction".to_owned(),
                sink: CaptureSinkSpec::new(
                    PathBuf::from("captures"),
                    "{requestId}-{suffix}.json".to_owned(),
                    10,
                    1024 * 1024,
                )
                .unwrap(),
                max_body_bytes: 4096,
                max_inflight_body_bytes: 8192,
                working_set: CaptureWorkingSetPlan::default(),
            }),
        }
    }

    fn facts(url: &str, method: &str) -> InterceptedRequestFacts {
        let headers = vec![
            HeaderField::new(
                NeutralHeaderName::new("x-environment").unwrap(),
                NeutralHeaderValue::new(b"prod".to_vec()).unwrap(),
            ),
            HeaderField::new(
                NeutralHeaderName::new("x-present").unwrap(),
                NeutralHeaderValue::new(b"yes".to_vec()).unwrap(),
            ),
        ];
        InterceptedRequestFacts::new(
            IngressMode::ExplicitHttps,
            HttpVersion::Http11,
            HttpMethod::new(method).unwrap(),
            canonicalize_http_url(url).unwrap(),
            headers,
            BodyMetadata::new(BodyFraming::None),
            None,
        )
        .unwrap()
    }

    fn evaluation_input<'a>(
        facts: &'a InterceptedRequestFacts,
        sensitive: &'a [NeutralHeaderName],
    ) -> http_access_policy_acl::EvaluationInput<'a> {
        let mut raw_headers = facts.headers().to_vec();
        raw_headers.extend(sensitive.iter().cloned().map(|name| {
            HeaderField::new(name, NeutralHeaderValue::new(b"hidden".to_vec()).unwrap())
        }));
        raw_headers.sort_by(|left, right| left.name().cmp(right.name()));
        let header_facts = PolicyHeaderFacts::new(raw_headers, sensitive.to_vec()).unwrap();
        http_access_policy_acl::EvaluationInput::new(
            facts,
            "192.0.2.44".parse::<IpAddr>().unwrap(),
            header_facts,
            7,
            BodyRepresentation::PreservedContentCoded,
            BodyObservation::unobserved(),
        )
        .unwrap()
    }

    #[test]
    fn complete_product_plan_compiles_and_evaluates_at_neutral_boundary() {
        let plan = product_plan();
        let identity = SnapshotIdentity::new();
        let compiled = compile_neutral_policy(
            &plan,
            &product_egress_plan(),
            &observation_plan(),
            PolicyGeneration::new(41).unwrap(),
            identity.clone(),
            &[product_name("x-sensitive")],
        )
        .unwrap();
        let request_facts = facts("https://service.example.test/app/resource", "POST");
        let sensitive = vec![NeutralHeaderName::new("x-sensitive").unwrap()];
        let input = evaluation_input(&request_facts, &sensitive);

        let PolicyEvaluation::Delegate(delegated) = compiled.snapshot.evaluate(&input).unwrap()
        else {
            panic!("expected delegated product rule")
        };
        assert_eq!(delegated.action().id().as_str(), "approval-provider");
        let resolved = compiled
            .snapshot
            .resolve_delegate(delegated, ProviderDisposition::Allow, &input)
            .unwrap();
        let PolicyEvaluation::Allow { effects, .. } = resolved else {
            panic!("expected provider allow effects")
        };
        let outbound = compiled
            .outbound_effects(&effects, provider_credentials(&identity))
            .unwrap();
        let MatchedEffects::Rule(effects) = &effects else {
            panic!("expected rule effects")
        };
        assert_eq!(effects.request_timeout, Some(Duration::from_secs(17)));
        assert!(effects.allow_upgrades);
        assert_eq!(
            effects
                .request_headers
                .as_ref()
                .map(HeaderMutationBatch::mutations)
                .map(<[_]>::len),
            Some(5)
        );
        assert_eq!(
            effects
                .response_headers
                .as_ref()
                .map(HeaderMutationBatch::mutations)
                .map(<[_]>::len),
            Some(1)
        );
        assert!(effects
            .redaction
            .as_ref()
            .is_some_and(|reference| reference.belongs_to(&identity)
                && reference.id().as_str() == "wire-redaction"));
        assert!(matches!(
            effects.credentials[0].kind(),
            CredentialMutationKind::Bearer(reference)
                if reference.id().as_str() == "bearer-token"
        ));
        assert!(matches!(
            effects.credentials[1].kind(),
            CredentialMutationKind::CustomHeader { name, credential }
                if name.as_str() == "x-api-key" && credential.id().as_str() == "api-key"
        ));
        assert_eq!(outbound.request_header_batches.len(), 2);
        assert_eq!(
            outbound
                .request_header_batches
                .iter()
                .map(|batch| batch.mutations().len())
                .sum::<usize>(),
            7
        );
        assert_eq!(outbound.credentials.len(), 4);
        assert!(matches!(
            outbound.credentials[0].kind(),
            CredentialMutationKind::Bearer(reference)
                if reference.id().as_str() == "bearer-token"
        ));
        assert!(matches!(
            outbound.credentials[1].kind(),
            CredentialMutationKind::CustomHeader { name, credential }
                if name.as_str() == "x-api-key" && credential.id().as_str() == "api-key"
        ));
        assert!(matches!(
            outbound.credentials[2].kind(),
            CredentialMutationKind::CustomHeader { name, credential }
                if name.as_str() == "x-provider-token"
                    && credential.id().as_str() == "provider-token"
        ));
        assert!(matches!(
            outbound.credentials[3].kind(),
            CredentialMutationKind::CustomHeader { name, credential }
                if name.as_str() == "x-global-token"
                    && credential.id().as_str() == "global-token"
        ));
        assert_eq!(
            compiled.body_reads_by_cursor[0],
            NeutralBodyReadPlan::Mandatory {
                max_encoded_bytes: 1024,
                max_decoded_bytes: 2048,
            }
        );
        let capture = compiled.capture.as_ref().unwrap();
        assert!(capture.reference.belongs_to(&identity));
        assert_eq!(capture.reference.id().as_str(), "observation.capture");
        assert_eq!(capture.redaction.id().as_str(), "capture-redaction");
        assert_eq!(
            capture.events,
            vec![
                NeutralCaptureEvent::RequestAllowed,
                NeutralCaptureEvent::RequestDenied,
            ]
        );
        assert_eq!(capture.max_body_bytes, 4096);
        assert_eq!(capture.max_inflight_body_bytes, 8192);
    }

    #[test]
    fn deny_allow_and_default_decisions_preserve_product_order() {
        let compiled = compile_neutral_policy(
            &product_plan(),
            &product_egress_plan(),
            &ObservationPlan { capture: None },
            PolicyGeneration::new(42).unwrap(),
            SnapshotIdentity::new(),
            &[product_name("x-sensitive")],
        )
        .unwrap();
        let sensitive = vec![NeutralHeaderName::new("x-sensitive").unwrap()];

        let denied_facts = facts("https://example.test/denied", "GET");
        assert!(matches!(
            compiled
                .snapshot
                .evaluate(&evaluation_input(&denied_facts, &sensitive))
                .unwrap(),
            PolicyEvaluation::Deny { .. }
        ));
        let allowed_facts = facts("https://example.test/allowed", "GET");
        let PolicyEvaluation::Allow { effects, .. } = compiled
            .snapshot
            .evaluate(&evaluation_input(&allowed_facts, &sensitive))
            .unwrap()
        else {
            panic!("expected rule allow")
        };
        assert!(matches!(effects, MatchedEffects::Rule(_)));
        let rule_outbound = compiled.outbound_effects(&effects, Vec::new()).unwrap();
        assert_eq!(rule_outbound.request_header_batches.len(), 1);
        assert_eq!(rule_outbound.request_header_batches[0].mutations().len(), 2);
        assert_eq!(rule_outbound.credentials.len(), 1);
        let default_facts = facts("https://example.test/other", "GET");
        let PolicyEvaluation::Allow { effects, .. } = compiled
            .snapshot
            .evaluate(&evaluation_input(&default_facts, &sensitive))
            .unwrap()
        else {
            panic!("expected default allow")
        };
        assert!(matches!(effects, MatchedEffects::Empty));
        let default_outbound = compiled.outbound_effects(&effects, Vec::new()).unwrap();
        assert_eq!(default_outbound.request_header_batches.len(), 1);
        assert_eq!(
            default_outbound.request_header_batches[0].mutations().len(),
            2
        );
        assert_eq!(default_outbound.credentials.len(), 1);
        assert!(matches!(
            default_outbound.credentials[0].kind(),
            CredentialMutationKind::CustomHeader { name, credential }
                if name.as_str() == "x-global-token"
                    && credential.id().as_str() == "global-token"
        ));
    }

    fn fixture_effect(mutation: &FixtureHeaderMutation) -> Result<HeaderEffectPlan, AdapterError> {
        let name = HeaderName::from_bytes(mutation.name.as_bytes())
            .map_err(|_| AdapterError::InvalidCheckedValue)?;
        let when = match mutation.condition {
            FixtureMutationCondition::Always => CompiledHeaderEffectWhen::Always,
            FixtureMutationCondition::IfPresent => CompiledHeaderEffectWhen::IfPresent,
            FixtureMutationCondition::IfAbsent => CompiledHeaderEffectWhen::IfAbsent,
        };
        let values = mutation
            .values_hex
            .iter()
            .map(|value| {
                HeaderValue::from_bytes(value.as_bytes())
                    .map_err(|_| AdapterError::MutationInvalidValue)
            })
            .collect::<Result<Vec<_>, _>>()?;
        match mutation.operation {
            FixtureMutationOperation::Set => Ok(HeaderEffectPlan::Set { when, name, values }),
            FixtureMutationOperation::Append => Ok(HeaderEffectPlan::Append { when, name, values }),
            FixtureMutationOperation::Remove => Ok(HeaderEffectPlan::Remove { when, name }),
            FixtureMutationOperation::Replace => {
                let search = mutation
                    .search_hex
                    .as_ref()
                    .ok_or(AdapterError::MutationInvalidShape)?;
                let replacement = mutation
                    .replacement_hex
                    .as_ref()
                    .ok_or(AdapterError::MutationInvalidShape)?;
                Ok(HeaderEffectPlan::Replace {
                    when,
                    name,
                    search: std::str::from_utf8(search.as_bytes())
                        .map_err(|_| AdapterError::MutationInvalidValue)?
                        .to_owned(),
                    replace: std::str::from_utf8(replacement.as_bytes())
                        .map_err(|_| AdapterError::MutationInvalidValue)?
                        .to_owned(),
                })
            }
        }
    }

    fn neutral_fixture_headers(fields: &[FixtureHeaderField]) -> Vec<HeaderField> {
        fields
            .iter()
            .map(|field| {
                HeaderField::new(
                    NeutralHeaderName::new(field.name.clone()).unwrap(),
                    NeutralHeaderValue::new(field.value_hex.as_bytes().to_vec()).unwrap(),
                )
            })
            .collect()
    }

    fn fixture_pairs(fields: &[FixtureHeaderField]) -> Vec<(String, Vec<u8>)> {
        fields
            .iter()
            .map(|field| (field.name.clone(), field.value_hex.as_bytes().to_vec()))
            .collect()
    }

    const fn fixture_mutation_error(error: AdapterError) -> Option<FixtureMutationError> {
        match error {
            AdapterError::SharedBound => Some(FixtureMutationError::LimitExceeded),
            AdapterError::MutationInvalidShape => Some(FixtureMutationError::InvalidShape),
            AdapterError::MutationForbiddenHeader => Some(FixtureMutationError::ForbiddenHeader),
            AdapterError::MutationInvalidValue => Some(FixtureMutationError::InvalidValue),
            AdapterError::InvalidPlan | AdapterError::InvalidCheckedValue => None,
        }
    }

    #[test]
    fn shared_mutation_fixtures_execute_through_the_product_adapter() {
        for case in load_header_mutation_suite().unwrap().into_cases() {
            let effects = case
                .mutations
                .iter()
                .map(fixture_effect)
                .collect::<Result<Vec<_>, _>>();
            let compiled = effects
                .as_ref()
                .map_err(|error| *error)
                .and_then(|effects| compile_header_batch(effects));

            match (&case.expected, effects, compiled) {
                (HeaderMutationOutcome::Accepted { fields }, Ok(_), Ok(Some(batch))) => {
                    let neutral = http_access_types::apply_header_mutation_batches(
                        &neutral_fixture_headers(&case.initial),
                        &[batch],
                    )
                    .unwrap();
                    assert_eq!(
                        neutral_pairs(&neutral),
                        fixture_pairs(fields),
                        "{}",
                        case.id
                    );
                }
                (HeaderMutationOutcome::Rejected { error }, _, Err(actual)) => {
                    assert_eq!(fixture_mutation_error(actual), Some(*error), "{}", case.id);
                }
                (expected, _, _) => {
                    panic!("{}: unexpected adapter result for {expected:?}", case.id)
                }
            }
        }
    }

    fn cursor_rule(
        id: &str,
        decision: FixturePolicyDecision,
        url: &str,
        matches: bool,
    ) -> PolicyRulePlan {
        let decision = match decision {
            FixturePolicyDecision::Allow => CompiledRuleDecision::Allow,
            FixturePolicyDecision::Deny => CompiledRuleDecision::Deny,
            FixturePolicyDecision::Delegate => CompiledRuleDecision::Delegate,
        };
        let mut rule = simple_rule(
            id,
            decision,
            if matches {
                url
            } else {
                "https://cursor-nonmatch.test/**"
            },
        );
        if decision == CompiledRuleDecision::Delegate {
            rule.authorization_provider = Some(format!("provider-{id}"));
        }
        rule
    }

    fn cursor_source_plan(case: &CursorScenarioCase, url: &str) -> Option<PolicyPlan> {
        let delegate_ordinal = case.cursor.next_ordinal.checked_sub(1)?;
        let rules = (0..case.cursor.next_ordinal)
            .map(|ordinal| {
                if ordinal == delegate_ordinal {
                    cursor_rule(
                        &format!("cursor-source-{ordinal}"),
                        FixturePolicyDecision::Delegate,
                        url,
                        true,
                    )
                } else {
                    cursor_rule(
                        &format!("cursor-source-{ordinal}"),
                        FixturePolicyDecision::Deny,
                        url,
                        false,
                    )
                }
            })
            .collect::<Vec<_>>();
        Some(PolicyPlan {
            default: CompiledDefaultDecision::Deny,
            http_body_read_plans_by_cursor: vec![HttpBodyReadPlan::Disabled; rules.len() + 1],
            rules,
        })
    }

    fn cursor_selected_plan(case: &CursorScenarioCase, url: &str) -> PolicyPlan {
        let rule_count = case
            .snapshot
            .rules
            .iter()
            .map(|rule| rule.ordinal as usize + 1)
            .max()
            .unwrap_or(0);
        let rules = (0..rule_count)
            .map(|ordinal| {
                let fixture = case
                    .snapshot
                    .rules
                    .iter()
                    .find(|rule| rule.ordinal as usize == ordinal);
                fixture.map_or_else(
                    || {
                        cursor_rule(
                            &format!("cursor-gap-{ordinal}"),
                            FixturePolicyDecision::Deny,
                            url,
                            false,
                        )
                    },
                    |rule| {
                        cursor_rule(
                            &rule.rule_id,
                            rule.decision,
                            url,
                            case.resume.matching_rule_ordinals.contains(&rule.ordinal),
                        )
                    },
                )
            })
            .collect::<Vec<_>>();
        PolicyPlan {
            default: match case.snapshot.default {
                FixturePolicyDecision::Allow => CompiledDefaultDecision::Allow,
                FixturePolicyDecision::Deny => CompiledDefaultDecision::Deny,
                FixturePolicyDecision::Delegate => {
                    panic!("{}: a product snapshot cannot delegate by default", case.id)
                }
            },
            http_body_read_plans_by_cursor: vec![HttpBodyReadPlan::Disabled; rules.len() + 1],
            rules,
        }
    }

    fn fixture_effective_policy(value: &EffectivePolicy) -> FixtureEffectivePolicy {
        match value {
            EffectivePolicy::Default => FixtureEffectivePolicy::Default,
            EffectivePolicy::Rule { id, ordinal } => FixtureEffectivePolicy::Rule {
                rule_id: id.as_str().to_owned(),
                ordinal: *ordinal,
            },
        }
    }

    fn cursor_outcome(evaluation: PolicyEvaluation<NeutralRuleEffects>) -> CursorScenarioOutcome {
        match evaluation {
            PolicyEvaluation::Allow { provenance, .. } => CursorScenarioOutcome::Terminal {
                decision: FixturePolicyDecision::Allow,
                effective_policy: fixture_effective_policy(provenance.effective_policy()),
            },
            PolicyEvaluation::Deny { provenance } => CursorScenarioOutcome::Terminal {
                decision: FixturePolicyDecision::Deny,
                effective_policy: fixture_effective_policy(provenance.effective_policy()),
            },
            PolicyEvaluation::Delegate(delegated) => {
                let EffectivePolicy::Rule { id, ordinal } =
                    delegated.provenance().effective_policy()
                else {
                    panic!("a delegated product decision must identify its rule")
                };
                CursorScenarioOutcome::Delegate {
                    rule_id: id.as_str().to_owned(),
                    ordinal: *ordinal,
                }
            }
        }
    }

    #[test]
    fn shared_cursor_and_generation_fixtures_execute_through_the_product_adapter() {
        for case in load_cursor_scenario_suite().unwrap().into_cases() {
            let url = "https://cursor-product.test/match";
            let source_identity = SnapshotIdentity::new();
            let Some(source_plan) = cursor_source_plan(&case, url) else {
                assert_eq!(
                    case.expected,
                    CursorScenarioOutcome::Rejected {
                        error: FixtureCursorError::InvalidCursor,
                    },
                    "{}",
                    case.id
                );
                continue;
            };
            let source = compile_neutral_policy(
                &source_plan,
                &product_egress_plan(),
                &ObservationPlan { capture: None },
                PolicyGeneration::new(case.cursor.policy_generation).unwrap(),
                source_identity.clone(),
                &[],
            )
            .unwrap();
            let request_facts = facts(url, "GET");
            let input = evaluation_input(&request_facts, &[]);
            let PolicyEvaluation::Delegate(delegated) = source.snapshot.evaluate(&input).unwrap()
            else {
                panic!("{}: source plan did not produce a cursor", case.id)
            };

            let same_snapshot = case.cursor.snapshot_identity == case.snapshot.identity
                && case.resume.snapshot_identity == case.snapshot.identity
                && case.cursor.policy_generation == case.snapshot.policy_generation
                && case.resume.policy_generation == case.snapshot.policy_generation;
            let selected_identity = if same_snapshot {
                source_identity
            } else {
                SnapshotIdentity::new()
            };
            let selected = compile_neutral_policy(
                &cursor_selected_plan(&case, url),
                &product_egress_plan(),
                &ObservationPlan { capture: None },
                PolicyGeneration::new(case.snapshot.policy_generation).unwrap(),
                selected_identity,
                &[],
            )
            .unwrap();
            let actual =
                selected
                    .snapshot
                    .resolve_delegate(delegated, ProviderDisposition::Pass, &input);

            match (&case.expected, actual) {
                (expected, Ok(evaluation)) => {
                    assert_eq!(&cursor_outcome(evaluation), expected, "{}", case.id);
                }
                (
                    CursorScenarioOutcome::Rejected {
                        error: FixtureCursorError::ForeignSnapshot,
                    },
                    Err(AclError::ForeignSnapshot),
                ) => {}
                (
                    CursorScenarioOutcome::Rejected {
                        error: FixtureCursorError::GenerationMismatch,
                    },
                    Err(AclError::ForeignSnapshot),
                ) => {
                    // Product cursors bind the unforgeable snapshot identity. Publishing a
                    // new generation selects a new identity, so this boundary intentionally
                    // sanitizes both descriptive mismatch categories as ForeignSnapshot.
                }
                (expected, _) => {
                    panic!("{}: unexpected product result for {expected:?}", case.id)
                }
            }
        }
    }

    struct FixtureEvaluationParts {
        facts: InterceptedRequestFacts,
        peer_ip: IpAddr,
        header_facts: PolicyHeaderFacts,
        revision: u64,
        body_representation: BodyRepresentation,
        body_observation: BodyObservation,
    }

    fn fixture_evaluation_parts(input: &FixtureRequestBindingInput) -> FixtureEvaluationParts {
        let ingress = match input.ingress_mode {
            FixtureIngressMode::ExplicitHttp => IngressMode::ExplicitHttp,
            FixtureIngressMode::ExplicitHttps => IngressMode::ExplicitHttps,
            FixtureIngressMode::TransparentHttp => IngressMode::TransparentHttp,
            FixtureIngressMode::ConnectMitmInner => IngressMode::ConnectMitmInner,
            FixtureIngressMode::TransparentHttps => IngressMode::TransparentHttps,
        };
        let version = match input.http_version {
            FixtureHttpVersion::Http10 => HttpVersion::Http10,
            FixtureHttpVersion::Http11 => HttpVersion::Http11,
            FixtureHttpVersion::Http2 => HttpVersion::Http2,
        };
        let framing = match input.body_framing {
            FixtureBodyFraming::None => BodyFraming::None,
            FixtureBodyFraming::ContentLength { length } => BodyFraming::ContentLength(length),
            FixtureBodyFraming::Chunked => BodyFraming::Chunked,
            FixtureBodyFraming::Http2Stream => BodyFraming::Http2Stream,
        };
        let upgrade = match &input.upgrade {
            FixtureUpgrade::None => None,
            FixtureUpgrade::Websocket => Some(UpgradeIntent::WebSocket),
            FixtureUpgrade::Other { protocol } => Some(UpgradeIntent::Other(
                UpgradeProtocol::new(protocol.clone()).unwrap(),
            )),
        };
        let ordinary_headers = neutral_fixture_headers(&input.headers);
        let facts = InterceptedRequestFacts::new(
            ingress,
            version,
            HttpMethod::new(input.method.clone()).unwrap(),
            canonicalize_http_url(&input.url).unwrap(),
            ordinary_headers.clone(),
            BodyMetadata::new(framing),
            upgrade,
        )
        .unwrap();
        let sensitive = input
            .sensitive_header_presence
            .iter()
            .map(|name| NeutralHeaderName::new(name.clone()).unwrap())
            .collect::<Vec<_>>();
        let mut raw_headers = ordinary_headers;
        raw_headers.extend(sensitive.iter().cloned().map(|name| {
            HeaderField::new(name, NeutralHeaderValue::new(b"redacted".to_vec()).unwrap())
        }));
        raw_headers.sort_by(|left, right| left.name().cmp(right.name()));
        let header_facts = PolicyHeaderFacts::new(raw_headers, sensitive).unwrap();
        let body_representation = match input.body_representation {
            FixtureBodyRepresentation::PreservedContentCoded => {
                BodyRepresentation::PreservedContentCoded
            }
            FixtureBodyRepresentation::CanonicalIdentity => BodyRepresentation::CanonicalIdentity,
        };
        let body_observation = match &input.body_observation {
            FixtureBodyObservation::Unobserved => BodyObservation::unobserved(),
            FixtureBodyObservation::Complete { body_hex } => {
                BodyObservation::complete(body_hex.as_bytes())
            }
            FixtureBodyObservation::Partial { .. } => {
                panic!("partial bodies belong to the request-body-state suite")
            }
        };
        FixtureEvaluationParts {
            facts,
            peer_ip: input.peer_ip.parse().unwrap(),
            header_facts,
            revision: input.revision,
            body_representation,
            body_observation,
        }
    }

    fn fixture_input(parts: &FixtureEvaluationParts, revision: u64) -> EvaluationInput<'_> {
        EvaluationInput::new(
            &parts.facts,
            parts.peer_ip,
            parts.header_facts.clone(),
            revision,
            parts.body_representation,
            parts.body_observation,
        )
        .unwrap()
    }

    #[test]
    fn shared_request_binding_fixtures_drive_product_cursor_binding() {
        for case in load_request_binding_suite().unwrap().into_cases() {
            let parts = fixture_evaluation_parts(&case.input);
            let input = fixture_input(&parts, parts.revision);
            assert_eq!(
                input.request_binding().to_wire(),
                case.expected.digest.as_str(),
                "{}",
                case.id
            );

            let mut delegate = simple_rule(
                &format!("binding-{}", case.id),
                CompiledRuleDecision::Delegate,
                &case.input.url,
            );
            delegate.authorization_provider = Some(format!("binding-provider-{}", case.id));
            let plan = PolicyPlan {
                default: CompiledDefaultDecision::Allow,
                rules: vec![delegate],
                http_body_read_plans_by_cursor: vec![
                    HttpBodyReadPlan::Disabled,
                    HttpBodyReadPlan::Disabled,
                ],
            };
            let compiled = compile_neutral_policy(
                &plan,
                &product_egress_plan(),
                &ObservationPlan { capture: None },
                PolicyGeneration::new(51).unwrap(),
                SnapshotIdentity::new(),
                &case
                    .input
                    .sensitive_header_presence
                    .iter()
                    .map(|name| HeaderName::from_bytes(name.as_bytes()).unwrap())
                    .collect::<Vec<_>>(),
            )
            .unwrap();

            let PolicyEvaluation::Delegate(unchanged) = compiled.snapshot.evaluate(&input).unwrap()
            else {
                panic!("{}: binding fixture did not match product rule", case.id)
            };
            assert!(matches!(
                compiled
                    .snapshot
                    .resolve_delegate(unchanged, ProviderDisposition::Pass, &input,),
                Ok(PolicyEvaluation::Allow { .. })
            ));

            let PolicyEvaluation::Delegate(changed) = compiled.snapshot.evaluate(&input).unwrap()
            else {
                panic!("{}: binding fixture did not match product rule", case.id)
            };
            let changed_input = fixture_input(&parts, parts.revision.wrapping_add(1));
            assert!(matches!(
                compiled.snapshot.resolve_delegate(
                    changed,
                    ProviderDisposition::Pass,
                    &changed_input,
                ),
                Err(AclError::InputBindingMismatch)
            ));
        }
    }

    #[test]
    fn shared_mutations_compile_into_end_state_outbound_effects() {
        let plan = product_plan();
        let egress = product_egress_plan();
        let compiled = compile_neutral_policy(
            &plan,
            &egress,
            &ObservationPlan { capture: None },
            PolicyGeneration::new(43).unwrap(),
            SnapshotIdentity::new(),
            &[product_name("x-sensitive")],
        )
        .unwrap();
        let request_facts = facts("https://service.example.test/app/resource", "POST");
        let sensitive = vec![NeutralHeaderName::new("x-sensitive").unwrap()];
        let input = evaluation_input(&request_facts, &sensitive);
        let PolicyEvaluation::Delegate(delegated) = compiled.snapshot.evaluate(&input).unwrap()
        else {
            panic!("expected delegate")
        };
        let PolicyEvaluation::Allow { effects, .. } = compiled
            .snapshot
            .resolve_delegate(delegated, ProviderDisposition::Allow, &input)
            .unwrap()
        else {
            panic!("expected effects")
        };
        let outbound = compiled
            .outbound_effects(&effects, provider_credentials(compiled.snapshot.identity()))
            .unwrap();

        let neutral_headers = vec![
            HeaderField::new(
                NeutralHeaderName::new("x-list").unwrap(),
                NeutralHeaderValue::new(b"a".to_vec()).unwrap(),
            ),
            HeaderField::new(
                NeutralHeaderName::new("x-remove").unwrap(),
                NeutralHeaderValue::new(b"gone".to_vec()).unwrap(),
            ),
            HeaderField::new(
                NeutralHeaderName::new("x-replace").unwrap(),
                NeutralHeaderValue::new(b"old-old".to_vec()).unwrap(),
            ),
        ];
        let neutral_headers = http_access_types::apply_header_mutation_batches(
            &neutral_headers,
            &outbound.request_header_batches,
        )
        .unwrap();
        let neutral_headers = neutral_pairs(&neutral_headers);
        assert_eq!(
            neutral_headers
                .iter()
                .filter(|(name, _)| name == "x-list")
                .map(|(_, value)| value.as_slice())
                .collect::<Vec<_>>(),
            vec![b"a".as_slice(), b"b".as_slice(), b"global".as_slice()]
        );
        assert!(neutral_headers
            .iter()
            .any(|(name, value)| name == "x-mutation-order" && value == b"global"));
        assert!(neutral_headers
            .iter()
            .any(|(name, value)| name == "x-set" && value == b"new"));
        assert!(neutral_headers
            .iter()
            .any(|(name, value)| name == "x-replace" && value == b"new-new"));
        assert!(!neutral_headers.iter().any(|(name, _)| name == "x-remove"));
        assert!(matches!(
            outbound.credentials[0].kind(),
            CredentialMutationKind::Bearer(reference)
                if reference.id().as_str() == "bearer-token"
        ));
        assert!(matches!(
            outbound.credentials[3].kind(),
            CredentialMutationKind::CustomHeader { name, credential }
                if name.as_str() == "x-global-token"
                    && credential.id().as_str() == "global-token"
        ));
    }

    #[test]
    fn rule_and_global_conditions_observe_separate_presence_snapshots() {
        let mut plan = product_plan();
        plan.rules[0].request_headers = vec![
            HeaderEffectPlan::Set {
                when: CompiledHeaderEffectWhen::Always,
                name: product_name("x-created-by-rule"),
                values: vec![product_value("rule")],
            },
            HeaderEffectPlan::Remove {
                when: CompiledHeaderEffectWhen::Always,
                name: product_name("x-removed-by-rule"),
            },
        ];
        let mut egress = product_egress_plan();
        egress.request_headers = vec![
            HeaderEffectPlan::Append {
                when: CompiledHeaderEffectWhen::IfPresent,
                name: product_name("x-created-by-rule"),
                values: vec![product_value("global")],
            },
            HeaderEffectPlan::Set {
                when: CompiledHeaderEffectWhen::IfPresent,
                name: product_name("x-removed-by-rule"),
                values: vec![product_value("must-not-return")],
            },
        ];
        let compiled = compile_neutral_policy(
            &plan,
            &egress,
            &ObservationPlan { capture: None },
            PolicyGeneration::new(46).unwrap(),
            SnapshotIdentity::new(),
            &[product_name("x-sensitive")],
        )
        .unwrap();
        let request_facts = facts("https://service.example.test/app/resource", "POST");
        let sensitive = vec![NeutralHeaderName::new("x-sensitive").unwrap()];
        let input = evaluation_input(&request_facts, &sensitive);
        let PolicyEvaluation::Delegate(delegated) = compiled.snapshot.evaluate(&input).unwrap()
        else {
            panic!("expected delegate")
        };
        let PolicyEvaluation::Allow { effects, .. } = compiled
            .snapshot
            .resolve_delegate(delegated, ProviderDisposition::Allow, &input)
            .unwrap()
        else {
            panic!("expected allow")
        };
        let outbound = compiled.outbound_effects(&effects, Vec::new()).unwrap();

        let neutral_headers = vec![HeaderField::new(
            NeutralHeaderName::new("x-removed-by-rule").unwrap(),
            NeutralHeaderValue::new(b"before".to_vec()).unwrap(),
        )];
        let neutral_headers = http_access_types::apply_header_mutation_batches(
            &neutral_headers,
            &outbound.request_header_batches,
        )
        .unwrap();
        assert_eq!(
            neutral_headers
                .iter()
                .filter(|field| field.name().as_str() == "x-created-by-rule")
                .map(|field| field.value().as_bytes())
                .collect::<Vec<_>>(),
            vec![b"rule".as_slice(), b"global".as_slice()]
        );
        assert!(!neutral_headers
            .iter()
            .any(|field| field.name().as_str() == "x-removed-by-rule"));
    }

    #[test]
    fn adapter_preserves_independent_product_effect_boundaries() {
        let mut rule = simple_rule(
            "boundary-rule",
            CompiledRuleDecision::Allow,
            "https://example.test/boundary",
        );
        rule.request_headers = (0..1_024)
            .map(|index| HeaderEffectPlan::Remove {
                when: CompiledHeaderEffectWhen::Always,
                name: HeaderName::from_bytes(format!("x-rule-{index}").as_bytes()).unwrap(),
            })
            .collect();
        let plan = PolicyPlan {
            default: CompiledDefaultDecision::Deny,
            rules: vec![rule],
            http_body_read_plans_by_cursor: vec![
                HttpBodyReadPlan::Disabled,
                HttpBodyReadPlan::Disabled,
            ],
        };
        let mut egress = product_egress_plan();
        egress.request_headers = (0..1_024)
            .map(|index| HeaderEffectPlan::Remove {
                when: CompiledHeaderEffectWhen::Always,
                name: HeaderName::from_bytes(format!("x-global-{index}").as_bytes()).unwrap(),
            })
            .collect();
        let compiled = compile_neutral_policy(
            &plan,
            &egress,
            &ObservationPlan { capture: None },
            PolicyGeneration::new(47).unwrap(),
            SnapshotIdentity::new(),
            &[],
        )
        .unwrap();
        let request_facts = facts("https://example.test/boundary", "GET");
        let PolicyEvaluation::Allow { effects, .. } = compiled
            .snapshot
            .evaluate(&evaluation_input(&request_facts, &[]))
            .unwrap()
        else {
            panic!("expected boundary allow")
        };
        let outbound = compiled.outbound_effects(&effects, Vec::new()).unwrap();

        assert_eq!(outbound.request_header_batches.len(), 2);
        assert!(outbound
            .request_header_batches
            .iter()
            .all(|batch| batch.mutations().len() == 1_024));
        assert!(http_access_types::apply_header_mutation_batches(
            &[],
            &outbound.request_header_batches,
        )
        .is_ok());
    }

    #[test]
    fn default_deny_releases_no_outbound_effects() {
        let plan = PolicyPlan {
            default: CompiledDefaultDecision::Deny,
            rules: Vec::new(),
            http_body_read_plans_by_cursor: vec![HttpBodyReadPlan::Disabled],
        };
        let compiled = compile_neutral_policy(
            &plan,
            &product_egress_plan(),
            &ObservationPlan { capture: None },
            PolicyGeneration::new(48).unwrap(),
            SnapshotIdentity::new(),
            &[],
        )
        .unwrap();
        let request_facts = facts("https://example.test/default-deny", "GET");

        assert!(matches!(
            compiled
                .snapshot
                .evaluate(&evaluation_input(&request_facts, &[]))
                .unwrap(),
            PolicyEvaluation::Deny { .. }
        ));
    }

    #[test]
    fn adapter_rejects_credential_collisions_at_every_stage_boundary() {
        let mut local_duplicate = product_plan();
        local_duplicate.rules[0]
            .credential_actions
            .push(CredentialActionPlan::Basic {
                username: "agent".to_owned(),
                password_credential: "basic-password".to_owned(),
            });
        assert!(matches!(
            compile_neutral_policy(
                &local_duplicate,
                &product_egress_plan(),
                &ObservationPlan { capture: None },
                PolicyGeneration::new(49).unwrap(),
                SnapshotIdentity::new(),
                &[product_name("x-sensitive")],
            ),
            Err(AdapterError::InvalidPlan)
        ));

        let mut global_collision = product_egress_plan();
        global_collision.credential_actions = vec![CredentialActionPlan::CustomHeader {
            header: product_name("x-api-key"),
            credential: "global-collision".to_owned(),
        }];
        assert!(matches!(
            compile_neutral_policy(
                &product_plan(),
                &global_collision,
                &ObservationPlan { capture: None },
                PolicyGeneration::new(50).unwrap(),
                SnapshotIdentity::new(),
                &[product_name("x-sensitive")],
            ),
            Err(AdapterError::InvalidPlan)
        ));

        let mut header_collision = product_egress_plan();
        header_collision
            .request_headers
            .push(HeaderEffectPlan::Remove {
                when: CompiledHeaderEffectWhen::Always,
                name: product_name("x-api-key"),
            });
        assert!(matches!(
            compile_neutral_policy(
                &product_plan(),
                &header_collision,
                &ObservationPlan { capture: None },
                PolicyGeneration::new(52).unwrap(),
                SnapshotIdentity::new(),
                &[product_name("x-sensitive")],
            ),
            Err(AdapterError::InvalidPlan)
        ));

        let identity = SnapshotIdentity::new();
        let compiled = compile_neutral_policy(
            &product_plan(),
            &product_egress_plan(),
            &ObservationPlan { capture: None },
            PolicyGeneration::new(51).unwrap(),
            identity.clone(),
            &[product_name("x-sensitive")],
        )
        .unwrap();
        let request_facts = facts("https://service.example.test/app/resource", "POST");
        let sensitive = vec![NeutralHeaderName::new("x-sensitive").unwrap()];
        let input = evaluation_input(&request_facts, &sensitive);
        let PolicyEvaluation::Delegate(delegated) = compiled.snapshot.evaluate(&input).unwrap()
        else {
            panic!("expected delegate")
        };
        let PolicyEvaluation::Allow { effects, .. } = compiled
            .snapshot
            .resolve_delegate(delegated, ProviderDisposition::Allow, &input)
            .unwrap()
        else {
            panic!("expected allow")
        };
        let provider_collision = vec![compile_credential(
            &CredentialActionPlan::CustomHeader {
                header: product_name("x-api-key"),
                credential: "provider-collision".to_owned(),
            },
            &identity,
        )
        .unwrap()];
        assert!(matches!(
            compiled.outbound_effects(&effects, provider_collision),
            Err(AdapterError::InvalidPlan)
        ));
    }

    #[test]
    fn adapter_rejects_an_over_aggregate_product_predicate_shape() {
        let mut rule = simple_rule(
            "too-many-predicates",
            CompiledRuleDecision::Allow,
            "https://example.test/**",
        );
        rule.urls.clear();
        rule.headers.present_all = vec![
            product_name("x-repeated");
            http_access_policy_acl::MAX_SEMANTIC_PREDICATES_PER_RULE + 1
        ];
        let plan = PolicyPlan {
            default: CompiledDefaultDecision::Deny,
            rules: vec![rule],
            http_body_read_plans_by_cursor: vec![
                HttpBodyReadPlan::Disabled,
                HttpBodyReadPlan::Disabled,
            ],
        };

        assert!(matches!(
            compile_neutral_policy(
                &plan,
                &product_egress_plan(),
                &ObservationPlan { capture: None },
                PolicyGeneration::new(44).unwrap(),
                SnapshotIdentity::new(),
                &[],
            ),
            Err(AdapterError::SharedBound)
        ));
    }

    #[test]
    fn adapter_rejects_sensitive_header_value_predicates() {
        let sensitive = product_name("x-sensitive");
        let mut rule = simple_rule(
            "sensitive-value",
            CompiledRuleDecision::Allow,
            "https://example.test/**",
        );
        rule.headers.all.push(HeaderValuePredicatePlan {
            name: sensitive.clone(),
            values: vec![product_value("must-not-enter-facts")],
        });
        let plan = PolicyPlan {
            default: CompiledDefaultDecision::Deny,
            rules: vec![rule],
            http_body_read_plans_by_cursor: vec![
                HttpBodyReadPlan::Disabled,
                HttpBodyReadPlan::Disabled,
            ],
        };

        assert!(matches!(
            compile_neutral_policy(
                &plan,
                &product_egress_plan(),
                &ObservationPlan { capture: None },
                PolicyGeneration::new(45).unwrap(),
                SnapshotIdentity::new(),
                &[sensitive],
            ),
            Err(AdapterError::InvalidCheckedValue)
        ));
    }

    fn neutral_pairs(headers: &[HeaderField]) -> Vec<(String, Vec<u8>)> {
        let mut pairs = headers
            .iter()
            .map(|field| {
                (
                    field.name().as_str().to_owned(),
                    field.value().as_bytes().to_vec(),
                )
            })
            .collect::<Vec<_>>();
        pairs.sort();
        pairs
    }
}
