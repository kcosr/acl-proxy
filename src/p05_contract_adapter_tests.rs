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
    .map_err(|_| AdapterError::InvalidCheckedValue)
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
        MutationError::InvalidShape
        | MutationError::ForbiddenHeader
        | MutationError::InvalidValue => AdapterError::InvalidCheckedValue,
        _ => AdapterError::InvalidCheckedValue,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use http::{HeaderMap, HeaderName, HeaderValue, Method};
    use http_access_policy_acl::{PolicyEvaluation, ProviderDisposition};
    use http_access_types::{
        BodyFraming, BodyMetadata, BodyObservation, BodyRepresentation, CanonicalUrl, HeaderField,
        HttpVersion, IngressMode, InterceptedRequestFacts, PolicyHeaderFacts,
    };
    use http_access_url::{canonicalize_http_url, CompiledUrlPattern};

    use super::*;
    use crate::capture::CaptureSinkSpec;
    use crate::config::compiler::{
        CaptureWorkingSetPlan, CompiledEgressRoute, CompiledHttpVersion, CompiledTlsTrust,
        HttpBodyReadLimits, TransportTlsPlan,
    };
    use crate::policy::apply_header_effects;

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

    #[test]
    fn shared_mutations_match_current_product_effect_application() {
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

        let mut product_headers = HeaderMap::new();
        product_headers.append(product_name("x-list"), product_value("a"));
        product_headers.append(product_name("x-remove"), product_value("gone"));
        product_headers.append(product_name("x-replace"), product_value("old-old"));
        apply_header_effects(&plan.rules[0].request_headers, &mut product_headers).unwrap();
        apply_header_effects(&egress.request_headers, &mut product_headers).unwrap();

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
        assert_eq!(
            product_pairs(&product_headers),
            neutral_pairs(&neutral_headers)
        );
        assert_eq!(product_headers["x-mutation-order"], "global");
        assert_eq!(
            product_headers
                .get_all("x-list")
                .iter()
                .map(HeaderValue::as_bytes)
                .collect::<Vec<_>>(),
            vec![b"a".as_slice(), b"b".as_slice(), b"global".as_slice()]
        );
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

        let mut product_headers = HeaderMap::new();
        product_headers.insert(product_name("x-removed-by-rule"), product_value("before"));
        apply_header_effects(&plan.rules[0].request_headers, &mut product_headers).unwrap();
        apply_header_effects(&egress.request_headers, &mut product_headers).unwrap();
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
            product_pairs(&product_headers),
            neutral_pairs(&neutral_headers)
        );
        assert_eq!(
            product_headers
                .get_all("x-created-by-rule")
                .iter()
                .map(HeaderValue::as_bytes)
                .collect::<Vec<_>>(),
            vec![b"rule".as_slice(), b"global".as_slice()]
        );
        assert!(!product_headers.contains_key("x-removed-by-rule"));
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

    fn product_pairs(headers: &HeaderMap) -> Vec<(String, Vec<u8>)> {
        let mut pairs = headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect::<Vec<_>>();
        pairs.sort();
        pairs
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

    #[allow(dead_code)]
    fn shared_api_contains_only_neutral_effects(
        snapshot: &TrafficPolicySnapshot<NeutralRuleEffects>,
    ) -> &TrafficPolicySnapshot<NeutralRuleEffects> {
        snapshot
    }

    #[allow(dead_code)]
    fn canonical_url_is_a_shared_fact(_url: &CanonicalUrl) {}
}
