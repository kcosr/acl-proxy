use std::sync::atomic::{AtomicU64, Ordering};

use http_access_policy_acl::{
    AclError, DefaultDecision, DelegateMatch, HeaderPredicate, PeerCidr, ProductActionRef, Rule,
    RulePredicates, TrafficPolicySnapshot,
};
use http_access_types::{
    ContractError, DecisionProvenance, EffectivePolicy, HeaderName as NeutralHeaderName,
    HeaderValue as NeutralHeaderValue, HttpMethod, PolicyGeneration, SnapshotIdentity, StableId,
};

use crate::config::compiler::{
    CompiledDefaultDecision, CompiledRuleDecision, HeaderPredicatesPlan, HeaderValuePredicatePlan,
    HttpBodyReadPlan, PolicyPlan, PolicyRulePlan,
};

static NEXT_WIRE_BODY_PLAN_BRAND: AtomicU64 = AtomicU64::new(1);

/// Copyable lookup key into the generation-owned product rule effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductRuleEffectsRef {
    ordinal: usize,
}

impl ProductRuleEffectsRef {
    pub(crate) const fn ordinal(self) -> usize {
        self.ordinal
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HttpWireBodyPlanIndex {
    brand: HttpWireBodyPlanBrand,
    ordinal: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HttpWireBodyPlanBrand {
    id: u64,
    cursor_count: usize,
}

impl HttpWireBodyPlanIndex {
    pub(super) const fn new(brand: HttpWireBodyPlanBrand, ordinal: usize) -> Self {
        Self { brand, ordinal }
    }

    pub(crate) fn resolve<T: Copy>(
        self,
        expected_brand: HttpWireBodyPlanBrand,
        values: &[T],
    ) -> Option<T> {
        (self.brand == expected_brand)
            .then(|| values.get(self.ordinal).copied())
            .flatten()
    }

    #[cfg(test)]
    pub(crate) fn test_pair(cursor_count: usize, ordinal: usize) -> (HttpWireBodyPlanBrand, Self) {
        let brand = next_wire_body_plan_brand(cursor_count);
        (brand, Self::new(brand, ordinal))
    }

    #[cfg(test)]
    pub(crate) const fn test_for_brand(brand: HttpWireBodyPlanBrand, ordinal: usize) -> Self {
        Self::new(brand, ordinal)
    }
}

impl HttpWireBodyPlanBrand {
    pub(crate) const fn cursor_count(self) -> usize {
        self.cursor_count
    }
}

pub(super) fn next_wire_body_plan_brand(cursor_count: usize) -> HttpWireBodyPlanBrand {
    let id = NEXT_WIRE_BODY_PLAN_BRAND.fetch_add(1, Ordering::Relaxed);
    assert!(id != 0, "HTTP wire-body plan brand overflow");
    HttpWireBodyPlanBrand { id, cursor_count }
}

/// Product-owned request-body admission data selected by an ACL cursor.
pub(crate) struct ProductAclResources {
    body_read_plans_by_cursor: Box<[HttpBodyReadPlan]>,
    wire_body_plan_brand: HttpWireBodyPlanBrand,
}

impl ProductAclResources {
    pub(crate) const fn wire_body_plan_brand(&self) -> HttpWireBodyPlanBrand {
        self.wire_body_plan_brand
    }

    pub(crate) fn body_read_plan(
        &self,
        cursor: ProductAclResourceCursor,
    ) -> Option<HttpBodyReadPlan> {
        cursor
            .wire_body_plan
            .resolve(self.wire_body_plan_brand, &self.body_read_plans_by_cursor)
    }

    pub(crate) fn wire_body_plan(
        &self,
        cursor: ProductAclResourceCursor,
    ) -> Option<HttpWireBodyPlanIndex> {
        (cursor.wire_body_plan.brand == self.wire_body_plan_brand).then_some(cursor.wire_body_plan)
    }
}

/// Snapshot-bound product resource selector derived from neutral provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductAclResourceCursor {
    wire_body_plan: HttpWireBodyPlanIndex,
}

impl ProductAclResourceCursor {
    pub(crate) const fn ordinal(self) -> usize {
        self.wire_body_plan.ordinal
    }
}

/// Production compilation boundary from product config plans to the neutral ACL.
pub(crate) struct ProductAclSnapshot {
    snapshot: TrafficPolicySnapshot<ProductRuleEffectsRef>,
    resources: ProductAclResources,
    rule_ids: Box<[StableId]>,
    action_ids: Box<[Option<StableId>]>,
}

impl ProductAclSnapshot {
    pub(crate) fn compile(
        plan: &PolicyPlan,
        generation: PolicyGeneration,
        identity: SnapshotIdentity,
        sensitive_headers: &[NeutralHeaderName],
    ) -> Result<Self, ProductAclCompileError> {
        let cursor_count = plan
            .rules
            .len()
            .checked_add(1)
            .ok_or(ProductAclCompileError::InvalidPlan)?;
        if plan.http_body_read_plans_by_cursor.len() != cursor_count {
            return Err(ProductAclCompileError::BodyReadPlanCount {
                expected: cursor_count,
                actual: plan.http_body_read_plans_by_cursor.len(),
            });
        }

        let mut neutral_sensitive = sensitive_headers.to_vec();
        neutral_sensitive.sort();
        neutral_sensitive.dedup();

        let compiled_rules = plan
            .rules
            .iter()
            .enumerate()
            .map(|(ordinal, rule)| compile_rule(rule, ordinal, &identity))
            .collect::<Result<Vec<_>, _>>()?;
        let mut rules = Vec::with_capacity(compiled_rules.len());
        let mut rule_ids = Vec::with_capacity(compiled_rules.len());
        let mut action_ids = Vec::with_capacity(compiled_rules.len());
        for compiled in compiled_rules {
            rules.push(compiled.rule);
            rule_ids.push(compiled.id);
            action_ids.push(compiled.action_id);
        }
        let snapshot = TrafficPolicySnapshot::new(
            generation,
            identity,
            match plan.default {
                CompiledDefaultDecision::Allow => DefaultDecision::Allow,
                CompiledDefaultDecision::Deny => DefaultDecision::Deny,
            },
            neutral_sensitive,
            rules,
        )
        .map_err(map_acl_error)?;

        Ok(Self {
            snapshot,
            resources: ProductAclResources {
                body_read_plans_by_cursor: plan
                    .http_body_read_plans_by_cursor
                    .clone()
                    .into_boxed_slice(),
                wire_body_plan_brand: next_wire_body_plan_brand(cursor_count),
            },
            rule_ids: rule_ids.into_boxed_slice(),
            action_ids: action_ids.into_boxed_slice(),
        })
    }

    pub(crate) const fn snapshot(&self) -> &TrafficPolicySnapshot<ProductRuleEffectsRef> {
        &self.snapshot
    }

    pub(crate) const fn resources(&self) -> &ProductAclResources {
        &self.resources
    }

    pub(crate) fn provider_action_id(&self, ordinal: usize) -> Option<&StableId> {
        self.action_ids.get(ordinal).and_then(Option::as_ref)
    }

    pub(crate) fn resource_cursor(
        &self,
        provenance: &DecisionProvenance,
    ) -> Result<ProductAclResourceCursor, ProductAclResourceError> {
        if provenance.generation() != self.snapshot.generation() {
            return Err(ProductAclResourceError::ForeignGeneration);
        }
        let ordinal = match provenance.effective_policy() {
            EffectivePolicy::Default => self.rule_ids.len(),
            EffectivePolicy::Rule { id, ordinal } => {
                let ordinal = usize::try_from(*ordinal)
                    .map_err(|_| ProductAclResourceError::InvalidProvenance)?;
                if self.rule_ids.get(ordinal) != Some(id) {
                    return Err(ProductAclResourceError::InvalidProvenance);
                }
                ordinal
            }
        };
        Ok(ProductAclResourceCursor {
            wire_body_plan: HttpWireBodyPlanIndex::new(
                self.resources.wire_body_plan_brand,
                ordinal,
            ),
        })
    }

    pub(crate) fn delegated_action<'a>(
        &self,
        delegated: &'a DelegateMatch<ProductRuleEffectsRef>,
    ) -> Result<&'a ProductActionRef, ProductAclResourceError> {
        let cursor = self.resource_cursor(delegated.provenance())?;
        let expected = self
            .action_ids
            .get(cursor.ordinal())
            .and_then(Option::as_ref)
            .ok_or(ProductAclResourceError::InvalidProvenance)?;
        let action = delegated.action();
        if !action.belongs_to(self.snapshot.identity()) || action.id() != expected {
            return Err(ProductAclResourceError::ForeignAction);
        }
        Ok(action)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum ProductAclResourceError {
    #[error("policy provenance belongs to a different generation")]
    ForeignGeneration,
    #[error("policy provenance does not select a compiled resource cursor")]
    InvalidProvenance,
    #[error("delegated action does not belong to the selected policy rule")]
    ForeignAction,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum ProductAclCompileError {
    #[error("policy body-read plan count mismatch: expected {expected}, got {actual}")]
    BodyReadPlanCount { expected: usize, actual: usize },
    #[error("invalid compiled policy plan")]
    InvalidPlan,
    #[error("compiled policy contains an invalid checked value")]
    InvalidCheckedValue,
    #[error("compiled policy exceeds a shared ACL bound")]
    SharedBound,
}

struct CompiledRule {
    rule: Rule<ProductRuleEffectsRef>,
    id: StableId,
    action_id: Option<StableId>,
}

fn compile_rule(
    rule: &PolicyRulePlan,
    ordinal: usize,
    identity: &SnapshotIdentity,
) -> Result<CompiledRule, ProductAclCompileError> {
    let id = stable_id(&rule.id)?;
    let predicates = compile_predicates(rule)?;
    let effects = ProductRuleEffectsRef { ordinal };
    match rule.decision {
        CompiledRuleDecision::Allow => Ok(CompiledRule {
            rule: Rule::allow(id.clone(), predicates, effects),
            id,
            action_id: None,
        }),
        CompiledRuleDecision::Deny => {
            if rule.authorization_provider.is_some()
                || rule.redaction_profile.is_some()
                || !rule.request_headers.is_empty()
                || !rule.response_headers.is_empty()
                || !rule.credential_actions.is_empty()
                || rule.allow_upgrades
            {
                return Err(ProductAclCompileError::InvalidPlan);
            }
            Ok(CompiledRule {
                rule: Rule::deny(id.clone(), predicates),
                id,
                action_id: None,
            })
        }
        CompiledRuleDecision::Delegate => {
            let provider = rule
                .authorization_provider
                .as_deref()
                .ok_or(ProductAclCompileError::InvalidPlan)?;
            let action_id = stable_id(provider)?;
            Ok(CompiledRule {
                rule: Rule::delegate(
                    id.clone(),
                    predicates,
                    ProductActionRef::new(identity, action_id.clone()),
                    effects,
                ),
                id,
                action_id: Some(action_id),
            })
        }
    }
}

fn compile_predicates(rule: &PolicyRulePlan) -> Result<RulePredicates, ProductAclCompileError> {
    let methods = rule
        .methods
        .iter()
        .map(|method| {
            HttpMethod::new(method.as_str().to_owned())
                .map_err(|_| ProductAclCompileError::InvalidCheckedValue)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let peers = rule
        .client_cidrs
        .iter()
        .map(|network| PeerCidr::new(network.network(), network.prefix_len()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_acl_error)?;
    RulePredicates::new(
        rule.urls.clone(),
        methods,
        peers,
        compile_header_predicates(&rule.headers)?,
    )
    .map_err(map_acl_error)
}

fn compile_header_predicates(
    plan: &HeaderPredicatesPlan,
) -> Result<Vec<HeaderPredicate>, ProductAclCompileError> {
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
            .map(HeaderPredicate::present)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProductAclCompileError::InvalidCheckedValue)?,
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
) -> Result<HeaderPredicate, ProductAclCompileError> {
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

fn neutral_header_name(
    value: &http::HeaderName,
) -> Result<NeutralHeaderName, ProductAclCompileError> {
    NeutralHeaderName::new(value.as_str().to_owned())
        .map_err(|_| ProductAclCompileError::InvalidCheckedValue)
}

fn neutral_header_value(
    value: &http::HeaderValue,
) -> Result<NeutralHeaderValue, ProductAclCompileError> {
    NeutralHeaderValue::new(value.as_bytes().to_vec())
        .map_err(|_| ProductAclCompileError::InvalidCheckedValue)
}

fn stable_id(value: &str) -> Result<StableId, ProductAclCompileError> {
    StableId::new(value.to_owned()).map_err(map_contract_error)
}

const fn map_acl_error(error: AclError) -> ProductAclCompileError {
    match error {
        AclError::InvalidCollection => ProductAclCompileError::SharedBound,
        AclError::InvalidPredicate | AclError::ForeignSnapshot | AclError::InputBindingMismatch => {
            ProductAclCompileError::InvalidCheckedValue
        }
        _ => ProductAclCompileError::InvalidCheckedValue,
    }
}

const fn map_contract_error(_error: ContractError) -> ProductAclCompileError {
    ProductAclCompileError::InvalidCheckedValue
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use http::header::{HeaderName, HeaderValue};
    use http::Method;
    use http_access_policy_acl::{
        EvaluationInput, MatchedEffects, PolicyEvaluation, ProviderDisposition,
        MAX_URL_PATTERNS_PER_RULE,
    };
    use http_access_types::{
        BodyFraming, BodyMetadata, BodyObservation, BodyRepresentation, DecisionReasonCategory,
        EffectivePolicy, HeaderField, HttpVersion, IngressMode, InterceptedRequestFacts,
        PolicyHeaderFacts,
    };
    use http_access_url::{canonicalize_http_url, CompiledUrlPattern};
    use ipnet::IpNet;

    use super::*;
    use crate::config::compiler::HttpBodyReadLimits;

    struct RequestFixture {
        facts: InterceptedRequestFacts,
        header_facts: PolicyHeaderFacts,
    }

    impl RequestFixture {
        fn new(
            method: &str,
            url: &str,
            ordinary_headers: &[(&str, &[u8])],
            sensitive_presence: &[&str],
            sensitive_headers: &[&str],
        ) -> Self {
            let mut ordinary_headers = ordinary_headers
                .iter()
                .map(|(name, value)| neutral_header(name, value))
                .collect::<Vec<_>>();
            ordinary_headers.sort_by(|left, right| left.name().cmp(right.name()));
            let sensitive_presence = sorted_neutral_names(sensitive_presence);
            let sensitive_headers = sorted_neutral_names(sensitive_headers);
            let facts = InterceptedRequestFacts::new(
                IngressMode::ExplicitHttps,
                HttpVersion::Http11,
                HttpMethod::new(method.to_owned()).unwrap(),
                canonicalize_http_url(url).unwrap(),
                ordinary_headers.clone(),
                BodyMetadata::new(BodyFraming::None),
                None,
            )
            .unwrap();
            let header_facts = PolicyHeaderFacts::from_partitioned(
                ordinary_headers,
                sensitive_presence,
                sensitive_headers,
            )
            .unwrap();
            Self {
                facts,
                header_facts,
            }
        }

        fn input(&self, peer: &str, revision: u64) -> EvaluationInput<'_> {
            EvaluationInput::new(
                &self.facts,
                IpAddr::from_str(peer).unwrap(),
                &self.header_facts,
                revision,
                BodyRepresentation::PreservedContentCoded,
                BodyObservation::unobserved(),
            )
            .unwrap()
        }
    }

    fn neutral_header(name: &str, value: &[u8]) -> HeaderField {
        HeaderField::new(
            NeutralHeaderName::new(name.to_owned()).unwrap(),
            NeutralHeaderValue::new(value.to_vec()).unwrap(),
        )
    }

    fn sorted_neutral_names(names: &[&str]) -> Vec<NeutralHeaderName> {
        let mut names = names
            .iter()
            .map(|name| NeutralHeaderName::new((*name).to_owned()).unwrap())
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        names
    }

    fn empty_predicates() -> HeaderPredicatesPlan {
        HeaderPredicatesPlan {
            absent_any: Vec::new(),
            present_all: Vec::new(),
            all: Vec::new(),
            none: Vec::new(),
        }
    }

    fn rule(id: &str, decision: CompiledRuleDecision, url: &str) -> PolicyRulePlan {
        PolicyRulePlan {
            id: id.to_owned(),
            description: None,
            decision,
            urls: vec![CompiledUrlPattern::compile(url).unwrap()],
            methods: Vec::new(),
            client_cidrs: Vec::new(),
            headers: empty_predicates(),
            request_timeout: None,
            allow_upgrades: false,
            authorization_provider: None,
            redaction_profile: None,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            credential_actions: Vec::new(),
        }
    }

    fn plan(default: CompiledDefaultDecision, rules: Vec<PolicyRulePlan>) -> PolicyPlan {
        let cursor_count = rules.len() + 1;
        PolicyPlan {
            default,
            rules,
            http_body_read_plans_by_cursor: vec![HttpBodyReadPlan::Disabled; cursor_count],
        }
    }

    fn compile(
        plan: &PolicyPlan,
        generation: u64,
        identity: SnapshotIdentity,
        sensitive_headers: &[&str],
    ) -> ProductAclSnapshot {
        ProductAclSnapshot::compile(
            plan,
            PolicyGeneration::new(generation).unwrap(),
            identity,
            &sorted_neutral_names(sensitive_headers),
        )
        .unwrap()
    }

    fn evaluate<'a>(
        snapshot: &'a ProductAclSnapshot,
        fixture: &'a RequestFixture,
        peer: &str,
    ) -> PolicyEvaluation<ProductRuleEffectsRef> {
        snapshot
            .snapshot()
            .evaluate(&fixture.input(peer, 1))
            .unwrap()
    }

    fn delegated(
        evaluation: PolicyEvaluation<ProductRuleEffectsRef>,
    ) -> DelegateMatch<ProductRuleEffectsRef> {
        let PolicyEvaluation::Delegate(delegated) = evaluation else {
            panic!("expected delegated evaluation")
        };
        delegated
    }

    #[test]
    fn production_adapter_preserves_url_method_cidr_and_header_predicates() {
        let mut allow = rule(
            "restricted",
            CompiledRuleDecision::Allow,
            "https://example.test/api/**",
        );
        allow.methods.push(Method::POST);
        allow.client_cidrs = vec![IpNet::from_str("192.0.2.0/24").unwrap()];
        allow.headers.absent_any = vec![
            HeaderName::from_static("x-never"),
            HeaderName::from_static("x-scope"),
        ];
        allow
            .headers
            .present_all
            .push(HeaderName::from_static("authorization"));
        allow.headers.all.push(HeaderValuePredicatePlan {
            name: HeaderName::from_static("x-scope"),
            values: vec![HeaderValue::from_static("write")],
        });
        allow.headers.none.push(HeaderValuePredicatePlan {
            name: HeaderName::from_static("x-scope"),
            values: vec![HeaderValue::from_static("blocked")],
        });
        let snapshot = compile(
            &plan(CompiledDefaultDecision::Deny, vec![allow]),
            8,
            SnapshotIdentity::new(),
            &["authorization"],
        );
        let matching = RequestFixture::new(
            "POST",
            "HTTPS://EXAMPLE.TEST/api/item",
            &[("x-scope", b"read"), ("x-scope", b"write")],
            &["authorization"],
            &["authorization"],
        );

        assert!(matches!(
            evaluate(&snapshot, &matching, "::ffff:192.0.2.44"),
            PolicyEvaluation::Allow { .. }
        ));
        for rejected in [
            RequestFixture::new(
                "GET",
                "https://example.test/api/item",
                &[("x-scope", b"write")],
                &["authorization"],
                &["authorization"],
            ),
            RequestFixture::new(
                "POST",
                "http://example.test/api/item",
                &[("x-scope", b"write")],
                &["authorization"],
                &["authorization"],
            ),
            RequestFixture::new(
                "POST",
                "https://example.test/api/item",
                &[("x-scope", b"write")],
                &[],
                &["authorization"],
            ),
            RequestFixture::new(
                "POST",
                "https://example.test/api/item",
                &[("x-scope", b"blocked")],
                &["authorization"],
                &["authorization"],
            ),
        ] {
            assert!(matches!(
                evaluate(&snapshot, &rejected, "192.0.2.44"),
                PolicyEvaluation::Deny { .. }
            ));
        }
        assert!(matches!(
            evaluate(&snapshot, &matching, "198.51.100.4"),
            PolicyEvaluation::Deny { .. }
        ));
    }

    #[test]
    fn first_match_and_default_outcomes_keep_exact_provenance() {
        let first = rule(
            "first",
            CompiledRuleDecision::Allow,
            "https://example.test/**",
        );
        let later = rule(
            "later",
            CompiledRuleDecision::Deny,
            "https://example.test/**",
        );
        let snapshot = compile(
            &plan(CompiledDefaultDecision::Allow, vec![first, later]),
            9,
            SnapshotIdentity::new(),
            &[],
        );
        let matched = RequestFixture::new("GET", "https://example.test/", &[], &[], &[]);
        let missed = RequestFixture::new("GET", "https://other.test/", &[], &[], &[]);

        let PolicyEvaluation::Allow {
            provenance,
            effects: MatchedEffects::Rule(effects),
        } = evaluate(&snapshot, &matched, "192.0.2.1")
        else {
            panic!("expected first rule allow")
        };
        assert_eq!(effects.ordinal(), 0);
        assert!(matches!(
            provenance.effective_policy(),
            EffectivePolicy::Rule { id, ordinal: 0 } if id.as_str() == "first"
        ));
        let PolicyEvaluation::Allow {
            provenance,
            effects: MatchedEffects::Empty,
        } = evaluate(&snapshot, &missed, "192.0.2.1")
        else {
            panic!("expected default allow")
        };
        assert_eq!(provenance.effective_policy(), &EffectivePolicy::Default);
    }

    #[test]
    fn product_resources_select_the_exact_rule_and_default_cursor() {
        let skipped = rule(
            "skipped",
            CompiledRuleDecision::Deny,
            "https://other.test/**",
        );
        let matched = rule(
            "matched",
            CompiledRuleDecision::Allow,
            "https://example.test/**",
        );
        let mut policy = plan(CompiledDefaultDecision::Deny, vec![skipped, matched]);
        policy.http_body_read_plans_by_cursor = vec![
            HttpBodyReadPlan::Disabled,
            HttpBodyReadPlan::Mandatory(HttpBodyReadLimits::try_new(64, 128).unwrap()),
            HttpBodyReadPlan::Disabled,
        ];
        let snapshot = compile(&policy, 10, SnapshotIdentity::new(), &[]);
        let matched_request = RequestFixture::new("GET", "https://example.test/", &[], &[], &[]);
        let missed_request = RequestFixture::new("GET", "https://missing.test/", &[], &[], &[]);

        let PolicyEvaluation::Allow { provenance, .. } =
            evaluate(&snapshot, &matched_request, "192.0.2.1")
        else {
            panic!("expected matched allow")
        };
        let cursor = snapshot.resource_cursor(&provenance).unwrap();
        assert_eq!(
            snapshot.resources().body_read_plan(cursor),
            Some(HttpBodyReadPlan::Mandatory(
                HttpBodyReadLimits::try_new(64, 128).unwrap()
            ))
        );
        let wire = snapshot.resources().wire_body_plan(cursor).unwrap();
        assert_eq!(
            wire.resolve(
                snapshot.resources().wire_body_plan_brand(),
                &[11_u16, 22, 33]
            ),
            Some(22)
        );

        let PolicyEvaluation::Deny { provenance } =
            evaluate(&snapshot, &missed_request, "192.0.2.1")
        else {
            panic!("expected default deny")
        };
        let cursor = snapshot.resource_cursor(&provenance).unwrap();
        assert_eq!(cursor.ordinal(), 2);
        assert_eq!(
            snapshot.resources().body_read_plan(cursor),
            Some(HttpBodyReadPlan::Disabled)
        );
    }

    #[test]
    fn delegated_actions_are_validated_against_the_product_snapshot() {
        let mut delegated_rule = rule(
            "delegate",
            CompiledRuleDecision::Delegate,
            "https://example.test/**",
        );
        delegated_rule.authorization_provider = Some("approval".to_owned());
        let policy = plan(CompiledDefaultDecision::Deny, vec![delegated_rule]);
        let generation = PolicyGeneration::new(11).unwrap();
        let first =
            ProductAclSnapshot::compile(&policy, generation, SnapshotIdentity::new(), &[]).unwrap();
        let foreign =
            ProductAclSnapshot::compile(&policy, generation, SnapshotIdentity::new(), &[]).unwrap();
        let request = RequestFixture::new("GET", "https://example.test/", &[], &[], &[]);

        let own = delegated(evaluate(&first, &request, "192.0.2.1"));
        assert_eq!(
            first.delegated_action(&own).unwrap().id().as_str(),
            "approval"
        );
        let foreign_match = delegated(evaluate(&foreign, &request, "192.0.2.1"));
        assert_eq!(
            first.delegated_action(&foreign_match),
            Err(ProductAclResourceError::ForeignAction)
        );
    }

    #[test]
    fn provider_allow_deny_and_pass_use_shared_delegate_resolution() {
        let mut delegated_rule = rule(
            "delegate",
            CompiledRuleDecision::Delegate,
            "https://example.test/**",
        );
        delegated_rule.authorization_provider = Some("approval".to_owned());
        let later = rule(
            "later",
            CompiledRuleDecision::Allow,
            "https://example.test/**",
        );
        let snapshot = compile(
            &plan(
                CompiledDefaultDecision::Deny,
                vec![delegated_rule.clone(), later],
            ),
            12,
            SnapshotIdentity::new(),
            &[],
        );
        let request = RequestFixture::new("GET", "https://example.test/", &[], &[], &[]);
        let input = request.input("192.0.2.1", 1);

        let allow = snapshot
            .snapshot()
            .resolve_delegate(
                delegated(snapshot.snapshot().evaluate(&input).unwrap()),
                ProviderDisposition::Allow,
                &input,
            )
            .unwrap();
        let PolicyEvaluation::Allow {
            provenance,
            effects: MatchedEffects::Rule(effects),
        } = allow
        else {
            panic!("expected provider allow")
        };
        assert_eq!(effects.ordinal(), 0);
        assert_eq!(
            provenance.reason().category(),
            DecisionReasonCategory::Provider
        );

        let deny = snapshot
            .snapshot()
            .resolve_delegate(
                delegated(snapshot.snapshot().evaluate(&input).unwrap()),
                ProviderDisposition::Deny,
                &input,
            )
            .unwrap();
        assert!(matches!(deny, PolicyEvaluation::Deny { provenance }
            if provenance.reason().category() == DecisionReasonCategory::Provider));

        let passed = snapshot
            .snapshot()
            .resolve_delegate(
                delegated(snapshot.snapshot().evaluate(&input).unwrap()),
                ProviderDisposition::Pass,
                &input,
            )
            .unwrap();
        let PolicyEvaluation::Allow {
            provenance,
            effects: MatchedEffects::Rule(effects),
        } = passed
        else {
            panic!("expected later allow")
        };
        assert_eq!(effects.ordinal(), 1);
        assert!(matches!(
            provenance.effective_policy(),
            EffectivePolicy::Rule { ordinal: 1, .. }
        ));

        let default_snapshot = compile(
            &plan(CompiledDefaultDecision::Deny, vec![delegated_rule]),
            13,
            SnapshotIdentity::new(),
            &[],
        );
        let delegated = delegated(default_snapshot.snapshot().evaluate(&input).unwrap());
        assert!(matches!(
            default_snapshot.snapshot().resolve_delegate(
                delegated,
                ProviderDisposition::Pass,
                &input
            ),
            Ok(PolicyEvaluation::Deny { provenance })
                if provenance.effective_policy() == &EffectivePolicy::Default
        ));
    }

    #[test]
    fn foreign_snapshots_and_changed_request_bindings_fail_closed() {
        let mut delegated_rule = rule(
            "delegate",
            CompiledRuleDecision::Delegate,
            "https://example.test/**",
        );
        delegated_rule.authorization_provider = Some("approval".to_owned());
        let policy = plan(CompiledDefaultDecision::Deny, vec![delegated_rule]);
        let generation = PolicyGeneration::new(14).unwrap();
        let first =
            ProductAclSnapshot::compile(&policy, generation, SnapshotIdentity::new(), &[]).unwrap();
        let second =
            ProductAclSnapshot::compile(&policy, generation, SnapshotIdentity::new(), &[]).unwrap();
        let request = RequestFixture::new("GET", "https://example.test/", &[], &[], &[]);
        let original = request.input("192.0.2.1", 1);

        let foreign = delegated(first.snapshot().evaluate(&original).unwrap());
        assert!(matches!(
            second
                .snapshot()
                .resolve_delegate(foreign, ProviderDisposition::Pass, &original),
            Err(AclError::ForeignSnapshot)
        ));

        let changed = request.input("192.0.2.1", 2);
        let rebound = delegated(first.snapshot().evaluate(&original).unwrap());
        assert!(matches!(
            first
                .snapshot()
                .resolve_delegate(rebound, ProviderDisposition::Allow, &changed),
            Err(AclError::InputBindingMismatch)
        ));
    }

    #[test]
    fn product_compilation_reports_body_table_and_shared_collection_bounds() {
        let one_rule = rule(
            "one",
            CompiledRuleDecision::Allow,
            "https://example.test/**",
        );
        let malformed = PolicyPlan {
            default: CompiledDefaultDecision::Deny,
            rules: vec![one_rule],
            http_body_read_plans_by_cursor: vec![HttpBodyReadPlan::Disabled],
        };
        assert!(matches!(
            ProductAclSnapshot::compile(
                &malformed,
                PolicyGeneration::new(15).unwrap(),
                SnapshotIdentity::new(),
                &[]
            ),
            Err(ProductAclCompileError::BodyReadPlanCount {
                expected: 2,
                actual: 1
            })
        ));

        let pattern = CompiledUrlPattern::compile("https://example.test/**").unwrap();
        let mut oversized = rule(
            "oversized",
            CompiledRuleDecision::Allow,
            "https://example.test/**",
        );
        oversized.urls = vec![pattern; MAX_URL_PATTERNS_PER_RULE + 1];
        assert!(matches!(
            ProductAclSnapshot::compile(
                &plan(CompiledDefaultDecision::Deny, vec![oversized]),
                PolicyGeneration::new(16).unwrap(),
                SnapshotIdentity::new(),
                &[]
            ),
            Err(ProductAclCompileError::SharedBound)
        ));
    }
}
