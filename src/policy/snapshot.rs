use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::Method;
use memchr::memmem::Finder;

#[cfg(test)]
use crate::config::v3_compile::CredentialActionPlan;
use crate::config::v3_compile::{
    CompiledDefaultDecision, CompiledHeaderEffectWhen, CompiledRuleDecision, HeaderEffectPlan,
    HeaderPredicatesPlan, PolicyPlan, PolicyRulePlan,
};
use crate::credentials::{
    resolve_credential_action, CredentialBindingError, ResolvedCredentialAction,
};
use crate::runtime::{
    CredentialSourceIndex, CredentialSourceRegistry, ProviderIndex, ProviderRegistry,
    RedactionProfileIndex, RedactionProfileRegistry, ResolvedBindings, ResolvedRuleBindings,
};
use crate::url::CanonicalUrl;

const MAX_HEADER_FIELD_BYTES: usize = 64 * 1024;
const MAX_HEADER_VALUE_BYTES: usize = 1024 * 1024;
static NEXT_WIRE_BODY_PLAN_BRAND: AtomicU64 = AtomicU64::new(1);

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
    fn new(brand: HttpWireBodyPlanBrand, ordinal: usize) -> Self {
        Self { brand, ordinal }
    }

    pub(crate) fn resolve(
        self,
        expected_brand: HttpWireBodyPlanBrand,
        peaks: &[usize],
    ) -> Option<usize> {
        (self.brand == expected_brand)
            .then(|| peaks.get(self.ordinal).copied())
            .flatten()
    }

    #[cfg(test)]
    pub(crate) fn test_pair(cursor_count: usize, ordinal: usize) -> (HttpWireBodyPlanBrand, Self) {
        let brand = next_wire_body_plan_brand(cursor_count);
        (brand, Self::new(brand, ordinal))
    }

    #[cfg(test)]
    pub(crate) fn test_for_brand(brand: HttpWireBodyPlanBrand, ordinal: usize) -> Self {
        Self::new(brand, ordinal)
    }
}

impl HttpWireBodyPlanBrand {
    pub(crate) fn cursor_count(self) -> usize {
        self.cursor_count
    }
}

fn next_wire_body_plan_brand(cursor_count: usize) -> HttpWireBodyPlanBrand {
    let id = NEXT_WIRE_BODY_PLAN_BRAND.fetch_add(1, Ordering::Relaxed);
    assert!(id != 0, "HTTP wire-body plan brand overflow");
    HttpWireBodyPlanBrand { id, cursor_count }
}

/// Immutable, generation-owned policy compiled from the product configuration.
pub(crate) struct CompiledPolicySnapshot {
    default: CompiledDefaultDecision,
    rules: Box<[ActivatedPolicyRule]>,
    wire_body_plan_brand: HttpWireBodyPlanBrand,
}

pub(crate) struct PolicyActivation {
    snapshot: CompiledPolicySnapshot,
    bindings: ResolvedBindings,
}

impl fmt::Debug for CompiledPolicySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledPolicySnapshot")
            .field("rule_count", &self.rules.len())
            .finish()
    }
}

impl fmt::Debug for PolicyActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.snapshot.fmt(formatter)
    }
}

struct ActivatedPolicyRule {
    id: String,
    description: Option<String>,
    decision: CompiledRuleDecision,
    urls: Vec<crate::url::CompiledUrlPattern>,
    methods: Vec<Method>,
    client_cidrs: Vec<ipnet::IpNet>,
    headers: HeaderPredicatesPlan,
    request_timeout: Option<Duration>,
    allow_upgrades: bool,
    authorization_provider: Option<ProviderIndex>,
    redaction_profile: Option<RedactionProfileIndex>,
    request_headers: Vec<HeaderEffectPlan>,
    response_headers: Vec<HeaderEffectPlan>,
    credential_actions: Box<[ResolvedCredentialAction]>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum PolicyActivationError {
    #[error("policy rule {rule_index} references an unknown authorization provider")]
    AuthorizationProvider { rule_index: usize },
    #[error("policy rule {rule_index} references an unknown redaction profile")]
    RedactionProfile { rule_index: usize },
    #[error(
        "credential action {action_index} in policy rule {rule_index} references an unknown source"
    )]
    CredentialSource {
        rule_index: usize,
        action_index: usize,
    },
}

pub(crate) struct PolicyCursor<'snapshot> {
    snapshot: &'snapshot CompiledPolicySnapshot,
    next_index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PolicyOutcome {
    Allow,
    Deny,
    Delegate,
}

pub(crate) struct PolicyEvaluation<'snapshot> {
    pub(crate) outcome: PolicyOutcome,
    pub(crate) matched: Option<PolicyRuleMatch<'snapshot>>,
    wire_body_plan: HttpWireBodyPlanIndex,
}

impl PolicyEvaluation<'_> {
    pub(crate) fn wire_body_plan(&self) -> HttpWireBodyPlanIndex {
        self.wire_body_plan
    }
}

pub(crate) struct PolicyRuleMatch<'snapshot> {
    snapshot: &'snapshot CompiledPolicySnapshot,
    index: usize,
    rule: &'snapshot ActivatedPolicyRule,
}

impl CompiledPolicySnapshot {
    pub(crate) fn activate(
        plan: PolicyPlan,
        provider_registry: &ProviderRegistry,
        redaction_profile_registry: &RedactionProfileRegistry,
        credential_source_registry: &CredentialSourceRegistry,
    ) -> Result<PolicyActivation, PolicyActivationError> {
        let PolicyPlan { default, rules } = plan;
        let rules = rules
            .into_iter()
            .enumerate()
            .map(|(rule_index, rule)| {
                activate_rule(
                    rule_index,
                    rule,
                    provider_registry,
                    redaction_profile_registry,
                    credential_source_registry,
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();
        let cursor_count = rules
            .len()
            .checked_add(1)
            .expect("policy cursor count overflow");
        let bindings = resolved_bindings(
            &rules,
            provider_registry.len(),
            redaction_profile_registry.len(),
            credential_source_registry.len(),
        );
        Ok(PolicyActivation {
            snapshot: Self {
                default,
                rules,
                wire_body_plan_brand: next_wire_body_plan_brand(cursor_count),
            },
            bindings,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_plan(plan: PolicyPlan) -> Self {
        let provider_names = plan
            .rules
            .iter()
            .filter_map(|rule| rule.authorization_provider.as_deref());
        let profile_names = plan
            .rules
            .iter()
            .filter_map(|rule| rule.redaction_profile.as_deref());
        let credential_names = plan.rules.iter().flat_map(|rule| {
            rule.credential_actions.iter().map(|action| match action {
                CredentialActionPlan::Bearer { credential }
                | CredentialActionPlan::CustomHeader { credential, .. } => credential.as_str(),
                CredentialActionPlan::Basic {
                    password_credential,
                    ..
                } => password_credential.as_str(),
            })
        });
        let provider_registry = ProviderRegistry::from_names(provider_names.map(str::to_owned));
        let redaction_profile_registry =
            RedactionProfileRegistry::from_names(profile_names.map(str::to_owned));
        let credential_source_registry =
            CredentialSourceRegistry::from_names(credential_names.map(str::to_owned));
        Self::activate(
            plan,
            &provider_registry,
            &redaction_profile_registry,
            &credential_source_registry,
        )
        .expect("test policy bindings are complete")
        .into_parts()
        .0
    }

    pub(crate) fn evaluate<'snapshot, ExtraPresence>(
        &'snapshot self,
        url: &CanonicalUrl,
        peer_ip: IpAddr,
        method: &Method,
        headers: &HeaderMap,
        extra_presence: ExtraPresence,
    ) -> PolicyEvaluation<'snapshot>
    where
        ExtraPresence: Fn(&HeaderName) -> bool,
    {
        self.evaluate_at(0, url, peer_ip, method, headers, extra_presence)
    }

    fn evaluate_at<'snapshot, ExtraPresence>(
        &'snapshot self,
        start_index: usize,
        url: &CanonicalUrl,
        peer_ip: IpAddr,
        method: &Method,
        headers: &HeaderMap,
        extra_presence: ExtraPresence,
    ) -> PolicyEvaluation<'snapshot>
    where
        ExtraPresence: Fn(&HeaderName) -> bool,
    {
        let peer_ip = canonical_peer_ip(peer_ip);
        for (index, rule) in self.rules.iter().enumerate().skip(start_index) {
            if rule_matches(rule, url, peer_ip, method, headers, &extra_presence) {
                return PolicyEvaluation {
                    outcome: outcome(rule.decision),
                    matched: Some(PolicyRuleMatch {
                        snapshot: self,
                        index,
                        rule,
                    }),
                    wire_body_plan: HttpWireBodyPlanIndex::new(
                        self.wire_body_plan_brand,
                        start_index,
                    ),
                };
            }
        }

        PolicyEvaluation {
            outcome: match self.default {
                CompiledDefaultDecision::Allow => PolicyOutcome::Allow,
                CompiledDefaultDecision::Deny => PolicyOutcome::Deny,
            },
            matched: None,
            wire_body_plan: HttpWireBodyPlanIndex::new(self.wire_body_plan_brand, start_index),
        }
    }
}

impl PolicyActivation {
    pub(crate) fn wire_body_plan_brand(&self) -> HttpWireBodyPlanBrand {
        self.snapshot.wire_body_plan_brand
    }

    pub(crate) fn into_parts(self) -> (CompiledPolicySnapshot, ResolvedBindings) {
        (self.snapshot, self.bindings)
    }
}

impl std::ops::Deref for PolicyActivation {
    type Target = CompiledPolicySnapshot;

    fn deref(&self) -> &Self::Target {
        &self.snapshot
    }
}

impl<'snapshot> PolicyRuleMatch<'snapshot> {
    pub(crate) fn index(&self) -> usize {
        self.index
    }

    pub(crate) fn id(&self) -> &'snapshot str {
        &self.rule.id
    }

    pub(crate) fn description(&self) -> Option<&'snapshot str> {
        self.rule.description.as_deref()
    }

    pub(crate) fn resume_cursor(self) -> PolicyCursor<'snapshot> {
        PolicyCursor {
            snapshot: self.snapshot,
            next_index: self.index + 1,
        }
    }

    pub(crate) fn request_timeout(&self) -> Option<Duration> {
        self.rule.request_timeout
    }

    pub(crate) fn allows_upgrades(&self) -> bool {
        self.rule.allow_upgrades
    }

    pub(crate) fn authorization_provider(&self) -> Option<ProviderIndex> {
        self.rule.authorization_provider
    }

    pub(crate) fn redaction_profile(&self) -> Option<RedactionProfileIndex> {
        self.rule.redaction_profile
    }

    pub(crate) fn request_header_effects(&self) -> &'snapshot [HeaderEffectPlan] {
        &self.rule.request_headers
    }

    pub(crate) fn response_header_effects(&self) -> &'snapshot [HeaderEffectPlan] {
        &self.rule.response_headers
    }

    pub(crate) fn credential_actions(&self) -> &'snapshot [ResolvedCredentialAction] {
        &self.rule.credential_actions
    }
}

impl crate::runtime::PolicySnapshot for CompiledPolicySnapshot {}

fn resolved_bindings(
    rules: &[ActivatedPolicyRule],
    provider_count: usize,
    redaction_profile_count: usize,
    credential_count: usize,
) -> ResolvedBindings {
    let rules = rules
        .iter()
        .map(|rule| ResolvedRuleBindings {
            authorization_provider: rule.authorization_provider,
            redaction_profile: rule.redaction_profile,
            credentials: rule
                .credential_actions
                .iter()
                .map(credential_source_index)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    ResolvedBindings {
        provider_count,
        redaction_profile_count,
        credential_count,
        rules,
    }
}

fn credential_source_index(action: &ResolvedCredentialAction) -> CredentialSourceIndex {
    match action {
        ResolvedCredentialAction::Bearer { source }
        | ResolvedCredentialAction::Basic { source, .. }
        | ResolvedCredentialAction::CustomHeader { source, .. } => *source,
    }
}

fn activate_rule(
    rule_index: usize,
    rule: PolicyRulePlan,
    provider_registry: &ProviderRegistry,
    redaction_profile_registry: &RedactionProfileRegistry,
    credential_source_registry: &CredentialSourceRegistry,
) -> Result<ActivatedPolicyRule, PolicyActivationError> {
    let authorization_provider = rule
        .authorization_provider
        .map(|name| {
            provider_registry
                .get(&name)
                .ok_or(PolicyActivationError::AuthorizationProvider { rule_index })
        })
        .transpose()?;
    let redaction_profile = rule
        .redaction_profile
        .map(|name| {
            redaction_profile_registry
                .get(&name)
                .ok_or(PolicyActivationError::RedactionProfile { rule_index })
        })
        .transpose()?;
    let credential_actions = rule
        .credential_actions
        .into_iter()
        .enumerate()
        .map(|(action_index, action)| {
            resolve_credential_action(action, credential_source_registry).map_err(
                |CredentialBindingError::UnknownSource| PolicyActivationError::CredentialSource {
                    rule_index,
                    action_index,
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_boxed_slice();
    Ok(ActivatedPolicyRule {
        id: rule.id,
        description: rule.description,
        decision: rule.decision,
        urls: rule.urls,
        methods: rule.methods,
        client_cidrs: rule.client_cidrs,
        headers: rule.headers,
        request_timeout: rule.request_timeout,
        allow_upgrades: rule.allow_upgrades,
        authorization_provider,
        redaction_profile,
        request_headers: rule.request_headers,
        response_headers: rule.response_headers,
        credential_actions,
    })
}

impl<'snapshot> PolicyCursor<'snapshot> {
    pub(crate) fn resume<ExtraPresence>(
        self,
        url: &CanonicalUrl,
        peer_ip: IpAddr,
        method: &Method,
        headers: &HeaderMap,
        extra_presence: ExtraPresence,
    ) -> PolicyEvaluation<'snapshot>
    where
        ExtraPresence: Fn(&HeaderName) -> bool,
    {
        self.snapshot.evaluate_at(
            self.next_index,
            url,
            peer_ip,
            method,
            headers,
            extra_presence,
        )
    }
}

fn canonical_peer_ip(peer_ip: IpAddr) -> IpAddr {
    match peer_ip {
        IpAddr::V6(ipv6) => ipv6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ipv6)),
        ipv4 => ipv4,
    }
}

fn rule_matches<ExtraPresence>(
    rule: &ActivatedPolicyRule,
    url: &CanonicalUrl,
    peer_ip: IpAddr,
    method: &Method,
    headers: &HeaderMap,
    extra_presence: &ExtraPresence,
) -> bool
where
    ExtraPresence: Fn(&HeaderName) -> bool,
{
    (rule.urls.is_empty() || rule.urls.iter().any(|pattern| pattern.is_match(url)))
        && (rule.methods.is_empty()
            || rule
                .methods
                .iter()
                .any(|allowed| allowed.as_str().eq_ignore_ascii_case(method.as_str())))
        && (rule.client_cidrs.is_empty()
            || rule
                .client_cidrs
                .iter()
                .any(|network| network.contains(&peer_ip)))
        && header_predicates_match(&rule.headers, headers, extra_presence)
}

fn header_predicates_match<ExtraPresence>(
    predicates: &HeaderPredicatesPlan,
    headers: &HeaderMap,
    extra_presence: &ExtraPresence,
) -> bool
where
    ExtraPresence: Fn(&HeaderName) -> bool,
{
    let is_present = |name: &HeaderName| headers.contains_key(name) || extra_presence(name);

    (predicates.absent_any.is_empty() || predicates.absent_any.iter().any(|name| !is_present(name)))
        && predicates.present_all.iter().all(is_present)
        && predicates.all.iter().all(|predicate| {
            headers.get_all(&predicate.name).iter().any(|actual| {
                predicate
                    .values
                    .iter()
                    .any(|expected| actual.as_bytes() == expected.as_bytes())
            })
        })
        && predicates.none.iter().all(|predicate| {
            !headers.get_all(&predicate.name).iter().any(|actual| {
                predicate
                    .values
                    .iter()
                    .any(|expected| actual.as_bytes() == expected.as_bytes())
            })
        })
}

fn outcome(decision: CompiledRuleDecision) -> PolicyOutcome {
    match decision {
        CompiledRuleDecision::Allow => PolicyOutcome::Allow,
        CompiledRuleDecision::Deny => PolicyOutcome::Deny,
        CompiledRuleDecision::Delegate => PolicyOutcome::Delegate,
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum HeaderEffectError {
    #[error("header effect exceeds the per-field value limit")]
    FieldLimit,
    #[error("header effect exceeds the aggregate value limit")]
    AggregateLimit,
    #[error("header effect size arithmetic overflow")]
    SizeOverflow,
    #[error("header effect produced an invalid value")]
    InvalidValue,
}

/// Applies a validated effect list in authored order.
///
/// Every `when` predicate observes the header set from before the first effect,
/// and the caller's map is replaced only after every effect succeeds.
/// Preexisting fields remain outside result-limit accounting until an applied
/// effect targets their name, allowing unrelated effects to preserve inbound
/// values and targeted set/remove/replace effects to remediate them.
pub(crate) fn apply_header_effects(
    effects: &[HeaderEffectPlan],
    headers: &mut HeaderMap,
) -> Result<(), HeaderEffectError> {
    let original_presence: HashSet<HeaderName> = headers.keys().cloned().collect();
    let mut staged = headers.clone();
    let mut touched = HashSet::new();
    let mut touched_bytes = 0usize;

    for effect in effects {
        let (when, name) = effect_when_and_name(effect);
        let originally_present = original_presence.contains(name);
        let applies = match when {
            CompiledHeaderEffectWhen::Always => true,
            CompiledHeaderEffectWhen::IfPresent => originally_present,
            CompiledHeaderEffectWhen::IfAbsent => !originally_present,
        };
        if !applies {
            continue;
        }
        let previously_touched = !touched.insert(name.clone());
        let previous = named_value_bytes(&staged, name)?;
        let other_touched_bytes = if previously_touched {
            touched_bytes
                .checked_sub(previous)
                .ok_or(HeaderEffectError::SizeOverflow)?
        } else {
            touched_bytes
        };

        let resulting_named_bytes = match effect {
            HeaderEffectPlan::Set { name, values, .. } => {
                let replacement = effect_value_bytes(values)?;
                ensure_changed_aggregate(other_touched_bytes, replacement)?;
                staged.remove(name);
                for value in values {
                    staged.append(name.clone(), value.clone());
                }
                replacement
            }
            HeaderEffectPlan::Append { name, values, .. } => {
                let appended = effect_value_bytes(values)?;
                let replacement = previous
                    .checked_add(appended)
                    .ok_or(HeaderEffectError::SizeOverflow)?;
                ensure_changed_aggregate(other_touched_bytes, replacement)?;
                for value in values {
                    staged.append(name.clone(), value.clone());
                }
                replacement
            }
            HeaderEffectPlan::Remove { name, .. } => {
                staged.remove(name);
                0
            }
            HeaderEffectPlan::Replace {
                name,
                search,
                replace,
                ..
            } => replace_header_bytes(
                &mut staged,
                other_touched_bytes,
                name,
                search.as_bytes(),
                replace.as_bytes(),
            )?,
        };
        validate_named_header_limits(&staged, name)?;
        touched_bytes = other_touched_bytes
            .checked_add(resulting_named_bytes)
            .ok_or(HeaderEffectError::SizeOverflow)?;
    }

    *headers = staged;
    Ok(())
}

fn effect_when_and_name(effect: &HeaderEffectPlan) -> (CompiledHeaderEffectWhen, &HeaderName) {
    match effect {
        HeaderEffectPlan::Set { when, name, .. }
        | HeaderEffectPlan::Append { when, name, .. }
        | HeaderEffectPlan::Remove { when, name }
        | HeaderEffectPlan::Replace { when, name, .. } => (*when, name),
    }
}

fn replace_header_bytes(
    headers: &mut HeaderMap,
    other_touched_bytes: usize,
    name: &HeaderName,
    search: &[u8],
    replacement: &[u8],
) -> Result<usize, HeaderEffectError> {
    if search.is_empty() {
        return Err(HeaderEffectError::InvalidValue);
    }
    let finder = Finder::new(search);
    let output_lengths: Vec<usize> = headers
        .get_all(name)
        .iter()
        .map(|value| replaced_len(value.as_bytes(), &finder, search.len(), replacement))
        .collect::<Result<_, _>>()?;
    if output_lengths.is_empty() {
        return Ok(0);
    }
    let replacement_total = checked_sum(output_lengths.iter().copied())?;
    ensure_changed_aggregate(other_touched_bytes, replacement_total)?;

    let values: Vec<HeaderValue> = headers
        .get_all(name)
        .iter()
        .zip(output_lengths)
        .map(|(value, output_len)| {
            let replaced = replace_all(
                value.as_bytes(),
                &finder,
                search.len(),
                replacement,
                output_len,
            );
            HeaderValue::from_bytes(&replaced).map_err(|_| HeaderEffectError::InvalidValue)
        })
        .collect::<Result<_, _>>()?;
    headers.remove(name);
    for value in values {
        headers.append(name.clone(), value);
    }
    Ok(replacement_total)
}

fn replaced_len(
    input: &[u8],
    finder: &Finder<'_>,
    search_len: usize,
    replacement: &[u8],
) -> Result<usize, HeaderEffectError> {
    let matches = finder.find_iter(input).count();
    let removed = matches
        .checked_mul(search_len)
        .ok_or(HeaderEffectError::SizeOverflow)?;
    let inserted = matches
        .checked_mul(replacement.len())
        .ok_or(HeaderEffectError::SizeOverflow)?;
    let output_len = input
        .len()
        .checked_sub(removed)
        .and_then(|value| value.checked_add(inserted))
        .ok_or(HeaderEffectError::SizeOverflow)?;
    if output_len > MAX_HEADER_FIELD_BYTES {
        return Err(HeaderEffectError::FieldLimit);
    }
    Ok(output_len)
}

fn replace_all(
    input: &[u8],
    finder: &Finder<'_>,
    search_len: usize,
    replacement: &[u8],
    output_len: usize,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(output_len);
    let mut cursor = 0usize;
    for index in finder.find_iter(input) {
        output.extend_from_slice(&input[cursor..index]);
        output.extend_from_slice(replacement);
        cursor = index + search_len;
    }
    output.extend_from_slice(&input[cursor..]);
    debug_assert_eq!(output.len(), output_len);
    output
}

fn validate_named_header_limits(
    headers: &HeaderMap,
    name: &HeaderName,
) -> Result<(), HeaderEffectError> {
    for value in headers.get_all(name).iter() {
        if value.as_bytes().len() > MAX_HEADER_FIELD_BYTES {
            return Err(HeaderEffectError::FieldLimit);
        }
    }
    Ok(())
}

fn named_value_bytes(headers: &HeaderMap, name: &HeaderName) -> Result<usize, HeaderEffectError> {
    checked_sum(
        headers
            .get_all(name)
            .iter()
            .map(|value| value.as_bytes().len()),
    )
}

fn effect_value_bytes(values: &[HeaderValue]) -> Result<usize, HeaderEffectError> {
    for value in values {
        if value.as_bytes().len() > MAX_HEADER_FIELD_BYTES {
            return Err(HeaderEffectError::FieldLimit);
        }
    }
    checked_sum(values.iter().map(|value| value.as_bytes().len()))
}

fn checked_sum(mut values: impl Iterator<Item = usize>) -> Result<usize, HeaderEffectError> {
    values.try_fold(0usize, |sum, value| {
        sum.checked_add(value)
            .ok_or(HeaderEffectError::SizeOverflow)
    })
}

fn ensure_aggregate_limit(value: usize) -> Result<(), HeaderEffectError> {
    if value > MAX_HEADER_VALUE_BYTES {
        Err(HeaderEffectError::AggregateLimit)
    } else {
        Ok(())
    }
}

fn ensure_changed_aggregate(
    other_touched_bytes: usize,
    resulting_named_bytes: usize,
) -> Result<(), HeaderEffectError> {
    ensure_aggregate_limit(
        other_touched_bytes
            .checked_add(resulting_named_bytes)
            .ok_or(HeaderEffectError::SizeOverflow)?,
    )
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ipnet::IpNet;

    use super::*;
    use crate::config::v3_compile::{HeaderValuePredicatePlan, PolicyRulePlan};
    use crate::url::{canonicalize_http_url, CompiledUrlPattern};

    fn provider_index(index: usize) -> ProviderIndex {
        let name = format!("index-{index:08}");
        ProviderRegistry::from_names((0..=index).map(|value| format!("index-{value:08}")))
            .get(&name)
            .unwrap()
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
            id: id.to_string(),
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

    fn snapshot(
        default: CompiledDefaultDecision,
        rules: Vec<PolicyRulePlan>,
    ) -> CompiledPolicySnapshot {
        CompiledPolicySnapshot::from_plan(PolicyPlan { default, rules })
    }

    fn evaluate<'a>(
        snapshot: &'a CompiledPolicySnapshot,
        url: &str,
        headers: &HeaderMap,
    ) -> PolicyEvaluation<'a> {
        snapshot.evaluate(
            &canonicalize_http_url(url).unwrap(),
            "192.0.2.10".parse().unwrap(),
            &Method::GET,
            headers,
            |_| false,
        )
    }

    fn evaluate_single_rule(
        rule: PolicyRulePlan,
        peer: &str,
        method: &Method,
        headers: &HeaderMap,
    ) -> PolicyOutcome {
        snapshot(CompiledDefaultDecision::Deny, vec![rule])
            .evaluate(
                &canonicalize_http_url("https://example.com/").unwrap(),
                peer.parse().unwrap(),
                method,
                headers,
                |_| false,
            )
            .outcome
    }

    #[test]
    fn canonical_url_matching_keeps_schemes_exact() {
        let snapshot = snapshot(
            CompiledDefaultDecision::Deny,
            vec![rule(
                "https-only",
                CompiledRuleDecision::Allow,
                "https://example.com/**",
            )],
        );
        assert_eq!(
            evaluate(&snapshot, "HTTPS://EXAMPLE.COM/path", &HeaderMap::new()).outcome,
            PolicyOutcome::Allow
        );
        assert_eq!(
            evaluate(&snapshot, "http://example.com/path", &HeaderMap::new()).outcome,
            PolicyOutcome::Deny
        );
    }

    #[test]
    fn client_cidr_uses_peer_and_ignores_forwarded_headers() {
        let mut allow = rule(
            "local",
            CompiledRuleDecision::Allow,
            "https://example.com/**",
        );
        allow.client_cidrs = vec![IpNet::from_str("192.0.2.0/24").unwrap()];
        let snapshot = snapshot(CompiledDefaultDecision::Deny, vec![allow]);
        let mut headers = HeaderMap::new();
        headers.insert("forwarded", HeaderValue::from_static("for=192.0.2.10"));
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.0.2.10"));
        let result = snapshot.evaluate(
            &canonicalize_http_url("https://example.com/path").unwrap(),
            "198.51.100.4".parse().unwrap(),
            &Method::GET,
            &headers,
            |_| false,
        );
        assert_eq!(result.outcome, PolicyOutcome::Deny);
    }

    #[test]
    fn ipv4_mapped_peer_matches_ipv4_allow_cidr() {
        let mut allow = rule(
            "mapped-allow",
            CompiledRuleDecision::Allow,
            "https://example.com/**",
        );
        allow.client_cidrs = vec![IpNet::from_str("192.0.2.0/24").unwrap()];
        let snapshot = snapshot(CompiledDefaultDecision::Deny, vec![allow]);
        let result = snapshot.evaluate(
            &canonicalize_http_url("https://example.com/").unwrap(),
            "::ffff:192.0.2.44".parse().unwrap(),
            &Method::GET,
            &HeaderMap::new(),
            |_| false,
        );
        assert_eq!(result.outcome, PolicyOutcome::Allow);
    }

    #[test]
    fn ipv4_mapped_peer_cannot_bypass_ipv4_deny_into_allow_default() {
        let mut deny = rule(
            "mapped-deny",
            CompiledRuleDecision::Deny,
            "https://example.com/**",
        );
        deny.client_cidrs = vec![IpNet::from_str("192.0.2.0/24").unwrap()];
        let snapshot = snapshot(CompiledDefaultDecision::Allow, vec![deny]);
        let result = snapshot.evaluate(
            &canonicalize_http_url("https://example.com/").unwrap(),
            "::ffff:192.0.2.44".parse().unwrap(),
            &Method::GET,
            &HeaderMap::new(),
            |_| false,
        );
        assert_eq!(result.outcome, PolicyOutcome::Deny);
        assert_eq!(result.matched.as_ref().unwrap().id(), "mapped-deny");
    }

    #[test]
    fn native_ipv6_cidr_matches_only_native_ipv6_peers_in_range() {
        let mut allow = rule(
            "native-v6",
            CompiledRuleDecision::Allow,
            "https://example.com/**",
        );
        allow.client_cidrs = vec![IpNet::from_str("2001:db8::/32").unwrap()];

        for (peer, expected) in [
            ("2001:db8::1", PolicyOutcome::Allow),
            ("2001:dba::1", PolicyOutcome::Deny),
            ("::ffff:192.0.2.44", PolicyOutcome::Deny),
        ] {
            assert_eq!(
                evaluate_single_rule(allow.clone(), peer, &Method::GET, &HeaderMap::new()),
                expected,
                "peer {peer}"
            );
        }
    }

    #[test]
    fn raw_duplicate_values_are_compared_individually() {
        let name = HeaderName::from_static("x-scope");
        let mut allow = rule(
            "headers",
            CompiledRuleDecision::Allow,
            "https://example.com/**",
        );
        allow.headers.all.push(HeaderValuePredicatePlan {
            name: name.clone(),
            values: vec![HeaderValue::from_static("second")],
        });
        allow.headers.none.push(HeaderValuePredicatePlan {
            name: name.clone(),
            values: vec![HeaderValue::from_static("blocked,other")],
        });
        let snapshot = snapshot(CompiledDefaultDecision::Deny, vec![allow]);
        let mut headers = HeaderMap::new();
        headers.append(name.clone(), HeaderValue::from_static("first"));
        headers.append(name, HeaderValue::from_static("second"));
        assert_eq!(
            evaluate(&snapshot, "https://example.com/", &headers).outcome,
            PolicyOutcome::Allow
        );
    }

    #[test]
    fn extracted_inbound_credentials_participate_only_in_presence() {
        let inbound = HeaderName::from_static("x-workload-identity");
        let mut allow = rule(
            "inbound",
            CompiledRuleDecision::Allow,
            "https://example.com/**",
        );
        allow.headers.present_all.push(inbound.clone());
        let snapshot = snapshot(CompiledDefaultDecision::Deny, vec![allow]);
        let url = canonicalize_http_url("https://example.com/").unwrap();
        let result = snapshot.evaluate(
            &url,
            "192.0.2.10".parse().unwrap(),
            &Method::GET,
            &HeaderMap::new(),
            |name| name == inbound,
        );
        assert_eq!(result.outcome, PolicyOutcome::Allow);
    }

    #[test]
    fn header_predicate_and_method_parity_corpus() {
        let first = HeaderName::from_static("x-first");
        let second = HeaderName::from_static("x-second");
        let mut both_headers = HeaderMap::new();
        both_headers.insert(first.clone(), HeaderValue::from_static("allow"));
        both_headers.insert(second.clone(), HeaderValue::from_static("present"));

        let mut absent_any = rule(
            "absent-any",
            CompiledRuleDecision::Allow,
            "https://example.com/**",
        );
        absent_any.headers.absent_any = vec![first.clone(), second.clone()];
        assert_eq!(
            evaluate_single_rule(
                absent_any.clone(),
                "192.0.2.10",
                &Method::GET,
                &both_headers
            ),
            PolicyOutcome::Deny
        );
        let mut one_absent = both_headers.clone();
        one_absent.remove(&second);
        assert_eq!(
            evaluate_single_rule(absent_any, "192.0.2.10", &Method::GET, &one_absent),
            PolicyOutcome::Allow
        );

        let mut present_all = rule(
            "present-all",
            CompiledRuleDecision::Allow,
            "https://example.com/**",
        );
        present_all.headers.present_all = vec![first.clone(), second.clone()];
        assert_eq!(
            evaluate_single_rule(present_all.clone(), "192.0.2.10", &Method::GET, &one_absent,),
            PolicyOutcome::Deny
        );
        assert_eq!(
            evaluate_single_rule(present_all, "192.0.2.10", &Method::GET, &both_headers),
            PolicyOutcome::Allow
        );

        let value_predicate = HeaderValuePredicatePlan {
            name: first.clone(),
            values: vec![HeaderValue::from_static("allow")],
        };
        let mut all = rule("all", CompiledRuleDecision::Allow, "https://example.com/**");
        all.headers.all.push(value_predicate.clone());
        assert_eq!(
            evaluate_single_rule(all.clone(), "192.0.2.10", &Method::GET, &HeaderMap::new()),
            PolicyOutcome::Deny
        );
        assert_eq!(
            evaluate_single_rule(all, "192.0.2.10", &Method::GET, &both_headers),
            PolicyOutcome::Allow
        );

        let mut none = rule(
            "none",
            CompiledRuleDecision::Allow,
            "https://example.com/**",
        );
        none.headers.none.push(value_predicate);
        assert_eq!(
            evaluate_single_rule(none.clone(), "192.0.2.10", &Method::GET, &both_headers),
            PolicyOutcome::Deny
        );
        assert_eq!(
            evaluate_single_rule(none, "192.0.2.10", &Method::GET, &HeaderMap::new()),
            PolicyOutcome::Allow
        );

        let mut method_and_header = rule(
            "method-and-header",
            CompiledRuleDecision::Allow,
            "https://example.com/**",
        );
        method_and_header.methods.push(Method::GET);
        method_and_header.headers.present_all.push(first);
        assert_eq!(
            evaluate_single_rule(
                method_and_header.clone(),
                "192.0.2.10",
                &Method::GET,
                &both_headers,
            ),
            PolicyOutcome::Allow
        );
        assert_eq!(
            evaluate_single_rule(
                method_and_header.clone(),
                "192.0.2.10",
                &Method::from_bytes(b"get").unwrap(),
                &both_headers,
            ),
            PolicyOutcome::Allow
        );
        assert_eq!(
            evaluate_single_rule(
                method_and_header.clone(),
                "192.0.2.10",
                &Method::POST,
                &both_headers,
            ),
            PolicyOutcome::Deny
        );
        assert_eq!(
            evaluate_single_rule(
                method_and_header,
                "192.0.2.10",
                &Method::GET,
                &HeaderMap::new(),
            ),
            PolicyOutcome::Deny
        );
    }

    #[test]
    fn delegate_resume_cursor_reaches_later_rule_then_default() {
        let mut delegate = rule(
            "approval",
            CompiledRuleDecision::Delegate,
            "https://example.com/**",
        );
        delegate.authorization_provider = Some("provider".to_string());
        delegate.description = Some("approval step".to_string());
        let allow = rule(
            "fallback",
            CompiledRuleDecision::Allow,
            "https://example.com/**",
        );
        let snapshot = snapshot(CompiledDefaultDecision::Deny, vec![delegate, allow]);
        let url = canonicalize_http_url("https://example.com/path").unwrap();
        let first = snapshot.evaluate(
            &url,
            "192.0.2.10".parse().unwrap(),
            &Method::GET,
            &HeaderMap::new(),
            |_| false,
        );
        assert_eq!(first.outcome, PolicyOutcome::Delegate);
        let matched = first.matched.unwrap();
        assert_eq!(
            (matched.index(), matched.id(), matched.description()),
            (0, "approval", Some("approval step"))
        );
        let resumed = matched.resume_cursor().resume(
            &url,
            "192.0.2.10".parse().unwrap(),
            &Method::GET,
            &HeaderMap::new(),
            |_| false,
        );
        assert_eq!(resumed.outcome, PolicyOutcome::Allow);
        assert_eq!(resumed.matched.as_ref().unwrap().id(), "fallback");
        let default = resumed.matched.unwrap().resume_cursor().resume(
            &url,
            "192.0.2.10".parse().unwrap(),
            &Method::GET,
            &HeaderMap::new(),
            |_| false,
        );
        assert_eq!(default.outcome, PolicyOutcome::Deny);
        assert!(default.matched.is_none());
    }

    #[test]
    fn skipped_rules_keep_the_evaluation_plan_at_the_starting_cursor() {
        let skipped = rule(
            "skipped",
            CompiledRuleDecision::Deny,
            "https://other.example/**",
        );
        let matched = rule(
            "matched",
            CompiledRuleDecision::Allow,
            "https://example.com/**",
        );
        let snapshot = snapshot(CompiledDefaultDecision::Deny, vec![skipped, matched]);
        let evaluation = evaluate(&snapshot, "https://example.com/path", &HeaderMap::new());

        assert_eq!(evaluation.matched.as_ref().unwrap().index(), 1);
        assert_eq!(
            evaluation
                .wire_body_plan()
                .resolve(snapshot.wire_body_plan_brand, &[101, 202, 303]),
            Some(101)
        );
    }

    #[test]
    fn resumed_cursor_owns_its_branded_plan_independent_of_later_match() {
        let delegate = rule(
            "delegate",
            CompiledRuleDecision::Delegate,
            "https://example.com/**",
        );
        let skipped = rule(
            "skipped",
            CompiledRuleDecision::Deny,
            "https://other.example/**",
        );
        let allow = rule(
            "allow",
            CompiledRuleDecision::Allow,
            "https://example.com/**",
        );
        let active = snapshot(
            CompiledDefaultDecision::Deny,
            vec![delegate, skipped, allow],
        );
        let url = canonicalize_http_url("https://example.com/path").unwrap();
        let first = active.evaluate(
            &url,
            "192.0.2.10".parse().unwrap(),
            &Method::GET,
            &HeaderMap::new(),
            |_| false,
        );
        assert_eq!(
            first
                .wire_body_plan()
                .resolve(active.wire_body_plan_brand, &[11, 22, 33, 44]),
            Some(11)
        );
        let resumed = first.matched.unwrap().resume_cursor().resume(
            &url,
            "192.0.2.10".parse().unwrap(),
            &Method::GET,
            &HeaderMap::new(),
            |_| false,
        );
        assert_eq!(resumed.matched.as_ref().unwrap().index(), 2);
        assert_eq!(
            resumed
                .wire_body_plan()
                .resolve(active.wire_body_plan_brand, &[11, 22, 33, 44]),
            Some(22)
        );

        let foreign = snapshot(
            CompiledDefaultDecision::Deny,
            vec![rule(
                "foreign",
                CompiledRuleDecision::Allow,
                "https://example.com/**",
            )],
        );
        assert_eq!(
            resumed
                .wire_body_plan()
                .resolve(foreign.wire_body_plan_brand, &[22, 0]),
            None
        );
    }

    #[test]
    fn continuation_is_bound_to_its_originating_snapshot() {
        let first = rule(
            "delegate-old",
            CompiledRuleDecision::Delegate,
            "https://example.com/**",
        );
        let old_allow = rule(
            "old-allow",
            CompiledRuleDecision::Allow,
            "https://example.com/**",
        );
        let old = snapshot(CompiledDefaultDecision::Deny, vec![first, old_allow]);
        let url = canonicalize_http_url("https://example.com/").unwrap();
        let old_match = old
            .evaluate(
                &url,
                "192.0.2.10".parse().unwrap(),
                &Method::GET,
                &HeaderMap::new(),
                |_| false,
            )
            .matched
            .unwrap();
        let old_continuation = old_match.resume_cursor();

        let replacement = snapshot(
            CompiledDefaultDecision::Deny,
            vec![rule(
                "new-deny",
                CompiledRuleDecision::Deny,
                "https://example.com/**",
            )],
        );
        assert_eq!(
            replacement
                .evaluate(
                    &url,
                    "192.0.2.10".parse().unwrap(),
                    &Method::GET,
                    &HeaderMap::new(),
                    |_| false,
                )
                .outcome,
            PolicyOutcome::Deny
        );

        let resumed = old_continuation.resume(
            &url,
            "192.0.2.10".parse().unwrap(),
            &Method::GET,
            &HeaderMap::new(),
            |_| false,
        );
        assert_eq!(resumed.outcome, PolicyOutcome::Allow);
        assert_eq!(resumed.matched.as_ref().unwrap().id(), "old-allow");
    }

    #[test]
    fn effects_are_ordered_and_when_uses_original_presence() {
        let x = HeaderName::from_static("x-order");
        let y = HeaderName::from_static("x-original");
        let effects = vec![
            HeaderEffectPlan::Append {
                when: CompiledHeaderEffectWhen::IfAbsent,
                name: x.clone(),
                values: vec![HeaderValue::from_static("first")],
            },
            HeaderEffectPlan::Set {
                when: CompiledHeaderEffectWhen::Always,
                name: x.clone(),
                values: vec![HeaderValue::from_static("second")],
            },
            HeaderEffectPlan::Append {
                when: CompiledHeaderEffectWhen::IfAbsent,
                name: x.clone(),
                values: vec![HeaderValue::from_static("third")],
            },
            HeaderEffectPlan::Set {
                when: CompiledHeaderEffectWhen::Always,
                name: y.clone(),
                values: vec![HeaderValue::from_static("added")],
            },
            HeaderEffectPlan::Remove {
                when: CompiledHeaderEffectWhen::IfPresent,
                name: y.clone(),
            },
        ];
        let mut headers = HeaderMap::new();
        apply_header_effects(&effects, &mut headers).unwrap();
        let values: Vec<_> = headers
            .get_all(&x)
            .iter()
            .map(|value| value.as_bytes())
            .collect();
        assert_eq!(values, vec![b"second".as_slice(), b"third".as_slice()]);
        assert_eq!(headers.get(&y).unwrap(), "added");
    }

    #[test]
    fn replacement_is_byte_exact_for_each_raw_field() {
        let name = HeaderName::from_static("x-bytes");
        let effects = [HeaderEffectPlan::Replace {
            when: CompiledHeaderEffectWhen::Always,
            name: name.clone(),
            search: "a".to_string(),
            replace: "z".to_string(),
        }];
        let mut headers = HeaderMap::new();
        headers.append(name.clone(), HeaderValue::from_bytes(b"a\x80a").unwrap());
        headers.append(name.clone(), HeaderValue::from_static("ba"));
        apply_header_effects(&effects, &mut headers).unwrap();
        let values: Vec<_> = headers
            .get_all(&name)
            .iter()
            .map(|value| value.as_bytes())
            .collect();
        assert_eq!(values, vec![b"z\x80z".as_slice(), b"bz".as_slice()]);
    }

    #[test]
    fn oversized_set_is_rejected_without_mutation() {
        let name = HeaderName::from_static("x-value");
        let effects = [HeaderEffectPlan::Set {
            when: CompiledHeaderEffectWhen::Always,
            name: name.clone(),
            values: vec![HeaderValue::from_bytes(&vec![b'x'; MAX_HEADER_FIELD_BYTES + 1]).unwrap()],
        }];
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_static("original"));
        let original = headers.clone();
        assert_eq!(
            apply_header_effects(&effects, &mut headers),
            Err(HeaderEffectError::FieldLimit)
        );
        assert_eq!(headers, original);
    }

    #[test]
    fn effects_may_remove_or_ignore_oversized_inbound_fields() {
        let name = HeaderName::from_static("x-oversized");
        let oversized = HeaderValue::from_bytes(&vec![b'x'; MAX_HEADER_FIELD_BYTES + 1]).unwrap();

        let mut unchanged = HeaderMap::new();
        unchanged.insert(name.clone(), oversized.clone());
        let original = unchanged.clone();
        apply_header_effects(&[], &mut unchanged).unwrap();
        assert_eq!(unchanged, original);

        let effects = [HeaderEffectPlan::Remove {
            when: CompiledHeaderEffectWhen::Always,
            name: name.clone(),
        }];
        let mut removed = HeaderMap::new();
        removed.insert(name.clone(), oversized.clone());
        apply_header_effects(&effects, &mut removed).unwrap();
        assert!(!removed.contains_key(&name));

        let unrelated = HeaderName::from_static("x-unrelated");
        let effects = [HeaderEffectPlan::Set {
            when: CompiledHeaderEffectWhen::Always,
            name: unrelated.clone(),
            values: vec![HeaderValue::from_static("changed")],
        }];
        let mut changed = original.clone();
        apply_header_effects(&effects, &mut changed).unwrap();
        assert_eq!(changed.get(&name).unwrap(), &oversized);
        assert_eq!(changed.get(unrelated).unwrap(), "changed");

        let effects = [HeaderEffectPlan::Append {
            when: CompiledHeaderEffectWhen::Always,
            name,
            values: vec![HeaderValue::from_static("changed")],
        }];
        let mut rejected = original.clone();
        assert_eq!(
            apply_header_effects(&effects, &mut rejected),
            Err(HeaderEffectError::FieldLimit)
        );
        assert_eq!(rejected, original);
    }

    #[test]
    fn shrinking_replace_can_remediate_an_oversized_inbound_field() {
        let name = HeaderName::from_static("x-shrink");
        let oversized = HeaderValue::from_bytes(&vec![b'a'; MAX_HEADER_FIELD_BYTES + 1]).unwrap();
        let effects = [HeaderEffectPlan::Replace {
            when: CompiledHeaderEffectWhen::Always,
            name: name.clone(),
            search: "aa".to_string(),
            replace: String::new(),
        }];
        let mut headers = HeaderMap::new();
        headers.insert(name.clone(), oversized);

        apply_header_effects(&effects, &mut headers).unwrap();

        assert_eq!(headers.get(name).unwrap().as_bytes(), b"a");
    }

    #[test]
    fn append_aggregate_limit_is_rejected_without_mutation() {
        let existing = HeaderName::from_static("x-existing");
        let full_field = HeaderValue::from_bytes(&vec![b'x'; MAX_HEADER_FIELD_BYTES]).unwrap();
        let mut headers = HeaderMap::new();
        for _ in 0..(MAX_HEADER_VALUE_BYTES / MAX_HEADER_FIELD_BYTES) {
            headers.append(existing.clone(), full_field.clone());
        }
        let original = headers.clone();
        let effects = [HeaderEffectPlan::Append {
            when: CompiledHeaderEffectWhen::Always,
            name: existing,
            values: vec![HeaderValue::from_static("x")],
        }];
        assert_eq!(
            apply_header_effects(&effects, &mut headers),
            Err(HeaderEffectError::AggregateLimit)
        );
        assert_eq!(headers, original);
    }

    #[test]
    fn changed_aggregate_limit_is_cumulative_across_touched_names() {
        let first = HeaderName::from_static("x-first-changed");
        let second = HeaderName::from_static("x-second-changed");
        let full_field = HeaderValue::from_bytes(&vec![b'x'; MAX_HEADER_FIELD_BYTES]).unwrap();
        let effects = [
            HeaderEffectPlan::Set {
                when: CompiledHeaderEffectWhen::Always,
                name: first,
                values: vec![full_field.clone(); 9],
            },
            HeaderEffectPlan::Set {
                when: CompiledHeaderEffectWhen::Always,
                name: second,
                values: vec![full_field; 8],
            },
        ];
        let mut headers = HeaderMap::new();

        assert_eq!(
            apply_header_effects(&effects, &mut headers),
            Err(HeaderEffectError::AggregateLimit)
        );
        assert!(headers.is_empty());
    }

    #[test]
    fn retargeted_name_replaces_its_prior_aggregate_contribution() {
        let first = HeaderName::from_static("x-first-retargeted");
        let second = HeaderName::from_static("x-second-retargeted");
        let full_field = HeaderValue::from_bytes(&vec![b'x'; MAX_HEADER_FIELD_BYTES]).unwrap();
        let effects = [
            HeaderEffectPlan::Set {
                when: CompiledHeaderEffectWhen::Always,
                name: first.clone(),
                values: vec![full_field.clone(); 9],
            },
            HeaderEffectPlan::Set {
                when: CompiledHeaderEffectWhen::Always,
                name: first.clone(),
                values: vec![full_field.clone()],
            },
            HeaderEffectPlan::Set {
                when: CompiledHeaderEffectWhen::Always,
                name: second.clone(),
                values: vec![full_field; 15],
            },
        ];
        let mut headers = HeaderMap::new();

        apply_header_effects(&effects, &mut headers).unwrap();

        assert_eq!(headers.get_all(first).iter().count(), 1);
        assert_eq!(headers.get_all(second).iter().count(), 15);
    }

    #[test]
    fn set_replaces_a_name_that_occupies_the_aggregate_boundary() {
        let name = HeaderName::from_static("x-full");
        let full_field = HeaderValue::from_bytes(&vec![b'x'; MAX_HEADER_FIELD_BYTES]).unwrap();
        let mut headers = HeaderMap::new();
        for _ in 0..(MAX_HEADER_VALUE_BYTES / MAX_HEADER_FIELD_BYTES) {
            headers.append(name.clone(), full_field.clone());
        }
        let effects = [HeaderEffectPlan::Set {
            when: CompiledHeaderEffectWhen::Always,
            name: name.clone(),
            values: vec![HeaderValue::from_static("x")],
        }];
        apply_header_effects(&effects, &mut headers).unwrap();
        assert_eq!(headers.get_all(name).iter().count(), 1);
        assert_eq!(headers.values().next().unwrap(), "x");
    }

    #[test]
    fn replacement_aggregate_expansion_is_rejected_without_mutation() {
        let name = HeaderName::from_static("x-expand-many");
        let input = HeaderValue::from_bytes(&vec![b'a'; 30_000]).unwrap();
        let mut headers = HeaderMap::new();
        for _ in 0..20 {
            headers.append(name.clone(), input.clone());
        }
        let original = headers.clone();
        let effects = [HeaderEffectPlan::Replace {
            when: CompiledHeaderEffectWhen::Always,
            name,
            search: "a".to_string(),
            replace: "aa".to_string(),
        }];
        assert_eq!(
            apply_header_effects(&effects, &mut headers),
            Err(HeaderEffectError::AggregateLimit)
        );
        assert_eq!(headers, original);
    }

    #[test]
    fn replacement_expansion_rolls_back_prior_staged_effects() {
        let changed = HeaderName::from_static("x-changed");
        let expanded = HeaderName::from_static("x-expanded");
        let effects = [
            HeaderEffectPlan::Set {
                when: CompiledHeaderEffectWhen::Always,
                name: changed.clone(),
                values: vec![HeaderValue::from_static("changed")],
            },
            HeaderEffectPlan::Replace {
                when: CompiledHeaderEffectWhen::Always,
                name: expanded.clone(),
                search: "a".to_string(),
                replace: "aa".to_string(),
            },
        ];
        let mut headers = HeaderMap::new();
        headers.insert(changed, HeaderValue::from_static("original"));
        headers.insert(
            expanded,
            HeaderValue::from_bytes(&vec![b'a'; (MAX_HEADER_FIELD_BYTES / 2) + 1]).unwrap(),
        );
        let original = headers.clone();
        assert_eq!(
            apply_header_effects(&effects, &mut headers),
            Err(HeaderEffectError::FieldLimit)
        );
        assert_eq!(headers, original);
    }

    #[test]
    fn deny_and_delegate_keep_stable_metadata() {
        let deny = rule(
            "deny-rule",
            CompiledRuleDecision::Deny,
            "https://denied.example/**",
        );
        let mut delegate = rule(
            "delegate-rule",
            CompiledRuleDecision::Delegate,
            "https://delegate.example/**",
        );
        delegate.authorization_provider = Some("approval".to_string());
        let snapshot = snapshot(CompiledDefaultDecision::Allow, vec![deny, delegate]);
        let denied = evaluate(&snapshot, "https://denied.example/", &HeaderMap::new());
        assert_eq!(denied.outcome, PolicyOutcome::Deny);
        let matched = denied.matched.as_ref().unwrap();
        assert_eq!((matched.index(), matched.id()), (0, "deny-rule"));
        let delegated = evaluate(&snapshot, "https://delegate.example/", &HeaderMap::new());
        assert_eq!(delegated.outcome, PolicyOutcome::Delegate);
        let matched = delegated.matched.unwrap();
        assert_eq!(
            (
                matched.index(),
                matched.id(),
                matched.authorization_provider()
            ),
            (1, "delegate-rule", Some(provider_index(0)))
        );
    }

    #[test]
    fn activation_resolves_canonical_registries_and_preserves_action_order() {
        let mut bound = rule(
            "bound",
            CompiledRuleDecision::Allow,
            "https://example.com/**",
        );
        bound.authorization_provider = Some("provider-marker".to_string());
        bound.redaction_profile = Some("profile-marker".to_string());
        bound.credential_actions = vec![
            CredentialActionPlan::Bearer {
                credential: "bearer-marker".to_string(),
            },
            CredentialActionPlan::Basic {
                username: "buildbot".to_string(),
                password_credential: "password-marker".to_string(),
            },
            CredentialActionPlan::CustomHeader {
                header: HeaderName::from_static("x-api-key"),
                credential: "custom-marker".to_string(),
            },
        ];
        let provider_registry = ProviderRegistry::from_names(["provider-marker".to_string()]);
        let profile_registry = RedactionProfileRegistry::from_names(["profile-marker".to_string()]);
        let credential_registry = CredentialSourceRegistry::from_names([
            "custom-marker".to_string(),
            "password-marker".to_string(),
            "bearer-marker".to_string(),
        ]);
        let activation = CompiledPolicySnapshot::activate(
            PolicyPlan {
                default: CompiledDefaultDecision::Deny,
                rules: vec![bound],
            },
            &provider_registry,
            &profile_registry,
            &credential_registry,
        )
        .unwrap();
        let (snapshot, bindings) = activation.into_parts();
        let matched = evaluate(&snapshot, "https://example.com/", &HeaderMap::new())
            .matched
            .unwrap();

        assert_eq!(
            matched.authorization_provider(),
            provider_registry.get("provider-marker")
        );
        assert_eq!(
            matched.redaction_profile(),
            profile_registry.get("profile-marker")
        );
        assert_eq!(
            matched.credential_actions(),
            &[
                ResolvedCredentialAction::Bearer {
                    source: credential_registry.get("bearer-marker").unwrap(),
                },
                ResolvedCredentialAction::Basic {
                    username: "buildbot".to_string(),
                    source: credential_registry.get("password-marker").unwrap(),
                },
                ResolvedCredentialAction::CustomHeader {
                    header: HeaderName::from_static("x-api-key"),
                    source: credential_registry.get("custom-marker").unwrap(),
                },
            ]
        );
        assert_eq!(bindings.provider_count, provider_registry.len());
        assert_eq!(bindings.redaction_profile_count, profile_registry.len());
        assert_eq!(bindings.credential_count, credential_registry.len());
        assert_eq!(bindings.rules.len(), 1);
        assert_eq!(
            bindings.rules[0],
            ResolvedRuleBindings {
                authorization_provider: provider_registry.get("provider-marker"),
                redaction_profile: profile_registry.get("profile-marker"),
                credentials: vec![
                    credential_registry.get("bearer-marker").unwrap(),
                    credential_registry.get("password-marker").unwrap(),
                    credential_registry.get("custom-marker").unwrap(),
                ]
                .into_boxed_slice(),
            }
        );
        let rendered = format!("{snapshot:?}");
        for marker in [
            "provider-marker",
            "profile-marker",
            "bearer-marker",
            "password-marker",
            "custom-marker",
        ] {
            assert!(!rendered.contains(marker));
        }
    }

    #[test]
    fn activation_rejects_each_unknown_reference_with_indices_only() {
        let providers = ProviderRegistry::from_names([]);
        let profiles = RedactionProfileRegistry::from_names([]);
        let credentials = CredentialSourceRegistry::from_names([]);
        let mut provider = rule(
            "provider",
            CompiledRuleDecision::Delegate,
            "https://example.com/**",
        );
        provider.authorization_provider = Some("missing-provider-marker".to_string());
        let error = CompiledPolicySnapshot::activate(
            PolicyPlan {
                default: CompiledDefaultDecision::Deny,
                rules: vec![provider],
            },
            &providers,
            &profiles,
            &credentials,
        )
        .unwrap_err();
        assert_eq!(
            error,
            PolicyActivationError::AuthorizationProvider { rule_index: 0 }
        );
        assert!(!format!("{error:?} {error}").contains("missing-provider-marker"));

        let mut profile = rule(
            "profile",
            CompiledRuleDecision::Allow,
            "https://example.com/**",
        );
        profile.redaction_profile = Some("missing-profile-marker".to_string());
        assert_eq!(
            CompiledPolicySnapshot::activate(
                PolicyPlan {
                    default: CompiledDefaultDecision::Deny,
                    rules: vec![profile],
                },
                &providers,
                &profiles,
                &credentials,
            )
            .unwrap_err(),
            PolicyActivationError::RedactionProfile { rule_index: 0 }
        );

        let mut credential = rule(
            "credential",
            CompiledRuleDecision::Allow,
            "https://example.com/**",
        );
        credential.credential_actions = vec![CredentialActionPlan::Bearer {
            credential: "missing-credential-marker".to_string(),
        }];
        assert_eq!(
            CompiledPolicySnapshot::activate(
                PolicyPlan {
                    default: CompiledDefaultDecision::Deny,
                    rules: vec![credential],
                },
                &providers,
                &profiles,
                &credentials,
            )
            .unwrap_err(),
            PolicyActivationError::CredentialSource {
                rule_index: 0,
                action_index: 0,
            }
        );
    }
}
