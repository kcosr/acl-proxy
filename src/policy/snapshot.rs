use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::Method;

use crate::config::v3_compile::{
    CompiledDefaultDecision, CompiledHeaderEffectWhen, CompiledRuleDecision, CredentialActionPlan,
    HeaderEffectPlan, HeaderPredicatesPlan, PolicyPlan, PolicyRulePlan,
};
use crate::url::CanonicalUrl;

const MAX_HEADER_FIELD_BYTES: usize = 64 * 1024;
const MAX_HEADER_VALUE_BYTES: usize = 1024 * 1024;

/// Immutable, generation-owned policy compiled from the product configuration.
pub(crate) struct CompiledPolicySnapshot {
    default: CompiledDefaultDecision,
    rules: Box<[PolicyRulePlan]>,
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
}

pub(crate) struct PolicyRuleMatch<'snapshot> {
    snapshot: &'snapshot CompiledPolicySnapshot,
    index: usize,
    rule: &'snapshot PolicyRulePlan,
}

impl CompiledPolicySnapshot {
    pub(crate) fn from_plan(plan: PolicyPlan) -> Self {
        Self {
            default: plan.default,
            rules: plan.rules.into_boxed_slice(),
        }
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
                };
            }
        }

        PolicyEvaluation {
            outcome: match self.default {
                CompiledDefaultDecision::Allow => PolicyOutcome::Allow,
                CompiledDefaultDecision::Deny => PolicyOutcome::Deny,
            },
            matched: None,
        }
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

    pub(crate) fn authorization_provider(&self) -> Option<&'snapshot str> {
        self.rule.authorization_provider.as_deref()
    }

    pub(crate) fn redaction_profile(&self) -> Option<&'snapshot str> {
        self.rule.redaction_profile.as_deref()
    }

    pub(crate) fn request_header_effects(&self) -> &'snapshot [HeaderEffectPlan] {
        &self.rule.request_headers
    }

    pub(crate) fn response_header_effects(&self) -> &'snapshot [HeaderEffectPlan] {
        &self.rule.response_headers
    }

    pub(crate) fn credential_actions(&self) -> &'snapshot [CredentialActionPlan] {
        &self.rule.credential_actions
    }
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
    rule: &PolicyRulePlan,
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
pub(crate) fn apply_header_effects(
    effects: &[HeaderEffectPlan],
    headers: &mut HeaderMap,
) -> Result<(), HeaderEffectError> {
    validate_header_limits(headers)?;
    let original_presence: HashSet<HeaderName> = headers.keys().cloned().collect();
    let mut staged = headers.clone();

    for effect in effects {
        let (when, name) = effect_when_and_name(effect);
        let originally_present = original_presence.contains(name);
        let applies = match when {
            CompiledHeaderEffectWhen::Always => true,
            CompiledHeaderEffectWhen::IfPresent => originally_present,
            CompiledHeaderEffectWhen::IfAbsent => !originally_present,
        };
        if !applies {
            validate_header_limits(&staged)?;
            continue;
        }

        match effect {
            HeaderEffectPlan::Set { name, values, .. } => {
                let aggregate = aggregate_value_bytes(&staged)?;
                let previous = named_value_bytes(&staged, name)?;
                let replacement = effect_value_bytes(values)?;
                ensure_aggregate_limit(
                    aggregate
                        .checked_sub(previous)
                        .and_then(|value| value.checked_add(replacement))
                        .ok_or(HeaderEffectError::SizeOverflow)?,
                )?;
                staged.remove(name);
                for value in values {
                    staged.append(name.clone(), value.clone());
                }
            }
            HeaderEffectPlan::Append { name, values, .. } => {
                let appended = effect_value_bytes(values)?;
                ensure_aggregate_limit(
                    aggregate_value_bytes(&staged)?
                        .checked_add(appended)
                        .ok_or(HeaderEffectError::SizeOverflow)?,
                )?;
                for value in values {
                    staged.append(name.clone(), value.clone());
                }
            }
            HeaderEffectPlan::Remove { name, .. } => {
                staged.remove(name);
            }
            HeaderEffectPlan::Replace {
                name,
                search,
                replace,
                ..
            } => replace_header_bytes(&mut staged, name, search.as_bytes(), replace.as_bytes())?,
        }
        validate_header_limits(&staged)?;
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
    name: &HeaderName,
    search: &[u8],
    replacement: &[u8],
) -> Result<(), HeaderEffectError> {
    if search.is_empty() {
        return Err(HeaderEffectError::InvalidValue);
    }
    let output_lengths: Vec<usize> = headers
        .get_all(name)
        .iter()
        .map(|value| replaced_len(value.as_bytes(), search, replacement))
        .collect::<Result<_, _>>()?;
    if output_lengths.is_empty() {
        return Ok(());
    }
    let replacement_total = checked_sum(output_lengths.iter().copied())?;
    let aggregate = aggregate_value_bytes(headers)?;
    let previous = named_value_bytes(headers, name)?;
    ensure_aggregate_limit(
        aggregate
            .checked_sub(previous)
            .and_then(|value| value.checked_add(replacement_total))
            .ok_or(HeaderEffectError::SizeOverflow)?,
    )?;

    let values: Vec<HeaderValue> = headers
        .get_all(name)
        .iter()
        .zip(output_lengths)
        .map(|(value, output_len)| {
            let replaced = replace_all(value.as_bytes(), search, replacement, output_len);
            HeaderValue::from_bytes(&replaced).map_err(|_| HeaderEffectError::InvalidValue)
        })
        .collect::<Result<_, _>>()?;
    headers.remove(name);
    for value in values {
        headers.append(name.clone(), value);
    }
    Ok(())
}

fn replaced_len(
    input: &[u8],
    search: &[u8],
    replacement: &[u8],
) -> Result<usize, HeaderEffectError> {
    let matches = nonoverlapping_match_count(input, search);
    let removed = matches
        .checked_mul(search.len())
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

fn nonoverlapping_match_count(mut input: &[u8], search: &[u8]) -> usize {
    let mut count = 0;
    while let Some(index) = find_subslice(input, search) {
        count += 1;
        input = &input[index + search.len()..];
    }
    count
}

fn replace_all(input: &[u8], search: &[u8], replacement: &[u8], output_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(output_len);
    let mut remainder = input;
    while let Some(index) = find_subslice(remainder, search) {
        output.extend_from_slice(&remainder[..index]);
        output.extend_from_slice(replacement);
        remainder = &remainder[index + search.len()..];
    }
    output.extend_from_slice(remainder);
    debug_assert_eq!(output.len(), output_len);
    output
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|candidate| candidate == needle)
}

fn validate_header_limits(headers: &HeaderMap) -> Result<(), HeaderEffectError> {
    for value in headers.values() {
        if value.as_bytes().len() > MAX_HEADER_FIELD_BYTES {
            return Err(HeaderEffectError::FieldLimit);
        }
    }
    ensure_aggregate_limit(aggregate_value_bytes(headers)?)
}

fn aggregate_value_bytes(headers: &HeaderMap) -> Result<usize, HeaderEffectError> {
    checked_sum(headers.values().map(|value| value.as_bytes().len()))
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ipnet::IpNet;

    use super::*;
    use crate::config::v3_compile::{HeaderValuePredicatePlan, PolicyRulePlan};
    use crate::url::{canonicalize_http_url, CompiledUrlPattern};

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
    fn append_aggregate_limit_is_rejected_without_mutation() {
        let existing = HeaderName::from_static("x-existing");
        let appended = HeaderName::from_static("x-appended");
        let full_field = HeaderValue::from_bytes(&vec![b'x'; MAX_HEADER_FIELD_BYTES]).unwrap();
        let mut headers = HeaderMap::new();
        for _ in 0..(MAX_HEADER_VALUE_BYTES / MAX_HEADER_FIELD_BYTES) {
            headers.append(existing.clone(), full_field.clone());
        }
        let original = headers.clone();
        let effects = [HeaderEffectPlan::Append {
            when: CompiledHeaderEffectWhen::Always,
            name: appended,
            values: vec![HeaderValue::from_static("x")],
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
            (1, "delegate-rule", Some("approval"))
        );
    }
}
