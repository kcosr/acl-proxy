use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use http::header::{HeaderName, HeaderValue};
use http::HeaderMap;
use ipnet::IpNet;
use regex::{Regex, RegexBuilder};
use serde::Serialize;
use thiserror::Error;
use url::Url;

use crate::config::{
    EgressRequestHeaderActionConfig, ExternalAuthProfileConfigMap, HeaderActionConfig,
    HeaderActionKind, HeaderDirection, HeaderMatchValueConfig, HeaderWhen, MacroMap,
    MacroOverrideMap, MacroValues, PolicyConfig, PolicyDefaultAction, PolicyRuleAction,
    PolicyRuleConfig, PolicyRuleDirectConfig, PolicyRuleIncludeConfig, PolicyRuleTemplateConfig,
    RulesetMap, UrlEncVariants,
};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Policy macro not found: {name}{context}")]
    MacroNotFound { name: String, context: String },

    #[error("Policy ruleset not found: {name}")]
    RulesetNotFound { name: String },

    #[error("Invalid policy rule at index {index}: {reason}")]
    RuleInvalid { index: usize, reason: String },

    #[error("Invalid proxy.egress.request_header_actions entry at index {index}: {reason}")]
    EgressRequestHeaderActionInvalid { index: usize, reason: String },

    #[error("Failed to compile pattern for rule at index {index}: {source}")]
    PatternCompile {
        index: usize,
        #[source]
        source: regex::Error,
    },

    #[error("URL parsing failed: {0}")]
    UrlParse(String),
}

#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub matched: Option<MatchedRule>,
}

#[derive(Debug, Clone)]
pub struct MatchedRule {
    pub index: usize,
    pub action: PolicyRuleAction,
    pub pattern: Option<String>,
    pub description: Option<String>,
    pub rule_id: Option<String>,
    pub subnets: Vec<IpNet>,
    pub methods: Vec<String>,
    pub request_timeout_ms: Option<u64>,
    pub header_actions: Vec<CompiledHeaderAction>,
    pub external_auth_profile: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    default_action: PolicyDefaultAction,
    rules: Vec<CompiledRule>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    index: usize,
    action: PolicyRuleAction,
    pattern: Option<String>,
    regex: Option<Regex>,
    description: Option<String>,
    rule_id: Option<String>,
    subnets: Vec<IpNet>,
    methods: Vec<String>,
    headers_absent: Vec<HeaderName>,
    headers_match: Vec<CompiledHeaderMatch>,
    request_timeout_ms: Option<u64>,
    header_actions: Vec<CompiledHeaderAction>,
    external_auth_profile: Option<String>,
}

#[derive(Debug, Clone)]
struct CompiledHeaderMatch {
    name: HeaderName,
    values: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct ExpandedPolicy {
    default: PolicyDefaultAction,
    rules: Vec<ExpandedRule>,
}

#[derive(Debug, Clone)]
struct ExpandedRule {
    action: PolicyRuleAction,
    pattern: Option<String>,
    description: Option<String>,
    rule_id: Option<String>,
    subnets: Vec<IpNet>,
    methods: Vec<String>,
    headers_absent: Option<Vec<String>>,
    headers_match: Option<BTreeMap<String, Vec<String>>>,
    request_timeout_ms: Option<u64>,
    header_actions: Vec<HeaderActionConfig>,
    external_auth_profile: Option<String>,
}

struct TemplatePatterns<'a> {
    template: &'a PolicyRuleTemplateConfig,
    patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectivePolicy {
    pub default: PolicyDefaultAction,
    pub rules: Vec<EffectiveRule>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveRule {
    pub index: usize,
    pub action: PolicyRuleAction,
    pub pattern: Option<String>,
    pub description: Option<String>,
    pub rule_id: Option<String>,
    pub subnets: Vec<IpNet>,
    pub methods: Vec<String>,
    pub headers_absent: Vec<String>,
    pub headers_match: BTreeMap<String, Vec<String>>,
    pub request_timeout_ms: Option<u64>,
    pub header_actions: Vec<EffectiveHeaderAction>,
    pub external_auth: Option<EffectiveExternalAuth>,
}

#[derive(Debug, Clone)]
pub struct CompiledHeaderAction {
    pub direction: HeaderDirection,
    pub action: HeaderActionKind,
    pub name: HeaderName,
    pub values: Vec<HeaderValue>,
    pub when: HeaderWhen,
    pub search: Option<String>,
    pub replace: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveHeaderAction {
    pub direction: HeaderDirection,
    pub action: HeaderActionKind,
    pub name: String,
    pub values: Vec<String>,
    pub when: HeaderWhen,
    pub search: Option<String>,
    pub replace: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveExternalAuth {
    pub profile: String,
    pub timeout_ms: u64,
}

impl PolicyEngine {
    pub fn from_config(cfg: &PolicyConfig) -> Result<Self, PolicyError> {
        let expanded = expand_policy(cfg)?;
        let mut compiled_rules = Vec::with_capacity(expanded.rules.len());

        for (idx, rule) in expanded.rules.into_iter().enumerate() {
            let headers_absent = compile_headers_absent(rule.headers_absent.as_deref(), idx)?;
            let headers_match = compile_headers_match(rule.headers_match.as_ref(), idx)?;
            let header_actions = compile_header_actions(&rule.header_actions, idx)?;

            let regex = if let Some(ref pattern) = rule.pattern {
                let pattern_re = pattern_to_regex(pattern);
                Some(
                    RegexBuilder::new(&pattern_re)
                        .case_insensitive(true)
                        .build()
                        .map_err(|source| PolicyError::PatternCompile { index: idx, source })?,
                )
            } else {
                None
            };

            compiled_rules.push(CompiledRule {
                index: idx,
                action: rule.action,
                pattern: rule.pattern,
                regex,
                description: rule.description,
                rule_id: rule.rule_id,
                subnets: rule.subnets,
                methods: rule.methods,
                headers_absent,
                headers_match,
                request_timeout_ms: rule.request_timeout_ms,
                header_actions,
                external_auth_profile: rule.external_auth_profile,
            });
        }

        Ok(PolicyEngine {
            default_action: cfg.default,
            rules: compiled_rules,
        })
    }

    pub fn evaluate(
        &self,
        url_str: &str,
        client_ip: Option<&str>,
        method: Option<&str>,
        headers: &HeaderMap<HeaderValue>,
    ) -> PolicyDecision {
        self.evaluate_from(0, url_str, client_ip, method, headers)
    }

    pub fn evaluate_from(
        &self,
        start_index: usize,
        url_str: &str,
        client_ip: Option<&str>,
        method: Option<&str>,
        headers: &HeaderMap<HeaderValue>,
    ) -> PolicyDecision {
        let normalized_url = match normalize_url(url_str) {
            Ok(u) => u,
            Err(_) => {
                return PolicyDecision {
                    allowed: false,
                    matched: None,
                }
            }
        };

        let normalized_ip = normalize_client_ip(client_ip);
        let method_upper = method.map(|m| m.to_ascii_uppercase());

        for rule in self.rules.iter().skip(start_index) {
            if let Some(ref re) = rule.regex {
                if !re.is_match(&normalized_url) {
                    continue;
                }
            }

            if !rule.subnets.is_empty()
                && !client_in_any_subnet(normalized_ip.as_deref(), &rule.subnets)
            {
                continue;
            }

            if !rule.methods.is_empty() {
                let m = match method_upper.as_deref() {
                    Some(m) => m,
                    None => continue,
                };
                if !rule.methods.iter().any(|v| v == m) {
                    continue;
                }
            }

            if !rule.headers_absent.is_empty() && !any_header_absent(headers, &rule.headers_absent)
            {
                continue;
            }

            if !rule.headers_match.is_empty() && !all_headers_match(headers, &rule.headers_match) {
                continue;
            }

            let matched = MatchedRule {
                index: rule.index,
                action: rule.action,
                pattern: rule.pattern.clone(),
                description: rule.description.clone(),
                rule_id: rule.rule_id.clone(),
                subnets: rule.subnets.clone(),
                methods: rule.methods.clone(),
                request_timeout_ms: rule.request_timeout_ms,
                header_actions: rule.header_actions.clone(),
                external_auth_profile: rule.external_auth_profile.clone(),
            };

            let allowed = matches!(rule.action, PolicyRuleAction::Allow);

            return PolicyDecision {
                allowed,
                matched: Some(matched),
            };
        }

        PolicyDecision {
            allowed: matches!(self.default_action, PolicyDefaultAction::Allow),
            matched: None,
        }
    }

    pub fn is_allowed(&self, url_str: &str, client_ip: Option<&str>, method: Option<&str>) -> bool {
        let headers = HeaderMap::new();
        self.evaluate(url_str, client_ip, method, &headers).allowed
    }

    pub fn is_allowed_with_headers(
        &self,
        url_str: &str,
        client_ip: Option<&str>,
        method: Option<&str>,
        headers: &HeaderMap<HeaderValue>,
    ) -> bool {
        self.evaluate(url_str, client_ip, method, headers).allowed
    }
}

impl EffectivePolicy {
    pub fn from_config(cfg: &PolicyConfig) -> Result<Self, PolicyError> {
        let expanded = expand_policy(cfg)?;

        let rules = expanded
            .rules
            .into_iter()
            .enumerate()
            .map(|(index, rule)| {
                let header_actions = rule
                    .header_actions
                    .iter()
                    .map(|cfg| {
                        let values = cfg
                            .values
                            .clone()
                            .or_else(|| cfg.value.as_ref().map(|v| vec![v.clone()]))
                            .unwrap_or_default();

                        EffectiveHeaderAction {
                            direction: cfg.direction.clone(),
                            action: cfg.action.clone(),
                            name: cfg.name.to_ascii_lowercase(),
                            values,
                            when: cfg.when.clone(),
                            search: cfg.search.clone(),
                            replace: cfg.replace.clone(),
                        }
                    })
                    .collect();

                let external_auth = rule.external_auth_profile.as_ref().and_then(|name| {
                    cfg.external_auth_profiles
                        .get(name)
                        .map(|profile| EffectiveExternalAuth {
                            profile: name.clone(),
                            timeout_ms: profile.timeout_ms,
                        })
                });

                EffectiveRule {
                    index,
                    action: rule.action,
                    pattern: rule.pattern,
                    description: rule.description,
                    rule_id: rule.rule_id,
                    subnets: rule.subnets,
                    methods: rule.methods,
                    headers_absent: rule.headers_absent.unwrap_or_default(),
                    headers_match: rule.headers_match.unwrap_or_default(),
                    request_timeout_ms: rule.request_timeout_ms,
                    header_actions,
                    external_auth,
                }
            })
            .collect();

        Ok(EffectivePolicy {
            default: expanded.default,
            rules,
        })
    }
}

fn expand_policy(cfg: &PolicyConfig) -> Result<ExpandedPolicy, PolicyError> {
    let macros = &cfg.macros;
    let rulesets = &cfg.rulesets;
    let external_profiles: &ExternalAuthProfileConfigMap = &cfg.external_auth_profiles;

    let mut expanded_rules = Vec::new();

    for (index, rule) in cfg.rules.iter().enumerate() {
        match rule {
            PolicyRuleConfig::Direct(d) => {
                expand_direct_rule(d, macros, external_profiles, index, &mut expanded_rules)?
            }
            PolicyRuleConfig::Include(i) => expand_include_rule(
                i,
                macros,
                rulesets,
                external_profiles,
                index,
                &mut expanded_rules,
            )?,
        }
    }

    Ok(ExpandedPolicy {
        default: cfg.default,
        rules: expanded_rules,
    })
}

fn expand_direct_rule(
    rule: &PolicyRuleDirectConfig,
    macros: &MacroMap,
    external_profiles: &ExternalAuthProfileConfigMap,
    index: usize,
    out: &mut Vec<ExpandedRule>,
) -> Result<(), PolicyError> {
    let patterns = normalize_patterns(
        rule.pattern.as_ref(),
        rule.patterns.as_deref(),
        index,
        "policy rule",
        false,
    )?;
    reject_multi_pattern_rule_id(patterns.as_deref(), rule.rule_id.as_ref(), index)?;

    let methods = rule
        .methods
        .as_ref()
        .map(|m| m.as_slice().to_vec())
        .unwrap_or_default();

    let has_pattern = patterns.is_some();
    let has_subnets = !rule.subnets.is_empty();
    let has_methods = !methods.is_empty();
    let headers_absent = validate_headers_absent(rule.headers_absent.as_deref(), index)?;
    let has_headers_absent = headers_absent.is_some();
    let headers_match = validate_headers_match(rule.headers_match.as_ref(), index)?;
    let has_headers_match = headers_match.is_some();

    validate_rule_external_auth(
        rule.action,
        rule.external_auth_profile.as_ref(),
        external_profiles,
        index,
    )?;

    if !has_pattern && (has_subnets || has_methods || has_headers_absent || has_headers_match) {
        out.push(ExpandedRule {
            action: rule.action,
            pattern: None,
            description: rule.description.clone(),
            rule_id: rule.rule_id.clone(),
            subnets: rule.subnets.clone(),
            methods,
            headers_absent,
            headers_match,
            request_timeout_ms: rule.request_timeout_ms,
            header_actions: rule.header_actions.clone(),
            external_auth_profile: rule.external_auth_profile.clone(),
        });
        return Ok(());
    }

    if !has_pattern {
        return Err(PolicyError::RuleInvalid {
            index,
            reason:
                "policy rule must define at least a pattern, patterns, subnets, methods, headers_absent, or headers_match"
                    .to_string(),
        });
    }

    let patterns = patterns.unwrap();
    let mut extra_placeholders = BTreeSet::new();
    if let Some(desc) = &rule.description {
        collect_placeholders(desc, &mut extra_placeholders);
    }

    if let Some(rule_id) = &rule.rule_id {
        collect_placeholders(rule_id, &mut extra_placeholders);
    }

    for pattern in patterns {
        let mut placeholders = extra_placeholders.clone();
        collect_placeholders(&pattern, &mut placeholders);

        if placeholders.is_empty() {
            out.push(ExpandedRule {
                action: rule.action,
                pattern: Some(pattern),
                description: rule.description.clone(),
                rule_id: rule.rule_id.clone(),
                subnets: rule.subnets.clone(),
                methods: methods.clone(),
                headers_absent: headers_absent.clone(),
                headers_match: headers_match.clone(),
                request_timeout_ms: rule.request_timeout_ms,
                header_actions: rule.header_actions.clone(),
                external_auth_profile: rule.external_auth_profile.clone(),
            });
            continue;
        }

        let resolved = resolve_placeholders(rule.with.as_ref(), macros, &placeholders, |_| {
            format!(" (required by direct rule pattern {pattern})")
        })?;

        let mut combos = cartesian_product(&resolved);
        let keys_to_vary = keys_for_url_variants(rule.add_url_enc_variants.as_ref(), &placeholders);
        if !keys_to_vary.is_empty() {
            combos = add_url_encoded_variants(combos, &keys_to_vary);
        }

        for combo in combos {
            let pattern_interp = interpolate_template(&pattern, &combo);
            let description_interp = rule
                .description
                .as_ref()
                .map(|d| interpolate_template(d, &combo));
            let rule_id_interp = rule
                .rule_id
                .as_ref()
                .map(|id| interpolate_template(id, &combo));

            out.push(ExpandedRule {
                action: rule.action,
                pattern: Some(pattern_interp),
                description: description_interp,
                rule_id: rule_id_interp,
                subnets: rule.subnets.clone(),
                methods: methods.clone(),
                headers_absent: headers_absent.clone(),
                headers_match: headers_match.clone(),
                request_timeout_ms: rule.request_timeout_ms,
                header_actions: rule.header_actions.clone(),
                external_auth_profile: rule.external_auth_profile.clone(),
            });
        }
    }

    Ok(())
}

fn validate_rule_external_auth(
    action: PolicyRuleAction,
    external_auth_profile: Option<&String>,
    external_profiles: &ExternalAuthProfileConfigMap,
    index: usize,
) -> Result<(), PolicyError> {
    match action {
        PolicyRuleAction::Delegate => {
            let Some(name) = external_auth_profile else {
                return Err(PolicyError::RuleInvalid {
                    index,
                    reason: "external_auth_profile is required on delegate rules".to_string(),
                });
            };

            if !external_profiles.contains_key(name) {
                return Err(PolicyError::RuleInvalid {
                    index,
                    reason: format!("external_auth_profile '{}' not found", name),
                });
            }
        }
        PolicyRuleAction::Allow | PolicyRuleAction::Deny => {
            if external_auth_profile.is_some() {
                return Err(PolicyError::RuleInvalid {
                    index,
                    reason: "external_auth_profile is only allowed on delegate rules".to_string(),
                });
            }
        }
    }

    Ok(())
}

fn normalize_patterns(
    pattern: Option<&String>,
    patterns: Option<&[String]>,
    index: usize,
    context: &str,
    require_pattern: bool,
) -> Result<Option<Vec<String>>, PolicyError> {
    if pattern.is_some() && patterns.is_some() {
        return Err(PolicyError::RuleInvalid {
            index,
            reason: format!("{context} must not define both pattern and patterns"),
        });
    }

    if let Some(patterns) = patterns {
        if patterns.is_empty() {
            return Err(PolicyError::RuleInvalid {
                index,
                reason: "patterns must include at least one pattern".to_string(),
            });
        }

        let mut normalized = Vec::with_capacity(patterns.len());
        let mut seen = BTreeSet::new();
        for (entry_idx, pattern) in patterns.iter().enumerate() {
            let trimmed = pattern.trim();
            if trimmed.is_empty() {
                return Err(PolicyError::RuleInvalid {
                    index,
                    reason: format!("patterns entry at index {entry_idx} must not be empty"),
                });
            }
            if !seen.insert(trimmed.to_string()) {
                return Err(PolicyError::RuleInvalid {
                    index,
                    reason: format!("patterns entry at index {entry_idx} duplicates an earlier pattern"),
                });
            }
            normalized.push(trimmed.to_string());
        }

        return Ok(Some(normalized));
    }

    let pattern = pattern
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string());

    if pattern.is_none() && require_pattern {
        return Err(PolicyError::RuleInvalid {
            index,
            reason: format!("{context} must define either pattern or patterns"),
        });
    }

    Ok(pattern.map(|p| vec![p]))
}

fn reject_multi_pattern_rule_id(
    patterns: Option<&[String]>,
    rule_id: Option<&String>,
    index: usize,
) -> Result<(), PolicyError> {
    if rule_id.is_some() && patterns.is_some_and(|patterns| patterns.len() > 1) {
        return Err(PolicyError::RuleInvalid {
            index,
            reason: "rule_id is not allowed on multi-pattern rules; use one rule per pattern when rule_id is required"
                .to_string(),
        });
    }

    Ok(())
}

fn expand_include_rule(
    rule: &PolicyRuleIncludeConfig,
    macros: &MacroMap,
    rulesets: &RulesetMap,
    external_profiles: &ExternalAuthProfileConfigMap,
    index: usize,
    out: &mut Vec<ExpandedRule>,
) -> Result<(), PolicyError> {
    let templates = rulesets
        .get(&rule.include)
        .ok_or_else(|| PolicyError::RulesetNotFound {
            name: rule.include.clone(),
        })?;

    for template in templates {
        validate_rule_external_auth(
            template.action,
            template.external_auth_profile.as_ref(),
            external_profiles,
            index,
        )?;
    }

    let mut template_patterns = Vec::with_capacity(templates.len());
    for template in templates {
        let patterns = normalize_patterns(
            template.pattern.as_ref(),
            template.patterns.as_deref(),
            index,
            "policy ruleset template",
            true,
        )?
        .expect("ruleset template normalization requires patterns");
        reject_multi_pattern_rule_id(Some(patterns.as_slice()), template.rule_id.as_ref(), index)?;
        template_patterns.push(TemplatePatterns { template, patterns });
    }

    let mut template_extra_placeholders = Vec::with_capacity(template_patterns.len());
    for template_patterns in &template_patterns {
        let mut placeholders = BTreeSet::new();
        let template = template_patterns.template;
        if let Some(desc) = &template.description {
            collect_placeholders(desc, &mut placeholders);
        }
        if let Some(rule_id) = &template.rule_id {
            collect_placeholders(rule_id, &mut placeholders);
        }
        template_extra_placeholders.push(placeholders);
    }

    for (template_patterns, extra_placeholders) in template_patterns
        .iter()
        .zip(template_extra_placeholders.iter())
    {
        let template = template_patterns.template;
        let headers_absent = validate_headers_absent(template.headers_absent.as_deref(), index)?;
        let headers_match = validate_headers_match(template.headers_match.as_ref(), index)?;
        let methods = rule
            .methods
            .as_ref()
            .map(|m| m.as_slice().to_vec())
            .or_else(|| template.methods.as_ref().map(|m| m.as_slice().to_vec()))
            .unwrap_or_default();
        let request_timeout_ms = rule.request_timeout_ms.or(template.request_timeout_ms);

        for pattern in &template_patterns.patterns {
            let mut placeholders = extra_placeholders.clone();
            collect_placeholders(pattern, &mut placeholders);

            if placeholders.is_empty() {
                out.push(ExpandedRule {
                    action: template.action,
                    pattern: Some(pattern.clone()),
                    description: template.description.clone(),
                    rule_id: template.rule_id.clone(),
                    subnets: if !rule.subnets.is_empty() {
                        rule.subnets.clone()
                    } else {
                        template.subnets.clone()
                    },
                    methods: methods.clone(),
                    headers_absent: headers_absent.clone(),
                    headers_match: headers_match.clone(),
                    request_timeout_ms,
                    header_actions: template.header_actions.clone(),
                    external_auth_profile: template.external_auth_profile.clone(),
                });
                continue;
            }

            let resolved = resolve_placeholders(rule.with.as_ref(), macros, &placeholders, |_| {
                format!(" (required by ruleset {ruleset})", ruleset = rule.include)
            })?;

            let mut combos = cartesian_product(&resolved);
            let keys_to_vary =
                keys_for_url_variants(rule.add_url_enc_variants.as_ref(), &placeholders);
            if !keys_to_vary.is_empty() {
                combos = add_url_encoded_variants(combos, &keys_to_vary);
            }

            for combo in combos {
                let pattern_interp = interpolate_template(pattern, &combo);
                let description_interp = template
                    .description
                    .as_ref()
                    .map(|d| interpolate_template(d, &combo));
                let rule_id_interp = template
                    .rule_id
                    .as_ref()
                    .map(|id| interpolate_template(id, &combo));

                out.push(ExpandedRule {
                    action: template.action,
                    pattern: Some(pattern_interp),
                    description: description_interp,
                    rule_id: rule_id_interp,
                    subnets: if !rule.subnets.is_empty() {
                        rule.subnets.clone()
                    } else {
                        template.subnets.clone()
                    },
                    methods: methods.clone(),
                    headers_absent: headers_absent.clone(),
                    headers_match: headers_match.clone(),
                    request_timeout_ms,
                    header_actions: template.header_actions.clone(),
                    external_auth_profile: template.external_auth_profile.clone(),
                });
            }
        }
    }

    Ok(())
}

fn macro_values_to_vec(values: &MacroValues) -> Vec<String> {
    match values {
        MacroValues::Single(s) => vec![s.clone()],
        MacroValues::Many(v) => v.clone(),
    }
}

fn resolve_placeholders(
    overrides: Option<&MacroOverrideMap>,
    macros: &MacroMap,
    needed: &BTreeSet<String>,
    context_builder: impl Fn(&str) -> String,
) -> Result<BTreeMap<String, Vec<String>>, PolicyError> {
    let mut resolved: BTreeMap<String, Vec<String>> = BTreeMap::new();

    if let Some(map) = overrides {
        for (k, v) in map {
            resolved.insert(k.clone(), macro_values_to_vec(v));
        }
    }

    for name in needed {
        if resolved.contains_key(name) {
            continue;
        }
        match macros.get(name) {
            Some(v) => {
                resolved.insert(name.clone(), macro_values_to_vec(v));
            }
            None => {
                return Err(PolicyError::MacroNotFound {
                    name: name.clone(),
                    context: context_builder(name),
                })
            }
        }
    }

    Ok(resolved)
}

fn cartesian_product(vars: &BTreeMap<String, Vec<String>>) -> Vec<BTreeMap<String, String>> {
    if vars.is_empty() {
        return vec![BTreeMap::new()];
    }

    let mut acc: Vec<BTreeMap<String, String>> = vec![BTreeMap::new()];

    for (key, values) in vars {
        let mut next = Vec::new();
        for combo in &acc {
            for v in values {
                let mut new_combo = combo.clone();
                new_combo.insert(key.clone(), v.clone());
                next.push(new_combo);
            }
        }
        acc = next;
    }

    acc
}

fn compile_header_actions(
    actions: &[HeaderActionConfig],
    index: usize,
) -> Result<Vec<CompiledHeaderAction>, PolicyError> {
    compile_header_actions_with_context(
        actions,
        |action_cfg| HeaderActionCompileInput {
            direction: action_cfg.direction.clone(),
            action: &action_cfg.action,
            name: &action_cfg.name,
            when: action_cfg.when.clone(),
            value: action_cfg.value.as_ref(),
            values: action_cfg.values.as_ref(),
            search: action_cfg.search.as_ref(),
            replace: action_cfg.replace.as_ref(),
        },
        |reason| PolicyError::RuleInvalid { index, reason },
    )
}

pub fn compile_egress_request_header_actions(
    actions: &[EgressRequestHeaderActionConfig],
) -> Result<Vec<CompiledHeaderAction>, PolicyError> {
    let mut compiled = Vec::with_capacity(actions.len());

    for (index, action_cfg) in actions.iter().enumerate() {
        let one = compile_header_actions_with_context(
            std::slice::from_ref(action_cfg),
            |action_cfg| HeaderActionCompileInput {
                direction: HeaderDirection::Request,
                action: &action_cfg.action,
                name: &action_cfg.name,
                when: action_cfg.when.clone(),
                value: action_cfg.value.as_ref(),
                values: action_cfg.values.as_ref(),
                search: action_cfg.search.as_ref(),
                replace: action_cfg.replace.as_ref(),
            },
            |reason| PolicyError::EgressRequestHeaderActionInvalid { index, reason },
        )?;
        compiled.extend(one);
    }

    Ok(compiled)
}

struct HeaderActionCompileInput<'a> {
    direction: HeaderDirection,
    action: &'a HeaderActionKind,
    name: &'a str,
    when: HeaderWhen,
    value: Option<&'a String>,
    values: Option<&'a Vec<String>>,
    search: Option<&'a String>,
    replace: Option<&'a String>,
}

fn compile_header_actions_with_context<T, I, E>(
    actions: &[T],
    make_input: I,
    make_error: E,
) -> Result<Vec<CompiledHeaderAction>, PolicyError>
where
    I: Fn(&T) -> HeaderActionCompileInput<'_>,
    E: Fn(String) -> PolicyError,
{
    let mut compiled = Vec::with_capacity(actions.len());

    for action_cfg in actions {
        let input = make_input(action_cfg);

        let name = HeaderName::from_lowercase(input.name.to_ascii_lowercase().as_bytes())
            .map_err(|e| make_error(format!("invalid header name '{}': {e}", input.name)))?;

        let mut values: Vec<HeaderValue> = Vec::new();

        match input.action {
            HeaderActionKind::Set | HeaderActionKind::Add => {
                let source_values = match (input.value, input.values) {
                    (Some(v), None) => vec![v.clone()],
                    (None, Some(vs)) if !vs.is_empty() => vs.clone(),
                    (Some(_), Some(_)) => {
                        return Err(make_error(format!(
                            "header action for '{}' must not set both value and values",
                            input.name
                        )));
                    }
                    _ => {
                        return Err(make_error(format!(
                            "header action for '{}' must provide value or values",
                            input.name
                        )));
                    }
                };

                for v in source_values {
                    let hv = HeaderValue::from_str(&v).map_err(|e| {
                        make_error(format!(
                            "invalid header value for '{}': {} ({e})",
                            input.name, v
                        ))
                    })?;
                    values.push(hv);
                }
            }
            HeaderActionKind::Remove | HeaderActionKind::ReplaceSubstring => {
                if input.value.is_some() || input.values.is_some() {
                    return Err(make_error(format!(
                        "header action for '{}' with action {:?} must not set value/values",
                        input.name, input.action
                    )));
                }
            }
        }

        let (search, replace) = match input.action {
            HeaderActionKind::ReplaceSubstring => {
                let search = input.search.cloned().ok_or_else(|| {
                    make_error(format!(
                        "header action for '{}' with action replace_substring requires search",
                        input.name
                    ))
                })?;
                if search.is_empty() {
                    return Err(make_error(format!(
                        "header action for '{}' with action replace_substring requires non-empty search",
                        input.name
                    )));
                }
                let replace = input.replace.cloned().ok_or_else(|| {
                    make_error(format!(
                        "header action for '{}' with action replace_substring requires replace",
                        input.name
                    ))
                })?;
                (Some(search), Some(replace))
            }
            _ => (None, None),
        };

        compiled.push(CompiledHeaderAction {
            direction: input.direction,
            action: input.action.clone(),
            name,
            values,
            when: input.when,
            search,
            replace,
        });
    }

    Ok(compiled)
}

fn compile_headers_absent(
    headers_absent: Option<&[String]>,
    index: usize,
) -> Result<Vec<HeaderName>, PolicyError> {
    let Some(headers_absent) = headers_absent else {
        return Ok(Vec::new());
    };

    headers_absent
        .iter()
        .map(|name| {
            HeaderName::from_lowercase(name.as_bytes()).map_err(|err| PolicyError::RuleInvalid {
                index,
                reason: format!("invalid header name '{}' in headers_absent: {err}", name),
            })
        })
        .collect()
}

fn compile_headers_match(
    headers_match: Option<&BTreeMap<String, Vec<String>>>,
    index: usize,
) -> Result<Vec<CompiledHeaderMatch>, PolicyError> {
    let Some(headers_match) = headers_match else {
        return Ok(Vec::new());
    };

    let mut compiled = Vec::with_capacity(headers_match.len());

    for (name, values) in headers_match {
        let header_name = HeaderName::from_lowercase(name.as_bytes()).map_err(|err| {
            PolicyError::RuleInvalid {
                index,
                reason: format!("invalid header name '{}' in headers_match: {err}", name),
            }
        })?;

        compiled.push(CompiledHeaderMatch {
            name: header_name,
            values: values
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect(),
        });
    }

    Ok(compiled)
}

fn validate_headers_absent(
    headers_absent: Option<&[String]>,
    index: usize,
) -> Result<Option<Vec<String>>, PolicyError> {
    let Some(headers_absent) = headers_absent else {
        return Ok(None);
    };

    if headers_absent.is_empty() {
        return Err(PolicyError::RuleInvalid {
            index,
            reason: "headers_absent must not be empty".to_string(),
        });
    }

    let mut normalized = Vec::with_capacity(headers_absent.len());
    let mut seen = BTreeSet::new();

    for name in headers_absent {
        let lowered = name.to_ascii_lowercase();
        let parsed = HeaderName::from_lowercase(lowered.as_bytes()).map_err(|err| {
            PolicyError::RuleInvalid {
                index,
                reason: format!("invalid header name '{}' in headers_absent: {err}", name),
            }
        })?;
        let normalized_name = parsed.as_str().to_string();

        if !seen.insert(normalized_name.clone()) {
            return Err(PolicyError::RuleInvalid {
                index,
                reason: format!(
                    "duplicate header name '{}' in headers_absent after normalization",
                    name
                ),
            });
        }

        normalized.push(normalized_name);
    }

    Ok(Some(normalized))
}

fn validate_headers_match(
    headers_match: Option<&BTreeMap<String, HeaderMatchValueConfig>>,
    index: usize,
) -> Result<Option<BTreeMap<String, Vec<String>>>, PolicyError> {
    let Some(headers_match) = headers_match else {
        return Ok(None);
    };

    if headers_match.is_empty() {
        return Err(PolicyError::RuleInvalid {
            index,
            reason: "headers_match must not be empty".to_string(),
        });
    }

    let mut normalized = BTreeMap::new();
    let mut seen = BTreeSet::new();

    for (name, raw_values) in headers_match {
        let lowered = name.to_ascii_lowercase();
        let parsed = HeaderName::from_lowercase(lowered.as_bytes()).map_err(|err| {
            PolicyError::RuleInvalid {
                index,
                reason: format!("invalid header name '{}' in headers_match: {err}", name),
            }
        })?;
        let normalized_name = parsed.as_str().to_string();

        if !seen.insert(normalized_name.clone()) {
            return Err(PolicyError::RuleInvalid {
                index,
                reason: format!(
                    "duplicate header name '{}' in headers_match after normalization",
                    name
                ),
            });
        }

        let values = raw_values.values();
        if values.is_empty() {
            return Err(PolicyError::RuleInvalid {
                index,
                reason: format!(
                    "headers_match entry '{}' must include at least one allowed value",
                    name
                ),
            });
        }

        if values.iter().any(|value| value.is_empty()) {
            return Err(PolicyError::RuleInvalid {
                index,
                reason: format!(
                    "headers_match entry '{}' must not include empty-string values",
                    name
                ),
            });
        }

        normalized.insert(normalized_name, values);
    }

    Ok(Some(normalized))
}

fn any_header_absent(headers: &HeaderMap<HeaderValue>, headers_absent: &[HeaderName]) -> bool {
    headers_absent
        .iter()
        .any(|header_name| !headers.contains_key(header_name))
}

fn all_headers_match(
    headers: &HeaderMap<HeaderValue>,
    headers_match: &[CompiledHeaderMatch],
) -> bool {
    headers_match.iter().all(|matcher| {
        headers.get_all(&matcher.name).iter().any(|actual| {
            matcher
                .values
                .iter()
                .any(|expected| actual.as_bytes() == expected.as_slice())
        })
    })
}

fn keys_for_url_variants(
    config: Option<&UrlEncVariants>,
    placeholders: &BTreeSet<String>,
) -> Vec<String> {
    match config {
        None => Vec::new(),
        Some(UrlEncVariants::All(flag)) => {
            if *flag {
                placeholders.iter().cloned().collect()
            } else {
                Vec::new()
            }
        }
        Some(UrlEncVariants::Names(names)) => names.clone(),
    }
}

fn add_url_encoded_variants(
    combos: Vec<BTreeMap<String, String>>,
    keys_to_vary: &[String],
) -> Vec<BTreeMap<String, String>> {
    if keys_to_vary.is_empty() {
        return combos;
    }

    let mut expanded = Vec::new();

    for base in combos {
        let mut acc = vec![base];
        for key in keys_to_vary {
            let mut next = Vec::new();
            for combo in acc {
                next.push(combo.clone());
                if let Some(val) = combo.get(key) {
                    let enc = urlencoding::encode(val).into_owned();
                    let mut modified = combo.clone();
                    modified.insert(key.clone(), enc);
                    next.push(modified);
                }
            }
            acc = next;
        }
        expanded.extend(acc);
    }

    expanded
}

fn collect_placeholders(input: &str, out: &mut BTreeSet<String>) {
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b'}' {
                j += 1;
            }
            if j < bytes.len() {
                let name = &input[start..j];
                if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    out.insert(name.to_string());
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
}

fn interpolate_template(input: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let bytes = input.as_bytes();

    while i < bytes.len() {
        if bytes[i] == b'{' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b'}' {
                j += 1;
            }
            if j < bytes.len() {
                let name = &input[start..j];
                if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    if let Some(val) = vars.get(name) {
                        out.push_str(val);
                    }
                    i = j + 1;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }

    out
}

fn escape_regex(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '.' | '*' | '+' | '?' | '^' | '$' | '{' | '}' | '(' | ')' | '|' | '[' | ']' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

pub fn pattern_to_regex(pattern: &str) -> String {
    let raw = pattern.trim();
    if raw.is_empty() {
        return String::from(r"^https?://$");
    }

    let lower = raw.to_ascii_lowercase();
    let rest = if lower.starts_with("http://") {
        &raw[7..]
    } else if lower.starts_with("https://") {
        &raw[8..]
    } else {
        let trimmed = raw.trim_start_matches('/');
        trimmed
    };

    let mut rest = rest.to_string();

    let slash_idx = rest.find('/');
    let path_part = slash_idx
        .map(|idx| rest[idx + 1..].to_string())
        .unwrap_or_default();
    let is_host_only = path_part.is_empty();

    if is_host_only {
        while rest.ends_with('/') {
            rest.pop();
        }
    }

    let escaped = escape_regex(&rest);
    let mut s = escaped.replace("\\*\\*", ".*").replace("\\*", "[^/]*");

    if is_host_only {
        s.push_str("/?");
    }

    let scheme_regex = "https?://";
    format!("^{}{}$", scheme_regex, s)
}

fn normalize_url(raw: &str) -> Result<String, PolicyError> {
    let url = Url::parse(raw).map_err(|e| PolicyError::UrlParse(e.to_string()))?;

    let scheme = url.scheme();
    let protocol = format!("{scheme}:");

    let host = match url.host_str() {
        Some(h) => {
            if let Some(port) = url.port() {
                format!("{h}:{port}")
            } else {
                h.to_string()
            }
        }
        None => return Err(PolicyError::UrlParse("URL is missing host".to_string())),
    };

    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };

    let search = match url.query() {
        Some(q) => {
            let mut s = String::with_capacity(q.len() + 1);
            s.push('?');
            s.push_str(q);
            s
        }
        None => String::new(),
    };

    Ok(format!("{protocol}//{host}{path}{search}"))
}

pub fn normalize_client_ip(raw: Option<&str>) -> Option<String> {
    let raw = raw?;
    let mut addr = raw.to_string();

    if let Some(idx) = addr.find('%') {
        addr.truncate(idx);
    }

    if let Some(stripped) = addr.strip_prefix("::ffff:") {
        return Some(stripped.to_string());
    }

    if addr == "::1" {
        return Some("127.0.0.1".to_string());
    }

    Some(addr)
}

fn client_in_any_subnet(raw_ip: Option<&str>, subnets: &[IpNet]) -> bool {
    let ip = match raw_ip {
        Some(s) => s,
        None => return false,
    };

    let ip_norm = match normalize_client_ip(Some(ip)) {
        Some(s) => s,
        None => return false,
    };

    let parsed: IpAddr = match ip_norm.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    for net in subnets {
        match (net, &parsed) {
            (IpNet::V4(v4net), IpAddr::V4(v4)) => {
                if v4net.contains(v4) {
                    return true;
                }
            }
            (IpNet::V6(v6net), IpAddr::V6(v6)) => {
                if v6net.contains(v6) {
                    return true;
                }
            }
            _ => {}
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EgressRequestHeaderActionConfig, PolicyRuleTemplateConfig};
    use toml;

    fn allow_action() -> PolicyRuleAction {
        PolicyRuleAction::Allow
    }

    fn header_map(entries: &[(&str, &str)]) -> HeaderMap<HeaderValue> {
        let mut headers = HeaderMap::new();
        for (name, value) in entries {
            headers.insert(
                HeaderName::from_lowercase(name.to_ascii_lowercase().as_bytes())
                    .expect("valid header name"),
                HeaderValue::from_str(value).expect("valid header value"),
            );
        }
        headers
    }

    #[test]
    fn compile_egress_request_header_actions_sets_request_direction() {
        let actions = vec![EgressRequestHeaderActionConfig {
            action: HeaderActionKind::Set,
            name: "x-egress-tag".to_string(),
            when: HeaderWhen::Always,
            value: Some("edge-a".to_string()),
            values: None,
            search: None,
            replace: None,
        }];

        let compiled =
            compile_egress_request_header_actions(&actions).expect("compile egress actions");

        assert_eq!(compiled.len(), 1);
        assert!(matches!(compiled[0].direction, HeaderDirection::Request));
    }

    #[test]
    fn compile_egress_request_header_actions_reports_egress_specific_error_context() {
        let actions = vec![EgressRequestHeaderActionConfig {
            action: HeaderActionKind::Set,
            name: "x-egress-tag".to_string(),
            when: HeaderWhen::Always,
            value: None,
            values: None,
            search: None,
            replace: None,
        }];

        let err =
            compile_egress_request_header_actions(&actions).expect_err("expected compile error");

        let msg = format!("{err}");
        assert!(
            msg.contains("proxy.egress.request_header_actions entry at index 0"),
            "unexpected error message: {msg}"
        );
        assert!(
            msg.contains("must provide value or values"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn pattern_to_regex_host_only() {
        let re = Regex::new(&pattern_to_regex("https://example.com")).expect("compile regex");
        assert!(re.is_match("https://example.com"));
        assert!(re.is_match("https://example.com/"));
        assert!(!re.is_match("https://example.com/path"));
    }

    #[test]
    fn pattern_to_regex_wildcards() {
        let re =
            Regex::new(&pattern_to_regex("https://example.com/api/**")).expect("compile regex");
        assert!(re.is_match("https://example.com/api/"));
        assert!(re.is_match("https://example.com/api/v1/resource"));

        let re2 = Regex::new(&pattern_to_regex("https://example.com/api/*/resource"))
            .expect("compile regex");
        assert!(re2.is_match("https://example.com/api/v1/resource"));
        assert!(!re2.is_match("https://example.com/api/v1/v2/resource"));
    }

    #[test]
    fn normalize_client_ip_matches_legacy() {
        assert_eq!(
            normalize_client_ip(Some("::ffff:10.1.2.3")),
            Some("10.1.2.3".to_string())
        );
        assert_eq!(
            normalize_client_ip(Some("::1")),
            Some("127.0.0.1".to_string())
        );
        assert_eq!(
            normalize_client_ip(Some("2001:db8::1")),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn subnet_only_rule_allows_matching_clients() {
        let cfg = PolicyConfig {
            default: PolicyDefaultAction::Deny,
            macros: MacroMap::default(),
            approval_macros: crate::config::ApprovalMacroConfigMap::default(),
            rulesets: RulesetMap::default(),
            external_auth_profiles: ExternalAuthProfileConfigMap::default(),
            rules: vec![PolicyRuleConfig::Direct(PolicyRuleDirectConfig {
                action: PolicyRuleAction::Allow,
                pattern: None,
                patterns: None,
                description: None,
                methods: None,
                subnets: vec!["192.168.0.0/16".parse::<IpNet>().unwrap()],
                headers_absent: None,
                headers_match: None,
                request_timeout_ms: None,
                with: None,
                add_url_enc_variants: None,
                header_actions: Vec::new(),
                rule_id: None,
                external_auth_profile: None,
            })],
        };

        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");
        assert!(engine.is_allowed("https://example.com/", Some("192.168.1.10"), None));
        assert!(!engine.is_allowed("https://example.com/", Some("10.0.0.1"), None));
    }

    #[test]
    fn subnet_only_rule_allows_ipv6_clients() {
        let cfg = PolicyConfig {
            default: PolicyDefaultAction::Deny,
            macros: MacroMap::default(),
            approval_macros: crate::config::ApprovalMacroConfigMap::default(),
            rulesets: RulesetMap::default(),
            external_auth_profiles: ExternalAuthProfileConfigMap::default(),
            rules: vec![PolicyRuleConfig::Direct(PolicyRuleDirectConfig {
                action: PolicyRuleAction::Allow,
                pattern: None,
                patterns: None,
                description: None,
                methods: None,
                subnets: vec!["2001:db8::/32".parse::<IpNet>().unwrap()],
                headers_absent: None,
                headers_match: None,
                request_timeout_ms: None,
                with: None,
                add_url_enc_variants: None,
                header_actions: Vec::new(),
                rule_id: None,
                external_auth_profile: None,
            })],
        };

        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");
        assert!(engine.is_allowed("https://example.com/", Some("2001:db8::1"), None));
        assert!(!engine.is_allowed("https://example.com/", Some("2001:dead::1"), None));
    }

    #[test]
    fn macros_and_rulesets_expand_with_urlenc_variants() {
        let mut macros = MacroMap::default();
        macros.insert(
            "repo".to_string(),
            MacroValues::Many(vec![
                "user/ts-test-1".to_string(),
                "user/ts-test-2".to_string(),
            ]),
        );

        let mut rulesets = RulesetMap::default();
        rulesets.insert(
            "gitlabRepo".to_string(),
            vec![
                PolicyRuleTemplateConfig {
                    action: allow_action(),
                    pattern: Some("https://gitlab.internal/api/v4/projects/{repo}?**".to_string()),
                    patterns: None,
                    description: None,
                    methods: None,
                    subnets: Vec::new(),
                    headers_absent: None,
                    headers_match: None,
                    request_timeout_ms: None,
                    header_actions: Vec::new(),
                    external_auth_profile: None,
                    rule_id: None,
                },
                PolicyRuleTemplateConfig {
                    action: allow_action(),
                    pattern: Some("https://gitlab.internal/{repo}.git/**".to_string()),
                    patterns: None,
                    description: None,
                    methods: None,
                    subnets: Vec::new(),
                    headers_absent: None,
                    headers_match: None,
                    request_timeout_ms: None,
                    header_actions: Vec::new(),
                    external_auth_profile: None,
                    rule_id: None,
                },
            ],
        );

        let cfg = PolicyConfig {
            default: PolicyDefaultAction::Deny,
            macros,
            rulesets,
            approval_macros: crate::config::ApprovalMacroConfigMap::default(),
            external_auth_profiles: ExternalAuthProfileConfigMap::default(),
            rules: vec![PolicyRuleConfig::Include(PolicyRuleIncludeConfig {
                include: "gitlabRepo".to_string(),
                with: None,
                add_url_enc_variants: Some(UrlEncVariants::All(true)),
                methods: None,
                subnets: Vec::new(),
                request_timeout_ms: None,
            })],
        };

        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        assert!(engine.is_allowed(
            "https://gitlab.internal/api/v4/projects/user%2Fts-test-1?stats=true",
            None,
            None
        ));
        assert!(engine.is_allowed(
            "https://gitlab.internal/api/v4/projects/user%2Fts-test-2?stats=true",
            None,
            None
        ));
        assert!(engine.is_allowed(
            "https://gitlab.internal/user/ts-test-1.git/info/refs",
            None,
            None
        ));
        assert!(engine.is_allowed(
            "https://gitlab.internal/user/ts-test-2.git/info/refs",
            None,
            None
        ));
        assert!(!engine.is_allowed("https://gitlab.internal/other/repo/any", None, None));
    }

    #[test]
    fn missing_macro_in_ruleset_causes_error() {
        let rulesets = {
            let mut m = RulesetMap::default();
            m.insert(
                "needsRepo".to_string(),
                vec![PolicyRuleTemplateConfig {
                    action: allow_action(),
                    pattern: Some("https://gitlab.internal/api/v4/projects/{repo}?**".to_string()),
                    patterns: None,
                    description: None,
                    methods: None,
                    subnets: Vec::new(),
                    headers_absent: None,
                    headers_match: None,
                    request_timeout_ms: None,
                    header_actions: Vec::new(),
                    external_auth_profile: None,
                    rule_id: None,
                }],
            );
            m
        };

        let cfg = PolicyConfig {
            default: PolicyDefaultAction::Deny,
            macros: MacroMap::default(),
            rulesets,
            approval_macros: crate::config::ApprovalMacroConfigMap::default(),
            external_auth_profiles: ExternalAuthProfileConfigMap::default(),
            rules: vec![PolicyRuleConfig::Include(PolicyRuleIncludeConfig {
                include: "needsRepo".to_string(),
                with: None,
                add_url_enc_variants: Some(UrlEncVariants::All(true)),
                methods: None,
                subnets: Vec::new(),
                request_timeout_ms: None,
            })],
        };

        let err = PolicyEngine::from_config(&cfg).expect_err("expected error");
        let msg = format!("{err}");
        assert!(
            msg.contains("Policy macro not found: repo"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn method_rule_requires_method_match() {
        let toml = r#"
default = "deny"

[[rules]]
	action = "allow"
pattern = "https://example.com/**"
methods = ["GET", "HEAD"]
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        assert!(engine.is_allowed("https://example.com/path", None, Some("GET")));
        assert!(engine.is_allowed("https://example.com/path", None, Some("head")));
        assert!(!engine.is_allowed("https://example.com/path", None, Some("POST")));

        // Method-scoped rules do not match when method is omitted.
        assert!(!engine.is_allowed("https://example.com/path", None, None));
    }

    #[test]
    fn methods_can_combine_with_subnets() {
        let toml = r#"
default = "deny"

[[rules]]
action = "allow"
pattern = "https://api.internal.example.com/**"
subnets = ["10.0.0.0/8"]
methods = ["POST"]
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        assert!(engine.is_allowed(
            "https://api.internal.example.com/resource",
            Some("10.1.2.3"),
            Some("POST")
        ));
        assert!(!engine.is_allowed(
            "https://api.internal.example.com/resource",
            Some("10.1.2.3"),
            Some("GET")
        ));
        assert!(!engine.is_allowed(
            "https://api.internal.example.com/resource",
            Some("192.168.1.1"),
            Some("POST")
        ));
    }

    #[test]
    fn method_only_rule_works_without_pattern_or_subnets() {
        let toml = r#"
default = "deny"

[[rules]]
action = "allow"
methods = ["HEAD"]
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        assert!(engine.is_allowed("https://example.com/path", None, Some("HEAD")));
        assert!(!engine.is_allowed("https://example.com/path", None, Some("GET")));
    }

    #[test]
    fn methods_can_be_provided_as_single_string() {
        let toml = r#"
default = "deny"

[[rules]]
action = "allow"
pattern = "https://example.com/**"
methods = "PUT"
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        assert!(engine.is_allowed("https://example.com/path", None, Some("PUT")));
        assert!(!engine.is_allowed("https://example.com/path", None, Some("GET")));
    }

    #[test]
    fn first_matching_rule_wins() {
        let toml = r#"
default = "deny"

[[rules]]
action = "deny"
pattern = "https://example.com/admin/**"

[[rules]]
action = "allow"
pattern = "https://example.com/**"
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        // Matches the second rule.
        assert!(engine.is_allowed("https://example.com/public", None, None));

        // Matches the first (deny) rule.
        assert!(!engine.is_allowed("https://example.com/admin/panel", None, None));
    }

    #[test]
    fn default_action_applies_when_no_rules_match() {
        let toml = r#"
default = "allow"
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        assert!(engine.is_allowed("https://anything.com/path", None, None));
    }

    #[test]
    fn headers_absent_matches_when_header_is_missing() {
        let toml = r#"
default = "allow"

[[rules]]
action = "deny"
headers_absent = ["x-workload-id"]
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");
        let headers = HeaderMap::new();

        let decision = engine.evaluate("https://example.com/path", None, Some("GET"), &headers);

        assert!(!decision.allowed);
        assert_eq!(decision.matched.as_ref().map(|rule| rule.index), Some(0));
    }

    #[test]
    fn headers_absent_falls_through_when_header_is_present() {
        let toml = r#"
default = "deny"

[[rules]]
action = "deny"
headers_absent = ["x-workload-id"]

[[rules]]
action = "allow"
pattern = "https://example.com/**"
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");
        let headers = header_map(&[("X-Workload-Id", "worker-123")]);

        let decision = engine.evaluate("https://example.com/path", None, Some("GET"), &headers);

        assert!(decision.allowed);
        assert_eq!(decision.matched.as_ref().map(|rule| rule.index), Some(1));
    }

    #[test]
    fn headers_absent_treats_empty_values_as_present() {
        let toml = r#"
default = "allow"

[[rules]]
action = "deny"
headers_absent = ["x-workload-id"]
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");
        let headers = header_map(&[("x-workload-id", "")]);

        let decision = engine.evaluate("https://example.com/path", None, Some("GET"), &headers);

        assert!(decision.allowed);
        assert!(decision.matched.is_none());
    }

    #[test]
    fn headers_absent_lookup_is_case_insensitive() {
        let toml = r#"
default = "allow"

[[rules]]
action = "deny"
headers_absent = ["X-Workload-Id"]
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");
        let headers = header_map(&[("x-workload-id", "worker-123")]);

        let decision = engine.evaluate("https://example.com/path", None, Some("GET"), &headers);

        assert!(decision.allowed);
        assert!(decision.matched.is_none());
    }

    #[test]
    fn headers_absent_combines_with_methods_using_and_semantics() {
        let toml = r#"
default = "allow"

[[rules]]
action = "deny"
pattern = "https://example.com/**"
methods = ["POST"]
headers_absent = ["x-workload-id"]
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");
        let headers = HeaderMap::new();

        let deny_decision =
            engine.evaluate("https://example.com/path", None, Some("POST"), &headers);
        let allow_decision =
            engine.evaluate("https://example.com/path", None, Some("GET"), &headers);

        assert!(!deny_decision.allowed);
        assert!(allow_decision.allowed);
    }

    #[test]
    fn headers_absent_combines_with_subnets_using_and_semantics() {
        let toml = r#"
default = "allow"

[[rules]]
action = "deny"
pattern = "https://example.com/**"
subnets = ["10.0.0.0/8"]
headers_absent = ["x-workload-id"]
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");
        let headers = HeaderMap::new();

        let deny_decision = engine.evaluate(
            "https://example.com/path",
            Some("10.1.2.3"),
            Some("GET"),
            &headers,
        );
        let allow_decision = engine.evaluate(
            "https://example.com/path",
            Some("192.168.1.10"),
            Some("GET"),
            &headers,
        );

        assert!(!deny_decision.allowed);
        assert!(allow_decision.allowed);
    }

    #[test]
    fn headers_absent_matches_when_any_listed_header_is_missing() {
        let toml = r#"
default = "allow"

[[rules]]
action = "deny"
headers_absent = ["x-workload-id", "x-trace-id"]
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        let both_missing = HeaderMap::new();
        let both_present =
            header_map(&[("x-workload-id", "worker-123"), ("x-trace-id", "trace-456")]);
        let missing_workload = header_map(&[("x-trace-id", "trace-456")]);
        let missing_trace = header_map(&[("x-workload-id", "worker-123")]);

        assert!(
            !engine
                .evaluate("https://example.com/path", None, Some("GET"), &both_missing)
                .allowed
        );
        assert!(
            engine
                .evaluate("https://example.com/path", None, Some("GET"), &both_present)
                .allowed
        );
        assert!(
            !engine
                .evaluate(
                    "https://example.com/path",
                    None,
                    Some("GET"),
                    &missing_workload
                )
                .allowed
        );
        assert!(
            !engine
                .evaluate(
                    "https://example.com/path",
                    None,
                    Some("GET"),
                    &missing_trace
                )
                .allowed
        );
    }

    #[test]
    fn headers_match_single_key_single_value_match_and_fallthrough() {
        let toml = r#"
default = "deny"

[[rules]]
action = "allow"
pattern = "https://example.com/**"
headers_match = { "x-workload-id" = "worker-123" }
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        let matching_headers = header_map(&[("x-workload-id", "worker-123")]);
        let non_matching_headers = header_map(&[("x-workload-id", "worker-456")]);

        assert!(
            engine
                .evaluate(
                    "https://example.com/path",
                    None,
                    Some("GET"),
                    &matching_headers
                )
                .allowed
        );
        assert!(
            !engine
                .evaluate(
                    "https://example.com/path",
                    None,
                    Some("GET"),
                    &non_matching_headers
                )
                .allowed
        );
    }

    #[test]
    fn headers_match_single_key_multi_value_uses_or_semantics() {
        let toml = r#"
default = "deny"

[[rules]]
action = "allow"
pattern = "https://example.com/**"
headers_match = { "x-workload-id" = ["worker-123", "worker-456"] }
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        let first_match = header_map(&[("x-workload-id", "worker-123")]);
        let second_match = header_map(&[("x-workload-id", "worker-456")]);
        let miss = header_map(&[("x-workload-id", "worker-789")]);

        assert!(
            engine
                .evaluate("https://example.com/path", None, Some("GET"), &first_match)
                .allowed
        );
        assert!(
            engine
                .evaluate("https://example.com/path", None, Some("GET"), &second_match)
                .allowed
        );
        assert!(
            !engine
                .evaluate("https://example.com/path", None, Some("GET"), &miss)
                .allowed
        );
    }

    #[test]
    fn headers_match_multi_key_uses_and_semantics() {
        let toml = r#"
default = "deny"

[[rules]]
action = "allow"
pattern = "https://example.com/**"
headers_match = { "x-workload-id" = "worker-123", "x-tenant-id" = "tenant-a" }
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        let both = header_map(&[("x-workload-id", "worker-123"), ("x-tenant-id", "tenant-a")]);
        let one_missing = header_map(&[("x-workload-id", "worker-123")]);
        let one_wrong = header_map(&[("x-workload-id", "worker-123"), ("x-tenant-id", "tenant-b")]);

        assert!(
            engine
                .evaluate("https://example.com/path", None, Some("GET"), &both)
                .allowed
        );
        assert!(
            !engine
                .evaluate("https://example.com/path", None, Some("GET"), &one_missing)
                .allowed
        );
        assert!(
            !engine
                .evaluate("https://example.com/path", None, Some("GET"), &one_wrong)
                .allowed
        );
    }

    #[test]
    fn headers_match_lookup_is_case_insensitive_for_header_names() {
        let toml = r#"
default = "deny"

[[rules]]
action = "allow"
pattern = "https://example.com/**"
headers_match = { "X-Workload-Id" = "worker-123" }
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");
        let headers = header_map(&[("x-workload-id", "worker-123")]);

        assert!(
            engine
                .evaluate("https://example.com/path", None, Some("GET"), &headers)
                .allowed
        );
    }

    #[test]
    fn headers_match_uses_exact_case_sensitive_value_semantics_without_trimming_or_comma_split() {
        let toml = r#"
default = "deny"

[[rules]]
action = "allow"
pattern = "https://example.com/**"
headers_match = { "x-workload-id" = "worker-123", "x-comma" = "a,b" }
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        let exact = header_map(&[("x-workload-id", "worker-123"), ("x-comma", "a,b")]);
        let different_case = header_map(&[("x-workload-id", "Worker-123"), ("x-comma", "a,b")]);
        let trimmed = header_map(&[("x-workload-id", " worker-123 "), ("x-comma", "a,b")]);
        let comma_split_like = header_map(&[("x-workload-id", "worker-123"), ("x-comma", "a, b")]);

        assert!(
            engine
                .evaluate("https://example.com/path", None, Some("GET"), &exact)
                .allowed
        );
        assert!(
            !engine
                .evaluate(
                    "https://example.com/path",
                    None,
                    Some("GET"),
                    &different_case
                )
                .allowed
        );
        assert!(
            !engine
                .evaluate("https://example.com/path", None, Some("GET"), &trimmed)
                .allowed
        );
        assert!(
            !engine
                .evaluate(
                    "https://example.com/path",
                    None,
                    Some("GET"),
                    &comma_split_like
                )
                .allowed
        );
    }

    #[test]
    fn headers_match_succeeds_when_any_repeated_header_value_matches() {
        let toml = r#"
default = "deny"

[[rules]]
action = "allow"
pattern = "https://example.com/**"
headers_match = { "x-workload-id" = "worker-123" }
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_static("x-workload-id"),
            HeaderValue::from_static("worker-456"),
        );
        headers.append(
            HeaderName::from_static("x-workload-id"),
            HeaderValue::from_static("worker-123"),
        );

        assert!(
            engine
                .evaluate("https://example.com/path", None, Some("GET"), &headers)
                .allowed
        );
    }

    #[test]
    fn headers_match_combines_with_methods_and_subnets_using_and_semantics() {
        let toml = r#"
default = "deny"

[[rules]]
action = "allow"
pattern = "https://example.com/**"
methods = ["POST"]
subnets = ["10.0.0.0/8"]
headers_match = { "x-workload-id" = "worker-123" }
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");
        let headers = header_map(&[("x-workload-id", "worker-123")]);

        let allowed = engine.evaluate(
            "https://example.com/path",
            Some("10.1.2.3"),
            Some("POST"),
            &headers,
        );
        let wrong_method = engine.evaluate(
            "https://example.com/path",
            Some("10.1.2.3"),
            Some("GET"),
            &headers,
        );
        let wrong_subnet = engine.evaluate(
            "https://example.com/path",
            Some("192.168.1.10"),
            Some("POST"),
            &headers,
        );

        assert!(allowed.allowed);
        assert!(!wrong_method.allowed);
        assert!(!wrong_subnet.allowed);
    }

    #[test]
    fn headers_absent_and_headers_match_combine_conjunctively() {
        let toml = r#"
default = "allow"

[[rules]]
action = "deny"
pattern = "https://example.com/**"
headers_absent = ["x-trace-id"]
headers_match = { "x-workload-id" = "worker-123" }
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        let both = header_map(&[("x-workload-id", "worker-123")]);
        let absent_only = HeaderMap::new();
        let match_only = header_map(&[("x-workload-id", "worker-123"), ("x-trace-id", "trace-1")]);

        assert!(
            !engine
                .evaluate("https://example.com/path", None, Some("GET"), &both)
                .allowed
        );
        assert!(
            engine
                .evaluate("https://example.com/path", None, Some("GET"), &absent_only)
                .allowed
        );
        assert!(
            engine
                .evaluate("https://example.com/path", None, Some("GET"), &match_only)
                .allowed
        );
    }

    #[test]
    fn headers_match_failure_falls_through_before_external_auth_rule() {
        let toml = r#"
default = "deny"

[external_auth_profiles.example]
webhook_url = "https://auth.internal/start"
timeout_ms = 5000

[[rules]]
action = "delegate"
pattern = "https://example.com/**"
headers_match = { "x-workload-id" = "worker-123" }
external_auth_profile = "example"

[[rules]]
action = "allow"
pattern = "https://example.com/**"
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        let miss_headers = header_map(&[("x-workload-id", "worker-999")]);
        let hit_headers = header_map(&[("x-workload-id", "worker-123")]);

        let miss = engine.evaluate("https://example.com/path", None, Some("GET"), &miss_headers);
        let hit = engine.evaluate("https://example.com/path", None, Some("GET"), &hit_headers);

        assert!(miss.allowed);
        assert_eq!(miss.matched.as_ref().map(|rule| rule.index), Some(1));
        assert_eq!(
            miss.matched
                .as_ref()
                .and_then(|rule| rule.external_auth_profile.as_deref()),
            None
        );

        assert!(!hit.allowed);
        assert_eq!(hit.matched.as_ref().map(|rule| rule.index), Some(0));
        assert_eq!(
            hit.matched
                .as_ref()
                .and_then(|rule| rule.external_auth_profile.as_deref()),
            Some("example")
        );
    }

    #[test]
    fn evaluate_from_resumes_after_delegate_rule() {
        let toml = r#"
default = "deny"

[external_auth_profiles.example]
webhook_url = "https://auth.internal/start"
timeout_ms = 5000

[[rules]]
action = "delegate"
pattern = "https://example.com/**"
external_auth_profile = "example"

[[rules]]
action = "allow"
pattern = "https://example.com/public/**"
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");
        let headers = HeaderMap::new();

        let first = engine.evaluate("https://example.com/public/index", None, Some("GET"), &headers);
        assert!(!first.allowed);
        assert_eq!(first.matched.as_ref().map(|rule| rule.index), Some(0));
        assert!(matches!(
            first.matched.as_ref().map(|rule| rule.action),
            Some(PolicyRuleAction::Delegate)
        ));

        let resumed =
            engine.evaluate_from(1, "https://example.com/public/index", None, Some("GET"), &headers);
        assert!(resumed.allowed);
        assert_eq!(resumed.matched.as_ref().map(|rule| rule.index), Some(1));
    }

    #[test]
    fn evaluate_from_after_delegate_uses_default_when_no_later_match() {
        let toml = r#"
default = "deny"

[external_auth_profiles.example]
webhook_url = "https://auth.internal/start"
timeout_ms = 5000

[[rules]]
action = "delegate"
pattern = "https://example.com/**"
external_auth_profile = "example"
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");
        let headers = HeaderMap::new();

        let resumed =
            engine.evaluate_from(1, "https://example.com/path", None, Some("GET"), &headers);
        assert!(!resumed.allowed);
        assert!(resumed.matched.is_none());
    }

    #[test]
    fn static_deny_before_delegate_is_terminal() {
        let toml = r#"
default = "allow"

[external_auth_profiles.example]
webhook_url = "https://auth.internal/start"
timeout_ms = 5000

[[rules]]
action = "deny"
pattern = "https://example.com/private/**"

[[rules]]
action = "delegate"
pattern = "https://example.com/**"
external_auth_profile = "example"
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");
        let headers = HeaderMap::new();

        let decision = engine.evaluate(
            "https://example.com/private/secret",
            None,
            Some("GET"),
            &headers,
        );

        assert!(!decision.allowed);
        let matched = decision.matched.expect("matched rule");
        assert_eq!(matched.index, 0);
        assert!(matches!(matched.action, PolicyRuleAction::Deny));
    }

    #[test]
    fn headers_match_only_rule_is_valid_match_criteria() {
        let toml = r#"
default = "deny"

[[rules]]
	action = "allow"
headers_match = { "x-workload-id" = "worker-123" }
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        assert_eq!(engine.rules.len(), 1);
    }

    #[test]
    fn invalid_urls_are_denied() {
        let toml = r#"
default = "allow"
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        assert!(engine.is_allowed("https://example.com/path", None, None));
        assert!(!engine.is_allowed("not-a-url", None, None));
        assert!(!engine.is_allowed("", None, None));
    }

    #[test]
    fn missing_macro_in_direct_rule_causes_error() {
        let toml = r#"
default = "deny"

[[rules]]
action = "allow"
pattern = "https://gitlab.internal/api/v4/projects/{repo}?**"
add_url_enc_variants = true
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let err = PolicyEngine::from_config(&cfg).expect_err("expected error");
        let msg = format!("{err}");
        assert!(
            msg.contains("Policy macro not found: repo"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn direct_patterns_expand_and_report_matched_effective_pattern() {
        let toml = r#"
default = "deny"

[[rules]]
action = "allow"
patterns = [
  "https://example.com/docs/**",
  "https://example.com/api/**",
]
description = "Example grouped rule"
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        assert!(engine.is_allowed("https://example.com/docs/index.html", None, None));
        let decision = engine.evaluate("https://example.com/api/v1", None, None, &HeaderMap::new());

        assert!(decision.allowed);
        let matched = decision.matched.expect("matched rule");
        assert_eq!(matched.index, 1);
        assert_eq!(
            matched.pattern.as_deref(),
            Some("https://example.com/api/**")
        );
        assert_eq!(matched.description.as_deref(), Some("Example grouped rule"));
        assert!(!engine.is_allowed("https://example.com/other", None, None));
    }

    #[test]
    fn direct_patterns_preserve_order_and_first_match_wins() {
        let toml = r#"
default = "deny"

[[rules]]
action = "deny"
patterns = [
  "https://example.com/admin/**",
  "https://example.com/private/**",
]

[[rules]]
	action = "allow"
pattern = "https://example.com/**"
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        assert!(!engine.is_allowed("https://example.com/admin/settings", None, None));
        assert!(!engine.is_allowed("https://example.com/private/data", None, None));
        assert!(engine.is_allowed("https://example.com/public", None, None));
    }

    #[test]
    fn direct_patterns_copy_predicates_header_actions_and_external_auth_metadata() {
        let toml = r#"
default = "deny"

[external_auth_profiles.example]
webhook_url = "https://auth.internal/start"
timeout_ms = 5000

[[rules]]
action = "delegate"
patterns = [
  "https://example.com/api/**",
  "https://example.com/files/**",
]
methods = ["GET"]
headers_absent = ["x-blocked"]
headers_match = { "x-workload-id" = "worker-123" }
external_auth_profile = "example"
request_timeout_ms = 1500

[[rules.header_actions]]
direction = "request"
action = "set"
name = "x-test"
value = "one"
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");
        let headers = header_map(&[("x-workload-id", "worker-123")]);
        let decision = engine.evaluate(
            "https://example.com/files/report",
            None,
            Some("GET"),
            &headers,
        );

        assert!(!decision.allowed);
        let matched = decision.matched.expect("matched rule");
        assert_eq!(
            matched.pattern.as_deref(),
            Some("https://example.com/files/**")
        );
        assert_eq!(matched.methods, vec!["GET".to_string()]);
        assert_eq!(matched.request_timeout_ms, Some(1500));
        assert_eq!(matched.header_actions.len(), 1);
        assert_eq!(matched.external_auth_profile.as_deref(), Some("example"));

        let effective = EffectivePolicy::from_config(&cfg).expect("build effective policy");
        assert_eq!(effective.rules.len(), 2);
        assert_eq!(
            effective.rules[0].pattern.as_deref(),
            Some("https://example.com/api/**")
        );
        assert_eq!(
            effective.rules[1].pattern.as_deref(),
            Some("https://example.com/files/**")
        );
        assert_eq!(effective.rules[1].header_actions.len(), 1);
        assert_eq!(
            effective.rules[1]
                .external_auth
                .as_ref()
                .map(|external| external.profile.as_str()),
            Some("example")
        );
    }

    #[test]
    fn direct_patterns_validation_rejects_invalid_shapes() {
        let cases = [
            (
                r#"
default = "deny"

[[rules]]
action = "allow"
pattern = "https://example.com/**"
patterns = ["https://example.org/**"]
                "#,
                "policy rule must not define both pattern and patterns",
            ),
            (
                r#"
default = "deny"

[[rules]]
action = "allow"
patterns = []
                "#,
                "patterns must include at least one pattern",
            ),
            (
                r#"
default = "deny"

[[rules]]
action = "allow"
patterns = ["https://example.com/**", "   "]
                "#,
                "patterns entry at index 1 must not be empty",
            ),
            (
                r#"
default = "deny"

[[rules]]
action = "allow"
patterns = ["https://example.com/**", " https://example.com/** "]
                "#,
                "patterns entry at index 1 duplicates an earlier pattern",
            ),
            (
                r#"
default = "deny"

[[rules]]
action = "allow"
patterns = ["https://example.com/**", "https://example.org/**"]
rule_id = "duplicate"
                "#,
                "rule_id is not allowed on multi-pattern rules",
            ),
        ];

        for (toml, expected) in cases {
            let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
            let err = PolicyEngine::from_config(&cfg).expect_err("expected validation error");
            let msg = format!("{err}");
            assert!(
                msg.contains(expected),
                "expected {expected:?} in error message: {msg}"
            );
        }
    }

    #[test]
    fn direct_patterns_trim_entries_and_allow_patternless_header_rules() {
        let patternless_toml = r#"
default = "deny"

[[rules]]
action = "allow"
headers_match = { "x-workload-id" = "worker-123" }
        "#;
        let patternless_cfg: PolicyConfig =
            toml::from_str(patternless_toml).expect("parse policy config");
        let patternless =
            PolicyEngine::from_config(&patternless_cfg).expect("header-only rule remains valid");
        assert!(patternless.is_allowed_with_headers(
            "https://example.com/anything",
            None,
            None,
            &header_map(&[("x-workload-id", "worker-123")])
        ));

        let trimmed_toml = r#"
default = "deny"

[[rules]]
action = "allow"
patterns = ["  https://example.com/docs/**  "]
        "#;
        let trimmed_cfg: PolicyConfig = toml::from_str(trimmed_toml).expect("parse policy config");
        let effective = EffectivePolicy::from_config(&trimmed_cfg).expect("effective policy");
        assert_eq!(
            effective.rules[0].pattern.as_deref(),
            Some("https://example.com/docs/**")
        );
    }

    #[test]
    fn direct_patterns_expand_macros_and_url_encoded_variants() {
        let toml = r#"
default = "deny"

[macros]
repo = ["sip/sipsource", "sip/sipsink"]

[[rules]]
action = "allow"
patterns = [
  "https://gitlab.internal/{repo}.git/**",
  "https://gitlab.internal/api/v4/projects/{repo}?**",
]
add_url_enc_variants = ["repo"]
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let engine = PolicyEngine::from_config(&cfg).expect("build policy engine");

        assert!(engine.is_allowed(
            "https://gitlab.internal/sip/sipsource.git/info/refs",
            None,
            None
        ));
        assert!(engine.is_allowed(
            "https://gitlab.internal/api/v4/projects/sip%2Fsipsink?statistics=true",
            None,
            None
        ));

        let effective = EffectivePolicy::from_config(&cfg).expect("effective policy");
        let patterns = effective
            .rules
            .iter()
            .map(|rule| rule.pattern.as_deref().expect("pattern"))
            .collect::<Vec<_>>();

        assert_eq!(
            patterns,
            vec![
                "https://gitlab.internal/sip/sipsource.git/**",
                "https://gitlab.internal/sip%2Fsipsource.git/**",
                "https://gitlab.internal/sip/sipsink.git/**",
                "https://gitlab.internal/sip%2Fsipsink.git/**",
                "https://gitlab.internal/api/v4/projects/sip/sipsource?**",
                "https://gitlab.internal/api/v4/projects/sip%2Fsipsource?**",
                "https://gitlab.internal/api/v4/projects/sip/sipsink?**",
                "https://gitlab.internal/api/v4/projects/sip%2Fsipsink?**",
            ]
        );
    }

    #[test]
    fn direct_patterns_with_divergent_placeholders_match_duplicated_rule_behavior() {
        let toml = r#"
default = "deny"

[macros]
tenant = ["tenant-a"]
repo = ["service-a", "service-b"]

[[rules]]
action = "allow"
patterns = [
  "https://example.com/static/{tenant}/**",
  "https://example.com/repos/{repo}/**",
]
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let effective = EffectivePolicy::from_config(&cfg).expect("effective policy");
        let patterns = effective
            .rules
            .iter()
            .map(|rule| rule.pattern.as_deref().expect("pattern"))
            .collect::<Vec<_>>();

        assert_eq!(
            patterns,
            vec![
                "https://example.com/static/tenant-a/**",
                "https://example.com/repos/service-a/**",
                "https://example.com/repos/service-b/**",
            ]
        );
    }

    #[test]
    fn ruleset_template_patterns_expand_and_validate() {
        let toml = r#"
default = "deny"

[macros]
repo = ["sip/sipsource"]

[[rulesets.gitlab]]
action = "allow"
patterns = [
  "https://gitlab.internal/{repo}.git/**",
  "https://gitlab.internal/api/v4/projects/{repo}?**",
]
methods = ["GET"]

[[rules]]
include = "gitlab"
add_url_enc_variants = ["repo"]
methods = ["POST"]
subnets = ["10.0.0.0/8"]
request_timeout_ms = 2500
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let effective = EffectivePolicy::from_config(&cfg).expect("effective policy");

        assert_eq!(effective.rules.len(), 4);
        assert_eq!(
            effective.rules[0].pattern.as_deref(),
            Some("https://gitlab.internal/sip/sipsource.git/**")
        );
        assert_eq!(
            effective.rules[1].pattern.as_deref(),
            Some("https://gitlab.internal/sip%2Fsipsource.git/**")
        );
        assert_eq!(
            effective.rules[2].pattern.as_deref(),
            Some("https://gitlab.internal/api/v4/projects/sip/sipsource?**")
        );
        assert_eq!(
            effective.rules[3].pattern.as_deref(),
            Some("https://gitlab.internal/api/v4/projects/sip%2Fsipsource?**")
        );
        for rule in &effective.rules {
            assert_eq!(rule.methods, vec!["POST".to_string()]);
            assert_eq!(
                rule.subnets.iter().map(|subnet| subnet.to_string()).collect::<Vec<_>>(),
                vec!["10.0.0.0/8".to_string()]
            );
            assert_eq!(rule.request_timeout_ms, Some(2500));
        }

        let invalid_toml = r#"
default = "deny"

[[rulesets.bad]]
action = "allow"
pattern = "https://example.com/**"
patterns = ["https://example.org/**"]

[[rules]]
include = "bad"
        "#;
        let invalid_cfg: PolicyConfig = toml::from_str(invalid_toml).expect("parse policy config");
        let err = EffectivePolicy::from_config(&invalid_cfg).expect_err("expected error");
        let msg = format!("{err}");
        assert!(
            msg.contains("policy ruleset template must not define both pattern and patterns"),
            "unexpected error message: {msg}"
        );

        let rule_id_toml = r#"
default = "deny"

[[rulesets.bad]]
action = "allow"
patterns = ["https://example.com/**", "https://example.org/**"]
rule_id = "duplicate"

[[rules]]
include = "bad"
        "#;
        let rule_id_cfg: PolicyConfig = toml::from_str(rule_id_toml).expect("parse policy config");
        let err = EffectivePolicy::from_config(&rule_id_cfg).expect_err("expected error");
        let msg = format!("{err}");
        assert!(
            msg.contains("rule_id is not allowed on multi-pattern rules"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn effective_policy_includes_header_actions() {
        let toml = r#"
default = "deny"

[[rules]]
action = "allow"
pattern = "https://example.com/**"

[[rules.header_actions]]
direction = "request"
action = "set"
name = "x-test"
value = "one"
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let effective = EffectivePolicy::from_config(&cfg).expect("build effective policy");

        assert_eq!(effective.rules.len(), 1);
        let rule = &effective.rules[0];
        assert_eq!(rule.header_actions.len(), 1);
        let ha = &rule.header_actions[0];
        assert_eq!(ha.name, "x-test");
        assert_eq!(ha.values, vec!["one".to_string()]);
    }

    #[test]
    fn effective_policy_includes_external_auth_metadata() {
        let toml = r#"
default = "deny"

[external_auth_profiles.example]
webhook_url = "https://auth.internal/start"
timeout_ms = 5000

[[rules]]
action = "delegate"
pattern = "https://example.com/**"
external_auth_profile = "example"
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let effective = EffectivePolicy::from_config(&cfg).expect("build effective policy");

        assert_eq!(effective.rules.len(), 1);
        let rule = &effective.rules[0];
        let ext = rule
            .external_auth
            .as_ref()
            .expect("external_auth metadata should be present");
        assert_eq!(ext.profile, "example");
        assert_eq!(ext.timeout_ms, 5000);
    }

    #[test]
    fn effective_policy_includes_headers_absent() {
        let toml = r#"
default = "deny"

[[rules]]
action = "deny"
pattern = "**"
headers_absent = ["x-workload-id"]
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let effective = EffectivePolicy::from_config(&cfg).expect("build effective policy");

        assert_eq!(effective.rules.len(), 1);
        assert_eq!(
            effective.rules[0].headers_absent,
            vec!["x-workload-id".to_string()]
        );
    }

    #[test]
    fn effective_policy_includes_headers_match_and_defaults_to_empty_object() {
        let configured_toml = r#"
default = "deny"

[[rules]]
action = "allow"
pattern = "https://example.com/**"
headers_match = { "x-workload-id" = ["worker-123", "worker-456"], "x-tenant-id" = "tenant-a" }
        "#;

        let unset_toml = r#"
default = "deny"

[[rules]]
action = "allow"
pattern = "https://example.com/**"
        "#;

        let configured_cfg: PolicyConfig =
            toml::from_str(configured_toml).expect("parse policy config");
        let unset_cfg: PolicyConfig = toml::from_str(unset_toml).expect("parse policy config");

        let configured =
            EffectivePolicy::from_config(&configured_cfg).expect("build effective policy");
        let unset = EffectivePolicy::from_config(&unset_cfg).expect("build effective policy");

        assert_eq!(
            configured.rules[0].headers_match,
            BTreeMap::from([
                ("x-tenant-id".to_string(), vec!["tenant-a".to_string()]),
                (
                    "x-workload-id".to_string(),
                    vec!["worker-123".to_string(), "worker-456".to_string()]
                ),
            ])
        );
        assert!(
            unset.rules[0].headers_match.is_empty(),
            "headers_match should be serialized as empty object when unset"
        );
    }

    #[test]
    fn headers_absent_rejects_invalid_header_names() {
        let toml = r#"
default = "deny"

[[rules]]
action = "deny"
headers_absent = ["bad header"]
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let err = PolicyEngine::from_config(&cfg).expect_err("expected error");
        let msg = format!("{err}");
        assert!(
            msg.contains("invalid header name 'bad header' in headers_absent"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn headers_absent_rejects_duplicates_after_normalization() {
        let toml = r#"
default = "deny"

[[rules]]
action = "deny"
headers_absent = ["X-Workload-Id", "x-workload-id"]
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let err = PolicyEngine::from_config(&cfg).expect_err("expected error");
        let msg = format!("{err}");
        assert!(
            msg.contains(
                "duplicate header name 'x-workload-id' in headers_absent after normalization"
            ) || msg.contains(
                "duplicate header name 'X-Workload-Id' in headers_absent after normalization"
            ),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn ruleset_template_headers_absent_is_validated() {
        let toml = r#"
default = "deny"

[[rulesets.guard]]
action = "deny"
pattern = "https://example.com/**"
headers_absent = ["x-workload-id", "X-Workload-Id"]

[[rules]]
include = "guard"
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let err = PolicyEngine::from_config(&cfg).expect_err("expected error");
        let msg = format!("{err}");
        assert!(
            msg.contains("duplicate header name"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn headers_absent_valid_names_are_normalized() {
        let toml = r#"
default = "deny"

[[rules]]
action = "deny"
headers_absent = ["X-Workload-Id", "X-Trace-Id"]
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let expanded = expand_policy(&cfg).expect("expand policy");

        assert_eq!(expanded.rules.len(), 1);
        assert_eq!(
            expanded.rules[0].headers_absent,
            Some(vec!["x-workload-id".to_string(), "x-trace-id".to_string()])
        );
    }

    #[test]
    fn headers_match_rejects_empty_map() {
        let toml = r#"
default = "deny"

[[rules]]
action = "deny"
headers_match = {}
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let err = PolicyEngine::from_config(&cfg).expect_err("expected error");
        let msg = format!("{err}");
        assert!(
            msg.contains("headers_match must not be empty"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn headers_match_rejects_invalid_header_names() {
        let toml = r#"
default = "deny"

[[rules]]
action = "deny"
headers_match = { "bad header" = "worker-123" }
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let err = PolicyEngine::from_config(&cfg).expect_err("expected error");
        let msg = format!("{err}");
        assert!(
            msg.contains("invalid header name 'bad header' in headers_match"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn headers_match_rejects_duplicates_after_normalization() {
        let toml = r#"
default = "deny"

[[rules]]
action = "deny"
headers_match = { "X-Workload-Id" = "worker-123", "x-workload-id" = "worker-456" }
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let err = PolicyEngine::from_config(&cfg).expect_err("expected error");
        let msg = format!("{err}");
        assert!(
            msg.contains("duplicate header name"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn headers_match_rejects_empty_values_or_value_lists() {
        let empty_value_toml = r#"
default = "deny"

[[rules]]
action = "deny"
headers_match = { "x-workload-id" = "" }
        "#;

        let empty_list_toml = r#"
default = "deny"

[[rules]]
action = "deny"
headers_match = { "x-workload-id" = [] }
        "#;

        let empty_value_cfg: PolicyConfig =
            toml::from_str(empty_value_toml).expect("parse policy config");
        let empty_list_cfg: PolicyConfig =
            toml::from_str(empty_list_toml).expect("parse policy config");

        let empty_value_msg = format!(
            "{}",
            PolicyEngine::from_config(&empty_value_cfg).expect_err("expected err")
        );
        let empty_list_msg = format!(
            "{}",
            PolicyEngine::from_config(&empty_list_cfg).expect_err("expected err")
        );

        assert!(
            empty_value_msg.contains("must not include empty-string values"),
            "unexpected error message: {empty_value_msg}"
        );
        assert!(
            empty_list_msg.contains("must include at least one allowed value"),
            "unexpected error message: {empty_list_msg}"
        );
    }

    #[test]
    fn headers_match_valid_names_and_values_are_normalized() {
        let toml = r#"
default = "deny"

[[rules]]
action = "deny"
headers_match = { "X-Workload-Id" = ["worker-123", "worker-456"], "x-tenant-id" = "tenant-a" }
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let expanded = expand_policy(&cfg).expect("expand policy");

        assert_eq!(expanded.rules.len(), 1);
        assert_eq!(
            expanded.rules[0].headers_match,
            Some(BTreeMap::from([
                ("x-tenant-id".to_string(), vec!["tenant-a".to_string()]),
                (
                    "x-workload-id".to_string(),
                    vec!["worker-123".to_string(), "worker-456".to_string()]
                ),
            ]))
        );
    }

    #[test]
    fn ruleset_template_headers_match_is_validated() {
        let toml = r#"
default = "deny"

[[rulesets.guard]]
action = "deny"
pattern = "https://example.com/**"
headers_match = { "x-workload-id" = [], "x-tenant-id" = "tenant-a" }

[[rules]]
include = "guard"
        "#;

        let cfg: PolicyConfig = toml::from_str(toml).expect("parse policy config");
        let err = PolicyEngine::from_config(&cfg).expect_err("expected error");
        let msg = format!("{err}");
        assert!(
            msg.contains(
                "headers_match entry 'x-workload-id' must include at least one allowed value"
            ),
            "unexpected error message: {msg}"
        );
    }
}
