use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use ipnet::Ipv4Net;
use regex::{Regex, RegexBuilder};
use serde::Serialize;
use thiserror::Error;
use url::Url;

use crate::config::{
    MacroMap, MacroOverrideMap, MacroValues, PolicyConfig, PolicyDefaultAction,
    PolicyRuleConfig, PolicyRuleDirectConfig, PolicyRuleIncludeConfig,
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
    pub action: PolicyDefaultAction,
    pub pattern: Option<String>,
    pub description: Option<String>,
    pub subnets: Vec<Ipv4Net>,
    pub methods: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    default_action: PolicyDefaultAction,
    rules: Vec<CompiledRule>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    action: PolicyDefaultAction,
    pattern: Option<String>,
    regex: Option<Regex>,
    description: Option<String>,
    subnets: Vec<Ipv4Net>,
    methods: Vec<String>,
}

#[derive(Debug, Clone)]
struct ExpandedPolicy {
    default: PolicyDefaultAction,
    rules: Vec<ExpandedRule>,
}

#[derive(Debug, Clone)]
struct ExpandedRule {
    action: PolicyDefaultAction,
    pattern: Option<String>,
    description: Option<String>,
    subnets: Vec<Ipv4Net>,
    methods: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectivePolicy {
    pub default: PolicyDefaultAction,
    pub rules: Vec<EffectiveRule>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveRule {
    pub index: usize,
    pub action: PolicyDefaultAction,
    pub pattern: Option<String>,
    pub description: Option<String>,
    pub subnets: Vec<Ipv4Net>,
    pub methods: Vec<String>,
}

impl PolicyEngine {
    pub fn from_config(cfg: &PolicyConfig) -> Result<Self, PolicyError> {
        let expanded = expand_policy(cfg)?;
        let mut compiled_rules = Vec::with_capacity(expanded.rules.len());

        for (idx, rule) in expanded.rules.into_iter().enumerate() {
            let regex = if let Some(ref pattern) = rule.pattern {
                let pattern_re = pattern_to_regex(pattern);
                Some(
                    RegexBuilder::new(&pattern_re)
                        .case_insensitive(true)
                        .build()
                        .map_err(|source| PolicyError::PatternCompile {
                            index: idx,
                            source,
                        })?,
                )
            } else {
                None
            };

            compiled_rules.push(CompiledRule {
                action: rule.action,
                pattern: rule.pattern,
                regex,
                description: rule.description,
                subnets: rule.subnets,
                methods: rule.methods,
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

        for rule in &self.rules {
            if let Some(ref re) = rule.regex {
                if !re.is_match(&normalized_url) {
                    continue;
                }
            }

            if !rule.subnets.is_empty() {
                if !client_in_any_subnet(normalized_ip.as_deref(), &rule.subnets)
                {
                    continue;
                }
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

            let matched = MatchedRule {
                action: rule.action,
                pattern: rule.pattern.clone(),
                description: rule.description.clone(),
                subnets: rule.subnets.clone(),
                methods: rule.methods.clone(),
            };

            let allowed = matches!(rule.action, PolicyDefaultAction::Allow);

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

    pub fn is_allowed(
        &self,
        url_str: &str,
        client_ip: Option<&str>,
        method: Option<&str>,
    ) -> bool {
        self.evaluate(url_str, client_ip, method).allowed
    }
}

impl EffectivePolicy {
    pub fn from_config(cfg: &PolicyConfig) -> Result<Self, PolicyError> {
        let expanded = expand_policy(cfg)?;

        let rules = expanded
            .rules
            .into_iter()
            .enumerate()
            .map(|(index, rule)| EffectiveRule {
                index,
                action: rule.action,
                pattern: rule.pattern,
                description: rule.description,
                subnets: rule.subnets,
                methods: rule.methods,
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

    let mut expanded_rules = Vec::new();

    for (index, rule) in cfg.rules.iter().enumerate() {
        match rule {
            PolicyRuleConfig::Direct(d) => {
                expand_direct_rule(
                    d,
                    macros,
                    index,
                    &mut expanded_rules,
                )?
            }
            PolicyRuleConfig::Include(i) => expand_include_rule(
                i,
                macros,
                rulesets,
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
    index: usize,
    out: &mut Vec<ExpandedRule>,
) -> Result<(), PolicyError> {
    let pattern = rule
        .pattern
        .as_ref()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string());

    let methods = rule
        .methods
        .as_ref()
        .map(|m| m.as_slice().to_vec())
        .unwrap_or_default();

    let has_pattern = pattern.is_some();
    let has_subnets = !rule.subnets.is_empty();
    let has_methods = !methods.is_empty();

    if !has_pattern && (has_subnets || has_methods) {
        out.push(ExpandedRule {
            action: rule.action,
            pattern: None,
            description: rule.description.clone(),
            subnets: rule.subnets.clone(),
            methods,
        });
        return Ok(());
    }

    if !has_pattern {
        return Err(PolicyError::RuleInvalid {
            index,
            reason: "policy rule must define at least a pattern, subnets, or methods"
                .to_string(),
        });
    }

    let pattern_str = pattern.unwrap();
    let mut placeholders = BTreeSet::new();
    collect_placeholders(&pattern_str, &mut placeholders);
    if let Some(desc) = &rule.description {
        collect_placeholders(desc, &mut placeholders);
    }

    if placeholders.is_empty() {
        out.push(ExpandedRule {
            action: rule.action,
            pattern: Some(pattern_str),
            description: rule.description.clone(),
            subnets: rule.subnets.clone(),
            methods,
        });
        return Ok(());
    }

    let resolved =
        resolve_placeholders(rule.with.as_ref(), macros, &placeholders, |_| {
            format!(
                " (required by direct rule pattern {pattern})",
                pattern = pattern_str
            )
        })?;

    let mut combos = cartesian_product(&resolved);
    let keys_to_vary =
        keys_for_url_variants(rule.add_url_enc_variants.as_ref(), &placeholders);
    if !keys_to_vary.is_empty() {
        combos = add_url_encoded_variants(combos, &keys_to_vary);
    }

    for combo in combos {
        let pattern_interp = interpolate_template(&pattern_str, &combo);
        let description_interp =
            rule.description.as_ref().map(|d| interpolate_template(d, &combo));

        out.push(ExpandedRule {
            action: rule.action,
            pattern: Some(pattern_interp),
            description: description_interp,
            subnets: rule.subnets.clone(),
            methods: methods.clone(),
        });
    }

    Ok(())
}

fn expand_include_rule(
    rule: &PolicyRuleIncludeConfig,
    macros: &MacroMap,
    rulesets: &RulesetMap,
    _index: usize,
    out: &mut Vec<ExpandedRule>,
) -> Result<(), PolicyError> {
    let templates = rulesets
        .get(&rule.include)
        .ok_or_else(|| PolicyError::RulesetNotFound {
            name: rule.include.clone(),
        })?;

    let mut placeholders = BTreeSet::new();
    for template in templates {
        collect_placeholders(&template.pattern, &mut placeholders);
        if let Some(desc) = &template.description {
            collect_placeholders(desc, &mut placeholders);
        }
    }

    if placeholders.is_empty() {
        for template in templates {
            let methods = rule
                .methods
                .as_ref()
                .map(|m| m.as_slice().to_vec())
                .or_else(|| {
                    template
                        .methods
                        .as_ref()
                        .map(|m| m.as_slice().to_vec())
                })
                .unwrap_or_default();

            out.push(ExpandedRule {
                action: template.action,
                pattern: Some(template.pattern.clone()),
                description: template.description.clone(),
                subnets: if !rule.subnets.is_empty() {
                    rule.subnets.clone()
                } else {
                    template.subnets.clone()
                },
                methods,
            });
        }
        return Ok(());
    }

    let resolved = resolve_placeholders(
        rule.with.as_ref(),
        macros,
        &placeholders,
        |_| {
            format!(" (required by ruleset {ruleset})", ruleset = rule.include)
        },
    )?;

    let mut combos = cartesian_product(&resolved);
    let keys_to_vary =
        keys_for_url_variants(rule.add_url_enc_variants.as_ref(), &placeholders);
    if !keys_to_vary.is_empty() {
        combos = add_url_encoded_variants(combos, &keys_to_vary);
    }

    for combo in combos {
        for template in templates {
            let methods = rule
                .methods
                .as_ref()
                .map(|m| m.as_slice().to_vec())
                .or_else(|| {
                    template
                        .methods
                        .as_ref()
                        .map(|m| m.as_slice().to_vec())
                })
                .unwrap_or_default();

            let pattern_interp = interpolate_template(&template.pattern, &combo);
            let description_interp = template
                .description
                .as_ref()
                .map(|d| interpolate_template(d, &combo));

            out.push(ExpandedRule {
                action: template.action,
                pattern: Some(pattern_interp),
                description: description_interp,
                subnets: if !rule.subnets.is_empty() {
                    rule.subnets.clone()
                } else {
                    template.subnets.clone()
                },
                methods,
            });
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

fn cartesian_product(
    vars: &BTreeMap<String, Vec<String>>,
) -> Vec<BTreeMap<String, String>> {
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
                if !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    out.insert(name.to_string());
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
}

fn interpolate_template(
    input: &str,
    vars: &BTreeMap<String, String>,
) -> String {
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
                if !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
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
            '.' | '*' | '+' | '?' | '^' | '$' | '{' | '}' | '(' | ')' | '|'
            | '[' | ']' | '\\' => {
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
    let (has_scheme, rest) = if lower.starts_with("http://") {
        (true, &raw[7..])
    } else if lower.starts_with("https://") {
        (true, &raw[8..])
    } else {
        let trimmed = raw.trim_start_matches('/');
        (false, trimmed)
    };

    let mut rest = if has_scheme {
        rest.to_string()
    } else {
        rest.to_string()
    };

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
    let mut s = escaped
        .replace("\\*\\*", ".*")
        .replace("\\*", "[^/]*");

    if is_host_only {
        s.push_str("/?");
    }

    let scheme_regex = "https?://";
    format!("^{}{}$", scheme_regex, s)
}

fn normalize_url(raw: &str) -> Result<String, PolicyError> {
    let url = Url::parse(raw)
        .map_err(|e| PolicyError::UrlParse(e.to_string()))?;

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
        None => {
            return Err(PolicyError::UrlParse(
                "URL is missing host".to_string(),
            ))
        }
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

fn client_in_any_subnet(
    raw_ip: Option<&str>,
    subnets: &[Ipv4Net],
) -> bool {
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

    let v4 = match parsed {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return false,
    };

    for net in subnets {
        if net.contains(&v4) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PolicyRuleTemplateConfig;
    use toml;

    fn allow_action() -> PolicyDefaultAction {
        PolicyDefaultAction::Allow
    }

    #[test]
    fn pattern_to_regex_host_only() {
        let re = Regex::new(&pattern_to_regex("https://example.com"))
            .expect("compile regex");
        assert!(re.is_match("https://example.com"));
        assert!(re.is_match("https://example.com/"));
        assert!(!re.is_match("https://example.com/path"));
    }

    #[test]
    fn pattern_to_regex_wildcards() {
        let re = Regex::new(&pattern_to_regex(
            "https://example.com/api/**",
        ))
        .expect("compile regex");
        assert!(re.is_match("https://example.com/api/"));
        assert!(re.is_match("https://example.com/api/v1/resource"));

        let re2 = Regex::new(&pattern_to_regex(
            "https://example.com/api/*/resource",
        ))
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
            rulesets: RulesetMap::default(),
            rules: vec![PolicyRuleConfig::Direct(
                PolicyRuleDirectConfig {
                    action: PolicyDefaultAction::Allow,
                    pattern: None,
                    description: None,
                    methods: None,
                    subnets: vec!["192.168.0.0/16"
                        .parse::<Ipv4Net>()
                        .unwrap()],
                    with: None,
                    add_url_enc_variants: None,
                },
            )],
        };

        let engine =
            PolicyEngine::from_config(&cfg).expect("build policy engine");
        assert!(engine.is_allowed(
            "https://example.com/",
            Some("192.168.1.10"),
            None
        ));
        assert!(!engine.is_allowed(
            "https://example.com/",
            Some("10.0.0.1"),
            None
        ));
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
                    pattern:
                        "https://gitlab.internal/api/v4/projects/{repo}?**"
                            .to_string(),
                    description: None,
                    methods: None,
                    subnets: Vec::new(),
                },
                PolicyRuleTemplateConfig {
                    action: allow_action(),
                    pattern:
                        "https://gitlab.internal/{repo}.git/**".to_string(),
                    description: None,
                    methods: None,
                    subnets: Vec::new(),
                },
            ],
        );

        let cfg = PolicyConfig {
            default: PolicyDefaultAction::Deny,
            macros,
            rulesets,
            rules: vec![PolicyRuleConfig::Include(
                PolicyRuleIncludeConfig {
                    include: "gitlabRepo".to_string(),
                    with: None,
                    add_url_enc_variants: Some(UrlEncVariants::All(true)),
                    methods: None,
                    subnets: Vec::new(),
                },
            )],
        };

        let engine =
            PolicyEngine::from_config(&cfg).expect("build policy engine");

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
        assert!(!engine.is_allowed(
            "https://gitlab.internal/other/repo/any",
            None,
            None
        ));
    }

    #[test]
    fn missing_macro_in_ruleset_causes_error() {
        let rulesets = {
            let mut m = RulesetMap::default();
            m.insert(
                "needsRepo".to_string(),
                vec![PolicyRuleTemplateConfig {
                    action: allow_action(),
                    pattern:
                        "https://gitlab.internal/api/v4/projects/{repo}?**"
                            .to_string(),
                    description: None,
                    methods: None,
                    subnets: Vec::new(),
                }],
            );
            m
        };

        let cfg = PolicyConfig {
            default: PolicyDefaultAction::Deny,
            macros: MacroMap::default(),
            rulesets,
            rules: vec![PolicyRuleConfig::Include(
                PolicyRuleIncludeConfig {
                    include: "needsRepo".to_string(),
                    with: None,
                    add_url_enc_variants: Some(UrlEncVariants::All(true)),
                    methods: None,
                    subnets: Vec::new(),
                },
            )],
        };

        let err =
            PolicyEngine::from_config(&cfg).expect_err("expected error");
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

        let cfg: PolicyConfig =
            toml::from_str(toml).expect("parse policy config");
        let engine =
            PolicyEngine::from_config(&cfg).expect("build policy engine");

        assert!(engine.is_allowed(
            "https://example.com/path",
            None,
            Some("GET")
        ));
        assert!(engine.is_allowed(
            "https://example.com/path",
            None,
            Some("head")
        ));
        assert!(!engine.is_allowed(
            "https://example.com/path",
            None,
            Some("POST")
        ));

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

        let cfg: PolicyConfig =
            toml::from_str(toml).expect("parse policy config");
        let engine =
            PolicyEngine::from_config(&cfg).expect("build policy engine");

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

        let cfg: PolicyConfig =
            toml::from_str(toml).expect("parse policy config");
        let engine =
            PolicyEngine::from_config(&cfg).expect("build policy engine");

        assert!(engine.is_allowed(
            "https://example.com/path",
            None,
            Some("HEAD")
        ));
        assert!(!engine.is_allowed(
            "https://example.com/path",
            None,
            Some("GET")
        ));
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

        let cfg: PolicyConfig =
            toml::from_str(toml).expect("parse policy config");
        let engine =
            PolicyEngine::from_config(&cfg).expect("build policy engine");

        assert!(engine.is_allowed(
            "https://example.com/path",
            None,
            Some("PUT")
        ));
        assert!(!engine.is_allowed(
            "https://example.com/path",
            None,
            Some("GET")
        ));
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

        let cfg: PolicyConfig =
            toml::from_str(toml).expect("parse policy config");
        let engine =
            PolicyEngine::from_config(&cfg).expect("build policy engine");

        // Matches the second rule.
        assert!(engine.is_allowed(
            "https://example.com/public",
            None,
            None
        ));

        // Matches the first (deny) rule.
        assert!(!engine.is_allowed(
            "https://example.com/admin/panel",
            None,
            None
        ));
    }

    #[test]
    fn default_action_applies_when_no_rules_match() {
        let toml = r#"
default = "allow"
        "#;

        let cfg: PolicyConfig =
            toml::from_str(toml).expect("parse policy config");
        let engine =
            PolicyEngine::from_config(&cfg).expect("build policy engine");

        assert!(engine.is_allowed(
            "https://anything.com/path",
            None,
            None
        ));
    }

    #[test]
    fn invalid_urls_are_denied() {
        let toml = r#"
default = "allow"
        "#;

        let cfg: PolicyConfig =
            toml::from_str(toml).expect("parse policy config");
        let engine =
            PolicyEngine::from_config(&cfg).expect("build policy engine");

        assert!(engine.is_allowed(
            "https://example.com/path",
            None,
            None
        ));
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

        let cfg: PolicyConfig =
            toml::from_str(toml).expect("parse policy config");
        let err =
            PolicyEngine::from_config(&cfg).expect_err("expected error");
        let msg = format!("{err}");
        assert!(
            msg.contains("Policy macro not found: repo"),
            "unexpected error message: {msg}"
        );
    }
}
