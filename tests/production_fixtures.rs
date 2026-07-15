use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value as JsonValue};
use toml::Value as TomlValue;

fn production_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/production")
        .join(name)
}

fn parse_fixture(name: &str) -> TomlValue {
    let path = production_fixture(name);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    toml::from_str(&source)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn table<'a>(value: &'a TomlValue, key: &str) -> &'a toml::map::Map<String, TomlValue> {
    value
        .get(key)
        .and_then(TomlValue::as_table)
        .unwrap_or_else(|| panic!("expected table {key}"))
}

fn rules(config: &TomlValue) -> &[TomlValue] {
    table(config, "policy")
        .get("rules")
        .and_then(TomlValue::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn strings<'a>(value: &'a TomlValue, key: &str) -> Vec<&'a str> {
    value
        .get(key)
        .and_then(TomlValue::as_array)
        .map(|values| {
            values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .unwrap_or_else(|| panic!("expected string in {key}"))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn sanitized_production_role_structure_matches_difference_record() {
    let expectations = [
        ("host-proxy.toml", 45, 134, 22, 2, 4),
        ("common-container-proxy.toml", 1, 1, 0, 0, 0),
        ("internal-container-proxy.toml", 8, 12, 1, 0, 0),
    ];

    for (
        name,
        rule_count,
        pattern_count,
        method_rule_count,
        provider_count,
        redaction_rule_count,
    ) in expectations
    {
        let config = parse_fixture(name);
        assert_eq!(
            config.get("schema_version").and_then(TomlValue::as_integer),
            Some(3)
        );
        assert!(
            config.get("proxy").is_none(),
            "{name} retained a v1 proxy table"
        );

        let role_rules = rules(&config);
        assert_eq!(role_rules.len(), rule_count, "{name} rule count");
        assert_eq!(
            role_rules
                .iter()
                .map(|rule| strings(rule, "urls").len())
                .sum::<usize>(),
            pattern_count,
            "{name} URL-pattern count"
        );
        assert_eq!(
            role_rules
                .iter()
                .filter(|rule| !strings(rule, "methods").is_empty())
                .count(),
            method_rule_count,
            "{name} method-constrained rule count"
        );
        assert_eq!(
            role_rules
                .iter()
                .filter(|rule| rule.get("redaction_profile").is_some())
                .count(),
            redaction_rule_count,
            "{name} wire-redaction rule count"
        );
        assert_eq!(
            config
                .get("authorization")
                .and_then(|authorization| authorization.get("providers"))
                .and_then(TomlValue::as_table)
                .map_or(0, toml::map::Map::len),
            provider_count,
            "{name} provider count"
        );

        let ids: BTreeSet<_> = role_rules
            .iter()
            .map(|rule| {
                rule.get("id")
                    .and_then(TomlValue::as_str)
                    .expect("every v3 production rule must have an ID")
            })
            .collect();
        assert_eq!(ids.len(), rule_count, "{name} rule IDs must be unique");
        assert!(role_rules.iter().all(|rule| rule.get("decision").is_some()));
        assert!(role_rules
            .iter()
            .all(|rule| rule.get("action").is_none() && rule.get("pattern").is_none()));
    }

    let host = parse_fixture("host-proxy.toml");
    let decisions = rules(&host)
        .iter()
        .fold(BTreeMap::new(), |mut counts, rule| {
            let decision = rule
                .get("decision")
                .and_then(TomlValue::as_str)
                .expect("host rule decision");
            *counts.entry(decision).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(decisions.get("allow"), Some(&37));
    assert_eq!(decisions.get("deny"), Some(&7));
    assert_eq!(decisions.get("delegate"), Some(&1));

    let delegate = rules(&host)
        .iter()
        .find(|rule| rule.get("decision").and_then(TomlValue::as_str) == Some("delegate"))
        .expect("host fixture must retain one delegated GitLab rule");
    assert_eq!(
        delegate.get("id").and_then(TomlValue::as_str),
        Some("prod-host-r42-gitlab-delegate")
    );
    assert_eq!(
        delegate
            .get("authorization_provider")
            .and_then(TomlValue::as_str),
        Some("gitlab_acl")
    );

    let host_patterns: BTreeSet<_> = rules(&host)
        .iter()
        .flat_map(|rule| strings(rule, "urls"))
        .collect();
    for required in [
        "https://**.chatgpt.com/**",
        "https://**.sentry.io/**",
        "https://**.datadoghq.com/**",
        "https://rocky-linux-*.production.gcp.mirrors.ctrliq.cloud/pub/rocky/**",
        "https://*.cursor.sh/**",
        "https://*.private-a.example.test/**",
        "https://*.source.private-e.example.test/**",
    ] {
        assert!(
            host_patterns.contains(required),
            "missing reviewed wildcard {required}"
        );
    }

    let providers = table(
        table(&host, "authorization").get("providers").unwrap(),
        "gitlab_acl",
    );
    assert_eq!(
        providers.get("kind").and_then(TomlValue::as_str),
        Some("process")
    );
    let all_provider_names: BTreeSet<_> = table(&host, "authorization")
        .get("providers")
        .and_then(TomlValue::as_table)
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        all_provider_names,
        BTreeSet::from(["agent_runner_acl", "gitlab_acl"])
    );
}

#[test]
fn sanitized_v1_fixtures_are_structurally_incompatible_with_v3() {
    for name in [
        "v1-host-shape.toml",
        "v1-common-container-shape.toml",
        "v1-internal-container-shape.toml",
    ] {
        let config = parse_fixture(name);
        assert_eq!(
            config.get("schema_version").and_then(TomlValue::as_str),
            Some("1")
        );
        assert!(
            config.get("proxy").is_some(),
            "{name} must retain a rejected v1 table"
        );
        assert!(config.get("listeners").is_none());

        for rule in rules(&config) {
            assert!(rule.get("action").is_some());
            assert!(rule.get("pattern").is_some());
            assert!(rule.get("id").is_none());
            assert!(rule.get("decision").is_none());
            assert!(rule.get("urls").is_none());
        }
    }
}

#[test]
fn legacy_single_star_host_rules_receive_explicit_v3_intent() {
    let host = parse_fixture("host-proxy.toml");
    let internal = parse_fixture("internal-container-proxy.toml");
    let patterns: BTreeSet<_> = rules(&host)
        .iter()
        .chain(rules(&internal))
        .flat_map(|rule| strings(rule, "urls"))
        .collect();

    for recursive in [
        "https://**.chatgpt.com/**",
        "https://**.sentry.io/**",
        "https://**.datadoghq.com/**",
    ] {
        assert!(patterns.contains(recursive));
    }
    for one_label in [
        "https://*.cursor.sh/**",
        "https://*.private-a.example.test/**",
        "https://*.source.private-e.example.test/**",
        "https://*.corp.example.test/**",
        "http://*.corp.example.test/**",
    ] {
        assert!(patterns.contains(one_label));
        assert!(
            !patterns.contains(&one_label.replacen("*.", "**.", 1).as_str()),
            "legacy one-label intent must not be silently widened: {one_label}"
        );
    }
    assert!(
        patterns.contains("https://rocky-linux-*.production.gcp.mirrors.ctrliq.cloud/pub/rocky/**")
    );
}

struct ProviderFixture {
    script: &'static str,
    config: &'static str,
    allowed: JsonValue,
    denied: JsonValue,
    missing_identity: JsonValue,
    unknown_identity: JsonValue,
}

fn invoke_provider(fixture: &ProviderFixture, lines: &[String]) -> Vec<JsonValue> {
    let root = production_fixture("providers");
    let mut child = Command::new("python3")
        .arg(root.join(fixture.script))
        .arg("--config")
        .arg(root.join(fixture.config))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn {}: {error}", fixture.script));

    {
        let stdin = child.stdin.as_mut().expect("provider stdin");
        for line in lines {
            writeln!(stdin, "{line}").expect("write provider request");
        }
    }

    let output = child.wait_with_output().expect("wait for provider");
    assert!(
        output.status.success(),
        "{} failed: {}",
        fixture.script,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("provider stdout must be UTF-8")
        .lines()
        .map(|line| {
            serde_json::from_str(line).expect("provider must emit one JSON object per line")
        })
        .collect()
}

fn assert_provider_parity(fixture: ProviderFixture) {
    let cases = [
        (fixture.allowed.clone(), "allow"),
        (fixture.denied.clone(), "deny"),
        (fixture.missing_identity.clone(), "deny"),
        (fixture.unknown_identity.clone(), "deny"),
    ];
    let mut lines: Vec<_> = cases
        .iter()
        .map(|(request, _)| serde_json::to_string(request).unwrap())
        .collect();
    lines.push("{".to_string());

    let responses = invoke_provider(&fixture, &lines);
    assert_eq!(responses.len(), lines.len());
    for ((request, decision), response) in cases.iter().zip(&responses) {
        assert_eq!(response.get("id"), request.get("id"));
        assert_eq!(response.get("type"), Some(&json!("response")));
        assert_eq!(response.get("decision"), Some(&json!(decision)));
    }
    assert_eq!(responses.last().unwrap().get("id"), Some(&JsonValue::Null));
    assert_eq!(
        responses.last().unwrap().get("decision"),
        Some(&json!("deny"))
    );

    let restart_line = serde_json::to_string(&fixture.allowed).unwrap();
    let first = invoke_provider(&fixture, std::slice::from_ref(&restart_line));
    let second = invoke_provider(&fixture, std::slice::from_ref(&restart_line));
    assert_eq!(
        first, second,
        "independent provider restart changed its decision"
    );
    assert_eq!(first[0].get("decision"), Some(&json!("allow")));
}

#[test]
fn production_gitlab_process_provider_parity() {
    assert_provider_parity(ProviderFixture {
        script: "gitlab_acl.py",
        config: "gitlab_acl.json",
        allowed: json!({
            "id": "git-allow",
            "type": "request",
            "url": "https://gitlab.example.test/group/internal.git",
            "headers": {
                "x-aw-identity-token": ["fixture-internal-identity"],
                "x-aw-policy-context": ["fixture-internal"]
            }
        }),
        denied: json!({
            "id": "git-deny",
            "type": "request",
            "url": "https://gitlab.example.test/group/private.git",
            "headers": {"x-aw-identity-token": ["fixture-internal-identity"]}
        }),
        missing_identity: json!({
            "id": "git-missing",
            "type": "request",
            "url": "https://gitlab.example.test/group/internal.git",
            "headers": {"x-aw-policy-context": ["fixture-internal"]}
        }),
        unknown_identity: json!({
            "id": "git-unknown",
            "type": "request",
            "url": "https://gitlab.example.test/group/internal.git",
            "headers": {
                "x-aw-identity-token": ["fixture-unknown"],
                "x-aw-policy-context": ["fixture-internal"]
            }
        }),
    });
}

#[test]
fn production_agent_runner_process_provider_parity() {
    assert_provider_parity(ProviderFixture {
        script: "agent_runner_acl.py",
        config: "agent_runner_acl.json",
        allowed: json!({
            "id": "runner-allow",
            "type": "request",
            "url": "https://runner.example.test/jobs/42",
            "headers": {"x-aw-identity-token": ["fixture-runner-identity"]}
        }),
        denied: json!({
            "id": "runner-deny",
            "type": "request",
            "url": "https://runner.example.test/admin",
            "headers": {"x-aw-identity-token": ["fixture-runner-identity"]}
        }),
        missing_identity: json!({
            "id": "runner-missing",
            "type": "request",
            "url": "https://runner.example.test/jobs/42",
            "headers": {}
        }),
        unknown_identity: json!({
            "id": "runner-unknown",
            "type": "request",
            "url": "https://runner.example.test/jobs/42",
            "headers": {"x-aw-identity-token": ["fixture-unknown"]}
        }),
    });
}
