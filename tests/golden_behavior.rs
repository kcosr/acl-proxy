use std::collections::BTreeMap;

use acl_proxy::capture::{
    build_capture_record, BodyCaptureResult, CaptureDecision, CaptureEndpoint, CaptureKind,
    CaptureMode, CaptureRecordOptions,
};
use acl_proxy::config::{Config, PolicyRuleAction};
use acl_proxy::policy::PolicyEngine;
use assert_cmd::Command;
use http::HeaderMap;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct DecisionCase {
    name: String,
    url: String,
    method: String,
    start_index: usize,
    allowed: bool,
    matched_index: Option<usize>,
    matched_action: Option<String>,
    matched_rule_id: Option<String>,
}

fn action_name(action: PolicyRuleAction) -> &'static str {
    match action {
        PolicyRuleAction::Allow => "allow",
        PolicyRuleAction::Deny => "deny",
        PolicyRuleAction::Delegate => "delegate",
    }
}

#[test]
fn effective_decisions_match_golden_corpus() {
    let config: Config = toml::from_str(include_str!("fixtures/golden/policy-input.toml"))
        .expect("parse golden policy config");
    let engine = PolicyEngine::from_config(&config.policy).expect("compile golden policy");
    let cases: Vec<DecisionCase> =
        serde_json::from_str(include_str!("fixtures/golden/effective-decisions.json"))
            .expect("parse golden decision cases");

    for case in cases {
        let decision = engine.evaluate_from(
            case.start_index,
            &case.url,
            Some("192.0.2.10"),
            Some(&case.method),
            &HeaderMap::new(),
        );
        assert_eq!(decision.allowed, case.allowed, "{}: allowed", case.name);
        assert_eq!(
            decision.matched.as_ref().map(|rule| rule.index),
            case.matched_index,
            "{}: matched index",
            case.name
        );
        assert_eq!(
            decision
                .matched
                .as_ref()
                .map(|rule| action_name(rule.action).to_string()),
            case.matched_action,
            "{}: matched action",
            case.name
        );
        assert_eq!(
            decision.matched.and_then(|rule| rule.rule_id),
            case.matched_rule_id,
            "{}: matched rule ID",
            case.name
        );
    }
}

#[test]
fn capture_json_matches_golden_shape() {
    let mut headers = BTreeMap::new();
    headers.insert(
        "content-type".to_string(),
        serde_json::Value::String("text/plain".to_string()),
    );
    let record = build_capture_record(CaptureRecordOptions {
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        request_id: "golden-request".to_string(),
        kind: CaptureKind::Request,
        decision: CaptureDecision::Allow,
        mode: CaptureMode::HttpsConnect,
        url: "https://example.com/resource".to_string(),
        method: Some("POST".to_string()),
        client: CaptureEndpoint {
            address: Some("127.0.0.1".to_string()),
            port: Some(43210),
        },
        target: Some(CaptureEndpoint {
            address: Some("203.0.113.10".to_string()),
            port: Some(443),
        }),
        http_version: Some("1.1".to_string()),
        headers: Some(headers),
        status_code: Some(200),
        status_message: Some("OK".to_string()),
        body: Some(BodyCaptureResult {
            captured: b"hello".to_vec(),
            total_len: 5,
        }),
    });

    let actual = serde_json::to_value(record).expect("serialize capture record");
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/golden/capture-record.json"))
            .expect("parse golden capture record");
    assert_eq!(actual, expected);
}

#[test]
fn effective_policy_dump_matches_golden_corpus() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("acl-proxy"))
        .args([
            "policy",
            "dump",
            "--format",
            "json",
            "--config",
            "tests/fixtures/golden/compiled-policy-input.toml",
        ])
        .output()
        .expect("run policy dump");
    assert!(
        output.status.success(),
        "policy dump failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let actual: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse policy dump output");
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/golden/compiled-policy-dump.json"))
            .expect("parse golden policy dump");
    assert_eq!(actual, expected);
}
