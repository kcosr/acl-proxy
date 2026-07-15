use assert_cmd::Command;

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
