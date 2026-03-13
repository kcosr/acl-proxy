use std::io::Write;
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::str::contains;
use serde_json::Value;
use tempfile::NamedTempFile;

#[test]
fn config_validate_succeeds_for_policy_with_macros_and_rulesets() {
    let mut file = NamedTempFile::new().expect("create temp config");
    file.write_all(
        br#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"

[policy.macros]
repo = ["user/ts-test-1", "user/ts-test-2"]

[[policy.rulesets.gitlab_repo]]
action = "allow"
pattern = "https://gitlab.internal/api/v4/projects/{repo}?**"

[[policy.rules]]
include = "gitlab_repo"
add_url_enc_variants = true
        "#,
    )
    .expect("write config");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    cmd.arg("config")
        .arg("validate")
        .arg("--config")
        .arg(file.path());

    cmd.assert()
        .success()
        .stdout(contains("Configuration is valid"));
}

#[test]
fn config_validate_fails_for_missing_macro_in_ruleset() {
    let mut file = NamedTempFile::new().expect("create temp config");
    file.write_all(
        br#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"

[[policy.rulesets.gitlab_repo]]
action = "allow"
pattern = "https://gitlab.internal/api/v4/projects/{repo}?**"

[[policy.rules]]
include = "gitlab_repo"
add_url_enc_variants = true
        "#,
    )
    .expect("write config");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    cmd.arg("config")
        .arg("validate")
        .arg("--config")
        .arg(file.path());

    cmd.assert()
        .failure()
        .stderr(contains("Policy macro not found: repo"));
}

#[test]
fn config_validate_fails_for_missing_macro_in_direct_rule() {
    let mut file = NamedTempFile::new().expect("create temp config");
    file.write_all(
        br#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "https://gitlab.internal/api/v4/projects/{repo}?**"
add_url_enc_variants = true
        "#,
    )
    .expect("write config");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    cmd.arg("config")
        .arg("validate")
        .arg("--config")
        .arg(file.path());

    cmd.assert()
        .failure()
        .stderr(contains("Policy macro not found: repo"));
}

#[test]
fn policy_dump_defaults_to_json_on_non_tty() {
    let mut file = NamedTempFile::new().expect("create temp config");
    file.write_all(
        br#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "https://example.com/api/**"
methods = ["GET"]
description = "Allow API"
subnets = ["10.0.0.0/8"]
        "#,
    )
    .expect("write config");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    cmd.arg("policy")
        .arg("dump")
        .arg("--config")
        .arg(file.path());

    let assert = cmd.assert().success();
    let stdout =
        String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is valid UTF-8");

    let value: Value = serde_json::from_str(&stdout).expect("output is valid JSON");
    assert_eq!(value["default"], "deny");

    let rules = value["rules"].as_array().expect("rules is an array");
    assert_eq!(rules.len(), 1);

    let rule = &rules[0];
    assert_eq!(rule["index"], 0);
    assert_eq!(rule["action"], "allow");
    assert_eq!(rule["pattern"], "https://example.com/api/**");
    assert_eq!(rule["description"], "Allow API");

    let methods = rule["methods"].as_array().expect("methods is an array");
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0], "GET");

    let subnets = rule["subnets"].as_array().expect("subnets is an array");
    assert_eq!(subnets.len(), 1);
    assert_eq!(subnets[0], "10.0.0.0/8");
}

#[test]
fn policy_dump_table_format_contains_expected_fields() {
    let mut file = NamedTempFile::new().expect("create temp config");
    file.write_all(
        br#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "https://example.com/api/**"
methods = ["GET"]
description = "Allow API"
subnets = ["10.0.0.0/8"]
        "#,
    )
    .expect("write config");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    cmd.arg("policy")
        .arg("dump")
        .arg("--format")
        .arg("table")
        .arg("--config")
        .arg(file.path());

    cmd.assert()
        .success()
        .stdout(contains("Default action: deny"))
        .stdout(contains("INDEX"))
        .stdout(contains("https://example.com/api/**"))
        .stdout(contains("Allow API"));
}

#[test]
fn policy_dump_json_includes_headers_absent() {
    let mut file = NamedTempFile::new().expect("create temp config");
    file.write_all(
        br#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"

[[policy.rules]]
action = "deny"
pattern = "**"
headers_absent = ["x-workload-id"]
        "#,
    )
    .expect("write config");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    cmd.arg("policy")
        .arg("dump")
        .arg("--config")
        .arg(file.path());

    let assert = cmd.assert().success();
    let stdout =
        String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is valid UTF-8");

    let value: Value = serde_json::from_str(&stdout).expect("output is valid JSON");
    let rules = value["rules"].as_array().expect("rules is an array");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["headers_absent"][0], "x-workload-id");
    assert_eq!(
        rules[0]["headers_match"]
            .as_object()
            .expect("headers_match is object")
            .len(),
        0
    );
}

#[test]
fn policy_dump_table_includes_headers_absent_column() {
    let mut file = NamedTempFile::new().expect("create temp config");
    file.write_all(
        br#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"

[[policy.rules]]
action = "deny"
pattern = "**"
headers_absent = ["x-workload-id"]
description = "Deny missing identity"
        "#,
    )
    .expect("write config");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    cmd.arg("policy")
        .arg("dump")
        .arg("--format")
        .arg("table")
        .arg("--config")
        .arg(file.path());

    cmd.assert()
        .success()
        .stdout(contains("HEADERS_ABSENT"))
        .stdout(contains("HEADERS_MATCH"))
        .stdout(contains("x-workload-id"))
        .stdout(contains("Deny missing identity"));
}

#[test]
fn policy_dump_json_includes_headers_match_values() {
    let mut file = NamedTempFile::new().expect("create temp config");
    file.write_all(
        br#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "https://example.com/**"
headers_match = { "x-workload-id" = ["worker-123", "worker-456"], "x-tenant-id" = "tenant-a" }
        "#,
    )
    .expect("write config");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    cmd.arg("policy")
        .arg("dump")
        .arg("--config")
        .arg(file.path());

    let assert = cmd.assert().success();
    let stdout =
        String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is valid UTF-8");

    let value: Value = serde_json::from_str(&stdout).expect("output is valid JSON");
    let rules = value["rules"].as_array().expect("rules is an array");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["headers_match"]["x-tenant-id"][0], "tenant-a");
    assert_eq!(rules[0]["headers_match"]["x-workload-id"][0], "worker-123");
    assert_eq!(rules[0]["headers_match"]["x-workload-id"][1], "worker-456");
}

#[test]
fn policy_dump_table_includes_headers_match_column_values() {
    let mut file = NamedTempFile::new().expect("create temp config");
    file.write_all(
        br#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "https://example.com/**"
headers_match = { "x-workload-id" = ["worker-123", "worker-456"], "x-tenant-id" = "tenant-a" }
description = "Allow trusted identity values"
        "#,
    )
    .expect("write config");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    cmd.arg("policy")
        .arg("dump")
        .arg("--format")
        .arg("table")
        .arg("--config")
        .arg(file.path());

    cmd.assert()
        .success()
        .stdout(contains("HEADERS_MATCH"))
        .stdout(contains("x-tenant-id=tenant-a"))
        .stdout(contains("x-workload-id=worker-123|worker-456"))
        .stdout(contains("Allow trusted identity values"));
}
