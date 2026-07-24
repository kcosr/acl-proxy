use std::fs;
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::str::contains;
use serde_json::Value;
use tempfile::TempDir;

fn policy_config(schema_version: u32) -> String {
    format!(
        r#"schema_version = {schema_version}

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[authorization.providers.approval]
kind = "process"
command = "missing-provider"

[credentials.sources.api_token]
source = "environment"
variable = "POLICY_DUMP_SECRET_VARIABLE"

[redaction.profiles.secrets]
rules = [{{ literals = ["literal-secret-value"] }}]

[policy]
default = "deny"

[[policy.rules]]
id = "delegated-api"
description = "Delegate API"
decision = "delegate"
urls = ["https://example.test/api/**", "https://example.test/status"]
methods = ["get"]
client_cidrs = ["10.0.0.0/8"]
identity_states = ["disabled"]
request_timeout = "5s"
allow_upgrades = true
authorization_provider = "approval"
redaction_profile = "secrets"

[policy.rules.headers]
absent_any = ["x-blocked"]
present_all = ["x-identity"]
all = {{ x-tenant = ["engineering"] }}
none = {{ x-channel = ["untrusted"] }}

[[policy.rules.request_headers]]
operation = "set"
when = "always"
name = "x-route"
value = "literal-secret-value"

[[policy.rules.response_headers]]
operation = "remove"
when = "always"
name = "x-remove-me"

[[policy.rules.credential_actions]]
kind = "bearer"
transport_security = "tls_required"
credential = "api_token"
"#
    )
}

fn fixture(schema_version: u32) -> (TempDir, std::path::PathBuf) {
    let directory = TempDir::new().expect("create temporary directory");
    let path = directory.path().join("acl-proxy.toml");
    fs::write(&path, policy_config(schema_version)).unwrap();
    (directory, path)
}

fn command() -> Command {
    Command::new(assert_cmd::cargo_bin!("acl-proxy"))
}

#[test]
fn policy_dump_defaults_to_stable_secret_free_json_off_tty() {
    let (_directory, path) = fixture(3);
    let output = command()
        .args(["policy", "dump", "--config"])
        .arg(path)
        .output()
        .expect("run policy dump");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    for excluded in [
        "POLICY_DUMP_SECRET_VARIABLE",
        "literal-secret-value",
        "missing-provider",
    ] {
        assert!(!stdout.contains(excluded), "dump disclosed {excluded}");
    }
    let value: Value = serde_json::from_str(&stdout).expect("policy dump JSON");
    assert_eq!(value["default"], "deny");
    let rule = &value["rules"][0];
    assert_eq!(rule["index"], 0);
    assert_eq!(rule["id"], "delegated-api");
    assert_eq!(rule["decision"], "delegate");
    assert_eq!(rule["urls"][0], "https://example.test/api/**");
    assert_eq!(rule["urls"][1], "https://example.test/status");
    assert_eq!(rule["methods"][0], "GET");
    assert_eq!(rule["client_cidrs"][0], "10.0.0.0/8");
    assert_eq!(rule["identity_states"][0], "disabled");
    assert_eq!(rule["identity_subjects"], serde_json::json!([]));
    assert_eq!(rule["headers"]["absent_any"][0], "x-blocked");
    assert_eq!(rule["headers"]["present_all"][0], "x-identity");
    assert_eq!(rule["headers"]["all"][0]["name"], "x-tenant");
    assert_eq!(rule["headers"]["none"][0]["name"], "x-channel");
    assert_eq!(rule["request_timeout_ms"], 5000);
    assert_eq!(rule["allow_upgrades"], true);
    assert_eq!(rule["authorization_provider"], "approval");
    assert_eq!(rule["redaction_profile"], "secrets");
    assert_eq!(rule["request_header_mutations"][0]["operation"], "set");
    assert_eq!(rule["response_header_mutations"][0]["operation"], "remove");
    assert_eq!(rule["credential_mutations"][0]["kind"], "bearer");
    assert_eq!(rule["credential_mutations"][0]["credential"], "api_token");
}

#[test]
fn policy_dump_table_uses_the_same_compiled_projection() {
    let (_directory, path) = fixture(3);
    command()
        .args(["policy", "dump", "--format", "table", "--config"])
        .arg(path)
        .assert()
        .success()
        .stdout(contains("Default action: deny"))
        .stdout(contains("INDEX\tDECISION\tURLS"))
        .stdout(contains(
            "https://example.test/api/**,https://example.test/status",
        ))
        .stdout(contains("absent:x-blocked"))
        .stdout(contains("present:x-identity"))
        .stdout(contains("x-tenant=engineering"))
        .stdout(contains("x-channel!=untrusted"))
        .stdout(contains("state=disabled"))
        .stdout(contains("approval"))
        .stdout(contains("request:set:x-route"))
        .stdout(contains("response:remove:x-remove-me"))
        .stdout(contains("credential:bearer:api_token"));
}

#[test]
fn explicit_json_format_is_machine_readable() {
    let (_directory, path) = fixture(3);
    let output = command()
        .args(["policy", "dump", "--format", "json", "--config"])
        .arg(path)
        .output()
        .unwrap();

    assert!(output.status.success());
    serde_json::from_slice::<Value>(&output.stdout).expect("explicit JSON output");
}

#[test]
fn policy_dump_rejects_non_schema_three_without_fallback() {
    let (_directory, path) = fixture(2);
    command()
        .args(["policy", "dump", "--config"])
        .arg(path)
        .assert()
        .failure()
        .stderr(contains("strict schema v3 TOML"))
        .stderr(contains("invalid value"));
}
