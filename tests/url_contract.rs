use std::fs;
use std::process::Command;

use http_access_conformance::{load_matching_suite, MatchOutcome, UrlErrorCode};
use serde_json::Value;
use tempfile::TempDir;

fn policy_config(pattern: &str) -> String {
    format!(
        r#"schema_version = 3

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"

[[policy.rules]]
id = "url-contract"
decision = "allow"
urls = [{pattern:?}]
"#
    )
}

fn fixture(pattern: &str) -> (TempDir, std::path::PathBuf) {
    let directory = TempDir::new().expect("create temporary config root");
    let path = directory.path().join("acl-proxy.toml");
    fs::write(&path, policy_config(pattern)).expect("write strict config");
    (directory, path)
}

fn command() -> Command {
    Command::new(assert_cmd::cargo_bin!("acl-proxy"))
}

#[test]
fn shared_patterns_cross_the_strict_config_compiler_boundary() {
    for case in load_matching_suite().unwrap().into_cases() {
        let (_directory, path) = fixture(&case.input.pattern);
        let pattern_must_fail = matches!(
            case.expected,
            MatchOutcome::Rejected {
                error: UrlErrorCode::Pattern
            }
        );

        let validation = command()
            .args(["config", "validate", "--config"])
            .arg(&path)
            .output()
            .expect("run config validation");
        if pattern_must_fail {
            assert!(
                !validation.status.success(),
                "{}: invalid corpus pattern passed strict compilation",
                case.id
            );
            let stderr = String::from_utf8_lossy(&validation.stderr);
            assert!(
                stderr.contains("policy.rules[0].urls[0]"),
                "{}: compiler did not locate the invalid pattern: {stderr}",
                case.id
            );
            continue;
        }

        assert!(
            validation.status.success(),
            "{}: valid corpus pattern failed strict compilation: {}",
            case.id,
            String::from_utf8_lossy(&validation.stderr)
        );
        let dump = command()
            .args(["policy", "dump", "--format", "json", "--config"])
            .arg(&path)
            .output()
            .expect("dump compiled policy");
        assert!(
            dump.status.success(),
            "{}: compiled policy dump failed: {}",
            case.id,
            String::from_utf8_lossy(&dump.stderr)
        );
        let policy: Value = serde_json::from_slice(&dump.stdout).expect("policy dump JSON");
        assert_eq!(
            policy["rules"][0]["urls"][0], case.input.pattern,
            "{}: compiled policy lost its authored URL pattern",
            case.id
        );
    }
}
