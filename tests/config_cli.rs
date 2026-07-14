use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, TcpListener};
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::str::contains;
use tempfile::{NamedTempFile, TempDir};

const MINIMAL: &str = r#"schema_version = 3

[listeners.explicit_http]
bind = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[policy]
default = "deny"
"#;

fn config_file(contents: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("create temporary config");
    file.write_all(contents.as_bytes()).expect("write config");
    file
}

fn command() -> Command {
    Command::new(assert_cmd::cargo_bin!("acl-proxy"))
}

#[test]
fn config_validate_accepts_strict_schema_three() {
    let file = config_file(MINIMAL);
    command()
        .args(["config", "validate", "--config"])
        .arg(file.path())
        .assert()
        .success()
        .stdout(contains("Configuration is valid"));
}

#[test]
fn config_validate_rejects_old_missing_and_future_schema_versions() {
    for (name, contents) in [
        (
            "old",
            MINIMAL.replace("schema_version = 3", "schema_version = 2"),
        ),
        ("missing", MINIMAL.replace("schema_version = 3\n\n", "")),
        (
            "future",
            MINIMAL.replace("schema_version = 3", "schema_version = 4"),
        ),
    ] {
        let file = config_file(&contents);
        command()
            .args(["config", "validate", "--config"])
            .arg(file.path())
            .assert()
            .failure()
            .stderr(contains("strict schema v3 TOML"))
            .stderr(contains(if name == "missing" {
                "missing required field"
            } else {
                "invalid value"
            }));
    }
}

#[test]
fn config_validate_reports_sanitized_syntax_errors() {
    let file = config_file("schema_version =\nsecret-value-that-must-not-leak");
    let output = command()
        .args(["config", "validate", "--config"])
        .arg(file.path())
        .output()
        .expect("run config validate");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("syntax error"), "{stderr}");
    assert!(!stderr.contains("secret-value-that-must-not-leak"));
}

#[test]
fn static_cli_commands_never_execute_provider_or_resolve_secrets() {
    let directory = TempDir::new().expect("create temporary directory");
    let marker = directory.path().join("provider-ran");
    let logging_target = directory.path().join("logging-target-is-a-file");
    fs::write(&logging_target, "keep").unwrap();
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let bind = occupied.local_addr().unwrap();
    let path = directory.path().join("acl-proxy.toml");
    fs::write(
        &path,
        format!(
            r#"schema_version = 3

[control]
bind = "127.0.0.1:8898"

[control.tls]
certificate_chain = "missing-control-cert.pem"
private_key = "missing-control-key.pem"

[listeners.explicit_http]
bind = "{bind}"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "deny"

[authorization.providers.marker]
kind = "process"
command = "/bin/sh"
args = ["-c", "printf ran > {marker}"]

[credentials.sources.missing_file]
source = "file"
path = "missing-credential"

[redaction.profiles.missing_environment]
rules = [{{ literal_environment_variables = ["ACL_PROXY_STATIC_CLI_MISSING"] }}]

[observation.logging]
directory = "{logging_target}"

[policy]
default = "deny"
"#,
            marker = marker.display(),
            logging_target = logging_target.display(),
        ),
    )
    .unwrap();

    for arguments in [
        ["config", "validate", "--config"],
        ["policy", "dump", "--config"],
    ] {
        command()
            .args(arguments)
            .arg(&path)
            .env_remove("ACL_PROXY_STATIC_CLI_MISSING")
            .assert()
            .success();
        assert!(!marker.exists(), "static command spawned the provider");
        assert_eq!(fs::read_to_string(&logging_target).unwrap(), "keep");
        assert!(
            TcpListener::bind(bind).is_err(),
            "static command disturbed the occupied listener"
        );
    }
}

#[test]
fn config_init_writes_a_strict_loopback_template_that_validates() {
    let directory = TempDir::new().expect("create temporary directory");
    let target = directory.path().join("nested/acl-proxy.toml");

    command()
        .args(["config", "init"])
        .arg(&target)
        .assert()
        .success()
        .stdout(contains("Wrote default config"));

    let contents = fs::read_to_string(&target).unwrap();
    assert!(contents.starts_with("schema_version = 3\n"));
    assert!(contents.contains("[listeners.explicit_http]"));
    assert!(contents.contains("127.0.0.1:8881"));
    assert!(!contents.contains("[proxy]"));
    assert!(!contents.contains("0.0.0.0"));

    command()
        .args(["config", "validate", "--config"])
        .arg(&target)
        .assert()
        .success();
}

#[test]
fn config_init_never_overwrites_an_existing_file() {
    let directory = TempDir::new().expect("create temporary directory");
    let target = directory.path().join("acl-proxy.toml");
    fs::write(&target, "existing = true\n").unwrap();

    command()
        .args(["config", "init"])
        .arg(&target)
        .assert()
        .failure()
        .stderr(contains("already exists"));
    assert_eq!(fs::read_to_string(target).unwrap(), "existing = true\n");
}

#[test]
fn config_path_environment_is_the_only_static_command_override() {
    let file = config_file(MINIMAL);
    command()
        .args(["config", "validate"])
        .env("ACL_PROXY_CONFIG", file.path())
        .env("PROXY_EXPLICIT_HTTP_BIND", "not-an-address")
        .env("LOG_LEVEL", "not-a-level")
        .assert()
        .success()
        .stdout(contains("Configuration is valid"));
}
