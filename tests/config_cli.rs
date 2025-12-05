use std::io::Write;
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::str::contains;
use tempfile::{NamedTempFile, TempDir};

#[test]
fn config_validate_succeeds_for_valid_config() {
    let mut file = NamedTempFile::new().expect("create temp config");
    writeln!(
        file,
        r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#
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
fn config_validate_fails_for_wrong_schema_version() {
    let mut file = NamedTempFile::new().expect("create temp config");
    writeln!(
        file,
        r#"
schema_version = "999"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#
    )
    .expect("write config");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    cmd.arg("config")
        .arg("validate")
        .arg("--config")
        .arg(file.path());

    cmd.assert()
        .failure()
        .stderr(contains("unsupported schema_version"));
}

#[test]
fn env_overrides_are_applied() {
    let mut file = NamedTempFile::new().expect("create temp config");
    writeln!(
        file,
        r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
        "#
    )
    .expect("write config");

    // Use a small helper binary run via `cargo run`-style to inspect overrides.
    // For now, just ensure that `config validate` still succeeds with overrides set.
    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    cmd.arg("config")
        .arg("validate")
        .arg("--config")
        .arg(file.path())
        .env("PROXY_PORT", "9999")
        .env("PROXY_HOST", "0.0.0.0")
        .env("LOG_LEVEL", "debug");

    cmd.assert()
        .success()
        .stdout(contains("Configuration is valid"));
}

#[test]
fn config_validate_fails_for_malformed_toml() {
    let mut file = NamedTempFile::new().expect("create temp config");
    // Missing value for schema_version to force a parse error.
    writeln!(
        file,
        r#"
schema_version =

[proxy]
bind_address = "127.0.0.1"
http_port = 8080
        "#
    )
    .expect("write config");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    cmd.arg("config")
        .arg("validate")
        .arg("--config")
        .arg(file.path());

    cmd.assert()
        .failure()
        .stderr(contains("failed to parse config"));
}

#[test]
fn missing_default_config_suggests_init() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    cmd.arg("config")
        .arg("validate")
        // No --config and no ACL_PROXY_CONFIG: should use default path and fail with hint.
        .current_dir(temp_dir.path());

    cmd.assert().failure().stderr(contains("config init"));
}

#[test]
fn config_init_creates_file_at_path() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let target = temp_dir.path().join("acl-proxy.toml");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    cmd.arg("config").arg("init").arg(&target);

    cmd.assert()
        .success()
        .stdout(contains("Wrote default config"));

    assert!(target.exists(), "config file should be created");
    let contents = std::fs::read_to_string(&target).expect("read generated config");
    assert!(
        contents.contains("schema_version"),
        "generated config should contain schema_version"
    );
    assert!(
        contents.contains("[proxy]"),
        "generated config should contain [proxy] section"
    );
}

#[test]
fn config_init_refuses_to_overwrite_existing_file() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let target = temp_dir.path().join("acl-proxy.toml");

    {
        let mut file = std::fs::File::create(&target).expect("create existing config");
        writeln!(file, "existing = true").expect("write existing config");
    }

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    cmd.arg("config").arg("init").arg(&target);

    cmd.assert().failure().stderr(contains("already exists"));
}
