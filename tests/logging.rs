use std::io::Write;
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::str::contains;
use tempfile::NamedTempFile;

#[test]
fn config_validate_fails_for_invalid_logging_level() {
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
level = "notalevel"

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
        .stderr(contains("invalid log level for logging.level"));
}
