use std::io::Write;

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

    let mut cmd = assert_cmd::Command::cargo_bin("acl-proxy").expect("binary built");
    cmd.arg("config")
        .arg("validate")
        .arg("--config")
        .arg(file.path());

    cmd.assert()
        .failure()
        .stderr(contains("invalid log level for logging.level"));
}
