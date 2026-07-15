use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::prelude::*;
use predicates::prelude::PredicateBooleanExt;
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

fn ephemeral_addresses() -> (SocketAddr, SocketAddr) {
    let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let second = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    (first.local_addr().unwrap(), second.local_addr().unwrap())
}

fn readiness_status(address: SocketAddr) -> Option<u16> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(100)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .ok()?;
    stream
        .write_all(b"GET /_acl-proxy/ready HTTP/1.1\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    response
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
}

fn wait_for_ready(child: &mut Child, address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "acl-proxy exited before becoming ready"
        );
        if readiness_status(address) == Some(200) {
            return;
        }
        assert!(Instant::now() < deadline, "acl-proxy did not become ready");
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_file_text(path: &std::path::Path, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if fs::read_to_string(path).is_ok_and(|contents| contents.contains(expected)) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{} never contained {expected:?}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
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
fn config_validate_rejects_invalid_observation_logging_level() {
    let file = config_file(&format!(
        "{MINIMAL}\n[observation.logging]\nlevel = \"notalevel\"\n"
    ));

    command()
        .args(["config", "validate", "--config"])
        .arg(file.path())
        .assert()
        .failure()
        .stderr(contains("observation.logging.level"))
        .stderr(contains("must be trace, debug, info, warn, or error"));
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

#[test]
fn cli_help_describes_the_strict_toml_runtime() {
    command()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("Path to the strict TOML configuration file"))
        .stdout(contains("Run the proxy"))
        .stdout(predicates::str::contains("not yet implemented").not())
        .stdout(predicates::str::contains("TOML or JSON").not());
}

#[test]
fn run_rejects_schema_two_without_fallback() {
    let file = config_file(&MINIMAL.replace("schema_version = 3", "schema_version = 2"));
    command()
        .args(["run", "--config"])
        .arg(file.path())
        .assert()
        .failure()
        .stderr(contains("strict schema v3 TOML"));
}

#[cfg(unix)]
#[test]
fn strict_run_owns_reload_shutdown_and_listener_release() {
    let directory = TempDir::new().unwrap();
    let (proxy, control) = ephemeral_addresses();
    let config = directory.path().join("acl-proxy.toml");
    fs::write(
        &config,
        format!(
            r#"schema_version = 3

[service]
shutdown_drain_timeout = "2s"

[control]
bind = "{control}"
request_header_timeout = "1s"
request_body_timeout = "1s"
max_connections = 8
max_request_body_bytes = 65536

[listeners.explicit_http]
bind = "{proxy}"
http_versions = ["http1"]
request_header_timeout = "1s"
max_connections = 8
max_concurrent_streams = 8

[listeners.explicit_http.connect]
http1 = "deny"

[observation.logging]
directory = "logs"
console = false

[policy]
default = "deny"
"#
        ),
    )
    .unwrap();

    let mut child = command()
        .args(["run", "--config"])
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_ready(&mut child, control);

    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGHUP) },
        0
    );
    wait_for_file_text(
        &directory.path().join("logs/acl-proxy.log"),
        "configuration reload completed successfully",
    );
    assert_eq!(readiness_status(control), Some(200));

    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "acl-proxy did not exit after SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "acl-proxy failed: {stderr}");
    TcpListener::bind(proxy).expect("proxy listener was not released");
    TcpListener::bind(control).expect("control listener was not released");
}
