use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::prelude::*;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use tempfile::{NamedTempFile, TempDir};

const MINIMAL: &str = r#"schema_version = 3

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
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

#[cfg(unix)]
struct ChildGuard(Child);

#[cfg(unix)]
impl ChildGuard {
    fn spawn(config: &Path) -> Self {
        Self(
            command()
                .args(["run", "--config"])
                .arg(config)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start acl-proxy"),
        )
    }

    fn signal(&self, signal: libc::c_int) {
        assert_eq!(
            unsafe { libc::kill(self.id() as libc::pid_t, signal) },
            0,
            "send signal {signal} to acl-proxy"
        );
    }

    fn wait_for_exit(&mut self, timeout: Duration, context: &str) -> std::process::ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.try_wait().expect("poll acl-proxy") {
                return status;
            }
            assert!(Instant::now() < deadline, "{context}");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(unix)]
impl Deref for ChildGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(unix)]
impl DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(unix)]
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.try_wait().ok().flatten().is_none() {
            let _ = self.kill();
            let _ = self.wait();
        }
    }
}

#[cfg(unix)]
fn wait_for_file_text_count(path: &Path, expected: &str, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let actual = fs::read_to_string(path)
            .map(|contents| contents.matches(expected).count())
            .unwrap_or(0);
        if actual >= count {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{} never contained {count} occurrences of {expected:?}; found {actual}",
            path.display()
        );
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(unix)]
fn runtime_config(
    proxy: SocketAddr,
    control: SocketAddr,
    drain_timeout: &str,
    extra: &str,
) -> String {
    format!(
        r#"schema_version = 3

[service]
shutdown_drain_timeout = "{drain_timeout}"

[control]
bind = "{control}"
request_header_timeout = "1s"
request_body_timeout = "1s"
max_connections = 8
max_request_body_bytes = 65536

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "{proxy}"
http_versions = ["http1"]
request_header_timeout = "1s"
max_connections = 8
max_concurrent_streams = 8

[listeners.explicit_http.connect]
http1 = "deny"

[observation.logging]
directory = "logs"
console = false

{extra}
"#
    )
}

#[cfg(unix)]
fn proxy_get(proxy: SocketAddr, url: &str, timeout: Duration) -> std::io::Result<Vec<u8>> {
    let authority = url
        .strip_prefix("http://")
        .expect("HTTP fixture URL")
        .split('/')
        .next()
        .unwrap();
    let mut stream = TcpStream::connect_timeout(&proxy, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "GET {url} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}

#[cfg(unix)]
fn blocking_provider_config(python: &Path, script: &Path, marker: &Path, release: &Path) -> String {
    format!(
        r#"[authorization.providers.blocking]
kind = "process"
command = {python:?}
args = ["-u", {script:?}, {marker:?}, {release:?}]
timeout = "60s"
retire_timeout = "60s"
on_failure = "deny"
inherit_environment = false
environment = {{ PATH = "/usr/bin:/bin" }}
include_request_body = false
max_request_body_bytes = 1024
max_decoded_request_body_bytes = 1024
max_stdout_line_bytes = 4096

[policy]
default = "deny"

[[policy.rules]]
id = "blocking-provider"
decision = "delegate"
urls = [
  "http://192.0.2.1/drain",
  "http://192.0.2.1/stuck",
  "http://192.0.2.1/forced",
]
methods = ["GET"]
authorization_provider = "blocking"
"#,
    )
}

#[cfg(unix)]
fn python3_path() -> std::path::PathBuf {
    let output = Command::new("python3")
        .args(["-c", "import sys; print(sys.executable)"])
        .output()
        .expect("locate python3");
    assert!(output.status.success(), "python3 is required for this test");
    std::path::PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
}

#[cfg(unix)]
fn write_blocking_provider_script(path: &Path) {
    fs::write(
        path,
        r#"import json, os, sys, time
marker, release = sys.argv[1:]
for line in sys.stdin:
    request = json.loads(line)
    with open(marker, "w", encoding="utf-8") as output:
        output.write(request["id"])
    while not os.path.exists(release):
        time.sleep(0.01)
    print(json.dumps({"id": request["id"], "type": "response", "decision": "deny"}, separators=(",", ":")), flush=True)
"#,
    )
    .unwrap();
}

#[cfg(unix)]
fn wait_for_file(path: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "acl-proxy exited before {} appeared",
            path.display()
        );
        if path.is_file() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{} did not appear",
            path.display()
        );
        thread::sleep(Duration::from_millis(20));
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
fn config_validate_rejects_missing_policy_and_default() {
    for contents in [
        MINIMAL.replace("[policy]\ndefault = \"deny\"\n", ""),
        MINIMAL.replace("default = \"deny\"\n", ""),
    ] {
        let file = config_file(&contents);
        command()
            .args(["config", "validate", "--config"])
            .arg(file.path())
            .assert()
            .failure()
            .stdout(contains("Configuration is valid").not())
            .stderr(contains("strict schema v3 TOML"))
            .stderr(contains("missing required field"));
    }
}

#[test]
fn config_validate_explains_the_removed_data_listener_bind_shape() {
    let file = config_file(&MINIMAL.replace(
        "endpoint.kind = \"tcp\"\nendpoint.address = \"127.0.0.1:8881\"",
        "bind = \"127.0.0.1:8881\"",
    ));
    command()
        .args(["config", "validate", "--config"])
        .arg(file.path())
        .assert()
        .failure()
        .stderr(contains("removed data-listener field `bind`"))
        .stderr(contains(
            "endpoint = { kind = \"tcp\", address = \"127.0.0.1:8881\" }",
        ));
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
endpoint.kind = "tcp"
endpoint.address = "{bind}"
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

#[cfg(unix)]
#[test]
fn config_path_environment_preserves_non_unicode_paths() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let directory = TempDir::new().expect("create temporary directory");
    let path = directory
        .path()
        .join(OsString::from_vec(b"acl-proxy-\xff.toml".to_vec()));
    fs::write(&path, MINIMAL).expect("write non-Unicode config path");

    command()
        .args(["config", "validate"])
        .current_dir(directory.path())
        .env("ACL_PROXY_CONFIG", path.as_os_str())
        .assert()
        .success()
        .stdout(contains("Configuration is valid"));
}

#[cfg(unix)]
#[test]
fn explicit_config_path_overrides_a_non_unicode_environment_path() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let directory = TempDir::new().expect("create temporary directory");
    let explicit = directory.path().join("explicit.toml");
    fs::write(&explicit, MINIMAL).expect("write explicit config");
    let environment = directory
        .path()
        .join(OsString::from_vec(b"rejected-\xff.toml".to_vec()));
    fs::write(
        &environment,
        MINIMAL.replace("schema_version = 3", "schema_version = 2"),
    )
    .expect("write environment config");

    command()
        .args(["config", "validate", "--config"])
        .arg(&explicit)
        .env("ACL_PROXY_CONFIG", environment.as_os_str())
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
endpoint.kind = "tcp"
endpoint.address = "{proxy}"
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

#[cfg(unix)]
#[test]
fn invalid_reload_candidates_preserve_live_generation_until_corrected_reload() {
    let directory = TempDir::new().unwrap();
    let (proxy, control) = ephemeral_addresses();
    let config = directory.path().join("acl-proxy.toml");
    let valid = runtime_config(proxy, control, "2s", "[policy]\ndefault = \"deny\"\n");
    fs::write(&config, &valid).unwrap();

    let mut child = ChildGuard::spawn(&config);
    wait_for_ready(&mut child, control);
    let log = directory.path().join("logs/acl-proxy.log");

    fs::write(
        &config,
        "schema_version =\nreload-secret-that-must-not-leak",
    )
    .unwrap();
    child.signal(libc::SIGHUP);
    wait_for_file_text_count(&log, "configuration reload failed", 1);
    assert_eq!(readiness_status(control), Some(200));

    fs::write(
        &config,
        valid.replace("schema_version = 3", "schema_version = 2"),
    )
    .unwrap();
    child.signal(libc::SIGHUP);
    wait_for_file_text_count(&log, "configuration reload failed", 2);
    assert_eq!(readiness_status(control), Some(200));

    fs::write(&config, &valid).unwrap();
    child.signal(libc::SIGHUP);
    wait_for_file_text_count(&log, "configuration reload completed successfully", 1);
    assert_eq!(readiness_status(control), Some(200));
    let logs = fs::read_to_string(&log).unwrap();
    assert!(
        logs.contains("generation=2"),
        "corrected reload skipped generation 2: {logs}"
    );
    assert!(!logs.contains("reload-secret-that-must-not-leak"));

    child.signal(libc::SIGTERM);
    let status = child.wait_for_exit(
        Duration::from_secs(5),
        "acl-proxy did not exit after corrected reload",
    );
    assert!(status.success());
}

#[cfg(unix)]
#[test]
fn first_termination_signal_drains_an_inflight_request_to_completion() {
    let directory = TempDir::new().unwrap();
    let (proxy, control) = ephemeral_addresses();
    let python = python3_path();
    let script = directory.path().join("provider.py");
    let marker = directory.path().join("provider-admitted");
    let release = directory.path().join("provider-release");
    write_blocking_provider_script(&script);
    let config = directory.path().join("acl-proxy.toml");
    fs::write(
        &config,
        runtime_config(
            proxy,
            control,
            "3s",
            &blocking_provider_config(&python, &script, &marker, &release),
        ),
    )
    .unwrap();
    let mut child = ChildGuard::spawn(&config);
    wait_for_ready(&mut child, control);

    let client = thread::spawn(move || {
        proxy_get(proxy, "http://192.0.2.1/drain", Duration::from_secs(5))
            .expect("draining request completed")
    });
    let admitted_deadline = Instant::now() + Duration::from_secs(5);
    while !marker.is_file() {
        if client.is_finished() {
            let logs =
                fs::read_to_string(directory.path().join("logs/acl-proxy.log")).unwrap_or_default();
            panic!(
                "request completed before provider admission: {:?}; logs: {logs}",
                client.join().unwrap(),
            );
        }
        assert!(
            Instant::now() < admitted_deadline,
            "provider did not admit the request"
        );
        thread::sleep(Duration::from_millis(20));
    }
    child.signal(libc::SIGTERM);
    thread::sleep(Duration::from_millis(150));
    assert!(
        child.try_wait().unwrap().is_none(),
        "first termination signal aborted the in-flight request"
    );
    fs::write(&release, b"release").unwrap();
    let response = client.join().unwrap();
    assert!(response.starts_with(b"HTTP/1.1 403"), "{response:?}");
    let status = child.wait_for_exit(
        Duration::from_secs(5),
        "acl-proxy did not exit after the in-flight request drained",
    );
    assert!(status.success());
}

#[cfg(unix)]
#[test]
fn stuck_inflight_request_is_cut_off_at_the_configured_drain_deadline() {
    let directory = TempDir::new().unwrap();
    let (proxy, control) = ephemeral_addresses();
    let python = python3_path();
    let script = directory.path().join("provider.py");
    let marker = directory.path().join("provider-admitted");
    let release = directory.path().join("provider-release");
    write_blocking_provider_script(&script);
    let config = directory.path().join("acl-proxy.toml");
    fs::write(
        &config,
        runtime_config(
            proxy,
            control,
            "400ms",
            &blocking_provider_config(&python, &script, &marker, &release),
        ),
    )
    .unwrap();
    let mut child = ChildGuard::spawn(&config);
    wait_for_ready(&mut child, control);
    let client =
        thread::spawn(move || proxy_get(proxy, "http://192.0.2.1/stuck", Duration::from_secs(5)));
    wait_for_file(&marker, &mut child);

    let started = Instant::now();
    child.signal(libc::SIGTERM);
    let status = child.wait_for_exit(
        Duration::from_secs(3),
        "acl-proxy exceeded the configured drain deadline",
    );
    let elapsed = started.elapsed();
    assert!(status.success());
    assert!(
        elapsed >= Duration::from_millis(300),
        "stuck request was not given the configured drain window: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "stuck request exceeded the bounded drain window: {elapsed:?}"
    );
    let _ = client.join().unwrap();
}

#[cfg(unix)]
#[test]
fn second_termination_signal_forces_immediate_exit_during_drain() {
    let directory = TempDir::new().unwrap();
    let (proxy, control) = ephemeral_addresses();
    let python = python3_path();
    let script = directory.path().join("provider.py");
    let marker = directory.path().join("provider-admitted");
    let release = directory.path().join("provider-release");
    write_blocking_provider_script(&script);
    let config = directory.path().join("acl-proxy.toml");
    fs::write(
        &config,
        runtime_config(
            proxy,
            control,
            "30s",
            &blocking_provider_config(&python, &script, &marker, &release),
        ),
    )
    .unwrap();
    let mut child = ChildGuard::spawn(&config);
    wait_for_ready(&mut child, control);
    let client =
        thread::spawn(move || proxy_get(proxy, "http://192.0.2.1/forced", Duration::from_secs(5)));
    wait_for_file(&marker, &mut child);

    child.signal(libc::SIGTERM);
    thread::sleep(Duration::from_millis(150));
    assert!(child.try_wait().unwrap().is_none());
    let forced_at = Instant::now();
    child.signal(libc::SIGINT);
    let _status = child.wait_for_exit(
        Duration::from_secs(2),
        "a second termination signal did not force immediate process exit",
    );
    assert!(
        forced_at.elapsed() < Duration::from_secs(1),
        "forced shutdown was not immediate"
    );
    let _ = client.join();
}

#[cfg(target_os = "linux")]
#[test]
fn external_capture_state_lock_cannot_block_process_shutdown_past_deadline() {
    let directory = TempDir::new().unwrap();
    let (proxy, control) = ephemeral_addresses();
    let config = directory.path().join("acl-proxy.toml");
    let capture = r#"[redaction.profiles.capture]
replacement = "[MASKED]"
rules = [{ literals = ["secret"], payloads = "both" }]

[observation.capture]
events = ["request.denied", "response.denied"]
redaction_profile = "capture"
directory = "captures"
max_body_bytes = 65536
max_inflight_body_bytes = 134217728
max_pending_records = 8
max_files = 8
max_total_bytes = 1048576

[policy]
    default = "deny"
"#;
    fs::write(&config, runtime_config(proxy, control, "500ms", capture)).unwrap();
    let validation = command()
        .args(["config", "validate", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        validation.status.success(),
        "capture-lock fixture failed validation: {}",
        String::from_utf8_lossy(&validation.stderr)
    );
    let mut proxy_child = ChildGuard::spawn(&config);
    wait_for_ready(&mut proxy_child, control);

    let initial = proxy_get(
        proxy,
        "http://192.0.2.1/initialize-capture-state",
        Duration::from_secs(2),
    )
    .expect("initial denied capture completed");
    assert!(initial.starts_with(b"HTTP/1.1 403"), "{initial:?}");
    let lock = directory.path().join("captures/.capture-state/lock");
    wait_for_file(&lock, &mut proxy_child);
    let marker = directory.path().join("external-lock-held");
    let holder = Command::new("/bin/sh")
        .args([
            "-c",
            "exec 9>>\"$LOCK_PATH\"; flock -x 9; : >\"$MARKER_PATH\"; exec sleep 30",
        ])
        .env("LOCK_PATH", &lock)
        .env("MARKER_PATH", &marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start external capture lock holder");
    let mut holder = ChildGuard(holder);
    wait_for_file(&marker, &mut holder);

    let denied = proxy_get(
        proxy,
        "http://192.0.2.1/capture-lock",
        Duration::from_secs(2),
    )
    .expect("denied request completed while capture lock was held");
    assert!(denied.starts_with(b"HTTP/1.1 403"), "{denied:?}");

    let started = Instant::now();
    proxy_child.signal(libc::SIGTERM);
    let status = proxy_child.wait_for_exit(
        Duration::from_secs(3),
        "external capture-state lock blocked process shutdown",
    );
    let elapsed = started.elapsed();
    assert!(status.success());
    assert!(
        elapsed < Duration::from_secs(2),
        "capture-state lock exceeded the bounded shutdown window: {elapsed:?}"
    );

    holder.signal(libc::SIGTERM);
    holder.wait_for_exit(
        Duration::from_secs(2),
        "external capture lock holder did not exit",
    );
}
