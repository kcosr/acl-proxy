#![cfg(target_os = "linux")]

use std::io::Read as _;
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::net::UnixListener;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn reserve_address() -> std::net::SocketAddr {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

fn write_config(
    directory: &tempfile::TempDir,
    socket_path: &std::path::Path,
    presentation: serde_json::Value,
) -> std::path::PathBuf {
    let config_path = directory.path().join("relay.json");
    let config = serde_json::json!({
        "routes": [{
            "name": "http",
            "listen": reserve_address().to_string(),
            "allowedDestinationPorts": [80],
            "transport": {
                "kind": "unix",
                "path": socket_path,
            },
        }],
        "presentation": presentation,
        "setupTimeout": "2s",
        "drainTimeout": "1s",
        "maxConnections": 1,
        "copyBufferBytesPerDirection": 1024,
    });
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    config_path
}

#[test]
fn binary_loads_strict_config_binds_and_drains_on_signal() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("proxy.sock");
    let _socket = UnixListener::bind(&socket_path).unwrap();
    let listen = reserve_address();
    let config_path = directory.path().join("relay.json");
    let config = serde_json::json!({
        "routes": [{
            "name": "http",
            "listen": listen.to_string(),
            "allowedDestinationPorts": [listen.port()],
            "transport": {
                "kind": "unix",
                "path": socket_path,
            },
        }],
        "presentation": {"kind": "disabled"},
        "setupTimeout": "2s",
        "drainTimeout": "1s",
        "maxConnections": 1,
        "copyBufferBytesPerDirection": 1024,
    });
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();

    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_acl-proxy-access-flow-relay"))
            .args(["--config", config_path.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut stderr = String::new();
            child
                .0
                .stderr
                .as_mut()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("relay exited before binding ({status}): {stderr}");
        }
        if std::net::TcpStream::connect(listen).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "relay did not bind within 5s");
        thread::sleep(Duration::from_millis(20));
    }

    // SAFETY: the PID is the live child process owned by this test.
    assert_eq!(
        unsafe { libc::kill(child.0.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "relay exited unsuccessfully: {status}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "relay did not stop after SIGTERM"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn binary_reports_removed_fields_without_accepting_an_alias() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("invalid.json");
    std::fs::write(
        &config_path,
        br#"{"routes":[{"name":"http","listen":"127.0.0.1:3128","allowedOriginalPorts":[80],"upstreamSocket":"/run/acl-proxy/http.sock"}],"presentation":{"kind":"disabled"},"setupTimeout":"2s","drainTimeout":"10s","maxConnections":1,"copyBufferBytesPerDirection":1024}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_acl-proxy-access-flow-relay"))
        .args(["--config", config_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("allowedOriginalPorts"), "{stderr}");
    assert!(stderr.contains("allowedDestinationPorts"), "{stderr}");
}

#[test]
fn binary_sanitizes_missing_and_invalid_bearer_activation_failures() {
    const MISSING_VARIABLE: &str = "AW_ACCESS_FLOW_CLI_MISSING_BEARER";
    const INVALID_VARIABLE: &str = "AW_ACCESS_FLOW_CLI_INVALID_BEARER";
    const INVALID_SECRET: &str = "invalid secret that must not appear anywhere";

    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("proxy.sock");
    let _socket = UnixListener::bind(&socket_path).unwrap();

    let missing_config = write_config(
        &directory,
        &socket_path,
        serde_json::json!({
            "kind": "bearer_environment",
            "variable": MISSING_VARIABLE,
        }),
    );
    let missing = Command::new(env!("CARGO_BIN_EXE_acl-proxy-access-flow-relay"))
        .args(["--config", missing_config.to_str().unwrap()])
        .env_remove(MISSING_VARIABLE)
        .output()
        .unwrap();
    assert!(!missing.status.success());
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(
        stderr.contains("bearer presentation environment source is unavailable"),
        "{stderr}"
    );
    assert!(!stderr.contains(MISSING_VARIABLE), "{stderr}");

    let invalid_config = write_config(
        &directory,
        &socket_path,
        serde_json::json!({
            "kind": "bearer_environment",
            "variable": INVALID_VARIABLE,
        }),
    );
    let invalid = Command::new(env!("CARGO_BIN_EXE_acl-proxy-access-flow-relay"))
        .args(["--config", invalid_config.to_str().unwrap()])
        .env(INVALID_VARIABLE, INVALID_SECRET)
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    let stderr = String::from_utf8_lossy(&invalid.stderr);
    assert!(
        stderr.contains("bearer presentation value is invalid"),
        "{stderr}"
    );
    assert!(!stderr.contains(INVALID_VARIABLE), "{stderr}");
    assert!(!stderr.contains(INVALID_SECRET), "{stderr}");
}
