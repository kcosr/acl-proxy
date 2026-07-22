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

#[test]
fn binary_loads_strict_config_binds_and_shuts_down() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("proxy.sock");
    let _socket = UnixListener::bind(&socket_path).unwrap();
    let listen = reserve_address();
    let config_path = directory.path().join("relay.json");
    let config = serde_json::json!({
        "routes": [{
            "name": "http",
            "listen": listen.to_string(),
            "allowedOriginalPorts": [listen.port()],
            "upstreamSocket": socket_path,
        }],
        "setupTimeout": "2s",
        "maxConnections": 1,
        "copyBufferBytesPerDirection": 1024,
    });
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();

    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_acl-proxy-transparent-uds-relay"))
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
        unsafe { libc::kill(child.0.id() as libc::pid_t, libc::SIGINT) },
        0
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "relay exited unsuccessfully: {status}");
            break;
        }
        assert!(Instant::now() < deadline, "relay did not stop after SIGINT");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn binary_rejects_unknown_config_fields() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("invalid.json");
    std::fs::write(
        &config_path,
        br#"{"schemaVersion":1,"routes":[],"setupTimeout":"2s","maxConnections":1,"copyBufferBytesPerDirection":1024}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_acl-proxy-transparent-uds-relay"))
        .args(["--config", config_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("schemaVersion"),
        "unexpected stderr: {stderr}"
    );
}
