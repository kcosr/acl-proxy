#![cfg(target_os = "linux")]

use std::io::Read as _;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use access_flow::{write_access_flow_preface, AccessFlowDestination};
use access_identity::IdentityPresentation;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn reserve_address() -> SocketAddr {
    StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn wait_until_ready(child: &mut Child, control: SocketAddr, socket: &Path) {
    for _ in 0..400 {
        if let Some(status) = child.try_wait().unwrap() {
            let mut stderr = String::new();
            child
                .stderr
                .as_mut()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("ACL Proxy exited before readiness ({status}): {stderr}");
        }
        if socket.exists() {
            if let Ok(mut stream) = TcpStream::connect(control).await {
                stream
                    .write_all(b"GET /_acl-proxy/ready HTTP/1.1\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await.unwrap();
                if response.starts_with(b"HTTP/1.1 200") {
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("ACL Proxy did not become ready");
}

async fn stop(child: &mut ChildGuard, socket: &Path) {
    // SAFETY: the child PID identifies the live ACL Proxy process owned by this test.
    assert_eq!(
        unsafe { libc::kill(child.0.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    for _ in 0..200 {
        if child.0.try_wait().unwrap().is_some() {
            assert!(!socket.exists());
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("ACL Proxy did not stop after SIGTERM");
}

fn spawn(config_path: &Path) -> ChildGuard {
    ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_acl-proxy"))
            .args(["run", "--config"])
            .arg(config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    )
}

#[tokio::test]
async fn access_flow_and_acl_proxy_binary_round_trip_http_across_the_unix_artifact_boundary() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.path().join("transparent-http.sock");
    let config_path = directory.path().join("acl-proxy.toml");
    let control = reserve_address();
    // A local policy response exercises the artifact boundary without disabling
    // ACL Proxy's production guard against dialing a fake loopback origin.
    let config = format!(
        r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[control]
bind = "{control}"
base_path = "/_acl-proxy"

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]

[listeners.transparent_http.endpoint.transport]
kind = "unix"
path = {socket:?}
mode = "0600"

[egress]
route = "direct"

[policy]
default = "deny"
"#
    );
    std::fs::write(&config_path, config).unwrap();

    let mut child = spawn(&config_path);
    wait_until_ready(&mut child.0, control, &socket).await;

    let mut rejected = UnixStream::connect(&socket).await.unwrap();
    write_access_flow_preface(
        &mut rejected,
        AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 443).unwrap(),
        &IdentityPresentation::Disabled,
    )
    .await
    .unwrap();
    rejected
        .write_all(
            b"GET /must-not-dispatch HTTP/1.1\r\nHost: origin.example.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    rejected.shutdown().await.unwrap();
    let mut rejected_response = Vec::new();
    let rejected_read = tokio::time::timeout(
        Duration::from_secs(1),
        rejected.read_to_end(&mut rejected_response),
    )
    .await
    .unwrap();
    if let Err(error) = rejected_read {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    }
    assert!(rejected_response.is_empty());

    let mut client = UnixStream::connect(&socket).await.unwrap();
    write_access_flow_preface(
        &mut client,
        AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
        &IdentityPresentation::Disabled,
    )
    .await
    .unwrap();
    client
        .write_all(
            b"GET /artifact HTTP/1.1\r\nHost: origin.example.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "unexpected ACL response: {}",
        String::from_utf8_lossy(&response)
    );
    assert!(String::from_utf8_lossy(&response).contains("request denied"));
    stop(&mut child, &socket).await;

    let mut restarted = spawn(&config_path);
    wait_until_ready(&mut restarted.0, control, &socket).await;
    stop(&mut restarted, &socket).await;
}

#[tokio::test]
async fn forced_exit_leaves_a_stale_socket_that_the_next_startup_recovers() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.path().join("forced-exit.sock");
    let config_path = directory.path().join("acl-proxy.toml");
    let control = reserve_address();
    std::fs::write(
        &config_path,
        format!(
            r#"schema_version = 4

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[control]
bind = "{control}"
base_path = "/_acl-proxy"

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]

[listeners.transparent_http.endpoint.transport]
kind = "unix"
path = {socket:?}
mode = "0600"

[egress]
route = "direct"

[policy]
default = "deny"
"#
        ),
    )
    .unwrap();

    let mut killed = spawn(&config_path);
    wait_until_ready(&mut killed.0, control, &socket).await;
    killed.0.kill().unwrap();
    assert!(!killed.0.wait().unwrap().success());
    assert!(std::fs::symlink_metadata(&socket)
        .unwrap()
        .file_type()
        .is_socket());

    let mut restarted = spawn(&config_path);
    wait_until_ready(&mut restarted.0, control, &socket).await;
    stop(&mut restarted, &socket).await;
}
