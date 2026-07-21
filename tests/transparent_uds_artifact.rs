#![cfg(target_os = "linux")]

use std::io::Read as _;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use acl_proxy_transparent_uds_relay::config::Route;
use acl_proxy_transparent_uds_relay::relay::relay_known_destination_for_test;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
            assert!(std::fs::symlink_metadata(socket)
                .unwrap()
                .file_type()
                .is_socket());
            std::fs::remove_file(socket).unwrap();
            assert!(!socket.exists());
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("ACL Proxy did not stop after SIGTERM");
}

#[tokio::test]
async fn relay_and_acl_proxy_binary_round_trip_http_across_the_unix_artifact_boundary() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.path().join("transparent-http.sock");
    let config_path = directory.path().join("acl-proxy.toml");
    let control = reserve_address();
    // A local policy response exercises the artifact boundary without disabling
    // ACL Proxy's production guard against dialing a fake loopback origin.
    let config = format!(
        r#"schema_version = 3

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[control]
bind = "{control}"
base_path = "/_acl-proxy"

[listeners.transparent_http]
endpoint.kind = "unix_proxy_v2"
endpoint.path = {socket:?}
endpoint.mode = "0600"
proxy_header_timeout = "1s"
http_versions = ["http1"]

[egress]
route = "direct"

[policy]
default = "deny"
"#
    );
    std::fs::write(&config_path, config).unwrap();

    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_acl-proxy"))
            .args(["run", "--config"])
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    wait_until_ready(&mut child.0, control, &socket).await;

    let relay_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let relay_address = relay_listener.local_addr().unwrap();
    let client_task = tokio::spawn(TcpStream::connect(relay_address));
    let (relay_client, peer) = relay_listener.accept().await.unwrap();
    let mut client = client_task.await.unwrap().unwrap();
    let route = Route {
        name: "http".to_owned(),
        listen: relay_address,
        allowed_original_ports: vec![80],
        upstream_socket: PathBuf::from(&socket),
    };
    let relay = tokio::spawn(relay_known_destination_for_test(
        relay_client,
        peer,
        "203.0.113.8:80".parse().unwrap(),
        route,
        Duration::from_secs(1),
        1024,
    ));

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
    let outcome = relay.await.unwrap();
    assert!(outcome.completed);
    assert!(outcome.bytes_to_upstream > 0);
    assert!(outcome.bytes_to_client > 0);

    stop(&mut child, &socket).await;
}
