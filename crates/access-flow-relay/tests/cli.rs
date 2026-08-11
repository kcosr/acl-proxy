#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt as _;
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

fn write_runtime_config(
    directory: &tempfile::TempDir,
    socket_path: &std::path::Path,
    listen: std::net::SocketAddr,
    max_connections: usize,
) -> std::path::PathBuf {
    let config_path = directory.path().join("runtime-relay.json");
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
        "setupTimeout": "500ms",
        "drainTimeout": "1s",
        "maxConnections": max_connections,
        "copyBufferBytesPerDirection": 1024,
    });
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    config_path
}

fn relay_command(config_path: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_acl-proxy-access-flow-relay"));
    command.args(["--config", config_path.to_str().unwrap()]);
    command
}

fn set_nofile_limit(command: &mut Command, limit: libc::rlim_t) {
    // SAFETY: the closure performs only async-signal-safe libc limit changes
    // between fork and exec and does not access shared process state.
    unsafe {
        command.pre_exec(move || {
            let limit = libc::rlimit {
                rlim_cur: limit,
                rlim_max: limit,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn start_with_dumping_enabled(command: &mut Command) {
    // SAFETY: the closure performs only async-signal-safe libc calls between
    // fork and exec and deliberately establishes the state main must remove.
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 1024 * 1024,
                rlim_max: 1024 * 1024,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn connect_when_ready(address: std::net::SocketAddr) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(address) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                return stream;
            }
            Err(_) => {
                assert!(Instant::now() < deadline, "relay did not bind within 5s");
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn accept_unix(listener: &UnixListener) -> std::os::unix::net::UnixStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "relay did not connect to the Unix endpoint"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("Unix endpoint accept failed: {error}"),
        }
    }
}

fn exchange(
    listener: &UnixListener,
    listen: std::net::SocketAddr,
    request: &[u8],
    response: &[u8],
) {
    let mut source = connect_when_ready(listen);
    let mut endpoint = accept_unix(listener);
    let mut header = [0_u8; access_flow::ACCESS_FLOW_V2_HEADER_LEN];
    endpoint.read_exact(&mut header).unwrap();
    assert_eq!(&header[..4], b"AWAF");
    assert_eq!(header[4], 2);
    assert_eq!(u16::from_be_bytes([header[8], header[9]]), listen.port());
    assert_eq!(&header[10..14], &Ipv4Addr::LOCALHOST.octets());
    assert_eq!(u16::from_be_bytes([header[14], header[15]]), 0);
    assert_eq!(header[16], 0);

    source.write_all(request).unwrap();
    source.shutdown(Shutdown::Write).unwrap();
    let mut actual_request = vec![0; request.len()];
    endpoint.read_exact(&mut actual_request).unwrap();
    assert_eq!(actual_request, request);
    endpoint.write_all(response).unwrap();
    endpoint.shutdown(Shutdown::Write).unwrap();
    let mut actual_response = Vec::new();
    source.read_to_end(&mut actual_response).unwrap();
    assert_eq!(actual_response, response);
}

fn terminate_successfully(child: &mut ChildGuard) {
    // SAFETY: the PID is the live child process owned by this test.
    assert_eq!(
        unsafe { libc::kill(child.0.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "relay exited unsuccessfully: {status}");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "relay did not stop after SIGTERM"
        );
        thread::sleep(Duration::from_millis(20));
    }
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

    terminate_successfully(&mut child);
}

#[test]
fn binary_recovers_after_endpoint_removal_and_rebind() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("proxy.sock");
    let first_endpoint = UnixListener::bind(&socket_path).unwrap();
    let listen = reserve_address();
    let config_path = write_runtime_config(&directory, &socket_path, listen, 4);
    let mut child = ChildGuard(
        relay_command(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );

    exchange(&first_endpoint, listen, b"first", b"one");
    drop(first_endpoint);
    std::fs::remove_file(&socket_path).unwrap();

    let mut unavailable = connect_when_ready(listen);
    unavailable.shutdown(Shutdown::Write).unwrap();
    let mut byte = [0_u8; 1];
    match unavailable.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ) => {}
        outcome => panic!("flow did not close while endpoint was absent: {outcome:?}"),
    }

    let replacement = UnixListener::bind(&socket_path).unwrap();
    exchange(&replacement, listen, b"second", b"two");
    terminate_successfully(&mut child);
}

#[test]
fn binary_disables_dumps_before_config_parse_and_preserves_usage_errors() {
    let directory = tempfile::tempdir().unwrap();
    let fifo_path = directory.path().join("blocked-config");
    let fifo = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
    // SAFETY: fifo is a valid NUL-terminated path and mode is a scalar.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

    let mut command = relay_command(&fifo_path);
    command.stdout(Stdio::null()).stderr(Stdio::piped());
    start_with_dumping_enabled(&mut command);
    let mut child = ChildGuard(command.spawn().unwrap());
    let limits_path = format!("/proc/{}/limits", child.0.id());
    let memory_path = format!("/proc/{}/mem", child.0.id());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let limits = std::fs::read_to_string(&limits_path).unwrap();
        let core_disabled = limits
            .lines()
            .find(|line| line.starts_with("Max core file size"))
            .is_some_and(|line| {
                line.split_whitespace()
                    .collect::<Vec<_>>()
                    .ends_with(&["0", "0", "bytes"])
            });
        let memory_denied = OpenOptions::new()
            .read(true)
            .open(&memory_path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied);
        if core_disabled && memory_denied {
            break;
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "relay exited before blocking on configuration input"
        );
        assert!(
            Instant::now() < deadline,
            "relay did not suppress core dumps and dumpability"
        );
        thread::sleep(Duration::from_millis(10));
    }

    std::fs::write(&fifo_path, b"{").unwrap();
    let status = child.0.wait().unwrap();
    assert!(!status.success());
    let mut stderr = String::new();
    child
        .0
        .stderr
        .as_mut()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        stderr.contains("configuration is not valid JSON"),
        "{stderr}"
    );

    let mut usage = Command::new(env!("CARGO_BIN_EXE_acl-proxy-access-flow-relay"));
    start_with_dumping_enabled(&mut usage);
    let usage = usage.output().unwrap();
    assert!(!usage.status.success());
    assert!(String::from_utf8_lossy(&usage.stderr)
        .contains("usage: acl-proxy-access-flow-relay --config <path>"));
}

#[test]
fn low_nofile_reserve_and_projection_overbudget_fail_before_bind() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("proxy.sock");
    let _endpoint = UnixListener::bind(&socket_path).unwrap();

    let reserve_listen = reserve_address();
    let reserve_config = write_runtime_config(&directory, &socket_path, reserve_listen, 1);
    let mut reserve = relay_command(&reserve_config);
    set_nofile_limit(&mut reserve, 16);
    let reserve = reserve.output().unwrap();
    assert!(!reserve.status.success());
    let stderr = String::from_utf8_lossy(&reserve.stderr);
    assert!(
        stderr.contains("RLIMIT_NOFILE must exceed the 16-descriptor consumer reserve"),
        "{stderr}"
    );
    assert!(TcpStream::connect(reserve_listen).is_err());

    let projection_listen = reserve_address();
    let projection_config = write_runtime_config(&directory, &socket_path, projection_listen, 1024);
    let mut projection = relay_command(&projection_config);
    set_nofile_limit(&mut projection, 64);
    let projection = projection.output().unwrap();
    assert!(!projection.status.success());
    let stderr = String::from_utf8_lossy(&projection.stderr);
    assert!(stderr.contains("resource budget"), "{stderr}");
    assert!(TcpStream::connect(projection_listen).is_err());
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
fn binary_names_presentation_as_the_only_identity_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("invalid-identity.json");
    std::fs::write(
        &config_path,
        br#"{"routes":[{"name":"http","listen":"127.0.0.1:3128","allowedDestinationPorts":[80],"transport":{"kind":"unix","path":"/run/acl-proxy/http.sock"},"identity":{"kind":"disabled"}}],"presentation":{"kind":"disabled"},"setupTimeout":"2s","drainTimeout":"10s","maxConnections":1,"copyBufferBytesPerDirection":1024}"#,
    )
    .unwrap();
    let output = relay_command(&config_path).output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("removed field(s) identity"), "{stderr}");
    assert!(stderr.contains("top-level presentation"), "{stderr}");
    assert!(!stderr.contains("top-level identity"), "{stderr}");
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
