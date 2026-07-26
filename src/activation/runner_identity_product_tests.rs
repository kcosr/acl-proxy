use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use access_flow::{write_access_flow_preface, AccessFlowDestination};
use access_identity::{IdentityPresentation, SensitiveBearer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

const FILE_BEARER: &str = "file-backed-product-identity-bearer-000000000";

fn trusted_product_tempdir() -> tempfile::TempDir {
    let directory = tempfile::Builder::new()
        .prefix(".identity-product-")
        .tempdir_in(std::env::var_os("HOME").unwrap())
        .unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn write_private_file(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn empty_forwarding_network() -> Arc<http_access_runtime::ForwardingNetworkGuard> {
    Arc::new(
        http_access_runtime::ForwardingDevHarness::new(
            http_access_runtime::ForwardingNetworkFacts::new(Vec::new(), None, None, None).unwrap(),
        )
        .into_standalone_guard(),
    )
}

fn identity_resolver(path: &Path) -> String {
    format!(
        r#"
[identity]
max_pending_authentications = 2
max_pending_authentications_per_connection = 1

[identity.resolver]
kind = "static"
authority = "product-test"

[[identity.resolver.principals]]
id = "test-workload"
kind = "service_account"

[[identity.resolver.tokens]]
id = "test-workload-primary"
principal = "test-workload"
source = "file"
path = {path:?}
"#
    )
}

fn access_flow_config(
    socket_path: &Path,
    identity_mode: Option<&str>,
    token_path: &Path,
) -> String {
    let resolver = identity_mode.map_or_else(String::new, |_| identity_resolver(token_path));
    let identity = identity_mode.map_or_else(String::new, |mode| {
        format!(
            r#"[listeners.transparent_http.identity]
mode = "{mode}"
"#
        )
    });
    format!(
        r#"schema_version = 3

[service]
request_timeout = "2s"
shutdown_drain_timeout = "1s"

[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "1s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]

{identity}

[listeners.transparent_http.endpoint.transport]
kind = "unix"
path = {socket_path:?}
mode = "0600"

{resolver}

[egress]
route = "direct"

[policy]
default = "deny"
"#
    )
}

fn presentation(kind: &str) -> IdentityPresentation {
    match kind {
        "disabled" => IdentityPresentation::Disabled,
        "anonymous" => IdentityPresentation::Anonymous,
        "bearer" => IdentityPresentation::Bearer(
            SensitiveBearer::new(FILE_BEARER.as_bytes()).unwrap(),
        ),
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn access_flow_product_enforces_the_identity_mode_matrix() {
    let _test = crate::activation::LISTENER_TEST_LOCK.lock().await;

    for (mode, presentation_kind, accepted) in [
        (None, "disabled", true),
        (None, "anonymous", false),
        (None, "bearer", false),
        (Some("optional"), "disabled", false),
        (Some("optional"), "anonymous", true),
        (Some("optional"), "bearer", true),
        (Some("required"), "disabled", false),
        (Some("required"), "anonymous", false),
        (Some("required"), "bearer", true),
    ] {
        let directory = trusted_product_tempdir();
        let socket_path = directory.path().join("access-flow.sock");
        let token_path = directory.path().join("identity-token");
        write_private_file(&token_path, FILE_BEARER);
        let config_path = directory.path().join("acl-proxy.toml");
        fs::write(
            &config_path,
            access_flow_config(
                &socket_path,
                mode,
                &fs::canonicalize(&token_path).unwrap(),
            ),
        )
        .unwrap();
        let loaded = crate::config::load_and_compile_exact_config(&config_path).unwrap();
        let product = ProductRuntime::prepare_from_prebound_with_forwarding_network(
            loaded,
            Vec::new(),
            empty_forwarding_network(),
        )
        .await
        .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let mut client = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
        let preface_result = write_access_flow_preface(
            &mut client,
            AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
            &presentation(presentation_kind),
        )
        .await;
        if accepted {
            preface_result.unwrap();
            client
                .write_all(
                    b"GET /matrix HTTP/1.1\r\nHost: denied.example.test\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let response = read_http_message(&mut client).await;
            assert!(
                response.starts_with(b"HTTP/1.1 403 "),
                "mode={}, presentation={presentation_kind}, response={:?}",
                mode.unwrap_or("omitted"),
                String::from_utf8_lossy(&response)
            );
        } else {
            if preface_result.is_ok() {
                let _ = client
                    .write_all(
                        b"GET /matrix HTTP/1.1\r\nHost: denied.example.test\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            }
            let mut byte = [0_u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut byte))
                .await
                .expect("rejected Access Flow remained open");
            assert!(
                matches!(read, Ok(0) | Err(_)),
                "mode={}, presentation={presentation_kind} reached HTTP",
                mode.unwrap_or("omitted")
            );
        }

        product.shutdown().await;
        assert!(socket_path.exists());
        fs::remove_file(&socket_path).unwrap();
    }
}

#[tokio::test]
async fn optional_explicit_http_admits_anonymous_requests() {
    let _test = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let reservations = crate::activation::reserve_listeners::<1>(&_test);
    let addresses = reservations.addresses();
    let origin = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin_address = origin.local_addr().unwrap();
    let directory = trusted_product_tempdir();
    let token_path = directory.path().join("identity-token");
    write_private_file(&token_path, FILE_BEARER);
    let config_path = directory.path().join("acl-proxy.toml");
    fs::write(
        &config_path,
        format!(
            r#"schema_version = 3

[service]
request_timeout = "2s"
shutdown_drain_timeout = "1s"

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "{}"
http_versions = ["http1"]

[listeners.explicit_http.identity]
mode = "optional"

[listeners.explicit_http.connect]
http1 = "deny"

{}

[egress]
route = "direct"

[policy]
default = "deny"

[[policy.rules]]
id = "anonymous"
decision = "allow"
urls = ["http://origin.example.test/**"]
methods = ["GET"]
identity_states = ["anonymous"]
"#,
            addresses[0],
            identity_resolver(&fs::canonicalize(&token_path).unwrap())
        ),
    )
    .unwrap();
    let loaded = crate::config::load_and_compile_exact_config(&config_path).unwrap();
    let origin_url =
        http_access_url::canonicalize_http_url("http://origin.example.test/").unwrap();
    let network = Arc::new(
        http_access_runtime::ForwardingDevHarness::new(
            http_access_runtime::ForwardingNetworkFacts::new(
                vec![addresses[0]],
                None,
                None,
                None,
            )
            .unwrap(),
        )
        .map_prebound(&origin_url, origin_address)
        .unwrap()
        .into_standalone_guard(),
    );
    let product = ProductRuntime::prepare_from_prebound_with_forwarding_network(
        loaded,
        reservations.into_listeners(),
        network,
    )
    .await
    .unwrap();
    product.activate_initial().await.unwrap();
    product.start_listeners().await.unwrap();

    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let request = read_http_message(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        request
    });
    let mut client = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
    client
        .write_all(
            b"GET http://origin.example.test/anonymous HTTP/1.1\r\nHost: origin.example.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let response = read_http_message(&mut client).await;
    assert!(response.starts_with(b"HTTP/1.1 200 "));
    let request = String::from_utf8(origin_task.await.unwrap())
        .unwrap()
        .to_ascii_lowercase();
    assert!(!request.contains("x-aw-identity-token"));

    product.shutdown().await;
    crate::activation::assert_listener_addresses_released(&_test, addresses);
}

async fn read_until(stream: &mut tokio::net::TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.windows(needle.len()).any(|window| window == needle) {
        let mut buffer = [0_u8; 1024];
        let count = stream.read(&mut buffer).await.unwrap();
        assert_ne!(count, 0, "peer closed before expected bytes arrived");
        bytes.extend_from_slice(&buffer[..count]);
    }
    bytes
}

async fn assert_connection_cancelled(stream: &mut tokio::net::TcpStream, label: &str) {
    let mut byte = [0_u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
        .await
        .unwrap_or_else(|_| panic!("{label} remained open after identity generation rotation"));
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "{label} delivered bytes after identity generation rotation"
    );
}

#[tokio::test]
async fn file_token_rotation_cancels_authenticated_streams_and_websockets() {
    let _test = crate::activation::LISTENER_TEST_LOCK.lock().await;
    let reservations = crate::activation::reserve_listeners::<1>(&_test);
    let addresses = reservations.addresses();
    let origin = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin_address = origin.local_addr().unwrap();
    let directory = trusted_product_tempdir();
    let token_path = directory.path().join("identity-token");
    const OLD_BEARER: &str = "old-file-product-identity-bearer-000000000000";
    const NEW_BEARER: &str = "new-file-product-identity-bearer-000000000000";
    write_private_file(&token_path, OLD_BEARER);
    let config_path = directory.path().join("acl-proxy.toml");
    fs::write(
        &config_path,
        format!(
            r#"schema_version = 3

[service]
request_timeout = "5s"
shutdown_drain_timeout = "1s"

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "{}"
http_versions = ["http1"]

[listeners.explicit_http.identity]
mode = "required"

[listeners.explicit_http.connect]
http1 = "deny"

{}

[egress]
route = "direct"

[policy]
default = "deny"

[[policy.rules]]
id = "authenticated"
decision = "allow"
urls = ["http://origin.example.test/**"]
methods = ["GET"]
allow_upgrades = true
identity_states = ["authenticated"]
"#,
            addresses[0],
            identity_resolver(&fs::canonicalize(&token_path).unwrap())
        ),
    )
    .unwrap();
    let loaded = crate::config::load_and_compile_exact_config(&config_path).unwrap();
    let origin_url =
        http_access_url::canonicalize_http_url("http://origin.example.test/").unwrap();
    let network = Arc::new(
        http_access_runtime::ForwardingDevHarness::new(
            http_access_runtime::ForwardingNetworkFacts::new(
                vec![addresses[0]],
                None,
                None,
                None,
            )
            .unwrap(),
        )
        .map_prebound(&origin_url, origin_address)
        .unwrap()
        .into_standalone_guard(),
    );
    let product = ProductRuntime::prepare_from_prebound_with_forwarding_network(
        loaded,
        reservations.into_listeners(),
        network,
    )
    .await
    .unwrap();
    product.activate_initial().await.unwrap();
    product.start_listeners().await.unwrap();

    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let stream_request = read_http_message(&mut stream).await;
        assert!(stream_request.starts_with(b"GET /stream HTTP/1.1\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nhello\r\n",
            )
            .await
            .unwrap();
        let stream_task = tokio::spawn(async move {
            let mut trailing = Vec::new();
            let _ = stream.read_to_end(&mut trailing).await;
        });

        let (mut websocket, _) = origin.accept().await.unwrap();
        let websocket_request = read_http_message(&mut websocket).await;
        assert!(websocket_request.starts_with(b"GET /socket HTTP/1.1\r\n"));
        websocket
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            )
            .await
            .unwrap();
        let websocket_task = tokio::spawn(async move {
            let mut trailing = Vec::new();
            let _ = websocket.read_to_end(&mut trailing).await;
        });

        let (mut fresh, _) = origin.accept().await.unwrap();
        let fresh_request = read_http_message(&mut fresh).await;
        assert!(fresh_request.starts_with(b"GET /fresh HTTP/1.1\r\n"));
        fresh
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfresh",
            )
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(2), stream_task)
            .await
            .expect("stream origin did not observe generation cancellation")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), websocket_task)
            .await
            .expect("WebSocket origin did not observe generation cancellation")
            .unwrap();
    });

    let mut stream_client = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
    stream_client
        .write_all(
            format!(
                "GET http://origin.example.test/stream HTTP/1.1\r\nHost: origin.example.test\r\nx-aw-identity-token: {OLD_BEARER}\r\nConnection: keep-alive\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let stream_response = read_until(&mut stream_client, b"hello\r\n").await;
    assert!(stream_response.starts_with(b"HTTP/1.1 200 "));

    let mut websocket_client = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
    websocket_client
        .write_all(
            format!(
                "GET http://origin.example.test/socket HTTP/1.1\r\nHost: origin.example.test\r\nx-aw-identity-token: {OLD_BEARER}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let websocket_response = read_http_message(&mut websocket_client).await;
    assert!(websocket_response.starts_with(b"HTTP/1.1 101 "));

    write_private_file(&token_path, NEW_BEARER);
    let reload = product.runtime().trigger_reload().await.unwrap();
    assert!(
        matches!(reload, crate::runtime::ReloadTriggerResult::Completed { .. }),
        "identity file rotation unexpectedly coalesced"
    );

    assert_connection_cancelled(&mut stream_client, "stream").await;
    assert_connection_cancelled(&mut websocket_client, "WebSocket").await;

    let mut old_client = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
    old_client
        .write_all(
            format!(
                "GET http://origin.example.test/stale HTTP/1.1\r\nHost: origin.example.test\r\nx-aw-identity-token: {OLD_BEARER}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let old_response = read_http_message(&mut old_client).await;
    assert!(old_response.starts_with(b"HTTP/1.1 403 "));
    assert!(old_response.ends_with(b"\r\n\r\nidentity invalid\n"));

    let mut fresh_client = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
    fresh_client
        .write_all(
            format!(
                "GET http://origin.example.test/fresh HTTP/1.1\r\nHost: origin.example.test\r\nx-aw-identity-token: {NEW_BEARER}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let fresh_response = read_http_message(&mut fresh_client).await;
    assert!(fresh_response.starts_with(b"HTTP/1.1 200 "));
    assert!(fresh_response.ends_with(b"\r\n\r\nfresh"));

    origin_task.await.unwrap();
    product.shutdown().await;
    crate::activation::assert_listener_addresses_released(&_test, addresses);
}

enum CarrierIngress {
    Explicit {
        identity_mode: Option<&'static str>,
        headers: String,
    },
    AccessFlow {
        identity_mode: Option<&'static str>,
        presentation: &'static str,
    },
}

#[tokio::test]
async fn protected_identity_carriers_stop_before_policy_capture_and_upstream() {
    let _test = crate::activation::LISTENER_TEST_LOCK.lock().await;

    for (label, ingress) in [
        (
            "explicit duplicate",
            CarrierIngress::Explicit {
                identity_mode: Some("required"),
                headers: format!(
                    "x-aw-identity-token: {FILE_BEARER}\r\nx-aw-identity-token: {FILE_BEARER}\r\n"
                ),
            },
        ),
        (
            "explicit identity omitted",
            CarrierIngress::Explicit {
                identity_mode: None,
                headers: format!("x-aw-identity-token: {FILE_BEARER}\r\n"),
            },
        ),
        (
            "Access Flow identity omitted",
            CarrierIngress::AccessFlow {
                identity_mode: None,
                presentation: "disabled",
            },
        ),
        (
            "Access Flow anonymous",
            CarrierIngress::AccessFlow {
                identity_mode: Some("optional"),
                presentation: "anonymous",
            },
        ),
        (
            "Access Flow authenticated",
            CarrierIngress::AccessFlow {
                identity_mode: Some("required"),
                presentation: "bearer",
            },
        ),
    ] {
        let directory = trusted_product_tempdir();
        let token_path = directory.path().join("identity-token");
        write_private_file(&token_path, FILE_BEARER);
        let provider_script = directory.path().join("provider.py");
        let provider_log = directory.path().join("provider.jsonl");
        fs::write(
            &provider_script,
            r#"import json, sys
for line in sys.stdin:
    request = json.loads(line)
    with open(sys.argv[1], "a", encoding="utf-8") as output:
        output.write(json.dumps(request) + "\n")
    print(json.dumps({"id": request["id"], "type": "response", "decision": "allow"}), flush=True)
"#,
        )
        .unwrap();
        let origin = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let socket_path = directory.path().join("access-flow.sock");
        let reservations = matches!(&ingress, CarrierIngress::Explicit { .. })
            .then(|| crate::activation::reserve_listeners::<1>(&_test));
        let addresses = reservations
            .as_ref()
            .map_or(Vec::new(), |value| value.addresses().to_vec());
        let (listener_config, identity_mode, prebound) = match &ingress {
            CarrierIngress::Explicit { identity_mode, .. } => (
                format!(
                    r#"[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "{}"
http_versions = ["http1"]

{identity}

[listeners.explicit_http.connect]
http1 = "deny"
"#,
                    addresses[0],
                    identity = identity_mode.map_or_else(String::new, |mode| format!(
                        "[listeners.explicit_http.identity]\nmode = \"{mode}\""
                    ))
                ),
                *identity_mode,
                reservations.unwrap().into_listeners(),
            ),
            CarrierIngress::AccessFlow { identity_mode, .. } => (
                format!(
                    r#"[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "1s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]

{identity}

[listeners.transparent_http.endpoint.transport]
kind = "unix"
path = {socket_path:?}
mode = "0600"
"#,
                    identity = identity_mode.map_or_else(String::new, |mode| format!(
                        "[listeners.transparent_http.identity]\nmode = \"{mode}\""
                    ))
                ),
                *identity_mode,
                Vec::new(),
            ),
        };
        let resolver = identity_mode.map_or_else(String::new, |_| {
            identity_resolver(&fs::canonicalize(&token_path).unwrap())
        });
        let config_path = directory.path().join("acl-proxy.toml");
        fs::write(
            &config_path,
            format!(
                r#"schema_version = 3

[service]
request_timeout = "2s"
shutdown_drain_timeout = "1s"

{listener_config}

{resolver}

[authorization.providers.probe]
kind = "process"
command = "/usr/bin/python3"
args = [{provider_script:?}, {provider_log:?}]
include_headers = []

[egress]
route = "direct"

[redaction.profiles.capture]
rules = [{{ literals = ["never-observed"] }}]

[observation.capture]
events = ["request.allowed", "request.denied"]
redaction_profile = "capture"
directory = "captures"
max_body_bytes = 1024
max_inflight_body_bytes = 134217728
max_pending_records = 8
max_files = 8
max_total_bytes = 1048576

[policy]
default = "deny"

[[policy.rules]]
id = "must-not-run"
decision = "delegate"
authorization_provider = "probe"
urls = ["http://origin.example.test/**"]
methods = ["GET"]
"#
            ),
        )
        .unwrap();
        let loaded = crate::config::load_and_compile_exact_config(&config_path).unwrap();
        let origin_url =
            http_access_url::canonicalize_http_url("http://origin.example.test/").unwrap();
        let network = Arc::new(
            http_access_runtime::ForwardingDevHarness::new(
                http_access_runtime::ForwardingNetworkFacts::new(
                    addresses.to_vec(),
                    None,
                    None,
                    None,
                )
                .unwrap(),
            )
            .map_prebound(&origin_url, origin_address)
            .unwrap()
            .into_standalone_guard(),
        );
        let product = ProductRuntime::prepare_from_prebound_with_forwarding_network(
            loaded, prebound, network,
        )
        .await
        .unwrap();
        product.activate_initial().await.unwrap();
        product.start_listeners().await.unwrap();

        let response = match ingress {
            CarrierIngress::Explicit { headers, .. } => {
                let mut client = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
                client
                    .write_all(
                        format!(
                            "GET http://origin.example.test/carrier HTTP/1.1\r\nHost: origin.example.test\r\n{headers}Connection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                read_http_message(&mut client).await
            }
            CarrierIngress::AccessFlow { presentation: p, .. } => {
                let mut client = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
                write_access_flow_preface(
                    &mut client,
                    AccessFlowDestination::new("203.0.113.8".parse().unwrap(), 80).unwrap(),
                    &presentation(p),
                )
                .await
                .unwrap();
                client
                    .write_all(
                        format!(
                            "GET /carrier HTTP/1.1\r\nHost: origin.example.test\r\nx-aw-identity-token: {FILE_BEARER}\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                read_http_message(&mut client).await
            }
        };
        assert!(
            response.starts_with(b"HTTP/1.1 403 "),
            "{label}: {:?}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            response.ends_with(b"\r\n\r\nidentity invalid\n"),
            "{label}: {:?}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), origin.accept())
                .await
                .is_err(),
            "{label}: protected carrier reached upstream"
        );
        product.shutdown().await;
        assert!(
            !provider_log.exists(),
            "{label}: protected carrier reached authorization provider"
        );
        let capture_directory = directory.path().join("captures");
        if capture_directory.exists() {
            assert!(
                capture_records(&capture_directory).is_empty(),
                "{label}: protected carrier was captured"
            );
        }

        if socket_path.exists() {
            fs::remove_file(&socket_path).unwrap();
        }
        crate::activation::assert_listener_addresses_released(&_test, addresses);
    }
}
