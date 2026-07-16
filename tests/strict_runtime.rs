#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use tempfile::TempDir;

const IO_TIMEOUT: Duration = Duration::from_secs(3);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(10);

struct ChildGuard {
    child: Child,
    signal: libc::c_int,
}

impl ChildGuard {
    fn new(child: Child, signal: libc::c_int) -> Self {
        Self { child, signal }
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn is_running(&mut self) -> bool {
        self.child.try_wait().expect("inspect child").is_none()
    }

    fn terminate(&mut self) -> std::process::ExitStatus {
        if self.is_running() {
            unsafe {
                libc::kill(self.child.id() as libc::pid_t, self.signal);
            }
        }
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().expect("wait for child") {
                return status;
            }
            if Instant::now() >= deadline {
                self.child.kill().expect("kill child after timeout");
                return self.child.wait().expect("reap killed child");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.is_running() {
            unsafe {
                libc::kill(self.child.id() as libc::pid_t, self.signal);
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while self.is_running() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            if self.is_running() {
                let _ = self.child.kill();
            }
        }
        let _ = self.child.wait();
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

fn write_file(path: &Path, contents: &str) {
    fs::write(path, contents)
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    while !path.is_file() {
        assert!(
            Instant::now() < deadline,
            "{} was not created",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_file_text(path: &Path, needle: &str) {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    loop {
        if fs::read_to_string(path).is_ok_and(|text| text.contains(needle)) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{} did not contain {needle:?}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn connect(address: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)
        .unwrap_or_else(|error| panic!("connect to {address}: {error}"));
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    stream
}

fn send_request(
    stream: &mut TcpStream,
    method: &str,
    target: &str,
    host: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    close: bool,
) -> HttpResponse {
    write!(
        stream,
        "{method} {target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: {}\r\n",
        body.len(),
        if close { "close" } else { "keep-alive" }
    )
    .unwrap();
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n").unwrap();
    }
    stream.write_all(b"\r\n").unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
    read_response(stream)
}

fn read_response(stream: &mut TcpStream) -> HttpResponse {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 64 * 1024, "HTTP response head exceeded 64 KiB");
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).expect("read response head");
        head.push(byte[0]);
    }
    let text = std::str::from_utf8(&head).expect("response head is UTF-8");
    let mut lines = text[..text.len() - 4].split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .expect("response status");
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').expect("response header");
        headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
    }
    let length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .expect("response Content-Length");
    let mut body = vec![0; length];
    stream.read_exact(&mut body).expect("read response body");
    HttpResponse {
        status,
        headers,
        body,
    }
}

fn proxy_request(proxy: SocketAddr, method: &str, url: &str, body: &[u8]) -> HttpResponse {
    let host = url
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .expect("test URL authority");
    let mut stream = connect(proxy);
    send_request(
        &mut stream,
        method,
        url,
        host,
        &[("Content-Type", "text/plain"), ("X-Test-Input", "included")],
        body,
        true,
    )
}

fn control_request(control: SocketAddr, path: &str) -> HttpResponse {
    let mut stream = connect(control);
    send_request(
        &mut stream,
        "GET",
        path,
        &control.to_string(),
        &[],
        &[],
        true,
    )
}

fn readiness_status(control: SocketAddr) -> Option<u16> {
    let mut stream = TcpStream::connect_timeout(&control, Duration::from_millis(100)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(250)))
        .ok()?;
    stream
        .write_all(
            format!(
                "GET /_acl-proxy/ready HTTP/1.1\r\nHost: {control}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    response
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
}

fn wait_for_ready(proxy: &mut ChildGuard, control: SocketAddr) {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    loop {
        assert!(proxy.is_running(), "acl-proxy exited before readiness");
        if readiness_status(control) == Some(200) {
            return;
        }
        assert!(Instant::now() < deadline, "acl-proxy did not become ready");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn origin_script() -> &'static str {
    r#"import http.client
import http.server
import json
import sys
import threading
import time
import urllib.parse

port_file, event_file = sys.argv[1:]

def deliver_callback(callback_url, payload):
    time.sleep(0.05)
    target = urllib.parse.urlsplit(callback_url)
    body = json.dumps(payload, separators=(",", ":")).encode("ascii")
    connection = http.client.HTTPConnection(target.hostname, target.port, timeout=3)
    connection.request("POST", target.path, body=body, headers={"Content-Type": "application/json"})
    response = connection.getresponse()
    response.read()
    connection.close()

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def send_body(self, status, body=b"", headers=None):
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.send_body(200, self.path.encode("ascii"), {
            "Content-Type": "text/plain",
            "X-Seen-Provider-Token": self.headers.get("x-provider-token", "missing"),
            "X-Seen-Authorization": self.headers.get("authorization", "missing"),
        })

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        if self.path == "/authorize":
            request = json.loads(body)
            with open(event_file, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n")
            path = urllib.parse.urlsplit(request["url"]).path
            decision = {
                "/webhook-deny": "deny",
                "/webhook-pass": "pass",
            }.get(path, "allow")
            callback = {
                "resumeToken": request["resumeToken"],
                "type": "response",
                "decision": decision,
            }
            if decision == "allow" and path != "/webhook-error":
                callback["values"] = {"token": "webhook-typed-secret"}
            self.send_body(204)
            threading.Thread(
                target=deliver_callback,
                args=(request["callbackUrl"], callback),
                daemon=True,
            ).start()
            return
        self.send_body(200, body, {
            "Content-Type": self.headers.get("content-type", "application/octet-stream"),
            "X-Seen-Provider-Token": self.headers.get("x-provider-token", "missing"),
            "X-Seen-Authorization": self.headers.get("authorization", "missing"),
        })

    def log_message(self, _format, *_args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(port_file, "w", encoding="ascii") as handle:
    handle.write(str(server.server_port))
server.serve_forever()
"#
}

fn provider_script() -> &'static str {
    r#"import base64
import json
import sys
import urllib.parse

for line in sys.stdin:
    request = json.loads(line)
    path = urllib.parse.urlsplit(request["url"]).path
    decision = {
        "/provider-deny": "deny",
        "/provider-pass": "pass",
    }.get(path, "allow")
    response = {"id": request["id"], "type": "response", "decision": decision}
    if decision == "allow":
        response["values"] = {"token": "typed-secret"}
    if path == "/provider-replace":
        response["requestBody"] = {
            "encoding": "base64",
            "contentType": "text/plain",
            "data": base64.b64encode(b"provider secret body").decode("ascii"),
        }
    print(json.dumps(response, separators=(",", ":")), flush=True)
"#
}

fn strict_config(
    directory: &Path,
    python: &Path,
    data: SocketAddr,
    control: SocketAddr,
    origin: SocketAddr,
    generation: &str,
) -> String {
    let provider = directory.join("provider.py");
    format!(
        r#"schema_version = 3

[service]
request_timeout = "5s"
shutdown_drain_timeout = "2s"
max_retiring_generations = 2

[control]
bind = "{control}"
base_path = "/_acl-proxy"
request_header_timeout = "1s"
request_body_timeout = "2s"
max_connections = 16
max_request_body_bytes = 65536

[listeners.explicit_http]
bind = "{data}"
http_versions = ["http1"]
request_header_timeout = "2s"
max_connections = 32
max_concurrent_streams = 32

[listeners.explicit_http.connect]
http1 = "deny"

[authorization.callback]
public_url = "http://{control}/_acl-proxy/external-auth/callback"
resume_token_ttl = "3s"
max_pending_operations = 16

[authorization.providers.local]
kind = "process"
command = "{}"
args = ["{}"]
timeout = "2s"
inherit_environment = false
include_headers = ["x-test-input"]
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 65536
max_decoded_request_body_bytes = 65536
max_stdout_line_bytes = 65536
max_pending_requests = 16
restart_backoff = "100ms"
retire_timeout = "6s"

[authorization.providers.local.outputs.token]
kind = "custom_header"
header = "x-provider-token"
required = true

[authorization.providers.approval]
kind = "webhook"
url = "http://{origin}/authorize"
timeout = "3s"
on_failure = "error"
max_request_bytes = 65536
max_response_bytes = 65536

[authorization.providers.approval.outputs.token]
kind = "bearer"
required = true

[credentials]
allowed_custom_headers = ["x-provider-token"]

[redaction.profiles.wire]
replacement = "[MASKED]"
max_body_bytes = 65536
max_decoded_body_bytes = 65536
rules = [{{ literals = ["secret"], payloads = "text" }}]

[observation.logging]
level = "info"
directory = "logs"
console = false

[observation.capture]
events = ["request.allowed", "response.allowed", "request.denied", "response.denied"]
redaction_profile = "wire"
directory = "captures"
filename = "{{requestId}}-{{suffix}}.json"
max_body_bytes = 65536
max_inflight_body_bytes = 33554432
max_pending_records = 64
max_files = 128
max_total_bytes = 16777216

[policy]
default = "deny"

[[policy.rules]]
id = "process"
decision = "delegate"
urls = [
  "http://{origin}/provider-allow",
  "http://{origin}/provider-deny",
  "http://{origin}/provider-pass",
  "http://{origin}/provider-replace",
]
authorization_provider = "local"
redaction_profile = "wire"

[[policy.rules.response_headers]]
operation = "set"
when = "always"
name = "x-generation"
value = "{generation}"

[[policy.rules]]
id = "passed"
decision = "allow"
urls = ["http://{origin}/provider-pass"]

[[policy.rules.response_headers]]
operation = "set"
when = "always"
name = "x-generation"
value = "{generation}"

[[policy.rules]]
id = "webhook"
decision = "delegate"
urls = [
  "http://{origin}/webhook-allow",
  "http://{origin}/webhook-deny",
  "http://{origin}/webhook-error",
  "http://{origin}/webhook-pass",
]
authorization_provider = "approval"

[[policy.rules.response_headers]]
operation = "set"
when = "always"
name = "x-generation"
value = "{generation}"

[[policy.rules]]
id = "webhook-passed"
decision = "allow"
urls = ["http://{origin}/webhook-pass"]

[[policy.rules]]
id = "reload"
decision = "allow"
urls = ["http://{origin}/reload"]

[[policy.rules.response_headers]]
operation = "set"
when = "always"
name = "x-generation"
value = "{generation}"

[safety.loop_detection]
inject = true
header = "x-strict-request-id"
"#,
        python.display(),
        provider.display()
    )
}

fn start_origin(directory: &Path, python: &Path) -> (ChildGuard, SocketAddr) {
    let script = directory.join("origin.py");
    let port_file = directory.join("origin.port");
    let event_file = directory.join("webhook-events.jsonl");
    write_file(&script, origin_script());
    let child = Command::new(python)
        .args([&script, &port_file, &event_file])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start fixture origin");
    let mut guard = ChildGuard::new(child, libc::SIGTERM);
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    let port = loop {
        if let Ok(contents) = fs::read_to_string(&port_file) {
            if let Ok(port) = contents.parse::<u16>() {
                break port;
            }
        }
        assert!(guard.is_running(), "fixture origin exited during startup");
        assert!(Instant::now() < deadline, "fixture origin did not bind");
        std::thread::sleep(Duration::from_millis(20));
    };
    (guard, SocketAddr::from(([127, 0, 0, 1], port)))
}

fn python3_path() -> PathBuf {
    let output = Command::new("python3")
        .args(["-c", "import sys; print(sys.executable)"])
        .output()
        .expect("locate python3 for the process-provider fixture");
    assert!(output.status.success(), "python3 is required for this test");
    PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
}

fn unused_address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn start_proxy(config: &Path) -> ChildGuard {
    let child = Command::new(assert_cmd::cargo::cargo_bin!("acl-proxy"))
        .args(["run", "--config"])
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start acl-proxy");
    ChildGuard::new(child, libc::SIGTERM)
}

fn records_for_url(capture_dir: &Path, url: &str) -> Vec<Value> {
    let Ok(entries) = fs::read_dir(capture_dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read(entry.path()).ok())
        .filter_map(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .filter(|record| record["url"] == url)
        .collect()
}

fn wait_for_records(capture_dir: &Path, url: &str, count: usize) -> Vec<Value> {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    loop {
        let records = records_for_url(capture_dir, url);
        if records.len() >= count {
            return records;
        }
        assert!(
            Instant::now() < deadline,
            "capture records for {url} did not reach {count}: {records:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn strict_runtime_provider_webhook_capture_and_reload_are_live() {
    let directory = TempDir::new().expect("create runtime fixture");
    let python = python3_path();
    write_file(&directory.path().join("provider.py"), provider_script());
    let (_origin_process, origin) = start_origin(directory.path(), &python);
    let data = unused_address();
    let control = unused_address();
    assert_ne!(data, control);
    let config_path = directory.path().join("acl-proxy.toml");
    write_file(
        &config_path,
        &strict_config(directory.path(), &python, data, control, origin, "one"),
    );

    let validation = Command::new(assert_cmd::cargo::cargo_bin!("acl-proxy"))
        .args(["config", "validate", "--config"])
        .arg(&config_path)
        .output()
        .expect("validate strict fixture");
    assert!(
        validation.status.success(),
        "strict fixture must validate: {}",
        String::from_utf8_lossy(&validation.stderr)
    );

    let policy_output = Command::new(assert_cmd::cargo::cargo_bin!("acl-proxy"))
        .args(["policy", "dump", "--format", "json", "--config"])
        .arg(&config_path)
        .output()
        .expect("dump strict fixture policy");
    assert!(
        policy_output.status.success(),
        "strict policy dump failed: {}",
        String::from_utf8_lossy(&policy_output.stderr)
    );
    let policy: Value = serde_json::from_slice(&policy_output.stdout).unwrap();
    let policy_projection: Vec<Value> = policy["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| {
            json!({
                "id": rule["id"],
                "decision": rule["decision"],
                "authorization_provider": rule["authorization_provider"],
                "redaction_profile": rule["redaction_profile"],
            })
        })
        .collect();
    assert_eq!(policy["default"], "deny");
    assert_eq!(
        Value::Array(policy_projection),
        json!([
            {
                "id": "process",
                "decision": "delegate",
                "authorization_provider": "local",
                "redaction_profile": "wire"
            },
            {
                "id": "passed",
                "decision": "allow",
                "authorization_provider": null,
                "redaction_profile": null
            },
            {
                "id": "webhook",
                "decision": "delegate",
                "authorization_provider": "approval",
                "redaction_profile": null
            },
            {
                "id": "webhook-passed",
                "decision": "allow",
                "authorization_provider": null,
                "redaction_profile": null
            },
            {
                "id": "reload",
                "decision": "allow",
                "authorization_provider": null,
                "redaction_profile": null
            }
        ])
    );

    let mut proxy = start_proxy(&config_path);
    wait_for_ready(&mut proxy, control);
    let readiness = control_request(control, "/_acl-proxy/ready");
    assert_eq!(readiness.status, 200);
    assert_eq!(readiness.header("cache-control"), Some("no-store"));
    assert_eq!(readiness.body, br#"{"status":"ready"}"#);

    let data_ready = proxy_request(data, "GET", &format!("http://{data}/_acl-proxy/ready"), &[]);
    assert_ne!(data_ready.status, 200, "data listener exposed readiness");
    let data_callback = proxy_request(
        data,
        "POST",
        &format!("http://{data}/_acl-proxy/external-auth/callback"),
        br#"{}"#,
    );
    assert_ne!(data_callback.status, 204, "data listener exposed callbacks");

    let allow_url = format!("http://{origin}/provider-allow");
    let allow = proxy_request(data, "GET", &allow_url, &[]);
    assert_eq!(allow.status, 200);
    assert_eq!(allow.header("x-seen-provider-token"), Some("typed-secret"));
    assert_eq!(allow.header("x-generation"), Some("one"));

    let deny_url = format!("http://{origin}/provider-deny");
    assert_eq!(proxy_request(data, "GET", &deny_url, &[]).status, 403);

    let pass_url = format!("http://{origin}/provider-pass");
    let pass = proxy_request(data, "GET", &pass_url, &[]);
    assert_eq!(pass.status, 200);
    assert_eq!(pass.header("x-seen-provider-token"), Some("missing"));

    let replace_url = format!("http://{origin}/provider-replace");
    let replaced = proxy_request(data, "POST", &replace_url, b"client body");
    assert_eq!(replaced.status, 200);
    assert_eq!(
        replaced.header("x-seen-provider-token"),
        Some("typed-secret")
    );
    assert_eq!(replaced.body, b"provider [MASKED] body");

    let webhook_allow_url = format!("http://{origin}/webhook-allow");
    let webhook_allow = proxy_request(data, "POST", &webhook_allow_url, b"webhook allow body");
    assert_eq!(webhook_allow.status, 200);
    assert_eq!(
        webhook_allow.header("x-seen-authorization"),
        Some("Bearer webhook-typed-secret")
    );
    assert_eq!(
        webhook_allow.header("x-seen-provider-token"),
        Some("missing")
    );
    assert_eq!(webhook_allow.body, b"webhook allow body");

    let webhook_pass_url = format!("http://{origin}/webhook-pass");
    let webhook_pass = proxy_request(data, "POST", &webhook_pass_url, b"webhook pass body");
    assert_eq!(webhook_pass.status, 200);
    assert_eq!(webhook_pass.header("x-seen-authorization"), Some("missing"));
    assert_eq!(
        webhook_pass.header("x-seen-provider-token"),
        Some("missing")
    );
    assert_eq!(webhook_pass.body, b"webhook pass body");

    let webhook_deny_url = format!("http://{origin}/webhook-deny");
    assert_eq!(
        proxy_request(data, "GET", &webhook_deny_url, &[]).status,
        403
    );
    let webhook_error_url = format!("http://{origin}/webhook-error");
    assert_eq!(
        proxy_request(data, "GET", &webhook_error_url, &[]).status,
        500
    );
    let webhook_events = directory.path().join("webhook-events.jsonl");
    wait_for_file(&webhook_events);
    let events: Vec<Value> = fs::read_to_string(&webhook_events)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 4);
    assert_eq!(
        events
            .iter()
            .map(|event| event["url"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            webhook_allow_url.as_str(),
            webhook_pass_url.as_str(),
            webhook_deny_url.as_str(),
            webhook_error_url.as_str(),
        ]
    );
    assert!(events.iter().all(|event| event["type"] == "request"));
    assert!(events
        .iter()
        .all(|event| event.get("body").is_none() && event.get("requestBody").is_none()));
    let callback_url = format!("http://{control}/_acl-proxy/external-auth/callback");
    assert!(events
        .iter()
        .all(|event| event["callbackUrl"] == callback_url));
    assert!(events.iter().all(|event| event["resumeToken"]
        .as_str()
        .is_some_and(|token| token.len() == 43)));

    let captures = wait_for_records(&directory.path().join("captures"), &replace_url, 2);
    let request = captures
        .iter()
        .find(|record| record["kind"] == "request")
        .expect("replacement request capture");
    assert_eq!(request["decision"], "allow");
    assert_eq!(request["mode"], "http_proxy");
    assert_eq!(request["method"], "POST");
    assert!(request["body"].is_null());
    assert_eq!(request["providerReplacementOmitted"], true);
    assert_eq!(request["providerReplacementSize"], 20);
    let response = captures
        .iter()
        .find(|record| record["kind"] == "response")
        .expect("replacement response capture");
    let captured_body = BASE64_STANDARD
        .decode(response["body"]["data"].as_str().unwrap())
        .unwrap();
    assert_eq!(captured_body, b"provider [MASKED] body");

    let reload_url = format!("http://{origin}/reload");
    let mut keepalive = connect(data);
    let before = send_request(
        &mut keepalive,
        "GET",
        &reload_url,
        &origin.to_string(),
        &[],
        &[],
        false,
    );
    assert_eq!(before.status, 200);
    assert_eq!(before.header("x-generation"), Some("one"));

    let replacement_path = directory.path().join("acl-proxy.next.toml");
    write_file(
        &replacement_path,
        &strict_config(directory.path(), &python, data, control, origin, "two"),
    );
    fs::rename(&replacement_path, &config_path).expect("publish reload config");
    assert_eq!(
        unsafe { libc::kill(proxy.id() as libc::pid_t, libc::SIGHUP) },
        0
    );
    wait_for_file_text(
        &directory.path().join("logs/acl-proxy.log"),
        "configuration reload completed successfully",
    );

    let after = send_request(
        &mut keepalive,
        "GET",
        &reload_url,
        &origin.to_string(),
        &[],
        &[],
        false,
    );
    assert_eq!(after.status, 200);
    assert_eq!(after.header("x-generation"), Some("two"));
    let new_connection = proxy_request(data, "GET", &reload_url, &[]);
    assert_eq!(new_connection.status, 200);
    assert_eq!(new_connection.header("x-generation"), Some("two"));
    assert_eq!(control_request(control, "/_acl-proxy/ready").status, 200);

    let status = proxy.terminate();
    assert!(status.success(), "acl-proxy shutdown failed: {status}");
    std::net::TcpListener::bind(data).expect("data listener was not released");
    std::net::TcpListener::bind(control).expect("control listener was not released");
}
