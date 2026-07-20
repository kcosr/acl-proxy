# acl-proxy

`acl-proxy` is a strict, policy-controlled HTTP and HTTPS egress proxy. It
supports explicit and transparent listeners, HTTP/1 CONNECT interception,
ordered allow/deny/delegate policy, process and webhook authorization
providers, typed credentials, bounded body handling, and generation-safe
reloads.

The only accepted configuration contract is integer `schema_version = 3`.
Older schemas and mixed v2/v3 shapes are rejected; there is no compatibility
parser or migration mode.

## Install

Release archives contain `acl-proxy`, the capture-body extraction helper, this
README, `LICENSE`, `THIRD_PARTY_NOTICES`, and `acl-proxy.sample.toml`. To build
locally:

```text
acl-proxy-<version>-<acl12>/
  bin/acl-proxy
  bin/acl-proxy-extract-capture-body
  README.md
  LICENSE
  THIRD_PARTY_NOTICES
  acl-proxy.sample.toml
```

`<version>` is the exact Cargo package version and `<acl12>` is the first 12
lowercase hexadecimal characters of the packaged `acl-proxy` commit. That
directory is the archive root, and the two executables are its only `bin/`
entries.

The `0.3.0-rc.1` candidate requires `schema_version = 3`; configurations for
the `0.2.x` contract must be rewritten rather than migrated through aliases or
fallback parsing. This local candidate is validated for build and runtime on
Linux x86_64 and for compilation on Linux aarch64. macOS arm64 and Windows MSVC
x86_64 have not been validated because suitable hosts are unavailable.

```bash
cargo build --release --locked
```

The executable is then `target/release/acl-proxy`.

## Quick Start

Create a new deny-by-default loopback configuration:

```bash
acl-proxy config init ./acl-proxy.toml
acl-proxy config validate --config ./acl-proxy.toml
acl-proxy run --config ./acl-proxy.toml
```

`config init` never overwrites an existing file. `config validate` and
`policy dump` parse and compile without binding listeners, resolving secret
sources, or starting providers.

The generated template enables an explicit HTTP data listener on
`127.0.0.1:8881` and denies every request. It does not enable a control
listener. The shipped sample adds a dedicated loopback control listener on
`127.0.0.1:8898`:

```bash
curl --fail http://127.0.0.1:8898/_acl-proxy/ready
# {"status":"ready"}
```

Readiness and authorization callbacks exist only on the control listener.
Data-plane listeners never serve `/_acl-proxy/*` control routes.

To make an explicit HTTP request after adding a matching allow rule:

```bash
curl --proxy http://127.0.0.1:8881 http://example.test/resource
```

## Architecture

This repository owns the product shell: strict schema-3 compilation, listener
binding and OS integration, authorization/provider and credential-I/O adapters,
capture/logging sinks, reload and signal policy, CLI, samples, and packaging.
The sibling `access-runtime` repository owns canonical URLs, ACL/redaction and
credential cores, forwarding, listeners, MITM, HTTP serving, and WebSocket
relay. `src/proxy` contains only the product forwarding, observation, and
private-field adapters into that shared runtime; it is not a second proxy
engine.

The Rust library surface is intentionally small. It exposes the capture
artifact format used by the extraction helper and one `run() -> ExitCode`
process entry. CLI parser and operational error types are private, and the
exact surface is checked against `public-api.txt`.

## Configuration

All unknown fields are errors. Relative filesystem paths resolve from the
directory containing the selected configuration file.

### Service And Control

```toml
schema_version = 3

[service]
request_timeout = "30s"
shutdown_drain_timeout = "30s"
max_retiring_generations = 2

[control]
bind = "127.0.0.1:8898"
base_path = "/_acl-proxy"
request_header_timeout = "10s"
request_body_timeout = "10s"
max_connections = 128
max_request_body_bytes = 65536
```

The control bind must be a non-wildcard address and must not overlap a proxy
listener. Omit `[control]` when readiness and callback HTTP endpoints are not
needed.

### Listeners

Listener sections are independent; omitted listeners are disabled.

| Section | Ingress |
| --- | --- |
| `listeners.explicit_http` | Cleartext explicit proxy requests; optional HTTP/1 CONNECT MITM |
| `listeners.transparent_http` | Redirected origin-form cleartext HTTP |
| `listeners.explicit_https` | TLS-wrapped explicit proxy using a static server identity |
| `listeners.transparent_https` | Redirected TLS using the configured MITM authority |

```toml
[listeners.explicit_http]
bind = "127.0.0.1:8881"
http_versions = ["http1"]
request_header_timeout = "10s"
max_connections = 1024
max_concurrent_streams = 128

[listeners.explicit_http.connect]
http1 = "deny" # deny | mitm
```

HTTP/2 CONNECT is intentionally deny-only. Enabling `http1 = "mitm"` or a
transparent HTTPS listener requires `[mitm]`:

```toml
[mitm]
mode = "generated"
directory = "runtime/certs"
max_cached_certificates = 1024
persist_leaf_certificates = false
```

Each admitted connection on an HTTP/1-capable listener owns one fallibly
allocated, zeroizing 64 KiB validation buffer. The allocation is bounded by
that listener's `max_connections`; HTTP/2-only connections do not allocate it.
The validator checks request framing before Hyper can dispatch policy,
credential, or destination work.

Generated CA material is private process state with no stable internal file
names. Export only its public certificate chain to a new caller-selected file:

```bash
acl-proxy --config /etc/acl-proxy/acl-proxy.toml export-ca --output ./acl-proxy-ca.pem
```

The command never overwrites an existing file and cannot write inside the
private generated-storage directory. The output parent must already exist, be
owned by the effective user, and have neither its group-write nor other-write
permission bit set; use `chmod go-w <directory>` before export when necessary.
The command fails closed when this ownership and permission requirement is not
met. It is supported on Unix; other platforms fail before touching generated
storage or the output path. File-backed mode uses explicit `ca_certificate` and
`ca_private_key` paths. The certificate file may contain an ordered PEM CA
chain: its first certificate must match the private key and be CA-capable, and
the complete chain is served with generated leaf certificates. Private keys
must not grant group or other access. Generated leaf certificates use a
30-day validity window clamped to the signing CA. When leaf persistence is
enabled, the dynamic directory retains at most `max_cached_certificates`
distinct host certificate/key/chain sets and prunes older sets on startup and
runtime generation. Persisted sets use opaque SHA-256 host keys and distinct
leaf, private-key, and chain suffixes so valid hostnames cannot collide in the
managed directory.

### Egress

Direct egress is the default. TLS trust and protocol selection are explicit:

```toml
[egress]
route = "direct"

[egress.origin_tls]
trust = "system" # system | custom | system_plus_custom | insecure
http_versions = ["http1", "http2"]
```

For a parent proxy:

```toml
[egress]
route = "parent_proxy"

[egress.parent_proxy]
kind = "acl_proxy" # acl_proxy | generic
url = "http://parent-proxy.example.test:8881"
```

Parent endpoints may not resolve to loopback, a local interface, a data
listener, or the control listener. DNS results are pinned and revalidated
before and after connect.

### Policy

Rules are evaluated in authored order. A matched allow or deny is terminal. A
delegate rule calls its provider; `pass` resumes at the next rule. The policy
default applies only when no later rule matches.

```toml
[policy]
default = "deny"

[[policy.rules]]
id = "allow-example-get"
description = "Read-only example access"
decision = "allow"
urls = ["https://api.example.test/v1/**"]
methods = ["GET", "HEAD"]
client_cidrs = ["192.0.2.0/24"]

[policy.rules.headers]
present_all = ["x-workload-id"]
none = { x-blocked = ["true"] }
```

Every rule requires a stable, unique `id` and a `decision`. An empty `urls`
list means every canonical HTTP/HTTPS URL, subject to the other predicates.

URL patterns are component aware:

- `*` as a hostname label matches exactly one DNS label.
- `**` as a hostname label matches one or more DNS labels.
- `*` inside a hostname label is label-local and never crosses a dot.
- Hostname wildcards match DNS names only; IP addresses require exact IPv4 or
  IPv6 patterns.
- `**` in a path or query is the recursive component wildcard.
- A whole pattern of `**` matches every canonical HTTP/HTTPS URL.
- Query text is matched as an opaque, ordered string. Duplicate keys and their
  order are significant, and a pattern without a query ignores the request
  query.
- Scheme and port are exact; list HTTP and HTTPS separately when both are
  intended.

Upgrades are denied unless every matched allow/delegate cursor explicitly sets
`allow_upgrades = true`. The default allow decision never authorizes an
upgrade.

### Authorization Providers

Process providers exchange bounded newline-delimited JSON and are owned by the
active generation. Ambient environment inheritance is off by default.

Process response framing is intentionally stricter than general JSON member
ordering: `id` must be the first member. Bounded spaces or horizontal tabs are
accepted only before the opening `{` and between `{`, `"id"`, the colon, and
the opening value quote. Standard serializers work when they preserve `id` as
the first inserted member; arbitrary member order and whitespace elsewhere do
not.

```toml
[authorization.providers.repo_acl]
kind = "process"
command = "/usr/bin/python3"
args = ["providers/repo_acl.py", "--config", "providers/repo_acl.json"]
timeout = "1s"
on_failure = "deny"
inherit_environment = false
environment = { PATH = "/usr/bin:/bin" }
include_headers = ["x-workload-id"]
include_request_body = false
allow_request_body_replacement = false
max_pending_requests = 128
restart_backoff = "1s"
retire_timeout = "30s"

[[policy.rules]]
id = "delegate-repositories"
decision = "delegate"
urls = ["https://git.example.test/**"]
authorization_provider = "repo_acl"
```

Webhook providers require a control listener and a canonical public callback
URL. Control routes are never exposed by a data listener.

#### Outer CONNECT Decisions

When an HTTP/1 CONNECT is selected for MITM, a matching delegated policy rule
still calls its process or webhook provider before the tunnel is established.
This synthetic outer request is decision-only: the provider request has
`method = "CONNECT"`, uses the canonical HTTPS root URL for the CONNECT
authority, and never contains a body, even when the provider is configured
with `include_request_body = true`.

The provider must return only `allow`, `deny`, or `pass`. An `allow` response
must not contain `values` or `requestBody`; effect-bearing responses are invalid
and fail the CONNECT closed. For example, a process provider returns:

```json
{"id":"<request-id>","type":"response","decision":"allow"}
```

A webhook callback follows the same decision-only rule while retaining its
normal `resumeToken` envelope. Providers that normally emit credential values
should branch on `method = "CONNECT"` and return a bare decision for this
invocation. The decrypted inner request is planned and authorized separately
with normal body, required-output, credential, and replacement semantics.

### Credentials

Credential sources are named and typed. Secret values are resolved only at the
credential boundary and are not accepted as generic string interpolation.

```toml
[credentials]
allowed_custom_headers = ["x-workload-token"]

[credentials.sources.workload]
source = "environment"
variable = "WORKLOAD_TOKEN"

[[egress.credential_actions]]
kind = "custom_header"
transport_security = "tls_required"
header = "x-workload-token"
credential = "workload"
```

A credential action replaces all attacker-supplied values at its destination.
Missing, empty, invalid, or oversized credential material fails closed.
Every credential action and authorization-provider output must declare exactly
one `transport_security` value: `tls_required` or `cleartext_allowed`. There is
no default or compatibility spelling. An allow/delegate rule that can reach an
HTTP origin is rejected unless every effective global action, rule action, and
selected-provider output explicitly uses `cleartext_allowed`; URL-less rules
and `**` are HTTP-reachable. A default-allow policy applies the same requirement
to global actions. HTTPS origin requests remain protected when routed through
an HTTP parent proxy, so their credentials may remain `tls_required`.

### Header Effects

Request and response effects can be attached to rules; global request effects
live under `egress.request_headers`.

```toml
[[egress.request_headers]]
operation = "remove"
when = "always"
name = "x-internal-context"

[[policy.rules.response_headers]]
operation = "set"
when = "always"
name = "cache-control"
value = "no-store"
```

Credential destination headers and reserved hop/control headers cannot be
mutated with literal effects.

### Redaction And Capture

Redaction profiles apply to normalized outbound HTTP bodies and protected
client-to-upstream WebSocket messages. Environment-backed secret literals use
an explicit typed list; `${NAME}` interpolation is not supported.

For protected WebSocket traffic, text and binary application data is redacted
before forwarding. Ping and pong payloads are treated as binary application
data, while close reasons are treated as text; close status codes are
preserved. Every resulting control frame remains within the protocol's
125-byte payload limit.

An established WebSocket keeps the wire-redaction matcher selected when the
stream was authorized. Observation capture is independent: it selects the
current capture epoch at the first frame of each logical message and keeps that
epoch through the message's final frame. A reload therefore never splits a
fragmented message, while the next message can use updated capture settings or
redaction without changing the stream's authorized wire behavior.

```toml
[redaction.profiles.sensitive]
replacement = "[REDACTED]"
max_body_bytes = 10485760
max_decoded_body_bytes = 52428800
max_frame_bytes = 262144
max_message_bytes = 1048576
allow_permessage_deflate = false

[[redaction.profiles.sensitive.rules]]
literals = ["safe-fixture-literal"]
literal_environment_variables = ["REDACT_SECRET_A", "REDACT_SECRET_B"]
expressions = ["token-[A-Za-z0-9_.-]{20,}"]
payloads = "text"
```

Every listed environment variable is required during activation and reload.
Its name and value are excluded from dumps, logs, captures, and diagnostics.

Destination semantic preflight failures are fail-closed policy outcomes. They
are audited as `InvalidPlan` and return a sanitized HTTP 403 because no DNS,
dial, or transport attempt has begun; HTTP 502 and 503 remain transport and
availability failures.

Policy decision logging is reloadable with the observation snapshot. Decision
events are disabled for allows and enabled for denies by default; their event
levels accept only `info` or `warn`.

```toml
[observation.logging.policy_decisions]
allows = false
denies = true
allow_level = "info"
deny_level = "warn"
```

Each selected final decision is submitted without waiting to a bounded static
INFO or WARN worker. The structured target is `acl_proxy::policy`, the message
is `policy decision`, and the fields are `request_id`, `allowed`, sink-safe
`url`, `method`, `client_ip`, `generation`, `effective_policy`,
`reason_category`, `reason_code`, `trace_id`, and
`sensitive_header_presence`. Missing pre-policy fields are empty;
`effective_policy` is `default` or `<rule-id>#<zero-based-ordinal>`. Sensitive
header presence is canonical, sorted, comma-separated names without values.
Queue saturation, closure, or sink failure only omits the operational event.

Capture is optional and bounded. It requires a redaction profile:

```toml
[observation.capture]
events = ["request.denied", "response.denied"]
redaction_profile = "sensitive"
directory = "runtime/captures"
filename = "{requestId}-{suffix}.json"
max_body_bytes = 1048576
max_inflight_body_bytes = 134217728
max_pending_records = 1024
max_files = 10000
max_total_bytes = 1073741824
```

Selected `response.allowed` capture also records sanitized listener-generated
forwarding failures. The 500, 502, 503, or 504 status and pre-redaction fixed
body come from the listener's authoritative mapping; persisted headers and body
remain subject to the configured capture redaction and omission policy.
Incomplete request or upstream response captures remain abandoned.

All HTTP ingress paths, including requests decrypted inside CONNECT MITM,
serialize capture `mode` as `http_proxy`.

## Operations

Validate and inspect before startup:

```bash
acl-proxy config validate --config /etc/acl-proxy/acl-proxy.toml
acl-proxy policy dump --format table --config /etc/acl-proxy/acl-proxy.toml
```

`SIGHUP` compiles and activates a complete reloadable generation. A failed
reload leaves the current generation published. Static listener, control,
filesystem ownership, and process-wide resource changes are rejected as static
changes. `SIGINT` and `SIGTERM` initiate joined graceful shutdown.

Readiness is HTTP 200 only after static resources, proxy supervisors, and the
initial generation are all active. It changes to HTTP 503 while not ready and
uses `Cache-Control: no-store`.

## Smoke Tests

The ordinary local smoke is unprivileged and creates only private temporary
files and loopback listeners:

```bash
scripts/loopback-smoke.sh
```

It builds or uses `ACL_PROXY_BIN`, validates generated strict v3 config, probes
readiness on the control listener, proves the data listener does not serve
readiness, tests deny/allow HTTP and CONNECT/TLS, and checks graceful shutdown.

The production topology smoke is intentionally opt-in because it creates Linux
network namespaces, veth devices, a bridge, and namespace-local redirect rules:

```bash
sudo ACL_PROXY_RUN_PRODUCTION_TOPOLOGY=1 \
  scripts/production-topology-smoke.sh
```

Prerequisites are Linux, root, `ip` with network-namespace support, `iptables`,
`curl`, `openssl`, `python3`, and a non-conflicting `198.18.0.0/15` benchmark
route. The script uses only sanitized fixture identities and one-run synthetic
secrets. It never reads production files or broker configuration.

## Development

On a fresh machine, provision the RustSec advisory database and check the
crates.io index for yanked packages once before running the offline ownership
gate:

```bash
cargo audit --deny warnings
```

```bash
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
scripts/check-ownership.sh
```

Repository-local agent instructions are in `AGENTS.md`. Detailed design and
implementation records are under `docs/implementation/`.

## License

MIT. See `LICENSE`. Dependency attribution and license notices are in
`THIRD_PARTY_NOTICES`.
