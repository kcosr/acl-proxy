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
Every data listener uses a typed `endpoint`. The legacy scalar `bind` field is
not accepted.

| Section | Ingress |
| --- | --- |
| `listeners.explicit_http` | Cleartext explicit proxy requests; optional HTTP/1 CONNECT MITM |
| `listeners.transparent_http` | Redirected origin-form cleartext HTTP |
| `listeners.explicit_https` | TLS-wrapped explicit proxy using a static server identity |
| `listeners.transparent_https` | Redirected TLS using the configured MITM authority |

```toml
[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]
request_header_timeout = "10s"
max_connections = 1024
max_concurrent_streams = 128

[listeners.explicit_http.connect]
http1 = "deny" # deny | mitm
```

Transparent HTTP and HTTPS listeners may instead accept a Unix stream carrying
one strict PROXY Protocol v2 IPv4/STREAM preface followed by the untouched TCP
stream:

```toml
[listeners.transparent_http]
endpoint.kind = "unix_proxy_v2"
endpoint.path = "/Users/your-user/Library/Application Support/AW Gateway/runtime/transparent-http.sock"
endpoint.mode = "0606"
proxy_header_timeout = "1s"
http_versions = ["http1"]
```

The workstation host path must be inside a user-writable runtime directory
owned by the workstation user and protected with mode `0700`; the placeholder
above must be replaced with that user's actual home path. Mode `0606` is
deliberate for Apple Container's root-owned guest endpoint mapping. Other Unix
deployments should select the narrowest socket mode compatible with their relay
account.

The path must be absolute. ACL Proxy refuses every pre-existing path and never
unlinks it. For a socket owned by the current user, a bounded liveness probe
only improves the diagnostic: live, busy, and indeterminate sockets report
`AddrInUse`, while a refused connection identifies a stale socket that must be
removed explicitly. Symlinks, non-sockets, sockets owned by another user, and
other probe failures are rejected.

ACL Proxy prepares the socket and its mode under a private same-directory name,
then atomically publishes it without replacing an occupied final path. Linux
uses `renameat2(RENAME_NOREPLACE)` and Apple platforms use
`renameatx_np(RENAME_EXCL)`; Unix targets without a supported no-replace
primitive reject this listener kind. The lifetime lock coordinates ACL Proxy
instances, but is not a security boundary against other processes running as
the same trusted workstation user.

ACL Proxy deliberately does not unlink the final path during shutdown because
POSIX has no atomic compare-inode-and-unlink operation. The service supervisor
or operator must remove the socket after the proxy has exited and released its
lock, before starting it again. This is also required after a later startup
stage fails following socket publication. The immediate parent must already
exist as a real directory owned by the workstation user with no group or other
permission bits (normally mode `0700`).

Unix-PROXY-v2 ingress represents one local workstation principal. The asserted
PROXY source is discarded, the effective client is loopback and local for quota
purposes, and configurations using this transport may not contain
`client_cidrs` predicates. The validated original destination is retained;
transparent HTTP accepts destination port 80 and transparent HTTPS accepts
port 443. This transport is available on supported Unix hosts. The companion
`acl-proxy-transparent-uds-relay` artifact is Linux-only because it retrieves
`SO_ORIGINAL_DST` from redirected TCP connections.

Run the relay with its separate strict JSON configuration:

```bash
acl-proxy-transparent-uds-relay --config /etc/acl-proxy/transparent-uds-relay.json
```

See `examples/transparent-uds-relay.json` for the complete schema and
`examples/acl-proxy-transparent-uds.toml` for the paired host listeners. Relay
listener addresses must be unprivileged IPv4 loopback addresses. Route names,
listeners, original-port sets, and Unix paths are unique. `setupTimeout` covers
both the Unix connection and complete PROXY preface write. `maxConnections` is
global across routes, and the relay validates its projected file descriptors
and `maxConnections * 2 * copyBufferBytesPerDirection` memory before binding.
The relay never parses HTTP or TLS and has no TCP egress fallback.
The shipped host example requires TLS parent-proxy egress; it does not silently
fall back to direct origin access.

Repository tests cover the relay-to-ACL HTTP artifact boundary through an
injected original-destination seam and cover TLS MITM on the Unix listener.
Kernel `SO_ORIGINAL_DST`/iptables netns behavior and the complete
TLS/HTTP2/WebSocket topology remain the T04 AW Gateway cross-repository release
gates because they require the privileged Linux redirect environment and the
Apple host socket relay.

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

Every candidate activation loads and validates one bounded snapshot of the
native system trust store, then binds that exact typed root set into the shared
runtime snapshot. This is deliberate even when the candidate's configured
routes currently use only custom trust, insecure TLS, or cleartext: activation
fails if the native trust store cannot be loaded, and request paths never
reload or reinterpret it.

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
active generation. Ambient environment inheritance is off by default. A
relative `command` resolves from the configuration directory, the child uses
that directory as its working directory, and relative arguments therefore
resolve there as well. The child environment is cleared and rebuilt from
`pass_environment` and literal `environment` entries unless
`inherit_environment = true` is explicitly selected; inheritance emits a
startup warning. Every passed name must exist, and a name cannot also be a
literal entry.

```toml
[authorization.providers.repo_acl]
kind = "process"
command = "/usr/bin/python3"
args = ["providers/repo_acl.py", "--config", "providers/repo_acl.json"]
timeout = "1s"
on_failure = "deny"
inherit_environment = false
pass_environment = []
environment = { PATH = "/usr/bin:/bin" }
include_headers = ["x-workload-id"]
include_request_body = true
allow_request_body_replacement = true
max_request_body_bytes = 10485760
max_decoded_request_body_bytes = 52428800
max_stdout_line_bytes = 1048576
max_pending_requests = 128
restart_backoff = "1s"
retire_timeout = "30s"

[authorization.providers.repo_acl.outputs.access_token]
kind = "bearer"
transport_security = "tls_required"
required = true

[[policy.rules]]
id = "delegate-repositories"
decision = "delegate"
urls = ["https://git.example.test/**"]
authorization_provider = "repo_acl"
```

Each stdin request is one compact JSON object followed by LF. The fixed fields
are `id`, `requestId`, `type`, `url`, `method`, and `clientIp`; `headers` and
`body` are present only when selected by the provider configuration. Header
names are lowercase and each array preserves duplicate field order. An
included body contains decoded bytes, never content-coded bytes:

```json
{"id":"<dispatch-id>","requestId":"<request-id>","type":"request","url":"https://git.example.test/project","method":"POST","clientIp":"192.0.2.10","headers":{"x-workload-id":["runner-1"]},"body":{"encoding":"base64","contentType":"application/json","contentEncoding":"identity","data":"e30="}}
```

`requestId` is the stable request identifier. `id` is a fixed-width correlation
identifier for one dispatch in one child epoch, and the provider must echo it.
Responses are one JSON object followed by LF or CRLF. The response `id` must be
the first member so the bounded reader can assign the response before admitting
the remaining bytes. Before and within that prefix, only bounded ASCII space or
horizontal tab is accepted between the `{`, `"id"`, colon, and opening value
quote. After the closing ID quote, ordinary single-line JSON whitespace is
accepted. `type` and `decision` may appear in either order; both must precede an
optional `values` object, and an optional `requestBody` must be last. This means
ordinary serializers work when `id` is inserted first.

An allow response may return values only for names declared under the
provider's `outputs` table. Every output has a fixed credential kind,
destination, required flag, and `transport_security`; the response cannot
choose those properties dynamically:

```json
{"id":"<dispatch-id>","type":"response","decision":"allow","values":{"access_token":"fixture-value"}}
```

When body replacement is enabled, `requestBody` uses base64 data with optional
validated content metadata. `contentEncoding`, when present, must be
`identity`:

```json
{"id":"<dispatch-id>","decision":"allow","type":"response","values":{"access_token":"fixture-value"},"requestBody":{"encoding":"base64","contentType":"application/json","contentEncoding":"identity","data":"e30="}}
```

`deny` and `pass` forbid `values` and `requestBody`. Unknown or duplicate
non-ID members, undeclared values, missing required values, invalid material,
and unapproved body replacement fail closed. A syntactically complete response
with a live assigned ID fails only that request when its shape is invalid. A
repeated, unusable, or unsolicited ID, malformed framing, invalid UTF-8, or a
line over the configured bound makes the child epoch fatal and fails every
unanswered request without replay.

Candidate activation eagerly starts one child per process provider, and every
successful reload starts a fresh child even when its configuration is
unchanged. A child observed exited by the publication liveness check rejects
the candidate. After a clean active-generation exit, complete responses
already written to stdout are given up to the one-second cleanup grace to
drain; unanswered requests then fail, without replay. While the generation
remains active, a replacement is attempted after `restart_backoff`, and a
failed spawn schedules another attempt after the same backoff.
Retiring generations keep their own child only while admitted work may finish,
bounded by `retire_timeout`.

On Unix, each provider is placed in its own process group. Controlled cleanup
sends `SIGTERM` to the group, retains the unreaped leader for a one-second grace
period when needed, then sends `SIGKILL`. If the leader is already observed
exited, remaining group members receive `SIGKILL` immediately. These guarantees
cover members that remain in the owned process group; a child that deliberately
detaches into another process group is outside that authority.

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
unsupported_extensions = "deny" # deny | strip

[[redaction.profiles.sensitive.rules]]
literals = ["safe-fixture-literal"]
literal_environment_variables = ["REDACT_SECRET_A", "REDACT_SECRET_B"]
expressions = ["token-[A-Za-z0-9_.-]{20,}"]
payloads = "text"
```

Protected WebSocket upgrades validate extension offers before contacting the
origin. `deny` rejects a well-formed but unsupported offer, while `strip`
removes all `Sec-WebSocket-Extensions` fields and establishes an uncompressed
connection. Malformed extension syntax always fails closed. Compression is
forwarded only when `allow_permessage_deflate = true` and both peers negotiate
the supported no-context-takeover subset.

Complete HTTP bodies are classified as text only when they are valid UTF-8;
otherwise they are binary. Text-only literals and every expression are skipped
for a binary body, while literals configured with `payloads = "both"` still
apply. If a selected wire-redaction profile contains any protection that
requires text classification, a binary body fails closed instead of being
forwarded with that protection skipped. Best-effort capture under such a
profile keeps the metadata but omits the body with
`bodyOmission.reason = "text_protections_skipped"`.

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
Visible UTF-8 header values pass through the active capture redaction profile;
non-UTF-8 values and values that cannot be redacted within the configured
bounds are omitted.

Every persisted record contains exactly one of `body` or `bodyOmission`.
`bodyOmission.reason` is `empty`, `incomplete`, `limit_exceeded`,
`resource_exhausted`, `decoding_failed`, `redaction_failed`,
`text_protections_skipped`, `artifact_encoding_failed`,
`head_preparation_failed`, or `provider_replacement`; provider replacement also
records its bounded `size`. Nonempty forwarded trailers are represented by
`trailersOmitted = true` because trailer values are not serialized. When a
stored body is a redacted prefix, `bodyTruncated = true` and `body.length`
retains the complete redacted length. `acl-proxy-extract-capture-body` still
emits that prefix and writes a truncation warning to standard error.

All HTTP ingress paths, including requests decrypted inside CONNECT MITM,
serialize capture `mode` as `http_proxy`.

## Operations

Validate and inspect before startup:

```bash
acl-proxy config validate --config /etc/acl-proxy/acl-proxy.toml
acl-proxy policy dump --format table --config /etc/acl-proxy/acl-proxy.toml
```

`SIGHUP` compiles and activates a complete reloadable generation. Invalid TOML,
an invalid schema, activation failure, or a rejected static change leaves the
current generation published and readiness unchanged; a later corrected reload
can publish normally. Static listener, control, filesystem ownership, and
process-wide resource changes are rejected as static changes.

`SIGINT` and `SIGTERM` initiate joined graceful shutdown and continue to be
polled while admitted work drains within `service.shutdown_drain_timeout`.
`SIGHUP` is ignored after shutdown begins. A second `SIGINT` or `SIGTERM`
abandons the graceful wait and forces prompt process termination.

Configured sockets are reserved during static preparation, but proxy listeners
cannot start admitting data-plane work until the initial generation has
published. Readiness is HTTP 200 only after static resources, proxy
supervisors, and that initial generation are all active. It changes to HTTP 503
before initial publication and during shutdown, and uses
`Cache-Control: no-store`.

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
