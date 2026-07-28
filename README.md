# acl-proxy

`acl-proxy` is a strict, policy-controlled HTTP and HTTPS egress proxy. It
supports explicit and transparent listeners, HTTP/1 CONNECT interception,
ordered allow/deny/delegate policy, process and webhook authorization
providers, typed credentials, bounded body handling, and generation-safe
reloads.

The only accepted configuration contract is integer `schema_version = 4`.
Every older schema and mixed shape is rejected; there is no compatibility
parser or migration mode.

## Install

Release archives contain `acl-proxy`, the capture-body extraction helper, this
README, `LICENSE`, `THIRD_PARTY_NOTICES`, and `acl-proxy.sample.toml`. Linux
archives also contain the Linux-only Access Flow relay. To build locally:

The current local candidate contains only
`acl-proxy-<version>-<acl12>-linux-x86_64.tar.gz`. The planned filename for a
future native-host-validated macOS ARM64 archive is
`acl-proxy-<version>-<acl12>-macos-arm64.tar.gz`; no macOS archive is built or
included in this candidate.

```text
acl-proxy-<version>-<acl12>/
  bin/acl-proxy
  bin/acl-proxy-extract-capture-body
  bin/acl-proxy-access-flow-relay  # Linux archives only
  README.md
  LICENSE
  THIRD_PARTY_NOTICES
  acl-proxy.sample.toml
```

`<version>` is the exact Cargo package version and `<acl12>` is the first 12
lowercase hexadecimal characters of the packaged `acl-proxy` commit. That
directory is the archive root. The current Linux archive has the three shown
`bin/` entries; the planned macOS archive would omit the Linux-only relay and
have the other two.

The `0.3.0-rc.1` candidate requires `schema_version = 4`; configurations for
schema 3 and every earlier contract must be rewritten rather than migrated
through aliases or fallback parsing. This local candidate is validated for
build and runtime on Linux x86_64 and for compilation on Linux aarch64. macOS
arm64 and Windows MSVC x86_64 have not been validated because suitable hosts
are unavailable.

### Schema 4 Migration

Treat the binary and its complete configuration directory as one deployment
transaction:

1. Stage the new binary and a separate complete configuration directory.
2. Inventory the staged main file's implicit sibling `rules.d`. Remove
   unrelated content and convert the main file and every intended fragment to
   strict integer `schema_version = 4`.
3. Give fragments fixed-width ordering prefixes such as `00-`, `10-`, and
   `20-`. Raw ASCII filename order remains the normative ordering rule.
4. Run `config validate`, table `policy dump`, and JSON `policy dump` against
   the staged main path. Review the complete fragment-before-main order and
   source provenance.
5. Deploy the new binary, main file, and complete `rules.d` set together, then
   start or reload only after the complete set is in place.

Rollback must likewise restore the prior binary, main file, and complete
`rules.d` directory together. Do not run a schema-v4-only binary against a
partial directory transaction or pair an older binary with v4 configuration.

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

This repository owns the product shell: strict schema-4 compilation, listener
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
schema_version = 4

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

Listeners support `optional` or `required` workload identity. Omit the
listener's `identity` table to disable identity:

```toml
[listeners.explicit_http.identity]
mode = "required"

[identity]
max_pending_authentications = 256
max_pending_authentications_per_connection = 16

[identity.resolver]
kind = "static"
authority = "workstation"

[[identity.resolver.principals]]
id = "local-workload"
kind = "service_account" # user | service_account | system

[[identity.resolver.groups]]
id = "developers"
members = ["local-workload"]

[[identity.resolver.tokens]]
id = "local-workload-primary"
principal = "local-workload"
source = "environment"
variable = "AW_IDENTITY_TOKEN"
```

Environment token sources are read once before runtime threads start, removed
from the process environment, and retained in sensitive process-owned storage.
File sources use `source = "file"` with an absolute `path` and are read through
the proxy's private credential-file checks during candidate activation. Reload
may replace file-backed catalogs, but cannot introduce a new environment
locator after startup. Cleartext TCP identity is restricted to loopback;
Access Flow carries the typed presentation in its authenticated preface.

For HTTP listeners, `optional` treats a missing protected carrier as anonymous,
while `required` rejects it. Every presented invalid bearer fails closed.
`x-aw-identity-token` is reserved for this carrier and cannot be used by
ordinary header predicates, mutations, credentials, provider header
projection, capture, or generic egress.

Transparent HTTP and HTTPS listeners may instead accept a Unix stream carrying
one strict AW Access Flow preface followed by the untouched TCP stream:

```toml
[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]

[listeners.transparent_http.endpoint.transport]
kind = "unix"
path = "/Users/your-user/Library/Application Support/AW Gateway/runtime/transparent-http.sock"
mode = "0600"
```

The same Access Flow endpoint may use server-authenticated TLS/TCP for a relay
on another host. Remote listeners require workload identity and use exact
destination port 80 for transparent HTTP or 443 for transparent HTTPS:

```toml
[listeners.transparent_http]
endpoint.kind = "access_flow"
endpoint.admission_timeout = "2s"
endpoint.allowed_destination_ports = [80]
http_versions = ["http1"]
max_connections = 1024

[listeners.transparent_http.identity]
mode = "required"

[listeners.transparent_http.endpoint.transport]
kind = "tls_tcp"
bind = "0.0.0.0:7443"
handshake_timeout = "5s"

[listeners.transparent_http.endpoint.transport.server_identity]
certificate_chain = "/etc/acl-proxy/access-flow-chain.pem"
private_key = "/etc/acl-proxy/access-flow-key.pem"

[listeners.transparent_http.endpoint.transport.abuse_control]
max_handshakes = 128
max_connections_per_source = 8
handshakes_per_second = 4
handshake_burst = 8
source_table_capacity = 4096
```

TLS/TCP is TLS 1.3 only and requires ALPN `aw-access-flow/1`. The relay
authenticates the proxy certificate with its configured name and PEM trust
bundle; the proxy does not request a client certificate. The AWAF bearer is the
sole workload authentication input. A remote socket source is used only for
transport abuse control and is never exposed to ACLs, delegates, captures, or
decision logs. Remote policy has no source-CIDR fact, and its fixed diagnostic
client value is `0.0.0.0:0` (`0.0.0.0` in provider and decision-log fields).
Wire-body quotas use the resolved authority-qualified principal.

The certificate chain and private key are read from bounded, stable, direct,
single-link files. Unix uses no-follow descriptor traversal and requires the
private key to be owner-only. Windows uses the same handle-pinned, reparse-safe
snapshot contract as configuration loading. `acl-proxy config validate`
performs the same material validation as startup without binding the listener.

Use a dedicated or otherwise narrowly constrained issuing CA for Access Flow.
The relay sends its reusable AWAF bearer after standard WebPKI validation, so
any server key that chains to the configured bundle and satisfies the
configured `server_name` can receive that bearer. Keep the server private key
only on the ACL Proxy host; neither the Gateway, workload container, nor an
intermediate TLS terminator needs it. Access Flow performs no online OCSP or
CRL retrieval. Operational revocation therefore uses short-lived server
certificates plus explicit replacement of the relay trust generation.

One fixed listener coordinator continues accepting TCP candidates while
handshake, preface, and bearer operations are in flight. Global, per-source,
rate, and handshake capacity are acquired synchronously without waiting;
overflow candidates are closed without spawning admission tasks.

The workstation host path must be inside a user-writable runtime directory
owned by the workstation user and protected with mode `0700`; the placeholder
above must be replaced with that user's actual home path. Mode `0600` keeps the
host listener private and is sufficient for the root-owned guest endpoint and
root-supervised relay. Other Unix deployments should select the narrowest
socket mode compatible with their relay process.

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
primitive reject this listener kind. One lifetime-held lock per Unix endpoint
coordinates overlapping ACL Proxy instances while permitting disjoint endpoint
sets; the locks are not a security boundary against other processes running as
the same trusted workstation user.

ACL Proxy deliberately does not unlink the final path during shutdown because
POSIX has no atomic compare-inode-and-unlink operation. The service supervisor
or operator must remove the socket after the proxy has exited and released its
endpoint lock, before starting it again. This is also required after a later
startup
stage fails following socket publication. The immediate parent must already
exist as a real directory owned by the workstation user with no group or other
permission bits (normally mode `0700`).

Access Flow ingress represents one local workstation principal. The effective
client is loopback and local for quota purposes, and configurations using this
transport may not contain
`client_cidrs` predicates. The validated original destination is retained and
must belong to that endpoint's nonempty `allowed_destination_ports` set. The
workstation profile uses port 80 for transparent HTTP and port 443 for
transparent HTTPS. This transport is available on supported Unix hosts. The companion
`acl-proxy-access-flow-relay` artifact is Linux-only because it retrieves
`SO_ORIGINAL_DST` from redirected TCP connections.

Run the relay with its separate strict JSON configuration:

```bash
acl-proxy-access-flow-relay --config /etc/acl-proxy/access-flow-relay.json
```

See `examples/access-flow-relay.json` for the complete schema and
`examples/acl-proxy-access-flow.toml` for the paired host listeners. Relay
listener addresses must be nonzero IPv4 loopback addresses. Route names and
listen addresses must each be unique. `setupTimeout` covers both the Unix connection and
complete AW Access Flow preface write. `maxConnections` is global across routes.
Existing relay configurations require a one-time rewrite:
`allowedOriginalPorts` becomes `allowedDestinationPorts`, and
`upstreamSocket` becomes the nested
`"transport": {"kind": "unix", "path": "..."}` object. The old fields and
mixed old/new route shapes are rejected; there are no aliases.
The strict `presentation` union accepts `disabled`, `anonymous`, or
`bearer_environment`; the latter requires a `variable`, consumes and removes
that environment value before the Tokio runtime starts, and presents the same
bearer on every admitted relay connection.
The relay reserves 16 non-relay descriptors from `RLIMIT_NOFILE`, reserves
2 MiB from its fixed 256 MiB process preflight ceiling, and delegates exact
checked resource projection to the shared relay engine before binding.
The relay never parses HTTP or TLS and has no TCP egress fallback.
The shipped host example requires TLS parent-proxy egress; it does not silently
fall back to direct origin access.

Repository tests cover the relay-to-ACL HTTP artifact boundary through an
injected original-destination seam and cover TLS MITM on the Unix listener.
Kernel `SO_ORIGINAL_DST`/iptables netns behavior and the complete
TLS/HTTP2/WebSocket topology remain part of Gate A and the exact-tuple Gate X
suite. Gate X runs both relay consumers in a privileged Linux redirect
environment. Live Apple Container socket-relay execution remains a
host-conditional platform gate and is not inferred from Linux coverage.

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
url = "https://parent-proxy.example.test:8443"

[egress.parent_proxy.presentation]
kind = "bearer_environment" # bearer_environment | bearer_file
variable = "AW_IDENTITY_TOKEN"

[egress.parent_proxy.tls]
trust = "system"
```

Parent endpoints may not resolve to loopback, a local interface, a data
listener, or the control listener. DNS results are pinned and revalidated
before and after connect. Presentation requires an HTTPS endpoint and is valid
only for `kind = "acl_proxy"`; the bearer is added to ACL Proxy parent requests
and never to direct-origin or generic-parent traffic. A file presentation uses
`path` instead of `variable`. Cleartext HTTP parents cannot carry a typed
identity presentation.

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
identity_states = ["authenticated"]
identity_subjects = [
  { kind = "group", authority = "workstation", id = "developers" }
]

[policy.rules.headers]
present_all = ["x-workload-id"]
none = { x-blocked = ["true"] }
```

Every rule requires a stable, unique `id` and a `decision`. An empty `urls`
list means every canonical HTTP/HTTPS URL, subject to the other predicates.
`identity_states` is an optional nonempty, duplicate-free OR set drawn from
`disabled`, `anonymous`, and `authenticated`; omission means no identity-state
predicate. Authoring order does not affect the compiled rule. The singular
`identity_state` field is rejected and has no alias. `identity_subjects` is an
OR set of exact authority-qualified `principal` or `group` references and may
appear only with `identity_states = ["authenticated"]`. Identity predicates
combine with the other predicates using the rule-wide AND behavior.

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

#### Policy Fragments (`rules.d`)

For a selected main file such as `/etc/acl-proxy/acl-proxy.toml`, ACL Proxy
implicitly discovers only the sibling `/etc/acl-proxy/rules.d` directory.
Missing or empty `rules.d` means there are no fragment rules. A fragment is a
strict schema-4 TOML document containing only the required version and one or
more rules:

The directory belongs to the parent, not to the main filename. Two selected
main files in the same parent therefore consume the same `rules.d` authority.
Before upgrading or selecting any main file, inventory that file's sibling
directory and reject unrelated content. Validate the staged authority through
the production facade in all three sanctioned views:

```bash
acl-proxy config validate --config /etc/acl-proxy/acl-proxy.toml
acl-proxy policy dump --format table --config /etc/acl-proxy/acl-proxy.toml
acl-proxy policy dump --format json --config /etc/acl-proxy/acl-proxy.toml
```

```toml
schema_version = 4

[[rules]]
id = "workstation-read"
decision = "allow"
urls = ["https://api.example.test/**"]
methods = ["GET"]
```

Fragment `[[rules]]` use the same rule shape as main-file
`[[policy.rules]]`. Product configuration, a fragment default, unknown fields,
and empty rule lists are rejected.

Eligible fragment names are at most 255 ASCII bytes and match
`[A-Za-z0-9][A-Za-z0-9._-]*\.toml`. Windows reserved device basenames and
names that collide under ASCII case folding are rejected on every platform.
Every directory entry must be an eligible direct, single-link regular file;
symlinks, Windows reparse points, hard links, nested directories, special
files, and unrelated temporary files reject the complete candidate.
Use fixed-width prefixes such as `00-`, `10-`, and `20-` so intended insertion
points remain obvious. This is authoring guidance; raw ASCII filename order is
the normative composition rule.

The hard source bounds are:

| Resource | Limit |
| --- | ---: |
| Direct `rules.d` entries and fragment files | 1,024 |
| Bytes per fragment | 2 MiB |
| Aggregate fragment bytes | 10 MiB |
| Main configuration bytes | 10 MiB |
| Composed policy rules | 100,000 |
| Aggregate identity subjects | 4,096 |

ACL Proxy composes one global first-match policy: fragment files in ascending
ASCII filename order, rules within each fragment in authored order, then
main-file rules in authored order, followed by the main-file default. Rule IDs
and all references and compiler limits are global. A delegated `pass` advances
to the next rule in this global order.

Write access to `rules.d` grants policy authority equal to write access to the
main rule list. A writer can prepend an allow, invoke any provider, credential,
or redaction effect available from the main configuration, remove fragment
denies, or make the next reload fail. There is no protected mandatory-rule
tier. The main file, its parent and redirect-capable ancestors, and `rules.d`
must therefore be writable only by principals granted full policy authority;
group- or world-writable policy paths are a deployment security error.

Use one trusted writer for the main file, fragments, and reload trigger. Stage
temporary files outside `rules.d`, atomically rename completed files into
place, request one reload only after the complete set is stable, and retain
writer serialization until reload completes. Any file, membership, mutation,
parse, reference, bounds, or activation failure preserves the complete prior
generation.

During a schema cutover or rollback, deploy the binary, main file, and complete
`rules.d` directory as one coordinated transaction. Mixing an old binary with
v4 authoring or publishing only part of the v4 directory is unsupported.

These permission and publication rules are operator controls, not checks
performed by ACL Proxy. ACL Proxy does not validate owner, group, or mode; lock
writers; or make hostile same-UID multi-file mutation transactional. Apply the
same permission boundary to every redirect-capable symlink target and ancestor
used to reach the selected main file.

`config validate`, `policy dump`, startup, CA export, and reload all use the
same composition facade. Diagnostics identify `main` or
`rules.d/<filename>` plus the source-local rule index. Table dumps add
`RULE_ID` and `SOURCE`; JSON rules contain a tagged `source` object. Absolute
host paths are omitted from routine diagnostics, dumps, and reload
observations.

The ready event and every successful reload publication report `generation`,
`rules_directory` (`missing`, `empty`, or `populated`), `fragment_count`,
`fragment_bytes`, `fragment_rule_count`, `main_rule_count`, and
`total_rule_count`. A rejected candidate emits no publication summary; the
prior generation's summary remains authoritative.

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

Unix authorization providers connect to a separately managed local service for
each selected request. They use one bounded `AWAP` version 1 request/response
exchange over the shared access RPC frame, without a callback listener,
connection pool, retry, request body, or dynamic credential destination:

```toml
[authorization.providers.repo_acl]
kind = "unix_socket"
socket_path = "/run/acl-proxy/repo-authorization.sock"
timeout = "2s"
on_failure = "deny"
include_headers = ["x-workload-id"]
include_identity = true
max_request_bytes = 262144
max_response_bytes = 65536
max_pending_requests = 128
peer_uid = 1000

[authorization.providers.repo_acl.outputs.access_token]
kind = "bearer"
transport_security = "tls_required"
required = true
```

All fields shown above except `include_identity`, `peer_uid`, and `outputs` are
required. `include_identity` defaults to false, `peer_uid` is optional, and an
omitted `outputs` table is empty. The socket path is absolute and normalized.
Activation validates the platform and optional peer-UID capability but never
probes or connects to the socket. Socket loss affects only requests selecting
that provider; rebinding the same path lets later requests recover.

AWAP requests contain the exact matched `ruleId`, invocation mode, canonical
URL and method, fixed workstation client, mandatory header object, and checked
identity only when selected. They never contain the raw identity bearer,
request body, caller credentials, provider configuration, or output
destinations. Responses echo the protocol request ID and return `allow`,
`deny`, or `pass`; only an effects-allowed `allow` may carry values declared by
the active configuration. Returned values are authorization effects passed to
the existing late credential-injection boundary. AWAP is not a credential
lookup protocol.

#### Outer CONNECT Decisions

When an HTTP/1 CONNECT is selected for MITM, a matching delegated policy rule
still calls its process, webhook, or Unix provider before the tunnel is
established. This synthetic outer request is decision-only: the provider
request has `method = "CONNECT"`, uses the canonical HTTPS root URL for the
CONNECT authority, and never contains a body, even when the provider is
configured
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

### Remote Access Flow Cutover

Unix and TLS/TCP are strict physical transport alternatives for each route.
There is no cleartext, opportunistic TLS, downgrade, endpoint fallback, or
automatic return to Unix after a remote failure. A controlled Unix-to-TLS
cutover is:

1. Add the workload principal, groups, and bearer to the Proxy resolver and
   validate policy before exposing a remote listener.
2. Provision a dedicated CA and a `serverAuth` leaf whose SAN matches the
   Gateway route's exact `server_name`. Install the owner-only private key only
   on the Proxy host.
3. Install the minimal CA bundle on the Gateway host, configure one exact
   Proxy address and port per route, and validate both product configurations.
4. Permit container egress only to those Proxy endpoints, permit Proxy-host
   ingress only from the intended relay network, and retain only the DNS
   access required to resolve configured names. TLS transport does not itself
   provide no-NAT isolation.
5. Start the Proxy listener and verify readiness, then activate the Gateway
   route and transparent redirect. Prove real HTTP and nested HTTPS policy,
   identity, and denial behavior before removing the old Unix route.

Rollback restores the previous Unix route and its redirect as one coordinated
configuration change after stopping new TLS admission. Do not configure a
fallback route. Keep the old socket and deployment material until the real-flow
check passes, and remove the remote firewall allowance only after the remote
route has drained.

### Certificate And Bearer Rotation

Rotate a CA or server identity with a bounded trust overlap:

1. Add the new CA to the existing bounded Gateway PEM bundle and send `SIGHUP`
   to `aw-container-agent`. Verify relay readiness.
2. Atomically replace the Proxy leaf chain and owner-only key at their unchanged
   paths, then send `SIGHUP` to ACL Proxy.
3. Verify both readiness endpoints and a real bearer-authenticated Access Flow.
4. Remove the old CA from the Gateway bundle, send `SIGHUP` to the agent, and
   verify the real flow again.

If the Gateway trust reload fails, repair the bundle and send another `SIGHUP`;
new relay admission remains closed while established flows drain. If the Proxy
identity reload fails, restore the prior matching leaf/key pair and reload it
while the old CA is still trusted. Do not proceed to trust removal until the
new generation has carried a real flow.

Bearer rotation is a separate disruptive transaction. `SIGHUP` does not reload
the Gateway bearer or static resolver configuration. Close new admission,
drain existing flows, update the Proxy resolver and Gateway environment
together, then restart the affected processes and verify authorization.

`SIGHUP` independently reloads the policy/configuration generation and Access
Flow TLS server identities from their unchanged static locators. A policy
failure leaves the current policy generation published. A TLS identity failure
closes every new Access Flow admission, including Unix listeners, and changes
readiness to HTTP 503; existing admitted flows retain their generation and
drain. A later valid TLS identity reload atomically reopens admission and
readiness. Leaf expiry has the same fail-closed admission behavior. Static
listener, control, filesystem ownership, and process-wide resource changes
remain restart-required.

`SIGINT` and `SIGTERM` initiate joined graceful shutdown and continue to be
polled while admitted work drains within `service.shutdown_drain_timeout`.
`SIGHUP` is ignored after shutdown begins. A second `SIGINT` or `SIGTERM`
abandons the graceful wait and forces prompt process termination.

Capture and policy-decision admission closes when graceful shutdown begins,
before admitted data-plane work drains. Capture jobs accepted before that
boundary drain within the remaining shutdown deadline; observations completed
during the later flow-drain window are intentionally omitted.

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

It builds or uses `ACL_PROXY_BIN`, validates generated strict v4 config, probes
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
