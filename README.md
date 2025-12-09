# acl-proxy

Rust-based ACL-aware HTTP/HTTPS proxy with a TOML configuration file and a flexible URL policy engine.

acl-proxy is designed to sit between clients and upstream HTTP/HTTPS services and enforce
allow/deny rules based on normalized URLs, HTTP methods, and client subnets. It can also capture
structured request/response logs for debugging and audit.

Key capabilities:
- HTTP/1.1 explicit proxy on a configurable host/port.
- HTTPS MITM via CONNECT with per-host certificates signed by a configurable or generated CA.
- Transparent HTTPS listener that terminates TLS directly and proxies to upstream HTTPS.
- HTTP/2 support on TLS listeners (transparent HTTPS), with the same policy/capture semantics as HTTP/1.1.
- Structured policy decision logging and JSON capture files with optional, size-limited bodies.
- Loop protection using a configurable header to prevent proxy loops.
- Config reload via SIGHUP with atomic AppState swapping and safe failure semantics.
- A helper CLI (`acl-proxy-extract-capture-body`) to decode captured HTTP bodies from JSON.

> Note: acl-proxy is configured via a single TOML file. There is no requirement to know about any
> previous implementations – this README documents the Rust proxy as the primary implementation.

---

## Quick start

### 1. Create a configuration

You can either generate a default config, copy the comprehensive sample from the repo root, or start from the manual example below.

Generate a default config file:

```bash
cargo run -- config init config/acl-proxy.toml
```

This writes a minimal, safe configuration (default deny policy, capture disabled) to
`config/acl-proxy.toml` if it does not already exist.

The generated default config currently looks like:

```toml
schema_version = "1"

[proxy]
bind_address = "0.0.0.0"
http_port = 8881
https_bind_address = "0.0.0.0"
https_port = 8889

[logging]
directory = "logs"
level = "info"

[policy]
default = "deny"
```

Alternatively, you can:

- Copy the root sample config and customize it:

  ```bash
  mkdir -p config
  cp acl-proxy.sample.toml config/acl-proxy.toml
  ```

- Or create a minimal config manually, for example:

```toml
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8881
https_bind_address = "127.0.0.1"
https_port = 8889

[logging]
directory = "logs"
level = "info"

[capture]
allowed_request = false
allowed_response = false
denied_request = false
denied_response = false
directory = "logs-capture"

[loop_protection]
enabled = true
add_header = true
header_name = "x-acl-proxy-request-id"

[certificates]
certs_dir = "certs"

[tls]
verify_upstream = true

[policy]
default = "deny"
```

Place this file at `config/acl-proxy.toml` (the default path), or anywhere else and reference it
via `--config` as shown below.

### 2. Validate the configuration

Before starting the proxy, validate the config:

```bash
cargo run -- config validate --config config/acl-proxy.toml
```

If the file is valid, you should see:

```text
Configuration is valid
```

If `--config` is omitted, the proxy resolves the path in this order:
- `--config <path>` (CLI)
- `ACL_PROXY_CONFIG` environment variable
- Default path `config/acl-proxy.toml` (relative to the current working directory)

### 3. Run the proxy

Start the proxy using the `Run` command (the default if no subcommand is provided):

```bash
cargo run -- --config config/acl-proxy.toml
```

or, once built:

```bash
acl-proxy --config config/acl-proxy.toml
```

On startup, the proxy:
- Loads and validates the configuration (applying environment overrides where applicable).
- Initializes logging based on `[logging].level`.
- Logs a structured startup event summarizing bind addresses, capture settings, loop protection,
  and certificate/CA mode.
- Starts the HTTP proxy listener and, if `https_port != 0`, the transparent HTTPS listener.

### 4. Connect a client

Assuming the minimal config above and a policy that allows the target URL:

#### HTTP proxy (HTTP/1.1 explicit)

```bash
curl -x http://127.0.0.1:8881 http://example.com/
```

The HTTP listener expects **absolute-form** requests (e.g., `GET http://host/path HTTP/1.1`),
which standard HTTP clients will automatically use when configured with an HTTP proxy.

#### HTTPS over CONNECT (MITM)

Clients talk HTTPS to the proxy using CONNECT; the proxy terminates TLS and applies URL policy:

```bash
curl -x http://127.0.0.1:8881 https://example.com/ \
  --proxy-cacert certs/ca-cert.pem
```

- The proxy generates or loads a CA under `[certificates].certs_dir` (default `certs/`).
- Per-host certificates are generated on demand and signed by that CA.
- Clients must trust `certs/ca-cert.pem` (or the CA configured via `ca_cert_path`) to avoid TLS
  verification errors.

#### Transparent HTTPS listener (TLS-terminating proxy)

The transparent HTTPS listener terminates TLS directly and proxies to upstream HTTPS:

```bash
# Example: listen on 127.0.0.1:8889 for transparent HTTPS

curl https://upstream.internal/resource \
  --resolve upstream.internal:443:127.0.0.1 \
  --cacert certs/ca-cert.pem
```

In a real deployment you would typically:
- Configure `[proxy].https_bind_address`/`https_port` for the listener.
- Configure your network or service mesh to route outbound HTTPS traffic through acl-proxy.
- Distribute the CA certificate from `certs/ca-cert.pem` to client trust stores.

---

## Using acl-proxy with mcp-gateway

When deploying mcp-gateway behind acl-proxy:
- Bind acl-proxy on the edge (for example 0.0.0.0:8881/8889) and run mcp-gateway on `127.0.0.1:4100` as the only upstream.
- Start from the commented `MCP Gateway suite` block in `acl-proxy.sample.toml` (or copy it into `config/mcp-gateway-suite.sample.toml`) and adjust hosts/ports to your environment.
- Enable `[logging.evidence]` to emit JSONL lines (`logs/acl_proxy_evidence.jsonl` by default) that can be merged with mcp-gateway Evidence for chat-to-html and audits.

## Development notes

If OpenSSL headers are missing on your system, you can build a local OpenSSL and point cargo to it. See `docs/DEV_SETUP.md` for the exact commands and environment variables (`OPENSSL_DIR`, `OPENSSL_STATIC`, `OPENSSL_NO_PKG_CONFIG`, `PKG_CONFIG_PATH`).

## Configuration model

### File location and environment overrides

Config path resolution:
- CLI `--config <path>` if provided.
- Else, `ACL_PROXY_CONFIG` environment variable.
- Else, `config/acl-proxy.toml` (relative to the current working directory).

Environment overrides applied after parsing:
- `PROXY_PORT` – overrides `[proxy].http_port` when set to a valid `u16`.
- `PROXY_HOST` – overrides `[proxy].bind_address` when non-empty.
- `LOG_LEVEL` – overrides `[logging].level` when non-empty.

If the resolved config file does not exist and the default path is in use, the CLI prints a
helpful message including a suggested `acl-proxy config init` command.

### Top-level keys

```toml
schema_version = "1"   # required, must currently be "1"

[proxy]
[logging]
[capture]
[loop_protection]
[certificates]
[tls]
[policy]
```

- `schema_version` – required; currently only `"1"` is supported. Any other value results in an
  error during validation.

### `[proxy]` – listeners and ports

```toml
[proxy]
bind_address = "0.0.0.0"      # default
http_port = 8881              # default
https_bind_address = "0.0.0.0"# default
https_port = 8889             # default (0 disables transparent HTTPS)
```

- `bind_address` – IP/host for the HTTP explicit proxy listener.
- `http_port` – HTTP explicit proxy port. Setting `0` asks the OS to choose an ephemeral port
  (useful for tests, not typical in production).
- `https_bind_address` – IP/host for the transparent HTTPS listener.
- `https_port` – transparent HTTPS listener port; setting this to `0` **disables** the transparent
  HTTPS listener.

### `[logging]` – base logging and policy decision logging

```toml
[logging]
directory = "logs"   # used as a fallback for capture directory
level = "info"       # TRACE, DEBUG, INFO, WARN, ERROR (case-insensitive)

[logging.policy_decisions]
log_allows = false
log_denies = true
level_allows = "info"
level_denies = "warn"
```

- `logging.level` – global log level used to configure the `tracing` subscriber at startup.
  Invalid values cause `config validate` (and startup) to fail.
- `logging.directory` – currently **not** used to configure a file sink; it is used as a fallback
  for the capture directory when `[capture].directory` is empty.
- `logging.policy_decisions`:
  - `log_allows` – whether to log allowed policy decisions.
  - `log_denies` – whether to log denied policy decisions.
  - `level_allows` / `level_denies` – log levels for allowed/denied decisions, respectively.

Policy decision logs are emitted to the `acl_proxy::policy` tracing target with structured fields
(request ID, URL, method, client IP, matched rule action/pattern/description).

### `[capture]` – request/response capture

```toml
[capture]
allowed_request = false
allowed_response = false
denied_request = false
denied_response = false
directory = "logs-capture"
filename = "{requestId}-{suffix}.json"
```

The capture subsystem records JSON files describing requests and responses. It is fully optional,
and controlled by four booleans:

- `allowed_request` / `allowed_response` – capture allowed traffic.
- `denied_request` / `denied_response` – capture denied traffic (policy or loop).
- `directory` – base directory for capture files. This field must be non-empty in configuration;
  omitting the `[capture]` table uses the default directory `"logs-capture"`.
- `filename` – template for capture filenames. Supports the placeholders:
  - `{requestId}` – a sanitized request identifier (non-alphanumeric characters replaced with `_`).
  - `{kind}` – `"request"` or `"response"`.
  - `{suffix}` – `"req"` or `"res"` (the default template uses `{suffix}` so callers can change
    the suffix semantics without changing the `kind` field stored in capture JSON).

Example filenames with the default template:
- `abc123-req.json`
- `abc123-res.json`

#### Capture record format

Each capture file contains a single JSON object with this shape:

- `timestamp` – RFC 3339 timestamp.
- `requestId` – the internal request identifier.
- `kind` – `"request"` or `"response"`.
- `decision` – `"allow"` or `"deny"`.
- `mode` – `"http_proxy"`, `"https_connect"`, or `"https_transparent"`.
- `url` – normalized URL (no fragment).
- `method` – HTTP method (for responses, the method of the originating request).
- `statusCode` / `statusMessage` – present for responses.
- `client` – `{ "address": "IP", "port": number }`.
- `target` – optional upstream endpoint (host/port) when known.
- `httpVersion` – string such as `"1.1"` or `"2"`.
- `headers` – map from lowercased header name to either a string or an array of strings.
- `body` – optional, present when a body is captured:
  - `encoding` – `"base64"`.
  - `length` – full logical body length in bytes (may exceed the captured portion).
  - `data` – base64-encoded captured bytes.
  - `contentType` – optional content type derived from headers.

Bodies are captured using a bounded buffer: up to 64 KiB of body bytes are stored per
request/response, while `body.length` records the full length. This prevents large payloads from
exhausting memory while still providing useful samples for debugging.

> Important: only the first 64 KiB of each request/response body are stored in `body.data`; the
> full logical length is always recorded in `body.length`.

The `mode` field makes it easy to distinguish traffic coming from:
- HTTP explicit proxy – `mode = "http_proxy"`.
- HTTPS over CONNECT – `mode = "https_connect"`.
- Transparent HTTPS listener – `mode = "https_transparent"`.

### `[loop_protection]` – loop detection and header injection

```toml
[loop_protection]
enabled = true
add_header = true
header_name = "x-acl-proxy-request-id"
```

- When `enabled` is `true`, acl-proxy:
  - Rejects any incoming request that already contains `header_name` with a `508 Loop Detected`
    response, including a JSON error body:
    `{"error":"LoopDetected","message":"Proxy loop detected via loop protection header"}`.
  - Optionally adds `header_name` with the internal request ID to outbound requests when
    `add_header = true` and no such header is already present.
- When `enabled = false`, the proxy neither injects nor checks the loop header (loop protection is
  effectively disabled).

Loop protection applies consistently across:
- HTTP explicit proxy requests.
- HTTPS requests inside CONNECT tunnels.
- Transparent HTTPS requests on the TLS listener.

The default header name (`x-acl-proxy-request-id`) must be a valid HTTP header name; invalid values
cause configuration validation to fail.

### `[certificates]` – CA and per-host certificates

```toml
[certificates]
certs_dir = "certs"
ca_key_path = "/optional/path/to/ca-key.pem"
ca_cert_path = "/optional/path/to/ca-cert.pem"
max_cached_certs = 1024
```

- `certs_dir` – base directory for certificate material. If empty or whitespace, `"certs"` is used.
- `ca_key_path` / `ca_cert_path`:
  - When **both** are unset or empty, the proxy uses auto-generated CA key/cert:
    - CA key: `${certs_dir}/ca-key.pem`
    - CA cert: `${certs_dir}/ca-cert.pem`
    - Files are generated once and then reused across restarts when present and valid.
  - When **both** are set (non-empty), the proxy uses the configured CA:
    - The CA key and certificate must exist and be parseable; errors are treated as fatal.
    - Generated per-host certificates embed the exact configured CA certificate bytes in the chain.
  - Any other combination (only one of the two set) is rejected during config validation.
- `max_cached_certs` (integer, default `1024`):
  - Maximum number of distinct per-host certificates kept in the in-memory LRU caches used by
    the proxy for TLS handshakes.
  - When the cache is full and a new host is added, the least recently used entry is evicted.

Per-host certificates:
- Per-host leaf certificates and keys are generated on demand and cached in memory.
- For transparency and debugging, PEM files are also written under `${certs_dir}/dynamic/`:
  - `<host>.crt` – leaf certificate.
  - `<host>.key` – private key.
  - `<host>-chain.crt` – leaf + CA chain.
- These dynamic files are an **audit view** only, written so operators can inspect or verify the
  exact certificates presented to clients; runtime certificate selection is based on the in-memory
  cache and CA, not by re-reading files on startup.

### `[tls]` – upstream TLS behavior

```toml
[tls]
verify_upstream = true
enable_http2_upstream = false
```

- `verify_upstream` (bool, default `true`):
  - When `true`, upstream HTTPS connections verify server certificates using the system’s native
    root store.
  - When `false`, upstream TLS verification is disabled:
    - The proxy accepts any upstream certificate for any host.
    - This is useful in controlled testing environments but **not recommended** for production.

- `enable_http2_upstream` (bool, default `false`):
  - When `false`, the proxy uses HTTP/1.1 for outbound requests to upstream servers, even when
    clients speak HTTP/2 to the proxy. This mirrors the legacy implementation and is the
    recommended default for maximum compatibility.
  - When `true`, the shared HTTP client enables HTTP/2 and lets ALPN negotiation choose the
    protocol per origin:
    - Origins that advertise `h2` may be reached over HTTP/2.
    - Origins that only advertise `http/1.1` are automatically downgraded while the client side
      can still use HTTP/2.

Inbound TLS (client → proxy) is always terminated using the proxy’s CA and per-host certificates;
`[tls]` only affects outbound HTTPS from the proxy to upstream servers.

### `[policy]` – URL policy engine

```toml
[policy]
default = "deny"   # "allow" or "deny"

[policy.macros]
# user-defined placeholders used in patterns/descriptions

[[policy.rulesets.git_repo]]
action = "allow"
pattern = "https://git.internal/{repo}.git/**"
description = "Git over HTTPS for {repo}"

[[policy.rules]]
action = "allow"
pattern = "https://status.internal/**"

[[policy.rules]]
include = "git_repo"
add_url_enc_variants = true
methods = ["GET", "POST"]
subnets = ["10.0.0.0/8"]
```

The policy engine evaluates an ordered list of rules; **first match wins**. If no rule matches,
`policy.default` is applied.

Supported concepts:

- `default` – `"allow"` or `"deny"` (case-insensitive). Controls the fallback behavior.
- `macros` – map from macro name to either a string or list of strings. Used for placeholder
  expansion in rules and rulesets.
- `rulesets` – named lists of template rules under `policy.rulesets.<name>`.
- `rules` – top-level rules (`[[policy.rules]]`) that can be either:
  - Direct rules with `action`, optional `pattern`, `description`, optional `methods`, and
    optional `subnets`.
  - Include rules that reference a ruleset via `include`, with optional `with` overrides and
    `add_url_enc_variants`.

#### Direct rules

Direct rules look like:

```toml
[[policy.rules]]
action = "allow"
pattern = "https://api.example.com/v1/**"
methods = ["GET", "POST"]
subnets = ["10.0.0.0/8"]
description = "Allow API from internal network"
```

Fields:
- `action` – `"allow"` or `"deny"`.
- `pattern` – optional string pattern; may include wildcards and, when using macros, `{placeholder}`
  segments.
- `description` – free-form text; propagated into logs and capture for matched rules.
- `methods` – optional string or list of strings. Values are normalized to uppercase, and rules only
  match when the incoming method is present and matches one of them.
- `subnets` – list of IPv4 CIDR strings (e.g., `"192.168.0.0/16"`). If present, the client IP must
  fall within at least one subnet for the rule to match. Subnet matching is currently IPv4-only;
  IPv6 client addresses do not match any subnet rules.
- `with` – optional macro overrides used when the pattern/description includes `{placeholder}`
  variables (see below).
- `add_url_enc_variants` – optional:
  - `true` / `false` – generate both raw and URL-encoded variants for **all** placeholders when
    true.
  - `["name1", "name2"]` – generate encoded variants only for the listed placeholder names.

At least one of `pattern`, `methods`, or `subnets` must be specified; rules with no match criteria
are rejected during validation.

#### Include rules and rulesets

Rulesets define reusable rule templates:

```toml
[policy.macros]
repo = [
  "team/service-a",
  "team/service-b",
]

[[policy.rulesets.git_repo]]
action = "allow"
pattern = "https://git.internal/{repo}.git/**"
description = "Git HTTP(S) for {repo}"
```

Include rules expand a ruleset into concrete rules:

```toml
[[policy.rules]]
include = "git_repo"
add_url_enc_variants = true
subnets = ["10.0.0.0/8"]
```

- `include` – name of the ruleset under `policy.rulesets`.
- `with` – optional macro overrides used for this include.
- `add_url_enc_variants` – same as in direct rules, but applied to placeholders used by the
  ruleset.
- `methods` / `subnets` – override or extend template-level methods/subnets.

If a required macro is missing (from `with` and `policy.macros`), configuration validation fails
with a clear error message.

#### Pattern syntax and URL normalization

Patterns are matched against a normalized URL string of the form:

```text
protocol + "//" + host[:port] + path + optional "?query"
```

Key details:
- Schemes:
  - Patterns starting with `http://` or `https://` are normalized to be **scheme-agnostic**:
    both are treated as `https?://` in the underlying regex.
  - Patterns without a scheme treat the beginning as `host[:port]/path`.
- Wildcards:
  - `*` matches any sequence of characters **excluding `/`**.
  - `**` matches any sequence of characters, including `/`.
- Host-only patterns:
  - For patterns that only specify scheme + host (or host), trailing `/` characters are ignored.
  - They match both `https://host` and `https://host/` but not deeper paths.

On evaluation, the engine:
- Parses and normalizes the URL (invalid URLs are treated as denied).
- Normalizes client IP addresses:
  - Strips interface suffixes (e.g., `%eth0`).
  - Maps `::ffff:x.y.z.w` to `x.y.z.w`.
  - Maps `::1` to `127.0.0.1`.
- Applies rules in order, returning the first match along with metadata about the matched rule.

IPv6 hosts are normalized using bracket notation (for example, `https://[::1]:8443/path`) before
pattern matching is applied.

For a more exhaustive schema-level reference (including additional examples), see
`docs/CONFIG_REFERENCE.md`.

---

## Policy inspection CLI

To inspect the fully resolved policy (after applying macros, rulesets, includes, URL-encoded
variants, and environment overrides) without starting the proxy, use:

```bash
cargo run -- policy dump --config config/acl-proxy.toml
```

or, once built:

```bash
acl-proxy policy dump --config config/acl-proxy.toml
```

Behavior:
- Reuses the same configuration loading and validation pipeline as `config validate`, including
  `--config`, `ACL_PROXY_CONFIG`, and environment overrides.
- Produces the effective rule set with default action, rule order, actions, patterns, methods,
  subnets, and descriptions.
- Output format:
  - Defaults to a human-readable table when stdout is a TTY.
  - Defaults to JSON when stdout is not a TTY (e.g., in CI).
  - Can be overridden explicitly via `--format json` or `--format table`.

Example (JSON):

```bash
acl-proxy policy dump --format json --config config/acl-proxy.toml
```

The JSON output is stable and machine-readable, suitable for CI checks or other tooling that needs
to audit the active policy.

---

## Proxy modes and HTTP/2 behavior

### HTTP explicit proxy (client → proxy over HTTP/1.1)

- Listener: `[proxy].bind_address` / `[proxy].http_port`.
- Request form: absolute-form HTTP/1.1 requests (standard for HTTP proxies).
- Policy evaluation:
  - Uses the full URL from the request line.
  - Includes client IP and HTTP method in the decision.
- Responses:
  - Allowed requests are proxied to upstream using HTTP/1.1 (even when clients speak HTTP/2 to
    a TLS listener elsewhere).
  - Denied requests receive a `403 Forbidden` JSON body:
    `{"error":"Forbidden","message":"Blocked by URL policy"}`.
  - Requests that trigger loop protection receive `508 Loop Detected` with a JSON body:
    `{"error":"LoopDetected","message":"Proxy loop detected via loop protection header"}`.
  - Non-absolute-form requests are rejected with `400 Bad Request`.

Capture records for this mode have `mode = "http_proxy"`.

### HTTPS over CONNECT (client → proxy over HTTP/1.1 CONNECT)

- Entry: clients send `CONNECT host:port HTTP/1.1` to the HTTP listener.
- The proxy:
  - Validates the CONNECT target `host:port`.
  - Builds or reuses a per-host certificate via the CA.
  - Responds `200 OK` and upgrades the connection to TLS.
  - Runs an HTTP/1.1 server **inside** the tunnel to inspect decrypted requests.
- Policy evaluation:
  - Uses URLs of the form `https://host[:port]/path?query`.
  - Applies the same method and subnet filters as in HTTP mode.
- Loop protection:
  - Checked both on the CONNECT request itself and on subsequent decrypted HTTPS requests.
- Responses:
  - Allowed traffic is proxied upstream using HTTPS with HTTP/1.1.
  - Denied inner HTTPS requests receive `403 Forbidden` (plaintext body) and are captured when
    configured.

HTTP/2 **inside** CONNECT tunnels is not currently supported; the inner decrypted connection is
handled as HTTP/1.1 only. Capture records for this mode have `mode = "https_connect"`.

### Transparent HTTPS listener (client → proxy over TLS)

- Listener: `[proxy].https_bind_address` / `[proxy].https_port` (disabled when `https_port = 0`).
- The proxy:
  - Terminates TLS using SNI and per-host certificates signed by its CA.
  - Supports HTTP/1.1 and HTTP/2 from clients via ALPN negotiation.
  - Parses decrypted HTTP requests and reconstructs full URLs from `Host` and the request target.
- Policy evaluation:
  - Uses `https://host[:port]/path?query`.
  - Applies method and subnet filters.
- Loop protection:
  - Checks for the loop header on inbound decrypted requests, returning `508 Loop Detected` when
    present.
- Responses:
  - Allowed traffic is proxied upstream using HTTPS with HTTP/1.1 by default.
  - When `tls.enable_http2_upstream = true`, the upstream client may negotiate HTTP/2 via ALPN
    where supported; capture records reflect the client-facing HTTP version for requests and the
    negotiated upstream HTTP version for responses.
  - Denied traffic receives `403 Forbidden` with a JSON error body as in HTTP mode.

Capture records for this mode have `mode = "https_transparent"`, and `httpVersion` reflects the
client-facing HTTP version (e.g., `"2"` for HTTP/2).

---

## Logging, capture, and the extract-capture-body helper

### Logging overview

- Logs are emitted via the `tracing` crate.
- Base log level is controlled by `[logging].level` (or `LOG_LEVEL` env override) at startup.
- Startup logs (target `acl_proxy::startup`) summarize:
  - HTTP and HTTPS bind addresses.
  - Loop protection settings.
  - Capture settings and directory.
  - CA mode (generated vs configured) and certificates directory.
  - Whether HTTP/2 is enabled on TLS listeners and, when configured, for upstream connections.
- Policy decision logs (target `acl_proxy::policy`) are controlled by
  `[logging.policy_decisions]` as described above.

### Capture and body limits

- Capture is optional and must be explicitly enabled via `[capture]` flags.
- For each captured request/response:
  - A JSON file is written under `[capture].directory` (or fallback directories).
  - Bodies are base64 encoded and truncated to 64 KiB of captured bytes while preserving the full
    logical length.

### `acl-proxy-extract-capture-body`

The helper binary `acl-proxy-extract-capture-body` decodes the body from a single capture JSON file
and writes the raw bytes to stdout.

Run it via Cargo:

```bash
cargo run --bin acl-proxy-extract-capture-body -- path/to/capture.json > body.bin
```

or once installed:

```bash
acl-proxy-extract-capture-body path/to/capture.json > body.bin
```

Behavior:
- Expects a JSON file matching the capture schema above.
- Requires `body.encoding == "base64"` when a body is present.
- On error (missing file, invalid JSON, missing body, unsupported encoding, invalid base64), prints
  a short error message to stderr and exits with a non-zero status.

---

## Operational behavior (reload, shutdown, signals)

### Configuration reload (SIGHUP on Unix)

- Sending `SIGHUP` to the acl-proxy process triggers a configuration reload.
- The proxy reloads the config from the same path resolution as startup (`--config`, `ACL_PROXY_CONFIG`,
  or default path).
- On successful reload:
  - A new `AppState` is built from the updated config.
  - The shared application state is atomically swapped.
  - New connections and requests see the updated policy, capture, loop protection, TLS, and
    certificate settings.
  - In-flight requests continue using the previous snapshot until they complete.
- On failure (e.g., parse error, invalid loop protection header, bad certificate settings):
  - The error is logged.
  - The previous working configuration remains in effect; no partial state is applied.

Listener bind addresses/ports and the base global tracing subscriber are configured at startup and
currently require a restart to change.

### Graceful shutdown

- `Ctrl+C` (cross-platform) or `SIGTERM` (on Unix) initiate a graceful shutdown:
  - HTTP and HTTPS listeners stop accepting new connections.
  - Existing connections and in-flight requests are allowed to complete using Hyper’s graceful
    shutdown semantics.
- There is currently no built-in timeout for draining long-lived TLS sessions; external tooling
  (e.g., a supervisor) should enforce any global time limits.

---

## CLI reference

### Main binary: `acl-proxy`

```bash
acl-proxy [--config <path>] [COMMAND]
```

Commands:
- `Run` (default) – start the proxy.
- `config validate` – validate the configuration file without starting the proxy.
- `config init <path>` – write a default configuration to `<path>`; refuses to overwrite.

Examples:

```bash
# Validate explicit config
acl-proxy config validate --config config/acl-proxy.toml

# Validate using ACL_PROXY_CONFIG
ACL_PROXY_CONFIG=config/acl-proxy.toml acl-proxy config validate

# Initialize a new config (non-existent path)
acl-proxy config init config/acl-proxy.toml

# Run the proxy
acl-proxy --config config/acl-proxy.toml
```

On missing default config (no `--config`, no `ACL_PROXY_CONFIG`, and no `config/acl-proxy.toml`),
`config validate` prints a helpful message including a suggested `config init` command.

### Helper binary: `acl-proxy-extract-capture-body`

See “Logging, capture, and the extract-capture-body helper” above for details.

---

## Examples

### Minimal local testing config

```toml
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8881
https_bind_address = "127.0.0.1"
https_port = 0        # disable transparent HTTPS for now

[logging]
directory = "logs"
level = "debug"

[capture]
allowed_request = false
allowed_response = false
denied_request = true
denied_response = true
directory = "logs-capture"

[loop_protection]
enabled = true
add_header = true

[certificates]
certs_dir = "certs"

[tls]
verify_upstream = true

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "http://example.com/**"
description = "Allow HTTP to example.com"
```

This configuration:
- Listens on `127.0.0.1:8881` for HTTP proxy traffic.
- Denies all traffic by default, except HTTP to `example.com`.
- Captures denied requests/responses.
- Uses a generated CA for HTTPS CONNECT and future transparent HTTPS use.

### Example: internal Git server + API

```toml
schema_version = "1"

[proxy]
bind_address = "0.0.0.0"
http_port = 8881
https_bind_address = "0.0.0.0"
https_port = 8889

[logging]
directory = "logs"
level = "info"

[capture]
allowed_request = true
allowed_response = false
denied_request = true
denied_response = true
directory = "logs-capture"

[loop_protection]
enabled = true
add_header = true

[certificates]
certs_dir = "certs"

[tls]
verify_upstream = true

[policy]
default = "deny"

[policy.macros]
repo = [
  "team1/service-a",
  "team2/service-b",
]

[[policy.rulesets.git_repo]]
action = "allow"
pattern = "https://git.internal/{repo}.git/**"
description = "Git HTTP(S) for {repo}"

[[policy.rulesets.git_repo]]
action = "allow"
pattern = "https://git.internal/api/v4/projects/{repo}?**"  # ?** matches any query string
description = "Git API for {repo}"

[[policy.rules]]
include = "git_repo"
add_url_enc_variants = true
subnets = ["10.0.0.0/8"]

[[policy.rules]]
action = "allow"
pattern = "https://status.internal/**"
description = "Status pages"

[[policy.rules]]
action = "deny"
pattern = "https://git.internal/admin/**"
description = "Block Git admin area"

[[policy.rules]]
action = "deny"
pattern = "https://git.internal/api/v4/**"
methods = ["DELETE"]
description = "Block destructive Git API calls"
```

This configuration:
- Exposes both HTTP and transparent HTTPS listeners.
- Restricts Git HTTP(S) access to specific repositories from `10.0.0.0/8`, including URL-encoded
  variants of repository paths.
- Allows access to internal status pages.
- Explicitly denies access to administrative Git paths.
- Captures allowed requests and all denied traffic for auditing, tagging each record with a mode
  (`http_proxy`, `https_connect`, or `https_transparent`).

---

## Development and testing

To run the test suite for the Rust crate:

```bash
cargo test
```

The tests include:
- Unit tests for configuration parsing, policy expansion, logging, capture, certificates, and loop
  protection.
- Integration tests that start HTTP/HTTPS/HTTP2 upstream servers and exercise:
  - HTTP explicit proxy behavior.
  - HTTPS CONNECT MITM behavior.
  - Transparent HTTPS behavior (HTTP/1.1 and HTTP/2).
  - Config reload semantics and loop protection updates.

All tests are deterministic and run entirely offline.

For a more detailed configuration schema walkthrough, see `docs/CONFIG_REFERENCE.md`.
