# acl-proxy configuration reference

This document describes the configuration schema and behavior of the Rust-based `acl-proxy`
implementation in more detail than the README.

The configuration file is a single TOML document. It controls:

- Listener addresses and ports.
- Logging behavior and policy decision logging.
- Capture of requests/responses to JSON files.
- Loop protection behavior.
- Certificate/CA management and per-host certificate generation.
- Upstream TLS verification.
- The URL policy engine (rules, macros, rulesets, methods, and subnets).

For a user-facing walkthrough and examples, see `README.md`. This document focuses on field-level
details.

---

## CLI overview (config and policy inspection)

The main `acl-proxy` binary exposes several CLI subcommands that operate purely on configuration
and policy, without starting the proxy:

- `acl-proxy config validate [--config <path>]` – load and validate configuration.
- `acl-proxy config init <path>` – write a minimal default configuration to `<path>`.
- `acl-proxy policy dump [--format json|table] [--config <path>]` – load configuration, fully
  resolve the policy (macros, rulesets, includes, URL-encoded variants), and print the effective
  rule set.

All of these commands share the same config-path resolution and environment overrides described
below. `policy dump` is particularly useful for offline policy debugging and CI enforcement.

---

## Config path resolution and overrides

The configuration file path is resolved in this order:

1. CLI argument `--config <path>`.
2. `ACL_PROXY_CONFIG` environment variable.
3. Default path `config/acl-proxy.toml` (relative to the current working directory).

After parsing, environment overrides are applied:

- `PROXY_PORT` – overrides `[proxy].http_port` when set to a valid `u16`.
- `PROXY_HOST` – overrides `[proxy].bind_address` when non-empty.
- `LOG_LEVEL` – overrides `[logging].level` when non-empty.

If the resolved file is missing and the default path is in use, `acl-proxy config validate` prints
a helpful message including a suggested `acl-proxy config init` command.

---

## Top-level keys

```toml
schema_version = "1"

[proxy]
[logging]
[capture]
[loop_protection]
[certificates]
[tls]
[policy]
```

- `schema_version` – required string; currently only `"1"` is supported. Any other value results in
  a validation error.

The remaining sections are optional and defaulted when absent.

---

## `[proxy]` – listeners and ports

```toml
[proxy]
bind_address = "0.0.0.0"      # default
http_port = 8881              # default
https_bind_address = "0.0.0.0"# default
https_port = 8889             # default (0 disables transparent HTTPS)
```

Fields:

- `bind_address` (string, default `"0.0.0.0"`):
  - The IP or hostname on which the HTTP explicit proxy listener binds.
  - Environment override: `PROXY_HOST`.

- `http_port` (integer, default `8881`):
  - Port for the HTTP explicit proxy.
  - Setting `0` requests an ephemeral port from the OS (used primarily in tests).
  - Environment override: `PROXY_PORT`.

- `https_bind_address` (string, default `"0.0.0.0"`):
  - IP/host for the transparent HTTPS listener.

- `https_port` (integer, default `8889`):
  - Port for the transparent HTTPS listener.
  - `0` disables the transparent HTTPS listener entirely.

---

## `[logging]` – base logging and policy decision logging

```toml
[logging]
directory = "logs"
level = "info"

[logging.policy_decisions]
log_allows = false
log_denies = true
level_allows = "info"
level_denies = "warn"
```

### Base logging

- `directory` (string, default `"logs"`):
  - Currently used as a **fallback** for the capture directory when `[capture].directory` is empty.
  - Does not control an on-disk log file; logs are emitted through `tracing` according to the
    process environment.

- `level` (string, default `"info"`):
  - Global log level for the `tracing` subscriber installed at startup.
  - Accepted values correspond to `tracing::Level` (case-insensitive), e.g. `trace`, `debug`,
    `info`, `warn`, `error`.
  - Invalid values cause `config validate` (and startup) to fail with an error.
  - Environment override: `LOG_LEVEL`.

### Policy decision logging

The nested `[logging.policy_decisions]` table controls how individual policy decisions are logged:

- `log_allows` (bool, default `false`):
  - Whether to log decisions for allowed requests.

- `log_denies` (bool, default `true`):
  - Whether to log decisions for denied requests.

- `level_allows` (string, default `"info"`):
  - Log level for allowed decisions.

- `level_denies` (string, default `"warn"`):
  - Log level for denied decisions.

Policy decision events are emitted to the `acl_proxy::policy` target with structured fields:

- `request_id`, `allowed`, `url`, `method`, `client_ip`.
- `rule_action`, `rule_pattern`, `rule_description` (for matched rules).

---

## `[capture]` – request/response capture

```toml
[capture]
allowed_request = false
allowed_response = false
denied_request = false
denied_response = false
directory = "logs-capture"
filename = "{requestId}-{suffix}.json"
```

Fields:

- `allowed_request` (bool, default `false`):
  - Capture request records for allowed traffic.

- `allowed_response` (bool, default `false`):
  - Capture response records for allowed traffic.

- `denied_request` (bool, default `false`):
  - Capture request records for denied traffic (policy or loop).

- `denied_response` (bool, default `false`):
  - Capture response records for denied traffic.

- `directory` (string, default `"logs-capture"`):
  - Base directory for capture files. Configuration validation requires this field to be
    non-empty; omitting the `[capture]` table uses the default `"logs-capture"`.

- `filename` (string, default `"{requestId}-{suffix}.json"`):
  - Template used to produce filenames.
  - Valid placeholders:
    - `{requestId}` – the internal request ID, sanitized to contain only `A-Za-z0-9_-`.
    - `{kind}` – `"request"` or `"response"`.
    - `{suffix}` – `"req"` or `"res"` (the default template uses `{suffix}` so you can change file
      naming conventions without affecting the `kind` value stored in the capture record itself).
  - If empty/whitespace, the default template is effectively `"${requestId}-${suffix}.json"`.

### Capture record JSON format

Every capture file contains a single JSON object with the following fields (subset; many are
optional):

- `timestamp` (`string`) – RFC 3339 timestamp.
- `requestId` (`string`) – internal request ID.
- `kind` (`"request" | "response"`).
- `decision` (`"allow" | "deny"`).
- `mode` (`"http_proxy" | "https_connect" | "https_transparent"`).
- `url` (`string`) – normalized URL (no fragment).
- `method` (`string`) – HTTP method (request’s verb, carried across to the response record).
- `statusCode` (`number`, optional) – HTTP status code (responses only).
- `statusMessage` (`string`, optional).
- `client` (object):
  - `address` (`string`, optional) – client IP address.
  - `port` (`number`, optional) – client port.
- `target` (object, optional) – upstream target endpoint:
  - `address` (`string`, optional) – upstream host.
  - `port` (`number`, optional) – upstream port.
- `httpVersion` (`string`, optional) – e.g. `"1.1"`, `"2"`.
- `headers` (object, optional):
  - Keys are lowercase header names.
  - Values are either a string (single header) or an array of strings (multi-valued header).
- `body` (object, optional):
  - `encoding` (`string`) – currently `"base64"`.
  - `length` (`number`) – full logical body length (in bytes).
  - `data` (`string`) – base64-encoded captured bytes.
  - `contentType` (`string`, optional) – content type inferred from headers.

Bodies are captured into an in-memory buffer up to 64 KiB per request/response. The full logical
length is still recorded in `body.length`, but only the first 64 KiB are serialized into `body.data`.
When capture is disabled for a given kind/decision, no file is written for that record.

---

## `[loop_protection]` – loop detection

```toml
[loop_protection]
enabled = true
add_header = true
header_name = "x-acl-proxy-request-id"
```

Fields:

- `enabled` (bool, default `true`):
  - When `true`, loop protection is active for all proxy paths (HTTP, CONNECT, and transparent
    HTTPS).
  - When `false`, the proxy neither injects nor checks the loop header.

- `add_header` (bool, default `true`):
  - When `enabled` is `true` and `add_header` is `true`, the proxy injects `header_name` into
    outbound requests if the header is not already present.
  - When `enabled` is `true` and `add_header` is `false`, the proxy only checks for loops; no
    header is injected.

- `header_name` (string, default `"x-acl-proxy-request-id"`):
  - HTTP header name used for loop detection and injection.
  - Must be a syntactically valid header name; invalid values cause validation to fail.

Behavior:

- If an inbound request contains `header_name` and loop protection is enabled, the proxy responds
  with:
  - HTTP status `508 Loop Detected`.
  - JSON body containing exactly:
    - `{ "error": "LoopDetected", "message": "Proxy loop detected via loop protection header" }`.
  - Capture logging for this decision follows the `[capture]` flags for denied traffic.

Loop detection is applied:

- On HTTP explicit proxy requests.
- On the initial CONNECT request.
- On decrypted HTTPS requests inside CONNECT tunnels.
- On decrypted requests received by the transparent HTTPS listener.

---

## `[certificates]` – CA and per-host certificates

```toml
[certificates]
certs_dir = "certs"
ca_key_path = "/optional/path/to/ca-key.pem"
ca_cert_path = "/optional/path/to/ca-cert.pem"
```

Fields:

- `certs_dir` (string, default `"certs"`):
  - Base directory for all certificate material.
  - When empty/whitespace, `"certs"` is used.

- `ca_key_path` / `ca_cert_path` (string, optional):
  - When both are `null`, empty, or absent:
    - The proxy uses an auto-generated CA.
    - Default paths:
      - CA key: `${certs_dir}/ca-key.pem`
      - CA cert: `${certs_dir}/ca-cert.pem`
    - If files exist and are valid, they are reused; otherwise a new CA is generated and written.
  - When both are non-empty:
    - The proxy uses the configured CA key/cert as-is.
    - Invalid or unreadable files produce a configuration error when TLS state is built (for
      example at startup or on reload).
  - When only one is provided:
    - Validation fails with an error; both must be set or both omitted.

Per-host certificates:

- Generated on demand for each host (SNI or CONNECT target).
- Stored on disk under `${certs_dir}/dynamic/`:
  - `<host>.crt` – leaf certificate PEM.
  - `<host>.key` – private key PEM.
  - `<host>-chain.crt` – leaf + CA certificate chain PEM.
- Also cached in memory; the in-memory cache is the authoritative source used during TLS
  handshakes. The dynamic PEM files are written for transparency and debugging and are not
  reloaded on startup; the proxy regenerates per-host certificates from the CA as needed.

The CA certificate path used by the running proxy is accessible via internal APIs and is expected
to point at the CA used to sign per-host certificates (useful for distributing trust to clients).

---

## `[tls]` – upstream TLS behavior

```toml
[tls]
verify_upstream = true
enable_http2_upstream = false
```

Fields:

- `verify_upstream` (bool, default `true`):
  - When `true`, upstream HTTPS connections are verified against system-native root certificates.
  - When `false`, upstream TLS verification is disabled:
    - All upstream certificates are accepted regardless of host or issuer.
    - This is intended for controlled lab/testing environments only.

- `enable_http2_upstream` (bool, default `false`):
  - When `false`, the proxy always uses HTTP/1.1 for outbound requests to upstream servers, even
    when clients speak HTTP/2 to the proxy. This is the recommended default for maximum
    compatibility with arbitrary origins.
  - When `true`, the shared HTTP client enables HTTP/2 and lets ALPN negotiation choose the
    protocol per origin:
    - If the origin advertises `h2`, the proxy may use HTTP/2 for upstream traffic.
    - If the origin only advertises `http/1.1`, the proxy automatically downgrades while still
      serving HTTP/2 to clients where applicable.

These settings affect only outbound TLS from the proxy to upstream servers. Incoming TLS from
clients is always terminated using the proxy’s CA and per-host certificates.

---

## `[policy]` – URL policy engine

The `[policy]` section defines a default action and an ordered list of rules. Rules can be direct
rules or ruleset includes with macro-driven expansion.

Top-level structure:

```toml
[policy]
default = "deny"   # "allow" or "deny"

[policy.macros]
# user-defined placeholder values

[policy.rulesets]
# named collections of template rules

[[policy.rules]]
# individual rules (direct or includes)
```

### `policy.default`

```toml
[policy]
default = "deny"   # or "allow"
```

- Controls behavior when no rule matches.
- Accepts `"allow"` or `"deny"` (case-insensitive).

### `policy.macros`

`[policy.macros]` is a map from macro name to one or more string values:

```toml
[policy.macros]
repo = "team/service-a"
project = ["team/service-a", "team/service-b"]
```

Values may be:

- A single string, treated as a singleton list.
- A list of strings.

Macros are referenced using `{placeholder}` syntax inside `pattern` and `description` fields.
Missing macros cause configuration validation to fail.

### `policy.rulesets`

Rulesets define reusable rule templates. They live under `policy.rulesets.<set_name>` and are
declared as arrays of tables:

```toml
[[policy.rulesets.git_repo]]
action = "allow"
pattern = "https://git.internal/{repo}.git/**"
description = "Git HTTP(S) for {repo}"
methods = ["GET", "POST"]
subnets = ["10.0.0.0/8"]

[[policy.rulesets.git_repo]]
action = "allow"
pattern = "https://git.internal/api/v4/projects/{repo}?**"  # ?** matches any query string
description = "Git API for {repo}"
```

Fields:

- `action` (`"allow" | "deny"`) – required.
- `pattern` (`string`) – required template string; may contain `{placeholder}` names.
- `description` (`string`, optional) – may also contain `{placeholder}` names.
- `methods` (string or list of strings, optional) – HTTP methods (normalized to uppercase).
- `subnets` (`["192.168.0.0/16", ...]`, optional) – list of IPv4 CIDR subnets.

Rulesets themselves are not evaluated until referenced from `policy.rules` via an include rule.

### `[[policy.rules]]` – direct and include rules

Each entry in `[[policy.rules]]` is either:

1. A **direct rule** with an `action` (and optional pattern, methods, subnets).
2. An **include rule** that references a named ruleset.

#### Direct rules

Example:

```toml
[[policy.rules]]
action = "allow"
pattern = "https://api.internal.example.com/v1/**"
methods = ["GET", "POST"]
subnets = ["10.0.0.0/8"]
description = "API from internal network"
```

Fields:

- `action` (`"allow" | "deny"`) – required.
- `pattern` (`string`, optional) – match target pattern; may contain placeholders.
- `description` (`string`, optional).
- `methods` (string or list, optional) – allowed HTTP methods (normalized to uppercase).
- `subnets` (`["CIDR", ...]`, optional) – allowed client IP subnets (IPv4 only; IPv6 client
  addresses do not match subnet rules).
- `with` (map from macro name to single string or list of strings, optional):
  - Overrides values for placeholders used in this rule.
  - Useful when the same macro is reused with different values in different rules.
- `add_url_enc_variants` (bool or list of strings, optional):
  - When `true`, for every placeholder used in this rule, the engine generates pattern variants
    using both raw and URL-encoded values.
  - When a list of names, only those placeholders get URL-encoded variants.

At least one of `pattern`, `methods`, or `subnets` must be present; otherwise the rule is rejected
as invalid.

Rules without `pattern` but with subnets and/or methods are allowed (e.g., “allow POST requests
from `10.0.0.0/8` to any URL”).

##### Header actions (per rule)

Each direct rule (and each ruleset template entry) may optionally define an ordered list of
per-rule header actions under `[[policy.rules.header_actions]]`. These actions do not affect rule
matching; they only mutate headers on the matching requests/responses.

Example:

```toml
[[policy.rules]]
action = "allow"
pattern = "https://github.com/**"
description = "Allow GitHub; tweak headers"

[[policy.rules.header_actions]]
direction = "request"          # "request" | "response" | "both"
action    = "set"              # "set" | "add" | "remove" | "replace_substring"
name      = "user-agent"
value     = "acl-proxy/1.0"

[[policy.rules.header_actions]]
direction = "request"
action    = "set"
name      = "x-if-present"
value     = "set-value"
when      = "if_present"       # "always" (default) | "if_present" | "if_absent"

[[policy.rules.header_actions]]
direction = "response"
action    = "replace_substring"
name      = "x-upstream-tag"
search    = "old"
replace   = "new"
```

Fields:

- `direction` (`"request" | "response" | "both"`, required):
  - Where to apply the action:
    - `request` – outbound request to the upstream.
    - `response` – response back to the client.
    - `both` – applies once on the request and once on the response.
- `action` (`"remove" | "set" | "add" | "replace_substring"`, required):
  - `remove` – delete the header entirely.
  - `set` – replace all existing values with the configured value(s).
  - `add` – append new values without removing existing ones (multi-valued headers).
  - `replace_substring` – for textual headers, replace all occurrences of `search` with
    `replace` in each current value.
- `name` (string, required):
  - Header name (case-insensitive). Must be a valid HTTP header name.
- `value` / `values` (string or list, for `set`/`add`):
  - Exactly one of `value` or `values` must be provided, and at least one value overall.
  - Values must be valid HTTP header values; invalid values cause config validation to fail.
- `when` (`"always" | "if_present" | "if_absent"`, optional):
  - `always` (default) – action is always considered.
  - `if_present` – action runs only if the header was present on the **original** message for
    that direction (before any actions for that direction run).
  - `if_absent` – action runs only if the header was **not** present on the original message.
- `search` / `replace` (strings, for `replace_substring`):
  - `search` must be non-empty; both fields are required for `replace_substring`.

For `when` evaluation, the proxy snapshots header presence separately for the request and response
before applying any header actions for that side, and uses that snapshot for all actions in the
rule. Actions are then applied in the order they appear in the configuration.

#### Include rules

Include rules expand a ruleset into one or more concrete rules:

```toml
[[policy.rules]]
include = "git_repo"
add_url_enc_variants = true
methods = ["GET", "POST"]
subnets = ["10.0.0.0/8"]
```

Fields:

- `include` (`string`, required) – the name of a ruleset defined under `policy.rulesets`.
- `with` (map, optional) – macro overrides specific to this include.
- `add_url_enc_variants` (bool or list, optional) – same meaning as in direct rules; applied to
  placeholders used by the ruleset.
- `methods` / `subnets` (optional) – rule-level overrides:
  - If provided, override template-level `methods` / `subnets` in the referenced ruleset.
  - If omitted, the template’s `methods` / `subnets` are used.

Missing macros required by a referenced ruleset (after accounting for `with` overrides) cause
configuration validation to fail with a clear error message.

### External auth profiles and approval-required rules

The policy engine supports **external auth profiles** that turn certain allow rules into
**approval-required** rules. When such a rule matches, the proxy:

- Creates a pending entry keyed by the internal `requestId`.
- POSTs a JSON webhook to an external auth service describing the pending request.
- Waits asynchronously for a callback decision.
- Either forwards the request upstream on approval, or returns a synthetic deny/timeout/error
  response to the client.

Profiles are defined under `[policy.external_auth_profiles]`:

```toml
[policy.external_auth_profiles]

[policy.external_auth_profiles.github_mfa]
webhook_url = "https://auth.internal/github/mfa-start"
timeout_ms = 5000           # approval timeout for the original client request
webhook_timeout_ms = 1000   # optional timeout for the webhook delivery itself
on_webhook_failure = "error"# "deny" | "error" | "timeout" (default: "error")
```

Fields:

- `webhook_url` (string, required):
  - URL of the external auth service that receives the initial webhook.

- `timeout_ms` (integer, required):
  - How long to wait for an approval/deny callback before timing out the client with a
    `504 Gateway Timeout`.

- `webhook_timeout_ms` (integer, optional):
  - Optional timeout (in milliseconds) for delivering the webhook itself.
  - If the webhook cannot be delivered within this timeout (or fails quickly), the proxy applies
    `on_webhook_failure`.
  - When omitted, the webhook delivery is not additionally time-bounded by acl-proxy; it relies on
    the underlying HTTP client’s behavior. In most environments you should set this explicitly to
    avoid long-hanging webhook calls.

- `on_webhook_failure` (`"deny" | "error" | "timeout"`, optional):
  - Behavior when the webhook fails fast:
    - `"deny"` – respond `403 Forbidden` with the normal policy-deny JSON shape.
    - `"error"` – respond `503 Service Unavailable` with an external-approval error JSON.
    - `"timeout"` – behave as if approval timed out (`504`) and remove the pending entry.
  - When omitted, `"error"` is used.

Profiles are attached to rules via the `external_auth_profile` field:

```toml
[[policy.rules]]
action = "allow"
pattern = "https://api.github.com/**"
description = "GitHub API with external MFA"
external_auth_profile = "github_mfa"
```

For rules and templates you may also define an optional, stable `rule_id`:

```toml
[[policy.rules]]
action = "allow"
pattern = "https://api.github.com/**"
description = "GitHub API with external MFA"
external_auth_profile = "github_mfa"
rule_id = "github-allow-mfa"
```

When present, `rule_id` is included in external auth webhooks alongside the numeric `ruleIndex`.

Semantics:

- Rules keep `action = "allow"` or `"deny"` as before.
- When `action = "allow"` **and** `external_auth_profile` is set:
  - The rule becomes **approval-required**.
  - On match, the proxy:
    - Creates a pending entry keyed by `requestId`.
    - Sends an initial **pending** webhook to the configured profile’s `webhook_url`.
    - Waits for a callback decision (up to `timeout_ms`).
    - On approval: proxies the request upstream as usual (including any header actions).
    - On deny: returns `403 Forbidden` with the standard policy-deny JSON shape.
    - On timeout: returns `504 Gateway Timeout` with an `"ExternalApprovalTimeout"` error.
    - On internal error (e.g., callback channel closed): returns `503 Service Unavailable`.
- When `action = "deny"` and `external_auth_profile` is set:
  - Configuration validation fails; approval-required deny rules are not allowed.
- Rules without `external_auth_profile` behave exactly as today.
- Ruleset templates (`[[policy.rulesets.<name>]]`) may also specify `external_auth_profile`; the
  expanded rules inherit the profile.

Lifecycle status telemetry:

- All external auth webhooks are POSTed to the profile’s `webhook_url` with a JSON body and an
  `X-Acl-Proxy-Event` header:
  - `X-Acl-Proxy-Event: pending` – initial approval webhook.
  - `X-Acl-Proxy-Event: status` – best-effort lifecycle notifications.
- Both webhook kinds include the base fields:
  - `requestId`, `profile`, `ruleIndex`, optional `ruleId`, `url`, `method`, `clientIp`.
- Additional lifecycle fields:
  - `status`: `"pending"`, `"webhook_failed"`, `"timed_out"`, `"error"`, or `"cancelled"`.
  - `reason`: optional human-readable explanation.
  - `timestamp`: RFC3339 timestamp when the event was generated.
  - `elapsedMs`: milliseconds since the pending entry was created.
  - `terminal`: `false` for `"pending"`, `true` for terminal statuses.
  - `eventId`: unique identifier for the notification (useful for dedupe).
  - `failureKind` (terminal only): `"timeout" | "connect" | "non_2xx"`.
  - `httpStatus` (terminal only): HTTP status code when applicable.

The proxy may emit at most one terminal status event per `requestId` in addition to the initial
`"pending"` webhook. Status webhooks are **best-effort telemetry only**; delivery failures are
logged but never affect the allow/deny decision or the client’s HTTP response.

Callback endpoint:

- The proxy exposes a dedicated callback path on the HTTP listener:

  ```http
  POST /_acl-proxy/external-auth/callback
  Content-Type: application/json

  { "requestId": "req-...", "decision": "allow" | "deny" }
  ```

- Behavior:
  - If `requestId` refers to an active pending request:
    - The pending entry is removed.
    - The decision is delivered to the waiting request task.
    - The callback responds with `200 OK` and body `{ "status": "ok" }`.
  - If no pending entry exists (unknown or already completed/timed-out `requestId`):
    - The callback responds with `404 Not Found` and JSON
      `{ "error": "RequestNotFound", "message": "No pending request for this requestId" }`.

Security note:

- The callback endpoint does not perform authentication in this initial version.
- Deployments should ensure that only the trusted external auth service (or a tightly controlled
  network segment) can reach `/_acl-proxy/external-auth/callback` (for example via firewall rules
  or network policy).
- Future versions may add optional shared-secret or signature-based callback authentication.

---

## Pattern syntax and URL normalization

### URL normalization

Before applying rules, the engine normalizes input URLs into the form:

```text
protocol + "//" + host[:port] + path + optional "?query"
```

Details:

- The scheme (`protocol`) is preserved (`http:` or `https:`).
- Host includes an explicit port if present in the URL, otherwise the default.
- Path:
  - Defaults to `/` when omitted.
  - Copied as-is otherwise.
- Query:
  - If present, prepended with `?` and appended after the path.
  - If absent, omitted.

Invalid URLs (missing host, parse errors, empty strings) are treated as denied.

IPv6 hostnames are normalized using standard bracket notation, for example:
`https://[::1]:8443/path`.

### Pattern syntax

Patterns are string templates that are converted to case-insensitive regular expressions. Key rules:

- Scheme handling:
  - Patterns that start with `http://` or `https://` are normalized to be scheme-agnostic:
    the underlying regex uses `https?://`.
  - Patterns with no scheme are treated as host/path patterns and also matched with `https?://`.

- Wildcards:
  - `*` matches any sequence of characters **excluding `/`**.
  - `**` matches any sequence of characters, including `/`.

- Host-only patterns:
  - When a pattern only specifies scheme + host (or just host), trailing `/` is ignored.
  - Such patterns match both `https://host` and `https://host/` but not deeper paths.

Examples:

- `https://example.com`:
  - Matches `https://example.com` and `https://example.com/`.
  - Does not match `https://example.com/path`.

- `https://example.com/api/**`:
  - Matches `https://example.com/api/` and any deeper path.

- `https://example.com/api/*/resource`:
  - Matches `https://example.com/api/v1/resource`.
  - Does not match `https://example.com/api/v1/v2/resource`.

Placeholders (e.g., `{repo}`) are interpolated before the pattern is converted to a regex.

---

## Client IP normalization and subnets

Subnets are defined as IPv4 CIDR strings, e.g.:

```toml
subnets = ["10.0.0.0/8", "192.168.0.0/16"]
```

For each request, the engine:

1. Normalizes the client IP string:
   - Strips any interface suffix after `%` (e.g., `fe80::1%eth0` → `fe80::1`).
   - Maps `::ffff:x.y.z.w` to `x.y.z.w`.
   - Maps `::1` to `127.0.0.1`.
2. Parses the normalized string as an IP address (IPv4 or IPv6).
3. Applies subnet checks only when the address is IPv4 and at least one subnet is configured.

If no subnet rule matches, the rule does not apply.

---

## Methods

Methods in rules are specified as either:

- A single string:

```toml
methods = "POST"
```

- Or a list of strings:

```toml
methods = ["GET", "HEAD"]
```

Values are normalized to uppercase during parsing, and comparisons are case-insensitive. When a
rule specifies `methods`, the request must include a method and it must appear in the rule’s method
list for the rule to match.

Examples:

- Rule with `methods = ["GET", "HEAD"]`:
  - Matches `GET` and `HEAD` requests.
  - Does not match `POST`.
  - Does not match requests where the method is unknown or omitted.

Rules without `methods` have no method restriction.

---

## Rule evaluation semantics

When evaluating a request, the policy engine:

1. Normalizes the URL.
2. Normalizes the client IP (if present).
3. Normalizes the method (if present).
4. Evaluates rules in the configured order:
   - For each rule, check:
     - Pattern (if any).
     - Subnets (if any).
     - Methods (if any).
   - The first rule that matches yields:
     - A decision (`allow` or `deny`).
     - Metadata (action, pattern, description, subnets, methods) exposed in logs and capture.
5. If no rule matches, apply `policy.default`.

Invalid URLs are treated as denied, regardless of `policy.default`.

---

## Validation rules

The config loader performs additional validation beyond basic TOML parsing:

- `schema_version` must equal `"1"`.
- For every `[[policy.rules]]` entry:
  - Direct rules must specify at least one of `pattern`, `methods`, or `subnets`.
  - Include rules must specify a non-empty `include` name.
- Macros:
  - For any pattern/description using `{placeholder}`, that placeholder must be provided by either:
    - An entry in `policy.macros`.
    - Overrides in `with` for direct or include rules.
- Certificates:
  - `certificates.ca_key_path` and `certificates.ca_cert_path` must be both set or both omitted.
  - When both are set, files must exist and be parseable; otherwise, configuration fails.
- Loop protection:
  - `loop_protection.header_name` must be a valid HTTP header name.

On validation failure, `config validate` and `acl-proxy` startup report a human-readable error and
abort, leaving any previously running instance (in the case of reload) unchanged.

---

## Further reading

- `README.md` – high-level overview, quick start, proxy modes, and operational guidance.
- `src/config/mod.rs` – source of the configuration structs and default values.
- `src/policy/mod.rs` – implementation of the policy engine, including pattern compilation and
  macro/ruleset expansion.
