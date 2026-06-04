# Auth Plugins Design

## Overview

External auth profiles support two modes:

- `http`: the existing async approval flow (webhook + callback).
- `plugin`: a long-running stdio process that returns allow/deny/pass with optional
  request/response header actions.

This keeps the existing `external_auth_profile` profile wiring intact while
introducing a synchronous, per-request authorization plugin for cases like
URL allowlists or repo ACLs.

## Goals

- Preserve current async HTTP external auth behavior and configuration.
- Add a sync, stdio-based plugin that returns allow/deny/pass.
- Reuse `policy.external_auth_profiles` and `external_auth_profile` in delegate rules.
- Support full header action outputs from plugins (request + response).
- Keep the protocol explicit: `pass` continues policy evaluation without header actions.

## Non-goals

- Exec or script-based handlers.
- Async plugins with callbacks.
- Caching, health checks, or load balancing.

## Configuration

### Profile types

Profiles live under `[policy.external_auth_profiles]` and add a `type` field:

- `type = "http"` (default, async approval)
- `type = "plugin"` (sync stdio plugin)

Example:

```toml
[external_auth]
callback_url = "https://proxy.example.com/_acl-proxy/external-auth/callback"

[policy.external_auth_profiles]

[policy.external_auth_profiles.approval_http]
type = "http"               # default if omitted
webhook_url = "https://auth.internal/approval-start"
timeout_ms = 5000
webhook_timeout_ms = 1000
on_webhook_failure = "error"

[policy.external_auth_profiles.url_allow]
type = "plugin"
command = "/usr/local/bin/url-allow"
args = ["--config", "/etc/url-allow.json"]
timeout_ms = 1000
restart_delay_ms = 10000
```

### HTTP profile fields (existing)

- `webhook_url` (string, required)
- `timeout_ms` (integer, required)
- `webhook_timeout_ms` (integer, optional)
- `on_webhook_failure` (`"deny" | "error" | "timeout"`, optional)

### Plugin profile fields (new)

- `command` (string, required)
- `args` (array of strings, optional)
- `timeout_ms` (integer, required)
- `include_headers` (array of strings, optional)
- `include_request_body` (boolean, optional, default false)
- `max_request_body_bytes` (integer, optional, default 10485760)
- `max_decompressed_request_body_bytes` (integer, optional, default 52428800)
- `env` (map of string to string, optional)
- `restart_delay_ms` (integer, optional, default 10000)

### Rule usage

Rules use `action = "delegate"` with `external_auth_profile`:

```toml
[[policy.rules]]
action = "delegate"
pattern = "https://repo.example.com/**"
external_auth_profile = "url_allow"
```

Rules must not set `external_auth_profile` on `allow` or `deny` rules.

### Header action precedence

For allow decisions, apply header actions in this order:

1. Rule `header_actions` (static policy)
2. Plugin `requestHeaders` / `responseHeaders`

This lets the plugin override or remove static defaults when needed.

For pass decisions, do not apply rule or plugin header actions. A plugin response
with `decision = "pass"` and non-empty `requestHeaders` or `responseHeaders` is
a protocol error.

For body-aware plugin profiles, `decision = "allow"` may include a `requestBody`
replacement. `decision = "pass"` must not include `requestBody`.

For deny decisions, plugins may include `denyMessage` to replace the
client-visible JSON `message` in the 403 response. The HTTP status remains fixed
at 403 and the JSON `error` remains `Forbidden`.

### Failure behavior

- Plugin failures (timeout, crash, invalid response) return a 503 error response.
- HTTP profiles continue to follow `on_webhook_failure`.

### Header inclusion

`include_headers` uses simple glob patterns (case-insensitive):

- `authorization` - exact match
- `x-auth-*` - prefix match
- `x-*` - matches any header starting with `x-`

If unset or empty, no headers are sent to the plugin.

### Request body inclusion

When `include_request_body = true`, acl-proxy buffers the outbound request body
before forwarding it upstream. If the request uses `Content-Encoding: gzip`, the
body is decompressed before being sent to the plugin. The plugin receives the
decoded body as base64. On `allow`, the plugin may return a replacement decoded
body; acl-proxy recompresses it when the original request was gzip-compressed and
rebuilds `Content-Length`.

Unsupported request encodings, body read failures, and configured size-limit
violations fail the delegated request before upstream egress. Body-aware
delegation is supported only for synchronous plugin profiles, not HTTP webhook
callback profiles.

## Plugin Protocol (stdio)

The plugin communicates via NDJSON (one JSON object per line).

**Request:**
```json
{
  "id": "req-abc123",
  "type": "request",
  "url": "https://repo.example.com/group/repo.git/info/refs",
  "method": "GET",
  "clientIp": "192.168.1.100",
  "headers": {
    "authorization": "Bearer token"
  },
  "body": {
    "encoding": "base64",
    "contentType": "application/json",
    "contentEncoding": "gzip",
    "data": "eyJwcm9tcHQiOiJkZWNvZGVkIGJvZHkifQ=="
  }
}
```

**Response:**
```json
{
  "id": "req-abc123",
  "type": "response",
  "decision": "allow",
  "requestBody": {
    "encoding": "base64",
    "contentType": "application/json",
    "data": "eyJwcm9tcHQiOiJyZWRhY3RlZCBib2R5In0="
  },
  "requestHeaders": [
    {"action": "remove", "name": "authorization", "when": "if_present"}
  ],
  "responseHeaders": [
    {"action": "set", "name": "x-auth-plugin", "value": "url-allow"}
  ]
}
```

**Header Action Object:**
```json
{
  "action": "set",           // "set", "add", "remove", "replace_substring"
  "name": "header-name",     // case-insensitive
  "value": "single value",   // for set/add
  "values": ["a", "b"],      // for set/add
  "when": "always",          // "always", "if_present", "if_absent"
  "search": "find",          // for replace_substring only
  "replace": "replace"        // for replace_substring only
}
```

Notes:

- `decision` is `"allow"`, `"deny"`, or `"pass"`.
- `headers` may be empty or omitted when no headers are included.
- Header values may be strings; repeated headers may be encoded as arrays.
- `requestHeaders` and `responseHeaders` are applied with `decision = "allow"`;
  they are ignored with `decision = "deny"` and must be empty or omitted with
  `decision = "pass"`.
- `requestBody` is applied only with `decision = "allow"` and must use
  `encoding = "base64"`. It is a decoded replacement body; acl-proxy handles
  recompression and `Content-Length` rebuilding.
- `denyMessage` is applied only with `decision = "deny"`. Blank, oversized, or
  control-character messages fall back to acl-proxy's default plugin-deny
  message.
- Plugins should write only JSON responses to stdout.

## Runtime behavior

- Plugin processes are spawned lazily (on first request) and kept alive.
- Requests are synchronous per request but handled asynchronously by the proxy.
- On process exit, the handler restarts after `restart_delay_ms`.
- Requests during downtime return a 503 error (no queueing).

## Logging

Log entries include:

- Profile name
- Request ID
- URL, method, client IP
- Decision (allow/deny/pass)
- Failure reason (when applicable)

## Demo

Reference plugins live in `demos/auth-plugin-stdio` and
`demos/body-inspection-plugin`.

## Review

Decisions captured in this revision:

- Keep async HTTP external auth unchanged; add a sync stdio plugin mode only.
- Reuse `external_auth_profiles` + `external_auth_profile` on delegate rules.
- Apply rule `header_actions` first, then plugin header actions (plugin can override).
- Treat plugin failures as 503 errors (deny is only on explicit `decision = "deny"`; pass continues policy evaluation).

Open questions and gaps:

- Startup behavior is lazy; if startup-on-boot is preferred, add an eager spawn path.
- No queueing during restarts; decide whether to buffer or fail fast.
- No health checks/metrics beyond logs; add if operational needs require it.
