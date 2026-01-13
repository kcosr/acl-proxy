# Auth Plugins Design

## Overview

External auth profiles now support two modes:

- `http`: the existing async approval flow (webhook + callback).
- `plugin`: a long-running stdio process that returns allow/deny with optional
  request/response header actions.

This keeps the existing `external_auth_profile` rule wiring intact while
introducing a synchronous, per-request authorization plugin for cases like
URL allowlists or repo ACLs.

## Goals

- Preserve current async HTTP external auth behavior and configuration.
- Add a sync, stdio-based plugin that returns allow/deny.
- Reuse `policy.external_auth_profiles` and `external_auth_profile` in rules.
- Support full header action outputs from plugins (request + response).
- Keep the change minimal and backwards compatible.

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
- `env` (map of string to string, optional)
- `restart_delay_ms` (integer, optional, default 10000)

### Rule usage

Rules continue to use `external_auth_profile` and `action = "allow"`:

```toml
[[policy.rules]]
action = "allow"
pattern = "https://repo.example.com/**"
external_auth_profile = "url_allow"
```

Rules must not set `external_auth_profile` on deny rules.

### Header action precedence

For allow decisions, apply header actions in this order:

1. Rule `header_actions` (static policy)
2. Plugin `requestHeaders` / `responseHeaders`

This lets the plugin override or remove static defaults when needed.

### Failure behavior

- Plugin failures (timeout, crash, invalid response) return a 503 error response.
- HTTP profiles continue to follow `on_webhook_failure`.

### Header inclusion

`include_headers` uses simple glob patterns (case-insensitive):

- `authorization` - exact match
- `x-auth-*` - prefix match
- `x-*` - matches any header starting with `x-`

If unset or empty, no headers are sent to the plugin.

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
  }
}
```

**Response:**
```json
{
  "id": "req-abc123",
  "type": "response",
  "decision": "allow",
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

- `headers` may be empty or omitted when no headers are included.
- Header values may be strings; repeated headers may be encoded as arrays.
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
- Decision (allow/deny)
- Failure reason (when applicable)

## Demo

A reference plugin (`url_allow`) lives in `demos/auth-plugin-stdio`.

## Review

Decisions captured in this revision:

- Keep async HTTP external auth unchanged; add a sync stdio plugin mode only.
- Reuse `external_auth_profiles` + `external_auth_profile` on allow rules.
- Apply rule `header_actions` first, then plugin header actions (plugin can override).
- Treat plugin failures as 503 errors (deny is only on explicit `decision = "deny"`).

Open questions and gaps:

- Startup behavior is lazy; if startup-on-boot is preferred, add an eager spawn path.
- No queueing during restarts; decide whether to buffer or fail fast.
- No health checks/metrics beyond logs; add if operational needs require it.
