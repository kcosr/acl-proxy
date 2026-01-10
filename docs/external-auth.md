# External authentication (approval workflows)

External auth turns allow rules into approval-required rules. When such a rule
matches, the proxy pauses the request, sends a webhook to an external service,
and waits for a callback decision.

## Configuration overview

```toml
[external_auth]
callback_url = "https://proxy.example.com/_acl-proxy/external-auth/callback"

[policy.external_auth_profiles]
[policy.external_auth_profiles.github_mfa]
webhook_url = "https://auth.internal/github/mfa-start"
timeout_ms = 5000
webhook_timeout_ms = 1000
on_webhook_failure = "error" # deny | error | timeout

[[policy.rules]]
action = "allow"
pattern = "https://api.github.com/**"
external_auth_profile = "github_mfa"
rule_id = "github-allow-mfa"
```

Notes:
- `external_auth.callback_url` is optional but recommended. It must be a full
  absolute URL with a host.
- `external_auth_profile` is only allowed on `action = "allow"` rules.

## Pending webhook

When a rule with `external_auth_profile` matches, the proxy POSTs a webhook:

- URL: `policy.external_auth_profiles.<name>.webhook_url`
- Header: `X-Acl-Proxy-Event: pending`

Payload fields include:
- `requestId`, `profile`, `ruleIndex`, optional `ruleId`
- `url`, `method`, `clientIp`
- `status: "pending"`, `terminal: false`
- `timestamp` (RFC3339), `elapsedMs`, `eventId`
- `callbackUrl` when `[external_auth].callback_url` is configured
- `macros` describing approval macro descriptors (if any)

## Terminal status webhook

For terminal lifecycle events, the proxy emits a best-effort status webhook:

- Header: `X-Acl-Proxy-Event: status`
- `status`: `webhook_failed`, `timed_out`, `error`, or `cancelled`
- `terminal: true`
- `reason` and optional `failureKind` / `httpStatus`

Status webhooks are telemetry only; failures do not affect the allow/deny
outcome.

## Callback endpoint

The proxy exposes a callback endpoint on the HTTP listener:

```
POST /{internal_base_path}/external-auth/callback
Content-Type: application/json

{
  "requestId": "req-...",
  "decision": "allow" | "deny",
  "macros": {
    "github_token": "ghp_...",
    "reason": "Approving for test"
  }
}
```

Behavior:
- `200 OK` with `{ "status": "ok" }` on success.
- `404 Not Found` if `requestId` is unknown or already completed.
- `400 Bad Request` if the body is invalid or required macros are missing.

Macro validation rules:
- Required macros must be present and non-empty.
- Values must not contain control characters (ASCII < 0x20 or DEL).
- Optional macros may be omitted or empty.

## Approval macros

Header actions may include `{{name}}` placeholders. These placeholders define
approval macros that the external approver must supply on allow decisions.
Descriptors are configured in `policy.approval_macros`:

```toml
[policy.approval_macros]
github_token = { label = "GitHub token", required = true, secret = true }
reason       = { label = "Approval reason", required = false, secret = false }
```

During approval:
- The proxy describes these macros in the pending webhook.
- On allow, the callback supplies values.
- The proxy interpolates the values into header actions before forwarding the
  request upstream.

## Failure handling

`on_webhook_failure` controls what happens if the initial webhook fails:

- `deny` - respond `403 Forbidden`.
- `error` - respond `503 Service Unavailable` with an external auth error.
- `timeout` - respond `504 Gateway Timeout`.

## Security note

The callback endpoint does not authenticate requests. Restrict access to
`/{internal_base_path}/external-auth/callback` using network policy or other
controls.
