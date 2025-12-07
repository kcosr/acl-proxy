# acl-proxy external auth → TermStation adapter demo

This is a minimal Node/TypeScript service that bridges `acl-proxy`'s
`external_auth_profiles` webhooks into TermStation's interactive
notifications API.

## High-level flow

```text
               (agent runs `gh` CLI)
         HTTPS_PROXY=https://localhost:8889

┌───────────────┐                                   ┌───────────────────────────────┐
│   gh CLI      │  (1) HTTPS request (no auth)      │ acl-proxy (transparent HTTPS  │
│ (agent code)  │──────────────────────────────────▶│ listener on :8889)            │
└───────────────┘  https://api.github.com/user      └───────────────┬───────────────┘
                                                                    │
                          approval-required rule matches:           │
                          pattern = "https://api.github.com/**"     │
                          external_auth_profile = "termstation_adapter_demo"
                                                                    │
                                                                    ▼
┌───────────────────────────────┐  (2) POST /webhook  ┌───────────────────────────────┐
│ acl-proxy                     │────────────────────▶│ TermStation adapter (this)    │
│ (holds request, waiting)      │  X-Acl-Proxy-Event: │                               │
└───────────────────────────────┘  pending            └───────────────┬───────────────┘
                                                                      │
                                                      (3) POST /api/notifications
                                                          (Basic auth)
                                                                      │
                                                                      ▼
                                                      ┌───────────────────────────────┐
                                                      │ TermStation backend           │
                                                      │  + TermStation UI client      │
                                                      └───────────────┬───────────────┘
                                                                      │
                                                      (4) user clicks Approve/Deny
                                                          + enters github_token
                                                                      │
                                                                      ▼
┌───────────────────────────────┐                     ┌───────────────────────────────┐
│ TermStation adapter           │◀────────────────────│ TermStation                   │
│                               │  (5) POST           │                               │
└───────────────┬───────────────┘  /termstation/      └───────────────────────────────┘
                │                  callback/:requestId
                │                  { action, inputs: { github_token } }
                │
                │  (6) POST /_acl-proxy/external-auth/callback
                │      { requestId, decision, macros: { github_token } }
                │
                ▼
┌───────────────────────────────┐                     ┌───────────────────────────────┐
│ acl-proxy                     │  (7) HTTPS request  │ api.github.com                │
│ (resumes original request)    │────────────────────▶│                               │
└───────────────────────────────┘  Authorization:     └───────────────────────────────┘
                                   token <github_token>
                                   (injected via header_actions)
```

When an approval-required rule matches in `acl-proxy`, the proxy:

- Sends a webhook to this adapter with the pending request details.
- Waits for a callback decision.

The adapter:

- Exposes `POST /webhook` for `acl-proxy` to call.
- For each `"pending"` webhook, creates an interactive notification in
  TermStation via `/api/notifications`.
- For terminal lifecycle status webhooks (`"timed_out"`, `"webhook_failed"`,
  `"error"`, or `"cancelled"`), best-effort cancels the corresponding
  TermStation notification using the `/api/notifications/{id}/cancel`
  endpoint, including the webhook `reason` (if present) in the JSON body.
- Lets the TermStation user click **Approve** or **Deny** and enter a GitHub
  token.
- Receives the TermStation interactive callback and forwards the decision
  (and token) to the `callbackUrl` provided in the `acl-proxy` webhook
  payload. This adapter **requires** that `callbackUrl` is present in the
  webhook (that is, `[external_auth].callback_url` must be configured in
  `acl-proxy`).

This demo is intentionally focused on a single macro (`github_token`) to
support "Allow agent to use GitHub credentials?" flows.

## Data shapes

### 1. acl-proxy → adapter: pending webhook

Request:

```http
POST /webhook HTTP/1.1
Host: localhost:3000
Content-Type: application/json
X-Acl-Proxy-Event: pending
```

Payload (subset of fields):

```json
{
  "requestId": "req-123",
  "profile": "termstation_adapter_demo",
  "ruleIndex": 0,
  "ruleId": "github-allow-mfa",
  "url": "https://api.github.com/user",
  "method": "GET",
  "clientIp": "127.0.0.1",
  "callbackUrl": "http://localhost:8881/_acl-proxy/external-auth/callback",
  "status": "pending",
  "macros": [
    {
      "name": "github_token",
      "label": "GitHub token",
      "required": true,
      "secret": true
    }
  ]
}
```

The adapter **requires** `callbackUrl` to be present and starting with
`http`/`https`.

### 2. Adapter → TermStation: interactive notification

Request:

```http
POST /api/notifications HTTP/1.1
Host: localhost:6624
Content-Type: application/json
Authorization: Basic d2ViaG9va3M6d2ViaG9vaG9rcw==
```

Payload (simplified):

```json
{
  "type": "info",
  "title": "Agent needs your permission",
  "message": "GET https://api.github.com/user",
  "sound": true,
  "actions": [
    {
      "key": "allow",
      "label": "Approve",
      "style": "primary",
      "requires_inputs": ["github_token"]
    },
    {
      "key": "deny",
      "label": "Deny",
      "style": "secondary"
    }
  ],
  "inputs": [
    {
      "id": "github_token",
      "label": "Token",
      "type": "secret",
      "required": true
    }
  ],
  "callback_url": "http://localhost:3000/termstation/callback/req-123",
  "callback_method": "POST"
}
```

TermStation renders this as an interactive notification with **Approve** /
**Deny** buttons and a single `Token` secret input.

### 3. TermStation → adapter: interactive callback

When the user clicks **Approve**:

```http
POST /termstation/callback/req-123 HTTP/1.1
Host: localhost:3000
Content-Type: application/json
```

Payload (subset):

```json
{
  "notification_id": "n-abc",
  "user": "webhooks",
  "action": "allow",
  "inputs": {
    "github_token": "ghp_XXXXXXXXXXXXXXXXXXXX"
  }
}
```

When the user clicks **Deny**, the adapter receives `action: "deny"` and
typically no `inputs`.

### 4. Adapter → acl-proxy: external auth callback

The adapter forwards the decision to `callbackUrl` from the original
webhook:

```http
POST /_acl-proxy/external-auth/callback HTTP/1.1
Host: localhost:8881
Content-Type: application/json
```

Payload:

```json
{
  "requestId": "req-123",
  "decision": "allow",
  "macros": {
    "github_token": "ghp_XXXXXXXXXXXXXXXXXXXX"
  }
}
```

For a deny decision:

```json
{
  "requestId": "req-123",
  "decision": "deny"
}
```

## Prerequisites

- Node.js 18+ (required for the built-in `fetch` API).
- `npm` to install dependencies.
- A running TermStation backend (for example at
  `http://localhost:6624`) with `/api/notifications` enabled.

## Install and run

From the repository root:

```sh
cd demos/external-auth-termstation-adapter
npm install
npm run build
npm start
```

By default, the adapter listens on `http://localhost:3000`.

## Configuration

Environment variables:

- `PORT` (default: `3000`)
  - Port for the adapter HTTP server.

- `ADAPTER_PUBLIC_BASE_URL`
  - Base URL that TermStation should call back to.
  - Defaults to `http://localhost:${PORT}`.

- `TERMSTATION_NOTIFICATIONS_URL`
  - Full URL for TermStation's notifications API.
  - Defaults to `http://localhost:6624/api/notifications`.

- `TERMSTATION_BASIC_USER` / `TERMSTATION_BASIC_PASS`
  - Basic auth credentials for TermStation.
  - Defaults to `webhooks` / `webhoooks`.

## Wiring it up with acl-proxy

In your `acl-proxy` config, define an external auth profile that points at
the adapter and attach it to an allow rule. For example:

```toml
[external_auth]
# Required so that acl-proxy includes callbackUrl in the webhook payload.
callback_url = "http://localhost:8881/_acl-proxy/external-auth/callback"

[policy.approval_macros]
github_token = { label = "GitHub token", required = true, secret = true }

[policy.external_auth_profiles]

[policy.external_auth_profiles.termstation_adapter_demo]
webhook_url = "http://localhost:3000/webhook"
timeout_ms = 15000
webhook_timeout_ms = 2000
on_webhook_failure = "error"

[[policy.rules]]
action = "allow"
pattern = "https://api.github.com/**"
description = "GitHub API with TermStation approval"
external_auth_profile = "termstation_adapter_demo"

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "authorization"
value = "token {{github_token}}"
```

Then:

1. Start `acl-proxy` with this config.
2. Start TermStation (for example on `http://localhost:6624`).
3. Start the adapter (`npm start` as above).
4. Use the TermStation UI as user `webhooks` (or whichever user your
   Basic auth credentials map to).
5. Send a request through `acl-proxy` that matches the approval-required
   rule (for example, using `curl` configured to use the proxy).

When the rule matches, TermStation should display an interactive
notification:

- Title: `Agent needs your permission`
- Message: the HTTP method and URL being proxied.
- Inputs: a single `Token` field (secret).
- Actions: **Approve** and **Deny**.

Clicking **Approve** with a non-empty token sends the callback to
`acl-proxy`, which then proxies the request upstream. Clicking **Deny**
denies the original request.

## Limitations and future work

### Broadcast notifications

Currently, this adapter creates user-scoped notifications (no `session_id`),
meaning each pending request results in a single notification to a single
user. TermStation also supports broadcast notifications via `session_id`,
which would send the same notification to multiple users.

To support broadcast notifications, the adapter would need changes:

1. **Store multiple notification IDs per request.** Change `notificationId`
   from a single string to an array:

   ```typescript
   type PendingRequestState = {
     callbackUrl: string;
     macros: MacroDescriptor[];
     notificationIds: string[];  // instead of notificationId?: string
   };
   ```

2. **Parse the broadcast response.** When creating with `session_id`,
   TermStation returns:

   ```json
   {
     "recipients": ["alice", "bob"],
     "notifications": [
       { "id": "notif-1", ... },
       { "id": "notif-2", ... }
     ]
   }
   ```

   Extract all IDs from the `notifications` array.

3. **Cancel all notifications on resolution.** When a request is resolved
   (either by a status webhook like `timed_out`/`cancelled`, or by a user
   responding), cancel all outstanding notifications:

   ```typescript
   for (const id of state.notificationIds) {
     void cancelTermStationNotification(id, reason).catch(...);
   }
   ```

4. **Exclude the responding notification on callback.** When a user responds,
   cancel only the *other* notifications (the responding one is already
   resolved):

   ```typescript
   const otherIds = state.notificationIds.filter(id => id !== body.notification_id);
   for (const id of otherIds) {
     void cancelTermStationNotification(id, "Resolved by another user").catch(...);
   }
   ```

This ensures that when any user approves or denies (or the request times out),
all other users' notifications are cleaned up.
