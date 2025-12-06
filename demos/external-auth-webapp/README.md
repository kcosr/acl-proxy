# acl-proxy external auth demo webapp

This is a minimal Node/TypeScript web application that demonstrates how to
integrate with `acl-proxy`'s `external_auth_profiles` feature using a simple
browser UI.

When an approval-required rule matches in `acl-proxy`, the proxy:

- Sends a webhook to this app with the pending request details.
- Waits for a callback decision.

The app:

- Exposes `POST /webhook` for `acl-proxy` to call.
- Maintains an in-memory list of pending approvals.
- Pushes new approvals to connected browsers over WebSocket.
- Lets a user click **Approve** or **Deny** in the browser and, for rules
  that define approval macros, fill in any required macro values.
- Sends the callback decision (including any approved macro values) to the
  `callbackUrl` provided in the webhook payload when present, falling back to
  calling `/_acl-proxy/external-auth/callback` on the configured proxy base URL
  for older `acl-proxy` versions.

## Prerequisites

- Node.js 18+ (required for the built-in `fetch` API used in the server).
- `npm` or `yarn` to install dependencies.

## Install and run

From the repository root:

```sh
cd demos/external-auth-webapp
npm install
npm run build
npm start
```

By default, the app listens on `http://localhost:3000` and serves a tiny UI at
that address. It expects `acl-proxy`'s HTTP listener to be reachable at
`http://localhost:8881` so it can call the callback endpoint when a webhook
does not include a `callbackUrl` field.

You can override the proxy base URL or the app port via environment variables:

```sh
ACL_PROXY_BASE=http://localhost:8881 PORT=3000 npm start
```

## Wiring it up with acl-proxy

In your `acl-proxy` config, define an external auth profile that points at the
demo app and attach it to an allow rule. For example:

```toml
[policy.approval_macros]
github_token = { label = "GitHub token", required = true, secret = true }
reason       = { label = "Approval reason", required = false, secret = false }

[policy.external_auth_profiles]

[policy.external_auth_profiles.web_ui_demo]
webhook_url = "http://localhost:3000/webhook"
timeout_ms = 15000
webhook_timeout_ms = 2000
on_webhook_failure = "error"

[[policy.rules]]
action = "allow"
pattern = "https://api.github.com/**"
description = "GitHub API with web UI approval and macros"
external_auth_profile = "web_ui_demo"

[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "authorization"
value = "token {{github_token}}"

[[policy.rules.header_actions]]
direction = "request"
action = "add"
name = "x-approval-reason"
value = "{{reason}}"

[external_auth]
# Full URL external auth services (including this demo app) should use when
# calling back into this proxy instance.
callback_url = "http://localhost:8881/_acl-proxy/external-auth/callback"
```

Then:

1. Start `acl-proxy` with this config.
2. Start the demo webapp (`npm start` as above).
3. Open `http://localhost:3000/` in your browser.
4. Send a request through `acl-proxy` that matches the approval-required rule
   (for example, using `curl` configured to use the proxy).

When the rule matches, the app should display a new pending approval in the
browser. Clicking **Approve** or **Deny** sends the callback to `acl-proxy`,
which then either proxies the request upstream or returns a synthetic deny /
timeout / error response according to its configuration. When the webhook
payload includes a `callbackUrl`, the demo app prefers that URL; otherwise it
falls back to `ACL_PROXY_BASE + "/_acl-proxy/external-auth/callback"` so it
continues to work with older `acl-proxy` versions.
