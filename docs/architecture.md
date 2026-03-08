# Architecture overview

This document gives a high-level view of the acl-proxy runtime. It is intended
for operators who want to understand how requests flow through the system.

## Components

- HTTP explicit proxy listener (`proxy.http_port`)
- Transparent HTTPS listener (`proxy.https_port`)
- Shared application state (`AppState`) that contains:
  - Config and policy engine
  - Optional default egress forwarding destination
  - Certificate manager (CA + per-host certs)
  - Loop protection settings
  - Logging settings
  - External auth manager
  - Shared HTTP client

State is wrapped in `ArcSwap` to allow atomic reloads.

## Request flow (summary)

### HTTP explicit

1. Accept HTTP/1.1 request (absolute-form).
2. Check loop protection header.
3. Evaluate policy (URL, client IP, method, and inbound request-header predicates such as `headers_absent`).
4. Optional external auth gate.
5. Apply header actions and forward to upstream.
6. When `proxy.egress.default` is set, dial the configured egress destination
   instead of the original target while preserving the original URI and `Host`
   header.
7. Capture/log as configured.

### HTTPS CONNECT (MITM)

1. Accept CONNECT on HTTP listener.
2. Check loop protection header on CONNECT.
3. Establish TLS tunnel using per-host certificate.
4. Parse inner HTTP/1.1 requests.
5. Apply policy/external auth/header actions per decrypted request.
6. If egress forwarding is enabled, apply it only to the decrypted inner
   requests. The outer CONNECT handshake is unchanged, so request-header
   predicates such as `headers_absent` apply only to the inner requests.

### Transparent HTTPS

1. Accept TLS on transparent listener.
2. Select certificate by SNI.
3. Parse decrypted HTTP/1.1 or HTTP/2 requests.
4. Apply policy/external auth/header actions per request, including any request-header predicates.
5. If egress forwarding is enabled, dial the configured egress destination for
   allowed requests while keeping policy/capture metadata tied to the original
   target.

## Reload and shutdown

- SIGHUP (Unix) reloads configuration and swaps `AppState`.
- Ctrl+C / SIGTERM triggers graceful shutdown.
