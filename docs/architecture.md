# Architecture overview

This document gives a high-level view of the acl-proxy runtime. It is intended
for operators who want to understand how requests flow through the system.

## Components

- HTTP explicit proxy listener (`proxy.http_port`)
- Transparent HTTPS listener (`proxy.https_port`)
- Shared application state (`AppState`) that contains:
  - Config and policy engine
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
3. Evaluate policy (URL, client IP, method).
4. Optional external auth gate.
5. Apply header actions and forward to upstream.
6. Capture/log as configured.

### HTTPS CONNECT (MITM)

1. Accept CONNECT on HTTP listener.
2. Check loop protection header on CONNECT.
3. Establish TLS tunnel using per-host certificate.
4. Parse inner HTTP/1.1 requests.
5. Apply policy/external auth/header actions per request.

### Transparent HTTPS

1. Accept TLS on transparent listener.
2. Select certificate by SNI.
3. Parse decrypted HTTP/1.1 or HTTP/2 requests.
4. Apply policy/external auth/header actions per request.

## Reload and shutdown

- SIGHUP (Unix) reloads configuration and swaps `AppState`.
- Ctrl+C / SIGTERM triggers graceful shutdown.
