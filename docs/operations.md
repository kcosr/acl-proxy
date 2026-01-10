# Operations

This guide covers runtime behaviors that operators need during deployment and
incident response.

## Startup and validation

- `acl-proxy` validates configuration at startup.
- If logging initialization fails, the proxy still starts but reports the
  logging error to stderr.

## Reloading configuration

On Unix systems, sending SIGHUP triggers a reload:

```bash
kill -HUP <pid>
```

Behavior:
- The proxy reloads config from the same sources as startup.
- A new `AppState` is built and swapped atomically.
- If reload fails, the previous state remains active.

## Graceful shutdown

- Ctrl+C triggers a graceful shutdown on all platforms.
- On Unix, SIGTERM triggers graceful shutdown.

The proxy stops accepting new connections. In-flight requests continue using
existing state until they finish.

## Loop protection

Loop protection rejects any request that already contains the configured header
(default `x-acl-proxy-request-id`). When triggered, the proxy returns:

- Status: `508 Loop Detected`
- JSON body: `{ "error": "LoopDetected", "message": "Proxy loop detected via loop protection header" }`

Loop checks run on HTTP explicit requests, CONNECT requests, decrypted CONNECT
requests, and transparent HTTPS requests.

## Upstream timeouts

- `proxy.request_timeout_ms` sets the default upstream timeout.
- Rules can override with `request_timeout_ms`.
- `0` disables the timeout.

When the timeout expires, the proxy responds with `504 Gateway Timeout`.

## External auth timeouts

External auth profiles define `timeout_ms` (decision timeout) and optional
`webhook_timeout_ms` (initial webhook delivery). Failures map to 403/503/504
based on `on_webhook_failure`. See `docs/external-auth.md`.
