# Operations

This guide covers runtime behaviors that operators need during deployment and
incident response.

## Startup and validation

- `acl-proxy` validates configuration at startup.
- If logging initialization fails, the proxy still starts but reports the
  logging error to stderr.

## Readiness probe

The HTTP listener exposes a simple readiness endpoint at:

- `GET /{proxy.internal_base_path}/ready`

Behavior:

- Returns `200 OK` with JSON body `{ "status": "ready" }` when the process is
  running and the HTTP listener is reachable.
- The default path is `/_acl-proxy/ready`.
- This endpoint is internal to the proxy and does not require a policy match.

## Reloading configuration

On Unix systems, sending SIGHUP triggers a reload:

```bash
kill -HUP <pid>
```

Behavior:
- The proxy reloads config from the same sources as startup.
- A new `AppState` is built and swapped atomically.
- If reload fails, the previous state remains active.
- Header-action `${NAME}` env placeholders are resolved again during reload. Changing a required
  env var takes effect on the next successful reload; removing one causes the reload to fail and
  keeps the previous running config active.

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

## Chained egress forwarding

When `[proxy.egress.default]` is configured, allowed proxied requests are sent
to the configured egress host:port instead of dialing the original target
directly.

Operational expectations:

- The inter-proxy forwarding leg remains cleartext TCP. Deploy the egress
  destination on a trusted/local network path.
- Forwarding is protocol-aware per request:
  - HTTP/2 requests use h2c on the inner-to-outer hop.
  - HTTP/1.1 requests (including upgrade/WebSocket flows) stay HTTP/1.1.
  - HTTP/2 requests do not silently downgrade when the outer hop cannot
    negotiate HTTP/2.
- The forwarded request keeps the original absolute URI and original `Host`
  header, so the outer proxy still evaluates policy against the real target.
- The usual target for chained deployments is the outer proxy's HTTP explicit
  listener (`proxy.http_port`), not the transparent HTTPS listener.

Loop-prevention guidance:

- If both hops use loop protection, either configure different
  `loop_protection.header_name` values per hop, or disable outbound loop-header
  injection on the inner proxy with `loop_protection.add_header = false`.
- Exempt the outer proxy's listener address/port from any redirect/iptables
  rules that feed traffic into the inner proxy, or the chain can loop back into
  itself before policy is evaluated. For example, if the outer proxy listens on
  `127.0.0.1:8881`, exclude that destination from the inner proxy's REDIRECT
  rules.

TLS and trust guidance:

- Clients still need to trust the proxy CA that terminates their TLS
  connection for CONNECT and transparent HTTPS flows.
- Current egress forwarding does not add TLS on the inter-proxy hop; CA trust
  does not protect the inner-to-outer forwarding leg. Request bodies and any
  sensitive headers injected by inner-proxy header actions travel in cleartext
  on that hop.

Timeout guidance:

- Two-hop forwarding adds an extra connection and policy decision point. If the
  outer proxy performs additional checks or upstreams are slow, raise
  `proxy.request_timeout_ms` (or per-rule `request_timeout_ms`) accordingly.
- As a starting point, set the inner proxy timeout high enough to cover the
  outer proxy timeout plus its upstream work so the inner hop does not mask the
  outer proxy's own timeout/error response.

## External auth timeouts

External auth profiles define `timeout_ms` (decision timeout) and optional
`webhook_timeout_ms` (initial webhook delivery). Failures map to 403/503/504
based on `on_webhook_failure`. See `docs/external-auth.md`.
