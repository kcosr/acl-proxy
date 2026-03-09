# Troubleshooting

## HTTP 400 Bad Request

Common causes:
- HTTP listener received an origin-form request without a valid `Host` header.
- HTTP explicit-proxy clients sent an invalid request-target (for example, missing scheme/host).
- Transparent HTTPS requests missing or invalid `Host` header.
- CONNECT requests missing a valid `host:port` authority.

## HTTP 403 Forbidden

- The request was denied by policy.
- External auth returned a deny decision.

Check your `policy.rules` ordering and patterns.

## HTTP 502 Bad Gateway

- The proxy could not connect to the upstream origin.
- The upstream closed the connection before responding.

Confirm upstream reachability and DNS resolution.

## HTTP 504 Gateway Timeout

- Upstream request timed out (`proxy.request_timeout_ms` or rule override).
- External auth decision timed out (`timeout_ms`).

Adjust timeouts or check upstream latency and external auth responsiveness.

## HTTP 503 Service Unavailable

- External auth webhook failed and `on_webhook_failure = "error"`.
- Internal external auth processing failed.

Check the external auth service availability and logs.

## HTTP 508 Loop Detected

Loop protection found the loop header in the inbound request. Remove the
header from clients or disable loop protection if appropriate.

## TLS errors

- Clients must trust the proxy CA for CONNECT and transparent HTTPS modes.
- Use `--proxy-cacert certs/ca-cert.pem` or `--cacert certs/ca-cert.pem`.
- If upstream TLS verification fails, check `tls.verify_upstream` and
  confirm upstream certificates are valid.

## Missing configuration file

If you see "No configuration file found", create one with:

```bash
acl-proxy config init config/acl-proxy.toml
```

## Config validation fails on `${...}` header-action values

Common messages:
- `references missing env var 'NAME'`
- `uses invalid env interpolation syntax`

Checks:
- Export required env vars in the same environment used for `acl-proxy config validate`,
  startup, and reload.
- Use exact whole-string placeholders only: `${NAME}`.
- Do not use mixed strings such as `Bearer ${TOKEN}` in `set` / `add` header-action values.
