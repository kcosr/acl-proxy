# acl-proxy

Rust-based ACL-aware HTTP/HTTPS proxy with a TOML configuration file and a
flexible URL policy engine.

Key capabilities:
- HTTP/1.1 explicit proxy (absolute-form requests).
- HTTPS MITM via CONNECT with per-host certificates signed by a local CA.
- Transparent HTTPS listener that terminates TLS directly.
- HTTP/2 support on transparent HTTPS; optional HTTP/2 upstream.
- HTTP/1.1 protocol upgrade tunneling (including WebSocket handshakes).
- Structured logging, policy decision logging, and JSON capture files with
  size-limited bodies.
- Loop protection with configurable header injection.
- Config reload via SIGHUP with atomic state swap.
- External auth webhooks for approval-required rules.
- Helper CLI to decode captured bodies.

## Quick start

Create a config:

```bash
acl-proxy config init config/acl-proxy.toml
```

Validate it:

```bash
acl-proxy config validate --config config/acl-proxy.toml
```

Run the proxy:

```bash
acl-proxy --config config/acl-proxy.toml
```

Send traffic:

```bash
curl -x http://127.0.0.1:8881 http://example.com/

curl -x http://127.0.0.1:8881 https://example.com/ \
  --proxy-cacert certs/ca-cert.pem
```

For a full walkthrough, see `docs/getting-started.md`.

## Documentation

Start with `docs/README.md`, then explore:
- `docs/configuration.md` and `docs/config-reference.md`
- `docs/policy.md`
- `docs/proxy-modes.md`
- `docs/tls-and-certificates.md`
- `docs/logging-and-capture.md`
- `docs/external-auth.md`
- `docs/operations.md`
- `docs/cli.md`
- `docs/troubleshooting.md`

## Sample configuration

The repository includes `acl-proxy.sample.toml` as a comprehensive example.

## Development

See `docs/development.md` for build and test notes.
