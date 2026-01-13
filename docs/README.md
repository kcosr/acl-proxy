# acl-proxy documentation

This documentation is organized for operators running acl-proxy in production or test
infrastructure. Start with the quick start, then move into the configuration and
proxy mode references as needed.

## Start here

- `docs/getting-started.md` - minimal setup, config init, and first requests
- `docs/configuration.md` - config file location, overrides, and defaults
- `docs/config-reference.md` - complete configuration reference
- `docs/policy.md` - policy engine concepts, rules, macros, and header actions
- `docs/proxy-modes.md` - HTTP explicit proxy, HTTPS CONNECT MITM, and transparent HTTPS
- `docs/tls-and-certificates.md` - CA behavior, per-host certs, and client trust
- `docs/logging-and-capture.md` - logging, capture files, and body extraction
- `docs/external-auth.md` - approval workflows, webhooks, and callbacks
- `docs/operations.md` - reloads, shutdown, timeouts, and loop protection
- `docs/cli.md` - CLI reference for `acl-proxy` and helpers
- `docs/troubleshooting.md` - common errors and how to fix them

## Deep dives

- `docs/architecture.md` - internal architecture and request flows
- `docs/development.md` - build/test notes for contributors

## Examples and demos

- `acl-proxy.sample.toml` - comprehensive sample configuration
- `demos/external-auth-webapp/README.md` - minimal approval web UI demo
- `demos/external-auth-termstation-adapter/README.md` - TermStation adapter demo
- `demos/auth-plugin-stdio/README.md` - stdio auth plugin demo
