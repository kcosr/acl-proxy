# Configuration

acl-proxy is configured using a single TOML file. The configuration controls
listeners, optional egress forwarding, logging, capture, certificates, TLS,
and the policy engine.

## Config file location

The proxy resolves the config path in this order:

1. `--config <path>`
2. `ACL_PROXY_CONFIG` environment variable
3. `config/acl-proxy.toml` (relative to the current working directory)

If the default path is missing, the CLI suggests running:

```bash
acl-proxy config init config/acl-proxy.toml
```

## Environment overrides

After parsing the file, these overrides are applied:

- `PROXY_PORT` - overrides `[proxy].http_port` when set to a valid `u16`
- `PROXY_HOST` - overrides `[proxy].bind_address` when non-empty
- `LOG_LEVEL` - overrides `[logging].level` when non-empty

## Header-action env placeholders

Policy header actions also support a separate load-time env interpolation path for `set` / `add`
`value` and `values[*]` entries:

```toml
[[policy.rules.header_actions]]
direction = "request"
action = "set"
name = "authorization"
value = "${API_TOKEN}"
```

Rules:

- Interpolation happens once when the config is loaded or reloaded.
- Only exact whole-string placeholders are supported: `${NAME}`.
- `NAME` must match `[A-Za-z_][A-Za-z0-9_]*`.
- Mixed strings such as `Bearer ${TOKEN}` are rejected instead of partially interpolated.
- Missing env vars fail `acl-proxy config validate`, startup, `policy dump`, and reload.
- Approval macros using `{{name}}` are a separate feature and are not rewritten by this pass.
- Existing literal `${...}` strings in affected `set` / `add` header-action fields are now
  reserved syntax and must be migrated before rollout.

## Minimal configuration

The generated default config is intentionally small:

```toml
schema_version = "1"

[proxy]
bind_address = "0.0.0.0"
http_port = 8881
https_bind_address = "0.0.0.0"
https_port = 8889
request_timeout_ms = 30000
internal_base_path = "/_acl-proxy"

[logging]
level = "info"

[policy]
default = "deny"
```

Start with this and expand as needed.

## Top-level sections

```toml
schema_version = "1"

[proxy]
[proxy.egress]
[logging]
[capture]
[loop_protection]
[certificates]
[tls]
[external_auth]
[policy]
```

`[proxy.egress.default]` is an additive schema v1 section. Adding it does not
change `schema_version`; omitting it keeps direct-to-origin forwarding behavior.
When enabled, it sends allowed proxied traffic to a fixed forwarding
destination instead of dialing the original target directly.

See `docs/config-reference.md` for full field-level details.
