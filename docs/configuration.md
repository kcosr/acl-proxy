# Configuration

acl-proxy is configured using a single TOML file. The configuration controls
listeners, logging, capture, certificates, TLS, and the policy engine.

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
[logging]
[capture]
[loop_protection]
[certificates]
[tls]
[external_auth]
[policy]
```

See `docs/config-reference.md` for full field-level details.
