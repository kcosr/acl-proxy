# CLI reference

## Main binary: `acl-proxy`

Usage:

```bash
acl-proxy [--config <path>] [command]
```

Commands:

- Run the proxy (default when no command is given):

```bash
acl-proxy --config config/acl-proxy.toml
```

- Validate configuration:

```bash
acl-proxy config validate --config config/acl-proxy.toml
```

- Initialize a minimal config:

```bash
acl-proxy config init config/acl-proxy.toml
```

- Inspect the effective policy:

```bash
acl-proxy policy dump --config config/acl-proxy.toml
acl-proxy policy dump --format table --config config/acl-proxy.toml
acl-proxy policy dump --format json --config config/acl-proxy.toml
```

`policy dump` defaults to table output on a TTY and JSON otherwise.

## Helper binary: `acl-proxy-extract-capture-body`

Decode the body payload from a capture JSON file:

```bash
acl-proxy-extract-capture-body logs-capture/req-123-res.json > body.bin
```

Errors are reported for invalid JSON, missing bodies, or unsupported encodings.
