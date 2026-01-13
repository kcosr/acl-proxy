# Auth plugin (stdio) demo

This demo shows a minimal stdio auth plugin that allows or denies requests
based on URL patterns.

## Plugin behavior

- Reads NDJSON request messages on stdin.
- Matches the request URL against an allowlist of glob patterns.
- Returns `decision = "allow"` or `decision = "deny"`.

## Configure acl-proxy

```toml
[policy.external_auth_profiles.url_allow]
type = "plugin"
command = "/path/to/url_allow.py"
args = ["--config", "/path/to/url_allow.json"]
timeout_ms = 1000

[[policy.rules]]
action = "allow"
pattern = "https://repo.example.com/**"
external_auth_profile = "url_allow"
```

## Plugin config

Example `url_allow.json`:

```json
{
  "allow": [
    "https://repo.example.com/**",
    "https://packages.example.com/public/**"
  ]
}
```

## Run the plugin

```bash
./demos/auth-plugin-stdio/url_allow.py --config ./demos/auth-plugin-stdio/url_allow.json
```

The plugin stays running and processes requests over stdin/stdout. When
running under acl-proxy, it is spawned automatically.
