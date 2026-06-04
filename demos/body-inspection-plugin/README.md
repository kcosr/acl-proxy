# Body inspection plugin demo

This demo is a stdio auth plugin for prototyping body-aware delegation. It reads
acl-proxy plugin request messages from stdin, inspects the decoded request body,
and returns `allow`, `deny`, or `allow` with a redacted replacement body.

## Plugin behavior

- Reads NDJSON request messages on stdin.
- Expects `include_request_body = true` so acl-proxy sends `body.data` as
  decoded base64 content.
- Supports ordered `literal` and `regex` rules.
- `deny` rules stop processing and block the request. They may include a
  `denyMessage` returned to acl-proxy for the client-visible JSON `message`.
- `redact` rules replace every match and return `requestBody` on `allow`.
- Redactions preserve match length by default.
- Text bodies are interpreted as UTF-8. Binary bodies use `binaryDecision`.

The plugin writes diagnostics to stderr only. Stdout is reserved for protocol
responses.

## Configure acl-proxy

```toml
[policy.external_auth_profiles.body_guard]
type = "plugin"
command = "/path/to/demos/body-inspection-plugin/body_guard.py"
args = ["--config", "/path/to/demos/body-inspection-plugin/body_guard.json"]
timeout_ms = 3000
include_headers = ["content-type"]
include_request_body = true
max_request_body_bytes = 10485760
max_decompressed_request_body_bytes = 52428800

[[policy.rules]]
action = "delegate"
pattern = "https://api.example-ai.com/**"
external_auth_profile = "body_guard"
allow_upgrades = false
```

The body guard runs only for requests that match this `delegate` rule. The
profile limits default to 10 MiB for the encoded request body and 50 MiB after
gzip decompression. `allow_upgrades = false` blocks HTTP/1.1 upgrade handshakes
for the protected endpoint before the plugin or upstream receives them.

## Plugin config

Example `body_guard.json`:

```json
{
  "binaryDecision": "allow",
  "rules": [
    {
      "name": "deny-api-key",
      "action": "deny",
      "type": "regex",
      "value": "(?i)\\b(api[_-]?key|secret[_-]?key)\\b\\s*[:=]",
      "denyMessage": "Request blocked because it appears to contain an API key."
    },
    {
      "name": "redact-password",
      "action": "redact",
      "type": "regex",
      "value": "(?i)\\bpassword\\b\\s*[:=]\\s*[^\\s,}\"]+",
      "preserveLength": true,
      "redactionChar": "*"
    },
    {
      "name": "redact-internal-codename",
      "action": "redact",
      "type": "literal",
      "value": "Project Vulcan",
      "caseSensitive": false,
      "preserveLength": true,
      "redactionChar": "#"
    }
  ]
}
```

Rule fields:

- `name`: label returned in `x-acl-proxy-body-guard` on matched allow responses.
- `action`: `deny` or `redact`.
- `type`: `literal` or `regex`.
- `value`: literal string or Python regex.
- `caseSensitive`: literal-only boolean, default `true`.
- `denyMessage`: deny-only client-visible message; acl-proxy uses its default
  deny message when omitted.
- `flags`: regex-only list of `ignore_case`, `multiline`, or `dotall`.
- `preserveLength`: redact-only boolean, default `true`.
- `redactionChar`: one-character replacement used when preserving length.
- `replacement`: replacement string used when `preserveLength = false`.

## Run the plugin

```bash
./demos/body-inspection-plugin/body_guard.py \
  --config ./demos/body-inspection-plugin/body_guard.json
```

The plugin stays running and processes requests over stdin/stdout. When running
under acl-proxy, it is spawned automatically.
