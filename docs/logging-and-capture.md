# Logging and capture

acl-proxy emits structured logs and can optionally capture request/response
records to JSON files.

## Logging

```toml
[logging]
level = "info"
directory = "logs"
max_bytes = 104857600
max_files = 5
console = true

[logging.policy_decisions]
log_allows = false
log_denies = true
level_allows = "info"
level_denies = "warn"
```

Notes:
- When `logging.directory` is set, logs go to `acl-proxy.log` and rotate by size.
- Log writing is non-blocking; when the internal buffer is full, entries are
  dropped to avoid stalling requests.
- Policy decision logs include `request_id`, `url`, `client_ip`, and rule
  metadata on the `acl_proxy::policy` target.

## Capture

```toml
[capture]
allowed_request = false
allowed_response = false
denied_request = false
denied_response = false
directory = "logs-capture"
filename = "{requestId}-{suffix}.json"
```

Capture behavior:
- Each captured request and response is written as a JSON file.
- `mode` indicates `http_proxy`, `https_connect`, or `https_transparent`.
- `decision` indicates `allow` or `deny`.
- Bodies are recorded up to 64 KiB; the full logical length is stored in
  `body.length` even when truncated.

Capture happens for:
- Allowed requests/responses when the corresponding flags are enabled.
- Denied requests/responses for policy or loop protection when the denied flags
  are enabled.
- Upstream failures (502/504) as allowed traffic when capture is enabled.

## Capture record format

Each JSON record includes (subset):
- `timestamp`, `requestId`, `kind`, `decision`, `mode`
- `url`, `method`, `httpVersion`
- `statusCode` / `statusMessage` for responses
- `client` and optional `target` endpoints
- `headers` as lowercase keys
- Optional `body` with base64 data

For the full schema, see `docs/config-reference.md`.

## Extract captured bodies

The helper binary decodes base64 body payloads:

```bash
acl-proxy-extract-capture-body /path/to/capture.json > body.bin
```

It reports errors for invalid JSON, missing bodies, or unsupported encodings.
