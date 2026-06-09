# Native Request Redaction

## Summary

Add a shared native redaction facility configured with TOML profiles and attached to allow/delegate policy rules. This replaces the WebSocket-specific redaction contract with a transport-neutral `redaction_profile` rule field. The feature redacts outbound/request-side data only: normal HTTP request bodies before upstream forwarding, and WebSocket client-to-upstream data messages after a successful HTTP/1.1 upgrade.

## Configuration

Profiles live under `[redaction.profiles.<name>]`; names are arbitrary operator-defined identifiers.

```toml
[redaction.profiles.secrets]
replacement = "[REDACTED]"
max_body_bytes = 10485760
max_decoded_body_bytes = 52428800
max_frame_bytes = 262144
max_message_bytes = 1048576
allow_permessage_deflate = false
unsupported_extensions = "deny" # deny | strip

[[redaction.profiles.secrets.rules]]
literals = ["password", "api-token"]
expressions = ["(?i)bearer\\s+[a-z0-9._-]+"]
match = "text" # text | binary | both
```

Policy rules reference a profile with:

```toml
redaction_profile = "secrets"
```

`redaction_profile` is valid only on `allow` and `delegate` rules. Denied rules never forward payload data, so they cannot redact.

## Matching and Replacement

- Rules can contain `literals`, `expressions`, or both; at least one matcher is required per rule.
- Literals are exact byte/string matches.
- Expressions use Rust `regex` syntax and are compiled during config validation.
- `replacement` is fixed per profile and may have any length. Replacements are no longer required to match the matched text length because both HTTP request bodies and WebSocket data messages are fully buffered before rewriting.
- For text matches, the decoded payload must be valid UTF-8 before expression matching. Literal matching may still operate on bytes.

## HTTP Behavior

For a matched non-upgrade request, acl-proxy buffers the outbound request body, decompresses supported `Content-Encoding` values, applies native redaction in-process, recompresses with the original encoding, updates body headers, and forwards upstream. This mirrors the existing body-aware plugin body pipeline, but no plugin process receives or mutates the body.

Unsupported encodings, oversized encoded bodies, oversized decoded bodies, invalid UTF-8 for text expression rules, and post-redaction decoded bodies over the configured limit fail before upstream forwarding with an internal proxy error response.

## WebSocket Behavior

For a matched HTTP/1.1 WebSocket upgrade, acl-proxy validates/sanitizes the handshake, then runs a frame-aware relay after `101 Switching Protocols`. Only client-to-upstream text/binary data messages are redacted. Upstream-to-client data and all control frames are forwarded without redaction.

The relay buffers one complete data message at a time, decompresses `permessage-deflate` messages when negotiated, applies the shared redaction profile, recompresses if needed, and reframes before forwarding upstream.

`permessage-deflate` remains opt-in. When enabled, acl-proxy only permits the no-context-takeover subset so each message is independently decompressible/recompressible. Unsupported extension negotiation is denied or stripped according to the profile.

## Non-Goals

- Response body redaction.
- Upstream-to-client WebSocket redaction.
- Per-message plugin invocation for WebSocket payloads.
- HTTP/2 RFC 8441 WebSocket support.
- Capturing redacted WebSocket payloads to disk.
