# Egress Destination Forwarding Schema Proposal

Status: Locked

## 1. Goal

Lock phase-one configuration contract for default egress forwarding destination in a way that can evolve into per-rule egress profile selection without replacing core transport semantics.

## 2. Example configuration payloads

## 2.1 Disabled (default behavior)

```toml
[proxy]
bind_address = "127.0.0.1"
http_port = 8881
https_bind_address = "127.0.0.1"
https_port = 8889
```

## 2.2 Enabled default egress forwarding

```toml
[proxy]
bind_address = "127.0.0.1"
http_port = 8881
https_bind_address = "127.0.0.1"
https_port = 8889

[proxy.egress.default]
host = "172.17.0.1"
port = 8889
```

## 3. JSON schema skeleton (conceptual)

```json
{
  "$id": "acl-proxy.proxy.egress.schema.v1",
  "type": "object",
  "properties": {
    "proxy": {
      "type": "object",
      "properties": {
        "egress": {
          "type": "object",
          "properties": {
            "default": {
              "type": "object",
              "properties": {
                "host": { "type": "string", "minLength": 1 },
                "port": { "type": "integer", "minimum": 1, "maximum": 65535 }
              },
              "required": ["host", "port"],
              "additionalProperties": false
            }
          },
          "additionalProperties": true
        }
      }
    }
  }
}
```

## 4. Endpoint/contract lock

1. No HTTP API contract changes in phase one.
2. Contract is TOML configuration only.
3. If `proxy.egress.default` is absent, forwarding override is disabled.
4. If present and valid, forwarding override is enabled for all allowed request-forwarding paths.
5. Config reload applies updated egress config via existing shared-state swap behavior.

## 5. Deterministic reject/status lock

1. Missing `host` or `port` inside `proxy.egress.default` -> config parse/validation failure.
2. Blank/whitespace `host` -> deterministic validation failure.
3. `port` outside `1..65535` -> parse/validation failure.
4. Host must be a DNS hostname or IP literal and must not include a port suffix.
5. Unix socket paths are out of scope in phase one.

## 6. Notes

1. Forward-compatible shape reserves future extension:
   - named egress profiles,
   - per-rule profile selection.
2. Phase-one toggle is section presence/absence; no explicit `enabled` field in this phase.
3. New env-var overrides for egress fields are deferred; config file is source of truth in phase one.
4. Existing header action features are orthogonal and unchanged.
