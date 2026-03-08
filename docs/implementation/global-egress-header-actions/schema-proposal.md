# Global Egress Header Actions Schema Proposal

Status: Locked (2026-03-08)

## 1. Goal

Lock an additive config contract for global outbound request header actions so operators can apply one shared egress header-mutation policy without duplicating per-rule actions.

## 2. Example configuration

```toml
schema_version = "1"

[proxy]
bind_address = "0.0.0.0"
http_port = 8881

[proxy.egress.default]
host = "172.17.0.1"
port = 8881

[[proxy.egress.request_header_actions]]
action = "remove"
name = "x-aw-identity-token"
when = "if_present"

[[proxy.egress.request_header_actions]]
action = "set"
name = "x-egress-tag"
value = "edge-a"
```

### Example payloads (contract-level)

Input action payload (conceptual):

```json
{
  "action": "replace_substring",
  "name": "x-forwarded-for",
  "when": "if_present",
  "search": ", ",
  "replace": ";"
}
```

Compiled/runtime action payload (conceptual):

```json
{
  "action": "replace_substring",
  "name": "x-forwarded-for",
  "when": "if_present",
  "search": ", ",
  "replace": ";",
  "scope": "global_request_egress"
}
```

## 3. JSON schema skeleton (conceptual)

```json
{
  "$id": "acl-proxy.global-egress-header-actions.v1",
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
                "host": { "type": "string" },
                "port": { "type": "integer", "minimum": 1, "maximum": 65535 }
              },
              "required": ["host", "port"]
            },
            "request_header_actions": {
              "type": "array",
              "items": {
                "type": "object",
                "properties": {
                  "action": { "enum": ["remove", "set", "add", "replace_substring"] },
                  "name": { "type": "string" },
                  "when": { "enum": ["always", "if_present", "if_absent"] },
                  "value": { "type": "string" },
                  "values": { "type": "array", "items": { "type": "string" } },
                  "search": { "type": "string" },
                  "replace": { "type": "string" }
                },
                "required": ["action", "name"]
              }
            }
          }
        }
      }
    }
  }
}
```

## 4. Endpoint / contract lock

1. No API endpoint changes.
2. Add one config list at `proxy.egress.request_header_actions`.
3. Action grammar matches existing policy request-header actions, but this section intentionally has no `direction` field.
4. Actions apply only to outbound forwarded requests.
5. `CONNECT` scope is metadata headers only; tunneled bytes are not parsed/mutated.
6. `Host` mutation is header-only and does not alter selected upstream authority/target.
7. Actions do not affect policy matching.
8. Execution ordering is locked:
   1. matched-rule/plugin request actions,
   2. global egress request actions,
   3. send upstream.

## 5. Deterministic reject / status lock

1. Invalid global action shape/name/value semantics fail config validation/startup/reload.
2. Invalid env placeholder interpolation in global `set`/`add` values fails config load/reload.
3. Existing configs with no `proxy.egress.request_header_actions` remain valid.
4. Runtime request failures keep existing upstream error behavior; no new transport status contracts are introduced by this feature.

## 6. Notes

1. This is additive in schema v1.
2. The section uses a dedicated action config type with no `direction` field.
3. Global response actions are intentionally deferred.
4. Existing rule-level actions remain supported and can coexist with global actions.

## 7. Status

Status: Locked (2026-03-08)
