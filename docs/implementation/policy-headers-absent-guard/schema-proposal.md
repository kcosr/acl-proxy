# Policy Headers-Absent Guard Schema Proposal

Status: Locked

## 1. Goal

Add a minimal missing-header predicate to policy rules so operators can express fail-closed deny guards for required identity headers.

## 2. Example configuration

```toml
[policy]
default = "deny"

[[policy.rules]]
action = "deny"
pattern = "**"
headers_absent = ["x-workload-id"]

[[policy.rules]]
action = "allow"
pattern = "https://api.internal/**"
methods = ["GET", "POST"]
subnets = ["10.0.0.0/8"]
```

## 3. JSON schema skeleton (conceptual)

```json
{
  "$id": "acl-proxy.policy.headers-absent.v1",
  "type": "object",
  "properties": {
    "policy": {
      "type": "object",
      "properties": {
        "rules": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "headers_absent": {
                "type": "array",
                "items": { "type": "string", "minLength": 1 },
                "minItems": 1,
                "uniqueItems": true
              }
            }
          }
        }
      }
    }
  }
}
```

## 4. Contract lock

1. `headers_absent` is optional on direct/template-derived rules.
2. Predicate passes when **any** listed header is absent.
3. Header-name matching is case-insensitive.
4. Predicate failure causes normal rule fall-through.
5. Headers present with empty values are treated as present (not absent).

## 5. Deterministic reject/status lock

1. Empty `headers_absent` list -> config validation failure.
2. Invalid header name token -> config validation failure.
3. Duplicate names after normalization -> config validation failure.
4. Missing field -> no behavior change from current baseline.

## 6. Notes

1. Header names follow valid HTTP header-name token constraints (RFC token rules).
2. `uniqueItems` in skeleton is illustrative; canonical duplicate handling is normalization-aware validation in Rust (e.g., `X-Foo` and `x-foo` considered duplicates).
3. Scope intentionally excludes header value matching.
4. Scope intentionally excludes generic negation framework.
5. Future work may add value-based predicates and composite logic.
