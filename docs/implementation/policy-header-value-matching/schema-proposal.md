# Policy Header Value Matching Schema Proposal

Status: Locked

## 1. Goal

Lock a deterministic configuration contract for matching inbound request headers by exact value in policy rules.

## 2. Example request/response payloads

### Example config input (request)

```toml
[policy]
default = "deny"

[[policy.rules]]
action = "deny"
pattern = "**"
headers_absent = ["x-aw-identity-token"]

[[policy.rules]]
action = "allow"
pattern = "https://api.internal/**"
headers_match = { "x-aw-identity-token" = ["prod-token-a", "prod-token-b"], "x-tenant-id" = "tenant-1" }
```

### Example effective policy output (response)

```json
{
  "default": "deny",
  "rules": [
    {
      "index": 0,
      "action": "deny",
      "pattern": "**",
      "headers_absent": ["x-aw-identity-token"],
      "headers_match": {}
    },
    {
      "index": 1,
      "action": "allow",
      "pattern": "https://api.internal/**",
      "headers_absent": [],
      "headers_match": {
        "x-aw-identity-token": ["prod-token-a", "prod-token-b"],
        "x-tenant-id": ["tenant-1"]
      }
    }
  ]
}
```

## 3. JSON schema skeleton (conceptual)

```json
{
  "$id": "acl-proxy.policy.headers-match.v1",
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
              "headers_match": {
                "type": "object",
                "minProperties": 1,
                "additionalProperties": {
                  "oneOf": [
                    { "type": "string", "minLength": 1 },
                    {
                      "type": "array",
                      "minItems": 1,
                      "items": { "type": "string", "minLength": 1 }
                    }
                  ]
                }
              }
            }
          }
        }
      }
    }
  }
}
```

## 4. Endpoint/contract lock

1. Field name: `headers_match`.
2. Placement: direct rules and ruleset template rules.
3. Type: map `header-name -> string | [string, ...]`.
4. Header names are case-insensitive and normalized to lowercase.
5. Matching semantics:
   - across map keys: `AND`,
   - within a key's values: `OR`,
   - exact value equality (case-sensitive, no trimming, no comma splitting).
6. Predicate evaluation occurs before header actions and forwarding.
7. `headers_match` combines with `pattern`, `methods`, `subnets`, and `headers_absent` using implicit `AND` semantics.
8. Include rules inherit template `headers_match`; include rules do not override `headers_match` in this stream.
9. `headers_match` alone is valid match criteria for patternless direct rules.
10. Effective policy output includes `headers_match` on every rule; when not configured it is serialized as `{}`.

## 5. Deterministic reject/status lock

1. `headers_match = {}` -> validation failure.
2. Invalid header name key -> validation failure.
3. Duplicate header-name keys after normalization -> validation failure.
4. Empty value list for any key -> validation failure.
5. Non-string values in map/list -> parse or validation failure.
6. Empty-string configured value -> validation failure.
7. Missing field -> no behavior change.

## 6. Notes

1. This stream intentionally excludes regex/glob/substring value matching.
2. Exact matching avoids ambiguity and keeps evaluation fast/deterministic.
3. Ruleset include behavior follows existing template-expansion model.
4. Header values that contain commas are treated as one literal value; no tokenization occurs in this stream.
5. Future streams can add explicit match modes (for example `exact|glob|regex`) without changing this baseline contract.
