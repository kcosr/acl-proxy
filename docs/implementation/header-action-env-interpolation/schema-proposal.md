# Header Action Env Interpolation Schema Proposal

Status: Locked

## 1. Goal

Lock the config contract for exact environment-variable interpolation in policy header-action values, with deterministic rejection for missing variables and malformed placeholder usage.

## 2. Example configuration

```toml
[policy]
default = "deny"

[[policy.rulesets.api_headers]]
action = "allow"
pattern = "https://api.internal/**"

[[policy.rulesets.api_headers.header_actions]]
direction = "request"
action = "set"
name = "authorization"
value = "${API_TOKEN}"

[[policy.rules]]
include = "api_headers"

[[policy.rules]]
action = "allow"
pattern = "https://status.internal/**"

[[policy.rules.header_actions]]
direction = "request"
action = "add"
name = "x-env-tag"
values = ["${DEPLOYMENT}", "${REGION}"]
```

## 3. JSON schema skeleton (conceptual)

```json
{
  "$id": "acl-proxy.header-action-env-interpolation.v1",
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
              "header_actions": {
                "type": "array",
                "items": {
                  "type": "object",
                  "properties": {
                    "action": {
                      "enum": ["set", "add", "remove", "replace_substring"]
                    },
                    "value": { "type": "string" },
                    "values": {
                      "type": "array",
                      "items": { "type": "string" }
                    }
                  }
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

## 4. Endpoint / contract lock

1. No HTTP endpoint or wire-protocol changes are introduced by this feature.
2. Interpolation scope is limited to:
   - direct rules under `policy.rules`,
   - ruleset templates under `policy.rulesets.<name>`,
   - `header_actions` with `action = "set"` or `action = "add"`,
   - `value` and `values[*]`.
3. Interpolation occurs only when the entire string exactly matches `${NAME}`.
4. `NAME` must match `[A-Za-z_][A-Za-z0-9_]*`.
5. Marker detection is triggered only by the literal sequence `${`; any string containing `${` that does not exactly match the placeholder contract is rejected.
6. Resolution source is the current process environment at config load/reload time.
7. Resolved values are stored in memory and reused; there is no per-request environment lookup.
8. Static strings with no `${` marker remain unchanged.
9. Empty resolved values are allowed through interpolation and remain subject to existing header-value validation.
10. Non-`set`/`add` actions are untouched.
11. `replace_substring.search` and `replace_substring.replace` are untouched.
12. Resolved values must not be logged by the interpolation path.

## 5. Deterministic reject / status lock

1. Missing env var referenced by an exact placeholder -> config load/reload failure via `ConfigError::Invalid(...)`.
2. Placeholder marker text used in any non-exact form -> config load/reload failure via `ConfigError::Invalid(...)`.
3. Invalid placeholder names such as `${}` or `${1BAD}` -> config load/reload failure via `ConfigError::Invalid(...)`.
4. Failure must block:
   - `acl-proxy config validate`,
   - normal startup,
   - `policy dump`,
   - config reload.
5. Successful interpolation does not bypass existing header-action validation; invalid or empty resolved header values still fail or pass according to current validation rules.

## 6. Notes

1. This is an additive schema-v1 behavior change; no `schema_version` bump is required.
2. Approval macros (`{{name}}`) are outside this contract and continue to resolve later in the approval flow.
3. Strings like `Bearer ${TOKEN}` are intentionally rejected instead of partially interpolated.
4. Existing literal `${...}` strings in affected fields become reserved syntax under this contract and must be migrated before rollout.
5. The conceptual JSON schema cannot fully express the marker-detection rule; Rust validation remains the source of truth for exact placeholder semantics, non-logging behavior, and location-aware errors.
