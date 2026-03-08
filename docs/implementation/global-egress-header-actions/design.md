# Global Egress Header Actions Design

Status: Locked (2026-03-08)

## 1. Purpose

Add a global egress request header mutation layer so operators can strip/replace/set headers for all forwarded upstream requests without duplicating the same `header_actions` block across many policy rules.

## 2. Problem statement

Today, `acl-proxy` only supports per-rule `header_actions` on the matched policy rule (or auth-plugin decision actions). This creates operational friction when an operator wants one consistent outbound behavior for all allowed traffic, such as removing `x-aw-identity-token` before origin egress.

Current pain points:

1. The same header action must be copied to every relevant allow rule.
2. Missed rules silently create inconsistent behavior.
3. Rule sprawl makes policy maintenance harder.
4. Policy matching and transport concerns are coupled in one layer.

## 3. Goals

1. Add a config-defined, global outbound header action list applied to every proxied upstream request.
2. Reuse existing header-action semantics (`remove`, `set`, `add`, `replace_substring`, `when`) to avoid a new operator model.
3. Preserve policy matching behavior (global egress actions must not affect rule evaluation).
4. Preserve deterministic ordering with current per-rule and plugin actions.
5. Keep behavior consistent across explicit HTTP proxy and transparent HTTPS forwarding paths.
6. Add docs, sample config guidance, and deterministic test coverage.

## 4. Non-goals

1. Global response header mutation in this stream.
2. Policy-rule accumulation (first-match-wins policy behavior remains unchanged).
3. New action kinds or a separate expression DSL.
4. External-auth approval macros for global actions.
5. Runtime-per-request environment lookups beyond existing config-load interpolation semantics.

## 5. Current baseline

1. Policy is first-match-wins; only the matched rule contributes `header_actions`.
2. Header actions are applied during outbound request construction in proxy handlers.
3. There is no single global post-policy outbound action list.
4. Operators currently duplicate identical per-rule `header_actions` to achieve broad egress behavior.

## 6. Key decisions

1. Introduce `proxy.egress.request_header_actions` as an ordered list.
2. Use a dedicated config type for this section (`EgressRequestHeaderActionConfig`) that reuses the same action grammar (`action`, `name`, `when`, `value`/`values`, `search`, `replace`) but intentionally omits `direction`.
3. Keep `direction` required for rule/plugin `header_actions`; do not change existing rule/plugin config contracts.
4. Action application order for outbound requests:
   1. copy inbound headers,
   2. apply matched-rule/plugin request actions,
   3. apply global egress request actions,
   4. send upstream using existing transport/protocol handling.
5. `when=if_present|if_absent` for global actions is evaluated against the request header set at the start of step 3 (after rule/plugin actions), giving deterministic local behavior for this layer.
6. Global egress actions never participate in policy matching.
7. Keep config-load validation fail-fast and location-aware for invalid global action entries.
8. `CONNECT` behavior lock: global request egress actions apply to the CONNECT request metadata headers only; tunneled payload bytes are not parsed or mutated.
9. `Host` behavior lock: mutating a `host` header via actions affects only header fields, never the selected egress authority/socket target (which remains URI/egress-target driven).

## 7. Contract / HTTP semantics

Config contract (additive, schema v1 compatible):

```toml
[proxy.egress]

[[proxy.egress.request_header_actions]]
action = "remove"              # remove | set | add | replace_substring
name = "x-aw-identity-token"
when = "if_present"            # always | if_present | if_absent
```

Rules:

1. `request_header_actions` defaults to empty.
2. Actions execute in configured order.
3. `set`/`add` accept `value` or `values` exactly as policy header actions do.
4. `replace_substring` uses existing `search`/`replace` semantics.
5. Invalid entries fail validation/startup/reload deterministically with location context for `proxy.egress.request_header_actions[<idx>]`.
6. Existing policy rule semantics remain unchanged.
7. Header-name normalization/canonicalization matches existing header-action handling in the proxy.

## 8. Service/module design

1. `src/config/mod.rs`
   - Extend `ProxyEgressConfig` with `request_header_actions: Vec<EgressRequestHeaderActionConfig>`.
   - Add validation for this list, reusing existing header-action validation helpers where possible.
   - Extend env-interpolation traversal (for `set`/`add`) to include global egress request actions.
2. `src/policy/mod.rs`
   - Add a compile path for global egress request actions that is not coupled to policy-rule index context.
   - Keep existing `compile_header_actions` behavior unchanged for rules/plugins.
3. `src/proxy/http.rs`
   - Compile and pass global egress actions into request forwarding path.
   - Apply global egress request actions after matched-rule/plugin request actions.
4. `src/proxy/https_transparent.rs` and `src/proxy/https_connect.rs`
   - Ensure global egress request actions are applied for those forwarding paths too.
5. Docs
   - Update config reference and sample config with section syntax and ordering semantics.

## 9. Error semantics

1. Config errors (invalid action shape/header name/value/etc.) use `ConfigError::Invalid(...)` with `proxy.egress.request_header_actions[<idx>]` location context.
2. Missing env interpolation variables in global `set`/`add` values fail config load/reload with location-aware errors.
3. Runtime behavior for a valid config does not add new HTTP error families; failures still flow through existing upstream failure handling.

## 10. Migration strategy

1. Additive change; existing configs remain valid.
2. Operators can remove duplicated per-rule header actions incrementally after adding global egress actions.
3. Recommended migration:
   1. add global egress actions,
   2. validate config,
   3. remove duplicated per-rule actions,
   4. validate again and reload.

## 11. Test strategy

1. Config tests:
   - parse/validate `proxy.egress.request_header_actions`,
   - invalid shape failures with location strings,
   - env interpolation coverage for global `set`/`add` values.
2. Proxy behavior tests:
   - global `remove` applied to request forwarding,
   - ordering test: per-rule set then global remove,
   - explicit HTTP and transparent HTTPS coverage,
   - CONNECT request path coverage (metadata-only mutation guarantee).
3. Determinism/ordering tests:
   - intra-global ordering (`set` then `replace_substring` then `remove`),
   - cross-layer `when` behavior (rule action alters presence; global `if_present|if_absent` observes post-rule state),
   - empty-global-list regression (no behavior change).
4. Regression tests:
   - policy matching still sees original inbound headers,
   - first-match-wins unchanged,
   - host mutation does not alter selected egress target.
5. Full verification gate:
   - `cargo fmt`
   - `cargo clippy`
   - `cargo test`
   - `cargo build --release`

## 12. Acceptance criteria

1. New `proxy.egress.request_header_actions` section is supported and documented.
2. Global egress actions apply to all forwarded upstream requests across request-forwarding modes.
3. Per-rule/plugin actions and global actions execute in deterministic documented order.
4. Policy matching behavior is unchanged.
5. Config validation and env interpolation errors are deterministic and location-aware.
6. New tests and full verification pass.

## 13. Status and risks

Status: Locked (2026-03-08)

1. Risk: action-order ambiguity between per-rule and global actions.
   - Mitigation: lock ordering in docs and tests.
2. Risk: operators expect global actions to influence policy matching.
   - Mitigation: explicit non-goal and matching regression test.
3. Risk: duplicated actions during migration cause surprises.
   - Mitigation: docs include migration sequencing guidance and order examples.
