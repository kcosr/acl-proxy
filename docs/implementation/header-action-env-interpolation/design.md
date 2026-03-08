# Header Action Env Interpolation Design

Status: Locked

## 1. Purpose

Add a config-load interpolation pass for policy header-action values so operators can keep selected header values in process environment variables instead of committing them to TOML.

## 2. Problem statement

`acl-proxy` already supports static `header_actions` on policy rules and ruleset templates. Today those values are taken literally from TOML, which forces operators to choose between:

1. storing sensitive or deployment-specific header values directly in config files, or
2. introducing external approval/plugin flows for values that are actually static per deployment.

The requested feature is intentionally narrow:

1. interpolate only during config load/reload,
2. only in `header_actions` for `set` and `add`,
3. only in `value` / `values`,
4. fail fast when a referenced variable is missing or the syntax is ambiguous.

## 3. Goals

1. Add one deterministic interpolation pass in `src/config/mod.rs` after TOML parse and before final validation returns success.
2. Support direct rules under `policy.rules` and template rules under `policy.rulesets.<name>`.
3. Resolve exact whole-string placeholders of the form `${NAME}` from the current process environment at load/reload time.
4. Keep runtime request handling unchanged after substitution.
5. Return clear `ConfigError::Invalid(...)` messages for missing variables or invalid interpolation syntax, with config location context.
6. Avoid logging resolved env values.
7. Add targeted config-module tests and operator docs.

## 4. Non-goals

1. Substring interpolation such as `Bearer ${TOKEN}` or `${TOKEN}-suffix`.
2. Per-request interpolation or any runtime environment lookups on the hot path.
3. Interpolation in fields outside policy header actions.
4. Changes to approval-macro interpolation (`{{name}}`) or external-auth callback behavior.
5. Escape syntax for forcing a literal `${NAME}` value.
6. Schema-version changes.

## 5. Current baseline

1. `Config::load_from_sources()` parses TOML, applies existing env overrides (`ACL_PROXY_CONFIG`, `PROXY_PORT`, `PROXY_HOST`, `LOG_LEVEL`), then calls `validate_basic()`.
2. `header_actions` are stored in config structs and later compiled by `PolicyEngine::from_config()`.
3. Validation of `header_actions` today happens during policy compilation in `src/policy/mod.rs`.
4. Reload behavior (`SIGHUP`) already reuses `Config::load_from_sources()`, so a load-time interpolation pass will automatically apply to startup, `config validate`, `policy dump`, and reload.

## 6. Key decisions

1. Add a dedicated config mutation step, for example `interpolate_header_action_env_vars(&mut self)`, in `src/config/mod.rs`.
2. Invoke this step inside `Config::load_from_sources()` after environment overrides are applied and before `validate_basic()`.
3. Walk only:
   - direct rules: `policy.rules[*]` where the variant is `Direct`,
   - ruleset templates: `policy.rulesets.<ruleset_name>[*]`.
4. Only inspect `HeaderActionKind::Set` and `HeaderActionKind::Add`.
5. Only inspect `HeaderActionConfig.value` and `HeaderActionConfig.values[*]`.
6. Placeholder rule: interpolate only when the entire string exactly matches `${NAME}`.
7. Marker-detection rule: only the literal sequence `${` triggers interpolation validation. Values that contain `${` but do not exactly match `^\$\{[A-Za-z_][A-Za-z0-9_]*\}$` are rejected as invalid for clarity.
8. Placeholder-name contract: `NAME` is non-empty and matches `[A-Za-z_][A-Za-z0-9_]*`.
9. Missing environment variables are hard failures, not fallbacks to the literal string.
10. Empty resolved values are accepted by the interpolation step and then flow into existing header-value validation unchanged.
11. Static values with no `${` marker remain unchanged.
12. Non-`set`/`add` actions (`remove`, `replace_substring`) remain completely untouched.
13. `replace_substring.search` and `replace_substring.replace` are never interpolated.
14. Resolved env values must not be emitted to logs by the interpolation path; error messages may name the env var but not print its resolved value.

## 7. Contract / HTTP semantics

1. This feature changes configuration-load semantics only; it does not add new HTTP endpoints or alter request-routing behavior.
2. The resolved value is frozen into the in-memory config snapshot created at startup or reload time.
3. After config load succeeds, downstream policy/header-action behavior is identical to today's behavior for literal strings.
4. `config validate`, normal startup, and `SIGHUP` reload all fail before serving new traffic when interpolation fails.
5. Approval macros still work exactly as today:
   - values like `token {{github_token}}` remain literal config strings at load time,
   - env interpolation does not attempt to rewrite `{{...}}` syntax,
   - env interpolation runs before any later approval-time macro substitution.
6. If an operator removes a previously required env var and then triggers reload, reload fails and the existing running config remains active.

## 8. Service/module design

1. `src/config/mod.rs`
   - Add a config-level interpolation helper on `Config`.
   - Add smaller helpers to:
     - iterate rule/ruleset header-action collections,
     - parse and classify a candidate placeholder string,
     - build stable location strings for direct rules and ruleset templates,
     - resolve env vars and rewrite strings in place.
2. Traversal model
   - Direct rules:
     - process `PolicyRuleConfig::Direct`.
     - skip `PolicyRuleConfig::Include` because include rules have no `header_actions`.
   - Ruleset templates:
     - process each `PolicyRuleTemplateConfig` in each named ruleset.
3. Location formatting
   - Direct-rule errors should identify `policy.rules[<idx>]`.
   - Ruleset-template errors should identify `policy.rulesets.<ruleset_name>[<idx>]`.
   - Header-action details should include `header_actions[<idx>]` and the configured header action name.
4. Validation split
   - The interpolation pass is responsible for syntax and missing-env failures.
   - Existing policy compilation remains responsible for header-name/value validity and existing action-shape validation.
5. Implementation shape
   - A helper such as `interpolate_header_action_value(raw, location, header_name)` should:
     - return the original string unchanged when no interpolation marker appears,
     - parse exact placeholders,
     - reject malformed or substring-style markers,
     - replace exact placeholders with `std::env::var(name)`.
6. Reload behavior
   - No special reload code is needed beyond the existing `Config::load_from_sources()` path.
   - Failed reload preserves the old running state because reload already swaps state only after config build succeeds.
7. Test support
   - Add a test-only environment guard in `src/config/mod.rs` tests so env mutation is serialized and restored, keeping `cargo test` deterministic.
   - Keep env-mutating coverage in the lib-test binary; if execution later adds integration-test env mutation, it must use equivalent cross-test serialization.

## 9. Error semantics

1. Missing env var
   - Return `ConfigError::Invalid(...)`.
   - Message must include:
     - direct-rule or ruleset-template location,
     - header action name,
     - referenced env var name.
   - Example shape:
     - `invalid configuration: policy.rules[1].header_actions[0] for header 'authorization' references missing env var 'GITHUB_TOKEN'`
2. Invalid interpolation syntax
   - Return `ConfigError::Invalid(...)`.
   - Trigger when the literal sequence `${` appears in a non-exact form, for example:
     - `Bearer ${TOKEN}`
     - `${TOKEN}/suffix`
     - `${}`
     - `${1BAD}`
   - Message should include config location, header action name, and the offending raw value.
3. Static strings
   - Values with no interpolation marker pass through unchanged.
4. Existing validation behavior
   - If interpolation succeeds but the resolved string is not a valid HTTP header value, existing policy validation still fails as it does today.
   - If the resolved env var is an empty string, interpolation still succeeds and existing header validation remains the source of truth.

## 10. Migration strategy

1. Feature is additive; existing configs remain valid when they do not use `${...}` placeholders in affected fields.
2. No config-schema bump is required.
3. Operators can migrate incrementally:
   - replace a literal `value` or `values` entry with `${ENV_NAME}`,
   - export the variable in the runtime environment,
   - run `acl-proxy config validate`,
   - reload or restart.
4. Recommended rollout guidance:
   - validate in the same environment context used for service startup,
   - prefer this feature for deployment-specific secrets/tokens that are otherwise static after load,
   - avoid mixed literal-plus-placeholder strings because they are intentionally rejected,
   - update any existing literal `${...}` header values before upgrade, because those values now become reserved interpolation syntax in the affected fields.

## 11. Test strategy

1. Add config-module unit tests in `src/config/mod.rs` for:
   - exact `${VAR}` resolution in `value`,
   - exact `${VAR}` resolution for every `values` entry,
   - ruleset-template interpolation,
   - missing env var failure with location context,
   - invalid placeholder names such as `${}` and `${1BAD}`,
   - non-`set`/`add` actions unaffected,
   - static values unchanged,
   - approval-macro strings such as `{{github_token}}` passing through unchanged.
2. Add invalid-syntax tests for substring-style interpolation and mixed `values` lists such as `["static", "${DYNAMIC}"]` to lock per-entry behavior.
3. Add at least one case where the same `${VAR}` appears multiple times across affected entries.
4. Add one end-to-end `load_from_sources()` test using a temp config file so the load-path wiring cannot regress silently.
5. Add CLI-path verification or equivalent execution evidence that:
   - `config validate` fails on missing env vars,
   - `policy dump` observes resolved values after successful load.
6. Use a module-test mutex/guard to serialize env var mutation and restore prior values after each test.
7. Prefer direct `toml::from_str()` plus explicit interpolation/validation helper calls where useful, so tests stay fast and avoid temp files; use the end-to-end load test only for load-path wiring.
8. Run full project verification during execution:
   - `cargo fmt`
   - `cargo clippy`
   - `cargo test`
   - `cargo build --release`

## 12. Acceptance criteria

1. `Config::load_from_sources()` performs a dedicated interpolation pass before final validation succeeds.
2. Direct-rule and ruleset-template `set`/`add` header-action values support exact `${NAME}` placeholders.
3. Missing env vars fail config validation/startup/reload with clear location-aware errors.
4. Substring-style interpolation is rejected deterministically.
5. Static values, approval-macro strings, and non-`set`/`add` actions preserve current behavior.
6. No resolved env value is logged by the interpolation path.
7. Config docs and the sample config describe scope, syntax, fail-fast reload/startup behavior, and the `${...}` backward-compatibility edge case.

## 13. Status and risks

Status: Locked

1. Risk: env-mutating tests become flaky under parallel execution.
   - Mitigation: serialize env-sensitive tests with a local test mutex, restore previous state, and keep env-mutating coverage in a single test binary unless broader serialization is introduced.
2. Risk: ambiguous operator expectations about mixed literal + placeholder strings.
   - Mitigation: explicitly reject non-exact `${NAME}` forms and document that choice in config docs and sample comments.
3. Risk: literal `${...}` strings that previously behaved as plain text in affected fields now become invalid or reserved syntax.
   - Mitigation: call this out in migration docs, sample comments, and changelog text during execution.
4. Risk: future callers may construct `Config` directly and bypass load-time interpolation.
   - Mitigation: keep the interpolation helper in `src/config/mod.rs` so tests and future alternate loaders can call the same logic deliberately.
5. Risk: ruleset-template error messages can be harder to read than top-level rule errors.
   - Mitigation: standardize location strings in one helper and lock them with tests.
6. Risk: operators may assume the proxy logs resolved secret values while debugging.
   - Mitigation: explicitly state that interpolation errors may mention the env var name but must not print the resolved value.
