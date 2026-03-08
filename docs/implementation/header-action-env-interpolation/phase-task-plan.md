# Header Action Env Interpolation Phase Task Plan

Status: Locked

## 1. Scope

Deliver a load-time environment interpolation pass for policy header-action values in `src/config/mod.rs`, covering direct rules and ruleset templates, while preserving existing runtime header-action behavior after substitution.

## 2. Global rules

1. Keep scope limited to `header_actions` with `action = "set"` or `action = "add"`.
2. Interpolate only `value` and `values[*]`.
3. Interpolate only exact whole-string placeholders of the form `${NAME}`.
4. Reject ambiguous or substring-style marker usage instead of treating it literally.
5. Preserve existing behavior for static values and for non-`set`/`add` actions.
6. Keep tests offline and deterministic.
7. Do not change approval-macro semantics or add per-request environment lookups.

## 3. Phase plan

`H0` through `H2` are the ordered implementation handoff phases for this feature.

## H0 - Contract wiring and traversal helpers

Deliverables:

1. Add a dedicated interpolation step in `Config::load_from_sources()`.
2. Add helper(s) in `src/config/mod.rs` to walk:
   - direct-rule header actions under `policy.rules`,
   - ruleset-template header actions under `policy.rulesets`.
3. Add a strict placeholder parser/classifier for exact `${NAME}` strings.
4. Add standardized location-format helpers for direct rules and ruleset templates.
5. Explicitly exclude `replace_substring.search` and `replace_substring.replace` from interpolation scope.

Acceptance criteria:

1. Interpolation is part of config load before `validate_basic()`.
2. Include rules are explicitly skipped because they do not own `header_actions`.
3. The placeholder contract is centralized in one helper and not duplicated across call sites.
4. Error messages have stable location prefixes for both direct rules and rulesets.
5. Marker detection is defined precisely as literal `${` detection plus exact-placeholder regex validation.

## H1 - Resolution behavior and config tests

Deliverables:

1. Resolve env vars for `value`.
2. Resolve env vars for each `values[*]` entry.
3. Reject missing env vars with clear `ConfigError::Invalid(...)` messages.
4. Reject malformed or substring-style marker usage.
5. Add deterministic config-module tests, including env-state guard/restore logic.
6. Ensure interpolation does not log resolved env values.

Acceptance criteria:

1. `${VAR}` resolves correctly in `value`.
2. `${VAR}` resolves correctly in each `values` entry.
3. Missing env vars fail with rule/ruleset location, header name, and env var name.
4. Static values remain unchanged.
5. Approval-macro strings such as `{{name}}` remain unchanged.
6. Non-`set`/`add` actions and `replace_substring.search` / `replace_substring.replace` remain unaffected.
7. Env-sensitive tests are reliable under parallel `cargo test` within the chosen test binary.

## H2 - Docs, sample config, and full verification

Deliverables:

1. Update `docs/config-reference.md`.
2. Update `docs/configuration.md`.
3. Update `acl-proxy.sample.toml`.
4. Document scope, exact syntax, failure behavior, and load/reload timing.
5. Run full project-required verification.
6. Capture CLI/operator verification for `config validate` and `policy dump`.

Acceptance criteria:

1. Operator docs clearly state that interpolation happens once at config load/reload time.
2. Docs clearly state that only exact whole-string `${NAME}` placeholders are supported.
3. Docs clearly state that missing env vars fail `config validate`, startup, and reload.
4. Sample config shows a realistic `header_actions` example using `${NAME}` without implying substring support.
5. Docs call out that literal `${...}` strings in affected fields are now reserved syntax and must be migrated.
6. `cargo fmt`, `cargo clippy`, `cargo test`, and `cargo build --release` all pass.
7. `CHANGELOG.md` entry is prepared under `Unreleased` after a PR number exists, per repo rules.

## 4. Verification matrix

| Phase | Verification command(s) | Required evidence |
| --- | --- | --- |
| H0 | Targeted config-module test filter (name decided during execution) | Pass output plus evidence that load path now includes interpolation helper |
| H1 | Targeted `cargo test` for config interpolation cases | Pass output for exact-match, ruleset-template, repeated-placeholder, mixed values-list, missing-env, static, approval-macro coexistence, non-set/add, and invalid-syntax cases |
| H2 | `cargo fmt`, `cargo clippy`, `cargo test`, `cargo build --release`, plus CLI/doc checks | Full pass output plus `config validate` / `policy dump` evidence and doc/sample grep evidence |

## 5. Milestone commit gate

1. H1 starts only after H0 helper and contract evidence is recorded.
2. H2 starts only after H1 behavior/tests evidence is recorded.
3. Final completion requires the repo-mandated Rust verification commands and doc updates.

## 6. Review policy (execution stream)

1. Run independent Gemini and PI reviews at phase gates or at least once after substantial H1/H2 changes.
2. Do not allow reviewer runs to edit files.
3. Triage each finding as `accept`, `defer`, or `reject`.
4. Record run IDs and triage in Section 9.
5. Determine review completion from the live session stream (`result.completed` or `result.failed`), not redirected log files.

## 7. Risk controls

1. Centralize placeholder parsing to avoid inconsistent syntax handling.
2. Keep interpolation in config loading, not in policy request evaluation, to avoid hot-path complexity.
3. Serialize env-mutating tests to avoid nondeterministic failures.
4. Preserve existing policy validation ownership for header-value validity after interpolation.
5. Treat invalid marker syntax as a hard config error to prevent silent misconfiguration.
6. Keep resolved env values out of logs and evidence output.

## 8. Rollout checklist

1. Export required env vars in the service manager/runtime environment before validation or restart.
2. Run `acl-proxy config validate --config <path>` in the same environment used for deployment.
3. Confirm startup succeeds with expected resolved header values.
4. Confirm reload fails closed when a required env var is missing.
5. After PR creation, add the required `CHANGELOG.md` `Unreleased` entry with the PR number.
6. Verify any existing literal `${...}` values in affected fields are migrated before rollout.

## 9. Operator checklist and evidence log schema

### Evidence block template

- Phase: `H0|H1|H2`
- Completion date: `YYYY-MM-DD`
- Commit hash(es): `<hash list>`
- Acceptance evidence:
  - `<test command>` -> `<result>`
  - `<doc/config check>` -> `<result>`
- Review run IDs + triage outcomes:
  - `gemini:<run_id>` -> `<accept|defer|reject summary>`
  - `pi:<run_id>` -> `<accept|defer|reject summary>`
- Go/No-Go decision: `GO|NO-GO`
- Notes: `<caveats/deferred items>`

### Planned execution evidence blocks

- Phase: `H0`
- Completion date: `2026-03-08`
- Commit hash(es): `8b504d5`
- Acceptance evidence:
  - `cargo test header_action_env --lib` -> passed (`4 passed; 0 failed`) covering the exact-placeholder classifier, direct-rule and ruleset location errors, and `load_from_sources()` wiring for invalid marker syntax.
  - `rg -n "interpolate_header_action_env_vars|classify_header_action_env_placeholder|format_direct_rule_location|format_ruleset_template_location|format_header_action_location" src/config/mod.rs` -> confirmed the dedicated load-path hook, centralized placeholder classifier, and stable direct-rule / ruleset / header-action location helpers are all present in one module.
- Review run IDs + triage outcomes:
  - `gemini:r_20260308043637316_9f6ebc7d`
    - accept: H0 deliverables, strict marker detection, direct-rule/ruleset traversal, and load-path wiring are complete and aligned with the locked design.
  - `pi:r_20260308043637316_f6627fbb`
    - accept: H0 helper factoring, location formatting, and exact-placeholder classification match the phase contract.
    - defer: add explicit passthrough coverage for `remove` / `replace_substring` and valid exact-placeholder/static happy paths in H1, where behavior tests are in scope.
- Go/No-Go decision: `GO`
- Notes: Both required reviews completed from the live session stream with no fallback. The exact-placeholder branch intentionally remains a no-op in H0 so env resolution and missing-env failures can land cleanly in H1 without widening the current phase scope.

- Phase: `H1`
- Completion date: `2026-03-08`
- Commit hash(es): `b1a33da`
- Acceptance evidence:
  - `cargo test header_action_env --lib` -> passed (`13 passed; 0 failed`) covering exact `value` resolution, ruleset-template resolution, mixed static/dynamic `values`, repeated placeholders, missing-env failure, static values, approval-macro coexistence, non-`set`/`add` behavior, empty resolved values, invalid syntax, and both load-path success/failure cases.
  - `rg -n "HeaderActionEnvTestGuard|header_action_env_interpolation_allows_empty_resolved_value|header_action_env_interpolation_skips_remove_actions|header_action_env_interpolation_resolves_mixed_values_and_repeated_placeholder|load_from_sources_resolves_header_action_env_placeholders" src/config/mod.rs` -> confirmed serialized env-state guard/restore coverage plus explicit tests for mixed values, remove-action passthrough, empty resolved values, and end-to-end `load_from_sources()` success.
- Review run IDs + triage outcomes:
  - `gemini:r_20260308044046216_fe1f7df4`
    - accept: H1 implementation satisfies the locked behavior and test requirements.
    - accept: add an explicit empty-resolved-value test to lock the documented interpolation behavior; applied before phase close.
  - `pi:r_20260308044046216_b7bb5256`
    - accept: H1 resolution behavior, missing-env failures, env-test guard, and end-to-end load wiring are implemented correctly.
    - accept: add explicit `remove`-action passthrough coverage and an empty-resolved-value test; both applied before phase close.
    - reject: ruleset iteration nondeterminism is not a real risk here because `RulesetMap` is a `BTreeMap`, not a hash map.
    - reject: locking first-error ordering across mixed invalid entries is unnecessary for the current contract and outside the phase acceptance criteria.
- Go/No-Go decision: `GO`
- Notes: Both required reviews completed from the live session stream with no fallback. Accepted review follow-ups were limited to additional deterministic tests; no runtime behavior changed after the initial H1 implementation.

- Phase: `H2`
- Completion date: `TBD`
- Commit hash(es): `TBD`
- Acceptance evidence:
  - `TBD`
- Review run IDs + triage outcomes:
  - `gemini:TBD`
  - `pi:TBD`
- Go/No-Go decision: `TBD`
- Notes: `TBD`

### Authoring-stage review evidence (spec plan stream)

- Stage: `Spec authoring`
- Completion date: `2026-03-08`
- Review run IDs + triage outcomes:
  - `gemini:r_20260308042357989_214e8fcf`
    - reject: add escape syntax for literal `${NAME}` values; this stream keeps `${...}` reserved and documents the migration risk instead.
    - accept: clarify empty resolved-value behavior and defer final validity to existing header validation.
    - accept: strengthen the env-test isolation note.
    - accept: reinforce operator-facing docs around strict substring rejection.
  - `pi:r_20260308042357994_6b53cf4e`
    - accept: specify marker detection exactly as literal `${` detection plus exact-placeholder regex.
    - accept: state explicitly that `replace_substring.search` and `replace_substring.replace` are not interpolated.
    - accept: explain the `H0`-`H2` phase naming.
    - accept: add `config validate` / `policy dump` verification requirements.
    - accept: lock the rule that resolved env values are not logged.
    - accept: clarify empty resolved-value behavior.
    - accept: add repeated-placeholder coverage.
    - accept: call out the backward-compatibility risk for existing literal `${...}` strings.
    - accept: document reload expectations when a required env var is removed before reload.
    - accept: clarify that env-mutating tests must stay in the protected test binary unless broader serialization is introduced.
    - accept: add explicit ruleset-template, mixed-values, load-path, invalid-name, and approval-macro coexistence test requirements.
    - accept: make the verification-matrix test filter wording illustrative instead of prescriptive.
    - reject: the note that the repo lacks a formal `schema_version` field is incorrect; `schema_version = "1"` already exists in the config contract.
    - accept: strengthen the read-order relationship between schema, design, and phase plan through the execution handoff.
- Lock decision: `LOCKED`
- Notes: `Both required authoring reviews completed from the live session stream with no fallback. Accepted findings were applied before locking the artifacts.`

## 10. Execution handoff contract

1. Required read order:
   - `docs/implementation/header-action-env-interpolation/schema-proposal.md`
   - `docs/implementation/header-action-env-interpolation/design.md`
   - `docs/implementation/header-action-env-interpolation/phase-task-plan.md`
2. Phase start point:
   - Start at `H0` only.
3. Boundaries and semantic-preservation constraints:
   - do not expand beyond `set`/`add` `value`/`values`,
   - do not add substring interpolation,
   - do not change runtime request-time header-action semantics after load succeeds,
   - do not alter approval-macro behavior,
   - do not add schema-version churn.
4. Review command policy requirements:
   - use `agent-runner-review`,
   - use independent Gemini and PI reviewers,
   - no timeout or reasoning-effort CLI overrides,
   - completion from live stream only.
5. Completion requirements:
   - update `docs/config-reference.md`, `docs/configuration.md`, and `acl-proxy.sample.toml`,
   - update `docs/architecture.md` only if execution reveals stable cross-cutting behavior worth documenting,
   - the repo currently does not contain `docs/implementation/implementation-plan.md`; do not create it just to satisfy this plan unless maintainers introduce that tracker separately,
   - add a `CHANGELOG.md` `Unreleased` entry after a PR number exists,
   - fill in Section 9 evidence for each phase,
   - publish a final phase summary with residual risks or deferred items.
