# Global Egress Header Actions Phase Task Plan

Status: Locked (2026-03-08)

## 1. Scope

Deliver a global outbound request-header action layer under `proxy.egress` that reuses existing header-action semantics and eliminates per-rule duplication for common egress mutations.

## 2. Global rules

1. Keep policy evaluation first-match-wins and unchanged.
2. Global egress actions must not affect rule matching.
3. Reuse existing header-action semantics and validation behavior.
4. Keep tests deterministic/offline.
5. Do not add global response actions in this stream.

## 3. Phase plan

`H0` through `H3` are the ordered execution phases.

## H0 - Config contract and validation wiring

Deliverables:

1. Add `proxy.egress.request_header_actions` to config structs.
2. Use a dedicated config struct for global egress request actions (no `direction` field).
3. Reuse/extend header-action validation for this new section.
4. Add location-aware validation errors for `proxy.egress.request_header_actions[<idx>]`.

Acceptance criteria:

1. Config parses with empty or populated `request_header_actions`.
2. Invalid entries fail deterministically with location-aware errors.
3. Existing configs without the new section remain valid.
4. Existing rule/plugin `header_actions` contract remains unchanged.

## H1 - Interpolation and policy-output plumbing

Deliverables:

1. Extend load-time env interpolation traversal to include global egress request actions.
2. Thread compiled global egress actions into request forwarding paths.
3. Keep global compile path decoupled from rule-index-specific compile errors.

Acceptance criteria:

1. `${NAME}` interpolation behavior for global `set`/`add` matches existing policy-action semantics.
2. Missing env variables fail startup/reload/validate with location-aware errors.
3. No policy-match semantics regressions.

## H2 - Runtime application and ordering

Deliverables:

1. Apply global egress request actions after matched-rule/plugin actions and before send.
2. Ensure behavior is consistent in explicit HTTP and transparent HTTPS request-forwarding paths.
3. Clarify and enforce CONNECT scope (headers only, not tunneled bytes).
4. Lock `Host` mutation semantics (header mutation only, never target-authority rewrite).
5. Preserve existing upgrade and streaming request behavior.

Acceptance criteria:

1. Deterministic action ordering is enforced in code and tests.
2. Global remove/set/add/replace_substring work as documented.
3. Existing per-rule behavior continues to work when global actions are empty.
4. Cross-layer `when` semantics are deterministic and covered by tests.

## H3 - Docs, sample config, and verification

Deliverables:

1. Update docs and sample config for new section and ordering semantics.
2. Add/refresh tests for config, ordering, and path coverage.
3. Run full verification suite.
4. Update `CHANGELOG.md` after PR number exists.

Acceptance criteria:

1. Operator docs clearly describe non-goals, order of operations, and migration guidance.
2. Full verification passes.
3. Changelog entry exists under `Unreleased` with PR link.

## 4. Verification matrix

| Phase | Verification command(s) | Required evidence |
| --- | --- | --- |
| H0 | targeted config tests | parse/validation pass/fail evidence with location strings |
| H1 | targeted interpolation/config tests | global egress interpolation success/failure evidence |
| H2 | targeted proxy path tests | global action ordering and forwarding behavior evidence |
| H3 | `cargo fmt`, `cargo clippy`, `cargo test`, `cargo build --release` | full pass evidence + docs/sample/changelog checks |

## 5. Milestone commit gate

1. H1 starts only after H0 acceptance evidence is recorded.
2. H2 starts only after H1 acceptance evidence is recorded.
3. H3 starts only after H2 runtime behavior evidence is recorded.
4. Final merge readiness requires H3 verification and changelog entry.

## 6. Review policy (execution stream)

1. Use `agent-runner-review` at major phase gates (at least once after H2/H3 work).
2. Use independent Gemini and PI runs.
3. No timeout/reasoning-effort overrides on CLI.
4. Record run IDs and triage outcomes in Section 9.
5. Determine completion from live session terminal events.

## 7. Risk controls

1. Lock action ordering with direct tests.
2. Keep global actions request-only to avoid scope creep.
3. Keep matching behavior and runtime semantics separated by contract.
4. Ensure migration docs prevent double-mutation surprises.

## 8. Rollout checklist

1. Add `proxy.egress.request_header_actions` to config.
2. Validate config in deployment environment.
3. Roll out and observe egress behavior in logs/capture.
4. Remove duplicated per-rule actions once global behavior is confirmed.

## 9. Operator checklist and evidence log schema

### Evidence block template

- Phase: `H0|H1|H2|H3`
- Completion date: `YYYY-MM-DD`
- Commit hash(es): `<hash list>`
- Acceptance evidence:
  - `<command/check>` -> `<result>`
- Review run IDs + triage outcomes:
  - `gemini:<run_id>` -> `<accept|defer|reject summary>`
  - `pi:<run_id>` -> `<accept|defer|reject summary>`
- Go/No-Go decision: `GO|NO-GO`
- Notes: `<deferred items / caveats>`

### Execution evidence blocks

- Phase: `H0`
- Completion date: `2026-03-08`
- Commit hash(es): `a08e9f6`
- Acceptance evidence:
  - `cargo test proxy_egress_request_header_actions --lib` -> passed (`3 passed; 0 failed`), covering default-empty behavior, valid parse, and location-aware invalid-value-shape errors.
  - `cargo test sample_config_in_repo_root_is_valid --lib` -> passed (`1 passed; 0 failed`), confirming existing sample config remains valid when the new section is absent.
- Review run IDs + triage outcomes:
  - `gemini:N/A` -> `defer`; per execution review policy, independent reviews are required at major gates and were executed at H2/H3.
  - `pi:N/A` -> `defer`; per execution review policy, independent reviews are required at major gates and were executed at H2/H3.
- Go/No-Go decision: `GO`
- Notes: `Global config contract is additive-only and preserves existing first-match policy behavior when the section is omitted.`

- Phase: `H1`
- Completion date: `2026-03-08`
- Commit hash(es): `d0f4177`
- Acceptance evidence:
  - `cargo test header_action_env_interpolation_resolves_egress_request_header_actions --lib` -> passed (`1 passed; 0 failed`), confirming load-time `${NAME}` resolution on global `set/add` values.
  - `cargo test header_action_env_interpolation_reports_egress_action_location --lib` -> passed (`1 passed; 0 failed`), confirming missing-env failures include `proxy.egress.request_header_actions[<idx>]` context.
  - `cargo test compile_egress_request_header_actions --lib` -> passed (`2 passed; 0 failed`), confirming request-only compile semantics and dedicated egress error context.
- Review run IDs + triage outcomes:
  - `gemini:N/A` -> `defer`; per execution review policy, independent reviews are required at major gates and were executed at H2/H3.
  - `pi:N/A` -> `defer`; per execution review policy, independent reviews are required at major gates and were executed at H2/H3.
- Go/No-Go decision: `GO`
- Notes: `Interpolation and compile plumbing were added without changing policy-match semantics.`

- Phase: `H2`
- Completion date: `2026-03-08`
- Commit hash(es): `9a16138`
- Acceptance evidence:
  - `cargo test --test proxy_http global_egress_request_actions` -> passed (`2 passed; 0 failed`), covering cross-layer ordering and non-interference with matching.
  - `cargo test --test proxy_http empty_global_egress_actions_preserve_existing_rule_header_behavior` -> passed (`1 passed; 0 failed`), confirming per-rule behavior is unchanged when global actions are empty.
  - `cargo test --test proxy_https_connect global_egress_request_actions_apply_to_https_connect_inner_requests` -> passed (`1 passed; 0 failed`), confirming CONNECT inner-request coverage.
  - `cargo test --test proxy_https_transparent global_egress_request_actions_apply_to_https_transparent_requests` -> passed (`1 passed; 0 failed`), confirming transparent HTTPS coverage.
- Review run IDs + triage outcomes:
  - `gemini:r_20260308203536377_08c206a7`
    - accept: add explicit intra-global ordering coverage; implemented via `global_egress_request_actions_respect_intra_layer_order`.
  - `pi:r_20260308203741841_568fdeab`
    - accept: add explicit empty-global-list regression coverage; implemented via `empty_global_egress_actions_preserve_existing_rule_header_behavior`.
    - defer: expanded follow-up coverage for additional CONNECT/H2 pseudo-header edge cases is outside this stream's locked scope.
- Go/No-Go decision: `GO`
- Notes: `Runtime ordering is now explicit and consistent across explicit HTTP, CONNECT inner requests, and transparent HTTPS forwarding.`

- Phase: `H3`
- Completion date: `2026-03-08`
- Commit hash(es): `1bfbf04`
- Acceptance evidence:
  - `cargo fmt` -> passed.
  - `cargo clippy` -> passed.
  - `cargo test` -> passed (`110 unit tests`, integration/doc tests all passed on rerun; one transient EOF flake was observed once in `allowed_https_via_connect_is_proxied_and_captured`, then reproduced as passing and full suite passed).
  - `cargo build --release` -> passed.
  - `rg -n "proxy\\.egress\\.request_header_actions|global egress request actions|do not affect rule matching|CONNECT inner requests|transparent HTTPS" docs/config-reference.md docs/configuration.md docs/policy.md docs/architecture.md acl-proxy.sample.toml` -> passed, confirming docs/sample updates for scope and ordering semantics.
  - `CHANGELOG.md` update -> deferred until PR number exists, per repository policy.
- Review run IDs + triage outcomes:
  - `gemini:r_20260308204214414_e18afb16`
    - accept: docs/sample describe ordering semantics, non-goals, and mode coverage clearly for stabilized behavior.
  - `pi:r_20260308204314063_bacee106`
    - defer: add an explicit operator note calling out reload behavior for `[[proxy.egress.request_header_actions]]` as a separate docs-hardening follow-up.
    - defer: add explicit docs callout for `policy dump` visibility of global egress compiled actions as a follow-up.
    - defer: add operations/troubleshooting callouts specific to global egress actions as a follow-up.
- Go/No-Go decision: `GO`
- Notes: `H3 docs/sample stabilization is complete for this stream; changelog entry is intentionally deferred until PR number assignment.`

### Execution-stage triage log

1. Finding: Add explicit intra-global action ordering test.
   - Decision: `accept`
   - Resolution: added `global_egress_request_actions_respect_intra_layer_order`.
2. Finding: Add explicit regression test for empty global action list.
   - Decision: `accept`
   - Resolution: added `empty_global_egress_actions_preserve_existing_rule_header_behavior`.
3. Finding: Add broader CONNECT/H2 pseudo-header edge-case coverage in this stream.
   - Decision: `defer`
   - Resolution: deferred to follow-up stream because current plan scope already locks request-layer behavior across explicit HTTP, CONNECT inner requests, and transparent HTTPS.
4. Finding: Add explicit reload-behavior note for global egress action section.
   - Decision: `defer`
   - Resolution: deferred as docs-hardening follow-up; baseline reload semantics already documented in config docs.
5. Finding: Clarify `policy dump` visibility expectations for global egress actions.
   - Decision: `defer`
   - Resolution: deferred to docs follow-up; current stream does not change policy-dump command behavior.
6. Finding: Add operations/troubleshooting-specific global egress callouts.
   - Decision: `defer`
   - Resolution: deferred to follow-up docs pass; core config and policy docs were prioritized for this stream.

### Authoring-stage review evidence (spec plan stream)

- Stage: `Spec authoring`
- Completion date: `2026-03-08`
- Review run IDs + triage outcomes:
  - `gemini:r_20260308200554967_556b4e87` -> `completed`
  - `pi:r_20260308200635028_a18509ec` -> `completed`
- Lock decision: `GO`
- Notes:
  - Accepted: dedicated global action config without `direction`; explicit CONNECT scope; explicit Host mutation semantics; decoupled global action compile path; expanded ordering/`when`/empty-list tests.
  - Deferred: global response-header action layer (out of this stream).
  - Rejected: reusing `HeaderActionConfig` with implicit/default `direction=request` because it keeps an ambiguous contract and weakens validation clarity.

### Authoring-stage triage log

1. Finding: Direction-field ambiguity for global actions.
   - Decision: `accept`
   - Resolution: define a dedicated global request action config with no `direction`.
2. Finding: `Host` mutation behavior unspecified.
   - Decision: `accept`
   - Resolution: lock behavior to header-only mutation; egress authority selection is unchanged.
3. Finding: Global compile path coupled to rule-index error context.
   - Decision: `accept`
   - Resolution: add a dedicated compile/validation path for global actions.
4. Finding: `CONNECT` scope unspecified.
   - Decision: `accept`
   - Resolution: lock to CONNECT metadata headers only, not tunneled traffic.
5. Finding: Hop-by-hop cleanup step may not reflect actual implementation.
   - Decision: `accept`
   - Resolution: remove it from ordering contract and rely on existing transport/protocol behavior wording.
6. Finding: Additional test gaps (cross-layer `when`, intra-global ordering, empty defaults).
   - Decision: `accept`
   - Resolution: add to H2/H3 acceptance and verification expectations.

## 10. Execution handoff contract

1. Required read order:
   1. `docs/implementation/global-egress-header-actions/schema-proposal.md`
   2. `docs/implementation/global-egress-header-actions/design.md`
   3. `docs/implementation/global-egress-header-actions/phase-task-plan.md`
2. Start point: `H0` only.
3. Boundaries and semantic-preservation constraints:
   - no policy-rule accumulation,
   - no global response actions,
   - no matching behavior changes,
   - preserve existing proxy mode behavior unless explicitly scoped.
4. Review command policy:
   - use `agent-runner-review` with independent Gemini + PI runs,
   - no timeout or reasoning-effort overrides,
   - completion by live stream terminal events.
5. Completion requirements:
   - docs + sample updates,
   - `CHANGELOG.md` `Unreleased` entry after PR number exists,
   - completed Section 9 evidence,
   - final phase summary including deferred/rejected items.

## 11. Default compact handoff prompt

`Use $agent-runner-spec-execution and $agent-runner-review.`

`Topic slug: global-egress-header-actions.`

`Read:`
`1) docs/implementation/global-egress-header-actions/schema-proposal.md`
`2) docs/implementation/global-egress-header-actions/design.md`
`3) docs/implementation/global-egress-header-actions/phase-task-plan.md`

`Execute all phases declared in phase-task-plan.md in strict order, using the plan as source of truth for scope, gates, review/triage policy, and Section 9 evidence updates.`
