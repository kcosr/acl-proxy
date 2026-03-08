# Policy Headers-Absent Guard Phase Task Plan

Status: Locked

## 1. Scope

Deliver a minimal `headers_absent` rule predicate to support top-level deny guards for missing headers while preserving current first-match behavior.

## 2. Global rules

1. Preserve existing policy semantics when `headers_absent` is not configured.
2. Keep feature additive and deterministic.
3. Keep tests offline and deterministic.
4. Do not expand to header value matching in this stream.

## 3. Phase plan

## H0 - Contract and schema wiring

Deliverables:

1. Add `headers_absent` to direct/template rule config model.
2. Add validation for empty/invalid/duplicate names.
3. Update `has_match_criteria` validation to recognize `headers_absent`.
4. Update config reference and sample docs with usage.

Acceptance criteria:

1. Valid configs parse successfully.
2. Invalid header names and invalid lists fail with clear errors.
3. Existing configs remain valid.
4. Header-name normalization behavior is covered by tests.

## H1 - Policy evaluation implementation

Deliverables:

1. Compile and normalize `headers_absent` names in policy engine.
2. Evaluate absence predicate in rule matching with `AND` semantics against other predicates.
3. Update policy-evaluation interface and call sites to include request headers.
4. Include new predicate in effective policy output.

Acceptance criteria:

1. Rule matches when any listed header is absent.
2. Rule does not match when all listed headers are present.
3. Present-but-empty headers are treated as present.
4. Existing method/subnet/pattern behavior remains intact.

## H2 - Integration coverage and docs finalization

Deliverables:

1. Add integration test for top deny guard with fallback allow rules.
2. Add method-constrained deny-guard integration case.
3. Add unit tests for multi-header `any`-absent semantics.
4. Finalize docs with ordering and action/predicate distinctions.

Acceptance criteria:

1. Tests cover guard behavior, empty-value behavior, and fall-through semantics.
2. Documentation clearly differentiates predicate from header actions.
3. Changelog entry prepared under `Unreleased` once PR number exists.

## 4. Verification matrix

| Phase | Verification command(s) | Required evidence |
| --- | --- | --- |
| H0 | Targeted config validation tests | Pass output + invalid-case evidence |
| H1 | Targeted policy tests | Pass output for absent/present/empty/fall-through |
| H2 | `cargo fmt`, `cargo clippy`, `cargo test`, `cargo build --release` | Full pass output + integration evidence |

## 5. Milestone commit gate

1. H1 starts only after H0 gate evidence is recorded.
2. H2 starts only after H1 gate evidence is recorded.
3. Final merge requires all project-required checks.

## 6. Review policy (execution stream)

1. Run independent Gemini and PI reviews at phase gates.
2. Triage each finding as `accept`, `defer`, or `reject`.
3. Record run IDs and triage in Section 9 evidence.

## 7. Risk controls

1. Strict validation prevents ambiguous config.
2. Minimal scope avoids semantic drift.
3. Tests explicitly verify fall-through behavior.
4. Call-site updates are required for policy evaluation signature changes.

## 8. Rollout checklist

1. Add top deny guard rule in non-prod validation environment.
2. Verify deny logs for missing headers.
3. Confirm allow behavior for valid requests.
4. Roll to production after policy ordering review.

## 9. Operator checklist and evidence log schema

### Evidence block template

- Phase: `H0|H1|H2`
- Completion date: `YYYY-MM-DD`
- Commit hash(es): `<hash list>`
- Acceptance evidence:
  - `<test command>` -> `<result>`
  - `<doc/config check>` -> `<result>`
- Review run IDs + triage outcomes:
  - `gemini:<run_id>` -> summary
  - `pi:<run_id>` -> summary
- Go/No-Go decision: `GO|NO-GO`
- Notes: `<caveats/deferred items>`

### Execution-stage evidence

- Phase: `H0`
- Completion date: `2026-03-08`
- Commit hash(es): `416252e`
- Acceptance evidence:
  - `cargo test headers_absent --lib` -> passed (`6 passed; 0 failed`) covering empty-list rejection, invalid-header rejection, duplicate-after-normalization rejection, `headers_absent`-only match criteria, template validation, and positive normalization.
  - `rg -n "headers_absent" docs/config-reference.md acl-proxy.sample.toml src/config/mod.rs src/policy/mod.rs` -> confirmed config-model fields, `has_match_criteria` wiring, validation helper/tests, ruleset/direct-rule docs, include inheritance note, and sample usage are present.
- Review run IDs + triage outcomes:
  - `gemini:r_20260308033027172_e1f21047`
    - accept: H0 deliverables and targeted coverage are complete.
    - reject: include-rule override symmetry for `headers_absent` is outside the locked minimal scope.
    - reject: templated header-name placeholders are outside the locked contract.
  - `pi:r_20260308033027199_8a5ad453`
    - accept: add `headers_absent` to the ruleset-template field listing in `docs/config-reference.md`.
    - accept: document that include rules inherit `headers_absent` from referenced templates and do not override it in this release.
    - accept: add a positive normalization assertion for valid `headers_absent` input.
    - defer: effective policy / inspection output remains an H1 deliverable.
    - reject: duplicate empty-list validation in `validate_basic()` is unnecessary because the policy validation path already returns a clear deterministic error.
- Go/No-Go decision: `GO`
- Notes: Both required reviews completed from live session streams with no fallback. The only deferred item is the effective-policy output update, which is explicitly scoped to H1.

- Phase: `H1`
- Completion date: `2026-03-08`
- Commit hash(es): `859736c`
- Acceptance evidence:
  - `cargo test headers_absent --lib` -> passed (`13 passed; 0 failed`) covering absent/present/empty behavior, case-insensitive lookup, method+subnet `AND` semantics, validation, normalization, and effective-policy output.
  - `cargo test policy_dump --test policy_cli` -> passed (`4 passed; 0 failed`) confirming JSON and table inspection output both include `headers_absent`.
- Review run IDs + triage outcomes:
  - `gemini:r_20260308033714556_bd797e9b`
    - accept: H1 deliverables are implemented cleanly across engine compilation, evaluation, call sites, and inspection output.
    - defer: clarify in H2 docs that `headers_absent` applies to decrypted inner requests, not CONNECT tunnel establishment metadata.
  - `pi:r_20260308033714564_29a5eeb6`
    - accept: add explicit subnet `AND` semantics coverage for `headers_absent`.
    - defer: multi-header `any`-absent semantics test remains scheduled for H2 per the locked phase plan.
    - defer: CONNECT outer-vs-inner request-header behavior should be clarified in H2 docs.
    - reject: narrowing `is_allowed_with_headers` to a test-only API is stylistic and not required.
    - reject: keeping both validation-time normalization and compile-time `HeaderName` conversion is intentional separation of concerns.
- Go/No-Go decision: `GO`
- Notes: Both required reviews completed from live session streams with no fallback. The only deferred items are H2-scoped docs/integration coverage additions.

### Authoring-stage review evidence (spec plan stream)

- Stage: `Spec authoring`
- Completion date: `2026-03-08`
- Review run IDs + triage outcomes:
  - `gemini:r_20260308024424416_2f229312`
    - accept: empty-value vs absent behavior explicitly defined and tested.
    - accept: explicit `AND` combination semantics documented.
    - accept: malformed-header validation test requirements clarified.
  - `pi:r_20260308024456281_5d1a2dd8`
    - accept: policy-evaluate interface impact documented.
    - accept: `headers_absent` recognized as match criteria in validation plan.
    - accept: effective policy output update captured.
    - accept: additional edge-case tests added.
    - defer: richer logging of which header triggered match (defer to follow-up observability feature).
    - reject: expanding scope to generic negation in this stream (explicit non-goal).
- Lock decision: `LOCKED`
- Notes: Both required reviews completed from live session streams; no fallback needed.
