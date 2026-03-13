# Policy Header Value Matching Phase Task Plan

Status: Locked

## 1. Scope

Deliver `headers_match`, a new inbound request-header value predicate for policy rules, while preserving existing first-match rule evaluation and all behavior when the field is not configured.

## 2. Global rules

1. Preserve all existing semantics for policies that do not use `headers_match`.
2. Keep matching deterministic and offline-testable.
3. Keep scope to exact value matching only.
4. Keep tests deterministic and fully offline.
5. Do not change header-action execution order or semantics.

## 3. Phase plan

## H0 - Contract and config schema wiring

Deliverables:

1. Add `headers_match` to direct rule and ruleset template config models.
2. Add parsing support for `header -> string | [string, ...]`.
3. Add validation for empty map, invalid header names, duplicate normalized names, and empty per-header values.
4. Update `docs/config-reference.md`, `docs/policy.md`, and `acl-proxy.sample.toml` with canonical usage and semantics.

Acceptance criteria:

1. Valid string/list syntax parses and validates.
2. Invalid configurations fail with deterministic errors.
3. Existing configs remain valid and unchanged.
4. New field is recognized as match criteria where applicable, including patternless direct rules.

## H1 - Policy engine matching and inspection output

Deliverables:

1. Compile `headers_match` into normalized header-name + allowed-value structures.
2. Evaluate `headers_match` in rule matching with locked semantics:
   - across keys: `AND`,
   - within values for a key: `OR`,
   - exact value equality (case-sensitive, no trimming, no comma tokenization).
3. Ensure interaction with `headers_absent` remains conjunctive (`AND`).
4. Ensure `headers_match` predicate is evaluated before external auth invocation on allow rules.
5. Add `headers_match` to effective policy JSON/table output.

Acceptance criteria:

1. Matching behavior for single-key, multi-value, and multi-key cases passes.
2. `headers_absent` + `headers_match` combined behavior is deterministic and documented.
3. Existing predicate behavior (`pattern`, `methods`, `subnets`, `headers_absent`) remains intact.
4. Policy inspection output includes `headers_match` with a locked empty-object behavior when unset.

## H2 - Integration coverage and docs finalization

Deliverables:

1. Add integration tests for deny/allow flow based on header value matching.
2. Add regression tests for repeated header values, comma-containing value handling, and case-insensitive header-name lookups.
3. Add CONNECT-path integration coverage proving matching is on decrypted inner requests.
4. Finalize policy/config docs to clarify exact-match semantics, ordering, and sensitive-value visibility in dumps.
5. Prepare changelog entry under `Unreleased` once PR number exists.

Acceptance criteria:

1. Integration tests prove deny-before-forward and allow-forward when values match, including CONNECT inner-request behavior.
2. Full required project verification passes (`cargo fmt`, `cargo clippy`, `cargo test`, `cargo build --release`).
3. Docs clearly differentiate predicate matching from header actions.

## 4. Verification matrix

| Phase | Verification command(s) | Required evidence |
| --- | --- | --- |
| H0 | Targeted config parsing/validation tests | Pass output + deterministic failure cases |
| H1 | Targeted `policy`/`policy_cli` tests | Pass output for `AND`/`OR`/exact semantics + dump output |
| H2 | `cargo fmt`, `cargo clippy`, `cargo test`, `cargo build --release` | Full pass output + integration behavior evidence |

### Phase-to-test mapping

- H0 tests:
  - parse/validation coverage for `string | [string]` value forms.
  - empty `headers_match` map rejection.
  - invalid header name rejection.
  - duplicate normalized header names rejection.
  - empty configured value rejection.
  - patternless `headers_match`-only rule accepted as valid match criteria.
- H1 tests:
  - single-key single-value success/failure.
  - single-key multi-value `OR`.
  - multi-key `AND`.
  - exact value semantics (case-sensitive, no trim, no comma split).
  - `headers_absent` + `headers_match` conjunctive behavior.
  - external-auth short-circuit behavior when header predicate fails.
  - policy dump JSON/table includes `headers_match` with locked empty-object semantics.
- H2 tests:
  - HTTP integration deny-before-forward and allow-forward flows.
  - repeated inbound header value behavior.
  - CONNECT decrypted inner-request matching behavior.
  - full project verification commands.

## 5. Milestone commit gate

1. H1 starts only after H0 evidence and review triage are recorded.
2. H2 starts only after H1 evidence and review triage are recorded.
3. Merge readiness requires all locked phase acceptance criteria and full verification matrix completion.

## 6. Review policy (execution stream)

1. Run independent Gemini and PI reviews at each phase gate using `agent-runner-review`.
2. Reviewer prompts must request concise findings for clarity, missing requirements, risks, and test gaps.
3. Triage every finding as `accept`, `defer`, or `reject`; no untriaged items.
4. Determine completion from live session stream terminal events (`result.completed` or `result.failed`).

## 7. Risk controls

1. Enforce exact-match-only contract to avoid ambiguous interpretation.
2. Require explicit tests for multi-key and multi-value semantics.
3. Keep `headers_absent` behavior unchanged and verify combined semantics.
4. Ensure docs and dump output expose final matching contract clearly.

## 8. Rollout checklist

1. Add value-matching rules in staging with explicit rule ordering.
2. Validate policy expansion and fields with `acl-proxy policy dump`.
3. Verify deny/allow behavior with representative headers.
4. Promote to production after log and traffic verification.

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

### Authoring-stage review evidence (spec plan stream)

- Stage: `Spec authoring`
- Completion date: `2026-03-13`
- Review run IDs + triage outcomes:
  - `gemini:r_20260313050939112_1184f073`
    - accept: explicitly lock case-sensitive exact-value semantics.
    - accept: explicitly lock repeated-header/comma-handling semantics.
    - accept: explicitly define empty inbound header-value behavior and associated tests.
  - `pi:r_20260313051022721_db9d03a9`
    - accept: clarify repeated-value wording and exact dump-output contract (`headers_match` always present, `{}` when unset).
    - accept: document include-rule behavior (template inheritance, no include override in this stream).
    - accept: document patternless `headers_match`-only rule validity.
    - accept: explicitly lock whitespace/comma handling and external-auth evaluation ordering.
    - accept: add sensitive-value visibility risk note for policy dump outputs.
    - accept: map concrete test scenarios to phase gates.
    - accept: add CONNECT-path integration coverage requirement.
    - defer: add large value-list performance sanity coverage (non-blocking follow-up optimization check).
    - reject: table-output truncation formatting requirements are out of scope for this contract-locking stream.
- Lock decision: `LOCKED`
- Notes: `Both required independent reviews completed via live session stream terminal events with no fallback path required.`

### Execution-stage evidence

- Phase: `H0`
- Completion date: `2026-03-13`
- Commit hash(es): `411f6f4`
- Acceptance evidence:
  - `cargo test headers_match --lib` -> passed (`12 passed; 0 failed`) covering parse/validation for string-or-list values, empty-map rejection, invalid-name rejection, duplicate-after-normalization rejection, empty-value rejection, and `headers_match`-only rule validity.
  - `rg -n "headers_match|headers_absent" docs/config-reference.md docs/policy.md acl-proxy.sample.toml src/config/mod.rs src/policy/mod.rs` -> confirmed config model wiring, direct/template docs, include inheritance note, patternless match-criteria validation wiring, and sample usage.
- Review run IDs + triage outcomes:
  - `gemini:r_20260313134354823_624c6f2c`
    - accept: H0 `headers_match` contract/config wiring and targeted test coverage satisfy declared scope.
    - defer: `capture.max_body_bytes` upper-bound validation concern is outside this topic stream.
    - defer: non-default proxy integration assertion for `capture.max_body_bytes` is outside this topic stream.
  - `pi:r_20260313134547509_c7b21a8a`
    - accept: H0 deliverables and documentation alignment are complete and clear.
    - defer: transient `dead_code` warning risk for `ExpandedRule.headers_match` until H1 evaluation wiring lands.
    - defer: `capture.max_body_bytes` upper-bound guard is outside this topic stream.
- Go/No-Go decision: `GO`
- Notes: `Gemini and PI execution-stage reviews were completed via live session stream terminal events; one earlier Gemini attempt (r_20260313133823206_8d69967e) was interrupted during a stream stall retry and not used for gate evidence.`

## 10. Execution handoff contract

1. Required read order:
   - `docs/implementation/policy-header-value-matching/schema-proposal.md`
   - `docs/implementation/policy-header-value-matching/design.md`
   - `docs/implementation/policy-header-value-matching/phase-task-plan.md`
2. Phase start point: `Start at H0 only`.
3. Boundaries and semantic-preservation constraints:
   - exact value matching only,
   - no regex/glob matching,
   - preserve first-match behavior,
   - preserve all behavior when field absent,
   - no header-action semantic changes.
4. Review command policy requirements:
   - use `agent-runner-review`,
   - no timeout/reasoning-effort CLI overrides,
   - completion from live session terminal events,
   - triage all findings.
5. Completion requirements:
   - update stable docs if behavior is finalized,
   - update `CHANGELOG.md` under `Unreleased` after PR number exists,
   - complete Section 9 evidence for each phase,
   - provide final phase summary with go/no-go status.
