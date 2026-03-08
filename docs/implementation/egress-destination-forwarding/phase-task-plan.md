# Egress Destination Forwarding Phase Task Plan

Status: Locked

## 1. Scope

Deliver phase-one support for default egress destination forwarding with config/docs/tests, preserving current ACL semantics and enabling chained proxy deployments.

## 2. Global rules

1. Preserve semantic behavior for disabled/default configuration.
2. Keep all tests deterministic and offline.
3. No transparent HTTP scope in this effort.
4. No per-rule egress profile selection in this effort.
5. Outer CONNECT handshake behavior remains unchanged in phase one.
6. Every phase must satisfy acceptance checks before next phase starts.

## 3. Phase plan

## H0 - Contract and config scaffolding

Deliverables:

1. Add config model for default egress forwarding profile (host + port).
2. Add validation and deterministic error messages for invalid host/port.
3. Define reload behavior expectations for forwarding config.
4. Update config docs and sample config references.

Acceptance criteria:

1. Startup/reload succeeds with valid config and fails deterministically with invalid config.
2. Existing configs without forwarding settings remain valid.
3. Sample config and config reference include new fields and semantics.
4. Schema-version impact decision is documented (additive change, no version bump in phase one).

## H1 - Transport wiring and forwarding behavior

Deliverables:

1. Wire optional forwarding destination into outbound transport for allowed request-forwarding paths.
2. Keep rule evaluation and logs keyed on original request URL/method/client IP.
3. Preserve host-header contract (original authority remains `Host`).
4. Ensure external-auth transport path remains unaffected.

Acceptance criteria:

1. With feature off: behavior equivalent to current baseline.
2. With feature on: allowed request-forwarding paths use forwarding destination.
3. Deny behavior unchanged.
4. External-auth requests are not redirected by forwarding override.

## H2 - Integration coverage and operator safety

Deliverables:

1. Add two-proxy-chain smoke test (no iptables) validating end-to-end forwarding.
2. Add header-action trust test (`remove` then `set`) across forwarding path.
3. Add unavailable-destination failure test.
4. Add config-reload test for forwarding enable/disable transition.
5. Add chained loop-protection behavior test for supported operator strategy.
6. Update operator docs for loop bypass, loop-header strategy, TLS trust, and timeout sizing.

Acceptance criteria:

1. New tests pass reliably in CI/local.
2. Docs include deployment warnings and recovery guidance.
3. Changelog entry is prepared under `Unreleased` when implementation PR exists.

## 4. Verification matrix

| Phase | Verification command(s) | Required evidence |
| --- | --- | --- |
| H0 | Targeted config validation tests + sample config validation test | Passing output and note on schema/additive compatibility |
| H1 | Targeted proxy forwarding tests across explicit + HTTPS paths | Passing output for feature disabled/enabled and ext-auth isolation |
| H2 | `cargo fmt`, `cargo clippy`, `cargo test`, `cargo build --release` | Command outputs + smoke-test and reload evidence |

## 5. Milestone commit gate

1. Do not start H1 until H0 acceptance criteria are met and evidence captured.
2. Do not start H2 until H1 acceptance criteria are met and evidence captured.
3. Final merge gate requires all H2 acceptance criteria and required project checks (`fmt`, `clippy`, `test`, `build --release`).

## 6. Review policy (for execution stream)

1. At each phase completion, run independent reviews via `agent-runner-review` (Gemini + PI) on changed artifacts/code.
2. Triage each finding as `accept`, `defer`, or `reject`.
3. Record review run IDs and triage outcomes in Section 9 evidence.

## 7. Risk controls

1. Keep feature behind optional config.
2. Avoid external-auth regression by explicit transport scoping tests.
3. Explicitly test TLS and host/authority semantics in chained mode.
4. Validate loop-protection strategy in chained deployments.

## 8. Rollout checklist

1. Deploy host proxy and verify baseline policy behavior.
2. Deploy in-container proxy with forwarding disabled, confirm baseline.
3. Enable forwarding destination and identity header actions.
4. Configure loop-header strategy and redirect bypass exemptions.
5. Validate captures/logs, then roll forward or roll back.

## 9. Operator checklist and evidence log schema

Use one evidence block per phase.

### Evidence block template

- Phase: `H0|H1|H2`
- Completion date: `YYYY-MM-DD`
- Commit hash(es): `<hash list>`
- Acceptance evidence:
  - `<test command>` -> `<pass/fail + short notes>`
  - `<artifact/doc check>` -> `<result>`
- Review run IDs + triage outcomes:
  - `gemini:<run_id>` -> `accept|defer|reject` summary
  - `pi:<run_id>` -> `accept|defer|reject` summary
- Go/No-Go decision: `GO|NO-GO`
- Notes: `<rollout caveats, deferred items>`

### Authoring-stage review evidence (spec plan stream)

- Stage: `Spec authoring`
- Completion date: `2026-03-08`
- Review run IDs + triage outcomes:
  - `gemini:r_20260308003708787_bc918eb0`
    - accept: TLS/SNI trust requirements and external-auth isolation tests explicitly added.
    - accept: loop-protection operational expectations clarified.
    - accept: additional test coverage callouts incorporated.
  - `pi:r_20260308003744123_f964bc96`
    - accept: host-header contract explicitly locked.
    - accept: CONNECT-scope lock clarified (outer CONNECT unchanged).
    - accept: reload behavior and loop-protection test expectations added.
    - accept: host-format validation requirements tightened.
    - defer: env var overrides for egress forwarding (deferred to post-phase-one expansion).
    - reject: add `enabled` field now (rejected; presence/absence of section is the phase-one toggle for minimal config surface).
- Lock decision: `LOCKED`
- Notes: Both required independent reviews completed from live session streams; no fallback path needed.
