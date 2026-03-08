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

### Execution evidence

- Phase: `H0`
- Completion date: `2026-03-08`
- Commit hash(es): `5977b46`
- Acceptance evidence:
  - `cargo test proxy_egress --lib` -> `PASS (9 tests); config parsing/validation covers absent config, valid config, blank/whitespace host rejection, port-suffix rejection, IPv6 literals, bracketed IPv6 handling, malformed bracket rejection, and port=0 rejection`
  - `cargo test sample_config_in_repo_root_is_valid --lib` -> `PASS; sample config remains valid with forwarding config documented as optional`
  - `cargo test --test config_reload egress_forwarding` -> `PASS (2 tests); valid forwarding config applies on reload and invalid forwarding config is rejected without replacing the active state`
  - `docs/config-reference.md`, `docs/configuration.md`, `acl-proxy.sample.toml` -> `UPDATED; additive schema-v1 contract documented, reload behavior noted, and no schema_version bump required when adding [proxy.egress.default]`
- Review run IDs + triage outcomes:
  - `gemini:r_20260308022747464_d720241a`
    - accept: `port = 0` violated the locked `1..65535` contract; fixed with explicit validation in `validate_egress_target`
    - accept: added unit coverage for `port = 0` rejection
  - `pi:r_20260308022747472_260109cf`
    - accept: added bracketed IPv6 documentation and test coverage for valid and malformed bracketed hosts
    - accept: expanded `docs/configuration.md` with a brief forwarding-behavior summary
    - defer: add reload coverage for `Some(target) -> None` transition in `H2` alongside the phase-planned enable/disable reload test
    - reject: no changes to `AppState::from_config` were needed; rejected because startup/reload needed direct validation parity and `AppState::from_config` now enforces `config.validate_basic()`
- Go/No-Go decision: `GO`
- Notes: `H0 preserves default behavior when forwarding config is absent. External-auth transport and CONNECT outer-handshake behavior remain untouched in this phase.`

- Phase: `H1`
- Completion date: `2026-03-08`
- Commit hash(es): `788fa20`
- Acceptance evidence:
  - `cargo test --test proxy_http allowed_request_is_proxied_and_loop_header_added` -> `PASS; feature-off explicit HTTP path still proxies directly and preserves existing loop-header behavior`
  - `cargo test --test proxy_http allowed_request_uses_configured_egress_forwarding_destination` -> `PASS; explicit HTTP path dials the configured egress destination while preserving absolute-form URI and original Host header`
  - `cargo test --test proxy_http external_auth_webhook_transport_is_not_redirected_by_egress_forwarding` -> `PASS; external-auth webhook transport still reaches the configured webhook directly while the allowed proxied request goes to the forwarding destination`
  - `cargo test --test proxy_https_connect allowed_https_via_connect_is_proxied_and_captured` -> `PASS; feature-off CONNECT outer/inner behavior remains on the existing path`
  - `cargo test --test proxy_https_connect configured_egress_forwarding_applies_to_https_connect_inner_requests` -> `PASS; CONNECT outer handshake remains unchanged and decrypted inner HTTPS requests forward through the configured egress destination with original Host/URI semantics preserved`
  - `cargo test --test proxy_https_transparent allowed_https_transparent_is_proxied_and_captured` -> `PASS; feature-off transparent HTTPS path remains on the existing direct-origin behavior`
  - `cargo test --test proxy_https_transparent configured_egress_forwarding_applies_to_https_transparent_requests` -> `PASS; transparent HTTPS requests forward through the configured egress destination with original Host/URI semantics preserved`
- Review run IDs + triage outcomes:
  - `gemini:r_20260308023829702_530052f1`
    - defer: document plaintext egress-leg transport expectations in operator guidance during `H2`
    - reject: elevate background egress-connection logs from `debug`; rejected for phase one because it is an observability preference, not a correctness defect
  - `pi:r_20260308023829724_28b90b92`
    - defer: add unavailable-egress and timeout-path coverage in `H2`, which already owns the failure-path test deliverables
    - defer: add forwarding-path header-action and operator TLS guidance in `H2`, which already owns trust-header and operator-doc stabilization
    - reject: add connection pooling now; rejected because it is outside the locked phase-one transport scope and not required for correctness
    - reject: require CONNECT/transparent-specific external-auth isolation duplicates now; rejected because all allowed paths converge through the same `proxy_allowed_request` transport seam and the explicit integration test already proves the isolation boundary
- Go/No-Go decision: `GO`
- Notes: `H1 forwards only allowed proxied request paths. Policy evaluation, capture metadata, and Host-header semantics remain tied to the original target, outer CONNECT handshake stays unchanged, and external-auth transport remains isolated from forwarding override.`

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
