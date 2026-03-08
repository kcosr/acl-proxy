# Policy Headers-Absent Guard Design

Status: Locked

## 1. Purpose

Define a minimal policy extension that enables explicit top-of-policy deny guards when required identity headers are missing.

## 2. Problem statement

Current policy matching supports URL pattern, methods, and subnets. There is no native rule predicate for missing-request-header checks, which makes fail-closed identity-header enforcement awkward without plugins.

Operators want a simple configuration field that works with existing first-match policy flow:

- top deny guard rule,
- pattern `**`,
- list of required header names,
- deny when any listed header is absent,
- otherwise fall through to normal rules.

## 3. Goals

1. Add one minimal rule predicate field: `headers_absent`.
2. Preserve existing first-match rule evaluation model.
3. Enable explicit deny guards for missing headers using ordinary policy rules.
4. Keep behavior deterministic and easy to reason about.

## 4. Non-goals

1. Full generic boolean matcher trees (`all/any/none`).
2. Header value matching (`glob`/regex/exact) in this feature.
3. Global pre-policy required-header gate.
4. Plugin/external-auth workflow changes.

## 5. Current baseline

1. Rule predicates: `pattern`, `methods`, `subnets`.
2. Header actions mutate headers after rule match; they do not affect rule matching.
3. Method/subnet mismatch causes rule fall-through; no automatic deny.
4. PolicyEngine evaluation currently does not include request-header predicate input.

## 6. Key decisions

1. Introduce `headers_absent = ["header-a", ...]` as a new rule predicate.
2. Predicate semantics: rule condition is true when **any** listed header is absent on the inbound request.
3. Header names are case-insensitive; normalize to lowercase in compile/validation path.
4. `headers_absent` combines with other predicates using existing implicit `AND` semantics.
5. Keep first-match flow unchanged: if `headers_absent` does not match, continue evaluating next rule.
6. Scope to direct and template-derived rules in phase one; include rules inherit template behavior.
7. Rules using only `headers_absent` are valid match-criteria rules.

## 7. Contract / HTTP semantics

1. `headers_absent` is evaluated against inbound request headers before forwarding and before any header actions are applied.
2. If a rule has `headers_absent` and any listed header is absent, this predicate passes.
3. If all listed headers are present, this predicate fails and rule does not match.
4. A header that is present with an empty value is treated as present (not absent).
5. Other predicates (`pattern`, `methods`, `subnets`) retain current semantics.

## 8. Service/module design

1. Config model:
   - add optional `headers_absent: Vec<String>` to direct rules and template rules.
2. Validation:
   - list must not be empty when provided,
   - each header name must be a valid HTTP header name token,
   - duplicate names after normalization are rejected.
3. Policy compile/evaluate path:
   - compile header names once,
   - evaluate absence predicate during rule matching.
4. Internal interface impact:
   - policy evaluation path must receive request headers where decisions are made,
   - update policy evaluation call sites accordingly.
5. Effective policy output:
   - include `headers_absent` in effective/inspection output for operator visibility.

## 9. Error semantics

1. Invalid header name -> config validation failure.
2. Empty `headers_absent` list -> config validation failure.
3. Duplicate normalized header names -> config validation failure.
4. Runtime behavior remains deterministic fall-through when predicate fails.

## 10. Migration strategy

1. Feature is additive and optional.
2. Existing configs remain valid.
3. Recommended rollout pattern:
   - add top deny guard rule with `pattern = "**"` and `headers_absent = ["x-workload-id"]`,
   - keep existing allow rules below,
   - verify deny logging and rule ordering.

## 11. Test strategy

1. Config tests for validation failures and normalization behavior.
2. Policy engine tests:
   - rule matches when header absent,
   - rule does not match when header present,
   - present-but-empty value is treated as present,
   - case-insensitive header lookup,
   - multi-header scenarios (`any`-absent semantics),
   - `headers_absent` with other predicates (`AND` combination),
   - `headers_absent`-only rule validity.
3. Integration tests:
   - top deny guard then allow fallback,
   - method-constrained deny guard behavior,
   - unchanged behavior when field is absent.

## 12. Acceptance criteria

1. `headers_absent` is parsed and validated deterministically.
2. Top deny guard scenario works with existing first-match semantics.
3. Existing policies without `headers_absent` are unchanged.
4. Effective policy output and docs reflect new predicate.

## 13. Status and risks

1. Risk: confusion between `headers_absent` (predicate) and header actions.
   - Mitigation: explicit docs with ordering notes.
2. Risk: internal policy-evaluate interface changes can miss call sites.
   - Mitigation: compile-time call-site updates + targeted integration tests.
