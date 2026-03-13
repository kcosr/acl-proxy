# Policy Header Value Matching Design

Status: Locked

## 1. Purpose

Define a minimal, deterministic policy predicate that matches inbound request headers by value so operators can require trusted identity header values directly in policy rules.

## 2. Problem statement

`headers_absent` allows deny guards for missing headers, but operators cannot express "header must be present with one of these values" in native policy. Today that pushes value checks into external auth plugins, which adds operational complexity for common cases.

## 3. Goals

1. Add a native rule predicate for exact inbound header value matching.
2. Keep first-match policy behavior unchanged.
3. Preserve deterministic offline validation and evaluation.
4. Keep config syntax concise for one or many headers.

## 4. Non-goals

1. Regex/glob/substring value matching in this stream.
2. Boolean expression trees (`any`/`all` groups, negation blocks).
3. Response-header matching.
4. Header-action behavior changes.
5. Plugin contract changes.

## 5. Current baseline

1. Policy predicates are `pattern`, `methods`, `subnets`, and `headers_absent`.
2. `headers_absent` matches when any listed header name is missing.
3. Header actions run after a rule matches and do not affect rule matching.
4. Effective policy output and `policy dump` include `headers_absent` but no header-value predicate.

## 6. Key decisions

1. Add optional `headers_match` on direct rules and ruleset templates.
2. Syntax: map of `header-name -> string | [string, ...]`.
3. Header-name lookup is case-insensitive and normalized to lowercase at validation.
4. Multiple header keys combine with `AND` semantics.
5. Multiple allowed values for one key combine with `OR` semantics.
6. Matching is exact value equality (case-sensitive, no trimming, no regex/glob/substring transforms).
7. `headers_match` combines with existing predicates using existing implicit `AND` behavior.
8. Include rules inherit template `headers_match`; include rules do not override `headers_match` in this stream.
9. `headers_match` is valid as standalone match criteria (patternless rule support), same as existing method/subnet/header predicates.
10. Feature is additive; existing configs remain valid.

## 7. Contract / HTTP semantics

1. Evaluate `headers_match` against inbound request headers before forwarding and before any header actions.
2. A header key in `headers_match` passes when:
   - the header is present, and
   - at least one inbound header value exactly matches one configured allowed value.
3. The full `headers_match` predicate passes only when all configured header keys pass.
4. Repeated inbound header values are supported; any matching value satisfies that header key.
5. Each header field value is evaluated as received; values are not split on commas.
6. Empty inbound header values do not match because configured allowed values must be non-empty.
7. If `external_auth_profile` is configured on a rule, `headers_match` must pass before external auth is invoked for that rule.
8. On HTTPS over CONNECT, matching applies to the decrypted inner request, not outer CONNECT establishment metadata.
9. If both `headers_absent` and `headers_match` are set on a rule, both predicates must pass for the rule to match.

## 8. Service/module design

1. Config model:
   - add `headers_match` to `PolicyRuleDirectConfig` and `PolicyRuleTemplateConfig`.
   - add a reusable untagged config type for string-or-list values.
2. Validation:
   - `headers_match` map must not be empty when provided.
   - each header name must be a valid HTTP header name.
   - header names are normalization-deduped (case-insensitive duplicate keys reject deterministically).
   - each configured value must be a non-empty string; each header value list must be non-empty after parsing.
   - value comparison is case-sensitive raw equality; no whitespace normalization is applied.
3. Policy compile path:
   - compile normalized header names and allowed values once per rule.
4. Evaluation path:
   - add a `headers_match` check after method/subnet checks and before rule acceptance.
5. Effective policy / inspection:
   - include `headers_match` in JSON and table policy dump output.
   - effective JSON output always includes `headers_match`; rules without this predicate serialize as `{}`.

## 9. Error semantics

1. Empty `headers_match` map -> config validation failure.
2. Invalid header name -> config validation failure.
3. Duplicate header names after case normalization -> config validation failure.
4. Empty allowed values for any header key -> config validation failure.
5. If predicate does not match at runtime, rule falls through exactly as today.

## 10. Migration strategy

1. Keep existing `headers_absent` deny-guard patterns unchanged.
2. Add value-sensitive rules where needed, for example:
   - deny when token header missing (existing `headers_absent`),
   - allow only when token header equals trusted value (`headers_match`).
3. Treat `headers_match` values as potentially sensitive; restrict who can run/see `policy dump` outputs in production.
4. Roll out with explicit rule ordering validation using `acl-proxy policy dump`.

## 11. Test strategy

1. Config tests:
   - valid parse for string and list forms,
   - empty map rejection,
   - invalid-name rejection,
   - duplicate-name-after-normalization rejection,
   - empty-value-list rejection.
2. Policy engine unit tests:
   - single-key single-value match,
   - single-key multi-value `OR`,
   - multi-key `AND`,
   - case-insensitive header names,
   - repeated inbound header values,
   - interaction with `headers_absent`, `methods`, `subnets`.
3. Integration tests:
   - top guard plus allow fallback with concrete header values,
   - non-matching value denied without upstream forwarding,
   - matching value forwarded.
4. CLI tests:
   - `policy dump --format json` includes `headers_match`.
   - table output includes a `HEADERS_MATCH` column.
5. CONNECT-path integration:
   - verify `headers_match` is evaluated on decrypted inner requests for HTTPS CONNECT traffic.

## 12. Acceptance criteria

1. `headers_match` config is parsed, validated, and compiled deterministically.
2. Rule evaluation supports exact value matching with documented `AND`/`OR` semantics.
3. Existing policy behavior remains unchanged when `headers_match` is absent.
4. Effective policy output/docs reflect final contract.

## 13. Status and risks

1. Risk: confusion between predicate matching and header actions.
   - Mitigation: explicit docs on ordering and separation of concerns.
2. Risk: ambiguous expectations around exact matching vs pattern matching.
   - Mitigation: contract explicitly locks exact matching only.
3. Risk: misordered rules reduce intended protection.
   - Mitigation: rollout guidance and policy dump verification.
