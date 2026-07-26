# Sanitized Production V1 To V4 Difference Record

## Scope And Handling

This corpus is a deterministic, non-secret representation of three production
roles. It is not a copy of production configuration, provider authorization
data, private names, filesystem paths, identity material, redaction material,
or certificate keys. Private destinations use reserved `.example.test`
authorities and benchmark network ranges.

The source files were inventoried read-only. Their byte identities establish
traceability without retaining their contents:

| Role | Source bytes | Source SHA256 | Sanitized v4 fixture |
| --- | ---: | --- | --- |
| host TCP | 15,597 | `401d5573e9ee82d1f042e66c15034644741ab297f3e45e88e844bad0943aed00` | `host-proxy-tcp.toml` |
| host UDS workstation | new topology | not derived from a production source file | `host-proxy-uds.toml` |
| common container | 1,077 | `a93af31c7a0c74e6f44ea6c8b58fbcddf2648933a61ee28d1421e0fa3ca04bd4` | `common-container-proxy.toml` |
| internal container | 2,907 | `0c8965f1529ed55618624d0fd5f4c2a39f066cf076a6400acf4dd91b8d0d09e0` | `internal-container-proxy.toml` |

The TCP fixture preserves the migrated source topology. The separate UDS host
fixture records the workstation end state: only transparent Access Flow over Unix data
listeners, one fixed local-workstation principal with no `client_cidrs`, and
mandatory TLS parent-proxy egress with typed workstation identity injection.

The sanitized v1 files retain only obsolete authoring shapes needed for strict
negative tests. They are not production byte copies.

## Structural Inventory

| Role | V4 rules | V4 patterns | Actions | Scheme intent |
| --- | ---: | ---: | --- | --- |
| host TCP | 44 | 133 | 37 allow, 6 deny, 1 delegate | 118 HTTPS, 13 HTTP, 2 catchall |
| host UDS workstation | 1 | 1 | 1 allow | catchall under fixed workstation identity |
| common container | 1 | 1 | 1 allow | catchall |
| internal container | 8 | 12 | 8 allow | 11 HTTPS, 1 HTTP |

The host fixture has 22 method-constrained rules, no header-predicate rules, and
4 wire-redaction rules. The v4 fixture preserves source-rule order,
HTTP-versus-HTTPS intent, method boundaries, and provider placement. The host
adds one CONNECT-only bootstrap rule because parent CONNECT control requests
intentionally carry no origin identity or context. It also applies mandatory
wire redaction to content-coded telemetry under the reviewed R7 normalization
contract. Context-header predicates are the other reviewed exception described
below.

## Authoring And Ownership Changes

| V1 source shape | V4 fixture disposition |
| --- | --- |
| string schema version and mixed proxy table | integer schema 4 with explicit service, listener, control, MITM, egress, policy, observation, and safety owners |
| implicit listener defaults | explicit 8881 HTTP/CONNECT MITM and 8889 transparent HTTPS listeners |
| readiness on proxy data plane | loopback control listener on 8898; proxy listeners have no control routes |
| host-generated CA directory | explicit generated MITM mode |
| container CA certificate/key paths | explicit file MITM mode; tests generate non-checked-in material |
| parent host and port | `route = "parent_proxy"`, `kind = "acl_proxy"`, and one canonical HTTPS URL with explicit trust |
| loop protection enabled with inner add-header false | unconditional detection with `inject = false` only for the `acl_proxy` child |
| remove identity then set it from an environment placeholder | one typed static identity token source, required listener identity, and typed ACL Proxy parent presentation |
| host identity header removal | protected carrier extraction authenticates before policy and the bearer cannot enter ordinary header configuration |
| literal policy-context injection/removal | declared internal-context header with exactly one unconditional global set or remove action |
| policy `action`, `pattern`/`patterns`, and implicit IDs | ordered `decision` plus one `urls` array and stable source-index IDs |
| context value used as a policy predicate | removed as an authentication input; sanitized CIDRs retain ordering/blast-radius intent and the Git provider validates the exact identity/context pair |
| legacy plugin profiles | generation-owned process providers with config-rooted command/arguments, no environment inheritance, and a minimal explicit PATH |
| implicit provider retirement | explicit two-hour retirement windows cover the host role's greatest effective request timeout |
| exact environment placeholders in redaction literals | five typed `literal_environment_variables` plus one ordinary synthetic literal and one expression |
| request-header rule removing `Sec-WebSocket-Extensions` | typed `unsupported_extensions = "strip"` on `sensitive_strings`; protected upgrades strip unsupported compression before origin forwarding |
| content-coded telemetry forwarded without mandatory normalization | the Sentry/Datadog telemetry rule selects `sensitive_strings`, producing bounded identity-coded upstream bytes under the R7 contract |
| all capture events disabled | capture table absent |
| relative runtime paths with legacy ownership | config-rooted fixture paths |

The context change is intentional security hardening. The internal fixture
injects the invented value `fixture-internal`. The host declares a consuming
role, strips the context before origin egress, and passes it only to the Git
process provider. The raw identity bearer is never projected to a provider. The
Git delegate is limited to an exact authority-qualified authenticated group,
and both process providers receive the complete checked identity projection
plus the exact matched rule ID. Local policy does not trust an internal-context
value. Sanitized benchmark CIDRs preserve the source rule groups without
claiming that a source address authenticates a workload.

## Provider Traceability And Parity

| Source artifact | Bytes | SHA256 | Sanitized artifact |
| --- | ---: | --- | --- |
| Git provider script | 10,730 | `30d4903d38a9aadd55905aadd28b4743e852ed9221874dd14ee638ab3f35904a` | `providers/gitlab_acl.py` |
| Git provider data | 3,516 | `b05f8ac09e30b22676a892990d402f8659fe2effd7a3c115fae89ce5ceb31212` | `providers/gitlab_acl.json` |
| runner provider script | 2,308 | `4008a18c49769191d680ee91c13346a5bf621b54b67e63e41c699709aad27e2c` | `providers/agent_runner_acl.py` |
| runner provider data | 827 | `665d0d7d3d2dd518938b25b2daee474d842211439cc5269cd2bb0edd606fd8d5` | `providers/agent_runner_acl.json` |

The source scripts use `#!/usr/bin/env python3`, `--config` with a relative JSON
file, newline-delimited JSON on stdin/stdout, stable request IDs, and only
`allow` or `deny`. Missing and unknown identities deny with a normal response.
The active Git provider receives context plus checked identity and authorizes
the exact matched rule through authority-qualified group membership. The
configured but inactive runner provider receives checked principal identity and
uses the same rule-ID keyed provider contract. Synthetic providers preserve the
existing protocol and failure posture without reproducing source code or
private authorization data.

## Host Rule Map

Stable IDs retain the source role and zero-based source index. Private
destinations and paths are replaced, but the stated counts apply to each row.

| Source | V4 ID | Decision | Patterns | Preserved intent |
| --- | --- | --- | ---: | --- |
| bootstrap | `prod-host-parent-connect` | allow | 1 | credential-free parent CONNECT from the sanitized container network; inner requests remain fully authorized |
| 01 | `prod-host-r01-ai-redaction-a` | allow | 4 | AI service group with wire redaction |
| 02 | `prod-host-r02-editor-redaction` | allow | 2 | editor group, one-label wildcard, wire redaction |
| 03 | `prod-host-r03-ai-redaction-b` | allow | 7 | AI/source group, recursive ChatGPT wildcard, wire redaction |
| 04 | `prod-host-r04-context-a-allow` | allow | 12 | paired HTTP/HTTPS context-A destination group |
| 05 | `prod-host-r05-context-b-models` | allow | 4 | context-B model endpoints |
| 06 | `prod-host-r06-context-a-corporate-deny` | deny | 14 | paired HTTP/HTTPS context-A broad deny |
| 07 | `prod-host-r07-github-sensitive-deny` | deny | 2 | scoped source-host deny |
| 08 | `prod-host-r08-npm-mutation-deny` | deny | 1 | package PUT/PATCH/DELETE deny |
| 09 | `prod-host-r09-context-a-catchall` | allow | 1 | context-A catchall |
| 10 | `prod-host-r10-development-host` | allow | 1 | development host |
| 11 | `prod-host-r11-agent-service` | allow | 1 | internal agent service |
| 12 | `prod-host-r12-agent-chat` | allow | 1 | internal agent chat API |
| 13 | `prod-host-r13-telemetry` | allow | 3 | telemetry and recursive Sentry/Datadog wildcards with reviewed wire redaction |
| 14 | `prod-host-r14-raw-source-get` | allow | 1 | GET raw source content |
| 15 | `prod-host-r15-storage-get` | allow | 2 | GET storage/download pair |
| 16 | `prod-host-r16-context-c-model-a-deny` | deny | 1 | context-C model-A gate |
| 17 | `prod-host-r17-context-c-model-a-get` | allow | 1 | GET model-A download |
| 18 | `prod-host-r18-context-c-model-b-deny` | deny | 1 | context-C model-B gate |
| 19 | `prod-host-r19-context-c-model-b-get` | allow | 1 | GET model-B download |
| 20 | `prod-host-r20-editor-download-get` | allow | 1 | GET editor download |
| 21 | `prod-host-r21-ai-source-downloads` | allow | 2 | GET AI/source downloads |
| 22 | `prod-host-r22-private-api-group` | allow | 8 | ordered private API group |
| 23 | `prod-host-r23-private-api-put` | allow | 1 | private API PUT |
| 24 | `prod-host-r24-private-api-get-a` | allow | 1 | private API GET |
| 25 | `prod-host-r25-private-api-get-b` | allow | 1 | private API GET |
| 26 | `prod-host-r26-private-api-get-c` | allow | 1 | private API GET |
| 27 | `prod-host-r27-private-api-post-a` | allow | 1 | private API POST |
| 28 | `prod-host-r28-private-api-post-b` | allow | 1 | private API POST |
| 29 | `prod-host-r29-private-api-post-c` | allow | 1 | private API POST |
| 30 | `prod-host-r30-agent-api-group` | allow | 8 | ordered agent API group |
| 31 | `prod-host-r31-private-api-secondary` | allow | 6 | secondary private API group |
| 32 | `prod-host-r32-toolchain-downloads` | allow | 20 | GET/HEAD toolchain and package downloads |
| 33 | `prod-host-r33-package-sources` | allow | 3 | GET package sources |
| 34 | `prod-host-r34-ai-npm-packages` | allow | 2 | GET AI package metadata |
| 35 | `prod-host-r35-npm-get` | allow | 1 | npm GET |
| 36 | `prod-host-r36-npm-post` | allow | 1 | npm POST |
| 37 | `prod-host-r37-rocky-downloads` | allow | 3 | GET OS mirrors and label-local Rocky wildcard |
| 38 | `prod-host-r38-public-gitlab-get` | allow | 1 | GET public Git service |
| 39 | `prod-host-r39-internal-git-read` | allow | 2 | internal Git token/repository reads |
| 40 | `prod-host-r40-internal-git-query` | allow | 2 | query-bearing internal Git reads |
| 41 | `prod-host-r41-internal-git-context-c-deny` | deny | 2 | internal-workload deny before delegation |
| 42 | `prod-host-r42-gitlab-delegate` | delegate | 1 | process-provider identity/context validation |
| 43 | `prod-host-r43-private-tail-allow` | allow | 2 | final private destination pair |

## Container Rule Map

| Source | V4 ID | Decision | Patterns | Preserved intent |
| --- | --- | --- | ---: | --- |
| common 00 | `prod-common-r00-parent-all` | allow | 1 | all valid URLs forwarded to the acl-proxy parent |
| internal 00 | `prod-internal-r00-internal-api` | allow | 1 | internal API |
| internal 01 | `prod-internal-r01-downloads` | allow | 5 | GET source/release downloads |
| internal 02 | `prod-internal-r02-packages` | allow | 1 | package registry |
| internal 03 | `prod-internal-r03-tool-service` | allow | 1 | internal tool service |
| internal 04 | `prod-internal-r04-gitlab` | allow | 1 | internal Git service |
| internal 05 | `prod-internal-r05-development-host` | allow | 1 | development host |
| internal 06 | `prod-internal-r06-corporate-https` | allow | 1 | one-label HTTPS corporate wildcard |
| internal 07 | `prod-internal-r07-corporate-http` | allow | 1 | one-label HTTP corporate wildcard |

## Wildcard Review

- Recursive whole-label intent is explicit only for `**.chatgpt.com`,
  `**.sentry.io`, and `**.datadoghq.com`.
- Label-local intent is explicit for
  `rocky-linux-*.production.gcp.mirrors.ctrliq.cloud`.
- Whole-label `*` remains one DNS label in the editor, corporate, and sanitized
  private wildcard rules. No legacy single star is silently widened to `**`.
- Base-domain access is represented separately where intended; recursive
  patterns never imply the base domain.

## Required Integration Assertions

1. Parse the four v4 fixtures through `AuthoringConfig` and compile them with temporary
   CA files and five deterministic redaction environment values.
2. Reject all three sanitized v1 shapes through the strict runtime and CLI.
3. Assert the exact rule IDs, counts, pattern counts, method sets, wildcard
   classes, provider placement, and redaction placement recorded above.
4. Execute both synthetic providers for allow, deny, missing or unknown checked
   identity, malformed input, restart, timeout, and reload cases.
5. Prove the protected bearer is filtered from both providers and origin
   traffic, checked identity and matched rule ID reach both provider transports,
   and the internal context reaches only the Git provider.
6. Probe readiness at control port 8898 and prove control paths are unavailable
   through ports 8881 and 8889.
