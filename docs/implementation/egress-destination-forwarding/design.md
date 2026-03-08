# Egress Destination Forwarding Design

Status: Locked

## 1. Purpose

Define a correct and extensible design for forwarding allowed outbound proxy traffic to a fixed upstream destination (host + port) while preserving ACL semantics and enabling trusted identity header injection.

## 2. Problem statement

Current `acl-proxy` forwards allowed requests directly to origin targets derived from request URL/authority. This blocks a deployment model where:

- a local proxy instance runs inside a workload/container,
- local iptables redirects workload egress to that in-container proxy,
- the in-container proxy injects trusted identity headers, and
- the in-container proxy forwards to a host-level proxy for final policy and upstream access.

A native forwarding target is required so chaining does not depend on brittle external NAT rules.

## 3. Goals

1. Add an optional configurable outbound forwarding destination (host + port) used for allowed proxied traffic.
2. Preserve rule matching semantics (URL, method, subnet, rule ordering) on the original request target.
3. Keep forwarding model compatible with existing header actions so static identity headers can be injected and spoofed headers removed.
4. Design phase-one config as a default egress profile that can evolve into per-rule profile selection later.
5. Keep behavior deterministic, reloadable, and testable offline.

## 4. Non-goals

1. Per-rule egress profile selection in phase one.
2. Transparent HTTP feature work (separate roadmap item).
3. Load balancing, failover pools, or health-checked upstream sets.
4. Automatic loop-header rewriting between chained proxies.
5. New environment-variable overrides for egress forwarding in phase one.

## 5. Current baseline

1. HTTP explicit listener expects absolute-form request URIs; non-absolute is rejected (`400`).
2. Transparent HTTPS listener exists; policy evaluates each decrypted request.
3. Policy uses request URL + method + client IP/subnet; first matching rule decides.
4. Header actions already support `set`, `add`, `remove`, and `replace_substring`.
5. Upstream transport currently dials target authority from request URL.
6. Loop protection rejects inbound requests containing configured loop header.

## 6. Key decisions

1. Introduce an optional **default egress profile** in config, represented as fixed destination host and port.
2. Keep policy and audit metadata bound to original request target, not forwarding destination.
3. Implement forwarding override at transport-connect stage, not by mutating policy URL semantics.
4. Keep phase-one selection global: all allowed requests use default egress profile when enabled.
5. Preserve backward compatibility by making profile optional; absent profile keeps current direct-origin behavior.
6. Keep a forward-compatible config shape so per-rule profile selection can be added later without replacing transport plumbing.
7. Scope lock for CONNECT: outer CONNECT handshake behavior remains unchanged; forwarding override applies to normal forwarded request paths, including decrypted inner HTTPS requests.

## 7. Contract / HTTP semantics

When forwarding is enabled:

1. Policy matching continues to evaluate original normalized URL/method/client IP.
2. Request header actions still execute exactly as today.
3. Outbound TCP destination is overridden to configured egress host:port.
4. `Host` header for forwarded requests remains the original target authority, not the forwarding destination.
5. Loop protection expectations for chained deployments are explicit:
   - either distinct loop header names per proxy hop, or
   - disable outbound loop-header injection on the inner proxy.
6. Error status behavior remains existing proxy behavior unless a deterministic config validation error occurs.

## 8. Service/module design

### 8.1 Config model

Add forwarding configuration under proxy config as a default egress profile placeholder for future expansion.

### 8.2 App state and transport

Keep external-auth transport isolated from proxy forwarding transport behavior. Forwarding override must apply only to proxied request forwarding path.

### 8.3 Forwarding call sites

Forwarding behavior must be validated across all request-forwarding entry points:

1. HTTP explicit forwarding path (`src/proxy/http.rs` for non-CONNECT requests).
2. HTTPS transparent decrypted request path (`src/proxy/https_transparent.rs`).
3. HTTPS CONNECT inner decrypted request path (`src/proxy/https_connect.rs`).

### 8.4 Reload behavior

Egress forwarding config changes apply on config reload via existing shared-state swap behavior; restart is not required.

### 8.5 Observability

Capture/logging remains keyed to original URL/decision metadata. Destination override diagnostics are logged for operator troubleshooting.

## 9. Error semantics

1. Invalid forwarding host/port config fails startup/reload with deterministic config validation errors.
2. Invalid host format (blank/whitespace or host including port suffix) fails validation.
3. If forwarding destination is unreachable, existing upstream failure semantics apply (`502`, timeout handling).
4. Denied request behavior remains unchanged.

## 10. Migration strategy

1. Default: feature off, no behavior change.
2. Enable by adding forwarding profile config.
3. Rollout sequence:
   - deploy host proxy,
   - deploy in-container proxy with forwarding enabled,
   - configure loop-header strategy for chained proxies,
   - enable iptables redirect to in-container proxy with bypass exemptions,
   - verify request traces and tighten identity header policy.

## 11. Test strategy

1. Unit tests: config parsing/validation and forwarding profile edge cases.
2. Integration tests:
   - baseline direct-origin behavior unchanged when feature disabled,
   - forwarding-enabled chain across two proxy instances and one upstream echo service,
   - identity header `remove` then `set` sequence preserved,
   - external-auth webhook path remains unaffected by forwarding override,
   - config reload applies forwarding config changes,
   - error path when forwarding destination unavailable.
3. Deterministic offline only; local ephemeral listeners only.

## 12. Acceptance criteria

1. Feature is optional and backward-compatible.
2. Enabled forwarding sends allowed request-forwarding traffic to configured destination.
3. Rule matching remains based on original request target.
4. `Host` header semantics are locked to original target authority.
5. Header action behavior remains unchanged and usable for trusted identity injection.
6. Integration smoke test validates two-proxy chain without iptables.
7. External-auth behavior remains isolated from forwarding override.
8. Docs and config reference updates are included.

## 13. Open risks and mitigations

1. Risk: host/SNI/authority mismatch regressions in HTTPS chaining.
   - Mitigation: explicit TLS path integration tests and deployment trust notes.
2. Risk: accidental coupling of external-auth client to forwarding override.
   - Mitigation: transport isolation + explicit tests.
3. Risk: loops in production due to redirect/header settings.
   - Mitigation: documented loop-header strategy and bypass requirements.
4. Risk: chain latency increasing timeout failures.
   - Mitigation: operator guidance on `request_timeout_ms` sizing for two-hop flow.
