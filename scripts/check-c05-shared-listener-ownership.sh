#!/usr/bin/env bash
set -euo pipefail

ROOT=${ACL_PROXY_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}

fail() {
    printf 'C05 shared-listener ownership check failed: %s\n' "$1" >&2
    exit 1
}

obsolete_paths=(
    src/certs
    src/http1
    src/tls_identity.rs
    src/upgrade
    src/runtime_body_source.rs
    src/proxy/authority.rs
    src/proxy/facts.rs
    src/proxy/h2_stream_cancellation.rs
    src/proxy/headers.rs
    src/proxy/ingress.rs
    src/proxy/upgrade_relay.rs
    third_party/hyper
)
for path in "${obsolete_paths[@]}"; do
    [[ ! -e "$ROOT/$path" ]] || fail "obsolete owner exists: $path"
done

[[ -f "$ROOT/src/control/tls_identity.rs" ]] || fail 'control TLS owner is missing'
[[ -f "$ROOT/src/proxy/observation_adapter.rs" ]] || fail 'product observation adapter is missing'
[[ -f "$ROOT/src/proxy/private_fields.rs" ]] || fail 'product private-field partition is missing'

python3 - "$ROOT/Cargo.toml" <<'PY' || fail 'acl-proxy directly depends on Hyper through a dependency name, package alias, or path'
import pathlib
import sys
import tomllib

manifest = tomllib.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))

def check_dependencies(table):
    for name, value in table.items():
        if name == "hyper":
            raise SystemExit(1)
        if isinstance(value, dict):
            if value.get("package") == "hyper":
                raise SystemExit(1)
            path = value.get("path")
            if isinstance(path, str) and "hyper" in pathlib.PurePath(path).parts:
                raise SystemExit(1)

for key in ("dependencies", "dev-dependencies", "build-dependencies"):
    check_dependencies(manifest.get(key, {}))
for target in manifest.get("target", {}).values():
    if not isinstance(target, dict):
        continue
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        check_dependencies(target.get(key, {}))
PY

mapfile -d '' product_sources < <(
    find "$ROOT" \
        -path "$ROOT/.git" -prune -o \
        -path "$ROOT/target" -prune -o \
        -path "$ROOT/.cargo" -prune -o \
        -type f \( -name '*.rs' -o -name 'Cargo.toml' \) -print0
)

for source in "${product_sources[@]}"; do
    relative=${source#"$ROOT/"}
    if grep -Eq 'hyper::|extern[[:space:]]+crate[[:space:]]+hyper([^[:alnum:]_]|$)' "$source"; then
        fail "direct Hyper ownership returned in $relative"
    fi
    if grep -Eq '(ProductProxySupervisorStarter|ProductIngressSupervisor|ConnectTunnelPlan|ProxyResponseBody|UpgradeEntryPlan|UpgradeRelayPair|PreparedUpgradeRelay|WebSocketNegotiation|H2StreamCancellation|ValidatedIngressIo|MitmCertificateManager|StandaloneIngressTransport|StandaloneTerminalService|ForwardingOutcome)' "$source"; then
        fail "deleted data-plane or handoff owner returned in $relative"
    fi
    if grep -Eq '#[[:space:]]*\[[[:space:]]*path[[:space:]]*=.*(ingress|upgrade_relay|certs|tls_identity|http1)' "$source"; then
        fail "deleted owner returned through a path module in $relative"
    fi
    if grep -Eq 'include![[:space:]]*\([^)]*(ingress|upgrade_relay|certs|tls_identity|http1)' "$source"; then
        fail "deleted owner returned through include! in $relative"
    fi
    if grep -Eq '(^|[^[:alnum:]_])mod[[:space:]]+(http1|certs|upgrade)[[:space:]]*;' "$source"; then
        fail "deleted owner returned through a module alias in $relative"
    fi
    if grep -Eq '(^|[^[:alnum:]_])mod[[:space:]]+tls_identity[[:space:]]*;' "$source" \
        && [[ "$relative" != src/control/mod.rs ]]; then
        fail "deleted root TLS owner returned through a module alias in $relative"
    fi
done

grep -Fq 'http_access_runtime::http1' "$ROOT/src/control/connection.rs" \
    || fail 'control does not consume the shared HTTP/1 facade'
grep -Fq 'http_access_runtime::http1' "$ROOT/src/authorization/webhook/ack.rs" \
    || fail 'webhook acknowledgement does not consume the shared HTTP/1 facade'
grep -Fq 'ListenerRuntime::start(bundle, services)' "$ROOT/src/activation/runner.rs" \
    || fail 'product does not synchronously adopt the shared listener runtime'
grep -Fq 'ProductStandaloneRequestFactory::new' "$ROOT/src/activation/runner.rs" \
    || fail 'shared listener is not wired to the product request factory'
grep -Fq 'ProductUpgradeCaptureContext' "$ROOT/src/proxy/observation_adapter.rs" \
    || fail 'shared relay capture factory adapter is missing'

private_field_cases=(
    standalone_ingress_atomically_binds_method_version_framing_and_upgrade_transport
    standalone_connect_ingress_atomically_binds_empty_facts_and_tunnel_transport
    ordinary_ingress_partitions_authorization_and_custom_internal_before_neutralization
    outer_connect_partitions_sensitive_values_before_neutralization
    prepartition_consumes_nominated_sensitive_fields_and_preserves_valid_upgrade_control
    h2_invalid_te_remains_for_shared_validation_after_prepartition
    connection_nominated_partition_owners_are_removed_before_connect_extraction
    ordinary_proxy_authorization_presence_is_retained_but_value_never_becomes_neutral
    connect_proxy_authorization_presence_is_retained_but_value_never_becomes_neutral
    ordinary_raw_projection_bounds_precede_internal_partition
    connect_raw_projection_bounds_precede_internal_partition
    standalone_connect_ingress_rejects_wrong_mode_target_framing_or_body
)
for case_id in "${private_field_cases[@]}"; do
    grep -Eq "fn[[:space:]]+$case_id[[:space:]]*\(" "$ROOT/src/proxy/private_fields.rs" \
        || fail "missing retained private-field oracle: $case_id"
done

control_tls_cases=(
    control_tls_identity_loads_valid_material
    control_tls_identity_rejects_missing_and_empty_materials
    control_tls_identity_rejects_malformed_private_key_pem
    control_tls_identity_rejects_malformed_certificate_pem
    control_tls_identity_rejects_mismatched_certificate_and_private_key
)
for case_id in "${control_tls_cases[@]}"; do
    grep -Eq "fn[[:space:]]+$case_id[[:space:]]*\(" "$ROOT/src/control/tls_identity.rs" \
        || fail "missing control TLS oracle: $case_id"
done

printf 'C05 shared-listener ownership check passed (12 private-field, 5 control-TLS oracles)\n'
