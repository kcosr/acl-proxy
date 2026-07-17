#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
RUNTIME_ROOT=${ACCESS_RUNTIME_ROOT:-"$ROOT/../access-runtime"}
CHECKER_MANIFEST=${PIPELINE_OWNERSHIP_CHECK_MANIFEST:-"$RUNTIME_ROOT/Cargo.toml"}

cargo run --quiet --locked \
    --manifest-path "$CHECKER_MANIFEST" \
    -p pipeline-ownership-check -- header-shared "$RUNTIME_ROOT"
cargo run --quiet --locked \
    --manifest-path "$CHECKER_MANIFEST" \
    -p pipeline-ownership-check -- header-product "$ROOT"

metadata=$(cd "$ROOT" && cargo metadata --format-version 1 --no-deps)
python3 - "$ROOT" "$RUNTIME_ROOT" "$metadata" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
runtime = pathlib.Path(sys.argv[2]).resolve()
metadata = json.loads(sys.argv[3])
package = next(package for package in metadata["packages"] if package["name"] == "acl-proxy")
matches = [
    dependency
    for dependency in package["dependencies"]
    if dependency["name"] == "http-access-runtime"
]
expected = runtime / "crates" / "http-access-runtime"
production = [dependency for dependency in matches if dependency["kind"] is None]
development = [dependency for dependency in matches if dependency["kind"] == "dev"]
if len(production) != 1:
    raise SystemExit("acl-proxy must have exactly one production http-access-runtime dependency")
if len(development) != 1:
    raise SystemExit("acl-proxy must have exactly one dev-harness http-access-runtime dependency")
if len(matches) != 2:
    raise SystemExit("acl-proxy has an unexpected additional http-access-runtime dependency")
for dependency in matches:
    if dependency.get("rename") is not None:
        raise SystemExit("http-access-runtime must not be renamed")
    if dependency["req"] != "=0.1.0":
        raise SystemExit("http-access-runtime must use exact version =0.1.0")
    if pathlib.Path(dependency["path"]).resolve() != expected:
        raise SystemExit(f"http-access-runtime must use the exact sibling path {expected}")
    if dependency.get("source") is not None or dependency.get("optional"):
        raise SystemExit("http-access-runtime must be a required local path dependency")
    if dependency.get("target") is not None or not dependency.get("uses_default_features", True):
        raise SystemExit("http-access-runtime dependency scope/default features changed")
if production[0].get("features") != []:
    raise SystemExit("production http-access-runtime dependency must not enable test features")
if development[0].get("features") != ["dev-harness"]:
    raise SystemExit("development http-access-runtime dependency must enable only dev-harness")
PY

runtime_inventory=$(mktemp "${TMPDIR:-/tmp}/shared-header-runtime-tests.XXXXXX")
product_inventory=$(mktemp "${TMPDIR:-/tmp}/shared-header-product-tests.XXXXXX")
cleanup() {
    rm -f -- "$runtime_inventory" "$product_inventory"
}
trap cleanup EXIT INT TERM

cargo run --quiet --locked \
    --manifest-path "$CHECKER_MANIFEST" \
    -p pipeline-ownership-check -- inventory "$RUNTIME_ROOT" \
    crates/http-access-runtime/src/header_hygiene.rs >"$runtime_inventory"
cargo run --quiet --locked \
    --manifest-path "$CHECKER_MANIFEST" \
    -p pipeline-ownership-check -- inventory "$ROOT" \
    src/proxy/headers.rs >"$product_inventory"

moved_cases=(
    request_hygiene_derives_h1_and_h2_targets
    h2_te_is_strict_and_protocol_translation_is_exact
    attacker_nominations_precede_trusted_changes_and_hop_injection_fails
    upgrades_preserve_request_spelling_and_validate_response
    connect_and_connection_token_errors_fail_closed
    response_cleanup_tolerates_bad_nominations_and_bounds_are_enforced
)
for case_id in "${moved_cases[@]}"; do
    if ! grep -Fxq -- "$case_id" "$runtime_inventory"; then
        printf 'missing moved shared header test case: %s\n' "$case_id" >&2
        exit 1
    fi
done
if ((${#moved_cases[@]} == 0)); then
    printf 'moved shared header test inventory is vacuous\n' >&2
    exit 1
fi

adapter_cases=(
    ingress_adapter_preserves_body_extensions_and_upgrade_owner
    neutral_product_conversion_preserves_duplicate_order
)
for case_id in "${adapter_cases[@]}"; do
    if ! grep -Fxq -- "$case_id" "$product_inventory"; then
        printf 'missing retained product header adapter test case: %s\n' "$case_id" >&2
        exit 1
    fi
done

obsolete_product_cases=(
    h1_origin_form_rebuilds_authority_and_preserves_canonical_encoding
    h1_parent_uses_exact_absolute_form
    h2_rebuilds_pseudo_authority_without_a_host_header
    response_hygiene_removes_connection_nominated_and_proxy_headers
    h1_strips_te_even_when_the_client_only_offers_trailers
    h2_normalizes_trailers_te_and_rejects_every_other_value
    production_translation_matches_the_shared_fixture_corpus
    attacker_connection_tokens_are_consumed_before_trusted_injection
    trusted_hop_header_mutation_fails_closed
    h2_trailers_te_is_removed_when_selected_origin_is_h1
    trusted_trailers_te_is_retained_when_selected_origin_is_h2
    trusted_trailers_te_is_removed_when_selected_origin_is_h1
    valid_upgrade_intent_is_typed_before_hop_header_sanitization
    malformed_and_h2_upgrade_intents_fail_closed
    dedicated_upgrade_request_restores_only_canonical_handshake_headers
    upgrade_response_is_validated_and_canonicalized
    h1_and_h2_connect_require_the_dedicated_executor
    malformed_connection_token_list_fails_closed
    connection_tokens_trim_only_http_ows_and_reject_obs_text
)
for case_id in "${obsolete_product_cases[@]}"; do
    if grep -Fxq -- "$case_id" "$product_inventory"; then
        printf 'obsolete product-owned header semantic test remains: %s\n' "$case_id" >&2
        exit 1
    fi
done

printf 'shared header ownership/deletion and moved-test gate passed (%d moved, %d adapter cases)\n' \
    "${#moved_cases[@]}" "${#adapter_cases[@]}"
