#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
RUNTIME_ROOT=${ACCESS_RUNTIME_ROOT:-"$ROOT/../access-runtime"}
CHECKER_MANIFEST=${PIPELINE_OWNERSHIP_CHECK_MANIFEST:-"$RUNTIME_ROOT/Cargo.toml"}
INVENTORY_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/forwarding-product-inventory.XXXXXX")
cleanup() {
    rm -rf -- "$INVENTORY_ROOT"
}
trap cleanup EXIT INT TERM

collect_inventory() {
    local source_file=$1
    local inventory_name=$2
    cargo run --quiet --locked \
        --manifest-path "$CHECKER_MANIFEST" \
        -p pipeline-ownership-check -- inventory "$ROOT" \
        "$source_file" >"$INVENTORY_ROOT/$inventory_name"
}

require_cases() {
    local group=$1
    local inventory_name=$2
    shift 2
    if (($# == 0)); then
        printf 'product forwarding test group is vacuous: %s\n' "$group" >&2
        exit 1
    fi
    local case_id
    for case_id in "$@"; do
        if ! grep -Fxq -- "$case_id" "$INVENTORY_ROOT/$inventory_name"; then
            printf 'missing retained product forwarding test case in %s: %s\n' \
                "$group" "$case_id" >&2
            exit 1
        fi
    done
}

credential_retained_cases=(
    connect_failure_precedes_environment_credential_resolution
    credential_rotation_and_disappearance_fail_closed
    external_source_projection_reserves_one_bounded_io_operation
    parent_connect_rejection_precedes_environment_credential_resolution
)
activation_retained_cases=(
    forwarding_network_facts_derive_from_compiled_static_config
)
egress_retained_cases=(
    custom_ca_failures_are_classified_without_exposing_paths
    custom_ca_material_reads_are_bracketed_by_cancellation_checks
    http_parent_owns_canonical_endpoint_and_kind
    insecure_origin_and_parent_each_emit_one_sanitized_warning
    neutral_root_bindings_change_for_content_and_generation_and_preserve_trust_mode
    one_custom_ca_read_feeds_origin_parent_and_exact_registrations
)
ingress_retained_cases=(
    absolute_deadline_bounds_committed_upgrade_setup
    downstream_cancellation_after_accepted_101_releases_committed_upgrade_once
)
adapter_context_cases=(
    downstream_version_requires_matching_h2_stream_context
)

ingress_c03_oracles=(
    h1_204_removes_content_length_and_preserves_pipeline
    h1_consumed_origin_trailers_remove_the_downstream_declaration
    h1_205_normalizes_nonzero_content_length_and_preserves_pipeline
    h1_304_preserves_representation_content_length_and_pipeline
    h1_response_wire_limit_closes_before_committing_a_partial_response
    h2_204_removes_content_length_data_and_trailers
    h2_205_response_suppresses_origin_data_and_completes_terminal
    h2_304_preserves_representation_content_length
    h2_exact_final_chunk_window_watchdog_resets_before_eof_poll
    h2_one_byte_window_complete_cl2_watchdog_resets_without_window_update
    h2_response_wire_limit_resets_only_the_failed_stream
    h2_zero_window_complete_cl0_watchdog_resets_and_releases_admission
    h2_zero_window_complete_cl1_watchdog_resets_and_preserves_sibling_stream
    h2_zero_window_watchdog_releases_admission_and_preserves_sibling_stream
    h2_zero_window_watchdog_sends_stream_cancel
    head_h1_response_completes_terminal_without_body_polling
    ordinary_forwarding_preserves_response_trailers_end_to_end
    upgrade_admission_saturation_rejects_before_second_origin_connect
)

collect_inventory src/credential_resolver.rs credentials
collect_inventory src/activation/assets.rs activation
collect_inventory src/egress.rs egress
collect_inventory src/proxy/forwarding_adapter.rs adapter
collect_inventory src/proxy/ingress.rs ingress

require_cases retained-credentials credentials "${credential_retained_cases[@]}"
require_cases retained-activation activation "${activation_retained_cases[@]}"
require_cases retained-egress egress "${egress_retained_cases[@]}"
require_cases retained-ingress ingress "${ingress_retained_cases[@]}"
require_cases h2-context adapter "${adapter_context_cases[@]}"
require_cases c03-product-e2e ingress "${ingress_c03_oracles[@]}"

retained_count=$((${#credential_retained_cases[@]}
    + ${#activation_retained_cases[@]}
    + ${#egress_retained_cases[@]}
    + ${#ingress_retained_cases[@]}))
if ((retained_count != 13)); then
    printf 'retained product forwarding inventory has unexpected size: %d\n' \
        "$retained_count" >&2
    exit 1
fi
if ((${#ingress_c03_oracles[@]} != 18)); then
    printf 'product C03 forwarding oracle inventory has unexpected size: %d\n' \
        "${#ingress_c03_oracles[@]}" >&2
    exit 1
fi

printf 'product forwarding test inventory passed (%d retained contract cases, %d H2 context oracle, %d C03 E2E oracles)\n' \
    "$retained_count" "${#adapter_context_cases[@]}" "${#ingress_c03_oracles[@]}"
