#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/forwarding-product-inventory-test.XXXXXX")
cleanup() {
    rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

BASELINE="$TEST_ROOT/baseline"
mkdir -p \
    "$BASELINE/scripts" \
    "$BASELINE/src/activation" \
    "$BASELINE/src/proxy"
cp "$SOURCE_ROOT/scripts/check-forwarding-product-test-inventory.sh" "$BASELINE/scripts/"

credential_cases=(
    connect_failure_precedes_environment_credential_resolution
    credential_rotation_and_disappearance_fail_closed
    external_source_projection_reserves_one_bounded_io_operation
    parent_connect_rejection_precedes_environment_credential_resolution
)
activation_cases=(
    forwarding_network_facts_derive_from_compiled_static_config
)
egress_cases=(
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
ingress_c03_cases=(
    h1_204_removes_content_length_and_preserves_pipeline
    h1_consumed_origin_trailers_remove_the_downstream_declaration
    h1_205_normalizes_nonzero_content_length_and_preserves_pipeline
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

write_test_module() {
    local source_file=$1
    shift
    mkdir -p "$(dirname -- "$source_file")"
    {
        printf '%s\n' '#[cfg(test)]' 'mod tests {'
        local case_id
        for case_id in "$@"; do
            printf '    #[test]\n    fn %s() {}\n' "$case_id"
        done
        printf '%s\n' '}'
    } >"$source_file"
}

write_test_module "$BASELINE/src/credential_resolver.rs" "${credential_cases[@]}"
write_test_module "$BASELINE/src/activation/assets.rs" "${activation_cases[@]}"
write_test_module "$BASELINE/src/egress.rs" "${egress_cases[@]}"
write_test_module "$BASELINE/src/proxy/forwarding_adapter.rs" "${adapter_context_cases[@]}"
write_test_module "$BASELINE/src/proxy/ingress.rs" \
    "${ingress_retained_cases[@]}" "${ingress_c03_cases[@]}"

runner() {
    PIPELINE_OWNERSHIP_CHECK_MANIFEST="$SOURCE_ROOT/../access-runtime/Cargo.toml" \
        "$1/scripts/check-forwarding-product-test-inventory.sh"
}

runner "$BASELINE" >"$TEST_ROOT/pass.log"
grep -Fq 'product forwarding test inventory passed (13 retained contract cases, 1 H2 context oracle, 17 C03 E2E oracles)' \
    "$TEST_ROOT/pass.log"

expect_failure() {
    local root=$1
    local description=$2
    if runner "$root" >"$TEST_ROOT/failure.log" 2>&1; then
        printf '%s was accepted\n' "$description" >&2
        exit 1
    fi
    if ! grep -Fq 'missing retained product forwarding test case' "$TEST_ROOT/failure.log"; then
        printf '%s failed for the wrong reason\n' "$description" >&2
        cat "$TEST_ROOT/failure.log" >&2
        exit 1
    fi
}

mutations=0
mutate_cases() {
    local source_file=$1
    shift
    local case_id
    for case_id in "$@"; do
        mutations=$((mutations + 1))
        local case_root="$TEST_ROOT/case-$mutations"
        cp -R "$BASELINE" "$case_root"
        sed -i "/#\[test\]/{N; /fn $case_id()/d;}" "$case_root/$source_file"
        expect_failure "$case_root" "missing product forwarding oracle $case_id"
    done
    return 0
}

mutate_cases src/credential_resolver.rs "${credential_cases[@]}"
mutate_cases src/activation/assets.rs "${activation_cases[@]}"
mutate_cases src/egress.rs "${egress_cases[@]}"
mutate_cases src/proxy/forwarding_adapter.rs "${adapter_context_cases[@]}"
mutate_cases src/proxy/ingress.rs \
    "${ingress_retained_cases[@]}" "${ingress_c03_cases[@]}"

printf 'product forwarding test inventory mutation tests passed (%d mutations)\n' \
    "$mutations"
