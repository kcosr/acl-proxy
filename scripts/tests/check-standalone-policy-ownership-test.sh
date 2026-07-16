#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/standalone-policy-ownership-test.XXXXXX")
cleanup() {
    rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

BASELINE="$TEST_ROOT/baseline"
mkdir -p "$BASELINE/scripts" "$BASELINE/src/proxy" "$BASELINE/src/http1"
cp "$SOURCE_ROOT/scripts/check-standalone-policy-ownership.sh" "$BASELINE/scripts/"

for source in \
    src/proxy/ingress.rs \
    src/proxy/forward.rs \
    src/proxy/upgrade_relay.rs \
    src/http1/ingress.rs
do
    mkdir -p "$BASELINE/$(dirname -- "$source")"
    printf '%s\n' \
        '#[cfg(test)]' \
        'mod tests {' \
        '    const FORBIDDEN_TEST_TEXT: &str = "crate::policy .policy() AllowedRequest RequestDecision request_decision request_header_effects response_header_effects credential_actions allow_upgrades AuthoringConfig CompiledHttp1ConnectPolicy PolicySnapshot PolicyEvaluation PolicyOutcome PolicyResult";' \
        '}' \
        'fn production_transport() {}' \
        '// crate::policy AllowedRequest request_header_effects response_header_effects' \
        '/* PolicySnapshot PolicyEvaluation PolicyOutcome PolicyResult */' \
        >"$BASELINE/$source"
done

runner() {
    local root=$1
    PIPELINE_OWNERSHIP_CHECK_MANIFEST="$SOURCE_ROOT/../access-runtime/Cargo.toml" \
        "$root/scripts/check-standalone-policy-ownership.sh"
}

runner "$BASELINE" >"$TEST_ROOT/pass.log"
grep -Fq 'standalone policy ownership gate passed' "$TEST_ROOT/pass.log"

expect_failure() {
    local root=$1
    local description=$2
    local expected=$3
    if runner "$root" >"$TEST_ROOT/failure.log" 2>&1; then
        printf '%s was accepted\n' "$description" >&2
        exit 1
    fi
    if ! grep -Fq -- "$expected" "$TEST_ROOT/failure.log"; then
        printf '%s failed for the wrong reason; expected: %s\n' "$description" "$expected" >&2
        cat "$TEST_ROOT/failure.log" >&2
        exit 1
    fi
}

mutations=(
    'use crate::policy::PolicySnapshot;'
    'let _ = state.policy();'
    'let _: PolicySnapshot;'
    'let _: PolicyEvaluation;'
    'let _: PolicyOutcome;'
    'let _: PolicyResult;'
    'let _: AllowedRequest;'
    'use crate::request_decision;'
    'let _: RequestDecision;'
    'let _ = value.request_header_effects();'
    'let _ = value.response_header_effects();'
    'let _ = value.credential_actions();'
    'let _ = value.allow_upgrades;'
    'let _: AuthoringConfig;'
    'let _: CompiledHttp1ConnectPolicy;'
)

case_index=0
for source in \
    src/proxy/ingress.rs \
    src/proxy/forward.rs \
    src/proxy/upgrade_relay.rs \
    src/http1/ingress.rs
do
    for mutation in "${mutations[@]}"; do
        case_index=$((case_index + 1))
        case_root="$TEST_ROOT/case-$case_index"
        cp -R "$BASELINE" "$case_root"
        python3 - "$case_root/$source" "$mutation" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
mutation = sys.argv[2]
source = path.read_text(encoding="utf-8")
replacement = f"fn production_transport() {{ {mutation} }}"
path.write_text(
    source.replace("fn production_transport() {}", replacement, 1),
    encoding="utf-8",
)
PY
        expect_failure "$case_root" "$source mutation: $mutation" \
            'standalone listener/forwarding ownership violations:'
    done
done

case_index=$((case_index + 1))
case_root="$TEST_ROOT/extra-decision"
cp -R "$BASELINE" "$case_root"
printf '%s\n' 'fn bypass(other: Context, facts: Facts, request: Request) { other.decide(&facts, request); }' \
    >>"$case_root/src/proxy/ingress.rs"
expect_failure "$case_root" 'second DecisionProvider caller' \
    'DecisionProvider::decide must have no product production caller'

case_index=$((case_index + 1))
case_root="$TEST_ROOT/renamed-decision"
cp -R "$BASELINE" "$case_root"
printf '%s\n' 'fn bypass(other: Context, request_facts: Facts, request: Request) { other.decide(&request_facts, request); }' \
    >>"$case_root/src/proxy/ingress.rs"
expect_failure "$case_root" 'renamed-facts DecisionProvider caller' \
    'DecisionProvider::decide must have no product production caller'

case_index=$((case_index + 1))
case_root="$TEST_ROOT/ufcs-decision"
cp -R "$BASELINE" "$case_root"
printf '%s\n' 'fn bypass(other: Context, request_facts: Facts, request: Request) { DecisionProvider::decide(&other, &request_facts, request); }' \
    >>"$case_root/src/proxy/ingress.rs"
expect_failure "$case_root" 'UFCS DecisionProvider caller' \
    'DecisionProvider::decide must have no product production caller'

case_index=$((case_index + 1))
case_root="$TEST_ROOT/macro-decision"
cp -R "$BASELINE" "$case_root"
printf '%s\n' 'macro_rules! bypass { () => { other.decide(&request_facts, request); } }' \
    >>"$case_root/src/proxy/ingress.rs"
expect_failure "$case_root" 'macro DecisionProvider caller' \
    'DecisionProvider::decide must have no product production caller'

case_index=$((case_index + 1))
case_root="$TEST_ROOT/obsolete-pipeline"
cp -R "$BASELINE" "$case_root"
printf '%s\n' 'fn obsolete() {}' >"$case_root/src/request_pipeline.rs"
expect_failure "$case_root" 'obsolete product pipeline owner' \
    'obsolete product request_pipeline.rs must be deleted'

printf 'standalone policy ownership mutation tests passed (%d mutations)\n' \
    "$case_index"
