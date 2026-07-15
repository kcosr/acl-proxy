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
        'fn production_transport() {}' \
        '// crate::policy AllowedRequest request_header_effects response_header_effects' \
        '/* PolicySnapshot PolicyEvaluation PolicyOutcome PolicyResult */' \
        '#[cfg(test)]' \
        'mod tests {' \
        '    const FORBIDDEN_TEST_TEXT: &str = "crate::policy .policy() AllowedRequest RequestDecision request_decision request_header_effects response_header_effects credential_actions allow_upgrades AuthoringConfig CompiledHttp1ConnectPolicy PolicySnapshot PolicyEvaluation PolicyOutcome PolicyResult";' \
        '}' >"$BASELINE/$source"
done

cat >"$BASELINE/src/request_pipeline.rs" <<'EOF'
fn execute(context: Context, facts: Facts, request: Request) {
    match context.decide(&facts, request) {
        Respond(response) => context.respond(response),
        Forward(exchange) => context.forward(exchange),
    }
}

#[cfg(test)]
mod tests {
    fn test_only(second: Context, facts: Facts, request: Request) {
        second.decide(&facts, request);
        second.respond(response);
        second.forward(exchange);
    }
}
EOF

runner() {
    local root=$1
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
path.write_text(source.replace("fn production_transport() {}", mutation, 1), encoding="utf-8")
PY
        expect_failure "$case_root" "$source mutation: $mutation" \
            'standalone listener/forwarding ownership violations:'
    done
done

case_root="$TEST_ROOT/extra-decision"
cp -R "$BASELINE" "$case_root"
sed -i '1i fn bypass(other: Context, facts: Facts, request: Request) { other.decide(&facts, request); }' \
    "$case_root/src/proxy/ingress.rs"
expect_failure "$case_root" 'second DecisionProvider caller' \
    'DecisionProvider::decide must have exactly one production caller'

case_root="$TEST_ROOT/extra-respond"
cp -R "$BASELINE" "$case_root"
sed -i '/context.respond(response)/a\        Other(response) => context.respond(response),' \
    "$case_root/src/request_pipeline.rs"
expect_failure "$case_root" 'second terminal response dispatcher' \
    'must own exactly one terminal respond and one terminal forward dispatch'

case_root="$TEST_ROOT/missing-forward"
cp -R "$BASELINE" "$case_root"
sed -i '/context.forward(exchange)/d' "$case_root/src/request_pipeline.rs"
expect_failure "$case_root" 'missing terminal forward dispatcher' \
    'must own exactly one terminal respond and one terminal forward dispatch'

printf 'standalone policy ownership mutation tests passed (%d path/pattern mutations)\n' \
    "$case_index"
