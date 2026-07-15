#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/forwarding-executor-ownership-test.XXXXXX")
cleanup() {
    rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

BASELINE="$TEST_ROOT/baseline"
mkdir -p "$BASELINE/scripts" "$BASELINE/src/proxy"
cp "$SOURCE_ROOT/scripts/check-forwarding-executor-ownership.sh" "$BASELINE/scripts/"

cat >"$BASELINE/src/proxy/forward.rs" <<'EOF'
async fn forward_request(request: Request) {}
async fn forward_upgrade_request(request: Request) {}

#[cfg(test)]
mod tests {
    fn test_only() {
        forward_request(request);
        forward_upgrade_request(request);
    }
}
EOF

cat >"$BASELINE/src/proxy/forwarding_executor.rs" <<'EOF'
use crate::proxy::forward::{forward_request, forward_upgrade_request};

struct ForwardingExecutor;

impl ForwardingExecutor {
    fn execute_ordinary(request: Request) {
        forward_request(request);
    }

    #[cfg(test)]
    fn test_only_method() {
        let _: AppState;
        let _: ProductConfig;
        crate::policy::evaluate_policy();
        StandalonePolicyProvider::prepare();
        forward_request(request);
        forward_upgrade_request(request);
    }

    fn execute_upgrade(request: Request) {
        forward_upgrade_request(request);
    }
}

// AppState ProductConfig AuthoringConfig PolicySnapshot StandalonePolicyProvider
/* crate::policy nested /* DecisionProvider */ forward_request(request); */
const TEXT: &str = "AppState Config crate::policy forward_upgrade_request(request)";
const RAW: &str = r#"ForwardingExecutor::execute(dispatch); forward_request(request)"#;
const CHARACTER: char = 'x';
const BYTE: u8 = b'{';
EOF

cat >"$BASELINE/src/proxy/ingress.rs" <<'EOF'
fn terminal_forward(dispatch: Dispatch) {
    ForwardingExecutor::execute(dispatch);
}

#[cfg(test)]
mod tests {
    fn test_only() {
        ForwardingExecutor::execute(dispatch);
        forward_request(request);
        forward_upgrade_request(request);
    }
}

fn production_after_test_module() {}
EOF

cat >"$BASELINE/src/test_only.rs" <<'EOF'
#![cfg(test)]
fn test_only() {
    ForwardingExecutor::execute(dispatch);
    forward_request(request);
    forward_upgrade_request(request);
}
EOF

runner() {
    local root=$1
    "$root/scripts/check-forwarding-executor-ownership.sh"
}

runner "$BASELINE" >"$TEST_ROOT/pass.log"
grep -Fq 'forwarding executor ownership gate passed' "$TEST_ROOT/pass.log"

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

forbidden_mutations=(
    'let _: AppState;'
    'let _: GenerationLease;'
    'let _: Runtime;'
    'let _: CredentialResolver;'
    'let _: EgressSnapshot;'
    'let _: SafetySnapshot;'
    'let _: ProductConfig;'
    'let _: Config;'
    'let _ = config.timeout;'
    'let _ = self.config;'
    'let _: AuthoringForwardingRule;'
    'use crate::policy;'
    'let _ = state.policy();'
    'let _: PolicySnapshot;'
    'let _: PolicyEvaluation;'
    'let _: PolicyOutcome;'
    'let _: PolicyResult;'
    'let _: CompiledForwardingPolicy;'
    'let _: AllowedRequest;'
    'evaluate_policy();'
    'let _: StandalonePolicyProvider;'
    'let _: DecisionProvider;'
    'let _: ProviderDispatcher;'
    'provider.decide();'
    'dispatch_provider();'
    'invoke_provider();'
    'call_provider();'
)

case_index=0
for mutation in "${forbidden_mutations[@]}"; do
    case_index=$((case_index + 1))
    case_root="$TEST_ROOT/case-$case_index"
    cp -R "$BASELINE" "$case_root"
    python3 - "$case_root/src/proxy/forwarding_executor.rs" "$mutation" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
mutation = sys.argv[2]
source = path.read_text(encoding="utf-8")
path.write_text(source.replace("struct ForwardingExecutor;", mutation, 1), encoding="utf-8")
PY
    expect_failure "$case_root" "executor dependency mutation: $mutation" \
        'forwarding executor dependency violations:'
done

case_root="$TEST_ROOT/extra-entry"
cp -R "$BASELINE" "$case_root"
printf '%s\n' 'fn bypass(dispatch: Dispatch) { ForwardingExecutor::execute(dispatch); }' \
    >"$case_root/src/bypass.rs"
expect_failure "$case_root" 'second executor entry' \
    'must have exactly one production terminal caller in ingress.rs'

case_root="$TEST_ROOT/missing-entry"
cp -R "$BASELINE" "$case_root"
sed -i 's/ForwardingExecutor::execute(dispatch);/terminal_response(dispatch);/' \
    "$case_root/src/proxy/ingress.rs"
expect_failure "$case_root" 'missing executor entry' \
    'must have exactly one production terminal caller in ingress.rs'

for primitive in forward_request forward_upgrade_request; do
    case_index=$((case_index + 1))
    case_root="$TEST_ROOT/case-$case_index"
    cp -R "$BASELINE" "$case_root"
    sed -i "1i use crate::proxy::forward::$primitive as escaped_transport;" \
        "$case_root/src/proxy/ingress.rs"
    expect_failure "$case_root" "$primitive alias outside executor" \
        "$primitive references must be confined to the forwarding executor transport seam"

    case_index=$((case_index + 1))
    case_root="$TEST_ROOT/case-$case_index"
    cp -R "$BASELINE" "$case_root"
    sed -i "/        $primitive(request);/a\        $primitive(request);" \
        "$case_root/src/proxy/forwarding_executor.rs"
    expect_failure "$case_root" "second executor $primitive call" \
        "must contain exactly one production $primitive transport call"

    case_index=$((case_index + 1))
    case_root="$TEST_ROOT/case-$case_index"
    cp -R "$BASELINE" "$case_root"
    sed -i "/        $primitive(request);/d" \
        "$case_root/src/proxy/forwarding_executor.rs"
    expect_failure "$case_root" "missing executor $primitive call" \
        "must contain exactly one production $primitive transport call"
done

printf 'forwarding executor ownership mutation tests passed (%d mutations)\n' \
    "$case_index"
