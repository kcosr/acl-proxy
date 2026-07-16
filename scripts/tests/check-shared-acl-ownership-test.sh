#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/shared-acl-ownership-test.XXXXXX")
cleanup() {
    rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

BASELINE="$TEST_ROOT/baseline"
mkdir -p "$BASELINE/scripts" "$BASELINE/src/policy" "$TEST_ROOT/fake-bin"
cp "$SOURCE_ROOT/scripts/check-shared-acl-ownership.sh" "$BASELINE/scripts/"
cat >"$BASELINE/src/policy/adapter.rs" <<'EOF'
use http_access_policy_acl::TrafficPolicySnapshot;

#[derive(Clone, Copy)]
struct ProductRuleEffectsRef(u32);

fn evaluate(snapshot: &TrafficPolicySnapshot<ProductRuleEffectsRef>) {
    let _ = snapshot;
}
EOF
cat >"$BASELINE/src/standalone_policy_provider.rs" <<'EOF'
fn dispatch(snapshot: Snapshot) {
    let _ = snapshot.resolve_delegate(delegated, disposition, input);
}
EOF

cat >"$TEST_ROOT/fake-bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

python3 - "$PWD" "${FAKE_METADATA_MODE:-valid}" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
mode = sys.argv[2]
kind = None
path = root.parent / "access-runtime" / "crates" / "http-access-policy-acl"
version = "=0.1.0"
if mode == "dev-dependency":
    kind = "dev"
elif mode == "wrong-path":
    path = root.parent / "access-runtime" / "crates" / "http-access-conformance"
elif mode == "loose-version":
    version = "0.1.0"
elif mode != "valid":
    raise SystemExit(f"unknown fake metadata mode {mode}")

json.dump(
    {
        "packages": [
            {
                "name": "acl-proxy",
                "dependencies": [
                    {
                        "name": "http-access-policy-acl",
                        "kind": kind,
                        "path": str(path),
                        "req": version,
                    }
                ],
            }
        ]
    },
    sys.stdout,
)
PY
EOF
chmod +x "$TEST_ROOT/fake-bin/cargo"

runner() {
    local root=$1
    PATH="$TEST_ROOT/fake-bin:$PATH" "$root/scripts/check-shared-acl-ownership.sh"
}

runner "$BASELINE" >"$TEST_ROOT/pass.log"
grep -Fq 'shared ACL evaluator ownership/deletion gate passed' "$TEST_ROOT/pass.log"

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

expect_success() {
    local root=$1
    local description=$2
    if ! runner "$root" >"$TEST_ROOT/pass.log" 2>&1; then
        printf '%s was rejected\n' "$description" >&2
        cat "$TEST_ROOT/pass.log" >&2
        exit 1
    fi
    grep -Fq 'shared ACL evaluator ownership/deletion gate passed' "$TEST_ROOT/pass.log"
}

source_case_count=0
for mutation in \
    'struct CompiledPolicySnapshot;' \
    'struct PolicyActivation;' \
    'enum PolicyActivationError { Invalid }' \
    'struct ActivatedPolicyRule;' \
    'struct PolicyCursor;' \
    'enum PolicyOutcome { Allow }' \
    'struct PolicyEvaluation;' \
    'struct PreparedPolicyEvaluation;' \
    'struct PolicyRuleMatch;' \
    'fn rule_matches() {}' \
    'trait PolicySnapshot {}' \
    'struct ResolvedBindings;' \
    'struct ResolvedRuleBindings;' \
    'fn evaluate_at() {}' \
    'fn header_predicates_match() {}' \
    'fn resolved_bindings() {}' \
    'fn compile_neutral_policy() {}' \
    'fn default_provenance() {}' \
    'fn local_provenance() {}' \
    'fn provider_provenance() {}' \
    'type CompiledPolicySnapshot = ProductAclSnapshot;' \
    'type PolicyEvaluation = SharedPolicyEvaluation<ProductRuleEffectsRef>;'
do
    source_case_count=$((source_case_count + 1))
    case_root="$TEST_ROOT/legacy-$source_case_count"
    cp -R "$BASELINE" "$case_root"
    printf '\n%s\n' "$mutation" >>"$case_root/src/policy/adapter.rs"
    expect_failure "$case_root" "legacy ACL mutation: $mutation" \
        'legacy product ACL evaluator ownership violations:'
done

source_case_count=$((source_case_count + 1))
case_root="$TEST_ROOT/test-only-legacy"
cp -R "$BASELINE" "$case_root"
cat >>"$case_root/src/policy/adapter.rs" <<'EOF'

# [cfg(all(target_os = "linux", test))]
mod legacy_test_helpers {
    struct CompiledPolicySnapshot;
    struct PolicyActivation;
    enum PolicyActivationError { Invalid }
    struct ActivatedPolicyRule;
    struct PolicyCursor;
    enum PolicyOutcome { Allow }
    struct PolicyEvaluation;
    struct PreparedPolicyEvaluation;
    struct PolicyRuleMatch;
    trait PolicySnapshot {}
    struct ResolvedBindings;
    struct ResolvedRuleBindings;
    fn evaluate_at() {}
    fn rule_matches() {}
    fn header_predicates_match() {}
    fn resolved_bindings() {}
    fn compile_neutral_policy() {}
    fn default_provenance() {}
    fn local_provenance() {}
    fn provider_provenance() {}
}
EOF
expect_success "$case_root" 'test-only legacy ACL helpers'

source_case_count=$((source_case_count + 1))
case_root="$TEST_ROOT/non-code-legacy"
cp -R "$BASELINE" "$case_root"
cat >>"$case_root/src/policy/adapter.rs" <<'EOF'

// struct CompiledPolicySnapshot; fn evaluate_at() {}
const LEGACY_NAMES: &str = r#"trait PolicySnapshot {}; fn rule_matches() {}"#;
EOF
expect_success "$case_root" 'legacy ACL names in comments and literals'

source_case_count=$((source_case_count + 1))
case_root="$TEST_ROOT/test-only-dispatch"
cp -R "$BASELINE" "$case_root"
cat >"$case_root/src/standalone_policy_provider.rs" <<'EOF'
#[cfg(all(test, unix))]
mod tests {
    fn dispatch(snapshot: Snapshot) {
        let _ = snapshot.resolve_delegate(delegated, disposition, input);
    }
}
EOF
expect_failure "$case_root" 'test-only shared ACL delegate resolution' \
    'product provider dispatch must consume shared ACL resolve_delegate'

source_case_count=$((source_case_count + 1))
case_root="$TEST_ROOT/production-after-test-helper"
cp -R "$BASELINE" "$case_root"
cat >"$case_root/src/standalone_policy_provider.rs" <<'EOF'
#[cfg(test)]
fn test_helper(snapshot: Snapshot) {
    let _ = snapshot.resolve_test_delegate(delegated, disposition, input);
}

fn dispatch(snapshot: Snapshot) {
    let _ = snapshot.resolve_delegate(delegated, disposition, input);
}
EOF
expect_success "$case_root" 'production delegate resolution after a test helper'

source_case_count=$((source_case_count + 1))
case_root="$TEST_ROOT/comparator"
cp -R "$BASELINE" "$case_root"
touch "$case_root/src/p05_contract_adapter_tests.rs"
expect_failure "$case_root" 'retained P05 comparator' \
    'src/p05_contract_adapter_tests.rs must be deleted'

source_case_count=$((source_case_count + 1))
case_root="$TEST_ROOT/product-snapshot"
cp -R "$BASELINE" "$case_root"
touch "$case_root/src/policy/snapshot.rs"
expect_failure "$case_root" 'restored product policy snapshot' \
    'src/policy/snapshot.rs must remain deleted'

for pair in \
    'TrafficPolicySnapshot TrafficSnapshot' \
    'ProductRuleEffectsRef ProductEffects' \
    'resolve_delegate resolve_product'
do
    source_case_count=$((source_case_count + 1))
    case_root="$TEST_ROOT/missing-$source_case_count"
    cp -R "$BASELINE" "$case_root"
    read -r old new <<<"$pair"
    if [[ $old == resolve_delegate ]]; then
        sed -i "s/$old/$new/g" "$case_root/src/standalone_policy_provider.rs"
        expected='product provider dispatch must consume shared ACL resolve_delegate'
    else
        sed -i "s/$old/$new/g" "$case_root/src/policy/adapter.rs"
        expected="product policy adapter must use shared ACL $old"
    fi
    expect_failure "$case_root" "missing shared ACL ownership token: $old" "$expected"
done

source_case_count=$((source_case_count + 1))
case_root="$TEST_ROOT/test-only-traffic-snapshot"
cp -R "$BASELINE" "$case_root"
sed -i 's/TrafficPolicySnapshot/ProductTrafficSnapshot/g' \
    "$case_root/src/policy/adapter.rs"
cat >>"$case_root/src/policy/adapter.rs" <<'EOF'

#[cfg(test)]
type TrafficPolicySnapshot = ProductTrafficSnapshot;
EOF
expect_failure "$case_root" 'test-only TrafficPolicySnapshot ownership token' \
    'product policy adapter must use shared ACL TrafficPolicySnapshot'

source_case_count=$((source_case_count + 1))
case_root="$TEST_ROOT/test-only-product-effects"
cp -R "$BASELINE" "$case_root"
sed -i 's/ProductRuleEffectsRef/ProductEffects/g' "$case_root/src/policy/adapter.rs"
cat >>"$case_root/src/policy/adapter.rs" <<'EOF'

#[cfg(all(test, unix))]
struct ProductRuleEffectsRef;
EOF
expect_failure "$case_root" 'test-only ProductRuleEffectsRef ownership token' \
    'product policy adapter must use shared ACL ProductRuleEffectsRef'

metadata_case_count=0
for spec in \
    'dev-dependency|production dependency' \
    'wrong-path|exact sibling path' \
    'loose-version|exact version =0.1.0'
do
    metadata_case_count=$((metadata_case_count + 1))
    mode=${spec%%|*}
    expected=${spec#*|}
    if FAKE_METADATA_MODE="$mode" runner "$BASELINE" >"$TEST_ROOT/failure.log" 2>&1; then
        printf '%s metadata mutation was accepted\n' "$mode" >&2
        exit 1
    fi
    grep -Fq "$expected" "$TEST_ROOT/failure.log"
done

printf 'shared ACL ownership mutation tests passed (%d source mutations, %d metadata mutations)\n' \
    "$source_case_count" "$metadata_case_count"
