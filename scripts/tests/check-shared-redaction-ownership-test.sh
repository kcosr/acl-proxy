#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/shared-redaction-ownership-test.XXXXXX")
cleanup() {
    rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

BASE_PARENT="$TEST_ROOT/baseline"
BASELINE="$BASE_PARENT/acl-proxy"
SHARED="$BASE_PARENT/access-runtime/crates/http-access-redaction/src"
mkdir -p "$BASELINE/scripts" "$BASELINE/src" "$SHARED" "$TEST_ROOT/fake-bin"
cp "$SOURCE_ROOT/scripts/check-shared-redaction-ownership.sh" "$BASELINE/scripts/"

cat >"$BASELINE/src/redaction_adapter.rs" <<'EOF'
use http_access_redaction::{PreparedProfile, ProfileHandle};

fn bind(prepared: PreparedProfile) -> ProfileHandle {
    prepared.bind()
}
EOF

cat >"$SHARED/lib.rs" <<'EOF'
pub struct PreparedProfile;
pub struct ProfileHandle;
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
dependencies = []

if mode != "missing-redaction":
    dependency = {
        "name": "http-access-redaction",
        "kind": None,
        "path": str(root.parent / "access-runtime" / "crates" / "http-access-redaction"),
        "req": "=0.1.0",
        "rename": None,
    }
    if mode == "dev-dependency":
        dependency["kind"] = "dev"
    elif mode == "wrong-path":
        dependency["path"] = str(root.parent / "access-runtime" / "crates" / "http-access-types")
    elif mode == "loose-version":
        dependency["req"] = "0.1.0"
    elif mode == "renamed":
        dependency["rename"] = "shared-redaction"
    dependencies.append(dependency)

if mode in {"direct-regex", "dev-regex"}:
    dependencies.append(
        {
            "name": "regex-automata",
            "kind": "dev" if mode == "dev-regex" else None,
            "path": None,
            "req": "^0.4.13",
            "rename": None,
        }
    )
elif mode not in {
    "valid",
    "missing-redaction",
    "dev-dependency",
    "wrong-path",
    "loose-version",
    "renamed",
}:
    raise SystemExit(f"unknown fake metadata mode {mode}")

json.dump(
    {"packages": [{"name": "acl-proxy", "dependencies": dependencies}]},
    sys.stdout,
)
PY
EOF
chmod +x "$TEST_ROOT/fake-bin/cargo"

runner() {
    local root=$1
    PATH="$TEST_ROOT/fake-bin:$PATH" "$root/scripts/check-shared-redaction-ownership.sh"
}

runner "$BASELINE" >"$TEST_ROOT/pass.log"
grep -Fq 'shared redaction ownership/deletion gate passed' "$TEST_ROOT/pass.log"

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
    grep -Fq 'shared redaction ownership/deletion gate passed' "$TEST_ROOT/pass.log"
}

source_mutations=(
    'struct RedactionSnapshot;'
    'struct ProfileHandle;'
    'enum PayloadClass { Text }'
    'struct RedactionLimits;'
    'enum SnapshotError { Invalid }'
    'type RedactionActivation = ();'
    'enum RedactionPlan { Empty }'
    'struct RedactionProfilePlan;'
    'struct RedactionRulePlan;'
    'enum CompiledRedactionPayloads { Text }'
    'struct LiteralMatcher;'
    'struct ZeroizingAhoCorasick;'
    'struct PendingIntervals;'
    'struct RedactionLiteralProjection;'
    'struct RedactionProfileIndex(usize);'
    'struct RedactionProfileRegistry;'
    'type ProductRedactionMatcher = ();'
    'type ProductRedactionCompiler = ();'
    'type ProductRedactionProjection = ();'
    'type HiddenSnapshot = RedactionSnapshot;'
    'use legacy::Snapshot as RedactionSnapshot;'
    'use legacy::RedactionSnapshot as HiddenSnapshot;'
    'pub use legacy::RedactionSnapshot;'
    'pub use legacy::LiteralMatcher as SharedMatcher;'
    'use regex_automata::dfa::regex::Regex as DfaRegex;'
    'fn build_redaction_regex() {}'
    'fn redaction_literal_projection() {}'
    'fn redaction_literal_scratch_bytes() {}'
    'fn checked_redaction_matcher_resident_bytes() {}'
    'fn replace_regex_bounded() {}'
    'fn replacement_shape() {}'
    'fn wipe_vec_capacity() {}'
)

source_case_count=0
for mutation in "${source_mutations[@]}"; do
    source_case_count=$((source_case_count + 1))
    case_parent="$TEST_ROOT/product-$source_case_count"
    cp -R "$BASE_PARENT" "$case_parent"
    printf '\n%s\n' "$mutation" >>"$case_parent/acl-proxy/src/redaction_adapter.rs"
    expect_failure "$case_parent/acl-proxy" "legacy product mutation: $mutation" \
        'legacy product redaction ownership violations:'
done

case_parent="$TEST_ROOT/old-file"
cp -R "$BASE_PARENT" "$case_parent"
mkdir -p "$case_parent/acl-proxy/src/redaction"
touch "$case_parent/acl-proxy/src/redaction/snapshot.rs"
expect_failure "$case_parent/acl-proxy" 'old snapshot file' \
    'src/redaction/snapshot.rs must be deleted'

case_parent="$TEST_ROOT/test-only-product"
cp -R "$BASE_PARENT" "$case_parent"
cat >>"$case_parent/acl-proxy/src/redaction_adapter.rs" <<'EOF'

#[cfg(all(target_os = "linux", test))]
mod legacy_test_helpers {
    struct RedactionSnapshot;
    struct LiteralMatcher;
    struct RedactionProfileRegistry;
    fn build_redaction_regex() {}
    use regex_automata::Regex as DfaRegex;
}
EOF
expect_success "$case_parent/acl-proxy" 'test-only product helpers'

case_parent="$TEST_ROOT/crate-test-only-product"
cp -R "$BASE_PARENT" "$case_parent"
cat >"$case_parent/acl-proxy/src/test_only.rs" <<'EOF'
#![cfg(test)]
struct RedactionSnapshot;
type ProductRedactionMatcher = ();
EOF
expect_success "$case_parent/acl-proxy" 'crate-level test-only product helpers'

shared_mutations=(
    'fn read_source() { let _ = std::env::var_os("NAME"); }'
    'fn request(value: http::Request<()>) { let _ = value; }'
    'fn response(value: hyper::Response<()>) { let _ = value; }'
    'struct RedactionConfig;'
    'struct ReloadableProductPlan;'
    'struct CaptureBody;'
    'struct CaptureOperation;'
    'struct GuardedBody;'
    'struct HttpWireBodyGuard;'
    'struct WireBodyPool;'
    'struct CaptureContentEncoding;'
    'struct WebSocketNegotiation;'
    'struct WebSocketDirection;'
    'struct PathBuf;'
    'fn open(path: &std::path::Path) { let _ = path; }'
    'fn decode_capture_body() {}'
    'fn inflate() { let _ = flate2::Compression::default(); }'
)

shared_case_count=0
for mutation in "${shared_mutations[@]}"; do
    shared_case_count=$((shared_case_count + 1))
    case_parent="$TEST_ROOT/shared-$shared_case_count"
    cp -R "$BASE_PARENT" "$case_parent"
    printf '\n%s\n' "$mutation" >>"$case_parent/access-runtime/crates/http-access-redaction/src/lib.rs"
    expect_failure "$case_parent/acl-proxy" "shared boundary mutation: $mutation" \
        'shared redaction boundary violations:'
done

case_parent="$TEST_ROOT/test-only-shared"
cp -R "$BASE_PARENT" "$case_parent"
cat >>"$case_parent/access-runtime/crates/http-access-redaction/src/lib.rs" <<'EOF'

#[cfg(test)]
mod product_fixture_helpers {
    struct CaptureBody;
    struct HttpWireBodyGuard;
    fn source() { let _ = std::env::var_os("TEST_SOURCE"); }
}
EOF
expect_success "$case_parent/acl-proxy" 'test-only shared fixture helpers'

metadata_case_count=0
for mode in missing-redaction dev-dependency wrong-path loose-version renamed direct-regex dev-regex; do
    metadata_case_count=$((metadata_case_count + 1))
    expected='http-access-redaction'
    if [[ "$mode" == direct-regex || "$mode" == dev-regex ]]; then
        expected='must not depend directly on regex-automata'
    fi
    if FAKE_METADATA_MODE="$mode" runner "$BASELINE" >"$TEST_ROOT/failure.log" 2>&1; then
        printf 'metadata mutation %s was accepted\n' "$mode" >&2
        exit 1
    fi
    if ! grep -Fq -- "$expected" "$TEST_ROOT/failure.log"; then
        printf 'metadata mutation %s failed for the wrong reason; expected: %s\n' "$mode" "$expected" >&2
        cat "$TEST_ROOT/failure.log" >&2
        exit 1
    fi
done

printf 'shared redaction ownership mutation tests passed (%d product, %d shared, %d metadata mutations)\n' \
    "$source_case_count" "$shared_case_count" "$metadata_case_count"
