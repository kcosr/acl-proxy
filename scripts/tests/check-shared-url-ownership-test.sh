#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/shared-url-ownership-test.XXXXXX")
cleanup() {
    rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

mkdir -p "$TEST_ROOT/fake-bin"
cat >"$TEST_ROOT/fake-bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

python3 - "$PWD" "${FAKE_METADATA_MODE:-valid}" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
mode = sys.argv[2]
runtime = root.parent / "access-runtime" / "crates"
policy_kind = None
policy_path = runtime / "http-access-policy-acl"
policy_version = "=0.1.0"
if mode == "dev-policy":
    policy_kind = "dev"
elif mode == "wrong-policy-path":
    policy_path = runtime / "http-access-conformance"
elif mode == "wrong-policy-version":
    policy_version = "0.1.0"
elif mode != "valid":
    raise SystemExit(f"unknown fake metadata mode {mode}")

dependencies = [
    ("http-access-types", None, runtime / "http-access-types", "=0.1.0"),
    ("http-access-url", None, runtime / "http-access-url", "=0.1.0"),
    ("http-access-conformance", "dev", runtime / "http-access-conformance", "=0.1.0"),
    ("http-access-policy-acl", policy_kind, policy_path, policy_version),
]
json.dump(
    {
        "packages": [
            {
                "name": "acl-proxy",
                "dependencies": [
                    {
                        "name": name,
                        "kind": kind,
                        "path": str(path),
                        "req": version,
                    }
                    for name, kind, path, version in dependencies
                ],
            }
        ]
    },
    sys.stdout,
)
PY
EOF
chmod +x "$TEST_ROOT/fake-bin/cargo"

runner="$SOURCE_ROOT/scripts/check-shared-url-ownership.sh"
PATH="$TEST_ROOT/fake-bin:$PATH" "$runner" >"$TEST_ROOT/pass.log"
grep -Fq 'shared URL and request-facts ownership/dependency gate passed' \
    "$TEST_ROOT/pass.log"

expect_failure() {
    local mode=$1
    local description=$2
    local expected=$3
    if FAKE_METADATA_MODE="$mode" PATH="$TEST_ROOT/fake-bin:$PATH" \
        "$runner" >"$TEST_ROOT/failure.log" 2>&1; then
        printf '%s was accepted\n' "$description" >&2
        exit 1
    fi
    if ! grep -Fq -- "$expected" "$TEST_ROOT/failure.log"; then
        printf '%s failed for the wrong reason; expected: %s\n' \
            "$description" "$expected" >&2
        cat "$TEST_ROOT/failure.log" >&2
        exit 1
    fi
}

expect_failure dev-policy 'development-only policy dependency' \
    "http-access-policy-acl has kind 'dev', expected None"
expect_failure wrong-policy-path 'wrong policy dependency path' \
    'http-access-policy-acl must use the exact sibling path'
expect_failure wrong-policy-version 'loose policy dependency version' \
    'http-access-policy-acl must use exact version =0.1.0'

printf 'shared URL ownership policy mutation tests passed\n'
