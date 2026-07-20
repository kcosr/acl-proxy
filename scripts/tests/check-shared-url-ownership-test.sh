#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
RUNTIME_SOURCE="$SOURCE_ROOT/../access-runtime"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/shared-url-ownership-test.XXXXXX")
cleanup() {
    rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

mkdir -p "$TEST_ROOT/fake-bin"
REAL_CARGO=$(command -v cargo)
export REAL_CARGO
cat >"$TEST_ROOT/fake-bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} != metadata ]]; then
    exec "$REAL_CARGO" "$@"
fi

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
elif mode not in ("valid", "direct-idna", "direct-memchr", "direct-url"):
    raise SystemExit(f"unknown fake metadata mode {mode}")

dependencies = [
    ("http-access-types", None, runtime / "http-access-types", "=0.1.0"),
    ("http-access-url", None, runtime / "http-access-url", "=0.1.0"),
    ("http-access-conformance", "dev", runtime / "http-access-conformance", "=0.1.0"),
    ("http-access-policy-acl", policy_kind, policy_path, policy_version),
]
if mode.startswith("direct-"):
    dependencies.append((mode.removeprefix("direct-"), None, None, "*"))
json.dump(
    {
        "packages": [
            {
                "name": "acl-proxy",
                "dependencies": [
                    {
                        "name": name,
                        "kind": kind,
                        "path": None if path is None else str(path),
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
expect_failure direct-idna 'direct idna dependency' \
    'idna must not be a direct dependency'
expect_failure direct-memchr 'direct memchr dependency' \
    'memchr must not be a direct dependency'
expect_failure direct-url 'direct url dependency' \
    'url must not be a direct dependency'

source_case="$TEST_ROOT/source-case"
mkdir -p "$source_case/scripts"
ln -s "$RUNTIME_SOURCE" "$TEST_ROOT/access-runtime"
cp -R "$SOURCE_ROOT/src" "$source_case/"
cp "$SOURCE_ROOT/scripts/check-shared-url-ownership.sh" "$source_case/scripts/"
PATH="$TEST_ROOT/fake-bin:$PATH" \
    "$source_case/scripts/check-shared-url-ownership.sh" >"$TEST_ROOT/source-pass.log"
grep -Fq 'shared URL and request-facts ownership/dependency gate passed' \
    "$TEST_ROOT/source-pass.log"

expect_source_failure() {
    local description=$1
    local expected=$2
    if PATH="$TEST_ROOT/fake-bin:$PATH" \
        "$source_case/scripts/check-shared-url-ownership.sh" \
        >"$TEST_ROOT/source-failure.log" 2>&1; then
        printf '%s was accepted\n' "$description" >&2
        exit 1
    fi
    if ! grep -Fq -- "$expected" "$TEST_ROOT/source-failure.log"; then
        printf '%s failed for the wrong reason; expected: %s\n' \
            "$description" "$expected" >&2
        cat "$TEST_ROOT/source-failure.log" >&2
        exit 1
    fi
}

reset_source_case() {
    rm -rf -- "$source_case/src"
    cp -R "$SOURCE_ROOT/src" "$source_case/"
}

touch "$source_case/src/proxy/facts.rs"
expect_source_failure 'restored product facts.rs' \
    'deleted product request-fact/header owner was restored: src/proxy/facts.rs'

reset_source_case
touch "$source_case/src/proxy/headers.rs"
expect_source_failure 'restored product headers.rs' \
    'deleted product request-fact/header owner was restored: src/proxy/headers.rs'

reset_source_case
touch "$source_case/src/proxy/raw_h2_conformance.rs"
expect_source_failure 'restored product raw HTTP/2 conformance adapter' \
    'product raw HTTP/2 conformance adapter must remain deleted'

reset_source_case
cat >>"$source_case/src/standalone_policy_provider.rs" <<'EOF'

fn escaped_fact_constructor() { http_access_types::InterceptedRequestFacts::new(); }
EOF
expect_source_failure 'constructor outside private-field rebuild' \
    'InterceptedRequestFacts::new must remain inside rebuild_standalone_facts'

reset_source_case
cat >>"$source_case/src/standalone_policy_provider.rs" <<'EOF'

use http_access_types::InterceptedRequestFacts as FactsAlias;
fn escaped_fact_alias() { FactsAlias::new(); }
EOF
expect_source_failure 'renamed InterceptedRequestFacts constructor' \
    'InterceptedRequestFacts import must not be renamed around the ingress funnel'

reset_source_case
cat >>"$source_case/src/standalone_policy_provider.rs" <<'EOF'

use crate::proxy::private_fields::visible_fields as convert_headers;
fn escaped_visible_alias() { convert_headers(); }
EOF
expect_source_failure 'renamed visible_fields funnel' \
    'visible_fields import must not be renamed around the private-field funnel'

reset_source_case
cat >>"$source_case/src/standalone_policy_provider.rs" <<'EOF'

macro_rules! escaped_fact_macro {
    () => {{
        use http_access_types::InterceptedRequestFacts as FactsAlias;
        FactsAlias::new();
    }};
}
EOF
expect_source_failure 'fact constructor alias inside macro definition' \
    'fact constructors and aliases are forbidden inside production macros'

reset_source_case
cat >>"$source_case/src/standalone_policy_provider.rs" <<'EOF'

macro_rules! escaped_neutral_macro {
    () => { neutral_headers() };
}
EOF
expect_source_failure 'neutralization inside macro definition' \
    'deleted product neutral_headers funnel is forbidden inside production macros'

reset_source_case
cat >>"$source_case/src/standalone_policy_provider.rs" <<'EOF'

macro_rules! escaped_materialization_macro {
    ($shape:expr, $headers:expr) => { $shape.into_facts($headers) };
}
EOF
expect_source_failure 'fact materialization inside macro definition' \
    'deleted product into_facts materializer is forbidden inside production macros'

reset_source_case
cat >>"$source_case/src/standalone_policy_provider.rs" <<'EOF'

fn neutral_headers() {}
EOF
expect_source_failure 'restored neutral_headers function' \
    'deleted product neutral_headers funnel may not be restored'

reset_source_case
cat >>"$source_case/src/standalone_policy_provider.rs" <<'EOF'

fn visible_fields() {}
EOF
expect_source_failure 'visible_fields outside private owner' \
    'visible_fields must remain inside the private-field owner'

reset_source_case
python3 - "$source_case/src/proxy/private_fields.rs" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
source = source.replace("fn rebuild_standalone_facts(", "fn escaped_rebuild_standalone_facts(", 1)
path.write_text(source, encoding="utf-8")
PY
expect_source_failure 'renamed sole facts rebuild' \
    'InterceptedRequestFacts::new must remain inside rebuild_standalone_facts'

reset_source_case
python3 - "$source_case/src/proxy/private_fields.rs" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
source = source.replace("let visible = visible_fields(&private)?;", "let visible = Vec::new();", 1)
path.write_text(source, encoding="utf-8")
PY
expect_source_failure 'removed sole visible-field conversion' \
    'visible_fields must run exactly once after private-field partitioning'

reset_source_case
cat >>"$source_case/src/proxy/private_fields.rs" <<'EOF'

mod tests {
}
fn escaped_after_fake_test_truncation() { InterceptedRequestFacts::new(); }
EOF
expect_source_failure 'fake test module truncation' \
    'InterceptedRequestFacts::new must remain inside rebuild_standalone_facts'

reset_source_case
cat >>"$source_case/src/policy/adapter.rs" <<'EOF'

use http_access_url::canonicalize_http_url as normalize_again;
fn escaped_policy_normalization() { normalize_again(); }
EOF
expect_source_failure 'renamed policy URL normalization' \
    'production policy and decision code must not re-normalize URLs'

printf 'shared URL ownership policy mutation tests passed\n'
