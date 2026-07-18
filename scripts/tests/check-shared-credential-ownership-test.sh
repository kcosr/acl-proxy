#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/shared-credential-ownership-test.XXXXXX")
cleanup() {
    rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

BASELINE="$TEST_ROOT/baseline"
mkdir -p "$BASELINE/scripts" "$BASELINE/src/activation" "$TEST_ROOT/fake-bin"
cp "$SOURCE_ROOT/scripts/check-shared-credential-ownership.sh" "$BASELINE/scripts/"
cat >"$BASELINE/src/credential_resolver.rs" <<'EOF'
use credential_core::{CredentialProgram, CredentialResolver};

struct ProductCredentialResolver;

impl CredentialResolver for ProductCredentialResolver {}

fn prepare() {
    let _ = CredentialProgram::prepare();
}

enum OutboundCredentialLocator {
    Environment,
    File,
}

struct ProviderCredentialWireStore;

fn sensitive_header_value() {}
EOF

cat >"$BASELINE/src/activation/runner.rs" <<'EOF'
#[cfg(test)]
mod tests {
    mod connect_mitm_tests {
        include!("runner_connect_mitm_tests.rs");
    }
}
EOF

cat >"$BASELINE/src/activation/runner_connect_mitm_tests.rs" <<'EOF'
fn test_only_environment_setup() {
    std::env::set_var("TOKEN", "secret");
    std::env::remove_var("TOKEN");
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
path = root.parent / "access-runtime" / "crates" / "credential-core"
version = "=0.1.0"
if mode == "dev-dependency":
    kind = "dev"
elif mode == "wrong-path":
    path = root.parent / "access-runtime" / "crates" / "http-access-types"
elif mode == "loose-version":
    version = "0.1.0"
elif mode == "missing":
    dependency = []
elif mode != "valid":
    raise SystemExit(f"unknown fake metadata mode {mode}")

if mode != "missing":
    dependency = [
        {
            "name": "credential-core",
            "kind": kind,
            "path": str(path),
            "req": version,
        }
    ]

json.dump(
    {
        "packages": [
            {
                "name": "acl-proxy",
                "dependencies": dependency,
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
    PATH="$TEST_ROOT/fake-bin:$PATH" "$root/scripts/check-shared-credential-ownership.sh"
}

runner "$BASELINE" >"$TEST_ROOT/pass.log"
grep -Fq 'shared credential ownership/deletion gate passed' "$TEST_ROOT/pass.log"

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
    grep -Fq 'shared credential ownership/deletion gate passed' "$TEST_ROOT/pass.log"
}

source_case_count=0
for mutation in \
    'struct CredentialSourceIndex(usize);' \
    'struct CredentialSourceRegistry;' \
    'enum ResolvedCredentialAction { Bearer }' \
    'struct CredentialResolverSnapshot;' \
    'trait CredentialResolver {}' \
    'struct StandaloneCredentialBindingManifest;' \
    'struct StandaloneCredentialSourceBinding;' \
    'struct StandaloneCredentialProgram;' \
    'trait StandaloneCredentialInjector {}' \
    'struct StagedProviderCredentialMutation;' \
    'enum ProviderCredentialInjectionError { Invalid }' \
    'struct CredentialMaterial(Vec<u8>);' \
    'struct ResolvedCredential(Vec<u8>);' \
    'struct RenderedCredentialSet;' \
    'struct ProviderCredentialMaterialStore;' \
    'struct SecretBytes(Vec<u8>);' \
    'struct ResolvedHeader;' \
    'fn resolve_credential_action() {}' \
    'fn resolved_credential_actions() {}' \
    'fn render_credential() {}' \
    'fn render_basic_credentials() {}' \
    'fn take_credential_program() {}' \
    'fn take_credential_preparation() {}' \
    'fn stage_credentials() {}' \
    'fn stage_credential_material() {}' \
    'const credential_program_taken: bool = false;' \
    'const rule_credential_sources: usize = 0;' \
    'const global_credential_sources: usize = 0;' \
    'const provider_credential_mutations: usize = 0;' \
    'enum Error { CredentialProgramConsumed }' \
    'fn mutate_environment() { std::env::set_var("TOKEN", "secret"); }' \
    'fn mutate_environment() { std::env::remove_var("TOKEN"); }' \
    'fn mutate_environment() { env::set_var("TOKEN", "secret"); }' \
    'fn mutate_environment() { env::remove_var("TOKEN"); }'
do
    source_case_count=$((source_case_count + 1))
    case_root="$TEST_ROOT/legacy-$source_case_count"
    cp -R "$BASELINE" "$case_root"
    printf '\n%s\n' "$mutation" >>"$case_root/src/credential_resolver.rs"
    expect_failure "$case_root" "legacy credential mutation: $mutation" \
        'legacy product credential ownership violations:'
done

source_case_count=$((source_case_count + 1))
case_root="$TEST_ROOT/test-only-legacy"
cp -R "$BASELINE" "$case_root"
cat >>"$case_root/src/credential_resolver.rs" <<'EOF'

#[cfg(all(target_os = "linux", test))]
mod legacy_test_helpers {
    struct CredentialSourceIndex(usize);
    struct CredentialSourceRegistry;
    enum ResolvedCredentialAction { Bearer }
    struct CredentialResolverSnapshot;
    struct StandaloneCredentialProgram;
    struct StagedProviderCredentialMutation;
    enum ProviderCredentialInjectionError { Invalid }
    struct SecretBytes(Vec<u8>);
    fn render_credential() {}
    fn take_credential_program() {}
    fn stage_credentials() {}
    fn mutate_environment() {
        std::env::set_var("TOKEN", "secret");
        env::remove_var("TOKEN");
    }
}
EOF
expect_success "$case_root" 'test-only legacy credential helpers'

source_case_count=$((source_case_count + 1))
case_root="$TEST_ROOT/non-code-legacy"
cp -R "$BASELINE" "$case_root"
cat >>"$case_root/src/credential_resolver.rs" <<'EOF'

// struct SecretBytes(Vec<u8>); fn render_credential() {}; std::env::set_var("TOKEN", "secret");
const LEGACY_NAMES: &str = r#"struct StandaloneCredentialProgram; fn stage_credentials() {}; env::remove_var("TOKEN")"#;
EOF
expect_success "$case_root" 'legacy credential names in comments and literals'

source_case_count=$((source_case_count + 1))
case_root="$TEST_ROOT/connect-suite-without-test-owner"
cp -R "$BASELINE" "$case_root"
sed -i '/#\[cfg(test)\]/d' "$case_root/src/activation/runner.rs"
expect_failure "$case_root" 'CONNECT/MITM include without cfg(test) owner' \
    'activation runner must have exactly one #[cfg(test)] mod tests owner'

source_case_count=$((source_case_count + 1))
case_root="$TEST_ROOT/connect-suite-renamed-include"
cp -R "$BASELINE" "$case_root"
sed -i 's/runner_connect_mitm_tests\.rs/other_tests.rs/' \
    "$case_root/src/activation/runner.rs"
expect_failure "$case_root" 'renamed CONNECT/MITM include' \
    'CONNECT/MITM suite must have exactly one test-only include'

source_case_count=$((source_case_count + 1))
case_root="$TEST_ROOT/connect-suite-duplicate-include"
cp -R "$BASELINE" "$case_root"
cat >>"$case_root/src/activation/runner.rs" <<'EOF'

#[cfg(test)]
mod duplicate_tests {
    include!("runner_connect_mitm_tests.rs");
}
EOF
expect_failure "$case_root" 'duplicate CONNECT/MITM include' \
    'CONNECT/MITM suite must have exactly one test-only include'

for pair in \
    'impl CredentialResolver for ProductCredentialResolver|impl ProductResolver for ProductCredentialResolver|product credential adapter must implement shared CredentialResolver' \
    'CredentialProgram::prepare|CredentialProgram::build|product credential adapter must prepare the shared CredentialProgram'
do
    source_case_count=$((source_case_count + 1))
    case_root="$TEST_ROOT/missing-shared-$source_case_count"
    cp -R "$BASELINE" "$case_root"
    old=${pair%%|*}
    remainder=${pair#*|}
    new=${remainder%%|*}
    expected=${remainder#*|}
    python3 - "$case_root/src/credential_resolver.rs" "$old" "$new" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(path.read_text().replace(sys.argv[2], sys.argv[3]), encoding="utf-8")
PY
    expect_failure "$case_root" "missing shared credential ownership token: $old" "$expected"
done

metadata_case_count=0
for spec in \
    'missing|missing production dependency credential-core' \
    'dev-dependency|credential-core must be a production dependency' \
    'wrong-path|credential-core must use the exact sibling path' \
    'loose-version|credential-core must use exact version =0.1.0'
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

printf 'shared credential ownership mutation tests passed (%d source mutations, %d metadata mutations)\n' \
    "$source_case_count" "$metadata_case_count"
