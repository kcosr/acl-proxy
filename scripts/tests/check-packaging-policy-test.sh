#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
GATE="$ROOT/scripts/check-packaging-policy.py"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/acl-proxy-packaging-policy.XXXXXX")
runtime_source_tree=
if (( $# != 0 )); then
    if (( $# != 2 )) || [[ $1 != --runtime-source-tree ]] \
        || [[ ! $2 =~ ^[0-9a-f]{40}$ ]]; then
        printf 'usage: %s [--runtime-source-tree <40-hex-git-tree>]\n' "$0" >&2
        exit 2
    fi
    runtime_source_tree=$2
fi
AUTHENTICATED_RUNTIME_SOURCE="$ROOT/../access-runtime"
RUNTIME_REPOSITORY=
if [[ -z $runtime_source_tree ]]; then
    RUNTIME_REPOSITORY=$(git -C "$AUTHENTICATED_RUNTIME_SOURCE" rev-parse --show-toplevel)
fi
readarray -t GATE_AUTHORITY < <(python3 - "$GATE" <<'PY'
from pathlib import Path
import runpy
import sys

authority = runpy.run_path(Path(sys.argv[1]))
for name in ("RUNTIME_COMMIT", "RUNTIME_TREE", "PRODUCT_INITIAL_COMMIT"):
    value = authority[name]
    if not isinstance(value, str) or len(value) != 40:
        raise SystemExit(f"packaging gate has no exact {name}")
    print(value)
PY
)
RUNTIME_COMMIT=${GATE_AUTHORITY[0]}
RUNTIME_TREE=${GATE_AUTHORITY[1]}
PRODUCT_INITIAL_COMMIT=${GATE_AUTHORITY[2]}
readonly RUNTIME_COMMIT
readonly RUNTIME_TREE
readonly PRODUCT_INITIAL_COMMIT
if [[ -n $runtime_source_tree && $runtime_source_tree != "$RUNTIME_TREE" ]]; then
    printf '%s\n' 'packaging mutation suite Runtime tree differs from gate authority' >&2
    exit 1
fi
RUNTIME_FIXTURE="$TMP/workspace/access-runtime"

cleanup() {
    if [[ -n $RUNTIME_REPOSITORY ]]; then
        git -C "$RUNTIME_REPOSITORY" worktree remove --force "$RUNTIME_FIXTURE" \
            >/dev/null 2>&1 || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

reset_runtime_fixture() {
    if [[ -n $RUNTIME_REPOSITORY ]]; then
        git -C "$RUNTIME_REPOSITORY" worktree remove --force "$RUNTIME_FIXTURE" \
            >/dev/null 2>&1 || true
        rm -rf "$RUNTIME_FIXTURE"
        git -C "$RUNTIME_REPOSITORY" worktree add --detach "$RUNTIME_FIXTURE" \
            "$RUNTIME_COMMIT" >/dev/null
    else
        rm -rf "$RUNTIME_FIXTURE"
        mkdir -p "$RUNTIME_FIXTURE"
        cp -a "$AUTHENTICATED_RUNTIME_SOURCE/." "$RUNTIME_FIXTURE/"
    fi
}

BASELINE="$TMP/workspace/acl-proxy"
mkdir -p "$BASELINE/scripts"
mkdir -p "$BASELINE/crates/access-flow-relay"
mkdir -p "$BASELINE/src/bin"
mkdir -p "$BASELINE/crates/access-flow-relay/src"
reset_runtime_fixture
for file in Cargo.toml Cargo.lock README.md acl-proxy.sample.toml deny.toml PROVENANCE.md THIRD_PARTY_NOTICES; do
    cp "$ROOT/$file" "$BASELINE/$file"
done
cp "$ROOT/crates/access-flow-relay/Cargo.toml" "$BASELINE/crates/access-flow-relay/"
cp "$ROOT/scripts/check-packaging-policy.sh" "$BASELINE/scripts/"
cp "$ROOT/scripts/release.mjs" "$BASELINE/scripts/"
printf '%s\n' '// metadata-only fixture' >"$BASELINE/src/lib.rs"
printf '%s\n' 'fn main() {}' >"$BASELINE/src/bin/extract-capture-body.rs"
printf '%s\n' '// metadata-only fixture' >"$BASELINE/crates/access-flow-relay/src/lib.rs"
(
    cd "$BASELINE"
    cargo metadata --locked --offline --format-version 1 >metadata.json
)

run_gate() {
    local fixture=$1
    local runtime_source_tree_argument=${2-$runtime_source_tree}
    local resolved_metadata
    resolved_metadata=$(mktemp "$TMP/resolved-metadata.XXXXXX.json")
    python3 - "$fixture/metadata.json" "$resolved_metadata" "$BASELINE" "$fixture" <<'PY'
from pathlib import Path
import json
import sys

source, destination, old_root, new_root = map(Path, sys.argv[1:])
document = json.loads(source.read_text(encoding="utf-8"))

def rebase(value):
    if isinstance(value, dict):
        return {key: rebase(item) for key, item in value.items()}
    if isinstance(value, list):
        return [rebase(item) for item in value]
    if isinstance(value, str):
        return value.replace(str(old_root), str(new_root))
    return value

destination.write_text(json.dumps(rebase(document)), encoding="utf-8")
PY
    arguments=(--root "$fixture" --metadata "$resolved_metadata")
    if [[ -n $runtime_source_tree_argument ]]; then
        arguments+=(--runtime-source-tree "$runtime_source_tree_argument")
    fi
    python3 "$GATE" "${arguments[@]}"
}

run_gate "$BASELINE"

reset_runtime_archive_fixture() {
    if [[ -n $RUNTIME_REPOSITORY ]]; then
        git -C "$RUNTIME_REPOSITORY" worktree remove --force "$RUNTIME_FIXTURE" \
            >/dev/null 2>&1 || true
    fi
    rm -rf "$RUNTIME_FIXTURE"
    mkdir -p "$RUNTIME_FIXTURE"
    if [[ -n $RUNTIME_REPOSITORY ]]; then
        git -C "$RUNTIME_REPOSITORY" archive "$RUNTIME_COMMIT" \
            | tar -x -C "$RUNTIME_FIXTURE"
    else
        cp -a "$AUTHENTICATED_RUNTIME_SOURCE/." "$RUNTIME_FIXTURE/"
    fi
}

expect_archive_rejected() {
    local name=$1
    local expected=$2
    local source_tree=${3:-$RUNTIME_TREE}
    if run_gate "$BASELINE" "$source_tree" >"$TMP/$name.out" 2>&1; then
        printf 'packaging archive mutation unexpectedly passed: %s\n' "$name" >&2
        exit 1
    fi
    if ! grep -Fq "$expected" "$TMP/$name.out"; then
        printf 'packaging archive mutation failed for the wrong reason: %s\n' "$name" >&2
        cat "$TMP/$name.out" >&2
        exit 1
    fi
    reset_runtime_archive_fixture
    run_gate "$BASELINE" "$RUNTIME_TREE" >/dev/null
}

reset_runtime_archive_fixture
run_gate "$BASELINE" "$RUNTIME_TREE"
if GIT_CEILING_DIRECTORIES="$TMP" run_gate "$BASELINE" "" \
    >"$TMP/archive-mode-omitted.out" 2>&1; then
    printf '%s\n' 'metadata-free runtime unexpectedly passed without an authenticated tree' >&2
    exit 1
fi
grep -Fq 'cannot verify canonical sibling runtime source state' \
    "$TMP/archive-mode-omitted.out"
expect_archive_rejected archive-wrong-tree \
    'authenticated runtime source tree argument differs from the accepted runtime tree' \
    0000000000000000000000000000000000000000

printf '\n// authenticated archive content mutation\n' \
    >>"$RUNTIME_FIXTURE/crates/http-access-types/src/lib.rs"
expect_archive_rejected archive-content-mutation \
    'authenticated runtime source archive tree differs from the accepted runtime tree'

chmod +x "$RUNTIME_FIXTURE/crates/http-access-types/src/lib.rs"
expect_archive_rejected archive-mode-mutation \
    'authenticated runtime source archive tree differs from the accepted runtime tree'

ln -s PROVENANCE.md "$RUNTIME_FIXTURE/untracked-source-link"
expect_archive_rejected archive-symlink-mutation \
    'authenticated runtime source archive tree differs from the accepted runtime tree'

mkdir "$RUNTIME_FIXTURE/.git"
expect_archive_rejected archive-git-metadata \
    'authenticated runtime source archive contains Git metadata'

printf '%s\n' 'Git metadata file' >"$RUNTIME_FIXTURE/.git"
expect_archive_rejected archive-git-metadata-file \
    'authenticated runtime source archive contains Git metadata'

ln -s PROVENANCE.md "$RUNTIME_FIXTURE/.git"
expect_archive_rejected archive-git-metadata-symlink \
    'authenticated runtime source archive contains Git metadata'

mkdir -p "$RUNTIME_FIXTURE/crates/http-access-types/.git"
printf '%s\n' 'nested Git metadata' \
    >"$RUNTIME_FIXTURE/crates/http-access-types/.git/payload"
expect_archive_rejected archive-nested-git-metadata \
    'authenticated runtime source archive contains Git metadata'

printf '%s\n' 'nested Git metadata file' \
    >"$RUNTIME_FIXTURE/crates/http-access-types/.git"
expect_archive_rejected archive-nested-git-metadata-file \
    'authenticated runtime source archive contains Git metadata'

ln -s ../../PROVENANCE.md \
    "$RUNTIME_FIXTURE/crates/http-access-types/.git"
expect_archive_rejected archive-nested-git-metadata-symlink \
    'authenticated runtime source archive contains Git metadata'

reset_runtime_fixture
run_gate "$BASELINE"

MISMATCHED_ROOT="$TMP/workspace/metadata-root-mismatch"
cp -a "$BASELINE" "$MISMATCHED_ROOT"
if python3 "$GATE" --root "$MISMATCHED_ROOT" --metadata "$BASELINE/metadata.json" \
    >"$TMP/metadata-root-mismatch.out" 2>&1; then
    printf '%s\n' 'packaging mismatched metadata/root mutation unexpectedly passed' >&2
    exit 1
fi
grep -Fq \
    'locked metadata acl-proxy manifest root differs from the validated product root' \
    "$TMP/metadata-root-mismatch.out" \
    || {
        printf '%s\n' 'packaging mismatched metadata/root mutation failed for the wrong reason' >&2
        cat "$TMP/metadata-root-mismatch.out" >&2
        exit 1
    }

expect_runtime_rejected() {
    local name=$1
    local expected=$2
    if run_gate "$BASELINE" >"$TMP/$name.out" 2>&1; then
        printf 'packaging runtime mutation unexpectedly passed: %s\n' "$name" >&2
        exit 1
    fi
    if ! grep -Fq "$expected" "$TMP/$name.out"; then
        printf 'packaging runtime mutation failed for the wrong reason: %s\n' "$name" >&2
        cat "$TMP/$name.out" >&2
        exit 1
    fi
    reset_runtime_fixture
    run_gate "$BASELINE" >/dev/null
}

if [[ -n $RUNTIME_REPOSITORY ]]; then
    git -C "$RUNTIME_REPOSITORY" worktree remove --force "$RUNTIME_FIXTURE" >/dev/null
    git -C "$RUNTIME_REPOSITORY" worktree add --detach "$RUNTIME_FIXTURE" \
        "$RUNTIME_COMMIT^" >/dev/null
    expect_runtime_rejected runtime-wrong-head \
        'canonical sibling runtime HEAD differs from the accepted runtime commit'

    printf '\n// tracked runtime mutation\n' \
        >>"$RUNTIME_FIXTURE/crates/http-access-types/src/lib.rs"
    expect_runtime_rejected runtime-dirty-tracked \
        'canonical sibling runtime worktree or index is not clean'

    printf '\n// indexed runtime mutation\n' \
        >>"$RUNTIME_FIXTURE/crates/http-access-types/src/lib.rs"
    git -C "$RUNTIME_FIXTURE" add crates/http-access-types/src/lib.rs
    expect_runtime_rejected runtime-dirty-index \
        'canonical sibling runtime worktree or index is not clean'

    printf '%s\n' '// untracked runtime source mutation' \
        >"$RUNTIME_FIXTURE/crates/http-access-types/src/untracked_release_input.rs"
    expect_runtime_rejected runtime-untracked-source \
        'canonical sibling runtime worktree or index is not clean'

python3 - "$RUNTIME_FIXTURE/PROVENANCE.md" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
marker = "- `crates/http-access-mitm`: moved and redesigned product behavior"
if text.count(marker) != 1:
    raise SystemExit("runtime provenance coverage mutation marker is not unique")
path.write_text(text.replace(marker, "", 1), encoding="utf-8")
PY
git -C "$RUNTIME_FIXTURE" update-index --assume-unchanged PROVENANCE.md
expect_runtime_rejected runtime-provenance-coverage \
    'access-runtime provenance crate coverage differs from the exact accepted classification inventory'

python3 - "$RUNTIME_FIXTURE/PROVENANCE.md" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
old = "- `crates/http-access-mitm`: moved and redesigned product behavior"
new = "- `crates/http-access-mitm`: independently authored"
if text.count(old) != 1:
    raise SystemExit("runtime provenance classification mutation marker is not unique")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
PY
git -C "$RUNTIME_FIXTURE" update-index --assume-unchanged PROVENANCE.md
expect_runtime_rejected runtime-provenance-classification \
    'access-runtime provenance crate coverage differs from the exact accepted classification inventory'

python3 - "$RUNTIME_FIXTURE/PROVENANCE.md" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
marker = "- `crates/http-access-mitm`: moved and redesigned product behavior"
if text.count(marker) != 1:
    raise SystemExit("runtime provenance duplicate mutation marker is not unique")
path.write_text(text.replace(marker, f"{marker}\n{marker}", 1), encoding="utf-8")
PY
git -C "$RUNTIME_FIXTURE" update-index --assume-unchanged PROVENANCE.md
expect_runtime_rejected runtime-provenance-duplicate \
    'access-runtime provenance crate coverage contains a duplicate entry'

printf '\n- `crates/outside-coverage`: independently authored\n' \
    >>"$RUNTIME_FIXTURE/PROVENANCE.md"
git -C "$RUNTIME_FIXTURE" update-index --assume-unchanged PROVENANCE.md
expect_runtime_rejected runtime-provenance-outside-section \
    'access-runtime provenance has a crate coverage record outside its section'
fi

reject_runtime_authentication_failure() {
    local name=$1 output=$2
    if grep -Eq \
        'authenticated runtime source|Git metadata|cannot inspect authenticated runtime' \
        "$output"; then
        printf 'packaging mutation failed through Runtime authentication instead of its target: %s\n' \
            "$name" >&2
        cat "$output" >&2
        return 1
    fi
}

printf '%s\n' \
    'packaging policy check failed: authenticated runtime source archive tree differs' \
    >"$TMP/runtime-authentication-control.out"
if reject_runtime_authentication_failure \
    runtime-authentication-control "$TMP/runtime-authentication-control.out" \
    >"$TMP/runtime-authentication-control.log" 2>&1; then
    printf '%s\n' 'Runtime authentication control unexpectedly passed' >&2
    exit 1
fi

expect_rejected() {
    local name=$1
    local old=$2
    local new=$3
    local file=$4
    local fixture="$TMP/workspace/$name"
    cp -a "$BASELINE" "$fixture"
    python3 - "$fixture/$file" "$old" "$new" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
old = sys.argv[2]
new = sys.argv[3]
text = path.read_text(encoding="utf-8")
if text.count(old) != 1:
    raise SystemExit(f"expected exactly one mutation target {old!r} in {path}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
PY
    if run_gate "$fixture" >"$fixture.out" 2>&1; then
        printf 'packaging mutation unexpectedly passed: %s\n' "$name" >&2
        exit 1
    fi
    reject_runtime_authentication_failure "$name" "$fixture.out"
}

expect_metadata_rejected() {
    local name=$1
    local package=$2
    local field=$3
    local value=$4
    local fixture="$TMP/workspace/$name"
    cp -a "$BASELINE" "$fixture"
    python3 - "$fixture/metadata.json" "$package" "$field" "$value" <<'PY'
from pathlib import Path
import json
import sys

path = Path(sys.argv[1])
package_name = sys.argv[2]
field = sys.argv[3]
value = sys.argv[4]
document = json.loads(path.read_text(encoding="utf-8"))
matches = [package for package in document["packages"] if package["name"] == package_name]
if len(matches) != 1:
    raise SystemExit(f"expected exactly one metadata package {package_name!r}")
matches[0][field] = value
path.write_text(json.dumps(document), encoding="utf-8")
PY
    if run_gate "$fixture" >"$fixture.out" 2>&1; then
        printf 'packaging metadata mutation unexpectedly passed: %s\n' "$name" >&2
        exit 1
    fi
    reject_runtime_authentication_failure "$name" "$fixture.out"
}

expect_metadata_duplicate_rejected() {
    local name=$1
    local package=$2
    local fixture="$TMP/workspace/$name"
    cp -a "$BASELINE" "$fixture"
    python3 - "$fixture/metadata.json" "$package" <<'PY'
from pathlib import Path
import copy
import json
import sys

path = Path(sys.argv[1])
package_name = sys.argv[2]
document = json.loads(path.read_text(encoding="utf-8"))
matches = [package for package in document["packages"] if package["name"] == package_name]
if len(matches) != 1:
    raise SystemExit(f"expected exactly one metadata package {package_name!r}")
document["packages"].append(copy.deepcopy(matches[0]))
path.write_text(json.dumps(document), encoding="utf-8")
PY
    if run_gate "$fixture" >"$fixture.out" 2>&1; then
        printf 'packaging duplicate metadata mutation unexpectedly passed: %s\n' "$name" >&2
        exit 1
    fi
    reject_runtime_authentication_failure "$name" "$fixture.out"
}

expect_relay_metadata_dependency_rejected() {
    local name=$1
    local package_name=$2
    local fixture="$TMP/workspace/$name"
    cp -a "$BASELINE" "$fixture"
    python3 - "$fixture/metadata.json" "$package_name" <<'PY'
from pathlib import Path
import json
import sys

path = Path(sys.argv[1])
package_name = sys.argv[2]
document = json.loads(path.read_text(encoding="utf-8"))
packages = [package for package in document["packages"] if package["name"] == package_name]
if len(packages) != 1:
    raise SystemExit(f"expected exactly one metadata package {package_name!r}")
relay = [
    package
    for package in document["packages"]
    if package["name"] == "acl-proxy-access-flow-relay"
]
if len(relay) != 1:
    raise SystemExit("expected exactly one relay metadata package")
nodes = [node for node in document["resolve"]["nodes"] if node["id"] == relay[0]["id"]]
if len(nodes) != 1:
    raise SystemExit("expected exactly one relay resolution node")
package_id = packages[0]["id"]
nodes[0]["dependencies"].append(package_id)
nodes[0]["deps"].append(
    {
        "name": f"forbidden_{package_name.replace('-', '_')}",
        "pkg": package_id,
        "dep_kinds": [{"kind": None, "target": 'cfg(target_os = "linux")'}],
    }
)
path.write_text(json.dumps(document), encoding="utf-8")
PY
    if run_gate "$fixture" >"$fixture.out" 2>&1; then
        printf 'packaging relay metadata dependency mutation unexpectedly passed: %s\n' \
            "$name" >&2
        exit 1
    fi
    reject_runtime_authentication_failure "$name" "$fixture.out"
}

expect_resolved_runtime_package_rejected() {
    local name=$1
    local relative_manifest=$2
    local expected=$3
    local fixture="$TMP/workspace/$name"
    cp -a "$BASELINE" "$fixture"
    python3 - "$fixture/metadata.json" "$RUNTIME_FIXTURE" "$relative_manifest" <<'PY'
from pathlib import Path
import copy
import json
import sys

path = Path(sys.argv[1])
runtime = Path(sys.argv[2])
relative_manifest = Path(sys.argv[3])
document = json.loads(path.read_text(encoding="utf-8"))
templates = [
    package
    for package in document["packages"]
    if package["name"] == "access-async-contracts"
]
if len(templates) != 1:
    raise SystemExit("expected exactly one runtime crate metadata template")
package = copy.deepcopy(templates[0])
package_id = "path+file:///injected/access-new-foundation#0.1.0"
package["id"] = package_id
package["name"] = "access-new-foundation"
package["manifest_path"] = str(runtime / relative_manifest)
document["packages"].append(package)
document["resolve"]["nodes"].append(
    {
        "id": package_id,
        "dependencies": [],
        "deps": [],
        "features": [],
    }
)
runtime_nodes = [
    node
    for node in document["resolve"]["nodes"]
    if "/http-access-runtime#" in node["id"]
]
if len(runtime_nodes) != 1:
    raise SystemExit("expected exactly one http-access-runtime resolution node")
runtime_nodes[0]["dependencies"].append(package_id)
runtime_nodes[0]["deps"].append(
    {
        "name": "access_new_foundation",
        "pkg": package_id,
        "dep_kinds": [{"kind": None, "target": None}],
    }
)
path.write_text(json.dumps(document), encoding="utf-8")
PY
    if run_gate "$fixture" >"$fixture.out" 2>&1; then
        printf 'packaging resolved runtime package mutation unexpectedly passed: %s\n' \
            "$name" >&2
        exit 1
    fi
    if ! grep -Fq "$expected" "$fixture.out"; then
        printf 'packaging resolved runtime package mutation failed for the wrong reason: %s\n' \
            "$name" >&2
        cat "$fixture.out" >&2
        exit 1
    fi
}

expect_created_path_rejected() {
    local name=$1
    local path=$2
    local fixture="$TMP/workspace/$name"
    cp -a "$BASELINE" "$fixture"
    mkdir -p "$(dirname -- "$fixture/$path")"
    printf 'obsolete\n' >"$fixture/$path"
    if run_gate "$fixture" >"$fixture.out" 2>&1; then
        printf 'packaging created-path mutation unexpectedly passed: %s\n' "$name" >&2
        exit 1
    fi
    reject_runtime_authentication_failure "$name" "$fixture.out"
}

expect_obsolete_surface_rejected() {
    local name=$1
    local file=$2
    local marker=$3
    local fixture="$TMP/workspace/$name"
    cp -a "$BASELINE" "$fixture"
    printf '\n%s\n' "$marker" >>"$fixture/$file"
    if run_gate "$fixture" >"$fixture.out" 2>&1; then
        printf 'packaging obsolete-surface mutation unexpectedly passed: %s\n' "$name" >&2
        exit 1
    fi
    reject_runtime_authentication_failure "$name" "$fixture.out"
}

expect_rejected product-version 'version = "0.3.0-rc.1"' 'version = "0.3.0-rc.2"' Cargo.toml
expect_rejected product-version-inheritance 'version.workspace = true' 'version = "0.3.0-rc.1"' Cargo.toml
expect_rejected relay-version-inheritance 'version.workspace = true' 'version = "0.3.0-rc.1"' crates/access-flow-relay/Cargo.toml
expect_rejected relay-workspace-member $'[workspace]\nmembers = [".", "crates/access-flow-relay"]' $'[workspace]\nmembers = ["."]' Cargo.toml
expect_rejected relay-default-member 'default-members = [".", "crates/access-flow-relay"]' 'default-members = ["."]' Cargo.toml
expect_rejected relay-shared-engine 'access-flow-relay = {' 'removed-access-flow-relay = {' crates/access-flow-relay/Cargo.toml
expect_rejected relay-unix-adapter 'access-flow-unix = {' 'removed-access-flow-unix = {' crates/access-flow-relay/Cargo.toml
expect_rejected relay-publish-guard 'publish = false' 'publish = true' crates/access-flow-relay/Cargo.toml
expect_rejected release-repository 'kcosr/acl-proxy-access-runtime' 'kcosr/acl-proxy' scripts/release.mjs
expect_rejected release-remote 'const RELEASE_REMOTE = "access-runtime";' 'const RELEASE_REMOTE = "origin";' scripts/release.mjs
expect_rejected publish-guard 'publish = false' 'publish = true' Cargo.toml
expect_rejected lock-product-version $'name = "acl-proxy"\nversion = "0.3.0-rc.1"' $'name = "acl-proxy"\nversion = "0.3.0-rc.2"' Cargo.lock
expect_metadata_rejected metadata-product-version acl-proxy version 0.3.0-rc.2
expect_metadata_rejected metadata-publish-guard acl-proxy publish unexpected
expect_metadata_rejected metadata-relay-publish-guard acl-proxy-access-flow-relay publish unexpected
expect_rejected compu-version '=1.2.0' '^1.2.0' Cargo.toml
expect_rejected http-version 'http = "=1.4.2"' 'http = "1.4"' Cargo.toml
expect_rejected h2-version 'h2 = "=0.4.15"' 'h2 = "0.4"' Cargo.toml
expect_rejected production-h2 $'http = "=1.4.2"' $'http = "=1.4.2"\nh2-production = { package = "h2", version = "=0.4.15" }' Cargo.toml
expect_rejected renamed-http $'http = "=1.4.2"' $'http = "=1.4.2"\nhttp-transport = { package = "http", version = "=1.4.2" }' Cargo.toml
expect_rejected direct-http-body $'http = "=1.4.2"' $'http = "=1.4.2"\nhttp-body = "=1.0.1"' Cargo.toml
expect_rejected renamed-http-body-util $'http = "=1.4.2"' $'http = "=1.4.2"\nbody-util = { package = "http-body-util", version = "=0.1.3" }' Cargo.toml
expect_rejected direct-hyper $'http = "=1.4.2"' $'http = "=1.4.2"\nhyper = "=1.10.1"' Cargo.toml
expect_rejected renamed-hyper $'http = "=1.4.2"' $'http = "=1.4.2"\ntransport = { package = "hyper", version = "=1.10.1" }' Cargo.toml
expect_rejected direct-hyper-util $'http = "=1.4.2"' $'http = "=1.4.2"\nhyper-util = "=0.1.20"' Cargo.toml
relay_linux_dependencies='[target.'"'"'cfg(target_os = "linux")'"'"'.dependencies]'
relay_linux_dev_dependencies='[target.'"'"'cfg(target_os = "linux")'"'"'.dev-dependencies]'
expect_rejected relay-direct-http \
    "$relay_linux_dependencies" \
    "$relay_linux_dependencies"$'\nhttp = "=1.4.2"' \
    crates/access-flow-relay/Cargo.toml
expect_rejected relay-renamed-h2 \
    "$relay_linux_dev_dependencies" \
    "$relay_linux_dev_dependencies"$'\nrelay-h2 = { package = "h2", version = "=0.4.15" }' \
    crates/access-flow-relay/Cargo.toml
expect_rejected relay-direct-hyper \
    "$relay_linux_dependencies" \
    "$relay_linux_dependencies"$'\nhyper = "=1.10.1"' \
    crates/access-flow-relay/Cargo.toml
expect_rejected relay-renamed-hyper-util \
    "$relay_linux_dependencies" \
    "$relay_linux_dependencies"$'\nrelay-hyper-util = { package = "hyper-util", version = "=0.1.20" }' \
    crates/access-flow-relay/Cargo.toml
expect_rejected relay-target-build-http-body \
    "$relay_linux_dev_dependencies" \
    $'[target.'"'"'cfg(target_os = "linux")'"'"'.build-dependencies]\nhttp-body = "=1.0.1"\n\n'"$relay_linux_dev_dependencies" \
    crates/access-flow-relay/Cargo.toml
expect_rejected relay-renamed-http-body-util \
    "$relay_linux_dependencies" \
    $'[build-dependencies]\nrelay-body = { package = "http-body-util", version = "=0.1.3" }\n\n'"$relay_linux_dependencies" \
    crates/access-flow-relay/Cargo.toml
expect_rejected missing-patch '[patch.crates-io]' '[patch.removed]' Cargo.toml
expect_rejected wrong-patch-path '../access-runtime/third_party/hyper' '../wrong-runtime/third_party/hyper' Cargo.toml
expect_rejected extra-patch $'hyper = { path = "../access-runtime/third_party/hyper" }' $'hyper = { path = "../access-runtime/third_party/hyper" }\nhttp = { path = "../access-runtime/third_party/hyper" }' Cargo.toml
expect_rejected replace-override $'[profile.release]' $'[replace]\n"hyper:1.10.1" = { path = "../access-runtime/third_party/hyper" }\n\n[profile.release]' Cargo.toml
expect_rejected obsolete-advisories-policy '[licenses]' $'[advisories]\nignore = []\n\n[licenses]' deny.toml
expect_rejected global-bsl '"Unicode-3.0"]' '"Unicode-3.0", "BSL-1.0"]' deny.toml
expect_rejected exception-version 'version = "=1.2.0"' 'version = "^1.2.0"' deny.toml
expect_rejected exception-name 'name = "compu-brotli-sys"' 'name = "brotli"' deny.toml
expect_rejected source-policy 'unknown-git = "deny"' 'unknown-git = "allow"' deny.toml
expect_rejected notice-license 'Boost Software License - Version 1.0' 'Removed License - Version 1.0' THIRD_PARTY_NOTICES
expect_rejected notice-checksum 'd864fe78a6384799d3740c45f7fd2fd6d7518f139e68ba87be033b31ce7e17fe' 'missing-checksum' THIRD_PARTY_NOTICES
expect_rejected notice-shared-runtime-license \
    'access-runtime` crates are MIT-licensed' \
    'access-runtime` crates are proprietary' \
    THIRD_PARTY_NOTICES
expect_rejected lock-checksum 'd864fe78a6384799d3740c45f7fd2fd6d7518f139e68ba87be033b31ce7e17fe' 'e864fe78a6384799d3740c45f7fd2fd6d7518f139e68ba87be033b31ce7e17fe' Cargo.lock
expect_rejected direct-version '- tokio 1.48.0, MIT' '- tokio 1.47.0, MIT' THIRD_PARTY_NOTICES
expect_rejected direct-name '- tokio 1.48.0, MIT' '- tokio-renamed 1.48.0, MIT' THIRD_PARTY_NOTICES
expect_rejected direct-license '- tokio-rustls 0.26.4, MIT OR Apache-2.0' '- tokio-rustls 0.26.4, MIT OR Apache-2.0 OR ISC' THIRD_PARTY_NOTICES
expect_metadata_rejected metadata-direct-version tokio version 1.47.0
expect_metadata_rejected metadata-direct-license tokio-rustls license 'MIT OR Apache-2.0 OR ISC'
expect_metadata_rejected metadata-http-version http version 0.2.12
expect_metadata_rejected metadata-hyper-source hyper source "registry+https://github.com/rust-lang/crates.io-index"
expect_metadata_rejected metadata-hyper-path hyper manifest_path /tmp/wrong-runtime/third_party/hyper/Cargo.toml
expect_metadata_duplicate_rejected metadata-duplicate-http http
expect_metadata_duplicate_rejected metadata-duplicate-hyper hyper
expect_relay_metadata_dependency_rejected metadata-relay-hyper hyper
expect_resolved_runtime_package_rejected \
    metadata-resolved-runtime-crate \
    crates/access-new-foundation/Cargo.toml \
    'access-runtime provenance crate coverage differs from the exact resolved shared product dependency graph'
expect_resolved_runtime_package_rejected \
    metadata-unapproved-runtime-path \
    third_party/newlib/Cargo.toml \
    'locked metadata resolves an unapproved source-less runtime package path'
expect_rejected lock-http-version $'name = "http"\nversion = "1.4.2"' $'name = "http"\nversion = "0.2.12"' Cargo.lock
expect_rejected lock-hyper-source $'name = "hyper"\nversion = "1.10.1"' $'name = "hyper"\nversion = "1.10.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"' Cargo.lock
expect_rejected lock-duplicate-hyper $'name = "hyper-util"\nversion = "0.1.20"' $'name = "hyper"\nversion = "0.14.32"\n\n[[package]]\nname = "hyper-util"\nversion = "0.1.20"' Cargo.lock
expect_rejected brotli-copyright 'Copyright (c) 2009, 2010, 2013-2016 by the Brotli Authors.' 'Copyright removed from Brotli.' THIRD_PARTY_NOTICES
expect_rejected dropbox-copyright 'Copyright (c) 2016 Dropbox, Inc.' 'Copyright removed from Dropbox brotli.' THIRD_PARTY_NOTICES
expect_rejected zstd-copyright 'Copyright (c) Meta Platforms, Inc. and affiliates. All rights reserved.' 'Copyright removed from Zstandard.' THIRD_PARTY_NOTICES
expect_rejected hyper-license-copyright 'Copyright (c) 2014-2026 Sean McArthur' 'Copyright removed from Hyper.' THIRD_PARTY_NOTICES
expect_rejected provenance-product-initial \
    "$PRODUCT_INITIAL_COMMIT" \
    1111111111111111111111111111111111111111 \
    PROVENANCE.md
initial_record=$(printf -- '- Initial source commit: `%s`' "$PRODUCT_INITIAL_COMMIT")
expect_rejected provenance-product-initial-unstructured \
    "$initial_record" \
    "Product source lineage includes \`$PRODUCT_INITIAL_COMMIT\`." \
    PROVENANCE.md
initial_duplicate_record=$(printf -- '%s\n%s' "$initial_record" "$initial_record")
expect_rejected provenance-product-initial-duplicate \
    "$initial_record" \
    "$initial_duplicate_record" \
    PROVENANCE.md
initial_conflicting_record=$(printf -- '%s\n- Initial source commit: `%s`' \
    "$initial_record" 1111111111111111111111111111111111111111)
expect_rejected provenance-product-initial-conflict \
    "$initial_record" \
    "$initial_conflicting_record" \
    PROVENANCE.md
expect_rejected provenance-runtime "$RUNTIME_COMMIT" 'wrong-runtime-commit' PROVENANCE.md
runtime_record=$(printf -- '- Accepted runtime commit:\n  `%s`' "$RUNTIME_COMMIT")
runtime_duplicate_record=$(printf -- '%s\n- Accepted runtime commit:\n  `%s`' \
    "$runtime_record" 1111111111111111111111111111111111111111)
expect_rejected provenance-runtime-record \
    "$runtime_record" \
    "$runtime_duplicate_record" \
    PROVENANCE.md
expect_rejected provenance-runtime-authority-description \
    'The authoritative complete origin record is' \
    'The authoritative moved-source record is' \
    PROVENANCE.md
expect_rejected provenance-runtime-authority-file \
    'access-runtime/PROVENANCE.md' \
    'access-runtime/WRONG-PROVENANCE.md' \
    PROVENANCE.md
expect_rejected provenance-runtime-coverage-authority \
    '`Shared Crate Origin Coverage` inventory is the exact per-crate' \
    '`Shared Crate Origin Coverage` inventory is an advisory per-crate' \
    PROVENANCE.md
expect_rejected provenance-compu-package-version \
    'compu-brotli-sys` 1.2.0' \
    'compu-brotli-sys` 1.1.0' \
    PROVENANCE.md
expect_rejected provenance-brotli-license 'Google Brotli C implementation it compiles is MIT' 'Google Brotli C implementation has the wrong license' PROVENANCE.md
expect_rejected provenance-zstd-license 'Zstandard source under BSD-3-Clause' 'Zstandard source has the wrong license' PROVENANCE.md
expect_rejected archive-notices 'README, `LICENSE`, `THIRD_PARTY_NOTICES`' 'README, `LICENSE`, `REMOVED_NOTICES`' README.md
expect_rejected audit-gate-fetch ' --no-fetch' '' scripts/check-packaging-policy.sh
expect_rejected audit-gate-yanked ' --no-yanked' '' scripts/check-packaging-policy.sh
expect_rejected audit-gate-warnings ' --deny warnings' '' scripts/check-packaging-policy.sh
expect_rejected audit-gate-ignore 'cargo audit --no-fetch --no-yanked --deny warnings' 'cargo audit --no-fetch --no-yanked --deny warnings --ignore FORBIDDEN-ADVISORY' scripts/check-packaging-policy.sh
expect_rejected audit-gate-db-override 'cargo audit --no-fetch --no-yanked --deny warnings' 'cargo audit --no-fetch --no-yanked --deny warnings --db /tmp/repository-advisory-db' scripts/check-packaging-policy.sh
expect_rejected audit-gate-comment 'cargo audit --no-fetch --no-yanked --deny warnings' '# cargo audit --no-fetch --no-yanked --deny warnings' scripts/check-packaging-policy.sh
expect_rejected packaging-gate-argument-bypass \
    'python3 scripts/check-packaging-policy.py "${runtime_source_arguments[@]}"' \
    'python3 scripts/check-packaging-policy.py "$@"' \
    scripts/check-packaging-policy.sh
expect_rejected deny-gate-advisories 'licenses sources' 'advisories licenses sources' scripts/check-packaging-policy.sh
expect_rejected deny-gate-online '--offline ' '' scripts/check-packaging-policy.sh
expect_rejected deny-gate-warnings ' -D warnings' '' scripts/check-packaging-policy.sh
expect_rejected deny-gate-comment 'cargo deny --locked --offline check -D warnings licenses sources' '# cargo deny --locked --offline check -D warnings licenses sources' scripts/check-packaging-policy.sh
expect_rejected gate-order $'cargo audit --no-fetch --no-yanked --deny warnings\ncargo deny --locked --offline check -D warnings licenses sources' $'cargo deny --locked --offline check -D warnings licenses sources\ncargo audit --no-fetch --no-yanked --deny warnings' scripts/check-packaging-policy.sh
expect_rejected archive-root 'acl-proxy-<version>-<acl12>/' 'acl-proxy-release/' README.md
expect_rejected archive-hardcoded-sha 'acl-proxy-<version>-<acl12>/' 'acl-proxy-0.3.0-rc.1-0123456789ab/' README.md
expect_rejected archive-linux-name 'acl-proxy-<version>-<acl12>-linux-x86_64.tar.gz' 'acl-proxy-<version>-<acl12>-linux-amd64.tar.gz' README.md
expect_rejected archive-macos-name 'acl-proxy-<version>-<acl12>-macos-arm64.tar.gz' 'acl-proxy-<version>-<acl12>-darwin-arm64.tar.gz' README.md
expect_rejected archive-macos-qualification \
    $'no macOS archive is built or\nincluded in this candidate' \
    $'a macOS archive may be built or\nincluded in this candidate' \
    README.md
expect_rejected candidate-doc-version 'The `0.3.0-rc.1` candidate requires' 'The `0.3.0-rc.2` candidate requires' README.md
expect_created_path_rejected obsolete-demo demos/auth-plugin-stdio/README.md
expect_created_path_rejected obsolete-relay-crate crates/transparent-uds-relay/Cargo.toml
obsolete_markers=(
    'policy.external_auth_profiles'
    'policy.approval_macros'
    'external_auth_profile ='
    '[[policy.rules.header_actions]]'
)
for file in README.md acl-proxy.sample.toml; do
    surface=${file//[^[:alnum:]]/-}
    for index in "${!obsolete_markers[@]}"; do
        expect_obsolete_surface_rejected \
            "obsolete-${surface}-${index}" \
            "$file" \
            "${obsolete_markers[$index]}"
    done
done
expect_rejected archive-bin '  bin/acl-proxy-extract-capture-body' '  acl-proxy-extract-capture-body' README.md
expect_rejected archive-relay-bin '  bin/acl-proxy-access-flow-relay  # Linux archives only' '  acl-proxy-access-flow-relay' README.md
expect_rejected sample-export 'acl-proxy export-ca' 'ca-cert.pem' acl-proxy.sample.toml

printf 'packaging policy mutation suite passed\n'
