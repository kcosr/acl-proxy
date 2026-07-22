#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
GATE="$ROOT/scripts/check-packaging-policy.py"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/acl-proxy-packaging-policy.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

BASELINE="$TMP/baseline"
mkdir -p "$BASELINE/scripts"
mkdir -p "$BASELINE/crates/transparent-uds-relay"
for file in Cargo.toml Cargo.lock README.md acl-proxy.sample.toml deny.toml PROVENANCE.md THIRD_PARTY_NOTICES; do
    cp "$ROOT/$file" "$BASELINE/$file"
done
cp "$ROOT/crates/transparent-uds-relay/Cargo.toml" "$BASELINE/crates/transparent-uds-relay/"
cp "$ROOT/scripts/check-packaging-policy.sh" "$BASELINE/scripts/"
cp "$ROOT/scripts/release.mjs" "$BASELINE/scripts/"
cargo metadata --locked --offline --format-version 1 >"$BASELINE/metadata.json"

run_gate() {
    local fixture=$1
    python3 "$GATE" --root "$fixture" --metadata "$fixture/metadata.json"
}

run_gate "$BASELINE"

expect_rejected() {
    local name=$1
    local old=$2
    local new=$3
    local file=$4
    local fixture="$TMP/$name"
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
}

expect_metadata_rejected() {
    local name=$1
    local package=$2
    local field=$3
    local value=$4
    local fixture="$TMP/$name"
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
}

expect_metadata_duplicate_rejected() {
    local name=$1
    local package=$2
    local fixture="$TMP/$name"
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
}

expect_created_path_rejected() {
    local name=$1
    local path=$2
    local fixture="$TMP/$name"
    cp -a "$BASELINE" "$fixture"
    mkdir -p "$(dirname -- "$fixture/$path")"
    printf 'obsolete\n' >"$fixture/$path"
    if run_gate "$fixture" >"$fixture.out" 2>&1; then
        printf 'packaging created-path mutation unexpectedly passed: %s\n' "$name" >&2
        exit 1
    fi
}

expect_obsolete_surface_rejected() {
    local name=$1
    local file=$2
    local marker=$3
    local fixture="$TMP/$name"
    cp -a "$BASELINE" "$fixture"
    printf '\n%s\n' "$marker" >>"$fixture/$file"
    if run_gate "$fixture" >"$fixture.out" 2>&1; then
        printf 'packaging obsolete-surface mutation unexpectedly passed: %s\n' "$name" >&2
        exit 1
    fi
}

expect_rejected product-version 'version = "0.3.0-rc.1"' 'version = "0.3.0-rc.2"' Cargo.toml
expect_rejected product-version-inheritance 'version.workspace = true' 'version = "0.3.0-rc.1"' Cargo.toml
expect_rejected relay-version-inheritance 'version.workspace = true' 'version = "0.3.0-rc.1"' crates/transparent-uds-relay/Cargo.toml
expect_rejected relay-workspace-member $'[workspace]\nmembers = [".", "crates/transparent-uds-relay"]' $'[workspace]\nmembers = ["."]' Cargo.toml
expect_rejected relay-default-member 'default-members = [".", "crates/transparent-uds-relay"]' 'default-members = ["."]' Cargo.toml
expect_rejected release-repository 'kcosr/acl-proxy-access-runtime' 'kcosr/acl-proxy' scripts/release.mjs
expect_rejected release-remote 'const RELEASE_REMOTE = "access-runtime";' 'const RELEASE_REMOTE = "origin";' scripts/release.mjs
expect_rejected publish-guard 'publish = false' 'publish = true' Cargo.toml
expect_rejected lock-product-version $'name = "acl-proxy"\nversion = "0.3.0-rc.1"' $'name = "acl-proxy"\nversion = "0.3.0-rc.2"' Cargo.lock
expect_metadata_rejected metadata-product-version acl-proxy version 0.3.0-rc.2
expect_metadata_rejected metadata-publish-guard acl-proxy publish unexpected
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
expect_rejected lock-http-version $'name = "http"\nversion = "1.4.2"' $'name = "http"\nversion = "0.2.12"' Cargo.lock
expect_rejected lock-hyper-source $'name = "hyper"\nversion = "1.10.1"' $'name = "hyper"\nversion = "1.10.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"' Cargo.lock
expect_rejected lock-duplicate-hyper $'name = "hyper-util"\nversion = "0.1.20"' $'name = "hyper"\nversion = "0.14.32"\n\n[[package]]\nname = "hyper-util"\nversion = "0.1.20"' Cargo.lock
expect_rejected brotli-copyright 'Copyright (c) 2009, 2010, 2013-2016 by the Brotli Authors.' 'Copyright removed from Brotli.' THIRD_PARTY_NOTICES
expect_rejected dropbox-copyright 'Copyright (c) 2016 Dropbox, Inc.' 'Copyright removed from Dropbox brotli.' THIRD_PARTY_NOTICES
expect_rejected zstd-copyright 'Copyright (c) Meta Platforms, Inc. and affiliates. All rights reserved.' 'Copyright removed from Zstandard.' THIRD_PARTY_NOTICES
expect_rejected hyper-license-copyright 'Copyright (c) 2014-2026 Sean McArthur' 'Copyright removed from Hyper.' THIRD_PARTY_NOTICES
expect_rejected provenance-runtime 'bca85d11787afe988dc63cad817f20434523cf66' 'wrong-runtime-commit' PROVENANCE.md
expect_rejected provenance-brotli-license 'Google Brotli C implementation it compiles is MIT' 'Google Brotli C implementation has the wrong license' PROVENANCE.md
expect_rejected provenance-zstd-license 'Zstandard source under BSD-3-Clause' 'Zstandard source has the wrong license' PROVENANCE.md
expect_rejected archive-notices 'README, `LICENSE`, `THIRD_PARTY_NOTICES`' 'README, `LICENSE`, `REMOVED_NOTICES`' README.md
expect_rejected audit-gate-fetch ' --no-fetch' '' scripts/check-packaging-policy.sh
expect_rejected audit-gate-yanked ' --no-yanked' '' scripts/check-packaging-policy.sh
expect_rejected audit-gate-warnings ' --deny warnings' '' scripts/check-packaging-policy.sh
expect_rejected audit-gate-ignore 'cargo audit --no-fetch --no-yanked --deny warnings' 'cargo audit --no-fetch --no-yanked --deny warnings --ignore FORBIDDEN-ADVISORY' scripts/check-packaging-policy.sh
expect_rejected audit-gate-db-override 'cargo audit --no-fetch --no-yanked --deny warnings' 'cargo audit --no-fetch --no-yanked --deny warnings --db /tmp/repository-advisory-db' scripts/check-packaging-policy.sh
expect_rejected audit-gate-comment 'cargo audit --no-fetch --no-yanked --deny warnings' '# cargo audit --no-fetch --no-yanked --deny warnings' scripts/check-packaging-policy.sh
expect_rejected deny-gate-advisories 'licenses sources' 'advisories licenses sources' scripts/check-packaging-policy.sh
expect_rejected deny-gate-online '--offline ' '' scripts/check-packaging-policy.sh
expect_rejected deny-gate-warnings ' -D warnings' '' scripts/check-packaging-policy.sh
expect_rejected deny-gate-comment 'cargo deny --locked --offline check -D warnings licenses sources' '# cargo deny --locked --offline check -D warnings licenses sources' scripts/check-packaging-policy.sh
expect_rejected gate-order $'cargo audit --no-fetch --no-yanked --deny warnings\ncargo deny --locked --offline check -D warnings licenses sources' $'cargo deny --locked --offline check -D warnings licenses sources\ncargo audit --no-fetch --no-yanked --deny warnings' scripts/check-packaging-policy.sh
expect_rejected archive-root 'acl-proxy-<version>-<acl12>/' 'acl-proxy-release/' README.md
expect_rejected archive-hardcoded-sha 'acl-proxy-<version>-<acl12>/' 'acl-proxy-0.3.0-rc.1-0123456789ab/' README.md
expect_rejected candidate-doc-version 'The `0.3.0-rc.1` candidate requires' 'The `0.3.0-rc.2` candidate requires' README.md
expect_created_path_rejected obsolete-demo demos/auth-plugin-stdio/README.md
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
expect_rejected archive-relay-bin '  bin/acl-proxy-transparent-uds-relay  # Linux archives only' '  acl-proxy-transparent-uds-relay' README.md
expect_rejected sample-export 'acl-proxy export-ca' 'ca-cert.pem' acl-proxy.sample.toml

printf 'packaging policy mutation suite passed\n'
