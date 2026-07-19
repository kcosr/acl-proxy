#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
GATE="$ROOT/scripts/check-packaging-policy.py"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/acl-proxy-packaging-policy.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

BASELINE="$TMP/baseline"
mkdir -p "$BASELINE/scripts"
for file in Cargo.toml Cargo.lock README.md acl-proxy.sample.toml deny.toml PROVENANCE.md THIRD_PARTY_NOTICES; do
    cp "$ROOT/$file" "$BASELINE/$file"
done
cp "$ROOT/scripts/check-packaging-policy.sh" "$BASELINE/scripts/"
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
expect_rejected provenance-runtime '9bf11cdbe73e63d69ac4ec9935cf9da68612d243' 'wrong-runtime-commit' PROVENANCE.md
expect_rejected provenance-brotli-license 'Google Brotli C implementation it compiles is MIT' 'Google Brotli C implementation has the wrong license' PROVENANCE.md
expect_rejected provenance-zstd-license 'Zstandard source under BSD-3-Clause' 'Zstandard source has the wrong license' PROVENANCE.md
expect_rejected archive-notices 'README, `LICENSE`, `THIRD_PARTY_NOTICES`' 'README, `LICENSE`, `REMOVED_NOTICES`' README.md
expect_rejected advisory-gate 'advisories licenses sources' 'licenses sources' scripts/check-packaging-policy.sh
expect_rejected advisory-gate-online '--offline ' '' scripts/check-packaging-policy.sh
expect_rejected advisory-gate-warnings ' -D warnings' '' scripts/check-packaging-policy.sh
expect_rejected advisory-gate-comment 'cargo deny --locked --offline check -D warnings advisories licenses sources' '# cargo deny --locked --offline check -D warnings advisories licenses sources' scripts/check-packaging-policy.sh
expect_rejected archive-root 'acl-proxy-0.2.0-extraction-checkpoint-<acl12>/' 'acl-proxy-extraction-checkpoint/' README.md
expect_rejected archive-hardcoded-sha 'acl-proxy-0.2.0-extraction-checkpoint-<acl12>/' 'acl-proxy-0.2.0-extraction-checkpoint-0123456789ab/' README.md
expect_rejected archive-bin '  bin/acl-proxy-extract-capture-body' '  acl-proxy-extract-capture-body' README.md
expect_rejected sample-export 'acl-proxy export-ca' 'ca-cert.pem' acl-proxy.sample.toml

printf 'packaging policy mutation suite passed\n'
