#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

tool_version='cargo-public-api 0.52.0'
toolchain='nightly-2026-07-13'
baseline="$ROOT/public-api.txt"

if [[ $# -ne 0 ]]; then
    if [[ $# -ne 2 || $1 != '--baseline' ]]; then
        printf 'usage: %s [--baseline PATH]\n' "$0" >&2
        exit 2
    fi
    baseline=$2
fi

if ! command -v cargo-public-api >/dev/null 2>&1; then
    printf '%s is required\n' "$tool_version" >&2
    exit 1
fi
if [[ $(cargo public-api --version) != "$tool_version" ]]; then
    printf 'expected %s\n' "$tool_version" >&2
    exit 1
fi
rustup run "$toolchain" rustc --version >/dev/null

generated=$(mktemp "${TMPDIR:-/tmp}/acl-proxy-public-api.XXXXXX")
cleanup() {
    rm -f -- "$generated"
}
trap cleanup EXIT INT TERM

lock_before=$(sha256sum Cargo.lock)
RUSTUP_TOOLCHAIN="$toolchain" cargo public-api \
    --all-features --color never 2>/dev/null >"$generated"
lock_after=$(sha256sum Cargo.lock)
if [[ "$lock_before" != "$lock_after" ]]; then
    printf 'public API generation modified Cargo.lock\n' >&2
    exit 1
fi

if ! diff -u "$baseline" "$generated"; then
    printf 'public API differs from public-api.txt; review the product boundary and update intentionally\n' >&2
    exit 1
fi

printf 'product public API snapshot passed\n'
