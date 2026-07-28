#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Darwin ]]; then
    printf 'scripts/test-macos.sh is only for macOS hosts\n' >&2
    exit 2
fi

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TEMP_ROOT=$(getconf DARWIN_USER_TEMP_DIR)
TEMP_ROOT=$(cd -- "$TEMP_ROOT" && pwd -P)

cd "$ROOT"
TMPDIR=$TEMP_ROOT cargo test --locked "$@"
