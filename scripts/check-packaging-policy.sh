#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

runtime_source_arguments=()
if (( $# != 0 )); then
    if (( $# != 2 )) || [[ $1 != --runtime-source-tree ]] \
        || [[ ! $2 =~ ^[0-9a-f]{40}$ ]]; then
        printf 'usage: %s [--runtime-source-tree <40-hex-git-tree>]\n' "$0" >&2
        exit 2
    fi
    runtime_source_arguments=("$1" "$2")
fi

python3 scripts/check-packaging-policy.py "${runtime_source_arguments[@]}"
cargo audit --no-fetch --no-yanked --deny warnings
cargo deny --locked --offline check -D warnings licenses sources
