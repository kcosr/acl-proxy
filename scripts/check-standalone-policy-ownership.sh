#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
CHECKER_MANIFEST=${PIPELINE_OWNERSHIP_CHECK_MANIFEST:-"$ROOT/../access-runtime/Cargo.toml"}

cargo run --quiet --locked \
    --manifest-path "$CHECKER_MANIFEST" \
    -p pipeline-ownership-check -- product "$ROOT"
