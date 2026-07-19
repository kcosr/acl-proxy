#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

python3 scripts/check-packaging-policy.py
cargo audit --no-fetch --no-yanked --deny warnings
cargo deny --locked --offline check -D warnings licenses sources
