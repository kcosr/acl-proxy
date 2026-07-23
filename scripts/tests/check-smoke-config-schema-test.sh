#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
GATE=$ROOT/scripts/check-smoke-config-schema.py
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/smoke-config-schema-test.XXXXXX")
trap 'rm -rf -- "$TEST_ROOT"' EXIT

cp "$ROOT/scripts/loopback-smoke.sh" "$TEST_ROOT/loopback.sh"
cp "$ROOT/scripts/production-topology-smoke.sh" "$TEST_ROOT/production.sh"

"$GATE" "$TEST_ROOT/loopback.sh" "$TEST_ROOT/production.sh"

expect_rejected() {
    local description=$1 expected=$2
    if "$GATE" "$TEST_ROOT/loopback.sh" "$TEST_ROOT/production.sh" \
        >"$TEST_ROOT/failure.log" 2>&1; then
        printf '%s mutation was accepted\n' "$description" >&2
        exit 1
    fi
    grep -Fq "$expected" "$TEST_ROOT/failure.log"
}

replace_once() {
    python3 - "$1" "$2" "$3" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
if text.count(sys.argv[2]) != 1:
    raise SystemExit("mutation source does not occur exactly once")
path.write_text(text.replace(sys.argv[2], sys.argv[3]), encoding="utf-8")
PY
}

replace_once "$TEST_ROOT/loopback.sh" \
    'endpoint = { kind = "tcp", address = "127.0.0.1:$DATA_PORT" }' \
    'bind = "127.0.0.1:$DATA_PORT"'
expect_rejected loopback 'loopback smoke does not generate the exact typed explicit_http endpoint'
cp "$ROOT/scripts/loopback-smoke.sh" "$TEST_ROOT/loopback.sh"

replace_once "$TEST_ROOT/production.sh" \
    'endpoint = { kind = "tcp", address = "0.0.0.0:8443" }' \
    'bind = "0.0.0.0:8443"'
expect_rejected production 'production topology smoke does not generate the exact typed explicit_https endpoint'

cp "$ROOT/scripts/production-topology-smoke.sh" "$TEST_ROOT/production.sh"
replace_once "$TEST_ROOT/production.sh" \
    'endpoint = { kind = "tcp", address = "0.0.0.0:8443" }' \
    $'endpoint = { kind = "tcp", address = "0.0.0.0:8443" }\nbind = "0.0.0.0:8443"'
expect_rejected removed-bind 'production topology smoke retains a removed data-listener bind field'

printf 'smoke configuration listener schema mutation tests passed\n'
