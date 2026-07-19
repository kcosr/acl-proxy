#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
GATE="$ROOT/scripts/check-public-api.sh"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/acl-proxy-public-api.XXXXXX")
trap 'rm -rf -- "$TMP"' EXIT INT TERM

gate_line='    scripts/check-public-api.sh'
test_line='    scripts/tests/check-public-api-test.sh'
[[ $(grep -Fxc "$gate_line" "$ROOT/scripts/check-ownership.sh") -eq 1 ]]
[[ $(grep -Fxc "$test_line" "$ROOT/scripts/check-ownership.sh") -eq 1 ]]

"$GATE" >/dev/null
cp "$ROOT/public-api.txt" "$TMP/missing-run.txt"
python3 - "$TMP/missing-run.txt" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
marker = "pub fn acl_proxy::run() -> std::process::ExitCode\n"
if text.count(marker) != 1:
    raise SystemExit("expected exactly one root run API marker")
path.write_text(text.replace(marker, "", 1), encoding="utf-8")
PY
ACL_PROXY_PUBLIC_API_BASELINE="$TMP/missing-run.txt" "$GATE" >/dev/null
if "$GATE" --baseline "$TMP/missing-run.txt" >/dev/null 2>&1; then
    printf 'public API gate accepted a snapshot without the root run entry\n' >&2
    exit 1
fi

printf 'product public API snapshot mutation test passed\n'
