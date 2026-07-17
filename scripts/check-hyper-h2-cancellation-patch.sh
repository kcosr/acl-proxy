#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
VENDOR="$ROOT/third_party/hyper"
EXPECTED_UPSTREAM_TREE=a4209cbb6edbb87334988f1a93916760815cc7d19a50ec704f936ecefaf19751
EXPECTED_PATCHED_SERVER=d4df9c076c7bcae71e54472d018471399891585ea4381450793a64d5aeb826e7

fail() {
    printf 'Hyper H2 cancellation patch ownership violation: %s\n' "$1" >&2
    exit 1
}

[[ -f "$VENDOR/ACL_PROXY_PATCH.md" ]] || fail 'missing patch provenance'
[[ -f "$VENDOR/src/proto/h2/server.rs" ]] || fail 'missing patched server owner'

python3 - "$ROOT" <<'PY' || exit 1
import pathlib
import re
import sys
import tomllib

root = pathlib.Path(sys.argv[1])


def fail(message: str) -> None:
    print(f"Hyper H2 cancellation patch ownership violation: {message}", file=sys.stderr)
    raise SystemExit(1)


cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
patch = cargo.get("patch", {}).get("crates-io", {}).get("hyper")
if patch != {"path": "third_party/hyper"}:
    fail("Cargo must select only the repository-owned Hyper patch")

vendor_cargo = tomllib.loads(
    (root / "third_party/hyper/Cargo.toml").read_text(encoding="utf-8")
)
if vendor_cargo.get("package", {}).get("name") != "hyper" or vendor_cargo.get("package", {}).get("version") != "0.14.32":
    fail("vendored crate must be exactly Hyper 0.14.32")

lock = (root / "Cargo.lock").read_text(encoding="utf-8")
locked = re.findall(r'\[\[package\]\]\s+name = "hyper"\s+version = "([^"]+)"(.*?)(?=\n\[\[package\]\]|\Z)', lock, re.S)
if len(locked) != 1 or locked[0][0] != "0.14.32":
    fail("Cargo.lock must resolve exactly one Hyper 0.14.32")
if re.search(r'^source\s*=|^checksum\s*=', locked[0][1], re.M):
    fail("the locked Hyper package must resolve through the path patch")

note = (root / "third_party/hyper/ACL_PROXY_PATCH.md").read_text(encoding="utf-8")
for required in ("Hyper 0.14.32", "src/proto/h2/server.rs", "finished", "RST_STREAM(CANCEL)"):
    if required not in note:
        fail(f"patch provenance must document {required}")

server = (root / "third_party/hyper/src/proto/h2/server.rs").read_text(encoding="utf-8")
checks = (
    (r"pub\s+struct\s+H2Stream<.*?finished\s*:\s*bool", "H2Stream must own a pinned finished bit"),
    (r"impl<[^>]+>\s+PinnedDrop\s+for\s+H2Stream.*?if\s+!\s*\*me\.finished\s*\{\s*me\.reply\.send_reset\(Reason::CANCEL\);\s*\}", "pinned drop must cancel only unfinished streams"),
    (r"H2Stream\s*\{.*?finished\s*:\s*false", "new streams must begin unfinished"),
    (r"if\s+result\.is_ready\(\)\s*\{\s*\*self\.as_mut\(\)\.project\(\)\.finished\s*=\s*true;\s*\}", "ready streams must be marked finished before future drop"),
)
for pattern, message in checks:
    if re.search(pattern, server, re.S) is None:
        fail(message)
PY

actual_upstream_tree=$(
    cd "$VENDOR"
    find . -type f \
        ! -path './src/proto/h2/server.rs' \
        ! -path './ACL_PROXY_PATCH.md' \
        -print0 \
        | sort -z \
        | while IFS= read -r -d '' file; do
            printf '%s  %s\n' "$(sha256sum "$file" | cut -d' ' -f1)" "$file"
        done \
        | sha256sum \
        | cut -d' ' -f1
)
[[ $actual_upstream_tree == "$EXPECTED_UPSTREAM_TREE" ]] \
    || fail 'vendored tree differs from the upstream 0.14.32 crate outside the two documented exceptions'

actual_server=$(sha256sum "$VENDOR/src/proto/h2/server.rs" | cut -d' ' -f1)
[[ $actual_server == "$EXPECTED_PATCHED_SERVER" ]] \
    || fail 'patched server.rs differs from the reviewed pinned-drop implementation'

printf 'Hyper 0.14.32 H2 cancellation patch ownership gate passed\n'
