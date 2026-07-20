#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
RUNTIME_ROOT="$ROOT/../access-runtime"
cd "$ROOT"

if [[ -e src/url.rs ]]; then
    printf 'src/url.rs must remain deleted; URL semantics belong to http-access-url\n' >&2
    exit 1
fi

cargo run --quiet --locked \
    --manifest-path "$RUNTIME_ROOT/Cargo.toml" \
    -p pipeline-ownership-check -- fact-product "$ROOT"

if [[ -e src/proxy/raw_h2_conformance.rs ]]; then
    printf 'the product raw HTTP/2 conformance adapter must remain deleted\n' >&2
    exit 1
fi
shared_raw_h2="$RUNTIME_ROOT/crates/http-access-runtime/src/raw_h2_conformance.rs"
if [[ ! -f "$shared_raw_h2" ]]; then
    printf 'the shared raw HTTP/2 conformance owner is missing\n' >&2
    exit 1
fi
for case_id in \
    raw_h2_suite_matches_the_decoded_product_boundary \
    accepted_fields_body_and_trailers_survive_fact_materialization; do
    if [[ $(rg -c "fn ${case_id}\\(" "$shared_raw_h2") != 1 ]]; then
        printf 'the shared raw HTTP/2 conformance owner is missing %s\n' "$case_id" >&2
        exit 1
    fi
done

metadata=$(cargo metadata --format-version 1 --no-deps)
python3 - "$ROOT" "$metadata" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
metadata = json.loads(sys.argv[2])
package = next(package for package in metadata["packages"] if package["name"] == "acl-proxy")
dependencies = {dependency["name"]: dependency for dependency in package["dependencies"]}

for name in ("idna", "memchr", "url"):
    if name in dependencies:
        raise SystemExit(
            f"{name} must not be a direct dependency; URL semantics belong to http-access-url"
        )

expected = {
    "http-access-types": (None, root.parent / "access-runtime" / "crates" / "http-access-types"),
    "http-access-url": (None, root.parent / "access-runtime" / "crates" / "http-access-url"),
    "http-access-conformance": ("dev", root.parent / "access-runtime" / "crates" / "http-access-conformance"),
    "http-access-policy-acl": (None, root.parent / "access-runtime" / "crates" / "http-access-policy-acl"),
}
for name, (kind, path) in expected.items():
    dependency = dependencies.get(name)
    if dependency is None:
        raise SystemExit(f"missing dependency {name}")
    if dependency["kind"] != kind:
        raise SystemExit(f"{name} has kind {dependency['kind']!r}, expected {kind!r}")
    if dependency["req"] != "=0.1.0":
        raise SystemExit(f"{name} must use exact version =0.1.0")
    if pathlib.Path(dependency["path"]).resolve() != path.resolve():
        raise SystemExit(f"{name} must use the exact sibling path {path}")
PY

printf 'shared URL and request-facts ownership/dependency gate passed\n'
