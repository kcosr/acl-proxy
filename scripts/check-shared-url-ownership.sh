#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if [[ -e src/url.rs ]]; then
    printf 'src/url.rs must remain deleted; URL semantics belong to http-access-url\n' >&2
    exit 1
fi

if rg -n '(^|[[:space:]])mod url;|crate::url' src; then
    printf 'the product URL module must not be restored\n' >&2
    exit 1
fi

if rg -n '^[[:space:]]*(pub([^[:space:]]*)?[[:space:]]+)?(struct|enum)[[:space:]]+(CanonicalUrl|CanonicalAuthority|UrlError|CompiledUrlPattern)\b|^[[:space:]]*(pub([^[:space:]]*)?[[:space:]]+)?fn[[:space:]]+canonicalize_http_' src; then
    printf 'product-owned URL definitions are forbidden\n' >&2
    exit 1
fi

for source in src/policy/*.rs src/standalone_policy_provider.rs; do
    # Inline test-only helpers can appear before the production implementation.
    # Scan through those helpers and stop only at the final inline test module.
    if sed '/^mod tests {$/,$d' "$source" | rg -n 'canonicalize_http_'; then
        printf '%s: production policy and decision code must not re-normalize\n' "$source" >&2
        exit 1
    fi
done

while IFS= read -r source; do
    [[ $source == src/proxy/facts.rs ]] && continue
    if sed '/^mod tests {$/,$d' "$source" | rg -n 'InterceptedRequestFacts::new|neutral_headers\('; then
        printf '%s: production request facts must use the credential-safe ingress funnel\n' "$source" >&2
        exit 1
    fi
done < <(rg -l 'InterceptedRequestFacts::new|neutral_headers\(' src --glob '*.rs')

if [[ $(sed -n '1p' src/proxy/raw_h2_conformance.rs) != '#![cfg(test)]' ]]; then
    printf 'the raw HTTP/2 conformance adapter must remain test-only\n' >&2
    exit 1
fi

mapfile -t fact_materializers < <(
    rg -n '\binto_facts\b' src \
        --glob '*.rs' \
        --glob '!src/proxy/facts.rs' \
        --glob '!src/proxy/raw_h2_conformance.rs'
)
if [[ ${#fact_materializers[@]} -ne 1 ]] \
    || [[ ${fact_materializers[0]} != src/standalone_policy_provider.rs:*'let facts = shape.into_facts(&headers)?;' ]]; then
    printf 'request facts must be materialized exactly once, after typed credential extraction\n' >&2
    printf '%s\n' "${fact_materializers[@]}" >&2
    exit 1
fi

metadata=$(cargo metadata --format-version 1 --no-deps)
python3 - "$ROOT" "$metadata" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
metadata = json.loads(sys.argv[2])
package = next(package for package in metadata["packages"] if package["name"] == "acl-proxy")
dependencies = {dependency["name"]: dependency for dependency in package["dependencies"]}

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
