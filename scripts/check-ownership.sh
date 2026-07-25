#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

runtime_source_tree=
if (( $# != 0 )); then
    if (( $# != 2 )) || [[ $1 != --runtime-source-tree ]] \
        || [[ ! $2 =~ ^[0-9a-f]{40}$ ]]; then
        printf 'usage: %s [--runtime-source-tree <40-hex-git-tree>]\n' "$0" >&2
        exit 2
    fi
    runtime_source_tree=$2
fi

ownership_gates=(
    scripts/check-packaging-policy.sh
    scripts/check-public-api.sh
    scripts/check-shared-url-ownership.sh
    scripts/check-shared-acl-ownership.sh
    # Supersedes the deleted standalone, forwarding, product-inventory, and
    # product-header gates after their owners moved behind the shared listener.
    scripts/check-c05-shared-listener-ownership.sh
    scripts/check-c06-tls-dependencies.py
    scripts/check-shared-redaction-ownership.sh
    scripts/check-shared-credential-ownership.sh
    scripts/check-smoke-config-schema.py
    scripts/check-production-websocket-smoke.sh
    scripts/check-awap-fixtures.py
    scripts/check-transport-oracles.py
)
mutation_suites=(
    scripts/tests/check-packaging-policy-test.sh
    scripts/tests/check-public-api-test.sh
    scripts/tests/check-shared-url-ownership-test.sh
    scripts/tests/check-shared-acl-ownership-test.sh
    scripts/tests/check-c05-shared-listener-ownership-test.sh
    scripts/tests/check-c06-tls-dependencies-test.sh
    scripts/tests/check-shared-redaction-ownership-test.sh
    scripts/tests/check-shared-credential-ownership-test.sh
    scripts/tests/check-smoke-config-schema-test.sh
    scripts/tests/check-production-websocket-smoke-test.sh
    scripts/tests/check-awap-fixtures-test.py
    scripts/tests/check-transport-oracles-test.py
)

for gate in "${ownership_gates[@]}"; do
    if [[ $gate == scripts/check-packaging-policy.sh ]]; then
        if [[ -n $runtime_source_tree ]]; then
            "$gate" --runtime-source-tree "$runtime_source_tree"
        else
            "$gate"
        fi
    else
        "$gate"
    fi
done
for suite in "${mutation_suites[@]}"; do
    "$suite"
done

printf 'all product ownership/deletion gates and mutation suites passed\n'
