#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

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
    scripts/tests/check-transport-oracles-test.py
)

for gate in "${ownership_gates[@]}"; do
    "$gate"
done
for suite in "${mutation_suites[@]}"; do
    "$suite"
done

printf 'all product ownership/deletion gates and mutation suites passed\n'
