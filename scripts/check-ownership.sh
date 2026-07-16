#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

ownership_gates=(
    scripts/check-shared-url-ownership.sh
    scripts/check-shared-acl-ownership.sh
    scripts/check-standalone-policy-ownership.sh
    scripts/check-forwarding-executor-ownership.sh
    scripts/check-shared-redaction-ownership.sh
    scripts/check-shared-credential-ownership.sh
    scripts/check-shared-header-ownership.sh
)
mutation_suites=(
    scripts/tests/check-shared-url-ownership-test.sh
    scripts/tests/check-shared-acl-ownership-test.sh
    scripts/tests/check-standalone-policy-ownership-test.sh
    scripts/tests/check-forwarding-executor-ownership-test.sh
    scripts/tests/check-shared-redaction-ownership-test.sh
    scripts/tests/check-shared-credential-ownership-test.sh
    scripts/tests/check-shared-header-ownership-test.sh
)

for gate in "${ownership_gates[@]}"; do
    "$gate"
done
for suite in "${mutation_suites[@]}"; do
    "$suite"
done

printf 'all product ownership/deletion gates and mutation suites passed\n'
