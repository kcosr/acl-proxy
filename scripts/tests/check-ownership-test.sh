#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SOURCE="$ROOT/scripts/check-ownership.sh"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/acl-proxy-ownership.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

FIXTURE="$TMP/repository"
LOG="$TMP/invocations.log"
mkdir -p "$FIXTURE/scripts/tests"
cp "$SOURCE" "$FIXTURE/scripts/check-ownership.sh"
chmod +x "$FIXTURE/scripts/check-ownership.sh"

mapfile -t commands < <(
    sed -nE 's/^[[:space:]]+(scripts\/[A-Za-z0-9._\/-]+)$/\1/p' "$SOURCE"
)
[[ ${#commands[@]} -gt 2 ]]
[[ $(printf '%s\n' "${commands[@]}" | LC_ALL=C sort -u | wc -l) -eq ${#commands[@]} ]]

for command in "${commands[@]}"; do
    path="$FIXTURE/$command"
    mkdir -p "$(dirname -- "$path")"
    cat >"$path" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$0" >>"${OWNERSHIP_TEST_LOG:?}"
if (( $# != 0 )); then
    printf '\t%s' "$@" >>"$OWNERSHIP_TEST_LOG"
fi
printf '\n' >>"$OWNERSHIP_TEST_LOG"
EOF
    chmod +x "$path"
done

expected_invocations() {
    local runtime_tree=${1:-}
    local command
    for command in "${commands[@]}"; do
        printf '%s' "$command"
        if [[ -n $runtime_tree && ( $command == scripts/check-packaging-policy.sh \
            || $command == scripts/tests/check-packaging-policy-test.sh ) ]]; then
            printf '\t--runtime-source-tree\t%s' "$runtime_tree"
        fi
        printf '\n'
    done
}

assert_invocations() {
    local runtime_tree=${1:-}
    : >"$LOG"
    if [[ -n $runtime_tree ]]; then
        (
            cd "$FIXTURE"
            OWNERSHIP_TEST_LOG="$LOG" \
                scripts/check-ownership.sh --runtime-source-tree "$runtime_tree"
        ) >/dev/null
    else
        (
            cd "$FIXTURE"
            OWNERSHIP_TEST_LOG="$LOG" scripts/check-ownership.sh
        ) >/dev/null
    fi
    expected_invocations "$runtime_tree" >"$TMP/expected.log"
    cmp "$TMP/expected.log" "$LOG"
}

assert_usage_rejected() {
    set +e
    (
        cd "$FIXTURE"
        OWNERSHIP_TEST_LOG="$LOG" scripts/check-ownership.sh "$@"
    ) >"$TMP/invalid.out" 2>&1
    status=$?
    set -e
    if (( status == 0 )); then
        printf 'invalid aggregate ownership invocation passed: %s\n' "$*" >&2
        exit 1
    fi
    [[ $status -eq 2 ]]
    grep -Fq 'usage:' "$TMP/invalid.out"
}

tree=0123456789abcdef0123456789abcdef01234567
assert_invocations
assert_invocations "$tree"
assert_usage_rejected --runtime-source-tree
assert_usage_rejected --runtime-tree "$tree"
assert_usage_rejected --runtime-source-tree not-a-tree
assert_usage_rejected --runtime-source-tree "$tree" extra

printf 'aggregate ownership argument and forwarding tests passed\n'
