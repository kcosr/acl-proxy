#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/hyper-h2-patch-test.XXXXXX")
cleanup() { rm -rf -- "$TEST_ROOT"; }
trap cleanup EXIT INT TERM

BASELINE="$TEST_ROOT/baseline"
mkdir -p "$BASELINE/scripts" "$BASELINE/third_party"
cp "$SOURCE_ROOT/scripts/check-hyper-h2-cancellation-patch.sh" "$BASELINE/scripts/"
cp "$SOURCE_ROOT/Cargo.toml" "$SOURCE_ROOT/Cargo.lock" "$BASELINE/"
cp -R "$SOURCE_ROOT/third_party/hyper" "$BASELINE/third_party/"

runner() { "$1/scripts/check-hyper-h2-cancellation-patch.sh"; }
runner "$BASELINE" >"$TEST_ROOT/pass.log"
grep -Fq 'Hyper 0.14.32 H2 cancellation patch ownership gate passed' "$TEST_ROOT/pass.log"

expect_failure() {
    local root=$1
    local description=$2
    if runner "$root" >"$TEST_ROOT/failure.log" 2>&1; then
        printf '%s was accepted\n' "$description" >&2
        exit 1
    fi
    grep -Fq 'Hyper H2 cancellation patch ownership violation:' "$TEST_ROOT/failure.log"
}

mutations=0
new_case() {
    mutations=$((mutations + 1))
    CASE_ROOT="$TEST_ROOT/case-$mutations"
    cp -R "$BASELINE" "$CASE_ROOT"
}

new_case
sed -i '/^\[patch.crates-io\]/,+1d' "$CASE_ROOT/Cargo.toml"
expect_failure "$CASE_ROOT" 'removed Cargo patch'

new_case
sed -i '0,/version = "0.14.32"/s//version = "0.14.31"/' \
    "$CASE_ROOT/third_party/hyper/Cargo.toml"
expect_failure "$CASE_ROOT" 'changed vendored Hyper version'

new_case
printf '\nmutation\n' >>"$CASE_ROOT/third_party/hyper/README.md"
expect_failure "$CASE_ROOT" 'changed upstream source outside patch owner'

new_case
printf 'extra\n' >"$CASE_ROOT/third_party/hyper/EXTRA"
expect_failure "$CASE_ROOT" 'added unreviewed vendor file'

new_case
sed -i 's/finished: bool,/finished_state: bool,/' \
    "$CASE_ROOT/third_party/hyper/src/proto/h2/server.rs"
expect_failure "$CASE_ROOT" 'removed exact finished bit'

new_case
sed -i 's/if !\*me.finished {/if *me.finished {/' \
    "$CASE_ROOT/third_party/hyper/src/proto/h2/server.rs"
expect_failure "$CASE_ROOT" 'cancelled finished streams'

new_case
sed -i '0,/finished: false,/s//finished: true,/' \
    "$CASE_ROOT/third_party/hyper/src/proto/h2/server.rs"
expect_failure "$CASE_ROOT" 'created a stream already finished'

new_case
sed -i 's/project().finished = true/project().finished = false/' \
    "$CASE_ROOT/third_party/hyper/src/proto/h2/server.rs"
expect_failure "$CASE_ROOT" 'failed to mark ready stream finished'

new_case
sed -i '0,/send_reset(Reason::CANCEL)/s//send_reset(Reason::INTERNAL_ERROR)/' \
    "$CASE_ROOT/third_party/hyper/src/proto/h2/server.rs"
expect_failure "$CASE_ROOT" 'changed unfinished reset reason'

printf 'Hyper H2 cancellation patch mutation tests passed (%d mutations)\n' "$mutations"
