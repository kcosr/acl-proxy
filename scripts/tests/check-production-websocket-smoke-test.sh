#!/usr/bin/env bash

set -Eeuo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly GATE="$ROOT_DIR/scripts/check-production-websocket-smoke.sh"
readonly SOURCE="$ROOT_DIR/scripts/production-topology-smoke.sh"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

expect_rejected() {
    local name=$1
    if ! bash -n "$TMP_DIR/$name.sh"; then
        printf 'mutation is not valid shell: %s\n' "$name" >&2
        exit 1
    fi
    if "$GATE" "$TMP_DIR/$name.sh" >"$TMP_DIR/$name.out" 2>&1; then
        printf 'mutation unexpectedly passed: %s\n' "$name" >&2
        exit 1
    fi
}

"$GATE" "$SOURCE"

python3 - "$SOURCE" "$TMP_DIR" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
target = Path(sys.argv[2])
case = "p11_ws_direct_unprotected"
target.joinpath("missing.sh").write_text(source.replace(f"P11_WS_CASE {case} PASS", "removed", 1))
target.joinpath("duplicate.sh").write_text(source.replace(
    f"printf '%s\\n' 'P11_WS_CASE {case} PASS'",
    f"printf '%s\\n' 'P11_WS_CASE {case} PASS'\n    printf '%s\\n' 'P11_WS_CASE {case} PASS'", 1))
target.joinpath("skipped.sh").write_text(source.replace(f"P11_WS_CASE {case} PASS", f"P11_WS_CASE {case} SKIPPED", 1))
target.joinpath("unexpected.sh").write_text(source.replace(f"P11_WS_CASE {case} PASS", "P11_WS_CASE p11_ws_unexpected PASS", 1))
target.joinpath("ordering.sh").write_text(source.replace(
    '    assert_ws_101 "$result"\n    ws_stream_assertions "$result"',
    '    ws_stream_assertions "$result"\n    assert_ws_101 "$result"', 1))
target.joinpath("proof.sh").write_text(source.replace(
    '    assert_ws_field "$result" ASSERT_NO_DETACHED_WORK\n', "", 1))
target.joinpath("uncalled.sh").write_text(source.replace(f"\n{case}\n", "\nremoved_case_invocation\n", 1))
target.joinpath("unscoped-capture.sh").write_text(source.replace(
    "assert_capture_contains /connect '[CAPTURE-OLD]'",
    "assert_capture_contains '[CAPTURE-OLD]'", 1))
target.joinpath("successor-matcher.sh").write_text(source.replace(
    'message(new, b"new-secret", b"[WIRE-NEW]")',
    'message(new, b"old-secret", b"[WIRE-NEW]")', 1))
target.joinpath("direct-message.sh").write_text(source.replace(
    'message(stream, sensitive, sensitive)', 'message(stream, b"direct-message")', 1))
target.joinpath("fragmentation.sh").write_text(source.replace(
    'stream.sendall(masked_frame(0x0, literal[18:], fin=True))', '', 1))
target.joinpath("tls-trust.sh").write_text(source.replace(
    'context = ssl.create_default_context(cafile=ca)',
    'context = ssl._create_unverified_context()', 1))
target.joinpath("parent-spoof.sh").write_text(source.replace(
    '("x-aw-policy-context", "spoofed-client-context")',
    '("x-unused", "removed")', 1))
target.joinpath("parent-authorization.sh").write_text(source.replace(
    'authorization_provider = "gitlab_acl"', '', 1))
target.joinpath("tcp-accept.sh").write_text(source.replace(
    'record("tcp_accept", connection=connection_id,',
    'record("removed_accept", connection=connection_id,', 1))
target.joinpath("admission-quiet.sh").write_text(source.replace(
    'assert_no_origin_accept(event_path, before_second)', '', 1))
target.joinpath("admission-overrelease.sh").write_text(source.replace(
    'rejected_upgrade("/admission-overrelease")', '', 1))
target.joinpath("lifetime-origin.sh").write_text(source.replace(
    'lifetime_elapsed = closed_at - opened_at',
    'lifetime_elapsed = closed_at - reload_at', 1))
target.joinpath("lifetime-reset.sh").write_text(source.replace(
    'assert post_reload_elapsed < 3.7, post_reload_elapsed', '', 1))
target.joinpath("shutdown-order.sh").write_text(source.replace(
    '    (( listener_closed_ns <= client_finished_ns )) \\\n        || fail "WebSocket streams stopped before the data listener closed"',
    '    true # removed listener-first assertion', 1))
target.joinpath("shutdown-relay.sh").write_text(source.replace(
    'assert_origin_events terminal-once:/shutdown-direct terminal-once:/shutdown-connect',
    'true # removed relay join proof', 1))
target.joinpath("shutdown-capture.sh").write_text(source.replace(
    "assert_capture_contains /shutdown-connect 'connect-before-stop'",
    'true # removed capture join proof', 1))
target.joinpath("shutdown-abort.sh").write_text(source.replace(
    '    (( host_status == 0 )) || fail', '    true || fail', 1))
target.joinpath("cleanup-ownership.sh").write_text(source.replace(
    'ip link del "$BRIDGE" 2>/dev/null \\\n            || record_cleanup_failure "could not delete owned bridge $BRIDGE"',
    'true # removed owned bridge deletion', 1))
target.joinpath("cleanup-term.sh").write_text(source.replace(
    'signal_owned_pid TERM "$pid" 2>/dev/null || true',
    'true # removed TERM', 1))
target.joinpath("cleanup-kill.sh").write_text(source.replace(
    'signal_owned_pid KILL "$pid" 2>/dev/null || true', 'true # removed KILL', 1))
target.joinpath("cleanup-pid-identity.sh").write_text(source.replace(
    '[[ -n "$actual" && "$actual" == "$expected" ]]',
    '[[ -n "$actual" ]]', 1))
target.joinpath("cleanup-owned-delete.sh").write_text(source.replace(
    'ip netns del "$namespace" 2>/dev/null \\\n            || record_cleanup_failure "could not delete owned namespace $namespace"',
    'true # ip netns del "$namespace" 2>/dev/null', 1))
target.joinpath("cleanup-status.sh").write_text(source.replace(
    'if (( final_status == 0 && ${#CLEANUP_FAILURES[@]} > 0 )); then',
    'if false; then # if (( final_status == 0 && ${#CLEANUP_FAILURES[@]} > 0 )); then', 1))
target.joinpath("cleanup-namespace-residue.sh").write_text(source.replace(
    'record_cleanup_failure "owned namespace residue remains for $namespace"',
    'true # removed namespace residue failure', 1))
target.joinpath("cleanup-link-residue.sh").write_text(source.replace(
    'record_cleanup_failure "owned link residue remains for $link"',
    'true # removed link residue failure', 1))
target.joinpath("cleanup-rule-residue.sh").write_text(source.replace(
    'record_cleanup_failure "owned FORWARD rule residue remains"',
    'true # removed rule residue failure', 1))
target.joinpath("cleanup-orphan-netns.sh").write_text(source.replace(
    'fail "generated namespace configuration path already exists: /etc/netns/$namespace"',
    'true # ignored orphan netns configuration', 1))
target.joinpath("cleanup-rule-identity.sh").write_text(source.replace(
    '--comment "acl-proxy-p11-$SUFFIX"',
    '--comment "non-unique"', 1))
target.joinpath("cleanup-link-delete.sh").write_text(source.replace(
    'ip link del "$link" 2>/dev/null \\\n                || record_cleanup_failure "could not delete owned link $link"',
    'true # removed owned link deletion', 1))
target.joinpath("cleanup-post-kill-bound.sh").write_text(source.replace(
    'local post_kill_attempts=$attempts',
    'local post_kill_attempts=0', 1))
target.joinpath("assert-field-comment.sh").write_text(source.replace(
    'grep -qx "$field=1" <<<"$result" || fail "WebSocket proof is missing $field"',
    'true # grep -qx "$field=1" <<<"$result" || fail "WebSocket proof is missing $field"', 1))
target.joinpath("parent-headers-comment.sh").write_text(source.replace(
    '        headers-absent:/group/public.git/parent-protected \\\n',
    '        opened-once:/group/public.git/parent-protected \\\n        # headers-absent:/group/public.git/parent-protected \\\n', 1))
target.joinpath("cleanup-temp-delete-comment.sh").write_text(source.replace(
    'rm -rf "$TMP_DIR" || record_cleanup_failure "could not delete temporary directory"',
    'true # rm -rf "$TMP_DIR" || record_cleanup_failure "could not delete temporary directory"', 1))
target.joinpath("cleanup-temp-residue-comment.sh").write_text(source.replace(
    '[[ -e "$TMP_DIR" ]] \\\n            && record_cleanup_failure "temporary directory residue remains"',
    'true # [[ -e "$TMP_DIR" ]] && record_cleanup_failure "temporary directory residue remains"', 1))
target.joinpath("cleanup-netns-dir-comment.sh").write_text(source.replace(
    'rm -rf "/etc/netns/$namespace" \\\n            || record_cleanup_failure "could not delete owned netns configuration $namespace"',
    'true # rm -rf "/etc/netns/$namespace" || record_cleanup_failure "could not delete owned netns configuration $namespace"', 1))
target.joinpath("cleanup-bridge-error-comment.sh").write_text(source.replace(
    'ip link del "$BRIDGE" 2>/dev/null \\\n            || record_cleanup_failure "could not delete owned bridge $BRIDGE"',
    'ip link del "$BRIDGE" 2>/dev/null || true # record_cleanup_failure "could not delete owned bridge $BRIDGE"', 1))
target.joinpath("cleanup-final-status-comment.sh").write_text(source.replace(
    '        final_status=1',
    '        true # final_status=1', 1))
target.joinpath("cleanup-recorder-comment.sh").write_text(source.replace(
    '    CLEANUP_FAILURES+=("$1")',
    '    true # CLEANUP_FAILURES+=("$1")', 1))
target.joinpath("suffix-rand-comment.sh").write_text(source.replace(
    'SUFFIX=$(openssl rand -hex 4) || fail "could not generate network resource suffix"',
    'SUFFIX=deadbeef # SUFFIX=$(openssl rand -hex 4) || fail "could not generate network resource suffix"', 1))
target.joinpath("suffix-validation-comment.sh").write_text(source.replace(
    '[[ "$SUFFIX" =~ ^[0-9a-f]{8}$ ]] || fail "generated network resource suffix is invalid"',
    'true # [[ "$SUFFIX" =~ ^[0-9a-f]{8}$ ]] || fail "generated network resource suffix is invalid"', 1))
target.joinpath("cleanup-term-comment.sh").write_text(source.replace(
    'signal_owned_pid TERM "$pid" 2>/dev/null || true',
    'true # signal_owned_pid TERM "$pid" 2>/dev/null || true', 1))
target.joinpath("cleanup-kill-comment.sh").write_text(source.replace(
    'signal_owned_pid KILL "$pid" 2>/dev/null || true',
    'true # signal_owned_pid KILL "$pid" 2>/dev/null || true', 1))
target.joinpath("inert-term-heredoc.sh").write_text(source.replace(
    'signal_owned_pid TERM "$pid" 2>/dev/null || true',
    'true\n        : <<\'INERT_TERM\'\nsignal_owned_pid TERM "$pid" 2>/dev/null || true\nINERT_TERM', 1))
target.joinpath("inert-kill-quoted.sh").write_text(source.replace(
    'signal_owned_pid KILL "$pid" 2>/dev/null || true',
    'true\n        : \'\nsignal_owned_pid KILL "$pid" 2>/dev/null || true\ninert quoted proof\'', 1))
target.joinpath("inert-assert-field-heredoc.sh").write_text(source.replace(
    'grep -qx "$field=1" <<<"$result" || fail "WebSocket proof is missing $field"',
    'true\n    : <<\'INERT_ASSERT\'\ngrep -qx "$field=1" <<<"$result" || fail "WebSocket proof is missing $field"\nINERT_ASSERT', 1))
suffix_proofs = """SUFFIX=$(openssl rand -hex 4) || fail "could not generate network resource suffix"
[[ "$SUFFIX" =~ ^[0-9a-f]{8}$ ]] || fail "generated network resource suffix is invalid"
readonly SUFFIX"""
target.joinpath("inert-suffix-heredoc.sh").write_text(source.replace(
    suffix_proofs,
    """SUFFIX=deadbeef
: <<'INERT_SUFFIX'
SUFFIX=$(openssl rand -hex 4) || fail "could not generate network resource suffix"
[[ "$SUFFIX" =~ ^[0-9a-f]{8}$ ]] || fail "generated network resource suffix is invalid"
readonly SUFFIX
INERT_SUFFIX""", 1))
target.joinpath("inert-post-kill-heredoc.sh").write_text(source.replace(
    'local post_kill_attempts=$attempts',
    """local post_kill_attempts=0
    : <<'INERT_POST_KILL'
local post_kill_attempts=$attempts
INERT_POST_KILL""", 1))
link_delete = ('ip link del "$link" 2>/dev/null \\\n'
               '                || record_cleanup_failure "could not delete owned link $link"')
target.joinpath("inert-link-delete-heredoc.sh").write_text(source.replace(
    link_delete,
    """true
            : <<'INERT_LINK_DELETE'
ip link del "$link" 2>/dev/null \\
    || record_cleanup_failure "could not delete owned link $link"
INERT_LINK_DELETE""", 1))
forward_delete = ('iptables -D FORWARD "${FORWARD_RULE_ARGS[@]}" 2>/dev/null \\\n'
                  '            || record_cleanup_failure "could not delete the owned FORWARD rule"')
target.joinpath("inert-forward-delete-heredoc.sh").write_text(source.replace(
    forward_delete,
    """true
        : <<'INERT_FORWARD_DELETE'
iptables -D FORWARD "${FORWARD_RULE_ARGS[@]}" 2>/dev/null \\
    || record_cleanup_failure "could not delete the owned FORWARD rule"
INERT_FORWARD_DELETE""", 1))
inert_all = source.replace(
    'signal_owned_pid TERM "$pid" 2>/dev/null || true', 'true', 1).replace(
    'signal_owned_pid KILL "$pid" 2>/dev/null || true', 'true', 1).replace(
    'local post_kill_attempts=$attempts', 'local post_kill_attempts=0', 1).replace(
    suffix_proofs, 'SUFFIX=deadbeef\nreadonly SUFFIX', 1)
inert_all += """
: <<'INERT_ALL_SHELL_PROOFS'
signal_owned_pid TERM "$pid" 2>/dev/null || true
signal_owned_pid KILL "$pid" 2>/dev/null || true
local post_kill_attempts=$attempts
SUFFIX=$(openssl rand -hex 4) || fail "could not generate network resource suffix"
[[ "$SUFFIX" =~ ^[0-9a-f]{8}$ ]] || fail "generated network resource suffix is invalid"
readonly SUFFIX
ip link del "$link" 2>/dev/null
iptables -D FORWARD "${FORWARD_RULE_ARGS[@]}" 2>/dev/null
INERT_ALL_SHELL_PROOFS
"""
target.joinpath("inert-all-shell-proofs.sh").write_text(inert_all)
target.joinpath("inert-python-proof-string.sh").write_text(source.replace(
    'message(stream, sensitive, sensitive)',
    '\"\"\"message(stream, sensitive, sensitive)\"\"\"', 1))
target.joinpath("inert-python-proof-assignment.sh").write_text(source.replace(
    'message(stream, sensitive, sensitive)',
    'inert_proof = \"message(stream, sensitive, sensitive)\"', 1))
duplicate_case = '''
p11_ws_direct_unprotected() {
    printf '%s\\n' 'P11_WS_CASE p11_ws_direct_unprotected PASS'
}
'''
target.joinpath("duplicate-later-case-function.sh").write_text(source.replace(
    '\np11_ws_direct_unprotected\n',
    duplicate_case + '\np11_ws_direct_unprotected\n', 1))
target.joinpath("case-early-return.sh").write_text(source.replace(
    'p11_ws_direct_unprotected() {\n    local result',
    'p11_ws_direct_unprotected() {\n    return 0\n    local result', 1))
target.joinpath("same-line-quoted-noop.sh").write_text(source.replace(
    'assert_ws_field "$result" ASSERT_NO_DETACHED_WORK',
    ': \'assert_ws_field "$result" ASSERT_NO_DETACHED_WORK\'', 1))
target.joinpath("python-if-false-proof.sh").write_text(source.replace(
    '    message(stream, sensitive, sensitive)',
    '    if False:\n        message(stream, sensitive, sensitive)', 1))
host_anchor = '''python3 - "$TMP_DIR/host/acl-proxy.toml" <<'PY'
from pathlib import Path
import sys
'''
target.joinpath("config-inert-assignment.sh").write_text(source.replace(
    'authorization_provider = "gitlab_acl"',
    'removed_provider = "gitlab_acl"', 1).replace(
    host_anchor,
    host_anchor + '_ = \'authorization_provider = "gitlab_acl"\'\n', 1))
target.joinpath("cleanup-if-false.sh").write_text(source.replace(
    forward_delete,
    """if false; then
            iptables -D FORWARD "${FORWARD_RULE_ARGS[@]}" 2>/dev/null \\
                || record_cleanup_failure "could not delete the owned FORWARD rule"
        fi""", 1))
target.joinpath("pidfd-open-removed.sh").write_text(source.replace(
    'pidfd = os.pidfd_open(pid)', 'pidfd = pid', 1))
target.joinpath("pidfd-identity-removed.sh").write_text(source.replace(
    'if fields_after_comm[19] != expected_start_time or fields_after_comm[0] == "Z":',
    'if False:', 1))
PY

for mutation in missing duplicate skipped unexpected ordering proof uncalled \
    unscoped-capture successor-matcher direct-message fragmentation tls-trust \
    parent-spoof parent-authorization tcp-accept admission-quiet \
    admission-overrelease lifetime-origin lifetime-reset shutdown-order \
    shutdown-relay shutdown-capture shutdown-abort cleanup-ownership \
    cleanup-term cleanup-kill cleanup-pid-identity cleanup-owned-delete \
    cleanup-status cleanup-namespace-residue cleanup-link-residue \
    cleanup-rule-residue cleanup-orphan-netns cleanup-rule-identity \
    cleanup-link-delete cleanup-post-kill-bound assert-field-comment \
    parent-headers-comment cleanup-temp-delete-comment \
    cleanup-temp-residue-comment cleanup-netns-dir-comment \
    cleanup-bridge-error-comment cleanup-final-status-comment \
    cleanup-recorder-comment suffix-rand-comment suffix-validation-comment \
    cleanup-term-comment cleanup-kill-comment inert-term-heredoc \
    inert-kill-quoted inert-assert-field-heredoc inert-suffix-heredoc \
    inert-post-kill-heredoc inert-link-delete-heredoc \
    inert-forward-delete-heredoc inert-all-shell-proofs \
    inert-python-proof-string inert-python-proof-assignment \
    duplicate-later-case-function case-early-return same-line-quoted-noop \
    python-if-false-proof config-inert-assignment cleanup-if-false \
    pidfd-open-removed pidfd-identity-removed; do
    expect_rejected "$mutation"
done

printf '%s\n' 'production WebSocket smoke gate mutation test passed'
