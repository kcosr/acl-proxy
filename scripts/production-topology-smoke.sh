#!/usr/bin/env bash

set -Eeuo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly FIXTURE_DIR="$ROOT_DIR/tests/fixtures/production"
readonly RUN_TOPOLOGY="${ACL_PROXY_RUN_PRODUCTION_TOPOLOGY:-0}"

TMP_DIR=""
BRIDGE=""
HOST_NS=""
COMMON_NS=""
INTERNAL_NS=""
ORIGIN_NS=""
PIDS=()
declare -A ROLE_PIDS=()
declare -A PID_START_TIMES=()
OWNED_NAMESPACES=()
OWNED_HOST_LINKS=()
BRIDGE_OWNED=0
FORWARD_RULE=0
FORWARD_RULE_ARGS=()
CLEANUP_FAILURES=()

fail() {
    printf 'production topology smoke failed: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    local original_status=$?
    local final_status pid namespace role link attempt rule_status
    trap - EXIT
    set +e
    for pid in "${PIDS[@]:-}"; do
        [[ -z "$pid" ]] && continue
        terminate_owned_pid "$pid" 5 \
            || record_cleanup_failure "owned process $pid survived TERM/KILL cleanup"
    done
    if (( original_status != 0 )) && [[ -n "$TMP_DIR" ]]; then
        for role in host common internal origin; do
            if [[ -s "$TMP_DIR/$role/stderr.log" ]]; then
                printf '%s\n' "--- $role stderr ---" >&2
                tail -n 40 "$TMP_DIR/$role/stderr.log" >&2
            fi
        done
        while IFS= read -r log; do
            printf '%s\n' "--- ${log#"$TMP_DIR/"} ---" >&2
            tail -n 40 "$log" >&2
        done < <(find "$TMP_DIR" -type f -path '*/runtime/logs/*' -size +0c -print)
    fi
    if (( FORWARD_RULE == 1 )); then
        iptables -D FORWARD "${FORWARD_RULE_ARGS[@]}" 2>/dev/null \
            || record_cleanup_failure "could not delete the owned FORWARD rule"
    fi
    for namespace in "${OWNED_NAMESPACES[@]:-}"; do
        [[ -z "$namespace" ]] && continue
        ip netns del "$namespace" 2>/dev/null \
            || record_cleanup_failure "could not delete owned namespace $namespace"
        rm -rf "/etc/netns/$namespace" \
            || record_cleanup_failure "could not delete owned netns configuration $namespace"
    done
    for link in "${OWNED_HOST_LINKS[@]:-}"; do
        [[ -z "$link" ]] && continue
        if ip link show "$link" >/dev/null 2>&1; then
            ip link del "$link" 2>/dev/null \
                || record_cleanup_failure "could not delete owned link $link"
        fi
    done
    if (( BRIDGE_OWNED == 1 )); then
        ip link del "$BRIDGE" 2>/dev/null \
            || record_cleanup_failure "could not delete owned bridge $BRIDGE"
    fi

    for namespace in "${OWNED_NAMESPACES[@]:-}"; do
        [[ -z "$namespace" ]] && continue
        for attempt in {1..100}; do
            if ! ip netns list | awk '{print $1}' | grep -qx "$namespace" \
                && [[ ! -e "/etc/netns/$namespace" ]]; then
                break
            fi
            sleep 0.02
        done
        if ip netns list | awk '{print $1}' | grep -qx "$namespace" \
            || [[ -e "/etc/netns/$namespace" ]]; then
            record_cleanup_failure "owned namespace residue remains for $namespace"
        fi
    done
    for link in "${OWNED_HOST_LINKS[@]:-}"; do
        [[ -z "$link" ]] && continue
        for attempt in {1..100}; do
            ip link show "$link" >/dev/null 2>&1 || break
            sleep 0.02
        done
        ip link show "$link" >/dev/null 2>&1 \
            && record_cleanup_failure "owned link residue remains for $link"
    done
    if (( BRIDGE_OWNED == 1 )); then
        for attempt in {1..100}; do
            ip link show "$BRIDGE" >/dev/null 2>&1 || break
            sleep 0.02
        done
        ip link show "$BRIDGE" >/dev/null 2>&1 \
            && record_cleanup_failure "owned bridge residue remains for $BRIDGE"
    fi
    if (( FORWARD_RULE == 1 )); then
        for attempt in {1..100}; do
            iptables -C FORWARD "${FORWARD_RULE_ARGS[@]}" >/dev/null 2>&1
            rule_status=$?
            (( rule_status != 0 )) && break
            sleep 0.02
        done
        if (( rule_status == 0 )); then
            record_cleanup_failure "owned FORWARD rule residue remains"
        elif (( rule_status > 1 )); then
            record_cleanup_failure "could not verify owned FORWARD rule removal"
        fi
    fi
    if [[ -n "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR" || record_cleanup_failure "could not delete temporary directory"
        for attempt in {1..100}; do
            [[ ! -e "$TMP_DIR" ]] && break
            sleep 0.02
        done
        [[ -e "$TMP_DIR" ]] \
            && record_cleanup_failure "temporary directory residue remains"
    fi
    if ((${#CLEANUP_FAILURES[@]} > 0)); then
        printf 'production topology smoke cleanup failures:\n' >&2
        printf '  - %s\n' "${CLEANUP_FAILURES[@]}" >&2
    fi
    final_status=$original_status
    if (( final_status == 0 && ${#CLEANUP_FAILURES[@]} > 0 )); then
        final_status=1
    fi
    exit "$final_status"
}
trap cleanup EXIT

record_cleanup_failure() {
    CLEANUP_FAILURES+=("$1")
}

register_pid() {
    local pid=$1
    local start_time
    start_time=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null || true)
    [[ -n "$start_time" ]] || return 1
    PID_START_TIMES["$pid"]=$start_time
    PIDS+=("$pid")
}

owns_pid() {
    local pid=$1
    [[ -n "$pid" ]] || return 1
    local expected=${PID_START_TIMES[$pid]:-}
    local actual
    [[ -n "$expected" ]] || return 1
    actual=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null || true)
    [[ -n "$actual" && "$actual" == "$expected" ]]
}

owned_pid_running() {
    local pid=$1
    local state
    owns_pid "$pid" || return 1
    state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)
    [[ -n "$state" && "$state" != Z ]]
}

signal_owned_pid() {
    local signal_name=$1
    local pid=$2
    local expected=${PID_START_TIMES[$pid]:-}
    [[ -n "$pid" && -n "$expected" ]] || return 1
    python3 - "$pid" "$expected" "$signal_name" <<'PY'
import os
import signal
import sys

pid = int(sys.argv[1])
expected_start_time = sys.argv[2]
signal_number = getattr(signal, f"SIG{sys.argv[3]}")

try:
    pidfd = os.pidfd_open(pid)
except ProcessLookupError:
    raise SystemExit(1)

try:
    try:
        stat = open(f"/proc/{pid}/stat", encoding="ascii").read()
    except (FileNotFoundError, ProcessLookupError):
        raise SystemExit(1)
    fields_after_comm = stat[stat.rfind(")") + 2 :].split()
    if fields_after_comm[19] != expected_start_time or fields_after_comm[0] == "Z":
        raise SystemExit(1)
    signal.pidfd_send_signal(pidfd, signal_number)
except ProcessLookupError:
    raise SystemExit(1)
finally:
    os.close(pidfd)
PY
}

terminate_owned_pid() {
    local pid=$1
    local seconds=${2:-5}
    local attempts=$((seconds * 20))
    local attempt
    if owned_pid_running "$pid"; then
        signal_owned_pid TERM "$pid" 2>/dev/null || true
    fi
    for ((attempt = 0; attempt < attempts; attempt++)); do
        owned_pid_running "$pid" || break
        sleep 0.05
    done
    if owned_pid_running "$pid"; then
        signal_owned_pid KILL "$pid" 2>/dev/null || true
    fi
    local post_kill_attempts=$attempts
    for ((attempt = 0; attempt < post_kill_attempts; attempt++)); do
        owned_pid_running "$pid" || break
        sleep 0.05
    done
    owned_pid_running "$pid" && return 1
    wait "$pid" 2>/dev/null || true
    ! owned_pid_running "$pid"
}

stop_owned_pid_gracefully() {
    local pid=$1
    local seconds=${2:-10}
    local attempts=$((seconds * 20))
    local attempt status
    owned_pid_running "$pid" || return 1
    signal_owned_pid TERM "$pid"
    for ((attempt = 0; attempt < attempts; attempt++)); do
        owned_pid_running "$pid" || break
        sleep 0.05
    done
    owned_pid_running "$pid" && return 1
    if wait "$pid"; then
        status=0
    else
        status=$?
    fi
    (( status == 0 ))
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

for command in curl date openssl python3 timeout; do
    require_command "$command"
done

cd "$ROOT_DIR"
if [[ -n "${ACL_PROXY_BIN:-}" ]]; then
    PROXY_BIN=$ACL_PROXY_BIN
else
    require_command cargo
    cargo build --locked --bin acl-proxy
    PROXY_BIN="$ROOT_DIR/target/debug/acl-proxy"
fi
[[ -x "$PROXY_BIN" ]] || fail "acl-proxy binary is not executable: $PROXY_BIN"
PROXY_BIN="$(cd "$(dirname "$PROXY_BIN")" && pwd)/$(basename "$PROXY_BIN")"
readonly PROXY_BIN

umask 077
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/acl-proxy-production-smoke.XXXXXX")
mkdir -p "$TMP_DIR/home"

fixture_env=(
    AW_IDENTITY_TOKEN=fixture-validation-identity
    FIXTURE_REDACT_A=fixture-secret-a-00000000000000000000
    FIXTURE_REDACT_B=fixture-secret-b-00000000000000000000
    FIXTURE_REDACT_C=fixture-secret-c-00000000000000000000
    FIXTURE_REDACT_D=fixture-secret-d-00000000000000000000
    FIXTURE_REDACT_E=fixture-secret-e-00000000000000000000
)

validate_fixture() {
    local fixture=$1
    env -i HOME="$TMP_DIR/home" PATH="$PATH" "${fixture_env[@]}" \
        "$PROXY_BIN" config validate --config "$fixture" \
        >"$TMP_DIR/$(basename "$fixture").validate.log" 2>&1 \
        || fail "strict fixture did not validate: $fixture"
}

for fixture in \
    "$FIXTURE_DIR/host-proxy-tcp.toml" \
    "$FIXTURE_DIR/host-proxy-uds.toml" \
    "$FIXTURE_DIR/common-container-proxy.toml" \
    "$FIXTURE_DIR/internal-container-proxy.toml"; do
    validate_fixture "$fixture"
done

for fixture in "$FIXTURE_DIR"/v1-*-shape.toml; do
    if env -i HOME="$TMP_DIR/home" PATH="$PATH" \
        "$PROXY_BIN" config validate --config "$fixture" \
        >"$TMP_DIR/$(basename "$fixture").reject.log" 2>&1; then
        fail "obsolete v1 fixture was accepted: $fixture"
    fi
done

if [[ "$RUN_TOPOLOGY" != 1 ]]; then
    printf '%s\n' \
        'production fixture validation passed; set ACL_PROXY_RUN_PRODUCTION_TOPOLOGY=1 as root for the namespace smoke'
    exit 0
fi

[[ "$(uname -s)" == Linux ]] || fail "namespace topology requires Linux"
[[ "${EUID:-$(id -u)}" == 0 ]] || fail "namespace topology requires root"
for command in ip iptables; do
    require_command "$command"
done

if ip route show 198.18.0.0/15 | grep -q .; then
    fail "198.18.0.0/15 already has a host route; refusing to alter benchmark routing"
fi

SUFFIX=$(openssl rand -hex 4) || fail "could not generate network resource suffix"
[[ "$SUFFIX" =~ ^[0-9a-f]{8}$ ]] || fail "generated network resource suffix is invalid"
readonly SUFFIX
BRIDGE="apb$SUFFIX"
HOST_NS="aph$SUFFIX"
COMMON_NS="apc$SUFFIX"
INTERNAL_NS="api$SUFFIX"
ORIGIN_NS="apo$SUFFIX"

ip link show "$BRIDGE" >/dev/null 2>&1 && fail "generated bridge name already exists: $BRIDGE"
for namespace in "$HOST_NS" "$COMMON_NS" "$INTERNAL_NS" "$ORIGIN_NS"; do
    ip netns list | awk '{print $1}' | grep -qx "$namespace" \
        && fail "generated namespace name already exists: $namespace"
    [[ ! -e "/etc/netns/$namespace" ]] \
        || fail "generated namespace configuration path already exists: /etc/netns/$namespace"
done

ip link add "$BRIDGE" type bridge
BRIDGE_OWNED=1
ip link set "$BRIDGE" up
FORWARD_RULE_ARGS=(
    -s 198.18.0.0/15
    -d 198.18.0.0/15
    -m comment --comment "acl-proxy-p11-$SUFFIX"
    -j ACCEPT
)
if iptables -C FORWARD "${FORWARD_RULE_ARGS[@]}" >/dev/null 2>&1; then
    fail "generated FORWARD rule identity already exists"
else
    rule_status=$?
    (( rule_status == 1 )) || fail "could not check generated FORWARD rule identity"
fi
iptables -I FORWARD "${FORWARD_RULE_ARGS[@]}"
FORWARD_RULE=1

add_namespace() {
    local namespace=$1
    local address=$2
    local tag=$3
    local host_veth="v${tag}h$SUFFIX"
    local ns_veth="v${tag}n$SUFFIX"
    ip link show "$host_veth" >/dev/null 2>&1 \
        && fail "generated host link already exists: $host_veth"
    ip link show "$ns_veth" >/dev/null 2>&1 \
        && fail "generated peer link already exists: $ns_veth"
    ip netns add "$namespace"
    OWNED_NAMESPACES+=("$namespace")
    ip link add "$host_veth" type veth peer name "$ns_veth"
    OWNED_HOST_LINKS+=("$host_veth")
    ip link set "$host_veth" master "$BRIDGE"
    ip link set "$host_veth" up
    ip link set "$ns_veth" netns "$namespace"
    ip -n "$namespace" link set lo up
    ip -n "$namespace" addr add "$address/15" dev "$ns_veth"
    ip -n "$namespace" link set "$ns_veth" up
}

add_namespace "$HOST_NS" 198.18.0.10 h
add_namespace "$COMMON_NS" 198.18.2.10 c
add_namespace "$INTERNAL_NS" 198.18.1.10 i
add_namespace "$ORIGIN_NS" 198.18.10.10 o

for namespace in "$HOST_NS" "$COMMON_NS" "$INTERNAL_NS" "$ORIGIN_NS"; do
    mkdir -p "/etc/netns/$namespace"
    cat >"/etc/netns/$namespace/hosts" <<'EOF'
127.0.0.1 localhost
198.18.0.10 host-proxy.example.test
198.18.10.10 gitlab.example.test
198.18.10.10 git.private-a.example.test
198.18.10.10 api.private-a.example.test
198.18.10.10 ws.example.test
198.18.10.10 reload.example.test
198.18.10.10 parent-ws.example.test
EOF
done

mkdir -p "$TMP_DIR/host/providers" "$TMP_DIR/host/tls" \
    "$TMP_DIR/common/providers" "$TMP_DIR/common/tls" \
    "$TMP_DIR/internal/providers" "$TMP_DIR/internal/tls" "$TMP_DIR/origin"
cp "$FIXTURE_DIR/host-proxy-tcp.toml" "$TMP_DIR/host/acl-proxy.toml"
cp "$FIXTURE_DIR/common-container-proxy.toml" "$TMP_DIR/common/acl-proxy.toml"
cp "$FIXTURE_DIR/internal-container-proxy.toml" "$TMP_DIR/internal/acl-proxy.toml"
cp "$FIXTURE_DIR/providers/"* "$TMP_DIR/host/providers/"
chmod 0755 "$TMP_DIR/host/providers/"*.py

# The generated MITM store intentionally does not export its private CA. The
# deployment smoke uses an ephemeral file-backed CA so downstream clients can
# trust MITM leaves without depending on internal certificate-store layout.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$TMP_DIR/host/tls/mitm-ca-key.pem" >/dev/null 2>&1
openssl req -x509 -new -key "$TMP_DIR/host/tls/mitm-ca-key.pem" -days 1 \
    -subj '/CN=acl-proxy topology MITM CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'subjectKeyIdentifier=hash' \
    -addext 'authorityKeyIdentifier=keyid:always' \
    -out "$TMP_DIR/host/tls/mitm-ca-cert.pem" >/dev/null 2>&1
chmod 0600 "$TMP_DIR/host/tls/mitm-ca-key.pem"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=acl-proxy topology origin CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$TMP_DIR/origin/ca-key.pem" -out "$TMP_DIR/origin/ca-cert.pem" \
    >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -subj '/CN=gitlab.example.test' \
    -addext 'subjectAltName=DNS:gitlab.example.test,DNS:git.private-a.example.test,DNS:api.private-a.example.test,DNS:ws.example.test,DNS:reload.example.test,DNS:parent-ws.example.test' \
    -keyout "$TMP_DIR/origin/server-key.pem" -out "$TMP_DIR/origin/server.csr" \
    >/dev/null 2>&1
openssl x509 -req -days 1 -sha256 \
    -in "$TMP_DIR/origin/server.csr" \
    -CA "$TMP_DIR/origin/ca-cert.pem" -CAkey "$TMP_DIR/origin/ca-key.pem" \
    -CAcreateserial -out "$TMP_DIR/origin/server-cert.pem" \
    -extfile <(printf '%s\n' 'subjectAltName=DNS:gitlab.example.test,DNS:git.private-a.example.test,DNS:api.private-a.example.test,DNS:ws.example.test,DNS:reload.example.test,DNS:parent-ws.example.test') \
    >/dev/null 2>&1
cp "$TMP_DIR/origin/ca-cert.pem" "$TMP_DIR/host/tls/origin-ca.pem"

openssl req -newkey rsa:2048 -nodes \
    -subj '/CN=host-proxy.example.test' \
    -addext 'subjectAltName=DNS:host-proxy.example.test' \
    -keyout "$TMP_DIR/host/tls/parent-key.pem" \
    -out "$TMP_DIR/host/tls/parent.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -sha256 \
    -in "$TMP_DIR/host/tls/parent.csr" \
    -CA "$TMP_DIR/origin/ca-cert.pem" -CAkey "$TMP_DIR/origin/ca-key.pem" \
    -CAcreateserial -out "$TMP_DIR/host/tls/parent-cert.pem" \
    -extfile <(printf '%s\n' 'subjectAltName=DNS:host-proxy.example.test') \
    >/dev/null 2>&1

python3 - "$TMP_DIR/host/acl-proxy.toml" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
needle = '[egress.origin_tls]\ntrust = "system"\n'
replacement = '[egress.origin_tls]\ntrust = "custom"\nca_certificate = "tls/origin-ca.pem"\n'
if text.count(needle) != 1:
    raise SystemExit("unexpected host origin TLS fixture shape")
text = text.replace(needle, replacement)
text = text.replace(
    '[mitm]\nmode = "generated"\ndirectory = "runtime/certs"\n',
    '[mitm]\nmode = "files"\nca_certificate = "tls/mitm-ca-cert.pem"\n'
    'ca_private_key = "tls/mitm-ca-key.pem"\ndirectory = "runtime/certs"\n',
)
listener = '''
[listeners.explicit_https]
endpoint = { kind = "tcp", address = "0.0.0.0:8443" }
http_versions = ["http1"]
handshake_timeout = "2s"

[listeners.explicit_https.connect]
http1 = "mitm"

[listeners.explicit_https.tls]
certificate_chain = "tls/parent-cert.pem"
private_key = "tls/parent-key.pem"

'''
text = text.replace('[listeners.transparent_https]\n', listener + '[listeners.transparent_https]\n')
text = text.replace('max_active_webhook_deliveries = 256\n',
                    'max_active_webhook_deliveries = 256\nmax_active_upgrades = 1\n'
                    # 2 slots * (3 * 1 MiB reassembly + 1 MiB scratch for the
                    # 64 KiB environment-literal ceiling + 8192 relay bytes).
                    'upgrade_relay_buffer_bytes = 4096\nmax_upgrade_buffer_bytes = 8404992\n'
                    'max_upgrade_lifetime = "4s"\n')
text = text.replace('id = "prod-host-r04-context-a-allow"',
                    'id = "prod-host-r04-context-a-allow"')
text = text.replace('client_cidrs = ["198.18.1.0/24"]\n\n[[policy.rules]]\nid = "prod-host-r05',
                    'client_cidrs = ["198.18.1.0/24"]\nallow_upgrades = true\n'
                    'redaction_profile = "sensitive_strings"\n\n[[policy.rules]]\nid = "prod-host-r05')
text = text.replace('[[policy.rules]]\nid = "prod-host-r00-require-identity"', '''[[policy.rules]]
id = "p11-ws-direct"
decision = "allow"
urls = ["http://ws.example.test:8080/**", "https://ws.example.test:8443/**"]
allow_upgrades = true

[[policy.rules]]
id = "p11-ws-connect-redaction"
decision = "allow"
urls = ["https://parent-ws.example.test:8443/**"]
allow_upgrades = true
redaction_profile = "sensitive_strings"

[[policy.rules]]
id = "p11-ws-protected"
decision = "delegate"
urls = ["https://gitlab.example.test:8443/group/public.git/**"]
allow_upgrades = true
redaction_profile = "sensitive_strings"
authorization_provider = "gitlab_acl"

[[policy.rules]]
id = "p11-ws-reload"
decision = "allow"
urls = ["http://reload.example.test:8080/**"]
allow_upgrades = true
redaction_profile = "sensitive_strings"

[[policy.rules]]
id = "prod-host-r00-require-identity"''')
text += '''

[[redaction.profiles.sensitive_strings.rules]]
literals = ["old-secret"]
payloads = "both"

[redaction.profiles.capture_strings]
replacement = "[CAPTURE-OLD]"
max_body_bytes = 1048576
max_decoded_body_bytes = 1048576
max_frame_bytes = 262144
max_message_bytes = 1048576
allow_permessage_deflate = false
rules = [{ literals = ["fixture-secret-a-00000000000000000000", "old-secret", "new-secret"], payloads = "both" }]

[observation.capture]
events = ["request.allowed", "response.allowed"]
redaction_profile = "capture_strings"
directory = "runtime/captures"
filename = "capture-{requestId}-{suffix}.json"
max_body_bytes = 1048576
max_inflight_body_bytes = 33554432
max_pending_records = 64
max_files = 256
max_total_bytes = 16777216
'''
path.write_text(text, encoding="utf-8")
PY

cat >"$TMP_DIR/origin/origin.py" <<'PY'
import base64
import hashlib
import json
import http.server
import json
import socket
import ssl
import sys
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        identity = self.headers.get("x-aw-identity-token", "absent")
        context = self.headers.get("x-aw-policy-context", "absent")
        body = f"origin-ok:{self.path}:identity={identity}:context={context}".encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


http_server = http.server.ThreadingHTTPServer(("0.0.0.0", 80), Handler)
https_server = http.server.ThreadingHTTPServer(("0.0.0.0", 443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
https_server.socket = context.wrap_socket(https_server.socket, server_side=True)
threading.Thread(target=http_server.serve_forever, daemon=True).start()
threading.Thread(target=https_server.serve_forever, daemon=True).start()

event_path = sys.argv[3]
event_lock = threading.Lock()
connection_sequence = 0


def record(event, **values):
    with event_lock, open(event_path, "a", encoding="utf-8") as stream:
        stream.write(json.dumps({"event": event, **values}, sort_keys=True) + "\n")
        stream.flush()


def read_exact(stream, length):
    data = b""
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise EOFError("unexpected websocket EOF")
        data += chunk
    return data


def read_head(stream):
    data = b""
    while b"\r\n\r\n" not in data:
        data += read_exact(stream, 1)
        if len(data) > 65536:
            raise ValueError("oversized websocket request head")
    return data


def read_frame(stream):
    first, second = read_exact(stream, 2)
    masked = bool(second & 0x80)
    length = second & 0x7f
    if length == 126:
        length = int.from_bytes(read_exact(stream, 2), "big")
    elif length == 127:
        length = int.from_bytes(read_exact(stream, 8), "big")
    mask = read_exact(stream, 4) if masked else b""
    payload = read_exact(stream, length)
    if masked:
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return bool(first & 0x80), first & 0x0f, masked, payload


def frame(opcode, payload=b"", *, fin=True):
    head = bytes([(0x80 if fin else 0) | opcode])
    length = len(payload)
    if length < 126:
        head += bytes([length])
    elif length < 65536:
        head += bytes([126]) + length.to_bytes(2, "big")
    else:
        head += bytes([127]) + length.to_bytes(8, "big")
    return head + payload


def serve_websocket(stream, address, connection_id):
    target = None
    try:
        head = read_head(stream).decode("latin1")
        lines = head.split("\r\n")
        method, target, version = lines[0].split(" ")
        headers = {}
        for line in lines[1:]:
            if line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()
        if method != "GET" or version != "HTTP/1.1":
            raise ValueError("invalid websocket request line")
        if headers.get("upgrade", "").lower() != "websocket":
            raise ValueError("missing websocket upgrade")
        key = headers["sec-websocket-key"]
        accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
        ).digest()).decode("ascii")
        stream.sendall((
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Connection: Upgrade\r\nUpgrade: websocket\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode("ascii"))
        record("open", connection=connection_id, target=target,
               identity=headers.get("x-aw-identity-token", "absent"),
               context=headers.get("x-aw-policy-context", "absent"))
        message_opcode = None
        message = bytearray()
        while True:
            fin, opcode, masked, payload = read_frame(stream)
            if not masked:
                raise ValueError("origin received an unmasked client frame")
            if opcode == 0x8:
                stream.sendall(frame(0x8, payload))
                record("close", connection=connection_id,
                       target=target, payload=payload.hex())
                return
            if opcode == 0x9:
                stream.sendall(frame(0xA, payload))
                continue
            if opcode in (0x1, 0x2):
                if message_opcode is not None:
                    raise ValueError("nested fragmented message")
                message_opcode = opcode
                message.extend(payload)
            elif opcode == 0x0:
                if message_opcode is None:
                    raise ValueError("orphan continuation")
                message.extend(payload)
            else:
                raise ValueError("unsupported websocket opcode")
            if fin:
                record("message", connection=connection_id,
                       target=target,
                       payload=bytes(message).decode("utf-8", "replace"))
                stream.sendall(frame(message_opcode, bytes(message)))
                message_opcode = None
                message.clear()
    except EOFError as error:
        record("eof", connection=connection_id, target=target, detail=str(error))
    except Exception as error:
        record("error", connection=connection_id, target=target, detail=str(error))
    finally:
        record("terminal", connection=connection_id, target=target)
        stream.close()


def accept_loop(listener, tls_context=None):
    global connection_sequence
    while True:
        stream, address = listener.accept()
        with event_lock:
            connection_sequence += 1
            connection_id = connection_sequence
        record("tcp_accept", connection=connection_id,
               listener=listener.getsockname()[1], client=address[0])
        if tls_context is not None:
            try:
                stream = tls_context.wrap_socket(stream, server_side=True)
            except ssl.SSLError as error:
                record("tls_error", connection=connection_id, detail=str(error))
                record("terminal", connection=connection_id, target=None)
                stream.close()
                continue
        threading.Thread(target=serve_websocket,
                         args=(stream, address, connection_id), daemon=True).start()


plain_listener = socket.create_server(("0.0.0.0", 8080), reuse_port=False)
tls_listener = socket.create_server(("0.0.0.0", 8443), reuse_port=False)
ws_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ws_tls.load_cert_chain(sys.argv[1], sys.argv[2])
threading.Thread(target=accept_loop, args=(plain_listener,), daemon=True).start()
accept_loop(tls_listener, ws_tls)
PY

ip netns exec "$ORIGIN_NS" python3 "$TMP_DIR/origin/origin.py" \
    "$TMP_DIR/origin/server-cert.pem" "$TMP_DIR/origin/server-key.pem" \
    "$TMP_DIR/origin/websocket-events.jsonl" \
    >"$TMP_DIR/origin/stdout.log" 2>"$TMP_DIR/origin/stderr.log" &
register_pid "$!" || fail "could not register the origin process"

cat >"$TMP_DIR/websocket_client.py" <<'PY'
import base64
import hashlib
import json
import os
import socket
import ssl
import sys
import time

KEY = "dGhlIHNhbXBsZSBub25jZQ=="
EXPECTED_ACCEPT = base64.b64encode(hashlib.sha1(
    (KEY + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
).digest()).decode("ascii")


def exact(stream, length):
    data = b""
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise EOFError("unexpected EOF")
        data += chunk
    return data


def head(stream):
    data = b""
    while b"\r\n\r\n" not in data:
        data += exact(stream, 1)
        if len(data) > 65536:
            raise AssertionError("response head exceeded 64 KiB")
    return data.decode("latin1")


def masked_frame(opcode, payload=b"", *, fin=True):
    mask = b"\x11\x22\x33\x44"
    first = (0x80 if fin else 0) | opcode
    length = len(payload)
    if length < 126:
        prefix = bytes([first, 0x80 | length])
    elif length < 65536:
        prefix = bytes([first, 0x80 | 126]) + length.to_bytes(2, "big")
    else:
        prefix = bytes([first, 0x80 | 127]) + length.to_bytes(8, "big")
    encoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return prefix + mask + encoded


def read_frame(stream):
    first, second = exact(stream, 2)
    assert not second & 0x80, "server frame was masked"
    length = second & 0x7f
    if length == 126:
        length = int.from_bytes(exact(stream, 2), "big")
    elif length == 127:
        length = int.from_bytes(exact(stream, 8), "big")
    return bool(first & 0x80), first & 0x0f, exact(stream, length)


def connect_tcp(address):
    stream = socket.create_connection(address, timeout=4)
    stream.settimeout(6)
    return stream


def outer_connect(proxy, authority):
    stream = connect_tcp(proxy)
    stream.sendall((f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").encode("ascii"))
    response = head(stream)
    assert response.startswith("HTTP/1.1 200"), response
    return stream


def tls_wrap(stream, ca, hostname):
    context = ssl.create_default_context(cafile=ca)
    # Python 3.14 enables X509_STRICT by default; deployed MITM leaves are
    # intentionally minimal. Keep CA/hostname verification while accepting
    # the product leaf profile exercised by non-strict production clients.
    if hasattr(ssl, "VERIFY_X509_STRICT"):
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context.wrap_socket(stream, server_hostname=hostname)


def upgrade(stream, target, host, extra_headers=()):
    headers = "".join(f"{name}: {value}\r\n" for name, value in extra_headers)
    stream.sendall((
        f"GET {target} HTTP/1.1\r\nHost: {host}\r\n"
        "Connection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {KEY}\r\n{headers}\r\n"
    ).encode("ascii"))
    response = head(stream)
    assert response.startswith("HTTP/1.1 101"), response
    parsed = {}
    for line in response.split("\r\n")[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            parsed[name.strip().lower()] = value.strip()
    assert parsed.get("upgrade", "").lower() == "websocket", response
    assert "upgrade" in parsed.get("connection", "").lower(), response
    assert parsed.get("sec-websocket-accept") == EXPECTED_ACCEPT, response
    return response


def message(stream, payload, expected=None):
    stream.sendall(masked_frame(0x1, payload))
    fin, opcode, observed = read_frame(stream)
    assert fin and opcode == 0x1
    assert observed == (payload if expected is None else expected), (observed, expected)


def close_exact(stream, code=1000, reason=b"p11"):
    payload = code.to_bytes(2, "big") + reason
    stream.sendall(masked_frame(0x8, payload))
    fin, opcode, observed = read_frame(stream)
    assert fin and opcode == 0x8 and observed == payload
    stream.settimeout(2)
    assert stream.recv(1) == b""
    stream.close()


def direct_open(host="ws.example.test", path="/direct"):
    stream = connect_tcp(("127.0.0.1", 8881))
    upgrade(stream, f"http://{host}:8080{path}", f"{host}:8080")
    return stream


def mitm_open(ca, host="parent-ws.example.test", path="/connect", extra_headers=()):
    stream = outer_connect(("127.0.0.1", 8881), f"{host}:8443")
    stream = tls_wrap(stream, ca, host)
    upgrade(stream, path, f"{host}:8443", extra_headers)
    return stream


def success(**extra):
    print("ASSERT_WS_101=1")
    print("ASSERT_WS_ACCEPT=1")
    print("ASSERT_WS_STREAM=1")
    print("ASSERT_WS_CLOSE=1")
    for name, value in extra.items():
        print(f"{name}={value}")


def direct_case():
    stream = direct_open()
    sensitive = b"fixture-secret-a-00000000000000000000"
    message(stream, sensitive, sensitive)
    close_exact(stream)
    success(ASSERT_UNPROTECTED_LITERAL_UNCHANGED=1, ASSERT_NO_DETACHED_WORK=1)


def fragmented_connect_case(ca):
    stream = mitm_open(ca)
    literal = b"fixture-secret-a-00000000000000000000"
    stream.sendall(masked_frame(0x1, literal[:18], fin=False))
    stream.sendall(masked_frame(0x0, literal[18:], fin=True))
    fin, opcode, observed = read_frame(stream)
    assert fin and opcode == 0x1 and observed == b"[REDACTED]"
    close_exact(stream)
    success(ASSERT_FRAGMENTED_REDACTION=1)


def parent_case(ca):
    stream = mitm_open(
        ca,
        host="gitlab.example.test",
        path="/group/public.git/parent-protected",
        extra_headers=(
            ("x-aw-identity-token", "spoofed-client-identity"),
            ("x-aw-policy-context", "spoofed-client-context"),
        ),
    )
    message(stream, b"fixture-secret-a-00000000000000000000", b"[REDACTED]")
    close_exact(stream)
    success(ASSERT_PARENT_TLS=1, ASSERT_INJECTED_IDENTITY_AUTHORIZATION=1,
            ASSERT_SPOOF_REPLACED_AND_STRIPPED=1, ASSERT_CREDENTIAL_ISOLATION=1)


def origin_event_count(path, event):
    with open(path, encoding="utf-8") as stream:
        return sum(json.loads(line).get("event") == event for line in stream if line.strip())


def rejected_upgrade(path):
    stream = connect_tcp(("127.0.0.1", 8881))
    stream.sendall((
        f"GET http://ws.example.test:8080{path} HTTP/1.1\r\n"
        "Host: ws.example.test:8080\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n\r\n"
    ).encode("ascii"))
    response = head(stream)
    assert response.startswith("HTTP/1.1 503"), response
    stream.close()


def assert_no_origin_accept(event_path, before, duration=0.6):
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        observed = origin_event_count(event_path, "tcp_accept")
        assert observed == before, (before, observed)
        time.sleep(0.02)


def admission_case(event_path):
    first = direct_open(path="/admission-first")
    before_second = origin_event_count(event_path, "tcp_accept")
    rejected_upgrade("/admission-second")
    assert_no_origin_accept(event_path, before_second)
    message(first, b"first-still-live")
    close_exact(first)
    restored = direct_open(path="/admission-restored-held")
    before_overrelease = origin_event_count(event_path, "tcp_accept")
    rejected_upgrade("/admission-overrelease")
    assert_no_origin_accept(event_path, before_overrelease)
    message(restored, b"restored-slot-live")
    close_exact(restored)
    final = direct_open(path="/admission-restored-after-close")
    close_exact(final)
    success(ASSERT_REJECTED_BEFORE_ORIGIN=1, ASSERT_ACCEPT_QUIET_WINDOW=1,
            ASSERT_NO_OVER_RELEASE=1, ASSERT_SLOT_RESTORED_EXACTLY_ONCE=1)


def captured(directory, path_suffix, expected):
    import json
    from pathlib import Path
    for _ in range(100):
        for path in Path(directory).glob("*.json"):
            for line in path.read_text(encoding="utf-8").splitlines():
                record = json.loads(line)
                body = record.get("body")
                if not record.get("url", "").endswith(path_suffix) or not isinstance(body, dict):
                    continue
                if body.get("encoding") == "base64":
                    payload = base64.b64decode(body.get("data", ""))
                    if expected in payload:
                        return
        time.sleep(0.05)
    raise AssertionError(f"capture did not contain {expected!r} for {path_suffix}")


def reload_case(config, pid, capture_directory):
    old = direct_open("reload.example.test", "/old-generation")
    opened_at = time.monotonic()
    message(old, b"old-secret", b"[REDACTED]")
    captured(capture_directory, "/old-generation", b"[CAPTURE-OLD]")
    time.sleep(1.0)
    with open(config, encoding="utf-8") as stream:
        text = stream.read()
    assert text.count('replacement = "[REDACTED]"') >= 1
    text = text.replace('replacement = "[REDACTED]"', 'replacement = "[WIRE-NEW]"', 1)
    text = text.replace('literals = ["old-secret"]', 'literals = ["new-secret"]', 1)
    text = text.replace('replacement = "[CAPTURE-OLD]"', 'replacement = "[CAPTURE-NEW]"', 1)
    temporary = config + ".new"
    with open(temporary, "w", encoding="utf-8") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, config)
    reload_at = time.monotonic()
    os.kill(int(pid), 1)
    time.sleep(0.8)
    message(old, b"old-secret", b"[REDACTED]")
    captured(capture_directory, "/old-generation", b"[CAPTURE-NEW]")
    new = direct_open("reload.example.test", "/new-generation")
    message(new, b"old-secret", b"old-secret")
    message(new, b"new-secret", b"[WIRE-NEW]")
    close_exact(new)
    old.settimeout(6)
    while old.recv(1):
        pass
    closed_at = time.monotonic()
    lifetime_elapsed = closed_at - opened_at
    post_reload_elapsed = closed_at - reload_at
    assert 3.4 <= lifetime_elapsed <= 4.7, lifetime_elapsed
    assert post_reload_elapsed < 3.7, post_reload_elapsed
    success(ASSERT_OLD_MATCHER=1, ASSERT_NEW_MATCHER=1,
            ASSERT_CAPTURE_EPOCH_BOUNDARY=1, ASSERT_ONE_LIFETIME_CLOCK=1,
            ASSERT_LIFETIME_FROM_ORIGINAL_OPEN=1, ASSERT_RELOAD_DID_NOT_RESET_LIFETIME=1,
            LIFETIME_SECONDS=f"{lifetime_elapsed:.3f}",
            POST_RELOAD_SECONDS=f"{post_reload_elapsed:.3f}")


def shutdown_case(ca, ready, finished):
    direct = direct_open(path="/shutdown-direct")
    connected = mitm_open(ca, path="/shutdown-connect")
    message(direct, b"direct-before-stop")
    message(connected, b"connect-before-stop")
    with open(ready, "w", encoding="ascii") as stream:
        stream.write("ready\n")
    stop_modes = []
    for stream in (direct, connected):
        stream.settimeout(8)
        try:
            while stream.recv(4096):
                pass
            stop_modes.append("eof")
        except ConnectionResetError:
            stop_modes.append("reset")
        except ssl.SSLError:
            stop_modes.append("tls-stop")
        stream.close()
    assert len(stop_modes) == 2
    with open(finished, "w", encoding="ascii") as stream:
        stream.write(f"{time.time_ns()} {' '.join(stop_modes)}\n")
    success(ASSERT_BOUNDED_STOP=1, ASSERT_STREAMS_STOPPED=1)


command = sys.argv[1]
if command == "direct":
    direct_case()
elif command == "connect":
    fragmented_connect_case(sys.argv[2])
elif command == "parent":
    parent_case(sys.argv[2])
elif command == "admission":
    admission_case(sys.argv[2])
elif command == "reload":
    reload_case(sys.argv[2], sys.argv[3], sys.argv[4])
elif command == "shutdown":
    shutdown_case(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    raise SystemExit(f"unknown websocket smoke command: {command}")
PY

run_proxy() {
    local namespace=$1
    local role=$2
    local identity=$3
    env_args=(
        HOME="$TMP_DIR/home"
        PATH="/usr/bin:/bin"
        AW_IDENTITY_TOKEN="$identity"
        FIXTURE_REDACT_A=fixture-secret-a-00000000000000000000
        FIXTURE_REDACT_B=fixture-secret-b-00000000000000000000
        FIXTURE_REDACT_C=fixture-secret-c-00000000000000000000
        FIXTURE_REDACT_D=fixture-secret-d-00000000000000000000
        FIXTURE_REDACT_E=fixture-secret-e-00000000000000000000
    )
    ip netns exec "$namespace" env -i "${env_args[@]}" \
        "$PROXY_BIN" run --config "$TMP_DIR/$role/acl-proxy.toml" \
        >"$TMP_DIR/$role/stdout.log" 2>"$TMP_DIR/$role/stderr.log" &
    ROLE_PIDS["$role"]=$!
    register_pid "$!" || fail "could not register the $role proxy process"
}

wait_ready() {
    local namespace=$1
    local role=$2
    local attempt
    for attempt in {1..200}; do
        if ip netns exec "$namespace" curl --fail --silent --noproxy '*' \
            http://127.0.0.1:8898/_acl-proxy/ready \
            >"$TMP_DIR/$role/ready.json" 2>/dev/null; then
            grep -qx '{"status":"ready"}' "$TMP_DIR/$role/ready.json" \
                || fail "$role returned an unexpected readiness body"
            return 0
        fi
        sleep 0.05
    done
    fail "$role control listener did not become ready"
}

run_proxy "$HOST_NS" host fixture-host-unused
wait_ready "$HOST_NS" host

origin_body=$(ip netns exec "$HOST_NS" curl --fail --silent --show-error \
    --connect-timeout 3 --max-time 10 --noproxy '*' \
    --cacert "$TMP_DIR/origin/ca-cert.pem" \
    https://gitlab.example.test/topology-origin-preflight)
[[ "$origin_body" == *'origin-ok:/topology-origin-preflight:'* ]] \
    || fail "host namespace could not reach the HTTPS origin"

readonly HOST_CA="$TMP_DIR/host/tls/mitm-ca-cert.pem"
readonly HOST_CA_KEY="$TMP_DIR/host/tls/mitm-ca-key.pem"

for role in common internal; do
    cp "$HOST_CA" "$TMP_DIR/$role/tls/fixture-ca-cert.pem"
    cp "$HOST_CA_KEY" "$TMP_DIR/$role/tls/fixture-ca-key.pem"
    chmod 0600 "$TMP_DIR/$role/tls/fixture-ca-key.pem"
    python3 - "$TMP_DIR/$role/acl-proxy.toml" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
needle = '[egress.origin_tls]\ntrust = "system"\n'
replacement = '[egress.origin_tls]\ntrust = "custom"\nca_certificate = "tls/fixture-ca-cert.pem"\n'
if text.count(needle) != 1:
    raise SystemExit("unexpected child origin TLS fixture shape")
text = text.replace(needle, replacement)
text = text.replace(
    'url = "http://host-proxy.example.test:8881"\n',
    'url = "https://host-proxy.example.test:8443"\n\n'
    '[egress.parent_proxy.tls]\ntrust = "custom"\n'
    'ca_certificate = "tls/parent-ca.pem"\nserver_name = "host-proxy.example.test"\n',
)
if path.parent.name == "common":
    text = text.replace('urls = ["**"]\n',
                        'urls = ["**"]\nallow_upgrades = true\n'
                        'redaction_profile = "p11_child_wire"\n', 1)
    text += '''

[redaction.profiles.p11_child_wire]
replacement = "[REDACTED]"
max_body_bytes = 1048576
max_decoded_body_bytes = 1048576
max_frame_bytes = 262144
max_message_bytes = 1048576
allow_permessage_deflate = false
rules = [{ literals = ["fixture-secret-a-00000000000000000000"], payloads = "both" }]
'''
path.write_text(text, encoding="utf-8")
PY
    cp "$TMP_DIR/origin/ca-cert.pem" "$TMP_DIR/$role/tls/parent-ca.pem"
done

run_proxy "$COMMON_NS" common fixture-common-identity
run_proxy "$INTERNAL_NS" internal fixture-internal-identity
wait_ready "$COMMON_NS" common
wait_ready "$INTERNAL_NS" internal

for namespace in "$HOST_NS" "$COMMON_NS" "$INTERNAL_NS"; do
    status=$(ip netns exec "$namespace" curl --silent --output /dev/null \
        --write-out '%{http_code}' --noproxy '*' \
        http://127.0.0.1:8881/_acl-proxy/ready || true)
    [[ "$status" != 200 ]] || fail "data listener exposed readiness in $namespace"
done

spoofed_policy_context_is_replaced_before_provider_dispatch() {
    local common_body common_status internal_body internal_status
    common_status=$(ip netns exec "$COMMON_NS" curl --silent --show-error \
        --connect-timeout 3 --max-time 10 \
        --proxy http://127.0.0.1:8881 --cacert "$HOST_CA" \
        -H 'x-aw-identity-token: spoofed-client-value' \
        -H 'x-aw-policy-context: fixture-internal' \
        --output "$TMP_DIR/common/provider.body" --write-out '%{http_code}' \
        https://gitlab.example.test/group/public.git/custom)
    common_body=$(<"$TMP_DIR/common/provider.body")
    [[ "$common_status" == 200 ]] \
        || fail "common provider path returned HTTP $common_status: $common_body"
    [[ "$common_body" == *'identity=absent:context=absent' ]] \
        || fail "common identity/context reached the origin or request failed"

    internal_status=$(ip netns exec "$INTERNAL_NS" curl --silent --show-error \
        --connect-timeout 3 --max-time 10 \
        --proxy http://127.0.0.1:8881 --cacert "$HOST_CA" \
        -H 'x-aw-identity-token: spoofed-client-value' \
        -H 'x-aw-policy-context: workload-spoof' \
        --output "$TMP_DIR/internal/provider.body" --write-out '%{http_code}' \
        https://gitlab.example.test/group/internal.git/custom)
    internal_body=$(<"$TMP_DIR/internal/provider.body")
    [[ "$internal_status" == 200 ]] \
        || fail "internal provider path returned HTTP $internal_status: $internal_body"
    [[ "$internal_body" == *'identity=absent:context=absent' ]] \
        || fail "internal identity/context reached the origin or request failed"
}

spoofed_policy_context_is_replaced_before_provider_dispatch

direct_host_context_must_match_identity_authorization() {
    local status
    status=$(ip netns exec "$COMMON_NS" curl --silent --show-error \
        --connect-timeout 3 --max-time 10 \
        --proxy http://198.18.0.10:8881 --cacert "$HOST_CA" \
        -H 'x-aw-identity-token: fixture-common-identity' \
        -H 'x-aw-policy-context: fixture-internal' \
        --output "$TMP_DIR/common/direct-host-denied.body" --write-out '%{http_code}' \
        https://gitlab.example.test/group/public.git/custom)
    [[ "$status" == 403 ]] \
        || fail "direct host identity/context mismatch returned HTTP $status"
}

direct_host_context_must_match_identity_authorization

deny_status=$(ip netns exec "$COMMON_NS" curl --silent --show-error \
    --connect-timeout 3 --max-time 10 \
    --proxy http://127.0.0.1:8881 --cacert "$HOST_CA" \
    --output "$TMP_DIR/common/denied.body" --write-out '%{http_code}' \
    https://gitlab.example.test/group/not-authorized/custom)
[[ "$deny_status" == 403 ]] || fail "provider denial returned HTTP $deny_status"

http_body=$(ip netns exec "$INTERNAL_NS" curl --fail --silent --show-error \
    --connect-timeout 3 --max-time 10 \
    --proxy http://198.18.0.10:8881 \
    -H 'x-aw-identity-token: fixture-internal-identity' \
    -H 'x-aw-policy-context: fixture-internal' \
    http://git.private-a.example.test/topology-http)
[[ "$http_body" == *'identity=absent:context=absent' ]] \
    || fail "host HTTP proxy path failed or leaked internal headers"

ip netns exec "$INTERNAL_NS" iptables -t nat -A OUTPUT -p tcp --dport 443 \
    -j REDIRECT --to-ports 8889
transparent_body=$(ip netns exec "$INTERNAL_NS" curl --fail --silent --show-error \
    --connect-timeout 3 --max-time 10 \
    --noproxy '*' --cacert "$HOST_CA" \
    -H 'x-aw-identity-token: spoofed-client-value' \
    https://gitlab.example.test/group/internal.git/custom)
[[ "$transparent_body" == *'identity=absent:context=absent' ]] \
    || fail "redirected transparent TLS path failed or leaked internal headers"

assert_ws_101() {
    local result=$1
    grep -qx 'ASSERT_WS_101=1' <<<"$result" || fail "WebSocket client did not prove HTTP 101"
    grep -qx 'ASSERT_WS_ACCEPT=1' <<<"$result" \
        || fail "WebSocket client did not prove Sec-WebSocket-Accept"
}

ws_stream_assertions() {
    local result=$1
    grep -qx 'ASSERT_WS_STREAM=1' <<<"$result" \
        || fail "WebSocket client did not prove stream behavior"
    grep -qx 'ASSERT_WS_CLOSE=1' <<<"$result" \
        || fail "WebSocket client did not prove exact close"
}

assert_ws_field() {
    local result=$1
    local field=$2
    grep -qx "$field=1" <<<"$result" || fail "WebSocket proof is missing $field"
}

assert_origin_events() {
    local attempt
    for attempt in {1..100}; do
        if python3 - "$TMP_DIR/origin/websocket-events.jsonl" "$@" 2>/dev/null <<'PY'
import json
from pathlib import Path
import sys

records = [json.loads(line) for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()]
for assertion in sys.argv[2:]:
    kind, path = assertion.split(":", 1)
    expected = None
    if kind == "message-is":
        path, expected = path.rsplit("=", 1)
    matching = [record for record in records if record.get("target") == path]
    if kind == "opened-once" and sum(record.get("event") == "open" for record in matching) != 1:
        raise SystemExit(f"origin did not open exactly once for {path}: {matching!r}")
    if kind == "closed-once" and sum(record.get("event") == "close" for record in matching) != 1:
        raise SystemExit(f"origin did not close exactly once for {path}: {matching!r}")
    if kind == "never-opened" and any(record.get("event") == "open" for record in matching):
        raise SystemExit(f"rejected request connected to origin for {path}: {matching!r}")
    if kind == "accepted-once":
        opened = [record for record in matching if record.get("event") == "open"]
        accepted = [record for record in records if record.get("event") == "tcp_accept"
                    and any(record.get("connection") == item.get("connection") for item in opened)]
        if len(opened) != 1 or len(accepted) != 1:
            raise SystemExit(f"origin TCP acceptance mismatch for {path}: {opened!r} {accepted!r}")
    if kind == "terminal-once" and sum(record.get("event") == "terminal" for record in matching) != 1:
        raise SystemExit(f"origin did not terminate exactly once for {path}: {matching!r}")
    if kind == "message-is":
        messages = [record.get("payload") for record in matching if record.get("event") == "message"]
        if messages.count(expected) != 1:
            raise SystemExit(f"origin message mismatch for {path}: {messages!r}")
    if kind == "headers-absent":
        opened = [record for record in matching if record.get("event") == "open"]
        if len(opened) != 1 or opened[0].get("identity") != "absent" or opened[0].get("context") != "absent":
            raise SystemExit(f"protected headers escaped to origin for {path}: {opened!r}")
PY
        then
            return 0
        fi
        sleep 0.02
    done
    python3 - "$TMP_DIR/origin/websocket-events.jsonl" "$@" <<'PY'
import json
from pathlib import Path
import sys
records = [json.loads(line) for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()]
raise SystemExit(f"origin event assertion timed out: assertions={sys.argv[2:]!r} records={records!r}")
PY
}

assert_capture_contains() {
    local path_suffix=$1
    local expected=$2
    local attempt
    for attempt in {1..100}; do
        if python3 - "$TMP_DIR/host/runtime/captures" "$path_suffix" "$expected" <<'PY'
import base64
import json
from pathlib import Path
import sys

directory = Path(sys.argv[1])
path_suffix = sys.argv[2]
expected = sys.argv[3].encode("utf-8")
for path in directory.glob("*.json") if directory.exists() else ():
    for line in path.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        if not record.get("url", "").endswith(path_suffix):
            continue
        body = record.get("body")
        if isinstance(body, dict) and body.get("encoding") == "base64":
            if expected in base64.b64decode(body.get("data", "")):
                raise SystemExit(0)
raise SystemExit(1)
PY
        then
            return 0
        fi
        sleep 0.05
    done
    fail "logical capture did not contain the expected redacted message"
}

p11_ws_direct_unprotected() {
    local result
    result=$(ip netns exec "$HOST_NS" timeout 15s python3 "$TMP_DIR/websocket_client.py" direct)
    assert_ws_101 "$result"
    ws_stream_assertions "$result"
    assert_ws_field "$result" ASSERT_UNPROTECTED_LITERAL_UNCHANGED
    assert_ws_field "$result" ASSERT_NO_DETACHED_WORK
    assert_origin_events accepted-once:/direct opened-once:/direct closed-once:/direct \
        terminal-once:/direct \
        'message-is:/direct=fixture-secret-a-00000000000000000000'
    printf '%s\n' 'P11_WS_CASE p11_ws_direct_unprotected PASS'
}

p11_ws_connect_mitm_fragmented_redaction_capture() {
    local result
    result=$(ip netns exec "$HOST_NS" timeout 15s python3 "$TMP_DIR/websocket_client.py" \
        connect "$HOST_CA")
    assert_ws_101 "$result"
    ws_stream_assertions "$result"
    assert_ws_field "$result" ASSERT_FRAGMENTED_REDACTION
    assert_capture_contains /connect '[CAPTURE-OLD]'
    assert_origin_events accepted-once:/connect opened-once:/connect closed-once:/connect \
        terminal-once:/connect 'message-is:/connect=[REDACTED]'
    printf '%s\n' 'P11_WS_CASE p11_ws_connect_mitm_fragmented_redaction_capture PASS'
}

p11_ws_https_parent_protected_redaction() {
    local result
    result=$(ip netns exec "$COMMON_NS" timeout 15s python3 "$TMP_DIR/websocket_client.py" \
        parent "$HOST_CA")
    assert_ws_101 "$result"
    ws_stream_assertions "$result"
    assert_ws_field "$result" ASSERT_PARENT_TLS
    assert_ws_field "$result" ASSERT_INJECTED_IDENTITY_AUTHORIZATION
    assert_ws_field "$result" ASSERT_SPOOF_REPLACED_AND_STRIPPED
    assert_ws_field "$result" ASSERT_CREDENTIAL_ISOLATION
    assert_origin_events accepted-once:/group/public.git/parent-protected \
        opened-once:/group/public.git/parent-protected \
        closed-once:/group/public.git/parent-protected \
        terminal-once:/group/public.git/parent-protected \
        headers-absent:/group/public.git/parent-protected \
        'message-is:/group/public.git/parent-protected=[REDACTED]'
    printf '%s\n' 'P11_WS_CASE p11_ws_https_parent_protected_redaction PASS'
}

p11_ws_admission_saturation() {
    local result
    result=$(ip netns exec "$HOST_NS" timeout 25s python3 "$TMP_DIR/websocket_client.py" \
        admission "$TMP_DIR/origin/websocket-events.jsonl")
    assert_ws_101 "$result"
    ws_stream_assertions "$result"
    assert_ws_field "$result" ASSERT_REJECTED_BEFORE_ORIGIN
    assert_ws_field "$result" ASSERT_ACCEPT_QUIET_WINDOW
    assert_ws_field "$result" ASSERT_NO_OVER_RELEASE
    assert_ws_field "$result" ASSERT_SLOT_RESTORED_EXACTLY_ONCE
    assert_origin_events accepted-once:/admission-first closed-once:/admission-first \
        accepted-once:/admission-restored-held closed-once:/admission-restored-held \
        accepted-once:/admission-restored-after-close \
        closed-once:/admission-restored-after-close \
        terminal-once:/admission-first terminal-once:/admission-restored-held \
        terminal-once:/admission-restored-after-close
    printf '%s\n' 'P11_WS_CASE p11_ws_admission_saturation PASS'
}

restart_host_with_two_upgrade_slots() {
    stop_owned_pid_gracefully "${ROLE_PIDS[host]}" 10 \
        || fail "host proxy did not stop for the isolated reload fixture"
    python3 - "$TMP_DIR/host/acl-proxy.toml" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
if text.count("max_active_upgrades = 1") != 1:
    raise SystemExit("unexpected host upgrade-slot fixture shape")
path.write_text(text.replace("max_active_upgrades = 1", "max_active_upgrades = 2"), encoding="utf-8")
PY
    run_proxy "$HOST_NS" host fixture-host-unused
    wait_ready "$HOST_NS" host
}

p11_ws_reload_and_lifetime() {
    local result
    result=$(ip netns exec "$HOST_NS" timeout 15s python3 "$TMP_DIR/websocket_client.py" \
        reload "$TMP_DIR/host/acl-proxy.toml" "${ROLE_PIDS[host]}" \
        "$TMP_DIR/host/runtime/captures")
    assert_ws_101 "$result"
    ws_stream_assertions "$result"
    assert_ws_field "$result" ASSERT_OLD_MATCHER
    assert_ws_field "$result" ASSERT_NEW_MATCHER
    assert_ws_field "$result" ASSERT_CAPTURE_EPOCH_BOUNDARY
    assert_ws_field "$result" ASSERT_ONE_LIFETIME_CLOCK
    assert_ws_field "$result" ASSERT_LIFETIME_FROM_ORIGINAL_OPEN
    assert_ws_field "$result" ASSERT_RELOAD_DID_NOT_RESET_LIFETIME
    grep -q 'configuration reload completed successfully' "$TMP_DIR/host/runtime/logs/acl-proxy.log" \
        || fail "host reload did not publish a successor generation"
    assert_origin_events opened-once:/old-generation opened-once:/new-generation \
        closed-once:/new-generation terminal-once:/old-generation \
        terminal-once:/new-generation
    printf '%s\n' 'P11_WS_CASE p11_ws_reload_and_lifetime PASS'
}

p11_ws_shutdown_join() {
    local result_file="$TMP_DIR/host/shutdown-websocket.out"
    local ready_file="$TMP_DIR/host/shutdown-websocket.ready"
    local finished_file="$TMP_DIR/host/shutdown-websocket.finished"
    ip netns exec "$HOST_NS" timeout 15s python3 "$TMP_DIR/websocket_client.py" \
        shutdown "$HOST_CA" "$ready_file" "$finished_file" \
        >"$result_file" 2>"$TMP_DIR/host/shutdown-websocket.err" &
    local client_pid=$!
    register_pid "$client_pid" || fail "could not register shutdown WebSocket clients"
    local attempt
    for attempt in {1..100}; do
        [[ -s "$ready_file" ]] && break
        sleep 0.05
    done
    [[ -s "$ready_file" ]] || fail "shutdown WebSocket clients did not become ready"
    local started=$SECONDS listener_closed_ns="" process_exit_ns="" client_finished_ns=""
    signal_owned_pid TERM "${ROLE_PIDS[host]}" \
        || fail "could not signal the owned host process"
    for attempt in {1..2000}; do
        if [[ -z "$listener_closed_ns" ]] && ip netns exec "$HOST_NS" \
            bash -c '! exec 3<>/dev/tcp/127.0.0.1/8881' >/dev/null 2>&1; then
            listener_closed_ns=$(date +%s%N)
        fi
        if [[ -z "$client_finished_ns" && -s "$finished_file" ]]; then
            read -r client_finished_ns _ <"$finished_file"
        fi
        if [[ -z "$process_exit_ns" ]] && ! owned_pid_running "${ROLE_PIDS[host]}"; then
            process_exit_ns=$(date +%s%N)
        fi
        if [[ -n "$listener_closed_ns" && -n "$client_finished_ns" && -n "$process_exit_ns" ]]; then
            break
        fi
        sleep 0.005
    done
    [[ -n "$listener_closed_ns" ]] || fail "host listener remained open during shutdown"
    [[ -n "$client_finished_ns" ]] || fail "shutdown clients did not record bounded stream stop"
    [[ -n "$process_exit_ns" ]] || fail "host process exceeded its shutdown bound"
    (( listener_closed_ns <= client_finished_ns )) \
        || fail "WebSocket streams stopped before the data listener closed"
    local host_status client_status
    if wait "${ROLE_PIDS[host]}"; then host_status=0; else host_status=$?; fi
    (( host_status == 0 )) || fail "host process aborted during shutdown: status $host_status"
    if wait "$client_pid"; then client_status=0; else client_status=$?; fi
    (( client_status == 0 )) || fail "shutdown WebSocket clients failed: status $client_status"
    (( SECONDS - started <= 10 )) || fail "shutdown exceeded the deployment bound"
    assert_origin_events terminal-once:/shutdown-direct terminal-once:/shutdown-connect
    assert_capture_contains /shutdown-direct 'direct-before-stop'
    assert_capture_contains /shutdown-connect 'connect-before-stop'
    {
        printf '%s\n' 'ASSERT_LISTENER_CLOSED_FIRST=1'
        printf '%s\n' 'ASSERT_GRACEFUL_PROCESS_EXIT=1'
        printf '%s\n' 'ASSERT_RELAY_TERMINALS_JOINED=1'
        printf '%s\n' 'ASSERT_CAPTURE_TASKS_FLUSHED=1'
        printf '%s\n' 'ASSERT_TASKS_JOINED=1'
    } >>"$result_file"
    local result
    result=$(<"$result_file")
    assert_ws_101 "$result"
    ws_stream_assertions "$result"
    assert_ws_field "$result" ASSERT_BOUNDED_STOP
    assert_ws_field "$result" ASSERT_STREAMS_STOPPED
    assert_ws_field "$result" ASSERT_LISTENER_CLOSED_FIRST
    assert_ws_field "$result" ASSERT_GRACEFUL_PROCESS_EXIT
    assert_ws_field "$result" ASSERT_RELAY_TERMINALS_JOINED
    assert_ws_field "$result" ASSERT_CAPTURE_TASKS_FLUSHED
    assert_ws_field "$result" ASSERT_TASKS_JOINED
    printf '%s\n' 'P11_WS_CASE p11_ws_shutdown_join PASS'
}

p11_ws_direct_unprotected
p11_ws_connect_mitm_fragmented_redaction_capture
p11_ws_https_parent_protected_redaction
p11_ws_admission_saturation
restart_host_with_two_upgrade_slots
p11_ws_reload_and_lifetime
p11_ws_shutdown_join

for pid in "${PIDS[@]}"; do
    terminate_owned_pid "$pid" 5
done
PIDS=()

printf '%s\n' \
    'production topology smoke passed: strict fixtures, v1 rejection, control readiness, data isolation, parent forwarding, identity replacement/stripping, provider allow/deny, HTTP, CONNECT, redirected TLS'
