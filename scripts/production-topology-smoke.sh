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
FORWARD_RULE=0

fail() {
    printf 'production topology smoke failed: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    local status=$?
    local pid namespace role
    for pid in "${PIDS[@]:-}"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    for pid in "${PIDS[@]:-}"; do
        [[ -z "$pid" ]] || wait "$pid" 2>/dev/null || true
    done
    if (( status != 0 )) && [[ -n "$TMP_DIR" ]]; then
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
        iptables -D FORWARD -s 198.18.0.0/15 -d 198.18.0.0/15 -j ACCEPT \
            2>/dev/null || true
    fi
    for namespace in "$HOST_NS" "$COMMON_NS" "$INTERNAL_NS" "$ORIGIN_NS"; do
        if [[ -n "$namespace" ]]; then
            ip netns del "$namespace" 2>/dev/null || true
            rm -rf "/etc/netns/$namespace"
        fi
    done
    if [[ -n "$BRIDGE" ]]; then
        ip link del "$BRIDGE" 2>/dev/null || true
    fi
    [[ -z "$TMP_DIR" ]] || rm -rf "$TMP_DIR"
    return "$status"
}
trap cleanup EXIT

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

for command in curl openssl python3; do
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
    "$FIXTURE_DIR/host-proxy.toml" \
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

readonly SUFFIX="$$"
BRIDGE="apb$SUFFIX"
HOST_NS="aph$SUFFIX"
COMMON_NS="apc$SUFFIX"
INTERNAL_NS="api$SUFFIX"
ORIGIN_NS="apo$SUFFIX"

ip link add "$BRIDGE" type bridge
ip link set "$BRIDGE" up
iptables -I FORWARD -s 198.18.0.0/15 -d 198.18.0.0/15 -j ACCEPT
FORWARD_RULE=1

add_namespace() {
    local namespace=$1
    local address=$2
    local tag=$3
    local host_veth="v${tag}h$SUFFIX"
    local ns_veth="v${tag}n$SUFFIX"
    ip netns add "$namespace"
    ip link add "$host_veth" type veth peer name "$ns_veth"
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
EOF
done

mkdir -p "$TMP_DIR/host/providers" "$TMP_DIR/host/tls" \
    "$TMP_DIR/common/providers" "$TMP_DIR/common/tls" \
    "$TMP_DIR/internal/providers" "$TMP_DIR/internal/tls" "$TMP_DIR/origin"
cp "$FIXTURE_DIR/host-proxy.toml" "$TMP_DIR/host/acl-proxy.toml"
cp "$FIXTURE_DIR/common-container-proxy.toml" "$TMP_DIR/common/acl-proxy.toml"
cp "$FIXTURE_DIR/internal-container-proxy.toml" "$TMP_DIR/internal/acl-proxy.toml"
cp "$FIXTURE_DIR/providers/"* "$TMP_DIR/host/providers/"
chmod 0755 "$TMP_DIR/host/providers/"*.py

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=acl-proxy topology origin CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$TMP_DIR/origin/ca-key.pem" -out "$TMP_DIR/origin/ca-cert.pem" \
    >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -subj '/CN=gitlab.example.test' \
    -addext 'subjectAltName=DNS:gitlab.example.test,DNS:git.private-a.example.test,DNS:api.private-a.example.test' \
    -keyout "$TMP_DIR/origin/server-key.pem" -out "$TMP_DIR/origin/server.csr" \
    >/dev/null 2>&1
openssl x509 -req -days 1 -sha256 \
    -in "$TMP_DIR/origin/server.csr" \
    -CA "$TMP_DIR/origin/ca-cert.pem" -CAkey "$TMP_DIR/origin/ca-key.pem" \
    -CAcreateserial -out "$TMP_DIR/origin/server-cert.pem" \
    -extfile <(printf '%s\n' 'subjectAltName=DNS:gitlab.example.test,DNS:git.private-a.example.test,DNS:api.private-a.example.test') \
    >/dev/null 2>&1
cp "$TMP_DIR/origin/ca-cert.pem" "$TMP_DIR/host/tls/origin-ca.pem"

python3 - "$TMP_DIR/host/acl-proxy.toml" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
needle = '[egress.origin_tls]\ntrust = "system"\n'
replacement = '[egress.origin_tls]\ntrust = "custom"\nca_certificate = "tls/origin-ca.pem"\n'
if text.count(needle) != 1:
    raise SystemExit("unexpected host origin TLS fixture shape")
path.write_text(text.replace(needle, replacement), encoding="utf-8")
PY

cat >"$TMP_DIR/origin/origin.py" <<'PY'
import http.server
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
https_server.serve_forever()
PY

ip netns exec "$ORIGIN_NS" python3 "$TMP_DIR/origin/origin.py" \
    "$TMP_DIR/origin/server-cert.pem" "$TMP_DIR/origin/server-key.pem" \
    >"$TMP_DIR/origin/stdout.log" 2>"$TMP_DIR/origin/stderr.log" &
PIDS+=("$!")

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
    PIDS+=("$!")
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

readonly HOST_CA="$TMP_DIR/host/runtime/certs/ca-cert.pem"
readonly HOST_CA_KEY="$TMP_DIR/host/runtime/certs/ca-key.pem"
for attempt in {1..200}; do
    [[ -s "$HOST_CA" && -s "$HOST_CA_KEY" ]] && break
    sleep 0.05
done
[[ -s "$HOST_CA" && -s "$HOST_CA_KEY" ]] || fail "host generated MITM CA is missing"

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
path.write_text(text.replace(needle, replacement), encoding="utf-8")
PY
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

for pid in "${PIDS[@]}"; do
    kill -TERM "$pid" 2>/dev/null || true
done
for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
done
PIDS=()

printf '%s\n' \
    'production topology smoke passed: strict fixtures, v1 rejection, control readiness, data isolation, parent forwarding, identity replacement/stripping, provider allow/deny, HTTP, CONNECT, redirected TLS'
