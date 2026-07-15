#!/usr/bin/env bash

set -Eeuo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly CURL=(curl --silent --show-error --noproxy "")

TMP_DIR=""
PROXY_PID=""
HTTP_ORIGIN_PID=""
HTTPS_ORIGIN_PID=""

fail() {
    printf 'loopback smoke failed: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    local pid
    for pid in "$PROXY_PID" "$HTTP_ORIGIN_PID" "$HTTPS_ORIGIN_PID"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    for pid in "$PROXY_PID" "$HTTP_ORIGIN_PID" "$HTTPS_ORIGIN_PID"; do
        [[ -z "$pid" ]] || wait "$pid" 2>/dev/null || true
    done
    [[ -z "$TMP_DIR" ]] || rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

file_mode() {
    if stat -c '%a' "$1" >/dev/null 2>&1; then
        stat -c '%a' "$1"
    else
        stat -f '%Lp' "$1"
    fi
}

ephemeral_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

wait_for_url() {
    local url=$1
    local insecure=${2:-false}
    local attempt
    local args=(--fail --output /dev/null --proxy '' --noproxy '*')
    [[ "$insecure" != true ]] || args+=(--insecure)
    for attempt in {1..120}; do
        if "${CURL[@]}" "${args[@]}" "$url" 2>/dev/null; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

wait_for_exit() {
    local pid=$1
    local attempt
    for attempt in {1..120}; do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.05
    done
    return 1
}

for command in curl openssl python3 stat; do
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
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/acl-proxy-loopback-smoke.XXXXXX")
mkdir -p "$TMP_DIR/home"

cat >"$TMP_DIR/origin.py" <<'PY'
import http.server
import ssl
import sys

mode = sys.argv[1]
port_file = sys.argv[2]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"origin-ok:{mode}:{self.path}".encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
if mode == "https":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(sys.argv[3], sys.argv[4])
    server.socket = context.wrap_socket(server.socket, server_side=True)
with open(port_file, "w", encoding="ascii") as handle:
    handle.write(str(server.server_port))
server.serve_forever()
PY

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' \
    -keyout "$TMP_DIR/origin-key.pem" -out "$TMP_DIR/origin-cert.pem" \
    >/dev/null 2>&1

python3 "$TMP_DIR/origin.py" http "$TMP_DIR/http-origin.port" \
    >"$TMP_DIR/http-origin.log" 2>&1 &
HTTP_ORIGIN_PID=$!
python3 "$TMP_DIR/origin.py" https "$TMP_DIR/https-origin.port" \
    "$TMP_DIR/origin-cert.pem" "$TMP_DIR/origin-key.pem" \
    >"$TMP_DIR/https-origin.log" 2>&1 &
HTTPS_ORIGIN_PID=$!

for attempt in {1..120}; do
    [[ -s "$TMP_DIR/http-origin.port" && -s "$TMP_DIR/https-origin.port" ]] && break
    sleep 0.05
done
[[ -s "$TMP_DIR/http-origin.port" && -s "$TMP_DIR/https-origin.port" ]] \
    || fail "origins did not report bound ports"
readonly HTTP_ORIGIN_PORT=$(<"$TMP_DIR/http-origin.port")
readonly HTTPS_ORIGIN_PORT=$(<"$TMP_DIR/https-origin.port")

wait_for_url "http://127.0.0.1:$HTTP_ORIGIN_PORT/health" \
    || fail "HTTP origin did not become ready"
wait_for_url "https://127.0.0.1:$HTTPS_ORIGIN_PORT/health" true \
    || fail "HTTPS origin did not become ready"

start_proxy() {
    local startup_attempt wait_attempt proxy_status
    for startup_attempt in {1..5}; do
        DATA_PORT=$(ephemeral_port)
        CONTROL_PORT=$(ephemeral_port)
        [[ "$DATA_PORT" != "$CONTROL_PORT" ]] || continue
        cat >"$TMP_DIR/acl-proxy.toml" <<EOF
schema_version = 3

[service]
request_timeout = "5s"
shutdown_drain_timeout = "2s"

[control]
bind = "127.0.0.1:$CONTROL_PORT"
base_path = "/_acl-proxy"

[listeners.explicit_http]
bind = "127.0.0.1:$DATA_PORT"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "mitm"

[mitm]
mode = "generated"
directory = "$TMP_DIR/mitm"

[egress]
route = "direct"

[egress.origin_tls]
trust = "insecure"
http_versions = ["http1"]

[policy]
default = "deny"

[[policy.rules]]
id = "loopback-http"
decision = "allow"
urls = ["http://127.0.0.1:$HTTP_ORIGIN_PORT/allowed"]

[[policy.rules]]
id = "loopback-connect-outer"
decision = "allow"
urls = ["https://127.0.0.1:$HTTPS_ORIGIN_PORT/"]
methods = ["CONNECT"]

[[policy.rules]]
id = "loopback-connect-inner"
decision = "allow"
urls = ["https://127.0.0.1:$HTTPS_ORIGIN_PORT/secure"]
methods = ["GET"]

[observation.logging]
level = "info"
directory = "$TMP_DIR/logs"
console = false

[safety.loop_detection]
inject = true
header = "x-acl-proxy-request-id"
EOF

        env -i HOME="$TMP_DIR/home" PATH="$PATH" \
            "$PROXY_BIN" config validate --config "$TMP_DIR/acl-proxy.toml" \
            >"$TMP_DIR/config-validate.log" 2>&1 \
            || fail "generated strict v3 smoke configuration is invalid"

        env -i HOME="$TMP_DIR/home" PATH="$PATH" \
            "$PROXY_BIN" run --config "$TMP_DIR/acl-proxy.toml" \
            >"$TMP_DIR/proxy.stdout" 2>"$TMP_DIR/proxy.stderr" &
        PROXY_PID=$!

        for wait_attempt in {1..120}; do
            if curl --fail --silent --output /dev/null --noproxy '*' \
                "http://127.0.0.1:$CONTROL_PORT/_acl-proxy/ready" 2>/dev/null; then
                return 0
            fi
            if ! kill -0 "$PROXY_PID" 2>/dev/null; then
                set +e
                wait "$PROXY_PID"
                proxy_status=$?
                set -e
                PROXY_PID=""
                if grep -Eqi 'address.*(already )?in use|AddrInUse' \
                    "$TMP_DIR/proxy.stderr"; then
                    break
                fi
                sed -n '1,40p' "$TMP_DIR/proxy.stderr" >&2
                fail "proxy exited with status $proxy_status during startup"
            fi
            sleep 0.05
        done

        if [[ -n "$PROXY_PID" ]]; then
            kill -TERM "$PROXY_PID" 2>/dev/null || true
            wait "$PROXY_PID" 2>/dev/null || true
            PROXY_PID=""
            sed -n '1,40p' "$TMP_DIR/proxy.stderr" >&2
            fail "proxy did not become ready on its control listener"
        fi
    done
    fail "proxy could not bind loopback ports after five attempts"
}

start_proxy
readonly DATA_PORT CONTROL_PORT

ready_body=$(curl --fail --silent --show-error --noproxy '*' \
    "http://127.0.0.1:$CONTROL_PORT/_acl-proxy/ready")
[[ "$ready_body" == '{"status":"ready"}' ]] \
    || fail "unexpected readiness response: $ready_body"

data_ready_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --noproxy '*' "http://127.0.0.1:$DATA_PORT/_acl-proxy/ready" || true)
[[ "$data_ready_status" != 200 ]] \
    || fail "data listener exposed the control readiness route"

deny_status=$("${CURL[@]}" --proxy "http://127.0.0.1:$DATA_PORT" \
    --output "$TMP_DIR/deny.body" --write-out '%{http_code}' \
    "http://127.0.0.1:$HTTP_ORIGIN_PORT/denied")
[[ "$deny_status" == 403 ]] \
    || fail "deny request returned HTTP $deny_status, expected 403"

http_body=$("${CURL[@]}" --fail --proxy "http://127.0.0.1:$DATA_PORT" \
    "http://127.0.0.1:$HTTP_ORIGIN_PORT/allowed")
[[ "$http_body" == 'origin-ok:http:/allowed' ]] \
    || fail "unexpected allowed HTTP response: $http_body"

readonly CA_CERT="$TMP_DIR/mitm/ca-cert.pem"
readonly CA_KEY="$TMP_DIR/mitm/ca-key.pem"
for attempt in {1..120}; do
    [[ -s "$CA_CERT" && -s "$CA_KEY" ]] && break
    sleep 0.05
done
[[ -s "$CA_CERT" && -s "$CA_KEY" ]] || fail "generated MITM CA files are missing"
[[ "$(file_mode "$TMP_DIR/mitm")" == 700 ]] \
    || fail "generated MITM directory is not mode 0700"
[[ "$(file_mode "$CA_KEY")" == 600 ]] \
    || fail "generated CA private key is not mode 0600"

https_body=$("${CURL[@]}" --fail --http1.1 \
    --proxy "http://127.0.0.1:$DATA_PORT" --cacert "$CA_CERT" \
    --trace-ascii "$TMP_DIR/connect.trace" \
    "https://127.0.0.1:$HTTPS_ORIGIN_PORT/secure")
[[ "$https_body" == 'origin-ok:https:/secure' ]] \
    || fail "unexpected allowed HTTPS response: $https_body"
grep -Eq "CONNECT 127\\.0\\.0\\.1:$HTTPS_ORIGIN_PORT HTTP/1\\.1" \
    "$TMP_DIR/connect.trace" || fail "curl trace did not prove CONNECT interception"

kill -INT "$PROXY_PID"
wait_for_exit "$PROXY_PID" || fail "proxy did not stop after SIGINT"
set +e
wait "$PROXY_PID"
proxy_status=$?
set -e
PROXY_PID=""
[[ "$proxy_status" == 0 ]] \
    || fail "proxy exited with status $proxy_status after SIGINT"

printf '%s\n' \
    'loopback smoke passed: strict v3, control readiness, data isolation, deny, HTTP, CONNECT/TLS, graceful shutdown'
