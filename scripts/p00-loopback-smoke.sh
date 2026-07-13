#!/usr/bin/env bash

set -Eeuo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly CURL=(curl --silent --show-error --noproxy "")

TMP_DIR=""
PROXY_PID=""
HTTP_ORIGIN_PID=""
HTTPS_ORIGIN_PID=""

fail() {
    printf 'P00 smoke failed: %s\n' "$*" >&2
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
        if [[ -n "$pid" ]]; then
            wait "$pid" 2>/dev/null || true
        fi
    done
    if [[ -n "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
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

wait_for_url() {
    local url=$1
    local insecure=${2:-false}
    local attempt
    local args=(--fail --output /dev/null --proxy '' --noproxy '*')
    if [[ "$insecure" == true ]]; then
        args+=(--insecure)
    fi
    for attempt in {1..100}; do
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
    for attempt in {1..100}; do
        if ! kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

require_command cargo
require_command curl
require_command openssl
require_command python3
require_command stat

cd "$ROOT_DIR"
cargo build --locked --bin acl-proxy
readonly PROXY_BIN="$ROOT_DIR/target/debug/acl-proxy"
[[ -x "$PROXY_BIN" ]] || fail "local acl-proxy binary was not built"

umask 077
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/acl-proxy-p00-smoke.XXXXXX")
mkdir "$TMP_DIR/home"

cat >"$TMP_DIR/origin.py" <<'PY'
import http.server
import ssl
import sys

mode = sys.argv[1]
port = int(sys.argv[2])
port_file = sys.argv[3]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"origin-ok:{mode}:{self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
if mode == "https":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(sys.argv[4], sys.argv[5])
    server.socket = context.wrap_socket(server.socket, server_side=True)
with open(port_file, "w", encoding="ascii") as handle:
    handle.write(str(server.server_port))
server.serve_forever()
PY

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' \
    -keyout "$TMP_DIR/origin-key.pem" -out "$TMP_DIR/origin-cert.pem" \
    >/dev/null 2>&1

python3 "$TMP_DIR/origin.py" http 0 "$TMP_DIR/http-origin.port" \
    >"$TMP_DIR/http-origin.log" 2>&1 &
HTTP_ORIGIN_PID=$!
python3 "$TMP_DIR/origin.py" https 0 "$TMP_DIR/https-origin.port" \
    "$TMP_DIR/origin-cert.pem" "$TMP_DIR/origin-key.pem" \
    >"$TMP_DIR/https-origin.log" 2>&1 &
HTTPS_ORIGIN_PID=$!

for attempt in {1..100}; do
    [[ -s "$TMP_DIR/http-origin.port" && -s "$TMP_DIR/https-origin.port" ]] && break
    sleep 0.05
done
[[ -s "$TMP_DIR/http-origin.port" && -s "$TMP_DIR/https-origin.port" ]] \
    || fail "origins did not report their bound ports"
readonly HTTP_ORIGIN_PORT=$(<"$TMP_DIR/http-origin.port")
readonly HTTPS_ORIGIN_PORT=$(<"$TMP_DIR/https-origin.port")

wait_for_url "http://127.0.0.1:$HTTP_ORIGIN_PORT/health" \
    || fail "HTTP origin did not become ready"
wait_for_url "https://127.0.0.1:$HTTPS_ORIGIN_PORT/health" true \
    || fail "HTTPS origin did not become ready"

start_proxy() {
    local startup_attempt wait_attempt
    for startup_attempt in {1..5}; do
        PROXY_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
        cat >"$TMP_DIR/acl-proxy.toml" <<EOF
schema_version = "2"

[proxy]
listeners.explicit_http.bind = "127.0.0.1:$PROXY_PORT"
request_timeout_ms = 5000
shutdown_drain_timeout_ms = 2000

[logging]
level = "info"
directory = "$TMP_DIR/logs"
console = false

[capture]
allowed_request = false
allowed_response = false
denied_request = false
denied_response = false
directory = "$TMP_DIR/captures"

[certificates]
certs_dir = "$TMP_DIR/certs"

[tls]
verify_upstream = false
enable_http2_upstream = false

[policy]
default = "deny"

[[policy.rules]]
action = "allow"
pattern = "http://127.0.0.1:$HTTP_ORIGIN_PORT/allowed"
description = "P00 loopback HTTP smoke"

[[policy.rules]]
action = "allow"
pattern = "https://127.0.0.1:$HTTPS_ORIGIN_PORT/secure"
description = "P00 loopback CONNECT smoke"
EOF

        env -i HOME="$TMP_DIR/home" PATH="$PATH" \
            "$PROXY_BIN" --config "$TMP_DIR/acl-proxy.toml" config validate \
            >"$TMP_DIR/config-validate.log" 2>&1 \
            || fail "generated smoke configuration is invalid"

        env -i HOME="$TMP_DIR/home" PATH="$PATH" \
            "$PROXY_BIN" --config "$TMP_DIR/acl-proxy.toml" run \
            >"$TMP_DIR/proxy.stdout" 2>"$TMP_DIR/proxy.stderr" &
        PROXY_PID=$!

        for wait_attempt in {1..100}; do
            if curl --fail --silent --output /dev/null --noproxy '*' \
                "http://127.0.0.1:$PROXY_PORT/_acl-proxy/ready" 2>/dev/null; then
                return 0
            fi
            if ! kill -0 "$PROXY_PID" 2>/dev/null; then
                wait "$PROXY_PID" 2>/dev/null || true
                PROXY_PID=""
                break
            fi
            sleep 0.05
        done

        if [[ -n "$PROXY_PID" ]]; then
            kill -TERM "$PROXY_PID" 2>/dev/null || true
            wait "$PROXY_PID" 2>/dev/null || true
            PROXY_PID=""
        fi
    done
    fail "proxy could not bind an ephemeral loopback port after five attempts"
}

start_proxy
readonly PROXY_PORT

ready_body=$(curl --fail --silent --show-error --noproxy '*' \
    "http://127.0.0.1:$PROXY_PORT/_acl-proxy/ready")
[[ "$ready_body" == '{"status":"ready"}' ]] \
    || fail "unexpected readiness response: $ready_body"

deny_status=$("${CURL[@]}" --proxy "http://127.0.0.1:$PROXY_PORT" \
    --output "$TMP_DIR/deny.body" --write-out '%{http_code}' \
    "http://127.0.0.1:$HTTP_ORIGIN_PORT/denied")
[[ "$deny_status" == 403 ]] || fail "deny request returned HTTP $deny_status, expected 403"
grep -q 'Blocked by URL policy' "$TMP_DIR/deny.body" \
    || fail "deny response did not contain the policy rejection message"

http_body=$("${CURL[@]}" --fail --proxy "http://127.0.0.1:$PROXY_PORT" \
    "http://127.0.0.1:$HTTP_ORIGIN_PORT/allowed")
[[ "$http_body" == 'origin-ok:http:/allowed' ]] \
    || fail "unexpected allowed HTTP response: $http_body"

readonly CA_CERT="$TMP_DIR/certs/ca-cert.pem"
readonly CA_KEY="$TMP_DIR/certs/ca-key.pem"
for attempt in {1..100}; do
    [[ -s "$CA_CERT" && -s "$CA_KEY" ]] && break
    sleep 0.05
done
[[ -s "$CA_CERT" && -s "$CA_KEY" ]] || fail "generated proxy CA files are missing"
[[ "$(file_mode "$TMP_DIR/certs")" == 700 ]] \
    || fail "generated CA directory is not mode 0700"
[[ "$(file_mode "$CA_CERT")" == 600 ]] \
    || fail "generated CA certificate is not mode 0600"
[[ "$(file_mode "$CA_KEY")" == 600 ]] \
    || fail "generated CA private key is not mode 0600"

https_body=$("${CURL[@]}" --fail --http1.1 \
    --proxy "http://127.0.0.1:$PROXY_PORT" --cacert "$CA_CERT" \
    --trace-ascii "$TMP_DIR/connect.trace" \
    "https://127.0.0.1:$HTTPS_ORIGIN_PORT/secure")
[[ "$https_body" == 'origin-ok:https:/secure' ]] \
    || fail "unexpected allowed HTTPS response: $https_body"
grep -Eq "CONNECT 127\\.0\\.0\\.1:$HTTPS_ORIGIN_PORT HTTP/1\\.1" \
    "$TMP_DIR/connect.trace" || fail "curl trace did not prove a CONNECT tunnel"

kill -INT "$PROXY_PID"
wait_for_exit "$PROXY_PID" || fail "proxy did not stop within 5 seconds after SIGINT"
set +e
wait "$PROXY_PID"
proxy_status=$?
set -e
PROXY_PID=""
[[ "$proxy_status" == 0 ]] || fail "proxy exited with status $proxy_status after SIGINT"

printf '%s\n' 'P00 loopback smoke passed: readiness, deny, HTTP, CONNECT/TLS, CA permissions, graceful SIGINT'
