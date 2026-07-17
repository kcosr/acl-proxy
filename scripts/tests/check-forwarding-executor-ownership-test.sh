#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/forwarding-adapter-ownership-test.XXXXXX")
cleanup() {
    rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

BASELINE="$TEST_ROOT/baseline"
mkdir -p \
    "$BASELINE/scripts" \
    "$BASELINE/src/activation" \
    "$BASELINE/src/authorization/webhook" \
    "$BASELINE/src/proxy" \
    "$BASELINE/src/runtime"
cp "$SOURCE_ROOT/scripts/check-forwarding-executor-ownership.sh" "$BASELINE/scripts/"

cat >"$BASELINE/src/proxy/mod.rs" <<'EOF'
pub(crate) mod forwarding_adapter;
pub(crate) mod ingress;
EOF

cat >"$BASELINE/src/proxy/forwarding_adapter.rs" <<'EOF'
use http_access_runtime::{
    ForwardingAdmission, ForwardingObservation, ForwardingOutcome, ForwardingRequestHead,
    ForwardingResources, ForwardingResponseHead, ForwardingRetention, ForwardingTerminal,
    ForwardingTerminalOutcome, ForwardingTerminalOwner, PreparedUpgradeHandoff, UpgradeHandoff,
    UpgradeOffer, UpstreamUpgradeBounds,
};

fn adapter(mut parts: Parts, executor: Executor, dispatch: Dispatch, resources: Resources) {
    let h2_stream = parts.extensions.remove::<H2StreamCancellation>();
    let outcome = executor.execute(dispatch.exchange, dispatch.resolved, resources);
    let body = ProxyResponseBody::forwarded(
        body,
        Arc::clone(&observation),
        h2_stream,
        downstream_supports_trailers,
    );
}

// AppState ProductConfig ForwardingExecutor forward_request TcpStream::connect(endpoint)
/* nested /* ForwardingOutcome */ HttpsConnector */
const TEXT: &str = "ForwardingExecutor::activate ForwardingResources client::conn";
const RAW: &str = r#"H2StreamCancellation::current() DestinationGuard"#;

#[cfg(test)]
mod tests {
    fn ignored() {
        ForwardingExecutor::activate();
        executor.execute(dispatch.exchange, dispatch.resolved, resources);
        TcpStream::connect(endpoint);
    }
}
EOF

cat >"$BASELINE/src/proxy/ingress.rs" <<'EOF'
fn terminal(terminal: Terminal, dispatch: Dispatch) {
    crate::proxy::forwarding_adapter::execute(terminal, dispatch);
}

fn execute_request_via_pipeline(mut request: Request) {
    if let Some(h2_stream) = H2StreamCancellation::current() {
        request.extensions_mut().insert(h2_stream);
    }
}

fn retained_listener() {
    let _: tokio_rustls::TlsAcceptor;
    hyper::server::conn::Http::new();
}

#[cfg(test)]
fn ignored_test_client() {
    hyper::client::conn::handshake(stream);
    tokio::net::TcpStream::connect(endpoint);
}
EOF

cat >"$BASELINE/src/activation/product.rs" <<'EOF'
fn activate() {
    let forwarding_executor = http_access_runtime::ForwardingExecutor::activate(bindings);
}
EOF

cat >"$BASELINE/src/runtime/generation.rs" <<'EOF'
struct Generation {
    forwarding_executor: Arc<http_access_runtime::ForwardingExecutor>,
}
EOF

cat >"$BASELINE/src/authorization/webhook/connector.rs" <<'EOF'
fn connect() {
    tokio::net::TcpStream::connect(endpoint);
    tokio::net::lookup_host(endpoint);
    hyper::client::conn::handshake(stream);
    let _: tokio_rustls::TlsConnector;
}
EOF

cat >"$BASELINE/src/authorization/webhook/provider.rs" <<'EOF'
use crate::tls::{build_client_config, load_client_trust, ClientAlpn};
EOF

cat >"$BASELINE/src/tls.rs" <<'EOF'
use rustls::ClientConfig;
fn build_client_config() { let _: ClientConfig; }
fn load_client_trust() {}
enum ClientAlpn { Http1 }
EOF

cat >"$BASELINE/src/test_only.rs" <<'EOF'
#![cfg(test)]
fn ignored() {
    let _: ForwardingOutcome;
    let _: ForwardingExecutor;
    tokio::net::TcpStream::connect(endpoint);
}
EOF

runner() {
    local root=$1
    "$root/scripts/check-forwarding-executor-ownership.sh"
}

runner "$BASELINE" >"$TEST_ROOT/pass.log"
grep -Fq 'shared forwarding adapter ownership gate passed' "$TEST_ROOT/pass.log"

expect_failure() {
    local root=$1
    local description=$2
    local expected=$3
    if runner "$root" >"$TEST_ROOT/failure.log" 2>&1; then
        printf '%s was accepted\n' "$description" >&2
        exit 1
    fi
    if ! grep -Fq -- "$expected" "$TEST_ROOT/failure.log"; then
        printf '%s failed for the wrong reason; expected: %s\n' "$description" "$expected" >&2
        cat "$TEST_ROOT/failure.log" >&2
        exit 1
    fi
}

mutations=0
new_case() {
    mutations=$((mutations + 1))
    CASE_ROOT="$TEST_ROOT/case-$mutations"
    cp -R "$BASELINE" "$CASE_ROOT"
}

new_case
rm "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'missing adapter' 'forwarding ownership scan path is missing: src/proxy/forwarding_adapter.rs'

for obsolete in \
    src/proxy/forward.rs \
    src/proxy/forwarding_executor.rs \
    src/proxy/standalone_body.rs \
    src/destination.rs
do
    new_case
    mkdir -p "$(dirname -- "$CASE_ROOT/$obsolete")"
    printf '%s\n' 'fn obsolete() {}' >"$CASE_ROOT/$obsolete"
    expect_failure "$CASE_ROOT" "restored obsolete path $obsolete" \
        'obsolete product forwarding owners must remain deleted'
done

new_case
mkdir -p "$CASE_ROOT/src/destination"
printf '%s\n' 'fn obsolete() {}' >"$CASE_ROOT/src/destination/mod.rs"
expect_failure "$CASE_ROOT" 'restored destination directory' \
    'obsolete product forwarding owners must remain deleted'

new_case
printf '%s\n' 'mod forward;' >>"$CASE_ROOT/src/proxy/mod.rs"
expect_failure "$CASE_ROOT" 'restored obsolete module declaration' \
    'obsolete product forwarding module declarations must remain deleted'

for dependency in \
    'let _: AppState;' \
    'let _: GenerationLease;' \
    'let _: ProductConfig;' \
    'use crate::config;' \
    'let _: AuthoringForwardingRule;' \
    'use crate::policy;' \
    'evaluate_policy();' \
    'let _: PolicySnapshot;' \
    'let _: StandalonePolicyProvider;' \
    'provider.decide();'
do
    new_case
    printf '%s\n' "$dependency" >>"$CASE_ROOT/src/proxy/forwarding_adapter.rs"
    expect_failure "$CASE_ROOT" "adapter dependency $dependency" \
        'forwarding adapter dependency violations:'
done

new_case
printf '%s\n' \
    'fn bypass(terminal: Terminal, dispatch: Dispatch) {' \
    '    crate::proxy::forwarding_adapter::execute(terminal, dispatch);' \
    '}' >"$CASE_ROOT/src/bypass.rs"
expect_failure "$CASE_ROOT" 'second adapter entry' \
    'ingress-to-adapter terminal entry ownership violation'

new_case
sed -i 's/crate::proxy::forwarding_adapter::execute/terminal_response/' \
    "$CASE_ROOT/src/proxy/ingress.rs"
expect_failure "$CASE_ROOT" 'missing adapter entry' \
    'ingress-to-adapter terminal entry ownership violation'

new_case
printf '%s\n' \
    'fn bypass(executor: Executor, dispatch: Dispatch, resources: Resources) {' \
    '    executor.execute(dispatch.exchange, dispatch.resolved, resources);' \
    '}' >"$CASE_ROOT/src/bypass.rs"
expect_failure "$CASE_ROOT" 'shared executor bypass' \
    'adapter-to-shared-executor terminal call ownership violation'

new_case
sed -i 's/executor.execute(dispatch.exchange, dispatch.resolved, resources)/terminal_response(dispatch)/' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'missing shared executor call' \
    'adapter-to-shared-executor terminal call ownership violation'

new_case
printf '%s\n' 'fn escaped() { ForwardingExecutor::activate(bindings); }' \
    >"$CASE_ROOT/src/bypass.rs"
expect_failure "$CASE_ROOT" 'escaped executor activation' \
    'shared forwarding executor activation ownership violation'

new_case
sed -i 's/ForwardingExecutor::activate/ForwardingRuntime::activate/' \
    "$CASE_ROOT/src/activation/product.rs"
expect_failure "$CASE_ROOT" 'missing executor activation' \
    'shared forwarding executor activation ownership violation'

new_case
printf '%s\n' 'struct Escaped(Arc<ForwardingExecutor>);' >"$CASE_ROOT/src/bypass.rs"
expect_failure "$CASE_ROOT" 'escaped executor storage' \
    'ForwardingExecutor storage and activation must remain confined'

for symbol in \
    ForwardingAdmission \
    ForwardingObservation \
    ForwardingOutcome \
    ForwardingRequestHead \
    ForwardingResources \
    ForwardingResponseHead \
    ForwardingRetention \
    ForwardingTerminal \
    ForwardingTerminalOutcome \
    ForwardingTerminalOwner \
    PreparedUpgradeHandoff \
    UpgradeHandoff \
    UpgradeOffer \
    UpstreamUpgradeBounds
do
    new_case
    printf '%s\n' "fn escaped(_: $symbol) {}" >"$CASE_ROOT/src/bypass.rs"
    expect_failure "$CASE_ROOT" "escaped adapter type $symbol" \
        "$symbol must be owned exclusively and non-vacuously by forwarding_adapter.rs"
done

new_case
sed -i '/if let Some(h2_stream) = H2StreamCancellation::current()/d' \
    "$CASE_ROOT/src/proxy/ingress.rs"
expect_failure "$CASE_ROOT" 'missing H2 lookup' \
    'ambient H2 cancellation lookup ownership violation'

new_case
printf '%s\n' 'fn escaped() { H2StreamCancellation::current(); }' >"$CASE_ROOT/src/bypass.rs"
expect_failure "$CASE_ROOT" 'escaped H2 lookup' \
    'ambient H2 cancellation lookup ownership violation'

new_case
sed -i 's/if let Some(h2_stream) = H2StreamCancellation::current()/if let Some(detached) = H2StreamCancellation::current()/' \
    "$CASE_ROOT/src/proxy/ingress.rs"
expect_failure "$CASE_ROOT" 'detached H2 lookup and injection' \
    'direct H2 cancellation capability transfer ownership violation'

new_case
sed -i '/request.extensions_mut().insert(h2_stream);/d' "$CASE_ROOT/src/proxy/ingress.rs"
expect_failure "$CASE_ROOT" 'missing H2 injection' \
    'typed H2 cancellation injection ownership violation'

new_case
printf '%s\n' 'fn escaped(mut request: Request) { request.extensions_mut().insert(h2_stream); }' \
    >"$CASE_ROOT/src/bypass.rs"
expect_failure "$CASE_ROOT" 'escaped H2 injection' \
    'typed H2 cancellation injection ownership violation'

new_case
sed -i '/let h2_stream = parts.extensions.remove::<H2StreamCancellation>();/d' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'missing adapter H2 take' \
    'adapter H2 cancellation ownership take ownership violation'

new_case
printf '%s\n' 'fn escaped(mut parts: Parts) { parts.extensions.remove::<H2StreamCancellation>(); }' \
    >"$CASE_ROOT/src/bypass.rs"
expect_failure "$CASE_ROOT" 'escaped H2 take' \
    'adapter H2 cancellation ownership take ownership violation'

new_case
sed -i 's/        h2_stream,/        None,/' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'missing response-lifetime H2 transfer' \
    'adapter H2 response-lifetime transfer ownership violation'

for primitive in \
    'forward_request(request);' \
    'forward_upgrade_request(request);' \
    'let _: DestinationGuard;' \
    'let _: DestinationConnector;' \
    'let _: StandaloneBody;'
do
    new_case
    printf '%s\n' "$primitive" >"$CASE_ROOT/src/bypass.rs"
    expect_failure "$CASE_ROOT" "obsolete private primitive $primitive" \
        'obsolete product-private ordinary forwarding primitives must remain absent'
done

for primitive in \
    'tokio::net::TcpStream::connect(endpoint);' \
    'std::net::TcpStream::connect(endpoint);' \
    'TcpSocket::new_v4();' \
    'socket2::Socket::new(domain, kind, protocol);' \
    'tokio::net::lookup_host(endpoint);' \
    'let _: std::net::ToSocketAddrs;' \
    'hyper::client::conn::handshake(stream);' \
    'use hyper::{client as private_client};' \
    'let _: hyper::Client;' \
    'let _: HttpConnector;' \
    'let _: HttpsConnector;' \
    'let _: tokio_rustls::TlsConnector;' \
    'let _: rustls::ClientConfig;' \
    'let _: rustls::ClientConnection;' \
    'use tokio_rustls::{TlsConnector as OutboundTls};'
do
    new_case
    printf '%s\n' "$primitive" >"$CASE_ROOT/src/bypass.rs"
    expect_failure "$CASE_ROOT" "escaped client transport $primitive" \
        'ordinary product forwarding must not own dialing, client TLS, or private Hyper client transport'
done

for helper in build_client_config load_client_trust ClientAlpn; do
    new_case
    printf '%s\n' "fn escaped() { let _ = $helper; }" >"$CASE_ROOT/src/egress.rs"
    expect_failure "$CASE_ROOT" "ordinary use of webhook TLS helper $helper" \
        'retained client TLS helpers must remain webhook-only'
done

for dependency in \
    'use crate::destination::DestinationGuard;' \
    'use crate::egress::EgressActivation;' \
    'use crate::proxy::forwarding_adapter;' \
    'fn escaped(_: ForwardingPlan) {}' \
    'fn escaped(_: ProductCredentialExecution) {}'
do
    new_case
    printf '%s\n' "$dependency" >>"$CASE_ROOT/src/authorization/webhook/connector.rs"
    expected='authorization webhook connector must remain independent of ordinary forwarding ownership'
    if [[ $dependency == *DestinationGuard* ]]; then
        expected='obsolete product-private ordinary forwarding primitives must remain absent'
    fi
    expect_failure "$CASE_ROOT" "webhook dependency $dependency" "$expected"
done

new_case
printf '%s\n' 'use crate::authorization::webhook::connector::WebhookConnector;' \
    >>"$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'adapter webhook dependency' \
    'ordinary egress and forwarding adapter owners must not reference the authorization webhook connector'

printf 'shared forwarding adapter ownership mutation tests passed (%d mutations)\n' "$mutations"
