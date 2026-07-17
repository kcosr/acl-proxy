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
    "$BASELINE/access-runtime/crates/http-access-runtime/src" \
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
    ForwardingAdmission, ForwardingDownstreamAbort, ForwardingObservation, ForwardingOutcome,
    ForwardingRequestHead, ForwardingResources, ForwardingResponseHead, ForwardingRetention,
    ForwardingTerminal, ForwardingTerminalOutcome, ForwardingTerminalOwner,
    PreparedUpgradeHandoff, UpgradeHandoff, UpgradeOffer, UpstreamUpgradeBounds,
};

struct ProductDownstreamAbort(H2StreamCancellation);

impl ForwardingDownstreamAbort for ProductDownstreamAbort {
    fn abort(self: Box<Self>) { self.0.cancel(); }
}

fn adapter(mut parts: Parts, executor: Executor, dispatch: Dispatch, mut resources: Resources) {
    let h2_stream = parts.extensions.remove::<H2StreamCancellation>();
    if !h2_stream_context_matches(downstream_supports_trailers, h2_stream.is_some()) {
        return internal_failure(&terminal.capture);
    }
    resources = resources.with_downstream_abort(ProductDownstreamAbort(h2_stream));
    let handoff = ProductUpgradeHandoff::admit(runtime);
    resources = resources.with_upgrade_handoff(handoff, bounds);
    let outcome = executor.execute(dispatch.exchange, dispatch.resolved, resources);
    let no_content = head.status() == StatusCode::NO_CONTENT.as_u16();
    let reset_content = head.status() == StatusCode::RESET_CONTENT.as_u16();
    let h1_content_length = if downstream_supports_trailers || no_content || reset_content {
        None
    } else {
        single_content_length()
    };
    let downstream_suppresses_body =
        downstream_is_head || no_content || reset_content || head.status() == 304;
    let completion = if downstream_suppresses_body {
        drain_suppressed_response(&mut body).await
    } else {
        complete_empty_response(&mut body).await
    };
    let body = ProxyResponseBody::forwarded(
        body,
        Arc::clone(&observation),
        h2_stream,
        downstream_supports_trailers,
        h1_content_length,
    );
    if no_content {
        response.headers_mut().remove(CONTENT_LENGTH);
    } else if reset_content {
        response.headers_mut().remove(CONTENT_LENGTH);
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    }
}

fn h2_stream_context_matches(downstream_is_h2: bool, h2_stream_present: bool) -> bool {
    downstream_is_h2 == h2_stream_present
}

fn complete_empty_response(body: &mut Body) {}
fn drain_suppressed_response(body: &mut Body) {}

struct ProductUpgradeHandoff;

impl ProductUpgradeHandoff {
    fn admit(runtime: Runtime) -> Self {
        runtime.try_spawn_handshake(allocation, |_| async {});
        Self
    }
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

struct ForwardedState {
    h1_remaining: Option<u64>,
    pending_h1_final: Option<Chunk>,
    h1_source_done: bool,
    data_done: bool,
    trailers_done: bool,
}

fn forwarded(h1_content_length: Option<u64>) -> ForwardedState {
    ForwardedState {
        h1_remaining: h1_content_length,
        pending_h1_final: None,
        h1_source_done: false,
        data_done: false,
        trailers_done: false,
    }
}

fn poll_forwarded_h1_eof() {}
fn poll_forwarded_h1_fixed_final() {}

fn poll_forwarded_data() {
    poll_forwarded_h1_eof();
    poll_forwarded_h1_eof();
    poll_forwarded_h1_fixed_final();
    poll_forwarded_h1_fixed_final();
}

fn retained_listener() {
    let _: tokio_rustls::TlsAcceptor;
    let _ = Http::new().with_executor(H2StreamExecutor);
}

#[cfg(test)]
fn ignored_test_client() {
    hyper::client::conn::handshake(stream);
    tokio::net::TcpStream::connect(endpoint);
}
EOF

cat >"$BASELINE/src/proxy/h2_stream_cancellation.rs" <<'EOF'
tokio::task_local! {
    static CURRENT_H2_STREAM: H2StreamCancellation;
}

impl H2StreamCancellation {
    fn current() -> Option<Self> {
        CURRENT_H2_STREAM.try_with(Clone::clone).ok()
    }
}

impl<F> Executor<F> for H2StreamExecutor {
    fn execute(&self, future: F) {
        let cancellation = H2StreamCancellation(Arc::new(H2StreamCancellationState {
            cancelled: AtomicBool::new(false),
            changed: Notify::new(),
        }));
        let scoped_cancellation = cancellation.clone();
        drop(tokio::spawn(CURRENT_H2_STREAM.scope(
            scoped_cancellation,
            async move {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => {}
                    _ = future => {}
                }
            },
        )));
    }
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
trait WebhookDialer {
    type Stream;
}
struct SystemWebhookDialer;
impl WebhookDialer for SystemWebhookDialer {
    type Stream = tokio::net::TcpStream;

    fn connect() {
        tokio::net::TcpStream::connect(endpoint);
    }
}

trait WebhookResolver {}
struct SystemWebhookResolver;
impl WebhookResolver for SystemWebhookResolver {
    fn resolve() {
        tokio::net::lookup_host(endpoint);
    }
}
EOF

cat >"$BASELINE/src/authorization/webhook/provider.rs" <<'EOF'
use rustls::ClientConfig;
use crate::tls::{build_client_config, load_client_trust, ClientAlpn};

struct WebhookProvider {
    tls: Option<Arc<ClientConfig>>,
}

fn tls(provider: &WebhookProvider) -> Option<Arc<ClientConfig>> {
    provider.tls.clone()
}
EOF

cat >"$BASELINE/src/authorization/webhook/runtime.rs" <<'EOF'
struct WebhookAuthorizationRuntime;
EOF

cat >"$BASELINE/src/authorization/webhook/transport.rs" <<'EOF'
use tokio_rustls::TlsConnector;

async fn connect_and_deliver() {
    TlsConnector::from(config).connect(server_name, stream);
}
EOF

cat >"$BASELINE/src/tls.rs" <<'EOF'
use rustls::ClientConfig;
fn build_client_config() { let _: ClientConfig; }
fn client_config_builders() {
    let _: rustls::ClientConfig;
    let _: ClientConfig;
}
fn load_client_trust() {}
enum ClientAlpn { Http1 }
EOF

cat >"$BASELINE/access-runtime/crates/http-access-runtime/src/lib.rs" <<'EOF'
pub struct ManagedForwardingExecutor;

#[cfg(test)]
mod removed_api_tests;
EOF

cat >"$BASELINE/access-runtime/crates/http-access-runtime/src/removed_api_tests.rs" <<'EOF'
fn ignored() {
    let _: ManagedStreamTermination;
}
EOF

cat >"$BASELINE/src/lib.rs" <<'EOF'
#[cfg(test)]
mod test_only;

#[cfg(test)]
mod included_test_only {
    include!("included_test_only.rs");
}
EOF

cat >"$BASELINE/src/test_only.rs" <<'EOF'
fn ignored() {
    let _: ForwardingOutcome;
    let _: ForwardingExecutor;
    tokio::net::TcpStream::connect(endpoint);
}
EOF

cat >"$BASELINE/src/included_test_only.rs" <<'EOF'
fn ignored() {
    hyper::client::conn::handshake(stream);
}
EOF

runner() {
    local root=$1
    ACCESS_RUNTIME_ROOT="$root/access-runtime" \
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
    ForwardingDownstreamAbort \
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
    'adapter response-lifetime capability transfer ownership violation'

new_case
sed -i 's/        h1_content_length,/        None,/' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'missing H1 completion-length transfer' \
    'adapter response-lifetime capability transfer ownership violation'

new_case
sed -i 's/h1_remaining: h1_content_length/h1_remaining: None/' \
    "$CASE_ROOT/src/proxy/ingress.rs"
expect_failure "$CASE_ROOT" 'detached H1 completion-length binding' \
    'ingress H1 content-length completion binding ownership violation'

new_case
sed -i '/^fn poll_forwarded_h1_eof() {}$/d' "$CASE_ROOT/src/proxy/ingress.rs"
expect_failure "$CASE_ROOT" 'missing H1 EOF completion owner' \
    'ingress poll_forwarded_h1_eof completion owner ownership violation'

new_case
sed -i '/^fn poll_forwarded_h1_fixed_final() {}$/d' "$CASE_ROOT/src/proxy/ingress.rs"
expect_failure "$CASE_ROOT" 'missing H1 fixed-length completion owner' \
    'ingress poll_forwarded_h1_fixed_final completion owner ownership violation'

new_case
printf '%s\n' 'fn escaped() { let _ = pending_h1_final; }' >"$CASE_ROOT/src/bypass.rs"
expect_failure "$CASE_ROOT" 'escaped H1 completion state' \
    'response completion state pending_h1_final must remain confined non-vacuously to ingress.rs'

new_case
sed -i '/        complete_empty_response(&mut body).await/d' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'missing suppressed-body completion call' \
    'adapter suppressed-body completion owner ownership violation'

new_case
printf '%s\n' 'fn complete_empty_response() {}' >"$CASE_ROOT/src/bypass.rs"
expect_failure "$CASE_ROOT" 'escaped suppressed-body completion owner' \
    'adapter suppressed-body completion owner ownership violation'

new_case
printf '%s\n' 'fn complete_empty_h1_response() {}' >"$CASE_ROOT/src/bypass.rs"
expect_failure "$CASE_ROOT" 'restored H1-specific completion helper' \
    'the H1-specific empty-response completion helper must remain deleted'

new_case
sed -i '/impl ForwardingDownstreamAbort for ProductDownstreamAbort/d' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'missing downstream-abort implementation' \
    'adapter downstream-abort implementation ownership violation'

new_case
sed -i 's/self.0.cancel()/drop(self)/' "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'detached H2 stream cancellation' \
    'adapter exact H2 stream cancellation ownership violation'

new_case
sed -i 's/Http::new().with_executor(H2StreamExecutor)/Http::new()/' \
    "$CASE_ROOT/src/proxy/ingress.rs"
expect_failure "$CASE_ROOT" 'missing H2 stream executor installation' \
    'ingress exact H2 stream executor installation ownership violation'

new_case
sed -i 's/CURRENT_H2_STREAM.scope(/DETACHED_H2_STREAM.scope(/' \
    "$CASE_ROOT/src/proxy/h2_stream_cancellation.rs"
expect_failure "$CASE_ROOT" 'detached H2 task-local scope' \
    'H2 stream cancellation context ownership violation:'

new_case
sed -i '/                    biased;/d' \
    "$CASE_ROOT/src/proxy/h2_stream_cancellation.rs"
expect_failure "$CASE_ROOT" 'unprioritized H2 cancellation' \
    'H2 stream cancellation context ownership violation:'

new_case
sed -i 's/downstream_is_h2 == h2_stream_present/downstream_is_h2 \&\& h2_stream_present/' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'one-sided H2 context implication' \
    'adapter exact downstream-version/H2-context equivalence ownership violation'

new_case
sed -i '/if !h2_stream_context_matches/,+2d' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'removed fail-closed H2 context check' \
    'adapter fail-closed H2 context validation ownership violation'

new_case
sed -i '/with_downstream_abort/d' "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'missing shared downstream-abort transfer' \
    'adapter shared downstream-abort capability transfer ownership violation'

new_case
printf '%s\n' 'struct ProductDownstreamAbort;' >"$CASE_ROOT/src/bypass.rs"
expect_failure "$CASE_ROOT" 'escaped product downstream-abort owner' \
    'ProductDownstreamAbort must remain confined non-vacuously to forwarding_adapter.rs'

new_case
sed -i '/let handoff = ProductUpgradeHandoff::admit(runtime);/d' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'missing pre-connect upgrade admission' \
    'adapter pre-connect upgrade admission ownership violation'

new_case
sed -i '/with_upgrade_handoff/d' "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'missing admitted upgrade transfer' \
    'adapter admitted upgrade handoff transfer ownership violation'

new_case
sed -i '/runtime.try_spawn_handshake/d' "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
printf '%s\n' 'impl UpgradeHandoff for ProductUpgradeHandoff { fn prepare() { runtime.try_spawn_handshake(allocation, |_| async {}); } }' \
    >>"$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'upgrade admission moved into post-connect prepare' \
    'upgrade runtime admission must occur exactly once inside ProductUpgradeHandoff::admit'

new_case
sed -i '/let handoff = ProductUpgradeHandoff::admit(runtime);/d' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
sed -i '/let outcome = executor.execute/a\    let handoff = ProductUpgradeHandoff::admit(runtime);' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'upgrade admission after shared publication' \
    'downstream abort and admitted upgrade handoff must be installed before shared executor publication'

new_case
sed -i '/drain_suppressed_response(&mut body).await/d' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'missing suppressed response drain' \
    'adapter suppressed-body drain owner ownership violation'

new_case
printf '%s\n' 'fn drain_suppressed_response() {}' >"$CASE_ROOT/src/bypass.rs"
expect_failure "$CASE_ROOT" 'escaped suppressed response drain' \
    'adapter suppressed-body drain owner ownership violation'

new_case
sed -i 's/StatusCode::RESET_CONTENT.as_u16()/204/' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'inexact reset-content classification' \
    'adapter exact reset-content classification ownership violation'

new_case
sed -i 's/StatusCode::NO_CONTENT.as_u16()/204/' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'inexact no-content classification' \
    'adapter exact no-content classification ownership violation'

new_case
sed -i 's/ || no_content || reset_content/ || reset_content/' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'suppressed status content-length parse' \
    'adapter suppressed H1 content-length parse bypass ownership violation'

new_case
sed -i 's/downstream_is_head || no_content || reset_content ||/downstream_is_head ||/' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'reset content omitted from response suppression' \
    'adapter semantic response-body suppression selection ownership violation'

new_case
sed -i 's/ || head.status() == 304//' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'not-modified omitted from response suppression' \
    'adapter semantic response-body suppression selection ownership violation'

new_case
sed -i '/response.headers_mut().remove(CONTENT_LENGTH);/d' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'reset content retains original content length' \
    'adapter reset-content framing normalization ownership violation'

new_case
sed -i 's/HeaderValue::from_static("0")/HeaderValue::from_static("1")/' \
    "$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'reset content publishes nonzero content length' \
    'adapter reset-content framing normalization ownership violation'

for state in data_done trailers_done; do
    new_case
    printf '%s\n' "fn escaped() { let _ = $state; }" >"$CASE_ROOT/src/bypass.rs"
    expect_failure "$CASE_ROOT" "escaped response completion state $state" \
        "response completion state $state must remain confined non-vacuously to ingress.rs"
done

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
    '(std::net::TcpStream::connect)(endpoint);' \
    'let dial = std::net::TcpStream::connect; dial(endpoint);' \
    'std::net::TcpStream::connect_timeout(endpoint, timeout);' \
    '(std::net::TcpStream::connect_timeout)(endpoint, timeout);' \
    'let dial = std::net::TcpStream::connect_timeout; dial(endpoint, timeout);' \
    'std::net::TcpStream::connect(endpoint);' \
    '(std::os::unix::net::UnixStream::connect)(path);' \
    'let dial = std::os::unix::net::UnixStream::connect; dial(path);' \
    'type ProductSocket = std::net::TcpStream; fn dial() { ProductSocket::connect(endpoint); }' \
    'use std::net::TcpStream as ProductSocket; fn dial() { ProductSocket::connect(endpoint); }' \
    'use hyper as h; fn dial() { h::client::conn::handshake(stream); }' \
    'use hyper::{self as h}; fn dial() { h::client::conn::handshake(stream); }' \
    'extern crate hyper as h; fn dial() { h::Client::builder().build_http(); }' \
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

for owner in \
    src/tls.rs \
    src/authorization/webhook/transport.rs \
    src/authorization/webhook/provider.rs \
    src/authorization/webhook/runtime.rs
do
    for primitive in \
        'tokio::net::TcpStream::connect(endpoint);' \
        'hyper::client::conn::handshake(stream);'
    do
        new_case
        printf '%s\n' "$primitive" >>"$CASE_ROOT/$owner"
        expect_failure "$CASE_ROOT" "escaped client transport in $owner: $primitive" \
            'ordinary product forwarding must not own dialing, client TLS, or private Hyper client transport'
    done
done

new_case
printf '%s\n' 'tokio::net::TcpStream::connect(second_endpoint);' \
    >>"$CASE_ROOT/src/authorization/webhook/connector.rs"
expect_failure "$CASE_ROOT" 'second webhook dial site' \
    'ordinary product forwarding must not own dialing, client TLS, or private Hyper client transport'

new_case
printf '%s\n' 'tokio::net::lookup_host(second_endpoint);' \
    >>"$CASE_ROOT/src/authorization/webhook/connector.rs"
expect_failure "$CASE_ROOT" 'second webhook DNS site' \
    'ordinary product forwarding must not own dialing, client TLS, or private Hyper client transport'

new_case
printf '%s\n' 'TlsConnector::from(other_config).connect(server_name, stream);' \
    >>"$CASE_ROOT/src/authorization/webhook/transport.rs"
expect_failure "$CASE_ROOT" 'second webhook TLS connector site' \
    'ordinary product forwarding must not own dialing, client TLS, or private Hyper client transport'

new_case
sed -i '/        tokio::net::TcpStream::connect(endpoint);/d' \
    "$CASE_ROOT/src/authorization/webhook/connector.rs"
printf '%s\n' 'fn escaped_dial() { tokio::net::TcpStream::connect(endpoint); }' \
    >>"$CASE_ROOT/src/authorization/webhook/connector.rs"
expect_failure "$CASE_ROOT" 'webhook dial moved outside its sealed owner' \
    'ordinary product forwarding must not own dialing, client TLS, or private Hyper client transport'

new_case
sed -i '/        tokio::net::lookup_host(endpoint);/d' \
    "$CASE_ROOT/src/authorization/webhook/connector.rs"
printf '%s\n' 'fn escaped_resolve() { tokio::net::lookup_host(endpoint); }' \
    >>"$CASE_ROOT/src/authorization/webhook/connector.rs"
expect_failure "$CASE_ROOT" 'webhook DNS moved outside its sealed owner' \
    'ordinary product forwarding must not own dialing, client TLS, or private Hyper client transport'

new_case
sed -i '/    TlsConnector::from(config).connect(server_name, stream);/d' \
    "$CASE_ROOT/src/authorization/webhook/transport.rs"
printf '%s\n' \
    'fn escaped_tls() { TlsConnector::from(config).connect(server_name, stream); }' \
    >>"$CASE_ROOT/src/authorization/webhook/transport.rs"
expect_failure "$CASE_ROOT" 'webhook TLS moved outside its sealed owner' \
    'ordinary product forwarding must not own dialing, client TLS, or private Hyper client transport'

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

for owner in \
    src/authorization/webhook/transport.rs \
    src/authorization/webhook/provider.rs \
    src/authorization/webhook/runtime.rs
do
    new_case
    printf '%s\n' 'fn escaped(_: ForwardingPlan) {}' >>"$CASE_ROOT/$owner"
    expect_failure "$CASE_ROOT" "ordinary forwarding dependency in $owner" \
        'authorization webhook connector must remain independent of ordinary forwarding ownership'
done

for obsolete in \
    AuditedManagedRedemption \
    ConnectionBoundManagedRedemption \
    ManagedRedemptionFailure \
    CredentializedManagedConnection \
    ManagedFirstOriginWrite \
    ManagedConnection \
    ManagedSecureConnector \
    ManagedFirstWriteTransport \
    ManagedPostWriteConnection \
    ManagedStreamLease \
    ManagedStreamLeaseFailure \
    ManagedStreamTerminationReason \
    ManagedStreamTermination
do
    new_case
    printf '%s\n' "struct $obsolete;" \
        >>"$CASE_ROOT/access-runtime/crates/http-access-runtime/src/lib.rs"
    expect_failure "$CASE_ROOT" "restored obsolete managed type $obsolete" \
        'obsolete P09 managed forwarding API must remain deleted'
done

new_case
printf '%s\n' 'fn restored() { ManagedConnectionEvidence::new(); }' \
    >>"$CASE_ROOT/access-runtime/crates/http-access-runtime/src/lib.rs"
expect_failure "$CASE_ROOT" 'restored caller-constructible managed evidence' \
    'obsolete P09 managed forwarding API must remain deleted'

for adoption in \
    'use http_access_runtime::ManagedForwardingExecutor;' \
    'fn adopt() { ManagedForwardingExecutor::execute(plan, request, services, resources); }' \
    'fn adopt(_: HostEnforcer) {}' \
    'fn adopt(_: ValidatedManagedPlan) {}'
do
    new_case
    printf '%s\n' "$adoption" >"$CASE_ROOT/src/managed_adoption.rs"
    expect_failure "$CASE_ROOT" "premature managed execution adoption $adoption" \
        'acl-proxy must not adopt managed forwarding execution before P12'
done

new_case
cat >"$CASE_ROOT/src/production_transport_tests.rs" <<'EOF'
fn dial() {
    tokio::net::TcpStream::connect(endpoint);
}
EOF
printf '%s\n' 'mod production_transport_tests;' >>"$CASE_ROOT/src/lib.rs"
expect_failure "$CASE_ROOT" 'unconditional product tests-suffixed transport module' \
    'ordinary product forwarding must not own dialing, client TLS, or private Hyper client transport'

new_case
cat >"$CASE_ROOT/src/production_transport_tests.rs" <<'EOF'
fn dial() {
    tokio::net::TcpStream::connect(endpoint);
}
EOF
printf '%s\n' 'include!("production_transport_tests.rs");' >>"$CASE_ROOT/src/lib.rs"
expect_failure "$CASE_ROOT" 'unconditional product tests-suffixed transport include' \
    'ordinary product forwarding must not own dialing, client TLS, or private Hyper client transport'

new_case
cat >"$CASE_ROOT/access-runtime/crates/http-access-runtime/src/production_managed_tests.rs" <<'EOF'
pub struct ManagedStreamTermination;
EOF
printf '%s\n' 'mod production_managed_tests;' \
    >>"$CASE_ROOT/access-runtime/crates/http-access-runtime/src/lib.rs"
expect_failure "$CASE_ROOT" 'unconditional runtime tests-suffixed obsolete module' \
    'obsolete P09 managed forwarding API must remain deleted'

new_case
cat >"$CASE_ROOT/access-runtime/crates/http-access-runtime/src/production_managed_tests.rs" <<'EOF'
pub struct ManagedStreamTermination;
EOF
printf '%s\n' 'include!("production_managed_tests.rs");' \
    >>"$CASE_ROOT/access-runtime/crates/http-access-runtime/src/lib.rs"
expect_failure "$CASE_ROOT" 'unconditional runtime tests-suffixed obsolete include' \
    'obsolete P09 managed forwarding API must remain deleted'

new_case
printf '%s\n' 'use crate::authorization::webhook::connector::WebhookConnector;' \
    >>"$CASE_ROOT/src/proxy/forwarding_adapter.rs"
expect_failure "$CASE_ROOT" 'adapter webhook dependency' \
    'ordinary egress and forwarding adapter owners must not reference the authorization webhook connector'

printf 'shared forwarding adapter ownership mutation tests passed (%d mutations)\n' "$mutations"
