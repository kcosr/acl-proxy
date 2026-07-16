#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
RUNTIME_SOURCE="$SOURCE_ROOT/../access-runtime"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/shared-header-ownership-test.XXXXXX")
cleanup() {
    rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

BASE_PARENT="$TEST_ROOT/baseline"
PRODUCT="$BASE_PARENT/acl-proxy"
SHARED="$BASE_PARENT/access-runtime"
mkdir -p "$PRODUCT/scripts" "$PRODUCT/src/config" "$PRODUCT/src/proxy" \
    "$SHARED/crates/http-access-runtime/src" "$TEST_ROOT/fake-bin"
cp "$SOURCE_ROOT/scripts/check-shared-header-ownership.sh" "$PRODUCT/scripts/"

cat >"$SHARED/crates/http-access-runtime/src/lib.rs" <<'EOF'
mod header_hygiene;
mod private_transport;
EOF
cat >"$SHARED/crates/http-access-runtime/src/private_transport.rs" <<'EOF'
use rustls::RootCertStore;
fn private_transport(_: RootCertStore) {}
EOF
cat >"$SHARED/crates/http-access-runtime/src/header_hygiene.rs" <<'EOF'
use std::fmt;

pub enum HeaderHygieneError { Invalid }
pub struct SanitizedRequestHead;
pub struct SanitizedConnectRequestHead;
pub enum PreparedRequestTargetForm { Origin }
pub struct PreparedRequestTarget;
pub struct PreparedRequestHead;

pub fn sanitize_request_head() {}
pub fn sanitize_connect_request_head() {}
pub fn prepare_request_head() {}
pub fn prepare_upgrade_request_head() {}
pub fn sanitize_response_headers() {}
pub fn prepare_upgrade_response_headers() {}
pub fn validate_header_projection() {}
pub fn prepartition_connection_nominations() {}
pub fn is_prepartition_caller_credential_header() {}

#[cfg(test)]
mod tests {
    #[test] fn request_hygiene_derives_h1_and_h2_targets() {}
    #[test] fn h2_te_is_strict_and_protocol_translation_is_exact() {}
    #[test] fn attacker_nominations_precede_trusted_changes_and_hop_injection_fails() {}
    #[test] fn upgrades_preserve_request_spelling_and_validate_response() {}
    #[test] fn connect_and_connection_token_errors_fail_closed() {}
    #[test] fn response_cleanup_tolerates_bad_nominations_and_bounds_are_enforced() {}
    use hyper::Body;
    fn test_transport(_: Body) {}
}

const TEXT: &str = "hyper::Body http::Request tokio::spawn";
// rustls::RootCertStore
EOF

cat >"$PRODUCT/src/lib.rs" <<'EOF'
mod config;
mod credential_resolver;
mod proxy;
mod unrelated;
EOF
cat >"$PRODUCT/src/config/mod.rs" <<'EOF'
mod compiler;
EOF
cat >"$PRODUCT/src/config/compiler.rs" <<'EOF'
fn base_protected_headers() {
    let _ = "connection";
}
EOF
cat >"$PRODUCT/src/credential_resolver.rs" <<'EOF'
use http_access_runtime::validate_header_projection;

fn validate_final_header_projection() {
    validate_header_projection();
}
EOF
cat >"$PRODUCT/src/proxy/mod.rs" <<'EOF'
mod facts;
mod forward;
mod headers;
EOF
cat >"$PRODUCT/src/proxy/facts.rs" <<'EOF'
use http_access_runtime::{
    is_prepartition_caller_credential_header, prepartition_connection_nominations,
    validate_header_projection,
};

struct PartitionPolicy;
impl PartitionPolicy { fn from_lease() {} }
struct StandaloneIngress;
impl StandaloneIngress {
    fn protocol() {}
    fn ingress() {}
    fn into_parts() {}
}
struct FactShape;
impl FactShape { fn into_facts() {} }

fn validate_standalone_ingress_request() {}
fn validate_standalone_connect_ingress_request() {}

fn partition_ingress_headers() {
    prepartition_connection_nominations();
    is_prepartition_caller_credential_header();
}

fn validate_raw_ingress_headers() {
    validate_header_projection();
}

fn partition_internal_context() {}
fn http_version() {}
fn http_method() {}
fn neutral_headers() {}
fn product_headers() {}
fn apply_response_mutations() {}
fn body_metadata() {}
fn single_content_length() {}
fn upgrade_intent() {}
fn validate_request_fact_shape() {}
EOF
cat >"$PRODUCT/src/proxy/headers.rs" <<'EOF'
use http::{HeaderMap, Uri};
use http_access_runtime::{
    prepare_upgrade_response_headers, sanitize_connect_request_head,
    sanitize_request_head, sanitize_response_headers,
};

struct OrdinaryIngress;
impl OrdinaryIngress {
    fn ingress_protocol() {}
    fn upgrade_protocol() {}
    fn into_parts() {}
}
struct PendingRequest;
impl PendingRequest {
    fn head() {}
    fn into_parts() {}
}
struct ConnectIngress;
impl ConnectIngress {
    fn head() {}
    fn into_parts() {}
}

fn sanitize_untrusted_ingress_request() {}

fn sanitize_product_request(request: &mut hyper::Request<()>) {
    let _: hyper::upgrade::OnUpgrade = hyper::upgrade::on(request);
    let _: HeaderMap = HeaderMap::new();
    let _: Uri = "/".parse().unwrap();
    sanitize_request_head();
}

fn sanitize_untrusted_connect_ingress_request() {
    sanitize_connect_request_head();
}

fn sanitize_product_response_headers() {
    sanitize_response_headers();
}

fn prepare_product_upgrade_response() {
    prepare_upgrade_response_headers();
}

fn neutral_version() {}
fn product_protocol() {}
fn neutral_method() {}
fn neutral_headers() {}
fn product_headers() {}
fn replace_sanitized_headers() {}
fn apply_prepared_head() {}

#[cfg(test)]
mod tests {
    #[test] fn ingress_adapter_preserves_body_extensions_and_upgrade_owner() {}
    #[test] fn neutral_product_conversion_preserves_duplicate_order() {}
    struct SanitizedRequest;
    fn strip_hop_by_hop() {}
}

const TEXT: &str = "CONNECTION split trim canonical_path_and_query";
// use http::header::UPGRADE;
EOF
cat >"$PRODUCT/src/proxy/forward.rs" <<'EOF'
use http_access_runtime::{prepare_request_head, prepare_upgrade_request_head};

fn send_request() {
    prepare_request_head();
}

fn send_upgrade_request() {
    prepare_upgrade_request_head();
}
EOF
cat >"$PRODUCT/src/unrelated.rs" <<'EOF'
fn unrelated() {}
EOF

REAL_CARGO=$(command -v cargo)
export REAL_CARGO
cat >"$TEST_ROOT/fake-bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} != metadata ]]; then
    exec "$REAL_CARGO" "$@"
fi
python3 - "$PWD" "${FAKE_METADATA_MODE:-valid}" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
mode = sys.argv[2]
kind = None
path = root.parent / "access-runtime" / "crates" / "http-access-runtime"
version = "=0.1.0"
rename = None
include = True
if mode == "missing":
    include = False
elif mode == "dev":
    kind = "dev"
elif mode == "wrong-path":
    path = root.parent / "access-runtime" / "crates" / "http-access-types"
elif mode == "loose-version":
    version = "0.1.0"
elif mode == "renamed":
    rename = "shared-runtime"
elif mode != "valid":
    raise SystemExit(f"unknown metadata mode: {mode}")

dependencies = []
if include:
    dependencies.append({
        "name": "http-access-runtime",
        "kind": kind,
        "path": str(path),
        "req": version,
        "rename": rename,
    })
json.dump({"packages": [{"name": "acl-proxy", "dependencies": dependencies}]}, sys.stdout)
PY
EOF
chmod +x "$TEST_ROOT/fake-bin/cargo"

runner() {
    local root=$1
    PATH="$TEST_ROOT/fake-bin:$PATH" \
        ACCESS_RUNTIME_ROOT="$root/../access-runtime" \
        PIPELINE_OWNERSHIP_CHECK_MANIFEST="$RUNTIME_SOURCE/Cargo.toml" \
        "$root/scripts/check-shared-header-ownership.sh"
}

runner "$PRODUCT" >"$TEST_ROOT/pass.log"
grep -Fq 'shared header ownership/deletion and moved-test gate passed' "$TEST_ROOT/pass.log"

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

expect_success() {
    local root=$1
    local description=$2
    if ! runner "$root" >"$TEST_ROOT/pass.log" 2>&1; then
        printf '%s was rejected\n' "$description" >&2
        cat "$TEST_ROOT/pass.log" >&2
        exit 1
    fi
}

case_index=0
product_type_mutations=(
    'enum RequestTargetForm { Origin }'
    'enum HeaderPreparationError { Invalid }'
    'struct SanitizedRequest;'
    'struct UpgradeIntent;'
    'struct PreparedRequestHead;'
)
for mutation in "${product_type_mutations[@]}"; do
    case_index=$((case_index + 1))
    case_parent="$TEST_ROOT/product-type-$case_index"
    cp -R "$BASE_PARENT" "$case_parent"
    printf '\n%s\n' "$mutation" >>"$case_parent/acl-proxy/src/unrelated.rs"
    expect_failure "$case_parent/acl-proxy" "product type mutation: $mutation" \
        'product header ownership/deletion violations:'
done

legacy_functions=(
    sanitize_untrusted_request sanitize_untrusted_connect_request extract_upgrade_intent
    single_upgrade_protocol valid_upgrade_protocol is_http_token
    strict_connection_header_tokens connection_header_tokens strip_request_hop_by_hop
    strip_response_hop_by_hop strip_hop_by_hop te_is_trailers_only validate_h2_te
    canonical_path_and_query is_hop_by_hop prepare_origin_request
    prepare_origin_upgrade_request prepare_origin_request_head
    prepare_downstream_upgrade_response
)
for function in "${legacy_functions[@]}"; do
    case_index=$((case_index + 1))
    case_parent="$TEST_ROOT/product-function-$case_index"
    cp -R "$BASE_PARENT" "$case_parent"
    printf '\nfn %s() {}\n' "$function" >>"$case_parent/acl-proxy/src/unrelated.rs"
    expect_failure "$case_parent/acl-proxy" "legacy product function: $function" \
        'obsolete product header function definition is forbidden'
done

for operation in \
    sanitize_request_head sanitize_connect_request_head prepare_request_head \
    prepare_upgrade_request_head sanitize_response_headers prepare_upgrade_response_headers \
    validate_header_projection prepartition_connection_nominations \
    is_prepartition_caller_credential_header
do
    case_index=$((case_index + 1))
    case_parent="$TEST_ROOT/impl-definition-$case_index"
    cp -R "$BASE_PARENT" "$case_parent"
    printf '\nstruct Escape; impl Escape { fn %s() {} }\n' "$operation" \
        >>"$case_parent/acl-proxy/src/unrelated.rs"
    expect_failure "$case_parent/acl-proxy" "impl operation definition: $operation" \
        'product must not define shared header operation'

    case_index=$((case_index + 1))
    case_parent="$TEST_ROOT/trait-definition-$case_index"
    cp -R "$BASE_PARENT" "$case_parent"
    printf '\ntrait Escape { fn %s(); }\n' "$operation" \
        >>"$case_parent/acl-proxy/src/unrelated.rs"
    expect_failure "$case_parent/acl-proxy" "trait operation definition: $operation" \
        'product must not define shared header operation'
done

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/associated-legacy-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\nstruct Escape; impl Escape { fn strip_hop_by_hop() {} }\n' \
    >>"$case_parent/acl-proxy/src/unrelated.rs"
expect_failure "$case_parent/acl-proxy" 'associated legacy header definition' \
    'obsolete product header function definition is forbidden'

adapter_mutations=(
    'use http::header::CONNECTION;'
    'use http::header::{TE, UPGRADE};'
    'use std::collections::HashSet;'
    'use std::collections::BTreeSet;'
    'use http_access_types::CanonicalUrl;'
    'fn parser(value: &str) { let _ = value.split(","); }'
    'fn parser(value: &str) { let _ = value.trim(); }'
    'fn parser(value: &str) { let _ = value.eq_ignore_ascii_case("upgrade"); }'
    'fn parser(value: u8) { let _ = value.is_ascii_alphanumeric(); }'
)
for mutation in "${adapter_mutations[@]}"; do
    case_index=$((case_index + 1))
    case_parent="$TEST_ROOT/adapter-$case_index"
    cp -R "$BASE_PARENT" "$case_parent"
    printf '\n%s\n' "$mutation" >>"$case_parent/acl-proxy/src/proxy/headers.rs"
    expect_failure "$case_parent/acl-proxy" "semantic adapter mutation: $mutation" \
        'product header ownership/deletion violations:'
done

semantic_move_mutations=(
    'use http::header::CONNECTION; fn cleanse(headers: &mut HeaderMap) { headers.remove(CONNECTION); }'
    'fn cleanse(headers: &mut HeaderMap) { headers.remove("connection"); }'
    'const HOP: &str = "connection"; fn cleanse(headers: &mut HeaderMap) { headers.remove(HOP); }'
    'const HOP: &[u8] = b"upgrade"; fn cleanse(headers: &mut HeaderMap) { headers.remove(HOP); }'
    'fn hop() -> HeaderName { HeaderName::from_static("connection") } fn cleanse(headers: &mut HeaderMap) { headers.remove(hop()); }'
    'fn cleanse(headers: &mut HeaderMap) { headers.remove(HeaderName::from_static(concat!("connec", "tion"))); }'
    'fn cleanse(headers: &mut HeaderMap) { headers.remove(HeaderName::from_static(stringify!(connection))); }'
    'macro_rules! cleanse { ($headers:expr) => { $headers.remove(http::header::UPGRADE); }; }'
)
for mutation in "${semantic_move_mutations[@]}"; do
    case_index=$((case_index + 1))
    case_parent="$TEST_ROOT/semantic-move-$case_index"
    cp -R "$BASE_PARENT" "$case_parent"
    printf '\n%s\n' "$mutation" >>"$case_parent/acl-proxy/src/unrelated.rs"
    expect_failure "$case_parent/acl-proxy" "moved new-named header semantics: $mutation" \
        'product header ownership/deletion violations:'
done

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/facts-parallel-parser-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\nfn escaped_connection_parser(value: &[u8]) { let _ = value.split(|byte| *byte == 44).count(); }\n' \
    >>"$case_parent/acl-proxy/src/proxy/facts.rs"
expect_failure "$case_parent/acl-proxy" 'parallel parser in arbitrary facts function' \
    'outside an exact residual parser owner uses semantic parser method .split()'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/facts-new-helper-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\nfn arbitrary_new_helper() {}\n' >>"$case_parent/acl-proxy/src/proxy/facts.rs"
expect_failure "$case_parent/acl-proxy" 'new facts free helper' \
    'src/proxy/facts.rs active production callable inventory changed'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/headers-new-helper-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\nfn arbitrary_new_helper() {}\n' >>"$case_parent/acl-proxy/src/proxy/headers.rs"
expect_failure "$case_parent/acl-proxy" 'new headers free helper' \
    'src/proxy/headers.rs active production callable inventory changed'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/facts-missing-helper-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
sed -i '/^fn http_method() {}$/d' "$case_parent/acl-proxy/src/proxy/facts.rs"
expect_failure "$case_parent/acl-proxy" 'missing required facts helper' \
    'src/proxy/facts.rs active production callable inventory changed'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/facts-associated-helper-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\nstruct AssociatedEscape; impl AssociatedEscape { fn helper() {} }\n' \
    >>"$case_parent/acl-proxy/src/proxy/facts.rs"
expect_failure "$case_parent/acl-proxy" 'new facts associated helper' \
    'src/proxy/facts.rs active production callable inventory changed'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/facts-trait-helper-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\ntrait TraitEscape { fn helper(); }\n' \
    >>"$case_parent/acl-proxy/src/proxy/facts.rs"
expect_failure "$case_parent/acl-proxy" 'new facts trait helper' \
    'src/proxy/facts.rs active production callable inventory changed'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/facts-macro-helper-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\nmacro_rules! make_helper { () => { fn helper() {} }; }\n' \
    >>"$case_parent/acl-proxy/src/proxy/facts.rs"
expect_failure "$case_parent/acl-proxy" 'macro-generated facts helper' \
    'owned product header/facts file invokes a non-audited macro: macro_rules'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/facts-target-disabled-helper-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\n#[cfg(target_os = "windows")] fn inactive_helper() {}\n' \
    >>"$case_parent/acl-proxy/src/proxy/facts.rs"
expect_success "$case_parent/acl-proxy" 'target-disabled facts helper'

operations=(
    sanitize_request_head sanitize_connect_request_head prepare_request_head
    prepare_upgrade_request_head sanitize_response_headers prepare_upgrade_response_headers
    validate_header_projection prepartition_connection_nominations
    is_prepartition_caller_credential_header
)
for operation in "${operations[@]}"; do
    case_index=$((case_index + 1))
    case_parent="$TEST_ROOT/escaped-call-$case_index"
    cp -R "$BASE_PARENT" "$case_parent"
    printf '\nfn escaped() { http_access_runtime::%s(); }\n' "$operation" \
        >>"$case_parent/acl-proxy/src/unrelated.rs"
    expect_failure "$case_parent/acl-proxy" "escaped shared call: $operation" \
        'called outside its adapter owner'

    case_index=$((case_index + 1))
    case_parent="$TEST_ROOT/escaped-parenthesized-call-$case_index"
    cp -R "$BASE_PARENT" "$case_parent"
    printf '\nfn escaped() { (http_access_runtime::%s)(); }\n' "$operation" \
        >>"$case_parent/acl-proxy/src/unrelated.rs"
    expect_failure "$case_parent/acl-proxy" "parenthesized escaped shared call: $operation" \
        'called outside its adapter owner'

    case_index=$((case_index + 1))
    case_parent="$TEST_ROOT/escaped-reference-$case_index"
    cp -R "$BASE_PARENT" "$case_parent"
    printf '\nfn escaped() { let _call = http_access_runtime::%s; }\n' "$operation" \
        >>"$case_parent/acl-proxy/src/unrelated.rs"
    expect_failure "$case_parent/acl-proxy" "escaped shared reference: $operation" \
        'referenced outside its adapter owner'

    case_index=$((case_index + 1))
    case_parent="$TEST_ROOT/escaped-macro-call-$case_index"
    cp -R "$BASE_PARENT" "$case_parent"
    printf '\nmacro_rules! escaped { () => { http_access_runtime::%s(); }; }\n' "$operation" \
        >>"$case_parent/acl-proxy/src/unrelated.rs"
    expect_failure "$case_parent/acl-proxy" "macro escaped shared call: $operation" \
        'referenced outside its adapter owner'

    case_index=$((case_index + 1))
    case_parent="$TEST_ROOT/missing-call-$case_index"
    cp -R "$BASE_PARENT" "$case_parent"
    sed -i "/^[[:space:]]*$operation();$/d" \
        "$case_parent/acl-proxy/src/credential_resolver.rs" \
        "$case_parent/acl-proxy/src/proxy/facts.rs" \
        "$case_parent/acl-proxy/src/proxy/headers.rs" \
        "$case_parent/acl-proxy/src/proxy/forward.rs"
    expect_failure "$case_parent/acl-proxy" "missing shared call: $operation" \
        "shared header operation $operation must have exactly its active product calls"

    case_index=$((case_index + 1))
    case_parent="$TEST_ROOT/dead-call-$case_index"
    cp -R "$BASE_PARENT" "$case_parent"
    sed -i "/^[[:space:]]*$operation();$/d" \
        "$case_parent/acl-proxy/src/credential_resolver.rs" \
        "$case_parent/acl-proxy/src/proxy/facts.rs" \
        "$case_parent/acl-proxy/src/proxy/headers.rs" \
        "$case_parent/acl-proxy/src/proxy/forward.rs"
    case "$operation" in
        sanitize_request_head|sanitize_connect_request_head|sanitize_response_headers|prepare_upgrade_response_headers)
            dead_owner="$case_parent/acl-proxy/src/proxy/headers.rs"
            ;;
        prepare_request_head|prepare_upgrade_request_head)
            dead_owner="$case_parent/acl-proxy/src/proxy/forward.rs"
            ;;
        validate_header_projection)
            dead_owner="$case_parent/acl-proxy/src/credential_resolver.rs"
            ;;
        prepartition_connection_nominations|is_prepartition_caller_credential_header)
            dead_owner="$case_parent/acl-proxy/src/proxy/facts.rs"
            ;;
    esac
    printf '\nfn dead_adoption() { %s(); }\n' "$operation" >>"$dead_owner"
    expect_failure "$case_parent/acl-proxy" "dead shared call: $operation" \
        'called outside its adapter owner'
done

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/target-disabled-call-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
sed -i 's/    sanitize_request_head();/    #[cfg(target_os = "windows")] sanitize_request_head();/' \
    "$case_parent/acl-proxy/src/proxy/headers.rs"
expect_failure "$case_parent/acl-proxy" 'target-disabled required adoption call' \
    'shared header operation sanitize_request_head must have exactly its active product calls'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/residual-owner-helper-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\nfn escaped_residual_helper() { let _ = "connection"; }\n' \
    >>"$case_parent/acl-proxy/src/config/compiler.rs"
expect_failure "$case_parent/acl-proxy" 'hop literal outside exact residual function' \
    'contains hop-header literal'

for owner in credential facts; do
    case_index=$((case_index + 1))
    case_parent="$TEST_ROOT/missing-projection-owner-$case_index"
    cp -R "$BASE_PARENT" "$case_parent"
    if [[ $owner == credential ]]; then
        projection_source="$case_parent/acl-proxy/src/credential_resolver.rs"
    else
        projection_source="$case_parent/acl-proxy/src/proxy/facts.rs"
    fi
    sed -i '/^[[:space:]]*validate_header_projection();$/d' "$projection_source"
    expect_failure "$case_parent/acl-proxy" "missing $owner projection owner" \
        'shared header operation validate_header_projection must have exactly its active product calls'
done

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/allowed-parenthesized-call-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
sed -i 's/    sanitize_request_head();/    (sanitize_request_head)();/' \
    "$case_parent/acl-proxy/src/proxy/headers.rs"
expect_success "$case_parent/acl-proxy" 'allowed parenthesized shared call'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/renamed-import-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
sed -i 's/sanitize_request_head, sanitize_response_headers/sanitize_request_head as hidden, sanitize_response_headers/' \
    "$case_parent/acl-proxy/src/proxy/headers.rs"
expect_failure "$case_parent/acl-proxy" 'renamed shared operation import' \
    'shared header operation import must not be renamed'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/glob-import-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\nuse http_access_runtime::*;\n' >>"$case_parent/acl-proxy/src/proxy/headers.rs"
expect_failure "$case_parent/acl-proxy" 'glob shared runtime import' \
    'glob imports from http_access_runtime are not ownership-audited'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/product-include-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\ninclude!("included_escape.rs");\n' >>"$case_parent/acl-proxy/src/lib.rs"
printf 'fn strip_hop_by_hop() {}\n' >"$case_parent/acl-proxy/src/included_escape.rs"
expect_failure "$case_parent/acl-proxy" 'product include source escape' \
    'production include! source is not ownership-audited'

transport_roots=(http http_body hyper h2 tokio tokio_rustls rustls)
for root in "${transport_roots[@]}"; do
    for mutation in \
        "use $root::Transport;" \
        "fn escaped(_: $root::Transport) {}" \
        "use $root as transport;" \
        "macro_rules! escaped { () => { $root::Transport }; }"
    do
        case_index=$((case_index + 1))
        case_parent="$TEST_ROOT/shared-transport-$case_index"
        cp -R "$BASE_PARENT" "$case_parent"
        printf '\n%s\n' "$mutation" \
            >>"$case_parent/access-runtime/crates/http-access-runtime/src/header_hygiene.rs"
        expect_failure "$case_parent/acl-proxy" "shared transport mutation: $mutation" \
            'shared header hygiene boundary violations:'
    done
done
for mutation in 'use std::io::Read;' 'use std::net::TcpStream;'; do
    case_index=$((case_index + 1))
    case_parent="$TEST_ROOT/shared-std-transport-$case_index"
    cp -R "$BASE_PARENT" "$case_parent"
    printf '\n%s\n' "$mutation" \
        >>"$case_parent/access-runtime/crates/http-access-runtime/src/header_hygiene.rs"
    expect_failure "$case_parent/acl-proxy" "shared standard transport mutation: $mutation" \
        'shared header hygiene boundary violations:'
done

shared_alias_mutations=(
    'extern crate hyper as transport;'
    'pub use hyper as transport;'
    'pub(crate) use hyper::Body as TransportBody;'
    'pub use hyper::*;'
)
for mutation in "${shared_alias_mutations[@]}"; do
    case_index=$((case_index + 1))
    case_parent="$TEST_ROOT/shared-alias-$case_index"
    cp -R "$BASE_PARENT" "$case_parent"
    printf '\n%s\n' "$mutation" \
        >>"$case_parent/access-runtime/crates/http-access-runtime/src/private_transport.rs"
    expect_failure "$case_parent/acl-proxy" "shared transport alias/re-export: $mutation" \
        'shared header hygiene boundary violations:'
done

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/cross-module-use-alias-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\nuse hyper as transport;\n' \
    >>"$case_parent/access-runtime/crates/http-access-runtime/src/lib.rs"
printf '\nuse crate::transport::Body; fn escaped(_: Body) {}\n' \
    >>"$case_parent/access-runtime/crates/http-access-runtime/src/header_hygiene.rs"
expect_failure "$case_parent/acl-proxy" 'cross-module transport use alias' \
    'shared header hygiene reaches transport through alias transport'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/cross-module-extern-alias-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\nextern crate hyper as transport;\n' \
    >>"$case_parent/access-runtime/crates/http-access-runtime/src/lib.rs"
printf '\nuse crate::transport::Body; fn escaped(_: Body) {}\n' \
    >>"$case_parent/access-runtime/crates/http-access-runtime/src/header_hygiene.rs"
expect_failure "$case_parent/acl-proxy" 'cross-module extern-crate transport alias' \
    'shared runtime must not use extern crate transport alias'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/shared-wrapper-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\npub struct NeutralHeader(pub RootCertStore);\n' \
    >>"$case_parent/access-runtime/crates/http-access-runtime/src/private_transport.rs"
printf '\nuse crate::private_transport::NeutralHeader; fn escaped(_: NeutralHeader) {}\n' \
    >>"$case_parent/access-runtime/crates/http-access-runtime/src/header_hygiene.rs"
expect_failure "$case_parent/acl-proxy" 'crate-local shared transport wrapper' \
    'shared header hygiene must not depend on crate-local modules'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/shared-macro-std-transport-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\nmacro_rules! escaped_transport { () => { std::net::TcpStream }; }\n' \
    >>"$case_parent/access-runtime/crates/http-access-runtime/src/header_hygiene.rs"
expect_failure "$case_parent/acl-proxy" 'shared macro std transport escape' \
    'shared header hygiene macro references std::io or std::net transport types'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/shared-local-macro-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\nmacro_rules! local_helper { ($value:expr) => { $value }; }\n' \
    >>"$case_parent/access-runtime/crates/http-access-runtime/src/header_hygiene.rs"
expect_failure "$case_parent/acl-proxy" 'shared local macro definition' \
    'shared header hygiene must not define production macros'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/shared-parameterized-macro-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\ntransport_path!(transport);\n' \
    >>"$case_parent/access-runtime/crates/http-access-runtime/src/header_hygiene.rs"
expect_failure "$case_parent/acl-proxy" 'shared parameterized transport macro invocation' \
    'shared header hygiene invokes a non-audited macro: transport_path'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/duplicate-shared-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
printf '\npub fn sanitize_request_head() {}\n' \
    >>"$case_parent/access-runtime/crates/http-access-runtime/src/private_transport.rs"
expect_failure "$case_parent/acl-proxy" 'duplicate shared operation definition' \
    'must have exactly one production definition'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/missing-moved-test-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
sed -i '/request_hygiene_derives_h1_and_h2_targets/d' \
    "$case_parent/access-runtime/crates/http-access-runtime/src/header_hygiene.rs"
expect_failure "$case_parent/acl-proxy" 'missing moved runtime test' \
    'missing moved shared header test case:'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/helper-not-test-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
sed -i 's/#\[test\] fn request_hygiene_derives_h1_and_h2_targets()/fn request_hygiene_derives_h1_and_h2_targets()/' \
    "$case_parent/access-runtime/crates/http-access-runtime/src/header_hygiene.rs"
expect_failure "$case_parent/acl-proxy" 'helper function spoofing moved runtime test' \
    'missing moved shared header test case:'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/ignored-moved-test-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
sed -i 's/#\[test\] fn request_hygiene_derives_h1_and_h2_targets()/#[test] #[ignore] fn request_hygiene_derives_h1_and_h2_targets()/' \
    "$case_parent/access-runtime/crates/http-access-runtime/src/header_hygiene.rs"
expect_failure "$case_parent/acl-proxy" 'ignored moved runtime test' \
    'missing moved shared header test case:'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/cfg-disabled-moved-test-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
sed -i 's/#\[test\] fn request_hygiene_derives_h1_and_h2_targets()/#[cfg(any())] #[test] fn request_hygiene_derives_h1_and_h2_targets()/' \
    "$case_parent/access-runtime/crates/http-access-runtime/src/header_hygiene.rs"
expect_failure "$case_parent/acl-proxy" 'cfg-disabled moved runtime test' \
    'missing moved shared header test case:'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/cfg-attr-ignored-moved-test-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
sed -i 's/#\[test\] fn request_hygiene_derives_h1_and_h2_targets()/#[cfg_attr(test, ignore)] #[test] fn request_hygiene_derives_h1_and_h2_targets()/' \
    "$case_parent/access-runtime/crates/http-access-runtime/src/header_hygiene.rs"
expect_failure "$case_parent/acl-proxy" 'cfg-attr ignored moved runtime test' \
    'missing moved shared header test case:'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/target-disabled-moved-test-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
sed -i 's/#\[test\] fn request_hygiene_derives_h1_and_h2_targets()/#[cfg(target_os = "windows")] #[test] fn request_hygiene_derives_h1_and_h2_targets()/' \
    "$case_parent/access-runtime/crates/http-access-runtime/src/header_hygiene.rs"
expect_failure "$case_parent/acl-proxy" 'current-target-disabled moved runtime test' \
    'missing moved shared header test case:'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/missing-adapter-test-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
sed -i '/neutral_product_conversion_preserves_duplicate_order/d' \
    "$case_parent/acl-proxy/src/proxy/headers.rs"
expect_failure "$case_parent/acl-proxy" 'missing retained adapter test' \
    'missing retained product header adapter test case:'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/ignored-adapter-test-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
sed -i 's/#\[test\] fn neutral_product_conversion_preserves_duplicate_order()/#[test] #[ignore] fn neutral_product_conversion_preserves_duplicate_order()/' \
    "$case_parent/acl-proxy/src/proxy/headers.rs"
expect_failure "$case_parent/acl-proxy" 'ignored retained adapter test' \
    'missing retained product header adapter test case:'

case_index=$((case_index + 1))
case_parent="$TEST_ROOT/obsolete-product-test-$case_index"
cp -R "$BASE_PARENT" "$case_parent"
sed -i '/mod tests {/a\    #[test] fn h1_parent_uses_exact_absolute_form() {}' \
    "$case_parent/acl-proxy/src/proxy/headers.rs"
expect_failure "$case_parent/acl-proxy" 'obsolete product semantic test' \
    'obsolete product-owned header semantic test remains:'

for mode in missing dev wrong-path loose-version renamed; do
    if FAKE_METADATA_MODE="$mode" runner "$PRODUCT" >"$TEST_ROOT/failure.log" 2>&1; then
        printf 'metadata mutation %s was accepted\n' "$mode" >&2
        exit 1
    fi
done

printf 'shared header ownership mutation tests passed (%d source/test mutations, 5 metadata mutations)\n' \
    "$case_index"
