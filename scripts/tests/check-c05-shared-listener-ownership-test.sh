#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
GATE="$SOURCE_ROOT/scripts/check-c05-shared-listener-ownership.sh"
TEMP=$(mktemp -d "${TMPDIR:-/tmp}/acl-proxy-c05-gate.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT INT TERM

mkdir -p "$TEMP/baseline"
cp "$SOURCE_ROOT/Cargo.toml" "$TEMP/baseline/Cargo.toml"
cp -R "$SOURCE_ROOT/src" "$TEMP/baseline/src"
ACL_PROXY_ROOT="$TEMP/baseline" "$GATE" >/dev/null

expect_failure() {
    local name=$1
    shift
    local case_root="$TEMP/$name"
    cp -R "$TEMP/baseline" "$case_root"
    "$@" "$case_root"
    if ACL_PROXY_ROOT="$case_root" "$GATE" >/dev/null 2>&1; then
        printf 'C05 ownership mutation unexpectedly passed: %s\n' "$name" >&2
        exit 1
    fi
}

recreate_ingress() { mkdir -p "$1/src/proxy"; printf 'struct ProductIngressSupervisor;\n' >"$1/src/proxy/ingress.rs"; }
recreate_ignored_certs() { mkdir -p "$1/src/certs"; printf 'struct HiddenCertificateCache;\n' >"$1/src/certs/hidden.rs"; }
recreate_hyper_tree() { mkdir -p "$1/third_party/hyper"; printf '[package]\nname="hyper"\n' >"$1/third_party/hyper/Cargo.toml"; }
add_hyper_dependency() { sed -i '/^\[dependencies\]$/a hyper = { path = "third_party/hyper" }' "$1/Cargo.toml"; }
add_hyper_package_alias() { sed -i '/^\[dependencies\]$/a transport = { package = "hyper", path = "../access-runtime/third_party/hyper" }' "$1/Cargo.toml"; }
add_hyper_alias() { printf '\nmod disguised { use hyper::Body; }\n' >>"$1/src/lib.rs"; }
add_path_alias() { printf '\n#[path = "disguised_ingress.rs"] mod data_plane;\n' >>"$1/src/lib.rs"; }
add_module_alias() { printf '\nmod http1;\n' >>"$1/src/lib.rs"; }
add_include_alias() { printf '\nconst _: () = { include!("proxy/disguised_ingress.rs"); };\n' >>"$1/src/lib.rs"; }
add_transport_wrapper() { printf '\nstruct ConnectTunnelPlan;\n' >>"$1/src/lib.rs"; }
add_upgrade_engine() { printf '\nstruct PreparedUpgradeRelay;\n' >>"$1/src/lib.rs"; }
remove_oracle() { sed -i '/fn ordinary_proxy_authorization_presence_is_retained_but_value_never_becomes_neutral/ s/ordinary_proxy_authorization_presence_is_retained_but_value_never_becomes_neutral/removed_oracle/' "$1/src/proxy/private_fields.rs"; }

expect_failure legacy-ingress recreate_ingress
expect_failure ignored-certs recreate_ignored_certs
expect_failure product-hyper-tree recreate_hyper_tree
expect_failure hyper-path-dependency add_hyper_dependency
expect_failure hyper-package-alias add_hyper_package_alias
expect_failure hyper-import-alias add_hyper_alias
expect_failure path-module-alias add_path_alias
expect_failure plain-module-alias add_module_alias
expect_failure include-alias add_include_alias
expect_failure connect-transport-wrapper add_transport_wrapper
expect_failure product-upgrade-engine add_upgrade_engine
expect_failure missing-retained-oracle remove_oracle

printf 'C05 shared-listener ownership mutation suite passed (12 mutations)\n'
