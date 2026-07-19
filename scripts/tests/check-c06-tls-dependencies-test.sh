#!/usr/bin/env bash

set -Eeuo pipefail

readonly SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly GATE="$SOURCE_ROOT/scripts/check-c06-tls-dependencies.py"
readonly TEMP="$(mktemp -d "${TMPDIR:-/tmp}/acl-proxy-c06-dependencies.XXXXXX")"
trap 'rm -rf "$TEMP"' EXIT

BASELINE="$TEMP/baseline"
mkdir -p "$BASELINE/acl-proxy/fixtures/empty" \
    "$BASELINE/access-runtime/crates/example" \
    "$BASELINE/access-runtime/.cargo"

python3 - "$BASELINE" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
tls = '''rustls = { version = "=0.23.42", default-features = false, features = ["ring", "std", "tls12"] }
rustls-native-certs = "=0.8.3"
rustls-pki-types = "=1.15.0"
rustls-webpki = { version = "=0.103.13", default-features = false, features = ["alloc", "ring", "std"] }
tokio-rustls = { version = "=0.26.4", default-features = false, features = ["ring", "tls12"] }
'''
(root / "acl-proxy/Cargo.toml").write_text(
    '[package]\nname = "acl-proxy"\nversion = "0.3.0-rc.1"\n\n[dependencies]\n' + tls,
    encoding="utf-8",
)
(root / "access-runtime/Cargo.toml").write_text(
    '[workspace]\nmembers = ["crates/example"]\n\n[workspace.dependencies]\n' + tls,
    encoding="utf-8",
)
(root / "access-runtime/crates/example/Cargo.toml").write_text(
    '''[package]
name = "example"
version = "0.1.0"

[dependencies]
rustls.workspace = true
tokio-rustls.workspace = true
''',
    encoding="utf-8",
)

def lock(root_package):
    packages = [
        ("rustls", "0.23.42"),
        ("rustls-native-certs", "0.8.3"),
        ("rustls-pki-types", "1.15.0"),
        ("rustls-webpki", "0.103.13"),
        ("tokio-rustls", "0.26.4"),
    ]
    text = 'version = 4\n\n[[package]]\nname = ' + repr(root_package) + '\nversion = "0.1.0"\n'
    for name, version in packages:
        text += f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
    return text.replace("'", '"')

(root / "acl-proxy/Cargo.lock").write_text(lock("acl-proxy"), encoding="utf-8")
(root / "access-runtime/Cargo.lock").write_text(lock("access-runtime"), encoding="utf-8")
(root / "acl-proxy/fixtures/empty/Cargo.lock").write_text(
    'version = 4\n\n[[package]]\nname = "empty"\nversion = "0.1.0"\n',
    encoding="utf-8",
)
(root / "acl-proxy/deny.toml").write_text('[advisories]\nignore = []\n', encoding="utf-8")
(root / "access-runtime/.cargo/audit.toml").write_text(
    '[advisories]\nignore = []\n', encoding="utf-8"
)
PY

run_gate() {
    local fixture=$1
    "$GATE" --acl-root "$fixture/acl-proxy" \
        --runtime-root "$fixture/access-runtime"
}

run_gate "$BASELINE"

mutate() {
    local mode=$1
    local fixture=$2
    python3 - "$mode" "$fixture" <<'PY'
from pathlib import Path
import re
import subprocess
import sys

mode = sys.argv[1]
root = Path(sys.argv[2])
acl = root / "acl-proxy/Cargo.toml"
runtime = root / "access-runtime/Cargo.toml"
acl_lock = root / "acl-proxy/Cargo.lock"
runtime_lock = root / "access-runtime/Cargo.lock"

def replace(path, old, new):
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(f"mutation {mode}: expected one {old!r} in {path}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")

def append(path, text):
    path.write_text(path.read_text(encoding="utf-8") + text, encoding="utf-8")

def force_track(repo, path):
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "add", "-f", str(path.relative_to(repo))], check=True
    )

if mode == "acl-missing-rustls":
    replace(acl, 'rustls = { version = "=0.23.42", default-features = false, features = ["ring", "std", "tls12"] }\n', '')
elif mode == "acl-rustls-version":
    replace(acl, '=0.23.42', '=0.23.41')
elif mode == "acl-rustls-default-features":
    replace(acl, 'rustls = { version = "=0.23.42", default-features = false', 'rustls = { version = "=0.23.42", default-features = true')
elif mode == "acl-rustls-missing-ring":
    replace(acl, '["ring", "std", "tls12"]', '["std", "tls12"]')
elif mode == "acl-rustls-extra-feature":
    replace(acl, '["ring", "std", "tls12"]', '["aws_lc_rs", "ring", "std", "tls12"]')
elif mode == "acl-rustls-extra-key":
    replace(acl, 'features = ["ring", "std", "tls12"] }', 'features = ["ring", "std", "tls12"], optional = true }')
elif mode == "acl-tokio-version":
    replace(acl, '=0.26.4', '=0.26.3')
elif mode == "acl-tokio-default-features":
    replace(acl, 'tokio-rustls = { version = "=0.26.4", default-features = false', 'tokio-rustls = { version = "=0.26.4", default-features = true')
elif mode == "acl-tokio-extra-feature":
    replace(acl, 'features = ["ring", "tls12"]', 'features = ["logging", "ring", "tls12"]')
elif mode == "acl-native-version":
    replace(acl, 'rustls-native-certs = "=0.8.3"', 'rustls-native-certs = "=0.8.2"')
elif mode == "acl-pki-version":
    replace(acl, 'rustls-pki-types = "=1.15.0"', 'rustls-pki-types = "=1.14.0"')
elif mode == "acl-webpki-version":
    replace(acl, '=0.103.13', '=0.103.12')
elif mode == "acl-webpki-features":
    replace(acl, '["alloc", "ring", "std"]', '["alloc", "std"]')
elif mode == "acl-webpki-alias":
    replace(acl, 'rustls-webpki = {', 'webpki = { package = "rustls-webpki",')
elif mode == "acl-rustls-alias":
    replace(acl, '\nrustls = { version', '\ntls = { package = "rustls", version')
elif mode == "acl-legacy-alias":
    append(acl, 'rustls-legacy = "=0.21.12"\n')
elif mode == "acl-rcgen":
    append(acl, 'rcgen = "=0.13.2"\n')
elif mode == "acl-rcgen-alias":
    append(acl, 'certificate-generator = { package = "rcgen", version = "=0.13.2" }\n')
elif mode == "acl-pemfile":
    append(acl, 'rustls-pemfile = "=1.0.4"\n')
elif mode == "acl-pemfile-alias":
    append(acl, 'pem-reader = { package = "rustls-pemfile", version = "=1.0.4" }\n')
elif mode == "runtime-webpki-alias":
    replace(runtime, 'rustls-webpki = {', 'webpki = { package = "rustls-webpki",')
elif mode == "runtime-rustls-feature":
    replace(runtime, '["ring", "std", "tls12"]', '["std", "tls12"]')
elif mode == "member-wrong-rustls":
    replace(root / "access-runtime/crates/example/Cargo.toml", '\nrustls.workspace = true', '\nrustls = "0.23"')
elif mode == "member-rustls-alias":
    replace(root / "access-runtime/crates/example/Cargo.toml", '\nrustls.workspace = true', '\ntls = { package = "rustls", workspace = true }')
elif mode.startswith("lock-version-"):
    package, old, new = {
        "lock-version-rustls": ("rustls", "0.23.42", "0.21.12"),
        "lock-version-native": ("rustls-native-certs", "0.8.3", "0.6.3"),
        "lock-version-pki": ("rustls-pki-types", "1.15.0", "1.14.0"),
        "lock-version-webpki": ("rustls-webpki", "0.103.13", "0.101.7"),
        "lock-version-tokio": ("tokio-rustls", "0.26.4", "0.24.1"),
    }[mode]
    replace(acl_lock, f'name = "{package}"\nversion = "{old}"', f'name = "{package}"\nversion = "{new}"')
elif mode == "lock-rcgen":
    append(acl_lock, '\n[[package]]\nname = "rcgen"\nversion = "0.13.2"\n')
elif mode == "lock-pemfile":
    append(acl_lock, '\n[[package]]\nname = "rustls-pemfile"\nversion = "1.0.4"\n')
elif mode == "lock-x509-parser":
    append(acl_lock, '\n[[package]]\nname = "x509-parser"\nversion = "0.16.0"\n')
elif mode == "lock-yasna":
    append(acl_lock, '\n[[package]]\nname = "yasna"\nversion = "0.5.2"\n')
elif mode == "lock-duplicate-rustls":
    append(acl_lock, '\n[[package]]\nname = "rustls"\nversion = "0.23.42"\n')
elif mode == "lock-missing-tokio":
    text = acl_lock.read_text(encoding="utf-8")
    text, count = re.subn(r'\n\[\[package\]\]\nname = "tokio-rustls"\nversion = "0\.26\.4"\n', '\n', text)
    if count != 1:
        raise SystemExit("missing tokio lock mutation did not apply")
    acl_lock.write_text(text, encoding="utf-8")
elif mode == "runtime-lock-legacy":
    replace(runtime_lock, 'name = "rustls"\nversion = "0.23.42"', 'name = "rustls"\nversion = "0.21.12"')
elif mode == "nested-lock-rcgen":
    append(root / "acl-proxy/fixtures/empty/Cargo.lock", '\n[[package]]\nname = "rcgen"\nversion = "0.13.2"\n')
elif mode == "acl-deny-ignore":
    rustsec = "RUST" + "SEC-2026-0001"
    (root / "acl-proxy/deny.toml").write_text(f'[advisories]\nignore = ["{rustsec}"]\n', encoding="utf-8")
elif mode == "runtime-audit-ignore":
    rustsec = "RUST" + "SEC-2026-0002"
    (root / "access-runtime/.cargo/audit.toml").write_text(f'[advisories]\nignore = ["{rustsec}"]\n', encoding="utf-8")
elif mode == "cargo-metadata-ignore":
    rustsec = "RUST" + "SEC-2026-0003"
    append(acl, f'\n[package.metadata.audit]\nignore = ["{rustsec}"]\n')
elif mode == "audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0004"
    scripts = root / "acl-proxy/scripts"
    scripts.mkdir()
    (scripts / "audit.sh").write_text(f'#!/bin/sh\ncargo audit --ignore {rustsec}\n', encoding="utf-8")
elif mode == "multiline-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0008"
    scripts = root / "acl-proxy/scripts"
    scripts.mkdir()
    (scripts / "audit.sh").write_text(
        '#!/bin/sh\n'
        'cargo audit \\\n'
        '  --deny warnings \\\n'
        f'  --ignore {rustsec}\n',
        encoding="utf-8",
    )
elif mode == "split-subcommand-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0009"
    scripts = root / "acl-proxy/scripts"
    scripts.mkdir()
    (scripts / "audit.sh").write_text(
        '#!/bin/sh\n'
        'cargo \\\n'
        '  audit \\\n'
        f'  --ignore {rustsec}\n',
        encoding="utf-8",
    )
elif mode == "split-ignore-value-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0010"
    scripts = root / "acl-proxy/scripts"
    scripts.mkdir()
    (scripts / "audit.sh").write_text(
        '#!/bin/sh\n'
        'cargo audit --ignore \\\n'
        f'  {rustsec}\n',
        encoding="utf-8",
    )
elif mode == "toolchain-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0011"
    scripts = root / "acl-proxy/scripts"
    scripts.mkdir()
    (scripts / "audit.sh").write_text(
        f'#!/bin/sh\ncargo +stable audit --ignore {rustsec}\n', encoding="utf-8"
    )
elif mode == "cargo-alias-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0012"
    cargo_config = root / "acl-proxy/.cargo/config.toml"
    cargo_config.parent.mkdir(exist_ok=True)
    cargo_config.write_text(
        f'[alias]\nsecurity = "audit --ignore {rustsec}"\n', encoding="utf-8"
    )
elif mode == "cargo-alias-array-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0013"
    cargo_config = root / "acl-proxy/.cargo/config.toml"
    cargo_config.parent.mkdir(exist_ok=True)
    cargo_config.write_text(
        f'[alias]\nsecurity = ["audit", "--ignore", "{rustsec}"]\n', encoding="utf-8"
    )
elif mode == "direct-cargo-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0014"
    scripts = root / "acl-proxy/scripts"
    scripts.mkdir()
    (scripts / "audit.sh").write_text(
        f'#!/bin/sh\ncargo-audit audit --ignore {rustsec}\n', encoding="utf-8"
    )
elif mode == "cargo-global-option-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0015"
    scripts = root / "acl-proxy/scripts"
    scripts.mkdir()
    (scripts / "audit.sh").write_text(
        f'#!/bin/sh\ncargo --color never audit --ignore {rustsec}\n', encoding="utf-8"
    )
elif mode == "folded-workflow-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0016"
    workflows = root / "acl-proxy/.github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "audit.yml").write_text(
        f'run: >\n  cargo audit\n  --ignore {rustsec}\n', encoding="utf-8"
    )
elif mode == "argv-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0017"
    scripts = root / "acl-proxy/scripts"
    scripts.mkdir()
    (scripts / "audit.py").write_text(
        f'import subprocess\nsubprocess.run(["cargo", "audit", "--ignore", "{rustsec}"])\n',
        encoding="utf-8",
    )
elif mode == "variable-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0018"
    scripts = root / "acl-proxy/scripts"
    scripts.mkdir()
    (scripts / "audit.sh").write_text(
        f'#!/bin/sh\nadvisory={rustsec}\ncargo audit --ignore "$advisory"\n',
        encoding="utf-8",
    )
elif mode == "workflow-env-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0019"
    workflows = root / "acl-proxy/.github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "audit.yml").write_text(
        f'env:\n  ADVISORY: {rustsec}\nsteps:\n  - run: cargo audit --ignore "$ADVISORY"\n',
        encoding="utf-8",
    )
elif mode == "custom-toml-advisory-ignore":
    rustsec = "RUST" + "SEC-2026-0020"
    policy = root / "acl-proxy/policy/security.toml"
    policy.parent.mkdir(parents=True)
    policy.write_text(f'[advisories]\nignore = ["{rustsec}"]\n', encoding="utf-8")
elif mode == "extensionless-executable-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0021"
    script = root / "acl-proxy/scripts/audit"
    script.parent.mkdir()
    script.write_text(f'#!/bin/sh\ncargo audit --ignore {rustsec}\n', encoding="utf-8")
    script.chmod(0o755)
elif mode == "invalid-utf8-executable-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0028"
    script = root / "acl-proxy/scripts/audit-invalid"
    script.parent.mkdir()
    script.write_bytes(
        f'#!/bin/sh\ncargo audit --ignore {rustsec}\n'.encode("ascii") + b'# invalid: \xff\n'
    )
    script.chmod(0o755)
elif mode == "nul-executable-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0030"
    script = root / "acl-proxy/scripts/audit-nul"
    script.parent.mkdir()
    script.write_bytes(
        f'#!/bin/sh\ncargo audit --ignore {rustsec}\n'.encode("ascii") + b'# invalid: \0\n'
    )
    script.chmod(0o755)
elif mode == "nested-target-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0029"
    script = root / "acl-proxy/scripts/target/audit.sh"
    script.parent.mkdir(parents=True)
    script.write_text(f'#!/bin/sh\ncargo audit --ignore {rustsec}\n', encoding="utf-8")
    force_track(root / "acl-proxy", script)
elif mode == "nested-target-manifest-forbidden-dependency":
    manifest = root / "acl-proxy/components/target/Cargo.toml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        '[package]\nname = "nested-target"\nversion = "0.1.0"\n\n'
        '[dependencies]\nrcgen = "=0.13.2"\n',
        encoding="utf-8",
    )
    force_track(root / "acl-proxy", manifest)
elif mode == "nested-target-lock-forbidden-dependency":
    lock = root / "acl-proxy/components/target/Cargo.lock"
    lock.parent.mkdir(parents=True)
    lock.write_text(
        'version = 4\n\n[[package]]\nname = "rcgen"\nversion = "0.13.2"\n',
        encoding="utf-8",
    )
    force_track(root / "acl-proxy", lock)
elif mode == "root-target-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0032"
    script = root / "acl-proxy/target/audit.sh"
    script.parent.mkdir(parents=True)
    script.write_text(f'#!/bin/sh\ncargo audit --ignore {rustsec}\n', encoding="utf-8")
    force_track(root / "acl-proxy", script)
elif mode == "cross-repository-authority-path-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0031"
    script = root / "access-runtime/scripts/check-c06-tls-dependencies.py"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(f'cargo audit --ignore {rustsec}\n', encoding="utf-8")
elif mode == "rust-launcher-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0022"
    launcher = root / "acl-proxy/tools/audit.rs"
    launcher.parent.mkdir()
    launcher.write_text(
        f'Command::new("cargo").args(["audit", "--ignore", "{rustsec}"]);\n',
        encoding="utf-8",
    )
elif mode == "json-task-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0023"
    (root / "acl-proxy/package.json").write_text(
        f'{{"scripts":{{"audit":"cargo audit --ignore {rustsec}"}}}}\n', encoding="utf-8"
    )
elif mode == "scripts-tests-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0024"
    script = root / "acl-proxy/scripts/tests/audit.sh"
    script.parent.mkdir(parents=True)
    script.write_text(f'#!/bin/sh\ncargo audit --ignore {rustsec}\n', encoding="utf-8")
elif mode == "workflow-block-advisory-ignore":
    rustsec = "RUST" + "SEC-2026-0025"
    workflow = root / "access-runtime/.github/workflows/audit.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        f'uses: rustsec/audit-check@v2\nwith:\n  ignore: |\n    {rustsec}\n',
        encoding="utf-8",
    )
elif mode == "workflow-anchor-advisory-ignore":
    rustsec = "RUST" + "SEC-2026-0026"
    workflow = root / "access-runtime/.github/workflows/audit.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        f'env:\n  ADVISORY: &advisory {rustsec}\nwith:\n  ignore: *advisory\n',
        encoding="utf-8",
    )
elif mode == "workflow-inline-advisory-ignore":
    rustsec = "RUST" + "SEC-2026-0027"
    workflow = root / "access-runtime/.github/workflows/audit.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        f'uses: rustsec/audit-check@v2\nwith: {{ ignore: {rustsec} }}\n',
        encoding="utf-8",
    )
elif mode == "js-audit-command-ignore":
    rustsec = "RUST" + "SEC-2026-0005"
    scripts = root / "acl-proxy/scripts"
    scripts.mkdir()
    (scripts / "audit.mjs").write_text(
        f'execSync("cargo audit --ignore={rustsec}");\n', encoding="utf-8"
    )
elif mode == "workflow-advisory-ignore":
    rustsec = "RUST" + "SEC-2026-0006"
    workflows = root / "access-runtime/.github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "audit.yml").write_text(
        f'uses: rustsec/audit-check@v2\nwith:\n  ignore: {rustsec}\n', encoding="utf-8"
    )
elif mode == "workflow-multiline-advisory-ignore":
    rustsec = "RUST" + "SEC-2026-0007"
    workflows = root / "access-runtime/.github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "audit.yml").write_text(
        f'uses: rustsec/audit-check@v2\nwith:\n  ignore:\n    - {rustsec}\n',
        encoding="utf-8",
    )
else:
    raise SystemExit(f"unknown mutation: {mode}")
PY
}

expect_failure() {
    local mode=$1
    local fixture="$TEMP/$mode"
    cp -R "$BASELINE" "$fixture"
    mutate "$mode" "$fixture"
    if run_gate "$fixture" >"$fixture.out" 2>&1; then
        printf 'C06 dependency mutation unexpectedly passed: %s\n' "$mode" >&2
        exit 1
    fi
}

mutations=(
    acl-missing-rustls
    acl-rustls-version
    acl-rustls-default-features
    acl-rustls-missing-ring
    acl-rustls-extra-feature
    acl-rustls-extra-key
    acl-tokio-version
    acl-tokio-default-features
    acl-tokio-extra-feature
    acl-native-version
    acl-pki-version
    acl-webpki-version
    acl-webpki-features
    acl-webpki-alias
    acl-rustls-alias
    acl-legacy-alias
    acl-rcgen
    acl-rcgen-alias
    acl-pemfile
    acl-pemfile-alias
    runtime-webpki-alias
    runtime-rustls-feature
    member-wrong-rustls
    member-rustls-alias
    lock-version-rustls
    lock-version-native
    lock-version-pki
    lock-version-webpki
    lock-version-tokio
    lock-rcgen
    lock-pemfile
    lock-x509-parser
    lock-yasna
    lock-duplicate-rustls
    lock-missing-tokio
    runtime-lock-legacy
    nested-lock-rcgen
    acl-deny-ignore
    runtime-audit-ignore
    cargo-metadata-ignore
    audit-command-ignore
    multiline-audit-command-ignore
    split-subcommand-audit-command-ignore
    split-ignore-value-audit-command-ignore
    toolchain-audit-command-ignore
    cargo-alias-audit-command-ignore
    cargo-alias-array-audit-command-ignore
    direct-cargo-audit-command-ignore
    cargo-global-option-audit-command-ignore
    folded-workflow-audit-command-ignore
    argv-audit-command-ignore
    variable-audit-command-ignore
    workflow-env-audit-command-ignore
    custom-toml-advisory-ignore
    extensionless-executable-audit-command-ignore
    invalid-utf8-executable-audit-command-ignore
    nul-executable-audit-command-ignore
    nested-target-audit-command-ignore
    nested-target-manifest-forbidden-dependency
    nested-target-lock-forbidden-dependency
    root-target-audit-command-ignore
    cross-repository-authority-path-audit-command-ignore
    rust-launcher-audit-command-ignore
    json-task-audit-command-ignore
    scripts-tests-audit-command-ignore
    workflow-block-advisory-ignore
    workflow-anchor-advisory-ignore
    workflow-inline-advisory-ignore
    js-audit-command-ignore
    workflow-advisory-ignore
    workflow-multiline-advisory-ignore
)

for mutation in "${mutations[@]}"; do
    expect_failure "$mutation"
done

printf 'C06 TLS dependency sentinel mutation test passed (%s cases)\n' "${#mutations[@]}"
