#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
import tomllib
from typing import Any, Iterator


TLS_SPECS: dict[str, object] = {
    "rustls": {
        "version": "=0.23.42",
        "default-features": False,
        "features": ["ring", "std", "tls12"],
    },
    "rustls-native-certs": "=0.8.3",
    "rustls-pki-types": "=1.15.0",
    "rustls-webpki": {
        "version": "=0.103.13",
        "default-features": False,
        "features": ["alloc", "ring", "std"],
    },
    "tokio-rustls": {
        "version": "=0.26.4",
        "default-features": False,
        "features": ["ring", "tls12"],
    },
}
TLS_VERSIONS = {
    "rustls": "0.23.42",
    "rustls-native-certs": "0.8.3",
    "rustls-pki-types": "1.15.0",
    "rustls-webpki": "0.103.13",
    "tokio-rustls": "0.26.4",
}
FORBIDDEN_PACKAGES = {"rcgen", "rustls-pemfile", "x509-parser", "yasna"}
DEPENDENCY_TABLES = {"dependencies", "dev-dependencies", "build-dependencies"}
AUDIT_COMMAND_IGNORE = re.compile(
    r"cargo\s+(?:audit|deny\s+check(?:\s+advisories)?)\b[^\n]*"
    r"--ignore(?:=|\s+)[\"']?RUSTSEC-",
    re.IGNORECASE,
)
WORKFLOW_ADVISORY_IGNORE = re.compile(
    r"(?mi)^\s*ignore\s*:\s*(?:[^\n]*RUSTSEC-|\n\s*-\s*[^\n]*RUSTSEC-)",
)


def fail(message: str) -> None:
    raise ValueError(message)


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot parse {path}: {error}")


def equivalent_spec(actual: object, expected: object) -> bool:
    if not isinstance(expected, dict):
        return actual == expected
    if not isinstance(actual, dict) or set(actual) != set(expected):
        return False
    for key, expected_value in expected.items():
        actual_value = actual[key]
        if key == "features":
            if not isinstance(actual_value, list) or sorted(actual_value) != sorted(expected_value):
                return False
        elif actual_value != expected_value:
            return False
    return True


def dependency_tables(document: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    for name in DEPENDENCY_TABLES:
        table = document.get(name)
        if isinstance(table, dict):
            yield name, table
    workspace = document.get("workspace")
    if isinstance(workspace, dict) and isinstance(workspace.get("dependencies"), dict):
        yield "workspace.dependencies", workspace["dependencies"]
    targets = document.get("target")
    if isinstance(targets, dict):
        for target_name, target in targets.items():
            if not isinstance(target, dict):
                continue
            for name in DEPENDENCY_TABLES:
                table = target.get(name)
                if isinstance(table, dict):
                    yield f"target.{target_name}.{name}", table


def check_manifest(path: Path, authority_section: str | None) -> None:
    document = load_toml(path)
    authority: dict[str, Any] | None = None
    for section, dependencies in dependency_tables(document):
        if section == authority_section:
            authority = dependencies
        for name, spec in dependencies.items():
            package = spec.get("package") if isinstance(spec, dict) else None
            resolved_name = package if isinstance(package, str) else name
            protected = name in TLS_SPECS or resolved_name in TLS_SPECS
            forbidden = name in FORBIDDEN_PACKAGES or resolved_name in FORBIDDEN_PACKAGES
            legacy_alias = "legacy" in name.lower() and (
                "rustls" in name.lower() or "webpki" in name.lower()
            )
            if forbidden:
                fail(f"{path}: forbidden dependency {name!r} resolves to {resolved_name!r}")
            if legacy_alias:
                fail(f"{path}: forbidden legacy TLS dependency name {name!r}")
            if protected and package is not None:
                fail(f"{path}: TLS dependency {name!r} must not use package aliases")
            if not protected:
                continue
            if name != resolved_name:
                fail(f"{path}: TLS dependency {name!r} is not canonical")
            if isinstance(spec, dict) and spec == {"workspace": True}:
                continue
            if not equivalent_spec(spec, TLS_SPECS[name]):
                fail(f"{path}: {name} does not use the exact C06 version/features")

    if authority_section is not None:
        if authority is None:
            fail(f"{path}: missing authoritative [{authority_section}] table")
        for name, expected in TLS_SPECS.items():
            if name not in authority:
                fail(f"{path}: missing authoritative C06 dependency {name}")
            if not equivalent_spec(authority[name], expected):
                fail(f"{path}: authoritative {name} version/features are not exact")


def check_lock(path: Path, require_family: bool) -> None:
    document = load_toml(path)
    packages = document.get("package")
    if not isinstance(packages, list):
        fail(f"{path}: lockfile has no package array")
    observed: dict[str, list[str]] = {name: [] for name in TLS_VERSIONS}
    for package in packages:
        if not isinstance(package, dict):
            fail(f"{path}: invalid package entry")
        name = package.get("name")
        version = package.get("version")
        if name in FORBIDDEN_PACKAGES:
            fail(f"{path}: forbidden lock node {name} {version}")
        if name in TLS_VERSIONS:
            if version != TLS_VERSIONS[name]:
                fail(f"{path}: legacy or unexpected lock node {name} {version}")
            observed[name].append(version)
    for name, versions in observed.items():
        if len(versions) > 1:
            fail(f"{path}: duplicate TLS lock nodes for {name}")
        if require_family and versions != [TLS_VERSIONS[name]]:
            fail(f"{path}: missing exact TLS lock node {name} {TLS_VERSIONS[name]}")


def walk_values(value: object, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], object]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = (*path, str(key))
            yield child_path, child
            yield from walk_values(child, child_path)
    elif isinstance(value, list):
        for child in value:
            yield from walk_values(child, path)


def check_advisory_config(path: Path) -> None:
    document = load_toml(path)
    for key_path, value in walk_values(document):
        if not key_path or key_path[-1].lower() != "ignore":
            continue
        advisory_scope = any(part.lower() in {"advisory", "advisories", "audit"}
                             for part in key_path[:-1])
        rustsec_value = "RUSTSEC-" in repr(value).upper()
        nonempty = value not in (None, "", [], {})
        if nonempty and (advisory_scope or rustsec_value):
            fail(f"{path}: advisory ignore list must be empty")


def repository_files(root: Path, filename: str) -> Iterator[Path]:
    for path in root.rglob(filename):
        if any(part in {".git", "target"} for part in path.parts):
            continue
        yield path


def check_advisory_policy(root: Path) -> None:
    config_paths = set(repository_files(root, "deny.toml"))
    config_paths.update(repository_files(root, "audit.toml"))
    config_paths.update(repository_files(root, "Cargo.toml"))
    for path in sorted(config_paths):
        check_advisory_config(path)

    command_files: set[Path] = set()
    command_suffixes = {".js", ".mjs", ".py", ".sh", ".toml", ".yaml", ".yml"}
    for path in root.rglob("*"):
        if not path.is_file() or any(part in {".git", "target"} for part in path.parts):
            continue
        relative = path.relative_to(root)
        if relative.parts[:2] == ("scripts", "tests"):
            continue
        if path.resolve() == Path(__file__).resolve():
            continue
        if path.suffix in command_suffixes or path.name in {"Makefile", "Justfile"}:
            command_files.add(path)
    for path in sorted(command_files):
        text = path.read_text(encoding="utf-8")
        if AUDIT_COMMAND_IGNORE.search(text):
            fail(f"{path}: advisory audit command must not ignore RustSec IDs")
        if path.suffix in {".yaml", ".yml"} and WORKFLOW_ADVISORY_IGNORE.search(text):
            fail(f"{path}: advisory workflow must not ignore RustSec IDs")


def check_repository(acl_root: Path, runtime_root: Path) -> None:
    roots = (acl_root.resolve(), runtime_root.resolve())
    for root in roots:
        if not root.is_dir():
            fail(f"repository root does not exist: {root}")

    acl_manifest = roots[0] / "Cargo.toml"
    runtime_manifest = roots[1] / "Cargo.toml"
    for root in roots:
        for manifest in repository_files(root, "Cargo.toml"):
            authority = None
            if manifest == acl_manifest:
                authority = "dependencies"
            elif manifest == runtime_manifest:
                authority = "workspace.dependencies"
            check_manifest(manifest, authority)

        main_lock = root / "Cargo.lock"
        if not main_lock.is_file():
            fail(f"missing repository lockfile: {main_lock}")
        for lock in repository_files(root, "Cargo.lock"):
            check_lock(lock, require_family=lock == main_lock)
        check_advisory_policy(root)


def main() -> int:
    script_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Enforce the P11-C06 TLS dependency end state")
    parser.add_argument("--acl-root", type=Path, default=script_root)
    parser.add_argument("--runtime-root", type=Path, default=script_root.parent / "access-runtime")
    args = parser.parse_args()
    try:
        check_repository(args.acl_root, args.runtime_root)
    except ValueError as error:
        print(f"C06 TLS dependency sentinel failed: {error}", file=sys.stderr)
        return 1
    print("C06 TLS dependency sentinel passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
