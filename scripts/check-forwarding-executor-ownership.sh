#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

python3 - "$ROOT" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
executor_path = pathlib.Path("src/proxy/forwarding_executor.rs")
transport_path = pathlib.Path("src/proxy/forward.rs")
ingress_path = pathlib.Path("src/proxy/ingress.rs")


def mask_non_code(source: str) -> str:
    """Mask comments and literals while retaining code offsets and line numbers."""
    output = []
    index = 0
    block_depth = 0
    state = "code"
    raw_hashes = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""

        if state == "line-comment":
            if char == "\n":
                output.append(char)
                state = "code"
            else:
                output.append(" ")
            index += 1
            continue
        if state == "block-comment":
            if char == "/" and following == "*":
                output.extend((" ", " "))
                block_depth += 1
                index += 2
            elif char == "*" and following == "/":
                output.extend((" ", " "))
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
            else:
                output.append("\n" if char == "\n" else " ")
                index += 1
            continue
        if state == "string":
            output.append("\n" if char == "\n" else " ")
            index += 1
            if char == "\\" and index < len(source):
                output.append("\n" if source[index] == "\n" else " ")
                index += 1
            elif char == '"':
                state = "code"
            continue
        if state == "raw-string":
            terminator = '"' + ("#" * raw_hashes)
            if source.startswith(terminator, index):
                output.extend(" " * len(terminator))
                index += len(terminator)
                state = "code"
            else:
                output.append("\n" if char == "\n" else " ")
                index += 1
            continue
        if state == "char":
            output.append("\n" if char == "\n" else " ")
            index += 1
            if char == "\\" and index < len(source):
                output.append("\n" if source[index] == "\n" else " ")
                index += 1
            elif char == "'":
                state = "code"
            continue

        if char == "/" and following == "/":
            output.extend((" ", " "))
            index += 2
            state = "line-comment"
        elif char == "/" and following == "*":
            output.extend((" ", " "))
            index += 2
            block_depth = 1
            state = "block-comment"
        elif char == '"':
            output.append(" ")
            index += 1
            state = "string"
        elif char == "r":
            raw = re.match(r'r(#+)?"', source[index:])
            if raw is None:
                output.append(char)
                index += 1
            else:
                opener = raw.group(0)
                output.extend(" " * len(opener))
                index += len(opener)
                raw_hashes = len(raw.group(1) or "")
                state = "raw-string"
        elif char == "'":
            lifetime = re.match(r"'[A-Za-z_][A-Za-z0-9_]*", source[index:])
            lifetime_end = index + len(lifetime.group(0)) if lifetime is not None else index
            if lifetime is not None and (
                lifetime_end >= len(source) or source[lifetime_end] != "'"
            ):
                token = lifetime.group(0)
                output.extend(token)
                index += len(token)
            else:
                output.append(" ")
                index += 1
                state = "char"
        else:
            output.append(char)
            index += 1
    return "".join(output)


def matching_brace(source: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    line = source.count("\n", 0, opening) + 1
    raise SystemExit(
        f"unterminated #[cfg(test)] item beginning near line {line} while scanning ownership"
    )


def mask_range(source: str, start: int, end: int) -> str:
    masked = "".join("\n" if char == "\n" else " " for char in source[start:end])
    return source[:start] + masked + source[end:]


def mask_test_items(source: str) -> str:
    """Mask whole test-only files and cfg(test)-attributed items."""
    if re.search(r"#!\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]", source):
        return mask_range(source, 0, len(source))

    attribute = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
    while True:
        match = attribute.search(source)
        if match is None:
            return source
        cursor = match.end()
        while True:
            whitespace = re.match(r"\s*", source[cursor:])
            cursor += len(whitespace.group(0))
            extra_attribute = re.match(r"#\s*\[[^\]]*\]", source[cursor:])
            if extra_attribute is None:
                break
            cursor += len(extra_attribute.group(0))

        opening = source.find("{", cursor)
        semicolon = source.find(";", cursor)
        if semicolon != -1 and (opening == -1 or semicolon < opening):
            end = semicolon + 1
        elif opening != -1:
            end = matching_brace(source, opening)
            trailing = re.match(r"\s*;", source[end:])
            if trailing is not None:
                end += len(trailing.group(0))
        else:
            raise SystemExit("unsupported #[cfg(test)] item while scanning ownership")
        source = mask_range(source, match.start(), end)


def production(path: pathlib.Path) -> str:
    absolute = root / path
    if not absolute.is_file():
        raise SystemExit(f"forwarding executor ownership scan path is missing: {path}")
    source = mask_non_code(absolute.read_text(encoding="utf-8"))
    ownership_token = re.compile(
        r"\b(?:ForwardingExecutor|forward_request|forward_upgrade_request)\b"
    )
    if path != executor_path and ownership_token.search(source) is None:
        return ""
    try:
        return mask_test_items(source)
    except SystemExit as error:
        raise SystemExit(f"{path}: {error}") from error


if not (root / executor_path).is_file():
    raise SystemExit(f"forwarding executor ownership scan path is missing: {executor_path}")

sources = []
for absolute in sorted((root / "src").rglob("*.rs")):
    relative = absolute.relative_to(root)
    sources.append((relative, production(relative)))

executor = dict(sources)[executor_path]
forbidden = (
    ("AppState dependency", re.compile(r"\bAppState\b")),
    ("broad generation lease", re.compile(r"\bGenerationLease\b")),
    ("product runtime", re.compile(r"\bRuntime\b")),
    (
        "broad generation snapshot capability",
        re.compile(r"\b(?:CredentialResolver|EgressSnapshot|SafetySnapshot)\b"),
    ),
    (
        "product configuration type",
        re.compile(r"\b(?:[A-Za-z_][A-Za-z0-9_]*)?Config\b"),
    ),
    (
        "product configuration module/read",
        re.compile(
            r"\b(?:crate|super|self)\s*::\s*config\b"
            r"|\bconfig\s*\."
            r"|\.\s*config\b"
        ),
    ),
    (
        "authoring dependency",
        re.compile(r"\bAuthoring[A-Za-z0-9_]*\b|\bauthoring\b"),
    ),
    (
        "product policy dependency/read",
        re.compile(
            r"\bcrate\s*::\s*policy\b"
            r"|\.\s*policy\s*\("
            r"|\b(?:PolicySnapshot|PolicyEvaluation|PolicyOutcome|PolicyResult)\b"
            r"|\bCompiled[A-Za-z0-9_]*Policy\b"
            r"|\bAllowedRequest\b"
            r"|\b(?:evaluate|compile)_policy\b"
        ),
    ),
    (
        "provider dispatch dependency/read",
        re.compile(
            r"\b(?:StandalonePolicyProvider|DecisionProvider|ProviderDispatcher)\b"
            r"|\.\s*decide\s*\("
            r"|\b(?:dispatch|invoke|call)_provider\b"
        ),
    ),
)

violations = []
for description, pattern in forbidden:
    for match in pattern.finditer(executor):
        line = executor.count("\n", 0, match.start()) + 1
        violations.append(
            f"{executor_path}:{line}: forbidden {description}: {match.group(0)}"
        )
if violations:
    print("forwarding executor dependency violations:", file=sys.stderr)
    print("\n".join(violations), file=sys.stderr)
    raise SystemExit(1)

entry_pattern = re.compile(r"\bForwardingExecutor\s*::\s*execute\s*\(")
entries = []
for path, source in sources:
    if path == executor_path:
        continue
    for match in entry_pattern.finditer(source):
        line = source.count("\n", 0, match.start()) + 1
        entries.append(f"{path}:{line}")
if len(entries) != 1 or not entries[0].startswith(f"{ingress_path}:"):
    print(
        "ForwardingExecutor::execute must have exactly one production terminal caller in ingress.rs",
        file=sys.stderr,
    )
    print("call sites: " + (", ".join(entries) or "none"), file=sys.stderr)
    raise SystemExit(1)

for primitive in ("forward_request", "forward_upgrade_request"):
    reference_pattern = re.compile(rf"\b{primitive}\b")
    call_pattern = re.compile(rf"\b{primitive}\s*\(")
    escaped = []
    calls = []
    for path, source in sources:
        if path == transport_path:
            continue
        for match in reference_pattern.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            location = f"{path}:{line}"
            if path != executor_path:
                escaped.append(location)
        if path == executor_path:
            for match in call_pattern.finditer(source):
                line = source.count("\n", 0, match.start()) + 1
                calls.append(f"{path}:{line}")
    if escaped:
        print(
            f"{primitive} references must be confined to the forwarding executor transport seam",
            file=sys.stderr,
        )
        print("escaped references: " + ", ".join(escaped), file=sys.stderr)
        raise SystemExit(1)
    if len(calls) != 1:
        print(
            f"the forwarding executor must contain exactly one production {primitive} transport call",
            file=sys.stderr,
        )
        print("call sites: " + (", ".join(calls) or "none"), file=sys.stderr)
        raise SystemExit(1)

print("forwarding executor ownership gate passed")
PY
