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
webhook_connector_path = pathlib.Path("src/authorization/webhook/connector.rs")


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
    try:
        return mask_test_items(source)
    except SystemExit as error:
        raise SystemExit(f"{path}: {error}") from error


def parsed_use_paths(source: str) -> list[tuple[str, ...]]:
    """Resolve Rust use trees into their imported component paths."""
    paths = []

    def parse_body(body: str) -> None:
        tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|::|[{},*]", body)

        def parse_group(index: int, prefix: tuple[str, ...]) -> int:
            while index < len(tokens) and tokens[index] != "}":
                index = parse_item(index, prefix)
                if index < len(tokens) and tokens[index] == ",":
                    index += 1
            if index >= len(tokens) or tokens[index] != "}":
                raise SystemExit("unterminated Rust use group")
            return index + 1

        def parse_item(index: int, prefix: tuple[str, ...]) -> int:
            components = []
            while index < len(tokens):
                token = tokens[index]
                if token in (",", "}"):
                    break
                if token == "as":
                    index += 2
                    break
                if token == "::":
                    index += 1
                    continue
                if token == "{":
                    return parse_group(index + 1, prefix + tuple(components))
                components.append(token)
                index += 1
            resolved = prefix + tuple(component for component in components if component != "self")
            if resolved:
                paths.append(resolved)
            return index

        index = 0
        while index < len(tokens):
            index = parse_item(index, ())
            if index < len(tokens) and tokens[index] == ",":
                index += 1

    for match in re.finditer(r"\buse\s+([^;]+);", source):
        parse_body(match.group(1))
    return paths


if not (root / executor_path).is_file():
    raise SystemExit(f"forwarding executor ownership scan path is missing: {executor_path}")

sources = []
for absolute in sorted((root / "src").rglob("*.rs")):
    relative = absolute.relative_to(root)
    sources.append((relative, production(relative)))

webhook_connector = dict(sources).get(webhook_connector_path)
if webhook_connector is None:
    raise SystemExit("authorization webhook connector ownership path is missing")
webhook_use_paths = parsed_use_paths(webhook_connector)
webhook_violations = []
for name, component in (
    ("ordinary destination", "destination"),
    ("ordinary egress", "egress"),
    ("ordinary forwarding", "proxy"),
):
    if any(component in path for path in webhook_use_paths):
        webhook_violations.append(name)
for name, pattern in (
    ("ordinary destination", r"\b(?:crate|super)\s*::\s*destination\b"),
    ("ordinary egress", r"\b(?:crate|super)\s*::\s*egress\b"),
    ("ordinary forwarding", r"\b(?:crate|super)\s*::\s*proxy\b"),
    ("forwarding plan", r"\bForwardingPlan\b"),
    (
        "credential execution",
        r"\b(?:ProductCredentialExecution|CredentialResolverSession|TransportCredentialBatch)\b",
    ),
):
    if re.search(pattern, webhook_connector) and name not in webhook_violations:
        webhook_violations.append(name)
if webhook_violations:
    print(
        "authorization webhook connector must remain independent of ordinary forwarding ownership",
        file=sys.stderr,
    )
    print("forbidden dependencies: " + ", ".join(webhook_violations), file=sys.stderr)
    raise SystemExit(1)

ordinary_webhook_references = []
for path, source in sources:
    ordinary_owner = (
        path == pathlib.Path("src/destination/mod.rs")
        or path == pathlib.Path("src/egress.rs")
        or path.parts[:2] == ("src", "proxy")
    )
    if not ordinary_owner:
        continue
    imports_authorization = any(
        "authorization" in use_path for use_path in parsed_use_paths(source)
    )
    qualifies_webhook = re.search(
        r"\b(?:WebhookConnector|authorization\s*::\s*webhook)\b", source
    )
    if imports_authorization or qualifies_webhook:
        ordinary_webhook_references.append(str(path))
if ordinary_webhook_references:
    print(
        "ordinary destination and forwarding owners must not reference the authorization webhook connector",
        file=sys.stderr,
    )
    print("escaped references: " + ", ".join(ordinary_webhook_references), file=sys.stderr)
    raise SystemExit(1)

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


def locations(pattern: re.Pattern[str]):
    matches = []
    for path, source in sources:
        for match in pattern.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            matches.append((path, line, match))
    return matches


ambient_lookup_pattern = re.compile(
    r"\bH2StreamCancellation\s*::\s*current\s*\("
)
ambient_lookups = locations(ambient_lookup_pattern)
if len(ambient_lookups) != 1 or ambient_lookups[0][0] != ingress_path:
    print(
        "H2StreamCancellation::current must have exactly one production lookup in ingress.rs",
        file=sys.stderr,
    )
    print(
        "lookup sites: "
        + (
            ", ".join(f"{path}:{line}" for path, line, _ in ambient_lookups)
            or "none"
        ),
        file=sys.stderr,
    )
    raise SystemExit(1)

h2_injection_pattern = re.compile(
    r"\brequest\s*\.\s*extensions_mut\s*\(\s*\)\s*"
    r"\.\s*insert\s*\(\s*h2_stream\s*\)"
)
h2_injections = locations(h2_injection_pattern)
if len(h2_injections) != 1 or h2_injections[0][0] != ingress_path:
    print(
        "the H2 cancellation capability must be injected exactly once in ingress.rs",
        file=sys.stderr,
    )
    print(
        "injection sites: "
        + (
            ", ".join(f"{path}:{line}" for path, line, _ in h2_injections)
            or "none"
        ),
        file=sys.stderr,
    )
    raise SystemExit(1)

h2_transfer_pattern = re.compile(
    r"\bif\s+let\s+Some\s*\(\s*h2_stream\s*\)\s*=\s*"
    r"H2StreamCancellation\s*::\s*current\s*\(\s*\)\s*\{\s*"
    r"request\s*\.\s*extensions_mut\s*\(\s*\)\s*"
    r"\.\s*insert\s*\(\s*h2_stream\s*\)\s*;\s*\}"
)
h2_transfers = locations(h2_transfer_pattern)
if len(h2_transfers) != 1 or h2_transfers[0][0] != ingress_path:
    print(
        "the ingress H2 lookup must directly inject its typed cancellation capability",
        file=sys.stderr,
    )
    print(
        "transfer sites: "
        + (
            ", ".join(f"{path}:{line}" for path, line, _ in h2_transfers)
            or "none"
        ),
        file=sys.stderr,
    )
    raise SystemExit(1)

h2_removal_pattern = re.compile(
    r"\.\s*extensions\s*\.\s*remove\s*::\s*<\s*"
    r"H2StreamCancellation\s*>\s*\("
)
h2_removals = locations(h2_removal_pattern)
if len(h2_removals) != 1 or h2_removals[0][0] != executor_path:
    print(
        "the H2 cancellation capability must be removed exactly once in forwarding_executor.rs",
        file=sys.stderr,
    )
    print(
        "removal sites: "
        + (
            ", ".join(f"{path}:{line}" for path, line, _ in h2_removals)
            or "none"
        ),
        file=sys.stderr,
    )
    raise SystemExit(1)


def closing_parenthesis(source: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "(":
            depth += 1
        elif source[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    line = source.count("\n", 0, opening) + 1
    raise SystemExit(
        f"unterminated bind_response_lifetime call beginning near line {line}"
    )


bind_start_pattern = re.compile(r"\.\s*bind_response_lifetime\s*\(")
h2_bindings = []
invalid_h2_bindings = []
for path, source in sources:
    for match in bind_start_pattern.finditer(source):
        opening = source.find("(", match.start(), match.end())
        closing = closing_parenthesis(source, opening)
        arguments = source[opening + 1 : closing]
        line = source.count("\n", 0, match.start()) + 1
        location = f"{path}:{line}"
        h2_bindings.append((path, location))
        if re.search(r"(?:^|,)\s*h2_stream\s*,?\s*$", arguments) is None:
            invalid_h2_bindings.append(location)
if len(h2_bindings) != 2 or any(path != executor_path for path, _ in h2_bindings):
    print(
        "H2 response lifetime binding must have exactly two production calls in forwarding_executor.rs",
        file=sys.stderr,
    )
    print(
        "binding sites: "
        + (", ".join(location for _, location in h2_bindings) or "none"),
        file=sys.stderr,
    )
    raise SystemExit(1)
if invalid_h2_bindings:
    print(
        "each response lifetime binding must receive the executor-owned h2_stream capability",
        file=sys.stderr,
    )
    print("invalid binding sites: " + ", ".join(invalid_h2_bindings), file=sys.stderr)
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
