#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

python3 - "$ROOT" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
adapter_path = pathlib.Path("src/proxy/forwarding_adapter.rs")
ingress_path = pathlib.Path("src/proxy/ingress.rs")
activation_path = pathlib.Path("src/activation/product.rs")
generation_path = pathlib.Path("src/runtime/generation.rs")
proxy_module_path = pathlib.Path("src/proxy/mod.rs")
webhook_connector_path = pathlib.Path("src/authorization/webhook/connector.rs")
webhook_provider_path = pathlib.Path("src/authorization/webhook/provider.rs")
tls_path = pathlib.Path("src/tls.rs")
h2_context_path = pathlib.Path("src/proxy/h2_stream_cancellation.rs")
test_only_paths = set()


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
    raise SystemExit(f"unterminated #[cfg(test)] item near line {line}")


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
        raise SystemExit(f"forwarding ownership scan path is missing: {path}")
    source = mask_non_code(absolute.read_text(encoding="utf-8"))
    if path in test_only_paths:
        return mask_range(source, 0, len(source))
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


def locations(sources, pattern: re.Pattern[str]):
    matches = []
    for path, source in sources.items():
        for match in pattern.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            matches.append((path, line, match.group(0)))
    return matches


def require_exact_locations(description, matches, allowed_paths, count):
    escaped = [(path, line, text) for path, line, text in matches if path not in allowed_paths]
    if len(matches) != count or escaped:
        rendered = ", ".join(f"{path}:{line}" for path, line, _ in matches) or "none"
        print(f"{description} ownership violation", file=sys.stderr)
        print(f"locations: {rendered}", file=sys.stderr)
        raise SystemExit(1)


obsolete_files = (
    pathlib.Path("src/proxy/forward.rs"),
    pathlib.Path("src/proxy/forwarding_executor.rs"),
    pathlib.Path("src/proxy/standalone_body.rs"),
    pathlib.Path("src/destination.rs"),
)
obsolete = [str(path) for path in obsolete_files if (root / path).exists()]
destination_dir = root / "src/destination"
if destination_dir.exists() and any(destination_dir.rglob("*")):
    obsolete.append("src/destination/")
if obsolete:
    print("obsolete product forwarding owners must remain deleted", file=sys.stderr)
    print("obsolete paths: " + ", ".join(obsolete), file=sys.stderr)
    raise SystemExit(1)

required_paths = (
    adapter_path,
    ingress_path,
    activation_path,
    generation_path,
    proxy_module_path,
    webhook_connector_path,
    webhook_provider_path,
    tls_path,
    h2_context_path,
)
for path in required_paths:
    if not (root / path).is_file():
        raise SystemExit(f"forwarding ownership scan path is missing: {path}")

# External test modules are separate files, so their own source does not carry the
# cfg(test) attribute. Resolve conventional external test files and explicit
# cfg(test) module declarations before scanning the production source set.
for absolute in sorted((root / "src").rglob("*.rs")):
    relative = absolute.relative_to(root)
    if relative.name == "tests.rs" or relative.stem.endswith("_tests"):
        test_only_paths.add(relative)
    module_source = mask_non_code(absolute.read_text(encoding="utf-8"))
    for match in re.finditer(
        r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*"
        r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;",
        module_source,
    ):
        module = match.group(1)
        if relative.name in ("lib.rs", "main.rs", "mod.rs"):
            base = relative.parent
        else:
            base = relative.parent / relative.stem
        flat = base / f"{module}.rs"
        nested = base / module / "mod.rs"
        if (root / flat).is_file():
            test_only_paths.add(flat)
        if (root / nested).is_file():
            test_only_paths.add(nested)

sources = {}
for absolute in sorted((root / "src").rglob("*.rs")):
    relative = absolute.relative_to(root)
    sources[relative] = production(relative)

proxy_module = sources[proxy_module_path]
if len(re.findall(r"\bmod\s+forwarding_adapter\s*;", proxy_module)) != 1:
    raise SystemExit("src/proxy/mod.rs must declare forwarding_adapter exactly once")
obsolete_modules = re.findall(
    r"\bmod\s+(forward|forwarding_executor|standalone_body|destination)\s*;",
    proxy_module,
)
if obsolete_modules:
    raise SystemExit("obsolete product forwarding module declarations must remain deleted")

adapter = sources[adapter_path]
adapter_forbidden = (
    ("application state", re.compile(r"\bAppState\b")),
    ("generation lease", re.compile(r"\bGenerationLease\b")),
    ("product configuration", re.compile(r"\b(?:[A-Za-z_][A-Za-z0-9_]*)?Config\b")),
    ("configuration module", re.compile(r"\b(?:crate|super)\s*::\s*config\b")),
    ("authoring dependency", re.compile(r"\bAuthoring[A-Za-z0-9_]*\b|\bauthoring\b")),
    (
        "product policy evaluation",
        re.compile(
            r"\bcrate\s*::\s*policy\b|\b(?:evaluate|compile)_policy\b"
            r"|\b(?:PolicySnapshot|PolicyEvaluation|PolicyOutcome|PolicyResult)\b"
        ),
    ),
    (
        "provider dispatch",
        re.compile(
            r"\b(?:StandalonePolicyProvider|DecisionProvider|ProviderDispatcher)\b"
            r"|\.\s*decide\s*\("
        ),
    ),
)
adapter_violations = []
for description, pattern in adapter_forbidden:
    for match in pattern.finditer(adapter):
        line = adapter.count("\n", 0, match.start()) + 1
        adapter_violations.append(
            f"{adapter_path}:{line}: forbidden {description}: {match.group(0)}"
        )
if adapter_violations:
    print("forwarding adapter dependency violations:", file=sys.stderr)
    print("\n".join(adapter_violations), file=sys.stderr)
    raise SystemExit(1)

ingress_entry = re.compile(r"\b(?:crate\s*::\s*)?proxy\s*::\s*forwarding_adapter\s*::\s*execute\s*\(")
require_exact_locations(
    "ingress-to-adapter terminal entry",
    locations(sources, ingress_entry),
    {ingress_path},
    1,
)

shared_execute = re.compile(
    r"\.\s*execute\s*\(\s*dispatch\s*\.\s*exchange\s*,"
    r"\s*dispatch\s*\.\s*resolved\s*,\s*resources\s*\)"
)
require_exact_locations(
    "adapter-to-shared-executor terminal call",
    locations(sources, shared_execute),
    {adapter_path},
    1,
)

activation_call = re.compile(r"\bForwardingExecutor\s*::\s*activate\s*\(")
require_exact_locations(
    "shared forwarding executor activation",
    locations(sources, activation_call),
    {activation_path},
    1,
)

executor_type = re.compile(r"\bForwardingExecutor\b")
executor_locations = locations(sources, executor_type)
executor_allowed = {activation_path, generation_path}
escaped_executor = [
    (path, line, text)
    for path, line, text in executor_locations
    if path not in executor_allowed
]
if escaped_executor:
    print(
        "ForwardingExecutor storage and activation must remain confined to activation/product.rs and runtime/generation.rs",
        file=sys.stderr,
    )
    print(
        "escaped locations: "
        + ", ".join(f"{path}:{line}" for path, line, _ in escaped_executor),
        file=sys.stderr,
    )
    raise SystemExit(1)

adapter_only_types = (
    "ForwardingAdmission",
    "ForwardingDownstreamAbort",
    "ForwardingObservation",
    "ForwardingOutcome",
    "ForwardingRequestHead",
    "ForwardingResources",
    "ForwardingResponseHead",
    "ForwardingRetention",
    "ForwardingTerminal",
    "ForwardingTerminalOutcome",
    "ForwardingTerminalOwner",
    "PreparedUpgradeHandoff",
    "UpgradeHandoff",
    "UpgradeOffer",
    "UpstreamUpgradeBounds",
)
for symbol in adapter_only_types:
    matches = locations(sources, re.compile(rf"\b{symbol}\b"))
    if not matches or any(path != adapter_path for path, _, _ in matches):
        rendered = ", ".join(f"{path}:{line}" for path, line, _ in matches) or "none"
        print(f"{symbol} must be owned exclusively and non-vacuously by forwarding_adapter.rs", file=sys.stderr)
        print("locations: " + rendered, file=sys.stderr)
        raise SystemExit(1)

h2_lookup = re.compile(r"\bH2StreamCancellation\s*::\s*current\s*\(")
require_exact_locations(
    "ambient H2 cancellation lookup",
    locations(sources, h2_lookup),
    {ingress_path},
    1,
)

h2_injection = re.compile(
    r"\brequest\s*\.\s*extensions_mut\s*\(\s*\)\s*"
    r"\.\s*insert\s*\(\s*h2_stream\s*\)"
)
require_exact_locations(
    "typed H2 cancellation injection",
    locations(sources, h2_injection),
    {ingress_path},
    1,
)

h2_direct_transfer = re.compile(
    r"\bif\s+let\s+Some\s*\(\s*h2_stream\s*\)\s*=\s*"
    r"H2StreamCancellation\s*::\s*current\s*\(\s*\)\s*\{\s*"
    r"request\s*\.\s*extensions_mut\s*\(\s*\)\s*"
    r"\.\s*insert\s*\(\s*h2_stream\s*\)\s*;\s*\}"
)
require_exact_locations(
    "direct H2 cancellation capability transfer",
    locations(sources, h2_direct_transfer),
    {ingress_path},
    1,
)

h2_removal = re.compile(
    r"\.\s*extensions\s*\.\s*remove\s*::\s*<\s*H2StreamCancellation\s*>\s*\("
)
require_exact_locations(
    "adapter H2 cancellation ownership take",
    locations(sources, h2_removal),
    {adapter_path},
    1,
)

product_downstream_abort = locations(
    sources, re.compile(r"\bProductDownstreamAbort\b")
)
if not product_downstream_abort or any(
    path != adapter_path for path, _, _ in product_downstream_abort
):
    print(
        "ProductDownstreamAbort must remain confined non-vacuously to forwarding_adapter.rs",
        file=sys.stderr,
    )
    print(
        "locations: "
        + (
            ", ".join(f"{path}:{line}" for path, line, _ in product_downstream_abort)
            or "none"
        ),
        file=sys.stderr,
    )
    raise SystemExit(1)

require_exact_locations(
    "adapter downstream-abort implementation",
    locations(
        sources,
        re.compile(
            r"\bimpl\s+ForwardingDownstreamAbort\s+for\s+ProductDownstreamAbort\b"
        ),
    ),
    {adapter_path},
    1,
)

require_exact_locations(
    "adapter exact H2 stream cancellation",
    locations(sources, re.compile(r"\bself\s*\.\s*0\s*\.\s*cancel\s*\(\s*\)")),
    {adapter_path},
    1,
)

h2_executor_install = re.compile(
    r"\bHttp\s*::\s*new\s*\(\s*\)\s*\.\s*with_executor\s*\(\s*H2StreamExecutor\s*\)"
)
require_exact_locations(
    "ingress exact H2 stream executor installation",
    locations(sources, h2_executor_install),
    {ingress_path},
    1,
)

h2_context = sources[h2_context_path]
h2_context_invariants = (
    (
        r"tokio\s*::\s*task_local!\s*\{\s*static\s+CURRENT_H2_STREAM\s*:\s*H2StreamCancellation\s*;\s*\}",
        "one typed task-local H2 stream context is required",
    ),
    (
        r"CURRENT_H2_STREAM\s*\.\s*try_with\s*\(\s*Clone\s*::\s*clone\s*\)\s*\.\s*ok\s*\(\s*\)",
        "H2 cancellation lookup must clone only the current stream context",
    ),
    (
        r"let\s+cancellation\s*=\s*H2StreamCancellation\s*\(\s*Arc\s*::\s*new\s*\(\s*H2StreamCancellationState\s*\{\s*cancelled\s*:\s*AtomicBool\s*::\s*new\s*\(\s*false\s*\)\s*,\s*changed\s*:\s*Notify\s*::\s*new\s*\(\s*\)\s*,?\s*\}\s*\)\s*\)\s*;",
        "each Hyper H2 stream future must receive a fresh cancellation state",
    ),
    (
        r"CURRENT_H2_STREAM\s*\.\s*scope\s*\(\s*scoped_cancellation\s*,\s*async\s+move\s*\{\s*tokio\s*::\s*select!\s*\{\s*biased\s*;\s*_\s*=\s*cancellation\s*\.\s*cancelled\s*\(\s*\)\s*=>\s*\{\s*\}\s*_\s*=\s*future\s*=>\s*\{\s*\}\s*\}\s*\}\s*,?\s*\)",
        "the exact stream context must cancel its scoped Hyper future with priority",
    ),
)
for pattern, description in h2_context_invariants:
    if re.search(pattern, h2_context, re.S) is None:
        raise SystemExit(f"H2 stream cancellation context ownership violation: {description}")

h2_context_equivalence = re.compile(
    r"\bfn\s+h2_stream_context_matches\s*\(\s*downstream_is_h2\s*:\s*bool\s*,\s*"
    r"h2_stream_present\s*:\s*bool\s*\)\s*->\s*bool\s*\{\s*"
    r"downstream_is_h2\s*==\s*h2_stream_present\s*\}"
)
require_exact_locations(
    "adapter exact downstream-version/H2-context equivalence",
    locations(sources, h2_context_equivalence),
    {adapter_path},
    1,
)

h2_context_fail_closed = re.compile(
    r"\bif\s+!\s*h2_stream_context_matches\s*\(\s*downstream_supports_trailers\s*,\s*"
    r"h2_stream\s*\.\s*is_some\s*\(\s*\)\s*\)\s*\{\s*"
    r"return\s+internal_failure\s*\(\s*&\s*terminal\s*\.\s*capture\s*\)\s*;\s*\}"
)
require_exact_locations(
    "adapter fail-closed H2 context validation",
    locations(sources, h2_context_fail_closed),
    {adapter_path},
    1,
)

downstream_abort_transfer = re.compile(
    r"\bresources\s*=\s*resources\s*\.\s*with_downstream_abort\s*\(\s*"
    r"ProductDownstreamAbort\s*\(\s*h2_stream\s*\)\s*\)"
)
require_exact_locations(
    "adapter shared downstream-abort capability transfer",
    locations(sources, downstream_abort_transfer),
    {adapter_path},
    1,
)

h2_response_transfer = re.compile(
    r"ProxyResponseBody\s*::\s*forwarded\s*\(\s*body\s*,"
    r"\s*Arc\s*::\s*clone\s*\(\s*&\s*observation\s*\)\s*,\s*h2_stream\s*,"
    r"\s*downstream_supports_trailers\s*,\s*h1_content_length\s*,?\s*\)"
)
require_exact_locations(
    "adapter response-lifetime capability transfer",
    locations(sources, h2_response_transfer),
    {adapter_path},
    1,
)

upgrade_admission = re.compile(r"\bProductUpgradeHandoff\s*::\s*admit\s*\(")
require_exact_locations(
    "adapter pre-connect upgrade admission",
    locations(sources, upgrade_admission),
    {adapter_path},
    1,
)

upgrade_transfer = re.compile(
    r"\bresources\s*=\s*resources\s*\.\s*with_upgrade_handoff\s*\(\s*"
    r"handoff\s*,\s*bounds\s*\)"
)
require_exact_locations(
    "adapter admitted upgrade handoff transfer",
    locations(sources, upgrade_transfer),
    {adapter_path},
    1,
)


def braced_item_range(source: str, header: re.Pattern[str], description: str) -> tuple[int, int]:
    declarations = list(header.finditer(source))
    if len(declarations) != 1:
        raise SystemExit(f"forwarding_adapter.rs must define exactly one {description}")
    opening = source.find("{", declarations[0].end())
    if opening == -1:
        raise SystemExit(f"forwarding_adapter.rs {description} has no body")
    return declarations[0].start(), matching_brace(source, opening)


def function_range(source: str, name: str) -> tuple[int, int]:
    declarations = list(re.finditer(rf"\bfn\s+{re.escape(name)}\s*\(", source))
    if len(declarations) != 1:
        raise SystemExit(
            f"forwarding_adapter.rs must define exactly one production {name} function"
        )
    opening = source.find("{", declarations[0].end())
    if opening == -1:
        raise SystemExit(f"forwarding_adapter.rs {name} function has no body")
    return declarations[0].start(), matching_brace(source, opening)


handoff_impl_start, handoff_impl_end = braced_item_range(
    adapter,
    re.compile(r"\bimpl\s+ProductUpgradeHandoff\s*\{"),
    "inherent ProductUpgradeHandoff implementation",
)
handoff_impl = adapter[handoff_impl_start:handoff_impl_end]
admit_start, admit_end = function_range(handoff_impl, "admit")
admit_source = handoff_impl[admit_start:admit_end]
try_spawn = re.compile(r"\.\s*try_spawn_handshake\s*\(")
if len(list(try_spawn.finditer(adapter))) != 1 or try_spawn.search(admit_source) is None:
    raise SystemExit(
        "upgrade runtime admission must occur exactly once inside ProductUpgradeHandoff::admit"
    )

admission_match = upgrade_admission.search(adapter)
upgrade_transfer_match = upgrade_transfer.search(adapter)
shared_execute_match = shared_execute.search(adapter)
downstream_abort_match = downstream_abort_transfer.search(adapter)
if not (
    admission_match
    and upgrade_transfer_match
    and shared_execute_match
    and downstream_abort_match
    and downstream_abort_match.start() < shared_execute_match.start()
    and admission_match.start() < upgrade_transfer_match.start() < shared_execute_match.start()
):
    raise SystemExit(
        "downstream abort and admitted upgrade handoff must be installed before shared executor publication"
    )

h1_length_binding = re.compile(r"\bh1_remaining\s*:\s*h1_content_length\b")
require_exact_locations(
    "ingress H1 content-length completion binding",
    locations(sources, h1_length_binding),
    {ingress_path},
    1,
)

for helper in ("poll_forwarded_h1_eof", "poll_forwarded_h1_fixed_final"):
    require_exact_locations(
        f"ingress {helper} completion owner",
        locations(sources, re.compile(rf"\b{helper}\b")),
        {ingress_path},
        3,
    )

require_exact_locations(
    "adapter suppressed-body completion owner",
    locations(sources, re.compile(r"\bcomplete_empty_response\b")),
    {adapter_path},
    2,
)
require_exact_locations(
    "adapter suppressed-body drain owner",
    locations(sources, re.compile(r"\bdrain_suppressed_response\b")),
    {adapter_path},
    2,
)

reset_content_selection = re.compile(
    r"\blet\s+reset_content\s*=\s*head\s*\.\s*status\s*\(\s*\)\s*==\s*"
    r"StatusCode\s*::\s*RESET_CONTENT\s*\.\s*as_u16\s*\(\s*\)\s*;"
)
require_exact_locations(
    "adapter exact reset-content classification",
    locations(sources, reset_content_selection),
    {adapter_path},
    1,
)

no_content_selection = re.compile(
    r"\blet\s+no_content\s*=\s*head\s*\.\s*status\s*\(\s*\)\s*==\s*"
    r"StatusCode\s*::\s*NO_CONTENT\s*\.\s*as_u16\s*\(\s*\)\s*;"
)
require_exact_locations(
    "adapter exact no-content classification",
    locations(sources, no_content_selection),
    {adapter_path},
    1,
)

h1_suppressed_length_bypass = re.compile(
    r"\blet\s+h1_content_length\s*=\s*if\s+downstream_supports_trailers\s*\|\|\s*"
    r"no_content\s*\|\|\s*reset_content\s*\{\s*None"
)
require_exact_locations(
    "adapter suppressed H1 content-length parse bypass",
    locations(sources, h1_suppressed_length_bypass),
    {adapter_path},
    1,
)

suppressed_body_selection = re.compile(
    r"\blet\s+downstream_suppresses_body\s*=\s*downstream_is_head\s*\|\|\s*"
    r"no_content\s*\|\|\s*reset_content\s*\|\|\s*head\s*\.\s*status\s*\(\s*\)\s*==\s*304\s*;"
)
require_exact_locations(
    "adapter semantic response-body suppression selection",
    locations(sources, suppressed_body_selection),
    {adapter_path},
    1,
)

reset_content_normalization = re.compile(
    r"\bif\s+no_content\s*\{\s*"
    r"response\s*\.\s*headers_mut\s*\(\s*\)\s*\.\s*remove\s*\(\s*"
    r"CONTENT_LENGTH\s*\)\s*;\s*\}\s*else\s+if\s+reset_content\s*\{\s*"
    r"response\s*\.\s*headers_mut\s*\(\s*\)\s*\.\s*remove\s*\(\s*"
    r"CONTENT_LENGTH\s*\)\s*;\s*"
    r"response\s*\.\s*headers_mut\s*\(\s*\)\s*\.\s*insert\s*\(\s*"
    r"CONTENT_LENGTH\s*,\s*HeaderValue\s*::\s*from_static\s*\(\s*\)\s*\)\s*;\s*\}"
)
require_exact_locations(
    "adapter reset-content framing normalization",
    locations(sources, reset_content_normalization),
    {adapter_path},
    1,
)

zero_content_length_token = "OWNERSHIP_EXACT_ZERO_CONTENT_LENGTH"
adapter_with_zero_literal = mask_test_items(
    mask_non_code(
        (root / adapter_path)
        .read_text(encoding="utf-8")
        .replace('"0"', zero_content_length_token)
    )
)
zero_content_length_insert = re.compile(
    rf"\.\s*insert\s*\(\s*CONTENT_LENGTH\s*,\s*HeaderValue\s*::\s*"
    rf"from_static\s*\(\s*{zero_content_length_token}\s*\)\s*\)"
)
if len(list(zero_content_length_insert.finditer(adapter_with_zero_literal))) != 1:
    raise SystemExit("adapter reset-content framing normalization ownership violation")

suppressed_body_completion = re.compile(
    r"\bif\s+downstream_suppresses_body\s*\{\s*"
    r"drain_suppressed_response\s*\(\s*&\s*mut\s+body\s*\)\s*\.\s*await"
)
require_exact_locations(
    "adapter semantic response-body suppression completion",
    locations(sources, suppressed_body_completion),
    {adapter_path},
    1,
)
obsolete_empty_h1 = locations(sources, re.compile(r"\bcomplete_empty_h1_response\b"))
if obsolete_empty_h1:
    print("the H1-specific empty-response completion helper must remain deleted", file=sys.stderr)
    print(
        "locations: " + ", ".join(f"{path}:{line}" for path, line, _ in obsolete_empty_h1),
        file=sys.stderr,
    )
    raise SystemExit(1)

for state_name in (
    "h1_remaining",
    "pending_h1_final",
    "h1_source_done",
    "data_done",
    "trailers_done",
):
    state_locations = locations(sources, re.compile(rf"\b{state_name}\b"))
    if not state_locations or any(path != ingress_path for path, _, _ in state_locations):
        print(
            f"response completion state {state_name} must remain confined non-vacuously to ingress.rs",
            file=sys.stderr,
        )
        print(
            "locations: "
            + (", ".join(f"{path}:{line}" for path, line, _ in state_locations) or "none"),
            file=sys.stderr,
        )
        raise SystemExit(1)

private_forwarding_symbols = re.compile(
    r"\b(?:forward_request|forward_upgrade_request|DestinationGuard|DestinationConnector|StandaloneBody)\b"
)
private_locations = locations(sources, private_forwarding_symbols)
if private_locations:
    print("obsolete product-private ordinary forwarding primitives must remain absent", file=sys.stderr)
    print(
        "locations: " + ", ".join(f"{path}:{line}" for path, line, _ in private_locations),
        file=sys.stderr,
    )
    raise SystemExit(1)

client_transport_patterns = (
    ("socket dialing", re.compile(r"\b(?:(?:tokio|std)\s*::\s*net\s*::\s*)?(?:TcpStream|UnixStream)\s*::\s*connect\s*\(|\bTcpSocket\s*::|\bsocket2\s*::\s*Socket\b")),
    ("DNS resolution", re.compile(r"\b(?:tokio\s*::\s*net\s*::\s*)?lookup_host\s*\(|\bToSocketAddrs\b")),
    ("private Hyper client", re.compile(r"\bhyper\s*::\s*client\b|\bclient\s*::\s*conn\b|\bHttpConnector\b|\bHttpsConnector\b|\bhyper\s*::\s*Client\b")),
    ("private TLS connector", re.compile(r"\b(?:tokio_rustls\s*::\s*)?TlsConnector\b|\bhyper_rustls\b")),
    ("private client TLS config", re.compile(r"\b(?:rustls\s*::\s*)?(?:ClientConfig|ClientConnection)\b|\b(?:native_tls|tokio_native_tls|hyper_tls)\b")),
)
transport_allowed = {
    path for path in sources if path.parts[:3] == ("src", "authorization", "webhook")
}
transport_allowed.add(tls_path)
listener_socket_paths = {
    pathlib.Path("src/control/server.rs"),
    ingress_path,
    pathlib.Path("src/proxy/original_destination.rs"),
}
transport_violations = []
for description, pattern in client_transport_patterns:
    for path, line, text in locations(sources, pattern):
        if path not in transport_allowed:
            transport_violations.append(
                f"{path}:{line}: forbidden product-owned {description}: {text}"
            )
for path, source in sources.items():
    if path in transport_allowed:
        continue
    for use_path in parsed_use_paths(source):
        components = set(use_path)
        accepted_listener_socket = (
            path in listener_socket_paths
            and bool(components & {"tokio", "std"})
            and "net" in components
            and bool(components & {"TcpStream", "UnixStream", "TcpSocket"})
        )
        private_import = (
            ("hyper" in components and bool(components & {"client", "Client", "HttpConnector", "HttpsConnector"}))
            or bool(components & {"hyper_rustls", "hyper_tls", "native_tls", "tokio_native_tls", "socket2"})
            or (
                bool(components & {"tokio", "std"})
                and "net" in components
                and bool(components & {"TcpStream", "UnixStream", "TcpSocket", "lookup_host", "ToSocketAddrs"})
            )
            or ("tokio_rustls" in components and "TlsConnector" in components)
            or (
                "rustls" in components
                and bool(components & {"ClientConfig", "ClientConnection"})
            )
        )
        if private_import and not accepted_listener_socket:
            transport_violations.append(
                f"{path}: forbidden product-owned client transport import: {'::'.join(use_path)}"
            )
if transport_violations:
    print(
        "ordinary product forwarding must not own dialing, client TLS, or private Hyper client transport",
        file=sys.stderr,
    )
    print("\n".join(transport_violations), file=sys.stderr)
    raise SystemExit(1)

tls_helpers = re.compile(r"\b(?:build_client_config|load_client_trust|ClientAlpn)\b")
tls_helper_locations = locations(sources, tls_helpers)
tls_helper_allowed = {tls_path, webhook_provider_path}
escaped_tls_helpers = [
    (path, line, text)
    for path, line, text in tls_helper_locations
    if path not in tls_helper_allowed
]
if escaped_tls_helpers:
    print("retained client TLS helpers must remain webhook-only", file=sys.stderr)
    print(
        "escaped locations: "
        + ", ".join(f"{path}:{line}" for path, line, _ in escaped_tls_helpers),
        file=sys.stderr,
    )
    raise SystemExit(1)

webhook_connector = sources[webhook_connector_path]
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
    ("credential execution", r"\b(?:ProductCredentialExecution|CredentialResolverSession|TransportCredentialBatch)\b"),
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
for path in (adapter_path, pathlib.Path("src/egress.rs")):
    source = sources.get(path)
    if source is None:
        continue
    imports_authorization = any(
        "authorization" in use_path for use_path in parsed_use_paths(source)
    )
    qualifies_webhook = re.search(r"\b(?:WebhookConnector|authorization\s*::\s*webhook)\b", source)
    if imports_authorization or qualifies_webhook:
        ordinary_webhook_references.append(str(path))
if ordinary_webhook_references:
    print(
        "ordinary egress and forwarding adapter owners must not reference the authorization webhook connector",
        file=sys.stderr,
    )
    print("escaped references: " + ", ".join(ordinary_webhook_references), file=sys.stderr)
    raise SystemExit(1)

print("shared forwarding adapter ownership gate passed")
PY
