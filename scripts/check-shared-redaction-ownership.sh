#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if [[ -e src/redaction/snapshot.rs ]]; then
    printf 'src/redaction/snapshot.rs must be deleted; redaction compilation and matching belong to http-access-redaction\n' >&2
    exit 1
fi

python3 - "$ROOT" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
shared_root = root.parent / "access-runtime" / "crates" / "http-access-redaction" / "src"


def mask_non_code(source: str) -> str:
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
        if state in {"string", "char"}:
            output.append("\n" if char == "\n" else " ")
            index += 1
            if char == "\\" and index < len(source):
                output.append("\n" if source[index] == "\n" else " ")
                index += 1
            elif (state == "string" and char == '"') or (state == "char" and char == "'"):
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


def mask_range(source: str, start: int, end: int) -> str:
    masked = "".join("\n" if char == "\n" else " " for char in source[start:end])
    return source[:start] + masked + source[end:]


def matching_delimiter(source: str, opening: int, left: str, right: str) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == left:
            depth += 1
        elif source[index] == right:
            depth -= 1
            if depth == 0:
                return index + 1
    line = source.count("\n", 0, opening) + 1
    raise SystemExit(f"unterminated {left}{right} pair near line {line}")


class CfgParser:
    """Evaluate cfg expressions with `test = false` and other atoms unknown."""

    def __init__(self, expression: str):
        self.tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|[(),=]", expression)
        self.index = 0

    def parse(self):
        value = self.parse_expression()
        return value if self.index == len(self.tokens) else None

    def parse_expression(self):
        if self.index >= len(self.tokens):
            return None
        name = self.tokens[self.index]
        self.index += 1
        if self.index < len(self.tokens) and self.tokens[self.index] == "=":
            self.index += 1
            if self.index < len(self.tokens) and self.tokens[self.index] not in {",", ")"}:
                self.index += 1
            return None
        if self.index >= len(self.tokens) or self.tokens[self.index] != "(":
            return False if name == "test" else None

        self.index += 1
        values = []
        while self.index < len(self.tokens) and self.tokens[self.index] != ")":
            values.append(self.parse_expression())
            if self.index < len(self.tokens) and self.tokens[self.index] == ",":
                self.index += 1
            elif self.index < len(self.tokens) and self.tokens[self.index] != ")":
                return None
        if self.index >= len(self.tokens):
            return None
        self.index += 1

        if name == "all":
            if any(value is False for value in values):
                return False
            return True if all(value is True for value in values) else None
        if name == "any":
            if any(value is True for value in values):
                return True
            return False if all(value is False for value in values) else None
        if name == "not" and len(values) == 1:
            return None if values[0] is None else not values[0]
        return None


def cfg_is_test_only(attribute: str) -> bool:
    match = re.fullmatch(r"\s*cfg\s*\((.*)\)\s*", attribute, re.DOTALL)
    return match is not None and CfgParser(match.group(1)).parse() is False


def attributed_item_end(source: str, start: int) -> int:
    cursor = start
    paren_depth = 0
    bracket_depth = 0
    angle_depth = 0
    item_prefix = source[start : start + 160]
    block_item = re.match(
        r"\s*(?:(?:pub(?:\s*\([^)]*\))?|async|const|unsafe|extern)\s+)*"
        r"(?:fn|impl|mod|trait|struct|enum|union)\b",
        item_prefix,
    ) is not None

    while cursor < len(source):
        char = source[cursor]
        if char == "(":
            paren_depth += 1
        elif char == ")" and paren_depth:
            paren_depth -= 1
        elif char == "[":
            bracket_depth += 1
        elif char == "]" and bracket_depth:
            bracket_depth -= 1
        elif char == "<" and paren_depth == 0 and bracket_depth == 0:
            angle_depth += 1
        elif char == ">" and angle_depth:
            angle_depth -= 1
        elif paren_depth == 0 and bracket_depth == 0 and angle_depth == 0:
            if char == "{":
                end = matching_delimiter(source, cursor, "{", "}")
                trailing = re.match(r"\s*[,;]?", source[end:])
                return end + len(trailing.group(0))
            if char == ";" or (char == "," and not block_item):
                return cursor + 1
        cursor += 1
    line = source.count("\n", 0, start) + 1
    raise SystemExit(f"unsupported cfg(test) item near line {line}")


def mask_test_only(source: str) -> str:
    search_from = 0
    while True:
        attribute_start = source.find("#", search_from)
        while attribute_start != -1:
            cursor = attribute_start + 1
            whitespace = re.match(r"\s*", source[cursor:])
            cursor += len(whitespace.group(0))
            crate_level = cursor < len(source) and source[cursor] == "!"
            if crate_level:
                cursor += 1
                whitespace = re.match(r"\s*", source[cursor:])
                cursor += len(whitespace.group(0))
            if cursor < len(source) and source[cursor] == "[":
                break
            attribute_start = source.find("#", attribute_start + 1)
        if attribute_start == -1:
            return source

        group_start = attribute_start
        group_end = attribute_start
        test_only = False
        crate_test_only = False
        cursor = attribute_start
        while True:
            marker = cursor + 1
            whitespace = re.match(r"\s*", source[marker:])
            marker += len(whitespace.group(0))
            crate_level = marker < len(source) and source[marker] == "!"
            if crate_level:
                marker += 1
                whitespace = re.match(r"\s*", source[marker:])
                marker += len(whitespace.group(0))
            if marker >= len(source) or source[marker] != "[":
                break
            end = matching_delimiter(source, marker, "[", "]")
            attribute = source[marker + 1 : end - 1]
            if cfg_is_test_only(attribute):
                test_only = True
                crate_test_only = crate_test_only or crate_level
            group_end = end
            whitespace = re.match(r"\s*", source[group_end:])
            cursor = group_end + len(whitespace.group(0))
            if cursor >= len(source) or source[cursor] != "#":
                break

        if crate_test_only:
            return mask_range(source, 0, len(source))
        if test_only:
            end = attributed_item_end(source, cursor)
            source = mask_range(source, group_start, end)
            search_from = group_start
        else:
            source = mask_range(source, group_start, group_end)
            search_from = group_start


def production(path: pathlib.Path, base: pathlib.Path) -> str:
    source = mask_non_code((base / path).read_text(encoding="utf-8"))
    try:
        return mask_test_only(source)
    except SystemExit as error:
        raise SystemExit(f"{path}: {error}") from error


product_sources = []
for path in sorted((root / "src").rglob("*.rs")):
    relative = path.relative_to(root)
    product_sources.append((relative, production(relative, root)))

forbidden_names = (
    "CompiledRedactionPayloads",
    "LiteralMatcher",
    "PendingIntervals",
    "PayloadClass",
    "PayloadLimit",
    "ProfileSnapshot",
    "ProfileHandle",
    "RedactionActivation",
    "RedactionLiteralEdge",
    "RedactionLiteralInterval",
    "RedactionLiteralNode",
    "RedactionLiteralProjection",
    "RedactionPlan",
    "RedactionProfileIndex",
    "RedactionProfilePlan",
    "RedactionProfileRegistry",
    "RedactionRulePlan",
    "RedactionSnapshot",
    "RedactionLimits",
    "RedactedPayload",
    "SnapshotError",
    "ZeroizingAhoCorasick",
    "ZeroizingPatternRefs",
)
name_group = "(?:" + "|".join(forbidden_names) + ")"
forbidden_product = (
    ("legacy redaction type", re.compile(rf"\b(?:struct|enum|trait|union|type)\s+{name_group}\b")),
    ("legacy redaction type alias", re.compile(rf"\btype\s+[A-Za-z_][A-Za-z0-9_]*[^;=]*=\s*[^;]*\b{name_group}\b")),
    ("legacy redaction alias", re.compile(rf"\b(?:struct|enum|trait|union|type)\s+[A-Za-z_][A-Za-z0-9_]*(?:RedactionMatcher|RedactionCompiler|RedactionProjection|RedactionRegistry|RedactionIndex)\b")),
    ("legacy redaction import alias", re.compile(rf"\buse\b[^;]*(?:\b{name_group}\s+as\s+[A-Za-z_][A-Za-z0-9_]*|\bas\s+{name_group})\b")),
    ("legacy redaction re-export", re.compile(rf"\bpub(?:\s*\([^)]*\))?\s+use\b[^;]*\b{name_group}\b")),
    ("direct regex-automata source use", re.compile(r"\b(?:regex_automata|DfaRegex)\b")),
    (
        "legacy redaction compiler or matcher function",
        re.compile(
            r"\bfn\s+(?:build_redaction_(?:regex|nfa|dfa)|redaction_(?:regex_resident_bytes|literal_reference_bytes|literal_projection|literal_scratch_bytes)|checked_redaction_matcher_resident_bytes|remaining_redaction_matcher_resident_bytes|replace_regex_bounded|replacement_shape|checked_output_len|wipe_vec_capacity)\b"
        ),
    ),
)

violations = []
for path, source in product_sources:
    for description, pattern in forbidden_product:
        for match in pattern.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            violations.append(f"{path}:{line}: forbidden {description}: {match.group(0)}")

if violations:
    print("legacy product redaction ownership violations:", file=sys.stderr)
    print("\n".join(violations), file=sys.stderr)
    raise SystemExit(1)

product_source = "\n".join(source for _, source in product_sources)
if re.search(r"\bhttp_access_redaction\b", product_source) is None:
    raise SystemExit("product production source must use http-access-redaction directly")

if not shared_root.is_dir():
    raise SystemExit(f"shared redaction source directory is missing: {shared_root}")
shared_sources = []
for path in sorted(shared_root.rglob("*.rs")):
    relative = path.relative_to(shared_root)
    shared_sources.append((relative, production(relative, shared_root)))
if not shared_sources:
    raise SystemExit("shared redaction source directory contains no Rust source")

forbidden_shared = (
    ("environment access", re.compile(r"\b(?:std::)?env::")),
    ("HTTP crate type", re.compile(r"\b(?:http|hyper)::")),
    (
        "product configuration type",
        re.compile(r"\b(?:AuthoringConfig|RedactionConfig|RedactionProfileConfig|ReloadableProductPlan)\b"),
    ),
    (
        "product capture or guarded-buffer type",
        re.compile(r"\b(?:CaptureArtifact\w*|CaptureBody|CaptureExactBytes|CaptureOperation|CapturePool|GuardedBody|HttpWireBodyGuard|WireBodyPool)\b"),
    ),
    (
        "product codec type",
        re.compile(
            r"\b(?:CaptureContentEncoding|WebSocketInflateSession|decode_capture\w*|permessage_deflate)\b"
            r"|\b(?:flate2|brotli|zstd|miniz_oxide)::"
        ),
    ),
    (
        "product WebSocket protocol type",
        re.compile(r"\b(?:WebSocketNegotiation|WebSocketDirection|WebSocketMessageCapture|FrameHeader|OpCode)\b"),
    ),
    ("filesystem type", re.compile(r"\b(?:std::fs|File|OpenOptions|Path|PathBuf)\b")),
)

shared_violations = []
for path, source in shared_sources:
    for description, pattern in forbidden_shared:
        for match in pattern.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            shared_violations.append(
                f"http-access-redaction/src/{path}:{line}: forbidden {description}: {match.group(0)}"
            )
if shared_violations:
    print("shared redaction boundary violations:", file=sys.stderr)
    print("\n".join(shared_violations), file=sys.stderr)
    raise SystemExit(1)
PY

metadata=$(cargo metadata --format-version 1 --no-deps)
python3 - "$ROOT" "$metadata" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
metadata = json.loads(sys.argv[2])
package = next(package for package in metadata["packages"] if package["name"] == "acl-proxy")
dependencies = package["dependencies"]

redaction_dependencies = [
    dependency for dependency in dependencies if dependency["name"] == "http-access-redaction"
]
if len(redaction_dependencies) != 1:
    raise SystemExit("acl-proxy must have exactly one direct http-access-redaction dependency")
dependency = redaction_dependencies[0]
if dependency["kind"] is not None:
    raise SystemExit("http-access-redaction must be a production dependency")
if dependency.get("rename") is not None:
    raise SystemExit("http-access-redaction dependency must not be renamed")
if dependency["req"] != "=0.1.0":
    raise SystemExit("http-access-redaction must use exact version =0.1.0")
expected_path = root.parent / "access-runtime" / "crates" / "http-access-redaction"
path = dependency.get("path")
if path is None or pathlib.Path(path).resolve() != expected_path.resolve():
    raise SystemExit(f"http-access-redaction must use the exact sibling path {expected_path}")

if any(dependency["name"] == "regex-automata" for dependency in dependencies):
    raise SystemExit("acl-proxy must not depend directly on regex-automata")
PY

printf 'shared redaction ownership/deletion gate passed\n'
