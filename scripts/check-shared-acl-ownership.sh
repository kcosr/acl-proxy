#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if [[ -e src/p05_contract_adapter_tests.rs ]]; then
    printf 'src/p05_contract_adapter_tests.rs must be deleted with the product ACL evaluator\n' >&2
    exit 1
fi

if [[ -e src/policy/snapshot.rs ]]; then
    printf 'src/policy/snapshot.rs must remain deleted; ACL evaluation belongs to http-access-policy-acl\n' >&2
    exit 1
fi

python3 - "$ROOT" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])


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
    while True:
        attribute_start = source.find("#")
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
        else:
            # Keep non-test attributes visible to the source scan, but avoid
            # repeatedly discovering the same attribute group.
            source = source[:group_start] + (" " * (group_end - group_start)) + source[group_end:]


def production(path: pathlib.Path) -> str:
    absolute = root / path
    source = mask_non_code(absolute.read_text(encoding="utf-8"))
    try:
        return mask_test_only(source)
    except SystemExit as error:
        raise SystemExit(f"{path}: {error}") from error


sources = []
for path in sorted((root / "src").rglob("*.rs")):
    relative = path.relative_to(root)
    sources.append((relative, production(relative)))

forbidden = (
    ("compiled snapshot", re.compile(r"\b(?:struct|type)\s+CompiledPolicySnapshot\b")),
    ("product policy activation", re.compile(r"\b(?:struct|enum|type)\s+PolicyActivation\b")),
    (
        "product policy activation error",
        re.compile(r"\b(?:struct|enum|type)\s+PolicyActivationError\b"),
    ),
    ("activated predicate rule", re.compile(r"\b(?:struct|type)\s+ActivatedPolicyRule\b")),
    ("product cursor", re.compile(r"\b(?:struct|type)\s+PolicyCursor\b")),
    ("product outcome", re.compile(r"\b(?:enum|type)\s+PolicyOutcome\b")),
    ("product evaluation", re.compile(r"\b(?:struct|enum|type)\s+PolicyEvaluation\b")),
    (
        "prepared product evaluation",
        re.compile(r"\b(?:struct|type)\s+PreparedPolicyEvaluation\b"),
    ),
    ("product rule match", re.compile(r"\b(?:struct|type)\s+PolicyRuleMatch\b")),
    ("product matcher", re.compile(r"\bfn\s+rule_matches\b")),
    ("product evaluator trait", re.compile(r"\b(?:trait|type)\s+PolicySnapshot\b")),
    ("resolved product bindings", re.compile(r"\b(?:struct|type)\s+ResolvedBindings\b")),
    (
        "resolved product rule bindings",
        re.compile(r"\b(?:struct|type)\s+ResolvedRuleBindings\b"),
    ),
    ("product evaluator", re.compile(r"\bfn\s+evaluate_at\b")),
    ("product header matcher", re.compile(r"\bfn\s+header_predicates_match\b")),
    ("product binding compiler", re.compile(r"\bfn\s+resolved_bindings\b")),
    ("temporary ACL comparator", re.compile(r"\bfn\s+compile_neutral_policy\b")),
    (
        "duplicate product provenance",
        re.compile(r"\bfn\s+(?:default|local|provider)_provenance\b"),
    ),
)

violations = []
for path, source in sources:
    for description, pattern in forbidden:
        for match in pattern.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            violations.append(f"{path}:{line}: forbidden {description}: {match.group(0)}")

if violations:
    print("legacy product ACL evaluator ownership violations:", file=sys.stderr)
    print("\n".join(violations), file=sys.stderr)
    raise SystemExit(1)

policy_source = "\n".join(
    source for path, source in sources if path.parts[:2] == ("src", "policy") or path == pathlib.Path("src/policy.rs")
)
policy_required = (
    ("TrafficPolicySnapshot", re.compile(r"\bTrafficPolicySnapshot\b")),
    ("ProductRuleEffectsRef", re.compile(r"\bProductRuleEffectsRef\b")),
)
for description, pattern in policy_required:
    if pattern.search(policy_source) is None:
        raise SystemExit(f"product policy adapter must use shared ACL {description}")

provider_path = pathlib.Path("src/standalone_policy_provider.rs")
provider_source = next((source for path, source in sources if path == provider_path), None)
if provider_source is None:
    raise SystemExit(f"shared ACL provider dispatch path is missing: {provider_path}")
if re.search(r"\.\s*resolve_delegate\s*\(", provider_source) is None:
    raise SystemExit("product provider dispatch must consume shared ACL resolve_delegate")
PY

metadata=$(cargo metadata --format-version 1 --no-deps)
python3 - "$ROOT" "$metadata" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
metadata = json.loads(sys.argv[2])
package = next(package for package in metadata["packages"] if package["name"] == "acl-proxy")
dependencies = {dependency["name"]: dependency for dependency in package["dependencies"]}
dependency = dependencies.get("http-access-policy-acl")
if dependency is None:
    raise SystemExit("missing production dependency http-access-policy-acl")
if dependency["kind"] is not None:
    raise SystemExit("http-access-policy-acl must be a production dependency")
if dependency["req"] != "=0.1.0":
    raise SystemExit("http-access-policy-acl must use exact version =0.1.0")
expected_path = root.parent / "access-runtime" / "crates" / "http-access-policy-acl"
if pathlib.Path(dependency["path"]).resolve() != expected_path.resolve():
    raise SystemExit(f"http-access-policy-acl must use the exact sibling path {expected_path}")
PY

printf 'shared ACL evaluator ownership/deletion gate passed\n'
