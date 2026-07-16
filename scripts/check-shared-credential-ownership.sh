#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

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
    ("credential source ordinal", re.compile(r"\b(?:struct|enum|type)\s+CredentialSourceIndex\b")),
    ("credential source registry", re.compile(r"\b(?:struct|enum|type)\s+CredentialSourceRegistry\b")),
    ("resolved product action", re.compile(r"\b(?:struct|enum|type)\s+ResolvedCredentialAction\b")),
    ("product resolver snapshot", re.compile(r"\b(?:struct|enum|type)\s+CredentialResolverSnapshot\b")),
    ("product resolver trait", re.compile(r"\b(?:trait|type)\s+CredentialResolver\b")),
    ("standalone binding manifest", re.compile(r"\b(?:struct|enum|type)\s+StandaloneCredentialBindingManifest\b")),
    ("standalone source bridge", re.compile(r"\b(?:struct|enum|type)\s+StandaloneCredentialSourceBinding\b")),
    ("standalone credential program", re.compile(r"\b(?:struct|enum|type)\s+StandaloneCredentialProgram\b")),
    ("standalone credential injector", re.compile(r"\b(?:trait|type)\s+StandaloneCredentialInjector\b")),
    ("staged provider credential renderer", re.compile(r"\b(?:struct|enum|type)\s+StagedProviderCredentialMutation\b")),
    ("provider credential injection error", re.compile(r"\b(?:struct|enum|type)\s+ProviderCredentialInjectionError\b")),
    ("product credential material", re.compile(r"\b(?:struct|enum|type)\s+(?:CredentialMaterial|ResolvedCredential|RenderedCredential(?:Set)?|ProviderCredentialMaterial(?:Store|Error)?)\b")),
    ("product secret owner", re.compile(r"\b(?:struct|enum|type)\s+SecretBytes\b")),
    ("resolved product header", re.compile(r"\b(?:struct|enum|type)\s+ResolvedHeader\b")),
    ("product credential action compiler", re.compile(r"\bfn\s+resolve(?:d)?_credential_actions?\b")),
    ("product credential renderer", re.compile(r"\bfn\s+render_(?:bearer_|basic_)?credentials?\b")),
    ("sidecar credential bridge", re.compile(r"\bfn\s+take_credential_(?:program|preparation)\b")),
    ("provider credential staging renderer", re.compile(r"\bfn\s+stage_(?:credentials|credential_material)\b")),
    ("consumed credential bridge state", re.compile(r"\bcredential_program_taken\b")),
    ("rule credential bridge state", re.compile(r"\brule_credential_sources\b")),
    ("global credential bridge state", re.compile(r"\bglobal_credential_sources\b")),
    ("provider mutation bridge state", re.compile(r"\bprovider_credential_mutations\b")),
    ("credential program consumed bridge error", re.compile(r"\bCredentialProgramConsumed\b")),
    (
        "production process environment mutation",
        re.compile(
            r"\b(?:std\s*::\s*)?env\s*::\s*(?:set_var|remove_var)\s*\("
        ),
    ),
)

violations = []
for path, source in sources:
    for description, pattern in forbidden:
        for match in pattern.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            violations.append(f"{path}:{line}: forbidden {description}: {match.group(0)}")

if violations:
    print("legacy product credential ownership violations:", file=sys.stderr)
    print("\n".join(violations), file=sys.stderr)
    raise SystemExit(1)

resolver_path = pathlib.Path("src/credential_resolver.rs")
resolver = next((source for path, source in sources if path == resolver_path), None)
if resolver is None:
    raise SystemExit(f"shared credential product adapter is missing: {resolver_path}")
if re.search(r"\bimpl\s+CredentialResolver\s+for\s+ProductCredentialResolver\b", resolver) is None:
    raise SystemExit("product credential adapter must implement shared CredentialResolver")
if re.search(r"\bCredentialProgram\s*::\s*prepare\s*\(", resolver) is None:
    raise SystemExit("product credential adapter must prepare the shared CredentialProgram")
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
dependency = dependencies.get("credential-core")
if dependency is None:
    raise SystemExit("missing production dependency credential-core")
if dependency["kind"] is not None:
    raise SystemExit("credential-core must be a production dependency")
if dependency["req"] != "=0.1.0":
    raise SystemExit("credential-core must use exact version =0.1.0")
expected_path = root.parent / "access-runtime" / "crates" / "credential-core"
if pathlib.Path(dependency["path"]).resolve() != expected_path.resolve():
    raise SystemExit(f"credential-core must use the exact sibling path {expected_path}")
PY

printf 'shared credential ownership/deletion gate passed\n'
