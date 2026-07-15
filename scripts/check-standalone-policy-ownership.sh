#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

python3 - "$ROOT" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
scanned_paths = (
    pathlib.Path("src/proxy/ingress.rs"),
    pathlib.Path("src/proxy/forward.rs"),
    pathlib.Path("src/proxy/upgrade_relay.rs"),
    pathlib.Path("src/http1/ingress.rs"),
)

forbidden = (
    ("product policy import", re.compile(r"\bcrate\s*::\s*policy\b")),
    ("policy accessor", re.compile(r"\.\s*policy\s*\(")),
    (
        "policy snapshot/evaluation/outcome/result",
        re.compile(
            r"\b(?:[A-Za-z_][A-Za-z0-9_]*)?Policy(?:Snapshot|Evaluation|Outcome|Result)\b"
            r"|\bpolicy_?(?:snapshot|evaluation|outcome|result)\b",
            re.IGNORECASE,
        ),
    ),
    ("allowed-request type", re.compile(r"\bAllowedRequest\b")),
    ("request-decision module", re.compile(r"\b(?:crate\s*::\s*)?request_decision\b")),
    ("request-decision type", re.compile(r"\bRequestDecision\b")),
    ("request header effects", re.compile(r"\brequest_header_effects\b")),
    ("response header effects", re.compile(r"\bresponse_header_effects\b")),
    ("credential actions", re.compile(r"\bcredential_actions\b")),
    ("upgrade policy accessor", re.compile(r"\ballow_upgrades\b")),
    ("authoring policy DTO", re.compile(r"\bAuthoringConfig\b")),
    ("compiled policy DTO", re.compile(r"\bCompiled[A-Za-z0-9_]*Policy\b")),
)


def production_prefix(source: str) -> str:
    """Exclude inline test sections from the production ownership scan."""
    marker = re.search(
        r"(?m)^#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]",
        source,
    )
    if marker is not None:
        return source[: marker.start()]
    return source


def strip_comments(source: str) -> str:
    """Remove Rust comments while preserving strings and source line numbers."""
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
            output.append(char)
            index += 1
            if char == "\\" and index < len(source):
                output.append(source[index])
                index += 1
            elif char == '"':
                state = "code"
            continue
        if state == "raw-string":
            terminator = '"' + ("#" * raw_hashes)
            if source.startswith(terminator, index):
                output.extend(terminator)
                index += len(terminator)
                state = "code"
            else:
                output.append(char)
                index += 1
            continue
        if state == "char":
            output.append(char)
            index += 1
            if char == "\\" and index < len(source):
                output.append(source[index])
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
            output.append(char)
            index += 1
            state = "string"
        elif char == "r":
            raw = re.match(r'r(#+)?"', source[index:])
            if raw is None:
                output.append(char)
                index += 1
            else:
                opener = raw.group(0)
                output.extend(opener)
                index += len(opener)
                raw_hashes = len(raw.group(1) or "")
                state = "raw-string"
        elif char == "'":
            # A lifetime is followed by an identifier and has no closing quote.
            lifetime = re.match(r"'[A-Za-z_][A-Za-z0-9_]*", source[index:])
            if lifetime is not None:
                token = lifetime.group(0)
                output.extend(token)
                index += len(token)
            else:
                output.append(char)
                index += 1
                state = "char"
        else:
            output.append(char)
            index += 1
    return "".join(output)


def production(path: pathlib.Path) -> str:
    absolute = root / path
    if not absolute.is_file():
        raise SystemExit(f"standalone ownership scan path is missing: {path}")
    return strip_comments(production_prefix(absolute.read_text(encoding="utf-8")))


violations = []
for path in scanned_paths:
    source = production(path)
    for description, pattern in forbidden:
        match = pattern.search(source)
        if match is not None:
            line = source.count("\n", 0, match.start()) + 1
            violations.append(f"{path}:{line}: forbidden {description}: {match.group(0)}")

if violations:
    print("standalone listener/forwarding ownership violations:", file=sys.stderr)
    print("\n".join(violations), file=sys.stderr)
    raise SystemExit(1)

pipeline_path = pathlib.Path("src/request_pipeline.rs")
pipeline = production(pipeline_path)
all_production = []
for path in (root / "src").rglob("*.rs"):
    relative = path.relative_to(root)
    all_production.append((relative, production(relative)))

decision_call = re.compile(
    r"\b(?:DecisionProvider\s*::\s*decide|[A-Za-z_][A-Za-z0-9_]*\s*\.\s*decide)"
    r"\s*\(\s*&\s*facts\s*,"
)
decision_calls = []
for path, source in all_production:
    for match in decision_call.finditer(source):
        line = source.count("\n", 0, match.start()) + 1
        decision_calls.append(f"{path}:{line}")
if len(decision_calls) != 1 or not decision_calls[0].startswith("src/request_pipeline.rs:"):
    print("DecisionProvider::decide must have exactly one production caller in request_pipeline.rs", file=sys.stderr)
    print("call sites: " + (", ".join(decision_calls) or "none"), file=sys.stderr)
    raise SystemExit(1)

respond_calls = re.findall(r"\bcontext\s*\.\s*respond\s*\(", pipeline)
forward_calls = re.findall(r"\bcontext\s*\.\s*forward\s*\(", pipeline)
if len(respond_calls) != 1 or len(forward_calls) != 1:
    print(
        "request_pipeline.rs must own exactly one terminal respond and one terminal forward dispatch",
        file=sys.stderr,
    )
    print(
        f"dispatch counts: respond={len(respond_calls)} forward={len(forward_calls)}",
        file=sys.stderr,
    )
    raise SystemExit(1)

print("standalone policy ownership gate passed")
PY
