#!/usr/bin/env python3
"""Mutation self-test for the AWAP/v1 fixture gate."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Callable


sys.dont_write_bytecode = True
SOURCE_ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = SOURCE_ROOT / "scripts/check-awap-fixtures.py"
FIXTURE_PATH = SOURCE_ROOT / "tests/fixtures/awap/v1.json"


Document = dict[str, Any]
Mutation = Callable[[Document], None]


def vector(document: Document, name: str) -> dict[str, Any]:
    matches = [item for item in document["vectors"] if item["name"] == name]
    if len(matches) != 1:
        raise AssertionError(f"fixture vector {name!r} is not unique")
    return matches[0]


def reframe(item: dict[str, Any]) -> None:
    kind = {"request": 1, "response": 2}[item["kind"]]
    body = item["body"].encode("ascii")
    item["frame_hex"] = (
        b"AWAP" + bytes((1, kind)) + len(body).to_bytes(4, "big") + body
    ).hex()


def mutate_frame_byte(document: Document, offset: int, value: int) -> None:
    item = vector(document, "allow-response")
    frame = bytearray.fromhex(item["frame_hex"])
    frame[offset] = value
    item["frame_hex"] = frame.hex()


def wrong_magic(document: Document) -> None:
    item = vector(document, "allow-response")
    frame = bytearray.fromhex(item["frame_hex"])
    frame[0:4] = b"AXAP"
    item["frame_hex"] = frame.hex()


def wrong_version(document: Document) -> None:
    mutate_frame_byte(document, 4, 2)


def wrong_kind(document: Document) -> None:
    mutate_frame_byte(document, 5, 1)


def wrong_length(document: Document) -> None:
    item = vector(document, "allow-response")
    frame = bytearray.fromhex(item["frame_hex"])
    declared = int.from_bytes(frame[6:10], "big")
    frame[6:10] = (declared + 1).to_bytes(4, "big")
    item["frame_hex"] = frame.hex()


def trailing_data(document: Document) -> None:
    vector(document, "allow-response")["frame_hex"] += "00"


def body_mismatch(document: Document) -> None:
    item = vector(document, "allow-response")
    item["body"] = item["body"].replace('"secret"', '"changed"', 1)


def member_order(document: Document) -> None:
    item = vector(document, "effects-allowed-request")
    body = json.loads(item["body"])
    item["body"] = json.dumps(
        {"type": body.pop("type"), **body}, separators=(",", ":")
    )
    reframe(item)


def forbidden_body_field(document: Document) -> None:
    item = vector(document, "effects-allowed-request")
    body = json.loads(item["body"])
    body["body"] = "forbidden"
    item["body"] = json.dumps(body, separators=(",", ":"))
    reframe(item)


def forbidden_remote_field(document: Document) -> None:
    item = vector(document, "effects-allowed-request")
    body = json.loads(item["body"])
    body["remoteEndpoint"] = "https://remote.example.test"
    item["body"] = json.dumps(body, separators=(",", ":"))
    reframe(item)


def schema_corruption(document: Document) -> None:
    document["obsolete"] = {}


MUTATIONS: tuple[tuple[str, Mutation], ...] = (
    ("magic", wrong_magic),
    ("version", wrong_version),
    ("kind", wrong_kind),
    ("length", wrong_length),
    ("trailing data", trailing_data),
    ("body equality", body_mismatch),
    ("member order", member_order),
    ("forbidden body field", forbidden_body_field),
    ("forbidden remote field", forbidden_remote_field),
    ("fixture schema", schema_corruption),
)


def run_gate(path: Path, expect_success: bool, label: str) -> None:
    result = subprocess.run(
        [sys.executable, str(GATE_PATH), "--fixture", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if (result.returncode == 0) != expect_success:
        outcome = "pass" if expect_success else "rejection"
        raise AssertionError(
            f"{label}: expected {outcome}, got exit {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def write_document(path: Path, document: Document) -> None:
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    baseline = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(
        prefix=".awap-fixture-gate.", dir=SOURCE_ROOT
    ) as directory:
        fixture = Path(directory) / "v1.json"
        write_document(fixture, baseline)
        run_gate(fixture, True, "baseline")

        for label, mutation in MUTATIONS:
            mutated = copy.deepcopy(baseline)
            mutation(mutated)
            write_document(fixture, mutated)
            run_gate(fixture, False, label)

    print(
        "AWAP/v1 fixture gate self-test passed: "
        f"{len(MUTATIONS)} corruption mutations rejected"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
