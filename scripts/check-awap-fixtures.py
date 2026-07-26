#!/usr/bin/env python3
"""Validate the ACL Proxy's canonical AWAP/v1 language-neutral fixtures."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys
from types import ModuleType
from typing import Any


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE = ROOT / "tests/fixtures/awap/v1.json"
DEFAULT_DECODER = (
    ROOT.parent / "access-runtime/fixtures/access-rpc-framing/reference_decode.py"
)

MAGIC = "AWAP"
VERSION = 1
REQUEST_MAX_BODY_BYTES = 262144
RESPONSE_MAX_BODY_BYTES = 65536
VECTOR_INVENTORY = (
    ("effects-allowed-request", "request"),
    ("allow-response", "response"),
    ("deny-response", "response"),
    ("pass-response", "response"),
)
EXPECTED_ID = "u0000000000000001"
FORBIDDEN_FIELDS = frozenset(
    {
        "authorization",
        "bearer",
        "body",
        "config",
        "endpoint",
        "host",
        "port",
        "remote",
        "remoteendpoint",
        "remoteurl",
        "socket",
        "socketpath",
        "tls",
    }
)
HEX = re.compile(r"[0-9a-f]+")


def ordered_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def load_json(text: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(text, object_pairs_hook=ordered_object)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        raise ValueError(f"{label} is not valid duplicate-free JSON: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def read_fixture(path: Path) -> dict[str, Any]:
    try:
        return load_json(path.read_text(encoding="utf-8"), f"fixture {path}")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read UTF-8 fixture {path}: {error}") from error


def load_decoder(path: Path) -> ModuleType:
    if not path.is_file():
        raise ValueError(f"Runtime reference decoder is missing: {path}")
    spec = importlib.util.spec_from_file_location("awap_reference_decode", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load Runtime reference decoder: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except (OSError, ImportError, SyntaxError) as error:
        raise ValueError(f"cannot import Runtime reference decoder {path}: {error}") from error
    if not callable(getattr(module, "decode_frame", None)):
        raise ValueError(f"Runtime reference decoder has no decode_frame function: {path}")
    return module


def exact_keys(value: dict[str, Any], expected: tuple[str, ...], label: str) -> None:
    actual = tuple(value)
    if actual != expected:
        raise ValueError(
            f"{label} members must be exactly {expected} in that order, got {actual}"
        )


def exact_string(value: Any, expected: str, label: str) -> None:
    if not isinstance(value, str) or value != expected:
        raise ValueError(f"{label} must be exactly {expected!r}")


def normalized_field(name: str) -> str:
    return name.lower().replace("_", "").replace("-", "")


def reject_forbidden_fields(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if normalized_field(key) in FORBIDDEN_FIELDS:
                raise ValueError(f"{label} contains forbidden field {key!r}")
            reject_forbidden_fields(child, label)
    elif isinstance(value, list):
        for child in value:
            reject_forbidden_fields(child, label)


def check_request(body: dict[str, Any]) -> None:
    exact_keys(
        body,
        (
            "id",
            "type",
            "requestId",
            "ruleId",
            "invocation",
            "url",
            "method",
            "client",
            "headers",
            "identity",
        ),
        "request body",
    )
    exact_string(body["id"], EXPECTED_ID, "request id")
    exact_string(body["type"], "request", "request type")
    exact_string(body["requestId"], "acl-request-0001", "request requestId")
    exact_string(body["ruleId"], "engineering-gitlab", "request ruleId")
    exact_string(body["invocation"], "effects_allowed", "request invocation")
    exact_string(body["url"], "https://gitlab.example.test/a", "request url")
    exact_string(body["method"], "GET", "request method")
    exact_string(body["client"], "127.0.0.1:0", "request client")
    if body["headers"] != {}:
        raise ValueError("request headers must be the mandatory empty object")

    identity = body["identity"]
    if not isinstance(identity, dict):
        raise ValueError("request identity must be an object")
    exact_keys(identity, ("state", "principal", "groups"), "request identity")
    exact_string(identity["state"], "authenticated", "identity state")

    principal = identity["principal"]
    if not isinstance(principal, dict):
        raise ValueError("identity principal must be an object")
    exact_keys(principal, ("authority", "id", "kind"), "identity principal")
    exact_string(principal["authority"], "aw-workstation", "principal authority")
    exact_string(principal["id"], "container-a", "principal id")
    exact_string(principal["kind"], "service_account", "principal kind")

    groups = identity["groups"]
    if not isinstance(groups, list) or len(groups) != 1 or not isinstance(groups[0], dict):
        raise ValueError("identity groups must contain exactly one object")
    exact_keys(groups[0], ("authority", "id"), "identity group")
    exact_string(groups[0]["authority"], "aw-workstation", "group authority")
    exact_string(groups[0]["id"], "git-users", "group id")


def check_response(body: dict[str, Any], expected_decision: str) -> None:
    expected_keys = (
        ("id", "type", "decision", "values")
        if expected_decision == "allow"
        else ("id", "type", "decision")
    )
    exact_keys(body, expected_keys, f"{expected_decision} response body")
    exact_string(body["id"], EXPECTED_ID, f"{expected_decision} response id")
    exact_string(body["type"], "response", f"{expected_decision} response type")
    exact_string(
        body["decision"], expected_decision, f"{expected_decision} response decision"
    )
    if expected_decision == "allow":
        values = body["values"]
        if not isinstance(values, dict):
            raise ValueError("allow response values must be an object")
        exact_keys(values, ("api_token",), "allow response values")
        exact_string(values["api_token"], "secret", "allow response api_token")


def check_body(vector_name: str, body_text: Any) -> bytes:
    if not isinstance(body_text, str):
        raise ValueError(f"vector {vector_name!r} body must be a string")
    try:
        body_bytes = body_text.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError(f"vector {vector_name!r} body must be ASCII: {error}") from error
    body = load_json(body_text, f"vector {vector_name!r} body")
    canonical = json.dumps(body, ensure_ascii=True, separators=(",", ":"))
    if canonical != body_text:
        raise ValueError(f"vector {vector_name!r} body is not canonical compact JSON")
    reject_forbidden_fields(body, f"vector {vector_name!r} body")

    if vector_name == "effects-allowed-request":
        check_request(body)
    else:
        check_response(body, vector_name.removesuffix("-response"))
    return body_bytes


def check_document(document: dict[str, Any], decoder: ModuleType) -> None:
    exact_keys(document, ("protocol", "vectors"), "fixture")
    protocol = document["protocol"]
    if not isinstance(protocol, dict):
        raise ValueError("fixture protocol must be an object")
    exact_keys(
        protocol,
        (
            "magic",
            "version",
            "request_max_body_bytes",
            "response_max_body_bytes",
        ),
        "fixture protocol",
    )
    exact_string(protocol["magic"], MAGIC, "protocol magic")
    if type(protocol["version"]) is not int or protocol["version"] != VERSION:
        raise ValueError(f"protocol version must be exactly {VERSION}")
    if (
        type(protocol["request_max_body_bytes"]) is not int
        or protocol["request_max_body_bytes"] != REQUEST_MAX_BODY_BYTES
    ):
        raise ValueError(
            f"request body ceiling must be exactly {REQUEST_MAX_BODY_BYTES}"
        )
    if (
        type(protocol["response_max_body_bytes"]) is not int
        or protocol["response_max_body_bytes"] != RESPONSE_MAX_BODY_BYTES
    ):
        raise ValueError(
            f"response body ceiling must be exactly {RESPONSE_MAX_BODY_BYTES}"
        )

    vectors = document["vectors"]
    if not isinstance(vectors, list):
        raise ValueError("fixture vectors must be an array")
    inventory: list[tuple[Any, Any]] = []
    for index, vector in enumerate(vectors):
        if not isinstance(vector, dict):
            raise ValueError(f"vector {index} must be an object")
        exact_keys(vector, ("name", "kind", "body", "frame_hex"), f"vector {index}")
        inventory.append((vector["name"], vector["kind"]))
    if tuple(inventory) != VECTOR_INVENTORY:
        raise ValueError(
            f"vector inventory must be exactly {VECTOR_INVENTORY}, got {tuple(inventory)}"
        )

    for vector in vectors:
        name = vector["name"]
        kind = vector["kind"]
        body_bytes = check_body(name, vector["body"])
        ceiling = (
            protocol["request_max_body_bytes"]
            if kind == "request"
            else protocol["response_max_body_bytes"]
        )
        if len(body_bytes) > ceiling:
            raise ValueError(
                f"vector {name!r} body is {len(body_bytes)} bytes, exceeding {ceiling}"
            )

        frame_hex = vector["frame_hex"]
        if (
            not isinstance(frame_hex, str)
            or len(frame_hex) % 2 != 0
            or HEX.fullmatch(frame_hex) is None
        ):
            raise ValueError(
                f"vector {name!r} frame_hex must be contiguous lowercase hexadecimal"
            )
        frame = bytes.fromhex(frame_hex)
        kind_number = decoder.KINDS[kind]
        try:
            decoded = decoder.decode_frame(
                frame,
                MAGIC.encode("ascii"),
                VERSION,
                kind_number,
                ceiling,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(
                f"Runtime decoder rejected vector {name!r}: {error}"
            ) from error
        if decoded != body_bytes:
            raise ValueError(f"vector {name!r} decoded body does not equal body")

        expected_frame = (
            MAGIC.encode("ascii")
            + bytes((VERSION, kind_number))
            + len(body_bytes).to_bytes(4, "big")
            + body_bytes
        )
        if frame != expected_frame:
            raise ValueError(f"vector {name!r} frame is not the complete canonical frame")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--decoder", type=Path, default=DEFAULT_DECODER)
    args = parser.parse_args()

    decoder = load_decoder(args.decoder)
    document = read_fixture(args.fixture)
    check_document(document, decoder)
    print(
        "AWAP/v1 fixture gate passed: "
        f"{len(VECTOR_INVENTORY)} canonical request/response frames"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, TypeError, ValueError) as error:
        print(f"AWAP fixture failure: {error}", file=sys.stderr)
        raise SystemExit(1) from None
