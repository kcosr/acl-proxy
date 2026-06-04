#!/usr/bin/env python3

import argparse
import base64
import json
import re
import sys


def fail(message):
    sys.stderr.write(message + "\n")
    sys.exit(1)


def load_config(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        fail(f"failed to load config: {exc}")


def normalize_rules(config):
    rules = config.get("rules")
    if not isinstance(rules, list) or not rules:
        fail("config must include a non-empty rules list")

    normalized = []
    for index, raw in enumerate(rules):
        location = f"rules[{index}]"
        if not isinstance(raw, dict):
            fail(f"{location} must be an object")

        name = raw.get("name", f"rule-{index + 1}")
        if not isinstance(name, str) or not name.strip():
            fail(f"{location}.name must be a non-empty string")

        action = raw.get("action")
        if action not in ("deny", "redact"):
            fail(f"{location}.action must be deny or redact")

        matcher_type = raw.get("type")
        value = raw.get("value")
        if matcher_type not in ("literal", "regex"):
            fail(f"{location}.type must be literal or regex")
        if not isinstance(value, str) or not value:
            fail(f"{location}.value must be a non-empty string")

        rule = {
            "name": name.strip(),
            "action": action,
            "type": matcher_type,
            "value": value,
            "preserve_length": bool(raw.get("preserveLength", action == "redact")),
            "replacement": raw.get("replacement", "[REDACTED]"),
            "redaction_char": raw.get("redactionChar", "*"),
            "deny_message": None,
        }

        if not isinstance(rule["replacement"], str):
            fail(f"{location}.replacement must be a string")
        if not isinstance(rule["redaction_char"], str) or len(rule["redaction_char"]) != 1:
            fail(f"{location}.redactionChar must be one character")
        if "denyMessage" in raw:
            if action != "deny":
                fail(f"{location}.denyMessage is only valid on deny rules")
            deny_message = raw["denyMessage"]
            if not isinstance(deny_message, str):
                fail(f"{location}.denyMessage must be a string")
            deny_message = deny_message.strip()
            if deny_message:
                rule["deny_message"] = deny_message

        if matcher_type == "literal":
            case_sensitive = raw.get("caseSensitive", True)
            if not isinstance(case_sensitive, bool):
                fail(f"{location}.caseSensitive must be a boolean")
            flags = 0 if case_sensitive else re.IGNORECASE
            rule["regex"] = re.compile(re.escape(value), flags)
        else:
            flags = 0
            for flag in raw.get("flags", []):
                if flag == "ignore_case":
                    flags |= re.IGNORECASE
                elif flag == "multiline":
                    flags |= re.MULTILINE
                elif flag == "dotall":
                    flags |= re.DOTALL
                else:
                    fail(f"{location}.flags contains unsupported flag {flag!r}")
            try:
                rule["regex"] = re.compile(value, flags)
            except re.error as exc:
                fail(f"{location}.value is not a valid regex: {exc}")

        normalized.append(rule)

    return normalized


def decode_body(message):
    body = message.get("body")
    if body is None:
        return None
    if not isinstance(body, dict):
        return None
    if body.get("encoding") != "base64":
        return None
    data = body.get("data")
    if not isinstance(data, str):
        return None
    try:
        return base64.b64decode(data, validate=True)
    except Exception:
        return None


def decode_text(body_bytes):
    try:
        return body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None


def replacement_for_match(match, rule):
    if rule["preserve_length"]:
        return rule["redaction_char"] * len(match.group(0))
    return rule["replacement"]


def inspect_text(text, rules):
    changed = False
    matched_rules = []

    for rule in rules:
        regex = rule["regex"]
        if not regex.search(text):
            continue

        matched_rules.append(rule["name"])
        if rule["action"] == "deny":
            return {
                "decision": "deny",
                "text": text,
                "changed": changed,
                "matched_rules": matched_rules,
                "deny_message": rule["deny_message"],
            }

        text = regex.sub(lambda match: replacement_for_match(match, rule), text)
        changed = True

    return {
        "decision": "allow",
        "text": text,
        "changed": changed,
        "matched_rules": matched_rules,
        "deny_message": None,
    }


def build_response(request_id, result, content_type):
    response = {
        "id": request_id,
        "type": "response",
        "decision": result["decision"],
    }

    if result["decision"] == "allow" and result["changed"]:
        encoded = base64.b64encode(result["text"].encode("utf-8")).decode("ascii")
        request_body = {
            "encoding": "base64",
            "data": encoded,
        }
        if content_type:
            request_body["contentType"] = content_type
        response["requestBody"] = request_body

    if result["decision"] == "allow" and result["matched_rules"]:
        response["responseHeaders"] = [
            {
                "action": "set",
                "name": "x-acl-proxy-body-guard",
                "value": ",".join(result["matched_rules"]),
            }
        ]
    elif result["decision"] == "deny" and result.get("deny_message"):
        response["denyMessage"] = result["deny_message"]

    return response


def main():
    parser = argparse.ArgumentParser(description="Body inspection auth plugin demo")
    parser.add_argument("--config", required=True, help="Path to JSON rules")
    args = parser.parse_args()

    config = load_config(args.config)
    rules = normalize_rules(config)
    binary_decision = config.get("binaryDecision", "allow")
    if binary_decision not in ("allow", "deny"):
        fail("binaryDecision must be allow or deny")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            message = json.loads(line)
        except Exception:
            continue

        if message.get("type") != "request":
            continue

        request_id = message.get("id", "")
        body_bytes = decode_body(message)
        if body_bytes is None:
            result = {
                "decision": "allow",
                "text": "",
                "changed": False,
                "matched_rules": [],
                "deny_message": None,
            }
            response = build_response(request_id, result, None)
        else:
            text = decode_text(body_bytes)
            if text is None:
                result = {
                    "decision": binary_decision,
                    "text": "",
                    "changed": False,
                    "matched_rules": ["binary-body"],
                    "deny_message": None,
                }
                response = build_response(request_id, result, None)
            else:
                result = inspect_text(text, rules)
                content_type = (message.get("body") or {}).get("contentType")
                response = build_response(request_id, result, content_type)

        sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
