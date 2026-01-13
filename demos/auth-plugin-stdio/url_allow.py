#!/usr/bin/env python3

import argparse
import base64
import fnmatch
import json
import sys


def load_config(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        sys.stderr.write(f"failed to load config: {exc}\n")
        sys.exit(1)


def normalize_allowlist(raw):
    if raw is None:
        sys.stderr.write("config must include allow list\n")
        sys.exit(1)
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, str):
        items = [raw]
    else:
        sys.stderr.write("allow must be a string or list\n")
        sys.exit(1)

    normalized = []
    for item in items:
        if not isinstance(item, str):
            sys.stderr.write("allow must contain strings\n")
            sys.exit(1)
        trimmed = item.strip()
        if not trimmed:
            sys.stderr.write("allow must not contain empty values\n")
            sys.exit(1)
        normalized.append(trimmed)
    return normalized


def normalize_tokens(raw):
    if raw is None:
        return None
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, str):
        items = [raw]
    else:
        sys.stderr.write("tokens must be a string or list\n")
        sys.exit(1)

    normalized = []
    for item in items:
        if not isinstance(item, str):
            sys.stderr.write("tokens must contain strings\n")
            sys.exit(1)
        trimmed = item.strip()
        if not trimmed:
            sys.stderr.write("tokens must not contain empty values\n")
            sys.exit(1)
        normalized.append(trimmed)
    return normalized


def extract_basic_token(auth_value):
    if not isinstance(auth_value, str):
        return None
    auth_value = auth_value.strip()
    if not auth_value.lower().startswith("basic "):
        return None
    encoded = auth_value[6:].strip()
    if not encoded:
        return None
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    return decoded.split(":", 1)[1]


def is_allowed(url, allowlist):
    for pattern in allowlist:
        if fnmatch.fnmatchcase(url, pattern):
            return True
    return False


def main():
    parser = argparse.ArgumentParser(description="URL allowlist auth plugin demo")
    parser.add_argument("--config", required=True, help="Path to JSON config")
    args = parser.parse_args()

    config = load_config(args.config)
    allowlist = normalize_allowlist(config.get("allow"))
    if not allowlist:
        sys.stderr.write("allow list must not be empty\n")
        sys.exit(1)
    tokens = normalize_tokens(config.get("tokens"))

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            msg = json.loads(line)
        except Exception:
            continue

        if msg.get("type") != "request":
            continue

        request_id = msg.get("id", "")
        url = msg.get("url", "")
        headers = msg.get("headers") or {}

        if tokens is None:
            token_ok = True
        else:
            auth = headers.get("authorization")
            if isinstance(auth, list):
                auth = auth[0] if auth else None
            token = extract_basic_token(auth)
            token_ok = token in tokens if token else False

        decision = "allow" if token_ok and is_allowed(url, allowlist) else "deny"

        response = {
            "id": request_id,
            "type": "response",
            "decision": decision,
        }

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
