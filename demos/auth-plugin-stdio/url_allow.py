#!/usr/bin/env python3

import argparse
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


def normalize_string_list(raw, location):
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, str):
        items = [raw]
    else:
        sys.stderr.write(f"{location} must be a string or list\n")
        sys.exit(1)

    normalized = []
    for item in items:
        if not isinstance(item, str):
            sys.stderr.write(f"{location} must contain strings\n")
            sys.exit(1)
        trimmed = item.strip()
        if not trimmed:
            sys.stderr.write(f"{location} must not contain empty values\n")
            sys.exit(1)
        normalized.append(trimmed)
    return normalized


def normalize_header_rules(raw):
    if raw is None:
        return None
    if not isinstance(raw, dict):
        sys.stderr.write("headers must be a map of header -> value(s)\n")
        sys.exit(1)

    normalized = {}
    for name, values in raw.items():
        if not isinstance(name, str) or not name.strip():
            sys.stderr.write("headers must have non-empty string keys\n")
            sys.exit(1)
        header_name = name.strip().lower()
        normalized[header_name] = set(normalize_string_list(values, f"headers.{name}"))
    return normalized


def collect_header_values(headers, name):
    value = headers.get(name)
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    if isinstance(value, str):
        return [value]
    return []


def headers_match(headers, rules):
    if rules is None:
        return True

    for name, allowed in rules.items():
        values = collect_header_values(headers, name)
        if not values:
            return False
        if not any(value in allowed for value in values):
            return False
    return True


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
    header_rules = normalize_header_rules(config.get("headers"))

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
        if isinstance(headers, dict):
            headers = {str(k).lower(): v for k, v in headers.items()}
        else:
            headers = {}

        decision = "allow" if is_allowed(url, allowlist) and headers_match(headers, header_rules) else "deny"

        response = {
            "id": request_id,
            "type": "response",
            "decision": decision,
        }

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
