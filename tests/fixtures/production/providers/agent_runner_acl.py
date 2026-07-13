#!/usr/bin/env python3

import argparse
import fnmatch
import json
import sys


def header_value(headers, name):
    value = headers.get(name)
    if isinstance(value, list):
        return value[0] if len(value) == 1 and isinstance(value[0], str) else None
    return value if isinstance(value, str) else None


def decide(request, config):
    if request.get("type") != "request" or not isinstance(request.get("id"), str):
        return "deny"
    headers = request.get("headers")
    if not isinstance(headers, dict):
        return "deny"
    identity = header_value(headers, "x-aw-identity-token")
    patterns = config["identities"].get(identity, [])
    raw_url = request.get("url", "")
    return "allow" if any(fnmatch.fnmatchcase(raw_url, pattern) for pattern in patterns) else "deny"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    with open(args.config, "r", encoding="utf-8") as handle:
        config = json.load(handle)

    for line in sys.stdin:
        try:
            request = json.loads(line)
            response = {
                "id": request.get("id"),
                "type": "response",
                "decision": decide(request, config),
            }
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            response = {"id": None, "type": "response", "decision": "deny"}
        print(json.dumps(response, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
