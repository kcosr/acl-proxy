#!/usr/bin/env python3

import argparse
import json
import sys
from urllib.parse import urlsplit


def header_value(headers, name):
    value = headers.get(name)
    if isinstance(value, list):
        return value[0] if len(value) == 1 and isinstance(value[0], str) else None
    return value if isinstance(value, str) else None


def repository_from_url(raw_url):
    parsed = urlsplit(raw_url)
    if parsed.scheme != "https" or parsed.hostname != "gitlab.example.test":
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return None
    return "/".join(parts[:2]).removesuffix(".git")


def decide(request, config):
    if request.get("type") != "request" or not isinstance(request.get("id"), str):
        return "deny"
    headers = request.get("headers")
    if not isinstance(headers, dict):
        return "deny"
    identity = header_value(headers, "x-aw-identity-token")
    context = header_value(headers, "x-aw-policy-context") or ""
    repository = repository_from_url(request.get("url", ""))
    identity_entry = config["identities"].get(identity)
    if identity_entry is None or repository is None:
        return "deny"
    allowed = identity_entry.get("contexts", {}).get(context, [])
    return "allow" if repository in allowed else "deny"


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
