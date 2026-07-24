#!/usr/bin/env python3

import argparse
import fnmatch
import json
import sys


def checked_principal(request, authority):
    identity = request.get("identity")
    if not isinstance(identity, dict) or identity.get("state") != "authenticated":
        return None
    principal = identity.get("principal")
    if (
        not isinstance(principal, dict)
        or principal.get("authority") != authority
        or not isinstance(principal.get("id"), str)
    ):
        return None
    return principal["id"]


def decide(request, config):
    if request.get("type") != "request" or not isinstance(request.get("id"), str):
        return "deny"
    rule = config["rules"].get(request.get("ruleId"))
    if not isinstance(rule, dict):
        return "deny"
    principal = checked_principal(request, config["authority"])
    if principal is None:
        return "deny"
    patterns = rule.get("principals", {}).get(principal, [])
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
