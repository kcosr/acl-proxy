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


def checked_identity(request, authority):
    identity = request.get("identity")
    if not isinstance(identity, dict) or identity.get("state") != "authenticated":
        return None
    principal = identity.get("principal")
    groups = identity.get("groups")
    if (
        not isinstance(principal, dict)
        or principal.get("authority") != authority
        or not isinstance(principal.get("id"), str)
        or not isinstance(groups, list)
    ):
        return None
    checked_groups = set()
    for group in groups:
        if (
            not isinstance(group, dict)
            or group.get("authority") != authority
            or not isinstance(group.get("id"), str)
        ):
            return None
        checked_groups.add(group["id"])
    return principal["id"], checked_groups


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
    rule = config["rules"].get(request.get("ruleId"))
    if not isinstance(rule, dict):
        return "deny"
    headers = request.get("headers", {})
    if not isinstance(headers, dict):
        return "deny"
    context = header_value(headers, "x-aw-policy-context") or ""
    repository = repository_from_url(request.get("url", ""))
    identity = checked_identity(request, config["authority"])
    if identity is None or repository is None:
        return "deny"
    principal, groups = identity
    principal_allowed = rule.get("principals", {}).get(principal, {}).get(context, [])
    group_allowed = [
        repository
        for group in groups
        if repository in rule.get("groups", {}).get(group, {}).get(context, [])
    ]
    return "allow" if repository in principal_allowed or group_allowed else "deny"


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
