# Policy engine

The policy engine evaluates each request against an ordered list of rules and
returns the first match. If no rule matches, `policy.default` applies.

This doc focuses on behavior and concepts. For field-level details, see
`docs/config-reference.md`.

## Rule evaluation order

1. Normalize the request URL.
2. Normalize the client IP (if present).
3. Normalize the HTTP method (if present).
4. Evaluate rules in the order they appear:
   - Pattern match (if set)
   - Subnet match (if set)
   - Method match (if set)
5. First match wins.
6. If nothing matches, apply `policy.default`.

Invalid or unparseable URLs are always denied.

## URL normalization

The engine normalizes URLs to:

```
protocol + "//" + host[:port] + path + optional "?query"
```

Notes:
- The scheme is preserved (`http:` or `https:`).
- The host includes a port only when it was explicit in the URL.
- The path defaults to `/` when empty.
- Query strings are preserved; fragments are ignored.

## Pattern syntax

Patterns are matched case-insensitively against normalized URLs.

- Scheme is optional:
  - `https://example.com/**` and `example.com/**` both match `https` and `http`.
- Wildcards:
  - `*` matches any sequence of characters except `/`.
  - `**` matches any sequence of characters including `/`.
- Host-only patterns:
  - `https://example.com` matches `https://example.com` and `https://example.com/`.
  - It does not match deeper paths.

Examples:

```
https://example.com/api/**        # any path under /api
https://example.com/api/*/v1      # one segment between /api and /v1
example.com                       # host-only, any scheme
```

## Macros and rulesets

Macros are placeholders expanded before patterns are compiled:

```toml
[policy.macros]
repo = ["team/service-a", "team/service-b"]

[[policy.rulesets.git_repo]]
action = "allow"
pattern = "https://git.internal/{repo}.git/**"
```

Include rules expand a ruleset into concrete rules:

```toml
[[policy.rules]]
include = "git_repo"
add_url_enc_variants = true
```

`add_url_enc_variants = true` generates both raw and URL-encoded variants for
all placeholders used in the rule or ruleset.

## Methods and subnets

- `methods` can be a string or list. Values are normalized to uppercase.
- `subnets` accept IPv4 or IPv6 CIDR ranges.

Rules may omit `pattern` and match only on methods and/or subnets.

## Header actions

Rules can modify headers on matching requests/responses:

```toml
[[policy.rules.header_actions]]
direction = "request"          # request | response | both
action    = "set"              # set | add | remove | replace_substring
name      = "x-test"
value     = "one"
when      = "always"           # always | if_present | if_absent
```

Behavior:
- `set` replaces existing values; `add` appends; `remove` deletes.
- `replace_substring` rewrites textual header values.
- `when` is evaluated against the original header set before any actions run.

## Approval macros

When an allow rule uses `external_auth_profile`, header actions can reference
approval macros with `{{name}}`. The proxy discovers these placeholders and
includes descriptors in the external auth webhook payload. After approval, the
values are interpolated into header actions before they are applied.

See `docs/external-auth.md` for the full approval workflow.

## Debugging policies

Use the policy inspection CLI to see the fully expanded rule set:

```bash
acl-proxy policy dump --config config/acl-proxy.toml
```

Add `--format table` or `--format json` to control output.
