#!/usr/bin/env bash

set -Eeuo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SMOKE_PATH="${1:-$ROOT_DIR/scripts/production-topology-smoke.sh}"

python3 - "$SMOKE_PATH" <<'PY'
from pathlib import Path
import ast
import re
import shlex
import sys

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")


HEREDOC = re.compile(r"(?<!<)<<(?!<)(?P<tabs>-)?\s*(?:'(?P<single>[^']+)'|\"(?P<double>[^\"]+)\"|\\(?P<escaped>[A-Za-z_][A-Za-z0-9_]*)|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))")


def shell_executable_view(text):
    lines = text.splitlines(keepends=True)
    masked = []
    pending = []
    single = False
    double = False
    for line in lines:
        if pending:
            delimiter, strip_tabs = pending[0]
            candidate = line.rstrip("\r\n")
            if strip_tabs:
                candidate = candidate.lstrip("\t")
            masked.append("\n" if line.endswith("\n") else "")
            if candidate == delimiter:
                pending.pop(0)
            continue

        escaped = False
        carried_quote = single or double
        output = []
        heredocs = []
        index = 0
        while index < len(line):
            char = line[index]
            if escaped:
                output.append(" " if carried_quote and char not in "\r\n" else char)
                escaped = False
                index += 1
                continue
            if char == "\\" and not single:
                output.append(" " if carried_quote else char)
                escaped = True
                index += 1
                continue
            if char == "'" and not double:
                single = not single
                output.append(" " if carried_quote else char)
                if carried_quote and not single:
                    carried_quote = False
                index += 1
                continue
            if char == '"' and not single:
                double = not double
                output.append(" " if carried_quote else char)
                if carried_quote and not double:
                    carried_quote = False
                index += 1
                continue
            parameter_length = index >= 2 and line[index - 2:index] == "${"
            if char == "#" and not single and not double and not parameter_length:
                output.append("\n" if line.endswith("\n") else "")
                break
            if not single and not double:
                match = HEREDOC.match(line, index)
                if match is not None:
                    token = match.group(0)
                    output.append(token)
                    delimiter = match.group("single") or match.group("double") \
                        or match.group("escaped") or match.group("plain")
                    heredocs.append((delimiter, match.group("tabs") is not None))
                    index = match.end()
                    continue
            output.append(" " if carried_quote and char not in "\r\n" else char)
            index += 1
        executable_line = "".join(output)
        masked.append(executable_line)
        if not single and not double:
            pending.extend(heredocs)
    if pending:
        raise SystemExit(f"unterminated shell heredoc: {pending[0][0]}")
    if single or double:
        raise SystemExit("unterminated shell quote")
    return "".join(masked)


def extract_heredoc(anchor):
    lines = source.splitlines(keepends=True)
    matches = [index for index, line in enumerate(lines) if line.rstrip("\r\n") == anchor]
    if len(matches) != 1:
        raise SystemExit(f"expected one active heredoc anchor {anchor!r}, found {len(matches)}")
    match = HEREDOC.search(lines[matches[0]])
    if match is None:
        raise SystemExit(f"active heredoc anchor has no delimiter: {anchor}")
    delimiter = match.group("single") or match.group("double") or match.group("escaped") or match.group("plain")
    strip_tabs = match.group("tabs") is not None
    body = []
    for line in lines[matches[0] + 1:]:
        candidate = line.rstrip("\r\n")
        if strip_tabs:
            candidate = candidate.lstrip("\t")
        if candidate == delimiter:
            return "".join(body)
        body.append(line.lstrip("\t") if strip_tabs else line)
    raise SystemExit(f"unterminated active heredoc: {anchor}")


code = shell_executable_view(source)

active_python_anchors = {
    "origin": 'cat >"$TMP_DIR/origin/origin.py" <<\'PY\'',
    "client": 'cat >"$TMP_DIR/websocket_client.py" <<\'PY\'',
    "host_config": 'python3 - "$TMP_DIR/host/acl-proxy.toml" <<\'PY\'',
    "child_config": '    python3 - "$TMP_DIR/$role/acl-proxy.toml" <<\'PY\'',
    "signal": '    python3 - "$pid" "$expected" "$signal_name" <<\'PY\'',
}
shell_lines = code.splitlines()
for name, anchor in active_python_anchors.items():
    if shell_lines.count(anchor) != 1:
        raise SystemExit(f"active {name} Python heredoc anchor is not executable exactly once")

origin_python = extract_heredoc(active_python_anchors["origin"])
client_python = extract_heredoc(active_python_anchors["client"])
host_config_python = extract_heredoc(active_python_anchors["host_config"])
child_config_python = extract_heredoc(active_python_anchors["child_config"])
signal_python = extract_heredoc(active_python_anchors["signal"])

python_trees = {}
for name, body in {
    "origin": origin_python,
    "client": client_python,
    "host_config": host_config_python,
    "child_config": child_config_python,
    "signal": signal_python,
}.items():
    try:
        python_trees[name] = ast.parse(body, filename=f"<{name}-heredoc>")
    except SyntaxError as error:
        raise SystemExit(f"invalid active {name} Python heredoc: {error}") from error


def python_function_node(name, tree):
    matches = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
    if len(matches) != 1:
        raise SystemExit(f"expected one Python function {name}, found {len(matches)}")
    return matches[0]

def function_match(name):
    headers = re.findall(rf'(?m)^(?:function\s+{re.escape(name)}(?:\s*\(\))?|{re.escape(name)}\s*\(\))\s*\{{', code)
    if len(headers) != 1:
        raise SystemExit(f"expected one executable shell function header {name}, found {len(headers)}")
    matches = list(re.finditer(rf"(?ms)^{re.escape(name)}\(\) \{{(?P<body>.*?)^\}}", code))
    if len(matches) != 1:
        raise SystemExit(f"expected one executable shell function {name}, found {len(matches)}")
    body = matches[0].group("body")
    if re.search(r'^\s*if\s+false(?:\s*;|\s*$)', body, re.MULTILINE):
        raise SystemExit(f"static-false branch is forbidden in authoritative shell function: {name}")
    if re.search(r'^ {4}return(?:\s+[0-9]+)?\s*;?\s*$', body, re.MULTILINE):
        raise SystemExit(f"unconditional top-level return is forbidden in authoritative shell function: {name}")
    return matches[0]


def function_body(name):
    return function_match(name).group("body")


def shell_statements(body):
    statements = []
    continued = ""
    for line in body.splitlines():
        logical = continued + line.lstrip() if continued else line.strip()
        if logical.endswith("\\"):
            continued = logical[:-1] + " "
            continue
        continued = ""
        if not logical:
            continue
        try:
            statements.append(shlex.split(logical, comments=False, posix=True))
        except ValueError as error:
            raise SystemExit(f"invalid executable shell statement {logical!r}: {error}") from error
    if continued:
        raise SystemExit("unterminated shell line continuation")
    return statements


def statement_index(statements, expected, description):
    matches = [index for index, tokens in enumerate(statements) if tokens == list(expected)]
    if len(matches) != 1:
        raise SystemExit(f"expected one executable {description}, found {len(matches)}")
    return matches[0]


def require_executable(body, pattern, description):
    if re.search(pattern, body, re.MULTILINE) is None:
        raise SystemExit(f"missing executable smoke statement: {description}")


topology_identities = re.findall(
    r"(?m)^readonly TOPOLOGY_IDENTITY=([A-Za-z0-9._-]+)$",
    code,
)
if len(topology_identities) != 1 or len(topology_identities[0].encode("ascii")) < 32:
    raise SystemExit("topology identity must be one literal bearer of at least 32 bytes")
for alias in ("HOST_IDENTITY", "COMMON_IDENTITY", "INTERNAL_IDENTITY"):
    assignments = re.findall(
        rf"(?m)^readonly {alias}=\$TOPOLOGY_IDENTITY$",
        code,
    )
    if len(assignments) != 1:
        raise SystemExit(f"{alias} must derive exactly once from the topology identity")

topology_statements = shell_statements(code)
for namespace, role, identity, expected_count in (
    ("$HOST_NS", "host", "$HOST_IDENTITY", 2),
    ("$COMMON_NS", "common", "$COMMON_IDENTITY", 1),
    ("$INTERNAL_NS", "internal", "$INTERNAL_IDENTITY", 1),
):
    expected_launch = ["run_proxy", namespace, role, identity]
    if sum(tokens == expected_launch for tokens in topology_statements) != expected_count:
        raise SystemExit(
            f"expected {expected_count} executable {role} identity-bearing proxy launches"
        )

expected = [
    "p11_ws_direct_unprotected",
    "p11_ws_connect_mitm_fragmented_redaction_capture",
    "p11_ws_https_parent_protected_redaction",
    "p11_ws_admission_saturation",
    "p11_ws_reload_and_lifetime",
    "p11_ws_shutdown_join",
]
required_commands = {
    "p11_ws_direct_unprotected": [
        ("assert_ws_field", ["$result", "ASSERT_UNPROTECTED_LITERAL_UNCHANGED"]),
        ("assert_ws_field", ["$result", "ASSERT_NO_DETACHED_WORK"]),
        ("assert_origin_events", ["terminal-once:/direct", "message-is:/direct=fixture-secret-a-00000000000000000000"]),
    ],
    "p11_ws_connect_mitm_fragmented_redaction_capture": [
        ("assert_ws_field", ["$result", "ASSERT_FRAGMENTED_REDACTION"]),
        ("assert_capture_contains", ["/connect", "[CAPTURE-OLD]"]),
        ("assert_origin_events", ["terminal-once:/connect", "message-is:/connect=[REDACTED]"]),
    ],
    "p11_ws_https_parent_protected_redaction": [
        ("assert_ws_field", ["$result", "ASSERT_PARENT_TLS"]),
        ("assert_ws_field", ["$result", "ASSERT_INJECTED_IDENTITY_AUTHORIZATION"]),
        ("assert_ws_field", ["$result", "ASSERT_CONTEXT_REPLACED_AND_STRIPPED"]),
        ("assert_origin_events", ["headers-absent:/group/public.git/parent-protected"]),
    ],
    "p11_ws_admission_saturation": [
        ("assert_ws_field", ["$result", "ASSERT_ACCEPT_QUIET_WINDOW"]),
        ("assert_ws_field", ["$result", "ASSERT_NO_OVER_RELEASE"]),
        ("assert_ws_field", ["$result", "ASSERT_SLOT_RESTORED_EXACTLY_ONCE"]),
        ("assert_origin_events", ["accepted-once:/admission-restored-after-close"]),
    ],
    "p11_ws_reload_and_lifetime": [
        ("assert_ws_field", ["$result", "ASSERT_OLD_MATCHER"]),
        ("assert_ws_field", ["$result", "ASSERT_NEW_MATCHER"]),
        ("assert_ws_field", ["$result", "ASSERT_CAPTURE_EPOCH_BOUNDARY"]),
        ("assert_ws_field", ["$result", "ASSERT_LIFETIME_FROM_ORIGINAL_OPEN"]),
        ("assert_ws_field", ["$result", "ASSERT_RELOAD_DID_NOT_RESET_LIFETIME"]),
    ],
    "p11_ws_shutdown_join": [
        ("assert_ws_field", ["$result", "ASSERT_LISTENER_CLOSED_FIRST"]),
        ("assert_ws_field", ["$result", "ASSERT_GRACEFUL_PROCESS_EXIT"]),
        ("assert_ws_field", ["$result", "ASSERT_RELAY_TERMINALS_JOINED"]),
        ("assert_ws_field", ["$result", "ASSERT_CAPTURE_TASKS_FLUSHED"]),
        ("assert_ws_field", ["$result", "ASSERT_TASKS_JOINED"]),
    ],
}

for case in expected:
    body = function_body(case)
    if re.search(r'^\s*return(?:\s+[0-9]+)?\s*$', body, re.MULTILINE):
        raise SystemExit(f"unconditional early return is forbidden in P11 WebSocket case: {case}")
    statements = shell_statements(body)
    asserted = statement_index(statements, ["assert_ws_101", "$result"], f"{case} HTTP 101 assertion")
    streamed = statement_index(statements, ["ws_stream_assertions", "$result"], f"{case} stream assertion")
    marker = statement_index(statements, ["printf", "%s\\n", f"P11_WS_CASE {case} PASS"], f"{case} PASS marker")
    if not asserted < streamed < marker:
        raise SystemExit(f"P11 WebSocket case ordering is invalid: {case}")
    for command, required in required_commands[case]:
        matches = [tokens for tokens in statements if tokens and tokens[0] == command
                   and all(token in tokens[1:] for token in required)]
        if len(matches) != 1:
            raise SystemExit(f"P11 WebSocket case {case} lacks one reachable {command} proof: {required}")

host_identity_cases = [
    "p11_ws_direct_unprotected",
    "p11_ws_connect_mitm_fragmented_redaction_capture",
    "p11_ws_admission_saturation",
    "p11_ws_reload_and_lifetime",
    "p11_ws_shutdown_join",
]
for case in host_identity_cases:
    statements = shell_statements(function_body(case))
    presentations = [
        tokens
        for tokens in statements
        if "TOPOLOGY_IDENTITY=$TOPOLOGY_IDENTITY" in tokens
    ]
    command_prefix = "ip" if case == "p11_ws_shutdown_join" else "result=$(ip"
    expected_prefix = [
        command_prefix,
        "netns",
        "exec",
        "$HOST_NS",
        "env",
        "TOPOLOGY_IDENTITY=$TOPOLOGY_IDENTITY",
        "timeout",
    ]
    if (
        len(presentations) != 1
        or presentations[0][:len(expected_prefix)] != expected_prefix
        or any(
            token in {"env", "-u", "unset"}
            or token.startswith("TOPOLOGY_IDENTITY=")
            for token in presentations[0][len(expected_prefix):]
        )
    ):
        raise SystemExit(f"host-only WebSocket case lacks one exact trusted identity command: {case}")

parent_statements = shell_statements(function_body("p11_ws_https_parent_protected_redaction"))
parent_identity_command = [
    tokens
    for tokens in parent_statements
    if tokens[:8] == [
        "result=$(ip",
        "netns",
        "exec",
        "$COMMON_NS",
        "env",
        "-u",
        "TOPOLOGY_IDENTITY",
        "timeout",
    ]
]
if (
    len(parent_identity_command) != 1
    or any(
        token.startswith("TOPOLOGY_IDENTITY=")
        or token in {"env", "-u", "unset"}
        for token in parent_identity_command[0][8:]
    )
):
    raise SystemExit("disabled-identity child WebSocket case must explicitly clear topology identity")

assertion_body = function_body("assert_ws_101")
assertion_statements = shell_statements(assertion_body)
for proof in ("ASSERT_WS_101=1", "ASSERT_WS_ACCEPT=1"):
    matches = [tokens for tokens in assertion_statements if tokens[:4] == ["grep", "-qx", proof, "<<<$result"]
               and tokens[4:6] == ["||", "fail"]]
    if len(matches) != 1:
        raise SystemExit(f"assert_ws_101 does not executably enforce {proof}")

stream_body = function_body("ws_stream_assertions")
stream_statements = shell_statements(stream_body)
for proof in ("ASSERT_WS_STREAM=1", "ASSERT_WS_CLOSE=1"):
    matches = [tokens for tokens in stream_statements if tokens[:4] == ["grep", "-qx", proof, "<<<$result"]
               and tokens[4:6] == ["||", "fail"]]
    if len(matches) != 1:
        raise SystemExit(f"ws_stream_assertions does not executably enforce {proof}")

tail = code[function_match(expected[-1]).end():]
tail_statements = shell_statements(tail)
for case in expected:
    if sum(tokens == [case] for tokens in tail_statements) != 1:
        raise SystemExit(f"P11 WebSocket case is not invoked exactly once: {case}")

def statement_shape(statement):
    parsed = ast.parse(statement)
    if len(parsed.body) != 1:
        raise AssertionError(statement)
    return ast.dump(parsed.body[0], include_attributes=False)


def require_direct_python_statement(function, statement, description):
    expected_shape = statement_shape(statement)
    matches = [node for node in function.body
               if ast.dump(node, include_attributes=False) == expected_shape]
    if len(matches) != 1:
        raise SystemExit(f"active Python function lacks one direct {description}: {statement}")


client_tree = python_trees["client"]
client_identity_assignment = statement_shape(
    'IDENTITY = os.environ.get("TOPOLOGY_IDENTITY")'
)
if sum(
    ast.dump(node, include_attributes=False) == client_identity_assignment
    for node in client_tree.body
) != 1:
    raise SystemExit("generated WebSocket client must bind identity from TOPOLOGY_IDENTITY")

direct_node = python_function_node("direct_case", client_tree)
require_direct_python_statement(direct_node, 'sensitive = b"fixture-secret-a-00000000000000000000"', "direct literal assignment")
require_direct_python_statement(direct_node, "message(stream, sensitive, sensitive)", "direct unprotected message")

fragmented_node = python_function_node("fragmented_connect_case", client_tree)
require_direct_python_statement(fragmented_node, "stream.sendall(masked_frame(0x1, literal[:18], fin=False))", "first fragmented frame")
require_direct_python_statement(fragmented_node, "stream.sendall(masked_frame(0x0, literal[18:], fin=True))", "continuation fragmented frame")

tls_node = python_function_node("tls_wrap", client_tree)
require_direct_python_statement(tls_node, "context = ssl.create_default_context(cafile=ca)", "verified TLS context")

identity_headers_node = python_function_node("identity_headers", client_tree)
require_direct_python_statement(
    identity_headers_node,
    'return (("x-aw-identity-token", IDENTITY),) if IDENTITY else ()',
    "identity-header projection",
)

outer_connect_node = python_function_node("outer_connect", client_tree)
require_direct_python_statement(
    outer_connect_node,
    'headers = "".join(f"{name}: {value}\\r\\n" for name, value in identity_headers())',
    "outer CONNECT identity headers",
)

direct_open_node = python_function_node("direct_open", client_tree)
require_direct_python_statement(
    direct_open_node,
    'upgrade(stream, f"http://{host}:8080{path}", f"{host}:8080", identity_headers())',
    "direct request identity headers",
)

parent_node = python_function_node("parent_case", client_tree)
parent_assignments = [node for node in parent_node.body if isinstance(node, ast.Assign)
                      and isinstance(node.value, ast.Call)
                      and isinstance(node.value.func, ast.Name) and node.value.func.id == "mitm_open"]
if len(parent_assignments) != 1:
    raise SystemExit("parent_case must directly assign one mitm_open call")
extra_headers = [keyword.value for keyword in parent_assignments[0].value.keywords
                 if keyword.arg == "extra_headers"]
expected_headers = ast.parse(
    'x = (("x-aw-policy-context", "spoofed-client-context"),)'
).body[0].value
if len(extra_headers) != 1 or ast.dump(extra_headers[0], include_attributes=False) != ast.dump(expected_headers, include_attributes=False):
    raise SystemExit("parent_case lacks the exact disabled-ingress-safe context spoof fixture")
require_direct_python_statement(
    parent_node,
    """success(ASSERT_PARENT_TLS=1, ASSERT_INJECTED_IDENTITY_AUTHORIZATION=1,
        ASSERT_CONTEXT_REPLACED_AND_STRIPPED=1, ASSERT_CREDENTIAL_ISOLATION=1)""",
    "parent identity/context proof",
)
if "ASSERT_SPOOF_REPLACED_AND_STRIPPED" in source:
    raise SystemExit("stale spoof-replacement assertion name remains in topology smoke")

admission_node = python_function_node("admission_case", client_tree)
for statement in (
    "assert_no_origin_accept(event_path, before_second)",
    "assert_no_origin_accept(event_path, before_overrelease)",
    'rejected_upgrade("/admission-overrelease")',
):
    require_direct_python_statement(admission_node, statement, "admission proof")

reload_node = python_function_node("reload_case", client_tree)
for statement in (
    "opened_at = time.monotonic()",
    "time.sleep(1.0)",
    "lifetime_elapsed = closed_at - opened_at",
    "post_reload_elapsed = closed_at - reload_at",
    "assert post_reload_elapsed < 3.7, post_reload_elapsed",
    'message(new, b"old-secret", b"old-secret")',
    'message(new, b"new-secret", b"[WIRE-NEW]")',
    'captured(capture_directory, "/old-generation", b"[CAPTURE-OLD]")',
    'captured(capture_directory, "/old-generation", b"[CAPTURE-NEW]")',
):
    require_direct_python_statement(reload_node, statement, "reload/lifetime proof")

listener_closed_node = python_function_node("assert_listener_closed", client_tree)
expected_listener_closed = ast.parse(
    '''def expected():
    try:
        stream = socket.create_connection(("127.0.0.1", 8881), timeout=1)
    except ConnectionRefusedError:
        return
    stream.close()
    raise AssertionError("data listener accepted after WebSocket streams stopped")
'''
).body[0]
expected_listener_closed.name = "assert_listener_closed"
if ast.dump(listener_closed_node, include_attributes=False) != ast.dump(
    expected_listener_closed, include_attributes=False
):
    raise SystemExit("listener-closure proof must use one exact same-namespace refusal probe")

shutdown_python_node = python_function_node("shutdown_case", client_tree)
require_direct_python_statement(
    shutdown_python_node,
    "assert_listener_closed()",
    "listener closure after stream stop",
)
require_direct_python_statement(
    shutdown_python_node,
    """success(ASSERT_BOUNDED_STOP=1, ASSERT_STREAMS_STOPPED=1,
        ASSERT_LISTENER_CLOSED_FIRST=1)""",
    "listener-first shutdown result",
)

accept_node = python_function_node("accept_loop", python_trees["origin"])
accept_loops = [node for node in accept_node.body if isinstance(node, ast.While)
                and isinstance(node.test, ast.Constant) and node.test.value is True]
if len(accept_loops) != 1:
    raise SystemExit("origin accept_loop lacks its direct infinite accept loop")
accept_record = statement_shape('record("tcp_accept", connection=connection_id, listener=listener.getsockname()[1], client=address[0])')
if sum(ast.dump(node, include_attributes=False) == accept_record for node in accept_loops[0].body) != 1:
    raise SystemExit("origin accept loop lacks one direct tcp_accept record")


def require_config_replace(tree, old_text, new_fragment, description):
    matches = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        call = node.value
        if not isinstance(target, ast.Name) or target.id != "text" or not isinstance(call, ast.Call):
            continue
        if not isinstance(call.func, ast.Attribute) or call.func.attr != "replace":
            continue
        if not isinstance(call.func.value, ast.Name) or call.func.value.id != "text" or len(call.args) < 2:
            continue
        old, new = call.args[:2]
        if (isinstance(old, ast.Constant) and old.value == old_text
                and isinstance(new, ast.Constant) and isinstance(new.value, str)
                and new_fragment in new.value):
            matches.append(node)
    if len(matches) != 1:
        raise SystemExit(f"active config program lacks one direct {description} replacement")
    return matches[0]


host_policy_replace = require_config_replace(
    python_trees["host_config"],
    '[[policy.rules]]\nid = "prod-host-parent-connect"',
    'authorization_provider = "gitlab_acl"',
    "host protected-policy provider",
)
require_config_replace(
    python_trees["child_config"],
    'url = "http://host-proxy.example.test:8881"\n',
    'url = "https://host-proxy.example.test:8443"\n',
    "child HTTPS parent proxy",
)

host_config_tree = python_trees["host_config"]
listener_assignments = [
    node
    for node in host_config_tree.body
    if isinstance(node, ast.Assign)
    and len(node.targets) == 1
    and isinstance(node.targets[0], ast.Name)
    and node.targets[0].id == "listener"
    and isinstance(node.value, ast.Constant)
    and isinstance(node.value.value, str)
]
if len(listener_assignments) != 1 or (
    "\n[listeners.explicit_https.identity]\nmode = \"required\"\n"
    not in listener_assignments[0].value.value
):
    raise SystemExit("generated host HTTPS listener must require identity")

policy_anchor_assignment = statement_shape(
    'policy_anchor = \'[[policy.rules]]\\nid = "prod-host-parent-connect"\''
)
policy_anchor_guard = statement_shape(
    '''if text.count(policy_anchor) != 1:
    raise SystemExit("unexpected host policy anchor fixture shape")'''
)
anchor_assignments = [
    node
    for node in host_config_tree.body
    if ast.dump(node, include_attributes=False) == policy_anchor_assignment
]
anchor_guards = [
    node
    for node in host_config_tree.body
    if ast.dump(node, include_attributes=False) == policy_anchor_guard
]
if (
    len(anchor_assignments) != 1
    or len(anchor_guards) != 1
    or not anchor_assignments[0].lineno
    < anchor_guards[0].lineno
    < host_policy_replace.lineno
):
    raise SystemExit("host policy anchor requires one exact-count guard before replacement")

def require_tls_proxy_identity(statements, identity, description):
    identity_header = f"x-aw-identity-token: ${identity}"

    def is_identity_header(value):
        name, separator, _ = value.partition(":")
        return bool(separator) and name.strip().lower() == "x-aw-identity-token"

    def has_origin_identity_header(tokens):
        for index, token in enumerate(tokens):
            if token in {"-H", "--header"}:
                if index + 1 < len(tokens) and is_identity_header(tokens[index + 1]):
                    return True
            elif token.startswith("-H") and token != "-H":
                if is_identity_header(token[2:]):
                    return True
            elif token.startswith("--header="):
                if is_identity_header(token.removeprefix("--header=")):
                    return True
        return False

    matches = [
        tokens
        for tokens in statements
        if "https://host-proxy.example.test:8443" in tokens
        and "--proxy-cacert" in tokens
        and sum(
            tokens[index:index + 2] == ["--proxy-header", identity_header]
            for index in range(len(tokens) - 1)
        ) == 1
    ]
    if len(matches) != 1:
        raise SystemExit(f"{description} lacks one TLS proxy identity presentation")
    tokens = matches[0]
    if has_origin_identity_header(tokens):
        raise SystemExit(f"{description} sends proxy identity as an origin header")


require_tls_proxy_identity(
    shell_statements(function_body("direct_host_context_must_match_identity_authorization")),
    "COMMON_IDENTITY",
    "direct host authorization check",
)
require_tls_proxy_identity(
    shell_statements(code),
    "INTERNAL_IDENTITY",
    "direct host HTTP check",
)

signal_tree = python_trees["signal"]
pidfd_assignments = [node for node in signal_tree.body if isinstance(node, ast.Try)
                     for node in node.body if ast.dump(node, include_attributes=False)
                     == statement_shape("pidfd = os.pidfd_open(pid)")]
outer_signal_tries = [node for node in signal_tree.body if isinstance(node, ast.Try)
                      and any(ast.dump(child, include_attributes=False)
                              == statement_shape("signal.pidfd_send_signal(pidfd, signal_number)")
                              for child in node.body)]
if len(pidfd_assignments) != 1 or len(outer_signal_tries) != 1:
    raise SystemExit("pidfd signal helper must directly acquire and use one stable PID handle")
signal_try = outer_signal_tries[0]
identity_guard_shape = statement_shape('''if fields_after_comm[19] != expected_start_time or fields_after_comm[0] == "Z":
    raise SystemExit(1)''')
identity_guards = [node for node in signal_try.body
                   if ast.dump(node, include_attributes=False) == identity_guard_shape]
close_shape = statement_shape("os.close(pidfd)")
signal_calls = [node for node in signal_try.body
                if ast.dump(node, include_attributes=False)
                == statement_shape("signal.pidfd_send_signal(pidfd, signal_number)")]
if len(identity_guards) != 1 or sum(ast.dump(node, include_attributes=False) == close_shape
                                    for node in signal_try.finalbody) != 1:
    raise SystemExit("pidfd signal helper lacks direct identity/zombie validation or guaranteed close")
if len(signal_calls) != 1 or not pidfd_assignments[0].lineno < identity_guards[0].lineno < signal_calls[0].lineno:
    raise SystemExit("pidfd signal helper must acquire, validate, then signal in that order")

cleanup = function_body("cleanup")
terminate = function_body("terminate_owned_pid")
pid_identity = function_body("owns_pid")
signal_helper = function_body("signal_owned_pid")
field_assertion = function_body("assert_ws_field")
protected_case = function_body("p11_ws_https_parent_protected_redaction")
shutdown_case = function_body("p11_ws_shutdown_join")
failure_recorder = function_body("record_cleanup_failure")

terminate_statements = shell_statements(terminate)
statement_index(terminate_statements, ["signal_owned_pid", "TERM", "$pid", "2>/dev/null", "||", "true"], "owned PID pidfd TERM")
statement_index(terminate_statements, ["signal_owned_pid", "KILL", "$pid", "2>/dev/null", "||", "true"], "owned PID pidfd KILL")
require_executable(pid_identity, r'^\s*\[\[ -n "\$actual" && "\$actual" == "\$expected" \]\]\s*$', "PID start-time equality")
require_executable(cleanup, r'^\s*if \(\( final_status == 0 && \$\{#CLEANUP_FAILURES\[@\]\} > 0 \)\); then\s*$', "cleanup failure propagation")
require_executable(cleanup, r'^\s*final_status=1\s*$', "cleanup success-to-failure result")
require_executable(failure_recorder, r'^\s*CLEANUP_FAILURES\+=\("\$1"\)\s*$', "cleanup failure recording")
field_statements = shell_statements(field_assertion)
field_matches = [tokens for tokens in field_statements
                 if tokens[:4] == ["grep", "-qx", "$field=1", "<<<$result"]
                 and tokens[4:6] == ["||", "fail"]]
if len(field_matches) != 1:
    raise SystemExit("assert_ws_field lacks one reachable grep enforcement")
if "listener_closed_ns" in shutdown_case:
    raise SystemExit("shutdown case retains delayed shell listener-closure timing")
require_executable(shutdown_case, r'^\s*\(\( host_status == 0 \)\) \|\| fail ', "graceful shutdown status")
require_executable(shutdown_case, r'^\s*assert_origin_events terminal-once:/shutdown-direct terminal-once:/shutdown-connect\s*$', "shutdown relay joins")
require_executable(shutdown_case, r'^\s*assert_capture_contains /shutdown-connect ', "shutdown capture flush")
require_executable(code, r'^\s*\|\| fail "generated namespace configuration path already exists: /etc/netns/\$namespace"\s*$', "netns configuration collision rejection")
require_executable(code, r'^\s*OWNED_NAMESPACES\+=\("\$namespace"\)\s*$', "namespace ownership registration")
require_executable(code, r'^\s*OWNED_HOST_LINKS\+=\("\$host_veth"\)\s*$', "host-link ownership registration")
require_executable(code, r'^\s*-m comment --comment "acl-proxy-p11-\$SUFFIX"\s*$', "unique FORWARD rule ownership")
require_executable(cleanup, r'^\s*rm -rf "\$TMP_DIR" \|\| record_cleanup_failure ', "temporary directory deletion")
require_executable(cleanup, r'^\s*\[\[ -e "\$TMP_DIR" \]\] \\$', "temporary directory residue assertion")
require_executable(cleanup, r'^\s*&& record_cleanup_failure "temporary directory residue remains"\s*$', "temporary directory residue failure")
require_executable(cleanup, r'^\s*ip netns del "\$namespace" 2>/dev/null \\$', "owned namespace deletion")
require_executable(cleanup, r'^\s*\|\| record_cleanup_failure "could not delete owned namespace \$namespace"\s*$', "owned namespace deletion failure handling")
require_executable(cleanup, r'^\s*rm -rf "/etc/netns/\$namespace" \\$', "owned netns configuration deletion")
require_executable(cleanup, r'^\s*\|\| record_cleanup_failure "could not delete owned netns configuration \$namespace"\s*$', "owned netns configuration deletion failure handling")
require_executable(cleanup, r'^\s*record_cleanup_failure "owned namespace residue remains for \$namespace"\s*$', "owned namespace residue failure")
require_executable(cleanup, r'^\s*ip link del "\$link" 2>/dev/null \\$', "owned link deletion")
require_executable(cleanup, r'^\s*\|\| record_cleanup_failure "could not delete owned link \$link"\s*$', "owned link deletion failure handling")
require_executable(cleanup, r'^\s*&& record_cleanup_failure "owned link residue remains for \$link"\s*$', "owned link residue failure")
require_executable(cleanup, r'^\s*ip link del "\$BRIDGE" 2>/dev/null \\$', "owned bridge deletion")
require_executable(cleanup, r'^\s*\|\| record_cleanup_failure "could not delete owned bridge \$BRIDGE"\s*$', "owned bridge deletion failure handling")
require_executable(cleanup, r'^\s*&& record_cleanup_failure "owned bridge residue remains for \$BRIDGE"\s*$', "owned bridge residue failure")
require_executable(cleanup, r'^\s*iptables -D FORWARD "\$\{FORWARD_RULE_ARGS\[@\]\}" 2>/dev/null \\$', "owned FORWARD rule deletion")
require_executable(cleanup, r'^\s*\|\| record_cleanup_failure "could not delete the owned FORWARD rule"\s*$', "owned FORWARD rule deletion failure handling")
require_executable(cleanup, r'^\s*record_cleanup_failure "owned FORWARD rule residue remains"\s*$', "owned FORWARD rule residue failure")
require_executable(terminate, r'^\s*local post_kill_attempts=\$attempts\s*$', "bounded post-KILL wait")

suffix_assignment = re.search(r'^SUFFIX=\$\(openssl rand -hex 4\) \|\| fail "could not generate network resource suffix"$', code, re.MULTILINE)
suffix_validation = re.search(r'^\[\[ "\$SUFFIX" =~ \^\[0-9a-f\]\{8\}\$ \]\] \|\| fail "generated network resource suffix is invalid"$', code, re.MULTILINE)
suffix_readonly = re.search(r'^readonly SUFFIX$', code, re.MULTILINE)
if not suffix_assignment or not suffix_validation or not suffix_readonly:
    raise SystemExit("network resource suffix must be actively generated, validated, and frozen")
if not suffix_assignment.start() < suffix_validation.start() < suffix_readonly.start():
    raise SystemExit("network resource suffix generation order is invalid")

print("production WebSocket smoke gate passed")
PY
