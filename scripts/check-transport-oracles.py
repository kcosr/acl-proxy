#!/usr/bin/env python3

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import sys


ORACLE_SOURCE = Path("src/activation/runner_response_parity_tests.rs")
ORACLE_IDS = (
    "h2_zero_window_complete_cl1_watchdog_resets_and_preserves_sibling_stream",
    "h2_one_byte_window_complete_cl2_watchdog_resets_without_window_update",
    "h2_zero_window_complete_cl0_watchdog_resets_and_releases_admission",
    "h2_exact_final_chunk_window_watchdog_resets_before_eof_poll",
    "h1_unread_response_body_watchdog_releases_admission_and_closes_origin",
    "h2_zero_window_watchdog_releases_admission_and_preserves_sibling_stream",
    "h2_zero_window_watchdog_sends_stream_cancel",
    "h1_response_wire_limit_closes_before_committing_a_partial_response",
    "h2_response_wire_limit_resets_only_the_failed_stream",
    "h1_304_preserves_representation_content_length_and_pipeline",
)


@dataclass(frozen=True)
class Requirement:
    label: str
    fragment: str


def requirements(*items: tuple[str, str]) -> tuple[Requirement, ...]:
    return tuple(Requirement(label, fragment) for label, fragment in items)


HELPER_REQUIREMENTS = {
    "assert_empty_chunked_request_body": requirements(
        ("two-second empty-body bound", "tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut body))"),
        ("exact empty chunked request body", 'assert_eq!(&body, b"0\\r\\n\\r\\n");'),
    ),
    "assert_body_pool_released": requirements(
        ("product body-pool authority", "let pool = product.wire_body_pool();"),
        ("two-second charge-release bound", "tokio::time::timeout(Duration::from_secs(2), async"),
        ("exact zero pool charge", "while pool.global_charge() != 0"),
    ),
    "assert_exact_request_path": requirements(
        ("request-target extraction", "line.split_ascii_whitespace().nth(1)"),
        ("exact path assertion", 'assert_eq!(actual, Some(path), "origin did not receive exact path");'),
    ),
    "assert_origin_closed": requirements(
        ("origin closure assertion", "assert!(matches!(result, Ok(0) | Err(_)), \"{message}\");"),
    ),
    "accept_origin": requirements(
        ("two-second accept bound", "tokio::time::timeout(Duration::from_secs(2), listener.accept())"),
    ),
    "assert_downstream_terminated": requirements(
        ("two-second downstream bound", "tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut tail))"),
        ("timeout is a failure", 'Err(_) => panic!("the response watchdog did not terminate the HTTP/1 downstream")'),
    ),
    "assert_cancel_reset": requirements(
        ("stream reset assertion", "assert!(reset.is_reset());"),
        ("exact cancel reason", "assert_eq!(reset.reason(), Some(h2::Reason::CANCEL));"),
    ),
    "assert_no_partial_h1_response": requirements(
        ("zero partial response bytes", "assert!( response.is_empty(),"),
    ),
    "assert_h2_limit_sibling": requirements(
        ("200 sibling", "assert_eq!(status, StatusCode::OK);"),
        ("exact sibling body", 'assert_eq!(body, b"ok");'),
    ),
    "assert_304_pipeline": requirements(
        ("304 first response", 'assert!(first_head.starts_with("http/1.1 304"));'),
        ("one content-length", 'assert_eq!(first_head.matches("\\r\\ncontent-length:").count(), 1);'),
        ("representation length eight", 'assert_eq!(first_head.matches("\\r\\ncontent-length: 8\\r\\n").count(), 1);'),
        ("pipeline aligned at second head", 'assert!(response[first_end..].starts_with(b"HTTP/1.1 200"));'),
        ("exact following body", 'assert!(response.ends_with(b"\\r\\n\\r\\nok"));'),
    ),
    "response_watchdog_config": requirements(
        ("200ms response watchdog", 'body_idle_timeout = "200ms"'),
        ("64MiB response wire fixture", "max_response_wire_bytes = 67108864"),
        ("one-stream H2 fixture", 'max_concurrent_streams = 1'),
    ),
    "response_h2_client": requirements(
        ("caller-selected initial window", "builder.initial_window_size(initial_window_size);"),
        ("single returned connection driver", "(sender, tokio::spawn(connection))"),
    ),
    "response_h2_send": requirements(
        ("exact requested path", '.uri(format!("http://{origin}{path}"))'),
        ("empty end-stream request", ".body(())"),
        ("request body is complete", "true,"),
    ),
    "assert_complete_h2_response_watchdog": requirements(
        ("bounded origin accept", 'accept_origin(&origin_listener, "the watchdog origin was not contacted").await'),
        ("exact origin path assertion", "assert_exact_request_path(&request, path);"),
        ("chunked request assertion", 'assert!(request_text.contains("transfer-encoding: chunked\\r\\n"));'),
        ("empty request helper wiring", "assert_empty_chunked_request_body(&mut stream).await;"),
        ("bounded origin close", "tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))"),
        ("origin-close helper wiring", "assert_origin_closed("),
        ("same sender issues selected request", "response_h2_send(&mut sender, origin, path).await"),
        ("200 response head", "assert_eq!(response.status(), StatusCode::OK);"),
        ("stalled response retains charge", "assert!( pool.global_charge() > 0,"),
        ("exact window-sized data", "assert_eq!(data.as_ref(), expected_data);"),
        ("no premature end stream", "data.is_empty() && !body.is_end_stream()"),
        ("cancel-reset helper wiring", "assert_cancel_reset(&reset);"),
        ("bounded close notification", "tokio::time::timeout(Duration::from_secs(2), origin_closed_rx)"),
        ("sole stream slot release", "sender.poll_ready(context)"),
        ("same-connection sibling", 'response_h2_send(&mut sender, origin, "/sibling").await'),
        ("204 sibling", "assert_eq!(sibling.status(), StatusCode::NO_CONTENT);"),
        ("pool-release helper wiring", "assert_body_pool_released("),
    ),
    "bounded_response_wire_config": requirements(
        ("five-byte response wire limit", "max_response_wire_bytes = 5"),
        ("two-byte chunks", "chunk_bytes = 2"),
    ),
    "serve_bounded_response_origin": requirements(
        ("six-byte oversized response", 'Content-Length: 6\\r\\nConnection: close\\r\\n\\r\\nabcdef'),
        ("exact sibling body", 'Content-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok'),
    ),
}


ORACLE_REQUIREMENTS = {
    ORACLE_IDS[0]: requirements(
        ("CL1 zero-window fixture", 'assert_complete_h2_response_watchdog("/complete-cl1", 0, b"x", b"", true).await;'),
    ),
    ORACLE_IDS[1]: requirements(
        ("CL2 one-byte-window fixture", 'assert_complete_h2_response_watchdog("/complete-cl2-partial", 1, b"xy", b"x", false).await;'),
    ),
    ORACLE_IDS[2]: requirements(
        ("CL0 zero-window fixture", 'assert_complete_h2_response_watchdog("/complete-cl0", 0, b"", b"", false).await;'),
    ),
    ORACLE_IDS[3]: requirements(
        ("exact-final-chunk fixture", 'assert_complete_h2_response_watchdog("/complete-final-chunk", 2, b"xy", b"xy", false).await;'),
    ),
    ORACLE_IDS[4]: requirements(
        ("64MiB declared body", "const RESPONSE_BYTES: usize = 64 * 1024 * 1024;"),
        ("bounded origin accept", 'accept_origin(&origin_listener, "the unread origin was not contacted").await'),
        ("exact unread path", 'assert_exact_request_path(&request, "/unread");'),
        ("200 response head", 'assert!(response.starts_with(b"HTTP/1.1 200"));'),
        ("unread response retains charge", "assert!( pool.global_charge() > 0,"),
        ("bounded origin close", "tokio::time::timeout(Duration::from_secs(2), origin_closed_rx)"),
        ("bounded prefix", "assert!( sent < RESPONSE_BYTES,"),
        ("bounded downstream termination", "assert_downstream_terminated(&mut client).await;"),
        ("pool-release helper wiring", "assert_body_pool_released("),
    ),
    ORACLE_IDS[5]: requirements(
        ("bounded origin accept", 'accept_origin(&origin_listener, "the stalled origin was not contacted").await'),
        ("exact stalled path", 'assert_exact_request_path(&request, "/stalled");'),
        ("chunked request assertion", 'assert!(request_text.contains("transfer-encoding: chunked\\r\\n"));'),
        ("empty request helper wiring", "assert_empty_chunked_request_body(&mut stalled).await;"),
        ("bounded origin close", "tokio::time::timeout(Duration::from_secs(2), stalled.read(&mut byte))"),
        ("zero initial window", "response_h2_client(proxy, 0).await"),
        ("200 stalled head", "assert_eq!(stalled.status(), StatusCode::OK);"),
        ("stalled response retains charge", "assert!( pool.global_charge() > 0,"),
        ("sole stream slot release", "sender.poll_ready(context)"),
        ("same-connection sibling", 'response_h2_send(&mut sender, origin, "/sibling").await'),
        ("204 sibling", "assert_eq!(sibling.status(), StatusCode::NO_CONTENT);"),
        ("bounded close notification", "tokio::time::timeout(Duration::from_secs(2), origin_closed_rx)"),
        ("pool-release helper wiring", "assert_body_pool_released("),
    ),
    ORACLE_IDS[6]: requirements(
        ("bounded origin accept", 'accept_origin(&origin_listener, "the reset origin was not contacted").await'),
        ("exact reset path", 'assert_exact_request_path(&request, "/reset");'),
        ("chunked request assertion", 'assert!(request_text.contains("transfer-encoding: chunked\\r\\n"));'),
        ("empty request helper wiring", "assert_empty_chunked_request_body(&mut stream).await;"),
        ("zero initial window", "response_h2_client(proxy, 0).await"),
        ("200 response head", "assert_eq!(response.status(), StatusCode::OK);"),
        ("cancel-reset helper wiring", "assert_cancel_reset(&reset);"),
    ),
    ORACLE_IDS[7]: requirements(
        ("over-limit route", 'http://{origin}/oversized'),
        ("zero partial bytes", "assert_no_partial_h1_response(&response);"),
    ),
    ORACLE_IDS[8]: requirements(
        ("over-limit request", 'response_h2_send(&mut sender, origin, "/oversized").await'),
        ("no successful response head", "assert!( oversized.is_err(),"),
        ("failed stream releases readiness", "sender.poll_ready(context)"),
        ("same-connection sibling", 'response_h2_send(&mut sender, origin, "/sibling").await'),
        ("200 and exact sibling body", "assert_h2_limit_sibling(sibling_status, &bytes);"),
    ),
    ORACLE_IDS[9]: requirements(
        ("two pipelined requests", 'GET http://{origin}/first HTTP/1.1'),
        ("following request", 'GET http://{origin}/second HTTP/1.1'),
        ("304 pipeline helper wiring", "assert_304_pipeline(&response);"),
    ),
}


FORBIDDEN_REQUIREMENTS = {
    "assert_complete_h2_response_watchdog": requirements(
        (
            "explicit H2 receive-window capacity release",
            "body.flow_control().release_capacity(",
        ),
    ),
}


FUNCTION_START = re.compile(r"^(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^\n{]*>)?\s*\(", re.MULTILINE)


def normalize(source: str) -> str:
    return " ".join(source.split())


def read_source(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read UTF-8 oracle source {path}: {error}") from error


def function_bodies(source: str) -> dict[str, list[str]]:
    matches = list(FUNCTION_START.finditer(source))
    bodies: dict[str, list[str]] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        bodies.setdefault(match.group(1), []).append(source[match.start():end])
    return bodies


def check_requirements(
    bodies: dict[str, list[str]],
    owner: str,
    expected: tuple[Requirement, ...],
) -> None:
    observed = bodies.get(owner, [])
    if len(observed) != 1:
        raise ValueError(f"required function {owner!r} occurs {len(observed)} times, expected once")
    body = normalize(observed[0])
    for requirement in expected:
        fragment = normalize(requirement.fragment)
        count = body.count(fragment)
        if count != 1:
            raise ValueError(
                f"{owner}: semantic marker {requirement.label!r} occurs {count} times, expected once"
            )


def check_forbidden(
    bodies: dict[str, list[str]],
    owner: str,
    forbidden: tuple[Requirement, ...],
) -> None:
    observed = bodies.get(owner, [])
    if len(observed) != 1:
        raise ValueError(f"required function {owner!r} occurs {len(observed)} times, expected once")
    body = normalize(observed[0])
    for requirement in forbidden:
        fragment = normalize(requirement.fragment)
        if fragment in body:
            raise ValueError(
                f"{owner}: forbidden semantic marker {requirement.label!r} is present"
            )


def check_source(path: Path) -> None:
    source = read_source(path)
    bodies = function_bodies(source)
    for helper, expected in HELPER_REQUIREMENTS.items():
        check_requirements(bodies, helper, expected)
    for oracle in ORACLE_IDS:
        test_declaration = re.compile(
            rf"^#\[tokio::test\]\s*async\s+fn\s+{re.escape(oracle)}\s*\(",
            re.MULTILINE,
        )
        count = len(test_declaration.findall(source))
        if count != 1:
            raise ValueError(
                f"required Tokio test {oracle!r} occurs {count} times, expected once"
            )
        check_requirements(bodies, oracle, ORACLE_REQUIREMENTS[oracle])
    for owner, forbidden in FORBIDDEN_REQUIREMENTS.items():
        check_forbidden(bodies, owner, forbidden)


def main() -> int:
    script_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Enforce the frozen transport response-oracle inventory and semantics"
    )
    parser.add_argument("--source", type=Path, default=script_root / ORACLE_SOURCE)
    args = parser.parse_args()
    try:
        check_source(args.source)
    except ValueError as error:
        print(f"transport response oracle gate failed: {error}", file=sys.stderr)
        return 1
    print(f"transport response oracle gate passed: {len(ORACLE_IDS)} exact live tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
