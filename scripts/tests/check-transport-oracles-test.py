#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile


sys.dont_write_bytecode = True
SOURCE_ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = SOURCE_ROOT / "scripts/check-transport-oracles.py"
EXPECTED_ORACLES = 10
EXPECTED_HELPERS = 16


BEHAVIOR_MUTATIONS = (
    ("assert_cancel_reset", "assert!(reset.is_reset());", "assert!(!reset.is_reset());", "unfinished drop reset"),
    ("assert_cancel_reset", "assert_eq!(reset.reason(), Some(h2::Reason::CANCEL));", "assert_eq!(reset.reason(), Some(h2::Reason::INTERNAL_ERROR));", "reset reason"),
    ("assert_complete_h2_response_watchdog", "data.is_empty() && !body.is_end_stream()", "data.is_empty()", "premature END_STREAM"),
    ("h2_zero_window_complete_cl0_watchdog_resets_and_releases_admission", 'assert_complete_h2_response_watchdog("/complete-cl0", 0, b"", b"", false).await;', 'assert_complete_h2_response_watchdog("/complete-cl0", 1, b"", b"", false).await;', "zero-length watchdog arm"),
    ("h2_exact_final_chunk_window_watchdog_resets_before_eof_poll", 'assert_complete_h2_response_watchdog("/complete-final-chunk", 2, b"xy", b"xy", false).await;', 'assert_complete_h2_response_watchdog("/complete-final-chunk", 2, b"xy", b"", false).await;', "exact-final-data EOF"),
    ("assert_complete_h2_response_watchdog", "sender.poll_ready(context)", "std::future::ready(Ok(())).await", "sole-slot release"),
    ("assert_complete_h2_response_watchdog", "assert!( pool.global_charge() > 0,", "assert!(pool.global_charge() >= 0,", "admission retention"),
    ("assert_complete_h2_response_watchdog", "assert_body_pool_released(", "skip_body_pool_release(", "admission release"),
    ("assert_complete_h2_response_watchdog", "assert_origin_closed(", "skip_origin_close(", "origin reuse"),
    ("h1_response_wire_limit_closes_before_committing_a_partial_response", "assert_no_partial_h1_response(&response);", "assert!(!response.is_empty());", "H1 prevalidation and partial commit"),
    ("h2_response_wire_limit_resets_only_the_failed_stream", "assert_h2_limit_sibling(sibling_status, &bytes);", "drop((sibling_status, bytes));", "H2 connection-wide failure"),
    ("assert_304_pipeline", 'assert_eq!(first_head.matches("\\r\\ncontent-length: 8\\r\\n").count(), 1);', 'assert_eq!(first_head.matches("\\r\\ncontent-length: 8\\r\\n").count(), 0);', "304 length stripping"),
    ("assert_304_pipeline", 'assert_eq!(first_head.matches("\\r\\ncontent-length:").count(), 1);', 'assert!(first_head.matches("\\r\\ncontent-length:").count() >= 1);', "304 length duplication"),
    ("assert_304_pipeline", 'assert!(response[first_end..].starts_with(b"HTTP/1.1 200"));', 'assert!(response.windows(12).any(|window| window == b"HTTP/1.1 200"));', "304 framing"),
    ("response_watchdog_config", 'body_idle_timeout = "200ms"', 'body_idle_timeout = "2s"', "watchdog timeout fixture"),
    ("response_watchdog_config", 'max_concurrent_streams = 1', 'max_concurrent_streams = 2', "concurrency fixture"),
    ("bounded_response_wire_config", "max_response_wire_bytes = 5", "max_response_wire_bytes = 6", "wire-limit fixture"),
)


def load_gate():
    spec = importlib.util.spec_from_file_location("transport_oracle_gate", GATE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {GATE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def synthetic_source(gate) -> str:
    sections: list[str] = []
    for name, required in (*gate.HELPER_REQUIREMENTS.items(), *gate.ORACLE_REQUIREMENTS.items()):
        fragments = "\n".join(item.fragment for item in required)
        attribute = "#[tokio::test]\n" if name in gate.ORACLE_IDS else ""
        sections.append(f"{attribute}async fn {name}() {{\n{fragments}\n}}\n")
    return "\n".join(sections)


def run_gate(source: Path, expect_success: bool) -> None:
    result = subprocess.run(
        [sys.executable, str(GATE_PATH), "--source", str(source)],
        check=False,
        capture_output=True,
        text=True,
    )
    if (result.returncode == 0) != expect_success:
        outcome = "pass" if expect_success else "rejection"
        raise AssertionError(
            f"expected {outcome}, got exit {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def replace_in_function(gate, source: str, owner: str, old: str, new: str) -> str:
    bodies = gate.function_bodies(source)
    observed = bodies.get(owner, [])
    if len(observed) != 1:
        raise AssertionError(f"test fixture function {owner!r} is not unique")
    body = observed[0]
    if body.count(old) != 1:
        raise AssertionError(f"fixture fragment {old!r} in {owner} is not unique")
    changed = body.replace(old, new, 1)
    start = source.index(body)
    return source[:start] + changed + source[start + len(body):]


def main() -> int:
    gate = load_gate()
    if len(gate.ORACLE_IDS) != EXPECTED_ORACLES:
        raise AssertionError(f"expected {EXPECTED_ORACLES} oracle IDs")
    if tuple(gate.ORACLE_REQUIREMENTS) != gate.ORACLE_IDS:
        raise AssertionError("oracle requirements do not preserve the exact ID inventory")
    if len(gate.HELPER_REQUIREMENTS) != EXPECTED_HELPERS:
        raise AssertionError(f"expected {EXPECTED_HELPERS} helper definitions")

    baseline = synthetic_source(gate)
    with tempfile.TemporaryDirectory(
        prefix=".transport-oracle-gate.", dir=SOURCE_ROOT
    ) as directory:
        source_path = Path(directory) / "runner_response_parity_tests.rs"
        source_path.write_text(baseline, encoding="utf-8")
        run_gate(source_path, True)

        for oracle in gate.ORACLE_IDS:
            mutated = baseline.replace(f"async fn {oracle}()", f"async fn removed_{oracle}()", 1)
            source_path.write_text(mutated, encoding="utf-8")
            run_gate(source_path, False)

        for helper in gate.HELPER_REQUIREMENTS:
            mutated = baseline.replace(f"async fn {helper}()", f"async fn removed_{helper}()", 1)
            source_path.write_text(mutated, encoding="utf-8")
            run_gate(source_path, False)

        all_requirements = (*gate.HELPER_REQUIREMENTS.items(), *gate.ORACLE_REQUIREMENTS.items())
        for owner, expected in all_requirements:
            for requirement in expected:
                mutated = replace_in_function(
                    gate, baseline, owner, requirement.fragment, "/* removed semantic call */"
                )
                source_path.write_text(mutated, encoding="utf-8")
                run_gate(source_path, False)

        assertion_mutations = 0
        for owner, expected in all_requirements:
            for requirement in expected:
                fragment = requirement.fragment
                if "assert" not in fragment:
                    continue
                relaxed = fragment.replace("assert_eq!", "relaxed_eq!", 1).replace(
                    "assert!", "relaxed!", 1
                )
                if relaxed == fragment:
                    continue
                mutated = replace_in_function(gate, baseline, owner, fragment, relaxed)
                source_path.write_text(mutated, encoding="utf-8")
                run_gate(source_path, False)
                assertion_mutations += 1
        if assertion_mutations == 0:
            raise AssertionError("self-test did not exercise assertion relaxation")

        for owner, old, new, _label in BEHAVIOR_MUTATIONS:
            mutated = replace_in_function(gate, baseline, owner, old, new)
            source_path.write_text(mutated, encoding="utf-8")
            run_gate(source_path, False)

        additive_mutations = 0
        for owner, forbidden in gate.FORBIDDEN_REQUIREMENTS.items():
            for requirement in forbidden:
                anchor = gate.HELPER_REQUIREMENTS[owner][0].fragment
                mutated = replace_in_function(
                    gate,
                    baseline,
                    owner,
                    anchor,
                    f"{anchor}\n{requirement.fragment}1).unwrap();",
                )
                source_path.write_text(mutated, encoding="utf-8")
                run_gate(source_path, False)
                additive_mutations += 1
        if additive_mutations == 0:
            raise AssertionError("self-test did not exercise additive behavior mutation")

    print(
        "transport response oracle gate self-test passed: "
        f"{EXPECTED_ORACLES} ID removals, "
        f"{EXPECTED_HELPERS} helper removals, "
        f"{sum(len(items) for _, items in all_requirements)} semantic removals, "
        f"{assertion_mutations} assertion relaxations, "
        f"{len(BEHAVIOR_MUTATIONS)} named behavior mutations, "
        f"{additive_mutations} additive behavior mutations"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
