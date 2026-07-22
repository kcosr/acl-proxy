#!/usr/bin/env python3
"""Pin inline data-listener declarations in the smoke-script sources."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED = (
    (
        "loopback",
        Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "scripts/loopback-smoke.sh",
        "explicit_http",
        'endpoint = { kind = "tcp", address = "127.0.0.1:$DATA_PORT" }',
    ),
    (
        "production topology",
        Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "scripts/production-topology-smoke.sh",
        "explicit_https",
        'endpoint = { kind = "tcp", address = "0.0.0.0:8443" }',
    ),
)

if len(sys.argv) > 3:
    raise SystemExit(f"usage: {Path(sys.argv[0]).name} [loopback-script production-script]")

for description, path, listener, endpoint in EXPECTED:
    text = path.read_text(encoding="utf-8")
    section = f"[listeners.{listener}]\n{endpoint}\n"
    if text.count(section) != 1:
        raise SystemExit(
            f"{description} smoke does not generate the exact typed {listener} endpoint"
        )
    if re.search(r"(?ms)^\[listeners\.[^]]+\]\n(?:(?!^\[).)*^bind\s*=", text):
        raise SystemExit(f"{description} smoke retains a removed data-listener bind field")

print("smoke configuration listener schema gate passed")
