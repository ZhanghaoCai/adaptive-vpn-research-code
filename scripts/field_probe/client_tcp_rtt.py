#!/usr/bin/env python3
"""Measure TCP handshake RTT from the local authorised client vantage."""

from __future__ import annotations

import argparse
import json
import math
import socket
import statistics
import time
from pathlib import Path

from scripts.field_probe.node_config import load_nodes


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * quantile) - 1))
    return ordered[index]


def measure(host: str, port: int, attempts: int, timeout: float) -> dict[str, object]:
    rtts: list[float] = []
    for _ in range(attempts):
        started = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                rtts.append((time.perf_counter() - started) * 1000.0)
        except OSError:
            continue
    succeeded = len(rtts)
    return {
        "host": host,
        "port": port,
        "attempts": attempts,
        "ok": succeeded,
        "loss_pct": round(100.0 * (attempts - succeeded) / attempts, 2),
        "rtt_median_ms": round(statistics.median(rtts), 2) if rtts else None,
        "rtt_p95_ms": round(percentile(rtts, 0.95), 2) if rtts else None,
        "rtt_min_ms": round(min(rtts), 2) if rtts else None,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", type=Path, help="local node inventory JSON")
    parser.add_argument("--aliases", nargs="*", help="node aliases to measure")
    parser.add_argument("--attempts", type=int, default=10)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.attempts < 1:
        parser.error("--attempts must be positive")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


def main() -> int:
    args = parse_args()
    nodes = load_nodes(args.nodes)
    aliases = args.aliases or list(nodes)
    unknown = sorted(set(aliases) - set(nodes))
    if unknown:
        raise SystemExit("unknown node aliases: " + ", ".join(unknown))

    rows = []
    for alias in aliases:
        node = nodes[alias]
        row = measure(node.host, args.port, args.attempts, args.timeout)
        row.update(alias=alias, location=node.location, region=node.region)
        rows.append(row)

    rendered = json.dumps(rows, ensure_ascii=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
