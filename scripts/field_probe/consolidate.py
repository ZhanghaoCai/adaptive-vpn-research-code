#!/usr/bin/env python3
"""Consolidate field-probe sweep TSVs and client TCP timing records."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from scripts.field_probe.node_config import load_nodes


def number(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def load_sweeps(probe_dir: Path, host_to_alias: dict[str, str]) -> dict[str, dict[str, dict[str, str]]]:
    sweeps: dict[str, dict[str, dict[str, str]]] = {}
    for path in sorted(probe_dir.glob("sweep-*.tsv")):
        alias = path.stem.split("-", 1)[1]
        rows: dict[str, dict[str, str]] = {}
        for row in csv.reader(path.read_text(encoding="utf-8").splitlines(), delimiter="\t"):
            if not row or len(row) < 5 or row[0] in {"source_node", "target_ip"}:
                continue
            host = row[0]
            if host not in host_to_alias or row[1] == "self":
                continue
            rows[host] = {
                "icmp_loss_pct": row[1],
                "icmp_avg_rtt_ms": row[2],
                "tcp_ok": row[3],
                "tcp_best_rtt_ms": row[4],
            }
        sweeps[alias] = rows
    return sweeps


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("probe_dir", type=Path)
    parser.add_argument("--nodes", type=Path, help="local node inventory JSON")
    parser.add_argument("--client-record", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    nodes = load_nodes(args.nodes)
    order = list(nodes)
    host_to_alias = {node.host: alias for alias, node in nodes.items()}
    probe_dir = args.probe_dir
    client_path = args.client_record or probe_dir / "client-tcp-rtt.json"
    client = json.loads(client_path.read_text(encoding="utf-8"))
    sweeps = load_sweeps(probe_dir, host_to_alias)

    matrix: dict[str, dict[str, float | None]] = {}
    for source_alias, rows in sweeps.items():
        matrix[source_alias] = {
            host_to_alias[host]: number(row["icmp_avg_rtt_ms"])
            for host, row in rows.items()
        }

    report = {
        "probe": probe_dir.name,
        "classification": "exploratory network probe; not a completed field evaluation",
        "method": "ICMP sweep and bounded TCP handshake timing",
        "nodes": [
            {
                "alias": alias,
                "host": node.host,
                "location": node.location,
                "region": node.region,
            }
            for alias, node in nodes.items()
        ],
        "rtt_matrix_icmp_avg_ms": matrix,
        "client_tcp_rtt_ms": {row["alias"]: row for row in client},
    }
    (probe_dir / "analysis-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    lines = [
        "| src / dst | " + " | ".join(order) + " |",
        "|---" + "|---" * len(order) + "|",
    ]
    for source in order:
        values = [source]
        for target in order:
            if source == target:
                values.append("self")
            else:
                value = matrix.get(source, {}).get(target)
                values.append(f"{value:g}" if value is not None else "-")
        lines.append("| " + " | ".join(values) + " |")
    markdown = "\n".join(lines) + "\n"
    (probe_dir / "rtt-matrix.md").write_text(markdown, encoding="utf-8")
    print(markdown, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
