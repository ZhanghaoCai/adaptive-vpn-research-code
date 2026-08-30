#!/usr/bin/env python3
"""Compatibility CLI for the bounded adaptive-VPN namespace lab."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from adaptive_vpn.lab import WireGuardLab


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage the isolated WireGuard lab")
    parser.add_argument("--runtime-dir", type=Path, default=Path("/run/avpn-lab"))
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("setup", help="idempotently create the lab")
    subparsers.add_parser("status", help="capture namespace network state")
    subparsers.add_parser("cleanup", help="remove only bounded avpn-* resources")
    impair = subparsers.add_parser("impair", help="impair one lab path symmetrically")
    impair.add_argument("path", choices=("a", "b", "c"))
    impair.add_argument("--rtt-ms", type=float, required=True)
    impair.add_argument("--jitter-ms", type=float, default=0.0)
    impair.add_argument("--loss-pct", type=float, default=0.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    lab = WireGuardLab(runtime_dir=args.runtime_dir)
    if args.command == "setup":
        lab.setup()
    elif args.command == "status":
        print(json.dumps(lab.status(), indent=2, sort_keys=True))
    elif args.command == "impair":
        lab.impair(
            args.path,
            rtt_ms=args.rtt_ms,
            jitter_ms=args.jitter_ms,
            loss_pct=args.loss_pct,
        )
    elif args.command == "cleanup":
        lab.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
