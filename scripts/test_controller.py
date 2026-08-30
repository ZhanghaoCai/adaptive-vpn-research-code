#!/usr/bin/env python3
"""Deprecated wrapper for the registered real-packet experiment runner."""

from __future__ import annotations

import sys
from collections.abc import Sequence

from adaptive_vpn.cli import main as workflow_main


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    return workflow_main(["run", *arguments])


if __name__ == "__main__":
    raise SystemExit(main())
