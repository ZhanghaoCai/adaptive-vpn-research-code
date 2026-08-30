"""Compatibility entry point for the measured research workflow."""

from adaptive_vpn.cli import main


__all__ = ["main"]


if __name__ == "__main__":
    raise SystemExit(main())
