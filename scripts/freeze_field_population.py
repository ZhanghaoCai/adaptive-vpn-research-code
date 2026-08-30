"""Freeze or verify the complete gated field-experiment population registry."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from adaptive_vpn.field_schedule import (
    FieldDesignError,
    generate_field_population,
    load_field_design,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DESIGN = ROOT / "experiments" / "field-design.yaml"


def _write_no_replace(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
        if path.read_bytes() != content:
            raise FieldDesignError(
                f"existing content-addressed population differs: {path}"
            )
        return
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--design", type=Path, default=DEFAULT_DESIGN)
    parser.add_argument("--write-dir", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args(argv)
    if args.write_dir is not None and args.check is not None:
        parser.error("--write-dir and --check are mutually exclusive")
    try:
        population = generate_field_population(load_field_design(args.design))
        content = population.canonical_bytes()
        output: Path | None = None
        if args.write_dir is not None:
            output = args.write_dir / f"field-population.{population.sha256}.json"
            _write_no_replace(output, content)
        if args.check is not None:
            observed = args.check.read_bytes()
            if observed != content:
                raise FieldDesignError(
                    "registered field population bytes do not match the current design"
                )
            output = args.check
    except (FieldDesignError, OSError) as exc:
        print(f"freeze_field_population: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "valid",
                "dataset_id": population.dataset_id,
                "expected_units": len(population.cells),
                "design_sha256": population.design_sha256,
                "population_sha256": population.sha256,
                "execution_order_frozen": False,
                "output": str(output) if output is not None else None,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
