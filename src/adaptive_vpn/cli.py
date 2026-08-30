"""Command-line entry point for the adaptive VPN research workflow."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from adaptive_vpn.config import load_experiment_plan
from adaptive_vpn.lab import WireGuardLab
from adaptive_vpn.schedule import experiment_config_sha256
from adaptive_vpn.workflow import (
    doctor_report,
    execute_registered_plan,
    validate_raw_dataset,
)

WORKFLOW_COMMANDS = ("doctor", "lab", "plan", "run", "validate", "analyse")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adaptive-vpn",
        description="Reproducible adaptive VPN experiment workflow",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("doctor", help="inspect live experiment prerequisites")

    lab = subparsers.add_parser("lab", help="manage bounded avpn-* resources")
    lab_subparsers = lab.add_subparsers(dest="lab_action", required=True)
    lab_subparsers.add_parser("setup")
    lab_subparsers.add_parser("status")
    lab_subparsers.add_parser("cleanup")
    impair = lab_subparsers.add_parser("impair")
    impair.add_argument("path", choices=("path-a", "path-b", "path-c"))
    impair.add_argument("--delay-ms", type=float, required=True)
    impair.add_argument("--jitter-ms", type=float, default=0)
    impair.add_argument("--loss-pct", type=float, default=0)
    impair.add_argument("--loss-correlation-pct", type=float, default=0)
    impair.add_argument("--rate-mbit", type=float)

    plan = subparsers.add_parser("plan", help="validate and inspect a frozen plan")
    plan.add_argument("plan", type=Path)

    run = subparsers.add_parser("run", help="execute registered real-packet runs")
    run.add_argument("plan", type=Path)
    run.add_argument("--data-root", type=Path, default=Path("data"))
    run.add_argument("--dataset")
    run.add_argument("--resume", action="store_true")
    run.add_argument("--limit", type=int)

    validate = subparsers.add_parser("validate", help="validate raw evidence bundles")
    validate.add_argument("raw_dir", type=Path)
    validate.add_argument("--dataset", required=True)
    validate.add_argument("--plan", type=Path)
    validate.add_argument("--expected-runs", type=int)
    validate.add_argument("--require-complete", action="store_true")

    analyse = subparsers.add_parser("analyse", help="analyse validated run evidence")
    analyse.add_argument("--raw-dir", type=Path, default=Path("data/raw"))
    analyse.add_argument("--processed-root", type=Path, default=Path("data/processed"))
    analyse.add_argument("--dataset", required=True)
    analyse.add_argument(
        "--plan", type=Path, default=Path("experiments/hypotheses.yaml")
    )
    analyse.add_argument("--expected-runs", type=int, default=432)
    analyse.add_argument("--bootstrap-samples", type=int, default=10_000)
    return parser


def _print_json(value) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _print_progress(value) -> None:
    print(json.dumps(value, sort_keys=True), file=sys.stderr, flush=True)


def _run_lab(args: argparse.Namespace) -> int:
    lab = WireGuardLab()
    if args.lab_action == "setup":
        lab.setup()
    elif args.lab_action == "status":
        _print_json(lab.status())
    elif args.lab_action == "cleanup":
        lab.cleanup()
    elif args.lab_action == "impair":
        lab.impair(
            args.path,
            delay_ms=args.delay_ms,
            jitter_ms=args.jitter_ms,
            loss_pct=args.loss_pct,
            loss_correlation_pct=args.loss_correlation_pct,
            rate_mbit=args.rate_mbit,
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            _print_json(doctor_report())
            return 0
        if args.command == "lab":
            return _run_lab(args)
        if args.command == "plan":
            plan = load_experiment_plan(args.plan)
            _print_json(
                {
                    "schema_version": plan.schema_version,
                    "dataset_id": plan.dataset_id,
                    "source_path": str(plan.source_path),
                    "blocks": plan.blocks,
                    "scenarios": [item.scenario_id for item in plan.scenarios],
                    "traffic_profiles": [
                        item.profile_id for item in plan.traffic_profiles
                    ],
                    "strategies": plan.strategies,
                    "expected_runs": plan.expected_runs,
                    "schedule_seed": plan.schedule_seed,
                    "config_sha256": experiment_config_sha256(plan),
                }
            )
            return 0
        if args.command == "validate":
            _print_json(
                validate_raw_dataset(
                    args.raw_dir,
                    dataset_id=args.dataset,
                    expected_runs=args.expected_runs,
                    require_complete=args.require_complete,
                    plan_path=args.plan,
                )
            )
            return 0
        if args.command == "run":
            report = execute_registered_plan(
                args.plan,
                data_root=args.data_root,
                dataset_id=args.dataset,
                resume=args.resume,
                limit=args.limit,
                progress=_print_progress,
            )
            _print_json(report)
            return 0 if report["status"] == "complete" else 2
        if args.command == "analyse":
            from analysis.statistical_analysis import analyse_dataset

            output = analyse_dataset(
                raw_dir=args.raw_dir,
                processed_root=args.processed_root,
                dataset_id=args.dataset,
                expected_run_count=args.expected_runs,
                expected_strategies=("static", "threshold", "adaptive"),
                bootstrap_samples=args.bootstrap_samples,
                seed=20260803,
                analysis_plan_path=args.plan,
            )
            _print_json(
                {
                    "status": "complete",
                    "dataset_id": args.dataset,
                    "output_dir": str(output.resolve()),
                }
            )
            return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"adaptive-vpn: {exc}", file=sys.stderr)
        return 2
    parser.error(f"unsupported command {args.command}")
    return 2
