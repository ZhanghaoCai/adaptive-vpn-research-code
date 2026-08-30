import json
from pathlib import Path

import pytest

from adaptive_vpn import cli
from adaptive_vpn.cli import build_parser, main

ROOT = Path(__file__).resolve().parents[2]


def test_cli_exposes_research_workflow_commands():
    parser = build_parser()
    help_text = parser.format_help()
    for command in ("doctor", "lab", "plan", "run", "validate", "analyse"):
        assert command in help_text


def test_plan_command_validates_and_reports_frozen_main_design(capsys):
    result = main(["plan", str(ROOT / "experiments" / "plans" / "main.yaml")])

    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert report["dataset_id"] == "main-20260804"
    assert report["expected_runs"] == 432
    assert report["blocks"] == 12
    assert report["config_sha256"]


def test_plan_command_rejects_unregistered_schedule_writer():
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "plan",
                str(ROOT / "experiments" / "plans" / "main.yaml"),
                "--write-schedule",
                "unregistered.schedule.json",
            ]
        )


def test_lab_parser_requires_a_bounded_action():
    parser = build_parser()
    args = parser.parse_args(["lab", "status"])
    assert args.command == "lab"
    assert args.lab_action == "status"


def test_run_command_dispatches_registered_plan_without_dataset_drift(
    tmp_path, monkeypatch, capsys
):
    calls = []

    def fake_execute(plan, **kwargs):
        calls.append((plan, kwargs))
        return {
            "status": "complete",
            "dataset_id": "smoke-20260803",
            "selected_runs": 1,
        }

    monkeypatch.setattr(cli, "execute_registered_plan", fake_execute)
    result = main(
        [
            "run",
            str(ROOT / "experiments" / "plans" / "smoke.yaml"),
            "--data-root",
            str(tmp_path),
            "--dataset",
            "smoke-20260803",
            "--resume",
            "--limit",
            "1",
        ]
    )

    assert result == 0
    assert calls[0][1]["dataset_id"] == "smoke-20260803"
    assert calls[0][1]["resume"] is True
    assert calls[0][1]["limit"] == 1
    assert json.loads(capsys.readouterr().out)["status"] == "complete"


def test_analyse_parser_accepts_frozen_hypothesis_plan():
    parser = build_parser()
    args = parser.parse_args(
        [
            "analyse",
            "--dataset",
            "main-20260803",
            "--plan",
            "experiments/hypotheses.yaml",
        ]
    )

    assert args.plan == Path("experiments/hypotheses.yaml")
