import csv
import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

import adaptive_vpn.collector as collector_module
import analysis.statistical_analysis as statistics_module
from adaptive_vpn.collector import (
    EVIDENCE_SCHEMA_VERSION,
    LEGACY_EVIDENCE_SCHEMA_VERSION,
    AttemptEvidenceBundle,
    BundleValidation,
    EvidenceBundle,
)
from adaptive_vpn.config import load_experiment_plan
from adaptive_vpn.runner import AttemptDefinition, RunOutcome
from adaptive_vpn.schedule import registered_schedule_path
from adaptive_vpn.workflow import execute_registered_plan
from analysis.statistical_analysis import (
    SCHEMA_VERSION,
    AnalysisInputError,
    PairedDifference,
    aggregate_block_differences,
    align_paired_differences,
    analyse_dataset,
    bootstrap_mean_ci,
    build_quality_control,
    holm_adjusted,
    load_analysis_plan,
    load_validated_runs,
    paired_standardised_effect,
    read_run_table,
    summarise_packet_rows,
    validate_confirmatory_matrix,
)

FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "measured-schema-example"
HYPOTHESES_PATH = Path(__file__).parents[2] / "experiments" / "hypotheses.yaml"
STRATEGIES = ("static", "threshold", "adaptive")


def _content_addressed_schedule_fixture(tmp_path: Path) -> tuple[Path, Path, str]:
    from tests.unit.test_schedule import _registered_plan, _schedule_path

    plan = _registered_plan(tmp_path)
    plan_path = plan.registration_path
    schedule_path = _schedule_path(plan)
    assert plan_path is not None
    digest = hashlib.sha256(schedule_path.read_bytes()).hexdigest()
    content_addressed = schedule_path.with_name(
        f"{plan_path.stem}.{digest}.schedule.json"
    )
    schedule_path.rename(content_addressed)
    registration = yaml.safe_load(plan_path.read_text(encoding="utf-8"))
    registration["schedule_path"] = content_addressed.name
    plan_path.write_text(
        yaml.safe_dump(registration, sort_keys=False), encoding="utf-8"
    )
    return plan_path, content_addressed, digest


def test_analysis_discovers_and_loads_checked_in_v2_main_schedule():
    path = statistics_module._discover_registered_schedule("main-20260804")

    assert path is not None
    assert path.name == (
        "main.7f9bd96f73c21d85cde860be9cfe436a351d7ae0de74163262298a293bc46570"
        ".schedule.json"
    )
    loaded = statistics_module._load_registered_schedule(path, "main-20260804")
    document = loaded.document
    registry = loaded.registry

    assert document["schema_version"] == "2.0.0"
    assert len(registry) == 432
    assert all(uuid.UUID(run_id).version == 5 for run_id in registry)

    cell = document["cells"][0]
    statistics_module._validate_registered_manifest(
        {
            "run_id": cell["cell_id"],
            "strategy": cell["strategy"],
            "scenario": cell["scenario_id"],
            "traffic_profile": cell["traffic_profile_id"],
            "block": cell["block"],
            "schedule_seed": document["schedule_seed"],
            "ordinal": cell["ordinal"],
            "config_sha256": document["config_sha256"],
        },
        document,
        registry,
    )


@pytest.mark.parametrize("failure", ("renamed", "bytes", "registration"))
def test_analysis_authenticates_schema2_content_addressed_registration(
    tmp_path: Path, failure: str
):
    plan_path, schedule_path, digest = _content_addressed_schedule_fixture(tmp_path)
    if failure == "renamed":
        renamed = schedule_path.with_name(f"smoke.{'f' * 64}.schedule.json")
        schedule_path.rename(renamed)
        schedule_path = renamed
        registration = yaml.safe_load(plan_path.read_text(encoding="utf-8"))
        registration["schedule_path"] = renamed.name
        plan_path.write_text(
            yaml.safe_dump(registration, sort_keys=False), encoding="utf-8"
        )
    elif failure == "bytes":
        schedule_path.write_bytes(schedule_path.read_bytes() + b" ")
    else:
        registration = yaml.safe_load(plan_path.read_text(encoding="utf-8"))
        registration["schedule_sha256"] = "f" * 64
        plan_path.write_text(
            yaml.safe_dump(registration, sort_keys=False), encoding="utf-8"
        )

    assert digest != "f" * 64
    with pytest.raises(AnalysisInputError, match="content-addressed|digest|registration"):
        statistics_module._load_registered_schedule(schedule_path, "test-plan")


@pytest.mark.parametrize("oversized", ("registration", "included-source"))
def test_analysis_bounds_schema2_registration_and_included_source(
    tmp_path: Path, oversized: str
):
    plan_path, schedule_path, _digest = _content_addressed_schedule_fixture(tmp_path)
    target = (
        plan_path
        if oversized == "registration"
        else plan_path.parent.parent / "config" / "system.yaml"
    )
    target.write_bytes(b"x" * (1_048_576 + 1))

    with pytest.raises(AnalysisInputError, match="exceeds 1048576 bytes"):
        statistics_module._load_registered_schedule(schedule_path, "test-plan")


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX FIFO semantics")
def test_analysis_nonblocks_strict_recheck_post_stat_fifo_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _plan_path, schedule_path, _digest = _content_addressed_schedule_fixture(tmp_path)
    original_open = os.open
    schedule_open_count = 0

    def race_before_second_schedule_open(path, flags, *args, **kwargs):
        nonlocal schedule_open_count
        if (
            Path(path).name == schedule_path.name
            and not flags & getattr(os, "O_DIRECTORY", 0)
        ):
            schedule_open_count += 1
            if schedule_open_count == 2:
                schedule_path.unlink()
                os.mkfifo(schedule_path)
                assert flags & getattr(os, "O_NONBLOCK", 0)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(statistics_module.os, "open", race_before_second_schedule_open)

    with pytest.raises(AnalysisInputError, match="regular file"):
        statistics_module._load_registered_schedule(schedule_path, "test-plan")
    assert schedule_open_count == 2


def test_schedule_discovery_bounds_file_before_json_decode(tmp_path: Path):
    oversized = tmp_path / f"main.{'a' * 64}.schedule.json"
    oversized.write_bytes(b"{" + b"x" * (8 * 1024 * 1024))

    with pytest.raises(AnalysisInputError, match="exceeds 8388608 bytes"):
        statistics_module._read_bounded_schedule_bytes(oversized)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX FIFO semantics")
def test_schedule_reader_rejects_fifo_without_blocking(tmp_path: Path):
    path = tmp_path / f"main.{'a' * 64}.schedule.json"
    os.mkfifo(path)

    started = time.monotonic()
    with pytest.raises(AnalysisInputError, match="regular file"):
        statistics_module._read_bounded_schedule_bytes(path)

    assert time.monotonic() - started < 1.0


def test_schedule_reader_rejects_symbolic_link(tmp_path: Path):
    target = tmp_path / "schedule.json"
    target.write_text('{}\n', encoding="utf-8")
    link = tmp_path / f"main.{'a' * 64}.schedule.json"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symbolic links are unavailable")

    with pytest.raises(AnalysisInputError, match="symlink"):
        statistics_module._read_bounded_schedule_bytes(link)


def test_schedule_discovery_requires_an_explicit_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(statistics_module, "DEFAULT_SCHEDULES_DIR", tmp_path)

    with pytest.raises(AnalysisInputError, match="registration.*not found"):
        statistics_module._discover_registered_schedule("main-20260804")


def test_analyse_dataset_requires_registration_before_loading_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    registrations = tmp_path / "plans"
    registrations.mkdir()
    monkeypatch.setattr(
        statistics_module,
        "DEFAULT_SCHEDULES_DIR",
        registrations,
    )

    with pytest.raises(AnalysisInputError, match="registration.*not found"):
        analyse_dataset(
            raw_dir=tmp_path / "missing-raw",
            processed_root=tmp_path / "processed",
            dataset_id="main-20260804",
            analysis_plan_path=HYPOTHESES_PATH,
        )


def test_analyse_dataset_rejects_explicit_schedule_registration_bypass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    plan_path, _registered_path, _digest = _content_addressed_schedule_fixture(
        tmp_path
    )
    decoy = tmp_path / "decoy.schedule.json"
    decoy.write_text('{}\n', encoding="utf-8")
    monkeypatch.setattr(
        statistics_module,
        "DEFAULT_SCHEDULES_DIR",
        plan_path.parent,
    )

    with pytest.raises(AnalysisInputError, match="does not match.*registration"):
        analyse_dataset(
            raw_dir=tmp_path / "missing-raw",
            processed_root=tmp_path / "processed",
            dataset_id="test-plan",
            analysis_plan_path=HYPOTHESES_PATH,
            schedule_path=decoy,
        )


@pytest.mark.parametrize("failure", ("missing", "renamed", "dataset-header"))
def test_schedule_discovery_uses_registration_not_untrusted_schedule_header(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
):
    plan_path, schedule_path, _digest = _content_addressed_schedule_fixture(tmp_path)
    registered_path = schedule_path
    if failure == "missing":
        schedule_path.unlink()
    elif failure == "renamed":
        schedule_path.rename(schedule_path.with_suffix(".renamed"))
    else:
        document = json.loads(schedule_path.read_text(encoding="utf-8"))
        document["dataset_id"] = "untrusted-other-dataset"
        schedule_path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    monkeypatch.setattr(
        statistics_module,
        "DEFAULT_SCHEDULES_DIR",
        plan_path.parent,
    )

    discovered = statistics_module._discover_registered_schedule("test-plan")

    assert discovered == registered_path
    with pytest.raises(AnalysisInputError, match="schedule|digest|cannot read"):
        statistics_module._load_registered_schedule(discovered, "test-plan")


def test_schedule_discovery_rejects_ambiguous_registrations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    plan_path, _schedule_path, _digest = _content_addressed_schedule_fixture(tmp_path)
    duplicate = plan_path.with_name("duplicate.yaml")
    duplicate.write_bytes(plan_path.read_bytes())
    monkeypatch.setattr(
        statistics_module,
        "DEFAULT_SCHEDULES_DIR",
        plan_path.parent,
    )

    with pytest.raises(AnalysisInputError, match="multiple.*registrations"):
        statistics_module._discover_registered_schedule("test-plan")


def _run_id(number):
    return str(uuid.UUID(int=number, version=4))


def _write_bundle(
    base_dir,
    *,
    number,
    strategy="adaptive",
    block=1,
    status="complete",
    rtts=(20.0, 21.0, 22.0, 23.0),
    timeouts=0,
    marker=None,
    run_id=None,
    event_marker=None,
    auxiliary_artifact=None,
):
    manifest = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "run_id": run_id or _run_id(number),
        "dataset_id": "confirmatory-test",
        "strategy": strategy,
        "scenario": "latency_step",
        "traffic_profile": "video_low",
        "block": block,
        "schedule_seed": 20260803,
        "ordinal": number,
        "config_sha256": "a" * 64,
        "experimental_unit": "run",
        "provenance": {"git_commit": "a" * 40},
    }
    if marker:
        marker = dict(marker)
        if "provenance" in marker:
            manifest["provenance"].update(marker.pop("provenance"))
        manifest.update(marker)
    bundle = EvidenceBundle.create(base_dir, manifest)
    for sequence, rtt_ms in enumerate(rtts, 1):
        sent_ns = sequence * 1_000_000_000
        bundle.write_packet(
            {
                "sequence": sequence,
                "path_id": "path-a",
                "sent_ns": sent_ns,
                "received_ns": sent_ns + round(rtt_ms * 1_000_000),
                "status": "received",
                "rtt_ms": rtt_ms,
                "datagram_bytes": 256,
            }
        )
    for offset in range(timeouts):
        sequence = len(rtts) + offset + 1
        bundle.write_packet(
            {
                "sequence": sequence,
                "path_id": "path-a",
                "sent_ns": sequence * 1_000_000_000,
                "received_ns": None,
                "status": "timeout",
                "rtt_ms": None,
                "datagram_bytes": 256,
            }
        )
    if strategy != "static":
        bundle.write_event(
            {
                "event": "path_switched",
                "from_path_id": "path-a",
                "to_path_id": "path-b",
                "evidence": "packet_arrival_timestamps",
            }
        )
    bundle.write_event(
        {
            "event": "phase_completed",
            "phase_id": "measured-phase",
            "longest_disruption_ms": 8.0 + block,
        }
    )
    if event_marker:
        bundle.write_event(event_marker)
    if auxiliary_artifact:
        artifact_name, artifact_value = auxiliary_artifact
        bundle.write_text_artifact(
            artifact_name,
            json.dumps(artifact_value, sort_keys=True) + "\n",
        )
    if status == "complete":
        return bundle.finalise(status=status)
    return bundle.finalise(status=status, failure_reason="fixture setup failure")


def _write_schema1_schedule(path: Path, bundle_paths: list[Path]) -> str:
    runs = []
    for bundle_path in bundle_paths:
        manifest = json.loads(
            (bundle_path / "manifest.json").read_text(encoding="utf-8")
        )
        runs.append(
            {
                "run_id": manifest["run_id"],
                "ordinal": manifest["ordinal"],
                "block": manifest["block"],
                "scenario_id": manifest["scenario"],
                "traffic_profile_id": manifest["traffic_profile"],
                "strategy": manifest["strategy"],
                "schedule_seed": manifest["schedule_seed"],
                "config_sha256": manifest["config_sha256"],
                "design": "randomised-complete-block",
            }
        )
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "dataset_id": "confirmatory-test",
                "design": "randomised-complete-block",
                "schedule_seed": 20260803,
                "config_sha256": "a" * 64,
                "expected_runs": len(runs),
                "runs": runs,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_complete_analysis_input(tmp_path: Path) -> tuple[list[Path], Path, str]:
    number = 100
    bundle_paths = []
    profiles = {
        "static": ((90.0, 100.0, 110.0, 120.0), 1),
        "threshold": ((75.0, 85.0, 95.0, 105.0), 1),
        "adaptive": ((55.0, 65.0, 75.0, 85.0), 0),
    }
    for block in (1, 2):
        for strategy in STRATEGIES:
            rtts, timeouts = profiles[strategy]
            bundle_paths.append(
                _write_bundle(
                    tmp_path,
                    number=number,
                    strategy=strategy,
                    block=block,
                    rtts=tuple(value + block for value in rtts),
                    timeouts=timeouts,
                )
            )
            number += 1

    schedule_path = tmp_path / "confirmatory.schedule.json"
    schedule_digest = _write_schema1_schedule(schedule_path, bundle_paths)
    return bundle_paths, schedule_path, schedule_digest


def test_fixture_aligns_pairs_by_block_scenario_traffic_and_exact_count():
    runs = read_run_table(FIXTURE_DIR / "runs.csv")

    validate_confirmatory_matrix(
        runs,
        expected_run_count=6,
        expected_strategies=STRATEGIES,
    )
    pairs = align_paired_differences(
        runs,
        baseline_strategy="static",
        alternative_strategy="adaptive",
        metric="rtt_p95_ms",
    )

    assert [pair.key for pair in pairs] == [
        (1, "latency_step", "video_low"),
        (2, "latency_step", "video_low"),
    ]
    assert [pair.difference for pair in pairs] == [-30.0, -40.0]


def test_packet_summary_uses_linear_p95_and_sent_packets_as_loss_denominator():
    rows = []
    for sequence, rtt in enumerate((10.0, 20.0, 30.0, 40.0), 1):
        rows.append(
            {
                "sequence": str(sequence),
                "path_id": "path-a",
                "sent_ns": str(sequence * 1_000_000_000),
                "received_ns": str(sequence * 1_000_000_000 + int(rtt * 1_000_000)),
                "status": "received",
                "rtt_ms": str(rtt),
                "datagram_bytes": "256",
            }
        )
    rows.append(
        {
            "sequence": "5",
            "path_id": "path-a",
            "sent_ns": "5000000000",
            "received_ns": "",
            "status": "timeout",
            "rtt_ms": "",
            "datagram_bytes": "256",
        }
    )

    summary = summarise_packet_rows(rows)

    assert summary.sent_count == 5
    assert summary.received_count == 4
    assert summary.loss_pct == pytest.approx(20.0)
    assert summary.rtt_mean_ms == pytest.approx(25.0)
    assert summary.rtt_median_ms == pytest.approx(25.0)
    assert summary.rtt_p95_ms == pytest.approx(38.5)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("datagram_bytes", "31", "datagram_bytes"),
        ("status", "RECEIVED", "non-final status"),
    ),
)
def test_packet_summary_enforces_exact_wire_schema(field, value, message):
    row = {
        "sequence": "1",
        "path_id": "path-a",
        "sent_ns": "1000000000",
        "received_ns": "1010000000",
        "status": "received",
        "rtt_ms": "10.0",
        "datagram_bytes": "256",
    }
    row[field] = value

    with pytest.raises(AnalysisInputError, match=message):
        summarise_packet_rows([row])


def test_packet_sequences_are_globally_unique_across_paths():
    rows = [
        {
            "sequence": "1",
            "path_id": path_id,
            "sent_ns": "1000000000",
            "received_ns": "1010000000",
            "status": "received",
            "rtt_ms": "10.0",
            "datagram_bytes": "256",
        }
        for path_id in ("path-a", "path-b")
    ]

    with pytest.raises(AnalysisInputError, match="duplicate packet sequence"):
        summarise_packet_rows(rows)


def test_bootstrap_interval_is_ordered_reproducible_and_contains_estimate():
    first = bootstrap_mean_ci((-4.0, -2.0, 1.0, 3.0), samples=2_000, seed=17)
    second = bootstrap_mean_ci((-4.0, -2.0, 1.0, 3.0), samples=2_000, seed=17)

    assert first == second
    assert first.lower <= -0.5 <= first.upper
    assert first.lower <= first.upper


def test_inference_aggregates_paired_cells_within_independent_blocks():
    pairs = (
        PairedDifference((1, "baseline", "low"), "s1", "a1", 10, 0, -10),
        PairedDifference((1, "jitter", "low"), "s2", "a2", 30, 0, -30),
        PairedDifference((2, "baseline", "low"), "s3", "a3", 20, 0, -20),
        PairedDifference((2, "jitter", "low"), "s4", "a4", 40, 0, -40),
    )

    blocks = aggregate_block_differences(pairs)

    assert [(item.block, item.cell_count, item.difference) for item in blocks] == [
        (1, 2, -20.0),
        (2, 2, -30.0),
    ]


def test_paired_effect_preserves_sign_and_handles_zero_variance():
    assert paired_standardised_effect((-10.0, -20.0, -30.0)) < 0
    assert paired_standardised_effect((0.0, 0.0, 0.0)) == 0.0
    assert paired_standardised_effect((-5.0, -5.0, -5.0)) is None


def test_holm_adjustment_is_monotonic_in_raw_p_value_order():
    raw = (0.04, 0.01, 0.03, 0.20)
    adjusted = holm_adjusted(raw)
    ordered = sorted(zip(raw, adjusted))

    assert [value for _, value in ordered] == sorted(value for _, value in ordered)
    assert adjusted == pytest.approx((0.09, 0.04, 0.09, 0.20))


def test_frozen_hypothesis_plan_defines_exact_confirmatory_family():
    plan = load_analysis_plan(HYPOTHESES_PATH)

    assert [contrast.contrast_id for contrast in plan.contrasts] == [
        "adaptive-vs-static-loss",
        "adaptive-vs-static-mean-rtt",
        "adaptive-vs-threshold-loss",
        "adaptive-vs-threshold-mean-rtt",
    ]
    assert [
        (contrast.alternative_strategy, contrast.baseline_strategy, contrast.run_metric)
        for contrast in plan.contrasts
    ] == [
        ("adaptive", "static", "loss_pct"),
        ("adaptive", "static", "rtt_mean_ms"),
        ("adaptive", "threshold", "loss_pct"),
        ("adaptive", "threshold", "rtt_mean_ms"),
    ]


def test_quality_control_rejects_wrong_count_and_unpaired_cells():
    runs = read_run_table(FIXTURE_DIR / "runs.csv")

    with pytest.raises(AnalysisInputError, match="expected 7 runs"):
        validate_confirmatory_matrix(
            runs,
            expected_run_count=7,
            expected_strategies=STRATEGIES,
        )
    with pytest.raises(AnalysisInputError, match="paired cell"):
        validate_confirmatory_matrix(
            runs[:-1],
            expected_run_count=5,
            expected_strategies=STRATEGIES,
        )

    mismatched_blocks = [
        replace(run, scenario="jitter_step") if run.block == 2 else run for run in runs
    ]
    with pytest.raises(AnalysisInputError, match="block cell layout"):
        validate_confirmatory_matrix(
            mismatched_blocks,
            expected_run_count=6,
            expected_strategies=STRATEGIES,
        )


def test_quality_control_reports_outliers_without_removing_runs():
    runs = read_run_table(FIXTURE_DIR / "runs.csv")
    runs[0] = replace(runs[0], rtt_p95_ms=1_000.0)

    report = build_quality_control(
        runs,
        expected_run_count=6,
        expected_strategies=STRATEGIES,
    )

    assert report["observed_run_count"] == 6
    assert report["accepted_run_count"] == 6
    assert report["outliers"]


def test_raw_loader_rejects_incomplete_confirmatory_run(tmp_path):
    _write_bundle(tmp_path, number=1, status="incomplete")

    with pytest.raises(AnalysisInputError, match="incomplete"):
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")


def test_raw_loader_analyses_validator_byte_snapshot_after_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    bundle_path = _write_bundle(tmp_path, number=1, rtts=(10.0, 20.0, 30.0, 40.0))
    original_validate = statistics_module.validate_evidence_bundle

    def validate_then_replace(path: Path):
        validation = original_validate(path)
        packet_path = path / "packets.csv"
        replaced = packet_path.read_text(encoding="utf-8").replace(
            ",10.0,", ",999.0,", 1
        )
        packet_path.write_text(replaced, encoding="utf-8", newline="\n")
        return validation

    monkeypatch.setattr(
        statistics_module, "validate_evidence_bundle", validate_then_replace
    )

    records = load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")

    assert records[0].rtt_mean_ms == pytest.approx(25.0)
    assert bundle_path is not None


def test_raw_loader_selects_only_terminal_complete_attempt_per_registered_cell(
    tmp_path: Path,
):
    root = Path(__file__).resolve().parents[2]
    plan_path = root / "experiments" / "plans" / "smoke.yaml"
    plan = load_experiment_plan(plan_path)
    observed: list[AttemptDefinition] = []

    def persist_attempt(definition, data_root, provenance):
        observed.append(definition)
        first_failure = (
            definition.entry.ordinal == 1
            and definition.allocation.attempt_number == 1
        )
        bundle = AttemptEvidenceBundle.create(data_root, definition.manifest)
        if not first_failure:
            bundle.write_packet(
                {
                    "sequence": 1,
                    "path_id": "path-a",
                    "sent_ns": 1_000,
                    "received_ns": 2_000,
                    "status": "received",
                    "rtt_ms": 0.001,
                    "datagram_bytes": 256,
                }
            )
            bundle.write_event(
                {
                    "event": "phase_completed",
                    "phase_id": "measured",
                    "longest_disruption_ms": 1.0,
                }
            )
        status = "incomplete" if first_failure else "complete"
        reason = "controlled apparatus failure" if first_failure else None
        evidence_path = bundle.finalise(status=status, failure_reason=reason)
        return RunOutcome(
            status=status,
            evidence_path=evidence_path,
            failure_reason=reason,
            final_active_path_id="path-a",
            packet_count=0 if first_failure else 1,
        )

    execute_registered_plan(
        plan_path,
        data_root=tmp_path,
        limit=1,
        effective_uid=0,
        provenance={"git_commit": "a" * 40, "git_dirty": False},
        run_one=persist_attempt,
    )
    with pytest.raises(AnalysisInputError, match="complete terminal attempt"):
        load_validated_runs(
            tmp_path / "raw",
            dataset_id=plan.dataset_id,
            schedule_path=registered_schedule_path(plan),
        )

    execute_registered_plan(
        plan_path,
        data_root=tmp_path,
        resume=True,
        effective_uid=0,
        provenance={
            "git_commit": "a" * 40,
            "git_dirty": True,
            "git_code_dirty": False,
            "git_changed_paths": ["data/raw/retained-attempt/manifest.json"],
        },
        run_one=persist_attempt,
    )
    records = load_validated_runs(
        tmp_path / "raw",
        dataset_id=plan.dataset_id,
        schedule_path=registered_schedule_path(plan),
    )

    assert len(records) == plan.expected_runs == 3
    assert all(uuid.UUID(record.run_id).version == 5 for record in records)
    assert all(uuid.UUID(record.source_bundle).version == 4 for record in records)
    first_cell_attempts = [
        definition
        for definition in observed
        if definition.entry.ordinal == 1
    ]
    assert len(first_cell_attempts) == 2
    first_record = next(record for record in records if record.run_id == str(
        first_cell_attempts[0].allocation.cell_id
    ))
    assert first_record.source_bundle == str(
        first_cell_attempts[1].allocation.attempt_id
    )

    dataset_dir = analyse_dataset(
        raw_dir=tmp_path / "raw",
        processed_root=tmp_path / "processed",
        dataset_id=plan.dataset_id,
        expected_run_count=plan.expected_runs,
        expected_strategies=STRATEGIES,
        bootstrap_samples=100,
        seed=20260803,
        analysis_plan_path=HYPOTHESES_PATH,
        schedule_path=registered_schedule_path(plan),
    )
    ledger = json.loads((dataset_dir / "source-bundles.json").read_text())
    quality = json.loads((dataset_dir / "quality-control.json").read_text())

    assert ledger["retained_bundle_count"] == 4
    assert ledger["selected_terminal_bundle_count"] == 3
    assert len(ledger["bundles"]) == 4
    assert sum(entry["selected_for_analysis"] for entry in ledger["bundles"]) == 3
    predecessor = next(
        entry for entry in ledger["bundles"] if entry["status"] == "incomplete"
    )
    successor = next(
        entry
        for entry in ledger["bundles"]
        if entry["supersedes_attempt_id"] == predecessor["attempt_id"]
    )
    assert predecessor["terminal"] is False
    assert predecessor["selected_for_analysis"] is False
    assert successor["terminal"] is True
    assert successor["selected_for_analysis"] is True
    assert all(
        re.fullmatch(r"[0-9a-f]{64}", entry["sha256sums_sha256"])
        for entry in ledger["bundles"]
    )
    assert quality["retained_attempt_count"] == 4
    assert quality["incomplete_predecessor_attempt_count"] == 1
    assert quality["terminal_attempt_count"] == 3
    assert quality["attempt_budget_exhausted_cell_count"] == 1


def test_raw_loader_normalises_deep_manifest_recursion(tmp_path, monkeypatch):
    bundle_path = tmp_path / "raw" / "deep-manifest"
    bundle_path.mkdir(parents=True)
    (bundle_path / "manifest.json").write_text(
        "[" * 2_000 + "0" + "]" * 2_000,
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "analysis.statistical_analysis.json.loads",
        lambda value: (_ for _ in ()).throw(RecursionError("decoder depth limit")),
    )

    with pytest.raises(AnalysisInputError, match="invalid manifest"):
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")


def test_raw_loader_calls_public_validator_for_malformed_manifest(
    tmp_path, monkeypatch
):
    bundle_path = tmp_path / "raw" / "malformed-manifest"
    bundle_path.mkdir(parents=True)
    (bundle_path / "manifest.json").write_text("{", encoding="utf-8")
    calls = []
    original_validation = statistics_module.validate_evidence_bundle

    def record_validation(path):
        calls.append(path)
        return original_validation(path)

    monkeypatch.setattr(
        "analysis.statistical_analysis.validate_evidence_bundle",
        record_validation,
    )

    with pytest.raises(AnalysisInputError):
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")

    assert calls == [bundle_path]


def test_raw_loader_calls_public_validator_for_oversized_manifest(
    tmp_path, monkeypatch
):
    bundle_path = tmp_path / "raw" / "oversized-manifest"
    bundle_path.mkdir(parents=True)
    (bundle_path / "manifest.json").write_bytes(b"{" + b" " * 1_048_576)
    calls = []
    original_validation = statistics_module.validate_evidence_bundle

    def record_validation(path):
        calls.append(path)
        return original_validation(path)

    monkeypatch.setattr(
        "analysis.statistical_analysis.validate_evidence_bundle",
        record_validation,
    )

    with pytest.raises(AnalysisInputError):
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")

    assert calls == [bundle_path]


def test_raw_loader_calls_public_validator_before_unreadable_manifest(
    tmp_path, monkeypatch
):
    bundle_path = tmp_path / "raw" / "unreadable-manifest"
    bundle_path.mkdir(parents=True)
    manifest_path = bundle_path / "manifest.json"
    manifest_path.write_text("{}", encoding="utf-8")
    calls = []
    original_read_text = Path.read_text

    def record_validation(path):
        calls.append(path)
        return BundleValidation(False, ("public validation failed",), ())

    def reject_manifest_read(path, *args, **kwargs):
        if path == manifest_path:
            raise PermissionError("manifest read denied")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(
        "analysis.statistical_analysis.validate_evidence_bundle",
        record_validation,
    )
    monkeypatch.setattr(Path, "read_text", reject_manifest_read)

    with pytest.raises(AnalysisInputError):
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")

    assert calls == [bundle_path]


def test_raw_loader_rejects_checksum_invalid_dataset_reclassification(
    tmp_path, monkeypatch
):
    first_bundle = _write_bundle(tmp_path, number=70)
    second_bundle = _write_bundle(tmp_path, number=71)
    manifest_path = second_bundle / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["dataset_id"] = "other-dataset"
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    calls = []
    original_validation = statistics_module.validate_evidence_bundle

    def record_validation(path):
        calls.append(path)
        return original_validation(path)

    monkeypatch.setattr(
        "analysis.statistical_analysis.validate_evidence_bundle",
        record_validation,
    )

    with pytest.raises(AnalysisInputError, match="failed evidence validation"):
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")

    assert calls == [first_bundle, second_bundle]


def test_raw_loader_bounds_public_validation_exception(tmp_path, monkeypatch):
    bundle_path = tmp_path / "raw" / "rejected-bundle"
    bundle_path.mkdir(parents=True)
    diagnostics = tuple("x" * 1_024 for _ in range(100))
    monkeypatch.setattr(
        statistics_module,
        "validate_evidence_bundle",
        lambda path: BundleValidation(False, diagnostics, ()),
    )

    with pytest.raises(AnalysisInputError) as caught:
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")

    assert len(str(caught.value)) <= 1_024


def test_raw_loader_bounds_raw_bundle_inventory_before_sorting(
    tmp_path, monkeypatch
):
    raw_dir = tmp_path / "raw"
    (raw_dir / "bundle-b").mkdir(parents=True)
    (raw_dir / "bundle-a").mkdir()
    monkeypatch.setattr(
        statistics_module,
        "MAX_DATASET_BUNDLES",
        1,
        raising=False,
    )

    with pytest.raises(AnalysisInputError, match="more than 1 bundle"):
        load_validated_runs(raw_dir, dataset_id="confirmatory-test")


def test_raw_loader_normalises_post_parse_deep_manifest(tmp_path):
    bundle_path = tmp_path / "raw" / "deep-parsed-manifest"
    bundle_path.mkdir(parents=True)
    (bundle_path / "manifest.json").write_text(
        '{"dataset_id":"confirmatory-test","nested":'
        + "[" * 1_000
        + "0"
        + "]" * 1_000
        + "}",
        encoding="utf-8",
    )

    with pytest.raises(AnalysisInputError):
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")


def test_raw_loader_uses_runner_switch_and_disruption_event_schema(tmp_path):
    _write_bundle(tmp_path, number=3, strategy="threshold", block=1)

    record = load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")[0]

    assert record.schema_version == SCHEMA_VERSION
    assert record.switch_count == 1
    assert record.longest_disruption_ms == pytest.approx(9.0)


def test_raw_loader_applies_legacy_packet_semantics_without_relabeling_output(tmp_path):
    bundle_path = _write_bundle(
        tmp_path,
        number=31,
        rtts=(20.0,),
        timeouts=0,
    )
    packets_path = bundle_path / "packets.csv"
    with packets_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "sequence",
                "path_id",
                "sent_ns",
                "received_ns",
                "status",
                "rtt_ms",
                "datagram_bytes",
            ),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerow(
            {
                "sequence": 1,
                "path_id": "path-a",
                "sent_ns": 1_000_000_000,
                "received_ns": 1_020_000_000,
                "status": "timeout",
                "rtt_ms": 20.0,
                "datagram_bytes": 256,
            }
        )
    manifest_path = bundle_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["schema_version"] = LEGACY_EVIDENCE_SCHEMA_VERSION
    for field in (
        "ordinal",
        "config_sha256",
        "experimental_unit",
        "failure_reason",
        "finalised_at_utc",
    ):
        saved.pop(field)
    saved["evidence_sha256"] = {
        name: hashlib.sha256((bundle_path / name).read_bytes()).hexdigest()
        for name in saved["evidence_sha256"]
    }
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    sums = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in bundle_path.iterdir()
        if path.name != "SHA256SUMS"
    }
    (bundle_path / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items())),
        encoding="ascii",
        newline="\n",
    )

    record = load_validated_runs(
        tmp_path / "raw", dataset_id="confirmatory-test"
    )[0]

    assert record.schema_version == SCHEMA_VERSION
    assert record.sent_count == 1
    assert record.received_count == 0
    assert record.loss_pct == 100.0


def test_raw_loader_accepts_deterministic_schedule_uuid5(tmp_path):
    scheduled_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "registered-run"))
    _write_bundle(tmp_path, number=4, run_id=scheduled_id)

    record = load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")[0]

    assert record.run_id == scheduled_id


@pytest.mark.parametrize(
    "marker",
    (
        {"provenance": {"synthetic": True}},
        {"generated": True},
        {"data_source": "fabricated"},
    ),
)
def test_raw_loader_rejects_generated_data_markers(tmp_path, marker):
    _write_bundle(
        tmp_path,
        number=2,
        marker=marker,
    )

    with pytest.raises(AnalysisInputError, match="generated-data marker"):
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")


def test_raw_loader_rejects_evidence_not_covered_by_sha256sums(tmp_path):
    bundle_path = _write_bundle(tmp_path, number=5)
    sums_path = bundle_path / "SHA256SUMS"
    sums_path.write_text(
        "\n".join(
            line
            for line in sums_path.read_text(encoding="ascii").splitlines()
            if not line.endswith("  packets.csv")
        )
        + "\n",
        encoding="ascii",
    )

    with pytest.raises(AnalysisInputError, match="not covered by SHA256SUMS"):
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")


def test_raw_loader_rejects_generated_marker_in_hashed_event(tmp_path):
    _write_bundle(
        tmp_path,
        number=6,
        event_marker={"event": "provenance", "data_source": "generated"},
    )

    with pytest.raises(AnalysisInputError, match="generated-data marker"):
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")


def test_raw_loader_bounds_generated_marker_with_long_json_key(tmp_path):
    huge_key = "A" * 200_000
    _write_bundle(
        tmp_path,
        number=61,
        auxiliary_artifact=("trace.json", {huge_key: {"generated": True}}),
    )

    with pytest.raises(AnalysisInputError, match="generated-data marker") as caught:
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")

    assert len(str(caught.value)) <= 1_024


def test_raw_loader_rejects_generated_marker_after_long_separator_prefix(tmp_path):
    disguised_marker = "_" * 200_000 + "generated"
    _write_bundle(
        tmp_path,
        number=62,
        auxiliary_artifact=("trace.json", {disguised_marker: True}),
    )

    with pytest.raises(AnalysisInputError, match="generated-data marker") as caught:
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")

    assert len(str(caught.value)) <= 1_024


@pytest.mark.parametrize("artifact_name", ["marker.JSON", "trace.JSONL"])
def test_raw_loader_rejects_generated_marker_in_mixed_case_structured_artifact(
    tmp_path, artifact_name
):
    _write_bundle(
        tmp_path,
        number=8,
        auxiliary_artifact=(artifact_name, {"synthetic": True}),
    )

    with pytest.raises(AnalysisInputError, match="generated-data marker"):
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")


def test_raw_loader_streams_auxiliary_jsonl_without_path_read_text(
    tmp_path, monkeypatch
):
    _write_bundle(
        tmp_path,
        number=9,
        auxiliary_artifact=("trace.JSONL", {"event": "measured"}),
    )
    original_read_text = Path.read_text

    def guarded_read_text(path, *args, **kwargs):
        if path.name == "trace.JSONL":
            raise AssertionError("auxiliary JSONL must be streamed")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)

    assert len(
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")
    ) == 1


def test_raw_loader_streams_events_jsonl_without_path_read_text(
    tmp_path, monkeypatch
):
    _write_bundle(tmp_path, number=32)
    original_read_text = Path.read_text

    def guarded_read_text(path, *args, **kwargs):
        if path.name == "events.jsonl":
            raise AssertionError("events.jsonl must be streamed")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)

    assert len(
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")
    ) == 1


def test_raw_loader_rejects_oversized_manifest_before_json_decode(tmp_path):
    bundle_path = _write_bundle(tmp_path, number=10)
    (bundle_path / "manifest.json").write_bytes(
        b'{"dataset_id":"confirmatory-test","padding":"'
        + b"x" * 1_048_576
        + b'"}'
    )

    with pytest.raises(AnalysisInputError, match="exceeds 1048576 bytes"):
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")


def test_raw_loader_reconciles_manifest_evidence_hashes(tmp_path):
    bundle_path = _write_bundle(tmp_path, number=7)
    manifest_path = bundle_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["evidence_sha256"]["packets.csv"] = "0" * 64
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    sums_path = bundle_path / "SHA256SUMS"
    manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    sums_path.write_text(
        "\n".join(
            f"{manifest_digest}  manifest.json"
            if line.endswith("  manifest.json")
            else line
            for line in sums_path.read_text(encoding="ascii").splitlines()
        )
        + "\n",
        encoding="ascii",
    )

    with pytest.raises(AnalysisInputError, match="evidence_sha256"):
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")


def test_raw_loader_rejects_manifest_drift_from_registered_schedule(tmp_path):
    bundle_path = _write_bundle(
        tmp_path,
        number=8,
        marker={"scenario": "wrong-scenario"},
    )
    schedule_path = tmp_path / "main.schedule.json"
    schedule_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "dataset_id": "confirmatory-test",
                "design": "randomised-complete-block",
                "schedule_seed": 20260803,
                "config_sha256": "a" * 64,
                "expected_runs": 1,
                "runs": [
                    {
                        "run_id": bundle_path.name,
                        "ordinal": 8,
                        "block": 1,
                        "scenario_id": "latency_step",
                        "traffic_profile_id": "video_low",
                        "strategy": "adaptive",
                        "schedule_seed": 20260803,
                        "config_sha256": "a" * 64,
                        "design": "randomised-complete-block",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(AnalysisInputError, match="registered schedule mismatch"):
        load_validated_runs(
            tmp_path / "raw",
            dataset_id="confirmatory-test",
            schedule_path=schedule_path,
        )


def test_raw_loader_normalises_invalid_utf8_manifest(tmp_path):
    bundle_path = tmp_path / "raw" / "invalid-utf8"
    bundle_path.mkdir(parents=True)
    (bundle_path / "manifest.json").write_bytes(b"\xff")

    with pytest.raises(AnalysisInputError, match="invalid manifest"):
        load_validated_runs(tmp_path / "raw", dataset_id="confirmatory-test")


def test_analysis_writes_frozen_machine_readable_outputs_and_figures(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    _bundle_paths, schedule_path, authenticated_schedule_digest = (
        _write_complete_analysis_input(tmp_path)
    )
    authenticated_analysis_plan_digest = hashlib.sha256(
        HYPOTHESES_PATH.read_bytes()
    ).hexdigest()
    original_sha256_file = statistics_module._sha256_file

    def reject_schedule_reread(path):
        if Path(path) in {schedule_path, HYPOTHESES_PATH}:
            raise AssertionError("authenticated protocol input must not be re-read")
        return original_sha256_file(path)

    monkeypatch.setattr(statistics_module, "_sha256_file", reject_schedule_reread)

    dataset_dir = analyse_dataset(
        raw_dir=tmp_path / "raw",
        processed_root=tmp_path / "processed",
        dataset_id="confirmatory-test",
        expected_run_count=6,
        expected_strategies=STRATEGIES,
        bootstrap_samples=500,
        seed=20260803,
        analysis_plan_path=HYPOTHESES_PATH,
        schedule_path=schedule_path,
        allow_unregistered_legacy_schedule=True,
    )

    expected = {
        "runs.csv",
        "quality-control.json",
        "confirmatory-results.csv",
        "descriptive-results.csv",
        "analysis-report.json",
    }
    assert expected <= {path.name for path in dataset_dir.iterdir()}
    with (dataset_dir / "runs.csv").open(newline="", encoding="utf-8") as handle:
        assert len(list(csv.DictReader(handle))) == 6
    quality = json.loads((dataset_dir / "quality-control.json").read_text())
    report = json.loads((dataset_dir / "analysis-report.json").read_text())
    assert quality["status"] == "pass"
    assert quality["observed_run_count"] == 6
    assert quality["sent_packet_count"] == 28
    assert quality["received_packet_count"] == 24
    assert quality["timed_out_packet_count"] == 4
    assert report["source_kind"] == "measured_evidence_bundles"
    assert report["analysis_parameters"]["registered_schedule_sha256"] == (
        authenticated_schedule_digest
    )
    assert report["analysis_parameters"]["analysis_plan_sha256"] == (
        authenticated_analysis_plan_digest
    )
    assert report["analysis_parameters"]["legacy_unregistered_schedule"] is True
    assert len(report["confirmatory_results"]) == 4
    assert [row["contrast_id"] for row in report["confirmatory_results"]] == [
        "adaptive-vs-static-loss",
        "adaptive-vs-static-mean-rtt",
        "adaptive-vs-threshold-loss",
        "adaptive-vs-threshold-mean-rtt",
    ]
    assert {row["block_count"] for row in report["confirmatory_results"]} == {2}
    assert {row["inference_unit"] for row in report["confirmatory_results"]} == {
        "block_mean_of_paired_cell_differences"
    }
    assert all(
        not any(key.startswith("sensitivity_") for key in row)
        for row in report["confirmatory_results"]
    )

    pngs = sorted((dataset_dir / "figures").glob("*.png"))
    pdfs = sorted((dataset_dir / "figures").glob("*.pdf"))
    assert pngs and len(pngs) == len(pdfs)
    assert pngs[0].read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    assert pdfs[0].read_bytes().startswith(b"%PDF")
    import matplotlib

    assert matplotlib.get_backend().lower() == "agg"


def test_analysis_source_ledger_uses_validator_captured_sums_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _bundle_paths, schedule_path, _digest = _write_complete_analysis_input(tmp_path)
    original_validate = statistics_module.validate_evidence_bundle
    captured_digests: dict[str, str] = {}

    def validate_then_replace_sums(path: Path):
        validation = original_validate(path)
        assert validation.valid
        assert validation.sha256sums_sha256 is not None
        captured_digests[path.name] = validation.sha256sums_sha256
        (path / "SHA256SUMS").write_bytes(b"changed-after-validator-snapshot\n")
        return validation

    monkeypatch.setattr(
        statistics_module,
        "validate_evidence_bundle",
        validate_then_replace_sums,
    )

    dataset_dir = analyse_dataset(
        raw_dir=tmp_path / "raw",
        processed_root=tmp_path / "processed",
        dataset_id="confirmatory-test",
        expected_run_count=6,
        expected_strategies=STRATEGIES,
        bootstrap_samples=100,
        analysis_plan_path=HYPOTHESES_PATH,
        schedule_path=schedule_path,
        allow_unregistered_legacy_schedule=True,
    )

    ledger = json.loads((dataset_dir / "source-bundles.json").read_text())
    assert {
        entry["bundle"]: entry["sha256sums_sha256"] for entry in ledger["bundles"]
    } == captured_digests


def test_analysis_publication_preserves_racing_destination_and_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _bundle_paths, schedule_path, _digest = _write_complete_analysis_input(tmp_path)
    processed_root = tmp_path / "processed"
    real_publish = collector_module._publish_directory_no_replace

    def occupy_then_publish(source: Path, destination: Path):
        destination.mkdir()
        (destination / "sentinel.txt").write_text("racing owner\n", encoding="utf-8")
        return real_publish(source, destination)

    monkeypatch.setattr(
        statistics_module,
        "_publish_directory_no_replace",
        occupy_then_publish,
        raising=False,
    )

    with pytest.raises(FileExistsError):
        analyse_dataset(
            raw_dir=tmp_path / "raw",
            processed_root=processed_root,
            dataset_id="confirmatory-test",
            expected_run_count=6,
            expected_strategies=STRATEGIES,
            bootstrap_samples=100,
            analysis_plan_path=HYPOTHESES_PATH,
            schedule_path=schedule_path,
            allow_unregistered_legacy_schedule=True,
        )

    destination = processed_root / "confirmatory-test"
    assert (destination / "sentinel.txt").read_text(encoding="utf-8") == (
        "racing owner\n"
    )
    assert not (destination / "runs.csv").exists()
    quarantined = tuple((processed_root / ".staging").iterdir())
    assert len(quarantined) == 1
    assert (quarantined[0] / "runs.csv").is_file()


def test_analysis_rejects_inconsistent_processed_checksum_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _bundle_paths, schedule_path, _digest = _write_complete_analysis_input(tmp_path)
    processed_root = tmp_path / "processed"
    original_write_checksums = statistics_module._write_checksums

    def write_inconsistent_checksums(root: Path):
        original_write_checksums(root)
        sums_path = root / "SHA256SUMS"
        lines = sums_path.read_text(encoding="ascii").splitlines()
        _digest, separator, name = lines[0].partition("  ")
        assert separator
        lines[0] = f"{'0' * 64}  {name}"
        sums_path.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")

    monkeypatch.setattr(
        statistics_module,
        "_write_checksums",
        write_inconsistent_checksums,
    )

    with pytest.raises(AnalysisInputError, match="processed SHA256SUMS"):
        analyse_dataset(
            raw_dir=tmp_path / "raw",
            processed_root=processed_root,
            dataset_id="confirmatory-test",
            expected_run_count=6,
            expected_strategies=STRATEGIES,
            bootstrap_samples=100,
            analysis_plan_path=HYPOTHESES_PATH,
            schedule_path=schedule_path,
            allow_unregistered_legacy_schedule=True,
        )

    assert not (processed_root / "confirmatory-test").exists()
    quarantined = tuple((processed_root / ".staging").iterdir())
    assert len(quarantined) == 1
