import os
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

import adaptive_vpn.config as config_module
from adaptive_vpn.config import (
    ExperimentPlan,
    build_experiment_plan,
    load_experiment_plan,
)
from adaptive_vpn.schedule import experiment_config_sha256

ROOT = Path(__file__).resolve().parents[2]


def minimal_plan_data():
    impairment = {
        "delay_ms": 20,
        "jitter_ms": 2,
        "loss_pct": 0.1,
        "loss_correlation_pct": 0,
    }
    return {
        "schema_version": "1.0.0",
        "dataset_id": "test-plan",
        "namespace_prefix": "avpn",
        "paths": [
            {"path_id": "path-a", "path_index": 0},
            {"path_id": "path-b", "path_index": 1},
            {"path_id": "path-c", "path_index": 2},
        ],
        "strategies": ["static", "threshold", "adaptive"],
        "traffic_profiles": [
            {
                "profile_id": "video-low",
                "packet_rate_hz": 50,
                "datagram_size": 800,
                "response_timeout_ms": 500,
            }
        ],
        "scenarios": [
            {
                "scenario_id": "baseline",
                "phases": [
                    {
                        "phase_id": "steady",
                        "duration_s": 2,
                        "paths": {
                            "path-a": impairment,
                            "path-b": impairment,
                            "path-c": impairment,
                        },
                    }
                ],
            }
        ],
        "blocks": 1,
        "schedule_seed": 20260803,
    }


def registration_data():
    return {
        "campaign_stage": "smoke",
        "schedule_path": "smoke.schedule.json",
        "schedule_sha256": "a" * 64,
        "max_attempts_per_cell": 2,
    }


def test_plan_rejects_unknown_strategy():
    data = minimal_plan_data()
    data["strategies"] = ["static", "magic"]
    with pytest.raises(ValidationError, match="strategies"):
        ExperimentPlan.model_validate(data)


def test_plan_rejects_duplicate_path_ids_and_indexes():
    data = minimal_plan_data()
    data["paths"][1] = {"path_id": "path-a", "path_index": 0}
    with pytest.raises(ValidationError, match="unique"):
        ExperimentPlan.model_validate(data)


def test_plan_rejects_non_positive_phase_duration():
    data = minimal_plan_data()
    data["scenarios"][0]["phases"][0]["duration_s"] = 0
    with pytest.raises(ValidationError, match="duration_s"):
        ExperimentPlan.model_validate(data)


@pytest.mark.parametrize("prefix", ("vpn", "avpn/unsafe", "AVPN", "avpn_unsafe"))
def test_plan_rejects_unsafe_namespace_prefix(prefix):
    data = minimal_plan_data()
    data["namespace_prefix"] = prefix
    with pytest.raises(ValidationError, match="namespace_prefix"):
        ExperimentPlan.model_validate(data)


def test_phase_must_define_treatment_for_every_path():
    data = minimal_plan_data()
    del data["scenarios"][0]["phases"][0]["paths"]["path-c"]
    with pytest.raises(ValidationError, match="every configured path"):
        ExperimentPlan.model_validate(data)


def test_loss_correlation_requires_nonzero_registered_loss():
    data = minimal_plan_data()
    data["scenarios"][0]["phases"][0]["paths"]["path-a"] = {
        "delay_ms": 20,
        "jitter_ms": 2,
        "loss_pct": 0,
        "loss_correlation_pct": 70,
    }
    with pytest.raises(ValidationError, match="correlation"):
        ExperimentPlan.model_validate(data)


def test_duplicate_drain_is_an_explicit_positive_measurement_contract():
    data = minimal_plan_data()
    data["measurement"] = {"duplicate_drain_ms": 50}

    plan = ExperimentPlan.model_validate(data)

    assert plan.measurement.duplicate_drain_ms == 50
    data["measurement"]["duplicate_drain_ms"] = 0
    with pytest.raises(ValidationError, match="duplicate_drain_ms"):
        ExperimentPlan.model_validate(data)


def test_main_plan_is_single_source_and_contains_exactly_432_runs():
    plan = load_experiment_plan(ROOT / "experiments" / "plans" / "main.yaml")
    assert plan.expected_runs == 432
    assert len(plan.scenarios) == 6
    assert len(plan.traffic_profiles) == 2
    assert plan.blocks == 12
    assert plan.source_path == (ROOT / "config" / "system_config.yaml").resolve()
    assert plan.measurement.window_duration_s == 1.0
    assert plan.measurement.monitor_packet_rate_hz == 20
    assert plan.measurement.monitor_packets_per_window == 10
    assert plan.measurement.monitor_datagram_size == 128
    assert plan.measurement.echo_port == 39_993
    assert plan.measurement.duplicate_drain_ms == 50
    assert plan.switching.min_score_threshold == 0.8


def test_pilot_reference_filters_authoritative_scenarios_and_profiles():
    plan = load_experiment_plan(ROOT / "experiments" / "plans" / "pilot.yaml")
    assert plan.expected_runs == 12
    assert {item.scenario_id for item in plan.scenarios} == {"baseline", "compound"}
    assert {item.profile_id for item in plan.traffic_profiles} == {"video-low"}
    assert plan.blocks == 2


@pytest.mark.parametrize("field", tuple(registration_data()))
def test_plan_rejects_partial_schedule_registration(field):
    data = minimal_plan_data()
    data[field] = registration_data()[field]

    with pytest.raises(ValidationError, match="registration fields"):
        ExperimentPlan.model_validate(data)


@pytest.mark.parametrize("missing", tuple(registration_data()))
def test_plan_rejects_registration_missing_any_required_field(missing):
    data = minimal_plan_data()
    data.update(registration_data())
    del data[missing]

    with pytest.raises(ValidationError, match="registration fields"):
        ExperimentPlan.model_validate(data)


def test_unit_plan_may_omit_all_registration_fields():
    plan = ExperimentPlan.model_validate(minimal_plan_data())

    assert plan.campaign_stage is None
    assert plan.schedule_path is None
    assert plan.schedule_sha256 is None
    assert plan.max_attempts_per_cell is None
    assert plan.registration_path is None


def test_plan_accepts_complete_schedule_registration():
    data = minimal_plan_data()
    data.update(registration_data())

    plan = ExperimentPlan.model_validate(data)

    assert plan.campaign_stage == "smoke"
    assert plan.schedule_path == "smoke.schedule.json"
    assert plan.schedule_sha256 == "a" * 64
    assert plan.max_attempts_per_cell == 2


@pytest.mark.parametrize(
    "digest",
    (
        "a" * 63,
        "a" * 65,
        "A" * 64,
        "g" * 64,
        "0" * 63 + "-",
    ),
)
def test_plan_rejects_malformed_schedule_digest(digest):
    data = minimal_plan_data()
    data.update(registration_data())
    data["schedule_sha256"] = digest

    with pytest.raises(ValidationError, match="schedule_sha256"):
        ExperimentPlan.model_validate(data)


@pytest.mark.parametrize("stage", ("", "Smoke", "calibration", "main/unsafe"))
def test_plan_rejects_unsafe_campaign_stage(stage):
    data = minimal_plan_data()
    data.update(registration_data())
    data["campaign_stage"] = stage

    with pytest.raises(ValidationError, match="campaign_stage"):
        ExperimentPlan.model_validate(data)


@pytest.mark.parametrize("attempts", (True, 0, -1, 1.5, "2"))
def test_plan_rejects_invalid_max_attempts_per_cell(attempts):
    data = minimal_plan_data()
    data.update(registration_data())
    data["max_attempts_per_cell"] = attempts

    with pytest.raises(ValidationError, match="max_attempts_per_cell"):
        ExperimentPlan.model_validate(data)


def test_registration_path_is_reference_yaml_not_included_config(
    tmp_path: Path,
):
    config_path = tmp_path / "config" / "system.yaml"
    config_path.parent.mkdir()
    config_path.write_text(
        __import__("yaml").safe_dump(minimal_plan_data(), sort_keys=False),
        encoding="utf-8",
    )
    reference_path = tmp_path / "plans" / "smoke.yaml"
    reference_path.parent.mkdir()
    reference_path.write_text(
        __import__("yaml").safe_dump(
            {
                "include": "../config/system.yaml",
                **registration_data(),
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    plan = load_experiment_plan(reference_path)

    assert plan.registration_path == reference_path.resolve()
    assert plan.source_path == config_path.resolve()


def test_mapping_builder_matches_the_path_loader(tmp_path: Path):
    yaml = __import__("yaml")
    source_mapping = minimal_plan_data()
    config_path = tmp_path / "config" / "system.yaml"
    config_path.parent.mkdir()
    config_path.write_text(
        yaml.safe_dump(source_mapping, sort_keys=False), encoding="utf-8"
    )
    reference_mapping = {
        "include": "../config/system.yaml",
        "scenario_ids": ["baseline"],
        "traffic_profile_ids": ["video-low"],
        **registration_data(),
    }
    reference_path = tmp_path / "plans" / "smoke.yaml"
    reference_path.parent.mkdir()
    reference_path.write_text(
        yaml.safe_dump(reference_mapping, sort_keys=False), encoding="utf-8"
    )

    from_path = load_experiment_plan(reference_path)
    from_mappings = build_experiment_plan(
        reference_mapping,
        registration_path=reference_path.resolve(),
        source_mapping=source_mapping,
        source_path=config_path.resolve(),
    )

    assert from_mappings.model_dump(mode="json") == from_path.model_dump(mode="json")
    assert from_mappings.registration_path == from_path.registration_path
    assert from_mappings.source_path == from_path.source_path


@pytest.mark.parametrize(
    "include",
    (
        "C:/config.yaml",
        "C:config.yaml",
        r"\\server\share\config.yaml",
        r"..\config\system.yaml",
        "/absolute/config.yaml",
        "config\x00.yaml",
    ),
)
def test_path_and_mapping_loaders_reject_unsafe_include_syntax(
    tmp_path: Path, include: str
):
    yaml = __import__("yaml")
    reference = {"include": include, **registration_data()}
    reference_path = tmp_path / "plans" / "smoke.yaml"
    reference_path.parent.mkdir()
    reference_path.write_text(
        yaml.safe_dump(reference, sort_keys=False), encoding="utf-8"
    )

    with pytest.raises(ValueError, match="safe relative POSIX"):
        load_experiment_plan(reference_path)
    with pytest.raises(ValueError, match="safe relative POSIX"):
        build_experiment_plan(
            reference,
            registration_path=reference_path,
            source_mapping=minimal_plan_data(),
            source_path=tmp_path / "config" / "system.yaml",
        )


def test_path_loader_normalises_invalid_utf8_to_value_error(tmp_path: Path):
    path = tmp_path / "invalid.yaml"
    path.write_bytes(b"\xff")

    with pytest.raises(ValueError, match="cannot load experiment plan"):
        load_experiment_plan(path)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX FIFO semantics")
def test_bounded_plan_reader_rejects_fifo_without_blocking(tmp_path: Path):
    path = tmp_path / "plan.yaml"
    os.mkfifo(path)

    started = time.monotonic()
    with pytest.raises(ValueError, match="regular file"):
        config_module.read_bounded_regular_bytes(
            path,
            max_bytes=1_024,
            label="experiment plan",
        )

    assert time.monotonic() - started < 1.0


def test_bounded_plan_reader_rejects_symbolic_link(tmp_path: Path):
    target = tmp_path / "target.yaml"
    target.write_text("dataset_id: target\n", encoding="utf-8")
    link = tmp_path / "plan.yaml"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symbolic links are unavailable")

    with pytest.raises(ValueError, match="symlink"):
        config_module.read_bounded_regular_bytes(
            link,
            max_bytes=1_024,
            label="experiment plan",
        )


def test_bounded_plan_reader_rejects_path_replacement_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = tmp_path / "plan.yaml"
    path.write_bytes(b"dataset_id: original\n")
    replacement = tmp_path / "replacement.yaml"
    replacement.write_bytes(b"dataset_id: replaced\n")
    original_read = config_module.os.read
    replaced = False

    def replace_after_first_read(descriptor: int, count: int) -> bytes:
        nonlocal replaced
        chunk = original_read(descriptor, count)
        if chunk and not replaced:
            replaced = True
            replacement.replace(path)
        return chunk

    monkeypatch.setattr(config_module.os, "read", replace_after_first_read)

    with pytest.raises(ValueError, match="identity changed"):
        config_module.read_bounded_regular_bytes(
            path,
            max_bytes=1_024,
            label="experiment plan",
        )


def test_path_loader_bounds_registration_before_yaml_decode(tmp_path: Path):
    path = tmp_path / "oversized.yaml"
    path.write_bytes(b"x" * (1_048_576 + 1))

    with pytest.raises(ValueError, match="exceeds 1048576 bytes"):
        load_experiment_plan(path)


def test_path_loader_bounds_included_source_before_yaml_decode(tmp_path: Path):
    source_path = tmp_path / "config" / "system.yaml"
    source_path.parent.mkdir()
    source_path.write_bytes(b"x" * (1_048_576 + 1))
    reference_path = tmp_path / "plans" / "smoke.yaml"
    reference_path.parent.mkdir()
    reference_path.write_text(
        __import__("yaml").safe_dump(
            {
                "include": "../config/system.yaml",
                **registration_data(),
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exceeds 1048576 bytes"):
        load_experiment_plan(reference_path)


def test_scientific_hash_excludes_registration_identity_and_private_paths():
    first_data = minimal_plan_data()
    first_data.update(registration_data())
    first = ExperimentPlan.model_validate(first_data)
    first._source_path = Path("/one/config.yaml")
    first._registration_path = Path("/one/smoke.yaml")

    second_data = minimal_plan_data()
    second_data.update(
        {
            "campaign_stage": "pilot",
            "schedule_path": "nested/pilot.schedule.json",
            "schedule_sha256": "b" * 64,
            "max_attempts_per_cell": 2,
        }
    )
    second = ExperimentPlan.model_validate(second_data)
    second._source_path = Path("/two/config.yaml")
    second._registration_path = Path("/two/pilot.yaml")

    assert experiment_config_sha256(first) == experiment_config_sha256(second)


def test_scientific_hash_includes_attempt_limit():
    first_data = minimal_plan_data()
    first_data.update(registration_data())
    second_data = minimal_plan_data()
    second_data.update(registration_data())
    second_data["max_attempts_per_cell"] = 3

    assert experiment_config_sha256(
        ExperimentPlan.model_validate(first_data)
    ) != experiment_config_sha256(ExperimentPlan.model_validate(second_data))
