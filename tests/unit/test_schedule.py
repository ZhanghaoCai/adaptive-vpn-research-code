import hashlib
import json
import os
import shutil
import stat
from contextlib import contextmanager
from pathlib import Path

import pytest
import yaml

from adaptive_vpn import schedule as schedule_module
from adaptive_vpn.config import ExperimentPlan, load_experiment_plan
from adaptive_vpn.schedule import (
    experiment_config_sha256,
    generate_schedule,
)
from tests.unit.test_config import minimal_plan_data

ROOT = Path(__file__).resolve().parents[2]
MAX_SCHEDULE_BYTES = 8 * 1024 * 1024


def load_registered_schedule(plan: ExperimentPlan):
    return schedule_module.load_registered_schedule(plan)


def plan_with(blocks=4, seed=123):
    data = minimal_plan_data()
    data["blocks"] = blocks
    data["schedule_seed"] = seed
    data["scenarios"].append(
        {
            "scenario_id": "latency-step",
            "phases": data["scenarios"][0]["phases"],
        }
    )
    return ExperimentPlan.model_validate(data)


def serialise(schedule):
    return json.dumps(
        [entry.model_dump(mode="json") for entry in schedule],
        sort_keys=True,
        separators=(",", ":"),
    )


def _write_yaml(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def _registered_plan(tmp_path: Path, *, blocks: int = 2) -> ExperimentPlan:
    plan_data = minimal_plan_data()
    plan_data["blocks"] = blocks
    config_path = tmp_path / "config" / "system.yaml"
    _write_yaml(config_path, plan_data)
    registration_path = tmp_path / "plans" / "smoke.yaml"
    reference = {
        "include": "../config/system.yaml",
        "campaign_stage": "smoke",
        "schedule_path": "smoke.schedule.json",
        "schedule_sha256": "0" * 64,
        "max_attempts_per_cell": 2,
    }
    _write_yaml(registration_path, reference)
    plan = load_experiment_plan(registration_path)
    schedule_path = registration_path.parent / reference["schedule_path"]
    schedule_path.write_bytes(schedule_module.schedule_bytes(plan))
    reference["schedule_sha256"] = hashlib.sha256(
        schedule_path.read_bytes()
    ).hexdigest()
    _write_yaml(registration_path, reference)
    return load_experiment_plan(registration_path)


def _schedule_path(plan: ExperimentPlan) -> Path:
    assert plan.registration_path is not None
    assert plan.schedule_path is not None
    return plan.registration_path.parent / plan.schedule_path


def _document(plan: ExperimentPlan) -> dict:
    return json.loads(_schedule_path(plan).read_bytes())


def _replace_document(
    plan: ExperimentPlan, document: object, *, refresh_digest: bool = True
) -> ExperimentPlan:
    raw = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    _schedule_path(plan).write_bytes(raw)
    if refresh_digest:
        plan.schedule_sha256 = hashlib.sha256(raw).hexdigest()
    return plan


def test_same_seed_produces_byte_identical_schedule():
    assert serialise(generate_schedule(plan_with())) == serialise(
        generate_schedule(plan_with())
    )


def test_each_block_scenario_traffic_cell_is_a_strategy_permutation():
    schedule = generate_schedule(plan_with())
    cells = {}
    for entry in schedule:
        key = (entry.block, entry.scenario_id, entry.traffic_profile_id)
        cells.setdefault(key, []).append(entry.strategy)
    assert cells
    assert all(
        sorted(strategies) == ["adaptive", "static", "threshold"]
        for strategies in cells.values()
    )


def test_schedule_has_expected_size_unique_cell_ids_and_contiguous_ordinals():
    plan = plan_with()
    schedule = generate_schedule(plan)
    assert len(schedule) == plan.expected_runs
    assert len({entry.cell_id for entry in schedule}) == len(schedule)
    assert all(entry.cell_id.version == 5 for entry in schedule)
    assert [entry.ordinal for entry in schedule] == list(range(1, len(schedule) + 1))


def test_different_seed_changes_strategy_order_without_changing_cells():
    first = generate_schedule(plan_with(seed=1))
    second = generate_schedule(plan_with(seed=2))
    assert [entry.strategy for entry in first] != [entry.strategy for entry in second]
    assert {
        (entry.block, entry.scenario_id, entry.traffic_profile_id, entry.strategy)
        for entry in first
    } == {
        (entry.block, entry.scenario_id, entry.traffic_profile_id, entry.strategy)
        for entry in second
    }


def test_frozen_schedule_v2_document_records_exact_design_identity(tmp_path: Path):
    plan = _registered_plan(tmp_path)
    document = _document(plan)

    assert document == {
        "schema_version": "2.0.0",
        "campaign_stage": plan.campaign_stage,
        "dataset_id": plan.dataset_id,
        "design": "randomised-complete-block",
        "schedule_seed": plan.schedule_seed,
        "config_sha256": experiment_config_sha256(plan),
        "expected_cells": plan.expected_runs,
        "source": "config/system_config.yaml",
        "cells": [item.model_dump(mode="json") for item in generate_schedule(plan)],
    }
    assert all(
        "run_id" not in cell and "attempt_id" not in cell for cell in document["cells"]
    )


def test_registered_loader_returns_cells_parsed_from_frozen_bytes(tmp_path: Path):
    plan = _registered_plan(tmp_path)

    loaded = load_registered_schedule(plan)

    assert [entry.model_dump(mode="json") for entry in loaded] == _document(plan)[
        "cells"
    ]
    assert loaded is not generate_schedule(plan)


def test_registered_loader_rejects_unregistered_plan():
    with pytest.raises(ValueError, match="registered"):
        load_registered_schedule(plan_with())


@pytest.mark.parametrize(
    "unsafe_path",
    (
        "/absolute/schedule.json",
        "C:/absolute/schedule.json",
        "C:\\absolute\\schedule.json",
        "\\\\server\\share\\schedule.json",
        "../schedule.json",
        "nested/../../schedule.json",
        "nested\\schedule.json",
        "nested//schedule.json",
        "./schedule.json",
        "schedule.json/.",
        "schedule.json/..",
        "schedule\x00.json",
    ),
)
def test_registered_loader_rejects_unsafe_lexical_paths(
    tmp_path: Path, unsafe_path: str
):
    plan = _registered_plan(tmp_path)
    plan.schedule_path = unsafe_path

    with pytest.raises(ValueError, match="schedule path"):
        load_registered_schedule(plan)


@pytest.mark.parametrize(
    "unsafe_path",
    ("../outside.json", "/absolute/outside.json", "nested\\outside.json"),
)
def test_registered_schedule_destination_rejects_unsafe_path_before_write(
    tmp_path: Path, unsafe_path: str
):
    plan = _registered_plan(tmp_path)
    plan.schedule_path = unsafe_path

    with pytest.raises(ValueError, match="schedule path"):
        schedule_module.registered_schedule_path(plan)


def test_registered_loader_rejects_symlink_file(tmp_path: Path):
    plan = _registered_plan(tmp_path)
    schedule_path = _schedule_path(plan)
    target = schedule_path.with_name("target.json")
    schedule_path.replace(target)
    schedule_path.symlink_to(target)

    with pytest.raises(ValueError, match="symlink"):
        load_registered_schedule(plan)


def test_registered_loader_rejects_symlink_parent(tmp_path: Path):
    plan = _registered_plan(tmp_path)
    schedule_path = _schedule_path(plan)
    real_parent = schedule_path.parent / "real"
    real_parent.mkdir()
    target = real_parent / schedule_path.name
    schedule_path.replace(target)
    linked_parent = schedule_path.parent / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    plan.schedule_path = f"linked/{schedule_path.name}"

    with pytest.raises(ValueError, match="symlink"):
        load_registered_schedule(plan)


def test_registered_loader_opens_final_file_through_held_parent_fd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    plan = _registered_plan(tmp_path)
    schedule_path = _schedule_path(plan)
    original_open = os.open

    def guarded_open(path, flags, *args, **kwargs):
        if kwargs.get("dir_fd") is None and Path(path) == schedule_path:
            raise AssertionError("final schedule was opened by an attackable path")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded_open)

    assert len(load_registered_schedule(plan)) == plan.expected_runs


def test_registered_loader_rejects_registration_base_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    plan = _registered_plan(tmp_path)
    plans = plan.registration_path.parent
    moved = tmp_path / "plans-moved"
    original_read = os.read
    replaced = False

    def racing_read(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        if not replaced:
            replaced = True
            plans.rename(moved)
            plans.mkdir()
            (plans / plan.schedule_path).write_bytes(b"attacker replacement")
        return original_read(descriptor, size)

    monkeypatch.setattr(os, "read", racing_read)

    with pytest.raises(ValueError, match="parent identity"):
        load_registered_schedule(plan)


def test_freeze_registered_write_rejects_symlink_parent(tmp_path: Path):
    from scripts import freeze_schedules

    plan = _registered_plan(tmp_path)
    schedule_path = _schedule_path(plan)
    real_parent = schedule_path.parent / "real"
    real_parent.mkdir()
    target = real_parent / schedule_path.name
    schedule_path.replace(target)
    linked_parent = schedule_path.parent / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    plan.schedule_path = f"linked/{schedule_path.name}"

    with pytest.raises(ValueError, match="symlink"):
        freeze_schedules._atomic_write_registered(plan, b"replacement")

    assert target.read_bytes() != b"replacement"


def test_immutable_publication_rejects_destination_symlink_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from scripts import freeze_schedules

    content = b"immutable schedule\n"
    digest = hashlib.sha256(content).hexdigest()
    filename = f"smoke.schedule.{digest}.json"
    destination = tmp_path / filename
    outside = tmp_path / "outside-target"
    outside.write_bytes(b"outside sentinel")
    parent_descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    original_publish = freeze_schedules._publish_no_replace_at
    raced = False

    def racing_publish(
        parent_descriptor: int, source: str, destination_name: str
    ) -> None:
        nonlocal raced
        if not raced:
            raced = True
            destination.symlink_to(outside)
        original_publish(parent_descriptor, source, destination_name)

    monkeypatch.setattr(freeze_schedules, "_publish_no_replace_at", racing_publish)

    try:
        with pytest.raises(ValueError, match="appeared during publication"):
            freeze_schedules._publish_immutable_at(parent_descriptor, filename, content)
    finally:
        os.close(parent_descriptor)

    assert outside.read_bytes() == b"outside sentinel"
    assert destination.is_symlink()


def test_freeze_keeps_schedule_and_digest_under_one_held_registration_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from scripts import freeze_schedules

    plan = _registered_plan(tmp_path)
    plan_path = plan.registration_path
    plans = plan_path.parent
    moved = tmp_path / "plans-moved"
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_plan = outside / plan_path.name
    shutil.copy2(plan_path, outside_plan)
    outside_before = outside_plan.read_bytes()
    original_publish = freeze_schedules._publish_immutable_at
    raced = False

    def racing_publish(*args, **kwargs) -> None:
        nonlocal raced
        original_publish(*args, **kwargs)
        if not raced:
            raced = True
            plans.rename(moved)
            plans.symlink_to(outside, target_is_directory=True)

    monkeypatch.setattr(freeze_schedules, "_publish_immutable_at", racing_publish)

    with pytest.raises(ValueError, match="parent identity"):
        freeze_schedules._freeze_registered_schedule(
            plan, schedule_module.schedule_bytes(plan)
        )

    assert outside_plan.read_bytes() == outside_before


def test_freeze_rejects_plan_entry_replacement_after_bounded_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from scripts import freeze_schedules

    plan = _registered_plan(tmp_path)
    plan_path = plan.registration_path
    original_publish = freeze_schedules._publish_immutable_at
    replaced = False

    def replacing_publish(*args, **kwargs):
        nonlocal replaced
        result = original_publish(*args, **kwargs)
        if not replaced:
            replaced = True
            plan_path.write_text("attacker: replacement\n", encoding="utf-8")
        return result

    monkeypatch.setattr(freeze_schedules, "_publish_immutable_at", replacing_publish)

    with pytest.raises(ValueError, match="plan identity"):
        freeze_schedules._freeze_registered_schedule(
            plan, schedule_module.schedule_bytes(plan)
        )

    assert plan_path.read_text(encoding="utf-8") == "attacker: replacement\n"


def test_freeze_commits_with_a_content_addressed_schedule(tmp_path: Path):
    from scripts import freeze_schedules

    plan = _registered_plan(tmp_path)
    old_schedule = _schedule_path(plan)
    old_schedule_bytes = old_schedule.read_bytes()
    content = schedule_module.schedule_bytes(plan)
    digest = hashlib.sha256(content).hexdigest()

    destination, frozen_digest = freeze_schedules._freeze_registered_schedule(
        plan, content
    )

    reloaded = load_experiment_plan(plan.registration_path)
    assert frozen_digest == digest
    assert reloaded.schedule_path == f"smoke.{digest}.schedule.json"
    assert destination == plan.registration_path.parent / reloaded.schedule_path
    assert destination.read_bytes() == content
    assert old_schedule.read_bytes() == old_schedule_bytes
    assert len(load_registered_schedule(reloaded)) == reloaded.expected_runs


def test_freeze_plan_commit_failure_keeps_the_old_registered_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from scripts import freeze_schedules

    plan = _registered_plan(tmp_path)
    plan_path = plan.registration_path
    old_plan_bytes = plan_path.read_bytes()
    old_schedule = _schedule_path(plan)
    old_schedule_bytes = old_schedule.read_bytes()

    def fail_plan_commit(*args, **kwargs):
        raise RuntimeError("injected plan commit failure")

    monkeypatch.setattr(freeze_schedules, "_replace_plan_at", fail_plan_commit)

    with pytest.raises(RuntimeError, match="injected plan commit failure"):
        freeze_schedules._freeze_registered_schedule(
            plan, schedule_module.schedule_bytes(plan)
        )

    assert plan_path.read_bytes() == old_plan_bytes
    assert old_schedule.read_bytes() == old_schedule_bytes
    assert len(load_registered_schedule(load_experiment_plan(plan_path))) == (
        plan.expected_runs
    )
    assert not list(plan_path.parent.glob("*.tmp"))
    assert not list(plan_path.parent.glob("*.backup"))


def test_immutable_publication_rejects_destination_replacement_during_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from scripts import freeze_schedules

    content = b"immutable schedule\n"
    digest = hashlib.sha256(content).hexdigest()
    filename = f"smoke.schedule.{digest}.json"
    temporary_name = f".{filename}.freeze.tmp"
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside sentinel")
    parent_descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    original_unlink = freeze_schedules.os.unlink
    raced = False

    def racing_unlink(path, *args, **kwargs):
        nonlocal raced
        if not raced and path == temporary_name:
            raced = True
            original_unlink(filename, dir_fd=parent_descriptor)
            os.symlink(outside.name, filename, dir_fd=parent_descriptor)
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(freeze_schedules.os, "unlink", racing_unlink)
    try:
        with pytest.raises(ValueError, match="identity"):
            freeze_schedules._publish_immutable_at(parent_descriptor, filename, content)
    finally:
        os.close(parent_descriptor)

    assert outside.read_bytes() == b"outside sentinel"
    assert (tmp_path / filename).is_symlink()


@pytest.mark.parametrize("published_before_crash", [False, True])
def test_immutable_publication_recovers_a_deterministic_crash_temp(
    tmp_path: Path, published_before_crash: bool
):
    from scripts import freeze_schedules

    content = b"immutable schedule\n"
    digest = hashlib.sha256(content).hexdigest()
    filename = f"smoke.schedule.{digest}.json"
    temporary_name = f".{filename}.freeze.tmp"
    (tmp_path / temporary_name).write_bytes(content)
    if published_before_crash:
        os.link(tmp_path / temporary_name, tmp_path / filename)
    parent_descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        freeze_schedules._publish_immutable_at(parent_descriptor, filename, content)
    finally:
        os.close(parent_descriptor)

    assert (tmp_path / filename).read_bytes() == content
    assert not (tmp_path / temporary_name).exists()


def test_stale_exact_temp_is_recreated_and_file_fsynced_after_fsync_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from scripts import freeze_schedules

    content = b"staged content\n"
    temporary_name = ".smoke.schedule.publish.tmp"
    parent_descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    original_fsync = os.fsync
    fail_file_sync = True

    def failing_fsync(descriptor: int) -> None:
        nonlocal fail_file_sync
        if fail_file_sync and stat.S_ISREG(os.fstat(descriptor).st_mode):
            fail_file_sync = False
            raise OSError("injected file fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", failing_fsync)
    with pytest.raises(OSError, match="injected file fsync failure"):
        freeze_schedules._stage_temp_at(parent_descriptor, temporary_name, content)
    assert (tmp_path / temporary_name).read_bytes() == content

    file_syncs = 0

    def recording_fsync(descriptor: int) -> None:
        nonlocal file_syncs
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            file_syncs += 1
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    try:
        freeze_schedules._stage_temp_at(parent_descriptor, temporary_name, content)
    finally:
        os.close(parent_descriptor)

    assert file_syncs == 1


@pytest.mark.skipif(not hasattr(os, "fork"), reason="hard-crash probe requires fork")
@pytest.mark.parametrize(
    "crash_boundary", ["schedule_temp", "schedule_published", "plan_temp"]
)
def test_freeze_recovers_after_a_hard_exit_at_each_commit_boundary(
    tmp_path: Path, crash_boundary: str
):
    from scripts import freeze_schedules

    plan = _registered_plan(tmp_path)
    plan_path = plan.registration_path
    old_plan_bytes = plan_path.read_bytes()
    old_schedule = _schedule_path(plan)
    old_schedule_bytes = old_schedule.read_bytes()
    content = schedule_module.schedule_bytes(plan)

    child = os.fork()
    if child == 0:
        if crash_boundary == "schedule_temp":

            def crash_publish(
                parent_descriptor,
                filename,
                value,
                *,
                temporary_name=None,
            ):
                if temporary_name is None:
                    temporary_name = f".{filename}.freeze.tmp"
                freeze_schedules._stage_temp_at(
                    parent_descriptor, temporary_name, value
                )
                os._exit(77)

            freeze_schedules._publish_immutable_at = crash_publish
        elif crash_boundary == "schedule_published":
            original_publish = freeze_schedules._publish_immutable_at

            def crash_after_publish(*args, **kwargs):
                original_publish(*args, **kwargs)
                os._exit(77)

            freeze_schedules._publish_immutable_at = crash_after_publish
        else:

            def crash_plan_commit(
                parent_descriptor,
                filename,
                value,
                *,
                expected_snapshot,
                precommit_check=None,
            ):
                del expected_snapshot, precommit_check
                freeze_schedules._stage_temp_at(
                    parent_descriptor, f".{filename}.freeze.tmp", value
                )
                os._exit(77)

            freeze_schedules._replace_plan_at = crash_plan_commit
        try:
            freeze_schedules._freeze_registered_schedule(plan, content)
        except BaseException:  # noqa: BLE001 - child must not return to pytest.
            os._exit(98)
        os._exit(99)

    _pid, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 77
    assert plan_path.read_bytes() == old_plan_bytes
    assert old_schedule.read_bytes() == old_schedule_bytes
    assert len(load_registered_schedule(load_experiment_plan(plan_path))) == (
        plan.expected_runs
    )

    recovered_plan = load_experiment_plan(plan_path)
    destination, _digest = freeze_schedules._freeze_registered_schedule(
        recovered_plan, schedule_module.schedule_bytes(recovered_plan)
    )

    final_plan = load_experiment_plan(plan_path)
    assert destination == _schedule_path(final_plan)
    assert len(load_registered_schedule(final_plan)) == final_plan.expected_runs
    assert not list(plan_path.parent.rglob("*.tmp"))
    assert not list(plan_path.parent.rglob("*.backup"))


@pytest.mark.skipif(not hasattr(os, "fork"), reason="concurrency probe requires fork")
def test_directory_lock_serializes_two_freezers_with_the_same_stale_plan(
    tmp_path: Path,
):
    from scripts import freeze_schedules

    plan = _registered_plan(tmp_path)
    content = schedule_module.schedule_bytes(plan)
    children: list[int] = []
    for _index in range(2):
        child = os.fork()
        if child == 0:
            try:
                freeze_schedules._freeze_registered_schedule(plan, content)
            except BaseException:  # noqa: BLE001 - child must exit immediately.
                os._exit(1)
            os._exit(0)
        children.append(child)

    exit_codes = [
        os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]) for child in children
    ]
    assert exit_codes == [0, 0]
    final_plan = load_experiment_plan(plan.registration_path)
    assert len(load_registered_schedule(final_plan)) == final_plan.expected_runs
    assert not list(plan.registration_path.parent.rglob("*.tmp"))


def test_stale_freezer_cannot_overwrite_a_newer_registered_generation(
    tmp_path: Path,
):
    from scripts import freeze_schedules

    stale_plan = _registered_plan(tmp_path)
    plan_path = stale_plan.registration_path
    schedule_path = _schedule_path(stale_plan)
    newer_schedule = schedule_path.read_bytes() + b"\n"
    schedule_path.write_bytes(newer_schedule)
    reference = yaml.safe_load(plan_path.read_text(encoding="utf-8"))
    reference["schedule_sha256"] = hashlib.sha256(newer_schedule).hexdigest()
    _write_yaml(plan_path, reference)
    newer_plan_bytes = plan_path.read_bytes()
    assert len(load_registered_schedule(load_experiment_plan(plan_path))) == (
        stale_plan.expected_runs
    )

    with pytest.raises(ValueError, match="changed since schedule generation"):
        freeze_schedules._freeze_registered_schedule(
            stale_plan, schedule_module.schedule_bytes(stale_plan)
        )

    assert plan_path.read_bytes() == newer_plan_bytes
    assert schedule_path.read_bytes() == newer_schedule
    assert len(load_registered_schedule(load_experiment_plan(plan_path))) == (
        stale_plan.expected_runs
    )


def test_idempotent_freeze_keeps_plan_and_generation_inodes(tmp_path: Path):
    from scripts import freeze_schedules

    plan = _registered_plan(tmp_path)
    destination, _digest = freeze_schedules._freeze_registered_schedule(
        plan, schedule_module.schedule_bytes(plan)
    )
    committed_plan = load_experiment_plan(plan.registration_path)
    plan_snapshot = plan.registration_path.stat()
    schedule_snapshot = destination.stat()
    plan_bytes = plan.registration_path.read_bytes()
    schedule_raw = destination.read_bytes()

    second_destination, _second_digest = freeze_schedules._freeze_registered_schedule(
        committed_plan, schedule_module.schedule_bytes(committed_plan)
    )

    assert second_destination == destination
    assert plan.registration_path.stat().st_ino == plan_snapshot.st_ino
    assert destination.stat().st_ino == schedule_snapshot.st_ino
    assert plan.registration_path.read_bytes() == plan_bytes
    assert destination.read_bytes() == schedule_raw
    assert not list(plan.registration_path.parent.rglob("*.tmp"))
    assert not list(plan.registration_path.parent.rglob("*.backup"))


def test_freeze_write_captures_bounded_inputs_after_persistent_lock(
    monkeypatch: pytest.MonkeyPatch,
):
    from scripts import freeze_schedules

    original_lock = freeze_schedules._exclusive_freeze_lock_at
    original_capture = freeze_schedules._capture_frozen_inputs
    state = {"lock_held": False, "captures": 0}

    @contextmanager
    def tracked_lock(registration_descriptor):
        with original_lock(registration_descriptor) as lock_descriptor:
            state["lock_held"] = True
            try:
                yield lock_descriptor
            finally:
                state["lock_held"] = False

    @contextmanager
    def checked_capture(registration_descriptor, plan_path):
        assert state["lock_held"]
        state["captures"] += 1
        with original_capture(registration_descriptor, plan_path) as inputs:
            yield inputs

    monkeypatch.setattr(freeze_schedules, "_exclusive_freeze_lock_at", tracked_lock)
    monkeypatch.setattr(freeze_schedules, "_capture_frozen_inputs", checked_capture)
    monkeypatch.setattr(
        freeze_schedules,
        "_assert_transaction_capabilities_at",
        lambda _fd, _lock_fd: None,
    )

    assert len(freeze_schedules.freeze_all(check=False)) == 3
    assert state == {"lock_held": False, "captures": 3}


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
def test_freezer_rejects_unsafe_include_syntax(include: str):
    from scripts import freeze_schedules

    with pytest.raises(ValueError, match="safe relative POSIX"):
        freeze_schedules._resolve_include_lexically(
            Path("/tmp/plans/smoke.yaml"), include
        )


def test_freeze_rejects_source_drift_after_generation_before_plan_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from scripts import freeze_schedules

    plan = _registered_plan(tmp_path)
    plan_path = plan.registration_path
    old_plan_bytes = plan_path.read_bytes()
    old_schedule = _schedule_path(plan)
    old_schedule_bytes = old_schedule.read_bytes()
    original_publish = freeze_schedules._publish_immutable_at
    changed = False

    def publish_then_change_source(*args, **kwargs):
        nonlocal changed
        original_publish(*args, **kwargs)
        if not changed:
            changed = True
            inputs.source_path.write_bytes(inputs.source_raw + b"\n")

    with (
        freeze_schedules._open_absolute_file_parent(plan_path) as (
            registration_descriptor,
            _plan_name,
        ),
        freeze_schedules._exclusive_freeze_lock_at(registration_descriptor),
        freeze_schedules._capture_frozen_inputs(
            registration_descriptor, plan_path
        ) as inputs,
    ):
        monkeypatch.setattr(
            freeze_schedules, "_publish_immutable_at", publish_then_change_source
        )
        with pytest.raises(ValueError, match="source configuration changed"):
            freeze_schedules._freeze_captured_inputs(inputs)
        inputs.source_path.write_bytes(inputs.source_raw)

    assert plan_path.read_bytes() == old_plan_bytes
    assert old_schedule.read_bytes() == old_schedule_bytes
    assert len(load_registered_schedule(load_experiment_plan(plan_path))) == (
        plan.expected_runs
    )


def test_freeze_rejects_source_drift_during_plan_temp_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from scripts import freeze_schedules

    plan = _registered_plan(tmp_path)
    plan_path = plan.registration_path
    old_plan_bytes = plan_path.read_bytes()
    old_schedule = _schedule_path(plan)
    old_schedule_bytes = old_schedule.read_bytes()
    original_stage = freeze_schedules._stage_temp_at

    with (
        freeze_schedules._open_absolute_file_parent(plan_path) as (
            registration_descriptor,
            _plan_name,
        ),
        freeze_schedules._exclusive_freeze_lock_at(registration_descriptor),
        freeze_schedules._capture_frozen_inputs(
            registration_descriptor, plan_path
        ) as inputs,
    ):

        def stage_then_change_source(parent_descriptor, temporary_name, content):
            snapshot = original_stage(parent_descriptor, temporary_name, content)
            if temporary_name.endswith(".yaml.freeze.tmp"):
                inputs.source_path.write_bytes(inputs.source_raw + b"\n")
            return snapshot

        monkeypatch.setattr(
            freeze_schedules, "_stage_temp_at", stage_then_change_source
        )
        with pytest.raises(ValueError, match="source configuration changed"):
            freeze_schedules._freeze_captured_inputs(inputs)
        inputs.source_path.write_bytes(inputs.source_raw)

    assert plan_path.read_bytes() == old_plan_bytes
    assert old_schedule.read_bytes() == old_schedule_bytes
    assert load_registered_schedule(load_experiment_plan(plan_path))


def test_freeze_rejects_generation_replacement_during_plan_temp_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from scripts import freeze_schedules

    plan = _registered_plan(tmp_path)
    plan_path = plan.registration_path
    old_plan_bytes = plan_path.read_bytes()
    old_schedule = _schedule_path(plan)
    old_schedule_bytes = old_schedule.read_bytes()
    content = schedule_module.schedule_bytes(plan)
    digest = hashlib.sha256(content).hexdigest()
    generation = plan_path.parent / f"smoke.{digest}.schedule.json"
    outside = tmp_path / "outside-generation"
    outside.write_bytes(b"outside sentinel")
    original_stage = freeze_schedules._stage_temp_at

    with (
        freeze_schedules._open_absolute_file_parent(plan_path) as (
            registration_descriptor,
            _plan_name,
        ),
        freeze_schedules._exclusive_freeze_lock_at(registration_descriptor),
        freeze_schedules._capture_frozen_inputs(
            registration_descriptor, plan_path
        ) as inputs,
    ):

        def stage_then_replace_generation(parent_descriptor, temporary_name, value):
            snapshot = original_stage(parent_descriptor, temporary_name, value)
            if temporary_name.endswith(".yaml.freeze.tmp"):
                generation.unlink()
                generation.symlink_to(outside)
            return snapshot

        monkeypatch.setattr(
            freeze_schedules,
            "_stage_temp_at",
            stage_then_replace_generation,
        )
        with pytest.raises(ValueError, match="content-addressed schedule"):
            freeze_schedules._freeze_captured_inputs(inputs)

    assert plan_path.read_bytes() == old_plan_bytes
    assert old_schedule.read_bytes() == old_schedule_bytes
    assert outside.read_bytes() == b"outside sentinel"
    assert load_registered_schedule(load_experiment_plan(plan_path))


def test_registered_loader_rejects_non_regular_file(tmp_path: Path):
    plan = _registered_plan(tmp_path)
    schedule_path = _schedule_path(plan)
    schedule_path.unlink()
    os.mkfifo(schedule_path)
    assert stat.S_ISFIFO(schedule_path.lstat().st_mode)

    with pytest.raises(ValueError, match="regular file"):
        load_registered_schedule(plan)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX FIFO semantics")
def test_registered_loader_nonblocks_post_stat_fifo_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    plan = _registered_plan(tmp_path)
    schedule_path = _schedule_path(plan)
    original_open = os.open
    raced = False

    def race_before_file_open(path, flags, *args, **kwargs):
        nonlocal raced
        if (
            not raced
            and Path(path).name == schedule_path.name
            and not flags & getattr(os, "O_DIRECTORY", 0)
        ):
            raced = True
            schedule_path.unlink()
            os.mkfifo(schedule_path)
            assert flags & getattr(os, "O_NONBLOCK", 0)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", race_before_file_open)

    with pytest.raises(ValueError, match="regular file"):
        load_registered_schedule(plan)
    assert raced


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX FIFO semantics")
def test_freezer_reader_nonblocks_post_stat_fifo_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from scripts import freeze_schedules

    filename = "captured-plan.yaml"
    (tmp_path / filename).write_text("dataset_id: original\n", encoding="utf-8")
    parent_descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    original_open = os.open
    raced = False

    def race_before_file_open(path, flags, *args, **kwargs):
        nonlocal raced
        if (
            not raced
            and path == filename
            and kwargs.get("dir_fd") == parent_descriptor
        ):
            raced = True
            os.unlink(filename, dir_fd=parent_descriptor)
            os.mkfifo(filename, dir_fd=parent_descriptor)
            assert flags & getattr(os, "O_NONBLOCK", 0)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", race_before_file_open)
    try:
        with pytest.raises(ValueError, match="changed before bounded read"):
            freeze_schedules._read_bounded_regular_at(
                parent_descriptor,
                filename,
                maximum_bytes=1_024,
                label="captured plan",
            )
    finally:
        os.close(parent_descriptor)
    assert raced


def test_registered_loader_rejects_oversized_file(tmp_path: Path):
    plan = _registered_plan(tmp_path)
    raw = b"{" + b" " * MAX_SCHEDULE_BYTES
    _schedule_path(plan).write_bytes(raw)
    plan.schedule_sha256 = hashlib.sha256(raw).hexdigest()

    with pytest.raises(ValueError, match="size limit"):
        load_registered_schedule(plan)


def test_registered_loader_compares_digest_before_json_decode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    plan = _registered_plan(tmp_path)
    plan.schedule_sha256 = "f" * 64

    def unexpected_decode(*_args, **_kwargs):
        raise AssertionError("JSON decoding happened before digest verification")

    monkeypatch.setattr(json, "loads", unexpected_decode)
    with pytest.raises(ValueError, match="digest"):
        load_registered_schedule(plan)


@pytest.mark.parametrize("raw", (b"{", b"\xff"))
def test_registered_loader_rejects_malformed_json(tmp_path: Path, raw: bytes):
    plan = _registered_plan(tmp_path)
    _schedule_path(plan).write_bytes(raw)
    plan.schedule_sha256 = hashlib.sha256(raw).hexdigest()

    with pytest.raises(ValueError, match="JSON"):
        load_registered_schedule(plan)


@pytest.mark.parametrize("location", ("document", "cell"))
def test_registered_loader_rejects_extra_keys(tmp_path: Path, location: str):
    plan = _registered_plan(tmp_path)
    document = _document(plan)
    target = document if location == "document" else document["cells"][0]
    target["unexpected"] = True

    with pytest.raises(ValueError, match="invalid schedule"):
        load_registered_schedule(_replace_document(plan, document))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("schema_version", "1.0.0"),
        ("campaign_stage", "pilot"),
        ("dataset_id", "other-dataset"),
        ("design", "random"),
        ("schedule_seed", 999),
        ("config_sha256", "f" * 64),
        ("expected_cells", 999),
        ("source", "other.yaml"),
    ),
)
def test_registered_loader_rejects_wrong_header(
    tmp_path: Path, field: str, value: object
):
    plan = _registered_plan(tmp_path)
    document = _document(plan)
    document[field] = value

    with pytest.raises(ValueError, match="schedule"):
        load_registered_schedule(_replace_document(plan, document))


@pytest.mark.parametrize(
    "ordinals",
    (
        [1, 1, 3, 4, 5, 6],
        [1, 2, 4, 3, 5, 6],
        [True, 2, 3, 4, 5, 6],
    ),
)
def test_registered_loader_rejects_duplicate_gapped_or_bool_ordinal(
    tmp_path: Path, ordinals: list[object]
):
    plan = _registered_plan(tmp_path)
    document = _document(plan)
    for cell, ordinal in zip(document["cells"], ordinals, strict=True):
        cell["ordinal"] = ordinal

    with pytest.raises(ValueError, match="ordinal|invalid schedule"):
        load_registered_schedule(_replace_document(plan, document))


def test_registered_loader_rejects_duplicate_cell_id(tmp_path: Path):
    plan = _registered_plan(tmp_path)
    document = _document(plan)
    document["cells"][1]["cell_id"] = document["cells"][0]["cell_id"]

    with pytest.raises(ValueError, match="duplicate cell_id"):
        load_registered_schedule(_replace_document(plan, document))


@pytest.mark.parametrize("transform", (str.upper, lambda value: "{" + value + "}"))
def test_registered_loader_rejects_noncanonical_cell_id(tmp_path: Path, transform):
    plan = _registered_plan(tmp_path)
    document = _document(plan)
    document["cells"][0]["cell_id"] = transform(document["cells"][0]["cell_id"])

    with pytest.raises(ValueError, match="canonical UUIDv5|invalid schedule"):
        load_registered_schedule(_replace_document(plan, document))


def test_registered_loader_rejects_duplicate_cell_tuple(tmp_path: Path):
    plan = _registered_plan(tmp_path)
    document = _document(plan)
    first = document["cells"][0]
    second = document["cells"][1]
    for field in ("block", "scenario_id", "traffic_profile_id", "strategy"):
        second[field] = first[field]

    with pytest.raises(ValueError, match="duplicate cell tuple"):
        load_registered_schedule(_replace_document(plan, document))


@pytest.mark.parametrize("operation", ("missing", "extra"))
def test_registered_loader_rejects_missing_or_extra_cell(
    tmp_path: Path, operation: str
):
    plan = _registered_plan(tmp_path)
    document = _document(plan)
    if operation == "missing":
        document["cells"].pop()
    else:
        document["cells"].append(dict(document["cells"][-1]))

    with pytest.raises(ValueError, match="count|duplicate"):
        load_registered_schedule(_replace_document(plan, document))


def test_registered_loader_rejects_substituted_cell(tmp_path: Path):
    plan = _registered_plan(tmp_path)
    document = _document(plan)
    document["cells"][0]["scenario_id"] = "substituted"

    with pytest.raises(ValueError, match="deterministic schedule"):
        load_registered_schedule(_replace_document(plan, document))


def test_registered_loader_rejects_order_drift_from_deterministic_output(
    tmp_path: Path,
):
    plan = _registered_plan(tmp_path)
    document = _document(plan)
    document["cells"][0], document["cells"][1] = (
        document["cells"][1],
        document["cells"][0],
    )
    document["cells"][0]["ordinal"] = 1
    document["cells"][1]["ordinal"] = 2

    with pytest.raises(ValueError, match="deterministic schedule"):
        load_registered_schedule(_replace_document(plan, document))


def test_registered_loader_detects_file_identity_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    plan = _registered_plan(tmp_path)
    schedule_path = _schedule_path(plan)
    real_stat = os.stat
    calls = 0

    def changing_stat(path, *args, **kwargs):
        nonlocal calls
        result = real_stat(path, *args, **kwargs)
        if path == schedule_path.name and kwargs.get("dir_fd") is not None:
            calls += 1
            if calls > 1:
                values = list(result)
                values[1] += 1
                return os.stat_result(values)
        return result

    monkeypatch.setattr(os, "stat", changing_stat)

    with pytest.raises(ValueError, match="identity"):
        load_registered_schedule(plan)


@pytest.mark.parametrize("name", ("smoke", "pilot", "main"))
def test_checked_in_schedule_is_registered_and_loads_completely(name: str):
    plan = load_experiment_plan(ROOT / "experiments" / "plans" / f"{name}.yaml")
    path = _schedule_path(plan)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()

    schedule = load_registered_schedule(plan)

    assert path.name == f"{name}.{digest}.schedule.json"
    assert plan.schedule_sha256 == digest
    assert len(schedule) == plan.expected_runs
    assert [entry.ordinal for entry in schedule] == list(
        range(1, plan.expected_runs + 1)
    )


def test_freeze_check_uses_bounded_registered_loader_not_path_read_bytes(
    monkeypatch: pytest.MonkeyPatch,
):
    from scripts import freeze_schedules

    original_read_bytes = Path.read_bytes
    original_read_text = Path.read_text

    def reject_schedule_read_bytes(path: Path) -> bytes:
        if path.name.endswith(".schedule.json"):
            raise AssertionError("freeze check performed an unbounded schedule read")
        return original_read_bytes(path)

    def reject_yaml_read_text(path: Path, *args, **kwargs) -> str:
        if path.suffix in {".yaml", ".yml"}:
            raise AssertionError("freeze check performed an unbounded YAML read")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", reject_schedule_read_bytes)
    monkeypatch.setattr(Path, "read_text", reject_yaml_read_text)

    assert len(freeze_schedules.freeze_all(check=True)) == 3


def test_freezer_atomic_writer_fsyncs_parent_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from scripts import freeze_schedules

    directory_syncs = 0
    original_fsync = os.fsync

    def recording_fsync(descriptor: int) -> None:
        nonlocal directory_syncs
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_syncs += 1
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    freeze_schedules._atomic_write(tmp_path / "durable.yaml", b"value: true\n")

    assert directory_syncs == 1
