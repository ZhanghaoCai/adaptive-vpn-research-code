import fcntl
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from adaptive_vpn.config import load_experiment_plan
from adaptive_vpn.schedule import load_registered_schedule, schedule_bytes
from scripts import freeze_schedules
from tests.unit.test_schedule import _registered_plan, _schedule_path

pytestmark = pytest.mark.drvfs


@pytest.fixture
def drvfs_tmp_path():
    base = Path("/mnt/c/tmp")
    if not base.is_dir():
        pytest.skip("DrvFs /mnt/c/tmp is unavailable")
    path = Path(tempfile.mkdtemp(prefix="adaptive-vpn-drvfs-", dir=base))
    try:
        assert path.resolve().is_relative_to(base.resolve())
        yield path
    finally:
        assert path.resolve().is_relative_to(base.resolve())
        shutil.rmtree(path)


def test_drvfs_flock_excludes_a_second_process(drvfs_tmp_path: Path):
    lock_path = drvfs_tmp_path / "lock"
    lock_path.touch()
    parent_descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    fcntl.flock(parent_descriptor, fcntl.LOCK_EX)
    child = os.fork()
    if child == 0:
        descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os._exit(0)
        os._exit(1)
    assert os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]) == 0
    fcntl.flock(parent_descriptor, fcntl.LOCK_UN)
    os.close(parent_descriptor)

    descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(descriptor, fcntl.LOCK_UN)
    os.close(descriptor)


def test_drvfs_hardlink_is_no_replace_and_directory_fsyncs(
    drvfs_tmp_path: Path,
):
    source = drvfs_tmp_path / "source.tmp"
    destination = drvfs_tmp_path / "generation.schedule.json"
    source.write_bytes(b"schedule\n")
    os.link(source, destination, follow_symlinks=False)
    with pytest.raises(FileExistsError):
        os.link(source, destination, follow_symlinks=False)
    assert source.stat().st_ino == destination.stat().st_ino
    directory_descriptor = os.open(drvfs_tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    os.fsync(directory_descriptor)
    os.close(directory_descriptor)


def test_drvfs_capability_gate_rejects_non_atomic_plan_replacement(
    drvfs_tmp_path: Path,
):
    directory_descriptor = os.open(drvfs_tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with (
            freeze_schedules._exclusive_freeze_lock_at(
                directory_descriptor
            ) as lock_descriptor,
            pytest.raises(RuntimeError, match="atomic plan replacement"),
        ):
            freeze_schedules._assert_transaction_capabilities_at(
                directory_descriptor, lock_descriptor
            )
    finally:
        os.close(directory_descriptor)
    assert not list(drvfs_tmp_path.glob(".freeze-capability.*"))


def test_native_linux_capability_probe_accepts_atomic_replace(tmp_path: Path):
    directory_descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with freeze_schedules._exclusive_freeze_lock_at(
            directory_descriptor
        ) as lock_descriptor:
            freeze_schedules._assert_transaction_capabilities_at(
                directory_descriptor, lock_descriptor
            )
    finally:
        os.close(directory_descriptor)
    assert not list(tmp_path.glob(".freeze-capability.*"))


def test_production_capability_probe_rejects_a_noop_flock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    lock_path = tmp_path / ".freeze-schedules.lock"
    lock_path.touch()
    lock_descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    directory_descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
    monkeypatch.setattr(freeze_schedules.fcntl, "flock", lambda *_args: None)
    try:
        with pytest.raises(RuntimeError, match="flock"):
            freeze_schedules._assert_transaction_capabilities_at(
                directory_descriptor, lock_descriptor
            )
    finally:
        os.close(directory_descriptor)
        os.close(lock_descriptor)


@pytest.mark.parametrize(
    "crash_boundary", ["schedule_temp", "schedule_published", "plan_temp"]
)
def test_drvfs_transaction_recovers_hard_exit_boundaries(
    drvfs_tmp_path: Path, crash_boundary: str
):
    plan = _registered_plan(drvfs_tmp_path)
    plan_path = plan.registration_path
    old_plan = plan_path.read_bytes()
    old_schedule_path = _schedule_path(plan)
    old_schedule = old_schedule_path.read_bytes()
    content = schedule_bytes(plan)
    child = os.fork()
    if child == 0:
        if crash_boundary == "schedule_temp":

            def crash_publish(parent_descriptor, filename, value, **kwargs):
                temporary_name = kwargs["temporary_name"]
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

            def crash_plan(
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

            freeze_schedules._replace_plan_at = crash_plan
        try:
            freeze_schedules._freeze_registered_schedule(plan, content)
        except BaseException:  # noqa: BLE001 - child must not return to pytest.
            os._exit(98)
        os._exit(99)

    assert os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]) == 77
    assert plan_path.read_bytes() == old_plan
    assert old_schedule_path.read_bytes() == old_schedule
    assert load_registered_schedule(load_experiment_plan(plan_path))

    recovered = load_experiment_plan(plan_path)
    freeze_schedules._freeze_registered_schedule(recovered, schedule_bytes(recovered))
    final_plan = load_experiment_plan(plan_path)
    assert load_registered_schedule(final_plan)
    assert not list(plan_path.parent.rglob("*.tmp"))
    assert not list(plan_path.parent.rglob("*.backup"))
