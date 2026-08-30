"""Atomically freeze every registered experiment schedule or verify stability."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ntpath
import os
import re
import select
import stat
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

try:
    import fcntl
except ImportError:  # pragma: no cover - the freezer is a Linux/WSL tool.
    fcntl = None

from adaptive_vpn.config import (
    ExperimentPlan,
    build_experiment_plan,
)
from adaptive_vpn.schedule import (
    load_registered_schedule,
    open_registered_schedule_parent,
    schedule_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
PLAN_NAMES = ("smoke", "pilot", "main")
_DIGEST_LINE = re.compile(r"(?m)^schedule_sha256:[^\r\n]*$")
_SCHEDULE_PATH_LINE = re.compile(r"(?m)^schedule_path:[^\r\n]*$")
_MAX_PLAN_BYTES = 1024 * 1024
_MAX_SCHEDULE_BYTES = 8 * 1024 * 1024
_LOCK_NAME = ".freeze-schedules.lock"


@dataclass(frozen=True, slots=True)
class FrozenInputs:
    plan: ExperimentPlan
    registration_descriptor: int
    registration_name: str
    registration_raw: bytes
    registration_snapshot: tuple[int, int, int, int, int]
    registration_mapping: dict[str, Any]
    source_descriptor: int
    source_name: str
    source_path: Path
    source_raw: bytes
    source_snapshot: tuple[int, int, int, int, int]
    source_mapping: dict[str, Any]


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with open(descriptor, "wb", closefd=True) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        directory_descriptor = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _publish_no_replace_at(
    parent_descriptor: int, source: str, destination: str
) -> None:
    os.link(
        source,
        destination,
        src_dir_fd=parent_descriptor,
        dst_dir_fd=parent_descriptor,
        follow_symlinks=False,
    )


def _entry_snapshot(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
    )


@contextmanager
def _exclusive_directory_lock(parent_descriptor: int) -> Iterator[None]:
    if fcntl is None:
        raise RuntimeError("schedule freezing requires POSIX flock support")
    try:
        fcntl.flock(parent_descriptor, fcntl.LOCK_EX)
    except OSError as exc:
        raise RuntimeError("cannot acquire the registered plan directory lock") from exc
    try:
        yield
    finally:
        fcntl.flock(parent_descriptor, fcntl.LOCK_UN)


def _directory_identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


@contextmanager
def _open_absolute_file_parent(path: Path) -> Iterator[tuple[int, str]]:
    if path.anchor != "/" or path.name in {"", ".", ".."}:
        raise ValueError("freeze input path must be an absolute POSIX file path")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors: list[int] = []
    parent_links: list[tuple[int, str, int]] = []
    verification_error: ValueError | None = None
    body_completed = False
    try:
        current_descriptor = os.open("/", directory_flags)
        descriptors.append(current_descriptor)
        for component in path.parent.parts[1:]:
            if component in {"", ".", ".."}:
                raise ValueError("freeze input path has an unsafe component")
            before = os.stat(
                component,
                dir_fd=current_descriptor,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise ValueError("freeze input parent is not a real directory")
            child_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=current_descriptor,
            )
            descriptors.append(child_descriptor)
            if _directory_identity(before) != _directory_identity(
                os.fstat(child_descriptor)
            ):
                raise ValueError("freeze input parent identity changed during open")
            parent_links.append((current_descriptor, component, child_descriptor))
            current_descriptor = child_descriptor
        yield current_descriptor, path.name
        body_completed = True
    finally:
        if body_completed:
            try:
                for parent_descriptor, component, child_descriptor in parent_links:
                    current = os.stat(
                        component,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    if stat.S_ISLNK(current.st_mode) or _directory_identity(
                        current
                    ) != _directory_identity(os.fstat(child_descriptor)):
                        raise ValueError(
                            "freeze input parent identity changed during use"
                        )
            except (OSError, ValueError) as exc:
                verification_error = (
                    exc
                    if isinstance(exc, ValueError)
                    else ValueError("freeze input parent identity changed during use")
                )
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        if verification_error is not None:
            raise verification_error


@contextmanager
def _exclusive_freeze_lock_at(registration_descriptor: int) -> Iterator[int]:
    if fcntl is None:
        raise RuntimeError("schedule freezing requires POSIX flock support")
    lock_descriptor = os.open(
        _LOCK_NAME,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
        0o600,
        dir_fd=registration_descriptor,
    )
    verification_error: ValueError | None = None
    try:
        opened = os.fstat(lock_descriptor)
        visible = _stat_regular_at(
            registration_descriptor, _LOCK_NAME, label="freeze lock"
        )
        if _directory_identity(opened) != _directory_identity(visible):
            raise ValueError("freeze lock identity changed during open")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        visible = _stat_regular_at(
            registration_descriptor, _LOCK_NAME, label="freeze lock"
        )
        if _directory_identity(opened) != _directory_identity(visible):
            raise ValueError("freeze lock identity changed before acquisition")
        yield lock_descriptor
        visible = _stat_regular_at(
            registration_descriptor, _LOCK_NAME, label="freeze lock"
        )
        if _directory_identity(opened) != _directory_identity(visible):
            raise ValueError("freeze lock identity changed during use")
    except ValueError as exc:
        verification_error = exc
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)
    if verification_error is not None:
        raise verification_error


def _unlink_capability_entry_at(registration_descriptor: int, filename: str) -> None:
    try:
        value = os.stat(
            filename,
            dir_fd=registration_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode):
        raise ValueError("freeze capability entry is not a regular file")
    os.unlink(filename, dir_fd=registration_descriptor)


def _write_capability_file_at(
    registration_descriptor: int, filename: str, content: bytes
) -> None:
    descriptor = os.open(
        filename,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=registration_descriptor,
    )
    with os.fdopen(descriptor, "wb", closefd=True) as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _assert_transaction_capabilities_at(
    registration_descriptor: int, lock_descriptor: int
) -> None:
    if not hasattr(os, "fork"):
        raise RuntimeError("schedule freezing requires a fork-capable POSIX runtime")
    source_name = ".freeze-capability.source"
    link_name = ".freeze-capability.link"
    plan_name = ".freeze-capability.plan"
    temporary_name = ".freeze-capability.plan.tmp"
    names = (source_name, link_name, plan_name, temporary_name)
    old = b"generation: old\n" + b"a" * 4096
    new = b"generation: new\n" + b"b" * 4096
    ready_reader: int | None = None
    ready_writer: int | None = None
    stop_reader: int | None = None
    stop_writer: int | None = None
    child: int | None = None
    lock_probe_child: int | None = None
    try:
        for name in names:
            _unlink_capability_entry_at(registration_descriptor, name)
        os.fsync(registration_descriptor)

        opened_lock = os.fstat(lock_descriptor)
        visible_lock = _stat_regular_at(
            registration_descriptor, _LOCK_NAME, label="freeze lock"
        )
        if _directory_identity(opened_lock) != _directory_identity(visible_lock):
            raise RuntimeError("freeze lock identity changed before capability probe")

        lock_probe_child = os.fork()
        if lock_probe_child == 0:
            try:
                descriptor = os.open(
                    _LOCK_NAME,
                    os.O_RDWR | os.O_NOFOLLOW,
                    dir_fd=registration_descriptor,
                )
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    os._exit(0)
                finally:
                    os.close(descriptor)
            except BaseException:  # noqa: BLE001 - fork child must not unwind.
                os._exit(22)
            os._exit(21)
        lock_probe_status = os.waitpid(lock_probe_child, 0)[1]
        lock_probe_child = None
        if os.waitstatus_to_exitcode(lock_probe_status) != 0:
            raise RuntimeError("filesystem flock does not exclude a second process")

        _write_capability_file_at(registration_descriptor, source_name, old)
        _publish_no_replace_at(registration_descriptor, source_name, link_name)
        source_entry = _stat_regular_at(
            registration_descriptor, source_name, label="freeze capability source"
        )
        linked_entry = _stat_regular_at(
            registration_descriptor, link_name, label="freeze capability link"
        )
        if _directory_identity(source_entry) != _directory_identity(linked_entry):
            raise RuntimeError("filesystem hard link changed the source inode")
        try:
            _publish_no_replace_at(registration_descriptor, source_name, link_name)
        except FileExistsError:
            pass
        else:
            raise RuntimeError("filesystem hard links do not enforce no-replace")
        os.fsync(registration_descriptor)
        _unlink_capability_entry_at(registration_descriptor, link_name)
        _unlink_capability_entry_at(registration_descriptor, source_name)

        _write_capability_file_at(registration_descriptor, plan_name, old)
        ready_reader, ready_writer = os.pipe()
        stop_reader, stop_writer = os.pipe()
        child = os.fork()
        if child == 0:
            assert None not in {
                ready_reader,
                ready_writer,
                stop_reader,
                stop_writer,
            }
            os.close(ready_reader)
            os.close(stop_writer)

            def read_plan() -> bytes:
                descriptor = os.open(
                    plan_name,
                    os.O_RDONLY
                    | os.O_NOFOLLOW
                    | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=registration_descriptor,
                )
                try:
                    chunks: list[bytes] = []
                    while True:
                        chunk = os.read(descriptor, 8192)
                        if not chunk:
                            return b"".join(chunks)
                        chunks.append(chunk)
                finally:
                    os.close(descriptor)

            try:
                if read_plan() != old:
                    os._exit(12)
                os.write(ready_writer, b"R")
                observed_count = 0
                while True:
                    if read_plan() not in {old, new}:
                        os._exit(12)
                    observed_count += 1
                    if select.select([stop_reader], [], [], 0)[0]:
                        break
                os.write(ready_writer, str(observed_count).encode("ascii"))
            except OSError:
                os._exit(11)
            if observed_count < 1:
                os._exit(13)
            os._exit(0)

        os.close(ready_writer)
        ready_writer = None
        os.close(stop_reader)
        stop_reader = None
        if os.read(ready_reader, 1) != b"R":
            _pid, status = os.waitpid(child, 0)
            child = None
            raise RuntimeError(
                "filesystem reader failed before the atomic-replace probe"
            )
        for index in range(200):
            _write_capability_file_at(
                registration_descriptor,
                temporary_name,
                new if index % 2 else old,
            )
            os.replace(
                temporary_name,
                plan_name,
                src_dir_fd=registration_descriptor,
                dst_dir_fd=registration_descriptor,
            )
            os.fsync(registration_descriptor)
            time.sleep(0.001)
        try:
            os.write(stop_writer, b"x")
        except BrokenPipeError:
            pass
        os.close(stop_writer)
        stop_writer = None
        _pid, status = os.waitpid(child, 0)
        child = None
        count_raw = os.read(ready_reader, 64)
        os.close(ready_reader)
        ready_reader = None
        try:
            observed_count = int(count_raw.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            observed_count = 0
        if os.waitstatus_to_exitcode(status) != 0 or observed_count < 10:
            raise RuntimeError(
                "filesystem does not provide atomic plan replacement to readers"
            )
    finally:
        if ready_reader is not None:
            os.close(ready_reader)
        if ready_writer is not None:
            os.close(ready_writer)
        if stop_reader is not None:
            os.close(stop_reader)
        if stop_writer is not None:
            try:
                os.close(stop_writer)
            except OSError:
                pass
        if child is not None:
            try:
                os.waitpid(child, 0)
            except ChildProcessError:
                pass
        if lock_probe_child is not None:
            try:
                os.waitpid(lock_probe_child, 0)
            except ChildProcessError:
                pass
        for name in names:
            _unlink_capability_entry_at(registration_descriptor, name)
        os.fsync(registration_descriptor)


def _parse_yaml_mapping(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 YAML") from exc
    if not isinstance(value, dict):
        raise ValueError(  # noqa: TRY004 - freezer exposes one validation error type.
            f"{label} must contain a YAML mapping"
        )
    return value


def _resolve_include_lexically(registration_path: Path, include: Any) -> Path:
    if (
        not isinstance(include, str)
        or not include.strip()
        or "\x00" in include
        or "\\" in include
        or ntpath.splitdrive(include)[0]
        or include.startswith("/")
    ):
        raise ValueError("plan include must be a safe relative POSIX path")
    components = list(registration_path.parent.parts[1:])
    for component in PurePosixPath(include).parts:
        if component in {"", "."}:
            continue
        if component == "..":
            if not components:
                raise ValueError("plan include escapes the filesystem root")
            components.pop()
            continue
        components.append(component)
    if not components:
        raise ValueError("plan include does not identify a file")
    return Path("/", *components)


def _stat_regular_at(
    parent_descriptor: int, filename: str, *, label: str
) -> os.stat_result:
    value = os.stat(filename, dir_fd=parent_descriptor, follow_symlinks=False)
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode):
        raise ValueError(f"{label} is not a regular non-symlink file")
    return value


def _read_bounded_regular_at(
    parent_descriptor: int,
    filename: str,
    *,
    maximum_bytes: int,
    label: str,
) -> tuple[bytes, tuple[int, int, int, int, int]]:
    path_before = _stat_regular_at(parent_descriptor, filename, label=label)
    descriptor = os.open(
        filename,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
        dir_fd=parent_descriptor,
    )
    try:
        opened = os.fstat(descriptor)
        opened_snapshot = _entry_snapshot(opened)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size > maximum_bytes
            or _entry_snapshot(path_before) != opened_snapshot
        ):
            raise ValueError(f"{label} changed before bounded read")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum_bytes:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        path_after = _stat_regular_at(parent_descriptor, filename, label=label)
        if (
            total > maximum_bytes
            or opened_snapshot != _entry_snapshot(os.fstat(descriptor))
            or opened_snapshot != _entry_snapshot(path_after)
        ):
            raise ValueError(f"{label} changed during bounded read")
        return b"".join(chunks), opened_snapshot
    finally:
        os.close(descriptor)


def _stage_temp_at(
    parent_descriptor: int, temporary_name: str, content: bytes
) -> tuple[int, int, int, int, int]:
    try:
        existing, _snapshot = _read_bounded_regular_at(
            parent_descriptor,
            temporary_name,
            maximum_bytes=max(_MAX_PLAN_BYTES, _MAX_SCHEDULE_BYTES),
            label="freeze temporary file",
        )
    except FileNotFoundError:
        existing = None
    if existing is not None:
        os.unlink(temporary_name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
        try:
            os.stat(
                temporary_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise ValueError("freeze temporary file remained after cleanup")

    descriptor = os.open(
        temporary_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o644,
        dir_fd=parent_descriptor,
    )
    with os.fdopen(descriptor, "wb", closefd=True) as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    staged = _stat_regular_at(
        parent_descriptor, temporary_name, label="freeze temporary file"
    )
    if staged.st_size != len(content):
        raise ValueError("freeze temporary file size changed after staging")
    return _entry_snapshot(staged)


def _remove_staged_temp_at(
    parent_descriptor: int,
    temporary_name: str,
    expected_snapshot: tuple[int, int, int, int, int],
) -> None:
    current = _stat_regular_at(
        parent_descriptor, temporary_name, label="freeze temporary file"
    )
    if _entry_snapshot(current) != expected_snapshot:
        raise ValueError("freeze temporary file identity changed before cleanup")
    os.unlink(temporary_name, dir_fd=parent_descriptor)
    os.fsync(parent_descriptor)


def _verify_exact_at(
    parent_descriptor: int,
    filename: str,
    content: bytes,
    *,
    label: str,
) -> tuple[int, int, int, int, int]:
    observed, snapshot = _read_bounded_regular_at(
        parent_descriptor,
        filename,
        maximum_bytes=max(len(content), 1),
        label=label,
    )
    if not hmac.compare_digest(observed, content):
        raise ValueError(f"{label} has unexpected bytes")
    return snapshot


def _publish_immutable_at(
    parent_descriptor: int,
    filename: str,
    content: bytes,
    *,
    temporary_name: str | None = None,
) -> None:
    if temporary_name is None:
        temporary_name = f".{filename}.freeze.tmp"
    temporary_snapshot = _stage_temp_at(parent_descriptor, temporary_name, content)
    try:
        existing_snapshot = _verify_exact_at(
            parent_descriptor,
            filename,
            content,
            label="content-addressed schedule",
        )
    except FileNotFoundError:
        existing_snapshot = None

    if existing_snapshot is None:
        try:
            _publish_no_replace_at(parent_descriptor, temporary_name, filename)
        except FileExistsError as exc:
            raise ValueError(
                "content-addressed schedule appeared during publication"
            ) from exc
        os.fsync(parent_descriptor)
        existing_snapshot = _verify_exact_at(
            parent_descriptor,
            filename,
            content,
            label="content-addressed schedule",
        )
        if existing_snapshot != temporary_snapshot:
            raise ValueError(
                "content-addressed schedule identity changed during publication"
            )

    _remove_staged_temp_at(parent_descriptor, temporary_name, temporary_snapshot)
    try:
        final_snapshot = _verify_exact_at(
            parent_descriptor,
            filename,
            content,
            label="content-addressed schedule",
        )
    except (OSError, ValueError) as exc:
        raise ValueError(
            "content-addressed schedule identity changed during cleanup"
        ) from exc
    if final_snapshot != existing_snapshot:
        raise ValueError("content-addressed schedule identity changed during cleanup")


def _read_regular_at(
    parent_descriptor: int, filename: str
) -> tuple[bytes, tuple[int, int, int, int, int]]:
    return _read_bounded_regular_at(
        parent_descriptor,
        filename,
        maximum_bytes=_MAX_PLAN_BYTES,
        label="registered plan",
    )


@contextmanager
def _capture_frozen_inputs(
    registration_descriptor: int, registration_path: Path
) -> Iterator[FrozenInputs]:
    registration_raw, registration_snapshot = _read_regular_at(
        registration_descriptor, registration_path.name
    )
    registration_mapping = _parse_yaml_mapping(
        registration_raw, label="registered plan"
    )
    include = registration_mapping.get("include")
    if include is None:
        plan = build_experiment_plan(
            registration_mapping,
            registration_path=registration_path,
        )
        yield FrozenInputs(
            plan=plan,
            registration_descriptor=registration_descriptor,
            registration_name=registration_path.name,
            registration_raw=registration_raw,
            registration_snapshot=registration_snapshot,
            registration_mapping=registration_mapping,
            source_descriptor=registration_descriptor,
            source_name=registration_path.name,
            source_path=registration_path,
            source_raw=registration_raw,
            source_snapshot=registration_snapshot,
            source_mapping=registration_mapping,
        )
        return

    source_path = _resolve_include_lexically(registration_path, include)
    with _open_absolute_file_parent(source_path) as (
        source_descriptor,
        source_name,
    ):
        source_raw, source_snapshot = _read_bounded_regular_at(
            source_descriptor,
            source_name,
            maximum_bytes=_MAX_PLAN_BYTES,
            label="authoritative source configuration",
        )
        source_mapping = _parse_yaml_mapping(
            source_raw, label="authoritative source configuration"
        )
        plan = build_experiment_plan(
            registration_mapping,
            registration_path=registration_path,
            source_mapping=source_mapping,
            source_path=source_path,
        )
        yield FrozenInputs(
            plan=plan,
            registration_descriptor=registration_descriptor,
            registration_name=registration_path.name,
            registration_raw=registration_raw,
            registration_snapshot=registration_snapshot,
            registration_mapping=registration_mapping,
            source_descriptor=source_descriptor,
            source_name=source_name,
            source_path=source_path,
            source_raw=source_raw,
            source_snapshot=source_snapshot,
            source_mapping=source_mapping,
        )


def _assert_inputs_unchanged(inputs: FrozenInputs) -> None:
    current_registration, registration_snapshot = _read_regular_at(
        inputs.registration_descriptor, inputs.registration_name
    )
    if registration_snapshot != inputs.registration_snapshot or not hmac.compare_digest(
        current_registration, inputs.registration_raw
    ):
        raise ValueError("registered plan changed during schedule freezing")
    if inputs.source_descriptor == inputs.registration_descriptor and (
        inputs.source_name == inputs.registration_name
    ):
        return
    current_source, source_snapshot = _read_bounded_regular_at(
        inputs.source_descriptor,
        inputs.source_name,
        maximum_bytes=_MAX_PLAN_BYTES,
        label="authoritative source configuration",
    )
    if source_snapshot != inputs.source_snapshot or not hmac.compare_digest(
        current_source, inputs.source_raw
    ):
        raise ValueError("source configuration changed during schedule freezing")


def _assert_source_unchanged(inputs: FrozenInputs) -> None:
    if inputs.source_descriptor == inputs.registration_descriptor and (
        inputs.source_name == inputs.registration_name
    ):
        return
    current_source, source_snapshot = _read_bounded_regular_at(
        inputs.source_descriptor,
        inputs.source_name,
        maximum_bytes=_MAX_PLAN_BYTES,
        label="authoritative source configuration",
    )
    if source_snapshot != inputs.source_snapshot or not hmac.compare_digest(
        current_source, inputs.source_raw
    ):
        raise ValueError("source configuration changed during schedule freezing")


def _updated_registration_bytes(
    original: bytes, schedule_path: str, digest: str
) -> bytes:
    try:
        text = original.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("registered plan is not UTF-8") from exc
    updated, path_replacements = _SCHEDULE_PATH_LINE.subn(
        f"schedule_path: {schedule_path}", text
    )
    updated, digest_replacements = _DIGEST_LINE.subn(
        f'schedule_sha256: "{digest}"', updated
    )
    if path_replacements != 1 or digest_replacements != 1:
        raise ValueError("registered plan must contain one schedule_sha256 line")
    return updated.encode("utf-8")


def _replace_plan_at(
    parent_descriptor: int,
    filename: str,
    content: bytes,
    *,
    expected_snapshot: tuple[int, int, int, int, int],
    precommit_check: Callable[[], None] | None = None,
) -> tuple[int, int, int, int, int]:
    temporary_name = f".{filename}.freeze.tmp"
    temporary_snapshot = _stage_temp_at(parent_descriptor, temporary_name, content)
    replaced = False
    try:
        if precommit_check is not None:
            precommit_check()
        current = _stat_regular_at(parent_descriptor, filename, label="registered plan")
        if _entry_snapshot(current) != expected_snapshot:
            raise ValueError("registered plan identity changed before commit")
        os.replace(
            temporary_name,
            filename,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        replaced = True
        os.fsync(parent_descriptor)
        published_snapshot = _verify_exact_at(
            parent_descriptor,
            filename,
            content,
            label="registered plan",
        )
        if published_snapshot != temporary_snapshot:
            raise ValueError("registered plan identity changed during commit")
        return published_snapshot
    finally:
        if not replaced:
            try:
                _remove_staged_temp_at(
                    parent_descriptor, temporary_name, temporary_snapshot
                )
            except FileNotFoundError:
                pass


def _content_addressed_schedule_name(plan: ExperimentPlan, digest: str) -> str:
    if plan.registration_path is None or plan.schedule_path is None:
        raise ValueError("registered plan is missing its reference path")
    stem = plan.registration_path.stem
    if re.fullmatch(r"[a-z0-9][a-z0-9-]*", stem) is None:
        raise ValueError("registered plan stem is unsafe for schedule publication")
    parent = PurePosixPath(plan.schedule_path).parent
    filename = f"{stem}.{digest}.schedule.json"
    if str(parent) == ".":
        return filename
    return f"{parent.as_posix()}/{filename}"


def _assert_registration_transition(
    original: bytes,
    plan: ExperimentPlan,
    target_path: str,
    target_digest: str,
) -> None:
    try:
        mapping = yaml.safe_load(original.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("registered plan cannot be decoded for freezing") from exc
    if not isinstance(mapping, dict):
        raise ValueError(  # noqa: TRY004 - freezer exposes one validation error type.
            "registered plan must be a YAML mapping"
        )
    current = (mapping.get("schedule_path"), mapping.get("schedule_sha256"))
    expected = (plan.schedule_path, plan.schedule_sha256)
    target = (target_path, target_digest)
    if current not in {expected, target}:
        raise ValueError("registered plan changed since schedule generation")


def _freeze_captured_inputs(inputs: FrozenInputs) -> tuple[Path, str]:
    plan = inputs.plan
    content = schedule_bytes(plan)
    digest = hashlib.sha256(content).hexdigest()
    target_path = _content_addressed_schedule_name(plan, digest)
    target_name = PurePosixPath(target_path).name
    with open_registered_schedule_parent(plan) as handles:
        if _directory_identity(
            os.fstat(handles.registration_descriptor)
        ) != _directory_identity(os.fstat(inputs.registration_descriptor)):
            raise ValueError("registered plan directory changed before freezing")
        if handles.plan_name != inputs.registration_name:
            raise ValueError("registered plan filename changed before freezing")
        _assert_inputs_unchanged(inputs)
        _assert_registration_transition(
            inputs.registration_raw, plan, target_path, digest
        )
        _publish_immutable_at(
            handles.schedule_parent_descriptor,
            target_name,
            content,
            temporary_name=f".{plan.registration_path.stem}.schedule.publish.tmp",
        )
        _assert_inputs_unchanged(inputs)
        updated_plan_raw = _updated_registration_bytes(
            inputs.registration_raw, target_path, digest
        )
        updated_mapping = _parse_yaml_mapping(
            updated_plan_raw, label="updated registered plan"
        )
        old_semantics = {
            key: value
            for key, value in inputs.registration_mapping.items()
            if key not in {"schedule_path", "schedule_sha256"}
        }
        new_semantics = {
            key: value
            for key, value in updated_mapping.items()
            if key not in {"schedule_path", "schedule_sha256"}
        }
        if old_semantics != new_semantics:
            raise ValueError("freeze changed non-registration plan semantics")
        updated_plan = build_experiment_plan(
            updated_mapping,
            registration_path=plan.registration_path,
            source_mapping=(
                inputs.source_mapping if "include" in updated_mapping else None
            ),
            source_path=(inputs.source_path if "include" in updated_mapping else None),
        )
        if not hmac.compare_digest(schedule_bytes(updated_plan), content):
            raise ValueError("content-addressed registration introduced a hash cycle")
        _assert_inputs_unchanged(inputs)
        committed_snapshot = inputs.registration_snapshot

        def assert_commit_inputs() -> None:
            _assert_inputs_unchanged(inputs)
            _verify_exact_at(
                handles.schedule_parent_descriptor,
                target_name,
                content,
                label="content-addressed schedule",
            )

        if not hmac.compare_digest(updated_plan_raw, inputs.registration_raw):
            committed_snapshot = _replace_plan_at(
                handles.registration_descriptor,
                handles.plan_name,
                updated_plan_raw,
                expected_snapshot=inputs.registration_snapshot,
                precommit_check=assert_commit_inputs,
            )
        final_plan_snapshot = _verify_exact_at(
            handles.registration_descriptor,
            handles.plan_name,
            updated_plan_raw,
            label="registered plan",
        )
        if final_plan_snapshot != committed_snapshot:
            raise ValueError("registered plan identity changed after commit")
        _verify_exact_at(
            handles.schedule_parent_descriptor,
            target_name,
            content,
            label="content-addressed schedule",
        )
        _assert_source_unchanged(inputs)
        load_registered_schedule(updated_plan)
        return plan.registration_path.parent.joinpath(
            *PurePosixPath(target_path).parts
        ), digest


def _atomic_write_registered(plan: ExperimentPlan, content: bytes) -> Path:
    with open_registered_schedule_parent(plan) as handles:
        with _exclusive_directory_lock(handles.registration_descriptor):
            _publish_immutable_at(
                handles.schedule_parent_descriptor, handles.schedule_name, content
            )
        return handles.schedule_path


def _freeze_registered_schedule(
    plan: ExperimentPlan, content: bytes
) -> tuple[Path, str]:
    if not hmac.compare_digest(content, schedule_bytes(plan)):
        raise ValueError("schedule bytes do not match the supplied plan")
    digest = hashlib.sha256(content).hexdigest()
    target_path = _content_addressed_schedule_name(plan, digest)
    target_name = PurePosixPath(target_path).name
    with (
        open_registered_schedule_parent(plan) as handles,
        _exclusive_directory_lock(handles.registration_descriptor),
    ):
        original_plan, plan_snapshot = _read_regular_at(
            handles.registration_descriptor, handles.plan_name
        )
        _assert_registration_transition(original_plan, plan, target_path, digest)
        _publish_immutable_at(
            handles.schedule_parent_descriptor,
            target_name,
            content,
            temporary_name=f".{plan.registration_path.stem}.schedule.publish.tmp",
        )
        current_plan, current_snapshot = _read_regular_at(
            handles.registration_descriptor, handles.plan_name
        )
        if current_snapshot != plan_snapshot or not hmac.compare_digest(
            current_plan, original_plan
        ):
            raise ValueError("registered plan identity changed before commit")
        updated_plan = _updated_registration_bytes(original_plan, target_path, digest)
        committed_snapshot = plan_snapshot

        def assert_commit_inputs() -> None:
            latest_plan, latest_snapshot = _read_regular_at(
                handles.registration_descriptor, handles.plan_name
            )
            if latest_snapshot != plan_snapshot or not hmac.compare_digest(
                latest_plan, original_plan
            ):
                raise ValueError("registered plan identity changed before commit")
            _verify_exact_at(
                handles.schedule_parent_descriptor,
                target_name,
                content,
                label="content-addressed schedule",
            )

        if not hmac.compare_digest(updated_plan, original_plan):
            committed_snapshot = _replace_plan_at(
                handles.registration_descriptor,
                handles.plan_name,
                updated_plan,
                expected_snapshot=plan_snapshot,
                precommit_check=assert_commit_inputs,
            )
        final_plan_snapshot = _verify_exact_at(
            handles.registration_descriptor,
            handles.plan_name,
            updated_plan,
            label="registered plan",
        )
        if final_plan_snapshot != committed_snapshot:
            raise ValueError("registered plan identity changed after commit")
        _verify_exact_at(
            handles.schedule_parent_descriptor,
            target_name,
            content,
            label="content-addressed schedule",
        )
        assert plan.registration_path is not None
        return plan.registration_path.parent.joinpath(
            *PurePosixPath(target_path).parts
        ), digest


def freeze_all(*, check: bool) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    plan_paths = [
        ROOT / "experiments" / "plans" / f"{name}.yaml" for name in PLAN_NAMES
    ]
    if check:
        first_plan_path = plan_paths[0]
        with _open_absolute_file_parent(first_plan_path) as (
            registration_descriptor,
            _first_plan_name,
        ):
            for name, plan_path in zip(PLAN_NAMES, plan_paths, strict=True):
                if plan_path.parent != first_plan_path.parent:
                    raise ValueError(
                        "all checked plans must share one registration directory"
                    )
                with _capture_frozen_inputs(
                    registration_descriptor, plan_path
                ) as inputs:
                    plan = inputs.plan
                    expected = schedule_bytes(plan)
                    digest = hashlib.sha256(expected).hexdigest()
                    if plan.schedule_sha256 != digest:
                        raise ValueError(
                            f"{plan_path} does not register the final byte digest"
                        )
                    if plan.schedule_path != _content_addressed_schedule_name(
                        plan, digest
                    ):
                        raise ValueError(
                            f"{plan_path} does not register a "
                            "content-addressed schedule"
                        )
                    load_registered_schedule(plan)
                    _assert_inputs_unchanged(inputs)
                results.append((name, digest))
        return results

    first_plan_path = plan_paths[0]
    with (
        _open_absolute_file_parent(first_plan_path) as (
            registration_descriptor,
            _first_plan_name,
        ),
        _exclusive_freeze_lock_at(registration_descriptor) as lock_descriptor,
    ):
        _assert_transaction_capabilities_at(registration_descriptor, lock_descriptor)
        for name, plan_path in zip(PLAN_NAMES, plan_paths, strict=True):
            if plan_path.parent != first_plan_path.parent:
                raise ValueError(
                    "all frozen plans must share one registration directory"
                )
            with _capture_frozen_inputs(registration_descriptor, plan_path) as inputs:
                _destination, digest = _freeze_captured_inputs(inputs)
            results.append((name, digest))
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify schedules and digests without writing files",
    )
    args = parser.parse_args()
    action = "verified" if args.check else "frozen"
    for name, digest in freeze_all(check=args.check):
        print(f"{action} {name}: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
