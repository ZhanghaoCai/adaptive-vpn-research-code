"""Generation and strict loading of registered frozen schedules."""

from __future__ import annotations

import hashlib
import hmac
import json
import ntpath
import os
import random
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from uuid import UUID, uuid5

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
)

from .config import CampaignStage, ExperimentPlan, StrategyName
from .provenance import canonical_sha256

_SCHEDULE_NAMESPACE = UUID("7f20fe6e-5fb3-4f0f-a758-37ae1b0c7d8a")
_SCHEDULE_SOURCE = "config/system_config.yaml"
MAX_SCHEDULE_BYTES = 8 * 1024 * 1024


class ScheduleEntry(BaseModel):
    """One immutable registered experimental cell."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cell_id: UUID
    ordinal: int = Field(strict=True, ge=1)
    block: int = Field(strict=True, ge=1)
    scenario_id: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    traffic_profile_id: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    strategy: StrategyName
    _schedule_seed: int | None = PrivateAttr(default=None)
    _config_sha256: str | None = PrivateAttr(default=None)

    @field_validator("cell_id", mode="before")
    @classmethod
    def cell_id_is_canonical_uuid5(cls, value: Any) -> UUID:
        try:
            parsed = value if isinstance(value, UUID) else UUID(str(value))
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("cell_id must be a canonical UUIDv5") from exc
        if parsed.version != 5 or (isinstance(value, str) and str(parsed) != value):
            raise ValueError("cell_id must be a canonical UUIDv5")
        return parsed

    def attach_registration_identity(
        self, *, schedule_seed: int, config_sha256: str
    ) -> None:
        """Carry Commit-1 compatibility context without serialising v1 fields."""

        self._schedule_seed = schedule_seed
        self._config_sha256 = config_sha256

    @property
    def run_id(self) -> UUID:
        """Temporary Python compatibility alias; never part of schedule v2 JSON."""

        return self.cell_id

    @property
    def schedule_seed(self) -> int:
        if self._schedule_seed is None:
            raise RuntimeError("schedule entry is missing registration seed context")
        return self._schedule_seed

    @property
    def config_sha256(self) -> str:
        if self._config_sha256 is None:
            raise RuntimeError("schedule entry is missing registration hash context")
        return self._config_sha256


class ScheduleDocument(BaseModel):
    """Strict tool-independent representation of schedule schema 2.0."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["2.0.0"]
    campaign_stage: CampaignStage
    dataset_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    design: Literal["randomised-complete-block"]
    schedule_seed: int = Field(strict=True, ge=0, le=2**63 - 1)
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_cells: int = Field(strict=True, ge=1)
    source: Literal["config/system_config.yaml"]
    cells: tuple[ScheduleEntry, ...]


def experiment_config_sha256(plan: ExperimentPlan) -> str:
    """Hash validated scientific/runtime parameters without registration identity."""

    scientific = plan.model_dump(
        mode="json",
        exclude={"campaign_stage", "schedule_path", "schedule_sha256"},
    )
    if plan.max_attempts_per_cell is None:
        scientific.pop("max_attempts_per_cell", None)
    return canonical_sha256(scientific)


def _registered_values(plan: ExperimentPlan) -> tuple[CampaignStage, str, str, int]:
    values = (
        plan.campaign_stage,
        plan.schedule_path,
        plan.schedule_sha256,
        plan.max_attempts_per_cell,
    )
    if any(value is None for value in values) or plan.registration_path is None:
        raise ValueError("experiment plan is not a registered schedule reference")
    stage, path, digest, attempts = values
    return stage, path, digest, attempts  # type: ignore[return-value]


def generate_schedule(plan: ExperimentPlan) -> list[ScheduleEntry]:
    """Generate the deterministic population used only for freezing and validation."""

    rng = random.Random(plan.schedule_seed)
    config_hash = experiment_config_sha256(plan)
    entries: list[ScheduleEntry] = []
    ordinal = 1
    for block in range(1, plan.blocks + 1):
        for scenario in plan.scenarios:
            for traffic in plan.traffic_profiles:
                strategies = list(plan.strategies)
                rng.shuffle(strategies)
                for strategy in strategies:
                    identity = (
                        f"{plan.dataset_id}|{config_hash}|{plan.schedule_seed}|{block}|"
                        f"{scenario.scenario_id}|{traffic.profile_id}|{strategy}"
                    )
                    entry = ScheduleEntry(
                        cell_id=uuid5(_SCHEDULE_NAMESPACE, identity),
                        ordinal=ordinal,
                        block=block,
                        scenario_id=scenario.scenario_id,
                        traffic_profile_id=traffic.profile_id,
                        strategy=strategy,
                    )
                    entry.attach_registration_identity(
                        schedule_seed=plan.schedule_seed,
                        config_sha256=config_hash,
                    )
                    entries.append(entry)
                    ordinal += 1
    if len(entries) != plan.expected_runs:
        raise RuntimeError("generated schedule does not match the validated design")
    return entries


def schedule_document(plan: ExperimentPlan) -> ScheduleDocument:
    """Build the canonical schedule document for offline freezing."""

    stage, _path, _digest, _attempts = _registered_values(plan)
    entries = generate_schedule(plan)
    return ScheduleDocument(
        schema_version="2.0.0",
        campaign_stage=stage,
        dataset_id=plan.dataset_id,
        design="randomised-complete-block",
        schedule_seed=plan.schedule_seed,
        config_sha256=experiment_config_sha256(plan),
        expected_cells=plan.expected_runs,
        source=_SCHEDULE_SOURCE,
        cells=tuple(entries),
    )


def schedule_bytes(plan: ExperimentPlan) -> bytes:
    """Serialise a plan deterministically for hashing and atomic publication."""

    document = schedule_document(plan).model_dump(mode="json")
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _validate_schedule_path(plan: ExperimentPlan, schedule_path: str) -> Path:
    if (
        not schedule_path
        or "\x00" in schedule_path
        or "\\" in schedule_path
        or schedule_path.startswith("/")
        or ntpath.splitdrive(schedule_path)[0]
    ):
        raise ValueError("registered schedule path must be a safe relative POSIX path")
    components = schedule_path.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise ValueError("registered schedule path contains an unsafe component")

    assert plan.registration_path is not None
    base = plan.registration_path.parent
    candidate = base.joinpath(*components)
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValueError(
            "registered schedule path escapes its reference directory"
        ) from exc
    return candidate


def registered_schedule_path(plan: ExperimentPlan) -> Path:
    """Resolve a registered destination through the loader's lexical boundary."""

    _stage, relative_path, _digest, _attempts = _registered_values(plan)
    return _validate_schedule_path(plan, relative_path)


@dataclass(frozen=True, slots=True)
class RegisteredScheduleHandles:
    registration_descriptor: int
    schedule_parent_descriptor: int
    schedule_name: str
    plan_name: str
    schedule_path: Path


@contextmanager
def open_registered_schedule_parent(
    plan: ExperimentPlan,
) -> Iterator[RegisteredScheduleHandles]:
    """Hold every registered parent directory open without following symlinks."""

    _stage, relative_path, _digest, _attempts = _registered_values(plan)
    candidate = _validate_schedule_path(plan, relative_path)
    if (
        os.name != "posix"
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
    ):
        raise ValueError("platform cannot enforce registered schedule path isolation")

    assert plan.registration_path is not None
    components = relative_path.split("/")
    base = plan.registration_path.parent
    if base.anchor != "/":
        raise ValueError("registered schedule base must be an absolute POSIX path")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors: list[int] = []
    parent_links: list[tuple[int, str, int]] = []
    body_completed = False
    verification_error: ValueError | None = None
    try:
        try:
            current_descriptor = os.open(base.anchor, directory_flags)
        except OSError as exc:
            raise ValueError(
                f"cannot open registered schedule anchor safely: {exc}"
            ) from exc
        descriptors.append(current_descriptor)

        registration_descriptor: int | None = None
        directory_components = [*base.parts[1:], *components[:-1]]
        base_component_count = len(base.parts[1:])
        if base_component_count == 0:
            registration_descriptor = current_descriptor
        for index, component in enumerate(directory_components, 1):
            try:
                before = os.stat(
                    component, dir_fd=current_descriptor, follow_symlinks=False
                )
            except OSError as exc:
                raise ValueError(
                    f"cannot inspect registered schedule parent: {exc}"
                ) from exc
            if stat.S_ISLNK(before.st_mode):
                raise ValueError("registered schedule path contains a symlink")
            if not stat.S_ISDIR(before.st_mode):
                raise ValueError("registered schedule parent is not a directory")
            try:
                child_descriptor = os.open(
                    component, directory_flags, dir_fd=current_descriptor
                )
            except OSError as exc:
                raise ValueError(
                    f"cannot open registered schedule parent safely: {exc}"
                ) from exc
            descriptors.append(child_descriptor)
            if _identity(before) != _identity(os.fstat(child_descriptor)):
                raise ValueError(
                    "registered schedule parent identity changed during open"
                )
            parent_links.append((current_descriptor, component, child_descriptor))
            current_descriptor = child_descriptor
            if index == base_component_count:
                registration_descriptor = current_descriptor

        if registration_descriptor is None:
            raise ValueError("registered schedule base descriptor was not established")
        yield RegisteredScheduleHandles(
            registration_descriptor=registration_descriptor,
            schedule_parent_descriptor=current_descriptor,
            schedule_name=components[-1],
            plan_name=plan.registration_path.name,
            schedule_path=candidate,
        )
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
                    if stat.S_ISLNK(current.st_mode) or _identity(current) != _identity(
                        os.fstat(child_descriptor)
                    ):
                        raise ValueError(
                            "registered schedule parent identity changed during use"
                        )
            except (OSError, ValueError) as exc:
                verification_error = (
                    exc
                    if isinstance(exc, ValueError)
                    else ValueError(
                        "registered schedule parent identity changed during use"
                    )
                )
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        if verification_error is not None:
            raise verification_error


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _snapshot(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
    )


def _read_registered_bytes(plan: ExperimentPlan, schedule_path: str) -> bytes:
    if plan.schedule_path != schedule_path:
        raise ValueError("registered schedule path changed during load")
    with open_registered_schedule_parent(plan) as handles:
        parent_descriptor = handles.schedule_parent_descriptor
        filename = handles.schedule_name
        try:
            before = os.stat(filename, dir_fd=parent_descriptor, follow_symlinks=False)
        except OSError as exc:
            raise ValueError(f"cannot inspect registered schedule file: {exc}") from exc
        if stat.S_ISLNK(before.st_mode):
            raise ValueError("registered schedule path contains a symlink")
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("registered schedule must be a regular file")

        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | os.O_NOFOLLOW
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            descriptor = os.open(filename, flags, dir_fd=parent_descriptor)
        except OSError as exc:
            raise ValueError(f"cannot open registered schedule safely: {exc}") from exc

        try:
            opened_stat = os.fstat(descriptor)
            if not stat.S_ISREG(opened_stat.st_mode):
                raise ValueError("registered schedule must be a regular file")
            if _identity(before) != _identity(opened_stat):
                raise ValueError(
                    "registered schedule file identity changed before open"
                )

            chunks: list[bytes] = []
            total = 0
            while total <= MAX_SCHEDULE_BYTES:
                chunk = os.read(
                    descriptor,
                    min(64 * 1024, MAX_SCHEDULE_BYTES + 1 - total),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            if total > MAX_SCHEDULE_BYTES:
                raise ValueError("registered schedule exceeds the 8 MiB size limit")

            after_read = os.fstat(descriptor)
            try:
                after_path = os.stat(
                    filename,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise ValueError(
                    "registered schedule file identity changed after open"
                ) from exc
            if stat.S_ISLNK(after_path.st_mode):
                raise ValueError("registered schedule path became a symlink")
            if not (
                _snapshot(before)
                == _snapshot(opened_stat)
                == _snapshot(after_read)
                == _snapshot(after_path)
            ):
                raise ValueError(
                    "registered schedule metadata or identity changed during read"
                )
            return b"".join(chunks)
        finally:
            os.close(descriptor)


def load_registered_schedule(plan: ExperimentPlan) -> list[ScheduleEntry]:
    """Load and independently verify the exact raw bytes registered by a plan."""

    stage, relative_path, registered_digest, _attempts = _registered_values(plan)
    raw = _read_registered_bytes(plan, relative_path)
    observed_digest = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(observed_digest, registered_digest):
        raise ValueError("registered schedule raw-byte digest does not match the plan")

    try:
        decoded = raw.decode("utf-8")
        value = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("registered schedule is not valid UTF-8 JSON") from exc
    try:
        document = ScheduleDocument.model_validate(value)
    except ValidationError as exc:
        raise ValueError(f"invalid schedule document: {exc}") from exc

    expected_headers = {
        "schema_version": "2.0.0",
        "campaign_stage": stage,
        "dataset_id": plan.dataset_id,
        "design": "randomised-complete-block",
        "schedule_seed": plan.schedule_seed,
        "config_sha256": experiment_config_sha256(plan),
        "expected_cells": plan.expected_runs,
        "source": _SCHEDULE_SOURCE,
    }
    observed = document.model_dump(mode="json")
    for field, expected in expected_headers.items():
        if observed[field] != expected:
            raise ValueError(f"registered schedule header {field} does not match plan")

    if document.expected_cells != len(document.cells):
        raise ValueError("registered schedule cell count does not match expected_cells")
    if len(document.cells) != plan.expected_runs:
        raise ValueError("registered schedule cell count does not match the plan")
    ordinals = [entry.ordinal for entry in document.cells]
    if ordinals != list(range(1, document.expected_cells + 1)):
        raise ValueError(
            "registered schedule ordinals must be contiguous in document order"
        )

    cell_ids = [entry.cell_id for entry in document.cells]
    if len(cell_ids) != len(set(cell_ids)):
        raise ValueError("registered schedule contains a duplicate cell_id")
    cell_tuples = [
        (
            entry.block,
            entry.scenario_id,
            entry.traffic_profile_id,
            entry.strategy,
        )
        for entry in document.cells
    ]
    if len(cell_tuples) != len(set(cell_tuples)):
        raise ValueError("registered schedule contains a duplicate cell tuple")

    expected_document = schedule_document(plan).model_dump(mode="json")
    if observed != expected_document:
        raise ValueError(
            "registered population differs from the deterministic schedule"
        )

    entries = list(document.cells)
    config_hash = experiment_config_sha256(plan)
    for entry in entries:
        entry.attach_registration_identity(
            schedule_seed=plan.schedule_seed,
            config_sha256=config_hash,
        )
    return entries
