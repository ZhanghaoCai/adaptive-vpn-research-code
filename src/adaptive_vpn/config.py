"""Validated experiment configuration loaded from one authoritative YAML source."""

from __future__ import annotations

import ntpath
import os
import stat
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

StrategyName = Literal["static", "threshold", "adaptive"]
CampaignStage = Literal["smoke", "pilot", "main"]
MAX_PLAN_BYTES = 1_048_576


class StrictModel(BaseModel):
    """Base model that rejects silent configuration drift."""

    model_config = ConfigDict(extra="forbid")


class PathConfig(StrictModel):
    path_id: str = Field(min_length=1, pattern=r"^path-[a-z0-9]+$")
    path_index: int = Field(ge=0, le=255)


class Impairment(StrictModel):
    """Registered end-to-end target applied symmetrically by the lab backend."""

    delay_ms: float = Field(ge=0, le=2_000)
    jitter_ms: float = Field(ge=0, le=1_000)
    loss_pct: float = Field(ge=0, le=100)
    loss_correlation_pct: float = Field(ge=0, le=100)
    rate_mbit: float | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def correlation_requires_loss(self) -> Impairment:
        if self.loss_correlation_pct > 0 and self.loss_pct == 0:
            raise ValueError("loss correlation requires a nonzero loss percentage")
        return self


class TrafficProfile(StrictModel):
    profile_id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9-]*$")
    packet_rate_hz: float = Field(gt=0, le=1_000)
    datagram_size: int = Field(ge=64, le=65_507)
    response_timeout_ms: float = Field(gt=0, le=10_000)


class ScenarioPhase(StrictModel):
    phase_id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9-]*$")
    duration_s: float = Field(gt=0, le=3_600)
    paths: dict[str, Impairment]


class Scenario(StrictModel):
    scenario_id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9-]*$")
    phases: list[ScenarioPhase] = Field(min_length=1)

    @model_validator(mode="after")
    def phase_ids_are_unique(self) -> Scenario:
        phase_ids = [phase.phase_id for phase in self.phases]
        if len(phase_ids) != len(set(phase_ids)):
            raise ValueError("phase IDs must be unique within each scenario")
        return self


class ScoringConfig(StrictModel):
    latency: float = Field(default=0.4, ge=0, le=1)
    jitter: float = Field(default=0.3, ge=0, le=1)
    loss: float = Field(default=0.3, ge=0, le=1)
    latency_threshold_ms: float = Field(default=300.0, gt=0)
    jitter_threshold_ms: float = Field(default=80.0, gt=0)
    loss_threshold_pct: float = Field(default=5.0, gt=0, le=100)

    @model_validator(mode="after")
    def weights_sum_to_one(self) -> ScoringConfig:
        if abs(self.latency + self.jitter + self.loss - 1.0) > 1e-9:
            raise ValueError("scoring weights must sum to 1")
        return self


class SwitchingConfig(StrictModel):
    min_score_threshold: float = Field(default=0.6, ge=0, le=1)
    score_improvement_margin: float = Field(default=0.10, ge=0, le=1)
    min_switch_interval_s: float = Field(default=0.5, ge=0)
    sustained_degradation_s: float = Field(default=1.0, ge=0)
    max_switches_per_hour: int = Field(default=60, ge=1)
    threshold_rtt_ms: float = Field(default=150.0, gt=0)
    threshold_loss_pct: float = Field(default=2.0, gt=0, le=100)
    threshold_hold_s: float = Field(default=1.0, ge=0)


class MeasurementConfig(StrictModel):
    window_duration_s: float = Field(default=1.0, gt=0, le=60)
    duplicate_drain_ms: float = Field(default=50.0, gt=0, le=1_000)
    monitor_packet_rate_hz: float = Field(default=20.0, gt=0, le=1_000)
    monitor_packets_per_window: int = Field(default=10, ge=2, le=10_000)
    monitor_datagram_size: int = Field(default=128, ge=64, le=65_507)
    echo_port: int = Field(default=39_993, ge=1, le=65_535)

    @model_validator(mode="after")
    def monitor_burst_fits_window(self) -> MeasurementConfig:
        send_span = (self.monitor_packets_per_window - 1) / self.monitor_packet_rate_hz
        if send_span >= self.window_duration_s:
            raise ValueError(
                "monitor packet burst must fit within one measurement window"
            )
        return self


class ExperimentPlan(StrictModel):
    """Complete, balanced experimental design after reference expansion."""

    schema_version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    dataset_id: str = Field(min_length=1, pattern=r"^[a-z0-9][a-z0-9-]*$")
    namespace_prefix: str = Field(pattern=r"^avpn(?:-[a-z0-9]+)*$")
    paths: list[PathConfig] = Field(min_length=3, max_length=3)
    strategies: list[StrategyName] = Field(min_length=3, max_length=3)
    traffic_profiles: list[TrafficProfile] = Field(min_length=1)
    scenarios: list[Scenario] = Field(min_length=1)
    blocks: int = Field(ge=1)
    schedule_seed: int = Field(ge=0, le=2**63 - 1)
    campaign_stage: CampaignStage | None = None
    schedule_path: str | None = Field(default=None, min_length=1)
    schedule_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    max_attempts_per_cell: int | None = Field(default=None, strict=True, ge=1)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    switching: SwitchingConfig = Field(default_factory=SwitchingConfig)
    measurement: MeasurementConfig = Field(default_factory=MeasurementConfig)
    _source_path: Path | None = PrivateAttr(default=None)
    _registration_path: Path | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def validate_balanced_design(self) -> ExperimentPlan:
        registration = (
            self.campaign_stage,
            self.schedule_path,
            self.schedule_sha256,
            self.max_attempts_per_cell,
        )
        if any(value is not None for value in registration) and not all(
            value is not None for value in registration
        ):
            raise ValueError(
                "registration fields campaign_stage, schedule_path, "
                "schedule_sha256, and max_attempts_per_cell must be provided together"
            )
        path_ids = [path.path_id for path in self.paths]
        path_indexes = [path.path_index for path in self.paths]
        if len(path_ids) != len(set(path_ids)) or len(path_indexes) != len(
            set(path_indexes)
        ):
            raise ValueError("path IDs and indexes must each be unique")
        if set(self.strategies) != {"static", "threshold", "adaptive"}:
            raise ValueError(
                "strategies must contain static, threshold, and adaptive exactly once"
            )
        profile_ids = [profile.profile_id for profile in self.traffic_profiles]
        scenario_ids = [scenario.scenario_id for scenario in self.scenarios]
        if len(profile_ids) != len(set(profile_ids)):
            raise ValueError("traffic profile IDs must be unique")
        if len(scenario_ids) != len(set(scenario_ids)):
            raise ValueError("scenario IDs must be unique")
        expected_paths = set(path_ids)
        for scenario in self.scenarios:
            for phase in scenario.phases:
                if set(phase.paths) != expected_paths:
                    raise ValueError(
                        "every phase must define every configured path exactly once"
                    )
        return self

    @property
    def expected_runs(self) -> int:
        return (
            self.blocks
            * len(self.scenarios)
            * len(self.traffic_profiles)
            * len(self.strategies)
        )

    @property
    def source_path(self) -> Path | None:
        return self._source_path

    @property
    def registration_path(self) -> Path | None:
        return self._registration_path


_REFERENCE_KEYS = {
    "include",
    "dataset_id",
    "blocks",
    "schedule_seed",
    "campaign_stage",
    "schedule_path",
    "schedule_sha256",
    "max_attempts_per_cell",
    "scenario_ids",
    "traffic_profile_ids",
}


def _stat_identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _stat_snapshot(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
    )


def _read_open_regular_file(
    descriptor: int,
    *,
    before: os.stat_result,
    stat_path: Callable[[], os.stat_result],
    max_bytes: int,
    label: str,
) -> bytes:
    opened = os.fstat(descriptor)
    if not stat.S_ISREG(opened.st_mode):
        raise ValueError(f"{label} must be a regular file")
    if _stat_snapshot(before) != _stat_snapshot(opened):
        raise ValueError(f"{label} identity changed before open")

    chunks: list[bytes] = []
    total = 0
    while total <= max_bytes:
        chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes} bytes")

    after_read = os.fstat(descriptor)
    after_path = stat_path()
    if stat.S_ISLNK(after_path.st_mode):
        raise ValueError(f"{label} path became a symlink")
    if not (
        _stat_snapshot(before)
        == _stat_snapshot(opened)
        == _stat_snapshot(after_read)
        == _stat_snapshot(after_path)
    ):
        raise ValueError(f"{label} metadata or identity changed during read")
    return b"".join(chunks)


def _read_bounded_regular_bytes_portable(
    path: Path, *, max_bytes: int, label: str
) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise ValueError(f"cannot inspect {label} {path}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode):
        raise ValueError(f"{label} path contains a symlink")
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{label} must be a regular file")
    if before.st_size > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes} bytes")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"cannot open {label} {path} safely: {exc}") from exc
    try:
        return _read_open_regular_file(
            descriptor,
            before=before,
            stat_path=lambda: os.lstat(path),
            max_bytes=max_bytes,
            label=label,
        )
    except OSError as exc:
        raise ValueError(f"cannot read {label} {path} safely: {exc}") from exc
    finally:
        os.close(descriptor)


def read_bounded_regular_bytes(
    path: str | Path, *, max_bytes: int, label: str
) -> bytes:
    """Capture one regular file without following links or blocking on a FIFO."""

    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    if not isinstance(label, str) or not label.strip():
        raise ValueError("label must be nonblank text")
    requested = Path(os.path.abspath(path))
    if (
        os.name != "posix"
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
    ):
        return _read_bounded_regular_bytes_portable(
            requested, max_bytes=max_bytes, label=label
        )

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors: list[int] = []
    parent_links: list[tuple[int, str, int]] = []
    file_descriptor: int | None = None
    result: bytes | None = None
    try:
        try:
            current = os.open(requested.anchor, directory_flags)
        except OSError as exc:
            raise ValueError(f"cannot open {label} anchor safely: {exc}") from exc
        descriptors.append(current)
        for component in requested.parent.parts[1:]:
            try:
                before_parent = os.stat(
                    component, dir_fd=current, follow_symlinks=False
                )
            except OSError as exc:
                raise ValueError(f"cannot inspect {label} parent: {exc}") from exc
            if stat.S_ISLNK(before_parent.st_mode):
                raise ValueError(f"{label} path contains a symlink")
            if not stat.S_ISDIR(before_parent.st_mode):
                raise ValueError(f"{label} parent is not a directory")
            try:
                child = os.open(component, directory_flags, dir_fd=current)
            except OSError as exc:
                raise ValueError(f"cannot open {label} parent safely: {exc}") from exc
            descriptors.append(child)
            if _stat_identity(before_parent) != _stat_identity(os.fstat(child)):
                raise ValueError(f"{label} parent identity changed during open")
            parent_links.append((current, component, child))
            current = child

        filename = requested.name
        try:
            before = os.stat(filename, dir_fd=current, follow_symlinks=False)
        except OSError as exc:
            raise ValueError(f"cannot inspect {label} {requested}: {exc}") from exc
        if stat.S_ISLNK(before.st_mode):
            raise ValueError(f"{label} path contains a symlink")
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} must be a regular file")
        if before.st_size > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes} bytes")

        file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_BINARY", 0)
        file_flags |= getattr(os, "O_NONBLOCK", 0)
        try:
            file_descriptor = os.open(filename, file_flags, dir_fd=current)
        except OSError as exc:
            raise ValueError(f"cannot open {label} {requested} safely: {exc}") from exc
        try:
            result = _read_open_regular_file(
                file_descriptor,
                before=before,
                stat_path=lambda: os.stat(
                    filename, dir_fd=current, follow_symlinks=False
                ),
                max_bytes=max_bytes,
                label=label,
            )
        except OSError as exc:
            raise ValueError(f"cannot read {label} {requested} safely: {exc}") from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        verification_error: ValueError | None = None
        try:
            for parent, component, child in parent_links:
                current_parent = os.stat(
                    component, dir_fd=parent, follow_symlinks=False
                )
                if stat.S_ISLNK(current_parent.st_mode) or _stat_identity(
                    current_parent
                ) != _stat_identity(os.fstat(child)):
                    raise ValueError(f"{label} parent identity changed during read")
        except (OSError, ValueError) as exc:
            verification_error = (
                exc
                if isinstance(exc, ValueError)
                else ValueError(f"{label} parent identity changed during read")
            )
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        if verification_error is not None:
            raise verification_error
    assert result is not None
    return result


def _read_yaml_mapping(path: Path) -> dict[str, Any]:
    try:
        raw = read_bounded_regular_bytes(
            path,
            max_bytes=MAX_PLAN_BYTES,
            label="experiment plan",
        )
        value = yaml.safe_load(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError) as exc:
        raise ValueError(f"cannot load experiment plan {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(  # noqa: TRY004 - plan loaders expose one validation error type.
            f"experiment plan {path} must contain a YAML mapping"
        )
    return value


def _filter_named(
    records: list[dict[str, Any]], requested: Any, *, key: str, label: str
) -> list[dict[str, Any]]:
    if (
        not isinstance(requested, list)
        or not requested
        or not all(isinstance(item, str) for item in requested)
    ):
        raise ValueError(f"{label} must be a non-empty list of IDs")
    if len(requested) != len(set(requested)):
        raise ValueError(f"{label} must not contain duplicate IDs")
    indexed = {record[key]: record for record in records}
    missing = sorted(set(requested) - set(indexed))
    if missing:
        raise ValueError(f"unknown {label}: {', '.join(missing)}")
    requested_set = set(requested)
    return [record for record in records if record[key] in requested_set]


def _validated_include(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\x00" in value
        or "\\" in value
        or ntpath.splitdrive(value)[0]
        or PurePosixPath(value).is_absolute()
    ):
        raise ValueError("include must be a safe relative POSIX path")
    return value


def build_experiment_plan(
    reference_mapping: dict[str, Any],
    *,
    registration_path: Path,
    source_mapping: dict[str, Any] | None = None,
    source_path: Path | None = None,
) -> ExperimentPlan:
    """Build a plan from already captured mappings without reopening either file."""

    requested_path = Path(os.path.abspath(registration_path))
    raw = deepcopy(reference_mapping)
    resolved_source_path = requested_path
    if "include" in raw:
        unexpected = set(raw) - _REFERENCE_KEYS
        if unexpected:
            raise ValueError(
                "plan references may only select registered cells; unexpected keys: "
                + ", ".join(sorted(unexpected))
            )
        include = _validated_include(raw["include"])
        expected_source_path = Path(os.path.abspath(requested_path.parent / include))
        if expected_source_path == requested_path:
            raise ValueError("experiment plan cannot include itself")
        if source_mapping is None or source_path is None:
            raise ValueError("referenced plans require captured source configuration")
        resolved_source_path = Path(os.path.abspath(source_path))
        if resolved_source_path != expected_source_path:
            raise ValueError("captured source path does not match the plan include")
        base = deepcopy(source_mapping)
        if "include" in base:
            raise ValueError(
                "authoritative configuration must not include another plan"
            )
        raw_plan = deepcopy(base)
        for scalar in (
            "dataset_id",
            "blocks",
            "schedule_seed",
            "campaign_stage",
            "schedule_path",
            "schedule_sha256",
            "max_attempts_per_cell",
        ):
            if scalar in raw:
                raw_plan[scalar] = raw[scalar]
        if "scenario_ids" in raw:
            raw_plan["scenarios"] = _filter_named(
                raw_plan.get("scenarios", []),
                raw["scenario_ids"],
                key="scenario_id",
                label="scenario_ids",
            )
        if "traffic_profile_ids" in raw:
            raw_plan["traffic_profiles"] = _filter_named(
                raw_plan.get("traffic_profiles", []),
                raw["traffic_profile_ids"],
                key="profile_id",
                label="traffic_profile_ids",
            )
    else:
        raw_plan = raw

    plan = ExperimentPlan.model_validate(raw_plan)
    plan._source_path = resolved_source_path
    plan._registration_path = requested_path
    return plan


def load_experiment_plan(path: str | Path) -> ExperimentPlan:
    """Load a full plan or a constrained reference to the authoritative plan."""

    requested_path = Path(os.path.abspath(path))
    raw = _read_yaml_mapping(requested_path)
    if "include" not in raw:
        return build_experiment_plan(raw, registration_path=requested_path)

    include = _validated_include(raw.get("include"))
    source_path = Path(os.path.abspath(requested_path.parent / include))
    source_mapping = _read_yaml_mapping(source_path)
    return build_experiment_plan(
        raw,
        registration_path=requested_path,
        source_mapping=source_mapping,
        source_path=source_path,
    )
