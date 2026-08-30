"""Quality control and pre-specified paired analysis for measured VPN runs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import random
import re
import stat
import statistics
import uuid
import warnings
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from itertools import pairwise
from pathlib import Path, PurePosixPath
from typing import Any

import matplotlib

from adaptive_vpn.collector import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    EVIDENCE_SCHEMA_VERSION,
    LEGACY_EVIDENCE_SCHEMA_VERSION,
    MAX_BUNDLE_ENTRIES,
    MAX_DATASET_BUNDLES,
    MAX_EVIDENCE_ARTIFACT_BYTES,
    MAX_EVIDENCE_BUNDLE_BYTES,
    MAX_JSON_BYTES,
    PACKET_FIELDS,
    _bounded_sorted_directory_entries,
    _directory_identity,
    _fsync_directory,
    _fsync_file,
    _is_real_directory_stat,
    _is_regular_file_stat,
    _probe_directory_publish_capability,
    _publish_directory_no_replace,
    _read_bounded_regular_bytes,
    format_validation_diagnostics,
    validate_evidence_bundle,
)
from adaptive_vpn.config import (
    MAX_PLAN_BYTES,
    load_experiment_plan,
    read_bounded_regular_bytes,
)
from adaptive_vpn.schedule import (
    MAX_SCHEDULE_BYTES,
    registered_schedule_path,
)
from adaptive_vpn.schedule import (
    load_registered_schedule as load_strict_registered_schedule,
)

matplotlib.use("Agg", force=True)

SCHEMA_VERSION = "1.0.0"
REGISTERED_SCHEDULE_SCHEMA_VERSION = "2.0.0"
_CONTENT_ADDRESSED_SCHEDULE_NAME = re.compile(
    r"\A(?P<plan>[a-z0-9][a-z0-9-]*)\."
    r"(?P<digest>[0-9a-f]{64})\.schedule\.json\Z"
)
SUPPORTED_EVIDENCE_SCHEMA_VERSIONS = {
    LEGACY_EVIDENCE_SCHEMA_VERSION,
    EVIDENCE_SCHEMA_VERSION,
    CURRENT_MANIFEST_SCHEMA_VERSION,
}
DEFAULT_STRATEGIES = ("static", "threshold", "adaptive")
PRIMARY_METRICS = ("rtt_mean_ms", "loss_pct")
ENDPOINT_TO_RUN_METRIC = {
    "loss_pct": "loss_pct",
    "mean_rtt_ms": "rtt_mean_ms",
    "p95_rtt_ms": "rtt_p95_ms",
}
DEFAULT_ANALYSIS_PLAN_PATH = (
    Path(__file__).resolve().parents[1] / "experiments" / "hypotheses.yaml"
)
DEFAULT_SCHEDULES_DIR = Path(__file__).resolve().parents[1] / "experiments" / "plans"
MAX_SCHEDULE_REGISTRATIONS = 1_024
DESCRIPTIVE_METRICS = (
    "rtt_mean_ms",
    "rtt_p95_ms",
    "loss_pct",
    "rtt_median_ms",
    "mean_jitter_ms",
    "switch_count",
    "longest_disruption_ms",
)
RUN_TABLE_FIELDS = (
    "schema_version",
    "run_id",
    "dataset_id",
    "strategy",
    "scenario",
    "traffic_profile",
    "block",
    "status",
    "sent_count",
    "received_count",
    "rtt_mean_ms",
    "rtt_p95_ms",
    "rtt_median_ms",
    "mean_jitter_ms",
    "loss_pct",
    "switch_count",
    "longest_disruption_ms",
    "apparatus_failure",
    "source_bundle",
)
CONFIRMATORY_FIELDS = (
    "contrast_id",
    "endpoint",
    "metric",
    "baseline_strategy",
    "alternative_strategy",
    "direction",
    "pair_count",
    "block_count",
    "inference_unit",
    "mean_difference",
    "bootstrap_95_lower",
    "bootstrap_95_upper",
    "paired_standardised_effect",
    "effect_status",
    "wilcoxon_statistic",
    "p_value_raw",
    "p_value_holm",
    "test_status",
)
DESCRIPTIVE_FIELDS = (
    "scenario",
    "traffic_profile",
    "strategy",
    "metric",
    "n",
    "mean",
    "standard_deviation",
    "median",
    "p95",
)


class AnalysisInputError(ValueError):
    """Raised when evidence is not eligible for confirmatory analysis."""


class _ScheduleRegistrationNotFound(AnalysisInputError):
    """Raised only when no dataset registration exists in the trusted directory."""


@dataclass(frozen=True, slots=True)
class _RegisteredScheduleInput:
    path: Path
    sha256: str
    document: dict[str, object]
    registry: dict[str, dict[str, object]]
    campaign_stage: str | None = None
    max_attempts_per_cell: int | None = None


@dataclass(frozen=True, slots=True)
class _ValidatedBundleSnapshot:
    path: Path
    manifest: Mapping[str, object]
    artifacts: Mapping[str, bytes]
    sha256sums_sha256: str


@dataclass(frozen=True, slots=True)
class _ValidatedDataset:
    records: tuple[RunRecord, ...]
    bundles: tuple[_ValidatedBundleSnapshot, ...]
    selected_bundle_names: frozenset[str]
    max_attempts_per_cell: int | None


@dataclass(frozen=True, slots=True)
class _ProcessedTreeSnapshot:
    files: tuple[tuple[str, tuple[int, ...], str], ...]
    directories: tuple[tuple[str, tuple[int, ...]], ...]


@dataclass(frozen=True, slots=True)
class PacketSummary:
    sent_count: int
    received_count: int
    loss_pct: float
    rtt_mean_ms: float | None
    rtt_p95_ms: float | None
    rtt_median_ms: float | None
    mean_jitter_ms: float | None


@dataclass(frozen=True, slots=True)
class RunRecord:
    schema_version: str
    run_id: str
    dataset_id: str
    strategy: str
    scenario: str
    traffic_profile: str
    block: int
    status: str
    sent_count: int
    received_count: int
    rtt_mean_ms: float | None
    rtt_p95_ms: float | None
    rtt_median_ms: float | None
    mean_jitter_ms: float | None
    loss_pct: float
    switch_count: int
    longest_disruption_ms: float
    apparatus_failure: bool
    source_bundle: str

    @property
    def pairing_key(self) -> tuple[int, str, str]:
        return (self.block, self.scenario, self.traffic_profile)

    def metric(self, name: str) -> float:
        if name not in DESCRIPTIVE_METRICS:
            raise AnalysisInputError(f"unknown analysis metric: {name}")
        value = getattr(self, name)
        if value is None or not math.isfinite(float(value)):
            raise AnalysisInputError(f"run {self.run_id} has no finite {name}")
        return float(value)


@dataclass(frozen=True, slots=True)
class PairedDifference:
    key: tuple[int, str, str]
    baseline_run_id: str
    alternative_run_id: str
    baseline: float
    alternative: float
    difference: float


@dataclass(frozen=True, slots=True)
class BlockDifference:
    block: int
    difference: float
    cell_count: int


@dataclass(frozen=True, slots=True)
class ConfirmatoryContrast:
    contrast_id: str
    endpoint: str
    run_metric: str
    alternative_strategy: str
    baseline_strategy: str
    direction: str


@dataclass(frozen=True, slots=True)
class AnalysisPlan:
    schema_version: str
    correction: str
    alpha: float
    contrasts: tuple[ConfirmatoryContrast, ...]
    source_path: Path
    source_sha256: str


@dataclass(frozen=True, slots=True)
class BootstrapInterval:
    lower: float
    upper: float


def load_analysis_plan(path: Path) -> AnalysisPlan:
    """Load and strictly validate the frozen confirmatory family."""
    import yaml

    plan_path = Path(os.path.abspath(path))
    try:
        plan_bytes = read_bounded_regular_bytes(
            plan_path,
            max_bytes=MAX_PLAN_BYTES,
            label="analysis plan",
        )
        document = yaml.safe_load(plan_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError) as error:
        raise AnalysisInputError(
            f"cannot read analysis plan {plan_path}: {error}"
        ) from error
    if not isinstance(document, dict):
        raise AnalysisInputError("analysis plan must contain a mapping")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise AnalysisInputError("analysis plan has an unsupported schema version")
    if document.get("experimental_unit") != "run":
        raise AnalysisInputError("analysis plan experimental_unit must be run")
    family = document.get("confirmatory_family")
    if not isinstance(family, dict) or family.get("correction") != "holm":
        raise AnalysisInputError("analysis plan must specify Holm correction")
    alpha = _require_float(family.get("alpha"), "confirmatory alpha")
    if not 0 < alpha < 1:
        raise AnalysisInputError("confirmatory alpha must be between zero and one")
    raw_contrasts = family.get("contrasts")
    if not isinstance(raw_contrasts, list) or not raw_contrasts:
        raise AnalysisInputError("analysis plan has no confirmatory contrasts")
    contrasts: list[ConfirmatoryContrast] = []
    for index, raw in enumerate(raw_contrasts, 1):
        if not isinstance(raw, dict):
            raise AnalysisInputError(f"confirmatory contrast {index} is not a mapping")
        contrast_id = _require_text(raw.get("contrast_id"), f"contrast {index} ID")
        match = re.fullmatch(
            r"(?P<alternative>[a-z0-9]+)-vs-(?P<baseline>[a-z0-9]+)-[a-z0-9-]+",
            contrast_id,
        )
        if match is None:
            raise AnalysisInputError(
                f"contrast ID does not encode two strategies: {contrast_id}"
            )
        endpoint = _require_text(
            raw.get("endpoint"), f"contrast {contrast_id} endpoint"
        )
        if endpoint not in ENDPOINT_TO_RUN_METRIC:
            raise AnalysisInputError(f"unsupported confirmatory endpoint: {endpoint}")
        paired_by = raw.get("paired_by")
        if paired_by != ["block", "scenario_id", "traffic_profile_id"]:
            raise AnalysisInputError(
                f"contrast {contrast_id} must use the frozen three-field pairing key"
            )
        direction = _require_text(
            raw.get("direction"), f"contrast {contrast_id} direction"
        )
        if direction != "lower":
            raise AnalysisInputError(
                f"contrast {contrast_id} has unsupported direction"
            )
        contrasts.append(
            ConfirmatoryContrast(
                contrast_id=contrast_id,
                endpoint=endpoint,
                run_metric=ENDPOINT_TO_RUN_METRIC[endpoint],
                alternative_strategy=match.group("alternative"),
                baseline_strategy=match.group("baseline"),
                direction=direction,
            )
        )
    identifiers = [contrast.contrast_id for contrast in contrasts]
    if len(identifiers) != len(set(identifiers)):
        raise AnalysisInputError("analysis plan contains duplicate contrast IDs")
    return AnalysisPlan(
        schema_version=SCHEMA_VERSION,
        correction="holm",
        alpha=alpha,
        contrasts=tuple(contrasts),
        source_path=plan_path,
        source_sha256=hashlib.sha256(plan_bytes).hexdigest(),
    )


def _normalise_marker(value: object) -> str:
    normalised: list[str] = []
    separator_pending = False
    for character in str(value):
        for lowered in character.lower():
            if ("a" <= lowered <= "z") or ("0" <= lowered <= "9"):
                if separator_pending and normalised:
                    normalised.append("_")
                normalised.append(lowered)
                separator_pending = False
                if len(normalised) > 256:
                    return "oversized_marker_name"
            else:
                separator_pending = True
    return "".join(normalised)


def _marker_location(location: str, component: object) -> str:
    suffix = "...[truncated]"
    prefix = f"{location}."
    if len(prefix) >= 512:
        return prefix[: 512 - len(suffix)] + suffix
    text = str(component)
    available = 512 - len(prefix)
    if len(text) > available:
        text = text[: available - len(suffix)] + suffix
    return prefix + text


def _generated_marker(value: object, location: str = "manifest") -> str | None:
    marker_keys = {
        "generated",
        "is_generated",
        "is_mock",
        "is_simulated",
        "is_synthetic",
        "mock",
        "simulated",
        "synthetic",
        "synthetic_data",
        "simulated_data",
        "fabricated",
        "fabricated_data",
        "generated_data",
        "mock_data",
        "fixture_data",
    }
    source_keys = {
        "data_origin",
        "data_source",
        "measurement_origin",
        "measurement_source",
        "source_kind",
    }
    source_markers = {
        "synthetic",
        "simulated",
        "fabricated",
        "generated",
        "mock",
        "fixture",
    }
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_name = _normalise_marker(key)
            child_location = _marker_location(location, key)
            if key_name in marker_keys and child not in (False, None, 0, "", "false"):
                return child_location
            if key_name in source_keys and _normalise_marker(child) in source_markers:
                return child_location
            nested = _generated_marker(child, child_location)
            if nested:
                return nested
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            nested = _generated_marker(child, _marker_location(location, f"[{index}]"))
            if nested:
                return nested
    return None


def _require_text(value: object, field: str) -> str:
    text = str(value).strip()
    if not text:
        raise AnalysisInputError(f"{field} must not be empty")
    return text


def _require_int(value: object, field: str, *, minimum: int = 0) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError) as error:
        raise AnalysisInputError(f"{field} must be an integer") from error
    if parsed < minimum:
        raise AnalysisInputError(f"{field} must be at least {minimum}")
    return parsed


def _require_float(value: object, field: str, *, minimum: float = 0.0) -> float:
    try:
        parsed = float(str(value))
    except (TypeError, ValueError) as error:
        raise AnalysisInputError(f"{field} must be numeric") from error
    if not math.isfinite(parsed) or parsed < minimum:
        raise AnalysisInputError(f"{field} must be finite and at least {minimum}")
    return parsed


def _optional_float(value: object, field: str) -> float | None:
    if value is None or str(value).strip() == "":
        return None
    return _require_float(value, field)


def _parse_bool(value: object, field: str) -> bool:
    if isinstance(value, bool):
        return value
    normalised = str(value).strip().lower()
    if normalised in {"true", "1", "yes"}:
        return True
    if normalised in {"false", "0", "no", ""}:
        return False
    raise AnalysisInputError(f"{field} must be boolean")


def _linear_quantile(values: Sequence[float], probability: float) -> float:
    if not values:
        raise AnalysisInputError("a quantile requires at least one value")
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * probability
    lower_index = math.floor(position)
    upper_index = math.ceil(position)
    fraction = position - lower_index
    return ordered[lower_index] + fraction * (
        ordered[upper_index] - ordered[lower_index]
    )


def summarise_packet_rows(
    rows: Iterable[Mapping[str, object]], *, strict: bool = True
) -> PacketSummary:
    """Validate packet rows and reduce them to one run-level observation."""
    seen: set[int] = set()
    received: list[tuple[int, float]] = []
    sent_count = 0
    for row_number, row in enumerate(rows, 1):
        missing = set(PACKET_FIELDS) - row.keys()
        extra = row.keys() - set(PACKET_FIELDS)
        if missing or extra:
            raise AnalysisInputError(
                f"packet row {row_number} schema mismatch; "
                f"missing={sorted(missing)}, extra={sorted(extra)}"
            )
        sequence = _require_int(row["sequence"], f"packet row {row_number} sequence")
        path_id = _require_text(row["path_id"], f"packet row {row_number} path_id")
        if strict and sequence in seen:
            raise AnalysisInputError(
                f"duplicate packet sequence {sequence} on {path_id}"
            )
        seen.add(sequence)
        sent_ns = _require_int(row["sent_ns"], f"packet row {row_number} sent_ns")
        _require_int(
            row["datagram_bytes"],
            f"packet row {row_number} datagram_bytes",
            minimum=32,
        )
        status = _require_text(row["status"], f"packet row {row_number} status")
        sent_count += 1
        if status == "received":
            received_ns = _require_int(
                row["received_ns"], f"packet row {row_number} received_ns"
            )
            if strict and received_ns < sent_ns:
                raise AnalysisInputError(
                    f"packet row {row_number} was received before it was sent"
                )
            rtt_ms = _require_float(row["rtt_ms"], f"packet row {row_number} rtt_ms")
            if strict:
                measured_rtt_ms = (received_ns - sent_ns) / 1_000_000
                if not math.isclose(
                    rtt_ms, measured_rtt_ms, rel_tol=1e-9, abs_tol=1e-6
                ):
                    raise AnalysisInputError(
                        f"packet row {row_number} has inconsistent RTT"
                    )
            received.append((sent_ns, rtt_ms))
        elif status == "timeout":
            if strict and (
                str(row["received_ns"] or "").strip()
                or str(row["rtt_ms"] or "").strip()
            ):
                raise AnalysisInputError(
                    f"packet row {row_number} timeout must have empty receive fields"
                )
        else:
            raise AnalysisInputError(
                f"packet row {row_number} has non-final status {status!r}"
            )
    if sent_count == 0:
        raise AnalysisInputError("packets.csv must contain at least one packet")

    ordered_rtts = [rtt for _, rtt in sorted(received)]
    jitter = 0.0
    for previous, current in pairwise(ordered_rtts):
        jitter += (abs(current - previous) - jitter) / 16.0
    return PacketSummary(
        sent_count=sent_count,
        received_count=len(ordered_rtts),
        loss_pct=(sent_count - len(ordered_rtts)) / sent_count * 100.0,
        rtt_mean_ms=(statistics.fmean(ordered_rtts) if ordered_rtts else None),
        rtt_p95_ms=(_linear_quantile(ordered_rtts, 0.95) if ordered_rtts else None),
        rtt_median_ms=(statistics.median(ordered_rtts) if ordered_rtts else None),
        mean_jitter_ms=(jitter if ordered_rtts else None),
    )


def _record_from_mapping(row: Mapping[str, object]) -> RunRecord:
    missing = set(RUN_TABLE_FIELDS) - row.keys()
    if missing:
        raise AnalysisInputError(f"run table is missing fields: {sorted(missing)}")
    schema_version = _require_text(row["schema_version"], "schema_version")
    if schema_version != SCHEMA_VERSION:
        raise AnalysisInputError(f"unsupported run schema version: {schema_version}")
    run_id = _require_text(row["run_id"], "run_id")
    try:
        parsed_uuid = uuid.UUID(run_id)
    except ValueError as error:
        raise AnalysisInputError("run_id must be a UUID") from error
    if parsed_uuid.version not in {4, 5}:
        raise AnalysisInputError("run_id must be a version-4 or version-5 UUID")
    status = _require_text(row["status"], "status")
    if status != "complete":
        raise AnalysisInputError(f"run {run_id} is incomplete")
    sent_count = _require_int(row["sent_count"], "sent_count", minimum=1)
    received_count = _require_int(row["received_count"], "received_count")
    if received_count > sent_count:
        raise AnalysisInputError("received_count cannot exceed sent_count")
    loss_pct = _require_float(row["loss_pct"], "loss_pct")
    expected_loss = (sent_count - received_count) / sent_count * 100.0
    if not math.isclose(loss_pct, expected_loss, rel_tol=1e-9, abs_tol=1e-6):
        raise AnalysisInputError("loss_pct is inconsistent with packet counts")
    return RunRecord(
        schema_version=schema_version,
        run_id=run_id,
        dataset_id=_require_text(row["dataset_id"], "dataset_id"),
        strategy=_require_text(row["strategy"], "strategy"),
        scenario=_require_text(row["scenario"], "scenario"),
        traffic_profile=_require_text(row["traffic_profile"], "traffic_profile"),
        block=_require_int(row["block"], "block", minimum=1),
        status=status,
        sent_count=sent_count,
        received_count=received_count,
        rtt_mean_ms=_optional_float(row["rtt_mean_ms"], "rtt_mean_ms"),
        rtt_p95_ms=_optional_float(row["rtt_p95_ms"], "rtt_p95_ms"),
        rtt_median_ms=_optional_float(row["rtt_median_ms"], "rtt_median_ms"),
        mean_jitter_ms=_optional_float(row["mean_jitter_ms"], "mean_jitter_ms"),
        loss_pct=loss_pct,
        switch_count=_require_int(row["switch_count"], "switch_count"),
        longest_disruption_ms=_require_float(
            row["longest_disruption_ms"], "longest_disruption_ms"
        ),
        apparatus_failure=_parse_bool(row["apparatus_failure"], "apparatus_failure"),
        source_bundle=_require_text(row["source_bundle"], "source_bundle"),
    )


def read_run_table(path: Path) -> list[RunRecord]:
    """Read the versioned processed-run schema."""
    with Path(path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise AnalysisInputError("run table has no header")
        return [_record_from_mapping(row) for row in reader]


def _read_switch_metrics_bytes(content: bytes, *, label: str) -> tuple[int, float]:
    switch_count = 0
    maximum_gap: float | None = None
    for line_number, raw_line in enumerate(content.splitlines(keepends=True), 1):
        if len(raw_line) > MAX_JSON_BYTES:
            raise AnalysisInputError(
                f"{label} line {line_number} exceeds {MAX_JSON_BYTES} bytes"
            )
        if not raw_line.strip():
            continue
        try:
            event = json.loads(raw_line.decode("utf-8"))
        except (
            UnicodeError,
            json.JSONDecodeError,
            OverflowError,
            RecursionError,
        ) as error:
            raise AnalysisInputError(
                f"invalid {label} line {line_number}"
            ) from error
        if not isinstance(event, dict):
            raise AnalysisInputError(f"{label} line {line_number} is not an object")
        event_name = _normalise_marker(event.get("event", event.get("type", "")))
        if event_name in {
            "path_switched",
            "switch_completed",
            "path_switch_completed",
            "route_switch_completed",
        }:
            switch_count += 1
        for field in (
            "longest_disruption_ms",
            "data_plane_gap_ms",
            "switch_gap_ms",
            "gap_ms",
        ):
            if field in event:
                gap = _require_float(event[field], f"{label} line {line_number} {field}")
                maximum_gap = gap if maximum_gap is None else max(maximum_gap, gap)
                break
    return switch_count, 0.0 if maximum_gap is None else maximum_gap


def _read_switch_metrics(path: Path) -> tuple[int, float]:
    try:
        return _read_switch_metrics_bytes(path.read_bytes(), label="events.jsonl")
    except OSError as error:
        raise AnalysisInputError(f"cannot read events.jsonl: {error}") from error


def _record_from_bundle(
    bundle_path: Path,
    manifest: Mapping[str, object],
    artifacts: Mapping[str, bytes] | None = None,
) -> RunRecord:
    evidence_schema_version = _require_text(
        manifest.get("schema_version", ""), "evidence schema_version"
    )
    if evidence_schema_version not in SUPPORTED_EVIDENCE_SCHEMA_VERSIONS:
        raise AnalysisInputError(
            f"unsupported evidence schema version: {evidence_schema_version}"
        )
    if artifacts is None:
        try:
            packet_bytes = (bundle_path / "packets.csv").read_bytes()
            event_bytes = (bundle_path / "events.jsonl").read_bytes()
        except OSError as error:
            raise AnalysisInputError(
                f"cannot read evidence streams for {bundle_path.name}: {error}"
            ) from error
    else:
        try:
            packet_bytes = artifacts["packets.csv"]
            event_bytes = artifacts["events.jsonl"]
        except KeyError as error:
            raise AnalysisInputError(
                f"{bundle_path.name} validator snapshot lacks {error.args[0]}"
            ) from error
    try:
        handle = io.StringIO(packet_bytes.decode("utf-8"), newline="")
    except UnicodeError as error:
        raise AnalysisInputError(f"{bundle_path.name} packets.csv is not UTF-8") from error
    with handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or tuple(reader.fieldnames) != PACKET_FIELDS:
            raise AnalysisInputError(f"{bundle_path.name} has an invalid packet schema")
        packet_summary = summarise_packet_rows(
            reader,
            strict=evidence_schema_version != LEGACY_EVIDENCE_SCHEMA_VERSION,
        )
    switch_count, longest_disruption_ms = _read_switch_metrics_bytes(
        event_bytes, label="events.jsonl"
    )
    mapping: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "run_id": (
            manifest.get("cell_id", "")
            if evidence_schema_version == CURRENT_MANIFEST_SCHEMA_VERSION
            else manifest.get("run_id", "")
        ),
        "dataset_id": manifest.get("dataset_id", ""),
        "strategy": manifest.get("strategy", ""),
        "scenario": manifest.get("scenario", ""),
        "traffic_profile": manifest.get("traffic_profile", ""),
        "block": manifest.get("block", ""),
        "status": manifest.get("status", ""),
        "sent_count": packet_summary.sent_count,
        "received_count": packet_summary.received_count,
        "rtt_mean_ms": packet_summary.rtt_mean_ms,
        "rtt_p95_ms": packet_summary.rtt_p95_ms,
        "rtt_median_ms": packet_summary.rtt_median_ms,
        "mean_jitter_ms": packet_summary.mean_jitter_ms,
        "loss_pct": packet_summary.loss_pct,
        "switch_count": switch_count,
        "longest_disruption_ms": longest_disruption_ms,
        # Retained only for schema-1 processed-table compatibility. Evidence
        # manifests do not authenticate this disposition and inference ignores it.
        "apparatus_failure": False,
        "source_bundle": bundle_path.name,
    }
    return _record_from_mapping(mapping)


def _read_bounded_schedule_bytes(path: Path) -> bytes:
    try:
        return read_bounded_regular_bytes(
            path,
            max_bytes=MAX_SCHEDULE_BYTES,
            label="registered schedule",
        )
    except (OSError, ValueError) as error:
        raise AnalysisInputError(
            f"cannot read registered schedule {path}: {error}"
        ) from error


def _find_schema2_registration(path: Path, plan_name: str):
    absolute_schedule = Path(os.path.abspath(path))
    for depth, parent in enumerate(absolute_schedule.parents):
        if depth >= 64:
            raise AnalysisInputError("schema 2 registration search exceeds 64 parents")
        candidate = parent / f"{plan_name}.yaml"
        # This probe only distinguishes an absent candidate; the loader below
        # independently captures it through held descriptors and rechecks identity.
        try:
            candidate_stat = os.lstat(candidate)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise AnalysisInputError(
                f"cannot inspect schema 2 registration {candidate}: {error}"
            ) from error
        if stat.S_ISLNK(candidate_stat.st_mode) or not stat.S_ISREG(
            candidate_stat.st_mode
        ):
            raise AnalysisInputError(
                "schema 2 registration must be a regular YAML file"
            )
        try:
            plan = load_experiment_plan(candidate)
            registered_path = Path(os.path.abspath(registered_schedule_path(plan)))
        except (OSError, RuntimeError, ValueError) as error:
            raise AnalysisInputError(
                f"invalid schema 2 schedule registration: {error}"
            ) from error
        if registered_path != absolute_schedule:
            raise AnalysisInputError(
                "schema 2 registration does not reference the schedule path"
            )
        return plan
    raise AnalysisInputError("schema 2 schedule registration was not found")


def _authenticate_schema2_schedule(path: Path, raw: bytes, dataset_id: str):
    match = _CONTENT_ADDRESSED_SCHEDULE_NAME.fullmatch(path.name)
    if match is None:
        raise AnalysisInputError(
            "schema 2 schedule must use a content-addressed filename"
        )
    observed_digest = hashlib.sha256(raw).hexdigest()
    filename_digest = match.group("digest")
    if observed_digest != filename_digest:
        raise AnalysisInputError(
            "schema 2 content-addressed filename digest does not match its bytes"
        )
    plan = _find_schema2_registration(path, match.group("plan"))
    if plan.dataset_id != dataset_id:
        raise AnalysisInputError(
            "schema 2 registration dataset_id does not match analysis"
        )
    if plan.schedule_sha256 != filename_digest:
        raise AnalysisInputError(
            "schema 2 registration digest does not match the content-addressed name"
        )
    try:
        load_strict_registered_schedule(plan)
    except (OSError, RuntimeError, ValueError) as error:
        raise AnalysisInputError(
            f"schema 2 registered schedule validation failed: {error}"
        ) from error
    return plan


def _load_registered_schedule(
    path: Path, dataset_id: str
) -> _RegisteredScheduleInput:
    schedule_path = Path(os.path.abspath(path))
    raw = _read_bounded_schedule_bytes(schedule_path)
    observed_digest = hashlib.sha256(raw).hexdigest()
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AnalysisInputError(
            f"cannot read registered schedule {path}: {error}"
        ) from error
    if not isinstance(document, dict):
        raise AnalysisInputError("registered schedule must contain an object")
    schedule_schema = document.get("schema_version")
    if schedule_schema == SCHEMA_VERSION:
        entries = document.get("runs")
        identity_field = "run_id"
        expected_field = "expected_runs"
        shared_identity: dict[str, object] = {}
        registered_plan = None
    elif schedule_schema == REGISTERED_SCHEDULE_SCHEMA_VERSION:
        registered_plan = _authenticate_schema2_schedule(
            schedule_path, raw, dataset_id
        )
        entries = document.get("cells")
        identity_field = "cell_id"
        expected_field = "expected_cells"
        shared_identity = {
            "schedule_seed": _require_int(
                document.get("schedule_seed"), "schedule schedule_seed"
            ),
            "config_sha256": _require_text(
                document.get("config_sha256"), "schedule config_sha256"
            ),
        }
    else:
        raise AnalysisInputError(
            "registered schedule has an unsupported schema version"
        )
    if document.get("dataset_id") != dataset_id:
        raise AnalysisInputError(
            "registered schedule dataset_id does not match analysis"
        )
    if not isinstance(entries, list) or not entries:
        raise AnalysisInputError("registered schedule has no registered cells")
    registry: dict[str, dict[str, object]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise AnalysisInputError("registered schedule cell is not an object")
        run_id = _require_text(
            entry.get(identity_field), f"registered {identity_field}"
        )
        if schedule_schema == REGISTERED_SCHEDULE_SCHEMA_VERSION:
            try:
                parsed_cell_id = uuid.UUID(run_id)
            except (ValueError, AttributeError) as error:
                raise AnalysisInputError("registered cell_id must be a UUID") from error
            if parsed_cell_id.version != 5 or str(parsed_cell_id) != run_id:
                raise AnalysisInputError(
                    "registered cell_id must be a canonical UUIDv5"
                )
        if run_id in registry:
            raise AnalysisInputError(f"registered schedule duplicates run {run_id}")
        registry[run_id] = {**entry, **shared_identity, "run_id": run_id}
    expected_runs = _require_int(
        document.get(expected_field), f"schedule {expected_field}", minimum=1
    )
    if expected_runs != len(registry):
        raise AnalysisInputError("registered schedule expected_runs is inconsistent")
    return _RegisteredScheduleInput(
        path=schedule_path,
        sha256=observed_digest,
        document=document,
        registry=registry,
        campaign_stage=(
            registered_plan.campaign_stage if registered_plan is not None else None
        ),
        max_attempts_per_cell=(
            registered_plan.max_attempts_per_cell
            if registered_plan is not None
            else None
        ),
    )


def _discover_registered_schedule(dataset_id: str) -> Path:
    matches: list[Path] = []
    if not DEFAULT_SCHEDULES_DIR.is_dir():
        raise _ScheduleRegistrationNotFound(
            f"registered schedule registration not found for dataset {dataset_id}"
        )
    registrations: list[Path] = []
    try:
        for path in DEFAULT_SCHEDULES_DIR.iterdir():
            if path.suffix != ".yaml":
                continue
            registrations.append(path)
            if len(registrations) > MAX_SCHEDULE_REGISTRATIONS:
                raise AnalysisInputError(
                    "registered schedule directory contains more than "
                    f"{MAX_SCHEDULE_REGISTRATIONS} YAML registrations"
                )
    except OSError as error:
        raise AnalysisInputError(
            f"cannot inventory registered schedules: {error}"
        ) from error
    for path in sorted(registrations, key=lambda candidate: candidate.name):
        try:
            plan = load_experiment_plan(path)
            if plan.dataset_id == dataset_id:
                matches.append(
                    Path(os.path.abspath(registered_schedule_path(plan)))
                )
        except (OSError, RuntimeError, ValueError) as error:
            raise AnalysisInputError(
                f"invalid registered schedule registration {path}: {error}"
            ) from error
    if len(matches) > 1:
        raise AnalysisInputError(
            f"multiple registered schedule registrations match dataset {dataset_id}"
        )
    if not matches:
        raise _ScheduleRegistrationNotFound(
            f"registered schedule registration not found for dataset {dataset_id}"
        )
    return matches[0]


def _validate_registered_manifest(
    manifest: Mapping[str, object],
    schedule: Mapping[str, object],
    registry: Mapping[str, Mapping[str, object]],
) -> None:
    run_id = str(
        manifest.get(
            "cell_id"
            if manifest.get("schema_version") == CURRENT_MANIFEST_SCHEMA_VERSION
            else "run_id",
            "",
        )
    )
    registered = registry.get(run_id)
    if registered is None:
        raise AnalysisInputError(f"registered schedule mismatch: unknown run {run_id}")
    comparisons = (
        ("strategy", "strategy"),
        ("scenario", "scenario_id"),
        ("traffic_profile", "traffic_profile_id"),
        ("block", "block"),
        ("schedule_seed", "schedule_seed"),
        ("ordinal", "ordinal"),
        ("config_sha256", "config_sha256"),
    )
    mismatches = [
        manifest_field
        for manifest_field, schedule_field in comparisons
        if manifest.get(manifest_field) != registered.get(schedule_field)
    ]
    if manifest.get("schedule_seed") != schedule.get("schedule_seed"):
        mismatches.append("schedule_seed_header")
    if manifest.get("config_sha256") != schedule.get("config_sha256"):
        mismatches.append("config_sha256_header")
    if mismatches:
        raise AnalysisInputError(
            f"registered schedule mismatch for run {run_id}: {sorted(set(mismatches))}"
        )


def _select_terminal_attempt_bundles(
    bundles: Sequence[_ValidatedBundleSnapshot],
    registered_schedule: _RegisteredScheduleInput,
) -> list[_ValidatedBundleSnapshot]:
    if registered_schedule.document.get("schema_version") != (
        REGISTERED_SCHEDULE_SCHEMA_VERSION
    ):
        raise AnalysisInputError("attempt evidence requires a schema 2 schedule")
    scope_keys = set()
    by_cell: dict[str, list[_ValidatedBundleSnapshot]] = defaultdict(list)
    for bundle in bundles:
        manifest = bundle.manifest
        provenance = manifest.get("provenance")
        commit = provenance.get("git_commit") if isinstance(provenance, Mapping) else None
        scope_keys.add(
            (
                manifest.get("campaign_stage"),
                manifest.get("schedule_sha256"),
                manifest.get("config_sha256"),
                commit,
            )
        )
        if manifest.get("schedule_sha256") != registered_schedule.sha256:
            raise AnalysisInputError(
                "attempt manifest schedule_sha256 does not match registration"
            )
        if manifest.get("campaign_stage") != registered_schedule.campaign_stage:
            raise AnalysisInputError(
                "attempt manifest campaign_stage does not match registration"
            )
        by_cell[str(manifest.get("cell_id", ""))].append(bundle)
    if len(scope_keys) != 1:
        raise AnalysisInputError("attempt dataset contains more than one collection scope")

    selected: list[_ValidatedBundleSnapshot] = []
    for cell_id, attempts in sorted(by_cell.items()):
        ordered = sorted(
            attempts, key=lambda item: int(item.manifest["attempt_number"])
        )
        maximum = registered_schedule.max_attempts_per_cell
        if maximum is None or len(ordered) > maximum:
            raise AnalysisInputError(
                f"attempt chain for cell {cell_id} exceeds the registered budget"
            )
        numbers = [int(item.manifest["attempt_number"]) for item in ordered]
        if numbers != list(range(1, len(ordered) + 1)):
            raise AnalysisInputError(
                f"attempt chain for cell {cell_id} is not contiguous"
            )
        predecessor: str | None = None
        complete_seen = False
        for item in ordered:
            manifest = item.manifest
            if manifest.get("supersedes_attempt_id") != predecessor:
                raise AnalysisInputError(
                    f"attempt chain for cell {cell_id} has an invalid predecessor"
                )
            if complete_seen:
                raise AnalysisInputError(
                    f"attempt chain for cell {cell_id} continues after complete"
                )
            if manifest.get("status") == "complete":
                complete_seen = True
            predecessor = str(manifest.get("attempt_id", ""))
        if ordered[-1].manifest.get("status") != "complete":
            raise AnalysisInputError(
                f"attempt chain for cell {cell_id} has no complete terminal attempt"
            )
        selected.append(ordered[-1])
    return selected


def _scan_json_artifacts_bytes(artifacts: Mapping[str, bytes]) -> str | None:
    for name, content in sorted(artifacts.items()):
        if name in {"manifest.json", "SHA256SUMS"}:
            continue
        suffix = Path(name).suffix.lower()
        if suffix == ".json":
            try:
                if len(content) > MAX_JSON_BYTES:
                    raise ValueError(f"exceeds {MAX_JSON_BYTES} bytes")
                value = json.loads(content.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError, ValueError) as error:
                raise AnalysisInputError(
                    f"invalid JSON provenance artifact {name}"
                ) from error
            marker = _generated_marker(value, name)
            if marker:
                return marker
        elif suffix == ".jsonl":
            for line_number, raw_line in enumerate(content.splitlines(keepends=True), 1):
                if len(raw_line) > MAX_JSON_BYTES:
                    raise AnalysisInputError(
                        f"invalid JSONL provenance artifact {name}:{line_number}: "
                        f"exceeds {MAX_JSON_BYTES} bytes"
                    )
                if not raw_line.strip():
                    continue
                try:
                    value = json.loads(raw_line.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError) as error:
                    raise AnalysisInputError(
                        f"invalid JSONL provenance artifact {name}:{line_number}"
                    ) from error
                marker = _generated_marker(value, f"{name}[{line_number}]")
                if marker:
                    return marker
    return None


def _scan_hashed_json_artifacts(bundle_path: Path) -> str | None:
    """Compatibility wrapper for callers outside the validated load path."""

    artifacts: dict[str, bytes] = {}
    try:
        for path in bundle_path.iterdir():
            if path.is_file():
                artifacts[path.name] = path.read_bytes()
    except OSError as error:
        raise AnalysisInputError(
            f"cannot read JSON provenance artifacts in {bundle_path.name}"
        ) from error
    return _scan_json_artifacts_bytes(artifacts)


def _bounded_sorted_bundle_directories(raw_dir: Path) -> tuple[Path, ...]:
    bundles: list[Path] = []
    try:
        for path in raw_dir.iterdir():
            if not path.is_dir():
                continue
            bundles.append(path)
            if len(bundles) > MAX_DATASET_BUNDLES:
                raise AnalysisInputError(
                    f"raw evidence contains more than {MAX_DATASET_BUNDLES} "
                    "bundle directories"
                )
    except OSError as error:
        raise AnalysisInputError(
            f"cannot inventory raw evidence directory {raw_dir}: {error}"
        ) from error
    return tuple(sorted(bundles, key=lambda path: path.name))


def _load_validated_dataset(
    raw_dir: Path,
    *,
    dataset_id: str,
    schedule_path: Path | None = None,
    registered_schedule: _RegisteredScheduleInput | None = None,
) -> _ValidatedDataset:
    """Capture all valid attempts and select terminal measured evidence."""
    raw_dir = Path(raw_dir)
    if not raw_dir.is_dir():
        raise AnalysisInputError(f"raw evidence directory does not exist: {raw_dir}")
    if schedule_path is not None and registered_schedule is not None:
        raise AnalysisInputError(
            "schedule_path and registered_schedule cannot both be provided"
        )
    loaded_schedule = registered_schedule
    if schedule_path is not None:
        loaded_schedule = _load_registered_schedule(schedule_path, dataset_id)
    schedule = loaded_schedule.document if loaded_schedule is not None else None
    registry = loaded_schedule.registry if loaded_schedule is not None else None
    eligible_bundles: list[_ValidatedBundleSnapshot] = []
    for bundle_path in _bounded_sorted_bundle_directories(raw_dir):
        validation = validate_evidence_bundle(bundle_path)
        if not validation.valid:
            raise AnalysisInputError(
                format_validation_diagnostics(
                    validation.errors,
                    prefix=(
                        f"run {bundle_path.name} failed evidence validation; "
                        "invalid manifest or evidence: "
                    ),
                )
            )
        manifest = validation.manifest
        if not isinstance(manifest, Mapping):
            raise AnalysisInputError(
                f"{bundle_path.name} validator returned no manifest snapshot"
            )
        artifacts = validation.artifacts
        if not isinstance(artifacts, Mapping):
            raise AnalysisInputError(
                f"{bundle_path.name} validator returned no immutable artifact snapshot"
            )
        sums_digest = validation.sha256sums_sha256
        if not isinstance(sums_digest, str) or not re.fullmatch(
            r"[0-9a-f]{64}", sums_digest
        ):
            raise AnalysisInputError(
                f"{bundle_path.name} validator returned no SHA256SUMS digest snapshot"
            )
        if manifest.get("dataset_id") != dataset_id:
            continue
        if schedule is not None and registry is not None:
            _validate_registered_manifest(manifest, schedule, registry)
        marker = _generated_marker(manifest)
        if marker:
            raise AnalysisInputError(
                format_validation_diagnostics(
                    (marker,),
                    prefix=(
                        f"run {bundle_path.name} contains generated-data marker at "
                    ),
                )
            )
        checked = set(validation.checked_files)
        required_evidence = {"manifest.json", "packets.csv", "events.jsonl"}
        actual_evidence = set(artifacts) - {"SHA256SUMS"}
        uncovered = (required_evidence | actual_evidence) - checked
        if uncovered:
            raise AnalysisInputError(
                f"run {bundle_path.name} has evidence not covered by SHA256SUMS: "
                f"{sorted(uncovered)}"
            )
        declared_hashes = manifest.get("evidence_sha256")
        declared_files = actual_evidence - {"manifest.json"}
        if (
            not isinstance(declared_hashes, Mapping)
            or set(declared_hashes) != declared_files
        ):
            raise AnalysisInputError(
                f"run {bundle_path.name} manifest.evidence_sha256 does not cover evidence"
            )
        mismatched_hashes = [
            name
            for name in sorted(declared_files)
            if name not in artifacts
            or declared_hashes.get(name)
            != hashlib.sha256(artifacts[name]).hexdigest()
        ]
        if mismatched_hashes:
            raise AnalysisInputError(
                f"run {bundle_path.name} manifest.evidence_sha256 mismatch: "
                f"{mismatched_hashes}"
            )
        artifact_marker = _scan_json_artifacts_bytes(artifacts)
        if artifact_marker:
            raise AnalysisInputError(
                format_validation_diagnostics(
                    (artifact_marker,),
                    prefix=(
                        f"run {bundle_path.name} contains generated-data marker at "
                    ),
                )
            )
        eligible_bundles.append(
            _ValidatedBundleSnapshot(
                path=bundle_path,
                manifest=manifest,
                artifacts=artifacts,
                sha256sums_sha256=sums_digest,
            )
        )
    if not eligible_bundles:
        raise AnalysisInputError(
            f"dataset {dataset_id!r} contains no complete measured runs"
        )
    versions = {
        bundle.manifest.get("schema_version") for bundle in eligible_bundles
    }
    if CURRENT_MANIFEST_SCHEMA_VERSION in versions:
        if versions != {CURRENT_MANIFEST_SCHEMA_VERSION}:
            raise AnalysisInputError(
                "dataset mixes attempt evidence with legacy run evidence"
            )
        if loaded_schedule is None:
            raise AnalysisInputError(
                "attempt evidence requires a frozen registered schedule"
            )
        selected_bundles = _select_terminal_attempt_bundles(
            eligible_bundles,
            loaded_schedule,
        )
    else:
        incomplete = [
            bundle.path.name
            for bundle in eligible_bundles
            if bundle.manifest.get("status") != "complete"
        ]
        if incomplete:
            raise AnalysisInputError(
                f"confirmatory run {incomplete[0]} is incomplete"
            )
        selected_bundles = eligible_bundles
    records = [
        _record_from_bundle(bundle.path, bundle.manifest, bundle.artifacts)
        for bundle in selected_bundles
    ]
    if registry is not None:
        observed_ids = {record.run_id for record in records}
        if observed_ids != set(registry):
            missing = sorted(set(registry) - observed_ids)
            extra = sorted(observed_ids - set(registry))
            raise AnalysisInputError(
                "registered schedule mismatch after loading; "
                f"missing={missing}, extra={extra}"
            )
    return _ValidatedDataset(
        records=tuple(records),
        bundles=tuple(eligible_bundles),
        selected_bundle_names=frozenset(bundle.path.name for bundle in selected_bundles),
        max_attempts_per_cell=(
            loaded_schedule.max_attempts_per_cell
            if loaded_schedule is not None
            else None
        ),
    )


def load_validated_runs(
    raw_dir: Path,
    *,
    dataset_id: str,
    schedule_path: Path | None = None,
    registered_schedule: _RegisteredScheduleInput | None = None,
) -> list[RunRecord]:
    """Load only hash-valid terminal complete measured evidence bundles."""

    loaded = _load_validated_dataset(
        raw_dir,
        dataset_id=dataset_id,
        schedule_path=schedule_path,
        registered_schedule=registered_schedule,
    )
    return list(loaded.records)


def validate_confirmatory_matrix(
    records: Sequence[RunRecord],
    *,
    expected_run_count: int,
    expected_strategies: Sequence[str] = DEFAULT_STRATEGIES,
) -> None:
    """Require an exact, duplicate-free strategy set in every paired cell."""
    strategies = tuple(expected_strategies)
    if not strategies or len(strategies) != len(set(strategies)):
        raise AnalysisInputError("expected strategies must be unique and non-empty")
    if len(records) != expected_run_count:
        raise AnalysisInputError(
            f"expected {expected_run_count} runs but observed {len(records)}"
        )
    run_ids = [record.run_id for record in records]
    if len(run_ids) != len(set(run_ids)):
        raise AnalysisInputError("run table contains duplicate run IDs")
    cells: dict[tuple[int, str, str], list[str]] = defaultdict(list)
    for record in records:
        if record.strategy not in strategies:
            raise AnalysisInputError(f"unexpected strategy {record.strategy!r}")
        cells[record.pairing_key].append(record.strategy)
    expected = set(strategies)
    problems = []
    for key, observed in sorted(cells.items()):
        if len(observed) != len(strategies) or set(observed) != expected:
            problems.append(f"{key}: {sorted(observed)}")
    if problems:
        raise AnalysisInputError(
            "incomplete or duplicate paired cell: " + "; ".join(problems)
        )
    layouts: dict[int, set[tuple[str, str]]] = defaultdict(set)
    for block, scenario, traffic_profile in cells:
        layouts[block].add((scenario, traffic_profile))
    reference_block, reference_layout = min(layouts.items())
    mismatched = [
        block for block, layout in sorted(layouts.items()) if layout != reference_layout
    ]
    if mismatched:
        raise AnalysisInputError(
            f"block cell layout differs from block {reference_block}: {mismatched}"
        )


def _outlier_rows(records: Sequence[RunRecord]) -> list[dict[str, object]]:
    outliers: list[dict[str, object]] = []
    for metric in DESCRIPTIVE_METRICS:
        available = [(record, record.metric(metric)) for record in records]
        if len(available) < 4:
            continue
        values = [value for _, value in available]
        first_quartile = _linear_quantile(values, 0.25)
        third_quartile = _linear_quantile(values, 0.75)
        spread = third_quartile - first_quartile
        lower = first_quartile - 1.5 * spread
        upper = third_quartile + 1.5 * spread
        for record, value in available:
            if value < lower or value > upper:
                outliers.append(
                    {
                        "run_id": record.run_id,
                        "metric": metric,
                        "value": value,
                        "lower_fence": lower,
                        "upper_fence": upper,
                        "action": "reported_not_removed",
                    }
                )
    return outliers


def build_quality_control(
    records: Sequence[RunRecord],
    *,
    expected_run_count: int,
    expected_strategies: Sequence[str] = DEFAULT_STRATEGIES,
) -> dict[str, object]:
    """Build a passing QC record without excluding flagged observations."""
    validate_confirmatory_matrix(
        records,
        expected_run_count=expected_run_count,
        expected_strategies=expected_strategies,
    )
    cells: dict[tuple[int, str, str], list[str]] = defaultdict(list)
    for record in records:
        cells[record.pairing_key].append(record.strategy)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "expected_run_count": expected_run_count,
        "observed_run_count": len(records),
        "accepted_run_count": len(records),
        "incomplete_run_count": 0,
        "sent_packet_count": sum(record.sent_count for record in records),
        "received_packet_count": sum(record.received_count for record in records),
        "timed_out_packet_count": sum(
            record.sent_count - record.received_count for record in records
        ),
        "missing_packet_count": sum(
            record.sent_count - record.received_count for record in records
        ),
        "protocol_violations": [],
        "paired_cells": [
            {
                "block": key[0],
                "scenario": key[1],
                "traffic_profile": key[2],
                "strategies": sorted(strategies),
            }
            for key, strategies in sorted(cells.items())
        ],
        "outliers": _outlier_rows(records),
        "outlier_policy": "report_only_no_automatic_exclusion",
    }


def _source_bundle_ledger(
    loaded: _ValidatedDataset, *, dataset_id: str
) -> dict[str, object]:
    bundles: list[dict[str, object]] = []
    for bundle in loaded.bundles:
        manifest = bundle.manifest
        is_attempt = (
            manifest.get("schema_version") == CURRENT_MANIFEST_SCHEMA_VERSION
        )
        run_id = str(
            manifest.get("cell_id" if is_attempt else "run_id", "")
        )
        selected = bundle.path.name in loaded.selected_bundle_names
        bundles.append(
            {
                "run_id": run_id,
                "bundle": bundle.path.name,
                "evidence_schema_version": manifest.get("schema_version"),
                "identity_model": "attempt_chain" if is_attempt else "legacy_run",
                "attempt_id": manifest.get("attempt_id") if is_attempt else None,
                "attempt_number": (
                    manifest.get("attempt_number") if is_attempt else None
                ),
                "supersedes_attempt_id": (
                    manifest.get("supersedes_attempt_id") if is_attempt else None
                ),
                "status": manifest.get("status"),
                "failure_reason": manifest.get("failure_reason"),
                "terminal": selected,
                "selected_for_analysis": selected,
                "sha256sums_sha256": bundle.sha256sums_sha256,
            }
        )
    bundles.sort(
        key=lambda item: (
            str(item["run_id"]),
            int(item["attempt_number"] or 1),
            str(item["bundle"]),
        )
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "dataset_id": dataset_id,
        "source_kind": "measured_evidence_bundles",
        "retained_bundle_count": len(bundles),
        "selected_terminal_bundle_count": len(loaded.selected_bundle_names),
        "bundles": bundles,
    }


def _attempt_quality_counts(loaded: _ValidatedDataset) -> dict[str, object]:
    current = all(
        bundle.manifest.get("schema_version") == CURRENT_MANIFEST_SCHEMA_VERSION
        for bundle in loaded.bundles
    )
    if not current:
        return {
            "attempt_identity_model": "legacy_single_run",
            "retained_attempt_count": None,
            "incomplete_predecessor_attempt_count": None,
            "terminal_attempt_count": None,
            "attempt_budget_exhausted_cell_count": None,
        }

    by_cell: dict[str, int] = defaultdict(int)
    incomplete_count = 0
    for bundle in loaded.bundles:
        manifest = bundle.manifest
        by_cell[str(manifest["cell_id"])] += 1
        if manifest.get("status") == "incomplete":
            incomplete_count += 1
    maximum = loaded.max_attempts_per_cell
    exhausted_count = (
        sum(count == maximum for count in by_cell.values())
        if maximum is not None
        else None
    )
    return {
        "attempt_identity_model": "attempt_chain_v1.2",
        "retained_attempt_count": len(loaded.bundles),
        "incomplete_predecessor_attempt_count": incomplete_count,
        "terminal_attempt_count": len(loaded.selected_bundle_names),
        "attempt_budget_exhausted_cell_count": exhausted_count,
    }


def align_paired_differences(
    records: Sequence[RunRecord],
    *,
    baseline_strategy: str,
    alternative_strategy: str,
    metric: str,
) -> list[PairedDifference]:
    """Align two strategies within block, scenario, and traffic profile."""
    cells: dict[tuple[int, str, str], dict[str, RunRecord]] = defaultdict(dict)
    for record in records:
        if record.strategy not in {baseline_strategy, alternative_strategy}:
            continue
        cell = cells[record.pairing_key]
        if record.strategy in cell:
            raise AnalysisInputError(
                f"duplicate {record.strategy} run in paired cell {record.pairing_key}"
            )
        cell[record.strategy] = record
    pairs: list[PairedDifference] = []
    for key, cell in sorted(cells.items()):
        if set(cell) != {baseline_strategy, alternative_strategy}:
            raise AnalysisInputError(f"unmatched paired cell {key}")
        baseline_record = cell[baseline_strategy]
        alternative_record = cell[alternative_strategy]
        baseline = baseline_record.metric(metric)
        alternative = alternative_record.metric(metric)
        pairs.append(
            PairedDifference(
                key=key,
                baseline_run_id=baseline_record.run_id,
                alternative_run_id=alternative_record.run_id,
                baseline=baseline,
                alternative=alternative,
                difference=alternative - baseline,
            )
        )
    if not pairs:
        raise AnalysisInputError(
            f"no pairs for {alternative_strategy} versus {baseline_strategy}"
        )
    return pairs


def aggregate_block_differences(
    pairs: Sequence[PairedDifference],
) -> tuple[BlockDifference, ...]:
    """Average paired cell differences within each independent block."""
    if not pairs:
        raise AnalysisInputError("block aggregation requires at least one pair")
    groups: dict[int, list[PairedDifference]] = defaultdict(list)
    for pair in pairs:
        groups[pair.key[0]].append(pair)
    return tuple(
        BlockDifference(
            block=block,
            difference=statistics.fmean(pair.difference for pair in block_pairs),
            cell_count=len(block_pairs),
        )
        for block, block_pairs in sorted(groups.items())
    )


def bootstrap_mean_ci(
    differences: Sequence[float],
    *,
    samples: int = 10_000,
    seed: int = 20260803,
    confidence: float = 0.95,
) -> BootstrapInterval:
    """Return a deterministic non-parametric paired bootstrap interval."""
    values = tuple(float(value) for value in differences)
    if not values or any(not math.isfinite(value) for value in values):
        raise AnalysisInputError("bootstrap differences must be finite and non-empty")
    if samples < 100:
        raise AnalysisInputError("bootstrap samples must be at least 100")
    if not 0 < confidence < 1:
        raise AnalysisInputError("bootstrap confidence must be between zero and one")
    generator = random.Random(seed)
    estimates = []
    for _ in range(samples):
        estimates.append(
            statistics.fmean(generator.choice(values) for _ in range(len(values)))
        )
    tail = (1.0 - confidence) / 2.0
    return BootstrapInterval(
        lower=_linear_quantile(estimates, tail),
        upper=_linear_quantile(estimates, 1.0 - tail),
    )


def paired_standardised_effect(differences: Sequence[float]) -> float | None:
    """Calculate Cohen's dz; return None for a non-zero constant difference."""
    values = tuple(float(value) for value in differences)
    if not values or any(not math.isfinite(value) for value in values):
        raise AnalysisInputError("paired differences must be finite and non-empty")
    if all(math.isclose(value, 0.0, abs_tol=1e-15) for value in values):
        return 0.0
    if len(values) < 2:
        return None
    deviation = statistics.stdev(values)
    if math.isclose(deviation, 0.0, abs_tol=1e-15):
        return None
    return statistics.fmean(values) / deviation


def holm_adjusted(p_values: Sequence[float]) -> tuple[float, ...]:
    """Adjust a family of p-values using Holm's step-down procedure."""
    values = tuple(float(value) for value in p_values)
    if any(not math.isfinite(value) or not 0 <= value <= 1 for value in values):
        raise AnalysisInputError("p-values must be finite and between zero and one")
    ordered = sorted(enumerate(values), key=lambda item: item[1])
    adjusted = [0.0] * len(values)
    running_max = 0.0
    family_size = len(values)
    for rank, (original_index, value) in enumerate(ordered):
        candidate = min(1.0, (family_size - rank) * value)
        running_max = max(running_max, candidate)
        adjusted[original_index] = running_max
    return tuple(adjusted)


def _wilcoxon(differences: Sequence[float]) -> tuple[float | None, float | None, str]:
    values = tuple(float(value) for value in differences)
    if all(math.isclose(value, 0.0, abs_tol=1e-15) for value in values):
        return 0.0, 1.0, "all_zero_differences"
    if len([value for value in values if not math.isclose(value, 0.0)]) < 2:
        return None, 1.0, "insufficient_nonzero_pairs"
    from scipy.stats import wilcoxon

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result = wilcoxon(
            values, alternative="two-sided", zero_method="wilcox", method="auto"
        )
    statistic = float(result.statistic)
    p_value = float(result.pvalue)
    if not math.isfinite(statistic) or not math.isfinite(p_value):
        return None, 1.0, "undefined"
    return statistic, p_value, "tested"


def _confirmatory_results(
    records: Sequence[RunRecord],
    *,
    analysis_plan: AnalysisPlan,
    bootstrap_samples: int,
    seed: int,
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for contrast_index, contrast in enumerate(analysis_plan.contrasts):
        pairs = align_paired_differences(
            records,
            baseline_strategy=contrast.baseline_strategy,
            alternative_strategy=contrast.alternative_strategy,
            metric=contrast.run_metric,
        )
        blocks = aggregate_block_differences(pairs)
        differences = tuple(block.difference for block in blocks)
        interval = bootstrap_mean_ci(
            differences,
            samples=bootstrap_samples,
            seed=seed + contrast_index,
        )
        effect = paired_standardised_effect(differences)
        statistic, p_value, test_status = _wilcoxon(differences)
        results.append(
            {
                "contrast_id": contrast.contrast_id,
                "endpoint": contrast.endpoint,
                "metric": contrast.run_metric,
                "baseline_strategy": contrast.baseline_strategy,
                "alternative_strategy": contrast.alternative_strategy,
                "direction": (
                    f"{contrast.alternative_strategy} - {contrast.baseline_strategy}; "
                    f"negative favours {contrast.alternative_strategy}"
                ),
                "pair_count": len(pairs),
                "block_count": len(blocks),
                "inference_unit": "block_mean_of_paired_cell_differences",
                "mean_difference": statistics.fmean(differences),
                "bootstrap_95_lower": interval.lower,
                "bootstrap_95_upper": interval.upper,
                "paired_standardised_effect": effect,
                "effect_status": (
                    "estimated" if effect is not None else "undefined_zero_variance"
                ),
                "wilcoxon_statistic": statistic,
                "p_value_raw": p_value,
                "p_value_holm": None,
                "test_status": test_status,
            }
        )
    adjusted = holm_adjusted([float(result["p_value_raw"]) for result in results])
    for result, value in zip(results, adjusted):
        result["p_value_holm"] = value
    return results


def _descriptive_results(records: Sequence[RunRecord]) -> list[dict[str, object]]:
    groups: dict[tuple[str, str, str], list[RunRecord]] = defaultdict(list)
    for record in records:
        groups[(record.scenario, record.traffic_profile, record.strategy)].append(
            record
        )
    results = []
    for (scenario, traffic_profile, strategy), group in sorted(groups.items()):
        for metric in DESCRIPTIVE_METRICS:
            values = [record.metric(metric) for record in group]
            results.append(
                {
                    "scenario": scenario,
                    "traffic_profile": traffic_profile,
                    "strategy": strategy,
                    "metric": metric,
                    "n": len(values),
                    "mean": statistics.fmean(values),
                    "standard_deviation": (
                        statistics.stdev(values) if len(values) > 1 else None
                    ),
                    "median": statistics.median(values),
                    "p95": _linear_quantile(values, 0.95),
                }
            )
    return results


def _csv_value(value: object) -> object:
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    return value


def _write_csv(
    path: Path, fields: Sequence[str], rows: Iterable[Mapping[str, object]]
) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: _csv_value(row.get(field)) for field in fields})


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
        + "\n",
        encoding="utf-8",
    )


def _write_figures(
    records: Sequence[RunRecord],
    confirmatory: Sequence[Mapping[str, object]],
    output_dir: Path,
    strategies: Sequence[str],
) -> list[str]:
    import matplotlib.pyplot as plt

    output_dir.mkdir()
    colours = ("#555555", "#0072B2", "#009E73")
    figure_names: list[str] = []

    figure, axes = plt.subplots(1, 2, figsize=(8.0, 4.5), constrained_layout=True)
    for axis, metric, label in zip(
        axes,
        PRIMARY_METRICS,
        ("Run-level mean RTT (ms)", "Packet loss (%)"),
    ):
        distributions = [
            [record.metric(metric) for record in records if record.strategy == strategy]
            for strategy in strategies
        ]
        boxplot = axis.boxplot(
            distributions,
            positions=range(1, len(strategies) + 1),
            widths=0.6,
            patch_artist=True,
        )
        for patch, colour in zip(boxplot["boxes"], colours):
            patch.set_facecolor(colour)
            patch.set_alpha(0.8)
        axis.set_xticks(range(1, len(strategies) + 1), strategies)
        axis.set_ylabel(label)
        axis.grid(axis="y", alpha=0.25)
    base_name = "primary-endpoints-by-strategy"
    _save_figure(figure, output_dir / base_name)
    plt.close(figure)
    figure_names.extend([f"figures/{base_name}.png", f"figures/{base_name}.pdf"])

    figure, axes = plt.subplots(1, 2, figsize=(9.0, 4.5), constrained_layout=True)
    endpoint_labels = {
        "rtt_mean_ms": "Paired run-mean RTT difference (ms)",
        "loss_pct": "Paired mean packet-loss difference (percentage points)",
    }
    for axis, metric in zip(axes, PRIMARY_METRICS):
        rows = [row for row in confirmatory if row["metric"] == metric]
        labels = [
            f"{row['alternative_strategy']} vs {row['baseline_strategy']}"
            for row in rows
        ]
        estimates = [float(row["mean_difference"]) for row in rows]
        lowers = [float(row["bootstrap_95_lower"]) for row in rows]
        uppers = [float(row["bootstrap_95_upper"]) for row in rows]
        positions = list(range(len(labels)))
        axis.errorbar(
            estimates,
            positions,
            xerr=(
                [estimate - lower for estimate, lower in zip(estimates, lowers)],
                [upper - estimate for estimate, upper in zip(estimates, uppers)],
            ),
            fmt="o",
            color="#0072B2",
            ecolor="#555555",
            capsize=4,
        )
        axis.axvline(0.0, color="#222222", linewidth=1, linestyle="--")
        axis.set_yticks(positions, labels)
        axis.set_xlabel(endpoint_labels[metric])
        axis.grid(axis="x", alpha=0.25)
    base_name = "confirmatory-paired-differences"
    _save_figure(figure, output_dir / base_name)
    plt.close(figure)
    figure_names.extend([f"figures/{base_name}.png", f"figures/{base_name}.pdf"])
    return figure_names


def _save_figure(figure: Any, base_path: Path) -> None:
    title = base_path.name.replace("-", " ").title()
    figure.savefig(
        base_path.with_suffix(".png"),
        dpi=300,
        metadata={
            "Title": title,
            "Author": "Adaptive VPN research pipeline",
            "Description": "Generated only from validated measured evidence bundles",
            "Software": "adaptive-vpn-research",
        },
    )
    figure.savefig(
        base_path.with_suffix(".pdf"),
        metadata={
            "Title": title,
            "Author": "Adaptive VPN research pipeline",
            "Subject": "Validated measured adaptive VPN experiment results",
            "Creator": "adaptive-vpn-research",
            "Producer": "adaptive-vpn-research",
            "CreationDate": None,
            "ModDate": None,
        },
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_checksums(root: Path) -> None:
    artifacts = sorted(
        path for path in root.rglob("*") if path.is_file() and path.name != "SHA256SUMS"
    )
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{_sha256_file(path)}  {path.relative_to(root).as_posix()}\n"
            for path in artifacts
        ),
        encoding="ascii",
    )


def _capture_processed_tree(root: Path) -> _ProcessedTreeSnapshot:
    files: list[tuple[str, tuple[int, ...], str]] = []
    directories: list[tuple[str, tuple[int, ...]]] = []
    entry_count = 0
    total_bytes = 0

    def visit(directory: Path) -> None:
        nonlocal entry_count, total_bytes
        for candidate in _bounded_sorted_directory_entries(directory):
            entry_count += 1
            if entry_count > MAX_BUNDLE_ENTRIES:
                raise AnalysisInputError(
                    f"processed dataset has more than {MAX_BUNDLE_ENTRIES} entries"
                )
            relative = candidate.relative_to(root).as_posix()
            observed = os.lstat(candidate)
            if _is_real_directory_stat(observed):
                directories.append((relative, _directory_identity(observed)))
                visit(candidate)
                continue
            if not _is_regular_file_stat(observed):
                raise AnalysisInputError(
                    f"processed artifact {relative} is not a regular file"
                )
            remaining = MAX_EVIDENCE_BUNDLE_BYTES - total_bytes
            if remaining < 0:
                raise AnalysisInputError(
                    f"processed dataset exceeds {MAX_EVIDENCE_BUNDLE_BYTES} bytes"
                )
            content, snapshot = _read_bounded_regular_bytes(
                candidate,
                maximum_bytes=min(MAX_EVIDENCE_ARTIFACT_BYTES, remaining),
                label=f"processed artifact {relative}",
            )
            total_bytes += len(content)
            files.append(
                (relative, tuple(snapshot[:-1]), hashlib.sha256(content).hexdigest())
            )

    try:
        observed_root = os.lstat(root)
        if not _is_real_directory_stat(observed_root):
            raise AnalysisInputError("processed staging root must be a real directory")
        visit(root)
    except AnalysisInputError:
        raise
    except (OSError, ValueError) as error:
        raise AnalysisInputError(
            f"cannot capture processed dataset identity: {error}"
        ) from error
    return _ProcessedTreeSnapshot(
        files=tuple(sorted(files)),
        directories=tuple(sorted(directories)),
    )


def _validate_processed_checksums(
    root: Path, snapshot: _ProcessedTreeSnapshot
) -> None:
    observed_hashes = {
        relative: digest
        for relative, _identity, digest in snapshot.files
        if relative != "SHA256SUMS"
    }
    if "SHA256SUMS" not in {relative for relative, _identity, _digest in snapshot.files}:
        raise AnalysisInputError("processed SHA256SUMS is missing")
    try:
        content, _snapshot = _read_bounded_regular_bytes(
            root / "SHA256SUMS",
            maximum_bytes=MAX_EVIDENCE_ARTIFACT_BYTES,
            label="processed SHA256SUMS",
        )
        lines = content.decode("ascii").splitlines()
    except (OSError, UnicodeError, ValueError) as error:
        raise AnalysisInputError(f"processed SHA256SUMS is invalid: {error}") from error
    declared: dict[str, str] = {}
    for line_number, line in enumerate(lines, 1):
        digest, separator, name = line.partition("  ")
        path = PurePosixPath(name)
        if (
            not separator
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not name
            or path.is_absolute()
            or ".." in path.parts
            or "\\" in name
            or name == "SHA256SUMS"
        ):
            raise AnalysisInputError(
                f"processed SHA256SUMS line {line_number} is invalid"
            )
        if name in declared:
            raise AnalysisInputError(
                f"processed SHA256SUMS repeats artifact {name}"
            )
        declared[name] = digest
    if declared != observed_hashes:
        raise AnalysisInputError(
            "processed SHA256SUMS does not match the captured artifact tree"
        )


def _sync_and_capture_processed_tree(root: Path) -> _ProcessedTreeSnapshot:
    snapshot = _capture_processed_tree(root)
    for relative, _identity, _digest in snapshot.files:
        _fsync_file(root / relative)
    for relative, _identity in sorted(
        snapshot.directories,
        key=lambda item: len(Path(item[0]).parts),
        reverse=True,
    ):
        _fsync_directory(root / relative)
    _fsync_directory(root)
    synced = _capture_processed_tree(root)
    if synced != snapshot:
        raise AnalysisInputError(
            "processed dataset identity changed while making staging durable"
        )
    _validate_processed_checksums(root, synced)
    return synced


def _publish_processed_tree(
    staging: Path,
    destination: Path,
    expected: _ProcessedTreeSnapshot,
) -> None:
    _publish_directory_no_replace(staging, destination)
    try:
        observed = _capture_processed_tree(destination)
        if observed != expected:
            raise AnalysisInputError(
                "published processed dataset differs from durable staging snapshot"
            )
    except BaseException as validation_error:
        try:
            _publish_directory_no_replace(destination, staging)
        except BaseException as rollback_error:  # noqa: BLE001 - preserve both failures
            raise BaseExceptionGroup(
                "processed publication validation and rollback failures",
                [validation_error, rollback_error],
            ) from validation_error
        raise


def analyse_dataset(
    *,
    raw_dir: Path,
    processed_root: Path,
    dataset_id: str,
    expected_run_count: int = 432,
    expected_strategies: Sequence[str] = DEFAULT_STRATEGIES,
    bootstrap_samples: int = 10_000,
    seed: int = 20260803,
    analysis_plan_path: Path = DEFAULT_ANALYSIS_PLAN_PATH,
    schedule_path: Path | None = None,
    allow_unregistered_legacy_schedule: bool = False,
) -> Path:
    """Create an immutable processed dataset and all pre-specified outputs."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", dataset_id):
        raise AnalysisInputError("dataset_id is not a safe path component")
    if type(allow_unregistered_legacy_schedule) is not bool:
        raise AnalysisInputError(
            "allow_unregistered_legacy_schedule must be boolean"
        )
    analysis_plan = load_analysis_plan(analysis_plan_path)
    expected_strategy_set = set(expected_strategies)
    for contrast in analysis_plan.contrasts:
        referenced = {contrast.baseline_strategy, contrast.alternative_strategy}
        if not referenced <= expected_strategy_set:
            raise AnalysisInputError(
                f"contrast {contrast.contrast_id} references an unexpected strategy"
            )
    legacy_unregistered_schedule = False
    if schedule_path is None:
        registered_schedule_path = _discover_registered_schedule(dataset_id)
    else:
        supplied_schedule_path = Path(os.path.abspath(schedule_path))
        try:
            registered_schedule_path = _discover_registered_schedule(dataset_id)
        except _ScheduleRegistrationNotFound:
            if not allow_unregistered_legacy_schedule:
                raise
            registered_schedule_path = supplied_schedule_path
            legacy_unregistered_schedule = True
        if supplied_schedule_path != registered_schedule_path:
            raise AnalysisInputError(
                "explicit schedule path does not match the dataset registration"
            )
    registered_schedule = _load_registered_schedule(
        registered_schedule_path,
        dataset_id,
    )
    loaded = _load_validated_dataset(
        raw_dir,
        dataset_id=dataset_id,
        registered_schedule=registered_schedule,
    )
    records = loaded.records
    quality = build_quality_control(
        records,
        expected_run_count=expected_run_count,
        expected_strategies=expected_strategies,
    )
    quality.update(_attempt_quality_counts(loaded))
    confirmatory = _confirmatory_results(
        records,
        analysis_plan=analysis_plan,
        bootstrap_samples=bootstrap_samples,
        seed=seed,
    )
    descriptive = _descriptive_results(records)

    processed_root = Path(processed_root)
    processed_root.mkdir(parents=True, exist_ok=True)
    destination = processed_root / dataset_id
    staging_parent = processed_root / ".staging"
    staging_parent.mkdir(exist_ok=True)
    _probe_directory_publish_capability(staging_parent, processed_root)
    if destination.exists():
        raise FileExistsError(f"processed dataset already exists: {destination}")
    staging = staging_parent / str(uuid.uuid4())
    staging.mkdir()
    _write_csv(
        staging / "runs.csv", RUN_TABLE_FIELDS, (asdict(record) for record in records)
    )
    _write_json(staging / "quality-control.json", quality)
    _write_csv(staging / "confirmatory-results.csv", CONFIRMATORY_FIELDS, confirmatory)
    _write_csv(staging / "descriptive-results.csv", DESCRIPTIVE_FIELDS, descriptive)
    figures = _write_figures(
        records, confirmatory, staging / "figures", expected_strategies
    )
    source_bundles = _source_bundle_ledger(loaded, dataset_id=dataset_id)
    _write_json(
        staging / "source-bundles.json",
        source_bundles,
    )
    report = {
        "schema_version": SCHEMA_VERSION,
        "dataset_id": dataset_id,
        "source_kind": "measured_evidence_bundles",
        "analysis_parameters": {
            "experimental_unit": "complete_run",
            "pairing_keys": ["block", "scenario", "traffic_profile"],
            "expected_run_count": expected_run_count,
            "expected_strategies": list(expected_strategies),
            "bootstrap_samples": bootstrap_samples,
            "bootstrap_seed": seed,
            "multiple_testing": "Holm",
            "confirmatory_alpha": analysis_plan.alpha,
            "analysis_plan": str(analysis_plan.source_path),
            "analysis_plan_sha256": analysis_plan.source_sha256,
            "confirmatory_family": [
                contrast.contrast_id for contrast in analysis_plan.contrasts
            ],
            "registered_schedule": str(registered_schedule.path),
            "registered_schedule_sha256": registered_schedule.sha256,
            "legacy_unregistered_schedule": legacy_unregistered_schedule,
        },
        "quality_control": quality,
        "confirmatory_results": confirmatory,
        "descriptive_results": descriptive,
        "figures": figures,
    }
    _write_json(staging / "analysis-report.json", report)
    _write_checksums(staging)
    processed_snapshot = _sync_and_capture_processed_tree(staging)
    _publish_processed_tree(staging, destination, processed_snapshot)
    return destination


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--processed-root", type=Path, default=Path("data/processed"))
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--expected-runs", type=int, default=432)
    parser.add_argument("--bootstrap-samples", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=20260803)
    parser.add_argument("--plan", type=Path, default=DEFAULT_ANALYSIS_PLAN_PATH)
    parser.add_argument("--schedule", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    destination = analyse_dataset(
        raw_dir=args.raw,
        processed_root=args.processed_root,
        dataset_id=args.dataset,
        expected_run_count=args.expected_runs,
        bootstrap_samples=args.bootstrap_samples,
        seed=args.seed,
        analysis_plan_path=args.plan,
        schedule_path=args.schedule,
    )
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
