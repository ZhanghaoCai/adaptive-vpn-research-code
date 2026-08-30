"""Pure registered-attempt inventory, chain validation, and allocation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

from adaptive_vpn.collector import (
    MAX_DATASET_BUNDLES,
    format_validation_diagnostics,
    validate_evidence_bundle,
)
from adaptive_vpn.config import CampaignStage, ExperimentPlan
from adaptive_vpn.schedule import (
    ScheduleEntry,
    experiment_config_sha256,
    generate_schedule,
)

ATTEMPT_MANIFEST_SCHEMA_VERSION = "1.2.0"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400


class AttemptStateError(ValueError):
    """Raised when registered attempt state cannot be constructed or advanced."""


class AttemptInventoryError(AttemptStateError):
    """Raised when retained attempt evidence violates the registered state model."""


def _is_real_directory(observed: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(observed.st_mode)
        and not stat.S_ISLNK(observed.st_mode)
        and not bool(
            getattr(observed, "st_file_attributes", 0)
            & _FILE_ATTRIBUTE_REPARSE_POINT
        )
    )


@dataclass(frozen=True, slots=True)
class RegisteredCellIdentity:
    cell_id: uuid.UUID
    ordinal: int
    block: int
    scenario_id: str
    traffic_profile_id: str
    strategy: str


@dataclass(frozen=True, slots=True)
class RegisteredAttemptScope:
    dataset_id: str
    campaign_stage: CampaignStage
    schedule_sha256: str
    config_sha256: str
    collection_commit: str
    max_attempts_per_cell: int
    schedule_seed: int
    cells: Mapping[uuid.UUID, RegisteredCellIdentity]
    # Process-local capability proving that an allocation came from this scope.
    _allocation_token: object = field(default_factory=object, repr=False, compare=False)

    @property
    def fingerprint(self) -> str:
        return attempt_scope_fingerprint(self)


@dataclass(frozen=True, slots=True)
class AttemptReservation:
    path: Path
    dataset_id: str
    campaign_stage: str
    schedule_sha256: str
    config_sha256: str
    collection_commit: str
    cell_id: uuid.UUID
    attempt_id: uuid.UUID
    attempt_number: int
    supersedes_attempt_id: uuid.UUID | None
    status: Literal["complete", "incomplete"]


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    path: Path
    cell_id: uuid.UUID
    attempt_id: uuid.UUID
    attempt_number: int
    supersedes_attempt_id: uuid.UUID | None
    status: Literal["complete", "incomplete"]
    failure_reason: str | None
    sha256sums_sha256: str
    manifest: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class AttemptInventory:
    scope_fingerprint: str
    all_current_attempts: tuple[AttemptRecord, ...]
    by_attempt_id: Mapping[uuid.UUID, AttemptReservation]
    by_cell_id: Mapping[uuid.UUID, tuple[AttemptRecord, ...]]
    _allocation_token: object = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class AttemptAllocation:
    cell_id: uuid.UUID
    attempt_id: uuid.UUID
    attempt_number: int
    supersedes_attempt_id: uuid.UUID | None
    scope_fingerprint: str
    _allocation_token: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.scope_fingerprint, str)
            or _SHA256_RE.fullmatch(self.scope_fingerprint) is None
        ):
            raise AttemptStateError(
                "allocation scope_fingerprint must be a lowercase SHA-256 digest"
            )
        if (
            type(self.cell_id) is not uuid.UUID
            or self.cell_id.version != 5
            or self.cell_id.variant != uuid.RFC_4122
        ):
            raise AttemptStateError("allocation cell_id must be an RFC UUIDv5")
        if (
            type(self.attempt_id) is not uuid.UUID
            or self.attempt_id.version != 4
            or self.attempt_id.variant != uuid.RFC_4122
        ):
            raise AttemptStateError("allocation attempt_id must be an RFC UUIDv4")
        if (
            isinstance(self.attempt_number, bool)
            or not isinstance(self.attempt_number, int)
            or self.attempt_number < 1
        ):
            raise AttemptStateError("allocation attempt_number must be positive")
        predecessor = self.supersedes_attempt_id
        if predecessor is not None and (
            type(predecessor) is not uuid.UUID
            or predecessor.version != 4
            or predecessor.variant != uuid.RFC_4122
        ):
            raise AttemptStateError(
                "allocation predecessor must be null or an RFC UUIDv4"
            )
        if self.attempt_number == 1 and predecessor is not None:
            raise AttemptStateError("allocation attempt 1 must not have a predecessor")
        if self.attempt_number >= 2 and predecessor is None:
            raise AttemptStateError("allocation later attempt requires a predecessor")


def attempt_scope_fingerprint(scope: RegisteredAttemptScope) -> str:
    """Hash every registered field that constrains inventory and allocation."""

    cells = [
        {
            "cell_id": str(identity.cell_id),
            "ordinal": identity.ordinal,
            "block": identity.block,
            "scenario": identity.scenario_id,
            "traffic_profile": identity.traffic_profile_id,
            "strategy": identity.strategy,
        }
        for _cell_id, identity in sorted(
            scope.cells.items(), key=lambda item: str(item[0])
        )
    ]
    payload = {
        "dataset_id": scope.dataset_id,
        "campaign_stage": scope.campaign_stage,
        "schedule_sha256": scope.schedule_sha256,
        "config_sha256": scope.config_sha256,
        "collection_commit": scope.collection_commit,
        "max_attempts_per_cell": scope.max_attempts_per_cell,
        "schedule_seed": scope.schedule_seed,
        "cells": cells,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(
        b"adaptive-vpn-attempt-scope-v1\0" + encoded
    ).hexdigest()


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _deep_freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_deep_freeze(item) for item in value)
    return value


def _canonical_uuid(value: object, *, version: int, label: str) -> uuid.UUID:
    if not isinstance(value, str):
        raise AttemptInventoryError(f"{label} must be canonical UUIDv{version} text")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise AttemptInventoryError(
            f"{label} must be canonical UUIDv{version} text"
        ) from exc
    if (
        parsed.version != version
        or parsed.variant != uuid.RFC_4122
        or str(parsed) != value
    ):
        raise AttemptInventoryError(f"{label} must be canonical UUIDv{version} text")
    return parsed


def _strict_positive_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AttemptInventoryError(f"{label} must be a positive integer")
    return value


def _required_text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AttemptInventoryError(f"{label} must be nonblank text")
    return value


def _required_digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise AttemptInventoryError(f"{label} must be a lowercase SHA-256 digest")
    return value


def build_registered_attempt_scope(
    plan: ExperimentPlan,
    schedule: Sequence[ScheduleEntry],
    *,
    collection_commit: str,
) -> RegisteredAttemptScope:
    """Build immutable attempt state from one already strict-loaded schedule."""

    if not isinstance(collection_commit, str) or _COMMIT_RE.fullmatch(
        collection_commit
    ) is None:
        raise AttemptStateError("collection_commit must be lowercase 40-hex text")
    if (
        plan.campaign_stage is None
        or plan.schedule_sha256 is None
        or plan.schedule_path is None
        or plan.max_attempts_per_cell is None
        or plan.registration_path is None
    ):
        raise AttemptStateError("attempt scope requires a fully registered plan")
    entries = tuple(schedule)
    expected = tuple(generate_schedule(plan))
    if len(entries) != plan.expected_runs or [
        item.model_dump(mode="json") for item in entries
    ] != [item.model_dump(mode="json") for item in expected]:
        raise AttemptStateError("attempt scope differs from the deterministic schedule")

    config_sha256 = experiment_config_sha256(plan)
    cells: dict[uuid.UUID, RegisteredCellIdentity] = {}
    for entry in entries:
        try:
            if (
                entry.schedule_seed != plan.schedule_seed
                or entry.config_sha256 != config_sha256
            ):
                raise AttemptStateError(
                    "attempt scope schedule registration identity does not match plan"
                )
        except RuntimeError as exc:
            raise AttemptStateError(
                "attempt scope requires entries from the strict registered loader"
            ) from exc
        identity = RegisteredCellIdentity(
            cell_id=entry.cell_id,
            ordinal=entry.ordinal,
            block=entry.block,
            scenario_id=entry.scenario_id,
            traffic_profile_id=entry.traffic_profile_id,
            strategy=entry.strategy,
        )
        if identity.cell_id in cells:
            raise AttemptStateError("attempt scope contains a duplicate cell_id")
        cells[identity.cell_id] = identity

    return RegisteredAttemptScope(
        dataset_id=plan.dataset_id,
        campaign_stage=plan.campaign_stage,
        schedule_sha256=plan.schedule_sha256,
        config_sha256=config_sha256,
        collection_commit=collection_commit,
        max_attempts_per_cell=plan.max_attempts_per_cell,
        schedule_seed=plan.schedule_seed,
        cells=MappingProxyType(cells),
    )


def _reservation_from_manifest(
    path: Path, manifest: Mapping[str, Any]
) -> AttemptReservation:
    attempt_id = _canonical_uuid(
        manifest.get("attempt_id"), version=4, label="attempt_id"
    )
    cell_id = _canonical_uuid(manifest.get("cell_id"), version=5, label="cell_id")
    if path.name != str(attempt_id):
        raise AttemptInventoryError(
            f"attempt directory {path.name} does not match manifest attempt_id"
        )
    attempt_number = _strict_positive_int(
        manifest.get("attempt_number"), label="attempt_number"
    )
    raw_predecessor = manifest.get("supersedes_attempt_id")
    predecessor = (
        None
        if raw_predecessor is None
        else _canonical_uuid(
            raw_predecessor,
            version=4,
            label="supersedes_attempt_id",
        )
    )
    status = manifest.get("status")
    if status not in {"complete", "incomplete"}:
        raise AttemptInventoryError("attempt status is invalid")
    provenance = manifest.get("provenance")
    if not isinstance(provenance, Mapping):
        raise AttemptInventoryError("attempt provenance is not an object")
    collection_commit = _required_text(
        provenance.get("git_commit"), label="provenance git_commit"
    )
    if _COMMIT_RE.fullmatch(collection_commit) is None:
        raise AttemptInventoryError("provenance git_commit is not canonical")
    return AttemptReservation(
        path=path,
        dataset_id=_required_text(manifest.get("dataset_id"), label="dataset_id"),
        campaign_stage=_required_text(
            manifest.get("campaign_stage"), label="campaign_stage"
        ),
        schedule_sha256=_required_digest(
            manifest.get("schedule_sha256"), label="schedule_sha256"
        ),
        config_sha256=_required_digest(
            manifest.get("config_sha256"), label="config_sha256"
        ),
        collection_commit=collection_commit,
        cell_id=cell_id,
        attempt_id=attempt_id,
        attempt_number=attempt_number,
        supersedes_attempt_id=predecessor,
        status=status,
    )


def _reservation_scope_key(reservation: AttemptReservation) -> tuple[object, ...]:
    return (
        reservation.dataset_id,
        reservation.campaign_stage,
        reservation.schedule_sha256,
        reservation.config_sha256,
        reservation.collection_commit,
        reservation.cell_id,
    )


def _validate_global_predecessors(
    reservations: Mapping[uuid.UUID, AttemptReservation],
) -> None:
    for reservation in reservations.values():
        predecessor_id = reservation.supersedes_attempt_id
        if reservation.attempt_number == 1:
            if predecessor_id is not None:
                raise AttemptInventoryError("first attempt must not have a predecessor")
            continue
        if predecessor_id is None:
            raise AttemptInventoryError("later attempt requires a predecessor")
        predecessor = reservations.get(predecessor_id)
        if predecessor is None:
            raise AttemptInventoryError(
                f"attempt {reservation.attempt_id} predecessor does not exist"
            )
        if _reservation_scope_key(predecessor) != _reservation_scope_key(reservation):
            raise AttemptInventoryError(
                f"attempt {reservation.attempt_id} has a cross-scope predecessor"
            )
        if predecessor.attempt_number != reservation.attempt_number - 1:
            raise AttemptInventoryError(
                f"attempt {reservation.attempt_id} predecessor number is invalid"
            )


def _validate_predecessor_scope(
    reservations: Mapping[uuid.UUID, AttemptReservation],
) -> None:
    for reservation in reservations.values():
        predecessor_id = reservation.supersedes_attempt_id
        if reservation.attempt_number == 1 or predecessor_id is None:
            continue
        predecessor = reservations.get(predecessor_id)
        if predecessor is None:
            raise AttemptInventoryError(
                f"attempt {reservation.attempt_id} predecessor does not exist"
            )
        if _reservation_scope_key(predecessor) != _reservation_scope_key(reservation):
            raise AttemptInventoryError(
                f"attempt {reservation.attempt_id} has a cross-scope predecessor"
            )


def _validate_reservation_group(records: Sequence[AttemptReservation]) -> None:
    ordered = sorted(records, key=lambda item: item.attempt_number)
    numbers = [item.attempt_number for item in ordered]
    if len(numbers) != len(set(numbers)):
        raise AttemptInventoryError("attempt chain contains a duplicate attempt number")
    if numbers != list(range(1, len(ordered) + 1)):
        raise AttemptInventoryError("attempt chain numbers must be contiguous")
    complete_seen = False
    for record in ordered:
        if complete_seen:
            raise AttemptInventoryError("attempt chain contains an attempt after complete")
        if record.status == "complete":
            complete_seen = True


def _validate_target_identity(
    manifest: Mapping[str, Any],
    reservation: AttemptReservation,
    scope: RegisteredAttemptScope,
) -> RegisteredCellIdentity:
    cell = scope.cells.get(reservation.cell_id)
    if cell is None:
        raise AttemptInventoryError(
            f"attempt {reservation.attempt_id} references an unknown cell"
        )
    expected = {
        "dataset_id": scope.dataset_id,
        "campaign_stage": scope.campaign_stage,
        "schedule_sha256": scope.schedule_sha256,
        "config_sha256": scope.config_sha256,
        "schedule_seed": scope.schedule_seed,
        "ordinal": cell.ordinal,
        "block": cell.block,
        "scenario": cell.scenario_id,
        "traffic_profile": cell.traffic_profile_id,
        "strategy": cell.strategy,
    }
    mismatches = [key for key, value in expected.items() if manifest.get(key) != value]
    provenance = manifest.get("provenance")
    if (
        not isinstance(provenance, Mapping)
        or provenance.get("git_commit") != scope.collection_commit
    ):
        mismatches.append("provenance.git_commit")
    if mismatches:
        raise AttemptInventoryError(
            f"attempt {reservation.attempt_id} identity mismatch: {sorted(mismatches)}"
        )
    return cell


def validate_attempt_chain(
    records: Sequence[AttemptRecord], scope: RegisteredAttemptScope
) -> tuple[AttemptRecord, ...]:
    """Validate and return one registered cell chain in attempt-number order."""

    ordered = tuple(sorted(records, key=lambda item: item.attempt_number))
    if len(ordered) > scope.max_attempts_per_cell:
        raise AttemptInventoryError("attempt chain exceeds max_attempts_per_cell")
    numbers = [item.attempt_number for item in ordered]
    if len(numbers) != len(set(numbers)):
        raise AttemptInventoryError("attempt chain contains a duplicate attempt number")
    if numbers != list(range(1, len(ordered) + 1)):
        raise AttemptInventoryError("attempt chain numbers must be contiguous")
    complete_seen = False
    for index, record in enumerate(ordered):
        expected_predecessor = ordered[index - 1].attempt_id if index else None
        if record.supersedes_attempt_id != expected_predecessor:
            if index == 0:
                raise AttemptInventoryError("first attempt must not have a predecessor")
            raise AttemptInventoryError("attempt chain predecessor is not attempt N-1")
        if complete_seen:
            raise AttemptInventoryError("attempt chain contains an attempt after complete")
        if record.status == "complete":
            complete_seen = True
    return ordered


def inventory_attempts(
    raw_root: str | Path, scope: RegisteredAttemptScope
) -> AttemptInventory:
    """Validate a whole raw root before selecting the registered dataset attempts."""

    root = Path(raw_root)
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise AttemptInventoryError(f"cannot inspect raw attempt root: {exc}") from exc
    if not _is_real_directory(root_stat):
        raise AttemptInventoryError("raw attempt root must be a non-symlink directory")

    entries: list[Path] = []
    try:
        for path in root.iterdir():
            entries.append(path)
            if len(entries) > MAX_DATASET_BUNDLES:
                raise AttemptInventoryError(
                    f"raw attempt root contains more than {MAX_DATASET_BUNDLES} entries"
                )
    except OSError as exc:
        raise AttemptInventoryError(f"cannot inventory raw attempt root: {exc}") from exc

    reservations: dict[uuid.UUID, AttemptReservation] = {}
    manifests: dict[uuid.UUID, Mapping[str, Any]] = {}
    sums_digests: dict[uuid.UUID, str] = {}
    for path in sorted(entries, key=lambda item: item.name):
        try:
            entry_stat = path.lstat()
        except OSError as exc:
            raise AttemptInventoryError(f"cannot inspect attempt entry {path.name}") from exc
        if not _is_real_directory(entry_stat):
            raise AttemptInventoryError(
                f"raw attempt entry {path.name} must be a non-symlink directory"
            )
        validation = validate_evidence_bundle(path)
        if not validation.valid:
            raise AttemptInventoryError(
                format_validation_diagnostics(
                    validation.errors,
                    prefix=f"attempt {path.name} failed evidence validation: ",
                )
            )
        manifest = validation.manifest
        sums_digest = validation.sha256sums_sha256
        if not isinstance(manifest, Mapping) or not isinstance(sums_digest, str):
            raise AttemptInventoryError(
                f"attempt {path.name} validation returned no immutable snapshot"
            )
        if manifest.get("schema_version") != ATTEMPT_MANIFEST_SCHEMA_VERSION:
            continue
        if _SHA256_RE.fullmatch(sums_digest) is None:
            raise AttemptInventoryError(
                f"attempt {path.name} has an invalid SHA256SUMS snapshot digest"
            )
        reservation = _reservation_from_manifest(path, manifest)
        if reservation.attempt_id in reservations:
            raise AttemptInventoryError(
                f"duplicate global attempt_id {reservation.attempt_id}"
            )
        reservations[reservation.attempt_id] = reservation
        manifests[reservation.attempt_id] = manifest
        sums_digests[reservation.attempt_id] = sums_digest

    _validate_predecessor_scope(reservations)
    global_groups: dict[tuple[object, ...], list[AttemptReservation]] = defaultdict(list)
    for reservation in reservations.values():
        global_groups[_reservation_scope_key(reservation)].append(reservation)
    for group in global_groups.values():
        _validate_reservation_group(group)
    _validate_global_predecessors(reservations)

    by_cell: dict[uuid.UUID, list[AttemptRecord]] = defaultdict(list)
    for reservation in reservations.values():
        if reservation.dataset_id != scope.dataset_id:
            continue
        manifest = manifests[reservation.attempt_id]
        _validate_target_identity(manifest, reservation, scope)
        failure_reason = manifest.get("failure_reason")
        if failure_reason is not None and not isinstance(failure_reason, str):
            raise AttemptInventoryError("attempt failure_reason must be text or null")
        by_cell[reservation.cell_id].append(
            AttemptRecord(
                path=reservation.path,
                cell_id=reservation.cell_id,
                attempt_id=reservation.attempt_id,
                attempt_number=reservation.attempt_number,
                supersedes_attempt_id=reservation.supersedes_attempt_id,
                status=reservation.status,
                failure_reason=failure_reason,
                sha256sums_sha256=sums_digests[reservation.attempt_id],
                manifest=_deep_freeze(manifest),
            )
        )

    frozen_by_cell: dict[uuid.UUID, tuple[AttemptRecord, ...]] = {}
    all_current: list[AttemptRecord] = []
    for cell_id, records in by_cell.items():
        ordered = validate_attempt_chain(records, scope)
        frozen_by_cell[cell_id] = ordered
        all_current.extend(ordered)
    all_current.sort(key=lambda item: (str(item.cell_id), item.attempt_number))
    return AttemptInventory(
        scope_fingerprint=scope.fingerprint,
        all_current_attempts=tuple(all_current),
        by_attempt_id=MappingProxyType(dict(reservations)),
        by_cell_id=MappingProxyType(frozen_by_cell),
        _allocation_token=scope._allocation_token,
    )


def allocate_next_attempt(
    inventory: AttemptInventory,
    scope: RegisteredAttemptScope,
    cell_id: uuid.UUID,
    *,
    attempt_id_factory: Callable[[], uuid.UUID] = uuid.uuid4,
) -> AttemptAllocation:
    """Pure allocation; caller must hold exclusive ownership through staging create."""

    if inventory.scope_fingerprint != scope.fingerprint:
        raise AttemptStateError("attempt inventory belongs to a different scope")
    if inventory._allocation_token is not scope._allocation_token:
        raise AttemptStateError("attempt inventory was not built for this scope")
    if type(cell_id) is not uuid.UUID or cell_id.version != 5:
        raise AttemptStateError("cell_id must be a registered UUIDv5")
    if cell_id not in scope.cells:
        raise AttemptStateError("cell_id is not registered in this attempt scope")
    records = validate_attempt_chain(inventory.by_cell_id.get(cell_id, ()), scope)
    if records and records[-1].status == "complete":
        raise AttemptStateError("registered cell already has a complete attempt")
    if len(records) >= scope.max_attempts_per_cell:
        raise AttemptStateError("registered cell attempt budget is exhausted")

    candidate = attempt_id_factory()
    if (
        type(candidate) is not uuid.UUID
        or candidate.version != 4
        or candidate.variant != uuid.RFC_4122
    ):
        raise AttemptStateError("attempt_id_factory must return one RFC UUIDv4")
    if candidate in inventory.by_attempt_id:
        raise AttemptStateError("attempt_id_factory returned a global collision")
    predecessor = records[-1].attempt_id if records else None
    return AttemptAllocation(
        cell_id=cell_id,
        attempt_id=candidate,
        attempt_number=len(records) + 1,
        supersedes_attempt_id=predecessor,
        scope_fingerprint=scope.fingerprint,
        _allocation_token=scope._allocation_token,
    )


def attempt_udp_token(attempt_id: uuid.UUID) -> int:
    """Derive the existing 64-bit wire token from all attempt UUID bits."""

    if type(attempt_id) is not uuid.UUID or attempt_id.version != 4:
        raise AttemptStateError("attempt UDP token requires a UUIDv4")
    material = b"adaptive-vpn-udp-attempt-v1\0" + attempt_id.bytes
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")
