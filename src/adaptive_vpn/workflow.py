"""High-level plan, evidence validation, and environment workflow helpers."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from functools import partial
from pathlib import Path
from typing import Any

from adaptive_vpn.attempts import (
    AttemptInventoryError,
    AttemptStateError,
    allocate_next_attempt,
    attempt_udp_token,
    build_registered_attempt_scope,
    inventory_attempts,
)
from adaptive_vpn.collector import (
    MAX_DATASET_BUNDLES,
    MAX_JSON_BYTES,
    AttemptEvidenceBundle,
    _is_real_directory_stat,
    _is_regular_file_stat,
    _probe_directory_publish_capability,
    format_validation_diagnostics,
    validate_evidence_bundle,
)
from adaptive_vpn.config import load_experiment_plan
from adaptive_vpn.lab import CLIENT_NAMESPACE, WireGuardLab
from adaptive_vpn.runner import (
    AttemptDefinition,
    ExperimentRunner,
    NamespaceEchoServer,
    NamespaceUDPProbeSession,
    PathEndpoint,
    RegisteredCell,
    RunOutcome,
    WindowedUDPExecutor,
)
from adaptive_vpn.schedule import load_registered_schedule


class DatasetValidationError(ValueError):
    """Raised when measured evidence fails a confirmatory input gate."""


class WorkflowError(RuntimeError):
    """Raised when a registered workflow cannot run without design drift."""


def _bounded_sorted_bundle_directories(root: Path) -> tuple[Path, ...]:
    bundles: list[Path] = []
    try:
        for path in root.iterdir():
            if not path.is_dir():
                continue
            bundles.append(path)
            if len(bundles) > MAX_DATASET_BUNDLES:
                raise DatasetValidationError(
                    f"raw evidence contains more than {MAX_DATASET_BUNDLES} "
                    "bundle directories"
                )
    except OSError as exc:
        raise DatasetValidationError(
            f"cannot inventory raw evidence directory {root}: {exc}"
        ) from exc
    return tuple(sorted(bundles, key=lambda path: path.name))


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            raise ValueError(f"manifest exceeds {MAX_JSON_BYTES} bytes")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        OverflowError,
        RecursionError,
        ValueError,
    ) as exc:
        raise DatasetValidationError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise DatasetValidationError(f"{path} does not contain a JSON object")
    return value


def validate_raw_dataset(
    raw_dir: str | Path,
    *,
    dataset_id: str,
    expected_runs: int | None = None,
    require_complete: bool = False,
    plan_path: str | Path | None = None,
) -> dict[str, Any]:
    """Validate hashes and status for every bundle in one named dataset."""

    root = Path(raw_dir)
    if not root.is_dir():
        raise DatasetValidationError(f"raw evidence directory does not exist: {root}")
    if not dataset_id:
        raise DatasetValidationError("dataset_id must not be empty")
    if expected_runs is not None and expected_runs <= 0:
        raise DatasetValidationError("expected_runs must be positive")
    registered_plan = None
    registered_schedule = None
    if plan_path is not None:
        try:
            registered_plan = load_experiment_plan(plan_path)
            if registered_plan.dataset_id != dataset_id:
                raise ValueError("plan dataset_id does not match validation dataset")
            registered_schedule = load_registered_schedule(registered_plan)
        except (OSError, RuntimeError, ValueError) as exc:
            raise DatasetValidationError(
                f"registered plan validation failed: {exc}"
            ) from exc

    matching: list[tuple[Path, Mapping[str, Any]]] = []
    errors: list[str] = []
    invalid_runs: list[dict[str, Any]] = []
    for bundle_path in _bounded_sorted_bundle_directories(root):
        validation = validate_evidence_bundle(bundle_path)
        if not validation.valid:
            run_errors = list(validation.errors)
            invalid_runs.append(
                {"run_id": bundle_path.name, "errors": run_errors}
            )
            errors.append(
                format_validation_diagnostics(
                    run_errors,
                    prefix=f"cannot read or validate {bundle_path.name}: ",
                )
            )
            break
        manifest = validation.manifest
        if not isinstance(manifest, Mapping):
            run_errors = ["validator returned no immutable manifest snapshot"]
            errors.append(f"{bundle_path.name}: {run_errors[0]}")
            invalid_runs.append({"run_id": bundle_path.name, "errors": run_errors})
            break
        if manifest.get("dataset_id") != dataset_id:
            continue
        matching.append((bundle_path, manifest))

    if not matching:
        errors.append(f"no validated runs found for dataset {dataset_id}")
    versions = {manifest.get("schema_version") for _, manifest in matching}
    attempt_mode = "1.2.0" in versions
    if attempt_mode and versions != {"1.2.0"}:
        errors.append("dataset mixes attempt evidence with legacy run evidence")

    matching_run_count = len(matching)
    complete_runs = sum(
        manifest.get("status") == "complete" for _, manifest in matching
    )
    incomplete_runs = len(matching) - complete_runs
    retained_incomplete_attempts = 0
    if attempt_mode and versions == {"1.2.0"}:
        if registered_plan is None or registered_schedule is None:
            errors.append("v1.2 attempt validation requires a frozen plan")
        else:
            registered_cells = {entry.cell_id: entry for entry in registered_schedule}
            observed_cells = {
                manifest.get("cell_id") for _, manifest in matching
            }
            if observed_cells != set(registered_cells):
                errors.append(
                    "attempt dataset cell population does not match frozen schedule"
                )
            for _bundle_path, manifest in matching:
                entry = registered_cells.get(manifest.get("cell_id"))
                if entry is None:
                    continue
                expected_identity = {
                    "campaign_stage": registered_plan.campaign_stage,
                    "schedule_sha256": registered_plan.schedule_sha256,
                    "config_sha256": entry.config_sha256,
                    "schedule_seed": entry.schedule_seed,
                    "ordinal": entry.ordinal,
                    "block": entry.block,
                    "scenario": entry.scenario_id,
                    "traffic_profile": entry.traffic_profile_id,
                    "strategy": entry.strategy,
                }
                mismatches = [
                    field
                    for field, expected in expected_identity.items()
                    if manifest.get(field) != expected
                ]
                if mismatches:
                    errors.append(
                        f"attempt {manifest.get('attempt_id')} registered identity "
                        f"mismatch: {sorted(mismatches)}"
                    )
        scope_keys = {
            (
                manifest.get("campaign_stage"),
                manifest.get("schedule_sha256"),
                manifest.get("config_sha256"),
                (
                    manifest.get("provenance", {}).get("git_commit")
                    if isinstance(manifest.get("provenance"), Mapping)
                    else None
                ),
            )
            for _, manifest in matching
        }
        if len(scope_keys) != 1:
            errors.append("attempt dataset contains more than one registered scope")
        by_cell: dict[str, list[tuple[Path, Mapping[str, Any]]]] = defaultdict(list)
        for bundle_path, manifest in matching:
            by_cell[str(manifest.get("cell_id", ""))].append((bundle_path, manifest))
        terminal_complete = 0
        terminal_incomplete = 0
        for cell_id, attempts in sorted(by_cell.items()):
            ordered = sorted(attempts, key=lambda item: int(item[1]["attempt_number"]))
            if (
                registered_plan is not None
                and len(ordered) > registered_plan.max_attempts_per_cell
            ):
                errors.append(f"cell {cell_id} exceeds max_attempts_per_cell")
            numbers = [int(manifest["attempt_number"]) for _, manifest in ordered]
            if numbers != list(range(1, len(ordered) + 1)):
                errors.append(f"cell {cell_id} attempt numbers are not contiguous")
                continue
            expected_predecessor: str | None = None
            complete_seen = False
            identity_fields = (
                "campaign_stage",
                "schedule_sha256",
                "config_sha256",
                "schedule_seed",
                "ordinal",
                "block",
                "scenario",
                "traffic_profile",
                "strategy",
            )
            first_identity = {
                field: ordered[0][1].get(field) for field in identity_fields
            }
            for bundle_path, manifest in ordered:
                if manifest.get("supersedes_attempt_id") != expected_predecessor:
                    errors.append(
                        f"cell {cell_id} attempt {manifest.get('attempt_id')} has "
                        "an invalid predecessor"
                    )
                if any(
                    manifest.get(field) != expected
                    for field, expected in first_identity.items()
                ):
                    errors.append(f"cell {cell_id} attempt identity drifts within chain")
                if complete_seen:
                    errors.append(f"cell {cell_id} has an attempt after complete")
                if manifest.get("status") == "complete":
                    complete_seen = True
                expected_predecessor = str(manifest.get("attempt_id"))
            terminal_status = ordered[-1][1].get("status")
            if terminal_status == "complete":
                terminal_complete += 1
                retained_incomplete_attempts += len(ordered) - 1
            else:
                terminal_incomplete += 1
                retained_incomplete_attempts += len(ordered)
                if require_complete:
                    errors.append(f"cell {cell_id} has no complete terminal attempt")
        matching_run_count = len(by_cell)
        complete_runs = terminal_complete
        incomplete_runs = terminal_incomplete
    elif require_complete:
        for bundle_path, manifest in matching:
            if manifest.get("status") != "complete":
                message = f"run is {manifest.get('status')}, not complete"
                invalid_runs.append(
                    {
                        "run_id": str(manifest.get("run_id", bundle_path.name)),
                        "errors": [message],
                    }
                )
                errors.append(f"{bundle_path.name}: {message}")

    if expected_runs is not None and matching_run_count != expected_runs:
        errors.append(
            f"expected {expected_runs} runs for {dataset_id}, "
            f"found {matching_run_count}"
        )
    report = {
        "schema_version": "1.0.0",
        "status": "pass" if not errors else "fail",
        "dataset_id": dataset_id,
        "raw_dir": str(root.resolve()),
        "matching_runs": matching_run_count,
        "complete_runs": complete_runs,
        "incomplete_runs": incomplete_runs,
        "matching_attempts": len(matching) if attempt_mode else None,
        "retained_incomplete_attempts": retained_incomplete_attempts,
        "expected_runs": expected_runs,
        "invalid_runs": invalid_runs,
    }
    if errors:
        raise DatasetValidationError(format_validation_diagnostics(errors))
    return report


def _tool_version(command: str, arguments: tuple[str, ...]) -> dict[str, Any]:
    executable = shutil.which(command)
    if executable is None:
        return {"available": False, "path": None, "version": None}
    completed = subprocess.run(
        (executable, *arguments),
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    output = (completed.stdout or completed.stderr).strip().splitlines()
    return {
        "available": completed.returncode == 0,
        "path": executable,
        "version": output[0] if output else "",
    }


def doctor_report() -> dict[str, Any]:
    """Report live prerequisites without changing the host."""

    tools = {
        "ip": _tool_version("ip", ("-Version",)),
        "tc": _tool_version("tc", ("-Version",)),
        "wg": _tool_version("wg", ("--version",)),
    }
    setns_available = hasattr(os, "setns")
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    return {
        "schema_version": "1.0.0",
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "is_root": is_root,
        "setns_available": setns_available,
        "tools": tools,
        "ready_for_rootless_commands": True,
        "ready_for_netns_experiment": bool(
            is_root
            and setns_available
            and all(item["available"] for item in tools.values())
        ),
    }


def _windows_path_to_wsl(value: str) -> Path:
    normalised = value.replace("\\", "/")
    if len(normalised) >= 3 and normalised[1:3] == ":/":
        return Path("/mnt") / normalised[0].lower() / normalised[3:]
    return Path(normalised)


def _wsl_path_to_windows(path: Path) -> str:
    parts = path.resolve().parts
    if len(parts) >= 4 and parts[0] == "/" and parts[1] == "mnt":
        drive = parts[2]
        if len(drive) == 1 and drive.isalpha():
            return f"{drive.upper()}:/" + "/".join(parts[3:])
    return str(path)


def git_snapshot(worktree: str | Path) -> dict[str, Any]:
    """Read commit and dirty state, including Windows-created WSL worktrees."""

    root = Path(worktree).resolve()
    marker = root / ".git"
    command = ["git"]
    if marker.is_file():
        first_line = marker.read_text(encoding="utf-8").strip()
        if not first_line.startswith("gitdir:"):
            raise WorkflowError("worktree .git file has an invalid format")
        raw_git_dir = first_line.partition(":")[2].strip()
        windows_git = shutil.which("git.exe")
        if re.match(r"^[A-Za-z]:[\\/]", raw_git_dir) and windows_git:
            command = [windows_git, "-C", _wsl_path_to_windows(root)]
        else:
            git_dir = _windows_path_to_wsl(raw_git_dir)
            if not git_dir.is_absolute():
                git_dir = (root / git_dir).resolve()
            command.extend((f"--git-dir={git_dir}", f"--work-tree={root}"))
    elif not marker.is_dir():
        raise WorkflowError(f"not a Git worktree: {root}")
    completed = subprocess.run(
        (*command, "rev-parse", "HEAD"),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if completed.returncode != 0:
        raise WorkflowError(f"cannot resolve Git commit: {completed.stderr.strip()}")
    commit = completed.stdout.strip()
    status = subprocess.run(
        (*command, "status", "--porcelain", "--untracked-files=all"),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if status.returncode != 0:
        raise WorkflowError(f"cannot inspect Git state: {status.stderr.strip()}")
    changed_paths = []
    for line in status.stdout.splitlines():
        path = line[3:].strip() if len(line) > 3 else ""
        if " -> " in path:
            path = path.rpartition(" -> ")[2]
        if path:
            changed_paths.append(path.strip('"').replace("\\", "/"))
    code_dirty = any(
        not path.startswith("data/raw/") for path in changed_paths
    )
    return {
        "git_commit": commit,
        "git_dirty": bool(changed_paths),
        "git_code_dirty": code_dirty,
        "git_changed_paths": changed_paths,
    }


def collect_runtime_provenance(worktree: str | Path) -> dict[str, Any]:
    """Capture non-secret code and apparatus identity once per campaign start."""

    git = git_snapshot(worktree)
    doctor = doctor_report()
    return {
        **git,
        "python_version": doctor["python"],
        "platform": doctor["platform"],
        "setns_available": doctor["setns_available"],
        "tools": doctor["tools"],
    }


@contextmanager
def _exclusive_campaign_lock(data_root: Path) -> Iterator[None]:
    data_root.mkdir(parents=True, exist_ok=True)
    root_stat = os.lstat(data_root)
    if not _is_real_directory_stat(root_stat):
        raise WorkflowError("evidence data root must be a real directory")
    lock_path = data_root / ".campaign.lock"
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(lock_path, flags, 0o600)
    locked = False
    try:
        opened = os.fstat(descriptor)
        path_stat = os.lstat(lock_path)
        if (
            not _is_regular_file_stat(opened)
            or not _is_regular_file_stat(path_stat)
            or (opened.st_dev, opened.st_ino) != (path_stat.st_dev, path_stat.st_ino)
        ):
            raise WorkflowError("campaign lock must be a stable regular file")
        if os.name == "posix":
            import fcntl

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise WorkflowError("another campaign process holds the data root lock") from exc
        elif os.name == "nt":
            import msvcrt

            if opened.st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise WorkflowError("another campaign process holds the data root lock") from exc
        else:
            raise WorkflowError(f"unsupported campaign lock platform: {os.name}")
        locked = True
        yield
    finally:
        if locked:
            if os.name == "posix":
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
            elif os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        os.close(descriptor)


def _prepare_attempt_roots(data_root: Path) -> tuple[Path, Path]:
    staging_root = data_root / ".staging"
    raw_root = data_root / "raw"
    staging_root.mkdir(parents=True, exist_ok=True)
    raw_root.mkdir(parents=True, exist_ok=True)
    for label, path in (("staging", staging_root), ("raw", raw_root)):
        observed = os.lstat(path)
        if not _is_real_directory_stat(observed):
            raise WorkflowError(f"{label} evidence root must be a real directory")
    _probe_directory_publish_capability(staging_root, raw_root)
    try:
        staging_entries = tuple(staging_root.iterdir())
    except OSError as exc:
        raise WorkflowError(f"cannot inspect evidence staging root: {exc}") from exc
    if staging_entries:
        raise WorkflowError("evidence staging root contains unresolved bundles")
    return staging_root, raw_root


def _execute_one_real_run(
    definition: AttemptDefinition,
    data_root: Path,
    provenance: dict[str, Any],
) -> RunOutcome:
    lab = WireGuardLab()
    lab_by_id = {f"path-{path.path_id}": path for path in lab.paths}
    registered_ids = {path.path_id for path in definition.plan.paths}
    if set(lab_by_id) != registered_ids:
        raise WorkflowError("registered paths do not match the fixed WireGuard lab")
    measurement = definition.plan.measurement
    endpoints = tuple(
        PathEndpoint(
            path.path_id,
            path.path_index,
            lab_by_id[path.path_id].server_overlay_ip,
            measurement.echo_port,
        )
        for path in sorted(definition.plan.paths, key=lambda item: item.path_index)
    )
    executor = WindowedUDPExecutor(
        endpoints=endpoints,
        run_token=attempt_udp_token(definition.allocation.attempt_id),
        monitor_packet_rate_hz=measurement.monitor_packet_rate_hz,
        monitor_packets_per_window=measurement.monitor_packets_per_window,
        monitor_datagram_size=measurement.monitor_datagram_size,
        window_duration_s=measurement.window_duration_s,
        duplicate_drain_s=measurement.duplicate_drain_ms / 1_000,
        probe_factory=partial(
            NamespaceUDPProbeSession,
            namespace=CLIENT_NAMESPACE,
        ),
    )
    server = NamespaceEchoServer(port=measurement.echo_port)

    def bundle_factory(manifest: dict[str, Any]):
        return AttemptEvidenceBundle.create(data_root, manifest)

    return ExperimentRunner(
        lab=lab,
        server=server,
        executor=executor,
        bundle_factory=bundle_factory,
    ).run(definition)


RunOne = Callable[[AttemptDefinition, Path, dict[str, Any]], RunOutcome]


def _same_json_value(left: Any, right: Any) -> bool:
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return set(left) == set(right) and all(
            _same_json_value(left[key], right[key]) for key in left
        )
    if isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
        return len(left) == len(right) and all(
            _same_json_value(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return type(left) is type(right) and left == right


def _verify_attempt_outcome(
    outcome: RunOutcome,
    definition: AttemptDefinition,
    raw_root: Path,
) -> None:
    expected_path = raw_root / str(definition.allocation.attempt_id)
    observed_path = Path(outcome.evidence_path)
    if os.path.abspath(observed_path) != os.path.abspath(expected_path):
        raise WorkflowError("attempt outcome evidence path does not match allocation")
    validation = validate_evidence_bundle(observed_path)
    if not validation.valid:
        raise WorkflowError(
            format_validation_diagnostics(
                validation.errors,
                prefix="attempt outcome evidence failed validation: ",
            )
        )
    manifest = validation.manifest
    if not isinstance(manifest, Mapping):
        raise WorkflowError("attempt outcome validation returned no manifest snapshot")
    mismatches = [
        field
        for field, expected in definition.manifest.items()
        if not _same_json_value(manifest.get(field), expected)
    ]
    if mismatches:
        raise WorkflowError(
            "attempt outcome registered identity mismatch: "
            + ", ".join(sorted(mismatches))
        )
    if manifest.get("status") != outcome.status:
        raise WorkflowError("attempt outcome status does not match evidence manifest")
    if manifest.get("failure_reason") != outcome.failure_reason:
        raise WorkflowError(
            "attempt outcome failure reason does not match evidence manifest"
        )


def execute_registered_plan(
    plan_path: str | Path,
    *,
    data_root: str | Path,
    dataset_id: str | None = None,
    resume: bool = False,
    limit: int | None = None,
    effective_uid: int | None = None,
    provenance: dict[str, Any] | None = None,
    run_one: RunOne = _execute_one_real_run,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Execute registered cells as immutable attempts under one campaign lock."""

    uid = (
        effective_uid
        if effective_uid is not None
        else (os.geteuid() if hasattr(os, "geteuid") else -1)
    )
    if uid != 0:
        raise WorkflowError("real WireGuard experiments require root")
    plan = load_experiment_plan(plan_path)
    if dataset_id is not None and dataset_id != plan.dataset_id:
        raise WorkflowError(
            f"dataset override {dataset_id!r} does not match frozen plan "
            f"{plan.dataset_id!r}"
        )
    if limit is not None and limit < 1:
        raise WorkflowError("limit must be at least 1")
    try:
        schedule = load_registered_schedule(plan)
    except (OSError, RuntimeError, ValueError) as exc:
        raise WorkflowError(f"registered schedule validation failed: {exc}") from exc
    selected = schedule if limit is None else schedule[:limit]
    evidence_root = Path(data_root)
    campaign_provenance = provenance or collect_runtime_provenance(Path.cwd())
    git_commit = campaign_provenance.get("git_commit")
    if not isinstance(git_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", git_commit):
        raise WorkflowError("campaign provenance has no canonical Git commit")
    code_dirty = campaign_provenance.get(
        "git_code_dirty", campaign_provenance.get("git_dirty", False)
    )
    if code_dirty:
        raise WorkflowError("campaign must start from a clean Git worktree")
    if campaign_provenance.get("git_dirty") and not resume:
        raise WorkflowError(
            "a dirty evidence-only worktree is accepted only with --resume"
        )

    try:
        scope = build_registered_attempt_scope(
            plan,
            schedule,
            collection_commit=git_commit,
        )
    except AttemptStateError as exc:
        raise WorkflowError(f"registered attempt scope is invalid: {exc}") from exc

    executed = 0
    skipped = 0
    outcomes: list[dict[str, Any]] = []
    overall_status = "complete"
    with _exclusive_campaign_lock(evidence_root):
        _staging_root, raw_root = _prepare_attempt_roots(evidence_root)
        for entry in selected:
            cell_id = entry.cell_id
            try:
                inventory = inventory_attempts(raw_root, scope)
            except AttemptInventoryError as exc:
                raise WorkflowError(f"attempt inventory is invalid: {exc}") from exc
            records = inventory.by_cell_id.get(cell_id, ())
            if records and records[-1].status == "complete":
                if not resume:
                    raise WorkflowError(
                        f"registered cell {cell_id} already has complete evidence; "
                        "use --resume"
                    )
                skipped += 1
                if progress is not None:
                    progress(
                        {
                            "event": "cell_skipped",
                            "cell_id": str(cell_id),
                            "attempt_id": str(records[-1].attempt_id),
                            "ordinal": entry.ordinal,
                        }
                    )
                continue
            if records and not resume:
                raise WorkflowError(
                    f"registered cell {cell_id} has retained incomplete evidence; "
                    "use --resume"
                )
            try:
                allocation = allocate_next_attempt(inventory, scope, cell_id)
                definition = AttemptDefinition(
                    cell=RegisteredCell.from_plan(plan, entry),
                    allocation=allocation,
                    scope=scope,
                    provenance=campaign_provenance,
                )
            except (AttemptStateError, ValueError) as exc:
                raise WorkflowError(f"cannot allocate registered attempt: {exc}") from exc
            attempt_id = str(allocation.attempt_id)
            if progress is not None:
                progress(
                    {
                        "event": "attempt_started",
                        "cell_id": str(cell_id),
                        "attempt_id": attempt_id,
                        "attempt_number": allocation.attempt_number,
                        "ordinal": entry.ordinal,
                        "selected_cells": len(selected),
                    }
                )
            outcome = run_one(definition, evidence_root, campaign_provenance)
            _verify_attempt_outcome(outcome, definition, raw_root)
            executed += 1
            outcomes.append(
                {
                    "cell_id": str(cell_id),
                    "attempt_id": attempt_id,
                    "attempt_number": allocation.attempt_number,
                    "supersedes_attempt_id": (
                        str(allocation.supersedes_attempt_id)
                        if allocation.supersedes_attempt_id is not None
                        else None
                    ),
                    "ordinal": entry.ordinal,
                    "status": outcome.status,
                    "packet_count": outcome.packet_count,
                    "evidence_path": str(outcome.evidence_path),
                    "failure_reason": outcome.failure_reason,
                }
            )
            if progress is not None:
                progress({"event": "attempt_finished", **outcomes[-1]})
            if outcome.status != "complete":
                overall_status = "incomplete"
                break

    return {
        "schema_version": "1.0.0",
        "status": overall_status,
        "dataset_id": plan.dataset_id,
        "expected_plan_runs": plan.expected_runs,
        "selected_cells": len(selected),
        "selected_runs": len(selected),
        "executed_attempts": executed,
        "executed_runs": executed,
        "skipped_cells": skipped,
        "skipped_runs": skipped,
        "outcomes": outcomes,
        "git_commit": campaign_provenance["git_commit"],
    }
