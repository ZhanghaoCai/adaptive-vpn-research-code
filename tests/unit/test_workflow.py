from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest
import yaml

import adaptive_vpn.workflow as workflow_module
from adaptive_vpn.attempts import (
    allocate_next_attempt,
    build_registered_attempt_scope,
    inventory_attempts,
)
from adaptive_vpn.collector import (
    EVIDENCE_SCHEMA_VERSION,
    AttemptEvidenceBundle,
    BundleValidation,
    EvidenceBundle,
)
from adaptive_vpn.config import load_experiment_plan
from adaptive_vpn.provenance import sha256_file
from adaptive_vpn.runner import AttemptDefinition, RegisteredCell, RunOutcome
from adaptive_vpn.schedule import load_registered_schedule
from adaptive_vpn.workflow import (
    DatasetValidationError,
    WorkflowError,
    execute_registered_plan,
    git_snapshot,
    validate_raw_dataset,
)

ROOT = Path(__file__).resolve().parents[2]
TEST_GIT_COMMIT = "a" * 40


def manifest(run_id: str, *, status_dataset: str = "validation-test"):
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "run_id": run_id,
        "dataset_id": status_dataset,
        "strategy": "adaptive",
        "scenario": "baseline",
        "traffic_profile": "video-low",
        "block": 1,
        "schedule_seed": 20260803,
        "ordinal": 1,
        "config_sha256": "a" * 64,
        "experimental_unit": "run",
        "provenance": {"git_commit": TEST_GIT_COMMIT},
    }


def write_minimum_complete_evidence(bundle: EvidenceBundle) -> None:
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
    bundle.write_event({"event": "test_completed"})


def _new_attempt_definition(
    plan_path: Path,
    data_root: Path,
    *,
    schedule_index: int = 0,
    commit: str = TEST_GIT_COMMIT,
    attempt_id: uuid.UUID | None = None,
) -> AttemptDefinition:
    plan = load_experiment_plan(plan_path)
    schedule = load_registered_schedule(plan)
    scope = build_registered_attempt_scope(
        plan,
        schedule,
        collection_commit=commit,
    )
    raw_root = data_root / "raw"
    raw_root.mkdir(parents=True, exist_ok=True)
    inventory = inventory_attempts(raw_root, scope)
    allocation = allocate_next_attempt(
        inventory,
        scope,
        schedule[schedule_index].cell_id,
        attempt_id_factory=lambda: attempt_id or uuid.uuid4(),
    )
    return AttemptDefinition(
        cell=RegisteredCell.from_plan(plan, schedule[schedule_index]),
        allocation=allocation,
        scope=scope,
        provenance={"git_commit": commit},
    )


def test_dataset_validation_checks_hashes_status_and_exact_count(tmp_path: Path):
    run_id = "00000000-0000-4000-8000-000000000011"
    bundle = EvidenceBundle.create(tmp_path, manifest(run_id))
    write_minimum_complete_evidence(bundle)
    bundle.finalise(status="complete")

    report = validate_raw_dataset(
        tmp_path / "raw",
        dataset_id="validation-test",
        expected_runs=1,
        require_complete=True,
    )

    assert report["status"] == "pass"
    assert report["matching_runs"] == 1
    assert report["complete_runs"] == 1
    assert report["invalid_runs"] == []


def test_dataset_validation_rejects_incomplete_or_tampered_bundle(tmp_path: Path):
    incomplete_id = "00000000-0000-4000-8000-000000000012"
    incomplete = EvidenceBundle.create(tmp_path, manifest(incomplete_id))
    incomplete.finalise(status="incomplete", failure_reason="apparatus failure")
    complete_id = "00000000-0000-4000-8000-000000000013"
    complete = EvidenceBundle.create(tmp_path, manifest(complete_id))
    write_minimum_complete_evidence(complete)
    complete_path = complete.finalise(status="complete")
    (complete_path / "events.jsonl").write_text("tampered\n", encoding="utf-8")

    with pytest.raises(DatasetValidationError) as error:
        validate_raw_dataset(
            tmp_path / "raw",
            dataset_id="validation-test",
            expected_runs=2,
            require_complete=True,
        )

    message = str(error.value)
    assert "incomplete" in message
    assert "checksum" in message


def test_dataset_validation_ignores_other_dataset_but_enforces_requested_count(
    tmp_path: Path,
):
    run_id = "00000000-0000-4000-8000-000000000014"
    bundle = EvidenceBundle.create(
        tmp_path, manifest(run_id, status_dataset="different-dataset")
    )
    write_minimum_complete_evidence(bundle)
    bundle.finalise(status="complete")

    with pytest.raises(DatasetValidationError, match="expected 1"):
        validate_raw_dataset(
            tmp_path / "raw",
            dataset_id="validation-test",
            expected_runs=1,
            require_complete=True,
        )


def test_dataset_validation_rejects_zero_matching_runs_without_expected_count(
    tmp_path: Path,
):
    (tmp_path / "raw").mkdir()

    with pytest.raises(DatasetValidationError, match="no validated runs"):
        validate_raw_dataset(tmp_path / "raw", dataset_id="validation-test")


def test_dataset_validation_rejects_explicit_zero_expected_runs(tmp_path: Path):
    (tmp_path / "raw").mkdir()

    with pytest.raises(DatasetValidationError, match="expected_runs must be positive"):
        validate_raw_dataset(
            tmp_path / "raw",
            dataset_id="validation-test",
            expected_runs=0,
        )


def test_dataset_validation_does_not_parse_rejected_bundle_and_bounds_error(
    tmp_path: Path, monkeypatch
):
    bundle_path = tmp_path / "raw" / "rejected-bundle"
    bundle_path.mkdir(parents=True)
    diagnostics = tuple("x" * 1_024 for _ in range(100))
    monkeypatch.setattr(
        workflow_module,
        "validate_evidence_bundle",
        lambda path: BundleValidation(False, diagnostics, ()),
    )
    monkeypatch.setattr(
        workflow_module,
        "_read_manifest",
        lambda path: pytest.fail("rejected manifest must not be parsed"),
    )

    with pytest.raises(DatasetValidationError) as caught:
        validate_raw_dataset(tmp_path / "raw", dataset_id="validation-test")

    assert len(str(caught.value)) <= 1_024


def test_dataset_validation_bounds_raw_bundle_inventory_before_sorting(
    tmp_path: Path, monkeypatch
):
    raw_dir = tmp_path / "raw"
    (raw_dir / "bundle-b").mkdir(parents=True)
    (raw_dir / "bundle-a").mkdir()
    monkeypatch.setattr(workflow_module, "MAX_DATASET_BUNDLES", 1, raising=False)

    with pytest.raises(DatasetValidationError, match="more than 1 bundle"):
        validate_raw_dataset(raw_dir, dataset_id="validation-test")


def test_dataset_validation_validates_bundle_before_trusting_dataset_id(
    tmp_path: Path,
):
    run_id = "00000000-0000-4000-8000-000000000015"
    bundle = EvidenceBundle.create(tmp_path, manifest(run_id))
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    manifest_path = final_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["dataset_id"] = "different-dataset"
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(DatasetValidationError, match="checksum"):
        validate_raw_dataset(tmp_path / "raw", dataset_id="validation-test")


def test_dataset_validation_normalises_invalid_utf8_manifest(tmp_path: Path):
    bundle_path = tmp_path / "raw" / "invalid-utf8"
    bundle_path.mkdir(parents=True)
    (bundle_path / "manifest.json").write_bytes(b"\xff")

    with pytest.raises(DatasetValidationError, match="cannot read"):
        validate_raw_dataset(tmp_path / "raw", dataset_id="validation-test")


def test_dataset_validation_calls_public_validator_for_malformed_manifest(
    tmp_path: Path, monkeypatch
):
    bundle_path = tmp_path / "raw" / "malformed-manifest"
    bundle_path.mkdir(parents=True)
    (bundle_path / "manifest.json").write_text("{", encoding="utf-8")
    calls: list[Path] = []
    original_validation = workflow_module.validate_evidence_bundle

    def record_validation(path):
        calls.append(path)
        return original_validation(path)

    monkeypatch.setattr(
        "adaptive_vpn.workflow.validate_evidence_bundle",
        record_validation,
    )

    with pytest.raises(DatasetValidationError):
        validate_raw_dataset(tmp_path / "raw", dataset_id="validation-test")

    assert calls == [bundle_path]


def test_dataset_validation_rejects_oversized_manifest_before_json_decode(
    tmp_path: Path,
):
    bundle_path = tmp_path / "raw" / "oversized"
    bundle_path.mkdir(parents=True)
    manifest_path = bundle_path / "manifest.json"
    manifest_path.write_bytes(
        b'{"dataset_id":"validation-test","padding":"'
        + b"x" * 1_048_576
        + b'"}'
    )
    (bundle_path / "SHA256SUMS").write_text(
        f"{sha256_file(manifest_path)}  manifest.json\n",
        encoding="ascii",
    )

    with pytest.raises(DatasetValidationError, match="exceeds 1048576 bytes"):
        validate_raw_dataset(tmp_path / "raw", dataset_id="validation-test")


def test_dataset_validation_normalises_deep_manifest_recursion(
    tmp_path: Path, monkeypatch
):
    bundle_path = tmp_path / "raw" / "deep-manifest"
    bundle_path.mkdir(parents=True)
    (bundle_path / "manifest.json").write_text(
        "[" * 2_000 + "0" + "]" * 2_000,
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "adaptive_vpn.workflow.json.loads",
        lambda value: (_ for _ in ()).throw(RecursionError("decoder depth limit")),
    )

    with pytest.raises(DatasetValidationError, match="cannot read"):
        validate_raw_dataset(tmp_path / "raw", dataset_id="validation-test")


def test_execute_plan_uses_frozen_schedule_order_and_root_gate(tmp_path: Path):
    observed: list[AttemptDefinition] = []

    def run_one(definition, data_root, provenance):
        observed.append(definition)
        bundle = AttemptEvidenceBundle.create(data_root, definition.manifest)
        write_minimum_complete_evidence(bundle)
        evidence_path = bundle.finalise(status="complete")
        return RunOutcome(
            status="complete",
            evidence_path=evidence_path,
            failure_reason=None,
            final_active_path_id="path-a",
            packet_count=10,
        )

    report = execute_registered_plan(
        ROOT / "experiments" / "plans" / "smoke.yaml",
        data_root=tmp_path,
        limit=2,
        effective_uid=0,
        provenance={"git_commit": TEST_GIT_COMMIT, "git_dirty": False},
        run_one=run_one,
    )

    assert report["status"] == "complete"
    assert report["selected_runs"] == 2
    assert report["selected_cells"] == 2
    assert report["executed_attempts"] == 2
    assert report["executed_runs"] == 2
    assert [definition.entry.ordinal for definition in observed] == [1, 2]
    assert all(definition.manifest["schema_version"] == "1.2.0" for definition in observed)
    assert all("run_id" not in definition.manifest for definition in observed)
    assert [definition.allocation.attempt_number for definition in observed] == [1, 1]
    assert report["outcomes"][0]["cell_id"] != report["outcomes"][1]["cell_id"]

    with pytest.raises(WorkflowError, match="root"):
        execute_registered_plan(
            ROOT / "experiments" / "plans" / "smoke.yaml",
            data_root=tmp_path,
            effective_uid=1000,
            provenance={"git_commit": TEST_GIT_COMMIT, "git_dirty": False},
            run_one=run_one,
        )


@pytest.mark.parametrize("failure", ("missing", "digest", "population"))
def test_execute_plan_rejects_invalid_registered_schedule_before_run_one(
    tmp_path: Path, failure: str
):
    from tests.unit.test_schedule import _registered_plan, _schedule_path

    plan = _registered_plan(tmp_path)
    plan_path = plan.registration_path
    schedule_path = _schedule_path(plan)
    assert plan_path is not None

    if failure == "missing":
        schedule_path.unlink()
    elif failure == "digest":
        schedule_path.write_bytes(schedule_path.read_bytes() + b" ")
    else:
        document = json.loads(schedule_path.read_text(encoding="utf-8"))
        document["cells"][0]["strategy"] = document["cells"][1]["strategy"]
        substituted = (
            json.dumps(document, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        schedule_path.write_bytes(substituted)
        registration = yaml.safe_load(plan_path.read_text(encoding="utf-8"))
        registration["schedule_sha256"] = hashlib.sha256(substituted).hexdigest()
        plan_path.write_text(
            yaml.safe_dump(registration, sort_keys=False), encoding="utf-8"
        )

    with pytest.raises(WorkflowError, match="registered schedule"):
        execute_registered_plan(
            plan_path,
            data_root=tmp_path / "evidence",
            limit=1,
            effective_uid=0,
            provenance={"git_commit": TEST_GIT_COMMIT, "git_dirty": False},
            run_one=lambda *_args: pytest.fail(
                "run_one must not be called for an invalid registered schedule"
            ),
        )


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX FIFO semantics")
def test_execute_plan_nonblocks_post_stat_schedule_fifo_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from adaptive_vpn import schedule as schedule_module
    from tests.unit.test_schedule import _registered_plan, _schedule_path

    plan = _registered_plan(tmp_path)
    plan_path = plan.registration_path
    schedule_path = _schedule_path(plan)
    assert plan_path is not None
    original_open = os.open
    raced = False

    def race_before_schedule_open(path, flags, *args, **kwargs):
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

    monkeypatch.setattr(schedule_module.os, "open", race_before_schedule_open)

    with pytest.raises(WorkflowError, match="registered schedule"):
        execute_registered_plan(
            plan_path,
            data_root=tmp_path / "evidence",
            limit=1,
            effective_uid=0,
            provenance={"git_commit": TEST_GIT_COMMIT, "git_dirty": False},
            run_one=lambda *_args: pytest.fail("run_one must not be called"),
        )
    assert raced


def test_resume_skips_only_hash_valid_complete_registered_run(tmp_path: Path):
    plan_path = ROOT / "experiments" / "plans" / "smoke.yaml"
    definition = _new_attempt_definition(plan_path, tmp_path)
    bundle = AttemptEvidenceBundle.create(tmp_path, definition.manifest)
    write_minimum_complete_evidence(bundle)
    bundle.finalise(status="complete")

    report = execute_registered_plan(
        plan_path,
        data_root=tmp_path,
        limit=1,
        resume=True,
        effective_uid=0,
        provenance={
            "git_commit": TEST_GIT_COMMIT,
            "git_dirty": True,
            "git_code_dirty": False,
            "git_changed_paths": ["data/raw/already-complete/manifest.json"],
        },
        run_one=lambda *args: pytest.fail("completed run must be skipped"),
    )

    assert report["executed_runs"] == 0
    assert report["skipped_runs"] == 1


def test_resume_rejects_complete_bundle_from_different_git_commit(tmp_path: Path):
    plan_path = ROOT / "experiments" / "plans" / "smoke.yaml"
    definition = _new_attempt_definition(plan_path, tmp_path)
    bundle = AttemptEvidenceBundle.create(tmp_path, definition.manifest)
    write_minimum_complete_evidence(bundle)
    bundle.finalise(status="complete")

    with pytest.raises(WorkflowError, match="git_commit"):
        execute_registered_plan(
            plan_path,
            data_root=tmp_path,
            limit=1,
            resume=True,
            effective_uid=0,
            provenance={
                "git_commit": "b" * 40,
                "git_dirty": True,
                "git_code_dirty": False,
                "git_changed_paths": ["data/raw/existing/manifest.json"],
            },
            run_one=lambda *args: pytest.fail("cross-commit run must not be skipped"),
        )


def test_resume_rejects_current_bundle_with_missing_git_commit(tmp_path: Path):
    plan_path = ROOT / "experiments" / "plans" / "smoke.yaml"
    definition = _new_attempt_definition(plan_path, tmp_path)
    bundle = AttemptEvidenceBundle.create(tmp_path, definition.manifest)
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    manifest_path = final_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["provenance"].pop("git_commit")
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    hashes = {
        path.name: sha256_file(path)
        for path in final_path.iterdir()
        if path.name != "SHA256SUMS"
    }
    (final_path / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(hashes.items())),
        encoding="ascii",
        newline="\n",
    )

    with pytest.raises(WorkflowError, match="provenance|git_commit"):
        execute_registered_plan(
            plan_path,
            data_root=tmp_path,
            limit=1,
            resume=True,
            effective_uid=0,
            provenance={
                "git_commit": TEST_GIT_COMMIT,
                "git_dirty": True,
                "git_code_dirty": False,
                "git_changed_paths": ["data/raw/missing-commit/manifest.json"],
            },
            run_one=lambda *args: pytest.fail("missing commit must not be skipped"),
        )


def test_resume_rejects_bundle_moved_from_another_registered_run(tmp_path: Path):
    plan_path = ROOT / "experiments" / "plans" / "smoke.yaml"
    definition = _new_attempt_definition(plan_path, tmp_path, schedule_index=1)
    bundle = AttemptEvidenceBundle.create(tmp_path, definition.manifest)
    write_minimum_complete_evidence(bundle)
    second_path = bundle.finalise(status="complete")
    second_path.rename(second_path.with_name(str(uuid.uuid4())))

    with pytest.raises(WorkflowError, match="attempt_id|directory"):
        execute_registered_plan(
            plan_path,
            data_root=tmp_path,
            limit=1,
            resume=True,
            effective_uid=0,
            provenance={
                "git_commit": TEST_GIT_COMMIT,
                "git_dirty": True,
                "git_code_dirty": False,
                "git_changed_paths": ["data/raw/moved-bundle/manifest.json"],
            },
            run_one=lambda *args: pytest.fail("wrong run identity must not be skipped"),
        )


def test_resume_rejects_self_consistent_uuid_with_wrong_registered_metadata(
    tmp_path: Path,
):
    plan_path = ROOT / "experiments" / "plans" / "smoke.yaml"
    definition = _new_attempt_definition(plan_path, tmp_path)
    drifted_manifest = {
        **definition.manifest,
        "scenario": "wrong-scenario",
        "ordinal": definition.manifest["ordinal"] + 1,
        "config_sha256": "f" * 64,
    }
    bundle = AttemptEvidenceBundle.create(tmp_path, drifted_manifest)
    write_minimum_complete_evidence(bundle)
    bundle.finalise(status="complete")

    with pytest.raises(WorkflowError, match="identity mismatch"):
        execute_registered_plan(
            plan_path,
            data_root=tmp_path,
            limit=1,
            resume=True,
            effective_uid=0,
            provenance={
                "git_commit": TEST_GIT_COMMIT,
                "git_dirty": True,
                "git_code_dirty": False,
                "git_changed_paths": ["data/raw/drifted/manifest.json"],
            },
            run_one=lambda *args: pytest.fail("drifted run must not be skipped"),
        )


def test_resume_retains_incomplete_attempt_and_allocates_exact_successor(
    tmp_path: Path,
):
    plan_path = ROOT / "experiments" / "plans" / "smoke.yaml"
    observed: list[AttemptDefinition] = []

    def persist_attempt(definition, data_root, provenance):
        observed.append(definition)
        bundle = AttemptEvidenceBundle.create(data_root, definition.manifest)
        status = "incomplete" if len(observed) == 1 else "complete"
        if status == "complete":
            write_minimum_complete_evidence(bundle)
        evidence_path = bundle.finalise(
            status=status,
            failure_reason=("controlled first-attempt failure" if status == "incomplete" else None),
        )
        return RunOutcome(
            status=status,
            evidence_path=evidence_path,
            failure_reason=("controlled first-attempt failure" if status == "incomplete" else None),
            final_active_path_id="path-a",
            packet_count=0 if status == "incomplete" else 1,
        )

    first_report = execute_registered_plan(
        plan_path,
        data_root=tmp_path,
        limit=1,
        effective_uid=0,
        provenance={"git_commit": TEST_GIT_COMMIT, "git_dirty": False},
        run_one=persist_attempt,
    )
    second_report = execute_registered_plan(
        plan_path,
        data_root=tmp_path,
        limit=1,
        resume=True,
        effective_uid=0,
        provenance={
            "git_commit": TEST_GIT_COMMIT,
            "git_dirty": True,
            "git_code_dirty": False,
            "git_changed_paths": ["data/raw/retained-attempt/manifest.json"],
        },
        run_one=persist_attempt,
    )

    assert first_report["status"] == "incomplete"
    assert second_report["status"] == "complete"
    assert [item.allocation.attempt_number for item in observed] == [1, 2]
    assert observed[1].allocation.supersedes_attempt_id == (
        observed[0].allocation.attempt_id
    )
    assert second_report["outcomes"][0]["supersedes_attempt_id"] == str(
        observed[0].allocation.attempt_id
    )
    assert len(list((tmp_path / "raw").iterdir())) == 2


def test_execute_plan_rejects_unresolved_staging_before_run_one(tmp_path: Path):
    unresolved = tmp_path / ".staging" / str(uuid.uuid4())
    unresolved.mkdir(parents=True)

    with pytest.raises(WorkflowError, match="unresolved bundles"):
        execute_registered_plan(
            ROOT / "experiments" / "plans" / "smoke.yaml",
            data_root=tmp_path,
            limit=1,
            resume=True,
            effective_uid=0,
            provenance={"git_commit": TEST_GIT_COMMIT, "git_dirty": False},
            run_one=lambda *args: pytest.fail("unresolved staging must block execution"),
        )


def test_execute_plan_rejects_run_one_without_published_attempt_evidence(
    tmp_path: Path,
):
    def missing_evidence(definition, data_root, provenance):
        return RunOutcome(
            status="complete",
            evidence_path=data_root / "raw" / str(definition.allocation.attempt_id),
            failure_reason=None,
            final_active_path_id="path-a",
            packet_count=1,
        )

    with pytest.raises(WorkflowError, match="evidence failed validation"):
        execute_registered_plan(
            ROOT / "experiments" / "plans" / "smoke.yaml",
            data_root=tmp_path,
            limit=1,
            effective_uid=0,
            provenance={"git_commit": TEST_GIT_COMMIT, "git_dirty": False},
            run_one=missing_evidence,
        )


def test_execute_plan_fails_fast_when_campaign_lock_is_already_held(tmp_path: Path):
    with (
        workflow_module._exclusive_campaign_lock(tmp_path),
        pytest.raises(WorkflowError, match="holds the data root lock"),
    ):
        execute_registered_plan(
            ROOT / "experiments" / "plans" / "smoke.yaml",
            data_root=tmp_path,
            limit=1,
            effective_uid=0,
            provenance={"git_commit": TEST_GIT_COMMIT, "git_dirty": False},
            run_one=lambda *args: pytest.fail("locked campaign must not execute"),
        )


def test_resume_rejects_boolean_ordinal_instead_of_registered_integer(tmp_path: Path):
    plan_path = ROOT / "experiments" / "plans" / "smoke.yaml"
    definition = _new_attempt_definition(plan_path, tmp_path)
    bundle = AttemptEvidenceBundle.create(tmp_path, definition.manifest)
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    manifest_path = final_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["ordinal"] = True
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    hashes = {
        path.name: sha256_file(path)
        for path in final_path.iterdir()
        if path.name != "SHA256SUMS"
    }
    (final_path / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(hashes.items())),
        encoding="ascii",
    )

    with pytest.raises(WorkflowError, match="registered identity|ordinal"):
        execute_registered_plan(
            plan_path,
            data_root=tmp_path,
            limit=1,
            resume=True,
            effective_uid=0,
            provenance={
                "git_commit": TEST_GIT_COMMIT,
                "git_dirty": True,
                "git_code_dirty": False,
                "git_changed_paths": ["data/raw/bool-ordinal/manifest.json"],
            },
            run_one=lambda *args: pytest.fail("wrong ordinal type must not be skipped"),
        )


def test_execute_plan_rejects_dataset_override_drift(tmp_path: Path):
    with pytest.raises(WorkflowError, match="dataset"):
        execute_registered_plan(
            ROOT / "experiments" / "plans" / "smoke.yaml",
            data_root=tmp_path,
            dataset_id="different-dataset",
            effective_uid=0,
            provenance={"git_commit": TEST_GIT_COMMIT, "git_dirty": False},
            run_one=lambda *args: None,
        )


def test_git_snapshot_supports_windows_created_wsl_worktree():
    snapshot = git_snapshot(ROOT)

    assert len(snapshot["git_commit"]) == 40
    int(snapshot["git_commit"], 16)
    assert isinstance(snapshot["git_dirty"], bool)


@pytest.mark.skipif(shutil.which("git.exe") is None, reason="Windows Git not available")
def test_git_snapshot_matches_native_windows_git_status():
    windows_root = subprocess.run(
        ("wslpath", "-w", str(ROOT)),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    native = subprocess.run(
        (
            shutil.which("git.exe"),
            "-C",
            windows_root,
            "status",
            "--porcelain",
            "--untracked-files=all",
        ),
        check=True,
        capture_output=True,
        text=True,
    )
    native_paths = []
    for line in native.stdout.splitlines():
        path = line[3:].strip()
        if " -> " in path:
            path = path.rpartition(" -> ")[2]
        native_paths.append(path.strip('"').replace("\\", "/"))

    assert git_snapshot(ROOT)["git_changed_paths"] == native_paths
