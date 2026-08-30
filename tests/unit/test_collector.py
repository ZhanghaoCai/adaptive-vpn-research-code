import csv
import errno
import hashlib
import json
import math
import os
import stat
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import adaptive_vpn.collector as collector_module
from adaptive_vpn.collector import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    EVIDENCE_SCHEMA_VERSION,
    LEGACY_EVIDENCE_SCHEMA_VERSION,
    MANIFEST_CONTRACTS,
    MAX_EVIDENCE_ARTIFACT_BYTES,
    MAX_EVIDENCE_BUNDLE_BYTES,
    PACKET_FIELDS,
    RENAME_NOREPLACE,
    STRICT_PACKET_EVENT_SCHEMA_VERSION,
    AttemptEvidenceBundle,
    BundleValidation,
    DirectoryPublishUnsupportedError,
    EvidenceBundle,
    validate_evidence_bundle,
)
from adaptive_vpn.config import ExperimentPlan
from adaptive_vpn.provenance import sha256_file
from adaptive_vpn.schedule import generate_schedule
from tests.unit.test_config import minimal_plan_data


def manifest(run_id="00000000-0000-4000-8000-000000000001"):
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "run_id": run_id,
        "dataset_id": "test-dataset",
        "strategy": "adaptive",
        "scenario": "latency_step",
        "traffic_profile": "video_low",
        "block": 1,
        "schedule_seed": 20260803,
        "ordinal": 1,
        "config_sha256": "a" * 64,
        "experimental_unit": "run",
        "provenance": {"git_commit": "a" * 40},
    }


def test_bundle_accepts_deterministic_registered_schedule_id(tmp_path):
    plan = ExperimentPlan.model_validate(minimal_plan_data())
    scheduled_run = generate_schedule(plan)[0]

    bundle = EvidenceBundle.create(tmp_path, manifest(str(scheduled_run.run_id)))
    bundle.write_packet(packet_row())
    bundle.write_event({"event": "test_completed"})
    final_path = bundle.finalise(status="complete")

    assert final_path.name == str(scheduled_run.run_id)


def test_writer_probes_actual_publish_parents_before_creating_staging(
    tmp_path, monkeypatch
):
    observed = []

    def record_probe(staging_parent, final_parent):
        assert staging_parent.is_dir()
        assert final_parent.is_dir()
        observed.append((staging_parent, final_parent))

    monkeypatch.setattr(
        collector_module, "_probe_directory_publish_capability", record_probe
    )

    bundle = EvidenceBundle.create(tmp_path, manifest())

    assert observed == [(tmp_path / ".staging", tmp_path / "raw")]
    assert bundle.staging_path.is_dir()
    bundle.finalise(status="incomplete", failure_reason="probe integration test")


def packet_row(sequence=1):
    return {
        "sequence": sequence,
        "path_id": "path-a",
        "sent_ns": 1_000,
        "received_ns": 2_000,
        "status": "received",
        "rtt_ms": 0.001,
        "datagram_bytes": 256,
    }


def write_minimum_complete_evidence(bundle):
    bundle.write_packet(packet_row())
    bundle.write_event({"event": "test_completed"})


def rewrite_sha256sums(bundle_path):
    hashes = {
        path.name: sha256_file(path)
        for path in bundle_path.iterdir()
        if path.name != "SHA256SUMS"
    }
    (bundle_path / "SHA256SUMS").write_bytes(
        "".join(
            f"{digest}  {name}\n" for name, digest in sorted(hashes.items())
        ).encode("ascii")
    )


def refresh_manifest_evidence_and_sha256sums(bundle_path):
    manifest_path = bundle_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["evidence_sha256"] = {
        name: sha256_file(bundle_path / name) for name in saved["evidence_sha256"]
    }
    manifest_path.write_bytes(
        (
            json.dumps(saved, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        ).encode("utf-8")
    )
    rewrite_sha256sums(bundle_path)


def manifest_v12(
    *,
    attempt_number=1,
    supersedes_attempt_id=None,
    status="complete",
    failure_reason=None,
    attempt_id="00000000-0000-4000-8000-000000000002",
):
    return {
        "schema_version": CURRENT_MANIFEST_SCHEMA_VERSION,
        "cell_id": "00000000-0000-5000-8000-000000000001",
        "attempt_id": attempt_id,
        "attempt_number": attempt_number,
        "supersedes_attempt_id": supersedes_attempt_id,
        "campaign_stage": "pilot",
        "schedule_sha256": "b" * 64,
        "dataset_id": "test-dataset",
        "strategy": "adaptive",
        "scenario": "latency_step",
        "traffic_profile": "video_low",
        "block": 1,
        "schedule_seed": 20260803,
        "ordinal": 1,
        "config_sha256": "a" * 64,
        "experimental_unit": "run",
        "provenance": {"git_commit": "a" * 40, "labels": ["phase-a"]},
        "status": status,
        "failure_reason": failure_reason,
        "finalised_at_utc": "2026-08-04T01:02:03.123456Z",
        "evidence_sha256": {
            "packets.csv": "0" * 64,
            "events.jsonl": "0" * 64,
        },
    }


def write_v12_bundle(tmp_path, *, status="complete", failure_reason=None):
    bundle_path = tmp_path / "raw" / "00000000-0000-4000-8000-000000000002"
    bundle_path.mkdir(parents=True)
    packets = (
        b"sequence,path_id,sent_ns,received_ns,status,rtt_ms,datagram_bytes\n"
        b"1,path-a,1000,2000,received,0.001,256\n"
    )
    events = b'{"event":"test_completed"}\n' if status == "complete" else b""
    (bundle_path / "packets.csv").write_bytes(
        packets if status == "complete" else packets.split(b"\n", 1)[0] + b"\n"
    )
    (bundle_path / "events.jsonl").write_bytes(events)
    manifest = manifest_v12(status=status, failure_reason=failure_reason)
    manifest["evidence_sha256"] = {
        name: hashlib.sha256((bundle_path / name).read_bytes()).hexdigest()
        for name in ("packets.csv", "events.jsonl")
    }
    (bundle_path / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    sums = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in bundle_path.iterdir()
    }
    (bundle_path / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items())),
        encoding="ascii",
        newline="\n",
    )
    return bundle_path


def test_manifest_contract_dispatch_distinguishes_all_readable_versions():
    assert set(MANIFEST_CONTRACTS) == {"1.0.0", "1.1.0", "1.2.0"}
    assert MANIFEST_CONTRACTS["1.0.0"].strict_packet_event is False
    assert MANIFEST_CONTRACTS["1.1.0"].strict_packet_event is True
    assert MANIFEST_CONTRACTS["1.2.0"].strict_packet_event is True
    assert MANIFEST_CONTRACTS["1.1.0"].attempt_identity is False
    assert MANIFEST_CONTRACTS["1.2.0"].attempt_identity is True
    assert EVIDENCE_SCHEMA_VERSION == STRICT_PACKET_EVENT_SCHEMA_VERSION == "1.1.0"


def test_generic_validator_accepts_complete_and_incomplete_v12_bundles(tmp_path):
    complete = validate_evidence_bundle(write_v12_bundle(tmp_path / "complete"))
    incomplete = validate_evidence_bundle(
        write_v12_bundle(
            tmp_path / "incomplete",
            status="incomplete",
            failure_reason="apparatus unavailable",
        )
    )

    assert complete.valid is True
    assert incomplete.valid is True


def test_attempt_writer_uses_v12_attempt_identity_and_rejects_legacy_input(
    tmp_path: Path,
):
    open_manifest = {
        key: value
        for key, value in manifest_v12().items()
        if key
        not in {"status", "failure_reason", "finalised_at_utc", "evidence_sha256"}
    }

    bundle = AttemptEvidenceBundle.create(tmp_path, open_manifest)

    assert bundle.staging_path.name == open_manifest["attempt_id"]
    assert bundle.final_path.name == open_manifest["attempt_id"]
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    validation = validate_evidence_bundle(final_path)
    assert validation.valid is True
    assert validation.manifest["attempt_id"] == open_manifest["attempt_id"]
    assert "run_id" not in validation.manifest

    rejected_root = tmp_path / "rejected"
    with pytest.raises(ValueError, match="requires current schema 1.2.0"):
        AttemptEvidenceBundle.create(rejected_root, manifest())
    assert not rejected_root.exists()


def test_attempt_writer_publishes_distinct_attempts_for_one_registered_cell(
    tmp_path: Path,
):
    attempts = (
        "00000000-0000-4000-8000-000000000011",
        "00000000-0000-4000-8000-000000000012",
    )
    for attempt_number, attempt_id in enumerate(attempts, 1):
        predecessor = attempts[attempt_number - 2] if attempt_number > 1 else None
        open_manifest = {
            key: value
            for key, value in manifest_v12(
                attempt_number=attempt_number,
                supersedes_attempt_id=predecessor,
                attempt_id=attempt_id,
            ).items()
            if key
            not in {"status", "failure_reason", "finalised_at_utc", "evidence_sha256"}
        }
        bundle = AttemptEvidenceBundle.create(tmp_path, open_manifest)
        bundle.finalise(status="incomplete", failure_reason="controlled retry")

    assert {path.name for path in (tmp_path / "raw").iterdir()} == set(attempts)


def test_valid_bundle_returns_deep_read_only_manifest_snapshot_and_sums_digest(tmp_path):
    bundle_path = write_v12_bundle(tmp_path)
    sums_bytes = (bundle_path / "SHA256SUMS").read_bytes()

    result = validate_evidence_bundle(bundle_path)

    assert result.valid is True
    assert result.manifest is not None
    assert result.manifest["attempt_id"] == "00000000-0000-4000-8000-000000000002"
    assert result.manifest["provenance"]["labels"] == ("phase-a",)
    assert result.sha256sums_sha256 == hashlib.sha256(sums_bytes).hexdigest()
    with pytest.raises(TypeError):
        result.manifest["dataset_id"] = "mutated"
    with pytest.raises(TypeError):
        result.manifest["provenance"]["labels"] = ("mutated",)
    with pytest.raises(AttributeError):
        result.manifest["provenance"]["labels"].append("mutated")


def test_invalid_bundle_exposes_no_manifest_snapshot_or_sums_digest(tmp_path):
    bundle_path = write_v12_bundle(tmp_path)
    (bundle_path / "events.jsonl").write_bytes(b"tampered\n")

    result = validate_evidence_bundle(bundle_path)

    assert result.valid is False
    assert result.manifest is None
    assert result.sha256sums_sha256 is None


def test_manifest_replacement_between_checksum_and_parse_fails_closed(tmp_path, monkeypatch):
    bundle_path = write_v12_bundle(tmp_path)
    original = collector_module._read_bounded_regular_bytes
    replaced = False

    def replace_after_capture(path, *, maximum_bytes, label):
        nonlocal replaced
        captured = original(path, maximum_bytes=maximum_bytes, label=label)
        if Path(path).name == "manifest.json" and not replaced:
            replaced = True
            changed = json.loads((Path(path)).read_text(encoding="utf-8"))
            changed["dataset_id"] = "replacement-after-checksum"
            Path(path).write_text(
                json.dumps(changed, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        return captured

    monkeypatch.setattr(
        collector_module, "_read_bounded_regular_bytes", replace_after_capture
    )

    result = validate_evidence_bundle(bundle_path)

    assert replaced is True
    assert result.valid is False
    assert result.manifest is None
    assert any("changed" in error or "race" in error for error in result.errors)


@pytest.mark.skipif(os.name != "posix", reason="FIFO replacement regression")
@pytest.mark.parametrize("artifact", ("packets.csv", "events.jsonl", "trace.jsonl"))
def test_validator_never_reopens_captured_artifact_path(
    tmp_path, monkeypatch, artifact
):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    bundle.write_text_artifact("trace.jsonl", '{"event":"trace"}\n')
    final_path = bundle.finalise(status="complete")
    original_capture = collector_module._read_bounded_regular_bytes
    replaced = False

    def replace_with_fifo_after_capture(path, *, maximum_bytes, label):
        nonlocal replaced
        captured = original_capture(
            path, maximum_bytes=maximum_bytes, label=label
        )
        if Path(path).name == artifact and not replaced:
            replaced = True
            Path(path).unlink()
            os.mkfifo(path)
        return captured

    monkeypatch.setattr(
        collector_module,
        "_read_bounded_regular_bytes",
        replace_with_fifo_after_capture,
    )

    result = validate_evidence_bundle(final_path)

    assert replaced is True
    assert result.valid is False
    assert result.manifest is None
    assert any("changed" in error for error in result.errors)
    (final_path / artifact).unlink()


def test_validator_detects_same_size_in_place_change_after_capture(
    tmp_path, monkeypatch
):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    packet_path = final_path / "packets.csv"
    original_capture = collector_module._read_bounded_regular_bytes
    changed = False

    def mutate_after_capture(path, *, maximum_bytes, label):
        nonlocal changed
        captured = original_capture(
            path, maximum_bytes=maximum_bytes, label=label
        )
        if Path(path).name == "packets.csv" and not changed:
            changed = True
            original_stat = os.stat(path)
            time.sleep(0.01)
            packet_path.write_bytes(packet_path.read_bytes().replace(b"path-a", b"path-b"))
            os.utime(
                path,
                ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
            )
        return captured

    monkeypatch.setattr(
        collector_module, "_read_bounded_regular_bytes", mutate_after_capture
    )

    result = validate_evidence_bundle(final_path)

    assert changed is True
    assert result.valid is False
    assert any("changed" in error for error in result.errors)


def test_validator_accepts_packet_evidence_larger_than_checksum_inventory_limit(
    tmp_path,
):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    packet_path = final_path / "packets.csv"
    rows = [
        "sequence,path_id,sent_ns,received_ns,status,rtt_ms,datagram_bytes\n"
    ]
    rows.extend(
        f"{sequence},path-a,{sequence * 1000},{sequence * 1000 + 1000},"
        "received,0.001,256\n"
        for sequence in range(1, 30_001)
    )
    packet_path.write_text("".join(rows), encoding="utf-8", newline="\n")
    assert packet_path.stat().st_size > 1_048_576
    refresh_manifest_evidence_and_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is True


def test_validator_enforces_explicit_artifact_and_bundle_byte_limits(
    tmp_path, monkeypatch
):
    bundle_path = write_v12_bundle(tmp_path)
    packet_size = (bundle_path / "packets.csv").stat().st_size
    monkeypatch.setattr(
        collector_module, "MAX_EVIDENCE_ARTIFACT_BYTES", packet_size - 1
    )

    artifact_result = validate_evidence_bundle(bundle_path)

    assert artifact_result.valid is False
    assert any("packets.csv" in error and "exceeds" in error for error in artifact_result.errors)

    monkeypatch.setattr(
        collector_module, "MAX_EVIDENCE_ARTIFACT_BYTES", MAX_EVIDENCE_ARTIFACT_BYTES
    )
    monkeypatch.setattr(
        collector_module, "MAX_EVIDENCE_BUNDLE_BYTES", MAX_EVIDENCE_BUNDLE_BYTES
    )
    total_size = sum(path.stat().st_size for path in bundle_path.iterdir())
    monkeypatch.setattr(
        collector_module, "MAX_EVIDENCE_BUNDLE_BYTES", total_size - 1
    )

    bundle_result = validate_evidence_bundle(bundle_path)

    assert bundle_result.valid is False
    assert any("total bytes" in error for error in bundle_result.errors)


def test_bundle_validation_three_positional_arguments_remain_compatible():
    result = BundleValidation(False, ("invalid",), ())

    assert result.valid is False
    assert result.errors == ("invalid",)
    assert result.manifest is None
    assert result.sha256sums_sha256 is None


@pytest.mark.skipif(os.name != "posix", reason="Linux renameat2 injection")
def test_linux_publish_uses_renameat2_with_rename_noreplace(tmp_path):
    staging_parent = tmp_path / ".staging"
    raw_parent = tmp_path / "raw"
    staging_parent.mkdir()
    raw_parent.mkdir()
    source = staging_parent / "source"
    destination = raw_parent / "destination"
    source.mkdir()
    calls = []

    def fake_renameat2(source_fd, source_name, destination_fd, destination_name, flags):
        calls.append((source_fd, source_name, destination_fd, destination_name, flags))
        os.rename(
            source_name,
            destination_name,
            src_dir_fd=source_fd,
            dst_dir_fd=destination_fd,
        )
        return 0

    collector_module._publish_directory_linux(
        source,
        destination,
        renameat2=fake_renameat2,
        fsync_directory=lambda path: None,
    )

    assert calls
    assert calls[0][-1] == RENAME_NOREPLACE


@pytest.mark.skipif(os.name != "posix", reason="Linux renameat2 injection")
@pytest.mark.parametrize("error_number", [errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP])
def test_linux_publish_maps_unsupported_renameat2_errors(tmp_path, error_number):
    staging_parent = tmp_path / ".staging"
    raw_parent = tmp_path / "raw"
    staging_parent.mkdir()
    raw_parent.mkdir()
    source = staging_parent / "source"
    destination = raw_parent / "destination"
    source.mkdir()

    def fake_renameat2(*args):
        raise OSError(error_number, "unsupported")

    with pytest.raises(DirectoryPublishUnsupportedError):
        collector_module._publish_directory_linux(
            source,
            destination,
            renameat2=fake_renameat2,
            fsync_directory=lambda path: None,
        )


@pytest.mark.skipif(os.name != "posix", reason="Linux renameat2 injection")
def test_linux_publish_preserves_existing_destination_on_eexist(tmp_path):
    staging_parent = tmp_path / ".staging"
    raw_parent = tmp_path / "raw"
    staging_parent.mkdir()
    raw_parent.mkdir()
    source = staging_parent / "source"
    destination = raw_parent / "destination"
    source.mkdir()
    (source / "source.txt").write_text("source", encoding="ascii")
    destination.mkdir()
    (destination / "sentinel.txt").write_text("sentinel", encoding="ascii")

    def fake_renameat2(*args):
        raise OSError(errno.EEXIST, "occupied")

    with pytest.raises(FileExistsError):
        collector_module._publish_directory_linux(
            source,
            destination,
            renameat2=fake_renameat2,
            fsync_directory=lambda path: None,
        )

    assert (destination / "sentinel.txt").read_text(encoding="ascii") == "sentinel"
    assert (source / "source.txt").read_text(encoding="ascii") == "source"
    assert (source / "source.txt").read_text(encoding="ascii") == "source"


def test_windows_publish_omits_movefile_replace_existing(tmp_path):
    staging_parent = tmp_path / ".staging"
    raw_parent = tmp_path / "raw"
    staging_parent.mkdir()
    raw_parent.mkdir()
    source = staging_parent / "source"
    destination = raw_parent / "destination"
    source.mkdir()
    calls = []

    def fake_move(source_path, destination_path, flags):
        calls.append((source_path, destination_path, flags))
        source_path.rename(destination_path)
        return True

    collector_module._publish_directory_windows(
        source,
        destination,
        move_file_ex=fake_move,
        fsync_directory=lambda path: None,
    )

    assert calls
    assert calls[0][2] & collector_module._MOVEFILE_WRITE_THROUGH
    assert not calls[0][2] & collector_module._MOVEFILE_REPLACE_EXISTING
    assert destination.is_dir()
    assert not source.exists()


def test_windows_publish_maps_existing_destination_without_overwrite(tmp_path):
    staging_parent = tmp_path / ".staging"
    raw_parent = tmp_path / "raw"
    staging_parent.mkdir()
    raw_parent.mkdir()
    source = staging_parent / "source"
    destination = raw_parent / "destination"
    source.mkdir()
    (source / "source.txt").write_text("source", encoding="ascii")
    destination.mkdir()
    (destination / "sentinel.txt").write_text("sentinel", encoding="ascii")

    def fake_move(source_path, destination_path, flags):
        raise OSError(183, "already exists")

    with pytest.raises(FileExistsError):
        collector_module._publish_directory_windows(
            source,
            destination,
            move_file_ex=fake_move,
            fsync_directory=lambda path: None,
        )

    assert (destination / "sentinel.txt").read_text(encoding="ascii") == "sentinel"


@pytest.mark.skipif(os.name != "posix", reason="dir-fd source swap injection")
def test_linux_publish_rejects_source_swap_before_rename(tmp_path, monkeypatch):
    staging_parent = tmp_path / ".staging"
    raw_parent = tmp_path / "raw"
    staging_parent.mkdir()
    raw_parent.mkdir()
    source = staging_parent / "source"
    original = staging_parent / "original-source"
    destination = raw_parent / "destination"
    source.mkdir()
    (source / "original.txt").write_text("original", encoding="ascii")
    real_open = collector_module._open_publish_parent
    swapped = False

    def swap_then_open(path, expected_identity):
        nonlocal swapped
        if not swapped and Path(path) == staging_parent:
            swapped = True
            source.rename(original)
            source.mkdir()
            (source / "replacement.txt").write_text("replacement", encoding="ascii")
        return real_open(path, expected_identity)

    monkeypatch.setattr(collector_module, "_open_publish_parent", swap_then_open)

    with pytest.raises(ValueError, match="source identity changed"):
        collector_module._publish_directory_linux(
            source,
            destination,
            fsync_directory=lambda path: None,
        )

    assert swapped is True
    assert not destination.exists()
    assert (original / "original.txt").read_text(encoding="ascii") == "original"
    assert (source / "replacement.txt").read_text(encoding="ascii") == "replacement"


@pytest.mark.skipif(os.name != "posix", reason="requires held POSIX dirfds")
def test_linux_publish_parent_swap_during_sync_rolls_back_through_held_dirfds(
    tmp_path: Path,
):
    staging_parent = tmp_path / ".staging"
    raw_parent = tmp_path / "raw"
    old_raw_parent = tmp_path / "old-raw"
    staging_parent.mkdir()
    raw_parent.mkdir()
    source = staging_parent / "source"
    destination = raw_parent / "destination"
    source.mkdir()
    (source / "original.txt").write_text("original", encoding="ascii")
    swapped = False

    def swap_destination_parent(path: Path) -> None:
        nonlocal swapped
        if not swapped:
            swapped = True
            raw_parent.rename(old_raw_parent)
            raw_parent.mkdir()

    with pytest.raises(RuntimeError, match="parent identity changed"):
        collector_module._publish_directory_linux(
            source,
            destination,
            fsync_directory=swap_destination_parent,
        )

    assert swapped is True
    assert source.is_dir()
    assert (source / "original.txt").read_text(encoding="ascii") == "original"
    assert not destination.exists()
    assert not (old_raw_parent / "destination").exists()


def test_windows_publish_rolls_back_swapped_source_identity(tmp_path):
    staging_parent = tmp_path / ".staging"
    raw_parent = tmp_path / "raw"
    staging_parent.mkdir()
    raw_parent.mkdir()
    source = staging_parent / "source"
    original = staging_parent / "original-source"
    destination = raw_parent / "destination"
    source.mkdir()
    (source / "original.txt").write_text("original", encoding="ascii")
    first_move = True

    def swap_move(source_path, destination_path, flags):
        nonlocal first_move
        if first_move:
            first_move = False
            source_path.rename(original)
            source_path.mkdir()
            (source_path / "replacement.txt").write_text(
                "replacement", encoding="ascii"
            )
        source_path.rename(destination_path)
        return True

    with pytest.raises(RuntimeError, match="identity does not match"):
        collector_module._publish_directory_windows(
            source,
            destination,
            move_file_ex=swap_move,
            fsync_directory=lambda path: None,
        )

    assert not destination.exists()
    assert (original / "original.txt").read_text(encoding="ascii") == "original"
    assert (source / "replacement.txt").read_text(encoding="ascii") == "replacement"


def test_windows_injected_source_swap_and_rollback_failure_quarantines_final(
    tmp_path: Path,
):
    staging_parent = tmp_path / ".staging"
    raw_parent = tmp_path / "raw"
    staging_parent.mkdir()
    raw_parent.mkdir()
    source = staging_parent / "source"
    original = staging_parent / "original-source"
    destination = raw_parent / "destination"
    source.mkdir()
    (source / "original.txt").write_text("original", encoding="ascii")
    calls = 0

    def swap_fail_rollback_then_quarantine(source_path, destination_path, flags):
        nonlocal calls
        calls += 1
        if calls == 1:
            source_path.rename(original)
            source_path.mkdir()
            (source_path / "replacement.txt").write_text(
                "replacement", encoding="ascii"
            )
            source_path.rename(destination_path)
            return True
        if calls == 2:
            raise OSError("forced rollback failure")
        source_path.rename(destination_path)
        return True

    with pytest.raises(BaseExceptionGroup, match="recovery failures"):
        collector_module._publish_directory_windows(
            source,
            destination,
            move_file_ex=swap_fail_rollback_then_quarantine,
            fsync_directory=lambda path: None,
        )

    assert calls == 3
    assert not destination.exists()
    quarantined = list(raw_parent.glob(".quarantine-*"))
    assert len(quarantined) == 1
    assert (quarantined[0] / "replacement.txt").read_text(encoding="ascii") == (
        "replacement"
    )
    assert (original / "original.txt").read_text(encoding="ascii") == "original"


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows handles")
def test_windows_publish_held_handles_block_parent_swap_and_roll_back(tmp_path: Path):
    staging_parent = tmp_path / ".staging"
    raw_parent = tmp_path / "raw"
    old_raw_parent = tmp_path / "old-raw"
    staging_parent.mkdir()
    raw_parent.mkdir()
    source = staging_parent / "source"
    destination = raw_parent / "destination"
    source.mkdir()
    (source / "original.txt").write_text("original", encoding="ascii")
    swap_attempted = False

    def swap_destination_parent(path: Path) -> None:
        nonlocal swap_attempted
        if not swap_attempted:
            swap_attempted = True
            root_handle = collector_module._open_directory_handle_windows(
                tmp_path,
                rename_source=False,
            )
            raw_handle = collector_module._open_directory_handle_windows(
                raw_parent,
                rename_source=True,
            )
            try:
                collector_module._invoke_set_file_information_rename_windows(
                    raw_handle,
                    root_handle,
                    old_raw_parent.name,
                )
            finally:
                collector_module._close_windows_handle(raw_handle)
                collector_module._close_windows_handle(root_handle)

    with pytest.raises(OSError, match="NtSetInformationFile rename failed"):
        collector_module._publish_directory_windows(
            source,
            destination,
            fsync_directory=swap_destination_parent,
        )

    assert swap_attempted is True
    assert source.is_dir()
    assert not destination.exists()
    assert not old_raw_parent.exists()


def test_windows_reparse_attribute_is_never_a_real_directory_or_file():
    observed = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o700,
        st_file_attributes=collector_module._FILE_ATTRIBUTE_REPARSE_POINT,
    )

    assert collector_module._is_reparse_point(observed) is True
    assert collector_module._is_real_directory_stat(observed) is False
    observed.st_mode = stat.S_IFREG | 0o600
    assert collector_module._is_regular_file_stat(observed) is False


def test_publish_capability_probe_proves_occupied_and_free_destinations(tmp_path):
    staging_parent = tmp_path / ".staging"
    raw_parent = tmp_path / "raw"
    staging_parent.mkdir()
    raw_parent.mkdir()

    collector_module._probe_directory_publish_capability(staging_parent, raw_parent)

    assert list(staging_parent.iterdir()) == []
    assert list(raw_parent.iterdir()) == []


def test_publish_capability_probe_fails_if_primitive_overwrites_occupied_target(
    tmp_path, monkeypatch
):
    staging_parent = tmp_path / ".staging"
    raw_parent = tmp_path / "raw"
    staging_parent.mkdir()
    raw_parent.mkdir()

    def overwrite(source, destination):
        (destination / "sentinel.txt").unlink()
        destination.rmdir()
        source.replace(destination)

    monkeypatch.setattr(collector_module, "_publish_directory_no_replace", overwrite)

    with pytest.raises(RuntimeError, match="occupied"):
        collector_module._probe_directory_publish_capability(staging_parent, raw_parent)


def test_finalise_destination_race_preserves_sentinel_and_quarantines_staging(
    tmp_path, monkeypatch
):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    raced = False
    publish_without_race = collector_module._publish_directory_no_replace

    def race(source, destination):
        nonlocal raced
        raced = True
        destination.mkdir()
        (destination / "sentinel.txt").write_text("keep", encoding="ascii")
        return publish_without_race(source, destination)

    monkeypatch.setattr(collector_module, "_publish_directory_no_replace", race)

    with pytest.raises(FileExistsError):
        bundle.finalise(status="complete")

    assert raced is True
    assert (bundle.final_path / "sentinel.txt").read_text(encoding="ascii") == "keep"
    assert bundle.staging_path.is_dir()
    assert bundle.lifecycle_state == "quarantined"


def rewrite_after_core_artifact_change(bundle_path, artifact):
    if artifact in {"packets.csv", "events.jsonl"}:
        refresh_manifest_evidence_and_sha256sums(bundle_path)
    elif artifact == "manifest.json":
        rewrite_sha256sums(bundle_path)


def test_complete_bundle_requires_packet_and_event_evidence(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())

    with pytest.raises(ValueError, match="packet"):
        bundle.finalise(status="complete")

    bundle.write_packet(packet_row())
    with pytest.raises(ValueError, match="event"):
        bundle.finalise(status="complete")

    bundle.write_event({"event": "test_completed"})
    assert bundle.finalise(status="complete").is_dir()


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"sequence": True}, "sequence"),
        ({"path_id": ""}, "path_id"),
        ({"received_ns": 999}, "received_ns"),
        ({"status": "lost"}, "status"),
        ({"status": "timeout"}, "timeout"),
        ({"rtt_ms": math.nan}, "rtt_ms"),
        ({"datagram_bytes": 31}, "datagram_bytes"),
    ],
)
def test_packet_writer_rejects_semantically_invalid_rows(tmp_path, changes, message):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    row = {**packet_row(), **changes}

    with pytest.raises(ValueError, match=message):
        bundle.write_packet(row)

    bundle.finalise(status="incomplete", failure_reason="expected validation failure")


def test_packet_writer_rejects_duplicate_sequence(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    bundle.write_packet(packet_row())

    with pytest.raises(ValueError, match="duplicate sequence"):
        bundle.write_packet(packet_row())

    bundle.finalise(status="incomplete", failure_reason="expected validation failure")


@pytest.mark.parametrize(
    "event",
    [
        {},
        {"event": ""},
        {"event": 1},
        {"event": "invalid", "value": math.inf},
    ],
)
def test_event_writer_rejects_semantically_invalid_events(tmp_path, event):
    bundle = EvidenceBundle.create(tmp_path, manifest())

    with pytest.raises((TypeError, ValueError)):
        bundle.write_event(event)

    bundle.finalise(status="incomplete", failure_reason="expected validation failure")


def test_finalised_run_is_immutable(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    bundle.write_packet(packet_row())
    bundle.write_event({"event": "test_completed"})
    final_path = bundle.finalise(status="complete")

    assert final_path == tmp_path / "raw" / manifest()["run_id"]
    with pytest.raises(RuntimeError, match="finalised"):
        bundle.write_packet(packet_row(sequence=2))
    with pytest.raises(RuntimeError, match="finalised"):
        bundle.write_event({"event": "late"})


def test_incomplete_run_is_retained_with_reason(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    bundle.write_event({"event": "setup_failed", "detail": "test failure"})
    final_path = bundle.finalise(status="incomplete", failure_reason="setup failed")

    saved = json.loads((final_path / "manifest.json").read_text(encoding="utf-8"))
    assert saved["status"] == "incomplete"
    assert saved["failure_reason"] == "setup failed"


def test_finalisation_hashes_every_evidence_file_and_validates(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    bundle.write_packet(packet_row())
    bundle.write_event({"event": "phase_started", "phase": 1})
    bundle.write_text_artifact("tc-state.txt", "qdisc netem delay 20ms\n")
    final_path = bundle.finalise(status="complete")

    result = validate_evidence_bundle(final_path)
    assert result.valid is True
    assert result.errors == ()
    assert {"packets.csv", "events.jsonl", "tc-state.txt", "manifest.json"} <= set(
        result.checked_files
    )


def test_validation_detects_post_finalisation_tampering(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    (final_path / "packets.csv").write_text("tampered\n", encoding="utf-8")

    result = validate_evidence_bundle(final_path)
    assert result.valid is False
    assert any("packets.csv" in error for error in result.errors)


def test_packet_csv_has_one_versioned_schema_and_explicit_empty_values(tmp_path):
    row = packet_row()
    row["received_ns"] = None
    row["rtt_ms"] = None
    row["status"] = "timeout"
    bundle = EvidenceBundle.create(tmp_path, manifest())
    bundle.write_packet(row)
    bundle.write_event({"event": "test_completed"})
    final_path = bundle.finalise(status="complete")

    with (final_path / "packets.csv").open(newline="", encoding="utf-8") as handle:
        saved = next(csv.DictReader(handle))
    assert saved["sequence"] == "1"
    assert saved["status"] == "timeout"
    assert saved["received_ns"] == ""
    assert saved["rtt_ms"] == ""


def test_writer_uses_canonical_lf_for_all_core_text_artifacts(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")

    for name in ("packets.csv", "events.jsonl", "manifest.json", "SHA256SUMS"):
        content = (final_path / name).read_bytes()
        assert b"\r\n" not in content
        assert content.endswith(b"\n")


def test_validation_rejects_rehashed_current_bundle_with_crlf_core_artifacts(
    tmp_path,
):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")

    for name in ("packets.csv", "events.jsonl"):
        artifact = final_path / name
        artifact.write_bytes(artifact.read_bytes().replace(b"\n", b"\r\n"))

    manifest_path = final_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["evidence_sha256"] = {
        name: sha256_file(final_path / name) for name in saved["evidence_sha256"]
    }
    manifest_path.write_bytes(
        (json.dumps(saved, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
        .replace("\n", "\r\n")
        .encode("utf-8")
    )
    hashes = {
        path.name: sha256_file(path)
        for path in final_path.iterdir()
        if path.name != "SHA256SUMS"
    }
    (final_path / "SHA256SUMS").write_bytes(
        "".join(f"{digest}  {name}\r\n" for name, digest in sorted(hashes.items()))
        .encode("ascii")
    )

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("canonical LF" in error for error in result.errors)


@pytest.mark.parametrize(
    "artifact", ["packets.csv", "events.jsonl", "manifest.json", "SHA256SUMS"]
)
def test_validation_rejects_each_rehashed_current_crlf_core_artifact(
    tmp_path, artifact
):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    artifact_path = final_path / artifact
    artifact_path.write_bytes(artifact_path.read_bytes().replace(b"\n", b"\r\n"))
    rewrite_after_core_artifact_change(final_path, artifact)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any(
        artifact in error and "canonical LF" in error for error in result.errors
    )


@pytest.mark.parametrize("separator", [b"\x1c", b"\x1d", b"\x1e"])
def test_validation_rejects_non_lf_control_line_separators(tmp_path, separator):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    sums_path = final_path / "SHA256SUMS"
    content = sums_path.read_bytes()
    assert b"\n" in content[:-1]
    sums_path.write_bytes(content.replace(b"\n", separator, 1))

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("canonical LF" in error for error in result.errors)


@pytest.mark.parametrize(
    "artifact", ["packets.csv", "events.jsonl", "manifest.json", "SHA256SUMS"]
)
def test_validation_rejects_current_core_artifact_without_terminal_lf(
    tmp_path, artifact
):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    artifact_path = final_path / artifact
    content = artifact_path.read_bytes()
    assert content.endswith(b"\n")
    artifact_path.write_bytes(content[:-1])
    rewrite_after_core_artifact_change(final_path, artifact)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any(
        artifact in error and "terminal LF" in error for error in result.errors
    )


def test_bundle_refuses_path_traversal_artifact_names(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    with pytest.raises(ValueError, match="artifact"):
        bundle.write_text_artifact("../outside.txt", "unsafe")
    bundle.finalise(status="incomplete", failure_reason="expected test")


def test_validation_rejects_empty_checksum_inventory(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    (final_path / "SHA256SUMS").write_text("", encoding="ascii")

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("empty" in error for error in result.errors)


def test_public_validator_fails_closed_but_preserves_process_control(monkeypatch):
    monkeypatch.setattr(
        "adaptive_vpn.collector._validate_evidence_bundle",
        lambda path: (_ for _ in ()).throw(RuntimeError("forced parser failure")),
    )

    result = validate_evidence_bundle(Path("unused"))

    assert result.valid is False
    assert any("forced parser failure" in error for error in result.errors)

    monkeypatch.setattr(
        "adaptive_vpn.collector._validate_evidence_bundle",
        lambda path: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        validate_evidence_bundle(Path("unused"))


def test_validation_rejects_unlisted_extra_file(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    (final_path / "unlisted.txt").write_text("not inventoried\n", encoding="utf-8")

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("not listed" in error for error in result.errors)


def test_validation_rejects_duplicate_checksum_entry(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    sums_path = final_path / "SHA256SUMS"
    first_line = sums_path.read_text(encoding="ascii").splitlines()[0]
    sums_path.write_text(
        sums_path.read_text(encoding="ascii") + first_line + "\n",
        encoding="ascii",
    )

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("duplicate" in error for error in result.errors)


def test_validation_reconciles_manifest_evidence_hashes(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    manifest_path = final_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["evidence_sha256"]["packets.csv"] = "0" * 64
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    rewrite_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("evidence_sha256" in error for error in result.errors)


@pytest.mark.parametrize("artifact", ["packets.csv", "events.jsonl"])
def test_validation_rejects_rehashed_semantically_invalid_evidence(tmp_path, artifact):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    if artifact == "packets.csv":
        with (final_path / artifact).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=(
                "sequence",
                "path_id",
                "sent_ns",
                "received_ns",
                "status",
                "rtt_ms",
                "datagram_bytes",
            ))
            writer.writeheader()
            writer.writerow({**packet_row(), "status": "timeout"})
    else:
        (final_path / artifact).write_text("{}\n", encoding="utf-8")
    refresh_manifest_evidence_and_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any(artifact in error for error in result.errors)


def test_validation_rejects_rehashed_huge_packet_integer_without_raising(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    with (final_path / "packets.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=(
            "sequence",
            "path_id",
            "sent_ns",
            "received_ns",
            "status",
            "rtt_ms",
            "datagram_bytes",
        ))
        writer.writeheader()
        writer.writerow({**packet_row(), "received_ns": "9" * 4_000, "rtt_ms": "1"})
    refresh_manifest_evidence_and_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("received_ns" in error for error in result.errors)


def test_validation_rejects_deep_event_json_without_raising(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    nested = "[" * 1_100 + "0" + "]" * 1_100
    (final_path / "events.jsonl").write_text(
        '{"event":"deep","value":' + nested + "}\n",
        encoding="utf-8",
    )
    refresh_manifest_evidence_and_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("events.jsonl" in error for error in result.errors)


def test_validation_counts_raw_crlf_jsonl_bytes_before_decoding(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    base = json.dumps(
        {"event": "x", "padding": ""},
        sort_keys=True,
        ensure_ascii=True,
    ).encode("ascii")
    padding = b"a" * (1_048_576 - 1 - len(base))
    raw_line = base[:-2] + padding + base[-2:] + b"\r\n"
    assert len(raw_line) == 1_048_577
    (final_path / "events.jsonl").write_bytes(raw_line)
    refresh_manifest_evidence_and_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("exceeds" in error for error in result.errors)


def test_validation_rejects_unregistered_schema_version_and_strategy(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    manifest_path = final_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["schema_version"] = "9.9.9"
    saved["strategy"] = "bogus"
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    rewrite_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("schema_version" in error for error in result.errors)
    assert any("strategy" in error for error in result.errors)


def test_validator_reads_original_legacy_manifest_contract(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    manifest_path = final_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["schema_version"] = LEGACY_EVIDENCE_SCHEMA_VERSION
    for field in (
        "ordinal",
        "config_sha256",
        "experimental_unit",
        "failure_reason",
        "finalised_at_utc",
    ):
        saved.pop(field)
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    rewrite_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is True


def test_legacy_reader_preserves_original_packet_and_event_schema_semantics(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    with (final_path / "packets.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=(
            "sequence",
            "path_id",
            "sent_ns",
            "received_ns",
            "status",
            "rtt_ms",
            "datagram_bytes",
        ))
        writer.writeheader()
        writer.writerow({**packet_row(), "status": "timeout"})
    (final_path / "events.jsonl").write_text(
        '{"event":" "}\n', encoding="utf-8", newline="\n"
    )
    manifest_path = final_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["schema_version"] = LEGACY_EVIDENCE_SCHEMA_VERSION
    for field in (
        "ordinal",
        "config_sha256",
        "experimental_unit",
        "failure_reason",
        "finalised_at_utc",
    ):
        saved.pop(field)
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    refresh_manifest_evidence_and_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is True


def test_validation_rejects_secret_keys_in_legacy_events(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    secret_key = "pass" + "word"
    (final_path / "events.jsonl").write_text(
        json.dumps({"event": "legacy", secret_key: "not-a-secret"}) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    manifest_path = final_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["schema_version"] = LEGACY_EVIDENCE_SCHEMA_VERSION
    for field in (
        "ordinal",
        "config_sha256",
        "experimental_unit",
        "failure_reason",
        "finalised_at_utc",
    ):
        saved.pop(field)
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    refresh_manifest_evidence_and_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("secret-bearing key" in error for error in result.errors)


def test_legacy_reader_accepts_historical_crlf_core_artifacts(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    manifest_path = final_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["schema_version"] = LEGACY_EVIDENCE_SCHEMA_VERSION
    for field in (
        "ordinal",
        "config_sha256",
        "experimental_unit",
        "provenance",
        "failure_reason",
        "finalised_at_utc",
    ):
        saved.pop(field)
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    refresh_manifest_evidence_and_sha256sums(final_path)
    for name in ("packets.csv", "events.jsonl", "manifest.json", "SHA256SUMS"):
        path = final_path / name
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["evidence_sha256"] = {
        name: sha256_file(final_path / name) for name in saved["evidence_sha256"]
    }
    manifest_path.write_bytes(
        (json.dumps(saved, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
        .replace("\n", "\r\n")
        .encode("utf-8")
    )
    hashes = {
        path.name: sha256_file(path)
        for path in final_path.iterdir()
        if path.name != "SHA256SUMS"
    }
    (final_path / "SHA256SUMS").write_bytes(
        "".join(
            f"{digest}  {name}\r\n" for name, digest in sorted(hashes.items())
        ).encode("ascii")
    )

    assert validate_evidence_bundle(final_path).valid is True


@pytest.mark.parametrize(
    ("artifact", "content"),
    [
        ("lab-status.json", '{"pass' + 'word":"not-a-secret"}\n'),
        ("trace.JSONL", '{"event":"trace","pass' + 'word":"not-a-secret"}\n'),
        ("nested.json", '{"node_cred' + 'ential":"not-a-secret"}\n'),
    ],
)
def test_writer_rejects_secret_keys_in_auxiliary_structured_artifacts(
    tmp_path, artifact, content
):
    bundle = EvidenceBundle.create(tmp_path, manifest())

    with pytest.raises(ValueError, match="secret-bearing key"):
        bundle.write_text_artifact(artifact, content)

    bundle.finalise(status="incomplete", failure_reason="expected boundary rejection")


@pytest.mark.parametrize(
    ("artifact", "safe_content", "unsafe_content"),
    [
        (
            "lab-status.json",
            '{"clean":true}\n',
            '{"pass' + 'word":"not-a-secret"}\n',
        ),
        (
            "trace.jsonl",
            '{"event":"trace"}\n',
            '{"event":"trace","pass' + 'word":"not-a-secret"}\n',
        ),
    ],
)
def test_validation_rejects_rehashed_secret_keys_in_auxiliary_structured_artifacts(
    tmp_path, artifact, safe_content, unsafe_content
):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    bundle.write_text_artifact(artifact, safe_content)
    final_path = bundle.finalise(status="complete")
    (final_path / artifact).write_text(
        unsafe_content, encoding="utf-8", newline="\n"
    )
    refresh_manifest_evidence_and_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any(
        artifact in error and "secret-bearing key" in error
        for error in result.errors
    )


def test_legacy_reader_rejects_noncanonical_uuid_text(tmp_path):
    run_id = manifest()["run_id"]
    bundle = EvidenceBundle.create(tmp_path, manifest(run_id))
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    manifest_path = final_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["schema_version"] = LEGACY_EVIDENCE_SCHEMA_VERSION
    saved["run_id"] = run_id.replace("-", "")
    for field in (
        "ordinal",
        "config_sha256",
        "experimental_unit",
        "failure_reason",
        "finalised_at_utc",
    ):
        saved.pop(field)
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    rewrite_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("canonical" in error for error in result.errors)


def test_writer_refuses_to_create_new_legacy_bundle(tmp_path):
    legacy_manifest = {
        **manifest(),
        "schema_version": LEGACY_EVIDENCE_SCHEMA_VERSION,
    }

    with pytest.raises(ValueError, match="current schema"):
        EvidenceBundle.create(tmp_path, legacy_manifest)


@pytest.mark.parametrize(("field", "value"), [("strategy", []), ("status", {})])
def test_validation_rejects_unhashable_manifest_fields_without_raising(
    tmp_path, field, value
):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    manifest_path = final_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved[field] = value
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    rewrite_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any(field in error for error in result.errors)


def test_writer_and_validator_reject_noncanonical_uuid_text(tmp_path):
    noncanonical = manifest()["run_id"].replace("-", "")
    with pytest.raises(ValueError, match="canonical"):
        EvidenceBundle.create(tmp_path, manifest(noncanonical))

    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    manifest_path = final_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["run_id"] = noncanonical
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    rewrite_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("canonical" in error for error in result.errors)


def test_validation_requires_exact_timestamp_derived_rtt(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    with (final_path / "packets.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=(
            "sequence",
            "path_id",
            "sent_ns",
            "received_ns",
            "status",
            "rtt_ms",
            "datagram_bytes",
        ))
        writer.writeheader()
        writer.writerow({**packet_row(), "rtt_ms": 0.0010000000005})
    refresh_manifest_evidence_and_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("rtt_ms" in error for error in result.errors)


def test_validation_binds_manifest_run_id_to_bundle_directory(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    wrong_path = final_path.with_name("00000000-0000-4000-8000-000000000099")
    final_path.rename(wrong_path)

    result = validate_evidence_bundle(wrong_path)

    assert result.valid is False
    assert any("directory" in error and "run_id" in error for error in result.errors)


def test_validation_returns_invalid_for_manifest_without_run_id(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    manifest_path = final_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    del saved["run_id"]
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    rewrite_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("run_id" in error for error in result.errors)


def test_validation_rejects_noncanonical_basic_iso_timestamp(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    manifest_path = final_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["finalised_at_utc"] = "20260804T010203Z"
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    rewrite_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("finalised_at_utc" in error for error in result.errors)


@pytest.mark.parametrize("failure", ["validation", "rename"])
def test_sealing_failure_quarantines_bundle_and_preserves_staging(
    tmp_path, monkeypatch, failure
):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    if failure == "validation":
        monkeypatch.setattr(
            "adaptive_vpn.collector.validate_evidence_bundle",
            lambda path: BundleValidation(False, ("forced self-check failure",), ()),
        )
        expected = "forced self-check failure"
    else:
        def fail_staging_publish(path, target):
            raise OSError("forced publish rename failure")

        monkeypatch.setattr(
            "adaptive_vpn.collector._publish_directory_no_replace",
            fail_staging_publish,
        )
        expected = "forced publish rename failure"

    with pytest.raises((OSError, ValueError), match=expected):
        bundle.finalise(status="complete")

    assert bundle.lifecycle_state == "quarantined"
    assert bundle.staging_path.is_dir()
    assert not bundle.final_path.exists()
    with pytest.raises(RuntimeError, match="quarantined"):
        bundle.write_event({"event": "must_not_overwrite_primary_failure"})


def test_pre_publish_validation_failure_durably_quarantines_staging(
    tmp_path, monkeypatch
):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    synced_directories: list[Path] = []

    monkeypatch.setattr(
        "adaptive_vpn.collector.validate_evidence_bundle",
        lambda path: BundleValidation(False, ("forced self-check failure",), ()),
    )
    monkeypatch.setattr(
        "adaptive_vpn.collector._fsync_directory",
        lambda path: synced_directories.append(Path(path)),
    )

    with pytest.raises(ValueError, match="forced self-check failure"):
        bundle.finalise(status="complete")

    assert bundle.lifecycle_state == "quarantined"
    assert bundle.staging_path.is_dir()
    assert not bundle.final_path.exists()
    assert bundle.staging_path in synced_directories
    assert bundle.staging_path.parent in synced_directories
    assert bundle.base_dir in synced_directories


def test_post_rename_fsync_failure_rolls_back_to_quarantined_staging(
    tmp_path, monkeypatch
):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    original_fsync_directory = collector_module._fsync_directory
    injected = False

    def fail_first_destination_sync(path):
        nonlocal injected
        if not injected and path == bundle.final_path.parent and bundle.final_path.exists():
            injected = True
            raise OSError("forced post-rename fsync failure")
        return original_fsync_directory(path)

    monkeypatch.setattr(
        "adaptive_vpn.collector._fsync_directory", fail_first_destination_sync
    )

    with pytest.raises(OSError, match="forced post-rename fsync failure"):
        bundle.finalise(status="complete")

    assert injected is True
    assert bundle.lifecycle_state == "quarantined"
    assert bundle.staging_path.is_dir()
    assert not bundle.final_path.exists()


def test_fsync_failure_closes_both_streams_and_quarantines(tmp_path, monkeypatch):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    original_fsync = os.fsync
    calls = 0

    def fail_first_fsync(file_descriptor):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("forced packet fsync failure")
        return original_fsync(file_descriptor)

    monkeypatch.setattr("adaptive_vpn.collector.os.fsync", fail_first_fsync)

    with pytest.raises(OSError, match="forced packet fsync failure"):
        bundle.finalise(status="complete")

    assert bundle.lifecycle_state == "quarantined"
    assert bundle._packet_handle.closed is True
    assert bundle._event_handle.closed is True


def test_writer_rejects_event_whose_jsonl_line_exceeds_byte_limit(tmp_path):
    limit = 1_048_576
    overhead = len(
        json.dumps(
            {"event": ""}, sort_keys=True, ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    )
    bundle = EvidenceBundle.create(tmp_path, manifest())

    with pytest.raises(ValueError, match="event exceeds"):
        bundle.write_event({"event": "a" * (limit - overhead)})

    bundle.finalise(status="incomplete", failure_reason="expected boundary rejection")


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX /proc fd names and directory fsync semantics"
)
def test_finalisation_fsyncs_all_evidence_and_publish_directories(tmp_path, monkeypatch):
    synced: list[str] = []
    original_fsync = os.fsync

    def record_fsync(file_descriptor):
        synced.append(os.readlink(f"/proc/self/fd/{file_descriptor}"))
        return original_fsync(file_descriptor)

    monkeypatch.setattr("adaptive_vpn.collector.os.fsync", record_fsync)
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    bundle.write_text_artifact("lab-status.json", '{"clean": true}\n')
    final_path = bundle.finalise(status="complete")

    synced_names = {Path(path).name for path in synced}
    assert {
        "packets.csv",
        "events.jsonl",
        "lab-status.json",
        "manifest.json",
        "SHA256SUMS",
        "raw",
        final_path.name,
    } <= synced_names


def test_validation_rejects_missing_core_and_absent_checksum_entries(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    (final_path / "events.jsonl").unlink()
    sums_path = final_path / "SHA256SUMS"
    sums_path.write_text(
        sums_path.read_text(encoding="ascii") + f"{'0' * 64}  absent.txt\n",
        encoding="ascii",
    )

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert any("core artifacts" in error for error in result.errors)
    assert any("absent files" in error for error in result.errors)


def test_validation_rejects_symlink_and_non_regular_entries(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    target = tmp_path / "external.txt"
    target.write_text("external\n", encoding="utf-8")
    symlink_created = True
    try:
        os.symlink(target, final_path / "linked.txt")
    except OSError as error:
        if os.name != "nt" or getattr(error, "winerror", None) != 1314:
            raise
        symlink_created = False
    (final_path / "nested").mkdir()

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    if symlink_created:
        assert any("linked.txt is not a regular file" in error for error in result.errors)
    assert any("nested is not a regular file" in error for error in result.errors)


@pytest.mark.parametrize(
    ("artifact", "repeated_invalid_line"),
    [
        ("events.jsonl", b"\n"),
        ("packets.csv", b"bad,bad,bad,bad,bad,bad,bad\n"),
        ("trace.jsonl", b"\n"),
    ],
)
def test_validation_bounds_repeated_line_diagnostics(
    tmp_path, artifact, repeated_invalid_line
):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    if artifact == "trace.jsonl":
        bundle.write_text_artifact("trace.jsonl", '{"event":"measured"}\n')
    final_path = bundle.finalise(status="complete")
    target = final_path / artifact
    if artifact == "packets.csv":
        target.write_bytes(
            (",".join(PACKET_FIELDS) + "\n").encode("ascii")
            + repeated_invalid_line * 10_000
        )
    else:
        target.write_bytes(repeated_invalid_line * 10_000)
    refresh_manifest_evidence_and_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert len(result.errors) == 100
    assert result.errors[-1] == (
        "validation diagnostic limit reached; additional errors omitted"
    )


def test_validation_bounds_unlisted_filename_diagnostic_length(tmp_path):
    bundle_path = tmp_path / "many-unlisted-files"
    bundle_path.mkdir()
    (bundle_path / "SHA256SUMS").write_text(
        f"{'0' * 64}  absent.txt\n",
        encoding="ascii",
    )
    for index in range(512):
        (bundle_path / f"extra-{index:04d}.txt").write_text("x", encoding="ascii")

    result = validate_evidence_bundle(bundle_path)

    assert result.valid is False
    assert max(map(len, result.errors)) <= 1_024
    assert any("additional names omitted" in error for error in result.errors)


def test_validation_bounds_manifest_digest_name_diagnostic_length(tmp_path):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    final_path = bundle.finalise(status="complete")
    manifest_path = final_path / "manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved["evidence_sha256"].update(
        {f"absent-{index:04d}.txt": "0" * 64 for index in range(512)}
    )
    manifest_path.write_text(
        json.dumps(saved, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    rewrite_sha256sums(final_path)

    result = validate_evidence_bundle(final_path)

    assert result.valid is False
    assert max(map(len, result.errors)) <= 1_024
    assert any("additional names omitted" in error for error in result.errors)


def test_publication_bounds_combined_validation_exception(tmp_path, monkeypatch):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    diagnostics = tuple("x" * 1_024 for _ in range(100))
    monkeypatch.setattr(
        collector_module,
        "validate_evidence_bundle",
        lambda path: BundleValidation(False, diagnostics, ()),
    )

    with pytest.raises(ValueError) as caught:
        bundle.finalise(status="complete")

    assert len(str(caught.value)) <= 1_024


def test_validation_rejects_bundle_inventory_over_entry_limit(
    tmp_path, monkeypatch
):
    bundle_path = tmp_path / "oversized-inventory"
    bundle_path.mkdir()
    (bundle_path / "SHA256SUMS").write_text("", encoding="ascii")
    (bundle_path / "extra-a.txt").write_text("a", encoding="ascii")
    (bundle_path / "extra-b.txt").write_text("b", encoding="ascii")
    monkeypatch.setattr(
        collector_module,
        "MAX_BUNDLE_ENTRIES",
        2,
        raising=False,
    )

    result = validate_evidence_bundle(bundle_path)

    assert result.valid is False
    assert any("more than 2 entries" in error for error in result.errors)


def test_quarantine_bounds_inventory_scan_and_records_omission(
    tmp_path, monkeypatch
):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    for index in range(8):
        (bundle.staging_path / f"extra-{index}.txt").write_text(
            "x",
            encoding="ascii",
        )
    synced_files = []
    monkeypatch.setattr(collector_module, "MAX_BUNDLE_ENTRIES", 4)
    monkeypatch.setattr(
        bundle,
        "_seal_streams",
        lambda: (_ for _ in ()).throw(ValueError("primary failure")),
    )
    monkeypatch.setattr(
        collector_module,
        "_fsync_file",
        lambda path: synced_files.append(path),
    )

    with pytest.raises(ValueError) as caught:
        bundle.finalise(status="complete")

    assert len(synced_files) <= 4
    assert any("omitted" in note for note in caught.value.__notes__)


def test_quarantine_bounds_secondary_exception_notes(tmp_path, monkeypatch):
    bundle = EvidenceBundle.create(tmp_path, manifest())
    write_minimum_complete_evidence(bundle)
    for index in range(150):
        (bundle.staging_path / f"extra-{index:03d}.txt").write_text(
            "x",
            encoding="ascii",
        )
    monkeypatch.setattr(
        bundle,
        "_seal_streams",
        lambda: (_ for _ in ()).throw(ValueError("primary failure")),
    )
    monkeypatch.setattr(
        collector_module,
        "_fsync_file",
        lambda path: (_ for _ in ()).throw(OSError("x" * 5_000)),
    )

    with pytest.raises(ValueError) as caught:
        bundle.finalise(status="complete")

    notes = caught.value.__notes__
    assert len(notes) <= 100
    assert max(map(len, notes)) <= 1_024
    assert notes[-1] == (
        "validation diagnostic limit reached; additional errors omitted"
    )
