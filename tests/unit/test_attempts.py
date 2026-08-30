from __future__ import annotations

import hashlib
import json
import stat
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import adaptive_vpn.attempts as attempts_module
from adaptive_vpn.attempts import (
    AttemptAllocation,
    AttemptInventoryError,
    AttemptStateError,
    allocate_next_attempt,
    attempt_udp_token,
    build_registered_attempt_scope,
    inventory_attempts,
)
from adaptive_vpn.schedule import load_registered_schedule
from tests.unit.test_schedule import _registered_plan

COMMIT = "a" * 40


def test_windows_reparse_directory_is_not_an_attempt_inventory_root():
    observed = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o700,
        st_file_attributes=attempts_module._FILE_ATTRIBUTE_REPARSE_POINT,
    )

    assert attempts_module._is_real_directory(observed) is False


def _scope(tmp_path: Path, *, blocks: int = 1, commit: str = COMMIT):
    plan = _registered_plan(tmp_path, blocks=blocks)
    schedule = load_registered_schedule(plan)
    return build_registered_attempt_scope(
        plan,
        schedule,
        collection_commit=commit,
    )


def _manifest(
    scope,
    cell,
    *,
    attempt_id: uuid.UUID,
    attempt_number: int,
    supersedes: uuid.UUID | None,
    status: str = "incomplete",
    **overrides,
):
    value = {
        "schema_version": "1.2.0",
        "cell_id": str(cell.cell_id),
        "attempt_id": str(attempt_id),
        "attempt_number": attempt_number,
        "supersedes_attempt_id": str(supersedes) if supersedes else None,
        "campaign_stage": scope.campaign_stage,
        "schedule_sha256": scope.schedule_sha256,
        "dataset_id": scope.dataset_id,
        "strategy": cell.strategy,
        "scenario": cell.scenario_id,
        "traffic_profile": cell.traffic_profile_id,
        "block": cell.block,
        "schedule_seed": scope.schedule_seed,
        "ordinal": cell.ordinal,
        "config_sha256": scope.config_sha256,
        "experimental_unit": "run",
        "provenance": {"git_commit": scope.collection_commit},
        "status": status,
        "failure_reason": "injected apparatus failure"
        if status == "incomplete"
        else None,
        "finalised_at_utc": "2026-08-04T00:00:00.000000Z",
        "evidence_sha256": {
            "events.jsonl": "b" * 64,
            "packets.csv": "c" * 64,
        },
    }
    value.update(overrides)
    return value


def _install_validator(monkeypatch, manifests, *, invalid=()):
    invalid_names = set(invalid)

    def validate(path: Path):
        if path.name in invalid_names:
            return SimpleNamespace(
                valid=False,
                errors=("injected invalid bundle",),
                checked_files=(),
                manifest=None,
                sha256sums_sha256=None,
            )
        manifest = manifests[path.name]
        return SimpleNamespace(
            valid=True,
            errors=(),
            checked_files=("events.jsonl", "manifest.json", "packets.csv"),
            manifest=manifest,
            sha256sums_sha256=hashlib.sha256(path.name.encode()).hexdigest(),
        )

    monkeypatch.setattr(attempts_module, "validate_evidence_bundle", validate)


def _write_attempt_directory(raw_root: Path, manifest) -> Path:
    path = raw_root / manifest["attempt_id"]
    path.mkdir(parents=True)
    return path


def _write_real_attempt_bundle(raw_root: Path, manifest) -> Path:
    path = raw_root / manifest["attempt_id"]
    path.mkdir(parents=True)
    packets = (
        b"sequence,path_id,sent_ns,received_ns,status,rtt_ms,datagram_bytes\n"
    )
    events = b""
    (path / "packets.csv").write_bytes(packets)
    (path / "events.jsonl").write_bytes(events)
    saved = dict(manifest)
    saved["evidence_sha256"] = {
        "packets.csv": hashlib.sha256(packets).hexdigest(),
        "events.jsonl": hashlib.sha256(events).hexdigest(),
    }
    manifest_bytes = (
        json.dumps(saved, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    (path / "manifest.json").write_bytes(manifest_bytes)
    hashes = {
        name: hashlib.sha256((path / name).read_bytes()).hexdigest()
        for name in ("events.jsonl", "manifest.json", "packets.csv")
    }
    sums_bytes = "".join(
        f"{digest}  {name}\n" for name, digest in sorted(hashes.items())
    ).encode("ascii")
    (path / "SHA256SUMS").write_bytes(sums_bytes)
    return path


def _inventory(tmp_path: Path, monkeypatch, scope, manifests):
    raw_root = tmp_path / "raw"
    raw_root.mkdir(parents=True, exist_ok=True)
    indexed = {}
    for manifest in manifests:
        path = _write_attempt_directory(raw_root, manifest)
        indexed[path.name] = manifest
    _install_validator(monkeypatch, indexed)
    return inventory_attempts(raw_root, scope)


def test_scope_requires_exact_registered_schedule_and_is_read_only(tmp_path: Path):
    plan = _registered_plan(tmp_path, blocks=1)
    schedule = load_registered_schedule(plan)
    scope = build_registered_attempt_scope(
        plan,
        schedule,
        collection_commit=COMMIT,
    )

    assert len(scope.cells) == plan.expected_runs
    assert scope.schedule_sha256 == plan.schedule_sha256
    assert scope.max_attempts_per_cell == plan.max_attempts_per_cell
    with pytest.raises(TypeError):
        scope.cells[next(iter(scope.cells))] = next(iter(scope.cells.values()))

    with pytest.raises(AttemptStateError, match="deterministic schedule"):
        build_registered_attempt_scope(
            plan,
            [*schedule[:-1], schedule[0]],
            collection_commit=COMMIT,
        )


@pytest.mark.parametrize("commit", ("", "A" * 40, "a" * 39, "g" * 40))
def test_scope_rejects_noncanonical_collection_commit(tmp_path: Path, commit: str):
    plan = _registered_plan(tmp_path, blocks=1)

    with pytest.raises(AttemptStateError, match="collection_commit"):
        build_registered_attempt_scope(
            plan,
            load_registered_schedule(plan),
            collection_commit=commit,
        )


def test_empty_inventory_allocates_attempt_one_without_predecessor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scope = _scope(tmp_path)
    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    _install_validator(monkeypatch, {})
    inventory = inventory_attempts(raw_root, scope)
    cell_id = next(iter(scope.cells))
    expected = uuid.uuid4()
    calls = 0

    def factory():
        nonlocal calls
        calls += 1
        return expected

    allocation = allocate_next_attempt(
        inventory,
        scope,
        cell_id,
        attempt_id_factory=factory,
    )

    assert calls == 1
    assert allocation.attempt_id == expected
    assert allocation.attempt_number == 1
    assert allocation.supersedes_attempt_id is None


@pytest.mark.parametrize(
    "changes",
    (
        {"cell_id": uuid.uuid4()},
        {"attempt_id": uuid.uuid5(uuid.NAMESPACE_DNS, "attempt")},
        {"attempt_number": True},
        {"attempt_number": 0},
        {"attempt_number": 1, "supersedes_attempt_id": uuid.uuid4()},
        {"attempt_number": 2, "supersedes_attempt_id": None},
    ),
)
def test_attempt_allocation_rejects_invalid_identity_or_chain_state(changes):
    values = {
        "cell_id": uuid.uuid5(uuid.NAMESPACE_DNS, "cell"),
        "attempt_id": uuid.uuid4(),
        "attempt_number": 1,
        "supersedes_attempt_id": None,
        "scope_fingerprint": "a" * 64,
    }
    values.update(changes)

    with pytest.raises(AttemptStateError):
        AttemptAllocation(**values)


def test_inventory_consumes_real_validator_snapshot_without_manifest_reread(
    tmp_path: Path,
):
    scope = _scope(tmp_path)
    cell = next(iter(scope.cells.values()))
    attempt_id = uuid.uuid4()
    raw_root = tmp_path / "real-raw"
    manifest = _manifest(
        scope,
        cell,
        attempt_id=attempt_id,
        attempt_number=1,
        supersedes=None,
    )
    bundle_path = _write_real_attempt_bundle(raw_root, manifest)
    expected_sums_digest = hashlib.sha256(
        (bundle_path / "SHA256SUMS").read_bytes()
    ).hexdigest()

    inventory = inventory_attempts(raw_root, scope)

    record = inventory.by_cell_id[cell.cell_id][0]
    assert record.attempt_id == attempt_id
    assert record.manifest["attempt_id"] == str(attempt_id)
    assert record.sha256sums_sha256 == expected_sums_digest
    with pytest.raises(TypeError):
        record.manifest["dataset_id"] = "mutated"


def test_incomplete_chain_allocates_contiguous_successor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scope = _scope(tmp_path)
    cell = next(iter(scope.cells.values()))
    first = uuid.uuid4()
    manifest = _manifest(
        scope,
        cell,
        attempt_id=first,
        attempt_number=1,
        supersedes=None,
    )
    inventory = _inventory(tmp_path, monkeypatch, scope, [manifest])
    successor = uuid.uuid4()

    allocation = allocate_next_attempt(
        inventory,
        scope,
        cell.cell_id,
        attempt_id_factory=lambda: successor,
    )

    assert allocation.attempt_number == 2
    assert allocation.attempt_id == successor
    assert allocation.supersedes_attempt_id == first


def test_inventory_sorts_random_directory_order_and_freezes_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scope = _scope(tmp_path)
    cell = next(iter(scope.cells.values()))
    first = uuid.UUID("ffffffff-ffff-4fff-8fff-ffffffffffff")
    second = uuid.UUID("00000000-0000-4000-8000-000000000001")
    inventory = _inventory(
        tmp_path,
        monkeypatch,
        scope,
        [
            _manifest(
                scope,
                cell,
                attempt_id=first,
                attempt_number=1,
                supersedes=None,
            ),
            _manifest(
                scope,
                cell,
                attempt_id=second,
                attempt_number=2,
                supersedes=first,
            ),
        ],
    )

    records = inventory.by_cell_id[cell.cell_id]
    assert [record.attempt_number for record in records] == [1, 2]
    with pytest.raises(TypeError):
        records[0].manifest["dataset_id"] = "mutated"
    with pytest.raises(TypeError):
        records[0].manifest["provenance"]["git_commit"] = "b" * 40


@pytest.mark.parametrize(
    ("numbers", "predecessor_mode", "match"),
    (
        ((0,), "normal", "attempt_number"),
        ((1, 1), "normal", "duplicate"),
        ((1, 3), "normal", "contiguous"),
        ((1,), "first-nonnull", "first attempt"),
        ((1, 2), "later-null", "predecessor"),
        ((1, 2), "wrong", "predecessor"),
    ),
)
def test_inventory_rejects_invalid_attempt_number_or_predecessor_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    numbers,
    predecessor_mode: str,
    match: str,
):
    scope = _scope(tmp_path)
    cell = next(iter(scope.cells.values()))
    identifiers = [uuid.uuid4() for _ in numbers]
    manifests = []
    for index, (number, attempt_id) in enumerate(zip(numbers, identifiers)):
        predecessor = identifiers[index - 1] if index else None
        if predecessor_mode == "first-nonnull" and index == 0:
            predecessor = uuid.uuid4()
        elif predecessor_mode == "later-null" and index > 0:
            predecessor = None
        elif predecessor_mode == "wrong" and index > 0:
            predecessor = uuid.uuid4()
        manifests.append(
            _manifest(
                scope,
                cell,
                attempt_id=attempt_id,
                attempt_number=number,
                supersedes=predecessor,
            )
        )

    with pytest.raises(AttemptInventoryError, match=match):
        _inventory(tmp_path, monkeypatch, scope, manifests)


@pytest.mark.parametrize(
    "statuses",
    (
        ("complete", "incomplete"),
        ("complete", "complete"),
        ("incomplete", "complete", "incomplete"),
    ),
)
def test_inventory_rejects_attempts_after_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, statuses
):
    scope = _scope(tmp_path)
    scope = replace(scope, max_attempts_per_cell=4)
    cell = next(iter(scope.cells.values()))
    identifiers = [uuid.uuid4() for _ in statuses]
    manifests = [
        _manifest(
            scope,
            cell,
            attempt_id=attempt_id,
            attempt_number=index + 1,
            supersedes=identifiers[index - 1] if index else None,
            status=status,
        )
        for index, (attempt_id, status) in enumerate(zip(identifiers, statuses))
    ]

    with pytest.raises(AttemptInventoryError, match="complete"):
        _inventory(tmp_path, monkeypatch, scope, manifests)


def test_allocation_rejects_complete_and_exhausted_cells(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scope = _scope(tmp_path)
    cell = next(iter(scope.cells.values()))
    complete = _manifest(
        scope,
        cell,
        attempt_id=uuid.uuid4(),
        attempt_number=1,
        supersedes=None,
        status="complete",
    )
    inventory = _inventory(tmp_path, monkeypatch, scope, [complete])
    with pytest.raises(AttemptStateError, match="complete"):
        allocate_next_attempt(inventory, scope, cell.cell_id)

    first = uuid.uuid4()
    second = uuid.uuid4()
    exhausted = _inventory(
        tmp_path / "exhausted",
        monkeypatch,
        scope,
        [
            _manifest(
                scope,
                cell,
                attempt_id=first,
                attempt_number=1,
                supersedes=None,
            ),
            _manifest(
                scope,
                cell,
                attempt_id=second,
                attempt_number=2,
                supersedes=first,
            ),
        ],
    )
    with pytest.raises(AttemptStateError, match="exhausted"):
        allocate_next_attempt(exhausted, scope, cell.cell_id)


def test_inventory_rejects_chain_beyond_registered_attempt_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scope = _scope(tmp_path)
    cell = next(iter(scope.cells.values()))
    identifiers = [uuid.uuid4() for _ in range(scope.max_attempts_per_cell + 1)]
    manifests = [
        _manifest(
            scope,
            cell,
            attempt_id=attempt_id,
            attempt_number=index + 1,
            supersedes=identifiers[index - 1] if index else None,
        )
        for index, attempt_id in enumerate(identifiers)
    ]

    with pytest.raises(AttemptInventoryError, match="max_attempts_per_cell"):
        _inventory(tmp_path, monkeypatch, scope, manifests)


@pytest.mark.parametrize("bad_factory", (lambda: uuid.uuid1(), lambda: uuid.uuid5(uuid.NAMESPACE_DNS, "x"), lambda: "not-a-uuid"))
def test_allocation_calls_factory_once_and_rejects_invalid_uuid4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_factory
):
    scope = _scope(tmp_path)
    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    _install_validator(monkeypatch, {})
    inventory = inventory_attempts(raw_root, scope)
    cell_id = next(iter(scope.cells))
    calls = 0

    def factory():
        nonlocal calls
        calls += 1
        return bad_factory()

    with pytest.raises(AttemptStateError, match="UUIDv4"):
        allocate_next_attempt(
            inventory,
            scope,
            cell_id,
            attempt_id_factory=factory,
        )
    assert calls == 1


def test_allocation_rejects_global_attempt_id_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scope = _scope(tmp_path)
    cell = next(iter(scope.cells.values()))
    existing = uuid.uuid4()
    manifest = _manifest(
        scope,
        cell,
        attempt_id=existing,
        attempt_number=1,
        supersedes=None,
    )
    inventory = _inventory(tmp_path, monkeypatch, scope, [manifest])

    with pytest.raises(AttemptStateError, match="collision"):
        allocate_next_attempt(
            inventory,
            scope,
            cell.cell_id,
            attempt_id_factory=lambda: existing,
        )


def test_allocation_rejects_inventory_from_another_scope_before_uuid_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scope_a = _scope(tmp_path)
    cell = next(iter(scope_a.cells.values()))
    first = uuid.uuid4()
    inventory = _inventory(
        tmp_path,
        monkeypatch,
        scope_a,
        [
            _manifest(
                scope_a,
                cell,
                attempt_id=first,
                attempt_number=1,
                supersedes=None,
            )
        ],
    )
    scope_b = replace(scope_a, collection_commit="b" * 40)
    calls = 0

    def factory():
        nonlocal calls
        calls += 1
        return uuid.uuid4()

    with pytest.raises(AttemptStateError, match="scope"):
        allocate_next_attempt(
            inventory,
            scope_b,
            cell.cell_id,
            attempt_id_factory=factory,
        )

    assert calls == 0


def test_allocation_rejects_fabricated_inventory_with_matching_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scope = _scope(tmp_path)
    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    _install_validator(monkeypatch, {})
    inventory = inventory_attempts(raw_root, scope)
    fabricated = replace(inventory, _allocation_token=object())

    with pytest.raises(AttemptStateError, match="not built"):
        allocate_next_attempt(
            fabricated,
            scope,
            next(iter(scope.cells)),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("campaign_stage", "pilot"),
        ("schedule_sha256", "f" * 64),
        ("config_sha256", "e" * 64),
        ("schedule_seed", 1),
        ("ordinal", 999),
        ("block", 999),
        ("scenario", "wrong"),
        ("traffic_profile", "wrong"),
        ("strategy", "wrong"),
        ("provenance", {"git_commit": "b" * 40}),
    ),
)
def test_inventory_rejects_target_scope_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value,
):
    scope = _scope(tmp_path)
    cell = next(iter(scope.cells.values()))
    manifest = _manifest(
        scope,
        cell,
        attempt_id=uuid.uuid4(),
        attempt_number=1,
        supersedes=None,
        **{field: value},
    )

    with pytest.raises(AttemptInventoryError, match="identity"):
        _inventory(tmp_path, monkeypatch, scope, [manifest])


def test_inventory_rejects_unknown_cell_and_invalid_prior_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scope = _scope(tmp_path)
    cell = next(iter(scope.cells.values()))
    manifest = _manifest(
        scope,
        cell,
        attempt_id=uuid.uuid4(),
        attempt_number=1,
        supersedes=None,
        cell_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, "unknown-cell")),
    )
    raw_root = tmp_path / "raw"
    path = _write_attempt_directory(raw_root, manifest)
    _install_validator(monkeypatch, {path.name: manifest})
    with pytest.raises(AttemptInventoryError, match="unknown cell"):
        inventory_attempts(raw_root, scope)

    _install_validator(monkeypatch, {path.name: manifest}, invalid={path.name})
    with pytest.raises(AttemptInventoryError, match="validation"):
        inventory_attempts(raw_root, scope)


def test_foreign_v12_reserves_id_and_cross_dataset_links_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scope = _scope(tmp_path)
    cell = next(iter(scope.cells.values()))
    foreign_id = uuid.uuid4()
    foreign = _manifest(
        scope,
        cell,
        attempt_id=foreign_id,
        attempt_number=1,
        supersedes=None,
        dataset_id="foreign-dataset",
    )
    target_id = uuid.uuid4()
    target = _manifest(
        scope,
        cell,
        attempt_id=target_id,
        attempt_number=2,
        supersedes=foreign_id,
    )

    with pytest.raises(AttemptInventoryError, match="cross-scope predecessor"):
        _inventory(tmp_path, monkeypatch, scope, [foreign, target])

    inventory = _inventory(
        tmp_path / "foreign-only",
        monkeypatch,
        scope,
        [foreign],
    )
    assert not inventory.all_current_attempts
    with pytest.raises(AttemptStateError, match="collision"):
        allocate_next_attempt(
            inventory,
            scope,
            cell.cell_id,
            attempt_id_factory=lambda: foreign_id,
        )


def test_legacy_bundles_are_generic_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scope = _scope(tmp_path)
    raw_root = tmp_path / "raw"
    legacy = raw_root / str(uuid.uuid4())
    legacy.mkdir(parents=True)
    _install_validator(
        monkeypatch,
        {legacy.name: {"schema_version": "1.1.0", "run_id": legacy.name}},
    )

    inventory = inventory_attempts(raw_root, scope)

    assert not inventory.all_current_attempts
    assert not inventory.by_attempt_id


def test_inventory_bounds_root_and_rejects_alias_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scope = _scope(tmp_path)
    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    (raw_root / "not-a-directory").write_text("x", encoding="utf-8")
    _install_validator(monkeypatch, {})
    with pytest.raises(AttemptInventoryError, match="directory"):
        inventory_attempts(raw_root, scope)

    (raw_root / "not-a-directory").unlink()
    monkeypatch.setattr(attempts_module, "MAX_DATASET_BUNDLES", 2)
    for name in ("one", "two", "three"):
        (raw_root / name).mkdir()
    with pytest.raises(AttemptInventoryError, match="more than 2"):
        inventory_attempts(raw_root, scope)


def test_inventory_rejects_symlink_bundle_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scope = _scope(tmp_path)
    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    target = tmp_path / "outside-bundle"
    target.mkdir()
    alias = raw_root / "alias"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("symbolic links are unavailable")
    _install_validator(monkeypatch, {})

    with pytest.raises(AttemptInventoryError, match="non-symlink directory"):
        inventory_attempts(raw_root, scope)


def test_attempt_udp_token_is_domain_separated_and_uses_all_uuid_bits():
    low = 0x1234567890ABCDEF
    first = uuid.UUID(int=(1 << 64) | low, version=4)
    second = uuid.UUID(int=(2 << 64) | low, version=4)

    first_token = attempt_udp_token(first)
    second_token = attempt_udp_token(second)

    expected = int.from_bytes(
        hashlib.sha256(b"adaptive-vpn-udp-attempt-v1\0" + first.bytes).digest()[:8],
        "big",
    )
    assert first_token == expected
    assert first_token != second_token
    assert 0 <= first_token < 2**64
