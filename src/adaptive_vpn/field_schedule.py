"""Deterministic population registry for the gated dual-stack field study."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any
from uuid import UUID, uuid5

import yaml

FIELD_NAMESPACE = UUID("ca7b5de8-3ef4-4d72-91a7-dcb322726d10")
MAX_FIELD_DESIGN_BYTES = 1_048_576
_NODE_ID_RE = re.compile(r"^[a-z][a-z0-9-]*$")


class FieldDesignError(ValueError):
    """Raised when the field population cannot be authenticated or expanded."""


@dataclass(frozen=True, slots=True)
class FieldCell:
    cell_id: str
    ordinal: int
    stage: str
    block: int
    outer_family: str
    scenario_id: str
    carrier_id: str
    relationship_id: str | None = None
    client_ids: tuple[str, ...] = ()
    server_id: str | None = None
    candidate_server_ids: tuple[str, ...] = ()
    strategy: str | None = None
    media_profile: str | None = None
    protocol_mode: str | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            "cell_id": self.cell_id,
            "ordinal": self.ordinal,
            "stage": self.stage,
            "block": self.block,
            "outer_family": self.outer_family,
            "scenario_id": self.scenario_id,
            "carrier_id": self.carrier_id,
            "relationship_id": self.relationship_id,
            "client_ids": list(self.client_ids),
            "server_id": self.server_id,
            "candidate_server_ids": list(self.candidate_server_ids),
            "strategy": self.strategy,
            "media_profile": self.media_profile,
            "protocol_mode": self.protocol_mode,
        }


@dataclass(frozen=True, slots=True)
class FieldPopulation:
    protocol_version: str
    dataset_id: str
    schedule_seed: int
    design_sha256: str
    cells: tuple[FieldCell, ...]

    def document(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "protocol_version": self.protocol_version,
            "dataset_id": self.dataset_id,
            "design": "registered-population-not-execution-order",
            "execution_gate": "gate1-trusted-host-fingerprints",
            "execution_order_frozen": False,
            "schedule_seed": self.schedule_seed,
            "design_sha256": self.design_sha256,
            "expected_units": len(self.cells),
            "cells": [cell.as_json() for cell in self.cells],
        }

    def canonical_bytes(self) -> bytes:
        return (
            json.dumps(
                self.document(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class _Relationship:
    relationship_id: str
    left: str
    right: str
    mainland_client: str | None


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def load_field_design(path: str | Path) -> dict[str, Any]:
    """Load one bounded regular YAML design and validate its population headers."""

    source = Path(os.path.abspath(path))
    try:
        observed = os.lstat(source)
    except OSError as exc:
        raise FieldDesignError(f"cannot inspect field design: {exc}") from exc
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
        raise FieldDesignError("field design must be a regular non-symlink file")
    if observed.st_size > MAX_FIELD_DESIGN_BYTES:
        raise FieldDesignError(
            f"field design exceeds {MAX_FIELD_DESIGN_BYTES} bytes"
        )
    try:
        raw = source.read_bytes()
        document = yaml.safe_load(raw.decode("utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise FieldDesignError(f"cannot load field design: {exc}") from exc
    if not isinstance(document, dict):
        raise FieldDesignError("field design must contain an object")
    _validate_design_headers(document)
    return document


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FieldDesignError(f"{label} must be an object")
    return value


def _sequence(value: object, label: str) -> Sequence[Any]:
    if not isinstance(value, (list, tuple)) or not value:
        raise FieldDesignError(f"{label} must be a non-empty list")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise FieldDesignError(f"{label} must be a positive integer")
    return value


def _text_levels(value: object, label: str) -> tuple[str, ...]:
    levels = tuple(_sequence(value, label))
    if any(
        not isinstance(item, str) or not item or _NODE_ID_RE.fullmatch(item) is None
        for item in levels
    ):
        raise FieldDesignError(f"{label} contains an invalid identifier")
    if len(levels) != len(set(levels)):
        raise FieldDesignError(f"{label} contains a duplicate identifier")
    return levels


def _node_ids(nodes: object, *, label: str, required_roles: tuple[str, ...]) -> tuple[str, ...]:
    values = _sequence(nodes, label)
    identifiers: list[str] = []
    for index, raw_node in enumerate(values, 1):
        node = _mapping(raw_node, f"{label}[{index}]")
        node_id = node.get("node_id")
        roles = node.get("roles")
        if not isinstance(node_id, str) or _NODE_ID_RE.fullmatch(node_id) is None:
            raise FieldDesignError(f"{label}[{index}] has an invalid node_id")
        observed_roles = tuple(roles) if isinstance(roles, list) else ()
        if observed_roles != required_roles:
            raise FieldDesignError(f"{label}[{index}] has invalid roles")
        identifiers.append(node_id)
    if len(identifiers) != len(set(identifiers)):
        raise FieldDesignError(f"{label} contains duplicate node IDs")
    return tuple(identifiers)


def _carrier_ids(plan: Mapping[str, Any]) -> tuple[str, ...]:
    carriers = _mapping(plan.get("encrypted_carriers"), "encrypted_carriers")
    registered = _text_levels(
        carriers.get("registered_levels"), "encrypted_carriers.registered_levels"
    )
    primary = _mapping(carriers.get("primary"), "encrypted_carriers.primary")
    secondary = _mapping(carriers.get("secondary"), "encrypted_carriers.secondary")
    defined = (primary.get("carrier_id"), secondary.get("carrier_id"))
    if registered != defined:
        raise FieldDesignError(
            "registered carrier levels must match the primary and secondary carriers"
        )
    if registered != ("wireguard-udp", "wireguard-over-wss"):
        raise FieldDesignError("field design has unsupported registered carriers")
    if carriers.get("population_rule") != "crossed-with-every-stage-cell":
        raise FieldDesignError("field design carrier population rule is unsupported")
    if secondary.get("substitution_for_primary_cell") != "forbidden":
        raise FieldDesignError("compatibility carrier substitution must be forbidden")
    return registered


def _require_carrier_factor(
    factors: Mapping[str, Any], *, label: str, carrier_count: int
) -> None:
    observed = _positive_int(factors.get("carriers"), f"{label}.carriers")
    if observed != carrier_count:
        raise FieldDesignError(
            f"{label} carrier factor must equal registered carrier count"
        )


def _validate_design_headers(plan: Mapping[str, Any]) -> None:
    if plan.get("schema_version") != "2.0.0":
        raise FieldDesignError("field design schema_version must be 2.0.0")
    if plan.get("protocol_version") != "field-2.0-plan":
        raise FieldDesignError("field design protocol_version is unsupported")
    dataset_id = plan.get("dataset_id")
    if not isinstance(dataset_id, str) or _NODE_ID_RE.fullmatch(dataset_id) is None:
        raise FieldDesignError("field design dataset_id is invalid")
    inventory = _mapping(plan.get("inventory"), "inventory")
    cloud = _node_ids(
        inventory.get("server_nodes"),
        label="inventory.server_nodes",
        required_roles=("client", "server"),
    )
    mainland = _node_ids(
        inventory.get("mainland_client_nodes"),
        label="inventory.mainland_client_nodes",
        required_roles=("client",),
    )
    if len(cloud) != 6 or len(mainland) != 4 or set(cloud) & set(mainland):
        raise FieldDesignError("field design requires six cloud and four mainland nodes")
    families = _text_levels(
        _mapping(plan.get("network_families"), "network_families").get("levels"),
        "network_families.levels",
    )
    if set(families) != {"native-outer-ipv4", "native-outer-ipv6"}:
        raise FieldDesignError("field design must register native IPv4 and IPv6")
    scenarios = _text_levels(
        _mapping(plan.get("access_scenarios"), "access_scenarios").get("levels"),
        "access_scenarios.levels",
    )
    if len(scenarios) != 7:
        raise FieldDesignError("field design must register seven access scenarios")
    carrier_count = len(_carrier_ids(plan))
    stage_a = _mapping(plan.get("stage_a_full_mesh_characterisation"), "stage_a")
    _require_carrier_factor(
        _mapping(stage_a.get("factors"), "stage_a.factors"),
        label="stage_a.factors",
        carrier_count=carrier_count,
    )
    stage_b = _mapping(plan.get("stage_b_adaptive_replica_selection"), "stage_b")
    _require_carrier_factor(
        _mapping(stage_b.get("factors"), "stage_b.factors"),
        label="stage_b.factors",
        carrier_count=carrier_count,
    )
    stage_c = _mapping(plan.get("stage_c_real_meeting_protocols"), "stage_c")
    _require_carrier_factor(
        _mapping(stage_c.get("pairwise"), "stage_c.pairwise"),
        label="stage_c.pairwise",
        carrier_count=carrier_count,
    )
    _require_carrier_factor(
        _mapping(stage_c.get("multiparty_sfu"), "stage_c.multiparty_sfu"),
        label="stage_c.multiparty_sfu",
        carrier_count=carrier_count,
    )
    seed = _mapping(plan.get("randomisation"), "randomisation").get("schedule_seed")
    _positive_int(seed, "randomisation.schedule_seed")
    totals = _mapping(plan.get("matrix_totals"), "matrix_totals")
    per_carrier_units = 15_348 // carrier_count
    if any(
        _positive_int(totals.get(label), f"matrix_totals.{label}")
        != per_carrier_units
        for label in ("primary_carrier_units", "compatibility_carrier_units")
    ):
        raise FieldDesignError(
            "each registered carrier population must contain 7674 units"
        )
    if (
        _positive_int(totals.get("total_scheduled_units"), "total_scheduled_units")
        != 15_348
    ):
        raise FieldDesignError("field design total_scheduled_units must be 15348")


def _relationships(cloud: tuple[str, ...], mainland: tuple[str, ...]) -> tuple[_Relationship, ...]:
    values: list[_Relationship] = []
    for left, right in combinations(cloud, 2):
        values.append(_Relationship(f"rel-{left}--{right}", left, right, None))
    for client in mainland:
        for server in cloud:
            values.append(
                _Relationship(
                    f"rel-{client}--{server}", client, server, client
                )
            )
    if len(values) != 39:
        raise FieldDesignError("field relationship population is not 39")
    return tuple(values)


def _oriented_pair(
    relationship: _Relationship, *, block: int, relationship_index: int
) -> tuple[str, str]:
    if relationship.mainland_client is not None:
        return relationship.mainland_client, relationship.right
    if (block + relationship_index) % 2:
        return relationship.left, relationship.right
    return relationship.right, relationship.left


def generate_field_population(plan: Mapping[str, Any]) -> FieldPopulation:
    """Expand all 15,348 registered units without authorising execution order."""

    _validate_design_headers(plan)
    inventory = _mapping(plan["inventory"], "inventory")
    cloud = _node_ids(
        inventory["server_nodes"],
        label="inventory.server_nodes",
        required_roles=("client", "server"),
    )
    mainland = _node_ids(
        inventory["mainland_client_nodes"],
        label="inventory.mainland_client_nodes",
        required_roles=("client",),
    )
    families = _text_levels(plan["network_families"]["levels"], "families")
    scenarios = _text_levels(plan["access_scenarios"]["levels"], "scenarios")
    carrier_ids = _carrier_ids(plan)
    relationships = _relationships(cloud, mainland)
    dataset_id = str(plan["dataset_id"])
    protocol_version = str(plan["protocol_version"])
    schedule_seed = _positive_int(
        plan["randomisation"]["schedule_seed"], "schedule_seed"
    )
    design_sha256 = _canonical_sha256(plan)
    cells: list[FieldCell] = []

    def add(**values: Any) -> None:
        identity = {
            "protocol_version": protocol_version,
            "dataset_id": dataset_id,
            **values,
        }
        cell_id = str(
            uuid5(
                FIELD_NAMESPACE,
                json.dumps(
                    identity,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ),
            )
        )
        cells.append(FieldCell(cell_id=cell_id, ordinal=len(cells) + 1, **values))

    stage_a = _mapping(
        plan["stage_a_full_mesh_characterisation"], "stage_a"
    )
    stage_a_blocks = _positive_int(stage_a["factors"]["temporal_blocks"], "stage_a blocks")
    for block in range(1, stage_a_blocks + 1):
        for relationship_index, relationship in enumerate(relationships):
            client, server = _oriented_pair(
                relationship,
                block=block,
                relationship_index=relationship_index,
            )
            for family in families:
                for carrier_id in carrier_ids:
                    for scenario in scenarios:
                        add(
                            stage="stage-a",
                            block=block,
                            outer_family=family,
                            scenario_id=scenario,
                            carrier_id=carrier_id,
                            relationship_id=relationship.relationship_id,
                            client_ids=(client,),
                            server_id=server,
                        )

    stage_b = _mapping(plan["stage_b_adaptive_replica_selection"], "stage_b")
    b_factors = _mapping(stage_b["factors"], "stage_b.factors")
    meeting_profiles = _text_levels(
        b_factors["meeting_profiles"], "stage_b.meeting_profiles"
    )
    strategies = _text_levels(b_factors["strategies"], "stage_b.strategies")
    stage_b_blocks = _positive_int(b_factors["temporal_blocks"], "stage_b blocks")
    for block in range(1, stage_b_blocks + 1):
        for client in (*cloud, *mainland):
            candidates = tuple(server for server in cloud if server != client)
            for family in families:
                for carrier_id in carrier_ids:
                    for scenario in scenarios:
                        for media_profile in meeting_profiles:
                            for strategy in strategies:
                                add(
                                    stage="stage-b",
                                    block=block,
                                    outer_family=family,
                                    scenario_id=scenario,
                                    carrier_id=carrier_id,
                                    client_ids=(client,),
                                    candidate_server_ids=candidates,
                                    strategy=strategy,
                                    media_profile=media_profile,
                                )

    stage_c = _mapping(plan["stage_c_real_meeting_protocols"], "stage_c")
    pairwise = _mapping(stage_c["pairwise"], "stage_c.pairwise")
    pairwise_modes = _text_levels(pairwise["protocol_modes"], "pairwise modes")
    pairwise_scenarios = _text_levels(pairwise["scenarios"], "pairwise scenarios")
    if not set(pairwise_scenarios) <= set(scenarios):
        raise FieldDesignError("pairwise scenarios are not registered access scenarios")
    pairwise_blocks = _positive_int(pairwise["temporal_blocks"], "pairwise blocks")
    for block in range(1, pairwise_blocks + 1):
        for relationship_index, relationship in enumerate(relationships):
            client, server = _oriented_pair(
                relationship,
                block=block,
                relationship_index=relationship_index,
            )
            for family in families:
                for carrier_id in carrier_ids:
                    for protocol_mode in pairwise_modes:
                        for scenario in pairwise_scenarios:
                            add(
                                stage="stage-c-pairwise",
                                block=block,
                                outer_family=family,
                                scenario_id=scenario,
                                carrier_id=carrier_id,
                                relationship_id=relationship.relationship_id,
                                client_ids=(client,),
                                server_id=server,
                                protocol_mode=protocol_mode,
                            )

    sfu = _mapping(stage_c["multiparty_sfu"], "stage_c.multiparty_sfu")
    sfu_scenarios = _text_levels(sfu["scenarios"], "sfu scenarios")
    if not set(sfu_scenarios) <= set(scenarios):
        raise FieldDesignError("SFU scenarios are not registered access scenarios")
    sfu_blocks = _positive_int(sfu["temporal_blocks"], "sfu blocks")
    for block in range(1, sfu_blocks + 1):
        for clients in combinations(mainland, 2):
            for server in cloud:
                for family in families:
                    for carrier_id in carrier_ids:
                        for scenario in sfu_scenarios:
                            add(
                                stage="stage-c-sfu",
                                block=block,
                                outer_family=family,
                                scenario_id=scenario,
                                carrier_id=carrier_id,
                                client_ids=clients,
                                server_id=server,
                                protocol_mode="sfu-forwarded-webrtc",
                            )

    expected = {
        "stage-a": _positive_int(stage_a["expected_sessions"], "stage_a expected"),
        "stage-b": _positive_int(stage_b["expected_runs"], "stage_b expected"),
        "stage-c-pairwise": _positive_int(
            pairwise["expected_sessions"], "pairwise expected"
        ),
        "stage-c-sfu": _positive_int(sfu["expected_conferences"], "sfu expected"),
    }
    observed = Counter(cell.stage for cell in cells)
    if observed != expected or len(cells) != 15_348:
        raise FieldDesignError(
            f"field population count mismatch: expected={expected}, observed={dict(observed)}"
        )
    if len({cell.cell_id for cell in cells}) != len(cells):
        raise FieldDesignError("field population contains a duplicate cell_id")
    if any(
        cell.server_id in mainland or set(cell.candidate_server_ids) & set(mainland)
        for cell in cells
    ):
        raise FieldDesignError("field population assigns a mainland node as server")
    return FieldPopulation(
        protocol_version=protocol_version,
        dataset_id=dataset_id,
        schedule_seed=schedule_seed,
        design_sha256=design_sha256,
        cells=tuple(cells),
    )
