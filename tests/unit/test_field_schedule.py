from collections import Counter, defaultdict
from copy import deepcopy
from itertools import product
from pathlib import Path
from uuid import UUID

import pytest

from adaptive_vpn.field_schedule import (
    FieldDesignError,
    generate_field_population,
    load_field_design,
)

ROOT = Path(__file__).parents[2]


def test_field_population_expands_every_registered_unit_once():
    plan = load_field_design(ROOT / "experiments" / "field-design.yaml")
    population = generate_field_population(plan)

    assert len(population.cells) == 15_348
    assert Counter(cell.stage for cell in population.cells) == {
        "stage-a": 3_276,
        "stage-b": 8_400,
        "stage-c-pairwise": 2_808,
        "stage-c-sfu": 864,
    }
    assert len({cell.cell_id for cell in population.cells}) == 15_348
    assert all(UUID(cell.cell_id).version == 5 for cell in population.cells)
    assert [cell.ordinal for cell in population.cells] == list(range(1, 15_349))


def test_field_population_never_assigns_mainland_node_as_server():
    plan = load_field_design(ROOT / "experiments" / "field-design.yaml")
    population = generate_field_population(plan)
    mainland = {
        node["node_id"] for node in plan["inventory"]["mainland_client_nodes"]
    }

    assert all(cell.server_id not in mainland for cell in population.cells)
    assert all(
        not (set(cell.candidate_server_ids) & mainland) for cell in population.cells
    )
    stage_b = [cell for cell in population.cells if cell.stage == "stage-b"]
    assert {cell.client_ids[0] for cell in stage_b} == {
        node["node_id"]
        for node in (
            plan["inventory"]["server_nodes"]
            + plan["inventory"]["mainland_client_nodes"]
        )
    }


def test_field_population_has_exact_dual_stack_scenario_and_protocol_levels():
    plan = load_field_design(ROOT / "experiments" / "field-design.yaml")
    population = generate_field_population(plan)

    assert {cell.outer_family for cell in population.cells} == {
        "native-outer-ipv4",
        "native-outer-ipv6",
    }
    stage_a = [cell for cell in population.cells if cell.stage == "stage-a"]
    assert len({cell.relationship_id for cell in stage_a}) == 39
    assert {cell.scenario_id for cell in stage_a} == set(
        plan["access_scenarios"]["levels"]
    )
    pairwise = [
        cell for cell in population.cells if cell.stage == "stage-c-pairwise"
    ]
    assert {cell.protocol_mode for cell in pairwise} == set(
        plan["stage_c_real_meeting_protocols"]["pairwise"]["protocol_modes"]
    )
    sfu = [cell for cell in population.cells if cell.stage == "stage-c-sfu"]
    assert {cell.protocol_mode for cell in sfu} == {"sfu-forwarded-webrtc"}


def test_carrier_is_independent_of_every_other_registered_factor():
    plan = load_field_design(ROOT / "experiments" / "field-design.yaml")
    population = generate_field_population(plan)
    carriers = {
        plan["encrypted_carriers"]["primary"]["carrier_id"],
        plan["encrypted_carriers"]["secondary"]["carrier_id"],
    }
    observed_by_base_cell: dict[tuple[object, ...], set[str]] = defaultdict(set)

    for cell in population.cells:
        base_cell = (
            cell.stage,
            cell.block,
            cell.outer_family,
            cell.scenario_id,
            cell.relationship_id,
            cell.client_ids,
            cell.server_id,
            cell.candidate_server_ids,
            cell.strategy,
            cell.media_profile,
            cell.protocol_mode,
        )
        observed_by_base_cell[base_cell].add(cell.carrier_id)

    assert observed_by_base_cell
    assert {frozenset(value) for value in observed_by_base_cell.values()} == {
        frozenset(carriers)
    }
    pairwise = [
        cell for cell in population.cells if cell.stage == "stage-c-pairwise"
    ]
    assert {(cell.carrier_id, cell.protocol_mode) for cell in pairwise} == set(
        product(
            carriers,
            plan["stage_c_real_meeting_protocols"]["pairwise"]["protocol_modes"],
        )
    )
    assert Counter(cell.carrier_id for cell in population.cells) == {
        "wireguard-udp": 7_674,
        "wireguard-over-wss": 7_674,
    }


def test_carrier_aware_inference_strata_have_exact_registered_comparison_levels():
    plan = load_field_design(ROOT / "experiments" / "field-design.yaml")
    population = generate_field_population(plan)

    stage_a: dict[tuple[object, ...], set[str]] = defaultdict(set)
    stage_b: dict[tuple[object, ...], set[str | None]] = defaultdict(set)
    stage_c: dict[tuple[object, ...], set[str | None]] = defaultdict(set)
    for cell in population.cells:
        if cell.stage == "stage-a":
            key = (
                cell.relationship_id,
                cell.scenario_id,
                cell.block,
                cell.carrier_id,
            )
            stage_a[key].add(cell.outer_family)
        elif cell.stage == "stage-b":
            key = (
                cell.client_ids[0],
                cell.outer_family,
                cell.scenario_id,
                cell.media_profile,
                cell.block,
                cell.carrier_id,
            )
            stage_b[key].add(cell.strategy)
        elif cell.stage == "stage-c-pairwise":
            key = (
                cell.relationship_id,
                cell.outer_family,
                cell.scenario_id,
                cell.block,
                cell.carrier_id,
            )
            stage_c[key].add(cell.protocol_mode)

    assert stage_a and {len(levels) for levels in stage_a.values()} == {2}
    assert stage_b and {len(levels) for levels in stage_b.values()} == {3}
    assert stage_c and {len(levels) for levels in stage_c.values()} == {3}


def test_field_population_serialisation_is_deterministic_and_content_addressed():
    plan = load_field_design(ROOT / "experiments" / "field-design.yaml")
    first = generate_field_population(plan)
    second = generate_field_population(plan)

    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.sha256 == second.sha256
    assert len(first.sha256) == 64


def test_field_population_rejects_duplicate_registered_carriers():
    plan = deepcopy(load_field_design(ROOT / "experiments" / "field-design.yaml"))
    plan["encrypted_carriers"]["registered_levels"] = [
        "wireguard-udp",
        "wireguard-udp",
    ]

    with pytest.raises(FieldDesignError, match="carrier"):
        generate_field_population(plan)


def test_field_population_rejects_stage_carrier_count_mismatch():
    plan = deepcopy(load_field_design(ROOT / "experiments" / "field-design.yaml"))
    plan["stage_a_full_mesh_characterisation"]["factors"]["carriers"] = 1

    with pytest.raises(FieldDesignError, match="carrier"):
        generate_field_population(plan)


def test_field_population_rejects_carrier_population_total_mismatch():
    plan = deepcopy(load_field_design(ROOT / "experiments" / "field-design.yaml"))
    plan["matrix_totals"]["compatibility_carrier_units"] = 7_673

    with pytest.raises(FieldDesignError, match="carrier population"):
        generate_field_population(plan)
