from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]


def load_yaml(relative_path: str):
    return yaml.safe_load((ROOT / relative_path).read_text(encoding="utf-8"))


def test_field_plan_preserves_roles_and_exact_stage_counts():
    plan = load_yaml("experiments/field-design.yaml")

    assert plan["status"] == "plan-only-no-remote-execution"
    assert len(plan["inventory"]["server_nodes"]) == 6
    assert len(plan["inventory"]["mainland_client_nodes"]) == 4
    assert all(
        node["roles"] == ["client"]
        for node in plan["inventory"]["mainland_client_nodes"]
    )
    assert plan["relationships"]["total_valid_relationships"] == 39
    assert plan["relationships"]["total_directed_media_legs"] == 78

    assert plan["stage_a_full_mesh_characterisation"]["expected_sessions"] == (
        39 * 2 * 2 * 7 * 3
    )
    assert plan["stage_b_adaptive_replica_selection"]["expected_runs"] == (
        10 * 2 * 2 * 7 * 2 * 3 * 5
    )
    meeting = plan["stage_c_real_meeting_protocols"]
    assert meeting["pairwise"]["expected_sessions"] == 39 * 2 * 2 * 3 * 3 * 2
    assert meeting["multiparty_sfu"]["expected_conferences"] == (
        6 * 6 * 2 * 2 * 3 * 2
    )
    assert plan["matrix_totals"]["primary_carrier_units"] == 7_674
    assert plan["matrix_totals"]["compatibility_carrier_units"] == 7_674
    assert plan["matrix_totals"]["total_scheduled_units"] == 15_348


def test_field_plan_registers_carrier_as_an_independent_all_stage_factor():
    plan = load_yaml("experiments/field-design.yaml")
    carriers = plan["encrypted_carriers"]

    assert carriers["registered_levels"] == [
        carriers["primary"]["carrier_id"],
        carriers["secondary"]["carrier_id"],
    ]
    assert carriers["population_rule"] == "crossed-with-every-stage-cell"
    assert carriers["secondary"]["substitution_for_primary_cell"] == "forbidden"
    assert plan["stage_a_full_mesh_characterisation"]["factors"]["carriers"] == 2
    assert plan["stage_b_adaptive_replica_selection"]["factors"]["carriers"] == 2
    meeting = plan["stage_c_real_meeting_protocols"]
    assert meeting["pairwise"]["carriers"] == 2
    assert meeting["multiparty_sfu"]["carriers"] == 2


def test_field_plan_requires_native_ipv6_and_the_requested_execution_model():
    plan = load_yaml("experiments/field-design.yaml")

    family = plan["network_families"]
    assert family["native_outer_required"] is True
    assert family["ipv6_over_ipv4_counts_as_native_ipv6"] is False
    assert family["address_family_fallback"] == "forbidden"
    assert plan["encrypted_carriers"]["secondary"]["substitution_for_primary_cell"] == (
        "forbidden"
    )
    assert plan["execution_model"] == {
        "required_by_operator": "gpt-5.6-luna",
        "reasoning_effort": "max",
        "remote_execution_before_model_is_available": "forbidden",
    }


def test_field_hypotheses_and_profiles_share_the_protocol_identity():
    plan = load_yaml("experiments/field-design.yaml")
    profiles = load_yaml("experiments/field-netem-profiles.yaml")
    hypotheses = load_yaml("experiments/field-hypotheses.yaml")

    assert plan["protocol_version"] == "field-2.0-plan"
    assert profiles["protocol_version"] == plan["protocol_version"]
    assert hypotheses["protocol_version"] == plan["protocol_version"]
    assert set(plan["access_scenarios"]["levels"]) == set(profiles["scenarios"])
    assert len(hypotheses["stage_a_network_family"]["contrasts"]) == 2
    assert len(hypotheses["stage_b_policy_family"]["contrasts"]) == 6


def test_field_hypotheses_hold_carrier_constant_with_carrier_specific_reporting():
    hypotheses = load_yaml("experiments/field-hypotheses.yaml")

    carrier = hypotheses["carrier_inference"]
    assert carrier == {
        "primary_confirmatory_carrier": "wireguard-udp",
        "compatibility_carrier": "wireguard-over-wss",
        "pairing_rule": "hold-carrier-id-constant-within-every-pair-or-stratum",
        "reporting_rule": "carrier-specific-estimates-never-pooled-or-substituted",
        "compatibility_inference": "estimation-only-secondary-family",
    }
    assert "carrier_id" in hypotheses["stage_a_network_family"]["pairing"]
    assert "carrier_id" in hypotheses["stage_b_policy_family"]["pairing"]
    stage_c = hypotheses["stage_c_protocol_analysis"]
    assert "carrier_id" in stage_c["pairwise_pairing"]
    assert "carrier_id" in stage_c["multiparty_strata"]
    assert stage_c["reporting_by"] == ["carrier_id", "protocol_mode"]
