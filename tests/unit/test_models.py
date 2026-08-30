import pytest

from adaptive_vpn.models import PathObservation
from adaptive_vpn.models import PathState
from adaptive_vpn.models import PolicySnapshot
from adaptive_vpn.models import ScoringWeights
from adaptive_vpn.models import SwitchDecision


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("rtt_ms", -0.1, "rtt_ms"),
        ("jitter_ms", -0.1, "jitter_ms"),
        ("loss_pct", -0.1, "loss_pct"),
        ("loss_pct", 100.1, "loss_pct"),
        ("sample_count", 0, "sample_count"),
    ),
)
def test_path_observation_rejects_invalid_metrics(field, value, message):
    values = {
        "path_id": "path-a",
        "observed_at_s": 1.0,
        "rtt_ms": 40.0,
        "jitter_ms": 3.0,
        "loss_pct": 0.2,
        "sample_count": 10,
    }
    values[field] = value

    with pytest.raises(ValueError, match=message):
        PathObservation(**values)


def test_path_observation_requires_non_empty_path_id():
    with pytest.raises(ValueError, match="path_id"):
        PathObservation(" ", 1.0, 10.0, 1.0, 0.0, 1)


def test_weights_must_sum_to_one():
    with pytest.raises(ValueError, match="sum to 1"):
        ScoringWeights(latency=0.5, jitter=0.5, loss=0.5)


def test_weights_reject_negative_components():
    with pytest.raises(ValueError, match="non-negative"):
        ScoringWeights(latency=1.1, jitter=-0.1, loss=0.0)


def test_snapshot_rejects_missing_active_path():
    observation = PathObservation("path-b", 1.0, 10.0, 1.0, 0.0, 1)
    with pytest.raises(ValueError, match="active path"):
        PolicySnapshot(now_s=1.0, active_path_id="path-a", observations=(observation,))


def test_snapshot_rejects_duplicate_paths():
    observation = PathObservation("path-a", 1.0, 10.0, 1.0, 0.0, 1)
    with pytest.raises(ValueError, match="duplicate"):
        PolicySnapshot(
            now_s=1.0,
            active_path_id="path-a",
            observations=(observation, observation),
        )


def test_switch_decision_distinguishes_noop_from_request():
    no_switch = SwitchDecision.no_switch("path-a", reason="healthy")
    request = SwitchDecision.request(
        from_path_id="path-a",
        to_path_id="path-b",
        reason="sustained_degradation",
        from_score=0.4,
        to_score=0.8,
    )

    assert no_switch.switch is False
    assert no_switch.to_path_id is None
    assert request.switch is True
    assert request.to_path_id == "path-b"


def test_failed_observation_is_valid_but_ineligible():
    observation = PathObservation(
        "path-a", 1.0, 999.0, 0.0, 100.0, 1, state=PathState.FAILED
    )
    assert observation.eligible is False


def test_observation_rejects_untyped_state_values():
    with pytest.raises(ValueError, match="state"):
        PathObservation("path-a", 1.0, 10.0, 1.0, 0.0, 1, state="failed")


def test_switch_request_rejects_out_of_range_scores():
    with pytest.raises(ValueError, match="score"):
        SwitchDecision.request(
            from_path_id="path-a",
            to_path_id="path-b",
            reason="test",
            from_score=-0.1,
            to_score=0.8,
        )
