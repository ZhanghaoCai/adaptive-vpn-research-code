import pytest

from adaptive_vpn.models import PathObservation
from adaptive_vpn.models import PathState
from adaptive_vpn.models import PolicyConfig
from adaptive_vpn.models import PolicySnapshot
from adaptive_vpn.models import ScoringThresholds
from adaptive_vpn.models import ScoringWeights
from adaptive_vpn.policy import AdaptivePolicy
from adaptive_vpn.policy import PathScorer
from adaptive_vpn.policy import StaticPolicy
from adaptive_vpn.policy import ThresholdPolicy


def observation(
    path_id,
    *,
    score="good",
    observed_at_s=0.0,
    state=PathState.HEALTHY,
):
    metrics = {
        "excellent": (20.0, 2.0, 0.0),
        "good": (60.0, 8.0, 0.2),
        "poor": (240.0, 60.0, 4.0),
        "bad": (300.0, 80.0, 5.0),
    }
    rtt, jitter, loss = metrics[score]
    return PathObservation(
        path_id=path_id,
        observed_at_s=observed_at_s,
        rtt_ms=rtt,
        jitter_ms=jitter,
        loss_pct=loss,
        sample_count=20,
        state=state,
    )


def snapshot(now_s, *, active="path-a", active_score="poor", backup_score="excellent"):
    return PolicySnapshot(
        now_s=now_s,
        active_path_id=active,
        observations=(
            observation(active, score=active_score, observed_at_s=now_s),
            observation("path-b", score=backup_score, observed_at_s=now_s),
            observation("path-c", score="good", observed_at_s=now_s),
        ),
    )


def policy_config(**overrides):
    values = {
        "min_score_threshold": 0.6,
        "score_improvement_margin": 0.15,
        "min_switch_interval_s": 10.0,
        "sustained_degradation_s": 2.0,
        "max_switches_per_hour": 2,
        "threshold_rtt_ms": 200.0,
        "threshold_loss_pct": 2.0,
        "threshold_hold_s": 1.0,
    }
    values.update(overrides)
    return PolicyConfig(**values)


def test_scorer_uses_registered_weights_and_bounds_score():
    scorer = PathScorer(
        ScoringWeights(latency=0.4, jitter=0.3, loss=0.3),
        ScoringThresholds(latency_ms=300.0, jitter_ms=80.0, loss_pct=5.0),
    )

    assert scorer.score(observation("path-a", score="excellent")) == pytest.approx(
        0.4 * (1 - 20 / 300) + 0.3 * (1 - 2 / 80) + 0.3
    )
    assert scorer.score(observation("path-a", score="bad")) == 0.0


def test_static_policy_never_switches():
    decision = StaticPolicy().decide(snapshot(100.0))
    assert decision.switch is False
    assert decision.reason == "static_policy"


def test_adaptive_requires_sustained_degradation_and_margin():
    policy = AdaptivePolicy(policy_config())

    assert policy.decide(snapshot(0.0)).switch is False
    assert policy.decide(snapshot(1.9)).switch is False
    decision = policy.decide(snapshot(2.1))

    assert decision.switch is True
    assert decision.to_path_id == "path-b"
    assert decision.to_score > decision.from_score + 0.15


def test_adaptive_resets_hold_when_path_recovers():
    policy = AdaptivePolicy(policy_config())
    assert policy.decide(snapshot(0.0)).switch is False
    assert policy.decide(snapshot(1.0, active_score="good")).switch is False
    assert policy.decide(snapshot(2.5)).switch is False


def test_adaptive_does_not_switch_without_improvement_margin():
    policy = AdaptivePolicy(policy_config(score_improvement_margin=0.7))
    assert policy.decide(snapshot(0.0)).switch is False
    decision = policy.decide(snapshot(2.1, backup_score="good"))
    assert decision.switch is False
    assert decision.reason == "insufficient_improvement"


def test_adaptive_respects_minimum_switch_interval():
    policy = AdaptivePolicy(policy_config(min_switch_interval_s=10.0))
    policy.record_completed_switch(0.0)
    assert policy.decide(snapshot(1.0)).switch is False
    decision = policy.decide(snapshot(3.1))
    assert decision.switch is False
    assert decision.reason == "minimum_switch_interval"


def test_adaptive_rate_limits_completed_switches():
    policy = AdaptivePolicy(policy_config(max_switches_per_hour=2, min_switch_interval_s=0))
    policy.record_completed_switch(0.0)
    policy.record_completed_switch(100.0)
    assert policy.decide(snapshot(200.0)).switch is False
    decision = policy.decide(snapshot(202.1))
    assert decision.switch is False
    assert decision.reason == "switch_rate_limit"


def test_adaptive_excludes_failed_alternative():
    policy = AdaptivePolicy(policy_config(sustained_degradation_s=0))
    failed = observation("path-b", score="excellent", state=PathState.FAILED)
    snap = PolicySnapshot(
        now_s=1.0,
        active_path_id="path-a",
        observations=(observation("path-a", score="poor"), failed, observation("path-c")),
    )
    decision = policy.decide(snap)
    assert decision.to_path_id == "path-c"


def test_adaptive_can_leave_failed_active_path_even_with_stale_good_metrics():
    policy = AdaptivePolicy(policy_config(sustained_degradation_s=0))
    snap = PolicySnapshot(
        now_s=1.0,
        active_path_id="path-a",
        observations=(
            observation("path-a", score="excellent", state=PathState.FAILED),
            observation("path-b", score="good"),
            observation("path-c", score="poor"),
        ),
    )
    decision = policy.decide(snap)
    assert decision.switch is True
    assert decision.to_path_id == "path-b"


def test_completed_switch_time_must_be_finite():
    policy = AdaptivePolicy(policy_config())
    with pytest.raises(ValueError, match="finite"):
        policy.record_completed_switch(float("nan"))


def test_adaptive_tie_breaks_by_path_id():
    policy = AdaptivePolicy(policy_config(sustained_degradation_s=0))
    snap = PolicySnapshot(
        now_s=1.0,
        active_path_id="path-a",
        observations=(
            observation("path-a", score="poor"),
            observation("path-c", score="excellent"),
            observation("path-b", score="excellent"),
        ),
    )
    assert policy.decide(snap).to_path_id == "path-b"


def test_threshold_policy_holds_then_selects_best_path():
    policy = ThresholdPolicy(policy_config(threshold_hold_s=1.0))
    assert policy.decide(snapshot(0.0)).switch is False
    assert policy.decide(snapshot(0.9)).switch is False
    decision = policy.decide(snapshot(1.1))
    assert decision.switch is True
    assert decision.to_path_id == "path-b"
    assert decision.reason == "threshold_exceeded"


def test_threshold_policy_resets_when_both_metrics_recover():
    policy = ThresholdPolicy(policy_config())
    assert policy.decide(snapshot(0.0)).switch is False
    assert policy.decide(snapshot(0.5, active_score="good")).switch is False
    assert policy.decide(snapshot(1.6)).switch is False
