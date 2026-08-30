"""Pure path-scoring and stateful switching policies."""

from __future__ import annotations

import math
from collections import deque
from typing import Protocol

from adaptive_vpn.models import PathObservation
from adaptive_vpn.models import PolicyConfig
from adaptive_vpn.models import PolicySnapshot
from adaptive_vpn.models import ScoringThresholds
from adaptive_vpn.models import ScoringWeights
from adaptive_vpn.models import SwitchDecision


class Policy(Protocol):
    """Interface consumed by the experiment runner."""

    def decide(self, snapshot: PolicySnapshot) -> SwitchDecision: ...

    def record_completed_switch(self, completed_at_s: float) -> None: ...


class PathScorer:
    """Calculate a bounded score from measured network impairments."""

    def __init__(
        self,
        weights: ScoringWeights | None = None,
        thresholds: ScoringThresholds | None = None,
    ) -> None:
        self.weights = weights or ScoringWeights()
        self.thresholds = thresholds or ScoringThresholds()

    @staticmethod
    def _component(value: float, threshold: float) -> float:
        return max(0.0, min(1.0, 1.0 - value / threshold))

    def score(self, observation: PathObservation) -> float:
        if not observation.eligible:
            return 0.0
        latency = self._component(observation.rtt_ms, self.thresholds.latency_ms)
        jitter = self._component(observation.jitter_ms, self.thresholds.jitter_ms)
        loss = self._component(observation.loss_pct, self.thresholds.loss_pct)
        return (
            self.weights.latency * latency
            + self.weights.jitter * jitter
            + self.weights.loss * loss
        )


class StaticPolicy:
    """Control condition that never changes the initial path."""

    def decide(self, snapshot: PolicySnapshot) -> SwitchDecision:
        return SwitchDecision.no_switch(snapshot.active_path_id, reason="static_policy")

    def record_completed_switch(self, completed_at_s: float) -> None:
        raise RuntimeError("static policy cannot complete a path switch")


class _SwitchingPolicy:
    def __init__(
        self,
        config: PolicyConfig,
        scorer: PathScorer | None = None,
    ) -> None:
        self.config = config
        self.scorer = scorer or PathScorer()
        self._degradation_started_at_s: float | None = None
        self._completed_switches: deque[float] = deque()

    def record_completed_switch(self, completed_at_s: float) -> None:
        if not math.isfinite(completed_at_s) or completed_at_s < 0:
            raise ValueError("completed switch time must be finite and non-negative")
        if self._completed_switches and completed_at_s < self._completed_switches[-1]:
            raise ValueError("completed switch times must be monotonic")
        self._completed_switches.append(completed_at_s)
        self._degradation_started_at_s = None

    def _best_alternative(
        self, snapshot: PolicySnapshot
    ) -> tuple[PathObservation, float] | None:
        alternatives = [
            observation
            for observation in snapshot.observations
            if observation.path_id != snapshot.active_path_id and observation.eligible
        ]
        if not alternatives:
            return None
        scored = [(observation, self.scorer.score(observation)) for observation in alternatives]
        scored.sort(key=lambda pair: (-pair[1], pair[0].path_id))
        return scored[0]

    def _switch_guard(self, now_s: float) -> str | None:
        cutoff = now_s - 3600.0
        while self._completed_switches and self._completed_switches[0] <= cutoff:
            self._completed_switches.popleft()
        if len(self._completed_switches) >= self.config.max_switches_per_hour:
            return "switch_rate_limit"
        if (
            self._completed_switches
            and now_s - self._completed_switches[-1] < self.config.min_switch_interval_s
        ):
            return "minimum_switch_interval"
        return None

    def _hold_elapsed(self, now_s: float, hold_s: float) -> bool:
        if self._degradation_started_at_s is None:
            self._degradation_started_at_s = now_s
        return now_s - self._degradation_started_at_s >= hold_s

    def _reset_hold(self) -> None:
        self._degradation_started_at_s = None


class AdaptivePolicy(_SwitchingPolicy):
    """Weighted policy with hysteresis and completed-switch rate limits."""

    def decide(self, snapshot: PolicySnapshot) -> SwitchDecision:
        active = snapshot.observation_for(snapshot.active_path_id)
        active_score = self.scorer.score(active)
        if active.eligible and active_score >= self.config.min_score_threshold:
            self._reset_hold()
            return SwitchDecision.no_switch(snapshot.active_path_id, reason="active_path_healthy")

        if not self._hold_elapsed(snapshot.now_s, self.config.sustained_degradation_s):
            return SwitchDecision.no_switch(
                snapshot.active_path_id, reason="degradation_not_sustained"
            )

        alternative = self._best_alternative(snapshot)
        if alternative is None:
            return SwitchDecision.no_switch(snapshot.active_path_id, reason="no_eligible_path")
        best, best_score = alternative
        if best_score < active_score + self.config.score_improvement_margin:
            return SwitchDecision.no_switch(
                snapshot.active_path_id, reason="insufficient_improvement"
            )

        if guard := self._switch_guard(snapshot.now_s):
            return SwitchDecision.no_switch(snapshot.active_path_id, reason=guard)

        return SwitchDecision.request(
            from_path_id=snapshot.active_path_id,
            to_path_id=best.path_id,
            reason="sustained_degradation",
            from_score=active_score,
            to_score=best_score,
        )


class ThresholdPolicy(_SwitchingPolicy):
    """Naive baseline using explicit RTT and loss cut-offs."""

    def decide(self, snapshot: PolicySnapshot) -> SwitchDecision:
        active = snapshot.observation_for(snapshot.active_path_id)
        threshold_exceeded = (
            not active.eligible
            or active.rtt_ms > self.config.threshold_rtt_ms
            or active.loss_pct > self.config.threshold_loss_pct
        )
        if not threshold_exceeded:
            self._reset_hold()
            return SwitchDecision.no_switch(snapshot.active_path_id, reason="below_thresholds")

        if not self._hold_elapsed(snapshot.now_s, self.config.threshold_hold_s):
            return SwitchDecision.no_switch(
                snapshot.active_path_id, reason="threshold_not_sustained"
            )

        alternative = self._best_alternative(snapshot)
        if alternative is None:
            return SwitchDecision.no_switch(snapshot.active_path_id, reason="no_eligible_path")
        best, best_score = alternative
        active_score = self.scorer.score(active)
        if best_score <= active_score:
            return SwitchDecision.no_switch(
                snapshot.active_path_id, reason="no_better_alternative"
            )
        if guard := self._switch_guard(snapshot.now_s):
            return SwitchDecision.no_switch(snapshot.active_path_id, reason=guard)

        return SwitchDecision.request(
            from_path_id=snapshot.active_path_id,
            to_path_id=best.path_id,
            reason="threshold_exceeded",
            from_score=active_score,
            to_score=best_score,
        )
