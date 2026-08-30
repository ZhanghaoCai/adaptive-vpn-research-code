"""Validated domain models for path-selection experiments."""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum


class PathState(str, Enum):
    """Operational state reported by the measurement layer."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"


def _require_finite_non_negative(name: str, value: float) -> None:
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class PathObservation:
    """A rolling, path-specific summary derived from measured packets."""

    path_id: str
    observed_at_s: float
    rtt_ms: float
    jitter_ms: float
    loss_pct: float
    sample_count: int
    state: PathState = PathState.HEALTHY

    def __post_init__(self) -> None:
        if not self.path_id.strip():
            raise ValueError("path_id must not be empty")
        _require_finite_non_negative("observed_at_s", self.observed_at_s)
        _require_finite_non_negative("rtt_ms", self.rtt_ms)
        _require_finite_non_negative("jitter_ms", self.jitter_ms)
        _require_finite_non_negative("loss_pct", self.loss_pct)
        if self.loss_pct > 100:
            raise ValueError("loss_pct must not exceed 100")
        if self.sample_count < 1:
            raise ValueError("sample_count must be at least 1")
        if not isinstance(self.state, PathState):
            raise ValueError("state must be a PathState value")

    @property
    def eligible(self) -> bool:
        """Return whether this path may receive workload traffic."""
        return self.state is not PathState.FAILED


@dataclass(frozen=True, slots=True)
class ScoringWeights:
    """Relative contribution of each measured impairment."""

    latency: float = 0.4
    jitter: float = 0.3
    loss: float = 0.3

    def __post_init__(self) -> None:
        values = (self.latency, self.jitter, self.loss)
        if any(not math.isfinite(value) or value < 0 for value in values):
            raise ValueError("scoring weights must be finite and non-negative")
        if not math.isclose(sum(values), 1.0, abs_tol=1e-9):
            raise ValueError("scoring weights must sum to 1")


@dataclass(frozen=True, slots=True)
class ScoringThresholds:
    """Impairment values at which a component score reaches zero."""

    latency_ms: float = 300.0
    jitter_ms: float = 80.0
    loss_pct: float = 5.0

    def __post_init__(self) -> None:
        for name, value in (
            ("latency_ms", self.latency_ms),
            ("jitter_ms", self.jitter_ms),
            ("loss_pct", self.loss_pct),
        ):
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and greater than zero")


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    """Pre-registered switching controls shared by adaptive baselines."""

    min_score_threshold: float = 0.6
    score_improvement_margin: float = 0.15
    min_switch_interval_s: float = 10.0
    sustained_degradation_s: float = 5.0
    max_switches_per_hour: int = 6
    threshold_rtt_ms: float = 200.0
    threshold_loss_pct: float = 2.0
    threshold_hold_s: float = 3.0

    def __post_init__(self) -> None:
        for name in ("min_score_threshold", "score_improvement_margin"):
            value = getattr(self, name)
            if not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError(f"{name} must be between 0 and 1")
        for name in (
            "min_switch_interval_s",
            "sustained_degradation_s",
            "threshold_hold_s",
        ):
            _require_finite_non_negative(name, getattr(self, name))
        for name in ("threshold_rtt_ms", "threshold_loss_pct"):
            value = getattr(self, name)
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and greater than zero")
        if self.max_switches_per_hour < 1:
            raise ValueError("max_switches_per_hour must be at least 1")


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    """All path observations used for one auditable decision."""

    now_s: float
    active_path_id: str
    observations: tuple[PathObservation, ...]

    def __post_init__(self) -> None:
        _require_finite_non_negative("now_s", self.now_s)
        if not self.active_path_id.strip():
            raise ValueError("active_path_id must not be empty")
        path_ids = tuple(item.path_id for item in self.observations)
        if len(path_ids) != len(set(path_ids)):
            raise ValueError("observations contain duplicate path IDs")
        if self.active_path_id not in path_ids:
            raise ValueError("active path is missing from observations")

    def observation_for(self, path_id: str) -> PathObservation:
        for observation in self.observations:
            if observation.path_id == path_id:
                return observation
        raise KeyError(path_id)


@dataclass(frozen=True, slots=True)
class SwitchDecision:
    """A no-op or an explicit request for the switching backend."""

    switch: bool
    from_path_id: str
    to_path_id: str | None
    reason: str
    from_score: float | None = None
    to_score: float | None = None

    @classmethod
    def no_switch(cls, active_path_id: str, *, reason: str) -> SwitchDecision:
        return cls(False, active_path_id, None, reason)

    @classmethod
    def request(
        cls,
        *,
        from_path_id: str,
        to_path_id: str,
        reason: str,
        from_score: float,
        to_score: float,
    ) -> SwitchDecision:
        if from_path_id == to_path_id:
            raise ValueError("switch destination must differ from the active path")
        if any(
            not math.isfinite(score) or not 0 <= score <= 1
            for score in (from_score, to_score)
        ):
            raise ValueError("switch scores must be finite and between 0 and 1")
        return cls(True, from_path_id, to_path_id, reason, from_score, to_score)
