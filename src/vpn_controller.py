"""Legacy import surface for the validated path-selection policy core.

New code should import from :mod:`adaptive_vpn.models` and
:mod:`adaptive_vpn.policy` directly.
"""

from adaptive_vpn.models import PathObservation
from adaptive_vpn.models import PathState
from adaptive_vpn.models import PolicyConfig
from adaptive_vpn.models import PolicySnapshot
from adaptive_vpn.models import ScoringThresholds
from adaptive_vpn.models import ScoringWeights
from adaptive_vpn.models import SwitchDecision
from adaptive_vpn.policy import AdaptivePolicy
from adaptive_vpn.policy import PathScorer
from adaptive_vpn.policy import StaticPolicy
from adaptive_vpn.policy import ThresholdPolicy


__all__ = [
    "AdaptivePolicy",
    "PathObservation",
    "PathScorer",
    "PathState",
    "PolicyConfig",
    "PolicySnapshot",
    "ScoringThresholds",
    "ScoringWeights",
    "StaticPolicy",
    "SwitchDecision",
    "ThresholdPolicy",
]
