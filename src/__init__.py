"""Compatibility namespace for inherited adaptive-VPN module paths.

The maintained implementation lives in :mod:`adaptive_vpn` and measures real
UDP packets in a controlled WireGuard testbed.
"""

from adaptive_vpn.collector import EvidenceBundle
from adaptive_vpn.config import ExperimentPlan
from adaptive_vpn.config import TrafficProfile
from adaptive_vpn.lab import WireGuardLab
from adaptive_vpn.models import PathObservation
from adaptive_vpn.policy import AdaptivePolicy
from adaptive_vpn.probe import UDPProbeSession


__version__ = "0.1.0"

__all__ = [
    "AdaptivePolicy",
    "EvidenceBundle",
    "ExperimentPlan",
    "PathObservation",
    "TrafficProfile",
    "UDPProbeSession",
    "WireGuardLab",
]
