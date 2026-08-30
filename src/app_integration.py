"""Controlled UDP traffic profiles used by the registered experiment.

The supplied prototype contained fixed vendor-specific call metrics. Those
values were not observations and have been removed. ``video-low`` and
``video-high`` are transparent packet-load labels; they do not claim to
reproduce any conferencing vendor's application telemetry or subjective QoE.
"""

from adaptive_vpn.config import TrafficProfile


CONTROLLED_TRAFFIC_SCOPE = (
    "Real UDP packets in an isolated testbed; no vendor SDK, call telemetry, "
    "media codec, or public-Internet path is represented."
)

__all__ = ["CONTROLLED_TRAFFIC_SCOPE", "TrafficProfile"]
