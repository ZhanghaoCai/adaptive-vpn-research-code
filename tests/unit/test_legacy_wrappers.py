from adaptive_vpn.cli import main as package_main
from adaptive_vpn.collector import EvidenceBundle
from adaptive_vpn.config import TrafficProfile
from adaptive_vpn.lab import WireGuardLab
from adaptive_vpn.policy import AdaptivePolicy
from adaptive_vpn.probe import UDPProbeSession


def test_legacy_modules_resolve_to_measured_package_implementations():
    from src.app_integration import TrafficProfile as legacy_traffic_profile
    from src.data_collector import EvidenceBundle as legacy_bundle
    from src.main import main as legacy_main
    from src.path_manager import WireGuardLab as legacy_lab
    from src.quality_monitor import UDPProbeSession as legacy_probe
    from src.vpn_controller import AdaptivePolicy as legacy_policy

    assert legacy_main is package_main
    assert legacy_bundle is EvidenceBundle
    assert legacy_traffic_profile is TrafficProfile
    assert legacy_lab is WireGuardLab
    assert legacy_probe is UDPProbeSession
    assert legacy_policy is AdaptivePolicy
