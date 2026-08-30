import socket

import pytest

from adaptive_vpn.echo_server import UDPEchoServer
from adaptive_vpn.probe import UDPProbeSession


def test_real_udp_loopback_records_finite_metrics():
    with UDPEchoServer(host="127.0.0.1", port=0) as server:
        session = UDPProbeSession(
            target_host="127.0.0.1",
            target_port=server.port,
            run_token=20260803,
            path_index=0,
            packet_rate_hz=200,
            datagram_size=256,
            response_timeout_s=0.25,
        )
        result = session.run_packets(100)

    assert result.metrics.sent_count == 100
    assert result.metrics.received_count == 100
    assert result.metrics.loss_pct == 0
    assert result.metrics.rtt_mean_ms >= 0
    assert result.metrics.rtt_p95_ms >= result.metrics.rtt_median_ms
    assert result.metrics.rfc3550_jitter_ms >= 0
    assert result.attribution_errors == 0
    assert result.duplicate_echoes == 0
    assert len(result.rows) == 100


@pytest.mark.skipif(not socket.has_ipv6, reason="IPv6 is unavailable")
def test_real_ipv6_udp_loopback_uses_native_ipv6_socket():
    with UDPEchoServer(
        host="::1", port=0, address_family=socket.AF_INET6
    ) as server:
        session = UDPProbeSession(
            target_host="::1",
            target_port=server.port,
            run_token=20260805,
            path_index=0,
            packet_rate_hz=100,
            datagram_size=256,
            response_timeout_s=0.25,
            address_family=socket.AF_INET6,
        )
        result = session.run_packets(10)

    assert result.metrics.sent_count == 10
    assert result.metrics.received_count == 10
    assert result.attribution_errors == 0
