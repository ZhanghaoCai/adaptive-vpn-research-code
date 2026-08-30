from __future__ import annotations

import socket
import threading
import time

import pytest

from adaptive_vpn.echo_server import UDPEchoServer
from adaptive_vpn.models import PolicyConfig
from adaptive_vpn.models import SwitchDecision
from adaptive_vpn.models import ScoringThresholds
from adaptive_vpn.models import ScoringWeights
from adaptive_vpn.policy import AdaptivePolicy
from adaptive_vpn.policy import PathScorer
from adaptive_vpn.runner import PathEndpoint
from adaptive_vpn.runner import WindowedUDPExecutor


class DelayedUDPEchoServer:
    """Actual UDP echo endpoint with a controlled response delay for integration QA."""

    def __init__(self, delay_s: float) -> None:
        self.delay_s = delay_s
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.05)
        self.port = self.socket.getsockname()[1]
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                data, address = self.socket.recvfrom(65_535)
            except TimeoutError:
                continue
            except OSError:
                if self.stop_event.is_set():
                    return
                raise
            time.sleep(self.delay_s)
            try:
                self.socket.sendto(data, address)
            except OSError:
                return

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args) -> None:
        self.stop_event.set()
        self.socket.close()
        self.thread.join(timeout=1)


class RecordingStaticPolicy:
    def __init__(self) -> None:
        self.snapshot_times: list[float] = []

    def decide(self, snapshot):
        self.snapshot_times.append(snapshot.now_s)
        return SwitchDecision.no_switch(snapshot.active_path_id, reason="test_static")

    def record_completed_switch(self, completed_at_s: float) -> None:
        raise AssertionError("record_completed_switch must not be called")


def test_real_packets_change_destination_only_after_policy_switch():
    with (
        DelayedUDPEchoServer(0.025) as slow,
        UDPEchoServer(host="127.0.0.1", port=0) as fast_b,
        UDPEchoServer(host="127.0.0.1", port=0) as fast_c,
    ):
        executor = WindowedUDPExecutor(
            endpoints=(
                PathEndpoint("path-a", 0, "127.0.0.1", slow.port),
                PathEndpoint("path-b", 1, "127.0.0.1", fast_b.port),
                PathEndpoint("path-c", 2, "127.0.0.1", fast_c.port),
            ),
            run_token=71,
            monitor_packet_rate_hz=50,
            monitor_packets_per_window=8,
            window_duration_s=0.20,
        )
        policy = AdaptivePolicy(
            PolicyConfig(
                min_score_threshold=0.80,
                score_improvement_margin=0.10,
                min_switch_interval_s=0,
                sustained_degradation_s=0,
                max_switches_per_hour=10,
            ),
            scorer=PathScorer(
                ScoringWeights(latency=1, jitter=0, loss=0),
                ScoringThresholds(latency_ms=50, jitter_ms=100, loss_pct=100),
            ),
        )

        result = executor.run_windowed(
            duration_s=0.65,
            packet_rate_hz=80,
            datagram_size=256,
            response_timeout_s=0.30,
            policy=policy,
            active_path_id="path-a",
            sequence_offset=0,
        )

    switch = next(event for event in result.events if event["event"] == "path_switched")
    path_ids = [row["path_id"] for row in result.packets]
    switched_to = switch["to_path_id"]
    first_switched_packet = path_ids.index(switched_to)
    assert switched_to in {"path-b", "path-c"}
    assert set(path_ids[:first_switched_packet]) == {"path-a"}
    assert set(path_ids[first_switched_packet:]) == {switched_to}
    assert switch["effective_sequence"] == first_switched_packet

    arrivals = sorted(
        row["received_ns"] for row in result.packets if row["received_ns"] is not None
    )
    measured_gap_ms = max(
        (current - previous) / 1_000_000
        for previous, current in zip(arrivals, arrivals[1:])
    )
    assert result.longest_disruption_ms == pytest.approx(measured_gap_ms)
    assert switch["evidence"] == "packet_arrival_timestamps"


def test_policy_clock_remains_monotonic_across_phase_calls():
    with (
        UDPEchoServer(host="127.0.0.1", port=0) as server_a,
        UDPEchoServer(host="127.0.0.1", port=0) as server_b,
        UDPEchoServer(host="127.0.0.1", port=0) as server_c,
    ):
        executor = WindowedUDPExecutor(
            endpoints=(
                PathEndpoint("path-a", 0, "127.0.0.1", server_a.port),
                PathEndpoint("path-b", 1, "127.0.0.1", server_b.port),
                PathEndpoint("path-c", 2, "127.0.0.1", server_c.port),
            ),
            run_token=91,
            monitor_packet_rate_hz=50,
            monitor_packets_per_window=2,
            window_duration_s=0.10,
        )
        policy = RecordingStaticPolicy()
        executor.run_windowed(
            duration_s=0.25,
            packet_rate_hz=50,
            datagram_size=128,
            response_timeout_s=0.10,
            policy=policy,
            active_path_id="path-a",
            sequence_offset=0,
        )
        split = len(policy.snapshot_times)
        executor.run_windowed(
            duration_s=0.10,
            packet_rate_hz=50,
            datagram_size=128,
            response_timeout_s=0.10,
            policy=policy,
            active_path_id="path-a",
            sequence_offset=15,
        )

    assert split == 3
    assert policy.snapshot_times == sorted(policy.snapshot_times)
    assert policy.snapshot_times[split] > policy.snapshot_times[split - 1]
