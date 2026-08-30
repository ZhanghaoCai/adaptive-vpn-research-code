import json
import os
import shutil
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from adaptive_vpn.lab import CLIENT_NAMESPACE
from adaptive_vpn.lab import LAB_PATHS
from adaptive_vpn.lab import SERVER_NAMESPACE
from adaptive_vpn.lab import WireGuardLab
from adaptive_vpn.runner import NamespaceUDPProbeSession


pytestmark = [
    pytest.mark.netns,
    pytest.mark.skipif(os.geteuid() != 0, reason="network namespace test requires root"),
]

RUNTIME_DIR = Path("/run/avpn-lab")
ECHO_PORT = 39_993
_PROBE_SCRIPT = """
import json
import sys
from adaptive_vpn.probe import UDPProbeSession

session = UDPProbeSession(
    target_host=sys.argv[1],
    target_port=int(sys.argv[2]),
    run_token=int(sys.argv[3]),
    path_index=int(sys.argv[4]),
    packet_rate_hz=100,
    datagram_size=256,
    response_timeout_s=0.75,
    bind_device=sys.argv[5],
)
result = session.run_packets(int(sys.argv[6]))
print(json.dumps({
    "sent": result.metrics.sent_count,
    "received": result.metrics.received_count,
    "rtt_mean_ms": result.metrics.rtt_mean_ms,
    "rtt_p95_ms": result.metrics.rtt_p95_ms,
    "attribution_errors": result.attribution_errors,
}))
"""


def run(command, *, check=True):
    return subprocess.run(command, check=check, capture_output=True, text=True)


def force_cleanup() -> None:
    for namespace in (CLIENT_NAMESPACE, SERVER_NAMESPACE):
        result = run(("ip", "netns", "pids", namespace), check=False)
        for raw_pid in result.stdout.split():
            try:
                os.kill(int(raw_pid), signal.SIGKILL)
            except (ProcessLookupError, ValueError):
                pass
        run(("ip", "netns", "delete", namespace), check=False)
    for path in LAB_PATHS:
        for interface in (path.client_underlay_if, path.server_underlay_if):
            run(("ip", "link", "delete", interface), check=False)
    shutil.rmtree(RUNTIME_DIR, ignore_errors=True)


def assert_clean_host() -> None:
    namespaces = run(("ip", "netns", "list"), check=False).stdout
    links = run(("ip", "-o", "link", "show"), check=False).stdout
    assert "avpn-" not in namespaces
    assert "avpn-" not in links
    assert not RUNTIME_DIR.exists()


def measure(path_index: int, packet_count: int = 30) -> dict[str, float]:
    path = LAB_PATHS[path_index]
    result = run(
        (
            "ip",
            "netns",
            "exec",
            CLIENT_NAMESPACE,
            sys.executable,
            "-c",
            _PROBE_SCRIPT,
            path.server_overlay_ip,
            str(ECHO_PORT),
            str(20_260_803 + path_index),
            str(path_index),
            path.wireguard_if,
            str(packet_count),
        )
    )
    return json.loads(result.stdout.strip().splitlines()[-1])


def measure_with_runner_namespace_session(path_index: int):
    path = LAB_PATHS[path_index]

    def run_probe():
        return NamespaceUDPProbeSession(
            target_host=path.server_overlay_ip,
            target_port=ECHO_PORT,
            run_token=30_000_000 + path_index,
            path_index=path_index,
            packet_rate_hz=100,
            datagram_size=256,
            response_timeout_s=0.75,
            bind_device=path.wireguard_if,
        ).run_packets(10)

    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(run_probe).result()


def test_three_wireguard_paths_and_path_specific_rtt_impairment():
    missing = [command for command in ("ip", "tc", "wg") if shutil.which(command) is None]
    if missing:
        pytest.skip(f"missing required Linux tools: {', '.join(missing)}")

    force_cleanup()
    lab = WireGuardLab(runtime_dir=RUNTIME_DIR)
    server = None
    try:
        lab.setup()
        lab.setup()
        server = subprocess.Popen(
            (
                "ip",
                "netns",
                "exec",
                SERVER_NAMESPACE,
                sys.executable,
                "-m",
                "adaptive_vpn.echo_server",
                "--host",
                "0.0.0.0",
                "--port",
                str(ECHO_PORT),
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        time.sleep(0.3)
        assert server.poll() is None, server.stderr.read()

        baseline = [measure(index) for index in range(3)]
        assert all(result["received"] == result["sent"] for result in baseline)
        assert all(result["attribution_errors"] == 0 for result in baseline)
        runner_probe = measure_with_runner_namespace_session(0)
        assert runner_probe.metrics.received_count == runner_probe.metrics.sent_count == 10
        assert runner_probe.attribution_errors == 0

        status = lab.status()
        assert status[CLIENT_NAMESPACE]["wireguard"].count("latest handshake:") == 3

        lab.impair("a", rtt_ms=80.0)
        impaired = [measure(index) for index in range(3)]

        assert impaired[0]["rtt_mean_ms"] >= baseline[0]["rtt_mean_ms"] + 60.0
        assert impaired[1]["rtt_mean_ms"] < baseline[1]["rtt_mean_ms"] + 20.0
        assert impaired[2]["rtt_mean_ms"] < baseline[2]["rtt_mean_ms"] + 20.0

        lab.cleanup()
        try:
            server.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pytest.fail("cleanup left the echo process running in the lab namespace")
        assert_clean_host()
    finally:
        if server is not None and server.poll() is None:
            os.killpg(server.pid, signal.SIGTERM)
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(server.pid, signal.SIGKILL)
                server.wait(timeout=3)
        try:
            lab.cleanup()
        finally:
            force_cleanup()

    assert_clean_host()
