from __future__ import annotations

import json
import socket
import threading
import uuid
from pathlib import Path
from typing import ClassVar

import pytest

from adaptive_vpn.attempts import AttemptAllocation, build_registered_attempt_scope
from adaptive_vpn.collector import (
    BundleValidation,
    EvidenceBundle,
    validate_evidence_bundle,
)
from adaptive_vpn.config import ExperimentPlan
from adaptive_vpn.models import SwitchDecision
from adaptive_vpn.probe import ProbeRunResult
from adaptive_vpn.protocol import ProbeMetrics
from adaptive_vpn.runner import (
    AttemptDefinition,
    ExperimentRunner,
    NamespaceEchoServer,
    NamespaceUDPProbeSession,
    PathEndpoint,
    PhaseExecution,
    RegisteredCell,
    RunDefinition,
    WindowedUDPExecutor,
)
from adaptive_vpn.schedule import generate_schedule, load_registered_schedule
from tests.unit.test_config import minimal_plan_data
from tests.unit.test_schedule import _registered_plan

TEST_GIT_COMMIT = "a" * 40


def test_registered_cell_preserves_schedule_to_plan_validation(tmp_path: Path):
    plan = _registered_plan(tmp_path, blocks=1)
    entry = load_registered_schedule(plan)[0]

    cell = RegisteredCell.from_plan(plan, entry)

    assert cell.plan.model_dump(mode="json") == plan.model_dump(mode="json")
    assert cell.entry.model_dump(mode="json") == entry.model_dump(mode="json")
    assert cell.plan is not plan
    assert cell.entry is not entry
    assert cell.scenario.scenario_id == entry.scenario_id
    assert cell.traffic_profile.profile_id == entry.traffic_profile_id

    drifted = entry.model_copy(update={"ordinal": entry.ordinal + 1})
    with pytest.raises(ValueError, match="deterministic schedule"):
        RegisteredCell.from_plan(plan, drifted)
    assert RunDefinition.from_plan(plan, drifted).entry is drifted


def test_attempt_definition_emits_exact_v12_identity_and_read_only_provenance(
    tmp_path: Path,
):
    plan = _registered_plan(tmp_path, blocks=1)
    schedule = load_registered_schedule(plan)
    entry = schedule[0]
    scope = build_registered_attempt_scope(
        plan,
        schedule,
        collection_commit=TEST_GIT_COMMIT,
    )
    cell = RegisteredCell.from_plan(plan, entry)
    attempt_id = uuid.uuid4()
    definition = AttemptDefinition(
        cell=cell,
        allocation=AttemptAllocation(
            cell_id=entry.cell_id,
            attempt_id=attempt_id,
            attempt_number=1,
            supersedes_attempt_id=None,
            scope_fingerprint=scope.fingerprint,
            _allocation_token=scope._allocation_token,
        ),
        scope=scope,
        provenance={
            "git_commit": TEST_GIT_COMMIT,
            "runtime": {"kernel": "test-kernel"},
        },
    )

    manifest = definition.manifest

    assert set(manifest) == {
        "schema_version",
        "cell_id",
        "attempt_id",
        "attempt_number",
        "supersedes_attempt_id",
        "campaign_stage",
        "schedule_sha256",
        "dataset_id",
        "strategy",
        "scenario",
        "traffic_profile",
        "block",
        "schedule_seed",
        "ordinal",
        "config_sha256",
        "experimental_unit",
        "provenance",
    }
    assert manifest["schema_version"] == "1.2.0"
    assert manifest["cell_id"] == str(entry.cell_id)
    assert manifest["attempt_id"] == str(attempt_id)
    assert manifest["attempt_number"] == 1
    assert manifest["supersedes_attempt_id"] is None
    assert manifest["campaign_stage"] == plan.campaign_stage
    assert manifest["schedule_sha256"] == plan.schedule_sha256
    assert manifest["provenance"]["git_commit"] == TEST_GIT_COMMIT
    assert "run_id" not in manifest
    with pytest.raises(TypeError):
        definition.provenance["runtime"]["kernel"] = "mutated"
    manifest["provenance"]["runtime"]["kernel"] = "caller-mutated"
    assert definition.manifest["provenance"]["runtime"]["kernel"] == "test-kernel"


def test_attempt_definition_rejects_cell_or_provenance_mismatch(tmp_path: Path):
    plan = _registered_plan(tmp_path, blocks=1)
    schedule = load_registered_schedule(plan)
    first, second = schedule[:2]
    scope = build_registered_attempt_scope(
        plan,
        schedule,
        collection_commit=TEST_GIT_COMMIT,
    )
    cell = RegisteredCell.from_plan(plan, first)

    with pytest.raises(ValueError, match="allocation cell_id"):
        AttemptDefinition(
            cell=cell,
            allocation=AttemptAllocation(
                cell_id=second.cell_id,
                attempt_id=uuid.uuid4(),
                attempt_number=1,
                supersedes_attempt_id=None,
                scope_fingerprint=scope.fingerprint,
                _allocation_token=scope._allocation_token,
            ),
            scope=scope,
            provenance={"git_commit": TEST_GIT_COMMIT},
        )
    with pytest.raises(ValueError, match="git_commit"):
        AttemptDefinition(
            cell=cell,
            allocation=AttemptAllocation(
                cell_id=first.cell_id,
                attempt_id=uuid.uuid4(),
                attempt_number=1,
                supersedes_attempt_id=None,
                scope_fingerprint=scope.fingerprint,
                _allocation_token=scope._allocation_token,
            ),
            scope=scope,
            provenance={"git_commit": "not-a-commit"},
        )

    with pytest.raises(ValueError, match="does not match scope"):
        AttemptDefinition(
            cell=cell,
            allocation=AttemptAllocation(
                cell_id=first.cell_id,
                attempt_id=uuid.uuid4(),
                attempt_number=1,
                supersedes_attempt_id=None,
                scope_fingerprint=scope.fingerprint,
                _allocation_token=scope._allocation_token,
            ),
            scope=scope,
            provenance={"git_commit": "b" * 40},
        )


def test_attempt_definition_rejects_unissued_or_over_budget_allocation(
    tmp_path: Path,
):
    plan = _registered_plan(tmp_path, blocks=1)
    schedule = load_registered_schedule(plan)
    entry = schedule[0]
    scope = build_registered_attempt_scope(
        plan,
        schedule,
        collection_commit=TEST_GIT_COMMIT,
    )
    cell = RegisteredCell.from_plan(plan, entry)

    with pytest.raises(ValueError, match="not issued"):
        AttemptDefinition(
            cell=cell,
            allocation=AttemptAllocation(
                cell_id=entry.cell_id,
                attempt_id=uuid.uuid4(),
                attempt_number=1,
                supersedes_attempt_id=None,
                scope_fingerprint=scope.fingerprint,
            ),
            scope=scope,
            provenance={"git_commit": TEST_GIT_COMMIT},
        )

    with pytest.raises(ValueError, match="attempt budget"):
        AttemptDefinition(
            cell=cell,
            allocation=AttemptAllocation(
                cell_id=entry.cell_id,
                attempt_id=uuid.uuid4(),
                attempt_number=scope.max_attempts_per_cell + 1,
                supersedes_attempt_id=uuid.uuid4(),
                scope_fingerprint=scope.fingerprint,
                _allocation_token=scope._allocation_token,
            ),
            scope=scope,
            provenance={"git_commit": TEST_GIT_COMMIT},
        )


def _attempt_definition(tmp_path: Path) -> AttemptDefinition:
    plan = _registered_plan(tmp_path, blocks=1)
    schedule = load_registered_schedule(plan)
    entry = schedule[0]
    scope = build_registered_attempt_scope(
        plan,
        schedule,
        collection_commit=TEST_GIT_COMMIT,
    )
    return AttemptDefinition(
        cell=RegisteredCell.from_plan(plan, entry),
        allocation=AttemptAllocation(
            cell_id=entry.cell_id,
            attempt_id=uuid.uuid4(),
            attempt_number=1,
            supersedes_attempt_id=None,
            scope_fingerprint=scope.fingerprint,
            _allocation_token=scope._allocation_token,
        ),
        scope=scope,
        provenance={"git_commit": TEST_GIT_COMMIT, "runtime": {"kernel": "test"}},
    )


def test_attempt_definition_is_detached_from_mutable_source_objects(tmp_path: Path):
    plan = _registered_plan(tmp_path, blocks=1)
    schedule = load_registered_schedule(plan)
    entry = schedule[0]
    scope = build_registered_attempt_scope(
        plan,
        schedule,
        collection_commit=TEST_GIT_COMMIT,
    )
    definition = AttemptDefinition(
        cell=RegisteredCell.from_plan(plan, entry),
        allocation=AttemptAllocation(
            cell_id=entry.cell_id,
            attempt_id=uuid.uuid4(),
            attempt_number=1,
            supersedes_attempt_id=None,
            scope_fingerprint=scope.fingerprint,
            _allocation_token=scope._allocation_token,
        ),
        scope=scope,
        provenance={"git_commit": TEST_GIT_COMMIT},
    )
    expected_manifest = definition.manifest
    expected_dataset_id = plan.dataset_id
    expected_ordinal = entry.ordinal

    plan.dataset_id = "mutated-after-registration"
    object.__setattr__(entry, "ordinal", 999)

    assert definition.manifest == expected_manifest
    assert definition.plan.dataset_id == expected_dataset_id
    assert definition.entry.ordinal == expected_ordinal


class FakeProbeSession:
    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs

    def run_packets(self, packet_count: int):
        return {"packet_count": packet_count, "target": self.kwargs["target_host"]}


class StaticPolicy:
    def decide(self, snapshot):
        return SwitchDecision.no_switch(snapshot.active_path_id, reason="test_static")

    def record_completed_switch(self, completed_at_s: float) -> None:
        raise AssertionError("static policy must not switch")


class MisattributedProbeSession:
    def __init__(self, **kwargs) -> None:
        self.path_index = kwargs["path_index"]

    def run_packets(self, packet_count: int) -> ProbeRunResult:
        return ProbeRunResult(
            rows=(),
            metrics=ProbeMetrics(
                sent_count=packet_count,
                received_count=0,
                loss_pct=100.0,
                rtt_mean_ms=float("nan"),
                rtt_median_ms=float("nan"),
                rtt_p95_ms=float("nan"),
                rfc3550_jitter_ms=0.0,
            ),
            attribution_errors=1,
            duplicate_echoes=0,
        )


class HealthyProbeSession:
    calls: ClassVar[list[dict]] = []

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        type(self).calls.append(kwargs)

    def run_packets(self, packet_count: int) -> ProbeRunResult:
        from adaptive_vpn.protocol import PacketResult, PacketStatus

        rows = tuple(
            PacketResult(
                sequence=sequence,
                path_index=self.kwargs["path_index"],
                sent_ns=sequence,
                datagram_bytes=self.kwargs["datagram_size"],
                status=PacketStatus.RECEIVED,
                received_ns=sequence + 1,
                rtt_ms=0.000001,
            )
            for sequence in range(packet_count)
        )
        return ProbeRunResult(
            rows=rows,
            metrics=ProbeMetrics(
                sent_count=packet_count,
                received_count=packet_count,
                loss_pct=0.0,
                rtt_mean_ms=0.000001,
                rtt_median_ms=0.000001,
                rtt_p95_ms=0.000001,
                rfc3550_jitter_ms=0.0,
            ),
            attribution_errors=0,
            duplicate_echoes=0,
        )


def test_windowed_executor_records_explicit_probe_timing_contract():
    HealthyProbeSession.calls = []
    clock = iter((100.0, 100.0, 100.25))
    executor = WindowedUDPExecutor(
        endpoints=(
            PathEndpoint("path-a", 0, "127.0.0.1", 39_993),
            PathEndpoint(
                "path-b", 1, "::1", 39_993, address_family=socket.AF_INET6
            ),
        ),
        run_token=1,
        monitor_packets_per_window=1,
        window_duration_s=1.0,
        duplicate_drain_s=0.05,
        probe_factory=HealthyProbeSession,
        monotonic=lambda: next(clock),
    )

    result = executor.run_windowed(
        duration_s=1.0,
        packet_rate_hz=1,
        datagram_size=128,
        response_timeout_s=0.5,
        policy=StaticPolicy(),
        active_path_id="path-a",
        sequence_offset=0,
    )

    assert {call["duplicate_drain_s"] for call in HealthyProbeSession.calls} == {0.05}
    assert {call["address_family"] for call in HealthyProbeSession.calls} == {
        socket.AF_INET,
        socket.AF_INET6,
    }
    observation = next(event for event in result.events if event["event"] == "path_observations")
    assert observation["measurement_timing"] == {
        "logical_window_duration_s": 1.0,
        "response_timeout_s": 0.5,
        "duplicate_drain_s": 0.05,
        "observation_elapsed_s": 0.25,
        "window_started_elapsed_s": 0.0,
        "window_elapsed_s": 0.25,
        "logical_workload_duration_s": 1.0,
    }


class ManualClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class TimedProbeSession(HealthyProbeSession):
    clock: ClassVar[ManualClock]
    workload_received: ClassVar[bool] = True
    durations: ClassVar[dict[int, list[float]]] = {}
    lock: ClassVar[threading.Lock] = threading.Lock()

    def run_packets(self, packet_count: int) -> ProbeRunResult:
        from adaptive_vpn.protocol import PacketResult, PacketStatus

        is_workload = self.kwargs["packet_rate_hz"] != 20
        received = self.workload_received or not is_workload
        send_span = (packet_count - 1) / self.kwargs["packet_rate_hz"]
        terminal_wait = (
            self.kwargs["duplicate_drain_s"]
            if received
            else self.kwargs["response_timeout_s"]
        )
        duration = send_span + terminal_wait
        run_token = self.kwargs["run_token"]
        window = (run_token - 2) // 3
        with self.lock:
            window_durations = self.durations.setdefault(window, [])
            window_durations.append(duration)
            if len(window_durations) == 3:
                self.clock.advance(max(window_durations))
        rows = tuple(
            PacketResult(
                sequence=sequence,
                path_index=self.kwargs["path_index"],
                sent_ns=sequence,
                datagram_bytes=self.kwargs["datagram_size"],
                status=PacketStatus.RECEIVED if received else PacketStatus.TIMEOUT,
                received_ns=sequence + 1 if received else None,
                rtt_ms=0.000001 if received else None,
            )
            for sequence in range(packet_count)
        )
        return ProbeRunResult(
            rows=rows,
            metrics=ProbeMetrics(
                sent_count=packet_count,
                received_count=packet_count if received else 0,
                loss_pct=0.0 if received else 100.0,
                rtt_mean_ms=0.000001 if received else float("nan"),
                rtt_median_ms=0.000001 if received else float("nan"),
                rtt_p95_ms=0.000001 if received else float("nan"),
                rfc3550_jitter_ms=0.0,
            ),
            attribution_errors=0,
            duplicate_echoes=0,
        )


@pytest.mark.parametrize(
    ("workload_received", "expected_observations", "expected_window_elapsed"),
    (
        (True, [0.55, 1.05], [0.55, 0.50]),
        (False, [1.0, 1.5], [1.0, 0.5]),
    ),
)
def test_windowed_executor_cadence_accounts_for_drain_timeout_and_partial_window(
    workload_received,
    expected_observations,
    expected_window_elapsed,
):
    clock = ManualClock()
    TimedProbeSession.clock = clock
    TimedProbeSession.workload_received = workload_received
    TimedProbeSession.durations = {}
    executor = WindowedUDPExecutor(
        endpoints=(
            PathEndpoint("path-a", 0, "127.0.0.1", 39_993),
            PathEndpoint("path-b", 1, "127.0.0.1", 39_993),
        ),
        run_token=1,
        monitor_packet_rate_hz=20,
        monitor_packets_per_window=10,
        window_duration_s=1.0,
        duplicate_drain_s=0.05,
        probe_factory=TimedProbeSession,
        monotonic=clock,
    )

    result = executor.run_windowed(
        duration_s=1.5,
        packet_rate_hz=2,
        datagram_size=128,
        response_timeout_s=0.5,
        policy=StaticPolicy(),
        active_path_id="path-a",
        sequence_offset=0,
    )

    timings = [
        event["measurement_timing"]
        for event in result.events
        if event["event"] == "path_observations"
    ]
    assert [item["observation_elapsed_s"] for item in timings] == pytest.approx(
        expected_observations
    )
    assert [item["window_elapsed_s"] for item in timings] == pytest.approx(
        expected_window_elapsed
    )
    assert [item["logical_workload_duration_s"] for item in timings] == [1.0, 0.5]


def test_windowed_executor_uses_unique_stream_tokens_for_all_registered_paths():
    HealthyProbeSession.calls = []
    endpoint_count = 17
    executor = WindowedUDPExecutor(
        endpoints=tuple(
            PathEndpoint(f"path-{index}", index, "127.0.0.1", 39_993)
            for index in range(endpoint_count)
        ),
        run_token=1,
        monitor_packets_per_window=1,
        window_duration_s=1.0,
        probe_factory=HealthyProbeSession,
        monotonic=lambda: 0.0,
    )

    executor.run_windowed(
        duration_s=1.0,
        packet_rate_hz=1,
        datagram_size=128,
        response_timeout_s=0.1,
        policy=StaticPolicy(),
        active_path_id="path-0",
        sequence_offset=0,
    )

    tokens = [call["run_token"] for call in HealthyProbeSession.calls]
    assert len(tokens) == endpoint_count + 1
    assert len(tokens) == len(set(tokens))


def test_windowed_executor_keeps_tokens_unique_across_phase_calls():
    HealthyProbeSession.calls = []
    executor = WindowedUDPExecutor(
        endpoints=(
            PathEndpoint("path-a", 0, "127.0.0.1", 39_993),
            PathEndpoint("path-b", 1, "127.0.0.1", 39_993),
        ),
        run_token=2**64 - 3,
        monitor_packets_per_window=1,
        window_duration_s=1.0,
        probe_factory=HealthyProbeSession,
        monotonic=lambda: 0.0,
    )

    for sequence_offset in (0, 1):
        executor.run_windowed(
            duration_s=1.0,
            packet_rate_hz=1,
            datagram_size=128,
            response_timeout_s=0.1,
            policy=StaticPolicy(),
            active_path_id="path-a",
            sequence_offset=sequence_offset,
        )

    tokens = [call["run_token"] for call in HealthyProbeSession.calls]
    assert set(tokens) == {2**64 - 2, 2**64 - 1, 0, 1, 2, 3}
    assert len(tokens) == len(set(tokens))


def test_windowed_executor_rejects_probe_attribution_errors():
    executor = WindowedUDPExecutor(
        endpoints=(
            PathEndpoint("path-a", 0, "127.0.0.1", 39_993),
            PathEndpoint("path-b", 1, "127.0.0.1", 39_993),
        ),
        run_token=1,
        monitor_packets_per_window=1,
        window_duration_s=1.0,
        probe_factory=MisattributedProbeSession,
    )

    with pytest.raises(RuntimeError, match="probe attribution integrity failure"):
        executor.run_windowed(
            duration_s=1.0,
            packet_rate_hz=1,
            datagram_size=128,
            response_timeout_s=0.1,
            policy=StaticPolicy(),
            active_path_id="path-a",
            sequence_offset=0,
        )


def test_namespace_probe_enters_client_namespace_before_socket_session():
    events: list[str] = []

    class OrderedProbe(FakeProbeSession):
        def __init__(self, **kwargs) -> None:
            assert events == ["enter:avpn-client"]
            super().__init__(**kwargs)

    session = NamespaceUDPProbeSession(
        namespace="avpn-client",
        namespace_enter=lambda namespace: events.append(f"enter:{namespace}"),
        session_factory=OrderedProbe,
        target_host="10.210.0.2",
        target_port=39_993,
        run_token=1,
        path_index=0,
        packet_rate_hz=10,
        datagram_size=128,
        response_timeout_s=0.5,
    )

    result = session.run_packets(3)

    assert result == {"packet_count": 3, "target": "10.210.0.2"}


class FakeProcess:
    def __init__(self, argv) -> None:
        self.argv = tuple(argv)
        self.returncode = None
        self.terminated = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


def test_namespace_echo_server_uses_argument_array_and_stops_process():
    processes = []

    def process_factory(argv, **kwargs):
        process = FakeProcess(argv)
        processes.append((process, kwargs))
        return process

    server = NamespaceEchoServer(
        namespace="avpn-server",
        host="0.0.0.0",
        port=39_993,
        process_factory=process_factory,
        startup_wait_s=0,
    )

    server.start()
    server.stop()

    process, kwargs = processes[0]
    assert process.argv[:4] == ("ip", "netns", "exec", "avpn-server")
    assert process.argv[-6:] == (
        "--host",
        "0.0.0.0",
        "--port",
        "39993",
        "--family",
        "4",
    )
    assert kwargs["shell"] is False
    assert process.terminated is True


class RecordingLab:
    def __init__(self, events: list[str], fail_at: str | None = None) -> None:
        self.events = events
        self.fail_at = fail_at

    def _step(self, name: str) -> None:
        self.events.append(name)
        if self.fail_at == name:
            raise RuntimeError(f"failed at {name}")

    def assert_clean(self) -> None:
        self._step("verify_clean")

    def setup(self) -> None:
        self._step("setup")

    def impair(self, path_id: str, **values) -> None:
        self._step(f"impair:{path_id}")

    def status(self):
        self._step("capture_status")
        return {"lab": "measured state"}

    def cleanup(self) -> None:
        self.events.append("cleanup")


class SensitiveFailureLab(RecordingLab):
    def setup(self) -> None:
        self.events.append("setup")
        raise RuntimeError("CANARY-SENSITIVE-VALUE")


class FailingCleanupLab(RecordingLab):
    def cleanup(self) -> None:
        self.events.append("cleanup")
        raise RuntimeError("forced cleanup failure")


class ResidualCleanupLab(RecordingLab):
    def __init__(self, events: list[str]) -> None:
        super().__init__(events)
        self.clean_checks = 0

    def assert_clean(self) -> None:
        self.clean_checks += 1
        self.events.append("verify_clean")
        if self.clean_checks > 1:
            raise RuntimeError("forced post-cleanup residue")


class RecordingServer:
    def __init__(self, events: list[str], fail_at: str | None = None) -> None:
        self.events = events
        self.fail_at = fail_at
        self.started = False

    def start(self) -> None:
        self.events.append("start_server")
        if self.fail_at == "start_server":
            raise RuntimeError("failed at start_server")
        self.started = True

    def stop(self) -> None:
        if self.started:
            self.events.append("stop_server")
            self.started = False


class RecordingExecutor:
    def __init__(self, events: list[str], fail_at: str | None = None) -> None:
        self.events = events
        self.fail_at = fail_at

    def calibrate(self, definition) -> dict:
        self.events.append("calibrate")
        if self.fail_at == "calibrate":
            raise RuntimeError("failed at calibrate")
        return {"reachable_paths": 3}

    def run_phase(self, **kwargs) -> PhaseExecution:
        phase = kwargs["phase"]
        self.events.append(f"collect:{phase.phase_id}")
        if self.fail_at == "collect":
            raise RuntimeError("failed at collect")
        return PhaseExecution(
            active_path_id=kwargs["active_path_id"],
            next_sequence=kwargs["sequence_offset"] + 1,
            packets=(
                {
                    "sequence": kwargs["sequence_offset"],
                    "path_id": kwargs["active_path_id"],
                    "sent_ns": 1_000,
                    "received_ns": 2_000,
                    "status": "received",
                    "rtt_ms": 0.001,
                    "datagram_bytes": 256,
                },
            ),
            events=(),
        )


class RecordingBundle:
    def __init__(self, events: list[str], tmp_path: Path) -> None:
        self.events = events
        self.tmp_path = tmp_path
        self.packet_rows = []
        self.event_rows = []

    def write_packet(self, row) -> None:
        self.packet_rows.append(row)

    def write_event(self, row) -> None:
        self.event_rows.append(row)

    def write_text_artifact(self, name: str, content: str) -> Path:
        assert name == "lab-status.json"
        assert "measured state" in content
        return self.tmp_path / name

    def finalise(self, *, status: str, failure_reason: str | None = None) -> Path:
        self.events.append(f"finalise:{status}")
        if status == "incomplete":
            assert failure_reason
        return self.tmp_path / status


def definition(strategy: str = "static") -> RunDefinition:
    plan = ExperimentPlan.model_validate(minimal_plan_data())
    entry = next(item for item in generate_schedule(plan) if item.strategy == strategy)
    return RunDefinition.from_plan(plan, entry)


def make_runner(tmp_path: Path, fail_at: str | None = None):
    events: list[str] = []
    bundle = RecordingBundle(events, tmp_path)
    lab_failure = (
        fail_at if fail_at in {"verify_clean", "setup", "impair:path-a"} else None
    )
    runner = ExperimentRunner(
        lab=RecordingLab(events, lab_failure),
        server=RecordingServer(events, fail_at),
        executor=RecordingExecutor(events, fail_at),
        bundle_factory=lambda manifest: bundle,
    )
    return runner, events, bundle


def test_successful_run_has_bounded_auditable_lifecycle(tmp_path):
    runner, events, bundle = make_runner(tmp_path)

    outcome = runner.run(definition())

    assert outcome.status == "complete"
    assert events == [
        "verify_clean",
        "setup",
        "calibrate",
        "start_server",
        "impair:path-a",
        "impair:path-b",
        "impair:path-c",
        "collect:steady",
        "stop_server",
        "capture_status",
        "cleanup",
        "verify_clean",
        "finalise:complete",
    ]
    assert len(bundle.packet_rows) == 1


@pytest.mark.parametrize(
    ("fail_at", "expected_status"),
    ((None, "complete"), ("collect", "incomplete")),
)
def test_attempt_definition_keeps_one_attempt_id_through_runner_lifecycle(
    tmp_path: Path,
    fail_at: str | None,
    expected_status: str,
):
    definition = _attempt_definition(tmp_path)
    events: list[str] = []
    bundle = RecordingBundle(events, tmp_path)
    captured_manifests: list[dict] = []

    def bundle_factory(manifest: dict) -> RecordingBundle:
        captured_manifests.append(json.loads(json.dumps(manifest)))
        return bundle

    runner = ExperimentRunner(
        lab=RecordingLab(events),
        server=RecordingServer(events),
        executor=RecordingExecutor(events, fail_at),
        bundle_factory=bundle_factory,
    )

    outcome = runner.run(definition)

    assert outcome.status == expected_status
    assert captured_manifests == [definition.manifest]
    assert captured_manifests[0]["attempt_id"] == str(
        definition.allocation.attempt_id
    )
    assert events.count(f"finalise:{expected_status}") == 1


@pytest.mark.parametrize(
    "fail_at",
    ("verify_clean", "setup", "calibrate", "start_server", "impair:path-a", "collect"),
)
def test_failure_is_retained_as_incomplete_and_cleanup_always_runs(tmp_path, fail_at):
    runner, events, bundle = make_runner(tmp_path, fail_at)

    outcome = runner.run(definition())

    assert outcome.status == "incomplete"
    assert "finalise:incomplete" in events
    assert events.index("cleanup") < events.index("finalise:incomplete")
    assert fail_at in outcome.failure_reason
    assert bundle.event_rows[-1]["event"] == "run_failed"


def test_failure_evidence_does_not_persist_raw_exception_text(tmp_path):
    events: list[str] = []
    runner = ExperimentRunner(
        lab=SensitiveFailureLab(events),
        server=RecordingServer(events),
        executor=RecordingExecutor(events),
        bundle_factory=lambda saved_manifest: EvidenceBundle.create(
            tmp_path,
            {
                **saved_manifest,
                "provenance": {"git_commit": TEST_GIT_COMMIT},
            },
        ),
    )

    outcome = runner.run(definition())

    assert outcome.status == "incomplete"
    assert "CANARY-SENSITIVE-VALUE" not in outcome.failure_reason
    for artifact in outcome.evidence_path.iterdir():
        assert b"CANARY-SENSITIVE-VALUE" not in artifact.read_bytes()


def test_cleanup_failure_is_published_only_as_incomplete_evidence(tmp_path):
    events: list[str] = []
    runner = ExperimentRunner(
        lab=FailingCleanupLab(events),
        server=RecordingServer(events),
        executor=RecordingExecutor(events),
        bundle_factory=lambda saved_manifest: EvidenceBundle.create(
            tmp_path,
            {
                **saved_manifest,
                "provenance": {"git_commit": TEST_GIT_COMMIT},
            },
        ),
    )

    outcome = runner.run(definition())

    assert outcome.status == "incomplete"
    assert "cleanup: RuntimeError" in outcome.failure_reason
    assert "forced cleanup failure" not in outcome.failure_reason
    saved = json.loads(
        (outcome.evidence_path / "manifest.json").read_text(encoding="utf-8")
    )
    assert saved["status"] == "incomplete"
    assert validate_evidence_bundle(outcome.evidence_path).valid is True
    assert events.count("cleanup") == 1


def test_post_cleanup_residue_is_published_only_as_incomplete_evidence(tmp_path):
    events: list[str] = []
    runner = ExperimentRunner(
        lab=ResidualCleanupLab(events),
        server=RecordingServer(events),
        executor=RecordingExecutor(events),
        bundle_factory=lambda saved_manifest: EvidenceBundle.create(
            tmp_path,
            {
                **saved_manifest,
                "provenance": {"git_commit": TEST_GIT_COMMIT},
            },
        ),
    )

    outcome = runner.run(definition())

    assert outcome.status == "incomplete"
    assert "verify_cleanup: RuntimeError" in outcome.failure_reason
    assert "forced post-cleanup residue" not in outcome.failure_reason
    saved = json.loads(
        (outcome.evidence_path / "manifest.json").read_text(encoding="utf-8")
    )
    assert saved["status"] == "incomplete"
    assert events.count("cleanup") == 1


def test_final_evidence_self_check_failure_preserves_primary_error_and_cleans_up(
    tmp_path, monkeypatch
):
    events: list[str] = []
    runner = ExperimentRunner(
        lab=RecordingLab(events),
        server=RecordingServer(events),
        executor=RecordingExecutor(events),
        bundle_factory=lambda manifest: EvidenceBundle.create(
            tmp_path,
            {
                **manifest,
                "provenance": {"git_commit": TEST_GIT_COMMIT},
            },
        ),
    )
    monkeypatch.setattr(
        "adaptive_vpn.collector.validate_evidence_bundle",
        lambda path: BundleValidation(False, ("forced self-check failure",), ()),
    )

    with pytest.raises(RuntimeError, match="evidence_recovery_failed") as caught:
        runner.run(definition())

    assert isinstance(caught.value.__cause__, ValueError)
    assert "forced self-check failure" in str(caught.value.__cause__)
    assert events[-2:] == ["cleanup", "verify_clean"]
    assert (tmp_path / "raw").is_dir()
    assert not any((tmp_path / "raw").iterdir())
    assert any((tmp_path / ".staging").iterdir())
