"""Auditable run lifecycle and online real-UDP path switching."""

from __future__ import annotations

import json
import math
import os
import re
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import Path
from typing import Any, Protocol

from adaptive_vpn.attempts import (
    ATTEMPT_MANIFEST_SCHEMA_VERSION,
    AttemptAllocation,
    RegisteredAttemptScope,
)
from adaptive_vpn.collector import EVIDENCE_SCHEMA_VERSION
from adaptive_vpn.config import ExperimentPlan, Scenario, ScenarioPhase, TrafficProfile
from adaptive_vpn.models import (
    PathObservation,
    PathState,
    PolicyConfig,
    PolicySnapshot,
    ScoringThresholds,
    ScoringWeights,
)
from adaptive_vpn.policy import (
    AdaptivePolicy,
    PathScorer,
    Policy,
    StaticPolicy,
    ThresholdPolicy,
)
from adaptive_vpn.probe import ProbeRunResult, UDPProbeSession
from adaptive_vpn.provenance import ensure_no_secrets
from adaptive_vpn.schedule import (
    ScheduleEntry,
    experiment_config_sha256,
    generate_schedule,
)


@dataclass(frozen=True, slots=True)
class PathEndpoint:
    path_id: str
    path_index: int
    host: str
    port: int
    address_family: int = socket.AF_INET

    def __post_init__(self) -> None:
        if not self.path_id:
            raise ValueError("path_id must not be empty")
        if not 0 <= self.path_index <= 65_535:
            raise ValueError("path_index must fit the probe header")
        if not self.host:
            raise ValueError("host must not be empty")
        if not 0 < self.port <= 65_535:
            raise ValueError("port must be between 1 and 65535")
        if self.address_family not in {socket.AF_INET, socket.AF_INET6}:
            raise ValueError("address_family must be AF_INET or AF_INET6")


_NAMESPACE_NAME = re.compile(r"avpn-[a-z0-9]+\Z")


def enter_network_namespace(namespace: str) -> None:
    """Move only the calling probe thread into a validated named netns."""

    if _NAMESPACE_NAME.fullmatch(namespace) is None:
        raise ValueError("network namespace must use a safe avpn-* name")
    setns = getattr(os, "setns", None)
    if setns is None:
        raise RuntimeError("this Python runtime does not provide os.setns")
    descriptor = os.open(f"/var/run/netns/{namespace}", os.O_RDONLY)
    try:
        setns(descriptor, 0)
    finally:
        os.close(descriptor)


class NamespaceUDPProbeSession:
    """Enter the client netns before creating any probe socket or RX thread."""

    def __init__(
        self,
        *,
        namespace: str = "avpn-client",
        namespace_enter: Callable[[str], None] = enter_network_namespace,
        session_factory: Callable[..., Any] = UDPProbeSession,
        **session_kwargs: Any,
    ) -> None:
        if _NAMESPACE_NAME.fullmatch(namespace) is None:
            raise ValueError("network namespace must use a safe avpn-* name")
        self.namespace = namespace
        self.namespace_enter = namespace_enter
        self.session_factory = session_factory
        self.session_kwargs = session_kwargs

    def run_packets(self, packet_count: int) -> ProbeRunResult:
        self.namespace_enter(self.namespace)
        return self.session_factory(**self.session_kwargs).run_packets(packet_count)


class NamespaceEchoServer:
    """Run the validated echo service in the isolated server namespace."""

    def __init__(
        self,
        *,
        namespace: str = "avpn-server",
        host: str = "0.0.0.0",
        port: int = 39_993,
        address_family: int = socket.AF_INET,
        python_executable: str = sys.executable,
        process_factory: Callable[..., Any] = subprocess.Popen,
        startup_wait_s: float = 0.2,
    ) -> None:
        if _NAMESPACE_NAME.fullmatch(namespace) is None:
            raise ValueError("network namespace must use a safe avpn-* name")
        if not host:
            raise ValueError("echo host must not be empty")
        if not 0 < port <= 65_535:
            raise ValueError("echo port must be between 1 and 65535")
        if address_family not in {socket.AF_INET, socket.AF_INET6}:
            raise ValueError("address_family must be AF_INET or AF_INET6")
        if startup_wait_s < 0:
            raise ValueError("startup_wait_s must be non-negative")
        self.namespace = namespace
        self.host = host
        self.port = port
        self.address_family = address_family
        self.python_executable = python_executable
        self.process_factory = process_factory
        self.startup_wait_s = startup_wait_s
        self._process: Any | None = None

    def start(self) -> None:
        if self._process is not None:
            raise RuntimeError("namespace echo server is already started")
        argv = (
            "ip",
            "netns",
            "exec",
            self.namespace,
            self.python_executable,
            "-m",
            "adaptive_vpn.echo_server",
            "--host",
            self.host,
            "--port",
            str(self.port),
            "--family",
            "6" if self.address_family == socket.AF_INET6 else "4",
        )
        process = self.process_factory(
            argv,
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        self._process = process
        if self.startup_wait_s:
            time.sleep(self.startup_wait_s)
        if process.poll() is not None:
            self._process = None
            raise RuntimeError(
                f"namespace echo server exited during startup with {process.returncode}"
            )

    def stop(self) -> None:
        process = self._process
        if process is None:
            return
        self._process = None
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


@dataclass(frozen=True, slots=True)
class RegisteredCell:
    _plan_snapshot: Mapping[str, Any] = field(repr=False)
    _entry_snapshot: Mapping[str, Any] = field(repr=False)
    _schedule_seed: int = field(repr=False)
    _config_sha256: str = field(repr=False)

    @property
    def plan(self) -> ExperimentPlan:
        return ExperimentPlan.model_validate(_thaw_json_value(self._plan_snapshot))

    @property
    def entry(self) -> ScheduleEntry:
        entry = ScheduleEntry.model_validate(
            _thaw_json_value(self._entry_snapshot)
        )
        entry.attach_registration_identity(
            schedule_seed=self._schedule_seed,
            config_sha256=self._config_sha256,
        )
        return entry

    @property
    def scenario(self) -> Scenario:
        entry = self.entry
        return next(
            item for item in self.plan.scenarios if item.scenario_id == entry.scenario_id
        )

    @property
    def traffic_profile(self) -> TrafficProfile:
        entry = self.entry
        return next(
            item
            for item in self.plan.traffic_profiles
            if item.profile_id == entry.traffic_profile_id
        )

    @classmethod
    def from_plan(cls, plan: ExperimentPlan, entry: ScheduleEntry) -> RegisteredCell:
        if entry.config_sha256 != experiment_config_sha256(plan):
            raise ValueError("schedule entry does not match the experiment config hash")
        if entry.schedule_seed != plan.schedule_seed:
            raise ValueError("schedule entry does not match the plan seed")
        expected_schedule = generate_schedule(plan)
        expected_index = entry.ordinal - 1
        if (
            expected_index < 0
            or expected_index >= len(expected_schedule)
            or entry.model_dump(mode="json")
            != expected_schedule[expected_index].model_dump(mode="json")
        ):
            raise ValueError("schedule entry differs from the deterministic schedule")
        scenario_ids = {item.scenario_id for item in plan.scenarios}
        profile_ids = {item.profile_id for item in plan.traffic_profiles}
        if entry.scenario_id not in scenario_ids:
            raise ValueError("schedule entry references an unknown scenario")
        if entry.traffic_profile_id not in profile_ids:
            raise ValueError("schedule entry references an unknown traffic profile")
        if entry.strategy not in plan.strategies:
            raise ValueError("schedule entry references an unknown strategy")
        return cls(
            _plan_snapshot=_freeze_json_value(plan.model_dump(mode="json")),
            _entry_snapshot=_freeze_json_value(entry.model_dump(mode="json")),
            _schedule_seed=entry.schedule_seed,
            _config_sha256=entry.config_sha256,
        )


def _freeze_json_value(value: Any) -> Any:
    from types import MappingProxyType

    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze_json_value(child) for key, child in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_json_value(child) for child in value)
    return value


def _thaw_json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json_value(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json_value(child) for child in value]
    return value


def _require_json_string_keys(value: Any, *, label: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{label} JSON object keys must be strings")
            _require_json_string_keys(child, label=label)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _require_json_string_keys(child, label=label)


@dataclass(frozen=True, slots=True)
class AttemptDefinition:
    cell: RegisteredCell
    allocation: AttemptAllocation
    scope: RegisteredAttemptScope
    provenance: Mapping[str, Any]
    _manifest_snapshot: Mapping[str, Any] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.provenance, Mapping):
            raise TypeError("attempt provenance must be an object")
        plan = self.cell.plan
        entry = self.cell.entry
        if self.allocation.cell_id != entry.cell_id:
            raise ValueError("attempt allocation cell_id does not match registered cell")
        if self.allocation.scope_fingerprint != self.scope.fingerprint:
            raise ValueError("attempt allocation belongs to a different scope")
        if self.allocation._allocation_token is not self.scope._allocation_token:
            raise ValueError("attempt allocation was not issued by this scope")
        if (
            plan.campaign_stage is None
            or plan.schedule_sha256 is None
            or plan.max_attempts_per_cell is None
        ):
            raise ValueError("attempt definition requires a registered experiment plan")
        if self.allocation.attempt_number > plan.max_attempts_per_cell:
            raise ValueError("attempt allocation exceeds the registered attempt budget")
        identity = self.scope.cells.get(entry.cell_id)
        if identity is None:
            raise ValueError("attempt cell is not registered in the supplied scope")
        scope_mismatches = []
        expected_plan = {
            "dataset_id": self.scope.dataset_id,
            "campaign_stage": self.scope.campaign_stage,
            "schedule_sha256": self.scope.schedule_sha256,
            "schedule_seed": self.scope.schedule_seed,
            "max_attempts_per_cell": self.scope.max_attempts_per_cell,
        }
        for name, expected in expected_plan.items():
            if getattr(plan, name) != expected:
                scope_mismatches.append(name)
        if experiment_config_sha256(plan) != self.scope.config_sha256:
            scope_mismatches.append("config_sha256")
        expected_cell = {
            "ordinal": identity.ordinal,
            "block": identity.block,
            "scenario_id": identity.scenario_id,
            "traffic_profile_id": identity.traffic_profile_id,
            "strategy": identity.strategy,
            "schedule_seed": self.scope.schedule_seed,
            "config_sha256": self.scope.config_sha256,
        }
        for name, expected in expected_cell.items():
            if getattr(entry, name) != expected:
                scope_mismatches.append(f"cell.{name}")
        if scope_mismatches:
            raise ValueError(
                "attempt definition scope identity mismatch: "
                + ", ".join(sorted(scope_mismatches))
            )
        _require_json_string_keys(self.provenance, label="attempt provenance")
        try:
            snapshot = json.loads(
                json.dumps(
                    dict(self.provenance),
                    sort_keys=True,
                    ensure_ascii=True,
                    allow_nan=False,
                )
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("attempt provenance must be finite JSON data") from exc
        git_commit = snapshot.get("git_commit")
        if not isinstance(git_commit, str) or re.fullmatch(
            r"[0-9a-f]{40}", git_commit
        ) is None:
            raise ValueError("attempt provenance git_commit must be lowercase 40-hex")
        if git_commit != self.scope.collection_commit:
            raise ValueError("attempt provenance git_commit does not match scope")
        ensure_no_secrets(snapshot, location="attempt.provenance")
        frozen_provenance = _freeze_json_value(snapshot)
        object.__setattr__(self, "provenance", frozen_provenance)
        manifest = {
            "schema_version": ATTEMPT_MANIFEST_SCHEMA_VERSION,
            "cell_id": str(entry.cell_id),
            "attempt_id": str(self.allocation.attempt_id),
            "attempt_number": self.allocation.attempt_number,
            "supersedes_attempt_id": (
                str(self.allocation.supersedes_attempt_id)
                if self.allocation.supersedes_attempt_id is not None
                else None
            ),
            "campaign_stage": self.scope.campaign_stage,
            "schedule_sha256": self.scope.schedule_sha256,
            "dataset_id": self.scope.dataset_id,
            "strategy": identity.strategy,
            "scenario": identity.scenario_id,
            "traffic_profile": identity.traffic_profile_id,
            "block": identity.block,
            "schedule_seed": self.scope.schedule_seed,
            "ordinal": identity.ordinal,
            "config_sha256": self.scope.config_sha256,
            "experimental_unit": "run",
            "provenance": _thaw_json_value(frozen_provenance),
        }
        object.__setattr__(self, "_manifest_snapshot", _freeze_json_value(manifest))

    @property
    def plan(self) -> ExperimentPlan:
        return self.cell.plan

    @property
    def entry(self) -> ScheduleEntry:
        return self.cell.entry

    @property
    def scenario(self) -> Scenario:
        return self.cell.scenario

    @property
    def traffic_profile(self) -> TrafficProfile:
        return self.cell.traffic_profile

    @property
    def manifest(self) -> dict[str, Any]:
        return _thaw_json_value(self._manifest_snapshot)


@dataclass(frozen=True, slots=True)
class RunDefinition:
    plan: ExperimentPlan
    entry: ScheduleEntry
    scenario: Scenario
    traffic_profile: TrafficProfile

    @classmethod
    def from_plan(cls, plan: ExperimentPlan, entry: ScheduleEntry) -> RunDefinition:
        if entry.config_sha256 != experiment_config_sha256(plan):
            raise ValueError("schedule entry does not match the experiment config hash")
        if entry.schedule_seed != plan.schedule_seed:
            raise ValueError("schedule entry does not match the plan seed")
        scenarios = {item.scenario_id: item for item in plan.scenarios}
        profiles = {item.profile_id: item for item in plan.traffic_profiles}
        if entry.scenario_id not in scenarios:
            raise ValueError("schedule entry references an unknown scenario")
        if entry.traffic_profile_id not in profiles:
            raise ValueError("schedule entry references an unknown traffic profile")
        if entry.strategy not in plan.strategies:
            raise ValueError("schedule entry references an unknown strategy")
        return cls(
            plan=plan,
            entry=entry,
            scenario=scenarios[entry.scenario_id],
            traffic_profile=profiles[entry.traffic_profile_id],
        )

    @property
    def manifest(self) -> dict[str, Any]:
        return {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "run_id": str(self.entry.run_id),
            "dataset_id": self.plan.dataset_id,
            "strategy": self.entry.strategy,
            "scenario": self.entry.scenario_id,
            "traffic_profile": self.entry.traffic_profile_id,
            "block": self.entry.block,
            "schedule_seed": self.entry.schedule_seed,
            "ordinal": self.entry.ordinal,
            "config_sha256": self.entry.config_sha256,
            "experimental_unit": "run",
        }


class ExecutionDefinition(Protocol):
    @property
    def plan(self) -> ExperimentPlan: ...

    @property
    def entry(self) -> ScheduleEntry: ...

    @property
    def scenario(self) -> Scenario: ...

    @property
    def traffic_profile(self) -> TrafficProfile: ...

    @property
    def manifest(self) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class PhaseExecution:
    active_path_id: str
    next_sequence: int
    packets: tuple[dict[str, Any], ...]
    events: tuple[dict[str, Any], ...]
    longest_disruption_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class RunOutcome:
    status: str
    evidence_path: Path
    failure_reason: str | None
    final_active_path_id: str
    packet_count: int


class LabBackend(Protocol):
    def assert_clean(self) -> None: ...

    def setup(self) -> None: ...

    def impair(self, path_id: str, **values: Any) -> None: ...

    def status(self) -> Mapping[str, Any]: ...

    def cleanup(self) -> None: ...


class ServerController(Protocol):
    def start(self) -> None: ...

    def stop(self) -> None: ...


class PhaseExecutor(Protocol):
    def calibrate(self, definition: ExecutionDefinition) -> Mapping[str, Any]: ...

    def run_phase(self, **kwargs: Any) -> PhaseExecution: ...


class BundleWriter(Protocol):
    def write_packet(self, row: dict[str, Any]) -> None: ...

    def write_event(self, event: dict[str, Any]) -> None: ...

    def write_text_artifact(self, name: str, content: str) -> Path: ...

    def finalise(self, *, status: str, failure_reason: str | None = None) -> Path: ...


def build_policy(definition: ExecutionDefinition) -> Policy:
    registered = definition.plan
    switch = registered.switching
    config = PolicyConfig(
        min_score_threshold=switch.min_score_threshold,
        score_improvement_margin=switch.score_improvement_margin,
        min_switch_interval_s=switch.min_switch_interval_s,
        sustained_degradation_s=switch.sustained_degradation_s,
        max_switches_per_hour=switch.max_switches_per_hour,
        threshold_rtt_ms=switch.threshold_rtt_ms,
        threshold_loss_pct=switch.threshold_loss_pct,
        threshold_hold_s=switch.threshold_hold_s,
    )
    scoring = registered.scoring
    scorer = PathScorer(
        ScoringWeights(scoring.latency, scoring.jitter, scoring.loss),
        ScoringThresholds(
            scoring.latency_threshold_ms,
            scoring.jitter_threshold_ms,
            scoring.loss_threshold_pct,
        ),
    )
    if definition.entry.strategy == "static":
        return StaticPolicy()
    if definition.entry.strategy == "threshold":
        return ThresholdPolicy(config, scorer)
    return AdaptivePolicy(config, scorer)


class ExperimentRunner:
    """Execute one registered run while retaining failures as evidence."""

    def __init__(
        self,
        *,
        lab: LabBackend,
        server: ServerController,
        executor: PhaseExecutor,
        bundle_factory: Callable[[dict[str, Any]], BundleWriter],
    ) -> None:
        self.lab = lab
        self.server = server
        self.executor = executor
        self.bundle_factory = bundle_factory

    def run(self, definition: ExecutionDefinition) -> RunOutcome:
        bundle = self.bundle_factory(definition.manifest)
        active_path_id = min(
            definition.plan.paths, key=lambda path: path.path_index
        ).path_id
        sequence = 0
        server_started = False
        cleanup_attempted = False
        finalised = False
        stage = "verify_clean"
        evidence_path: Path | None = None
        try:
            self.lab.assert_clean()
            stage = "setup"
            self.lab.setup()
            stage = "calibrate"
            calibration = self.executor.calibrate(definition)
            bundle.write_event({"event": "calibration_completed", **calibration})
            stage = "start_server"
            self.server.start()
            server_started = True
            policy = build_policy(definition)
            for phase in definition.scenario.phases:
                for path_id, impairment in phase.paths.items():
                    stage = f"impair:{path_id}"
                    self.lab.impair(path_id, **impairment.model_dump())
                bundle.write_event(
                    {
                        "event": "phase_started",
                        "phase_id": phase.phase_id,
                        "duration_s": phase.duration_s,
                    }
                )
                stage = f"collect:{phase.phase_id}"
                result = self.executor.run_phase(
                    phase=phase,
                    traffic_profile=definition.traffic_profile,
                    policy=policy,
                    active_path_id=active_path_id,
                    sequence_offset=sequence,
                )
                for packet in result.packets:
                    bundle.write_packet(packet)
                for event in result.events:
                    bundle.write_event(event)
                bundle.write_event(
                    {
                        "event": "phase_completed",
                        "phase_id": phase.phase_id,
                        "longest_disruption_ms": result.longest_disruption_ms,
                    }
                )
                active_path_id = result.active_path_id
                sequence = result.next_sequence

            stage = "stop_server"
            self.server.stop()
            server_started = False
            stage = "capture_status"
            bundle.write_text_artifact(
                "lab-status.json",
                json.dumps(self.lab.status(), indent=2, sort_keys=True) + "\n",
            )
            stage = "cleanup"
            cleanup_attempted = True
            self.lab.cleanup()
            stage = "verify_cleanup"
            self.lab.assert_clean()
            stage = "finalise"
            evidence_path = bundle.finalise(status="complete")
            finalised = True
            return RunOutcome("complete", evidence_path, None, active_path_id, sequence)
        except Exception as exc:  # noqa: BLE001 - normalise run failures into evidence
            reason = f"{stage}: {type(exc).__name__}"
            if server_started:
                try:
                    self.server.stop()
                except Exception as stop_exc:  # noqa: BLE001 - retain primary failure
                    reason += f"; stop_server: {type(stop_exc).__name__}"
            if not cleanup_attempted:
                cleanup_attempted = True
                try:
                    self.lab.cleanup()
                    self.lab.assert_clean()
                except Exception as cleanup_exc:  # noqa: BLE001 - retain run failure
                    reason += f"; cleanup: {type(cleanup_exc).__name__}"
            if not finalised:
                try:
                    bundle.write_event(
                        {
                            "event": "run_failed",
                            "failure_stage": stage,
                            "error_type": type(exc).__name__,
                            "error_detail_persisted": False,
                        }
                    )
                    evidence_path = bundle.finalise(
                        status="incomplete", failure_reason=reason
                    )
                    finalised = True
                except Exception as recovery_exc:  # noqa: BLE001 - retain primary failure
                    raise RuntimeError(
                        f"{reason}; evidence_recovery_failed: "
                        f"{type(recovery_exc).__name__}"
                    ) from exc
            assert evidence_path is not None
            return RunOutcome(
                "incomplete", evidence_path, reason, active_path_id, sequence
            )
        finally:
            if not cleanup_attempted:
                self.lab.cleanup()


class WindowedUDPExecutor:
    """Measure every path and send workload packets on the selected path."""

    def __init__(
        self,
        *,
        endpoints: tuple[PathEndpoint, ...],
        run_token: int,
        monitor_packet_rate_hz: float = 20,
        monitor_packets_per_window: int = 10,
        monitor_datagram_size: int = 128,
        window_duration_s: float = 1.0,
        duplicate_drain_s: float = 0.05,
        probe_factory: Callable[..., Any] = UDPProbeSession,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if len(endpoints) < 2:
            raise ValueError("at least two path endpoints are required")
        if len({item.path_id for item in endpoints}) != len(endpoints):
            raise ValueError("path endpoint IDs must be unique")
        if len({item.path_index for item in endpoints}) != len(endpoints):
            raise ValueError("path endpoint indexes must be unique")
        if not 0 <= run_token <= 2**64 - 1:
            raise ValueError("run_token must fit an unsigned 64-bit integer")
        if monitor_packet_rate_hz <= 0 or monitor_packets_per_window < 1:
            raise ValueError("monitor packet settings must be positive")
        if not 64 <= monitor_datagram_size <= 65_507:
            raise ValueError("monitor_datagram_size must fit one UDP datagram")
        if window_duration_s <= 0:
            raise ValueError("window_duration_s must be positive")
        if duplicate_drain_s <= 0:
            raise ValueError("duplicate_drain_s must be positive")
        self.endpoints = endpoints
        self.run_token = run_token
        self.monitor_packet_rate_hz = monitor_packet_rate_hz
        self.monitor_packets_per_window = monitor_packets_per_window
        self.monitor_datagram_size = monitor_datagram_size
        self.window_duration_s = window_duration_s
        self.duplicate_drain_s = duplicate_drain_s
        self.probe_factory = probe_factory
        self.monotonic = monotonic
        self._run_started_at_s: float | None = None
        self._probe_window = 0

    def _probe(
        self,
        endpoint: PathEndpoint,
        *,
        run_token: int,
        packet_rate_hz: float,
        packet_count: int,
        datagram_size: int,
        response_timeout_s: float,
    ) -> ProbeRunResult:
        session = self.probe_factory(
            target_host=endpoint.host,
            target_port=endpoint.port,
            address_family=endpoint.address_family,
            run_token=run_token,
            path_index=endpoint.path_index,
            packet_rate_hz=packet_rate_hz,
            datagram_size=datagram_size,
            response_timeout_s=response_timeout_s,
            duplicate_drain_s=self.duplicate_drain_s,
        )
        return session.run_packets(packet_count)

    def _token(self, window: int, stream: int) -> int:
        streams_per_window = len(self.endpoints) + 1
        return (self.run_token + window * streams_per_window + stream + 1) % (2**64)

    def _observations(
        self, results: Mapping[str, ProbeRunResult], now_s: float
    ) -> tuple[PathObservation, ...]:
        observations = []
        for endpoint in self.endpoints:
            result = results[endpoint.path_id]
            metrics = result.metrics
            if metrics.received_count:
                rtt_ms = metrics.rtt_mean_ms
                jitter_ms = metrics.rfc3550_jitter_ms
                state = PathState.HEALTHY
            else:
                rtt_ms = self.window_duration_s * 1_000
                jitter_ms = 0.0
                state = PathState.FAILED
            observations.append(
                PathObservation(
                    path_id=endpoint.path_id,
                    observed_at_s=now_s,
                    rtt_ms=rtt_ms,
                    jitter_ms=jitter_ms,
                    loss_pct=metrics.loss_pct,
                    sample_count=metrics.sent_count,
                    state=state,
                )
            )
        return tuple(observations)

    @staticmethod
    def _require_probe_integrity(
        monitor_results: Mapping[str, ProbeRunResult],
        workload: ProbeRunResult,
        workload_path_id: str,
    ) -> None:
        failures = []
        streams = [
            (f"monitor:{path_id}", result)
            for path_id, result in monitor_results.items()
        ]
        streams.append((f"workload:{workload_path_id}", workload))
        for stream, result in streams:
            if result.attribution_errors or result.duplicate_echoes:
                failures.append(
                    f"{stream} attribution_errors={result.attribution_errors} "
                    f"duplicate_echoes={result.duplicate_echoes}"
                )
        if failures:
            raise RuntimeError(
                "probe attribution integrity failure: " + "; ".join(failures)
            )

    def calibrate(self, definition: ExecutionDefinition) -> Mapping[str, Any]:
        """Record the registered endpoint count; apparatus calibration is separate."""

        registered = {path.path_id for path in definition.plan.paths}
        actual = {path.path_id for path in self.endpoints}
        if registered != actual:
            raise ValueError("executor endpoints do not match the registered paths")
        return {"registered_endpoint_count": len(actual)}

    def run_phase(
        self,
        *,
        phase: ScenarioPhase,
        traffic_profile: TrafficProfile,
        policy: Policy,
        active_path_id: str,
        sequence_offset: int,
    ) -> PhaseExecution:
        return self.run_windowed(
            duration_s=phase.duration_s,
            packet_rate_hz=traffic_profile.packet_rate_hz,
            datagram_size=traffic_profile.datagram_size,
            response_timeout_s=traffic_profile.response_timeout_ms / 1_000,
            policy=policy,
            active_path_id=active_path_id,
            sequence_offset=sequence_offset,
        )

    def run_windowed(
        self,
        *,
        duration_s: float,
        packet_rate_hz: float,
        datagram_size: int,
        response_timeout_s: float,
        policy: Policy,
        active_path_id: str,
        sequence_offset: int,
    ) -> PhaseExecution:
        endpoints = {item.path_id: item for item in self.endpoints}
        if active_path_id not in endpoints:
            raise ValueError("active path has no endpoint")
        if duration_s <= 0 or packet_rate_hz <= 0 or response_timeout_s <= 0:
            raise ValueError("duration, packet rate, and timeout must be positive")
        if sequence_offset < 0:
            raise ValueError("sequence_offset must be non-negative")

        packet_rows: list[dict[str, Any]] = []
        events: list[dict[str, Any]] = []
        sequence = sequence_offset
        window_count = max(1, math.ceil(duration_s / self.window_duration_s))
        if self._run_started_at_s is None:
            self._run_started_at_s = self.monotonic()
        for window in range(window_count):
            token_window = self._probe_window
            self._probe_window += 1
            window_started_s = self.monotonic() - self._run_started_at_s
            remaining_s = duration_s - window * self.window_duration_s
            workload_duration_s = min(self.window_duration_s, remaining_s)
            workload_count = max(1, round(workload_duration_s * packet_rate_hz))
            active_endpoint = endpoints[active_path_id]
            with ThreadPoolExecutor(max_workers=len(self.endpoints) + 1) as pool:
                monitor_futures = {
                    endpoint.path_id: pool.submit(
                        self._probe,
                        endpoint,
                        run_token=self._token(token_window, stream),
                        packet_rate_hz=self.monitor_packet_rate_hz,
                        packet_count=self.monitor_packets_per_window,
                        datagram_size=self.monitor_datagram_size,
                        response_timeout_s=response_timeout_s,
                    )
                    for stream, endpoint in enumerate(self.endpoints)
                }
                workload_future = pool.submit(
                    self._probe,
                    active_endpoint,
                    run_token=self._token(token_window, len(self.endpoints)),
                    packet_rate_hz=packet_rate_hz,
                    packet_count=workload_count,
                    datagram_size=datagram_size,
                    response_timeout_s=response_timeout_s,
                )
                monitor_results = {
                    path_id: future.result()
                    for path_id, future in monitor_futures.items()
                }
                workload = workload_future.result()

            self._require_probe_integrity(
                monitor_results,
                workload,
                active_path_id,
            )

            for row in workload.rows:
                packet_rows.append(
                    {
                        "sequence": sequence,
                        "path_id": active_path_id,
                        "sent_ns": row.sent_ns,
                        "received_ns": row.received_ns,
                        "status": row.status.value,
                        "rtt_ms": row.rtt_ms,
                        "datagram_bytes": row.datagram_bytes,
                    }
                )
                sequence += 1

            now_s = self.monotonic() - self._run_started_at_s
            observations = self._observations(monitor_results, now_s)
            events.append(
                {
                    "event": "path_observations",
                    "window": window + 1,
                    "measurement_timing": {
                        "logical_window_duration_s": self.window_duration_s,
                        "response_timeout_s": response_timeout_s,
                        "duplicate_drain_s": self.duplicate_drain_s,
                        "observation_elapsed_s": now_s,
                        "window_started_elapsed_s": window_started_s,
                        "window_elapsed_s": now_s - window_started_s,
                        "logical_workload_duration_s": workload_duration_s,
                    },
                    "observations": [
                        {
                            "path_id": observation.path_id,
                            "rtt_ms": observation.rtt_ms,
                            "jitter_ms": observation.jitter_ms,
                            "loss_pct": observation.loss_pct,
                            "sample_count": observation.sample_count,
                            "state": observation.state.value,
                        }
                        for observation in observations
                    ],
                }
            )
            decision = policy.decide(
                PolicySnapshot(
                    now_s=now_s,
                    active_path_id=active_path_id,
                    observations=observations,
                )
            )
            if decision.switch:
                assert decision.to_path_id is not None
                events.append(
                    {
                        "event": "path_switched",
                        "from_path_id": active_path_id,
                        "to_path_id": decision.to_path_id,
                        "reason": decision.reason,
                        "effective_sequence": sequence,
                        "observed_at_s": now_s,
                        "evidence": "packet_arrival_timestamps",
                    }
                )
                active_path_id = decision.to_path_id
                policy.record_completed_switch(now_s)

        arrivals = sorted(
            row["received_ns"] for row in packet_rows if row["received_ns"] is not None
        )
        longest_gap_ms = max(
            (
                (current - previous) / 1_000_000
                for previous, current in pairwise(arrivals)
            ),
            default=0.0,
        )
        return PhaseExecution(
            active_path_id=active_path_id,
            next_sequence=sequence,
            packets=tuple(packet_rows),
            events=tuple(events),
            longest_disruption_ms=longest_gap_ms,
        )
