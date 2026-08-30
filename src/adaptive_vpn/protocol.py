"""Binary probe protocol, packet correlation, and measured endpoint metrics."""

from __future__ import annotations

import math
import struct
import threading
from dataclasses import dataclass
from enum import Enum
from statistics import fmean, median


MAGIC = b"AVPN"
VERSION = 1
_HEADER = struct.Struct("!4sBBHQQQ")
HEADER_SIZE = _HEADER.size
_UINT64_MAX = (1 << 64) - 1
_UINT16_MAX = (1 << 16) - 1


def _require_uint(name: str, value: int, maximum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
        raise ValueError(f"{name} must be an integer between 0 and {maximum}")


@dataclass(frozen=True, slots=True)
class ProbePacket:
    """A sequence-aware UDP payload echoed without modification by the server."""

    run_token: int
    path_index: int
    sequence: int
    sent_ns: int
    payload: bytes = b""

    def __post_init__(self) -> None:
        _require_uint("run_token", self.run_token, _UINT64_MAX)
        _require_uint("path_index", self.path_index, _UINT16_MAX)
        _require_uint("sequence", self.sequence, _UINT64_MAX)
        _require_uint("sent_ns", self.sent_ns, _UINT64_MAX)
        if not isinstance(self.payload, bytes):
            raise ValueError("payload must be bytes")


def encode_packet(packet: ProbePacket) -> bytes:
    """Encode a probe datagram using network byte order."""
    return _HEADER.pack(
        MAGIC,
        VERSION,
        0,
        packet.path_index,
        packet.run_token,
        packet.sequence,
        packet.sent_ns,
    ) + packet.payload


def decode_packet(data: bytes) -> ProbePacket:
    """Decode and validate a probe datagram."""
    if len(data) < HEADER_SIZE:
        raise ValueError("probe datagram is shorter than the fixed header")
    magic, version, reserved, path_index, run_token, sequence, sent_ns = _HEADER.unpack_from(
        data
    )
    if magic != MAGIC:
        raise ValueError("probe datagram has the wrong magic value")
    if version != VERSION:
        raise ValueError(f"unsupported probe version {version}")
    if reserved != 0:
        raise ValueError("reserved probe header bits must be zero")
    return ProbePacket(run_token, path_index, sequence, sent_ns, data[HEADER_SIZE:])


class PacketStatus(str, Enum):
    PENDING = "pending"
    RECEIVED = "received"
    TIMEOUT = "timeout"


@dataclass(frozen=True, slots=True)
class PacketResult:
    sequence: int
    path_index: int
    sent_ns: int
    datagram_bytes: int
    status: PacketStatus
    received_ns: int | None
    rtt_ms: float | None


@dataclass(slots=True)
class _LedgerEntry:
    sent_ns: int
    datagram_bytes: int
    received_ns: int | None = None
    timed_out: bool = False


class PacketLedger:
    """Thread-safe correlation ledger for one run and one path."""

    def __init__(self, *, run_token: int, path_index: int) -> None:
        _require_uint("run_token", run_token, _UINT64_MAX)
        _require_uint("path_index", path_index, _UINT16_MAX)
        self.run_token = run_token
        self.path_index = path_index
        self.attribution_errors = 0
        self.duplicate_echoes = 0
        self._entries: dict[int, _LedgerEntry] = {}
        self._lock = threading.RLock()

    @property
    def sent_count(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def received_count(self) -> int:
        with self._lock:
            return sum(entry.received_ns is not None for entry in self._entries.values())

    def record_send(self, sequence: int, sent_ns: int, datagram_bytes: int) -> None:
        _require_uint("sequence", sequence, _UINT64_MAX)
        _require_uint("sent_ns", sent_ns, _UINT64_MAX)
        if datagram_bytes < HEADER_SIZE:
            raise ValueError("datagram_bytes must include the complete probe header")
        with self._lock:
            if sequence in self._entries:
                raise ValueError(f"sequence {sequence} was already sent")
            self._entries[sequence] = _LedgerEntry(sent_ns, datagram_bytes)

    def record_echo(self, packet: ProbePacket, received_ns: int) -> bool:
        _require_uint("received_ns", received_ns, _UINT64_MAX)
        with self._lock:
            if packet.run_token != self.run_token or packet.path_index != self.path_index:
                self.attribution_errors += 1
                return False
            entry = self._entries.get(packet.sequence)
            if entry is None or packet.sent_ns != entry.sent_ns or received_ns < entry.sent_ns:
                self.attribution_errors += 1
                return False
            if entry.received_ns is not None or entry.timed_out:
                self.duplicate_echoes += 1
                return False
            entry.received_ns = received_ns
            return True

    def finalize(self, *, now_ns: int, timeout_ns: int) -> None:
        _require_uint("now_ns", now_ns, _UINT64_MAX)
        _require_uint("timeout_ns", timeout_ns, _UINT64_MAX)
        with self._lock:
            for entry in self._entries.values():
                if (
                    entry.received_ns is None
                    and not entry.timed_out
                    and now_ns - entry.sent_ns >= timeout_ns
                ):
                    entry.timed_out = True

    def rows(self) -> tuple[PacketResult, ...]:
        with self._lock:
            results = []
            for sequence, entry in sorted(self._entries.items()):
                if entry.received_ns is not None:
                    status = PacketStatus.RECEIVED
                    rtt_ms = (entry.received_ns - entry.sent_ns) / 1_000_000
                elif entry.timed_out:
                    status = PacketStatus.TIMEOUT
                    rtt_ms = None
                else:
                    status = PacketStatus.PENDING
                    rtt_ms = None
                results.append(
                    PacketResult(
                        sequence=sequence,
                        path_index=self.path_index,
                        sent_ns=entry.sent_ns,
                        datagram_bytes=entry.datagram_bytes,
                        status=status,
                        received_ns=entry.received_ns,
                        rtt_ms=rtt_ms,
                    )
                )
            return tuple(results)


@dataclass(frozen=True, slots=True)
class ProbeMetrics:
    sent_count: int
    received_count: int
    loss_pct: float
    rtt_mean_ms: float
    rtt_median_ms: float
    rtt_p95_ms: float
    rfc3550_jitter_ms: float


def _linear_quantile(sorted_values: list[float], probability: float) -> float:
    if not sorted_values:
        return math.nan
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = (len(sorted_values) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    fraction = position - lower
    return sorted_values[lower] + fraction * (sorted_values[upper] - sorted_values[lower])


def _rfc3550_jitter(rtts_ms: list[float]) -> float:
    jitter = 0.0
    for previous, current in zip(rtts_ms, rtts_ms[1:]):
        jitter += (abs(current - previous) - jitter) / 16.0
    return jitter


def calculate_probe_metrics(rows: tuple[PacketResult, ...]) -> ProbeMetrics:
    """Calculate run metrics while preserving sent packets as the loss denominator."""
    if not rows:
        raise ValueError("at least one packet row is required")
    if any(row.status is PacketStatus.PENDING for row in rows):
        raise ValueError("packet ledger must be finalised before metrics are calculated")
    rtts = [row.rtt_ms for row in rows if row.rtt_ms is not None]
    sorted_rtts = sorted(rtts)
    sent_count = len(rows)
    received_count = len(rtts)
    return ProbeMetrics(
        sent_count=sent_count,
        received_count=received_count,
        loss_pct=(sent_count - received_count) / sent_count * 100.0,
        rtt_mean_ms=fmean(rtts) if rtts else math.nan,
        rtt_median_ms=median(rtts) if rtts else math.nan,
        rtt_p95_ms=_linear_quantile(sorted_rtts, 0.95),
        rfc3550_jitter_ms=_rfc3550_jitter(rtts),
    )
