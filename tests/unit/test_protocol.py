import math

import pytest

from adaptive_vpn.protocol import HEADER_SIZE
from adaptive_vpn.protocol import PacketLedger
from adaptive_vpn.protocol import PacketStatus
from adaptive_vpn.protocol import ProbePacket
from adaptive_vpn.protocol import calculate_probe_metrics
from adaptive_vpn.protocol import decode_packet
from adaptive_vpn.protocol import encode_packet


def packet(**overrides):
    values = {
        "run_token": 7,
        "path_index": 2,
        "sequence": 11,
        "sent_ns": 1_000,
        "payload": b"payload",
    }
    values.update(overrides)
    return ProbePacket(**values)


def test_packet_round_trip_preserves_correlation_fields_and_payload():
    original = packet()
    assert decode_packet(encode_packet(original)) == original
    assert HEADER_SIZE > 0


@pytest.mark.parametrize(
    "mutation",
    (
        lambda data: data[: HEADER_SIZE - 1],
        lambda data: b"NOPE" + data[4:],
        lambda data: data[:4] + bytes([99]) + data[5:],
    ),
)
def test_decode_rejects_truncated_wrong_magic_and_wrong_version(mutation):
    with pytest.raises(ValueError):
        decode_packet(mutation(encode_packet(packet())))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("run_token", -1),
        ("path_index", -1),
        ("path_index", 65_536),
        ("sequence", -1),
        ("sent_ns", -1),
    ),
)
def test_packet_rejects_out_of_range_header_values(field, value):
    with pytest.raises(ValueError, match=field):
        packet(**{field: value})


def test_response_is_correlated_to_run_path_and_sequence():
    ledger = PacketLedger(run_token=7, path_index=2)
    ledger.record_send(sequence=11, sent_ns=1_000, datagram_bytes=64)

    accepted = ledger.record_echo(packet(payload=b""), received_ns=1_900)

    assert accepted is True
    row = ledger.rows()[0]
    assert row.status is PacketStatus.RECEIVED
    assert row.rtt_ms == pytest.approx(0.0009)


def test_ledger_rejects_wrong_run_path_unknown_and_duplicate_echoes():
    ledger = PacketLedger(run_token=7, path_index=2)
    ledger.record_send(sequence=11, sent_ns=1_000, datagram_bytes=64)

    assert ledger.record_echo(packet(run_token=8), 2_000) is False
    assert ledger.record_echo(packet(path_index=1), 2_000) is False
    assert ledger.record_echo(packet(sequence=12), 2_000) is False
    assert ledger.record_echo(packet(), 2_000) is True
    assert ledger.record_echo(packet(), 2_100) is False
    assert ledger.attribution_errors == 3
    assert ledger.duplicate_echoes == 1


def test_finalize_records_explicit_timeouts_without_zero_filling_rtt():
    ledger = PacketLedger(run_token=7, path_index=2)
    ledger.record_send(sequence=1, sent_ns=1_000, datagram_bytes=64)
    ledger.record_send(sequence=2, sent_ns=2_000, datagram_bytes=64)
    ledger.record_echo(packet(sequence=1, sent_ns=1_000), received_ns=1_500)

    ledger.finalize(now_ns=10_000, timeout_ns=5_000)

    rows = ledger.rows()
    assert [row.status for row in rows] == [PacketStatus.RECEIVED, PacketStatus.TIMEOUT]
    assert rows[1].received_ns is None
    assert rows[1].rtt_ms is None


def test_metrics_use_sent_packets_as_denominator_and_small_sample_p95():
    ledger = PacketLedger(run_token=7, path_index=2)
    for sequence, sent_ns in enumerate((0, 1_000_000, 2_000_000), start=1):
        ledger.record_send(sequence, sent_ns, 100)
    ledger.record_echo(packet(sequence=1, sent_ns=0), 10_000_000)
    ledger.record_echo(packet(sequence=2, sent_ns=1_000_000), 21_000_000)
    ledger.finalize(now_ns=100_000_000, timeout_ns=5_000_000)

    metrics = calculate_probe_metrics(ledger.rows())

    assert metrics.sent_count == 3
    assert metrics.received_count == 2
    assert metrics.loss_pct == pytest.approx(100 / 3)
    assert metrics.rtt_p95_ms == pytest.approx(19.5)
    assert metrics.rfc3550_jitter_ms > 0
    assert all(math.isfinite(value) for value in (metrics.rtt_mean_ms, metrics.rtt_p95_ms))
