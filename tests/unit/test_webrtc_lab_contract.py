from __future__ import annotations

import copy

import pytest

from scripts.webrtc_lab.records import (
    RecordValidationError,
    normalize_session,
    summarize_sessions,
    validate_session,
)


def _complete_record(*, mode: str = "direct", media_profile: str = "audio") -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "session_id": f"{mode}-{media_profile}",
        "mode": mode,
        "media_profile": media_profile,
        "client_role": "client-only",
        "status": "complete",
        "duration_s": 12.0,
        "protocol_evidence": {
            "ice_state": "connected",
            "connection_state": "connected",
            "dtls_state": "connected",
            "sdp_fingerprint_present": True,
        },
        "selected_candidate_pair": {
            "local_candidate_type": "relay" if mode.startswith("turn") else "srflx",
            "remote_candidate_type": "srflx",
            "protocol": "udp" if mode != "turn-tls" else "tcp",
            "relay_protocol": "tls" if mode == "turn-tls" else None,
            "current_round_trip_time_ms": 105.0,
        },
        "browser_stats": {
            "samples": 4,
            "inbound": {
                "packets_received": 580,
                "packets_lost": 2,
                "bytes_received": 72000,
                "jitter_ms": 4.5,
            },
            "outbound": {"packets_sent": 600, "bytes_sent": 76000},
        },
        "remote_stats": {
            "inbound": {"packets_received": 598, "packets_lost": 2},
            "outbound": {"packets_sent": 582},
        },
        "packet_cross_check": {
            "browser_outbound_packets": 600,
            "remote_inbound_packets": 598,
            "browser_inbound_packets": 580,
            "remote_outbound_packets": 582,
        },
    }


def test_validate_session_accepts_complete_real_webrtc_record() -> None:
    record = _complete_record(mode="turn-tls", media_profile="video")

    validated = validate_session(record)

    assert validated["session_id"] == "turn-tls-video"
    assert validated["selected_candidate_pair"]["local_candidate_type"] == "relay"


def test_validate_session_accepts_chromium_prflx_with_matching_relay_protocol() -> None:
    record = _complete_record(mode="turn-tls")
    record["selected_candidate_pair"]["local_candidate_type"] = "prflx"  # type: ignore[index]

    validated = validate_session(record)

    assert validated["selected_candidate_pair"]["relay_protocol"] == "tls"


def test_normalize_session_reconstructs_explicit_remote_packet_bounds() -> None:
    record = _complete_record()
    record["remote_stats"]["inbound"]["packets_received"] = 0  # type: ignore[index]
    record["remote_stats"]["outbound"]["packets_sent"] = 0  # type: ignore[index]

    normalized = normalize_session(record)

    assert normalized["remote_stats"]["inbound"]["packets_received"] == 598
    assert normalized["remote_stats"]["outbound"]["packets_sent"] == 582
    assert len(normalized["evidence_normalization"]) == 2


@pytest.mark.parametrize(
    ("path", "value", "message"),
    (
        (("client_role",), "server", "client-only"),
        (("protocol_evidence", "dtls_state"), "failed", "DTLS"),
        (("selected_candidate_pair",), {}, "candidate pair"),
        (("browser_stats", "outbound", "packets_sent"), 0, "RTP packets"),
        (("remote_stats", "inbound", "packets_received"), 0, "RTP packets"),
    ),
)
def test_validate_session_rejects_incomplete_evidence(
    path: tuple[str, ...], value: object, message: str
) -> None:
    record = copy.deepcopy(_complete_record())
    target = record
    for key in path[:-1]:
        target = target[key]  # type: ignore[index,assignment]
    target[path[-1]] = value  # type: ignore[index]

    with pytest.raises(RecordValidationError, match=message):
        validate_session(record)


def test_summarize_sessions_requires_all_eight_protocol_profile_cells() -> None:
    sessions = [
        _complete_record(mode=mode, media_profile=profile)
        for mode in ("direct", "turn-udp", "turn-tls", "sfu")
        for profile in ("audio", "video")
    ]

    summary = summarize_sessions(sessions)

    assert summary["completed_sessions"] == 8
    assert summary["modes"] == ["direct", "turn-udp", "turn-tls", "sfu"]
    assert summary["media_profiles"] == ["audio", "video"]
    assert summary["cells"]["turn-tls/video"]["inbound_loss_pct"] == pytest.approx(
        100 * 2 / 582
    )


def test_summarize_sessions_rejects_missing_protocol_cell() -> None:
    sessions = [
        _complete_record(mode=mode, media_profile=profile)
        for mode in ("direct", "turn-udp", "turn-tls", "sfu")
        for profile in ("audio", "video")
        if (mode, profile) != ("sfu", "video")
    ]

    with pytest.raises(RecordValidationError, match="missing cells: sfu/video"):
        summarize_sessions(sessions)
