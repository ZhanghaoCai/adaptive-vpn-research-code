from __future__ import annotations

from scripts.webrtc_lab.analysis import session_metrics


def test_session_metrics_compute_protocol_qoe_endpoints() -> None:
    record = {
        "mode": "turn-tls",
        "media_profile": "video",
        "duration_s": 10.0,
        "selected_candidate_pair": {
            "local_candidate_type": "relay",
            "remote_candidate_type": "host",
            "protocol": "tcp",
            "relay_protocol": "tls",
            "current_round_trip_time_ms": 110.0,
        },
        "protocol_evidence": {"peer_connections": 1},
        "browser_stats": {
            "samples": 11,
            "inbound": {
                "packets_received": 990,
                "packets_lost": 10,
                "bytes_received": 1_000_000,
                "jitter_ms": 4.0,
                "jitter_buffer_delay_ms": 6.0,
                "frames_decoded": 190,
                "frames_dropped": 10,
                "total_freezes_duration_s": 0.5,
                "concealed_samples": 480,
                "total_samples_received": 48_000,
            },
            "outbound": {"packets_sent": 1_010, "bytes_sent": 1_100_000},
        },
        "packet_cross_check": {
            "browser_outbound_packets": 1_010,
            "remote_inbound_packets": 1_000,
            "browser_inbound_packets": 990,
            "remote_outbound_packets": 1_000,
        },
    }

    metrics = session_metrics(record)

    assert metrics["inbound_loss_pct"] == 1.0
    assert metrics["inbound_bitrate_kbps"] == 800.0
    assert metrics["video_frame_drop_pct"] == 5.0
    assert metrics["video_freeze_ratio_pct"] == 5.0
    assert metrics["audio_concealment_pct"] == 1.0
    assert metrics["outbound_counter_delta_packets"] == 10
