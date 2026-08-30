#!/usr/bin/env python3
"""Compute descriptive endpoints for the bounded WebRTC protocol matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from scripts.webrtc_lab.records import normalize_session, summarize_sessions, validate_session


def _number(mapping: Mapping[str, Any], key: str) -> float:
    value = mapping.get(key, 0)
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else 0.0


def _ratio(numerator: float, denominator: float) -> float:
    return 100.0 * numerator / denominator if denominator > 0 else 0.0


def session_metrics(record: Mapping[str, Any]) -> dict[str, Any]:
    browser = record["browser_stats"]
    inbound = browser["inbound"]
    outbound = browser["outbound"]
    pair = record["selected_candidate_pair"]
    cross = record["packet_cross_check"]
    duration = _number(record, "duration_s")
    received = _number(inbound, "packets_received")
    lost = max(0.0, _number(inbound, "packets_lost"))
    frames_decoded = _number(inbound, "frames_decoded")
    frames_dropped = _number(inbound, "frames_dropped")
    total_samples = _number(inbound, "total_samples_received")
    concealed = _number(inbound, "concealed_samples")
    candidate_pairs = pair.get("sfu_candidate_pairs", [pair])
    rtts = [_number(item, "current_round_trip_time_ms") for item in candidate_pairs]
    return {
        "mode": record["mode"],
        "media_profile": record["media_profile"],
        "duration_s": round(duration, 3),
        "stats_samples": int(browser["samples"]),
        "peer_connections": int(record["protocol_evidence"].get("peer_connections", 1)),
        "local_candidate_type": pair["local_candidate_type"],
        "remote_candidate_type": pair["remote_candidate_type"],
        "transport_protocol": pair.get("protocol"),
        "relay_protocol": pair.get("relay_protocol"),
        "rtt_ms": round(max(rtts, default=0.0), 3),
        "inbound_packets": int(received),
        "inbound_loss_pct": round(_ratio(lost, received + lost), 4),
        "inbound_bitrate_kbps": round(
            _number(inbound, "bytes_received") * 8 / duration / 1000 if duration > 0 else 0.0,
            3,
        ),
        "jitter_ms": round(_number(inbound, "jitter_ms"), 3),
        "jitter_buffer_delay_ms": round(_number(inbound, "jitter_buffer_delay_ms"), 3),
        "video_frame_drop_pct": round(_ratio(frames_dropped, frames_decoded + frames_dropped), 4),
        "video_freeze_ratio_pct": round(_ratio(_number(inbound, "total_freezes_duration_s"), duration), 4),
        "audio_concealment_pct": round(_ratio(concealed, total_samples), 4),
        "outbound_counter_delta_packets": int(
            abs(_number(cross, "browser_outbound_packets") - _number(cross, "remote_inbound_packets"))
        ),
        "inbound_counter_delta_packets": int(
            abs(_number(cross, "browser_inbound_packets") - _number(cross, "remote_outbound_packets"))
        ),
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_report(raw_dir: Path, normalized_dir: Path | None = None) -> dict[str, Any]:
    paths = sorted(raw_dir.glob("*.json"))
    records = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    normalized = [normalize_session(record) for record in records]
    validated = [validate_session(record) for record in normalized]
    if normalized_dir is not None:
        normalized_dir.mkdir(parents=True, exist_ok=True)
        for path, record in zip(paths, validated, strict=True):
            (normalized_dir / path.name).write_text(
                json.dumps(record, indent=2, sort_keys=True), encoding="utf-8"
            )
    summary = summarize_sessions(validated)
    metrics = [session_metrics(record) for record in validated]
    return {
        "schema_version": "1.0.0",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "evidence_class": "completed-bounded-exploratory-webrtc",
        "scope": {
            "completed_sessions": len(validated),
            "matrix": "4 protocols x 2 media profiles x 1 session",
            "duration_target_s": 12,
            "client_role": "client-only",
            "field_status": "blocked-not-a-completed-registered-field-study",
        },
        "contract_summary": summary,
        "sessions": sorted(metrics, key=lambda item: (item["mode"], item["media_profile"])),
        "source_sha256": {path.name: sha256(path) for path in paths},
        "limitations": [
            "One successful session per protocol/profile cell; no replication or inferential comparison.",
            "The pairwise modes use Janus EchoTest; SFU uses Janus VideoRoom publisher and subscriber PeerConnections.",
            "Synthetic audio/video sources are deterministic and are not human QoE observations.",
            "The registered multi-day Main and Field populations remain unexecuted.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("raw_dir", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--normalized-dir", type=Path)
    args = parser.parse_args()
    report = build_report(args.raw_dir, args.normalized_dir)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"completed_sessions": report["scope"]["completed_sessions"]}))


if __name__ == "__main__":
    main()
