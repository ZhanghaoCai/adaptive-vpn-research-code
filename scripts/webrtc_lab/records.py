"""Fail-closed validation and summaries for retained WebRTC session records."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any, cast


MODES = ("direct", "turn-udp", "turn-tls", "sfu")
MEDIA_PROFILES = ("audio", "video")


class RecordValidationError(ValueError):
    """Raised when a session lacks evidence required for a completed claim."""


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RecordValidationError(f"{label} must be an object")
    return cast(Mapping[str, Any], value)


def _positive_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
        raise RecordValidationError(f"{label} must contain non-zero RTP packets")
    return float(value)


def validate_session(record: Mapping[str, object]) -> dict[str, Any]:
    """Return a mutable validated copy of one completed bounded session."""

    if record.get("schema_version") != "1.0.0":
        raise RecordValidationError("unsupported session schema")
    mode = record.get("mode")
    profile = record.get("media_profile")
    if mode not in MODES or profile not in MEDIA_PROFILES:
        raise RecordValidationError("unknown protocol or media profile")
    if record.get("client_role") != "client-only":
        raise RecordValidationError("mainland participant must remain client-only")
    if record.get("status") != "complete":
        raise RecordValidationError("only complete sessions may be summarized")

    evidence = _mapping(record.get("protocol_evidence"), "protocol evidence")
    if evidence.get("ice_state") not in {"connected", "completed"}:
        raise RecordValidationError("ICE did not connect")
    if evidence.get("connection_state") != "connected":
        raise RecordValidationError("peer connection did not connect")
    if evidence.get("dtls_state") != "connected":
        raise RecordValidationError("DTLS did not connect")
    if evidence.get("sdp_fingerprint_present") is not True:
        raise RecordValidationError("SDP fingerprint evidence is absent")

    pair = _mapping(record.get("selected_candidate_pair"), "selected candidate pair")
    if not pair.get("local_candidate_type") or not pair.get("remote_candidate_type"):
        raise RecordValidationError("selected candidate pair is absent")
    if mode.startswith("turn"):
        expected_relay = "tls" if mode == "turn-tls" else "udp"
        relay_evidence = pair.get("local_candidate_type") == "relay" or (
            pair.get("relay_protocol") == expected_relay
        )
        if not relay_evidence:
            raise RecordValidationError("TURN session did not select a relay candidate pair")

    browser = _mapping(record.get("browser_stats"), "browser stats")
    remote = _mapping(record.get("remote_stats"), "remote stats")
    if not isinstance(browser.get("samples"), int) or browser["samples"] < 2:
        raise RecordValidationError("browser stats require at least two samples")
    browser_inbound = _mapping(browser.get("inbound"), "browser inbound stats")
    browser_outbound = _mapping(browser.get("outbound"), "browser outbound stats")
    remote_inbound = _mapping(remote.get("inbound"), "remote inbound stats")
    remote_outbound = _mapping(remote.get("outbound"), "remote outbound stats")
    for value, label in (
        (browser_inbound.get("packets_received"), "browser inbound"),
        (browser_outbound.get("packets_sent"), "browser outbound"),
        (remote_inbound.get("packets_received"), "remote inbound"),
        (remote_outbound.get("packets_sent"), "remote outbound"),
    ):
        _positive_number(value, label)

    cross_check = _mapping(record.get("packet_cross_check"), "packet cross-check")
    for key in (
        "browser_outbound_packets",
        "remote_inbound_packets",
        "browser_inbound_packets",
        "remote_outbound_packets",
    ):
        _positive_number(cross_check.get(key), f"packet cross-check {key}")
    return dict(record)


def normalize_session(record: Mapping[str, object]) -> dict[str, Any]:
    """Add explicitly labelled packet bounds when Chromium omits RTCP totals."""

    normalized = copy.deepcopy(dict(record))
    remote = _mapping(normalized.get("remote_stats"), "remote stats")
    remote_inbound = _mapping(remote.get("inbound"), "remote inbound stats")
    remote_outbound = _mapping(remote.get("outbound"), "remote outbound stats")
    cross_check = _mapping(normalized.get("packet_cross_check"), "packet cross-check")
    notes: list[dict[str, str]] = []
    if not isinstance(remote_inbound.get("packets_received"), int | float) or (
        float(remote_inbound.get("packets_received", 0)) <= 0
    ):
        reconstructed = _positive_number(
            cross_check.get("remote_inbound_packets"), "remote inbound packet bound"
        )
        cast(dict[str, Any], remote_inbound)["packets_received"] = int(reconstructed)
        notes.append(
            {
                "field": "remote_stats.inbound.packets_received",
                "rule": "browser outbound packets minus remote RTCP loss when available",
            }
        )
    if not isinstance(remote_outbound.get("packets_sent"), int | float) or (
        float(remote_outbound.get("packets_sent", 0)) <= 0
    ):
        reconstructed = _positive_number(
            cross_check.get("remote_outbound_packets"), "remote outbound packet bound"
        )
        cast(dict[str, Any], remote_outbound)["packets_sent"] = int(reconstructed)
        notes.append(
            {
                "field": "remote_stats.outbound.packets_sent",
                "rule": "bounded by browser inbound packets when remote RTCP total is absent",
            }
        )
    normalized["evidence_normalization"] = notes
    return normalized


def summarize_sessions(records: Sequence[Mapping[str, object]]) -> dict[str, Any]:
    """Validate and reduce exactly one complete record per protocol/profile cell."""

    validated = [validate_session(record) for record in records]
    cells: dict[str, dict[str, float | int | str]] = {}
    for record in validated:
        key = f"{record['mode']}/{record['media_profile']}"
        if key in cells:
            raise RecordValidationError(f"duplicate cell: {key}")
        inbound = _mapping(
            _mapping(record["browser_stats"], "browser stats").get("inbound"),
            "browser inbound stats",
        )
        received = _positive_number(inbound.get("packets_received"), "packets received")
        lost_raw = inbound.get("packets_lost", 0)
        if isinstance(lost_raw, bool) or not isinstance(lost_raw, int | float) or lost_raw < 0:
            raise RecordValidationError("packets lost must be non-negative")
        lost = float(lost_raw)
        cells[key] = {
            "mode": cast(str, record["mode"]),
            "media_profile": cast(str, record["media_profile"]),
            "inbound_loss_pct": 100.0 * lost / (received + lost),
            "packets_received": int(received),
            "packets_lost": int(lost),
        }

    expected = {f"{mode}/{profile}" for mode in MODES for profile in MEDIA_PROFILES}
    missing = sorted(expected - set(cells))
    unexpected = sorted(set(cells) - expected)
    if missing:
        raise RecordValidationError(f"missing cells: {', '.join(missing)}")
    if unexpected:
        raise RecordValidationError(f"unexpected cells: {', '.join(unexpected)}")
    return {
        "schema_version": "1.0.0",
        "completed_sessions": len(validated),
        "modes": list(MODES),
        "media_profiles": list(MEDIA_PROFILES),
        "cells": dict(sorted(cells.items())),
    }
