import hashlib
import json
from pathlib import Path

import pytest

from adaptive_vpn.collector import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    EVIDENCE_SCHEMA_VERSION,
    LEGACY_EVIDENCE_SCHEMA_VERSION,
    MANIFEST_CONTRACTS,
    MAX_DATAGRAM_BYTES,
    MAX_EVIDENCE_ARTIFACT_BYTES,
    MAX_EVIDENCE_BUNDLE_BYTES,
    MAX_JSON_BYTES,
    STRICT_PACKET_EVENT_SCHEMA_VERSION,
    UINT64_MAX,
    _manifest_errors,
    _validate_event,
)
from adaptive_vpn.provenance import (
    FORBIDDEN_SECRET_KEY_SUFFIXES,
    FORBIDDEN_SECRET_KEYS,
)

ROOT = Path(__file__).resolve().parents[2]


def load_schema(name: str):
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def test_manifest_v11_schema_matches_active_writer_and_strict_final_fields():
    schema = load_schema("run-manifest-v1.1.schema.json")

    assert schema["properties"]["schema_version"]["const"] == EVIDENCE_SCHEMA_VERSION
    assert schema["properties"]["strategy"]["enum"] == [
        "static",
        "threshold",
        "adaptive",
    ]
    assert {
        "status",
        "failure_reason",
        "finalised_at_utc",
        "evidence_sha256",
        "ordinal",
        "config_sha256",
        "experimental_unit",
        "provenance",
    } <= set(schema["required"])
    assert schema["properties"]["ordinal"] == {"type": "integer", "minimum": 1}
    assert schema["properties"]["config_sha256"]["pattern"] == "^[0-9a-f]{64}$"
    assert schema["properties"]["experimental_unit"]["const"] == "run"
    assert schema["properties"]["provenance"]["required"] == ["git_commit"]
    assert schema["properties"]["provenance"]["properties"]["git_commit"] == {
        "type": "string",
        "pattern": "^[0-9a-f]{40}$",
    }
    assert {
        condition["if"]["properties"]["status"]["const"]
        for condition in schema["allOf"]
    } == {"complete", "incomplete"}


def test_manifest_v11_schema_bytes_are_frozen_against_transition_drift():
    content = (ROOT / "schemas" / "run-manifest-v1.1.schema.json").read_bytes()

    assert hashlib.sha256(content).hexdigest() == (
        "49635eb6cd139ef1bda7c40551b9de4c0d8b34c8bb7b0605896571109d19ada8"
    )


def test_manifest_v12_schema_requires_exact_attempt_identity_fields():
    schema = load_schema("run-manifest.schema.json")
    expected_fields = {
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
        "status",
        "failure_reason",
        "finalised_at_utc",
        "evidence_sha256",
    }

    assert schema["properties"]["schema_version"]["const"] == (
        CURRENT_MANIFEST_SCHEMA_VERSION
    )
    assert set(schema["required"]) == expected_fields
    assert set(schema["properties"]) == expected_fields
    assert schema["additionalProperties"] is False
    assert "run_id" not in schema["properties"]
    assert schema["properties"]["campaign_stage"]["enum"] == [
        "smoke",
        "pilot",
        "main",
    ]


def test_manifest_v12_schema_requires_canonical_uuid_identity_and_attempt_conditionals():
    schema = load_schema("run-manifest.schema.json")

    assert schema["properties"]["cell_id"]["pattern"].endswith(
        "-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )
    assert schema["properties"]["attempt_id"]["pattern"].endswith(
        "-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )
    assert schema["properties"]["supersedes_attempt_id"]["anyOf"] == [
        {"type": "null"},
        {
            "type": "string",
            "format": "uuid",
            "pattern": (
                "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                "[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
            ),
        },
    ]
    assert schema["properties"]["attempt_number"] == {
        "type": "integer",
        "minimum": 1,
    }
    attempt_conditions = [
        condition
        for condition in schema["allOf"]
        if "attempt_number" in condition["if"]["properties"]
    ]
    assert {
        condition["if"]["properties"]["attempt_number"].get("const")
        for condition in attempt_conditions
        if "const" in condition["if"]["properties"]["attempt_number"]
    } == {1}
    assert any(
        condition["if"]["properties"]["attempt_number"].get("minimum") == 2
        for condition in attempt_conditions
    )


def test_manifest_contracts_keep_manifest_and_packet_event_versions_independent():
    assert EVIDENCE_SCHEMA_VERSION == STRICT_PACKET_EVENT_SCHEMA_VERSION == "1.1.0"
    assert CURRENT_MANIFEST_SCHEMA_VERSION == "1.2.0"
    assert set(MANIFEST_CONTRACTS) == {"1.0.0", "1.1.0", "1.2.0"}
    assert MANIFEST_CONTRACTS["1.0.0"].strict_packet_event is False
    assert MANIFEST_CONTRACTS["1.1.0"].strict_packet_event is True
    assert MANIFEST_CONTRACTS["1.2.0"].strict_packet_event is True
    assert MANIFEST_CONTRACTS["1.1.0"].attempt_identity is False
    assert MANIFEST_CONTRACTS["1.2.0"].attempt_identity is True


def _runtime_v12_manifest():
    return {
        "schema_version": CURRENT_MANIFEST_SCHEMA_VERSION,
        "cell_id": "00000000-0000-5000-8000-000000000001",
        "attempt_id": "00000000-0000-4000-8000-000000000002",
        "attempt_number": 1,
        "supersedes_attempt_id": None,
        "campaign_stage": "pilot",
        "schedule_sha256": "b" * 64,
        "dataset_id": "test-dataset",
        "strategy": "adaptive",
        "scenario": "latency_step",
        "traffic_profile": "video_low",
        "block": 1,
        "schedule_seed": 20260803,
        "ordinal": 1,
        "config_sha256": "a" * 64,
        "experimental_unit": "run",
        "provenance": {"git_commit": "a" * 40},
        "status": "complete",
        "failure_reason": None,
        "finalised_at_utc": "2026-08-04T01:02:03.123456Z",
        "evidence_sha256": {"packets.csv": "c" * 64, "events.jsonl": "d" * 64},
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("attempt_number", True),
        ("attempt_number", 0),
        ("attempt_number", -1),
        ("attempt_number", 1.5),
        ("attempt_number", "1"),
        ("cell_id", "00000000-0000-4000-8000-000000000001"),
        ("cell_id", "00000000-0000-5000-0000-000000000001"),
        ("cell_id", "00000000-0000-5000-8ABC-000000000001"),
        ("cell_id", "00000000000050008000000000000001"),
        ("attempt_id", "00000000-0000-5000-8000-000000000002"),
        ("attempt_id", "00000000-0000-4000-0000-000000000002"),
        ("attempt_id", "00000000-0000-4000-8ABC-000000000002"),
        ("attempt_id", "00000000000040008000000000000002"),
        ("campaign_stage", "production"),
        ("schedule_sha256", "B" * 64),
        ("schedule_sha256", "b" * 63),
        ("config_sha256", "A" * 64),
        ("config_sha256", "a" * 63),
        ("dataset_id", " "),
        ("scenario", ""),
        ("traffic_profile", "\t"),
        ("provenance", {"git_commit": "not-a-commit"}),
        ("run_id", "00000000-0000-4000-8000-000000000099"),
    ],
)
def test_manifest_v12_runtime_rejects_identity_and_conditional_mutations(field, value):
    manifest = _runtime_v12_manifest()
    manifest[field] = value

    errors = _manifest_errors(manifest, require_final=True)

    assert errors, field


def test_manifest_v12_runtime_rejects_predecessor_conditionals_and_extra_keys():
    first = _runtime_v12_manifest()
    first["supersedes_attempt_id"] = "00000000-0000-4000-8000-000000000003"
    assert _manifest_errors(first, require_final=True)

    later = _runtime_v12_manifest()
    later["attempt_number"] = 2
    assert not later["supersedes_attempt_id"]
    assert _manifest_errors(later, require_final=True)

    extra = _runtime_v12_manifest()
    extra["unexpected"] = True
    assert _manifest_errors(extra, require_final=True)


def test_manifest_v12_runtime_accepts_exact_prefinal_attempt_definition():
    manifest = _runtime_v12_manifest()
    for field in ("status", "failure_reason", "finalised_at_utc", "evidence_sha256"):
        manifest.pop(field)

    assert _manifest_errors(manifest, require_final=False) == []


def test_original_legacy_manifest_schema_remains_published_for_read_compatibility():
    schema = load_schema("run-manifest-v1.0.schema.json")

    assert schema["properties"]["schema_version"]["const"] == (
        LEGACY_EVIDENCE_SCHEMA_VERSION
    )
    assert "ordinal" not in schema["required"]
    assert "finalised_at_utc" not in schema["required"]
    assert schema["properties"]["run_id"]["pattern"] == (
        "^[0-9a-f]{8}-[0-9a-f]{4}-[45][0-9a-f]{3}-[89ab][0-9a-f]{3}-"
        "[0-9a-f]{12}$"
    )
    for field in ("dataset_id", "scenario", "traffic_profile"):
        assert schema["properties"][field]["pattern"] == "\\S"
    assert schema["properties"]["schedule_seed"]["maximum"] == 2**63 - 1


def test_public_structured_evidence_schemas_publish_recursive_secret_policy():
    expected = {
        "normalization": ["trim", "lowercase", "hyphen_to_underscore"],
        "forbidden_normalized_keys": sorted(FORBIDDEN_SECRET_KEYS),
        "forbidden_normalized_suffixes": list(FORBIDDEN_SECRET_KEY_SUFFIXES),
        "scope": "all_nested_object_keys",
    }

    for name in (
        "event.schema.json",
        "run-manifest.schema.json",
        "run-manifest-v1.0.schema.json",
        "run-manifest-v1.1.schema.json",
    ):
        assert load_schema(name)["x-secret-boundary"] == expected


def test_public_bundle_policy_covers_auxiliary_structured_artifacts():
    policy_path = ROOT / "schemas" / "evidence-bundle-policy.schema.json"
    assert policy_path.is_file()
    policy = json.loads(policy_path.read_text(encoding="utf-8"))

    assert policy["x-structured-artifact-policy"] == {
        "extensions": [".json", ".jsonl"],
        "extension_matching": "case-insensitive",
        "parse_mode": {".json": "single-json-value", ".jsonl": "json-value-per-line"},
        "secret_boundary_scope": "all_nested_object_keys",
    }
    for name in (
        "event.schema.json",
        "run-manifest.schema.json",
        "run-manifest-v1.0.schema.json",
        "run-manifest-v1.1.schema.json",
    ):
        assert load_schema(name)["x-bundle-policy"] == (
            "evidence-bundle-policy.schema.json"
        )


def test_public_bundle_policy_publishes_all_runtime_cross_artifact_invariants():
    policy = load_schema("evidence-bundle-policy.schema.json")

    assert policy["x-runtime-validator"] == {
        "required": True,
        "python_entrypoint": "adaptive_vpn.collector.validate_evidence_bundle",
        "invocation_scope": "whole-evidence-bundle",
        "acceptance_condition": "result.valid == true",
        "json_schema_scope": "artifact-structure-only",
        "json_schema_alone_is_sufficient": False,
        "maximum_diagnostic_messages": 100,
        "maximum_diagnostic_characters": 1_024,
        "maximum_bundle_entries": 1_024,
        "maximum_dataset_bundles": 20_000,
        "maximum_manifest_or_json_bytes": MAX_JSON_BYTES,
        "maximum_artifact_bytes": MAX_EVIDENCE_ARTIFACT_BYTES,
        "maximum_bundle_bytes": MAX_EVIDENCE_BUNDLE_BYTES,
    }
    assert policy["x-bundle-invariants"] == {
        "bundle_path": {
            "must_be_directory": True,
            "symlink_allowed": False,
            "windows_reparse_point_allowed": False,
        },
        "top_level_inventory": {
            "scope": "top-level",
            "all_entries_except_sha256sums_must_be_regular_files": True,
            "symlinks_and_non_regular_entries_forbidden": True,
            "windows_reparse_points_forbidden": True,
            "required_artifacts": [
                "packets.csv",
                "events.jsonl",
                "manifest.json",
                "SHA256SUMS",
            ],
        },
        "sha256sums": {
            "encoding": "ascii",
            "maximum_bytes": MAX_JSON_BYTES,
            "must_be_nonempty": True,
            "line_format": "<lowercase-sha256><two-spaces><safe-basename>",
            "safe_basename": {
                "nonempty": True,
                "forbidden_exact_names": [".", ".."],
                "forbidden_characters": ["/", "\\", "\x00"],
            },
            "duplicate_entries_forbidden": True,
            "self_entry_forbidden": True,
            "coverage": "exactly-all-other-top-level-regular-files",
            "digests_must_match": True,
        },
        "manifest_evidence_sha256": {
            "coverage": (
                "exactly-all-top-level-regular-files-except-manifest-and-sha256sums"
            ),
            "excluded_artifacts": ["manifest.json", "SHA256SUMS"],
            "safe_basename_required": True,
            "lowercase_sha256_required": True,
            "digests_must_match": True,
        },
        "directory_identity": {
            "directory_name_must_equal_canonical_manifest_identity": True,
            "manifest_identity_field_by_version": {
                "1.0.0": "run_id",
                "1.1.0": "run_id",
                "1.2.0": "attempt_id",
            },
        },
        "packets_csv": {
            "exact_header": [
                "sequence",
                "path_id",
                "sent_ns",
                "received_ns",
                "status",
                "rtt_ms",
                "datagram_bytes",
            ],
            "current_schema_sequence_values_must_be_unique": True,
        },
        "current_complete_run": {
            "when": {
                "schema_version_in": [
                    EVIDENCE_SCHEMA_VERSION,
                    CURRENT_MANIFEST_SCHEMA_VERSION,
                ],
                "status": "complete",
            },
            "packets_csv_minimum_semantically_valid_data_rows": 1,
            "events_jsonl_minimum_semantically_valid_events": 1,
        },
    }

    assert policy["x-manifest-artifact-contracts"] == {
        "1.0.0": {
            "packet_schema_version": "1.0.0",
            "event_schema_version": "1.0.0",
        },
        "1.1.0": {
            "packet_schema_version": STRICT_PACKET_EVENT_SCHEMA_VERSION,
            "event_schema_version": STRICT_PACKET_EVENT_SCHEMA_VERSION,
        },
        "1.2.0": {
            "packet_schema_version": STRICT_PACKET_EVENT_SCHEMA_VERSION,
            "event_schema_version": STRICT_PACKET_EVENT_SCHEMA_VERSION,
        },
    }
    assert policy["x-core-text-contract"] == {
        "manifest_schema_versions": [
            STRICT_PACKET_EVENT_SCHEMA_VERSION,
            CURRENT_MANIFEST_SCHEMA_VERSION,
        ],
        "packet_event_schema_version": STRICT_PACKET_EVENT_SCHEMA_VERSION,
        "artifacts": ["packets.csv", "events.jsonl", "manifest.json", "SHA256SUMS"],
        "line_separator": "LF",
        "terminal_lf_required_when_nonempty": True,
    }


def test_packet_schema_matches_runtime_bounds_and_cross_field_contract():
    schema = load_schema("packet.schema.json")

    assert set(schema["required"]) == {
        "sequence",
        "path_id",
        "sent_ns",
        "received_ns",
        "status",
        "rtt_ms",
        "datagram_bytes",
    }
    assert schema["properties"]["sequence"]["maximum"] == UINT64_MAX
    assert schema["properties"]["sent_ns"]["maximum"] == UINT64_MAX
    assert schema["properties"]["received_ns"]["maximum"] == UINT64_MAX
    assert schema["properties"]["datagram_bytes"]["maximum"] == MAX_DATAGRAM_BYTES
    assert {condition["if"]["properties"]["status"]["const"] for condition in schema["allOf"]} == {
        "received",
        "timeout",
    }
    assert schema["x-runtime-validator"] == {
        "required": True,
        "python_entrypoint": "adaptive_vpn.collector.validate_evidence_bundle",
        "invocation_scope": "containing-evidence-bundle",
        "acceptance_condition": "result.valid == true",
        "json_schema_scope": "artifact-structure-only",
        "json_schema_alone_is_sufficient": False,
    }
    assert schema["x-invariants"] == {
        "enforcement": "runtime-required",
        "standard_json_schema_enforces": False,
        "rules": [
            {
                "id": "received-time-order",
                "when": {"status": "received"},
                "expression": "received_ns >= sent_ns",
            },
            {
                "id": "exact-rtt",
                "when": {"status": "received"},
                "expression": "rtt_ms == (received_ns - sent_ns) / 1000000",
            },
        ],
    }


def test_event_schemas_publish_raw_and_canonical_ascii_line_limits():
    expected_limits = {
        "maximum_raw_utf8_jsonl_line_bytes_including_newline": MAX_JSON_BYTES,
        "maximum_canonical_ascii_jsonl_line_bytes_including_newline": (
            MAX_JSON_BYTES
        ),
        "canonical_ascii_serialization": {
            "sort_keys": True,
            "ensure_ascii": True,
            "allow_nan": False,
            "terminal_lf": True,
        },
        "maximum_json_depth": 32,
        "maximum_json_nodes": 10_000,
    }

    assert load_schema("event.schema.json")["x-resource-limits"] == expected_limits
    assert load_schema("event-v1.0.schema.json")["x-resource-limits"] == (
        expected_limits
    )


def test_legacy_non_ascii_event_can_fit_raw_limit_but_exceed_canonical_limit():
    event = {"event": "é" * 200_000}
    raw = (json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8")
    canonical = (
        json.dumps(event, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
    ).encode("utf-8")

    assert len(raw) <= MAX_JSON_BYTES
    assert len(canonical) > MAX_JSON_BYTES
    with pytest.raises(ValueError, match="event exceeds"):
        _validate_event(event, strict=False)


def test_packet_and_event_schemas_publish_current_and_legacy_contracts():
    packet_current = load_schema("packet.schema.json")
    event_current = load_schema("event.schema.json")
    packet_legacy_path = ROOT / "schemas" / "packet-v1.0.schema.json"
    event_legacy_path = ROOT / "schemas" / "event-v1.0.schema.json"
    assert packet_legacy_path.is_file()
    assert event_legacy_path.is_file()
    packet_legacy = json.loads(packet_legacy_path.read_text(encoding="utf-8"))
    event_legacy = json.loads(event_legacy_path.read_text(encoding="utf-8"))

    assert packet_current["x-evidence-schema-version"] == EVIDENCE_SCHEMA_VERSION
    assert event_current["x-evidence-schema-version"] == EVIDENCE_SCHEMA_VERSION
    assert packet_legacy["x-evidence-schema-version"] == LEGACY_EVIDENCE_SCHEMA_VERSION
    assert event_legacy["x-evidence-schema-version"] == LEGACY_EVIDENCE_SCHEMA_VERSION
    assert "maximum" not in packet_legacy["properties"]["sequence"]
    assert "maximum" not in packet_legacy["properties"]["sent_ns"]
    assert "allOf" not in packet_legacy
    assert event_legacy["properties"]["event"] == {
        "type": "string",
        "minLength": 1,
    }
