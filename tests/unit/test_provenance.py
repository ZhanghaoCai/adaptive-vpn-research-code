import json

import pytest

from adaptive_vpn.provenance import canonical_sha256
from adaptive_vpn.provenance import ensure_no_secrets
from adaptive_vpn.provenance import sha256_file


def test_canonical_hash_is_key_order_independent():
    first = canonical_sha256({"b": 2, "a": {"z": 1, "y": 2}})
    second = canonical_sha256({"a": {"y": 2, "z": 1}, "b": 2})
    assert first == second
    assert len(first) == 64


def test_file_hash_matches_known_sha256(tmp_path):
    path = tmp_path / "value.txt"
    path.write_bytes(b"abc")
    assert sha256_file(path) == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


@pytest.mark.parametrize(
    "secret_key",
    ("private_key", "password", "access_token", "api-secret", "credential"),
)
def test_manifest_rejects_secret_bearing_keys_at_any_depth(secret_key):
    with pytest.raises(ValueError, match="secret-bearing"):
        ensure_no_secrets({"safe": {secret_key: "not-for-a-manifest"}})


def test_manifest_allows_non_secret_hash_and_public_key_metadata():
    value = {
        "config_sha256": "0" * 64,
        "wireguard_public_keys": ["public-a", "public-b"],
    }
    ensure_no_secrets(value)
    assert json.loads(json.dumps(value)) == value
