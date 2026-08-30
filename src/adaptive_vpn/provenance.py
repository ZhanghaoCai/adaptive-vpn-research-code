"""Hashing and secret-boundary helpers for experiment provenance."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

FORBIDDEN_SECRET_KEYS = frozenset(
    {
    "private_key",
    "password",
    "access_token",
    "auth_token",
    "api_secret",
    "client_secret",
    "credential",
    "credentials",
    }
)
FORBIDDEN_SECRET_KEY_SUFFIXES = ("_credential",)


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of a file without loading it into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    """Hash JSON-compatible data using a deterministic representation."""
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def ensure_no_secrets(value: Any, *, location: str = "manifest") -> None:
    """Reject secret-bearing keys before provenance is persisted."""
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalised = str(key).strip().lower().replace("-", "_")
            if normalised in FORBIDDEN_SECRET_KEYS or normalised.endswith(
                FORBIDDEN_SECRET_KEY_SUFFIXES
            ):
                raise ValueError(f"secret-bearing key at {location}.{key}")
            ensure_no_secrets(child, location=f"{location}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            ensure_no_secrets(child, location=f"{location}[{index}]")
