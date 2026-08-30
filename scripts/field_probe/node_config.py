"""Load a local-only node inventory for field and media probes."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / "config" / "nodes.local.json"
ALIAS_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
ALLOWED_FIELDS = {
    "host",
    "location",
    "region",
    "ssh_user",
    "identity_file",
    "roles",
}
ALLOWED_ROLES = {"client", "server", "relay", "sfu"}


class NodeConfigError(ValueError):
    """Raised when the local node inventory is unsafe or malformed."""


@dataclass(frozen=True)
class Node:
    alias: str
    host: str
    location: str
    region: str
    ssh_user: str
    identity_file: Path | None
    roles: frozenset[str]

    @property
    def ssh_target(self) -> str:
        if not self.ssh_user:
            raise NodeConfigError(f"node {self.alias!r} has no SSH user")
        return f"{self.ssh_user}@{self.host}"

    def require_identity_file(self) -> Path:
        if self.identity_file is None:
            raise NodeConfigError(f"node {self.alias!r} has no identity file")
        if not self.identity_file.is_file():
            raise NodeConfigError(
                f"identity file for node {self.alias!r} does not exist: "
                f"{self.identity_file}"
            )
        return self.identity_file


def configured_path(path: str | Path | None = None) -> Path:
    if path is not None:
        return Path(path).expanduser()
    return Path(os.environ.get("AVPN_NODES_FILE", DEFAULT_CONFIG)).expanduser()


def known_hosts_path() -> Path:
    return Path(
        os.environ.get("AVPN_KNOWN_HOSTS", "~/.ssh/known_hosts")
    ).expanduser()


def _text(value: Any, label: str, *, required: bool = True) -> str:
    if not isinstance(value, str):
        raise NodeConfigError(f"{label} must be a string")
    result = value.strip()
    if required and not result:
        raise NodeConfigError(f"{label} must not be empty")
    return result


def _host(value: Any, label: str) -> str:
    host = _text(value, label)
    if any(character in host for character in ("/", "@", ":", " ")):
        raise NodeConfigError(f"{label} must contain only a host name or IPv4 address")
    if not HOST_RE.fullmatch(host):
        raise NodeConfigError(f"{label} is not a valid host name or IPv4 address")
    return host


def load_nodes(path: str | Path | None = None) -> dict[str, Node]:
    config_path = configured_path(path)
    if not config_path.is_file():
        raise NodeConfigError(
            f"node inventory not found: {config_path}; copy config/nodes.example.json "
            "to config/nodes.local.json and fill it locally"
        )
    try:
        document = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NodeConfigError(f"cannot read node inventory {config_path}: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {"nodes"}:
        raise NodeConfigError("node inventory must contain only a top-level 'nodes' object")
    raw_nodes = document["nodes"]
    if not isinstance(raw_nodes, dict) or not raw_nodes:
        raise NodeConfigError("node inventory must define at least one node")

    nodes: dict[str, Node] = {}
    seen_hosts: set[str] = set()
    for raw_alias, value in raw_nodes.items():
        alias = _text(raw_alias, "node alias")
        if not ALIAS_RE.fullmatch(alias):
            raise NodeConfigError(f"invalid node alias: {alias!r}")
        if not isinstance(value, dict):
            raise NodeConfigError(f"node {alias!r} must be an object")
        unexpected = set(value) - ALLOWED_FIELDS
        if unexpected:
            raise NodeConfigError(
                f"node {alias!r} contains unsupported fields: "
                + ", ".join(sorted(unexpected))
            )
        host = _host(value.get("host"), f"node {alias!r} host")
        if host in seen_hosts:
            raise NodeConfigError(f"duplicate node host: {host}")
        seen_hosts.add(host)
        raw_roles = value.get("roles")
        if not isinstance(raw_roles, list) or not raw_roles:
            raise NodeConfigError(f"node {alias!r} roles must be a non-empty list")
        roles = frozenset(_text(role, f"node {alias!r} role") for role in raw_roles)
        if not roles <= ALLOWED_ROLES:
            raise NodeConfigError(
                f"node {alias!r} has unsupported roles: "
                + ", ".join(sorted(roles - ALLOWED_ROLES))
            )
        identity_text = _text(
            value.get("identity_file", ""),
            f"node {alias!r} identity_file",
            required=False,
        )
        identity_file = Path(identity_text).expanduser() if identity_text else None
        nodes[alias] = Node(
            alias=alias,
            host=host,
            location=_text(value.get("location", ""), f"node {alias!r} location", required=False),
            region=_text(value.get("region", ""), f"node {alias!r} region", required=False),
            ssh_user=_text(value.get("ssh_user", ""), f"node {alias!r} ssh_user", required=False),
            identity_file=identity_file,
            roles=roles,
        )
    return nodes


def server_nodes(nodes: dict[str, Node]) -> list[Node]:
    result = [node for node in nodes.values() if "server" in node.roles]
    if not result:
        raise NodeConfigError("node inventory contains no server-role nodes")
    return result
