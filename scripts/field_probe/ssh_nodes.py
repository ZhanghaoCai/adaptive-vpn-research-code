"""SSH helpers that require a local identity file and pinned host key."""

from __future__ import annotations

import subprocess
from pathlib import Path

from scripts.field_probe.node_config import Node, NodeConfigError, known_hosts_path


def connection_options(node: Node) -> list[str]:
    identity = node.require_identity_file()
    known_hosts = known_hosts_path()
    if not known_hosts.is_file():
        raise NodeConfigError(f"known-hosts file does not exist: {known_hosts}")
    return [
        "-i",
        str(identity),
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "ServerAliveInterval=10",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "BatchMode=yes",
    ]


def run_ssh(node: Node, command: str, *, timeout: float = 150) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["ssh", *connection_options(node), node.ssh_target, command],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def copy_to(node: Node, source: Path, destination: str, *, timeout: float = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["scp", *connection_options(node), str(source), f"{node.ssh_target}:{destination}"],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
