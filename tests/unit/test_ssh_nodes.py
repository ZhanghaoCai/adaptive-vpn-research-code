from pathlib import Path

from scripts.field_probe.node_config import Node
from scripts.field_probe.ssh_nodes import connection_options


def test_ssh_options_require_pinned_host_keys(monkeypatch, tmp_path):
    key = tmp_path / "identity"
    known_hosts = tmp_path / "known_hosts"
    key.write_text("fixture", encoding="ascii")
    known_hosts.write_text("fixture", encoding="ascii")
    monkeypatch.setenv("AVPN_KNOWN_HOSTS", str(known_hosts))
    node = Node(
        alias="edge-a",
        host="192.0.2.10",
        location="",
        region="",
        ssh_user="admin",
        identity_file=Path(key),
        roles=frozenset({"server"}),
    )

    options = connection_options(node)

    assert "StrictHostKeyChecking=yes" in options
    assert "StrictHostKeyChecking=no" not in options
    assert f"UserKnownHostsFile={known_hosts}" in options
