import json
from pathlib import Path

import pytest

from scripts.field_probe.node_config import NodeConfigError, load_nodes, server_nodes


ROOT = Path(__file__).resolve().parents[2]


def test_example_inventory_uses_documentation_addresses_only():
    nodes = load_nodes(ROOT / "config" / "nodes.example.json")

    assert [node.alias for node in server_nodes(nodes)] == ["edge-a", "edge-b"]
    assert {node.host for node in nodes.values()} == {
        "192.0.2.10",
        "198.51.100.20",
        "203.0.113.30",
    }


def test_inventory_rejects_secret_or_unknown_fields(tmp_path):
    path = tmp_path / "nodes.json"
    path.write_text(
        json.dumps(
            {
                "nodes": {
                    "edge-a": {
                        "host": "192.0.2.10",
                        "roles": ["server"],
                        "password": "not-accepted",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(NodeConfigError, match="unsupported fields"):
        load_nodes(path)


@pytest.mark.parametrize("host", ["admin@example.test", "https://example.test", "host:22"])
def test_inventory_rejects_hosts_with_embedded_connection_syntax(tmp_path, host):
    path = tmp_path / "nodes.json"
    path.write_text(
        json.dumps({"nodes": {"edge-a": {"host": host, "roles": ["server"]}}}),
        encoding="utf-8",
    )

    with pytest.raises(NodeConfigError, match="host name or IPv4 address"):
        load_nodes(path)
