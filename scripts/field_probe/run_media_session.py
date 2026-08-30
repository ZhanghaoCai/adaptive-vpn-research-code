#!/usr/bin/env python3
"""Run one direct or relayed UDP media session using local node configuration."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from scripts.field_probe.node_config import Node, load_nodes
from scripts.field_probe.ssh_nodes import copy_to, run_ssh


ROOT = Path(__file__).resolve().parents[2]
MEDIA = ROOT / "scripts" / "field_probe" / "media_sim.py"


def parse_result(output: str) -> dict[str, object] | None:
    for line in output.splitlines():
        if line.startswith("RESULT "):
            value = json.loads(line[7:])
            return value if isinstance(value, dict) else None
    return None


def upload(nodes: list[Node]) -> None:
    for node in nodes:
        result = copy_to(node, MEDIA, "/tmp/avpn_media_sim.py")
        if result.returncode != 0:
            raise RuntimeError(f"upload failed for {node.alias}: {result.stderr.strip()}")


def start_receiver(node: Node, port: int, duration: float, label: str) -> None:
    result = run_ssh(
        node,
        f"nohup python3 /tmp/avpn_media_sim.py recv {port} {duration + 10} "
        f"> /tmp/avpn_{label}.out 2>&1 < /dev/null &",
    )
    if result.returncode != 0:
        raise RuntimeError(f"receiver failed for {node.alias}: {result.stderr.strip()}")


def send(sender: Node | None, host: str, port: int, rate: int, duration: float) -> None:
    command = [
        sys.executable,
        str(MEDIA),
        "send",
        host,
        str(port),
        str(rate),
        str(duration),
    ]
    if sender is None:
        subprocess.run(command, timeout=duration + 40, check=True)
        return
    result = run_ssh(
        sender,
        f"python3 /tmp/avpn_media_sim.py send {host} {port} {rate} {duration}",
        timeout=duration + 40,
    )
    if result.returncode != 0:
        raise RuntimeError(f"sender failed for {sender.alias}: {result.stderr.strip()}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", type=Path, help="local node inventory JSON")
    parser.add_argument("--sender", default="CLIENT", help="CLIENT or a server alias")
    parser.add_argument("--receiver", required=True, help="server alias")
    parser.add_argument("--relay", help="optional relay server alias")
    parser.add_argument("--profile", choices=("audio", "video"), default="audio")
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--port", type=int, default=29300)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    nodes = load_nodes(args.nodes)
    for alias in (args.receiver, args.relay):
        if alias and alias not in nodes:
            raise SystemExit(f"unknown node alias: {alias}")
    if args.sender != "CLIENT" and args.sender not in nodes:
        raise SystemExit(f"unknown node alias: {args.sender}")
    receiver = nodes[args.receiver]
    relay = nodes[args.relay] if args.relay else None
    sender = None if args.sender == "CLIENT" else nodes[args.sender]
    upload([node for node in (receiver, relay, sender) if node is not None])

    rate = 64 if args.profile == "audio" else 512
    label = f"session_{args.port}"
    start_receiver(receiver, args.port + (1000 if relay else 0), args.duration, label)
    time.sleep(1)
    destination_host = receiver.host
    destination_port = args.port
    if relay:
        receive_port = args.port + 1000
        result = run_ssh(
            relay,
            f"nohup python3 /tmp/avpn_media_sim.py relay {args.port} "
            f"{receiver.host} {receive_port} > /tmp/avpn_{label}_relay.out 2>&1 < /dev/null &",
        )
        if result.returncode != 0:
            raise RuntimeError(f"relay failed for {relay.alias}: {result.stderr.strip()}")
        destination_host = relay.host
    send(sender, destination_host, destination_port, rate, args.duration)
    time.sleep(6)
    result = run_ssh(receiver, f"cat /tmp/avpn_{label}.out")
    record = parse_result(result.stdout)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(record, sort_keys=True))
    return 0 if record is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
