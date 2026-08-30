#!/usr/bin/env python3
"""Run directed UDP media legs over an authorised local node inventory."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from scripts.field_probe.node_config import Node, load_nodes, server_nodes
from scripts.field_probe.ssh_nodes import copy_to, run_ssh


ROOT = Path(__file__).resolve().parents[2]
MEDIA = ROOT / "scripts" / "field_probe" / "media_sim.py"
RECEIVER_GRACE_S = 60.0


def upload_media_sim(nodes: list[Node]) -> None:
    for node in nodes:
        result = copy_to(node, MEDIA, "/tmp/avpn_media_sim.py")
        if result.returncode != 0:
            raise RuntimeError(f"upload failed for {node.alias}: {result.stderr.strip()}")
        print(f"uploaded media_sim.py -> {node.alias}", flush=True)


def parse_result(output: str) -> dict[str, object] | None:
    for line in output.splitlines():
        if line.startswith("RESULT "):
            value = json.loads(line[7:])
            return value if isinstance(value, dict) else None
    return None


def start_receiver(node: Node, label: str, port: int, window: float) -> None:
    command = (
        f"nohup python3 /tmp/avpn_media_sim.py recv {port} {window} "
        f"> /tmp/avpn_{label}.out 2>&1 < /dev/null &"
    )
    last_error = ""
    for _ in range(3):
        try:
            result = run_ssh(node, command, timeout=40)
            if result.returncode == 0:
                return
            last_error = result.stderr.strip()
        except subprocess.TimeoutExpired as exc:
            last_error = str(exc)
        time.sleep(3)
    raise RuntimeError(f"receiver start failed for {node.alias}: {last_error}")


def wait_for(node: Node, label: str, marker: str, window: float) -> str:
    iterations = max(1, int(window / 2))
    command = (
        f"for i in $(seq 1 {iterations}); do "
        f"grep -q '{marker}' /tmp/avpn_{label}.out 2>/dev/null && break; "
        "sleep 2; done; "
        f"cat /tmp/avpn_{label}.out"
    )
    result = run_ssh(node, command, timeout=window + 45)
    if result.returncode != 0:
        raise RuntimeError(f"receiver read failed for {node.alias}: {result.stderr.strip()}")
    return result.stdout


def run_leg(
    nodes: dict[str, Node],
    sender_alias: str,
    receiver_alias: str,
    port: int,
    kbps: int,
    duration: float,
) -> dict[str, object] | None:
    receiver = nodes[receiver_alias]
    label = f"{sender_alias}_{receiver_alias}_{kbps}_{port}".lower()
    window = duration + RECEIVER_GRACE_S
    start_receiver(receiver, label, port, window)
    wait_for(receiver, label, "LISTENING", 40)

    if sender_alias == "CLIENT":
        subprocess.run(
            [
                sys.executable,
                str(MEDIA),
                "send",
                receiver.host,
                str(port),
                str(kbps),
                str(duration),
            ],
            timeout=duration + 40,
            check=True,
        )
    else:
        sender = nodes[sender_alias]
        result = run_ssh(
            sender,
            f"python3 /tmp/avpn_media_sim.py send {receiver.host} {port} {kbps} {duration}",
            timeout=duration + RECEIVER_GRACE_S + 30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"sender failed for {sender.alias}: {result.stderr.strip()}")
    return parse_result(wait_for(receiver, label, "RESULT", window))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--nodes", type=Path, help="local node inventory JSON")
    parser.add_argument("--duration", type=float, default=20.0)
    parser.add_argument("--start-port", type=int, default=30000)
    args = parser.parse_args()
    if args.duration <= 0:
        parser.error("--duration must be positive")
    if not 1024 <= args.start_port <= 65000:
        parser.error("--start-port must be between 1024 and 65000")
    return args


def main() -> int:
    args = parse_args()
    inventory = load_nodes(args.nodes)
    servers = server_nodes(inventory)
    nodes = {node.alias: node for node in servers}
    aliases = list(nodes)
    pairs = [(left, right) for left in aliases for right in aliases if left != right]
    pairs.extend(("CLIENT", alias) for alias in aliases)
    args.output.parent.mkdir(parents=True, exist_ok=True)

    results: dict[str, dict[str, object | None]] = {}
    if args.output.exists():
        value = json.loads(args.output.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise SystemExit("existing output must be a JSON object")
        results = value

    upload_media_sim(servers)

    def checkpoint() -> None:
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        temporary.write_text(
            json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.replace(args.output)

    port = args.start_port
    for sender_alias, receiver_alias in pairs:
        pair_key = f"{sender_alias}->{receiver_alias}"
        entry = results.setdefault(pair_key, {})
        for label, rate in (("audio", 64), ("video", 512)):
            if entry.get(label) is not None:
                port += 1
                continue
            result = None
            for attempt in range(2):
                try:
                    result = run_leg(
                        nodes,
                        sender_alias,
                        receiver_alias,
                        port,
                        rate,
                        args.duration,
                    )
                except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    print(
                        f"{pair_key} {label} attempt {attempt + 1} failed: {exc}",
                        file=sys.stderr,
                        flush=True,
                    )
                    result = None
                if result and int(result.get("packets_received", 0)) > 0:
                    break
                port += 1
            entry[label] = result
            port += 1
            checkpoint()
            print(f"{pair_key} {label}: {json.dumps(result, sort_keys=True)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
