"""Bounded Linux namespace and WireGuard testbed management."""

from __future__ import annotations

import math
import os
import re
import signal
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


RESOURCE_PREFIX = "avpn-"
CLIENT_NAMESPACE = "avpn-client"
SERVER_NAMESPACE = "avpn-server"
_RESOURCE_NAME = re.compile(r"avpn-[a-z0-9]+\Z")


@dataclass(frozen=True, slots=True)
class LabPath:
    """Names and addresses for one isolated WireGuard path."""

    path_id: str
    client_underlay_if: str
    server_underlay_if: str
    wireguard_if: str
    client_underlay_cidr: str
    server_underlay_cidr: str
    client_overlay_cidr: str
    server_overlay_cidr: str
    listen_port: int

    @property
    def client_underlay_ip(self) -> str:
        return self.client_underlay_cidr.partition("/")[0]

    @property
    def server_underlay_ip(self) -> str:
        return self.server_underlay_cidr.partition("/")[0]

    @property
    def client_overlay_ip(self) -> str:
        return self.client_overlay_cidr.partition("/")[0]

    @property
    def server_overlay_ip(self) -> str:
        return self.server_overlay_cidr.partition("/")[0]


LAB_PATHS = (
    LabPath(
        "a",
        "avpn-ca",
        "avpn-sa",
        "avpn-wga",
        "10.200.0.1/30",
        "10.200.0.2/30",
        "10.210.0.1/30",
        "10.210.0.2/30",
        51_821,
    ),
    LabPath(
        "b",
        "avpn-cb",
        "avpn-sb",
        "avpn-wgb",
        "10.200.0.5/30",
        "10.200.0.6/30",
        "10.210.0.5/30",
        "10.210.0.6/30",
        51_822,
    ),
    LabPath(
        "c",
        "avpn-cc",
        "avpn-sc",
        "avpn-wgc",
        "10.200.0.9/30",
        "10.200.0.10/30",
        "10.210.0.9/30",
        "10.210.0.10/30",
        51_823,
    ),
)

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def _require_resource_name(name: str) -> None:
    if len(name) > 15 or _RESOURCE_NAME.fullmatch(name) is None:
        raise ValueError(
            f"resource name must use the {RESOURCE_PREFIX!r} prefix and safe characters"
        )


def _require_impairment(name: str, value: float, *, maximum: float | None = None) -> None:
    if not math.isfinite(value) or value < 0 or (maximum is not None and value > maximum):
        suffix = f" and at most {maximum}" if maximum is not None else ""
        raise ValueError(f"{name} must be finite, non-negative{suffix}")


def _format_number(value: float) -> str:
    return f"{value:.6f}".rstrip("0").rstrip(".") or "0"


class WireGuardLab:
    """Create and remove only the fixed ``avpn-*`` research topology."""

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        runtime_dir: Path | str = Path("/run/avpn-lab"),
    ) -> None:
        self._runner = runner or subprocess.run
        self.runtime_dir = Path(runtime_dir)
        if not self.runtime_dir.name.startswith(RESOURCE_PREFIX):
            raise ValueError("runtime directory name must use the 'avpn-' prefix")
        self.paths = LAB_PATHS
        for name in self.resource_names:
            _require_resource_name(name)

    @property
    def resource_names(self) -> tuple[str, ...]:
        path_names = tuple(
            name
            for path in self.paths
            for name in (
                path.client_underlay_if,
                path.server_underlay_if,
                path.wireguard_if,
            )
        )
        return (CLIENT_NAMESPACE, SERVER_NAMESPACE, *path_names)

    @property
    def key_files(self) -> tuple[Path, ...]:
        return tuple(
            self.runtime_dir / f"{path.wireguard_if}-{side}.key"
            for path in self.paths
            for side in ("client", "server")
        )

    def path(self, path_id: str) -> LabPath:
        if path_id.startswith("path-"):
            path_id = path_id.removeprefix("path-")
        for path in self.paths:
            if path.path_id == path_id:
                return path
        raise ValueError(f"unknown lab path {path_id!r}; expected a, b, or c")

    def assert_clean(self) -> None:
        """Fail without mutation when a previous bounded lab residue exists."""

        namespace_state = self._run("ip", "netns", "list", check=False).stdout
        link_state = self._run("ip", "-o", "link", "show", check=False).stdout
        residues = [
            name
            for name in self.resource_names
            if name in namespace_state or name in link_state
        ]
        residues.extend(str(path) for path in self.key_files if path.exists())
        if residues:
            raise RuntimeError(
                "bounded WireGuard lab is not clean: " + ", ".join(sorted(residues))
            )

    def _run(
        self,
        *command: str,
        check: bool = True,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        kwargs: dict[str, Any] = {
            "check": check,
            "capture_output": True,
            "text": True,
        }
        if input_text is not None:
            kwargs["input"] = input_text
        return self._runner(tuple(command), **kwargs)

    def _prepare_keys(self) -> dict[tuple[str, str], str]:
        self.runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.runtime_dir, 0o700)
        public_keys: dict[tuple[str, str], str] = {}
        for path in self.paths:
            for side in ("client", "server"):
                private_key = self._run("wg", "genkey").stdout.strip()
                if not private_key:
                    raise RuntimeError("wg genkey returned an empty private key")
                public_key = self._run(
                    "wg", "pubkey", input_text=f"{private_key}\n"
                ).stdout.strip()
                if not public_key:
                    raise RuntimeError("wg pubkey returned an empty public key")
                key_file = self.runtime_dir / f"{path.wireguard_if}-{side}.key"
                key_file.write_text(f"{private_key}\n", encoding="ascii")
                os.chmod(key_file, 0o600)
                public_keys[(path.path_id, side)] = public_key
        return public_keys

    def setup(self) -> None:
        """Idempotently create the two namespaces and three tunnel paths."""
        self.cleanup()
        try:
            public_keys = self._prepare_keys()
            self._run("ip", "netns", "add", CLIENT_NAMESPACE)
            self._run("ip", "netns", "add", SERVER_NAMESPACE)
            for namespace in (CLIENT_NAMESPACE, SERVER_NAMESPACE):
                self._run("ip", "-n", namespace, "link", "set", "lo", "up")
            for path in self.paths:
                self._setup_underlay(path)
                self._setup_wireguard(path, public_keys)
                self.impair(path.path_id, rtt_ms=0.0)
        except Exception:
            self.cleanup()
            raise

    def _setup_underlay(self, path: LabPath) -> None:
        self._run(
            "ip",
            "link",
            "add",
            path.client_underlay_if,
            "type",
            "veth",
            "peer",
            "name",
            path.server_underlay_if,
        )
        self._run(
            "ip", "link", "set", path.client_underlay_if, "netns", CLIENT_NAMESPACE
        )
        self._run(
            "ip", "link", "set", path.server_underlay_if, "netns", SERVER_NAMESPACE
        )
        self._run(
            "ip",
            "-n",
            CLIENT_NAMESPACE,
            "address",
            "add",
            path.client_underlay_cidr,
            "dev",
            path.client_underlay_if,
        )
        self._run(
            "ip",
            "-n",
            SERVER_NAMESPACE,
            "address",
            "add",
            path.server_underlay_cidr,
            "dev",
            path.server_underlay_if,
        )
        self._run(
            "ip", "-n", CLIENT_NAMESPACE, "link", "set", path.client_underlay_if, "up"
        )
        self._run(
            "ip", "-n", SERVER_NAMESPACE, "link", "set", path.server_underlay_if, "up"
        )

    def _setup_wireguard(
        self,
        path: LabPath,
        public_keys: dict[tuple[str, str], str],
    ) -> None:
        for namespace, overlay_cidr in (
            (CLIENT_NAMESPACE, path.client_overlay_cidr),
            (SERVER_NAMESPACE, path.server_overlay_cidr),
        ):
            self._run(
                "ip", "-n", namespace, "link", "add", path.wireguard_if, "type", "wireguard"
            )
            self._run(
                "ip",
                "-n",
                namespace,
                "address",
                "add",
                overlay_cidr,
                "dev",
                path.wireguard_if,
            )

        client_key = self.runtime_dir / f"{path.wireguard_if}-client.key"
        server_key = self.runtime_dir / f"{path.wireguard_if}-server.key"
        self._configure_peer(
            namespace=CLIENT_NAMESPACE,
            path=path,
            private_key=client_key,
            peer_public_key=public_keys[(path.path_id, "server")],
            peer_overlay_ip=path.server_overlay_ip,
            endpoint_ip=path.server_underlay_ip,
        )
        self._configure_peer(
            namespace=SERVER_NAMESPACE,
            path=path,
            private_key=server_key,
            peer_public_key=public_keys[(path.path_id, "client")],
            peer_overlay_ip=path.client_overlay_ip,
            endpoint_ip=path.client_underlay_ip,
        )
        for namespace, peer_overlay_ip in (
            (CLIENT_NAMESPACE, path.server_overlay_ip),
            (SERVER_NAMESPACE, path.client_overlay_ip),
        ):
            self._run(
                "ip", "-n", namespace, "link", "set", path.wireguard_if, "up"
            )
            self._run(
                "ip",
                "-n",
                namespace,
                "route",
                "replace",
                f"{peer_overlay_ip}/32",
                "dev",
                path.wireguard_if,
            )

    def _configure_peer(
        self,
        *,
        namespace: str,
        path: LabPath,
        private_key: Path,
        peer_public_key: str,
        peer_overlay_ip: str,
        endpoint_ip: str,
    ) -> None:
        self._run(
            "ip",
            "netns",
            "exec",
            namespace,
            "wg",
            "set",
            path.wireguard_if,
            "private-key",
            str(private_key),
            "listen-port",
            str(path.listen_port),
            "peer",
            peer_public_key,
            "allowed-ips",
            f"{peer_overlay_ip}/32",
            "endpoint",
            f"{endpoint_ip}:{path.listen_port}",
            "persistent-keepalive",
            "1",
        )

    def impair(
        self,
        path_id: str,
        *,
        rtt_ms: float | None = None,
        delay_ms: float | None = None,
        jitter_ms: float = 0.0,
        loss_pct: float = 0.0,
        loss_correlation_pct: float = 0.0,
        rate_mbit: float | None = None,
    ) -> None:
        """Apply a symmetric impairment to one underlay and no other path."""
        path = self.path(path_id)
        if (rtt_ms is None) == (delay_ms is None):
            raise ValueError("provide exactly one of rtt_ms or delay_ms")
        registered_delay_ms = delay_ms if delay_ms is not None else rtt_ms
        assert registered_delay_ms is not None
        _require_impairment("delay_ms", registered_delay_ms)
        _require_impairment("jitter_ms", jitter_ms)
        _require_impairment("loss_pct", loss_pct, maximum=100.0)
        _require_impairment(
            "loss_correlation_pct", loss_correlation_pct, maximum=100.0
        )
        if loss_correlation_pct and not loss_pct:
            raise ValueError("loss correlation requires a nonzero loss percentage")
        if rate_mbit is not None:
            if not math.isfinite(rate_mbit) or rate_mbit <= 0:
                raise ValueError("rate_mbit must be finite and greater than zero")
        one_way_delay = registered_delay_ms / 2.0
        one_way_jitter = jitter_ms / 2.0
        one_way_loss = (1.0 - math.sqrt(1.0 - loss_pct / 100.0)) * 100.0

        netem = ["root", "netem", "delay", f"{_format_number(one_way_delay)}ms"]
        if one_way_jitter:
            netem.extend((f"{_format_number(one_way_jitter)}ms", "distribution", "normal"))
        if one_way_loss:
            netem.extend(("loss", f"{_format_number(one_way_loss)}%"))
            if loss_correlation_pct:
                netem.append(f"{_format_number(loss_correlation_pct)}%")
        if rate_mbit is not None:
            netem.extend(("rate", f"{_format_number(rate_mbit)}mbit"))
        for namespace, interface in (
            (CLIENT_NAMESPACE, path.client_underlay_if),
            (SERVER_NAMESPACE, path.server_underlay_if),
        ):
            self._run(
                "ip",
                "netns",
                "exec",
                namespace,
                "tc",
                "qdisc",
                "replace",
                "dev",
                interface,
                *netem,
            )

    def status(self) -> dict[str, dict[str, str]]:
        """Capture links, routes, qdiscs, and handshakes in each namespace."""
        commands: dict[str, tuple[str, ...]] = {
            "links": ("ip", "-details", "-statistics", "link", "show"),
            "routes": ("ip", "route", "show", "table", "all"),
            "qdiscs": ("tc", "-details", "qdisc", "show"),
            "wireguard": ("wg", "show", "all"),
        }
        result: dict[str, dict[str, str]] = {}
        for namespace in (CLIENT_NAMESPACE, SERVER_NAMESPACE):
            result[namespace] = {
                label: self._run(
                    "ip",
                    "netns",
                    "exec",
                    namespace,
                    *command,
                    check=False,
                ).stdout
                for label, command in commands.items()
            }
        return result

    def cleanup(self, *, namespaces: Sequence[str] | None = None) -> None:
        """Remove bounded namespaces and orphan links; reject all other names."""
        targets = tuple(namespaces) if namespaces is not None else (
            CLIENT_NAMESPACE,
            SERVER_NAMESPACE,
        )
        for namespace in targets:
            _require_resource_name(namespace)
        for namespace in targets:
            self._stop_namespace_processes(namespace)
        for namespace in targets:
            self._run("ip", "netns", "delete", namespace, check=False)

        if namespaces is None:
            for path in self.paths:
                for interface in (path.client_underlay_if, path.server_underlay_if):
                    _require_resource_name(interface)
                    self._run("ip", "link", "delete", interface, check=False)
            for key_file in self.key_files:
                try:
                    key_file.unlink(missing_ok=True)
                except IsADirectoryError:
                    pass
            try:
                self.runtime_dir.rmdir()
            except OSError:
                pass

    def _stop_namespace_processes(self, namespace: str) -> None:
        """Terminate only processes reported inside one validated lab namespace."""
        _require_resource_name(namespace)
        result = self._run("ip", "netns", "pids", namespace, check=False)
        pids = tuple(int(token) for token in result.stdout.split() if token.isdecimal())
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

        deadline = time.monotonic() + 1.0
        remaining = set(pids)
        while remaining and time.monotonic() < deadline:
            for pid in tuple(remaining):
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    remaining.remove(pid)
            if remaining:
                time.sleep(0.02)
        for pid in remaining:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
