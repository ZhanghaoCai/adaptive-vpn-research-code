"""Validated UDP echo service used inside the experiment server namespace."""

from __future__ import annotations

import argparse
import signal
import socket
import threading
from collections.abc import Sequence
from typing import Self

from adaptive_vpn.protocol import decode_packet


class UDPEchoServer:
    """Echo only datagrams that conform to the experiment probe protocol."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        address_family: int = socket.AF_INET,
    ) -> None:
        if not 0 <= port <= 65_535:
            raise ValueError("port must be between 0 and 65535")
        if address_family not in {socket.AF_INET, socket.AF_INET6}:
            raise ValueError("address_family must be AF_INET or AF_INET6")
        self.host = host
        self.requested_port = port
        self.address_family = address_family
        self.invalid_datagrams = 0
        self.echoed_datagrams = 0
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    @property
    def port(self) -> int:
        if self._socket is None:
            raise RuntimeError("echo server is not running")
        return int(self._socket.getsockname()[1])

    def start(self) -> UDPEchoServer:
        if self._socket is not None:
            raise RuntimeError("echo server is already running")
        sock = socket.socket(self.address_family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_address = (
            (self.host, self.requested_port, 0, 0)
            if self.address_family == socket.AF_INET6
            else (self.host, self.requested_port)
        )
        sock.bind(bind_address)
        sock.settimeout(0.1)
        self._socket = sock
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._serve, name="avpn-echo", daemon=True)
        self._thread.start()
        return self

    def _serve(self) -> None:
        assert self._socket is not None
        while not self._stop_event.is_set():
            try:
                data, address = self._socket.recvfrom(65_535)
            except TimeoutError:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                raise
            try:
                decode_packet(data)
            except ValueError:
                self.invalid_datagrams += 1
                continue
            self._socket.sendto(data, address)
            self.echoed_datagrams += 1

    def stop(self) -> None:
        if self._socket is None:
            return
        self._stop_event.set()
        self._socket.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._thread = None
        self._socket = None

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.stop()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Adaptive VPN UDP echo service")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--family", choices=("4", "6"), default="4")
    args = parser.parse_args(argv)

    stopped = threading.Event()

    def handle_signal(signum, frame) -> None:
        stopped.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    with UDPEchoServer(
        host=args.host,
        port=args.port,
        address_family=socket.AF_INET6 if args.family == "6" else socket.AF_INET,
    ):
        stopped.wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
