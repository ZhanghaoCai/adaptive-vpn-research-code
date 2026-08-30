"""Active real-packet UDP probe session."""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass
from types import TracebackType

from adaptive_vpn.protocol import (
    HEADER_SIZE,
    PacketLedger,
    PacketResult,
    ProbeMetrics,
    ProbePacket,
    calculate_probe_metrics,
    decode_packet,
    encode_packet,
)


@dataclass(frozen=True, slots=True)
class ProbeRunResult:
    rows: tuple[PacketResult, ...]
    metrics: ProbeMetrics
    attribution_errors: int
    duplicate_echoes: int


class UDPProbeSession:
    """Send a paced UDP stream and correlate echoes on a dedicated socket."""

    def __init__(
        self,
        *,
        target_host: str,
        target_port: int,
        run_token: int,
        path_index: int,
        packet_rate_hz: float,
        datagram_size: int,
        response_timeout_s: float,
        duplicate_drain_s: float = 0.05,
        bind_host: str | None = None,
        bind_device: str | None = None,
        address_family: int = socket.AF_INET,
    ) -> None:
        if not 0 < target_port <= 65_535:
            raise ValueError("target_port must be between 1 and 65535")
        if packet_rate_hz <= 0:
            raise ValueError("packet_rate_hz must be greater than zero")
        if not HEADER_SIZE <= datagram_size <= 65_507:
            raise ValueError("datagram_size must fit one complete UDP datagram")
        if response_timeout_s <= 0:
            raise ValueError("response_timeout_s must be greater than zero")
        if duplicate_drain_s <= 0:
            raise ValueError("duplicate_drain_s must be greater than zero")
        if address_family not in {socket.AF_INET, socket.AF_INET6}:
            raise ValueError("address_family must be AF_INET or AF_INET6")
        if bind_host is not None and not bind_host:
            raise ValueError("bind_host must be non-empty when provided")
        self.target = (target_host, target_port)
        self.run_token = run_token
        self.path_index = path_index
        self.packet_rate_hz = packet_rate_hz
        self.datagram_size = datagram_size
        self.response_timeout_s = response_timeout_s
        self.duplicate_drain_s = duplicate_drain_s
        self.bind_host = bind_host or (
            "::" if address_family == socket.AF_INET6 else "0.0.0.0"
        )
        self.bind_device = bind_device
        self.address_family = address_family

    def run_packets(self, packet_count: int) -> ProbeRunResult:
        if packet_count < 1:
            raise ValueError("packet_count must be at least 1")
        ledger = PacketLedger(run_token=self.run_token, path_index=self.path_index)
        resolved_target = socket.getaddrinfo(
            self.target[0],
            self.target[1],
            family=self.address_family,
            type=socket.SOCK_DGRAM,
        )[0][4]
        expected_endpoint = self._normalise_endpoint(resolved_target)
        stop_event = threading.Event()
        receiver_failed = threading.Event()
        receiver_entered = threading.Event()
        receiver_exited = threading.Event()
        receiver_errors: list[BaseException] = []
        sock: socket.socket | None = None
        receiver: threading.Thread | None = None
        receiver_start_attempted = False
        receiver_started = False

        def raise_receiver_failure() -> None:
            if receiver_failed.is_set():
                raise RuntimeError("probe receive loop failed") from receiver_errors[0]

        def receive_loop() -> None:
            assert sock is not None
            receiver_entered.set()
            try:
                while not stop_event.is_set():
                    try:
                        data, address = sock.recvfrom(65_535)
                    except TimeoutError:
                        continue
                    except OSError as error:
                        if stop_event.is_set():
                            return
                        receiver_errors.append(error)
                        receiver_failed.set()
                        return
                    if self._normalise_endpoint(address) != expected_endpoint:
                        ledger.attribution_errors += 1
                        continue
                    received_ns = time.monotonic_ns()
                    try:
                        response = decode_packet(data)
                    except ValueError:
                        ledger.attribution_errors += 1
                        continue
                    ledger.record_echo(response, received_ns)
            except BaseException as error:  # noqa: BLE001
                receiver_errors.append(error)
                receiver_failed.set()
            finally:
                receiver_exited.set()

        primary_error: BaseException | None = None
        primary_traceback: TracebackType | None = None
        cleanup_errors: list[BaseException] = []
        try:
            sock = socket.socket(self.address_family, socket.SOCK_DGRAM)
            if self.bind_device is not None:
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_BINDTODEVICE,
                    self.bind_device.encode(),
                )
            sock.bind(self._bind_address())
            sock.settimeout(0.02)
            receiver = threading.Thread(
                target=receive_loop,
                name="avpn-probe-rx",
                daemon=True,
            )
            receiver_start_attempted = True
            receiver.start()
            receiver_started = True
            interval_ns = round(1_000_000_000 / self.packet_rate_hz)
            next_send_ns = time.monotonic_ns()
            payload_size = self.datagram_size - HEADER_SIZE

            for sequence in range(packet_count):
                raise_receiver_failure()
                now_ns = time.monotonic_ns()
                if now_ns < next_send_ns:
                    receiver_failed.wait((next_send_ns - now_ns) / 1_000_000_000)
                    raise_receiver_failure()
                sent_ns = time.monotonic_ns()
                payload = bytes([sequence % 256]) * payload_size
                encoded = encode_packet(
                    ProbePacket(
                        run_token=self.run_token,
                        path_index=self.path_index,
                        sequence=sequence,
                        sent_ns=sent_ns,
                        payload=payload,
                    )
                )
                ledger.record_send(sequence, sent_ns, len(encoded))
                raise_receiver_failure()
                sock.sendto(encoded, resolved_target)
                next_send_ns += interval_ns

            deadline = time.monotonic() + self.response_timeout_s
            while ledger.received_count < packet_count and time.monotonic() < deadline:
                receiver_failed.wait(0.002)
                raise_receiver_failure()
            if ledger.received_count == packet_count:
                drain_deadline = time.monotonic() + self.duplicate_drain_s
                while time.monotonic() < drain_deadline:
                    receiver_failed.wait(0.002)
                    raise_receiver_failure()
        except BaseException as error:  # noqa: BLE001
            primary_error = error
            primary_traceback = error.__traceback__
        finally:
            stop_event.set()
            if sock is not None:
                try:
                    sock.close()
                except BaseException as error:  # noqa: BLE001
                    cleanup_errors.append(error)
            receiver_joinable = receiver is not None and (
                receiver_started or receiver.ident is not None
            )
            if receiver_joinable:
                try:
                    receiver.join(timeout=1.0)
                except BaseException as error:  # noqa: BLE001
                    cleanup_errors.append(error)
            elif receiver_start_attempted:
                receiver_exited.wait(timeout=1.0)

        def collapse_errors(errors: list[BaseException]) -> BaseException | None:
            if not errors:
                return None
            if len(errors) == 1:
                return errors[0]
            return BaseExceptionGroup("multiple probe failures", errors)

        receiver_joinable = receiver is not None and (
            receiver_started or receiver.ident is not None
        )
        if receiver_joinable and (receiver.is_alive() or not receiver_exited.is_set()):
            cause = collapse_errors(
                ([primary_error] if primary_error is not None else [])
                + cleanup_errors
                + receiver_errors
            )
            raise RuntimeError("probe receive thread did not stop") from cause
        if receiver_start_attempted and not receiver_joinable and not receiver_exited.is_set():
            cause = collapse_errors(
                ([primary_error] if primary_error is not None else [])
                + cleanup_errors
                + receiver_errors
            )
            raise RuntimeError("probe receiver termination could not be proven") from cause
        if cleanup_errors:
            cause = collapse_errors(
                ([primary_error] if primary_error is not None else [])
                + cleanup_errors
                + receiver_errors
            )
            raise RuntimeError("probe socket cleanup failed") from cause
        if primary_error is not None:
            if receiver_errors and primary_error.__cause__ not in receiver_errors:
                cause = collapse_errors([primary_error] + receiver_errors)
                raise RuntimeError("probe execution and receive loop failed") from cause
            raise primary_error.with_traceback(primary_traceback)
        if receiver_errors:
            raise RuntimeError("probe receive loop failed") from receiver_errors[0]

        ledger.finalize(
            now_ns=time.monotonic_ns(),
            timeout_ns=round(self.response_timeout_s * 1_000_000_000),
        )
        rows = ledger.rows()
        return ProbeRunResult(
            rows=rows,
            metrics=calculate_probe_metrics(rows),
            attribution_errors=ledger.attribution_errors,
            duplicate_echoes=ledger.duplicate_echoes,
        )

    def _bind_address(self) -> tuple:
        if self.address_family == socket.AF_INET6:
            return (self.bind_host, 0, 0, 0)
        return (self.bind_host, 0)

    def _normalise_endpoint(self, endpoint: tuple) -> tuple:
        if self.address_family == socket.AF_INET6:
            return (endpoint[0], endpoint[1], endpoint[2], endpoint[3])
        return (endpoint[0], endpoint[1])
