import socket
import threading

import pytest

import adaptive_vpn.probe as probe_module
from adaptive_vpn.probe import UDPProbeSession


def _session(
    *,
    target_port: int,
    response_timeout_s: float = 0.05,
    packet_rate_hz: float = 100,
    duplicate_drain_s: float | None = None,
) -> UDPProbeSession:
    values = {
        "target_host": "127.0.0.1",
        "target_port": target_port,
        "run_token": 20260804,
        "path_index": 1,
        "packet_rate_hz": packet_rate_hz,
        "datagram_size": 128,
        "response_timeout_s": response_timeout_s,
    }
    if duplicate_drain_s is not None:
        values["duplicate_drain_s"] = duplicate_drain_s
    return UDPProbeSession(**values)


def test_probe_rejects_echo_from_wrong_udp_endpoint():
    target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rogue = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target.bind(("127.0.0.1", 0))
    rogue.bind(("127.0.0.1", 0))

    def reply_from_rogue_endpoint() -> None:
        data, client = target.recvfrom(65_535)
        rogue.sendto(data, client)

    worker = threading.Thread(target=reply_from_rogue_endpoint, daemon=True)
    worker.start()
    try:
        result = _session(target_port=target.getsockname()[1]).run_packets(1)
    finally:
        target.close()
        rogue.close()
        worker.join(timeout=1)

    assert result.metrics.received_count == 0
    assert result.attribution_errors == 1


def test_probe_counts_duplicate_echo_during_bounded_receive_window():
    target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target.bind(("127.0.0.1", 0))
    first_echo_sent = threading.Event()
    release_duplicate = threading.Event()
    worker_errors: list[Exception] = []

    def reply_twice() -> None:
        try:
            data, client = target.recvfrom(65_535)
            target.sendto(data, client)
            first_echo_sent.set()
            assert release_duplicate.wait(timeout=1)
            target.sendto(data, client)
        except Exception as error:  # noqa: BLE001
            worker_errors.append(error)

    worker = threading.Thread(target=reply_twice, daemon=True)
    worker.start()
    result_holder = []
    session_errors: list[Exception] = []
    session_done = threading.Event()

    def run_session() -> None:
        try:
            result_holder.append(
                _session(
                    target_port=target.getsockname()[1],
                    response_timeout_s=0.5,
                    duplicate_drain_s=0.2,
                ).run_packets(1)
            )
        except Exception as error:  # noqa: BLE001
            session_errors.append(error)
        finally:
            session_done.set()

    session_worker = threading.Thread(target=run_session, daemon=True)
    session_worker.start()
    try:
        assert first_echo_sent.wait(timeout=1)
        assert not session_done.wait(timeout=0.05)
        release_duplicate.set()
        assert session_done.wait(timeout=1)
    finally:
        release_duplicate.set()
        session_worker.join(timeout=1)
        worker.join(timeout=1)
        target.close()

    assert not worker_errors
    assert not session_errors
    result = result_holder[0]
    assert result.metrics.received_count == 1
    assert result.duplicate_echoes == 1


@pytest.mark.skipif(not socket.has_ipv6, reason="IPv6 is unavailable")
def test_probe_uses_explicit_ipv6_family_without_fallback():
    target = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    target.bind(("::1", 0))
    worker = None

    def echo_once() -> None:
        data, client = target.recvfrom(65_535)
        target.sendto(data, client)

    worker = threading.Thread(target=echo_once, daemon=True)
    worker.start()
    try:
        session = UDPProbeSession(
            target_host="::1",
            target_port=target.getsockname()[1],
            run_token=20260805,
            path_index=2,
            packet_rate_hz=100,
            datagram_size=128,
            response_timeout_s=0.2,
            address_family=socket.AF_INET6,
        )
        result = session.run_packets(1)
    finally:
        target.close()
        worker.join(timeout=1)

    assert result.metrics.received_count == 1
    assert result.attribution_errors == 0


class _FailingReceiveSocket:
    def __init__(self) -> None:
        self.send_count = 0

    def setsockopt(self, *_args) -> None:
        return None

    def bind(self, _address) -> None:
        return None

    def settimeout(self, _timeout) -> None:
        return None

    def recvfrom(self, _size):
        raise OSError("synthetic receive failure")

    def sendto(self, data, _address) -> int:
        self.send_count += 1
        return len(data)

    def close(self) -> None:
        return None


def test_probe_propagates_receive_thread_failure(monkeypatch):
    monkeypatch.setattr(probe_module.socket, "socket", lambda *_args: _FailingReceiveSocket())

    with pytest.raises(RuntimeError, match="receive loop failed") as raised:
        _session(target_port=9, response_timeout_s=0.01).run_packets(1)

    assert isinstance(raised.value.__cause__, OSError)


class _PostReceiveFailureSocket(_FailingReceiveSocket):
    def recvfrom(self, _size):
        return b"synthetic packet", ("127.0.0.1", 9)


def test_probe_propagates_post_receive_processing_failure(monkeypatch):
    monkeypatch.setattr(
        probe_module.socket,
        "socket",
        lambda *_args: _PostReceiveFailureSocket(),
    )
    monkeypatch.setattr(
        probe_module,
        "decode_packet",
        lambda _data: (_ for _ in ()).throw(RuntimeError("synthetic decode failure")),
    )

    with pytest.raises(RuntimeError, match="receive loop failed") as raised:
        _session(target_port=9, response_timeout_s=0.01).run_packets(1)

    assert isinstance(raised.value.__cause__, RuntimeError)


def test_probe_propagates_receiver_baseexception(monkeypatch):
    monkeypatch.setattr(
        probe_module.socket,
        "socket",
        lambda *_args: _PostReceiveFailureSocket(),
    )
    monkeypatch.setattr(
        probe_module,
        "decode_packet",
        lambda _data: (_ for _ in ()).throw(SystemExit("synthetic receiver exit")),
    )

    with pytest.raises(RuntimeError, match="receive loop failed") as raised:
        _session(target_port=9, response_timeout_s=0.01).run_packets(1)

    assert isinstance(raised.value.__cause__, SystemExit)


class _ReceiveBaseExceptionSocket(_FailingReceiveSocket):
    def recvfrom(self, _size):
        raise SystemExit("synthetic recvfrom exit")


def test_probe_propagates_recvfrom_baseexception(monkeypatch):
    monkeypatch.setattr(
        probe_module.socket,
        "socket",
        lambda *_args: _ReceiveBaseExceptionSocket(),
    )

    with pytest.raises(RuntimeError, match="receive loop failed") as raised:
        _session(target_port=9, response_timeout_s=0.01).run_packets(1)

    assert isinstance(raised.value.__cause__, SystemExit)


class _TeardownProcessingFailureSocket(_FailingReceiveSocket):
    def __init__(self) -> None:
        super().__init__()
        self.sent = threading.Event()
        self.closed = threading.Event()

    def recvfrom(self, _size):
        self.sent.wait(timeout=1)
        return b"synthetic packet", ("127.0.0.1", 9)

    def sendto(self, data, _address) -> int:
        result = super().sendto(data, _address)
        self.sent.set()
        return result

    def close(self) -> None:
        self.closed.set()


def test_teardown_does_not_suppress_processing_oserror(monkeypatch):
    fake_socket = _TeardownProcessingFailureSocket()
    monkeypatch.setattr(probe_module.socket, "socket", lambda *_args: fake_socket)

    def fail_after_cleanup_starts(_data):
        assert fake_socket.closed.wait(timeout=1)
        raise OSError("synthetic processing failure")

    monkeypatch.setattr(probe_module, "decode_packet", fail_after_cleanup_starts)

    with pytest.raises(RuntimeError, match="receive loop failed") as raised:
        _session(target_port=9, response_timeout_s=0.01).run_packets(1)

    assert isinstance(raised.value.__cause__, OSError)


class _SignallingReceiveFailureSocket(_FailingReceiveSocket):
    def __init__(self, first_send: threading.Event, failed: threading.Event) -> None:
        super().__init__()
        self.first_send = first_send
        self.failed = failed

    def recvfrom(self, _size):
        self.first_send.wait(timeout=1)
        self.failed.set()
        raise OSError("synthetic receive failure")

    def sendto(self, data, _address) -> int:
        result = super().sendto(data, _address)
        self.first_send.set()
        self.failed.wait(timeout=1)
        return result


def test_probe_stops_paced_send_after_receiver_failure(monkeypatch):
    first_send = threading.Event()
    failed = threading.Event()
    fake_socket = _SignallingReceiveFailureSocket(first_send, failed)
    monkeypatch.setattr(probe_module.socket, "socket", lambda *_args: fake_socket)

    with pytest.raises(RuntimeError, match="receive loop failed"):
        _session(
            target_port=9,
            response_timeout_s=0.1,
            packet_rate_hz=100,
        ).run_packets(10)

    assert fake_socket.send_count == 1


class _StuckReceiveSocket(_FailingReceiveSocket):
    def __init__(self, release: threading.Event) -> None:
        super().__init__()
        self.release = release

    def recvfrom(self, _size):
        self.release.wait(timeout=2)
        raise TimeoutError


def test_probe_rejects_receiver_that_does_not_stop(monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(
        probe_module.socket,
        "socket",
        lambda *_args: _StuckReceiveSocket(release),
    )

    try:
        with pytest.raises(RuntimeError, match="did not stop"):
            _session(target_port=9, response_timeout_s=0.01).run_packets(1)
    finally:
        release.set()


class _SendFailureWithStuckReceiver(_StuckReceiveSocket):
    def sendto(self, _data, _address) -> int:
        raise ValueError("synthetic send failure")


def test_send_failure_still_rejects_stuck_receiver(monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(
        probe_module.socket,
        "socket",
        lambda *_args: _SendFailureWithStuckReceiver(release),
    )

    try:
        with pytest.raises(RuntimeError, match="did not stop") as raised:
            _session(target_port=9, response_timeout_s=0.01).run_packets(1)
    finally:
        release.set()

    assert isinstance(raised.value.__cause__, ValueError)


class _BindFailureSocket(_FailingReceiveSocket):
    def __init__(self) -> None:
        super().__init__()
        self.closed = False

    def bind(self, _address) -> None:
        raise ValueError("synthetic bind failure")

    def close(self) -> None:
        self.closed = True


def test_setup_failure_closes_socket(monkeypatch):
    fake_socket = _BindFailureSocket()
    monkeypatch.setattr(probe_module.socket, "socket", lambda *_args: fake_socket)

    with pytest.raises(ValueError, match="bind failure"):
        _session(target_port=9).run_packets(1)

    assert fake_socket.closed is True


class _PostStartClockFailureSocket(_FailingReceiveSocket):
    def __init__(self) -> None:
        super().__init__()
        self.release = threading.Event()
        self.exited = threading.Event()
        self.closed = False

    def recvfrom(self, _size):
        try:
            self.release.wait(timeout=2)
            raise OSError("socket closed")
        finally:
            self.exited.set()

    def close(self) -> None:
        self.closed = True
        self.release.set()


def test_post_start_clock_failure_closes_socket_and_joins_receiver(monkeypatch):
    fake_socket = _PostStartClockFailureSocket()
    monkeypatch.setattr(probe_module.socket, "socket", lambda *_args: fake_socket)
    monkeypatch.setattr(
        probe_module.time,
        "monotonic_ns",
        lambda: (_ for _ in ()).throw(ValueError("synthetic clock failure")),
    )

    try:
        with pytest.raises(ValueError, match="clock failure"):
            _session(target_port=9).run_packets(1)
        assert fake_socket.closed is True
        assert fake_socket.exited.is_set()
    finally:
        fake_socket.release.set()


class _PartialStartThread:
    def __init__(self, *, target, gate: threading.Event, real_thread) -> None:
        self.target = target
        self.gate = gate
        self.real_thread = real_thread
        self.worker = None
        self.ident = None

    def start(self) -> None:
        self.worker = self.real_thread(target=self._run, daemon=True)
        self.worker.start()
        raise ValueError("synthetic partial thread start")

    def _run(self) -> None:
        self.gate.wait(timeout=2)
        self.target()

    def join(self, timeout=None) -> None:
        if self.worker is not None:
            self.worker.join(timeout=timeout)

    def is_alive(self) -> bool:
        return self.worker is not None and self.worker.is_alive()


def test_partial_thread_start_without_ident_fails_closed(monkeypatch):
    gate = threading.Event()
    real_thread = threading.Thread
    created = []

    def thread_factory(*, target, name, daemon):
        del name, daemon
        thread = _PartialStartThread(target=target, gate=gate, real_thread=real_thread)
        created.append(thread)
        return thread

    monkeypatch.setattr(probe_module.threading, "Thread", thread_factory)

    try:
        with pytest.raises(RuntimeError, match="termination could not be proven") as raised:
            _session(target_port=9).run_packets(1)
        assert isinstance(raised.value.__cause__, ValueError)
    finally:
        gate.set()
        for thread in created:
            thread.join(timeout=1)


class _SendAndCloseFailureSocket(_PostStartClockFailureSocket):
    def sendto(self, _data, _address) -> int:
        raise ValueError("synthetic send failure")

    def close(self) -> None:
        super().close()
        raise OSError("synthetic close failure")


def test_combined_primary_and_cleanup_failures_are_preserved(monkeypatch):
    fake_socket = _SendAndCloseFailureSocket()
    monkeypatch.setattr(probe_module.socket, "socket", lambda *_args: fake_socket)

    with pytest.raises(RuntimeError, match="cleanup failed") as raised:
        _session(target_port=9).run_packets(1)

    assert isinstance(raised.value.__cause__, BaseExceptionGroup)
    assert {type(error) for error in raised.value.__cause__.exceptions} == {
        ValueError,
        OSError,
    }


class _ThreeWayFailureSocket(_TeardownProcessingFailureSocket):
    def __init__(self, processing_started: threading.Event) -> None:
        super().__init__()
        self.processing_started = processing_started

    def sendto(self, _data, _address) -> int:
        self.sent.set()
        assert self.processing_started.wait(timeout=1)
        raise ValueError("primary send failure")

    def close(self) -> None:
        super().close()
        raise OSError("cleanup close failure")


def test_cleanup_group_preserves_primary_cleanup_and_receiver_failures(monkeypatch):
    processing_started = threading.Event()
    fake_socket = _ThreeWayFailureSocket(processing_started)
    monkeypatch.setattr(probe_module.socket, "socket", lambda *_args: fake_socket)

    def fail_processing(_data):
        processing_started.set()
        assert fake_socket.closed.wait(timeout=1)
        raise LookupError("receiver processing failure")

    monkeypatch.setattr(probe_module, "decode_packet", fail_processing)

    with pytest.raises(RuntimeError, match="cleanup failed") as raised:
        _session(target_port=9).run_packets(1)

    assert isinstance(raised.value.__cause__, BaseExceptionGroup)
    assert {type(error) for error in raised.value.__cause__.exceptions} == {
        ValueError,
        OSError,
        LookupError,
    }
