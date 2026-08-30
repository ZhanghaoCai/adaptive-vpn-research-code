#!/usr/bin/env python3
"""Deterministic UDP media-stream simulator (RTP-like, no external deps).

Direct-leg meeting-workload probe. Sender emits sequence-numbered UDP datagrams
at a configured bit-rate with 20 ms packetization (RTP-like). Receiver computes,
without clock synchronisation:
  - packet loss % from sequence gaps (RFC 3550 style population)
  - interarrival jitter via the registered RFC 3550-style recurrence
  - out-of-order count
  - delivered throughput (kbps)

Usage:
  python3 media_sim.py send <dst_host> <dst_port> <kbps> <seconds> [payload_hint]
  python3 media_sim.py recv <bind_port> <seconds>
  python3 media_sim.py probe_send <dst_host> <dst_port> <kbps> <seconds>   # send + self-collect (one-host echo helper)
"""
import socket
import struct
import sys
import time

MAGIC = b"AVPM1"
PPS = 50  # 20 ms packetization
OVERHEAD_BYTES = 5 + 4 + 8  # magic + seq + send_time_us
IDLE_EXIT = 5.0  # receiver exits this long after the sender stops (seconds)


def payload_bytes_for(kbps):
    # bytes per 20 ms datagram to sustain kbps
    return max(1, int(kbps * 1000 * 0.020 / 8))


def sender(dst_host, dst_port, kbps, seconds):
    p = payload_bytes_for(kbps)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    seq = 0
    start = time.monotonic()
    deadline = start + seconds
    interval = 1.0 / PPS
    while time.monotonic() < deadline:
        now_us = int(time.monotonic() * 1_000_000)
        payload = MAGIC + struct.pack(">IQ", seq, now_us) + (b"\x00" * (p - OVERHEAD_BYTES))
        try:
            s.sendto(payload, (dst_host, dst_port))
        except Exception:
            pass
        seq += 1
        time.sleep(interval)
    s.close()


def relay(bind_port, dst_host, dst_port):
    """TURN-like UDP relay: bind locally, forward every datagram to dst."""
    s_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_in.bind(("0.0.0.0", bind_port))
    s_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_in.settimeout(0.2)
    while True:
        try:
            data, _addr = s_in.recvfrom(4096)
        except socket.timeout:
            continue
        s_out.sendto(data, (dst_host, dst_port))


def receiver(bind_port, seconds):
    """Bind, print a LISTENING marker, then collect until the window ends or the
    sender goes silent for IDLE_EXIT seconds after at least one arrival. The
    marker lets the orchestrator handshake before sending; the idle early-exit
    keeps a long safety window from delaying the result."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", bind_port))
    print(f"LISTENING {bind_port}", flush=True)
    s.settimeout(0.2)
    seqs = []
    arrivals = []
    total_bytes = 0
    start = time.monotonic()
    deadline = start + seconds + 0.5
    last_arrival = None
    while time.monotonic() < deadline:
        try:
            data, _addr = s.recvfrom(4096)
        except socket.timeout:
            if last_arrival is not None and time.monotonic() - last_arrival > IDLE_EXIT:
                break
            continue
        if len(data) < 17 or data[:5] != MAGIC:
            continue
        seq, send_us = struct.unpack(">IQ", data[5:17])
        seqs.append(seq)
        arrivals.append((time.monotonic(), send_us))
        total_bytes += len(data)
        last_arrival = time.monotonic()
    s.close()
    stats(seqs, arrivals, seconds, total_bytes)
    return seqs, arrivals


def stats(seqs, arrivals, seconds, total_bytes):
    seqs.sort()
    n = len(seqs)
    total = (max(seqs) - min(seqs) + 1) if seqs else 0
    loss = (1.0 - n / total) * 100.0 if total else 0.0
    reorder = 0
    prev = -1
    for q in seqs:
        if q < prev:
            reorder += 1
        prev = q
    # RFC 3550-style jitter recurrence over consecutive valid arrivals
    jitter = 0.0
    prev_d = None
    prev_r = None
    prev_s = None
    for r, s_us in arrivals:
        if prev_r is not None:
            d = (r - prev_r) - (s_us - prev_s) / 1e6
            if prev_d is not None:
                jitter += (abs(d - prev_d) - jitter) / 16.0
            prev_d = d
        prev_r = r
        prev_s = s_us
    span = (arrivals[-1][0] - arrivals[0][0]) if len(arrivals) > 1 else float(seconds)
    kbps = total_bytes * 8.0 / 1000.0 / span if span > 0 else 0.0
    # arrival gaps: longest disruption analogue (maximum adjacent valid-arrival gap)
    gaps_ms = []
    for i in range(1, len(arrivals)):
        gaps_ms.append((arrivals[i][0] - arrivals[i - 1][0]) * 1000.0)
    longest_gap_ms = max(gaps_ms) if gaps_ms else 0.0
    if gaps_ms:
        gaps_ms.sort()
        idx = max(0, int(len(gaps_ms) * 0.95) - 1)
        p95_gap_ms = gaps_ms[idx]
    else:
        p95_gap_ms = 0.0
    out = {
        "packets_received": n,
        "sequence_span": total,
        "loss_pct": round(loss, 3),
        "out_of_order": reorder,
        "jitter_rfc3550_ms": round(jitter * 1000.0, 3),
        "delivered_kbps": round(kbps, 2),
        "longest_gap_ms": round(longest_gap_ms, 3),
        "p95_gap_ms": round(p95_gap_ms, 3),
    }
    print("RESULT " + __import__("json").dumps(out, sort_keys=True))


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "send":
        sender(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5]))
    elif mode == "recv":
        receiver(int(sys.argv[2]), float(sys.argv[3]))
    elif mode == "relay":
        relay(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
    else:
        sys.exit("unknown mode")
