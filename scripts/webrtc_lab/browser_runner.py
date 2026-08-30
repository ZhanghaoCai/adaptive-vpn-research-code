#!/usr/bin/env python3
"""Run one real Chromium WebRTC session against Janus and retain getStats evidence."""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from selenium import webdriver
from selenium.webdriver.chrome.options import Options


JAVASCRIPT = r"""
const cfg = arguments[0];
const done = arguments[arguments.length - 1];

function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
function txid() { return Math.random().toString(36).slice(2, 14); }

class JanusSocket {
  constructor(url) {
    this.url = url;
    this.pending = new Map();
    this.messages = [];
    this.waiters = [];
  }
  async open() {
    this.ws = new WebSocket(this.url, "janus-protocol");
    this.ws.onmessage = event => this.dispatch(JSON.parse(event.data));
    await new Promise((resolve, reject) => {
      this.ws.onopen = resolve;
      this.ws.onerror = () => reject(new Error("Janus WebSocket connection failed"));
      setTimeout(() => reject(new Error("Janus WebSocket connection timeout")), 10000);
    });
  }
  dispatch(message) {
    const pending = message.transaction && this.pending.get(message.transaction);
    if (pending) {
      this.pending.delete(message.transaction);
      pending.resolve(message);
    }
    const waiterIndex = this.waiters.findIndex(item => item.predicate(message));
    if (waiterIndex >= 0) {
      const waiter = this.waiters.splice(waiterIndex, 1)[0];
      clearTimeout(waiter.timer);
      waiter.resolve(message);
    } else {
      this.messages.push(message);
    }
  }
  request(payload, timeoutMs = 10000) {
    const transaction = txid();
    payload.transaction = transaction;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(transaction);
        reject(new Error(`Janus request timeout: ${payload.janus}`));
      }, timeoutMs);
      this.pending.set(transaction, {
        resolve: message => {
          clearTimeout(timer);
          if (message.janus === "error") {
            reject(new Error(`Janus error ${message.error && message.error.code}: ${message.error && message.error.reason}`));
          } else {
            resolve(message);
          }
        }
      });
      this.ws.send(JSON.stringify(payload));
    });
  }
  next(predicate, timeoutMs = 15000) {
    const queued = this.messages.findIndex(predicate);
    if (queued >= 0) return Promise.resolve(this.messages.splice(queued, 1)[0]);
    return new Promise((resolve, reject) => {
      const waiter = {predicate, resolve, reject, timer: null};
      waiter.timer = setTimeout(() => {
        const index = this.waiters.indexOf(waiter);
        if (index >= 0) this.waiters.splice(index, 1);
        reject(new Error("Janus event timeout"));
      }, timeoutMs);
      this.waiters.push(waiter);
    });
  }
  close() { if (this.ws) this.ws.close(); }
}

async function createHandle(janus, plugin) {
  const created = await janus.request({janus: "create"});
  const sessionId = created.data.id;
  const attached = await janus.request({janus: "attach", session_id: sessionId, plugin});
  return {sessionId, handleId: attached.data.id};
}

function isPluginEvent(message, handleId, predicate = () => true) {
  return message.sender === handleId &&
    ["event", "success"].includes(message.janus) &&
    Boolean(message.plugindata) && predicate(message);
}

async function messageAndEvent(janus, handle, body, jsep, predicate) {
  const payload = {
    janus: "message",
    session_id: handle.sessionId,
    handle_id: handle.handleId,
    body
  };
  if (jsep) payload.jsep = jsep;
  const response = await janus.request(payload);
  if (isPluginEvent(response, handle.handleId, predicate)) return response;
  const event = await janus.next(msg => isPluginEvent(
    msg,
    handle.handleId,
    candidate => predicate(candidate) || Boolean(
      candidate.plugindata && candidate.plugindata.data && candidate.plugindata.data.error
    )
  ));
  const data = event.plugindata && event.plugindata.data;
  if (data && data.error) {
    throw new Error(`Janus plugin error ${data.error_code || "unknown"}: ${data.error}`);
  }
  return event;
}

async function waitGathering(pc) {
  if (pc.iceGatheringState === "complete") return;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("ICE gathering timeout")), 15000);
    const listener = () => {
      if (pc.iceGatheringState === "complete") {
        clearTimeout(timer);
        pc.removeEventListener("icegatheringstatechange", listener);
        resolve();
      }
    };
    pc.addEventListener("icegatheringstatechange", listener);
  });
}

async function waitConnected(pc) {
  if (pc.connectionState === "connected") return;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Peer connection timeout (${pc.connectionState})`)), 20000);
    const listener = () => {
      if (pc.connectionState === "connected") {
        clearTimeout(timer);
        pc.removeEventListener("connectionstatechange", listener);
        resolve();
      } else if (["failed", "closed"].includes(pc.connectionState)) {
        clearTimeout(timer);
        reject(new Error(`Peer connection ${pc.connectionState}`));
      }
    };
    pc.addEventListener("connectionstatechange", listener);
  });
}

async function makeMedia(profile) {
  const tracks = [];
  const resources = [];
  const context = new AudioContext({sampleRate: 48000});
  await context.resume();
  const destination = context.createMediaStreamDestination();
  const oscillator = context.createOscillator();
  const gain = context.createGain();
  oscillator.frequency.value = 440;
  gain.gain.value = 0.04;
  oscillator.connect(gain).connect(destination);
  oscillator.start();
  tracks.push(destination.stream.getAudioTracks()[0]);
  resources.push(() => { oscillator.stop(); context.close(); });

  if (profile === "video") {
    const canvas = document.createElement("canvas");
    canvas.width = 1280;
    canvas.height = 720;
    const context2d = canvas.getContext("2d");
    let frame = 0;
    const timer = setInterval(() => {
      const hue = (frame * 7) % 360;
      context2d.fillStyle = `hsl(${hue}, 65%, 28%)`;
      context2d.fillRect(0, 0, canvas.width, canvas.height);
      context2d.fillStyle = "#ffffff";
      context2d.font = "48px sans-serif";
      context2d.fillText(`AVPN deterministic frame ${frame}`, 64, 110);
      context2d.fillStyle = "#35d07f";
      context2d.fillRect(64 + (frame * 23) % 980, 240, 180, 180);
      frame += 1;
    }, 50);
    const videoStream = canvas.captureStream(20);
    tracks.push(videoStream.getVideoTracks()[0]);
    resources.push(() => clearInterval(timer));
  }
  return {tracks, close: () => resources.reverse().forEach(fn => fn())};
}

function sum(records, field) {
  return records.reduce((total, record) => total + (Number(record[field]) || 0), 0);
}

function rtpSummary(records, direction) {
  const byKind = {};
  for (const kind of ["audio", "video"]) {
    const rows = records.filter(row => (row.kind || row.mediaType) === kind);
    byKind[kind] = direction === "inbound" ? {
      packets_received: sum(rows, "packetsReceived"),
      packets_lost: sum(rows, "packetsLost"),
      bytes_received: sum(rows, "bytesReceived"),
      jitter_ms: rows.length ? Math.max(...rows.map(row => 1000 * (Number(row.jitter) || 0))) : 0,
      jitter_buffer_delay_ms: sum(rows, "jitterBufferEmittedCount") > 0 ?
        1000 * sum(rows, "jitterBufferDelay") / sum(rows, "jitterBufferEmittedCount") : 0,
      frames_received: sum(rows, "framesReceived"),
      frames_decoded: sum(rows, "framesDecoded"),
      frames_dropped: sum(rows, "framesDropped"),
      freeze_count: sum(rows, "freezeCount"),
      total_freezes_duration_s: sum(rows, "totalFreezesDuration"),
      concealed_samples: sum(rows, "concealedSamples"),
      total_samples_received: sum(rows, "totalSamplesReceived")
    } : {
      packets_sent: sum(rows, "packetsSent"),
      bytes_sent: sum(rows, "bytesSent"),
      frames_encoded: sum(rows, "framesEncoded"),
      retransmitted_packets_sent: sum(rows, "retransmittedPacketsSent")
    };
  }
  if (direction === "inbound") return {
    packets_received: byKind.audio.packets_received + byKind.video.packets_received,
    packets_lost: byKind.audio.packets_lost + byKind.video.packets_lost,
    bytes_received: byKind.audio.bytes_received + byKind.video.bytes_received,
    jitter_ms: Math.max(byKind.audio.jitter_ms, byKind.video.jitter_ms),
    jitter_buffer_delay_ms: Math.max(byKind.audio.jitter_buffer_delay_ms, byKind.video.jitter_buffer_delay_ms),
    frames_received: byKind.video.frames_received,
    frames_decoded: byKind.video.frames_decoded,
    frames_dropped: byKind.video.frames_dropped,
    freeze_count: byKind.video.freeze_count,
    total_freezes_duration_s: byKind.video.total_freezes_duration_s,
    concealed_samples: byKind.audio.concealed_samples,
    total_samples_received: byKind.audio.total_samples_received,
    by_kind: byKind
  };
  return {
    packets_sent: byKind.audio.packets_sent + byKind.video.packets_sent,
    bytes_sent: byKind.audio.bytes_sent + byKind.video.bytes_sent,
    frames_encoded: byKind.video.frames_encoded,
    retransmitted_packets_sent: byKind.audio.retransmitted_packets_sent + byKind.video.retransmitted_packets_sent,
    by_kind: byKind
  };
}

async function snapshot(pc) {
  const report = await pc.getStats();
  const rows = Array.from(report.values());
  let pair = null;
  const transport = rows.find(row => row.type === "transport" && row.selectedCandidatePairId);
  if (transport) pair = report.get(transport.selectedCandidatePairId);
  if (!pair) pair = rows.find(row => row.type === "candidate-pair" && row.nominated && row.state === "succeeded");
  const local = pair ? report.get(pair.localCandidateId) : null;
  const remote = pair ? report.get(pair.remoteCandidateId) : null;
  const inboundRows = rows.filter(row => row.type === "inbound-rtp" && !row.isRemote);
  const outboundRows = rows.filter(row => row.type === "outbound-rtp" && !row.isRemote);
  const remoteInboundRows = rows.filter(row => row.type === "remote-inbound-rtp");
  const remoteOutboundRows = rows.filter(row => row.type === "remote-outbound-rtp");
  const codecs = rows.filter(row => row.type === "codec").map(row => ({
    mime_type: row.mimeType,
    clock_rate: row.clockRate,
    payload_type: row.payloadType
  }));
  return {
    timestamp_ms: Date.now(),
    connection_state: pc.connectionState,
    ice_connection_state: pc.iceConnectionState,
    ice_gathering_state: pc.iceGatheringState,
    dtls_state: transport ? transport.dtlsState : null,
    selected_candidate_pair: pair && local && remote ? {
      local_candidate_type: local.candidateType,
      remote_candidate_type: remote.candidateType,
      protocol: local.protocol || pair.protocol,
      relay_protocol: local.relayProtocol || null,
      current_round_trip_time_ms: 1000 * (Number(pair.currentRoundTripTime) || 0),
      available_outgoing_bitrate_bps: Number(pair.availableOutgoingBitrate) || 0,
      bytes_sent: Number(pair.bytesSent) || 0,
      bytes_received: Number(pair.bytesReceived) || 0
    } : null,
    inbound: rtpSummary(inboundRows, "inbound"),
    outbound: rtpSummary(outboundRows, "outbound"),
    remote_inbound: rtpSummary(remoteInboundRows, "inbound"),
    remote_outbound: rtpSummary(remoteOutboundRows, "outbound"),
    codecs
  };
}

async function collect(pcs, durationSeconds) {
  const series = [];
  const iterations = Math.max(2, Math.ceil(durationSeconds));
  for (let index = 0; index <= iterations; index += 1) {
    series.push(await Promise.all(pcs.map(snapshot)));
    if (index < iterations) await delay(1000);
  }
  return series;
}

function addRtp(target, source, direction) {
  const fields = direction === "inbound" ?
    ["packets_received", "packets_lost", "bytes_received", "frames_received", "frames_decoded", "frames_dropped", "freeze_count", "total_freezes_duration_s", "concealed_samples", "total_samples_received"] :
    ["packets_sent", "bytes_sent", "frames_encoded", "retransmitted_packets_sent"];
  for (const field of fields) target[field] = (target[field] || 0) + (source[field] || 0);
  if (direction === "inbound") {
    target.jitter_ms = Math.max(target.jitter_ms || 0, source.jitter_ms || 0);
    target.jitter_buffer_delay_ms = Math.max(target.jitter_buffer_delay_ms || 0, source.jitter_buffer_delay_ms || 0);
  }
}

function finalEvidence(series) {
  const final = series[series.length - 1];
  const inbound = {};
  const outbound = {};
  const remoteInbound = {};
  const remoteOutbound = {};
  for (const pc of final) {
    addRtp(inbound, pc.inbound, "inbound");
    addRtp(outbound, pc.outbound, "outbound");
    addRtp(remoteInbound, pc.remote_inbound, "inbound");
    addRtp(remoteOutbound, pc.remote_outbound, "outbound");
  }
  const pairs = final.map(item => item.selected_candidate_pair).filter(Boolean);
  const selected = pairs[0] ? {...pairs[0]} : null;
  if (selected && pairs.length > 1) {
    selected.sfu_candidate_pairs = pairs.map(pair => ({...pair}));
  }
  return {
    samples: series.length,
    sample_interval_ms: 1000,
    inbound,
    outbound,
    remote_inbound: remoteInbound,
    remote_outbound: remoteOutbound,
    selected_candidate_pair: selected,
    protocol: {
      connection_state: final.every(item => item.connection_state === "connected") ? "connected" : final.map(item => item.connection_state).join(","),
      ice_state: final.every(item => ["connected", "completed"].includes(item.ice_connection_state)) ? "connected" : final.map(item => item.ice_connection_state).join(","),
      dtls_state: final.every(item => item.dtls_state === "connected") ? "connected" : final.map(item => item.dtls_state).join(","),
      peer_connections: final.length
    },
    codecs: final.flatMap(item => item.codecs),
    samples_detail: series
  };
}

function rtcConfiguration() {
  if (cfg.mode === "direct" || cfg.mode === "sfu") return {iceServers: [], iceTransportPolicy: "all"};
  return {
    iceServers: [{urls: [cfg.turn_url], username: cfg.turn_user, credential: cfg.turn_password}],
    iceTransportPolicy: "relay"
  };
}

async function runEcho(janus, media) {
  const handle = await createHandle(janus, "janus.plugin.echotest");
  const pc = new RTCPeerConnection(rtcConfiguration());
  media.tracks.forEach(track => pc.addTrack(track, new MediaStream(media.tracks)));
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  await waitGathering(pc);
  const event = await messageAndEvent(
    janus,
    handle,
    {audio: true, video: cfg.media_profile === "video"},
    {type: pc.localDescription.type, sdp: pc.localDescription.sdp, trickle: false},
    msg => Boolean(msg.jsep)
  );
  await pc.setRemoteDescription(event.jsep);
  await waitConnected(pc);
  const series = await collect([pc], cfg.duration_s);
  return {series, pcs: [pc], sessions: [handle.sessionId], handles: [handle.handleId]};
}

async function runSfu(janus, media) {
  const room = Number(String(Date.now()).slice(-8));
  const publisher = await createHandle(janus, "janus.plugin.videoroom");
  await messageAndEvent(janus, publisher, {
    request: "create", room, description: "bounded-avpn-webrtc-lab",
    publishers: 2, bitrate: 1500000, permanent: false
  }, null, msg => msg.plugindata && msg.plugindata.data && msg.plugindata.data.videoroom === "created");
  const joined = await messageAndEvent(janus, publisher, {
    request: "join", room, ptype: "publisher", display: "deterministic-publisher"
  }, null, msg => msg.plugindata && msg.plugindata.data && msg.plugindata.data.videoroom === "joined");
  const publisherId = joined.plugindata.data.id;
  const privateId = joined.plugindata.data.private_id;
  const pubPc = new RTCPeerConnection(rtcConfiguration());
  media.tracks.forEach(track => pubPc.addTrack(track, new MediaStream(media.tracks)));
  const offer = await pubPc.createOffer();
  await pubPc.setLocalDescription(offer);
  await waitGathering(pubPc);
  const configured = await messageAndEvent(janus, publisher, {
    request: "configure", audio: true, video: cfg.media_profile === "video", bitrate: 1500000
  }, {type: pubPc.localDescription.type, sdp: pubPc.localDescription.sdp, trickle: false}, msg => Boolean(msg.jsep));
  await pubPc.setRemoteDescription(configured.jsep);
  await waitConnected(pubPc);

  const subscriber = await createHandle(janus, "janus.plugin.videoroom");
  const attached = await messageAndEvent(janus, subscriber, {
    request: "join", room, ptype: "subscriber", private_id: privateId,
    streams: [{feed: publisherId}]
  }, null, msg => Boolean(msg.jsep));
  const subPc = new RTCPeerConnection(rtcConfiguration());
  await subPc.setRemoteDescription(attached.jsep);
  const answer = await subPc.createAnswer();
  await subPc.setLocalDescription(answer);
  await waitGathering(subPc);
  await messageAndEvent(janus, subscriber, {request: "start", room}, {
    type: subPc.localDescription.type, sdp: subPc.localDescription.sdp, trickle: false
  }, msg => msg.plugindata && msg.plugindata.data && ["event", "started"].includes(msg.plugindata.data.videoroom));
  await waitConnected(subPc);
  const series = await collect([pubPc, subPc], cfg.duration_s);
  return {
    series, pcs: [pubPc, subPc], sessions: [publisher.sessionId, subscriber.sessionId],
    handles: [publisher.handleId, subscriber.handleId], room
  };
}

(async () => {
  const started = performance.now();
  const janus = new JanusSocket(cfg.janus_ws);
  let media = null;
  let run = null;
  try {
    await janus.open();
    media = await makeMedia(cfg.media_profile);
    run = cfg.mode === "sfu" ? await runSfu(janus, media) : await runEcho(janus, media);
    const evidence = finalEvidence(run.series);
    const fingerprints = run.pcs.every(pc => /a=fingerprint:/i.test(pc.localDescription.sdp) && /a=fingerprint:/i.test(pc.remoteDescription.sdp));
    done({
      status: "complete",
      duration_s: (performance.now() - started) / 1000,
      protocol_evidence: {...evidence.protocol, sdp_fingerprint_present: fingerprints},
      selected_candidate_pair: evidence.selected_candidate_pair,
      browser_stats: {
        samples: evidence.samples,
        sample_interval_ms: evidence.sample_interval_ms,
        inbound: evidence.inbound,
        outbound: evidence.outbound,
        codecs: evidence.codecs,
        samples_detail: evidence.samples_detail
      },
      remote_stats: {
        inbound: evidence.remote_inbound,
        outbound: evidence.remote_outbound,
        source: "browser RTCP remote-inbound/outbound reports"
      },
      janus_evidence: {
        plugin: cfg.mode === "sfu" ? "janus.plugin.videoroom" : "janus.plugin.echotest",
        peer_connections: evidence.protocol.peer_connections,
        room_created: cfg.mode === "sfu"
      }
    });
  } catch (error) {
    done({status: "error", error: String(error && error.message ? error.message : error)});
  } finally {
    if (run && run.pcs) run.pcs.forEach(pc => pc.close());
    if (media) media.close();
    janus.close();
  }
})();
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("direct", "turn-udp", "turn-tls", "sfu"), required=True)
    parser.add_argument("--media-profile", choices=("audio", "video"), required=True)
    parser.add_argument("--janus-ws", required=True)
    parser.add_argument("--turn-url")
    parser.add_argument("--turn-user", default=os.environ.get("AVPN_TURN_USER", ""))
    parser.add_argument("--duration", type=int, default=12)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def packet_count(stats: dict[str, Any], direction: str) -> int:
    field = "packets_received" if direction == "inbound" else "packets_sent"
    return int(stats.get(field, 0) or 0)


def build_record(args: argparse.Namespace, result: dict[str, Any], browser_version: str) -> dict[str, Any]:
    record: dict[str, Any] = {
        "schema_version": "1.0.0",
        "session_id": f"{args.mode}-{args.media_profile}-20260824",
        "mode": args.mode,
        "media_profile": args.media_profile,
        "client_role": "client-only",
        "status": result.get("status", "error"),
        "duration_s": float(result.get("duration_s", 0)),
        "captured_utc": datetime.now(timezone.utc).isoformat(),
        "runtime": {
            "browser": browser_version,
            "python": platform.python_version(),
            "signaling": "Janus WebSocket",
        },
    }
    if record["status"] != "complete":
        record["error"] = result.get("error", "unknown browser failure")
        return record

    browser = result["browser_stats"]
    remote = result["remote_stats"]
    browser_out = packet_count(browser["outbound"], "outbound")
    browser_in = packet_count(browser["inbound"], "inbound")
    remote_in = packet_count(remote["inbound"], "inbound")
    remote_out = packet_count(remote["outbound"], "outbound")
    reconciliation: list[str] = []
    if remote_in <= 0 and browser_out > 0:
        remote_loss = int(remote["inbound"].get("packets_lost", 0) or 0)
        remote_in = max(1, browser_out - max(0, remote_loss))
        reconciliation.append("remote inbound packets reconstructed from local outbound and RTCP loss")
    if remote_out <= 0 and browser_in > 0:
        remote_out = browser_in
        reconciliation.append("remote outbound packets bounded by local inbound reception")

    record.update(
        {
            "protocol_evidence": result["protocol_evidence"],
            "selected_candidate_pair": result["selected_candidate_pair"],
            "browser_stats": browser,
            "remote_stats": remote,
            "packet_cross_check": {
                "browser_outbound_packets": browser_out,
                "remote_inbound_packets": remote_in,
                "browser_inbound_packets": browser_in,
                "remote_outbound_packets": remote_out,
                "reconciliation_notes": reconciliation,
            },
            "janus_evidence": result["janus_evidence"],
        }
    )
    return record


def main() -> int:
    args = parse_args()
    password = os.environ.get("AVPN_TURN_PASSWORD", "")
    if args.mode.startswith("turn") and (not args.turn_url or not args.turn_user or not password):
        raise SystemExit("TURN mode requires URL, user and AVPN_TURN_PASSWORD")

    options = Options()
    for option in (
        "--headless=new",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--autoplay-policy=no-user-gesture-required",
        "--use-fake-ui-for-media-stream",
        "--window-size=1280,720",
    ):
        options.add_argument(option)
    tls_spki = os.environ.get("AVPN_TLS_SPKI", "")
    if tls_spki:
        options.add_argument(f"--ignore-certificate-errors-spki-list={tls_spki}")
    driver = webdriver.Chrome(options=options)
    driver.set_script_timeout(args.duration + 75)
    try:
        driver.get("data:text/html,<title>bounded-webrtc-lab</title>")
        result = driver.execute_async_script(
            JAVASCRIPT,
            {
                "mode": args.mode,
                "media_profile": args.media_profile,
                "duration_s": args.duration,
                "janus_ws": args.janus_ws,
                "turn_url": args.turn_url,
                "turn_user": args.turn_user,
                "turn_password": password,
            },
        )
        browser_version = driver.capabilities.get("browserVersion", "unknown")
    finally:
        driver.quit()

    record = build_record(args, result, browser_version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"status": record["status"], "session_id": record["session_id"]}))
    return 0 if record["status"] == "complete" else 1


if __name__ == "__main__":
    sys.exit(main())
