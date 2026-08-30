#!/usr/bin/env bash
set -euo pipefail

TURN_ENV=${AVPN_TURN_ENV:-/tmp/avpn-webrtc/turn.env}
if [[ -f "$TURN_ENV" ]]; then
  # shellcheck disable=SC1090
  source "$TURN_ENV"
fi

: "${AVPN_JANUS_WS:?AVPN_JANUS_WS is required}"
export AVPN_TURN_PASSWORD="${AVPN_TURN_PASSWORD:-}"

DURATION=${1:-12}
OUTPUT_DIR=${2:-/tmp/avpn-webrtc/results}
ONLY_MODE=${3:-all}
ONLY_PROFILE=${4:-all}
RUNNER=${AVPN_WEBRTC_RUNNER:-/tmp/avpn-webrtc/browser_runner.py}

mkdir -p "$OUTPUT_DIR"

for mode in direct turn-udp turn-tls sfu; do
  if [[ "$ONLY_MODE" != all && "$ONLY_MODE" != "$mode" ]]; then
    continue
  fi
  for profile in audio video; do
    if [[ "$ONLY_PROFILE" != all && "$ONLY_PROFILE" != "$profile" ]]; then
      continue
    fi
    args=(
      python3 "$RUNNER"
      --mode "$mode"
      --media-profile "$profile"
      --janus-ws "$AVPN_JANUS_WS"
      --duration "$DURATION"
      --output "$OUTPUT_DIR/$mode-$profile.json"
    )
    if [[ "$mode" == turn-udp ]]; then
      : "${AVPN_TURN_URL_UDP:?AVPN_TURN_URL_UDP is required for turn-udp}"
      : "${AVPN_TURN_USER:?AVPN_TURN_USER is required for TURN modes}"
      : "${AVPN_TURN_PASSWORD:?AVPN_TURN_PASSWORD is required for TURN modes}"
      args+=(--turn-url "$AVPN_TURN_URL_UDP" --turn-user "$AVPN_TURN_USER")
    elif [[ "$mode" == turn-tls ]]; then
      : "${AVPN_TURN_URL_TLS:?AVPN_TURN_URL_TLS is required for turn-tls}"
      : "${AVPN_TURN_USER:?AVPN_TURN_USER is required for TURN modes}"
      : "${AVPN_TURN_PASSWORD:?AVPN_TURN_PASSWORD is required for TURN modes}"
      args+=(--turn-url "$AVPN_TURN_URL_TLS" --turn-user "$AVPN_TURN_USER")
    fi
    "${args[@]}"
  done
done
