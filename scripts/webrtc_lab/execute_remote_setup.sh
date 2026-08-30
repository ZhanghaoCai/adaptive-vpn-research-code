#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TURN_ENV=${AVPN_TURN_ENV:-/tmp/avpn-turn.env}
: "${AVPN_SSH_KEY:?AVPN_SSH_KEY is required}"
: "${AVPN_REMOTE_HOST:?AVPN_REMOTE_HOST must be user@host}"
: "${AVPN_PUBLIC_IP:?AVPN_PUBLIC_IP is required}"
: "${AVPN_PRIVATE_IP:?AVPN_PRIVATE_IP is required}"
: "${AVPN_KNOWN_HOSTS:?AVPN_KNOWN_HOSTS is required}"
: "${AVPN_REMOTE_INTERFACE:?AVPN_REMOTE_INTERFACE is required}"

test -f "$TURN_ENV"
test -f "$AVPN_SSH_KEY"
test -f "$AVPN_KNOWN_HOSTS"
# shellcheck disable=SC1090
source "$TURN_ENV"
: "${AVPN_TURN_USER:?AVPN_TURN_USER is required}"
: "${AVPN_TURN_PASSWORD:?AVPN_TURN_PASSWORD is required}"

SSH=(
  ssh -i "$AVPN_SSH_KEY"
  -o StrictHostKeyChecking=yes
  -o "UserKnownHostsFile=$AVPN_KNOWN_HOSTS"
  -o BatchMode=yes
)
SCP=(
  scp -q -i "$AVPN_SSH_KEY"
  -o StrictHostKeyChecking=yes
  -o "UserKnownHostsFile=$AVPN_KNOWN_HOSTS"
  -o BatchMode=yes
)

"${SCP[@]}" "$ROOT/scripts/webrtc_lab/coturn.conf.template" \
  "$AVPN_REMOTE_HOST":/tmp/avpn-coturn.conf.template
"${SCP[@]}" "$ROOT/scripts/webrtc_lab/deploy_overseas_components.sh" \
  "$AVPN_REMOTE_HOST":/tmp/deploy_overseas_components.sh
"${SSH[@]}" "$AVPN_REMOTE_HOST" chmod 700 /tmp/deploy_overseas_components.sh
"${SSH[@]}" "$AVPN_REMOTE_HOST" /tmp/deploy_overseas_components.sh \
  "$AVPN_PUBLIC_IP" "$AVPN_PRIVATE_IP" "$AVPN_TURN_USER" \
  "$AVPN_TURN_PASSWORD" "$AVPN_REMOTE_INTERFACE"
"${SCP[@]}" "$AVPN_REMOTE_HOST":/tmp/avpn-webrtc-ca.crt /tmp/avpn-webrtc-ca.crt
"${SCP[@]}" "$AVPN_REMOTE_HOST":/tmp/avpn-webrtc-spki.txt /tmp/avpn-webrtc-spki.txt

spki=$(cat /tmp/avpn-webrtc-spki.txt)
filtered=$(mktemp)
trap 'rm -f "$filtered"' EXIT
grep -v '^AVPN_TLS_SPKI=' "$TURN_ENV" > "$filtered"
printf 'AVPN_TLS_SPKI=%s\n' "$spki" >> "$filtered"
chmod 0600 "$filtered"
mv "$filtered" "$TURN_ENV"
trap - EXIT
