#!/usr/bin/env bash
set -euo pipefail

JANUS=/etc/janus/janus.jcfg
TURN=/etc/turnserver.conf

if sudo test -f "$JANUS.pre-avpn-webrtc"; then
  sudo cp -a "$JANUS.pre-avpn-webrtc" "$JANUS"
fi
if sudo test -f "$TURN.pre-avpn-webrtc"; then
  sudo cp -a "$TURN.pre-avpn-webrtc" "$TURN"
fi
sudo systemctl stop janus coturn
sudo systemctl disable janus coturn >/dev/null 2>&1 || true
sudo rm -rf /run/avpn-webrtc-tls /tmp/avpn-webrtc-ca.crt /tmp/avpn-webrtc-spki.txt
echo "experiment services stopped and pre-experiment configurations restored"
