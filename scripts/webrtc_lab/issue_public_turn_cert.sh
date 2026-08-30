#!/usr/bin/env bash
set -euo pipefail

DOMAIN=${1:-${AVPN_TURN_DOMAIN:-}}
EMAIL=${2:-${AVPN_ACME_EMAIL:-}}
: "${DOMAIN:?pass a domain or set AVPN_TURN_DOMAIN}"
: "${EMAIL:?pass an ACME email or set AVPN_ACME_EMAIL}"

LEGO_DIR=${AVPN_LEGO_DIR:-/tmp/avpn-lego}
RUN_DIR=/run/avpn-webrtc-tls

command -v lego >/dev/null
sudo lego --path "$LEGO_DIR" --email "$EMAIL" --domains "$DOMAIN" \
  --accept-tos --tls run
sudo install -m 0640 -o root -g turnserver \
  "$LEGO_DIR/certificates/$DOMAIN.crt" "$RUN_DIR/public.crt"
sudo install -m 0640 -o root -g turnserver \
  "$LEGO_DIR/certificates/$DOMAIN.key" "$RUN_DIR/public.key"
sudo sed -i \
  -e 's|^cert=.*|cert=/run/avpn-webrtc-tls/public.crt|' \
  -e 's|^pkey=.*|pkey=/run/avpn-webrtc-tls/public.key|' \
  /etc/turnserver.conf
sudo systemctl restart coturn
sleep 2
sudo systemctl is-active --quiet coturn
openssl x509 -in "$LEGO_DIR/certificates/$DOMAIN.crt" -noout -issuer -dates
