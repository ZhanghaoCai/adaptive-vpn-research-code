#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 || $# -gt 5 ]]; then
  echo "usage: $0 PUBLIC_IP PRIVATE_IP TURN_USER TURN_PASSWORD [INTERFACE]" >&2
  exit 2
fi

PUBLIC_IP=$1
PRIVATE_IP=$2
TURN_USER=$3
TURN_PASSWORD=$4
REMOTE_INTERFACE=${5:-ens5}
WORK=/run/avpn-webrtc-tls
JANUS=/etc/janus/janus.jcfg
TURN=/etc/turnserver.conf
TEMPLATE=/tmp/avpn-coturn.conf.template

test -f "$TEMPLATE"
sudo test -f "$JANUS"
sudo install -d -m 0750 -o root -g turnserver "$WORK"

if ! sudo test -f "$JANUS.pre-avpn-webrtc"; then
  sudo cp -a "$JANUS" "$JANUS.pre-avpn-webrtc"
fi
if ! sudo test -f "$TURN.pre-avpn-webrtc"; then
  sudo cp -a "$TURN" "$TURN.pre-avpn-webrtc"
fi

sudo sed -i \
  -e 's|^[[:space:]]*#rtp_port_range = "20000-40000"|rtp_port_range = "30000-30199"|' \
  -e "s|^[[:space:]]*#nat_1_1_mapping = \"[^\"]*\"|nat_1_1_mapping = \"$PUBLIC_IP\"|" \
  -e "s|^[[:space:]]*#ice_enforce_list = \"eth0\"|ice_enforce_list = \"$REMOTE_INTERFACE\"|" \
  "$JANUS"

sudo openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
  -subj '/CN=AVPN bounded WebRTC lab root' \
  -keyout "$WORK/ca.key" -out "$WORK/ca.crt" >/dev/null 2>&1
sudo openssl req -newkey rsa:2048 -sha256 -nodes \
  -subj "/CN=$PUBLIC_IP" \
  -keyout "$WORK/server.key" -out "$WORK/server.csr" >/dev/null 2>&1
printf 'subjectAltName=IP:%s\nextendedKeyUsage=serverAuth\n' "$PUBLIC_IP" | \
  sudo tee "$WORK/server.ext" >/dev/null
sudo openssl x509 -req -sha256 -days 2 \
  -in "$WORK/server.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
  -CAcreateserial -extfile "$WORK/server.ext" -out "$WORK/server.crt" >/dev/null 2>&1
sudo chown root:turnserver "$WORK/server.key" "$WORK/server.crt"
sudo chmod 0640 "$WORK/server.key"
sudo chmod 0644 "$WORK/server.crt" "$WORK/ca.crt"

escaped_password=$(printf '%s' "$TURN_PASSWORD" | sed 's/[&|\\]/\\&/g')
escaped_user=$(printf '%s' "$TURN_USER" | sed 's/[&|\\]/\\&/g')
sed \
  -e "s|@PUBLIC_IP@|$PUBLIC_IP|g" \
  -e "s|@PRIVATE_IP@|$PRIVATE_IP|g" \
  -e "s|@TURN_USER@|$escaped_user|g" \
  -e "s|@TURN_PASSWORD@|$escaped_password|g" \
  "$TEMPLATE" | sudo tee "$TURN" >/dev/null
sudo chown root:turnserver "$TURN"
sudo chmod 0640 "$TURN"

sudo systemctl restart janus
sudo systemctl restart coturn
sleep 2
sudo systemctl is-active --quiet janus
sudo systemctl is-active --quiet coturn

dpkg-query -W janus coturn
sudo install -m 0644 "$WORK/ca.crt" /tmp/avpn-webrtc-ca.crt
sudo openssl x509 -in "$WORK/server.crt" -pubkey -noout | \
  openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | \
  base64 | tr -d '\n' | sudo tee /tmp/avpn-webrtc-spki.txt >/dev/null
sudo chmod 0644 /tmp/avpn-webrtc-spki.txt
sha256sum /tmp/avpn-webrtc-ca.crt | cut -d' ' -f1
