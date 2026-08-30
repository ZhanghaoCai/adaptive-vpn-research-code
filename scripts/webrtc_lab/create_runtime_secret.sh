#!/usr/bin/env bash
set -euo pipefail

umask 077
turn_user="avpn-$(openssl rand -hex 4)"
turn_password="$(openssl rand -hex 18)"
printf 'AVPN_TURN_USER=%s\nAVPN_TURN_PASSWORD=%s\n' \
  "$turn_user" "$turn_password" > /tmp/avpn-turn.env
echo "temporary TURN credentials created"
