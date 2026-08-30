#!/usr/bin/env bash
# Field-probe remote sweep. Supply the authorised inventory at runtime:
#   TARGETS='192.0.2.10 198.51.100.20' SELF_IP=192.0.2.10 \
#     bash scripts/field_probe/remote_sweep.sh
# Emits: target, ICMP loss, ICMP average RTT, TCP successes, TCP best RTT.
set -eu
SELF="${SELF_IP:?SELF_IP env required}"
TARGETS="${TARGETS:?TARGETS env required}"
PING_N=20
TCP_PORT="${TCP_PORT:-22}"

for ip in $TARGETS; do
  if [ "$ip" = "$SELF" ]; then
    echo -e "$ip\tself\t-\t-\t-"
    continue
  fi
  line=$(ping -c "$PING_N" -i 0.3 -W 1 "$ip" 2>/dev/null)
  loss=$(printf '%s\n' "$line" | grep -o '[0-9]\+% packet loss' | grep -o '^[0-9]*' | head -1)
  rtt=$(printf '%s\n' "$line" | grep 'rtt ' | sed -n 's/.*min\/avg\/max\/mdev = \([0-9.]*\)\/\([0-9.]*\)\/\([0-9.]*\)\/.*/\2/p' | head -1)
  [ -z "$loss" ] && loss="-"
  [ -z "$rtt" ] && rtt="-"
  ok=0; best="-"
  for i in 1 2 3; do
    t0=$(date +%s%N)
    if timeout 5 bash -c "exec 3<>/dev/tcp/$ip/$TCP_PORT" 2>/dev/null; then
      t1=$(date +%s%N); ms=$(( (t1 - t0) / 1000000 ))
      ok=$((ok + 1))
      if [ "$best" = "-" ] || [ "$ms" -lt "$best" ]; then best=$ms; fi
    fi
  done
  echo -e "$ip\t$loss\t$rtt\t$ok\t$best"
done
