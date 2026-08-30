#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) -eq 0 ]]; then
  SUDO=()
else
  SUDO=(sudo)
fi

"${SUDO[@]}" apt-get update
"${SUDO[@]}" apt-get install -y --no-install-recommends \
  build-essential \
  iproute2 \
  iputils-ping \
  python3 \
  python3-dev \
  python3-pip \
  python3-venv \
  wireguard-tools

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[runtime,analysis,dev]'
.venv/bin/python -m pytest -q -m 'not netns'
