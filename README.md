# Adaptive VPN Path Selection Research Code

This repository contains the software and machine-readable experiment definitions
used to study adaptive path selection across encrypted network paths. It is a
code-only release: the dissertation, submission forms, rendered documents,
measurement datasets, credentials, and private infrastructure inventory are not
included.

## What Is Included

- `src/adaptive_vpn/`: installable experiment workflow, path-selection policies,
  UDP probes, WireGuard namespace control, immutable evidence bundles, and
  schedule handling.
- `analysis/`: validation-gated descriptive and confirmatory analysis.
- `experiments/`: controlled testbed and field-study definitions plus frozen
  local schedules.
- `scripts/`: schedule tools, Linux testbed helpers, field probes, and the
  bounded WebRTC measurement harness.
- `schemas/`: JSON contracts for packet, event, manifest, schedule, and analysis
  records.
- `tests/`: rootless unit/integration tests and separately marked root-only
  network-namespace tests.

## Evidence Boundary

The software records real observations only when an authorised experiment is
executed. Unit-test fixtures and controlled impairment settings are not empirical
results. This repository deliberately contains no raw or processed study data and
therefore does not, by itself, establish that one path-selection policy is better
than another.

Secrets are outside the repository boundary. Runtime manifests reject
secret-bearing keys, and the repository ignores private keys, local node
inventories, environment files, datasets, and generated output.

## Requirements

- Python 3.11 or newer
- Linux or WSL 2 for the WireGuard/network-namespace workflow
- `iproute2`, WireGuard tools, and root privileges for root-only tests
- Chromium/Chrome plus Selenium only for the optional WebRTC harness

## Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[runtime,analysis,dev]'
```

Install the optional browser/Janus tooling when needed:

```bash
python -m pip install -e '.[webrtc]'
```

## Verify

```bash
make verify
```

The root-only namespace/WireGuard checks are intentionally separate:

```bash
sudo --preserve-env=PATH make verify-netns
```

## Core CLI

```bash
adaptive-vpn doctor
adaptive-vpn plan experiments/plans/smoke.yaml
adaptive-vpn run experiments/plans/smoke.yaml --dataset smoke-local
adaptive-vpn validate data/raw --dataset smoke-local \
  --plan experiments/plans/smoke.yaml --require-complete
adaptive-vpn analyse --dataset smoke-local \
  --plan experiments/hypotheses.yaml
```

`run` is fail-closed: real collection requires a clean committed tree, the
required Linux capabilities, and a filesystem that supports atomic publication.
Published evidence bundles are immutable; retries receive new attempt identities.

## Private Node Configuration

Field and WebRTC scripts never contain a live host inventory. Start from the
documentation-only example:

```bash
cp config/nodes.example.json config/nodes.local.json
```

Fill `config/nodes.local.json` with authorised hosts, SSH users, and identity-file
paths. The local file is ignored by Git. Select it explicitly when running a
field helper:

```bash
export AVPN_NODES_FILE="$PWD/config/nodes.local.json"
python scripts/field_probe/client_tcp_rtt.py
python scripts/field_probe/run_media_allpairs.py output/media-allpairs.json
```

SSH helpers require pinned host keys in `~/.ssh/known_hosts` (or the path named by
`AVPN_KNOWN_HOSTS`). They do not disable host-key verification.

The WebRTC orchestration scripts similarly read endpoints and temporary TURN
credentials from environment variables. See the validation messages in
`scripts/webrtc_lab/run_remote_matrix.sh` and
`scripts/webrtc_lab/execute_remote_setup.sh` for the required names.

## Generate Registered Inputs

```bash
python scripts/freeze_schedules.py --check
python scripts/freeze_field_population.py \
  --design experiments/field-design.yaml \
  --write-dir build/field-population
```

Generated schedules, populations, measurements, and reports remain outside the
source release unless they are deliberately reviewed and published separately.

## Publication Scope

This repository has a fresh source-only Git history. It excludes all dissertation
text and binaries, university documents, submission packages, datasets, private
keys, credentials, and machine-specific runtime state.

No repository-wide open-source licence has been granted. Copyright remains with
the author unless a licence is added later.
