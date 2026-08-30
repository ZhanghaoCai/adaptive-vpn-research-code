# Frozen Real-Packet Experiment Protocol

**Protocol version:** 2.1-pre-main
**Decision date:** 2026-08-04
**Primary testbed:** local Linux/WSL network namespaces with three WireGuard tunnels

## Evidence Boundary

Every empirical observation is produced by an actual UDP datagram sent through a
real WireGuard interface in the bounded `avpn-*` namespace topology. `tc netem`
provides controlled impairment. This is real packet evidence from an emulated
local network, not public-Internet, encoded media, vendor telemetry, or human QoE
evidence. Random or fixed QoS values are forbidden outside automated tests.

## Registered Design

- Experimental unit: one registered schedule cell, represented by its terminal
  complete attempt.
- Factors: 6 scenarios x 2 packet-load profiles x 3 policies.
- Replication: 12 randomised complete blocks.
- Main population: 432 registered cells. The current plan permits at most two
  physical attempts per cell.
- Duplicate-attribution drain: 50 ms after all first echoes arrive. Missing
  first echoes use the registered profile response timeout instead. Every
  observation event records the logical workload window, response timeout,
  duplicate drain, actual window elapsed time, and cumulative observation time.
- Pairing key: `(block, scenario, traffic_profile)`.
- Primary endpoints: run-level mean RTT and round-trip UDP echo loss percentage.
- Secondary endpoints: p95/median RTT, RFC 3550-style RTT variation, switch count,
  and longest adjacent successful-packet arrival gap.
- Confirmatory contrasts: adaptive vs static and adaptive vs threshold for both
  primary endpoints; Holm correction across all four tests.
- Inference unit: block mean of paired cell differences, never individual packets.

## Apparatus Smoke And Pre-Main Amendment

The first real smoke dataset (`smoke-20260803`) contains three complete runs and
1,800 actual workload packets at Git commit
`608eba538104d53c15498c8b787970318a253926`. It is apparatus evidence only and is
permanently excluded from pilot and confirmatory populations.

The smoke exposed two design-level issues before pilot execution:

1. With weights 0.4/0.3/0.3, `min_score_threshold=0.6` allowed severe degradation
   in one dimension to be masked by two healthy dimensions. The threshold is now
   0.8, while the improvement margin, hold time, rate limit and weights remain
   unchanged.
2. At least one degraded window must be observed before a causal policy can
   switch. In a 12-second run those pre-switch packets exceed five percent of the
   packet population, so full-run p95 RTT remains near the degraded value even
   after a successful switch. Run-level mean RTT replaces p95 as the confirmatory
   latency estimand; p95 remains a reported secondary tail metric.

These changes are mechanical consequences of the registered score and endpoint
definitions, not selection of a favourable policy result. They were committed,
tested and assigned new config hashes and new cell/attempt identities before the
calibrated smoke, pilot, or main campaign. No first-smoke value is used to
estimate a main effect.

## Run Procedure

1. Require root, a clean code/config Git state, and no residual `avpn-*` resource.
2. Create two namespaces, three veth underlays, and three keyed WireGuard tunnels.
3. Start the validated UDP echo service in `avpn-server`.
4. Apply each phase's registered impairment symmetrically to its path underlay.
5. In every window, send concurrent monitoring packets on all paths and workload
   packets on the currently selected path from threads entered into `avpn-client`.
6. Apply a policy decision only to the following workload window and record its
   effective sequence number.
7. Close the server, capture links/routes/qdiscs/handshakes, hash all evidence,
   finalise as complete or incomplete, and perform bounded cleanup.

## Failure And Missing-Data Rules

- A setup, measurement, attribution, schema, checksum, or cleanup failure is not
  converted into a QoS observation.
- Incomplete evidence is retained with its reason and excluded from confirmatory
  analysis.
- Resume skips only a checksum-valid complete terminal cell. An incomplete cell
  receives a new UUIDv4 `attempt_id` linked by `supersedes_attempt_id`; it never
  overwrites an existing bundle.
- A protocol change after pilot requires a new protocol version, configuration
  hash, dataset ID, and schedule before any main run.
- Outliers are reported and retained. Apparatus or cleanup failures remain in
  the attempt ledger and trigger root-cause review; v1.2 does not silently
  exclude them or emit an unregistered sensitivity population.

## Campaign Gates

The calibrated smoke must complete all three strategies. The 12-run pilot must
pass hashes, pairing, packet attribution and apparatus checks and is analysed only
for reliability, timing and variance. The main campaign starts only after pilot
decisions are frozen in Git and uses the generated 432-entry schedule without
runtime parameter overrides.
