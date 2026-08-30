# Reproducibility Notes

The repository separates source code from evidence:

1. Experiment definitions and schedules describe intended work.
2. A run produces immutable raw bundles with configuration, schedule, code, and
   attempt identities.
3. Validation checks bundle structure, checksums, attempt chains, and the secret
   boundary.
4. Analysis consumes only validator-accepted terminal attempts and writes a new
   processed dataset.

No measurement dataset is distributed in this source-only repository. A user who
has an authorised apparatus can reproduce the workflow, but cannot reproduce the
original observations without the separately retained evidence bundles.

Run the rootless verification suite with:

```bash
make verify
```

Network-namespace and WireGuard tests create only bounded `avpn-*` resources and
must be run separately with the required privileges:

```bash
sudo --preserve-env=PATH make verify-netns
```

Never weaken atomic-publication, host-key pinning, clean-tree, or secret-boundary
checks for convenience. A failed or incomplete attempt must remain retained, and
a retry must receive a new attempt identity.
