# ProtonWire dependency license clearance

**Cleared: 2026-10-08**

ProTUN v3.0.1 and the Proton-registry dependency train now carry
GPLv3-compatible licenses:

- **protun v3.0.1** — GPLv3 `LICENSE` file in the source repository
  (verified at tag `v3.0.1`, revision `1c3aa646`)
- **muon 3.0.0** — cleared with the protun v3 train
- **pvpnclient 4.0.2** — cleared with the protun v3 train

This resolves PRD OQ-2 and NFR-35's distribution blocker. The
pre-release SBOM and per-crate license scan (NFR-37) remain before
the first shipped release.

The `cargo xtask release-guard` command re-verifies the clearance
by re-running the live license scan against the current
`Cargo.lock` — stale clearance cannot pass (the scan fails on any
newly added unlicensed dependency).
