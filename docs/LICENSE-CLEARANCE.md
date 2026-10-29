# ProtonWire dependency license clearance

**Cleared: 2026-10-08** (owner decision)

- **protun** — GPLv3 `LICENSE` file bundled in the source repository
  (verified at tag `v3.0.1`, resolved revision `836715cd`, on
  2026-10-08; re-verified at the current pin, tag `v3.0.5` / resolved
  revision `a498c38a`, on 2026-10-29).
- **muon 3.0.0** and **pvpnclient 4.4.1** — cleared with the protun
  v3 train by owner decision (2026-10-08; the pvpnclient entry moved
  4.0.2 → 4.4.1 with the 2026-10-29 protun v3.0.5 sweep — its archive
  is licenseless on the same basis). Their published archives
  carry no license field and no bundled license text (verified
  2026-10-29 against the local Proton-registry cache: no `license`
  in `Cargo.toml`, no LICENSE/COPYING file, no README grant); the
  clearance rests on Proton's stated licensing of the v3 train and
  its GPLv3 Linux-client practice, not on bundled text. The NFR-37
  per-crate scan before the first shipped release re-verifies this.
- The remaining Proton-registry crates of the train are cleared on
  the same basis as muon/pvpnclient (also verified licenseless in
  their archives 2026-10-29).

Because no crate in the train publishes a `license` manifest field,
`cargo xtask license-scan` records all 17 names on the unlicensed
drift baseline: the set may not grow, and a crate that gains a
manifest license must shrink it. This resolves PRD OQ-2 and
NFR-35's distribution blocker. The pre-release SBOM and per-crate
license scan (NFR-37) remain before the first shipped release.

The `cargo xtask release-guard` command re-verifies the clearance
by re-running the live license scan against the current
`Cargo.lock` — stale clearance cannot pass (the scan fails on any
newly added unlicensed dependency).
