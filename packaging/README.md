# Packaging

Targets (Milestone 8, PRD section 14): a systemd unit (including the
early-boot permanent kill-switch restore unit ordered
`Before=network-pre.target`), a Nix package and NixOS flake module, and
Debian/Fedora/Arch packages — all produced from the single workspace
lockfile with reproducible builds and an SBOM.

Disposition of the PRD's Milestone-1 "SBOM, license, vulnerability, and
reproducibility skeleton" bullet: the **vulnerability** (cargo-audit with
a justified ignore policy) and **parity-manifest** gates ship in CI today;
the **SBOM, license-inventory, and reproducibility** skeletons are
deferred to M1.1 (tracked in `docs/review-log.md`) — see
`docs/review-log.md` for the full compliance triage.
