# Packaging

Targets (Milestone 8, PRD section 14): a systemd unit (including the
early-boot permanent kill-switch restore unit ordered
`Before=network-pre.target`), a Nix package and NixOS flake module, and
Debian/Fedora/Arch packages — all produced from the single workspace
lockfile with reproducible builds and an SBOM.

Nothing here yet by design; this directory is the landing zone.
