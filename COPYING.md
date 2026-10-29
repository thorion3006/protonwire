# ProtonWire licensing

Unless a file or bundled dependency says otherwise, ProtonWire is free software:
you may redistribute it and/or modify it under the terms of the GNU General
Public License as published by the Free Software Foundation, either version 3
of the License, or (at your option) any later version.

See [LICENSE](LICENSE) for the full GNU General Public License version 3 text.

ProtonWire is an independent project and is not affiliated with or endorsed by
Proton AG. Proton, Proton VPN, ProTUN, and other names may be trademarks of their
respective owners.

ProTUN and other third-party dependencies retain their own copyright notices and
license terms.

**License clearance 2026-10-08 (OQ-2 RESOLVED):** protun v3.0.1 bundles a
GPLv3 `LICENSE` file, and the Proton-registry dependency train (muon 3.0.0,
pvpnclient 4.0.2) is cleared with it — owner decision, evidence and scope
recorded in [docs/LICENSE-CLEARANCE.md](docs/LICENSE-CLEARANCE.md). Those
registry crates still publish no `license` manifest field or bundled license
text, so `cargo xtask license-scan` keeps all 17 names on the unlicensed
drift baseline. The distribution blocker is cleared; the pre-release SBOM
and per-crate license scan (PRD NFR-37) remain before the first shipped
release.
