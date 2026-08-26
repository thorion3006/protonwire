# ProtonWire

A compiled, Linux-first Proton VPN client built as one Rust workspace,
reusing Proton's own engines: **ProTUN** as the tunnel/protocol engine and
**Muon** as the Proton API, authentication, session, and anti-censorship
transport. ProtonWire is a local VPN control plane — not a wrapper around
`wg-quick` — with a privileged daemon and three unprivileged first-party
clients (CLI, Ratatui TUI, Tauri GUI) speaking one versioned Unix-socket
frontend API.

Status: **Milestones 1 (Foundation) and 2 (Muon auth + server cache)
complete** — M1 merged to `master` via PR #3 (5baa12a); M2 merged via
PR #4 (5fd53d7, the current `master` tip). What builds and runs today:

- the M1 surface: the daemon, the versioned Unix-socket frontend API,
  CLI/TUI/GUI clients over the shared SDK, validated system
  configuration, repo-wide validation gates
- M2 authentication: Muon-backed SRP login with TOTP and FIDO2 second
  factor, session refresh/logout, external-session (fork) import —
  with secret-log suppression and a canary suite pinning that no
  secret class reaches any log writer
- M2 credential handling: interactive and systemd `LoadCredential`
  input; encrypted-local and Secret Service (keyring) writable session
  stores, fail-closed everywhere
- M2 server cache: catalog fetch with conditional (ETag) refresh, a
  strict-loaded on-disk cache, and a single-flight scheduler with
  persisted rate-limit suppression and warned manual-override
  confirmation; entitlement and user-location models over the same
  transport; per-UID configuration overlays; hardened IPC socket trust

Next per the PRD: Milestone 3 (server selection). Not present yet: any
tunneling (M4 ProTUN core is the first engine milestone) — connecting
is not possible in this tree today. The authoritative specification
set is:

- `docs/PRD-proton-wire.md` — the product requirements (normative)
- `docs/ADR-0001-monorepo-core-and-clients.md` — the architecture decision
- `docs/official-parity.yaml` — the official-client parity contract
- `docs/connection-groups.yaml` — the connection-group catalog
- `docs/spike-2026-08.md` — dependency spike decisions (M1) and the
  M2 addenda (Muon surface memo, wire-seam records, keyring audit)
- `docs/m2-plan.md` — the M2 unit plan (completed; see its header note)

## ⚠ Development builds only — no distribution

The pinned Proton registry crates `muon 2.6.1` and `pvpnclient 3.0.3`
carry no license manifest or bundled license text. Registry availability
does not grant redistribution rights. **No binary or source distribution
containing these crates may be published** until Proton supplies applicable
terms for them and every transitive Proton crate (`COPYING.md`, PRD OQ-2,
NFR-35). Building and running prototypes locally is fine.

## Layout

```
crates/     core (behavior owner)      frontend-api (wire schema, SoT)
            client (shared SDK)        ipc (Unix-socket transport)
            api (Muon adapter, M2)     protocol (ProTUN adapter, M4)
            net (netlink, M5)          policy (rules, M5/M7)
            pf (port forwarding, M6)   store (config/state/cache)
apps/       daemon · credential-agent · cli · tui · gui (Tauri)
xtask/      repo validation (parity manifest, groups, M49, dep graph, schemas)
resources/  vendored data (UN M49 snapshot)
schemas/    generated JSON Schemas for the frontend API
packaging/  systemd/Nix/Debian/Fedora/Arch packaging (M8)
```

Dependency direction is one-way: clients depend on `protonwire-client` and
frontend schemas only; the daemon depends on core; core depends on
infrastructure traits and adapters. `cargo run -p xtask -- dep-graph`
enforces this (PRD NFR-39).

## Building

ProtonWire builds on any mainstream Linux distribution — CI proves every
commit on stock Ubuntu runners. Two supported paths:

**Nix devshell (recommended, any distro with Nix installed)** — the
entire toolchain (rustc 1.97.1, cargo, rustfmt, clippy, gcc,
cargo-audit, git) comes from the repo, nothing installed system-wide.
With direnv it activates on entry:

```sh
direnv allow                # once: toolchain active in every shell here
PROTONWIRE_GUI=1 direnv allow   # opt in to the webkit2gtk stack:
                                # cargo check -p protonwire-gui works
```

Without direnv: `nix-shell` (or `nix-shell --arg gui true`).

**Plain distro toolchain (no Nix)** — any Rust 1.97+ toolchain works;
`rust-toolchain.toml` pins the version for rustup users:

```sh
rustup toolchain install 1.97.1   # or your distro's rustc >= 1.97
# C toolchain required (gcc/clang; the engine chain builds C code)
# GUI only: libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev \
#           libayatana-appindicator3-dev pkg-config
cargo build
```

The Proton sparse registry and the `cargo xtask` alias are configured in
`.cargo/config.toml`.

Toolchain floor: Rust ≥ 1.97 (edition 2024) — the Proton registry crates
the engines depend on do not compile below ~1.94 (probe record in
`docs/spike-2026-08.md`). The Proton sparse registry and the
`cargo xtask` alias are configured in `.cargo/config.toml`.

```sh
cargo build                 # everything except the GUI
cargo test                  # unit + in-process integration tests
cargo run -p xtask -- all   # repo validation suite
```

The Tauri GUI needs `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`,
`librsvg2-dev`, and `libayatana-appindicator3-dev`; CI builds it in a
dedicated job. It is a workspace member (single root `Cargo.lock`) but not
a default member.

## Running (development)

```sh
cargo run -p protonwire-daemon -- --socket-dir /run/user/$UID/protonwire  # unprivileged dev socket
PROTONWIRE_DEV_UNSAFE_SOCKET=1 \
  PROTONWIRE_SOCKET=/run/user/$UID/protonwire/protonwire.sock \
  cargo run -p protonwire-cli -- status
```

Stop the dev daemon with Ctrl+C (a stale socket is detected and removed by
the next start) or, as root, `protonwire daemon stop`.

Production sockets live at `/run/protonwire/protonwire.sock`, and clients
verify root ownership of the socket, its directory, and the connected
daemon peer. The development bypass variable is honored **only in debug
builds** and exists for per-user socket directories; release builds always
run the full checks.

## License

GPL-3.0-or-later (see `LICENSE` and `COPYING.md`).
