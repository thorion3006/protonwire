# ProtonWire

A compiled, Linux-first Proton VPN client built as one Rust workspace,
reusing Proton's own engines: **ProTUN** as the tunnel/protocol engine and
**Muon** as the Proton API, authentication, session, and anti-censorship
transport. ProtonWire is a local VPN control plane — not a wrapper around
`wg-quick` — with a privileged daemon and three unprivileged first-party
clients (CLI, Ratatui TUI, Tauri GUI) speaking one versioned Unix-socket
frontend API.

Status: **Milestone 1 (Foundation) in progress** on `feat/m1-foundation`.
The authoritative specification set is:

- `docs/PRD-proton-wire.md` — the product requirements (normative)
- `docs/ADR-0001-monorepo-core-and-clients.md` — the architecture decision
- `docs/official-parity.yaml` — the official-client parity contract
- `docs/connection-groups.yaml` — the connection-group catalog
- `docs/spike-2026-08.md` — Milestone 1 dependency spike decisions

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

Toolchain: Rust ≥ 1.85 (edition 2024), pinned in `rust-toolchain.toml`.
The Proton sparse registry is configured in `.cargo/config.toml`.

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
protonwire-daemon --socket-dir /run/user/$UID/protonwire   # unprivileged dev socket
PROTONWIRE_DEV_UNSAFE_SOCKET=1 PROTONWIRE_SOCKET=/run/user/$UID/protonwire/protonwire.sock \
  protonwire status
```

Production sockets live at `/run/protonwire/protonwire.sock`, and clients
verify root ownership of the socket and its parent directory; the
development bypass variable exists exactly for per-user socket directories
and is never set by packaged units.

## License

GPL-3.0-or-later (see `LICENSE` and `COPYING.md`).
