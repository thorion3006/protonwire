# ADR-0001: Single-Core Monorepo with Three First-Party Clients

- **Status:** Accepted
- **Date:** 2026-08-14
- **Decision owners:** ProtonWire maintainers
- **Related:** `docs/PRD-proton-wire.md`, `docs/official-parity.yaml`, `docs/connection-groups.yaml`

## Context

ProtonWire needs a headless automation interface, a rich terminal application, and a desktop application without creating three implementations of authentication, Proton API behavior, tunnel lifecycle, selection, profiles, or network policy. TUN, routing, DNS, nftables, split tunneling, and socket marking also require a privilege boundary that must survive any client exiting or crashing.

## Decision

ProtonWire will be developed and released from one monorepo. One `protonwire-core` application service owns all product behavior and authoritative state. A thin privileged `protonwire-daemon` hosts core and its Linux infrastructure adapters.

Three unprivileged first-party clients ship in v1:

1. `protonwire`: Clap CLI and automation interface.
2. `protonwire-tui`: Ratatui terminal application.
3. `protonwire-gui`: Tauri desktop application with bundled local UI assets.

All three clients use `protonwire-client`, the shared typed SDK for commands, queries, prompts, events, protocol negotiation, reconnect, and full-state resynchronization. The Tauri Rust shell is a narrow bridge from an allowlisted webview command surface to this SDK. An optional `protonwire-credential-agent` is a fourth process but not a client: it is a same-UID, policy-free broker for opaque Secret Service/KWallet records so the root daemon never adopts an arbitrary desktop D-Bus session.

```text
CLI ───────┐
Ratatui ───┼──> protonwire-client ──> versioned Unix IPC ──> daemon ──> core
Tauri ─────┘                                                     │
                                                                ├── Muon
                                                                ├── ProTUN
                                                                ├── netlink/nftables/DNS
                                                                ├── policy/NAT-PMP
                                                                └── secure storage ──> optional same-UID credential agent
```

## Invariants

- Core is the only application state machine and behavior implementation, including connection-group registry and resolution.
- The daemon owns privileges and process lifecycle, not a second set of product rules.
- Clients never link ProTUN, Muon, core, network adapters, or secure storage.
- The credential agent never links ProTUN, Muon, core, or policy. It accepts only the root daemon by Unix peer credentials, operates only on its own process UID, and exposes bounded opaque load/store/delete requests for allowlisted record kinds; a request cannot name another UID or arbitrary keyring operation.
- Clients never manipulate TUN, routes, DNS, nftables, socket marks, cgroups, or NAT-PMP directly.
- Client-specific code is limited to presentation, input, accessibility, desktop/terminal lifecycle, and automation formatting.
- Equivalent operations from all clients create equivalent typed core requests and converge on the same state and errors.
- Clients consume the generated connection-group catalog through the shared SDK and never carry independent preset or regional country lists.
- Closing or crashing a client does not disconnect or mutate the VPN.
- The CLI and TUI remain installable and usable without Tauri, WebKit, or a graphical session.
- One root Cargo workspace and `Cargo.lock` govern Rust builds. Any GUI package-manager lockfile is committed and frozen in CI.
- The host-global tunnel has one active owner UID. Account/profile data is namespaced by peer UID, and another user cannot inspect or mutate it without an explicit administrative transfer.
- systemd credentials are immutable provisioning input, not a writable credential backend and not a credential-migration target.
- A provisioned session may bootstrap an empty writable store only through an explicit, idempotent import; restart or rebuild never replays it over newer refreshed state.
- Per-UID configuration overlays are allowlisted requests validated by core and cannot change host-global, credential, refresh-budget, or administrator protection policy.

## Security Consequences

- The Tauri webview loads bundled assets only, uses a restrictive CSP and minimum capability allowlist, and exposes no generic shell, filesystem, HTTP, process, or arbitrary IPC bridge.
- Secret input is short-lived, never persisted in browser storage or terminal history, and redacted from logs, notifications, errors, analytics, and crash reports.
- Because core and Muon run in the root daemon, root is inside the authentication trust boundary; the design promises bounded/zeroized exposure and no propagation, not that a secret consumed by core is hidden from root.
- IPC authenticates both peers, validates bounded frames, negotiates a supported schema version, enforces per-method UID/owner authorization, and rejects unsafe downgrades.
- Pinned dependency logs are filtered before formatting, and production dependency trace logging is disabled because audited Muon/`pvpnclient` versions contain secret-bearing events.
- `Connect and Go` and browser handoffs execute as the requesting unprivileged user. The daemon returns an action intent but never launches a user application as root.

## Delivery Consequences

- CLI, TUI, and GUI are all v1 release artifacts, not sequential product generations.
- Feature work begins in core and schemas, then adds presentation in all applicable clients in the same change.
- A generated capability matrix and shared conformance harness block release when any client has an unexplained feature gap.
- TUI and GUI may be developed incrementally, but v1 is not complete until all three satisfy the parity contract.

## Rejected Alternatives

- Independent client implementations: rejected because security and feature behavior would drift.
- Embedding core directly in every client: rejected because privileged state would be duplicated and client failure could affect tunnel ownership.
- Letting the root daemon join a user's desktop D-Bus session for keyring access: rejected because it crosses user/session boundaries and makes headless behavior ambiguous.
- Treating `LoadCredential=` as application-managed storage: rejected because systemd credentials are immutable for a service lifetime and are provisioned outside ProtonWire.
- Making NetworkManager or systemd-networkd the VPN owner: rejected because either would become a hard architectural dependency.
- Shipping GUI or TUI after v1: rejected because all three are first-class ProtonWire clients.
