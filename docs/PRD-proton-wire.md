# PRD: ProtonWire — ProTUN/Muon Proton VPN Client for Linux

**Document ID:** PRD-proton-wire<br>
**Version:** v0.6.1<br>
**Status:** Draft for Codex implementation<br>
**Target path:** `/docs/PRD-proton-wire.md`<br>
**Primary language:** Rust<br>
**Target OS:** Linux first<br>
**Protocol engine:** ProTUN (required)<br>
**Proton API engine:** Muon (required)<br>
**Protocol scope:** Smart Protocol, WireGuard UDP, WireGuard TCP, and Stealth through ProTUN<br>
**Linux integration:** Native netlink/nftables, NetworkManager, or systemd-networkd<br>
**Repository architecture:** Rust monorepo with one core and CLI, Ratatui TUI, and Tauri GUI clients<br>
**Parity baseline:** Union of applicable official Proton VPN client capabilities as of 2026-08-14<br>
**Last updated:** 2026-08-14

---

## 1. Executive Summary {#1-executive-summary}

ProtonWire is a compiled, Linux-first Proton VPN application built as one Rust monorepo. ProTUN is its required tunnel and protocol engine. Muon is its required Proton API, authentication, session, and anti-censorship transport layer. A single `protonwire-core` owns all application behavior and is hosted by the privileged daemon; three unprivileged first-party clients provide a CLI, a Ratatui TUI, and a Tauri desktop GUI over the same versioned client API.

The product must be feature-complete against the union of official Proton VPN clients where a service capability is technically applicable to Linux or a headless client. Platform-specific presentation is not copied literally; ProtonWire must provide equivalent core behavior and expose every applicable interactive capability through all three clients. The parity contract is versioned, testable, and updated when official clients add or remove capabilities.

The product must include:

- ProTUN-managed Smart Protocol, WireGuard UDP, WireGuard TCP, and Stealth
- Muon-managed Proton API transport, alternative routing, SRP login, session refresh, TOTP, FIDO2 payloads, and session forking; human-verification, SSO, and guest flows remain explicit upstream gates until their public integration surfaces are verified
- One Cargo workspace and lockfile containing the core, daemon, shared client SDK, CLI, Ratatui TUI, and Tauri GUI
- Authenticated free and paid plans, plan enforcement, and guest mode where the public Muon/API surface supports it
- Secure writable session storage with backend priority: a per-user keyring broker, TPM2-sealed local storage, then an explicitly enabled encrypted local fallback; systemd credentials are a separate read-only provisioning source for headless deployments
- Server discovery and metadata caching
- A core-owned connection-group catalog exposing Proton's official built-in selectors and presets plus ProtonWire regional groups
- Official Fastest selection by Proton's catalog score, plus an explicitly selected ProtonWire smart mode using load, locally measured latency, stability, feature constraints, preferences, and exclusions
- Fastest, random, country, state, city, exact server, P2P, Tor, Secure Core, and organization Gateway connection targets
- Official free-plan fastest/change-server behavior, including backend cooldowns
- Split tunneling by app, process, UID, GID, cgroup, IP/CIDR, domain, and port/protocol
- Best-effort attachment of already-running processes to split-tunnel policy, with an explicit warning that existing sockets cannot be reclassified reliably
- Custom DNS and Proton DNS modes
- Domain-based split tunneling
- NetShield selection
- Kill switch and advanced/permanent kill switch
- Secure Core in v1
- Port forwarding via NAT-PMP
- Moderate NAT
- VPN Accelerator option negotiation
- LAN access exceptions
- IPv4 and IPv6 routing
- Auto-connect and reconnect on failure
- Headless operation
- Full CLI, Ratatui TUI, and Tauri GUI clients in v1
- Machine-readable status output
- Full profiles: Standard, Secure Core, P2P, Tor, Gateway, connection-group targets, protocol and feature overrides, recents, pins, default connection, duplicate/import/export, and safe Connect and Go actions
- LocalAgent connection details, tunnel statistics, NetShield statistics, server restrictions, and packet capture with explicit consent
- Systemd integration
- Optional NetworkManager and systemd-networkd integration without making either a hard dependency
- NixOS support as a flake module
- Declarative and interactive login support on NixOS

The core differentiator is that ProtonWire must be reliable in headless and server environments while also integrating cleanly with desktop networking. It must not require a graphical session, NetworkManager, systemd-networkd, a desktop-only secret service, or GUI-specific assumptions. NetworkManager and systemd-networkd are optional uplink/integration adapters; neither owns the VPN tunnel or ProtonWire policy.

---

## 2. Background and Problem Statement {#2-background-and-problem-statement}

The existing Proton VPN Linux stack is Python-based and currently couples its production tunnel path to NetworkManager. Proton's ProTUN release makes its cross-platform Rust tunnel engine available, and Muon provides the shared Rust Proton API layer. This permits ProtonWire to reuse Proton's protocol behavior while replacing the Linux network-control layer that creates the hard NetworkManager dependency.

The target product must provide:

1. A compiled client.
2. No hard dependency on NetworkManager or systemd-networkd.
3. ProTUN for protocol execution and direct TUN, route, DNS, and firewall control by ProtonWire.
4. Versioned feature parity with the union of official Proton VPN clients where applicable to Linux.
5. Smarter server selection based on measurable performance and server metadata.
6. Optional feature flags, matching the GUI pattern where features are individually enabled or disabled.
7. Clean architecture suitable for NixOS, servers, containers, and minimal Linux distributions.

ProtonWire should behave as a local VPN control plane for Proton VPN, not merely as a wrapper around `wg-quick`.

---

## 3. Goals and Non-Goals {#3-goals-and-non-goals}

### 3.1 Goals {#31-goals}

**G-1:** Provide one Rust monorepo containing the ProtonWire core, privileged daemon, shared client SDK, CLI, Ratatui TUI, and Tauri GUI.

**G-2:** Use ProTUN as the required protocol engine and Muon as the required Proton API/authentication engine.

**G-3:** Preserve Proton's score-based Fastest semantics for official selectors and provide a separate ProtonWire smart-selection policy based on country, city, server, load, locally measured latency, stability, feature constraints, preferences, and exclusions.

**G-4:** Match the union of official-client service capabilities where technically applicable to Linux, including:

- Split tunneling
- DNS configuration
- NetShield
- Kill switch
- Advanced kill switch
- Secure Core
- Port forwarding
- Moderate NAT
- VPN Accelerator
- LAN access
- Auto-connect
- Smart Protocol, WireGuard UDP, WireGuard TCP, and Stealth
- Tor over VPN
- Organization Gateways and dedicated servers
- Profiles, recents, pins, default connection, and Connect and Go
- TOTP/recovery-code and FIDO2/WebAuthn 2FA, plan/cooldown enforcement, and SSO/human-verification only after the required public Muon and authorized browser handoff surfaces are verified
- Connection and NetShield statistics
- Packet capture with explicit consent
- P2P-aware server selection
- Streaming-aware server selection if server metadata exposes it
- Proton official built-in selectors and presets, including Anti-censorship and Fastest excluding my country

**G-5:** Provide strong headless support.

**G-6:** Provide explicit machine-readable output for scripts and automation.

**G-7:** Provide safe failure behaviour: no traffic leaks when kill switch is enabled.

**G-8:** Support NixOS, Debian, Ubuntu, Fedora, Arch, and generic systemd-based Linux distributions.

**G-9:** Use principle-of-least-privilege architecture.

**G-10:** Make every major feature testable by automated integration tests.

**G-11:** Support writable credential storage using this priority order when compatible with the deployment: per-user keyring through an unprivileged broker, TPM2-backed credential sealing, then an explicitly enabled encrypted local fallback. Support systemd credentials separately as immutable runtime input, not as a writable storage backend.

**G-12:** Include Secure Core in v1.

**G-13:** Include domain-based split tunneling in v1.

**G-14:** Attempt best-effort attachment of already-running processes to split-tunnel policy.

**G-15:** Provide NixOS support as a flake module.

**G-16:** Support `native`, `network-manager`, and `networkd` integration modes behind one Linux networking interface, with `auto` detection and identical security semantics.

**G-17:** Maintain an auditable official-parity manifest tied to upstream versions, documentation, capability tests, and known gaps.

**G-18:** Preserve ProtonWire's added capabilities beyond official clients: advanced smart selection, regional Fastest groups, granular split tunneling, headless operation, JSON/event APIs, declarative NixOS support, and safe kill-switch/split-tunnel coexistence.

**G-19:** Make `protonwire-core` the sole implementation of product behavior. The daemon hosts core with privileged platform adapters; the CLI, TUI, and GUI are presentation clients and must not reimplement VPN, policy, authentication, profile, or selection logic.

**G-20:** Ship the CLI, Ratatui TUI, and Tauri GUI together in v1 and enforce client capability parity through shared schemas and automated contract tests.

**G-21:** Expose one versioned, namespaced connection-group catalog from core so official Proton compatibility groups and ProtonWire-added groups have identical IDs and behavior in the CLI, TUI, GUI, profiles, auto-connect, status, and automation APIs.

### 3.2 Non-Goals {#32-non-goals}

**NG-1:** ProtonWire will not implement OpenVPN.

**NG-2:** ProtonWire will not use NetworkManager or systemd-networkd as a mandatory dependency or as the owner of the Proton tunnel. Both may be optional integration adapters.

**NG-3:** ProtonWire will not place business logic, Proton API logic, ProTUN integration, or privileged network operations in any client. Client-only presentation behavior is allowed.

**NG-4:** ProtonWire will not attempt to bypass Proton account plan restrictions.

**NG-5:** ProtonWire will not scrape private APIs in a brittle way when official, documented, or legally reusable client API behaviour can be used instead.

**NG-6:** ProtonWire will not store account credentials in plaintext.

**NG-7:** ProtonWire will not guarantee feature availability if Proton’s backend, account plan, protocol support, or server metadata does not expose the required capability.

**NG-8:** ProtonWire will not reimplement WireGuard, WireGuard TCP, Stealth, Smart Protocol, Proton certificate refresh, or LocalAgent protocol behavior outside ProTUN unless an upstream defect requires a temporary, documented compatibility shim.

**NG-9:** ProtonWire will not claim parity based only on a visible toggle. A feature is complete only when entitlement checks, connection negotiation, failure handling, status, tests, and documentation work end to end.

**NG-10:** ProtonWire will not clone platform-only presentation such as mobile widgets, TV layouts, browser-extension proxy UI, or OS-native VPN settings screens. It must implement equivalent service behavior when that behavior is applicable to Linux.

**NG-11:** ProtonWire will not promise legacy OpenVPN or IKEv2 parity. Proton Protocols are the transport baseline; legacy protocols may be imported only as an explicitly separate compatibility project.

---

## 4. Personas {#4-personas}

### 4.1 Linux Desktop Power User {#41-linux-desktop-power-user}

Uses Arch, Fedora, Debian, Ubuntu, or NixOS. Wants Proton VPN but does not want NetworkManager. Uses custom DNS, split tunneling, and CLI automation.

### 4.2 Headless Server User {#42-headless-server-user}

Runs a VPS, homelab server, or NixOS host. Wants auto-connect, kill switch, port forwarding, and reliable reconnect after boot or network loss.

### 4.3 Privacy-Sensitive User {#43-privacy-sensitive-user}

Requires advanced kill switch, DNS leak prevention, IPv6 handling, minimal logs, and no GUI dependencies.

### 4.4 Automation / DevOps User {#44-automation-devops-user}

Needs JSON output, predictable exit codes, systemd integration, and declarative configuration.

### 4.5 Torrent / P2P User {#45-torrent-p2p-user}

Needs P2P-capable server selection, NAT-PMP port forwarding, forwarded port display, and optional split tunneling.

### 4.6 NixOS User {#46-nixos-user}

Wants a flake module, declarative profiles, declarative or interactive login, and compatibility with sops-nix/agenix and systemd LoadCredential.

### 4.7 Interactive Desktop and Terminal User {#47-interactive-desktop-and-terminal-user}

Wants the same ProtonWire capabilities through a keyboard-first Ratatui interface or a polished Tauri desktop application, with live connection state, accessible controls, secure prompts, and no behavioral differences from the CLI.

---

## 5. Product Scope {#5-product-scope}

### 5.1 v1 Scope {#51-v1-scope}

The v1 release must include:

- Rust CLI binary: `protonwire`
- Ratatui TUI binary: `protonwire-tui`
- Tauri desktop GUI: `protonwire-gui`
- Rust daemon binary: `protonwire-daemon`
- Stable, versioned Unix-socket frontend API so CLI, TUI, GUI, and automation clients share one capability surface
- ProTUN as the only production protocol engine
- Muon as the only production Proton API/auth/session transport
- Smart Protocol, WireGuard UDP, WireGuard TCP, and Stealth
- Proton SRP login, TOTP/recovery-code and FIDO2 2FA, session, logout, and entitlement support; human verification, SSO, and guest mode only when their public, authorized integration surfaces are verified
- Writable credential storage using a per-user keyring broker, TPM2, or explicit encrypted fallback, plus read-only systemd credential provisioning
- Server metadata retrieval and caching
- Smart server selection
- Official Proton connection groups and presets, plus Fastest Africa, Asia, Europe, North America, South America, and Oceania groups
- Fastest, random, free change-server, country, state, city, exact server, P2P, Tor, Secure Core, and Gateway connect commands
- Secure Core connection support
- Kill switch
- Advanced kill switch
- DNS management
- Domain-based split tunneling
- NetShield mode selection
- VPN Accelerator toggle
- Moderate NAT toggle
- Port forwarding via NAT-PMP
- Split tunneling by process, app, UID, GID, cgroup, IP/CIDR, domain, and port/protocol
- Best-effort attachment of already-running processes to split-tunnel policy
- LAN access exceptions
- IPv4 and IPv6 support
- Official-style profiles, recents, pins, default connection, and Connect and Go
- Connection statistics, NetShield statistics, packet capture, redacted debug bundles, and opt-in crash reporting
- Native, NetworkManager, and systemd-networkd integration modes
- Systemd units
- NixOS flake module
- NixOS declarative and interactive login support
- Config file support
- JSON output
- Structured logs
- Nix package expression

### 5.2 v1.1 Scope {#52-v11-scope}

- Profile import/export hardening
- Latency history database
- Server health scoring history
- Prometheus metrics endpoint
- Shell completions
- Additional desktop integrations beyond the v1 tray and notification baseline

### 5.3 v2 Scope {#53-v2-scope}

- Advanced Secure Core route optimization
- Secure Core multi-hop policy preferences
- Cross-platform daemon abstraction
- macOS support
- Windows support
- Browser extension integration

### 5.4 Official Client Parity Contract {#54-official-client-parity-contract}

“Feature complete” means parity with the union of service capabilities exposed by Proton's maintained Windows, macOS, Android, iOS/iPadOS, Linux GUI, and Linux CLI clients, when the capability can sensibly exist on Linux. The v1 core must implement every required capability, and the CLI, Ratatui TUI, and Tauri GUI must each expose every applicable interactive capability without changing daemon behavior.

The repository must contain a machine-readable `docs/official-parity.yaml` manifest. Every entry must record directly or inherit from an explicit manifest default:

- Stable capability ID
- User-visible behavior and entitlement
- Official source URLs and upstream client/release revisions
- Responsible ProtonWire component
- Required client surfaces inherited from the manifest's default client contract, plus any justified per-capability presentation-only override
- Status: `required`, `implemented`, `verified`, `blocked-upstream`, `not-applicable`, or `legacy-excluded`
- Protocol and network-integration test coverage
- Last evidence-review date and any known semantic difference; a `verified` entry must additionally record its own verification date

The repository must also contain `docs/connection-groups.yaml`. It is the machine-readable catalog of built-in group IDs, labels, origins, immutable selector/override semantics, source revisions, and regional taxonomy. Core generates its group registry from that contract; clients must not carry independent preset lists.

The baseline capability set is:

| Area | Required ProtonWire parity |
|---|---|
| Account | Proton account login, SRP through Muon, TOTP/recovery-code and FIDO2/WebAuthn 2FA, session refresh/logout, plan and organization entitlements, and device/session-limit errors; browser/human verification, SSO, and guest mode are tracked as upstream-gated capabilities until a public authorized flow is verified |
| Protocols | Smart Protocol plus manual WireGuard UDP, WireGuard TCP, and Stealth selection through ProTUN; protocol/port fallback and network-change recovery |
| Locations | Fastest, Fastest excluding my country, random, country, state/region, city, exact logical/physical server, search, server load/status, and paid/free selection rules |
| Connection groups | Proton-compatible built-in selectors and presets (including Anti-censorship, Streaming US, Gaming, Max Security, and Work/School), plus namespaced ProtonWire regional Fastest groups; immutable definitions may be copied into editable user profiles |
| Special servers | Secure Core entry/exit selection, P2P, Tor over VPN, streaming metadata, organization Gateways, and dedicated servers |
| Free plan | Fastest eligible free server, backend-selected random change server, cooldown countdown, and clear upgrade/entitlement errors |
| Profiles | Create, edit, duplicate, delete, import/export, Standard/Secure Core/P2P/Tor/Gateway targets, fastest/random/exact scopes, per-profile protocol and feature overrides, recents, pins, and default/last connection |
| Connect and Go | Open a validated URL or launch an explicitly configured application after connection from the invoking unprivileged frontend; the root daemon must never execute this action |
| Protection | Standard and advanced/permanent kill switch, DNS and IPv6 leak prevention, explicit LAN allow/block, reconnect fail-closed behavior, and always-on boot semantics |
| DNS and filtering | Proton DNS, custom IPv4/IPv6 DNS, NetShield off/malware/ads-trackers/adult levels, server-applied setting confirmation, incompatibility handling, and NetShield block/data-saved statistics |
| Connection options | VPN Accelerator, strict/moderate NAT, port forwarding with automatic NAT-PMP lease renewal and current-port publication, IPv4/IPv6, and server-probed MTU |
| Split tunneling | Official include/exclude app and IP/CIDR behavior plus ProtonWire's process, UID, GID, cgroup, domain, and port/protocol rules; safely attach already-running processes where possible |
| Lifecycle and diagnostics | Auto-start, auto-connect, reconnect, connectivity-change handling, duration, entry/exit IP, protocol/port, load, RX/TX, RTT/loss/handshake statistics, automatic route/DNS/firewall/VPN conflict detection, upstream-gated connection feedback, redacted logs/debug bundles, bounded opt-in packet capture, and opt-in crash reports |

The following are deliberately excluded from parity:

- OpenVPN and IKEv2, because Proton Protocols are the architectural transport baseline and Proton is retiring legacy transports from official apps.
- Mobile widgets, TV/browser-extension layouts, OS-native settings screens, and map animations. Equivalent connect/status actions remain required through ProtonWire frontends.
- Subscription purchase, organization administration, or account-security administration that official clients hand off to Proton web properties. ProtonWire must provide the same safe web handoff, not reproduce the account portal.

A capability may be marked `verified` only when it:

1. Builds from publicly obtainable, pinned dependencies.
2. Enforces plan and backend policy without bypasses.
3. Negotiates and confirms the server-applied state when applicable.
4. Appears in human-readable and JSON status/event output.
5. Has unit plus integration or end-to-end coverage for success, refusal, reconnect, and cleanup.
6. Works in `native` mode and has adapter conformance tests for NetworkManager and systemd-networkd when those adapters are installed.
7. Passes the shared CLI/TUI/GUI client contract for every client-applicable action, state, prompt, error, and event.

Upstream parity must be reviewed for every ProTUN/Muon update and at least once per ProtonWire release. A new official capability becomes `required` unless it is explicitly documented as `not-applicable` or `legacy-excluded` with rationale. The initial manifest is a provisional inventory: no capability may become `verified`, and no release may claim full official-client parity, until a capability-by-capability diff has been completed against every pinned Windows, Android, iOS/macOS, Linux GUI, and Linux CLI baseline revision.

---

## 6. System Architecture {#6-system-architecture}

### 6.1 Components {#61-components}

The dependency boundary in `docs/ADR-0001-monorepo-core-and-clients.md` is normative.

```text
protonwire
  Unprivileged Clap-based CLI client and automation interface.

protonwire-tui
  Unprivileged Ratatui client with keyboard-first navigation, live events,
  prompts, profiles, server browsing, and full interactive capability parity.

protonwire-gui
  Unprivileged Tauri desktop client. Its Rust shell is a narrow client-SDK
  bridge; its webview contains presentation code only.

protonwire-client
  Shared unprivileged Rust SDK used by all three clients. Handles IPC,
  typed commands, subscriptions, reconnect/resync, prompts, and view models.

protonwire-credential-agent
  Optional unprivileged per-user broker for Secret Service/KWallet storage.
  It stores and returns opaque credential envelopes over a narrow,
  peer-authenticated protocol and contains no authentication or VPN policy.

protonwire-frontend-api
  Versioned Unix-socket API and event stream shared by CLI, TUI, GUI, and
  automation clients. Uses peer credentials and per-method authorization.

protonwire-daemon
  Thin privileged host for protonwire-core. Owns process lifecycle, Linux
  capabilities, the Unix socket, TUN file descriptors, and system integration;
  it does not contain a second implementation of product behavior.

protonwire-core
  Authoritative application service and state machine. Owns authentication,
  connection orchestration, config, validation, connection groups, selection, profiles,
  entitlements, feature negotiation, policy, persistence, and status/events.
  All user-visible operations enter through its typed command/query interface.

protonwire-protocol
  Infrastructure adapter used only by core around pinned ProTUN APIs. Translates
  peer candidates, LocalAgent settings, states, statistics, and sockets without
  leaking ProTUN types into clients or public IPC schemas.

protonwire-api
  Infrastructure adapter used only by core around pinned Muon APIs for
  login/session state, Proton API requests, alternative routing, metadata,
  certificates, entitlements, Gateways, and free-plan policy.

protonwire-ipc
  Unix-domain socket protocol shared by protonwire-client and the daemon.

protonwire-net
  Linux networking module: TUN creation, netlink, routing tables, nftables,
  socket marks, DNS, and pluggable uplink integration adapters.

protonwire-policy
  Pure rule evaluation and compilation used only by core for split tunneling,
  kill switch, LAN, DNS, and server selection; it has no independent state,
  daemon entrypoint, or client-facing behavior.

protonwire-pf
  NAT-PMP client and port forwarding lease renewal manager.

protonwire-store
  Core persistence adapter and secure implementation of ProTUN's PersistentCache:
  Muon sessions, certificates, private keys, metadata cache, profiles, and latency DB.
  Its keyring implementation talks only to protonwire-credential-agent; the
  privileged daemon never joins an arbitrary user's desktop D-Bus session.
```

The repository must use one Cargo workspace, one root `Cargo.lock`, shared lint/profile settings, and atomic CI. The normative layout is:

```text
protonwire/
├── Cargo.toml
├── Cargo.lock
├── crates/
│   ├── core/                 # sole application behavior and state machine
│   ├── frontend-api/         # public command/query/event schema
│   ├── client/               # shared unprivileged client SDK and view models
│   ├── ipc/                  # Unix-socket framing, auth, version negotiation
│   ├── api/                  # Muon adapter
│   ├── protocol/             # ProTUN adapter
│   ├── net/                  # Linux TUN/netlink/nftables/DNS adapters
│   ├── policy/               # routing, split tunnel, kill switch, LAN policy
│   ├── port-forwarding/      # NAT-PMP lease manager
│   └── store/                # credentials, cache, profiles, persistent state
├── apps/
│   ├── daemon/               # privileged protonwire-daemon host
│   ├── credential-agent/     # optional unprivileged keyring broker, not a client
│   ├── cli/                  # Clap client: protonwire
│   ├── tui/                  # Ratatui client: protonwire-tui
│   └── gui/
│       ├── src-tauri/        # Tauri shell and client-SDK bridge
│       └── ui/               # bundled webview presentation assets
├── packaging/
├── docs/
└── xtask/                    # code generation, parity, packaging, release tasks
```

Dependency direction is one-way: clients depend on `protonwire-client` and frontend schemas; the daemon depends on `protonwire-core`; core depends on infrastructure traits and adapters. Core and adapters must never depend on a client, Ratatui, Tauri, webview code, or client presentation model.

### 6.2 Privilege Model {#62-privilege-model}

The CLI, TUI, GUI, Tauri webview, credential agent, and shared client SDK must run unprivileged. The daemon is a root trust boundary because it hosts core, Muon, and the ProTUN cache; secret values sent to it cannot be cryptographically hidden from root. It must run as root or under a separately reviewed capability/delegation model and minimize how long authentication secrets remain in memory.

The base network path requires:

```text
CAP_NET_ADMIN
```

`CAP_NET_RAW` is optional only for an explicitly enabled ICMP latency-probe implementation; TCP/UDP probing is the default. `CAP_DAC_READ_SEARCH` is not permitted. Any additional capability requires a documented operation-by-operation justification and a systemd sandbox regression test. Capability bounding does not replace method authorization or multi-user isolation.

### 6.3 IPC Model {#63-ipc-model}

All three clients must communicate with the daemon through `protonwire-client` over Unix-domain socket IPC with peer credential checks. Clients must also verify that the peer and socket are owned by root and that the socket path is not replaceable by an untrusted user. They must use the same protocol version negotiation, command/query types, prompt flow, event sequence numbers, reconnect behavior, and full-state resynchronization.

Default socket path:

```text
/run/protonwire/protonwire.sock
```

The daemon controls one host-global tunnel. Core must namespace account/profile data by authenticated Unix UID, designate an active connection owner, and reject conflicting mutations from another user unless an administrator explicitly transfers ownership. Read-only status must be redacted for non-owners. A root-owned socket group grants access to IPC, not implicit authority to read another user's account data or disconnect their tunnel.

D-Bus/PolicyKit integration may be added later, but must not be required for headless operation. The optional credential-agent protocol is separate from frontend IPC. The daemon authenticates the agent's Unix UID, the agent accepts only the authenticated root daemon, and the agent's own UID is the implicit account namespace; neither side accepts a caller-supplied target UID. The protocol permits only bounded opaque load/store/delete operations over allowlisted record kinds.

### 6.4 Process Boundary {#64-process-boundary}

No frontend may directly manipulate TUN devices, routing, DNS, nftables, socket marks, or NAT-PMP. No frontend may link ProTUN or Muon, access core persistence directly, or invent policy decisions. All product operations must go through the shared client SDK and daemon-hosted core. Authentication prompts and Connect and Go actions originate in an unprivileged frontend. Authentication secrets are passed to core only through a dedicated bounded IPC field, held briefly in best-effort locked/zeroized memory, and never placed in argv, environment variables, URLs, a shell, logs, or persistence by default. Browser navigation and application launch remain entirely unprivileged.

### 6.5 ProTUN and Muon Core {#65-protun-and-muon-core}

ProTUN is the required production tunnel engine. The daemon must:

1. Create and configure a Linux TUN device, default name `protonwire0`.
2. Pass an owned TUN file descriptor to `Connection::unix_connect` or its current equivalent.
3. Convert selected logical/physical servers into prioritized ProTUN peer candidates with UDP, TCP, and TLS ports.
4. Use ProTUN LocalAgent mode in production so certificates, server-applied features, restrictions, exit IPs, MTU, and statistics are available.
5. Implement ProTUN's three-value persistent cache (`Certificate`, `PrivateKey`, and its internal LocalAgent `ApiSession`) using a preloaded, bounded facade over ProtonWire's approved encrypted storage. These values are distinct from ProtonWire's top-level Muon account session and must not overwrite or alias it.
6. mark or policy-route every outer transport socket received through ProTUN's socket-FD callback so it bypasses the tunnel without bypassing kill-switch policy.
7. Forward physical-connectivity changes to ProTUN and treat its state/event callbacks as the authoritative protocol state.
8. Keep all ProTUN-specific types behind `protonwire-protocol` so an upstream beta API change is localized.

Muon is the required production Proton API transport and authentication layer. ProtonWire must use it for SRP login, TOTP/FIDO2 payload submission, session state, cookies, normal Proton API requests, alternative routing, and session-fork flows wherever the public crate exposes those operations. ProtonWire-owned typed models may describe VPN endpoints Muon does not model; they must still be sent through Muon rather than a second Proton HTTP/auth stack. Human verification, organization SSO, guest login, feedback, and other flows absent from the pinned public surface must remain `blocked-upstream` until an authorized implementation is documented.

Muon account authentication must create a child fork selector for ProTUN LocalAgent rather than sharing serialized account tokens with ProTUN's `ApiSession` cache. ProTUN's development-only `test_utils` login helper is forbidden in production.

The application must not use:

- `wg-quick`
- a separately implemented kernel WireGuard or `wireguard-go` production tunnel path
- Proton's Python API/networking packages in production
- resolvconf as a mandatory dependency
- desktop network applets

ProTUN commit `12e7755a112f59b7b843da79290b3de25febf653` (tagged `v2.2.1`) is the initial pin. That source tag does not include a Cargo lockfile, so ProtonWire's committed root lockfile is the authority: it initially resolves Muon `2.6.1` and `pvpnclient` `3.0.3` with their registry checksums. Upgrades require adapter tests, parity tests, dependency-license review, and release notes. Packet capture is disabled by default, size-bounded, permission-restricted, and requires explicit user action for each capture.

### 6.6 Linux Network Integration {#66-linux-network-integration}

ProtonWire owns the VPN TUN interface and all privacy policy in every mode. The configured integration mode controls only how ProtonWire discovers and reacts to the physical uplink and how it cooperates with the host's DNS/network manager.

```text
auto             Select NetworkManager when it owns the default uplink, otherwise
                 networkd when it owns the default uplink, otherwise native.
native           Observe netlink directly; configure addresses/routes with netlink,
                 DNS through resolved when available or a safe direct adapter.
network-manager  Observe NetworkManager connectivity/default-route/DNS state over
                 D-Bus; ProtonWire still owns protonwire0, nftables, and policy routes.
networkd         Observe systemd-networkd over D-Bus/netlink and cooperate with
                 systemd-resolved; ProtonWire still owns the tunnel and policy.
```

Each adapter must implement the same interface:

- Discover default-route interfaces, gateways, DNS domains, and connectivity state.
- Notify the daemon of link, address, route, and network-switch events.
- Install and remove only ProtonWire-owned state, tagged so cleanup is idempotent.
- Detect manager restart and reconcile without a leak window.
- Avoid changing the user's existing uplink profiles or `.network` files.
- Produce the same kill-switch, split-tunnel, DNS-leak, and IPv6-leak guarantees.

NetworkManager and systemd-networkd packages are optional. Selecting an unavailable explicit adapter is a configuration error; `auto` falls back safely to the next applicable adapter and reports the chosen mode in status.

---

## 7. Functional Requirements {#7-functional-requirements}

### 7.1 Authentication and Account Session {#71-authentication-and-account-session}

**FR-1:** The app must support Proton account login through a secure flow.

**FR-2:** The app must store access tokens securely.

**FR-3:** The app must refresh sessions automatically before expiry.

**FR-4:** The app must support logout that removes local credentials and tokens.

**FR-5:** The app must expose account plan and entitlement information.

**FR-6:** The app must prefer token storage over raw password storage.

**FR-7:** The app must detect whether the account supports paid-only features such as NetShield modes, split tunneling, Secure Core, and port forwarding.

**FR-7K:** Muon must be the sole production implementation of Proton authentication, session refresh, cookies, API forking, and alternative-routing behavior.

**FR-7L:** The login state machine must implement the flows actually exposed by pinned Muon: SRP username/password login, TOTP or recovery-code submission, FIDO2 request/response payload submission, refresh/logout, external-session import, and session forking. ProtonWire must perform the WebAuthn ceremony through a reviewed native or local-browser handoff. Human verification, password re-entry variants, SSO, and unknown challenges must fail closed with stable machine-readable codes unless their public Muon/API continuation contract has been separately verified.

**FR-7M:** Authentication must be modeled separately from VPN connection authorization. ProTUN LocalAgent wait/jail states such as low plan, disabled user, pending invoice, session over limit, VPN 2FA, and client challenge must be surfaced without allowing unrestricted traffic.

**FR-7N:** If Muon exposes Proton VPN guest sessions on Linux, the app must support guest mode with an ephemeral encrypted cache and no invented identity. Until then the parity manifest must record `guest-mode` as `blocked-upstream`, not silently omit it.

**FR-7O:** Organization SSO must remain `blocked-upstream` until ProtonWire can prove an authorized public flow for initiating the browser handoff, binding it to a nonce, importing/forking the resulting session, handling cancellation, and logging out. Gateway/dedicated-server entitlements for an otherwise authenticated organization account remain required independently of SSO.

**FR-7P:** Pinned Muon `2.6.1` emits a TOTP value at `info` level, and pinned `pvpnclient` `3.0.3` can emit fork selectors and cookies at `trace`. Release logging must suppress the affected module events before formatting, keep dependency `trace` disabled in production, and pass canary-secret tests for passwords, TOTP/recovery codes, FIDO payloads, usernames, session IDs, selectors, cookies, tokens, fingerprints, and private keys. Regex-only post-processing is insufficient as the sole control.

**Acceptance Criteria**

```gherkin
Given the user is not authenticated
When the user runs "protonwire login"
Then the CLI starts a supported login flow
And no raw password is persisted unless explicitly requested
And secure tokens are stored using the configured writable session store
```

```gherkin
Given the stored session has expired
When the user runs "protonwire connect fastest"
Then the daemon refreshes the session
And the connection proceeds without requiring a new login
```

```gherkin
Given Muon reports that a supported TOTP or FIDO2 challenge is required
When the user logs in from an interactive frontend
Then the frontend completes the typed or reviewed WebAuthn handoff challenge through bounded secret IPC to core
And the resulting refreshable session is stored through the approved writable session store
```

```gherkin
Given Muon or the Proton API returns human verification, SSO, or an unknown challenge without a verified continuation adapter
When login is attempted
Then ProtonWire returns a stable upstream-capability-blocked or unsupported-challenge error
And does not retry, open an untrusted URL, or approximate the flow
```

```gherkin
Given LocalAgent reports a hard jail or a server-applied setting refusal
When a connection is being established
Then the kill switch remains enforced
And status exposes the stable reason and required user action
And ProtonWire does not claim that the refused feature is active
```

### 7.1A Credential Storage and Password Handling {#71a-credential-storage-and-password-handling}

**FR-7A:** ProtonWire must support optional password storage, but a refreshable Muon session envelope is the default persisted credential. Password persistence is never required for normal reconnect.

**FR-7B:** For writable persistent session storage, `auto` must consider only backends usable in the current deployment and use this order:

```text
1. Per-user Secret Service/KWallet keyring through protonwire-credential-agent
2. TPM2-sealed encrypted local store
3. Explicitly enabled encrypted local store with a key not stored beside the ciphertext
```

systemd `LoadCredential=`/`LoadCredentialEncrypted=` is not in this list: systemd credentials are immutable, service-lifetime input files supplied by an administrator. ProtonWire consumes them but cannot select, update, or migrate data "to LoadCredential".

**FR-7C:** The app must prefer storing a versioned Muon session envelope over storing the raw password. ProtonWire's account-session envelope and ProTUN's internal LocalAgent `ApiSession` cache entry are different records with independent schema/version checks.

**FR-7D:** If raw password storage is explicitly enabled by the user, every client must display a warning and require confirmation unless a non-interactive `--yes` is provided; `--yes` still emits the warning to stderr/events.

**FR-7E:** The app must support headless-safe writable storage without a desktop keyring. `auto` may skip an unavailable keyring only with a recorded reason; an explicitly selected backend must fail instead of falling through.

**FR-7EA:** `none` is an explicit no-persistence store for an ephemeral session. If `auto` finds no approved writable store, it must return a confirmation requirement before continuing as `none`, mark restart persistence unavailable, and disable credential-dependent boot auto-connect unless a provisioned systemd session is available. It must never retain the raw password to compensate.

**FR-7F:** The daemon must consume optional systemd credentials relative to `$CREDENTIALS_DIRECTORY` using configured short names. Supported inputs are a preferred versioned session envelope or username/password bootstrap credentials. They are read once, never modified, never treated as a writable backend, and never copied to another store unless an administrator explicitly imports them.

**FR-7G:** TPM2-backed storage must seal credentials to a documented local-machine policy and provide a tested recovery/reseal procedure for expected kernel, initrd, Secure Boot, and PCR changes.

**FR-7H:** `protonwire account --json` must separately expose `credential_input_source`, `writable_session_store`, persistence health, account owner UID, and whether restart-time authentication is available; it must not expose secret names or values to unauthorized users.

**FR-7I:** The app must allow an explicit, transactional migration between writable backends. Migration to a systemd credential source is invalid. Importing a systemd-provisioned session into a writable store is a separate confirmed operation.

**FR-7J:** The app must fail safely if a configured source or store becomes unavailable. A persistence write failure must be surfaced even though Muon and ProTUN expose infallible storage callbacks; ProtonWire must not report a session as restart-persistent until the durable write succeeds.

**FR-7JA:** A desktop keyring is accessed only by `protonwire-credential-agent` running as the account owner. The agent initiates a long-lived registration channel to a root-owned ProtonWire daemon endpoint below `/run/protonwire`; the daemon binds the registration to the agent's `SO_PEERCRED` UID, and the agent verifies the root-owned socket and daemon peer before accepting broker requests on that channel. Its own UID is the implicit account namespace, so request payloads cannot select another UID, arbitrary keyring attributes, or arbitrary secret-service operations. This outbound registration design must not require the capability-bounded daemon to open a user-owned mode-`0600` runtime socket. The root daemon must not adopt a user's D-Bus environment, scrape a session bus address, or launch a keyring helper as an arbitrary user. Keyring-backed boot auto-connect is unavailable until that authenticated agent is registered; headless boot auto-connect requires a system/headless store or provisioned systemd session credential.

**FR-7JB:** Muon `Store` state and the three ProTUN `PersistentCache` values must be preloaded before their engines start. Synchronous callbacks use a bounded locked-memory facade and a serialized persistence worker; no callback may make an unbounded desktop D-Bus, TPM, or filesystem call on a ProTUN connection thread. Flush failure, timeout, and shutdown behavior must be deterministic and tested.

**FR-7JC:** A provisioned systemd session and a writable session store must have deterministic precedence. A valid writable session is authoritative after first import. Provisioned-session import is an explicit, transactional bootstrap into an empty store, records the source digest and envelope generation, and is idempotent; daemon restart must not replay the same or an older read-only envelope over newer refreshed state. Replacing an existing writable session from provisioning requires a separate explicit administrative replace action. Without import, the systemd session is ephemeral and persistence status must warn that refresh progress may be lost at restart.

Example commands:

```bash
protonwire login
protonwire login --store-password
protonwire login --credential-backend keyring
protonwire login --credential-backend tpm2
protonwire login --credential-backend encrypted-local
protonwire credentials status
protonwire credentials migrate --to tpm2
protonwire credentials import-provisioned-session --to tpm2
protonwire credentials forget-password
```

Example config:

```yaml
account:
  writable_session_store: auto
  credential_input_source: interactive
  import_provisioned_session: false
  allow_password_storage: false
  prefer_token_storage: true
  encrypted_local_fallback: false
  systemd_credential_names:
    session: protonwire-session
    username: protonwire-username
    password: protonwire-password
```

**Acceptance Criteria**

```gherkin
Given keyring is available
When the user runs "protonwire login --store-password"
Then ProtonWire stores credentials in the keyring
And does not attempt TPM2 or encrypted-local storage
```

```gherkin
Given keyring is unavailable
And TPM2 is available
When the user runs "protonwire login --store-password"
Then ProtonWire stores credentials using TPM2-backed storage
And reports "writable_session_store: tpm2" in account status
```

```gherkin
Given systemd credentials are configured as the input source
When the daemon starts
Then ProtonWire reads credentials from systemd-provided credential files
And does not persist them elsewhere
```

```gherkin
Given systemd credentials are configured as the input source
And the user requests "credentials migrate --to loadcredential"
When the command is validated
Then ProtonWire rejects it because systemd credentials are not a writable backend
```

```gherkin
Given no secure writable credential store is available
When the user runs "protonwire login --store-password"
Then ProtonWire refuses password storage by default
And explains how to explicitly enable encrypted local fallback
```

### 7.2 Server Discovery and Metadata Cache {#72-server-discovery-and-metadata-cache}

**FR-8:** The app must retrieve Proton VPN server metadata.

**FR-9:** The metadata model must support at least:

- Server ID
- Server name
- Country
- State or region where exposed
- City
- Exit IPs
- Entry IPs where relevant
- Secure Core route metadata
- Features
- Tier
- Load
- Score
- Supported protocols
- WireGuard public key
- P2P support
- Secure Core support
- Tor support
- Gateway and dedicated-server identity/authorization
- Streaming support if exposed
- Port forwarding support
- IPv6 support
- Online/offline status
- Logical server vs physical server mapping

**FR-10:** The app must cache server metadata locally.

**FR-11:** A client may request a server-metadata refresh. If the next eligible automatic refresh time has not arrived, core must first return a typed confirmation requirement containing the catalog age, last request time, next automatic refresh time, and a warning that unnecessary requests may be rate-limited or blocked by Proton. After the user explicitly confirms that warning, core may perform one manual conditional refresh that bypasses only the local three-hour interval.

**FR-12:** The automatic server-metadata refresh interval must default to three hours and must never be configured below three hours. Configuration, profiles, IPC requests, and client settings that specify a shorter interval must fail validation.

**FR-13:** The app must continue to use cached metadata during temporary API outages if the cache is within a configurable emergency threshold.

**FR-13A:** All Proton API reads in this section must use Muon, including its alternative-routing path when the canonical endpoint is blocked.

**FR-13B:** Cached metadata must preserve ETag/revision information and must never make an expired entitlement, revoked Gateway, or offline physical server appear usable.

**FR-13C:** All automatic and client-requested server-catalog refreshes must pass through one daemon-wide, single-flight scheduler. Starting or reconnecting the CLI, TUI, GUI, daemon, network adapter, or tunnel must not create an additional refresh schedule.

**FR-13D:** The effective next automatic refresh time must be the last metadata request time plus the greatest of the configured interval, three hours, Proton-provided cache lifetime, or `Retry-After`, followed only by non-negative jitter. Jitter must never make an automatic refresh occur before the three-hour floor.

**FR-13E:** Refreshes must use ETag/revision-based conditional requests where the Muon/API surface supports them. A not-modified response updates cache freshness without rewriting unchanged catalog data.

**FR-13F:** A first-run bootstrap with no usable server cache may use a separate bounded retry policy for initial availability. It must honor `Retry-After`, rate-limit responses, and exponential backoff and must stop retrying when the API indicates that the client is blocked or unauthorized.

**FR-13G:** The three-hour floor applies to server-catalog/metadata retrieval. It must not delay expiry-driven authentication refresh, ProTUN certificate renewal, LocalAgent messages, connection-state events, or DNS TTL processing.

**FR-13H:** The last metadata request time, effective interval source, and next automatic refresh time must be persisted across daemon restarts. Clock rollback must not make an automatic refresh eligible early.

**FR-13I:** Every early manual refresh requires a fresh confirmation; approval must not be stored as a preference. CLI `--yes` may provide explicit non-interactive confirmation but must still emit the warning to stderr and the structured event stream. A confirmed manual request remains single-flight, is counted separately in diagnostics, and resets the next automatic refresh to at least three hours after that request.

**Acceptance Criteria**

```gherkin
Given the local server cache is older than the effective refresh interval
And the next eligible refresh time has arrived
When the user runs "protonwire connect uk"
Then the app performs one conditional server-metadata refresh before choosing a server
And schedules no subsequent automatic refresh for at least three hours
```

```gherkin
Given a server-metadata request completed less than three hours ago
When the CLI, TUI, and GUI request refresh concurrently without a confirmed manual override
Then no Proton API metadata request is made
And every client receives the cached catalog and the same next eligible refresh time
```

```gherkin
Given a server-metadata request completed less than three hours ago
When the user manually requests refresh and confirms the rate-limit warning
Then core performs one conditional metadata request
And records it as a manual interval override
And moves the next automatic refresh to at least three hours after the manual request
```

```gherkin
Given a user configures a server metadata refresh interval of 15 minutes
When configuration is validated
Then validation fails with the minimum supported interval of three hours
```

```gherkin
Given the Proton API is unavailable
And the local server cache is within the emergency cache window
When the user runs "protonwire connect fastest"
Then the app may use cached metadata
And the status output must show that cached metadata was used
```

Manual refresh examples:

```bash
protonwire servers refresh
protonwire servers refresh --yes
```

When run before the next automatic refresh is eligible, interactive clients must display an equivalent warning:

```text
The server catalog was refreshed recently. Refreshing again may create
unnecessary load and could cause Proton to rate-limit or block requests.
Next automatic refresh: 2026-08-14T18:00:00Z
Refresh now anyway? [y/N]
```

### 7.3 Smart Server Selection {#73-smart-server-selection}

**FR-14:** The app must support distinct, named selection policies. `official` is the default for Proton Fastest intents and sorts eligible servers by Proton's catalog `Score`, matching the pinned official Android behavior. `balanced` is ProtonWire's added weighted policy. `load` and `latency` are explicit user-selected policies. Status must identify the policy and signal provenance.

**FR-15:** The user must be able to select by:

- Connection group by stable namespaced ID
- Fastest overall
- Fastest excluding the user's physical country
- Random
- Country
- State or region
- City
- Exact server
- Secure Core route
- P2P
- Tor over VPN
- Organization Gateway and dedicated server
- Lowest load
- Lowest latency
- Port-forwarding-capable
- Excluded countries
- Excluded states or regions
- Excluded cities
- Excluded servers
- Preferred countries
- Preferred cities
- Feature constraints

**FR-16:** Only the ProtonWire `balanced` policy uses a weighted scoring model. It must not replace or be labeled as official Fastest behavior.

Default scoring formula:

```text
score =
  (load_weight * normalized_load_score)
+ (latency_weight * normalized_latency_score)
+ (stability_weight * stability_score)
+ (feature_weight * feature_match_score)
+ (history_weight * historical_success_score)
```

Lower score means better candidate.

Default `balanced`-policy weights:

```yaml
server_selection:
  balanced_weights:
    load: 0.40
    latency: 0.40
    stability: 0.15
    feature_match: 0.05
    history: 0.00
```

**FR-17:** If the user asks for `load`, server choice must prioritize lowest load.

**FR-18:** If the user asks for `latency`, server choice must use a fresh-enough cached local probe or actively measure a bounded shortlist before connecting. Probing must never scan the full catalog, run as a background polling loop, or interpret an unanswered probe as proof that a VPN endpoint is offline.

**FR-19:** Server selection must not invent or expose a throughput score. Official selection may use Proton's opaque catalog `Score`; ProtonWire selection may use only Proton-exposed load/status/features plus locally measurable latency, connection success, and stability history. A `speed` sort mode or weight in CLI, IPC, profiles, or configuration must fail validation as unsupported rather than being silently ignored.

**FR-19A:** Official score is opaque upstream data, not an estimated throughput value. If an official Fastest request has no usable Proton score or backend selector, ProtonWire must request an eligible catalog refresh or return `official-score-unavailable`; it must not silently substitute its balanced model.

**FR-19B:** Latency probes default to unprivileged TCP/UDP mechanisms, are limited to the configured shortlist, reuse per-endpoint results for a configured minimum age, have global and per-endpoint rate limits, and stop on cancellation. ICMP is opt-in and is the only probe mode allowed to request `CAP_NET_RAW`.

**FR-20:** If the user provides a country, selection must be limited to that country unless the country is excluded or unavailable.

**FR-21:** If the user provides an exclude country list, those countries must never be selected.

**FR-21A:** State/region, city, and exact-server exclusions must be enforced at the same hard-filter stage as country exclusions and must apply to Fastest selection.

**FR-22:** If no server satisfies all constraints, the CLI must return a structured error explaining which constraints eliminated candidates.

**FR-23:** Exact server requests must never silently fall back to another server.

**FR-23G:** For a free plan, ProtonWire must request the fastest eligible free connection and backend-authorized random server changes. It must display the authoritative cooldown and must never simulate paid location selection locally.

**FR-23H:** P2P, Tor, Secure Core, Gateway, and dedicated-server requests must be explicit constraints. ProtonWire must not silently downgrade to a Standard server.

Example commands:

```bash
protonwire connect fastest
protonwire connect group proton:anti-censorship
protonwire connect group proton:fastest-excluding-my-country
protonwire connect group protonwire:fastest-asia
protonwire connect country GB
protonwire connect country GB --by latency
protonwire connect country NL --by load
protonwire connect country CH --by balanced
protonwire connect city "London" --by latency
protonwire connect state "California" --by latency
protonwire connect server "UK#42"
protonwire connect p2p
protonwire connect tor
protonwire connect gateway <GATEWAY_NAME>
protonwire change-server
protonwire connect fastest --exclude-country US --exclude-country AU
protonwire connect fastest --exclude-city London --exclude-server "CH#42"
protonwire connect fastest --require p2p --require port-forwarding
protonwire connect fastest --netshield malware
protonwire select fastest --dry-run --json
```

Selection request example:

```json
{
  "mode": "fastest",
  "group_id": null,
  "country": "GB",
  "city": null,
  "server": null,
  "selection_policy": "balanced",
  "required_features": ["wireguard"],
  "optional_features": ["vpn_accelerator"],
  "excluded_countries": ["US", "AU"],
  "excluded_servers": [],
  "weights": {
    "load": 0.35,
    "latency": 0.50,
    "stability": 0.10,
    "feature_match": 0.05
  }
}
```

**Acceptance Criteria**

```gherkin
Given the user requests "protonwire connect country GB --by latency"
When multiple UK servers are available
Then the app measures or retrieves latency for candidate UK servers
And selects the lowest-latency eligible server
And records the selection reason in the connection state
```

```gherkin
Given the user requests "protonwire connect fastest --exclude-country US --exclude-country DE"
When the lowest Proton-score server is in the United States
Then that server is excluded
And the next eligible server by Proton score is selected
```

```gherkin
Given the user requests the official Fastest target
When eligible servers have Proton catalog scores
Then ProtonWire orders them by Proton score after hard filters
And performs no latency probe unless the user explicitly requests a ProtonWire ranking policy
```

```gherkin
Given no server supports both P2P and port forwarding
When the user runs "protonwire connect fastest --require p2p --require port-forwarding"
Then the app must not connect
And the CLI must return a constraints-not-satisfied error
```

### 7.3A Secure Core Server Selection {#73a-secure-core-server-selection}

**FR-23A:** Secure Core must be supported in v1.

**FR-23B:** The user must be able to request Secure Core explicitly.

**FR-23C:** Secure Core selection must support:

- Fastest Secure Core route
- Exit country
- Entry country
- Exact Secure Core route where metadata allows
- Lowest load
- Lowest latency
- Excluded entry countries
- Excluded exit countries

**FR-23D:** Secure Core status must show both entry and exit country/server details.

**FR-23E:** Secure Core must be compatible with kill switch, DNS leak prevention, NetShield, and VPN Accelerator where supported.

**FR-23F:** Secure Core must reject incompatible options with clear errors.

Example commands:

```bash
protonwire connect secure-core
protonwire connect secure-core --exit-country GB
protonwire connect secure-core --entry-country CH --exit-country GB
protonwire connect secure-core --by latency
protonwire connect secure-core --exclude-entry-country US
protonwire connect secure-core --exclude-exit-country AU
```

Example JSON status:

```json
{
  "secure_core": {
    "enabled": true,
    "entry": {
      "country": "CH",
      "server": "CH-SC#12"
    },
    "exit": {
      "country": "GB",
      "server": "UK#42"
    }
  }
}
```

**Acceptance Criteria**

```gherkin
Given the user requests Secure Core with GB as exit country
When eligible Secure Core routes exist
Then ProtonWire selects the eligible Secure Core route using the requested policy, or Proton score by default
And status output shows both entry and exit servers
```

```gherkin
Given Secure Core is requested
And no eligible route satisfies the requested constraints
When the user runs the connect command
Then ProtonWire must not fall back to non-Secure-Core servers
And must return a no-eligible-secure-core-route error
```

### 7.3B Connection Groups and Built-in Presets {#73b-connection-groups-and-built-in-presets}

A connection group is an immutable, reusable connection selector with optional feature overrides. It is distinct from an editable user profile: a group has a stable namespaced ID and maintained semantics, while a profile belongs to the user and may copy or reference a group.

The normative built-in catalog is `docs/connection-groups.yaml`. The core representation must preserve at least:

```text
ConnectionGroup
  id: GroupId
  origin: proton | protonwire
  definition_source: proton-api | official-client-compat | protonwire
  display label plus stable localization keys when localized
  target selector
  ranking policy and permitted request-time ranking overrides
  feature overrides
  entitlement requirements
  immutable: true
  source revision or taxonomy revision
```

**FR-23I:** `protonwire-core` must own one connection-group registry generated and validated from `docs/connection-groups.yaml`. The CLI, TUI, GUI, profile editor, auto-connect settings, and frontend API must consume that registry through shared schemas and must not maintain hard-coded client-specific preset lists.

**FR-23J:** Built-in IDs must be stable and namespaced. `proton:*` identifies behavior reproduced from an official Proton selector or preset; `protonwire:*` identifies an added ProtonWire group. Display labels may be localized or renamed without changing IDs.

**FR-23K:** When a public Muon/Proton API response exposes a canonical group ID, server subset, selector, entitlement, or override, core must preserve and apply it rather than reconstructing a different definition locally. When no public runtime definition exists, ProtonWire may use a compatibility definition verified against a pinned official-client source revision. An incompatible or unrepresentable upstream definition must be marked `blocked-upstream`; it must not be silently approximated.

**FR-23L:** The v1 catalog must expose these Proton-compatible groups:

| Stable ID | Display label | Required behavior |
|---|---|---|
| `proton:fastest-country` | Fastest country | Fastest eligible Standard target |
| `proton:fastest-excluding-my-country` | Fastest country (excluding my country) | Fastest eligible Standard target after excluding the physical country |
| `proton:random-country` | Random country | Official/backend-authorized random eligible target |
| `proton:streaming-us` | Streaming US | Fastest eligible US Standard target using WireGuard UDP |
| `proton:gaming` | Gaming | Fastest eligible Standard target with Moderate NAT requested |
| `proton:anti-censorship` | Anti-censorship | Fastest eligible Standard target excluding the physical country, using Stealth |
| `proton:max-security` | Max security | Fastest eligible Secure Core entry/exit route with LAN access blocked |
| `proton:work-school` | Work/School | Fastest eligible Standard target using Stealth with LAN access blocked |

The last five presets reproduce the official Android initial-profile definitions at the pinned parity revision. Fastest, Fastest excluding my country, and Random remain first-class group targets even when an account or client would normally present them outside its profile list.

**FR-23M:** Official group definitions are read-only. Users may pin, unpin, connect, inspect, or copy an official group into an editable profile, but may not edit or delete the `proton:*` definition. A copied profile must record `derived_from_group`, snapshot the visible selector and overrides, and stop inheriting future group changes unless the user explicitly chooses a live group reference.

**FR-23N:** ProtonWire must additionally expose these built-in regional groups:

| Stable ID | Display label | Geographic membership |
|---|---|---|
| `protonwire:fastest-africa` | Fastest Africa | UN M49 Africa (`002`) |
| `protonwire:fastest-asia` | Fastest Asia | UN M49 Asia (`142`) |
| `protonwire:fastest-europe` | Fastest Europe | UN M49 Europe (`150`) |
| `protonwire:fastest-north-america` | Fastest North America | Northern America (`021`), Central America (`013`), and Caribbean (`029`) |
| `protonwire:fastest-south-america` | Fastest South America | UN M49 South America (`005`) |
| `protonwire:fastest-oceania` | Fastest Oceania | UN M49 Oceania (`009`) |

**FR-23O:** Regional membership must come from a vendored, checksummed UN M49 snapshot normalized to ISO 3166-1 alpha-2 country codes. Its source date and checksum must be recorded. Each supported country must resolve deterministically to one primary continental group; changes require a reviewed data update and generated mapping tests. Runtime locale, translated country names, server coordinates, and ad hoc client lists must not determine membership.

**FR-23P:** Group resolution must apply hard filters in this order: authoritative server subset/catalog visibility, account entitlement, online state, target geography/type, physical-country exclusion, explicit user exclusions, required features, and protocol compatibility. Core then applies the catalog's declared ranking policy. Pinned `proton:*` Fastest presets use Proton score and reject request-time ranking overrides that would change their official semantics. ProtonWire regional groups use Proton score by default and may declare `load`, `latency`, or `balanced` as explicit, status-visible request overrides. No group may expose or derive an estimated throughput/speed value.

**FR-23Q:** “My country” means the user's physical country before the VPN, not the VPN exit country, account country, UI locale, or current tunnel address. Resolution uses, in order, an explicit per-request country, an explicitly configured `connection_groups.physical_country`, or the latest Proton user-location country obtained through Muon while disconnected. ProtonWire must never silently use third-party IP geolocation or infer a country from locale/timezone. If no physical country is known, a country-excluding group must return `physical-country-required` with instructions for setting it; it must not connect without the exclusion.

**FR-23R:** Built-in catalog listing and local regional membership must make no network request. A Muon user-location request may occur single-flight only when a user explicitly resolves a country-dependent group and no usable country is cached; it must be cached, carry provenance and observation time, and create no periodic polling loop. Repeated location requests must have a persisted minimum three-hour interval and honor longer Muon `Retry-After`, rate-limit, and block suppression; users can avoid a wait by supplying the country explicitly, not by forcing another request. Any API-supplied group metadata must be co-fetched or cached under the daemon-wide server-catalog scheduler and its three-hour automatic minimum rather than creating a separate client or group refresh timer.

**FR-23S:** A group whose target, protocol, or feature is unavailable to the current account or current catalog must remain visible with a structured availability reason. Connecting it must return the precise entitlement, protocol, no-country, or no-eligible-server error and must never downgrade the group silently.

**FR-23T:** Group selection state and events must include `group_id`, `origin`, catalog revision, resolved selector, applied hard filters, physical-country value/source when relevant, winning server, scoring signals, and any requested-versus-applied feature difference. Sensitive location/IP details remain subject to logging and status redaction rules.

**FR-23U:** CLI, TUI, and GUI must expose group list, group details, availability, connect, pin/unpin, and copy-to-profile actions with identical stable IDs, confirmation behavior, structured errors, and resolution results through the shared client contract.

**FR-23V:** Profiles, default connection, auto-connect, recents, pins, import/export, and declarative NixOS configuration must accept a stable group reference. Import must reject unknown namespaces and retain an unavailable known group reference without rewriting it into a different target.

Example commands:

```bash
protonwire group list
protonwire group list --origin proton
protonwire group show proton:anti-censorship
protonwire connect group proton:anti-censorship
protonwire connect group proton:fastest-excluding-my-country --physical-country GB
protonwire connect group protonwire:fastest-asia
protonwire connect group protonwire:fastest-europe --by latency
protonwire group pin protonwire:fastest-europe
protonwire group copy-to-profile proton:anti-censorship my-anti-censorship
```

**Acceptance Criteria**

```gherkin
Given the physical country is GB
And an entitled online Stealth server exists outside GB
When the user connects to "proton:anti-censorship"
Then core excludes every GB exit server before scoring
And requests Stealth through ProTUN
And status identifies the official group and the physical-country exclusion
```

```gherkin
Given eligible servers exist in Asia and Europe
When the user connects to "protonwire:fastest-asia"
Then every candidate belongs to the vendored UN M49 Asia mapping
And core selects the lowest Proton-score eligible server without producing an estimated speed or an implicit probe sweep
```

```gherkin
Given no physical country is configured or cached
When the Proton user-location request is unavailable
And the user connects to "proton:fastest-excluding-my-country"
Then ProtonWire does not connect
And returns a physical-country-required error through CLI, TUI, and GUI
```

```gherkin
Given CLI, TUI, and GUI are connected to the same daemon
When each client lists connection groups
Then each receives the same catalog revision, IDs, origins, availability, and definitions
And listing causes no Proton API request
```

### 7.4 ProTUN Tunnel Lifecycle {#74-protun-tunnel-lifecycle}

**FR-24:** The daemon must create a Linux TUN interface and pass its owned file descriptor to ProTUN. ProTUN must perform all WireGuard packet processing and protocol transport.

**FR-25:** Default interface name must be `protonwire0`.

**FR-26:** The interface name must be configurable.

**FR-27:** The daemon must provide ProTUN with prioritized peer IDs, entry IPs, WireGuard public keys, UDP/TCP/TLS port candidates, exit labels, connectivity state, LocalAgent settings, and the configured SNI strategy. ProTUN `v2.2.1` does not negotiate Linux TUN addresses through its public API: ProtonWire must configure the client/gateway/DNS addresses required by the pinned ProTUN/`pvpnclient` integration contract (initially `10.2.0.2/32` → `10.2.0.1` and, when enabled, `2a07:b944::2:2/128` → `2a07:b944::2:1`), detect route/address conflicts before commit, and update this contract only with an upstream versioned test. LocalAgent-probed MTU may be applied after connection; it is not an address source.

**FR-28:** The daemon must support reconnecting with a new endpoint.

**FR-29:** The daemon must expose ProTUN connection/interface state, selected peer, protocol, port, handshake age, RTT, estimated loss, and LocalAgent connection state.

**FR-30:** The daemon must expose RX/TX counters.

**FR-31:** The daemon must cleanly remove stale TUN interfaces and tagged policy state on startup if they were created by ProtonWire.

**FR-32:** The daemon must not delete or modify TUN interfaces, routes, DNS state, firewall tables, or manager configuration it did not create unless explicitly configured.

**FR-32A:** Production connections must use ProTUN LocalAgent mode and an encrypted `PersistentCache` implementation for certificates, WireGuard private keys, and ProTUN's internal LocalAgent API session. Cache callbacks block the connection thread and return no error, so the adapter must use the bounded preloaded facade in FR-7JB and surface durable-write health separately.

**FR-32B:** The daemon must translate ProTUN socket-FD callbacks into a stable outer-socket bypass mark before full-tunnel routes are committed.

**FR-32C:** Peer candidates and LocalAgent settings must be atomically updatable through the ProTUN connection object. Endpoint rotation and network changes must not require destroying the frontend session.

**FR-32D:** ProTUN state and event callbacks must be delivered to the frontend API without blocking ProTUN's connection thread.

**FR-32DA:** `AgentConnectionInfo.groups` must be exposed as LocalAgent-provided connection labels only. They are not assumed to be Proton connection-group catalog definitions and must not override `docs/connection-groups.yaml` without a documented upstream mapping.

**Acceptance Criteria**

```gherkin
Given the daemon has valid Muon session and server metadata
When the user runs "protonwire connect server UK#42"
Then the daemon creates protonwire0 and passes its TUN file descriptor to ProTUN
And ProTUN chooses an eligible peer/protocol/port from the supplied candidates
And LocalAgent confirms the connection and server-applied settings
```

### 7.4A Protocol Selection and Smart Protocol {#74a-protocol-selection-and-smart-protocol}

**FR-32E:** ProtonWire must expose `smart`, `wireguard-udp`, `wireguard-tcp`, and `stealth` modes, all implemented by ProTUN.

**FR-32F:** Smart Protocol is the default. ProtonWire supplies eligible candidate peers and ports; ProTUN performs transport fallback and returns the actual chosen protocol and port.

**FR-32G:** A manually selected protocol must constrain candidates to that transport. A manual request must never silently change protocol unless the caller separately enables fallback.

**FR-32H:** Protocol capability reporting must derive from the pinned ProTUN build and current server candidates, not hard-coded UI labels.

**FR-32I:** OpenVPN and IKEv2 must be reported as `legacy-excluded`, not as temporarily unavailable ProtonWire features.

**FR-32J:** ProtonWire must request ProTUN/LocalAgent circumvention routing when censorship policy requires it and expose whether the server applied or refused the setting. Muon alternative routing and LocalAgent circumvention routing are distinct layers and both must be supported.

Example commands:

```bash
protonwire protocols list
protonwire connect fastest --protocol smart
protonwire connect fastest --protocol wireguard-udp
protonwire connect fastest --protocol wireguard-tcp
protonwire connect fastest --protocol stealth
```

Protocol status example:

```json
{
  "protocols": {
    "smart": {
      "available": true,
      "engine": "protun"
    },
    "stealth": {
      "available": true,
      "engine": "protun"
    }
  }
}
```

**Acceptance Criteria**

```gherkin
Given UDP is blocked but TCP and TLS candidates are reachable
When the user runs "protonwire connect fastest --protocol smart"
Then ProTUN falls back without a traffic leak
And status reports the actual protocol and port selected
```

```gherkin
Given the user requests "--protocol stealth"
When no selected peer has an eligible TLS/Stealth port
Then ProtonWire does not connect with another protocol
And returns a machine-readable protocol-unavailable error
```

### 7.5 Routing and Policy Routing {#75-routing-and-policy-routing}

**FR-33:** The daemon must manage routing using Linux netlink.

**FR-34:** The daemon must use dedicated routing tables for VPN traffic.

Recommended tables:

```text
51820  protonwire-main
51821  protonwire-bypass
51822  protonwire-lan
```

These are preferred IDs, not unconditional constants. Startup must inspect `/etc/iproute2/rt_tables` and active rules/routes, reuse only a table already proven to be ProtonWire-owned, or allocate conflict-free IDs and persist the mapping. ProtonWire must never flush a table merely because its numeric ID matches a preferred value.

**FR-35:** Full-tunnel mode must route `0.0.0.0/0` and `::/0` through the ProTUN-backed TUN interface unless split tunneling says otherwise.

**FR-36:** The daemon must preserve local LAN routes when LAN access is enabled.

**FR-37:** The daemon must block IPv6 leaks if IPv6 over VPN is unavailable.

**FR-38:** Route changes must be transactional where possible.

**FR-39:** Disconnect must remove ProtonWire-owned routes and rules and leave concurrently changed unowned state intact. It must not restore a stale whole-table snapshot over changes made by another network manager while connected.

**FR-40:** The daemon must detect route drift and repair it while connected.

**Acceptance Criteria**

```gherkin
Given the VPN is connected in full-tunnel mode
When the user runs "ip route get 1.1.1.1"
Then the selected route must use the ProtonWire routing table
And the packet path must go through the ProTUN-backed TUN interface
```

### 7.6 DNS Management {#76-dns-management}

**FR-41:** The app must support Proton DNS by default.

**FR-42:** The app must support custom DNS servers.

**FR-43:** The app must support DNS modes: `proton`, `custom`, `system`, and `none`. `none` means ProtonWire does not select or mutate a resolver; it does not mean DNS is automatically safe.

**FR-44:** Under strict DNS leak protection, `system` is valid only when every active system resolver is proven to route through the VPN or is an explicitly permitted LAN resolver. `none` is valid only when the caller declares externally managed resolver endpoints that pass the same route/firewall proof. Otherwise validation fails; a generic override must not silently weaken leak protection.

**FR-45:** The daemon must support systemd-resolved if available.

**FR-46:** If systemd-resolved is unavailable, the daemon may manage `/etc/resolv.conf` only after detecting its owner/symlink model. It must use symlink-safe atomic replacement, retain inode/content ownership evidence, and restore only the version it replaced if the file has not since changed. If ownership cannot be established, it must fail or require an explicitly configured resolver adapter rather than clobber another manager.

**FR-47:** DNS changes must be reverted on disconnect.

**FR-48:** DNS changes must be leak-safe when kill switch is enabled.

**FR-49:** Custom DNS must be routed according to policy: `through-vpn`, `bypass-vpn`, or `system-default`. Default is `through-vpn`. `bypass-vpn` and an off-tunnel `system-default` are deliberate leak exceptions: they require `dns.leak_protection: off`, a fresh warning/confirmation, exact destination allowlisting, and status that says protection is off. LAN resolver exceptions use the narrower LAN-name-resolution policy instead.

**FR-49A:** Custom DNS and NetShield are mutually exclusive because NetShield requires Proton's filtering DNS. Enabling one must reject or explicitly disable the other; imported profiles must never resolve this conflict silently.

**FR-49B:** DNS firewall policy must cover UDP/TCP 53 and any DNS transport ProtonWire itself configures. ProtonWire cannot claim to intercept application-owned DoH/DoT that it cannot identify; split-domain documentation and status must preserve that limitation.

Example commands:

```bash
protonwire config set dns.mode proton
protonwire config set dns.mode custom
protonwire config set dns.servers 9.9.9.9,149.112.112.112
protonwire config set dns.policy through-vpn
```

**Acceptance Criteria**

```gherkin
Given custom DNS is configured as 9.9.9.9
And DNS policy is through-vpn
When the VPN connects
Then DNS queries to 9.9.9.9 must route through the ProTUN-backed tunnel
```

### 7.7 NetShield {#77-netshield}

**FR-50:** The app must support NetShield as an optional feature.

**FR-51:** Supported NetShield modes must be: `off`, `malware`, `ads-trackers-malware`, and `adult-ads-trackers-malware` when backend/account support exists.

**FR-52:** The app must request NetShield modes through ProTUN LocalAgent settings.

**FR-53:** If a selected NetShield mode is unsupported by the account, platform, server, or backend, the app must fail gracefully.

**FR-54:** The requested and server-applied NetShield modes must be visible in status output, including any LocalAgent policy refusal.

**FR-55:** The app must expose LocalAgent NetShield counters for malicious domains, ads, trackers, adult content, and data saved whenever the server provides them.

Example commands:

```bash
protonwire connect fastest --netshield malware
protonwire connect fastest --netshield ads-trackers-malware
protonwire config set netshield ads-trackers-malware
protonwire config set netshield off
```

**Acceptance Criteria**

```gherkin
Given the user has configured NetShield as malware
When the user connects
Then the connection must request Proton's malware-blocking DNS mode
And status output must show "netshield: malware"
```

### 7.8 Kill Switch {#78-kill-switch}

**FR-56:** The app must support kill switch modes: `off`, `on`, and `permanent`.

**FR-57:** `on` mode must block non-VPN traffic only while a VPN session is expected to be active.

**FR-58:** `permanent` mode must block non-VPN traffic even when the VPN is disconnected.

**FR-59:** Kill switch must use an atomically replaced, dedicated `inet protonwire` nftables table by default. Rule generation and validation must not interpolate a shell command. Handles/comments and a persisted generation ID establish ownership; no unowned table or chain may be flushed.

**FR-60:** iptables fallback may be provided only where nftables is unavailable.

**FR-61:** Kill switch rules must permit loopback, the exact DHCP/local-link setup required by the active uplink, LAN traffic only if LAN access is enabled, and explicit validated bypass policy. Off-tunnel Proton API/bootstrap and ProTUN traffic must be authorized by daemon-controlled socket/cgroup identity plus a private mark applied before connect; broad destination-IP allowlists are insufficient because CDN/shared addresses could permit unrelated traffic. Only sockets created by the active daemon/ProTUN instance may receive that mark.

**FR-62:** Kill switch rules must block IPv4 and IPv6 leaks.

**FR-63:** Kill switch state must survive daemon restart in permanent mode.

**FR-63A:** Permanent mode must also be fail-closed across boot before ordinary uplink services start. Packaging must install a separate early firewall unit ordered before `network-pre.target`; the main daemon's `After=network-online.target` ordering cannot provide this guarantee. Stopping or crashing the daemon leaves permanent rules intact. Only an explicit authorized disable/recovery operation removes them.

**FR-64:** The daemon must validate firewall rules after applying them.

**FR-65:** The daemon must fail closed if it cannot verify kill-switch enforcement.

Example commands:

```bash
protonwire config set kill-switch on
protonwire config set kill-switch permanent
protonwire config set kill-switch off
protonwire killswitch enable
protonwire killswitch disable
```

**Acceptance Criteria**

```gherkin
Given kill switch is enabled
When ProTUN reports tunnel failure after route setup
Then all non-exempt internet traffic must be blocked
And DNS traffic must not leak to the system resolver
```

```gherkin
Given permanent kill switch is enabled
When the daemon restarts
Then non-VPN internet traffic must remain blocked until the daemon restores policy
```

### 7.9 Split Tunneling {#79-split-tunneling}

**FR-66:** The app must support split tunneling as an optional feature.

**FR-67:** Split tunneling modes: `off`, `exclude`, and `include`.

**FR-68:** Exclude mode means all traffic uses VPN except configured apps, processes, users, groups, IP ranges, domains, or protocol/port rules.

**FR-69:** Include mode means only configured apps, processes, users, groups, IP ranges, domains, or protocol/port rules use VPN.

**FR-70:** Linux implementation must support UID rules, GID rules, delegated cgroup v2 app rules, IP/CIDR rules, domain rules, port/protocol rules, and process attachment by PID where technically possible. Absence of cgroup v2 disables app/process rules with a capability error; it does not prevent the base VPN from running.

**FR-71:** App-path split tunneling must be implemented using a launcher, cgroup assignment model, and daemon-side process tracking.

**FR-71A:** An app-path rule identifies a reviewed executable identity, not every process whose mutable name or argv string matches. Resolution must reject relative paths, prevent symlink/TOCTOU substitution at launch, preserve the requesting UID, and never let the root daemon execute the target. Process-name attachment must first return exact PID/executable/UID candidates and require confirmation (or an explicit automation selector) rather than attaching ambiguous matches silently.

**FR-72:** The daemon must attempt to attach already-running processes to split-tunnel policy when requested.

**FR-73:** If an already-running process cannot be safely attached, ProtonWire must report that process as partially applied or failed rather than claiming success. Moving a task to a cgroup affects only packets from sockets that policy can classify after the move; existing connected sockets and conntrack entries may keep their old path. ProtonWire must report this limitation and recommend restarting the application; it must not disruptively purge unrelated conntrack state by default.

**FR-74:** The CLI must provide launch commands:

```bash
protonwire run --vpn firefox
protonwire run --bypass qbittorrent
```

**FR-75:** The CLI must provide attach commands:

```bash
protonwire split attach --pid 12345 --vpn
protonwire split attach --pid 12345 --bypass
protonwire split attach --process-name firefox --vpn
protonwire split attach --process-name qbittorrent --bypass
protonwire split attach-existing --profile torrent
```

**FR-76:** The daemon must support named split-tunnel profiles.

**FR-77:** Domain-based split tunneling must be supported in v1.

**FR-78:** Domain-based split tunneling must use DNS observation and dynamic IP sets.

**FR-79:** Domain-based split tunneling must be TTL-aware.

**FR-80:** Domain-based split tunneling must document limitations for CDN-backed domains, DNS over HTTPS inside applications, DNS over TLS inside applications, encrypted client hello/SNI privacy features, applications using hardcoded IPs, and shared IP hosting.

**FR-81:** Domain rules must support include and exclude modes.

**FR-82:** Domain resolution updates must not create traffic leak windows when kill switch is enabled.

**FR-83:** Split tunneling must be compatible with kill switch.

**FR-84:** Split tunneling must never silently downgrade kill-switch guarantees.

Example commands:

```bash
protonwire config set split-tunnel.mode exclude
protonwire split add app /usr/bin/firefox --bypass
protonwire split add cidr 192.168.1.0/24 --bypass
protonwire split add uid 1001 --vpn
protonwire split add domain example.com --bypass
protonwire split add domain "*.example.org" --vpn
protonwire split add port tcp/443 --vpn
protonwire split attach --pid 12345 --bypass
protonwire run --bypass /usr/bin/qbittorrent
protonwire run --vpn /usr/bin/firefox
```

Domain rule example:

```yaml
split_tunnel:
  mode: exclude
  domains:
    - domain: "*.example.com"
      action: bypass
      resolve: dynamic
      ttl_policy: respect_dns_ttl
    - domain: "internal.company.test"
      action: vpn
      resolve: dynamic
```

**Acceptance Criteria**

```gherkin
Given split tunneling is set to exclude mode
And /usr/bin/qbittorrent is configured to bypass VPN
When the user launches "protonwire run --bypass /usr/bin/qbittorrent"
Then qBittorrent traffic must route outside the ProTUN-backed tunnel
And all other default internet traffic must route through the tunnel
```

```gherkin
Given split tunneling is set to include mode
And /usr/bin/firefox is configured for VPN
When Firefox is already running
And the user runs "protonwire split attach --process-name firefox --vpn"
Then the daemon attempts to attach matching Firefox processes to the VPN routing policy
And reports success, partial success, or failure per process
```

```gherkin
Given domain-based split tunneling is configured for "*.example.com" as bypass
When the system resolves api.example.com
Then the daemon adds the resolved IPs to the bypass IP set
And refreshes the IP set according to DNS TTL
```

```gherkin
Given an application uses DNS over HTTPS internally
When domain-based split tunneling is configured for that application's destination domain
Then ProtonWire must document that the domain may not be observable
And must not claim guaranteed domain-based routing for that application
```

### 7.10 Port Forwarding {#710-port-forwarding}

**FR-85:** The app must request port forwarding through ProTUN LocalAgent and maintain the Proton-compatible forwarded port through NAT-PMP.

**FR-86:** Port forwarding must be optional.

**FR-87:** The app must only select servers that support port forwarding when port forwarding is requested.

**FR-88:** The app must detect and reject incompatible configuration combinations.

**FR-89:** Port forwarding must be incompatible with Moderate NAT.

**FR-90:** The daemon must request a NAT-PMP mapping after tunnel establishment.

**FR-91:** The daemon must renew the NAT-PMP lease before expiry.

**FR-92:** The active forwarded port must be shown in CLI status.

**FR-93:** The daemon must emit an event when the forwarded port changes.

**FR-94:** The CLI must support blocking until a forwarded port is available.

**FR-94A:** The active port must be published atomically to the frontend API and, for official Linux-app compatibility, to `/run/user/$UID/Proton/VPN/forwarded_port` with user-only permissions when a verified user runtime directory exists. The root daemon must not follow user-controlled symlinks or write an arbitrary runtime path; it passes the value to the authenticated unprivileged agent/client or writes through a pre-opened safe directory FD after ownership, mode, mount, and path checks.

Example commands:

```bash
protonwire connect fastest --port-forwarding
protonwire config set port-forwarding on
protonwire port show
protonwire port watch
```

Status example:

```json
{
  "port_forwarding": {
    "enabled": true,
    "active": true,
    "external_port": 54321,
    "lease_seconds": 60,
    "renewal_due_in_seconds": 45
  }
}
```

**Acceptance Criteria**

```gherkin
Given port forwarding is enabled
When the user connects to a P2P-capable server that supports NAT-PMP
Then the daemon requests a NAT-PMP mapping
And "protonwire port show" returns the active forwarded port
```

```gherkin
Given Moderate NAT is enabled
When the user enables port forwarding
Then the CLI must reject the configuration
And explain that port forwarding and Moderate NAT are mutually exclusive
```

### 7.11 Moderate NAT {#711-moderate-nat}

**FR-95:** The app must support Moderate NAT as an optional feature.

**FR-96:** The app must support NAT modes: `strict` and `moderate`.

**FR-97:** Moderate NAT must be incompatible with port forwarding.

**FR-98:** Moderate NAT must be expressed as ProTUN LocalAgent random-NAT policy: `strict` requests `random_nat = true`, while `moderate` requests `random_nat = false`. Status must reflect the server-applied value rather than the requested value alone.

**FR-99:** Status output must show active NAT type.

Example commands:

```bash
protonwire config set nat strict
protonwire config set nat moderate
protonwire connect fastest --nat moderate
```

**Acceptance Criteria**

```gherkin
Given NAT mode is set to moderate
When the user connects
Then the connection request must include the backend-supported Moderate NAT option
And status output must show "nat: moderate"
```

### 7.12 VPN Accelerator {#712-vpn-accelerator}

**FR-100:** The app must support VPN Accelerator as an optional feature through ProTUN's split-TCP/LocalAgent setting.

**FR-101:** VPN Accelerator must be enabled by default unless the user disables it.

**FR-102:** The CLI must allow toggling VPN Accelerator.

**FR-103:** The active VPN Accelerator state must be visible in status output.

Example commands:

```bash
protonwire config set vpn-accelerator on
protonwire config set vpn-accelerator off
protonwire connect fastest --vpn-accelerator off
```

**Acceptance Criteria**

```gherkin
Given VPN Accelerator is disabled
When the user connects
Then the ProTUN LocalAgent request must disable split TCP
And status output must show "vpn_accelerator: off"
```

### 7.13 LAN Access {#713-lan-access}

**FR-104:** The app must expose an explicit `allow` or `block` policy for LAN traffic while VPN is connected.

**FR-105:** LAN access must be optional.

**FR-106:** Default LAN ranges:

```text
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
fd00::/8
fe80::/10
```

**FR-107:** The user must be able to customize LAN ranges.

**FR-108:** LAN access must be enforced consistently with kill switch.

**FR-108A:** When LAN access and `lan-name-resolution` are enabled, ProtonWire must permit only the link-local multicast and explicitly configured local-resolver traffic needed to resolve LAN device names. It must support `.local` mDNS on Linux, keep ordinary DNS on the selected protected DNS path, and never send local-only names to Proton DNS. The setting defaults to `off`, is ineffective while LAN access is blocked, and status must report the active local-name resolution mechanism.

Example commands:

```bash
protonwire config set lan-access on
protonwire config set lan-access off
protonwire config set lan-name-resolution on
protonwire lan add 192.168.50.0/24
protonwire lan remove 192.168.50.0/24
```

**Acceptance Criteria**

```gherkin
Given LAN access is enabled
And the VPN is connected
When the user connects to 192.168.1.10
Then traffic to 192.168.1.10 must bypass the VPN
And internet traffic must continue through the VPN

Given LAN access and LAN name resolution are enabled
When the user resolves printer.local
Then only link-local mDNS traffic may bypass the VPN
And ordinary DNS queries must continue through the selected protected DNS path
```

### 7.14 Auto-Connect and Reconnect {#714-auto-connect-and-reconnect}

**FR-109:** The app must support auto-connect at daemon startup.

**FR-110:** The app must support reconnect on unexpected tunnel failure.

**FR-111:** The app must support reconnect on network change.

**FR-112:** The app must support a max retry policy.

**FR-113:** The app must support exponential backoff.

**FR-114:** The app must support preferred default connection profiles.

**FR-114A:** Default connection choices must include fastest, random, last successful connection, a stable connection-group ID, and a named profile, subject to plan entitlement.

**FR-114B:** The configured network integration adapter must translate uplink changes into ProTUN `Up`, `Down`, or `NetworkSwitch` events and reconcile routes, DNS, and firewall state before reporting the connection recovered.

Example configuration:

```yaml
auto_connect:
  enabled: true
  profile: default
  retry:
    max_attempts: 0
    initial_delay_seconds: 2
    max_delay_seconds: 300
    jitter: true
```

**Acceptance Criteria**

```gherkin
Given auto-connect is enabled
When the daemon starts after boot
Then it connects using the configured default profile
```

```gherkin
Given the VPN is connected
When the ProTUN-selected endpoint becomes unreachable
Then the daemon attempts reconnection according to retry policy
And kill switch policy remains enforced during reconnection
```

### 7.15 Profiles {#715-profiles}

**FR-115:** The app must support named connection profiles.

**FR-116:** A profile must include:

- Name, optional color and icon
- Connection type: Standard, Secure Core, P2P, Tor, or Gateway
- Selection mode
- Optional live connection-group ID or copied `derived_from_group` provenance
- Country
- State or region
- City
- Server
- Secure Core settings
- Gateway and dedicated-server settings
- Protocol: Smart, WireGuard UDP, WireGuard TCP, or Stealth
- Required features
- Excluded countries
- Excluded states or regions
- Excluded cities
- Excluded servers
- DNS mode
- NetShield mode
- Kill switch mode
- Split tunneling profile
- Port forwarding
- NAT type
- VPN Accelerator
- LAN access
- MTU
- IPv6 mode
- Optional Connect and Go action

**FR-116A:** Profiles must support create, edit, duplicate, delete, import, export, pin, unpin, and atomic connect operations.

**FR-116B:** ProtonWire must maintain bounded recent connections and allow a recent entry or profile to become the default connection.

**FR-116C:** A Connect and Go action may open one validated `https` URL, optionally requesting private/incognito browser mode, or launch one explicitly configured executable only after connection reaches the server-confirmed connected state. The action must run as the requesting user through an unprivileged frontend, never as root, and must require confirmation when imported from a profile.

Example profile:

```yaml
profiles:
  torrent-nl:
    selection:
      mode: country
      country: NL
      by: latency
      require:
        - p2p
        - port-forwarding
    features:
      port_forwarding: true
      netshield: ads-trackers-malware
      vpn_accelerator: true
      nat: strict
      kill_switch: on
      lan_access: true
```

Example commands:

```bash
protonwire profile create torrent-nl
protonwire profile edit torrent-nl
protonwire profile duplicate torrent-nl torrent-backup
protonwire profile pin torrent-nl
protonwire profile default torrent-nl
protonwire connect profile torrent-nl
protonwire profile export torrent-nl > torrent-nl.yaml
protonwire profile import torrent-nl.yaml
protonwire profile create travel --from-group protonwire:fastest-europe
```

**Acceptance Criteria**

```gherkin
Given a profile named "torrent-nl" exists
When the user runs "protonwire connect profile torrent-nl"
Then all profile settings must be applied atomically
```

### 7.16 Status, Events, and Observability {#716-status-events-and-observability}

**FR-117:** The CLI must provide human-readable status.

**FR-118:** The CLI must provide JSON status.

**FR-119:** The daemon must emit connection lifecycle events.

**FR-120:** Logs must be structured.

**FR-121:** Logs must not contain credentials, challenge values, tokens, selectors, cookies, private keys, full IP addresses, usernames, session/account IDs, or device fingerprints. Dependency events must be filtered before they reach a general formatter or sink; production builds must cap pinned Muon/ProTUN/`pvpnclient` module levels according to FR-7P.

**FR-122:** The daemon must expose debug bundles with redaction.

**FR-123:** Status must distinguish requested settings from server-applied LocalAgent settings and include the active connection-group ID/origin/catalog revision when applicable, selected ProTUN peer ID, entry IP, protocol, port, exit IPv4/IPv6, server MTU, active integration adapter, any restriction or wait/jail reason, server-catalog age, last refresh result, next automatic metadata refresh time, active suppression deadline, and manual-override count.

**FR-124:** The daemon must expose ProTUN connection statistics including RX/TX, handshake age, estimated RTT, and loss, plus LocalAgent NetShield statistics when available.

**FR-125:** Packet capture must use ProTUN's bounded capture API, be disabled by default, require a fresh explicit request, enforce a maximum byte count, and emit start/stop reasons. User-selected output must use a caller-opened FD transferred over IPC; a daemon path is allowed only inside a fixed root-owned capture directory opened without following symlinks. The resulting file must be owned by the requesting user and mode `0600`.

**FR-126:** Anonymous crash reporting must be disabled by default unless the user opts in. Any report must be inspectable, redacted, and must not contain packet data, credentials, full IP addresses, profile actions, or DNS queries.

**FR-127:** The frontend API must expose every core command, query, asynchronous prompt, state snapshot, and event needed by the client capability contract. No first-party client may require privileged access or a second protocol implementation.

**FR-127A:** The core, daemon, shared client SDK, CLI, TUI, GUI, tests, packaging, schemas, and release automation must live in one repository and one Cargo workspace with one committed root `Cargo.lock`.

**FR-127B:** v1 must ship three first-party unprivileged clients: the `protonwire` CLI, the Ratatui-based `protonwire-tui`, and the Tauri-based `protonwire-gui`.

**FR-127C:** `protonwire-core` must be the sole application-behavior implementation. All three clients must perform operations through `protonwire-client`; they must not link ProTUN, Muon, `protonwire-core`, `protonwire-net`, or `protonwire-store`.

**FR-127D:** The shared client SDK must provide typed commands, queries, prompts, errors, view models, event subscriptions, protocol negotiation, reconnect, missed-event detection, and atomic full-state resynchronization.

**FR-127E:** The CLI must remain the complete non-interactive and automation surface, including JSON/YAML output where defined, stable exit codes, stdin-safe prompts, `--no-input`, and `--yes` behavior. TUI or GUI availability must never be required for daemon administration.

**FR-127F:** The TUI must use Ratatui, support keyboard-only operation, resize safely, render connection and server updates without blocking its event loop, provide searchable server/profile views, and restore the terminal after normal exit, error, panic, or handled termination signal.

**FR-127G:** The GUI must use Tauri with bundled local presentation assets. Its Rust shell may expose only narrow typed commands backed by `protonwire-client`; remote code, arbitrary shell execution, unrestricted file access, and direct arbitrary network access from the webview are forbidden.

**FR-127H:** Credentials and challenge responses may exist in client memory only long enough to complete the requested flow. The Tauri webview must never persist them in browser storage, caches, analytics, crash reports, URLs, or logs. TUI and CLI input must disable terminal echo for secret values.

**FR-127I:** Closing the TUI or GUI must not disconnect an active VPN unless the user explicitly requests disconnect. The GUI may provide a system tray and desktop notifications when supported, but loss of the tray or desktop session must not affect the daemon or tunnel.

**FR-127J:** A generated client capability matrix must map every interactive command, query, prompt, error, and event to CLI, TUI, and GUI coverage. A missing client implementation for a required capability is a v1 release blocker unless the manifest records a narrow presentation-only exception.

**FR-127K:** Destructive and privacy-sensitive actions must use the same confirmation and consent semantics in all clients. Display text and layout may differ, but defaults, validation, entitlement handling, state transitions, and error codes must not.

**FR-128:** The daemon must detect and explain network conflicts involving another default-route VPN/TUN, route ownership, DNS ownership, nftables priority, outer-socket reachability, and network-manager drift. Detection must not disable third-party security software or mutate unowned state.

**FR-129:** Connection-quality feedback is `blocked-upstream` until an authorized public endpoint, schema, client identifier, and Muon request path are verified. When unblocked, submission is opt-in per event, shows the exact payload before sending, and never includes traffic, DNS, credentials, or full IP addresses. ProtonWire must not invent or reverse-engineer a private endpoint to satisfy parity.

Example commands:

```bash
protonwire status
protonwire status --json
protonwire events
protonwire logs --since 10m
protonwire debug bundle
protonwire debug capture start --max-size 64MiB --output capture.pcap
protonwire debug capture stop
```

Example JSON status:

```json
{
  "state": "connected",
  "server": {
    "name": "UK#42",
    "country": "GB",
    "city": "London",
    "load": 34,
    "latency_ms": 18,
    "selection_policy": "latency",
    "selection_reason": "lowest_measured_latency_in_country",
    "selection_signal_provenance": "local-bounded-probe"
  },
  "tunnel": {
    "engine": "protun",
    "interface": "protonwire0",
    "protocol": "wireguard-tcp",
    "port": 443,
    "latest_handshake_seconds_ago": 12,
    "rtt_ms": 32,
    "estimated_loss": 0.002,
    "rx_bytes": 123456789,
    "tx_bytes": 987654321
  },
  "network_integration": "networkd",
  "features": {
    "kill_switch": "on",
    "split_tunnel": "exclude",
    "netshield": "ads-trackers-malware",
    "port_forwarding": true,
    "nat": "strict",
    "vpn_accelerator": true,
    "lan_access": true,
    "secure_core": false
  }
}
```

**Acceptance Criteria**

```gherkin
Given the VPN is connected
When the user runs "protonwire status --json"
Then the output must be valid JSON
And include connection state, selected server, ProTUN state, requested and applied features, network integration, and restrictions
```

---

## 8. Non-Functional Requirements {#8-non-functional-requirements}

### 8.1 Performance {#81-performance}

**NFR-1:** CLI cold start must complete within 150 ms for non-network commands on typical hardware.

**NFR-2:** Status command must complete within 100 ms when daemon is running.

**NFR-3:** Tunnel setup must complete within 5 seconds after receiving valid server config under normal network conditions.

**NFR-4:** Server selection using cached metadata must complete within 500 ms for 20,000 servers.

**NFR-5:** Latency probing must support bounded parallelism, per-endpoint and global rate limits, cancellation, and a cache. It is on-demand for an explicit ProtonWire policy only; there is no scheduled catalog-wide probe loop.

**NFR-6:** The daemon’s idle RSS should target under 50 MB.

**NFR-6A:** Client memory and startup budgets must be measured in CI release builds. The TUI must remain suitable for low-resource SSH sessions, and the GUI must not cause daemon/core memory growth when opened, closed, or restarted repeatedly.

### 8.2 Security {#82-security}

**NFR-7:** No plaintext password persistence.

**NFR-8:** No private key logging.

**NFR-9:** No token logging.

**NFR-10:** File permissions for sensitive files must be `0600`.

**NFR-11:** Daemon socket must reject unauthorized users.

**NFR-12:** Privileged operations must be isolated in the daemon.

**NFR-13:** Firewall policy must fail closed when kill switch is enabled.

**NFR-14:** DNS must not leak when DNS leak protection is active.

**NFR-15:** IPv6 must be either tunneled or blocked.

**NFR-16:** Credential backend downgrade must never be silent.

**NFR-16A:** Secret-bearing buffers must be non-cloneable where practical, zeroized on drop, excluded from core dumps, and held in locked memory when the platform permits. Because pinned upstream APIs accept ordinary Rust strings/byte vectors, documentation must describe this as best effort and tests must verify lifecycle boundaries rather than promise impossible perfect erasure.

**NFR-16B:** The host-global connection owner, per-UID account/profile namespace, administrative transfer, read-only redaction, and concurrent-client authorization rules must be enforced in core and tested over real Unix peer credentials.

### 8.3 Reliability {#83-reliability}

**NFR-17:** Daemon must recover from crash by reconciling only cryptographically or structurally tagged ProtonWire-owned state; it must never infer ownership from a common interface name, table number, or nftables priority alone.

**NFR-18:** Permanent kill switch must survive daemon crash and restart.

**NFR-19:** The app must detect stale routes and firewall drift.

**NFR-20:** The app must tolerate Proton API unavailability using valid cached metadata.

**NFR-21:** Reconnect must not produce a traffic leak window when kill switch is enabled.

### 8.4 Compatibility {#84-compatibility}

**NFR-22:** Must support Linux TUN and the kernel facilities required by pinned ProTUN; the Linux WireGuard kernel module is not required.

**NFR-23:** Must support nftables.

**NFR-24:** Must support systemd services.

**NFR-25:** Must work without NetworkManager.

**NFR-25A:** Must work without systemd-networkd.

**NFR-25B:** Must interoperate with NetworkManager and systemd-networkd when either owns the physical uplink, without allowing either to own or recreate ProtonWire's TUN interface.

**NFR-26:** Must support NixOS through a flake module.

**NFR-27:** Must support systems with systemd-resolved and without systemd-resolved.

### 8.5 Maintainability {#85-maintainability}

**NFR-28:** Rust code must use explicit error types.

**NFR-29:** Public structs must derive serialization where appropriate.

**NFR-30:** All config schemas must have versioning.

**NFR-31:** Integration tests must run in isolated Linux network namespaces.

**NFR-32:** Feature logic must be unit-testable without root privileges.

**NFR-33:** ProTUN and Muon must be wrapped behind internal traits and pinned exactly in `Cargo.lock`; no Proton registry dependency may float at build time.

**NFR-34:** Release builds must be reproducible from publicly obtainable source packages and registries. Builds must fail with a clear diagnostic when the pinned Proton registry is unavailable; vendoring, checksums, and an offline source archive are required before stable release.

**NFR-35:** Every shipped Rust dependency must have a declared SPDX-compatible license or a reviewed upstream license file. ProTUN's source is GPLv3-or-later, so ProtonWire is licensed GPL-3.0-or-later and every linked dependency must be compatible. The downloaded Muon `2.6.1` and `pvpnclient` `3.0.3` source archives contain no `license`/`license-file` manifest field or license text; their registry availability is not permission to redistribute. This and the same review for all transitive Proton crates are release blockers until Proton supplies applicable terms.

**NFR-36:** The ProTUN/Muon adapters must have contract tests against the pinned version and an upgrade test against the candidate next version. Beta API changes must not propagate into the frontend API or configuration schema.

**NFR-37:** The project must generate an SBOM, run license and vulnerability checks, record registry checksums, and document source-offer obligations for every release.

**NFR-38:** Workspace dependency versions, Rust edition, MSRV, lint policy, release profiles, and feature flags must be declared centrally. Leaf crates and applications must use workspace inheritance rather than independent version policy.

**NFR-38A:** If the Tauri UI uses JavaScript or TypeScript tooling, its package-manager choice and lockfile must be repository-wide and committed, CI must use frozen/offline-capable installs, and release assets must not depend on runtime CDNs.

**NFR-39:** CI must reject forbidden dependency edges: client applications may depend only on the shared client SDK, frontend schemas, and presentation libraries; infrastructure adapters may not depend on client applications or presentation frameworks.

**NFR-40:** IPC and client view-model schemas must be generated or shared from one Rust source of truth. CLI, TUI, Tauri commands, and GUI bindings must not maintain hand-copied protocol models.

**NFR-41:** Regular server-catalog refresh traffic must be independent of the number of connected clients and limited to at most one request window every three hours per daemon/API environment. Excluding first-run bootstrap recovery, this is at most eight scheduled request windows in any 24-hour period.

**NFR-41A:** Confirmed manual interval overrides are excluded from the automatic request budget but must be separately counted and exposed in diagnostics so repeated user-driven refreshes remain visible.

**NFR-42:** The workspace compiler floor is at least Rust 1.85 because ProTUN and Muon use edition 2024. Their manifests do not declare `rust-version`, so ProtonWire must establish and continuously test its actual MSRV rather than infer an unsupported upstream guarantee.

---

## 9. Client Specifications {#9-client-specifications}

### 9.1 Top-Level Commands {#91-top-level-commands}

```bash
protonwire login
protonwire logout
protonwire account
protonwire credentials
protonwire protocols
protonwire integration
protonwire connect <target>
protonwire change-server
protonwire disconnect
protonwire reconnect
protonwire status
protonwire servers
protonwire servers refresh
protonwire group
protonwire select <target>
protonwire config
protonwire profile
protonwire split
protonwire dns
protonwire port
protonwire killswitch
protonwire lan
protonwire daemon
protonwire debug
```

### 9.2 Connect Syntax {#92-connect-syntax}

```bash
protonwire connect fastest
protonwire connect random
protonwire connect country <COUNTRY_CODE>
protonwire connect state <STATE_OR_REGION>
protonwire connect city <CITY_NAME>
protonwire connect server <SERVER_NAME>
protonwire connect p2p
protonwire connect tor
protonwire connect gateway <GATEWAY_NAME>
protonwire connect secure-core
protonwire connect group <NAMESPACED_GROUP_ID>
protonwire connect profile <PROFILE_NAME>
```

### 9.3 Selection Modifiers {#93-selection-modifiers}

```bash
--by official
--by balanced
--by load
--by latency
--physical-country <COUNTRY_CODE>
--exclude-country <COUNTRY_CODE>
--exclude-state <STATE_OR_REGION>
--exclude-city <CITY_NAME>
--exclude-server <SERVER_NAME>
--require p2p
--require secure-core
--require port-forwarding
--netshield off|malware|ads-trackers-malware|adult-ads-trackers-malware
--kill-switch off|on|permanent
--split-tunnel off|exclude|include
--port-forwarding
--nat strict|moderate
--vpn-accelerator on|off
--dns proton|custom|system|none
--lan-access on|off
--protocol smart|wireguard-udp|wireguard-tcp|stealth
--json
--dry-run
```

`--by` is valid only for targets whose contract permits a ranking choice. Immutable `proton:*` presets reject it because changing the ranking would no longer reproduce the official definition. ProtonWire regional groups allow the catalog-declared overrides and report the derived policy in status.

### 9.4 Protocol Commands {#94-protocol-commands}

```bash
protonwire protocols list
protonwire connect fastest --protocol smart
protonwire connect fastest --protocol wireguard-udp
protonwire connect fastest --protocol wireguard-tcp
protonwire connect fastest --protocol stealth
```

### 9.5 Secure Core Commands {#95-secure-core-commands}

```bash
protonwire connect secure-core
protonwire connect secure-core --exit-country GB
protonwire connect secure-core --entry-country CH --exit-country GB
protonwire connect secure-core --by latency
```

### 9.6 Credential Commands {#96-credential-commands}

```bash
protonwire credentials status
protonwire credentials migrate --to keyring
protonwire credentials migrate --to tpm2
protonwire credentials migrate --to encrypted-local
protonwire credentials import-provisioned-session --to keyring|tpm2|encrypted-local
protonwire credentials forget-password
```

### 9.7 Split Tunnel Commands {#97-split-tunnel-commands}

```bash
protonwire split attach --pid <PID> --vpn
protonwire split attach --pid <PID> --bypass
protonwire split attach --process-name <NAME> --vpn
protonwire split attach --process-name <NAME> --bypass
protonwire split attach-existing --profile <PROFILE>
protonwire split add domain example.com --vpn
protonwire split add domain "*.example.com" --bypass
protonwire split remove domain example.com
protonwire split domains list
protonwire split domains refresh
```

### 9.8 Exit Codes {#98-exit-codes}

```text
0   Success
1   General error
2   Invalid arguments
3   Not authenticated
4   Entitlement missing
5   No eligible server
6   Network unavailable
7   Tunnel failed
8   Kill switch enforcement failed
9   DNS configuration failed
10  Firewall configuration failed
11  Split tunnel configuration failed
12  Port forwarding failed
13  Daemon unavailable
14  Permission denied
15  Config validation failed
16  Credential backend unavailable
17  Secure Core route unavailable
18  Protocol unavailable
```

### 9.9 Ratatui TUI {#99-ratatui-tui}

`protonwire-tui` must be a first-class Ratatui application, not a terminal wrapper around CLI output. It consumes `protonwire-client` view models and event subscriptions and provides these primary views:

```text
Dashboard         Connection state, server, protocol, IPs, statistics, active features
Locations         Search/filter countries, states, cities, servers, P2P, Tor, Secure Core, Gateway
Groups            Official and ProtonWire groups, availability, details, pins, copy, connect
Profiles          Create, edit, duplicate, import/export, pin, default, connect, Connect and Go
Connection        Protocol, NetShield, NAT, forwarding, Accelerator, DNS, LAN, IPv4/IPv6
Split tunneling   Apps/processes, UID/GID, cgroup, IP/CIDR, domain, port/protocol policies
Account           Login, supported 2FA, upstream-gate status, plan, entitlement, session, logout
Diagnostics       Events, restrictions, conflict detection, redacted bundle, bounded capture
Settings          Integration adapter, auto-connect, kill switch, storage, privacy and feedback
```

The TUI must expose discoverable key help, keyboard-only focus traversal, confirmation dialogs, safe secret input, scrollable errors, a reconnecting indicator, and a full refresh after IPC sequence gaps. Exiting the TUI exits only the client.

### 9.10 Tauri GUI {#910-tauri-gui}

`protonwire-gui` must be a Tauri desktop application whose local UI assets render the same views and operations as the TUI. The Tauri Rust shell owns the shared client SDK connection, maps an explicit allowlist of typed GUI commands to SDK calls, and emits sanitized state/events to the webview.

The v1 GUI must include:

- Dashboard and quick connect/change-server/disconnect controls
- Searchable locations and full special-server selection
- Searchable official and ProtonWire connection groups with provenance, availability, pins, copy-to-profile, and connect actions
- Profile creation and management
- Complete connection, DNS, kill-switch, LAN, split-tunnel, and feature settings
- Login, supported 2FA/WebAuthn, entitlement, session flows, and visible SSO/human-verification upstream-gate status
- Connection details, restrictions, forwarded port, NetShield statistics, diagnostics, and privacy controls
- Optional system tray and desktop notifications that degrade safely when unavailable
- Accessible names, keyboard navigation, focus visibility, scalable text, reduced-motion support, and a layout usable on small laptop screens

The GUI must apply a restrictive content security policy, load no remote executable content, disable development tooling in release builds, and request only the minimum Tauri capabilities. It must not expose generic shell, filesystem, HTTP, process, or arbitrary IPC commands to the webview.

### 9.11 Shared Client Contract {#911-shared-client-contract}

The command/query schema and capability matrix are normative. Each client may optimize presentation for its medium, but all three must produce the same validated core request and observe the same resulting state. Automation-only formatting such as CLI JSON and desktop-only presentation such as a tray icon are explicit client-specific capabilities; they do not permit missing VPN behavior.

**Acceptance Criteria**

```gherkin
Given the same authenticated daemon and profile
When a connection is started separately from the CLI, TUI, and GUI
Then each client must send an equivalent typed core request
And each must converge on the same connection, feature, and restriction state
```

```gherkin
Given an active tunnel and a connected TUI or GUI
When that client exits or crashes
Then the daemon and tunnel must remain active
And a restarted client must resynchronize to the current state without changing it
```

---

## 10. Configuration Schema {#10-configuration-schema}

Default config path:

```text
/etc/protonwire/config.yaml
```

User override path:

```text
$XDG_CONFIG_HOME/protonwire/config.yaml
```

The unprivileged client loads and parses its own user override and submits a bounded typed overlay for its UID. The daemon reparses and validates the typed request rather than trusting client-side validation. User overlays are allowlisted to per-UID profiles, selectors, presentation preferences, and feature requests within administrator-defined ceilings. They cannot change daemon paths, integration mode, credential source/store policy, systemd credential names, metadata request budgets, permanent kill-switch floor, another UID's state, or any other host-global setting. The root daemon must never expand `~`, derive a home directory, or follow a user-controlled config path. System/headless policy comes only from the root-owned system configuration and daemon store.

Runtime state path:

```text
/var/lib/protonwire/state.json
```

Cache path:

```text
/var/cache/protonwire/
```

Example configuration:

```yaml
schema_version: 2

daemon:
  socket_path: /run/protonwire/protonwire.sock
  # Group the socket is chowned to so unprivileged clients can reach it.
  # Defaults to the packaged `protonwire` group (the package creates it);
  # an explicit null opts out of the chown.
  socket_group: protonwire
  interface_name: protonwire0
  log_level: info
  network_integration: auto  # auto|native|network-manager|networkd

account:
  writable_session_store: auto  # auto|keyring|tpm2|encrypted-local|none
  writable_store_priority:
    - keyring
    - tpm2
    - encrypted-local
  credential_input_source: interactive  # interactive|systemd
  import_provisioned_session: false
  allow_password_storage: false
  prefer_token_storage: true
  encrypted_local_fallback: false
  systemd_credential_names:
    session: protonwire-session
    username: protonwire-username
    password: protonwire-password

server_selection:
  metadata_cache:
    refresh_interval_hours: 3  # hard minimum; shorter values are invalid
    max_positive_jitter_minutes: 10
    conditional_requests: true
    emergency_max_age_hours: 24
  latency_probe:
    enabled: true  # used only by explicit latency/balanced policies
    max_candidates: 20
    timeout_ms: 750
    parallelism: 4
    result_min_age_minutes: 15
    background_scan: false
    transport: tcp-udp  # icmp is opt-in and requires CAP_NET_RAW
  balanced_weights:
    load: 0.40
    latency: 0.40
    stability: 0.15
    feature_match: 0.05
  secure_core:
    enabled_by_default: false
    preferred_entry_countries: []
    excluded_entry_countries: []
    excluded_exit_countries: []

connection_groups:
  # Optional explicit ISO 3166-1 alpha-2 physical-country override. Null uses
  # the latest Proton user-location country observed through Muon.
  physical_country: null
  region_taxonomy: un-m49-six-continent-view
  regional_default_ranking: proton-score

connection:
  default: fastest  # fastest|random|last|group:<namespaced-id>|profile:<name>
  protocol: smart
  protun:
    mtu: auto
    sni_strategy: random
  ipv6:
    mode: auto

features:
  secure_core: false
  kill_switch: on
  split_tunnel: off
  netshield: ads-trackers-malware
  port_forwarding: false
  nat: strict
  vpn_accelerator: true

dns:
  mode: proton
  custom_servers: []
  policy: through-vpn
  leak_protection: strict
  externally_managed_resolvers: []

lan:
  policy: allow
  allowed_cidrs:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - fd00::/8
    - fe80::/10

split_tunnel:
  mode: off
  attach_existing_processes: false
  domains:
    enabled: true
    resolver_observation: true
    refresh_on_ttl: true
    rules:
      - domain: "*.example.com"
        action: bypass
        ttl_policy: respect_dns_ttl

auto_connect:
  enabled: false
  target: fastest  # also group:<namespaced-id> or profile:<name>
  retry:
    max_attempts: 0
    initial_delay_seconds: 2
    max_delay_seconds: 300
    jitter: true

profiles:
  default:
    connection_type: standard
    protocol: smart
    selection:
      mode: fastest
      by: official
      exclude_countries: []
      require: []
```

The example combines system-only and per-UID fields for readability; the versioned schema must tag every field with its authority class. Duplicate aliases for one policy are forbidden—for example, `lan.policy` is the sole global LAN setting rather than a second `features.lan_access` value with ambiguous precedence.

---

## 11. Data Models {#11-data-models}

### 11.1 Server Model {#111-server-model}

```rust
pub struct Server {
    pub id: String,
    pub name: String,
    pub country: String,
    pub state: Option<String>,
    pub city: Option<String>,
    pub load_percent: u8,
    // Opaque Proton catalog ranking signal; never present it as throughput.
    pub score: Option<f64>,
    pub tier: u8,
    pub features: ServerFeatures,
    pub peers: Vec<ProTunPeerCandidate>,
    pub secure_core: Option<SecureCoreRoute>,
    pub gateway: Option<GatewayIdentity>,
    pub status: ServerStatus,
}
```

### 11.2 Server Features {#112-server-features}

```rust
pub struct ServerFeatures {
    pub p2p: bool,
    pub secure_core: bool,
    pub streaming: bool,
    pub tor: bool,
    pub port_forwarding: bool,
    pub ipv6: bool,
    pub smart_routing: bool,
}
```

### 11.3 Connection Request {#113-connection-request}

```rust
pub struct ConnectionRequest {
    pub selection: SelectionRequest,
    pub features: FeatureRequest,
    pub dns: DnsConfig,
    pub split_tunnel: SplitTunnelConfig,
    pub kill_switch: KillSwitchMode,
}
```

The authenticated Unix UID and active-owner authorization are server-side request context and must never be accepted from a caller-controlled payload field.

```rust
pub enum SelectionPolicy {
    OfficialProtonScore,
    ProtonWireBalanced,
    LowestLoad,
    LowestMeasuredLatency,
    Random,
}
```

### 11.4 Feature Request {#114-feature-request}

```rust
pub struct FeatureRequest {
    pub protocol: ProtocolMode,
    pub secure_core: bool,
    pub netshield: NetShieldMode,
    pub port_forwarding: bool,
    pub nat: NatMode,
    pub vpn_accelerator: bool,
    pub lan_access: bool,
}
```

### 11.5 Split Tunnel Config {#115-split-tunnel-config}

```rust
pub enum SplitTunnelMode {
    Off,
    Exclude,
    Include,
}

pub struct SplitTunnelConfig {
    pub mode: SplitTunnelMode,
    pub app_rules: Vec<AppRule>,
    pub cidr_rules: Vec<CidrRule>,
    pub uid_rules: Vec<UidRule>,
    pub gid_rules: Vec<GidRule>,
    pub domain_rules: Vec<DomainRule>,
    pub port_rules: Vec<PortRule>,
    pub attach_existing_processes: bool,
}
```

---

## 12. Error Handling and Recovery {#12-error-handling-and-recovery}

### 12.1 Error Categories {#121-error-categories}

```text
AuthenticationError
CredentialBackendError
CredentialInputError
CredentialPersistenceError
UpstreamCapabilityBlocked
EntitlementError
ApiError
ServerSelectionError
OfficialScoreUnavailableError
SecureCoreSelectionError
ProtocolUnavailableError
ProTunError
MuonError
LocalAgentPolicyError
NetworkIntegrationError
RouteError
FirewallError
DnsError
SplitTunnelError
PortForwardingError
ConfigError
PermissionError
ActiveConnectionOwnedByAnotherUser
DaemonUnavailable
```

### 12.2 Recovery Rules {#122-recovery-rules}

**ER-1:** If ProTUN setup fails before firewall policy is applied, remove staged ProtonWire-owned routes and conditionally restore only DNS state whose ownership/version still matches.

**ER-2:** If ProTUN setup fails after kill switch is applied, keep kill switch enforced and report failure.

**ER-3:** If DNS setup fails and DNS leak protection is active, abort connection.

**ER-4:** If port forwarding fails but is optional, connect and report degraded feature state.

**ER-5:** If port forwarding is explicitly required, abort connection.

**ER-6:** If selected server fails to connect, retry next eligible server unless exact server was requested.

**ER-7:** If exact server was requested and it fails, do not silently choose another server.

**ER-8:** If split tunneling setup fails, abort when the requested policy or kill-switch proof depends on it. A user may accept degraded operation only when core proves that the result remains at least as restrictive as the active protection policy; a confirmation may never authorize a traffic leak.

**ER-9:** If daemon crashes, permanent kill switch rules must remain in place.

**ER-10:** If Secure Core is requested and unavailable, do not fall back to non-Secure-Core.

**ER-11:** If any manual protocol is requested and unavailable, do not fall back to another protocol unless the user explicitly permits protocol fallback. Smart Protocol may use ProTUN's eligible transport fallback policy.

**ER-12:** If Muon canonical API routing fails, let Muon's alternative-routing policy run. Do not weaken TLS validation or add arbitrary untrusted API endpoints.

**ER-13:** If NetworkManager or systemd-networkd restarts, retain fail-closed firewall policy, rediscover the uplink, notify ProTUN of the network change, and reconcile tagged state.

**ER-14:** If ProTUN asks for a new API fork selector or reports certificate-refresh failure, use Muon to refresh exactly once per bounded retry cycle and prevent an infinite fork loop.

**ER-15:** If LocalAgent refuses a requested feature, report the applied state. Abort when the feature was required; otherwise continue only with an explicit degraded state.

**ER-16:** If a metadata request receives rate limiting, `Retry-After`, a block response, or an equivalent Muon error, persist the suppression deadline, cancel pending automatic refreshes, continue from an eligible cache where safe, and surface the reason and next allowed attempt. Client restart, daemon restart, reconnect, or manual refresh must not bypass it.

**ER-17:** Human verification, SSO, guest mode, feedback, or any other capability without a verified public adapter must return `upstream-capability-blocked` with evidence and remediation. It must not enter an automatic retry loop or fall back to an undocumented endpoint.

**ER-18:** If credential persistence fails after Muon or ProTUN updates an in-memory session/cache value, mark restart persistence unhealthy immediately, retry only with bounded backoff, and fail any operation that explicitly required durable login. Never discard the previous durable envelope until an atomic replacement is committed.

### 12.3 Example Error Output {#123-example-error-output}

```json
{
  "error": {
    "code": "NO_ELIGIBLE_SERVER",
    "message": "No server satisfied all requested constraints.",
    "constraints": {
      "country": "GB",
      "required_features": ["p2p", "port-forwarding"],
      "excluded_countries": ["NL", "CH"]
    },
    "eliminated": {
      "missing_feature": 12,
      "excluded_country": 4,
      "offline": 2
    }
  }
}
```

---

## 13. Security and Privacy Requirements {#13-security-and-privacy-requirements}

**SEC-1:** Private keys must be generated locally where possible.

**SEC-2:** Private keys must never be logged.

**SEC-3:** Tokens must be stored only in the configured writable secure store or supplied ephemerally by the configured systemd credential source. Input source and writable store are separate state.

**SEC-4:** Password storage is allowed only through an approved writable credential store. Plaintext storage is forbidden.

**SEC-5:** Logs, journals, crash reports, and debug bundles must redact access tokens, refresh tokens, private keys, credentials, account identifiers, and full IP addresses. Authorized foreground status may show connection IPs, and an explicitly requested packet capture may inherently contain them; neither exception permits those values in a log sink.

**SEC-6:** The daemon socket must be root-owned, non-world-writable, and require root, configured group membership, or equivalent peer-credential authorization. Every method also enforces request UID, active connection ownership, account namespace, and least disclosure; group membership alone is not authorization for another UID's secrets or mutation.

**SEC-7:** The app must validate file permissions for config and state files.

**SEC-8:** The kill switch must default to fail-closed behaviour when enabled.

**SEC-9:** IPv6 leak prevention must be mandatory unless IPv6 tunnel support is active.

**SEC-10:** DNS leak protection must be mandatory unless explicitly disabled.

**SEC-11:** Debug bundles must include a redaction pass.

**SEC-12:** Split tunneling must display a warning when include mode leaves apps outside the VPN.

**SEC-13:** Port forwarding must display a warning that inbound traffic may reach local services listening on the forwarded port.

**SEC-14:** Only sockets delivered by the active ProTUN instance may receive the outer-transport bypass mark. The mark must not be exposed through the frontend API or reusable by unprivileged processes.

**SEC-15:** Muon TLS validation, endpoint selection, and alternative routing must not be weakened. Custom Proton API endpoints are development-only and rejected in release builds unless an explicitly separate test build is used.

**SEC-16:** ProTUN persistent-cache values, including certificates, private keys, and API sessions, are sensitive credentials and must follow the same storage, zeroization, permission, backup, and logout rules as refresh tokens.

**SEC-16A:** The root daemon is inside the credential trust boundary. Documentation and UI must not claim that a password or challenge sent to daemon-hosted Muon is hidden from root. The security goal is bounded exposure, no persistence by default, best-effort locked/zeroized memory, dump protection, and no propagation to shells, argv, environment, logs, or unrelated processes.

**SEC-16B:** systemd credentials must be located from `$CREDENTIALS_DIRECTORY`, opened without path traversal, size-bounded, read once, and dropped from memory after import. Nix expressions and unit files must never embed plaintext secrets; use `LoadCredentialEncrypted=` or a root-readable runtime secret file managed outside the Nix store.

**SEC-17:** Packet capture must show a prominent content warning, be time/size bounded, never auto-start, and be excluded from debug bundles unless the user separately selects the capture file.

**SEC-18:** Imported profiles must not execute Connect and Go actions until the user reviews and confirms the exact URL or executable. Environment injection, shell evaluation, relative executables, and root execution are forbidden.

**SEC-19:** Network integration adapters must not write persistent NetworkManager profiles or systemd-networkd units during ordinary connection flow.

**SEC-20:** The Tauri GUI must ship a restrictive content security policy, bundled immutable UI assets, an explicit command allowlist, and the minimum capability manifest. Release builds must reject remote executable content and development-only commands.

**SEC-21:** Client crash reports, browser storage, terminal scrollback, clipboard integration, desktop notifications, and window titles must never contain credentials, challenge responses, tokens, private keys, or unredacted sensitive connection data.

**SEC-22:** Tauri plugins and third-party Ratatui widgets must be deny-by-default and individually reviewed for permissions, transitive dependencies, maintenance status, and license compatibility before inclusion.

**SEC-23:** The shared client SDK must authenticate the daemon peer, validate every IPC frame before deserialization into privileged operations, enforce size limits, and reject schema downgrade below the supported security floor.

**SEC-24:** Only core may schedule Proton server-metadata requests. Clients receive cached snapshots and refresh eligibility through IPC and must not hold a direct metadata endpoint, API polling timer, or alternate HTTP implementation that bypasses the shared limiter.

**SEC-25:** A tracing filter must drop known secret-bearing upstream events before serialization. Tests inject unique canaries through Muon login/TOTP/fork and ProTUN LocalAgent paths and search every configured sink, debug bundle, journal capture, panic, and error payload. Production diagnostics may not enable dependency `trace` dynamically.

**SEC-26:** Recovery and cleanup operate only on state carrying ProtonWire ownership evidence. Interface name, route-table number, nftables table name, cgroup name, or process name by itself is not sufficient evidence for deletion or mutation.

**SEC-27:** Per-UID configuration overlays are untrusted IPC input. Core must enforce the schema's field-level authority classes and administrator floors after peer-UID authentication; client-side parsing, ownership of a user config file, or membership in the daemon socket group must not authorize system-only changes.

---

## 14. Packaging and Deployment {#14-packaging-and-deployment}

### 14.1 Packages {#141-packages}

Required v1 release artifacts:

```text
protonwire-cli
protonwire-tui
protonwire-gui
protonwire-daemon
protonwire-systemd
protonwire                 # convenience meta-package
```

Optional integration packages:

```text
protonwire-completions
protonwire-nix
protonwire-credential-agent  # optional per-user keyring broker
protonwire-integration-networkmanager
protonwire-integration-networkd
```

The CLI/TUI packages must remain installable without a GUI stack. Installing `protonwire-gui` may pull its Tauri/WebKit desktop runtime, but the daemon, core, CLI, TUI, NixOS module, and headless deployments must not depend on that package or a graphical session.

### 14.2 Systemd Unit {#142-systemd-unit}

```ini
[Unit]
Description=ProtonWire VPN Daemon
After=network-online.target
Wants=network-online.target
RequiresMountsFor=/var/lib/protonwire /var/cache/protonwire

[Service]
Type=notify
ExecStart=/usr/bin/protonwire-daemon
Restart=on-failure
RestartSec=2
RuntimeDirectory=protonwire
StateDirectory=protonwire
CacheDirectory=protonwire
ConfigurationDirectory=protonwire
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateMounts=true
ProtectKernelModules=true
LockPersonality=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
ReadWritePaths=/run/protonwire /var/lib/protonwire /var/cache/protonwire

[Install]
WantedBy=multi-user.target
```

This is a baseline, not a claim that every distribution can use an identical sandbox. Cgroup delegation, resolver integration, and optional ICMP probes require explicit reviewed adjustments. ICMP support is an opt-in drop-in adding `CAP_NET_RAW`; it is not in the default unit. The daemon has no writable access to `/etc/protonwire`.

Permanent kill switch additionally requires an early one-shot unit with no stop action:

```ini
[Unit]
Description=Restore ProtonWire permanent kill switch
DefaultDependencies=no
Before=network-pre.target
RequiresMountsFor=/var/lib/protonwire
ConditionPathExists=/var/lib/protonwire/permanent-killswitch.json

[Service]
Type=oneshot
ExecStart=/usr/lib/protonwire/protonwire-firewall restore-permanent
RemainAfterExit=yes
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

[Install]
RequiredBy=network-pre.target
```

The helper accepts no caller-supplied rules, validates the root-owned compiled policy and generation ID, and atomically installs only the permanent fail-closed table. Failure must prevent the required `network-pre.target` transaction. Normal daemon shutdown has no `ExecStop` path that removes these rules.

### 14.3 NixOS Flake Module {#143-nixos-flake-module}

ProtonWire must provide NixOS support as a flake module.

The flake must expose:

```nix
{
  packages.${system}.default = ...;          # daemon + CLI
  packages.${system}.protonwire = ...;       # all first-party clients
  packages.${system}.protonwire-cli = ...;
  packages.${system}.protonwire-tui = ...;
  packages.${system}.protonwire-gui = ...;
  packages.${system}.protonwire-daemon = ...;
  packages.${system}.protonwire-credential-agent = ...;
  apps.${system}.default = ...;              # CLI
  apps.${system}.protonwire = ...;           # CLI
  apps.${system}.protonwire-tui = ...;
  apps.${system}.protonwire-gui = ...;
  apps.${system}.protonwire-credential-agent = ...;
  nixosModules.default = ...;
  nixosModules.protonwire = ...;
}
```

Example `flake.nix` consumer usage:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    protonwire.url = "github:thorion3006/protonwire";
  };

  outputs = { self, nixpkgs, protonwire, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        protonwire.nixosModules.protonwire
        {
          services.protonwire = {
            enable = true;
            autoConnect = true;
            defaultProfile = "default";

            login = {
              mode = "interactive";
            };

            killSwitch = "permanent";
            netShield = "ads-trackers-malware";
            vpnAccelerator = true;
            lanAccess = true;

            profiles.default = {
              selection = {
                mode = "fastest";
                by = "latency";
                excludeCountries = [ "US" ];
              };
            };
          };
        }
      ];
    };
  };
}
```

Declarative provisioning example using sops-nix or agenix-managed files:

```nix
{
  services.protonwire = {
    enable = true;

    login = {
      mode = "declarative";
      credentialSource = "systemd";
      writableSessionStore = "tpm2";
      sessionCredential = "protonwire-session";
      importProvisionedSession = true; # explicit first-import authorization
    };

    systemdCredentials = {
      "protonwire-session" = "/run/secrets/protonwire/session-envelope";
    };

    autoConnect = true;
    defaultProfile = "secure-core-uk";

    profiles.secure-core-uk = {
      selection = {
        mode = "secure-core";
        exitCountry = "GB";
        by = "latency";
      };
      features = {
        secureCore = true;
        killSwitch = "permanent";
        netShield = "ads-trackers-malware";
      };
    };
  };
}
```

**FR-143A:** The flake module must support interactive login.

**FR-143B:** The flake module must support declarative login.

**FR-143C:** Declarative login must support read-only systemd `LoadCredential=` and `LoadCredentialEncrypted=` input. The option is named a credential source, never a storage backend. A provisioned session envelope is preferred; username/password is a bootstrap path and repeated login after each daemon restart must use bounded backoff and an explicit operator warning if no writable session store is configured.

**FR-143CA:** `importProvisionedSession` authorizes only the idempotent empty-store bootstrap in FR-7JC. It must not overwrite a newer writable session on rebuild or restart. Replacing an existing session requires a distinct one-shot administrative action; declarative evaluation must not make stale credential replay automatic.

**FR-143D:** Declarative login must be compatible with secret managers such as sops-nix and agenix through root-readable runtime paths. Evaluation must assert that no plaintext secret, password, token, or session envelope is placed in the world-readable Nix store or literal unit options.

**FR-143E:** The flake module must expose options for all major ProtonWire features.

**FR-143F:** The module must support auto-connect at boot.

**FR-143G:** The module must support declarative profiles.

**FR-143H:** The module must support permanent kill switch activation at boot.

**Acceptance Criteria**

```gherkin
Given ProtonWire is enabled through the NixOS flake module
And login.mode is interactive
When the system is rebuilt
Then the daemon is installed and enabled
And the user can complete login using "protonwire login"
```

```gherkin
Given ProtonWire is enabled through the NixOS flake module
And login.mode is declarative
And systemd credential inputs are configured outside the Nix store
When the daemon starts
Then it reads credentials from systemd credentials
And auto-connects using the configured default profile
```

---

## 15. Metrics and Success Criteria {#15-metrics-and-success-criteria}

### 15.1 Product Success Metrics {#151-product-success-metrics}

**M-1:** Connects successfully through pinned ProTUN using WireGuard UDP, WireGuard TCP, Stealth, and Smart Protocol.

**M-2:** Maintains tunnel across 24-hour soak test.

**M-3:** Reconnects after simulated network loss.

**M-4:** No DNS leak in automated leak tests.

**M-5:** No IPv6 leak when IPv6 tunnel is unavailable.

**M-6:** Kill switch blocks traffic during tunnel failure.

**M-7:** On a fixed benchmark fixture, the explicit `latency` policy selects the lowest measured-latency eligible candidate and `official` selects the lowest Proton-score candidate. Production probing is not run merely to manufacture a comparative success metric.

**M-8:** Server selection completes within target time.

**M-9:** Port forwarding lease renews continuously for at least 1 hour.

**M-10:** Split tunneling routes test process traffic according to policy.

**M-11:** Secure Core connects through entry and exit route.

**M-12:** Domain-based split tunneling updates IP sets according to DNS TTL.

### 15.2 Engineering Quality Metrics {#152-engineering-quality-metrics}

**M-13:** Unit test coverage over policy logic: minimum 85%.

**M-14:** Integration tests pass in network namespaces.

**M-15:** No clippy warnings in CI.

**M-16:** No high-severity cargo-audit findings.

**M-17:** Reproducible Nix build.

**M-18:** All `required` entries in `docs/official-parity.yaml` are `verified`; no undocumented parity gaps remain.

**M-19:** The same connection, DNS, kill-switch, and split-tunnel conformance suite passes in `native`, `network-manager`, and `networkd` modes.

**M-20:** ProTUN/Muon builds pass SBOM, checksum, license, vulnerability, offline-source reproducibility, and secret-log canary gates.

**M-21:** The CLI, Ratatui TUI, and Tauri GUI pass the generated client capability matrix with no unexplained gaps or divergent core behavior.

**M-22:** A virtual-clock 24-hour catalog-refresh test produces no more than eight scheduled Proton metadata request windows, regardless of connected client count, daemon reconnects, or network-manager events. Confirmed manual overrides are excluded from that automatic budget and reported separately.

**M-23:** Every built-in official and ProtonWire connection group passes its semantic, entitlement, geographic-membership, no-silent-downgrade, and CLI/TUI/GUI parity tests against one generated catalog revision.

---

## 16. Dependencies and Constraints {#16-dependencies-and-constraints}

### 16.1 Runtime Dependencies {#161-runtime-dependencies}

Allowed:

```text
Linux kernel with TUN, policy routing, and network namespaces
nftables
systemd, recommended
systemd credentials, optional read-only provisioning input
systemd-resolved, optional
NetworkManager, optional integration target
systemd-networkd, optional integration target
cgroup v2, required only when app/process split tunneling is enabled
TPM2 stack, optional
Secret Service / KWallet / GNOME Keyring, optional
A UTF-8 terminal, required only for protonwire-tui
Tauri's supported Linux webview/runtime packages, required only for protonwire-gui
```

Forbidden:

```text
wg-quick as core control path
Linux kernel WireGuard or wireguard-go as a parallel production protocol engine
Proton Python packages as production API or network backends
NetworkManager or systemd-networkd as a mandatory dependency
Desktop keyring as mandatory dependency
GUI session as mandatory dependency
Plaintext credential storage
```

### 16.2 Rust Crates, Indicative {#162-rust-crates-indicative}

```toml
protun = { git = "https://github.com/ProtonVPN/protun", rev = "12e7755a112f59b7b843da79290b3de25febf653", features = ["linux", "local-agent"] }
muon = { version = "=2.6.1", registry = "proton", default-features = false, features = ["transport-hyper", "lenient", "other-product", "unsealed", "login", "alternative-routing"] }
clap = "4"
ratatui = "0.30"
tauri = { version = "2", default-features = false }
tokio = "1"
serde = "1"
serde_json = "1"
thiserror = "1"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = "0.3"
reqwest = "0.12"
rustls = "0.23"
nix = "0.29"
zbus = "5"
secrecy = "0.8"
zeroize = "1"
keyring = "3"
```

No wildcard dependency is allowed. The exact netlink route, nftables, and YAML implementation crates must be selected by the Milestone 1 spike, declared centrally, and committed in the root lockfile; the PRD does not guess their APIs. The original `serde_yaml` repository is archived and must not be selected merely because the schema examples use YAML. The chosen parser must have active maintenance or an explicit in-repository risk acceptance, input-size/depth/alias limits, duplicate-key handling, and fuzz coverage. Ratatui and Tauri are presentation dependencies and may appear only in their respective client application subtree. The exact Tauri capability/plugin set and terminal backend must be explicitly allowlisted. `reqwest` may support non-Proton probes or downloads with rustls and disabled default TLS features but must not become a second implementation of normal Proton API/auth control flow. Exact transitive versions, including `pvpnclient`, must be committed in the single root `Cargo.lock`. Final versions must be validated during technical design and pass the licensing/reproducibility gates in NFR-33 through NFR-40.

The workspace must configure Proton's public sparse registry:

```toml
[registries.proton]
index = "sparse+https://rust-registry.proton.me/index/"
```

The initial resolver target for pinned ProTUN is Muon `2.6.1` (registry checksum `be9ba1f347e00a86119ff6b70d36356cce28c33fd000290cc1254bf4048155de`) and transitive `pvpnclient` `3.0.3` (checksum `3c14ef052727e0204ec5e80cf8df50786db38a83b6a6557a188b78a4c264f380`). ProTUN's `~3.0.1` constraint permits `pvpnclient` `3.0.3`, and its Muon `^2` constraint unifies with the direct exact pin. The ProTUN tag has no lockfile, so these are ProtonWire resolution decisions, not upstream lockfile guarantees. Development prototypes may proceed; no binary or source distribution containing the unresolved Proton crates may be published before their license terms and every transitive Proton crate are cleared.

---

## 17. Test Plan {#17-test-plan}

### 17.1 Unit Tests {#171-unit-tests}

**T-1:** Validate Proton-score ordering for official Fastest, weighted load/latency/stability scoring only for ProtonWire `balanced`, missing-score refusal, and rejection of an unsupported `speed` sort mode or weight in every input schema.

**T-2:** Validate country exclusion.

**T-3:** Validate exact server selection.

**T-4:** Validate feature constraint filtering.

**T-5:** Validate port forwarding and Moderate NAT conflict.

**T-6:** Validate DNS config rendering.

**T-7:** Validate kill switch rule generation.

**T-8:** Validate split tunnel policy generation.

**T-9:** Validate config schema migration.

**T-10:** Validate token redaction.

**T-11:** Validate Secure Core route filtering.

**T-12:** Validate writable-store priority, keyring-agent availability, separate systemd input-source semantics, explicit-backend no-fallback, and rejection of migration to `LoadCredential`.

**T-13:** Validate ProTUN protocol capability and manual-fallback policy.

**T-14:** Validate domain split tunnel rule matching.

**T-15:** Validate Muon SRP, TOTP/recovery-code, FIDO2 payload, refresh/logout, external-session/fork state, and fail-closed `blocked-upstream` behavior for human verification, SSO, guest, and unknown challenges.

**T-16:** Validate free-plan selection and cooldown representation.

**T-17:** Validate profile Standard/Secure Core/P2P/Tor/Gateway schemas, import confirmation, recents, pins, and defaults.

**T-18:** Validate custom DNS/NetShield, port-forwarding/Moderate-NAT, and entitlement conflicts.

**T-19:** Validate official parity manifest schema and reject missing test/source metadata for `verified` entries.

**T-20:** Validate LocalAgent requested-versus-applied feature reconciliation.

**T-21:** Validate network-conflict detection without mutation of unowned state.

**T-22:** Validate that feedback is unavailable while blocked upstream; when an authorized adapter is supplied, validate per-event consent, exact payload preview, transport, and redaction.

**T-23:** Validate the monorepo dependency graph, single-lockfile rule, shared schema generation, and forbidden client-to-core/adapter dependency edges.

**T-24:** Validate that the generated client capability matrix covers every required interactive command, query, prompt, error, and event in CLI, TUI, and GUI.

**T-25:** Validate that the server-metadata refresh interval defaults to three hours and rejects every shorter value across config, profiles, IPC, CLI, TUI, and GUI schemas.

**T-26:** Validate refresh-deadline calculation, non-negative jitter, ETag/not-modified handling, persisted restart state, clock rollback, `Retry-After`, and block suppression.

**T-27:** Validate the early-manual-refresh warning and confirmation token, fresh confirmation per request, CLI `--yes` warning output, manual diagnostic counter, single-flight behavior, and reset of the next automatic deadline.

**T-28:** Validate `docs/connection-groups.yaml` schema, unique namespaced IDs, immutable built-in definitions, source/taxonomy revisions, supported selectors, and absence of client-local group catalogs.

**T-29:** Validate the pinned Proton-compatible semantics for Fastest, Fastest excluding my country, Random, Streaming US, Gaming, Anti-censorship, Max security, and Work/School, including protocol and feature overrides.

**T-30:** Validate the checksummed UN M49-to-ISO-alpha-2 mapping, the six regional group memberships, North America composition, deterministic single-continent membership, and unknown-country handling.

**T-31:** Validate physical-country source precedence, provenance, cache state, persisted three-hour location-request suppression, Muon `Retry-After`/block handling, `physical-country-required`, and that group listing or regional resolution creates no API request or throughput estimate.

**T-32:** Inject canaries for username, password, TOTP/recovery code, FIDO payload, session ID, fingerprint, selector, cookie, token, and key through pinned Muon/ProTUN/`pvpnclient`; assert they never reach any log, event, panic, journal fixture, or debug bundle at every allowed runtime log level.

**T-33:** Validate official group ranking is Proton score, immutable `proton:*` groups reject ranking modifiers, regional groups default to Proton score, and declared regional ranking overrides are explicit in status.

**T-34:** Validate latency-probe shortlist, cache age, per-endpoint/global rate limits, cancellation, no background scan, TCP/UDP default, and unanswered-probe handling.

**T-35:** Validate systemd credential input is immutable and read once, session-envelope precedence over password bootstrap, repeated-bootstrap backoff, confirmed `none` behavior, atomic/idempotent empty-store import, source digest/generation tracking, stale-replay refusal, and persistence-health reporting.

**T-36:** Validate YAML input size/depth/alias/duplicate-key policy and fuzz malformed config, profile, parity, and connection-group documents.

**T-37:** Validate field-level configuration authority, rejection of system-only fields in per-UID overlays, administrator security floors, duplicate-policy aliases, and daemon-side revalidation of malicious client requests.

### 17.2 Integration Tests {#172-integration-tests}

Run in Linux network namespaces.

**IT-1:** Create a TUN interface, transfer its FD to the ProTUN adapter, and clean it up idempotently.

**IT-2:** Apply full-tunnel route.

**IT-3:** Apply IPv6 block when IPv6 unsupported.

**IT-4:** Apply nftables kill switch.

**IT-5:** Verify DNS route through VPN table.

**IT-6:** Verify LAN IP bypass plus opt-in `.local` mDNS/local-resolver behavior without ordinary DNS leakage.

**IT-7:** Verify split tunnel UID policy.

**IT-8:** Verify split tunnel cgroup policy.

**IT-9:** Simulate endpoint failure and reconnect.

**IT-10:** Simulate daemon crash with permanent kill switch.

**IT-11:** Verify dynamic IP set updates for domain rules.

**IT-12:** Verify already-running process attachment reports success/partial/failure.

**IT-13:** Verify every ProTUN outer socket is marked into the bypass policy before full-tunnel routing is committed.

**IT-14:** Verify ProTUN UDP, TCP, Stealth, Smart fallback, peer update, connectivity-change, stats, and disconnect callbacks with deterministic test peers.

**IT-15:** Verify LocalAgent feature confirmation, restriction/jail states, certificate refresh, fork-selector refresh, and bounded retry behavior.

**IT-16:** Run the same uplink, route, DNS, kill-switch, IPv6, and reconnect suite with native, NetworkManager, and systemd-networkd adapters.

**IT-17:** Restart NetworkManager and systemd-networkd during connection and verify fail-closed reconciliation without persistent profile/unit changes.

**IT-18:** Verify bounded packet capture permissions, maximum size, and start/stop events.

**IT-19:** Verify frontend API authorization, shared client SDK negotiation/resynchronization, and complete core/API capability equivalence.

**IT-20:** Verify competing TUN/default routes, DNS ownership, nftables rules, and manager drift produce actionable conflict events without disabling other software.

**IT-21:** Run the generated client contract against CLI, Ratatui TUI, and Tauri GUI harnesses and verify equivalent requests, prompts, confirmations, errors, snapshots, and events.

**IT-22:** Verify TUI terminal restoration after normal exit, panic, and handled signals; verify the Tauri release bundle CSP, capability allowlist, local-only assets, and absence of generic shell/filesystem/network commands.

**IT-23:** With CLI, TUI, and GUI connected concurrently, verify unconfirmed early refresh requests return cache without API traffic, one confirmed manual override produces exactly one single-flight request, and client/daemon/network restarts preserve the resulting automatic deadline.

**IT-24:** Resolve every official and regional connection group through core against a Muon-provided catalog subset and entitlement fixture; verify one shared result across CLI, TUI, and GUI, no hidden-server enumeration, no group-specific polling timer, and a single-flight on-demand Proton user-location request only when required with persisted three-hour/request-suppression behavior.

**IT-25:** Verify preferred route-table ID conflicts allocate a different table, and crash cleanup refuses lookalike interfaces/routes/nftables/cgroups without ProtonWire ownership evidence.

**IT-26:** Verify `resolv.conf` symlink/owner/change races, strict `system`/`none` route proofs, explicit off-tunnel DNS confirmation, and no unowned resolver state overwrite.

**IT-27:** Boot a namespace/VM with permanent mode and prove the early firewall unit blocks traffic before uplink configuration, survives main-daemon stop/crash, and is removed only by an authorized explicit disable.

**IT-28:** Verify concurrent Unix UIDs cannot read or mutate each other's account/profile state or steal/disconnect an active tunnel; verify explicit administrative ownership transfer and redacted non-owner status.

**IT-29:** Verify keyring storage runs only through the account owner's credential agent, mutual daemon/agent peer credentials and socket ownership are enforced, target UID and arbitrary keyring operations are not caller-selectable, and boot auto-connect reports unavailable rather than trying to join or spoof a desktop D-Bus session.

**IT-30:** Verify systemd-session import is idempotent, an existing refreshed writable session wins after restart/rebuild, and stale provisioning cannot overwrite it without the explicit administrative replace operation.

### 17.3 End-to-End Tests {#173-end-to-end-tests}

**E2E-1:** Login.

**E2E-2:** Refresh the server cache when eligible using a conditional request; when requested early, show the warning and verify both cancel-to-cache and confirm-to-manual-refresh paths.

**E2E-3:** Connect fastest.

**E2E-4:** Connect by country.

**E2E-5:** Connect exact server.

**E2E-6:** Connect Secure Core by exit country.

**E2E-7:** Connect with NetShield.

**E2E-8:** Connect with port forwarding.

**E2E-9:** Reject port forwarding plus Moderate NAT.

**E2E-10:** Reconnect on network loss.

**E2E-11:** Disconnect and restore networking.

**E2E-12:** Complete Muon login with TOTP/recovery-code and FIDO2/WebAuthn in approved test environments; separately prove human-verification and SSO return the documented upstream blocker until their adapters are verified.

**E2E-13:** Connect with Smart Protocol, WireGuard UDP, WireGuard TCP, and Stealth and report the actual ProTUN selection.

**E2E-14:** Connect to P2P, Tor, Secure Core, and an organization Gateway using entitled test accounts.

**E2E-15:** Exercise free fastest and change-server flows and honor the backend cooldown.

**E2E-16:** Create, duplicate, import, pin, set default, connect, and delete a profile; verify Connect and Go executes only as the requesting user after confirmation.

**E2E-17:** Verify requested and LocalAgent-applied NetShield, VPN Accelerator, NAT, port-forwarding, exit-IP, MTU, restriction, and statistics state.

**E2E-18:** Run the official parity manifest test suite against a Proton staging or approved production test environment.

**E2E-19:** Complete FIDO2/WebAuthn login in an approved test environment. Run connection-feedback submission only after the parity entry is unblocked with an authorized endpoint fixture; until then verify no feedback request can be sent.

**E2E-20:** Complete login, server selection, connect, feature update, profile management, diagnostics, and disconnect journeys independently through CLI, TUI, and GUI against the same daemon build.

**E2E-21:** Exit, crash, and restart the TUI and GUI during an active connection and verify the tunnel is unchanged and each client resynchronizes to the authoritative core state.

**E2E-22:** Run the metadata scheduler for 24 virtual hours, confirm at most eight automatic request windows plus separately counted confirmed manual overrides, then inject rate limiting and verify even a confirmed manual request and every restart honor the persisted suppression deadline.

**E2E-23:** Connect each entitled Proton-compatible group, including Anti-censorship and Fastest excluding my country, and verify its exact target, protocol, feature overrides, physical-country exclusion, status provenance, and refusal behavior when unavailable.

**E2E-24:** Connect Fastest Africa, Asia, Europe, North America, South America, and Oceania; verify the winning server belongs to the requested vendored region and that identical requests through CLI, TUI, and GUI resolve identically.

**E2E-25:** Restart with each credential input/store combination and verify session continuity, no repeated password login when a durable session exists, clear degraded state on write failure, and no secret canary in system journals.

---

## 18. Implementation Milestones {#18-implementation-milestones}

### Milestone 1: Foundation {#milestone-1-foundation}

- Workspace structure
- CLI skeleton
- Ratatui TUI skeleton
- Tauri GUI shell with bundled local UI and restrictive capability baseline
- Shared unprivileged client SDK
- Optional unprivileged per-user credential agent
- Daemon skeleton
- Versioned frontend Unix-socket API and event stream
- Config loader
- Logging
- Error types
- CI, parity-manifest validation, SBOM, license, vulnerability, and reproducibility skeleton
- GPL-3.0-or-later licensing and dependency-license clearance

### Milestone 2: Muon API, Authentication, and Server Cache {#milestone-2-muon-api-authentication-and-server-cache}

- Pinned Muon adapter
- SRP login/session, TOTP/recovery-code, FIDO2 payload/WebAuthn, forking, and alternative-routing flows
- Explicit upstream blockers for human verification, SSO, guest mode, and feedback until authorized public adapters exist
- Separate credential-input and writable-store abstractions, keyring agent, systemd credential source, and persistence-health reporting
- Upstream secret-log suppression and canary regression suite
- Server metadata retrieval
- Metadata cache
- Three-hour-minimum single-flight automatic metadata scheduler, warned/confirmed manual override, conditional requests, persisted deadlines, positive jitter, and rate-limit suppression
- Entitlement model
- Free-plan/cooldown policy
- Gateway/dedicated-server data
- Server list command
- Muon user-location capture and provenance cache without periodic polling

### Milestone 3: Server Selection {#milestone-3-server-selection}

- Selection filters
- Core connection-group registry generated from the versioned catalog
- Proton-compatible built-in selectors and presets
- Fastest Africa, Asia, Europe, North America, South America, and Oceania using vendored UN M49 data
- Load sorting
- Latency probing
- Proton-score official Fastest and separate ProtonWire balanced policy
- Exclusion rules
- Secure Core route selection
- P2P, Tor, Gateway, state/region, and exact physical-server selection
- Dry-run output

### Milestone 4: ProTUN Core {#milestone-4-protun-core}

- Pinned ProTUN adapter and encrypted PersistentCache
- TUN creation and FD ownership
- Peer/port candidate translation
- LocalAgent integration and setting reconciliation
- Smart, WireGuard UDP, WireGuard TCP, and Stealth
- Outer-socket marks, connection state, statistics, and packet capture
- Disconnect cleanup
- Protocol capability reporting

### Milestone 5: Linux Network Control and Adapters {#milestone-5-linux-network-control-and-adapters}

- Transactional routes and policy routing
- Dynamic route-table ownership and collision handling
- DNS modes
- nftables kill switch
- Advanced kill switch
- Early-boot permanent kill-switch restore unit
- IPv6 leak prevention
- LAN access
- Native adapter
- NetworkManager adapter
- systemd-networkd adapter
- Cross-adapter conformance and manager-restart tests

### Milestone 6: Official Service Parity {#milestone-6-official-service-parity}

- NetShield
- VPN Accelerator
- Moderate NAT
- Port forwarding
- NAT-PMP lease renewal
- Profiles, recents, pins, defaults, and Connect and Go
- Group references, copy-to-profile, recents, pins, defaults, and auto-connect integration
- Auto-connect/reconnect
- Free change-server flow
- P2P, Tor, Gateway, and Secure Core end-to-end flows
- Observability and opt-in crash reporting
- Network conflict detection and upstream-gated opt-in connection feedback

### Milestone 7: Split Tunneling {#milestone-7-split-tunneling}

- UID/GID split rules
- cgroup app launcher
- IP/CIDR split rules
- Domain split rules and dynamic IP sets
- Include/exclude modes
- Best-effort existing-process attach
- Kill switch compatibility

### Milestone 8: Frontends, Packaging, and Hardening {#milestone-8-frontends-packaging-and-hardening}

- CLI, Ratatui TUI, and Tauri GUI capability-parity completion
- Generated client matrix and cross-client conformance harness
- TUI terminal lifecycle, accessibility, and SSH hardening
- Tauri CSP, capability allowlist, local-asset, accessibility, tray, and notification hardening
- systemd unit
- Nix package
- NixOS flake module
- Debian package
- Fedora package
- Arch package
- Security hardening
- Official parity audit and stable-release gates

---

## 19. Open Questions {#19-open-questions}

**OQ-1:** Which Muon/Proton API endpoints and client identifiers are stable and authorized for a third-party Proton VPN client, and what compatibility commitment will Proton provide?

**OQ-2:** Will Proton publish explicit SPDX/license metadata and complete corresponding source terms for Muon, `pvpnclient`, and every ProTUN transitive Proton crate? This blocks distribution.

**OQ-3:** Which authorized public Muon/API contracts expose human-verification continuation, SSO initiation/completion, guest VPN sessions, connection feedback, free change-server/cooldown state, Gateways, and device/session-limit remediation to non-official callers? Pinned Muon does not itself complete the first four flows.

**OQ-4:** Will ProTUN provide stable Rust API documentation, a semver policy, changelogs, lockfiles, and long-term public registry/source availability after beta?

**OQ-5:** What is the safest implementation strategy for domain-based split tunneling with CDN-backed and DoH-using applications?

**OQ-6:** How reliable is cgroup migration for already-running processes across common Linux distributions?

**OQ-7:** What is the best TPM2 sealing policy for headless servers where PCR values may change after kernel or initrd upgrades?

**OQ-8:** Which versioned session-envelope import/export format can be safely provisioned through systemd credentials without coupling NixOS configuration to Muon's private serialized representation?

**OQ-9:** Should NetworkManager integration be observation-only, or should ProtonWire also publish transient device/DNS state through NetworkManager for desktop visibility while retaining tunnel ownership?

**OQ-10:** Which systemd-networkd and systemd-resolved versions form the supported D-Bus/netlink compatibility floor?

**OQ-11:** Does ProTUN's LocalAgent `split_tcp` setting exactly represent the current official VPN Accelerator toggle on all servers, or are additional API fields required?

**OQ-12:** Is official-style profile synchronization server-side or app-local on each platform, and may third-party clients interoperate with it?

**OQ-13:** Will Muon expose canonical Proton connection-group definitions and the Proton user-location response with stable IDs and cache guidance, or must ProtonWire continue maintaining pinned official-client compatibility templates?

**OQ-14:** Will Proton remove the TOTP-at-info and selector/cookie-at-trace emissions from Muon/`pvpnclient`, publish a security logging contract, and provide a supported way to suppress sensitive dependency events?

**OQ-15:** Will ProTUN expose a versioned Linux interface-address/DNS contract and declare `rust-version`? Until then ProtonWire must contract-test the values observed in pinned ProTUN/`pvpnclient` source and establish its own MSRV.

---

## 20. Clarifying Notes {#20-clarifying-notes}

**CN-1:** ProTUN is the protocol engine. ProtonWire creates the Linux TUN device and manages host policy but does not implement WireGuard cryptography, WireGuard TCP, Stealth, Smart Protocol, certificates, or LocalAgent behavior.

**CN-2:** “No hard NetworkManager dependency” means `native` and `networkd` modes install and run without NetworkManager. NetworkManager remains a supported optional uplink adapter.

**CN-3:** “VPN Accelerator” is requested through ProTUN/LocalAgent, not reimplemented as a local acceleration algorithm.

**CN-4:** “NetShield” is treated as a Proton DNS-backed mode, not as a local adblock DNS resolver.

**CN-5:** “Split tunneling by app” on Linux must use cgroup v2, process tracking, and policy routing. Path-name matching alone is not sufficient.

**CN-6:** A `--by speed` mode is intentionally unsupported because Proton does not expose an authoritative throughput metric. ProtonWire must not present a locally inferred value as Proton server data.

**CN-7:** Port forwarding requires compatible server selection and NAT-PMP lease management.

**CN-8:** Moderate NAT and port forwarding are mutually exclusive.

**CN-9:** Secure Core is required in v1.

**CN-10:** Domain-based split tunneling is required in v1, but must explicitly document limitations involving CDNs, DoH, DoT, hardcoded IPs, and shared hosting.

**CN-11:** Already-running process attachment is best-effort. A cgroup move cannot reliably reroute existing sockets/conntrack flows, so ProtonWire must report exact attachment status and recommend an application restart rather than pretending all traffic moved.

**CN-12:** Password storage is allowed only through an approved writable store. Plaintext storage is forbidden. systemd credentials are externally provisioned immutable input, not a ProtonWire storage backend.

**CN-13:** NixOS support means a flake module, not merely a package.

**CN-14:** Stealth, WireGuard TCP, WireGuard UDP, and Smart Protocol are required in v1 because pinned ProTUN exposes them. Availability for a particular connection still depends on peer/port candidates and backend policy.

**CN-15:** “Feature complete” is a moving, versioned parity contract, not a marketing assertion. The manifest and conformance tests define it.

**CN-16:** Platform-specific UI is not parity scope. Applicable service behavior, error semantics, status, and safe handoffs are parity scope.

**CN-17:** ProTUN and Muon are beta/public-registry dependencies. ProTUN's tag has no Cargo lockfile, and Muon/`pvpnclient` source packages lack applicable license declarations. Internal adapters, the root exact lock, checksum/source archives, and release gates are mandatory risk containment.

**CN-18:** NetworkManager and systemd-networkd never own `protonwire0`, ProTUN, split-tunnel policy, or kill-switch policy.

**CN-19:** The official Linux client currently treats split tunneling and kill switch as conflicting. ProtonWire's tested coexistence is an intentional added feature, not a parity deviation.

**CN-20:** OpenVPN and IKEv2 are intentionally legacy-excluded. Their presence in an older or platform-specific official client does not block ProtonWire v1.

**CN-21:** “Core handles everything” means `protonwire-core` is the sole application state machine and behavior implementation. The daemon supplies its privilege boundary and infrastructure adapters; clients supply presentation only.

**CN-22:** CLI, TUI, and GUI are all v1 deliverables. They may have medium-specific presentation capabilities, but none may omit an applicable VPN capability or create its own behavioral semantics.

**CN-23:** The three-hour refresh floor protects Proton's server-catalog API from unnecessary polling. It does not apply to session/certificate expiry handling, LocalAgent control traffic, connection events, latency probes against selected candidates, or split-tunnel DNS TTLs.

**CN-24:** A manual refresh is a user-confirmed exception to ProtonWire's local three-hour automatic interval, not an override of Proton's rate-limit or block instructions. It never becomes a saved “always force” preference.

**CN-25:** The `proton:` namespace means the group targets source-pinned official-compatible behavior; it is not itself a `verified` status and does not claim the group is currently delivered by Proton's backend. `definition_source` distinguishes an API-supplied definition from a pinned official-client compatibility template, while the parity manifest records verification state.

**CN-26:** “Fastest” is a selection intent, not an estimated speed measurement. Official Fastest and default regional Fastest use Proton's opaque catalog score after hard filters. ProtonWire's `balanced`, `load`, and measured-`latency` policies are separate, explicit choices and expose no throughput estimate.

**CN-27:** Physical-country exclusion is fail-closed. ProtonWire never substitutes the VPN exit country, locale, or a third-party geolocation result when the user's pre-VPN country is unavailable.

**CN-28:** Regional group names use a documented six-continent convenience view over a pinned UN M49 dataset. North America deliberately combines Northern America, Central America, and the Caribbean; South America remains separate.

**CN-29:** Built-in groups and their regional taxonomy are local versioned data. Listing them never refreshes Proton metadata, and resolving them must reuse the daemon's cached authoritative server subset and refresh scheduler.

**CN-30:** The root daemon hosts core and therefore belongs to the authentication trust boundary. “Unprivileged prompt” means the UI and launch/browser actions are not root; it does not mean a secret consumed by daemon-hosted Muon is hidden from root.

**CN-31:** LocalAgent's `groups` field is connection metadata of undocumented semantics, not evidence that Proton delivered the connection-group catalog requested by this product.

**CN-32:** The three-hour minimum governs Proton catalog/location API requests. It does not authorize aggressive endpoint probing: local latency probes are separately bounded, cached, on-demand, and never catalog-wide background scans.

**CN-33:** `/etc/protonwire/config.yaml` and NixOS module options are administrator policy. `$XDG_CONFIG_HOME/protonwire/config.yaml` is a per-UID convenience overlay with an allowlisted schema, not a way to replace global networking, refresh, credential, or protection policy.

---

## 21. Traceability Matrix {#21-traceability-matrix}

| User Need | Requirement IDs |
|---|---|
| Compiled app | G-1, NFR-28 |
| Rust rewrite | G-1, Section 16 |
| Monorepo with one authoritative core | G-1, G-19, FR-127A to FR-127D, NFR-38 to NFR-40 |
| CLI, Ratatui TUI, and Tauri GUI | G-20, FR-127B to FR-127K, Section 9, IT-21 to IT-22, E2E-20 to E2E-21 |
| ProTUN protocol engine | G-2, NG-8, Section 6.5, FR-24 to FR-32J |
| Muon API/auth engine | G-2, FR-7K to FR-7O, FR-13A, ER-12, ER-14 |
| No hard network manager | G-16, NG-2, Section 6.6, NFR-25 to NFR-25B |
| NetworkManager support | G-16, Section 6.6, NFR-25B, IT-16 to IT-17 |
| systemd-networkd support | G-16, Section 6.6, NFR-25A to NFR-25B, IT-16 to IT-17 |
| Official client parity | G-4, G-17, Section 5.4, M-18 |
| Smart/WG UDP/WG TCP/Stealth | FR-32E to FR-32J, E2E-13 |
| Profiles/recents/pins/defaults | FR-114A, FR-115 to FR-116C |
| Official Proton connection groups | G-21, FR-23I to FR-23M, FR-23Q to FR-23V, T-28 to T-29, IT-24, E2E-23 |
| Fastest regional groups | G-18, G-21, FR-23N to FR-23P, FR-23U to FR-23V, T-30, IT-24, E2E-24 |
| Physical-country exclusion without third-party geolocation | FR-23L, FR-23P to FR-23R, T-31, E2E-23 |
| P2P/Tor/Gateway | FR-15, FR-23H, E2E-14 |
| Free-plan behavior | FR-23G, T-16, E2E-15 |
| Split tunneling | FR-66 to FR-84 |
| DNS | FR-41 to FR-49 |
| Kill switch | FR-56 to FR-65 |
| Port forwarding | FR-85 to FR-94 |
| NetShield | FR-50 to FR-55 |
| VPN Accelerator | FR-100 to FR-103 |
| Moderate NAT | FR-95 to FR-99 |
| LAN and local-name access | FR-104 to FR-108A, IT-6 |
| Smart server selection | FR-14 to FR-23 |
| Country/server targeting | FR-15, Client Section 9 |
| Exclude country list | FR-21 |
| Official Proton score plus load/measured-latency selection | FR-14 to FR-19B |
| Proton API metadata refresh budget | FR-10 to FR-13I, NFR-41 to NFR-41A, ER-16, SEC-24, T-25 to T-27, IT-23, E2E-22 |
| Password/session storage with preferred writable-store order | G-11, FR-7A to FR-7JC |
| Keyring first | FR-7B |
| TPM2 second | FR-7B, FR-7G |
| systemd credential input, not a storage backend | FR-7B, FR-7F, FR-143C |
| Provisioned-session replay protection | FR-7JC, FR-143CA, T-35, IT-30 |
| Configuration authority | Section 10, SEC-6, SEC-27, T-37, CN-33 |
| Upstream secret-log containment | FR-7P, FR-121, SEC-25, T-32 |
| Multi-user tunnel ownership and isolation | Section 6.3, NFR-16B, IT-28 |
| Secure Core in v1 | G-12, FR-23A to FR-23F |
| Stealth required through ProTUN | G-4, FR-32E to FR-32J |
| Domain split tunneling now | G-13, FR-77 to FR-82 |
| Attach already-running processes | G-14, FR-72, FR-73, FR-75 |
| Declarative and interactive NixOS login | FR-143A to FR-143D, including FR-143CA |
| NixOS as flake module | G-15, FR-143A to FR-143H |
| Headless and independent frontends | G-5, FR-127 to FR-127K, NFR-24, Packaging Section 14 |
| Dependency/license safety | NFR-33 to NFR-37, Section 16 |
| Safe failure behaviour | FR-56 to FR-65, ER-1 to ER-15 |

---

## 22. Definition of Done {#22-definition-of-done}

The project is considered v1 complete when:

1. All normal Proton API, authentication, session, alternative-routing, server, entitlement, Gateway, and free-plan operations use the pinned Muon adapter.
2. Login, refresh, logout, TOTP/recovery-code and FIDO2/WebAuthn 2FA plus all known LocalAgent jail/challenge states pass end-to-end tests. Human verification, SSO, guest mode, and feedback either pass through a newly verified authorized public adapter or remain explicit current-evidence `blocked-upstream` entries with no approximation.
3. Writable credential storage follows per-user keyring agent, TPM2, then explicit encrypted fallback order; systemd credentials are modeled as read-only input. Muon account sessions and ProTUN certificate/private-key/internal-session records are distinct, provisioned sessions cannot replay over newer writable state, durable-write health is visible, and no raw password is persisted by default.
4. Every production tunnel uses pinned ProTUN and an owned Linux TUN FD; no parallel kernel-WireGuard, `wireguard-go`, Python, or `wg-quick` control path exists.
5. Smart Protocol, WireGuard UDP, WireGuard TCP, and Stealth connect successfully, obey manual fallback policy, survive network changes, and report the actual peer/protocol/port.
6. Fastest, Fastest excluding my country, random, every official/ProtonWire connection group, country, state/region, city, exact server, P2P, Tor, Secure Core entry/exit, Gateway, and dedicated-server selection pass entitlement-aware tests; official Fastest uses Proton score and never silently switches to ProtonWire's weighted model.
7. Free accounts use only backend-authorized fastest/change-server behavior and honor the authoritative cooldown.
8. Standard, Secure Core, P2P, Tor, Gateway, and connection-group profile targets support create/edit/duplicate/delete/import/export/pin/default/recent operations, and Connect and Go runs only as the confirmed unprivileged user.
9. NetShield levels and statistics, VPN Accelerator, strict/moderate NAT, port forwarding/lease publication, IPv4/IPv6, server MTU, and restrictions are requested and reconciled against LocalAgent-applied state.
10. Custom DNS and NetShield, plus port forwarding and Moderate NAT, enforce their incompatibility rules without silent changes.
11. Standard and permanent kill switches, DNS leak prevention, IPv6 leak prevention, LAN allow/block, auto-connect, and reconnect remain fail-closed through daemon and network-manager restarts.
12. Split tunneling supports official include/exclude app and IP/CIDR behavior plus ProtonWire process, UID, GID, cgroup, domain, port/protocol, and best-effort running-process attachment while preserving kill-switch guarantees.
13. Human and JSON status plus the shared client API expose connection state, server/route, ProTUN state/statistics, requested/applied features, port forwarding, integration adapter, restrictions, and stable errors.
14. Network-conflict detection, bounded opt-in FD-based packet capture, redacted debug bundles, and opt-in crash reports pass privacy and permission tests. Connection feedback is unavailable unless its upstream gate is cleared.
15. The CLI, Ratatui TUI, and Tauri GUI ship from the same monorepo, use only the shared client SDK, pass the generated capability matrix, and expose every applicable core capability without root access, ProTUN/Muon linking, duplicated behavior, or a second network stack.
16. The full conformance suite passes in `native`, `network-manager`, and `networkd` modes; NetworkManager and systemd-networkd remain optional and never own `protonwire0` or privacy policy.
17. CLI, TUI, GUI, daemon, credential agent, early firewall helper, systemd, Debian, Fedora, Arch, Nix, and NixOS flake artifacts build from the single root lockfile; headless packages do not pull GUI dependencies, and the NixOS module supports interactive login and read-only systemd-credential provisioning without secrets in the Nix store.
18. `docs/official-parity.yaml` validates and every applicable `required` capability is `verified`; all exceptions are explicitly `blocked-upstream`, `not-applicable`, or `legacy-excluded` with current evidence.
19. ProTUN, Muon, `pvpnclient`, and every transitive crate pass license/source review, exact checksum pinning, SBOM, vulnerability audit, and reproducible offline-source build. No stable binary is distributed before this gate passes.
20. Integration and end-to-end tests show no route, DNS, IPv4, IPv6, outer-socket, manager-restart, or cleanup leak, and documentation explains every remaining limitation and parity distinction.
21. Automatic server-catalog refresh defaults to and enforces a minimum three-hour interval, remains single-flight across every client and restart, honors Proton cache/rate-limit guidance, and passes the 24-hour request-budget test. A fresh warning and confirmation permits a manual local-interval override but cannot bypass Proton rate-limit or block suppression.
22. `docs/connection-groups.yaml` validates; official compatibility groups match their pinned Proton sources, regional groups match the checksummed UN M49 mapping, country-dependent groups fail closed without a physical country, listing creates no API traffic, and CLI/TUI/GUI produce identical catalog and resolution behavior.
23. Upstream log canary tests prove passwords, TOTP/recovery codes, FIDO payloads, selectors, cookies, sessions, tokens, fingerprints, and keys never reach any supported sink; production dependency trace logging cannot be enabled.
24. Permanent kill switch is active before uplink configuration at boot, routing/firewall/DNS cleanup requires ownership evidence, preferred routing-table collisions are safe, and strict system/none DNS modes pass route proofs.
25. Multiple local UIDs cannot read or mutate one another's account/profile state or active connection without explicit administrative transfer, and desktop keyrings are accessed only by the same-UID credential agent.
26. Per-UID configuration overlays cannot change system-only fields or weaken administrator floors, and a provisioned systemd session cannot overwrite newer writable state through restart or rebuild replay.
