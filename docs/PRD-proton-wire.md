# PRD: ProtonWire — NetworkManager-Free Proton VPN CLI/Daemon in Rust

**Document ID:** PRD-proton-wire  
**Version:** v0.2.0  
**Status:** Draft for Codex implementation  
**Target path:** `/docs/PRD-proton-wire.md`  
**Primary language:** Rust  
**Target OS:** Linux first  
**Protocol scope:** WireGuard first; Stealth only if implementable over WireGuard-compatible transport  
**NetworkManager dependency:** Forbidden  
**Last updated:** 2026-06-16

---

## 1. Executive Summary {#1-executive-summary}

ProtonWire is a compiled, Linux-first Proton VPN client written in Rust. It replaces the Python Proton VPN CLI model with a native WireGuard implementation that does not depend on NetworkManager. The application consists of an unprivileged CLI, a privileged daemon, and shared Rust libraries.

The product must support the major user-facing capabilities currently available in Proton VPN GUI clients where technically possible on Linux:

- Pure WireGuard tunnel management
- Optional Stealth protocol support if implementable over WireGuard-compatible transport
- Login and session management
- Secure credential storage with backend priority: keyring, TPM2, systemd LoadCredential, explicit encrypted local fallback
- Server discovery and metadata caching
- Smart server selection by load, latency, estimated speed, feature constraints, preferred country, city, exact server, and exclusion rules
- Country, city, Secure Core route, and specific server connection
- Split tunneling by app, process, UID, GID, cgroup, IP/CIDR, domain, and port/protocol
- Best-effort attachment of already-running processes to split-tunnel policy
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
- Machine-readable status output
- Import/export of profiles
- Systemd integration
- NixOS support as a flake module
- Declarative and interactive login support on NixOS

The core differentiator is that ProtonWire must be reliable in headless and server environments. It must not rely on graphical sessions, NetworkManager, desktop-only secret services, or GUI-specific assumptions.

---

## 2. Background and Problem Statement {#2-background-and-problem-statement}

The existing Proton VPN Linux stack is Python-based and oriented around Proton’s current Linux app ecosystem. The current CLI and GUI experience is useful for desktop Linux users, but there are gaps for users who want a minimal, compiled, headless-friendly, server-grade client.

The target product must provide:

1. A compiled client.
2. No dependency on NetworkManager.
3. Direct WireGuard interface, route, DNS, and firewall control.
4. Feature parity with the Proton VPN GUI where technically possible.
5. Smarter server selection based on measurable performance and server metadata.
6. Optional feature flags, matching the GUI pattern where features are individually enabled or disabled.
7. Clean architecture suitable for NixOS, servers, containers, and minimal Linux distributions.

ProtonWire should behave as a local VPN control plane for Proton VPN, not merely as a wrapper around `wg-quick`.

---

## 3. Goals and Non-Goals {#3-goals-and-non-goals}

### 3.1 Goals {#31-goals}

**G-1:** Provide a Rust-based compiled Proton VPN CLI and daemon.

**G-2:** Implement direct WireGuard lifecycle management without NetworkManager.

**G-3:** Support smart server selection based on country, city, server, load, latency, estimated speed, feature constraints, user preferences, and exclusion rules.

**G-4:** Support Proton GUI-equivalent optional features where technically feasible:

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
- P2P-aware server selection
- Streaming-aware server selection if server metadata exposes it

**G-5:** Provide strong headless support.

**G-6:** Provide explicit machine-readable output for scripts and automation.

**G-7:** Provide safe failure behaviour: no traffic leaks when kill switch is enabled.

**G-8:** Support NixOS, Debian, Ubuntu, Fedora, Arch, and generic systemd-based Linux distributions.

**G-9:** Use principle-of-least-privilege architecture.

**G-10:** Make every major feature testable by automated integration tests.

**G-11:** Support secure credential storage using this priority order: keyring, TPM2-backed credential sealing, systemd LoadCredential, explicit encrypted local fallback.

**G-12:** Include Secure Core in v1.

**G-13:** Include domain-based split tunneling in v1.

**G-14:** Attempt best-effort attachment of already-running processes to split-tunnel policy.

**G-15:** Provide NixOS support as a flake module.

### 3.2 Non-Goals {#32-non-goals}

**NG-1:** ProtonWire will not implement OpenVPN.

**NG-2:** ProtonWire will not depend on NetworkManager.

**NG-3:** ProtonWire will not provide a GUI in v1.

**NG-4:** ProtonWire will not attempt to bypass Proton account plan restrictions.

**NG-5:** ProtonWire will not scrape private APIs in a brittle way when official, documented, or legally reusable client API behaviour can be used instead.

**NG-6:** ProtonWire will not store account credentials in plaintext.

**NG-7:** ProtonWire will not guarantee feature availability if Proton’s backend, account plan, protocol support, or server metadata does not expose the required capability.

**NG-8:** ProtonWire will not implement Stealth protocol in v1 unless it can be implemented cleanly over WireGuard-compatible transport without compromising the pure WireGuard architecture.

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

---

## 5. Product Scope {#5-product-scope}

### 5.1 v1 Scope {#51-v1-scope}

The v1 release must include:

- Rust CLI binary: `protonwire`
- Rust daemon binary: `protonwire-daemon`
- WireGuard tunnel creation and teardown
- Stealth protocol if implementable over WireGuard-compatible transport
- Proton login/session support
- Secure credential storage using keyring, TPM2, LoadCredential, or explicit encrypted fallback
- Server metadata retrieval and caching
- Smart server selection
- Country/server/city connect commands
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
- Systemd units
- NixOS flake module
- NixOS declarative and interactive login support
- Config file support
- JSON output
- Structured logs
- Nix package expression

### 5.2 v1.1 Scope {#52-v11-scope}

- TUI interface
- Profile import/export hardening
- Latency history database
- Server health scoring history
- Prometheus metrics endpoint
- Shell completions
- Optional desktop notification helper

### 5.3 v2 Scope {#53-v2-scope}

- Advanced Secure Core route optimization
- Secure Core multi-hop policy preferences
- Stealth protocol if not feasible in v1
- Optional GUI frontend
- Cross-platform daemon abstraction
- macOS support
- Windows support
- Browser extension integration

---

## 6. System Architecture {#6-system-architecture}

### 6.1 Components {#61-components}

```text
protonwire
  Unprivileged CLI frontend.

protonwire-daemon
  Privileged system daemon responsible for WireGuard, routing, DNS, firewall,
  NAT-PMP, split tunneling, Secure Core routing state, and kill-switch enforcement.

protonwire-core
  Shared Rust library for Proton API integration, config models, validation,
  server selection, auth, entitlement parsing, and profile handling.

protonwire-ipc
  Unix-domain socket protocol shared between CLI and daemon.

protonwire-net
  Linux networking module: netlink, routing tables, nftables, WireGuard UAPI.

protonwire-policy
  Split tunneling, kill switch, LAN exceptions, DNS policy, server selection policy.

protonwire-pf
  NAT-PMP client and port forwarding lease renewal manager.

protonwire-store
  Secure local state storage, token storage, server metadata cache, latency DB.
```

### 6.2 Privilege Model {#62-privilege-model}

The CLI must run unprivileged by default. The daemon must run as root or with a tightly scoped capability set.

Required Linux capabilities may include:

```text
CAP_NET_ADMIN
CAP_NET_RAW
CAP_DAC_READ_SEARCH
```

The final capability set must be minimized during implementation.

### 6.3 IPC Model {#63-ipc-model}

The CLI must communicate with the daemon using Unix-domain socket IPC with peer credential checks.

Default socket path:

```text
/run/protonwire/protonwire.sock
```

D-Bus/PolicyKit integration may be added later, but must not be required for headless operation.

### 6.4 Process Boundary {#64-process-boundary}

The CLI must never directly manipulate routing, DNS, WireGuard interfaces, nftables, or NAT-PMP. All privileged operations must go through the daemon.

### 6.5 WireGuard Backend {#65-wireguard-backend}

The daemon must use native Linux WireGuard support via:

1. WireGuard kernel module through netlink / WireGuard UAPI, preferred.
2. `wireguard-go`, optional fallback only if kernel WireGuard is unavailable.

The application must not depend on:

- `wg-quick`
- NetworkManager
- systemd-networkd
- resolvconf as a mandatory dependency
- desktop network applets

It may invoke `wg` only as a debug fallback in development, not as production control flow.

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

**Acceptance Criteria**

```gherkin
Given the user is not authenticated
When the user runs "protonwire login"
Then the CLI starts a supported login flow
And no raw password is persisted unless explicitly requested
And secure tokens are stored using the configured credential backend
```

```gherkin
Given the stored session has expired
When the user runs "protonwire connect fastest"
Then the daemon refreshes the session
And the connection proceeds without requiring a new login
```

### 7.1A Credential Storage and Password Handling {#71a-credential-storage-and-password-handling}

**FR-7A:** ProtonWire must support optional password storage.

**FR-7B:** Credential storage backend priority must be:

```text
1. Keyring
2. TPM2
3. systemd LoadCredential
4. Explicit encrypted local fallback
```

**FR-7C:** The app must prefer storing refresh/session tokens over storing the raw password when the authentication model allows it.

**FR-7D:** If raw password storage is explicitly enabled by the user, the CLI must display a warning and require confirmation unless `--yes` is provided.

**FR-7E:** The app must support headless-safe credential storage.

**FR-7F:** The app must support systemd `LoadCredential` for declarative, service-managed deployments.

**FR-7G:** TPM2-backed storage must seal credentials to local machine state where available.

**FR-7H:** The app must expose current credential backend in `protonwire account --json`.

**FR-7I:** The app must allow migrating credentials between supported backends.

**FR-7J:** The app must fail safely if the configured credential backend becomes unavailable.

Example commands:

```bash
protonwire login
protonwire login --store-password
protonwire login --credential-backend keyring
protonwire login --credential-backend tpm2
protonwire login --credential-backend loadcredential
protonwire credentials status
protonwire credentials migrate --to tpm2
protonwire credentials forget-password
```

Example config:

```yaml
account:
  credential_backend: auto
  allow_password_storage: false
  prefer_token_storage: true
  encrypted_local_fallback: false
  load_credential_names:
    username: protonwire-username
    password: protonwire-password
    refresh_token: protonwire-refresh-token
```

**Acceptance Criteria**

```gherkin
Given keyring is available
When the user runs "protonwire login --store-password"
Then ProtonWire stores credentials in the keyring
And does not attempt TPM2 or LoadCredential
```

```gherkin
Given keyring is unavailable
And TPM2 is available
When the user runs "protonwire login --store-password"
Then ProtonWire stores credentials using TPM2-backed storage
And reports "credential_backend: tpm2" in account status
```

```gherkin
Given keyring and TPM2 are unavailable
And systemd LoadCredential is configured
When the daemon starts
Then ProtonWire reads credentials from systemd-provided credential files
And does not persist them elsewhere
```

```gherkin
Given no secure credential backend is available
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
- Streaming support if exposed
- Port forwarding support
- IPv6 support
- Online/offline status
- Logical server vs physical server mapping

**FR-10:** The app must cache server metadata locally.

**FR-11:** The app must refresh metadata on demand.

**FR-12:** The app must auto-refresh stale metadata before connection.

**FR-13:** The app must continue to use cached metadata during temporary API outages if the cache is within a configurable emergency threshold.

**Acceptance Criteria**

```gherkin
Given the local server cache is older than the configured TTL
When the user runs "protonwire connect uk"
Then the app refreshes server metadata before choosing a server
```

```gherkin
Given the Proton API is unavailable
And the local server cache is within the emergency cache window
When the user runs "protonwire connect fastest"
Then the app may use cached metadata
And the status output must show that cached metadata was used
```

### 7.3 Smart Server Selection {#73-smart-server-selection}

**FR-14:** The app must support smart server selection.

**FR-15:** The user must be able to select by:

- Fastest overall
- Random
- Country
- City
- Exact server
- Secure Core route
- Lowest load
- Lowest latency
- Highest estimated speed
- P2P
- Secure Core
- Port-forwarding-capable
- Excluded countries
- Excluded servers
- Preferred countries
- Preferred cities
- Feature constraints

**FR-16:** Smart selection must use a weighted scoring model.

Default scoring formula:

```text
score =
  (load_weight * normalized_load_score)
+ (latency_weight * normalized_latency_score)
+ (speed_weight * normalized_speed_score)
+ (stability_weight * stability_score)
+ (feature_weight * feature_match_score)
+ (history_weight * historical_success_score)
```

Lower score means better candidate.

Default weights:

```yaml
server_selection:
  weights:
    load: 0.30
    latency: 0.30
    speed: 0.25
    stability: 0.10
    feature_match: 0.05
    history: 0.00
```

**FR-17:** If the user asks for `load`, server choice must prioritize lowest load.

**FR-18:** If the user asks for `latency`, server choice must actively measure latency before connecting.

**FR-19:** If the user asks for `speed`, server choice must estimate speed from server metadata, historical local measurements, and optional active probes.

**FR-20:** If the user provides a country, selection must be limited to that country unless the country is excluded or unavailable.

**FR-21:** If the user provides an exclude country list, those countries must never be selected.

**FR-22:** If no server satisfies all constraints, the CLI must return a structured error explaining which constraints eliminated candidates.

**FR-23:** Exact server requests must never silently fall back to another server.

Example commands:

```bash
protonwire connect fastest
protonwire connect country GB
protonwire connect country GB --by latency
protonwire connect country NL --by load
protonwire connect country DE --by speed
protonwire connect city "London" --by latency
protonwire connect server "UK#42"
protonwire connect fastest --exclude-country US --exclude-country AU
protonwire connect fastest --require p2p --require port-forwarding
protonwire connect fastest --netshield malware
protonwire select fastest --dry-run --json
```

Selection request example:

```json
{
  "mode": "fastest",
  "country": "GB",
  "city": null,
  "server": null,
  "sort_by": "latency",
  "required_features": ["wireguard"],
  "optional_features": ["vpn_accelerator"],
  "excluded_countries": ["US", "AU"],
  "excluded_servers": [],
  "weights": {
    "load": 0.25,
    "latency": 0.50,
    "speed": 0.20,
    "stability": 0.05
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
When the fastest server is in the United States
Then that server is excluded
And the next best non-excluded server is selected
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
- Highest estimated speed
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
Then ProtonWire selects the best eligible Secure Core route
And status output shows both entry and exit servers
```

```gherkin
Given Secure Core is requested
And no eligible route satisfies the requested constraints
When the user runs the connect command
Then ProtonWire must not fall back to non-Secure-Core servers
And must return a no-eligible-secure-core-route error
```

### 7.4 WireGuard Tunnel Lifecycle {#74-wireguard-tunnel-lifecycle}

**FR-24:** The daemon must create a WireGuard interface directly.

**FR-25:** Default interface name must be `protonwire0`.

**FR-26:** The interface name must be configurable.

**FR-27:** The daemon must configure private key, peer public key, endpoint, allowed IPs, persistent keepalive, MTU, IPv4 address, and IPv6 address where available.

**FR-28:** The daemon must support reconnecting with a new endpoint.

**FR-29:** The daemon must expose handshake status.

**FR-30:** The daemon must expose RX/TX counters.

**FR-31:** The daemon must cleanly remove stale interfaces on startup if they were created by ProtonWire.

**FR-32:** The daemon must not delete or modify WireGuard interfaces it did not create unless explicitly configured.

**Acceptance Criteria**

```gherkin
Given the daemon has valid WireGuard configuration
When the user runs "protonwire connect server UK#42"
Then the daemon creates the configured WireGuard interface
And configures the selected Proton peer
And the tunnel reaches a successful handshake state
```

### 7.4A Stealth Protocol {#74a-stealth-protocol}

**FR-32A:** ProtonWire must investigate Stealth protocol support for v1.

**FR-32B:** If Stealth can be implemented over a WireGuard-compatible transport without violating the pure WireGuard architecture, it must be included in v1.

**FR-32C:** If Stealth requires a non-WireGuard protocol stack, proprietary unsupported transport, or GUI-only implementation path, it must be marked as a future task.

**FR-32D:** The CLI must expose protocol capability detection.

**FR-32E:** The app must not advertise Stealth as available unless it can successfully connect using that mode.

Example commands:

```bash
protonwire protocols list
protonwire connect fastest --protocol wireguard
protonwire connect fastest --protocol stealth
```

Protocol status example:

```json
{
  "protocols": {
    "wireguard": {
      "available": true,
      "supported": true
    },
    "stealth": {
      "available": false,
      "supported": false,
      "reason": "not_implemented_over_wireguard_compatible_transport"
    }
  }
}
```

**Acceptance Criteria**

```gherkin
Given Stealth is implementable over WireGuard-compatible transport
When the user runs "protonwire connect fastest --protocol stealth"
Then ProtonWire connects using Stealth transport
And status output shows "protocol: stealth"
```

```gherkin
Given Stealth is not implementable in the current architecture
When the user runs "protonwire protocols list"
Then Stealth is shown as unavailable
And the reason is machine-readable
And the feature is tracked as a future task
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

**FR-35:** Full-tunnel mode must route `0.0.0.0/0` and `::/0` through WireGuard unless split tunneling says otherwise.

**FR-36:** The daemon must preserve local LAN routes when LAN access is enabled.

**FR-37:** The daemon must block IPv6 leaks if IPv6 over VPN is unavailable.

**FR-38:** Route changes must be transactional where possible.

**FR-39:** The daemon must restore previous routes on disconnect.

**FR-40:** The daemon must detect route drift and repair it while connected.

**Acceptance Criteria**

```gherkin
Given the VPN is connected in full-tunnel mode
When the user runs "ip route get 1.1.1.1"
Then the selected route must use the ProtonWire routing table
And the packet path must go through the WireGuard interface
```

### 7.6 DNS Management {#76-dns-management}

**FR-41:** The app must support Proton DNS by default.

**FR-42:** The app must support custom DNS servers.

**FR-43:** The app must support DNS modes: `proton`, `custom`, `system`, and `none`.

**FR-44:** `system` DNS mode must be incompatible with strict DNS leak protection unless explicitly overridden.

**FR-45:** The daemon must support systemd-resolved if available.

**FR-46:** The daemon must support resolv.conf management if systemd-resolved is unavailable.

**FR-47:** DNS changes must be reverted on disconnect.

**FR-48:** DNS changes must be leak-safe when kill switch is enabled.

**FR-49:** Custom DNS must be routed according to policy: `through-vpn`, `bypass-vpn`, or `system-default`. Default must be `through-vpn`.

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
Then DNS queries to 9.9.9.9 must route through the WireGuard tunnel
```

### 7.7 NetShield {#77-netshield}

**FR-50:** The app must support NetShield as an optional feature.

**FR-51:** Supported NetShield modes must be: `off`, `malware`, `ads-trackers-malware`, and `adult-ads-trackers-malware` when backend/account support exists.

**FR-52:** The app must map NetShield modes to Proton-supported connection options.

**FR-53:** If a selected NetShield mode is unsupported by the account, platform, server, or backend, the app must fail gracefully.

**FR-54:** The active NetShield mode must be visible in status output.

**FR-55:** The app should expose session statistics if Proton’s API or local DNS path makes this available.

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

**FR-59:** Kill switch must be implemented with nftables by default.

**FR-60:** iptables fallback may be provided only where nftables is unavailable.

**FR-61:** Kill switch rules must permit loopback, DHCP if required before connection, Proton API endpoints needed to establish VPN, WireGuard endpoint traffic outside tunnel, LAN traffic only if LAN access is enabled, and explicit user bypass rules.

**FR-62:** Kill switch rules must block IPv4 and IPv6 leaks.

**FR-63:** Kill switch state must survive daemon restart in permanent mode.

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
When the WireGuard handshake fails after route setup
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

**FR-70:** Linux implementation must support UID rules, GID rules, cgroup v2 app rules, IP/CIDR rules, domain rules, port/protocol rules, and process attachment by PID where technically possible.

**FR-71:** App-path split tunneling must be implemented using a launcher, cgroup assignment model, and daemon-side process tracking.

**FR-72:** The daemon must attempt to attach already-running processes to split-tunnel policy when requested.

**FR-73:** If an already-running process cannot be safely attached, ProtonWire must report that process as partially applied or failed rather than claiming success.

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
Then qBittorrent traffic must route outside the WireGuard tunnel
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

**FR-85:** The app must support Proton-compatible port forwarding via NAT-PMP.

**FR-86:** Port forwarding must be optional.

**FR-87:** The app must only select servers that support port forwarding when port forwarding is requested.

**FR-88:** The app must detect and reject incompatible configuration combinations.

**FR-89:** Port forwarding must be incompatible with Moderate NAT.

**FR-90:** The daemon must request a NAT-PMP mapping after tunnel establishment.

**FR-91:** The daemon must renew the NAT-PMP lease before expiry.

**FR-92:** The active forwarded port must be shown in CLI status.

**FR-93:** The daemon must emit an event when the forwarded port changes.

**FR-94:** The CLI must support blocking until a forwarded port is available.

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

**FR-98:** Moderate NAT selection must be passed to Proton connection configuration if supported.

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

**FR-100:** The app must support VPN Accelerator as an optional feature.

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
Then the connection request must not include the accelerator option
And status output must show "vpn_accelerator: off"
```

### 7.13 LAN Access {#713-lan-access}

**FR-104:** The app must support allowing LAN traffic while VPN is connected.

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

Example commands:

```bash
protonwire config set lan-access on
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
```

### 7.14 Auto-Connect and Reconnect {#714-auto-connect-and-reconnect}

**FR-109:** The app must support auto-connect at daemon startup.

**FR-110:** The app must support reconnect on unexpected tunnel failure.

**FR-111:** The app must support reconnect on network change.

**FR-112:** The app must support a max retry policy.

**FR-113:** The app must support exponential backoff.

**FR-114:** The app must support preferred default connection profiles.

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
When the WireGuard endpoint becomes unreachable
Then the daemon attempts reconnection according to retry policy
And kill switch policy remains enforced during reconnection
```

### 7.15 Profiles {#715-profiles}

**FR-115:** The app must support named connection profiles.

**FR-116:** A profile must include:

- Selection mode
- Country
- City
- Server
- Secure Core settings
- Required features
- Excluded countries
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
protonwire connect profile torrent-nl
protonwire profile export torrent-nl > torrent-nl.yaml
protonwire profile import torrent-nl.yaml
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

**FR-121:** Logs must avoid leaking credentials, tokens, private keys, full IP addresses where avoidable, and account-identifying information.

**FR-122:** The daemon must expose debug bundles with redaction.

Example commands:

```bash
protonwire status
protonwire status --json
protonwire events
protonwire logs --since 10m
protonwire debug bundle
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
    "selection_reason": "lowest_latency_in_country"
  },
  "wireguard": {
    "interface": "protonwire0",
    "latest_handshake_seconds_ago": 12,
    "rx_bytes": 123456789,
    "tx_bytes": 987654321
  },
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
And include connection state, selected server, WireGuard state, and active feature state
```

---

## 8. Non-Functional Requirements {#8-non-functional-requirements}

### 8.1 Performance {#81-performance}

**NFR-1:** CLI cold start must complete within 150 ms for non-network commands on typical hardware.

**NFR-2:** Status command must complete within 100 ms when daemon is running.

**NFR-3:** Tunnel setup must complete within 5 seconds after receiving valid server config under normal network conditions.

**NFR-4:** Server selection using cached metadata must complete within 500 ms for 20,000 servers.

**NFR-5:** Latency probing must support bounded parallelism.

**NFR-6:** The daemon’s idle RSS should target under 50 MB.

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

### 8.3 Reliability {#83-reliability}

**NFR-17:** Daemon must recover from crash without leaving the system in an unknown state.

**NFR-18:** Permanent kill switch must survive daemon crash and restart.

**NFR-19:** The app must detect stale routes and firewall drift.

**NFR-20:** The app must tolerate Proton API unavailability using valid cached metadata.

**NFR-21:** Reconnect must not produce a traffic leak window when kill switch is enabled.

### 8.4 Compatibility {#84-compatibility}

**NFR-22:** Must support Linux kernel WireGuard.

**NFR-23:** Must support nftables.

**NFR-24:** Must support systemd services.

**NFR-25:** Must work without NetworkManager.

**NFR-26:** Must support NixOS through a flake module.

**NFR-27:** Must support systems with systemd-resolved and without systemd-resolved.

### 8.5 Maintainability {#85-maintainability}

**NFR-28:** Rust code must use explicit error types.

**NFR-29:** Public structs must derive serialization where appropriate.

**NFR-30:** All config schemas must have versioning.

**NFR-31:** Integration tests must run in isolated Linux network namespaces.

**NFR-32:** Feature logic must be unit-testable without root privileges.

---

## 9. CLI Specification {#9-cli-specification}

### 9.1 Top-Level Commands {#91-top-level-commands}

```bash
protonwire login
protonwire logout
protonwire account
protonwire credentials
protonwire protocols
protonwire connect <target>
protonwire disconnect
protonwire reconnect
protonwire status
protonwire servers
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
protonwire connect city <CITY_NAME>
protonwire connect server <SERVER_NAME>
protonwire connect secure-core
protonwire connect profile <PROFILE_NAME>
```

### 9.3 Selection Modifiers {#93-selection-modifiers}

```bash
--by load
--by latency
--by speed
--exclude-country <COUNTRY_CODE>
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
--protocol wireguard|stealth
--json
--dry-run
```

### 9.4 Protocol Commands {#94-protocol-commands}

```bash
protonwire protocols list
protonwire connect fastest --protocol wireguard
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
protonwire credentials migrate --to loadcredential
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

---

## 10. Configuration Schema {#10-configuration-schema}

Default config path:

```text
/etc/protonwire/config.yaml
```

User override path:

```text
~/.config/protonwire/config.yaml
```

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
schema_version: 1

daemon:
  socket_path: /run/protonwire/protonwire.sock
  interface_name: protonwire0
  log_level: info

account:
  credential_backend: auto
  credential_backend_priority:
    - keyring
    - tpm2
    - loadcredential
    - encrypted-local
  allow_password_storage: false
  prefer_token_storage: true
  encrypted_local_fallback: false
  load_credential_names:
    username: protonwire-username
    password: protonwire-password
    refresh_token: protonwire-refresh-token

server_selection:
  metadata_ttl_minutes: 30
  latency_probe:
    enabled: true
    max_candidates: 20
    timeout_ms: 750
    parallelism: 8
  weights:
    load: 0.30
    latency: 0.30
    speed: 0.25
    stability: 0.10
    feature_match: 0.05
  secure_core:
    enabled_by_default: false
    preferred_entry_countries: []
    excluded_entry_countries: []
    excluded_exit_countries: []

connection:
  default_profile: default
  wireguard:
    mtu: auto
    persistent_keepalive_seconds: 25
  ipv6:
    mode: auto

features:
  protocol: wireguard
  stealth: auto
  secure_core: false
  kill_switch: on
  split_tunnel: off
  netshield: ads-trackers-malware
  port_forwarding: false
  nat: strict
  vpn_accelerator: true
  lan_access: true

dns:
  mode: proton
  custom_servers: []
  policy: through-vpn

lan:
  allowed_cidrs:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - fd00::/8
    - fe80::/10

split_tunnel:
  mode: off
  attach_existing_processes: true
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
  profile: default
  retry:
    max_attempts: 0
    initial_delay_seconds: 2
    max_delay_seconds: 300
    jitter: true

profiles:
  default:
    selection:
      mode: fastest
      by: balanced
      exclude_countries: []
      require: []
```

---

## 11. Data Models {#11-data-models}

### 11.1 Server Model {#111-server-model}

```rust
pub struct Server {
    pub id: String,
    pub name: String,
    pub country: String,
    pub city: Option<String>,
    pub load_percent: u8,
    pub score: Option<f64>,
    pub tier: u8,
    pub features: ServerFeatures,
    pub wireguard: WireGuardEndpoint,
    pub secure_core: Option<SecureCoreRoute>,
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

### 11.4 Feature Request {#114-feature-request}

```rust
pub struct FeatureRequest {
    pub protocol: ProtocolMode,
    pub stealth: StealthMode,
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
EntitlementError
ApiError
ServerSelectionError
SecureCoreSelectionError
ProtocolUnavailableError
WireGuardError
RouteError
FirewallError
DnsError
SplitTunnelError
PortForwardingError
ConfigError
PermissionError
DaemonUnavailable
```

### 12.2 Recovery Rules {#122-recovery-rules}

**ER-1:** If WireGuard setup fails before firewall policy is applied, restore previous routes and DNS.

**ER-2:** If WireGuard setup fails after kill switch is applied, keep kill switch enforced and report failure.

**ER-3:** If DNS setup fails and DNS leak protection is active, abort connection.

**ER-4:** If port forwarding fails but is optional, connect and report degraded feature state.

**ER-5:** If port forwarding is explicitly required, abort connection.

**ER-6:** If selected server fails to connect, retry next eligible server unless exact server was requested.

**ER-7:** If exact server was requested and it fails, do not silently choose another server.

**ER-8:** If split tunneling setup fails, abort when kill switch is enabled unless user explicitly allows degraded operation.

**ER-9:** If daemon crashes, permanent kill switch rules must remain in place.

**ER-10:** If Secure Core is requested and unavailable, do not fall back to non-Secure-Core.

**ER-11:** If Stealth is requested and unavailable, do not fall back to WireGuard unless the user explicitly permits protocol fallback.

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

**SEC-3:** Tokens must be stored only in the configured secure backend.

**SEC-4:** Password storage is allowed only through an approved credential backend. Plaintext storage is forbidden.

**SEC-5:** Logs must redact access tokens, refresh tokens, private keys, account identifiers, full IP addresses unless debug mode explicitly permits them, and credentials.

**SEC-6:** The daemon socket must require root, configured group membership, or equivalent peer credential authorization.

**SEC-7:** The app must validate file permissions for config and state files.

**SEC-8:** The kill switch must default to fail-closed behaviour when enabled.

**SEC-9:** IPv6 leak prevention must be mandatory unless IPv6 tunnel support is active.

**SEC-10:** DNS leak protection must be mandatory unless explicitly disabled.

**SEC-11:** Debug bundles must include a redaction pass.

**SEC-12:** Split tunneling must display a warning when include mode leaves apps outside the VPN.

**SEC-13:** Port forwarding must display a warning that inbound traffic may reach local services listening on the forwarded port.

---

## 14. Packaging and Deployment {#14-packaging-and-deployment}

### 14.1 Packages {#141-packages}

Required packages:

```text
protonwire
protonwire-daemon
protonwire-systemd
```

Optional packages:

```text
protonwire-completions
protonwire-tui
protonwire-nix
```

### 14.2 Systemd Unit {#142-systemd-unit}

```ini
[Unit]
Description=ProtonWire VPN Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/protonwire-daemon
Restart=on-failure
RestartSec=2
RuntimeDirectory=protonwire
StateDirectory=protonwire
CacheDirectory=protonwire
ConfigurationDirectory=protonwire
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/run/protonwire /var/lib/protonwire /var/cache/protonwire /etc/protonwire

[Install]
WantedBy=multi-user.target
```

### 14.3 NixOS Flake Module {#143-nixos-flake-module}

ProtonWire must provide NixOS support as a flake module.

The flake must expose:

```nix
{
  packages.${system}.protonwire = ...;
  apps.${system}.protonwire = ...;
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

Declarative login example using sops-nix or agenix-managed files:

```nix
{
  services.protonwire = {
    enable = true;

    login = {
      mode = "declarative";
      credentialBackend = "loadcredential";
      usernameCredential = "protonwire-username";
      passwordCredential = "protonwire-password";
    };

    systemdCredentials = {
      "protonwire-username" = "/run/secrets/protonwire/username";
      "protonwire-password" = "/run/secrets/protonwire/password";
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

**FR-143C:** Declarative login must support systemd `LoadCredential`.

**FR-143D:** Declarative login must be compatible with secret managers such as sops-nix and agenix.

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
And LoadCredential secrets are configured
When the daemon starts
Then it reads credentials from systemd credentials
And auto-connects using the configured default profile
```

---

## 15. Metrics and Success Criteria {#15-metrics-and-success-criteria}

### 15.1 Product Success Metrics {#151-product-success-metrics}

**M-1:** Connects successfully to a valid Proton WireGuard server.

**M-2:** Maintains tunnel across 24-hour soak test.

**M-3:** Reconnects after simulated network loss.

**M-4:** No DNS leak in automated leak tests.

**M-5:** No IPv6 leak when IPv6 tunnel is unavailable.

**M-6:** Kill switch blocks traffic during tunnel failure.

**M-7:** Smart selection picks a lower-latency server than random selection in at least 80% of test runs.

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

---

## 16. Dependencies and Constraints {#16-dependencies-and-constraints}

### 16.1 Runtime Dependencies {#161-runtime-dependencies}

Allowed:

```text
Linux kernel with WireGuard
nftables
systemd, recommended
systemd LoadCredential, optional
systemd-resolved, optional
cgroup v2, required for app/process split tunneling
TPM2 stack, optional
Secret Service / KWallet / GNOME Keyring, optional
```

Forbidden:

```text
NetworkManager
wg-quick as core control path
Desktop keyring as mandatory dependency
GUI session as mandatory dependency
Plaintext credential storage
```

### 16.2 Rust Crates, Indicative {#162-rust-crates-indicative}

```toml
clap = "4"
tokio = "1"
serde = "1"
serde_json = "1"
serde_yaml = "0.9"
thiserror = "1"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = "0.3"
reqwest = "0.12"
rustls = "0.23"
nix = "0.29"
netlink-packet-route = "*"
rtnetlink = "*"
nftables = "*"
secrecy = "0.8"
zeroize = "1"
keyring = "3"
```

Final crate choices must be validated during technical design.

---

## 17. Test Plan {#17-test-plan}

### 17.1 Unit Tests {#171-unit-tests}

**T-1:** Validate server scoring formula.

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

**T-12:** Validate credential backend priority.

**T-13:** Validate Stealth availability reporting.

**T-14:** Validate domain split tunnel rule matching.

### 17.2 Integration Tests {#172-integration-tests}

Run in Linux network namespaces.

**IT-1:** Create WireGuard interface.

**IT-2:** Apply full-tunnel route.

**IT-3:** Apply IPv6 block when IPv6 unsupported.

**IT-4:** Apply nftables kill switch.

**IT-5:** Verify DNS route through VPN table.

**IT-6:** Verify LAN bypass.

**IT-7:** Verify split tunnel UID policy.

**IT-8:** Verify split tunnel cgroup policy.

**IT-9:** Simulate endpoint failure and reconnect.

**IT-10:** Simulate daemon crash with permanent kill switch.

**IT-11:** Verify dynamic IP set updates for domain rules.

**IT-12:** Verify already-running process attachment reports success/partial/failure.

### 17.3 End-to-End Tests {#173-end-to-end-tests}

**E2E-1:** Login.

**E2E-2:** Refresh server cache.

**E2E-3:** Connect fastest.

**E2E-4:** Connect by country.

**E2E-5:** Connect exact server.

**E2E-6:** Connect Secure Core by exit country.

**E2E-7:** Connect with NetShield.

**E2E-8:** Connect with port forwarding.

**E2E-9:** Reject port forwarding plus Moderate NAT.

**E2E-10:** Reconnect on network loss.

**E2E-11:** Disconnect and restore networking.

---

## 18. Implementation Milestones {#18-implementation-milestones}

### Milestone 1: Foundation {#milestone-1-foundation}

- Workspace structure
- CLI skeleton
- Daemon skeleton
- Unix socket IPC
- Config loader
- Logging
- Error types
- CI skeleton

### Milestone 2: Proton API and Server Cache {#milestone-2-proton-api-and-server-cache}

- Login/session flow
- Credential backend abstraction
- Server metadata retrieval
- Metadata cache
- Entitlement model
- Server list command

### Milestone 3: Server Selection {#milestone-3-server-selection}

- Selection filters
- Load sorting
- Latency probing
- Speed estimate
- Exclusion rules
- Secure Core route selection
- Dry-run output

### Milestone 4: WireGuard Core {#milestone-4-wireguard-core}

- Interface creation
- Peer configuration
- Handshake monitoring
- Disconnect cleanup
- Route management
- Protocol capability reporting

### Milestone 5: DNS and Kill Switch {#milestone-5-dns-and-kill-switch}

- DNS modes
- nftables kill switch
- Advanced kill switch
- IPv6 leak prevention
- LAN access

### Milestone 6: Optional Features {#milestone-6-optional-features}

- NetShield
- VPN Accelerator
- Moderate NAT
- Port forwarding
- NAT-PMP lease renewal
- Stealth if feasible over WireGuard-compatible transport

### Milestone 7: Split Tunneling {#milestone-7-split-tunneling}

- UID/GID split rules
- cgroup app launcher
- IP/CIDR split rules
- Domain split rules and dynamic IP sets
- Include/exclude modes
- Best-effort existing-process attach
- Kill switch compatibility

### Milestone 8: Packaging and Hardening {#milestone-8-packaging-and-hardening}

- systemd unit
- Nix package
- NixOS flake module
- Debian package
- Fedora package
- Arch package
- Security hardening
- CI

---

## 19. Open Questions {#19-open-questions}

**OQ-1:** Which Proton API endpoints are stable and acceptable for third-party client use?

**OQ-2:** Can all GUI feature flags be expressed in WireGuard configuration, connection certificate metadata, or Proton API session options?

**OQ-3:** How should ProtonWire handle Proton’s anti-abuse or device-limit enforcement?

**OQ-4:** Can Stealth protocol be implemented over a WireGuard-compatible transport without violating the pure WireGuard architecture?

**OQ-5:** What is the safest implementation strategy for domain-based split tunneling with CDN-backed and DoH-using applications?

**OQ-6:** How reliable is cgroup migration for already-running processes across common Linux distributions?

**OQ-7:** What is the best TPM2 sealing policy for headless servers where PCR values may change after kernel or initrd upgrades?

**OQ-8:** Should declarative NixOS login prefer LoadCredential only, or also support sops-nix/agenix paths directly?

---

## 20. Clarifying Notes {#20-clarifying-notes}

**CN-1:** “Pure WireGuard implementation” means ProtonWire manages WireGuard interfaces and routing directly. It does not mean reimplementing WireGuard cryptography in userspace.

**CN-2:** “No NetworkManager” means neither direct nor indirect runtime dependence on NetworkManager.

**CN-3:** “VPN Accelerator” is treated as a Proton connection option, not as a locally implemented acceleration algorithm.

**CN-4:** “NetShield” is treated as a Proton DNS-backed mode, not as a local adblock DNS resolver.

**CN-5:** “Split tunneling by app” on Linux must use cgroup v2, process tracking, and policy routing. Path-name matching alone is not sufficient.

**CN-6:** “Best server by speed” is an estimate unless Proton exposes exact real-time throughput measurements. The product should combine server metadata, measured latency, and historical local performance.

**CN-7:** Port forwarding requires compatible server selection and NAT-PMP lease management.

**CN-8:** Moderate NAT and port forwarding are mutually exclusive.

**CN-9:** Secure Core is required in v1.

**CN-10:** Domain-based split tunneling is required in v1, but must explicitly document limitations involving CDNs, DoH, DoT, hardcoded IPs, and shared hosting.

**CN-11:** Already-running process attachment is best-effort. ProtonWire must report exact attachment status rather than pretending all processes were successfully moved.

**CN-12:** Password storage is allowed only through an approved credential backend. Plaintext storage is forbidden.

**CN-13:** NixOS support means a flake module, not merely a package.

**CN-14:** Stealth protocol must be implemented in v1 only if it can be implemented over WireGuard-compatible transport. Otherwise it remains a tracked future task.

---

## 21. Traceability Matrix {#21-traceability-matrix}

| User Need | Requirement IDs |
|---|---|
| Compiled app | G-1, NFR-28 |
| Rust rewrite | G-1, Section 16 |
| No NetworkManager | G-2, NG-2, NFR-25 |
| Pure WireGuard | G-2, FR-24 to FR-32 |
| GUI feature parity | G-4, FR-50 to FR-108 |
| Split tunneling | FR-66 to FR-84 |
| DNS | FR-41 to FR-49 |
| Kill switch | FR-56 to FR-65 |
| Port forwarding | FR-85 to FR-94 |
| NetShield | FR-50 to FR-55 |
| VPN Accelerator | FR-100 to FR-103 |
| Moderate NAT | FR-95 to FR-99 |
| Smart server selection | FR-14 to FR-23 |
| Country/server targeting | FR-15, CLI Section 9 |
| Exclude country list | FR-21 |
| Load/latency/speed selection | FR-17 to FR-19 |
| Password storage with preferred backend order | G-11, FR-7A to FR-7J |
| Keyring first | FR-7B |
| TPM2 second | FR-7B, FR-7G |
| LoadCredential third | FR-7B, FR-7F |
| Secure Core in v1 | G-12, FR-23A to FR-23F |
| Stealth not permanently excluded | G-4, FR-32A to FR-32E |
| Domain split tunneling now | G-13, FR-77 to FR-82 |
| Attach already-running processes | G-14, FR-72, FR-73, FR-75 |
| Declarative and interactive NixOS login | FR-143A to FR-143D |
| NixOS as flake module | G-15, FR-143A to FR-143H |
| Headless support | G-5, NFR-24, Packaging Section 14 |
| Safe failure behaviour | FR-56 to FR-65, ER-1 to ER-11 |

---

## 22. Definition of Done {#22-definition-of-done}

The project is considered v1 complete when:

1. `protonwire login` authenticates successfully.
2. Credential storage follows priority order: keyring, TPM2, LoadCredential, explicit encrypted fallback.
3. `protonwire credentials status` shows the active credential backend.
4. `protonwire servers refresh` retrieves and caches server metadata.
5. `protonwire connect fastest` connects without NetworkManager.
6. `protonwire connect country GB --by latency` selects and connects to an eligible UK server.
7. `protonwire connect server <SERVER>` connects only to the requested server.
8. `protonwire connect secure-core --exit-country GB` connects through a Secure Core route.
9. Secure Core status shows entry and exit servers.
10. Stealth protocol is either implemented over WireGuard-compatible transport or explicitly marked unavailable with a machine-readable reason.
11. Kill switch blocks traffic during tunnel failure.
12. Advanced kill switch survives daemon restart.
13. DNS does not leak in automated tests.
14. IPv6 does not leak when IPv6 VPN support is unavailable.
15. NetShield mode is configurable.
16. VPN Accelerator is configurable.
17. Moderate NAT is configurable.
18. Port forwarding retrieves and renews an active NAT-PMP port.
19. Port forwarding plus Moderate NAT is rejected.
20. Split tunneling supports include and exclude modes.
21. Split tunneling supports cgroup-launched apps, UID/GID rules, IP/CIDR rules, domain rules, port/protocol rules, and best-effort already-running process attachment.
22. Domain-based split tunneling updates dynamic IP sets according to DNS TTL.
23. `protonwire status --json` returns complete machine-readable status.
24. systemd service works.
25. Nix package builds reproducibly.
26. NixOS flake module is available.
27. NixOS flake module supports interactive login.
28. NixOS flake module supports declarative login with LoadCredential.
29. Integration tests pass in Linux network namespaces.
30. Documentation explains all feature trade-offs and known limitations.
