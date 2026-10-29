# M6 Unit Plan — Official Service Parity

Branch: `m6-plan` (the stack base; slices stack on it bottom-up).
Plan date: 2026-10-29. Inputs: PRD §7.7/§7.10–7.16/§9.1/§17–18, the four
2026-10-08 owner decisions (docs/review-log.md), the 2026-10-29 M6 gate
condition (PeerInfo::server_name), live seams at master 3af64e5.

Standing process per slice: TDD (failing test first), typed reviewer
gates BEFORE the PR opens, stacked PRs (each slice one reviewer
sitting), CI 9/9 is the compile authority, parity manifest flips to
`implemented` only with fixture-backed IT/T evidence (`verified`
requires staging accounts — see Risk 1).

## Stack order: 1→2→3→4→5→6→7

### Slice 1 — m6/daemon-composition (the entry point)
The daemon actually connects: selection → TunnelParams → engine.connect
composed with session::connect/disconnect. Retires THREE recorded
debts: the IT-13 composition deferral, the bypass-mark collision
contract (owner decision 2026-10-08: random mark at startup,
collision-checked against live ip-rule fwmarks AND nftables
mark-matching rules at survey time, re-chosen on collision, inside
route-commit BEFORE the kill switch arms), and the server_name gate
condition (PeerParams gains catalog entry domains; translate refuses
to drop domains silently — DNS-SAN-only certs fail closed otherwise).
Files: apps/daemon/src/{lib,connect,main,selection}.rs,
crates/core/src/state.rs (delete the NotImplemented stub at :120),
crates/net/src/session.rs (mark survey via NetlinkExecutor),
crates/protocol/src/{params,translate}.rs.
Tests: IT-13 (marks-before-route-commit, daemon-composed, netns),
IT-31 (pre-seeded fwmark/nft mark forces re-choose), T-38 (domains ⇒
server_name non-None), IT-32 (daemon connect/disconnect phase order +
state events + clean revert).
Parity flips: integration.native, protection.kill-switch-standard.
Gates: rust-reviewer, sec-auditor, qa-engineer.

### Slice 2 — m6/local-agent-features
NetShield / Moderate NAT / VPN Accelerator end-to-end: config +
connect modifiers → EngineAgentSettings; T-20 reconciliation
surfaced (requested vs applied vs refused + FR-55 counters);
PF×Moderate-NAT and entitlement conflicts rejected (T-5/T-18).
Files: daemon connect.rs (settings epoch), store sections validation,
frontend-api state features block, cli config/connect flags.
Tests: T-18 full, T-20 extended, T-39, IT-33 (mid-session feature
change rides the reconcile epoch).
Parity flips: dns.netshield-levels, dns.netshield-statistics,
options.nat, options.vpn-accelerator.
Gates: rust-reviewer, qa-engineer.

### Slice 3 — m6/port-forwarding
NAT-PMP lease lifecycle post-tunnel: request, renew-before-expiry,
port-change event, atomic user-owned publication (FR-94A —
pre-opened safe dirfd, symlink refusal), port show/watch,
PF-capable-only server filter (FR-87).
Files: crates/port-forwarding/src/{lib,nat_pmp,lease}.rs
(clock-injected FSM + traits for test doubles), daemon services.rs PF
worker, frontend-api event+status, cli port family, selection filter.
Tests: T-5 (specced), T-40 (lease FSM on injected clock), IT-34
(netns NAT-PMP responder: mapping/renewal/release + FR-94A
adversarial cases).
Parity flips: options.port-forwarding; completes servers.p2p's
PF-aware half.
Gates: rust-reviewer, sec-auditor (root→user-file), qa-engineer.

### Slice 4 — m6/profiles-recents
FR-115..116B: per-UID profile store, group refs + derived_from_group,
copy-to-profile, bounded recents, pins, defaults (FR-114A grammar:
fastest/random/last/group-id/profile), import/export with
confirmation.
Files: crates/store/src/profiles.rs (new) + sections.rs, daemon
profiles.rs handler (new), frontend-api request family, cli profile
family.
Tests: T-17 full, T-41 (recents LRU + default resolution matrix),
IT-35 (per-UID isolation + import confirmation).
Parity flips: profiles.crud-and-types, profiles.overrides,
profiles.recents-pins-default, profiles.import-export.
Gates: rust-reviewer, sec-auditor (per-UID authority), qa-engineer.

### Slice 5 — m6/auto-connect-reconnect
FR-109..114B + FR-23G: startup auto-connect via default; retry with
exponential backoff+jitter; adapter uplink changes →
Up/Down/NetworkSwitch + reconcile-before-recovered; change-server
with the authoritative cooldown.
Files: apps/daemon/src/autoconnect.rs (new), net adapters.rs
(NetworkSwitch), connect.rs reconnect, frontend-api ChangeServer,
cli change-server/reconnect.
Tests: T-42 (backoff policy, pure), IT-36 (failure → retry, kill
switch stays armed), IT-37 (adapter restart → reconciliation before
Connected; extends IT-17).
Parity flips: protection.auto-connect-reconnect; servers.free-change
only if the OQ-3 endpoint is verified (else stays required + note).
Gates: rust-reviewer, qa-engineer.
OPEN OWNER QUESTION: free change-server — pin the authorized Muon
endpoint, or record blocked-upstream like connection feedback (OQ-3)?

### Slice 6 — m6/connect-and-go-special-flows
FR-116C Connect-and-Go (client-side execution after server-confirmed
Connected, as the requesting user, confirmation on import) +
P2P/Tor/Gateway/Secure-Core composed flows (both SC hops in status).
Files: frontend-api Connected-anchored prompt, cli execution path,
daemon profile field + notification, selection path proofs.
Tests: IT-38 (action only post-Connected, non-root, imported profiles
need confirmation), IT-39 (SC both hops; Tor/Gateway via the composed
daemon in netns with fixture peers).
Parity flips: profiles.connect-and-go, servers.secure-core,
servers.p2p, servers.tor, servers.gateway.
Gates: sec-auditor (execute-as-user), rust-reviewer, qa-engineer.

### Slice 7 — m6/diagnostics-observability
FR-117..126, FR-128: full FR-123/124 status, network-conflict
detection (implements IT-20), redacted debug bundles, bounded
root-owned capture (implements IT-18, T-21), opt-in crash reporting
(T-43, default-off + redaction); connection feedback stays
blocked-upstream.
Files: daemon diagnostics.rs (new), adapters ConflictEvent,
core/redact extensions, frontend-api status/debug, cli debug family.
Tests: T-21, T-22 (negative), T-43, IT-18, IT-20.
Parity flips: diagnostics.connection-details,
diagnostics.network-conflict-detection, diagnostics.packet-capture,
diagnostics.debug-and-crash.
Gates: sec-auditor (capture FD, redaction), rust-reviewer,
qa-engineer, doc-writer.

## Risks

1. **Staging accounts (exit risk):** E2E-3..9/14..17 need entitled
   accounts (PF/SC/Tor/Gateway are paid; E2E-18 names staging).
   Every slice flips only to `implemented`; the manifest carries the
   verification debt; T-19 rejects `verified` without evidence.
2. **server_name (slice 1):** if the catalog domains don't reach
   TunnelParams in protun v3.0.5's shape, DNS-SAN-only certs fail
   closed at connect. T-38 pins domains⇒non-None end-to-end.
3. **Privilege boundaries (slices 3, 6):** FR-94A root→user-file and
   FR-116C execute-as-user are sec-critical; adversarial ITs +
   sec-auditor gates on both PRs.
