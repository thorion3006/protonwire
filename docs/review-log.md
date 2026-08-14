# Review Log

Chronological triage of SDLC agent reviews. Each entry records what was
fixed immediately versus tracked for a later milestone, so nothing reviewed
silently disappears.

## 2026-08-14 — Milestone 1 (IPC trust surface, sec-auditor)

Reviewed at `e51ba21`: `crates/ipc`, `crates/client`, `crates/core/redact.rs`,
`crates/core/state.rs` against PRD 6.2–6.4/FR-127.

### Fixed for M1

| # | Severity | Finding | Fix |
| --- | --- | --- | --- |
| 1 | HIGH | Client verified socket *metadata* but never the connected peer; stat-then-connect TOCTOU allowed daemon impersonation on writable socket dirs | `IpcClient::connect_with_timeout` now checks `SO_PEERCRED` of the connected stream and requires a root daemon peer; stat checks kept as defense in depth |
| 2 | MEDIUM | `PROTONWIRE_DEV_UNSAFE_SOCKET=1` disabled client trust checks in release builds | Bypass honored only under `cfg!(debug_assertions)` in SDK, CLI, and TUI; release builds always verify |
| 3 | MEDIUM | Slow-reader sessions pinned writer threads forever (no write timeout), pre-hello idlers held threads indefinitely, unbounded session count | 10 s write timeout, 5 s hello deadline, 64-session cap with backlog drain, unsubscribe drop-guard |
| 4 | MEDIUM | `Connect` recorded `active_owner_uid` then returned `NotImplemented` → unprivileged UID squatting of the host-global owner slot | No state committed on failing paths; owner recording deferred to the M4 engine transition (cross-UID refusal keys off the real owner) |
| 5 | MEDIUM | No committed root `Cargo.lock` (FR-127A; supply-chain authority for the lockless ProTUN tag) | **Correction 2026-08-14:** the first attempt did NOT commit it — a developer-global gitignore silently excluded the file (commit `a3d4acd`'s message was wrong). Found independently by the compliance and doc reviews. Fixed properly: repo `.gitignore` gains `!Cargo.lock`, the file is force-added, and `cargo xtask dep-graph` now fails whenever the lockfile is untracked (red-green verified). CI enforces `--locked` |
| 7 | LOW | Client-controlled hello `name`/`version` logged unsanitized → log forging via newlines/ANSI | `ClientInfo::sanitized()` (control chars stripped, 64/32-char caps) applied server-side before storage/logging |
| 13a | LOW | `HelloAck` replied with server version above the client's requested one | Reply with `min(requested, PROTOCOL_VERSION)` |

### Tracked for later milestones

- **6** (bus eviction starves lagging clients with no signal): terminate
  evicted sessions deterministically — M2 when event volume becomes real.
- **8** (`verify_socket_trusted` symlink-following metadata, parent-only
  walk, no socket-mode check): M2 hardening sweep; the post-connect
  SO_PEERCRED check is the authoritative gate now.
- **9** (`GetState` exposes `active_owner_uid` to non-owners; PRD 6.3 wants
  redaction): M2 with per-UID namespacing; decide redaction shape then.
- **10** (redaction registry: FIFO eviction could be poisoned by 256 junk
  registrations once peer-supplied secrets exist; line-based scrubbing and
  `from_utf8_lossy` edge evasions): unreachable in M1 (no secret IPC field);
  **blocking requirement for M2**: never register peer-derived values in
  the global registry; add the canary test then (T-32).
- **11** (bind does not validate the socket directory; stale-probe TOCTOU
  in writable dev dirs): M2 with production unit hardening.
- **12** (frame desync after a mid-frame read timeout): session-owned
  decoder buffer — fine to defer while senders are local and prompt.
- **13b** (`next_event` surfaces read timeout as an error): revisit with
  the TUI event loop (M8).

## 2026-08-14 — Milestone 1 (test coverage, qa-engineer)

Reviewed at `e51ba21` + in-flight tree.

### Fixed for M1

- `SystemConfig::default()` derived `schema_version: 0` → statically red
  `defaults_validate`; the daemon's missing-file path returned an invalid
  document. Manual `Default` with `schema_version: 2`; `load()` validates
  defaults too.
- `InvalidParams` mapped to exit 1, contradicting PRD 9.8 (2) and the CLI
  grammar test. Now 2, with an exhaustive code→exit table test.
- `SystemConfig::load` untested → missing-file/invalid/valid tests.
- Negative config tests only asserted `is_err()` → specific-violation and
  multi-violation tests (dns/custom, jitter ceiling, credential source,
  transport, combined report).
- `authority_report()` omitted `server_selection.secure_core`.
- (With the sec-auditor batch) handshake negative paths, request timeout,
  stale/live socket recovery tests — see the IPC test additions.

### Tracked for later milestones

- Per-UID overlay *loader* + `$XDG_CONFIG_HOME` path: M2 with the overlay
  IPC (T-37's daemon-side revalidation lives there).
- Field-level authority granularity (report is section-level): T-37, M2.
- `xtask it --netns` runner envelope + shared test daemon fixture: M1.1/M2
  per the QA harness recommendation (invocation contract and skip
  semantics first, netns fixtures with M5).
- Daemon `exit 15` on config failure and the TUI panic-restore path remain
  verified by component tests + manual smoke; binary-level harness lands
  with the systemd unit work (M8).
- Dead-weight items removed: duplicate event-envelope test in the IPC
  client, no-op anchor-bomb assertion in the YAML guard.

## 2026-08-14 — Milestone 1 (structure review, refactorer)

Full sequenced plan delivered; triage below. Executed TDD-first (failing
test → implementation) once the remaining reviewer reports landed, so
file:line citations in those reports stayed valid during review.

### Accepted — execute in this order (behavior-preserving, each step
verified by the full suite + `cargo xtask all`)

1. **Security-check policy consolidation** (~1 h): the
   `cfg!(debug_assertions) && env == "1"` trust-bypass policy is written
   three times (SDK `connect_default`, `apps/cli`, `apps/tui`) and is
   security-relevant — drift risk. One pure `checks_for(flag, debug)` seam
   in `protonwire-client` with four-case unit tests (the pure seam exists
   because edition 2024 makes `set_var` `unsafe` and the workspace denies
   `unsafe_code`); apps stop naming `IpcSecurityChecks` entirely.
2. **Handshake characterization tests** (~1 h): pin the four
   `serve_messages` refusals (duplicate-hello, request-before-hello,
   unsupported-version, negotiated `min(client, server)`) before M2's
   protocol-negotiation work edits that function; QA asked for the same
   tests. Hello-timeout stays unpinned (5 s wall-clock test not worth it).
3. **Shared in-process test fixture** (~1-1.5 h): feature-gated
   `protonwire-ipc::test_util` (`test-util` feature, never in releases, no
   new dependencies — PRD 6.1 fixes the member list, so no fixture crate);
   replaces the copy-pasted `spawn_server` fixtures in `ipc` and `client`
   test modules before M2's conformance harness copies them a third time.
4. **`frontend-api/src/proto.rs` split** (hello/rpc/target, root re-exports
   byte-identical; `schema-gen --check` proves the wire schemas did not
   move) and **`store/src/config.rs` split** (config/{mod,schema,overlay}):
   mechanical, lower priority; step 5 skippable if the M2 branch cuts first.
5. Micro: fold the triple-repeated "unexpected result" `RpcError` in the
   SDK into one helper (rides with step 1).

### Explicitly not refactoring (with reasons)

- No `Session` type in the IPC server — the function decomposition is
  right; the gap was tests, not structure.
- No new fixture crate, no splits of frame/bus/authz/peer (48-124 lines,
  stable through M8), no `DaemonCore`/`DaemonHandler` reshaping (M4 gets
  better information first), no `VpnState: Display` unification, no clap
  in the TUI's two-flag parser.

### Behavior items surfaced (not refactors)

- `apps/cli/src/commands.rs` `daemon start` calls `std::process::exit(1)`
  inside dispatch, contradicting the module's own no-exit contract —
  fixed in this round as a defect (return the error; exit mapping already
  lives in `main`).
- TUI opens a fresh IPC session every 750 ms refresh instead of holding
  one and consuming the event stream — queued as an M2 design item with
  the resync flow, where the event loop gets designed properly.

## 2026-08-14 — Milestone 1 (compliance mapping + docs audit)

The compliance review (OWASP ASVS V4/V5/V14 at L2 intent + supply-chain
provenance) and the docs accuracy audit ran against `fd82514`. Both
independently found the untracked `Cargo.lock` (see the corrected finding
5 above) — fixed red-green with a new xtask rule. Verdict "M1 is not done"
is discharged by that fix plus the items below.

### Fixed in this round

- **Cargo.lock under version control** (compliance Gap 1, docs finding 1;
  HIGH): repo `.gitignore` negation overrides developer-global excludes;
  `xtask dep-graph` now requires the lockfile to be *tracked*, not merely
  present. CI `--locked`/audit jobs are reproducible from fresh clones.
- **Stale `rust-toolchain.toml` comment** (compliance Gap 7, docs finding
  2): claimed a 1.85 floor contradicted by everything else; rewritten to
  the verified 1.97 floor.
- **`cargo xtask` alias** (docs finding 3): added to `.cargo/config.toml`;
  the three crate-doc references now name a working command.
- **`cargo audit --file .cargo/audit.toml`** (compliance Gap 6): policy
  application explicit in CI.
- Docs accuracy sweep (docs findings 4-10): README status/toolchain/
  examples/stop-path, spike tokio/reqwest clarification, CLI header
  precision on `daemon start`, GUI CSP wording, packaging README records
  the SBOM/license/reproducibility deferral, and CONTRIBUTING.md added
  (gates, TDD, reviewer loop, lockfile rule, GUI prerequisites).

### Tracked (M1.1 unless noted)

- **Release guard** (compliance Gap 2): the license blocker is documented
  everywhere but nothing *fails* at tag time; add a tag-triggered failing
  workflow or an xtask `release-guard` keyed to a clearance marker before
  any tag exists.
- **License inventory** (Gap 3): 17 packages in the live tree carry no
  license field (not just the two named in COPYING.md — the full Proton
  registry set incl. `protun` itself); add a cargo-deny/xtask enumeration
  so engine upgrades cannot silently grow the blocked set. No GPL
  incompatibility exists today (MPL-2.0 crates are GPLv3-compatible).
- **SBOM/license/reproducibility skeletons** (Gap 4 = PRD M1 bullet,
  re-baselined to M1.1 and recorded in packaging/README.md).
- **State/config file permissions 0600** (Gap 5 → M2 with the credential
  store; head-start when `StateStore` grows secrets).
- **`nix` `signal` feature unused** (docs finding 11): kept deliberately
  for the M2 SIGTERM/stop-path work; tracked there.
- Open human questions from the review: GitHub branch/tag protection and
  required-check configuration (not inspectable from the repo); whether
  the rsa/Marvin acceptance gets a formal owner risk-acceptance record.

## 2026-08-14 — Milestone 1 (Rust review)

Full manual review at `fd82514` against the crate/app surface; the
reviewer's summary of solid ground is recorded in the commit discussion.

### Fixed (TDD where behavior is testable: red observed, then green)

- **#1 CRITICAL — session teardown deadlock**: `handle_session` joined the
  writer before unsubscribing, but the event forwarder holds a writer-sender
  clone and only ends when the bus sender closes — so every ended session
  leaked its bus slot and two threads, and `MAX_SESSIONS` (64) wedged the
  daemon permanently after 64 short-lived connections. Fix: unsubscribe
  before joining, with the teardown order documented in code. Regression
  test `ended_sessions_release_their_bus_slot` (was red for the full 10 s
  deadline; green in 1.8 s after the fix).
- **#2 HIGH — event ordering**: `set_vpn_state` allocated and published
  sequence numbers after releasing the state lock, allowing publish order
  to invert against `seq` order (breaking the resync contract). Fix:
  mutation + allocation + publication under one lock hold via a
  guard-proof `emit_locked`. Regression test: 4-thread stress asserting
  publish order is strictly non-decreasing in `seq`.
- **#3 HIGH — TUI terminal restore**: normal quit (`q`/Esc/Ctrl-C) never
  restored raw mode/alternate screen (ratatui's Drop only restores the
  cursor), contradicting FR-127F. Fix: `run` borrows the terminal;
  `main` restores on every exit path. (No automated red-green: needs a
  tty; IT-22/M8 covers the lifecycle test.)
- **#9 — stale-event rewind**: `next_event` delivered stale/duplicate
  sequence numbers and rewound the cursor, making the next genuine event
  look like a gap. Fix: skip-and-continue. Red-green test
  `stale_events_are_skipped_without_rewinding`.
- **#10 — hello version floor**: version 0 below the oldest supported
  protocol was acked instead of refused. Red-green test added.
- **#6 (partial) — NaN/negative balanced weights** passed validation (all
  NaN comparisons are false). Fixed with a finiteness/non-negativity
  check + red-green tests.
- **#7 — dead config fields**: `daemon.log_level` is now applied (config
  loads before tracing init; `--log-level` overrides; RUST_LOG still
  wins); the no-op `--state-file` flag is removed until state persistence
  lands in M2.
- **#12 — `process::exit` inside CLI dispatch** (`daemon start`):
  returns a typed error; red-green test `daemon_start_returns_error`.
- **#11 + nits**: HelloAck send failure now ends the session instead of
  hanging the client; session writer channel reuses
  `bus::SESSION_QUEUE_LEN`; tautological tests deleted (protocol TUN
  constants, net route tables, duplicate envelope-shape test in ipc);
  `FALLBACK_CARGO` developer-machine path replaced by `$CARGO_HOME`
  resolution; `secure-core` rejects trailing words (test added); TUI
  `--socket` errors on a missing value.

### Tracked

- **#4 + #5 — client transport poisoning and request deadline** (M1.1): a
  read timeout strands the response in the stream and poisons the
  transport with a misleading `Internal` code; `request` has no overall
  deadline. Redesign: distinct transport-fatal error mapped to exit 13
  plus a poisoned flag; deserves its own TDD unit.
- **#6 (remainder) — stringly-typed config fields** (M2, before overlays):
  `dns.policy`, `connection.protocol`, `ipv6.mode`, `writable_session_store`,
  split-rule actions, ranking names → enums or validated vocabularies.
- **#8 — TUI per-750 ms reconnect** (M2, already tracked with the event
  loop redesign).
- Wire-shape nit (`request.request` nesting): revisit before the protocol
  freezes for M2 — flattening later costs a major version.
- `frame.rs`: `Closed` vs `Truncated` distinction; single-buffer writes.
- `redact.rs`: registry lock on the hot logging path (snapshot if volume
  grows); `StateStore`: parent-dir fsync, `schema_version` check on load;
  store→frontend-api conversion could live in core; client identity
  naming; socket-group comment pointing at PRD 6.3 (M8 packaging).

## 2026-08-15 — M1.1 closeout (refactorer steps + compliance gaps)

### Refactorer steps 1-3 — DONE (TDD where testable)

- **Step 3**: single trust-check policy seam (`checks_for(flag, debug)`
  pure fn, full input space pinned by test written first; CLI and TUI no
  longer assemble the policy).
- **Step 1**: feature-gated `protonwire-ipc::test_util::TestServer`
  (bind/serve/stop-on-drop) replaces both copy-pasted fixtures; the
  never-stopped serve-thread bookkeeping died with them.
- **Step 2**: `serve_messages` pinned by six characterization tests
  (duplicate-hello, request-before-hello, version above/below bounds,
  negotiated min, teardown slot release).
- Step 4 (proto.rs split) and step 5 (config.rs split): deferred to when
  M2 growth forces them — mechanical, low value today.

### Rust-review #4+#5 (transport redesign) — DONE (TDD: red on both)

`IpcClient::request` now distinguishes `RequestError::Rpc` from
`RequestError::Transport`: timeouts, I/O failures, and desynchronization
poison the connection (stranded bytes make the stream unusable), later
calls fail fast with a reconnect instruction, requests carry an overall
deadline (event streams can no longer keep one alive), and the SDK maps
transport failures to exit 13 (daemon unavailable) instead of exit 1.

### Compliance gaps — DONE

- **Gap 2 (release guard)**: `cargo xtask release-guard` fails unless
  `docs/LICENSE-CLEARANCE.md` exists; `.github/workflows/release.yml`
  runs it on every `v*` tag — the license blocker is now enforced, not
  just documented.
- **Gap 3 (license inventory)**: `cargo xtask license-scan` enumerates
  the live unlicensed set from `cargo metadata` and fails on drift
  against the recorded 17-crate baseline (verified matching live); runs
  in `xtask all`, so engine upgrades cannot silently grow the blocked
  set.
- **Gap 4 (SBOM/reproducibility skeletons)**: honest `cargo xtask sbom`
  stub alongside capability-matrix; disposition recorded here and in
  packaging/README.md.

Remaining tracked: Gap 5 (0600 file modes, M2 with the credential
store), the rust-review M2 items above, and the two open human questions
(branch/tag protection; rsa/Marvin risk-acceptance record).
