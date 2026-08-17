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

## 2026-08-15 — Devshell policy (standing rule)

Build and runtime tools now come exclusively from the repo-scoped
devshell (`shell.nix`, nixpkgs pinned to the revision carrying the
verified toolchain): rustc 1.97.1/cargo 1.97.0, rustfmt, clippy, gcc,
cargo-audit, git; `nix-shell --arg gui true` (or
`PROTONWIRE_GUI=1 direnv allow`, via the committed `.envrc`) adds the
webkit2gtk stack so `protonwire-gui` compiles locally too — with it, the
Tauri shell's missing webview runtime feature (`wry`) was found and
fixed locally instead of through a 16-minute CI round-trip. No
system-wide Rust installation is used — the machine's rustup was removed
entirely at the owner's direction (`rustup self uninstall`; 5.7 GB
reclaimed), and the session's earlier ad-hoc `nix shell nixpkgs#gcc`
wrappers are retired.

A flake-based devshell is deliberately NOT shipped: this repository uses
git's reftable ref storage, which Nix's libgit2 (flake `git+file`
fetching) cannot read — every available git here (system and nixpkgs,
all 2.55) predates `git refstorage migrate`. Classic `nix-shell` never
touches git, so `shell.nix` works today; the flake lands with the M8
packaging work once nixpkgs/nix catch up.

## 2026-08-15 — Codex PR review (PR #3)

The Codex bot reviewed PR #3 with 15 inline findings (2x P1, 13x P2).
All 15 were accepted as genuine defects after verification — each maps
to a fix commit with red-first TDD evidence in its message (read them
with `git log origin/feat/m1-foundation..HEAD --format=full`). The two
transport P2s share one commit (same request/response path), and the
redact commit also carries the stale-socket classification.

| # | Sev | Finding (anchor) | Verdict | Commit |
|---|-----|------------------|---------|--------|
| 1 | P1 | Keep lagging sessions subscribed after a full queue (`crates/ipc/src/bus.rs:48`) | Fixed @ 3173f64 | retain-on-Full, drop only on Disconnected; red: `lagging_session_stays_subscribed_and_receives_later_events` |
| 2 | P1 | Reserve a session slot before spawning the worker (`crates/ipc/src/server.rs:112`) | Fixed @ b411595 | atomic `try_reserve_session` before spawn + drop-guard; red: 192-connection burst measured 69 live sessions vs the 64 cap |
| 3 | P1 | Pass Cargo.lock rather than the audit policy to `--file` (`.github/workflows/ci.yml:78`) | Fixed @ c932bf2 | plain `cargo audit` from the root; before/after evidence in the message (0 vs 760 crate dependencies scanned) |
| 4 | P2 | Apply `daemon.socket_path` before binding (`apps/daemon/src/main.rs:76`) | Fixed @ 63ab27b | pure `resolve_bind_location` (--socket-dir > config > default); red: precedence test did not compile |
| 5 | P2 | Preserve partial frame bytes across polling timeouts (`crates/ipc/src/frame.rs:72`) | Fixed @ 0e601cf | stateful `FrameReader` retains prefix/payload progress; red: 3-byte prefix + 750 ms stall desynced the session |
| 6 | P2 | Let explicit socket flags override the environment (`crates/client/src/lib.rs:301`) | Fixed @ 41dbe70 | pure `resolve_socket_path` (Some(path) > env > default); red: precedence test did not compile |
| 7 | P2 | Parse connect options after target words (`apps/cli/src/commands.rs:36`) | Fixed @ 468b3a0 | dropped `trailing_var_arg` from Connect/Select; red: `connect country GB --by latency` landed `--by` in `target` |
| 8 | P2 | Restore the terminal when setup fails partway (`apps/tui/src/main.rs:99`) | Fixed @ 3b2503d | per-step rollback (raw mode, alternate screen, Terminal); no test — needs a real tty, defensive fix per the standing exception |
| 9 | P2 | Bound each response read by the remaining deadline (`crates/ipc/src/client.rs:242`) | Fixed @ 6d00e20 | every read gets `deadline.saturating_duration_since(now)`; red: ~1.4 s elapsed against a 1 s timeout |
| 10 | P2 | Fail event reads fast after the transport is poisoned (`crates/ipc/src/client.rs:275`) | Fixed @ 6d00e20 (same commit as #9) | `next_event` now checks `poisoned` first; red: it returned the stranded late response |
| 11 | P2 | Preserve a live socket on inconclusive connect errors (`crates/ipc/src/server.rs:150`) | Fixed @ e610265 | `authorizes_unlink` accepts only `ECONNREFUSED`; inconclusive errors abort startup; red: `only_connection_refused_authorizes_unlinking_a_stale_socket` |
| 12 | P2 | Keep active secrets registered for redaction (`crates/core/src/redact.rs:43`) | Fixed @ e610265 (same commit as #11) | Weak-reference registry, no cap; red: anchor secret still scrubbable after 320 churned registrations |
| 13 | P2 | Give concurrent state saves unique temporary files (`crates/store/src/state.rs:97`) | Fixed @ 4e40fec | per-save atomic counter in the temp name; red: 8x25 concurrent saves panicked on the shared inode |
| 14 | P2 | Reject obsolete files in the generated schema directory (`xtask/src/schema_gen.rs:56`) | Fixed @ 1ce17e6 | `check_dir` reports `.json` files outside `root_schemas()`; red: obsolete file passed `--check` silently |
| 15 | P2 | Scan the root workspace dependency versions (`xtask/src/deps.rs:130`) | Fixed @ 769e4d7 | `wildcard_versions` walks `[workspace]->dependencies`; `run()` scans the root `Cargo.toml`; red: root wildcard passed unseen |

No findings were rejected and none deferred: every item was either a
demonstrable correctness bug (1, 2, 4, 5, 6, 7, 9, 10, 11, 12, 13), a
gate that protected nothing (3, 14, 15), or a broken terminal-lifecycle
guarantee (8). Full per-finding rationale and test names live in the
commit messages; the consolidated verdict comment is posted on PR #3.

## 2026-08-15 — Codex PR review round 2 (PR #3)

The Codex bot posted 8 further inline findings on `62a64d7` (after the
round-1 set was fully fixed). Each was verified against the code before
acceptance; 7 were genuine and fixed red-first, 1 was rejected with
remote evidence. Red/green evidence lives in the commit messages.

| # | Sev | Finding (anchor) | Verdict | Commit |
|---|-----|------------------|---------|--------|
| 1 | P2 | Pair the resync snapshot with its sequence (`crates/client/src/lib.rs:240`) | Fixed @ 3c2e37f | additive-optional `DaemonState.latest_event_seq` (stamped under the emitter lock in core); the SDK advances its cursor to the snapshot's sequence. **Correction 2026-08-15 (round 3):** the original framing here — "and drops covered buffered events" — overstated what the test pins: `resync_snapshot_advances_the_cursor_to_its_own_sequence` proves events 3/4 are not *delivered* after the snapshot, but that suppression is equally delivered by the stale-skip path, so the test survived with `discard_events_through` removed entirely (QA mutation round). The discard call is now pinned directly (`discard_events_through_bounds_the_pending_queue`, commit 7748fc2) |
| 2 | P2 | Enforce the hello deadline during frame reads (`crates/ipc/src/server.rs:272`) | Fixed @ 034f291 | `FrameReader::read_msg_within` checks a codec-level deadline before every read — a steady dribble (one byte per sub-250 ms interval) keeps socket reads succeeding forever; red: `hello_deadline_holds_against_a_steady_byte_dribble` (7 s read expired with WouldBlock, 2 s past the 5 s deadline, server never disconnected) |
| 3 | P2 | Run push CI on the actual main branch (`.github/workflows/ci.yml:5`) | Rejected | the premise is false: the remote's only branch IS `master` (`git ls-remote --symref origin HEAD` → `ref: refs/heads/master`; `ls-remote --heads` lists no `main`; GitHub API `default_branch` = `master`), so the filter already targets the integration branch |
| 4 | P2 | Flush the shutdown acknowledgement before stopping (`apps/daemon/src/lib.rs:76`) | Fixed @ 9bcdb57 | `serve()` joins every session worker before returning (session teardown already joins the writer after unsubscribe), so main's exit cannot beat the ack flush; red: `serve_returns_only_after_sessions_flushed_their_final_responses` (serve() returned at ~250 ms with `active_sessions() == 1` and the ack unqueued) |
| 5 | P2 | Reject statuses outside the fixed manifest vocabulary (`xtask/src/manifest.rs:159`) | Fixed @ 54f20c3 | `status_definitions` must equal `REQUIRED_STATUSES` exactly — missing AND unknown keys are violations; red: `status_definitions_must_match_the_frozen_vocabulary_exactly` (a `waived` definition, with and without a capability using it, passed) |
| 6 | P2 | Compare recorded package checksums to the pinned values (`xtask/src/manifest.rs:215`) | Fixed @ c454af6 | manifest-validate parses the committed Cargo.lock (toml) and requires the muon 2.6.1 / pvpnclient 3.0.3 digests to EQUAL the lockfile checksums; missing lock entries fail rather than pass vacuously; red: `upstream_checksums_must_match_the_lockfile` (a well-formed but wrong digest passed) |
| 7 | P2 | Bound request writes by the request deadline (`crates/ipc/src/client.rs:231`) | Fixed @ 1670afe | connect/set_timeout set the write ceiling alongside the read ceiling; `request()` applies the remaining deadline to the write (zero-remainder guarded) and poisons on expiry; red: `request_write_is_bounded_by_the_deadline` (request() never returned within 2 s against a non-reading peer) |
| 8 | P2 | Prevent frontends from depending directly on IPC (`xtask/src/deps.rs:24`) | Fixed @ 068ac3a | separate `FRONTEND_APPS` class forbids the cli/tui/gui → protonwire-ipc edge while `protonwire-client` keeps its exemption (why the edge could not live in `DEEP_DEPS`); red: `frontends_cannot_depend_on_ipc_directly` (the edge passed unseen) |

One finding rejected with evidence (#3): every other item was a
demonstrable defect — four wire/lifecycle correctness bugs (1, 2, 4, 7)
and three gates that protected nothing (5, 6, 8). A follow-up style
commit (`4a93fd2`) reattached two round-1 doc comments the new test
insertions had split (caught by the clippy gate before push).

## 2026-08-15 — Consolidated round 3 (rust-reviewer + sec-auditor + qa-engineer)

The three reports converged on one fix round; every item landed TDD-first
with mutation-verified reds where the pin targets an existing behavior.
Commit messages carry the full evidence.

| Item | Verdict | Commit |
| --- | --- | --- |
| A — bound the serve() drain (SO_SNDTIMEO is per-syscall, not per-join) | Fixed | 16c9df2 (DRAIN_CEILING = 3x WRITE_TIMEOUT; stragglers force-disconnected via a weak socket handle and detached) |
| B — client-side dribble defense + partial-frame resume in handshake/next_event | Fixed | 0469046 (`read_msg_within` deadlines; next_event now bounded by self.timeout — expiry means "no event yet", callers re-poll) |
| C — dead request-local write re-arms dropped; zero-budget guard kept with rationale | Fixed | 6a54f01 |
| D — host-independent deaf-peer write fixture (SO_RCVBUF pinned to 4 KiB) | Fixed | 6a54f01 |
| E — FRONTEND_APPS/CLIENT_SIDE drift pinned by test | Fixed | 9a12827 |
| F — DaemonState version-bump doc corrected (additive-optional needs no bump) | Fixed | 63efb11 |
| G1-G7 — QA mutation gaps (legacy-None resync, stamp coherence, discard unit, max branch, pvpnclient tamper symmetry, zero-budget guard, multi-session drain) | Fixed | 7748fc2 (G1-G4), 6a54f01 (G6), cdbb74e (G5), 16c9df2 (G7) |
| H — injectable HELLO_DEADLINE, 10x faster dribble fixture | Fixed | 1a7b14f (plumbing landed with A) |
| I — lockfile map keyed (name, version) silently overwrote duplicates | Fixed | cdbb74e (duplicates rejected at parse) |

### Accepted risks

- **Post-hello dribble (server side) is deliberately unbounded** (carried
  from round 2's design): once a session completes the handshake, its
  reads may take as long as the client needs between requests — a live
  session trickling bytes forever is indistinguishable from a slow one.
  The exposure is bounded by the 64-session cap (`MAX_SESSIONS`): a
  dribbler holds one reserved slot, not a thread per byte. The shutdown
  path is no longer hostage to it: item A's DRAIN_CEILING force-closes
  stragglers at stop time.
- **G2's specific mutation is un-killable deterministically** (analysis in
  `snapshot_stamp_waits_for_an_inflight_publication`): because
  `emit_locked` allocates the sequence under the same lock that guards
  the fields, a stamp read moved outside the lock can only ever lag the
  fields — never lead them — and the field reads force `state()` to
  serialize with the emitter regardless. The test pins the serialization
  contract; both mutated read placements were run and stayed green.

### Red-evidence nuances for future rounds

Two shapes of "red" showed up this round that future commit messages
should keep honest about (per QA's evidence audit):

1. **Compile-failure reds** (the test cannot be built against the
   pre-fix API): state "red with plumbing kept, \<behavior\> removed" —
   land the inert plumbing first, then observe the behavioral red. Used
   for items A/E.
2. **Kernel-dependent reds** (the mutation's failure mode varies by
   kernel): record the mode actually observed, not the scariest one.
   G6 with the guard removed failed FAST at 0.02 s on the
   message-content assert — this kernel's sub-µs SO_SNDTIMEO yields an
   immediate EAGAIN, so the unguarded write fails promptly with a
   "write failed" wording (a fast wrong result, not a hang). A HANG is
   the possibility on kernels that round the zero-duration timeout to
   blocking ("block forever" on Linux), and G6's watchdog assert ('a
   zero write budget hung the request') exists to catch that mode. A
   test that merely times out in CI proves nothing without the message.
3. **Pinning tests for existing behavior** (G-series): the pre-fix code
   is green by definition, so the red must be demonstrated against the
   named mutation and the commit must say which mutation was run.

## 2026-08-15 — Round-3 closure (final fix pass)

Both reviewers PASSed the round-3 batch; this closing hygiene pass
landed their five remaining items:

1. **request-path codec deadline** (Medium, both reviewers): the
   request loop's read is now `read_msg_within(deadline)` — the last
   per-syscall-only bound on the client side, closing the same dribble
   gap round 3 fixed for handshake/next_event. Red-first: a daemon
   dribbling the response frame pinned `request()` past its deadline
   (watchdog fired at 2.00 s); green at 0.30 s after the fix.
2. `server.rs`: the finished-session drain branch now joins the handle
   (`session.join.join()`) instead of the no-op place expression.
3. `server.rs`: `DRAIN_CEILING` is `WRITE_TIMEOUT.saturating_mul(3)` —
   no truncation to a zero ceiling for a sub-second `WRITE_TIMEOUT`.
4. G6 red-evidence narrative corrected (test comment + the
   red-evidence nuances above): the observed red is a fast
   wrong-result (immediate EAGAIN); the hang is the kernel-dependent
   possibility.
5. rustdoc: private-const intra-doc links converted to plain code
   spans; `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps
   --document-private-items` is clean.

Remaining Track items (informational):

- **Abandoned-drain bus-slot release**: a session detached past
  DRAIN_CEILING still releases its bus slot via its own drop-guard —
  but if `serve()` were ever reused for a second run, an abandoned
  straggler from the first run could outlive its slot accounting.
  Today `serve()` runs once per process, so this is unreachable.
- **JoinHandle retention**: detached stragglers' handles are dropped,
  so a panic in an abandoned worker is silent (the catch_unwind log
  line never runs for it).
- **Lockfile strictness vs Cargo's keying**: our duplicate check keys
  on (name, version) alone, which is stricter than Cargo's
  (name, version, source) — a legitimate multi-source duplicate would
  be rejected. No such package exists in the current tree.

## 2026-08-15 — Codex PR review round 4 (PR #3)

Two further Codex passes on `1912fca` (5 findings at 15:14Z, 3 at
17:14Z — the raw-API "re-posts" of round-1/2 anchors were the REST
listing's original comments at their original commit ids; GraphQL
ground truth showed no duplicate threads). 7 accepted as genuine and
fixed red-first; 1 rejected on pinned-framework evidence. All 8 were
answered in-thread and resolved.

| Finding (anchor) | Verdict | Commit |
|------------------|---------|--------|
| Reap completed session workers (`server.rs`) — P1; the TUI reconnects every 750 ms, ~115k retained handles/day | Fixed @ 5ada8ea | `reap_finished` at the top of the accept loop; drain semantics unchanged (`reap_finished_joins_and_removes_ended_workers`) |
| Queue the hello ack before forwarding events (`server.rs`) — P2; a pre-hello publish reached the wire before `HelloAck` and clients rejected the session | Fixed @ cf0b81d | event forwarder gated on a channel opened only after the ack is queued (writer FIFO ⇒ ack first); pre-hello exits drop the gate and end the forwarder (`hello_ack_is_the_first_frame_even_under_pre_hello_events`) |
| Chown the production socket to the client group (`server.rs`) — P1; root daemon left the socket root:root 0o660, EACCES for every unprivileged client (PRD 6.3) | Fixed @ 6b2ca35 | `daemon.socket_group` (system authority, unset = no chown) + `bind_with_group` fail-loud on an unknown group; root-gated foreign-group test (`bind_with_group_chowns_to_a_real_group_when_root`) |
| CSP blocks the dashboard inline script (`tauri.conf.json`) — P1 | Rejected | premise false for Tauri-served assets: tauri-codegen 2.6.3 (`context.rs:47-66`) hashes every inline `script:not(:empty)` of frontendDist HTML, and tauri 2.11.5 (`manager/mod.rs:86-94, 126-153`) creates `script-src` with `'self'` + those hashes because `dangerousDisableAssetCspModification` defaults to enabled (we do not disable it). frontend-reviewer concurred |
| Enforce GPL-3 dependency compatibility in license-scan (`license.rs`) — P2; any nonempty license string passed, NFR-35 unenforced | Fixed @ e53fc40 | recursive-descent SPDX classifier: `/` ⇒ OR, OR=any branch, AND=all, `WITH` limited to LLVM-exception, unknown tokens fail loud (`gpl2_only_is_incompatible` and the classifier suite) |
| Redact longer overlapping secrets before substrings (`redact.rs`) — P2; registration-order replacement disclosed the longer secret's residue | Fixed @ a28a800 | live secrets sorted longest-first before replacement (`overlapping_secrets_redact_longest_first`) |
| Model `servers refresh` as the documented subcommand (`commands.rs`) — P2; PRD 9.4 grammar died in clap debug asserts before reaching the milestone-2 refusal | Fixed @ 5a733f7 | `ServersSub::Refresh { --yes }`; parse + refusal tests (`servers_refresh_parses_as_documented_subcommand`) |
| Pin the canonical group ID set (`groups.rs`) — P2; count-only check let renames through | Fixed @ f267beb | `EXPECTED_GROUP_IDS: [&str; EXPECTED_GROUP_COUNT]` set-equality check, mirroring the regions pin (`renamed_group_id_violates`) |

Process notes:

- **Batch integrity disclosure**: 5a733f7 folded a test-fixture hunk in
  `xtask/src/groups.rs` (canonical IDs replacing synthetic
  `proton:g{i}` in `good_groups_yaml()` — a dependency of f267beb's
  set check) alongside its CLI work. Test-fixture-only, benign; kept
  as history rather than rewritten.
- **Host quirk (WO-7 test)**: this machine's user namespace rejects
  chown to supplementary gids (EINVAL), so the unprivileged test
  injects the process's primary gid (a legal owner chgrp) to exercise
  the real chown path; the foreign-group stat assertion lives in the
  root-gated test and skips as non-root.
- **M8 advisories from the CSP rejection** (frontend-reviewer): (1)
  Tauri's runtime style-src nonce injection means a nonce-source makes
  engines ignore `'unsafe-inline'` — keep styling in the stylesheet,
  or disable style-src modification, if inline style attributes are
  ever wanted; (2) the compile-time script hashes follow frontendDist
  output — any post-codegen HTML rewriting would invalidate them (we
  register none today).

### Round-4 required-reviewer verdicts and track items

**ZhFMP (socket group, 6b2ca35) — sec-auditor PASS, no must-fix.**
Verified: mode-then-chown ordering safe (permissions widen
monotonically to the steady state); unknown group fails loud with no
silent root:root fallback; `chown(None, Some(gid))` preserves root
ownership so both client gates hold; `daemon.socket_group` is
system-authority-only (overlay cannot express it); NSS/name-confusion
ruled out (root-managed config, exact-name match, NUL names fail at
lookup); runtime dir root:root 0755 satisfies non-replaceability and
traverse-needs. Four Low track items (M2 hardening, non-blocking):

- (a) Pre-existing bind→chmod umask window: a umask guard at bind
  closes it; folds into tracked item 11's M2 hardening.
- (b) `create_dir_all` does not pin 0755 — set_permissions explicitly
  or fail-loud verify the mode.
- (c) The root-gated foreign-group test silently skips on non-root
  hosts — add a skip notice and assert uid stays 0 in the same test.
- (d) Untested enforcement interplay: member-can-connect /
  non-member-EACCES, plus a strict-mode client accepting a root:<grp>
  socket (root-gated arm).

**ZhFMR (license gate, e53fc40) — compliance-reviewer PASS, zero
allowlist corrections.** Every entry verified GPL-3.0-or-later
compatible, including the load-bearing orderings: GPL-2.0-or-later is
allowlisted before the incompatible-prefix branch; plain MPL-2.0
passes while MPL-2.0-no-copyleft-exception correctly falls to
Unrecognized. Four track items:

1. When `docs/LICENSE-CLEARANCE.md` is created, embed the license-scan
   output (743 classified packages, allowlist, commit) as clearance
   evidence; carry per-package verdicts in the M8 SBOM.
2. Compose `license::run` into `release_guard` so `v*` tags re-verify
   compatibility, not just marker existence.
3. Optional allowlist annotations: CC0 as waiver-fallback, CDLA as a
   data license, MPL-2.0 variant scoping.
4. Optional choose-the-compatible-branch semantics for
   Compatible-OR-Unrecognized expressions.

rust-reviewer and qa-engineer batch verdicts pending; any adverse
finding reopens the affected thread and re-enters the fix loop.

## 2026-08-15 — QA test-effectiveness round on the round-4 batch

qa-engineer's mutation audit of the round-4 tests: 3 High, 2 Medium,
2 Low — all test-effectiveness/process; the production code itself had
passed rust-reviewer, sec-auditor, and compliance-reviewer. Every
finding was accepted; six test commits landed (9f488c8..13d82a2).

| # | Finding | Disposition | Commit |
|---|---------|-------------|--------|
| F1 | `bind_with_group_applies_the_resolved_gid` was tautological (fresh-socket gid == process egid, so the assert held with the chown deleted — qa proved it); the only real gid-change assert never runs in CI | Fixed @ e8ac83b | chown injectable beside the resolver; `chown_seam_receives_the_resolved_gid` records the hand-off (path, name, RESOLVED gid, exactly once); resolver-Err/None arms now panic if chown runs; root-gated test skips under a user namespace with a notice and asserts uid stays 0 |
| F2 | The classifier could be disconnected from `run()` with everything green (constant-Compatible passed all 14 tests and CI) — the NFR-35 red was unproducible | Fixed @ 338bdcc | `scan_licenses` extracted; `scan_licenses_flags_gpl2_only` fails under the constant-Compatible mutation; `mixed_and_or_binds_tighter` kills the OR/AND swap (all prior mixed tests used parens); allowlist length pinned to 21; rot-guard comment on the real-tree vectors |
| F3 | `renamed_group_id_violates` was planted in 5a733f7 while its pin landed two commits later (f267beb), leaving **5a733f7, 5ada8ea, cf0b81d individually red** at their own trees (qa verified); 5a733f7's message claimed only the cli suite passed; 5ada8ea half-disclosed the cross-stream contamination | Process note (below) | history is pushed and stays; no code change |
| F4 | Deleting the `reap_finished` call passed the whole suite (only `-D warnings` caught full removal; partial wiring slipped silently) | Fixed @ 606d2b6 | `serve_observed` reports cumulative `ReapStats` after every reap; `accept_loop_reaps_ended_workers` drives real connect/disconnect cycles — the call-deletion mutation now fails it alone (watchdog red) |
| F5 | Hello-gate test: green-side regressions hung the suite (no read timeout); red side relied on a 100 ms sleep heuristic | Fixed @ 13d82a2 | 5 s read timeout + punctual-arrival assert; deterministic POLLIN readability poll replaces the sleep — a gate-open mutation fails in ~10 ms reporting the leaked frame verbatim; the green path has no sleep |
| F6 | `canonical_id_set_length_matches_expected_count` was provably always-true (the array type pins the length) | Fixed @ 86f7d9a | replaced with namespace + uniqueness validation of the canonical IDs (what the type does not pin) |
| F7 | The overlap-scrub test pinned the instance, not the property (reverse-registration mutation survived) | Fixed @ 9e0e5e7 | reverse-registration arm (long-then-short) added — a plain `reverse()` in place of the sort now leaks and fails |
| F8 | (1) both group-lookup error texts unmapped; (2) daemon 3-line `socket_group` pass-through untested | (1) folded into e8ac83b; (2) accepted residual (below) | — |

### F3 — bisect hazard disclosure

Three pushed commits in the round-4 batch are individually red:
**5a733f7** and **5ada8ea** and **cf0b81d**. Cause: the
`renamed_group_id_violates` red test and the canonical-ID fixture edit
for WO-2 were staged inside the WO-3 (cli) commit while WO-2's
EXPECTED_GROUP_IDS check landed two commits later (f267beb) —
cross-stream fixture staging in a concurrently-implemented batch.
`git bisect` across 5a733f7..cf0b81d will stop on these. Rules for
future rounds: **a red test ships in the SAME commit as the fix that
turns it green, never an unrelated stream's commit**; concurrent
implementers stage by explicit paths and gate in isolation (the
xtask implementer's temp-worktree gate during this QA round is the
pattern to keep).

### Accepted residual

The daemon's three-line `config_socket_group` pass-through
(main.rs: config → `bind_with_group`) is untested end-to-end: both
ends (the config field, the bind seam) are tested and the wiring is
type-checked, but no test drives `main` itself. Covered when the M2
daemon/systemd-unit integration test lands.

Mutation acceptance bar (qa re-verification): each named mutation —
chown deletion, constant-Compatible, OR/AND swap, reap-call deletion,
gate-open, reverse-registration, dead-length assert — must FAIL the
new tests. `Cargo.toml`: nix gained the `poll` feature for WO-R4's
readability poll (existing dependency, no version change, lockfile
untouched).

### Reviewer verdicts and acceptance record (closing)

- **compliance-reviewer**: PASS at both levels (classifier + scan seam);
  zero allowlist corrections; mutations M2a (constant-Compatible) and
  M2b (OR/AND swap) confirmed killed by `scan_licenses_flags_gpl2_only`
  and `mixed_and_or_binds_tighter` respectively.
- **sec-auditor**: PASS on the WO-R1 seam (re-verdict scoped to the
  test surface; the production-code PASS stands).
- **rust-reviewer**: FAIL→fixed @ a368775. The High: the root-gated
  test's user-namespace heuristic false-negatives in keep-id-shaped
  sandboxes (userns + pidns — the container init shares the user
  namespace, so `/proc/self/ns/user` vs `/proc/1/ns/user` compares
  equal), making the "gate is broken" canary panic for a plain
  non-root run. Reproduced red with the reviewer's exact
  `unshare --user --map-current-user --fork --pid --mount-proc` repro;
  fixed skip-first (non-root NOTICE-skip before the userns gate, canary
  removed); repro green (skip + NOTICE). qa independently recommended
  the same shape while verifying at 13d82a2 in a worktree — converged.
  Two Lows + one nit rode along in a368775 (distinct panic for a
  leaked non-Event frame; shadowed Mutex import dropped).
- **qa-engineer**: acceptance bar MET. All 7 named mutations killed by
  their intended tests as sole/designated failures; deterministic reds
  re-verified under 2-CPU pinning 3×; the hello gate red fires in
  ~0.01 s with no hang, reporting the leaked frame verbatim; the
  proactive probes M4b (non-cumulative counter) and M4c (never-called
  observer) are also killed. qa's item 2 (root-gate assert would fail
  stock non-root CI) was resolved by a368775 before its report landed.

Track items (recorded, not built):

1. Rootful-CI canary: enforce the real-chown arm's root precondition
   via an explicit env var on a rootful runner (the in-test canary
   assert died with the skip-first fix).
2. `ReapStats` fields are `allow(dead_code)` outside tests — consume
   the snapshot with `tracing::trace!` in `serve_observed` instead of
   the attribute.
3. The `serve` → `serve_with` → `serve_observed` delegation chain is
   unpinned; a doc-comment note on the chain suffices.
4. The userns/root skip NOTICEs are invisible under bare `cargo test`
   (libtest captures per-test output); surface via `--nocapture` or a
   test-runner notice mechanism.

## 2026-08-16 — Codex PR review round 5 (PR #3)

Four findings on the round-4 close (00:20Z). All four verified genuine
and fixed; one rejection-side kernel observation came out of V1's
test work and is recorded below. Each fix landed red-first; V1 was
champion-landed under explicit blessing with a documented test
deviation.

| Finding (anchor) | Verdict | Commit |
|------------------|---------|--------|
| Close the session when its writer fails (`server.rs`) — P1; a held-open client kept its slot forever after any writer exit; x64 wedged MAX_SESSIONS | Fixed @ 842c0c1 | writer-loop exit now `shutdown(Shutdown::Both)` — clones share one socket, so the dispatcher's read fails and the normal teardown runs (`writer_failure_tears_down_the_session`, toggle red 10.02 s / green 0.25 s) |
| Refuse connect modifiers instead of discarding them (`commands.rs`) — P2; `--dry-run` would build a real tunnel once Connect lands | Fixed @ ee1ef8d | typed per-modifier refusal with planned milestone (`--by`/`--dry-run` M3, `--protocol` M4); `--json` stays presentation-only (`connect_modifier_flags_are_refused_with_their_milestones`) |
| Validate every canonical group target (`groups.rs`) — P2; absent targets and every kind but fastest-in-region escaped validation | Fixed @ 65c56fc | every group must carry a target; `ALLOWED_TARGET_KINDS` vocabulary plus a per-canonical-group `EXPECTED_GROUP_TARGET_KINDS` map pins each id's selection semantics; fastest-in-region still requires a primary region (fixture-backed red tests) |
| Propagate configuration metadata errors (`config.rs`) — P2; `exists()` read EACCES as absence and handed the daemon silent defaults | Fixed @ 66fb598 | direct `fs::read`: only `NotFound` yields defaults, every other I/O error is a hard `ConfigLoadError::Io` naming path and source (unreadable-parent red test; missing-file-yields-defaults unchanged) |

### V1 test deviation (approved)

The finding's literal trigger — a blocked write dying at the 10 s
SO_SNDTIMEO ceiling — does not fire on this kernel. The pin therefore
uses a deterministic writer failure (a 2 MiB pong beyond
MAX_FRAME_LEN), which exercises the same invariant: writer-loop exit
⇒ shared-socket shutdown ⇒ dispatcher read fails ⇒ teardown.

### Track item: SO_SNDTIMEO does not interrupt steady-state blocked AF_UNIX sends here

Instrumented evidence from V1's test work: a server-side send of a
0.9 MiB frame to a client whose `SO_RCVBUF` is 4 KiB and which never
reads **outlasted a 20 s window with a 10 s `set_write_timeout` set**
— the blocked send was never interrupted; teardown only occurred when
the test's unwind closed the client side (ECONNRESET). Scope: the
shutdown drain is still bounded (DRAIN_CEILING force-closes
stragglers), and 842c0c1 recovers the session whenever the writer
does exit; the residual exposure is a writer blocked forever by a
never-reading peer — session-level, bounded by MAX_SESSIONS, and it
contradicts WRITE_TIMEOUT's doc comment on this kernel. Candidate
fix if escalated in a later round: a writer-side deadline watchdog
(a fan-out variant of `read_msg_within`). Not built now.

### Round-5 reviewer verdicts and follow-up lane (close-out)

- **rust-reviewer**: PASS on all four fixes — the shutdown ordering
  provably preserves the flush guarantee, the clone-sharing primitive is
  correct, no live-session false teardown, the CLI gate is the only
  dispatch route, and the store taxonomy is clean. Its mutation-sanity
  table drove five follow-ups, all landed:
  - FU-1 @ fbd2c44 — kind-swap-for-another-valid-kind red test (the
    per-id kind pin's only exposure).
  - FU-2 @ 2ed831b — semantic target fields: all six catalog fields
    deserialized, per-kind requirements (fastest-in-country ⇒ country,
    secure-core ⇒ entry+exit) and per-id pins (exclude_physical_country
    on two groups, connection_type on seven, selection_authority on
    random-country) verified against docs/connection-groups.yaml; three
    red tests pre-fix.
  - FU-3 @ d8484ff — client-side EOF assertion, with an honest
    correction: the literal `Shutdown::Read` mutation stays green
    because the session's last strong fd dropping delivers EOF on
    close(2) anyway; the red was demonstrated with the
    weakened-shutdown+fd-outlive pair — the class that actually hangs
    clients and the one the bounded EOF read pins.
  - FU-4 @ 37da03c — hermetic nonexistent-socket fixture; the
    environment-dependent Rpc arm removed.
  - FU-5 @ 350b787 — ALLOWED_TARGET_KINDS contents pinned; the
    arm-deletion mutation is honestly unobservable (shadowed by the
    per-id pin plus the id set), so the constant pin is the enforceable
    defense.
- **qa-engineer**: teeth CONFIRMED — the V1 mutation is caught exactly,
  the half-fix blindness is PROVEN benign (channel close implies the
  dispatcher already returned, so the guards run; corroborated across
  every channel-close-path test), and the TooLarge trigger is faithful
  (the writer loop is error-variant-agnostic). The one narrow gap became
  FU-5.
- **Champion disposition**: `yaml::from_path` deleted @ aa4f9fd — zero
  callers after V4, and the wrapper is the exact vector that would
  re-wrap future read errors into the parse-error channel V4 closed.

## 2026-08-16 — Codex PR review round 6 (PR #3)

Ten findings on the accumulated close (01:03/01:16Z batches): nine
accepted and fixed across eleven commits, one deferred to M2 with
evidence. All verified against HEAD before acceptance; the three
reviewer verdicts (rust PASS, sec PASS on the trust surfaces, qa teeth
CONFIRMED) sanctioned thread resolution, with residuals triaged into a
follow-up lane.

| Finding (anchor) | Verdict | Commit |
|------------------|---------|--------|
| Never unlink a non-socket entry at the bind path (`server.rs`) — P2; a regular file also answers ECONNREFUSED, so the probe alone authorized destroying it | Fixed @ 88941b7 | type check BEFORE the probe (`refuse_unless_stale_socket`); non-socket entries abort bind naming what they are; sec-auditor verified the symlink matrix fail-closed in every case |
| Bound events buffered while awaiting responses (`client.rs`) — P2; `pending_events` grew without limit | Fixed @ fc6310d | capped at 256 mirroring `SESSION_QUEUE_LEN`; overflow drops the oldest with cumulative accounting surfaced once per episode by `next_event`; the seq gap is recovered by the latest_event_seq resync path |
| Move owned secrets directly into zeroizing storage (`redact.rs`) — P2; `register(&value.into())` stranded an unzeroized temporary | Fixed @ 0eef7cb | `register_owned` moves the allocation into `Arc<Zeroizing>` — no copy on the owned path (compile-red disclosed; the no-copy property itself is inspection-level, sec-verified at the move-semantics level) |
| Attempt alternate-screen restoration after raw-mode errors (`tui/main.rs`) — P2; `?` returned before LeaveAlternateScreen | Fixed @ 5d38ba4 + 67afd3e | `attempt_both` runs BOTH teardown steps independently, first error reported |
| Emit the missing-config warning after tracing initializes (`daemon/main.rs`) — P2; load warned before any subscriber existed | Fixed @ 0c64724 | `LoadedSystemConfig { config, used_defaults }`; the daemon re-emits after `init_tracing_filtered` (no double-emit: the pre-init record is discarded by design) |
| Pin official-client revisions to recorded baselines (`manifest.rs`) — P2; 40-hex shape check only | Fixed @ 1e57e29 | `OFFICIAL_REVISIONS` pins all six; authority = recorded constants (a doc cannot vouch for itself); the any-further-entry rule derives from the pin map |
| Preserve the canonical capability ID set (`manifest.rs`) — P2; deleting `account.login` passed | Fixed @ 6149259 | `EXPECTED_CAPABILITY_IDS` (72) set equality, full-catalog fixture + meta-test |
| Require test references to resolve (`manifest.rs`) — P2; `T-999999` passed | Fixed @ 0403c6e | `CANONICAL_TEST_IDS` (92: T-1..37, IT-1..30, E2E-1..25 from PRD 17.1-17.3), subset check + split meta-test |
| Require the complete canonical M49 country set (`m49.rs`) — P2; a 150-row floor let dozens of countries vanish | Fixed @ f9fbbbc | `EXPECTED_M49_ISO_CODES` (247) set equality both directions; the floor stays as defense-in-depth |
| Preserve the negotiated protocol for outbound messages (`server.rs`) — P2 | Deferred to M2 | `PROTOCOL_VERSION` is 1 — version variance is unconstructible in M1 — and the handshake negotiation surface is M2's per the characterization tests' own docs (server.rs:870). **M2 track item:** when the constant grows, the negotiated version must flow into the event forwarder and response paths with per-version filtering; do not land a speculative filtering layer against a single-version protocol |

Reviewer verdicts: rust-reviewer PASS (focus points sound; pins
manually cross-diffed against ground truth — exact matches), with one
Medium (daemon re-emit unpinned) and Lows triaged to the follow-up
lane; sec-auditor PASS on W1+W2 (fail-closed symlink matrix; copy-free
claim verified at move-semantics level; Lows are pre-existing tracked
items including the round-4 dir-mode pin); qa-engineer teeth CONFIRMED
(all four production reverts kill exactly their intended tests; gaps
disclosed, none blocking).

Evidence disclosures: W2's no-copy property is inspection-level
(compile-red for the API, move-semantics verification by sec-auditor);
W8's teardown red is behavioral against the short-circuit semantics
(no tty in CI); W9's daemon-side re-emit is unpinned pending its FU
(extract `run(args)` with an injectable tracing factory). qa's
suite-health note: several `replacen`-based red tests can pass for
the wrong reason if their anchor strings drift — new fixture tests
should prefer unique anchors (the round-5 FU-1 test documents the
pattern).

Residual triage (follow-up lane): FU-A daemon run(args) extraction
with injectable tracing (rust Medium); FU-B symlink existence via
symlink_metadata + link→stale-socket (removed-not-target) and
link→regular (refused) cases; FU-C one-shot warn pinned via a
capturing subscriber (per-episode + two-episode reset); FU-D
test-only PRD cross-check of CANONICAL_TEST_IDS (the GATE stays
PRD-independent; only the `#[cfg(test)]` reads the PRD) plus
max-id-per-prefix + contiguity meta-tests — closes qa's one true
blind spot (nine unreferenced ids were swappable); FU-E W2 alloc
probe (approved with a scoped `#![allow(unsafe_code)]` in the test
crate, GUI-boundary precedent); FU-F any-further-entry rule test
(revision-less extra upstream). Review-log notes, no code:
duplicate-violation cosmetic, `dropped_events` consumer (M2 GUI/TUI
surfaces), W6-2 mapping-scope gap.

## 2026-08-16 — Codex round 7 + FU lane + verdict-fix lane (PR #3)

Round 7 (4 findings, 01:45Z) plus the round-6 FU lane and the
verdict-fix lane, all closed. Nine main commits + nine verdict-fix
commits + one champion residual fix.

| Finding | Verdict | Commit |
|---------|---------|--------|
| Enforce writer deadlines without SO_SNDTIMEO (P1, `server.rs`) | Fixed @ b3608e5 (+F1 774bc47, F3 faa3537, F2 dded3fc, F6 eb9288b, F7 c598ab0) | `write_msg_within`: MSG_DONTWAIT per chunk (the syscall never blocks), POLLOUT pacing inside the remaining budget, partial progress does not reset the deadline; expiry flows into the round-5 teardown. `ServeBudgets.write_timeout` injectable. rust PASS + sec PASS |
| `reconnect` panicked in the refusal table (P2, `commands.rs`) | Fixed @ ef2d516 (champion) | missing `planned_milestone` arm + the two-layer class killer: every-variant dispatch walk + no-wildcard exhaustiveness match |
| TUI refresh blocked the event loop (P2, `tui/main.rs`) | Fixed @ 0784acd (+F5 6ac6151) | background refresh thread, bounded newest-wins channel, STALE_AFTER marker; F5 stamps snapshots at FETCH time (mutation-red pinned) |
| Terminal state lost on SIGTERM/SIGHUP (P2, `tui/main.rs`) | Fixed @ 4c144c9 (+F4/F8 a475be5) | nix sigaction flag-only handler (async-signal-safe single store), restore on the main thread; SIGINT/SIGQUIT armed too; no signal-hook dependency needed |

FU lane (round-6/7 verdict residuals): FU-A @ b07aa72 daemon `run(args)`
tracing seam; FU-B @ 9308905 dangling-symlink naming + four symlink
pins; FU-C @ 25ef796 two-episode one-shot-warn pin
([(44,44),(44,88)]); FU-D @ 8c49f00 + FU-F @ 9f4a87d PRD cross-check,
contiguity/max-id pins, any-further-entry defender; FU-E @ 182ce83
owned-secret single-allocation pin (dedicated test binary, scoped
unsafe allow per the GUI precedent).

**SO_SNDTIMEO track item — SUPERSEDED WORDING (sec round-7 probe).**
The round-5 note said "never interrupted"; the round-7 first
correction said "~2x". The measured model is two defects: (1)
SO_SNDTIMEO bounds each WAIT, not the message — progress resets it,
and a multi-syscall write multiplies it (a 0.9 MiB frame ≈ 4 syscalls
≈ up to 4x the configured timeout); (2) under steady drain it never
expires at all — the probe watched a draining peer stretch past 80 s
under a 1 s timeout (round-5's 20 s-under-10 s observation sits
inside this model). DoS arithmetic, pre/post R7-1: pre-fix, one
never-reading peer pinned a writer + reserved slot indefinitely
(64x = permanent MAX_SESSIONS wedge); post-fix, one peer costs at
most one write_timeout per message and loses its session — the
watchdog's userspace deadline is the only bound that holds on every
kernel.

F7 reshape note (independently verified at close): the round-3
drain test's pinned-writer premise is gone post-R7-1 — the new
invariant (drain_ceiling ≥ 3x write_timeout, asserted in
serve_observed) makes a bounded writer unable to outlive the drain,
so the force-down path's genuine customer is now the BLOCKED
DISPATCH straggler; the pinned-writer class lives in the two
watchdog tests.

Track items: per-session write/idle ceiling (a slow-dribble client
can still hold a session indefinitely — bounded by MAX_SESSIONS);
queued-response memory amplification (~230 MiB/session possible from
the 256-deep queue of near-MAX_FRAME_LEN responses — pre-existing);
poll/send hot-loop spin under a perpetually-writable-but-unwritable
socket (nit); single-test seam note (ServeBudgets assertions live in
serve_observed); qa red-procedure notes incl. the R7-3 inline-fetch
hang construction for stall tests.

Process note: the IPC lane's `cargo fmt --all` reformatted the TUI
lane's in-flight file mid-run (harmless, nothing staged of theirs) —
concurrent lanes should use `-p`-scoped fmt.

## 2026-08-16 — Codex round 8 + verdicts + FAIL-fix lane (PR #3)

Eight findings (02:25Z) — the pin-family completion plus one trust
surface and one protocol corner. All eight fixed; verdicts: compliance
PASS, sec PASS (X4 hard trigger recorded), qa teeth CONFIRMED (20
mutations, all caught, deterministic under 2-CPU pinning), rust-review
FAIL → three prescribed fixes landed by the champion under explicit
blessing, each with its red recorded.

| Finding | Verdict | Commit |
|---------|---------|--------|
| Pin each country's canonical M49 mapping (`m49.rs`) | Fixed @ 715f4ef | 247 per-country (code, m49, region) tuples; distribution cross-checked |
| Reject unknown GPL-3.0-prefixed license IDs (`license.rs`) | Fixed @ 050a5f3 | exact-suffix acceptance in both GPL families; phantoms → Unrecognized |
| Validate source entries (`manifest.rs`) | Fixed @ 92f22ef | typed non-empty entries with kind describers |
| End-of-burst queue overflow signal (`bus.rs`/`server.rs`/SDK) | Fixed @ a0812ec + 4152cf8 | sentinel seq u64::MAX resync marker — see design record |
| Reject untrusted system configuration (`config.rs`) | Fixed @ 0af6234 | sshd StrictModes-style fs_trust walk — see design record |
| Compare the ProTUN pin with the resolved dependency (`manifest.rs`) | Fixed @ db1eb2a | pin vs the lockfile's `#<rev>` fragment; missing fragment fails |
| Pin canonical override maps (`groups.rs`) | Fixed @ 4d284ac | 14 per-id override maps pinned |
| Preserve every forbidden physical-country source (`groups.rs`) | Fixed @ 3d962d6 | the exact five-source set required |

**X4 design record.** A drop marks the session (atomic flag); the
forwarder claims it after forwarding one of the necessarily-queued
events (drop ⇒ full queue ⇒ events behind it — the reachability
argument) and sends the reserved-marker envelope straight down the
writer channel, bypassing the possibly-still-full bus queue while
riding the writer's FIFO and backpressure. Rejected alternatives (in
the commit): a new wire variant would poison old clients via serde
unknown-tag; a real-dropped-seq marker is indistinguishable at the
boundary. Compat, corrected per review: RELEASE builds of a pre-signal
SDK self-recover; DEBUG builds panicked on cursor+1 — fixed by
checked_add @ 55d7346 (red: "attempt to add with overflow" at
client.rs:267, reproduced by toggle). Fully gating the marker behind
the hello handshake is sec's HARD TRIGGER: must-fix before any
separately-shipped client artifact.

**X5 design record.** fs_trust walks every component from leaf to
trust root (`/` in production) with lstat: no symlinks, leaf regular,
ancestors directories, no group/world write, root uid+gid ownership;
two-pass leaf-first defect naming keeps the arms unprivileged-testable;
`MissingLeaf::Allow` keeps absence soft — and after rust's FAIL-fix,
absent ANCESTORS stay soft too (c3f7b49; live repro: the daemon called
a nonexistent dir "untrusted ... could not inspect" and exited 15) —
while existing ancestors are still verified (no laundering).
Relative components are rejected before inspection (dee01a9: `.`/`..`
resolve against the live tree, escaping the lexical walk). Track item:
consolidate ipc's verify_socket_trusted onto this walker when the
runtime-dir pinning lands.

**rust-review FAIL-fix lane** (champion-landed, reds recorded in the
commits): c3f7b49 absent-ancestor soft-NotFound; 55d7346 cursor
checked_add + release-only marker doc; dee01a9 RelativeComponent
rejection; plus 282466b (two more private doc links the doc gate
caught pre-push) and the #[test]-dedup followup.

**qa's three observations** (log-only): X1's unit-level gap is by
design — non-GB m49 drift is caught only by m49-verify against the
real snapshot (CI-side); the gate dependency is explicit. X7's
canonical_override_map_is_pinned meta-test is structure-only — value
drift is caught by the fixtures and the real gate, not the meta-test;
its name slightly oversells. X5's daemon production-call test cannot
distinguish mode from ownership regressions on unprivileged runners
(exit 15 either way) — the store suite carries both arms.

**Process records.** The coordinator's FAIL-blocking checkpoint fired
between fix-verification and the three-commit split — the window was
innocent (no close action preceded the fixes) and the correction is
recorded here as it happened. A pipe-masked clippy run hid the
duplicated-attribute error once; gate exit codes are now checked raw.
3c9936f (CONTRIBUTING conventions) rode this round's push.

## 2026-08-17 — Codex round 9 + the severity bar (PR #3)

Five findings (11:11Z) — TWO of them Codex escalating track items our
own reviews had recorded and deliberately deferred (the round-7
queued-response amplification figure and compliance-reviewer's
round-4 release-guard composition), both premises pre-verified by our
own evidence. All five fixed; closed LEAN under the new severity bar:
sec-auditor verdicts only where required (both PASS, no must-fix),
the three P2s' verdict record = lane evidence + the champion's batch
review.

| Finding | Verdict | Commit |
|---------|---------|--------|
| Set a usable default socket group (P1, `config.rs`) — defaults left the socket root:root against PRD 433 | Fixed @ ab8f464 (+3c4b951) | default Some("protonwire") in defaults AND the PRD example; hand-off gated on is_root (non-root dev keeps no-chown); root+unresolvable stays fail-loud; M8 packaging owns the group. sec PASS: gate un-invertible, no privilege path, PRD pairing executed |
| Bound the response queue by bytes (P1, `server.rs`) — ~230 MiB/session parked before backpressure | Fixed @ d22ef82 | request-credit window (16 unwritten → stop READING): flow control, not termination; ~18 MiB worst case; events count-but-never-wait; no wedge from ack or X4 marker. sec PASS: arithmetic verified, watchdog interplay traced |
| Re-run the license scan in the release guard (P2) | Fixed @ 3670bfe | release-guard composes the live license-scan before the marker check |
| Replace the queued snapshot with the newest one (P2, TUI) | Fixed @ c96029d | single-slot newest-wins cell replaces the depth-1 try_send channel |
| Run daemon_state off the Tauri main thread (P2, GUI) | Fixed @ c98704e | async command + worker task; webview boundary disclosed |

Verdict-Low dispositions from sec (3c4b951): the resolved gid is
logged at bind (operator audit — AnyUser covers Connect/Disconnect);
the hello-error refusals' counter underflow documented as a DELIBERATE
exception (terminal sends must not wait on the window). New track
items: M8 deployment note for the pre-existing-group collision hazard.

### Severity-bar dispositions (the 12:07Z batch, four P2s — replies ARE the dispositions)

- Client cursor seeds from the ack stamp, so a buffered pre-hello
  event classifies stale and is dropped — TRACK ITEM, M2 SDK
  event-cursor semantics (FR-127D): initialize from an initial
  snapshot or deliver-then-advance.
- IpcServer::drop unlinks a replaced socket — TRACK ITEM, M8 daemon
  lifecycle/handover: record the bound inode; remove only while it
  still identifies this server's socket.
- umask-0077 makes create_dir_all produce 0700, defeating traversal
  even with the default group — the RECORDED round-6 sec item
  ("create_dir_all does not pin 0755"), sharpened by R9-1's default;
  moves WITH the runtime-dir pinning hardening (M2).
- The dep gate checks direct names only; a neutral-helper transitive
  route would bypass — TRACK ITEM, M2 boundary-gate hardening: walk
  metadata.resolve from every client-side package (prophylactic; no
  such crate exists in-tree today).

Process note: the re-review queue is not a debt to drain —
triage-and-dispose (P1 lean / P2 track / reject with evidence) IS the
termination discipline. Two of five round-9 findings were our own
deferred track items, escalated on schedule: the deferral discipline
worked as designed.

### Post-close severity-bar disposals (12:56Z batch + CI incident)

Three further P2s, all groups.rs pin-family (target VALUES per id,
ranking policy per id, source values): each verified genuine, each
disposed as a TRACK ITEM (milestone 2). Recorded fix shape is
STRUCTURAL: golden-document equality for the canonical groups table
(subsuming every field-by-field pin) — the field-wise pattern has now
admitted one-more-unpinned-field three rounds running.

CI incident on 6eeddbf (attempt 1): the test job hung 20+ minutes in
`cargo test --locked` (others <1 min). Evidence triage: identical sha
green locally under 2-CPU pinning; rerun on the same sha passed in
48 s. Recorded as a runner/infra flake, one occurrence, no repro; if
it recurs, the R9-2 window tests get per-test timeouts first.

## 2026-08-17 — Refactor round (post-round-9): server split + set_drift

The queued structural work, landed after the review queue emptied so
it touched settled files: 177834d extracts the shared `set_drift`
helper for the xtask pin families (capability ids, M49 codes — one
violation message per drifted id, message wording at call sites);
283f264 splits server.rs into bind/session modules. rust-reviewer
PASS: behavior-preserving by region-by-region byte diffs beyond the
multiset claim; all pinned tests compared verbatim, none weakened
(the plan's "32 tests" was a miscount — the true pinned count is 34);
visibility changes exactly the three disclosed artifacts; gates
re-run raw and green.

Verdict-Low dispositions: the stray `./true` root artifact (a
mis-quoted shell redirect, content "echo R9-2:") deleted by the
coordinator; this entry is the findings-land-in-the-log obligation;
and the set_drift ordering contract is now pinned in-test — the
multi-element insertion-order case answers BOTH lists in canonical
sorted order (one honest correction to the reviewer's sketch: for
the {z,c} fixture the extra list is ["c","z"], not ["z"] — the
prescribed ordering pin is what landed, and the assert demonstrably
has teeth: a wrong expectation fails it).
