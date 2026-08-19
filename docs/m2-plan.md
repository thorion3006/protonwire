# Milestone 2 Plan — Muon Auth and Server Cache

Branch: `feat/m2-muon-auth` from master (`5baa12a`). Normative scope: PRD §18 M2, §7.1/7.1A/7.2, §10; tracked M2 items per docs/review-log.md. Conventions per CONTRIBUTING.md.

## Units (dependency order)

- **S0 — Muon 2.6.1 API spike** (spike-first, timeboxed ~1 day; BLOCKS S4/S6): fetch muon in the devshell, read the source, write the API-surface memo into docs/spike-2026-08.md, land compile-checked adapter-trait skeletons (AuthenticationApi: begin_login/submit_two_factor/submit_fido_payload/refresh/logout/fork; LoginStep = Session|Challenge|Blocked; CatalogApi: fetch(etag) → Changed|NotModified; fake-transport seam — if the transport cannot be faked, the seam moves to the byte/connector layer, decided in S0). Must answer: challenge shapes; Store trait (FR-7JB preload); transport fakeability; ETag support; fork selectors; alternative-routing entry; location endpoint; entitlement data; the FR-7P TOTP-at-info log claim. Reviewer: rust-reviewer.
- **S1 — Secret-log suppression + canary suite (T-32/T-10; BLOCKS all Muon wire work):** per-module before-formatting suppression in init_tracing_filtered (muon info TOTP, pvpnclient trace selectors/cookies; dependency trace off in release); canary harness parameterized over an emitter (stub arm now, real-muon arm rides with S4 in the same commit as the first real call sites); pin "peer-derived values never enter the global registry" with a killing test. Reviewers: sec-auditor, qa-engineer.
- **S2 — Wire surface v2 groundwork + negotiated-version gating:** additive RpcErrorCode variants (UpstreamCapabilityBlocked, UnsupportedChallenge, ConfirmationRequired, RateLimited, CredentialPersistenceUnhealthy); confirmation-requirement envelope (catalog age / last request / next eligible / warning text); Event variants (CatalogRefreshed, AccountChanged); X4 marker gated on hello-negotiated version with per-version filtering; DECISION — flatten the request nesting NOW (free pre-freeze; no shipped clients; round-6 reviewer recommendation). Characterization tests extended first. Reviewers: rust, sec (gating), qa.
- **S3 — Config enums + YAML hardening (T-36) + field-level authority:** the stringly-typed fields → enums/vocabularies (before overlays); depth/alias limits + adversarial corpus in yaml.rs; authority_report() to field granularity. After the config-split opening commit. Reviewers: rust, qa.
- **S4 — Muon adapter: transport, session, login state machine (T-15):** SRP/TOTP/recovery/FIDO2-payload/refresh/logout/fork via the S0 traits, fake-transport tests per step; blocked-upstream/unsupported-challenge fail-closed, stable codes, no auto-retry (ER-17); alternative routing through the fake; versioned session envelope in store (distinct from the future ProTUN ApiSession, FR-7C); the real-muon canary arm ships in the same commit. After S0+S1. Reviewers: rust, sec, qa.
- **S5 — Credential input vs writable store** (three slices): S5a traits + auto resolution with recorded skip reasons + none-confirmation + persistence-health + 0600 modes; S5b systemd read-once input + transactional idempotent import with stale-replay refusal; S5c credential-agent registration protocol + Secret Service backend (mini-spike: zbus vs keyring vs secret-service) + IT-29-shaped peer tests. Reviewers: sec (lead), rust, compliance (new dep).
- **S6 — Server metadata retrieval + cache:** full FR-9 model, /var/cache/protonwire strict load, recorded-fixture tests through the fake; never fabricate entitlement/offline fields. After S0. Reviewers: rust, qa.
- **S7 — Single-flight scheduler (T-25/26/27):** pure clock-injectable deadline fn = greatest-of(last request, interval, 3h, Proton lifetime, Retry-After) + non-negative jitter (getrandom — promoted transitive, decided); persisted deadlines/suppression immune to restart and manual bypass; warned/confirmed override with single-use token, --yes still warns; property tests for composition/jitter-floor/rollback-monotonicity. After S6. Reviewers: rust, qa.
- **S8 — Entitlement model + free-plan cooldown data + gateway data (T-16 data layer).** After S4+S6. Reviewers: rust, qa.
- **S9 — Client surface: servers/account/credentials wired end-to-end:** ServersList/ServersRefresh{confirmation} + login-family variants; confirmation UX in CLI; account --json (credential source, store, persistence health); GetState owner-UID redaction for non-owner non-root peers (decided). After S2+S5a+S7. Reviewers: rust, qa (§9.8 exit-code table).
- **S10 — User-location capture + provenance cache (T-31):** single-flight on-demand only when needed, provenance + 3h persisted floor, honors Retry-After/block, physical-country-required, zero requests for group listing. After S7. Reviewers: rust, qa.
- **S11 — Per-UID overlay loader + daemon-side revalidation (T-37).** After S3. Reviewers: sec, rust, qa.
- **S12 — IPC hardening sweep:** verify_socket_trusted onto the fs_trust walker; bind-dir validation + umask guard + 0755 pin; per-session idle/write ceiling; ReapStats trace consumption; daemon SIGTERM via the reserved nix signal feature. Any time (sequenced around daemon-file collisions). Reviewers: sec, rust.
- **S13 — Gate/pin-family structural:** golden-document equality for the groups table (retires the field-by-field family); partial-wildcard rejection; transitive dep walk from every client-side package; source-string evidence validation. Any time. Reviewers: qa, compliance.
- **S14 — SDK event-cursor semantics:** ack-stamp cursor must not silently drop pre-hello buffered events (initial-snapshot or deliver-then-advance, pinned). After S2. Reviewers: rust, qa.

## Decisions (2026-08-17, coordinator — all recorded pre-freeze)

1. **Wire nesting: FLATTEN in S2.** Free until first client ships; nothing has shipped (distribution license-blocked); round-6 reviewer recommended; deferral costs a major version.
2. **TPM2 + full encrypted-local stores: DEFER post-M2** (the M2 bullet names only the abstractions, agent, systemd source, health); record in docs/official-parity.yaml (account.credential-lifecycle stays required; note the slice boundary).
3. **Jitter RNG: getrandom** (already a lockfile transitive; promotion adds no surface; std has no RNG).
4. **GetState redaction: null active_owner_uid for non-owner non-root peers** (PRD 6.3 literal).
5. **T-36 fuzz: in-tree corpus/property tests** (cargo-fuzz needs nightly; outside the pinned toolchain).
6. **TUI event-loop redesign: DEFER to M8** (PRD puts TUI capability completion in M8; M2's events reach the TUI via the notice stream; only S14's cursor semantics are load-bearing).
7. **Keyring D-Bus dependency: mini-spike at S5c** (zbus vs keyring vs secret-service; the one open dependency call).

## Highest-value tests (normative)

1. The T-32 canary suite with the real muon emitter (before-formatting filter, not regex) — secret disclosure is the unacceptable class.
2. The S7 deadline property suite (greatest-of composition, jitter floor, rollback monotonicity, suppression surviving restart) — Proton rate-limiting/blocking is the other unacceptable class.

## Rollout

No deploy in M2 (distribution blocked). Merge order follows the dependency edges; every unit green and shippable in isolation except the noted S5b/S5c-after-S5a, S4's canary arm, S9's inputs. Rollback = revert the unit. The one quasi-irreversible step (wire nesting) is decided above and still revertible until S2's schema lands.
