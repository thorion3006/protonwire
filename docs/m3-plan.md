# Milestone 3 Plan — Server Selection

Branch stack: `m3/selection-core` from master (`5fd53d7`, M2 merged). Normative
scope: PRD §18 M3, §7.3/7.3A, §9.2–9.5, §11.1–11.3; the implementation plan's
M3 exit (selection ≤500 ms on 20k synthetic servers; group suite T-28..T-33
green); tracked items per docs/review-log.md. Conventions per CONTRIBUTING.md.

## Stack mapping (owner rule 2026-08-25: one PR = one reviewer sitting)

M3 is delivered as a four-PR stack, each PR independently coherent, based on
its parent's branch, opened early, merged bottom-up (every merge is the
owner's call). No milestone-sized PR.

| PR | Branch | Units | Scope (PRD anchors) |
|----|--------|-------|---------------------|
| 1 (bottom, this branch) | `m3/selection-core` | U1 | The pure selection core: candidate model over the cached S6 catalog, hard filters, exact/special server matching, `official`/`balanced`/`load` policies with SPEED-SORT REJECTION (FR-14, FR-16..FR-23, FR-23H; T-1/T-2/T-3/T-4 + FR-22's structured elimination report) |
| 2 | `m3/group-registry` | U2, U3 | Group-target resolution consuming S13's validated registry (FR-23I..FR-23K, FR-23P/Q/R/S; T-28/T-29/T-33 pins) + regional M49 groups over the vendored snapshot (FR-23N/O; T-30) |
| 3 | `m3/secure-core-latency` | U4, U5 | Secure Core entry/exit routing (FR-23A..F; T-11) + bounded on-demand latency probing (FR-18/FR-19B; T-34) feeding the latency term of `balanced`/`latency` |
| 4 (top) | `m3/select-surface` | U6, U7 | Selection IPC + daemon wiring (FR-23T state fields; entitlement composition for port-forwarding) and the Select/Group/`connect --dry-run` CLI surface (§9.1–9.5; FR-23U) |

Justification per slice: PR-1 is a pure function over the landed catalog
model with zero new wire/CLI surface — reviewable in one sitting on the T-1
through T-4 test classes alone. PR-2 adds the generated registry and the
regional data pins (one data-gate family + one resolver). PR-3 pairs the two
machinery units that exist to serve ranked Secure Core/latency requests
(U5's probe table is U4's `--by latency` data source). PR-4 is the only unit
set that touches frontends, and it lands after every behavior it exposes is
pinned underneath it.

## Units (dependency order)

- **U1 — Selection core (PR-1):** `crates/core/src/selection.rs`. The
  candidate model over the S6 catalog document (`protonwire_store::catalog`;
  core already depends on store — the S7 scheduler precedent). Selection
  reads the CACHED catalog bytes; no fetch, no network (FR-23R; fetching is
  S7's single-flight scheduler). Hard filters in the FR-23P order for the
  stages the pure core owns: online state (unknown-status never passes as
  online — FR-13B), target geography/type, physical-country exclusion,
  explicit user exclusions (country/state/city/server, FR-21/FR-21A),
  required features, protocol compatibility (from `EntryPerProtocol`
  presence). Entitlement/subset stages compose at the daemon boundary (U6)
  over S8. Feature constraints (T-4): p2p/tor/secure-core/streaming/ipv6
  evaluate against catalog bits; port-forwarding parses but requires S8
  entitlement composition — typed refusal, never silent pass/downgrade
  (FR-23H). Exact/special server matching (T-3, FR-23): `UK#42` logical
  names, Secure Core `CH-SE#1` forms, gateway names — exact match never
  silently falls back. Policies: `official` = Proton catalog `Score`
  ascending after hard filters (FR-14, the catalog contract's
  `proton-score` semantics) with load as the tiebreaker within constraints
  (FR-19's allowed Proton-exposed signals); `balanced` = the FR-16 weighted
  formula over caller-supplied weights (missing-score refusal per signal
  below); `load` = lowest Proton-exposed load (FR-17). NO speed sorting: a
  `speed`-named sort mode or weight is rejected with a typed error in the
  selection input schema (T-1's "every input schema" — config/IPC/CLI
  vocabularies already refuse it on their own surfaces, S3). Pure entry:
  `(catalog, target, policy, constraints) → ranked candidates` plus the
  FR-22 elimination report and FR-23T scoring-signal provenance fields the
  upper PRs surface. The 20k benchmark fixture (below). Reviewers: rust, qa.
- **U2 — Group registry + target resolution (PR-2):** xtask generates the
  core-owned registry from `docs/connection-groups.yaml` (FR-23I; S13's
  golden-document equality stays the validation gate —
  `GOLDEN_GROUP_ENTRIES`); consumers never hard-code presets. Target kinds
  `fastest`, `fastest-in-country`, `random` resolve through U1;
  `secure-core` delegates to U4; `fastest-in-region` to U3. Ranking
  discipline (T-33): `proton:*` presets are Proton-score-ranked and reject
  request-time ranking overrides that would change official semantics
  (FR-23P; §9.3's `--by` contract); regional groups default to Proton score
  with `balanced|load|latency` as catalog-declared, status-visible
  overrides. Physical-country precedence per FR-23Q (explicit request →
  explicit config → cached Muon location; else typed
  `physical-country-required`). Reviewers: qa, compliance.
- **U3 — Regional M49 groups (PR-2):** the six `protonwire:fastest-*`
  groups over a generated country→primary-region mapping derived from the
  vendored, checksummed snapshot (FR-23N/O; T-30: six memberships, North
  America's composite 021+013+029 composition, deterministic
  single-continent membership, unknown-country = unmapped-and-ineligible).
  Generation rides the xtask M49 gate; runtime reads code, not the CSV.
  Reviewers: qa.
- **U4 — Secure Core routing (PR-3):** entry/exit pair filtering (T-11,
  FR-23C: fastest route, exit country, entry country, exact route where
  metadata allows, lowest load, lowest latency, excluded entry/exit
  countries); status carries both ends (FR-23D); incompatible options
  rejected with clear errors (FR-23F). Reviewers: rust, qa.
- **U5 — Bounded on-demand latency probing (PR-3):** T-34/FR-18/FR-19B —
  shortlist only (never the full catalog), per-endpoint result reuse with a
  minimum age, global and per-endpoint rate limits, cancellation, no
  background scanning, TCP/UDP default with ICMP opt-in (CAP_NET_RAW only
  then), an unanswered probe is never proof a endpoint is offline. Feeds
  U1's latency table. Reviewers: sec, rust, qa.
- **U6 — Selection IPC + daemon wiring (PR-4):** frontend-api selection
  request/result types (schema-gen'd), daemon arms composing S8 entitlement
  and the cached-catalog load; FR-23T fields end-to-end (group_id, origin,
  catalog revision, resolved selector, applied hard filters,
  physical-country value/source, winning server, scoring signals,
  requested-versus-applied feature difference). Reviewers: rust, sec, qa.
- **U7 — Select/Group/dry-run CLI (PR-4):** §9.2/§9.3/§9.5 grammar through
  the SDK; `protonwire select <target> --dry-run --json` output shape;
  group list/show/availability per FR-23S/U. Reviewers: rust, qa.

## Decisions (2026-08-25, coordinator — recorded pre-freeze)

1. **The 20k-server benchmark shape.** "20k synthetic servers" = 20,000
   total server entries realized as 5,000 logicals × 4 physicals each: the
   landed S6 catalog contract caps logicals at 16,384
   (`MAX_LOGICAL_SERVERS`; the live catalog carries a few thousand), so a
   20k-logical fixture is unrepresentable. 5,000/20,000 sits inside both
   landed caps and stresses the full pipeline (JSON bytes → strict parse →
   filter → rank). Generation is deterministic (fixed-seed LCG; countries,
   features, tiers, loads 0–100, scores, online states, protocol maps).
2. **Official ordering and its tiebreaker.** `Score` ascending (the catalog
   contract's `proton-score`); ties broken by Proton-exposed `Load`
   ascending, then by logical id for determinism. Load is an allowed
   Proton-exposed signal (FR-19); no local signal ever influences the
   official policy.
3. **Missing-score refusal (T-1/FR-19A).** Under `official`, ANY eligible
   candidate lacking `Score` is a typed `official-score-unavailable`
   refusal naming the count and suggesting an eligible catalog refresh —
   never a silent substitution of the balanced model, never a silent
   drop.
4. **Missing load under `load` and `balanced`.** A server without an
   exposed `Load` is excluded-with-structured-report (FR-22) under `load`,
   and excluded-with-report from `balanced`'s load term is impossible
   (weight>0 requires the field — same report); missing load is never
   approximated (0, 50, or otherwise).
5. **Balanced signal availability.** Latency is an M3 capability (U5): a
   positive latency weight without a caller-supplied latency table is a
   typed refusal (no fabricated latencies). Stability and history have no
   data source until connection statistics exist (post-M4; FR-19's
   "stability history"): their terms contribute uniformly zero and the
   scoring-signal report marks them absent — the formula and vocabulary
   are pinned now so the data lands later without schema change. Forbidden
   signal keys (`speed`, `estimated-speed`, `estimated-throughput` — the
   catalog contract's `forbidden_ranking_signals`) are rejected with a
   typed error at the selection input schema (T-1).
6. **NetShield is not a selection filter.** It is a connection-time
   feature request (§11.4 `FeatureRequest`, LocalAgent reconciliation
   T-20); §9.3 exposes it as `--netshield`, outside the `--require`
   family. Selection carries it into the requested-versus-applied
   difference (FR-23T, U6) but never filters catalog candidates on it.
   Port-forwarding parses as a constraint (§9.3 `--require
   port-forwarding`) and evaluates only against an entitlement seam
   (`Option<bool>`); `None` = typed refusal naming the missing
   composition — never a silent pass or downgrade (FR-23H).
7. **M49 runtime shape.** Country→region membership ships as generated
   code beside the group registry (xtask-gated against the checksummed
   CSV); runtime never parses `resources/geo/un-m49.csv` (FR-23O's
   "generated mapping tests").
8. **E2E placement.** E2E-23/E2E-24 (group connections) are staging-gated
   per §17.3 and land with the M6 E2E lane; M3's contract with them is
   the dry-run output shape and FR-23T provenance, both pinned in U6/U7.

## Highest-value tests (normative)

1. T-1's full class on U1: official ordering (incl. the load tiebreaker),
   balanced weighting, missing-score refusal, and `speed` rejection at the
   selection input schema.
2. The FR-22 elimination report: every hard-filter stage accounts for the
   candidates it removes; an unsatisfiable request names which constraint
   eliminated what (the "no eligible server" exit-5 class).
3. The FR-23 no-fallback invariant: an exact/special server request that
   cannot be satisfied NEVER returns a different server.
4. The 20k timed test: a real wall-clock assert of the full
   parse+select pipeline at ≤500 ms (disclosed margin; see U1).
5. T-30's data pins and T-33's ranking-discipline pins (PR-2), T-11's
   entry/exit filtering (PR-3), T-34's probe-bound suite (PR-3).

## Normative exit (M3)

Selection ≤500 ms on the 20k synthetic catalog (a real timed test; the CI
margin is disclosed in the test — the measured budget must leave generous
headroom, not sit at the bar); the T-28..T-33 group suite green; T-1/T-2/
T-4/T-11 test classes green; `cargo xtask all`, fmt, clippy `-D warnings`,
tests, and doc gates green on every PR in the stack.

## Rollout

No deploy in M3 (distribution blocked, OQ-2). The stack opens after PR-1's
verdict set (coordinator); each PR rebases on its parent on merge.
Rollback = revert the PR. The one wire-freeze-relevant step (U6's schema)
lands last, after every behavior it exposes is pinned underneath.
