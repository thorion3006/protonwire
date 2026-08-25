//! The daemon-wide single-flight server-metadata scheduler
//! (FR-11/FR-12/FR-13C–FR-13I; tests T-25/T-26/T-27; E2E-22).
//!
//! One scheduler instance owns every automatic and client-requested
//! catalog refresh in the process; starting or reconnecting any client
//! must never create a second refresh schedule (FR-13C). The policy
//! core is a set of pure functions over injected inputs:
//!
//! * **Greatest-of deadlines (FR-13D, spike memo Q4):** the next
//!   automatic eligibility is `last request + greatest(configured
//!   interval, 3 h floor, Proton cache lifetime)` compared against
//!   `now + Retry-After`, followed only by *non-negative* jitter drawn
//!   from the OS CSPRNG via `getrandom` (m2-plan decision 3 — std has
//!   no RNG and hash-seeded pseudo-randomness is forbidden for this).
//!   Jitter can never pull an automatic refresh before the three-hour
//!   floor.
//! * **Rollback guard (T-26/FR-13H):** all deadlines are absolute wall
//!   times persisted beside a *wall high-water mark* (see
//!   [`protonwire_store::deadlines`]). The effective "now" is clamped
//!   to the high-water mark, so a wall clock that jumps backward cannot
//!   make any persisted deadline look already-due — no
//!   immediate-refetch storm, across restarts as well, because the
//!   clamp state is persisted.
//! * **Suppression (ER-16/E2E-22):** a rate-limited fetch sets the
//!   greatest-of suppression deadline `max(3 h floor, now +
//!   Retry-After)`; even a *confirmed* manual refresh and every restart
//!   honor it — the manual override bypasses only the local interval.
//! * **Warned/confirmed manual override (FR-11/FR-13I):** an early
//!   manual refresh demands a fresh confirmation; the minted token is
//!   single-use, expires, and is never persisted (approval is not a
//!   preference).
//!
//! ## The fetch seam (architecture note)
//!
//! Core must not depend on a transport ([ADR-0001], this crate's own
//! module docs), and `protonwire-api` already depends on
//! `protonwire-core`, so the scheduler consumes the S6 adapter surface
//! through [`CatalogFetch`] — a mirror of `CatalogApi::fetch(etag) ->
//! Changed{etag,body}|NotModified` whose failure side carries the
//! rate-limit classification. The daemon bridges `&dyn CatalogApi`
//! onto this seam (`services::bridge_fetch`, landed with S9): the
//! adapter's `ApiError::RateLimited{retry_after_seconds}` (the
//! 429/503 wire fixtures behind it) maps onto
//! [`FetchFailure::RateLimited`], and every other adapter failure
//! maps onto [`FetchFailure::Transport`].

use std::path::Path;

use protonwire_frontend_api::ConfirmationRequirement;
use protonwire_store::catalog::{
    CATALOG_CACHE_SCHEMA_VERSION as CACHE_SCHEMA_VERSION, CachedCatalog, CatalogDocument,
};
use protonwire_store::config::MetadataCacheSection;
use protonwire_store::deadlines::IntervalSource;

/// The hard product floor on the automatic catalog-refresh interval:
/// three hours (FR-12). Every shorter configured value — config,
/// profile, IPC, CLI, TUI, GUI — must fail validation somewhere, and
/// this module is the deepest enforcement point (T-25).
pub const FRESHNESS_FLOOR_SECONDS: u64 = 3 * 60 * 60;

/// How long a manual-refresh confirmation token stays redeemable after
/// minting. Fresh confirmation is required for *every* early manual
/// refresh (FR-13I); the TTL only bounds how long one ceremony's token
/// remains valid.
pub const CONFIRMATION_TOKEN_TTL_SECONDS: u64 = 300;

/// The FR-11 warning text. Deliberately a compile-time constant with no
/// interpolation: the eligibility facts ride the typed
/// [`ConfirmationRequirement`] fields, so no peer-derived or
/// redaction-class value can leak into what clients display (FR-121;
/// flagged for the S9 security review per the tracked item).
pub const MANUAL_REFRESH_WARNING: &str = "The server list is still fresh. Unnecessary refresh \
     requests may be rate-limited by Proton or your account may be \
     temporarily blocked from fetching server data. Confirm to refresh \
     now anyway.";

/// Failures of scheduler construction and wiring.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    /// The configuration violates a scheduler invariant (interval below
    /// the three-hour floor, ...).
    #[error("scheduler configuration invalid: {0}")]
    Config(String),
    /// The persisted deadlines could not be loaded or written.
    #[error("deadline store failure: {0}")]
    Deadlines(#[from] protonwire_store::deadlines::DeadlineStoreError),
    /// The catalog cache could not be loaded or written.
    #[error("catalog cache failure: {0}")]
    CatalogCache(#[from] protonwire_store::catalog::CatalogCacheError),
}

/// Validated scheduler policy derived from configuration (T-25).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerConfig {
    /// The configured automatic refresh interval in seconds; never below
    /// [`FRESHNESS_FLOOR_SECONDS`].
    pub refresh_interval_seconds: u64,
    /// The inclusive ceiling for the non-negative additive jitter, in
    /// seconds (FR-13D: 0..=ceiling, never negative). Never
    /// [`u64::MAX`] — [`SchedulerConfig::new`] rejects it (the range
    /// computation would overflow; see [`draw_jitter`]).
    pub max_positive_jitter_seconds: u64,
    /// Whether conditional (ETag) requests are used (FR-13E).
    pub conditional_requests: bool,
}

impl SchedulerConfig {
    /// Validates and builds a config. The core-side floor check is
    /// deliberate defense in depth: the YAML schema validates the same
    /// rule for files, and S9's IPC/CLI surfaces validate caller-supplied
    /// values — but the scheduler itself must never be constructible
    /// with a sub-three-hour interval (T-25).
    pub fn new(
        refresh_interval_seconds: u64,
        max_positive_jitter_seconds: u64,
        conditional_requests: bool,
    ) -> Result<Self, SchedulerError> {
        if refresh_interval_seconds < FRESHNESS_FLOOR_SECONDS {
            return Err(SchedulerError::Config(format!(
                "refresh interval {refresh_interval_seconds}s is below the three-hour floor \
                 ({FRESHNESS_FLOOR_SECONDS}s)"
            )));
        }
        // The same never-constructible defense for the ceiling (rust
        // M2): draw_jitter's `max_seconds + 1` wraps at exactly
        // u64::MAX (the subsequent modulo divides by zero) — and the
        // draw runs while the leader holds the lock, so the panic
        // would poison the mutex and wedge every joiner.
        if max_positive_jitter_seconds == u64::MAX {
            return Err(SchedulerError::Config(
                "jitter ceiling u64::MAX overflows draw_jitter's inclusive range \
                 (max_seconds + 1 wraps); use any value below u64::MAX"
                    .to_owned(),
            ));
        }
        Ok(Self {
            refresh_interval_seconds,
            max_positive_jitter_seconds,
            conditional_requests,
        })
    }

    /// Derives the policy from the system configuration's metadata-cache
    /// section, re-validating the floor (the section's YAML loader
    /// validates files, but a hand-built section — the IPC path — must
    /// not sneak a shorter interval past the scheduler).
    pub fn from_metadata_cache(section: &MetadataCacheSection) -> Result<Self, SchedulerError> {
        Self::new(
            u64::from(section.refresh_interval_hours) * 3600,
            u64::from(section.max_positive_jitter_minutes) * 60,
            section.conditional_requests,
        )
    }
}

/// The inputs of one deadline computation (FR-13D). All pure — the
/// property suite drives these directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadlineInputs {
    /// Unix time of the last upstream metadata request (`None` before
    /// the first ever request — the FR-13F bootstrap).
    pub last_request_unix: Option<u64>,
    /// The current wall reading.
    pub now_unix: u64,
    /// The configured interval (already floor-validated by
    /// [`SchedulerConfig`]; the pure function still applies the floor
    /// itself so the property holds regardless of caller).
    pub configured_interval_seconds: u64,
    /// A Proton-provided cache lifetime, when the API supplies one.
    pub proton_lifetime_seconds: Option<u64>,
    /// Whether the request was rate-limited at all (429/503 class),
    /// independent of whether the API supplied a usable
    /// `Retry-After` delay: a rate limit WITHOUT a delay still mints
    /// the suppression floor (Q4: `None` suppresses to the
    /// greatest-of floor).
    pub rate_limited: bool,
    /// A `Retry-After` delay observed at `now_unix` (seconds); only
    /// meaningful together with [`Self::rate_limited`].
    pub retry_after_seconds: Option<u64>,
    /// The already-drawn non-negative jitter (0..=ceiling).
    pub jitter_seconds: u64,
}

/// One computed deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    /// When the next *automatic* refresh is eligible: greatest-of plus
    /// the non-negative jitter.
    pub next_eligible_unix: u64,
    /// Which greatest-of component won (persisted per FR-13H).
    pub source: IntervalSource,
    /// The hard suppression floor — the greatest-of *without* jitter.
    /// `Some` only when a `Retry-After` signal participated; even a
    /// confirmed manual refresh is refused before it (E2E-22).
    pub suppression_until_unix: Option<u64>,
}

/// The greatest-of deadline function (FR-13D, spike memo Q4):
///
/// * span-origin = `last_request_unix` (or `now` for the bootstrap);
/// * span = `greatest(configured interval, 3 h floor, Proton lifetime)`
///   anchored at the origin;
/// * compared against `now + Retry-After`;
/// * the winner plus the non-negative jitter is the next eligibility.
///
/// Saturating arithmetic throughout: a hostile lifetime or Retry-After
/// of `u64::MAX` pins the deadline to "never", never to "overflowed to
/// the past".
pub fn next_deadline(inputs: &DeadlineInputs) -> Deadline {
    let origin = inputs.last_request_unix.unwrap_or(inputs.now_unix);
    // The floor participates in every greatest-of (FR-12/FR-13D).
    let (mut span, mut source) = if inputs.configured_interval_seconds > FRESHNESS_FLOOR_SECONDS {
        (
            inputs.configured_interval_seconds,
            IntervalSource::Configured,
        )
    } else {
        (FRESHNESS_FLOOR_SECONDS, IntervalSource::ThreeHourFloor)
    };
    if let Some(lifetime) = inputs.proton_lifetime_seconds
        && lifetime > span
    {
        span = lifetime;
        source = IntervalSource::ProtonLifetime;
    }
    let mut raw = origin.saturating_add(span);
    if let Some(retry_after) = inputs.retry_after_seconds {
        let retry_deadline = inputs.now_unix.saturating_add(retry_after);
        if retry_deadline > raw {
            raw = retry_deadline;
            source = IntervalSource::RetryAfter;
        }
    }
    Deadline {
        next_eligible_unix: raw.saturating_add(inputs.jitter_seconds),
        source,
        // Q4: EVERY rate limit mints the suppression floor — the
        // un-jittered greatest-of — including one that carried no
        // Retry-After delay (None suppresses to the floor; qa P1-1).
        suppression_until_unix: inputs.rate_limited.then_some(raw),
    }
}

/// Draws one non-negative jitter value in `0..=max_seconds` from the OS
/// CSPRNG (`getrandom` — m2-plan decision 3: already a lockfile
/// transitive, so promotion adds no surface; std has no RNG and
/// hash-seeded pseudo-randomness is forbidden for product jitter).
/// Rejection sampling keeps the distribution uniform (no modulo bias).
pub fn draw_jitter(max_seconds: u64) -> u64 {
    if max_seconds == 0 {
        return 0;
    }
    let range = max_seconds + 1;
    let limit = u64::MAX - u64::MAX % range; // values below `limit` map uniformly
    loop {
        let mut bytes = [0u8; 8];
        // getrandom cannot fail on supported platforms; a failure means a
        // broken CSPRNG, and refusing to jitter (0) is the safe default —
        // the floor, not the jitter, is what protects Proton.
        if getrandom::getrandom(&mut bytes).is_err() {
            return 0;
        }
        let value = u64::from_ne_bytes(bytes);
        if value < limit {
            return value % range;
        }
    }
}

// ---------------------------------------------------------------------------
// Clock seam (E2E-22: the virtual-clock property suite is normative)
// ---------------------------------------------------------------------------

/// The time source every scheduler decision consults. Two readings:
/// the wall clock (anchoring persisted deadlines) and a monotonic
/// counter (detecting that the wall went *backward* while time actually
/// passed). Injected everywhere — production gets [`SystemClock`], the
/// property suites drive rolled-back, jumped-forward, and repeated
/// virtual clocks.
pub trait Clock: Send + Sync {
    /// Current wall time in Unix seconds.
    fn now_unix(&self) -> u64;
    /// Milliseconds on a monotonic counter (any fixed origin).
    fn monotonic_ms(&self) -> u64;
}

/// The production clock: wall from `SystemTime`, monotonic from a
/// process-wide `Instant` anchor.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

/// Process-wide monotonic anchor (lazily initialized once).
static PROCESS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn monotonic_ms(&self) -> u64 {
        PROCESS_START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis() as u64
    }
}

/// A fully controllable virtual clock (E2E-22): the wall and monotonic
/// readings move only through explicit test direction, so rollback,
/// jump-forward, and repeated-tamper scenarios are deterministic.
/// Shared by handle (`Arc` inside), so the scheduler and the test move
/// one clock.
#[derive(Debug, Clone, Default)]
pub struct VirtualClock(std::sync::Arc<std::sync::Mutex<VirtualClockInner>>);

#[derive(Debug, Default)]
struct VirtualClockInner {
    wall_unix: u64,
    mono_ms: u64,
}

impl VirtualClock {
    /// A clock starting at `wall_unix`, monotonic counter at zero.
    pub fn new(wall_unix: u64) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(
            VirtualClockInner {
                wall_unix,
                mono_ms: 0,
            },
        )))
    }

    /// Sets the wall reading to any value — forward or backward
    /// (a backward set is exactly the rollback scenario).
    pub fn set_wall(&self, wall_unix: u64) {
        self.0.lock().expect("virtual clock").wall_unix = wall_unix;
    }

    /// Moves both readings forward by `seconds` (time passing normally).
    pub fn advance_secs(&self, seconds: u64) {
        let mut inner = self.0.lock().expect("virtual clock");
        inner.wall_unix += seconds;
        inner.mono_ms += seconds * 1000;
    }

    /// Forces the monotonic counter (for adversarial combinations).
    pub fn set_monotonic_ms(&self, ms: u64) {
        self.0.lock().expect("virtual clock").mono_ms = ms;
    }
}

impl Clock for VirtualClock {
    fn now_unix(&self) -> u64 {
        self.0.lock().expect("virtual clock").wall_unix
    }

    fn monotonic_ms(&self) -> u64 {
        self.0.lock().expect("virtual clock").mono_ms
    }
}

// ---------------------------------------------------------------------------
// The fetch seam (see the module docs' architecture note)
// ---------------------------------------------------------------------------

/// One conditional catalog fetch's success side — the mirror of the S6
/// adapter's `CatalogFetch` (`Changed{etag,body}|NotModified`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// The catalog changed (or no ETag was supplied).
    Changed {
        /// The response `ETag` for the next conditional request.
        etag: Option<String>,
        /// The raw catalog body.
        body: Vec<u8>,
    },
    /// The stored revision is still current (FR-13E).
    NotModified,
}

/// The failure classification the scheduler's pacing policy consumes.
/// The daemon's S9 bridge maps the adapter's `ApiError::RateLimited`
/// onto the [`FetchFailure::RateLimited`] arm (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchFailure {
    /// The upstream refused the request for pacing reasons (429/503
    /// class). `retry_after_seconds` carries the parsed `Retry-After`
    /// delay when the API supplied one; `None` still suppresses to the
    /// greatest-of floor (Q4).
    RateLimited { retry_after_seconds: Option<u64> },
    /// Any other transport failure: no suppression, but the deadline
    /// still resets from the attempt so failures cannot hammer either.
    Transport(String),
    /// The fetch was REFUSED because the local pacing anchor could not
    /// persist (the deadline store is unwritable — Codex PR#4 round 2,
    /// P2). Contacting the upstream without a durable pre-fetch
    /// timestamp lets a restart bypass the window (the FR-13H
    /// restart-storm class) and would lose any Retry-After suppression
    /// signaled this round. The failure path still resets the in-memory
    /// window; the next attempt retries (and the store may heal).
    Persistence(String),
}

/// The injected fetch service: `Fn(stored etag) -> fetch result` — the
/// `&dyn CatalogApi` seam the daemon bridges (FR-13C: every read goes
/// through the one scheduler).
pub type CatalogFetch =
    std::sync::Arc<dyn Fn(Option<&str>) -> Result<FetchOutcome, FetchFailure> + Send + Sync>;

// ---------------------------------------------------------------------------
// Outcomes and diagnostics
// ---------------------------------------------------------------------------

/// What one completed refresh did (the S2 `CatalogRefreshed` event and
/// FR-123 status fields derive from this).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// A new catalog revision was fetched.
    Changed {
        /// The new `ETag`.
        etag: Option<String>,
        /// The raw catalog body.
        body: Vec<u8>,
    },
    /// The stored revision was still current.
    NotModified,
    /// The upstream rate-limited the request; the suppression deadline
    /// is set from the greatest-of (Q4).
    RateLimited {
        /// The `Retry-After` delay the API supplied, if any.
        retry_after_seconds: Option<u64>,
    },
    /// The fetch failed for transport reasons.
    Failed {
        /// Stable failure description (never peer-secret).
        reason: String,
    },
}

/// The report every refresh caller receives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshReport {
    /// What the refresh did.
    pub outcome: RefreshOutcome,
    /// `true` when this caller joined an already in-flight refresh and
    /// received its result (T-25 single-flight coalescing).
    pub coalesced: bool,
    /// The next automatic eligibility the refresh set.
    pub next_eligible_unix: u64,
    /// The active suppression deadline after the refresh, if any.
    pub suppression_until_unix: Option<u64>,
}

/// The result of [`Scheduler::refresh_automatic`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutomaticOutcome {
    /// A refresh ran (or was coalesced into one).
    Due(RefreshReport),
    /// The next eligibility has not arrived; the caller does nothing.
    NotDue {
        /// When the next automatic refresh becomes eligible.
        next_eligible_unix: u64,
    },
}

/// The result of [`Scheduler::refresh_manual`] (FR-11/FR-13I).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManualOutcome {
    /// A refresh ran (eligible outright, or confirmed).
    Refreshed(RefreshReport),
    /// The refresh is early: the caller must surface the carried
    /// [`ConfirmationRequirement`] (warning + token) and replay the
    /// token to proceed.
    ConfirmationRequired(ConfirmationRequirement),
    /// An active suppression refuses even a confirmed manual request
    /// (ER-16/E2E-22); the manual override bypasses only the interval.
    Suppressed {
        /// When suppression ends.
        until_unix: u64,
    },
    /// Fail-closed (rust M4/sec F1): the confirmation-token CSPRNG is
    /// unavailable, so no ceremony can be held and no early manual
    /// refresh is possible — a broken RNG must not become a bypass.
    /// The caller may retry once the RNG recovers; nothing was burned.
    Unavailable,
}

/// Scheduler facts for FR-123 status and FR-13I diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerDiagnostics {
    /// Last upstream metadata request (any outcome).
    pub last_request_unix: Option<u64>,
    /// Last successful fetch (changed or not-modified).
    pub last_success_unix: Option<u64>,
    /// Next automatic eligibility.
    pub next_eligible_unix: Option<u64>,
    /// Which greatest-of component set it.
    pub next_eligible_source: Option<IntervalSource>,
    /// Active suppression deadline, if any.
    pub suppression_until_unix: Option<u64>,
    /// Completed automatic refreshes through the AUTOMATIC door
    /// (separately counted, FR-13I): every completed automatic-path
    /// refresh, whether due-window or coalesced-lead — a DOOR counter,
    /// not a confirmed-override counter (the S7 review's adjudicated
    /// semantics; the leader's kind owns the increment).
    pub automatic_refresh_count: u64,
    /// Completed refreshes through the MANUAL door (separately
    /// counted, FR-13I): every completed manual-path refresh — due
    /// (no ceremony needed) or confirmed early override alike — a
    /// DOOR counter, not a confirmed-override counter (same
    /// adjudication as [`Self::automatic_refresh_count`]).
    pub manual_refresh_count: u64,
    /// Whether a wall-clock rollback was ever detected this run.
    pub clock_rollback_detected: bool,
    /// Catalog age in seconds (from the last successful fetch).
    pub catalog_age_seconds: Option<u64>,
}

// ---------------------------------------------------------------------------
// The scheduler
// ---------------------------------------------------------------------------

/// Pure rollback arithmetic, property-tested directly: the wall went
/// backward while the monotonic counter did not — the only combination
/// that cannot be ordinary time passing.
pub fn wall_rolled_back(prev_wall: u64, prev_mono: u64, wall: u64, mono: u64) -> bool {
    wall < prev_wall && mono >= prev_mono
}

/// A minted, not-yet-redeemed confirmation token (in-memory ONLY —
/// FR-13I: approval is never a preference, and the persisted document's
/// `deny_unknown_fields` makes a smuggled token a hard parse error).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingToken {
    value: String,
    expires_unix: u64,
}

/// Live rollback-tracking state (the persisted half is
/// `SchedulerDeadlines::wall_high_water_unix`).
#[derive(Debug, Clone, Copy, Default)]
struct RollbackTracker {
    last_wall_seen: u64,
    last_mono_seen: u64,
    detected: bool,
}

#[derive(Debug, Default)]
struct Inner {
    persisted: protonwire_store::deadlines::SchedulerDeadlines,
    etag: Option<String>,
    generation: u64,
    in_flight: Option<u64>,
    completed: Option<(u64, std::sync::Arc<RefreshReport>)>,
    token: Option<PendingToken>,
    rollback: RollbackTracker,
    /// Confirmation-token mint source — the OS CSPRNG in production,
    /// injectable through this private field for the in-crate
    /// forced-failure fail-closed test (the seam-injection idiom the
    /// fetch seam uses).
    minter: MintSource,
    /// The production catalog cache (ConfigPaths-derived), when wired:
    /// successful fetches write the new revision through it (FR-10/
    /// FR-13B/FR-13E). `None` for test-only schedulers.
    cache: Option<CacheState>,
    /// Whether the deadline store is currently accepting writes. Set
    /// false by ANY save failure (pre- or post-fetch); while false, the
    /// next lead first RETRIES a bare save of the current state — if it
    /// succeeds the flag clears and the refresh proceeds; if not, the
    /// refresh is refused without contacting the upstream (Codex PR#4
    /// round 3, P2: a Retry-After longer than the floor that only
    /// exists in memory must not be silently lost to a restart — the
    /// process refuses further upstream contact until its suppression
    /// state is durably recorded).
    persistence_healthy: bool,
}

/// The confirmation-token mint source (see
/// [`mint_confirmation_token`]). A newtype so [`Inner`] keeps its
/// derived `Debug`/`Default` while holding an injectable closure.
#[derive(Clone)]
struct MintSource(std::sync::Arc<dyn Fn() -> Option<String> + Send + Sync>);

impl std::fmt::Debug for MintSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MintSource(<closure>)")
    }
}

impl Default for MintSource {
    fn default() -> Self {
        Self(std::sync::Arc::new(mint_confirmation_token))
    }
}

/// The wired catalog cache and its current document.
#[derive(Debug, Clone)]
struct CacheState {
    cache: protonwire_store::catalog::CatalogCache,
    current: Option<protonwire_store::catalog::CachedCatalog>,
}

/// Which door a refresh came through (separate counters, FR-13I). The
/// LEADER's kind owns the diagnostic counter: one fetch increments
/// exactly one counter, by the door that initiated it — a manual
/// joiner of an automatic lead is counted as automatic (it caused no
/// upstream request and overrode nothing), and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshKind {
    Automatic,
    Manual,
}

/// One observed instant: the rollback-clamped effective time every
/// deadline compares against (the raw wall/monotonic readings fed the
/// rollback decision inside `observe_now`).
#[derive(Debug, Clone, Copy)]
struct ObservedNow {
    effective: u64,
}

/// The daemon-wide single-flight server-metadata scheduler (FR-13C).
/// Clone-free by design: share one `Arc<Scheduler>` per process.
pub struct Scheduler {
    config: SchedulerConfig,
    clock: std::sync::Arc<dyn Clock>,
    fetch: CatalogFetch,
    store: protonwire_store::deadlines::DeadlineStore,
    inner: std::sync::Mutex<Inner>,
    cv: std::sync::Condvar,
}

impl Scheduler {
    /// Builds a scheduler over already-loaded persisted state and the
    /// injected collaborators (the clock and fetch seams, the deadline
    /// store). Production construction (strict loads with `/` as trust
    /// root, ConfigPaths-derived paths only) is [`Scheduler::production`].
    pub fn new(
        config: SchedulerConfig,
        clock: std::sync::Arc<dyn Clock>,
        fetch: CatalogFetch,
        store: protonwire_store::deadlines::DeadlineStore,
        persisted: protonwire_store::deadlines::SchedulerDeadlines,
        etag: Option<String>,
    ) -> Self {
        Self::new_with_cache(config, clock, fetch, store, persisted, etag, None)
    }

    /// The common construction path: the crash-between-saves
    /// re-derivation plus an optionally wired catalog cache (production
    /// wires one; test schedulers usually do not).
    fn new_with_cache(
        config: SchedulerConfig,
        clock: std::sync::Arc<dyn Clock>,
        fetch: CatalogFetch,
        store: protonwire_store::deadlines::DeadlineStore,
        persisted: protonwire_store::deadlines::SchedulerDeadlines,
        etag: Option<String>,
        cache: Option<CacheState>,
    ) -> Self {
        let mut persisted = persisted;
        Self::rederive_crash_pacing(&mut persisted);
        Self {
            config,
            clock,
            fetch,
            store,
            inner: std::sync::Mutex::new(Inner {
                persisted,
                etag,
                generation: 0,
                in_flight: None,
                completed: None,
                token: None,
                rollback: RollbackTracker::default(),
                minter: MintSource::default(),
                cache,
                persistence_healthy: true,
            }),
            cv: std::sync::Condvar::new(),
        }
    }

    /// The production constructor (the S9 daemon wiring point): strict
    /// loads over the `ConfigPaths`-derived cache-directory documents
    /// with `/` as the fs_trust root, the stored revision seeded for
    /// conditional requests, the catalog cache wired so successful
    /// fetches write each new revision through it, and the
    /// crash-between-saves re-derivation applied to the loaded
    /// deadlines.
    pub fn production(
        config: SchedulerConfig,
        clock: std::sync::Arc<dyn Clock>,
        fetch: CatalogFetch,
        paths: &protonwire_store::paths::ConfigPaths,
    ) -> Result<Self, SchedulerError> {
        Self::production_with_trust_root(config, clock, fetch, paths, Path::new("/"))
    }

    /// The production construction over an explicit fs_trust root.
    ///
    /// Public since S9 (the daemon wiring lane): the daemon's
    /// fail-closed startup constructs through [`Scheduler::production`]
    /// (root `/`), and its hermetic tests need the same construction
    /// over a shallower root — a root-owned tree is unprovable on
    /// unprivileged runners, and the ownership pass would otherwise
    /// refuse every test-planted document before the arm under test
    /// (the same opt-in this crate's own tests use). The production
    /// walk root stays `/` (the sshd StrictModes rule the fs_trust
    /// module documents); the shallower root is the hermetic-test
    /// opt-in.
    pub fn production_with_trust_root(
        config: SchedulerConfig,
        clock: std::sync::Arc<dyn Clock>,
        fetch: CatalogFetch,
        paths: &protonwire_store::paths::ConfigPaths,
        trust_root: &Path,
    ) -> Result<Self, SchedulerError> {
        let store =
            protonwire_store::deadlines::DeadlineStore::new(paths.cache_dir.join("deadlines.json"));
        let cache =
            protonwire_store::catalog::CatalogCache::new(paths.cache_dir.join("servers.json"));
        let persisted = store.load_strict(trust_root)?.unwrap_or_default();
        let current = cache.load_strict(trust_root)?;
        let etag = current.as_ref().and_then(|doc| doc.etag.clone());
        Ok(Self::new_with_cache(
            config,
            clock,
            fetch,
            store,
            persisted,
            etag,
            Some(CacheState { cache, current }),
        ))
    }

    /// The crash-between-saves floor re-derivation (rust M1): the
    /// pre-fetch save persists `last_request` but the floor-bumped
    /// `next_eligible` only lands post-fetch, so a daemon crash-looping
    /// inside that window loads a stale — or absent, on the first fetch
    /// — eligibility that reads as "due" and refetches on every start.
    /// The floor from the persisted request time is the minimum
    /// survivable window: re-deriving it at construction can only push
    /// eligibility further out, never shorten a greater surviving
    /// deadline.
    fn rederive_crash_pacing(persisted: &mut protonwire_store::deadlines::SchedulerDeadlines) {
        let Some(last_request) = persisted.last_request_unix else {
            return; // never fetched: the FR-13F bootstrap stays due
        };
        let floor = last_request.saturating_add(FRESHNESS_FLOOR_SECONDS);
        if persisted.next_eligible_unix.is_none_or(|next| next < floor) {
            persisted.next_eligible_unix = Some(floor);
            persisted.next_eligible_source = Some(IntervalSource::ThreeHourFloor);
        }
    }

    /// A snapshot of the persisted deadlines (restart-survival tests,
    /// FR-123 status fields).
    pub fn persisted(&self) -> protonwire_store::deadlines::SchedulerDeadlines {
        self.inner.lock().expect("scheduler lock").persisted.clone()
    }

    /// Current diagnostics (FR-123/FR-13I).
    pub fn diagnostics(&self) -> SchedulerDiagnostics {
        let guard = self.inner.lock().expect("scheduler lock");
        let now = self.observe_wall(&guard);
        SchedulerDiagnostics {
            last_request_unix: guard.persisted.last_request_unix,
            last_success_unix: guard.persisted.last_success_unix,
            next_eligible_unix: guard.persisted.next_eligible_unix,
            next_eligible_source: guard.persisted.next_eligible_source,
            suppression_until_unix: guard.persisted.suppression_until_unix,
            automatic_refresh_count: guard.persisted.automatic_refresh_count,
            manual_refresh_count: guard.persisted.manual_refresh_count,
            clock_rollback_detected: guard.rollback.detected,
            catalog_age_seconds: guard
                .persisted
                .last_success_unix
                .map(|success| now.saturating_sub(success)),
        }
    }

    /// Reads the clock and applies the rollback clamp without touching
    /// the live tracker (used where no mutation is wanted).
    fn observe_wall(&self, guard: &Inner) -> u64 {
        self.clock
            .now_unix()
            .max(guard.persisted.wall_high_water_unix)
    }

    /// Reads both clocks, updates the rollback tracker, and returns the
    /// effective (high-water-clamped) time. Callers hold the lock.
    fn observe_now(&self, guard: &mut Inner) -> ObservedNow {
        let wall = self.clock.now_unix();
        let mono = self.clock.monotonic_ms();
        let tracker = &mut guard.rollback;
        if wall_rolled_back(tracker.last_wall_seen, tracker.last_mono_seen, wall, mono) {
            tracker.detected = true;
        }
        tracker.last_wall_seen = tracker.last_wall_seen.max(wall);
        tracker.last_mono_seen = tracker.last_mono_seen.max(mono);
        let effective = wall.max(guard.persisted.wall_high_water_unix);
        ObservedNow { effective }
    }

    /// The automatic path (FR-13C: every automatic refresh, and every
    /// coalesced join of one, goes through here).
    pub fn refresh_automatic(&self) -> AutomaticOutcome {
        let mut guard = self.inner.lock().expect("scheduler lock");
        // T-25 single-flight: join an already-running refresh instead of
        // piling a second request onto Proton.
        while let Some(running) = guard.in_flight {
            let seen = running;
            while guard.in_flight == Some(seen) {
                guard = self.cv.wait(guard).expect("scheduler lock");
            }
            if let Some((done, report)) = &guard.completed
                && *done == seen
            {
                let mut joined = (**report).clone();
                joined.coalesced = true;
                return AutomaticOutcome::Due(joined);
            }
            // The generation resolved without our report (impossible
            // today — only the leader clears it while setting
            // `completed` — but re-evaluating is the safe loop shape).
        }
        // Leader: is the next window open? (Rollback-clamped time.)
        let now = self.observe_now(&mut guard);
        if let Some(deadline) = guard.persisted.next_eligible_unix
            && now.effective < deadline
        {
            return AutomaticOutcome::NotDue {
                next_eligible_unix: deadline,
            };
        }
        // Defense-in-depth (sec P3, invariant-trust): the writer derives
        // next_eligible >= suppression, but the automatic door must not
        // bet on that derivation surviving every writer — an active
        // suppression refuses directly, mirroring the manual door below.
        if let Some(until) = guard.persisted.suppression_until_unix
            && now.effective < until
        {
            return AutomaticOutcome::NotDue {
                next_eligible_unix: until,
            };
        }
        AutomaticOutcome::Due(self.lead_refresh(guard, RefreshKind::Automatic))
    }

    /// The manual path (FR-11/FR-13I): eligible refreshes proceed
    /// outright; early ones require a fresh warned confirmation; an
    /// active suppression refuses even a confirmed request (E2E-22).
    ///
    /// Single-flight joins (T-25): a manual caller that arrives while a
    /// refresh is already in flight receives its result — the joiner
    /// caused no upstream request, so it is counted by the LEADER's
    /// door (FR-13I) and any token it presents is NOT burned: a join
    /// consumes an already-running window, not the ceremony. (A live
    /// outstanding token can only predate the lead — ceremonies cannot
    /// be minted while a refresh is in flight, and a manual LEAD burns
    /// its token at redeem — so an unburned token has never authorized
    /// anything and still buys exactly its one later early refresh.)
    pub fn refresh_manual(&self, token: Option<&str>) -> ManualOutcome {
        let mut guard = self.inner.lock().expect("scheduler lock");
        while let Some(running) = guard.in_flight {
            let seen = running;
            while guard.in_flight == Some(seen) {
                guard = self.cv.wait(guard).expect("scheduler lock");
            }
            if let Some((done, report)) = &guard.completed
                && *done == seen
            {
                let mut joined = (**report).clone();
                joined.coalesced = true;
                return ManualOutcome::Refreshed(joined);
            }
        }
        let now = self.observe_now(&mut guard);
        // ER-16/E2E-22: suppression outranks confirmation — the manual
        // override bypasses only the local interval, never a
        // Proton-signalled rate limit.
        if let Some(until) = guard.persisted.suppression_until_unix
            && now.effective < until
        {
            return ManualOutcome::Suppressed { until_unix: until };
        }
        let due = guard
            .persisted
            .next_eligible_unix
            .is_none_or(|deadline| now.effective >= deadline);
        if due {
            return ManualOutcome::Refreshed(self.lead_refresh(guard, RefreshKind::Manual));
        }
        match token {
            // An empty echo is foreign by construction and is rejected
            // BEFORE the pending-token comparison (rust M4/sec F1,
            // redeem side): tokens are 64 hex characters, and a failed
            // mint mints NOTHING (`Unavailable`), so "" can never be
            // the live pending value — it must never redeem.
            Some(value) if !value.is_empty() => {
                let redeemable = guard.token.as_ref().is_some_and(|pending| {
                    pending.value == value && now.effective <= pending.expires_unix
                });
                if redeemable {
                    // Single-use: burned by the attempt itself, success
                    // or failure (a retry must re-confirm, FR-13I).
                    guard.token = None;
                    ManualOutcome::Refreshed(self.lead_refresh(guard, RefreshKind::Manual))
                } else {
                    // Expired, already-burned, or foreign token: a fresh
                    // ceremony, never a silent acceptance.
                    self.ceremony(&mut guard, now.effective)
                }
            }
            Some(_) | None => self.ceremony(&mut guard, now.effective),
        }
    }

    /// Mints one fresh ceremony, fail-closed: when the token CSPRNG is
    /// unavailable no requirement can be minted, no token is stored,
    /// and the early manual refresh is simply impossible (rust M4/
    /// sec F1 — the old shape returned an empty token, matchable by
    /// echoing "" back).
    fn ceremony(&self, guard: &mut Inner, effective_now: u64) -> ManualOutcome {
        match self.mint_requirement(guard, effective_now) {
            Some(requirement) => ManualOutcome::ConfirmationRequired(requirement),
            None => ManualOutcome::Unavailable,
        }
    }

    /// The next automatic eligibility (the daemon's timer target), on
    /// the rollback-clamped clock.
    pub fn next_due_unix(&self) -> Option<u64> {
        let guard = self.inner.lock().expect("scheduler lock");
        guard.persisted.next_eligible_unix
    }

    /// Test-only: the persistence-health flag's current state (the
    /// degraded-state observable; the refusal behavior itself is pinned
    /// end-to-end by the unwritable-store tests).
    #[cfg(test)]
    pub(crate) fn persistence_healthy_for_tests(&self) -> bool {
        self.inner
            .lock()
            .expect("scheduler lock")
            .persistence_healthy
    }

    /// Mints one fresh confirmation requirement (and replaces any
    /// outstanding token: confirmation is per-request, FR-13I). The
    /// warning is the compile-time constant — no peer-derived value
    /// enters it (see [`MANUAL_REFRESH_WARNING`]). `None` = the CSPRNG
    /// failed: nothing is stored and no ceremony is possible
    /// (fail-closed).
    fn mint_requirement(
        &self,
        guard: &mut Inner,
        effective_now: u64,
    ) -> Option<ConfirmationRequirement> {
        let token = (guard.minter.0)()?;
        guard.token = Some(PendingToken {
            value: token.clone(),
            expires_unix: effective_now.saturating_add(CONFIRMATION_TOKEN_TTL_SECONDS),
        });
        Some(ConfirmationRequirement {
            catalog_age_seconds: guard
                .persisted
                .last_success_unix
                .map(|success| effective_now.saturating_sub(success))
                .unwrap_or(0),
            last_request_unix: guard.persisted.last_request_unix,
            next_eligible_unix: guard
                .persisted
                .next_eligible_unix
                .unwrap_or(effective_now)
                .max(guard.persisted.suppression_until_unix.unwrap_or(0)),
            warning: MANUAL_REFRESH_WARNING.to_owned(),
            confirmation_token: token,
        })
    }

    /// Runs one fetch as the single-flight leader. `guard` is held on
    /// entry and dropped for the fetch itself; the caller's outcome is
    /// published to parked joiners on completion.
    fn lead_refresh(
        &self,
        mut guard: std::sync::MutexGuard<'_, Inner>,
        kind: RefreshKind,
    ) -> RefreshReport {
        guard.generation += 1;
        let generation = guard.generation;
        guard.in_flight = Some(generation);

        // The round-3 persistence-health gate: after a save failure the
        // in-memory state (notably a Retry-After suppression LONGER than
        // the reconstructable floor) may outrun what the disk holds.
        // Before any upstream contact, retry a bare save of the CURRENT
        // state — success clears the flag and the refresh proceeds;
        // failure refuses the fetch (the suppression must be durably
        // recorded before normal operation resumes).
        let persistence_cleared = if !guard.persistence_healthy {
            match self.store.save(&guard.persisted) {
                Ok(()) => {
                    tracing::info!("deadline store recovered; resuming refreshes");
                    guard.persistence_healthy = true;
                    true
                }
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        "deadline store still unwritable; refusing the fetch \
                         (suppression state must be durable before normal operation resumes)"
                    );
                    false
                }
            }
        } else {
            true
        };

        // Pre-fetch persistence (FR-13H/T-26): the request is about to
        // reach Proton; a crash after it must not forget that. Anchor
        // every wall timestamp in the rollback-clamped effective time so
        // the whole deadline space stays self-consistent.
        let started = self.observe_now(&mut guard);
        guard.persisted.last_request_unix = Some(started.effective);
        guard.persisted.wall_high_water_unix =
            guard.persisted.wall_high_water_unix.max(started.effective);
        let etag = self
            .config
            .conditional_requests
            .then(|| guard.etag.clone())
            .flatten();
        let anchored = if persistence_cleared {
            match self.store.save(&guard.persisted) {
                Ok(()) => true,
                Err(error) => {
                    // Codex PR#4 round 2 (P2): the pacing anchor must be
                    // DURABLE before the upstream is contacted — a fetch
                    // whose last_request cannot survive a restart lets the
                    // next boot bypass the window (the FR-13H restart-storm
                    // class), and any Retry-After suppression signaled this
                    // round would be lost the same way. Refuse the fetch;
                    // the in-memory window still resets and the next
                    // attempt retries the store.
                    tracing::error!(
                        error = %error,
                        "persisting pre-fetch deadlines failed; refusing the fetch \
                         (restart pacing protection)"
                    );
                    guard.persistence_healthy = false;
                    false
                }
            }
        } else {
            false
        };
        drop(guard);

        // A panicking fetch bridge must not wedge the single-flight
        // forever (joiners park on `in_flight`): convert a panic into a
        // transport failure so the generation resolves either way.
        let fetched = if anchored {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                (self.fetch)(etag.as_deref())
            }))
            .unwrap_or_else(|_panic| {
                tracing::error!("catalog fetch panicked inside the bridge");
                Err(FetchFailure::Transport("fetch bridge panicked".to_owned()))
            })
        } else {
            Err(FetchFailure::Persistence(
                "the deadline store is unwritable; the fetch was refused so a restart cannot \
                 bypass the window"
                    .to_owned(),
            ))
        };

        let mut guard = self.inner.lock().expect("scheduler lock");
        let finished = self.observe_now(&mut guard);
        // The fetch took monotonic time; effective time cannot have gone
        // backward even if the wall did mid-fetch.
        let effective_now = finished.effective.max(started.effective);
        let jitter = draw_jitter(self.config.max_positive_jitter_seconds);
        let retry_after = match &fetched {
            Err(FetchFailure::RateLimited {
                retry_after_seconds,
            }) => *retry_after_seconds,
            _ => None,
        };
        let deadline = next_deadline(&DeadlineInputs {
            last_request_unix: Some(started.effective),
            now_unix: effective_now,
            configured_interval_seconds: self.config.refresh_interval_seconds,
            // The adapter supplies no Proton cache lifetime today (spike
            // memo Q4/Q8); the input stays wired so S8 can feed it.
            proton_lifetime_seconds: None,
            rate_limited: matches!(&fetched, Err(FetchFailure::RateLimited { .. })),
            retry_after_seconds: retry_after,
            jitter_seconds: jitter,
        });
        let outcome = match &fetched {
            Ok(FetchOutcome::Changed { etag, body }) => {
                match adopt_fetched_revision(&mut guard.cache, etag, body, effective_now) {
                    RevisionVerdict::Adopted => {
                        // The revision is the server's current one AND,
                        // when a cache is wired, DURABLY stored (a store
                        // failure refuses the revision — never a split
                        // world where the refresh reports Changed while
                        // clients keep the old catalog): adopt it for
                        // the next conditional request and the age
                        // anchor.
                        guard.etag = etag.clone();
                        guard.persisted.last_success_unix = Some(effective_now);
                        RefreshOutcome::Changed {
                            etag: etag.clone(),
                            body: body.clone(),
                        }
                    }
                    RevisionVerdict::Unusable(reason) => RefreshOutcome::Failed { reason },
                }
            }
            Ok(FetchOutcome::NotModified) => {
                guard.persisted.last_success_unix = Some(effective_now);
                if let Some(state) = &mut guard.cache
                    && let Some(current) = &state.current
                {
                    // FR-13E: freshness only — the stored body bytes are
                    // carried through verbatim, never rewritten.
                    match state.cache.refresh_freshness(current, effective_now) {
                        Ok(updated) => state.current = Some(updated),
                        Err(error) => {
                            tracing::warn!(error = %error, "refreshing cached freshness failed")
                        }
                    }
                }
                RefreshOutcome::NotModified
            }
            Err(FetchFailure::RateLimited {
                retry_after_seconds,
            }) => RefreshOutcome::RateLimited {
                retry_after_seconds: *retry_after_seconds,
            },
            Err(FetchFailure::Transport(message)) | Err(FetchFailure::Persistence(message)) => {
                RefreshOutcome::Failed {
                    reason: message.clone(),
                }
            }
        };
        match kind {
            RefreshKind::Automatic => guard.persisted.automatic_refresh_count += 1,
            RefreshKind::Manual => guard.persisted.manual_refresh_count += 1,
        }
        // A lingering earlier suppression can outlive a fresh
        // non-rate-limited deadline: keep the greater on both fields.
        let suppression = guard
            .persisted
            .suppression_until_unix
            .map(|existing| existing.max(deadline.suppression_until_unix.unwrap_or(0)))
            .or(deadline.suppression_until_unix);
        let next_eligible = deadline.next_eligible_unix.max(suppression.unwrap_or(0));
        guard.persisted.next_eligible_unix = Some(next_eligible);
        guard.persisted.next_eligible_source = Some(deadline.source);
        guard.persisted.suppression_until_unix = suppression;
        guard.persisted.wall_high_water_unix =
            guard.persisted.wall_high_water_unix.max(effective_now);
        if let Err(error) = self.store.save(&guard.persisted) {
            // Codex PR#4 round 3 (P2): a post-fetch save failure means
            // the freshly computed deadlines — notably any Retry-After
            // suppression LONGER than the restart-reconstructable floor
            // — exist only in memory. Mark persistence unhealthy: the
            // next lead retries a bare save before ANY upstream contact
            // (see the gate at the top of lead_refresh), so the process
            // cannot keep fetching while its suppression state is
            // undurable. (A crash while unhealthy still degrades to the
            // floor on restart — the recorded residual; the fs being
            // broken makes full durability impossible.)
            tracing::warn!(
                error = %error,
                "persisting post-fetch deadlines failed; persistence degraded — the next \
                 refresh requires a durable save first"
            );
            guard.persistence_healthy = false;
        }
        let report = std::sync::Arc::new(RefreshReport {
            outcome,
            coalesced: false,
            next_eligible_unix: next_eligible,
            suppression_until_unix: suppression,
        });
        guard.completed = Some((generation, std::sync::Arc::clone(&report)));
        guard.in_flight = None;
        self.cv.notify_all();
        RefreshReport {
            outcome: report.outcome.clone(),
            coalesced: false,
            next_eligible_unix: report.next_eligible_unix,
            suppression_until_unix: report.suppression_until_unix,
        }
    }
}

/// Whether a fetched `Changed` revision may be adopted.
enum RevisionVerdict {
    /// The revision is usable AND, with a wired cache, DURABLY stored
    /// (a store failure refuses the revision — see below).
    Adopted,
    /// The revision is not adopted — the body failed the live catalog
    /// model, or the durable cache could not retain it: nothing
    /// adopted, stored, or anchored; the refresh reports failure.
    Unusable(String),
}

/// Writes one fetched revision through the wired catalog cache
/// (FR-10/FR-13B/FR-13E).
///
/// S6's sec discipline, applied on the WRITE side: the body is
/// validated against the live catalog model BEFORE anything may land
/// in the root-owned cache location — a drifted or garbage body must
/// never poison the cache (the loader's strict re-parse would then
/// fail every future boot until the file is removed by hand). A body
/// that fails validation is [`RevisionVerdict::Unusable`]: the refresh
/// reports `Failed` naming the drift, the last good cache survives,
/// and no etag or age anchor advances. A cache WRITE I/O failure is
/// the same verdict (Codex PR#4 round 2, tightening the round-1 fix):
/// the daemon's client-visible read path serves from the DURABLE
/// store, so adopting a revision only in memory would report
/// `Changed` while clients keep the old catalog — a split world. The
/// old durable revision keeps serving, the conditional etag keeps
/// naming what the disk actually retains, and the next eligible
/// window re-attempts the whole fetch-and-store (the filesystem may
/// heal).
fn adopt_fetched_revision(
    cache: &mut Option<CacheState>,
    etag: &Option<String>,
    body: &[u8],
    fetched_unix: u64,
) -> RevisionVerdict {
    if let Err(error) = CatalogDocument::from_bytes(body) {
        return RevisionVerdict::Unusable(format!(
            "fetched catalog body rejected by the live model (drift fails loudly): {error}"
        ));
    }
    let Some(state) = cache else {
        return RevisionVerdict::Adopted; // no cache wired (test schedulers)
    };
    // JSON is UTF-8 by specification and the model parse above already
    // consumed these bytes, so the conversion cannot fail for a
    // validated body; the arm stays a hard refusal anyway — never a
    // panic, never a lossy rewrite of what gets persisted.
    let text = match std::str::from_utf8(body) {
        Ok(text) => text.to_owned(),
        Err(_) => {
            return RevisionVerdict::Unusable("fetched catalog body is not valid UTF-8".to_owned());
        }
    };
    let doc = CachedCatalog {
        schema_version: CACHE_SCHEMA_VERSION,
        etag: etag.clone(),
        fetched_unix,
        body: text,
    };
    if let Err(error) = state.cache.store(&doc) {
        // Codex PR#4 round 2 (P2): a revision the CLIENT-VISIBLE cache
        // does not durably retain is not adopted. The daemon's read
        // path (`ServersList`) serves from the durable store, so an
        // in-memory-only adoption reports `Changed` while clients keep
        // seeing the old catalog until some later write-through — a
        // split world. Refuse the revision: the failure path resets
        // the window, the old durable revision keeps serving, and the
        // next eligible refresh re-attempts (the filesystem may heal).
        return RevisionVerdict::Unusable(format!(
            "persisting the fetched catalog revision failed (clients keep the last durable \
             catalog; the next window retries): {error}"
        ));
    }
    state.current = Some(doc);
    RevisionVerdict::Adopted
}

/// Mints one confirmation token: 32 CSPRNG bytes, hex-encoded
/// (single-use, expiring; see [`PendingToken`]). Never derived from
/// anything caller-controlled or hash-seeded. `None` when the CSPRNG
/// fails — fail-closed (rust M4/sec F1): no token means no ceremony
/// means no early manual refresh; the pre-fix shape returned an EMPTY
/// string, which a caller could "redeem" by echoing `""` back,
/// converting a broken RNG into a confirmation bypass.
fn mint_confirmation_token() -> Option<String> {
    mint_confirmation_token_from(|bytes| getrandom::getrandom(bytes).is_ok())
}

/// The mint over an injectable fill (`true` = the bytes were filled).
/// The seam exists for the forced-failure arm the OS CSPRNG cannot
/// produce on demand in a test.
fn mint_confirmation_token_from(fill: impl FnOnce(&mut [u8; 32]) -> bool) -> Option<String> {
    let mut bytes = [0u8; 32];
    if !fill(&mut bytes) {
        return None;
    }
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Test-support: a deterministic scenario generator for the property
/// suites (a plain xorshift LCG — NOT the product jitter source, which
/// is [`draw_jitter`] above; test-only per the std-hash-seeding ban's
/// scope, which governs product randomness).
#[cfg(test)]
pub(crate) mod testkit {
    /// Fixed-seed xorshift LCG.
    pub(crate) struct ScenarioRng(u64);

    impl ScenarioRng {
        /// A fixed seed keeps property failures reproducible.
        pub(crate) fn new(seed: u64) -> Self {
            Self(seed.wrapping_mul(6364136223846793005).wrapping_add(1))
        }

        pub(crate) fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        /// A value in `low..=high`.
        pub(crate) fn between(&mut self, low: u64, high: u64) -> u64 {
            if high <= low {
                return low;
            }
            low + self.next_u64() % (high - low + 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- T-25: the three-hour floor ----------------------------------------

    #[test]
    fn configuration_below_the_floor_is_rejected() {
        for seconds in [0u64, 1, 3600, FRESHNESS_FLOOR_SECONDS - 1] {
            let err =
                SchedulerConfig::new(seconds, 0, true).expect_err("below the floor must fail");
            assert!(
                err.to_string().contains("three-hour floor"),
                "{err} for {seconds}s"
            );
        }
        // The exact floor is accepted; so is everything above it.
        assert!(SchedulerConfig::new(FRESHNESS_FLOOR_SECONDS, 0, true).is_ok());
        assert!(SchedulerConfig::new(FRESHNESS_FLOOR_SECONDS + 1, 600, false).is_ok());
    }

    /// rust M2: draw_jitter(u64::MAX) overflows (`max_seconds + 1`
    /// wraps to 0, then `% range` divides by zero) and it runs while
    /// the leader HOLDS the lock — the panic would poison the mutex and
    /// wedge every joiner. The floor's "never constructible below the
    /// floor" defense applies to the ceiling too: the config must never
    /// be constructible with the overflow value.
    #[test]
    fn jitter_ceiling_is_validated_like_the_floor() {
        let err = SchedulerConfig::new(FRESHNESS_FLOOR_SECONDS, u64::MAX, true)
            .expect_err("the overflow ceiling must be rejected like a sub-floor interval");
        assert!(
            err.to_string().contains("jitter ceiling"),
            "the error must name the ceiling: {err}"
        );
        // Everything strictly below the overflow point stays
        // constructible, and the largest safe ceiling draws safely
        // (range = u64::MAX, limit = u64::MAX — every draw accepted).
        let config = SchedulerConfig::new(FRESHNESS_FLOOR_SECONDS, u64::MAX - 1, true)
            .expect("u64::MAX - 1 does not overflow the range");
        assert_eq!(config.max_positive_jitter_seconds, u64::MAX - 1);
        assert!(draw_jitter(u64::MAX - 1) < u64::MAX);
    }

    #[test]
    fn metadata_cache_section_maps_and_revalidates_the_floor() {
        let mut section = MetadataCacheSection::default();
        assert_eq!(section.refresh_interval_hours, 3);
        let config = SchedulerConfig::from_metadata_cache(&section).unwrap();
        assert_eq!(config.refresh_interval_seconds, FRESHNESS_FLOOR_SECONDS);
        assert_eq!(config.max_positive_jitter_seconds, 600);
        assert!(config.conditional_requests);

        // A hand-built section (the IPC path) cannot sneak past.
        section.refresh_interval_hours = 1;
        assert!(SchedulerConfig::from_metadata_cache(&section).is_err());
    }

    // --- FR-13D: greatest-of composition -----------------------------------

    fn base_inputs() -> DeadlineInputs {
        DeadlineInputs {
            last_request_unix: Some(1_771_000_000),
            now_unix: 1_771_000_010,
            configured_interval_seconds: FRESHNESS_FLOOR_SECONDS,
            proton_lifetime_seconds: None,
            rate_limited: false,
            retry_after_seconds: None,
            jitter_seconds: 0,
        }
    }

    #[test]
    fn configured_interval_above_the_floor_wins() {
        let inputs = DeadlineInputs {
            configured_interval_seconds: FRESHNESS_FLOOR_SECONDS * 2,
            ..base_inputs()
        };
        let deadline = next_deadline(&inputs);
        assert_eq!(
            deadline.next_eligible_unix,
            inputs.last_request_unix.unwrap() + FRESHNESS_FLOOR_SECONDS * 2
        );
        assert_eq!(deadline.source, IntervalSource::Configured);
    }

    #[test]
    fn the_floor_wins_when_the_interval_does_not_exceed_it() {
        for interval in [0u64, 3600, FRESHNESS_FLOOR_SECONDS] {
            let inputs = DeadlineInputs {
                configured_interval_seconds: interval,
                ..base_inputs()
            };
            let deadline = next_deadline(&inputs);
            assert_eq!(
                deadline.next_eligible_unix,
                inputs.last_request_unix.unwrap() + FRESHNESS_FLOOR_SECONDS,
                "interval {interval}s must not undercut the floor"
            );
            assert_eq!(deadline.source, IntervalSource::ThreeHourFloor);
        }
    }

    #[test]
    fn proton_lifetime_wins_when_it_is_the_greatest() {
        let inputs = DeadlineInputs {
            proton_lifetime_seconds: Some(FRESHNESS_FLOOR_SECONDS * 3),
            ..base_inputs()
        };
        let deadline = next_deadline(&inputs);
        assert_eq!(
            deadline.next_eligible_unix,
            inputs.last_request_unix.unwrap() + FRESHNESS_FLOOR_SECONDS * 3
        );
        assert_eq!(deadline.source, IntervalSource::ProtonLifetime);
        // A lifetime below the floor changes nothing.
        let inputs = DeadlineInputs {
            proton_lifetime_seconds: Some(60),
            ..base_inputs()
        };
        assert_eq!(
            next_deadline(&inputs).source,
            IntervalSource::ThreeHourFloor
        );
    }

    /// Spike memo Q4's greatest-of contract: a `Retry-After` observed at
    /// `now` competes with (and here beats) the floor; the suppression
    /// floor records the un-jittered greatest-of for the manual path.
    #[test]
    fn retry_after_wins_the_greatest_of_against_the_floor() {
        let inputs = DeadlineInputs {
            rate_limited: true,
            retry_after_seconds: Some(FRESHNESS_FLOOR_SECONDS * 2),
            ..base_inputs()
        };
        let deadline = next_deadline(&inputs);
        assert_eq!(
            deadline.next_eligible_unix,
            inputs.now_unix + FRESHNESS_FLOOR_SECONDS * 2
        );
        assert_eq!(deadline.source, IntervalSource::RetryAfter);
        assert_eq!(
            deadline.suppression_until_unix,
            Some(inputs.now_unix + FRESHNESS_FLOOR_SECONDS * 2),
            "the suppression floor is the greatest-of WITHOUT jitter"
        );
        // A Retry-After already inside the floor's window loses, but the
        // suppression floor still pins to the floor: a 429 never
        // *shortens* the suppression below the greatest-of.
        let inputs = DeadlineInputs {
            rate_limited: true,
            retry_after_seconds: Some(60),
            ..base_inputs()
        };
        let deadline = next_deadline(&inputs);
        assert_eq!(deadline.source, IntervalSource::ThreeHourFloor);
        assert_eq!(
            deadline.suppression_until_unix,
            Some(inputs.last_request_unix.unwrap() + FRESHNESS_FLOOR_SECONDS)
        );
        // Without any Retry-After there is no suppression floor at all.
        assert_eq!(next_deadline(&base_inputs()).suppression_until_unix, None);
    }

    /// qa P1-1 (the documented Q4 contract): a rate limit WITHOUT a
    /// `Retry-After` delay — `RateLimited { retry_after_seconds: None }`
    /// — still suppresses to the un-jittered greatest-of floor. The
    /// delay is optional; the rate limit itself is not.
    #[test]
    fn a_rate_limit_without_retry_after_still_pins_the_floor_suppression() {
        let inputs = DeadlineInputs {
            rate_limited: true,
            retry_after_seconds: None,
            ..base_inputs()
        };
        let deadline = next_deadline(&inputs);
        assert_eq!(
            deadline.suppression_until_unix,
            Some(inputs.last_request_unix.unwrap() + FRESHNESS_FLOOR_SECONDS),
            "None must suppress to the un-jittered greatest-of floor"
        );
        assert_eq!(deadline.source, IntervalSource::ThreeHourFloor);
        // The suppression is the floor WITHOUT jitter: eligibility may
        // sit above it by the drawn jitter, never below.
        assert!(deadline.next_eligible_unix >= deadline.suppression_until_unix.unwrap());

        // A configured interval above the floor raises the None-case
        // suppression with it (still the greatest-of).
        let inputs = DeadlineInputs {
            rate_limited: true,
            retry_after_seconds: None,
            configured_interval_seconds: FRESHNESS_FLOOR_SECONDS * 2,
            ..base_inputs()
        };
        assert_eq!(
            next_deadline(&inputs).suppression_until_unix,
            Some(inputs.last_request_unix.unwrap() + FRESHNESS_FLOOR_SECONDS * 2)
        );
    }

    #[test]
    fn bootstrap_without_a_last_request_is_due_from_now() {
        let inputs = DeadlineInputs {
            last_request_unix: None,
            ..base_inputs()
        };
        let deadline = next_deadline(&inputs);
        assert_eq!(
            deadline.next_eligible_unix,
            inputs.now_unix + FRESHNESS_FLOOR_SECONDS
        );
    }

    #[test]
    fn hostile_values_saturate_instead_of_overflowing_into_the_past() {
        let inputs = DeadlineInputs {
            rate_limited: true,
            retry_after_seconds: Some(u64::MAX),
            proton_lifetime_seconds: Some(u64::MAX),
            jitter_seconds: u64::MAX,
            ..base_inputs()
        };
        let deadline = next_deadline(&inputs);
        assert_eq!(deadline.next_eligible_unix, u64::MAX);
        assert_eq!(deadline.suppression_until_unix, Some(u64::MAX));
    }

    /// rust M4/sec F1, mint side: a failed CSPRNG mints NOTHING — not
    /// the empty string the fail-open shape returned, which was
    /// matchable by echoing "" back into the redeem arm.
    #[test]
    fn a_failed_csprng_mint_mints_nothing() {
        assert_eq!(mint_confirmation_token_from(|_| false), None);
        let token = mint_confirmation_token_from(|_| true).expect("a healthy fill mints");
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!token.is_empty());
        // The production mint delegates to the OS CSPRNG.
        let minted = mint_confirmation_token().expect("the OS CSPRNG is available");
        assert_eq!(minted.len(), 64);
    }

    // --- FR-13D: jitter is additive-only ------------------------------------

    #[test]
    fn jitter_only_ever_delays_and_stays_within_the_ceiling() {
        let raw = next_deadline(&base_inputs());
        for jitter in [0u64, 1, 60, 600, 100_000] {
            let inputs = DeadlineInputs {
                jitter_seconds: jitter,
                ..base_inputs()
            };
            let deadline = next_deadline(&inputs);
            assert_eq!(
                deadline.next_eligible_unix,
                raw.next_eligible_unix + jitter,
                "jitter must be exactly additive"
            );
            assert!(
                deadline.next_eligible_unix
                    >= inputs.last_request_unix.unwrap() + FRESHNESS_FLOOR_SECONDS,
                "jitter must never beat the three-hour floor"
            );
        }
    }

    #[test]
    fn drawn_jitter_stays_in_the_inclusive_range() {
        for ceiling in [0u64, 1, 7, 600] {
            for _ in 0..64 {
                let value = draw_jitter(ceiling);
                assert!(value <= ceiling, "{value} > {ceiling}");
            }
        }
    }

    // --- Property suites (E2E-22 class, pure layer) -------------------------

    use testkit::ScenarioRng;

    /// FR-13D composition property over many random inputs: the floor
    /// always participates, every component can only push eligibility
    /// further out, and jitter is additive-only.
    #[test]
    fn property_greatest_of_composition_holds_over_random_inputs() {
        let mut rng = ScenarioRng::new(0x5EED_0001);
        for _ in 0..2_000 {
            let last_request = rng.between(1_700_000_000, 1_800_000_000);
            let now = last_request + rng.between(0, 7_200);
            let interval = rng.between(0, FRESHNESS_FLOOR_SECONDS * 4);
            let lifetime = (rng.next_u64().is_multiple_of(4))
                .then(|| rng.between(0, FRESHNESS_FLOOR_SECONDS * 4));
            // A rate limit arrives with or without a Retry-After delay
            // (Q4); a delay never arrives without a rate limit.
            let rate_limited = rng.next_u64().is_multiple_of(3);
            let retry_after = rate_limited
                .then(|| rng.between(1, FRESHNESS_FLOOR_SECONDS * 6))
                .filter(|_| rng.next_u64().is_multiple_of(2));
            let jitter = rng.between(0, 600);
            let inputs = DeadlineInputs {
                last_request_unix: Some(last_request),
                now_unix: now,
                configured_interval_seconds: interval,
                proton_lifetime_seconds: lifetime,
                rate_limited,
                retry_after_seconds: retry_after,
                jitter_seconds: jitter,
            };
            let deadline = next_deadline(&inputs);

            // The floor always participates (FR-12).
            assert!(
                deadline.next_eligible_unix >= last_request + FRESHNESS_FLOOR_SECONDS,
                "floor violated for {inputs:?}"
            );
            // No component is ever dropped from the greatest-of.
            assert!(
                deadline.next_eligible_unix >= last_request + interval,
                "configured interval dropped for {inputs:?}"
            );
            if let Some(lifetime) = lifetime {
                assert!(
                    deadline.next_eligible_unix >= last_request + lifetime,
                    "proton lifetime dropped for {inputs:?}"
                );
            }
            if let Some(retry_after) = retry_after {
                assert!(
                    deadline.next_eligible_unix >= now + retry_after,
                    "retry-after dropped for {inputs:?}"
                );
            }
            if rate_limited {
                // Q4: EVERY rate limit pins a suppression floor — with a
                // delay it is at least now+Retry-After, without one it is
                // still the greatest-of floor; never below either.
                let suppression = deadline
                    .suppression_until_unix
                    .expect("a rate limit always pins a suppression floor");
                let delay_floor = retry_after.map_or(0, |delay| now + delay);
                assert!(
                    suppression >= delay_floor.max(last_request + FRESHNESS_FLOOR_SECONDS),
                    "suppression floor below the greatest-of for {inputs:?}"
                );
            } else {
                assert_eq!(
                    deadline.suppression_until_unix, None,
                    "no rate limit must not mint a suppression for {inputs:?}"
                );
            }
            // Jitter is additive-only (FR-13D non-negative).
            let unjittered = next_deadline(&DeadlineInputs {
                jitter_seconds: 0,
                ..inputs
            });
            assert!(deadline.next_eligible_unix >= unjittered.next_eligible_unix);
            assert!(
                deadline.next_eligible_unix - unjittered.next_eligible_unix <= jitter,
                "jitter exceeded its draw for {inputs:?}"
            );
        }
    }

    /// The winner label names a component whose time IS the greatest-of,
    /// and the raw (un-jittered) deadline equals that greatest time —
    /// cross-checked against an independent max over all candidate
    /// times, not a replay of the implementation's branch order.
    #[test]
    fn property_source_names_the_actual_winner() {
        let mut rng = ScenarioRng::new(0x5EED_0002);
        for _ in 0..2_000 {
            let last_request = 1_771_000_000u64;
            let now = last_request + rng.between(0, 60);
            let interval = rng.between(FRESHNESS_FLOOR_SECONDS, FRESHNESS_FLOOR_SECONDS * 2);
            let lifetime = (rng.next_u64().is_multiple_of(3))
                .then(|| rng.between(0, FRESHNESS_FLOOR_SECONDS * 3));
            let rate_limited = rng.next_u64().is_multiple_of(3);
            let retry_after = rate_limited
                .then(|| rng.between(1, FRESHNESS_FLOOR_SECONDS * 3))
                .filter(|_| rng.next_u64().is_multiple_of(2));
            let inputs = DeadlineInputs {
                last_request_unix: Some(last_request),
                now_unix: now,
                configured_interval_seconds: interval,
                proton_lifetime_seconds: lifetime,
                rate_limited,
                retry_after_seconds: retry_after,
                jitter_seconds: 0,
            };
            let deadline = next_deadline(&inputs);
            let mut candidates = vec![
                (last_request + interval, IntervalSource::Configured),
                (
                    last_request + FRESHNESS_FLOOR_SECONDS,
                    IntervalSource::ThreeHourFloor,
                ),
            ];
            if let Some(lifetime) = lifetime {
                candidates.push((last_request + lifetime, IntervalSource::ProtonLifetime));
            }
            if let Some(retry_after) = retry_after {
                candidates.push((now + retry_after, IntervalSource::RetryAfter));
            }
            let greatest = candidates.iter().map(|(unix, _)| *unix).max().unwrap();
            assert_eq!(
                deadline.next_eligible_unix, greatest,
                "deadline is not the greatest-of for {inputs:?}"
            );
            let labeled = candidates
                .iter()
                .find(|(_, source)| *source == deadline.source)
                .unwrap();
            assert_eq!(
                labeled.0, greatest,
                "label names a non-winning component for {inputs:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime suite: single-flight, rollback, suppression, manual override —
// driven on virtual clocks (E2E-22's virtual-clock harness is normative)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod runtime_tests {
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;

    use super::*;
    use protonwire_store::deadlines::{DeadlineStore, SchedulerDeadlines};
    use testkit::ScenarioRng;

    const T0: u64 = 1_771_000_000;
    /// The default jitter ceiling used across the suite (10 min, the
    /// config default).
    const JITTER: u64 = 600;

    // --- fixtures -----------------------------------------------------------

    /// Scripted fetch service: responses pop in order, the LAST repeats
    /// forever. Counts every invocation and RECORDS the ETag each one
    /// received (the FR-13E pass-through pin); can gate its first
    /// invocation until released (the single-flight race pin).
    #[derive(Clone)]
    struct FakeFetch(Arc<FetchInner>);

    struct FetchInner {
        calls: AtomicU64,
        seen: StdMutex<Vec<Option<String>>>,
        script: StdMutex<VecDeque<Result<FetchOutcome, FetchFailure>>>,
        repeat: Result<FetchOutcome, FetchFailure>,
        started: Option<mpsc::Sender<()>>,
        release: StdMutex<Option<mpsc::Receiver<()>>>,
    }

    impl FakeFetch {
        /// `script`'s last entry is the repeating fallback.
        fn new(script: Vec<Result<FetchOutcome, FetchFailure>>) -> Self {
            let mut script: VecDeque<_> = script.into();
            let repeat = script.pop_back().expect("at least one scripted response");
            Self(Arc::new(FetchInner {
                calls: AtomicU64::new(0),
                seen: StdMutex::new(Vec::new()),
                script: StdMutex::new(script),
                repeat,
                started: None,
                release: StdMutex::new(None),
            }))
        }

        /// Gates the first invocation: the fetch signals `started`, then
        /// blocks until [`Gate::release`]. Deterministic single-flight
        /// racing — while the gate holds, every additional caller must
        /// park.
        fn gated(mut self) -> (Self, mpsc::Receiver<()>, Gate) {
            let (started_tx, started_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let inner = Arc::get_mut(&mut self.0).expect("gated before any clone");
            inner.started = Some(started_tx);
            *inner.release.lock().unwrap() = Some(release_rx);
            (self, started_rx, Gate { tx: release_tx })
        }

        fn calls(&self) -> u64 {
            self.0.calls.load(Ordering::SeqCst)
        }

        /// The ETag each invocation received, in order (None = the
        /// request went out unconditional).
        fn seen_etags(&self) -> Vec<Option<String>> {
            self.0.seen.lock().unwrap().clone()
        }

        fn service(&self) -> CatalogFetch {
            let inner = Arc::clone(&self.0);
            Arc::new(move |etag| inner.invoke(etag))
        }
    }

    /// Releases the gated fetch.
    struct Gate {
        tx: mpsc::Sender<()>,
    }

    impl Gate {
        fn release(self) {
            let _ = self.tx.send(());
        }
    }

    impl FetchInner {
        fn invoke(&self, etag: Option<&str>) -> Result<FetchOutcome, FetchFailure> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().unwrap().push(etag.map(str::to_owned));
            if let Some(started) = &self.started
                && let Some(release) = self.release.lock().unwrap().take()
            {
                let _ = started.send(());
                let _ = release.recv();
            }
            self.script
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| self.repeat.clone())
        }
    }

    fn not_modified() -> Result<FetchOutcome, FetchFailure> {
        Ok(FetchOutcome::NotModified)
    }

    fn rate_limited(retry_after_seconds: Option<u64>) -> Result<FetchOutcome, FetchFailure> {
        Err(FetchFailure::RateLimited {
            retry_after_seconds,
        })
    }

    /// A scheduler over a temp deadline store, on the given clock.
    fn harness(clock: &VirtualClock, fetch: &FakeFetch) -> (Arc<Scheduler>, tempfile::TempDir) {
        harness_with_config(
            clock,
            fetch,
            SchedulerConfig::new(FRESHNESS_FLOOR_SECONDS, JITTER, true)
                .expect("the standard suite config is valid"),
        )
    }

    /// [`harness`] over an explicit policy (the conditional-requests
    /// arms).
    fn harness_with_config(
        clock: &VirtualClock,
        fetch: &FakeFetch,
        config: SchedulerConfig,
    ) -> (Arc<Scheduler>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let scheduler = Scheduler::new(
            config,
            Arc::new(clock.clone()),
            fetch.service(),
            DeadlineStore::new(dir.path().join("deadlines.json")),
            SchedulerDeadlines::default(),
            None,
        );
        (Arc::new(scheduler), dir)
    }

    /// A scheduler seeded as if a fetch completed at `last_request`
    /// (restart-style: no bootstrap call).
    fn seeded(
        clock: &VirtualClock,
        fetch: &FakeFetch,
        last_request: u64,
    ) -> (Arc<Scheduler>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let persisted = SchedulerDeadlines {
            last_request_unix: Some(last_request),
            last_success_unix: Some(last_request),
            next_eligible_unix: Some(last_request + FRESHNESS_FLOOR_SECONDS),
            next_eligible_source: Some(IntervalSource::ThreeHourFloor),
            wall_high_water_unix: last_request,
            ..SchedulerDeadlines::default()
        };
        let scheduler = Scheduler::new(
            SchedulerConfig::new(FRESHNESS_FLOOR_SECONDS, JITTER, true).unwrap(),
            Arc::new(clock.clone()),
            fetch.service(),
            DeadlineStore::new(dir.path().join("deadlines.json")),
            persisted,
            None,
        );
        (Arc::new(scheduler), dir)
    }

    /// Test-only restart: reads the persisted document directly (the
    /// strict fs_trust walk is root-runner territory — the store's own
    /// suite proves that arm; here we prove the SCHEDULER consumes the
    /// persisted state).
    fn restart(clock: &VirtualClock, fetch: &FakeFetch, dir: &tempfile::TempDir) -> Arc<Scheduler> {
        let bytes = std::fs::read(dir.path().join("deadlines.json")).unwrap();
        let persisted: SchedulerDeadlines = serde_json::from_slice(&bytes).unwrap();
        let scheduler = Scheduler::new(
            SchedulerConfig::new(FRESHNESS_FLOOR_SECONDS, JITTER, true).unwrap(),
            Arc::new(clock.clone()),
            fetch.service(),
            DeadlineStore::new(dir.path().join("deadlines.json")),
            persisted,
            None,
        );
        Arc::new(scheduler)
    }

    /// The rollback-clamped effective time, as the test computes it.
    fn effective_now(clock: &VirtualClock, scheduler: &Scheduler) -> u64 {
        clock
            .now_unix()
            .max(scheduler.persisted().wall_high_water_unix)
    }

    // --- T-25: single-flight --------------------------------------------------

    /// N racing callers at one eligibility window coalesce to exactly
    /// one fetch; joiners receive the leader's result with
    /// `coalesced: true` (T-25). The gated fetch makes the race
    /// deterministic in the important direction: while the gate holds,
    /// every additional caller MUST park — no caller can complete
    /// before the release, so no second fetch can start.
    #[test]
    fn single_flight_coalesces_racing_callers() {
        let clock = VirtualClock::new(T0);
        let (fetch, started, gate) = FakeFetch::new(vec![not_modified()]).gated();
        let (scheduler, _dir) = harness(&clock, &fetch);

        const RACERS: usize = 8;
        let (results_tx, results_rx) = mpsc::channel();
        let mut handles = Vec::new();
        for _ in 0..RACERS {
            let scheduler = Arc::clone(&scheduler);
            let results_tx = results_tx.clone();
            handles.push(std::thread::spawn(move || {
                results_tx.send(scheduler.refresh_automatic()).unwrap();
            }));
        }
        // Deterministic park point: the leader is inside the gated fetch
        // (calls == 1, started signaled); while the gate holds, every
        // other racer can only park — none can complete, none can fetch.
        started
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the leader must reach the fetch");
        // Race-settle note (the F5 discipline): this 200 ms sleep is
        // NOT the correctness anchor — the `started` signal above is.
        // While the gate holds, no additional fetch can begin, so
        // `calls() == 1` holds at any sleep length including zero; the
        // sleep only gives the losing racers time to REACH the condvar
        // so the joiner arm below is exercised (without it they could
        // straggle past completion and the joiner-count assert would
        // flake on scheduling, not on behavior).
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(fetch.calls(), 1, "the leader must be the only fetcher");
        gate.release();

        // Counted receive (Receiver::iter would block: the last sender
        // clone only drops when every racer thread exits).
        let outcomes: Vec<AutomaticOutcome> = (0..RACERS)
            .map(|_| {
                results_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("every racer must resolve")
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(fetch.calls(), 1, "single-flight: exactly one fetch");
        let mut leaders = 0;
        let mut joiners = 0;
        let mut stragglers = 0;
        for outcome in &outcomes {
            match outcome {
                AutomaticOutcome::Due(report) => {
                    assert!(matches!(report.outcome, RefreshOutcome::NotModified));
                    if report.coalesced {
                        joiners += 1;
                    } else {
                        leaders += 1;
                    }
                }
                AutomaticOutcome::NotDue { .. } => {
                    // A racer that arrived after completion sees the
                    // reset deadline — correct single-flight behavior;
                    // the herd still never happens (fetch count above).
                    stragglers += 1;
                }
            }
        }
        assert_eq!(
            leaders, 1,
            "exactly one non-coalesced leader ({joiners} joiners, {stragglers} stragglers)"
        );
        assert!(
            joiners >= 1,
            "at least one racer must have joined the in-flight refresh \
             ({stragglers} arrived after completion)"
        );
    }

    /// qa P1-2 (the prescribed shape): the MANUAL door's single-flight
    /// join. A manual caller presenting a token while an AUTOMATIC
    /// refresh is in flight joins it — exactly ONE fetch,
    /// `coalesced: true` — never a second request. Deleting the manual
    /// door's join block left 57/57 tests green; this pin kills that
    /// deletion (verified by running it).
    ///
    /// Counter semantics DECIDED and pinned (FR-13I): the LEADER's kind
    /// owns the counter — the manual joiner added no upstream request
    /// and overrode no interval, so `manual_refresh_count` does not
    /// move for a join.
    #[test]
    fn a_manual_caller_joins_an_in_flight_automatic_refresh() {
        let clock = VirtualClock::new(T0);
        let (fetch, started, gate) = FakeFetch::new(vec![not_modified()]).gated();
        let (scheduler, _dir) = seeded(&clock, &fetch, T0);

        // Mint a ceremony while the window is shut, so the joiner has
        // an outstanding token to present.
        clock.set_wall(T0 + 60);
        let requirement = match scheduler.refresh_manual(None) {
            ManualOutcome::ConfirmationRequired(requirement) => requirement,
            other => panic!("the early manual request must mint a ceremony: {other:?}"),
        };
        assert_eq!(fetch.calls(), 0);

        // Open the window; the automatic leader parks inside the gate.
        clock.set_wall(T0 + FRESHNESS_FLOOR_SECONDS + JITTER + 1);
        let leader = std::thread::spawn({
            let scheduler = Arc::clone(&scheduler);
            move || scheduler.refresh_automatic()
        });
        started
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the leader must reach the fetch");
        assert_eq!(fetch.calls(), 1);

        // The manual caller presents the token and must JOIN the
        // in-flight refresh (the token is not what opens this window —
        // the automatic leader's eligibility did).
        let joiner = std::thread::spawn({
            let scheduler = Arc::clone(&scheduler);
            let token = requirement.confirmation_token.clone();
            move || scheduler.refresh_manual(Some(&token))
        });
        // Park-settle (the racing test's idiom): give the joiner time
        // to reach the condvar BEFORE the release — the correctness
        // anchor is the gate (no second fetch can start while it
        // holds); this only ensures the join arm is the one exercised.
        std::thread::sleep(std::time::Duration::from_millis(200));
        gate.release();

        match leader.join().unwrap() {
            AutomaticOutcome::Due(report) => assert!(!report.coalesced, "the automatic led"),
            other => panic!("the open window must be due for the automatic door: {other:?}"),
        }
        match joiner.join().unwrap() {
            ManualOutcome::Refreshed(report) => {
                assert!(report.coalesced, "the manual caller must join, not lead");
                assert!(matches!(report.outcome, RefreshOutcome::NotModified));
            }
            other => panic!("the manual caller must join the in-flight refresh: {other:?}"),
        }
        assert_eq!(fetch.calls(), 1, "single-flight spans BOTH doors");

        // The leader's kind owns the counter (the decision, pinned).
        let diagnostics = scheduler.diagnostics();
        assert_eq!(diagnostics.automatic_refresh_count, 1);
        assert_eq!(
            diagnostics.manual_refresh_count, 0,
            "a join overrode nothing and caused no request"
        );
    }

    /// rust L1 (DECIDED + pinned): a JOIN does not burn the presented
    /// token. The join consumed an already-running window, not the
    /// ceremony — and a live outstanding token can only PREDATE the
    /// lead (ceremonies cannot be minted while a refresh is in flight,
    /// and a manual LEAD burns its token at redeem), so the surviving
    /// token has authorized nothing yet and still buys exactly its one
    /// later early refresh. Burning on join would charge the user a
    /// confirmation for a refresh that was already happening. (Times
    /// stay inside the 300 s token TTL: mint just before the window
    /// opens, join just after, replay while still live.)
    #[test]
    fn a_join_does_not_burn_the_outstanding_token() {
        let clock = VirtualClock::new(T0);
        let (fetch, started, gate) = FakeFetch::new(vec![not_modified(), not_modified()]).gated();
        let (scheduler, _dir) = seeded(&clock, &fetch, T0);
        let open = T0 + FRESHNESS_FLOOR_SECONDS; // the seeded window

        // Mint inside the TTL horizon of everything that follows.
        clock.set_wall(open - 60);
        let requirement = match scheduler.refresh_manual(None) {
            ManualOutcome::ConfirmationRequired(requirement) => requirement,
            other => panic!("expected a ceremony, got {other:?}"),
        };
        // The automatic leader opens the window; the token is still
        // live (minted 61 s ago, TTL 300 s).
        clock.set_wall(open + 1);
        let leader = std::thread::spawn({
            let scheduler = Arc::clone(&scheduler);
            move || scheduler.refresh_automatic()
        });
        started
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the leader must reach the fetch");
        let joiner = std::thread::spawn({
            let scheduler = Arc::clone(&scheduler);
            let token = requirement.confirmation_token.clone();
            move || scheduler.refresh_manual(Some(&token))
        });
        // Park-settle before the release (the racing test's idiom).
        std::thread::sleep(std::time::Duration::from_millis(200));
        gate.release();
        assert!(matches!(leader.join().unwrap(), AutomaticOutcome::Due(_)));
        assert!(matches!(
            joiner.join().unwrap(),
            ManualOutcome::Refreshed(RefreshReport {
                coalesced: true,
                ..
            })
        ));
        assert_eq!(fetch.calls(), 1);

        // The window is future again; the SAME token still authorizes
        // exactly one early refresh (the ceremony was never consumed,
        // and it has not expired: minted at open-60, redeemed at
        // open+120, TTL 300).
        clock.set_wall(open + 120);
        match scheduler.refresh_manual(Some(&requirement.confirmation_token)) {
            ManualOutcome::Refreshed(report) => assert!(!report.coalesced),
            other => panic!("the token around a join must still redeem once: {other:?}"),
        }
        assert_eq!(fetch.calls(), 2);
        assert_eq!(scheduler.diagnostics().manual_refresh_count, 1);

        // And is then dead for good — one ceremony, one redemption.
        match scheduler.refresh_manual(Some(&requirement.confirmation_token)) {
            ManualOutcome::ConfirmationRequired(_) => {}
            other => panic!("after its one redemption the token is dead: {other:?}"),
        }
        assert_eq!(fetch.calls(), 2);
    }

    // --- T-26: floor, jitter window, rollback, restart ------------------------

    #[test]
    fn bootstrap_is_due_immediately_then_the_floor_governs() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![not_modified()]);
        let (scheduler, _dir) = harness(&clock, &fetch);

        // FR-13F: no recorded request -> immediately due.
        let report = match scheduler.refresh_automatic() {
            AutomaticOutcome::Due(report) => report,
            other => panic!("bootstrap must be due, got {other:?}"),
        };
        assert!(!report.coalesced);
        assert!(matches!(report.outcome, RefreshOutcome::NotModified));
        assert_eq!(fetch.calls(), 1);

        // FR-12/FR-13D: the next window is [floor, floor + jitter].
        let next = scheduler.next_due_unix().unwrap();
        assert!(
            (T0 + FRESHNESS_FLOOR_SECONDS..=T0 + FRESHNESS_FLOOR_SECONDS + JITTER).contains(&next),
            "next {next} outside the floor+jitter window"
        );
        assert_eq!(
            scheduler.persisted().next_eligible_source,
            Some(IntervalSource::ThreeHourFloor)
        );

        // One second before: not due. At the deadline: due, one fetch.
        clock.set_wall(next - 1);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::NotDue { .. }
        ));
        clock.set_wall(next);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
        assert_eq!(fetch.calls(), 2);
    }

    /// T-26's rollback guard: a wall clock that jumps backward — even
    /// past the eligibility deadline, even repeatedly, even across a
    /// restart — must not produce a refetch storm.
    #[test]
    fn rollback_never_triggers_a_refetch_storm() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![not_modified()]);
        let (scheduler, dir) = harness(&clock, &fetch);

        // Bootstrap at T0, then let the first window pass and refresh.
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
        clock.advance_secs(FRESHNESS_FLOOR_SECONDS + JITTER + 60);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
        assert_eq!(fetch.calls(), 2);
        let second_window = scheduler.next_due_unix().unwrap();
        assert!(
            second_window >= T0 + FRESHNESS_FLOOR_SECONDS + JITTER + 60 + FRESHNESS_FLOOR_SECONDS
        );

        // Roll the wall back to just after the very first fetch; the
        // monotonic counter keeps running (the only shape that cannot be
        // time passing).
        clock.set_wall(T0 + 60);
        for _ in 0..50 {
            assert!(
                matches!(
                    scheduler.refresh_automatic(),
                    AutomaticOutcome::NotDue { .. }
                ),
                "a rolled-back clock must never re-open a window"
            );
        }
        assert_eq!(fetch.calls(), 2, "no storm across 50 repeated probes");
        assert!(scheduler.diagnostics().clock_rollback_detected);

        // Rollback survives the restart: the persisted high-water mark
        // clamps the fresh process to the same conclusion.
        let restarted = restart(&clock, &fetch, &dir);
        assert!(matches!(
            restarted.refresh_automatic(),
            AutomaticOutcome::NotDue { .. }
        ));
        assert_eq!(fetch.calls(), 2);
        assert!(
            effective_now(&clock, &restarted) >= second_window
                || restarted.next_due_unix().unwrap() > clock.now_unix()
        );
    }

    /// The rollback clamp never LOCKS the scheduler out forever: once
    /// the wall catches back up past the persisted deadline, the window
    /// opens normally again (a forward jump, symmetrically, is just
    /// elapsed time).
    #[test]
    fn the_guard_recovers_once_the_wall_catches_up() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![not_modified()]);
        let (scheduler, _dir) = harness(&clock, &fetch);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
        let next = scheduler.next_due_unix().unwrap();

        // Jump the wall FAR forward, then roll it back below the
        // deadline, then let real (monotonic) time carry the wall past
        // the deadline again.
        clock.set_wall(next + 10 * FRESHNESS_FLOOR_SECONDS);
        clock.set_wall(T0 + 30);
        for _ in 0..50 {
            assert!(matches!(
                scheduler.refresh_automatic(),
                AutomaticOutcome::NotDue { .. }
            ));
        }
        clock.set_wall(next + 5);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
        assert_eq!(fetch.calls(), 2);
    }

    /// qa P2-1: the rollback guard's deterministic pin, through the one
    /// path that legitimately runs while the effective time says "early"
    /// — a CONFIRMED manual override. A fetch completes at wall W, the
    /// wall rolls back, the confirmed refresh runs anyway (it is only
    /// early, not suppressed); its reset window must anchor at the
    /// rollback-clamped effective time (W, the persisted high-water
    /// mark), never at the rolled-back reading: rolling the clock back
    /// two hours must not buy a two-hour-earlier next refresh.
    #[test]
    fn a_confirmed_manual_refresh_after_a_rollback_anchors_at_the_high_water_mark() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![not_modified(), not_modified()]);
        let (scheduler, _dir) = harness(&clock, &fetch);

        // The fetch completes at wall W; W becomes the high-water mark.
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
        let w = T0;

        // Roll the wall back two hours while the monotonic counter keeps
        // running (the only shape that cannot be ordinary time passing).
        clock.set_wall(w - 2 * 3600);
        clock.set_monotonic_ms(clock.monotonic_ms() + 1000);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::NotDue { .. }
        ));

        // The effective time is still W, so the manual door is early but
        // NOT suppressed: the ceremony mints, the token redeems.
        let requirement = match scheduler.refresh_manual(None) {
            ManualOutcome::ConfirmationRequired(requirement) => requirement,
            other => panic!("the rolled-back wall must not reopen the window: {other:?}"),
        };
        let report = match scheduler.refresh_manual(Some(&requirement.confirmation_token)) {
            ManualOutcome::Refreshed(report) => report,
            other => panic!("a confirmed refresh must run while merely early: {other:?}"),
        };
        // THE pin: the reset window anchors at the high-water mark. The
        // exact upper bound is the drawn jitter (0..=JITTER); the floor
        // side is the deterministic fact under test.
        assert!(
            report.next_eligible_unix >= w + FRESHNESS_FLOOR_SECONDS,
            "next eligibility {} must anchor at the high-water mark {w} \
             (+{FRESHNESS_FLOOR_SECONDS}s floor), not the rolled-back wall",
            report.next_eligible_unix
        );
        assert!(report.next_eligible_unix <= w + FRESHNESS_FLOOR_SECONDS + JITTER);
        assert!(scheduler.next_due_unix().unwrap() >= w + FRESHNESS_FLOOR_SECONDS);
        assert_eq!(fetch.calls(), 2);

        // The persisted document carries the clamped window: a restart
        // inherits the same protection (the re-derivation and the saved
        // deadline agree on the W-anchored floor).
        let persisted = scheduler.persisted();
        assert!(persisted.wall_high_water_unix >= w);
        assert!(persisted.next_eligible_unix.unwrap() >= w + FRESHNESS_FLOOR_SECONDS);
    }

    /// T-26: deadlines, suppression, and the diagnostic counters survive
    /// the restart (FR-13H), and the FR-11 age anchor is the persisted
    /// last-success time.
    #[test]
    fn deadlines_and_counters_survive_restart() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![rate_limited(Some(4 * 3600))]);
        let (scheduler, dir) = harness(&clock, &fetch);

        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(RefreshReport {
                outcome: RefreshOutcome::RateLimited { .. },
                ..
            })
        ));
        let persisted = scheduler.persisted();
        assert_eq!(persisted.last_request_unix, Some(T0));
        assert_eq!(persisted.automatic_refresh_count, 1);
        let suppression = persisted.suppression_until_unix.unwrap();
        assert_eq!(suppression, T0 + 4 * 3600, "Q4: Retry-After 4h > floor 3h");

        let restarted = restart(&clock, &fetch, &dir);
        let carried = restarted.persisted();
        assert_eq!(carried.suppression_until_unix, Some(suppression));
        assert_eq!(carried.automatic_refresh_count, 1);
        // The automatic eligibility is the suppression plus the drawn
        // jitter (0..=JITTER) — never below the hard floor.
        let carried_next = carried.next_eligible_unix.unwrap();
        assert!(
            carried_next >= suppression && carried_next <= suppression + JITTER,
            "next eligibility {carried_next} not in [suppression {suppression}, +{JITTER}]"
        );
        assert_eq!(
            restarted.diagnostics().catalog_age_seconds,
            None,
            "no successful fetch yet"
        );
    }

    /// rust M1: the pre-fetch save persists `last_request` but the
    /// floor-bumped `next_eligible` only lands post-fetch — a daemon
    /// crash-looping inside that window must not refetch on every
    /// start. Construction re-derives the minimum survivable window.
    #[test]
    fn restart_after_a_crash_between_saves_is_not_immediately_due() {
        let dir = tempfile::tempdir().unwrap();
        // The exact document the pre-fetch save leaves behind when the
        // FIRST fetch crashes mid-flight: request recorded, eligibility
        // still absent (`None` reads as "immediately due").
        DeadlineStore::new(dir.path().join("deadlines.json"))
            .save(&SchedulerDeadlines {
                last_request_unix: Some(T0),
                wall_high_water_unix: T0,
                ..SchedulerDeadlines::default()
            })
            .unwrap();
        let clock = VirtualClock::new(T0 + 60);
        let fetch = FakeFetch::new(vec![not_modified()]);
        let restarted = restart(&clock, &fetch, &dir);

        assert_eq!(
            restarted.refresh_automatic(),
            AutomaticOutcome::NotDue {
                next_eligible_unix: T0 + FRESHNESS_FLOOR_SECONDS
            },
            "a crash between the saves must not make every restart due"
        );
        assert_eq!(
            fetch.calls(),
            0,
            "the crash-looping daemon refetches zero times"
        );

        // The re-derivation only ever pushes the window OUT: an
        // eligibility already at or above the floor survives untouched
        // (a longer suppression or configured window is not shortened).
        let dir = tempfile::tempdir().unwrap();
        DeadlineStore::new(dir.path().join("deadlines.json"))
            .save(&SchedulerDeadlines {
                last_request_unix: Some(T0),
                next_eligible_unix: Some(T0 + 6 * 3600),
                next_eligible_source: Some(IntervalSource::RetryAfter),
                wall_high_water_unix: T0,
                suppression_until_unix: Some(T0 + 6 * 3600),
                ..SchedulerDeadlines::default()
            })
            .unwrap();
        let restarted = restart(&clock, &fetch, &dir);
        assert_eq!(restarted.next_due_unix(), Some(T0 + 6 * 3600));
        assert_eq!(
            restarted.persisted().next_eligible_source,
            Some(IntervalSource::RetryAfter),
            "a surviving greater deadline keeps its own source label"
        );
    }

    // --- Q4 / ER-16 / E2E-22: suppression --------------------------------------

    #[test]
    fn retry_after_sets_the_greatest_of_suppression() {
        // A Retry-After inside the floor loses to the floor.
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![rate_limited(Some(3600)), not_modified()]);
        let (scheduler, _dir) = harness(&clock, &fetch);
        match scheduler.refresh_automatic() {
            AutomaticOutcome::Due(report) => {
                assert!(matches!(
                    report.outcome,
                    RefreshOutcome::RateLimited {
                        retry_after_seconds: Some(3600)
                    }
                ));
                assert_eq!(
                    report.suppression_until_unix,
                    Some(T0 + FRESHNESS_FLOOR_SECONDS)
                );
            }
            other => panic!("expected Due, got {other:?}"),
        }
        assert_eq!(
            scheduler.persisted().next_eligible_source,
            Some(IntervalSource::ThreeHourFloor)
        );

        // A Retry-After beyond the floor wins.
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![rate_limited(Some(6 * 3600)), not_modified()]);
        let (scheduler, _dir) = harness(&clock, &fetch);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
        assert_eq!(
            scheduler.persisted().suppression_until_unix,
            Some(T0 + 6 * 3600)
        );
        assert_eq!(
            scheduler.persisted().next_eligible_source,
            Some(IntervalSource::RetryAfter)
        );
    }

    /// qa P1-1, behavioral red: inject `RateLimited { None }` at T0;
    /// the manual door at T0+60 must be Suppressed with the floor-pinned
    /// deadline — not ConfirmationRequired.
    #[test]
    fn a_rate_limit_without_retry_after_suppresses_the_manual_door() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![rate_limited(None), not_modified()]);
        let (scheduler, _dir) = harness(&clock, &fetch);

        match scheduler.refresh_automatic() {
            AutomaticOutcome::Due(report) => assert!(matches!(
                report.outcome,
                RefreshOutcome::RateLimited {
                    retry_after_seconds: None
                }
            )),
            other => panic!("expected Due, got {other:?}"),
        }
        // The suppression is the un-jittered 3h floor from the request.
        assert_eq!(
            scheduler.persisted().suppression_until_unix,
            Some(T0 + FRESHNESS_FLOOR_SECONDS)
        );

        // The manual door: floor-pinned Suppressed, never a ceremony.
        clock.set_wall(T0 + 60);
        assert_eq!(
            scheduler.refresh_manual(None),
            ManualOutcome::Suppressed {
                until_unix: T0 + FRESHNESS_FLOOR_SECONDS
            }
        );
        assert_eq!(
            scheduler.refresh_manual(Some("confirmed-anyway")),
            ManualOutcome::Suppressed {
                until_unix: T0 + FRESHNESS_FLOOR_SECONDS
            },
            "even a confirmed shape cannot escape a delay-less rate limit"
        );
        assert_eq!(fetch.calls(), 1, "no request may escape the suppression");
    }

    /// sec P3 (invariant-trust defense-in-depth): the automatic door
    /// must refuse inside an active suppression EVEN IF the persisted
    /// next eligibility somehow sits below it — the writer derives
    /// next_eligible >= suppression, but no reader may bet on that
    /// derivation surviving every hand-built or future writer
    /// (mirroring the manual door's suppression check).
    #[test]
    fn the_automatic_door_refuses_directly_while_suppressed() {
        let clock = VirtualClock::new(T0 + 2 * 3600);
        let fetch = FakeFetch::new(vec![not_modified()]);
        let dir = tempfile::tempdir().unwrap();
        // The inconsistent shape the defense exists for: an eligibility
        // consistent with its own floor (it survives construction's
        // crash re-derivation) that has already passed, while a
        // suppression beyond it is still active — the writer's
        // next_eligible >= suppression derivation has been violated.
        let persisted = SchedulerDeadlines {
            last_request_unix: Some(T0 - 2 * 3600),
            last_success_unix: Some(T0 - 2 * 3600),
            next_eligible_unix: Some(T0 + 3600), // passed, below suppression
            next_eligible_source: Some(IntervalSource::ThreeHourFloor),
            wall_high_water_unix: T0 + 2 * 3600,
            suppression_until_unix: Some(T0 + 4 * 3600),
            ..SchedulerDeadlines::default()
        };
        let scheduler = Scheduler::new(
            SchedulerConfig::new(FRESHNESS_FLOOR_SECONDS, JITTER, true).unwrap(),
            Arc::new(clock.clone()),
            fetch.service(),
            DeadlineStore::new(dir.path().join("deadlines.json")),
            persisted,
            None,
        );
        assert_eq!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::NotDue {
                next_eligible_unix: T0 + 4 * 3600
            },
            "the suppression itself must gate the automatic door"
        );
        assert_eq!(fetch.calls(), 0);
    }

    /// E2E-22: even a confirmed manual request and every restart honor
    /// the persisted suppression deadline.
    #[test]
    fn suppression_refuses_even_confirmed_manual_requests() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![rate_limited(Some(6 * 3600)), not_modified()]);
        let (scheduler, dir) = harness(&clock, &fetch);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
        let suppression = T0 + 6 * 3600;

        // Well inside the window the manual door is Suppressed — before
        // any confirmation ceremony, and with a forged token too.
        clock.set_wall(T0 + 3 * 3600 + 60);
        assert_eq!(
            scheduler.refresh_manual(None),
            ManualOutcome::Suppressed {
                until_unix: suppression
            }
        );
        assert_eq!(
            scheduler.refresh_manual(Some("forged-token")),
            ManualOutcome::Suppressed {
                until_unix: suppression
            }
        );
        assert_eq!(fetch.calls(), 1, "no request may escape the suppression");

        // The restart inherits it (FR-13H/ER-16).
        let restarted = restart(&clock, &fetch, &dir);
        assert_eq!(
            restarted.refresh_manual(None),
            ManualOutcome::Suppressed {
                until_unix: suppression
            }
        );

        // Past the jittered next eligibility the window reopens (the
        // suppression floor itself is un-jittered; the automatic
        // eligibility adds 0..=JITTER on top).
        let reopened = restarted.next_due_unix().unwrap();
        assert!(reopened >= suppression);
        clock.set_wall(reopened + 1);
        assert!(matches!(
            restarted.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
    }

    // --- T-27: warned + confirmed manual override -------------------------------

    #[test]
    fn early_manual_refresh_requires_a_fresh_confirmed_token() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![not_modified()]);
        let (scheduler, _dir) = harness(&clock, &fetch);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));

        clock.set_wall(T0 + 600);
        // (a) No token: the typed requirement with the warning.
        let requirement = match scheduler.refresh_manual(None) {
            ManualOutcome::ConfirmationRequired(requirement) => requirement,
            other => panic!("expected ConfirmationRequired, got {other:?}"),
        };
        assert_eq!(requirement.catalog_age_seconds, 600);
        assert_eq!(requirement.last_request_unix, Some(T0));
        let next = scheduler.next_due_unix().unwrap();
        assert_eq!(requirement.next_eligible_unix, next);
        assert_eq!(requirement.warning, MANUAL_REFRESH_WARNING);
        assert_eq!(requirement.confirmation_token.len(), 64);
        assert!(
            requirement
                .confirmation_token
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
            "32 CSPRNG bytes, hex-encoded"
        );

        // The token is never persisted (FR-13I: approval is not a
        // preference).
        // (b) A wrong token never succeeds and forces a FRESH ceremony.
        let second = match scheduler.refresh_manual(Some("wrong")) {
            ManualOutcome::ConfirmationRequired(second) => second,
            other => panic!("expected a fresh requirement, got {other:?}"),
        };
        assert_ne!(
            second.confirmation_token, requirement.confirmation_token,
            "confirmation is per-request: every refusal mints fresh"
        );

        // (c) The correct token performs exactly one refresh, counted
        // separately, and resets the automatic deadline (FR-13I).
        let report = match scheduler.refresh_manual(Some(&second.confirmation_token)) {
            ManualOutcome::Refreshed(report) => report,
            other => panic!("expected Refreshed, got {other:?}"),
        };
        assert!(matches!(report.outcome, RefreshOutcome::NotModified));
        assert_eq!(fetch.calls(), 2);
        let diagnostics = scheduler.diagnostics();
        assert_eq!(diagnostics.manual_refresh_count, 1);
        assert_eq!(diagnostics.automatic_refresh_count, 1);
        assert!(
            report.next_eligible_unix >= T0 + 600 + FRESHNESS_FLOOR_SECONDS,
            "FR-13I: the confirmed request resets the next automatic window"
        );

        // (d) Single-use: replaying the burned token is a fresh refusal,
        // never a second refresh.
        match scheduler.refresh_manual(Some(&second.confirmation_token)) {
            ManualOutcome::ConfirmationRequired(_) => {}
            other => panic!("burned token must not refresh again: {other:?}"),
        }
        assert_eq!(fetch.calls(), 2);

        // (e) The automatic door stays shut until the reset deadline.
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::NotDue { .. }
        ));
        assert_eq!(fetch.calls(), 2);
    }

    #[test]
    fn a_manual_refresh_that_is_already_eligible_needs_no_confirmation() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![not_modified()]);
        let (scheduler, _dir) = harness(&clock, &fetch);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
        clock.set_wall(T0 + FRESHNESS_FLOOR_SECONDS + JITTER);
        match scheduler.refresh_manual(None) {
            ManualOutcome::Refreshed(report) => assert!(!report.coalesced),
            other => panic!("an eligible manual refresh proceeds: {other:?}"),
        }
        assert_eq!(scheduler.diagnostics().manual_refresh_count, 1);
    }

    #[test]
    fn confirmation_tokens_expire() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![not_modified()]);
        let (scheduler, _dir) = harness(&clock, &fetch);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
        clock.set_wall(T0 + 60);
        let requirement = match scheduler.refresh_manual(None) {
            ManualOutcome::ConfirmationRequired(requirement) => requirement,
            other => panic!("expected a requirement, got {other:?}"),
        };
        // Beyond the TTL the token is dead, whatever the caller does.
        clock.set_wall(T0 + 60 + CONFIRMATION_TOKEN_TTL_SECONDS + 1);
        match scheduler.refresh_manual(Some(&requirement.confirmation_token)) {
            ManualOutcome::ConfirmationRequired(fresh) => {
                assert_ne!(fresh.confirmation_token, requirement.confirmation_token);
            }
            other => panic!("an expired token must force a fresh ceremony: {other:?}"),
        }
        assert_eq!(fetch.calls(), 1);
    }

    /// rust M4/sec F1, scheduler side: a forced CSPRNG failure makes
    /// the manual door fail CLOSED — no ceremony, no token stored, no
    /// early fetch — and the door recovers once the RNG does.
    #[test]
    fn a_forced_csprng_failure_makes_the_manual_door_fail_closed() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![not_modified()]);
        let (scheduler, _dir) = harness(&clock, &fetch);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));

        // Force the mint source to fail THROUGH the real mint helper
        // (production = the OS CSPRNG via getrandom, which cannot be
        // made to fail on demand; routing the force through the helper
        // keeps the mint's own fail-closed shape under test).
        scheduler.inner.lock().unwrap().minter = MintSource(std::sync::Arc::new(|| {
            mint_confirmation_token_from(|_| false)
        }));
        clock.set_wall(T0 + 60);
        assert_eq!(
            scheduler.refresh_manual(None),
            ManualOutcome::Unavailable,
            "a broken RNG must not become a confirmation bypass"
        );
        // The empty echo of the old fail-open sentinel redeems nothing
        // either — there is no pending token at all.
        assert_eq!(
            scheduler.refresh_manual(Some("")),
            ManualOutcome::Unavailable
        );
        assert_eq!(fetch.calls(), 1, "no early fetch may escape");
        // Nothing was stored: a healthy mint still mints a real token.
        scheduler.inner.lock().unwrap().minter = MintSource::default();
        match scheduler.refresh_manual(None) {
            ManualOutcome::ConfirmationRequired(requirement) => {
                assert_eq!(requirement.confirmation_token.len(), 64);
            }
            other => panic!("a recovered mint must hold a ceremony: {other:?}"),
        }
        assert_eq!(fetch.calls(), 1);
    }

    /// rust M4/sec F1, redeem side: an empty echo never redeems — even
    /// against a live pending token, the empty string is foreign by
    /// construction (tokens are 64 hex chars) and must never match.
    #[test]
    fn an_empty_echo_never_redeems() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![not_modified()]);
        let (scheduler, _dir) = harness(&clock, &fetch);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
        clock.set_wall(T0 + 60);
        let requirement = match scheduler.refresh_manual(None) {
            ManualOutcome::ConfirmationRequired(requirement) => requirement,
            other => panic!("expected a requirement, got {other:?}"),
        };
        // The empty echo against the live ceremony: refused, and the
        // refusal mints a FRESH ceremony (per-request confirmation).
        match scheduler.refresh_manual(Some("")) {
            ManualOutcome::ConfirmationRequired(fresh) => {
                assert_ne!(fresh.confirmation_token, requirement.confirmation_token);
                assert!(!fresh.confirmation_token.is_empty());
            }
            other => panic!("an empty echo must never redeem: {other:?}"),
        }
        assert_eq!(fetch.calls(), 1, "no refresh ran");
    }

    /// The minted token never reaches the persisted document (FR-13I)
    /// even while it is live in memory.
    #[test]
    fn a_live_token_is_never_persisted() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![not_modified()]);
        let (scheduler, dir) = harness(&clock, &fetch);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
        clock.set_wall(T0 + 60);
        let requirement = match scheduler.refresh_manual(None) {
            ManualOutcome::ConfirmationRequired(requirement) => requirement,
            other => panic!("expected a requirement, got {other:?}"),
        };
        let stored = std::fs::read_to_string(dir.path().join("deadlines.json")).unwrap();
        assert!(
            !stored.contains(&requirement.confirmation_token),
            "the confirmation token must never persist"
        );
    }

    // --- robustness --------------------------------------------------------------

    /// A panicking fetch bridge must resolve its generation: joiners get
    /// a failure report, later windows still work (no permanent wedge).
    #[test]
    fn a_panicking_fetch_does_not_wedge_single_flight() {
        let clock = VirtualClock::new(T0);
        let fetch: CatalogFetch = Arc::new(|_etag| panic!("bridge exploded"));
        let dir = tempfile::tempdir().unwrap();
        let scheduler = Scheduler::new(
            SchedulerConfig::new(FRESHNESS_FLOOR_SECONDS, JITTER, true).unwrap(),
            Arc::new(clock.clone()),
            fetch,
            DeadlineStore::new(dir.path().join("deadlines.json")),
            SchedulerDeadlines::default(),
            None,
        );
        let scheduler = Arc::new(scheduler);
        let first = std::thread::spawn({
            let scheduler = Arc::clone(&scheduler);
            move || scheduler.refresh_automatic()
        })
        .join()
        .expect("the panic is contained inside the scheduler");
        match first {
            AutomaticOutcome::Due(report) => {
                assert!(matches!(report.outcome, RefreshOutcome::Failed { .. }));
            }
            other => panic!("expected a failure report, got {other:?}"),
        }
        // The window still advanced: the next caller is NotDue, not
        // parked forever.
        let second = std::thread::spawn({
            let scheduler = Arc::clone(&scheduler);
            move || scheduler.refresh_automatic()
        })
        .join()
        .expect("the scheduler must not be wedged");
        assert!(matches!(second, AutomaticOutcome::NotDue { .. }));
    }

    // --- The catalog-cache write-through (production wiring) -------------------

    use std::os::unix::fs::PermissionsExt as _;

    use protonwire_store::catalog::{
        CATALOG_CACHE_SCHEMA_VERSION as CACHE_SCHEMA, CachedCatalog, CatalogCache,
    };
    use protonwire_store::paths::ConfigPaths;

    /// A minimal body that parses against the live catalog model.
    const VALID_BODY: &str = r#"{"Code":1000,"StatusID":"t","LogicalServers":[]}"#;

    /// A scheduler with the production cache wired at `dir/servers.json`
    /// (the private-field injection point; production constructs this
    /// through its strict loads).
    fn wired(clock: &VirtualClock, fetch: &FakeFetch) -> (Arc<Scheduler>, tempfile::TempDir) {
        let (scheduler, dir) = harness(clock, fetch);
        scheduler.inner.lock().unwrap().cache = Some(CacheState {
            cache: CatalogCache::new(dir.path().join("servers.json")),
            current: None,
        });
        (scheduler, dir)
    }

    fn stored_doc(etag: Option<&str>, fetched_unix: u64, body: &str) -> CachedCatalog {
        CachedCatalog {
            schema_version: CACHE_SCHEMA,
            etag: etag.map(str::to_owned),
            fetched_unix,
            body: body.to_owned(),
        }
    }

    fn read_stored_cache(dir: &tempfile::TempDir) -> CachedCatalog {
        let bytes = std::fs::read(dir.path().join("servers.json")).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn a_changed_fetch_writes_the_revision_through_the_catalog_cache() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![Ok(FetchOutcome::Changed {
            etag: Some("\"rev-1\"".to_owned()),
            body: VALID_BODY.as_bytes().to_vec(),
        })]);
        let (scheduler, dir) = wired(&clock, &fetch);

        match scheduler.refresh_automatic() {
            AutomaticOutcome::Due(report) => {
                assert!(matches!(report.outcome, RefreshOutcome::Changed { .. }))
            }
            other => panic!("expected Due, got {other:?}"),
        }
        let stored = read_stored_cache(&dir);
        assert_eq!(stored.schema_version, CACHE_SCHEMA);
        assert_eq!(stored.etag.as_deref(), Some("\"rev-1\""), "FR-13B revision");
        assert_eq!(stored.fetched_unix, T0);
        assert_eq!(stored.body, VALID_BODY, "the raw body, verbatim");
    }

    #[test]
    fn a_not_modified_fetch_refreshes_cache_freshness_without_rewriting_the_body() {
        let clock = VirtualClock::new(T0 + FRESHNESS_FLOOR_SECONDS + 1);
        let fetch = FakeFetch::new(vec![not_modified()]);
        let (scheduler, dir) = wired(&clock, &fetch);
        // Seed the wired cache as if the revision was fetched long ago.
        let current = stored_doc(Some("\"rev-1\""), T0 - 10_000, VALID_BODY);
        CatalogCache::new(dir.path().join("servers.json"))
            .store(&current)
            .unwrap();
        scheduler.inner.lock().unwrap().cache = Some(CacheState {
            cache: CatalogCache::new(dir.path().join("servers.json")),
            current: Some(current),
        });

        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(RefreshReport {
                outcome: RefreshOutcome::NotModified,
                ..
            })
        ));
        let stored = read_stored_cache(&dir);
        assert_eq!(stored.etag.as_deref(), Some("\"rev-1\""));
        assert_eq!(
            stored.fetched_unix,
            T0 + FRESHNESS_FLOOR_SECONDS + 1,
            "FR-13E: freshness advances"
        );
        assert_eq!(stored.body, VALID_BODY, "FR-13E: catalog data unchanged");
    }

    /// S6's sec discipline on the write side: a body that fails the
    /// live model never lands in the trusted cache location — the
    /// refresh fails loudly and the last good revision survives.
    #[test]
    fn an_unusable_body_fails_the_refresh_and_keeps_the_last_good_cache() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![Ok(FetchOutcome::Changed {
            etag: Some("\"rev-2\"".to_owned()),
            body: b"{\"Code\":1000,\"Not\":\"a catalog\"}".to_vec(),
        })]);
        let (scheduler, dir) = wired(&clock, &fetch);
        let good = stored_doc(Some("\"rev-1\""), T0 - 500, VALID_BODY);
        CatalogCache::new(dir.path().join("servers.json"))
            .store(&good)
            .unwrap();
        scheduler.inner.lock().unwrap().cache = Some(CacheState {
            cache: CatalogCache::new(dir.path().join("servers.json")),
            current: Some(good),
        });
        // Production seeds the in-memory etag from the same loaded
        // document; mirror that here.
        scheduler.inner.lock().unwrap().etag = Some("\"rev-1\"".to_owned());

        match scheduler.refresh_automatic() {
            AutomaticOutcome::Due(report) => match report.outcome {
                RefreshOutcome::Failed { reason } => assert!(
                    reason.contains("live model") || reason.contains("drift"),
                    "the failure must name the validation: {reason}"
                ),
                other => panic!("an unusable body must fail, got {other:?}"),
            },
            other => panic!("expected Due, got {other:?}"),
        }
        // The last good revision is untouched: same etag, same body.
        let stored = read_stored_cache(&dir);
        assert_eq!(stored.etag.as_deref(), Some("\"rev-1\""));
        assert_eq!(stored.body, VALID_BODY);
        // No adoption happened: the age anchor never moved (there was
        // no successful fetch this run) and the in-memory etag still
        // points at the last good revision.
        assert_eq!(
            scheduler.diagnostics().last_success_unix,
            None,
            "an unusable fetch is not a successful fetch"
        );
        assert_eq!(scheduler.diagnostics().last_request_unix, Some(T0));
        assert_eq!(
            scheduler.inner.lock().unwrap().etag.as_deref(),
            Some("\"rev-1\"")
        );
        // Pacing still advanced from the attempt: the failure cannot
        // hammer Proton either.
        assert!(scheduler.next_due_unix().unwrap() >= T0 + FRESHNESS_FLOOR_SECONDS);
    }

    /// Breaks the wired cache's store deterministically: a directory at
    /// the cache path makes every atomic rename fail (EISDIR on Linux:
    /// rename(2) refuses a file→directory target) with the temp write
    /// succeeding first — exactly the "local I/O failed mid-persist"
    /// window.
    fn break_the_cache_store(dir: &tempfile::TempDir) {
        std::fs::create_dir_all(dir.path().join("servers.json"))
            .expect("plant the obstructing directory");
    }

    /// The Codex PR#4 round-2 tightening (P2): a failed cache WRITE
    /// REFUSES the revision. The round-1 fix adopted it in memory (so
    /// the etag never named an unretained body — coherent locally),
    /// but the daemon's client-visible read path serves from the
    /// DURABLE store: an in-memory-only adoption reports `Changed`
    /// while `ServersList` keeps serving the old catalog until some
    /// later write-through — a split world. No adoption, no etag
    /// advance, no age anchor; the old durable revision keeps serving.
    #[test]
    fn a_failed_cache_write_refuses_the_revision() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![Ok(FetchOutcome::Changed {
            etag: Some("\"rev-2\"".to_owned()),
            body: VALID_BODY.as_bytes().to_vec(),
        })]);
        let (scheduler, dir) = wired(&clock, &fetch);
        // Seed a durable good revision the clients keep serving.
        let good = stored_doc(Some("\"rev-1\""), T0 - 500, VALID_BODY);
        CatalogCache::new(dir.path().join("servers.json"))
            .store(&good)
            .unwrap();
        scheduler.inner.lock().unwrap().cache = Some(CacheState {
            cache: CatalogCache::new(dir.path().join("servers.json")),
            current: Some(good),
        });
        scheduler.inner.lock().unwrap().etag = Some("\"rev-1\"".to_owned());
        // Swap the durable file for the write obstruction: the seeded
        // in-memory `current` still names rev-1 (what clients were
        // serving), while every store() attempt fails on the rename.
        std::fs::remove_file(dir.path().join("servers.json")).unwrap();
        break_the_cache_store(&dir);

        match scheduler.refresh_automatic() {
            AutomaticOutcome::Due(report) => match report.outcome {
                RefreshOutcome::Failed { reason } => assert!(
                    reason.contains("clients keep the last durable catalog"),
                    "the failure must name the durability refusal: {reason}"
                ),
                other => panic!("an unretainable revision must fail, got {other:?}"),
            },
            other => panic!("expected Due, got {other:?}"),
        }
        // The split world does not open: etag, in-memory current, and
        // the age anchor all still name rev-1 (the durable file was
        // swapped for the obstruction; nothing overwrote it).
        assert_eq!(
            scheduler.inner.lock().unwrap().etag.as_deref(),
            Some("\"rev-1\"")
        );
        let current = scheduler
            .inner
            .lock()
            .unwrap()
            .cache
            .as_ref()
            .and_then(|state| state.current.clone())
            .expect("the last durable revision stays adopted");
        assert_eq!(current.etag.as_deref(), Some("\"rev-1\""));
        assert!(dir.path().join("servers.json").is_dir());
        assert_eq!(
            scheduler.diagnostics().last_success_unix,
            None,
            "an unretained fetch is not a successful fetch"
        );
        // Pacing still advanced from the attempt.
        assert!(scheduler.next_due_unix().unwrap() >= T0 + FRESHNESS_FLOOR_SECONDS);
    }

    /// The healing path under the tightened contract: with the write
    /// obstruction CLEARED and the next window open, the refresh
    /// re-offers the OLD conditional etag, re-fetches the body, and
    /// stores it — the disk heals, clients see the new revision.
    #[test]
    fn the_next_window_after_a_write_failure_heals_the_disk() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![
            Ok(FetchOutcome::Changed {
                etag: Some("\"rev-2\"".to_owned()),
                body: VALID_BODY.as_bytes().to_vec(),
            }),
            Ok(FetchOutcome::Changed {
                etag: Some("\"rev-2\"".to_owned()),
                body: VALID_BODY.as_bytes().to_vec(),
            }),
        ]);
        let (scheduler, dir) = wired(&clock, &fetch);
        let good = stored_doc(Some("\"rev-1\""), T0 - 500, VALID_BODY);
        CatalogCache::new(dir.path().join("servers.json"))
            .store(&good)
            .unwrap();
        scheduler.inner.lock().unwrap().cache = Some(CacheState {
            cache: CatalogCache::new(dir.path().join("servers.json")),
            current: Some(good),
        });
        scheduler.inner.lock().unwrap().etag = Some("\"rev-1\"".to_owned());
        std::fs::remove_file(dir.path().join("servers.json")).unwrap();
        break_the_cache_store(&dir);

        // Refresh 1: fetch succeeds, store fails, revision refused.
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(RefreshReport {
                outcome: RefreshOutcome::Failed { .. },
                ..
            })
        ));
        // The obstruction heals; the next window opens.
        std::fs::remove_dir(dir.path().join("servers.json")).unwrap();
        clock.set_wall(scheduler.next_due_unix().unwrap());

        // Refresh 2: the OLD etag is re-offered (nothing advanced past
        // rev-1), the body is re-fetched, and this time stored.
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(RefreshReport {
                outcome: RefreshOutcome::Changed { .. },
                ..
            })
        ));
        assert_eq!(
            fetch.seen_etags(),
            vec![Some("\"rev-1\"".to_owned()), Some("\"rev-1\"".to_owned())],
            "the conditional etag must keep naming what the disk retains"
        );
        let stored = read_stored_cache(&dir);
        assert_eq!(stored.etag.as_deref(), Some("\"rev-2\""));
        assert_eq!(stored.body, VALID_BODY);
    }

    /// Codex PR#4 round 3 (P2): a POST-fetch save failure that strands
    /// a Retry-After suppression LONGER than the restart floor puts the
    /// scheduler into the persistence-degraded state — the next refresh
    /// is refused without upstream contact until a bare save succeeds
    /// (the suppression must be durably recorded before normal
    /// operation resumes).
    #[test]
    fn a_post_fetch_save_failure_degrades_persistence_until_a_save_succeeds() {
        // A plain (non-TempDir) directory so the fetch seam can break
        // it mid-refresh: the pre-fetch save succeeds, the fetch plants
        // a FILE at the directory path, the post-fetch save fails.
        static CALL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pw-sched-degraded-{}-{}",
            std::process::id(),
            CALL.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let clock = VirtualClock::new(T0);
        let upstream_calls = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counter = Arc::clone(&upstream_calls);
        let obstruct_dir = dir.clone();
        let fetch_fn: CatalogFetch = Arc::new(move |_etag| {
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                // First fetch: the rate-limit response, THEN obstruct
                // the store so the post-fetch save fails. The retry
                // exceeds the floor — the restart-reconstructable state
                // is WEAKER than what only memory holds.
                std::fs::remove_dir_all(&obstruct_dir).ok();
                std::fs::write(&obstruct_dir, b"").ok();
                Err(FetchFailure::RateLimited {
                    retry_after_seconds: Some(FRESHNESS_FLOOR_SECONDS + 600),
                })
            } else {
                Ok(FetchOutcome::NotModified)
            }
        });
        let scheduler = Arc::new(Scheduler::new(
            SchedulerConfig::new(FRESHNESS_FLOOR_SECONDS, JITTER, true)
                .expect("the standard suite config is valid"),
            Arc::new(clock.clone()),
            fetch_fn,
            DeadlineStore::new(dir.join("deadlines.json")),
            SchedulerDeadlines::default(),
            None,
        ));

        // Refresh 1: RateLimited honored in memory; the post-fetch save
        // fails (the store path's parent is now a file) — degraded.
        match scheduler.refresh_automatic() {
            AutomaticOutcome::Due(report) => assert!(
                matches!(report.outcome, RefreshOutcome::RateLimited { .. }),
                "the rate limit itself is reported: {:?}",
                report.outcome
            ),
            other => panic!("expected Due, got {other:?}"),
        }
        assert_eq!(
            scheduler.diagnostics().suppression_until_unix,
            Some(T0 + FRESHNESS_FLOOR_SECONDS + 600),
            "the longer-than-floor suppression is honored in memory"
        );
        // The degradation itself: the post-fetch save failure flipped
        // the health flag (the next lead retries a bare save before ANY
        // upstream contact — the refusal mechanics are pinned
        // end-to-end by the unwritable-store tests below).
        assert!(
            !scheduler.persistence_healthy_for_tests(),
            "a post-fetch save failure must degrade persistence"
        );
        // The restart hazard the guard exists for: the durable document
        // is still the PRE-fetch one (the obstruction prevented the
        // write), so a restarted scheduler would reconstruct only the
        // floor — weaker than the suppression memory holds. The
        // degraded flag keeps THIS process from further upstream
        // contact until a save succeeds.
        assert!(
            !dir.join("deadlines.json").is_file(),
            "the durable document never landed"
        );

        // Heal the store and verify recovery end-to-end: the next lead
        // retries the bare save, succeeds (clearing the flag), and
        // proceeds to the upstream — the NotModified below is the
        // proof the gate opened.
        std::fs::remove_file(&dir).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        match scheduler.refresh_automatic() {
            AutomaticOutcome::Due(report) => assert!(
                matches!(report.outcome, RefreshOutcome::NotModified),
                "after healing, the refresh proceeds: {:?}",
                report.outcome
            ),
            AutomaticOutcome::NotDue { next_eligible_unix } => {
                // The failure window may still be closed — chase it
                // open (bounded) and require the refresh to eventually
                // reach the upstream.
                clock.set_wall(next_eligible_unix + 1);
                match scheduler.refresh_automatic() {
                    AutomaticOutcome::Due(report) => assert!(
                        matches!(report.outcome, RefreshOutcome::NotModified),
                        "after healing + window open, the refresh proceeds: {:?}",
                        report.outcome
                    ),
                    other => panic!("expected Due after the window opened, got {other:?}"),
                }
            }
        }
        assert_eq!(
            upstream_calls.load(Ordering::SeqCst),
            2,
            "the healed store resumed upstream contact"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Codex PR#4 round 2 (P2): an unwritable DEADLINE store refuses
    /// the fetch outright — contacting the upstream without a durable
    /// pre-fetch timestamp would let a restart bypass the window (the
    /// FR-13H restart-storm class) and lose any Retry-After
    /// suppression signaled this round.
    #[test]
    fn an_unwritable_deadline_store_refuses_the_fetch() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![Ok(FetchOutcome::Changed {
            etag: Some("\"rev-2\"".to_owned()),
            body: VALID_BODY.as_bytes().to_vec(),
        })]);
        let dir = tempfile::tempdir().unwrap();
        // `blocker` is a regular FILE: the deadlines path beneath it
        // can never be created or written.
        std::fs::write(dir.path().join("blocker"), b"").unwrap();
        let scheduler = Scheduler::new(
            SchedulerConfig::new(FRESHNESS_FLOOR_SECONDS, JITTER, true)
                .expect("the standard suite config is valid"),
            Arc::new(clock.clone()),
            fetch.service(),
            DeadlineStore::new(dir.path().join("blocker").join("deadlines.json")),
            SchedulerDeadlines::default(),
            None,
        );
        match scheduler.refresh_automatic() {
            AutomaticOutcome::Due(report) => match report.outcome {
                RefreshOutcome::Failed { reason } => assert!(
                    reason.contains("deadline store is unwritable"),
                    "the failure must name the refused anchor: {reason}"
                ),
                other => panic!("an un-anchored fetch must fail, got {other:?}"),
            },
            other => panic!("expected Due, got {other:?}"),
        }
        assert_eq!(
            fetch.calls(),
            0,
            "the upstream is never contacted without a durable pacing anchor"
        );
        // Pacing still advanced in memory: the refusal cannot hammer.
        assert!(scheduler.next_due_unix().unwrap() >= T0 + FRESHNESS_FLOOR_SECONDS);
    }

    /// (Superseded by `the_next_window_after_a_write_failure_heals_the_disk`
    /// under the round-2 contract: a write failure now REFUSES the
    /// revision, so there is no in-memory adoption for a later 304 to
    /// write through — the healing path re-fetches instead.)
    ///
    /// The production constructor's strict happy path: both documents
    /// load under the trust root, the stored revision seeds conditional
    /// requests, and the loaded deadlines govern. Root-gated (the
    /// fs_trust ownership pass needs a root-owned tree — the store
    /// suite's compromise); NOTICE-skip otherwise.
    #[test]
    fn production_seeds_deadlines_and_the_stored_revision() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let paths = ConfigPaths::rooted(dir.path());
        std::fs::create_dir_all(&paths.cache_dir).unwrap();
        DeadlineStore::new(dir.path().join("var/cache/protonwire/deadlines.json"))
            .save(&SchedulerDeadlines {
                last_request_unix: Some(T0),
                last_success_unix: Some(T0),
                next_eligible_unix: Some(T0 + FRESHNESS_FLOOR_SECONDS),
                next_eligible_source: Some(IntervalSource::ThreeHourFloor),
                wall_high_water_unix: T0,
                ..SchedulerDeadlines::default()
            })
            .unwrap();
        CatalogCache::new(dir.path().join("var/cache/protonwire/servers.json"))
            .store(&stored_doc(Some("\"rev-9\""), T0, VALID_BODY))
            .unwrap();
        let root_owned = std::fs::metadata(dir.path().join("var/cache/protonwire/servers.json"))
            .map(|m| m.uid() == 0 && m.gid() == 0)
            .unwrap_or(false);
        if !root_owned {
            // NOTICE skip (CONTRIBUTING rule 5, the a368775 idiom): the
            // fs_trust ownership pass needs a root-owned tree, which an
            // unprivileged runner cannot construct. The walk's mode and
            // symlink arms are covered unprivileged below; visible via
            // `cargo test -- --nocapture`.
            eprintln!(
                "NOTICE: skipping production_seeds_deadlines_and_the_stored_revision: the \
                 cache tree is not root-owned on this runner — the ownership arm of the \
                 fs_trust walk is unprovable unprivileged"
            );
            return;
        }
        let clock = VirtualClock::new(T0 + 60);
        let fetch = FakeFetch::new(vec![not_modified()]);
        let scheduler = Scheduler::production_with_trust_root(
            SchedulerConfig::new(FRESHNESS_FLOOR_SECONDS, JITTER, true).unwrap(),
            Arc::new(clock.clone()),
            fetch.service(),
            &paths,
            dir.path(),
        )
        .expect("the strict loads succeed over the root-owned tree");
        // Deadlines carried (not due until the loaded eligibility) and
        // the stored revision seeded for the next conditional request.
        assert_eq!(
            scheduler.next_due_unix(),
            Some(T0 + FRESHNESS_FLOOR_SECONDS)
        );
        assert_eq!(
            scheduler.inner.lock().unwrap().etag.as_deref(),
            Some("\"rev-9\"")
        );
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::NotDue { .. }
        ));
    }

    /// The production walk is strict on BOTH documents; the leaf-first
    /// pass names the tampered leaf before any ancestor (including the
    /// world-writable `/tmp` the `/` walk would meet), so the refusal
    /// is deterministic on every runner.
    #[test]
    fn production_refuses_a_tampered_deadlines_document() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ConfigPaths::rooted(dir.path());
        std::fs::create_dir_all(&paths.cache_dir).unwrap();
        let deadlines_path = paths.cache_dir.join("deadlines.json");
        DeadlineStore::new(&deadlines_path)
            .save(&SchedulerDeadlines {
                last_request_unix: Some(T0),
                wall_high_water_unix: T0,
                ..SchedulerDeadlines::default()
            })
            .unwrap();
        std::fs::set_permissions(&deadlines_path, std::fs::Permissions::from_mode(0o666)).unwrap();

        let err = match Scheduler::production(
            SchedulerConfig::new(FRESHNESS_FLOOR_SECONDS, JITTER, true).unwrap(),
            Arc::new(VirtualClock::new(T0)),
            FakeFetch::new(vec![not_modified()]).service(),
            &paths,
        ) {
            Err(err) => err,
            Ok(_) => panic!("a world-writable deadlines document must abort construction"),
        };
        assert!(
            matches!(
                &err,
                SchedulerError::Deadlines(
                    protonwire_store::deadlines::DeadlineStoreError::FsTrust(_)
                )
            ),
            "{err}"
        );
        assert!(
            err.to_string().contains("deadlines.json"),
            "the leaf defect must be named, not an ancestor: {err}"
        );
    }

    /// The production walk is strict on BOTH documents (deadlines load
    /// first, then the cache). Root-gated like the happy-path test —
    /// an unprivileged runner cannot pass the ownership arm of the
    /// FIRST (deadlines) walk at all, so reaching the cache walk
    /// requires a root-owned tree; NOTICE-skip otherwise. The cache's
    /// own walk arms are pinned unprivileged in the store suite.
    #[test]
    fn production_refuses_a_tampered_cache_document() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let paths = ConfigPaths::rooted(dir.path());
        std::fs::create_dir_all(&paths.cache_dir).unwrap();
        DeadlineStore::new(paths.cache_dir.join("deadlines.json"))
            .save(&SchedulerDeadlines {
                last_request_unix: Some(T0),
                wall_high_water_unix: T0,
                ..SchedulerDeadlines::default()
            })
            .unwrap();
        let cache_path = paths.cache_dir.join("servers.json");
        CatalogCache::new(&cache_path)
            .store(&stored_doc(None, T0, VALID_BODY))
            .unwrap();
        let root_owned = std::fs::metadata(&cache_path)
            .map(|m| m.uid() == 0 && m.gid() == 0)
            .unwrap_or(false);
        if !root_owned {
            eprintln!(
                "NOTICE: skipping production_refuses_a_tampered_cache_document: the \
                 cache tree is not root-owned on this runner — the first (deadlines) \
                 walk cannot pass the ownership arm unprivileged, so the cache arm is \
                 unreachable here"
            );
            return;
        }
        std::fs::set_permissions(&cache_path, std::fs::Permissions::from_mode(0o666)).unwrap();

        let err = match Scheduler::production_with_trust_root(
            SchedulerConfig::new(FRESHNESS_FLOOR_SECONDS, JITTER, true).unwrap(),
            Arc::new(VirtualClock::new(T0)),
            FakeFetch::new(vec![not_modified()]).service(),
            &paths,
            dir.path(),
        ) {
            Err(err) => err,
            Ok(_) => panic!("a world-writable cache document must abort construction"),
        };
        assert!(
            matches!(
                &err,
                SchedulerError::CatalogCache(
                    protonwire_store::catalog::CatalogCacheError::FsTrust(_)
                )
            ),
            "{err}"
        );
        assert!(
            err.to_string().contains("servers.json"),
            "the leaf defect must be named, not an ancestor: {err}"
        );
    }

    // --- FR-13E: conditional-request pass-through -------------------------------

    /// qa P2-2: the stored ETag flows to the next conditional request.
    /// The seam records the ETag every invocation receives; the bootstrap
    /// fetch goes out unconditional (no stored revision), and the adopted
    /// revision's ETag must ride the next request.
    #[test]
    fn the_adopted_etag_flows_to_the_next_conditional_request() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![
            Ok(FetchOutcome::Changed {
                etag: Some("\"rev-1\"".to_owned()),
                body: VALID_BODY.as_bytes().to_vec(),
            }),
            not_modified(),
        ]);
        let (scheduler, _dir) = harness(&clock, &fetch);

        // Bootstrap: nothing stored, so the request is unconditional.
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(RefreshReport {
                outcome: RefreshOutcome::Changed { .. },
                ..
            })
        ));
        assert_eq!(
            fetch.seen_etags(),
            [None],
            "the bootstrap request carries no ETag"
        );

        // The adopted revision's ETag must be presented on the next one.
        let next = scheduler.next_due_unix().unwrap();
        clock.set_wall(next);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
        assert_eq!(
            fetch.seen_etags(),
            [None, Some("\"rev-1\"".to_owned())],
            "the stored revision must be presented conditionally (FR-13E)"
        );
        assert_eq!(fetch.calls(), 2);
    }

    /// qa P2-2, the disabled arm: `conditional_requests: false` must
    /// strip the ETag from every request — the policy is the product
    /// gate on the pass-through, not a hint — while the revision itself
    /// is still adopted (a Changed outcome is a Changed outcome; only
    /// the wire shape changes).
    #[test]
    fn a_disabled_conditional_policy_never_sends_the_etag() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![
            Ok(FetchOutcome::Changed {
                etag: Some("\"rev-1\"".to_owned()),
                body: VALID_BODY.as_bytes().to_vec(),
            }),
            not_modified(),
        ]);
        let (scheduler, _dir) = harness_with_config(
            &clock,
            &fetch,
            SchedulerConfig::new(FRESHNESS_FLOOR_SECONDS, JITTER, false).unwrap(),
        );

        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
        let next = scheduler.next_due_unix().unwrap();
        clock.set_wall(next);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
        assert_eq!(
            fetch.seen_etags(),
            [None, None],
            "a disabled conditional policy must never present the stored ETag"
        );
        assert_eq!(
            scheduler.inner.lock().unwrap().etag.as_deref(),
            Some("\"rev-1\""),
            "the revision is still adopted; only the request shape changed"
        );
    }

    // --- E2E-22: the 24-virtual-hours suite -----------------------------------

    /// E2E-22's automatic-window budget: 24 virtual hours on the default
    /// policy yield at most eight automatic windows; a rate-limited
    /// window's suppression then binds the manual door, restarts
    /// included, until it passes.
    #[test]
    fn e2e22_twenty_four_virtual_hours() {
        let clock = VirtualClock::new(T0);
        let fetch = FakeFetch::new(vec![not_modified()]);
        let (scheduler, dir) = seeded(&clock, &fetch, T0);

        let mut automatic_windows = 0;
        for hour in 1..=24u64 {
            clock.set_wall(T0 + hour * 3600);
            if matches!(scheduler.refresh_automatic(), AutomaticOutcome::Due(_)) {
                automatic_windows += 1;
            }
        }
        assert!(
            automatic_windows <= 8,
            "at most eight automatic windows in 24h, got {automatic_windows}"
        );
        assert!(
            automatic_windows >= 6,
            "positive jitter (<= {JITTER}s) may slip hourly checks by at most \
             one hour per window; six windows is the floor, got {automatic_windows}"
        );
        assert_eq!(fetch.calls(), automatic_windows);

        // Inject rate limiting on the next window: suppression greatest-of
        // binds the confirmed manual door and every restart.
        let gated = FakeFetch::new(vec![rate_limited(Some(4 * 3600)), not_modified()]);
        let scheduler = restart(&clock, &gated, &dir);
        let next_window = scheduler.next_due_unix().unwrap();
        clock.set_wall(next_window + 1);
        match scheduler.refresh_automatic() {
            AutomaticOutcome::Due(report) => {
                assert!(matches!(report.outcome, RefreshOutcome::RateLimited { .. }));
            }
            other => panic!("the injected window must run, got {other:?}"),
        }
        let suppression = scheduler.persisted().suppression_until_unix.unwrap();
        assert_eq!(suppression, next_window + 1 + 4 * 3600);

        // A manual request while the suppression is active is refused
        // outright — suppression outranks confirmation (E2E-22). The
        // clock sits just past the injected window with a 4 h
        // suppression ahead, so every other arm is a failure of that
        // ordering (the old dead arm that merely discarded the
        // requirement is gone).
        match scheduler.refresh_manual(None) {
            ManualOutcome::Suppressed { until_unix } => {
                assert_eq!(until_unix, suppression);
                // While suppressed the ceremony itself is refused; use a
                // forged token to prove even a confirmed shape cannot pass.
                assert_eq!(
                    scheduler.refresh_manual(Some("confirmed-anyway")),
                    ManualOutcome::Suppressed { until_unix }
                );
            }
            other => panic!(
                "suppression must outrank the ceremony at this point (suppression \
                 {suppression}, wall {}): {other:?}",
                clock.now_unix()
            ),
        }

        // Every restart honors the persisted suppression deadline.
        for _ in 0..3 {
            let restarted = restart(&clock, &gated, &dir);
            assert!(matches!(
                restarted.refresh_automatic(),
                AutomaticOutcome::NotDue { .. }
            ));
        }

        // Past the jittered next eligibility the schedule resumes.
        let resumed = scheduler.next_due_unix().unwrap();
        assert!(resumed >= suppression);
        clock.set_wall(resumed + 1);
        assert!(matches!(
            scheduler.refresh_automatic(),
            AutomaticOutcome::Due(_)
        ));
    }

    // --- E2E-22: the randomized virtual-clock property ------------------------

    /// The normative property: over randomized virtual-clock walks
    /// (advances, rollbacks, forward jumps) with interleaved automatic
    /// and manual attempts, every performed fetch observes the greatest
    /// deadline computed before it, and suppression is never violated.
    ///
    /// sec P3 (mirror-oracle fix): every expectation is DERIVED from the
    /// virtual clock — which only this walk moves — never echoed from
    /// the scheduler's own reports. The walk keeps its own high-water
    /// mark (the highest wall reading any refresh call could have
    /// observed; the scheduler reads the clock only inside those calls),
    /// computes each led fetch's un-jittered greatest-of from the call's
    /// effective time and the rate limit THE WALK queued — with or
    /// without a `Retry-After` delay (`raw = E + max(floor,
    /// Retry-After)`, saturating; a delay-less rate limit still mints
    /// the floor, Q4) — and asserts
    /// the report lands in `[max(raw, suppression),
    /// max(raw + jitter ceiling, suppression)]` with the suppression
    /// EXACTLY the accumulated max of past rate-limited raws. The old
    /// shape copied `report.next_eligible_unix`/`suppression_until_unix`
    /// and the persisted high-water into the oracle, so a mis-anchored
    /// or mis-floored deadline was self-consistent and invisible here —
    /// exactly the qa P1-1 class, which only the unit tests caught.
    #[test]
    fn property_random_virtual_clock_walks_respect_every_deadline() {
        for seed in [0x5EED_1001u64, 0x5EED_1002, 0x5EED_1003] {
            let mut rng = ScenarioRng::new(seed);
            let clock = VirtualClock::new(T0);
            // The fetch behavior is scripted by the walk itself: normal
            // windows are not-modified; rate limiting is injected
            // occasionally via a shared script slot.
            let script: Arc<StdMutex<VecDeque<Result<FetchOutcome, FetchFailure>>>> =
                Arc::new(StdMutex::new(VecDeque::new()));
            let calls = Arc::new(AtomicU64::new(0));
            let service: CatalogFetch = {
                let script = Arc::clone(&script);
                let calls = Arc::clone(&calls);
                Arc::new(move |_etag| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    script
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or(Ok(FetchOutcome::NotModified))
                })
            };
            let dir = tempfile::tempdir().unwrap();
            let scheduler = Arc::new(Scheduler::new(
                SchedulerConfig::new(FRESHNESS_FLOOR_SECONDS, JITTER, true).unwrap(),
                Arc::new(clock.clone()),
                service,
                DeadlineStore::new(dir.path().join("deadlines.json")),
                SchedulerDeadlines::default(),
                None,
            ));

            // --- the walk's OWN ledger (nothing reads the scheduler's
            // idea of time or deadlines) ---
            // Highest wall reading any refresh call has observed. Updated
            // at call time below — the walk can jump the wall forward and
            // back between calls without the scheduler ever seeing the
            // peak, so a per-step max would be WRONG, not just mirrored.
            let mut walk_high_water: u64 = 0;
            // [lower, upper] bounds of the current next-eligibility: the
            // un-jittered greatest-of through the jitter ceiling, never
            // below the accumulated suppression (the drawn jitter hides
            // the exact value; the bounds do not). None before the first
            // fetch — the bootstrap is always due.
            let mut window: Option<(u64, u64)> = None;
            // The accumulated suppression: every rate limit mints the
            // un-jittered greatest-of, and suppression never clears.
            let mut suppression: Option<u64> = None;
            // The rate limits this walk queued, in order — `Some(delay)`
            // or `None` (the delay-less Q4 class) — the fetch that leads
            // next consumes the front, whichever door opened (the
            // service's script and this queue pop together).
            let mut queued_retry_afters: VecDeque<Option<u64>> = VecDeque::new();
            let mut automatic_windows = 0u64;
            let mut manual_windows = 0u64;
            let mut outstanding_token: Option<String> = None;

            // The un-jittered greatest-of for one fetch led at effective
            // time `effective` (the configured interval IS the floor in
            // this harness, so span = max(floor, Retry-After)).
            let raw_deadline = |effective: u64, retry_after: Option<u64>| {
                let span = retry_after.map_or(FRESHNESS_FLOOR_SECONDS, |delay| {
                    FRESHNESS_FLOOR_SECONDS.max(delay)
                });
                effective.saturating_add(span)
            };

            for _step in 0..400 {
                let choice = rng.next_u64() % 100;
                match choice {
                    0..=34 => clock.advance_secs(rng.between(1, 6 * 3600)),
                    35..=49 => {
                        // Rollback: wall drops, monotonic keeps running.
                        let back = rng.between(1, 12 * 3600);
                        let wall = clock.now_unix();
                        clock.set_monotonic_ms(clock.monotonic_ms() + 1000);
                        clock.set_wall(wall.saturating_sub(back).max(1));
                    }
                    50..=59 => {
                        // Forward jump: wall only.
                        clock.set_wall(clock.now_unix() + rng.between(1, 24 * 3600));
                    }
                    60..=79 => {
                        // Occasionally inject rate limiting ahead of the
                        // next fetch — with a Retry-After delay or
                        // delay-less (both Q4 classes suppress).
                        if rng.next_u64().is_multiple_of(4) {
                            let delay = rng
                                .next_u64()
                                .is_multiple_of(4)
                                .then(|| rng.between(1, 5 * 3600));
                            queued_retry_afters.push_back(delay);
                            script
                                .lock()
                                .unwrap()
                                .push_back(Err(FetchFailure::RateLimited {
                                    retry_after_seconds: delay,
                                }));
                        }
                        walk_high_water = walk_high_water.max(clock.now_unix());
                        let effective = clock.now_unix().max(walk_high_water);
                        match scheduler.refresh_automatic() {
                            AutomaticOutcome::Due(report) => {
                                // No fetch before its DERIVED floor, ever
                                // (the lower bound is jitter-free, so a
                                // due fetch below it is a real violation).
                                assert!(
                                    window.is_none_or(|(lower, _)| effective >= lower)
                                        || report.coalesced,
                                    "automatic fetch before its derived deadline at \
                                     effective {effective}, window {window:?} (seed {seed})"
                                );
                                if !report.coalesced {
                                    automatic_windows += 1;
                                    let injected = queued_retry_afters.pop_front();
                                    let raw = raw_deadline(effective, injected.flatten());
                                    if injected.is_some() {
                                        // EVERY rate limit — with or
                                        // without a delay — mints the
                                        // un-jittered greatest-of (Q4).
                                        suppression =
                                            Some(suppression.map_or(raw, |old: u64| old.max(raw)));
                                    }
                                    let sup = suppression.unwrap_or(0);
                                    let bounds =
                                        (raw.max(sup), raw.saturating_add(JITTER).max(sup));
                                    assert!(
                                        report.next_eligible_unix >= bounds.0
                                            && report.next_eligible_unix <= bounds.1,
                                        "automatic reset {} outside the derived window \
                                          {bounds:?} (seed {seed})",
                                        report.next_eligible_unix
                                    );
                                    assert_eq!(
                                        report.suppression_until_unix, suppression,
                                        "suppression drifted from the derived \
                                         accumulation (seed {seed})"
                                    );
                                    window = Some(bounds);
                                }
                            }
                            AutomaticOutcome::NotDue { next_eligible_unix } => {
                                let (lower, upper) =
                                    window.expect("the bootstrap fetch is always due");
                                assert!(
                                    next_eligible_unix >= lower && next_eligible_unix <= upper,
                                    "named deadline {next_eligible_unix} outside the \
                                     derived window ({lower}, {upper}) (seed {seed})"
                                );
                                assert!(
                                    effective < upper,
                                    "the door stalled past its own derived jittered \
                                     deadline: effective {effective}, upper {upper} \
                                     (seed {seed})"
                                );
                            }
                        }
                    }
                    80..=99 => {
                        // The manual door, with and without a token.
                        walk_high_water = walk_high_water.max(clock.now_unix());
                        let effective = clock.now_unix().max(walk_high_water);
                        let suppressed = suppression.is_some_and(|until| effective < until);
                        let token = if rng.next_u64().is_multiple_of(2) {
                            outstanding_token.as_deref()
                        } else {
                            None
                        };
                        match scheduler.refresh_manual(token) {
                            ManualOutcome::Suppressed { until_unix } => {
                                assert_eq!(
                                    Some(until_unix),
                                    suppression,
                                    "the named suppression is not the derived one \
                                     (seed {seed})"
                                );
                                assert!(suppressed, "unsuppressed manual refused (seed {seed})");
                            }
                            ManualOutcome::ConfirmationRequired(requirement) => {
                                assert!(!suppressed, "suppressed manual minted a ceremony");
                                outstanding_token = Some(requirement.confirmation_token);
                            }
                            ManualOutcome::Refreshed(report) => {
                                if !report.coalesced {
                                    manual_windows += 1;
                                    // A confirmed refresh is legal inside the
                                    // interval but NEVER inside a suppression.
                                    assert!(
                                        !suppressed,
                                        "manual refresh escaped suppression (seed {seed})"
                                    );
                                    let injected = queued_retry_afters.pop_front();
                                    let raw = raw_deadline(effective, injected.flatten());
                                    if injected.is_some() {
                                        // EVERY rate limit — with or
                                        // without a delay — mints the
                                        // un-jittered greatest-of (Q4).
                                        suppression =
                                            Some(suppression.map_or(raw, |old: u64| old.max(raw)));
                                    }
                                    let sup = suppression.unwrap_or(0);
                                    let bounds =
                                        (raw.max(sup), raw.saturating_add(JITTER).max(sup));
                                    assert!(
                                        report.next_eligible_unix >= bounds.0
                                            && report.next_eligible_unix <= bounds.1,
                                        "manual reset {} outside the derived window \
                                          {bounds:?} (seed {seed})",
                                        report.next_eligible_unix
                                    );
                                    assert_eq!(
                                        report.suppression_until_unix, suppression,
                                        "suppression drifted from the derived \
                                         accumulation (seed {seed})"
                                    );
                                    window = Some(bounds);
                                    outstanding_token = None; // burned
                                }
                            }
                            // The healthy-minter walk never fails the
                            // CSPRNG; the fail-closed arm is driven
                            // deterministically in its own test.
                            ManualOutcome::Unavailable => {
                                panic!("healthy minter reported unavailable (seed {seed})")
                            }
                        }
                    }
                    _ => unreachable!(),
                }
                // The persisted view agrees with the DERIVED ledger —
                // never a mirror: the bounds come from the walk's clock
                // math and its own queued rate limits alone.
                let persisted = scheduler.persisted();
                if let Some((lower, upper)) = window {
                    let persisted_next = persisted.next_eligible_unix;
                    assert!(
                        persisted_next.is_some_and(|next| next >= lower && next <= upper),
                        "persisted eligibility {persisted_next:?} outside \
                         the derived window ({lower}, {upper}) (seed {seed})"
                    );
                }
                assert_eq!(persisted.suppression_until_unix, suppression);
                assert_eq!(persisted.manual_refresh_count, manual_windows);
                assert_eq!(persisted.automatic_refresh_count, automatic_windows);
            }
        }
    }

    // --- wall_rolled_back pure properties --------------------------------------

    #[test]
    fn wall_rolled_back_matches_its_defining_combination() {
        // Wall down + monotonic up (or equal) => rollback.
        assert!(wall_rolled_back(100, 50, 99, 60));
        assert!(wall_rolled_back(100, 50, 99, 50));
        // Wall down + monotonic down => not this predicate's claim.
        assert!(!wall_rolled_back(100, 50, 99, 49));
        // Wall up is never a rollback, whatever the monotonic did.
        assert!(!wall_rolled_back(100, 50, 101, 49));
        assert!(!wall_rolled_back(100, 50, 101, 60));
        // Property over random pairs.
        let mut rng = ScenarioRng::new(0x5EED_0003);
        for _ in 0..4_000 {
            let (prev_wall, prev_mono, wall, mono) = (
                rng.between(0, 10_000),
                rng.between(0, 10_000),
                rng.between(0, 10_000),
                rng.between(0, 10_000),
            );
            assert_eq!(
                wall_rolled_back(prev_wall, prev_mono, wall, mono),
                wall < prev_wall && mono >= prev_mono
            );
        }
    }
}
