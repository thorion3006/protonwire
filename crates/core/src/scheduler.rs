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
//! rate-limit classification. The daemon (S9) bridges `&dyn CatalogApi`
//! onto this seam, mapping the adapter's `ApiError::RateLimited`
//! (landing with the api-wire-fixture lane) onto
//! [`FetchFailure::RateLimited`]; until that variant exists, the
//! bridge's `ApiError::Transport` arm maps onto
//! [`FetchFailure::Transport`]. The 429/503 wire-fixture obligation
//! itself is tracked for S9.

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
    /// seconds (FR-13D: 0..=ceiling, never negative).
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
    /// A `Retry-After` delay observed at `now_unix` (seconds).
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
        suppression_until_unix: inputs.retry_after_seconds.map(|_| raw),
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
            retry_after_seconds: Some(u64::MAX),
            proton_lifetime_seconds: Some(u64::MAX),
            jitter_seconds: u64::MAX,
            ..base_inputs()
        };
        let deadline = next_deadline(&inputs);
        assert_eq!(deadline.next_eligible_unix, u64::MAX);
        assert_eq!(deadline.suppression_until_unix, Some(u64::MAX));
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
            let retry_after = (rng.next_u64().is_multiple_of(3))
                .then(|| rng.between(1, FRESHNESS_FLOOR_SECONDS * 6));
            let jitter = rng.between(0, 600);
            let inputs = DeadlineInputs {
                last_request_unix: Some(last_request),
                now_unix: now,
                configured_interval_seconds: interval,
                proton_lifetime_seconds: lifetime,
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
                let suppression = deadline
                    .suppression_until_unix
                    .expect("a Retry-After always pins a suppression floor");
                assert!(
                    suppression >= (now + retry_after).max(last_request + FRESHNESS_FLOOR_SECONDS),
                    "suppression floor below the greatest-of for {inputs:?}"
                );
            } else {
                assert_eq!(
                    deadline.suppression_until_unix, None,
                    "no Retry-After must not mint a suppression for {inputs:?}"
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
            let retry_after = (rng.next_u64().is_multiple_of(3))
                .then(|| rng.between(1, FRESHNESS_FLOOR_SECONDS * 3));
            let inputs = DeadlineInputs {
                last_request_unix: Some(last_request),
                now_unix: now,
                configured_interval_seconds: interval,
                proton_lifetime_seconds: lifetime,
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
