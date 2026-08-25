//! Server selection: the pure choice core (PRD 7.3/7.3A; FR-14..FR-23).
//!
//! ## What this module is
//!
//! The pure function `(catalog, target, policy, constraints) → ranked
//! candidates` over the S6 catalog document
//! ([`protonwire_store::catalog::CatalogDocument`]). It performs NO I/O
//! and NO network access: selection reads the *cached* catalog the
//! daemon strictly loaded (FR-23R — fetching is the S7 single-flight
//! scheduler's job, never selection's). Everything here is deterministic
//! for identical inputs; the only ordering inputs are the catalog
//! document, the request, and the caller-supplied context.
//!
//! ## Hard filters, in the FR-23P order (the core-owned stages)
//!
//! online state → target geography/type → physical-country exclusion →
//! explicit user exclusions → required features → protocol
//! compatibility. The entitlement and authoritative-subset stages
//! compose at the daemon boundary over S8 (milestone 3 PR-4); the one
//! entitlement-dependent constraint this module knows — port forwarding
//! (no catalog field exists upstream; see the S6 catalog module docs) —
//! evaluates against an explicit [`SelectionContext`] seam and refuses
//! typed when that seam is unset rather than guessing (FR-23H: no
//! silent pass, no silent downgrade).
//!
//! ## Policies (FR-14..FR-19)
//!
//! * [`RankingPolicy::Official`] — Proton's opaque catalog `Score`
//!   ascending after hard filters (official Fastest semantics; the
//!   catalog contract's `proton-score`). Ties break by Proton-exposed
//!   `Load` ascending, then by logical id — load is an allowed
//!   Proton-exposed signal (FR-19) and the tiebreak keeps output
//!   deterministic; no locally measured signal ever influences the
//!   official policy. ANY eligible candidate lacking `Score` is a typed
//!   [`SelectionError::OfficialScoreUnavailable`] refusal (T-1/FR-19A):
//!   never a silent drop, never a silent substitution of the balanced
//!   model.
//! * [`RankingPolicy::Balanced`] — ProtonWire's weighted policy (FR-16;
//!   lower is better) over caller-supplied weights. A positive latency
//!   weight requires caller-supplied latency observations (probing is
//!   PR-3 of this milestone's stack); stability and history have no
//!   data source until connection statistics exist (post-M4), so their
//!   terms contribute uniformly zero and the scoring-signal report
//!   marks them absent.
//! * [`RankingPolicy::LowestLoad`] — lowest Proton-exposed load
//!   (FR-17); a server without an exposed load is excluded WITH a
//!   structured report entry, never approximated.
//!
//! ## No speed, ever (FR-19, T-1)
//!
//! A `speed` sort mode or weight — and the catalog contract's other
//! forbidden throughput signals — is rejected with the typed
//! [`SelectionError::UnsupportedRankingSignal`] at this module's input
//! schema ([`RankingPolicy::parse`], [`WeightedSignals::from_pairs`]),
//! mirroring the refusal the S3 config vocabularies already enforce on
//! their surfaces. Selection must never invent or expose a throughput
//! score.
//!
//! ## Matching discipline
//!
//! Exact server requests never silently fall back to another server
//! (FR-23): an unmatchable, offline, or eliminated exact target is a
//! typed error naming the server and the stage that refused it.
//! Country codes are ISO 3166-1 alpha-2 and must arrive uppercase —
//! canonicalization is the calling surface's job, and this module
//! refuses anything non-canonical rather than approximating. State and
//! city names compare ASCII-case-insensitively (user-typed prose
//! against catalog casing); server and gateway names compare exactly.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use protonwire_store::catalog::LogicalServer;

/// Latency observations keyed by logical server ID — the caller-supplied
/// probe results (milestone 3 PR-3 wires the bounded on-demand prober;
/// FR-18 forbids full-catalog scans, so keys cover at most a shortlist).
pub type LatencyTable = BTreeMap<String, Duration>;

/// The forbidden throughput ranking signals (the catalog contract's
/// `forbidden_ranking_signals`, plus `speed` itself — FR-19's named
/// offender). Rejecting these is T-1's "every input schema" clause for
/// this module's schema.
pub const FORBIDDEN_RANKING_SIGNALS: &[&str] =
    &["speed", "estimated-speed", "estimated-throughput"];

/// What the user is connecting to (PRD 9.2 grammar; the group targets
/// of PRD 7.4 resolve onto these kinds in milestone 3 PR-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Fastest overall — the eligible Standard fleet (FR-23L: gateway,
    /// Secure Core, and dedicated logicals are other connection types).
    Fastest,
    /// A country's eligible Standard servers (FR-20).
    Country(String),
    /// A state or region's eligible Standard servers.
    State(String),
    /// A city's eligible Standard servers.
    City(String),
    /// An exact logical server by name (`UK#42`; Secure Core `CH-SE#1`
    /// and gateway `acme-corp#1` forms are logical names too) — FR-23:
    /// never silently falls back.
    Server(String),
    /// A named gateway's logicals (dedicated-server fleet identity; the
    /// *authorization* is S8 entitlement data composed at the daemon).
    Gateway(String),
}

/// The ranking policy applied after hard filters (FR-14).
#[derive(Debug, Clone, PartialEq)]
pub enum RankingPolicy {
    /// Proton's opaque catalog score ascending — official Fastest
    /// semantics (FR-14/FR-19A).
    Official,
    /// ProtonWire's weighted policy over `weights` (FR-16).
    Balanced {
        /// The weighted signals (see [`WeightedSignals`]).
        weights: WeightedSignals,
    },
    /// Lowest Proton-exposed load (FR-17).
    LowestLoad,
}

impl RankingPolicy {
    /// Parses the ranking-mode vocabulary shared by `--by`, profile
    /// `selection.by`, and the wire `selection_policy`: `official`,
    /// `balanced`, `load`. `speed` — and the other forbidden throughput
    /// signals — is rejected with the typed T-1 error, never silently
    /// ignored (FR-19); unknown strings are invalid modes naming the
    /// input. (`latency` lands with this milestone's PR-3 probing; the
    /// random group policy is PR-2's.)
    pub fn parse(mode: &str) -> Result<Self, SelectionError> {
        match mode {
            "official" => Ok(RankingPolicy::Official),
            "balanced" => Ok(RankingPolicy::Balanced {
                weights: WeightedSignals::DEFAULT,
            }),
            "load" => Ok(RankingPolicy::LowestLoad),
            forbidden if FORBIDDEN_RANKING_SIGNALS.contains(&forbidden) => {
                Err(SelectionError::UnsupportedRankingSignal {
                    key: forbidden.to_owned(),
                })
            }
            other => Err(SelectionError::InvalidRankingMode(other.to_owned())),
        }
    }
}

/// The weighted signals of the `balanced` policy (FR-16's formula;
/// lower is better). Mirrors `server_selection.balanced_weights`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WeightedSignals {
    /// Weight of Proton-exposed load (normalized 0–1).
    pub load: f32,
    /// Weight of measured latency (normalized against the observed set).
    pub latency: f32,
    /// Weight of stability history (no data source until post-M4
    /// connection statistics; uniformly zero until then).
    pub stability: f32,
    /// Weight of optional-feature match.
    pub feature_match: f32,
    /// Weight of historical connection success (same availability note
    /// as `stability`).
    pub history: f32,
}

impl WeightedSignals {
    /// FR-16's documented defaults (`server_selection.balanced_weights`).
    pub const DEFAULT: Self = Self {
        load: 0.40,
        latency: 0.40,
        stability: 0.15,
        feature_match: 0.05,
        history: 0.00,
    };

    /// Parses weight pairs (the wire `weights` map). Known keys: load,
    /// latency, stability, feature_match, history; missing keys are 0.
    /// Rejects the forbidden throughput signals with the typed T-1
    /// error, unknown keys, duplicate keys, and non-finite or negative
    /// values (the M1 NaN lesson: every `NaN` comparison is false, so
    /// validation must be explicit).
    pub fn from_pairs(pairs: &[(String, f32)]) -> Result<Self, SelectionError> {
        let mut out = Self {
            load: 0.0,
            latency: 0.0,
            stability: 0.0,
            feature_match: 0.0,
            history: 0.0,
        };
        let mut seen: Vec<&str> = Vec::with_capacity(pairs.len());
        for (key, value) in pairs {
            if FORBIDDEN_RANKING_SIGNALS.contains(&key.as_str()) {
                return Err(SelectionError::UnsupportedRankingSignal { key: key.clone() });
            }
            if !value.is_finite() || *value < 0.0 {
                return Err(SelectionError::InvalidWeights(format!(
                    "weight for `{key}` is {value}; weights must be finite and non-negative"
                )));
            }
            let slot = match key.as_str() {
                "load" => &mut out.load,
                "latency" => &mut out.latency,
                "stability" => &mut out.stability,
                "feature_match" => &mut out.feature_match,
                "history" => &mut out.history,
                _ => {
                    return Err(SelectionError::InvalidWeights(format!(
                        "unknown weight key `{key}`: expected load, latency, stability, \
                         feature_match, or history"
                    )));
                }
            };
            if seen.contains(&key.as_str()) {
                return Err(SelectionError::InvalidWeights(format!(
                    "duplicate weight key `{key}` (ambiguous input, never last-wins)"
                )));
            }
            seen.push(key.as_str());
            *slot = *value;
        }
        Ok(out)
    }
}

/// A required or optional selection feature (T-4; PRD 9.3 `--require`
/// family plus the catalog-exposed bits the profile schema may pin).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureConstraint {
    /// P2P-friendly (catalog feature bit).
    P2p,
    /// Tor-over-VPN (catalog feature bit).
    Tor,
    /// Secure Core server (catalog feature bit; the *routed* Secure
    /// Core target is milestone 3 PR-3).
    SecureCore,
    /// Streaming-capable where exposed (catalog feature bit).
    Streaming,
    /// IPv6-capable (catalog feature bit).
    Ipv6,
    /// Port-forwarding-capable — no catalog field exists upstream; this
    /// evaluates only against the entitlement seam (FR-23H).
    PortForwarding,
}

/// A required connection protocol, matched against the per-protocol
/// entry map of a server's online physicals (the PRD 9.4 vocabulary;
/// presence IS the support set per the S6 catalog contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolConstraint {
    /// WireGuard over UDP.
    WireguardUdp,
    /// WireGuard over TCP.
    WireguardTcp,
    /// TLS-based Stealth (the catalog's `WireGuardTLS`).
    Stealth,
}

/// Hard-filter constraints (FR-20..FR-22; FR-23P's user-controlled
/// stages). Country codes are ISO 3166-1 alpha-2, uppercase — anything
/// else fails [`select`](fn.select.html) validation typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Constraints {
    /// Never select these countries (FR-21).
    pub excluded_countries: Vec<String>,
    /// Never select these states/regions (FR-21A).
    pub excluded_states: Vec<String>,
    /// Never select these cities (FR-21A).
    pub excluded_cities: Vec<String>,
    /// Never select these logical servers by name (FR-21A).
    pub excluded_servers: Vec<String>,
    /// Exclude the physical country — set by the
    /// fastest-excluding-my-country semantics; the country itself comes
    /// from [`Self::physical_country`] (FR-23Q's resolution is PR-2's;
    /// this module only enforces it once given).
    pub exclude_physical_country: bool,
    /// The resolved physical country (explicit request → config →
    /// cached Muon location, resolved by the caller per FR-23Q).
    pub physical_country: Option<String>,
    /// Required features (T-4; FR-23H explicit constraints).
    pub required_features: Vec<FeatureConstraint>,
    /// Optional features — they never eliminate, they feed the
    /// balanced feature-match term.
    pub optional_features: Vec<FeatureConstraint>,
    /// Required protocol (FR-23P's protocol-compatibility stage).
    pub required_protocol: Option<ProtocolConstraint>,
}

/// The full selection request: what the user asked for.
#[derive(Debug, Clone, PartialEq)]
pub struct SelectionRequest {
    /// The target (PRD 9.2).
    pub target: Target,
    /// The ranking policy (FR-14).
    pub policy: RankingPolicy,
    /// The hard-filter constraints.
    pub constraints: Constraints,
}

/// The environment a selection runs against: what the caller can
/// supply that the catalog cannot (probe results, entitlement
/// composition). Everything here is caller-owned; selection never
/// fetches or fabricates any of it.
#[derive(Debug, Clone, Default)]
pub struct SelectionContext {
    /// Latency observations by logical id (PR-3 of this milestone wires
    /// the bounded prober; an empty table with a positive latency
    /// weight is a typed refusal — no fabricated latencies).
    pub latency: LatencyTable,
    /// Whether the account is entitled to port forwarding (`None`:
    /// entitlement not composed yet — a port-forwarding constraint then
    /// refuses typed rather than guessing).
    pub port_forwarding_entitled: Option<bool>,
}

/// One hard-filter (or policy) stage, in the order FR-23P prescribes
/// for the core-owned prefix. The stage that first eliminates a
/// candidate is the one reported for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterStage {
    /// Logical status absent — unknown is never online (FR-13B,
    /// fail-closed).
    UnknownStatus,
    /// Logical status 0 (offline).
    Offline,
    /// Logical online but every physical is offline/maintenance.
    AllPhysicalsOffline,
    /// An exact target's name matched nothing in the catalog.
    AbsentFromCatalog,
    /// Wrong connection type for the target (gateway or Secure Core
    /// logical under a Standard target, or the converse).
    ServerType,
    /// Country/state/city/gateway-name miss.
    TargetGeography,
    /// Exit country equals the physical country under
    /// `exclude_physical_country` (FR-23Q).
    PhysicalCountryExclusion,
    /// An explicitly excluded country (FR-21).
    ExcludedCountry,
    /// An explicitly excluded state/region (FR-21A).
    ExcludedState,
    /// An explicitly excluded city (FR-21A).
    ExcludedCity,
    /// An explicitly excluded server name (FR-21A).
    ExcludedServer,
    /// A required feature is absent (T-4) or entitlement-refused.
    RequiredFeatures,
    /// No online physical exposes the required protocol.
    ProtocolCompatibility,
    /// Policy stage: no Proton-exposed load under a load-weighted
    /// ranking (never approximated).
    LoadNotExposed,
    /// Policy stage: no latency observation for the candidate (the
    /// FR-18 shortlist boundary; never probed, never guessed).
    NoLatencyObservation,
}

impl fmt::Display for FilterStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FilterStage {
    /// The stage's report label.
    fn label(self) -> &'static str {
        match self {
            FilterStage::UnknownStatus => "unknown-status",
            FilterStage::Offline => "offline",
            FilterStage::AllPhysicalsOffline => "all-physicals-offline",
            FilterStage::AbsentFromCatalog => "absent-from-catalog",
            FilterStage::ServerType => "server-type",
            FilterStage::TargetGeography => "target-geography",
            FilterStage::PhysicalCountryExclusion => "physical-country-exclusion",
            FilterStage::ExcludedCountry => "excluded-country",
            FilterStage::ExcludedState => "excluded-state",
            FilterStage::ExcludedCity => "excluded-city",
            FilterStage::ExcludedServer => "excluded-server",
            FilterStage::RequiredFeatures => "required-features",
            FilterStage::ProtocolCompatibility => "protocol-compatibility",
            FilterStage::LoadNotExposed => "load-not-exposed",
            FilterStage::NoLatencyObservation => "no-latency-observation",
        }
    }
}

/// FR-22's structured account of where every candidate went: one count
/// per stage, in order, plus the survivor count.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EliminationReport {
    /// Candidates that entered the pipeline.
    considered: usize,
    /// Candidates still eligible after every stage.
    survivors: usize,
    /// (stage, eliminated-at-that-stage) in evaluation order.
    stages: Vec<(FilterStage, usize)>,
}

impl EliminationReport {
    /// How many candidates entered the pipeline.
    pub fn considered(&self) -> usize {
        self.considered
    }

    /// How many candidates survived every stage.
    pub fn survivors(&self) -> usize {
        self.survivors
    }

    /// The per-stage counts, in evaluation order.
    pub fn stages(&self) -> &[(FilterStage, usize)] {
        &self.stages
    }
}

impl fmt::Display for EliminationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} considered, {} survivors",
            self.considered, self.survivors
        )?;
        for (stage, count) in &self.stages {
            if *count > 0 {
                write!(f, "; {count} {}", stage.label())?;
            }
        }
        Ok(())
    }
}

/// The scoring signals behind one ranked candidate (FR-23T's
/// scoring-signal provenance, at the source).
#[derive(Debug, Clone, PartialEq)]
pub struct ScoringSignals {
    /// The catalog's opaque Proton score, when exposed.
    pub proton_score: Option<f32>,
    /// The Proton-exposed load percentage, when present.
    pub load: Option<i8>,
    /// The caller-supplied latency observation, when one existed.
    pub latency: Option<Duration>,
    /// The weighted breakdown, when the balanced policy ranked this
    /// candidate.
    pub weighted: Option<WeightedBreakdown>,
}

/// The per-term decomposition of a balanced score (FR-16's formula,
/// made auditable). The stability and history terms are uniformly zero
/// until their data sources exist (post-M4 connection statistics).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WeightedBreakdown {
    /// `load_weight × normalized_load`.
    pub load_term: f32,
    /// `latency_weight × normalized_latency`.
    pub latency_term: f32,
    /// `stability_weight × stability_score` — zero until data exists.
    pub stability_term: f32,
    /// `feature_weight × (1 − match_ratio)`.
    pub feature_match_term: f32,
    /// `history_weight × success_score` — zero until data exists.
    pub history_term: f32,
    /// The weighted sum (lower is better).
    pub total: f32,
}

/// One ranked candidate: the server plus the signals that placed it.
#[derive(Debug, Clone, PartialEq)]
pub struct RankedCandidate<'a> {
    /// The logical server.
    pub server: &'a LogicalServer,
    /// The signals that ranked it.
    pub signals: ScoringSignals,
}

/// The selection result: candidates best-first plus the full
/// elimination report (FR-22/FR-23T).
#[derive(Debug, Clone, PartialEq)]
pub struct SelectionOutcome<'a> {
    /// Eligible candidates, best first.
    pub ranked: Vec<RankedCandidate<'a>>,
    /// Where every other candidate went.
    pub report: EliminationReport,
}

/// Failures of selection (PRD 12.1's ServerSelectionError family,
/// typed at the source).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum SelectionError {
    /// A forbidden throughput ranking signal (FR-19, T-1): `speed` and
    /// the catalog contract's other forbidden signals, rejected — never
    /// silently ignored.
    #[error(
        "unsupported ranking signal `{key}`: FR-19 forbids speed/throughput ranking in every input schema"
    )]
    UnsupportedRankingSignal {
        /// The rejected key.
        key: String,
    },
    /// An unrecognized ranking mode.
    #[error("invalid ranking mode `{0}`: expected `official`, `balanced`, or `load`")]
    InvalidRankingMode(String),
    /// Invalid weights: duplicates, unknown keys, or non-finite /
    /// negative values.
    #[error("invalid balanced weights: {0}")]
    InvalidWeights(String),
    /// A country input is not canonical ISO 3166-1 alpha-2 uppercase.
    #[error(
        "invalid country code `{0}`: expected ISO 3166-1 alpha-2, uppercase (canonicalization is the calling surface's job)"
    )]
    InvalidCountry(String),
    /// An official-policy request where eligible candidates carry no
    /// Proton score: refuse — request an eligible catalog refresh or
    /// use an explicit ProtonWire policy; never silently substitute the
    /// balanced model (FR-19A, T-1).
    #[error(
        "official-score-unavailable: {lacking} of {eligible} eligible servers expose no Proton catalog Score — request an eligible catalog refresh or use an explicit ProtonWire policy"
    )]
    OfficialScoreUnavailable {
        /// Eligible candidates lacking a score.
        lacking: usize,
        /// Total eligible candidates.
        eligible: usize,
    },
    /// A country-excluding request with no physical country known
    /// (FR-23Q): must not connect without the exclusion.
    #[error(
        "physical-country-required: the target excludes the physical country but none is known — pass it explicitly per request or set connection_groups.physical_country"
    )]
    PhysicalCountryRequired,
    /// A balanced request with a positive latency weight and no latency
    /// observations supplied (probing is this milestone's PR-3; no
    /// fabricated latencies in the meantime).
    #[error(
        "latency data unavailable: balanced weights assign {weight} to latency but no observations were supplied"
    )]
    LatencyDataUnavailable {
        /// The latency weight that could not be satisfied.
        weight: f32,
    },
    /// A port-forwarding constraint reached the pure core without the
    /// entitlement composition that must evaluate it (FR-23H).
    #[error("port-forwarding requires entitlement composition before selection can evaluate it")]
    RequiresEntitlementComposition,
    /// No candidate satisfies the constraints; the report names which
    /// stage eliminated what (FR-22).
    #[error("no eligible server: {report}")]
    ConstraintsNotSatisfied {
        /// The full elimination report.
        report: EliminationReport,
    },
    /// An exact server/gateway target that cannot be selected — absent,
    /// or eliminated at the named stage. NEVER falls back to another
    /// server (FR-23).
    #[error(
        "exact server `{name}` is not selectable ({stage}): exact requests never fall back to another server (FR-23)"
    )]
    ExactServerUnavailable {
        /// The requested name.
        name: String,
        /// Why it cannot be selected.
        stage: FilterStage,
    },
}

/// Selects and ranks eligible servers from the cached catalog. Pure:
/// no I/O, no network, no clock, no RNG. See the module docs for the
/// stage order and the policy semantics.
pub fn select<'a>(
    _catalog: &'a protonwire_store::catalog::CatalogDocument,
    _request: &SelectionRequest,
    _context: &SelectionContext,
) -> Result<SelectionOutcome<'a>, SelectionError> {
    // Slices 2-3 of this PR implement the filter pipeline and the
    // ranking policies; the parameters underscore until then so every
    // intermediate commit gates clean.
    todo!("slices 2-3")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Slice 1 — the input schema (T-1's "every input schema" clause,
    // this module's own): mode vocabulary, speed rejection, weight
    // validation.
    // ------------------------------------------------------------------

    #[test]
    fn ranking_mode_vocabulary_parses() {
        assert_eq!(
            RankingPolicy::parse("official").unwrap(),
            RankingPolicy::Official
        );
        assert_eq!(
            RankingPolicy::parse("balanced").unwrap(),
            RankingPolicy::Balanced {
                weights: WeightedSignals::DEFAULT
            }
        );
        assert_eq!(
            RankingPolicy::parse("load").unwrap(),
            RankingPolicy::LowestLoad
        );
    }

    #[test]
    fn speed_sort_mode_is_rejected_with_the_typed_error() {
        // T-1/FR-19: `speed` must fail validation as unsupported, never
        // be silently ignored — and never parse as some other mode.
        for mode in FORBIDDEN_RANKING_SIGNALS {
            let err = RankingPolicy::parse(mode).unwrap_err();
            assert!(
                matches!(err, SelectionError::UnsupportedRankingSignal { ref key } if key == mode),
                "`{mode}` must be the typed unsupported-signal rejection, got: {err}"
            );
            assert!(
                err.to_string().contains("FR-19"),
                "the refusal must cite the rule: {err}"
            );
        }
    }

    #[test]
    fn unknown_modes_are_invalid_not_unsupported() {
        // Only the named throughput signals are UnsupportedRankingSignal;
        // other junk is an ordinary invalid mode (distinct classes).
        let err = RankingPolicy::parse("cheapest").unwrap_err();
        assert_eq!(
            err,
            SelectionError::InvalidRankingMode("cheapest".to_owned())
        );
    }

    #[test]
    fn default_weights_match_fr16() {
        let w = WeightedSignals::DEFAULT;
        assert_eq!(w.load, 0.40);
        assert_eq!(w.latency, 0.40);
        assert_eq!(w.stability, 0.15);
        assert_eq!(w.feature_match, 0.05);
        assert_eq!(w.history, 0.00);
    }

    fn pairs(pairs: &[(&str, f32)]) -> Vec<(String, f32)> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect()
    }

    #[test]
    fn weight_pairs_parse_with_missing_keys_zero() {
        // The PRD's selection-request example carries a partial map.
        let w = WeightedSignals::from_pairs(&pairs(&[
            ("load", 0.35),
            ("latency", 0.50),
            ("stability", 0.10),
            ("feature_match", 0.05),
        ]))
        .unwrap();
        assert_eq!(w.load, 0.35);
        assert_eq!(w.latency, 0.50);
        assert_eq!(w.stability, 0.10);
        assert_eq!(w.feature_match, 0.05);
        assert_eq!(w.history, 0.0, "an omitted key is zero, not an error");
    }

    #[test]
    fn speed_weight_is_rejected_with_the_typed_error() {
        for forbidden in FORBIDDEN_RANKING_SIGNALS {
            let err = WeightedSignals::from_pairs(&pairs(&[(forbidden, 0.5)])).unwrap_err();
            assert!(
                matches!(err, SelectionError::UnsupportedRankingSignal { ref key } if key == forbidden),
                "weight key `{forbidden}` must be the typed rejection, got: {err}"
            );
        }
    }

    #[test]
    fn unknown_weight_keys_are_rejected_naming_the_key() {
        let err = WeightedSignals::from_pairs(&pairs(&[("throughput", 1.0)])).unwrap_err();
        assert!(
            matches!(err, SelectionError::InvalidWeights(ref msg) if msg.contains("throughput")),
            "unknown keys must be InvalidWeights naming the key: {err}"
        );
    }

    #[test]
    fn duplicate_weight_keys_are_rejected() {
        // The duplicate-key doctrine (S3's yaml work): a second value
        // for one key is ambiguous input, never last-wins.
        let err = WeightedSignals::from_pairs(&pairs(&[("load", 0.3), ("load", 0.4)])).unwrap_err();
        assert!(
            matches!(err, SelectionError::InvalidWeights(ref msg) if msg.contains("duplicate")),
            "duplicates must be rejected as ambiguous: {err}"
        );
    }

    #[test]
    fn non_finite_or_negative_weights_are_rejected() {
        // The M1 NaN lesson: every NaN comparison is false, so NaN (and
        // -0.0-adjacent abuse) must be refused explicitly, and negative
        // weights would invert the lower-is-better contract.
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.5] {
            let err = WeightedSignals::from_pairs(&pairs(&[("load", bad)])).unwrap_err();
            assert!(
                matches!(err, SelectionError::InvalidWeights(_)),
                "weight {bad} must be rejected: {err}"
            );
        }
        // Boundary control: 0.0 is legal (disables a signal).
        assert!(WeightedSignals::from_pairs(&pairs(&[("load", 0.0)])).is_ok());
    }
}
